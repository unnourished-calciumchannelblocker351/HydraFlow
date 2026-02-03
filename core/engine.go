// Package core provides the central proxy engine that orchestrates
// protocol selection, connection management, and automatic failover.
package core

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Engine is the central component that manages protocol selection
// and connection lifecycle. It coordinates between the probe engine,
// protocol implementations, and the subscription system.
type Engine struct {
	mu        sync.RWMutex
	config    *Config
	protocols []Protocol
	selector  *Selector
	monitor   *Monitor
	logger    *slog.Logger
	active    Protocol
}

// New creates a new Engine with the given configuration.
func New(cfg *Config, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		config: cfg,
		logger: logger,
	}

	selector, err := NewSelector(cfg.Selection, logger)
	if err != nil {
		return nil, fmt.Errorf("init selector: %w", err)
	}
	e.selector = selector

	e.monitor = NewMonitor(cfg.Monitor, e.onDegradation, logger)

	return e, nil
}

// RegisterProtocol adds a protocol implementation to the engine.
// Protocols are tried in priority order during selection.
func (e *Engine) RegisterProtocol(p Protocol) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protocols = append(e.protocols, p)
	e.logger.Info("protocol registered",
		"name", p.Name(),
		"priority", p.Priority(),
	)
}

// Connect establishes a proxied connection using the best available
// protocol. It first runs probes to detect censorship conditions,
// then selects the optimal protocol, and establishes the connection.
//
// If the selected protocol fails, it automatically falls back to
// the next available protocol in priority order.
func (e *Engine) Connect(ctx context.Context) (net.Conn, error) {
	e.mu.RLock()
	protocols := make([]Protocol, len(e.protocols))
	copy(protocols, e.protocols)
	e.mu.RUnlock()

	if len(protocols) == 0 {
		return nil, fmt.Errorf("no protocols registered")
	}

	// Run probes to understand censorship environment
	probeResult, err := e.selector.Probe(ctx, protocols)
	if err != nil {
		e.logger.Warn("probe failed, using priority order", "error", err)
	}

	// Select the best protocol based on probe results
	ordered := e.selector.Rank(protocols, probeResult)

	// Try each protocol in order until one succeeds
	var lastErr error
	for _, p := range ordered {
		e.logger.Info("attempting connection",
			"protocol", p.Name(),
			"priority", p.Priority(),
		)

		conn, err := p.Dial(ctx)
		if err != nil {
			e.logger.Warn("protocol failed",
				"protocol", p.Name(),
				"error", err,
			)
			lastErr = err
			continue
		}

		e.mu.Lock()
		e.active = p
		e.mu.Unlock()

		e.logger.Info("connected",
			"protocol", p.Name(),
		)

		// Start monitoring connection health
		e.monitor.Watch(conn, p)

		return conn, nil
	}

	return nil, fmt.Errorf("all protocols failed, last error: %w", lastErr)
}

// ActiveProtocol returns the currently active protocol, or nil if
// no connection is established.
func (e *Engine) ActiveProtocol() Protocol {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

// onDegradation is called by the monitor when the current connection
// shows signs of degradation (high latency, packet loss, throttling).
// It triggers a protocol switch.
func (e *Engine) onDegradation(p Protocol, reason string) {
	e.logger.Warn("connection degradation detected",
		"protocol", p.Name(),
		"reason", reason,
	)
	// Protocol switch will be handled by the client layer,
	// which will call Connect() again.
}

// Close shuts down the engine and releases all resources.
func (e *Engine) Close() error {
	e.monitor.Stop()
	return nil
}

// Protocol defines the interface that all bypass protocol
// implementations must satisfy.
type Protocol interface {
	// Name returns the human-readable protocol name.
	Name() string

	// Priority returns the protocol's priority (lower = higher priority).
	Priority() int

	// Dial establishes a connection through this protocol.
	Dial(ctx context.Context) (net.Conn, error)

	// Listen starts accepting connections (server-side).
	Listen(ctx context.Context, addr string) (net.Listener, error)

	// Available reports whether this protocol is likely to work
	// in the current network environment without running full probes.
	Available() bool

	// ProbeTests returns the censorship probe tests relevant
	// to this protocol.
	ProbeTests() []ProbeTest
}

// ProbeTest defines a single censorship detection test.
type ProbeTest interface {
	// Name returns the test identifier.
	Name() string

	// Run executes the test and returns the result.
	Run(ctx context.Context, target string) (*ProbeResult, error)

	// Weight returns how much this test's result should influence
	// protocol selection (0.0 to 1.0).
	Weight() float64
}

// ProbeResult contains the outcome of a single probe test.
type ProbeResult struct {
	TestName  string
	Success   bool
	Latency   time.Duration
	Details   map[string]string
	Timestamp time.Time
}
