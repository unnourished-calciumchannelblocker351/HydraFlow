package core

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// MonitorConfig controls connection health monitoring.
type MonitorConfig struct {
	// CheckInterval is how often to measure connection health.
	CheckInterval time.Duration `yaml:"check_interval"`

	// LatencyThreshold triggers a degradation event when exceeded.
	LatencyThreshold time.Duration `yaml:"latency_threshold"`

	// FailureThreshold is the number of consecutive failures
	// before declaring degradation.
	FailureThreshold int `yaml:"failure_threshold"`
}

// DegradationCallback is called when connection quality drops.
type DegradationCallback func(p Protocol, reason string)

// Monitor watches active connections for signs of degradation
// such as increased latency, packet loss, or throttling.
type Monitor struct {
	config   MonitorConfig
	callback DegradationCallback
	logger   *slog.Logger
	stopCh   chan struct{}
	mu       sync.Mutex
	watching bool
}

// NewMonitor creates a connection health monitor.
func NewMonitor(cfg MonitorConfig, cb DegradationCallback, logger *slog.Logger) *Monitor {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 10 * time.Second
	}
	if cfg.LatencyThreshold == 0 {
		cfg.LatencyThreshold = 2 * time.Second
	}
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = 3
	}

	return &Monitor{
		config:   cfg,
		callback: cb,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Watch starts monitoring the given connection. Only one connection
// can be monitored at a time; calling Watch again replaces the
// previous watch.
func (m *Monitor) Watch(conn net.Conn, p Protocol) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.watching {
		m.stopCh <- struct{}{}
	}

	m.watching = true
	go m.watchLoop(conn, p)
}

func (m *Monitor) watchLoop(conn net.Conn, p Protocol) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	failures := 0

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			start := time.Now()

			// Set a short deadline for the health check
			err := conn.SetReadDeadline(time.Now().Add(m.config.LatencyThreshold))
			if err != nil {
				failures++
				if failures >= m.config.FailureThreshold {
					m.callback(p, "connection unresponsive")
					return
				}
				continue
			}

			latency := time.Since(start)

			if latency > m.config.LatencyThreshold {
				failures++
				m.logger.Debug("high latency detected",
					"protocol", p.Name(),
					"latency", latency,
					"threshold", m.config.LatencyThreshold,
				)
			} else {
				failures = 0
			}

			if failures >= m.config.FailureThreshold {
				m.callback(p, "sustained high latency")
				return
			}

			// Reset deadline
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
}

// Stop terminates all monitoring.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.watching {
		m.stopCh <- struct{}{}
		m.watching = false
	}
}
