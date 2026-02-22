// Package server implements the HydraFlow server that runs multiple
// protocol inbound listeners simultaneously, managing their lifecycle,
// health checking, and configuration reloading.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
)

// ServerConfig is the top-level server configuration.
type ServerConfig struct {
	// Listen is the primary address for protocol listeners.
	Listen string `yaml:"listen"`

	// HealthAddr is the address for the health check endpoint.
	HealthAddr string `yaml:"health_addr"`

	// Inbounds defines the protocol listeners to start.
	Inbounds []InboundConfig `yaml:"inbounds"`

	// Subscription configures the subscription endpoint.
	Subscription SubEndpointConfig `yaml:"subscription"`

	// LogLevel sets logging verbosity.
	LogLevel string `yaml:"log_level"`
}

// InboundConfig describes a single protocol inbound listener.
type InboundConfig struct {
	// Tag is a unique identifier for this inbound.
	Tag string `yaml:"tag"`

	// Protocol is the protocol type: reality, xhttp, hysteria2.
	Protocol string `yaml:"protocol"`

	// Listen is the address to listen on (overrides server-level).
	Listen string `yaml:"listen"`

	// Port is the port number.
	Port int `yaml:"port"`

	// Settings holds protocol-specific configuration.
	Settings map[string]interface{} `yaml:"settings"`
}

// SubEndpointConfig configures the subscription HTTP endpoint.
type SubEndpointConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Token   string `yaml:"token"`
}

// inboundState tracks a running inbound listener.
type inboundState struct {
	tag      string
	protocol string
	listener net.Listener
	cancel   context.CancelFunc
}

// Server manages multiple protocol inbound listeners and provides
// lifecycle management including start, stop, and hot-reload.
type Server struct {
	mu     sync.RWMutex
	config *ServerConfig
	logger *slog.Logger

	inbounds    map[string]*inboundState
	protocols   map[string]core.Protocol
	healthSrv   *http.Server
	startedAt   time.Time
	connections int64

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new Server with the given configuration and logger.
func New(cfg *ServerConfig, logger *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server config is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.HealthAddr == "" {
		cfg.HealthAddr = "127.0.0.1:10085"
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:    cfg,
		logger:    logger,
		inbounds:  make(map[string]*inboundState),
		protocols: make(map[string]core.Protocol),
		ctx:       ctx,
		cancel:    cancel,
	}

	return s, nil
}

// RegisterProtocol registers a protocol implementation that can be used
// by inbound listeners. The name must match the protocol field in InboundConfig.
func (s *Server) RegisterProtocol(name string, p core.Protocol) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocols[name] = p
	s.logger.Info("server protocol registered", "name", name)
}

// Start initializes all inbound listeners and the health check endpoint.
// It blocks until the context is cancelled or Stop is called.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.startedAt = time.Now()
	s.mu.Unlock()

	s.logger.Info("starting HydraFlow server",
		"inbounds", len(s.config.Inbounds),
		"health_addr", s.config.HealthAddr,
	)

	// Start health check endpoint.
	if err := s.startHealthCheck(); err != nil {
		return fmt.Errorf("start health check: %w", err)
	}

	// Start all configured inbound listeners.
	var startErrors []error
	for _, inCfg := range s.config.Inbounds {
		if err := s.startInbound(ctx, inCfg); err != nil {
			s.logger.Error("failed to start inbound",
				"tag", inCfg.Tag,
				"protocol", inCfg.Protocol,
				"error", err,
			)
			startErrors = append(startErrors, fmt.Errorf("inbound %s: %w", inCfg.Tag, err))
		}
	}

	if len(startErrors) == len(s.config.Inbounds) && len(s.config.Inbounds) > 0 {
		return fmt.Errorf("all inbounds failed to start: %w", errors.Join(startErrors...))
	}

	for _, err := range startErrors {
		s.logger.Warn("partial start failure", "error", err)
	}

	s.logger.Info("server started",
		"active_inbounds", len(s.inbounds),
		"failed_inbounds", len(startErrors),
	)

	// Block until context is done.
	select {
	case <-ctx.Done():
		s.logger.Info("server context cancelled, shutting down")
	case <-s.ctx.Done():
		s.logger.Info("server stop requested")
	}

	return s.shutdown()
}

// Stop gracefully shuts down the server and all listeners.
func (s *Server) Stop() error {
	s.cancel()
	return nil
}

// Reload re-reads the configuration and applies changes. New inbounds
// are started, removed inbounds are stopped, and unchanged inbounds
// are left running.
func (s *Server) Reload(newCfg *ServerConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("reloading server configuration")

	// Determine which inbounds to add, remove, or keep.
	newTags := make(map[string]InboundConfig)
	for _, in := range newCfg.Inbounds {
		newTags[in.Tag] = in
	}

	// Stop removed inbounds.
	for tag, state := range s.inbounds {
		if _, exists := newTags[tag]; !exists {
			s.logger.Info("stopping removed inbound", "tag", tag)
			state.cancel()
			if state.listener != nil {
				state.listener.Close()
			}
			delete(s.inbounds, tag)
		}
	}

	// Start new inbounds.
	for tag, inCfg := range newTags {
		if _, exists := s.inbounds[tag]; !exists {
			s.logger.Info("starting new inbound", "tag", tag)
			if err := s.startInbound(s.ctx, inCfg); err != nil {
				s.logger.Error("failed to start new inbound on reload",
					"tag", tag,
					"error", err,
				)
			}
		}
	}

	s.config = newCfg
	s.logger.Info("reload complete", "active_inbounds", len(s.inbounds))
	return nil
}

// ActiveInbounds returns the tags of currently running inbounds.
func (s *Server) ActiveInbounds() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tags := make([]string, 0, len(s.inbounds))
	for tag := range s.inbounds {
		tags = append(tags, tag)
	}
	return tags
}

// startInbound creates and starts a single protocol inbound listener.
func (s *Server) startInbound(parentCtx context.Context, cfg InboundConfig) error {
	proto, ok := s.protocols[cfg.Protocol]
	if !ok {
		return fmt.Errorf("unknown protocol: %s", cfg.Protocol)
	}

	listenAddr := cfg.Listen
	if listenAddr == "" {
		listenAddr = s.config.Listen
	}
	if cfg.Port > 0 {
		host, _, _ := net.SplitHostPort(listenAddr)
		if host == "" {
			host = "0.0.0.0"
		}
		listenAddr = fmt.Sprintf("%s:%d", host, cfg.Port)
	}

	if listenAddr == "" {
		return fmt.Errorf("no listen address for inbound %s", cfg.Tag)
	}

	ctx, cancel := context.WithCancel(parentCtx)

	listener, err := proto.Listen(ctx, listenAddr)
	if err != nil {
		cancel()
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	state := &inboundState{
		tag:      cfg.Tag,
		protocol: cfg.Protocol,
		listener: listener,
		cancel:   cancel,
	}

	s.mu.Lock()
	s.inbounds[cfg.Tag] = state
	s.mu.Unlock()

	s.logger.Info("inbound started",
		"tag", cfg.Tag,
		"protocol", cfg.Protocol,
		"address", listenAddr,
	)

	// Accept connections in a goroutine.
	go s.acceptLoop(ctx, state)

	return nil
}

// acceptLoop handles incoming connections for an inbound listener.
func (s *Server) acceptLoop(ctx context.Context, state *inboundState) {
	defer func() {
		s.logger.Info("inbound accept loop exiting", "tag", state.tag)
	}()

	for {
		conn, err := state.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Temporary error: retry after a brief pause.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				s.logger.Debug("temporary accept error, retrying",
					"tag", state.tag,
					"error", err,
				)
				time.Sleep(50 * time.Millisecond)
				continue
			}

			s.logger.Error("accept error",
				"tag", state.tag,
				"error", err,
			)
			return
		}

		s.mu.Lock()
		s.connections++
		s.mu.Unlock()

		go s.handleConnection(ctx, state, conn)
	}
}

// handleConnection processes a single inbound connection.
func (s *Server) handleConnection(ctx context.Context, state *inboundState, conn net.Conn) {
	defer conn.Close()

	s.logger.Debug("new connection",
		"tag", state.tag,
		"remote", conn.RemoteAddr().String(),
	)

	// The actual proxying logic depends on the protocol implementation.
	// Each protocol's Listen() returns connections that are already
	// decrypted/decoded, so here we relay data to the target.
	//
	// For a full implementation, this would include:
	// 1. Parse the proxy request (VLESS header, etc.)
	// 2. Dial the target
	// 3. Bidirectional relay
	//
	// The relay is protocol-agnostic since Listen() handles protocol specifics.

	select {
	case <-ctx.Done():
		return
	}
}

// startHealthCheck starts the HTTP health check endpoint.
func (s *Server) startHealthCheck() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)

	s.healthSrv = &http.Server{
		Addr:              s.config.HealthAddr,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ln, err := net.Listen("tcp", s.config.HealthAddr)
	if err != nil {
		return fmt.Errorf("listen health: %w", err)
	}

	go func() {
		if err := s.healthSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("health server error", "error", err)
		}
	}()

	s.logger.Info("health endpoint started", "addr", s.config.HealthAddr)
	return nil
}

// handleHealth responds to health check requests with a simple OK.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	activeCount := len(s.inbounds)
	s.mu.RUnlock()

	if activeCount == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "no active inbounds")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// statusResponse is the JSON structure for the /status endpoint.
type statusResponse struct {
	Status      string        `json:"status"`
	Uptime      string        `json:"uptime"`
	Inbounds    []inboundInfo `json:"inbounds"`
	Connections int64         `json:"total_connections"`
}

type inboundInfo struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

// handleStatus returns a detailed JSON status of the server.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inbounds := make([]inboundInfo, 0, len(s.inbounds))
	for _, state := range s.inbounds {
		inbounds = append(inbounds, inboundInfo{
			Tag:      state.tag,
			Protocol: state.protocol,
		})
	}

	status := "healthy"
	if len(s.inbounds) == 0 {
		status = "degraded"
	}

	resp := statusResponse{
		Status:      status,
		Uptime:      time.Since(s.startedAt).Round(time.Second).String(),
		Inbounds:    inbounds,
		Connections: s.connections,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to write status response", "error", err)
	}
}

// shutdown gracefully shuts down all listeners and the health server.
func (s *Server) shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("shutting down server")

	// Stop health check server.
	if s.healthSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.healthSrv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("health server shutdown error", "error", err)
		}
	}

	// Stop all inbound listeners.
	var errs []error
	for tag, state := range s.inbounds {
		s.logger.Info("stopping inbound", "tag", tag)
		state.cancel()
		if state.listener != nil {
			if err := state.listener.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close inbound %s: %w", tag, err))
			}
		}
	}

	s.inbounds = make(map[string]*inboundState)
	s.logger.Info("server shutdown complete")

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
