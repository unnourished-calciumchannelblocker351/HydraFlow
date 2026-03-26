package hydra

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
	"github.com/Evr1kys/HydraFlow/protocols"
)

const (
	protocolName    = "hydra"
	defaultPriority = 5
	dialTimeout     = 20 * time.Second
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		hc := DefaultHydraConfig()

		if v, ok := cfg["host"].(string); ok {
			hc.Host = v
		}
		if v, ok := cfg["port"].(int); ok {
			hc.Port = v
		}
		if v, ok := cfg["password"].(string); ok {
			hc.Password = v
		}
		if v, ok := cfg["uuid"].(string); ok {
			hc.UUID = v
		}
		if v, ok := cfg["token"].(string); ok {
			hc.Token = v
		}
		if v, ok := cfg["sni"].(string); ok {
			hc.SNI = v
		}
		if v, ok := cfg["ws_path"].(string); ok {
			hc.WSPath = v
		}
		if v, ok := cfg["grpc_service"].(string); ok {
			hc.GRPCService = v
		}
		if v, ok := cfg["priority"].(int); ok {
			hc.Priority = v
		}
		if v, ok := cfg["camouflage"].(bool); ok {
			hc.Camouflage.Enabled = v
		}
		if v, ok := cfg["camouflage_padding"].(bool); ok {
			hc.Camouflage.PaddingEnabled = v
		}
		if v, ok := cfg["transport_order"].([]interface{}); ok {
			hc.TransportOrder = make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					hc.TransportOrder = append(hc.TransportOrder, s)
				}
			}
		}

		return NewHydra(hc, logger)
	})
}

// HydraConfig contains all settings for a Hydra protocol connection.
type HydraConfig struct {
	// Host is the server address to connect to.
	Host string `yaml:"host" json:"host"`

	// Port is the server port (typically 443).
	Port int `yaml:"port" json:"port"`

	// Password is the authentication password (used with AuthPassword).
	Password string `yaml:"password" json:"password"`

	// UUID is the authentication UUID (used with AuthUUID).
	UUID string `yaml:"uuid" json:"uuid"`

	// Token is the authentication token (used with AuthToken).
	Token string `yaml:"token" json:"token"`

	// SNI is the Server Name Indication for TLS connections.
	// Should be a legitimate domain to avoid detection.
	SNI string `yaml:"sni" json:"sni"`

	// WSPath is the WebSocket upgrade path for the WS transport.
	WSPath string `yaml:"ws_path" json:"ws_path"`

	// GRPCService is the gRPC service path for the gRPC transport.
	GRPCService string `yaml:"grpc_service" json:"grpc_service"`

	// TransportOrder specifies the preferred transport order.
	// Values: "tls", "websocket", "grpc", "h2"
	TransportOrder []string `yaml:"transport_order" json:"transport_order"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// DialTimeout overrides the default connection timeout.
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// Camouflage controls traffic camouflage settings.
	Camouflage CamouflageConfig `yaml:"camouflage" json:"camouflage"`
}

// DefaultHydraConfig returns a config with sensible defaults.
func DefaultHydraConfig() *HydraConfig {
	return &HydraConfig{
		Port:           443,
		SNI:            "www.google.com",
		WSPath:         "/ws",
		GRPCService:    "/grpc.health.v1.Health/Check",
		TransportOrder: []string{"tls", "websocket", "grpc", "h2"},
		Priority:       defaultPriority,
		DialTimeout:    dialTimeout,
		Camouflage:     DefaultCamouflageConfig(),
	}
}

// Validate checks the configuration for required fields.
func (c *HydraConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("hydra: host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("hydra: invalid port %d", c.Port)
	}
	if c.Password == "" && c.UUID == "" && c.Token == "" {
		return fmt.Errorf("hydra: at least one auth method required (password, uuid, or token)")
	}
	if len(c.TransportOrder) == 0 {
		return fmt.Errorf("hydra: transport_order must not be empty")
	}
	for _, t := range c.TransportOrder {
		switch t {
		case "tls", "websocket", "grpc", "h2":
			// valid
		default:
			return fmt.Errorf("hydra: unknown transport %q", t)
		}
	}
	return nil
}

// authMethod returns the auth method byte and auth data from the config.
func (c *HydraConfig) authMethod() (byte, []byte, error) {
	switch {
	case c.UUID != "":
		uuid, err := parseHydraUUID(c.UUID)
		if err != nil {
			return 0, nil, err
		}
		return AuthUUID, uuid[:], nil
	case c.Token != "":
		return AuthToken, []byte(c.Token), nil
	case c.Password != "":
		return AuthPassword, []byte(c.Password), nil
	default:
		return 0, nil, fmt.Errorf("hydra: no auth configured")
	}
}

// Hydra implements the core.Protocol interface for the Hydra protocol.
type Hydra struct {
	config   *HydraConfig
	logger   *slog.Logger
	selector *TransportSelector
	timing   *TimingObfuscator
	fpPool   *FingerprintPool

	mu        sync.RWMutex
	available bool
	lastCheck time.Time
}

// NewHydra creates a new Hydra protocol instance.
func NewHydra(cfg *HydraConfig, logger *slog.Logger) (*Hydra, error) {
	if cfg == nil {
		cfg = DefaultHydraConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Build the transport list based on configured order.
	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	transports := buildTransports(cfg, timeout)

	return &Hydra{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		selector:  NewTransportSelector(transports, logger.With("protocol", protocolName)),
		timing:    NewTimingObfuscator(cfg.Camouflage),
		fpPool:    NewFingerprintPool(),
		available: true,
	}, nil
}

// buildTransports constructs the transport list from config.
func buildTransports(cfg *HydraConfig, timeout time.Duration) []Transport {
	transports := make([]Transport, 0, len(cfg.TransportOrder))

	for _, name := range cfg.TransportOrder {
		switch name {
		case "tls":
			transports = append(transports, NewTLSTransport(cfg.SNI, timeout))
		case "websocket":
			transports = append(transports, NewWSTransport(cfg.SNI, cfg.WSPath, timeout))
		case "grpc":
			transports = append(transports, NewGRPCTransport(cfg.SNI, cfg.GRPCService, timeout))
		case "h2":
			transports = append(transports, NewH2Transport(cfg.SNI, timeout))
		}
	}

	return transports
}

// Name returns the protocol identifier.
func (h *Hydra) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (h *Hydra) Priority() int {
	return h.config.Priority
}

// Available reports whether the Hydra protocol is likely to work.
func (h *Hydra) Available() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.available
}

// Dial establishes a Hydra connection with automatic transport fallback.
//
// The connection process:
//  1. Try the primary transport (TLS with random fingerprint)
//  2. If blocked, fall back to WebSocket transport
//  3. If that fails, fall back to gRPC
//  4. If that fails, try HTTP/2 CONNECT
//  5. Perform the Hydra handshake over whichever transport succeeded
//  6. Wrap the connection with traffic camouflage
func (h *Hydra) Dial(ctx context.Context) (net.Conn, error) {
	timeout := h.config.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(h.config.Host, fmt.Sprintf("%d", h.config.Port))

	h.logger.Debug("dialing hydra server",
		"addr", addr,
		"sni", h.config.SNI,
		"transports", h.config.TransportOrder,
	)

	// Step 1-4: Try transports in order with fallback.
	conn, transport, err := h.selector.Dial(ctx, addr)
	if err != nil {
		h.markUnavailable()
		return nil, fmt.Errorf("hydra: transport dial: %w", err)
	}

	h.logger.Debug("transport established",
		"transport", transport.Name(),
		"addr", addr,
	)

	// Step 5: Perform Hydra handshake.
	if err := h.performHandshake(conn); err != nil {
		conn.Close()
		h.markUnavailable()
		return nil, fmt.Errorf("hydra: handshake: %w", err)
	}

	h.markAvailable()

	h.logger.Info("hydra connection established",
		"addr", addr,
		"transport", transport.Name(),
	)

	// Step 6: Wrap with camouflage.
	return &hydraConn{
		Conn:      conn,
		config:    h.config,
		logger:    h.logger,
		transport: transport,
		writer:    NewCamouflageWriter(conn, h.config.Camouflage),
		reader:    NewCamouflageReader(conn, h.config.Camouflage),
		timing:    h.timing,
	}, nil
}

// performHandshake sends the Hydra protocol handshake and reads the
// server's response.
func (h *Hydra) performHandshake(conn net.Conn) error {
	authMethod, authData, err := h.config.authMethod()
	if err != nil {
		return err
	}

	// Determine transport hint from the active connection.
	transportHint := TransportHintAuto

	handshake := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    authMethod,
		AuthData:      authData,
		TransportHint: transportHint,
	}

	if err := WriteHandshake(conn, handshake); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// Read server response handshake.
	resp, err := ReadHandshake(conn)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	if resp.Version != HydraVersion {
		return fmt.Errorf("version mismatch: got %d, expected %d", resp.Version, HydraVersion)
	}

	// AuthMethod 0x00 in response means "accepted".
	if resp.AuthMethod != 0x00 {
		return fmt.Errorf("auth rejected: method=0x%02x", resp.AuthMethod)
	}

	return nil
}

// Listen starts a Hydra server listener that accepts incoming connections,
// performs the handshake, and returns unwrapped connections.
func (h *Hydra) Listen(ctx context.Context, addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("hydra: listen: %w", err)
	}

	return &hydraListener{
		Listener: listener,
		config:   h.config,
		logger:   h.logger,
		fpPool:   h.fpPool,
	}, nil
}

// ProbeTests returns censorship detection tests relevant to Hydra.
func (h *Hydra) ProbeTests() []core.ProbeTest {
	return []core.ProbeTest{
		&hydraTLSProbe{
			host: h.config.Host,
			port: h.config.Port,
			sni:  h.config.SNI,
		},
		&hydraReachabilityProbe{
			host: h.config.Host,
			port: h.config.Port,
		},
	}
}

// markAvailable marks the protocol as available.
func (h *Hydra) markAvailable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.available = true
	h.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (h *Hydra) markUnavailable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.available = false
	h.lastCheck = time.Now()
}

// hydraConn wraps a transport connection with the Hydra protocol layer
// including camouflage, framing, and timing obfuscation.
type hydraConn struct {
	net.Conn
	config    *HydraConfig
	logger    *slog.Logger
	transport Transport
	writer    *CamouflageWriter
	reader    *CamouflageReader
	timing    *TimingObfuscator
	closed    bool
	mu        sync.Mutex
}

// Write sends data through the camouflage writer with optional timing jitter.
func (c *hydraConn) Write(p []byte) (int, error) {
	if c.timing.ShouldDelay() {
		c.timing.Delay()
	}
	return c.writer.Write(p)
}

// Read reads data through the camouflage reader.
func (c *hydraConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Close sends a CLOSE frame and shuts down the connection.
func (c *hydraConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	transportName := "unknown"
	if c.transport != nil {
		transportName = c.transport.Name()
	}
	c.logger.Debug("closing hydra connection",
		"remote", c.Conn.RemoteAddr().String(),
		"transport", transportName,
	)

	// Best-effort: send a close frame.
	closeFrame := &Frame{
		Type:       FrameClose,
		Payload:    nil,
		PaddingLen: 0,
	}
	_ = WriteFrame(c.Conn, closeFrame)

	return c.Conn.Close()
}

// hydraListener wraps a TCP listener with Hydra protocol handling.
type hydraListener struct {
	net.Listener
	config *HydraConfig
	logger *slog.Logger
	fpPool *FingerprintPool
}

// Accept accepts a connection and performs the Hydra server-side handshake.
func (l *hydraListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Read client handshake.
	handshake, err := ReadHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("hydra: read client handshake: %w", err)
	}

	// Validate version.
	if handshake.Version != HydraVersion {
		conn.Close()
		return nil, fmt.Errorf("hydra: unsupported version %d", handshake.Version)
	}

	// Validate auth.
	if !l.validateAuth(handshake) {
		// Send rejection.
		resp := &Handshake{
			Version:       HydraVersion,
			AuthMethod:    0xFF, // rejected
			AuthData:      nil,
			TransportHint: TransportHintAuto,
		}
		WriteHandshake(conn, resp) //nolint:errcheck
		conn.Close()
		return nil, fmt.Errorf("hydra: auth failed")
	}

	// Send acceptance.
	resp := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    0x00, // accepted
		AuthData:      nil,
		TransportHint: TransportHintAuto,
	}
	if err := WriteHandshake(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("hydra: send acceptance: %w", err)
	}

	l.logger.Debug("hydra client accepted",
		"remote", conn.RemoteAddr().String(),
		"auth_method", fmt.Sprintf("0x%02x", handshake.AuthMethod),
	)

	return &hydraConn{
		Conn:   conn,
		config: l.config,
		logger: l.logger,
		writer: NewCamouflageWriter(conn, l.config.Camouflage),
		reader: NewCamouflageReader(conn, l.config.Camouflage),
		timing: NewTimingObfuscator(l.config.Camouflage),
	}, nil
}

// validateAuth checks the client's auth credentials against the config.
func (l *hydraListener) validateAuth(h *Handshake) bool {
	switch h.AuthMethod {
	case AuthPassword:
		return l.config.Password != "" && string(h.AuthData) == l.config.Password
	case AuthUUID:
		if l.config.UUID == "" {
			return false
		}
		expected, err := parseHydraUUID(l.config.UUID)
		if err != nil {
			return false
		}
		if len(h.AuthData) != 16 {
			return false
		}
		for i := range expected {
			if expected[i] != h.AuthData[i] {
				return false
			}
		}
		return true
	case AuthToken:
		return l.config.Token != "" && string(h.AuthData) == l.config.Token
	default:
		return false
	}
}

// parseHydraUUID parses a UUID string into 16 bytes.
func parseHydraUUID(s string) ([16]byte, error) {
	var uuid [16]byte

	// Remove hyphens.
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}

	if len(clean) != 32 {
		return uuid, fmt.Errorf("hydra: invalid UUID length: %d (expected 32 hex chars)", len(clean))
	}

	b, err := hex.DecodeString(clean)
	if err != nil {
		return uuid, fmt.Errorf("hydra: invalid UUID hex: %w", err)
	}

	copy(uuid[:], b)
	return uuid, nil
}

// hydraTLSProbe tests if a TLS handshake with the given SNI succeeds.
type hydraTLSProbe struct {
	host string
	port int
	sni  string
}

func (p *hydraTLSProbe) Name() string    { return "hydra_tls_handshake" }
func (p *hydraTLSProbe) Weight() float64 { return 0.9 }

func (p *hydraTLSProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	pool := NewFingerprintPool()
	fp := pool.RandomFingerprint()
	tlsCfg := fp.ToTLSConfig(p.sni)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &core.ProbeResult{
			TestName:  p.Name(),
			Success:   false,
			Latency:   time.Since(start),
			Details:   map[string]string{"error": err.Error(), "addr": addr},
			Timestamp: time.Now(),
		}, nil
	}
	defer tcpConn.Close()

	conn := tls.Client(tcpConn, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error":       err.Error(),
				"sni":         p.sni,
				"fingerprint": fp.Name,
			},
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	return &core.ProbeResult{
		TestName: p.Name(),
		Success:  true,
		Latency:  time.Since(start),
		Details: map[string]string{
			"sni":         p.sni,
			"fingerprint": fp.Name,
		},
		Timestamp: time.Now(),
	}, nil
}

// hydraReachabilityProbe tests basic TCP connectivity.
type hydraReachabilityProbe struct {
	host string
	port int
}

func (p *hydraReachabilityProbe) Name() string    { return "hydra_reachability" }
func (p *hydraReachabilityProbe) Weight() float64 { return 1.0 }

func (p *hydraReachabilityProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return &core.ProbeResult{
			TestName:  p.Name(),
			Success:   false,
			Latency:   time.Since(start),
			Details:   map[string]string{"error": err.Error(), "addr": addr},
			Timestamp: time.Now(),
		}, nil
	}
	conn.Close()

	return &core.ProbeResult{
		TestName:  p.Name(),
		Success:   true,
		Latency:   time.Since(start),
		Details:   map[string]string{"addr": addr},
		Timestamp: time.Now(),
	}, nil
}
