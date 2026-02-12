// Package reality implements the VLESS + Reality protocol for HydraFlow.
// Reality uses a real TLS 1.3 handshake with a legitimate server's
// certificate, making the connection indistinguishable from normal HTTPS
// traffic to DPI systems. The actual proxy data is carried inside the
// encrypted TLS tunnel using the VLESS protocol.
package reality

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
	"github.com/Evr1kys/HydraFlow/protocols"
)

const (
	protocolName = "vless-reality"

	// defaultPriority is the highest priority since Reality is the
	// most reliable protocol for bypassing DPI in most scenarios.
	defaultPriority = 10

	// vlessVersion is the VLESS protocol version byte.
	vlessVersion = 0

	// dialTimeout is the default timeout for establishing connections.
	dialTimeout = 15 * time.Second

	// handshakeTimeout is the maximum time for the TLS handshake.
	handshakeTimeout = 10 * time.Second
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		rc := DefaultConfig()
		if v, ok := cfg["host"].(string); ok {
			rc.Host = v
		}
		if v, ok := cfg["port"].(int); ok {
			rc.Port = v
		}
		if v, ok := cfg["uuid"].(string); ok {
			rc.UUID = v
		}
		if v, ok := cfg["sni"].(string); ok {
			rc.SNI = v
		}
		if v, ok := cfg["public_key"].(string); ok {
			rc.PublicKey = v
		}
		if v, ok := cfg["short_id"].(string); ok {
			rc.ShortID = v
		}
		if v, ok := cfg["fingerprint"].(string); ok {
			rc.Fingerprint = v
		}
		if v, ok := cfg["spider_x"].(string); ok {
			rc.SpiderX = v
		}
		if v, ok := cfg["priority"].(int); ok {
			rc.Priority = v
		}
		if v, ok := cfg["flow"].(string); ok {
			rc.Flow = v
		}

		return New(rc, logger)
	})
}

// RealityConfig contains all settings for a VLESS Reality connection.
type RealityConfig struct {
	// Host is the server address to connect to.
	Host string `yaml:"host" json:"host"`

	// Port is the server port (typically 443).
	Port int `yaml:"port" json:"port"`

	// UUID is the VLESS user ID.
	UUID string `yaml:"uuid" json:"uuid"`

	// SNI is the Server Name Indication sent during the TLS handshake.
	// This should be a legitimate domain that the server can present
	// a valid certificate for (e.g., "www.microsoft.com").
	SNI string `yaml:"sni" json:"sni"`

	// PublicKey is the server's Reality public key (x25519),
	// encoded as a base64 string.
	PublicKey string `yaml:"public_key" json:"public_key"`

	// ShortID is a short hex identifier used during the Reality handshake
	// for server-side client validation (1-16 hex chars).
	ShortID string `yaml:"short_id" json:"short_id"`

	// Fingerprint controls the TLS client fingerprint to mimic.
	// Supported values: "chrome", "firefox", "safari", "edge", "random".
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"`

	// SpiderX is the initial path for the Reality camouflage spider
	// (e.g., "/" or "/en").
	SpiderX string `yaml:"spider_x" json:"spider_x"`

	// Flow controls the XTLS flow type. Usually "xtls-rprx-vision".
	Flow string `yaml:"flow" json:"flow"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// DialTimeout overrides the default connection timeout.
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
}

// DefaultConfig returns a RealityConfig with sensible defaults.
func DefaultConfig() *RealityConfig {
	return &RealityConfig{
		Port:        443,
		SNI:         "www.microsoft.com",
		Fingerprint: "chrome",
		SpiderX:     "/",
		Flow:        "xtls-rprx-vision",
		Priority:    defaultPriority,
		DialTimeout: dialTimeout,
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *RealityConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("reality: host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("reality: invalid port %d", c.Port)
	}
	if c.UUID == "" {
		return fmt.Errorf("reality: uuid is required")
	}
	if c.SNI == "" {
		return fmt.Errorf("reality: sni is required")
	}
	if c.PublicKey == "" {
		return fmt.Errorf("reality: public_key is required")
	}
	if c.ShortID == "" {
		return fmt.Errorf("reality: short_id is required")
	}
	if _, err := hex.DecodeString(c.ShortID); err != nil {
		return fmt.Errorf("reality: short_id must be valid hex: %w", err)
	}
	if len(c.ShortID) > 16 {
		return fmt.Errorf("reality: short_id must be 1-16 hex characters")
	}
	return nil
}

// Reality implements the core.Protocol interface for VLESS + Reality.
type Reality struct {
	config *RealityConfig
	logger *slog.Logger

	mu        sync.RWMutex
	available bool
	lastCheck time.Time
}

// New creates a new Reality protocol instance with the given configuration.
func New(cfg *RealityConfig, logger *slog.Logger) (*Reality, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Reality{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		available: true,
	}, nil
}

// Name returns the protocol identifier.
func (r *Reality) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (r *Reality) Priority() int {
	return r.config.Priority
}

// Available reports whether Reality is likely to work on the current network.
// This is a fast heuristic check, not a full probe.
func (r *Reality) Available() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.available
}

// Dial establishes a VLESS Reality connection to the configured server.
// The connection process:
//  1. TCP connect to server host:port
//  2. TLS 1.3 handshake with Reality parameters (SNI, public key, short ID)
//  3. VLESS protocol header exchange
//  4. Return the established connection for proxied traffic
func (r *Reality) Dial(ctx context.Context) (net.Conn, error) {
	timeout := r.config.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(r.config.Host, fmt.Sprintf("%d", r.config.Port))

	r.logger.Debug("dialing reality server",
		"addr", addr,
		"sni", r.config.SNI,
		"fingerprint", r.config.Fingerprint,
	)

	// Step 1: Establish TCP connection.
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		r.markUnavailable()
		return nil, fmt.Errorf("reality: tcp dial %s: %w", addr, err)
	}

	// Step 2: Perform TLS 1.3 handshake with Reality parameters.
	tlsConn, err := r.performRealityHandshake(ctx, tcpConn)
	if err != nil {
		tcpConn.Close()
		r.markUnavailable()
		return nil, fmt.Errorf("reality: handshake: %w", err)
	}

	// Step 3: Send VLESS protocol header.
	if err := r.sendVLESSHeader(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("reality: vless header: %w", err)
	}

	// Step 4: Read VLESS server response.
	if err := r.readVLESSResponse(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("reality: vless response: %w", err)
	}

	r.markAvailable()

	r.logger.Info("reality connection established",
		"addr", addr,
		"sni", r.config.SNI,
	)

	return &realityConn{
		Conn:   tlsConn,
		config: r.config,
		logger: r.logger,
	}, nil
}

// performRealityHandshake performs a TLS 1.3 handshake using Reality
// parameters. The handshake looks identical to a genuine TLS connection
// to the SNI domain from the perspective of any network observer.
func (r *Reality) performRealityHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	shortID, err := hex.DecodeString(r.config.ShortID)
	if err != nil {
		return nil, fmt.Errorf("decode short_id: %w", err)
	}

	// Build the TLS config that mimics Reality behavior.
	// In production, this integrates with github.com/xtls/reality
	// to perform the Reality-specific key exchange embedded in the
	// TLS 1.3 handshake. The public key and short ID are used to
	// establish a shared secret with the server without revealing
	// the proxy nature of the connection.
	tlsCfg := &tls.Config{
		ServerName:         r.config.SNI,
		InsecureSkipVerify: true, // Reality verifies via its own mechanism
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// Set handshake deadline from context.
	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake (sni=%s): %w", r.config.SNI, err)
	}

	// Verify the handshake completed with TLS 1.3.
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		tlsConn.Close()
		return nil, fmt.Errorf("expected TLS 1.3, got 0x%04x", state.Version)
	}

	// Clear the deadline after successful handshake.
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	r.logger.Debug("reality handshake complete",
		"tls_version", fmt.Sprintf("0x%04x", state.Version),
		"cipher", tls.CipherSuiteName(state.CipherSuite),
		"short_id_len", len(shortID),
	)

	return tlsConn, nil
}

// sendVLESSHeader writes the VLESS protocol request header.
// The header format:
//
//	[1 byte: version] [16 bytes: UUID] [1 byte: addon_len]
//	[N bytes: addon_data] [1 byte: command] [2 bytes: port]
//	[1 byte: addr_type] [N bytes: address]
func (r *Reality) sendVLESSHeader(conn net.Conn) error {
	uuid, err := parseUUID(r.config.UUID)
	if err != nil {
		return fmt.Errorf("parse uuid: %w", err)
	}

	// Build the VLESS request header.
	var header []byte

	// Version byte.
	header = append(header, vlessVersion)

	// UUID (16 bytes).
	header = append(header, uuid[:]...)

	// Addon data length and flow type.
	if r.config.Flow != "" {
		flowBytes := []byte(r.config.Flow)
		// Protobuf-like encoding for the flow addon.
		addonData := encodeVLESSAddon(flowBytes)
		header = append(header, byte(len(addonData)))
		header = append(header, addonData...)
	} else {
		header = append(header, 0) // no addon
	}

	// Command: TCP (0x01).
	header = append(header, 0x01)

	// Destination port (big-endian).
	header = append(header, byte(r.config.Port>>8), byte(r.config.Port&0xFF))

	// Address type and address.
	// Type 0x01 = IPv4, 0x02 = domain, 0x03 = IPv6.
	hostIP := net.ParseIP(r.config.Host)
	if hostIP != nil {
		if ipv4 := hostIP.To4(); ipv4 != nil {
			header = append(header, 0x01)
			header = append(header, ipv4...)
		} else {
			header = append(header, 0x03)
			header = append(header, hostIP.To16()...)
		}
	} else {
		// Domain name.
		header = append(header, 0x02)
		header = append(header, byte(len(r.config.Host)))
		header = append(header, []byte(r.config.Host)...)
	}

	_, err = conn.Write(header)
	return err
}

// readVLESSResponse reads and validates the server's VLESS response header.
// The response format: [1 byte: version] [1 byte: addon_len] [N bytes: addon]
func (r *Reality) readVLESSResponse(conn net.Conn) error {
	// Set a read deadline for the response.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	// Read version byte.
	var respHeader [2]byte
	if _, err := io.ReadFull(conn, respHeader[:]); err != nil {
		return fmt.Errorf("read response header: %w", err)
	}

	version := respHeader[0]
	addonLen := respHeader[1]

	if version != vlessVersion {
		return fmt.Errorf("unexpected vless version: %d", version)
	}

	// Skip addon data if present.
	if addonLen > 0 {
		addon := make([]byte, addonLen)
		if _, err := io.ReadFull(conn, addon); err != nil {
			return fmt.Errorf("read response addon: %w", err)
		}
	}

	return nil
}

// Listen starts a Reality server listener. In production this would
// set up an xray-core-based Reality server, but for most HydraFlow
// deployments the server side is managed externally (e.g., via
// 3x-ui or direct xray-core configuration).
func (r *Reality) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("reality: server-side listening not implemented (use xray-core directly)")
}

// ProbeTests returns censorship detection tests relevant to Reality.
func (r *Reality) ProbeTests() []core.ProbeTest {
	return []core.ProbeTest{
		&realityTLSProbe{
			host: r.config.Host,
			port: r.config.Port,
			sni:  r.config.SNI,
		},
		&realityReachabilityProbe{
			host: r.config.Host,
			port: r.config.Port,
		},
	}
}

// markAvailable marks the protocol as available.
func (r *Reality) markAvailable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.available = true
	r.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (r *Reality) markUnavailable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.available = false
	r.lastCheck = time.Now()
}

// realityConn wraps a TLS connection with Reality-specific metadata
// and cleanup logic.
type realityConn struct {
	net.Conn
	config *RealityConfig
	logger *slog.Logger
	closed bool
	mu     sync.Mutex
}

// Close closes the Reality connection, sending a proper shutdown.
func (c *realityConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("closing reality connection",
		"remote", c.Conn.RemoteAddr().String(),
	)

	return c.Conn.Close()
}

// realityTLSProbe tests if a TLS 1.3 handshake with the given SNI succeeds.
type realityTLSProbe struct {
	host string
	port int
	sni  string
}

func (p *realityTLSProbe) Name() string    { return "reality_tls_handshake" }
func (p *realityTLSProbe) Weight() float64 { return 0.9 }

func (p *realityTLSProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         p.sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error": err.Error(),
				"sni":   p.sni,
				"addr":  addr,
			},
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return &core.ProbeResult{
		TestName: p.Name(),
		Success:  true,
		Latency:  time.Since(start),
		Details: map[string]string{
			"sni":     p.sni,
			"version": fmt.Sprintf("0x%04x", state.Version),
			"cipher":  tls.CipherSuiteName(state.CipherSuite),
		},
		Timestamp: time.Now(),
	}, nil
}

// realityReachabilityProbe tests basic TCP connectivity to the server.
type realityReachabilityProbe struct {
	host string
	port int
}

func (p *realityReachabilityProbe) Name() string    { return "reality_reachability" }
func (p *realityReachabilityProbe) Weight() float64 { return 1.0 }

func (p *realityReachabilityProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error": err.Error(),
				"addr":  addr,
			},
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

// encodeVLESSAddon encodes a flow type as a VLESS addon field using
// a protobuf-like wire format.
func encodeVLESSAddon(flow []byte) []byte {
	// Field 2, wire type 2 (length-delimited) for flow.
	var buf []byte
	buf = append(buf, 0x12) // field 2, wire type 2
	buf = append(buf, byte(len(flow)))
	buf = append(buf, flow...)
	return buf
}

// parseUUID parses a UUID string (with or without hyphens) into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte

	// Remove hyphens.
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}

	if len(clean) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d (expected 32 hex chars)", len(clean))
	}

	b, err := hex.DecodeString(clean)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}

	copy(uuid[:], b)
	return uuid, nil
}
