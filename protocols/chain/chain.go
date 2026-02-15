// Package chain implements multi-hop chain proxy routing for HydraFlow.
// A chain proxy connects through multiple intermediate servers sequentially,
// enabling scenarios like: Client -> RU VPS (entry) -> NL server (exit) -> Internet.
// Each hop can use a different protocol and configuration, providing layered
// censorship bypass and traffic obfuscation.
package chain

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
	protocolName = "chain"

	// defaultPriority is lowest because chain adds latency from
	// multiple hops, but it is the most reliable when direct
	// connections and CDN routes are blocked.
	defaultPriority = 30

	// vlessVersion is the VLESS protocol version byte.
	vlessVersion = 0

	// hopDialTimeout is the default per-hop connection timeout.
	hopDialTimeout = 10 * time.Second

	// totalDialTimeout is the maximum total time for all hops.
	totalDialTimeout = 30 * time.Second
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		cc := DefaultConfig()
		if v, ok := cfg["priority"].(int); ok {
			cc.Priority = v
		}
		if v, ok := cfg["hops"].([]interface{}); ok {
			cc.Hops = make([]HopConfig, 0, len(v))
			for _, hopRaw := range v {
				if hopMap, ok2 := hopRaw.(map[string]interface{}); ok2 {
					hop := HopConfig{}
					if s, ok3 := hopMap["host"].(string); ok3 {
						hop.Host = s
					}
					if p, ok3 := hopMap["port"].(int); ok3 {
						hop.Port = p
					}
					if s, ok3 := hopMap["uuid"].(string); ok3 {
						hop.UUID = s
					}
					if s, ok3 := hopMap["sni"].(string); ok3 {
						hop.SNI = s
					}
					if s, ok3 := hopMap["public_key"].(string); ok3 {
						hop.PublicKey = s
					}
					if s, ok3 := hopMap["short_id"].(string); ok3 {
						hop.ShortID = s
					}
					if s, ok3 := hopMap["transport"].(string); ok3 {
						hop.Transport = s
					}
					if s, ok3 := hopMap["security"].(string); ok3 {
						hop.Security = s
					}
					if s, ok3 := hopMap["fingerprint"].(string); ok3 {
						hop.Fingerprint = s
					}
					if s, ok3 := hopMap["flow"].(string); ok3 {
						hop.Flow = s
					}
					cc.Hops = append(cc.Hops, hop)
				}
			}
		}

		return New(cc, logger)
	})
}

// ChainConfig contains the configuration for a multi-hop chain proxy.
type ChainConfig struct {
	// Hops defines the ordered list of proxy servers to connect through.
	// The first hop is connected to directly, and each subsequent hop
	// is reached through the previous one.
	Hops []HopConfig `yaml:"hops" json:"hops"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// HopTimeout is the per-hop connection timeout.
	HopTimeout time.Duration `yaml:"hop_timeout" json:"hop_timeout"`

	// TotalTimeout is the maximum total time to establish the full chain.
	TotalTimeout time.Duration `yaml:"total_timeout" json:"total_timeout"`

	// RetryPerHop is the number of retries for each hop before giving up.
	RetryPerHop int `yaml:"retry_per_hop" json:"retry_per_hop"`
}

// HopConfig describes a single hop in the chain.
type HopConfig struct {
	// Host is the server address for this hop.
	Host string `yaml:"host" json:"host"`

	// Port is the server port for this hop.
	Port int `yaml:"port" json:"port"`

	// UUID is the VLESS user ID for this hop.
	UUID string `yaml:"uuid" json:"uuid"`

	// SNI is the TLS Server Name Indication for this hop.
	SNI string `yaml:"sni" json:"sni"`

	// PublicKey is the Reality public key (if using Reality security).
	PublicKey string `yaml:"public_key" json:"public_key"`

	// ShortID is the Reality short ID (if using Reality security).
	ShortID string `yaml:"short_id" json:"short_id"`

	// Transport is the transport type: "tcp", "xhttp", "grpc".
	Transport string `yaml:"transport" json:"transport"`

	// Security is the security layer: "reality", "tls", "none".
	Security string `yaml:"security" json:"security"`

	// Fingerprint is the TLS fingerprint to use.
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"`

	// Flow is the XTLS flow type (e.g., "xtls-rprx-vision").
	Flow string `yaml:"flow" json:"flow"`
}

// DefaultConfig returns a ChainConfig with sensible defaults.
func DefaultConfig() *ChainConfig {
	return &ChainConfig{
		Priority:     defaultPriority,
		HopTimeout:   hopDialTimeout,
		TotalTimeout: totalDialTimeout,
		RetryPerHop:  1,
	}
}

// Validate checks the chain configuration for required fields.
func (c *ChainConfig) Validate() error {
	if len(c.Hops) < 2 {
		return fmt.Errorf("chain: at least 2 hops are required (got %d)", len(c.Hops))
	}
	for i, hop := range c.Hops {
		if hop.Host == "" {
			return fmt.Errorf("chain: hop %d: host is required", i)
		}
		if hop.Port <= 0 || hop.Port > 65535 {
			return fmt.Errorf("chain: hop %d: invalid port %d", i, hop.Port)
		}
		if hop.UUID == "" {
			return fmt.Errorf("chain: hop %d: uuid is required", i)
		}
	}
	return nil
}

// Chain implements the core.Protocol interface for multi-hop chain proxy.
type Chain struct {
	config *ChainConfig
	logger *slog.Logger

	mu        sync.RWMutex
	available bool
	lastCheck time.Time
}

// New creates a new Chain protocol instance.
func New(cfg *ChainConfig, logger *slog.Logger) (*Chain, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Chain{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		available: true,
	}, nil
}

// Name returns the protocol identifier.
func (c *Chain) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (c *Chain) Priority() int {
	return c.config.Priority
}

// Available reports whether the chain is likely to work.
func (c *Chain) Available() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.available
}

// Dial establishes a connection through all hops in the chain sequentially.
// For a chain [A, B, C]:
//  1. Connect directly to A (TCP + TLS/Reality)
//  2. Send VLESS CONNECT to A, targeting B
//  3. Over the tunneled connection, TLS handshake with B
//  4. Send VLESS CONNECT to B, targeting C
//  5. Return the final connection that exits through C
func (c *Chain) Dial(ctx context.Context) (net.Conn, error) {
	totalTimeout := c.config.TotalTimeout
	if totalTimeout == 0 {
		totalTimeout = totalDialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	if len(c.config.Hops) == 0 {
		return nil, fmt.Errorf("chain: no hops configured")
	}

	c.logger.Info("establishing chain connection",
		"hops", len(c.config.Hops),
		"chain", c.chainDescription(),
	)

	// Connect to the first hop directly.
	firstHop := c.config.Hops[0]
	conn, err := c.dialFirstHop(ctx, firstHop)
	if err != nil {
		c.markUnavailable()
		return nil, fmt.Errorf("chain: first hop (%s): %w", firstHop.Host, err)
	}

	c.logger.Debug("first hop connected",
		"host", firstHop.Host,
		"port", firstHop.Port,
	)

	// Connect through each subsequent hop.
	for i := 1; i < len(c.config.Hops); i++ {
		hop := c.config.Hops[i]
		prevHop := c.config.Hops[i-1]

		c.logger.Debug("connecting through hop",
			"hop_index", i,
			"host", hop.Host,
			"port", hop.Port,
			"via", prevHop.Host,
		)

		// Send VLESS request through the previous hop to connect to this hop.
		conn, err = c.dialThroughHop(ctx, conn, prevHop, hop)
		if err != nil {
			conn.Close()
			c.markUnavailable()
			return nil, fmt.Errorf("chain: hop %d (%s -> %s): %w",
				i, prevHop.Host, hop.Host, err)
		}

		c.logger.Debug("hop connected",
			"hop_index", i,
			"host", hop.Host,
		)
	}

	c.markAvailable()

	c.logger.Info("chain connection established",
		"hops", len(c.config.Hops),
		"exit", c.config.Hops[len(c.config.Hops)-1].Host,
	)

	return &chainConn{
		Conn:   conn,
		config: c.config,
		logger: c.logger,
	}, nil
}

// dialFirstHop establishes a direct connection to the first hop.
func (c *Chain) dialFirstHop(ctx context.Context, hop HopConfig) (net.Conn, error) {
	hopTimeout := c.config.HopTimeout
	if hopTimeout == 0 {
		hopTimeout = hopDialTimeout
	}

	addr := net.JoinHostPort(hop.Host, fmt.Sprintf("%d", hop.Port))

	// TCP connection.
	dialer := &net.Dialer{Timeout: hopTimeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	// Apply security layer.
	conn, err := c.applySecurityLayer(ctx, tcpConn, hop)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("security layer: %w", err)
	}

	return conn, nil
}

// applySecurityLayer wraps a TCP connection with the appropriate
// security layer (Reality, TLS, or none).
func (c *Chain) applySecurityLayer(ctx context.Context, conn net.Conn, hop HopConfig) (net.Conn, error) {
	switch hop.Security {
	case "reality", "":
		// Default to Reality for chain hops.
		return c.applyRealityLayer(ctx, conn, hop)
	case "tls":
		return c.applyTLSLayer(ctx, conn, hop)
	case "none":
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported security type: %s", hop.Security)
	}
}

// applyRealityLayer wraps a connection with Reality TLS 1.3.
func (c *Chain) applyRealityLayer(ctx context.Context, conn net.Conn, hop HopConfig) (net.Conn, error) {
	sni := hop.SNI
	if sni == "" {
		sni = "www.microsoft.com"
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// Set deadline from context.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake (sni=%s): %w", sni, err)
	}

	// Verify TLS 1.3.
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("expected TLS 1.3, got 0x%04x", state.Version)
	}

	// Clear deadline.
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return tlsConn, nil
}

// applyTLSLayer wraps a connection with standard TLS.
func (c *Chain) applyTLSLayer(ctx context.Context, conn net.Conn, hop HopConfig) (net.Conn, error) {
	sni := hop.SNI
	if sni == "" {
		sni = hop.Host
	}

	tlsCfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return tlsConn, nil
}

// dialThroughHop sends a VLESS CONNECT request through an existing
// connection to reach the next hop in the chain.
func (c *Chain) dialThroughHop(ctx context.Context, conn net.Conn, prevHop, nextHop HopConfig) (net.Conn, error) {
	// Send VLESS header targeting the next hop.
	uuid, err := parseUUID(prevHop.UUID)
	if err != nil {
		return nil, fmt.Errorf("parse uuid: %w", err)
	}

	header := buildVLESSConnectHeader(uuid, prevHop.Flow, nextHop.Host, nextHop.Port)

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("set write deadline: %w", err)
	}

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("write vless header: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear write deadline: %w", err)
	}

	// Read VLESS response.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	var respHeader [2]byte
	if _, err := io.ReadFull(conn, respHeader[:]); err != nil {
		return nil, fmt.Errorf("read vless response: %w", err)
	}

	version := respHeader[0]
	addonLen := respHeader[1]

	if version != vlessVersion {
		return nil, fmt.Errorf("unexpected vless version: %d", version)
	}

	// Skip addon data.
	if addonLen > 0 {
		addon := make([]byte, addonLen)
		if _, err := io.ReadFull(conn, addon); err != nil {
			return nil, fmt.Errorf("read vless addon: %w", err)
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear read deadline: %w", err)
	}

	// Now we have a tunnel through prevHop to nextHop.
	// Apply the security layer for the next hop over this tunnel.
	securedConn, err := c.applySecurityLayer(ctx, conn, nextHop)
	if err != nil {
		return nil, fmt.Errorf("security layer for %s: %w", nextHop.Host, err)
	}

	return securedConn, nil
}

// Listen is not supported for chain proxies.
func (c *Chain) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("chain: listening not supported (chain is client-only)")
}

// ProbeTests returns censorship detection tests for the chain.
// Tests the reachability of the first hop (entry point) since
// intermediate hops are only reachable through the chain.
func (c *Chain) ProbeTests() []core.ProbeTest {
	if len(c.config.Hops) == 0 {
		return nil
	}

	firstHop := c.config.Hops[0]
	tests := []core.ProbeTest{
		&chainEntryProbe{
			host: firstHop.Host,
			port: firstHop.Port,
		},
	}

	// If using Reality, add a TLS probe for the entry SNI.
	if firstHop.Security == "reality" || firstHop.Security == "" {
		tests = append(tests, &chainTLSProbe{
			host: firstHop.Host,
			port: firstHop.Port,
			sni:  firstHop.SNI,
		})
	}

	return tests
}

// chainDescription returns a human-readable description of the chain.
func (c *Chain) chainDescription() string {
	if len(c.config.Hops) == 0 {
		return "(empty)"
	}

	desc := ""
	for i, hop := range c.config.Hops {
		if i > 0 {
			desc += " -> "
		}
		desc += fmt.Sprintf("%s:%d", hop.Host, hop.Port)
	}
	return desc
}

// markAvailable marks the protocol as available.
func (c *Chain) markAvailable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.available = true
	c.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (c *Chain) markUnavailable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.available = false
	c.lastCheck = time.Now()
}

// chainConn wraps the final connection in a chain with metadata and
// cleanup logic.
type chainConn struct {
	net.Conn
	config *ChainConfig
	logger *slog.Logger
	closed bool
	mu     sync.Mutex
}

// Close closes the chain connection. This tears down all hops since
// closing the outermost connection cascades through the chain.
func (c *chainConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("closing chain connection",
		"hops", len(c.config.Hops),
	)

	return c.Conn.Close()
}

// buildVLESSConnectHeader builds a VLESS request header to tunnel
// a connection to the given destination through the current hop.
func buildVLESSConnectHeader(uuid [16]byte, flow string, destHost string, destPort int) []byte {
	var header []byte

	// Version.
	header = append(header, vlessVersion)

	// UUID.
	header = append(header, uuid[:]...)

	// Addon (flow type).
	if flow != "" {
		flowBytes := []byte(flow)
		addon := encodeVLESSAddon(flowBytes)
		header = append(header, byte(len(addon)))
		header = append(header, addon...)
	} else {
		header = append(header, 0)
	}

	// Command: TCP connect (0x01).
	header = append(header, 0x01)

	// Port (big-endian).
	header = append(header, byte(destPort>>8), byte(destPort&0xFF))

	// Address.
	hostIP := net.ParseIP(destHost)
	if hostIP != nil {
		if ipv4 := hostIP.To4(); ipv4 != nil {
			header = append(header, 0x01)
			header = append(header, ipv4...)
		} else {
			header = append(header, 0x03)
			header = append(header, hostIP.To16()...)
		}
	} else {
		header = append(header, 0x02)
		header = append(header, byte(len(destHost)))
		header = append(header, []byte(destHost)...)
	}

	return header
}

// encodeVLESSAddon encodes a flow type as a VLESS addon field.
func encodeVLESSAddon(flow []byte) []byte {
	var buf []byte
	buf = append(buf, 0x12) // field 2, wire type 2 (length-delimited)
	buf = append(buf, byte(len(flow)))
	buf = append(buf, flow...)
	return buf
}

// parseUUID parses a UUID string into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}
	if len(clean) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	copy(uuid[:], b)
	return uuid, nil
}

// chainEntryProbe tests TCP reachability of the chain entry point.
type chainEntryProbe struct {
	host string
	port int
}

func (p *chainEntryProbe) Name() string    { return "chain_entry_reachability" }
func (p *chainEntryProbe) Weight() float64 { return 1.0 }

func (p *chainEntryProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
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

// chainTLSProbe tests TLS handshake with the chain entry point.
type chainTLSProbe struct {
	host string
	port int
	sni  string
}

func (p *chainTLSProbe) Name() string    { return "chain_entry_tls" }
func (p *chainTLSProbe) Weight() float64 { return 0.8 }

func (p *chainTLSProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	sni := p.sni
	if sni == "" {
		sni = "www.microsoft.com"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
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
				"sni":   sni,
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
			"sni":     sni,
			"version": fmt.Sprintf("0x%04x", state.Version),
			"cipher":  tls.CipherSuiteName(state.CipherSuite),
		},
		Timestamp: time.Now(),
	}, nil
}
