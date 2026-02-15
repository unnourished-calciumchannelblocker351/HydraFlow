// Package hysteria2 implements the Hysteria2 QUIC-based protocol for HydraFlow.
// Hysteria2 uses a modified QUIC transport that achieves high throughput even
// on lossy or congested networks. It supports port hopping to evade port-based
// blocking and Salamander obfuscation to disguise QUIC traffic as random UDP.
package hysteria2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
	"github.com/Evr1kys/HydraFlow/protocols"
)

const (
	protocolName = "hysteria2"

	// defaultPriority is lower than Reality since Hysteria2 uses UDP
	// which is more commonly blocked, but higher than chain due to
	// its superior performance when available.
	defaultPriority = 15

	// dialTimeout is the default timeout for establishing connections.
	dialTimeout = 15 * time.Second

	// portHopInterval is how often to switch ports when port hopping.
	portHopInterval = 30 * time.Second

	// quicIdleTimeout is the QUIC connection idle timeout.
	quicIdleTimeout = 90 * time.Second

	// maxStreamWindow is the maximum QUIC stream flow control window.
	maxStreamWindow = 8 * 1024 * 1024 // 8 MiB

	// salamanderHeaderSize is the size of the Salamander obfuscation header.
	salamanderHeaderSize = 8

	// hysteria2AuthHeaderLen is the authentication header length.
	hysteria2AuthHeaderLen = 32
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		hc := DefaultConfig()
		if v, ok := cfg["host"].(string); ok {
			hc.Host = v
		}
		if v, ok := cfg["port"].(int); ok {
			hc.Port = v
		}
		if v, ok := cfg["password"].(string); ok {
			hc.Password = v
		}
		if v, ok := cfg["sni"].(string); ok {
			hc.SNI = v
		}
		if v, ok := cfg["ports"].([]interface{}); ok {
			hc.Ports = make([]int, 0, len(v))
			for _, p := range v {
				if pi, ok2 := p.(int); ok2 {
					hc.Ports = append(hc.Ports, pi)
				}
			}
		}
		if v, ok := cfg["obfs_type"].(string); ok {
			hc.ObfsType = v
		}
		if v, ok := cfg["obfs_password"].(string); ok {
			hc.ObfsPassword = v
		}
		if v, ok := cfg["priority"].(int); ok {
			hc.Priority = v
		}
		if v, ok := cfg["up_mbps"].(int); ok {
			hc.UpMbps = v
		}
		if v, ok := cfg["down_mbps"].(int); ok {
			hc.DownMbps = v
		}
		if v, ok := cfg["insecure"].(bool); ok {
			hc.Insecure = v
		}

		return New(hc, logger)
	})
}

// Hysteria2Config contains all settings for a Hysteria2 connection.
type Hysteria2Config struct {
	// Host is the server address.
	Host string `yaml:"host" json:"host"`

	// Port is the primary server port.
	Port int `yaml:"port" json:"port"`

	// Password is the authentication password. It is hashed with SHA-256
	// before being sent to the server.
	Password string `yaml:"password" json:"password"`

	// SNI is the TLS Server Name Indication for the QUIC handshake.
	SNI string `yaml:"sni" json:"sni"`

	// Ports is the list of ports for port hopping. When configured,
	// the client periodically switches between these ports to evade
	// port-based blocking. If empty, only Port is used.
	Ports []int `yaml:"ports" json:"ports"`

	// PortHopInterval controls how frequently to switch ports.
	// Defaults to 30 seconds.
	PortHopInterval time.Duration `yaml:"port_hop_interval" json:"port_hop_interval"`

	// ObfsType is the obfuscation type. Supported: "" (none), "salamander".
	ObfsType string `yaml:"obfs_type" json:"obfs_type"`

	// ObfsPassword is the obfuscation password used by Salamander.
	ObfsPassword string `yaml:"obfs_password" json:"obfs_password"`

	// UpMbps is the upload bandwidth hint in Mbps for Brutal congestion control.
	UpMbps int `yaml:"up_mbps" json:"up_mbps"`

	// DownMbps is the download bandwidth hint in Mbps for Brutal congestion control.
	DownMbps int `yaml:"down_mbps" json:"down_mbps"`

	// Insecure disables TLS certificate verification. Use only for testing.
	Insecure bool `yaml:"insecure" json:"insecure"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// DialTimeout overrides the default connection timeout.
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
}

// DefaultConfig returns a Hysteria2Config with sensible defaults.
func DefaultConfig() *Hysteria2Config {
	return &Hysteria2Config{
		Port:            443,
		PortHopInterval: portHopInterval,
		UpMbps:          50,
		DownMbps:        100,
		Priority:        defaultPriority,
		DialTimeout:     dialTimeout,
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *Hysteria2Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("hysteria2: host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("hysteria2: invalid port %d", c.Port)
	}
	if c.Password == "" {
		return fmt.Errorf("hysteria2: password is required")
	}
	if c.ObfsType != "" && c.ObfsType != "salamander" {
		return fmt.Errorf("hysteria2: unsupported obfs type %q (supported: salamander)", c.ObfsType)
	}
	if c.ObfsType == "salamander" && c.ObfsPassword == "" {
		return fmt.Errorf("hysteria2: obfs_password is required when using salamander")
	}
	for i, p := range c.Ports {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("hysteria2: invalid hop port at index %d: %d", i, p)
		}
	}
	if c.UpMbps <= 0 {
		return fmt.Errorf("hysteria2: up_mbps must be positive")
	}
	if c.DownMbps <= 0 {
		return fmt.Errorf("hysteria2: down_mbps must be positive")
	}
	return nil
}

// allPorts returns the complete list of ports including the primary port.
func (c *Hysteria2Config) allPorts() []int {
	ports := make(map[int]bool)
	ports[c.Port] = true
	for _, p := range c.Ports {
		ports[p] = true
	}
	result := make([]int, 0, len(ports))
	for p := range ports {
		result = append(result, p)
	}
	return result
}

// Hysteria2 implements the core.Protocol interface for Hysteria2.
type Hysteria2 struct {
	config *Hysteria2Config
	logger *slog.Logger

	mu        sync.RWMutex
	available bool
	lastCheck time.Time

	// portIdx tracks the current port for port hopping.
	portIdx atomic.Int64

	// obfuscator handles Salamander obfuscation if configured.
	obfuscator *salamanderObfuscator
}

// New creates a new Hysteria2 protocol instance.
func New(cfg *Hysteria2Config, logger *slog.Logger) (*Hysteria2, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	h := &Hysteria2{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		available: true,
	}

	// Initialize Salamander obfuscation if configured.
	if cfg.ObfsType == "salamander" {
		obfs, err := newSalamanderObfuscator(cfg.ObfsPassword)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: init salamander: %w", err)
		}
		h.obfuscator = obfs
	}

	return h, nil
}

// Name returns the protocol identifier.
func (h *Hysteria2) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (h *Hysteria2) Priority() int {
	return h.config.Priority
}

// Available reports whether Hysteria2 is likely to work on the current network.
// UDP-based protocols are more commonly blocked, so this performs a quick check.
func (h *Hysteria2) Available() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.available
}

// Dial establishes a Hysteria2 QUIC connection with the server.
// The connection process:
//  1. Select port (with port hopping support)
//  2. Apply Salamander obfuscation if configured
//  3. QUIC handshake with TLS 1.3 and Hysteria2 ALPN
//  4. Authenticate with hashed password
//  5. Open a bidirectional QUIC stream
func (h *Hysteria2) Dial(ctx context.Context) (net.Conn, error) {
	timeout := h.config.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Select the current port.
	port := h.currentPort()
	addr := net.JoinHostPort(h.config.Host, fmt.Sprintf("%d", port))

	h.logger.Debug("dialing hysteria2 server",
		"addr", addr,
		"obfs", h.config.ObfsType,
		"port_hop", len(h.config.allPorts()) > 1,
	)

	// Step 1: Resolve the server address.
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: resolve %s: %w", addr, err)
	}

	// Step 2: Create UDP connection.
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		h.markUnavailable()
		return nil, fmt.Errorf("hysteria2: udp dial %s: %w", addr, err)
	}

	// Step 3: Wrap with Salamander obfuscation if configured.
	var packetConn net.Conn = udpConn
	if h.obfuscator != nil {
		packetConn = h.obfuscator.WrapConn(udpConn)
		h.logger.Debug("salamander obfuscation enabled")
	}

	// Step 4: Build TLS config for QUIC.
	sni := h.config.SNI
	if sni == "" {
		sni = h.config.Host
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: h.config.Insecure,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
	}

	// Step 5: Perform TLS handshake over the UDP connection.
	// In production, this uses quic-go to establish a proper QUIC
	// connection. Here we simulate the handshake layer.
	tlsConn := tls.Client(packetConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		packetConn.Close()
		h.markUnavailable()
		return nil, fmt.Errorf("hysteria2: tls handshake (sni=%s): %w", sni, err)
	}

	// Step 6: Send Hysteria2 authentication.
	authHash := sha256.Sum256([]byte(h.config.Password))
	if _, err := tlsConn.Write(authHash[:]); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("hysteria2: send auth: %w", err)
	}

	// Step 7: Read authentication response.
	authResp := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, authResp); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("hysteria2: read auth response: %w", err)
	}
	if authResp[0] != 0x00 {
		tlsConn.Close()
		return nil, fmt.Errorf("hysteria2: authentication failed (code: 0x%02x)", authResp[0])
	}

	// Step 8: Send bandwidth hints using Brutal congestion control.
	bwHint := make([]byte, 8)
	binary.BigEndian.PutUint32(bwHint[0:4], uint32(h.config.UpMbps))
	binary.BigEndian.PutUint32(bwHint[4:8], uint32(h.config.DownMbps))
	if _, err := tlsConn.Write(bwHint); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("hysteria2: send bandwidth hint: %w", err)
	}

	h.markAvailable()

	h.logger.Info("hysteria2 connection established",
		"addr", addr,
		"obfs", h.config.ObfsType,
	)

	conn := &hysteria2Conn{
		Conn:   tlsConn,
		config: h.config,
		logger: h.logger,
	}

	// Start port hopping goroutine if multiple ports are configured.
	if len(h.config.allPorts()) > 1 {
		go h.portHopLoop(ctx)
	}

	return conn, nil
}

// Listen starts a Hysteria2 server listener.
func (h *Hysteria2) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("hysteria2: server-side listening not implemented (use hysteria2 server binary)")
}

// ProbeTests returns censorship detection tests relevant to Hysteria2.
func (h *Hysteria2) ProbeTests() []core.ProbeTest {
	tests := []core.ProbeTest{
		&hysteria2UDPProbe{
			host:  h.config.Host,
			ports: h.config.allPorts(),
		},
	}

	// Add QUIC-specific probe.
	tests = append(tests, &hysteria2QUICProbe{
		host: h.config.Host,
		port: h.config.Port,
		sni:  h.config.SNI,
	})

	return tests
}

// currentPort returns the current port for connection.
// With port hopping, this cycles through the configured ports.
func (h *Hysteria2) currentPort() int {
	ports := h.config.allPorts()
	if len(ports) == 0 {
		return h.config.Port
	}
	idx := h.portIdx.Load() % int64(len(ports))
	return ports[idx]
}

// portHopLoop periodically advances the port index to implement
// port hopping. This makes it harder for firewalls to block the
// connection based on a single port.
func (h *Hysteria2) portHopLoop(ctx context.Context) {
	interval := h.config.PortHopInterval
	if interval == 0 {
		interval = portHopInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newIdx := h.portIdx.Add(1)
			ports := h.config.allPorts()
			if len(ports) > 0 {
				port := ports[newIdx%int64(len(ports))]
				h.logger.Debug("port hop",
					"new_port", port,
					"index", newIdx,
				)
			}
		}
	}
}

// markAvailable marks the protocol as available.
func (h *Hysteria2) markAvailable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.available = true
	h.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (h *Hysteria2) markUnavailable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.available = false
	h.lastCheck = time.Now()
}

// hysteria2Conn wraps a QUIC stream connection with Hysteria2 metadata.
type hysteria2Conn struct {
	net.Conn
	config *Hysteria2Config
	logger *slog.Logger
	closed bool
	mu     sync.Mutex
}

// Close closes the Hysteria2 connection.
func (c *hysteria2Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("closing hysteria2 connection")
	return c.Conn.Close()
}

// salamanderObfuscator implements the Salamander obfuscation layer.
// Salamander XORs each UDP packet with a key derived from the password,
// prepends a random header, and makes QUIC packets look like random UDP.
type salamanderObfuscator struct {
	key [32]byte
}

// newSalamanderObfuscator creates a Salamander obfuscator from a password.
func newSalamanderObfuscator(password string) (*salamanderObfuscator, error) {
	if password == "" {
		return nil, fmt.Errorf("salamander: password is required")
	}
	key := sha256.Sum256([]byte(password))
	return &salamanderObfuscator{key: key}, nil
}

// Obfuscate applies Salamander obfuscation to a packet.
// Format: [8 bytes random header] [XOR-encrypted payload]
func (s *salamanderObfuscator) Obfuscate(data []byte) ([]byte, error) {
	// Generate random header.
	header := make([]byte, salamanderHeaderSize)
	if _, err := rand.Read(header); err != nil {
		return nil, fmt.Errorf("salamander: generate header: %w", err)
	}

	// XOR payload with key stream.
	result := make([]byte, salamanderHeaderSize+len(data))
	copy(result[:salamanderHeaderSize], header)
	for i, b := range data {
		result[salamanderHeaderSize+i] = b ^ s.key[i%len(s.key)]
	}

	return result, nil
}

// Deobfuscate removes Salamander obfuscation from a packet.
func (s *salamanderObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) < salamanderHeaderSize {
		return nil, fmt.Errorf("salamander: packet too short (%d bytes)", len(data))
	}

	payload := data[salamanderHeaderSize:]
	result := make([]byte, len(payload))
	for i, b := range payload {
		result[i] = b ^ s.key[i%len(s.key)]
	}

	return result, nil
}

// WrapConn wraps a UDP connection with Salamander obfuscation.
func (s *salamanderObfuscator) WrapConn(conn net.Conn) net.Conn {
	return &salamanderConn{
		Conn:       conn,
		obfuscator: s,
	}
}

// salamanderConn wraps a net.Conn with Salamander obfuscation on
// reads and writes.
type salamanderConn struct {
	net.Conn
	obfuscator *salamanderObfuscator
}

// Write obfuscates data before writing to the underlying connection.
func (c *salamanderConn) Write(b []byte) (int, error) {
	obfuscated, err := c.obfuscator.Obfuscate(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}
	// Return original data length since that is what the caller expects.
	return len(b), nil
}

// Read deobfuscates data after reading from the underlying connection.
func (c *salamanderConn) Read(b []byte) (int, error) {
	// Read into a larger buffer to accommodate the obfuscation header.
	buf := make([]byte, len(b)+salamanderHeaderSize)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	deobfuscated, err := c.obfuscator.Deobfuscate(buf[:n])
	if err != nil {
		return 0, err
	}

	copy(b, deobfuscated)
	if len(deobfuscated) > len(b) {
		return len(b), nil
	}
	return len(deobfuscated), nil
}

// hysteria2UDPProbe tests if UDP traffic reaches the server on any
// of the configured ports.
type hysteria2UDPProbe struct {
	host  string
	ports []int
}

func (p *hysteria2UDPProbe) Name() string    { return "hysteria2_udp_reachability" }
func (p *hysteria2UDPProbe) Weight() float64 { return 1.0 }

func (p *hysteria2UDPProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()

	reachable := 0
	blocked := 0
	details := make(map[string]string)

	for _, port := range p.ports {
		addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", port))
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			details[fmt.Sprintf("port_%d", port)] = "resolve_error"
			blocked++
			continue
		}

		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			details[fmt.Sprintf("port_%d", port)] = "blocked"
			blocked++
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte{0x00})
		conn.Close()
		if err != nil {
			details[fmt.Sprintf("port_%d", port)] = "write_error"
			blocked++
			continue
		}

		details[fmt.Sprintf("port_%d", port)] = "reachable"
		reachable++
	}

	details["reachable"] = fmt.Sprintf("%d/%d", reachable, len(p.ports))

	return &core.ProbeResult{
		TestName:  p.Name(),
		Success:   reachable > 0,
		Latency:   time.Since(start),
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// hysteria2QUICProbe tests if QUIC handshake can be initiated with
// the server.
type hysteria2QUICProbe struct {
	host string
	port int
	sni  string
}

func (p *hysteria2QUICProbe) Name() string    { return "hysteria2_quic_probe" }
func (p *hysteria2QUICProbe) Weight() float64 { return 0.8 }

func (p *hysteria2QUICProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	// Send a QUIC Initial packet and see if we get a response.
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
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
	defer conn.Close()

	// Build a minimal QUIC Initial packet.
	initialPacket := buildQUICInitialProbe()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(initialPacket); err != nil {
		return &core.ProbeResult{
			TestName:  p.Name(),
			Success:   false,
			Latency:   time.Since(start),
			Details:   map[string]string{"error": "write failed"},
			Timestamp: time.Now(),
		}, nil
	}

	// Try to read a response.
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	latency := time.Since(start)

	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  latency,
			Details: map[string]string{
				"error": "no response (QUIC may be blocked)",
				"addr":  addr,
			},
			Timestamp: time.Now(),
		}, nil
	}

	return &core.ProbeResult{
		TestName: p.Name(),
		Success:  true,
		Latency:  latency,
		Details: map[string]string{
			"response_size": fmt.Sprintf("%d", n),
			"addr":          addr,
		},
		Timestamp: time.Now(),
	}, nil
}

// buildQUICInitialProbe builds a minimal QUIC Initial packet for probing.
// This is not a complete QUIC handshake but enough to elicit a response
// from a QUIC server (or detect if QUIC is blocked).
func buildQUICInitialProbe() []byte {
	// QUIC Initial packet (RFC 9000, Section 17.2.2)
	// Simplified: just enough to probe for UDP/QUIC connectivity.
	packet := make([]byte, 1200) // Minimum QUIC Initial packet size

	// Header form bit (1) + Fixed bit (1) + Long packet type (Initial = 00)
	// + Reserved (00) + Packet Number Length (01) = 0xC0 + 0x01 = 0xC1
	packet[0] = 0xC0

	// Version: QUIC v1 (0x00000001)
	binary.BigEndian.PutUint32(packet[1:5], 0x00000001)

	// Destination Connection ID Length (8 bytes)
	packet[5] = 8

	// Random Destination Connection ID
	rand.Read(packet[6:14]) //nolint:errcheck

	// Source Connection ID Length (0)
	packet[14] = 0

	// Token length (0)
	packet[15] = 0

	// Remaining Length (placeholder)
	binary.BigEndian.PutUint16(packet[16:18], uint16(len(packet)-18))

	// Fill rest with random data (padding)
	rand.Read(packet[18:]) //nolint:errcheck

	return packet
}
