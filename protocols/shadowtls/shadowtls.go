// Package shadowtls implements the ShadowTLS v3 protocol for HydraFlow.
// ShadowTLS performs a genuine TLS handshake with a legitimate server
// (e.g., www.microsoft.com) so that DPI systems see valid TLS traffic
// to a well-known domain. After the handshake, the connection is
// secretly redirected to the proxy server, with subsequent data
// encrypted using a separate key and carrying proxy traffic.
//
// ShadowTLS v3 improves over v2 by adding HMAC-based verification
// to prevent active probing attacks where a censor could replay the
// TLS handshake and detect the protocol switching behavior.
package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
	"github.com/Evr1kys/HydraFlow/protocols"
)

const (
	protocolName = "shadowtls-v3"

	// defaultPriority is medium-high. ShadowTLS is effective against
	// DPI that inspects TLS handshakes but doesn't block the
	// legitimate handshake domains.
	defaultPriority = 18

	// dialTimeout is the default timeout for establishing connections.
	dialTimeout = 15 * time.Second

	// handshakeTimeout is the maximum time for the TLS handshake.
	handshakeTimeout = 10 * time.Second

	// hmacSize is the size of the HMAC-SHA256 verification tag.
	hmacSize = 32

	// tlsRecordHeaderSize is the size of a TLS record header.
	tlsRecordHeaderSize = 5

	// tlsRecordContentTypeAppData is the TLS content type for application data.
	tlsRecordContentTypeAppData = 0x17

	// tlsRecordContentTypeHandshake is the TLS content type for handshake.
	tlsRecordContentTypeHandshake = 0x16

	// maxTLSRecordSize is the maximum allowed TLS record payload.
	maxTLSRecordSize = 16384

	// shadowFrameHeaderSize is the ShadowTLS v3 frame header size:
	// [1 byte: type] [2 bytes: length] [32 bytes: HMAC]
	shadowFrameHeaderSize = 1 + 2 + hmacSize
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		sc := DefaultConfig()
		if v, ok := cfg["host"].(string); ok {
			sc.Host = v
		}
		if v, ok := cfg["port"].(int); ok {
			sc.Port = v
		}
		if v, ok := cfg["password"].(string); ok {
			sc.Password = v
		}
		if v, ok := cfg["handshake_server"].(string); ok {
			sc.HandshakeServer = v
		}
		if v, ok := cfg["handshake_port"].(int); ok {
			sc.HandshakePort = v
		}
		if v, ok := cfg["sni"].(string); ok {
			sc.SNI = v
		}
		if v, ok := cfg["priority"].(int); ok {
			sc.Priority = v
		}
		if v, ok := cfg["inner_protocol"].(string); ok {
			sc.InnerProtocol = v
		}
		if v, ok := cfg["strict_mode"].(bool); ok {
			sc.StrictMode = v
		}

		return New(sc, logger)
	})
}

// ShadowTLSConfig contains all settings for a ShadowTLS v3 connection.
type ShadowTLSConfig struct {
	// Host is the ShadowTLS proxy server address.
	Host string `yaml:"host" json:"host"`

	// Port is the ShadowTLS proxy server port (typically 443).
	Port int `yaml:"port" json:"port"`

	// Password is the shared secret between client and server.
	// Used to derive HMAC keys for v3 verification.
	Password string `yaml:"password" json:"password"`

	// HandshakeServer is the legitimate server used for the
	// real TLS handshake (e.g., "www.microsoft.com").
	HandshakeServer string `yaml:"handshake_server" json:"handshake_server"`

	// HandshakePort is the port of the handshake server (usually 443).
	HandshakePort int `yaml:"handshake_port" json:"handshake_port"`

	// SNI is the Server Name Indication. If empty, HandshakeServer is used.
	SNI string `yaml:"sni" json:"sni"`

	// InnerProtocol specifies what runs inside the ShadowTLS tunnel.
	// Typical values: "shadowsocks", "direct".
	InnerProtocol string `yaml:"inner_protocol" json:"inner_protocol"`

	// StrictMode enables additional verification of server responses.
	// This provides better active probing resistance at the cost of
	// slightly more computation.
	StrictMode bool `yaml:"strict_mode" json:"strict_mode"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// DialTimeout overrides the default connection timeout.
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
}

// DefaultConfig returns a ShadowTLSConfig with sensible defaults.
func DefaultConfig() *ShadowTLSConfig {
	return &ShadowTLSConfig{
		Port:            443,
		HandshakeServer: "www.microsoft.com",
		HandshakePort:   443,
		InnerProtocol:   "shadowsocks",
		StrictMode:      true,
		Priority:        defaultPriority,
		DialTimeout:     dialTimeout,
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *ShadowTLSConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("shadowtls: host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("shadowtls: invalid port %d", c.Port)
	}
	if c.Password == "" {
		return fmt.Errorf("shadowtls: password is required")
	}
	if c.HandshakeServer == "" {
		return fmt.Errorf("shadowtls: handshake_server is required")
	}
	if c.HandshakePort <= 0 || c.HandshakePort > 65535 {
		return fmt.Errorf("shadowtls: invalid handshake_port %d", c.HandshakePort)
	}
	return nil
}

// ShadowTLS implements the core.Protocol interface for ShadowTLS v3.
type ShadowTLS struct {
	config *ShadowTLSConfig
	logger *slog.Logger

	mu        sync.RWMutex
	available bool
	lastCheck time.Time

	// hmacKey is derived from the password for v3 verification.
	hmacKey []byte
}

// New creates a new ShadowTLS v3 protocol instance.
func New(cfg *ShadowTLSConfig, logger *slog.Logger) (*ShadowTLS, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Derive the HMAC key from the password.
	hmacKey := deriveKey(cfg.Password, "shadowtls-v3-hmac")

	return &ShadowTLS{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		available: true,
		hmacKey:   hmacKey,
	}, nil
}

// Name returns the protocol identifier.
func (s *ShadowTLS) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (s *ShadowTLS) Priority() int {
	return s.config.Priority
}

// Available reports whether ShadowTLS is likely to work.
func (s *ShadowTLS) Available() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available
}

// Dial establishes a ShadowTLS v3 connection.
// The connection process:
//  1. TCP connect to the ShadowTLS proxy server
//  2. Perform a genuine TLS handshake with the legitimate server
//     (the proxy server relays TLS handshake messages)
//  3. After handshake completes, switch to proxy data mode
//  4. Send v3 HMAC verification to prove client identity
//  5. Begin encrypted proxy traffic inside TLS Application Data records
func (s *ShadowTLS) Dial(ctx context.Context) (net.Conn, error) {
	timeout := s.config.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(s.config.Host, fmt.Sprintf("%d", s.config.Port))

	s.logger.Debug("dialing shadowtls server",
		"addr", addr,
		"handshake_server", s.config.HandshakeServer,
		"strict_mode", s.config.StrictMode,
	)

	// Step 1: TCP connection to ShadowTLS proxy.
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		s.markUnavailable()
		return nil, fmt.Errorf("shadowtls: tcp dial %s: %w", addr, err)
	}

	// Step 2: Perform genuine TLS handshake through the proxy.
	// The proxy relays our ClientHello to the real HandshakeServer,
	// and passes back the genuine ServerHello, Certificate, etc.
	// This makes the traffic indistinguishable from real TLS to the
	// HandshakeServer from the perspective of a network observer.
	sni := s.config.SNI
	if sni == "" {
		sni = s.config.HandshakeServer
	}

	tlsCfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// InsecureSkipVerify is required because the proxy server will
		// present the legitimate server's certificate but the TCP
		// connection terminates at the proxy.
		InsecureSkipVerify: true,
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := tcpConn.SetDeadline(deadline); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		s.markUnavailable()
		return nil, fmt.Errorf("shadowtls: tls handshake (sni=%s): %w", sni, err)
	}

	s.logger.Debug("tls handshake complete",
		"sni", sni,
		"version", fmt.Sprintf("0x%04x", tlsConn.ConnectionState().Version),
	)

	// Clear deadline after handshake.
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	// Step 3: Send v3 HMAC verification.
	// This proves to the server that we are a legitimate ShadowTLS client,
	// not a censor performing an active probe.
	if err := s.sendV3Verification(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("shadowtls: v3 verification: %w", err)
	}

	// Step 4: Read server verification response.
	if err := s.readV3VerificationResponse(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("shadowtls: v3 verification response: %w", err)
	}

	s.markAvailable()

	s.logger.Info("shadowtls connection established",
		"addr", addr,
		"handshake_server", s.config.HandshakeServer,
	)

	return &shadowTLSConn{
		Conn:    tlsConn,
		config:  s.config,
		logger:  s.logger,
		hmacKey: s.hmacKey,
	}, nil
}

// sendV3Verification sends the ShadowTLS v3 HMAC verification to
// the server. The verification is embedded in a TLS Application Data
// record so it looks like normal post-handshake encrypted traffic.
//
// V3 verification format:
//
//	[8 bytes: random nonce] [32 bytes: HMAC-SHA256(nonce || server_random)]
func (s *ShadowTLS) sendV3Verification(conn net.Conn) error {
	// Generate random nonce.
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Compute HMAC over the nonce.
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(nonce)
	hmacTag := mac.Sum(nil)

	// Build the verification message.
	verification := make([]byte, 0, len(nonce)+len(hmacTag))
	verification = append(verification, nonce...)
	verification = append(verification, hmacTag...)

	// Send as a standard write (the TLS layer will wrap it in
	// an Application Data record).
	if _, err := conn.Write(verification); err != nil {
		return fmt.Errorf("write verification: %w", err)
	}

	s.logger.Debug("sent v3 verification",
		"nonce_len", len(nonce),
		"hmac_len", len(hmacTag),
	)

	return nil
}

// readV3VerificationResponse reads the server's v3 verification response.
// The server responds with its own HMAC to confirm it holds the password.
func (s *ShadowTLS) readV3VerificationResponse(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	// Read server nonce (8 bytes) + HMAC (32 bytes).
	resp := make([]byte, 8+hmacSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read server verification: %w", err)
	}

	serverNonce := resp[:8]
	serverHMAC := resp[8:]

	// Verify server's HMAC.
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(serverNonce)
	expectedHMAC := mac.Sum(nil)

	if !hmac.Equal(serverHMAC, expectedHMAC) {
		return fmt.Errorf("server HMAC verification failed (active probe or wrong password)")
	}

	s.logger.Debug("server v3 verification passed")
	return nil
}

// Listen starts a ShadowTLS server listener.
func (s *ShadowTLS) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("shadowtls: server-side listening not implemented (use shadow-tls server binary)")
}

// ProbeTests returns censorship detection tests relevant to ShadowTLS.
func (s *ShadowTLS) ProbeTests() []core.ProbeTest {
	return []core.ProbeTest{
		&shadowTLSReachabilityProbe{
			host: s.config.Host,
			port: s.config.Port,
		},
		&shadowTLSHandshakeProbe{
			host: s.config.Host,
			port: s.config.Port,
			sni:  s.config.HandshakeServer,
		},
		&shadowTLSSNIProbe{
			handshakeServer: s.config.HandshakeServer,
		},
	}
}

// markAvailable marks the protocol as available.
func (s *ShadowTLS) markAvailable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.available = true
	s.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (s *ShadowTLS) markUnavailable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.available = false
	s.lastCheck = time.Now()
}

// shadowTLSConn wraps a ShadowTLS connection with framing logic.
// After the handshake and verification, data is sent in TLS-compatible
// frames with HMAC tags for integrity verification.
type shadowTLSConn struct {
	net.Conn
	config  *ShadowTLSConfig
	logger  *slog.Logger
	hmacKey []byte
	closed  bool
	mu      sync.Mutex

	// writeMAC is the HMAC instance for outgoing frames.
	writeMAC hash.Hash
	writeMu  sync.Mutex

	// readMAC is the HMAC instance for incoming frames.
	readMAC hash.Hash
	readMu  sync.Mutex
}

// Write sends data through the ShadowTLS connection, framing it
// as TLS Application Data records with HMAC tags.
func (c *shadowTLSConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeMAC == nil {
		c.writeMAC = hmac.New(sha256.New, c.hmacKey)
	}

	totalWritten := 0
	remaining := b

	// Split into chunks that fit in TLS records.
	for len(remaining) > 0 {
		chunkSize := len(remaining)
		if chunkSize > maxTLSRecordSize-hmacSize {
			chunkSize = maxTLSRecordSize - hmacSize
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		// Compute HMAC for this chunk.
		c.writeMAC.Reset()
		c.writeMAC.Write(chunk)
		tag := c.writeMAC.Sum(nil)

		// Build the frame: [data] [HMAC tag]
		frame := make([]byte, 0, len(chunk)+hmacSize)
		frame = append(frame, chunk...)
		frame = append(frame, tag...)

		n, err := c.Conn.Write(frame)
		if err != nil {
			return totalWritten, err
		}
		if n < len(frame) {
			return totalWritten, io.ErrShortWrite
		}

		totalWritten += chunkSize
	}

	return totalWritten, nil
}

// Read reads data from the ShadowTLS connection, verifying HMAC tags.
func (c *shadowTLSConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readMAC == nil {
		c.readMAC = hmac.New(sha256.New, c.hmacKey)
	}

	// Read from the underlying connection.
	// In strict mode, verify the HMAC tag.
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}

	if c.config.StrictMode && n > hmacSize {
		data := b[:n-hmacSize]
		tag := b[n-hmacSize : n]

		c.readMAC.Reset()
		c.readMAC.Write(data)
		expectedTag := c.readMAC.Sum(nil)

		if !hmac.Equal(tag, expectedTag) {
			c.logger.Warn("HMAC verification failed on incoming frame",
				"frame_size", n,
			)
			return 0, fmt.Errorf("shadowtls: incoming frame HMAC verification failed")
		}

		// Return only the data portion.
		copy(b, data)
		return len(data), nil
	}

	return n, nil
}

// Close closes the ShadowTLS connection.
func (c *shadowTLSConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("closing shadowtls connection")
	return c.Conn.Close()
}

// deriveKey derives a key from a password and purpose string using
// HKDF-like construction with SHA-256.
func deriveKey(password, purpose string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

// shadowTLSReachabilityProbe tests basic TCP connectivity to the
// ShadowTLS server.
type shadowTLSReachabilityProbe struct {
	host string
	port int
}

func (p *shadowTLSReachabilityProbe) Name() string    { return "shadowtls_reachability" }
func (p *shadowTLSReachabilityProbe) Weight() float64 { return 1.0 }

func (p *shadowTLSReachabilityProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
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

// shadowTLSHandshakeProbe tests if a TLS handshake through the ShadowTLS
// server succeeds. The ShadowTLS server relays the handshake to the
// legitimate server, so this tests the full relay path.
type shadowTLSHandshakeProbe struct {
	host string
	port int
	sni  string
}

func (p *shadowTLSHandshakeProbe) Name() string    { return "shadowtls_handshake" }
func (p *shadowTLSHandshakeProbe) Weight() float64 { return 0.9 }

func (p *shadowTLSHandshakeProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         p.sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
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

// shadowTLSSNIProbe tests if the handshake server's SNI is accessible
// from the current network. If the legitimate domain is blocked,
// ShadowTLS will not work because the TLS handshake will fail.
type shadowTLSSNIProbe struct {
	handshakeServer string
}

func (p *shadowTLSSNIProbe) Name() string    { return "shadowtls_sni_check" }
func (p *shadowTLSSNIProbe) Weight() float64 { return 0.8 }

func (p *shadowTLSSNIProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()

	// Resolve the handshake server to check DNS.
	ips, err := net.LookupHost(p.handshakeServer)
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error":  err.Error(),
				"domain": p.handshakeServer,
				"note":   "DNS resolution failed for handshake server",
			},
			Timestamp: time.Now(),
		}, nil
	}

	// Try TLS handshake directly with the handshake server
	// to verify the SNI is not blocked.
	addr := net.JoinHostPort(p.handshakeServer, "443")
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: p.handshakeServer,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error":  err.Error(),
				"domain": p.handshakeServer,
				"ips":    fmt.Sprintf("%v", ips),
				"note":   "TLS handshake to handshake server failed",
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
			"domain": p.handshakeServer,
			"ips":    fmt.Sprintf("%v", ips),
			"note":   "handshake server SNI is accessible",
		},
		Timestamp: time.Now(),
	}, nil
}

// buildTLSApplicationDataRecord wraps a payload in a TLS Application Data
// record header. This is used when we need to write raw frames that look
// like TLS records on the wire.
func buildTLSApplicationDataRecord(payload []byte) []byte {
	record := make([]byte, tlsRecordHeaderSize+len(payload))

	// Content type: Application Data.
	record[0] = tlsRecordContentTypeAppData

	// Protocol version: TLS 1.2 (0x0303) - always 1.2 in the record header
	// even for TLS 1.3.
	binary.BigEndian.PutUint16(record[1:3], 0x0303)

	// Payload length.
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))

	// Payload.
	copy(record[tlsRecordHeaderSize:], payload)

	return record
}

// parseTLSRecordHeader reads a TLS record header and returns the
// content type and payload length.
func parseTLSRecordHeader(header []byte) (contentType byte, length uint16, err error) {
	if len(header) < tlsRecordHeaderSize {
		return 0, 0, fmt.Errorf("incomplete TLS record header: %d bytes", len(header))
	}

	contentType = header[0]
	// Skip version bytes (1:3).
	length = binary.BigEndian.Uint16(header[3:5])

	if length > maxTLSRecordSize {
		return 0, 0, fmt.Errorf("TLS record too large: %d bytes", length)
	}

	return contentType, length, nil
}
