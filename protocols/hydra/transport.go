package hydra

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// Transport is the interface for different network transport mechanisms.
// Each transport wraps a connection in a way that disguises proxy traffic
// as legitimate application traffic (web requests, API calls, etc.).
type Transport interface {
	// Dial establishes a connection through this transport.
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Name returns the transport identifier for logging.
	Name() string
}

// TransportSelector manages multiple transports and attempts them in
// order, falling back to the next transport if one fails.
type TransportSelector struct {
	transports []Transport
	logger     *slog.Logger
}

// NewTransportSelector creates a selector with the given transports
// ordered by preference. The first transport is tried first; if it
// fails, the second is tried, and so on.
func NewTransportSelector(transports []Transport, logger *slog.Logger) *TransportSelector {
	return &TransportSelector{
		transports: transports,
		logger:     logger,
	}
}

// Dial attempts each transport in order until one succeeds or all fail.
// Returns the established connection and the transport that succeeded.
func (ts *TransportSelector) Dial(ctx context.Context, addr string) (net.Conn, Transport, error) {
	if len(ts.transports) == 0 {
		return nil, nil, fmt.Errorf("hydra: no transports configured")
	}

	var lastErr error
	for _, t := range ts.transports {
		ts.logger.Debug("trying transport",
			"transport", t.Name(),
			"addr", addr,
		)

		conn, err := t.Dial(ctx, addr)
		if err != nil {
			ts.logger.Debug("transport failed",
				"transport", t.Name(),
				"error", err,
			)
			lastErr = err
			continue
		}

		ts.logger.Info("transport connected",
			"transport", t.Name(),
			"addr", addr,
		)
		return conn, t, nil
	}

	return nil, nil, fmt.Errorf("hydra: all transports failed, last: %w", lastErr)
}

// Transports returns the list of configured transports.
func (ts *TransportSelector) Transports() []Transport {
	return ts.transports
}

// TLSTransport establishes a direct TLS connection with a randomized
// browser fingerprint. This is the primary and lowest-latency transport.
type TLSTransport struct {
	pool       *FingerprintPool
	serverName string
	timeout    time.Duration
}

// NewTLSTransport creates a TLS transport with fingerprint randomization.
func NewTLSTransport(serverName string, timeout time.Duration) *TLSTransport {
	return &TLSTransport{
		pool:       NewFingerprintPool(),
		serverName: serverName,
		timeout:    timeout,
	}
}

func (t *TLSTransport) Name() string { return "tls" }

// Dial connects via TLS with a random browser fingerprint.
func (t *TLSTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	timeout := t.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls: tcp dial: %w", err)
	}

	// Apply random fingerprint.
	fp := t.pool.RandomFingerprint()
	tlsCfg := fp.ToTLSConfig(t.serverName)

	tlsConn := tls.Client(tcpConn, tlsCfg)

	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls: handshake (fp=%s): %w", fp.Name, err)
	}

	return tlsConn, nil
}

// WSTransport wraps traffic in WebSocket frames over TLS, making the
// connection look like a standard WebSocket connection to a web
// application (e.g., a chat app or real-time dashboard).
type WSTransport struct {
	pool       *FingerprintPool
	serverName string
	path       string
	timeout    time.Duration
}

// NewWSTransport creates a WebSocket transport.
func NewWSTransport(serverName, path string, timeout time.Duration) *WSTransport {
	if path == "" {
		path = "/ws"
	}
	return &WSTransport{
		pool:       NewFingerprintPool(),
		serverName: serverName,
		path:       path,
		timeout:    timeout,
	}
}

func (t *WSTransport) Name() string { return "websocket" }

// Dial performs a WebSocket upgrade handshake over TLS and returns
// the upgraded connection.
func (t *WSTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	timeout := t.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ws: tcp dial: %w", err)
	}

	fp := t.pool.RandomFingerprint()
	tlsCfg := fp.ToTLSConfig(t.serverName)

	tlsConn := tls.Client(tcpConn, tlsCfg)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("ws: tls handshake: %w", err)
	}

	// Generate a WebSocket key.
	wsKey := generateWSKey()

	// Send WebSocket upgrade request.
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: https://%s\r\n"+
			"\r\n",
		t.path, t.serverName, wsKey, t.serverName,
	)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("ws: send upgrade: %w", err)
	}

	// Read the HTTP response.
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("ws: read upgrade response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("ws: unexpected status %d (expected 101)", resp.StatusCode)
	}

	return &wsConn{Conn: tlsConn}, nil
}

// wsConn wraps a connection with minimal WebSocket framing.
type wsConn struct {
	net.Conn
	mu sync.Mutex
}

// Write wraps data in a WebSocket binary frame before sending.
func (c *wsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame := encodeWSFrame(p)
	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read reads a WebSocket frame and returns the payload.
func (c *wsConn) Read(p []byte) (int, error) {
	payload, err := decodeWSFrame(c.Conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, payload)
	return n, nil
}

// encodeWSFrame creates a WebSocket binary frame (opcode 0x82 for
// masked binary data from client).
func encodeWSFrame(payload []byte) []byte {
	length := len(payload)
	var frame []byte

	// FIN bit set, binary opcode.
	frame = append(frame, 0x82)

	// Payload length with mask bit set (client frames must be masked).
	if length < 126 {
		frame = append(frame, byte(length)|0x80)
	} else if length < 65536 {
		frame = append(frame, 126|0x80)
		frame = append(frame, byte(length>>8), byte(length&0xFF))
	} else {
		frame = append(frame, 127|0x80)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(length))
		frame = append(frame, b...)
	}

	// Masking key (4 bytes).
	maskKey := make([]byte, 4)
	rand.Read(maskKey) //nolint:errcheck
	frame = append(frame, maskKey...)

	// Masked payload.
	masked := make([]byte, length)
	for i := 0; i < length; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	return frame
}

// decodeWSFrame reads and decodes a WebSocket frame from a reader.
func decodeWSFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("ws: read frame header: %w", err)
	}

	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	switch {
	case length == 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, fmt.Errorf("ws: read extended length: %w", err)
		}
		length = int(binary.BigEndian.Uint16(ext))
	case length == 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, fmt.Errorf("ws: read extended length: %w", err)
		}
		length = int(binary.BigEndian.Uint64(ext))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return nil, fmt.Errorf("ws: read mask key: %w", err)
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("ws: read payload: %w", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

// generateWSKey generates a random base64-encoded WebSocket key.
func generateWSKey() string {
	key := make([]byte, 16)
	rand.Read(key) //nolint:errcheck
	return base64.StdEncoding.EncodeToString(key)
}

// computeWSAccept computes the expected Sec-WebSocket-Accept value
// from a Sec-WebSocket-Key (used for server-side validation).
func computeWSAccept(key string) string {
	const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha3.New256()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GRPCTransport wraps traffic in gRPC-like framing over HTTP/2,
// making connections appear as legitimate gRPC API calls.
type GRPCTransport struct {
	pool       *FingerprintPool
	serverName string
	servicPath string
	timeout    time.Duration
}

// NewGRPCTransport creates a gRPC transport.
func NewGRPCTransport(serverName, servicePath string, timeout time.Duration) *GRPCTransport {
	if servicePath == "" {
		servicePath = "/grpc.health.v1.Health/Check"
	}
	return &GRPCTransport{
		pool:       NewFingerprintPool(),
		serverName: serverName,
		servicPath: servicePath,
		timeout:    timeout,
	}
}

func (t *GRPCTransport) Name() string { return "grpc" }

// Dial establishes a gRPC-like connection by performing a TLS handshake
// with ALPN h2, then sending an HTTP/2 preface and a gRPC request.
// For actual gRPC framing we use a simplified approach that wraps
// data in gRPC length-prefixed messages over the TLS connection.
func (t *GRPCTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	timeout := t.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("grpc: tcp dial: %w", err)
	}

	fp := t.pool.RandomFingerprint()
	tlsCfg := fp.ToTLSConfig(t.serverName)
	// Force h2 ALPN for gRPC.
	tlsCfg.NextProtos = []string{"h2"}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("grpc: tls handshake: %w", err)
	}

	// Verify h2 was negotiated.
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("grpc: expected h2, got %q", state.NegotiatedProtocol)
	}

	// Send HTTP/2 connection preface.
	if _, err := tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("grpc: send h2 preface: %w", err)
	}

	return &grpcConn{Conn: tlsConn}, nil
}

// grpcConn wraps a TLS connection with gRPC-like length-prefixed framing.
type grpcConn struct {
	net.Conn
	mu sync.Mutex
}

// Write wraps data in gRPC length-prefixed message format:
// [1 byte: compressed flag] [4 bytes: message length BE] [N bytes: message]
func (c *grpcConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := make([]byte, 5)
	header[0] = 0 // not compressed
	binary.BigEndian.PutUint32(header[1:5], uint32(len(p)))

	if _, err := c.Conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read reads a gRPC length-prefixed message.
func (c *grpcConn) Read(p []byte) (int, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	msgLen := binary.BigEndian.Uint32(header[1:5])
	if msgLen == 0 {
		return 0, nil
	}

	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, err
	}

	n := copy(p, buf)
	return n, nil
}

// H2Transport wraps traffic in HTTP/2 streams, making connections
// appear as normal HTTPS browsing. Uses the HTTP/2 CONNECT method
// to establish a tunnel that looks like standard web traffic.
type H2Transport struct {
	pool       *FingerprintPool
	serverName string
	timeout    time.Duration
}

// NewH2Transport creates an HTTP/2 stream transport.
func NewH2Transport(serverName string, timeout time.Duration) *H2Transport {
	return &H2Transport{
		pool:       NewFingerprintPool(),
		serverName: serverName,
		timeout:    timeout,
	}
}

func (t *H2Transport) Name() string { return "h2" }

// Dial establishes an HTTP/2 connection and opens a stream for tunneling.
func (t *H2Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	timeout := t.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("h2: tcp dial: %w", err)
	}

	fp := t.pool.RandomFingerprint()
	tlsCfg := fp.ToTLSConfig(t.serverName)
	tlsCfg.NextProtos = []string{"h2"}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("h2: tls handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("h2: expected h2, got %q", state.NegotiatedProtocol)
	}

	// Send HTTP/2 connection preface.
	if _, err := tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("h2: send preface: %w", err)
	}

	// Send a SETTINGS frame (empty, use defaults).
	// Frame format: Length(3) + Type(1) + Flags(1) + Stream(4)
	settingsFrame := []byte{
		0x00, 0x00, 0x00, // length: 0
		0x04,                   // type: SETTINGS
		0x00,                   // flags: none
		0x00, 0x00, 0x00, 0x00, // stream ID: 0
	}
	if _, err := tlsConn.Write(settingsFrame); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("h2: send settings: %w", err)
	}

	return &h2Conn{Conn: tlsConn}, nil
}

// h2Conn wraps a connection with HTTP/2 DATA frame encoding.
type h2Conn struct {
	net.Conn
	mu sync.Mutex
}

// Write wraps data in an HTTP/2 DATA frame on stream 1.
// DATA frame: Length(3) + Type(0x00) + Flags(1) + Stream(4) + Payload
func (c *h2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	length := len(p)
	header := make([]byte, 9)
	header[0] = byte(length >> 16)
	header[1] = byte(length >> 8)
	header[2] = byte(length)
	header[3] = 0x00                                   // type: DATA
	header[4] = 0x00                                   // flags: none
	binary.BigEndian.PutUint32(header[5:9], uint32(1)) // stream ID: 1

	if _, err := c.Conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read reads an HTTP/2 frame and returns the payload.
func (c *h2Conn) Read(p []byte) (int, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if length == 0 {
		// Skip empty frames (like SETTINGS ACK) and read next.
		return c.Read(p)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, err
	}

	n := copy(p, buf)
	return n, nil
}
