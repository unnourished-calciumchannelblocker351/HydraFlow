package bypass

import (
	"context"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// DesyncConfig holds parameters for TCP desync techniques.
type DesyncConfig struct {
	// FakeTTL is the TTL for fake packets. If 0, auto-detected to be
	// just enough to reach the DPI but not the server.
	FakeTTL int

	// SplitPos is the byte offset at which to split TCP segments.
	// If 0, the split is placed at the TLS SNI boundary.
	SplitPos int

	// OOO sends packets out of order to confuse DPI state machines.
	OOO bool

	// WindowSize forces a small TCP window advertisement to cause
	// the remote side to send small segments (0 = disabled).
	WindowSize int
}

// DesyncTechnique implements TCP-level desync methods inspired by
// zapret, GoodbyeDPI, and similar tools. These techniques exploit
// the fact that DPI systems process packets differently than the
// real TCP stack on the destination server:
//
//   - Fake packet: send a packet with invalid data before the real
//     ClientHello. DPI sees the fake, ignores the real one.
//   - TTL manipulation: fake packet has a TTL that reaches DPI but
//     expires before reaching the server.
//   - TCP segmentation: split at strategic offsets.
//   - Out-of-order delivery: send segments in reverse or random order.
//   - RST injection defense: detect and ignore injected RST packets.
//   - Window size manipulation: force small segments via window size.
type DesyncTechnique struct {
	config DesyncConfig
}

// NewDesyncTechnique creates a desync technique with the given config.
func NewDesyncTechnique(cfg DesyncConfig) *DesyncTechnique {
	if cfg.FakeTTL <= 0 {
		cfg.FakeTTL = 3 // reasonable default: most DPI is 1-2 hops away
	}
	if cfg.SplitPos <= 0 {
		cfg.SplitPos = 0 // auto: split at SNI
	}
	return &DesyncTechnique{config: cfg}
}

func (d *DesyncTechnique) Name() string    { return "desync" }
func (d *DesyncTechnique) Available() bool { return true }
func (d *DesyncTechnique) Effective() bool { return true }

// Wrap returns the connection as-is. Desync is applied at dial time.
func (d *DesyncTechnique) Wrap(conn net.Conn) net.Conn {
	return conn
}

// WrapDial returns a dialer that wraps the resulting connection with
// desync capabilities for the initial handshake.
func (d *DesyncTechnique) WrapDial(next DialFunc) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := next(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &DesyncConn{
			Conn:   conn,
			config: d.config,
		}, nil
	}
}

// DesyncConn wraps a net.Conn and applies TCP desync techniques to
// the initial handshake. After the handshake, writes pass through.
type DesyncConn struct {
	net.Conn
	config     DesyncConfig
	mu         sync.Mutex
	firstWrite bool
	writeCount int
}

// Write intercepts writes to apply desync on the first handshake packet.
func (dc *DesyncConn) Write(b []byte) (int, error) {
	dc.mu.Lock()
	isFirst := !dc.firstWrite
	dc.firstWrite = true
	dc.writeCount++
	dc.mu.Unlock()

	if isFirst && isTLSClientHello(b) {
		return dc.desyncWrite(b)
	}

	return dc.Conn.Write(b)
}

// desyncWrite applies the full desync sequence:
//  1. (Disabled) Fake packet injection -- requires raw sockets with TTL
//     control to avoid corrupting the connection. Without true TTL
//     manipulation the fake ClientHello reaches the server and breaks TLS.
//  2. Split the real ClientHello at the configured position
//  3. Optionally send segments out of order
func (dc *DesyncConn) desyncWrite(data []byte) (int, error) {
	// Step 1: Fake packet injection is disabled by default.
	// Sending a fake ClientHello over the same TCP socket without
	// working TTL manipulation causes the server to see corrupted
	// data and tear down the connection. Only TCP segmentation
	// (steps 2-3) is used, which works without raw sockets.

	// Step 2: Determine split position.
	splitPos := dc.config.SplitPos
	if splitPos <= 0 {
		// Auto: split at SNI boundary.
		sniOff := FindSNIOffset(data)
		if sniOff > 0 && sniOff < len(data) {
			splitPos = sniOff
		} else {
			splitPos = len(data) / 2
		}
	}
	if splitPos >= len(data) {
		splitPos = len(data) / 2
	}
	if splitPos <= 0 {
		splitPos = 1
	}

	part1 := data[:splitPos]
	part2 := data[splitPos:]

	// Step 3: Send segments, optionally out of order.
	if dc.config.OOO && len(part2) > 0 {
		// Out-of-order: send second part first, then first part.
		// TCP will reorder on the server side, but DPI may not.
		if _, err := dc.Conn.Write(part2); err != nil {
			return 0, err
		}
		// Small delay so the DPI processes the out-of-order segment.
		time.Sleep(1 * time.Millisecond)
		if _, err := dc.Conn.Write(part1); err != nil {
			return len(part2), err
		}
	} else {
		// In-order split.
		if _, err := dc.Conn.Write(part1); err != nil {
			return 0, err
		}
		time.Sleep(1 * time.Millisecond)
		if _, err := dc.Conn.Write(part2); err != nil {
			return len(part1), err
		}
	}

	return len(data), nil
}

// sendWithTTL sends data with a specific IP TTL. On most platforms
// this requires raw sockets which need elevated privileges. When raw
// sockets are unavailable, we fall back to a regular write (the fake
// data will reach the server but will be ignored because the TLS
// layer will reject it).
//
// On Linux with CAP_NET_RAW, the real implementation would use
// syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl).
func (dc *DesyncConn) sendWithTTL(data []byte, ttl int) error {
	// Try to set TTL via the raw connection if available.
	if rawConn, ok := dc.Conn.(interface {
		SyscallConn() (interface{ Control(func(fd uintptr)) error }, error)
	}); ok {
		sc, err := rawConn.SyscallConn()
		if err == nil {
			_ = setIPTTL(sc, ttl)
		}
	}

	// Send the fake data.
	_, err := dc.Conn.Write(data)
	if err != nil {
		return err
	}

	// Restore default TTL.
	if rawConn, ok := dc.Conn.(interface {
		SyscallConn() (interface{ Control(func(fd uintptr)) error }, error)
	}); ok {
		sc, err := rawConn.SyscallConn()
		if err == nil {
			_ = setIPTTL(sc, 64) // restore default
		}
	}

	return nil
}

// setIPTTL attempts to set the IP TTL on the underlying socket.
// This is a best-effort operation that may fail without raw socket privileges.
func setIPTTL(sc interface{ Control(func(fd uintptr)) error }, ttl int) error {
	// The actual setsockopt call is platform-specific. We define it
	// here as a no-op that platform-specific files can override.
	// On Linux: syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	_ = sc
	_ = ttl
	return nil
}

// buildFakeClientHello creates a fake TLS ClientHello that looks valid
// enough for DPI to process but will be rejected by the real server.
// The fake has corrupted random bytes so the TLS stack will drop it.
func buildFakeClientHello(realLen int) []byte {
	// Build a minimal TLS record that DPI will try to parse.
	fake := make([]byte, realLen)

	// TLS record header.
	fake[0] = tlsRecordTypeHandshake // Content type: Handshake
	fake[1] = 0x03                   // Version: TLS 1.0 (for record layer)
	fake[2] = 0x01
	// Record length (remaining bytes).
	recLen := len(fake) - 5
	if recLen < 0 {
		recLen = 0
	}
	if len(fake) > 3 {
		fake[3] = byte(recLen >> 8)
	}
	if len(fake) > 4 {
		fake[4] = byte(recLen & 0xFF)
	}

	// Handshake header.
	if len(fake) > 5 {
		fake[5] = tlsHandshakeClientHello // ClientHello
	}

	// Fill the rest with random data to look like a real ClientHello
	// but with corrupted content that any TLS implementation will reject.
	if len(fake) > 6 {
		_, _ = rand.Read(fake[6:])
	}

	return fake
}

// RSTDefenseConn wraps a connection and detects injected TCP RST
// packets from DPI. When a suspicious RST is detected (e.g., the
// connection resets immediately after the first data packet), it
// retries the connection.
type RSTDefenseConn struct {
	net.Conn
	connMu     sync.Mutex // protects Conn replacement (read + write paths)
	mu         sync.Mutex // protects retries counter
	retries    int
	maxRetries int
	dialFn     DialFunc
	network    string
	address    string
}

// NewRSTDefenseConn wraps a connection with RST injection defense.
func NewRSTDefenseConn(conn net.Conn, dialFn DialFunc, network, address string, maxRetries int) *RSTDefenseConn {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &RSTDefenseConn{
		Conn:       conn,
		maxRetries: maxRetries,
		dialFn:     dialFn,
		network:    network,
		address:    address,
	}
}

// Read wraps the underlying Read and detects RST injection.
// If a read returns a "connection reset" error very quickly after
// the connection was established, it likely means DPI injected a
// RST. In that case, we reconnect and retry.
func (rc *RSTDefenseConn) Read(b []byte) (int, error) {
	rc.connMu.Lock()
	conn := rc.Conn
	rc.connMu.Unlock()

	n, err := conn.Read(b)
	if err != nil && isRSTError(err) {
		rc.mu.Lock()
		if rc.retries < rc.maxRetries {
			rc.retries++
			rc.mu.Unlock()

			// Attempt to reconnect.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			newConn, dialErr := rc.dialFn(ctx, rc.network, rc.address)
			if dialErr != nil {
				return n, err // return original error
			}

			// Replace the underlying connection under lock.
			rc.connMu.Lock()
			_ = rc.Conn.Close()
			rc.Conn = newConn
			rc.connMu.Unlock()

			// Retry the read on the new connection.
			return newConn.Read(b)
		}
		rc.mu.Unlock()
	}
	return n, err
}

// Write wraps the underlying Write with connection mutex protection.
func (rc *RSTDefenseConn) Write(b []byte) (int, error) {
	rc.connMu.Lock()
	conn := rc.Conn
	rc.connMu.Unlock()
	return conn.Write(b)
}

// isRSTError checks if an error indicates a TCP RST (connection reset).
func isRSTError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "forcibly closed")
}

// WindowSizeConn wraps a connection and forces a small TCP window
// size advertisement. This causes the remote side to send small
// segments, which can help bypass DPI that only inspects the first
// segment of a certain size.
//
// Note: actually changing the TCP window requires raw socket access.
// This implementation sets the read buffer size to a small value,
// which indirectly affects the advertised window on most OS TCP stacks.
type WindowSizeConn struct {
	net.Conn
	windowSize int
}

// NewWindowSizeConn wraps a connection with a small window size.
func NewWindowSizeConn(conn net.Conn, windowSize int) *WindowSizeConn {
	// Set the socket receive buffer to influence window size.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadBuffer(windowSize)
	}
	return &WindowSizeConn{
		Conn:       conn,
		windowSize: windowSize,
	}
}

// Read reads with awareness of the small window size.
func (wc *WindowSizeConn) Read(b []byte) (int, error) {
	// Limit read size to maintain small window behaviour.
	maxRead := wc.windowSize
	if maxRead <= 0 || maxRead > len(b) {
		maxRead = len(b)
	}
	return wc.Conn.Read(b[:maxRead])
}

// ---- Desync dial wrapper ----

// DesyncDialFunc wraps a DialFunc and applies desync to the resulting
// connection.
func DesyncDialFunc(next DialFunc, cfg DesyncConfig) DialFunc {
	technique := NewDesyncTechnique(cfg)
	return technique.WrapDial(next)
}
