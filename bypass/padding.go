package bypass

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"sync"
	"time"
)

// PaddingTechnique adds random padding to packets to change size
// distribution and defeats DPI that uses statistical traffic analysis.
// It supports:
//   - Random padding to change packet sizes
//   - Timing jitter to prevent timing analysis
//   - Fake packets to obscure real traffic patterns
//   - Burst mode that mimics web browsing
type PaddingTechnique struct {
	padMin       int
	padMax       int
	jitterMs     int
	fakeInterval int
}

// NewPaddingTechnique creates a padding technique.
//
//	padRange:      e.g. "100-200" (pad each packet to this size range)
//	jitterMs:      max jitter in ms added to each write (0 = off)
//	fakeInterval:  send a fake packet every N real packets (0 = off)
func NewPaddingTechnique(padRange string, jitterMs, fakeInterval int) *PaddingTechnique {
	pt := &PaddingTechnique{
		padMin:       100,
		padMax:       200,
		jitterMs:     jitterMs,
		fakeInterval: fakeInterval,
	}
	if lo, hi, ok := parseRange(padRange); ok {
		pt.padMin = lo
		pt.padMax = hi
	}
	return pt
}

func (p *PaddingTechnique) Name() string    { return "padding" }
func (p *PaddingTechnique) Available() bool { return true }
func (p *PaddingTechnique) Effective() bool { return true }

// Wrap wraps a connection with padding/jitter/fake packet support.
func (p *PaddingTechnique) Wrap(conn net.Conn) net.Conn {
	return &PaddingConn{
		Conn:         conn,
		padMin:       p.padMin,
		padMax:       p.padMax,
		jitterMs:     p.jitterMs,
		fakeInterval: p.fakeInterval,
	}
}

// WrapDial passes through; padding is applied at the connection level.
func (p *PaddingTechnique) WrapDial(next DialFunc) DialFunc {
	return next
}

// PaddingConn wraps a net.Conn and adds traffic padding, timing jitter,
// and fake packets to obscure real traffic patterns.
//
// Wire format for padded packets:
//
//	[2 bytes: total frame length (big-endian)] [2 bytes: real data length (big-endian)] [real data] [random padding]
//
// The reader uses the total frame length to consume the exact number of
// bytes, preventing desync. Fake packets use a real data length of 0x0000.
type PaddingConn struct {
	net.Conn
	padMin       int
	padMax       int
	jitterMs     int
	fakeInterval int

	mu         sync.Mutex
	writeCount int
	readBuf    []byte
}

// Write pads the data to a random size, adds timing jitter, and
// periodically sends fake packets.
func (pc *PaddingConn) Write(b []byte) (int, error) {
	pc.mu.Lock()
	pc.writeCount++
	count := pc.writeCount
	pc.mu.Unlock()

	// Timing jitter: random delay before sending.
	if pc.jitterMs > 0 {
		jitter := cryptoRandIntn(pc.jitterMs)
		if jitter > 0 {
			time.Sleep(time.Duration(jitter) * time.Millisecond)
		}
	}

	// Periodically inject a fake packet before the real one.
	if pc.fakeInterval > 0 && count%pc.fakeInterval == 0 {
		_ = pc.sendFakePacket()
	}

	return pc.sendPadded(b)
}

// sendPadded writes data with frame and data length prefixes and random padding.
func (pc *PaddingConn) sendPadded(data []byte) (int, error) {
	realLen := len(data)

	// Calculate target padded size (includes 4-byte header).
	targetSize := randBetween(pc.padMin, pc.padMax)
	if targetSize < realLen+4 {
		targetSize = realLen + 4 // at minimum: 4-byte header + data
	}

	// Build the padded packet.
	packet := make([]byte, targetSize)
	// Total frame length (big-endian) -- bytes after this 2-byte field.
	binary.BigEndian.PutUint16(packet[0:2], uint16(targetSize-2))
	// Real data length (big-endian).
	binary.BigEndian.PutUint16(packet[2:4], uint16(realLen))
	// Real data.
	copy(packet[4:4+realLen], data)
	// Random padding fills the rest.
	if padLen := targetSize - 4 - realLen; padLen > 0 {
		_, _ = rand.Read(packet[4+realLen:])
	}

	_, err := pc.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return realLen, nil
}

// sendFakePacket sends a packet with zero-length real data (all padding).
func (pc *PaddingConn) sendFakePacket() error {
	size := randBetween(pc.padMin, pc.padMax)
	if size < 4 {
		size = 4
	}
	packet := make([]byte, size)
	// Total frame length (bytes after this 2-byte field).
	binary.BigEndian.PutUint16(packet[0:2], uint16(size-2))
	// Real data length = 0 means fake packet.
	binary.BigEndian.PutUint16(packet[2:4], 0)
	_, _ = rand.Read(packet[4:])
	_, err := pc.Conn.Write(packet)
	return err
}

// Read reads padded packets, strips padding, and skips fake packets.
func (pc *PaddingConn) Read(b []byte) (int, error) {
	// If we have buffered data from a previous read, return that first.
	pc.mu.Lock()
	if len(pc.readBuf) > 0 {
		n := copy(b, pc.readBuf)
		pc.readBuf = pc.readBuf[n:]
		pc.mu.Unlock()
		return n, nil
	}
	pc.mu.Unlock()

	for {
		// Read the 4-byte header: [2 bytes: frame len] [2 bytes: real data len].
		header := make([]byte, 4)
		if _, err := readFull(pc.Conn, header); err != nil {
			return 0, err
		}

		frameLen := int(binary.BigEndian.Uint16(header[0:2]))
		realLen := int(binary.BigEndian.Uint16(header[2:4]))

		// Read the entire frame body (real data + padding).
		frameBody := make([]byte, frameLen-2) // subtract the 2 bytes of realLen already read
		if _, err := readFull(pc.Conn, frameBody); err != nil {
			return 0, err
		}

		if realLen == 0 {
			// Fake packet: already fully consumed, skip.
			continue
		}

		// Extract real data from frame body.
		if realLen > len(frameBody) {
			realLen = len(frameBody)
		}
		buf := frameBody[:realLen]

		// Copy what fits into b, buffer the rest.
		n := copy(b, buf)
		if n < len(buf) {
			pc.mu.Lock()
			pc.readBuf = append(pc.readBuf, buf[n:]...)
			pc.mu.Unlock()
		}

		return n, nil
	}
}

// readFull reads exactly len(buf) bytes from the connection.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// BurstWriter mimics web browsing traffic patterns by sending data in
// bursts followed by idle periods, making the traffic less identifiable
// as a VPN/proxy.
type BurstWriter struct {
	conn     net.Conn
	burstMin int           // min bytes per burst
	burstMax int           // max bytes per burst
	idleMin  time.Duration // min idle between bursts
	idleMax  time.Duration // max idle between bursts
}

// NewBurstWriter creates a writer that sends in burst patterns.
func NewBurstWriter(conn net.Conn, burstMin, burstMax int, idleMin, idleMax time.Duration) *BurstWriter {
	return &BurstWriter{
		conn:     conn,
		burstMin: burstMin,
		burstMax: burstMax,
		idleMin:  idleMin,
		idleMax:  idleMax,
	}
}

// Write sends data in bursts with idle periods between them.
func (bw *BurstWriter) Write(data []byte) (int, error) {
	total := 0
	offset := 0

	for offset < len(data) {
		// Determine burst size.
		burstSize := randBetween(bw.burstMin, bw.burstMax)
		end := offset + burstSize
		if end > len(data) {
			end = len(data)
		}

		n, err := bw.conn.Write(data[offset:end])
		total += n
		offset += n
		if err != nil {
			return total, err
		}

		// Idle period between bursts.
		if offset < len(data) {
			idle := randDuration(bw.idleMin, bw.idleMax)
			time.Sleep(idle)
		}
	}

	return total, nil
}

// StripPadding removes padding from a padded packet, returning only
// the real data. This is used by the receiving side.
func StripPadding(packet []byte) []byte {
	if len(packet) < 4 {
		return packet
	}
	// Skip the 2-byte frame length, read the 2-byte real data length.
	realLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if realLen == 0 {
		return nil // fake packet
	}
	if 4+realLen > len(packet) {
		return packet[4:] // truncated, return what we have
	}
	return packet[4 : 4+realLen]
}

// AddPadding creates a padded packet from raw data.
func AddPadding(data []byte, targetSize int) []byte {
	if targetSize < len(data)+4 {
		targetSize = len(data) + 4
	}
	packet := make([]byte, targetSize)
	// Total frame length (bytes after this 2-byte field).
	binary.BigEndian.PutUint16(packet[0:2], uint16(targetSize-2))
	// Real data length.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(data)))
	copy(packet[4:], data)
	if padLen := targetSize - 4 - len(data); padLen > 0 {
		_, _ = rand.Read(packet[4+len(data):])
	}
	return packet
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}
	return int(val.Int64())
}

// TimingConn wraps a connection and adds random delays between writes
// to prevent timing-based traffic analysis.
type TimingConn struct {
	net.Conn
	intervalMin time.Duration
	intervalMax time.Duration
}

// NewTimingConn creates a connection wrapper with timing randomisation.
func NewTimingConn(conn net.Conn, intervalRange string) *TimingConn {
	tc := &TimingConn{
		Conn:        conn,
		intervalMin: 5 * time.Millisecond,
		intervalMax: 50 * time.Millisecond,
	}
	if lo, hi, ok := parseRange(intervalRange); ok {
		tc.intervalMin = time.Duration(lo) * time.Millisecond
		tc.intervalMax = time.Duration(hi) * time.Millisecond
	}
	return tc
}

// Write adds a random delay before each write.
func (tc *TimingConn) Write(b []byte) (int, error) {
	delay := randDuration(tc.intervalMin, tc.intervalMax)
	if delay > 0 {
		time.Sleep(delay)
	}
	return tc.Conn.Write(b)
}

// ---- Inline dialer for timing-only wrapping ----

// TimingDialFunc wraps a DialFunc and applies timing jitter to the
// resulting connection.
func TimingDialFunc(next DialFunc, intervalRange string) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := next(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return NewTimingConn(conn, intervalRange), nil
	}
}
