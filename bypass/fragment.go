package bypass

import (
	"context"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLS record types used to locate the ClientHello.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01

	// maxFragmentSize is the absolute maximum we'll allow for a single
	// fragment to avoid sending segments larger than a typical MTU.
	maxFragmentSize = 1460
)

// FragmentTechnique splits the TLS ClientHello into small TCP segments
// so that DPI systems that inspect the first packet cannot reassemble
// the SNI field. This is the core zapret/GoodbyeDPI technique.
type FragmentTechnique struct {
	sizeMin  int
	sizeMax  int
	delayMin time.Duration
	delayMax time.Duration
	mode     string // "tlshello" or packet count like "1-3"
	pktMin   int
	pktMax   int
}

// NewFragmentTechnique creates a fragment technique from range strings.
//
//	sizeRange:     e.g. "1-5" (bytes per fragment)
//	intervalRange: e.g. "1-5" (milliseconds between fragments)
//	packets:       "tlshello" or "1-3" (fragment first N packets)
func NewFragmentTechnique(sizeRange, intervalRange, packets string) *FragmentTechnique {
	ft := &FragmentTechnique{
		sizeMin:  1,
		sizeMax:  5,
		delayMin: 1 * time.Millisecond,
		delayMax: 5 * time.Millisecond,
		mode:     "tlshello",
	}

	if lo, hi, ok := parseRange(sizeRange); ok {
		ft.sizeMin = lo
		ft.sizeMax = hi
	}
	if lo, hi, ok := parseRange(intervalRange); ok {
		ft.delayMin = time.Duration(lo) * time.Millisecond
		ft.delayMax = time.Duration(hi) * time.Millisecond
	}

	if packets == "tlshello" || packets == "" {
		ft.mode = "tlshello"
	} else {
		ft.mode = "count"
		if lo, hi, ok := parseRange(packets); ok {
			ft.pktMin = lo
			ft.pktMax = hi
		} else {
			n, _ := strconv.Atoi(packets)
			if n <= 0 {
				n = 1
			}
			ft.pktMin = n
			ft.pktMax = n
		}
	}

	return ft
}

func (f *FragmentTechnique) Name() string    { return "fragment" }
func (f *FragmentTechnique) Available() bool { return true }
func (f *FragmentTechnique) Effective() bool { return true }

// Wrap returns the connection as-is; fragmentation is applied at dial
// time via WrapDial because we need to intercept the initial writes.
func (f *FragmentTechnique) Wrap(conn net.Conn) net.Conn {
	return conn
}

// WrapDial returns a dialer that wraps the resulting connection in a
// FragmentConn so the initial handshake bytes are fragmented.
func (f *FragmentTechnique) WrapDial(next DialFunc) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := next(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &FragmentConn{
			Conn: conn,
			ft:   f,
		}, nil
	}
}

// FragmentConn wraps a net.Conn and fragments the initial handshake
// writes according to the configured technique.
type FragmentConn struct {
	net.Conn
	ft            *FragmentTechnique
	mu            sync.Mutex
	writeCount    int
	handshakeDone bool
}

// Write intercepts writes to split handshake data into small segments.
// After the handshake phase (determined by mode), writes pass through
// unmodified for maximum throughput.
func (fc *FragmentConn) Write(b []byte) (int, error) {
	fc.mu.Lock()
	shouldFragment := fc.shouldFragment(b)
	fc.writeCount++
	fc.mu.Unlock()

	if !shouldFragment {
		return fc.Conn.Write(b)
	}

	return fc.fragmentWrite(b)
}

// shouldFragment decides whether this write should be fragmented.
func (fc *FragmentConn) shouldFragment(b []byte) bool {
	if fc.handshakeDone {
		return false
	}

	switch fc.ft.mode {
	case "tlshello":
		// Only fragment if this looks like a TLS ClientHello.
		if isTLSClientHello(b) {
			fc.handshakeDone = true
			return true
		}
		return false

	case "count":
		// Fragment the first N packets.
		target := randBetween(fc.ft.pktMin, fc.ft.pktMax)
		if fc.writeCount < target {
			return true
		}
		fc.handshakeDone = true
		return false

	default:
		return false
	}
}

// fragmentWrite splits data into small segments and writes each one
// with a configurable delay between them.
func (fc *FragmentConn) fragmentWrite(data []byte) (int, error) {
	total := 0
	offset := 0

	for offset < len(data) {
		// Pick a random fragment size within the configured range.
		fragSize := randBetween(fc.ft.sizeMin, fc.ft.sizeMax)
		if fragSize <= 0 {
			fragSize = 1
		}
		if fragSize > maxFragmentSize {
			fragSize = maxFragmentSize
		}

		end := offset + fragSize
		if end > len(data) {
			end = len(data)
		}

		n, err := fc.Conn.Write(data[offset:end])
		total += n
		if err != nil {
			return total, err
		}
		offset += n

		// Delay between fragments (skip after last fragment).
		if offset < len(data) {
			delay := randDuration(fc.ft.delayMin, fc.ft.delayMax)
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	return total, nil
}

// isTLSClientHello checks whether the given data starts with a TLS
// Handshake record containing a ClientHello message.
func isTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// TLS record: content_type=0x16 (Handshake)
	if data[0] != tlsRecordTypeHandshake {
		return false
	}
	// Handshake message type: 0x01 (ClientHello)
	// The handshake type is at offset 5 within the record.
	if data[5] != tlsHandshakeClientHello {
		return false
	}
	return true
}

// FindSNIOffset locates the Server Name Indication extension within a
// TLS ClientHello and returns the byte offset of the SNI value. This
// lets callers split the ClientHello precisely at the SNI boundary so
// DPI cannot read the domain name from a single packet.
//
// Returns -1 if the SNI extension cannot be found.
func FindSNIOffset(data []byte) int {
	// Minimum TLS record header (5) + handshake header (4) + version (2) +
	// random (32) = 43 bytes before session ID length.
	if len(data) < 44 {
		return -1
	}

	// Skip TLS record header (5 bytes).
	pos := 5
	// Skip handshake header: type(1) + length(3).
	pos += 4
	// Skip client version (2) and random (32).
	pos += 34

	if pos >= len(data) {
		return -1
	}

	// Session ID (variable length).
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return -1
	}

	// Cipher suites (variable length).
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos+1 > len(data) {
		return -1
	}

	// Compression methods (variable length).
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen

	if pos+2 > len(data) {
		return -1
	}

	// Extensions total length.
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	// Walk extensions looking for SNI (type 0x0000).
	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		if extType == 0 { // server_name extension
			// Return the offset of the extension data which contains the SNI.
			return pos + 4
		}
		pos += 4 + extLen
	}

	return -1
}

// FragmentAtSNI splits a TLS ClientHello into two pieces at the SNI
// boundary. The first piece contains everything up to the SNI, and
// the second piece contains the SNI and everything after.
// If the SNI offset cannot be found, it splits at the midpoint.
func FragmentAtSNI(data []byte) ([]byte, []byte) {
	offset := FindSNIOffset(data)
	if offset <= 0 || offset >= len(data) {
		// Fallback: split at midpoint.
		mid := len(data) / 2
		if mid == 0 {
			mid = 1
		}
		return data[:mid], data[mid:]
	}
	return data[:offset], data[offset:]
}

// ---- Helpers ----

// parseRange parses a string like "1-5" into (lo, hi, ok).
func parseRange(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}

	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, 0, false
		}
		return n, n, true
	}

	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return lo, hi, true
}

// randBetween returns a random int in [lo, hi] inclusive.
func randBetween(lo, hi int) int {
	if lo >= hi {
		return lo
	}
	return lo + rand.Intn(hi-lo+1)
}

// randDuration returns a random duration in [lo, hi].
func randDuration(lo, hi time.Duration) time.Duration {
	if lo >= hi {
		return lo
	}
	return lo + time.Duration(rand.Int63n(int64(hi-lo+1)))
}
