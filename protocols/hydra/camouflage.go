package hydra

import (
	"crypto/rand"
	"io"
	"math/big"
	"sync"
	"time"
)

// Typical HTTPS packet size distribution observed from real web browsing.
// These sizes represent common TLS record sizes and help the proxy traffic
// blend in with legitimate HTTPS traffic. DPI systems look for uniform
// packet sizes as a signal of tunnel traffic.
var typicalHTTPSSizes = []int{
	23, 41, 64, 96, 128, 200, 256, 384, 512, 768,
	1024, 1280, 1380, 1400, 1420, 1440, 1460,
}

// paddingRange defines min/max random padding bytes.
const (
	minPadding = 1
	maxPadding = 64
)

// CamouflageConfig controls traffic camouflage behavior.
type CamouflageConfig struct {
	// Enabled controls whether camouflage is active.
	Enabled bool

	// MinDelay is the minimum random delay between writes.
	MinDelay time.Duration

	// MaxDelay is the maximum random delay between writes.
	MaxDelay time.Duration

	// PaddingEnabled adds random padding to match HTTPS packet sizes.
	PaddingEnabled bool
}

// DefaultCamouflageConfig returns a configuration with sensible defaults.
func DefaultCamouflageConfig() CamouflageConfig {
	return CamouflageConfig{
		Enabled:        true,
		MinDelay:       0,
		MaxDelay:       5 * time.Millisecond,
		PaddingEnabled: true,
	}
}

// CamouflageWriter wraps a writer and adds random padding to make
// traffic patterns match typical HTTPS web browsing. Each write is
// transformed into a Hydra DATA frame with padding that brings the
// total packet size close to a common HTTPS record size.
type CamouflageWriter struct {
	w      io.Writer
	config CamouflageConfig
	mu     sync.Mutex
}

// NewCamouflageWriter creates a writer that applies traffic camouflage.
func NewCamouflageWriter(w io.Writer, config CamouflageConfig) *CamouflageWriter {
	return &CamouflageWriter{
		w:      w,
		config: config,
	}
}

// Write wraps data in a Hydra DATA frame with random padding and writes
// it to the underlying writer. The padding is chosen to bring the total
// frame size close to a typical HTTPS packet size.
func (cw *CamouflageWriter) Write(p []byte) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	paddingLen := byte(0)
	if cw.config.PaddingEnabled {
		paddingLen = cw.choosePadding(len(p))
	}

	frame := &Frame{
		Type:       FrameData,
		Payload:    p,
		PaddingLen: paddingLen,
	}

	data, err := frame.MarshalBinary()
	if err != nil {
		return 0, err
	}

	_, err = cw.w.Write(data)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// choosePadding calculates padding length to make the total frame size
// approximate a typical HTTPS packet size.
func (cw *CamouflageWriter) choosePadding(payloadLen int) byte {
	// Frame overhead: type(1) + length(2) + padding_len(1) = 4 bytes.
	frameOverhead := 4
	currentSize := frameOverhead + payloadLen

	// Find the nearest typical HTTPS size that is >= currentSize.
	targetSize := 0
	for _, size := range typicalHTTPSSizes {
		if size >= currentSize {
			targetSize = size
			break
		}
	}

	// If payload is already larger than all typical sizes, use random padding.
	if targetSize == 0 {
		n := cryptoRandIntn(maxPadding-minPadding+1) + minPadding
		return byte(n)
	}

	needed := targetSize - currentSize
	if needed <= 0 {
		// Add small random padding anyway to avoid zero-padding fingerprint.
		n := cryptoRandIntn(minPadding*3) + 1
		return byte(n)
	}

	if needed > maxPadding {
		needed = maxPadding
	}

	// Add slight randomization so padding is not exactly predictable.
	jitter := cryptoRandIntn(5)
	result := needed + jitter
	if result > maxPadding {
		result = maxPadding
	}
	if result < 1 {
		result = 1
	}

	return byte(result)
}

// CamouflageReader wraps a reader and strips Hydra frame padding,
// returning only the actual payload data.
type CamouflageReader struct {
	r      io.Reader
	config CamouflageConfig
	buf    []byte // buffered leftover payload data
	mu     sync.Mutex
}

// NewCamouflageReader creates a reader that strips camouflage padding.
func NewCamouflageReader(r io.Reader, config CamouflageConfig) *CamouflageReader {
	return &CamouflageReader{
		r:      r,
		config: config,
	}
}

// Read reads the next Hydra DATA frame from the underlying reader,
// strips any padding, and copies the payload into p.
func (cr *CamouflageReader) Read(p []byte) (int, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// Return buffered data first.
	if len(cr.buf) > 0 {
		n := copy(p, cr.buf)
		cr.buf = cr.buf[n:]
		return n, nil
	}

	// Read the next frame.
	frame, err := ReadFrame(cr.r)
	if err != nil {
		return 0, err
	}

	// Only DATA frames carry payload; others are control frames.
	switch frame.Type {
	case FrameData:
		n := copy(p, frame.Payload)
		if n < len(frame.Payload) {
			cr.buf = make([]byte, len(frame.Payload)-n)
			copy(cr.buf, frame.Payload[n:])
		}
		return n, nil

	case FrameKeepalive:
		// Silently consume keepalive frames, try to read next frame.
		cr.mu.Unlock()
		n, err := cr.Read(p)
		cr.mu.Lock()
		return n, err

	case FrameClose:
		return 0, io.EOF

	default:
		// Skip unknown frame types.
		cr.mu.Unlock()
		n, err := cr.Read(p)
		cr.mu.Lock()
		return n, err
	}
}

// TimingObfuscator adds random delays to network operations to defeat
// timing analysis. DPI systems can detect tunnels by analyzing
// inter-packet timing patterns; this obfuscator introduces jitter
// that matches typical human browsing behavior.
type TimingObfuscator struct {
	config CamouflageConfig
}

// NewTimingObfuscator creates a timing obfuscator with the given config.
func NewTimingObfuscator(config CamouflageConfig) *TimingObfuscator {
	return &TimingObfuscator{config: config}
}

// Delay introduces a random delay within the configured range.
// The delay follows a non-uniform distribution to better mimic
// human browsing patterns (shorter delays are more common).
func (t *TimingObfuscator) Delay() {
	if !t.config.Enabled {
		return
	}
	if t.config.MaxDelay <= 0 {
		return
	}

	minNs := t.config.MinDelay.Nanoseconds()
	maxNs := t.config.MaxDelay.Nanoseconds()
	if maxNs <= minNs {
		return
	}

	// Use exponential-like distribution: shorter delays are more likely.
	// Generate two random values and take the minimum for a skewed distribution.
	range64 := maxNs - minNs
	r1 := int64(cryptoRandIntn(int(range64)))
	r2 := int64(cryptoRandIntn(int(range64)))
	delay := r1
	if r2 < delay {
		delay = r2
	}

	time.Sleep(time.Duration(minNs + delay))
}

// ShouldDelay returns true if a delay should be inserted before the
// next write, based on a probabilistic decision. Not every packet
// needs a delay — roughly 30% of packets get delayed to maintain
// good throughput while still defeating timing analysis.
func (t *TimingObfuscator) ShouldDelay() bool {
	if !t.config.Enabled {
		return false
	}
	return cryptoRandIntn(10) < 3
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
// Falls back to 0 on error.
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
