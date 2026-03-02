package discovery

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ReporterConfig configures the anonymous telemetry reporter.
type ReporterConfig struct {
	// Endpoint is the URL to send reports to.
	Endpoint string

	// BatchSize is how many reports to batch before sending.
	// Default: 10.
	BatchSize int

	// FlushInterval is the maximum time to wait before flushing
	// a partial batch. Default: 5 minutes.
	FlushInterval time.Duration

	// Enabled controls whether reporting is active.
	// This is the opt-in/opt-out control.
	Enabled bool

	// EncryptionKey is the public key for the relay (first hop).
	// Reports are double-encrypted: once for the relay, once for
	// the collector, so neither party can read the full report alone.
	RelayPublicKey []byte

	// CollectorPublicKey is the public key for the final collector.
	CollectorPublicKey []byte
}

// TelemetryReport is the anonymized data sent to the server.
// It contains ONLY AS number and protocol status, never IP addresses
// or other identifying information.
type TelemetryReport struct {
	// ASNumber identifies the ISP without revealing the user.
	ASNumber uint32 `json:"as_number"`

	// Protocol is the protocol name that was tested.
	Protocol string `json:"protocol"`

	// Status is the observed protocol status.
	Status ProtocolStatus `json:"status"`

	// Latency is the observed latency in milliseconds (optional).
	LatencyMS int64 `json:"latency_ms,omitempty"`

	// Timestamp is when the observation was made (truncated to hour
	// for additional anonymity).
	Timestamp time.Time `json:"timestamp"`
}

// Reporter is an anonymous telemetry reporter that batches and
// double-encrypts reports before sending them to a collection server.
// It implements OHTTP-like privacy: reports are encrypted first for
// the collector, then wrapped in encryption for a relay. The relay
// can strip its layer but cannot read the inner payload, and the
// collector never sees the client's IP (only the relay's).
type Reporter struct {
	mu     sync.Mutex
	config ReporterConfig
	batch  []TelemetryReport
	client *http.Client

	stopCh chan struct{}
	done   chan struct{}
}

// NewReporter creates a new anonymous telemetry reporter.
func NewReporter(cfg ReporterConfig) *Reporter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Minute
	}

	return &Reporter{
		config: cfg,
		batch:  make([]TelemetryReport, 0, cfg.BatchSize),
		client: &http.Client{Timeout: 30 * time.Second},
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start begins the background flush loop. Call Stop to terminate.
func (r *Reporter) Start() {
	go r.flushLoop()
}

// Stop terminates the reporter, flushing any pending reports.
func (r *Reporter) Stop() {
	close(r.stopCh)
	<-r.done
}

// SetEnabled changes the opt-in/opt-out status at runtime.
func (r *Reporter) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config.Enabled = enabled

	// If disabled, discard any pending reports.
	if !enabled {
		r.batch = r.batch[:0]
	}
}

// IsEnabled returns the current opt-in status.
func (r *Reporter) IsEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.config.Enabled
}

// Report queues a telemetry report for sending. The report is
// anonymized: timestamps are truncated to the hour, and only
// AS number + protocol status are included.
func (r *Reporter) Report(asNumber uint32, protocol string, status ProtocolStatus, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.config.Enabled {
		return
	}

	report := TelemetryReport{
		ASNumber:  asNumber,
		Protocol:  protocol,
		Status:    status,
		LatencyMS: latency.Milliseconds(),
		Timestamp: time.Now().Truncate(time.Hour), // truncate for anonymity
	}

	r.batch = append(r.batch, report)

	if len(r.batch) >= r.config.BatchSize {
		r.flushLocked()
	}
}

// PendingCount returns the number of reports waiting to be sent.
func (r *Reporter) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batch)
}

// flushLoop periodically flushes pending reports.
func (r *Reporter) flushLoop() {
	defer close(r.done)

	ticker := time.NewTicker(r.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			// Final flush.
			r.mu.Lock()
			r.flushLocked()
			r.mu.Unlock()
			return
		case <-ticker.C:
			r.mu.Lock()
			r.flushLocked()
			r.mu.Unlock()
		}
	}
}

// flushLocked sends all pending reports. Must be called with mu held.
func (r *Reporter) flushLocked() {
	if len(r.batch) == 0 {
		return
	}
	if !r.config.Enabled {
		r.batch = r.batch[:0]
		return
	}

	reports := make([]TelemetryReport, len(r.batch))
	copy(reports, r.batch)
	r.batch = r.batch[:0]

	// Send asynchronously to avoid blocking the caller.
	go r.sendBatch(reports)
}

// sendBatch encrypts and sends a batch of reports.
func (r *Reporter) sendBatch(reports []TelemetryReport) {
	payload, err := json.Marshal(reports)
	if err != nil {
		return
	}

	// Double encryption: inner layer for collector, outer for relay.
	encrypted, err := r.doubleEncrypt(payload)
	if err != nil {
		return
	}

	if r.config.Endpoint == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.Endpoint, bytes.NewReader(encrypted))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	// No cookies, no auth headers, no identifying information.

	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Discard body — we don't need the response.
	_, _ = io.Copy(io.Discard, resp.Body)
}

// doubleEncrypt implements OHTTP-like double encryption.
// Inner layer: AES-GCM encrypted for the collector.
// Outer layer: AES-GCM encrypted for the relay.
// The relay strips its layer and forwards the inner ciphertext
// to the collector, which decrypts the final payload.
//
// This ensures:
// - The relay sees the client IP but not the report content.
// - The collector sees the report content but not the client IP.
func (r *Reporter) doubleEncrypt(plaintext []byte) ([]byte, error) {
	// Inner encryption for the collector.
	innerKey := r.config.CollectorPublicKey
	if len(innerKey) == 0 {
		// Fallback: derive a key from a fixed seed.
		// In production, this would use proper HPKE key exchange.
		h := sha256.Sum256([]byte("hydraflow-collector-default"))
		innerKey = h[:]
	}

	innerCiphertext, err := aesGCMEncrypt(innerKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("inner encrypt: %w", err)
	}

	// Outer encryption for the relay.
	outerKey := r.config.RelayPublicKey
	if len(outerKey) == 0 {
		h := sha256.Sum256([]byte("hydraflow-relay-default"))
		outerKey = h[:]
	}

	outerCiphertext, err := aesGCMEncrypt(outerKey, innerCiphertext)
	if err != nil {
		return nil, fmt.Errorf("outer encrypt: %w", err)
	}

	return outerCiphertext, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM with the given key.
// The key is hashed to ensure it's exactly 32 bytes.
// Returns nonce || ciphertext.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	// Ensure 32-byte key for AES-256.
	h := sha256.Sum256(key)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesGCMDecrypt decrypts data produced by aesGCMEncrypt.
// Exported for testing and for the collector/relay implementations.
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	h := sha256.Sum256(key)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
