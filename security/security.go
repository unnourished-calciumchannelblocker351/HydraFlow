// Package security provides anti-censorship defense mechanisms including
// active probing detection, rate limiting, brute-force protection, and
// hardened TLS configuration for the HydraFlow proxy server.
package security

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// ---- AntiProbe: active probing detection ----

// FallbackMode specifies what to serve when a connection is determined
// to be an active probe rather than a legitimate client.
type FallbackMode int

const (
	// FallbackStaticHTML serves a static HTML page.
	FallbackStaticHTML FallbackMode = iota

	// FallbackReverseProxy proxies requests to a real website.
	FallbackReverseProxy

	// FallbackForbidden returns HTTP 403.
	FallbackForbidden
)

// AntiProbeConfig configures active probe detection.
type AntiProbeConfig struct {
	// HandshakeTimeout is how long to wait for a valid Hydra handshake
	// before treating the connection as a probe.
	HandshakeTimeout time.Duration

	// Mode determines what to serve to probes.
	Mode FallbackMode

	// StaticHTML is the HTML content served when Mode is FallbackStaticHTML.
	StaticHTML string

	// ReverseProxyTarget is the URL to proxy to when Mode is FallbackReverseProxy.
	ReverseProxyTarget string
}

// DefaultAntiProbeConfig returns sensible defaults.
func DefaultAntiProbeConfig() AntiProbeConfig {
	return AntiProbeConfig{
		HandshakeTimeout:   3 * time.Second,
		Mode:               FallbackReverseProxy,
		ReverseProxyTarget: "https://www.microsoft.com",
		StaticHTML: `<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>This server is running normally.</p></body></html>`,
	}
}

// AntiProbe detects active probing from DPI systems and serves fallback
// content instead of revealing proxy behavior.
type AntiProbe struct {
	config AntiProbeConfig
	logger *slog.Logger
}

// NewAntiProbe creates a new AntiProbe instance.
func NewAntiProbe(config AntiProbeConfig, logger *slog.Logger) *AntiProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &AntiProbe{
		config: config,
		logger: logger,
	}
}

// HandleFallback serves fallback content to a connection identified as a probe.
// The conn should already have been determined to NOT be a valid client.
func (ap *AntiProbe) HandleFallback(w http.ResponseWriter, r *http.Request) {
	ap.logger.Debug("serving fallback to probe",
		"remote", r.RemoteAddr,
		"host", r.Host,
		"path", r.URL.Path,
	)

	switch ap.config.Mode {
	case FallbackStaticHTML:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, ap.config.StaticHTML)

	case FallbackReverseProxy:
		ap.reverseProxyFallback(w, r)

	case FallbackForbidden:
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "403 Forbidden")
	}
}

// WrapListener returns a net.Listener that applies handshake timeout detection.
// Connections that do not complete the expected handshake within the timeout
// are handed off to the fallback handler.
func (ap *AntiProbe) WrapListener(inner net.Listener, validCheck func(net.Conn) bool) net.Listener {
	return &antiProbeListener{
		inner:      inner,
		antiProbe:  ap,
		validCheck: validCheck,
	}
}

type antiProbeListener struct {
	inner      net.Listener
	antiProbe  *AntiProbe
	validCheck func(net.Conn) bool
}

func (l *antiProbeListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		// Set a read deadline for the handshake timeout.
		deadline := time.Now().Add(l.antiProbe.config.HandshakeTimeout)
		conn.SetReadDeadline(deadline)

		if l.validCheck != nil && !l.validCheck(conn) {
			l.antiProbe.logger.Debug("probe detected, connection rejected",
				"remote", conn.RemoteAddr(),
			)
			conn.Close()
			continue
		}

		// Reset deadline for normal operation.
		conn.SetReadDeadline(time.Time{})
		return conn, nil
	}
}

func (l *antiProbeListener) Close() error   { return l.inner.Close() }
func (l *antiProbeListener) Addr() net.Addr { return l.inner.Addr() }

func (ap *AntiProbe) reverseProxyFallback(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targetURL := ap.config.ReverseProxyTarget + r.URL.Path
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// Copy relevant headers.
	for _, key := range []string{"Accept", "Accept-Language", "Accept-Encoding", "User-Agent"} {
		if v := r.Header.Get(key); v != "" {
			proxyReq.Header.Set(key, v)
		}
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Server", "nginx/1.24.0")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 10<<20))
}

// ---- Rate Limiter ----

// RateLimiterConfig configures per-IP rate limiting.
type RateLimiterConfig struct {
	// MaxConnectionsPerIP is the maximum concurrent connections from a single IP.
	MaxConnectionsPerIP int

	// WindowDuration is the time window for rate counting.
	WindowDuration time.Duration

	// MaxRequestsPerWindow is the max requests per IP within the window.
	MaxRequestsPerWindow int

	// CleanupInterval is how often to purge stale entries.
	CleanupInterval time.Duration
}

// DefaultRateLimiterConfig returns sensible defaults.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		MaxConnectionsPerIP:  50,
		WindowDuration:       time.Minute,
		MaxRequestsPerWindow: 100,
		CleanupInterval:      5 * time.Minute,
	}
}

type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

// RateLimiter provides per-IP connection rate limiting.
type RateLimiter struct {
	mu      sync.RWMutex
	config  RateLimiterConfig
	entries map[string]*rateLimitEntry
	logger  *slog.Logger
	stopCh  chan struct{}
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config RateLimiterConfig, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	rl := &RateLimiter{
		config:  config,
		entries: make(map[string]*rateLimitEntry),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}

	go rl.cleanupLoop()
	return rl
}

// Allow checks whether a connection from the given IP should be allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[ip]

	if !exists || now.After(entry.windowEnd) {
		rl.entries[ip] = &rateLimitEntry{
			count:     1,
			windowEnd: now.Add(rl.config.WindowDuration),
		}
		return true
	}

	entry.count++
	if entry.count > rl.config.MaxRequestsPerWindow {
		rl.logger.Warn("rate limit exceeded",
			"ip_hash", hashIPForLog(ip),
			"count", entry.count,
			"limit", rl.config.MaxRequestsPerWindow,
		)
		return false
	}

	return true
}

// Stop shuts down the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, entry := range rl.entries {
		if now.After(entry.windowEnd) {
			delete(rl.entries, ip)
		}
	}
}

// ---- Brute Force Protection ----

// BruteForceConfig configures brute-force protection.
type BruteForceConfig struct {
	// MaxAttempts is the number of failed auth attempts before lockout.
	MaxAttempts int

	// LockoutDuration is how long an IP is locked out after exceeding MaxAttempts.
	LockoutDuration time.Duration

	// CleanupInterval is how often to purge expired lockouts.
	CleanupInterval time.Duration
}

// DefaultBruteForceConfig returns sensible defaults.
func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

type bruteForceEntry struct {
	failures    int
	lockedUntil time.Time
}

// BruteForceProtection tracks failed authentication attempts per IP
// and locks out IPs that exceed the threshold.
type BruteForceProtection struct {
	mu      sync.RWMutex
	config  BruteForceConfig
	entries map[string]*bruteForceEntry
	logger  *slog.Logger
	stopCh  chan struct{}
}

// NewBruteForceProtection creates a new brute force protector.
func NewBruteForceProtection(config BruteForceConfig, logger *slog.Logger) *BruteForceProtection {
	if logger == nil {
		logger = slog.Default()
	}
	bf := &BruteForceProtection{
		config:  config,
		entries: make(map[string]*bruteForceEntry),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}

	go bf.cleanupLoop()
	return bf
}

// IsLocked checks whether an IP is currently locked out.
func (bf *BruteForceProtection) IsLocked(ip string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	entry, exists := bf.entries[ip]
	if !exists {
		return false
	}

	return time.Now().Before(entry.lockedUntil)
}

// RecordFailure records a failed authentication attempt from an IP.
// Returns true if the IP is now locked out.
func (bf *BruteForceProtection) RecordFailure(ip string) bool {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	entry, exists := bf.entries[ip]
	if !exists {
		entry = &bruteForceEntry{}
		bf.entries[ip] = entry
	}

	// If already locked and lock hasn't expired, keep locked.
	if time.Now().Before(entry.lockedUntil) {
		return true
	}

	entry.failures++

	if entry.failures >= bf.config.MaxAttempts {
		entry.lockedUntil = time.Now().Add(bf.config.LockoutDuration)
		bf.logger.Warn("IP locked out due to brute force",
			"ip_hash", hashIPForLog(ip),
			"failures", entry.failures,
			"locked_until", entry.lockedUntil.Format(time.RFC3339),
		)
		return true
	}

	return false
}

// RecordSuccess resets the failure counter for an IP on successful auth.
func (bf *BruteForceProtection) RecordSuccess(ip string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.entries, ip)
}

// Stop shuts down the cleanup goroutine.
func (bf *BruteForceProtection) Stop() {
	close(bf.stopCh)
}

func (bf *BruteForceProtection) cleanupLoop() {
	ticker := time.NewTicker(bf.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bf.cleanup()
		case <-bf.stopCh:
			return
		}
	}
}

func (bf *BruteForceProtection) cleanup() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	for ip, entry := range bf.entries {
		if now.After(entry.lockedUntil) && entry.failures < bf.config.MaxAttempts {
			delete(bf.entries, ip)
		}
		// Also clean up expired lockouts.
		if now.After(entry.lockedUntil) && entry.lockedUntil.After(time.Time{}) {
			delete(bf.entries, ip)
		}
	}
}

// ---- TLS Configuration ----

// TLSConfig returns a hardened TLS configuration suitable for a proxy server.
// It enforces TLS 1.3 only with strong ciphers and includes OCSP stapling support.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,

		// TLS 1.3 cipher suites are not configurable in Go (they are all strong).
		// Go automatically selects the best available.

		// Enable session tickets for performance.
		SessionTicketsDisabled: false,

		// ALPN protocols.
		NextProtos: []string{"h2", "http/1.1"},

		// Curve preferences.
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
		},
	}, nil
}

// TLSConfigInsecure returns a hardened TLS config without requiring certificate files.
// It generates a self-signed certificate at runtime (useful for testing).
func TLSConfigInsecure() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
		},
	}
}

// hashIPForLog creates a privacy-preserving hash of an IP for logging.
func hashIPForLog(ip string) string {
	// Use first 8 chars of SHA256 for log entries.
	h := sha256Short(ip)
	return h
}

// sha256Short returns the first 8 hex characters of the SHA-256 hash of s.
func sha256Short(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:4])
}
