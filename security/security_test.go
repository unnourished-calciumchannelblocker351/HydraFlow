package security

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---- RateLimiter tests ----

func TestRateLimiter_AllowUpToLimit(t *testing.T) {
	cfg := RateLimiterConfig{
		MaxRequestsPerWindow: 5,
		WindowDuration:       time.Minute,
		CleanupInterval:      time.Hour, // won't fire during test
	}
	rl := NewRateLimiter(cfg, nil)
	defer rl.Stop()

	ip := "10.0.0.1"
	for i := 0; i < cfg.MaxRequestsPerWindow; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed (limit=%d)", i+1, cfg.MaxRequestsPerWindow)
		}
	}
}

func TestRateLimiter_BlockAfterLimit(t *testing.T) {
	cfg := RateLimiterConfig{
		MaxRequestsPerWindow: 3,
		WindowDuration:       time.Minute,
		CleanupInterval:      time.Hour,
	}
	rl := NewRateLimiter(cfg, nil)
	defer rl.Stop()

	ip := "10.0.0.2"
	for i := 0; i < cfg.MaxRequestsPerWindow; i++ {
		rl.Allow(ip)
	}

	if rl.Allow(ip) {
		t.Fatal("request beyond limit should be blocked")
	}
}

func TestRateLimiter_ResetAfterWindow(t *testing.T) {
	cfg := RateLimiterConfig{
		MaxRequestsPerWindow: 2,
		WindowDuration:       50 * time.Millisecond,
		CleanupInterval:      time.Hour,
	}
	rl := NewRateLimiter(cfg, nil)
	defer rl.Stop()

	ip := "10.0.0.3"
	// Exhaust the window.
	for i := 0; i < cfg.MaxRequestsPerWindow; i++ {
		rl.Allow(ip)
	}
	if rl.Allow(ip) {
		t.Fatal("should be blocked within window")
	}

	// Wait for the window to expire.
	time.Sleep(80 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("should be allowed after window expires")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	cfg := RateLimiterConfig{
		MaxRequestsPerWindow: 1,
		WindowDuration:       time.Minute,
		CleanupInterval:      time.Hour,
	}
	rl := NewRateLimiter(cfg, nil)
	defer rl.Stop()

	if !rl.Allow("10.0.0.1") {
		t.Fatal("first IP first request should be allowed")
	}
	if !rl.Allow("10.0.0.2") {
		t.Fatal("second IP first request should be allowed")
	}
	if rl.Allow("10.0.0.1") {
		t.Fatal("first IP second request should be blocked")
	}
}

// ---- BruteForceProtection tests ----

func TestBruteForce_LockoutAfterMaxAttempts(t *testing.T) {
	cfg := BruteForceConfig{
		MaxAttempts:     3,
		LockoutDuration: time.Minute,
		CleanupInterval: time.Hour,
	}
	bf := NewBruteForceProtection(cfg, nil)
	defer bf.Stop()

	ip := "192.168.1.1"

	// First N-1 failures should not lock.
	for i := 0; i < cfg.MaxAttempts-1; i++ {
		locked := bf.RecordFailure(ip)
		if locked {
			t.Fatalf("should not be locked after %d failures", i+1)
		}
	}

	// The N-th failure should lock.
	if !bf.RecordFailure(ip) {
		t.Fatal("should be locked after max attempts")
	}

	if !bf.IsLocked(ip) {
		t.Fatal("IsLocked should return true after lockout")
	}
}

func TestBruteForce_NotLockedInitially(t *testing.T) {
	cfg := DefaultBruteForceConfig()
	bf := NewBruteForceProtection(cfg, nil)
	defer bf.Stop()

	if bf.IsLocked("1.2.3.4") {
		t.Fatal("unknown IP should not be locked")
	}
}

func TestBruteForce_UnlockAfterTimeout(t *testing.T) {
	cfg := BruteForceConfig{
		MaxAttempts:     2,
		LockoutDuration: 50 * time.Millisecond,
		CleanupInterval: time.Hour,
	}
	bf := NewBruteForceProtection(cfg, nil)
	defer bf.Stop()

	ip := "192.168.1.2"
	for i := 0; i < cfg.MaxAttempts; i++ {
		bf.RecordFailure(ip)
	}

	if !bf.IsLocked(ip) {
		t.Fatal("should be locked immediately after max failures")
	}

	time.Sleep(80 * time.Millisecond)

	if bf.IsLocked(ip) {
		t.Fatal("should be unlocked after lockout duration")
	}
}

func TestBruteForce_RecordSuccessResets(t *testing.T) {
	cfg := BruteForceConfig{
		MaxAttempts:     3,
		LockoutDuration: time.Minute,
		CleanupInterval: time.Hour,
	}
	bf := NewBruteForceProtection(cfg, nil)
	defer bf.Stop()

	ip := "192.168.1.3"

	// Record 2 failures (one short of lockout).
	bf.RecordFailure(ip)
	bf.RecordFailure(ip)

	// Success resets.
	bf.RecordSuccess(ip)

	// After reset, 2 more failures should NOT lock (need MaxAttempts again).
	bf.RecordFailure(ip)
	bf.RecordFailure(ip)
	if bf.IsLocked(ip) {
		t.Fatal("should not be locked: counter was reset by RecordSuccess")
	}
}

// ---- AntiProbe tests ----

func TestAntiProbe_FallbackStaticHTML(t *testing.T) {
	cfg := AntiProbeConfig{
		HandshakeTimeout: time.Second,
		Mode:             FallbackStaticHTML,
		StaticHTML:       "<h1>Test</h1>",
	}
	ap := NewAntiProbe(cfg, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ap.HandleFallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "<h1>Test</h1>" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("unexpected content-type: %s", ct)
	}
	if srv := rec.Header().Get("Server"); srv != "nginx/1.24.0" {
		t.Fatalf("unexpected server header: %s", srv)
	}
}

func TestAntiProbe_FallbackForbidden(t *testing.T) {
	cfg := AntiProbeConfig{
		HandshakeTimeout: time.Second,
		Mode:             FallbackForbidden,
	}
	ap := NewAntiProbe(cfg, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	ap.HandleFallback(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if rec.Body.String() != "403 Forbidden" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestAntiProbe_DefaultConfig(t *testing.T) {
	cfg := DefaultAntiProbeConfig()
	if cfg.HandshakeTimeout != 3*time.Second {
		t.Fatalf("unexpected default timeout: %v", cfg.HandshakeTimeout)
	}
	if cfg.Mode != FallbackReverseProxy {
		t.Fatalf("unexpected default mode: %v", cfg.Mode)
	}
}

// ---- TLS config tests ----

func TestTLSConfigInsecure_TLS13Only(t *testing.T) {
	cfg := TLSConfigInsecure()

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion TLS 1.3 (%d), got %d", tls.VersionTLS13, cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("expected MaxVersion TLS 1.3 (%d), got %d", tls.VersionTLS13, cfg.MaxVersion)
	}
}

func TestTLSConfigInsecure_CurvePreferences(t *testing.T) {
	cfg := TLSConfigInsecure()

	expected := []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256}
	if len(cfg.CurvePreferences) != len(expected) {
		t.Fatalf("expected %d curves, got %d", len(expected), len(cfg.CurvePreferences))
	}
	for i, c := range expected {
		if cfg.CurvePreferences[i] != c {
			t.Fatalf("curve[%d]: expected %v, got %v", i, c, cfg.CurvePreferences[i])
		}
	}
}

func TestTLSConfigInsecure_ALPNProtocols(t *testing.T) {
	cfg := TLSConfigInsecure()

	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Fatalf("unexpected ALPN: %v", cfg.NextProtos)
	}
}

// ---- hashIPForLog tests ----

func TestHashIPForLog_Deterministic(t *testing.T) {
	ip := "192.168.0.1"
	h1 := hashIPForLog(ip)
	h2 := hashIPForLog(ip)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
}

func TestHashIPForLog_DifferentIPsDifferentHashes(t *testing.T) {
	h1 := hashIPForLog("10.0.0.1")
	h2 := hashIPForLog("10.0.0.2")
	if h1 == h2 {
		t.Fatal("different IPs should produce different hashes")
	}
}

func TestHashIPForLog_Length(t *testing.T) {
	h := hashIPForLog("10.0.0.1")
	// sha256Short returns first 4 bytes as hex = 8 hex chars.
	if len(h) != 8 {
		t.Fatalf("expected 8 hex chars, got %d (%s)", len(h), h)
	}
}
