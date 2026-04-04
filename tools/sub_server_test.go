package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fuzzyMatchISP
// ---------------------------------------------------------------------------

func TestFuzzyMatchISP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		isp  string
		org  string
		want string
	}{
		{"PJSC MegaFon", "", "megafon"},
		{"MTS PJSC", "", "mts"},
		{"Mobile TeleSystems", "", "mts"},
		{"Beeline", "", "beeline"},
		{"PJSC VimpelCom", "", "beeline"},
		{"Tele2 AB", "", "tele2"},
		{"Rostelecom", "", "rostelecom"},
		{"LLC Dom.Ru", "", "domru"},
		{"ERTelecom Holding", "", "domru"},
		{"Yota", "", "yota"},
		{"Scartel LLC", "", "yota"},
		{"TransTeleCom", "", "ttk"},
		{"China Telecom", "", "china-telecom"},
		{"ChinaNet", "", "china-telecom"},
		{"China Mobile", "", "china-mobile"},
		{"CMNET", "", "china-mobile"},
		{"China Unicom", "", "china-unicom"},
		{"Mobile Communication Company of Iran", "", "mci"},
		{"MTN Irancell", "", "irancell"},
		{"", "MegaFon", "megafon"},
		{"Unknown ISP", "Unknown Org", "default"},
		{"", "", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.isp+"_"+tt.org, func(t *testing.T) {
			t.Parallel()
			got := fuzzyMatchISP(tt.isp, tt.org)
			if got != tt.want {
				t.Errorf("fuzzyMatchISP(%q, %q) = %q, want %q", tt.isp, tt.org, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ispPriority map
// ---------------------------------------------------------------------------

func TestISPPriorityMap(t *testing.T) {
	t.Parallel()
	expectedISPs := []string{
		"megafon", "mts", "beeline", "tele2", "rostelecom",
		"domru", "yota", "ttk",
		"china-telecom", "china-mobile", "china-unicom",
		"mci", "irancell",
		"default",
	}

	for _, isp := range expectedISPs {
		t.Run(isp, func(t *testing.T) {
			t.Parallel()
			prioList, ok := ispPriority[isp]
			if !ok {
				t.Fatalf("ISP %q not in ispPriority map", isp)
			}
			if len(prioList) == 0 {
				t.Errorf("ISP %q has empty priority list", isp)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ispBypass map
// ---------------------------------------------------------------------------

func TestISPBypassMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		isp             string
		wantFragment    string
		wantPadding     bool
	}{
		{"megafon", "tlshello", true},
		{"mts", "tlshello", true},
		{"tele2", "tlshello", true},
		{"rostelecom", "tlshello", false},
		{"yota", "tlshello", true},
		{"mci", "tlshello", true},
		{"irancell", "tlshello", true},
		{"china-telecom", "1-3", false},
	}

	for _, tt := range tests {
		t.Run(tt.isp, func(t *testing.T) {
			t.Parallel()
			b, ok := ispBypass[tt.isp]
			if !ok {
				t.Fatalf("ISP %q not in ispBypass map", tt.isp)
			}
			if b.FragmentPackets != tt.wantFragment {
				t.Errorf("FragmentPackets = %q, want %q", b.FragmentPackets, tt.wantFragment)
			}
			if b.PaddingEnabled != tt.wantPadding {
				t.Errorf("PaddingEnabled = %v, want %v", b.PaddingEnabled, tt.wantPadding)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildProtocolList
// ---------------------------------------------------------------------------

func TestBuildProtocolList(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP: "1.2.3.4",
		Protocols: map[string]ProtocolConfig{
			"reality": {Port: 443, UUID: "u1", SNI: "example.com", PublicKey: "pk", ShortID: "ab"},
			"ws":      {Port: 8443, UUID: "u1", Path: "/ws", Host: "cdn.example.com"},
			"grpc":    {Port: 8443, UUID: "u1", ServiceName: "grpc"},
		},
		SubToken: "tok",
		SubPort:  10086,
	}

	srv := &server{
		cfg:           cfg,
		isp:           newISPLookup(),
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
		startTime:     time.Now(),
	}

	// MegaFon: ws-cdn, grpc-cdn, xhttp, shadowtls.
	protocols := srv.buildProtocolList("megafon")
	if len(protocols) == 0 {
		t.Fatal("expected non-empty protocol list")
	}

	// First protocol should be ws (mapped from ws-cdn).
	if protocols[0].Name != "ws" {
		t.Errorf("first protocol = %q, want %q", protocols[0].Name, "ws")
	}

	// Check all configured protocols are present.
	names := make(map[string]bool)
	for _, p := range protocols {
		names[p.Name] = true
	}
	for protoName := range cfg.Protocols {
		if !names[protoName] {
			t.Errorf("protocol %q not in output list", protoName)
		}
	}
}

// ---------------------------------------------------------------------------
// ISP lookup cache — set and get
// ---------------------------------------------------------------------------

func TestISPLookupCache(t *testing.T) {
	t.Parallel()
	l := newISPLookup()

	// Manually populate cache.
	l.mu.Lock()
	l.cache["1.2.3.4"] = &ispCacheEntry{
		ispName:   "megafon",
		raw:       &ipAPIResponse{Status: "success", ISP: "MegaFon"},
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	l.mu.Unlock()

	// Should return cached result (no network call).
	name, raw := l.lookup("1.2.3.4")
	if name != "megafon" {
		t.Errorf("cached ISP = %q, want %q", name, "megafon")
	}
	if raw == nil || raw.ISP != "MegaFon" {
		t.Error("cached raw response mismatch")
	}
}

func TestISPLookupCacheExpiry(t *testing.T) {
	t.Parallel()
	l := newISPLookup()

	// Set an expired entry.
	l.mu.Lock()
	l.cache["10.0.0.1"] = &ispCacheEntry{
		ispName:   "mts",
		raw:       &ipAPIResponse{Status: "success"},
		expiresAt: time.Now().Add(-1 * time.Hour),
	}
	l.mu.Unlock()

	// Expired cache for private IP falls through to private IP detection.
	name, _ := l.lookup("10.0.0.1")
	if name != "default" {
		t.Errorf("expired cache for private IP = %q, want %q", name, "default")
	}
}

func TestISPLookupPrivateIP(t *testing.T) {
	t.Parallel()
	l := newISPLookup()

	tests := []struct {
		ip   string
		want string
	}{
		{"127.0.0.1", "default"},
		{"192.168.1.1", "default"},
		{"10.0.0.1", "default"},
		{"::1", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()
			got, _ := l.lookup(tt.ip)
			if got != tt.want {
				t.Errorf("lookup(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Health checker — mark up/down
// ---------------------------------------------------------------------------

func TestProtocolHealth_SetAndGet(t *testing.T) {
	t.Parallel()
	ph := newProtocolHealth()

	ph.set("reality", &healthStatus{Up: true, LastCheck: time.Now(), Latency: 42})
	ph.set("ws", &healthStatus{Up: false, LastCheck: time.Now(), Error: "timeout"})

	realityStat := ph.get("reality")
	if !realityStat.Up {
		t.Error("reality should be UP")
	}
	if realityStat.Latency != 42 {
		t.Errorf("reality latency = %d, want 42", realityStat.Latency)
	}

	wsStat := ph.get("ws")
	if wsStat.Up {
		t.Error("ws should be DOWN")
	}
	if wsStat.Error != "timeout" {
		t.Errorf("ws error = %q, want %q", wsStat.Error, "timeout")
	}

	// Unknown protocol returns Up=true (assume up).
	unknownStat := ph.get("unknown")
	if !unknownStat.Up {
		t.Error("unknown protocol should assume UP")
	}
}

func TestProtocolHealth_GetAll(t *testing.T) {
	t.Parallel()
	ph := newProtocolHealth()

	ph.set("a", &healthStatus{Up: true})
	ph.set("b", &healthStatus{Up: false})

	all := ph.getAll()
	if len(all) != 2 {
		t.Fatalf("getAll returned %d, want 2", len(all))
	}

	// Modify returned map should not affect internal state.
	all["a"].Up = false
	orig := ph.get("a")
	if !orig.Up {
		t.Error("getAll should return a copy")
	}
}

func TestProtocolHealth_MockTCPServer(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	cfg := &SubConfig{
		ServerIP: "127.0.0.1",
		Protocols: map[string]ProtocolConfig{
			"test-proto": {Port: port},
		},
	}

	ph := newProtocolHealth()
	ph.checkAll(cfg)

	// Allow time for goroutine to complete.
	time.Sleep(200 * time.Millisecond)

	stat := ph.get("test-proto")
	if !stat.Up {
		t.Errorf("mock server protocol should be UP, error=%q", stat.Error)
	}
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

func TestReportRateLimiter_AllowUnderLimit(t *testing.T) {
	t.Parallel()
	rl := newReportRateLimiter()

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4", 3) {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
}

func TestReportRateLimiter_BlockOverLimit(t *testing.T) {
	t.Parallel()
	rl := newReportRateLimiter()

	for i := 0; i < 5; i++ {
		rl.allow("1.2.3.4", 3)
	}

	if rl.allow("1.2.3.4", 3) {
		t.Error("should be blocked after exceeding limit")
	}
}

func TestReportRateLimiter_DifferentIPs(t *testing.T) {
	t.Parallel()
	rl := newReportRateLimiter()

	for i := 0; i < 3; i++ {
		rl.allow("1.1.1.1", 3)
	}

	// Different IP should still be allowed.
	if !rl.allow("2.2.2.2", 3) {
		t.Error("different IP should not be rate limited")
	}
}

func TestReportRateLimiter_ResetAfterExpiry(t *testing.T) {
	t.Parallel()
	rl := newReportRateLimiter()

	// Exhaust the limit.
	for i := 0; i < 4; i++ {
		rl.allow("5.5.5.5", 3)
	}
	if rl.allow("5.5.5.5", 3) {
		t.Error("should be rate limited")
	}

	// Force reset by setting resetAt in the past.
	rl.mu.Lock()
	rl.resetAt = time.Now().Add(-1 * time.Second)
	rl.mu.Unlock()

	if !rl.allow("5.5.5.5", 3) {
		t.Error("should be allowed after reset")
	}
}

// ---------------------------------------------------------------------------
// Telemetry store
// ---------------------------------------------------------------------------

func TestTelemetryStore_RecordAndIsBlocked(t *testing.T) {
	t.Parallel()
	ts := newTelemetryStore()

	// Not blocked with no data.
	if ts.isBlocked("megafon", "reality") {
		t.Error("should not be blocked with no data")
	}

	// Record 5 blocked -- not enough.
	for i := 0; i < 5; i++ {
		ts.record("megafon", telemetryReport{Protocol: "reality", Status: "blocked"})
	}
	if ts.isBlocked("megafon", "reality") {
		t.Error("should not be blocked with only 5 reports")
	}

	// Record 6 more blocked (11 total, 100% blocked).
	for i := 0; i < 6; i++ {
		ts.record("megafon", telemetryReport{Protocol: "reality", Status: "blocked"})
	}
	if !ts.isBlocked("megafon", "reality") {
		t.Error("should be blocked with 11 blocked reports")
	}
}

func TestTelemetryStore_NotBlockedWhenOKDominates(t *testing.T) {
	t.Parallel()
	ts := newTelemetryStore()

	for i := 0; i < 8; i++ {
		ts.record("mts", telemetryReport{Protocol: "ws", Status: "ok"})
	}
	for i := 0; i < 4; i++ {
		ts.record("mts", telemetryReport{Protocol: "ws", Status: "blocked"})
	}

	if ts.isBlocked("mts", "ws") {
		t.Error("should not be blocked when OK dominates (33% < 60%)")
	}
}

func TestTelemetryStore_Snapshot(t *testing.T) {
	t.Parallel()
	ts := newTelemetryStore()

	ts.record("megafon", telemetryReport{Protocol: "reality", Status: "ok"})
	ts.record("megafon", telemetryReport{Protocol: "reality", Status: "blocked"})

	snap := ts.getSnapshot()
	if _, ok := snap["megafon"]; !ok {
		t.Fatal("expected megafon in snapshot")
	}
	pt := snap["megafon"].Protocols["reality"]
	if pt.OK != 1 || pt.Blocked != 1 {
		t.Errorf("counters: OK=%d Blocked=%d, want 1/1", pt.OK, pt.Blocked)
	}
}

// ---------------------------------------------------------------------------
// V2Ray link generation
// ---------------------------------------------------------------------------

func TestBuildV2RayLink_Reality(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP: "1.2.3.4",
		Protocols: map[string]ProtocolConfig{
			"reality": {
				Port:      443,
				UUID:      "test-uuid",
				SNI:       "www.example.com",
				PublicKey: "pubkey123",
				ShortID:   "ab",
				Flow:      "xtls-rprx-vision",
			},
		},
		SubToken: "tok",
		SubPort:  10086,
	}

	srv := &server{
		cfg:           cfg,
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
	}

	proto := orderedProtocol{
		Name:   "reality",
		Config: cfg.Protocols["reality"],
		Label:  "HydraFlow-Reality (recommended)",
	}

	link := srv.buildV2RayLink(proto)

	if !strings.HasPrefix(link, "vless://") {
		t.Errorf("link should start with vless://, got %q", link)
	}
	if !strings.Contains(link, "test-uuid") {
		t.Error("link missing UUID")
	}
	if !strings.Contains(link, "1.2.3.4") {
		t.Error("link missing server IP")
	}
	if !strings.Contains(link, "security=reality") {
		t.Error("link missing security=reality")
	}
	if !strings.Contains(link, "pbk=pubkey123") {
		t.Error("link missing public key")
	}
}

func TestBuildV2RayLink_WS(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP: "1.2.3.4",
		Protocols: map[string]ProtocolConfig{
			"ws": {
				Port: 443,
				UUID: "test-uuid",
				Path: "/ws-path",
				Host: "cdn.example.com",
			},
		},
		SubToken: "tok",
	}

	srv := &server{
		cfg:           cfg,
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
	}

	proto := orderedProtocol{
		Name:   "ws",
		Config: cfg.Protocols["ws"],
		Label:  "HydraFlow-WS-CDN",
	}

	link := srv.buildV2RayLink(proto)

	if !strings.HasPrefix(link, "vless://") {
		t.Errorf("link should start with vless://, got %q", link)
	}
	if !strings.Contains(link, "type=ws") {
		t.Error("link missing type=ws")
	}
	if !strings.Contains(link, "cdn.example.com") {
		t.Error("link missing CDN host")
	}
}

// ---------------------------------------------------------------------------
// extractClientIP
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			name:       "localhost trusts XFF",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.5, 10.0.0.1",
			want:       "203.0.113.5",
		},
		{
			name:       "localhost trusts X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xRealIP:    "198.51.100.7",
			want:       "198.51.100.7",
		},
		{
			name:       "non-localhost ignores XFF",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.5",
			want:       "10.0.0.1",
		},
		{
			name:       "ipv6 localhost trusts XFF",
			remoteAddr: "[::1]:12345",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			got := extractClientIP(r)
			if got != tt.want {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		ua    string
		query string
		want  string
	}{
		{"query v2ray", "", "format=v2ray", "v2ray"},
		{"query clash", "", "format=clash", "clash"},
		{"query singbox", "", "format=singbox", "singbox"},
		{"query json", "", "format=json", "json"},
		{"query base64", "", "format=base64", "v2ray"},
		{"ua v2rayng", "v2rayNG/1.8.5", "", "v2ray"},
		{"ua clash", "ClashMeta/1.0", "", "clash"},
		{"ua stash", "Stash/2.4", "", "clash"},
		{"ua singbox", "sing-box/1.5", "", "singbox"},
		{"ua hiddify", "Hiddify/1.0", "", "v2ray"},
		{"ua shadowrocket", "Shadowrocket/1.0", "", "v2ray"},
		{"ua nekobox", "NekoBox/1.0", "", "v2ray"},
		{"ua unknown", "curl/7.0", "", "v2ray"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url := "/"
			if tt.query != "" {
				url = "/?" + tt.query
			}
			r := httptest.NewRequest(http.MethodGet, url, nil)
			if tt.ua != "" {
				r.Header.Set("User-Agent", tt.ua)
			}
			got := detectFormat(r)
			if got != tt.want {
				t.Errorf("detectFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// formatProtocolName
// ---------------------------------------------------------------------------

func TestFormatProtocolName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"reality", "Reality"},
		{"ws", "WS-CDN"},
		{"grpc", "gRPC-CDN"},
		{"xhttp", "XHTTP"},
		{"ss", "SS-2022"},
		{"hysteria2", "Hysteria2"},
		{"shadowtls", "ShadowTLS"},
		{"naiveproxy", "NaiveProxy"},
		{"custom", "Custom"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := formatProtocolName(tt.input)
			if got != tt.want {
				t.Errorf("formatProtocolName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hashIP
// ---------------------------------------------------------------------------

func TestHashIP(t *testing.T) {
	t.Parallel()
	h1 := hashIP("192.168.1.1")
	h2 := hashIP("192.168.1.1")
	if h1 != h2 {
		t.Error("hashIP not deterministic")
	}

	h3 := hashIP("10.0.0.1")
	if h1 == h3 {
		t.Error("different IPs produced same hash")
	}

	if len(h1) != 8 {
		t.Errorf("hash length = %d, want 8", len(h1))
	}
}

// ---------------------------------------------------------------------------
// coalesce
// ---------------------------------------------------------------------------

func TestCoalesce(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"first non-empty", []string{"a", "b"}, "a"},
		{"skip empty", []string{"", "b"}, "b"},
		{"all empty", []string{"", ""}, ""},
		{"single value", []string{"x"}, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := coalesce(tt.values...)
			if got != tt.want {
				t.Errorf("coalesce(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Full HTTP handler test — subscription endpoint
// ---------------------------------------------------------------------------

func TestHTTPHandler_SubscriptionOK(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP: "1.2.3.4",
		Protocols: map[string]ProtocolConfig{
			"reality": {
				Port:      443,
				UUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				SNI:       "www.example.com",
				PublicKey: "pk123",
				ShortID:   "ab",
				Flow:      "xtls-rprx-vision",
			},
		},
		SubToken: "test-token",
		SubPort:  10086,
	}

	srv := &server{
		cfg:           cfg,
		isp:           newISPLookup(),
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
		startTime:     time.Now(),
	}

	// Mark protocol as up.
	srv.health.set("reality", &healthStatus{Up: true, LastCheck: time.Now()})

	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		srv.handleSubscription(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/sub/test-token", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Body should be valid base64.
	decoded, err := base64.StdEncoding.DecodeString(rr.Body.String())
	if err != nil {
		t.Fatalf("response is not valid base64: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Errorf("decoded body should contain vless:// link, got: %s", string(decoded))
	}

	// Check headers.
	if rr.Header().Get("Subscription-UserInfo") == "" {
		t.Error("missing Subscription-UserInfo header")
	}
	// X-HydraFlow-ISP header intentionally removed for security —
	// it would let observers fingerprint HydraFlow traffic.
}

func TestHTTPHandler_SubscriptionWrongToken(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP:  "1.2.3.4",
		Protocols: map[string]ProtocolConfig{"reality": {Port: 443}},
		SubToken:  "real-token",
	}

	srv := &server{
		cfg:           cfg,
		isp:           newISPLookup(),
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
		startTime:     time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		srv.handleSubscription(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/sub/wrong-token", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHTTPHandler_ReportEndpoint(t *testing.T) {
	t.Parallel()

	cfg := &SubConfig{
		ServerIP:  "1.2.3.4",
		Protocols: map[string]ProtocolConfig{"reality": {Port: 443}},
		SubToken:  "tok",
	}

	srv := &server{
		cfg:           cfg,
		isp:           newISPLookup(),
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
		startTime:     time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		srv.handleReport(w, r)
	})

	report := telemetryReport{
		ASN:      31213,
		Protocol: "reality",
		Status:   "ok",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

func TestLoadConfig_Valid(t *testing.T) {
	t.Parallel()

	configJSON := `{
		"server_ip": "1.2.3.4",
		"sub_token": "test-token",
		"sub_port": 8080,
		"protocols": {
			"reality": {"port": 443, "uuid": "test-uuid"}
		}
	}`

	tmpFile := t.TempDir() + "/config.json"
	if err := writeTestFile(tmpFile, configJSON); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(tmpFile)
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if cfg.ServerIP != "1.2.3.4" {
		t.Errorf("ServerIP = %q, want %q", cfg.ServerIP, "1.2.3.4")
	}
	if cfg.SubToken != "test-token" {
		t.Errorf("SubToken = %q, want %q", cfg.SubToken, "test-token")
	}
	if cfg.SubPort != 8080 {
		t.Errorf("SubPort = %d, want %d", cfg.SubPort, 8080)
	}
}

func TestLoadConfig_DefaultPort(t *testing.T) {
	t.Parallel()

	configJSON := `{
		"server_ip": "1.2.3.4",
		"sub_token": "tok",
		"protocols": {"reality": {"port": 443}}
	}`

	tmpFile := t.TempDir() + "/config.json"
	if err := writeTestFile(tmpFile, configJSON); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SubPort != 10086 {
		t.Errorf("default SubPort = %d, want 10086", cfg.SubPort)
	}
}

func TestLoadConfig_MissingToken(t *testing.T) {
	t.Parallel()
	configJSON := `{"server_ip": "1.2.3.4", "protocols": {"reality": {"port": 443}}}`
	tmpFile := t.TempDir() + "/config.json"
	writeTestFile(tmpFile, configJSON)

	_, err := loadConfig(tmpFile)
	if err == nil {
		t.Error("expected error for missing sub_token")
	}
}

func TestLoadConfig_MissingServerIP(t *testing.T) {
	t.Parallel()
	configJSON := `{"sub_token": "tok", "protocols": {"reality": {"port": 443}}}`
	tmpFile := t.TempDir() + "/config.json"
	writeTestFile(tmpFile, configJSON)

	_, err := loadConfig(tmpFile)
	if err == nil {
		t.Error("expected error for missing server_ip")
	}
}

func TestLoadConfig_NoProtocols(t *testing.T) {
	t.Parallel()
	configJSON := `{"server_ip": "1.2.3.4", "sub_token": "tok", "protocols": {}}`
	tmpFile := t.TempDir() + "/config.json"
	writeTestFile(tmpFile, configJSON)

	_, err := loadConfig(tmpFile)
	if err == nil {
		t.Error("expected error for empty protocols")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
