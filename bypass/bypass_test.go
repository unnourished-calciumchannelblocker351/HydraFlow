package bypass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- Fragment tests ----

func TestIsTLSClientHello(t *testing.T) {
	// Valid ClientHello.
	hello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x2f,
		0x01, 0x00, 0x00, 0x2b,
		0x03, 0x03,
	}
	if !isTLSClientHello(hello) {
		t.Error("expected isTLSClientHello to return true for valid ClientHello")
	}

	// Not a handshake record.
	notHello := []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x00}
	if isTLSClientHello(notHello) {
		t.Error("expected isTLSClientHello to return false for non-handshake")
	}

	// Too short.
	short := []byte{0x16, 0x03}
	if isTLSClientHello(short) {
		t.Error("expected isTLSClientHello to return false for short data")
	}

	// Handshake but not ClientHello (type 0x02 = ServerHello).
	serverHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02}
	if isTLSClientHello(serverHello) {
		t.Error("expected isTLSClientHello to return false for ServerHello")
	}
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		input  string
		lo, hi int
		ok     bool
	}{
		{"1-5", 1, 5, true},
		{"100-200", 100, 200, true},
		{"5-1", 1, 5, true}, // reversed
		{"10", 10, 10, true},
		{"", 0, 0, false},
		{"abc", 0, 0, false},
		{"1-abc", 0, 0, false},
	}

	for _, tt := range tests {
		lo, hi, ok := parseRange(tt.input)
		if ok != tt.ok || lo != tt.lo || hi != tt.hi {
			t.Errorf("parseRange(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tt.input, lo, hi, ok, tt.lo, tt.hi, tt.ok)
		}
	}
}

func TestFragmentWriteSplitsData(t *testing.T) {
	// Create a pipe to capture what FragmentConn writes.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ft := NewFragmentTechnique("2-2", "0-0", "1") // 2 bytes per fragment, count mode, 1 packet

	fc := &FragmentConn{
		Conn: clientConn,
		ft:   ft,
	}

	// Write test data in a goroutine.
	testData := []byte("ABCDEF")
	go func() {
		_, _ = fc.Write(testData)
	}()

	// Read all the fragments from the server side.
	buf := make([]byte, len(testData))
	n, err := io.ReadFull(serverConn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), n)
	}
	if !bytes.Equal(buf, testData) {
		t.Errorf("data mismatch: got %q, want %q", buf, testData)
	}
}

func TestFindSNIOffset(t *testing.T) {
	// Build a ClientHello with SNI extension.
	hello := buildClientHelloWithSNI("example.com")
	offset := FindSNIOffset(hello)
	if offset <= 0 {
		t.Errorf("expected positive SNI offset, got %d", offset)
	}
	if offset >= len(hello) {
		t.Errorf("SNI offset %d out of bounds (len=%d)", offset, len(hello))
	}
}

func TestFragmentAtSNI(t *testing.T) {
	hello := buildClientHelloWithSNI("test.example.com")
	part1, part2 := FragmentAtSNI(hello)

	// Reconstruct should give original.
	reconstructed := append(part1, part2...)
	if !bytes.Equal(reconstructed, hello) {
		t.Error("FragmentAtSNI: reconstructed data does not match original")
	}

	if len(part1) == 0 || len(part2) == 0 {
		t.Error("FragmentAtSNI: expected two non-empty parts")
	}
}

func TestNewFragmentTechnique(t *testing.T) {
	ft := NewFragmentTechnique("10-50", "1-10", "tlshello")
	if ft.Name() != "fragment" {
		t.Errorf("expected name 'fragment', got %q", ft.Name())
	}
	if ft.sizeMin != 10 || ft.sizeMax != 50 {
		t.Errorf("size range: got %d-%d, want 10-50", ft.sizeMin, ft.sizeMax)
	}
	if ft.mode != "tlshello" {
		t.Errorf("mode: got %q, want 'tlshello'", ft.mode)
	}
}

// ---- Padding tests ----

func TestAddPaddingAndStrip(t *testing.T) {
	original := []byte("hello world")
	padded := AddPadding(original, 100)

	if len(padded) != 100 {
		t.Errorf("expected padded length 100, got %d", len(padded))
	}

	stripped := StripPadding(padded)
	if !bytes.Equal(stripped, original) {
		t.Errorf("stripped data mismatch: got %q, want %q", stripped, original)
	}
}

func TestStripPaddingFakePacket(t *testing.T) {
	// A fake packet has length prefix 0.
	fake := make([]byte, 50)
	fake[0] = 0
	fake[1] = 0

	result := StripPadding(fake)
	if result != nil {
		t.Errorf("expected nil for fake packet, got %v", result)
	}
}

func TestPaddingConnWriteRead(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	pc := &PaddingConn{
		Conn:   clientConn,
		padMin: 50,
		padMax: 100,
	}

	testData := []byte("test message")

	// Write padded data.
	writeDone := make(chan error, 1)
	go func() {
		_, err := pc.sendPadded(testData)
		writeDone <- err
	}()

	// Read the padded packet from the server side and verify it
	// contains the length prefix and data.
	buf := make([]byte, 200)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if writeErr := <-writeDone; writeErr != nil {
		t.Fatalf("write error: %v", writeErr)
	}

	// Packet should be at least padMin.
	if n < 50 {
		t.Errorf("padded packet too small: %d bytes, expected >= 50", n)
	}

	// Strip and verify.
	stripped := StripPadding(buf[:n])
	if !bytes.Equal(stripped, testData) {
		t.Errorf("stripped data mismatch: got %q, want %q", stripped, testData)
	}
}

func TestBurstWriter(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	bw := NewBurstWriter(clientConn, 5, 10, 0, 0)

	testData := []byte("burst test data with enough bytes")

	go func() {
		_, _ = bw.Write(testData)
	}()

	buf := make([]byte, len(testData))
	n, err := io.ReadFull(serverConn, buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Error("burst writer: data mismatch")
	}
}

// ---- SNI tests ----

func TestUnblockableSNIs(t *testing.T) {
	// Verify that each country has at least one domain.
	for country, domains := range UnblockableSNIs {
		if len(domains) == 0 {
			t.Errorf("country %q has no unblockable SNI domains", country)
		}
	}

	// Russia should have gosuslugi.ru.
	found := false
	for _, d := range UnblockableSNIs["russia"] {
		if d == "gosuslugi.ru" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Russia unblockable SNIs should include gosuslugi.ru")
	}
}

func TestSNITechniqueRotation(t *testing.T) {
	st := NewSNITechnique(SNIConfig{
		Domain:    "first.com",
		Fallbacks: []string{"second.com", "third.com"},
		Rotation:  3, // rotate every 3 connections
	})

	// Pool is: [first.com, second.com, third.com]
	// count increments before division: idx = (count / rotation) % len(pool)
	// calls 1,2,3 => count/3 = 0 => pool[0] = first.com
	// calls 4,5,6 => count/3 = 1 => pool[1] = second.com
	// calls 7,8,9 => count/3 = 2 => pool[2] = third.com

	for i := 0; i < 3; i++ {
		sni := st.CurrentSNI()
		if sni != "first.com" {
			t.Errorf("call %d: expected first.com, got %s", i+1, sni)
		}
	}

	for i := 0; i < 3; i++ {
		sni := st.CurrentSNI()
		if sni != "second.com" {
			t.Errorf("call %d: expected second.com, got %s", i+4, sni)
		}
	}

	for i := 0; i < 3; i++ {
		sni := st.CurrentSNI()
		if sni != "third.com" {
			t.Errorf("call %d: expected third.com, got %s", i+7, sni)
		}
	}
}

func TestSNITechniqueNoRotation(t *testing.T) {
	st := NewSNITechnique(SNIConfig{
		Domain: "only.com",
	})

	for i := 0; i < 10; i++ {
		sni := st.CurrentSNI()
		if sni != "only.com" {
			t.Errorf("expected only.com, got %s", sni)
		}
	}
}

func TestBuildSNIPool(t *testing.T) {
	pool := BuildSNIPool("primary.com", []string{"fb1.com", "fb2.com"}, "russia")
	if len(pool) != 3 {
		t.Errorf("expected 3 domains, got %d", len(pool))
	}
	if pool[0] != "primary.com" {
		t.Errorf("first domain should be primary.com, got %s", pool[0])
	}
}

func TestBuildSNIPoolEmpty(t *testing.T) {
	pool := BuildSNIPool("", nil, "russia")
	if len(pool) == 0 {
		t.Error("expected non-empty pool from unblockable list")
	}
}

func TestBuildClientHelloWithSNI(t *testing.T) {
	hello := buildClientHelloWithSNI("test.example.com")

	// Should start with TLS record header.
	if len(hello) < 6 {
		t.Fatal("hello too short")
	}
	if hello[0] != 0x16 {
		t.Errorf("expected TLS handshake type 0x16, got 0x%02x", hello[0])
	}
	if hello[5] != 0x01 {
		t.Errorf("expected ClientHello type 0x01, got 0x%02x", hello[5])
	}

	// Should contain the SNI string.
	if !bytes.Contains(hello, []byte("test.example.com")) {
		t.Error("ClientHello should contain the SNI domain")
	}
}

func TestDomainFrontingInfo(t *testing.T) {
	sni, host := DomainFrontingInfo(SNIConfig{
		Domain:          "cdn.cloudflare.com",
		DomainFronting:  true,
		DomainFrontHost: "real-backend.example.com",
	})
	if sni != "cdn.cloudflare.com" {
		t.Errorf("expected CDN SNI, got %s", sni)
	}
	if host != "real-backend.example.com" {
		t.Errorf("expected real host, got %s", host)
	}
}

// ---- Chain tests ----

func TestChainTechniqueAvailable(t *testing.T) {
	ct := NewChainTechnique(ChainConfig{
		Servers: []ChainNode{
			{Host: "1.2.3.4", Port: 443},
			{Host: "5.6.7.8", Port: 443},
		},
	}, nil)

	if !ct.Available() {
		t.Error("chain should be available when servers are configured")
	}

	empty := NewChainTechnique(ChainConfig{}, nil)
	if empty.Available() {
		t.Error("chain should not be available with no servers")
	}
}

func TestParseUUIDSimple(t *testing.T) {
	uuid := parseUUIDSimple("550e8400-e29b-41d4-a716-446655440000")
	expected := [16]byte{0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00}
	if uuid != expected {
		t.Errorf("UUID parse mismatch: got %x, want %x", uuid, expected)
	}
}

func TestBuildChainTunnelRequest(t *testing.T) {
	req := buildChainTunnelRequest("example.com:443", "550e8400-e29b-41d4-a716-446655440000")
	if len(req) == 0 {
		t.Error("tunnel request should not be empty")
	}
	// First byte should be VLESS version 0.
	if req[0] != 0x00 {
		t.Errorf("expected VLESS version 0, got 0x%02x", req[0])
	}
	// Should contain the hostname.
	if !bytes.Contains(req, []byte("example.com")) {
		t.Error("tunnel request should contain hostname")
	}
}

func TestChainDialerFallback(t *testing.T) {
	ct := NewChainTechnique(ChainConfig{
		Servers: []ChainNode{
			{Host: "127.0.0.1", Port: 1}, // will fail
		},
		Fallback: []ChainNode{
			{Host: "127.0.0.1", Port: 2}, // will also fail
		},
	}, nil)

	// Both should fail, but fallback should be attempted.
	baseDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}
	}

	dialFn := ct.WrapDial(baseDial)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dialFn(ctx, "tcp", "target:443")
	if err == nil {
		t.Error("expected error when both chains fail")
	}
}

// ---- DNS tests ----

func TestBuildDNSQuery(t *testing.T) {
	query := buildDNSQuery("example.com", 1)

	// Minimum DNS query is 12 (header) + domain + 4 (qtype+qclass).
	if len(query) < 20 {
		t.Errorf("DNS query too short: %d bytes", len(query))
	}

	// Should contain the domain labels.
	if !bytes.Contains(query, []byte("example")) {
		t.Error("DNS query should contain domain label")
	}
}

func TestParseDNSResponse(t *testing.T) {
	// Construct a minimal DNS response with one A record.
	var resp []byte

	// Header.
	resp = append(resp, 0x00, 0x01) // Transaction ID
	resp = append(resp, 0x81, 0x80) // Flags: response, no error
	resp = append(resp, 0x00, 0x01) // QDCOUNT: 1
	resp = append(resp, 0x00, 0x01) // ANCOUNT: 1
	resp = append(resp, 0x00, 0x00) // NSCOUNT: 0
	resp = append(resp, 0x00, 0x00) // ARCOUNT: 0

	// Question: example.com A IN.
	resp = append(resp, 0x07)
	resp = append(resp, []byte("example")...)
	resp = append(resp, 0x03)
	resp = append(resp, []byte("com")...)
	resp = append(resp, 0x00)       // root
	resp = append(resp, 0x00, 0x01) // QTYPE: A
	resp = append(resp, 0x00, 0x01) // QCLASS: IN

	// Answer: example.com A 93.184.216.34
	resp = append(resp, 0xC0, 0x0C)             // compressed name pointer
	resp = append(resp, 0x00, 0x01)             // TYPE: A
	resp = append(resp, 0x00, 0x01)             // CLASS: IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x00) // TTL: 256
	resp = append(resp, 0x00, 0x04)             // RDLENGTH: 4
	resp = append(resp, 93, 184, 216, 34)       // RDATA: 93.184.216.34

	addrs, err := parseDNSResponse(resp)
	if err != nil {
		t.Fatalf("parseDNSResponse error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	if addrs[0] != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %s", addrs[0])
	}
}

func TestIsRussianDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"gosuslugi.ru", true},
		{"nalog.ru", true},
		{"subdomain.yandex.ru", true},
		{"vk.com", true},
		{"google.com", false},
		{"example.org", false},
		{"mail.ru", true},
		{"test.moscow", true},
	}

	for _, tt := range tests {
		got := isRussianDomain(tt.domain)
		if got != tt.want {
			t.Errorf("isRussianDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestDNSCacheSetGet(t *testing.T) {
	cache := newDNSCache(60)

	cache.set("example.com", []string{"1.2.3.4", "5.6.7.8"})
	addrs := cache.get("example.com")
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	if addrs[0] != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", addrs[0])
	}

	// Non-existent key.
	addrs = cache.get("nonexistent.com")
	if addrs != nil {
		t.Errorf("expected nil for non-existent key, got %v", addrs)
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	cache := newDNSCache(1) // 1 second TTL
	cache.set("example.com", []string{"1.2.3.4"})

	// Should be present immediately.
	addrs := cache.get("example.com")
	if len(addrs) != 1 {
		t.Fatal("expected cached address")
	}

	// Wait for expiry.
	time.Sleep(1100 * time.Millisecond)
	addrs = cache.get("example.com")
	if addrs != nil {
		t.Error("expected expired cache entry to return nil")
	}
}

func TestDNSCacheFlush(t *testing.T) {
	cache := newDNSCache(300)
	cache.set("a.com", []string{"1.1.1.1"})
	cache.set("b.com", []string{"2.2.2.2"})

	cache.Flush()

	if cache.get("a.com") != nil || cache.get("b.com") != nil {
		t.Error("expected all entries flushed")
	}
}

// ---- Probe tests ----

func TestProbeSummaryNil(t *testing.T) {
	summary := ProbeSummary(nil)
	if summary == "" {
		t.Error("expected non-empty summary for nil profile")
	}
}

func TestProbeSummary(t *testing.T) {
	profile := &NetworkProfile{
		FragmentEffective:   true,
		OptimalFragmentSize: 5,
		QUICAvailable:       false,
		TLS13Available:      true,
		CDNReachable:        true,
		ResetOnBlock:        true,
		BlockedSNIs:         []string{"blocked.com"},
		WorkingSNIs:         []string{"google.com"},
		ProbeTimestamp:      time.Now(),
		ConfidenceScore:     0.85,
	}

	summary := ProbeSummary(profile)
	if !strings.Contains(summary, "Fragment Bypass: true") {
		t.Error("summary should mention fragment bypass")
	}
	if !strings.Contains(summary, "QUIC/UDP: false") {
		t.Error("summary should mention QUIC status")
	}
}

// ---- Config generation tests ----

func TestXrayClientConfigValid(t *testing.T) {
	cfg := BypassConfig{
		FragmentEnabled:  true,
		FragmentSize:     "100-200",
		FragmentInterval: "10-20",
		FragmentPackets:  "tlshello",
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
	}

	data, err := XrayClientConfig(cfg, "1.2.3.4", 443,
		"test-uuid", "ya.ru", "test-pubkey", "ab")
	if err != nil {
		t.Fatalf("XrayClientConfig error: %v", err)
	}

	// Validate it's valid JSON.
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check that fragment settings are present.
	s := string(data)
	if !strings.Contains(s, "fragment") {
		t.Error("xray config should contain fragment settings")
	}
	if !strings.Contains(s, "tlshello") {
		t.Error("xray config should contain tlshello packet mode")
	}
	if !strings.Contains(s, "100-200") {
		t.Error("xray config should contain fragment length range")
	}
}

func TestXrayWSCDNConfigValid(t *testing.T) {
	cfg := BypassConfig{
		FragmentEnabled:  true,
		FragmentSize:     "50-100",
		FragmentInterval: "5-10",
		FragmentPackets:  "tlshello",
	}

	data, err := XrayWSCDNConfig(cfg, "cdn.example.com", 443,
		"test-uuid", "/ws-path", "ws.example.com")
	if err != nil {
		t.Fatalf("XrayWSCDNConfig error: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "ws") {
		t.Error("config should contain websocket settings")
	}
	if !strings.Contains(s, "/ws-path") {
		t.Error("config should contain the websocket path")
	}
}

func TestHiddifyConfigValid(t *testing.T) {
	cfg := BypassConfig{
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-200",
	}

	data, err := HiddifyConfig(cfg, "1.2.3.4", 443,
		"test-uuid", "ya.ru", "pubkey", "sid")
	if err != nil {
		t.Fatalf("HiddifyConfig error: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check fragment and padding sections.
	if config["fragment"] == nil {
		t.Error("hiddify config should have fragment section")
	}
	if config["padding"] == nil {
		t.Error("hiddify config should have padding section")
	}
}

func TestSingBoxConfigValid(t *testing.T) {
	cfg := BypassConfig{
		DOHEnabled: true,
		DOHServer:  "https://dns.google/dns-query",
	}

	data, err := SingBoxConfig(cfg, "1.2.3.4", 443,
		"test-uuid", "ya.ru", "pubkey", "sid")
	if err != nil {
		t.Fatalf("SingBoxConfig error: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should have inbounds and outbounds.
	if config["inbounds"] == nil {
		t.Error("sing-box config should have inbounds")
	}
	if config["outbounds"] == nil {
		t.Error("sing-box config should have outbounds")
	}
}

func TestClashMetaConfigValid(t *testing.T) {
	cfg := BypassConfig{}

	data, err := ClashMetaConfig(cfg, "1.2.3.4", 443,
		"test-uuid", "ya.ru", "pubkey", "sid")
	if err != nil {
		t.Fatalf("ClashMetaConfig error: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if config["proxies"] == nil {
		t.Error("clash config should have proxies")
	}
	if config["rules"] == nil {
		t.Error("clash config should have rules")
	}
}

func TestGenerateAllClientConfigs(t *testing.T) {
	cfg := BypassConfig{
		FragmentEnabled:  true,
		FragmentSize:     "100-200",
		FragmentInterval: "10-20",
		FragmentPackets:  "tlshello",
	}

	set, err := GenerateAllClientConfigs(cfg, "1.2.3.4", 443,
		"uuid", "ya.ru", "pbk", "sid")
	if err != nil {
		t.Fatalf("GenerateAllClientConfigs error: %v", err)
	}

	if len(set.Xray) == 0 {
		t.Error("xray config empty")
	}
	if len(set.Hiddify) == 0 {
		t.Error("hiddify config empty")
	}
	if len(set.SingBox) == 0 {
		t.Error("singbox config empty")
	}
	if len(set.Clash) == 0 {
		t.Error("clash config empty")
	}
	if set.V2RayLink == "" {
		t.Error("v2ray link empty")
	}
	if !strings.HasPrefix(set.V2RayLink, "vless://") {
		t.Error("v2ray link should start with vless://")
	}
}

func TestGenerateOptimalConfig(t *testing.T) {
	profile := &NetworkProfile{
		FragmentEffective:   true,
		OptimalFragmentSize: 5,
		QUICAvailable:       true,
		TLS13Available:      true,
		CDNReachable:        true,
		WorkingSNIs:         []string{"ya.ru", "sberbank.ru"},
		EstimatedDPILatency: 200 * time.Millisecond,
	}

	cfg := GenerateOptimalConfig(profile, DefaultBypassConfig())

	if !cfg.FragmentEnabled {
		t.Error("should enable fragment when effective")
	}
	if cfg.SNIDomain != "ya.ru" {
		t.Errorf("expected SNI ya.ru, got %s", cfg.SNIDomain)
	}
	if !cfg.PaddingEnabled {
		t.Error("should enable padding when DPI latency is high")
	}
	if !cfg.DOHEnabled {
		t.Error("should enable DoH")
	}
}

// ---- Desync tests ----

func TestDesyncTechniqueName(t *testing.T) {
	dt := NewDesyncTechnique(DesyncConfig{FakeTTL: 3})
	if dt.Name() != "desync" {
		t.Errorf("expected name 'desync', got %q", dt.Name())
	}
}

func TestBuildFakeClientHello(t *testing.T) {
	fake := buildFakeClientHello(100)
	if len(fake) != 100 {
		t.Errorf("expected 100 bytes, got %d", len(fake))
	}
	// Should look like a TLS record.
	if fake[0] != tlsRecordTypeHandshake {
		t.Errorf("expected TLS handshake type, got 0x%02x", fake[0])
	}
}

func TestIsRSTError(t *testing.T) {
	tests := []struct {
		errStr string
		want   bool
	}{
		{"connection reset by peer", true},
		{"read: connection reset", true},
		{"forcibly closed", true},
		{"timeout", false},
		{"", false},
	}

	for _, tt := range tests {
		var err error
		if tt.errStr != "" {
			err = &net.OpError{Op: "read", Err: fmt.Errorf(tt.errStr)}
		}
		got := isRSTError(err)
		if got != tt.want {
			t.Errorf("isRSTError(%q) = %v, want %v", tt.errStr, got, tt.want)
		}
	}
}

// ---- Preset tests ----

func TestPresetsExist(t *testing.T) {
	required := []string{
		"russia-megafon", "russia-mts", "russia-beeline",
		"china-telecom", "iran-mci", "default",
	}

	for _, name := range required {
		if _, ok := Presets[name]; !ok {
			t.Errorf("missing preset: %s", name)
		}
	}
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	if len(names) == 0 {
		t.Error("expected at least one preset name")
	}

	// Should be sorted.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("preset names not sorted: %s < %s", names[i], names[i-1])
		}
	}
}

func TestGetPresetDefault(t *testing.T) {
	cfg := GetPreset("nonexistent")
	if len(cfg.Protocols) == 0 {
		t.Error("default preset should have protocols")
	}
}

func TestPresetForISP(t *testing.T) {
	cfg, name := PresetForISP("MegaFon")
	if name != "russia-megafon" {
		t.Errorf("expected russia-megafon, got %s", name)
	}
	if !cfg.FragmentEnabled {
		t.Error("megafon preset should have fragment enabled")
	}
}

// ---- Engine tests ----

func TestBypassEngineCreate(t *testing.T) {
	cfg := DefaultBypassConfig()
	cfg.FragmentEnabled = true
	cfg.PaddingEnabled = true
	cfg.SNIDomain = "ya.ru"

	engine, err := NewBypassEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewBypassEngine error: %v", err)
	}

	techniques := engine.Techniques()
	if len(techniques) == 0 {
		t.Error("expected at least one technique")
	}

	// Should have fragment, padding, and sni techniques.
	names := map[string]bool{}
	for _, tech := range techniques {
		names[tech.Name()] = true
	}
	if !names["fragment"] {
		t.Error("expected fragment technique")
	}
	if !names["padding"] {
		t.Error("expected padding technique")
	}
	if !names["sni"] {
		t.Error("expected sni technique")
	}
}

func TestBypassEnginePreset(t *testing.T) {
	cfg := BypassConfig{
		Preset: "russia-megafon",
	}

	engine, err := NewBypassEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewBypassEngine error: %v", err)
	}

	ecfg := engine.Config()
	if !ecfg.FragmentEnabled {
		t.Error("megafon preset should enable fragment")
	}
	if ecfg.SNIDomain != "ya.ru" {
		t.Errorf("expected SNI ya.ru, got %s", ecfg.SNIDomain)
	}
}

func TestBypassEngineCurrentSNI(t *testing.T) {
	cfg := BypassConfig{
		SNIDomain:    "first.com",
		SNIFallbacks: []string{"second.com"},
		SNIRotation:  3,
	}

	engine, err := NewBypassEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Engine's CurrentSNI: idx = (counter / rotation) % len(pool), then counter++
	// pool = [first.com, second.com], rotation = 3
	// Calls 1-3: counter 0,1,2 => 0/3=0, 1/3=0, 2/3=0 => first.com
	// Calls 4-6: counter 3,4,5 => 3/3=1, 4/3=1, 5/3=1 => second.com
	for i := 0; i < 3; i++ {
		sni := engine.CurrentSNI()
		if sni != "first.com" {
			t.Errorf("call %d: expected first.com, got %s", i+1, sni)
		}
	}
	for i := 0; i < 3; i++ {
		sni := engine.CurrentSNI()
		if sni != "second.com" {
			t.Errorf("call %d: expected second.com, got %s", i+4, sni)
		}
	}
}

func TestMergeConfigs(t *testing.T) {
	preset := BypassConfig{
		FragmentEnabled: true,
		FragmentSize:    "1-3",
		SNIDomain:       "preset-sni.com",
		DOHEnabled:      true,
		DOHServer:       "https://preset-dns.com/dns-query",
	}

	user := BypassConfig{
		FragmentSize:   "10-20", // override
		SNIDomain:      "",      // keep preset
		PaddingEnabled: true,    // new addition
		Preset:         "test",
	}

	merged := mergeConfigs(preset, user)

	if !merged.FragmentEnabled {
		t.Error("should keep preset FragmentEnabled")
	}
	if merged.FragmentSize != "10-20" {
		t.Errorf("should override FragmentSize: got %s", merged.FragmentSize)
	}
	if merged.SNIDomain != "preset-sni.com" {
		t.Errorf("should keep preset SNIDomain: got %s", merged.SNIDomain)
	}
	if !merged.PaddingEnabled {
		t.Error("should add user PaddingEnabled")
	}
	if !merged.DOHEnabled {
		t.Error("should keep preset DOHEnabled")
	}
}

// ---- Concurrency test ----

func TestBypassEngineConcurrentSNI(t *testing.T) {
	cfg := BypassConfig{
		SNIDomain:    "a.com",
		SNIFallbacks: []string{"b.com", "c.com"},
		SNIRotation:  1,
	}

	engine, err := NewBypassEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sni := engine.CurrentSNI()
			if sni == "" {
				t.Error("got empty SNI")
			}
		}()
	}
	wg.Wait()
}
