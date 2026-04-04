package bypass

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// generateWireGuardKeyPair
// ---------------------------------------------------------------------------

func TestGenerateWireGuardKeyPair(t *testing.T) {
	t.Parallel()

	priv, pub, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generateWireGuardKeyPair() error: %v", err)
	}

	// Keys should be valid base64.
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("public key is not valid base64: %v", err)
	}

	// Keys should be 32 bytes (Curve25519).
	if len(privBytes) != 32 {
		t.Errorf("private key length = %d, want 32", len(privBytes))
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubBytes))
	}

	// Private key should be clamped.
	if privBytes[0]&7 != 0 {
		t.Error("private key not clamped: low 3 bits of first byte should be 0")
	}
	if privBytes[31]&128 != 0 {
		t.Error("private key not clamped: high bit of last byte should be 0")
	}
	if privBytes[31]&64 == 0 {
		t.Error("private key not clamped: bit 6 of last byte should be 1")
	}

	// Two calls should produce different keys.
	priv2, pub2, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if priv == priv2 {
		t.Error("two calls produced the same private key")
	}
	if pub == pub2 {
		t.Error("two calls produced the same public key")
	}
}

// ---------------------------------------------------------------------------
// generateClientID
// ---------------------------------------------------------------------------

func TestGenerateClientID(t *testing.T) {
	t.Parallel()

	id, b64, err := generateClientID()
	if err != nil {
		t.Fatalf("generateClientID() error: %v", err)
	}

	// Decoded base64 should match the raw bytes.
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("client ID is not valid base64: %v", err)
	}
	if len(decoded) != 3 {
		t.Errorf("decoded client ID length = %d, want 3", len(decoded))
	}
	for i := 0; i < 3; i++ {
		if decoded[i] != id[i] {
			t.Errorf("decoded[%d] = %d, want %d", i, decoded[i], id[i])
		}
	}
}

// ---------------------------------------------------------------------------
// RegisterWARP with mock HTTP
// ---------------------------------------------------------------------------

func TestRegisterWARP_Success(t *testing.T) {
	t.Parallel()

	// Mock WARP API response.
	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		if url != warpAPIBase {
			t.Errorf("unexpected URL: %s", url)
		}

		// Verify headers.
		if headers["Content-Type"] != "application/json" {
			t.Error("missing Content-Type header")
		}

		// Parse request to verify it has a key.
		var req warpRegRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("request body is not valid JSON: %v", err)
		}
		if req.Key == "" {
			t.Error("request missing public key")
		}

		resp := warpRegResponse{
			ID:    "device-123",
			Token: "token-abc",
		}
		resp.Account.ID = "account-456"
		resp.Config.Peers = []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		}{
			{
				PublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
			},
		}
		resp.Config.Peers[0].Endpoint.V4 = "162.159.193.1:2408"
		resp.Config.Peers[0].Endpoint.V6 = "[2606:4700:d0::1]:2408"
		resp.Config.Interface.Addresses.V4 = "172.16.0.2/32"
		resp.Config.Interface.Addresses.V6 = "fd01:db8:1111::2/128"
		resp.Config.ClientID = "AQID"

		return json.Marshal(resp)
	}

	cfg, err := RegisterWARP(mockPost)
	if err != nil {
		t.Fatalf("RegisterWARP() error: %v", err)
	}

	if !cfg.Enabled {
		t.Error("config should be enabled")
	}
	if cfg.DeviceID != "device-123" {
		t.Errorf("DeviceID = %q, want %q", cfg.DeviceID, "device-123")
	}
	if cfg.AccessToken != "token-abc" {
		t.Errorf("AccessToken = %q, want %q", cfg.AccessToken, "token-abc")
	}
	if cfg.PublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("PublicKey = %q", cfg.PublicKey)
	}
	if cfg.IPv4 != "172.16.0.2/32" {
		t.Errorf("IPv4 = %q, want %q", cfg.IPv4, "172.16.0.2/32")
	}
	if cfg.IPv6 != "fd01:db8:1111::2/128" {
		t.Errorf("IPv6 = %q", cfg.IPv6)
	}
	if cfg.Endpoint != "162.159.193.1:2408" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.PrivateKey == "" {
		t.Error("PrivateKey should not be empty")
	}
	if cfg.RegisteredAt.IsZero() {
		t.Error("RegisteredAt should not be zero")
	}
}

func TestRegisterWARP_EmptyDeviceID(t *testing.T) {
	t.Parallel()

	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		return json.Marshal(warpRegResponse{})
	}

	_, err := RegisterWARP(mockPost)
	if err == nil {
		t.Error("expected error for empty device ID")
	}
}

func TestRegisterWARP_NoPeers(t *testing.T) {
	t.Parallel()

	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		resp := warpRegResponse{ID: "device-1", Token: "tok"}
		resp.Config.Peers = nil
		return json.Marshal(resp)
	}

	_, err := RegisterWARP(mockPost)
	if err == nil {
		t.Error("expected error for no peers")
	}
}

func TestRegisterWARP_HTTPError(t *testing.T) {
	t.Parallel()

	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		return nil, fmt.Errorf("connection refused")
	}

	_, err := RegisterWARP(mockPost)
	if err == nil {
		t.Error("expected error for HTTP failure")
	}
}

func TestRegisterWARP_InvalidJSON(t *testing.T) {
	t.Parallel()

	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		return []byte("not json"), nil
	}

	_, err := RegisterWARP(mockPost)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestRegisterWARP_DefaultEndpoint(t *testing.T) {
	t.Parallel()

	mockPost := func(url string, headers map[string]string, body []byte) ([]byte, error) {
		resp := warpRegResponse{ID: "dev-1", Token: "tok"}
		resp.Config.Peers = []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		}{
			{PublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="},
		}
		// Endpoint fields left empty.
		resp.Config.Interface.Addresses.V4 = "172.16.0.3/32"
		resp.Config.Interface.Addresses.V6 = "fd01::3/128"
		return json.Marshal(resp)
	}

	cfg, err := RegisterWARP(mockPost)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("Endpoint = %q, want default", cfg.Endpoint)
	}
}

// ---------------------------------------------------------------------------
// GenerateWARPOutbound
// ---------------------------------------------------------------------------

func TestGenerateWARPOutbound_Success(t *testing.T) {
	t.Parallel()

	cfg := &WARPConfig{
		Enabled:    true,
		PrivateKey: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		IPv4:       "172.16.0.2/32",
		IPv6:       "fd01:db8:1111::2/128",
		Endpoint:   "162.159.193.1:2408",
		Reserved:   [3]byte{1, 2, 3},
	}

	outbound, err := GenerateWARPOutbound(cfg)
	if err != nil {
		t.Fatalf("GenerateWARPOutbound() error: %v", err)
	}

	if outbound.Tag != "warp-out" {
		t.Errorf("Tag = %q, want %q", outbound.Tag, "warp-out")
	}
	if outbound.Protocol != "wireguard" {
		t.Errorf("Protocol = %q, want %q", outbound.Protocol, "wireguard")
	}

	// Verify settings.
	if outbound.Settings["secretKey"] != cfg.PrivateKey {
		t.Error("secretKey mismatch")
	}

	addresses, ok := outbound.Settings["address"].([]string)
	if !ok || len(addresses) != 2 {
		t.Fatalf("address should be []string with 2 elements, got %v", outbound.Settings["address"])
	}
	if addresses[0] != "172.16.0.2/32" {
		t.Errorf("address[0] = %q", addresses[0])
	}

	peers, ok := outbound.Settings["peers"].([]map[string]interface{})
	if !ok || len(peers) != 1 {
		t.Fatalf("peers should have 1 entry, got %v", outbound.Settings["peers"])
	}
	if peers[0]["publicKey"] != cfg.PublicKey {
		t.Error("peer publicKey mismatch")
	}
	if peers[0]["endpoint"] != "162.159.193.1:2408" {
		t.Errorf("peer endpoint = %v", peers[0]["endpoint"])
	}

	reserved, ok := outbound.Settings["reserved"].([]int)
	if !ok || len(reserved) != 3 {
		t.Fatalf("reserved should be []int with 3 elements")
	}
	if reserved[0] != 1 || reserved[1] != 2 || reserved[2] != 3 {
		t.Errorf("reserved = %v, want [1 2 3]", reserved)
	}

	if outbound.Settings["mtu"] != 1280 {
		t.Errorf("mtu = %v, want 1280", outbound.Settings["mtu"])
	}

	// Verify it serializes to valid JSON.
	data, err := json.Marshal(outbound)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	if len(data) == 0 {
		t.Error("serialized JSON should not be empty")
	}
}

func TestGenerateWARPOutbound_NilConfig(t *testing.T) {
	t.Parallel()

	_, err := GenerateWARPOutbound(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestGenerateWARPOutbound_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &WARPConfig{Enabled: false}
	_, err := GenerateWARPOutbound(cfg)
	if err == nil {
		t.Error("expected error for disabled config")
	}
}

func TestGenerateWARPOutbound_MissingKeys(t *testing.T) {
	t.Parallel()

	cfg := &WARPConfig{Enabled: true, PrivateKey: "", PublicKey: ""}
	_, err := GenerateWARPOutbound(cfg)
	if err == nil {
		t.Error("expected error for missing keys")
	}
}

func TestGenerateWARPOutbound_DefaultEndpoint(t *testing.T) {
	t.Parallel()

	cfg := &WARPConfig{
		Enabled:    true,
		PrivateKey: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		IPv4:       "172.16.0.2/32",
		Endpoint:   "", // empty — should use default
	}

	outbound, err := GenerateWARPOutbound(cfg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	peers := outbound.Settings["peers"].([]map[string]interface{})
	if peers[0]["endpoint"] != "engage.cloudflareclient.com:2408" {
		t.Errorf("endpoint = %v, want default", peers[0]["endpoint"])
	}
}

// ---------------------------------------------------------------------------
// GenerateWARPRoutingRules
// ---------------------------------------------------------------------------

func TestGenerateWARPRoutingRules(t *testing.T) {
	t.Parallel()

	rule := GenerateWARPRoutingRules()

	if rule["type"] != "field" {
		t.Errorf("type = %v, want 'field'", rule["type"])
	}
	if rule["outboundTag"] != "warp-out" {
		t.Errorf("outboundTag = %v, want 'warp-out'", rule["outboundTag"])
	}

	domains, ok := rule["domain"].([]string)
	if !ok {
		t.Fatal("domain should be []string")
	}
	if len(domains) == 0 {
		t.Error("domain list should not be empty")
	}

	// Check some key domains are present.
	domainSet := make(map[string]bool)
	for _, d := range domains {
		domainSet[d] = true
	}

	expected := []string{
		"domain:netflix.com",
		"domain:openai.com",
		"domain:spotify.com",
		"domain:anthropic.com",
		"domain:claude.ai",
	}
	for _, d := range expected {
		if !domainSet[d] {
			t.Errorf("missing expected domain %q in routing rules", d)
		}
	}
}

// ---------------------------------------------------------------------------
// StreamingDomains
// ---------------------------------------------------------------------------

func TestStreamingDomains(t *testing.T) {
	t.Parallel()

	if len(StreamingDomains) == 0 {
		t.Error("StreamingDomains should not be empty")
	}

	// All entries should start with "domain:".
	for _, d := range StreamingDomains {
		if len(d) < 8 || d[:7] != "domain:" {
			t.Errorf("domain %q does not start with 'domain:'", d)
		}
	}
}

// ---------------------------------------------------------------------------
// GenerateFullXrayWARPConfig
// ---------------------------------------------------------------------------

func TestGenerateFullXrayWARPConfig_Success(t *testing.T) {
	t.Parallel()

	cfg := &WARPConfig{
		Enabled:    true,
		PrivateKey: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		IPv4:       "172.16.0.2/32",
		IPv6:       "fd01::2/128",
		Endpoint:   "162.159.193.1:2408",
		Reserved:   [3]byte{10, 20, 30},
	}

	outbound, rule, err := GenerateFullXrayWARPConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateFullXrayWARPConfig() error: %v", err)
	}

	if outbound == nil {
		t.Fatal("outbound should not be nil")
	}
	if outbound.Tag != "warp-out" {
		t.Errorf("outbound tag = %q", outbound.Tag)
	}

	if rule == nil {
		t.Fatal("rule should not be nil")
	}
	if rule["outboundTag"] != "warp-out" {
		t.Errorf("rule outboundTag = %v", rule["outboundTag"])
	}
}

func TestGenerateFullXrayWARPConfig_Error(t *testing.T) {
	t.Parallel()

	_, _, err := GenerateFullXrayWARPConfig(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}
