package xray

import (
	"encoding/json"
	"testing"
)

func TestNewConfigBuilder_Defaults(t *testing.T) {
	cb := NewConfigBuilder()
	if cb.LogLevel != "warning" {
		t.Fatalf("expected log level 'warning', got %q", cb.LogLevel)
	}
	if cb.APIPort != 10085 {
		t.Fatalf("expected API port 10085, got %d", cb.APIPort)
	}
	if !cb.StatsEnabled {
		t.Fatal("stats should be enabled by default")
	}
	if !cb.BlockAds {
		t.Fatal("BlockAds should be true by default")
	}
}

func TestConfigBuilder_AddInbound_AddUser_Build(t *testing.T) {
	cb := NewConfigBuilder()

	cb.AddInbound(InboundConfig{
		Tag:  "vless-reality-1",
		Type: InboundVLESSReality,
		Port: 443,
		RealityPrivateKey:  "test-private-key",
		RealityDest:        "www.google.com:443",
		RealityShortIDs:    []string{"abcd1234"},
		RealityServerNames: []string{"www.google.com"},
	})
	cb.AddUser("vless-reality-1", "user@example.com", "test-uuid-1234")

	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Should be valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("produced invalid JSON: %v", err)
	}

	// Check top-level keys exist.
	for _, key := range []string{"log", "dns", "routing", "policy", "inbounds", "outbounds", "stats"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing top-level key %q", key)
		}
	}
}

func TestConfigBuilder_Build_ValidJSON(t *testing.T) {
	cb := NewConfigBuilder()
	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("Build output is not valid JSON")
	}
}

func TestConfigBuilder_RealityInbound_HasCorrectFields(t *testing.T) {
	cb := NewConfigBuilder()

	cb.AddInbound(InboundConfig{
		Tag:                "reality-test",
		Type:               InboundVLESSReality,
		Port:               443,
		RealityPrivateKey:  "my-private-key",
		RealityShortIDs:    []string{"aabb"},
		RealityDest:        "example.com:443",
		RealityServerNames: []string{"example.com"},
	})
	cb.AddUser("reality-test", "alice@test.com", "uuid-alice")

	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var config map[string]interface{}
	json.Unmarshal(data, &config)

	inbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		t.Fatal("inbounds is not an array")
	}

	// Find the reality inbound (skip api-inbound).
	var realityInbound map[string]interface{}
	for _, ib := range inbounds {
		m := ib.(map[string]interface{})
		if m["tag"] == "reality-test" {
			realityInbound = m
			break
		}
	}
	if realityInbound == nil {
		t.Fatal("reality inbound not found")
	}

	if realityInbound["protocol"] != "vless" {
		t.Fatalf("expected protocol 'vless', got %v", realityInbound["protocol"])
	}
	if realityInbound["port"].(float64) != 443 {
		t.Fatalf("expected port 443, got %v", realityInbound["port"])
	}

	stream := realityInbound["streamSettings"].(map[string]interface{})
	if stream["security"] != "reality" {
		t.Fatalf("expected security 'reality', got %v", stream["security"])
	}

	realitySettings := stream["realitySettings"].(map[string]interface{})
	if realitySettings["privateKey"] != "my-private-key" {
		t.Fatalf("unexpected privateKey: %v", realitySettings["privateKey"])
	}
	if realitySettings["dest"] != "example.com:443" {
		t.Fatalf("unexpected dest: %v", realitySettings["dest"])
	}

	shortIds := realitySettings["shortIds"].([]interface{})
	if len(shortIds) != 1 || shortIds[0] != "aabb" {
		t.Fatalf("unexpected shortIds: %v", shortIds)
	}
}

func TestConfigBuilder_MultipleInbounds_DifferentPorts(t *testing.T) {
	cb := NewConfigBuilder()
	cb.StatsEnabled = false // simplify: no api-inbound

	cb.AddInbound(InboundConfig{
		Tag:  "ws-1",
		Type: InboundVLESSWS,
		Port: 8080,
		Path: "/ws",
	})
	cb.AddInbound(InboundConfig{
		Tag:  "grpc-1",
		Type: InboundVLESSGRPC,
		Port: 8081,
	})

	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var config map[string]interface{}
	json.Unmarshal(data, &config)

	inbounds := config["inbounds"].([]interface{})
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(inbounds))
	}

	ports := make(map[float64]bool)
	for _, ib := range inbounds {
		m := ib.(map[string]interface{})
		ports[m["port"].(float64)] = true
	}
	if !ports[8080] || !ports[8081] {
		t.Fatalf("expected ports 8080 and 8081, got %v", ports)
	}
}

func TestConfigBuilder_AddUser_SetsFlowForReality(t *testing.T) {
	cb := NewConfigBuilder()

	cb.AddInbound(InboundConfig{
		Tag:  "reality",
		Type: InboundVLESSReality,
		Port: 443,
		RealityPrivateKey: "key",
		RealityDest:       "example.com:443",
	})
	cb.AddUser("reality", "user@test.com", "uuid-123")

	cb.mu.RLock()
	users := cb.users["reality"]
	cb.mu.RUnlock()

	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("expected flow 'xtls-rprx-vision', got %q", users[0].Flow)
	}
}

func TestConfigBuilder_AddUser_SetsSecurityForVMess(t *testing.T) {
	cb := NewConfigBuilder()

	cb.AddInbound(InboundConfig{
		Tag:  "vmess-ws",
		Type: InboundVMessWS,
		Port: 8080,
	})
	cb.AddUser("vmess-ws", "user@test.com", "uuid-456")

	cb.mu.RLock()
	users := cb.users["vmess-ws"]
	cb.mu.RUnlock()

	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Security != "auto" {
		t.Fatalf("expected security 'auto', got %q", users[0].Security)
	}
}

func TestConfigBuilder_RemoveUser(t *testing.T) {
	cb := NewConfigBuilder()
	cb.AddInbound(InboundConfig{Tag: "ws", Type: InboundVLESSWS, Port: 8080})
	cb.AddUser("ws", "alice@test.com", "uuid-a")
	cb.AddUser("ws", "bob@test.com", "uuid-b")

	cb.RemoveUser("ws", "alice@test.com")

	cb.mu.RLock()
	users := cb.users["ws"]
	cb.mu.RUnlock()

	if len(users) != 1 {
		t.Fatalf("expected 1 user after removal, got %d", len(users))
	}
	if users[0].Email != "bob@test.com" {
		t.Fatalf("expected bob to remain, got %q", users[0].Email)
	}
}

func TestConfigBuilder_Reset(t *testing.T) {
	cb := NewConfigBuilder()
	cb.AddInbound(InboundConfig{Tag: "ws", Type: InboundVLESSWS, Port: 8080})
	cb.AddUser("ws", "user@test.com", "uuid")

	cb.Reset()

	cb.mu.RLock()
	inboundCount := len(cb.inbounds)
	userCount := len(cb.users)
	cb.mu.RUnlock()

	if inboundCount != 0 {
		t.Fatalf("expected 0 inbounds after reset, got %d", inboundCount)
	}
	if userCount != 0 {
		t.Fatalf("expected 0 user tags after reset, got %d", userCount)
	}
}

func TestGenerateConfig_Convenience(t *testing.T) {
	inbounds := []InboundConfig{
		{
			Tag:  "ss",
			Type: InboundShadowsocks,
			Port: 8388,
			SSMethod:   "2022-blake3-aes-128-gcm",
			SSPassword: "server-password",
		},
	}
	users := map[string][]XrayUser{
		"ss": {
			{Email: "user1@test.com", UUID: "user-key-1"},
		},
	}

	data, err := GenerateConfig(inbounds, users)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("output is not valid JSON")
	}
}

func TestGenerateConfigJSON_ReturnsString(t *testing.T) {
	inbounds := []InboundConfig{
		{Tag: "ws", Type: InboundVLESSWS, Port: 8080},
	}
	users := map[string][]XrayUser{}

	s, err := GenerateConfigJSON(inbounds, users)
	if err != nil {
		t.Fatalf("GenerateConfigJSON: %v", err)
	}
	if len(s) == 0 {
		t.Fatal("empty string returned")
	}
	if !json.Valid([]byte(s)) {
		t.Fatal("returned string is not valid JSON")
	}
}

func TestConfigBuilder_UnknownInboundType_Skipped(t *testing.T) {
	cb := NewConfigBuilder()
	cb.StatsEnabled = false

	cb.AddInbound(InboundConfig{
		Tag:  "unknown",
		Type: "nonexistent-type",
		Port: 9999,
	})

	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var config map[string]interface{}
	json.Unmarshal(data, &config)

	inbounds := config["inbounds"].([]interface{})
	if len(inbounds) != 0 {
		t.Fatalf("expected 0 inbounds for unknown type, got %d", len(inbounds))
	}
}

func TestConfigBuilder_VLESSWSInbound_DefaultPath(t *testing.T) {
	cb := NewConfigBuilder()
	cb.StatsEnabled = false

	cb.AddInbound(InboundConfig{
		Tag:  "ws",
		Type: InboundVLESSWS,
		Port: 8080,
		// No Path set -- should default to "/ws"
	})

	data, _ := cb.Build()
	var config map[string]interface{}
	json.Unmarshal(data, &config)

	inbounds := config["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}

	stream := inbounds[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
	ws := stream["wsSettings"].(map[string]interface{})
	if ws["path"] != "/ws" {
		t.Fatalf("expected default path '/ws', got %v", ws["path"])
	}
}

func TestConfigBuilder_TrojanInbound(t *testing.T) {
	cb := NewConfigBuilder()
	cb.StatsEnabled = false

	cb.AddInbound(InboundConfig{
		Tag:         "trojan-1",
		Type:        InboundTrojanTLS,
		Port:        443,
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
	})
	cb.AddUser("trojan-1", "trojan-user@test.com", "trojan-password-123")

	data, err := cb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var config map[string]interface{}
	json.Unmarshal(data, &config)

	inbounds := config["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}

	ib := inbounds[0].(map[string]interface{})
	if ib["protocol"] != "trojan" {
		t.Fatalf("expected protocol 'trojan', got %v", ib["protocol"])
	}

	settings := ib["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	client := clients[0].(map[string]interface{})
	if client["password"] != "trojan-password-123" {
		t.Fatalf("unexpected password: %v", client["password"])
	}
}
