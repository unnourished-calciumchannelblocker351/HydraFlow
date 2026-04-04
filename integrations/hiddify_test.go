package integrations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHiddifyProvider_RequiresAPIURL(t *testing.T) {
	_, err := NewHiddifyProvider(HiddifyConfig{
		APIToken: "test-token",
	})
	if err == nil {
		t.Fatal("expected error when api_url is empty")
	}
}

func TestNewHiddifyProvider_RequiresAPIToken(t *testing.T) {
	_, err := NewHiddifyProvider(HiddifyConfig{
		APIURL: "http://localhost:8080",
	})
	if err == nil {
		t.Fatal("expected error when api_token is empty")
	}
}

func TestNewHiddifyProvider_Success(t *testing.T) {
	p, err := NewHiddifyProvider(HiddifyConfig{
		APIURL:   "http://localhost:8080",
		APIToken: "test-token",
		ServerIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestHiddifyProvider_MapProtocol(t *testing.T) {
	p := &HiddifyProvider{}

	tests := []struct {
		name     string
		proto    string
		network  string
		security string
		expected string
	}{
		{"vless+reality", "vless", "tcp", "reality", "reality"},
		{"vless+ws", "vless", "ws", "none", "ws"},
		{"vless+grpc", "vless", "grpc", "tls", "grpc"},
		{"vless+xhttp", "vless", "xhttp", "none", "xhttp"},
		{"vless+tcp default", "vless", "tcp", "tls", "reality"},
		{"vmess", "vmess", "ws", "none", "ws"},
		{"trojan", "trojan", "ws", "tls", "ws"},
		{"shadowsocks", "shadowsocks", "tcp", "none", "ss"},
		{"unknown", "wireguard", "", "", "wireguard"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.mapProtocol(tc.proto, tc.network, tc.security)
			if result != tc.expected {
				t.Fatalf("mapProtocol(%q, %q, %q) = %q, want %q",
					tc.proto, tc.network, tc.security, result, tc.expected)
			}
		})
	}
}

func TestHiddifyProvider_UserToNodes_WithConfigs(t *testing.T) {
	p := &HiddifyProvider{serverIP: "10.0.0.1"}

	configs := []hiddifyConfig{
		{
			Tag:      "vless-reality",
			Protocol: "vless",
			Network:  "tcp",
			Security: "reality",
			Port:     443,
			SNI:      "www.google.com",
			Flow:     "xtls-rprx-vision",
		},
		{
			Tag:      "vmess-ws",
			Protocol: "vmess",
			Network:  "ws",
			Security: "none",
			Port:     8080,
			Path:     "/ws",
			Host:     "cdn.example.com",
		},
	}

	user := hiddifyUser{
		UUID:    "test-uuid-1234",
		Name:    "alice",
		Enabled: true,
	}

	nodes := p.userToNodes(user, configs)

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	// Check reality node.
	n0 := nodes[0]
	if n0.Protocol != "reality" {
		t.Fatalf("node[0] protocol: expected 'reality', got %q", n0.Protocol)
	}
	if n0.Port != 443 {
		t.Fatalf("node[0] port: expected 443, got %d", n0.Port)
	}
	if n0.UUID != "test-uuid-1234" {
		t.Fatalf("node[0] uuid: expected 'test-uuid-1234', got %q", n0.UUID)
	}
	if n0.Flow != "xtls-rprx-vision" {
		t.Fatalf("node[0] flow: expected 'xtls-rprx-vision', got %q", n0.Flow)
	}
	if n0.Fingerprint != "chrome" {
		t.Fatalf("node[0] fingerprint: expected 'chrome', got %q", n0.Fingerprint)
	}

	// Check WS node.
	n1 := nodes[1]
	if n1.Protocol != "ws" {
		t.Fatalf("node[1] protocol: expected 'ws', got %q", n1.Protocol)
	}
	if n1.Path != "/ws" {
		t.Fatalf("node[1] path: expected '/ws', got %q", n1.Path)
	}
	if n1.Host != "cdn.example.com" {
		t.Fatalf("node[1] host: expected 'cdn.example.com', got %q", n1.Host)
	}
}

func TestHiddifyProvider_UserToNodes_NoConfigs(t *testing.T) {
	p := &HiddifyProvider{serverIP: "10.0.0.1"}

	user := hiddifyUser{
		UUID:    "test-uuid",
		Name:    "bob",
		Enabled: true,
	}

	nodes := p.userToNodes(user, nil)

	if len(nodes) != 1 {
		t.Fatalf("expected 1 default node, got %d", len(nodes))
	}
	if nodes[0].Protocol != "reality" {
		t.Fatalf("expected default protocol 'reality', got %q", nodes[0].Protocol)
	}
	if nodes[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("expected default flow 'xtls-rprx-vision', got %q", nodes[0].Flow)
	}
}

func TestHiddifyProvider_FetchUsersHTTP_ListResponse(t *testing.T) {
	users := []hiddifyUser{
		{UUID: "uuid-1", Name: "alice", Enabled: true},
		{UUID: "uuid-2", Name: "bob", Enabled: true},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Hiddify-API-Key") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(users)
	}))
	defer srv.Close()

	p, err := NewHiddifyProvider(HiddifyConfig{
		APIURL:   srv.URL,
		APIToken: "test-token",
		ServerIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 users, got %d", len(result))
	}
}

func TestHiddifyProvider_FetchUsersHTTP_WrappedResponse(t *testing.T) {
	resp := hiddifyUsersResponse{
		Users: []hiddifyUser{
			{UUID: "uuid-1", Name: "charlie", Enabled: true},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewHiddifyProvider(HiddifyConfig{
		APIURL:   srv.URL,
		APIToken: "test-token",
		ServerIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 user, got %d", len(result))
	}
	if result[0].Name != "charlie" {
		t.Fatalf("expected name 'charlie', got %q", result[0].Name)
	}
}

func TestHiddifyProvider_FetchConfigsHTTP(t *testing.T) {
	configs := []hiddifyConfig{
		{Tag: "vless-reality", Protocol: "vless", Port: 443},
		{Tag: "vmess-ws", Protocol: "vmess", Port: 8080},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(configs)
	}))
	defer srv.Close()

	p, err := NewHiddifyProvider(HiddifyConfig{
		APIURL:   srv.URL,
		APIToken: "test-token",
		ServerIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchConfigs()
	if err != nil {
		t.Fatalf("fetch configs: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(result))
	}
}
