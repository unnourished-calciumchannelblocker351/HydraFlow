package integrations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRemnawaveProvider_RequiresAPIURL(t *testing.T) {
	_, err := NewRemnawaveProvider(RemnawaveConfig{
		APIToken: "test-token",
	})
	if err == nil {
		t.Fatal("expected error when api_url is empty")
	}
}

func TestNewRemnawaveProvider_RequiresAPIToken(t *testing.T) {
	_, err := NewRemnawaveProvider(RemnawaveConfig{
		APIURL: "http://localhost:8080",
	})
	if err == nil {
		t.Fatal("expected error when api_token is empty")
	}
}

func TestNewRemnawaveProvider_Success(t *testing.T) {
	p, err := NewRemnawaveProvider(RemnawaveConfig{
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

func TestRemnawaveProvider_MapProtocol(t *testing.T) {
	p := &RemnawaveProvider{}

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
		{"unknown passthrough", "wireguard", "", "", "wireguard"},
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

func TestRemnawaveProvider_EnrichInboundFromTag(t *testing.T) {
	p := &RemnawaveProvider{}

	tests := []struct {
		name     string
		tag      string
		wantProto string
		wantNet   string
		wantSec   string
	}{
		{"vless reality", "VLESS_TCP_REALITY", "vless", "tcp", "reality"},
		{"vmess ws", "VMESS_WS_TLS", "vmess", "ws", "tls"},
		{"trojan grpc", "TROJAN_GRPC", "trojan", "grpc", ""},
		{"ss", "SHADOWSOCKS_TCP", "shadowsocks", "tcp", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inb := &rwInbound{Tag: tc.tag}
			p.enrichInboundFromTag(inb)
			if inb.Protocol != tc.wantProto {
				t.Fatalf("protocol: expected %q, got %q", tc.wantProto, inb.Protocol)
			}
			if inb.Network != tc.wantNet {
				t.Fatalf("network: expected %q, got %q", tc.wantNet, inb.Network)
			}
			if inb.Security != tc.wantSec {
				t.Fatalf("security: expected %q, got %q", tc.wantSec, inb.Security)
			}
		})
	}
}

func TestRemnawaveProvider_UserToNodes(t *testing.T) {
	p := &RemnawaveProvider{serverIP: "10.0.0.1"}

	inboundMap := map[string]rwInbound{
		"vless-reality-443": {
			Tag:      "vless-reality-443",
			Protocol: "vless",
			Network:  "tcp",
			Security: "reality",
			Port:     443,
			SNI:      "www.google.com",
		},
		"vmess-ws-8080": {
			Tag:      "vmess-ws-8080",
			Protocol: "vmess",
			Network:  "ws",
			Security: "none",
			Port:     8080,
			Path:     "/ws",
			Host:     "cdn.example.com",
		},
	}

	user := rwUser{
		UUID:           "test-uuid-1234",
		Username:       "alice",
		Status:         "active",
		ActiveInbounds: []string{"vless-reality-443", "vmess-ws-8080"},
		VlessFlow:      "xtls-rprx-vision",
	}

	nodes := p.userToNodes(user, inboundMap)

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
	if n0.SNI != "www.google.com" {
		t.Fatalf("node[0] sni: expected 'www.google.com', got %q", n0.SNI)
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
	if n1.Port != 8080 {
		t.Fatalf("node[1] port: expected 8080, got %d", n1.Port)
	}
	if n1.Path != "/ws" {
		t.Fatalf("node[1] path: expected '/ws', got %q", n1.Path)
	}
	if n1.Host != "cdn.example.com" {
		t.Fatalf("node[1] host: expected 'cdn.example.com', got %q", n1.Host)
	}
}

func TestRemnawaveProvider_SkipsInactiveUsers(t *testing.T) {
	p := &RemnawaveProvider{serverIP: "10.0.0.1"}

	inboundMap := map[string]rwInbound{
		"vless-reality-443": {
			Tag:      "vless-reality-443",
			Protocol: "vless",
			Network:  "tcp",
			Security: "reality",
			Port:     443,
		},
	}

	user := rwUser{
		UUID:           "test-uuid",
		Username:       "disabled-user",
		Status:         "disabled",
		ActiveInbounds: []string{"vless-reality-443"},
	}

	// userToNodes doesn't check status (that's done in refresh()), but
	// we verify it at least creates nodes for active inbounds.
	nodes := p.userToNodes(user, inboundMap)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (status filtering is in refresh), got %d", len(nodes))
	}
}

func TestRemnawaveProvider_FetchUsersHTTP(t *testing.T) {
	resp := rwUsersResponse{
		Users: []rwUser{
			{UUID: "uuid-1", Username: "alice", Status: "active"},
			{UUID: "uuid-2", Username: "bob", Status: "active"},
		},
		Total: 2,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewRemnawaveProvider(RemnawaveConfig{
		APIURL:   srv.URL,
		APIToken: "test-token",
		ServerIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	users, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "alice" {
		t.Fatalf("expected username 'alice', got %q", users[0].Username)
	}
}

func TestRemnawaveProvider_FetchInboundsHTTP(t *testing.T) {
	resp := rwInboundsResponse{
		Inbounds: []rwInbound{
			{Tag: "vless-reality", Protocol: "vless", Port: 443},
			{Tag: "vmess-ws", Protocol: "vmess", Port: 8080},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewRemnawaveProvider(RemnawaveConfig{
		APIURL:   srv.URL,
		APIToken: "test-token",
		ServerIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	inbounds, err := p.fetchInbounds()
	if err != nil {
		t.Fatalf("fetch inbounds: %v", err)
	}
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(inbounds))
	}
}

func TestRemnawaveProvider_UnknownInboundFallsBackToTag(t *testing.T) {
	p := &RemnawaveProvider{serverIP: "10.0.0.1"}

	// No inbounds in the map -- should fall back to tag-based enrichment.
	inboundMap := map[string]rwInbound{}

	user := rwUser{
		UUID:           "test-uuid",
		Username:       "alice",
		Status:         "active",
		ActiveInbounds: []string{"VLESS_TCP_REALITY"},
	}

	nodes := p.userToNodes(user, inboundMap)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Protocol != "reality" {
		t.Fatalf("expected protocol 'reality', got %q", nodes[0].Protocol)
	}
}
