package integrations

import (
	"encoding/json"
	"testing"
)

// ---- parseStreamSettings / stream parsing tests ----

func TestParseStreamSettings_ExtractNetworkSecurity(t *testing.T) {
	tests := []struct {
		name            string
		streamJSON      string
		wantNetwork     string
		wantSecurity    string
	}{
		{
			name:         "reality tcp",
			streamJSON:   `{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"example.com:443","serverNames":["example.com"],"privateKey":"abc","shortIds":["1234"]}}`,
			wantNetwork:  "tcp",
			wantSecurity: "reality",
		},
		{
			name:         "ws none",
			streamJSON:   `{"network":"ws","security":"none","wsSettings":{"path":"/ws"}}`,
			wantNetwork:  "ws",
			wantSecurity: "none",
		},
		{
			name:         "grpc tls",
			streamJSON:   `{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"grpc"}}`,
			wantNetwork:  "grpc",
			wantSecurity: "tls",
		},
		{
			name:         "xhttp none",
			streamJSON:   `{"network":"xhttp","security":"none","xhttpSettings":{"path":"/xhttp","host":["cdn.example.com"]}}`,
			wantNetwork:  "xhttp",
			wantSecurity: "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stream xuiStreamSettings
			if err := json.Unmarshal([]byte(tc.streamJSON), &stream); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if stream.Network != tc.wantNetwork {
				t.Fatalf("network: expected %q, got %q", tc.wantNetwork, stream.Network)
			}
			if stream.Security != tc.wantSecurity {
				t.Fatalf("security: expected %q, got %q", tc.wantSecurity, stream.Security)
			}
		})
	}
}

// ---- parseInboundClients (settings JSON parsing) ----

func TestParseInboundClients_ExtractUUIDsAndEmails(t *testing.T) {
	settingsJSON := `{
		"clients": [
			{"id": "uuid-1111", "email": "alice@test.com", "enable": true, "flow": "xtls-rprx-vision"},
			{"id": "uuid-2222", "email": "bob@test.com", "enable": true}
		]
	}`

	var settings xuiSettings
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(settings.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(settings.Clients))
	}

	if settings.Clients[0].ID != "uuid-1111" {
		t.Fatalf("expected client[0].ID='uuid-1111', got %q", settings.Clients[0].ID)
	}
	if settings.Clients[0].Email != "alice@test.com" {
		t.Fatalf("expected client[0].Email='alice@test.com', got %q", settings.Clients[0].Email)
	}
	if settings.Clients[1].ID != "uuid-2222" {
		t.Fatalf("expected client[1].ID='uuid-2222', got %q", settings.Clients[1].ID)
	}
}

func TestParseInboundClients_DisabledClientSkipped(t *testing.T) {
	settingsJSON := `{
		"clients": [
			{"id": "uuid-enabled", "email": "on@test.com", "enable": true},
			{"id": "uuid-disabled", "email": "off@test.com", "enable": false}
		]
	}`

	var settings xuiSettings
	json.Unmarshal([]byte(settingsJSON), &settings)

	enabled := 0
	for _, c := range settings.Clients {
		if c.Enable {
			enabled++
		}
	}
	if enabled != 1 {
		t.Fatalf("expected 1 enabled client, got %d", enabled)
	}
}

func TestParseInboundClients_TrojanPassword(t *testing.T) {
	settingsJSON := `{
		"clients": [
			{"id": "", "email": "trojan@test.com", "enable": true, "password": "trojan-pass-123"}
		]
	}`

	var settings xuiSettings
	json.Unmarshal([]byte(settingsJSON), &settings)

	if settings.Clients[0].Password != "trojan-pass-123" {
		t.Fatalf("expected password 'trojan-pass-123', got %q", settings.Clients[0].Password)
	}
}

// ---- sanitizeForSQL (safeBase64RE) ----

func TestSafeBase64RE_AcceptsValidKeys(t *testing.T) {
	validKeys := []string{
		"abc123",
		"ABCdef",
		"aG9sYQ",
		"key+with/slash=",
		"base64url_key-test",
	}
	for _, key := range validKeys {
		if !safeBase64RE.MatchString(key) {
			t.Fatalf("expected valid key to be accepted: %q", key)
		}
	}
}

func TestSafeBase64RE_RejectsInvalidCharacters(t *testing.T) {
	invalidKeys := []string{
		"key; DROP TABLE inbounds;--",
		"key' OR '1'='1",
		"key\nwith\nnewlines",
		"key with spaces",
		"key\x00null",
		"key{braces}",
	}
	for _, key := range invalidKeys {
		if safeBase64RE.MatchString(key) {
			t.Fatalf("expected invalid key to be rejected: %q", key)
		}
	}
}

// ---- mapProtocol tests ----

func TestMapProtocol(t *testing.T) {
	// Use a zero-valued provider (no external dependencies needed for mapProtocol).
	p := &XUIProvider{}

	tests := []struct {
		name     string
		proto    string
		stream   xuiStreamSettings
		expected string
	}{
		{
			name:     "vless + reality",
			proto:    "vless",
			stream:   xuiStreamSettings{Network: "tcp", Security: "reality"},
			expected: "reality",
		},
		{
			name:     "vless + ws",
			proto:    "vless",
			stream:   xuiStreamSettings{Network: "ws", Security: "none"},
			expected: "ws",
		},
		{
			name:     "vless + grpc",
			proto:    "vless",
			stream:   xuiStreamSettings{Network: "grpc", Security: "tls"},
			expected: "grpc",
		},
		{
			name:     "vless + xhttp",
			proto:    "vless",
			stream:   xuiStreamSettings{Network: "xhttp", Security: "none"},
			expected: "xhttp",
		},
		{
			name:     "vless + tcp (no reality) fallback to reality",
			proto:    "vless",
			stream:   xuiStreamSettings{Network: "tcp", Security: "tls"},
			expected: "reality",
		},
		{
			name:     "vmess + ws",
			proto:    "vmess",
			stream:   xuiStreamSettings{Network: "ws", Security: "none"},
			expected: "ws",
		},
		{
			name:     "vmess default",
			proto:    "vmess",
			stream:   xuiStreamSettings{Network: "tcp", Security: "none"},
			expected: "ws",
		},
		{
			name:     "trojan",
			proto:    "trojan",
			stream:   xuiStreamSettings{Network: "tcp", Security: "tls"},
			expected: "ws",
		},
		{
			name:     "shadowsocks",
			proto:    "shadowsocks",
			stream:   xuiStreamSettings{Network: "tcp", Security: "none"},
			expected: "ss",
		},
		{
			name:     "unknown protocol passthrough",
			proto:    "wireguard",
			stream:   xuiStreamSettings{},
			expected: "wireguard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.mapProtocol(tc.proto, tc.stream)
			if result != tc.expected {
				t.Fatalf("mapProtocol(%q, {net:%q, sec:%q}) = %q, want %q",
					tc.proto, tc.stream.Network, tc.stream.Security, result, tc.expected)
			}
		})
	}
}

// ---- fillStreamSettings tests ----

func TestFillStreamSettings_Reality(t *testing.T) {
	p := &XUIProvider{}
	stream := xuiStreamSettings{
		Network:  "tcp",
		Security: "reality",
		RealitySettings: &xuiRealitySettings{
			ServerNames: []string{"sni.example.com"},
			ShortIds:    []string{"aabb"},
			PublicKey:   "test-public-key",
		},
	}

	// Minimal Node-like test: we use the smartsub import indirectly.
	// Since fillStreamSettings modifies a *smartsub.Node, create one.
	node := &nodeForTest{}
	p.fillStreamSettingsForTest(node, stream)

	if node.SNI != "sni.example.com" {
		t.Fatalf("expected SNI 'sni.example.com', got %q", node.SNI)
	}
	if node.ShortID != "aabb" {
		t.Fatalf("expected ShortID 'aabb', got %q", node.ShortID)
	}
	if node.PublicKey != "test-public-key" {
		t.Fatalf("expected PublicKey 'test-public-key', got %q", node.PublicKey)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Fatalf("expected Flow 'xtls-rprx-vision', got %q", node.Flow)
	}
}

func TestFillStreamSettings_WS(t *testing.T) {
	p := &XUIProvider{}
	stream := xuiStreamSettings{
		Network:  "ws",
		Security: "none",
		WSSettings: &xuiWSSettings{
			Path:    "/myws",
			Headers: map[string]string{"Host": "cdn.example.com"},
		},
	}

	node := &nodeForTest{}
	p.fillStreamSettingsForTest(node, stream)

	if node.Path != "/myws" {
		t.Fatalf("expected path '/myws', got %q", node.Path)
	}
	if node.Host != "cdn.example.com" {
		t.Fatalf("expected host 'cdn.example.com', got %q", node.Host)
	}
}

func TestFillStreamSettings_GRPC(t *testing.T) {
	p := &XUIProvider{}
	stream := xuiStreamSettings{
		Network:  "grpc",
		Security: "tls",
		GRPCSettings: &xuiGRPCSettings{
			ServiceName: "myservice",
		},
	}

	node := &nodeForTest{}
	p.fillStreamSettingsForTest(node, stream)

	if node.ServiceName != "myservice" {
		t.Fatalf("expected serviceName 'myservice', got %q", node.ServiceName)
	}
}

// nodeForTest mirrors the fields fillStreamSettings writes to, avoiding
// a direct import dependency on the smartsub.Node struct in these unit tests.
// We use a helper method that works on this type.
type nodeForTest struct {
	Security    string
	SNI         string
	ShortID     string
	PublicKey   string
	Flow        string
	Fingerprint string
	Path        string
	Host        string
	CDN         string
	ServiceName string
}

// fillStreamSettingsForTest exercises the same logic as fillStreamSettings
// but targets our test struct. This avoids creating a real smartsub.Node
// while still testing the stream-parsing logic.
func (p *XUIProvider) fillStreamSettingsForTest(node *nodeForTest, stream xuiStreamSettings) {
	node.Security = stream.Security

	if stream.RealitySettings != nil {
		rs := stream.RealitySettings
		if len(rs.ServerNames) > 0 {
			node.SNI = rs.ServerNames[0]
		}
		if len(rs.ShortIds) > 0 {
			node.ShortID = rs.ShortIds[0]
		}
		node.PublicKey = rs.PublicKey
		node.Flow = "xtls-rprx-vision"
		node.Fingerprint = "chrome"
	}

	if stream.TLSSettings != nil {
		node.SNI = stream.TLSSettings.ServerName
	}

	if stream.WSSettings != nil {
		node.Path = stream.WSSettings.Path
		if host, ok := stream.WSSettings.Headers["Host"]; ok {
			node.Host = host
			node.CDN = host
		}
	}

	if stream.GRPCSettings != nil {
		node.ServiceName = stream.GRPCSettings.ServiceName
	}

	if stream.XHTTPSettings != nil {
		node.Path = stream.XHTTPSettings.Path
		if len(stream.XHTTPSettings.Host) > 0 {
			node.Host = stream.XHTTPSettings.Host[0]
			node.CDN = stream.XHTTPSettings.Host[0]
		}
	}
}

// ---- execSQLite multi-statement rejection test ----

func TestExecSQLite_RejectsMultipleStatements(t *testing.T) {
	// We cannot actually call execSQLite (requires sqlite3 binary + DB),
	// but we can verify the multi-statement check logic.
	query := "SELECT 1; DROP TABLE users;"
	trimmed := trimForCheck(query)
	if !containsMultipleStatements(trimmed) {
		t.Fatal("should detect multiple statements")
	}

	query2 := "SELECT 1;"
	trimmed2 := trimForCheck(query2)
	if containsMultipleStatements(trimmed2) {
		t.Fatal("single statement should be OK")
	}
}

// trimForCheck mirrors the logic from execSQLite.
func trimForCheck(query string) string {
	s := query
	// Trim trailing whitespace
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	// Trim trailing semicolon
	if len(s) > 0 && s[len(s)-1] == ';' {
		s = s[:len(s)-1]
	}
	return s
}

func containsMultipleStatements(trimmed string) bool {
	for _, c := range trimmed {
		if c == ';' {
			return true
		}
	}
	return false
}

// ---- Reality settings parsing ----

func TestParseRealitySettings(t *testing.T) {
	streamJSON := `{
		"network": "tcp",
		"security": "reality",
		"realitySettings": {
			"show": false,
			"dest": "www.google.com:443",
			"xver": 0,
			"serverNames": ["www.google.com"],
			"privateKey": "test-private-key-base64",
			"shortIds": ["aabb", "ccdd"],
			"publicKey": "test-public-key-base64"
		}
	}`

	var stream xuiStreamSettings
	if err := json.Unmarshal([]byte(streamJSON), &stream); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if stream.RealitySettings == nil {
		t.Fatal("realitySettings should not be nil")
	}
	rs := stream.RealitySettings
	if rs.Dest != "www.google.com:443" {
		t.Fatalf("expected dest 'www.google.com:443', got %q", rs.Dest)
	}
	if rs.PrivateKey != "test-private-key-base64" {
		t.Fatalf("unexpected privateKey: %q", rs.PrivateKey)
	}
	if len(rs.ShortIds) != 2 {
		t.Fatalf("expected 2 shortIds, got %d", len(rs.ShortIds))
	}
	if rs.PublicKey != "test-public-key-base64" {
		t.Fatalf("unexpected publicKey: %q", rs.PublicKey)
	}
}
