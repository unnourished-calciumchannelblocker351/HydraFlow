package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantVer   int
		wantProto int
	}{
		{
			name: "valid minimal subscription",
			input: `
version: 1
server: example.com
protocols:
  - name: reality-vision
    priority: 1
    transport: tcp
    security: reality
`,
			wantVer:   1,
			wantProto: 1,
		},
		{
			name: "valid with multiple protocols",
			input: `
version: 2
server: proxy.example.com
protocols:
  - name: reality-vision
    priority: 1
    transport: tcp
    security: reality
  - name: xhttp-cdn
    priority: 2
    transport: xhttp
    security: tls
  - name: hysteria2
    priority: 3
    transport: quic
    security: tls
`,
			wantVer:   2,
			wantProto: 3,
		},
		{
			name: "valid with blocking map",
			input: `
version: 1
server: example.com
protocols:
  - name: reality-vision
    priority: 1
    transport: tcp
    security: reality
blocking_map:
  rostelecom:
    blocked: [quic, wireguard]
    recommended: [reality-vision, xhttp-cdn]
    notes: "QUIC and WireGuard blocked since 2024"
`,
			wantVer:   1,
			wantProto: 1,
		},
		{
			name:    "missing version",
			input:   "server: example.com\n",
			wantErr: true,
		},
		{
			name:    "invalid YAML",
			input:   "{{{{invalid yaml",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name: "version zero is invalid",
			input: `
version: 0
server: example.com
`,
			wantErr: true,
		},
		{
			name: "full protocol config",
			input: `
version: 1
server: proxy.example.com
protocols:
  - name: reality-vision
    priority: 1
    transport: tcp
    security: reality
    host: 1.2.3.4
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    sni: www.microsoft.com
    public_key: "abc123"
    short_id: "deadbeef"
    spider_x: "/"
    fingerprint: chrome
`,
			wantVer:   1,
			wantProto: 1,
		},
		{
			name: "chain proxy config",
			input: `
version: 1
server: proxy.example.com
protocols:
  - name: chain-proxy
    priority: 1
    transport: tcp
    security: reality
    chain:
      - host: hop1.example.com
        port: 443
        sni: www.google.com
        public_key: key1
      - host: hop2.example.com
        port: 443
        sni: www.apple.com
        public_key: key2
`,
			wantVer:   1,
			wantProto: 1,
		},
		{
			name: "with fragment config",
			input: `
version: 1
server: proxy.example.com
protocols:
  - name: fragmented
    priority: 1
    transport: tcp
    security: reality
    fragment:
      packets: "tlshello"
      length: "100-200"
      interval: "10-20"
`,
			wantVer:   1,
			wantProto: 1,
		},
		{
			name: "with TTL",
			input: `
version: 1
server: example.com
ttl: 3600
protocols: []
`,
			wantVer:   1,
			wantProto: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := Parse([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if sub.Version != tt.wantVer {
				t.Errorf("Version = %d, want %d", sub.Version, tt.wantVer)
			}
			if len(sub.Protocols) != tt.wantProto {
				t.Errorf("Protocol count = %d, want %d", len(sub.Protocols), tt.wantProto)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name string
		sub  Subscription
	}{
		{
			name: "minimal",
			sub: Subscription{
				Version: 1,
				Server:  "example.com",
			},
		},
		{
			name: "with protocols",
			sub: Subscription{
				Version: 1,
				Server:  "proxy.example.com",
				Protocols: []ProtocolConfig{
					{Name: "reality", Priority: 1, Transport: "tcp", Security: "reality"},
					{Name: "xhttp", Priority: 2, Transport: "xhttp", Security: "tls"},
				},
			},
		},
		{
			name: "with blocking map",
			sub: Subscription{
				Version: 1,
				Server:  "example.com",
				BlockingMap: map[string]ISPRecommendation{
					"test-isp": {
						Blocked:     []string{"quic"},
						Recommended: []string{"reality"},
						Notes:       "test note",
					},
				},
			},
		},
		{
			name: "with timestamp",
			sub: Subscription{
				Version: 1,
				Server:  "example.com",
				Updated: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "with TTL",
			sub: Subscription{
				Version: 1,
				Server:  "example.com",
				TTL:     3600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.sub.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}
			if len(data) == 0 {
				t.Error("Marshal() returned empty data")
			}

			// Verify it can be parsed back.
			var roundTrip Subscription
			if err := yaml.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("roundtrip unmarshal error: %v", err)
			}
			if roundTrip.Version != tt.sub.Version {
				t.Errorf("Version after roundtrip = %d, want %d", roundTrip.Version, tt.sub.Version)
			}
			if roundTrip.Server != tt.sub.Server {
				t.Errorf("Server after roundtrip = %q, want %q", roundTrip.Server, tt.sub.Server)
			}
		})
	}
}

func TestForISP(t *testing.T) {
	sub := &Subscription{
		Version: 1,
		Server:  "example.com",
		Protocols: []ProtocolConfig{
			{Name: "reality-vision", Priority: 1},
			{Name: "xhttp-cdn", Priority: 2},
			{Name: "hysteria2", Priority: 3},
			{Name: "shadowtls", Priority: 4},
			{Name: "wireguard", Priority: 5},
		},
		BlockingMap: map[string]ISPRecommendation{
			"rostelecom": {
				Blocked:     []string{"hysteria2", "wireguard"},
				Recommended: []string{"xhttp-cdn"},
			},
			"mts": {
				Blocked:     []string{"wireguard"},
				Recommended: []string{"reality-vision", "shadowtls"},
			},
		},
	}

	tests := []struct {
		name           string
		isp            string
		wantLen        int
		wantFirst      string
		wantNotPresent []string
	}{
		{
			name:      "unknown ISP gets all protocols",
			isp:       "unknown-isp",
			wantLen:   5,
			wantFirst: "reality-vision",
		},
		{
			name:           "rostelecom: blocked removed, recommended first",
			isp:            "rostelecom",
			wantLen:        3,
			wantFirst:      "xhttp-cdn",
			wantNotPresent: []string{"hysteria2", "wireguard"},
		},
		{
			name:           "mts: blocked removed, recommended first",
			isp:            "mts",
			wantLen:        4,
			wantFirst:      "reality-vision",
			wantNotPresent: []string{"wireguard"},
		},
		{
			name:      "case insensitive ISP name",
			isp:       "Rostelecom",
			wantLen:   3,
			wantFirst: "xhttp-cdn",
		},
		{
			name:      "case insensitive ISP name uppercase",
			isp:       "ROSTELECOM",
			wantLen:   3,
			wantFirst: "xhttp-cdn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sub.ForISP(tt.isp)

			if len(result) != tt.wantLen {
				names := make([]string, len(result))
				for i, p := range result {
					names[i] = p.Name
				}
				t.Fatalf("ForISP(%q) returned %d protocols %v, want %d",
					tt.isp, len(result), names, tt.wantLen)
			}

			if result[0].Name != tt.wantFirst {
				t.Errorf("first protocol = %q, want %q", result[0].Name, tt.wantFirst)
			}

			resultNames := make(map[string]bool)
			for _, p := range result {
				resultNames[p.Name] = true
			}
			for _, name := range tt.wantNotPresent {
				if resultNames[name] {
					t.Errorf("protocol %q should not be present", name)
				}
			}
		})
	}
}

func TestExportV2Ray(t *testing.T) {
	tests := []struct {
		name       string
		sub        Subscription
		wantLinks  int
		wantPrefix string
	}{
		{
			name: "single reality protocol",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{
						Name:        "reality-vision",
						Priority:    1,
						Transport:   "tcp",
						Security:    "reality",
						Host:        "1.2.3.4",
						Port:        443,
						UUID:        "test-uuid",
						SNI:         "www.microsoft.com",
						PublicKey:   "pubkey123",
						ShortID:     "abcd",
						SpiderX:     "/",
						Fingerprint: "chrome",
					},
				},
			},
			wantLinks:  1,
			wantPrefix: "vless://",
		},
		{
			name: "non-reality protocol produces no links",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{
						Name:      "hysteria2",
						Priority:  1,
						Transport: "quic",
						Security:  "tls",
					},
				},
			},
			wantLinks: 0,
		},
		{
			name: "multiple protocols",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{Name: "reality1", Transport: "tcp", Security: "reality", Host: "1.1.1.1", Port: 443, UUID: "u1"},
					{Name: "reality2", Transport: "tcp", Security: "reality", Host: "2.2.2.2", Port: 443, UUID: "u2"},
					{Name: "other", Transport: "xhttp", Security: "tls"},
				},
			},
			wantLinks: 2,
		},
		{
			name: "chain proxy uses first hop",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{
						Name:      "chain",
						Transport: "tcp",
						Security:  "reality",
						Host:      "original.host",
						Port:      443,
						UUID:      "uuid1",
						Chain: []ChainHop{
							{Host: "hop1.example.com", Port: 8443},
						},
					},
				},
			},
			wantLinks:  1,
			wantPrefix: "vless://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.sub.ExportV2Ray()
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("invalid base64: %v", err)
			}

			links := strings.Split(strings.TrimSpace(string(decoded)), "\n")
			// Filter empty strings.
			var nonEmpty []string
			for _, l := range links {
				if l != "" {
					nonEmpty = append(nonEmpty, l)
				}
			}

			if len(nonEmpty) != tt.wantLinks {
				t.Errorf("got %d links, want %d. Links: %v", len(nonEmpty), tt.wantLinks, nonEmpty)
			}

			if tt.wantPrefix != "" && len(nonEmpty) > 0 {
				if !strings.HasPrefix(nonEmpty[0], tt.wantPrefix) {
					t.Errorf("link does not start with %q: %s", tt.wantPrefix, nonEmpty[0])
				}
			}
		})
	}
}

func TestExportV2RayLinkContents(t *testing.T) {
	sub := &Subscription{
		Version: 1,
		Protocols: []ProtocolConfig{
			{
				Name:        "test-proto",
				Transport:   "tcp",
				Security:    "reality",
				Host:        "10.0.0.1",
				Port:        443,
				UUID:        "my-uuid",
				SNI:         "www.google.com",
				PublicKey:   "mypubkey",
				ShortID:     "1234",
				SpiderX:     "/index",
				Fingerprint: "chrome",
			},
		},
	}

	encoded := sub.ExportV2Ray()
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	link := string(decoded)

	checks := []struct {
		name    string
		contain string
	}{
		{"protocol", "vless://"},
		{"UUID", "my-uuid@"},
		{"host", "10.0.0.1"},
		{"port", ":443"},
		{"SNI", "sni=www.google.com"},
		{"public key", "pbk=mypubkey"},
		{"short ID", "sid=1234"},
		{"fingerprint", "fp=chrome"},
		{"spider X", "spx=/index"},
		{"flow", "flow=xtls-rprx-vision"},
		{"name fragment", "#test-proto"},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(link, c.contain) {
				t.Errorf("link does not contain %q: %s", c.contain, link)
			}
		})
	}
}

func TestExportClash(t *testing.T) {
	tests := []struct {
		name      string
		sub       Subscription
		wantProxy int
	}{
		{
			name: "single protocol",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{Name: "proto1", Host: "1.1.1.1", Port: 443, UUID: "u1"},
				},
			},
			wantProxy: 1,
		},
		{
			name: "multiple protocols",
			sub: Subscription{
				Version: 1,
				Protocols: []ProtocolConfig{
					{Name: "proto1", Host: "1.1.1.1", Port: 443, UUID: "u1"},
					{Name: "proto2", Host: "2.2.2.2", Port: 443, UUID: "u2"},
					{Name: "proto3", Host: "3.3.3.3", Port: 443, UUID: "u3"},
				},
			},
			wantProxy: 3,
		},
		{
			name: "empty protocols",
			sub: Subscription{
				Version:   1,
				Protocols: nil,
			},
			wantProxy: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.sub.ExportClash()
			if err != nil {
				t.Fatalf("ExportClash() error: %v", err)
			}

			// Verify it's valid YAML.
			var clash map[string]interface{}
			if err := yaml.Unmarshal(data, &clash); err != nil {
				t.Fatalf("invalid Clash YAML: %v", err)
			}

			// Check proxy count.
			proxies, ok := clash["proxies"]
			if !ok && tt.wantProxy > 0 {
				t.Fatal("missing 'proxies' key in Clash output")
			}
			if proxies != nil {
				proxyList, ok := proxies.([]interface{})
				if ok && len(proxyList) != tt.wantProxy {
					t.Errorf("proxy count = %d, want %d", len(proxyList), tt.wantProxy)
				}
			}

			// Check proxy groups exist.
			groups, ok := clash["proxy-groups"]
			if !ok && tt.wantProxy > 0 {
				t.Error("missing 'proxy-groups' key in Clash output")
			}
			if groups != nil {
				groupList, ok := groups.([]interface{})
				if ok && len(groupList) == 0 && tt.wantProxy > 0 {
					t.Error("proxy-groups is empty")
				}
			}
		})
	}
}

func TestForISPRecommendedOrder(t *testing.T) {
	sub := &Subscription{
		Version: 1,
		Protocols: []ProtocolConfig{
			{Name: "proto-a", Priority: 1},
			{Name: "proto-b", Priority: 2},
			{Name: "proto-c", Priority: 3},
		},
		BlockingMap: map[string]ISPRecommendation{
			"test-isp": {
				Recommended: []string{"proto-c", "proto-b"},
			},
		},
	}

	result := sub.ForISP("test-isp")
	if len(result) != 3 {
		t.Fatalf("got %d protocols, want 3", len(result))
	}

	// proto-c and proto-b should come before proto-a.
	foundRecommended := 0
	for _, p := range result[:2] {
		if p.Name == "proto-c" || p.Name == "proto-b" {
			foundRecommended++
		}
	}
	if foundRecommended != 2 {
		t.Error("recommended protocols should appear first")
	}

	if result[2].Name != "proto-a" {
		t.Errorf("non-recommended protocol should be last, got %q", result[2].Name)
	}
}

func TestProtocolConfigFields(t *testing.T) {
	input := `
version: 1
server: example.com
protocols:
  - name: full-config
    priority: 1
    transport: tcp
    security: reality
    host: 1.2.3.4
    port: 443
    uuid: "test-uuid"
    sni: www.example.com
    public_key: "pubkey"
    short_id: "1234"
    spider_x: "/path"
    cdn: cdn.example.com
    path: /ws
    obfs: salamander
    handshake_server: handshake.example.com
    fingerprint: chrome
    fragment:
      packets: "tlshello"
      length: "100-200"
      interval: "10-20"
`

	sub, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	p := sub.Protocols[0]

	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"Name", p.Name, "full-config"},
		{"Transport", p.Transport, "tcp"},
		{"Security", p.Security, "reality"},
		{"Host", p.Host, "1.2.3.4"},
		{"UUID", p.UUID, "test-uuid"},
		{"SNI", p.SNI, "www.example.com"},
		{"PublicKey", p.PublicKey, "pubkey"},
		{"ShortID", p.ShortID, "1234"},
		{"SpiderX", p.SpiderX, "/path"},
		{"CDN", p.CDN, "cdn.example.com"},
		{"Path", p.Path, "/ws"},
		{"Obfs", p.Obfs, "salamander"},
		{"HandshakeServer", p.HandshakeServer, "handshake.example.com"},
		{"Fingerprint", p.Fingerprint, "chrome"},
	}

	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
			}
		})
	}

	if p.Port != 443 {
		t.Errorf("Port = %d, want 443", p.Port)
	}
	if p.Priority != 1 {
		t.Errorf("Priority = %d, want 1", p.Priority)
	}
	if p.Fragment == nil {
		t.Fatal("Fragment is nil")
	}
	if p.Fragment.Packets != "tlshello" {
		t.Errorf("Fragment.Packets = %q, want %q", p.Fragment.Packets, "tlshello")
	}
}
