package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// getConfigPath
// ---------------------------------------------------------------------------

func TestGetConfigPath(t *testing.T) {
	// Not parallel: modifies global os.Args.
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "default path",
			args: []string{"hydraflow", "serve"},
			want: "/etc/hydraflow/hydraflow.yaml",
		},
		{
			name: "custom path",
			args: []string{"hydraflow", "serve", "--config", "/tmp/my-config.yaml"},
			want: "/tmp/my-config.yaml",
		},
		{
			name: "flag at end",
			args: []string{"hydraflow", "--config", "/custom/path.yaml"},
			want: "/custom/path.yaml",
		},
		{
			name: "flag without value (edge case)",
			args: []string{"hydraflow", "--config"},
			want: "/etc/hydraflow/hydraflow.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore os.Args.
			origArgs := os.Args
			defer func() { os.Args = origArgs }()

			os.Args = tt.args
			got := getConfigPath()
			if got != tt.want {
				t.Errorf("getConfigPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// portFromListen
// ---------------------------------------------------------------------------

func TestPortFromListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listen string
		want   string
	}{
		{"0.0.0.0:8080", "8080"},
		{":443", "443"},
		{"127.0.0.1:10086", "10086"},
		{"[::]:8443", "8443"},
		{"8080", "8080"}, // no colon, returns as-is
	}

	for _, tt := range tests {
		t.Run(tt.listen, func(t *testing.T) {
			t.Parallel()
			got := portFromListen(tt.listen)
			if got != tt.want {
				t.Errorf("portFromListen(%q) = %q, want %q", tt.listen, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getFlagValue
// ---------------------------------------------------------------------------

func TestGetFlagValue(t *testing.T) {
	// Not parallel: modifies global os.Args.
	tests := []struct {
		name string
		args []string
		flag string
		want string
	}{
		{
			name: "flag present",
			args: []string{"hydraflow", "serve", "--mode", "standalone"},
			flag: "--mode",
			want: "standalone",
		},
		{
			name: "flag absent",
			args: []string{"hydraflow", "serve"},
			flag: "--mode",
			want: "",
		},
		{
			name: "flag without value",
			args: []string{"hydraflow", "--mode"},
			flag: "--mode",
			want: "",
		},
		{
			name: "multiple flags",
			args: []string{"hydraflow", "serve", "--mode", "3xui", "--listen", ":9090"},
			flag: "--listen",
			want: ":9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origArgs := os.Args
			defer func() { os.Args = origArgs }()

			os.Args = tt.args
			got := getFlagValue(tt.flag)
			if got != tt.want {
				t.Errorf("getFlagValue(%q) = %q, want %q", tt.flag, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseLogLevel
// ---------------------------------------------------------------------------

func TestParseLogLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := parseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadUsers / saveUsers — JSON roundtrip
// ---------------------------------------------------------------------------

func TestLoadSaveUsers_Roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	users := []User{
		{
			Email:     "alice@example.com",
			UUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Enabled:   true,
			CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Email:       "bob@example.com",
			UUID:        "11111111-2222-3333-4444-555555555555",
			Enabled:     false,
			CreatedAt:   time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			TrafficUp:   1024,
			TrafficDown: 2048,
		},
	}

	// Save.
	if err := saveUsers(users, path); err != nil {
		t.Fatalf("saveUsers error: %v", err)
	}

	// Load.
	loaded, err := loadUsers(path)
	if err != nil {
		t.Fatalf("loadUsers error: %v", err)
	}

	if len(loaded) != len(users) {
		t.Fatalf("loaded %d users, want %d", len(loaded), len(users))
	}

	for i, u := range loaded {
		if u.Email != users[i].Email {
			t.Errorf("user[%d].Email = %q, want %q", i, u.Email, users[i].Email)
		}
		if u.UUID != users[i].UUID {
			t.Errorf("user[%d].UUID = %q, want %q", i, u.UUID, users[i].UUID)
		}
		if u.Enabled != users[i].Enabled {
			t.Errorf("user[%d].Enabled = %v, want %v", i, u.Enabled, users[i].Enabled)
		}
		if u.TrafficUp != users[i].TrafficUp {
			t.Errorf("user[%d].TrafficUp = %d, want %d", i, u.TrafficUp, users[i].TrafficUp)
		}
		if u.TrafficDown != users[i].TrafficDown {
			t.Errorf("user[%d].TrafficDown = %d, want %d", i, u.TrafficDown, users[i].TrafficDown)
		}
	}
}

func TestLoadUsers_NonExistentFile(t *testing.T) {
	t.Parallel()
	_, err := loadUsers("/tmp/nonexistent-hydraflow-test-file.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadUsers_InvalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := loadUsers(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSaveUsers_CreatesDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "dir", "users.json")

	users := []User{{Email: "test@test.com", UUID: "uuid-1", Enabled: true}}
	if err := saveUsers(users, nested); err != nil {
		t.Fatalf("saveUsers to nested path error: %v", err)
	}

	loaded, err := loadUsers(nested)
	if err != nil {
		t.Fatalf("loadUsers from nested path error: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Email != "test@test.com" {
		t.Error("roundtrip through nested path failed")
	}
}

// ---------------------------------------------------------------------------
// loadServers / saveServers — JSON roundtrip
// ---------------------------------------------------------------------------

func TestLoadSaveServers_Roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")

	servers := []ServerEntry{
		{
			Name:    "nl-1",
			IP:      "1.2.3.4",
			APIKey:  "key-abc",
			AddedAt: "2025-01-01T00:00:00Z",
		},
		{
			Name:      "de-1",
			IP:        "5.6.7.8",
			APIKey:    "key-xyz",
			Protocols: []string{"reality", "ws"},
			AddedAt:   "2025-06-01T00:00:00Z",
		},
	}

	// Save.
	if err := saveServers(servers, path); err != nil {
		t.Fatalf("saveServers error: %v", err)
	}

	// Load.
	loaded, err := loadServers(path)
	if err != nil {
		t.Fatalf("loadServers error: %v", err)
	}

	if len(loaded) != len(servers) {
		t.Fatalf("loaded %d servers, want %d", len(loaded), len(servers))
	}

	for i, s := range loaded {
		if s.Name != servers[i].Name {
			t.Errorf("server[%d].Name = %q, want %q", i, s.Name, servers[i].Name)
		}
		if s.IP != servers[i].IP {
			t.Errorf("server[%d].IP = %q, want %q", i, s.IP, servers[i].IP)
		}
		if s.APIKey != servers[i].APIKey {
			t.Errorf("server[%d].APIKey = %q, want %q", i, s.APIKey, servers[i].APIKey)
		}
	}

	// Verify protocols for second server.
	if len(loaded[1].Protocols) != 2 {
		t.Errorf("server[1].Protocols len = %d, want 2", len(loaded[1].Protocols))
	}
}

func TestLoadServers_NonExistentFile(t *testing.T) {
	t.Parallel()
	_, err := loadServers("/tmp/nonexistent-hydraflow-servers.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadServers_InvalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0644)

	_, err := loadServers(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSaveServers_CreatesDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "path", "servers.json")

	servers := []ServerEntry{{Name: "s1", IP: "1.1.1.1", APIKey: "k"}}
	if err := saveServers(servers, nested); err != nil {
		t.Fatalf("saveServers error: %v", err)
	}

	loaded, err := loadServers(nested)
	if err != nil {
		t.Fatalf("loadServers error: %v", err)
	}
	if len(loaded) != 1 || loaded[0].IP != "1.1.1.1" {
		t.Error("roundtrip failed")
	}
}

// ---------------------------------------------------------------------------
// VLESS link parsing
// ---------------------------------------------------------------------------

func TestParseVLESSLink_Valid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		link     string
		wantUUID string
		wantHost string
		wantPort int
		wantSec  string
		wantSNI  string
	}{
		{
			name:     "full reality link",
			link:     "vless://test-uuid@1.2.3.4:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=pk123&sid=ab&flow=xtls-rprx-vision#My-Node",
			wantUUID: "test-uuid",
			wantHost: "1.2.3.4",
			wantPort: 443,
			wantSec:  "reality",
			wantSNI:  "www.example.com",
		},
		{
			name:     "ws link",
			link:     "vless://uuid-ws@cdn.example.com:8443?type=ws&security=tls&sni=cdn.example.com&path=/ws#WS-Node",
			wantUUID: "uuid-ws",
			wantHost: "cdn.example.com",
			wantPort: 8443,
			wantSec:  "tls",
			wantSNI:  "cdn.example.com",
		},
		{
			name:     "default port",
			link:     "vless://uuid-def@host.com?security=none",
			wantUUID: "uuid-def",
			wantHost: "host.com",
			wantPort: 443,
			wantSec:  "none",
		},
		{
			name:     "with fragment name",
			link:     "vless://my-uuid@5.6.7.8:1234?security=reality&sni=example.com#My-VPS",
			wantUUID: "my-uuid",
			wantHost: "5.6.7.8",
			wantPort: 1234,
			wantSec:  "reality",
			wantSNI:  "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := parseVLESSLink(tt.link)
			if err != nil {
				t.Fatalf("parseVLESSLink error: %v", err)
			}
			if v.UUID != tt.wantUUID {
				t.Errorf("UUID = %q, want %q", v.UUID, tt.wantUUID)
			}
			if v.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", v.Host, tt.wantHost)
			}
			if v.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", v.Port, tt.wantPort)
			}
			if v.Security != tt.wantSec {
				t.Errorf("Security = %q, want %q", v.Security, tt.wantSec)
			}
			if tt.wantSNI != "" && v.SNI != tt.wantSNI {
				t.Errorf("SNI = %q, want %q", v.SNI, tt.wantSNI)
			}
		})
	}
}

func TestParseVLESSLink_Invalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		link string
	}{
		{"not vless scheme", "https://test-uuid@1.2.3.4:443"},
		{"missing uuid", "vless://@1.2.3.4:443"},
		{"empty string", ""},
		{"just vless prefix", "vless://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseVLESSLink(tt.link)
			if err == nil {
				t.Error("expected error for invalid VLESS link")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// User/Server JSON format validation
// ---------------------------------------------------------------------------

func TestUserJSONFormat(t *testing.T) {
	t.Parallel()
	u := User{
		Email:       "test@example.com",
		UUID:        "test-uuid",
		Enabled:     true,
		CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		TrafficUp:   100,
		TrafficDown: 200,
	}

	data, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}

	var decoded User
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Email != u.Email || decoded.UUID != u.UUID || decoded.Enabled != u.Enabled {
		t.Error("JSON roundtrip failed for User")
	}
}

func TestServerEntryJSONFormat(t *testing.T) {
	t.Parallel()
	s := ServerEntry{
		Name:      "test-server",
		IP:        "1.2.3.4",
		APIKey:    "key123",
		Protocols: []string{"reality", "ws"},
		AddedAt:   "2025-01-01T00:00:00Z",
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ServerEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != s.Name || decoded.IP != s.IP || len(decoded.Protocols) != 2 {
		t.Error("JSON roundtrip failed for ServerEntry")
	}
}
