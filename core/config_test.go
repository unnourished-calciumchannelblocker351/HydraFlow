package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name  string
		check func() bool
		msg   string
	}{
		{
			name:  "ProbeTimeout",
			check: func() bool { return cfg.Selection.ProbeTimeout == 5_000_000_000 },
			msg:   "expected probe timeout 5s",
		},
		{
			name:  "ProbeParallel",
			check: func() bool { return cfg.Selection.ProbeParallel == true },
			msg:   "expected parallel probes enabled",
		},
		{
			name:  "MinProbeScore",
			check: func() bool { return cfg.Selection.MinProbeScore == 0.3 },
			msg:   "expected min probe score 0.3",
		},
		{
			name:  "CheckInterval",
			check: func() bool { return cfg.Monitor.CheckInterval == 10_000_000_000 },
			msg:   "expected check interval 10s",
		},
		{
			name:  "LatencyThreshold",
			check: func() bool { return cfg.Monitor.LatencyThreshold == 2_000_000_000 },
			msg:   "expected latency threshold 2s",
		},
		{
			name:  "FailureThreshold",
			check: func() bool { return cfg.Monitor.FailureThreshold == 3 },
			msg:   "expected failure threshold 3",
		},
		{
			name:  "TelemetryDisabled",
			check: func() bool { return cfg.Telemetry.Enabled == false },
			msg:   "expected telemetry disabled by default",
		},
		{
			name:  "LogLevel",
			check: func() bool { return cfg.LogLevel == "info" },
			msg:   "expected log level info",
		},
		{
			name:  "TelemetryEndpoint empty",
			check: func() bool { return cfg.Telemetry.Endpoint == "" },
			msg:   "expected empty telemetry endpoint",
		},
		{
			name:  "SubscriptionURL empty",
			check: func() bool { return cfg.Subscription.URL == "" },
			msg:   "expected empty subscription URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check() {
				t.Error(tt.msg)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErr  bool
		validate func(*testing.T, *Config)
	}{
		{
			name: "minimal config",
			content: `
log_level: debug
`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LogLevel != "debug" {
					t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
				}
			},
		},
		{
			name: "full config",
			content: `
log_level: warn
selection:
  probe_timeout: 10s
  probe_parallel: false
  min_probe_score: 0.5
  prefer_low_latency: true
monitor:
  check_interval: 30s
  latency_threshold: 5s
  failure_threshold: 5
subscription:
  url: "https://example.com/sub"
  refresh_interval: "1h"
  token: "secret123"
telemetry:
  enabled: true
  endpoint: "https://telemetry.example.com"
  report_interval: "30m"
`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.LogLevel != "warn" {
					t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
				}
				if cfg.Selection.ProbeTimeout != 10*time.Second {
					t.Errorf("ProbeTimeout = %v, want 10s", cfg.Selection.ProbeTimeout)
				}
				if cfg.Selection.ProbeParallel {
					t.Error("expected ProbeParallel = false")
				}
				if cfg.Selection.MinProbeScore != 0.5 {
					t.Errorf("MinProbeScore = %f, want 0.5", cfg.Selection.MinProbeScore)
				}
				if !cfg.Selection.PreferLowLatency {
					t.Error("expected PreferLowLatency = true")
				}
				if cfg.Monitor.CheckInterval != 30*time.Second {
					t.Errorf("CheckInterval = %v, want 30s", cfg.Monitor.CheckInterval)
				}
				if cfg.Monitor.LatencyThreshold != 5*time.Second {
					t.Errorf("LatencyThreshold = %v, want 5s", cfg.Monitor.LatencyThreshold)
				}
				if cfg.Monitor.FailureThreshold != 5 {
					t.Errorf("FailureThreshold = %d, want 5", cfg.Monitor.FailureThreshold)
				}
				if cfg.Subscription.URL != "https://example.com/sub" {
					t.Errorf("Subscription.URL = %q", cfg.Subscription.URL)
				}
				if cfg.Subscription.Token != "secret123" {
					t.Errorf("Subscription.Token = %q", cfg.Subscription.Token)
				}
				if !cfg.Telemetry.Enabled {
					t.Error("expected Telemetry.Enabled = true")
				}
				if cfg.Telemetry.Endpoint != "https://telemetry.example.com" {
					t.Errorf("Telemetry.Endpoint = %q", cfg.Telemetry.Endpoint)
				}
			},
		},
		{
			name: "overrides defaults",
			content: `
selection:
  min_probe_score: 0.8
`,
			validate: func(t *testing.T, cfg *Config) {
				// Overridden value.
				if cfg.Selection.MinProbeScore != 0.8 {
					t.Errorf("MinProbeScore = %f, want 0.8", cfg.Selection.MinProbeScore)
				}
				// Default values should still be set.
				if cfg.Selection.ProbeTimeout != 5_000_000_000 {
					t.Errorf("ProbeTimeout should retain default, got %v", cfg.Selection.ProbeTimeout)
				}
				if cfg.Monitor.FailureThreshold != 3 {
					t.Errorf("FailureThreshold should retain default, got %d", cfg.Monitor.FailureThreshold)
				}
			},
		},
		{
			name: "empty config uses defaults",
			content: `
# Empty config
`,
			validate: func(t *testing.T, cfg *Config) {
				def := DefaultConfig()
				if cfg.Selection.ProbeTimeout != def.Selection.ProbeTimeout {
					t.Error("empty config should use default ProbeTimeout")
				}
				if cfg.LogLevel != def.LogLevel {
					t.Error("empty config should use default LogLevel")
				}
			},
		},
		{
			name:    "invalid YAML",
			content: "{{{{invalid yaml",
			wantErr: true,
		},
		{
			name: "subscription fields",
			content: `
subscription:
  url: "https://sub.example.com/my-sub"
  refresh_interval: "6h"
  token: "tok_abc123"
`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Subscription.URL != "https://sub.example.com/my-sub" {
					t.Errorf("Subscription.URL = %q", cfg.Subscription.URL)
				}
				if cfg.Subscription.RefreshInterval != "6h" {
					t.Errorf("RefreshInterval = %q, want %q", cfg.Subscription.RefreshInterval, "6h")
				}
				if cfg.Subscription.Token != "tok_abc123" {
					t.Errorf("Token = %q", cfg.Subscription.Token)
				}
			},
		},
		{
			name: "telemetry config",
			content: `
telemetry:
  enabled: true
  endpoint: "https://t.example.com/report"
  report_interval: "15m"
`,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Telemetry.Enabled {
					t.Error("expected Telemetry enabled")
				}
				if cfg.Telemetry.Endpoint != "https://t.example.com/report" {
					t.Errorf("Endpoint = %q", cfg.Telemetry.Endpoint)
				}
				if cfg.Telemetry.ReportInterval != "15m" {
					t.Errorf("ReportInterval = %q", cfg.Telemetry.ReportInterval)
				}
			},
		},
		{
			name: "monitor config only",
			content: `
monitor:
  failure_threshold: 10
`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Monitor.FailureThreshold != 10 {
					t.Errorf("FailureThreshold = %d, want 10", cfg.Monitor.FailureThreshold)
				}
				// Check defaults preserved.
				if cfg.Monitor.CheckInterval != 10_000_000_000 {
					t.Errorf("CheckInterval should be default, got %v", cfg.Monitor.CheckInterval)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "config.yml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write temp config: %v", err)
			}

			cfg, err := LoadConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig() error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestDefaultConfigNotNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
}

func TestConfigStructFields(t *testing.T) {
	// Verify that Config struct has the expected fields by creating
	// a config with all fields populated.
	cfg := Config{
		Selection: SelectionConfig{
			ProbeTimeout:     5 * time.Second,
			ProbeParallel:    true,
			MinProbeScore:    0.5,
			PreferLowLatency: true,
		},
		Monitor: MonitorConfig{
			CheckInterval:    10 * time.Second,
			LatencyThreshold: 2 * time.Second,
			FailureThreshold: 3,
		},
		Subscription: SubscriptionConfig{
			URL:             "https://example.com",
			RefreshInterval: "1h",
			Token:           "secret",
		},
		Telemetry: TelemetryConfig{
			Enabled:        true,
			Endpoint:       "https://telemetry.example.com",
			ReportInterval: "5m",
		},
		LogLevel: "debug",
	}

	if cfg.LogLevel != "debug" {
		t.Error("field assignment failed")
	}
}

func TestLoadConfigMultipleTimes(t *testing.T) {
	content := `log_level: debug`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Load the same config multiple times to ensure no state pollution.
	for i := 0; i < 5; i++ {
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("iteration %d: LoadConfig() error: %v", i, err)
		}
		if cfg.LogLevel != "debug" {
			t.Errorf("iteration %d: LogLevel = %q, want %q", i, cfg.LogLevel, "debug")
		}
		// Defaults should still apply.
		if cfg.Selection.ProbeTimeout != 5_000_000_000 {
			t.Errorf("iteration %d: ProbeTimeout lost default", i)
		}
	}
}
