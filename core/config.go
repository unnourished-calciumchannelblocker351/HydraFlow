package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the HydraFlow engine.
type Config struct {
	// Selection controls protocol selection behavior.
	Selection SelectionConfig `yaml:"selection"`

	// Monitor controls connection health monitoring.
	Monitor MonitorConfig `yaml:"monitor"`

	// Subscription configures the smart subscription system.
	Subscription SubscriptionConfig `yaml:"subscription"`

	// Telemetry controls anonymous usage reporting.
	Telemetry TelemetryConfig `yaml:"telemetry"`

	// LogLevel sets the logging verbosity (debug, info, warn, error).
	LogLevel string `yaml:"log_level"`
}

// SubscriptionConfig controls the subscription system.
type SubscriptionConfig struct {
	// URL is the subscription endpoint to fetch protocol configs from.
	URL string `yaml:"url"`

	// RefreshInterval is how often to check for config updates.
	RefreshInterval string `yaml:"refresh_interval"`

	// Token is the authentication token for the subscription.
	Token string `yaml:"token"`
}

// TelemetryConfig controls anonymous telemetry reporting.
type TelemetryConfig struct {
	// Enabled controls whether telemetry is sent.
	Enabled bool `yaml:"enabled"`

	// Endpoint is the URL to report telemetry to.
	Endpoint string `yaml:"endpoint"`

	// ReportInterval is how often to send reports.
	ReportInterval string `yaml:"report_interval"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Selection: SelectionConfig{
			ProbeTimeout:  5_000_000_000, // 5s
			ProbeParallel: true,
			MinProbeScore: 0.3,
		},
		Monitor: MonitorConfig{
			CheckInterval:    10_000_000_000, // 10s
			LatencyThreshold: 2_000_000_000,  // 2s
			FailureThreshold: 3,
		},
		Telemetry: TelemetryConfig{
			Enabled: false,
		},
		LogLevel: "info",
	}
}

// LoadConfig reads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}
