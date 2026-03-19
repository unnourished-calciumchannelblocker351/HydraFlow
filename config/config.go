// Package config provides the central configuration for HydraFlow.
// It reads YAML config from /etc/hydraflow/hydraflow.yaml and provides
// typed access to all settings across modes (standalone, 3xui, marzban).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath  = "/etc/hydraflow/hydraflow.yaml"
	DefaultUsersFile   = "/etc/hydraflow/users.json"
	DefaultServersFile = "/etc/hydraflow/servers.json"
	DefaultListen      = "0.0.0.0:10086"
)

// Mode represents the operating mode of HydraFlow.
type Mode string

const (
	ModeStandalone Mode = "standalone"
	Mode3XUI       Mode = "3xui"
	ModeMarzban    Mode = "marzban"
)

// Config is the top-level HydraFlow configuration.
type Config struct {
	Mode       Mode   `yaml:"mode"`
	Listen     string `yaml:"listen"`
	AdminToken string `yaml:"admin_token"`
	LogLevel   string `yaml:"log_level"`

	Standalone StandaloneConfig `yaml:"standalone"`
	XUI        XUIConfig        `yaml:"xui"`
	Marzban    MarzbanConfig    `yaml:"marzban"`

	Servers []ServerEntry `yaml:"servers"`
	CDN     CDNConfig     `yaml:"cdn"`
}

// StandaloneConfig holds settings for standalone mode with built-in xray management.
type StandaloneConfig struct {
	XrayBinary string `yaml:"xray_binary"`
	XrayConfig string `yaml:"xray_config"`
	UsersFile  string `yaml:"users_file"`
}

// XUIConfig holds settings for 3x-ui integration mode.
type XUIConfig struct {
	Database     string `yaml:"database"`
	PollInterval int    `yaml:"poll_interval"` // seconds
}

// MarzbanConfig holds settings for Marzban integration mode.
type MarzbanConfig struct {
	APIURL   string `yaml:"api_url"`
	APIToken string `yaml:"api_token"`
}

// ServerEntry represents a remote server in multi-server setup.
type ServerEntry struct {
	Name      string   `yaml:"name"`
	IP        string   `yaml:"ip"`
	APIKey    string   `yaml:"api_key"`
	Protocols []string `yaml:"protocols"`
}

// CDNConfig holds CDN-related settings.
type CDNConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Domain   string `yaml:"domain"`
	Provider string `yaml:"provider"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:     ModeStandalone,
		Listen:   DefaultListen,
		LogLevel: "info",
		Standalone: StandaloneConfig{
			XrayBinary: "/usr/local/bin/xray",
			XrayConfig: "/etc/hydraflow/xray-config.json",
			UsersFile:  DefaultUsersFile,
		},
		XUI: XUIConfig{
			Database:     "/etc/x-ui/x-ui.db",
			PollInterval: 30,
		},
		Marzban: MarzbanConfig{
			APIURL: "http://localhost:8000",
		},
	}
}

// Load reads the configuration from a YAML file.
// If the file does not exist, it returns the default config.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Validate mode.
	switch cfg.Mode {
	case ModeStandalone, Mode3XUI, ModeMarzban:
		// valid
	case "":
		cfg.Mode = ModeStandalone
	default:
		return nil, fmt.Errorf("unknown mode %q (must be standalone, 3xui, or marzban)", cfg.Mode)
	}

	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}

	if cfg.AdminToken == "" {
		cfg.AdminToken = generateToken()
	}

	return cfg, nil
}

// Save writes the configuration to a YAML file.
func Save(cfg *Config, path string) error {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.MkdirAll(dirOf(path), 0750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(path, data, 0640); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}

	return nil
}

// generateToken creates a random hex token.
func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "change-me-please"
	}
	return hex.EncodeToString(b)
}

// dirOf returns the directory portion of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
