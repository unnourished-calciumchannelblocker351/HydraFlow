// hf-server is the HydraFlow server binary that runs multi-protocol
// inbound listeners with smart subscription support.
//
// Usage:
//
//	hf-server --config /etc/hydraflow/config.yml     Start the server
//	hf-server --install                               One-command setup
//	hf-server --generate-sub                          Generate subscription
//	hf-server --version                               Print version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Evr1kys/HydraFlow/server"
	"github.com/Evr1kys/HydraFlow/subscription"

	"gopkg.in/yaml.v3"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Define flags.
	configPath := flag.String("config", "/etc/hydraflow/config.yml", "Path to configuration file")
	install := flag.Bool("install", false, "Run one-command server installation")
	installIP := flag.String("install-ip", "", "Override server IP for installation")
	installDir := flag.String("install-dir", "/etc/hydraflow", "Config directory for installation")
	generateSub := flag.Bool("generate-sub", false, "Generate subscription config and print to stdout")
	showVersion := flag.Bool("version", false, "Print version information")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	healthAddr := flag.String("health-addr", "", "Override health check listen address")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "HydraFlow Server %s (built %s)\n\n", version, buildTime)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  hf-server [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  hf-server --config /etc/hydraflow/config.yml\n")
		fmt.Fprintf(os.Stderr, "  hf-server --install --install-ip 1.2.3.4\n")
		fmt.Fprintf(os.Stderr, "  hf-server --generate-sub --config /etc/hydraflow/config.yml\n")
	}
	flag.Parse()

	// Setup logger.
	level := parseLogLevel(*logLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	// Handle --version.
	if *showVersion {
		fmt.Printf("hf-server %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Handle --install.
	if *install {
		if err := runInstall(logger, *installIP, *installDir); err != nil {
			logger.Error("installation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle --generate-sub.
	if *generateSub {
		if err := runGenerateSub(logger, *configPath); err != nil {
			logger.Error("subscription generation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Default: run the server.
	if err := runServer(logger, *configPath, *healthAddr); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// runServer loads configuration and starts the HydraFlow server.
func runServer(logger *slog.Logger, configPath, healthAddr string) error {
	logger.Info("starting hf-server",
		"version", version,
		"config", configPath,
	)

	// Load server configuration.
	cfg, err := loadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if healthAddr != "" {
		cfg.HealthAddr = healthAddr
	}

	// Create server.
	srv, err := server.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Setup context with signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Handle SIGHUP for config reload.
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	go func() {
		for {
			select {
			case sig := <-sigCh:
				logger.Info("received signal, shutting down", "signal", sig)
				cancel()
				return
			case <-reloadCh:
				logger.Info("received SIGHUP, reloading configuration")
				newCfg, err := loadServerConfig(configPath)
				if err != nil {
					logger.Error("reload failed", "error", err)
					continue
				}
				if err := srv.Reload(newCfg); err != nil {
					logger.Error("reload apply failed", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start the subscription server if enabled.
	if cfg.Subscription.Enabled {
		go func() {
			if err := startSubServer(ctx, cfg, logger); err != nil {
				logger.Error("subscription server error", "error", err)
			}
		}()
	}

	// Start the main server (blocks until shutdown).
	return srv.Start(ctx)
}

// startSubServer starts the subscription HTTP server.
func startSubServer(ctx context.Context, cfg *server.ServerConfig, logger *slog.Logger) error {
	subCfg := subscription.SubServerConfig{
		Listen:    cfg.Subscription.Listen,
		Token:     cfg.Subscription.Token,
		RateLimit: 30,
	}

	subSrv, err := subscription.NewSubServer(subCfg, logger)
	if err != nil {
		return fmt.Errorf("create subscription server: %w", err)
	}

	// Create a base subscription from the server config.
	baseSub := buildSubscriptionFromConfig(cfg)
	subSrv.SetSubscription(baseSub)

	return subSrv.Start(ctx)
}

// buildSubscriptionFromConfig creates a Subscription from the server config.
func buildSubscriptionFromConfig(cfg *server.ServerConfig) *subscription.Subscription {
	sub := &subscription.Subscription{
		Version: 1,
		Server:  cfg.Listen,
		Updated: time.Now(),
		TTL:     3600,
	}

	for _, in := range cfg.Inbounds {
		pc := subscription.ProtocolConfig{
			Name:      in.Tag,
			Transport: in.Protocol,
		}

		if in.Port > 0 {
			pc.Port = in.Port
		}

		// Extract protocol-specific settings.
		if in.Settings != nil {
			if sni, ok := in.Settings["sni"].(string); ok {
				pc.SNI = sni
				pc.Security = "reality"
			}
			if pubKey, ok := in.Settings["public_key"].(string); ok {
				pc.PublicKey = pubKey
			}
			if shortID, ok := in.Settings["short_id"].(string); ok {
				pc.ShortID = shortID
			}
			if fp, ok := in.Settings["fingerprint"].(string); ok {
				pc.Fingerprint = fp
			}
			if path, ok := in.Settings["path"].(string); ok {
				pc.Path = path
			}
			if host, ok := in.Settings["host"].(string); ok {
				pc.Host = host
			}
		}

		sub.Protocols = append(sub.Protocols, pc)
	}

	return sub
}

// runInstall performs the one-command server installation.
func runInstall(logger *slog.Logger, serverIP, installDir string) error {
	logger.Info("starting server installation",
		"version", version,
	)

	installer := server.NewInstaller(logger)

	cfg := server.InstallConfig{
		ServerIP:  serverIP,
		ConfigDir: installDir,
		Ports:     []int{443, 8443},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := installer.Install(ctx, cfg); err != nil {
		return err
	}

	logger.Info("installation complete. Start the server with:")
	fmt.Fprintf(os.Stderr, "\n  systemctl start hydraflow\n\n")
	fmt.Fprintf(os.Stderr, "Or run directly:\n")
	fmt.Fprintf(os.Stderr, "  hf-server --config %s/config.yml\n\n", installDir)

	return nil
}

// runGenerateSub generates a subscription config from the server config
// and prints it to stdout.
func runGenerateSub(logger *slog.Logger, configPath string) error {
	cfg, err := loadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	sub := buildSubscriptionFromConfig(cfg)

	data, err := sub.Marshal()
	if err != nil {
		return fmt.Errorf("marshal subscription: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

// loadServerConfig reads a ServerConfig from a YAML file.
func loadServerConfig(path string) (*server.ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg server.ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Apply defaults.
	if cfg.HealthAddr == "" {
		cfg.HealthAddr = "127.0.0.1:10085"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	return &cfg, nil
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
