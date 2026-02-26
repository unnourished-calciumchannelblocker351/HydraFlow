// hydraflow-map is the HydraFlow censorship monitoring server that collects
// anonymous blocking reports and serves a public dashboard showing which
// protocols are blocked on which ISPs in which countries.
//
// Usage:
//
//	hydraflow-map                                  Start with defaults
//	hydraflow-map --listen :8080                   Custom listen address
//	hydraflow-map --data-dir /var/lib/hydraflow-map  Custom data directory
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Evr1kys/HydraFlow/blockmap"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "/var/lib/hydraflow-map", "Data directory for persistent storage")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	showVersion := flag.Bool("version", false, "Print version information")
	noSeed := flag.Bool("no-seed", false, "Do not load seed data on first run")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "HydraFlow Censorship Monitor %s (built %s)\n\n", version, buildTime)
		fmt.Fprintf(os.Stderr, "Public dashboard showing real-time protocol blocking data.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  hydraflow-map [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEndpoints:\n")
		fmt.Fprintf(os.Stderr, "  GET  /                           Web dashboard\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/map                 Full blocking map\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/map/{country}       Country data\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/map/{country}/{isp} ISP data\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/stats               Global statistics\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/timeline/{protocol} Protocol timeline\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/v1/countries           Country list\n")
		fmt.Fprintf(os.Stderr, "  POST /api/v1/report              Submit report\n")
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("hydraflow-map %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	level := parseLogLevel(*logLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	cfg := blockmap.ServerConfig{
		Listen:  *listen,
		DataDir: *dataDir,
		NoSeed:  *noSeed,
	}

	srv, err := blockmap.NewMapServer(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize map server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	logger.Info("starting HydraFlow censorship monitor",
		"version", version,
		"listen", *listen,
		"data-dir", *dataDir,
	)

	if err := srv.Start(ctx); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

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
