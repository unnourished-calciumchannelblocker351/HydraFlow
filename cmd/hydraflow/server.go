package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ServerEntry represents a remote server in multi-server setup.
type ServerEntry struct {
	Name      string   `json:"name"`
	IP        string   `json:"ip"`
	APIKey    string   `json:"api_key"`
	Protocols []string `json:"protocols,omitempty"`
	AddedAt   string   `json:"added_at"`
}

// cmdServer handles all server management subcommands.
func cmdServer() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow server <add|list|health> [args]\n")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "add":
		cmdServerAdd()
	case "list", "ls":
		cmdServerList()
	case "health", "check":
		cmdServerHealth()
	default:
		fmt.Fprintf(os.Stderr, "unknown server command: %s\n", os.Args[2])
		fmt.Fprintf(os.Stderr, "usage: hydraflow server <add|list|health> [args]\n")
		os.Exit(1)
	}
}

func cmdServerAdd() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow server add <ip> <api_key>\n")
		os.Exit(1)
	}

	ip := os.Args[3]
	apiKey := os.Args[4]

	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	serversFile := getServersFile(cfg)

	servers, err := loadServers(serversFile)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error loading servers: %v\n", err)
		os.Exit(1)
	}

	// Check for duplicate.
	for _, s := range servers {
		if s.IP == ip {
			fmt.Fprintf(os.Stderr, "server %s already exists\n", ip)
			os.Exit(1)
		}
	}

	// Generate a name.
	name := fmt.Sprintf("server-%d", len(servers)+1)
	if n := getFlagValue("--name"); n != "" {
		name = n
	}

	entry := ServerEntry{
		Name:    name,
		IP:      ip,
		APIKey:  apiKey,
		AddedAt: time.Now().Format(time.RFC3339),
	}

	servers = append(servers, entry)

	if err := saveServers(servers, serversFile); err != nil {
		fmt.Fprintf(os.Stderr, "error saving servers: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Server added:\n")
	fmt.Printf("  Name: %s\n", name)
	fmt.Printf("  IP:   %s\n", ip)
	fmt.Printf("\n")
	fmt.Printf("Run 'hydraflow server health' to check connectivity.\n")
}

func cmdServerList() {
	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	serversFile := getServersFile(cfg)
	servers, err := loadServers(serversFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No servers configured. Add one with: hydraflow server add <ip> <key>")
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(servers) == 0 {
		fmt.Println("No servers configured. Add one with: hydraflow server add <ip> <key>")
		return
	}

	fmt.Printf("%-15s %-20s %-25s %s\n", "NAME", "IP", "PROTOCOLS", "ADDED")
	fmt.Printf("%-15s %-20s %-25s %s\n", "----", "--", "---------", "-----")

	for _, s := range servers {
		protocols := "-"
		if len(s.Protocols) > 0 {
			protocols = ""
			for i, p := range s.Protocols {
				if i > 0 {
					protocols += ", "
				}
				protocols += p
			}
		}
		fmt.Printf("%-15s %-20s %-25s %s\n", s.Name, s.IP, protocols, s.AddedAt)
	}

	fmt.Printf("\nTotal: %d servers\n", len(servers))
}

func cmdServerHealth() {
	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	serversFile := getServersFile(cfg)
	servers, err := loadServers(serversFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No servers configured.")
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(servers) == 0 {
		fmt.Println("No servers configured.")
		return
	}

	fmt.Printf("Checking health of %d servers...\n\n", len(servers))

	// Common ports to check.
	ports := []struct {
		port     int
		protocol string
	}{
		{443, "reality/tls"},
		{8443, "alt-tls"},
		{80, "http"},
		{2053, "hysteria2"},
	}

	var wg sync.WaitGroup
	type result struct {
		server   string
		name     string
		port     int
		protocol string
		up       bool
		latency  time.Duration
		err      string
	}

	results := make([]result, 0, len(servers)*len(ports))
	var mu sync.Mutex

	for _, s := range servers {
		for _, p := range ports {
			wg.Add(1)
			go func(srv ServerEntry, port int, proto string) {
				defer wg.Done()

				addr := net.JoinHostPort(srv.IP, fmt.Sprintf("%d", port))
				start := time.Now()

				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				r := result{
					server:   srv.IP,
					name:     srv.Name,
					port:     port,
					protocol: proto,
				}

				if err != nil {
					r.up = false
					r.err = err.Error()
					r.latency = time.Since(start)
				} else {
					// Try TLS handshake on TLS ports.
					if port == 443 || port == 8443 {
						tlsConn := tls.Client(conn, &tls.Config{
							InsecureSkipVerify: true,
						})
						tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
						if tlsErr := tlsConn.Handshake(); tlsErr != nil {
							r.up = true // TCP up, TLS may vary
							r.err = "tls: " + tlsErr.Error()
						} else {
							r.up = true
						}
						tlsConn.Close()
					} else {
						conn.Close()
						r.up = true
					}
					r.latency = time.Since(start)
				}

				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(s, p.port, p.protocol)
		}
	}

	wg.Wait()

	// Display results grouped by server.
	fmt.Printf("%-15s %-20s %-6s %-14s %-8s %s\n", "NAME", "IP", "PORT", "PROTOCOL", "STATUS", "LATENCY")
	fmt.Printf("%-15s %-20s %-6s %-14s %-8s %s\n", "----", "--", "----", "--------", "------", "-------")

	for _, r := range results {
		status := "UP"
		if !r.up {
			status = "DOWN"
		}

		latStr := fmt.Sprintf("%dms", r.latency.Milliseconds())

		errInfo := ""
		if r.err != "" {
			errInfo = "  (" + r.err + ")"
		}

		fmt.Printf("%-15s %-20s %-6d %-14s %-8s %s%s\n",
			r.name, r.server, r.port, r.protocol, status, latStr, errInfo)
	}
}

// --- Server file helpers ---

func loadServers(path string) ([]ServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var servers []ServerEntry
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("parse servers: %w", err)
	}

	return servers, nil
}

func saveServers(servers []ServerEntry, path string) error {
	data, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal servers: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create dir: %w", err)
		}
	}

	// Atomic write: create a temp file in the same directory, write, then rename.
	tmp, err := os.CreateTemp(dir, ".servers-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0640); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}

	return nil
}

func getServersFile(_ interface{}) string {
	return "/etc/hydraflow/servers.json"
}
