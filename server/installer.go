package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Installer handles one-command server setup: key generation,
// SNI discovery, config generation, systemd unit creation, and
// firewall configuration.
type Installer struct {
	logger    *slog.Logger
	serverIP  string
	configDir string
	binPath   string
}

// InstallConfig holds the parameters for server installation.
type InstallConfig struct {
	// ServerIP overrides auto-detected server IP.
	ServerIP string

	// ConfigDir is the directory for configuration files.
	ConfigDir string

	// BinPath is the path to the hf-server binary.
	BinPath string

	// Ports are the ports to configure for inbound listeners.
	Ports []int

	// SkipFirewall skips firewall rule setup.
	SkipFirewall bool

	// SkipSystemd skips systemd unit creation.
	SkipSystemd bool
}

// ASNInfo contains information about an IP address's autonomous system.
type ASNInfo struct {
	ASN          int    `json:"asn"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	ISP          string `json:"isp"`
}

// X25519KeyPair holds a Reality x25519 key pair.
type X25519KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// SNICandidate represents a domain evaluated for Reality SNI usage.
type SNICandidate struct {
	Domain    string
	Latency   time.Duration
	TLS13     bool
	H2        bool
	SameASN   bool
	NearbyASN bool
	Score     float64
}

// NewInstaller creates an installer with the given logger.
func NewInstaller(logger *slog.Logger) *Installer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Installer{
		logger:    logger,
		configDir: "/etc/hydraflow",
		binPath:   "/usr/local/bin/hf-server",
	}
}

// Install performs a full server installation.
func (inst *Installer) Install(ctx context.Context, cfg InstallConfig) error {
	inst.logger.Info("starting HydraFlow server installation")

	// Apply config overrides.
	if cfg.ConfigDir != "" {
		inst.configDir = cfg.ConfigDir
	}
	if cfg.BinPath != "" {
		inst.binPath = cfg.BinPath
	}

	// Step 1: Detect server IP.
	serverIP := cfg.ServerIP
	if serverIP == "" {
		var err error
		serverIP, err = inst.detectServerIP(ctx)
		if err != nil {
			return fmt.Errorf("detect server IP: %w", err)
		}
	}
	inst.serverIP = serverIP
	inst.logger.Info("server IP detected", "ip", serverIP)

	// Step 2: Detect hosting provider via ASN lookup.
	asnInfo, err := inst.DetectHostingProvider(ctx, serverIP)
	if err != nil {
		inst.logger.Warn("ASN lookup failed, continuing without provider info", "error", err)
		asnInfo = &ASNInfo{Organization: "unknown"}
	}
	inst.logger.Info("hosting provider detected",
		"asn", asnInfo.ASN,
		"org", asnInfo.Organization,
		"country", asnInfo.Country,
	)

	// Step 3: Generate x25519 key pair for Reality.
	keys, err := inst.GenerateX25519Keys()
	if err != nil {
		return fmt.Errorf("generate x25519 keys: %w", err)
	}
	inst.logger.Info("x25519 key pair generated",
		"public_key", keys.PublicKey,
	)

	// Step 4: Find optimal SNI domains.
	inst.logger.Info("discovering optimal SNI domains...")
	sniDomains, err := inst.FindOptimalSNI(ctx, serverIP, asnInfo)
	if err != nil {
		inst.logger.Warn("SNI discovery failed, using defaults", "error", err)
		sniDomains = []SNICandidate{
			{Domain: "www.microsoft.com", Score: 0.5},
			{Domain: "www.google.com", Score: 0.4},
		}
	}

	bestSNI := "www.microsoft.com"
	if len(sniDomains) > 0 {
		bestSNI = sniDomains[0].Domain
	}
	inst.logger.Info("best SNI selected", "domain", bestSNI)

	// Step 5: Generate short ID for Reality.
	shortID, err := generateShortID()
	if err != nil {
		return fmt.Errorf("generate short ID: %w", err)
	}

	// Step 6: Create config directory.
	if err := os.MkdirAll(inst.configDir, 0750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Step 7: Generate initial configuration.
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = []int{443, 8443}
	}

	configData := inst.GenerateConfig(keys, bestSNI, shortID, serverIP, ports)
	configPath := filepath.Join(inst.configDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(configData), 0640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	inst.logger.Info("configuration written", "path", configPath)

	// Step 8: Create systemd unit file.
	if !cfg.SkipSystemd && runtime.GOOS == "linux" {
		if err := inst.CreateSystemdUnit(); err != nil {
			inst.logger.Warn("failed to create systemd unit", "error", err)
		} else {
			inst.logger.Info("systemd unit created")
		}
	}

	// Step 9: Setup firewall rules.
	if !cfg.SkipFirewall && runtime.GOOS == "linux" {
		if err := inst.SetupFirewall(ports); err != nil {
			inst.logger.Warn("failed to setup firewall", "error", err)
		} else {
			inst.logger.Info("firewall rules configured")
		}
	}

	inst.logger.Info("installation complete",
		"config", configPath,
		"sni", bestSNI,
		"public_key", keys.PublicKey,
	)

	return nil
}

// detectServerIP determines the server's public IP address.
func (inst *Installer) detectServerIP(ctx context.Context) (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, svc := range services {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/8.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("could not determine public IP from any service")
}

// DetectHostingProvider performs an ASN lookup to identify the hosting provider.
func (inst *Installer) DetectHostingProvider(ctx context.Context, ip string) (*ASNInfo, error) {
	// Use ip-api.com for free ASN lookups.
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org,country,isp,query", ip)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ASN lookup request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read ASN response: %w", err)
	}

	var raw struct {
		AS      string `json:"as"`
		Org     string `json:"org"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
		Query   string `json:"query"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse ASN response: %w", err)
	}

	asn := 0
	if parts := strings.SplitN(raw.AS, " ", 2); len(parts) > 0 {
		asPart := strings.TrimPrefix(parts[0], "AS")
		fmt.Sscanf(asPart, "%d", &asn)
	}

	return &ASNInfo{
		ASN:          asn,
		Organization: raw.Org,
		Country:      raw.Country,
		ISP:          raw.ISP,
	}, nil
}

// GenerateX25519Keys generates a new x25519 key pair for Reality protocol.
func (inst *Installer) GenerateX25519Keys() (*X25519KeyPair, error) {
	// Generate a random 32-byte private key.
	var privateKey [32]byte

	// Use ed25519 seed generation for high-quality randomness, then
	// extract 32 bytes for x25519.
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate random seed: %w", err)
	}
	copy(privateKey[:], seed[:32])

	// Clamp the private key per x25519 spec.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive the public key.
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &X25519KeyPair{
		PrivateKey: hex.EncodeToString(privateKey[:]),
		PublicKey:  hex.EncodeToString(publicKey),
	}, nil
}

// FindOptimalSNI discovers suitable SNI domains for the Reality protocol.
// It evaluates candidates based on TLS 1.3 support, H2, latency,
// and ASN proximity.
func (inst *Installer) FindOptimalSNI(ctx context.Context, serverIP string, asnInfo *ASNInfo) ([]SNICandidate, error) {
	// Default candidate domains known to work well with Reality.
	candidates := []string{
		"www.microsoft.com",
		"www.google.com",
		"www.apple.com",
		"www.amazon.com",
		"cloudflare.com",
		"www.mozilla.org",
		"www.samsung.com",
		"www.nvidia.com",
		"www.intel.com",
		"www.amd.com",
		"www.dell.com",
		"www.hp.com",
		"www.ibm.com",
		"www.cisco.com",
		"www.oracle.com",
		"www.adobe.com",
		"www.spotify.com",
		"www.twitch.tv",
		"www.reddit.com",
		"www.stackoverflow.com",
		"www.github.com",
		"www.gitlab.com",
		"www.docker.com",
		"www.elastic.co",
		"www.grafana.com",
	}

	type result struct {
		candidate SNICandidate
		err       error
	}

	results := make(chan result, len(candidates))
	sem := make(chan struct{}, 10) // Limit concurrency.

	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for _, domain := range candidates {
		sem <- struct{}{}
		go func(domain string) {
			defer func() { <-sem }()
			c, err := inst.evaluateSNICandidate(testCtx, domain, serverIP, asnInfo)
			results <- result{candidate: c, err: err}
		}(domain)
	}

	var evaluated []SNICandidate
	for i := 0; i < len(candidates); i++ {
		r := <-results
		if r.err != nil {
			inst.logger.Debug("SNI candidate evaluation failed",
				"domain", r.candidate.Domain,
				"error", r.err,
			)
			continue
		}
		if r.candidate.TLS13 {
			evaluated = append(evaluated, r.candidate)
		}
	}

	// Sort by composite score (higher is better).
	sort.Slice(evaluated, func(i, j int) bool {
		return evaluated[i].Score > evaluated[j].Score
	})

	if len(evaluated) == 0 {
		return nil, fmt.Errorf("no suitable SNI candidates found")
	}

	// Return top 5.
	if len(evaluated) > 5 {
		evaluated = evaluated[:5]
	}

	return evaluated, nil
}

// evaluateSNICandidate tests a single domain for Reality SNI suitability.
func (inst *Installer) evaluateSNICandidate(ctx context.Context, domain, serverIP string, asnInfo *ASNInfo) (SNICandidate, error) {
	candidate := SNICandidate{Domain: domain}

	// Resolve the domain to check ASN proximity.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return candidate, fmt.Errorf("resolve %s: %w", domain, err)
	}

	// Check if any resolved IP is in the same ASN.
	if asnInfo != nil && len(ips) > 0 {
		for _, ip := range ips {
			domainASN, err := inst.lookupASN(ctx, ip.IP.String())
			if err != nil {
				continue
			}
			if domainASN == asnInfo.ASN {
				candidate.SameASN = true
				break
			}
			// Consider "nearby" if the ASN difference is small
			// (same provider, different region).
			diff := domainASN - asnInfo.ASN
			if diff < 0 {
				diff = -diff
			}
			if diff < 100 {
				candidate.NearbyASN = true
			}
		}
	}

	// Test TLS handshake to measure latency and check TLS 1.3 + H2 support.
	start := time.Now()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return candidate, fmt.Errorf("TLS handshake with %s: %w", domain, err)
	}
	defer conn.Close()

	candidate.Latency = time.Since(start)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return candidate, fmt.Errorf("not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	candidate.TLS13 = state.Version == tls.VersionTLS13
	candidate.H2 = state.NegotiatedProtocol == "h2"

	// Compute composite score.
	candidate.Score = inst.scoreSNICandidate(candidate)

	return candidate, nil
}

// scoreSNICandidate computes a composite score for an SNI candidate.
func (inst *Installer) scoreSNICandidate(c SNICandidate) float64 {
	score := 0.0

	// TLS 1.3 is required.
	if !c.TLS13 {
		return 0
	}
	score += 0.3

	// H2 support is preferred.
	if c.H2 {
		score += 0.2
	}

	// Same ASN is ideal for Reality.
	if c.SameASN {
		score += 0.3
	} else if c.NearbyASN {
		score += 0.1
	}

	// Lower latency is better (normalize to 0-0.2 range).
	if c.Latency > 0 {
		latencyMs := float64(c.Latency.Milliseconds())
		if latencyMs < 50 {
			score += 0.2
		} else if latencyMs < 100 {
			score += 0.15
		} else if latencyMs < 200 {
			score += 0.1
		} else if latencyMs < 500 {
			score += 0.05
		}
	}

	return score
}

// lookupASN performs a simple ASN lookup for a single IP.
func (inst *Installer) lookupASN(ctx context.Context, ip string) (int, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=as", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var raw struct {
		AS string `json:"as"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return 0, err
	}

	var asn int
	parts := strings.SplitN(raw.AS, " ", 2)
	if len(parts) > 0 {
		asPart := strings.TrimPrefix(parts[0], "AS")
		fmt.Sscanf(asPart, "%d", &asn)
	}

	return asn, nil
}

// GenerateConfig creates the initial server YAML configuration.
func (inst *Installer) GenerateConfig(keys *X25519KeyPair, sni, shortID, serverIP string, ports []int) string {
	const configTemplate = `# HydraFlow Server Configuration
# Generated by hf-server --install

listen: "0.0.0.0"
health_addr: "127.0.0.1:10085"
log_level: "info"

inbounds:
  - tag: "reality-vision"
    protocol: "reality"
    port: {{index .Ports 0}}
    settings:
      private_key: "{{.PrivateKey}}"
      public_key: "{{.PublicKey}}"
      short_id: "{{.ShortID}}"
      sni: "{{.SNI}}"
      dest: "{{.SNI}}:443"
      flow: "xtls-rprx-vision"
      fingerprint: "chrome"

{{- if gt (len .Ports) 1}}
  - tag: "xhttp-cdn"
    protocol: "xhttp"
    port: {{index .Ports 1}}
    settings:
      path: "/{{.RandomPath}}"
      host: "{{.ServerIP}}"
      cdn_compatible: true
{{- end}}

subscription:
  enabled: true
  listen: "127.0.0.1:10086"
  token: "{{.SubToken}}"
`

	randomPath, _ := generateRandomHex(8)
	subToken, _ := generateRandomHex(16)

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		// Fallback to simple string replacement if template fails.
		inst.logger.Error("template parse error", "error", err)
		return ""
	}

	data := map[string]interface{}{
		"Ports":      ports,
		"PrivateKey": keys.PrivateKey,
		"PublicKey":  keys.PublicKey,
		"ShortID":    shortID,
		"SNI":        sni,
		"ServerIP":   serverIP,
		"RandomPath": randomPath,
		"SubToken":   subToken,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		inst.logger.Error("template execute error", "error", err)
		return ""
	}

	return buf.String()
}

// CreateSystemdUnit generates and writes the systemd service file.
func (inst *Installer) CreateSystemdUnit() error {
	unit := GenerateSystemdUnit(inst.binPath, inst.configDir)

	unitPath := "/etc/systemd/system/hydraflow.service"
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	// Reload systemd and enable the service.
	commands := []struct {
		name string
		args []string
	}{
		{"systemctl", []string{"daemon-reload"}},
		{"systemctl", []string{"enable", "hydraflow.service"}},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd.name, cmd.args...).Run(); err != nil {
			return fmt.Errorf("run %s %v: %w", cmd.name, cmd.args, err)
		}
	}

	return nil
}

// GenerateSystemdUnit returns the content of a hardened systemd unit file.
func GenerateSystemdUnit(binPath, configDir string) string {
	return fmt.Sprintf(`[Unit]
Description=HydraFlow - Adaptive Multi-Protocol Proxy Server
Documentation=https://github.com/Evr1kys/HydraFlow
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
ExecStart=%s --config %s/config.yml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true

# Allow binding to privileged ports.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# File system access
ReadWritePaths=%s
ReadOnlyPaths=/etc/ssl/certs /usr/share/ca-certificates

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hydraflow

[Install]
WantedBy=multi-user.target
`, binPath, configDir, configDir)
}

// SetupFirewall configures firewall rules for the given ports.
// Supports both ufw and firewalld.
func (inst *Installer) SetupFirewall(ports []int) error {
	// Detect firewall manager.
	if _, err := exec.LookPath("ufw"); err == nil {
		return inst.setupUFW(ports)
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return inst.setupFirewalld(ports)
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return inst.setupIPTables(ports)
	}

	return fmt.Errorf("no supported firewall manager found (ufw, firewalld, iptables)")
}

func (inst *Installer) setupUFW(ports []int) error {
	for _, port := range ports {
		// Allow TCP.
		if err := exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", port)).Run(); err != nil {
			return fmt.Errorf("ufw allow %d/tcp: %w", port, err)
		}
		// Allow UDP (for QUIC/Hysteria2).
		if err := exec.Command("ufw", "allow", fmt.Sprintf("%d/udp", port)).Run(); err != nil {
			return fmt.Errorf("ufw allow %d/udp: %w", port, err)
		}
	}

	inst.logger.Info("ufw rules added", "ports", ports)
	return nil
}

func (inst *Installer) setupFirewalld(ports []int) error {
	for _, port := range ports {
		tcp := fmt.Sprintf("%d/tcp", port)
		udp := fmt.Sprintf("%d/udp", port)
		if err := exec.Command("firewall-cmd", "--permanent", "--add-port="+tcp).Run(); err != nil {
			return fmt.Errorf("firewalld add %s: %w", tcp, err)
		}
		if err := exec.Command("firewall-cmd", "--permanent", "--add-port="+udp).Run(); err != nil {
			return fmt.Errorf("firewalld add %s: %w", udp, err)
		}
	}

	if err := exec.Command("firewall-cmd", "--reload").Run(); err != nil {
		return fmt.Errorf("firewalld reload: %w", err)
	}

	inst.logger.Info("firewalld rules added", "ports", ports)
	return nil
}

func (inst *Installer) setupIPTables(ports []int) error {
	for _, port := range ports {
		portStr := fmt.Sprintf("%d", port)

		// TCP rule.
		if err := exec.Command("iptables",
			"-A", "INPUT", "-p", "tcp", "--dport", portStr,
			"-j", "ACCEPT",
		).Run(); err != nil {
			return fmt.Errorf("iptables tcp %d: %w", port, err)
		}

		// UDP rule.
		if err := exec.Command("iptables",
			"-A", "INPUT", "-p", "udp", "--dport", portStr,
			"-j", "ACCEPT",
		).Run(); err != nil {
			return fmt.Errorf("iptables udp %d: %w", port, err)
		}
	}

	inst.logger.Info("iptables rules added", "ports", ports)
	return nil
}

// generateShortID generates a random 8-character hex short ID for Reality.
func generateShortID() (string, error) {
	return generateRandomHex(4) // 4 bytes = 8 hex chars
}

// generateRandomHex generates n random bytes and returns them as a hex string.
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
