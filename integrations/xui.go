// Package integrations provides adapters that read user and inbound data
// from external panels (3x-ui, Marzban) and convert them into HydraFlow's
// internal Node format for the smart subscription engine.
package integrations

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/smartsub"
)

// safeBase64RE matches characters valid in base64-encoded x25519 keys.
var safeBase64RE = regexp.MustCompile(`^[a-zA-Z0-9+/=_-]+$`)

// XUIProvider reads users and inbound configs from 3x-ui's SQLite database.
// It uses the sqlite3 CLI tool (no CGO required) to query the database.
// HydraFlow only READS from 3x-ui -- no write access is needed.
type XUIProvider struct {
	mu           sync.RWMutex
	dbPath       string
	pollInterval time.Duration
	logger       *slog.Logger
	serverIP     string

	nodes    []smartsub.Node
	onChange func([]smartsub.Node)
	stopCh   chan struct{}
}

// XUIConfig configures the 3x-ui integration.
type XUIConfig struct {
	DatabasePath string
	PollInterval time.Duration
	ServerIP     string
	Logger       *slog.Logger
	OnChange     func([]smartsub.Node) // called when nodes change
}

// NewXUIProvider creates a new 3x-ui integration provider.
func NewXUIProvider(cfg XUIConfig) (*XUIProvider, error) {
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "/etc/x-ui/x-ui.db"
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Verify sqlite3 is available.
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, fmt.Errorf("sqlite3 command not found: install sqlite3 for 3x-ui integration")
	}

	// Verify database exists.
	if _, err := os.Stat(cfg.DatabasePath); err != nil {
		return nil, fmt.Errorf("3x-ui database not found at %s: %w", cfg.DatabasePath, err)
	}

	return &XUIProvider{
		dbPath:       cfg.DatabasePath,
		pollInterval: cfg.PollInterval,
		logger:       cfg.Logger,
		serverIP:     cfg.ServerIP,
		onChange:     cfg.OnChange,
		stopCh:       make(chan struct{}),
	}, nil
}

// Start begins polling the 3x-ui database for changes.
func (p *XUIProvider) Start() error {
	// Do an initial read.
	if err := p.refresh(); err != nil {
		return fmt.Errorf("initial 3x-ui database read: %w", err)
	}

	// Start polling.
	go p.pollLoop()
	return nil
}

// Stop stops the polling loop.
func (p *XUIProvider) Stop() {
	close(p.stopCh)
}

// Nodes returns the current set of nodes.
func (p *XUIProvider) Nodes() []smartsub.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]smartsub.Node, len(p.nodes))
	copy(out, p.nodes)
	return out
}

func (p *XUIProvider) pollLoop() {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.refresh(); err != nil {
				p.logger.Error("3x-ui database poll failed", "error", err)
			}
		case <-p.stopCh:
			return
		}
	}
}

func (p *XUIProvider) refresh() error {
	inbounds, err := p.readInbounds()
	if err != nil {
		return fmt.Errorf("read inbounds: %w", err)
	}

	var nodes []smartsub.Node

	for _, inb := range inbounds {
		inbNodes, err := p.parseInbound(inb)
		if err != nil {
			p.logger.Warn("failed to parse inbound",
				"id", inb.ID,
				"remark", inb.Remark,
				"error", err,
			)
			continue
		}
		nodes = append(nodes, inbNodes...)
	}

	p.mu.Lock()
	changed := len(nodes) != len(p.nodes) // simplified change detection
	p.nodes = nodes
	p.mu.Unlock()

	p.logger.Info("3x-ui database refreshed",
		"inbounds", len(inbounds),
		"nodes", len(nodes),
	)

	if changed && p.onChange != nil {
		p.onChange(nodes)
	}

	return nil
}

// xuiInbound represents a row from the inbounds table.
type xuiInbound struct {
	ID             int
	UserID         int
	Up             int64
	Down           int64
	Total          int64
	Remark         string
	Enable         bool
	ExpiryTime     int64
	Listen         string
	Port           int
	Protocol       string
	Settings       string // JSON
	StreamSettings string // JSON
	Tag            string
	Sniffing       string // JSON
}

// readInbounds queries the 3x-ui database for all inbounds.
func (p *XUIProvider) readInbounds() ([]xuiInbound, error) {
	// Query using sqlite3 CLI with JSON output mode.
	query := `SELECT id, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing FROM inbounds;`

	out, err := p.execSQLite(query)
	if err != nil {
		return nil, fmt.Errorf("query inbounds: %w", err)
	}

	if strings.TrimSpace(out) == "" {
		return nil, nil
	}

	var inbounds []xuiInbound
	lines := strings.Split(strings.TrimSpace(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// sqlite3 -separator '|' output: field1|field2|...
		fields := strings.SplitN(line, "|", 15)
		if len(fields) < 15 {
			p.logger.Debug("skipping malformed inbound row", "fields", len(fields))
			continue
		}

		id, _ := strconv.Atoi(fields[0])
		userID, _ := strconv.Atoi(fields[1])
		up, _ := strconv.ParseInt(fields[2], 10, 64)
		down, _ := strconv.ParseInt(fields[3], 10, 64)
		total, _ := strconv.ParseInt(fields[4], 10, 64)
		enable := fields[6] == "1" || fields[6] == "true"
		expiryTime, _ := strconv.ParseInt(fields[7], 10, 64)
		port, _ := strconv.Atoi(fields[9])

		inbounds = append(inbounds, xuiInbound{
			ID:             id,
			UserID:         userID,
			Up:             up,
			Down:           down,
			Total:          total,
			Remark:         fields[5],
			Enable:         enable,
			ExpiryTime:     expiryTime,
			Listen:         fields[8],
			Port:           port,
			Protocol:       fields[10],
			Settings:       fields[11],
			StreamSettings: fields[12],
			Tag:            fields[13],
			Sniffing:       fields[14],
		})
	}

	return inbounds, nil
}

// xuiSettings is the JSON structure of the "settings" field.
type xuiSettings struct {
	Clients []xuiClient `json:"clients"`
	// Shadowsocks fields
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

type xuiClient struct {
	ID         string `json:"id"` // UUID for VLESS/VMess
	Email      string `json:"email"`
	Enable     bool   `json:"enable"`
	Flow       string `json:"flow,omitempty"`
	TotalGB    int64  `json:"totalGB,omitempty"`
	ExpiryTime int64  `json:"expiryTime,omitempty"`
	// Trojan
	Password string `json:"password,omitempty"`
}

// xuiStreamSettings is the JSON structure of "stream_settings".
type xuiStreamSettings struct {
	Network         string              `json:"network"`
	Security        string              `json:"security"`
	RealitySettings *xuiRealitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *xuiTLSSettings     `json:"tlsSettings,omitempty"`
	WSSettings      *xuiWSSettings      `json:"wsSettings,omitempty"`
	GRPCSettings    *xuiGRPCSettings    `json:"grpcSettings,omitempty"`
	XHTTPSettings   *xuiXHTTPSettings   `json:"xhttpSettings,omitempty"`
	TCPSettings     json.RawMessage     `json:"tcpSettings,omitempty"`
}

type xuiRealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
	// These may be in settings or publicKey from x-ui
	PublicKey string `json:"publicKey,omitempty"`
}

type xuiTLSSettings struct {
	ServerName string `json:"serverName"`
}

type xuiWSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

type xuiGRPCSettings struct {
	ServiceName string `json:"serviceName"`
}

type xuiXHTTPSettings struct {
	Path string   `json:"path"`
	Host []string `json:"host,omitempty"`
}

// parseInbound converts a 3x-ui inbound + its clients into HydraFlow nodes.
func (p *XUIProvider) parseInbound(inb xuiInbound) ([]smartsub.Node, error) {
	if !inb.Enable {
		return nil, nil
	}

	var settings xuiSettings
	if err := json.Unmarshal([]byte(inb.Settings), &settings); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}

	var stream xuiStreamSettings
	if err := json.Unmarshal([]byte(inb.StreamSettings), &stream); err != nil {
		return nil, fmt.Errorf("parse stream_settings: %w", err)
	}

	// Determine protocol type.
	protocol := p.mapProtocol(inb.Protocol, stream)

	var nodes []smartsub.Node

	for _, client := range settings.Clients {
		if !client.Enable {
			continue
		}

		// Check expiry.
		if client.ExpiryTime > 0 && client.ExpiryTime < time.Now().UnixMilli() {
			continue
		}

		node := smartsub.Node{
			Name:       fmt.Sprintf("%s-%s", inb.Remark, client.Email),
			Server:     p.serverIP,
			Port:       inb.Port,
			Protocol:   protocol,
			UUID:       client.ID,
			Email:      client.Email,
			Enabled:    true,
			ServerName: "local",
		}

		// If client has a password (Trojan), use that as UUID.
		if client.Password != "" && client.ID == "" {
			node.UUID = client.Password
		}

		// Fill protocol-specific fields from stream settings.
		p.fillStreamSettings(&node, stream)

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// mapProtocol maps a 3x-ui protocol + stream combination to HydraFlow protocol type.
func (p *XUIProvider) mapProtocol(proto string, stream xuiStreamSettings) string {
	switch proto {
	case "vless":
		switch {
		case stream.Security == "reality":
			return "reality"
		case stream.Network == "ws":
			return "ws"
		case stream.Network == "grpc":
			return "grpc"
		case stream.Network == "xhttp":
			return "xhttp"
		default:
			return "reality" // fallback for vless+tcp
		}
	case "vmess":
		if stream.Network == "ws" {
			return "ws"
		}
		return "ws" // vmess is typically WS-based
	case "trojan":
		return "ws" // trojan commonly through WS
	case "shadowsocks":
		return "ss"
	default:
		return proto
	}
}

// fillStreamSettings populates protocol-specific fields on a node.
func (p *XUIProvider) fillStreamSettings(node *smartsub.Node, stream xuiStreamSettings) {
	node.Security = stream.Security

	// Reality settings.
	if stream.RealitySettings != nil {
		rs := stream.RealitySettings
		if len(rs.ServerNames) > 0 {
			node.SNI = rs.ServerNames[0]
		}
		if len(rs.ShortIds) > 0 {
			node.ShortID = rs.ShortIds[0]
		}
		// Public key: try to read from x-ui's inbound_client_ips or
		// derive from settings. In 3x-ui, the public key is stored
		// in the settings or can be queried.
		node.PublicKey = rs.PublicKey
		node.Flow = "xtls-rprx-vision"
		node.Fingerprint = "chrome"
		// If we don't have the public key from reality settings,
		// try to read it from x-ui settings table.
		if node.PublicKey == "" {
			pk := p.readPublicKey(rs.PrivateKey)
			if pk != "" {
				node.PublicKey = pk
			}
		}
	}

	// TLS settings.
	if stream.TLSSettings != nil {
		node.SNI = stream.TLSSettings.ServerName
	}

	// WebSocket settings.
	if stream.WSSettings != nil {
		node.Path = stream.WSSettings.Path
		if host, ok := stream.WSSettings.Headers["Host"]; ok {
			node.Host = host
			node.CDN = host
		}
	}

	// gRPC settings.
	if stream.GRPCSettings != nil {
		node.ServiceName = stream.GRPCSettings.ServiceName
	}

	// XHTTP settings.
	if stream.XHTTPSettings != nil {
		node.Path = stream.XHTTPSettings.Path
		if len(stream.XHTTPSettings.Host) > 0 {
			node.Host = stream.XHTTPSettings.Host[0]
			node.CDN = stream.XHTTPSettings.Host[0]
		}
	}
}

// readPublicKey attempts to read the Reality public key from the x-ui settings.
// In 3x-ui, public keys are sometimes stored alongside inbound configs.
func (p *XUIProvider) readPublicKey(privateKey string) string {
	if privateKey == "" {
		return ""
	}

	// Sanitize: reject characters outside base64/key alphabet to prevent SQL injection.
	if !safeBase64RE.MatchString(privateKey) {
		p.logger.Warn("readPublicKey: privateKey contains invalid characters, skipping query")
		return ""
	}

	// Try to query the x-ui database for the public key associated with this inbound.
	// 3x-ui stores reality keys in the inbound settings JSON itself.
	// The public key derivation from private key requires x25519 which we avoid.
	// Instead, we try to read it from the client_traffics or settings table.
	snippet := privateKey
	if len(snippet) > 16 {
		snippet = snippet[:16]
	}
	query := fmt.Sprintf(
		`SELECT settings FROM inbounds WHERE settings LIKE '%%%s%%' LIMIT 1;`,
		snippet,
	)

	out, err := p.execSQLite(query)
	if err != nil || strings.TrimSpace(out) == "" {
		return ""
	}

	// Parse the settings JSON to find a public key reference.
	// This is a best-effort approach.
	return ""
}

// execSQLite runs a query against the 3x-ui database using the sqlite3 CLI.
// exec.Command passes arguments directly without a shell, so shell injection
// is not possible. Callers must still sanitize any user-supplied data
// interpolated into the SQL query string to prevent SQL injection.
func (p *XUIProvider) execSQLite(query string) (string, error) {
	// Defense-in-depth: reject multiple statements (extra semicolons).
	trimmed := strings.TrimSpace(query)
	trimmed = strings.TrimSuffix(trimmed, ";")
	if strings.Contains(trimmed, ";") {
		return "", fmt.Errorf("query contains multiple statements")
	}
	cmd := exec.Command("sqlite3", "-separator", "|", p.dbPath, query)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sqlite3 query failed: %w", err)
	}
	return string(out), nil
}
