package integrations

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/smartsub"
)

// RemnawaveProvider reads users and inbound configs from the Remnawave REST API.
type RemnawaveProvider struct {
	mu           sync.RWMutex
	apiURL       string
	apiToken     string
	pollInterval time.Duration
	logger       *slog.Logger
	serverIP     string
	client       *http.Client

	nodes    []smartsub.Node
	onChange func([]smartsub.Node)
	stopCh   chan struct{}
}

// RemnawaveConfig configures the Remnawave integration.
type RemnawaveConfig struct {
	APIURL       string
	APIToken     string
	PollInterval time.Duration
	ServerIP     string
	Logger       *slog.Logger
	OnChange     func([]smartsub.Node)
}

// NewRemnawaveProvider creates a new Remnawave integration provider.
func NewRemnawaveProvider(cfg RemnawaveConfig) (*RemnawaveProvider, error) {
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("remnawave api_url is required")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("remnawave api_token is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &RemnawaveProvider{
		apiURL:       strings.TrimRight(cfg.APIURL, "/"),
		apiToken:     cfg.APIToken,
		pollInterval: cfg.PollInterval,
		logger:       cfg.Logger,
		serverIP:     cfg.ServerIP,
		client:       &http.Client{Timeout: 15 * time.Second},
		onChange:     cfg.OnChange,
		stopCh:       make(chan struct{}),
	}, nil
}

// Start begins polling the Remnawave API for changes.
func (p *RemnawaveProvider) Start() error {
	if err := p.refresh(); err != nil {
		return fmt.Errorf("initial Remnawave API read: %w", err)
	}
	go p.pollLoop()
	return nil
}

// Stop stops the polling loop.
func (p *RemnawaveProvider) Stop() {
	close(p.stopCh)
}

// Nodes returns the current set of nodes.
func (p *RemnawaveProvider) Nodes() []smartsub.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]smartsub.Node, len(p.nodes))
	copy(out, p.nodes)
	return out
}

func (p *RemnawaveProvider) pollLoop() {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.refresh(); err != nil {
				p.logger.Error("Remnawave API poll failed", "error", err)
			}
		case <-p.stopCh:
			return
		}
	}
}

func (p *RemnawaveProvider) refresh() error {
	users, err := p.fetchUsers()
	if err != nil {
		return fmt.Errorf("fetch users: %w", err)
	}

	inbounds, err := p.fetchInbounds()
	if err != nil {
		return fmt.Errorf("fetch inbounds: %w", err)
	}

	// Build inbound lookup by tag.
	inboundMap := make(map[string]rwInbound, len(inbounds))
	for _, inb := range inbounds {
		inboundMap[inb.Tag] = inb
	}

	var nodes []smartsub.Node

	for _, user := range users {
		if user.Status != "active" {
			continue
		}

		// Check expiry.
		if user.ExpireAt > 0 && user.ExpireAt < time.Now().Unix() {
			continue
		}

		userNodes := p.userToNodes(user, inboundMap)
		nodes = append(nodes, userNodes...)
	}

	p.mu.Lock()
	changed := len(nodes) != len(p.nodes)
	p.nodes = nodes
	p.mu.Unlock()

	p.logger.Info("Remnawave API refreshed",
		"users", len(users),
		"inbounds", len(inbounds),
		"nodes", len(nodes),
	)

	if changed && p.onChange != nil {
		p.onChange(nodes)
	}

	return nil
}

// rwUser represents a user from the Remnawave API.
type rwUser struct {
	UUID            string   `json:"uuid"`
	Username        string   `json:"username"`
	Status          string   `json:"status"` // active, disabled, limited, expired
	UsedTrafficBytes int64   `json:"usedTrafficBytes"`
	TrafficLimitBytes int64  `json:"trafficLimitBytes"`
	ExpireAt        int64    `json:"expireAt"` // unix timestamp
	ActiveInbounds  []string `json:"activeInbounds"`

	// VLESS/VMess
	VlessFlow string `json:"vlessFlow,omitempty"`

	// Trojan
	TrojanPassword string `json:"trojanPassword,omitempty"`

	// Shadowsocks
	SSMethod   string `json:"ssMethod,omitempty"`
	SSPassword string `json:"ssPassword,omitempty"`
}

// rwUsersResponse is the API response for listing users.
type rwUsersResponse struct {
	Users []rwUser `json:"users"`
	Total int      `json:"total"`
}

// rwInbound represents an inbound from the Remnawave API.
type rwInbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Network  string `json:"network,omitempty"`
	Security string `json:"security,omitempty"`
	Port     int    `json:"port,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
}

// rwInboundsResponse is the API response for listing inbounds.
type rwInboundsResponse struct {
	Inbounds []rwInbound `json:"inbounds"`
}

func (p *RemnawaveProvider) doRequest(method, path string) ([]byte, error) {
	url := p.apiURL + path

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (p *RemnawaveProvider) fetchUsers() ([]rwUser, error) {
	var allUsers []rwUser
	offset := 0
	limit := 100

	for {
		path := fmt.Sprintf("/api/users?offset=%d&limit=%d", offset, limit)
		body, err := p.doRequest(http.MethodGet, path)
		if err != nil {
			return nil, err
		}

		var resp rwUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse users response: %w", err)
		}

		allUsers = append(allUsers, resp.Users...)

		if len(allUsers) >= resp.Total || len(resp.Users) < limit {
			break
		}
		offset += limit
	}

	return allUsers, nil
}

func (p *RemnawaveProvider) fetchInbounds() ([]rwInbound, error) {
	body, err := p.doRequest(http.MethodGet, "/api/inbounds")
	if err != nil {
		return nil, err
	}

	var resp rwInboundsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse inbounds response: %w", err)
	}

	return resp.Inbounds, nil
}

// userToNodes converts a Remnawave user into HydraFlow nodes.
func (p *RemnawaveProvider) userToNodes(user rwUser, inboundMap map[string]rwInbound) []smartsub.Node {
	var nodes []smartsub.Node

	for _, tag := range user.ActiveInbounds {
		inb, ok := inboundMap[tag]
		if !ok {
			// If we have no inbound details, still create a node from the tag.
			inb = rwInbound{Tag: tag}
			p.enrichInboundFromTag(&inb)
		}

		protocol := p.mapProtocol(inb.Protocol, inb.Network, inb.Security)

		node := smartsub.Node{
			Name:       fmt.Sprintf("Remnawave-%s-%s", user.Username, tag),
			Server:     p.serverIP,
			Port:       inb.Port,
			Protocol:   protocol,
			UUID:       user.UUID,
			Email:      user.Username,
			Enabled:    true,
			ServerName: "remnawave",
		}

		// Fill transport-specific fields from inbound.
		if inb.SNI != "" {
			node.SNI = inb.SNI
		}
		if inb.Path != "" {
			node.Path = inb.Path
		}
		if inb.Host != "" {
			node.Host = inb.Host
			node.CDN = inb.Host
		}

		// Apply user-specific overrides.
		if user.VlessFlow != "" {
			node.Flow = user.VlessFlow
		}
		if user.TrojanPassword != "" && user.UUID == "" {
			node.UUID = user.TrojanPassword
		}
		if user.SSMethod != "" {
			node.SSMethod = user.SSMethod
			node.SSPassword = user.SSPassword
		}

		// Set defaults for Reality protocol.
		if protocol == "reality" {
			if node.Flow == "" {
				node.Flow = "xtls-rprx-vision"
			}
			node.Fingerprint = "chrome"
		}

		node.Security = inb.Security

		nodes = append(nodes, node)
	}

	return nodes
}

// mapProtocol maps Remnawave protocol + network + security to HydraFlow protocol type.
func (p *RemnawaveProvider) mapProtocol(proto, network, security string) string {
	proto = strings.ToLower(proto)
	network = strings.ToLower(network)
	security = strings.ToLower(security)

	switch proto {
	case "vless":
		switch {
		case security == "reality":
			return "reality"
		case network == "ws":
			return "ws"
		case network == "grpc":
			return "grpc"
		case network == "xhttp":
			return "xhttp"
		default:
			return "reality"
		}
	case "vmess":
		return "ws"
	case "trojan":
		return "ws"
	case "shadowsocks":
		return "ss"
	default:
		return proto
	}
}

// enrichInboundFromTag tries to derive protocol information from the inbound tag name.
// Tags typically follow patterns like "VLESS_TCP_REALITY" or "VMESS_WS".
func (p *RemnawaveProvider) enrichInboundFromTag(inb *rwInbound) {
	tagUpper := strings.ToUpper(inb.Tag)

	switch {
	case strings.Contains(tagUpper, "VLESS"):
		inb.Protocol = "vless"
	case strings.Contains(tagUpper, "VMESS"):
		inb.Protocol = "vmess"
	case strings.Contains(tagUpper, "TROJAN"):
		inb.Protocol = "trojan"
	case strings.Contains(tagUpper, "SHADOWSOCKS") || strings.Contains(tagUpper, "SS"):
		inb.Protocol = "shadowsocks"
	}

	switch {
	case strings.Contains(tagUpper, "REALITY"):
		inb.Security = "reality"
	case strings.Contains(tagUpper, "TLS"):
		inb.Security = "tls"
	}

	switch {
	case strings.Contains(tagUpper, "WEBSOCKET") || strings.Contains(tagUpper, "_WS") || strings.HasSuffix(tagUpper, "WS") || strings.HasPrefix(tagUpper, "WS_"):
		inb.Network = "ws"
	case strings.Contains(tagUpper, "GRPC"):
		inb.Network = "grpc"
	case strings.Contains(tagUpper, "XHTTP"):
		inb.Network = "xhttp"
	case strings.Contains(tagUpper, "TCP"):
		inb.Network = "tcp"
	}
}
