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

// HiddifyProvider reads users and configs from the Hiddify Manager REST API.
type HiddifyProvider struct {
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

// HiddifyConfig configures the Hiddify Manager integration.
type HiddifyConfig struct {
	APIURL       string
	APIToken     string
	PollInterval time.Duration
	ServerIP     string
	Logger       *slog.Logger
	OnChange     func([]smartsub.Node)
}

// NewHiddifyProvider creates a new Hiddify Manager integration provider.
func NewHiddifyProvider(cfg HiddifyConfig) (*HiddifyProvider, error) {
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("hiddify api_url is required")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("hiddify api_token is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &HiddifyProvider{
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

// Start begins polling the Hiddify API for changes.
func (p *HiddifyProvider) Start() error {
	if err := p.refresh(); err != nil {
		return fmt.Errorf("initial Hiddify API read: %w", err)
	}
	go p.pollLoop()
	return nil
}

// Stop stops the polling loop.
func (p *HiddifyProvider) Stop() {
	close(p.stopCh)
}

// Nodes returns the current set of nodes.
func (p *HiddifyProvider) Nodes() []smartsub.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]smartsub.Node, len(p.nodes))
	copy(out, p.nodes)
	return out
}

func (p *HiddifyProvider) pollLoop() {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.refresh(); err != nil {
				p.logger.Error("Hiddify API poll failed", "error", err)
			}
		case <-p.stopCh:
			return
		}
	}
}

func (p *HiddifyProvider) refresh() error {
	users, err := p.fetchUsers()
	if err != nil {
		return fmt.Errorf("fetch users: %w", err)
	}

	configs, err := p.fetchConfigs()
	if err != nil {
		// Configs are optional; log and continue with user data only.
		p.logger.Warn("Hiddify configs fetch failed, using user data only", "error", err)
		configs = nil
	}

	var nodes []smartsub.Node

	for _, user := range users {
		if !user.Enabled {
			continue
		}

		// Check expiry.
		if user.ExpireAt > 0 && user.ExpireAt < time.Now().Unix() {
			continue
		}

		userNodes := p.userToNodes(user, configs)
		nodes = append(nodes, userNodes...)
	}

	p.mu.Lock()
	changed := len(nodes) != len(p.nodes)
	p.nodes = nodes
	p.mu.Unlock()

	p.logger.Info("Hiddify API refreshed",
		"users", len(users),
		"configs", len(configs),
		"nodes", len(nodes),
	)

	if changed && p.onChange != nil {
		p.onChange(nodes)
	}

	return nil
}

// hiddifyUser represents a user from the Hiddify Manager API.
type hiddifyUser struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	UsageBytes       int64  `json:"usage_limit_bytes"`
	CurrentUsage     int64  `json:"current_usage_bytes"`
	ExpireAt         int64  `json:"expire_at"` // unix timestamp
	LastOnline       string `json:"last_online,omitempty"`
	SubLinkURL       string `json:"sub_link_url,omitempty"`
	PackageRemaining int64  `json:"package_remaining_bytes,omitempty"`
}

// hiddifyUsersResponse is the API response for listing users.
type hiddifyUsersResponse struct {
	Users []hiddifyUser `json:"users"`
}

// hiddifyConfig represents a proxy config from the Hiddify Manager API.
type hiddifyConfig struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"` // vless, vmess, trojan, shadowsocks
	Network  string `json:"network"`  // tcp, ws, grpc, xhttp
	Security string `json:"security"` // reality, tls, none
	Port     int    `json:"port"`
	SNI      string `json:"sni,omitempty"`
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

// hiddifyConfigsResponse is the API response for listing proxy configs.
type hiddifyConfigsResponse struct {
	Configs []hiddifyConfig `json:"configs"`
}

func (p *HiddifyProvider) doRequest(method, path string) ([]byte, error) {
	url := p.apiURL + path

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Hiddify-API-Key", p.apiToken)
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

func (p *HiddifyProvider) fetchUsers() ([]hiddifyUser, error) {
	body, err := p.doRequest(http.MethodGet, "/api/v2/admin/user/")
	if err != nil {
		return nil, err
	}

	// Hiddify may return either a list directly or wrapped in a response object.
	// Try list first.
	var users []hiddifyUser
	if err := json.Unmarshal(body, &users); err == nil {
		return users, nil
	}

	// Try wrapped response.
	var resp hiddifyUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse users response: %w", err)
	}

	return resp.Users, nil
}

func (p *HiddifyProvider) fetchConfigs() ([]hiddifyConfig, error) {
	body, err := p.doRequest(http.MethodGet, "/api/v2/admin/proxy/")
	if err != nil {
		return nil, err
	}

	// Same pattern: try list or wrapped.
	var configs []hiddifyConfig
	if err := json.Unmarshal(body, &configs); err == nil {
		return configs, nil
	}

	var resp hiddifyConfigsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse configs response: %w", err)
	}

	return resp.Configs, nil
}

// userToNodes converts a Hiddify user into HydraFlow nodes.
// If configs are available, each config becomes a separate node for the user.
// If no configs are known, a single default node is created.
func (p *HiddifyProvider) userToNodes(user hiddifyUser, configs []hiddifyConfig) []smartsub.Node {
	var nodes []smartsub.Node

	if len(configs) == 0 {
		// No config data available; create a basic node.
		node := smartsub.Node{
			Name:       fmt.Sprintf("Hiddify-%s", user.Name),
			Server:     p.serverIP,
			Protocol:   "reality",
			UUID:       user.UUID,
			Email:      user.Name,
			Enabled:    true,
			Flow:       "xtls-rprx-vision",
			Fingerprint: "chrome",
			ServerName: "hiddify",
		}
		return append(nodes, node)
	}

	for _, cfg := range configs {
		protocol := p.mapProtocol(cfg.Protocol, cfg.Network, cfg.Security)

		node := smartsub.Node{
			Name:       fmt.Sprintf("Hiddify-%s-%s", user.Name, cfg.Tag),
			Server:     p.serverIP,
			Port:       cfg.Port,
			Protocol:   protocol,
			UUID:       user.UUID,
			Email:      user.Name,
			Enabled:    true,
			Security:   cfg.Security,
			ServerName: "hiddify",
		}

		if cfg.SNI != "" {
			node.SNI = cfg.SNI
		}
		if cfg.Path != "" {
			node.Path = cfg.Path
		}
		if cfg.Host != "" {
			node.Host = cfg.Host
			node.CDN = cfg.Host
		}
		if cfg.Flow != "" {
			node.Flow = cfg.Flow
		}

		if protocol == "reality" {
			if node.Flow == "" {
				node.Flow = "xtls-rprx-vision"
			}
			node.Fingerprint = "chrome"
		}

		nodes = append(nodes, node)
	}

	return nodes
}

// mapProtocol maps Hiddify protocol + network + security to HydraFlow protocol type.
func (p *HiddifyProvider) mapProtocol(proto, network, security string) string {
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
