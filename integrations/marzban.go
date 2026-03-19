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

// MarzbanProvider reads users and proxy configs from Marzban's REST API.
type MarzbanProvider struct {
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

// MarzbanConfig configures the Marzban integration.
type MarzbanConfig struct {
	APIURL       string
	APIToken     string
	PollInterval time.Duration
	ServerIP     string
	Logger       *slog.Logger
	OnChange     func([]smartsub.Node)
}

// NewMarzbanProvider creates a new Marzban integration provider.
func NewMarzbanProvider(cfg MarzbanConfig) (*MarzbanProvider, error) {
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("marzban api_url is required")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("marzban api_token is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &MarzbanProvider{
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

// Start begins polling the Marzban API for changes.
func (p *MarzbanProvider) Start() error {
	if err := p.refresh(); err != nil {
		return fmt.Errorf("initial Marzban API read: %w", err)
	}
	go p.pollLoop()
	return nil
}

// Stop stops the polling loop.
func (p *MarzbanProvider) Stop() {
	close(p.stopCh)
}

// Nodes returns the current set of nodes.
func (p *MarzbanProvider) Nodes() []smartsub.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]smartsub.Node, len(p.nodes))
	copy(out, p.nodes)
	return out
}

func (p *MarzbanProvider) pollLoop() {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.refresh(); err != nil {
				p.logger.Error("Marzban API poll failed", "error", err)
			}
		case <-p.stopCh:
			return
		}
	}
}

func (p *MarzbanProvider) refresh() error {
	users, err := p.fetchUsers()
	if err != nil {
		return fmt.Errorf("fetch users: %w", err)
	}

	var nodes []smartsub.Node

	for _, user := range users {
		if user.Status != "active" {
			continue
		}

		userNodes := p.userToNodes(user)
		nodes = append(nodes, userNodes...)
	}

	p.mu.Lock()
	changed := len(nodes) != len(p.nodes)
	p.nodes = nodes
	p.mu.Unlock()

	p.logger.Info("Marzban API refreshed", "users", len(users), "nodes", len(nodes))

	if changed && p.onChange != nil {
		p.onChange(nodes)
	}

	return nil
}

// marzbanUser represents a user from the Marzban API.
type marzbanUser struct {
	Username    string                  `json:"username"`
	Status      string                  `json:"status"` // active, disabled, limited, expired
	UsedTraffic int64                   `json:"used_traffic"`
	DataLimit   int64                   `json:"data_limit"`
	Expire      int64                   `json:"expire"` // unix timestamp
	Proxies     map[string]marzbanProxy `json:"proxies"`
	Inbounds    map[string][]string     `json:"inbounds"`
}

// marzbanProxy holds proxy-specific settings for a user.
type marzbanProxy struct {
	ID       string `json:"id,omitempty"` // UUID
	Flow     string `json:"flow,omitempty"`
	Password string `json:"password,omitempty"`
}

// marzbanUsersResponse is the API response for /api/users.
type marzbanUsersResponse struct {
	Users []marzbanUser `json:"users"`
	Total int           `json:"total"`
}

// marzbanInbound represents an inbound from the Marzban API.
type marzbanInbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Network  string `json:"network,omitempty"`
	TLS      string `json:"tls,omitempty"`
	Port     int    `json:"port,omitempty"`
}

func (p *MarzbanProvider) fetchUsers() ([]marzbanUser, error) {
	var allUsers []marzbanUser
	offset := 0
	limit := 100

	for {
		url := fmt.Sprintf("%s/api/users?offset=%d&limit=%d", p.apiURL, offset, limit)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+p.apiToken)

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
		}

		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		var usersResp marzbanUsersResponse
		if err := json.Unmarshal(body, &usersResp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		allUsers = append(allUsers, usersResp.Users...)

		if len(allUsers) >= usersResp.Total || len(usersResp.Users) < limit {
			break
		}
		offset += limit
	}

	return allUsers, nil
}

// userToNodes converts a Marzban user into HydraFlow nodes.
func (p *MarzbanProvider) userToNodes(user marzbanUser) []smartsub.Node {
	var nodes []smartsub.Node

	for protoName, proxy := range user.Proxies {
		protocol := p.mapProtocol(protoName)

		node := smartsub.Node{
			Name:       fmt.Sprintf("Marzban-%s-%s", user.Username, protoName),
			Server:     p.serverIP,
			Protocol:   protocol,
			UUID:       proxy.ID,
			Email:      user.Username,
			Enabled:    true,
			Flow:       proxy.Flow,
			ServerName: "marzban",
		}

		if proxy.Password != "" && proxy.ID == "" {
			node.UUID = proxy.Password
		}

		// Try to get inbound details for port and settings.
		if inboundTags, ok := user.Inbounds[protoName]; ok {
			for _, tag := range inboundTags {
				inbNode := node
				inbNode.Name = fmt.Sprintf("Marzban-%s-%s", user.Username, tag)
				p.enrichFromInboundTag(&inbNode, tag, protoName)
				nodes = append(nodes, inbNode)
			}
		} else {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// mapProtocol maps Marzban protocol names to HydraFlow protocol types.
func (p *MarzbanProvider) mapProtocol(proto string) string {
	switch strings.ToLower(proto) {
	case "vless":
		return "reality"
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

// enrichFromInboundTag tries to extract port and settings from the inbound tag name.
// Marzban inbound tags follow patterns like "VLESS_TCP_REALITY_443".
func (p *MarzbanProvider) enrichFromInboundTag(node *smartsub.Node, tag, proto string) {
	parts := strings.Split(strings.ToUpper(tag), "_")

	for _, part := range parts {
		// Try to parse as port number.
		if port, err := fmt.Sscanf(part, "%d", new(int)); port == 1 && err == nil {
			fmt.Sscanf(part, "%d", &node.Port)
		}
	}

	// Detect protocol from tag.
	tagUpper := strings.ToUpper(tag)
	switch {
	case strings.Contains(tagUpper, "REALITY"):
		node.Protocol = "reality"
		node.Fingerprint = "chrome"
		node.Flow = "xtls-rprx-vision"
	case strings.Contains(tagUpper, "WS") || strings.Contains(tagUpper, "WEBSOCKET"):
		node.Protocol = "ws"
	case strings.Contains(tagUpper, "GRPC"):
		node.Protocol = "grpc"
	case strings.Contains(tagUpper, "XHTTP"):
		node.Protocol = "xhttp"
	}

	// Fetch detailed inbound config from the API if needed.
	// For now, we rely on tag-name heuristics.
	p.fetchInboundDetails(node, tag)
}

// fetchInboundDetails queries the Marzban API for specific inbound configuration.
func (p *MarzbanProvider) fetchInboundDetails(node *smartsub.Node, tag string) {
	url := fmt.Sprintf("%s/api/inbounds", p.apiURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}

	// Marzban returns inbounds as a map of protocol -> []inbound.
	var inbounds map[string][]marzbanInbound
	if err := json.Unmarshal(body, &inbounds); err != nil {
		return
	}

	// Find matching inbound by tag.
	for _, inbList := range inbounds {
		for _, inb := range inbList {
			if inb.Tag == tag {
				if inb.Port > 0 {
					node.Port = inb.Port
				}
				return
			}
		}
	}
}
