package integrations

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/smartsub"
)

// GenericProvider connects to any panel that exposes a REST API.
// Endpoint URLs and JSON field paths are fully configurable.
type GenericProvider struct {
	mu           sync.RWMutex
	cfg          GenericConfig
	logger       *slog.Logger
	client       *http.Client

	nodes    []smartsub.Node
	onChange func([]smartsub.Node)
	stopCh   chan struct{}
}

// GenericConfig configures the generic REST API integration.
type GenericConfig struct {
	APIURL       string
	APIToken     string
	AuthHeader   string // e.g., "Authorization", "X-API-Key"; defaults to "Authorization"
	AuthPrefix   string // e.g., "Bearer ", "Token "; defaults to "Bearer "
	PollInterval time.Duration
	ServerIP     string
	Logger       *slog.Logger
	OnChange     func([]smartsub.Node)

	// Endpoint paths relative to APIURL.
	UsersEndpoint    string // e.g., "/api/users"
	InboundsEndpoint string // e.g., "/api/inbounds" (optional)

	// JSON path mapping for the users response.
	// The users endpoint must return a JSON array (or an object with a list field).
	UsersListPath string // JSON path to the array of users, e.g., "users" or "" for root array

	// Field mappings: JSON field names within each user object.
	FieldUUID     string // default: "uuid"
	FieldEmail    string // default: "email"
	FieldUsername string // default: "username"
	FieldStatus   string // default: "status" (value compared to StatusActive)
	FieldEnabled  string // default: "enabled" (boolean field, used if FieldStatus is empty)
	FieldPort     string // default: "port"
	FieldProtocol string // default: "protocol"
	FieldExpireAt string // default: "expire_at"
	StatusActive  string // value considered active; default: "active"

	// Inbound field mappings.
	InboundsListPath   string // JSON path to the array of inbounds
	InboundFieldTag    string // default: "tag"
	InboundFieldPort   string // default: "port"
	InboundFieldProto  string // default: "protocol"
}

// NewGenericProvider creates a new generic REST API integration provider.
func NewGenericProvider(cfg GenericConfig) (*GenericProvider, error) {
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("generic api_url is required")
	}
	if cfg.UsersEndpoint == "" {
		return nil, fmt.Errorf("generic users_endpoint is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Apply defaults for field mappings.
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = "Authorization"
	}
	if cfg.AuthPrefix == "" {
		cfg.AuthPrefix = "Bearer "
	}
	if cfg.FieldUUID == "" {
		cfg.FieldUUID = "uuid"
	}
	if cfg.FieldEmail == "" {
		cfg.FieldEmail = "email"
	}
	if cfg.FieldUsername == "" {
		cfg.FieldUsername = "username"
	}
	if cfg.FieldStatus == "" && cfg.FieldEnabled == "" {
		cfg.FieldStatus = "status"
	}
	if cfg.FieldPort == "" {
		cfg.FieldPort = "port"
	}
	if cfg.FieldProtocol == "" {
		cfg.FieldProtocol = "protocol"
	}
	if cfg.FieldExpireAt == "" {
		cfg.FieldExpireAt = "expire_at"
	}
	if cfg.StatusActive == "" {
		cfg.StatusActive = "active"
	}
	if cfg.InboundFieldTag == "" {
		cfg.InboundFieldTag = "tag"
	}
	if cfg.InboundFieldPort == "" {
		cfg.InboundFieldPort = "port"
	}
	if cfg.InboundFieldProto == "" {
		cfg.InboundFieldProto = "protocol"
	}

	return &GenericProvider{
		cfg:      cfg,
		logger:   cfg.Logger,
		client:   &http.Client{Timeout: 15 * time.Second},
		onChange: cfg.OnChange,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start begins polling the generic API for changes.
func (p *GenericProvider) Start() error {
	if err := p.refresh(); err != nil {
		return fmt.Errorf("initial generic API read: %w", err)
	}
	go p.pollLoop()
	return nil
}

// Stop stops the polling loop.
func (p *GenericProvider) Stop() {
	close(p.stopCh)
}

// Nodes returns the current set of nodes.
func (p *GenericProvider) Nodes() []smartsub.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]smartsub.Node, len(p.nodes))
	copy(out, p.nodes)
	return out
}

func (p *GenericProvider) pollLoop() {
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.refresh(); err != nil {
				p.logger.Error("generic API poll failed", "error", err)
			}
		case <-p.stopCh:
			return
		}
	}
}

func (p *GenericProvider) refresh() error {
	users, err := p.fetchUsers()
	if err != nil {
		return fmt.Errorf("fetch users: %w", err)
	}

	var nodes []smartsub.Node

	for _, user := range users {
		node, ok := p.userToNode(user)
		if !ok {
			continue
		}
		nodes = append(nodes, node)
	}

	p.mu.Lock()
	changed := len(nodes) != len(p.nodes)
	p.nodes = nodes
	p.mu.Unlock()

	p.logger.Info("generic API refreshed", "users", len(users), "nodes", len(nodes))

	if changed && p.onChange != nil {
		p.onChange(nodes)
	}

	return nil
}

func (p *GenericProvider) doRequest(method, endpoint string) ([]byte, error) {
	url := strings.TrimRight(p.cfg.APIURL, "/") + endpoint

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	if p.cfg.APIToken != "" {
		req.Header.Set(p.cfg.AuthHeader, p.cfg.AuthPrefix+p.cfg.APIToken)
	}
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

func (p *GenericProvider) fetchUsers() ([]map[string]interface{}, error) {
	body, err := p.doRequest(http.MethodGet, p.cfg.UsersEndpoint)
	if err != nil {
		return nil, err
	}

	return p.extractList(body, p.cfg.UsersListPath)
}

// extractList parses a JSON body and extracts an array from the given path.
// If listPath is empty, the root is expected to be an array.
func (p *GenericProvider) extractList(body []byte, listPath string) ([]map[string]interface{}, error) {
	if listPath == "" {
		// Root is an array.
		var items []map[string]interface{}
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
		return items, nil
	}

	// Root is an object; dig into the path.
	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse JSON object: %w", err)
	}

	val := navigateJSON(root, listPath)
	if val == nil {
		return nil, fmt.Errorf("path %q not found in response", listPath)
	}

	arr, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("path %q is not an array", listPath)
	}

	var items []map[string]interface{}
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			items = append(items, m)
		}
	}

	return items, nil
}

// navigateJSON follows a dot-separated path into a JSON object.
// e.g., "data.users" navigates root["data"]["users"].
func navigateJSON(root map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = root

	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
	}

	return current
}

// userToNode converts a generic user map to a HydraFlow node.
// Returns false if the user should be skipped (disabled/expired).
func (p *GenericProvider) userToNode(user map[string]interface{}) (smartsub.Node, bool) {
	// Check if user is active.
	if p.cfg.FieldStatus != "" {
		status := getString(user, p.cfg.FieldStatus)
		if status != "" && status != p.cfg.StatusActive {
			return smartsub.Node{}, false
		}
	}
	if p.cfg.FieldEnabled != "" {
		enabled := getBool(user, p.cfg.FieldEnabled)
		if !enabled {
			return smartsub.Node{}, false
		}
	}

	// Check expiry.
	if p.cfg.FieldExpireAt != "" {
		expireAt := getInt64(user, p.cfg.FieldExpireAt)
		if expireAt > 0 && expireAt < time.Now().Unix() {
			return smartsub.Node{}, false
		}
	}

	uid := getString(user, p.cfg.FieldUUID)
	email := getString(user, p.cfg.FieldEmail)
	if email == "" {
		email = getString(user, p.cfg.FieldUsername)
	}
	protocol := getString(user, p.cfg.FieldProtocol)
	port := getInt(user, p.cfg.FieldPort)

	if uid == "" && email == "" {
		return smartsub.Node{}, false
	}

	if protocol == "" {
		protocol = "reality"
	}

	node := smartsub.Node{
		Name:       fmt.Sprintf("Generic-%s", email),
		Server:     p.cfg.ServerIP,
		Port:       port,
		Protocol:   protocol,
		UUID:       uid,
		Email:      email,
		Enabled:    true,
		ServerName: "generic",
	}

	return node, true
}

// --- JSON field access helpers ---

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func getInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(val)
		return n
	default:
		return 0
	}
}

func getInt64(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case string:
		n, _ := strconv.ParseInt(val, 10, 64)
		return n
	default:
		return 0
	}
}

func getBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case string:
		return val == "true" || val == "1"
	default:
		return false
	}
}
