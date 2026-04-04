// Package xray provides xray-core process management and configuration
// generation for HydraFlow. It creates xray-core JSON configs that support
// multiple inbound protocols simultaneously, enabling standard client
// compatibility (v2rayNG, Hiddify, Streisand, Clash, sing-box).
package xray

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ---- Inbound protocol types ----

// InboundType identifies the protocol and transport combination for an inbound.
type InboundType string

const (
	InboundVLESSReality InboundType = "vless-reality"
	InboundVLESSWS      InboundType = "vless-ws"
	InboundVLESSGRPC    InboundType = "vless-grpc"
	InboundVLESSXHTTP   InboundType = "vless-xhttp"
	InboundVMessWS      InboundType = "vmess-ws"
	InboundTrojanTLS    InboundType = "trojan-tls"
	InboundShadowsocks  InboundType = "shadowsocks-2022"
)

// ---- User management ----

// XrayUser represents a user entry within an xray inbound.
type XrayUser struct {
	Email    string `json:"email"`
	UUID     string `json:"id"`
	Flow     string `json:"flow,omitempty"`
	Level    int    `json:"level"`
	AlterId  int    `json:"alterId,omitempty"`
	Security string `json:"security,omitempty"`
}

// ---- Inbound configuration ----

// InboundConfig holds all parameters needed to construct one xray inbound.
type InboundConfig struct {
	Tag  string      `json:"tag"`
	Type InboundType `json:"type"`
	Port int         `json:"port"`

	// VLESS Reality
	RealityPrivateKey  string   `json:"reality_private_key,omitempty"`
	RealityPublicKey   string   `json:"reality_public_key,omitempty"`
	RealityShortIDs    []string `json:"reality_short_ids,omitempty"`
	RealityDest        string   `json:"reality_dest,omitempty"`
	RealityServerNames []string `json:"reality_server_names,omitempty"`
	Flow               string   `json:"flow,omitempty"`

	// CDN (WS / gRPC / XHTTP)
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`

	// TLS (Trojan, etc.)
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
	TLSSni      string `json:"tls_sni,omitempty"`

	// Shadowsocks-2022
	SSMethod   string `json:"ss_method,omitempty"`
	SSPassword string `json:"ss_password,omitempty"`

	// Trojan
	TrojanPassword string `json:"trojan_password,omitempty"`

	// VMess
	VMessAlterID int `json:"vmess_alter_id,omitempty"`

	// Fallback (serve real website when probed)
	FallbackDest string `json:"fallback_dest,omitempty"`
	FallbackPort int    `json:"fallback_port,omitempty"`
	FallbackXver int    `json:"fallback_xver,omitempty"`
}

// ---- Config builder ----

// ConfigBuilder constructs a complete xray-core JSON configuration.
type ConfigBuilder struct {
	mu       sync.RWMutex
	inbounds []InboundConfig
	users    map[string][]XrayUser // tag -> users

	// Global settings
	LogLevel     string
	APIPort      int
	DNSServers   []string
	BlockAds     bool
	DirectLocal  bool
	StatsEnabled bool
}

// NewConfigBuilder returns a ConfigBuilder with sensible defaults.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		users:        make(map[string][]XrayUser),
		LogLevel:     "warning",
		APIPort:      10085,
		DNSServers:   []string{"https+local://dns.google/dns-query", "https+local://cloudflare-dns.com/dns-query"},
		BlockAds:     true,
		DirectLocal:  true,
		StatsEnabled: true,
	}
}

// Reset clears all inbounds and users, restoring the builder to a clean
// state while preserving global settings. This avoids copying the mutex.
func (cb *ConfigBuilder) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.inbounds = nil
	cb.users = make(map[string][]XrayUser)
}

// AddInbound registers an inbound configuration.
func (cb *ConfigBuilder) AddInbound(in InboundConfig) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.inbounds = append(cb.inbounds, in)
	if _, ok := cb.users[in.Tag]; !ok {
		cb.users[in.Tag] = []XrayUser{}
	}
}

// AddUser adds a user to the specified inbound by tag.
func (cb *ConfigBuilder) AddUser(inboundTag, email, uuid string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	user := XrayUser{
		Email: email,
		UUID:  uuid,
		Level: 0,
	}

	// Set flow for reality inbounds.
	for _, in := range cb.inbounds {
		if in.Tag == inboundTag && in.Type == InboundVLESSReality {
			user.Flow = "xtls-rprx-vision"
			break
		}
		if in.Tag == inboundTag && in.Type == InboundVMessWS {
			user.Security = "auto"
			break
		}
	}

	cb.users[inboundTag] = append(cb.users[inboundTag], user)
}

// RemoveUser removes a user from the specified inbound by email.
func (cb *ConfigBuilder) RemoveUser(inboundTag, email string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	users := cb.users[inboundTag]
	for i, u := range users {
		if u.Email == email {
			cb.users[inboundTag] = append(users[:i], users[i+1:]...)
			return
		}
	}
}

// Build generates the complete xray-core JSON configuration.
func (cb *ConfigBuilder) Build() ([]byte, error) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	config := map[string]interface{}{
		"log":       cb.buildLog(),
		"dns":       cb.buildDNS(),
		"routing":   cb.buildRouting(),
		"policy":    cb.buildPolicy(),
		"inbounds":  cb.buildInbounds(),
		"outbounds": cb.buildOutbounds(),
		"stats":     map[string]interface{}{},
	}

	if cb.StatsEnabled {
		config["api"] = cb.buildAPI()
	}

	return json.MarshalIndent(config, "", "  ")
}

func (cb *ConfigBuilder) buildLog() map[string]interface{} {
	return map[string]interface{}{
		"loglevel": cb.LogLevel,
		"access":   "none",
		"error":    "",
		"dnsLog":   false,
	}
}

func (cb *ConfigBuilder) buildAPI() map[string]interface{} {
	return map[string]interface{}{
		"tag": "api",
		"services": []string{
			"HandlerService",
			"LoggerService",
			"StatsService",
		},
	}
}

func (cb *ConfigBuilder) buildDNS() map[string]interface{} {
	servers := make([]interface{}, 0, len(cb.DNSServers)+1)
	for _, s := range cb.DNSServers {
		servers = append(servers, s)
	}
	// Local DNS for direct routing.
	servers = append(servers, map[string]interface{}{
		"address":      "localhost",
		"domains":      []string{"geosite:private"},
		"skipFallback": true,
	})

	return map[string]interface{}{
		"servers":       servers,
		"queryStrategy": "UseIPv4",
		"tag":           "dns-inbound",
	}
}

func (cb *ConfigBuilder) buildRouting() map[string]interface{} {
	rules := []map[string]interface{}{
		// API routing.
		{
			"type":        "field",
			"inboundTag":  []string{"api-inbound"},
			"outboundTag": "api",
		},
		// DNS routing.
		{
			"type":        "field",
			"protocol":    []string{"dns"},
			"outboundTag": "dns-out",
		},
	}

	// Block ads.
	if cb.BlockAds {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      []string{"geosite:category-ads-all"},
			"outboundTag": "blocked",
		})
	}

	// Direct local traffic.
	if cb.DirectLocal {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"outboundTag": "direct",
		})
	}

	// Block BitTorrent.
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"protocol":    []string{"bittorrent"},
		"outboundTag": "blocked",
	})

	return map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules":          rules,
	}
}

func (cb *ConfigBuilder) buildPolicy() map[string]interface{} {
	return map[string]interface{}{
		"levels": map[string]interface{}{
			"0": map[string]interface{}{
				"statsUserUplink":   true,
				"statsUserDownlink": true,
				"handshake":         4,
				"connIdle":          300,
				"uplinkOnly":        2,
				"downlinkOnly":      5,
			},
		},
		"system": map[string]interface{}{
			"statsInboundUplink":    true,
			"statsInboundDownlink":  true,
			"statsOutboundUplink":   true,
			"statsOutboundDownlink": true,
		},
	}
}

func (cb *ConfigBuilder) buildInbounds() []map[string]interface{} {
	inbounds := make([]map[string]interface{}, 0, len(cb.inbounds)+1)

	// API inbound.
	if cb.StatsEnabled {
		inbounds = append(inbounds, map[string]interface{}{
			"tag":      "api-inbound",
			"listen":   "127.0.0.1",
			"port":     cb.APIPort,
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{
				"address": "127.0.0.1",
			},
		})
	}

	for _, in := range cb.inbounds {
		inbound := cb.buildSingleInbound(in)
		if inbound != nil {
			inbounds = append(inbounds, inbound)
		}
	}

	return inbounds
}

func (cb *ConfigBuilder) buildSingleInbound(in InboundConfig) map[string]interface{} {
	switch in.Type {
	case InboundVLESSReality:
		return cb.buildVLESSRealityInbound(in)
	case InboundVLESSWS:
		return cb.buildVLESSWSInbound(in)
	case InboundVLESSGRPC:
		return cb.buildVLESSGRPCInbound(in)
	case InboundVLESSXHTTP:
		return cb.buildVLESSXHTTPInbound(in)
	case InboundVMessWS:
		return cb.buildVMessWSInbound(in)
	case InboundTrojanTLS:
		return cb.buildTrojanTLSInbound(in)
	case InboundShadowsocks:
		return cb.buildShadowsocksInbound(in)
	default:
		return nil
	}
}

func (cb *ConfigBuilder) buildVLESSRealityInbound(in InboundConfig) map[string]interface{} {
	users := cb.buildVLESSUsers(in.Tag, true)

	shortIDs := in.RealityShortIDs
	if len(shortIDs) == 0 {
		shortIDs = []string{""}
	}

	serverNames := in.RealityServerNames
	if len(serverNames) == 0 && in.RealityDest != "" {
		// Extract hostname from dest.
		host := in.RealityDest
		for i, c := range host {
			if c == ':' {
				host = host[:i]
				break
			}
		}
		serverNames = []string{host}
	}

	fallbackDest := in.FallbackDest
	if fallbackDest == "" {
		fallbackDest = in.RealityDest
	}

	inbound := map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients":    users,
			"decryption": "none",
			"fallbacks": []map[string]interface{}{
				{
					"dest": fallbackDest,
					"xver": 1,
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"show":        false,
				"dest":        in.RealityDest,
				"xver":        0,
				"serverNames": serverNames,
				"privateKey":  in.RealityPrivateKey,
				"shortIds":    shortIDs,
			},
		},
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    true,
		},
	}

	return inbound
}

func (cb *ConfigBuilder) buildVLESSWSInbound(in InboundConfig) map[string]interface{} {
	users := cb.buildVLESSUsers(in.Tag, false)

	path := in.Path
	if path == "" {
		path = "/ws"
	}

	streamSettings := map[string]interface{}{
		"network":  "ws",
		"security": "none",
		"wsSettings": map[string]interface{}{
			"path": path,
			"headers": map[string]interface{}{
				"Host": in.Host,
			},
		},
	}

	// If TLS cert is provided, use TLS instead of none (direct, not behind CDN).
	if in.TLSCertFile != "" && in.TLSKeyFile != "" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"certificateFile": in.TLSCertFile,
					"keyFile":         in.TLSKeyFile,
				},
			},
			"minVersion": "1.3",
			"alpn":       []string{"h2", "http/1.1"},
		}
	}

	return map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients":    users,
			"decryption": "none",
		},
		"streamSettings": streamSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func (cb *ConfigBuilder) buildVLESSGRPCInbound(in InboundConfig) map[string]interface{} {
	users := cb.buildVLESSUsers(in.Tag, false)

	serviceName := in.ServiceName
	if serviceName == "" {
		serviceName = "grpc"
	}

	streamSettings := map[string]interface{}{
		"network":  "grpc",
		"security": "none",
		"grpcSettings": map[string]interface{}{
			"serviceName":          serviceName,
			"multiMode":            true,
			"idle_timeout":         60,
			"health_check_timeout": 20,
		},
	}

	if in.TLSCertFile != "" && in.TLSKeyFile != "" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"certificateFile": in.TLSCertFile,
					"keyFile":         in.TLSKeyFile,
				},
			},
			"minVersion": "1.3",
			"alpn":       []string{"h2"},
		}
	}

	return map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients":    users,
			"decryption": "none",
		},
		"streamSettings": streamSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func (cb *ConfigBuilder) buildVLESSXHTTPInbound(in InboundConfig) map[string]interface{} {
	users := cb.buildVLESSUsers(in.Tag, false)

	path := in.Path
	if path == "" {
		path = "/xhttp"
	}

	streamSettings := map[string]interface{}{
		"network":  "xhttp",
		"security": "none",
		"xhttpSettings": map[string]interface{}{
			"path": path,
			"host": []string{in.Host},
		},
	}

	if in.TLSCertFile != "" && in.TLSKeyFile != "" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"certificateFile": in.TLSCertFile,
					"keyFile":         in.TLSKeyFile,
				},
			},
			"minVersion": "1.3",
			"alpn":       []string{"h2", "http/1.1"},
		}
	}

	return map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients":    users,
			"decryption": "none",
		},
		"streamSettings": streamSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func (cb *ConfigBuilder) buildVMessWSInbound(in InboundConfig) map[string]interface{} {
	users := cb.buildVMessUsers(in.Tag, in.VMessAlterID)

	path := in.Path
	if path == "" {
		path = "/vmess"
	}

	streamSettings := map[string]interface{}{
		"network":  "ws",
		"security": "none",
		"wsSettings": map[string]interface{}{
			"path": path,
			"headers": map[string]interface{}{
				"Host": in.Host,
			},
		},
	}

	if in.TLSCertFile != "" && in.TLSKeyFile != "" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"certificateFile": in.TLSCertFile,
					"keyFile":         in.TLSKeyFile,
				},
			},
			"minVersion": "1.3",
			"alpn":       []string{"http/1.1"},
		}
	}

	return map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"clients": users,
		},
		"streamSettings": streamSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func (cb *ConfigBuilder) buildTrojanTLSInbound(in InboundConfig) map[string]interface{} {
	clients := make([]map[string]interface{}, 0)
	for _, u := range cb.users[in.Tag] {
		clients = append(clients, map[string]interface{}{
			"password": u.UUID,
			"email":    u.Email,
			"level":    0,
		})
	}

	fallbacks := []map[string]interface{}{}
	if in.FallbackDest != "" {
		fallbacks = append(fallbacks, map[string]interface{}{
			"dest": in.FallbackDest,
			"xver": in.FallbackXver,
		})
	}

	settings := map[string]interface{}{
		"clients": clients,
	}
	if len(fallbacks) > 0 {
		settings["fallbacks"] = fallbacks
	}

	streamSettings := map[string]interface{}{
		"network":  "tcp",
		"security": "tls",
		"tlsSettings": map[string]interface{}{
			"certificates": []map[string]interface{}{
				{
					"certificateFile": in.TLSCertFile,
					"keyFile":         in.TLSKeyFile,
				},
			},
			"minVersion": "1.3",
			"alpn":       []string{"h2", "http/1.1"},
		},
	}

	if in.TLSSni != "" {
		streamSettings["tlsSettings"].(map[string]interface{})["serverName"] = in.TLSSni
	}

	return map[string]interface{}{
		"tag":            in.Tag,
		"listen":         "0.0.0.0",
		"port":           in.Port,
		"protocol":       "trojan",
		"settings":       settings,
		"streamSettings": streamSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func (cb *ConfigBuilder) buildShadowsocksInbound(in InboundConfig) map[string]interface{} {
	method := in.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}

	password := in.SSPassword
	if password == "" {
		password = in.RealityPrivateKey // reuse as fallback; caller should set explicitly
	}

	clients := make([]map[string]interface{}, 0)
	for _, u := range cb.users[in.Tag] {
		clients = append(clients, map[string]interface{}{
			"password": u.UUID,
			"email":    u.Email,
			"level":    0,
		})
	}

	settings := map[string]interface{}{
		"method":   method,
		"password": password,
		"network":  "tcp,udp",
	}
	if len(clients) > 0 {
		settings["clients"] = clients
	}

	return map[string]interface{}{
		"tag":      in.Tag,
		"listen":   "0.0.0.0",
		"port":     in.Port,
		"protocol": "shadowsocks",
		"settings": settings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

// ---- Helper builders ----

func (cb *ConfigBuilder) buildVLESSUsers(tag string, withFlow bool) []map[string]interface{} {
	users := make([]map[string]interface{}, 0)
	for _, u := range cb.users[tag] {
		user := map[string]interface{}{
			"id":    u.UUID,
			"email": u.Email,
			"level": u.Level,
		}
		if withFlow {
			flow := u.Flow
			if flow == "" {
				flow = "xtls-rprx-vision"
			}
			user["flow"] = flow
		}
		users = append(users, user)
	}
	return users
}

func (cb *ConfigBuilder) buildVMessUsers(tag string, defaultAlterID int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0)
	for _, u := range cb.users[tag] {
		alterID := u.AlterId
		if alterID == 0 {
			alterID = defaultAlterID
		}
		user := map[string]interface{}{
			"id":       u.UUID,
			"email":    u.Email,
			"level":    u.Level,
			"alterId":  alterID,
			"security": "auto",
		}
		users = append(users, user)
	}
	return users
}

func (cb *ConfigBuilder) buildOutbounds() []map[string]interface{} {
	outbounds := []map[string]interface{}{
		{
			"tag":      "direct",
			"protocol": "freedom",
			"settings": map[string]interface{}{
				"domainStrategy": "UseIPv4",
			},
		},
		{
			"tag":      "blocked",
			"protocol": "blackhole",
			"settings": map[string]interface{}{
				"response": map[string]interface{}{
					"type": "http",
				},
			},
		},
		{
			"tag":      "dns-out",
			"protocol": "dns",
			"settings": map[string]interface{}{},
		},
	}

	return outbounds
}

// GenerateConfig is a convenience function that creates a full xray-core
// JSON configuration from a list of InboundConfigs and user mappings.
func GenerateConfig(inbounds []InboundConfig, users map[string][]XrayUser) ([]byte, error) {
	cb := NewConfigBuilder()

	for _, in := range inbounds {
		cb.AddInbound(in)
	}

	for tag, userList := range users {
		for _, u := range userList {
			cb.AddUser(tag, u.Email, u.UUID)
		}
	}

	return cb.Build()
}

// GenerateConfigJSON is like GenerateConfig but returns an indented JSON string.
func GenerateConfigJSON(inbounds []InboundConfig, users map[string][]XrayUser) (string, error) {
	data, err := GenerateConfig(inbounds, users)
	if err != nil {
		return "", fmt.Errorf("generate config: %w", err)
	}
	return string(data), nil
}
