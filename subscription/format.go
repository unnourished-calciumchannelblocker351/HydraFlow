// Package subscription implements the HydraFlow smart subscription
// system that provides multi-protocol configurations with priority
// ordering and ISP-specific recommendations.
package subscription

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Subscription is the top-level smart subscription document.
type Subscription struct {
	Version int       `yaml:"version" json:"version"`
	Server  string    `yaml:"server" json:"server"`
	Updated time.Time `yaml:"updated" json:"updated"`
	TTL     int       `yaml:"ttl,omitempty" json:"ttl,omitempty"` // seconds until refresh

	Protocols   []ProtocolConfig             `yaml:"protocols" json:"protocols"`
	BlockingMap map[string]ISPRecommendation `yaml:"blocking_map,omitempty" json:"blocking_map,omitempty"`
}

// ProtocolConfig describes a single protocol configuration.
type ProtocolConfig struct {
	Name      string `yaml:"name" json:"name"`
	Priority  int    `yaml:"priority" json:"priority"`
	Transport string `yaml:"transport" json:"transport"` // tcp, xhttp, quic, shadowtls, wireguard
	Security  string `yaml:"security" json:"security"`   // reality, tls, none

	// Connection details
	Host string `yaml:"host,omitempty" json:"host,omitempty"`
	Port int    `yaml:"port,omitempty" json:"port,omitempty"`
	UUID string `yaml:"uuid,omitempty" json:"uuid,omitempty"`

	// Reality-specific
	SNI       string `yaml:"sni,omitempty" json:"sni,omitempty"`
	PublicKey string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	ShortID   string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	SpiderX   string `yaml:"spider_x,omitempty" json:"spider_x,omitempty"`

	// XHTTP/WS-specific
	CDN  string `yaml:"cdn,omitempty" json:"cdn,omitempty"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Hysteria2-specific
	Ports []int  `yaml:"ports,omitempty" json:"ports,omitempty"` // port hopping
	Obfs  string `yaml:"obfs,omitempty" json:"obfs,omitempty"`

	// ShadowTLS-specific
	HandshakeServer string `yaml:"handshake_server,omitempty" json:"handshake_server,omitempty"`
	Version         int    `yaml:"version,omitempty" json:"version,omitempty"`

	// Chain proxy (multi-hop)
	Chain []ChainHop `yaml:"chain,omitempty" json:"chain,omitempty"`

	// TLS fingerprint
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`

	// Fragment settings for DPI bypass
	Fragment *FragmentConfig `yaml:"fragment,omitempty" json:"fragment,omitempty"`
}

// ChainHop describes one hop in a chain proxy configuration.
type ChainHop struct {
	Host      string `yaml:"host" json:"host"`
	Port      int    `yaml:"port" json:"port"`
	SNI       string `yaml:"sni,omitempty" json:"sni,omitempty"`
	PublicKey string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
}

// FragmentConfig controls TLS fragmentation for DPI bypass.
type FragmentConfig struct {
	Packets  string `yaml:"packets" json:"packets"`   // "tlshello"
	Length   string `yaml:"length" json:"length"`     // "100-200"
	Interval string `yaml:"interval" json:"interval"` // "10-20"
}

// ISPRecommendation provides per-ISP protocol guidance.
type ISPRecommendation struct {
	Blocked     []string `yaml:"blocked,omitempty" json:"blocked,omitempty"`
	Recommended []string `yaml:"recommended,omitempty" json:"recommended,omitempty"`
	Notes       string   `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Load reads a subscription from a .hydra.yml file.
func Load(path string) (*Subscription, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read subscription: %w", err)
	}

	return Parse(data)
}

// Parse parses subscription data from YAML bytes.
func Parse(data []byte) (*Subscription, error) {
	var sub Subscription
	if err := yaml.Unmarshal(data, &sub); err != nil {
		return nil, fmt.Errorf("parse subscription: %w", err)
	}

	if sub.Version == 0 {
		return nil, fmt.Errorf("missing or invalid version field")
	}

	return &sub, nil
}

// Marshal serializes the subscription to YAML.
func (s *Subscription) Marshal() ([]byte, error) {
	return yaml.Marshal(s)
}

// ForISP returns protocols ordered by recommendation for the given ISP.
// Blocked protocols are removed, recommended ones are prioritized.
func (s *Subscription) ForISP(isp string) []ProtocolConfig {
	rec, ok := s.BlockingMap[strings.ToLower(isp)]
	if !ok {
		return s.Protocols
	}

	blocked := make(map[string]bool)
	for _, name := range rec.Blocked {
		blocked[name] = true
	}

	recommended := make(map[string]bool)
	for _, name := range rec.Recommended {
		recommended[name] = true
	}

	var result []ProtocolConfig
	// First: recommended protocols
	for _, p := range s.Protocols {
		if recommended[p.Name] && !blocked[p.Name] {
			result = append(result, p)
		}
	}
	// Then: other non-blocked protocols
	for _, p := range s.Protocols {
		if !blocked[p.Name] && !recommended[p.Name] {
			result = append(result, p)
		}
	}

	return result
}

// ExportV2Ray converts the subscription to base64-encoded V2Ray
// compatible links for use with standard V2Ray clients.
func (s *Subscription) ExportV2Ray() string {
	var links []string

	for _, p := range s.Protocols {
		link := protocolToVLESSLink(p)
		if link != "" {
			links = append(links, link)
		}
	}

	return base64.StdEncoding.EncodeToString(
		[]byte(strings.Join(links, "\n")),
	)
}

// ExportClash converts the subscription to Clash Meta YAML format.
func (s *Subscription) ExportClash() ([]byte, error) {
	// Implementation generates Clash-compatible proxy config
	clash := map[string]interface{}{
		"proxies":      s.toClashProxies(),
		"proxy-groups": s.toClashGroups(),
	}

	return yaml.Marshal(clash)
}

func protocolToVLESSLink(p ProtocolConfig) string {
	if p.Transport == "tcp" && p.Security == "reality" {
		host := p.Host
		port := p.Port
		if len(p.Chain) > 0 {
			host = p.Chain[0].Host
			port = p.Chain[0].Port
		}

		return fmt.Sprintf(
			"vless://%s@%s:%d?flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&spx=%s&type=tcp#%s",
			p.UUID, host, port, p.SNI, p.Fingerprint,
			p.PublicKey, p.ShortID, p.SpiderX, p.Name,
		)
	}

	return ""
}

func (s *Subscription) toClashProxies() []map[string]interface{} {
	var proxies []map[string]interface{}
	for _, p := range s.Protocols {
		proxy := map[string]interface{}{
			"name":   p.Name,
			"type":   "vless",
			"server": p.Host,
			"port":   p.Port,
			"uuid":   p.UUID,
		}
		proxies = append(proxies, proxy)
	}
	return proxies
}

func (s *Subscription) toClashGroups() []map[string]interface{} {
	names := make([]string, len(s.Protocols))
	for i, p := range s.Protocols {
		names[i] = p.Name
	}

	return []map[string]interface{}{
		{
			"name":     "auto",
			"type":     "url-test",
			"proxies":  names,
			"url":      "https://www.gstatic.com/generate_204",
			"interval": 300,
		},
	}
}
