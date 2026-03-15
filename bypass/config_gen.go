package bypass

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---- xray-core config generation ----

// XrayClientConfig generates a complete xray-core client-side JSON
// configuration that uses built-in fragment/padding support (since v1.8.6).
// The fragment settings go into streamSettings.sockopt.fragment.
func XrayClientConfig(cfg BypassConfig, serverAddr string, serverPort int, uuid, sni, publicKey, shortID string) ([]byte, error) {
	// Build sockopt with fragment settings.
	sockopt := map[string]interface{}{
		"domainStrategy": "AsIs",
		"tcpNoDelay":     true,
	}

	if cfg.FragmentEnabled {
		sockopt["fragment"] = map[string]interface{}{
			"packets":  cfg.FragmentPackets,
			"length":   cfg.FragmentSize,
			"interval": cfg.FragmentInterval,
		}
	}

	// Build the outbound.
	streamSettings := map[string]interface{}{
		"network":  "tcp",
		"security": "reality",
		"realitySettings": map[string]interface{}{
			"serverName":  sni,
			"fingerprint": "chrome",
			"publicKey":   publicKey,
			"shortId":     shortID,
			"spiderX":     "/",
		},
		"sockopt": sockopt,
	}

	outbound := map[string]interface{}{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": serverAddr,
					"port":    serverPort,
					"users": []map[string]interface{}{
						{
							"id":         uuid,
							"encryption": "none",
							"flow":       "xtls-rprx-vision",
						},
					},
				},
			},
		},
		"streamSettings": streamSettings,
	}

	// Build DNS.
	dns := map[string]interface{}{
		"servers": []interface{}{
			"https+local://dns.google/dns-query",
			"https+local://cloudflare-dns.com/dns-query",
		},
	}
	if cfg.DOHEnabled && cfg.DOHServer != "" {
		dns["servers"] = []interface{}{cfg.DOHServer}
	}

	// Full config.
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"dns": dns,
		"inbounds": []map[string]interface{}{
			{
				"tag":      "socks-in",
				"port":     10808,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
			{
				"tag":      "http-in",
				"port":     10809,
				"listen":   "127.0.0.1",
				"protocol": "http",
				"settings": map[string]interface{}{},
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
			},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{
					"type":        "field",
					"ip":          []string{"geoip:private"},
					"outboundTag": "direct",
				},
				{
					"type":        "field",
					"domain":      []string{"geosite:category-ads-all"},
					"outboundTag": "block",
				},
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

// XrayWSCDNConfig generates an xray-core config for WebSocket + CDN
// transport, which routes traffic through a CDN like Cloudflare.
func XrayWSCDNConfig(cfg BypassConfig, cdnHost string, serverPort int, uuid, wsPath, wsHost string) ([]byte, error) {
	sockopt := map[string]interface{}{
		"domainStrategy": "AsIs",
	}

	if cfg.FragmentEnabled {
		sockopt["fragment"] = map[string]interface{}{
			"packets":  cfg.FragmentPackets,
			"length":   cfg.FragmentSize,
			"interval": cfg.FragmentInterval,
		}
	}

	streamSettings := map[string]interface{}{
		"network":  "ws",
		"security": "tls",
		"tlsSettings": map[string]interface{}{
			"serverName":  wsHost,
			"fingerprint": "chrome",
			"alpn":        []string{"h2", "http/1.1"},
		},
		"wsSettings": map[string]interface{}{
			"path": wsPath,
			"headers": map[string]interface{}{
				"Host": wsHost,
			},
		},
		"sockopt": sockopt,
	}

	outbound := map[string]interface{}{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": cdnHost,
					"port":    serverPort,
					"users": []map[string]interface{}{
						{
							"id":         uuid,
							"encryption": "none",
						},
					},
				},
			},
		},
		"streamSettings": streamSettings,
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []map[string]interface{}{
			{
				"port":     10808,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{"auth": "noauth", "udp": true},
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

// ---- Hiddify config generation ----

// HiddifyConfig generates a Hiddify-compatible configuration.
// Hiddify supports fragment+padding natively via its profile format.
func HiddifyConfig(cfg BypassConfig, serverAddr string, serverPort int, uuid, sni, publicKey, shortID string) ([]byte, error) {
	profile := map[string]interface{}{
		"remarks":     "HydraFlow",
		"server":      serverAddr,
		"port":        serverPort,
		"uuid":        uuid,
		"sni":         sni,
		"flow":        "xtls-rprx-vision",
		"security":    "reality",
		"type":        "tcp",
		"fingerprint": "chrome",
		"publicKey":   publicKey,
		"shortId":     shortID,
	}

	if cfg.FragmentEnabled {
		profile["fragment"] = map[string]interface{}{
			"mode":     cfg.FragmentPackets,
			"length":   cfg.FragmentSize,
			"interval": cfg.FragmentInterval,
		}
	}

	if cfg.PaddingEnabled {
		profile["padding"] = map[string]interface{}{
			"enabled": true,
			"size":    cfg.PaddingSize,
		}
	}

	if cfg.DOHEnabled {
		profile["dns"] = map[string]interface{}{
			"doh": cfg.DOHServer,
		}
	}

	return json.MarshalIndent(profile, "", "  ")
}

// ---- sing-box config generation ----

// SingBoxConfig generates a sing-box compatible configuration.
func SingBoxConfig(cfg BypassConfig, serverAddr string, serverPort int, uuid, sni, publicKey, shortID string) ([]byte, error) {
	// sing-box TLS fragment is configured via the TLS options.
	tlsOpts := map[string]interface{}{
		"enabled":     true,
		"server_name": sni,
		"utls": map[string]interface{}{
			"enabled":     true,
			"fingerprint": "chrome",
		},
		"reality": map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   shortID,
		},
	}

	outbound := map[string]interface{}{
		"type":            "vless",
		"tag":             "proxy",
		"server":          serverAddr,
		"server_port":     serverPort,
		"uuid":            uuid,
		"flow":            "xtls-rprx-vision",
		"tls":             tlsOpts,
		"packet_encoding": "xudp",
	}

	// Add TCP brutal / fragment settings if applicable.
	if cfg.FragmentEnabled {
		outbound["tcp_fast_open"] = false
		outbound["tcp_multi_path"] = false
	}

	dns := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"tag":     "dns-google",
				"address": "https://dns.google/dns-query",
			},
			{
				"tag":     "dns-direct",
				"address": "local",
				"detour":  "direct",
			},
		},
		"rules": []map[string]interface{}{
			{
				"outbound": []string{"any"},
				"server":   "dns-direct",
			},
		},
	}
	if cfg.DOHEnabled && cfg.DOHServer != "" {
		dns["servers"].([]map[string]interface{})[0]["address"] = cfg.DOHServer
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"dns": dns,
		"inbounds": []map[string]interface{}{
			{
				"type":                       "tun",
				"tag":                        "tun-in",
				"interface_name":             "tun0",
				"inet4_address":              "172.19.0.1/30",
				"auto_route":                 true,
				"strict_route":               true,
				"stack":                      "system",
				"sniff":                      true,
				"sniff_override_destination": true,
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{
				"type": "direct",
				"tag":  "direct",
			},
			map[string]interface{}{
				"type": "block",
				"tag":  "block",
			},
			map[string]interface{}{
				"type": "dns",
				"tag":  "dns-out",
			},
		},
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"rules": []map[string]interface{}{
				{
					"protocol": "dns",
					"outbound": "dns-out",
				},
				{
					"geoip":    []string{"private"},
					"outbound": "direct",
				},
				{
					"geosite":  []string{"category-ads-all"},
					"outbound": "block",
				},
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

// ---- Clash Meta config generation ----

// ClashMetaConfig generates a Clash Meta (mihomo) YAML-compatible
// configuration as JSON (caller can convert to YAML if needed).
func ClashMetaConfig(cfg BypassConfig, serverAddr string, serverPort int, uuid, sni, publicKey, shortID string) ([]byte, error) {
	proxy := map[string]interface{}{
		"name":               "hydraflow",
		"type":               "vless",
		"server":             serverAddr,
		"port":               serverPort,
		"uuid":               uuid,
		"network":            "tcp",
		"tls":                true,
		"servername":         sni,
		"flow":               "xtls-rprx-vision",
		"client-fingerprint": "chrome",
		"reality-opts": map[string]interface{}{
			"public-key": publicKey,
			"short-id":   shortID,
		},
	}

	config := map[string]interface{}{
		"port":          7890,
		"socks-port":    7891,
		"allow-lan":     false,
		"mode":          "rule",
		"log-level":     "warning",
		"unified-delay": true,
		"dns": map[string]interface{}{
			"enable":        true,
			"enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.1/16",
			"nameserver": []string{
				"https://dns.google/dns-query",
				"https://cloudflare-dns.com/dns-query",
			},
		},
		"proxies": []interface{}{proxy},
		"proxy-groups": []map[string]interface{}{
			{
				"name":     "auto",
				"type":     "url-test",
				"proxies":  []string{"hydraflow"},
				"url":      "https://www.gstatic.com/generate_204",
				"interval": 300,
			},
		},
		"rules": []string{
			"GEOIP,private,DIRECT",
			"GEOSITE,category-ads-all,REJECT",
			"MATCH,auto",
		},
	}

	if cfg.DOHEnabled && cfg.DOHServer != "" {
		config["dns"].(map[string]interface{})["nameserver"] = []string{cfg.DOHServer}
	}

	return json.MarshalIndent(config, "", "  ")
}

// ---- Config generation from NetworkProfile ----

// GenerateOptimalConfig uses probe results to generate the best
// configuration for the detected network conditions.
func GenerateOptimalConfig(profile *NetworkProfile, baseConfig BypassConfig) BypassConfig {
	cfg := baseConfig

	if profile == nil {
		return cfg
	}

	// Enable fragmentation if effective.
	if profile.FragmentEffective {
		cfg.FragmentEnabled = true
		if profile.OptimalFragmentSize > 0 {
			cfg.FragmentSize = fmt.Sprintf("%d-%d",
				profile.OptimalFragmentSize, profile.OptimalFragmentSize+5)
		}
		cfg.FragmentPackets = "tlshello"
		cfg.FragmentInterval = "1-5"
	}

	// Use working SNI.
	if len(profile.WorkingSNIs) > 0 {
		cfg.SNIDomain = profile.WorkingSNIs[0]
		if len(profile.WorkingSNIs) > 1 {
			cfg.SNIFallbacks = profile.WorkingSNIs[1:]
		}
	}

	// Set protocols based on what works.
	var protocols []ProtocolConfig
	priority := 1

	if profile.CDNReachable {
		protocols = append(protocols, ProtocolConfig{
			Name: "ws-cdn", Priority: priority, Enabled: true,
		})
		priority++
		protocols = append(protocols, ProtocolConfig{
			Name: "xhttp-cdn", Priority: priority, Enabled: true,
		})
		priority++
	}

	if profile.TLS13Available {
		protocols = append(protocols, ProtocolConfig{
			Name: "reality", Priority: priority, Enabled: true,
		})
		priority++
	}

	if profile.QUICAvailable {
		protocols = append(protocols, ProtocolConfig{
			Name: "hysteria2", Priority: priority, Enabled: true,
		})
		priority++
	}

	protocols = append(protocols, ProtocolConfig{
		Name: "ss2022", Priority: priority, Enabled: true,
	})

	cfg.Protocols = protocols

	// Enable padding if DPI latency suggests active inspection.
	if profile.EstimatedDPILatency > 100*time.Millisecond {
		cfg.PaddingEnabled = true
		cfg.PaddingSize = "100-200"
	}

	// Enable DoH always.
	cfg.DOHEnabled = true
	if cfg.DOHServer == "" {
		cfg.DOHServer = "https://dns.google/dns-query"
	}

	return cfg
}

// ---- Multi-client config generation ----

// ClientConfigSet holds configurations for all supported client apps.
type ClientConfigSet struct {
	Xray      json.RawMessage `json:"xray"`
	Hiddify   json.RawMessage `json:"hiddify"`
	SingBox   json.RawMessage `json:"singbox"`
	Clash     json.RawMessage `json:"clash"`
	V2RayLink string          `json:"v2ray_link"`
}

// GenerateAllClientConfigs produces configs for xray, Hiddify, sing-box,
// and Clash Meta from a single BypassConfig and server info.
func GenerateAllClientConfigs(cfg BypassConfig, serverAddr string, serverPort int, uuid, sni, publicKey, shortID string) (*ClientConfigSet, error) {
	set := &ClientConfigSet{}

	var err error
	set.Xray, err = XrayClientConfig(cfg, serverAddr, serverPort, uuid, sni, publicKey, shortID)
	if err != nil {
		return nil, fmt.Errorf("xray config: %w", err)
	}

	set.Hiddify, err = HiddifyConfig(cfg, serverAddr, serverPort, uuid, sni, publicKey, shortID)
	if err != nil {
		return nil, fmt.Errorf("hiddify config: %w", err)
	}

	set.SingBox, err = SingBoxConfig(cfg, serverAddr, serverPort, uuid, sni, publicKey, shortID)
	if err != nil {
		return nil, fmt.Errorf("singbox config: %w", err)
	}

	set.Clash, err = ClashMetaConfig(cfg, serverAddr, serverPort, uuid, sni, publicKey, shortID)
	if err != nil {
		return nil, fmt.Errorf("clash config: %w", err)
	}

	// V2Ray link.
	set.V2RayLink = buildVLESSLink(serverAddr, serverPort, uuid, sni, publicKey, shortID, cfg)

	return set, nil
}

// buildVLESSLink generates a vless:// sharing link.
func buildVLESSLink(server string, port int, uuid, sni, pbk, sid string, cfg BypassConfig) string {
	params := []string{
		"flow=xtls-rprx-vision",
		"security=reality",
		fmt.Sprintf("sni=%s", sni),
		"fp=chrome",
		fmt.Sprintf("pbk=%s", pbk),
		fmt.Sprintf("sid=%s", sid),
		"spx=/",
		"type=tcp",
	}

	if cfg.FragmentEnabled {
		params = append(params,
			fmt.Sprintf("fragment=%s,%s,%s", cfg.FragmentPackets, cfg.FragmentSize, cfg.FragmentInterval),
		)
	}

	return fmt.Sprintf("vless://%s@%s:%d?%s#HydraFlow",
		uuid, server, port, strings.Join(params, "&"))
}
