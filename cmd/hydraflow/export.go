package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// cmdExport reads the server config and outputs a ready-to-import config
// for V2Ray, Clash Meta, or sing-box client apps.
func cmdExport() {
	format := ""

	// Parse --format flag.
	for i, arg := range os.Args {
		if arg == "--format" && i+1 < len(os.Args) {
			format = os.Args[i+1]
			break
		}
	}

	if format == "" {
		fmt.Fprintf(os.Stderr, "usage: hydraflow export --format <v2ray|clash|singbox>\n\n")
		fmt.Fprintf(os.Stderr, "Reads server configuration and outputs a ready-to-import config.\n")
		fmt.Fprintf(os.Stderr, "Pipe to file:      hydraflow export --format clash > config.yaml\n")
		fmt.Fprintf(os.Stderr, "Copy to clipboard: hydraflow export --format v2ray | pbcopy\n")
		os.Exit(1)
	}

	// Load the sub-config.json which has all protocol details.
	subConfig, err := loadSubConfig("/etc/hydraflow/sub-config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read server config: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure HydraFlow is installed and /etc/hydraflow/sub-config.json exists.\n")
		os.Exit(1)
	}

	switch strings.ToLower(format) {
	case "v2ray", "v2rayng":
		exportV2Ray(subConfig)
	case "clash", "clashmeta", "clash-meta":
		exportClash(subConfig)
	case "singbox", "sing-box":
		exportSingBox(subConfig)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q\n", format)
		fmt.Fprintf(os.Stderr, "Supported formats: v2ray, clash, singbox\n")
		os.Exit(1)
	}
}

// subConfigFile represents the sub-config.json structure.
type subConfigFile struct {
	ServerIP string `json:"server_ip"`
	SubToken string `json:"sub_token"`
	SubPort  int    `json:"sub_port"`
	Protocols struct {
		Reality struct {
			Port        int    `json:"port"`
			UUID        string `json:"uuid"`
			PublicKey   string `json:"public_key"`
			ShortID     string `json:"short_id"`
			SNI         string `json:"sni"`
			Flow        string `json:"flow"`
			Fingerprint string `json:"fingerprint"`
		} `json:"reality"`
		WS struct {
			Port int    `json:"port"`
			UUID string `json:"uuid"`
			Path string `json:"path"`
			Host string `json:"host"`
		} `json:"ws"`
		SS struct {
			Port     int    `json:"port"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"ss"`
	} `json:"protocols"`
}

func loadSubConfig(path string) (*subConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg subConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &cfg, nil
}

func exportV2Ray(cfg *subConfigFile) {
	var links []string

	// VLESS + Reality.
	if cfg.Protocols.Reality.UUID != "" {
		params := url.Values{}
		params.Set("security", "reality")
		params.Set("sni", cfg.Protocols.Reality.SNI)
		params.Set("fp", cfg.Protocols.Reality.Fingerprint)
		params.Set("pbk", cfg.Protocols.Reality.PublicKey)
		params.Set("sid", cfg.Protocols.Reality.ShortID)
		params.Set("type", "tcp")
		params.Set("flow", cfg.Protocols.Reality.Flow)
		params.Set("encryption", "none")

		link := fmt.Sprintf("vless://%s@%s:%d?%s#HydraFlow-Reality",
			cfg.Protocols.Reality.UUID,
			cfg.ServerIP,
			cfg.Protocols.Reality.Port,
			params.Encode())
		links = append(links, link)
	}

	// VLESS + WebSocket.
	if cfg.Protocols.WS.UUID != "" {
		params := url.Values{}
		params.Set("security", "none")
		params.Set("type", "ws")
		params.Set("path", cfg.Protocols.WS.Path)
		params.Set("host", cfg.Protocols.WS.Host)
		params.Set("encryption", "none")

		link := fmt.Sprintf("vless://%s@%s:%d?%s#HydraFlow-WS",
			cfg.Protocols.WS.UUID,
			cfg.ServerIP,
			cfg.Protocols.WS.Port,
			params.Encode())
		links = append(links, link)
	}

	// Shadowsocks.
	if cfg.Protocols.SS.Password != "" {
		userInfo := base64.StdEncoding.EncodeToString(
			[]byte(cfg.Protocols.SS.Method + ":" + cfg.Protocols.SS.Password))
		link := fmt.Sprintf("ss://%s@%s:%d#HydraFlow-SS",
			userInfo, cfg.ServerIP, cfg.Protocols.SS.Port)
		links = append(links, link)
	}

	// V2Ray subscription format: base64-encoded links separated by newlines.
	output := base64.StdEncoding.EncodeToString(
		[]byte(strings.Join(links, "\n")))
	fmt.Println(output)
}

func exportClash(cfg *subConfigFile) {
	var proxies []map[string]interface{}
	var proxyNames []string

	// Reality proxy.
	if cfg.Protocols.Reality.UUID != "" {
		proxy := map[string]interface{}{
			"name":               "HydraFlow-Reality",
			"type":               "vless",
			"server":             cfg.ServerIP,
			"port":               cfg.Protocols.Reality.Port,
			"uuid":               cfg.Protocols.Reality.UUID,
			"network":            "tcp",
			"flow":               cfg.Protocols.Reality.Flow,
			"tls":                true,
			"servername":         cfg.Protocols.Reality.SNI,
			"client-fingerprint": cfg.Protocols.Reality.Fingerprint,
			"reality-opts": map[string]interface{}{
				"public-key": cfg.Protocols.Reality.PublicKey,
				"short-id":   cfg.Protocols.Reality.ShortID,
			},
		}
		proxies = append(proxies, proxy)
		proxyNames = append(proxyNames, "HydraFlow-Reality")
	}

	// WebSocket proxy.
	if cfg.Protocols.WS.UUID != "" {
		proxy := map[string]interface{}{
			"name":    "HydraFlow-WS",
			"type":    "vless",
			"server":  cfg.ServerIP,
			"port":    cfg.Protocols.WS.Port,
			"uuid":    cfg.Protocols.WS.UUID,
			"network": "ws",
			"tls":     false,
			"ws-opts": map[string]interface{}{
				"path":    cfg.Protocols.WS.Path,
				"headers": map[string]string{"Host": cfg.Protocols.WS.Host},
			},
		}
		proxies = append(proxies, proxy)
		proxyNames = append(proxyNames, "HydraFlow-WS")
	}

	// Shadowsocks proxy.
	if cfg.Protocols.SS.Password != "" {
		proxy := map[string]interface{}{
			"name":     "HydraFlow-SS",
			"type":     "ss",
			"server":   cfg.ServerIP,
			"port":     cfg.Protocols.SS.Port,
			"cipher":   cfg.Protocols.SS.Method,
			"password": cfg.Protocols.SS.Password,
		}
		proxies = append(proxies, proxy)
		proxyNames = append(proxyNames, "HydraFlow-SS")
	}

	allProxies := append([]string{"auto"}, proxyNames...)

	config := map[string]interface{}{
		"mixed-port":          7890,
		"allow-lan":           false,
		"mode":                "rule",
		"log-level":           "info",
		"external-controller": "127.0.0.1:9090",
		"dns": map[string]interface{}{
			"enable":        true,
			"enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.1/16",
			"nameserver":    []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]interface{}{
			{
				"name":    "proxy",
				"type":    "select",
				"proxies": allProxies,
			},
			{
				"name":      "auto",
				"type":      "url-test",
				"proxies":   proxyNames,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 50,
			},
		},
		"rules": []string{
			"GEOIP,PRIVATE,DIRECT",
			"GEOSITE,category-ads-all,REJECT",
			"MATCH,proxy",
		},
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal clash config: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}

func exportSingBox(cfg *subConfigFile) {
	var outbounds []map[string]interface{}
	var outboundNames []string

	// Reality outbound.
	if cfg.Protocols.Reality.UUID != "" {
		outbound := map[string]interface{}{
			"type":        "vless",
			"tag":         "HydraFlow-Reality",
			"server":      cfg.ServerIP,
			"server_port": cfg.Protocols.Reality.Port,
			"uuid":        cfg.Protocols.Reality.UUID,
			"flow":        cfg.Protocols.Reality.Flow,
			"tls": map[string]interface{}{
				"enabled":     true,
				"server_name": cfg.Protocols.Reality.SNI,
				"utls": map[string]interface{}{
					"enabled":     true,
					"fingerprint": cfg.Protocols.Reality.Fingerprint,
				},
				"reality": map[string]interface{}{
					"enabled":    true,
					"public_key": cfg.Protocols.Reality.PublicKey,
					"short_id":   cfg.Protocols.Reality.ShortID,
				},
			},
		}
		outbounds = append(outbounds, outbound)
		outboundNames = append(outboundNames, "HydraFlow-Reality")
	}

	// WebSocket outbound.
	if cfg.Protocols.WS.UUID != "" {
		outbound := map[string]interface{}{
			"type":        "vless",
			"tag":         "HydraFlow-WS",
			"server":      cfg.ServerIP,
			"server_port": cfg.Protocols.WS.Port,
			"uuid":        cfg.Protocols.WS.UUID,
			"transport": map[string]interface{}{
				"type":    "ws",
				"path":    cfg.Protocols.WS.Path,
				"headers": map[string]string{"Host": cfg.Protocols.WS.Host},
			},
		}
		outbounds = append(outbounds, outbound)
		outboundNames = append(outboundNames, "HydraFlow-WS")
	}

	// Shadowsocks outbound.
	if cfg.Protocols.SS.Password != "" {
		outbound := map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         "HydraFlow-SS",
			"server":      cfg.ServerIP,
			"server_port": cfg.Protocols.SS.Port,
			"method":      cfg.Protocols.SS.Method,
			"password":    cfg.Protocols.SS.Password,
		}
		outbounds = append(outbounds, outbound)
		outboundNames = append(outboundNames, "HydraFlow-SS")
	}

	// Prepend selector and urltest.
	controlOutbounds := []map[string]interface{}{
		{
			"type":      "selector",
			"tag":       "proxy",
			"outbounds": append([]string{"auto"}, outboundNames...),
			"default":   "auto",
		},
		{
			"type":      "urltest",
			"tag":       "auto",
			"outbounds": outboundNames,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  "3m",
			"tolerance": 50,
		},
	}

	allOutbounds := append(controlOutbounds, outbounds...)
	allOutbounds = append(allOutbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
		map[string]interface{}{"type": "dns", "tag": "dns-out"},
	)

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":              "google",
					"address":          "https://dns.google/dns-query",
					"address_resolver": "local",
					"detour":           "proxy",
				},
				{
					"tag":     "local",
					"address": "local",
					"detour":  "direct",
				},
			},
		},
		"inbounds": []map[string]interface{}{
			{
				"type":                       "tun",
				"tag":                        "tun-in",
				"inet4_address":              "172.19.0.1/30",
				"auto_route":                 true,
				"strict_route":               true,
				"stack":                      "system",
				"sniff":                      true,
				"sniff_override_destination": true,
			},
		},
		"outbounds": allOutbounds,
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"rules": []map[string]interface{}{
				{"protocol": "dns", "outbound": "dns-out"},
				{"geoip": []string{"private"}, "outbound": "direct"},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal sing-box config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
