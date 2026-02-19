package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExportV2RayFull converts the subscription to a complete base64-encoded
// V2Ray subscription string with all protocol types supported.
func ExportV2RayFull(sub *Subscription) string {
	var links []string

	for _, p := range sub.Protocols {
		var link string
		switch {
		case p.Security == "reality":
			link = exportVLESSReality(p)
		case p.Transport == "xhttp" || p.Transport == "ws":
			link = exportVLESSTransport(p)
		case p.Transport == "quic":
			link = exportHysteria2(p)
		default:
			link = exportVLESSGeneric(p)
		}
		if link != "" {
			links = append(links, link)
		}
	}

	return base64.StdEncoding.EncodeToString(
		[]byte(strings.Join(links, "\n")),
	)
}

// exportVLESSReality generates a VLESS Reality link.
func exportVLESSReality(p ProtocolConfig) string {
	params := url.Values{}
	params.Set("security", "reality")
	params.Set("sni", p.SNI)
	params.Set("fp", p.Fingerprint)
	params.Set("pbk", p.PublicKey)
	params.Set("sid", p.ShortID)
	params.Set("type", "tcp")
	params.Set("flow", "xtls-rprx-vision")

	if p.SpiderX != "" {
		params.Set("spx", p.SpiderX)
	}

	host := p.Host
	port := p.Port
	if len(p.Chain) > 0 {
		host = p.Chain[0].Host
		port = p.Chain[0].Port
	}

	name := url.PathEscape(p.Name)

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		p.UUID, host, port, params.Encode(), name)
}

// exportVLESSTransport generates a VLESS link with XHTTP or WebSocket transport.
func exportVLESSTransport(p ProtocolConfig) string {
	params := url.Values{}

	switch p.Transport {
	case "xhttp":
		params.Set("type", "xhttp")
	case "ws":
		params.Set("type", "ws")
	default:
		params.Set("type", p.Transport)
	}

	if p.Security == "tls" || p.Security == "reality" {
		params.Set("security", p.Security)
	} else {
		params.Set("security", "tls")
	}

	if p.Path != "" {
		params.Set("path", p.Path)
	}
	if p.CDN != "" {
		params.Set("host", p.CDN)
	}
	if p.SNI != "" {
		params.Set("sni", p.SNI)
	}
	if p.Fingerprint != "" {
		params.Set("fp", p.Fingerprint)
	}

	host := p.Host
	port := p.Port

	name := url.PathEscape(p.Name)

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		p.UUID, host, port, params.Encode(), name)
}

// exportHysteria2 generates a Hysteria2 link.
func exportHysteria2(p ProtocolConfig) string {
	params := url.Values{}

	if p.Obfs != "" {
		params.Set("obfs", "salamander")
		params.Set("obfs-password", p.Obfs)
	}
	if p.SNI != "" {
		params.Set("sni", p.SNI)
	}

	// Port hopping notation.
	portStr := fmt.Sprintf("%d", p.Port)
	if len(p.Ports) > 1 {
		var portParts []string
		for _, port := range p.Ports {
			portParts = append(portParts, fmt.Sprintf("%d", port))
		}
		params.Set("mport", strings.Join(portParts, ","))
	}

	name := url.PathEscape(p.Name)
	host := p.Host

	return fmt.Sprintf("hysteria2://%s@%s:%s?%s#%s",
		p.UUID, host, portStr, params.Encode(), name)
}

// exportVLESSGeneric generates a generic VLESS link for other configurations.
func exportVLESSGeneric(p ProtocolConfig) string {
	params := url.Values{}
	params.Set("type", "tcp")

	if p.Security != "" && p.Security != "none" {
		params.Set("security", p.Security)
	} else {
		params.Set("security", "none")
	}

	if p.SNI != "" {
		params.Set("sni", p.SNI)
	}
	if p.Fingerprint != "" {
		params.Set("fp", p.Fingerprint)
	}

	// Fragment settings.
	if p.Fragment != nil {
		params.Set("fragment", fmt.Sprintf("%s,%s,%s",
			p.Fragment.Packets, p.Fragment.Length, p.Fragment.Interval))
	}

	host := p.Host
	port := p.Port
	name := url.PathEscape(p.Name)

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		p.UUID, host, port, params.Encode(), name)
}

// ExportClashFull converts the subscription to a complete Clash Meta
// configuration YAML with proxies, proxy groups, and rules.
func ExportClashFull(sub *Subscription) ([]byte, error) {
	proxies := make([]map[string]interface{}, 0, len(sub.Protocols))
	proxyNames := make([]string, 0, len(sub.Protocols))

	for _, p := range sub.Protocols {
		proxy := buildClashProxy(p)
		if proxy != nil {
			proxies = append(proxies, proxy)
			proxyNames = append(proxyNames, p.Name)
		}
	}

	// Build proxy groups.
	groups := buildClashProxyGroups(proxyNames)

	// Build full Clash config.
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
			"fallback":      []string{"https://1.0.0.1/dns-query", "https://8.8.4.4/dns-query"},
			"fallback-filter": map[string]interface{}{
				"geoip":      true,
				"geoip-code": "CN",
				"ipcidr":     []string{"240.0.0.0/4"},
			},
		},
		"proxies":      proxies,
		"proxy-groups": groups,
		"rules": []string{
			"GEOIP,PRIVATE,DIRECT",
			"GEOSITE,category-ads-all,REJECT",
			"GEOIP,CN,DIRECT",
			"MATCH,auto",
		},
	}

	return yaml.Marshal(config)
}

// buildClashProxy converts a ProtocolConfig to a Clash proxy entry.
func buildClashProxy(p ProtocolConfig) map[string]interface{} {
	proxy := map[string]interface{}{
		"name":   p.Name,
		"server": p.Host,
		"port":   p.Port,
		"uuid":   p.UUID,
	}

	switch {
	case p.Security == "reality":
		proxy["type"] = "vless"
		proxy["network"] = "tcp"
		proxy["flow"] = "xtls-rprx-vision"
		proxy["tls"] = true
		proxy["servername"] = p.SNI
		proxy["client-fingerprint"] = coalesce(p.Fingerprint, "chrome")

		proxy["reality-opts"] = map[string]interface{}{
			"public-key": p.PublicKey,
			"short-id":   p.ShortID,
		}

	case p.Transport == "xhttp":
		proxy["type"] = "vless"
		proxy["network"] = "xhttp"
		proxy["tls"] = true
		if p.SNI != "" {
			proxy["servername"] = p.SNI
		}
		if p.Fingerprint != "" {
			proxy["client-fingerprint"] = p.Fingerprint
		}

		xhttpOpts := map[string]interface{}{}
		if p.Path != "" {
			xhttpOpts["path"] = p.Path
		}
		if p.CDN != "" {
			xhttpOpts["host"] = p.CDN
		}
		if len(xhttpOpts) > 0 {
			proxy["xhttp-opts"] = xhttpOpts
		}

	case p.Transport == "ws":
		proxy["type"] = "vless"
		proxy["network"] = "ws"
		proxy["tls"] = true
		if p.SNI != "" {
			proxy["servername"] = p.SNI
		}

		wsOpts := map[string]interface{}{}
		if p.Path != "" {
			wsOpts["path"] = p.Path
		}
		if p.CDN != "" {
			wsOpts["headers"] = map[string]string{"Host": p.CDN}
		}
		if len(wsOpts) > 0 {
			proxy["ws-opts"] = wsOpts
		}

	case p.Transport == "quic":
		proxy["type"] = "hysteria2"
		proxy["password"] = p.UUID
		if p.Obfs != "" {
			proxy["obfs"] = "salamander"
			proxy["obfs-password"] = p.Obfs
		}
		if p.SNI != "" {
			proxy["sni"] = p.SNI
		}
		if len(p.Ports) > 0 {
			proxy["ports"] = formatPortRange(p.Ports)
		}
		// Remove uuid for Hysteria2 (uses password).
		delete(proxy, "uuid")

	default:
		proxy["type"] = "vless"
		proxy["network"] = "tcp"
		if p.Security == "tls" {
			proxy["tls"] = true
			if p.SNI != "" {
				proxy["servername"] = p.SNI
			}
		}
	}

	// Fragment support.
	if p.Fragment != nil {
		proxy["tls-fragment"] = map[string]interface{}{
			"enable":   true,
			"packets":  p.Fragment.Packets,
			"length":   p.Fragment.Length,
			"interval": p.Fragment.Interval,
		}
	}

	return proxy
}

// buildClashProxyGroups creates standard proxy groups.
func buildClashProxyGroups(names []string) []map[string]interface{} {
	allProxies := make([]string, 0, len(names)+2)
	allProxies = append(allProxies, "auto")
	allProxies = append(allProxies, names...)

	return []map[string]interface{}{
		{
			"name":    "proxy",
			"type":    "select",
			"proxies": allProxies,
		},
		{
			"name":      "auto",
			"type":      "url-test",
			"proxies":   names,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  300,
			"tolerance": 50,
		},
		{
			"name":     "fallback",
			"type":     "fallback",
			"proxies":  names,
			"url":      "https://www.gstatic.com/generate_204",
			"interval": 300,
		},
	}
}

// ExportSingBoxFull converts the subscription to a complete sing-box
// configuration JSON with outbounds and routing rules.
func ExportSingBoxFull(sub *Subscription) ([]byte, error) {
	outbounds := make([]map[string]interface{}, 0, len(sub.Protocols)+3)

	// Add selector and urltest outbounds.
	outboundNames := make([]string, 0, len(sub.Protocols))
	for _, p := range sub.Protocols {
		outboundNames = append(outboundNames, p.Name)
	}

	outbounds = append(outbounds, map[string]interface{}{
		"type":      "selector",
		"tag":       "proxy",
		"outbounds": append([]string{"auto"}, outboundNames...),
		"default":   "auto",
	})

	outbounds = append(outbounds, map[string]interface{}{
		"type":      "urltest",
		"tag":       "auto",
		"outbounds": outboundNames,
		"url":       "https://www.gstatic.com/generate_204",
		"interval":  "3m",
		"tolerance": 50,
	})

	// Add protocol outbounds.
	for _, p := range sub.Protocols {
		outbound := buildSingBoxOutbound(p)
		if outbound != nil {
			outbounds = append(outbounds, outbound)
		}
	}

	// Add direct and block outbounds.
	outbounds = append(outbounds,
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
			"rules": []map[string]interface{}{
				{
					"outbound": []string{"any"},
					"server":   "local",
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
		"outbounds": outbounds,
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

// buildSingBoxOutbound converts a ProtocolConfig to a sing-box outbound.
func buildSingBoxOutbound(p ProtocolConfig) map[string]interface{} {
	switch {
	case p.Security == "reality":
		return buildSingBoxVLESSReality(p)
	case p.Transport == "xhttp" || p.Transport == "ws":
		return buildSingBoxVLESSTransport(p)
	case p.Transport == "quic":
		return buildSingBoxHysteria2(p)
	default:
		return buildSingBoxVLESSBasic(p)
	}
}

func buildSingBoxVLESSReality(p ProtocolConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         p.Name,
		"server":      p.Host,
		"server_port": p.Port,
		"uuid":        p.UUID,
		"flow":        "xtls-rprx-vision",
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": p.SNI,
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": coalesce(p.Fingerprint, "chrome"),
			},
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": p.PublicKey,
				"short_id":   p.ShortID,
			},
		},
	}

	if len(p.Chain) > 0 {
		outbound["server"] = p.Chain[0].Host
		outbound["server_port"] = p.Chain[0].Port
	}

	return outbound
}

func buildSingBoxVLESSTransport(p ProtocolConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         p.Name,
		"server":      p.Host,
		"server_port": p.Port,
		"uuid":        p.UUID,
	}

	// TLS configuration.
	tlsCfg := map[string]interface{}{
		"enabled": true,
	}
	if p.SNI != "" {
		tlsCfg["server_name"] = p.SNI
	}
	if p.Fingerprint != "" {
		tlsCfg["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": p.Fingerprint,
		}
	}
	outbound["tls"] = tlsCfg

	// Transport configuration.
	switch p.Transport {
	case "xhttp":
		transport := map[string]interface{}{
			"type": "httpupgrade",
		}
		if p.Path != "" {
			transport["path"] = p.Path
		}
		if p.CDN != "" {
			transport["host"] = p.CDN
		}
		outbound["transport"] = transport

	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
		}
		if p.Path != "" {
			transport["path"] = p.Path
		}
		if p.CDN != "" {
			transport["headers"] = map[string]string{"Host": p.CDN}
		}
		outbound["transport"] = transport
	}

	return outbound
}

func buildSingBoxHysteria2(p ProtocolConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         p.Name,
		"server":      p.Host,
		"server_port": p.Port,
		"password":    p.UUID,
	}

	if p.Obfs != "" {
		outbound["obfs"] = map[string]interface{}{
			"type":     "salamander",
			"password": p.Obfs,
		}
	}

	if p.SNI != "" {
		outbound["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": p.SNI,
		}
	}

	return outbound
}

func buildSingBoxVLESSBasic(p ProtocolConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         p.Name,
		"server":      p.Host,
		"server_port": p.Port,
		"uuid":        p.UUID,
	}

	if p.Security == "tls" {
		tlsCfg := map[string]interface{}{
			"enabled": true,
		}
		if p.SNI != "" {
			tlsCfg["server_name"] = p.SNI
		}
		if p.Fingerprint != "" {
			tlsCfg["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": p.Fingerprint,
			}
		}
		outbound["tls"] = tlsCfg
	}

	return outbound
}

// formatPortRange converts a list of ports to a string range notation.
func formatPortRange(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}

	// Check if ports form a contiguous range.
	isContiguous := true
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[i-1]+1 {
			isContiguous = false
			break
		}
	}

	if isContiguous {
		return fmt.Sprintf("%d-%d", ports[0], ports[len(ports)-1])
	}

	var parts []string
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ",")
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
