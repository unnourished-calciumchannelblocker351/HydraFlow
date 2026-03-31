# HydraFlow Subscription Format

## Overview

The `.hydra.yml` format extends traditional VPN subscription systems with multi-protocol support, priority ordering, and ISP-specific recommendations. It is designed to be:

- **Human-readable** — YAML-based, easy to edit and debug
- **Machine-parseable** — Strict schema for automated processing  
- **Backwards-compatible** — Can export to V2Ray base64, Clash YAML, sing-box JSON
- **Compact** — Typically under 2KB for a full multi-protocol config

## Format Specification

### Version 1

```yaml
# Required: format version
version: 1

# Required: server identifier (for display, not connection)
server: "nl-1.example.com"

# Required: last update timestamp (RFC 3339)
updated: "2026-04-04T12:00:00Z"

# Optional: seconds until client should refresh
ttl: 3600

# Required: ordered list of protocol configurations
protocols:
  - name: "reality-direct"        # Unique identifier
    priority: 1                    # Lower = higher priority
    transport: tcp                 # tcp, xhttp, quic, shadowtls, wireguard
    security: reality              # reality, tls, none
    host: "server.example.com"
    port: 443
    uuid: "a1b2c3d4-..."
    sni: "www.microsoft.com"
    public_key: "..."
    short_id: "abcd1234"
    spider_x: "/path"
    fingerprint: "chrome"

  - name: "xhttp-cdn"
    priority: 2
    transport: xhttp
    security: tls
    cdn: cloudflare
    host: "cdn.example.com"
    port: 443
    uuid: "a1b2c3d4-..."
    path: "/api/v2/stream"

  - name: "hysteria2"
    priority: 3
    transport: quic
    host: "server.example.com"
    ports: [443, 8443, 10443]      # Port hopping
    obfs: salamander
    uuid: "password-string"

  - name: "reality-chain"
    priority: 4
    transport: tcp
    security: reality
    chain:                          # Multi-hop
      - host: "relay.example.com"
        port: 443
        sni: "ya.ru"
        public_key: "..."
      - host: "exit.example.com"
        port: 443
        sni: "www.microsoft.com"
        public_key: "..."
    uuid: "a1b2c3d4-..."

# Optional: ISP-specific guidance
blocking_map:
  megafon:
    blocked: [reality-direct]
    recommended: [xhttp-cdn, reality-chain]
    notes: "Reality blocked since 2026-02"
  mts:
    blocked: [reality-direct, hysteria2]
    recommended: [xhttp-cdn]
  beeline:
    blocked: []
    recommended: [reality-direct]
```

### Fields Reference

#### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | int | Yes | Format version (currently 1) |
| `server` | string | Yes | Server display name |
| `updated` | datetime | Yes | Last modification time |
| `ttl` | int | No | Refresh interval in seconds |
| `protocols` | list | Yes | Protocol configurations |
| `blocking_map` | map | No | ISP-specific recommendations |

#### Protocol

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier |
| `priority` | int | Yes | Selection priority (1 = highest) |
| `transport` | string | Yes | Transport type |
| `security` | string | Yes | Security layer |
| `host` | string | Conditional | Server hostname/IP |
| `port` | int | Conditional | Server port |
| `uuid` | string | Conditional | Client UUID or password |

## Export Formats

HydraFlow subscriptions can be exported to standard formats:

### V2Ray Base64

```
hydraflow export --format v2ray --input config.hydra.yml
```

Outputs standard base64-encoded VLESS/VMess links.

### Clash Meta YAML

```
hydraflow export --format clash --input config.hydra.yml
```

Outputs Clash-compatible proxy configuration with auto-select group.

### sing-box JSON

```
hydraflow export --format singbox --input config.hydra.yml
```

Outputs sing-box outbound configuration.

## Serving Subscriptions

The HydraFlow server serves subscriptions via HTTP:

```
GET /sub/{token}
Accept: application/x-hydraflow+yaml    → .hydra.yml format
Accept: text/plain                       → V2Ray base64 (compatibility)
Accept: application/x-clash+yaml         → Clash format

GET /sub/{token}?format=hydra            → Force .hydra.yml
GET /sub/{token}?format=v2ray            → Force V2Ray base64
GET /sub/{token}?format=clash            → Force Clash YAML
GET /sub/{token}?format=singbox          → Force sing-box JSON
```

Content negotiation ensures compatibility with existing V2Ray clients while providing full functionality to HydraFlow clients.
