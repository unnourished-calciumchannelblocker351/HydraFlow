# Architecture

## Overview

HydraFlow is built around three core principles:

1. **No single point of failure** — Multiple protocols ensure that blocking one method doesn't cut off access
2. **Automatic adaptation** — The system detects censorship conditions and responds without user intervention
3. **Community intelligence** — Anonymous, aggregated data from all clients improves protocol selection for everyone

## System Components

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENT SIDE                            │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Subscription│  │ Probe Engine │  │ Protocol Selector   │ │
│  │ Manager     │──│              │──│                     │ │
│  │             │  │ - Port test  │  │ - Score calculation │ │
│  │ - Fetch     │  │ - TLS test   │  │ - History tracking  │ │
│  │ - Cache     │  │ - SNI test   │  │ - ISP matching      │ │
│  │ - Auto-     │  │ - QUIC test  │  │ - Auto fallback     │ │
│  │   refresh   │  │ - Fragment   │  │                     │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                │                      │            │
│  ┌──────▼────────────────▼──────────────────────▼──────────┐ │
│  │                    Core Engine                           │ │
│  │                                                          │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │ │
│  │  │ Reality  │ │  XHTTP   │ │Hysteria2 │ │ShadowTLS │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │ │
│  │                                                          │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │            Connection Monitor                     │   │ │
│  │  │  - Latency tracking                              │   │ │
│  │  │  - Throughput measurement                        │   │ │
│  │  │  - Degradation detection                         │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  └──────────────────────────┬───────────────────────────────┘ │
│                             │                                 │
│  ┌──────────────────────────▼───────────────────────────────┐ │
│  │              TUN / SOCKS5 / HTTP Proxy                    │ │
│  └───────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                              │
                    ══════════╪══════════  (censored network)
                              │
┌──────────────────────────────────────────────────────────────┐
│                        SERVER SIDE                            │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                Multi-Protocol Listener                    │ │
│  │                                                          │ │
│  │  :443/tcp ──→ nginx SNI router ──→ Reality (xray)       │ │
│  │                                ──→ ShadowTLS             │ │
│  │  :443/udp ──→ Hysteria2                                  │ │
│  │  CDN      ──→ Cloudflare ──→ XHTTP (xray)               │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │ Subscription    │  │ Blocking Map Aggregator          │  │
│  │ Server          │  │                                  │  │
│  │ - Generate      │  │ - Collect anonymous reports      │  │
│  │ - Serve configs │  │ - Aggregate by ISP               │  │
│  │ - Push updates  │  │ - Update subscription configs    │  │
│  └─────────────────┘  └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Protocol Selection Algorithm

The selector uses a weighted scoring system:

```
score = probe_score * 0.5 + history_score * 0.3 + priority_score * 0.2
```

Where:
- **probe_score** (50%) — Results from censorship detection probes
- **history_score** (30%) — Historical success rate on this network
- **priority_score** (20%) — Configured priority order

The algorithm ensures that:
1. Protocols that definitely don't work (probes failed) are excluded
2. Protocols that historically work well are preferred
3. User-configured priorities serve as a tiebreaker

## Data Flow

### Connection Establishment

```
1. Fetch subscription (cached, refreshed periodically)
2. Check blocking map for ISP-specific recommendations
3. Run probe tests (parallel, 2-5 second timeout)
4. Score and rank available protocols
5. Attempt connection with highest-ranked protocol
6. On failure: try next protocol (automatic fallback)
7. On success: start connection monitor
8. Report anonymous success/failure to blocking map
```

### Subscription Update

```
1. Server detects blocking pattern change (via aggregated reports)
2. Server updates subscription config (new priorities, new servers)
3. Client fetches updated config on next refresh interval
4. Client re-evaluates protocol selection with new data
```

## Security Architecture

### Threat Model

| Threat | Mitigation |
|--------|------------|
| DPI signature detection | Multiple protocols with different signatures |
| TLS fingerprinting | Chrome-mimicking TLS stack per protocol |
| IP/ASN correlation | CDN-based protocols use CDN IPs |
| Active probing | Reality's probe resistance, ShadowTLS real handshake |
| Traffic analysis | Protocol switching, traffic padding |
| Server discovery | Subscription tokens, no server IP in DNS |

### Privacy

- Telemetry contains only ISP AS number + protocol status
- No IP addresses are stored or transmitted
- Subscription tokens are cryptographically random
- No correlation between users and traffic patterns is possible
