# Security Policy

## Threat Model

HydraFlow operates in adversarial network environments where state-level actors actively attempt to detect and block circumvention traffic. Our security model considers:

**Adversary capabilities:**
- Deep Packet Inspection (DPI) on all network traffic
- TLS fingerprinting (JA3/JA4)
- IP/ASN correlation with SNI domains
- Traffic pattern analysis (timing, packet sizes, flow direction)
- Active probing of suspected proxy servers
- Replay attacks against proxy protocols

**What we protect against:**
- Traffic identification and blocking by DPI systems
- Server discovery through active probing
- User identification through traffic analysis
- Data exposure through protocol vulnerabilities

**What is out of scope:**
- Endpoint compromise (malware on user device)
- Physical access to server hardware
- Compromise of the CDN provider (Cloudflare, etc.)
- Legal compulsion of the server operator

## Data Collection

### Telemetry (opt-in)
- ISP/AS number (derived from client IP, IP is never stored)
- Protocol connection success/failure status
- Approximate latency measurements
- Client version and platform

### What we never collect
- User IP addresses
- Traffic content or destinations
- Connection timestamps tied to users
- Any personally identifiable information

## Reporting Vulnerabilities

If you discover a security vulnerability in HydraFlow, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email: security@hydraflow.dev
3. Include a description of the vulnerability and steps to reproduce
4. We will acknowledge receipt within 48 hours
5. We aim to release a fix within 7 days for critical issues

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Yes (current development) |

## Security Design Principles

1. **Defense in depth** — Multiple protocols ensure one being compromised doesn't affect others
2. **Minimal fingerprint** — Each protocol implementation minimizes distinguishable network characteristics
3. **Forward secrecy** — All protocols use ephemeral key exchange
4. **Fail closed** — If censorship detection fails, fall back to the most robust (CDN-based) protocol
5. **Zero knowledge** — The server operator cannot identify which user generated which traffic
