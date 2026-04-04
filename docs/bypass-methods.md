# Bypass Methods Guide

HydraFlow supports multiple bypass methods simultaneously. Each method has different strengths against different censorship systems. This guide explains every method, when it works, when it fails, and how to configure it.

---

## Table of Contents

1. [Quick Reference Table](#quick-reference-table)
2. [Split Tunneling](#split-tunneling)
3. [VLESS + Reality](#vless--reality)
4. [VLESS + WebSocket + CDN (Cloudflare)](#vless--websocket--cdn-cloudflare)
5. [Shadowsocks-2022](#shadowsocks-2022)
6. [Multi-Hop (Chain)](#multi-hop-chain)
7. [Fragment Bypass](#fragment-bypass)
8. [Hysteria2 (QUIC)](#hysteria2-quic)
9. [ShadowTLS](#shadowtls)
10. [Method Selection Flowchart](#method-selection-flowchart)
11. [ISP-Specific Recommendations (Russia)](#isp-specific-recommendations-russia)

---

## Quick Reference Table

| Method | DPI Resistance | Speed | Setup Difficulty | Works When IP Blocked | Best Against |
|--------|---------------|-------|-----------------|----------------------|--------------|
| VLESS + Reality | High | Fast | Auto | No | TSPU, GFW, Sandvine |
| VLESS + WS + CDN | Very High | Medium | 10 min | **Yes** | IP blocking, all DPI |
| Shadowsocks-2022 | Medium | Fast | Auto | No | TLS-focused DPI |
| Multi-Hop (Chain) | Very High | Slow | Manual | Partial | Traffic analysis, IP blocking |
| Fragment Bypass | Medium | Fast | Auto | No | Basic DPI without TCP reassembly |
| Hysteria2 (QUIC) | Medium | Very Fast | Auto | No | Bandwidth-limited DPI |
| ShadowTLS | High | Fast | Auto | No | Active probing |

---

## Split Tunneling

### Why It Exists

Starting April 15, 2026, Russian platforms (Yandex, VK, Ozon, Wildberries, Sberbank, Gosuslugi, and others) are required to detect and block users connecting through VPNs. If you access these services through a proxy, you may be blocked or asked to disconnect your VPN.

Split tunneling solves this: traffic to Russian services goes **DIRECT** (bypassing the proxy), while blocked foreign sites (YouTube, Instagram, Twitter, etc.) go **through the proxy**. Users can access both without disconnecting.

### How It Works

HydraFlow configures routing rules at three levels:

1. **Server side (xray):** The xray routing config sends traffic destined for Russian domains and Russian IPs directly, without proxying. This is configured in `install.sh` and uses both explicit domain lists and `geosite:category-ru` for broad coverage.

2. **Client side (Clash/Clash Meta):** The subscription server generates Clash configs with `DOMAIN-SUFFIX` rules for major Russian platforms and `GEOSITE,category-ru,DIRECT` as a catch-all. Russian sites connect directly from the user's device.

3. **Client side (sing-box):** The subscription server generates sing-box configs with `domain_suffix` and `geosite`/`geoip` rules that route Russian traffic directly.

### Covered Platforms

The following platforms are explicitly listed (in addition to `geosite:category-ru` which covers thousands more):

| Category | Domains |
|----------|---------|
| Search & services | ya.ru, yandex.ru, yandex.com, yandex.net, dzen.ru |
| Social networks | vk.com, vk.me, ok.ru, mail.ru |
| E-commerce | ozon.ru, wildberries.ru, wb.ru, avito.ru, cian.ru |
| Banking | sber.ru, sberbank.ru, tinkoff.ru, alfa-bank.ru, vtb.ru |
| Government | gosuslugi.ru, mos.ru, nalog.ru, nalog.gov.ru |
| News & media | ria.ru, rbc.ru, tass.ru, rt.com, 1tv.ru |
| Streaming | kinopoisk.ru, ivi.ru, okko.tv, rutube.ru |
| Jobs | hh.ru |

### How Each Client Handles It

**v2rayNG / Hiddify (V2Ray format):**
Split tunneling is handled server-side. The xray config routes Russian domains directly before they reach the proxy tunnel. No client-side configuration needed.

**Clash / Clash Meta / Clash Verge Rev:**
The subscription includes `DOMAIN-SUFFIX` rules for each platform and `GEOSITE,category-ru,DIRECT` + `GEOIP,RU,DIRECT` catch-all rules. The client evaluates rules top-to-bottom and sends matching traffic directly.

**sing-box / Hiddify (sing-box mode):**
The subscription includes `domain_suffix`, `geosite`, and `geoip` route rules. Russian traffic is matched and sent to the `direct` outbound.

### Adding Custom Domains

If a Russian site is not in the list and gets blocked when accessed through the proxy, you can add it:

- The domain list is defined in `bypass/split.go` (source of truth)
- Server-side rules are in `install.sh` (xray routing section)
- Client-side rules are generated in `tools/sub-server.go`

After adding a domain, reinstall or regenerate configs:

```bash
# Regenerate xray config with updated domains
hydraflow config --regenerate

# Or reinstall (safe, preserves credentials)
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
```

### China and Iran

Split tunneling lists are also available for China (`ChineseDirectDomains`) and Iran (`IranianDirectDomains`) in `bypass/split.go`. These are not active by default but can be enabled for users in those countries.

---

## VLESS + Reality

### How It Works

Reality is a protocol that makes your proxy traffic look exactly like a legitimate TLS 1.3 connection to a real website (e.g., microsoft.com).

```
Client ──TLS ClientHello (SNI: www.microsoft.com)──→ DPI ──→ Your Server
                                                        │
                                              DPI sees:
                                              "Normal HTTPS to Microsoft"
                                              ✓ Valid TLS 1.3
                                              ✓ Known SNI domain
                                              ✓ Chrome-like fingerprint
```

**Technical details:**
- Uses uTLS to mimic Chrome's TLS fingerprint (JA3/JA4 hash matches real Chrome)
- SNI points to a real website (default: `www.microsoft.com`)
- Server has Reality key pair; client verifies server using `public_key` + `short_id`
- The real website (microsoft.com) is never actually contacted
- If anyone connects to your server without the correct Reality credentials, they get proxied to the real microsoft.com (probe resistance)

### When It Works

- Most ISPs in Russia, Iran, Turkey, Egypt
- ISPs that rely on TLS fingerprinting and SNI analysis
- Networks where the server IP itself is not blocked

### When It Fails

- **IP blocking:** If the DPI blocks your server's IP address directly (not based on protocol), Reality cannot help. Use CDN instead.
- **IP + SNI correlation:** Some advanced DPI (TSPU in certain regions) notices that the IP address does not belong to Microsoft's AS, but the SNI says `www.microsoft.com`. This mismatch triggers blocking.
- **Mobile operators in Russia:** MegaFon and MTS have been observed blocking Reality on mobile networks since late 2025.

### How to Fix When Blocked

**Change SNI domain:**

```bash
# List available SNI domains that are safe for your server's IP
hydraflow probe --sni-scan

# Change SNI to a domain hosted on the same hoster/CDN as your server
hydraflow config --sni "cdn.example-hoster.com"
```

Good SNI choices:
- Domains hosted on the same hosting provider as your VPS
- Large CDN domains (Cloudflare, Akamai, Fastly sites)
- Avoid obvious choices like `google.com` (too scrutinized)

**Use a different port:**

```bash
# Default is 443, try other common HTTPS ports
hydraflow config --port 8443
hydraflow config --port 2083   # Cloudflare-associated port
hydraflow config --port 2096
```

**Switch to CDN if IP is blocked:**

```bash
hydraflow cdn --domain your-domain.xyz
# See docs/cdn-setup.md for full guide
```

### Configuration

Reality is configured automatically during installation. Manual configuration:

```bash
# View current Reality config
hydraflow config --show reality

# Regenerate keys
hydraflow config --reality-regenerate

# Change SNI
hydraflow config --sni "www.microsoft.com"

# Change fingerprint (chrome, firefox, safari, ios, android, random)
hydraflow config --fingerprint chrome
```

---

## VLESS + WebSocket + CDN (Cloudflare)

### How It Works

Traffic is wrapped in WebSocket frames inside a standard HTTPS connection, routed through Cloudflare's CDN network.

```
Client ──HTTPS──→ Cloudflare Edge ──HTTPS──→ Your Server
   │                    │
   │  DPI sees:         │  Already past DPI:
   │  - IP: 104.21.x.x │  - Encrypted tunnel
   │    (Cloudflare)    │  - From CF to your server
   │  - SNI: your.xyz   │
   │  - Normal HTTPS    │
```

**Technical details:**
- Client establishes HTTPS connection to Cloudflare (not your server)
- Inside HTTPS, a WebSocket upgrade happens
- Proxy traffic flows inside the WebSocket stream
- Your server receives traffic from Cloudflare's IP, not the client's

### When It Works

**Almost always.** This is the most reliable bypass method because:
- DPI sees traffic to Cloudflare's IP addresses, shared by millions of sites
- The protocol is standard HTTPS + WebSocket, used by countless legitimate services
- Blocking Cloudflare would break Discord, Canva, hundreds of thousands of corporate sites
- Even TSPU cannot practically block all Cloudflare traffic

### Downsides

- **Slower than direct:** Traffic makes an extra hop through Cloudflare's edge server. Expect +20-80ms latency.
- **Requires a domain:** You need a domain pointed through Cloudflare (or use Workers, see [cdn-setup.md](cdn-setup.md)).
- **Cloudflare free tier limits:** No hard bandwidth limit, but Cloudflare may throttle sustained high-throughput WebSocket connections on free plans.

### Setup

Full setup guide: [cdn-setup.md](cdn-setup.md)

Quick version:

```bash
# 1. Buy a domain, add to Cloudflare, point A record to server IP (proxied)
# 2. On your server:
hydraflow cdn --domain your-domain.xyz

# 3. Verify
curl -I https://your-domain.xyz
# Look for cf-ray header
```

### When to Use

- When direct Reality connection is blocked (IP blocked by ISP)
- As a permanent fallback in your subscription (always available)
- When traveling to heavily censored networks where you cannot predict what is blocked

---

## Shadowsocks-2022

### How It Works

Shadowsocks-2022 (SS-2022) is a completely encrypted stream protocol. Unlike VLESS/Reality which wraps traffic in TLS, SS-2022 uses its own authenticated encryption from byte zero. There is no TLS handshake for DPI to analyze.

```
Client ──[encrypted blob, no recognizable headers]──→ DPI ──→ Your Server
                                                        │
                                              DPI sees:
                                              "Unknown encrypted data"
                                              ? Not HTTP
                                              ? Not TLS
                                              ? No SNI to inspect
```

**Technical details:**
- Uses AEAD (AES-256-GCM or ChaCha20-Poly1305) from the first byte
- No protocol header, no version field, no identifiable pattern
- Server rejects replayed packets (anti-replay with sliding window)
- Uses pre-shared key (PSK) instead of UUID

### When It Works

- ISPs that focus detection on TLS-based protocols (looking for TLS fingerprints, SNI values)
- Networks where Reality is blocked but unknown protocols are allowed through
- Situations where the DPI looks specifically for proxy protocol signatures

### When It Fails

- **Behavioral analysis:** Advanced DPI (TSPU, GFW) can detect that traffic looks "too random" -- real HTTPS has recognizable patterns (packet sizes, timing). Pure encrypted streams stand out statistically.
- **Protocol whitelisting:** If the ISP only allows known protocols (HTTP, HTTPS, DNS) and blocks everything else, SS-2022 will be blocked.
- **Active probing:** If the DPI sends probe packets to your server port and gets encrypted garbage back (instead of a valid HTTP or TLS response), it may flag the server.

### Configuration

SS-2022 is set up automatically during installation alongside Reality:

```bash
# View SS-2022 config
hydraflow config --show ss2022

# Change encryption method
hydraflow config --ss2022-method aes-256-gcm
hydraflow config --ss2022-method chacha20-poly1305   # Better for ARM devices

# Change port (default: 8388)
hydraflow config --ss2022-port 8388

# Regenerate key
hydraflow config --ss2022-regenerate
```

### Combination with Other Methods

SS-2022 works best as a secondary protocol. Keep Reality as primary and fall back to SS-2022 when Reality is blocked by TLS-specific DPI:

```yaml
protocols:
  - name: reality-direct
    priority: 1
  - name: ss-2022
    priority: 3    # Fallback when Reality fails
```

---

## Multi-Hop (Chain)

### How It Works

Traffic is routed through two or more servers in sequence. The client connects to the first server, which forwards traffic to the second server, which exits to the internet.

```
Client ──→ Server 1 (RU VPS) ──→ Server 2 (NL VPS) ──→ Internet
   │              │                      │
   │  DPI sees:   │                      │
   │  Traffic to  │  Traffic from        │  Exit point
   │  a Russian   │  Russia to NL,       │  (clean IP)
   │  IP address  │  encrypted           │
```

### Why It Helps

- The DPI sees traffic going to a **domestic Russian IP address**, not a foreign one
- Traffic from one Russian server to a foreign one looks like normal server-to-server communication
- The Russian relay server itself is not blocked because it has a Russian IP
- Even if the DPI inspects the traffic between RU and NL, it is encrypted and looks like inter-server traffic

### When It Works

- When all foreign IPs are being scrutinized or throttled
- When the censor focuses on blocking connections to known VPN server ranges (foreign hosting providers)
- When you need to hide that you are using a proxy (traffic looks domestic)

### When It Fails

- **Russian VPS also censored:** If the RU relay server's ISP also runs DPI on outgoing traffic, the chain just moves the problem
- **Slow:** Every hop adds latency. With a 2-hop chain through RU and NL, expect +50-150ms
- **More complex:** Two servers to maintain, two points of failure

### Setup

**Step 1: Install HydraFlow on both servers.**

```bash
# On Russian relay VPS
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)

# On foreign exit VPS
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
```

**Step 2: Configure chain on the primary (foreign) server.**

```bash
hydraflow chain add \
  --relay-ip 91.200.xx.xx \
  --relay-api-key "sk_api_xxxxx" \
  --exit-server self
```

This configures:
- The Russian server as a relay (accepts client connections, forwards to exit)
- The foreign server as the exit point
- Adds the chain configuration to the subscription

**Step 3: Verify.**

```bash
hydraflow chain status
```

Output:

```
Chain: ru-relay → nl-exit
  Relay: 91.200.xx.xx (Russia, Rostelecom)  Status: UP
  Exit:  185.123.45.67 (Netherlands, Hetzner) Status: UP
  Latency: relay=15ms exit=62ms total=77ms
```

### Subscription format for chains

The `.hydra.yml` subscription automatically includes chain configurations:

```yaml
- name: "reality-chain"
  priority: 4
  transport: tcp
  security: reality
  chain:
    - host: "91.200.xx.xx"    # relay
      port: 443
      sni: "ya.ru"
      public_key: "..."
    - host: "185.123.45.67"   # exit
      port: 443
      sni: "www.microsoft.com"
      public_key: "..."
```

---

## Fragment Bypass

### How It Works

Many DPI systems only inspect the first TCP segment of a connection. The TLS ClientHello (which contains the SNI field that DPI checks) is normally sent in a single TCP segment. Fragment bypass splits the ClientHello into multiple small TCP segments.

```
Normal TLS handshake:
  Client ──[full ClientHello in 1 packet]──→ DPI ──→ Server
                                               │
                                     DPI reads SNI: "your-server.com" → BLOCK

Fragmented TLS handshake:
  Client ──[fragment 1: 50 bytes]──→ DPI ──→ Server
         ──[fragment 2: 50 bytes]──→ DPI ──→
         ──[fragment 3: 50 bytes]──→ DPI ──→
                                       │
                             DPI sees fragment 1:
                             incomplete ClientHello,
                             can't extract SNI → PASS
```

### When It Works

- DPI that does not reassemble TCP streams (only inspects the first segment)
- Basic DPI deployed by smaller ISPs
- Some configurations of Sandvine

### When It Fails

- **TSPU with full TCP reassembly:** The Russian TSPU can reassemble fragmented TCP streams and extract the SNI from reassembled data. Fragment bypass alone does not work against modern TSPU.
- **DPI that blocks fragmented ClientHello entirely:** Some DPI specifically flags connections where the ClientHello is fragmented as suspicious.

### How HydraFlow Uses It

HydraFlow's probe engine automatically tests multiple fragment sizes (1, 2, 5, 10, 50, 100, 200 bytes) and finds the optimal size that bypasses the DPI. This happens during the initial connection probe.

```bash
# View probe results including fragment test
hydraflow probe --target your-server:443

# Output includes:
# FragmentBypass: PASS
#   Working sizes: [50, 100, 200]
#   Optimal: 50 bytes
#   DPI does NOT reassemble TCP streams
```

Fragment bypass is applied **automatically** when the probe engine detects it is effective. No manual configuration needed.

**Manual override:**

```bash
# Force specific fragment size
hydraflow config --fragment-size 50

# Disable fragment bypass
hydraflow config --fragment-size 0

# Let HydraFlow auto-detect (default)
hydraflow config --fragment-size auto
```

### Combination with Other Methods

Fragment bypass is not a standalone method -- it enhances other methods. For example:
- **Reality + Fragment:** Fragments the TLS ClientHello so DPI cannot extract the SNI to perform IP+SNI correlation
- **CDN + Fragment:** Usually not needed (Cloudflare handles TLS termination)

---

## Hysteria2 (QUIC)

### How It Works

Hysteria2 uses the QUIC protocol (UDP-based) with obfuscation. QUIC is the same protocol used by Google, YouTube, and modern web services.

```
Client ──[QUIC/UDP packets]──→ DPI ──→ Your Server
                                  │
                        DPI sees:
                        UDP traffic to port 443
                        Looks like QUIC (Google uses this)
```

**Technical details:**
- Based on QUIC (HTTP/3 transport)
- Uses Salamander obfuscation to disguise the QUIC Initial packet
- Supports port hopping (switches ports periodically to avoid blocking)
- Excellent throughput due to QUIC's congestion control (Brutal CC)

### When It Works

- Networks that allow UDP traffic (many ISPs do)
- When TCP-based protocols are throttled or blocked but UDP is not inspected
- For high-throughput use cases (streaming, downloads) -- QUIC handles packet loss better than TCP

### When It Fails

- **UDP blocked:** Some ISPs block all UDP traffic except DNS (port 53). Russia's TSPU has been observed blocking QUIC/UDP selectively.
- **QUIC-specific blocking:** ISPs that specifically detect and block QUIC Initial packets.

### Configuration

```bash
# Check if UDP/QUIC works on your network
hydraflow probe --quic

# View Hysteria2 config
hydraflow config --show hysteria2

# Enable port hopping (cycles through multiple ports)
hydraflow config --hysteria2-ports 443,8443,10443

# Change obfuscation password
hydraflow config --hysteria2-regenerate
```

### Port Hopping

When the ISP blocks specific UDP ports, Hysteria2 can hop between multiple ports:

```yaml
- name: "hysteria2"
  transport: quic
  ports: [443, 8443, 10443, 20443, 30443]
  obfs: salamander
```

The client connects to port 443, then periodically switches to 8443, 10443, etc. If the ISP blocks one port, traffic continues on the next.

---

## ShadowTLS

### How It Works

ShadowTLS performs a **real TLS handshake** with a legitimate server (e.g., `www.microsoft.com`), then hijacks the connection after the handshake is complete.

```
Client ──TLS ClientHello──→ DPI ──→ Your Server ──→ real microsoft.com
       ←─TLS ServerHello───  DPI ←──            ←──  real microsoft.com
       ──Application Data──→ DPI ──→ Your Server (proxy data inside)
                               │
                     DPI sees:
                     Complete, valid TLS handshake
                     with real microsoft.com cert
                     ✓ Valid certificate chain
                     ✓ Real server response
```

### Why This Matters

Active probing is a technique where the DPI connects to your server to check if it is really microsoft.com. With Reality, the server has a fake certificate. With ShadowTLS, the TLS handshake is real -- the DPI gets a real microsoft.com certificate because the handshake is actually proxied to the real microsoft.com.

### When It Works

- Against DPI that performs active probing (GFW, TSPU)
- When Reality's fake TLS is detected
- Networks with strict TLS certificate validation

### When It Fails

- **Traffic analysis:** The application data after the handshake is not real HTTPS, so statistical analysis can detect the difference
- **Not widely supported by clients:** Fewer client apps support ShadowTLS compared to Reality

### Configuration

```bash
# View ShadowTLS config
hydraflow config --show shadowtls

# Change the handshake server (the real site to mimic)
hydraflow config --shadowtls-server "www.microsoft.com:443"
```

---

## Method Selection Flowchart

Use this to decide which method to try when something is blocked.

```
START: Can you connect to anything?
  │
  ├─ NO → Check if your VPS is actually running:
  │        systemctl status hydraflow
  │        Check firewall: ufw status
  │
  ├─ YES → Try Reality (default, fastest)
  │    │
  │    ├─ Works? → Done. Use Reality.
  │    │
  │    └─ Blocked? → What error?
  │         │
  │         ├─ Connection timeout → IP might be blocked
  │         │   → Set up CDN (docs/cdn-setup.md)
  │         │   → Or try Multi-Hop through RU relay
  │         │
  │         ├─ Connection reset → DPI blocks the protocol
  │         │   → Try changing SNI: hydraflow config --sni "other-domain.com"
  │         │   → Try Fragment: hydraflow probe --fragment
  │         │   → Try SS-2022 (different protocol signature)
  │         │   → Try ShadowTLS
  │         │
  │         ├─ TLS handshake fail → SNI/fingerprint blocked
  │         │   → Change SNI to domain on same hoster
  │         │   → Change fingerprint: hydraflow config --fingerprint firefox
  │         │   → Use CDN (no direct TLS to your server)
  │         │
  │         └─ Works but very slow → Throttled
  │             → Try Hysteria2 (QUIC, better congestion control)
  │             → Try CDN (different routing)
  │             → Try different port
  │
  └─ Everything blocked → Last resort options:
       → CDN via Cloudflare Workers (no domain needed)
       → Multi-Hop: RU relay → foreign exit
       → Try a completely different VPS/provider/country
```

---

## ISP-Specific Recommendations (Russia)

Based on crowdsourced blocking map data. Updated periodically -- check your HydraFlow subscription for the latest recommendations.

### Rostelecom (AS12389, AS25513)

| Method | Status | Notes |
|--------|--------|-------|
| Reality | Works with correct SNI | Use SNI for domain hosted on same provider as your VPS |
| CDN (Cloudflare) | Works | Recommended fallback |
| SS-2022 | Works intermittently | May be detected by behavioral analysis |
| Hysteria2 | QUIC throttled | UDP not fully blocked but slow |
| Fragment | Does not work | TSPU reassembles TCP |

**Recommendation:** Reality (primary) + CDN (fallback)

### MegaFon (AS31133)

| Method | Status | Notes |
|--------|--------|-------|
| Reality | Blocked on mobile | Works on home broadband in some regions |
| CDN (Cloudflare) | Works | Only reliable method on mobile |
| SS-2022 | Blocked | Behavioral analysis active |
| Hysteria2 | Blocked | UDP blocked |
| Multi-Hop | Works | RU relay → foreign exit |

**Recommendation:** CDN (primary) + Multi-Hop (fallback)

### MTS (AS8359)

| Method | Status | Notes |
|--------|--------|-------|
| Reality | Intermittent | Works in some regions, blocked in others |
| CDN (Cloudflare) | Works | Reliable |
| SS-2022 | Blocked | |
| Hysteria2 | Blocked | UDP blocked on mobile |
| Fragment | Does not work | |

**Recommendation:** CDN (primary) + Reality with hoster-matching SNI (secondary)

### Beeline (AS3216)

| Method | Status | Notes |
|--------|--------|-------|
| Reality | Works | Least aggressive DPI among major ISPs |
| CDN (Cloudflare) | Works | |
| SS-2022 | Works | |
| Hysteria2 | Works | |

**Recommendation:** Reality (primary), any method works

### Tele2 (AS15378)

| Method | Status | Notes |
|--------|--------|-------|
| Reality | Works on broadband, intermittent on mobile | |
| CDN (Cloudflare) | Works | |
| SS-2022 | Works | |

**Recommendation:** Reality (primary) + CDN (fallback for mobile)

> **Important:** These recommendations are based on community data and change as ISPs update their DPI rules. Always check the latest blocking map data via your HydraFlow subscription. Enable anonymous telemetry to contribute your data and help others: `hydraflow config --telemetry on`
