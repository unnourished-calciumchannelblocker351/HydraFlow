<h1 align="center">🐉 HydraFlow</h1>

<p align="center">
  <strong>Bypass internet censorship. Works in Russia, China, Iran, Turkey, and other countries.</strong>
</p>

<p align="center">
  <a href="https://github.com/Evr1kys/HydraFlow/releases"><img src="https://img.shields.io/github/v/release/Evr1kys/HydraFlow?style=flat-square" alt="Release"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/actions"><img src="https://img.shields.io/github/actions/workflow/status/Evr1kys/HydraFlow/ci.yml?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Evr1kys/HydraFlow?style=flat-square" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/Evr1kys/HydraFlow"><img src="https://goreportcard.com/badge/github.com/Evr1kys/HydraFlow?style=flat-square" alt="Go Report"></a>
</p>

<p align="center">
  <b>English</b> &bull;
  <a href="README.ru.md">Русский</a> &bull;
  <a href="README.zh.md">中文</a>
</p>

---

## What is this?

HydraFlow is a tool that helps you bypass internet blocking.

You install it on a server (VPS) located outside the censored country, and it:
- Sets up **multiple bypass methods at once**
- Automatically detects your internet provider
- Gives you the **best connection method** for your specific network
- If one method gets blocked -- **switches to another automatically**

Works with popular apps: v2rayNG, Hiddify, Clash, sing-box.

---

## Install (30 seconds)

You need a VPS (server) outside the country with censorship. Any cheap VPS with Debian, Ubuntu, or CentOS will work.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
```

After installation you get:
- **A link** for v2rayNG -- copy and paste it
- **A subscription URL** -- add to any app for auto-updates
- **A QR code** -- scan with your phone

That's it. Now connect your devices.

---

## Connect your devices

### Android
1. Download [v2rayNG](https://play.google.com/store/apps/details?id=com.v2ray.ang) from Google Play (or from [GitHub](https://github.com/2dust/v2rayNG/releases))
2. Tap **+** > **Import config from clipboard** > paste the link
3. Tap the connect button

### iPhone
1. Download [Hiddify](https://apps.apple.com/app/hiddify-proxy-vpn/id6596777532) (free) or [Streisand](https://apps.apple.com/app/streisand/id6450534064) from the App Store
2. **Add profile** > paste the subscription URL
3. Connect

### Windows
1. Download [Hiddify](https://github.com/hiddify/hiddify-app/releases) or [v2rayN](https://github.com/2dust/v2rayN/releases)
2. Add the subscription URL
3. Connect

### macOS
1. Download [Hiddify](https://github.com/hiddify/hiddify-app/releases) or [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)
2. Add the subscription URL
3. Connect

### Linux
1. Download [Hiddify](https://github.com/hiddify/hiddify-app/releases) or [nekoray](https://github.com/MatsuriDayo/nekoray/releases)
2. Add the subscription URL
3. Connect

---

## How does it work?

HydraFlow sets up all known bypass methods at once:

| Method | What it does | When it helps |
|--------|-------------|---------------|
| **Reality** | Disguises your traffic as regular HTTPS (like visiting microsoft.com) | Main method, works almost everywhere |
| **WebSocket + CDN** | Routes traffic through Cloudflare | When direct access to the server is blocked by IP |
| **Hysteria2** | Fast encrypted tunnel over QUIC (UDP) | When you need maximum speed |
| **ShadowTLS** | Real TLS handshake that resists active probing | When censors actively probe suspicious servers |
| **Shadowsocks-2022** | Encrypted tunnel without TLS | Alternative when VLESS is blocked |
| **Chain (multi-hop)** | Traffic goes through an intermediate server | When all foreign IPs are blocked |
| **Fragmentation** | Breaks packets into small pieces | Bypasses DPI that doesn't reassemble fragments |

### Smart subscription -- the main feature

When your app (v2rayNG / Hiddify) updates the subscription, HydraFlow:
1. Detects your internet provider (MegaFon, MTS, Beeline, China Telecom...)
2. Checks which methods currently work for your provider
3. Sends you a config with **only the working methods**, sorted by speed

If censors block a method tomorrow, your next subscription update will exclude it and offer working alternatives.

---

## CDN setup (when direct access is blocked)

If your server's IP gets blocked, you can route traffic through Cloudflare CDN. This is very hard to block because your traffic mixes with millions of other websites.

[Detailed guide](docs/cdn-setup.md)

Short version:
1. Buy a domain (~$1 for .xyz)
2. Add it to [Cloudflare](https://dash.cloudflare.com/) (free plan)
3. Point it to your server IP (orange cloud on)
4. Run on your server:
   ```bash
   hydraflow cdn --domain your-domain.com
   ```

Now even if the IP is blocked, the CDN path works.

---

## Use with 3x-ui or Marzban

If you already have 3x-ui or Marzban installed, HydraFlow works alongside them. It reads their data and adds smart subscriptions on top:

```bash
# With 3x-ui
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh) --mode 3xui

# With Marzban
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh) --mode marzban
```

Your existing users get smart subscriptions automatically -- no migration needed.

---

## Multiple servers

If one server gets blocked, clients automatically switch to another.

[Detailed guide](docs/multi-server.md)

```bash
# On the primary server, add a second server:
hydraflow server add 1.2.3.4 my-secret-key

# Check all servers:
hydraflow server health
```

---

## Server management

```bash
hydraflow user add friend@mail.com    # Add a user
hydraflow user sub friend@mail.com    # Get their subscription link
hydraflow user list                   # List all users
hydraflow user del friend@mail.com    # Remove a user

hydraflow status                      # Server status
hydraflow server health               # Check all servers
hydraflow probe server.com:443        # Test for censorship

# Or with systemd:
systemctl status hydraflow            # Service status
journalctl -u hydraflow -f            # View logs
```

Docker:

```bash
docker run -d --name hydraflow --network host \
  -v /etc/hydraflow:/etc/hydraflow \
  ghcr.io/evr1kys/hydraflow:latest
```

---

## Comparison

| Feature | HydraFlow | Xray | sing-box | Amnezia | Outline |
|---------|-----------|------|----------|---------|---------|
| One-command install | Yes | No | No | Yes | Yes |
| Auto protocol selection | Yes | No | No | No | No |
| Works when IP is blocked (CDN) | Yes | Manual | Manual | No | No |
| Smart subscription by ISP | Yes | No | No | No | No |
| Multiple servers with failover | Yes | No | Partial | No | No |
| Multi-protocol | Yes | Yes | Yes | Partial | No |

---

## Troubleshooting

Can't connect? [Detailed troubleshooting guide](docs/troubleshooting.md)

Quick checks:
- Make sure the server is running: `hydraflow status`
- Check if ports are blocked: `hydraflow probe your-server:443`
- Try updating the subscription in your app
- If nothing works via direct connection, set up CDN (see above)

---

## Security and privacy

- Zero logging of your traffic or the sites you visit
- Subscription links are protected with cryptographic tokens
- Anonymous telemetry: only ISP name + which method works, no IP addresses
- All censorship probes run locally on your device

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## For developers

<details>
<summary>Architecture, building from source, and contributing</summary>

### Project structure

```
cmd/
  hydraflow/       CLI tool (user, server, status, probe commands)
  hf-server/       Server binary
  hydraflow-panel/ Web panel
smartsub/          Smart subscription engine (ISP detection, protocol scoring)
bypass/            Bypass engine (fragmentation, padding, desync, chain)
discovery/         Censorship detection (probes, fingerprinting, blocking map)
protocols/         Protocol implementations
  reality/         VLESS + Reality
  xhttp/           VLESS + XHTTP (CDN-compatible)
  hysteria2/       Hysteria2 (QUIC)
  shadowtls/       ShadowTLS v3
  chain/           Multi-hop proxy chains
  hydra/           HydraFlow native protocol
subscription/      Subscription format generation (V2Ray, Clash, sing-box)
integrations/      3x-ui and Marzban adapters
server/            Server installer and SNI finder
config/            Configuration management
```

### Key components

- **Smart Subscription** (`smartsub/`) -- The core differentiator. Detects ISP, scores protocols by success rate, outputs configs in all formats. [Subscription format spec](docs/subscription-format.md)
- **Bypass Engine** (`bypass/`) -- Fragmentation, padding, desync, DNS tricks. [Bypass methods docs](docs/bypass-methods.md)
- **Discovery** (`discovery/`) -- Censorship probes, TLS fingerprinting, blocking map aggregation. [Probe engine docs](docs/probe-engine.md)
- **Protocol Selection** -- Weighted scoring: `score = probe * 0.5 + history * 0.3 + priority * 0.2`. [Architecture docs](docs/architecture.md)

### Build from source

```bash
git clone https://github.com/Evr1kys/HydraFlow.git
cd HydraFlow
make build-all    # Builds hydraflow, hf-server, hydraflow-sub
make test         # Run tests
make lint         # Run linter
```

### API

HydraFlow uses gRPC for inter-server communication. Proto definitions are in `api/proto/`.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

</details>

---

## License

[MPL-2.0](LICENSE) -- free to use, modifications to HydraFlow code must remain open source.

## Acknowledgments

Built on the work of [Xray-core](https://github.com/XTLS/Xray-core), [Hysteria](https://github.com/apernet/hysteria), [ShadowTLS](https://github.com/ihciah/shadow-tls), [AmneziaVPN](https://github.com/amnezia-vpn), and the [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)/[zapret](https://github.com/bol-van/zapret) pioneers.

---

<p align="center">
  <em>"Cut one head, two more grow back."</em>
</p>
