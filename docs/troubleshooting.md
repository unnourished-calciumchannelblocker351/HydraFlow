# Troubleshooting Guide

Practical solutions for common HydraFlow problems. Every section includes exact commands to run.

---

## Table of Contents

1. [Can't Connect After Install](#cant-connect-after-install)
2. [Works on WiFi but Not Mobile Data](#works-on-wifi-but-not-mobile-data)
3. [Slow Speed](#slow-speed)
4. [Was Working, Suddenly Stopped](#was-working-suddenly-stopped)
5. [v2rayNG Says "Connection Refused"](#v2rayng-says-connection-refused)
6. [Subscription Not Updating](#subscription-not-updating)
7. [CDN Not Working](#cdn-not-working)
8. [Multi-Server Issues](#multi-server-issues)
9. [Checking Logs](#checking-logs)
10. [Restarting Services](#restarting-services)
11. [Switching Protocols](#switching-protocols)
12. [Complete Diagnostic Checklist](#complete-diagnostic-checklist)

---

## Can't Connect After Install

### Step 1: Check HydraFlow is running

```bash
systemctl status hydraflow
```

**Expected:** `active (running)`.

If it shows `failed` or `inactive`:

```bash
# View why it failed
journalctl -u hydraflow -n 50 --no-pager

# Try restarting
systemctl restart hydraflow

# If still failing, check config
hydraflow config --validate
```

### Step 2: Check xray is running

```bash
systemctl status xray
```

If xray is not running:

```bash
journalctl -u xray -n 50 --no-pager
# Common issue: invalid xray config
xray run -test -config /etc/hydraflow/xray.json
```

### Step 3: Check firewall

```bash
# UFW
ufw status

# iptables
iptables -L -n | grep -E '443|8388'

# Check if port 443 is actually open
ss -tlnp | grep :443
```

If port 443 is not in the firewall allow list:

```bash
ufw allow 443/tcp
ufw allow 443/udp   # For Hysteria2
ufw allow 8388/tcp  # For SS-2022 (if using default port)
ufw reload
```

### Step 4: Test port from outside

From your local machine (not the server):

```bash
# Test TCP connectivity
nc -zv YOUR_SERVER_IP 443

# Test TLS handshake
openssl s_client -connect YOUR_SERVER_IP:443 -servername www.microsoft.com

# Expected: TLS handshake completes, shows certificate info
# If timeout: port is blocked by ISP or firewall
# If connection refused: nothing listening on port 443
```

### Step 5: Test from the server itself

```bash
# On the server, check xray is listening
ss -tlnp | grep xray

# Test local TLS connection
openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com
```

### Step 6: Check the VLESS link is correct

```bash
hydraflow info
```

Compare the output with what you pasted into v2rayNG/Hiddify. Common mistakes:
- Missing or wrong `public_key` (Reality)
- Wrong port number
- Wrong server IP (typo)
- Extra whitespace in the link when copy-pasting

---

## Works on WiFi but Not Mobile Data

This almost always means the mobile operator's DPI is blocking the protocol. Mobile ISPs in Russia (MegaFon, MTS) are more aggressive than broadband ISPs.

### Quick fix: Switch to CDN

CDN through Cloudflare works on virtually all mobile networks. See [cdn-setup.md](cdn-setup.md).

If CDN is already set up:

1. In your client app, switch to the CDN node
2. If you only see direct nodes, refresh subscription

### Diagnose which protocol is blocked

```bash
# On the server, check if mobile ISP is in blocking map
hydraflow blocking-map --check
```

From your phone (using a terminal app like Termux on Android):

```bash
# Test Reality
curl -x socks5://127.0.0.1:10808 https://google.com
# (requires proxy running locally)

# Or simpler: just try each node in your client app
# - Direct Reality node → if fails, Reality is blocked
# - CDN node → should work
# - SS-2022 node → may or may not work
```

### ISP-specific solutions

| Mobile ISP | What Works | What to Do |
|------------|-----------|------------|
| MegaFon | CDN only | Set up Cloudflare CDN |
| MTS | CDN, sometimes Reality | Try CDN first, Reality as backup |
| Beeline | Everything | No action needed |
| Tele2 | CDN, Reality (intermittent) | CDN primary, Reality backup |
| Yota | Same as parent ISP (MegaFon) | CDN only |

---

## Slow Speed

### Step 1: Identify the bottleneck

```bash
# Check server load
htop
# or
top -bn1 | head -20

# Check bandwidth on server
iperf3 -s   # On server
iperf3 -c YOUR_SERVER_IP   # From your machine (direct, not through proxy)

# Check xray CPU usage
ps aux | grep xray
```

### Step 2: Try a different protocol

Some protocols are faster than others on the same network:

| Protocol | Typical Speed | Why |
|----------|--------------|-----|
| Reality (TCP) | Fast | Direct connection, minimal overhead |
| CDN (WebSocket) | Medium | Extra hop through Cloudflare adds latency |
| Hysteria2 (QUIC) | Very fast | QUIC handles packet loss better, good for lossy networks |
| SS-2022 | Fast | Low overhead |
| Chain | Slow | Multiple hops, each adds latency |

Switch protocols in your client app and test speed with [fast.com](https://fast.com) or [speedtest.net](https://speedtest.net).

### Step 3: Check server location

Latency depends on geographic distance. If you are in Moscow and your server is in Singapore, you will have 200ms+ latency. Choose servers closer to you:

- Netherlands, Germany, Finland -- good for Russia (30-60ms)
- US -- far (150-200ms)
- Singapore, Japan -- very far (200-300ms)

### Step 4: Check if ISP is throttling

```bash
# Test speed without proxy
speedtest-cli

# Test speed through proxy
# If proxy speed is much lower than direct, ISP may be throttling proxy traffic

# Try different ports (some ISPs throttle port 443 specifically)
hydraflow config --port 8443
systemctl restart hydraflow
```

### Step 5: Check server bandwidth

Cheap VPS often have bandwidth limits:

```bash
# Check current bandwidth usage
vnstat -l   # Live monitoring
vnstat -d   # Daily stats

# If you are hitting VPS bandwidth limits, upgrade or add another server
```

---

## Was Working, Suddenly Stopped

The ISP updated their DPI rules. This is the most common reason.

### Step 1: Check if the server is actually running

```bash
systemctl status hydraflow
systemctl status xray
```

### Step 2: Check if your IP is blocked

From a different network (phone hotspot, different WiFi, another country):

```bash
# Try connecting to the same server
curl -x socks5://... https://google.com

# If it works from another network but not yours → your ISP blocked it
# If it doesn't work from anywhere → server issue
```

### Step 3: Switch protocol via subscription

The fastest fix -- change to a different protocol:

1. Open your client app
2. Refresh subscription (pull to refresh, or Subscription > Update)
3. Try connecting to a different node (CDN node if direct is blocked, or vice versa)

If the subscription includes the blocking map, dead protocols will already be removed.

### Step 4: Force protocol change on server

```bash
# Check which protocols are available
hydraflow config --show

# Run probe to see what works
hydraflow probe --target YOUR_SERVER_IP:443

# If Reality is blocked, make sure CDN is enabled
hydraflow cdn --status

# If CDN is not set up, set it up now
hydraflow cdn --domain your-domain.xyz
```

### Step 5: Change server characteristics

```bash
# Change Reality SNI
hydraflow config --sni "cdn.jsdelivr.net"

# Change port
hydraflow config --port 2083

# Regenerate keys (new cryptographic identity)
hydraflow config --reality-regenerate

# Restart
systemctl restart hydraflow

# Get new connection link
hydraflow info
```

After changing server config, clients need to update their subscription to get the new settings.

---

## v2rayNG Says "Connection Refused"

"Connection refused" means the client reached the server IP, but nothing is listening on that port.

### Check xray service

```bash
# Is xray running?
systemctl status xray

# If not running, check why
journalctl -u xray -n 30 --no-pager

# Common causes:
# - Invalid config: xray run -test -config /etc/hydraflow/xray.json
# - Port conflict: ss -tlnp | grep :443
# - Out of memory: free -h
```

### Check port binding

```bash
# What is listening on port 443?
ss -tlnp | grep :443

# Expected: xray or nginx (if using SNI routing)
# If empty: xray is not binding to 443

# Check xray config for the correct port
cat /etc/hydraflow/xray.json | grep '"port"'
```

### Check if another service grabbed the port

```bash
# Common culprits: apache2, nginx (not HydraFlow's), certbot
ss -tlnp | grep :443

# If it's apache2:
systemctl stop apache2
systemctl disable apache2

# If it's a stale nginx:
systemctl stop nginx
# Then restart HydraFlow
systemctl restart hydraflow
```

### Check client configuration

In v2rayNG, verify:
- **Address:** Your server IP (not domain, unless using CDN)
- **Port:** 443 (or whatever port HydraFlow is using)
- **Security:** reality
- **SNI:** www.microsoft.com (or your configured SNI)
- **Fingerprint:** chrome
- **PublicKey:** Must match server's public key exactly
- **ShortId:** Must match server's short ID exactly

Get the correct values:

```bash
hydraflow info --detailed
```

---

## Subscription Not Updating

### Check subscription service is running

```bash
systemctl status hydraflow

# Check subscription endpoint is responding
curl -s http://127.0.0.1:8080/sub/test | head -5
# (The actual port and path depend on your config)
```

### Check the subscription URL

```bash
# View your subscription URL
hydraflow sub --show-url

# Test it from outside (from your local machine)
curl -s "https://YOUR_SERVER/sub/YOUR_TOKEN" | head -10
```

### Check token

```bash
# If the token is wrong, regenerate
hydraflow sub --generate
# This creates a new subscription URL with a new token
# You will need to update the URL in all client apps
```

### Client-side issues

**v2rayNG:**
- Go to Subscription Group Setting
- Check the URL is correct (no extra spaces, no truncation)
- Tap "Update" manually
- If using custom User-Agent, try removing it

**Hiddify:**
- Go to Config Options > Subscription
- Check auto-update is enabled
- Tap refresh button

**Common client-side problems:**
- Clock is wrong on client device (certificate validation fails)
- DNS is blocked (client cannot resolve subscription domain)
- Subscription URL uses HTTPS but the certificate is expired

### Server-side: subscription port blocked

```bash
# HydraFlow subscription typically runs on port 443 (shared with xray via path routing)
# or on a separate port (e.g., 8080)

# Check what port subscription is on
hydraflow config --show | grep sub

# If on a separate port, make sure firewall allows it
ufw allow 8080/tcp
```

---

## CDN Not Working

See [cdn-setup.md](cdn-setup.md) for full setup. Quick troubleshooting:

### Check DNS resolution

```bash
dig A your-domain.xyz +short
# Should show Cloudflare IPs (104.21.x.x or 172.67.x.x)
# Should NOT show your server IP

# If it shows your server IP: orange cloud (Proxy) is OFF in Cloudflare DNS
```

### Check Cloudflare settings

1. SSL/TLS mode: must be **Full** (not Flexible, not Full Strict)
2. WebSockets: must be **enabled** (Network tab)
3. Minimum TLS: 1.2

### Check from server

```bash
# Is the WebSocket inbound configured?
cat /etc/hydraflow/xray.json | grep -A10 '"wsSettings"'

# Is xray listening for WebSocket connections?
journalctl -u xray -f
# Then try connecting via CDN and watch for log entries
```

### Test the full chain

```bash
# 1. Does HTTPS to your domain work through Cloudflare?
curl -I https://your-domain.xyz
# Look for cf-ray header

# 2. Does WebSocket upgrade work?
curl -H "Upgrade: websocket" -H "Connection: upgrade" \
  -v https://your-domain.xyz/your-ws-path 2>&1 | head -20

# 3. If curl works but client doesn't, the issue is in client config
# Make sure client uses the domain name (not server IP) for CDN connection
```

---

## Multi-Server Issues

### Server shows DOWN in cluster

```bash
# Check from primary
hydraflow cluster status

# Test connectivity to the down server
curl -s https://SECONDARY_IP:8443/api/health

# If timeout: firewall issue or server actually down
# If connection refused: HydraFlow not running on secondary
# If 401: API key mismatch
```

### Fix firewall

On the secondary server:

```bash
# Allow primary to reach the API
ufw allow from PRIMARY_IP to any port 8443
```

### Fix API key

```bash
# On secondary: get the current API key
hydraflow info --api-key

# On primary: update the stored key
hydraflow cluster update --name "server-name" --api-key "correct-key"
```

---

## Checking Logs

### HydraFlow service logs

```bash
# Follow logs in real time
journalctl -u hydraflow -f

# Last 100 lines
journalctl -u hydraflow -n 100 --no-pager

# Logs from the last hour
journalctl -u hydraflow --since "1 hour ago" --no-pager

# Logs from today only
journalctl -u hydraflow --since today --no-pager

# Search for errors
journalctl -u hydraflow --no-pager | grep -i error

# Search for specific connection issues
journalctl -u hydraflow --no-pager | grep -i "refused\|timeout\|failed"
```

### Xray logs

```bash
# Xray logs (proxy engine)
journalctl -u xray -f

# Xray error level only
journalctl -u xray --no-pager | grep -i "error\|warning"

# Xray access log (if enabled)
tail -f /var/log/xray/access.log

# Xray error log
tail -f /var/log/xray/error.log
```

### Connection-specific debugging

```bash
# Enable verbose logging temporarily
hydraflow config --log-level debug
systemctl restart hydraflow

# Watch connections in real time
journalctl -u xray -f | grep "accepted\|connection"

# After debugging, set back to normal
hydraflow config --log-level warning
systemctl restart hydraflow
```

---

## Restarting Services

### Restart HydraFlow (includes xray)

```bash
systemctl restart hydraflow
```

### Restart only xray

```bash
systemctl restart xray
```

### Full restart (nuclear option)

```bash
systemctl stop hydraflow
systemctl stop xray
systemctl stop nginx   # If using nginx for SNI routing

# Wait a moment
sleep 2

systemctl start nginx
systemctl start xray
systemctl start hydraflow

# Verify everything is running
systemctl status hydraflow xray nginx
```

### If systemctl does not work (broken system)

```bash
# Kill processes directly
pkill -f hydraflow
pkill -f xray

# Start manually to see output
/usr/local/bin/xray run -config /etc/hydraflow/xray.json &
hydraflow serve &

# Check if it's working
ss -tlnp | grep -E '443|8080'
```

---

## Switching Protocols

### From the panel

If HydraFlow panel is accessible:

1. Go to **Settings** > **Protocols**
2. Enable/disable specific protocols
3. Change priority order (drag and drop)
4. Click **Save** -- subscription is updated automatically
5. Clients get new config on next subscription refresh

### From command line

```bash
# See current protocol configuration
hydraflow config --show

# Disable Reality (if blocked)
hydraflow config --protocol reality --enabled false

# Enable SS-2022 as primary
hydraflow config --protocol ss2022 --priority 1

# Add CDN protocol
hydraflow cdn --domain your-domain.xyz

# Rebuild subscription with new priorities
hydraflow sub --rebuild

# Restart
systemctl restart hydraflow
```

### Client side

After server changes, clients need to update:

**Automatic:** Wait for next subscription refresh (default: 1 hour, configurable with `--ttl`)

**Manual:**
- v2rayNG: Subscription Group Setting > tap Update
- Hiddify: Config Options > Subscription > refresh button
- Clash: Profiles > tap refresh icon on profile

After updating, the client will see the new protocol list and auto-select the best one.

---

## Complete Diagnostic Checklist

Run through this when nothing else works.

```bash
# === SERVER SIDE ===

# 1. Is the server running?
systemctl status hydraflow xray

# 2. Is anything listening on the right ports?
ss -tlnp | grep -E '443|8388|8080'

# 3. Is the firewall allowing traffic?
ufw status

# 4. Can the server reach the internet?
curl -s https://google.com -o /dev/null -w "%{http_code}"

# 5. Is the xray config valid?
xray run -test -config /etc/hydraflow/xray.json

# 6. Are there any errors in logs?
journalctl -u hydraflow -n 20 --no-pager
journalctl -u xray -n 20 --no-pager

# 7. Is disk space OK?
df -h /

# 8. Is memory OK?
free -h

# 9. What are the current connection settings?
hydraflow info --detailed

# 10. Is the subscription endpoint responding?
curl -s http://127.0.0.1:8080/sub/test | head -3


# === CLIENT SIDE (from your local machine) ===

# 11. Can you reach the server at all?
ping -c 3 YOUR_SERVER_IP

# 12. Can you reach the port?
nc -zv YOUR_SERVER_IP 443

# 13. Does TLS work?
openssl s_client -connect YOUR_SERVER_IP:443 -servername www.microsoft.com </dev/null 2>&1 | head -20

# 14. Does the subscription URL work?
curl -s "https://YOUR_SERVER/sub/YOUR_TOKEN" | head -5

# 15. Can you reach the CDN domain?
curl -I https://your-domain.xyz 2>&1 | head -10


# === NETWORK DIAGNOSTICS ===

# 16. Is the ISP blocking at IP level?
traceroute YOUR_SERVER_IP

# 17. Is DNS working?
dig A your-domain.xyz +short

# 18. Run full HydraFlow probe
hydraflow probe --target YOUR_SERVER_IP:443 --verbose
```

If you have gone through all of these and still cannot connect, the most likely cause is ISP-level IP blocking. Set up CDN ([cdn-setup.md](cdn-setup.md)) or switch to a different server in a different IP range.
