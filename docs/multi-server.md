# Multi-Server Failover Guide

Run HydraFlow on multiple servers across different countries and providers. If one server goes down or gets blocked, clients automatically switch to the next one. Combined with CDN, this makes your setup nearly impossible to fully block.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Step 1: Install HydraFlow on Multiple Servers](#step-1-install-hydraflow-on-multiple-servers)
4. [Step 2: Designate a Primary Server](#step-2-designate-a-primary-server)
5. [Step 3: Add Secondary Servers](#step-3-add-secondary-servers)
6. [Step 4: Verify Cluster](#step-4-verify-cluster)
7. [How Health Checks Work](#how-health-checks-work)
8. [How Clients Fail Over](#how-clients-fail-over)
9. [Recommended Server Setups](#recommended-server-setups)
10. [Managing the Cluster](#managing-the-cluster)
11. [Troubleshooting](#troubleshooting)

---

## Architecture

```
                        ┌──────────────────────────────────┐
                        │        Subscription URL           │
                        │   https://primary.com/sub/{token} │
                        └──────────────┬───────────────────┘
                                       │
              ┌────────────────────────┼──────────────────────────┐
              │                        │                          │
              ▼                        ▼                          ▼
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────────┐
│  Server 1 (NL)      │ │  Server 2 (DE)      │ │  CDN (Cloudflare)       │
│  Protocol: Reality   │ │  Protocol: Reality   │ │  Protocol: WS + TLS     │
│  Status: UP          │ │  Status: DOWN        │ │  Status: UP             │
│  Latency: 45ms       │ │  (removed from sub)  │ │  Latency: 80ms          │
│  Priority: 1         │ │                      │ │  Priority: 2            │
└─────────────────────┘ └─────────────────────┘ └─────────────────────────┘
              │                                                   │
              ▼                                                   ▼
┌─────────────────────┐                         ┌─────────────────────────┐
│  Server 3 (FI)      │                         │  Server 4 (US) [chain]  │
│  Protocol: SS-2022   │                         │  RU relay → US exit     │
│  Status: UP          │                         │  Status: UP             │
│  Latency: 60ms       │                         │  Latency: 120ms         │
│  Priority: 3         │                         │  Priority: 4            │
└─────────────────────┘                         └─────────────────────────┘
```

**What the client sees:** A single subscription URL that always returns only the servers that are currently alive and reachable. Dead or blocked servers are silently removed.

**What happens during an outage:**

```
1. Server 2 (DE) goes down
2. Health check detects failure within 5 minutes
3. Primary server removes Server 2 from subscription
4. Client refreshes subscription (next auto-refresh or manual)
5. Client connects to next best server automatically
6. When Server 2 recovers, it is added back to subscription
```

---

## Prerequisites

- 2 or more VPS servers in **different countries** and/or **different providers**
- Each server has HydraFlow installed
- Servers can reach each other over the internet (for health check API)
- One server designated as **primary** (hosts the subscription URL)

**Recommended minimum:** 2 servers + CDN = 3 paths to the internet.

---

## Step 1: Install HydraFlow on Multiple Servers

Install HydraFlow on each VPS the same way:

```bash
# On Server 1 (e.g., Netherlands, Hetzner)
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)

# On Server 2 (e.g., Germany, Contabo)
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)

# On Server 3 (e.g., Finland, UpCloud)
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
```

After installation, each server has its own API key. Get it with:

```bash
hydraflow info --api-key
```

Save each server's IP and API key. You will need them in Step 3.

---

## Step 2: Designate a Primary Server

The primary server hosts the subscription URL. It is the server that your clients connect to for subscription updates.

Choose the server most likely to remain accessible. If you have CDN set up, the primary should be the one behind CDN (since CDN itself is hard to block).

On the primary server:

```bash
hydraflow cluster init
```

This creates the cluster configuration and generates a cluster secret used for server-to-server authentication.

Output:

```
Cluster initialized.
Cluster ID: abc123def456
Cluster secret: sk_cluster_xxxxxxxxxxxxxxxxx
Primary: this server (185.123.45.67)
API endpoint: https://185.123.45.67:8443/api/cluster
```

---

## Step 3: Add Secondary Servers

On the primary server, add each secondary server:

```bash
# Add Server 2
hydraflow cluster add \
  --name "de-contabo" \
  --ip 195.201.78.90 \
  --api-key "sk_api_xxxxxxxxxxxxxxx"

# Add Server 3
hydraflow cluster add \
  --name "fi-upcloud" \
  --ip 94.237.12.34 \
  --api-key "sk_api_yyyyyyyyyyyyyyy"
```

Each `cluster add` command:
1. Connects to the remote server's API
2. Exchanges cluster authentication tokens
3. Pulls the remote server's protocol configurations
4. Adds the remote server's nodes to the local subscription
5. Starts health monitoring

**Check that servers were added:**

```bash
hydraflow cluster list
```

Expected output:

```
CLUSTER: abc123def456
─────────────────────────────────────────────────────────────
 NAME          IP              STATUS    LATENCY   PROTOCOLS
─────────────────────────────────────────────────────────────
 nl-hetzner    185.123.45.67   UP        -         reality, xhttp-cdn
 de-contabo    195.201.78.90   UP        12ms      reality
 fi-upcloud    94.237.12.34    UP        18ms      reality, ss-2022
─────────────────────────────────────────────────────────────
 Subscription includes: 5 nodes from 3 servers + 1 CDN
```

---

## Step 4: Verify Cluster

**Check subscription includes all servers:**

```bash
hydraflow sub --show
```

You should see nodes from all servers:

```
Subscription nodes:
  1. nl-hetzner-reality     (185.123.45.67:443)   Reality    Priority: 1
  2. de-contabo-reality     (195.201.78.90:443)   Reality    Priority: 2
  3. fi-upcloud-reality     (94.237.12.34:443)    Reality    Priority: 3
  4. fi-upcloud-ss2022      (94.237.12.34:8388)   SS-2022    Priority: 4
  5. cdn-cloudflare-ws      (myproxy.xyz:443)     WS+TLS     Priority: 5
```

**Test failover manually:**

```bash
# Simulate server 2 going down (on server 2, temporarily)
systemctl stop hydraflow

# Wait for health check (up to 5 minutes), or force check
hydraflow cluster check

# Verify server 2 was removed from subscription
hydraflow sub --show
# Server 2 nodes should be gone

# Bring server 2 back
systemctl start hydraflow

# Force check again
hydraflow cluster check

# Server 2 nodes should reappear
hydraflow sub --show
```

**Test from client side:**

1. Update subscription in your client app
2. You should see nodes from all healthy servers
3. Stop one server -- update subscription again -- that server's nodes should disappear
4. Connect to a remaining node -- verify it works

---

## How Health Checks Work

The primary server polls each secondary server every **5 minutes** (configurable).

### What is checked

1. **API health endpoint:** `GET /api/health` on the secondary server
   - Returns server status, uptime, active connections, protocol status
   - Timeout: 10 seconds
2. **Protocol-level probe:** Attempts an actual protocol connection (Reality handshake, SS-2022 probe)
   - Timeout: 15 seconds
3. **Latency measurement:** Records round-trip time for monitoring

### Status transitions

```
          ┌─────────┐
          │   UP     │ ◄─── 2 consecutive successful checks
          └────┬────┘
               │ 2 consecutive failures
               ▼
          ┌─────────┐
          │  DOWN    │ ◄─── remains until recovered
          └────┬────┘
               │ 2 consecutive successes
               ▼
          ┌─────────┐
          │   UP     │
          └─────────┘
```

A server must fail **2 consecutive checks** (10 minutes) before being removed from the subscription. This prevents flapping due to transient network issues.

### Configuration

```yaml
# /etc/hydraflow/cluster.yml
cluster:
  health_check:
    interval: 5m          # How often to check (default: 5m)
    timeout: 15s           # Per-check timeout (default: 15s)
    failure_threshold: 2   # Failures before marking DOWN (default: 2)
    recovery_threshold: 2  # Successes before marking UP (default: 2)
```

To change the interval:

```bash
hydraflow cluster config --health-interval 3m
```

---

## How Clients Fail Over

### Automatic (via subscription refresh)

1. Client periodically refreshes subscription (default: every 1 hour, configurable via `ttl` in subscription)
2. Dead servers are already removed from the subscription response
3. Client's protocol selector re-evaluates available nodes
4. Client connects to the highest-scored available node

### Instant (HydraFlow client with probe engine)

If using a HydraFlow-aware client (or a client with fallback support like Hiddify):

1. Connection to current server fails
2. Client immediately tries the next node in the subscription
3. No need to wait for subscription refresh
4. Background subscription refresh still happens to get the latest server list

### Manual

If auto-refresh is not working:
1. Open your client app
2. Go to Subscription > Update
3. Reconnect

---

## Recommended Server Setups

### Budget Setup (2 servers + CDN)

**Cost:** ~$10-15/month total

```
Server 1: Hetzner (Germany) - $4/mo  → Reality
Server 2: Any other provider         → Reality + SS-2022
CDN:      Cloudflare (free)           → WS + TLS
```

Three independent paths. If Germany is blocked, CDN or Server 2 works. If the IP is blocked, CDN works.

### Resilient Setup (3 servers + CDN + chain)

**Cost:** ~$20-25/month total

```
Server 1: Hetzner (Netherlands) → Reality (primary, hosts subscription)
Server 2: UpCloud (Finland)     → Reality + SS-2022
Server 3: Oracle Cloud (US)     → Reality (free tier)
CDN:      Cloudflare            → WS + TLS
Chain:    RU VPS → Server 1     → Multi-hop (for hardest-to-block path)
```

Five independent paths including one that looks like domestic Russian traffic.

### Maximum Resilience Setup

```
Server 1: Netherlands   → Reality        (Hetzner)
Server 2: Germany       → Reality        (Contabo)
Server 3: Finland       → Reality + SS   (UpCloud)
Server 4: US            → Reality        (Oracle free)
Server 5: Singapore     → Reality        (DigitalOcean)
CDN 1:    Cloudflare    → WS + TLS       (domain 1)
CDN 2:    Cloudflare    → WS + TLS       (domain 2, Workers)
Chain:    RU VPS        → any server     (multi-hop)
```

> **Recommendation for most users:** The budget setup (2 servers + CDN) is enough. Add more servers only if you serve many users or operate in a heavily censored environment.

---

## Managing the Cluster

### View cluster status

```bash
hydraflow cluster status
```

### Remove a server

```bash
hydraflow cluster remove --name "de-contabo"
```

### Force health check

```bash
hydraflow cluster check
```

### View health check logs

```bash
journalctl -u hydraflow -f | grep cluster
```

### Temporarily disable a server (maintenance)

```bash
# Mark as maintenance (keeps in cluster but removes from subscription)
hydraflow cluster disable --name "de-contabo"

# Re-enable
hydraflow cluster enable --name "de-contabo"
```

### Update API key for a server

```bash
hydraflow cluster update --name "de-contabo" --api-key "sk_api_newkey"
```

---

## Troubleshooting

### Server shows DOWN but is actually running

```bash
# Check from primary server
curl -s https://195.201.78.90:8443/api/health

# If connection refused: firewall on secondary is blocking primary
# Fix: allow primary server IP in secondary's firewall
ufw allow from 185.123.45.67 to any port 8443

# If timeout: network issue between servers
# Check with:
traceroute 195.201.78.90
```

### Subscription does not include all servers

```bash
# Check cluster state
hydraflow cluster list

# If server shows UP but not in subscription, force rebuild
hydraflow sub --rebuild

# Check subscription output
hydraflow sub --show
```

### Clients not switching when server goes down

- Check that subscription TTL is reasonable (default 3600 seconds = 1 hour)
- For faster failover, reduce TTL:

```bash
hydraflow sub --ttl 900  # 15 minutes
```

- Some clients ignore TTL and only refresh manually. Nothing you can do except use a client that supports auto-refresh (Hiddify, v2rayNG latest versions).

### Health checks consume bandwidth

Each health check is tiny (~1KB). With 5 servers checked every 5 minutes:

```
5 servers * 1KB * 12 checks/hour * 24 hours = ~1.4MB/day
```

Negligible. Do not worry about bandwidth.

### Server-to-server authentication fails

```bash
# Verify API key on secondary
hydraflow info --api-key

# Compare with what primary has stored
hydraflow cluster list --show-keys

# If mismatch, update
hydraflow cluster update --name "de-contabo" --api-key "correct-key-here"
```

### Primary server goes down

The subscription URL is hosted on the primary. If the primary goes down, clients cannot refresh subscriptions.

**Mitigation:**
- Put the primary behind CDN so even if the IP is blocked, the subscription URL works
- Clients still have cached subscription data and can connect to secondary servers they already know about
- Consider hosting subscription on a separate stable endpoint (e.g., Cloudflare Workers serving a static config that you update manually)

```bash
# To migrate primary role to another server
# On new primary:
hydraflow cluster init --migrate-from 185.123.45.67
```
