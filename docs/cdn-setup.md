# CDN Setup Guide / Настройка CDN

When direct access to your server IP is blocked, Cloudflare CDN is the **only reliable fallback**. DPI sees traffic going to Cloudflare's IP addresses (shared by millions of websites), not to your server. Blocking Cloudflare would break half the internet, so censors can't do it.

Когда прямой доступ к IP сервера заблокирован, CDN через Cloudflare -- **единственный надежный способ обхода**. DPI видит трафик к IP-адресам Cloudflare (которые используют миллионы сайтов), а не к вашему серверу. Заблокировать Cloudflare нельзя -- это сломает половину интернета.

---

## Table of Contents

1. [Quick Overview](#quick-overview)
2. [Step 1: Get a Domain](#step-1-get-a-domain)
3. [Step 2: Add Domain to Cloudflare](#step-2-add-domain-to-cloudflare)
4. [Step 3: Point DNS to Your Server](#step-3-point-dns-to-your-server)
5. [Step 4: Configure HydraFlow](#step-4-configure-hydraflow)
6. [Step 5: Verify It Works](#step-5-verify-it-works)
7. [Cloudflare Workers Alternative (No Domain Needed)](#cloudflare-workers-alternative)
8. [Common Mistakes and Fixes](#common-mistakes-and-fixes)
9. [How It Works Technically](#how-it-works-technically)
10. [Руководство на русском](#руководство-на-русском)

---

## Quick Overview

```
Without CDN:
  Client ──→ [DPI sees server IP] ──→ Your Server (BLOCKED)

With CDN:
  Client ──→ Cloudflare IP ──→ Cloudflare edge ──→ Your Server (WORKS)
             (DPI sees Cloudflare,
              not your server)
```

**What you need:**
- A domain name (any cheap .xyz domain for ~$1/year)
- A Cloudflare account (free plan)
- HydraFlow installed on your server

**Time required:** 10-15 minutes.

---

## Step 1: Get a Domain

Buy any cheap domain. The domain itself does not matter -- nobody will visit it, it is only used as a routing label for Cloudflare.

**Cheap registrars:**
- [Namecheap](https://namecheap.com) -- .xyz domains from $0.99/year
- [Porkbun](https://porkbun.com) -- .xyz from $1.07/year
- [Cloudflare Registrar](https://dash.cloudflare.com/domains) -- at-cost pricing, no markup

> **Tip:** Do not use your personal domain or any domain associated with your identity. Buy a new throwaway domain specifically for this purpose.

---

## Step 2: Add Domain to Cloudflare

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com/) and sign up (or log in)
2. Click **"Add a site"** (top right)
3. Enter your domain name (e.g., `myproxy123.xyz`)
4. Select **Free plan** and click **Continue**
5. Cloudflare will show you two nameservers, for example:
   ```
   aria.ns.cloudflare.com
   jay.ns.cloudflare.com
   ```
6. Go to your domain registrar (where you bought the domain)
7. Find **Nameservers** or **DNS settings** and replace the existing nameservers with the Cloudflare ones
8. Wait for propagation (usually 5-30 minutes, sometimes up to 24 hours)

**How to check if nameservers propagated:**

```bash
dig NS myproxy123.xyz +short
```

Expected output should show Cloudflare nameservers:

```
aria.ns.cloudflare.com.
jay.ns.cloudflare.com.
```

---

## Step 3: Point DNS to Your Server

1. In Cloudflare dashboard, go to your domain > **DNS** > **Records**
2. Click **Add record**
3. Configure:
   - **Type:** A
   - **Name:** `@` (or any subdomain like `proxy`)
   - **IPv4 address:** Your server's IP (e.g., `185.123.45.67`)
   - **Proxy status:** **Proxied** (orange cloud ON)
4. Click **Save**

> **CRITICAL: The orange cloud (Proxy) must be ON.** If it is grey (DNS only), traffic goes directly to your server IP and the entire point of CDN bypass is lost.

If your server has an IPv6 address, also add an AAAA record the same way.

**Optional but recommended:** Add a subdomain too:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `@` | `185.123.45.67` | Proxied (orange) |
| A | `cdn` | `185.123.45.67` | Proxied (orange) |

---

## Step 4: Configure HydraFlow

SSH into your server and run:

```bash
hydraflow cdn --domain myproxy123.xyz
```

This command automatically:
- Creates a WebSocket inbound in xray configuration
- Configures TLS via Cloudflare (origin certificate)
- Adds the CDN node to your subscription
- Restarts the service

**Manual verification that the config was applied:**

```bash
# Check xray config has WebSocket inbound
cat /etc/hydraflow/xray.json | grep -A5 '"wsSettings"'

# Check subscription includes CDN node
hydraflow sub --show
```

You should see a `xhttp-cdn` or `ws-cdn` entry in the subscription output.

**Cloudflare SSL/TLS settings (in Cloudflare dashboard):**

1. Go to your domain > **SSL/TLS** > **Overview**
2. Set encryption mode to **Full** (not "Full (strict)", not "Flexible")
3. Go to **Edge Certificates** and ensure **Minimum TLS Version** is TLS 1.2
4. Go to **Network** and enable **WebSockets**

---

## Step 5: Verify It Works

**From any machine (your laptop, phone, etc.):**

```bash
# Check the domain resolves to Cloudflare IPs (NOT your server IP)
dig A myproxy123.xyz +short
# Should show Cloudflare IPs like 104.21.x.x or 172.67.x.x
# Should NOT show your server IP

# Check HTTPS works through Cloudflare
curl -I https://myproxy123.xyz
# Should return HTTP/2 200 or similar
# Look for "cf-ray" header -- confirms traffic goes through Cloudflare

# Full check with verbose output
curl -vvv https://myproxy123.xyz 2>&1 | grep -E '(cf-ray|server:|subject:)'
```

**From a client app (v2rayNG, Hiddify):**

1. Refresh your subscription (pull down to refresh, or go to Subscription > Update)
2. You should see a new CDN node in your server list
3. Connect to the CDN node specifically
4. Check connectivity: open any website

If the CDN node works but direct Reality node does not, your IP is blocked and CDN is saving you.

---

## Cloudflare Workers Alternative

**No domain needed.** If you cannot or do not want to buy a domain, use Cloudflare Workers as a proxy relay.

### Setup

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com/) > **Workers & Pages**
2. Click **Create application** > **Create Worker**
3. Name it anything (e.g., `relay-abc123`)
4. Replace the worker code with:

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Replace with your server IP and port
    const target = "wss://185.123.45.67:443" + url.pathname;

    if (request.headers.get("Upgrade") === "websocket") {
      return fetch(target, {
        headers: request.headers,
      });
    }

    return new Response("OK", { status: 200 });
  }
};
```

5. Deploy the worker
6. Your worker URL will be something like `relay-abc123.yourname.workers.dev`

### Configure in HydraFlow

```bash
hydraflow cdn --worker relay-abc123.yourname.workers.dev
```

### Limitations of Workers approach

- Cloudflare Workers free plan: 100,000 requests/day (enough for most personal use)
- WebSocket connections have a 25-minute idle timeout
- Slightly higher latency than a proper domain + proxy setup
- Workers domain (`workers.dev`) could theoretically be blocked (less likely than raw IP blocking though)

---

## Common Mistakes and Fixes

### 1. Orange cloud is OFF (DNS-only mode)

**Symptom:** `dig` shows your real server IP instead of Cloudflare IPs.

**Fix:** Go to Cloudflare DNS > click the record > toggle Proxy status to Proxied (orange cloud).

### 2. SSL mode set to "Flexible"

**Symptom:** Connections fail, or you get redirect loops (ERR_TOO_MANY_REDIRECTS).

**Fix:** Cloudflare SSL/TLS > Overview > set to **Full** (not Flexible, not Full Strict).

### 3. WebSockets not enabled

**Symptom:** WebSocket connection fails, client shows "connection closed" errors.

**Fix:** Cloudflare > Network > enable **WebSockets** toggle.

### 4. Nameservers not changed

**Symptom:** Domain does not resolve, or resolves to old hosting IP.

**Fix:** Check nameservers at your registrar. They must point to the two Cloudflare NS servers.

```bash
dig NS myproxy123.xyz +short
# Must show *.ns.cloudflare.com
```

### 5. Firewall on server blocks Cloudflare IPs

**Symptom:** Direct connection works, CDN does not.

**Fix:** Allow Cloudflare IP ranges through your firewall:

```bash
# Cloudflare IPv4 ranges
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
  ufw allow from $ip to any port 443
done
```

### 6. Server port 443 used by another service

**Symptom:** `hydraflow cdn` fails or nginx/xray can't start.

**Fix:**

```bash
# Check what is using port 443
ss -tlnp | grep :443

# If it's nginx, HydraFlow can coexist via SNI routing
# If it's something else, stop it or reconfigure HydraFlow to a different port
```

### 7. Domain registrar blocks nameserver changes

**Symptom:** Cannot change nameservers, or changes revert.

**Fix:** Some registrars lock nameserver changes. Look for "Domain Lock" or "Registrar Lock" and disable it. Contact registrar support if needed.

---

## How It Works Technically

```
┌──────────┐    TLS to CF IP     ┌───────────────┐   Origin req   ┌──────────────┐
│  Client   │ ─────────────────→ │  Cloudflare   │ ────────────→  │  Your Server │
│ (v2rayNG) │    SNI: your       │  Edge Server  │  WebSocket     │  (HydraFlow) │
│           │    domain.xyz      │  (104.21.x.x) │  over HTTPS    │  (185.x.x.x) │
└──────────┘                     └───────────────┘                └──────────────┘
      │                                │                                │
      │  DPI sees:                     │  DPI sees:                     │
      │  - Dst: Cloudflare IP          │  - Encrypted traffic           │
      │  - SNI: your-domain.xyz        │  - From Cloudflare to          │
      │  - Normal HTTPS traffic        │    your server (already past   │
      │  - Same as millions of         │    DPI checkpoint)             │
      │    other websites              │                                │
```

**Why DPI cannot block this:**

1. **IP-based blocking fails:** The client connects to Cloudflare's IP (shared by millions of sites), not your server's IP.
2. **SNI-based blocking fails:** Your domain is one of millions behind Cloudflare. Blocking by SNI means blocking every Cloudflare domain.
3. **Protocol-based blocking fails:** The traffic is standard HTTPS + WebSocket, identical to countless legitimate services.

The only theoretical attack is blocking all of Cloudflare. This would break too many legitimate services (Discord, Canva, thousands of corporate sites) to be practical.

---

## Руководство на русском

### Зачем нужен CDN

Когда провайдер блокирует IP вашего сервера, прямое подключение через Reality перестает работать. CDN решает эту проблему: трафик идет через IP-адреса Cloudflare, а не напрямую к серверу. ТСПУ видит подключение к Cloudflare -- а Cloudflare блокировать невозможно, потому что через него работают миллионы сайтов.

### Пошаговая инструкция

#### Шаг 1: Купите домен

Купите любой дешевый домен. Подойдет .xyz за $1/год:
- [Namecheap](https://namecheap.com) -- .xyz от $0.99
- [Porkbun](https://porkbun.com) -- .xyz от $1.07

Домен нужен только как метка маршрутизации. Никто не будет на него заходить.

> **Важно:** Не используйте домен, привязанный к вашему имени. Купите новый анонимный домен.

#### Шаг 2: Добавьте домен в Cloudflare

1. Зайдите на [dash.cloudflare.com](https://dash.cloudflare.com/) (регистрация бесплатная)
2. Нажмите **"Add a site"** (вверху справа)
3. Введите ваш домен (например, `myproxy123.xyz`)
4. Выберите **Free plan** и нажмите **Continue**
5. Cloudflare покажет два DNS-сервера, например:
   ```
   aria.ns.cloudflare.com
   jay.ns.cloudflare.com
   ```
6. Идите к регистратору домена (где покупали) и замените DNS-серверы (nameservers) на те, что дал Cloudflare
7. Подождите 5-30 минут (иногда до 24 часов)

**Проверка:**

```bash
dig NS myproxy123.xyz +short
# Должны быть *.ns.cloudflare.com
```

#### Шаг 3: Настройте DNS-запись

1. В панели Cloudflare: ваш домен > **DNS** > **Records** > **Add record**
2. Заполните:
   - **Type:** A
   - **Name:** `@`
   - **IPv4 address:** IP вашего сервера
   - **Proxy status:** **Proxied** (оранжевое облако ВКЛЮЧЕНО)
3. Нажмите **Save**

> **КРИТИЧНО: Оранжевое облако (Proxy) должно быть ВКЛЮЧЕНО.** Если облако серое -- трафик идет напрямую к серверу, и весь смысл CDN теряется.

#### Шаг 4: Настройте SSL в Cloudflare

1. Перейдите в **SSL/TLS** > **Overview**
2. Установите **Full** (не Flexible, не Full Strict)
3. Перейдите в **Network** и включите **WebSockets**

#### Шаг 5: Настройте HydraFlow

На сервере выполните:

```bash
hydraflow cdn --domain myproxy123.xyz
```

Команда автоматически:
- Создаст WebSocket-вход в конфигурации xray
- Настроит TLS-сертификат для Cloudflare
- Добавит CDN-ноду в подписку
- Перезапустит сервис

#### Шаг 6: Проверьте

```bash
# Проверка DNS (должен показать IP Cloudflare, НЕ ваш сервер)
dig A myproxy123.xyz +short

# Проверка HTTPS (ищите заголовок cf-ray)
curl -I https://myproxy123.xyz
```

В клиенте (v2rayNG, Hiddify):
1. Обновите подписку
2. В списке появится CDN-нода
3. Подключитесь к ней

### Частые ошибки

| Проблема | Решение |
|----------|---------|
| `dig` показывает реальный IP сервера | Включите оранжевое облако (Proxy) в DNS-записи |
| Redirect loop / ERR_TOO_MANY_REDIRECTS | SSL/TLS > установите режим **Full** |
| WebSocket не подключается | Network > включите **WebSockets** |
| DNS не обновляется | Проверьте, что NS-серверы у регистратора изменены на Cloudflare |
| CDN не работает, прямое работает | Разрешите IP Cloudflare в firewall сервера |

### Альтернатива: Cloudflare Workers (без домена)

Если нет возможности купить домен:

1. Cloudflare > **Workers & Pages** > **Create application** > **Create Worker**
2. Назовите как угодно (например, `relay-abc123`)
3. Вставьте код из раздела [Cloudflare Workers Alternative](#cloudflare-workers-alternative) выше
4. Замените IP на свой сервер
5. Deploy
6. На сервере: `hydraflow cdn --worker relay-abc123.yourname.workers.dev`

Ограничения: 100,000 запросов/день на бесплатном плане, таймаут WebSocket 25 минут.
