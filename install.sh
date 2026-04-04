#!/usr/bin/env bash
# =============================================================================
# HydraFlow Multi-Protocol Server Installer v2.0
# https://github.com/Evr1kys/HydraFlow
#
# Usage:
#   Install:    bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
#   Uninstall:  bash install.sh --uninstall
#
# Installs xray-core and configures three protocols:
#   1. VLESS + Reality    (port 443)  — primary, mimics HTTPS to a real site
#   2. VLESS + WebSocket  (port 2053) — CDN-ready, works behind Cloudflare
#   3. Shadowsocks-2022   (port 8388) — fast alternative for ISPs that block VLESS
#
# Also deploys a subscription server (port 10086) that serves links
# in V2Ray/Clash Meta/sing-box formats with auto-detection.
#
# Compatible with Debian/Ubuntu, CentOS/RHEL/Fedora, AlmaLinux, Rocky.
# Idempotent: safe to run multiple times — preserves existing credentials.
# =============================================================================

set -euo pipefail

HYDRAFLOW_VERSION="2.0.0"
SECONDS=0

# =============================================================================
#  Color output helpers
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[!]${NC}  $*"; }
error()   { echo -e "${RED}[x]${NC}  $*" >&2; }
step()    { echo -e "\n${BLUE}${BOLD}==> $*${NC}"; }
success() { echo -e "${GREEN}[+]${NC}  $*"; }
detail()  { echo -e "    ${DIM}$*${NC}"; }

# =============================================================================
#  Configuration constants
# =============================================================================
CONFIG_DIR="/etc/hydraflow"
XRAY_BIN="/usr/local/bin/xray"
SUB_BIN="/usr/local/bin/hydraflow-sub"
XRAY_CONFIG="${CONFIG_DIR}/xray-config.json"
SUB_CONFIG="${CONFIG_DIR}/sub-config.json"
CREDS_FILE="${CONFIG_DIR}/.credentials"  # internal backup of generated values

REALITY_PORT=443
WS_PORT=2053
SS_PORT=8388
SUB_PORT=10086
STATS_PORT=10085

LOG_DIR="/var/log/hydraflow"

# Auto-detect free ports. If a default port is occupied by another process,
# pick an alternative. This prevents conflicts with nginx, x-ui, etc.
find_free_port() {
    local port=$1
    local max_attempts=10
    # Check if port is free (no one listening, or only our previous install)
    while [ $max_attempts -gt 0 ]; do
        local pid_on_port
        pid_on_port=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -v "^State" | head -1)
        if [ -z "$pid_on_port" ]; then
            echo "$port"
            return 0
        fi
        # If it's our own xray from a previous install, it's fine
        if echo "$pid_on_port" | grep -q "hydraflow\|/etc/hydraflow"; then
            echo "$port"
            return 0
        fi
        # Port occupied by something else — try next
        port=$((port + 1000))
        max_attempts=$((max_attempts - 1))
    done
    echo "$port"
}

auto_select_ports() {
    REALITY_PORT=$(find_free_port ${REALITY_PORT})
    WS_PORT=$(find_free_port ${WS_PORT})
    SS_PORT=$(find_free_port ${SS_PORT})
    SUB_PORT=$(find_free_port ${SUB_PORT})
    STATS_PORT=$(find_free_port ${STATS_PORT})

    # Warn if ports changed from defaults
    [ "$REALITY_PORT" != "443" ] && warn "Port 443 occupied, using ${REALITY_PORT} for Reality"
    [ "$WS_PORT" != "2053" ] && warn "Port 2053 occupied, using ${WS_PORT} for WebSocket"
    [ "$SS_PORT" != "8388" ] && warn "Port 8388 occupied, using ${SS_PORT} for Shadowsocks"
    [ "$SUB_PORT" != "10086" ] && warn "Port 10086 occupied, using ${SUB_PORT} for subscription"
}
XRAY_ASSET_DIR="/usr/local/share/xray"

# =============================================================================
#  Banner
# =============================================================================
show_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'

    ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ███████╗██╗      ██████╗ ██╗    ██╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║█████╗  ██║     ██║   ██║██║ █╗ ██║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔══╝  ██║     ██║   ██║██║███╗██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║     ███████╗╚██████╔╝╚███╔███╔╝
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝

BANNER
    echo -e "${NC}"
    echo -e "    ${DIM}Multi-Protocol Anti-Censorship Proxy${NC}          ${BOLD}v${HYDRAFLOW_VERSION}${NC}"
    echo -e "    ${DIM}github.com/Evr1kys/HydraFlow${NC}"
    echo ""
    echo -e "    ${GREEN}Protocols:${NC} VLESS+Reality | VLESS+WebSocket | Shadowsocks-2022"
    echo ""
}

# =============================================================================
#  Uninstall handler
# =============================================================================
do_uninstall() {
    echo ""
    echo -e "${RED}${BOLD}==> Uninstalling HydraFlow${NC}"
    echo ""

    # Stop and disable services
    for svc in hydraflow-xray hydraflow-sub; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            info "Stopping ${svc}..."
            systemctl stop "${svc}" 2>/dev/null || true
        fi
        if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
            systemctl disable "${svc}" 2>/dev/null || true
        fi
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true

    # Remove binaries
    rm -f "${XRAY_BIN}" "${SUB_BIN}"

    # Remove config and logs
    rm -rf "${CONFIG_DIR}"
    rm -rf "${LOG_DIR}"
    rm -rf "${XRAY_ASSET_DIR}"

    # Remove firewall rules (best effort)
    if command -v ufw &>/dev/null; then
        for port in ${REALITY_PORT} ${WS_PORT} ${SS_PORT} ${SUB_PORT}; do
            ufw delete allow "${port}/tcp" 2>/dev/null || true
        done
    elif command -v firewall-cmd &>/dev/null; then
        for port in ${REALITY_PORT} ${WS_PORT} ${SS_PORT} ${SUB_PORT}; do
            firewall-cmd --permanent --remove-port="${port}/tcp" 2>/dev/null || true
        done
        firewall-cmd --reload 2>/dev/null || true
    elif command -v iptables &>/dev/null; then
        for port in ${REALITY_PORT} ${WS_PORT} ${SS_PORT} ${SUB_PORT}; do
            iptables -D INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || true
        done
    fi

    echo ""
    success "HydraFlow has been completely removed."
    echo ""
    exit 0
}

# Check for --uninstall flag before anything else
if [[ "${1:-}" == "--uninstall" || "${1:-}" == "uninstall" || "${1:-}" == "remove" ]]; then
    if [[ $EUID -ne 0 ]]; then
        error "Uninstall must be run as root."
        exit 1
    fi
    do_uninstall
fi

# =============================================================================
#  Non-interactive flag detection
# =============================================================================
AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y) AUTO_YES=true ;;
    esac
done

# =============================================================================
#  Rollback on failure
# =============================================================================
INSTALL_STAGE=""
rollback() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 && -n "${INSTALL_STAGE}" ]]; then
        echo ""
        error "Installation failed during: ${INSTALL_STAGE}"
        error "Exit code: ${exit_code}"
        echo ""
        warn "Partial installation may remain. To clean up:"
        warn "  bash install.sh --uninstall"
        echo ""
    fi
}
trap rollback EXIT

# =============================================================================
#  1. Banner
# =============================================================================
show_banner

# =============================================================================
#  2. System checks
# =============================================================================
INSTALL_STAGE="system checks"
step "Checking system requirements"

# Root check
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root."
    error "Usage: sudo bash install.sh"
    exit 1
fi
success "Running as root"

# OS detection
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-${ID}}"
else
    error "Cannot detect OS (/etc/os-release not found)"
    exit 1
fi

case "${OS_ID}" in
    ubuntu|debian)
        PKG_MANAGER="apt"
        PKG_UPDATE="apt-get update -qq"
        PKG_INSTALL="apt-get install -y -qq"
        ;;
    centos|rhel|almalinux|rocky|fedora|ol)
        PKG_MANAGER="yum"
        PKG_UPDATE="true"  # yum/dnf update metadata automatically
        if command -v dnf &>/dev/null; then
            PKG_INSTALL="dnf install -y -q"
        else
            PKG_INSTALL="yum install -y -q"
        fi
        ;;
    *)
        error "Unsupported OS: ${OS_ID}"
        error "Supported: Debian, Ubuntu, CentOS, RHEL, Fedora, AlmaLinux, Rocky"
        exit 1
        ;;
esac
success "OS: ${OS_NAME}"

# Architecture detection
ARCH=$(uname -m)
case "${ARCH}" in
    x86_64|amd64)   XRAY_ARCH="Xray-linux-64";           GO_ARCH="amd64" ;;
    aarch64|arm64)   XRAY_ARCH="Xray-linux-arm64-v8a";    GO_ARCH="arm64" ;;
    armv7l|armhf)    XRAY_ARCH="Xray-linux-arm32-v7a";    GO_ARCH="armv6l" ;;
    *)
        error "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac
success "Architecture: ${ARCH}"

# Memory check (warn if < 512MB)
MEM_TOTAL_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
if [[ ${MEM_TOTAL_MB} -gt 0 ]]; then
    if [[ ${MEM_TOTAL_MB} -lt 256 ]]; then
        error "Insufficient memory: ${MEM_TOTAL_MB}MB (minimum 256MB)"
        exit 1
    elif [[ ${MEM_TOTAL_MB} -lt 512 ]]; then
        warn "Low memory: ${MEM_TOTAL_MB}MB (512MB+ recommended)"
    else
        success "Memory: ${MEM_TOTAL_MB}MB"
    fi
fi

# Disk check (warn if < 1GB free)
DISK_FREE_KB=$(df / 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
DISK_FREE_MB=$((DISK_FREE_KB / 1024))
if [[ ${DISK_FREE_MB} -gt 0 ]]; then
    if [[ ${DISK_FREE_MB} -lt 500 ]]; then
        error "Insufficient disk space: ${DISK_FREE_MB}MB free (minimum 500MB)"
        exit 1
    elif [[ ${DISK_FREE_MB} -lt 1024 ]]; then
        warn "Low disk space: ${DISK_FREE_MB}MB free"
    else
        success "Disk: ${DISK_FREE_MB}MB free"
    fi
fi

# =============================================================================
#  2b. Interactive configuration wizard
# =============================================================================
XUI_MODE=false
CDN_DOMAIN=""

if [[ "${AUTO_YES}" == "true" ]]; then
    info "Non-interactive mode (--yes): using defaults"
else
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo ""

    # Ask about mode
    read -p "  Install mode (1=standalone, 2=alongside 3x-ui): " INSTALL_MODE
    case "$INSTALL_MODE" in
        2)
            XUI_MODE=true
            echo -e "  ${GREEN}Will read users from 3x-ui database${NC}"
            ;;
        *)
            XUI_MODE=false
            ;;
    esac

    # Ask about CDN
    read -p "  Do you have a domain for CDN bypass? (y/n): " HAS_DOMAIN
    if [[ "$HAS_DOMAIN" == "y" ]]; then
        read -p "  Enter domain (e.g. vpn.example.com): " CDN_DOMAIN
        echo -e "  ${GREEN}CDN transport will be configured for ${CDN_DOMAIN}${NC}"
    fi

    # Ask about ports (with defaults)
    read -p "  Reality port [443]: " REALITY_PORT_INPUT
    REALITY_PORT=${REALITY_PORT_INPUT:-443}

    read -p "  WebSocket port [2053]: " WS_PORT_INPUT
    WS_PORT=${WS_PORT_INPUT:-2053}

    echo ""
    info "Configuration complete. Starting installation..."
fi

# =============================================================================
#  3. Install dependencies
# =============================================================================
INSTALL_STAGE="installing dependencies"
step "Installing dependencies"

${PKG_UPDATE} 2>/dev/null || true
${PKG_INSTALL} curl unzip jq openssl ca-certificates socat 2>/dev/null
success "System packages installed"

# Install Go if not available (needed to build sub-server)
if ! command -v go &>/dev/null; then
    info "Installing Go toolchain (needed for subscription server)..."
    GO_VERSION="1.22.5"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:${PATH}"
    success "Go ${GO_VERSION} installed"
else
    success "Go available: $(go version | awk '{print $3}')"
fi

# =============================================================================
#  4. Install xray-core
# =============================================================================
INSTALL_STAGE="installing xray-core"
step "Installing xray-core"

install_xray() {
    local latest_tag
    latest_tag=$(curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r '.tag_name')

    if [[ -z "${latest_tag}" || "${latest_tag}" == "null" ]]; then
        error "Failed to fetch latest xray-core version from GitHub"
        exit 1
    fi
    info "Latest version: ${latest_tag}"

    local url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/${XRAY_ARCH}.zip"
    local tmpdir
    tmpdir=$(mktemp -d)

    info "Downloading xray-core..."
    curl -fsSL "${url}" -o "${tmpdir}/xray.zip"

    info "Extracting..."
    unzip -qo "${tmpdir}/xray.zip" -d "${tmpdir}/xray"

    # Install binary
    install -m 755 "${tmpdir}/xray/xray" "${XRAY_BIN}"

    # Install geodata
    mkdir -p "${XRAY_ASSET_DIR}"
    for f in geoip.dat geosite.dat; do
        if [[ -f "${tmpdir}/xray/${f}" ]]; then
            install -m 644 "${tmpdir}/xray/${f}" "${XRAY_ASSET_DIR}/"
        fi
    done

    rm -rf "${tmpdir}"
    success "xray-core ${latest_tag} installed"
}

if [[ -x "${XRAY_BIN}" ]]; then
    CURRENT_VER=$(${XRAY_BIN} version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    info "xray-core already installed: v${CURRENT_VER}"

    # Check for updates
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null | jq -r '.tag_name' 2>/dev/null || echo "")
    if [[ -n "${LATEST_TAG}" && "v${CURRENT_VER}" != "${LATEST_TAG}" ]]; then
        info "Newer version available (${LATEST_TAG}), updating..."
        install_xray
    else
        success "xray-core is up to date"
    fi
else
    install_xray
fi

# =============================================================================
#  5. Generate all credentials
# =============================================================================
INSTALL_STAGE="generating credentials"
step "Generating credentials"

mkdir -p "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

# If sub-config already exists, load credentials from it (idempotent reinstall).
# Supports both v2 format (protocols map) and v1 format (flat fields).
if [[ -f "${SUB_CONFIG}" ]]; then
    info "Existing configuration found. Reusing credentials..."

    # Detect config format: v2 has "protocols" key, v1 has flat "uuid"
    if jq -e '.protocols' "${SUB_CONFIG}" &>/dev/null; then
        # v2 format (new)
        UUID=$(jq -r '.protocols.reality.uuid // empty' "${SUB_CONFIG}")
        PUBLIC_KEY=$(jq -r '.protocols.reality.public_key // empty' "${SUB_CONFIG}")
        SHORT_ID=$(jq -r '.protocols.reality.short_id // empty' "${SUB_CONFIG}")
        SNI_DOMAIN=$(jq -r '.protocols.reality.sni // empty' "${SUB_CONFIG}")
        WS_PATH=$(jq -r '.protocols.ws.path // empty' "${SUB_CONFIG}")
        SS_PASSWORD=$(jq -r '.protocols.ss.password // empty' "${SUB_CONFIG}")
        SS_METHOD=$(jq -r '.protocols.ss.method // "2022-blake3-aes-256-gcm"' "${SUB_CONFIG}")
        SUB_TOKEN=$(jq -r '.sub_token // empty' "${SUB_CONFIG}")
        # Private key is in xray config, not sub-config; extract it
        if [[ -f "${XRAY_CONFIG}" ]]; then
            PRIVATE_KEY=$(jq -r '.inbounds[] | select(.tag=="vless-reality") | .streamSettings.realitySettings.privateKey // empty' "${XRAY_CONFIG}")
        else
            PRIVATE_KEY=""
        fi
    else
        # v1 format (legacy)
        UUID=$(jq -r '.uuid // empty' "${SUB_CONFIG}")
        PUBLIC_KEY=$(jq -r '.public_key // empty' "${SUB_CONFIG}")
        PRIVATE_KEY=$(jq -r '.private_key // empty' "${SUB_CONFIG}")
        SHORT_ID=$(jq -r '.short_id // empty' "${SUB_CONFIG}")
        WS_PATH=$(jq -r '.ws_path // empty' "${SUB_CONFIG}")
        SS_PASSWORD=$(jq -r '.ss_password // empty' "${SUB_CONFIG}")
        SS_METHOD=$(jq -r '.ss_method // "2022-blake3-aes-256-gcm"' "${SUB_CONFIG}")
        SUB_TOKEN=$(jq -r '.token // empty' "${SUB_CONFIG}")
        SNI_DOMAIN=$(jq -r '.sni // empty' "${SUB_CONFIG}")
    fi

    info "Loaded existing credentials (UUID: ${UUID:0:8}...)"
else
    info "Generating fresh credentials..."

    # x25519 keypair (for Reality)
    X25519_OUTPUT=$(${XRAY_BIN} x25519 2>&1)
    PRIVATE_KEY=$(echo "${X25519_OUTPUT}" | grep -i "private" | awk '{print $NF}')
    PUBLIC_KEY=$(echo "${X25519_OUTPUT}" | grep -i "public" | awk '{print $NF}')

    if [[ -z "${PRIVATE_KEY}" || -z "${PUBLIC_KEY}" ]]; then
        error "Failed to generate x25519 keypair"
        detail "xray output: ${X25519_OUTPUT}"
        exit 1
    fi

    # UUID (shared by all VLESS inbounds)
    UUID=$(${XRAY_BIN} uuid 2>/dev/null \
        || cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || uuidgen 2>/dev/null \
        || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/')

    # Short ID for Reality (8 hex chars)
    SHORT_ID=$(openssl rand -hex 4)

    # Random WebSocket path
    WS_PATH="/$(openssl rand -hex 8)"

    # Shadowsocks-2022 password (base64-encoded 32 bytes for 2022-blake3-aes-256-gcm)
    SS_METHOD="2022-blake3-aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 32)

    # Subscription access token
    SUB_TOKEN=$(openssl rand -hex 16)

    # SNI will be detected in the next step
    SNI_DOMAIN=""
fi

# If we loaded existing credentials but PRIVATE_KEY is missing, regenerate the keypair.
# This keeps the same public key / UUID but we need the private key for xray config.
if [[ -z "${PRIVATE_KEY:-}" && -n "${PUBLIC_KEY:-}" ]]; then
    warn "Private key not found (may have been from an older config format)."
    warn "Regenerating x25519 keypair. Clients will need to update public key."
    X25519_OUTPUT=$(${XRAY_BIN} x25519 2>&1)
    PRIVATE_KEY=$(echo "${X25519_OUTPUT}" | grep -i "private" | awk '{print $NF}')
    PUBLIC_KEY=$(echo "${X25519_OUTPUT}" | grep -i "public" | awk '{print $NF}')
fi

success "UUID:          ${UUID}"
success "Public key:    ${PUBLIC_KEY:0:20}..."
success "Short ID:      ${SHORT_ID}"
success "WS path:       ${WS_PATH}"
success "SS method:     ${SS_METHOD}"
success "SS password:   ${SS_PASSWORD:0:12}..."
success "Sub token:     ${SUB_TOKEN:0:16}..."

# =============================================================================
#  6. Detect server IP
# =============================================================================
INSTALL_STAGE="detecting server IP"
step "Detecting server IP"

detect_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
        "https://api.ip.sb/ip"
        "https://ipinfo.io/ip"
    )
    for svc in "${services[@]}"; do
        ip=$(curl -4 -fsSL --max-time 5 "${svc}" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "${ip}" ]] && [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "${ip}"
            return 0
        fi
    done
    # Fallback: kernel route table
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [[ -n "${ip}" ]]; then
        echo "${ip}"
        return 0
    fi
    return 1
}

SERVER_IP=$(detect_ip) || { error "Failed to detect server IP"; exit 1; }
success "Server IP: ${SERVER_IP}"

# =============================================================================
#  7. Find best SNI domain for Reality
# =============================================================================
INSTALL_STAGE="finding best SNI"
step "Finding best SNI domain for Reality"

find_best_sni() {
    local candidates=(
        "www.microsoft.com"
        "www.google.com"
        "www.apple.com"
        "www.amazon.com"
        "cloudflare.com"
        "www.mozilla.org"
        "www.samsung.com"
        "www.docker.com"
    )

    local best_domain="www.microsoft.com"
    local best_time=99999

    for domain in "${candidates[@]}"; do
        local start_ms end_ms elapsed
        start_ms=$(date +%s%N)

        local result
        result=$(timeout 5 openssl s_client -connect "${domain}:443" \
            -tls1_3 -servername "${domain}" \
            -brief </dev/null 2>&1 | head -5)

        if echo "${result}" | grep -qi "TLSv1.3"; then
            end_ms=$(date +%s%N)
            elapsed=$(( (end_ms - start_ms) / 1000000 ))

            if [[ ${elapsed} -lt ${best_time} ]]; then
                best_time=${elapsed}
                best_domain="${domain}"
            fi
            # Output progress to stderr so it doesn't pollute the return value
            echo -e "    ${DIM}${domain} -- TLS 1.3 OK (${elapsed}ms)${NC}" >&2
        else
            echo -e "    ${DIM}${domain} -- no TLS 1.3, skipped${NC}" >&2
        fi
    done

    # Only the domain name goes to stdout (captured by caller)
    echo "${best_domain}"
}

# Only probe if we don't already have a saved SNI
if [[ -z "${SNI_DOMAIN:-}" ]]; then
    SNI_DOMAIN=$(find_best_sni)
fi
success "SNI domain: ${SNI_DOMAIN}"

# =============================================================================
#  8. Generate xray config (3 protocols)
# =============================================================================
INSTALL_STAGE="generating xray config"
step "Generating xray-core configuration"

# Auto-select free ports (avoids conflicts with nginx, x-ui, etc.)
auto_select_ports

mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

cat > "${XRAY_CONFIG}" << XRAYEOF
{
  "log": {
    "loglevel": "warning",
    "access": "${LOG_DIR}/access.log",
    "error": "${LOG_DIR}/error.log"
  },

  "stats": {},
  "api": {
    "tag": "api",
    "services": ["StatsService", "HandlerService", "LoggerService"]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },

  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": ${STATS_PORT},
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },

    {
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "port": ${REALITY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "user@hydraflow",
            "flow": "xtls-rprx-vision",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${SNI_DOMAIN}:443",
          "xver": 0,
          "serverNames": ["${SNI_DOMAIN}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}", ""]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": false
      }
    },

    {
      "tag": "vless-ws",
      "listen": "0.0.0.0",
      "port": ${WS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "user-ws@hydraflow",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "${WS_PATH}",
          "headers": { "Host": "${SERVER_IP}" }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": false
      }
    },

    {
      "tag": "shadowsocks",
      "listen": "0.0.0.0",
      "port": ${SS_PORT},
      "protocol": "shadowsocks",
      "settings": {
        "method": "${SS_METHOD}",
        "password": "${SS_PASSWORD}",
        "network": "tcp,udp",
        "level": 0,
        "email": "user-ss@hydraflow"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": false
      }
    }
  ],

  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {
        "response": { "type": "http" }
      }
    }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": ["geoip:private"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["geoip:cn", "geoip:ru"]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": [
          "geosite:category-ads-all",
          "domain:doubleclick.net",
          "domain:googlesyndication.com",
          "domain:googleadservices.com",
          "domain:google-analytics.com",
          "domain:adservice.google.com",
          "domain:pagead2.googlevideo.com",
          "domain:s0.2mdn.net",
          "domain:ad.youtube.com",
          "domain:ads.youtube.com",
          "domain:facebook-ads.com",
          "domain:analytics.tiktok.com",
          "domain:ads.tiktok.com",
          "domain:mc.yandex.ru",
          "domain:an.yandex.ru",
          "domain:yandexadexchange.net",
          "domain:adfox.ru"
        ]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "protocol": ["bittorrent"]
      }
    ]
  }
}
XRAYEOF

chmod 640 "${XRAY_CONFIG}"
success "xray config written to ${XRAY_CONFIG}"
detail "Inbounds: vless-reality (:${REALITY_PORT}), vless-ws (:${WS_PORT}), shadowsocks (:${SS_PORT})"

# =============================================================================
#  9. Generate subscription config
# =============================================================================
INSTALL_STAGE="generating subscription config"
step "Generating subscription server configuration"

cat > "${SUB_CONFIG}" << SUBEOF
{
  "server_ip": "${SERVER_IP}",
  "sub_token": "${SUB_TOKEN}",
  "sub_port": ${SUB_PORT},
  "protocols": {
    "reality": {
      "port": ${REALITY_PORT},
      "uuid": "${UUID}",
      "public_key": "${PUBLIC_KEY}",
      "short_id": "${SHORT_ID}",
      "sni": "${SNI_DOMAIN}",
      "flow": "xtls-rprx-vision",
      "fingerprint": "chrome"
    },
    "ws": {
      "port": ${WS_PORT},
      "uuid": "${UUID}",
      "path": "${WS_PATH}",
      "host": "${SERVER_IP}"
    },
    "ss": {
      "port": ${SS_PORT},
      "method": "${SS_METHOD}",
      "password": "${SS_PASSWORD}"
    }
  }
}
SUBEOF

chmod 640 "${SUB_CONFIG}"
success "Subscription config written to ${SUB_CONFIG}"

# =============================================================================
#  10. Build subscription server
# =============================================================================
INSTALL_STAGE="building subscription server"
step "Building subscription server"

# Locate the Go source
SUB_SERVER_SRC=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "/tmp")"

if [[ -f "${SCRIPT_DIR}/tools/sub-server.go" ]]; then
    SUB_SERVER_SRC="${SCRIPT_DIR}/tools/sub-server.go"
    info "Found local source: ${SUB_SERVER_SRC}"
else
    info "Downloading sub-server source from GitHub..."
    SUB_SERVER_SRC="/tmp/hydraflow-sub-server.go"
    curl -fsSL "https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/tools/sub-server.go" \
        -o "${SUB_SERVER_SRC}" 2>/dev/null || true
fi

BUILD_OK=false
if [[ -f "${SUB_SERVER_SRC}" ]]; then
    info "Compiling subscription server..."
    export CGO_ENABLED=0
    if /usr/local/go/bin/go build -o "${SUB_BIN}" -ldflags="-s -w" "${SUB_SERVER_SRC}" 2>/dev/null \
        || go build -o "${SUB_BIN}" -ldflags="-s -w" "${SUB_SERVER_SRC}" 2>/dev/null; then
        chmod 755 "${SUB_BIN}"
        BUILD_OK=true
        success "Subscription server compiled: ${SUB_BIN}"
    fi
fi

# Fallback: shell-based subscription server using socat
if [[ "${BUILD_OK}" != "true" ]]; then
    warn "Go build failed. Creating shell-based fallback subscription server..."

    cat > "${SUB_BIN}" << 'SHSUBEOF'
#!/usr/bin/env bash
# HydraFlow subscription server (shell fallback)
# Serves base64-encoded subscription links via socat.
# Reads the v2-format sub-config.json with "protocols" map.
set -euo pipefail

CONFIG="/etc/hydraflow/sub-config.json"
cfg() { jq -r "$1" "${CONFIG}"; }

# Handle mode: serve a single HTTP request on stdin/stdout
if [[ "${1:-}" == "--handle" ]]; then
    SERVER_IP=$(cfg '.server_ip')
    TOKEN=$(cfg '.sub_token')

    UUID=$(cfg '.protocols.reality.uuid')
    PUBLIC_KEY=$(cfg '.protocols.reality.public_key')
    SHORT_ID=$(cfg '.protocols.reality.short_id')
    SNI=$(cfg '.protocols.reality.sni')
    REALITY_PORT=$(cfg '.protocols.reality.port')

    WS_PATH=$(cfg '.protocols.ws.path')
    WS_PORT=$(cfg '.protocols.ws.port')

    SS_PORT=$(cfg '.protocols.ss.port')
    SS_METHOD=$(cfg '.protocols.ss.method // "2022-blake3-aes-256-gcm"')
    SS_PASSWORD=$(cfg '.protocols.ss.password')

    VLESS_REALITY="vless://${UUID}@${SERVER_IP}:${REALITY_PORT}?security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision&encryption=none#HydraFlow-Reality"
    VLESS_WS="vless://${UUID}@${SERVER_IP}:${WS_PORT}?security=none&type=ws&path=${WS_PATH}&host=${SERVER_IP}&encryption=none#HydraFlow-WS"

    SS_USER_INFO=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)
    SS_LINK="ss://${SS_USER_INFO}@${SERVER_IP}:${SS_PORT}#HydraFlow-SS"

    LINKS="${VLESS_REALITY}"$'\n'"${VLESS_WS}"$'\n'"${SS_LINK}"
    BODY=$(echo -n "${LINKS}" | base64 -w 0)

    # Read the HTTP request line
    request=""
    read -r request || true
    path=$(echo "${request}" | awk '{print $2}')

    # Consume headers
    while IFS= read -r header; do
        header=$(echo "${header}" | tr -d '\r')
        [[ -z "${header}" ]] && break
    done

    if [[ "${path}" == "/sub/${TOKEN}" ]]; then
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${BODY}"
    elif [[ "${path}" == "/health" ]]; then
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}"
    else
        echo -e "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
    fi
    exit 0
fi

# Main mode: listen with socat
LISTEN_PORT=$(cfg '.sub_port')
echo "HydraFlow subscription server (shell) starting on port ${LISTEN_PORT}"
exec socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork SYSTEM:"bash $0 --handle"
SHSUBEOF

    chmod 755 "${SUB_BIN}"
    success "Shell-based fallback subscription server created"
fi

# =============================================================================
#  11. Create systemd services
# =============================================================================
INSTALL_STAGE="creating systemd services"
step "Creating systemd services"

# --- hydraflow-xray.service ---
cat > /etc/systemd/system/hydraflow-xray.service << SVCEOF
[Unit]
Description=HydraFlow Xray-core Proxy Server
Documentation=https://github.com/Evr1kys/HydraFlow
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -config ${XRAY_CONFIG}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30
TimeoutStopSec=30

Environment="XRAY_LOCATION_ASSET=${XRAY_ASSET_DIR}"

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RemoveIPC=true

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW

ReadWritePaths=${CONFIG_DIR} ${LOG_DIR}
ReadOnlyPaths=/etc/ssl/certs /usr/share/ca-certificates ${XRAY_ASSET_DIR}

LimitNOFILE=65535
LimitNPROC=4096

StandardOutput=journal
StandardError=journal
SyslogIdentifier=hydraflow-xray

[Install]
WantedBy=multi-user.target
SVCEOF

success "hydraflow-xray.service created"

# --- hydraflow-sub.service ---
cat > /etc/systemd/system/hydraflow-sub.service << SUBSVCEOF
[Unit]
Description=HydraFlow Subscription Server
Documentation=https://github.com/Evr1kys/HydraFlow
After=network-online.target hydraflow-xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SUB_BIN} -config ${SUB_CONFIG}
Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

ReadOnlyPaths=${CONFIG_DIR}

LimitNOFILE=4096

StandardOutput=journal
StandardError=journal
SyslogIdentifier=hydraflow-sub

[Install]
WantedBy=multi-user.target
SUBSVCEOF

success "hydraflow-sub.service created"

# Check if required ports are free before starting services
check_port() {
    local port=$1
    local name=$2
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        local pid
        pid=$(ss -tlnp 2>/dev/null | grep ":${port} " | sed -E 's/.*pid=([0-9]+).*/\1/' | head -1)
        warn "Port ${port} (${name}) is already in use (pid: ${pid:-unknown})."
        warn "  Consider stopping the conflicting service or changing ${name} port."
        return 1
    fi
    return 0
}

PORT_CONFLICT=0
check_port "${REALITY_PORT}" "Reality"  || PORT_CONFLICT=1
check_port "${WS_PORT}"      "WebSocket" || PORT_CONFLICT=1
check_port "${SS_PORT}"      "Shadowsocks" || PORT_CONFLICT=1
check_port "${SUB_PORT}"     "Subscription" || PORT_CONFLICT=1

if [[ ${PORT_CONFLICT} -eq 1 ]]; then
    warn ""
    warn "One or more required ports are occupied."
    warn "Services may fail to start. Consider freeing the ports above."
    warn ""
fi

# Enable and start
systemctl daemon-reload

systemctl enable hydraflow-xray.service 2>/dev/null
systemctl enable hydraflow-sub.service 2>/dev/null

systemctl stop hydraflow-xray.service 2>/dev/null || true
systemctl stop hydraflow-sub.service 2>/dev/null || true

systemctl start hydraflow-xray.service
success "hydraflow-xray started"

systemctl start hydraflow-sub.service 2>/dev/null \
    && success "hydraflow-sub started" \
    || warn "hydraflow-sub failed to start (check: journalctl -u hydraflow-sub)"

# =============================================================================
#  12. Configure firewall
# =============================================================================
INSTALL_STAGE="configuring firewall"
step "Configuring firewall"

ALL_PORTS=("${REALITY_PORT}" "${WS_PORT}" "${SS_PORT}" "${SUB_PORT}")

if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    info "Configuring ufw (already active)..."
    ufw allow "${REALITY_PORT}/tcp" comment "HydraFlow Reality" 2>/dev/null || true
    ufw allow "${WS_PORT}/tcp"      comment "HydraFlow WS"      2>/dev/null || true
    ufw allow "${SS_PORT}/tcp"      comment "HydraFlow SS"       2>/dev/null || true
    ufw allow "${SS_PORT}/udp"      comment "HydraFlow SS UDP"   2>/dev/null || true
    ufw allow "${SUB_PORT}/tcp"     comment "HydraFlow Sub"      2>/dev/null || true
    success "ufw rules added"

elif command -v firewall-cmd &>/dev/null; then
    info "Configuring firewalld..."
    for port in "${ALL_PORTS[@]}"; do
        firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
    done
    firewall-cmd --permanent --add-port="${SS_PORT}/udp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    success "firewalld rules added"

elif command -v iptables &>/dev/null; then
    info "Configuring iptables..."
    for port in "${ALL_PORTS[@]}"; do
        iptables  -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null \
            || iptables  -A INPUT -p tcp --dport "${port}" -j ACCEPT
    done
    # SS also needs UDP
    iptables  -C INPUT -p udp --dport "${SS_PORT}" -j ACCEPT 2>/dev/null \
        || iptables  -A INPUT -p udp --dport "${SS_PORT}" -j ACCEPT

    # Persist
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        elif command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save 2>/dev/null || true
        fi
    fi
    success "iptables rules added"
else
    warn "No firewall detected. Please manually open ports: ${ALL_PORTS[*]}"
fi

# =============================================================================
#  13. Build connection links
# =============================================================================
INSTALL_STAGE="building links"
step "Building connection links"

# URL-encode the WS path
WS_PATH_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${WS_PATH}'))" 2>/dev/null || echo "${WS_PATH}")

# VLESS + Reality
VLESS_REALITY_LINK="vless://${UUID}@${SERVER_IP}:${REALITY_PORT}?security=reality&sni=${SNI_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision&encryption=none#HydraFlow-Reality"

# VLESS + WebSocket
VLESS_WS_LINK="vless://${UUID}@${SERVER_IP}:${WS_PORT}?security=none&type=ws&path=${WS_PATH_ENCODED}&host=${SERVER_IP}&encryption=none#HydraFlow-WS"

# Shadowsocks-2022
SS_USER_INFO=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0 2>/dev/null || echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 2>/dev/null | tr -d '\n')
SS_LINK="ss://${SS_USER_INFO}@${SERVER_IP}:${SS_PORT}#HydraFlow-SS"

# Subscription URL
SUB_URL="http://${SERVER_IP}:${SUB_PORT}/sub/${SUB_TOKEN}"

# Clear the install stage (success path)
INSTALL_STAGE=""

# =============================================================================
#  14. Print results
# =============================================================================

echo ""
echo ""
echo -e "${GREEN}"
cat << 'DONE_BANNER'
     _                  _
  __| | ___  _ __   ___| |
 / _` |/ _ \| '_ \ / _ \ |
| (_| | (_) | | | |  __/_|
 \__,_|\___/|_| |_|\___(_)

DONE_BANNER
echo -e "${NC}"

# ---- Beautiful box ----
BOX_W=64

box_top()    { printf "${GREEN}"; printf '%0.s=' $(seq 1 $BOX_W); printf "${NC}\n"; }
box_empty()  { printf "${GREEN}||${NC}%-$(($BOX_W - 4))s${GREEN}||${NC}\n" ""; }
box_line()   { printf "${GREEN}||${NC}  %-$(($BOX_W - 6))s${GREEN}||${NC}\n" "$1"; }
box_center() {
    local text="$1"
    local len=${#text}
    local pad=$(( ($BOX_W - 4 - len) / 2 ))
    local rpad=$(( $BOX_W - 4 - len - pad ))
    printf "${GREEN}||${NC}%${pad}s${BOLD}%s${NC}%${rpad}s${GREEN}||${NC}\n" "" "${text}" ""
}
box_sep()    { printf "${GREEN}||"; printf '%0.s-' $(seq 1 $(($BOX_W - 4))); printf "||${NC}\n"; }
box_bot()    { printf "${GREEN}"; printf '%0.s=' $(seq 1 $BOX_W); printf "${NC}\n"; }

box_top
box_empty
box_center "HydraFlow installed successfully!"
box_center "v${HYDRAFLOW_VERSION}"
box_empty
box_sep
box_empty
box_line "Server:     ${SERVER_IP}"
box_line "Protocols:  3 configured"
box_empty
box_line "  [1] VLESS + Reality     port ${REALITY_PORT}"
box_line "  [2] VLESS + WebSocket   port ${WS_PORT}"
box_line "  [3] Shadowsocks-2022    port ${SS_PORT}"
box_empty
box_sep
box_empty
box_line "SUBSCRIPTION URL (add to any client):"
box_empty
box_line "  ${SUB_URL}"
box_empty
box_line "  Formats:  ?format=clash  |  ?format=singbox"
box_line "  Auto-detects client from User-Agent."
box_empty
box_sep
box_empty
box_line "VLESS Reality (paste into v2rayNG / Hiddify):"
box_empty
box_bot

# Print the actual links outside the box (they're too long to fit)
echo ""
echo -e "  ${CYAN}${BOLD}VLESS + Reality:${NC}"
echo -e "  ${YELLOW}${VLESS_REALITY_LINK}${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}VLESS + WebSocket:${NC}"
echo -e "  ${YELLOW}${VLESS_WS_LINK}${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}Shadowsocks-2022:${NC}"
echo -e "  ${YELLOW}${SS_LINK}${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}Subscription:${NC}"
echo -e "  ${YELLOW}${SUB_URL}${NC}"
echo ""

# ---- QR code ----
echo -e "${CYAN}${BOLD}QR Code:${NC}"
if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 "${VLESS_REALITY_LINK}" 2>/dev/null || true
else
    ENCODED_LINK=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${VLESS_REALITY_LINK}'))" 2>/dev/null || echo "${VLESS_REALITY_LINK}")
    echo -e "  Install ${BOLD}qrencode${NC} for terminal QR, or open:"
    echo -e "  ${DIM}https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${ENCODED_LINK}${NC}"
fi
echo ""

# ---- Management ----
echo -e "${CYAN}${BOLD}Management:${NC}"
echo -e "  ${BOLD}systemctl status hydraflow-xray${NC}    -- proxy status"
echo -e "  ${BOLD}systemctl restart hydraflow-xray${NC}   -- restart proxy"
echo -e "  ${BOLD}journalctl -u hydraflow-xray -f${NC}    -- live logs"
echo -e "  ${BOLD}journalctl -u hydraflow-sub -f${NC}     -- subscription logs"
echo ""
echo -e "${CYAN}${BOLD}Files:${NC}"
echo -e "  Config:   ${CONFIG_DIR}/"
echo -e "  Xray:     ${XRAY_CONFIG}"
echo -e "  Sub:      ${SUB_CONFIG}"
echo -e "  Logs:     ${LOG_DIR}/"
echo ""
echo -e "${CYAN}${BOLD}Uninstall:${NC}"
echo -e "  ${BOLD}bash install.sh --uninstall${NC}"
echo ""

# ---- Service status ----
echo -e "${CYAN}${BOLD}Service Status:${NC}"
if systemctl is-active --quiet hydraflow-xray 2>/dev/null; then
    echo -e "  hydraflow-xray:  ${GREEN}${BOLD}RUNNING${NC}"
else
    echo -e "  hydraflow-xray:  ${RED}${BOLD}NOT RUNNING${NC}"
    echo -e "  ${DIM}Check: journalctl -u hydraflow-xray --no-pager -n 20${NC}"
fi
if systemctl is-active --quiet hydraflow-sub 2>/dev/null; then
    echo -e "  hydraflow-sub:   ${GREEN}${BOLD}RUNNING${NC}"
else
    echo -e "  hydraflow-sub:   ${YELLOW}${BOLD}NOT RUNNING${NC}"
    echo -e "  ${DIM}Check: journalctl -u hydraflow-sub --no-pager -n 20${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation completed in ${SECONDS}s.${NC}"
echo ""
