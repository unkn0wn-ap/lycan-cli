#!/usr/bin/env bash
# =============================================================================
#  Lycan Security Agent — install.sh
#  Installs system dependencies and registers `lycan` globally.
#
#  Uso:
#      chmod +x install.sh
#      sudo ./install.sh
# =============================================================================
set -euo pipefail

# ── Colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Privileges ───────────────────────────────────────────────────────────────
SUDO=()
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO=(sudo)
        if [ -r /dev/tty ]; then
            info "Requesting administrator privileges..."
            sudo -v < /dev/tty || error "Unable to acquire sudo privileges."
        else
            warn "No TTY available for sudo prompt."
        fi
    else
        error "Administrator privileges are required (sudo not found)."
    fi
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'EOF'
 _      __     __   ____   _   _   ____   _____   ____   _   _   ____    ____   _____  __   __
| |     \ \   / /  / ___| | \ | | / ___| | ____| / ___| | | | | / ___|  / ___| |_   _| \ \ / /
| |      \ \ / /  | |     |  \| | \___ \ |  _|   \___ \ | | | | \___ \ | |       | |    \ V /
| |___    \ V /   | |___  | |\  |  ___) || |___   ___) || |_| |  ___) || |___    | |     | |
|_____|    \_/     \____| |_| \_| |____/ |_____| |____/  \___/  |____/  \____|   |_|     |_|

  Agent Installer v1.1.0
EOF
echo -e "${NC}"

# ── 1. Verify Python 3 ────────────────────────────────────────────────────────
info "Checking Python 3..."
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install it first (e.g., apt install python3)."
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python detected: ${PY_VER}"
if python3 -c 'import sys; exit(0 if sys.version_info >= (3,10) else 1)'; then
    success "Python version is supported (>= 3.10)."
else
    error "Python 3.10+ is required. Current version: ${PY_VER}"
fi

# ── 2. Verify pip ─────────────────────────────────────────────────────────────
info "Checking pip..."
if ! python3 -m pip --version &>/dev/null; then
    warn "pip not found. Installing via system package manager..."
    if command -v apt-get &>/dev/null; then
        "${SUDO[@]}" apt-get update -qq
        DEBIAN_FRONTEND=noninteractive "${SUDO[@]}" apt-get install -y python3-pip 2>/dev/null
    elif command -v dnf &>/dev/null; then
        "${SUDO[@]}" dnf install -y python3-pip 2>/dev/null
    elif command -v pacman &>/dev/null; then
        "${SUDO[@]}" pacman -Sy --noconfirm python-pip 2>/dev/null
    elif command -v brew &>/dev/null; then
        brew install python 2>/dev/null
    else
        error "pip is required but no supported package manager was found."
    fi
fi
if ! python3 -m pip --version &>/dev/null; then
    error "pip is still unavailable after installation attempt."
fi
success "pip available: $(python3 -m pip --version | awk '{print $2}')"

# ── 3. System dependencies ────────────────────────────────────────────────────
info "Checking system dependencies (nmap, sqlmap, curl)..."

OS_NAME="$(uname -s)"

is_tool_ready() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

missing_tools=()
for tool in nmap sqlmap curl; do
    if ! is_tool_ready "$tool"; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -eq 0 ]; then
    success "All required system tools are already installed."
else
    info "Installing missing tools: ${missing_tools[*]}"
    if [ "$OS_NAME" = "Darwin" ]; then
        if command -v brew &>/dev/null; then
            brew install "${missing_tools[@]}" 2>/dev/null
            success "System packages installed via Homebrew."
        else
            warn "Homebrew not found on macOS. Please install ${missing_tools[*]} manually."
        fi
    else
        # Linux package managers
        if command -v apt-get &>/dev/null; then
            "${SUDO[@]}" apt-get update -qq
            "${SUDO[@]}" apt-get install -y --no-install-recommends \
                "${missing_tools[@]}" \
                iputils-ping \
                ca-certificates \
                2>/dev/null
            success "System packages installed via apt."
        elif command -v dnf &>/dev/null; then
            "${SUDO[@]}" dnf install -y "${missing_tools[@]}" 2>/dev/null
            success "System packages installed via dnf."
        elif command -v pacman &>/dev/null; then
            "${SUDO[@]}" pacman -Sy --noconfirm "${missing_tools[@]}" 2>/dev/null
            success "System packages installed via pacman."
        else
            warn "Unsupported package manager. Install ${missing_tools[*]} manually."
        fi
    fi
fi

# Verificar herramientas críticas
for tool in nmap; do
    if command -v "$tool" &>/dev/null; then
        success "$tool available: $(command -v $tool)"
    else
        warn "$tool not found. Some features will be limited."
    fi
done

# ── 4. Install the agent ──────────────────────────────────────────────────────
SCRIPT_PATH="${BASH_SOURCE[0]:-${0:-}}"
SCRIPT_DIR=""
TEMP_DIR=""

if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
else
    TEMP_DIR="$(mktemp -d)"
    REPO_URL="https://github.com/unkn0wn-ap/lycan-cli"
    info "Downloading installer sources from ${REPO_URL}..."
    curl -sSL "${REPO_URL}/archive/refs/heads/main.tar.gz" | tar -xz -C "$TEMP_DIR"
    SCRIPT_DIR="$(find "$TEMP_DIR" -maxdepth 1 -type d -name 'lycan-cli-*' | head -n 1)"
fi

[ -n "$SCRIPT_DIR" ] || error "Unable to determine installation directory."
info "Installing lycan-security-agent from: ${SCRIPT_DIR}"

python3 -m pip install --upgrade pip --quiet
python3 -m pip install -e "${SCRIPT_DIR}" --quiet

# Verificar que el entry-point quedó registrado
if command -v lycan &>/dev/null; then
    success "'lycan' command registered at: $(command -v lycan)"
else
    # Puede estar en ~/.local/bin (instalación de usuario)
    export PATH="$HOME/.local/bin:$PATH"
    if command -v lycan &>/dev/null; then
        success "'lycan' available in ~/.local/bin"
        warn "Add this to your ~/.bashrc or ~/.zshrc:"
        echo -e "    ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    else
        error "'lycan' was not registered. Check pip install output."
    fi
fi

# ── 5. Crear directorio de configuración ─────────────────────────────────────
CONFIG_DIR="$HOME/.lycan"
CONFIG_FILE="$CONFIG_DIR/config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << 'JSONEOF'
{
  "lycan_api_key": "",
  "supabase_url": "",
  "supabase_anon_key": "",
  "worker_id": "",
  "agent_mode": "VERBOSE",
  "heartbeat_interval_seconds": 60
}
JSONEOF
    chmod 600 "$CONFIG_FILE"
    success "Configuration created at: ${CONFIG_FILE}"
    warn "Edit ${CONFIG_FILE} with your API key before running 'lycan start'"
else
    info "Existing configuration detected: ${CONFIG_FILE}"
fi

if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
fi

# ── 6. Resumen final ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Installation complete.${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Commands available:"
echo -e "    ${CYAN}lycan start${NC}                  → Start the agent"
echo -e "    ${CYAN}lycan start --key <API_KEY>${NC}  → Start with API key"
echo -e "    ${CYAN}lycan start --verbose${NC}        → Verbose mode"
echo -e "    ${CYAN}lycan install-deps${NC}           → Reinstall nmap/sqlmap"
echo -e "    ${CYAN}lycan config${NC}                 → Show active configuration"
echo ""
