#!/usr/bin/env bash
# =============================================================================
#  Lycan Security Agent — install.sh
#  Instala dependencias del sistema y registra el comando `lycan` globalmente.
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

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'EOF'
  _  __  ___   _   _   ___   _  _
 | |/ / |_ _| | | | | / __| | \| |
 | ' <   | |  | |_| || (__  | .` |
  \_/\_\ |_|   \__, | \___| |_|\_|
  __  __  ___   |___/ __  _ _  ___
 / _|/ _||  _| / __| | || | | | _ \
|__ \__ \| _| | (__  | |_| | |  _/
|___/|___/|___|  \___|  \___/  |_|

  Agent Installer v1.1.0
EOF
echo -e "${NC}"

# ── 1. Verificar Python 3 ─────────────────────────────────────────────────────
info "Verificando Python 3..."
if ! command -v python3 &>/dev/null; then
    error "Python 3 no encontrado. Instálalo primero: apt install python3"
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python encontrado: ${PY_VER}"
if python3 -c 'import sys; exit(0 if sys.version_info >= (3,10) else 1)'; then
    success "Versión de Python compatible (≥ 3.10)"
else
    error "Se requiere Python 3.10 o superior. Versión actual: ${PY_VER}"
fi

# ── 2. Verificar pip ──────────────────────────────────────────────────────────
info "Verificando pip..."
if ! python3 -m pip --version &>/dev/null; then
    warn "pip no encontrado. Intentando instalar..."
    python3 -m ensurepip --upgrade || error "No se pudo instalar pip."
fi
success "pip disponible: $(python3 -m pip --version | awk '{print $2}')"

# ── 3. Dependencias del sistema ───────────────────────────────────────────────
info "Instalando dependencias del sistema (nmap, sqlmap, curl)..."

OS_NAME="$(uname -s)"

if [ "$OS_NAME" = "Darwin" ]; then
    if command -v brew &>/dev/null; then
        brew install nmap sqlmap curl 2>/dev/null
        success "Paquetes del sistema instalados via brew (macOS)"
    else
        warn "Homebrew no encontrado en macOS. Instala nmap y sqlmap manualmente."
    fi
else
    # Linux package managers
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            nmap \
            sqlmap \
            curl \
            iputils-ping \
            ca-certificates \
            2>/dev/null
        success "Paquetes del sistema instalados via apt"
    elif command -v dnf &>/dev/null; then
        dnf install -y nmap sqlmap curl 2>/dev/null
        success "Paquetes del sistema instalados via dnf"
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm nmap sqlmap curl 2>/dev/null
        success "Paquetes del sistema instalados via pacman"
    else
        warn "Gestor de paquetes no reconocido. Instala nmap y sqlmap manualmente."
    fi
fi

# Verificar herramientas críticas
for tool in nmap; do
    if command -v "$tool" &>/dev/null; then
        success "$tool disponible: $(command -v $tool)"
    else
        warn "$tool no encontrado. Algunas funciones estarán limitadas."
    fi
done

# ── 4. Instalar el agente en modo editable ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Instalando lycan-security-agent desde: ${SCRIPT_DIR}"

python3 -m pip install --upgrade pip --quiet
python3 -m pip install -e "${SCRIPT_DIR}" --quiet

# Verificar que el entry-point quedó registrado
if command -v lycan &>/dev/null; then
    success "Comando 'lycan' registrado en: $(command -v lycan)"
else
    # Puede estar en ~/.local/bin (instalación de usuario)
    export PATH="$HOME/.local/bin:$PATH"
    if command -v lycan &>/dev/null; then
        success "Comando 'lycan' disponible en ~/.local/bin"
        warn "Añade esto a tu ~/.bashrc o ~/.zshrc:"
        echo -e "    ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    else
        error "'lycan' no se registró. Revisa la salida de pip install."
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
    success "Configuración creada en: ${CONFIG_FILE}"
    warn "Edita ${CONFIG_FILE} con tu API Key antes de ejecutar 'lycan start'"
else
    info "Configuración existente detectada: ${CONFIG_FILE}"
fi

# ── 6. Resumen final ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Instalación completada.${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Comandos disponibles:"
echo -e "    ${CYAN}lycan start${NC}                  → Iniciar el agente"
echo -e "    ${CYAN}lycan start --key <API_KEY>${NC}  → Iniciar con API Key"
echo -e "    ${CYAN}lycan start --verbose${NC}        → Modo detallado"
echo -e "    ${CYAN}lycan install-deps${NC}           → Reinstalar nmap/sqlmap"
echo -e "    ${CYAN}lycan config${NC}                 → Mostrar configuración activa"
echo ""
