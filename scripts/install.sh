#!/usr/bin/env bash
# LocalVault — Arch Linux installer
# Usage: curl -sSL <raw-url>/scripts/install.sh | bash
# Or:    git clone ... && cd localvault && bash scripts/install.sh
set -euo pipefail

APP_NAME="localvault"
INSTALL_DIR="${HOME}/.local/bin"
DESKTOP_DIR="${HOME}/.local/share/applications"
REPO_URL="https://github.com/david206614/localvault.git"
BUILD_DIR="${HOME}/.cache/localvault-build"

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { err "$*"; exit 1; }

# ── Prechecks ───────────────────────────────────────────────────────
check_arch() {
    if [[ ! -f /etc/arch-release ]]; then
        die "This installer supports Arch Linux only. See README.md for other distros."
    fi
    ok "Arch Linux detected"
}

check_not_root() {
    if [[ "$EUID" -eq 0 ]]; then
        die "Do not run this script as root. It will ask for sudo when needed."
    fi
}

# ── System dependencies (pacman) ────────────────────────────────────
DEPS=(
    base-devel
    rust
    nodejs
    npm
    webkit2gtk-4.1
    gtk3
    openssl
    libsoup3
    librsvg
    hicolor-icon-theme
    pkg-config
)

install_deps() {
    info "Checking system dependencies..."
    local missing=()
    for dep in "${DEPS[@]}"; do
        if ! pacman -Qi "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "All system dependencies are installed"
        return
    fi

    warn "Missing dependencies: ${missing[*]}"
    info "Installing with sudo (you may be prompted for your password)..."
    sudo pacman -S --needed --noconfirm "${missing[@]}"
    ok "Dependencies installed"
}

# ── Source code ──────────────────────────────────────────────────────
get_source() {
    # If we're already inside the repo, use local source
    if [[ -f "src-tauri/Cargo.toml" && -f "package.json" ]]; then
        info "Building from local source: $(pwd)"
        SOURCE_DIR="$(pwd)"
        return
    fi

    # Otherwise clone into cache
    if [[ -d "${BUILD_DIR}/.git" ]]; then
        info "Updating existing clone..."
        git -C "${BUILD_DIR}" pull --ff-only
    else
        info "Cloning repository..."
        rm -rf "${BUILD_DIR}"
        git clone "${REPO_URL}" "${BUILD_DIR}"
    fi
    SOURCE_DIR="${BUILD_DIR}"
}

# ── Build ────────────────────────────────────────────────────────────
build_frontend() {
    info "Installing frontend dependencies..."
    (cd "${SOURCE_DIR}" && npm ci)

    info "Building frontend (TypeScript + Vite)..."
    (cd "${SOURCE_DIR}" && npm run build)
    ok "Frontend built"
}

build_tauri() {
    info "Building Tauri release binary (this may take a few minutes)..."
    (cd "${SOURCE_DIR}/src-tauri" && cargo build --release --features app)
    ok "Tauri binary built"
}

# ── Install ──────────────────────────────────────────────────────────
install_binary() {
    local src="${SOURCE_DIR}/src-tauri/target/release/${APP_NAME}"
    if [[ ! -f "$src" ]]; then
        die "Binary not found at ${src}. Build may have failed."
    fi

    mkdir -p "${INSTALL_DIR}"
    cp "$src" "${INSTALL_DIR}/${APP_NAME}"
    chmod +x "${INSTALL_DIR}/${APP_NAME}"
    ok "Binary installed to ${INSTALL_DIR}/${APP_NAME}"
}

install_desktop_entry() {
    mkdir -p "${DESKTOP_DIR}"
    cat > "${DESKTOP_DIR}/${APP_NAME}.desktop" << 'DESKTOP'
[Desktop Entry]
Name=LocalVault
Comment=Encrypted password manager for Linux
Exec=localvault
Icon=localvault
Terminal=false
Type=Application
Categories=Utility;Security;密码管理;
Keywords=password;vault;security;encrypted;
DESKTOP
    ok "Desktop entry installed to ${DESKTOP_DIR}/${APP_NAME}.desktop"
}

cleanup() {
    if [[ "${SOURCE_DIR}" == "${BUILD_DIR}" ]]; then
        info "Cleaning build cache..."
        rm -rf "${BUILD_DIR}"
    fi
}

# ── PATH check ───────────────────────────────────────────────────────
check_path() {
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        warn "${INSTALL_DIR} is not in your PATH."
        echo "  Add this to your ~/.bashrc or ~/.zshrc:"
        echo ""
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       LocalVault — Arch Installer    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    echo ""

    check_arch
    check_not_root
    install_deps
    get_source
    build_frontend
    build_tauri
    install_binary
    install_desktop_entry
    cleanup
    check_path

    echo ""
    ok "Installation complete!"
    echo ""
    echo "  Run:  localvault"
    echo "  Or find 'LocalVault' in your application menu."
    echo ""
}

main "$@"
