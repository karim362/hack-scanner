#!/usr/bin/env bash
set -e
HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
mkdir -p "$TOOLS"

detect_os() {
    case "$(uname -s)" in
        Linux) [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ] && echo "termux" || echo "linux" ;;
        Darwin) echo "macos" ;;
        *) echo "unknown" ;;
    esac
}
detect_arch() {
    case "$(uname -m)" in
        aarch64|arm64) echo "arm64" ;;
        x86_64|amd64) echo "amd64" ;;
        armv7l) echo "armv7" ;;
        *) echo "unknown" ;;
    esac
}
install_deps() {
    case "$1" in
        termux) command -v python3 >/dev/null || pkg install -y python git curl unzip golang ;;
        linux) command -v python3 >/dev/null || sudo apt install -y python3 python3-pip git curl unzip golang ;;
        macos) command -v python3 >/dev/null || brew install python3 git curl go ;;
    esac
}
install_dirsearch() {
    [ -f "$TOOLS/dirsearch/dirsearch.py" ] && return
    echo "  → Installing dirsearch..."
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$TOOLS/dirsearch" 2>/dev/null
    cd "$TOOLS/dirsearch" || return
    if pip3 install -q -r requirements.txt 2>/dev/null; then
        return
    fi
    if pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null; then
        echo "  ok dirsearch deps (--break-system-packages)"
        return
    fi
    echo "  -> Creating venv..."
    python3 -m venv .venv 2>/dev/null && .venv/bin/pip install -q -r requirements.txt 2>/dev/null && echo "  ok dirsearch deps (venv)"
}
install_godirb() {
    [ -x "$TOOLS/godirb" ] && return
    echo "  → Installing godirb..."
    if command -v go >/dev/null; then
        go install github.com/MyCode83/godirb@latest 2>/dev/null
        if [ -f "$HOME/go/bin/godirb" ]; then
            cp "$HOME/go/bin/godirb" "$TOOLS/godirb" && chmod +x "$TOOLS/godirb"
            echo "  ✔ godirb installed"
            return
        fi
    fi
    echo "  ⚠ godirb skipped (Go not available)"
}
install_ffuf() {
    local arch="$1" os="$2"
    [ -x "$TOOLS/ffuf" ] && return
    echo "  → Installing ffuf ($os/$arch)..."
    local a="" osn="linux"
    case "$arch" in
        arm64) a="arm64" ;;
        amd64) a="amd64" ;;
        armv7) a="armv7" ;;
        *) echo "  ⚠ Unknown arch"; return ;;
    esac
    [ "$os" = "macos" ] && osn="darwin"
    # URLs الصحيحة لـ ffuf
    local url="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_${osn}_${a}.tar.gz"
    local tmp=$(mktemp -d)
    rm -f "$TOOLS/ffuf" 2>/dev/null
    if curl -sL "$url" -o "$tmp/f.tar.gz" && tar -xzf "$tmp/f.tar.gz" -C "$tmp" 2>/dev/null; then
        cp "$tmp/ffuf" "$TOOLS/ffuf" && chmod +x "$TOOLS/ffuf"
        echo "  ✔ ffuf installed"
    else
        echo "  ⚠ ffuf failed (will use dirsearch)"
    fi
    rm -rf "$tmp"
}
main() {
    local os=$(detect_os) arch=$(detect_arch)
    echo "Environment: $os / $arch"
    install_deps "$os"
    install_dirsearch
    install_godirb
    install_ffuf "$arch" "$os"
    echo "✔ Bootstrap complete"
}
main "$@"
