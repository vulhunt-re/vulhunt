#!/bin/sh
# VulHunt CE Installer
# Usage: curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/binarly-io/vulhunt-ce/dev/scripts/install.sh | sh

set -eu

REPO="binarly-io/vulhunt-ce"
DATA_URL="https://github.com/vulhunt-re/bias-data/archive/refs/heads/main.zip"
INSTALL_DIR="${VULHUNT_INSTALL_DIR:-$HOME/.vulhunt-ce}"
BIN_DIR="${VULHUNT_BIN_DIR:-$INSTALL_DIR/bin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    printf "${BLUE}info:${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}warn:${NC} %s\n" "$1"
}

error() {
    printf "${RED}error:${NC} %s\n" "$1" >&2
    exit 1
}

success() {
    printf "${GREEN}success:${NC} %s\n" "$1"
}

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)       error "Unsupported operating system: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)             error "Unsupported architecture: $(uname -m)" ;;
    esac
}

get_data_dir() {
    local os="$1"
    case "$os" in
        linux)  echo "${XDG_CONFIG_HOME:-$HOME/.config}/vulhunt/data" ;;
        macos)  echo "$HOME/Library/Application Support/vulhunt/data" ;;
    esac
}

install_data() {
    local data_dir="$1"
    local temp_dir="$2"

    info "Downloading auxiliary data..."
    curl -fSL --progress-bar "$DATA_URL" -o "$temp_dir/data.zip"

    info "Extracting auxiliary data to $data_dir..."
    mkdir -p "$data_dir"
    unzip -q -o "$temp_dir/data.zip" -d "$temp_dir/data_extracted"

    mv "$temp_dir/data_extracted/"*/data/* "$data_dir/"
}

check_dependencies() {
    for cmd in curl unzip; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required dependency '$cmd' is not installed"
        fi
    done
}

get_latest_release() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

get_download_url() {
    local version="$1"
    local platform="$2"
    local ver_stripped="${version#v}"  # Strip 'v' prefix if present
    echo "https://github.com/${REPO}/releases/download/${version}/vulhunt-ce-${ver_stripped}-${platform}.zip"
}

install() {
    local os arch platform version download_url temp_dir
    trap 'rm -rf "${temp_dir:-}"' EXIT

    info "Detecting system..."
    os=$(detect_os)
    arch=$(detect_arch)
    platform="${os}-${arch}"

    info "Detected platform: ${platform}"

    if [ "$os" = "windows" ]; then
        error "Please use install.ps1 for Windows installation"
    fi

    check_dependencies

    info "Fetching latest release..."
    version="${VULHUNT_VERSION:-$(get_latest_release)}"

    if [ -z "$version" ]; then
        error "Failed to determine latest version. Set VULHUNT_VERSION to install a specific version."
    fi

    info "Installing VulHunt CE ${version}..."

    download_url=$(get_download_url "$version" "$platform")
    info "Downloading from: ${download_url}"

    temp_dir=$(mktemp -d)

    if ! curl -fSL --progress-bar "$download_url" -o "$temp_dir/vulhunt-ce.zip"; then
        error "Failed to download VulHunt CE. Check if the release exists for your platform."
    fi

    info "Extracting..."
    mkdir -p "$BIN_DIR"
    unzip -q -o "$temp_dir/vulhunt-ce.zip" -d "$temp_dir/extracted"

    for binary in vulhunt-ce bias-lutil bias-tutil sleighc; do
        if [ -f "$temp_dir/extracted/$binary" ]; then
            mv "$temp_dir/extracted/$binary" "$BIN_DIR/"
            chmod +x "$BIN_DIR/$binary"
        fi
    done

    echo "$version" > "$INSTALL_DIR/version"

    data_dir=$(get_data_dir "$os")
    install_data "$data_dir" "$temp_dir"

    success "VulHunt CE ${version} installed to ${BIN_DIR}"

    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            warn "Add the following to your shell profile to add VulHunt CE to your PATH:"
            echo ""
            echo "  export PATH=\"\$PATH:$BIN_DIR\""
            echo ""

            shell_name=$(basename "$SHELL")
            case "$shell_name" in
                bash)
                    if [ -f "$HOME/.bash_profile" ]; then
                        info "For bash, add it to ~/.bash_profile"
                    else
                        info "For bash, add it to ~/.bashrc"
                    fi
                    ;;
                zsh)
                    info "For zsh, add it to ~/.zshrc"
                    ;;
                fish)
                    warn "For fish, run: fish_add_path $BIN_DIR"
                    ;;
            esac
            ;;
    esac

    warn "Set the following environment variable for auxiliary data:"
    echo ""
    echo "  export BIAS_DATA=\"$data_dir\""
    echo ""

    echo ""
    success "Installation complete!"
    echo ""
    info "Run 'vulhunt-ce --help' to get started"
}

install
