#!/usr/bin/env bash
set -euo pipefail

# Installs the toolchains and CLI dependencies needed to build the HEGEMON (HGN) workspace.
# The script is idempotent and can be re-run safely. On Debian/Ubuntu systems
# it will also ensure jq/clang-format/build-essential exist for benchmark demos.

RUST_TOOLCHAIN="stable"
GO_VERSION="1.26.4"
NODE_VERSION="20.19.0"
NODE_INSTALL_DIR=${NODE_INSTALL_DIR:-"$HOME/.local/node"}
APT_PACKAGES=(build-essential pkg-config libssl-dev clang-format jq)

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

print_tool_version() {
    local label=$1
    shift
    if have_cmd "$1"; then
        local cmd=$1
        shift || true
        echo "$label $("$cmd" "$@" 2>/dev/null)"
    else
        echo "$label (not found)"
    fi
}

sha256_file() {
    if have_cmd sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    actual="$(sha256_file "$file")"
    if [[ "$actual" != "$expected" ]]; then
        echo "error: checksum mismatch for $file" >&2
        echo "expected: $expected" >&2
        echo "actual:   $actual" >&2
        exit 1
    fi
}

go_archive_sha256() {
    case "$1" in
        go1.26.4.linux-amd64.tar.gz) echo "1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f" ;;
        go1.26.4.linux-arm64.tar.gz) echo "ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768" ;;
        go1.26.4.darwin-amd64.tar.gz) echo "05dc9b5f9997744520aaebb3d5deaa7c755371aebbfb7f97c2511a9f3367538d" ;;
        go1.26.4.darwin-arm64.tar.gz) echo "b62ad2b6d7d2464f12a5bcad7ff47f19d08325773b5efd21610e445a05a9bf53" ;;
        *) echo "error: no pinned Go checksum for $1" >&2; exit 1 ;;
    esac
}

node_archive_sha256() {
    case "$1" in
        node-v20.19.0-linux-x64.tar.gz) echo "8a4dbcdd8bccef3132d21e8543940557e55dcf44f00f0a99ba8a062f4552e722" ;;
        node-v20.19.0-linux-arm64.tar.gz) echo "618e4294602b78e97118a39050116b70d088b16197cd3819bba1fc18b473dfc4" ;;
        node-v20.19.0-darwin-x64.tar.gz) echo "a8554af97d6491fdbdabe63d3a1cfb9571228d25a3ad9aed2df856facb131b20" ;;
        node-v20.19.0-darwin-arm64.tar.gz) echo "c016cd1975a264a29dc1b07c6fbe60d5df0a0c2beb4113c0450e3d998d1a0d9c" ;;
        *) echo "error: no pinned Node.js checksum for $1" >&2; exit 1 ;;
    esac
}

rustup_target_and_sha256() {
    local rust_os rust_arch target sha
    case "$(uname -s)" in
        Linux) rust_os="unknown-linux-gnu" ;;
        Darwin) rust_os="apple-darwin" ;;
        *)
            echo "error: unsupported OS for rustup binary install: $(uname -s)" >&2
            exit 1
            ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) rust_arch="x86_64" ;;
        arm64 | aarch64) rust_arch="aarch64" ;;
        *)
            echo "error: unsupported CPU architecture for rustup binary install: $(uname -m)" >&2
            exit 1
            ;;
    esac
    target="${rust_arch}-${rust_os}"
    case "$target" in
        x86_64-unknown-linux-gnu) sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10" ;;
        aarch64-unknown-linux-gnu) sha="9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792" ;;
        x86_64-apple-darwin) sha="33cf85df9142bc6d29cbc62fa5ca1d4c29622cddb55213a4c1a43c457fb9b2d7" ;;
        aarch64-apple-darwin) sha="aeb4105778ca1bd3c6b0e75768f581c656633cd51368fa61289b6a71696ac7e1" ;;
        *) echo "error: no pinned rustup checksum for $target" >&2; exit 1 ;;
    esac
    printf '%s %s\n' "$target" "$sha"
}

# shellcheck disable=SC2120
ensure_apt_packages() {
    if ! have_cmd apt-get; then
        echo "apt-get not found; please install ${APT_PACKAGES[*]} manually." >&2
        return
    fi
    local missing=()
    for pkg in "${APT_PACKAGES[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done
    if ((${#missing[@]} == 0)); then
        return
    fi
    local apt_cmd=(apt-get)
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        if have_cmd sudo; then
            apt_cmd=(sudo apt-get)
        else
            echo "error: need root privileges or sudo to install packages: ${missing[*]}" >&2
            exit 1
        fi
    fi
    echo "Installing packages: ${missing[*]}"
    "${apt_cmd[@]}" update
    "${apt_cmd[@]}" install -y "${missing[@]}"
}

install_rustup() {
    if have_cmd rustup; then
        return
    fi
    if ! have_cmd curl; then
        echo "error: curl is required to install rustup" >&2
        exit 1
    fi
    local tmp target expected
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp:-}"' RETURN
    read -r target expected < <(rustup_target_and_sha256)
    echo "Installing rustup for ${target}"
    curl --proto '=https' --tlsv1.2 --fail --location --show-error \
        "https://static.rust-lang.org/rustup/dist/${target}/rustup-init" \
        -o "$tmp/rustup-init"
    verify_sha256 "$tmp/rustup-init" "$expected"
    chmod 755 "$tmp/rustup-init"
    "$tmp/rustup-init" -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
    fi
}

install_rust_toolchain() {
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
    fi
    rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
    rustup default "$RUST_TOOLCHAIN"
    rustup component add --toolchain "$RUST_TOOLCHAIN" clippy rustfmt
}

ensure_go() {
    if have_cmd go; then
        local version
        version=$(go version | awk '{print $3}' | sed 's/go//')
        if [[ -z "$version" ]]; then
            echo "warning: could not detect go version; reinstalling" >&2
        elif printf '%s\n' "$version" "$GO_VERSION" | sort -V | tail -n1 | grep -qx "$version"; then
            return
        else
            echo "Detected Go $version (<${GO_VERSION}); reinstalling"
        fi
    fi
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp:-}"' RETURN
    local go_os
    case "$(uname -s)" in
        Linux) go_os="linux" ;;
        Darwin) go_os="darwin" ;;
        *)
            echo "error: unsupported OS for Go binary install: $(uname -s)" >&2
            exit 1
            ;;
    esac
    local go_arch
    case "$(uname -m)" in
        x86_64 | amd64) go_arch="amd64" ;;
        arm64 | aarch64) go_arch="arm64" ;;
        *)
            echo "error: unsupported CPU architecture for Go binary install: $(uname -m)" >&2
            exit 1
            ;;
    esac
    local archive="go${GO_VERSION}.${go_os}-${go_arch}.tar.gz"
    local url="https://go.dev/dl/${archive}"
    echo "Installing Go ${GO_VERSION} from ${url}"
    curl --proto '=https' --tlsv1.2 --fail --location --show-error "$url" -o "$tmp/$archive"
    verify_sha256 "$tmp/$archive" "$(go_archive_sha256 "$archive")"

    local install_root
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        install_root="/usr/local"
    else
        install_root="$HOME/.local"
        mkdir -p "$install_root"
    fi

    local go_prefix="$install_root/go"
    rm -rf "$go_prefix"
    tar -C "$install_root" -xzf "$tmp/$archive"

    local go_bin="$go_prefix/bin"
    if [[ ":${PATH}:" != *":${go_bin}:"* ]]; then
        export PATH="$go_bin:$PATH"
    fi
    echo "Go installed to ${go_prefix}"
    echo "Add ${go_bin} to your PATH if it is missing"
}

ensure_node() {
    local desired="$NODE_VERSION"
    if have_cmd node; then
        local version
        version=$(node --version | sed 's/^v//')
        if [[ -z "$version" ]]; then
            echo "warning: could not detect node version; reinstalling" >&2
        elif printf '%s\n' "$version" "$desired" | sort -V | tail -n1 | grep -qx "$version"; then
            return
        else
            echo "Detected Node v$version (<${desired}); reinstalling"
        fi
    fi
    if ! have_cmd curl; then
        echo "error: curl is required to install Node.js" >&2
        exit 1
    fi
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp:-}"' RETURN
    local node_os
    case "$(uname -s)" in
        Linux) node_os="linux" ;;
        Darwin) node_os="darwin" ;;
        *)
            echo "error: unsupported OS for Node.js binary install: $(uname -s)" >&2
            exit 1
            ;;
    esac
    local node_arch
    case "$(uname -m)" in
        x86_64 | amd64) node_arch="x64" ;;
        arm64 | aarch64) node_arch="arm64" ;;
        *)
            echo "error: unsupported CPU architecture for Node.js binary install: $(uname -m)" >&2
            exit 1
            ;;
    esac
    local archive="node-v${desired}-${node_os}-${node_arch}.tar.gz"
    local url="https://nodejs.org/dist/v${desired}/${archive}"
    echo "Installing Node.js ${desired} from ${url}"
    curl --proto '=https' --tlsv1.2 --fail --location --show-error "$url" -o "$tmp/$archive"
    verify_sha256 "$tmp/$archive" "$(node_archive_sha256 "$archive")"
    tar -C "$tmp" -xzf "$tmp/$archive"

    local install_root
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        install_root="/usr/local"
    else
        install_root="$HOME/.local"
        mkdir -p "$install_root"
    fi

    local node_prefix="$NODE_INSTALL_DIR"
    [[ ${node_prefix} == /* ]] || node_prefix="$install_root/${node_prefix}"
    rm -rf "$node_prefix"
    mkdir -p "$(dirname "$node_prefix")"
    mv "$tmp/node-v${desired}-${node_os}-${node_arch}" "$node_prefix"

    local node_bin="$node_prefix/bin"
    if [[ ":${PATH}:" != *":${node_bin}:"* ]]; then
        export PATH="$node_bin:$PATH"
    fi
    echo "Node.js installed to ${node_prefix}"
    echo "Add ${node_bin} to your PATH if it is missing"
}

main() {
    ensure_apt_packages
    install_rustup
    install_rust_toolchain
    ensure_go
    ensure_node
    echo "Toolchains ready!"
    print_tool_version "Rust" rustc --version
    print_tool_version "Cargo" cargo --version
    print_tool_version "Go" go version
    print_tool_version "Node" node --version
    print_tool_version "npm" npm --version
    print_tool_version "clang-format" clang-format --version
    print_tool_version "jq" jq --version
}

main "$@"
