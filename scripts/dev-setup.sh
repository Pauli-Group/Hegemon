#!/usr/bin/env bash
set -euo pipefail

# Installs the toolchains and CLI dependencies needed to build the SHC workspace.
# The script is idempotent and can be re-run safely. On Debian/Ubuntu systems
# it will also ensure jq/clang-format/build-essential exist for benchmark demos.

RUST_TOOLCHAIN="stable"
GO_VERSION="1.21.6"
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
    echo "Installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
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
    curl -sSfL "$url" -o "$tmp/$archive"

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

main() {
    ensure_apt_packages
    install_rustup
    install_rust_toolchain
    ensure_go
    echo "Toolchains ready!"
    print_tool_version "Rust" rustc --version
    print_tool_version "Cargo" cargo --version
    print_tool_version "Go" go version
    print_tool_version "clang-format" clang-format --version
    print_tool_version "jq" jq --version
}

main "$@"
