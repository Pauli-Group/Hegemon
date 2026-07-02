#!/bin/bash
# start-mining.sh - Interactive script to set up wallet and start mining node
set -e

WALLET_PATH="${HEGEMON_WALLET_PATH:-$HOME/.hegemon-wallet}"
NODE_PATH="${HEGEMON_NODE_PATH:-$HOME/.hegemon-node}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NODE_BIN="${PROJECT_ROOT}/target/release/hegemon-node"
WALLETD_BIN="${PROJECT_ROOT}/target/release/walletd"

echo "=== Hegemon Mining Setup ==="
echo ""

# Check binaries exist
if [[ ! -x "$NODE_BIN" ]] || [[ ! -x "$WALLETD_BIN" ]]; then
    echo "ERROR: Binaries not found. Build first with:"
    echo "  cargo build -p hegemon-node -p walletd --release"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to parse walletd output."
    exit 1
fi

# Check for existing data
WALLET_EXISTS=false
NODE_EXISTS=false
[[ -d "$WALLET_PATH" ]] && WALLET_EXISTS=true
[[ -d "$NODE_PATH" ]] && NODE_EXISTS=true

if $WALLET_EXISTS || $NODE_EXISTS; then
    echo "Found existing data:"
    $WALLET_EXISTS && echo "  - Wallet: $WALLET_PATH"
    $NODE_EXISTS && echo "  - Node:   $NODE_PATH"
    echo ""
    read -p "Keep existing data? [Y/n] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Wiping existing data..."
        rm -rf "$WALLET_PATH" "$NODE_PATH"
        WALLET_EXISTS=false
        NODE_EXISTS=false
        echo "Done."
    fi
    echo ""
fi

# Create wallet if needed
if ! $WALLET_EXISTS; then
    echo "No wallet found. Creating new wallet..."
    echo ""
    read -s -p "Enter passphrase for new wallet: " PASSPHRASE
    echo ""
    read -s -p "Confirm passphrase: " PASSPHRASE_CONFIRM
    echo ""
    
    if [[ "$PASSPHRASE" != "$PASSPHRASE_CONFIRM" ]]; then
        echo "ERROR: Passphrases do not match."
        exit 1
    fi
    
    if [[ -z "$PASSPHRASE" ]]; then
        echo "ERROR: Passphrase cannot be empty."
        exit 1
    fi
    WALLET_MODE="create"
    echo ""
    echo "Wallet store will be created at $WALLET_PATH"
else
    read -s -p "Enter wallet passphrase: " PASSPHRASE
    echo ""
    WALLET_MODE="open"
fi

# Get shielded address
echo ""
echo "Fetching shielded address..."
STATUS_JSON=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "$PASSPHRASE" \
    | "$WALLETD_BIN" --store "$WALLET_PATH" --mode "$WALLET_MODE")
SHIELDED_ADDR=$(printf '%s' "$STATUS_JSON" | python3 - <<'PY'
import json
import sys

data = sys.stdin.read()
try:
    obj = json.loads(data) if data.strip() else {}
except Exception:
    obj = {}
print((obj.get("result") or {}).get("primaryAddress", ""))
PY
)

if [[ -z "$SHIELDED_ADDR" ]]; then
    echo "ERROR: Could not get shielded address. Check passphrase."
    exit 1
fi

echo "Shielded Address: ${SHIELDED_ADDR:0:40}...${SHIELDED_ADDR: -20}"
echo ""

# Create node directory
mkdir -p "$NODE_PATH"

# Start the node
echo "Starting mining node..."
echo "  Wallet: $WALLET_PATH"
echo "  Node:   $NODE_PATH"
echo "  Mining to shielded address"
echo ""
echo "Press Ctrl+C to stop."
echo ""

export HEGEMON_MINE=1
export HEGEMON_MINER_ADDRESS="$SHIELDED_ADDR"

check_time_sync() {
    if command -v timedatectl >/dev/null 2>&1; then
        if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" == "yes" ]]; then
            echo "  Time sync: timedatectl reports synchronized"
            return
        fi
        echo "WARNING: timedatectl does not report synchronized time. Enable NTP/chrony before mining." >&2
        return
    fi
    if command -v chronyc >/dev/null 2>&1; then
        if chronyc tracking >/dev/null 2>&1; then
            echo "  Time sync: chrony responds"
            return
        fi
        echo "WARNING: chrony is installed but not healthy. Fix time sync before mining." >&2
        return
    fi
    if command -v systemsetup >/dev/null 2>&1; then
        if systemsetup -getusingnetworktime 2>/dev/null | grep -qi 'on'; then
            echo "  Time sync: macOS network time is enabled"
            return
        fi
        echo "WARNING: could not confirm macOS network time. Enable NTP before mining." >&2
        return
    fi
    echo "WARNING: could not verify NTP/chrony status. Miners must keep time synchronized." >&2
}

seed_from_bootnode() {
    local bootnode="$1"
    if [[ "$bootnode" == /ip4/* ]]; then
        local ip
        local port
        ip=$(echo "$bootnode" | sed -n 's|/ip4/\([^/]*\)/.*|\1|p')
        port=$(echo "$bootnode" | sed -n 's|.*/tcp/\([0-9]*\).*|\1|p')
        if [[ -z "$ip" || -z "$port" ]]; then
            echo "ERROR: could not parse BOOTNODE multiaddr: $bootnode" >&2
            exit 1
        fi
        echo "${ip}:${port}"
    else
        echo "$bootnode"
    fi
}

LOCAL_DEV_MINING="${HEGEMON_LOCAL_DEV_MINING:-0}"
if [[ "$LOCAL_DEV_MINING" == "1" || "$LOCAL_DEV_MINING" == "true" ]]; then
    echo "Mode: local dev mining (--dev). This is intentionally isolated."
    export HEGEMON_BOOTSTRAP_AUTHORING=1
else
    if [[ -n "${BOOTNODE:-}" ]]; then
        export HEGEMON_SEEDS="$(seed_from_bootnode "$BOOTNODE")"
    else
        export HEGEMON_SEEDS="${HEGEMON_SEEDS:-devnet.hegemonprotocol.com:30333}"
    fi
    if [[ -z "$HEGEMON_SEEDS" ]]; then
        echo "ERROR: HEGEMON_SEEDS is empty. Use HEGEMON_SEEDS=\"devnet.hegemonprotocol.com:30333\" or set HEGEMON_LOCAL_DEV_MINING=1 for isolated dev mining." >&2
        exit 1
    fi
    echo "Mode: shared mining"
    echo "  HEGEMON_SEEDS=$HEGEMON_SEEDS"
    echo "  All miners on this network must share the same seed list to avoid forks."
    check_time_sync
fi

# Build node arguments
NODE_ARGS=(
    --base-path "$NODE_PATH"
    --rpc-port 9944
    --rpc-methods "${HEGEMON_RPC_METHODS:-safe}"
    --listen-addr 0.0.0.0:30333
    --name "HegemonMiner"
)
if [[ "$LOCAL_DEV_MINING" == "1" || "$LOCAL_DEV_MINING" == "true" ]]; then
    NODE_ARGS+=(--dev)
fi

# RPC hardening: default is localhost-only, safe methods.
# To explicitly expose RPC beyond localhost (not recommended), set:
#   HEGEMON_RPC_EXTERNAL=1 HEGEMON_RPC_CORS=<origin> ./scripts/start-mining.sh
if [[ "${HEGEMON_RPC_EXTERNAL:-0}" == "1" || "${HEGEMON_RPC_EXTERNAL:-}" == "true" ]]; then
    echo "WARNING: RPC is exposed beyond localhost. Use firewalls/VPN and keep --rpc-methods safe." >&2
    NODE_ARGS+=(--rpc-external)
fi
if [[ -n "${HEGEMON_RPC_CORS:-}" ]]; then
    NODE_ARGS+=(--rpc-cors "${HEGEMON_RPC_CORS}")
fi

exec "$NODE_BIN" "${NODE_ARGS[@]}"
