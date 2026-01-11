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

# Build node arguments
NODE_ARGS=(
    --dev
    --base-path "$NODE_PATH"
    --chain config/dev-chainspec.json
    --rpc-port 9944
    --rpc-methods "${HEGEMON_RPC_METHODS:-safe}"
    --listen-addr /ip4/0.0.0.0/tcp/30333
    --name "HegemonMiner"
)

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

# Handle bootnode connection
# BOOTNODE can be either:
#   - Simple host:port format: "hegemon.pauli.group:30333"
#   - Multiaddr format: "/ip4/1.2.3.4/tcp/30333/p2p/..." (peer ID ignored)
if [[ -n "$BOOTNODE" ]]; then
    # Extract IP:port from multiaddr if needed
    if [[ "$BOOTNODE" == /ip4/* ]]; then
        # Parse /ip4/X.X.X.X/tcp/PORT/...
        IP=$(echo "$BOOTNODE" | sed -n 's|/ip4/\([^/]*\)/.*|\1|p')
        PORT=$(echo "$BOOTNODE" | sed -n 's|.*/tcp/\([0-9]*\).*|\1|p')
        SEED_ADDR="${IP}:${PORT}"
    else
        # Assume it's already IP:port format
        SEED_ADDR="$BOOTNODE"
    fi
    echo "Connecting to seed node: $SEED_ADDR"
    export HEGEMON_SEEDS="$SEED_ADDR"
fi

exec "$NODE_BIN" "${NODE_ARGS[@]}"
