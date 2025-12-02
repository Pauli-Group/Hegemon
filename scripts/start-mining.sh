#!/bin/bash
# start-mining.sh - Interactive script to set up wallet and start mining node
set -e

WALLET_PATH="${HEGEMON_WALLET_PATH:-$HOME/.hegemon-wallet}"
NODE_PATH="${HEGEMON_NODE_PATH:-$HOME/.hegemon-node}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NODE_BIN="${PROJECT_ROOT}/target/release/hegemon-node"
WALLET_BIN="${PROJECT_ROOT}/target/release/wallet"

echo "=== Hegemon Mining Setup ==="
echo ""

# Check binaries exist
if [[ ! -x "$NODE_BIN" ]] || [[ ! -x "$WALLET_BIN" ]]; then
    echo "ERROR: Binaries not found. Build first with:"
    echo "  cargo build -p hegemon-node -p wallet --features substrate --release"
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
    
    "$WALLET_BIN" init --store "$WALLET_PATH" --passphrase "$PASSPHRASE"
    echo ""
    echo "Wallet created at $WALLET_PATH"
else
    read -s -p "Enter wallet passphrase: " PASSPHRASE
    echo ""
fi

# Get shielded address
echo ""
echo "Fetching shielded address..."
SHIELDED_ADDR=$("$WALLET_BIN" status --store "$WALLET_PATH" --passphrase "$PASSPHRASE" 2>/dev/null | grep "Shielded Address:" | awk '{print $3}')

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
    --base-path "$NODE_PATH"
    --chain dev
    --rpc-port 9944
    --rpc-cors all
    --unsafe-rpc-external
    --listen-addr /ip4/0.0.0.0/tcp/30333
    --name "HegemonMiner"
)

# Handle bootnode connection
# BOOTNODE can be either:
#   - Simple IP:port format: "75.155.93.185:30333"
#   - Multiaddr format: "/ip4/75.155.93.185/tcp/30333/p2p/..." (peer ID ignored)
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
