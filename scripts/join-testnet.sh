#!/bin/bash
# join-testnet.sh - Interactive wizard to create a wallet and join the Hegemon testnet.
# Passphrase is read from the terminal and never logged or exported beyond this process.
set -e

WALLET_PATH="${HEGEMON_WALLET_PATH:-$HOME/.hegemon-wallet-testnet}"
NODE_PATH="${HEGEMON_NODE_PATH:-$HOME/.hegemon-node-testnet}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NODE_BIN="${PROJECT_ROOT}/target/release/hegemon-node"
WALLETD_BIN="${PROJECT_ROOT}/target/release/walletd"
CHAINSPEC="${PROJECT_ROOT}/config/dev-chainspec.json"

SEED_NODE="${HEGEMON_SEED:-hegemon.pauli.group:31333}"
NODE_NAME="${HEGEMON_NODE_NAME:-TestnetNode}"

echo "=== Hegemon Testnet Setup ==="
echo ""

# ── Step 1: Check prerequisites ──────────────────────────────────────────────
echo "[1/5] Checking prerequisites..."

missing=""
[[ ! -x "$NODE_BIN" ]] && missing="$missing hegemon-node"
[[ ! -x "$WALLETD_BIN" ]] && missing="$missing walletd"
command -v jq >/dev/null 2>&1 || missing="$missing jq"

if [[ -n "$missing" ]]; then
    echo "ERROR: Missing required tools:$missing"
    echo ""
    echo "Build binaries:  make setup && make node && cargo build --release -p walletd"
    echo "Install jq:      brew install jq   (macOS)  or  apt install jq   (Linux)"
    exit 1
fi

if [[ ! -f "$CHAINSPEC" ]]; then
    echo "ERROR: Chainspec not found at $CHAINSPEC"
    exit 1
fi

echo "  hegemon-node  OK"
echo "  walletd       OK"
echo "  jq            OK"
echo "  chainspec     OK"
echo ""

# ── Step 2: Verify chainspec ─────────────────────────────────────────────────
echo "[2/5] Chainspec"
ACTUAL_HASH=$(shasum -a 256 "$CHAINSPEC" | awk '{print $1}')
echo "  SHA-256: $ACTUAL_HASH"

if [[ -n "${HEGEMON_CHAINSPEC_SHA256:-}" ]]; then
    if [[ "$ACTUAL_HASH" != "$HEGEMON_CHAINSPEC_SHA256" ]]; then
        echo ""
        echo "ERROR: Chainspec hash mismatch!"
        echo "  Expected: $HEGEMON_CHAINSPEC_SHA256"
        echo "  Actual:   $ACTUAL_HASH"
        echo "Verify you are on the correct branch."
        exit 1
    fi
    echo "  Hash verified against HEGEMON_CHAINSPEC_SHA256."
else
    echo "  (Set HEGEMON_CHAINSPEC_SHA256 to enforce hash verification)"
fi
echo ""

# ── Step 3: Wallet setup ─────────────────────────────────────────────────────
echo "[3/5] Wallet setup"
echo "  Store: $WALLET_PATH"
echo ""

WALLET_EXISTS=false
[[ -d "$WALLET_PATH" ]] && WALLET_EXISTS=true

if $WALLET_EXISTS; then
    echo "  Existing wallet found."
    read -p "  Keep it? [Y/n] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        rm -rf "$WALLET_PATH"
        WALLET_EXISTS=false
        echo "  Wallet removed."
    fi
fi

if ! $WALLET_EXISTS; then
    echo "  Creating new testnet wallet."
    echo ""
    read -s -p "  Enter passphrase: " PASSPHRASE
    echo ""
    read -s -p "  Confirm passphrase: " PASSPHRASE_CONFIRM
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
else
    read -s -p "  Enter wallet passphrase: " PASSPHRASE
    echo ""
    WALLET_MODE="open"
fi

echo ""
echo "  Fetching shielded address..."
STATUS_JSON=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "$PASSPHRASE" \
    | "$WALLETD_BIN" --store "$WALLET_PATH" --mode "$WALLET_MODE")

# Clear passphrase from memory as soon as possible
unset PASSPHRASE PASSPHRASE_CONFIRM

SHIELDED_ADDR=$(printf '%s' "$STATUS_JSON" | jq -r '.result.primaryAddress // empty')

if [[ -z "$SHIELDED_ADDR" ]]; then
    echo "ERROR: Could not get shielded address. Wrong passphrase?"
    exit 1
fi

echo "  Address: ${SHIELDED_ADDR:0:20}...${SHIELDED_ADDR: -12}"
echo ""

# ── Step 4: Check for existing node data ─────────────────────────────────────
echo "[4/5] Node data"
echo "  Base path: $NODE_PATH"

if [[ -d "$NODE_PATH" ]]; then
    echo "  Existing node data found."
    read -p "  Keep it (resume sync) or wipe (start fresh)? [K/w] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Ww]$ ]]; then
        rm -rf "$NODE_PATH"
        echo "  Node data wiped."
    else
        echo "  Keeping existing data."
    fi
fi
mkdir -p "$NODE_PATH"
echo ""

# ── Step 5: Launch ───────────────────────────────────────────────────────────
echo "[5/5] Starting testnet node"
echo "  Seed:    $SEED_NODE"
echo "  Name:    $NODE_NAME"
echo "  Mining:  enabled"
echo "  RPC:     http://127.0.0.1:9944 (localhost only)"
echo ""
echo "  Press Ctrl+C to stop."
echo ""
echo "  Monitor sync in another terminal:"
echo "    curl -s -H 'Content-Type: application/json' \\"
echo "      -d '{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"system_health\"}' \\"
echo "      http://127.0.0.1:9944 | jq"
echo ""

export HEGEMON_MINE=1
export HEGEMON_MINER_ADDRESS="$SHIELDED_ADDR"
export HEGEMON_PROVER_REWARD_ADDRESS="$SHIELDED_ADDR"
export HEGEMON_PQ_STRICT_COMPATIBILITY=1
export HEGEMON_SEEDS="$SEED_NODE"

exec "$NODE_BIN" \
    --dev \
    --base-path "$NODE_PATH" \
    --chain "$CHAINSPEC" \
    --rpc-port 9944 \
    --rpc-methods safe \
    --listen-addr /ip4/0.0.0.0/tcp/30333 \
    --name "$NODE_NAME"
