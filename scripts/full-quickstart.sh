#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_API_ADDR=${NODE_API_ADDR:-127.0.0.1:8080}
NODE_API_TOKEN=${NODE_API_TOKEN:-devnet-token}
NODE_P2P_ADDR=${NODE_P2P_ADDR:-0.0.0.0:9000}
NODE_DB_PATH=${NODE_DB_PATH:-"$REPO_ROOT/state/quickstart-node.db"}
NODE_WALLET_STORE=${NODE_WALLET_STORE:-"$REPO_ROOT/state/quickstart-wallet.store"}
NODE_WALLET_PASSPHRASE=${NODE_WALLET_PASSPHRASE:-"test passphrase"}
MINER_WORKERS=${MINER_WORKERS:-2}
NOTE_TREE_DEPTH=${NOTE_TREE_DEPTH:-32}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ -n "${HEGEMON_PID:-}" ]]; then
        if kill -0 "$HEGEMON_PID" 2>/dev/null; then
            echo "\nStopping hegemon (pid ${HEGEMON_PID})"
            kill "$HEGEMON_PID" 2>/dev/null || true
        fi
        wait "$HEGEMON_PID" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

cd "$REPO_ROOT"

echo "Running workstation quickstart (guard rails + benchmarks + wallet demo + node launch)..."
./scripts/dev-setup.sh
make check
make bench
./scripts/wallet-demo.sh --out wallet-demo-artifacts

echo "Building hegemon with embedded dashboard (same artifact as 'cargo build -p node --release')..."
cargo build -p node --release
HEGEMON_BIN="$REPO_ROOT/target/release/hegemon"

if [[ ! -x "$HEGEMON_BIN" ]]; then
    echo "Error: hegemon binary not found at ${HEGEMON_BIN}" >&2
    exit 1
fi

export NODE_WALLET_STORE
export NODE_WALLET_PASSPHRASE

echo "\nStarting hegemon on ${NODE_API_ADDR} (dashboard + API token ${NODE_API_TOKEN})"
"$HEGEMON_BIN" start \
    --db-path "$NODE_DB_PATH" \
    --api-addr "$NODE_API_ADDR" \
    --api-token "$NODE_API_TOKEN" \
    --p2p-addr "$NODE_P2P_ADDR" \
    --miner-workers "$MINER_WORKERS" \
    --note-tree-depth "$NOTE_TREE_DEPTH" &
HEGEMON_PID=$!

echo
echo "Dashboard available at http://${NODE_API_ADDR}"
echo "Press Ctrl+C to stop the node and wallet."

wait "$HEGEMON_PID"
