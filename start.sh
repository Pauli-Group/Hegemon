#!/usr/bin/env bash
# start.sh - Start a Hegemon node connecting to a boot node
#
# Usage:
#   ./start.sh                           # Connect without mining
#   HEGEMON_MINE=1 ./start.sh            # Connect and mine
#
# Prerequisites:
#   1. Build the node: cargo build -p hegemon-node -p wallet --release
#   2. Initialize wallet: ./target/release/wallet init --store ~/.hegemon-wallet --passphrase "YOUR_PASSPHRASE"
#   3. Get your address: ./target/release/wallet status --store ~/.hegemon-wallet --passphrase "YOUR_PASSPHRASE" --no-sync
#
# Environment variables:
#   HEGEMON_SEEDS          - Boot node address (default: your-bootnode.example.com:30333)
#   HEGEMON_MINE           - Enable mining (0 or 1, default: 0)
#   HEGEMON_MINER_ADDRESS  - Your shielded address for mining rewards

set -euo pipefail

: "${HEGEMON_SEEDS:=hegemon.pauli.group:30333}"
: "${HEGEMON_MINE:=0}"
: "${HEGEMON_MINER_ADDRESS:=}"

if [ "$HEGEMON_MINE" = "1" ] && [ -z "$HEGEMON_MINER_ADDRESS" ]; then
  echo "Error: HEGEMON_MINER_ADDRESS must be set when mining is enabled."
  echo "Get your address with: ./target/release/wallet status --store ~/.hegemon-wallet --passphrase YOUR_PASSPHRASE --no-sync"
  exit 1
fi

HEGEMON_MINE="$HEGEMON_MINE" \
HEGEMON_SEEDS="$HEGEMON_SEEDS" \
HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
./target/release/hegemon-node \
  --base-path "$HOME/.hegemon-node" \
  --chain config/dev-chainspec.json \
  --rpc-port 9944 \
  --rpc-cors all \
  --name "MyNode"