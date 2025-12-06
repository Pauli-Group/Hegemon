#!/usr/bin/env bash

# state.sh - Script to sync wallet and check state

set -euo pipefail

PASSWORD="${1:-}"

if [ -z "$PASSWORD" ]; then
  echo "Usage: $0 <wallet-passphrase>"
  exit 1
fi

./target/release/wallet substrate-sync \
  --store ~/.hegemon-wallet \
  --passphrase "$PASSWORD" \
  --ws-url ws://127.0.0.1:9944

./target/release/wallet status \
  --store ~/.hegemon-wallet \
  --passphrase "$PASSWORD"