#!/usr/bin/env bash

# state.sh - Script to sync wallet and check state

set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "Usage: $0" >&2
  echo "The wallet binary will prompt for the passphrase securely." >&2
  exit 1
fi

./target/release/wallet node-sync \
  --store ~/.hegemon-wallet \
  --ws-url ws://127.0.0.1:9944

./target/release/wallet status \
  --store ~/.hegemon-wallet
