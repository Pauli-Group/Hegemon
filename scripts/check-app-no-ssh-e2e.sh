#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NODE_BIN="${HEGEMON_NODE_BIN:-$ROOT/target/release/hegemon-node}"
WALLETD_BIN="${HEGEMON_WALLETD_BIN:-$ROOT/target/release/walletd}"

node --check scripts/live-app-no-ssh-e2e.mjs

if [[ "${HEGEMON_APP_NO_SSH_E2E_SYNTAX_ONLY:-0}" == "1" ]]; then
  exit 0
fi

if [[ ! -x "$NODE_BIN" || ! -x "$WALLETD_BIN" ]]; then
  cargo build --release -p hegemon-node -p walletd
fi

HEGEMON_NODE_BIN="$NODE_BIN" \
HEGEMON_WALLETD_BIN="$WALLETD_BIN" \
node scripts/live-app-no-ssh-e2e.mjs
