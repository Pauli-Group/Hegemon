#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

node --check scripts/live-app-no-ssh-e2e.mjs

if [[ "${HEGEMON_APP_NO_SSH_E2E_SYNTAX_ONLY:-0}" == "1" ]]; then
  exit 0
fi

if [[ -n "${HEGEMON_NODE_BIN:-}" || -n "${HEGEMON_WALLETD_BIN:-}" ]]; then
  echo "HEGEMON_NODE_BIN and HEGEMON_WALLETD_BIN are not accepted by the required E2E gate" >&2
  exit 2
fi

NODE_BIN="$ROOT/target/release/hegemon-node"
WALLETD_BIN="$ROOT/target/release/walletd"
MANIFEST="$ROOT/target/release/hegemon-app-no-ssh-e2e-artifacts.json"
"$ROOT/scripts/build_release_artifacts.sh" --manifest "$MANIFEST" >/dev/null

HEGEMON_NODE_BIN="$NODE_BIN" \
HEGEMON_WALLETD_BIN="$WALLETD_BIN" \
HEGEMON_RELEASE_MANIFEST="$MANIFEST" \
node scripts/live-app-no-ssh-e2e.mjs
