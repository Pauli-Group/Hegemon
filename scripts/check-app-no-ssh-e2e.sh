#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE_ARGS=()
if [[ "$#" -gt 1 || ( "$#" -eq 1 && "$1" != "--review-only" ) ]]; then
  echo "usage: $0 [--review-only]" >&2
  exit 2
fi
if [[ "$#" -eq 1 ]]; then
  MODE_ARGS+=("$1")
fi

node --check scripts/live-app-no-ssh-e2e.mjs
node --check scripts/app-no-ssh-e2e-mode.mjs
node --test scripts/test_app_no_ssh_e2e_mode.mjs

if [[ "${HEGEMON_APP_NO_SSH_E2E_SYNTAX_ONLY:-0}" == "1" ]]; then
  exit 0
fi

if [[ -n "${HEGEMON_NODE_BIN:-}" || -n "${HEGEMON_WALLETD_BIN:-}" ]]; then
  echo "HEGEMON_NODE_BIN and HEGEMON_WALLETD_BIN are not accepted by the required E2E gate" >&2
  exit 2
fi

# Run portable wallet transport regressions before building or launching E2E binaries.
cargo test --locked -p wallet --test node_rpc
cargo test --locked -p wallet --bin wallet rpc_argument_tests
cargo test --locked -p wallet --lib node_rpc::tests
npm --prefix hegemon-app test -- --no-cache --maxWorkers=1 --no-file-parallelism tests/connections.test.ts tests/rpcEndpoint.test.ts tests/walletSync.test.ts tests/walletdProtocol.test.ts
npm --prefix hegemon-app run typecheck

NODE_BIN="$ROOT/target/release/hegemon-node"
WALLETD_BIN="$ROOT/target/release/walletd"
MANIFEST="$ROOT/target/release/hegemon-app-no-ssh-e2e-artifacts.json"
"$ROOT/scripts/build_release_artifacts.sh" --manifest "$MANIFEST" >/dev/null

HEGEMON_NODE_BIN="$NODE_BIN" \
HEGEMON_WALLETD_BIN="$WALLETD_BIN" \
HEGEMON_RELEASE_MANIFEST="$MANIFEST" \
node scripts/live-app-no-ssh-e2e.mjs "${MODE_ARGS[@]}"
