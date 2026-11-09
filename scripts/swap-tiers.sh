#!/usr/bin/env bash
# Swap test tiers. Usage: scripts/swap-tiers.sh fast|integration|hegemon-local
#
#   fast            No network, no chain tools, no browser. Node 24 and the Python packages only (docs/SWAP_TOOLCHAIN.md).
#   integration     Real local chains and browsers. Each part runs when the host supports it and otherwise prints a
#                   SKIPPED line that names what is missing. Exit 0 with skips, unless SWAP_INTEGRATION_STRICT=1.
#   hegemon-local   Opt in: engine swaps on a real local Hegemon chain (needs the development binaries and the chain template).
#
# Qualification, fund sweeps and public-testnet spend tools are deliberately not part of any tier.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYDEPS="${HEGEMON_PYTHON_DEPS:-$HOME/.local/opt/hegemon-swap-python}"
export PYTHONPATH="$ROOT/scripts${PYDEPS:+:$PYDEPS}${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

# Script-level Python tests that belong to the swap series. Run from the repository root: several read repository files.
SCRIPT_TEST_PATTERNS=(
  'test_public_*.py'
  'test_hegemon_*.py'
  'test_check_hegemon_gateway.py'
  'test_probe_hegemon_testnet.py'
  'test_local_swap_companion.py'
  'test_unlock_swap_backup.py'
  'test_verify_public_btc_cases.py'
  'test_bitcoin_preimage_observer.py'
  'test_cardano_*.py'
  'test_ethereum_local_anchor.py'
  'test_check_swap_secrets.py'
)

# Browser suites for the hosted page, wallets and the relay. They start Chromium (and Anvil or a fake chain where needed).
BROWSER_TESTS=(
  swap-service/browser.test.mjs
  swap-service/journey-browser.test.mjs
  swap-service/guided-browser.test.mjs
  swap-service/identity-browser.test.mjs
  swap-service/observer-browser.test.mjs
  swap-service/timing-browser.test.mjs
  swap-service/sepolia-browser.test.mjs
  swap-service/sepolia-claim-browser.test.mjs
  swap-service/bitcoin-wallet-browser.test.mjs
  swap-service/cardano-wallet-browser.test.mjs
)
DESKTOP_TESTS=(swap-service/desktop.test.mjs swap-service/desktop-node-profile.test.mjs)

step() { printf '\n== %s\n' "$*"; }

require_node24() {
  if ! command -v node >/dev/null 2>&1 || ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)'; then
    echo "Node 24 or newer is required (node:sqlite, global crypto). Found: $(node --version 2>/dev/null || echo none). See .nvmrc and docs/SWAP_TOOLCHAIN.md." >&2
    exit 1
  fi
}

run_python_tests() {
  step "Python: swap engine"
  python3 -m unittest discover -s scripts/swap_engine -t scripts -p 'test_*.py'
  for pattern in "${SCRIPT_TEST_PATTERNS[@]}"; do
    step "Python: scripts/$pattern"
    python3 -m unittest discover -s scripts -t scripts -p "$pattern"
  done
}

fast() {
  require_node24
  step "Client manifest and vendored bundles match a fresh build"
  node scripts/build_client_manifest.mjs --check
  (cd swap-service/vendor-src && node build.mjs --check)
  step "No secrets in swap-related files"
  python3 scripts/check_swap_secrets.py
  step "JavaScript: swap-ui"
  node --test swap-ui/*.test.mjs
  step "JavaScript: relay and Worker"
  node --test swap-service/server.test.mjs swap-service/server-identity.test.mjs swap-service/swap-session.test.mjs swap-service/cloudflare/worker.test.mjs
  run_python_tests
  echo
  echo "swap-test: all fast-tier suites passed"
}

SKIPPED=0
skip() { SKIPPED=$((SKIPPED + 1)); echo "SKIPPED: $*"; }

chromium_path() {
  if [ -n "${CHROMIUM_PATH:-}" ] && [ -x "$CHROMIUM_PATH" ]; then echo "$CHROMIUM_PATH"; return 0; fi
  for name in chromium chromium-browser google-chrome; do
    if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return 0; fi
  done
  return 1
}

integration() {
  require_node24
  local chromium
  if [ ! -d swap-service/node_modules/playwright-core ]; then
    skip "browser suites: swap-service/node_modules/playwright-core is missing (run: npm ci --prefix swap-service)"
  elif ! chromium="$(chromium_path)"; then
    skip "browser suites: no Chromium found (install chromium or set CHROMIUM_PATH)"
  else
    step "Browser suites (Chromium: $chromium)"
    CHROMIUM_PATH="$chromium" node --test --test-concurrency=1 "${BROWSER_TESTS[@]}"
  fi

  local electron="hegemon-app/node_modules/electron/dist/electron"
  if [ ! -x "$electron" ] || [ ! -f hegemon-app/out/renderer/index.html ]; then
    skip "desktop suites: need $electron and a built hegemon-app/out/renderer/index.html (run: npm ci --prefix hegemon-app && npm run build --prefix hegemon-app)"
  elif [ ! -d swap-service/node_modules/playwright-core ]; then
    skip "desktop suites: swap-service/node_modules/playwright-core is missing (run: npm ci --prefix swap-service)"
  else
    step "Desktop suites"
    node --test --test-concurrency=1 "${DESKTOP_TESTS[@]}"
  fi

  local absent
  if absent="$(python3 -m swap_engine.tools anvil bitcoind cardano-node cardano-cli aiken 2>&1 >/dev/null)"; then
    step "Local chains: Ethereum, Bitcoin and Cardano fixtures through the engine (about 25 minutes)"
    HEGEMON_LOCAL_CHAINS=1 python3 -m unittest swap_engine.test_local_chains
  else
    skip "local chain swaps: ${absent}"
  fi

  echo
  if [ "$SKIPPED" -gt 0 ]; then
    echo "swap-integration: $SKIPPED part(s) SKIPPED (listed above); nothing in them was tested"
    if [ "${SWAP_INTEGRATION_STRICT:-0}" = "1" ]; then
      echo "SWAP_INTEGRATION_STRICT=1: failing because parts were skipped" >&2
      exit 1
    fi
  else
    echo "swap-integration: all parts ran and passed"
  fi
}

hegemon_local() {
  require_node24
  python3 - <<'PY' || exit 1
import sys
from swap_engine.adapters.hegemon_local import find_binaries
try:
    node, wallet = find_binaries()
except FileNotFoundError as error:
    print('swap-hegemon-local cannot run: ' + str(error), file=sys.stderr)
    raise SystemExit(1)
print('node  ', node)
print('wallet', wallet)
PY
  if ! python3 -m swap_engine.tools anvil bitcoind cardano-node cardano-cli aiken >/dev/null 2>&1; then
    python3 -m swap_engine.tools anvil bitcoind cardano-node cardano-cli aiken >&2 || true
    echo "swap-hegemon-local cannot run: chain tools are missing (see docs/SWAP_TOOLCHAIN.md)" >&2
    exit 1
  fi
  step "Hegemon local fixture swaps (happy paths; set HEGEMON_LOCAL_HEGEMON_SLOW=1 for the multi-hour refund and late-claim scenarios)"
  HEGEMON_LOCAL_CHAINS=1 HEGEMON_LOCAL_HEGEMON=1 python3 -m unittest -v swap_engine.test_local_hegemon_e2e
}

case "${1:-}" in
  fast) fast ;;
  integration) integration ;;
  hegemon-local) hegemon_local ;;
  *) echo "usage: $0 fast|integration|hegemon-local" >&2; exit 2 ;;
esac
