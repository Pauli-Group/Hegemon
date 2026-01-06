#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="${HEGEMON_E2E_TMUX_SESSION:-hegemon-e2e}"
LOG_FILE="${HEGEMON_E2E_LOG_FILE:-/tmp/hegemon-dev-node-e2e-tmux.log}"
PROOF_WAIT_SECS="${HEGEMON_E2E_PROOF_WAIT_SECS:-600}"
DA_WAIT_SECS="${HEGEMON_E2E_DA_WAIT_SECS:-300}"

WALLET_A="${HEGEMON_E2E_WALLET_A:-/tmp/hegemon-wallet-a}"
WALLET_B="${HEGEMON_E2E_WALLET_B:-/tmp/hegemon-wallet-b}"
PASS_A="${HEGEMON_E2E_PASS_A:-testwallet1}"
PASS_B="${HEGEMON_E2E_PASS_B:-testwallet2}"
RECIPIENTS_JSON="${HEGEMON_E2E_RECIPIENTS_JSON:-/tmp/hegemon-recipients-e2e.json}"

RPC_HTTP="${HEGEMON_E2E_RPC_HTTP:-http://127.0.0.1:9944}"
RPC_WS="${HEGEMON_E2E_RPC_WS:-ws://127.0.0.1:9944}"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required binary: $1" >&2
    exit 1
  fi
}

require_bin tmux
require_bin curl
require_bin rg
require_bin python3

cd "$ROOT_DIR"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  if [ "${HEGEMON_E2E_FORCE:-0}" = "1" ]; then
    tmux kill-session -t "$SESSION"
  else
    echo "tmux session already exists: $SESSION" >&2
    echo "Attach with: tmux attach -t $SESSION" >&2
    echo "Kill with:   tmux kill-session -t $SESSION" >&2
    echo "Or rerun with: HEGEMON_E2E_FORCE=1 $0" >&2
    exit 1
  fi
fi

if [ ! -x ./target/release/hegemon-node ]; then
  echo "Building node (fast proofs enabled)..." >&2
  make node-fast
fi

if [ ! -x ./target/release/wallet ]; then
  echo "Building wallet..." >&2
  cargo build --release -p wallet
fi

if [ -d "$WALLET_A" ] || [ -d "$WALLET_B" ]; then
  echo "Wallet stores already exist; delete them or set HEGEMON_E2E_FORCE=1:" >&2
  echo "  $WALLET_A" >&2
  echo "  $WALLET_B" >&2
  if [ "${HEGEMON_E2E_FORCE:-0}" != "1" ]; then
    exit 1
  fi
  rm -rf "$WALLET_A" "$WALLET_B"
fi

echo "Initializing wallets..." >&2
./target/release/wallet init --store "$WALLET_A" --passphrase "$PASS_A"
./target/release/wallet init --store "$WALLET_B" --passphrase "$PASS_B"

MINER_ADDRESS="$(
  ./target/release/wallet status --store "$WALLET_A" --passphrase "$PASS_A" --no-sync \
    | rg "Shielded Address" | awk '{print $3}'
)"
RECIPIENT_ADDRESS="$(
  ./target/release/wallet status --store "$WALLET_B" --passphrase "$PASS_B" --no-sync \
    | rg "Shielded Address" | awk '{print $3}'
)"

if [ -z "$MINER_ADDRESS" ] || [ -z "$RECIPIENT_ADDRESS" ]; then
  echo "Failed to read shielded addresses from wallet status output" >&2
  exit 1
fi

cat <<EOF > "$RECIPIENTS_JSON"
[
  {
    "address": "${RECIPIENT_ADDRESS}",
    "value": 100000000,
    "asset_id": 0,
    "memo": "e2e transfer"
  }
]
EOF

echo "Starting node in tmux session '$SESSION' (logs: $LOG_FILE)..." >&2
tmux new-session -d -s "$SESSION" -n node \
  "cd '$ROOT_DIR' && \
   RUST_LOG=info \
   HEGEMON_MINE=1 \
   HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
   HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1 \
   HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
   HEGEMON_ACCEPT_FAST_PROOFS=1 \
   HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK=1 \
   HEGEMON_MINER_ADDRESS='$MINER_ADDRESS' \
   ./target/release/hegemon-node --dev --tmp 2>&1 | tee '$LOG_FILE'"

echo "Waiting for RPC to respond..." >&2
for i in $(seq 1 60); do
  if curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 60 ]; then
    echo "RPC did not respond after 60s; check logs: $LOG_FILE" >&2
    exit 1
  fi
done

echo "Waiting for a few blocks so coinbase notes exist..." >&2
TARGET_BLOCK="${HEGEMON_E2E_TARGET_BLOCKS:-3}"
for i in $(seq 1 120); do
  HEADER_JSON="$(curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP" || true)"
  BLOCK_NUM="$(python3 - <<'PY'
import json,sys
data = sys.stdin.read()
try:
    obj = json.loads(data) if data.strip() else {}
except Exception:
    obj = {}
hdr = obj.get("result") or {}
num = hdr.get("number")
try:
    print(int(num, 16) if isinstance(num, str) else 0)
except Exception:
    print(0)
PY
  <<<"$HEADER_JSON")"
  if [ "$BLOCK_NUM" -ge "$TARGET_BLOCK" ]; then
    break
  fi
  sleep 1
done

echo "Syncing miner wallet (fast mode)..." >&2
HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/wallet substrate-sync \
  --store "$WALLET_A" --passphrase "$PASS_A" \
  --ws-url "$RPC_WS" --force-rescan

echo "Sending shielded transfer (fast proofs)..." >&2
HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/wallet substrate-send \
  --store "$WALLET_A" --passphrase "$PASS_A" \
  --recipients "$RECIPIENTS_JSON" \
  --ws-url "$RPC_WS"

echo "Waiting for commitment proof storage log line..." >&2
touch "$LOG_FILE"
FOUND_BLOCK=""
FOUND_BLOCK_HASH=""
for i in $(seq 1 "$PROOF_WAIT_SECS"); do
  LINE="$(rg "Commitment block proof stored for imported block" "$LOG_FILE" | tail -n 1 || true)"
  if [ -n "$LINE" ]; then
    FOUND_BLOCK="$(echo "$LINE" | sed -n 's/.*block_number=\([0-9][0-9]*\).*/\1/p')"
    FOUND_BLOCK_HASH="$(echo "$LINE" | sed -n 's/.*block_hash=\([0-9a-fA-F]\{64\}\).*/\1/p')"
    if [ -n "$FOUND_BLOCK" ]; then
      break
    fi
  fi
  sleep 1
done

if [ -z "$FOUND_BLOCK" ] || [ -z "$FOUND_BLOCK_HASH" ]; then
  echo "Timed out waiting for commitment proof storage; inspect logs: $LOG_FILE" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  echo "Tip: increase the timeout via HEGEMON_E2E_PROOF_WAIT_SECS if needed." >&2
  exit 1
fi

echo "Commitment proof stored for block $FOUND_BLOCK" >&2

BLOCK_HASH_JSON="$(curl -s -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHash\",\"params\":[${FOUND_BLOCK}],\"id\":1}" \
  "$RPC_HTTP")"
BLOCK_HASH="$(python3 - <<'PY'
import json,sys
data = sys.stdin.read()
try:
    obj = json.loads(data) if data.strip() else {}
except Exception:
    obj = {}
print((obj.get("result") or "").strip())
PY
<<<"$BLOCK_HASH_JSON")"

BLOCK_HASH_FROM_LOG="0x${FOUND_BLOCK_HASH}"
if [ -z "$BLOCK_HASH" ] || [ "$BLOCK_HASH" = "null" ]; then
  echo "chain_getBlockHash returned no result; using block hash from logs" >&2
  BLOCK_HASH="$BLOCK_HASH_FROM_LOG"
elif [ "$BLOCK_HASH" != "$BLOCK_HASH_FROM_LOG" ]; then
  echo "Warning: chain_getBlockHash != log block_hash; using RPC value" >&2
fi

echo "Waiting for DA root for block $FOUND_BLOCK..." >&2
DA_ROOT=""
for i in $(seq 1 "$DA_WAIT_SECS"); do
  DA_LINE="$(rg "DA encoding stored for imported block block_number=${FOUND_BLOCK} " "$LOG_FILE" | tail -n 1 || true)"
  if [ -n "$DA_LINE" ]; then
    DA_ROOT="$(echo "$DA_LINE" | sed -n 's/.*da_root=\([0-9a-fA-F]\{64\}\).*/\1/p')"
    if [ -n "$DA_ROOT" ]; then
      break
    fi
  fi
  sleep 1
done

if [ -z "$DA_ROOT" ]; then
  echo "Timed out waiting for DA root for block $FOUND_BLOCK; inspect logs: $LOG_FILE" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi

echo "Querying RPC endpoints for block hash $BLOCK_HASH" >&2
curl -s -H "Content-Type: application/json" \
  -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"block_getCommitmentProof\",\"params\":[\"${BLOCK_HASH}\"]}" \
  "$RPC_HTTP"
echo ""
curl -s -H "Content-Type: application/json" \
  -d "{\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"da_getParams\",\"params\":[]}" \
  "$RPC_HTTP"
echo ""
curl -s -H "Content-Type: application/json" \
  -d "{\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"da_getChunk\",\"params\":[\"0x${DA_ROOT}\",0]}" \
  "$RPC_HTTP"
echo ""

echo "Done. Node is still running in tmux." >&2
echo "  Attach: tmux attach -t $SESSION" >&2
echo "  Logs:   $LOG_FILE" >&2
echo "  Kill:   tmux kill-session -t $SESSION" >&2
