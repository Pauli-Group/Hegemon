#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SESSION="${HEGEMON_TP_TMUX_SESSION:-hegemon-throughput}"
LOG_FILE="${HEGEMON_TP_LOG_FILE:-/tmp/hegemon-throughput.log}"

RPC_PORT="${HEGEMON_TP_RPC_PORT:-9955}"
RPC_HTTP="http://127.0.0.1:${RPC_PORT}"
RPC_WS="ws://127.0.0.1:${RPC_PORT}"

TX_COUNT="${HEGEMON_TP_TX_COUNT:-8}"
VALUE="${HEGEMON_TP_VALUE:-100000000}" # 1.0 HGM (8 decimals)
FEE="${HEGEMON_TP_FEE:-0}"
COINBASE_BLOCKS="${HEGEMON_TP_COINBASE_BLOCKS:-$((TX_COUNT + 3))}"

FAST="${HEGEMON_TP_FAST:-0}" # 1 = fast proofs (dev only)

WALLET_A="${HEGEMON_TP_WALLET_A:-/tmp/hegemon-throughput-wallet-a}"
WALLET_B="${HEGEMON_TP_WALLET_B:-/tmp/hegemon-throughput-wallet-b}"
PASS_A="${HEGEMON_TP_PASS_A:-testwallet1}"
PASS_B="${HEGEMON_TP_PASS_B:-testwallet2}"
RECIPIENTS_JSON="${HEGEMON_TP_RECIPIENTS_JSON:-/tmp/hegemon-throughput-recipients.json}"

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
  if [ "${HEGEMON_TP_FORCE:-0}" = "1" ]; then
    tmux kill-session -t "$SESSION"
  else
    echo "tmux session already exists: $SESSION" >&2
    echo "Attach with: tmux attach -t $SESSION" >&2
    echo "Kill with:   tmux kill-session -t $SESSION" >&2
    echo "Or rerun with: HEGEMON_TP_FORCE=1 $0" >&2
    exit 1
  fi
fi

if [ "$FAST" = "1" ]; then
  if [ ! -x ./target/release/hegemon-node ]; then
    echo "Building node (fast proofs enabled)..." >&2
    make node-fast
  fi
else
  if [ ! -x ./target/release/hegemon-node ]; then
    echo "Building node..." >&2
    make node
  fi
fi

if [ ! -x ./target/release/wallet ]; then
  echo "Building wallet..." >&2
  if [ "$FAST" = "1" ]; then
    cargo build --release -p wallet
  else
    cargo build --release -p wallet
  fi
fi

if [ -d "$WALLET_A" ] || [ -d "$WALLET_B" ]; then
  echo "Wallet stores already exist; delete them or set HEGEMON_TP_FORCE=1:" >&2
  echo "  $WALLET_A" >&2
  echo "  $WALLET_B" >&2
  if [ "${HEGEMON_TP_FORCE:-0}" != "1" ]; then
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
    "value": ${VALUE},
    "asset_id": 0,
    "memo": "throughput bench"
  }
]
EOF

NODE_FAST_ENV=""
WALLET_FAST_ENV=""
if [ "$FAST" = "1" ]; then
  NODE_FAST_ENV="HEGEMON_ACCEPT_FAST_PROOFS=1 HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1"
  WALLET_FAST_ENV="HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1"
fi

echo "Starting node in tmux session '$SESSION' (logs: $LOG_FILE)..." >&2
tmux new-session -d -s "$SESSION" -n node \
  "cd '$ROOT_DIR' && \
   env \
     RUST_LOG=info \
     $NODE_FAST_ENV \
     HEGEMON_SEEDS='' \
     HEGEMON_MAX_PEERS=0 \
     HEGEMON_MINE=1 \
     HEGEMON_MINE_TEST=1 \
     HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
     HEGEMON_AGGREGATION_PROOFS=1 \
     HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
     HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK='${TX_COUNT}' \
     HEGEMON_MINER_ADDRESS='$MINER_ADDRESS' \
     ./target/release/hegemon-node --dev --tmp --rpc-port '${RPC_PORT}' 2>&1 | tee '$LOG_FILE'"

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

echo "Starting mining to generate coinbase notes..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_startMining","params":[{"threads":1}],"id":1}' \
  "$RPC_HTTP" >/dev/null

echo "Waiting for >= ${COINBASE_BLOCKS} blocks..." >&2
for i in $(seq 1 600); do
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
  if [ "$BLOCK_NUM" -ge "$COINBASE_BLOCKS" ]; then
    break
  fi
  sleep 1
done

echo "Stopping mining so transfers accumulate in the pool..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
  "$RPC_HTTP" >/dev/null

echo "Syncing miner wallet..." >&2
env $WALLET_FAST_ENV ./target/release/wallet substrate-sync \
  --store "$WALLET_A" --passphrase "$PASS_A" \
  --ws-url "$RPC_WS" --force-rescan

echo "Submitting ${TX_COUNT} sidecar transfers (this may take a while)..." >&2
for i in $(seq 1 "$TX_COUNT"); do
  echo "  sending ${i}/${TX_COUNT}..." >&2
  env HEGEMON_WALLET_DA_SIDECAR=1 $WALLET_FAST_ENV ./target/release/wallet substrate-send \
    --store "$WALLET_A" --passphrase "$PASS_A" \
    --recipients "$RECIPIENTS_JSON" \
    --ws-url "$RPC_WS" \
    --fee "$FEE" >/dev/null
done

echo "Starting mining to include the queued transfers..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_startMining","params":[{"threads":1}],"id":1}' \
  "$RPC_HTTP" >/dev/null

echo "Waiting for size + verify metrics in logs..." >&2
touch "$LOG_FILE"
FOUND=""
for i in $(seq 1 1200); do
  LINE="$(rg "block_payload_size_metrics" "$LOG_FILE" | tail -n 1 || true)"
  if [ -n "$LINE" ]; then
    FOUND="$LINE"
    break
  fi
  sleep 1
done

if [ -z "$FOUND" ]; then
  echo "Timed out waiting for metrics; inspect logs: $LOG_FILE" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi

BLOCK_NUMBER="$(
  python3 - <<'PY'
import re,sys
s = sys.stdin.read()
m = re.search(r"\\bblock_number=(\\d+)\\b", s)
print(m.group(1) if m else "")
PY
  <<<"$FOUND"
)"

VERIFY_LINE=""
CONS_LINE=""
if [ -n "$BLOCK_NUMBER" ]; then
  for i in $(seq 1 60); do
    VERIFY_LINE="$(rg "block_import_verify_time_ms block_number=${BLOCK_NUMBER}\\b" "$LOG_FILE" | tail -n 1 || true)"
    if [ -n "$VERIFY_LINE" ]; then
      break
    fi
    sleep 1
  done
fi

for i in $(seq 1 60); do
  CONS_LINE="$(rg "block_proof_verification_metrics" "$LOG_FILE" | tail -n 1 || true)"
  if [ -n "$CONS_LINE" ]; then
    break
  fi
  sleep 1
done

echo "" >&2
echo "=== Latest payload size metrics ===" >&2
rg "block_payload_size_metrics" "$LOG_FILE" | tail -n 1 >&2 || true
echo "=== Latest import verify time ===" >&2
if [ -n "$VERIFY_LINE" ]; then
  echo "$VERIFY_LINE" >&2
else
  rg "block_import_verify_time_ms" "$LOG_FILE" | tail -n 1 >&2 || true
fi
echo "=== Latest consensus breakdown ===" >&2
if [ -n "$CONS_LINE" ]; then
  echo "$CONS_LINE" >&2
else
  rg "block_proof_verification_metrics" "$LOG_FILE" | tail -n 1 >&2 || true
fi
echo "" >&2

echo "Done. Node is still running in tmux." >&2
echo "  Attach: tmux attach -t $SESSION" >&2
echo "  Logs:   $LOG_FILE" >&2
echo "  Kill:   tmux kill-session -t $SESSION" >&2
