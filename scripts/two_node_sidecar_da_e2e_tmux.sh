#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SESSION="${HEGEMON_2N_TMUX_SESSION:-hegemon-two-node-da}"
LOG_A="${HEGEMON_2N_LOG_A:-/tmp/hegemon-two-node-miner.log}"
LOG_B="${HEGEMON_2N_LOG_B:-/tmp/hegemon-two-node-verifier.log}"

RPC_PORT_A="${HEGEMON_2N_RPC_PORT_A:-9955}"
RPC_PORT_B="${HEGEMON_2N_RPC_PORT_B:-9956}"

P2P_PORT_A="${HEGEMON_2N_P2P_PORT_A:-31333}"
P2P_PORT_B="${HEGEMON_2N_P2P_PORT_B:-31334}"

BASE_A="${HEGEMON_2N_BASE_A:-/tmp/hegemon-two-node-a}"
BASE_B="${HEGEMON_2N_BASE_B:-/tmp/hegemon-two-node-b}"

RPC_HTTP_A="http://127.0.0.1:${RPC_PORT_A}"
RPC_WS_A="ws://127.0.0.1:${RPC_PORT_A}"
RPC_HTTP_B="http://127.0.0.1:${RPC_PORT_B}"

TX_COUNT="${HEGEMON_2N_TX_COUNT:-4}"
VALUE="${HEGEMON_2N_VALUE:-100000000}" # 1.0 HGM (8 decimals)
FEE="${HEGEMON_2N_FEE:-0}"
COINBASE_BLOCKS="${HEGEMON_2N_COINBASE_BLOCKS:-$((TX_COUNT + 3))}"
MAX_BLOCK_WAIT_SECS="${HEGEMON_2N_MAX_BLOCK_WAIT_SECS:-600}"

FAST="${HEGEMON_2N_FAST:-0}" # 1 = fast proofs (dev only)

# Guard rails: proving/aggregation is CPU+RAM heavy. Defaults are laptop-safe; override explicitly.
RAYON_THREADS="${HEGEMON_2N_RAYON_THREADS:-2}"
CARGO_JOBS="${HEGEMON_2N_CARGO_JOBS:-1}"
export RAYON_NUM_THREADS="$RAYON_THREADS"
export CARGO_BUILD_JOBS="$CARGO_JOBS"

if [ "${HEGEMON_2N_UNSAFE:-0}" != "1" ] && [ "$FAST" != "1" ] && [ "$TX_COUNT" -gt 32 ]; then
  echo "Refusing TX_COUNT=${TX_COUNT} without HEGEMON_2N_UNSAFE=1 (can wedge macOS during proving)." >&2
  echo "Hint: set HEGEMON_2N_FAST=1 for dev-only proofs, or run on a beefier machine." >&2
  exit 1
fi

WALLET_A="${HEGEMON_2N_WALLET_A:-/tmp/hegemon-two-node-wallet-a}"
WALLET_B="${HEGEMON_2N_WALLET_B:-/tmp/hegemon-two-node-wallet-b}"
PASS_A="${HEGEMON_2N_PASS_A:-testwallet1}"
PASS_B="${HEGEMON_2N_PASS_B:-testwallet2}"
RECIPIENTS_JSON="${HEGEMON_2N_RECIPIENTS_JSON:-/tmp/hegemon-two-node-recipients.json}"

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
  if [ "${HEGEMON_2N_FORCE:-0}" = "1" ]; then
    tmux kill-session -t "$SESSION"
  else
    echo "tmux session already exists: $SESSION" >&2
    echo "Attach with: tmux attach -t $SESSION" >&2
    echo "Kill with:   tmux kill-session -t $SESSION" >&2
    echo "Or rerun with: HEGEMON_2N_FORCE=1 $0" >&2
    exit 1
  fi
fi

if [ "${HEGEMON_2N_FORCE:-0}" = "1" ]; then
  rm -rf "$BASE_A" "$BASE_B" "$WALLET_A" "$WALLET_B" "$LOG_A" "$LOG_B"
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

echo "Building wallet..." >&2
cargo build --release -p wallet

if [ -d "$WALLET_A" ] || [ -d "$WALLET_B" ]; then
  echo "Wallet stores already exist; delete them or set HEGEMON_2N_FORCE=1:" >&2
  echo "  $WALLET_A" >&2
  echo "  $WALLET_B" >&2
  exit 1
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
    "memo": "two-node DA e2e"
  }
]
EOF

NODE_FAST_ENV=""
WALLET_FAST_ENV=""
if [ "$FAST" = "1" ]; then
  NODE_FAST_ENV="HEGEMON_ACCEPT_FAST_PROOFS=1 HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1"
  WALLET_FAST_ENV="HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1"
fi

echo "Starting nodes in tmux session '$SESSION' (logs: $LOG_A, $LOG_B)..." >&2
tmux new-session -d -s "$SESSION" -n miner \
  "cd '$ROOT_DIR' && \
   env \
     RUST_LOG=info \
     $NODE_FAST_ENV \
     HEGEMON_SEEDS='' \
     HEGEMON_MAX_PEERS=4 \
     HEGEMON_MINE=1 \
     HEGEMON_MINE_TEST=1 \
     HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
     HEGEMON_AGGREGATION_PROOFS=1 \
     HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
     HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK='${TX_COUNT}' \
     HEGEMON_MINER_ADDRESS='$MINER_ADDRESS' \
     ./target/release/hegemon-node --dev --base-path '$BASE_A' --rpc-port '${RPC_PORT_A}' --port '${P2P_PORT_A}' --name 'NodeA' 2>&1 | tee '$LOG_A'"

tmux new-window -t "$SESSION" -n verifier \
  "cd '$ROOT_DIR' && \
   env \
     RUST_LOG=info \
     $NODE_FAST_ENV \
     HEGEMON_SEEDS='127.0.0.1:${P2P_PORT_A}' \
     HEGEMON_MAX_PEERS=4 \
     HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
     HEGEMON_AGGREGATION_PROOFS=1 \
     HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
     ./target/release/hegemon-node --dev --base-path '$BASE_B' --rpc-port '${RPC_PORT_B}' --port '${P2P_PORT_B}' --name 'NodeB' 2>&1 | tee '$LOG_B'"

echo "Waiting for RPCs to respond..." >&2
for i in $(seq 1 60); do
  if curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP_A" >/dev/null 2>&1 && \
    curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP_B" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 60 ]; then
    echo "RPC did not respond after 60s; check logs: $LOG_A $LOG_B" >&2
    exit 1
  fi
done

echo "Starting mining to generate coinbase notes..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_startMining","params":[{"threads":1}],"id":1}' \
  "$RPC_HTTP_A" >/dev/null

echo "Waiting for >= ${COINBASE_BLOCKS} blocks (miner RPC)..." >&2
BLOCK_NUM=0
for i in $(seq 1 "$MAX_BLOCK_WAIT_SECS"); do
  HEADER_JSON="$(curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP_A" || true)"
  BLOCK_NUM="$(python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; num=(obj.get("result") or {}).get("number"); print(int(num,16) if isinstance(num,str) else 0)' <<<"$HEADER_JSON")"
  if [ "$BLOCK_NUM" -ge "$COINBASE_BLOCKS" ]; then
    break
  fi
  sleep 1
done
if [ "$BLOCK_NUM" -lt "$COINBASE_BLOCKS" ]; then
  echo "Timed out waiting for >= ${COINBASE_BLOCKS} blocks after ${MAX_BLOCK_WAIT_SECS}s (got ${BLOCK_NUM})." >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi

echo "Stopping mining so transfers accumulate in the pool..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
  "$RPC_HTTP_A" >/dev/null

echo "Syncing miner wallet..." >&2
env $WALLET_FAST_ENV ./target/release/wallet substrate-sync \
  --store "$WALLET_A" --passphrase "$PASS_A" \
  --ws-url "$RPC_WS_A" --force-rescan

echo "Submitting ${TX_COUNT} sidecar transfers (this may take a while)..." >&2
for i in $(seq 1 "$TX_COUNT"); do
  echo "  sending ${i}/${TX_COUNT}..." >&2
  env HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1 $WALLET_FAST_ENV ./target/release/wallet substrate-send \
    --store "$WALLET_A" --passphrase "$PASS_A" \
    --recipients "$RECIPIENTS_JSON" \
    --ws-url "$RPC_WS_A" \
    --fee "$FEE" >/dev/null
done

echo "Starting mining to include the queued transfers..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_startMining","params":[{"threads":1}],"id":1}' \
  "$RPC_HTTP_A" >/dev/null

echo "Waiting for verifier metrics in logs..." >&2
touch "$LOG_B"
FOUND=""
for i in $(seq 1 1200); do
  LINE="$(rg "block_payload_size_metrics" "$LOG_B" | tail -n 1 || true)"
  if [ -n "$LINE" ]; then
    FOUND="$LINE"
    break
  fi
  sleep 1
done

if [ -z "$FOUND" ]; then
  echo "Timed out waiting for verifier metrics; inspect logs: $LOG_B" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi

BLOCK_NUMBER="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\\bblock_number=(\\d+)\\b", s); print(m.group(1) if m else \"\")' <<<"$FOUND")"
VERIFY_LINE=""
if [ -n "$BLOCK_NUMBER" ]; then
  for i in $(seq 1 60); do
    VERIFY_LINE="$(rg "block_import_verify_time_ms block_number=${BLOCK_NUMBER}\\b" "$LOG_B" | tail -n 1 || true)"
    if [ -n "$VERIFY_LINE" ]; then
      break
    fi
    sleep 1
  done
fi

echo "" >&2
echo "=== Miner payload size metrics (NodeA) ===" >&2
rg "block_payload_size_metrics" "$LOG_A" | tail -n 1 >&2 || true
echo "=== Verifier payload size metrics (NodeB) ===" >&2
rg "block_payload_size_metrics" "$LOG_B" | tail -n 1 >&2 || true
echo "=== Verifier import verify time (NodeB) ===" >&2
if [ -n "$VERIFY_LINE" ]; then
  echo "$VERIFY_LINE" >&2
else
  rg "block_import_verify_time_ms" "$LOG_B" | tail -n 1 >&2 || true
fi
echo "" >&2

echo "Done. Nodes are still running in tmux." >&2
echo "  Attach: tmux attach -t $SESSION" >&2
echo "  Logs:   $LOG_A  $LOG_B" >&2
echo "  Kill:   tmux kill-session -t $SESSION" >&2
