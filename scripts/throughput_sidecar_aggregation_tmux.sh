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
MAX_BLOCK_WAIT_SECS="${HEGEMON_TP_MAX_BLOCK_WAIT_SECS:-600}"

FAST="${HEGEMON_TP_FAST:-0}" # 1 = fast proofs (dev only)
STRICT_AGGREGATION="${HEGEMON_TP_STRICT_AGGREGATION:-1}" # 1 = fail if proven batch is absent
TPS_EFFECTIVE_MODE="${HEGEMON_TP_EFFECTIVE_MODE:-inclusion}" # inclusion|end_to_end|submission

# Throughput profile:
# - safe: conservative laptop defaults
# - max:  use all visible CPU threads
# - auto: choose max on >=128 GiB machines, else safe
TP_PROFILE="${HEGEMON_TP_PROFILE:-auto}"
HOST_THREADS="$(
  getconf _NPROCESSORS_ONLN 2>/dev/null \
    || nproc 2>/dev/null \
    || echo 1
)"
HOST_MEM_GIB="$(
  awk '/MemTotal:/ {print int($2 / 1024 / 1024)}' /proc/meminfo 2>/dev/null \
    || echo 0
)"

case "$TP_PROFILE" in
  safe)
    DEFAULT_RAYON_THREADS=2
    DEFAULT_CARGO_JOBS=1
    DEFAULT_MINE_THREADS=1
    ;;
  max)
    DEFAULT_RAYON_THREADS="$HOST_THREADS"
    DEFAULT_CARGO_JOBS="$HOST_THREADS"
    DEFAULT_MINE_THREADS="$HOST_THREADS"
    ;;
  auto)
    if [ "$HOST_MEM_GIB" -ge 128 ]; then
      DEFAULT_RAYON_THREADS="$HOST_THREADS"
      DEFAULT_CARGO_JOBS="$HOST_THREADS"
      DEFAULT_MINE_THREADS="$HOST_THREADS"
    else
      DEFAULT_RAYON_THREADS=2
      DEFAULT_CARGO_JOBS=1
      DEFAULT_MINE_THREADS=1
    fi
    ;;
  *)
    echo "Unknown HEGEMON_TP_PROFILE='$TP_PROFILE' (expected safe|max|auto)" >&2
    exit 1
    ;;
esac

RAYON_THREADS="${HEGEMON_TP_RAYON_THREADS:-$DEFAULT_RAYON_THREADS}"
CARGO_JOBS="${HEGEMON_TP_CARGO_JOBS:-$DEFAULT_CARGO_JOBS}"
MINE_THREADS="${HEGEMON_TP_MINE_THREADS:-$DEFAULT_MINE_THREADS}"

if [ "$RAYON_THREADS" -lt 1 ] || [ "$CARGO_JOBS" -lt 1 ] || [ "$MINE_THREADS" -lt 1 ]; then
  echo "Thread settings must be >= 1 (rayon=$RAYON_THREADS cargo_jobs=$CARGO_JOBS mine_threads=$MINE_THREADS)" >&2
  exit 1
fi

export RAYON_NUM_THREADS="$RAYON_THREADS"
export HEGEMON_RAYON_THREADS="$RAYON_THREADS"
export CARGO_BUILD_JOBS="$CARGO_JOBS"

if [ "${HEGEMON_TP_UNSAFE:-0}" != "1" ] && [ "$FAST" != "1" ] && [ "$TX_COUNT" -gt 32 ]; then
  echo "Refusing TX_COUNT=${TX_COUNT} without HEGEMON_TP_UNSAFE=1 (can wedge macOS during proving)." >&2
  echo "Hint: set HEGEMON_TP_FAST=1 for dev-only proofs, or run on a beefier machine." >&2
  exit 1
fi

case "$TPS_EFFECTIVE_MODE" in
  inclusion|end_to_end|submission)
    ;;
  *)
    echo "HEGEMON_TP_EFFECTIVE_MODE must be one of inclusion|end_to_end|submission (got '$TPS_EFFECTIVE_MODE')." >&2
    exit 1
    ;;
esac

WALLET_A="${HEGEMON_TP_WALLET_A:-/tmp/hegemon-throughput-wallet-a}"
WALLET_B="${HEGEMON_TP_WALLET_B:-/tmp/hegemon-throughput-wallet-b}"
PASS_A="${HEGEMON_TP_PASS_A:-testwallet1}"
PASS_B="${HEGEMON_TP_PASS_B:-testwallet2}"
RECIPIENTS_JSON="${HEGEMON_TP_RECIPIENTS_JSON:-/tmp/hegemon-throughput-recipients.json}"
WORKERS="${HEGEMON_TP_WORKERS:-1}"
PROVER_WORKERS="${HEGEMON_TP_PROVER_WORKERS:-1}"
WORKER_PREFIX="${HEGEMON_TP_WORKER_PREFIX:-/tmp/hegemon-throughput-worker}"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required binary: $1" >&2
    exit 1
  fi
}

require_bin tmux
require_bin curl
require_bin python3

if command -v rg >/dev/null 2>&1; then
  SEARCH_BIN="rg"
elif command -v grep >/dev/null 2>&1; then
  SEARCH_BIN="grep -E"
else
  echo "Missing required search binary: rg or grep" >&2
  exit 1
fi

search_log() {
  local pattern="$1"
  if [ "$SEARCH_BIN" = "rg" ]; then
    rg "$pattern" "$LOG_FILE" || true
  else
    grep -E "$pattern" "$LOG_FILE" || true
  fi
}

wallet_shielded_address() {
  local store="$1"
  local passphrase="$2"
  ./target/release/wallet status --store "$store" --passphrase "$passphrase" --no-sync \
    | grep "Shielded Address" \
    | awk '{print $3}'
}

current_block_number() {
  local header_json
  header_json="$(
    curl -s -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
      "$RPC_HTTP" || true
  )"
  python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; num=(obj.get("result") or {}).get("number"); print(int(num,16) if isinstance(num,str) else 0)' <<<"$header_json"
}

now_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

cd "$ROOT_DIR"

echo "Throughput profile: $TP_PROFILE (host_threads=$HOST_THREADS host_mem_gib=$HOST_MEM_GIB)" >&2
echo "Thread config: RAYON_NUM_THREADS=$RAYON_THREADS CARGO_BUILD_JOBS=$CARGO_JOBS mine_threads=$MINE_THREADS" >&2

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

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
  echo "HEGEMON_TP_WORKERS must be a positive integer (got '$WORKERS')." >&2
  exit 1
fi
if ! [[ "$PROVER_WORKERS" =~ ^[0-9]+$ ]] || [ "$PROVER_WORKERS" -lt 1 ]; then
  echo "HEGEMON_TP_PROVER_WORKERS must be a positive integer (got '$PROVER_WORKERS')." >&2
  exit 1
fi
if [ "$WORKERS" -gt "$TX_COUNT" ]; then
  WORKERS="$TX_COUNT"
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

declare -a WORKER_STORES=()
declare -a WORKER_PASSES=()
declare -a WORKER_ADDRS=()
declare -a WORKER_TX_COUNTS=()
if [ "$WORKERS" -gt 1 ]; then
  for i in $(seq 1 "$WORKERS"); do
    WORKER_STORES+=("${WORKER_PREFIX}-${i}")
    WORKER_PASSES+=("testworker${i}")
  done
fi

existing_stores=()
for store in "$WALLET_A" "$WALLET_B" "${WORKER_STORES[@]}"; do
  if [ -n "$store" ] && [ -d "$store" ]; then
    existing_stores+=("$store")
  fi
done

if [ "${#existing_stores[@]}" -gt 0 ]; then
  echo "Wallet stores already exist; delete them or set HEGEMON_TP_FORCE=1:" >&2
  for store in "${existing_stores[@]}"; do
    echo "  $store" >&2
  done
  if [ "${HEGEMON_TP_FORCE:-0}" != "1" ]; then
    exit 1
  fi
  rm -rf "$WALLET_A" "$WALLET_B" "${WORKER_STORES[@]}"
fi

echo "Initializing wallets..." >&2
./target/release/wallet init --store "$WALLET_A" --passphrase "$PASS_A"
./target/release/wallet init --store "$WALLET_B" --passphrase "$PASS_B"

if [ "$WORKERS" -gt 1 ]; then
  for i in "${!WORKER_STORES[@]}"; do
    ./target/release/wallet init --store "${WORKER_STORES[$i]}" --passphrase "${WORKER_PASSES[$i]}"
  done
fi

MINER_ADDRESS="$(wallet_shielded_address "$WALLET_A" "$PASS_A")"
RECIPIENT_ADDRESS="$(wallet_shielded_address "$WALLET_B" "$PASS_B")"

if [ -z "$MINER_ADDRESS" ] || [ -z "$RECIPIENT_ADDRESS" ]; then
  echo "Failed to read shielded addresses from wallet status output" >&2
  exit 1
fi

if [ "$WORKERS" -gt 1 ]; then
  for i in "${!WORKER_STORES[@]}"; do
    WORKER_ADDRS[$i]="$(wallet_shielded_address "${WORKER_STORES[$i]}" "${WORKER_PASSES[$i]}")"
    if [ -z "${WORKER_ADDRS[$i]}" ]; then
      echo "Failed to read shielded address for worker $((i + 1))" >&2
      exit 1
    fi
  done
fi

base_tx_per_worker=$((TX_COUNT / WORKERS))
extra_tx_workers=$((TX_COUNT % WORKERS))
for i in $(seq 0 $((WORKERS - 1))); do
  count="$base_tx_per_worker"
  if [ "$i" -lt "$extra_tx_workers" ]; then
    count=$((count + 1))
  fi
  WORKER_TX_COUNTS[$i]="$count"
done

echo "Worker distribution: workers=$WORKERS tx_count=$TX_COUNT counts=${WORKER_TX_COUNTS[*]}" >&2

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
     HEGEMON_MINE_THREADS='${MINE_THREADS}' \
     HEGEMON_PROVER_WORKERS='${PROVER_WORKERS}' \
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
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"hegemon_startMining\",\"params\":[{\"threads\":${MINE_THREADS}}],\"id\":1}" \
  "$RPC_HTTP" >/dev/null

echo "Waiting for >= ${COINBASE_BLOCKS} blocks..." >&2
for i in $(seq 1 "$MAX_BLOCK_WAIT_SECS"); do
  HEADER_JSON="$(curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP" || true)"
  BLOCK_NUM="$(python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; num=(obj.get("result") or {}).get("number"); print(int(num,16) if isinstance(num,str) else 0)' <<<"$HEADER_JSON")"
  if [ "$BLOCK_NUM" -ge "$COINBASE_BLOCKS" ]; then
    break
  fi
  sleep 1
done
if [ "$BLOCK_NUM" -lt "$COINBASE_BLOCKS" ]; then
  echo "Timed out waiting for >= ${COINBASE_BLOCKS} blocks after ${MAX_BLOCK_WAIT_SECS}s (got ${BLOCK_NUM})." >&2
  echo "Hint: increase HEGEMON_TP_MAX_BLOCK_WAIT_SECS or lower HEGEMON_TP_VALUE/HEGEMON_TP_TX_COUNT." >&2
  exit 1
fi

echo "Stopping mining so transfers accumulate in the pool..." >&2
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
  "$RPC_HTTP" >/dev/null

echo "Syncing miner wallet..." >&2
env $WALLET_FAST_ENV ./target/release/wallet substrate-sync \
  --store "$WALLET_A" --passphrase "$PASS_A" \
  --ws-url "$RPC_WS" --force-rescan

if [ "$WORKERS" -gt 1 ]; then
  echo "Funding worker wallets from miner..." >&2
  for i in "${!WORKER_STORES[@]}"; do
    worker_tx_count="${WORKER_TX_COUNTS[$i]}"
    if [ "$worker_tx_count" -le 0 ]; then
      continue
    fi
    fund_json="/tmp/hegemon-throughput-worker-fund-$((i + 1)).json"
    fund_note_value=$((VALUE + FEE))
    cat <<EOF > "$fund_json"
[
  {
    "address": "${WORKER_ADDRS[$i]}",
    "value": ${fund_note_value},
    "asset_id": 0,
    "memo": "worker $((i + 1)) funding note"
  }
]
EOF
    echo "  funding worker $((i + 1)) with ${worker_tx_count} note(s) of ${fund_note_value} units..." >&2
    for j in $(seq 1 "$worker_tx_count"); do
      env HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1 $WALLET_FAST_ENV ./target/release/wallet substrate-send \
        --store "$WALLET_A" --passphrase "$PASS_A" \
        --recipients "$fund_json" \
        --ws-url "$RPC_WS" \
        --fee "$FEE" >/dev/null
    done
  done

  echo "Mining worker-funding transfers..." >&2
  before_funding_mine="$(current_block_number)"
  curl -s -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"hegemon_startMining\",\"params\":[{\"threads\":${MINE_THREADS}}],\"id\":1}" \
    "$RPC_HTTP" >/dev/null
  funding_target=$((before_funding_mine + 2))
  for i in $(seq 1 "$MAX_BLOCK_WAIT_SECS"); do
    current="$(current_block_number)"
    if [ "$current" -ge "$funding_target" ]; then
      break
    fi
    sleep 1
  done
  if [ "$current" -lt "$funding_target" ]; then
    echo "Timed out while mining worker funding transfers (target block ${funding_target}, got ${current})." >&2
    exit 1
  fi

  curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
    "$RPC_HTTP" >/dev/null

  echo "Syncing worker wallets..." >&2
  for i in "${!WORKER_STORES[@]}"; do
    env $WALLET_FAST_ENV ./target/release/wallet substrate-sync \
      --store "${WORKER_STORES[$i]}" --passphrase "${WORKER_PASSES[$i]}" \
      --ws-url "$RPC_WS" --force-rescan >/dev/null
  done
fi

echo "Submitting ${TX_COUNT} sidecar transfers (this may take a while)..." >&2
ROUND_START_MS="$(now_ms)"
SEND_START_MS="$ROUND_START_MS"
if [ "$WORKERS" -le 1 ]; then
  for i in $(seq 1 "$TX_COUNT"); do
    echo "  sending ${i}/${TX_COUNT}..." >&2
    env HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1 $WALLET_FAST_ENV ./target/release/wallet substrate-send \
      --store "$WALLET_A" --passphrase "$PASS_A" \
      --recipients "$RECIPIENTS_JSON" \
      --ws-url "$RPC_WS" \
      --fee "$FEE" >/dev/null
  done
else
  pids=()
  for i in "${!WORKER_STORES[@]}"; do
    worker_id=$((i + 1))
    worker_tx_count="${WORKER_TX_COUNTS[$i]}"
    worker_store="${WORKER_STORES[$i]}"
    worker_pass="${WORKER_PASSES[$i]}"
    if [ "$worker_tx_count" -le 0 ]; then
      continue
    fi
    (
      for j in $(seq 1 "$worker_tx_count"); do
        echo "  worker ${worker_id} sending ${j}/${worker_tx_count}..." >&2
        env HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1 $WALLET_FAST_ENV ./target/release/wallet substrate-send \
          --store "$worker_store" --passphrase "$worker_pass" \
          --recipients "$RECIPIENTS_JSON" \
          --ws-url "$RPC_WS" \
          --fee "$FEE" >/dev/null
      done
    ) &
    pids+=("$!")
  done

  send_failed=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      send_failed=1
    fi
  done
  if [ "$send_failed" -ne 0 ]; then
    echo "One or more worker send loops failed." >&2
    exit 1
  fi
fi
SEND_END_MS="$(now_ms)"
SEND_TOTAL_MS=$((SEND_END_MS - SEND_START_MS))
echo "Send stage complete: send_total_ms=${SEND_TOTAL_MS}" >&2

INCLUSION_START_BLOCK="$(current_block_number)"
INCLUSION_START_MS="$(now_ms)"
echo "Starting mining to include the queued transfers... (start_block=${INCLUSION_START_BLOCK})" >&2
curl -s -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"hegemon_startMining\",\"params\":[{\"threads\":${MINE_THREADS}}],\"id\":1}" \
  "$RPC_HTTP" >/dev/null

echo "Waiting for size + verify metrics in logs..." >&2
touch "$LOG_FILE"
FOUND=""
FOUND_BLOCK=""
for i in $(seq 1 1200); do
  LINE="$(search_log "block_payload_size_metrics" | tail -n 1 || true)"
  if [ -z "$LINE" ]; then
    sleep 1
    continue
  fi
  LINE_BLOCK="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\bblock_number=(\d+)\b", s); print(m.group(1) if m else "")' <<<"$LINE")"
  if [ -z "$LINE_BLOCK" ]; then
    sleep 1
    continue
  fi
  # Ignore stale payload lines from pre-round blocks (e.g., worker-funding inclusion).
  if [ "$LINE_BLOCK" -le "$INCLUSION_START_BLOCK" ]; then
    sleep 1
    continue
  fi
  FOUND="$LINE"
  FOUND_BLOCK="$LINE_BLOCK"
  break
done

if [ -z "$FOUND" ]; then
  echo "Timed out waiting for metrics; inspect logs: $LOG_FILE" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi
ROUND_END_MS="$(now_ms)"
ROUND_TOTAL_MS=$((ROUND_END_MS - ROUND_START_MS))
INCLUSION_TOTAL_MS=$((ROUND_END_MS - INCLUSION_START_MS))

SUBMISSION_TPS="$(python3 - <<PY
tx_count = int("${TX_COUNT}")
send_total_ms = int("${SEND_TOTAL_MS}")
print(f"{(tx_count / (send_total_ms / 1000.0)):.6f}" if send_total_ms > 0 else "0.000000")
PY
)"
INCLUSION_TPS="$(python3 - <<PY
tx_count = int("${TX_COUNT}")
inclusion_total_ms = int("${INCLUSION_TOTAL_MS}")
print(f"{(tx_count / (inclusion_total_ms / 1000.0)):.6f}" if inclusion_total_ms > 0 else "0.000000")
PY
)"
END_TO_END_TPS="$(python3 - <<PY
tx_count = int("${TX_COUNT}")
round_total_ms = int("${ROUND_TOTAL_MS}")
print(f"{(tx_count / (round_total_ms / 1000.0)):.6f}" if round_total_ms > 0 else "0.000000")
PY
)"

case "$TPS_EFFECTIVE_MODE" in
  submission)
    EFFECTIVE_TPS="$SUBMISSION_TPS"
    ;;
  end_to_end)
    EFFECTIVE_TPS="$END_TO_END_TPS"
    ;;
  inclusion)
    EFFECTIVE_TPS="$INCLUSION_TPS"
    ;;
esac

BLOCK_NUMBER="$FOUND_BLOCK"

VERIFY_LINE=""
CONS_LINE=""
if [ -n "$BLOCK_NUMBER" ]; then
  for i in $(seq 1 60); do
    VERIFY_LINE="$(search_log "block_import_verify_time_ms block_number=${BLOCK_NUMBER}" | tail -n 1 || true)"
    if [ -n "$VERIFY_LINE" ]; then
      break
    fi
    sleep 1
  done
fi

for i in $(seq 1 60); do
  CONS_LINE="$(search_log "block_proof_verification_metrics" | tail -n 1 || true)"
  if [ -n "$CONS_LINE" ]; then
    break
  fi
  sleep 1
done

if [ "$STRICT_AGGREGATION" = "1" ]; then
  if [ -z "$VERIFY_LINE" ]; then
    echo "Strict aggregation mode: missing block_import_verify_time_ms for block ${BLOCK_NUMBER}." >&2
    exit 1
  fi
  if [ -z "$CONS_LINE" ]; then
    echo "Strict aggregation mode: missing block_proof_verification_metrics line." >&2
    exit 1
  fi
  if grep -q "proven_batch_present=false" <<<"$VERIFY_LINE"; then
    echo "Strict aggregation mode: tested block imported without proven batch." >&2
    echo "$VERIFY_LINE" >&2
    exit 1
  fi
  if grep -q "aggregation_verified=false" <<<"$CONS_LINE"; then
    echo "Strict aggregation mode: tested block did not verify aggregation proof." >&2
    echo "$CONS_LINE" >&2
    exit 1
  fi
fi

echo "" >&2
echo "=== Latest payload size metrics ===" >&2
echo "$FOUND" >&2
echo "=== Latest import verify time ===" >&2
if [ -n "$VERIFY_LINE" ]; then
  echo "$VERIFY_LINE" >&2
else
  search_log "block_import_verify_time_ms" | tail -n 1 >&2 || true
fi
echo "=== Latest consensus breakdown ===" >&2
if [ -n "$CONS_LINE" ]; then
  echo "$CONS_LINE" >&2
else
  search_log "block_proof_verification_metrics" | tail -n 1 >&2 || true
fi
echo "" >&2
echo "throughput_round_metrics tx_count=${TX_COUNT} workers=${WORKERS} prover_workers=${PROVER_WORKERS} profile=${TP_PROFILE} tps_mode=${TPS_EFFECTIVE_MODE} send_total_ms=${SEND_TOTAL_MS} inclusion_total_ms=${INCLUSION_TOTAL_MS} round_total_ms=${ROUND_TOTAL_MS} submission_tps=${SUBMISSION_TPS} inclusion_tps=${INCLUSION_TPS} end_to_end_tps=${END_TO_END_TPS} effective_tps=${EFFECTIVE_TPS}" >&2

echo "Done. Node is still running in tmux." >&2
echo "  Attach: tmux attach -t $SESSION" >&2
echo "  Logs:   $LOG_FILE" >&2
echo "  Kill:   tmux kill-session -t $SESSION" >&2
