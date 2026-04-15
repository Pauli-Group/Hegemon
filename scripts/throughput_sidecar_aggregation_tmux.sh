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
BLOCK_SHIELDED_TRANSFER_LIMIT="${HEGEMON_TP_BLOCK_SHIELDED_LIMIT:-$((TX_COUNT + 1))}"

FAST="${HEGEMON_TP_FAST:-0}" # 1 = fast proofs (dev only)
SKIP_BUILD="${HEGEMON_TP_SKIP_BUILD:-0}" # 1 = reuse existing release binaries
REUSE_EXISTING_STATE="${HEGEMON_TP_REUSE_EXISTING_STATE:-0}" # 1 = reuse pre-funded base path + wallet stores
PREPARE_SNAPSHOT_ONLY="${HEGEMON_TP_PREPARE_SNAPSHOT_ONLY:-0}" # 1 = fund/sync then exit before sends
STRICT_AGGREGATION="${HEGEMON_TP_STRICT_AGGREGATION:-1}" # 1 = fail if proven batch is absent
STRICT_PREPARE_TIMEOUT_SECS="${HEGEMON_TP_STRICT_PREPARE_TIMEOUT_SECS:-}"
MIN_PREPARED_TXS="${HEGEMON_TP_MIN_PREPARED_TXS:-$TX_COUNT}"
TPS_EFFECTIVE_MODE="${HEGEMON_TP_EFFECTIVE_MODE:-inclusion}" # inclusion|end_to_end|submission
PROOF_MODE="${HEGEMON_TP_PROOF_MODE:-aggregation}" # aggregation=shipped recursive_block lane, single=historical inline comparison

case "$PROOF_MODE" in
  aggregation|single)
    ;;
  *)
    echo "HEGEMON_TP_PROOF_MODE must be aggregation or single (got '$PROOF_MODE')." >&2
    exit 1
    ;;
esac

if [ -n "${HEGEMON_TP_SEND_PROOF_SIDECAR:-}" ]; then
  SEND_PROOF_SIDECAR="${HEGEMON_TP_SEND_PROOF_SIDECAR}"
elif [ "$PROOF_MODE" = "single" ]; then
  SEND_PROOF_SIDECAR=0
else
  # The shipped recursive_block lane requires embedded proof bytes in every
  # shielded transfer. DA sidecars remain fine, proof sidecars do not.
  SEND_PROOF_SIDECAR=0
fi
if ! [[ "$SEND_PROOF_SIDECAR" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_SEND_PROOF_SIDECAR must be 0 or 1 (got '$SEND_PROOF_SIDECAR')." >&2
  exit 1
fi
if [ "$PROOF_MODE" = "single" ] && [ "$SEND_PROOF_SIDECAR" != "0" ]; then
  echo "HEGEMON_TP_PROOF_MODE=single requires HEGEMON_TP_SEND_PROOF_SIDECAR=0." >&2
  exit 1
fi
if [ "$PROOF_MODE" = "aggregation" ] && [ "$SEND_PROOF_SIDECAR" != "0" ]; then
  echo "HEGEMON_TP_PROOF_MODE=aggregation measures the shipped recursive_block lane and requires HEGEMON_TP_SEND_PROOF_SIDECAR=0." >&2
  exit 1
fi

if [ -n "${HEGEMON_TP_SEND_DA_SIDECAR:-}" ]; then
  SEND_DA_SIDECAR="${HEGEMON_TP_SEND_DA_SIDECAR}"
elif [ "$PROOF_MODE" = "single" ]; then
  SEND_DA_SIDECAR=0
else
  SEND_DA_SIDECAR=1
fi
if ! [[ "$SEND_DA_SIDECAR" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_SEND_DA_SIDECAR must be 0 or 1 (got '$SEND_DA_SIDECAR')." >&2
  exit 1
fi

if [ -n "${HEGEMON_TP_SEND_NO_SYNC:-}" ]; then
  SEND_NO_SYNC_DEFAULT="${HEGEMON_TP_SEND_NO_SYNC}"
elif [ "$PROOF_MODE" = "single" ]; then
  # Inline proofs mutate note state locally; forcing a sync between sends avoids
  # nullifier reuse during benchmark generation.
  SEND_NO_SYNC_DEFAULT=0
else
  SEND_NO_SYNC_DEFAULT=1
fi
if ! [[ "$SEND_NO_SYNC_DEFAULT" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_SEND_NO_SYNC must be 0 or 1 (got '$SEND_NO_SYNC_DEFAULT')." >&2
  exit 1
fi

if [ "$PROOF_MODE" = "single" ]; then
  if [ "$STRICT_AGGREGATION" = "1" ]; then
    echo "Disabling strict aggregation checks for HEGEMON_TP_PROOF_MODE=single." >&2
  fi
  STRICT_AGGREGATION=0
  AGGREGATION_PROOFS_ENABLED=0
else
  AGGREGATION_PROOFS_ENABLED=1
fi

if [ -n "${HEGEMON_TP_INCLUSION_TARGET_MODE:-}" ]; then
  INCLUSION_TARGET_MODE="${HEGEMON_TP_INCLUSION_TARGET_MODE}"
elif [ "$PROOF_MODE" = "single" ]; then
  INCLUSION_TARGET_MODE="cumulative"
else
  INCLUSION_TARGET_MODE="single_block"
fi
case "$INCLUSION_TARGET_MODE" in
  single_block|cumulative)
    ;;
  *)
    echo "HEGEMON_TP_INCLUSION_TARGET_MODE must be single_block or cumulative (got '$INCLUSION_TARGET_MODE')." >&2
    exit 1
    ;;
esac

if [ -n "${HEGEMON_TP_PROVER_LIVENESS_LANE:-}" ]; then
  PROVER_LIVENESS_LANE="${HEGEMON_TP_PROVER_LIVENESS_LANE}"
elif [ "$STRICT_AGGREGATION" = "1" ]; then
  PROVER_LIVENESS_LANE=0
else
  PROVER_LIVENESS_LANE=1
fi
if [ -n "${HEGEMON_TP_BATCH_QUEUE_CAPACITY:-}" ]; then
  BATCH_QUEUE_CAPACITY="${HEGEMON_TP_BATCH_QUEUE_CAPACITY}"
elif [ "$PROVER_LIVENESS_LANE" = "0" ]; then
  BATCH_QUEUE_CAPACITY=1
else
  BATCH_QUEUE_CAPACITY=4
fi
BATCH_INCREMENTAL_UPSIZE="${HEGEMON_TP_BATCH_INCREMENTAL_UPSIZE:-0}" # 1 = legacy +1 upsizing
MIN_READY_BATCH_TXS="${HEGEMON_TP_MIN_READY_BATCH_TXS:-$MIN_PREPARED_TXS}"

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
HOST_MEM_GIB=0
if [ -r /proc/meminfo ]; then
  HOST_MEM_GIB="$(
    awk '/MemTotal:/ {print int($2 / 1024 / 1024)}' /proc/meminfo 2>/dev/null \
      || echo 0
  )"
elif mem_bytes="$(sysctl -n hw.memsize 2>/dev/null)"; then
  if [[ "$mem_bytes" =~ ^[0-9]+$ ]] && [ "$mem_bytes" -gt 0 ]; then
    HOST_MEM_GIB=$((mem_bytes / 1024 / 1024 / 1024))
  fi
fi

case "$TP_PROFILE" in
  safe)
    DEFAULT_RAYON_THREADS=2
    DEFAULT_CARGO_JOBS=1
    ;;
  max)
    DEFAULT_RAYON_THREADS="$HOST_THREADS"
    DEFAULT_CARGO_JOBS="$HOST_THREADS"
    ;;
  auto)
    if [ "$HOST_MEM_GIB" -ge 128 ]; then
      DEFAULT_RAYON_THREADS="$HOST_THREADS"
      DEFAULT_CARGO_JOBS="$HOST_THREADS"
    else
      DEFAULT_RAYON_THREADS=2
      DEFAULT_CARGO_JOBS=1
    fi
    ;;
  *)
    echo "Unknown HEGEMON_TP_PROFILE='$TP_PROFILE' (expected safe|max|auto)" >&2
    exit 1
    ;;
esac

NODE_RAYON_THREADS="${HEGEMON_TP_NODE_RAYON_THREADS:-${HEGEMON_TP_RAYON_THREADS:-$DEFAULT_RAYON_THREADS}}"
CARGO_JOBS="${HEGEMON_TP_CARGO_JOBS:-$DEFAULT_CARGO_JOBS}"
DEFAULT_MINE_THREADS=1
MINE_THREADS="${HEGEMON_TP_MINE_THREADS:-$DEFAULT_MINE_THREADS}"
AGG_PROFILE="${HEGEMON_TP_AGG_PROFILE:-0}"
if [ -n "${HEGEMON_TP_AGG_PROVER_THREADS:-}" ]; then
  AGG_PROVER_THREADS="${HEGEMON_TP_AGG_PROVER_THREADS}"
elif [ "$TP_PROFILE" = "safe" ]; then
  AGG_PROVER_THREADS=1
elif [ "$HOST_MEM_GIB" -ge 128 ]; then
  AGG_PROVER_THREADS="$HOST_THREADS"
else
  if [ "$HOST_THREADS" -gt 2 ]; then
    AGG_PROVER_THREADS=2
  else
    AGG_PROVER_THREADS="$HOST_THREADS"
  fi
fi
AGG_PREPARE_THREADS="${HEGEMON_TP_AGG_PREPARE_THREADS:-}"
AGG_PREPARE_THREADS_AUTO=0
if [ -z "$AGG_PREPARE_THREADS" ]; then
  AGG_PREPARE_THREADS_AUTO=1
  AGG_PREPARE_THREADS="$NODE_RAYON_THREADS"
fi
AGG_WITNESS_LANES="${HEGEMON_TP_AGG_WITNESS_LANES:-}"
AGG_ADD_LANES="${HEGEMON_TP_AGG_ADD_LANES:-}"
AGG_MUL_LANES="${HEGEMON_TP_AGG_MUL_LANES:-}"
AGG_PREWARM_INCLUDE_MERGE="${HEGEMON_TP_AGG_PREWARM_INCLUDE_MERGE:-}"
AGG_PREWARM_MAX_TXS="${HEGEMON_TP_AGG_PREWARM_MAX_TXS:-}"
PREWARM_ONLY="${HEGEMON_TP_PREWARM_ONLY:-0}" # 1 = stop after prepared batch is available

if [ "$NODE_RAYON_THREADS" -lt 1 ] || [ "$CARGO_JOBS" -lt 1 ] || [ "$MINE_THREADS" -lt 1 ]; then
  echo "Thread settings must be >= 1 (node_rayon=$NODE_RAYON_THREADS cargo_jobs=$CARGO_JOBS mine_threads=$MINE_THREADS)" >&2
  exit 1
fi
if ! [[ "$AGG_PROFILE" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_AGG_PROFILE must be 0 or 1 (got '$AGG_PROFILE')." >&2
  exit 1
fi
if ! [[ "$AGG_PROVER_THREADS" =~ ^[0-9]+$ ]]; then
  echo "HEGEMON_TP_AGG_PROVER_THREADS must be an integer >= 0 (got '$AGG_PROVER_THREADS')." >&2
  exit 1
fi
if ! [[ "$AGG_PREPARE_THREADS" =~ ^[0-9]+$ ]] || [ "$AGG_PREPARE_THREADS" -lt 1 ]; then
  echo "HEGEMON_TP_AGG_PREPARE_THREADS must be a positive integer (got '$AGG_PREPARE_THREADS')." >&2
  exit 1
fi
if [ -n "$AGG_WITNESS_LANES" ] && { ! [[ "$AGG_WITNESS_LANES" =~ ^[0-9]+$ ]] || [ "$AGG_WITNESS_LANES" -lt 1 ]; }; then
  echo "HEGEMON_TP_AGG_WITNESS_LANES must be a positive integer when set (got '$AGG_WITNESS_LANES')." >&2
  exit 1
fi
if [ -n "$AGG_ADD_LANES" ] && { ! [[ "$AGG_ADD_LANES" =~ ^[0-9]+$ ]] || [ "$AGG_ADD_LANES" -lt 1 ]; }; then
  echo "HEGEMON_TP_AGG_ADD_LANES must be a positive integer when set (got '$AGG_ADD_LANES')." >&2
  exit 1
fi
if [ -n "$AGG_MUL_LANES" ] && { ! [[ "$AGG_MUL_LANES" =~ ^[0-9]+$ ]] || [ "$AGG_MUL_LANES" -lt 1 ]; }; then
  echo "HEGEMON_TP_AGG_MUL_LANES must be a positive integer when set (got '$AGG_MUL_LANES')." >&2
  exit 1
fi
if [ -n "$AGG_PREWARM_INCLUDE_MERGE" ] && ! [[ "$AGG_PREWARM_INCLUDE_MERGE" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_AGG_PREWARM_INCLUDE_MERGE must be 0 or 1 when set (got '$AGG_PREWARM_INCLUDE_MERGE')." >&2
  exit 1
fi
if [ -n "$AGG_PREWARM_MAX_TXS" ] && ! [[ "$AGG_PREWARM_MAX_TXS" =~ ^[0-9]+$ ]]; then
  echo "HEGEMON_TP_AGG_PREWARM_MAX_TXS must be an integer >= 0 (got '$AGG_PREWARM_MAX_TXS')." >&2
  exit 1
fi
if ! [[ "$PREWARM_ONLY" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_PREWARM_ONLY must be 0 or 1 (got '$PREWARM_ONLY')." >&2
  exit 1
fi
if ! [[ "$SKIP_BUILD" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_SKIP_BUILD must be 0 or 1 (got '$SKIP_BUILD')." >&2
  exit 1
fi
if ! [[ "$REUSE_EXISTING_STATE" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_REUSE_EXISTING_STATE must be 0 or 1 (got '$REUSE_EXISTING_STATE')." >&2
  exit 1
fi
if ! [[ "$PREPARE_SNAPSHOT_ONLY" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_PREPARE_SNAPSHOT_ONLY must be 0 or 1 (got '$PREPARE_SNAPSHOT_ONLY')." >&2
  exit 1
fi

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
if [ -n "$STRICT_PREPARE_TIMEOUT_SECS" ] && { ! [[ "$STRICT_PREPARE_TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [ "$STRICT_PREPARE_TIMEOUT_SECS" -lt 1 ]; }; then
  echo "HEGEMON_TP_STRICT_PREPARE_TIMEOUT_SECS must be a positive integer (got '$STRICT_PREPARE_TIMEOUT_SECS')." >&2
  exit 1
fi
if ! [[ "$MIN_PREPARED_TXS" =~ ^[0-9]+$ ]] || [ "$MIN_PREPARED_TXS" -lt 1 ]; then
  echo "HEGEMON_TP_MIN_PREPARED_TXS must be a positive integer (got '$MIN_PREPARED_TXS')." >&2
  exit 1
fi
if [ "$MIN_PREPARED_TXS" -gt "$TX_COUNT" ]; then
  echo "HEGEMON_TP_MIN_PREPARED_TXS (${MIN_PREPARED_TXS}) cannot exceed HEGEMON_TP_TX_COUNT (${TX_COUNT})." >&2
  exit 1
fi
if ! [[ "$PROVER_LIVENESS_LANE" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_PROVER_LIVENESS_LANE must be 0 or 1 (got '$PROVER_LIVENESS_LANE')." >&2
  exit 1
fi
if ! [[ "$BATCH_QUEUE_CAPACITY" =~ ^[0-9]+$ ]] || [ "$BATCH_QUEUE_CAPACITY" -lt 1 ]; then
  echo "HEGEMON_TP_BATCH_QUEUE_CAPACITY must be a positive integer (got '$BATCH_QUEUE_CAPACITY')." >&2
  exit 1
fi
if ! [[ "$BATCH_INCREMENTAL_UPSIZE" =~ ^[01]$ ]]; then
  echo "HEGEMON_TP_BATCH_INCREMENTAL_UPSIZE must be 0 or 1 (got '$BATCH_INCREMENTAL_UPSIZE')." >&2
  exit 1
fi
if ! [[ "$MIN_READY_BATCH_TXS" =~ ^[0-9]+$ ]] || [ "$MIN_READY_BATCH_TXS" -lt 1 ]; then
  echo "HEGEMON_TP_MIN_READY_BATCH_TXS must be a positive integer (got '$MIN_READY_BATCH_TXS')." >&2
  exit 1
fi
if [ "$MIN_READY_BATCH_TXS" -gt "$TX_COUNT" ]; then
  echo "HEGEMON_TP_MIN_READY_BATCH_TXS (${MIN_READY_BATCH_TXS}) cannot exceed HEGEMON_TP_TX_COUNT (${TX_COUNT})." >&2
  exit 1
fi
if ! [[ "$BLOCK_SHIELDED_TRANSFER_LIMIT" =~ ^[0-9]+$ ]] || [ "$BLOCK_SHIELDED_TRANSFER_LIMIT" -lt 1 ]; then
  echo "HEGEMON_TP_BLOCK_SHIELDED_LIMIT must be a positive integer (got '$BLOCK_SHIELDED_TRANSFER_LIMIT')." >&2
  exit 1
fi

CHAIN_SPEC="${HEGEMON_TP_CHAIN_SPEC:-}"
NODE_CHAIN_ARGS="--dev"
NODE_BASE_PATH="${HEGEMON_TP_NODE_BASE_PATH:-}"
if [ -n "$CHAIN_SPEC" ]; then
  if [ ! -f "$CHAIN_SPEC" ]; then
    echo "HEGEMON_TP_CHAIN_SPEC file not found: $CHAIN_SPEC" >&2
    exit 1
  fi
  CHAIN_SPEC_ABS="$(cd "$(dirname "$CHAIN_SPEC")" && pwd)/$(basename "$CHAIN_SPEC")"
  NODE_CHAIN_ARGS="--dev --chain '${CHAIN_SPEC_ABS}'"
fi
if [ -n "$NODE_BASE_PATH" ]; then
  mkdir -p "$NODE_BASE_PATH"
  NODE_BASE_PATH_ABS="$(cd "$(dirname "$NODE_BASE_PATH")" && pwd)/$(basename "$NODE_BASE_PATH")"
  NODE_CHAIN_ARGS="${NODE_CHAIN_ARGS} --base-path '${NODE_BASE_PATH_ABS}'"
else
  NODE_CHAIN_ARGS="${NODE_CHAIN_ARGS} --tmp"
fi

WALLET_A="${HEGEMON_TP_WALLET_A:-/tmp/hegemon-throughput-wallet-a}"
WALLET_B="${HEGEMON_TP_WALLET_B:-/tmp/hegemon-throughput-wallet-b}"
PASS_A="${HEGEMON_TP_PASS_A:-testwallet1}"
PASS_B="${HEGEMON_TP_PASS_B:-testwallet2}"
RECIPIENTS_JSON="${HEGEMON_TP_RECIPIENTS_JSON:-/tmp/hegemon-throughput-recipients.json}"
WORKERS="${HEGEMON_TP_WORKERS:-1}"
if [ -n "${HEGEMON_TP_PROVER_WORKERS:-}" ]; then
  PROVER_WORKERS="${HEGEMON_TP_PROVER_WORKERS}"
elif [ "$PROOF_MODE" = "single" ]; then
  PROVER_WORKERS=1
elif [ "$TP_PROFILE" = "safe" ]; then
  if [ "$HOST_THREADS" -ge 2 ]; then
    PROVER_WORKERS=2
  else
    PROVER_WORKERS=1
  fi
elif [ "$HOST_MEM_GIB" -ge 128 ]; then
  if [ "$HOST_THREADS" -ge 4 ]; then
    PROVER_WORKERS=4
  else
    PROVER_WORKERS="$HOST_THREADS"
  fi
else
  if [ "$HOST_THREADS" -ge 4 ]; then
    PROVER_WORKERS=4
  elif [ "$HOST_THREADS" -ge 2 ]; then
    PROVER_WORKERS=2
  else
    PROVER_WORKERS=1
  fi
fi
PROVER_BATCH_JOB_TIMEOUT_MS="${HEGEMON_TP_BATCH_JOB_TIMEOUT_MS:-}"
PROVER_WORK_PACKAGE_TTL_MS="${HEGEMON_TP_WORK_PACKAGE_TTL_MS:-}"
if [ -n "${HEGEMON_TP_ADAPTIVE_LIVENESS_MS:-}" ]; then
  ADAPTIVE_LIVENESS_MS="${HEGEMON_TP_ADAPTIVE_LIVENESS_MS}"
else
  ADAPTIVE_LIVENESS_MS=""
fi
WORKER_PREFIX="${HEGEMON_TP_WORKER_PREFIX:-/tmp/hegemon-throughput-worker}"
WALLET_RPC_REQUEST_TIMEOUT_SECS="${HEGEMON_TP_WALLET_RPC_REQUEST_TIMEOUT_SECS:-180}"
if [ -n "${HEGEMON_TP_RPC_WAIT_SECS:-}" ]; then
  RPC_WAIT_SECS="${HEGEMON_TP_RPC_WAIT_SECS}"
elif [ -n "$CHAIN_SPEC" ]; then
  RPC_WAIT_SECS=180
elif [ -n "$AGG_PREWARM_MAX_TXS" ] && [ "$AGG_PREWARM_MAX_TXS" -gt 0 ]; then
  RPC_WAIT_SECS=300
else
  RPC_WAIT_SECS=60
fi
SEND_RETRIES="${HEGEMON_TP_SEND_RETRIES:-4}"
SEND_RETRY_DELAY_SECS="${HEGEMON_TP_SEND_RETRY_DELAY_SECS:-2}"
TP_SEEDS="${HEGEMON_TP_SEEDS:-}"
TP_MAX_PEERS="${HEGEMON_TP_MAX_PEERS:-0}"
ARTIFACTS_DIR="${HEGEMON_TP_ARTIFACTS_DIR:-/tmp/hegemon-throughput-artifacts}"
RUN_ID="${HEGEMON_TP_RUN_ID:-${PROOF_MODE}-tx${TX_COUNT}-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_JSON="${ARTIFACTS_DIR}/${RUN_ID}.json"
SEND_TRACE_FILE="${ARTIFACTS_DIR}/${RUN_ID}.send-trace.tsv"
if [ -n "${HEGEMON_TP_WALLET_RAYON_THREADS:-}" ]; then
  WALLET_RAYON_THREADS="${HEGEMON_TP_WALLET_RAYON_THREADS}"
else
  WALLET_RAYON_THREADS=0
fi

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required binary: $1" >&2
    exit 1
  fi
}

require_bin tmux
require_bin curl
require_bin python3

find_rpc_listener_pids() {
  local pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(
      lsof -tiTCP:"${RPC_PORT}" -sTCP:LISTEN 2>/dev/null | sort -u | paste -sd' ' - || true
    )"
  elif command -v ss >/dev/null 2>&1; then
    pids="$(
      ss -lntp "( sport = :${RPC_PORT} )" 2>/dev/null \
        | awk -F'pid=' 'NR > 1 {split($2, a, ","); if (a[1] ~ /^[0-9]+$/) print a[1]}' \
        | sort -u \
        | paste -sd' ' - \
        || true
    )"
  elif command -v netstat >/dev/null 2>&1; then
    pids="$(
      netstat -lntp 2>/dev/null \
        | awk -v port=":${RPC_PORT}" '$4 ~ port {split($7, a, "/"); if (a[1] ~ /^[0-9]+$/) print a[1]}' \
        | sort -u \
        | paste -sd' ' - \
        || true
    )"
  fi
  echo "$pids"
}

print_pid_commands() {
  for pid in "$@"; do
    ps -p "$pid" -o pid=,comm=,args= 2>/dev/null || true
  done
}

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

wait_for_tip_quiescence() {
  local max_wait_secs="${1:-30}"
  local settle_polls="${2:-3}"
  local prev
  local current
  local stable_polls=0

  prev="$(current_block_number)"
  for _ in $(seq 1 "$max_wait_secs"); do
    sleep 1
    current="$(current_block_number)"
    if [ "$current" -eq "$prev" ]; then
      stable_polls=$((stable_polls + 1))
      if [ "$stable_polls" -ge "$settle_polls" ]; then
        return 0
      fi
    else
      prev="$current"
      stable_polls=0
    fi
  done

  echo "WARNING: chain tip did not quiesce after ${max_wait_secs}s; proceeding anyway." >&2
  return 0
}

author_pending_extrinsic_count() {
  curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"author_pendingExtrinsics","params":[],"id":1}' \
    "$RPC_HTTP" \
    | python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; print(len(obj.get("result") or []))'
}

prepared_bundle_count() {
  curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"prover_getStagePlanStatus","params":[],"id":1}' \
    "$RPC_HTTP" \
    | python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; print(((obj.get("result") or {}).get("prepared_bundles")) or 0)'
}

now_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

metric_from_line() {
  local line="$1"
  local key="$2"
  python3 -c 'import re,sys; key=re.escape(sys.argv[1]); line=sys.stdin.read(); m=re.search(rf"\b{key}=([0-9]+(?:\.[0-9]+)?)\b", line); print(m.group(1) if m else "")' "$key" <<<"$line"
}

ceil_div() {
  local numerator="$1"
  local denominator="$2"
  echo $(((numerator + denominator - 1) / denominator))
}

aggregation_leaf_job_count() {
  local tx_count="$1"
  local leaf_fanin="$2"
  ceil_div "$tx_count" "$leaf_fanin"
}

derive_aggregation_prepare_budget_ms() {
  local tx_count="$1"
  local leaf_fanin="$2"
  local merge_fanin="$3"
  local prover_workers="$4"
  local cold_leaf_ms=900000
  local warm_leaf_ms=720000
  local merge_base_ms=2400000
  local merge_per_child_ms=120000
  local finalize_ms=300000
  local safety_ms=900000
  local leaf_jobs
  local max_jobs_per_worker
  local leaf_phase_ms
  local merge_phase_ms=0

  leaf_jobs="$(aggregation_leaf_job_count "$tx_count" "$leaf_fanin")"
  if [ "$prover_workers" -lt 1 ]; then
    prover_workers=1
  fi
  if [ "$prover_workers" -gt "$leaf_jobs" ]; then
    prover_workers="$leaf_jobs"
  fi
  max_jobs_per_worker="$(ceil_div "$leaf_jobs" "$prover_workers")"
  leaf_phase_ms=$((cold_leaf_ms + (max_jobs_per_worker - 1) * warm_leaf_ms))

  if [ "$leaf_jobs" -gt 1 ]; then
    merge_phase_ms=$((merge_base_ms + leaf_jobs * merge_per_child_ms))
    if [ "$leaf_jobs" -gt "$merge_fanin" ]; then
      merge_phase_ms=$((merge_phase_ms + merge_base_ms))
    fi
  fi

  echo $((leaf_phase_ms + merge_phase_ms + finalize_ms + safety_ms))
}

bool_metric_from_line() {
  local line="$1"
  local key="$2"
  python3 -c 'import re,sys; key=re.escape(sys.argv[1]); line=sys.stdin.read(); m=re.search(rf"\b{key}=(true|false)\b", line, re.IGNORECASE); print(m.group(1).lower() if m else "")' "$key" <<<"$line"
}

emit_metrics_artifact() {
  local mode="$1"
  mkdir -p "$ARTIFACTS_DIR"
  python3 - "$ARTIFACT_JSON" "$mode" <<'PY'
import json
import os
import pathlib
import re
import sys

path = sys.argv[1]
mode = sys.argv[2]

def getenv(name, default=""):
    value = os.getenv(name)
    return value if value is not None else default

def to_int(name):
    value = getenv(name, "")
    if value == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None

def to_float(name):
    value = getenv(name, "")
    if value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None

def parse_bool(value):
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None

def parse_kv_line(line):
    return dict(re.findall(r'([A-Za-z0-9_]+)=([^\s]+)', line))

send_trace_path = pathlib.Path(getenv("SEND_TRACE_FILE"))
metric_block_number = to_int("METRIC_BLOCK_NUMBER")
metric_tx_count = to_int("METRIC_TX_COUNT")
send_trace = []
if send_trace_path.exists():
    for raw_line in send_trace_path.read_text().splitlines():
        if not raw_line.strip():
            continue
        worker_id, tx_ordinal, start_ms, end_ms, duration_ms, start_block, end_block = raw_line.split("\t")
        send_trace.append(
            {
                "worker_id": int(worker_id),
                "tx_ordinal": int(tx_ordinal),
                "start_ms": int(start_ms),
                "end_ms": int(end_ms),
                "duration_ms": int(duration_ms),
                "start_block": int(start_block),
                "end_block": int(end_block),
            }
        )

send_durations = [item["duration_ms"] for item in send_trace]
send_stats = {
    "count": len(send_trace),
    "min_ms": min(send_durations) if send_durations else None,
    "max_ms": max(send_durations) if send_durations else None,
    "avg_ms": round(sum(send_durations) / len(send_durations), 3) if send_durations else None,
}

log_path = pathlib.Path(getenv("LOG_FILE"))
inclusion_start_block = to_int("INCLUSION_START_BLOCK")
final_block_number = to_int("FINAL_BLOCK_NUMBER")
payload_by_block = {}
verify_by_block = {}
consensus_by_block = {}
prepare_stage_lines = {
    "context": [],
    "commitment": [],
    "aggregation": [],
    "artifacts": [],
    "attached": [],
    "failed": [],
}
if log_path.exists():
    for line in log_path.read_text().splitlines():
        if "block_payload_size_metrics" in line:
            data = parse_kv_line(line)
            block_number = data.get("block_number")
            if block_number is not None:
                payload_by_block[int(block_number)] = data
        elif "block_import_verify_time_ms" in line:
            data = parse_kv_line(line)
            block_number = data.get("block_number")
            if block_number is not None:
                verify_by_block[int(block_number)] = data
        elif "block_proof_verification_metrics" in line:
            data = parse_kv_line(line)
            tx_count = data.get("tx_count")
            if tx_count is not None:
                consensus_by_block[len(consensus_by_block) + 1] = data
        elif "prepare_block_proof_bundle: built shared candidate context" in line:
            prepare_stage_lines["context"].append(parse_kv_line(line))
        elif "prepare_block_proof_bundle: commitment stage complete" in line:
            prepare_stage_lines["commitment"].append(parse_kv_line(line))
        elif "prepare_block_proof_bundle: aggregation stage complete" in line:
            prepare_stage_lines["aggregation"].append(parse_kv_line(line))
        elif "prepare_block_proof_bundle: built commitment and bundle proof artifacts" in line:
            prepare_stage_lines["artifacts"].append(parse_kv_line(line))
        elif "Proven batch extrinsic attached" in line:
            prepare_stage_lines["attached"].append(parse_kv_line(line))
        elif "failed to build DA blob for proven batch" in line or "Missing prepared proven batch for mandatory proofless sidecar set" in line:
            prepare_stage_lines["failed"].append({"line": line})

block_progression = []
if inclusion_start_block is not None and final_block_number is not None:
    consensus_items = list(consensus_by_block.values())
    for offset, block_number in enumerate(range(inclusion_start_block + 1, final_block_number + 1)):
        payload = payload_by_block.get(block_number, {})
        verify = verify_by_block.get(block_number, {})
        consensus = consensus_items[offset] if offset < len(consensus_items) else {}
        block_progression.append(
            {
                "block_number": block_number,
                "tx_count": int(payload.get("tx_count", "0")),
                "proven_batch_present": parse_bool(payload.get("proven_batch_present")),
                "proven_batch_bytes": int(payload.get("proven_batch_bytes", "0")),
                "commitment_proof_bytes": int(payload.get("commitment_proof_bytes", "0")),
                "aggregation_proof_bytes": int(payload.get("aggregation_proof_bytes", "0")),
                "verify_ms": int(verify.get("verify_ms", "0")),
                "tx_verify_ms": int(consensus.get("tx_verify_ms", "0")),
                "commitment_verify_ms": int(consensus.get("commitment_verify_ms", "0")),
                "aggregation_verify_ms": int(consensus.get("aggregation_verify_ms", "0")),
                "total_verify_ms": int(consensus.get("total_verify_ms", "0")),
            }
        )

def latest_stage_value(name, key):
    entries = prepare_stage_lines[name]
    if not entries:
        return None
    filtered = entries
    if metric_block_number is not None:
        filtered = [
            entry for entry in filtered
            if int(entry.get("block_number", "-1")) == metric_block_number
        ]
    if metric_tx_count is not None and filtered:
        exact_tx = [
            entry for entry in filtered
            if int(entry.get("tx_count", entry.get("key_tx_count", "-1"))) == metric_tx_count
        ]
        if exact_tx:
            filtered = exact_tx
    target = filtered if filtered else entries
    value = target[-1].get(key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return value

payload = {
    "run_id": getenv("RUN_ID"),
    "mode": mode,
    "timestamp_utc": getenv("RUN_TIMESTAMP_UTC"),
    "git_commit": getenv("GIT_COMMIT"),
    "genesis_hash": getenv("GENESIS_HASH"),
    "network": {
        "seeds": getenv("TP_SEEDS"),
        "max_peers": to_int("TP_MAX_PEERS"),
    },
    "config": {
        "proof_mode": getenv("PROOF_MODE"),
        "send_da_sidecar": to_int("SEND_DA_SIDECAR"),
        "strict_aggregation": to_int("STRICT_AGGREGATION"),
        "tx_count_requested": to_int("TX_COUNT"),
        "workers": to_int("WORKERS"),
        "prover_workers": to_int("PROVER_WORKERS"),
        "profile": getenv("TP_PROFILE"),
        "target_txs": to_int("TX_COUNT"),
        "batch_queue_capacity": to_int("BATCH_QUEUE_CAPACITY"),
    },
    "timings_ms": {
        "send_total_ms": to_int("SEND_TOTAL_MS"),
        "inclusion_total_ms": to_int("INCLUSION_TOTAL_MS"),
        "round_total_ms": to_int("ROUND_TOTAL_MS"),
        "strict_wait_ms": to_int("STRICT_WAIT_MS"),
        "context_stage_ms": to_int("CONTEXT_STAGE_MS"),
        "commitment_stage_ms": to_int("COMMITMENT_STAGE_MS"),
        "aggregation_stage_ms": to_int("AGGREGATION_STAGE_MS"),
    },
    "metrics": {
        "included_tx_count": to_int("INCLUDED_TX_COUNT"),
        "submission_tps": to_float("SUBMISSION_TPS"),
        "inclusion_tps": to_float("INCLUSION_TPS"),
        "end_to_end_tps": to_float("END_TO_END_TPS"),
        "effective_tps": to_float("EFFECTIVE_TPS"),
        "payload_bytes_per_tx": to_float("PAYLOAD_BYTES_PER_TX"),
        "tx_proof_bytes_total": to_int("TX_PROOF_BYTES_TOTAL"),
        "proven_batch_bytes_total": to_int("PROVEN_BATCH_BYTES_TOTAL"),
        "queue_depth": to_int("QUEUE_DEPTH"),
        "queue_wait_ms": to_int("QUEUE_WAIT_MS"),
        "dispatch_wait_ms": to_int("DISPATCH_WAIT_MS"),
        "total_job_age_ms": to_int("TOTAL_JOB_AGE_MS"),
        "cache_hit": getenv("CACHE_HIT"),
        "cache_build_ms": to_int("CACHE_BUILD_MS"),
        "import_verify_total_ms": sum(item["verify_ms"] for item in block_progression),
        "consensus_verify_total_ms": sum(item["total_verify_ms"] for item in block_progression),
        "commitment_verify_total_ms": sum(item["commitment_verify_ms"] for item in block_progression),
        "tx_verify_total_ms": sum(item["tx_verify_ms"] for item in block_progression),
    },
    "proof_ready": {
        "send_trace_file": str(send_trace_path),
        "per_tx": send_trace,
        "stats": send_stats,
    },
    "mempool": {
        "ready_pending_extrinsics_before_mining": to_int("READY_PENDING_COUNT_BEFORE_MINING"),
        "ready_pending_extrinsics_after_inclusion": to_int("READY_PENDING_COUNT_AFTER_INCLUSION"),
    },
    "prepared": {
        "bundles_before_mining": to_int("PREPARED_BUNDLES_BEFORE_MINING"),
        "bundles_after_inclusion": to_int("PREPARED_BUNDLES_AFTER_INCLUSION"),
    },
    "blocks": {
        "inclusion_start_block": inclusion_start_block,
        "final_block_number": final_block_number,
        "progression": block_progression,
        "count_until_full_inclusion": len(block_progression),
        "proven_batch_blocks": sum(1 for item in block_progression if item["proven_batch_present"]),
        "missed_target_block": len(block_progression) > 1,
    },
    "prepare": {
        "context_stage_ms": latest_stage_value("context", "stage_ms"),
        "commitment_stage_ms": latest_stage_value("commitment", "commitment_stage_ms"),
        "aggregation_stage_ms": latest_stage_value("aggregation", "aggregation_stage_ms"),
        "bundle_total_ms": latest_stage_value("artifacts", "total_ms"),
        "prepared_bundle_build_ms": latest_stage_value("attached", "proven_batch_build_ms"),
        "artifact_failures": prepare_stage_lines["failed"][-5:],
    },
}

with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
print(f"metrics_artifact_path={path}", file=sys.stderr)
PY
}

cd "$ROOT_DIR"

GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
RUN_TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GENESIS_HASH=""

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

RPC_LISTENER_PIDS="$(find_rpc_listener_pids)"
if [ -n "$RPC_LISTENER_PIDS" ]; then
  echo "RPC port ${RPC_PORT} is already in use by:" >&2
  # shellcheck disable=SC2086
  print_pid_commands $RPC_LISTENER_PIDS >&2
  if [ "${HEGEMON_TP_FORCE:-0}" = "1" ]; then
    echo "HEGEMON_TP_FORCE=1 set; terminating existing RPC listeners on port ${RPC_PORT}." >&2
    for pid in $RPC_LISTENER_PIDS; do
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    RPC_LISTENER_PIDS="$(find_rpc_listener_pids)"
    if [ -n "$RPC_LISTENER_PIDS" ]; then
      echo "Failed to free RPC port ${RPC_PORT}; still in use by:" >&2
      # shellcheck disable=SC2086
      print_pid_commands $RPC_LISTENER_PIDS >&2
      exit 1
    fi
  else
    echo "Stop the existing node or rerun with HEGEMON_TP_FORCE=1." >&2
    exit 1
  fi
fi

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
  echo "HEGEMON_TP_WORKERS must be a positive integer (got '$WORKERS')." >&2
  exit 1
fi
if ! [[ "$PROVER_WORKERS" =~ ^[0-9]+$ ]]; then
  echo "HEGEMON_TP_PROVER_WORKERS must be an integer >= 0 (got '$PROVER_WORKERS')." >&2
  exit 1
fi
if [ -n "$PROVER_BATCH_JOB_TIMEOUT_MS" ] && { ! [[ "$PROVER_BATCH_JOB_TIMEOUT_MS" =~ ^[0-9]+$ ]] || [ "$PROVER_BATCH_JOB_TIMEOUT_MS" -lt 1 ]; }; then
  echo "HEGEMON_TP_BATCH_JOB_TIMEOUT_MS must be a positive integer (got '$PROVER_BATCH_JOB_TIMEOUT_MS')." >&2
  exit 1
fi
if [ -n "$PROVER_WORK_PACKAGE_TTL_MS" ] && { ! [[ "$PROVER_WORK_PACKAGE_TTL_MS" =~ ^[0-9]+$ ]] || [ "$PROVER_WORK_PACKAGE_TTL_MS" -lt 1 ]; }; then
  echo "HEGEMON_TP_WORK_PACKAGE_TTL_MS must be a positive integer (got '$PROVER_WORK_PACKAGE_TTL_MS')." >&2
  exit 1
fi
if [ -n "$ADAPTIVE_LIVENESS_MS" ] && ! [[ "$ADAPTIVE_LIVENESS_MS" =~ ^[0-9]+$ ]]; then
  echo "HEGEMON_TP_ADAPTIVE_LIVENESS_MS must be an integer >= 0 (got '$ADAPTIVE_LIVENESS_MS')." >&2
  exit 1
fi
if [ "$WORKERS" -gt "$TX_COUNT" ]; then
  WORKERS="$TX_COUNT"
fi
if ! [[ "$WALLET_RPC_REQUEST_TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [ "$WALLET_RPC_REQUEST_TIMEOUT_SECS" -lt 1 ]; then
  echo "HEGEMON_TP_WALLET_RPC_REQUEST_TIMEOUT_SECS must be a positive integer (got '$WALLET_RPC_REQUEST_TIMEOUT_SECS')." >&2
  exit 1
fi
if ! [[ "$SEND_RETRIES" =~ ^[0-9]+$ ]] || [ "$SEND_RETRIES" -lt 1 ]; then
  echo "HEGEMON_TP_SEND_RETRIES must be a positive integer (got '$SEND_RETRIES')." >&2
  exit 1
fi
if ! [[ "$SEND_RETRY_DELAY_SECS" =~ ^[0-9]+$ ]] || [ "$SEND_RETRY_DELAY_SECS" -lt 1 ]; then
  echo "HEGEMON_TP_SEND_RETRY_DELAY_SECS must be a positive integer (got '$SEND_RETRY_DELAY_SECS')." >&2
  exit 1
fi
if ! [[ "$WALLET_RAYON_THREADS" =~ ^[0-9]+$ ]]; then
  echo "HEGEMON_TP_WALLET_RAYON_THREADS must be an integer (got '$WALLET_RAYON_THREADS')." >&2
  exit 1
fi
if [ "$WALLET_RAYON_THREADS" -le 0 ]; then
  # Default wallet proving threads: split host CPU between sender workers and local node prover workers.
  local_prover_workers="$PROVER_WORKERS"
  if [ "$local_prover_workers" -lt 1 ]; then
    local_prover_workers=1
  fi
  denom=$((WORKERS + local_prover_workers))
  if [ "$denom" -lt 1 ]; then
    denom=1
  fi
  WALLET_RAYON_THREADS=$((HOST_THREADS / denom))
  if [ "$WALLET_RAYON_THREADS" -lt 1 ]; then
    WALLET_RAYON_THREADS=1
  fi
fi
echo "Wallet send config: workers=$WORKERS wallet_rayon=$WALLET_RAYON_THREADS wallet_rpc_timeout_s=$WALLET_RPC_REQUEST_TIMEOUT_SECS send_retries=$SEND_RETRIES" >&2

if [ "$SKIP_BUILD" = "1" ]; then
  if [ ! -x ./target/release/hegemon-node ]; then
    echo "HEGEMON_TP_SKIP_BUILD=1 requires ./target/release/hegemon-node to exist." >&2
    exit 1
  fi
  if [ ! -x ./target/release/wallet ]; then
    echo "HEGEMON_TP_SKIP_BUILD=1 requires ./target/release/wallet to exist." >&2
    exit 1
  fi
else
  if [ "$FAST" = "1" ]; then
    echo "Building node (fast proofs enabled)..." >&2
    make node-fast
  else
    if [ ! -x ./target/release/hegemon-node ]; then
      echo "Building node..." >&2
      make node
    fi
  fi

  echo "Building wallet..." >&2
  cargo build --release -p wallet
fi

WALLET_SEND_SUPPORTS_NO_SYNC=0
if ./target/release/wallet substrate-send --help 2>&1 | grep -q -- "--no-sync"; then
  WALLET_SEND_SUPPORTS_NO_SYNC=1
fi
echo "Wallet substrate-send --no-sync support: $WALLET_SEND_SUPPORTS_NO_SYNC" >&2

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

if [ "$REUSE_EXISTING_STATE" != "1" ]; then
  existing_stores=()
  for store in "$WALLET_A" "$WALLET_B" "${WORKER_STORES[@]-}"; do
    if [ -n "$store" ] && [ -e "$store" ]; then
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
    rm -rf "$WALLET_A" "$WALLET_B" "${WORKER_STORES[@]-}"
  fi

  echo "Initializing wallets..." >&2
  ./target/release/wallet init --store "$WALLET_A" --passphrase "$PASS_A"
  ./target/release/wallet init --store "$WALLET_B" --passphrase "$PASS_B"

  if [ "$WORKERS" -gt 1 ]; then
    for i in "${!WORKER_STORES[@]}"; do
      ./target/release/wallet init --store "${WORKER_STORES[$i]}" --passphrase "${WORKER_PASSES[$i]}"
    done
  fi
else
  for store in "$WALLET_A" "$WALLET_B" "${WORKER_STORES[@]-}"; do
    if [ -n "$store" ] && [ ! -e "$store" ]; then
      echo "HEGEMON_TP_REUSE_EXISTING_STATE=1 requires existing wallet store path: $store" >&2
      exit 1
    fi
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
NODE_STRICT_ENV=""
if [ "$STRICT_AGGREGATION" = "1" ] && [ "$AGGREGATION_PROOFS_ENABLED" = "1" ]; then
  NODE_STRICT_ENV="HEGEMON_DISABLE_PROOFLESS_HYDRATION=1"
fi
NODE_ADAPTIVE_LIVENESS_ENV=""
if [ -n "$ADAPTIVE_LIVENESS_MS" ]; then
  NODE_ADAPTIVE_LIVENESS_ENV="HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS=${ADAPTIVE_LIVENESS_MS}"
fi
NODE_MINE_ENV="HEGEMON_MINE=1"
NODE_PREWARM_BLOCKING_ENV=""
NODE_PREWARM_MAX_TXS_ENV=""
AGG_LEAF_FANIN="${HEGEMON_TP_AGG_LEAF_FANIN:-4}"
if ! [[ "$AGG_LEAF_FANIN" =~ ^[0-9]+$ ]] || [ "$AGG_LEAF_FANIN" -lt 1 ]; then
  echo "HEGEMON_TP_AGG_LEAF_FANIN must be a positive integer (got '$AGG_LEAF_FANIN')." >&2
  exit 1
fi
AGG_MERGE_FANIN="${HEGEMON_TP_AGG_MERGE_FANIN:-8}"
AGG_MERGE_FANIN_EXPLICIT=0
if [ -n "${HEGEMON_TP_AGG_MERGE_FANIN:-}" ]; then
  AGG_MERGE_FANIN_EXPLICIT=1
fi
if ! [[ "$AGG_MERGE_FANIN" =~ ^[0-9]+$ ]] || [ "$AGG_MERGE_FANIN" -lt 1 ]; then
  echo "HEGEMON_TP_AGG_MERGE_FANIN must be a positive integer (got '$AGG_MERGE_FANIN')." >&2
  exit 1
fi
if [ "$PROOF_MODE" = "aggregation" ]; then
  current_recursive_capacity=$((AGG_LEAF_FANIN * AGG_MERGE_FANIN))
  if [ "$TX_COUNT" -gt "$current_recursive_capacity" ]; then
    required_merge_fanin=$(((TX_COUNT + AGG_LEAF_FANIN - 1) / AGG_LEAF_FANIN))
    if [ "$AGG_MERGE_FANIN_EXPLICIT" = "1" ]; then
      echo "TX_COUNT=${TX_COUNT} exceeds recursive capacity ${current_recursive_capacity} for leaf_fanin=${AGG_LEAF_FANIN}, merge_fanin=${AGG_MERGE_FANIN}." >&2
      echo "Set HEGEMON_TP_AGG_MERGE_FANIN >= ${required_merge_fanin} or lower HEGEMON_TP_TX_COUNT." >&2
      exit 1
    fi
    AGG_MERGE_FANIN="$required_merge_fanin"
  fi
fi
TX_RECURSION_NUM_QUERIES="${HEGEMON_TP_TX_RECURSION_NUM_QUERIES:-2}"
if ! [[ "$TX_RECURSION_NUM_QUERIES" =~ ^[0-9]+$ ]] || [ "$TX_RECURSION_NUM_QUERIES" -lt 1 ]; then
  echo "HEGEMON_TP_TX_RECURSION_NUM_QUERIES must be a positive integer (got '$TX_RECURSION_NUM_QUERIES')." >&2
  exit 1
fi
TX_RECURSION_LOG_BLOWUP="${HEGEMON_TP_TX_RECURSION_LOG_BLOWUP:-2}"
if ! [[ "$TX_RECURSION_LOG_BLOWUP" =~ ^[0-9]+$ ]] || [ "$TX_RECURSION_LOG_BLOWUP" -lt 1 ]; then
  echo "HEGEMON_TP_TX_RECURSION_LOG_BLOWUP must be a positive integer (got '$TX_RECURSION_LOG_BLOWUP')." >&2
  exit 1
fi
AGG_OUTER_NUM_QUERIES="${HEGEMON_TP_AGG_OUTER_NUM_QUERIES:-2}"
if ! [[ "$AGG_OUTER_NUM_QUERIES" =~ ^[0-9]+$ ]] || [ "$AGG_OUTER_NUM_QUERIES" -lt 1 ]; then
  echo "HEGEMON_TP_AGG_OUTER_NUM_QUERIES must be a positive integer (got '$AGG_OUTER_NUM_QUERIES')." >&2
  exit 1
fi
AGG_OUTER_LOG_BLOWUP="${HEGEMON_TP_AGG_OUTER_LOG_BLOWUP:-2}"
if ! [[ "$AGG_OUTER_LOG_BLOWUP" =~ ^[0-9]+$ ]] || [ "$AGG_OUTER_LOG_BLOWUP" -lt 1 ]; then
  echo "HEGEMON_TP_AGG_OUTER_LOG_BLOWUP must be a positive integer (got '$AGG_OUTER_LOG_BLOWUP')." >&2
  exit 1
fi
if [ "$PREWARM_ONLY" = "1" ] && [ "$PROOF_MODE" = "aggregation" ]; then
  NODE_PREWARM_BLOCKING_ENV="HEGEMON_AGG_PREWARM_BLOCKING=1"
elif [ -n "$AGG_PREWARM_MAX_TXS" ] && [ "$AGG_PREWARM_MAX_TXS" -gt "$AGG_LEAF_FANIN" ]; then
  NODE_PREWARM_BLOCKING_ENV="HEGEMON_AGG_PREWARM_BLOCKING=1"
fi
if [ -n "$AGG_PREWARM_MAX_TXS" ]; then
  NODE_PREWARM_MAX_TXS_ENV="HEGEMON_AGG_PREWARM_MAX_TXS=${AGG_PREWARM_MAX_TXS}"
fi
AGG_LEAF_JOBS=0
if [ "$PROOF_MODE" = "aggregation" ]; then
  AGG_LEAF_JOBS="$(aggregation_leaf_job_count "$TX_COUNT" "$AGG_LEAF_FANIN")"
  if [ "$PROVER_WORKERS" -gt "$AGG_LEAF_JOBS" ]; then
    echo "Capping local aggregation prover workers from ${PROVER_WORKERS} to ${AGG_LEAF_JOBS} to match first-level leaf jobs." >&2
    PROVER_WORKERS="$AGG_LEAF_JOBS"
  fi
fi
if [ "$AGG_PREPARE_THREADS_AUTO" = "1" ]; then
  if [ "$PROVER_WORKERS" -gt "$NODE_RAYON_THREADS" ]; then
    AGG_PREPARE_THREADS="$PROVER_WORKERS"
  else
    AGG_PREPARE_THREADS="$NODE_RAYON_THREADS"
  fi
fi
if [ -z "$PROVER_BATCH_JOB_TIMEOUT_MS" ]; then
  if [ "$PROOF_MODE" = "aggregation" ]; then
    PROVER_BATCH_JOB_TIMEOUT_MS="$(derive_aggregation_prepare_budget_ms "$TX_COUNT" "$AGG_LEAF_FANIN" "$AGG_MERGE_FANIN" "$PROVER_WORKERS")"
  elif [ "$STRICT_AGGREGATION" = "1" ]; then
    PROVER_BATCH_JOB_TIMEOUT_MS=900000
  else
    PROVER_BATCH_JOB_TIMEOUT_MS=180000
  fi
fi
if [ -z "$PROVER_WORK_PACKAGE_TTL_MS" ]; then
  PROVER_WORK_PACKAGE_TTL_MS="$PROVER_BATCH_JOB_TIMEOUT_MS"
fi
if [ -z "$STRICT_PREPARE_TIMEOUT_SECS" ]; then
  STRICT_PREPARE_TIMEOUT_SECS="$(ceil_div "$PROVER_BATCH_JOB_TIMEOUT_MS" 1000)"
fi

echo "Throughput profile: $TP_PROFILE (host_threads=$HOST_THREADS host_mem_gib=$HOST_MEM_GIB)" >&2
echo "Thread config: node_rayon=$NODE_RAYON_THREADS cargo_jobs=$CARGO_JOBS mine_threads=$MINE_THREADS agg_prepare_threads=$AGG_PREPARE_THREADS agg_prover_threads=$AGG_PROVER_THREADS" >&2
echo "Batch config: target_txs=$TX_COUNT min_prepared_txs=$MIN_PREPARED_TXS min_ready_batch_txs=$MIN_READY_BATCH_TXS liveness_lane=$PROVER_LIVENESS_LANE queue_capacity=$BATCH_QUEUE_CAPACITY adaptive_liveness_ms=${ADAPTIVE_LIVENESS_MS:-default}" >&2
echo "Aggregation recursion config: leaf_fanin=$AGG_LEAF_FANIN merge_fanin=$AGG_MERGE_FANIN tx_recursion_queries=$TX_RECURSION_NUM_QUERIES tx_recursion_log_blowup=$TX_RECURSION_LOG_BLOWUP outer_queries=$AGG_OUTER_NUM_QUERIES outer_log_blowup=$AGG_OUTER_LOG_BLOWUP prover_workers=$PROVER_WORKERS" >&2
echo "Shielded block limit: block_shielded_transfer_limit=$BLOCK_SHIELDED_TRANSFER_LIMIT (includes coinbase when shielded mining is enabled)" >&2
echo "Aggregation packing config: witness_lanes=${AGG_WITNESS_LANES:-default} add_lanes=${AGG_ADD_LANES:-default} mul_lanes=${AGG_MUL_LANES:-default}" >&2
echo "Aggregation prewarm config: include_merge=${AGG_PREWARM_INCLUDE_MERGE:-default} max_txs=${AGG_PREWARM_MAX_TXS:-default(target_txs)}" >&2
echo "Aggregation timeout budget: strict_prepare_timeout_secs=$STRICT_PREPARE_TIMEOUT_SECS batch_job_timeout_ms=$PROVER_BATCH_JOB_TIMEOUT_MS work_package_ttl_ms=$PROVER_WORK_PACKAGE_TTL_MS leaf_jobs=${AGG_LEAF_JOBS:-0}" >&2
if [ -n "$NODE_PREWARM_BLOCKING_ENV" ]; then
  echo "Aggregation cache startup: worker_prewarm_blocking=1" >&2
fi
echo "Network config: seeds='${TP_SEEDS}' max_peers=${TP_MAX_PEERS}" >&2
echo "Mode flags: proof_mode=${PROOF_MODE} aggregation_enabled=${AGGREGATION_PROOFS_ENABLED} send_proof_sidecar=${SEND_PROOF_SIDECAR} send_da_sidecar=${SEND_DA_SIDECAR} send_no_sync=${SEND_NO_SYNC_DEFAULT} inclusion_target_mode=${INCLUSION_TARGET_MODE} prewarm_only=${PREWARM_ONLY} incremental_upsize=${BATCH_INCREMENTAL_UPSIZE}" >&2
echo "Artifacts: run_id=${RUN_ID} json=${ARTIFACT_JSON}" >&2

mkdir -p "$ARTIFACTS_DIR"
: > "$SEND_TRACE_FILE"

wallet_sync() {
  local store="$1"
  local passphrase="$2"
  env \
    HEGEMON_WALLET_RPC_REQUEST_TIMEOUT_SECS="$WALLET_RPC_REQUEST_TIMEOUT_SECS" \
    RAYON_NUM_THREADS="$WALLET_RAYON_THREADS" \
    HEGEMON_RAYON_THREADS="$WALLET_RAYON_THREADS" \
    $WALLET_FAST_ENV \
    ./target/release/wallet substrate-sync \
      --store "$store" --passphrase "$passphrase" \
      --ws-url "$RPC_WS" --force-rescan
}

wallet_send_once() {
  local store="$1"
  local passphrase="$2"
  local recipients_json="$3"
  local no_sync="${4:-0}"
  local proof_sidecar="${5:-1}"
  local maybe_no_sync=""
  if [ "$no_sync" = "1" ] && [ "$WALLET_SEND_SUPPORTS_NO_SYNC" = "1" ]; then
    maybe_no_sync="--no-sync"
  fi
  env \
    HEGEMON_WALLET_DA_SIDECAR="$SEND_DA_SIDECAR" \
    HEGEMON_WALLET_PROOF_SIDECAR="$proof_sidecar" \
    HEGEMON_TX_RECURSION_NUM_QUERIES="$TX_RECURSION_NUM_QUERIES" \
    HEGEMON_TX_RECURSION_LOG_BLOWUP="$TX_RECURSION_LOG_BLOWUP" \
    HEGEMON_WALLET_RPC_REQUEST_TIMEOUT_SECS="$WALLET_RPC_REQUEST_TIMEOUT_SECS" \
    RAYON_NUM_THREADS="$WALLET_RAYON_THREADS" \
    HEGEMON_RAYON_THREADS="$WALLET_RAYON_THREADS" \
    $WALLET_FAST_ENV \
    ./target/release/wallet substrate-send \
      --store "$store" --passphrase "$passphrase" \
      --recipients "$recipients_json" \
      --ws-url "$RPC_WS" \
      --fee "$FEE" \
      $maybe_no_sync >/dev/null
}

wallet_send_with_metrics() {
  local store="$1"
  local passphrase="$2"
  local recipients_json="$3"
  local no_sync="${4:-0}"
  local proof_sidecar="${5:-$SEND_PROOF_SIDECAR}"
  local worker_id="$6"
  local tx_ordinal="$7"
  local start_ms
  local end_ms
  local start_block
  local end_block

  start_ms="$(now_ms)"
  start_block="$(current_block_number)"
  wallet_send_with_retry "$store" "$passphrase" "$recipients_json" "$no_sync" "$proof_sidecar"
  end_ms="$(now_ms)"
  end_block="$(current_block_number)"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$worker_id" "$tx_ordinal" "$start_ms" "$end_ms" "$((end_ms - start_ms))" "$start_block" "$end_block" \
    >> "$SEND_TRACE_FILE"
}

wallet_send_with_retry() {
  local store="$1"
  local passphrase="$2"
  local recipients_json="$3"
  local no_sync="${4:-0}"
  local proof_sidecar="${5:-$SEND_PROOF_SIDECAR}"
  local attempt=1
  while true; do
    local output
    if output="$(wallet_send_once "$store" "$passphrase" "$recipients_json" "$no_sync" "$proof_sidecar" 2>&1)"; then
      return 0
    fi

    if [ "$attempt" -lt "$SEND_RETRIES" ] && grep -qiE "request timeout|connection closed|transport error" <<<"$output"; then
      echo "    wallet send transient failure (attempt ${attempt}/${SEND_RETRIES}); retrying in ${SEND_RETRY_DELAY_SECS}s..." >&2
      sleep "$SEND_RETRY_DELAY_SECS"
      attempt=$((attempt + 1))
      continue
    fi

    echo "$output" >&2
    return 1
  done
}

echo "Starting node in tmux session '$SESSION' (logs: $LOG_FILE)..." >&2
tmux new-session -d -s "$SESSION" -n node \
  "cd '$ROOT_DIR' && \
   env \
     RUST_LOG=info \
     RAYON_NUM_THREADS='${NODE_RAYON_THREADS}' \
     HEGEMON_RAYON_THREADS='${NODE_RAYON_THREADS}' \
     $NODE_FAST_ENV \
     $NODE_STRICT_ENV \
     HEGEMON_SEEDS='${TP_SEEDS}' \
     HEGEMON_MAX_PEERS='${TP_MAX_PEERS}' \
     $NODE_MINE_ENV \
     HEGEMON_MINE_THREADS='${MINE_THREADS}' \
     HEGEMON_PROVER_WORKERS='${PROVER_WORKERS}' \
     HEGEMON_PROVER_LIVENESS_LANE='${PROVER_LIVENESS_LANE}' \
     $NODE_ADAPTIVE_LIVENESS_ENV \
     $NODE_PREWARM_BLOCKING_ENV \
     HEGEMON_BATCH_QUEUE_CAPACITY='${BATCH_QUEUE_CAPACITY}' \
     HEGEMON_BATCH_INCREMENTAL_UPSIZE='${BATCH_INCREMENTAL_UPSIZE}' \
     HEGEMON_BATCH_TARGET_TXS='${TX_COUNT}' \
     HEGEMON_BATCH_JOB_TIMEOUT_MS='${PROVER_BATCH_JOB_TIMEOUT_MS}' \
     HEGEMON_PROVER_WORK_PACKAGE_TTL_MS='${PROVER_WORK_PACKAGE_TTL_MS}' \
     HEGEMON_MIN_READY_PROVEN_BATCH_TXS='${MIN_READY_BATCH_TXS}' \
     HEGEMON_MINE_TEST=1 \
     HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
     HEGEMON_AGGREGATION_PROOFS='${AGGREGATION_PROOFS_ENABLED}' \
     HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
     HEGEMON_FULL_IMPORT=1 \
     HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK='${BLOCK_SHIELDED_TRANSFER_LIMIT}' \
     HEGEMON_AGG_PROFILE='${AGG_PROFILE}' \
     HEGEMON_AGG_LEAF_FANIN='${AGG_LEAF_FANIN}' \
     HEGEMON_AGG_MERGE_FANIN='${AGG_MERGE_FANIN}' \
     HEGEMON_TX_RECURSION_NUM_QUERIES='${TX_RECURSION_NUM_QUERIES}' \
     HEGEMON_TX_RECURSION_LOG_BLOWUP='${TX_RECURSION_LOG_BLOWUP}' \
     HEGEMON_AGG_OUTER_NUM_QUERIES='${AGG_OUTER_NUM_QUERIES}' \
     HEGEMON_AGG_OUTER_LOG_BLOWUP='${AGG_OUTER_LOG_BLOWUP}' \
     HEGEMON_AGG_WITNESS_LANES='${AGG_WITNESS_LANES}' \
     HEGEMON_AGG_ADD_LANES='${AGG_ADD_LANES}' \
     HEGEMON_AGG_MUL_LANES='${AGG_MUL_LANES}' \
     HEGEMON_AGG_PREWARM_INCLUDE_MERGE='${AGG_PREWARM_INCLUDE_MERGE}' \
     HEGEMON_AGG_PREPARE_THREADS='${AGG_PREPARE_THREADS}' \
     HEGEMON_AGG_PROVER_THREADS='${AGG_PROVER_THREADS}' \
     HEGEMON_AGG_STAGE_LOCAL_PARALLELISM='${PROVER_WORKERS}' \
     $NODE_PREWARM_MAX_TXS_ENV \
     HEGEMON_MINER_ADDRESS='$MINER_ADDRESS' \
     ./target/release/hegemon-node ${NODE_CHAIN_ARGS} --rpc-port '${RPC_PORT}' 2>&1 | tee '$LOG_FILE'"

echo "Waiting for RPC to respond..." >&2
for i in $(seq 1 "$RPC_WAIT_SECS"); do
  if curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    "$RPC_HTTP" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq "$RPC_WAIT_SECS" ]; then
    echo "RPC did not respond after ${RPC_WAIT_SECS}s; check logs: $LOG_FILE" >&2
    exit 1
  fi
done

GENESIS_HASH="$(
  curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getBlockHash","params":[0],"id":1}' \
    "$RPC_HTTP" \
    | python3 -c 'import json,sys; data=sys.stdin.read().strip(); obj=json.loads(data) if data else {}; print((obj.get("result") or ""))'
)"

if [ "$REUSE_EXISTING_STATE" = "1" ]; then
  echo "Stopping mining immediately on reused funded state..." >&2
  curl -s -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
    "$RPC_HTTP" >/dev/null || true
  wait_for_tip_quiescence 30 3
fi

if [ "$REUSE_EXISTING_STATE" != "1" ]; then
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
  wait_for_tip_quiescence 30 3

  echo "Syncing miner wallet..." >&2
  wallet_sync "$WALLET_A" "$PASS_A"

  if [ "$WORKERS" -gt 1 ]; then
    echo "Funding worker wallets from miner..." >&2
    funding_sends=0
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
        # Funding must be mined deterministically before worker send loops begin.
        # Use inline proof bytes here (proof_sidecar=0) so strict aggregation mode
        # cannot defer these transfers as proofless sidecar calls.
        wallet_send_with_retry "$WALLET_A" "$PASS_A" "$fund_json" 0 0
        funding_sends=$((funding_sends + 1))

        # Confirm each funding send before issuing the next one so the miner wallet
        # never reuses a just-spent nullifier.
        before_funding_mine="$(current_block_number)"
        curl -s -H "Content-Type: application/json" \
          -d "{\"jsonrpc\":\"2.0\",\"method\":\"hegemon_startMining\",\"params\":[{\"threads\":${MINE_THREADS}}],\"id\":1}" \
          "$RPC_HTTP" >/dev/null
        funding_target=$((before_funding_mine + 1))
        current="$before_funding_mine"
        for k in $(seq 1 "$MAX_BLOCK_WAIT_SECS"); do
          current="$(current_block_number)"
          if [ "$current" -ge "$funding_target" ]; then
            break
          fi
          sleep 1
        done
        if [ "$current" -lt "$funding_target" ]; then
          echo "Timed out while confirming worker funding transfer (target block ${funding_target}, got ${current})." >&2
          exit 1
        fi
        curl -s -H "Content-Type: application/json" \
          -d '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[],"id":1}' \
          "$RPC_HTTP" >/dev/null
        wait_for_tip_quiescence 30 3

        wallet_sync "$WALLET_A" "$PASS_A" >/dev/null
      done
    done

    echo "Completed worker funding sends: ${funding_sends}" >&2

    echo "Syncing worker wallets..." >&2
    for i in "${!WORKER_STORES[@]}"; do
      wallet_sync "${WORKER_STORES[$i]}" "${WORKER_PASSES[$i]}" >/dev/null
    done
  fi
else
  echo "Reusing existing funded state; syncing wallets without bootstrap mining..." >&2
  wallet_sync "$WALLET_A" "$PASS_A" >/dev/null
  wallet_sync "$WALLET_B" "$PASS_B" >/dev/null
  if [ "$WORKERS" -gt 1 ]; then
    for i in "${!WORKER_STORES[@]}"; do
      wallet_sync "${WORKER_STORES[$i]}" "${WORKER_PASSES[$i]}" >/dev/null
    done
  fi
fi

if [ "$PREPARE_SNAPSHOT_ONLY" = "1" ]; then
  echo "Snapshot preparation complete; exiting before transfer submission." >&2
  exit 0
fi

echo "Submitting ${TX_COUNT} transfers (proof_mode=${PROOF_MODE}, proof_sidecar=${SEND_PROOF_SIDECAR})..." >&2
ROUND_START_MS="$(now_ms)"
SEND_START_MS="$ROUND_START_MS"
if [ "$WORKERS" -le 1 ]; then
  for i in $(seq 1 "$TX_COUNT"); do
    echo "  sending ${i}/${TX_COUNT}..." >&2
    wallet_send_with_metrics "$WALLET_A" "$PASS_A" "$RECIPIENTS_JSON" "$SEND_NO_SYNC_DEFAULT" "$SEND_PROOF_SIDECAR" 1 "$i"
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
    {
      for j in $(seq 1 "$worker_tx_count"); do
        echo "  worker ${worker_id} sending ${j}/${worker_tx_count}..." >&2
        wallet_send_with_metrics "$worker_store" "$worker_pass" "$RECIPIENTS_JSON" "$SEND_NO_SYNC_DEFAULT" "$SEND_PROOF_SIDECAR" "$worker_id" "$j"
      done
    } &
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
READY_PENDING_COUNT_BEFORE_MINING="$(author_pending_extrinsic_count)"
PREPARED_BUNDLES_BEFORE_MINING="$(prepared_bundle_count)"
STRICT_WAIT_MS=0
INCLUSION_TOTAL_MS=0
ROUND_TOTAL_MS=0
INCLUDED_TX_COUNT=0
TX_PROOF_BYTES_TOTAL=0
PROVEN_BATCH_BYTES_TOTAL=0
PAYLOAD_BYTES_PER_TX=0
SUBMISSION_TPS=0
INCLUSION_TPS=0
END_TO_END_TPS=0
EFFECTIVE_TPS=0
CONTEXT_STAGE_MS=0
COMMITMENT_STAGE_MS=0
AGGREGATION_STAGE_MS=0
QUEUE_DEPTH=0
QUEUE_WAIT_MS=0
DISPATCH_WAIT_MS=0
TOTAL_JOB_AGE_MS=0
CACHE_HIT=""
CACHE_BUILD_MS=0
METRIC_BLOCK_NUMBER=0
METRIC_TX_COUNT=0
READY_PENDING_COUNT_AFTER_INCLUSION=0
PREPARED_BUNDLES_AFTER_INCLUSION=0
FINAL_BLOCK_NUMBER=0

if [ "$STRICT_AGGREGATION" = "1" ]; then
  echo "Strict mode: waiting for local proven batch candidate before mining (min_prepared_txs=${MIN_PREPARED_TXS})..." >&2
  STRICT_WAIT_START_MS="$(now_ms)"
  PREPARED_LINE=""
  BEST_PREPARED_LINE=""
  BEST_PREPARED_TX_COUNT=0
  for i in $(seq 1 "$STRICT_PREPARE_TIMEOUT_SECS"); do
    LATEST_PREPARED_LINE="$(search_log "Prepared proven batch candidate" | tail -n 1 || true)"
    if [ -n "$LATEST_PREPARED_LINE" ]; then
      LATEST_PREPARED_TX_COUNT="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\btx_count=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LATEST_PREPARED_LINE")"
      if [ "$LATEST_PREPARED_TX_COUNT" -gt "$BEST_PREPARED_TX_COUNT" ]; then
        BEST_PREPARED_TX_COUNT="$LATEST_PREPARED_TX_COUNT"
        BEST_PREPARED_LINE="$LATEST_PREPARED_LINE"
      fi
      if [ "$LATEST_PREPARED_TX_COUNT" -ge "$MIN_PREPARED_TXS" ]; then
        PREPARED_LINE="$LATEST_PREPARED_LINE"
        break
      fi
    fi
    sleep 1
  done
  if [ -z "$PREPARED_LINE" ]; then
    if [ "$BEST_PREPARED_TX_COUNT" -gt 0 ]; then
      echo "Strict aggregation mode: timed out waiting for prepared batch >= ${MIN_PREPARED_TXS}; best_seen_tx_count=${BEST_PREPARED_TX_COUNT}." >&2
      echo "$BEST_PREPARED_LINE" >&2
    else
      echo "Strict aggregation mode: timed out waiting for local proven batch candidate." >&2
    fi
    echo "Inspect logs: $LOG_FILE" >&2
    exit 1
  fi
  echo "$PREPARED_LINE" >&2
  QUEUE_DEPTH="$(metric_from_line "$PREPARED_LINE" "queue_depth")"
  QUEUE_WAIT_MS="$(metric_from_line "$PREPARED_LINE" "queue_wait_ms")"
  DISPATCH_WAIT_MS="$(metric_from_line "$PREPARED_LINE" "dispatch_wait_ms")"
  TOTAL_JOB_AGE_MS="$(metric_from_line "$PREPARED_LINE" "total_job_age_ms")"
  STRICT_WAIT_END_MS="$(now_ms)"
  STRICT_WAIT_MS=$((STRICT_WAIT_END_MS - STRICT_WAIT_START_MS))
  echo "Prepared batch became ready in strict_wait_ms=${STRICT_WAIT_MS}" >&2
  if [ "$PREWARM_ONLY" = "1" ]; then
    CONTEXT_LINE="$(search_log "prepare_block_proof_bundle: built shared candidate context" | tail -n 1 || true)"
    STAGE_LINE="$(search_log "prepare_block_proof_bundle: built commitment and (aggregation proofs|bundle proof artifacts)" | tail -n 1 || true)"
    AGG_LINE="$(search_log "(prepare_block_proof_bundle: aggregation stage complete|prove_aggregation completed)" | tail -n 1 || true)"
    CONTEXT_STAGE_MS="$(metric_from_line "$CONTEXT_LINE" "stage_ms")"
    COMMITMENT_STAGE_MS="$(metric_from_line "$STAGE_LINE" "commitment_stage_ms")"
    AGGREGATION_STAGE_MS="$(metric_from_line "$STAGE_LINE" "aggregation_stage_ms")"
    CACHE_HIT="$(bool_metric_from_line "$AGG_LINE" "cache_hit")"
    CACHE_BUILD_MS="$(metric_from_line "$AGG_LINE" "cache_build_ms")"
    export RUN_ID RUN_TIMESTAMP_UTC GIT_COMMIT GENESIS_HASH TP_SEEDS TP_MAX_PEERS PROOF_MODE STRICT_AGGREGATION TX_COUNT WORKERS PROVER_WORKERS TP_PROFILE BATCH_QUEUE_CAPACITY SEND_TOTAL_MS INCLUSION_TOTAL_MS ROUND_TOTAL_MS STRICT_WAIT_MS CONTEXT_STAGE_MS COMMITMENT_STAGE_MS AGGREGATION_STAGE_MS INCLUDED_TX_COUNT SUBMISSION_TPS INCLUSION_TPS END_TO_END_TPS EFFECTIVE_TPS PAYLOAD_BYTES_PER_TX TX_PROOF_BYTES_TOTAL PROVEN_BATCH_BYTES_TOTAL QUEUE_DEPTH QUEUE_WAIT_MS DISPATCH_WAIT_MS TOTAL_JOB_AGE_MS CACHE_HIT CACHE_BUILD_MS SEND_DA_SIDECAR SEND_TRACE_FILE LOG_FILE READY_PENDING_COUNT_BEFORE_MINING READY_PENDING_COUNT_AFTER_INCLUSION PREPARED_BUNDLES_BEFORE_MINING PREPARED_BUNDLES_AFTER_INCLUSION INCLUSION_START_BLOCK FINAL_BLOCK_NUMBER
    emit_metrics_artifact "prewarm"
    echo "Prewarm-only mode: exiting before inclusion/mining stage." >&2
    echo "prewarm_metrics tx_count=${TX_COUNT} proof_mode=${PROOF_MODE} strict_wait_ms=${STRICT_WAIT_MS} min_prepared_txs=${MIN_PREPARED_TXS}" >&2
    echo "Done. Node is still running in tmux." >&2
    echo "  Attach: tmux attach -t $SESSION" >&2
    echo "  Logs:   $LOG_FILE" >&2
    echo "  Kill:   tmux kill-session -t $SESSION" >&2
    exit 0
  fi
fi

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
FOUND_TX_COUNT=0
FOUND_AT_MS="$INCLUSION_START_MS"
INCLUDED_TOTAL_TX=0
TOTAL_TX_PROOF_BYTES=0
TOTAL_PROVEN_BATCH_BYTES=0
LAST_SCANNED_BLOCK="$INCLUSION_START_BLOCK"
for i in $(seq 1 1200); do
  if [ "$INCLUSION_TARGET_MODE" = "single_block" ]; then
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
    LINE_TX_COUNT="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\btx_count=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
    if [ "$LINE_TX_COUNT" -gt "$FOUND_TX_COUNT" ]; then
      FOUND="$LINE"
      FOUND_BLOCK="$LINE_BLOCK"
      FOUND_TX_COUNT="$LINE_TX_COUNT"
      FOUND_AT_MS="$(now_ms)"
    fi
    if [ "$LINE_TX_COUNT" -ge "$TX_COUNT" ]; then
      INCLUDED_TOTAL_TX="$LINE_TX_COUNT"
      TOTAL_TX_PROOF_BYTES="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\btx_proof_bytes_total=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
      TOTAL_PROVEN_BATCH_BYTES="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\bproven_batch_bytes=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
      break
    fi
  else
    CURRENT_BLOCK="$(current_block_number)"
    if [ "$CURRENT_BLOCK" -le "$LAST_SCANNED_BLOCK" ]; then
      sleep 1
      continue
    fi
    for block in $(seq $((LAST_SCANNED_BLOCK + 1)) "$CURRENT_BLOCK"); do
      LINE="$(search_log "block_payload_size_metrics block_number=${block}" | tail -n 1 || true)"
      if [ -z "$LINE" ]; then
        continue
      fi
      LINE_TX_COUNT="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\btx_count=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
      LINE_TX_PROOF_BYTES="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\btx_proof_bytes_total=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
      LINE_PROVEN_BATCH_BYTES="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"\bproven_batch_bytes=(\d+)\b", s); print(m.group(1) if m else "0")' <<<"$LINE")"
      INCLUDED_TOTAL_TX=$((INCLUDED_TOTAL_TX + LINE_TX_COUNT))
      TOTAL_TX_PROOF_BYTES=$((TOTAL_TX_PROOF_BYTES + LINE_TX_PROOF_BYTES))
      TOTAL_PROVEN_BATCH_BYTES=$((TOTAL_PROVEN_BATCH_BYTES + LINE_PROVEN_BATCH_BYTES))
      if [ "$LINE_TX_COUNT" -gt "$FOUND_TX_COUNT" ]; then
        FOUND_TX_COUNT="$LINE_TX_COUNT"
      fi
      FOUND="$LINE"
      FOUND_BLOCK="$block"
      FOUND_AT_MS="$(now_ms)"
      if [ "$INCLUDED_TOTAL_TX" -ge "$TX_COUNT" ]; then
        break
      fi
    done
    LAST_SCANNED_BLOCK="$CURRENT_BLOCK"
    if [ "$INCLUDED_TOTAL_TX" -ge "$TX_COUNT" ]; then
      break
    fi
  fi
  sleep 1
done

if [ -z "$FOUND" ] || [ "$INCLUDED_TOTAL_TX" -le 0 ]; then
  echo "Timed out waiting for metrics; inspect logs: $LOG_FILE" >&2
  echo "Attach: tmux attach -t $SESSION" >&2
  exit 1
fi
ROUND_END_MS="$FOUND_AT_MS"
ROUND_TOTAL_MS=$((ROUND_END_MS - ROUND_START_MS))
INCLUSION_TOTAL_MS=$((ROUND_END_MS - INCLUSION_START_MS))
INCLUDED_TX_COUNT="$INCLUDED_TOTAL_TX"
TX_PROOF_BYTES_TOTAL="$TOTAL_TX_PROOF_BYTES"
PROVEN_BATCH_BYTES_TOTAL="$TOTAL_PROVEN_BATCH_BYTES"
PAYLOAD_BYTES_PER_TX="$(python3 - <<PY
tx_count = int("${INCLUDED_TX_COUNT}")
tx_proof_bytes = int("${TX_PROOF_BYTES_TOTAL}")
proven_batch_bytes = int("${PROVEN_BATCH_BYTES_TOTAL}")
total = tx_proof_bytes + proven_batch_bytes
print(f"{(total / tx_count):.2f}" if tx_count > 0 else "0.00")
PY
)"

SUBMISSION_TPS="$(python3 - <<PY
tx_count = int("${TX_COUNT}")
send_total_ms = int("${SEND_TOTAL_MS}")
print(f"{(tx_count / (send_total_ms / 1000.0)):.6f}" if send_total_ms > 0 else "0.000000")
PY
)"
INCLUSION_TPS="$(python3 - <<PY
tx_count = int("${INCLUDED_TX_COUNT}")
inclusion_total_ms = int("${INCLUSION_TOTAL_MS}")
print(f"{(tx_count / (inclusion_total_ms / 1000.0)):.6f}" if inclusion_total_ms > 0 else "0.000000")
PY
)"
END_TO_END_TPS="$(python3 - <<PY
tx_count = int("${INCLUDED_TX_COUNT}")
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
FINAL_BLOCK_NUMBER="$BLOCK_NUMBER"
METRIC_BLOCK_NUMBER="$BLOCK_NUMBER"
METRIC_TX_COUNT="$FOUND_TX_COUNT"
READY_PENDING_COUNT_AFTER_INCLUSION="$(author_pending_extrinsic_count)"
PREPARED_BUNDLES_AFTER_INCLUSION="$(prepared_bundle_count)"

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
echo "payload_cost_metrics included_tx_count=${INCLUDED_TX_COUNT} tx_proof_bytes_total=${TX_PROOF_BYTES_TOTAL} proven_batch_bytes=${PROVEN_BATCH_BYTES_TOTAL} payload_bytes_per_tx=${PAYLOAD_BYTES_PER_TX}" >&2
if [ "$INCLUDED_TX_COUNT" -lt "$TX_COUNT" ]; then
  echo "WARNING: Included tx_count (${INCLUDED_TX_COUNT}) is below requested tx_count (${TX_COUNT}); TPS uses included_tx_count." >&2
fi
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
echo "throughput_round_metrics tx_count=${TX_COUNT} included_tx_count=${INCLUDED_TX_COUNT} proof_mode=${PROOF_MODE} inclusion_target_mode=${INCLUSION_TARGET_MODE} send_proof_sidecar=${SEND_PROOF_SIDECAR} workers=${WORKERS} prover_workers=${PROVER_WORKERS} profile=${TP_PROFILE} tps_mode=${TPS_EFFECTIVE_MODE} send_total_ms=${SEND_TOTAL_MS} inclusion_total_ms=${INCLUSION_TOTAL_MS} round_total_ms=${ROUND_TOTAL_MS} submission_tps=${SUBMISSION_TPS} inclusion_tps=${INCLUSION_TPS} end_to_end_tps=${END_TO_END_TPS} effective_tps=${EFFECTIVE_TPS}" >&2

PREPARED_LINE_FINAL="$(search_log "Prepared proven batch candidate.*block_number=${BLOCK_NUMBER}.*key_tx_count=${FOUND_TX_COUNT}" | tail -n 1 || true)"
if [ -z "$PREPARED_LINE_FINAL" ]; then
  PREPARED_LINE_FINAL="$(search_log "Prepared proven batch candidate.*block_number=${BLOCK_NUMBER}" | tail -n 1 || true)"
fi
CONTEXT_LINE="$(search_log "prepare_block_proof_bundle: built shared candidate context.*block_number=${BLOCK_NUMBER}.*tx_count=${FOUND_TX_COUNT}" | tail -n 1 || true)"
if [ -z "$CONTEXT_LINE" ]; then
  CONTEXT_LINE="$(search_log "prepare_block_proof_bundle: built shared candidate context.*block_number=${BLOCK_NUMBER}" | tail -n 1 || true)"
fi
STAGE_LINE="$(search_log "prepare_block_proof_bundle: built commitment and (aggregation proofs|bundle proof artifacts).*block_number=${BLOCK_NUMBER}.*tx_count=${FOUND_TX_COUNT}" | tail -n 1 || true)"
if [ -z "$STAGE_LINE" ]; then
  STAGE_LINE="$(search_log "prepare_block_proof_bundle: built commitment and (aggregation proofs|bundle proof artifacts).*block_number=${BLOCK_NUMBER}" | tail -n 1 || true)"
fi
AGG_LINE="$(search_log "(prepare_block_proof_bundle: aggregation stage complete|prove_aggregation completed).*block_number=${BLOCK_NUMBER}.*tx_count=${FOUND_TX_COUNT}" | tail -n 1 || true)"
if [ -z "$AGG_LINE" ]; then
  AGG_LINE="$(search_log "(prepare_block_proof_bundle: aggregation stage complete|prove_aggregation completed).*block_number=${BLOCK_NUMBER}" | tail -n 1 || true)"
fi
QUEUE_DEPTH="$(metric_from_line "$PREPARED_LINE_FINAL" "queue_depth")"
QUEUE_WAIT_MS="$(metric_from_line "$PREPARED_LINE_FINAL" "queue_wait_ms")"
DISPATCH_WAIT_MS="$(metric_from_line "$PREPARED_LINE_FINAL" "dispatch_wait_ms")"
TOTAL_JOB_AGE_MS="$(metric_from_line "$PREPARED_LINE_FINAL" "total_job_age_ms")"
CONTEXT_STAGE_MS="$(metric_from_line "$CONTEXT_LINE" "stage_ms")"
COMMITMENT_STAGE_MS="$(metric_from_line "$STAGE_LINE" "commitment_stage_ms")"
AGGREGATION_STAGE_MS="$(metric_from_line "$STAGE_LINE" "aggregation_stage_ms")"
CACHE_HIT="$(bool_metric_from_line "$AGG_LINE" "cache_hit")"
CACHE_BUILD_MS="$(metric_from_line "$AGG_LINE" "cache_build_ms")"
export RUN_ID RUN_TIMESTAMP_UTC GIT_COMMIT GENESIS_HASH TP_SEEDS TP_MAX_PEERS PROOF_MODE STRICT_AGGREGATION TX_COUNT WORKERS PROVER_WORKERS TP_PROFILE BATCH_QUEUE_CAPACITY SEND_TOTAL_MS INCLUSION_TOTAL_MS ROUND_TOTAL_MS STRICT_WAIT_MS CONTEXT_STAGE_MS COMMITMENT_STAGE_MS AGGREGATION_STAGE_MS INCLUDED_TX_COUNT SUBMISSION_TPS INCLUSION_TPS END_TO_END_TPS EFFECTIVE_TPS PAYLOAD_BYTES_PER_TX TX_PROOF_BYTES_TOTAL PROVEN_BATCH_BYTES_TOTAL QUEUE_DEPTH QUEUE_WAIT_MS DISPATCH_WAIT_MS TOTAL_JOB_AGE_MS CACHE_HIT CACHE_BUILD_MS METRIC_BLOCK_NUMBER METRIC_TX_COUNT SEND_DA_SIDECAR SEND_TRACE_FILE LOG_FILE READY_PENDING_COUNT_BEFORE_MINING READY_PENDING_COUNT_AFTER_INCLUSION PREPARED_BUNDLES_BEFORE_MINING PREPARED_BUNDLES_AFTER_INCLUSION INCLUSION_START_BLOCK FINAL_BLOCK_NUMBER
emit_metrics_artifact "throughput"

echo "Done. Node is still running in tmux." >&2
echo "  Attach: tmux attach -t $SESSION" >&2
echo "  Logs:   $LOG_FILE" >&2
echo "  Kill:   tmux kill-session -t $SESSION" >&2
