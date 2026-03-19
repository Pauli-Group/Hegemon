#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TX_COUNTS="${HEGEMON_SCALE_TX_COUNTS:-32 64}"
PROVER_COUNTS="${HEGEMON_SCALE_PROVER_COUNTS:-1 2 4 8}"
ARTIFACTS_DIR="${HEGEMON_SCALE_ARTIFACTS_DIR:-/tmp/hegemon-scaling-artifacts}"
SUMMARY_TSV="${HEGEMON_SCALE_SUMMARY_TSV:-${ARTIFACTS_DIR}/summary.tsv}"
CHAIN_SPEC="${HEGEMON_SCALE_CHAIN_SPEC:-config/dev-chainspec.json}"
EASY_CHAIN="${HEGEMON_SCALE_EASY_CHAIN:-1}"
PROFILE="${HEGEMON_SCALE_PROFILE:-safe}"
NODE_RAYON_THREADS="${HEGEMON_SCALE_NODE_RAYON_THREADS:-0}"
AGG_PREPARE_THREADS="${HEGEMON_SCALE_AGG_PREPARE_THREADS:-0}"
AGG_PROVER_THREADS="${HEGEMON_SCALE_AGG_PROVER_THREADS:-1}"
AGG_WITNESS_LANES="${HEGEMON_SCALE_AGG_WITNESS_LANES:-}"
AGG_ADD_LANES="${HEGEMON_SCALE_AGG_ADD_LANES:-}"
AGG_MUL_LANES="${HEGEMON_SCALE_AGG_MUL_LANES:-}"
AGG_PREWARM_INCLUDE_MERGE="${HEGEMON_SCALE_AGG_PREWARM_INCLUDE_MERGE:-0}"
LEAF_FANIN="${HEGEMON_SCALE_AGG_LEAF_FANIN:-4}"
AGG_PREWARM_MAX_TXS="${HEGEMON_SCALE_AGG_PREWARM_MAX_TXS:-}"
RPC_WAIT_SECS="${HEGEMON_SCALE_RPC_WAIT_SECS:-1800}"
STRICT_PREPARE_TIMEOUT_SECS="${HEGEMON_SCALE_STRICT_PREPARE_TIMEOUT_SECS:-}"
BATCH_JOB_TIMEOUT_MS="${HEGEMON_SCALE_BATCH_JOB_TIMEOUT_MS:-}"
SKIP_BUILD="${HEGEMON_SCALE_SKIP_BUILD:-1}"
CONTINUE_ON_ERROR="${HEGEMON_SCALE_CONTINUE_ON_ERROR:-1}"
MINE_THREADS="${HEGEMON_SCALE_MINE_THREADS:-1}"
SNAPSHOT_ROOT="${HEGEMON_SCALE_SNAPSHOT_ROOT:-${ARTIFACTS_DIR}/snapshots}"
REBUILD_SNAPSHOTS="${HEGEMON_SCALE_REBUILD_SNAPSHOTS:-0}"
THREADS_PER_PROVER="${HEGEMON_SCALE_THREADS_PER_PROVER:-4}"
DISABLE_WORKER_PREWARM="${HEGEMON_SCALE_DISABLE_WORKER_PREWARM:-0}"
MATRIX_PROOF_MODE="${HEGEMON_TP_PROOF_MODE:-aggregation}"

HOST_THREADS="$(
  getconf _NPROCESSORS_ONLN 2>/dev/null \
    || nproc 2>/dev/null \
    || echo 1
)"

mkdir -p "$ARTIFACTS_DIR"
mkdir -p "$SNAPSHOT_ROOT"
printf "tx_count\tprover_workers\tincluded_tx_count\tstrict_wait_ms\tinclusion_total_ms\tround_total_ms\teffective_tps\tartifact_json\tstatus\n" > "$SUMMARY_TSV"

MATRIX_CHAIN_SPEC="$CHAIN_SPEC"
if [ "$EASY_CHAIN" = "1" ]; then
  MATRIX_CHAIN_SPEC="${ARTIFACTS_DIR}/easy-chainspec.json"
  BASE_CHAIN_SPEC="${ARTIFACTS_DIR}/base-chainspec.raw.json"
  if [ "${HEGEMON_SCALE_USE_CURRENT_BUILD_SPEC:-1}" = "1" ] && [ "$CHAIN_SPEC" = "config/dev-chainspec.json" ]; then
    ./target/release/hegemon-node build-spec --raw --disable-default-bootnode > "$BASE_CHAIN_SPEC"
  else
    cp "$CHAIN_SPEC" "$BASE_CHAIN_SPEC"
  fi
  python3 - "$BASE_CHAIN_SPEC" "$MATRIX_CHAIN_SPEC" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
data = json.loads(src.read_text())
top = data["genesis"]["raw"]["top"]
bits_key = "0x7d15dd66fbf0cbda1d3a651b5e606df2fbc97b050ba98067c6d1bdd855ff03b8"
value_key = "0x7d15dd66fbf0cbda1d3a651b5e606df27d15dd66fbf0cbda1d3a651b5e606df2"
data["name"] = f'{data.get("name", "Hegemon")} Throughput Matrix'
data["id"] = "hegemon-throughput-matrix"
data["chainType"] = "Development"
data["bootNodes"] = []
top[bits_key] = "0xffff001e"
top[value_key] = "0x0001000100000000000000000000000000000000000000000000000000000000"
dst.write_text(json.dumps(data))
PY
fi

for tx_count in $TX_COUNTS; do
  snapshot_node_rayon_threads="$NODE_RAYON_THREADS"
  if [ "$snapshot_node_rayon_threads" -le 0 ]; then
    snapshot_node_rayon_threads="$THREADS_PER_PROVER"
    if [ "$snapshot_node_rayon_threads" -gt "$HOST_THREADS" ]; then
      snapshot_node_rayon_threads="$HOST_THREADS"
    fi
    if [ "$snapshot_node_rayon_threads" -lt 1 ]; then
      snapshot_node_rayon_threads=1
    fi
  fi
  snapshot_agg_prepare_threads="$AGG_PREPARE_THREADS"
  if [ "$snapshot_agg_prepare_threads" -le 0 ]; then
    snapshot_agg_prepare_threads="$snapshot_node_rayon_threads"
  fi
  snapshot_dir="${SNAPSHOT_ROOT}/tx${tx_count}"
  snapshot_base="${snapshot_dir}/base"
  snapshot_wallet_a="${snapshot_dir}/wallet-a"
  snapshot_wallet_b="${snapshot_dir}/wallet-b"
  snapshot_recipients="${snapshot_dir}/recipients.json"
  snapshot_ready="${snapshot_dir}/.ready"
  snapshot_session="scale-snapshot-tx${tx_count}"
  snapshot_log="/tmp/${snapshot_session}.log"

  if [ "$REBUILD_SNAPSHOTS" = "1" ] || [ ! -f "$snapshot_ready" ] || [ ! -d "$snapshot_base" ] || [ ! -e "$snapshot_wallet_a" ] || [ ! -e "$snapshot_wallet_b" ]; then
    rm -rf "$snapshot_dir" "$snapshot_log"
    mkdir -p "$snapshot_dir"
    tmux kill-session -t "$snapshot_session" 2>/dev/null || true

    if ! env \
      HEGEMON_TP_FORCE=1 \
      HEGEMON_TP_TMUX_SESSION="$snapshot_session" \
      HEGEMON_TP_LOG_FILE="$snapshot_log" \
      HEGEMON_TP_RUN_ID="snapshot-tx${tx_count}" \
      HEGEMON_TP_CHAIN_SPEC="$MATRIX_CHAIN_SPEC" \
      HEGEMON_TP_UNSAFE=1 \
      HEGEMON_TP_PROFILE="$PROFILE" \
      HEGEMON_TP_TX_COUNT="$tx_count" \
      HEGEMON_TP_WORKERS=1 \
      HEGEMON_TP_PROVER_WORKERS=1 \
      HEGEMON_TP_SEND_DA_SIDECAR="$([ "$MATRIX_PROOF_MODE" = "single" ] && echo 0 || echo 1)" \
      HEGEMON_TP_NODE_RAYON_THREADS="$snapshot_node_rayon_threads" \
      HEGEMON_TP_AGG_PREPARE_THREADS="$snapshot_agg_prepare_threads" \
      HEGEMON_TP_AGG_PROVER_THREADS="$AGG_PROVER_THREADS" \
      HEGEMON_TP_AGG_WITNESS_LANES="$AGG_WITNESS_LANES" \
      HEGEMON_TP_AGG_ADD_LANES="$AGG_ADD_LANES" \
      HEGEMON_TP_AGG_MUL_LANES="$AGG_MUL_LANES" \
      HEGEMON_TP_AGG_PREWARM_INCLUDE_MERGE=0 \
      HEGEMON_TP_AGG_LEAF_FANIN="$LEAF_FANIN" \
      HEGEMON_TP_RPC_WAIT_SECS="$RPC_WAIT_SECS" \
      HEGEMON_TP_MAX_BLOCK_WAIT_SECS=7200 \
      HEGEMON_TP_PREPARE_SNAPSHOT_ONLY=1 \
      HEGEMON_TP_SKIP_BUILD="$SKIP_BUILD" \
      HEGEMON_AGG_DISABLE_WORKER_PREWARM=1 \
      HEGEMON_TP_MINE_THREADS="$MINE_THREADS" \
      HEGEMON_TP_NODE_BASE_PATH="$snapshot_base" \
      HEGEMON_TP_WALLET_A="$snapshot_wallet_a" \
      HEGEMON_TP_WALLET_B="$snapshot_wallet_b" \
      HEGEMON_TP_RECIPIENTS_JSON="$snapshot_recipients" \
      bash scripts/throughput_sidecar_aggregation_tmux.sh
    then
      tmux kill-session -t "$snapshot_session" 2>/dev/null || true
      exit 1
    fi

    tmux kill-session -t "$snapshot_session" 2>/dev/null || true
    touch "$snapshot_ready"
  fi

  for prover_workers in $PROVER_COUNTS; do
    run_id="tx${tx_count}-pw${prover_workers}"
    session="scale-${run_id}"
    log_file="/tmp/${session}.log"
    artifact_json="${ARTIFACTS_DIR}/${run_id}.json"
    run_base="/tmp/${session}-base"
    wallet_a="/tmp/${session}-wallet-a"
    wallet_b="/tmp/${session}-wallet-b"
    recipients_json="/tmp/${session}-recipients.json"

    rm -rf "$run_base" "$wallet_a" "$wallet_b" "$artifact_json" "$log_file" "$recipients_json"
    tmux kill-session -t "$session" 2>/dev/null || true
    mkdir -p "$run_base"
    cp -a "$snapshot_base/." "$run_base/"
    cp -a "$snapshot_wallet_a" "$wallet_a"
    cp -a "$snapshot_wallet_b" "$wallet_b"
    cp -a "$snapshot_recipients" "$recipients_json"

    run_prewarm_max_txs="$AGG_PREWARM_MAX_TXS"
    if [ -z "$run_prewarm_max_txs" ] && [ "$DISABLE_WORKER_PREWARM" != "1" ]; then
      run_prewarm_max_txs="$tx_count"
    fi
    prewarm_env=()
    if [ -n "$run_prewarm_max_txs" ]; then
      prewarm_env+=(HEGEMON_TP_AGG_PREWARM_MAX_TXS="$run_prewarm_max_txs")
    fi
    run_timeout_env=()
    if [ -n "$STRICT_PREPARE_TIMEOUT_SECS" ]; then
      run_timeout_env+=(HEGEMON_TP_STRICT_PREPARE_TIMEOUT_SECS="$STRICT_PREPARE_TIMEOUT_SECS")
    fi
    if [ -n "$BATCH_JOB_TIMEOUT_MS" ]; then
      run_timeout_env+=(HEGEMON_TP_BATCH_JOB_TIMEOUT_MS="$BATCH_JOB_TIMEOUT_MS")
    fi
    run_wallet_workers=1
    run_node_prover_workers="$prover_workers"
    run_node_rayon_threads="$NODE_RAYON_THREADS"
    if [ "$MATRIX_PROOF_MODE" = "single" ]; then
      run_wallet_workers="$prover_workers"
      # InlineTx still needs one local coordinator/finalize worker to build the
      # parent-bound commitment artifact; prover scaling lives at the tx edge.
      run_node_prover_workers=1
      if [ "$run_node_rayon_threads" -le 0 ]; then
        run_node_rayon_threads="$THREADS_PER_PROVER"
        if [ "$run_node_rayon_threads" -gt "$HOST_THREADS" ]; then
          run_node_rayon_threads="$HOST_THREADS"
        fi
        if [ "$run_node_rayon_threads" -lt 1 ]; then
          run_node_rayon_threads=1
        fi
      fi
    else
      if [ "$run_node_rayon_threads" -le 0 ]; then
        run_node_rayon_threads=$((THREADS_PER_PROVER * prover_workers))
        if [ "$run_node_rayon_threads" -gt "$HOST_THREADS" ]; then
          run_node_rayon_threads="$HOST_THREADS"
        fi
        if [ "$run_node_rayon_threads" -lt 1 ]; then
          run_node_rayon_threads=1
        fi
      fi
    fi
    run_agg_prepare_threads="$AGG_PREPARE_THREADS"
    if [ "$run_agg_prepare_threads" -le 0 ]; then
      run_agg_prepare_threads="$run_node_rayon_threads"
    fi

    run_status="ok"
    if ! env \
      HEGEMON_TP_FORCE=1 \
      HEGEMON_TP_TMUX_SESSION="$session" \
      HEGEMON_TP_LOG_FILE="$log_file" \
      HEGEMON_TP_ARTIFACTS_DIR="$ARTIFACTS_DIR" \
      HEGEMON_TP_RUN_ID="$run_id" \
      HEGEMON_TP_CHAIN_SPEC="$MATRIX_CHAIN_SPEC" \
      HEGEMON_TP_UNSAFE=1 \
      HEGEMON_TP_PROFILE="$PROFILE" \
      HEGEMON_TP_TX_COUNT="$tx_count" \
      HEGEMON_TP_WORKERS="$run_wallet_workers" \
      HEGEMON_TP_PROVER_WORKERS="$run_node_prover_workers" \
      HEGEMON_TP_SEND_DA_SIDECAR="$([ "$MATRIX_PROOF_MODE" = "single" ] && echo 0 || echo 1)" \
      HEGEMON_TP_NODE_RAYON_THREADS="$run_node_rayon_threads" \
      HEGEMON_TP_AGG_PREPARE_THREADS="$run_agg_prepare_threads" \
      HEGEMON_TP_AGG_PROVER_THREADS="$AGG_PROVER_THREADS" \
      HEGEMON_TP_AGG_WITNESS_LANES="$AGG_WITNESS_LANES" \
      HEGEMON_TP_AGG_ADD_LANES="$AGG_ADD_LANES" \
      HEGEMON_TP_AGG_MUL_LANES="$AGG_MUL_LANES" \
      HEGEMON_TP_AGG_PREWARM_INCLUDE_MERGE="$AGG_PREWARM_INCLUDE_MERGE" \
      HEGEMON_TP_AGG_LEAF_FANIN="$LEAF_FANIN" \
      HEGEMON_TP_RPC_WAIT_SECS="$RPC_WAIT_SECS" \
      HEGEMON_TP_SKIP_BUILD="$SKIP_BUILD" \
      HEGEMON_TP_REUSE_EXISTING_STATE=1 \
      HEGEMON_AGG_DISABLE_WORKER_PREWARM="$DISABLE_WORKER_PREWARM" \
      HEGEMON_TP_MINE_THREADS="$MINE_THREADS" \
      HEGEMON_TP_NODE_BASE_PATH="$run_base" \
      HEGEMON_TP_WALLET_A="$wallet_a" \
      HEGEMON_TP_WALLET_B="$wallet_b" \
      HEGEMON_TP_RECIPIENTS_JSON="$recipients_json" \
      ${run_timeout_env[@]+"${run_timeout_env[@]}"} \
      ${prewarm_env[@]+"${prewarm_env[@]}"} \
      bash scripts/throughput_sidecar_aggregation_tmux.sh
    then
      run_status="failed"
      printf "%s\t%s\t-\t-\t-\t-\t-\t%s\t%s\n" \
        "$tx_count" "$prover_workers" "$artifact_json" "$run_status" >> "$SUMMARY_TSV"
      tmux kill-session -t "$session" 2>/dev/null || true
      if [ "$CONTINUE_ON_ERROR" != "1" ]; then
        exit 1
      fi
      continue
    fi

    python3 - "$artifact_json" "$tx_count" "$prover_workers" "$run_status" >> "$SUMMARY_TSV" <<'PY'
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
tx_count = sys.argv[2]
prover_workers = sys.argv[3]
status = sys.argv[4]
if not artifact_path.exists():
    print(f"{tx_count}\t{prover_workers}\t-\t-\t-\t-\t-\t{artifact_path}\tmissing")
    sys.exit(0)

payload = json.loads(artifact_path.read_text())
metrics = payload.get("metrics") or {}
timings = payload.get("timings_ms") or {}
print(
    "\t".join(
        [
            tx_count,
            prover_workers,
            str(metrics.get("included_tx_count", "")),
            str(timings.get("strict_wait_ms", "")),
            str(timings.get("inclusion_total_ms", "")),
            str(timings.get("round_total_ms", "")),
            str(metrics.get("effective_tps", "")),
            str(artifact_path),
            status,
        ]
    )
)
PY

    tmux kill-session -t "$session" 2>/dev/null || true
  done
done

cat "$SUMMARY_TSV"
