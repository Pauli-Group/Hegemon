#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NODE_BIN="target/release/hegemon-node"
WORKER_BIN="target/release/hegemon-prover-worker"
WALLETD_BIN="target/release/walletd"

RPC_A=23944
RPC_B=23945
RPC_C=23946
P2P_A=42333
P2P_B=42334
P2P_C=42335

BOOT_PASS="soakboot123"
TEST_PASS="soaktest123"

DIFFICULTY_BITS_KEY="0x7d15dd66fbf0cbda1d3a651b5e606df2fbc97b050ba98067c6d1bdd855ff03b8"
DIFFICULTY_VALUE_KEY="0x7d15dd66fbf0cbda1d3a651b5e606df27d15dd66fbf0cbda1d3a651b5e606df2"

if [ ! -x "$NODE_BIN" ] || [ ! -x "$WORKER_BIN" ] || [ ! -x "$WALLETD_BIN" ]; then
    cargo build -p hegemon-node --release --features substrate
    cargo build --release -p walletd
fi

TMP_ROOT="$(mktemp -d /tmp/hegemon-multi-builder-soak.XXXXXX)"
HARNESS_SPEC="$TMP_ROOT/soak-chainspec.json"
BOOT_STORE="$TMP_ROOT/boot.wallet"
TEST_STORE="$TMP_ROOT/test.wallet"
SEEN_ARTIFACTS="$TMP_ROOT/seen-artifacts.txt"
PIDS=()
START_TS=0
END_TS=0
SUBMITTED_TXS="${1:-${SOAK_TXS:-3}}"
TX_VALUE="${SOAK_TX_VALUE:-100000000}"
GOSSIP_SAMPLE_EVERY="${SOAK_GOSSIP_SAMPLE_EVERY:-0}"
STEP="init"

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ "${KEEP_TMP:-0}" = "1" ]; then
        printf '[multi-builder-soak] preserving %s\n' "$TMP_ROOT" >&2
    else
        for _ in $(seq 1 10); do
            rm -rf "$TMP_ROOT" 2>/dev/null && break
            sleep 1
        done
    fi
}
trap cleanup EXIT

log_step() {
    STEP="$1"
    printf '[multi-builder-soak] %s\n' "$STEP"
}
trap 'printf "[multi-builder-soak] failed at step=%s tmp=%s\n" "$STEP" "$TMP_ROOT" >&2' ERR

: > "$SEEN_ARTIFACTS"

jq --arg bits_key "$DIFFICULTY_BITS_KEY" \
   --arg value_key "$DIFFICULTY_VALUE_KEY" \
   '.name = "Hegemon Multi Builder Soak"
    | .id = "hegemon-multi-builder-soak"
    | .chainType = "Development"
    | .bootNodes = []
    | .genesis.raw.top[$bits_key] = "0xffff001e"
    | .genesis.raw.top[$value_key] = "0x0001000100000000000000000000000000000000000000000000000000000000"' \
   config/dev-chainspec.json > "$HARNESS_SPEC"

rpc() {
    local port=$1
    local payload=$2
    curl --max-time 30 -s -X POST -H "Content-Type: application/json" -d "$payload" "http://127.0.0.1:$port"
}

best_hash() {
    rpc "$1" '{"jsonrpc":"2.0","method":"chain_getBlockHash","params":[],"id":1}' | jq -r '.result // "null"'
}

best_number() {
    local number
    number=$(rpc "$1" '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' | jq -r '.result.number // "null"')
    if [ "$number" = "null" ]; then
        echo "null"
    else
        printf '%d\n' "$number" 2>/dev/null || echo "null"
    fi
}

wait_for_rpc() {
    local port=$1
    for _ in $(seq 1 60); do
        if rpc "$port" '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_equal_tip() {
    local left=$1
    local right=$2
    for _ in $(seq 1 120); do
        local left_hash right_hash
        left_hash=$(best_hash "$left")
        right_hash=$(best_hash "$right")
        if [ "$left_hash" != "null" ] && [ "$left_hash" = "$right_hash" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_min_height() {
    local port=$1
    local target=$2
    for _ in $(seq 1 180); do
        local current
        current=$(best_number "$port")
        if [ "$current" != "null" ] && [ "$current" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_compact_job() {
    local port=$1
    for _ in $(seq 1 60); do
        local job
        job=$(rpc "$port" '{"jsonrpc":"2.0","method":"hegemon_compactJob","params":[{}],"id":1}')
        if [ "$(echo "$job" | jq -r '.result.available // false')" = "true" ]; then
            echo "$job"
            return 0
        fi
        sleep 1
    done
    return 1
}

mine_job_nonce() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import sys

pre_hash = bytes.fromhex(sys.argv[1].removeprefix("0x"))
bits = int(sys.argv[2])

def compact_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x00FFFFFF
    if exponent > 3:
        return mantissa << (8 * (exponent - 3))
    return mantissa >> (8 * (3 - exponent))

target = compact_to_target(bits)
counter = 0
while True:
    nonce = counter.to_bytes(8, "little") + b"\x00" * 24
    work = hashlib.sha256(hashlib.sha256(pre_hash + nonce).digest()).digest()
    if int.from_bytes(work, "big") <= target:
        print("0x" + nonce.hex())
        break
    counter += 1
PY
}

submit_compact_solution() {
    local port=$1
    local worker_name=$2
    local job_json=$3
    local before_block
    before_block=$(best_number "$port")
    local job_id pre_hash bits nonce payload
    job_id=$(echo "$job_json" | jq -r '.result.job_id')
    pre_hash=$(echo "$job_json" | jq -r '.result.pre_hash')
    bits=$(echo "$job_json" | jq -r '.result.network_bits')
    nonce=$(mine_job_nonce "$pre_hash" "$bits")
    payload=$(jq -n --arg worker_name "$worker_name" --arg job_id "$job_id" --arg nonce "$nonce" \
        '{jsonrpc:"2.0", method:"hegemon_submitCompactSolution", params:[{worker_name:$worker_name, job_id:$job_id, nonce:$nonce}], id:1}')
    rpc "$port" "$payload" >/dev/null
    for _ in $(seq 1 30); do
        local current
        current=$(best_number "$port")
        if [ "$current" != "null" ] && [ "$current" -gt "$before_block" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_new_artifact_hash() {
    local port=$1
    for _ in $(seq 1 300); do
        local listing
        listing=$(rpc "$port" '{"jsonrpc":"2.0","method":"prover_listArtifactAnnouncements","params":[],"id":1}')
        while IFS= read -r hash; do
            [ -z "$hash" ] && continue
            if ! grep -qx "$hash" "$SEEN_ARTIFACTS"; then
                printf '%s\n' "$hash" >> "$SEEN_ARTIFACTS"
                echo "$hash"
                return 0
            fi
        done < <(echo "$listing" | jq -r '.result[]?.artifact_hash // empty')
        sleep 1
    done
    return 1
}

mark_current_artifacts_seen() {
    local port=$1
    local listing
    listing=$(rpc "$port" '{"jsonrpc":"2.0","method":"prover_listArtifactAnnouncements","params":[],"id":1}')
    while IFS= read -r hash; do
        [ -z "$hash" ] && continue
        grep -qx "$hash" "$SEEN_ARTIFACTS" || printf '%s\n' "$hash" >> "$SEEN_ARTIFACTS"
    done < <(echo "$listing" | jq -r '.result[]?.artifact_hash // empty')
}

wait_for_artifact_fetch() {
    local port=$1
    local artifact_hash=$2
    for _ in $(seq 1 300); do
        if rpc "$port" \
            "{\"jsonrpc\":\"2.0\",\"method\":\"prover_getCandidateArtifact\",\"params\":[\"$artifact_hash\"],\"id\":1}" \
            | jq -re --arg artifact_hash "$artifact_hash" '.result.artifact_hash == $artifact_hash' >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

pending_extrinsic_count() {
    rpc "$1" '{"jsonrpc":"2.0","method":"author_pendingExtrinsics","params":[],"id":1}' \
        | jq -r '.result | length'
}

wait_for_pending_extrinsics() {
    local port=$1
    for _ in $(seq 1 60); do
        local count
        count=$(pending_extrinsic_count "$port")
        if [ "$count" != "null" ] && [ "$count" -gt 0 ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

set_mining_threads() {
    local port=$1
    local threads=$2
    rpc "$port" "$(jq -n --argjson threads "$threads" '{jsonrpc:"2.0", method:"hegemon_startMining", params:[{threads:$threads}], id:1}')" >/dev/null
}

stop_mining() {
    local port=$1
    rpc "$port" '{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[{}],"id":1}' >/dev/null || true
}

wallet_req() {
    local store=$1
    local pass=$2
    local mode=$3
    local request=$4
    printf '%s\n%s\n' "$pass" "$request" | "$WALLETD_BIN" --store "$store" --mode "$mode"
}

wallet_create_and_address() {
    local store=$1
    local pass=$2
    wallet_req "$store" "$pass" create '{"id":1,"method":"status.get","params":{}}' | jq -r '.result.primaryAddress'
}

wallet_sync() {
    local store=$1
    local pass=$2
    local ws_url=$3
    wallet_req "$store" "$pass" open "{\"id\":1,\"method\":\"sync.once\",\"params\":{\"ws_url\":\"$ws_url\",\"force_rescan\":true}}"
}

wallet_send() {
    local store=$1
    local pass=$2
    local ws_url=$3
    local recipient=$4
    local memo=$5
    local value=$6
    local recipients
    recipients=$(jq -nc --arg addr "$recipient" --arg memo "$memo" --argjson value "$value" \
        '[{address:$addr,value:$value,asset_id:0,memo:$memo}]')
    wallet_req "$store" "$pass" open "$(jq -nc --arg ws "$ws_url" --argjson recipients "$recipients" '{id:1,method:"tx.send",params:{ws_url:$ws,recipients:$recipients,fee:0,auto_consolidate:true}}')"
}

start_builder() {
    local rpc_port=$1
    local p2p_port=$2
    local base_path=$3
    local name=$4
    local seeds=$5
    local payout_address=$6
    local mine_threads=${7:-0}

    HEGEMON_MINE=1 \
    HEGEMON_MINE_THREADS="$mine_threads" \
    HEGEMON_MINER_ADDRESS="$payout_address" \
    HEGEMON_PROVER_REWARD_ADDRESS="$payout_address" \
    HEGEMON_PROVER_WORKERS=0 \
    HEGEMON_BATCH_VERIFY_PREWARM_TXS=0 \
    HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
    HEGEMON_SEEDS="$seeds" \
    "$NODE_BIN" \
        --dev \
        --chain "$HARNESS_SPEC" \
        --base-path "$base_path" \
        --rpc-port "$rpc_port" \
        --port "$p2p_port" \
        --rpc-methods unsafe \
        --name "$name" \
        >"$TMP_ROOT/$name.log" 2>&1 &
    echo $!
}

BOOT_ADDR=$(wallet_create_and_address "$BOOT_STORE" "$BOOT_PASS")
TEST_ADDR=$(wallet_create_and_address "$TEST_STORE" "$TEST_PASS")

log_step "bootstrap-builder-a"
BUILDER_A_PID=$(start_builder "$RPC_A" "$P2P_A" "$TMP_ROOT/a-base" "soak-builder-a" "" "$BOOT_ADDR" "1")
PIDS+=("$BUILDER_A_PID")
wait_for_rpc "$RPC_A"
BOOTSTRAP_BLOCKS=$(python3 - "$SUBMITTED_TXS" "$TX_VALUE" <<'PY'
import math, sys
txs = int(sys.argv[1])
value = int(sys.argv[2])
per_block = 499_000_000
print(max(3, math.ceil((txs * value) / per_block) + 2))
PY
)
wait_for_min_height "$RPC_A" "$BOOTSTRAP_BLOCKS"
stop_mining "$RPC_A"
sleep 2

log_step "clone-state"
kill "$BUILDER_A_PID" 2>/dev/null || true
wait "$BUILDER_A_PID" 2>/dev/null || true
PIDS=()
cp -a "$TMP_ROOT/a-base" "$TMP_ROOT/b-base"
cp -a "$TMP_ROOT/a-base" "$TMP_ROOT/c-base"
rm -f "$TMP_ROOT/b-base/pq-identity.seed" "$TMP_ROOT/b-base/pq-peers.bin"
rm -f "$TMP_ROOT/c-base/pq-identity.seed" "$TMP_ROOT/c-base/pq-peers.bin"

BUILDER_A_PID=$(start_builder "$RPC_A" "$P2P_A" "$TMP_ROOT/a-base" "soak-builder-a" "" "$BOOT_ADDR" "0")
PIDS+=("$BUILDER_A_PID")
wait_for_rpc "$RPC_A"
stop_mining "$RPC_A"
BUILDER_B_PID=$(start_builder "$RPC_B" "$P2P_B" "$TMP_ROOT/b-base" "soak-builder-b" "127.0.0.1:$P2P_A" "$BOOT_ADDR" "0")
PIDS+=("$BUILDER_B_PID")
wait_for_rpc "$RPC_B"
stop_mining "$RPC_B"
BUILDER_C_PID=$(start_builder "$RPC_C" "$P2P_C" "$TMP_ROOT/c-base" "soak-builder-c" "127.0.0.1:$P2P_A" "$BOOT_ADDR" "0")
PIDS+=("$BUILDER_C_PID")
wait_for_rpc "$RPC_C"
stop_mining "$RPC_C"

log_step "sync-snapshot"
wait_for_equal_tip "$RPC_A" "$RPC_B"
wait_for_equal_tip "$RPC_A" "$RPC_C"

log_step "start-prover-worker"
(
    while true; do
        HEGEMON_PROVER_RPC_URL="http://127.0.0.1:$RPC_A" \
        HEGEMON_PROVER_SOURCE="multi-builder-soak" \
            "$WORKER_BIN" --poll-ms 250 >>"$TMP_ROOT/worker-a.log" 2>&1 || true
        sleep 1
    done
) &
WORKER_A_PID=$!
PIDS+=("$WORKER_A_PID")
sleep 2
kill -0 "$WORKER_A_PID"

log_step "submit-load"
START_HEIGHT=$(best_number "$RPC_A")
START_TS=$(date +%s)
for idx in $(seq 1 "$SUBMITTED_TXS"); do
    log_step "submit-tx-$idx"
    wallet_sync "$BOOT_STORE" "$BOOT_PASS" "ws://127.0.0.1:$RPC_A" >/dev/null
    wallet_send "$BOOT_STORE" "$BOOT_PASS" "ws://127.0.0.1:$RPC_A" "$TEST_ADDR" "soak tx $idx" "$TX_VALUE" >/dev/null
    log_step "wait-pending-$idx"
    wait_for_pending_extrinsics "$RPC_A"
    if [ "$GOSSIP_SAMPLE_EVERY" -gt 0 ] && { [ "$idx" -eq 1 ] || [ $((idx % GOSSIP_SAMPLE_EVERY)) -eq 0 ]; }; then
        mark_current_artifacts_seen "$RPC_A"
        log_step "wait-artifact-hash-$idx"
        ARTIFACT_HASH=$(wait_for_new_artifact_hash "$RPC_A")
        log_step "wait-artifact-fetch-b-$idx"
        wait_for_artifact_fetch "$RPC_B" "$ARTIFACT_HASH"
        log_step "wait-artifact-fetch-c-$idx"
        wait_for_artifact_fetch "$RPC_C" "$ARTIFACT_HASH"
    fi
    attempts=0
    while [ "$(pending_extrinsic_count "$RPC_A")" -gt 0 ]; do
        attempts=$((attempts + 1))
        if [ "$attempts" -gt 10 ]; then
            echo "tx $idx remained pending after $attempts inclusion attempts" >&2
            exit 1
        fi
        log_step "compact-job-$idx-attempt-$attempts"
        set_mining_threads "$RPC_A" 1
        JOB_A=$(wait_for_compact_job "$RPC_A")
        log_step "submit-solution-$idx-attempt-$attempts"
        submit_compact_solution "$RPC_A" "soak-worker-a" "$JOB_A"
        stop_mining "$RPC_A"
        wait_for_equal_tip "$RPC_A" "$RPC_B"
        wait_for_equal_tip "$RPC_A" "$RPC_C"
    done
done

END_TS=$(date +%s)

ELAPSED=$((END_TS - START_TS))
if [ "$ELAPSED" -le 0 ]; then
    ELAPSED=1
fi
TPS=$(python3 - "$SUBMITTED_TXS" "$ELAPSED" <<'PY'
import sys
txs = int(sys.argv[1])
secs = int(sys.argv[2])
print(f"{txs / secs:.4f}")
PY
)
FINAL_HEIGHT=$(best_number "$RPC_A")
FINAL_HASH=$(best_hash "$RPC_A")

printf 'throughput_metrics submitted_txs=%s elapsed_s=%s tx_per_s=%s blocks_advanced=%s final_height=%s final_hash=%s\n' \
    "$SUBMITTED_TXS" "$ELAPSED" "$TPS" "$((FINAL_HEIGHT - START_HEIGHT))" "$FINAL_HEIGHT" "$FINAL_HASH"

echo "MULTI BUILDER SOAK HARNESS PASSED"
