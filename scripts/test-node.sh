#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BIN="$ROOT_DIR/target/debug/hegemon-node"
BIN="${HEGEMON_NODE_BIN:-$DEFAULT_BIN}"

A_BASE="${HEGEMON_TEST_NODE_A_BASE:-/tmp/hegemon-native-a}"
B_BASE="${HEGEMON_TEST_NODE_B_BASE:-/tmp/hegemon-native-b}"
A_RPC="${HEGEMON_TEST_NODE_A_RPC:-19945}"
B_RPC="${HEGEMON_TEST_NODE_B_RPC:-19946}"
A_P2P="${HEGEMON_TEST_NODE_A_P2P:-31333}"
B_P2P="${HEGEMON_TEST_NODE_B_P2P:-31334}"
SIGTERM_BASE="${HEGEMON_TEST_NODE_SIGTERM_BASE:-/tmp/hegemon-native-sigterm}"
SIGTERM_RPC="${HEGEMON_TEST_NODE_SIGTERM_RPC:-19947}"
SIGTERM_P2P="${HEGEMON_TEST_NODE_SIGTERM_P2P:-31335}"
SIGTERM_LOG="${HEGEMON_TEST_NODE_SIGTERM_LOG:-/tmp/hegemon-native-sigterm.log}"
RPC_URL="${HEGEMON_TEST_RPC_URL:-http://127.0.0.1:9944}"
TIMEOUT_SECS="${HEGEMON_TEST_TIMEOUT_SECS:-120}"
LIVENESS_MIN_BLOCKS="${HEGEMON_TEST_LIVENESS_MIN_BLOCKS:-12}"
LIVENESS_MAX_BLOCK_GAP_SECS="${HEGEMON_TEST_LIVENESS_MAX_BLOCK_GAP_SECS:-600}"

PID_DIR="/tmp/hegemon-native-test-pids"
A_PID="$PID_DIR/node-a.pid"
B_PID="$PID_DIR/node-b.pid"
A_LOG="/tmp/hegemon-native-a.log"
B_LOG="/tmp/hegemon-native-b.log"

log() {
  printf '[test-node] %s\n' "$*"
}

fail() {
  printf '[test-node] ERROR: %s\n' "$*" >&2
  exit 1
}

ensure_binary() {
  if [[ -n "${HEGEMON_NODE_BIN:-}" ]]; then
    if [[ ! -x "$BIN" ]]; then
      fail "HEGEMON_NODE_BIN is not executable: $BIN"
    fi
    return
  fi

  log "building hegemon-node"
  cargo build -p hegemon-node --bin hegemon-node --no-default-features
  if [[ ! -x "$BIN" ]]; then
    fail "built hegemon-node not found at $BIN"
  fi
}

rpc() {
  local port="$1"
  local method="$2"
  local params="${3:-[]}"
  curl -fsS \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "http://127.0.0.1:$port"
}

rpc_url() {
  local url="$1"
  local method="$2"
  local params="${3:-[]}"
  curl -fsS \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$url"
}

height() {
  local port="$1"
  rpc "$port" chain_getHeader |
    python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"]["number"], 16))'
}

rpc_height() {
  local url="$1"
  rpc_url "$url" hegemon_consensusStatus |
    python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"]["height"]))'
}

wait_rpc() {
  local port="$1"
  local deadline=$((SECONDS + TIMEOUT_SECS))
  until rpc "$port" system_health >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      fail "RPC on port $port did not become ready"
    fi
    sleep 1
  done
}

wait_height_gt() {
  local port="$1"
  local minimum="$2"
  local deadline=$((SECONDS + TIMEOUT_SECS))
  local current=0
  while ((SECONDS < deadline)); do
    current="$(height "$port" 2>/dev/null || echo 0)"
    if ((current > minimum)); then
      printf '%s\n' "$current"
      return 0
    fi
    sleep 1
  done
  fail "height on port $port did not exceed $minimum; last height $current"
}

mining_status_summary() {
  local port="$1"
  rpc "$port" hegemon_miningStatus |
    python3 -c '
import json, sys
status = json.load(sys.stdin)["result"]
print(
    status.get("is_mining"),
    status.get("threads"),
    status.get("hash_rate"),
    status.get("syncing"),
    status.get("mining_sync_gate_open"),
)
'
}

pending_count() {
  local port="$1"
  rpc "$port" author_pendingExtrinsics |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]))'
}

mining_status_summary_url() {
  local url="$1"
  rpc_url "$url" hegemon_miningStatus |
    python3 -c '
import json, sys
status = json.load(sys.stdin)["result"]
print(
    status.get("is_mining"),
    status.get("threads"),
    status.get("hash_rate"),
    status.get("syncing"),
    status.get("mining_sync_gate_open"),
    status.get("block_height"),
    status.get("difficulty"),
    status.get("next_difficulty"),
)
'
}

pending_count_url() {
  local url="$1"
  rpc_url "$url" author_pendingExtrinsics |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]))'
}

timestamp_stats_url() {
  local url="$1"
  local start_height="$2"
  local end_height="$3"
  rpc_url "$url" hegemon_blockTimestamps "[$start_height,$end_height]" |
    python3 -c '
import json, sys
rows = [row for row in json.load(sys.stdin)["result"] if row.get("timestamp_ms") is not None]
if len(rows) < 2:
    print("chain_samples=%d" % len(rows))
    raise SystemExit(0)
deltas = [
    (rows[i]["timestamp_ms"] - rows[i - 1]["timestamp_ms"]) / 1000
    for i in range(1, len(rows))
]
elapsed = (rows[-1]["timestamp_ms"] - rows[0]["timestamp_ms"]) / 1000
avg = elapsed / (len(rows) - 1)
print(
    f"chain_samples={len(rows)} chain_elapsed={elapsed:.3f}s "
    f"chain_avg={avg:.3f}s chain_min={min(deltas):.3f}s chain_max={max(deltas):.3f}s"
)
'
}

wait_liveness_window() {
  local miner_port="$1"
  local follower_port="$2"
  local start_height
  start_height="$(height "$miner_port")"
  local target_height=$((start_height + LIVENESS_MIN_BLOCKS))
  local deadline=$((SECONDS + TIMEOUT_SECS))
  local started_at
  started_at="$(date +%s)"
  local last_height="$start_height"
  local last_block_at="$started_at"
  local max_gap=0
  local miner_height="$start_height"
  local follower_height=0

  while ((SECONDS < deadline)); do
    local now
    now="$(date +%s)"
    miner_height="$(height "$miner_port" 2>/dev/null || echo 0)"
    follower_height="$(height "$follower_port" 2>/dev/null || echo 0)"
    if ((miner_height > last_height)); then
      local gap=$((now - last_block_at))
      if ((gap > max_gap)); then
        max_gap="$gap"
      fi
      if ((gap > LIVENESS_MAX_BLOCK_GAP_SECS)); then
        fail "devnet liveness block gap ${gap}s exceeded ${LIVENESS_MAX_BLOCK_GAP_SECS}s"
      fi
      last_height="$miner_height"
      last_block_at="$now"
    fi
    if ((miner_height >= target_height && follower_height >= target_height)); then
      local elapsed=$((now - started_at))
      local produced=$((miner_height - start_height))
      local summary
      summary="$(mining_status_summary "$miner_port")"
      local is_mining threads hash_rate syncing gate_open
      read -r is_mining threads hash_rate syncing gate_open <<<"$summary"
      if [[ "$is_mining" != "True" || "$gate_open" != "True" || "$syncing" != "False" ]]; then
        fail "miner status not live: is_mining=$is_mining gate_open=$gate_open syncing=$syncing"
      fi
      python3 - "$threads" "$hash_rate" <<'PY'
import sys
threads = int(sys.argv[1])
hash_rate = float(sys.argv[2])
if threads < 1 or hash_rate <= 0:
    raise SystemExit(1)
PY
      local pending
      pending="$(pending_count "$miner_port")"
      log "devnet liveness window miner_start=$start_height miner=$miner_height follower=$follower_height produced=$produced elapsed=${elapsed}s max_gap=${max_gap}s threads=$threads hash_rate=$hash_rate pending=$pending"
      return 0
    fi
    sleep 1
  done
  fail "devnet liveness did not reach target height $target_height; miner=$miner_height follower=$follower_height"
}

observe_rpc_liveness() {
  local start_height
  start_height="$(rpc_height "$RPC_URL")"
  local target_height=$((start_height + LIVENESS_MIN_BLOCKS))
  local deadline=$((SECONDS + TIMEOUT_SECS))
  local started_at
  started_at="$(date +%s)"
  local last_height="$start_height"
  local last_block_at="$started_at"
  local max_gap=0
  local current_height="$start_height"

  while ((SECONDS < deadline)); do
    local now
    now="$(date +%s)"
    current_height="$(rpc_height "$RPC_URL" 2>/dev/null || echo 0)"
    if ((current_height > last_height)); then
      local gap=$((now - last_block_at))
      if ((gap > max_gap)); then
        max_gap="$gap"
      fi
      if ((gap > LIVENESS_MAX_BLOCK_GAP_SECS)); then
        fail "RPC liveness block gap ${gap}s exceeded ${LIVENESS_MAX_BLOCK_GAP_SECS}s"
      fi
      last_height="$current_height"
      last_block_at="$now"
    fi
    if ((current_height >= target_height)); then
      local elapsed=$((now - started_at))
      local produced=$((current_height - start_height))
      local summary
      summary="$(mining_status_summary_url "$RPC_URL")"
      local is_mining threads hash_rate syncing gate_open block_height difficulty next_difficulty
      read -r is_mining threads hash_rate syncing gate_open block_height difficulty next_difficulty <<<"$summary"
      if [[ "$is_mining" != "True" || "$gate_open" != "True" || "$syncing" != "False" ]]; then
        fail "RPC miner status not live: is_mining=$is_mining gate_open=$gate_open syncing=$syncing"
      fi
      python3 - "$threads" "$hash_rate" <<'PY'
import sys
threads = int(sys.argv[1])
hash_rate = float(sys.argv[2])
if threads < 1 or hash_rate <= 0:
    raise SystemExit(1)
PY
      local pending
      pending="$(pending_count_url "$RPC_URL")"
      local timestamp_stats
      timestamp_stats="$(timestamp_stats_url "$RPC_URL" "$start_height" "$current_height")"
      log "RPC liveness url=$RPC_URL start=$start_height height=$current_height produced=$produced elapsed=${elapsed}s max_gap=${max_gap}s threads=$threads hash_rate=$hash_rate pending=$pending difficulty=$difficulty next_difficulty=$next_difficulty $timestamp_stats"
      return 0
    fi
    sleep 1
  done
  fail "RPC liveness did not reach target height $target_height; last height $current_height"
}

stop_pidfile() {
  local pidfile="$1"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

clean() {
  stop_pidfile "$A_PID"
  stop_pidfile "$B_PID"
  rm -rf "$A_BASE" "$B_BASE" "$PID_DIR"
  rm -f "$A_LOG" "$B_LOG"
}

sigterm_shutdown() {
  ensure_binary
  rm -rf "$SIGTERM_BASE"
  rm -f "$SIGTERM_LOG"
  log "starting native node for SIGTERM shutdown smoke on RPC $SIGTERM_RPC"
  (
    cd "$ROOT_DIR"
    exec env NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 RUST_LOG=hegemon_node=debug,network=info \
      "$BIN" --dev --base-path "$SIGTERM_BASE" --rpc-port "$SIGTERM_RPC" \
        --port "$SIGTERM_P2P" --rpc-methods unsafe --name native-sigterm
  ) >"$SIGTERM_LOG" 2>&1 &
  local pid="$!"
  local exit_code=0
  trap 'kill "$pid" >/dev/null 2>&1 || true; rm -rf "$SIGTERM_BASE"' RETURN

  wait_rpc "$SIGTERM_RPC"
  kill -TERM "$pid"
  wait "$pid" || exit_code="$?"
  if ((exit_code != 0)); then
    tail -80 "$SIGTERM_LOG" >&2 || true
    fail "SIGTERM shutdown exited with status $exit_code"
  fi
  grep -q 'signal.*"sigterm"' "$SIGTERM_LOG" || {
    tail -80 "$SIGTERM_LOG" >&2 || true
    fail "SIGTERM shutdown log did not record sigterm"
  }
  grep -q 'operation.*"shutdown_flush"' "$SIGTERM_LOG" || {
    tail -80 "$SIGTERM_LOG" >&2 || true
    fail "SIGTERM shutdown did not use shutdown_flush durability operation"
  }
  grep -q 'native Hegemon node shutdown complete' "$SIGTERM_LOG" || {
    tail -80 "$SIGTERM_LOG" >&2 || true
    fail "SIGTERM shutdown did not complete"
  }
  log "SIGTERM shutdown flushed through shutdown_flush durability barrier"
}

start_miner() {
  mkdir -p "$PID_DIR"
  log "starting native miner on RPC $A_RPC and P2P $A_P2P"
  (
    cd "$ROOT_DIR"
    HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \
      "$BIN" --dev --base-path "$A_BASE" --rpc-port "$A_RPC" --port "$A_P2P" --name native-a
  ) >"$A_LOG" 2>&1 &
  printf '%s\n' "$!" >"$A_PID"
  wait_rpc "$A_RPC"
}

start_follower() {
  mkdir -p "$PID_DIR"
  log "starting native follower on RPC $B_RPC and P2P $B_P2P"
  (
    cd "$ROOT_DIR"
    HEGEMON_SEEDS="127.0.0.1:$A_P2P" \
      "$BIN" --dev --base-path "$B_BASE" --rpc-port "$B_RPC" --port "$B_P2P" --name native-b
  ) >"$B_LOG" 2>&1 &
  printf '%s\n' "$!" >"$B_PID"
  wait_rpc "$B_RPC"
}

single_node() {
  clean
  ensure_binary
  trap clean EXIT
  start_miner
  local mined
  mined="$(wait_height_gt "$A_RPC" 0)"
  log "single-node mined height $mined"
}

two_node() {
  clean
  ensure_binary
  trap clean EXIT
  start_follower
  start_miner
  local follower_height
  follower_height="$(wait_height_gt "$B_RPC" 0)"
  local miner_height
  miner_height="$(height "$A_RPC")"
  log "two-node sync miner=$miner_height follower=$follower_height"
}

devnet_liveness() {
  clean
  ensure_binary
  trap clean EXIT
  start_follower
  start_miner

  local miner_height
  miner_height="$(wait_height_gt "$A_RPC" 1)"
  local follower_height
  follower_height="$(wait_height_gt "$B_RPC" 1)"
  log "devnet liveness miner=$miner_height follower=$follower_height"
  wait_liveness_window "$A_RPC" "$B_RPC"
}

two_node_restart() {
  clean
  ensure_binary
  trap clean EXIT
  start_follower
  start_miner

  local before_restart
  before_restart="$(wait_height_gt "$B_RPC" 0)"
  log "follower reached height $before_restart before restart"

  stop_pidfile "$B_PID"
  sleep 5
  start_follower

  local after_restart
  after_restart="$(wait_height_gt "$B_RPC" "$before_restart")"
  local miner_height
  miner_height="$(height "$A_RPC")"
  log "restart catch-up miner=$miner_height follower=$after_restart"
}

wallet_send() {
  ensure_binary
  log "running native wallet submission compatibility test"
  cargo test -p hegemon-node --lib --no-default-features submit_action_stages_and_imports_shielded_transfer
}

usage() {
  cat <<'EOF'
Usage: ./scripts/test-node.sh [single-node|two-node|devnet-liveness|two-node-restart|wallet-send|sigterm-shutdown|clean]

single-node       Start one native dev miner and require height > 0.
two-node          Start a native miner and follower using HEGEMON_SEEDS.
devnet-liveness   Start a miner and follower and require synced multi-block liveness.
rpc-liveness      Observe an already-running loopback RPC node for multi-block liveness.
two-node-restart  Restart the follower and require persisted sled catch-up.
wallet-send       Run the native wallet submission compatibility test.
sigterm-shutdown  Require SIGTERM shutdown to flush through the durability gate.
clean             Stop test nodes and remove disposable native state.
EOF
}

case "${1:-}" in
  single-node)
    single_node
    ;;
  two-node)
    two_node
    ;;
  devnet-liveness)
    devnet_liveness
    ;;
  rpc-liveness)
    observe_rpc_liveness
    ;;
  two-node-restart)
    two_node_restart
    ;;
  wallet-send)
    wallet_send
    ;;
  sigterm-shutdown)
    sigterm_shutdown
    ;;
  clean)
    clean
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
