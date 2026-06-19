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
TIMEOUT_SECS="${HEGEMON_TEST_TIMEOUT_SECS:-45}"

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

height() {
  local port="$1"
  rpc "$port" chain_getHeader |
    python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"]["number"], 16))'
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
Usage: ./scripts/test-node.sh [single-node|two-node|two-node-restart|wallet-send|sigterm-shutdown|clean]

single-node       Start one native dev miner and require height > 0.
two-node          Start a native miner and follower using HEGEMON_SEEDS.
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
