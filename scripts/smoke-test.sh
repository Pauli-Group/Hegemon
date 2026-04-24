#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${HEGEMON_RPC_URL:-http://127.0.0.1:9944}"

rpc() {
  local method="$1"
  local params="${2:-[]}"
  curl -fsS \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$RPC_URL"
}

height() {
  rpc chain_getHeader |
    python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"]["number"], 16))'
}

require_result() {
  local method="$1"
  local params="${2:-[]}"
  local response
  response="$(rpc "$method" "$params")"
  if ! printf '%s' "$response" | python3 -c 'import json,sys; data=json.load(sys.stdin); raise SystemExit(0 if "result" in data else 1)'; then
    printf 'FAIL: %s did not return a JSON-RPC result\n%s\n' "$method" "$response" >&2
    exit 1
  fi
  printf 'PASS: %s\n' "$method"
}

printf '=== Hegemon node smoke test ===\n'
printf 'RPC: %s\n' "$RPC_URL"

current_height="$(height)"
printf 'Current block height: %s\n' "$current_height"
if ((current_height <= 0)); then
  printf 'FAIL: no blocks mined yet\n' >&2
  exit 1
fi

require_result system_health
require_result system_version
require_result chain_getBlockHash "[$current_height]"
require_result state_getRuntimeVersion
require_result state_getStorage '["0x"]'
require_result author_pendingExtrinsics
require_result hegemon_consensusStatus
require_result hegemon_walletNotes
require_result da_getParams

printf '=== Hegemon node smoke test passed ===\n'
