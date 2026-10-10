#!/usr/bin/env bash
set -euo pipefail

# Hegemon 0.10.2: the existing public testnet, not the newer Bitcoin80 chain.
script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
expected_genesis="0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59"
data_dir="${HOME:?HOME must identify your user directory}/.hegemon-testnet"
rpc_port=9944
p2p_port=30333
mine=0
status=0

usage() {
  cat <<'EOF'
Hegemon 0.10.2 public testnet launcher
Usage: bash testnet-start.sh [--mine] [--data-dir PATH] [--rpc-port PORT] [--port PORT]
       bash testnet-start.sh --status [--rpc-port PORT]
Default: relay mode, persistent ~/.hegemon-testnet, loopback HTTP RPC on port 9944.
--mine requires HEGEMON_MINER_ADDRESS set to your existing public receive address.
--status reads the running local node; it does not start one.
See TESTNET-README.txt for chain checks and mining setup.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mine) mine=1; shift ;;
    --status) status=1; shift ;;
    --data-dir|--rpc-port|--port)
      option="$1"
      if [[ $# -lt 2 || -z "$2" ]]; then
        printf 'Missing value for %s\n' "$option" >&2
        exit 2
      fi
      case "$option" in
        --data-dir) data_dir="$2" ;;
        --rpc-port) rpc_port="$2" ;;
        --port) p2p_port="$2" ;;
      esac
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

for port_value in "$rpc_port" "$p2p_port"; do
  if [[ ! "$port_value" =~ ^[0-9]{1,5}$ ]] || (( 10#$port_value < 1 || 10#$port_value > 65535 )); then
    printf 'Port must be between 1 and 65535: %s\n' "$port_value" >&2
    exit 2
  fi
done

if [[ "$status" == 1 ]]; then
  printf 'Expected testnet genesis: %s\n' "$expected_genesis"
  curl --fail --silent --show-error --connect-timeout 3 --max-time 15 \
    -H 'Content-Type: application/json' \
    --data '[{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]},{"jsonrpc":"2.0","id":2,"method":"chain_getHeader","params":[]},{"jsonrpc":"2.0","id":3,"method":"chain_getBlockHash","params":[0]},{"jsonrpc":"2.0","id":4,"method":"hegemon_miningStatus","params":[]},{"jsonrpc":"2.0","id":5,"method":"system_version","params":[]}]' \
    "http://127.0.0.1:$rpc_port/"
  printf '\n'
  exit 0
fi

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) binary="$script_dir/hegemon-node-linux-x86_64" ;;
  Darwin:x86_64) binary="$script_dir/hegemon-node-macos-x86_64" ;;
  Darwin:arm64|Darwin:aarch64) binary="$script_dir/hegemon-node-macos-arm64" ;;
  *) printf 'This bundle supports Linux x86_64 and macOS Intel/Apple Silicon.\n' >&2; exit 2 ;;
esac
if [[ ! -f "$binary" || ! -x "$binary" ]]; then
  printf 'Place the matching release binary beside this script and make it executable:\n  chmod +x "%s"\n' "$binary" >&2
  exit 2
fi
payout_address="${HEGEMON_MINER_ADDRESS:-}"
if [[ "$mine" == 1 && -z "${payout_address//[[:space:]]/}" ]]; then
  printf 'Set HEGEMON_MINER_ADDRESS to your existing public receive address before --mine.\n' >&2
  exit 2
fi

export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
export HEGEMON_MINE="$mine"
export HEGEMON_BOOTSTRAP_AUTHORING=0
export NO_COLOR="${NO_COLOR:-1}"
export RUST_LOG="${RUST_LOG:-hegemon_node=info,consensus=info,network=info}"
printf 'Hegemon 0.10.2 testnet; mining=%s; data=%s; RPC=http://127.0.0.1:%s\n' "$mine" "$data_dir" "$rpc_port"
printf 'Seeds: %s\nExpected genesis: %s\n' "$HEGEMON_SEEDS" "$expected_genesis"
if [[ "$mine" == 1 ]]; then
  printf 'Mining requires synchronized system time and a verified canonical chain.\n'
fi
exec "$binary" --dev --base-path "$data_dir" --rpc-methods safe \
  --rpc-port "$rpc_port" --port "$p2p_port" --name HegemonTestnet
