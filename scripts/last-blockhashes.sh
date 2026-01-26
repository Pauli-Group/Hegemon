#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:9944}"
COUNT="${1:-3}"

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
  echo "usage: $0 [count>=1]" >&2
  exit 1
fi

python3 - "$RPC_URL" "$COUNT" <<'PY'
import json
import sys
import urllib.request

url = sys.argv[1]
count = int(sys.argv[2])

def rpc(method, params=None, rpc_id=1):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    if "error" in data:
        raise SystemExit(f"RPC error: {data['error']}")
    return data["result"]

header = rpc("chain_getHeader")
best = int(header["number"], 16)

for i in range(count):
    height = best - i
    if height < 0:
        break
    block_hash = rpc("chain_getBlockHash", [height], rpc_id=2 + i)
    print(block_hash)
PY
