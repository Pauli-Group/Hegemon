#!/usr/bin/env bash
# Start the release-bound v0.11 pre-mainnet node. Default role: sync/relay.
# Mining requires HEGEMON_MINE=1 and HEGEMON_MINER_ADDRESS=<your public address>.
# No wallet is created, opened or deleted. Keep NTP/chrony enabled.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "Usage: ./start.sh (configure mining through HEGEMON_MINE and HEGEMON_MINER_ADDRESS)" >&2
  exit 64
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$ROOT/config/testnet/0.11"
: "${HEGEMON_MINE:=0}"
: "${HEGEMON_MINER_ADDRESS:=}"
: "${HEGEMON_NODE_BIN:=$ROOT/target/release/hegemon-node}"
: "${HEGEMON_NODE_PATH:=$HOME/.hegemon-node-v0.11}"

case "$HEGEMON_MINE" in
  0) ;;
  1)
    if [[ -z "${HEGEMON_MINER_ADDRESS//[[:space:]]/}" ]]; then
      echo "HEGEMON_MINER_ADDRESS must be your full public reward address when mining." >&2
      exit 1
    fi
    ;;
  *) echo "HEGEMON_MINE must be 0 or 1." >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to verify release metadata." >&2; exit 1; }
APPROVED_SEEDS="$(python3 -I -B - "$RELEASE_DIR" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    directory = Path(sys.argv[1])
    release = json.loads((directory / "release.json").read_text(encoding="utf-8"))
    if not isinstance(release, dict) or release.get("schema") != "hegemon.pre-mainnet.release.v1":
        raise ValueError("unsupported release record schema")
    if release.get("release") != "v0.11" or release.get("network") != "pre-mainnet":
        raise ValueError("release/network identity mismatch")
    if release.get("cutover_status") != "ready":
        raise ValueError("v0.11 cutover is pending; keep the old testnet running and wait for the approved release")
    expected = release.get("network_manifest_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("missing frozen network-manifest SHA-256")
    manifest = (directory / "network-manifest.json").read_bytes()
    if hashlib.sha256(manifest).hexdigest() != expected:
        raise ValueError("network-manifest SHA-256 mismatch")
    if json.loads(manifest).get("profile") != "pre-mainnet":
        raise ValueError("network manifest must select pre-mainnet")
    seeds = release.get("seeds")
    if not isinstance(seeds, list) or not seeds or len(seeds) != len(set(seeds)):
        raise ValueError("release seed list must be nonempty and unique")
    if any(not isinstance(seed, str) or not re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", seed) or not 1 <= int(seed.rsplit(":", 1)[1]) <= 65535 for seed in seeds):
        raise ValueError("release contains an invalid seed endpoint")
    if seeds[0] != "hegemon.pauli.group:30333":
        raise ValueError("v0.11 primary seed must be the approved hegemon-ovh endpoint")
    print(",".join(seeds))
except (OSError, ValueError, TypeError, AttributeError) as error:
    print(f"Cannot start v0.11: {error}", file=sys.stderr)
    sys.exit(1)
PYTHON
)"
if [[ -n "${HEGEMON_SEEDS:-}" && "$HEGEMON_SEEDS" != "$APPROVED_SEEDS" ]]; then
  echo "HEGEMON_SEEDS differs from the versioned release seed list; use the approved list." >&2
  exit 1
fi
if [[ ! -x "$HEGEMON_NODE_BIN" ]]; then
  echo "Node binary is not executable: $HEGEMON_NODE_BIN. Build or install the verified v0.11 release." >&2
  exit 1
fi
export HEGEMON_MINE HEGEMON_MINER_ADDRESS
export HEGEMON_SEEDS="$APPROVED_SEEDS"
export HEGEMON_BOOTSTRAP_AUTHORING=0
exec "$HEGEMON_NODE_BIN" \
  --network pre-mainnet \
  --network-manifest "$RELEASE_DIR/network-manifest.json" \
  --base-path "$HEGEMON_NODE_PATH" \
  --rpc-port 9944 \
  --rpc-methods safe \
  --name "Hegemon-v0.11"
