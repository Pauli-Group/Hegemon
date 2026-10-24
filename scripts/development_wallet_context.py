#!/usr/bin/env python3
"""Write launch_wallet_prepare's pinned context from a local Development node."""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request


def rpc(endpoint: str, method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(endpoint, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read(1024 * 1024 + 1))
    if result.get("error"):
        raise ValueError(f"RPC {method} failed")
    return result.get("result")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True, help="explicit loopback HTTP node RPC endpoint")
    parser.add_argument("--out", required=True, type=Path, help="new context.json path")
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.rpc)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("RPC endpoint must be loopback HTTP")
    config = rpc(args.rpc, "hegemon_nodeConfig", [])
    manifest = config.get("networkManifest") or {}
    candidate = manifest.get("development_candidate")
    if (config.get("networkProfile") != "development"
            or manifest.get("profile") != "development" or not candidate):
        raise ValueError("node is not running a Development candidate manifest")
    chain_id = config.get("chainId", "")
    digest = config.get("networkManifestDigest", "")
    genesis = rpc(args.rpc, "chain_getBlockHash", [0])
    if not isinstance(chain_id, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", chain_id):
        raise ValueError("node returned an invalid 32-byte chain ID")
    if not isinstance(genesis, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", genesis):
        raise ValueError("node returned an invalid 32-byte genesis hash")
    if not isinstance(digest, str) or not re.fullmatch(r"0x[0-9a-fA-F]{128}", digest):
        raise ValueError("node returned an invalid 64-byte validated manifest digest")
    activation = candidate.get("activation_height")
    end = candidate.get("deactivation_height_exclusive")
    root = candidate.get("stablecoin_genesis_root")
    if (type(activation) is not int or type(end) is not int or not 0 < activation < end
            or not isinstance(root, list) or len(root) != 7
            or any(type(word) is not int or not 0 <= word < 0xffff_ffff_0000_0001 for word in root)):
        raise ValueError("node returned invalid Development candidate lifetime or stablecoin root")
    context = {"chain_id": chain_id.lower(), "genesis_hash": genesis.lower(),
               "manifest_digest": digest.lower(), "activation_height": activation,
               "deactivation_height_exclusive": end, "stablecoin_genesis_root": root}
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(context, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(str(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
