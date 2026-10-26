#!/usr/bin/env python3
"""Launch an integrity-checked v0.11 join bundle; never create wallet material."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys

SEEDS = ("hegemon.pauli.group:30333", "devnet.hegemonprotocol.com:30333")
NETWORK_SHA256 = "386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754"
MAX_FILE = 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def path_matches_open_file(path_stat, opened_stat):
    # Windows path stat reports creation ctime, while fstat can report change
    # ctime. Compare birthtime for that cross-API pair, retaining file ID,
    # device, size and mtime; same-API before/after checks still compare ctime.
    if os.name == "nt":
        path_birth = getattr(path_stat, "st_birthtime_ns", None)
        opened_birth = getattr(opened_stat, "st_birthtime_ns", None)
        if path_birth is not None or opened_birth is not None:
            return path_birth is not None and opened_birth is not None and identity(path_stat)[:4] + (path_birth,) == identity(opened_stat)[:4] + (opened_birth,)
    return identity(path_stat) == identity(opened_stat)


def safe_file(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or relative.as_posix() != name or any(
        part in ("", ".", "..") or ":" in part or "\\" in part for part in relative.parts
    ):
        fail(f"invalid bundle path: {name!r}")
    current = root
    for part in (None, *relative.parts):
        if part is not None:
            current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            fail(f"symlink/reparse point is not allowed: {current}")
        if current != root / relative and not stat.S_ISDIR(info.st_mode):
            fail(f"not a directory: {current}")
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        fail(f"not a bounded regular file: {name}")
    return current


def checked_bytes(root: Path, name: str, limit: int = 1024 * 1024) -> bytes:
    path = safe_file(root, name)
    before = path.stat()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    safe_file(root, name)
    if len(data) > limit or not path_matches_open_file(before, opened) or identity(opened) != identity(after) or not path_matches_open_file(path.stat(), after):
        fail(f"file changed or exceeded size bound: {name}")
    return data


def digest_file(root: Path, name: str) -> str:
    path = safe_file(root, name)
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    safe_file(root, name)
    if not path_matches_open_file(before, opened) or identity(opened) != identity(after) or not path_matches_open_file(path.stat(), after):
        fail(f"file changed while hashing: {name}")
    return digest.hexdigest()


def read_json(root: Path, name: str):
    return json.loads(checked_bytes(root, name).decode("utf-8"), object_pairs_hook=unique_object)


def verify_bundle(root: Path, *, check_host: bool = True):
    sums = checked_bytes(root, "SHA256SUMS").decode("ascii")
    expected = {}
    for line in sums.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in expected or match[2] == "SHA256SUMS":
            fail("invalid or duplicate SHA256SUMS entry")
        expected[match[2]] = match[1]
    if "bundle.json" not in expected or "start.py" not in expected:
        fail("incomplete bundle checksums")
    for name, digest in expected.items():
        if digest_file(root, name) != digest:
            fail(f"bundle checksum mismatch: {name}")
    bundle = read_json(root, "bundle.json")
    if bundle.get("schema") != "hegemon.v011.join-bundle.v1" or bundle.get("release") != "v0.11":
        fail("not a v0.11 join bundle")
    if set(bundle.get("files", {})) != set(expected) - {"bundle.json"}:
        fail("bundle file inventory disagrees with SHA256SUMS")
    for name, details in bundle["files"].items():
        if details != {"sha256": expected[name], "size": safe_file(root, name).stat().st_size}:
            fail(f"bundle inventory mismatch: {name}")
    selected = bundle.get("platform")
    hosts = {("linux", "x86_64"): "linux-x86_64", ("darwin", "x86_64"): "macos-x86_64", ("darwin", "arm64"): "macos-arm64", ("win32", "amd64"): "windows-x86_64", ("win32", "x86_64"): "windows-x86_64"}
    if check_host and hosts.get((sys.platform, platform.machine().lower())) != selected:
        fail(f"wrong archive for this operating system/architecture: {selected}")
    release = read_json(root, "config/testnet/0.11/release.json")
    manifest_name = "config/testnet/0.11/network-manifest.json"
    if release.get("schema") != "hegemon.pre-mainnet.release.v1" or release.get("release") != "v0.11" or release.get("network") != "pre-mainnet" or release.get("cutover_status") != "ready" or release.get("public_genesis_pending") is not False:
        fail("release record is not ready for public v0.11 joining")
    if release.get("network_manifest_sha256") != NETWORK_SHA256 or digest_file(root, manifest_name) != NETWORK_SHA256 or release.get("seeds") != list(SEEDS):
        fail("frozen network identity/approved seeds mismatch")
    manifest = read_json(root, manifest_name)
    if manifest.get("profile") != "pre-mainnet":
        fail("wrong network manifest profile")
    binary = "bin/hegemon-node.exe" if selected == "windows-x86_64" else "bin/hegemon-node"
    if binary not in expected:
        fail("missing bundled node")
    return root / binary


def port_number(value):
    try:
        number = int(value)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535") from error
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535")
    return number


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mine", action="store_true", help="explicitly enable mining; requires a full public reward address")
    parser.add_argument("--miner-address", help="public recipient only; never a key or seed")
    parser.add_argument("--wallet-rpc", action="store_true", help="enable submission RPC on loopback only for your local native wallet")
    parser.add_argument("--data-dir", help="deliberately selected v0.11 node database; never an old-chain directory")
    parser.add_argument("--rpc-port", type=port_number, default=9944, help="loopback RPC port, 1..65535 (default: 9944)")
    parser.add_argument("--p2p-port", type=port_number, default=30333, help="peer listener port, 1..65535 (default: 30333)")
    parser.add_argument("--check-only", action="store_true", help="verify bundle and print public launch arguments without starting a node")
    return parser.parse_args(argv)


def launch_command(root: Path, args, environment):
    binary = verify_bundle(root)
    env = dict(environment)
    seeds = ",".join(SEEDS)
    if "HEGEMON_SEEDS" in env and env["HEGEMON_SEEDS"] != seeds:
        fail("inherited HEGEMON_SEEDS differs from the approved release list")
    if "HEGEMON_NODE_BIN" in env and Path(env["HEGEMON_NODE_BIN"]).absolute() != binary.absolute():
        fail("HEGEMON_NODE_BIN must name this bundle's verified node")
    mine_value = env.get("HEGEMON_MINE", "0")
    if mine_value not in ("0", "1"):
        fail("HEGEMON_MINE must be exactly 0 or 1")
    mining = args.mine or mine_value == "1"
    recipient = args.miner_address or env.get("HEGEMON_MINER_ADDRESS", "")
    if mining and not re.fullmatch(r"shca1[023456789acdefghjklmnpqrstuvwxyz]{100,4096}", recipient):
        fail("mining requires a full public shca1 recipient; the node checks its checksum and network")
    if recipient and not mining:
        fail("a reward address requires explicit --mine or HEGEMON_MINE=1")
    data_dir = Path(args.data_dir or env.get("HEGEMON_NODE_PATH") or Path.home() / ".hegemon-node-v0.11").expanduser().absolute()
    if data_dir == root or root in data_dir.parents:
        fail("keep node state outside the release bundle")
    env.update(HEGEMON_SEEDS=seeds, HEGEMON_MINE="1" if mining else "0", HEGEMON_BOOTSTRAP_AUTHORING="0")
    if mining:
        env["HEGEMON_MINER_ADDRESS"] = recipient
    else:
        env.pop("HEGEMON_MINER_ADDRESS", None)
    command = [str(binary), "--network", "pre-mainnet", "--network-manifest", str(root / "config/testnet/0.11/network-manifest.json"), "--base-path", str(data_dir), "--rpc-port", str(args.rpc_port), "--port", str(args.p2p_port), "--rpc-methods", "unsafe" if args.wallet_rpc else "safe", "--name", "Hegemon-v0.11"]
    return command, env


def main(argv=None):
    args = arguments(argv)
    try:
        root = Path(__file__).absolute().parent
        command, env = launch_command(root, args, os.environ)
        if args.check_only:
            print(json.dumps({"command": command, "environment": {key: env[key] for key in ("HEGEMON_SEEDS", "HEGEMON_MINE", "HEGEMON_BOOTSTRAP_AUTHORING")}, "wallet_rpc": args.wallet_rpc}, indent=2))
            return 0
        os.execve(command[0], command, env)
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        print(f"v0.11 launcher: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
