#!/usr/bin/env python3
"""Package the accepted v0.11 binaries without rebuilding or changing provenance."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import zipfile

try:
    from . import v011_join as join
except ImportError:  # Direct script invocation.
    import v011_join as join

RELEASE_SOURCE = "9e580878dc46053579607610a46c5865787d6033"
BUILD_SOURCE = "46895bf8734ccedf1e7b31c44a43b9a7212597fc"
BUILD_TREE = "3bfa87d491879734c0f1b69bea65fa374aad3c77"
SOURCE_TREE_SHA256 = "ddd350af0f232b3bfdbe8ed56e51dccb689a4693b3101b436a6f945d6f1bc9fe"
CARGO_LOCK_SHA256 = "1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719"
IDENTITIES = ("hegemon-node", "wallet", "walletd", "private-spend")
PLATFORMS = {
    "linux-x86_64": ("x86_64-unknown-linux-gnu", "elf"),
    "macos-arm64": ("aarch64-apple-darwin", "mach-o"),
    "macos-x86_64": ("x86_64-apple-darwin", "mach-o"),
    "windows-x86_64": ("x86_64-pc-windows-msvc", "pe"),
}
APPROVED_MANIFESTS = {
    "linux-x86_64": "e6b986903cf6b0fec26d7c249269c777eed1ef9333a122437735970adbe51ae6",
    "macos-arm64": "81d1bec4a365644aa21123b416cab8fb82d8fd4ec3e14aac3d0cd839eca68d90",
    "macos-x86_64": "60b57db4fda65d486252bb092ba43ea02fcd67a99a29f385d2545f22b5482742",
    "windows-x86_64": "71e61a899c3b128239bdf5f41c150d414b67458998feb49e7a94bc3b6e6c6155",
}
SOURCE_FILES = ("scripts/package_v011_release.py", "scripts/v011_join.py", "config/testnet/0.11/network-manifest.json", "config/testnet/0.11/release.json", "config/testnet/0.11/README.md")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def native(data, selected):
    if selected == "linux-x86_64":
        valid = len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01" and int.from_bytes(data[18:20], "little") == 62
    elif selected.startswith("macos-"):
        cpu = 0x0100000C if selected == "macos-arm64" else 0x01000007
        valid = len(data) >= 64 and data[:4] == b"\xcf\xfa\xed\xfe" and int.from_bytes(data[4:8], "little") == cpu
    else:
        offset = int.from_bytes(data[60:64], "little") if len(data) >= 64 else 0
        valid = data[:2] == b"MZ" and 64 <= offset <= 1024 * 1024 and data[offset:offset + 6] == b"PE\0\0\x64\x86"
    if not valid:
        join.fail(f"native format/architecture mismatch: {selected}")


def expected_inputs():
    names = set()
    for selected in PLATFORMS:
        names.add(f"hegemon-release-assets-{selected}.json")
        for binary in IDENTITIES:
            name = f"{binary}-{selected}" + (".exe" if selected.startswith("windows") else "")
            names.update((name, name + ".sha256"))
    return names


def validate_assets(directory):
    join.safe_file(directory, "hegemon-release-assets-linux-x86_64.json")
    if {path.name for path in directory.iterdir()} != expected_inputs():
        join.fail("accepted input directory must contain exactly the 36 expected files")
    manifests = {}
    top_fields = {"schema_version", "source_head", "source_index_tree", "source_tree_sha256", "cargo_lock_sha256", "target_triple", "source_manifest_sha256", "assets"}
    asset_fields = {"package", "binary", "name", "sha256", "size", "native_format", "checksum_name"}
    for selected, (triple, fmt) in PLATFORMS.items():
        manifest_name = f"hegemon-release-assets-{selected}.json"
        raw = join.checked_bytes(directory, manifest_name)
        if sha(raw) != APPROVED_MANIFESTS[selected]:
            join.fail(f"unaccepted platform manifest: {selected}")
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=join.unique_object)
        required = {"schema_version": 1, "source_head": BUILD_SOURCE, "source_index_tree": BUILD_TREE, "source_tree_sha256": SOURCE_TREE_SHA256, "cargo_lock_sha256": CARGO_LOCK_SHA256, "target_triple": triple}
        if set(manifest) != top_fields or type(manifest["schema_version"]) is not int or any(manifest[key] != value for key, value in required.items()) or not re.fullmatch(r"[0-9a-f]{64}", manifest["source_manifest_sha256"]):
            join.fail(f"unexpected build provenance: {selected}")
        rows = manifest["assets"]
        if not isinstance(rows, list) or len(rows) != 4:
            join.fail("each platform must have exactly four binaries")
        for binary, row in zip(IDENTITIES, rows):
            name = f"{binary}-{selected}" + (".exe" if selected.startswith("windows") else "")
            required_row = {"package": "wallet" if binary == "private-spend" else binary, "binary": binary, "name": name, "native_format": fmt, "checksum_name": name + ".sha256"}
            if set(row) != asset_fields or any(row[key] != value for key, value in required_row.items()) or type(row["size"]) is not int or not 0 < row["size"] <= join.MAX_FILE or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
                join.fail(f"unexpected binary manifest entry: {name}")
            path = join.safe_file(directory, name)
            if path.stat().st_size != row["size"] or join.digest_file(directory, name) != row["sha256"]:
                join.fail(f"binary size/checksum mismatch: {name}")
            if join.checked_bytes(directory, row["checksum_name"], 256) != f"{row['sha256']}  {name}\n".encode("ascii"):
                join.fail(f"checksum sidecar mismatch: {name}")
            # A bounded prefix contains ELF/Mach-O headers and the accepted PE offset.
            with path.open("rb") as stream:
                native(stream.read(1024 * 1024 + 6), selected)
        manifests[selected] = (manifest, raw)
    return manifests


def quickstart(selected):
    windows = selected.startswith("windows")
    command = "py -3 start.py" if windows else "python3 start.py"
    wallet = "bin\\private-spend.exe" if windows else "./bin/private-spend"
    return f"""# Hegemon v0.11 pre-mainnet: {selected}

Install Python 3 (Windows: include the Python launcher), then verify the published
archive SHA-256 before extracting. No Bash, PowerShell policy bypass, downloads,
wallet keys or proof fixtures are required by this bundle. The checksums detect
file changes; obtain the published checksum through a trusted release channel.

From this extracted directory:

    {command} --check-only
    {command}

Optional wrapper: {'start.cmd' if windows else './start.sh'} (forwards the same options).
The default is a syncing node, no mining, no wallet access, safe RPC on loopback
port 9944, and a separate ~/.hegemon-node-v0.11 database. Never reuse an old-chain
database. --data-dir PATH deliberately selects another v0.11 directory; nothing
is deleted or reset. Keep state and wallet backups outside this release folder.
If another node owns the default ports: {command} --rpc-port 39944 --p2p-port 30335 --data-dir YOUR_NEW_V011_DIRECTORY

To mine, use only your full PUBLIC reward recipient (keep spending keys offline):

    {command} --mine --miner-address YOUR_FULL_PUBLIC_SHCA1_ADDRESS

HEGEMON_MINE=1 and HEGEMON_MINER_ADDRESS are also supported. HEGEMON_NODE_PATH
selects the data directory. All miners use the two approved seeds in release.json;
a conflicting inherited HEGEMON_SEEDS is rejected. Bootstrap authoring is disabled.
Enable NTP/time synchronization; future-skewed blocks are rejected. Rewards mature
after 120 blocks. This launcher joins the already deployed fresh v0.11 network.

For your local native wallet to submit actions, explicitly start with:

    {command} --wallet-rpc

This enables unsafe RPC methods on LOOPBACK ONLY; it never adds --rpc-external.
Keep that listener private; remote wallets use an authenticated SSH tunnel. Use
{wallet} --help for the native HGN wallet. The desktop GUI is qualified for sync
only, not funded sends. No wallet is created or opened by these launchers.

Read operator-guide.md and config/testnet/0.11/release.json. SHA256SUMS covers every
bundled file except itself. bundle.json maps normalized bin paths to the original
accepted assets and records the packaging commit. provenance/ contains the original
platform manifest VERBATIM: its build commit remains {BUILD_SOURCE}; source tree
{BUILD_TREE}. Packaging metadata does not relabel or rebuild those binaries.
""".encode("utf-8")


def members(source, directory, selected, manifest_pair, packaging_commit):
    manifest, raw = manifest_pair
    entries = {}
    mapping = {}
    for row in manifest["assets"]:
        name = "bin/" + row["binary"] + (".exe" if selected.startswith("windows") else "")
        data = join.checked_bytes(directory, row["name"], join.MAX_FILE)
        if len(data) != row["size"] or sha(data) != row["sha256"]:
            join.fail(f"accepted binary changed before packaging: {row['name']}")
        native(data, selected)
        entries[name] = (data, 0o755)
        mapping[name] = {"accepted_name": row["name"], "sha256": row["sha256"]}
    for name in ("network-manifest.json", "release.json"):
        entries[f"config/testnet/0.11/{name}"] = (join.checked_bytes(source, f"config/testnet/0.11/{name}"), 0o644)
    release = json.loads(entries["config/testnet/0.11/release.json"][0], object_pairs_hook=join.unique_object)
    if release.get("cutover_status") != "ready" or release.get("public_genesis_pending") is not False or release.get("network_manifest_sha256") != join.NETWORK_SHA256 or release.get("seeds") != list(join.SEEDS) or release.get("release") != "v0.11" or release.get("network") != "pre-mainnet" or release.get("schema") != "hegemon.pre-mainnet.release.v1":
        join.fail("public release metadata is not ready or does not match the approved network")
    if sha(entries["config/testnet/0.11/network-manifest.json"][0]) != join.NETWORK_SHA256:
        join.fail("network manifest differs from the approved deployment")
    entries["operator-guide.md"] = (join.checked_bytes(source, "config/testnet/0.11/README.md"), 0o644)
    entries["start.py"] = (join.checked_bytes(source, "scripts/v011_join.py"), 0o755)
    if selected.startswith("windows"):
        entries["start.cmd"] = (b'@echo off\r\npy -3 "%~dp0start.py" %*\r\n', 0o644)
    else:
        entries["start.sh"] = (b'#!/bin/sh\nset -eu\nexec python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/start.py" "$@"\n', 0o755)
    entries["QUICKSTART.md"] = (quickstart(selected), 0o644)
    entries[f"provenance/hegemon-release-assets-{selected}.json"] = (raw, 0o644)
    record = {"schema": "hegemon.v011.join-bundle.v1", "release": "v0.11", "platform": selected, "release_binary_source_head": RELEASE_SOURCE, "packaging_source_commit": packaging_commit, "binary_build_source_head": BUILD_SOURCE, "binary_build_index_tree": BUILD_TREE, "original_manifest_sha256": sha(raw), "binaries": mapping, "packaging_inputs": {name: sha(join.checked_bytes(source, name)) for name in SOURCE_FILES}, "files": {name: {"size": len(data), "sha256": sha(data)} for name, (data, _) in sorted(entries.items())}}
    entries["bundle.json"] = (encoded(record), 0o644)
    entries["SHA256SUMS"] = ("".join(f"{sha(data)}  {name}\n" for name, (data, _) in sorted(entries.items())).encode("ascii"), 0o644)
    return entries


def write_archive(path, prefix, entries, windows):
    if windows:
        with path.open("xb") as output, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, (data, mode) in sorted(entries.items()):
                info = zipfile.ZipInfo(f"{prefix}/{name}", (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data, compresslevel=6)
    else:
        with path.open("xb") as output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0, compresslevel=6) as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, (data, mode) in sorted(entries.items()):
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size, info.mode, info.mtime = len(data), mode, 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))


def require_committed_source(source, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        join.fail("packaging commit must be a full lowercase Git commit")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if head != commit:
        join.fail("packaging commit must equal the source checkout HEAD")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *SOURCE_FILES], cwd=source, check=True, stdout=subprocess.DEVNULL)
    tracked = subprocess.check_output(["git", "ls-files", "--", *SOURCE_FILES], cwd=source, text=True).splitlines()
    if set(tracked) != set(SOURCE_FILES):
        join.fail("all packaging inputs must be committed")


def package(source, directory, output, commit):
    manifests = validate_assets(directory)
    # Verify all metadata before creating output, including the final platform.
    for selected in PLATFORMS:
        preview = members(source, directory, selected, manifests[selected], commit)
        del preview
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        join.fail("output must be an empty regular directory; nothing is overwritten")
    sums = []
    for selected in PLATFORMS:
        prefix = f"hegemon-v0.11-{selected}"
        name = prefix + (".zip" if selected.startswith("windows") else ".tar.gz")
        entries = members(source, directory, selected, manifests[selected], commit)
        write_archive(output / name, prefix, entries, selected.startswith("windows"))
        digest = join.digest_file(output, name)
        line = f"{digest}  {name}\n"
        (output / (name + ".sha256")).write_text(line, encoding="ascii")
        sums.append(line)
    (output / "SHA256SUMS").write_text("".join(sums), encoding="ascii")
    return sums


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).absolute().parent.parent)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packaging-commit", required=True)
    args = parser.parse_args(argv)
    try:
        require_committed_source(args.source_root, args.packaging_commit)
        sums = package(args.source_root, args.assets, args.output, args.packaging_commit)
        print("".join(sums), end="")
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"v0.11 packaging: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
