#!/usr/bin/env python3
"""Package one native v0.11.6 local test candidate from a clean build checkout."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def sibling(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("_candidate_" + name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


previous = sibling("package_v0115_release")
base = previous.base
join = base.join
artifacts = sibling("release_artifact_manifest")
VERSION = "0.11.6"
CONFIG = "config/testnet/0.11/"
PREVIOUS_METADATA_SHA256 = "00c2be8dc617642d6f5f2e473848616e74ba3d3a9fa8fe8a01d76787253a00ec"


def check_checkout(root):
    if previous.git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("candidate packaging requires a clean committed checkout")
    product = join.checked_bytes(root, "protocol/versioning/src/lib.rs").decode()
    if re.findall(r'^pub const RELEASE_VERSION: &str = "([^"]+)";$', product, re.M) != [VERSION]:
        raise ValueError("candidate source product version differs from v0.11.6")
    if join.digest_file(root, "Cargo.lock") != previous.LOCK_SHA256:
        raise ValueError("candidate Cargo.lock differs from the frozen pre-mainnet lock")
    old = join.checked_bytes(root, CONFIG + "release-v0115.json")
    if base.sha(old) != PREVIOUS_METADATA_SHA256:
        raise ValueError("previous network release metadata changed")
    expected = json.loads(old)
    expected.update(software_release="v" + VERSION, software_version=VERSION)
    if join.read_json(root, CONFIG + "release-v0116.json") != expected:
        raise ValueError("candidate metadata differs from the deployed pre-mainnet identity")
    if join.digest_file(root, CONFIG + "network-manifest.json") != join.NETWORK_SHA256:
        raise ValueError("candidate pre-mainnet network manifest changed")


def verify_product_cli(directory, selected):
    suffix = ".exe" if selected.startswith("windows") else ""

    def output(binary, *args):
        executable = join.safe_file(directory, f"{binary}-{selected}{suffix}")
        return subprocess.check_output(
            [str(executable), *args], stdin=subprocess.DEVNULL, timeout=30, text=True
        )

    for binary in ("hegemon-node", "wallet", "private-spend"):
        if output(binary, "--version").strip() != f"{binary} {VERSION}":
            raise ValueError(f"candidate {binary} reports the wrong product version")
    if "--solo-payout-schedule" not in output("hegemon-node", "--help"):
        raise ValueError("candidate node is missing the solo payout option")
    if "--first-height" not in output("wallet", "solo-payout-schedule", "--help"):
        raise ValueError("candidate wallet is missing the solo payout schedule exporter")
    # walletd has a JSON-lines protocol and implements --help without --version.
    if not output("walletd", "--help").strip():
        raise ValueError("candidate walletd did not return its command help")


def archive_members(root, directory, selected, source_raw, asset_name, asset_manifest):
    windows = selected.startswith("windows")
    suffix = ".exe" if windows else ""
    entries = {}
    binaries = {}
    for row in asset_manifest["assets"]:
        name = "bin/" + row["binary"] + suffix
        data = join.checked_bytes(directory, row["name"], join.MAX_FILE)
        if len(data) != row["size"] or base.sha(data) != row["sha256"]:
            raise ValueError(f"candidate binary changed before archiving: {name}")
        base.native(data, selected)
        entries[name] = (data, 0o755)
        binaries[name] = {"asset_name": row["name"], "sha256": row["sha256"]}

    for name, source in {
        CONFIG + "release.json": CONFIG + "release-v0116.json",
        CONFIG + "network-manifest.json": CONFIG + "network-manifest.json",
        "operator-guide.md": "runbooks/miner_wallet_quickstart.md",
        "RELEASE_NOTES.md": "docs/releases/V0.11.6_PREPARATION.md",
    }.items():
        entries[name] = (join.checked_bytes(root, source), 0o644)
    entries["start.py"] = (join.checked_bytes(root, "scripts/v011_join.py"), 0o755)
    if windows:
        entries["start.cmd"] = (b'@echo off\r\npy -3 "%~dp0start.py" %*\r\n', 0o644)
    else:
        entries["start.sh"] = (
            b'#!/bin/sh\nset -eu\nexec python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/start.py" "$@"\n',
            0o755,
        )
    entries["provenance/hegemon-release-artifacts.json"] = (source_raw, 0o644)
    asset_raw = join.checked_bytes(directory, asset_name)
    if base.sha(source_raw) != asset_manifest["source_manifest_sha256"] or json.loads(asset_raw) != asset_manifest:
        raise ValueError("candidate provenance manifests changed during packaging")
    entries["provenance/" + asset_name] = (asset_raw, 0o644)
    record = {
        "schema": "hegemon.v011.join-bundle.v1",
        "release": "v0.11",
        "software_release": "v" + VERSION,
        "software_version": VERSION,
        "build_channel": "local-candidate",
        "platform": selected,
        "binary_build_source_head": asset_manifest["source_head"],
        "binary_build_index_tree": asset_manifest["source_index_tree"],
        "packaging_source_commit": asset_manifest["source_head"],
        "original_manifest_sha256": base.sha(asset_raw),
        "binaries": binaries,
        "files": {
            name: {"size": len(data), "sha256": base.sha(data)}
            for name, (data, _) in entries.items()
        },
    }
    entries["bundle.json"] = (base.encoded(record), 0o644)
    sums = "".join(f"{base.sha(data)}  {name}\n" for name, (data, _) in sorted(entries.items()))
    entries["SHA256SUMS"] = (sums.encode("ascii"), 0o644)
    return entries


def package(root: Path, selected: str, manifest_path: Path, output: Path) -> Path:
    root = root.resolve()
    check_checkout(root)
    triple = base.PLATFORMS[selected][0]
    manifest_path = root / manifest_path
    raw = join.checked_bytes(root, manifest_path.relative_to(root).as_posix())
    source = json.loads(raw, object_pairs_hook=join.unique_object)
    if source.get("target_triple") != triple:
        raise ValueError("candidate target triple does not match the selected platform")
    # Build script supports both native and explicit --target layouts.
    release_dir = Path(source["artifacts"][0]["path"]).parent
    if release_dir not in (Path("target/release"), Path("target") / triple / "release"):
        raise ValueError("expected release binaries under target/release or target/TRIPLE/release")
    suffix = ".exe" if selected.startswith("windows") else ""
    expects = [f"{pkg}:{binary}:{(release_dir / (binary + suffix)).as_posix()}" for pkg, binary in artifacts.EXPECTED_ARTIFACTS]
    names = [f"{pkg}:{binary}:{binary}-{selected}{suffix}" for pkg, binary in artifacts.EXPECTED_ARTIFACTS]
    asset_name = f"hegemon-release-assets-{selected}.json"
    with tempfile.TemporaryDirectory(prefix="candidate-pack-", dir=root / "target") as scratch:
        directory = Path(scratch) / "assets"
        manifest = artifacts.package_artifacts(root, manifest_path, expects, names, directory, asset_name)
        commit = manifest["source_head"]
        if (manifest["source_index_tree"] != previous.git(root, "rev-parse", "HEAD^{tree}").decode().strip()
                or manifest["source_tree_sha256"] != previous.committed_tree_sha256(root, commit)):
            raise ValueError("candidate build manifest differs from its committed source tree")
        verify_product_cli(directory, selected)
        entries = archive_members(root, directory, selected, raw, asset_name, manifest)
    if previous.git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("candidate checkout moved during packaging")
    check_checkout(root)
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        raise ValueError("candidate output must be an empty directory")
    prefix = f"hegemon-v{VERSION}-local-candidate-{selected}"
    windows = selected.startswith("windows")
    name = prefix + (".zip" if windows else ".tar.gz")
    with tempfile.TemporaryDirectory(prefix="pack-", dir=output) as scratch:
        staged = Path(scratch)
        base.write_archive(staged / name, prefix, entries, windows)
        digest = join.digest_file(staged, name)
        sidecar = name + ".sha256"
        (staged / sidecar).write_bytes(f"{digest}  {name}\n".encode("ascii"))
        os.link(staged / name, output / name)
        try:
            os.link(staged / sidecar, output / sidecar)
        except OSError:
            (output / name).unlink()
            raise
    return output / name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=base.PLATFORMS)
    parser.add_argument("--manifest", required=True, type=Path, help="original source build manifest under the checkout")
    parser.add_argument("--output", required=True, type=Path, help="new or empty local candidate directory")
    args = parser.parse_args(argv)
    try:
        print(package(Path(__file__).resolve().parent.parent, args.platform, args.manifest, args.output))
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError, artifacts.ManifestError) as error:
        parser.exit(1, f"v0.11.6 local candidate: {error}\n")


if __name__ == "__main__":
    main()
