#!/usr/bin/env python3
"""Make reproducible user ZIPs from source-bound, assembled release assets."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
import release_artifact_manifest as manifest

PLATFORMS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-arm64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
PROVENANCE_FIELDS = (
    "source_head", "source_index_tree", "source_tree_sha256", "cargo_lock_sha256",
)
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(root: Path, path: Path, label: str) -> bytes:
    _, relative = manifest._repository_relative(root, path)
    fd = manifest._open_repository_file(root, relative, label)
    try:
        before = os.fstat(fd)
        data = manifest._read_fd(fd)
        if manifest._file_identity(before) != manifest._file_identity(os.fstat(fd)):
            raise manifest.ManifestError(f"{label} changed during read: {relative}")
        return data
    finally:
        os.close(fd)


def launcher_names(platform: str) -> tuple[str, ...]:
    if platform.startswith("windows-"):
        return ("TESTNET-README.txt", "testnet-start.ps1", "testnet-start.cmd")
    return ("TESTNET-README.txt", "testnet-start.sh")


def load_bundle(root: Path, assets_dir: Path, platform: str):
    name = f"hegemon-release-assets-{platform}.json"
    payload, files = manifest._load_asset_bundle(root, assets_dir / name, False)
    if payload["target_triple"] != PLATFORMS[platform]:
        raise manifest.ManifestError(f"unexpected target for {platform}")
    suffix = ".exe" if platform.startswith("windows-") else ""
    expected_names = [f"{binary}-{platform}{suffix}" for _, binary in manifest.EXPECTED_ARTIFACTS]
    if [item["name"] for item in payload["assets"]] != expected_names:
        raise manifest.ManifestError(f"unexpected executable names for {platform}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("source_manifest_sha256", ""))):
        raise manifest.ManifestError(f"missing source manifest digest for {platform}")
    return payload, files


def package_downloads(root: Path, assets_dir: Path, launchers_dir: Path, version: str):
    if not re.fullmatch(r"0\.10\.[0-9]+", version):
        raise manifest.ManifestError("version must be a stable 0.10.x maintenance version")
    root = Path(os.path.abspath(root))
    assets_dir, assets_relative = manifest._repository_relative(root, assets_dir)
    launchers_dir, _ = manifest._repository_relative(root, launchers_dir)
    output_dir = manifest._open_directory_beneath(root, assets_relative, "release assets")
    try:
        canonical = None
        expected_files = set()
        verified_manifests = {}
        # Validate every raw platform before producing any downloadable output.
        for platform in PLATFORMS:
            payload, files = load_bundle(root, assets_dir, platform)
            provenance = {field: payload.get(field) for field in PROVENANCE_FIELDS}
            for field, value in provenance.items():
                length = 40 if field in {"source_head", "source_index_tree"} else 64
                if not re.fullmatch(f"[0-9a-f]{{{length}}}", str(value)):
                    raise manifest.ManifestError(f"invalid source provenance: {field}")
            if canonical is None:
                canonical = provenance
            elif provenance != canonical:
                raise manifest.ManifestError("platforms do not share source provenance")
            expected_files.update(files)
            manifest_name = f"hegemon-release-assets-{platform}.json"
            verified_manifests[platform] = digest(files[manifest_name])
            del files
        current = {
            "source_head": manifest.run_git(root, "rev-parse", "HEAD").decode().strip(),
            "source_index_tree": manifest.run_git(root, "write-tree").decode().strip(),
            "cargo_lock_sha256": digest(read_regular(root, root / "Cargo.lock", "Cargo.lock")),
        }
        for field, value in current.items():
            if canonical[field] != value:
                raise manifest.ManifestError(f"source provenance differs from checkout: {field}")
        actual_files = set()
        scan_target = output_dir.fd if output_dir.fd is not None else output_dir.path
        with os.scandir(scan_target) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or manifest._is_reparse_point(metadata):
                    raise manifest.ManifestError(f"non-regular release asset entry: {entry.name}")
                actual_files.add(entry.name)
        if actual_files != expected_files:
            raise manifest.ManifestError("assembled raw asset file-set mismatch (outputs must not already exist)")
        launchers = {}
        for name in sorted({name for platform in PLATFORMS for name in launcher_names(platform)}):
            data = read_regular(root, launchers_dir / name, "release launcher")
            _, relative = manifest._repository_relative(root, launchers_dir / name)
            try:
                committed = manifest.run_git(root, "show", f"HEAD:{relative}")
            except subprocess.CalledProcessError as exc:
                raise manifest.ManifestError(f"launcher is not committed: {relative}") from exc
            if data != committed:
                raise manifest.ManifestError(f"launcher differs from committed source: {relative}")
            launchers[name] = data
        archives = []
        for platform in PLATFORMS:
            payload, files = load_bundle(root, assets_dir, platform)
            if {field: payload.get(field) for field in PROVENANCE_FIELDS} != canonical:
                raise manifest.ManifestError("source provenance changed during packaging")
            raw_manifest = f"hegemon-release-assets-{platform}.json"
            if digest(files[raw_manifest]) != verified_manifests[platform]:
                raise manifest.ManifestError("raw asset manifest changed during packaging")
            archive_name = f"hegemon-testnet-{version}-{platform}.zip"
            contents = {**files, **{name: launchers[name] for name in launcher_names(platform)}}
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = manifest._open_at(output_dir, archive_name, flags, 0o644)
            with os.fdopen(fd, "w+b") as handle:
                with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    for name, data in sorted(contents.items()):
                        info = zipfile.ZipInfo(name, FIXED_TIME)
                        info.create_system = 3
                        mode = 0o755 if name in [item["name"] for item in payload["assets"]] or name == "testnet-start.sh" else 0o644
                        info.external_attr = (stat.S_IFREG | mode) << 16
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
                handle.flush()
                size = handle.tell()
                handle.seek(0)
                archive_digest = hashlib.sha256()
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    archive_digest.update(chunk)
                checksum = archive_digest.hexdigest()
            checksum_name = f"{archive_name}.sha256"
            manifest._write_exclusive_at(output_dir, checksum_name, f"{checksum}  {archive_name}\n".encode("ascii"), 0o644)
            archives.append({
                "platform": platform, "target_triple": payload["target_triple"],
                "name": archive_name, "sha256": checksum, "size": size,
                "checksum_name": checksum_name, "asset_manifest_name": raw_manifest,
                "asset_manifest_sha256": digest(files[raw_manifest]),
                "launchers": [{"name": name, "sha256": digest(launchers[name]), "size": len(launchers[name])} for name in launcher_names(platform)],
            })
        output = {"schema_version": 1, "release_version": version, **canonical, "archives": archives}
        name = f"hegemon-testnet-downloads-{version}.json"
        manifest._write_exclusive_at(output_dir, name, (json.dumps(output, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o644)
        return output
    finally:
        output_dir.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--launchers-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        output = package_downloads(args.root, args.assets_dir, args.launchers_dir, args.version)
    except (OSError, subprocess.CalledProcessError, manifest.ManifestError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
