#!/usr/bin/env python3
"""Restore the authenticated v0.11 predecessor for unchanged evidence checks.

This restores retained, public evidence. It grants no authority to new source,
new binaries or a deployment. The original checker must still accept its exact
inputs; release successor validation is a separate gate.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "release-evidence/v0.11-predecessor"
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_PART_BYTES = 40 * 1024**2
MAX_MANIFEST_BYTES = 8 * 1024**2
DISK_RESERVE_BYTES = 15 * 1024**3
CHUNK = 1024**2
SCHEMA = "hegemon.v011.portable-predecessor.v1"
# Source-reviewed transport identity; the archive cannot nominate its own code.
SOURCE_MANIFEST_SHA256 = "dbec7e35d7402e687c3a3aa19f70c45425a127a915c74185eb0054ed57aa76fc"


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def keys(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected), label + " keys differ")


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def relative(name):
    require(isinstance(name, str) and name and "\\" not in name and "\0" not in name,
            "invalid archive path")
    require(name.isascii() and not any(ord(char) < 32 or char in ':*?"<>|' for char in name),
            "nonportable archive path")
    p = PurePosixPath(name)
    devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
        prefix + str(index) for prefix in ("COM", "LPT") for index in range(1, 10)}
    require(all(not part.endswith((" ", ".")) and part.split(".")[0].upper() not in devices
                for part in p.parts), "reserved archive path")
    require(not p.is_absolute() and p.as_posix() == name and
            all(piece not in (".", "..") for piece in p.parts), "noncanonical archive path")
    return p


def regular(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            "not a single-link regular file: " + str(path))


def no_symlink_components(path):
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            require(not item.is_symlink(), "symlink path component: " + str(item))


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            value.update(block)
    return value.hexdigest()


def valid_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")


def load_manifest(file):
    no_symlink_components(file)
    regular(file)
    require(file.stat().st_size <= MAX_MANIFEST_BYTES, "manifest too large")
    value = json.loads(file.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    keys(value, ("schema", "scope", "source_checker_sha256", "source_registry_sha256",
                 "closure_inventory_sha256", "files", "file_count", "total_file_bytes",
                 "tar_bytes", "compressed_bytes", "archive_sha256", "parts"), "manifest")
    require(value["schema"] == SCHEMA, "wrong manifest schema")
    require(isinstance(value["scope"], str) and value["scope"], "missing predecessor scope")
    for key in ("source_checker_sha256", "source_registry_sha256", "closure_inventory_sha256", "archive_sha256"):
        valid_hash(value[key])
    files = value["files"]
    require(isinstance(files, list) and 0 < len(files) <= MAX_FILES and
            type(value["file_count"]) is int and value["file_count"] == len(files), "file count differs")
    names = set()
    for row in files:
        keys(row, ("path", "bytes", "sha256", "mode"), "file record")
        relative(row["path"])
        require(row["path"] not in names, "duplicate archive file")
        names.add(row["path"])
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_TOTAL_BYTES, "invalid file size")
        require(type(row["mode"]) is int and row["mode"] in (0o444, 0o600, 0o644, 0o755), "unsafe file mode")
        valid_hash(row["sha256"])
    require([row["path"] for row in files] == sorted(names), "file inventory must be sorted")
    require(len({name.casefold() for name in names}) == len(names), "case-insensitive path collision")
    for name in names:
        require(not any(parent.as_posix() in names for parent in PurePosixPath(name).parents
                        if parent.as_posix() != "."), "file used as parent directory")
    by_name = {row["path"]: row for row in files}
    for name, key in (("scripts/check_private_spend_launch_authorization.py", "source_checker_sha256"),
                      ("scripts/private_spend_launch_authorized_registry.json", "source_registry_sha256")):
        if name in by_name:
            require(by_name[name]["sha256"] == value[key], "recorded predecessor authority hash differs")
    total = sum(row["bytes"] for row in files)
    require(type(value["total_file_bytes"]) is int and value["total_file_bytes"] == total and
            total <= MAX_TOTAL_BYTES, "total size differs or exceeds cap")
    require(type(value["tar_bytes"]) is int and total <= value["tar_bytes"] <= MAX_TOTAL_BYTES + 64 * 1024**2,
            "invalid expanded archive bound")
    parts = value["parts"]
    require(isinstance(parts, list) and 0 < len(parts) <= 128, "invalid part count")
    for index, row in enumerate(parts):
        keys(row, ("path", "bytes", "sha256"), "archive part")
        require(row["path"] == f"part-{index:04d}.tar.gz.part", "noncanonical part name")
        require(type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_PART_BYTES, "part exceeds cap")
        valid_hash(row["sha256"])
    require(type(value["compressed_bytes"]) is int and
            value["compressed_bytes"] == sum(row["bytes"] for row in parts), "compressed size differs")
    return value


def verify_parts(bundle, manifest):
    archive_hash = hashlib.sha256()
    for row in manifest["parts"]:
        file = bundle / row["path"]
        no_symlink_components(file)
        regular(file)
        require(file.stat().st_size == row["bytes"], "archive part size differs")
        value = hashlib.sha256()
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(CHUNK), b""):
                value.update(block)
                archive_hash.update(block)
        require(value.hexdigest() == row["sha256"], "archive part hash differs")
    require(archive_hash.hexdigest() == manifest["archive_sha256"], "complete archive hash differs")


class PartsReader(io.RawIOBase):
    def __init__(self, bundle, parts):
        self.bundle, self.parts = bundle, iter(parts)
        self.current = None

    def readable(self):
        return True

    def readinto(self, buffer):
        while True:
            if self.current is None:
                row = next(self.parts, None)
                if row is None:
                    return 0
                file = self.bundle / row["path"]
                regular(file)
                self.current = file.open("rb")
            count = self.current.readinto(buffer)
            if count:
                return count
            self.current.close()
            self.current = None

    def close(self):
        if self.current:
            self.current.close()
        super().close()


class ExpandedReader(io.RawIOBase):
    def __init__(self, stream, limit):
        self.stream, self.limit, self.count = stream, limit, 0

    def readable(self):
        return True

    def readinto(self, buffer):
        # One extra byte detects expansion beyond the declared cap.
        block = self.stream.read(min(len(buffer), self.limit - self.count + 1))
        self.count += len(block)
        require(self.count <= self.limit, "expanded archive exceeds bound")
        buffer[:len(block)] = block
        return len(block)


def verify_tree(destination, manifest):
    no_symlink_components(destination)
    require(destination.is_dir(), "predecessor destination is not a directory")
    expected = {row["path"]: row for row in manifest["files"]}
    directories = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents
                   if parent.as_posix() != "."}
    seen = set()
    for parent, dirs, files in os.walk(destination, followlinks=False):
        for name in dirs:
            item = Path(parent) / name
            require(not item.is_symlink(), "symlink in restored tree")
            require(item.relative_to(destination).as_posix() in directories, "extra restored directory")
        for name in files:
            item = Path(parent) / name
            regular(item)
            name = item.relative_to(destination).as_posix()
            require(name in expected and name not in seen, "extra or duplicate restored file")
            row = expected[name]
            require(item.stat().st_size == row["bytes"] and sha256(item) == row["sha256"],
                    "restored file bytes differ: " + name)
            # Windows has no equivalent for the retained POSIX execute/group bits.
            # Archive metadata remains checked exactly on every platform.
            if os.name == "posix":
                require(stat.S_IMODE(item.stat().st_mode) == row["mode"], "restored file mode differs: " + name)
            seen.add(name)
    require(seen == set(expected), "restored file missing")


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # tarfile parses PAX metadata before yielding a member. Bound that read
        # here so a hostile PAX size cannot request an unbounded allocation.
        require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.XHDTYPE),
                "unsupported archive entry type")
        if self.type == tarfile.XHDTYPE:
            require(0 <= self.size <= 16 * 1024, "PAX metadata exceeds bound")
        else:
            require(0 <= self.size <= MAX_TOTAL_BYTES, "archive member exceeds size cap")
        return super()._proc_member(archive)


def extract(destination, bundle, manifest):
    expected = {row["path"]: row for row in manifest["files"]}
    seen = set()
    with io.BufferedReader(PartsReader(bundle, manifest["parts"]), buffer_size=CHUNK) as compressed:
        with gzip.GzipFile(fileobj=compressed, mode="rb") as uncompressed:
            expanded_raw = ExpandedReader(uncompressed, manifest["tar_bytes"])
            with io.BufferedReader(expanded_raw, buffer_size=CHUNK) as expanded:
                with tarfile.open(fileobj=expanded, mode="r|", tarinfo=BoundedTarInfo) as archive:
                    for member in archive:
                        relative(member.name)
                        require(member.isfile() and member.sparse is None and not member.linkname,
                                "archive entry must be an ordinary regular file")
                        require(set(member.pax_headers).issubset({"path"}), "unsupported PAX metadata")
                        require(member.name in expected and member.name not in seen, "extra or duplicate archive entry")
                        row = expected[member.name]
                        require(member.size == row["bytes"] and member.mode == row["mode"], "archive entry metadata differs")
                        file = destination / member.name
                        file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        value, count = hashlib.sha256(), 0
                        source = archive.extractfile(member)
                        require(source is not None, "archive entry content missing")
                        with source, file.open("xb") as output:
                            for block in iter(lambda: source.read(CHUNK), b""):
                                count += len(block)
                                require(count <= row["bytes"], "archive file exceeds bound")
                                value.update(block)
                                output.write(block)
                        require(count == row["bytes"] and value.hexdigest() == row["sha256"], "archive file hash differs")
                        file.chmod(row["mode"])
                        seen.add(member.name)
                # Consume padding and the gzip trailer; bound any trailing expansion.
                for block in iter(lambda: expanded.read(CHUNK), b""):
                    require(not block.strip(b"\0"), "unexpected trailing archive data")
                require(expanded_raw.count == manifest["tar_bytes"], "expanded archive size differs")
    require(seen == set(expected), "archive file missing")


def materialize(manifest_file, destination, *, reserve_bytes=DISK_RESERVE_BYTES,
                expected_manifest_sha256=SOURCE_MANIFEST_SHA256):
    manifest_file, destination = Path(manifest_file).absolute(), Path(destination).absolute()
    require(type(reserve_bytes) is int and reserve_bytes >= 0, "invalid disk reserve")
    # None is reserved for explicitly untrusted unit fixtures; CLI never disables this pin.
    if expected_manifest_sha256 is not None:
        no_symlink_components(manifest_file)
        regular(manifest_file)
        require(manifest_file.stat().st_size <= MAX_MANIFEST_BYTES and
                sha256(manifest_file) == expected_manifest_sha256, "source-reviewed manifest hash differs")
    manifest = load_manifest(manifest_file)
    verify_parts(manifest_file.parent, manifest)
    no_symlink_components(destination)
    if destination.exists():
        verify_tree(destination, manifest)
        return manifest, True
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(destination.parent).free >= manifest["total_file_bytes"] + reserve_bytes,
            "insufficient disk space above reserve")
    staging = Path(tempfile.mkdtemp(prefix=".v011-predecessor-partial-", dir=destination.parent))
    try:
        extract(staging, manifest_file.parent, manifest)
        verify_tree(staging, manifest)
        require(not destination.exists() and not destination.is_symlink(), "destination appeared during extraction")
        # Same-filesystem rename makes the complete tree visible together.
        staging.rename(destination)
    except BaseException:
        # Remove only this invocation's new incomplete staging directory.
        def make_writable_and_retry(function, name, error):
            os.chmod(name, 0o700)
            function(name)
        shutil.rmtree(staging, onerror=make_writable_and_retry)
        raise
    return manifest, False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BUNDLE / "manifest.json")
    parser.add_argument("--destination", type=Path, default=ROOT / "target/v011-predecessor")
    parser.add_argument("--reserve-bytes", type=int, default=DISK_RESERVE_BYTES,
                        help="free disk reserve after extraction (default: 15 GiB; hosted CI may set its own reserve)")
    args = parser.parse_args()
    try:
        manifest, reused = materialize(args.manifest, args.destination, reserve_bytes=args.reserve_bytes)
        print(json.dumps({"schema": "hegemon.v011.predecessor-materialization.v1", "status": "PASS",
                          "destination": str(args.destination.absolute()), "reused": reused,
                          "manifest_sha256": sha256(args.manifest), "files": manifest["file_count"],
                          "bytes": manifest["total_file_bytes"],
                          "authority_scope": "UNCHANGED_PREDECESSOR_ONLY"}, sort_keys=True))
    except (OSError, ValueError, tarfile.TarError, EOFError) as error:
        print("Predecessor materialization rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
