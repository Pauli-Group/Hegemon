#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


PACKAGE_ROOT_NAME = "native-backend-128b-review-package"
MAX_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_COUNT = 20_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
SOURCE_EXCLUSIONS = {
    "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
    "audits/native-backend-128b/package.sha256",
}


class ReviewPackageError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_sha256(source_root: Path) -> str:
    if not source_root.is_dir():
        raise ReviewPackageError(f"source tree is missing: {source_root}")
    digest = hashlib.sha256()
    for path in sorted(source_root.rglob("*")):
        if path.is_symlink():
            raise ReviewPackageError(f"source tree contains symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReviewPackageError(f"source tree contains special file: {path}")
        relative = path.relative_to(source_root).as_posix().encode("utf-8")
        data = path.read_bytes()
        executable = b"\x01" if path.stat().st_mode & 0o111 else b"\x00"
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(executable)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def verify_archive_hash(archive_path: Path, sha_path: Path) -> None:
    try:
        line = sha_path.read_text(encoding="utf-8").strip()
        expected_hash, expected_name = line.split("  ", 1)
    except (OSError, ValueError) as exc:
        raise ReviewPackageError(f"invalid package checksum file: {exc}") from exc
    if (
        len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
    ):
        raise ReviewPackageError("package checksum must be lowercase SHA-256")
    if expected_name != archive_path.name:
        raise ReviewPackageError(
            f"package name mismatch: {archive_path.name} != {expected_name}"
        )
    actual_hash = sha256_file(archive_path)
    if actual_hash != expected_hash:
        raise ReviewPackageError(
            f"package hash mismatch: {actual_hash} != {expected_hash}"
        )


def _validated_members(
    archive_path: Path, archive: tarfile.TarFile
) -> list[tarfile.TarInfo]:
    compressed_size = archive_path.stat().st_size
    if compressed_size <= 0 or compressed_size > MAX_COMPRESSED_BYTES:
        raise ReviewPackageError(
            f"package compressed size {compressed_size} exceeds bound "
            f"{MAX_COMPRESSED_BYTES}"
        )
    members = archive.getmembers()
    if not members or len(members) > MAX_MEMBER_COUNT:
        raise ReviewPackageError(
            f"package member count {len(members)} exceeds bound {MAX_MEMBER_COUNT}"
        )

    names: set[str] = set()
    expanded_size = 0
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != PACKAGE_ROOT_NAME
        ):
            raise ReviewPackageError(f"unsafe package member path: {member.name}")
        normalized = str(path)
        if normalized in names:
            raise ReviewPackageError(f"duplicate package member: {member.name}")
        names.add(normalized)
        if not (member.isdir() or member.isfile()):
            raise ReviewPackageError(
                f"unsupported package member type: {member.name}"
            )
        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
            raise ReviewPackageError(
                f"package member {member.name} size {member.size} exceeds bound "
                f"{MAX_MEMBER_BYTES}"
            )
        if member.isfile():
            expanded_size += member.size
            if expanded_size > MAX_EXPANDED_BYTES:
                raise ReviewPackageError(
                    f"package expanded size exceeds bound {MAX_EXPANDED_BYTES}"
                )
    if expanded_size > max(compressed_size, 1) * MAX_COMPRESSION_RATIO:
        raise ReviewPackageError(
            f"package compression ratio exceeds bound {MAX_COMPRESSION_RATIO}"
        )
    return members


def safe_extract(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = _validated_members(archive_path, archive)
        for member in members:
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ReviewPackageError(
                    f"could not read package member {member.name}"
                )
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    package_root = destination / PACKAGE_ROOT_NAME
    if not package_root.is_dir():
        raise ReviewPackageError(f"missing package root {PACKAGE_ROOT_NAME}")
    return package_root


def _git_output(checkout: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=checkout,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        raise ReviewPackageError(
            f"git {' '.join(args)} failed: {exc.output.decode(errors='replace')}"
        ) from exc


def tracked_source_paths(checkout: Path) -> list[str]:
    raw = _git_output(checkout, "ls-tree", "-r", "-z", "--name-only", "HEAD")
    return sorted(
        path
        for path in raw.decode("utf-8", "strict").split("\0")
        if path and path not in SOURCE_EXCLUSIONS
    )


def verify_source_snapshot(checkout: Path, package_root: Path) -> None:
    checkout = checkout.resolve()
    source_root = (package_root / "source").resolve()
    if not source_root.is_dir():
        raise ReviewPackageError("review package source tree is missing")
    tracked_diff = _git_output(checkout, "diff", "--binary", "HEAD", "--")
    if tracked_diff:
        raise ReviewPackageError(
            "source snapshot verification requires a clean tracked checkout"
        )

    expected = tracked_source_paths(checkout)
    actual = sorted(
        str(path.relative_to(source_root))
        for path in source_root.rglob("*")
        if path.is_file()
    )
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise ReviewPackageError(
            f"Git/package source file-set mismatch: missing={missing}, extra={extra}"
        )

    for relative in expected:
        expected_path = checkout / relative
        if not expected_path.is_file() or expected_path.is_symlink():
            raise ReviewPackageError(
                f"tracked checkout source is missing or not a regular file: {relative}"
            )
        expected_bytes = expected_path.read_bytes()
        actual_bytes = (source_root / relative).read_bytes()
        if actual_bytes != expected_bytes:
            raise ReviewPackageError(
                f"Git/package source content mismatch for {relative}: "
                f"{hashlib.sha256(expected_bytes).hexdigest()} != "
                f"{hashlib.sha256(actual_bytes).hexdigest()}"
            )
        expected_executable = bool(expected_path.stat().st_mode & 0o111)
        actual_executable = bool((source_root / relative).stat().st_mode & 0o111)
        if actual_executable != expected_executable:
            raise ReviewPackageError(
                f"Git/package source executable-mode mismatch for {relative}: "
                f"{actual_executable} != {expected_executable}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)

    extract = subcommands.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--sha", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)

    verify_source = subcommands.add_parser("verify-source")
    verify_source.add_argument("--checkout", type=Path, required=True)
    verify_source.add_argument("--package-root", type=Path, required=True)

    source_digest = subcommands.add_parser("source-digest")
    source_digest.add_argument("--source", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.command == "extract":
            verify_archive_hash(args.archive, args.sha)
            print(safe_extract(args.archive, args.destination))
        elif args.command == "verify-source":
            verify_source_snapshot(args.checkout, args.package_root)
            print("native backend review package matches the complete Git source tree")
        elif args.command == "source-digest":
            print(source_tree_sha256(args.source))
    except (OSError, tarfile.TarError, ReviewPackageError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
