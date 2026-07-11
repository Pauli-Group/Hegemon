#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO


PACKAGE_ROOT_NAME = "native-backend-128b-review-package"
MAX_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024
MAX_MEMBER_COUNT = 20_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
SOURCE_EXCLUSIONS = {
    "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
    "audits/native-backend-128b/package.sha256",
}
DIRECT_SOURCE_EVIDENCE_PATHS = (
    "docs/crypto/native_backend_spec.md",
    "docs/crypto/native_backend_formal_theorems.md",
    "docs/crypto/native_backend_commitment_reduction.md",
    "docs/crypto/native_backend_security_analysis.md",
    "docs/crypto/native_backend_cryptanalysis_note.md",
    "docs/crypto/native_backend_verified_aggregation.md",
    "docs/crypto/native_backend_attack_worksheet.md",
    "docs/crypto/native_backend_constant_time.md",
    "docs/SECURITY_REVIEWS.md",
    "testdata/native_backend_vectors/bundle.json",
    "audits/native-backend-128b/CLAIMS.md",
    "audits/native-backend-128b/THREAT_MODEL.md",
    "audits/native-backend-128b/REVIEW_QUESTIONS.md",
    "audits/native-backend-128b/REPORT_TEMPLATE.md",
    "audits/native-backend-128b/KNOWN_GAPS.md",
    "audits/native-backend-128b/BREAKIT_RULES.md",
)
GENERATED_EVIDENCE_PATHS = (
    "current_claim.json",
    "review_manifest.json",
    "attack_model.json",
    "message_class.json",
    "claim_sweep.json",
    "structured_lattice_model.json",
    "reduced_cryptanalysis_spikes.json",
    "structured_lattice_export_report.json",
    "structured_lattice/matrix_metadata.json",
    "structured_lattice/ring_commitment_matrix_u64_le.bin",
    "structured_lattice/flat_commitment_matrix_u64_le.bin",
    "reference_verifier_report.json",
    "reference_claim_verifier_report.json",
    "production_verifier_report.json",
)


class ReviewPackageError(RuntimeError):
    pass


class _BoundedDecompressedReader:
    def __init__(self, source: BinaryIO, maximum: int) -> None:
        self._source = source
        self._maximum = maximum
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._maximum - self.bytes_read
        requested = remaining + 1
        if size >= 0:
            requested = min(size, requested)
        data = self._source.read(requested)
        self.bytes_read += len(data)
        if self.bytes_read > self._maximum:
            raise ReviewPackageError(
                "package decompressed tar stream exceeds bound "
                f"{self._maximum}"
            )
        return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_regular_file_size(path: Path, label: str, maximum: int) -> int:
    if path.is_symlink() or not path.is_file():
        raise ReviewPackageError(f"{label} is not a regular file: {path}")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        raise ReviewPackageError(f"{label} size {size} exceeds bound {maximum}")
    return size


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
    _bounded_regular_file_size(
        archive_path, "package compressed", MAX_COMPRESSED_BYTES
    )
    _bounded_regular_file_size(sha_path, "package checksum", MAX_CHECKSUM_BYTES)
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


def safe_extract(archive_path: Path, destination: Path) -> Path:
    compressed_size = _bounded_regular_file_size(
        archive_path, "package compressed", MAX_COMPRESSED_BYTES
    )
    if destination.is_symlink():
        raise ReviewPackageError(f"package destination is a symlink: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
    decompressed_limit = min(
        MAX_EXPANDED_BYTES, compressed_size * MAX_COMPRESSION_RATIO
    )
    names: set[str] = set()
    member_count = 0
    expanded_size = 0
    with archive_path.open("rb") as compressed:
        with gzip.GzipFile(fileobj=compressed, mode="rb") as decompressed:
            bounded = _BoundedDecompressedReader(decompressed, decompressed_limit)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > MAX_MEMBER_COUNT:
                        raise ReviewPackageError(
                            f"package member count exceeds bound {MAX_MEMBER_COUNT}"
                        )
                    relative = PurePosixPath(member.name)
                    if (
                        relative.is_absolute()
                        or ".." in relative.parts
                        or not relative.parts
                        or relative.parts[0] != PACKAGE_ROOT_NAME
                    ):
                        raise ReviewPackageError(
                            f"unsafe package member path: {member.name}"
                        )
                    for part in relative.parts:
                        windows_part = PureWindowsPath(part)
                        if (
                            "\\" in part
                            or ":" in part
                            or "\x00" in part
                            or windows_part.drive
                            or windows_part.root
                        ):
                            raise ReviewPackageError(
                                f"non-portable package member path: {member.name}"
                            )
                    normalized = str(relative)
                    if normalized in names:
                        raise ReviewPackageError(
                            f"duplicate package member: {member.name}"
                        )
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
                        if expanded_size > compressed_size * MAX_COMPRESSION_RATIO:
                            raise ReviewPackageError(
                                "package compression ratio exceeds bound "
                                f"{MAX_COMPRESSION_RATIO}"
                            )
                    target = destination.joinpath(*relative.parts)
                    try:
                        target.relative_to(destination)
                    except ValueError as exc:
                        raise ReviewPackageError(
                            f"package member escapes destination: {member.name}"
                        ) from exc
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
                    if target.stat().st_size != member.size:
                        raise ReviewPackageError(
                            f"package member {member.name} extracted size mismatch"
                        )
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
    if member_count == 0:
        raise ReviewPackageError("package archive contains no members")
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


def verify_package_layout(package_root: Path) -> None:
    if package_root.is_symlink() or not package_root.is_dir():
        raise ReviewPackageError(f"package root is not a directory: {package_root}")
    expected = set(DIRECT_SOURCE_EVIDENCE_PATHS)
    expected.update(GENERATED_EVIDENCE_PATHS)
    expected.add("code_fingerprint.json")
    actual: set[str] = set()
    for path in sorted(package_root.rglob("*")):
        if path.is_symlink():
            raise ReviewPackageError(f"package layout contains symlink: {path}")
        relative = path.relative_to(package_root)
        if relative.parts and relative.parts[0] == "source":
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReviewPackageError(f"package layout contains special file: {path}")
        actual.add(relative.as_posix())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReviewPackageError(
            f"package non-source file-set mismatch: missing={missing}, extra={extra}"
        )

    source_root = package_root / "source"
    for relative in DIRECT_SOURCE_EVIDENCE_PATHS:
        direct = package_root / relative
        source = source_root / relative
        direct_hash = sha256_file(direct)
        source_hash = sha256_file(source)
        if direct_hash != source_hash:
            raise ReviewPackageError(
                f"package direct/source evidence mismatch for {relative}: "
                f"{direct_hash} != {source_hash}"
            )
        direct_executable = bool(direct.stat().st_mode & 0o111)
        source_executable = bool(source.stat().st_mode & 0o111)
        if direct_executable != source_executable:
            raise ReviewPackageError(
                f"package direct/source executable-mode mismatch for {relative}"
            )


def _normalize_json_value(value: object, prefixes: list[str]) -> object:
    if isinstance(value, dict):
        return {
            key: _normalize_json_value(item, prefixes)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_json_value(item, prefixes) for item in value]
    if isinstance(value, str):
        for prefix in prefixes:
            if value == prefix:
                return "."
            if value.startswith(prefix + os.sep):
                return Path(value[len(prefix) + 1 :]).as_posix()
    return value


def normalize_json_reports(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ReviewPackageError(f"JSON report root is not a directory: {root}")
    prefixes = sorted({str(root), str(root.resolve())}, key=len, reverse=True)
    for report in sorted(root.glob("*.json")):
        if report.is_symlink() or not report.is_file():
            raise ReviewPackageError(f"JSON report is not a regular file: {report}")
        payload = json.loads(report.read_text(encoding="utf-8"))
        report.write_text(
            json.dumps(_normalize_json_value(payload, prefixes), indent=2) + "\n",
            encoding="utf-8",
        )


def verify_generated_evidence(package_root: Path, regenerated_root: Path) -> None:
    for relative in GENERATED_EVIDENCE_PATHS:
        packaged = package_root / relative
        regenerated = regenerated_root / relative
        for label, path in (("packaged", packaged), ("regenerated", regenerated)):
            if path.is_symlink() or not path.is_file():
                raise ReviewPackageError(
                    f"{label} generated evidence is not a regular file: {relative}"
                )
        packaged_size = packaged.stat().st_size
        regenerated_size = regenerated.stat().st_size
        packaged_hash = sha256_file(packaged)
        regenerated_hash = sha256_file(regenerated)
        if packaged_size != regenerated_size or packaged_hash != regenerated_hash:
            raise ReviewPackageError(
                f"generated evidence mismatch for {relative}: "
                f"packaged(size={packaged_size},sha256={packaged_hash}) != "
                f"regenerated(size={regenerated_size},sha256={regenerated_hash})"
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

    verify_layout = subcommands.add_parser("verify-package-layout")
    verify_layout.add_argument("--package-root", type=Path, required=True)

    source_digest = subcommands.add_parser("source-digest")
    source_digest.add_argument("--source", type=Path, required=True)

    normalize_json = subcommands.add_parser("normalize-json-reports")
    normalize_json.add_argument("--root", type=Path, required=True)

    verify_generated = subcommands.add_parser("verify-generated-evidence")
    verify_generated.add_argument("--package-root", type=Path, required=True)
    verify_generated.add_argument("--regenerated-root", type=Path, required=True)
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
        elif args.command == "verify-package-layout":
            verify_package_layout(args.package_root)
            print("native backend review package has the exact non-source layout")
        elif args.command == "source-digest":
            print(source_tree_sha256(args.source))
        elif args.command == "normalize-json-reports":
            normalize_json_reports(args.root)
            print(f"normalized generated JSON reports under {args.root}")
        elif args.command == "verify-generated-evidence":
            verify_generated_evidence(args.package_root, args.regenerated_root)
            print("generated review evidence matches packaged-source regeneration")
    except (OSError, ValueError, tarfile.TarError, ReviewPackageError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
