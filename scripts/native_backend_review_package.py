#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import unicodedata
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
WINDOWS_RESERVED_COMPONENTS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "CLOCK$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
WINDOWS_INVALID_COMPONENT_CHARACTERS = frozenset('<>:"\\|?*')
WINDOWS_DEVICE_DIGIT_TRANSLATION = str.maketrans(
    {"\u00b9": "1", "\u00b2": "2", "\u00b3": "3"}
)
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
EXPECTED_VECTOR_CASES = (
    ("native_tx_leaf_valid", True),
    ("native_tx_leaf_invalid_spec_digest", False),
    ("native_tx_leaf_invalid_params_fingerprint", False),
    ("native_tx_leaf_invalid_stark_proof", False),
    ("native_tx_leaf_invalid_proof_digest", False),
    ("native_tx_leaf_invalid_trailing_bytes", False),
    ("receipt_root_valid", True),
    ("receipt_root_invalid_spec_digest", False),
    ("receipt_root_invalid_fold_rows", False),
    ("receipt_root_invalid_root_commitment", False),
    ("receipt_root_invalid_trailing_bytes", False),
)
EXPECTED_REDUCED_CRYPTANALYSIS_CASES = (
    ("crt_component_pair_box2", 4, 624),
    ("fq3_like_subspace_box1", 12, 531_440),
    ("sparse_two_term_box2", 108, 92_880),
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


def _portable_archive_path_identity(relative: PurePosixPath) -> str:
    identity_parts: list[str] = []
    for part in relative.parts:
        windows_part = PureWindowsPath(part)
        windows_basename = (
            part.split(".", 1)[0]
            .rstrip(" .")
            .upper()
            .translate(WINDOWS_DEVICE_DIGIT_TRANSLATION)
        )
        if (
            part in {"", ".", ".."}
            or "\\" in part
            or any(character in WINDOWS_INVALID_COMPONENT_CHARACTERS for character in part)
            or any(ord(character) < 32 for character in part)
            or part.endswith((".", " "))
            or windows_part.drive
            or windows_part.root
            or windows_basename in WINDOWS_RESERVED_COMPONENTS
        ):
            raise ReviewPackageError(
                f"non-portable package member path component: {part!r}"
            )
        identity_parts.append(unicodedata.normalize("NFC", part).casefold())
    return "/".join(identity_parts)


def _directory_open_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        raise ReviewPackageError(
            "safe package extraction requires " + ", ".join(missing)
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_or_create_directory_at(
    parent_fd: int, name: str, member_name: str
) -> int:
    try:
        os.mkdir(name, mode=0o755, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ReviewPackageError(
            f"could not create package directory for {member_name}: {exc}"
        ) from exc
    try:
        return os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise ReviewPackageError(
            f"unsafe package extraction path for {member_name}: {exc}"
        ) from exc


def _open_directory_chain(root_fd: int, parts: tuple[str, ...], member_name: str) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in parts:
            next_fd = _open_or_create_directory_at(current_fd, part, member_name)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _extract_regular_member_at(
    parent_fd: int,
    name: str,
    member_name: str,
    source: BinaryIO,
    expected_size: int,
    mode: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        output_fd = os.open(name, flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise ReviewPackageError(
            f"unsafe package extraction target for {member_name}: {exc}"
        ) from exc

    try:
        with os.fdopen(output_fd, "wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
            output.flush()
            actual_size = os.fstat(output.fileno()).st_size
            if actual_size != expected_size:
                raise ReviewPackageError(
                    f"package member {member_name} extracted size mismatch"
                )
            os.fchmod(output.fileno(), mode)
    except Exception:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise


def safe_extract(archive_path: Path, destination: Path) -> Path:
    compressed_size = _bounded_regular_file_size(
        archive_path, "package compressed", MAX_COMPRESSED_BYTES
    )
    if destination.is_symlink():
        raise ReviewPackageError(f"package destination is a symlink: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    destination = Path(os.path.abspath(destination))
    try:
        destination_fd = os.open(destination, _directory_open_flags())
    except OSError as exc:
        raise ReviewPackageError(
            f"package destination must be a non-symlink directory: {destination}"
        ) from exc

    decompressed_limit = min(
        MAX_EXPANDED_BYTES, compressed_size * MAX_COMPRESSION_RATIO
    )
    names: set[str] = set()
    member_count = 0
    expanded_size = 0
    try:
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
                        try:
                            normalized = _portable_archive_path_identity(relative)
                        except ReviewPackageError as exc:
                            raise ReviewPackageError(
                                f"non-portable package member path: {member.name}"
                            ) from exc
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
                            directory_fd = _open_directory_chain(
                                destination_fd, relative.parts, member.name
                            )
                            os.close(directory_fd)
                            continue

                        parent_fd = _open_directory_chain(
                            destination_fd, relative.parts[:-1], member.name
                        )
                        try:
                            source = archive.extractfile(member)
                            if source is None:
                                raise ReviewPackageError(
                                    f"could not read package member {member.name}"
                                )
                            mode = 0o755 if member.mode & 0o111 else 0o644
                            with source:
                                _extract_regular_member_at(
                                    parent_fd,
                                    relative.parts[-1],
                                    member.name,
                                    source,
                                    member.size,
                                    mode,
                                )
                        finally:
                            os.close(parent_fd)

        if member_count == 0:
            raise ReviewPackageError("package archive contains no members")
        try:
            package_root_stat = os.stat(
                PACKAGE_ROOT_NAME, dir_fd=destination_fd, follow_symlinks=False
            )
        except OSError as exc:
            raise ReviewPackageError(
                f"missing package root {PACKAGE_ROOT_NAME}"
            ) from exc
        if not stat.S_ISDIR(package_root_stat.st_mode):
            raise ReviewPackageError(f"missing package root {PACKAGE_ROOT_NAME}")
        return destination / PACKAGE_ROOT_NAME
    finally:
        os.close(destination_fd)


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


def tracked_source_entries(checkout: Path) -> dict[str, tuple[str, str]]:
    raw = _git_output(checkout, "ls-tree", "-r", "-z", "HEAD")
    entries: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", "strict")
            mode = raw_mode.decode("ascii", "strict")
            object_type = raw_type.decode("ascii", "strict")
            object_id = raw_object_id.decode("ascii", "strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReviewPackageError(f"invalid Git tree entry: {record!r}") from exc
        if path in SOURCE_EXCLUSIONS:
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ReviewPackageError(
                f"unsupported Git source entry for {path}: mode={mode} type={object_type}"
            )
        if path in entries:
            raise ReviewPackageError(f"duplicate Git source entry: {path}")
        entries[path] = (mode, object_id)
    return dict(sorted(entries.items()))


def tracked_source_paths(checkout: Path) -> list[str]:
    return list(tracked_source_entries(checkout))


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

    expected_entries = tracked_source_entries(checkout)
    expected = list(expected_entries)
    actual = []
    for path in source_root.rglob("*"):
        if path.is_symlink():
            raise ReviewPackageError(f"package source tree contains symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReviewPackageError(f"package source tree contains special file: {path}")
        actual.append(str(path.relative_to(source_root)))
    actual.sort()
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise ReviewPackageError(
            f"Git/package source file-set mismatch: missing={missing}, extra={extra}"
        )

    for relative in expected:
        expected_mode, object_id = expected_entries[relative]
        expected_bytes = _git_output(checkout, "cat-file", "blob", object_id)
        actual_bytes = (source_root / relative).read_bytes()
        if actual_bytes != expected_bytes:
            raise ReviewPackageError(
                f"Git/package source content mismatch for {relative}: "
                f"{hashlib.sha256(expected_bytes).hexdigest()} != "
                f"{hashlib.sha256(actual_bytes).hexdigest()}"
            )
        expected_executable = expected_mode == "100755"
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


def _read_json_evidence(root: Path, relative: str) -> object:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ReviewPackageError(f"generated evidence is not a regular file: {relative}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewPackageError(f"invalid JSON evidence {relative}: {exc}") from exc


def _verify_vector_report(payload: object, relative: str) -> tuple[tuple[str, bool, bool], ...]:
    if not isinstance(payload, dict):
        raise ReviewPackageError(f"{relative} must be a JSON object")
    summary = payload.get("summary")
    results = payload.get("results")
    if not isinstance(summary, dict) or not isinstance(results, list):
        raise ReviewPackageError(f"{relative} is missing summary or results")
    expected_count = len(EXPECTED_VECTOR_CASES)
    expected_summary = {
        "bundle_path": "testdata/native_backend_vectors/bundle.json",
        "case_count": expected_count,
        "passed_cases": expected_count,
        "failed_cases": 0,
    }
    for field, expected in expected_summary.items():
        if summary.get(field) != expected:
            raise ReviewPackageError(
                f"{relative} summary {field} must be {expected!r}, got {summary.get(field)!r}"
            )
    if len(results) != expected_count:
        raise ReviewPackageError(
            f"{relative} must contain exactly {expected_count} vector results"
        )

    identities: list[tuple[str, bool, bool]] = []
    for index, ((expected_name, expected_valid), result) in enumerate(
        zip(EXPECTED_VECTOR_CASES, results, strict=True)
    ):
        if not isinstance(result, dict):
            raise ReviewPackageError(f"{relative} result {index} must be an object")
        identity = (
            result.get("name"),
            result.get("expected_valid"),
            result.get("passed"),
        )
        expected_identity = (expected_name, expected_valid, True)
        if identity != expected_identity:
            raise ReviewPackageError(
                f"{relative} result {index} identity must be {expected_identity!r}, got {identity!r}"
            )
        identities.append(expected_identity)
    return tuple(identities)


def verify_evidence_semantics(root: Path) -> None:
    reference_identity = _verify_vector_report(
        _read_json_evidence(root, "reference_verifier_report.json"),
        "reference_verifier_report.json",
    )
    production_identity = _verify_vector_report(
        _read_json_evidence(root, "production_verifier_report.json"),
        "production_verifier_report.json",
    )
    if reference_identity != production_identity:
        raise ReviewPackageError(
            "reference and production verifier result identities differ"
        )

    reduced = _read_json_evidence(root, "reduced_cryptanalysis_spikes.json")
    if not isinstance(reduced, dict) or not isinstance(reduced.get("cases"), list):
        raise ReviewPackageError("reduced_cryptanalysis_spikes.json is missing cases")
    cases = reduced["cases"]
    if len(cases) != len(EXPECTED_REDUCED_CRYPTANALYSIS_CASES):
        raise ReviewPackageError(
            "reduced_cryptanalysis_spikes.json must contain exactly "
            f"{len(EXPECTED_REDUCED_CRYPTANALYSIS_CASES)} cases"
        )
    for index, ((expected_name, expected_variables, expected_searches), case) in enumerate(
        zip(EXPECTED_REDUCED_CRYPTANALYSIS_CASES, cases, strict=True)
    ):
        if not isinstance(case, dict):
            raise ReviewPackageError(
                f"reduced_cryptanalysis_spikes.json case {index} must be an object"
            )
        actual = (
            case.get("name"),
            case.get("variable_count"),
            case.get("searched_candidates"),
            case.get("found_nonzero_kernel"),
            case.get("first_kernel_vector"),
        )
        expected = (
            expected_name,
            expected_variables,
            expected_searches,
            False,
            None,
        )
        if actual != expected:
            raise ReviewPackageError(
                "reduced_cryptanalysis_spikes.json case "
                f"{index} must be {expected!r}, got {actual!r}"
            )


def _required_projection(
    value: object,
    fields: tuple[str, ...],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReviewPackageError(f"{label} must be an object")
    missing = [field for field in fields if field not in value]
    if missing:
        raise ReviewPackageError(f"{label} is missing stable fields: {missing!r}")
    return {field: value[field] for field in fields}


def _stable_tx_context(value: object, label: str) -> dict[str, object]:
    projected = _required_projection(
        value,
        (
            "backend_params",
            "expected_version",
            "params_fingerprint_hex",
            "spec_digest_hex",
            "relation_id_hex",
            "shape_digest_hex",
            "commitment_rows",
            "receipt",
            "tx",
            "stark_public_inputs",
        ),
        label,
    )
    projected["receipt"] = _required_projection(
        projected["receipt"],
        (
            "statement_hash_hex",
            "public_inputs_digest_hex",
            "verifier_profile_hex",
        ),
        f"{label}.receipt",
    )
    projected["tx"] = _required_projection(
        projected["tx"],
        (
            "nullifiers_hex",
            "commitments_hex",
            "ciphertext_hashes_hex",
            "balance_tag_hex",
            "version_circuit",
            "version_crypto",
        ),
        f"{label}.tx",
    )
    projected["stark_public_inputs"] = _required_projection(
        projected["stark_public_inputs"],
        (
            "input_flags",
            "output_flags",
            "fee",
            "value_balance_sign",
            "value_balance_magnitude",
            "merkle_root_hex",
            "balance_slot_asset_ids",
            "stablecoin_enabled",
            "stablecoin_asset_id",
            "stablecoin_policy_version",
            "stablecoin_issuance_sign",
            "stablecoin_issuance_magnitude",
            "stablecoin_policy_hash_hex",
            "stablecoin_oracle_commitment_hex",
            "stablecoin_attestation_commitment_hex",
        ),
        f"{label}.stark_public_inputs",
    )
    return projected


def _stable_block_context(value: object, label: str) -> dict[str, object]:
    projected = _required_projection(
        value,
        (
            "backend_params",
            "expected_version",
            "params_fingerprint_hex",
            "spec_digest_hex",
            "relation_id_hex",
            "shape_digest_hex",
            "leaves",
        ),
        label,
    )
    leaves = projected["leaves"]
    if not isinstance(leaves, list):
        raise ReviewPackageError(f"{label}.leaves must be a list")
    stable_leaves = []
    for index, leaf in enumerate(leaves):
        leaf_label = f"{label}.leaves[{index}]"
        leaf_projection = _required_projection(
            leaf,
            ("artifact_sha256", "artifact_hex", "tx_context"),
            leaf_label,
        )
        try:
            artifact = bytes.fromhex(leaf_projection["artifact_hex"])
        except (TypeError, ValueError) as exc:
            raise ReviewPackageError(f"{leaf_label}.artifact_hex is invalid") from exc
        digest = hashlib.sha256(artifact).hexdigest()
        if leaf_projection["artifact_sha256"] != digest:
            raise ReviewPackageError(f"{leaf_label} artifact SHA-256 mismatch")
        stable_leaves.append(
            {
                "tx_context": _stable_tx_context(
                    leaf_projection["tx_context"], f"{leaf_label}.tx_context"
                )
            }
        )
    projected["leaves"] = stable_leaves
    return projected


def _review_vector_semantic_manifest(root: Path) -> dict[str, object]:
    relative = "testdata/native_backend_vectors/bundle.json"
    payload = _read_json_evidence(root, relative)
    if not isinstance(payload, dict):
        raise ReviewPackageError(f"{relative} must be a JSON object")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise ReviewPackageError(f"{relative} cases must be a list")

    case_manifest: list[dict[str, object]] = []
    artifact_digests: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ReviewPackageError(f"{relative} case {index} must be an object")
        artifact_hex = case.get("artifact_hex")
        if not isinstance(artifact_hex, str):
            raise ReviewPackageError(f"{relative} case {index} lacks artifact_hex")
        try:
            artifact = bytes.fromhex(artifact_hex)
        except ValueError as exc:
            raise ReviewPackageError(
                f"{relative} case {index} has invalid artifact_hex"
            ) from exc
        digest = hashlib.sha256(artifact).hexdigest()
        if case.get("artifact_sha256") != digest:
            raise ReviewPackageError(f"{relative} case {index} artifact SHA-256 mismatch")
        if digest in artifact_digests:
            raise ReviewPackageError(f"{relative} case {index} aliases another artifact")
        artifact_digests.add(digest)
        tx_context = case.get("tx_context")
        block_context = case.get("block_context")
        if (tx_context is None) == (block_context is None):
            raise ReviewPackageError(
                f"{relative} case {index} must carry exactly one semantic context"
            )
        case_manifest.append(
            {
                "name": case.get("name"),
                "kind": case.get("kind"),
                "expected_valid": case.get("expected_valid"),
                "expected_error_substring": case.get("expected_error_substring"),
                "mutation_id": case.get("mutation_id"),
                "tx_context": (
                    None
                    if tx_context is None
                    else _stable_tx_context(tx_context, f"{relative} case {index}.tx_context")
                ),
                "block_context": (
                    None
                    if block_context is None
                    else _stable_block_context(
                        block_context, f"{relative} case {index}.block_context"
                    )
                ),
            }
        )

    return {
        "schema_version": payload.get("schema_version"),
        "generator_id": payload.get("generator_id"),
        "active_tx_profile": payload.get("active_tx_profile"),
        "parameter_fingerprint": payload.get("parameter_fingerprint"),
        "native_backend_params": payload.get("native_backend_params"),
        "native_security_claim": payload.get("native_security_claim"),
        "cases": case_manifest,
    }


def verify_vector_semantic_equivalence(package_root: Path, regenerated_root: Path) -> None:
    packaged = _review_vector_semantic_manifest(package_root)
    regenerated = _review_vector_semantic_manifest(regenerated_root)
    if packaged != regenerated:
        raise ReviewPackageError(
            "packaged native review bundle semantic manifest differs from "
            "the fresh packaged-source regeneration"
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

    verify_semantics = subcommands.add_parser("verify-evidence-semantics")
    verify_semantics.add_argument("--root", type=Path, required=True)

    verify_vectors = subcommands.add_parser("verify-vector-semantic-equivalence")
    verify_vectors.add_argument("--package-root", type=Path, required=True)
    verify_vectors.add_argument("--regenerated-root", type=Path, required=True)
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
        elif args.command == "verify-evidence-semantics":
            verify_evidence_semantics(args.root)
            print("native backend review evidence has exact semantic coverage")
        elif args.command == "verify-vector-semantic-equivalence":
            verify_vector_semantic_equivalence(args.package_root, args.regenerated_root)
            print("native review vectors match fresh packaged-source semantics")
    except (OSError, ValueError, tarfile.TarError, ReviewPackageError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
