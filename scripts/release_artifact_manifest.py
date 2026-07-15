#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SCHEMA_VERSION = 1
ASSET_SCHEMA_VERSION = 1
EXPECTED_ARTIFACTS = (
    ("hegemon-node", "hegemon-node"),
    ("wallet", "wallet"),
    ("walletd", "walletd"),
)


class ManifestError(RuntimeError):
    pass


@dataclass
class _DirectoryHandle:
    path: Path
    fd: int | None

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _descriptor_relative_io_available() -> bool:
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
    )


def _directory_open_flags() -> int:
    if not _descriptor_relative_io_available():
        raise ManifestError("release artifact verification requires O_DIRECTORY and O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _regular_open_flags() -> int:
    if not _descriptor_relative_io_available():
        raise ManifestError("release artifact verification requires O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _is_reparse_point(value: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(marker and attributes & marker)


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _checked_fallback_path(
    base: Path,
    relative: str,
    label: str,
    *,
    directory: bool,
) -> tuple[Path, os.stat_result]:
    base = Path(os.path.abspath(base))
    parts = () if relative in {"", "."} else Path(relative).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ManifestError(f"invalid {label} path: {relative}")
    current = base
    chain = (base, *(base.joinpath(*parts[: index + 1]) for index in range(len(parts))))
    final_stat: os.stat_result | None = None
    try:
        for index, candidate in enumerate(chain):
            current = candidate
            value = os.lstat(candidate)
            if stat.S_ISLNK(value.st_mode) or _is_reparse_point(value):
                raise ManifestError(f"{label} contains a symlink or reparse point: {candidate}")
            is_last = index == len(chain) - 1
            if not is_last or directory:
                if not stat.S_ISDIR(value.st_mode):
                    raise ManifestError(f"{label} contains a non-directory component: {candidate}")
            elif not stat.S_ISREG(value.st_mode):
                raise ManifestError(f"{label} is not a regular file: {candidate}")
            final_stat = value
    except OSError as exc:
        raise ManifestError(f"{label} is not a non-symlink path: {current}") from exc
    if final_stat is None:
        raise ManifestError(f"{label} path is empty")
    return current, final_stat


def _repository_relative(root: Path, path: Path) -> tuple[Path, str]:
    root = Path(os.path.abspath(root))
    candidate = path if path.is_absolute() else root / path
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise ManifestError(f"artifact path escapes repository: {candidate}") from exc
    if relative in {"", "."}:
        raise ManifestError("artifact path must name a file below the repository root")
    return candidate, relative


def _open_regular_beneath(base: Path, relative: str, label: str) -> int:
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ManifestError(f"invalid {label} path: {relative}")
    if not _descriptor_relative_io_available():
        candidate, expected = _checked_fallback_path(
            base, relative, label, directory=False
        )
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOINHERIT"):
            flags |= os.O_NOINHERIT
        try:
            file_fd = os.open(candidate, flags)
        except OSError as exc:
            raise ManifestError(
                f"{label} is not a regular non-symlink file: {relative}"
            ) from exc
        actual = os.fstat(file_fd)
        if not stat.S_ISREG(actual.st_mode) or _file_identity(actual) != _file_identity(expected):
            os.close(file_fd)
            raise ManifestError(f"{label} changed while being opened: {relative}")
        # Re-check the lexical chain after opening. The file descriptor remains
        # bound to the object whose bytes are inspected and copied below.
        _checked_fallback_path(base, relative, label, directory=False)
        return file_fd
    try:
        current_fd = os.open(base, _directory_open_flags())
    except OSError as exc:
        raise ManifestError(f"{label} root is not a non-symlink directory: {base}") from exc
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(parts[-1], _regular_open_flags(), dir_fd=current_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(file_fd)
            raise ManifestError(f"{label} is not a regular non-symlink file: {relative}")
        return file_fd
    except OSError as exc:
        raise ManifestError(f"{label} is not a regular non-symlink file: {relative}") from exc
    finally:
        os.close(current_fd)


def _open_directory_beneath(base: Path, relative: str, label: str) -> _DirectoryHandle:
    parts = () if relative in {"", "."} else Path(relative).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ManifestError(f"invalid {label} path: {relative}")
    base = Path(os.path.abspath(base))
    if not _descriptor_relative_io_available():
        path, _ = _checked_fallback_path(base, relative, label, directory=True)
        return _DirectoryHandle(path=path, fd=None)
    try:
        current_fd = os.open(base, _directory_open_flags())
        for part in parts:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return _DirectoryHandle(path=base / relative, fd=current_fd)
    except OSError as exc:
        if "current_fd" in locals():
            os.close(current_fd)
        raise ManifestError(f"{label} is not a non-symlink directory: {relative}") from exc


def _mkdir_at(directory: _DirectoryHandle, name: str, mode: int) -> None:
    if directory.fd is not None:
        os.mkdir(name, mode=mode, dir_fd=directory.fd)
    else:
        os.mkdir(directory.path / name, mode=mode)


def _open_at(
    directory: _DirectoryHandle,
    name: str,
    flags: int,
    mode: int = 0o777,
) -> int:
    if directory.fd is not None:
        return os.open(name, flags, mode, dir_fd=directory.fd)
    return os.open(directory.path / name, flags, mode)


def _open_repository_file(root: Path, relative: str, label: str) -> int:
    return _open_regular_beneath(Path(os.path.abspath(root)), relative, label)


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _sha256_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    )


def source_tree_sha256(root: Path) -> str:
    tracked = run_git(root, "ls-files", "-z").decode(
        "utf-8", "surrogateescape"
    ).split("\0")
    untracked = run_git(
        root, "ls-files", "--others", "--exclude-standard", "-z"
    ).decode("utf-8", "surrogateescape").split("\0")
    paths = sorted({path for path in (*tracked, *untracked) if path})
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8", "surrogateescape"))
        elif path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            digest.update(f"file:{mode:o}:{path.stat().st_size}".encode("ascii"))
            digest.update(b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            try:
                submodule_head = subprocess.check_output(
                    ["git", "-C", str(path), "rev-parse", "HEAD"],
                    stderr=subprocess.DEVNULL,
                ).strip()
            except (OSError, subprocess.CalledProcessError) as exc:
                raise ManifestError(f"tracked directory is not a Git submodule: {relative}") from exc
            digest.update(b"submodule\0")
            digest.update(submodule_head)
        else:
            raise ManifestError(f"source path is missing or unsupported: {relative}")
        digest.update(b"\0")
    return digest.hexdigest()


def detect_native_format_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, 4096)
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ") and len(data) >= 64:
        pe_offset = int.from_bytes(data[60:64], "little")
        os.lseek(fd, pe_offset, os.SEEK_SET)
        if os.read(fd, 4) == b"PE\0\0":
            return "pe"
    if data[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }:
        return "mach-o"
    return "unknown"


def detect_native_format(path: Path) -> str:
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    fd = os.open(path, flags)
    try:
        return detect_native_format_fd(fd)
    finally:
        os.close(fd)


def expected_format(target_triple: str) -> str:
    if "windows" in target_triple:
        return "pe"
    if "apple-darwin" in target_triple:
        return "mach-o"
    if "linux" in target_triple:
        return "elf"
    raise ManifestError(f"unsupported release target triple: {target_triple}")


def parse_spec(root: Path, value: str) -> tuple[str, str, Path, str]:
    parts = value.split(":", 2)
    if len(parts) != 3 or not all(parts):
        raise ManifestError(f"artifact spec must be PACKAGE:BIN:PATH, got {value!r}")
    package, binary, raw_path = parts
    path, relative = _repository_relative(root, Path(raw_path))
    return package, binary, path, relative


def inspect_artifact(
    root: Path, package: str, binary: str, path: Path, relative: str, target: str
) -> dict[str, object]:
    del path
    fd = _open_repository_file(root, relative, "artifact")
    try:
        before = os.fstat(fd)
        native_format = detect_native_format_fd(fd)
        required_format = expected_format(target)
        if native_format != required_format:
            raise ManifestError(
                f"artifact {relative} format {native_format!r} does not match "
                f"target {target!r} format {required_format!r}"
            )
        digest = _sha256_fd(fd)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ManifestError(f"artifact changed while being inspected: {relative}")
        return {
            "package": package,
            "binary": binary,
            "path": relative,
            "sha256": digest,
            "size": before.st_size,
            "native_format": native_format,
        }
    finally:
        os.close(fd)


def create_manifest(
    root: Path, output: Path, target_triple: str, artifact_specs: list[str]
) -> dict[str, object]:
    parsed = [parse_spec(root, value) for value in artifact_specs]
    identities = tuple((package, binary) for package, binary, _, _ in parsed)
    if identities != EXPECTED_ARTIFACTS:
        raise ManifestError(
            f"release manifest artifacts must be exactly {EXPECTED_ARTIFACTS!r}, got {identities!r}"
        )
    artifacts = [
        inspect_artifact(root, package, binary, path, relative, target_triple)
        for package, binary, path, relative in parsed
    ]
    if len({item["path"] for item in artifacts}) != len(artifacts):
        raise ManifestError("release artifact paths must be distinct")
    if len({item["sha256"] for item in artifacts}) != len(artifacts):
        raise ManifestError("release artifact SHA-256 digests must be distinct")
    cargo_lock = root / "Cargo.lock"
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "source_head": run_git(root, "rev-parse", "HEAD").decode().strip(),
        "source_index_tree": run_git(root, "write-tree").decode().strip(),
        "source_tree_sha256": source_tree_sha256(root),
        "cargo_lock_sha256": sha256_file(cargo_lock),
        "target_triple": target_triple,
        "artifacts": artifacts,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_manifest(root: Path, manifest_path: Path, expected_specs: list[str]) -> dict[str, object]:
    _, manifest_relative = _repository_relative(root, manifest_path)
    try:
        manifest_fd = _open_repository_file(root, manifest_relative, "release manifest")
        try:
            payload = json.loads(_read_fd(manifest_fd).decode("utf-8"))
        finally:
            os.close(manifest_fd)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"invalid release manifest: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("unsupported release manifest schema")

    target = payload.get("target_triple")
    if not isinstance(target, str):
        raise ManifestError("release manifest target_triple is missing")
    current_source = {
        "source_head": run_git(root, "rev-parse", "HEAD").decode().strip(),
        "source_index_tree": run_git(root, "write-tree").decode().strip(),
        "source_tree_sha256": source_tree_sha256(root),
        "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
    }
    for field, expected in current_source.items():
        if payload.get(field) != expected:
            raise ManifestError(
                f"release manifest {field} does not match current source: "
                f"{payload.get(field)!r} != {expected!r}"
            )

    expected = [parse_spec(root, value) for value in expected_specs]
    expected_identities = tuple((package, binary) for package, binary, _, _ in expected)
    if expected_identities != EXPECTED_ARTIFACTS:
        raise ManifestError(
            f"expected artifacts must be exactly {EXPECTED_ARTIFACTS!r}, got {expected_identities!r}"
        )
    manifest_artifacts = payload.get("artifacts")
    if not isinstance(manifest_artifacts, list) or len(manifest_artifacts) != len(expected):
        raise ManifestError("release manifest must contain exactly three artifacts")

    verified: list[dict[str, object]] = []
    for item, (package, binary, path, relative) in zip(
        manifest_artifacts, expected, strict=True
    ):
        if not isinstance(item, dict):
            raise ManifestError("release manifest artifact entry must be an object")
        if (item.get("package"), item.get("binary"), item.get("path")) != (
            package,
            binary,
            relative,
        ):
            raise ManifestError(f"release manifest artifact identity mismatch for {relative}")
        actual = inspect_artifact(root, package, binary, path, relative, target)
        if item != actual:
            raise ManifestError(f"release manifest artifact digest/metadata mismatch for {relative}")
        verified.append(actual)
    if len({item["path"] for item in verified}) != len(verified):
        raise ManifestError("release artifact paths must be distinct")
    if len({item["sha256"] for item in verified}) != len(verified):
        raise ManifestError("release artifact SHA-256 digests must be distinct")
    return payload


def _parse_asset_spec(value: str) -> tuple[str, str, str]:
    parts = value.split(":", 2)
    if len(parts) != 3 or not all(parts):
        raise ManifestError(f"asset spec must be PACKAGE:BIN:NAME, got {value!r}")
    package, binary, name = parts
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise ManifestError(f"release asset name is not portable: {name!r}")
    return package, binary, name


def _create_output_directory(
    root: Path, output: Path
) -> tuple[Path, str, _DirectoryHandle]:
    output_path, output_relative = _repository_relative(root, output)
    relative_path = Path(output_relative)
    parent_relative = relative_path.parent.as_posix()
    parent_fd = _open_directory_beneath(root, parent_relative, "output parent")
    try:
        _mkdir_at(parent_fd, relative_path.name, 0o755)
        output_fd = _open_directory_beneath(root, output_relative, "release output")
    except FileExistsError as exc:
        raise ManifestError(f"release output directory already exists: {output_path}") from exc
    except OSError as exc:
        raise ManifestError(f"could not create release output directory: {output_path}") from exc
    finally:
        parent_fd.close()
    return output_path, output_relative, output_fd


def _write_exclusive_at(
    directory_fd: _DirectoryHandle, name: str, data: bytes, mode: int
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise ManifestError(f"release output name is not portable: {name!r}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = _open_at(directory_fd, name, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _copy_verified_fd_at(
    source_fd: int,
    output_fd: _DirectoryHandle,
    output_name: str,
    expected_digest: str,
    expected_size: int,
) -> None:
    before = os.fstat(source_fd)
    os.lseek(source_fd, 0, os.SEEK_SET)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    destination_fd = _open_at(output_fd, output_name, flags, 0o755)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        if hasattr(os, "fchmod"):
            os.fchmod(destination_fd, 0o755)
    finally:
        os.close(destination_fd)
    after = os.fstat(source_fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ManifestError("release source artifact changed during packaging")
    actual_digest = digest.hexdigest()
    if size != expected_size or actual_digest != expected_digest:
        raise ManifestError(
            f"packaged asset does not match audited artifact: "
            f"size={size} sha256={actual_digest}"
        )


def package_artifacts(
    root: Path,
    manifest_path: Path,
    expected_specs: list[str],
    asset_specs: list[str],
    output_dir: Path,
    asset_manifest_name: str,
) -> dict[str, object]:
    payload = verify_manifest(root, manifest_path, expected_specs)
    expected = [parse_spec(root, value) for value in expected_specs]
    assets = [_parse_asset_spec(value) for value in asset_specs]
    identities = tuple((package, binary) for package, binary, _ in assets)
    if identities != EXPECTED_ARTIFACTS:
        raise ManifestError(
            f"release assets must be exactly {EXPECTED_ARTIFACTS!r}, got {identities!r}"
        )
    names = [name for _, _, name in assets]
    if len(names) != len(set(names)):
        raise ManifestError("release asset names must be distinct")
    if not re.fullmatch(r"hegemon-release-assets-[A-Za-z0-9._-]+\.json", asset_manifest_name):
        raise ManifestError(f"invalid release asset manifest name: {asset_manifest_name!r}")

    _, _, output_fd = _create_output_directory(root, output_dir)
    packaged: list[dict[str, object]] = []
    try:
        _, manifest_relative = _repository_relative(root, manifest_path)
        source_manifest_fd = _open_repository_file(
            root, manifest_relative, "release manifest"
        )
        try:
            source_manifest_sha256 = _sha256_fd(source_manifest_fd)
        finally:
            os.close(source_manifest_fd)
        manifest_artifacts = payload["artifacts"]
        for item, (package, binary, _path, relative), (_, _, output_name) in zip(
            manifest_artifacts, expected, assets, strict=True
        ):
            source_fd = _open_repository_file(root, relative, "release source artifact")
            try:
                native_format = detect_native_format_fd(source_fd)
                if native_format != item["native_format"]:
                    raise ManifestError(
                        f"release source format changed before packaging: {relative}"
                    )
                _copy_verified_fd_at(
                    source_fd,
                    output_fd,
                    output_name,
                    str(item["sha256"]),
                    int(item["size"]),
                )
            finally:
                os.close(source_fd)
            checksum_name = f"{output_name}.sha256"
            _write_exclusive_at(
                output_fd,
                checksum_name,
                f"{item['sha256']}  {output_name}\n".encode("ascii"),
                0o644,
            )
            packaged.append(
                {
                    "package": package,
                    "binary": binary,
                    "name": output_name,
                    "sha256": item["sha256"],
                    "size": item["size"],
                    "native_format": item["native_format"],
                    "checksum_name": checksum_name,
                }
            )
        asset_payload = {
            "schema_version": ASSET_SCHEMA_VERSION,
            "source_head": payload["source_head"],
            "source_index_tree": payload["source_index_tree"],
            "source_tree_sha256": payload["source_tree_sha256"],
            "cargo_lock_sha256": payload["cargo_lock_sha256"],
            "target_triple": payload["target_triple"],
            "source_manifest_sha256": source_manifest_sha256,
            "assets": packaged,
        }
        _write_exclusive_at(
            output_fd,
            asset_manifest_name,
            (json.dumps(asset_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o644,
        )
        return asset_payload
    finally:
        output_fd.close()


def _load_asset_bundle(
    root: Path, manifest_path: Path, require_exact_directory: bool
) -> tuple[dict[str, object], dict[str, bytes]]:
    manifest_path, manifest_relative = _repository_relative(root, manifest_path)
    manifest_fd = _open_repository_file(root, manifest_relative, "release asset manifest")
    try:
        manifest_bytes = _read_fd(manifest_fd)
    finally:
        os.close(manifest_fd)
    try:
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"invalid release asset manifest: {manifest_path}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != ASSET_SCHEMA_VERSION:
        raise ManifestError("unsupported release asset manifest schema")
    target = payload.get("target_triple")
    if not isinstance(target, str):
        raise ManifestError("release asset manifest target_triple is missing")
    assets = payload.get("assets")
    if not isinstance(assets, list) or len(assets) != len(EXPECTED_ARTIFACTS):
        raise ManifestError("release asset manifest must contain exactly three assets")
    identities = tuple(
        (item.get("package"), item.get("binary")) if isinstance(item, dict) else (None, None)
        for item in assets
    )
    if identities != EXPECTED_ARTIFACTS:
        raise ManifestError("release asset manifest identities are not canonical")

    parent_relative = Path(manifest_relative).parent.as_posix()
    files: dict[str, bytes] = {manifest_path.name: manifest_bytes}
    expected_names = {manifest_path.name}
    for item in assets:
        name = item.get("name")
        checksum_name = item.get("checksum_name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ManifestError("release asset manifest contains an invalid asset name")
        if checksum_name != f"{name}.sha256":
            raise ManifestError(f"release checksum name mismatch for {name}")
        if name in expected_names or checksum_name in expected_names:
            raise ManifestError("release asset bundle contains duplicate names")
        expected_names.update((name, checksum_name))
        asset_relative = (Path(parent_relative) / name).as_posix()
        asset_fd = _open_repository_file(root, asset_relative, "release asset")
        try:
            native_format = detect_native_format_fd(asset_fd)
            asset_bytes = _read_fd(asset_fd)
        finally:
            os.close(asset_fd)
        digest = hashlib.sha256(asset_bytes).hexdigest()
        if (
            digest != item.get("sha256")
            or len(asset_bytes) != item.get("size")
            or native_format != item.get("native_format")
            or native_format != expected_format(target)
        ):
            raise ManifestError(f"release asset does not match its manifest: {name}")
        checksum_relative = (Path(parent_relative) / checksum_name).as_posix()
        checksum_fd = _open_repository_file(root, checksum_relative, "release checksum")
        try:
            checksum_bytes = _read_fd(checksum_fd)
        finally:
            os.close(checksum_fd)
        if checksum_bytes != f"{digest}  {name}\n".encode("ascii"):
            raise ManifestError(f"release checksum does not match its asset: {checksum_name}")
        files[name] = asset_bytes
        files[checksum_name] = checksum_bytes

    if require_exact_directory:
        parent_fd = _open_directory_beneath(root, parent_relative, "release asset bundle")
        try:
            actual_names = set()
            scan_target: int | Path = (
                parent_fd.fd if parent_fd.fd is not None else parent_fd.path
            )
            with os.scandir(scan_target) as entries:
                for entry in entries:
                    if not entry.is_file(follow_symlinks=False):
                        raise ManifestError(
                            f"release asset bundle contains a non-regular entry: {entry.name}"
                        )
                    actual_names.add(entry.name)
        finally:
            parent_fd.close()
        if actual_names != expected_names:
            raise ManifestError(
                f"release asset bundle file-set mismatch: "
                f"missing={sorted(expected_names - actual_names)}, "
                f"extra={sorted(actual_names - expected_names)}"
            )
    return payload, files


def assemble_release_assets(
    root: Path, bundle_manifests: list[Path], output_dir: Path
) -> dict[str, object]:
    if not bundle_manifests:
        raise ManifestError("at least one release asset bundle is required")
    bundles = [
        _load_asset_bundle(root, manifest_path, require_exact_directory=True)
        for manifest_path in bundle_manifests
    ]
    provenance_fields = (
        "source_head",
        "source_index_tree",
        "source_tree_sha256",
        "cargo_lock_sha256",
    )
    canonical = {field: bundles[0][0].get(field) for field in provenance_fields}
    for payload, _ in bundles:
        if {field: payload.get(field) for field in provenance_fields} != canonical:
            raise ManifestError("release asset bundles do not share source provenance")
    current = {
        "source_head": run_git(root, "rev-parse", "HEAD").decode().strip(),
        "source_index_tree": run_git(root, "write-tree").decode().strip(),
        "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
    }
    for field, expected in current.items():
        if canonical.get(field) != expected:
            raise ManifestError(f"release asset {field} does not match the release checkout")
    targets = [payload.get("target_triple") for payload, _ in bundles]
    if len(targets) != len(set(targets)):
        raise ManifestError("release asset bundle target triples must be distinct")

    _, _, output_fd = _create_output_directory(root, output_dir)
    written: set[str] = set()
    try:
        for _payload, files in bundles:
            for name, data in files.items():
                if name in written:
                    raise ManifestError(f"release asset output name collision: {name}")
                written.add(name)
                mode = 0o755 if not name.endswith((".json", ".sha256")) else 0o644
                _write_exclusive_at(output_fd, name, data, mode)
    finally:
        output_fd.close()
    return {
        "schema_version": ASSET_SCHEMA_VERSION,
        **canonical,
        "target_triples": targets,
        "files": sorted(written),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--target-triple", required=True)
    create.add_argument("--artifact", action="append", required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expect", action="append", required=True)
    package = subcommands.add_parser("package")
    package.add_argument("--manifest", type=Path, required=True)
    package.add_argument("--expect", action="append", required=True)
    package.add_argument("--asset", action="append", required=True)
    package.add_argument("--output-dir", type=Path, required=True)
    package.add_argument("--asset-manifest-name", required=True)
    assemble = subcommands.add_parser("assemble")
    assemble.add_argument("--bundle-manifest", type=Path, action="append", required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    try:
        if args.command == "create":
            payload = create_manifest(root, args.output, args.target_triple, args.artifact)
            print(json.dumps(payload, sort_keys=True))
        elif args.command == "verify":
            payload = verify_manifest(root, args.manifest, args.expect)
            print(json.dumps(payload, sort_keys=True))
        elif args.command == "package":
            payload = package_artifacts(
                root,
                args.manifest,
                args.expect,
                args.asset,
                args.output_dir,
                args.asset_manifest_name,
            )
            print(json.dumps(payload, sort_keys=True))
        else:
            payload = assemble_release_assets(
                root, args.bundle_manifest, args.output_dir
            )
            print(json.dumps(payload, sort_keys=True))
    except (OSError, subprocess.CalledProcessError, ManifestError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
