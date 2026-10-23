#!/usr/bin/env python3
"""Check the reviewed release-helper allowlist and bounded release producers.

This is a source gate, not a general supply-chain or arbitrary-shell-code audit.
Adding or changing an approved digest still requires a review of those bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any


POLICY_PATH = "config/release-launcher-policy.json"
POLICY_MAX_BYTES = 64 * 1024
SOURCE_MAX_BYTES = 2 * 1024 * 1024
MAX_INVENTORY_ENTRIES = 10_000
ALLOWED_EXTENSIONS = frozenset({".cmd", ".bat", ".sh", ".txt"})
EXECUTABLE_EXTENSIONS = frozenset({".cmd", ".bat", ".sh", ".ps1", ".vbs", ".js"})
PRODUCER_PATHS = (
    "scripts/build_release_artifacts.sh",
    "scripts/release_artifact_manifest.py",
    "scripts/package_testnet_downloads.py",
    ".github/workflows/release.yml",
)


class LauncherPolicyError(ValueError):
    """A source tree does not satisfy the release-helper policy."""


def _fail(message: str) -> None:
    raise LauncherPolicyError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_link(info: os.stat_result) -> bool:
    # Windows junctions/reparse points can redirect a path without S_ISLNK.
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _safe_path(root: Path, relative: str, *, optional: bool = False) -> Path | None:
    """Check each repository-relative component before opening or traversing it."""
    current = root
    try:
        root_info = current.lstat()
        if _is_link(root_info) or not stat.S_ISDIR(root_info.st_mode):
            _fail(f"root must be a directory, without a symlink: {root}")
        parts = PurePosixPath(relative).parts
        for index, part in enumerate(parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if optional:
                    return None
                _fail(f"missing required file: {relative}")
            if _is_link(info):
                _fail(f"symlink is forbidden: {relative}")
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                _fail(f"non-directory path component: {relative}")
        return current
    except OSError as error:
        _fail(f"cannot inspect {relative}: {error}")


def _read_bounded(root: Path, relative: str, maximum: int) -> bytes:
    """Open without following symlinks; anchor component opens where supported."""
    path = _safe_path(root, relative)
    assert path is not None
    descriptors: list[int] = []
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            _fail(f"release source must be a regular file: {relative}")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        # Windows CRT text descriptors translate CRLF and stop at Ctrl-Z.
        # Digests and size limits must apply to the exact committed bytes.
        read_flags = (
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0)
        )
        if nofollow and os.open in os.supports_dir_fd:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
            descriptor = os.open(root, directory_flags)
            descriptors.append(descriptor)
            parts = PurePosixPath(relative).parts
            for part in parts[:-1]:
                descriptor = os.open(part, directory_flags, dir_fd=descriptor)
                descriptors.append(descriptor)
            descriptor = os.open(parts[-1], read_flags, dir_fd=descriptor)
        else:
            # Platforms without openat/O_NOFOLLOW use the checked components above.
            # As with the rest of a source build, the checkout must not be mutated
            # concurrently by an untrusted process on those platforms.
            descriptor = os.open(path, read_flags)
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            _fail(f"release source must be a regular file: {relative}")
        if info.st_size > maximum:
            _fail(f"file exceeds {maximum} bytes: {relative}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            _fail(f"file exceeds {maximum} bytes: {relative}")
        return data
    except OSError as error:
        _fail(f"cannot read {relative} without following symlinks: {error}")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _canonical_launcher_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("launcher path must be a nonempty string")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(part in {".", ".."} for part in path.parts)
        or not value.startswith("testnet-release/")
        or len(path.parts) < 2
    ):
        _fail(f"launcher path must be canonical beneath testnet-release/: {value!r}")
    if path.suffix.casefold() not in ALLOWED_EXTENSIONS:
        _fail(f"unsupported shipped helper extension: {value}")
    return value


def _parse_policy(data: bytes) -> dict[str, Any]:
    try:
        policy = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"invalid {POLICY_PATH}: {error}")
    if not isinstance(policy, dict) or set(policy) != {"schema_version", "launchers"}:
        _fail("policy must contain exactly schema_version and launchers")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        _fail("policy schema_version must be integer 1")
    if not isinstance(policy["launchers"], list):
        _fail("policy launchers must be a list")
    seen: set[str] = set()
    for entry in policy["launchers"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            _fail("each launcher must contain exactly path and sha256")
        path = _canonical_launcher_path(entry["path"])
        if path in seen:
            _fail(f"duplicate launcher path: {path}")
        seen.add(path)
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            _fail(f"sha256 must contain 64 lowercase hexadecimal digits: {path}")
    return policy


def _inventory_helpers(root: Path) -> set[str]:
    directory = _safe_path(root, "testnet-release", optional=True)
    if directory is None:
        return set()
    if not directory.is_dir():
        _fail("testnet-release must be a directory")
    helpers: set[str] = set()
    pending = [directory]
    count = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_INVENTORY_ENTRIES:
                        _fail(f"testnet-release inventory exceeds {MAX_INVENTORY_ENTRIES} entries")
                    relative = Path(entry.path).relative_to(root).as_posix()
                    info = entry.stat(follow_symlinks=False)
                    if _is_link(info):
                        _fail(f"symlink is forbidden in testnet-release: {relative}")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    else:
                        if not stat.S_ISREG(info.st_mode):
                            _fail(f"release source must be a regular file: {relative}")
                        extension = Path(entry.name).suffix.casefold()
                        if extension in EXECUTABLE_EXTENSIONS and extension not in ALLOWED_EXTENSIONS:
                            _fail(f"unsupported executable helper: {relative}")
                        # Markdown is retained release documentation and cannot
                        # be approved/shipped as a launcher under this policy.
                        # The packager must consume only approved entries.
                        if extension == ".md":
                            continue
                        helpers.add(relative)
        except OSError as error:
            _fail(f"cannot inventory testnet-release: {error}")
    return helpers


_POLICY_OPTIONS = {"ep", *("executionpolicy"[:length] for length in range(2, 16))}
_POLICY_OPTION_RE = "|".join(sorted(_POLICY_OPTIONS, key=len, reverse=True))
_WEAK_POLICY_RE = re.compile(
    rf"(?<![\w-])[/-](?:{_POLICY_OPTION_RE})(?:\s+|[:=]\s*)(?:bypass|unrestricted)\b",
    re.IGNORECASE,
)
_SET_WEAK_POLICY_RE = re.compile(
    r"\bset-executionpolicy\b[^;\r\n]*\b(?:bypass|unrestricted)\b", re.IGNORECASE
)
_POWERSHELL_RE = re.compile(r"(?<![\w])(?:powershell|pwsh)(?:\.exe)?(?![\w])", re.IGNORECASE)


def _normalized_commands(data: bytes, relative: str) -> list[str]:
    try:
        source = data.decode("utf-8-sig")
    except UnicodeError as error:
        _fail(f"helper/producer must be UTF-8 text: {relative}: {error}")
    # Join CMD, PowerShell, and shell line continuations before checking tokens.
    source = re.sub(r"(?:\^|`|\\)\r?\n", "", source)
    commands: list[str] = []
    for line in source.splitlines():
        normalized = re.sub(r"[\"'\^`]", "", line).strip()
        if not normalized or normalized.startswith(("#", "::")):
            continue
        # In CMD, a command after a separator on a REM line still executes.
        # Retain such lines conservatively after quote/caret normalization.
        if re.match(r"@?rem(?:\s|$)", normalized, re.IGNORECASE) and not re.search(r"[&|]", normalized):
            continue
        commands.append(normalized)
    return commands


def _check_commands(data: bytes, relative: str, *, helper: bool) -> None:
    for command in _normalized_commands(data, relative):
        if _WEAK_POLICY_RE.search(command) or _SET_WEAK_POLICY_RE.search(command):
            _fail(f"execution-policy weakening is forbidden: {relative}")
        if helper and _POWERSHELL_RE.search(command):
            _fail(f"PowerShell/pwsh invocation is forbidden in release helpers: {relative}")


def verify_source(root: Path) -> dict[str, Any]:
    """Validate the required policy, helper inventory/digests, and producers.

    Return the validated policy unchanged. Native-only trees use an explicit
    {"schema_version": 1, "launchers": []} policy, even without testnet-release.
    """
    root = Path(os.path.abspath(root))
    policy = _parse_policy(_read_bounded(root, POLICY_PATH, POLICY_MAX_BYTES))
    listed = {entry["path"] for entry in policy["launchers"]}
    inventory = _inventory_helpers(root)
    unlisted = inventory - listed
    if unlisted:
        _fail(f"release files are missing from the reviewed policy: {', '.join(sorted(unlisted))}")
    for entry in policy["launchers"]:
        relative = entry["path"]
        data = _read_bounded(root, relative, SOURCE_MAX_BYTES)
        actual = hashlib.sha256(data).hexdigest()
        if actual != entry["sha256"]:
            _fail(f"release helper digest differs from reviewed policy: {relative} (expected {entry['sha256']}, got {actual})")
        if PurePosixPath(relative).suffix.casefold() != ".txt":
            _check_commands(data, relative, helper=True)
    for relative in PRODUCER_PATHS:
        if _safe_path(root, relative, optional=True) is not None:
            _check_commands(_read_bounded(root, relative, SOURCE_MAX_BYTES), relative, helper=False)
    return policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        policy = verify_source(arguments.root)
    except LauncherPolicyError as error:
        print(f"release launcher policy rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(policy, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
