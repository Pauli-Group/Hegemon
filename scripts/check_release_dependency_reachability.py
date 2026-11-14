#!/usr/bin/env python3
"""Fail-closed source/feature scope for four temporary dependency exceptions.

Cargo.lock records optional and development dependencies.  This check does not
remove their advisories: it proves their absence from the exact packaged normal
and build graphs before the ordinary audit policy may accept an exception.
No compilation, binary qualification, or release authorization is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINDING_KEY = "release_dependency_reachability"
SCOPE = "packaged-release-nonreachability-v1"
LOCK_SHA256 = "1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719"
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
PACKAGES = (
    ("hegemon-node", ("--no-default-features",)),
    ("wallet", ("--no-default-features", "--features", "rpc-client")),
    ("walletd", ()),
)
EXCLUDED = frozenset(("quinn", "quinn-proto", "quinn-udp", "rustix", "reqwest", "tempfile"))
FINDINGS = frozenset((
    ("RUSTSEC-2026-0524", "quinn-proto", "0.11.18", "vulnerability"),
    ("RUSTSEC-2026-0523", "quinn-proto", "0.11.18", "vulnerability"),
    ("RUSTSEC-2026-0538", "quinn-udp", "0.5.15", "vulnerability"),
    ("RUSTSEC-2026-0486", "rustix", "1.1.4", "unsound"),
))
FINDING_IDS = frozenset(item[0] for item in FINDINGS)
# The lock and every local manifest/config controlling resolution are reviewed
# inputs.  Package sources need not be pinned: these crates must be absent.
CONTROL_PATHS = (
    "Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml",
    "scripts/build_release_artifacts.sh",
    "scripts/check_release_dependency_reachability.py",
    "scripts/dependency-audit-gate.sh",
)
BUILD_COMMANDS = (
    "build_release -p hegemon-node --bin hegemon-node --no-default-features",
    "build_release -p wallet --bin wallet --bin private-spend --no-default-features --features rpc-client",
    "build_release -p walletd --bin walletd",
)
PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_-]+) v[0-9][^ ]*(?: .*)?$")


class ReachabilityError(ValueError):
    pass


def source_paths(root: Path) -> set[str]:
    # Cargo tree resolves path manifests without compiling. Bind all checked-in
    # manifests, including excluded path packages that a dependency could select.
    result = set(CONTROL_PATHS)
    proc = subprocess.run(
        ["git", "ls-files", "--cached", "--", "**/Cargo.toml"], cwd=root,
        capture_output=True, text=True, check=False,
    )
    if proc.returncode:
        raise ReachabilityError("cannot enumerate tracked dependency manifests")
    result.update(proc.stdout.splitlines())
    return result


def validate_sources(root: Path, binding: dict) -> None:
    sources = binding.get("source_sha256")
    if not isinstance(sources, dict) or set(sources) != source_paths(root):
        raise ReachabilityError("source binding must cover every tracked Cargo manifest and release control file")
    if sources.get("Cargo.lock") != LOCK_SHA256:
        raise ReachabilityError("release exceptions cannot change the accepted proof-bound Cargo.lock identity")
    for name, expected in sources.items():
        path = root / name
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ReachabilityError(f"invalid source SHA-256: {name}")
        if path.is_symlink() or not path.is_file():
            raise ReachabilityError(f"source binding requires an ordinary file: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ReachabilityError(f"source binding changed: {name}; reassess dependency exceptions")
    commands = tuple(
        line.strip() for line in (root / "scripts/build_release_artifacts.sh").read_text().splitlines()
        if line.strip().startswith("build_release ")
    )
    if commands != BUILD_COMMANDS:
        raise ReachabilityError("packaging package/feature commands differ from the reviewed release scope")


def validate_policy(root: Path, policy: dict) -> dict | None:
    waivers = policy.get("waivers")
    if not isinstance(waivers, list):
        raise ReachabilityError("policy waivers must be a list")
    selected = [w for w in waivers if isinstance(w, dict) and w.get("id") in FINDING_IDS]
    binding = policy.get(BINDING_KEY)
    if not selected:
        if binding is not None:
            raise ReachabilityError("unused release dependency source binding")
        return None
    if not isinstance(binding, dict) or binding.get("schema") != 1 or binding.get("scope") != SCOPE:
        raise ReachabilityError("reviewed dependency exceptions require their source-bound release scope")
    if binding.get("targets") != list(TARGETS):
        raise ReachabilityError("release dependency targets differ from the reviewed four-platform scope")
    expected_packages = [{"package": p, "feature_args": list(f)} for p, f in PACKAGES]
    if binding.get("packages") != expected_packages or binding.get("excluded_packages") != sorted(EXCLUDED):
        raise ReachabilityError("release dependency package/features or exclusions changed")
    keys = [(w.get("id"), w.get("package"), w.get("version"), w.get("kind")) for w in selected]
    if len(keys) != len(FINDINGS) or set(keys) != FINDINGS:
        raise ReachabilityError("release dependency exceptions must match the four reviewed exact findings")
    for waiver in selected:
        if waiver.get("scope") != SCOPE or waiver.get("owner") != "release-maintainers":
            raise ReachabilityError("release dependency exception scope/owner changed")
        try:
            reviewed = date.fromisoformat(waiver["reviewed_at"])
            expires = date.fromisoformat(waiver["expires"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReachabilityError("invalid release dependency exception dates") from exc
        if not reviewed <= date.today() <= expires or expires > date(2026, 12, 14):
            raise ReachabilityError("release dependency exception expired or exceeds its reviewed deadline")
        if (expires - reviewed).days > 31:
            raise ReachabilityError("release dependency exception must expire within 31 days of review")
    validate_sources(root, binding)
    return binding


def check_graph(root: Path, target: str, package: str, flags: tuple[str, ...], *, offline: bool = False,
                runner=subprocess.run) -> int:
    command = ["cargo", "tree", "--locked", "--color", "never", "-p", package,
               "--target", target, "--edges", "normal,build", "--prefix", "none", "--format", "{p}", *flags]
    if offline:
        command.append("--offline")
    try:
        proc = runner(command, cwd=root, capture_output=True, text=True, check=False, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReachabilityError(f"cannot resolve {package}/{target}: {exc}") from exc
    if proc.returncode:
        raise ReachabilityError(f"failed dependency resolution for {package}/{target}: {proc.stderr.strip()}")
    names = []
    for line in proc.stdout.splitlines():
        match = PACKAGE_LINE.fullmatch(line)
        if not match:
            raise ReachabilityError(f"malformed dependency graph for {package}/{target}: {line!r}")
        names.append(match[1])
    if not names or names[0] != package:
        raise ReachabilityError(f"missing selected package in dependency graph for {package}/{target}")
    activated = EXCLUDED.intersection(names)
    if activated:
        raise ReachabilityError(f"reviewed-absent dependency activated for {package}/{target}: {', '.join(sorted(activated))}")
    return len(names)


def check(root: Path, policy: dict, *, offline: bool = False, runner=subprocess.run) -> int:
    binding = validate_policy(root, policy)
    if binding is None:
        return 0
    for target in TARGETS:
        for package, flags in PACKAGES:
            count = check_graph(root, target, package, flags, offline=offline, runner=runner)
            print(f"release dependency scope: {target} {package}: {count} graph entries, excluded crates absent")
    # Do not accept an inventory while one of its source inputs changes.
    validate_sources(root, binding)
    return len(TARGETS) * len(PACKAGES)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    policy_path = args.policy or root / "config/dependency-audit-waivers.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            raise ReachabilityError("dependency policy must be an object")
        count = check(root, policy, offline=args.offline)
    except (OSError, ValueError) as exc:
        print(f"release dependency reachability: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release dependency reachability: passed ({count} exact packaged graphs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
