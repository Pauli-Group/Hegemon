#!/usr/bin/env python3
"""Compute the pinned libiop Aurora include closure without compiling it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, deque
from pathlib import Path


LIBIOP_REVISION = "a2ed2ec2f3e85f29b6035951553b02cb737c817a"
EXPECTED_SOURCE_DIR = f"libiop-{LIBIOP_REVISION}"
LIBIOP_LICENSE = "MIT"
LIBIOP_LICENSE_SHA512 = (
    "05c7b8c925af9cc8a58c056f9cb2b9eeccd85146786396c798842448475a4019"
    "a9ff82168e9126ff466a0e8b76b929a2b8452833b90ae6b938589b680033ba44"
)


ROOTS = (
    "libiop/snark/aurora_snark.hpp",
    "libiop/common/common.cpp",
    "libiop/bcs/hashing/blake2b.cpp",
    "libiop/protocols/ldt/ldt_reducer.cpp",
    "libiop/protocols/ldt/fri/fri_ldt.cpp",
    "libiop/protocols/ldt/fri/fri_aux.cpp",
    "libiop/relations/sparse_matrix.cpp",
    "libiop/iop/utilities/batching.cpp",
    "libiop/algebra/utils.cpp",
)

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)


def component(path: str) -> str:
    if path.startswith("libiop/snark/"):
        return "snark_wrapper"
    if path.startswith("libiop/protocols/aurora"):
        return "aurora_composition"
    if path.startswith("libiop/protocols/encoded/"):
        return "encoded_r1cs_iop"
    if path.startswith("libiop/protocols/ldt/fri/"):
        return "fri_ldt"
    if path.startswith("libiop/protocols/ldt/"):
        return "ldt_reducer"
    if path.startswith("libiop/bcs/"):
        return "bcs_merkle_transcript"
    if path.startswith("libiop/iop/"):
        return "iop_runtime"
    if path.startswith("libiop/relations/"):
        return "r1cs_relation"
    if path.startswith("libiop/algebra/"):
        return "algebra_fft"
    return "common"


def digest(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check",
        type=Path,
        help="compare the computed canonical JSON with an existing receipt",
    )
    args = parser.parse_args()

    if args.output and args.check:
        parser.error("--output and --check are mutually exclusive")

    source_root = args.source_root.resolve()
    if source_root.name != EXPECTED_SOURCE_DIR:
        raise SystemExit(
            f"refusing unpinned source directory {source_root.name!r}; "
            f"expected {EXPECTED_SOURCE_DIR!r}"
        )
    license_path = source_root / "LICENSE"
    if not license_path.is_file() or digest(license_path) != LIBIOP_LICENSE_SHA512:
        raise SystemExit("pinned libiop LICENSE is absent or has the wrong SHA-512")
    pending = deque(ROOTS)
    seen: set[str] = set()
    external = Counter()
    missing: set[str] = set()

    while pending:
        relative = pending.popleft()
        if relative in seen:
            continue
        candidate = source_root / relative
        if not candidate.is_file():
            missing.add(relative)
            continue
        seen.add(relative)
        text = candidate.read_text(encoding="utf-8")
        for included in INCLUDE_RE.findall(text):
            if included.startswith("libiop/"):
                if included not in seen:
                    pending.append(included)
            elif included.startswith("libff/"):
                external["libff"] += 1
            elif included.startswith("libfqfft/"):
                external["libfqfft"] += 1
            elif included.startswith("sodium/"):
                external["libsodium"] += 1
            else:
                external["cxx_or_system"] += 1

    files = []
    component_totals: dict[str, dict[str, int]] = {}
    for relative in sorted(seen):
        candidate = source_root / relative
        raw = candidate.read_bytes()
        lines = len(raw.splitlines())
        group = component(relative)
        files.append(
            {
                "path": relative,
                "component": group,
                "lines": lines,
                "bytes": len(raw),
                "sha512": digest(candidate),
            }
        )
        totals = component_totals.setdefault(group, {"files": 0, "lines": 0, "bytes": 0})
        totals["files"] += 1
        totals["lines"] += lines
        totals["bytes"] += len(raw)

    payload = {
        "schema": "hegemon.aurora.libiop-source-closure.v1",
        "source": {
            "repository": "https://github.com/scipr-lab/libiop",
            "revision": LIBIOP_REVISION,
            "license_spdx": LIBIOP_LICENSE,
            "license_sha512": LIBIOP_LICENSE_SHA512,
        },
        "roots": list(ROOTS),
        "closure": {
            "files": len(files),
            "lines": sum(item["lines"] for item in files),
            "bytes": sum(item["bytes"] for item in files),
        },
        "component_totals": dict(sorted(component_totals.items())),
        "external_include_counts": dict(sorted(external.items())),
        "missing_local_includes": sorted(missing),
        "files": files,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.check:
        existing = args.check.read_text(encoding="utf-8")
        if existing != rendered:
            print(f"FAIL: source closure differs from {args.check}", file=sys.stderr)
            raise SystemExit(1)
        print(f"PASS: {args.check} matches the pinned source closure")
    elif args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
