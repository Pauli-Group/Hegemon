#!/usr/bin/env python3
"""Check Lean-generated release PQ-binary policy vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def evaluate_case(case: dict) -> tuple[bool, str | None]:
    if not case["source_scan_clean"]:
        return False, "source_forbidden"
    if not case["dependency_scan_clean"]:
        return False, "dependency_forbidden"
    if not case["binary_scan_clean"]:
        return False, "binary_forbidden"
    return True, None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_release_pq_binary_policy_vectors.py <vectors.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    vectors = json.loads(path.read_text())
    if vectors.get("schema_version") != 1:
        raise SystemExit(f"unsupported schema_version: {vectors.get('schema_version')!r}")

    cases = vectors.get("release_pq_binary_policy_cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("release_pq_binary_policy_cases must be a non-empty list")

    names: set[str] = set()
    for case in cases:
        name = case["name"]
        if name in names:
            raise SystemExit(f"duplicate case name: {name}")
        names.add(name)
        actual_valid, actual_rejection = evaluate_case(case)
        if actual_valid != case["expected_valid"]:
            raise SystemExit(
                f"{name}: validity drifted from Lean: {actual_valid} != "
                f"{case['expected_valid']}"
            )
        if actual_rejection != case["expected_rejection"]:
            raise SystemExit(
                f"{name}: rejection drifted from Lean: {actual_rejection!r} != "
                f"{case['expected_rejection']!r}"
            )

    print(json.dumps({"passed": True, "cases": len(cases)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
