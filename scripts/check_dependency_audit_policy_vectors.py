#!/usr/bin/env python3
"""Check Lean-generated dependency audit policy vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_WAIVER_FIELDS = ("id", "package", "version", "kind")


def non_empty(value: object) -> bool:
    return isinstance(value, str) and value != ""


def waiver_is_valid(waiver: dict) -> bool:
    return (
        all(non_empty(waiver.get(field)) for field in REQUIRED_WAIVER_FIELDS)
        and bool(waiver.get("not_expired"))
        and bool(waiver.get("has_tracking"))
        and bool(waiver.get("has_reason"))
    )


def waiver_matches_finding(finding: dict, waiver: dict) -> bool:
    return all(waiver.get(field) == finding.get(field) for field in REQUIRED_WAIVER_FIELDS)


def finding_has_valid_waiver(finding: dict, waivers: list[dict]) -> bool:
    return any(
        waiver_is_valid(waiver) and waiver_matches_finding(finding, waiver)
        for waiver in waivers
    )


def waiver_matches_any_finding(waiver: dict, findings: list[dict]) -> bool:
    return any(waiver_matches_finding(finding, waiver) for finding in findings)


def evaluate_case(case: dict) -> tuple[bool, str | None]:
    findings = case["findings"]
    waivers = case["waivers"]
    if not all(waiver_is_valid(waiver) for waiver in waivers):
        return False, "malformed_waiver"
    if not all(finding_has_valid_waiver(finding, waivers) for finding in findings):
        return False, "unwaived_finding"
    if not all(waiver_matches_any_finding(waiver, findings) for waiver in waivers):
        return False, "unused_waiver"
    return True, None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_dependency_audit_policy_vectors.py <vectors.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    vectors = json.loads(path.read_text())
    if vectors.get("schema_version") != 1:
        raise SystemExit(f"unsupported schema_version: {vectors.get('schema_version')!r}")

    cases = vectors.get("dependency_audit_policy_cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("dependency_audit_policy_cases must be a non-empty list")

    names: set[str] = set()
    for case in cases:
        name = case["name"]
        if name in names:
            raise SystemExit(f"duplicate case name: {name}")
        names.add(name)
        if not isinstance(case.get("findings"), list):
            raise SystemExit(f"{name}: findings must be a list")
        if not isinstance(case.get("waivers"), list):
            raise SystemExit(f"{name}: waivers must be a list")
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
