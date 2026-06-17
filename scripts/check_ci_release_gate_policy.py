#!/usr/bin/env python3
"""Check Lean-generated CI release-gate vectors and workflow wiring."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REJECTION_NAMES = {
    "dependency_audit_missing",
    "formal_core_missing",
    "security_adversarial_missing",
    "native_backend_security_missing",
    "release_build_missing",
    "release_build_dependency_missing",
    "release_build_security_adversarial_dependency_missing",
    "release_build_native_backend_security_dependency_missing",
    "release_binary_audit_missing",
    "tag_release_native_backend_review_missing",
    "tag_release_native_backend_posture_missing",
}


def evaluate(case: dict) -> tuple[bool, str | None]:
    if not case["dependency_audit_job"]:
        return False, "dependency_audit_missing"
    if not case["formal_core_job"]:
        return False, "formal_core_missing"
    if not case["security_adversarial_job"]:
        return False, "security_adversarial_missing"
    if not case["native_backend_security_job"]:
        return False, "native_backend_security_missing"
    if not case["release_build_job"]:
        return False, "release_build_missing"
    if not case["release_build_needs_security_gates"]:
        return False, "release_build_dependency_missing"
    if not case["release_build_needs_security_adversarial"]:
        return False, "release_build_security_adversarial_dependency_missing"
    if not case["release_build_needs_native_backend_security"]:
        return False, "release_build_native_backend_security_dependency_missing"
    if not case["release_binary_audit_step"]:
        return False, "release_binary_audit_missing"
    if not case["tag_release_native_backend_review_step"]:
        return False, "tag_release_native_backend_review_missing"
    if not case["tag_release_native_backend_posture_step"]:
        return False, "tag_release_native_backend_posture_missing"
    return True, None


def check_vectors(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise SystemExit("schema_version must be 1")
    cases = data.get("ci_release_gate_cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("ci_release_gate_cases must be a non-empty list")
    for case in cases:
        name = case.get("name", "<unnamed>")
        for field in (
            "dependency_audit_job",
            "formal_core_job",
            "security_adversarial_job",
            "native_backend_security_job",
            "release_build_job",
            "release_build_needs_security_gates",
            "release_build_needs_security_adversarial",
            "release_build_needs_native_backend_security",
            "release_binary_audit_step",
            "tag_release_native_backend_review_step",
            "tag_release_native_backend_posture_step",
            "expected_valid",
        ):
            if not isinstance(case.get(field), bool):
                raise SystemExit(f"{name}: {field} must be a bool")
        rejection = case.get("expected_rejection")
        if rejection is not None and rejection not in REJECTION_NAMES:
            raise SystemExit(f"{name}: unknown expected_rejection {rejection!r}")
        valid, actual_rejection = evaluate(case)
        if valid != case["expected_valid"]:
            raise SystemExit(f"{name}: expected_valid mismatch")
        if actual_rejection != rejection:
            raise SystemExit(
                f"{name}: expected_rejection mismatch: "
                f"got {actual_rejection!r}, expected {rejection!r}"
            )
    print(f"ci release gate vectors: {len(cases)} cases passed")


def job_block(workflow: str, job_name: str) -> str:
    pattern = re.compile(
        rf"(?ms)^  {re.escape(job_name)}:\n"
        rf"(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
    )
    match = pattern.search(workflow)
    if match is None:
        raise SystemExit(f"workflow job missing: {job_name}")
    return match.group("body")


def require_contains(name: str, text: str, needle: str) -> None:
    if needle not in text:
        raise SystemExit(f"{name}: missing {needle!r}")


def check_ci_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    release_build = job_block(workflow, "release-build")
    job_block(workflow, "dependency-audit")
    job_block(workflow, "formal-core")
    job_block(workflow, "security-adversarial")
    job_block(workflow, "native-backend-security")
    require_contains("release-build needs dependency-audit", release_build, "- dependency-audit")
    require_contains("release-build needs formal-core", release_build, "- formal-core")
    require_contains(
        "release-build needs security-adversarial",
        release_build,
        "- security-adversarial",
    )
    require_contains(
        "release-build needs native-backend-security",
        release_build,
        "- native-backend-security",
    )
    require_contains("release-build build command", release_build, "./scripts/check-core.sh build")
    require_contains("release-build binary audit", release_build, "./scripts/security-audit.sh")
    require_contains("release-build binary audit", release_build, "--require-binary")
    require_contains(
        "release-build binary audit",
        release_build,
        "--node-bin target/release/hegemon-node",
    )
    print(f"ci workflow release-build gate passed: {path}")


def check_release_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    security_gates = job_block(workflow, "security-gates")
    require_contains("release security-gates", security_gates, "./scripts/dependency-audit-gate.sh")
    require_contains("release security-gates", security_gates, "bash scripts/check_formal_core.sh")
    require_contains(
        "release security-gates",
        security_gates,
        "./scripts/verify_native_backend_review_package.sh",
    )
    require_contains(
        "release security-gates",
        security_gates,
        "./scripts/check_native_backend_release_posture.sh",
    )
    for job_name in (
        "build-linux",
        "build-macos-intel",
        "build-macos-arm",
        "build-windows",
    ):
        block = job_block(workflow, job_name)
        require_contains(f"{job_name} needs security-gates", block, "needs: security-gates")
        require_contains(f"{job_name} binary audit", block, "./scripts/security-audit.sh")
        require_contains(f"{job_name} binary audit", block, "--require-binary")
        require_contains(f"{job_name} binary audit", block, "--node-bin")
    print(f"tag release workflow gate passed: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors", type=Path)
    parser.add_argument("--ci-workflow", type=Path)
    parser.add_argument("--release-workflow", type=Path)
    args = parser.parse_args()

    check_vectors(args.vectors)
    if args.ci_workflow is not None:
        check_ci_workflow(args.ci_workflow)
    if args.release_workflow is not None:
        check_release_workflow(args.release_workflow)


if __name__ == "__main__":
    main()
