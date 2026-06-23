#!/usr/bin/env python3
"""Check Lean-generated CI release-gate vectors and workflow wiring."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REJECTION_NAMES = {
    "dependency_audit_missing",
    "dependency_audit_waiver_gate_missing",
    "formal_core_missing",
    "security_adversarial_missing",
    "native_backend_security_missing",
    "release_build_missing",
    "release_build_dependency_missing",
    "release_build_security_adversarial_dependency_missing",
    "release_build_native_backend_security_dependency_missing",
    "non_release_job_contents_write",
    "release_binary_audit_missing",
    "tag_release_native_backend_review_missing",
    "tag_release_native_backend_posture_missing",
    "branch_protection_ruleset_missing",
}

REQUIRED_RULESET_CHECKS = {
    "dependency-audit",
    "formal-core",
    "security-adversarial",
    "native-backend-security",
    "release-build",
}


def evaluate(case: dict) -> tuple[bool, str | None]:
    if not case["dependency_audit_job"]:
        return False, "dependency_audit_missing"
    if not case["dependency_audit_waiver_gate_step"]:
        return False, "dependency_audit_waiver_gate_missing"
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
    if not case["non_release_jobs_no_contents_write"]:
        return False, "non_release_job_contents_write"
    if not case["release_binary_audit_step"]:
        return False, "release_binary_audit_missing"
    if not case["tag_release_native_backend_review_step"]:
        return False, "tag_release_native_backend_review_missing"
    if not case["tag_release_native_backend_posture_step"]:
        return False, "tag_release_native_backend_posture_missing"
    if not case["branch_protection_ruleset_evidence"]:
        return False, "branch_protection_ruleset_missing"
    return True, None


def check_vectors(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 2:
        raise SystemExit("schema_version must be 2")
    cases = data.get("ci_release_gate_cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("ci_release_gate_cases must be a non-empty list")
    for case in cases:
        name = case.get("name", "<unnamed>")
        for field in (
            "dependency_audit_job",
            "dependency_audit_waiver_gate_step",
            "formal_core_job",
            "security_adversarial_job",
            "native_backend_security_job",
            "release_build_job",
            "release_build_needs_security_gates",
            "release_build_needs_security_adversarial",
            "release_build_needs_native_backend_security",
            "non_release_jobs_no_contents_write",
            "release_binary_audit_step",
            "tag_release_native_backend_review_step",
            "tag_release_native_backend_posture_step",
            "branch_protection_ruleset_evidence",
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
    dependency_audit = job_block(workflow, "dependency-audit")
    job_block(workflow, "formal-core")
    job_block(workflow, "security-adversarial")
    job_block(workflow, "native-backend-security")
    require_contains(
        "dependency-audit waiver gate",
        dependency_audit,
        "./scripts/dependency-audit-gate.sh",
    )
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
    if re.search(r"(?m)^permissions:\n\s+contents:\s+write\b", workflow):
        raise SystemExit("release workflow must not grant workflow-wide contents: write")
    if not re.search(r"(?m)^permissions:\n\s+contents:\s+read\b", workflow):
        raise SystemExit("release workflow must default to workflow-wide contents: read")
    security_gates = job_block(workflow, "security-gates")
    create_release = job_block(workflow, "create-release")
    if not re.search(r"(?m)^    permissions:\n\s+contents:\s+write\b", create_release):
        raise SystemExit("create-release job must carry the only contents: write permission")
    for job_match in re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", workflow):
        job_name = job_match.group(1)
        if job_name == "create-release":
            continue
        block = job_block(workflow, job_name)
        if re.search(r"(?m)^    permissions:\n(?:      .*\n)*?      contents:\s+write\b", block):
            raise SystemExit(
                f"{job_name}: only create-release may request contents: write"
            )
    for match in re.finditer(r"(?m)^\s*uses:\s*([^\s#]+)", workflow):
        value = match.group(1)
        if "@" not in value:
            raise SystemExit(f"release workflow action reference lacks ref: {value}")
        _, ref = value.rsplit("@", 1)
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise SystemExit(f"release workflow action ref must be pinned to a full SHA: {value}")
    for match in re.finditer(
        r"(?m)^(\s*)-\s+uses:\s+actions/checkout@[0-9a-f]{40}\s*$",
        workflow,
    ):
        next_step = workflow.find("\n      - ", match.end())
        step_body = workflow[match.end() : next_step if next_step != -1 else len(workflow)]
        if "persist-credentials: false" not in step_body:
            raise SystemExit("release workflow checkout must disable persist-credentials")
    require_contains("release security-gates", security_gates, "./scripts/dependency-audit-gate.sh")
    require_contains(
        "release security-gates cargo-audit pin",
        security_gates,
        "cargo install cargo-audit --version 0.22.2 --locked",
    )
    require_contains("release security-gates elan hash", security_gates, "ELAN_INIT_SHA256:")
    require_contains("release security-gates elan hash check", security_gates, "sha256sum -c -")
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


def _collect_required_status_checks(data: object) -> set[str]:
    contexts: set[str] = set()
    if not isinstance(data, dict):
        return contexts
    direct = data.get("required_status_checks")
    if isinstance(direct, list):
        for item in direct:
            if isinstance(item, str):
                contexts.add(item)
            elif isinstance(item, dict) and isinstance(item.get("context"), str):
                contexts.add(item["context"])
    for rule in data.get("rules", []):
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        params = rule.get("parameters", {})
        if not isinstance(params, dict):
            continue
        for item in params.get("required_status_checks", []):
            if isinstance(item, str):
                contexts.add(item)
            elif isinstance(item, dict) and isinstance(item.get("context"), str):
                contexts.add(item["context"])
    return contexts


def check_ruleset_export(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise SystemExit("ruleset export schema_version must be 1")
    if data.get("target") != "branch":
        raise SystemExit("ruleset export target must be branch")
    if data.get("enforcement") != "active":
        raise SystemExit("ruleset export enforcement must be active")
    conditions = data.get("conditions", {})
    ref_name = conditions.get("ref_name", {}) if isinstance(conditions, dict) else {}
    includes = set(ref_name.get("include", [])) if isinstance(ref_name, dict) else set()
    if "~DEFAULT_BRANCH" not in includes and "refs/heads/main" not in includes:
        raise SystemExit("ruleset export must include the default branch or main")
    contexts = _collect_required_status_checks(data)
    missing = sorted(REQUIRED_RULESET_CHECKS - contexts)
    if missing:
        raise SystemExit(
            "ruleset export missing required status checks: " + ", ".join(missing)
        )
    print(f"branch protection ruleset gate passed: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors", type=Path)
    parser.add_argument("--ci-workflow", type=Path)
    parser.add_argument("--release-workflow", type=Path)
    parser.add_argument("--ruleset-export", type=Path)
    args = parser.parse_args()

    check_vectors(args.vectors)
    if args.ci_workflow is not None:
        check_ci_workflow(args.ci_workflow)
    if args.release_workflow is not None:
        check_release_workflow(args.release_workflow)
    if args.ruleset_export is not None:
        check_ruleset_export(args.ruleset_export)


if __name__ == "__main__":
    main()
