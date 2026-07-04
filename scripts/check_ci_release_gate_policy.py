#!/usr/bin/env python3
"""Check Lean-generated CI release-gate vectors and workflow wiring."""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

REJECTION_NAMES = {
    "dependency_audit_missing",
    "dependency_audit_waiver_gate_missing",
    "formal_core_missing",
    "security_adversarial_missing",
    "native_backend_security_missing",
    "app_no_ssh_e2e_missing",
    "release_build_missing",
    "release_build_dependency_missing",
    "release_build_security_adversarial_dependency_missing",
    "release_build_native_backend_security_dependency_missing",
    "release_build_app_no_ssh_e2e_dependency_missing",
    "non_release_job_contents_write",
    "release_binary_audit_missing",
    "tag_release_native_backend_review_missing",
    "tag_release_native_backend_posture_missing",
    "app_ui_guard_missing",
    "branch_protection_ruleset_missing",
}

REQUIRED_RULESET_CHECKS = {
    "dependency-audit",
    "formal-core",
    "security-adversarial",
    "native-backend-security",
    "app-no-ssh-e2e",
    "release-build",
}

SHELL_CONTROL_TOKENS = {"||", "&&", "|", "|&", "&", ";"}


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
    if not case["app_no_ssh_e2e_job"]:
        return False, "app_no_ssh_e2e_missing"
    if not case["release_build_job"]:
        return False, "release_build_missing"
    if not case["release_build_needs_security_gates"]:
        return False, "release_build_dependency_missing"
    if not case["release_build_needs_security_adversarial"]:
        return False, "release_build_security_adversarial_dependency_missing"
    if not case["release_build_needs_native_backend_security"]:
        return False, "release_build_native_backend_security_dependency_missing"
    if not case["release_build_needs_app_no_ssh_e2e"]:
        return False, "release_build_app_no_ssh_e2e_dependency_missing"
    if not case["non_release_jobs_no_contents_write"]:
        return False, "non_release_job_contents_write"
    if not case["release_binary_audit_step"]:
        return False, "release_binary_audit_missing"
    if not case["tag_release_native_backend_review_step"]:
        return False, "tag_release_native_backend_review_missing"
    if not case["tag_release_native_backend_posture_step"]:
        return False, "tag_release_native_backend_posture_missing"
    if not case["app_ui_guard_step"]:
        return False, "app_ui_guard_missing"
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
            "app_no_ssh_e2e_job",
            "release_build_job",
            "release_build_needs_security_gates",
            "release_build_needs_security_adversarial",
            "release_build_needs_native_backend_security",
            "release_build_needs_app_no_ssh_e2e",
            "non_release_jobs_no_contents_write",
            "release_binary_audit_step",
            "tag_release_native_backend_review_step",
            "tag_release_native_backend_posture_step",
            "app_ui_guard_step",
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


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def run_commands(job_text: str) -> list[str]:
    commands: list[str] = []
    lines = job_text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if match is None:
            index += 1
            continue
        base_indent = len(match.group(1))
        value = match.group(2).strip()
        if value in {"|", ">"}:
            index += 1
            block_lines: list[str] = []
            while index < len(lines) and _indent(lines[index]) > base_indent:
                block_lines.append(lines[index].strip())
                index += 1
            commands.append("\n".join(block_lines))
        else:
            commands.append(value)
            index += 1
    return commands


def _command_lines(command: str) -> list[str]:
    return [
        line.strip()
        for line in command.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _tokens_match_prefix(line: str, expected_tokens: list[str]) -> bool:
    try:
        actual = shlex.split(line, comments=True, posix=True)
    except ValueError:
        return False
    if len(actual) < len(expected_tokens) or actual[: len(expected_tokens)] != expected_tokens:
        return False
    return not any(token in SHELL_CONTROL_TOKENS for token in actual[len(expected_tokens) :])


def require_run_prefix(name: str, text: str, expected: str) -> None:
    expected_tokens = shlex.split(expected, posix=True)
    for command in run_commands(text):
        for line in _command_lines(command):
            if _tokens_match_prefix(line, expected_tokens):
                return
    raise SystemExit(f"{name}: missing executable run command {expected!r}")


def require_run_contains_all(name: str, text: str, command: str, fragments: list[str]) -> None:
    command_tokens = shlex.split(command, posix=True)
    for run_command in run_commands(text):
        for line in _command_lines(run_command):
            if _tokens_match_prefix(line, command_tokens) and all(
                fragment in line for fragment in fragments
            ):
                return
    raise SystemExit(
        f"{name}: missing executable run command {command!r} with required arguments"
    )


def _self_test() -> None:
    good_job = "    steps:\n      run: ./scripts/dependency-audit-gate.sh\n"
    require_run_prefix("self-test clean prefix", good_job, "./scripts/dependency-audit-gate.sh")
    for suffix in ("|| true", "&& true", "| cat", "&"):
        try:
            require_run_prefix(
                "self-test fail-open prefix",
                f"    steps:\n      run: ./scripts/dependency-audit-gate.sh {suffix}\n",
                "./scripts/dependency-audit-gate.sh",
            )
        except SystemExit:
            continue
        raise SystemExit(f"self-test accepted fail-open suffix {suffix!r}")
    good_audit = (
        "    steps:\n"
        "      run: ./scripts/security-audit.sh --require-binary "
        "--node-bin target/release/hegemon-node --binary target/release/wallet "
        "--binary target/release/walletd\n"
    )
    require_binary_audit(
        "self-test binary audit",
        good_audit,
        "target/release/hegemon-node",
        "target/release/wallet",
        "target/release/walletd",
    )
    try:
        require_binary_audit(
            "self-test fail-open binary audit",
            good_audit.replace("walletd", "walletd || true"),
            "target/release/hegemon-node",
            "target/release/wallet",
            "target/release/walletd",
        )
    except SystemExit:
        print("ci release gate checker self-test passed")
        return
    raise SystemExit("self-test accepted fail-open binary audit suffix")


def require_run_line_contains_all(name: str, text: str, fragments: list[str]) -> None:
    for run_command in run_commands(text):
        for line in _command_lines(run_command):
            if all(fragment in line for fragment in fragments):
                return
    raise SystemExit(f"{name}: missing executable run line with required fragments")


def require_needs(name: str, text: str, required: str) -> None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)needs:\s*(.*)$", line)
        if match is None:
            continue
        base_indent = len(match.group(1))
        value = match.group(2).strip()
        if value:
            if value.startswith("[") and value.endswith("]"):
                entries = [entry.strip().strip("'\"") for entry in value[1:-1].split(",")]
                if required in entries:
                    return
            if required == value.strip("'\""):
                return
            continue
        cursor = index + 1
        while cursor < len(lines) and _indent(lines[cursor]) > base_indent:
            item = re.match(r"^\s*-\s*([A-Za-z0-9_-]+)\s*$", lines[cursor])
            if item is not None and item.group(1) == required:
                return
            cursor += 1
    raise SystemExit(f"{name}: missing needs entry {required!r}")


def require_binary_audit(
    name: str,
    text: str,
    node_bin: str,
    wallet_bin: str,
    walletd_bin: str,
) -> None:
    require_run_contains_all(
        name,
        text,
        "./scripts/security-audit.sh",
        [
            "--require-binary",
            f"--node-bin {node_bin}",
            f"--binary {wallet_bin}",
            f"--binary {walletd_bin}",
        ],
    )


def check_ci_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    release_build = job_block(workflow, "release-build")
    dependency_audit = job_block(workflow, "dependency-audit")
    job_block(workflow, "formal-core")
    security_adversarial = job_block(workflow, "security-adversarial")
    native_backend_security = job_block(workflow, "native-backend-security")
    app_no_ssh = job_block(workflow, "app-no-ssh-e2e")
    require_run_prefix(
        "dependency-audit waiver gate",
        dependency_audit,
        "./scripts/dependency-audit-gate.sh",
    )
    require_run_prefix(
        "app no-SSH E2E gate",
        app_no_ssh,
        "./scripts/check-app-no-ssh-e2e.sh",
    )
    require_run_prefix("app UI guard install", app_no_ssh, "npm ci --prefix hegemon-app")
    require_run_prefix(
        "app UI guard gate",
        app_no_ssh,
        "npm --prefix hegemon-app run check:ui-guards",
    )
    require_run_prefix(
        "security-adversarial red-team gate",
        security_adversarial,
        "bash scripts/run_proving_redteam.sh",
    )
    require_run_prefix(
        "native-backend-security review package tests",
        native_backend_security,
        "cargo test -p superneo-backend-lattice -p native-backend-ref -p superneo-hegemon -p superneo-bench",
    )
    require_run_prefix(
        "native-backend-security vector verification",
        native_backend_security,
        "cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors",
    )
    require_run_prefix(
        "native-backend-security timing gate",
        native_backend_security,
        "cargo run -p native-backend-timing --release",
    )
    require_run_prefix(
        "native-backend-security receipt-root scalability gate",
        native_backend_security,
        "bash scripts/verify_native_receipt_root_scalability.sh",
    )
    require_run_prefix(
        "native-backend-security tx-leaf fuzz gate",
        native_backend_security,
        "cargo +nightly-2026-06-23 fuzz run native_tx_leaf_artifact",
    )
    require_run_prefix(
        "native-backend-security receipt-root fuzz gate",
        native_backend_security,
        "cargo +nightly-2026-06-23 fuzz run receipt_root_artifact",
    )
    require_run_prefix(
        "native-backend-security package gate",
        native_backend_security,
        "./scripts/package_native_backend_review.sh",
    )
    require_run_prefix(
        "native-backend-security package verification",
        native_backend_security,
        "./scripts/verify_native_backend_review_package.sh",
    )
    require_run_prefix(
        "native-backend-security release posture",
        native_backend_security,
        "./scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
    )
    require_needs("release-build needs dependency-audit", release_build, "dependency-audit")
    require_needs("release-build needs formal-core", release_build, "formal-core")
    require_needs(
        "release-build needs security-adversarial",
        release_build,
        "security-adversarial",
    )
    require_needs(
        "release-build needs native-backend-security",
        release_build,
        "native-backend-security",
    )
    require_needs(
        "release-build needs app-no-SSH E2E",
        release_build,
        "app-no-ssh-e2e",
    )
    require_run_prefix("release-build build command", release_build, "./scripts/check-core.sh build")
    require_binary_audit(
        "release-build binary audit",
        release_build,
        "target/release/hegemon-node",
        "target/release/wallet",
        "target/release/walletd",
    )
    print(f"ci workflow release-build gate passed: {path}")


def check_release_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^permissions:\n\s+contents:\s+write\b", workflow):
        raise SystemExit("release workflow must not grant workflow-wide contents: write")
    if not re.search(r"(?m)^permissions:\n\s+contents:\s+read\b", workflow):
        raise SystemExit("release workflow must default to workflow-wide contents: read")
    security_gates = job_block(workflow, "security-gates")
    app_no_ssh = job_block(workflow, "app-no-ssh-e2e")
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
    require_run_prefix("release security-gates", security_gates, "./scripts/dependency-audit-gate.sh")
    require_run_prefix(
        "release security-gates cargo-audit pin",
        security_gates,
        "cargo install cargo-audit --version 0.22.2 --locked",
    )
    require_contains("release security-gates elan hash", security_gates, "ELAN_INIT_SHA256:")
    require_run_line_contains_all(
        "release security-gates elan hash check",
        security_gates,
        ["| sha256sum -c -"],
    )
    require_run_prefix("release security-gates", security_gates, "bash scripts/check_formal_core.sh")
    require_run_prefix(
        "release security-gates",
        security_gates,
        "./scripts/verify_native_backend_review_package.sh",
    )
    require_run_prefix(
        "release security-gates",
        security_gates,
        "./scripts/check_native_backend_release_posture.sh",
    )
    require_needs("release app no-SSH needs", app_no_ssh, "security-gates")
    require_run_prefix(
        "release app no-SSH gate",
        app_no_ssh,
        "./scripts/check-app-no-ssh-e2e.sh",
    )
    require_run_prefix("release app UI guard install", app_no_ssh, "npm ci --prefix hegemon-app")
    require_run_prefix(
        "release app UI guard gate",
        app_no_ssh,
        "npm --prefix hegemon-app run check:ui-guards",
    )
    for job_name in (
        "build-linux",
        "build-macos-intel",
        "build-macos-arm",
        "build-windows",
    ):
        block = job_block(workflow, job_name)
        require_needs(f"{job_name} needs security-gates", block, "security-gates")
        require_needs(f"{job_name} needs app-no-SSH E2E", block, "app-no-ssh-e2e")
        if job_name == "build-macos-intel":
            require_binary_audit(
                f"{job_name} binary audit",
                block,
                "target/x86_64-apple-darwin/release/hegemon-node",
                "target/x86_64-apple-darwin/release/wallet",
                "target/x86_64-apple-darwin/release/walletd",
            )
        elif job_name == "build-windows":
            require_binary_audit(
                f"{job_name} binary audit",
                block,
                "target/release/hegemon-node.exe",
                "target/release/wallet.exe",
                "target/release/walletd.exe",
            )
        else:
            require_binary_audit(
                f"{job_name} binary audit",
                block,
                "target/release/hegemon-node",
                "target/release/wallet",
                "target/release/walletd",
            )
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
    parser.add_argument("vectors", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--ci-workflow", type=Path)
    parser.add_argument("--release-workflow", type=Path)
    parser.add_argument("--ruleset-export", type=Path)
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        if args.vectors is None:
            return
    if args.vectors is None:
        raise SystemExit("vectors path is required unless --self-test is used")
    check_vectors(args.vectors)
    if args.ci_workflow is not None:
        check_ci_workflow(args.ci_workflow)
    if args.release_workflow is not None:
        check_release_workflow(args.release_workflow)
    if args.ruleset_export is not None:
        check_ruleset_export(args.ruleset_export)


if __name__ == "__main__":
    main()
