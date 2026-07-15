#!/usr/bin/env python3
"""Check Lean-generated CI release-gate vectors and workflow wiring."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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


@dataclass(frozen=True)
class WorkflowStep:
    index: int
    name: str | None
    uses: str | None
    run: str | None
    condition: str | None


def _yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _condition_is_disabled(condition: str | None) -> bool:
    if condition is None:
        return False
    normalized = _yaml_scalar(condition).strip().lower()
    if normalized.startswith("${{") and normalized.endswith("}}"):
        normalized = normalized[3:-2].strip()
    return normalized in {"false", "0", "null", "~"}


def workflow_steps(workflow: str, job_name: str) -> list[WorkflowStep]:
    body = job_block(workflow, job_name)
    lines = body.splitlines()
    try:
        steps_line = next(
            index for index, line in enumerate(lines) if re.fullmatch(r"    steps:\s*", line)
        )
    except StopIteration as exc:
        raise SystemExit(f"{job_name}: steps block missing") from exc

    starts = [
        index
        for index in range(steps_line + 1, len(lines))
        if re.match(r"^      -(?:\s|$)", lines[index])
    ]
    steps: list[WorkflowStep] = []
    for step_index, start in enumerate(starts):
        end = starts[step_index + 1] if step_index + 1 < len(starts) else len(lines)
        step_lines = lines[start:end]
        first = re.sub(r"^      -\s*", "", step_lines[0], count=1)
        fields: dict[str, str] = {}
        run_lines: list[str] | None = None
        for line_index, line in enumerate([f"        {first}", *step_lines[1:]]):
            match = re.match(r"^        (name|uses|if|run):(?:\s*(.*))?$", line)
            if match is None:
                continue
            key = match.group(1)
            value = match.group(2) or ""
            if key == "run" and re.fullmatch(r"[|>][-+]?", value.strip()):
                run_lines = []
                for continuation in [f"        {first}", *step_lines[1:]][line_index + 1 :]:
                    if continuation.strip() and not continuation.startswith("          "):
                        break
                    run_lines.append(
                        continuation[10:] if continuation.startswith("          ") else ""
                    )
            else:
                fields[key] = _yaml_scalar(value)
        if run_lines is not None:
            fields["run"] = "\n".join(run_lines)
        steps.append(
            WorkflowStep(
                index=step_index,
                name=fields.get("name"),
                uses=fields.get("uses"),
                run=fields.get("run"),
                condition=fields.get("if"),
            )
        )
    if not steps:
        raise SystemExit(f"{job_name}: no executable steps found")
    return steps


def _logical_shell_lines(script: str) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def _simple_shell_command(line: str) -> str | None:
    """Return a comment-free command only when no shell control syntax is present."""
    single_quoted = False
    double_quoted = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if single_quoted:
            if character == "'":
                single_quoted = False
            continue
        if double_quoted:
            if character == '"':
                double_quoted = False
            elif character == "\\":
                escaped = True
            elif character == "`" or (
                character == "$" and index + 1 < len(line) and line[index + 1] == "("
            ):
                return None
            continue
        if character == "'":
            single_quoted = True
        elif character == '"':
            double_quoted = True
        elif character == "\\":
            escaped = True
        elif character == "#":
            line = line[:index]
            break
        elif character in ";&|<>()`" or (
            character == "$" and index + 1 < len(line) and line[index + 1] == "("
        ):
            return None
    if single_quoted or double_quoted or escaped:
        return None
    return line.strip() or None


def _command_tokens(line: str) -> list[str]:
    line = _simple_shell_command(line)
    if line is None:
        return []
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return []
    while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        tokens.pop(0)
    if tokens and tokens[0] == "env":
        tokens.pop(0)
        while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens.pop(0)
    return tokens


def _contains_ordered_tokens(tokens: list[str], required: tuple[str, ...]) -> bool:
    position = 0
    for required_token in required:
        try:
            position = tokens.index(required_token, position) + 1
        except ValueError:
            return False
    return True


def step_executes_command(
    step: WorkflowStep,
    executable: str,
    required_tokens: tuple[str, ...] = (),
) -> bool:
    if step.run is None or step.condition is not None:
        return False
    expected = executable.removeprefix("./")
    logical = _logical_shell_lines(step.run)
    commands = [line for line in logical if line != "set -euo pipefail"]
    if len(commands) != 1:
        return False
    for line in commands:
        tokens = _command_tokens(line)
        if not tokens:
            continue
        command_index = 0
        if tokens[0] in {"bash", "sh", "python", "python3"}:
            command_index = 1
        if command_index >= len(tokens):
            continue
        command = tokens[command_index].removeprefix("./")
        if command != expected:
            continue
        command_tokens = tokens[command_index + 1 :]
        if any(
            token in {"-h", "--help", "-V", "--version"}
            and token not in required_tokens
            for token in command_tokens
        ):
            continue
        if _contains_ordered_tokens(command_tokens, required_tokens):
            return True
    return False


def require_executable_command(
    name: str,
    steps: list[WorkflowStep],
    executable: str,
    required_tokens: tuple[str, ...] = (),
) -> int:
    for step in steps:
        if step_executes_command(step, executable, required_tokens):
            return step.index
    suffix = "" if not required_tokens else f" with tokens {required_tokens!r}"
    raise SystemExit(f"{name}: executable command {executable!r}{suffix} missing")


def require_action(name: str, steps: list[WorkflowStep], action: str) -> int:
    for step in steps:
        if step.condition is not None or step.uses is None:
            continue
        if step.uses.split("@", 1)[0] == action:
            return step.index
    raise SystemExit(f"{name}: enabled action {action!r} missing")


def require_step_order(name: str, *indexes: int) -> None:
    if list(indexes) != sorted(indexes) or len(set(indexes)) != len(indexes):
        raise SystemExit(f"{name}: executable release steps are out of order")


def require_lean_installer_outside_worktree(name: str, text: str) -> None:
    require_contains(name, text, 'ELAN_INIT="$RUNNER_TEMP/elan-init.sh"')
    require_contains(name, text, '-o "$ELAN_INIT"')
    require_contains(name, text, 'sh "$ELAN_INIT" -y --default-toolchain none')
    if re.search(r"(?m)-o\s+elan-init\.sh(?:\s|$)", text):
        raise SystemExit(f"{name}: Lean installer download must not dirty the worktree")


def require_binary_audit(
    name: str,
    steps: list[WorkflowStep],
    node_bin: str,
    wallet_bin: str,
    walletd_bin: str,
    manifest: str,
) -> int:
    return require_executable_command(
        name,
        steps,
        "scripts/security-audit.sh",
        (
            "--require-binary",
            "--binary-manifest",
            manifest,
            "--node-bin",
            node_bin,
            "--binary",
            wallet_bin,
            "--binary",
            walletd_bin,
        ),
    )


def require_asset_package(
    name: str,
    steps: list[WorkflowStep],
    manifest: str,
    node_bin: str,
    wallet_bin: str,
    walletd_bin: str,
    node_asset: str,
    wallet_asset: str,
    walletd_asset: str,
    asset_manifest: str,
) -> int:
    return require_executable_command(
        name,
        steps,
        "scripts/release_artifact_manifest.py",
        (
            "package",
            "--manifest",
            manifest,
            "--expect",
            f"hegemon-node:hegemon-node:{node_bin}",
            "--expect",
            f"wallet:wallet:{wallet_bin}",
            "--expect",
            f"walletd:walletd:{walletd_bin}",
            "--asset",
            f"hegemon-node:hegemon-node:{node_asset}",
            "--asset",
            f"wallet:wallet:{wallet_asset}",
            "--asset",
            f"walletd:walletd:{walletd_asset}",
            "--output-dir",
            "release",
            "--asset-manifest-name",
            asset_manifest,
        ),
    )


def check_ci_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    release_build = job_block(workflow, "release-build")
    dependency_audit = job_block(workflow, "dependency-audit")
    formal_core = job_block(workflow, "formal-core")
    core_tests = job_block(workflow, "core-tests")
    security_adversarial = job_block(workflow, "security-adversarial")
    job_block(workflow, "native-backend-security")
    app_no_ssh = job_block(workflow, "app-no-ssh-e2e")
    dependency_steps = workflow_steps(workflow, "dependency-audit")
    app_steps = workflow_steps(workflow, "app-no-ssh-e2e")
    release_steps = workflow_steps(workflow, "release-build")
    require_lean_installer_outside_worktree("formal-core Lean installer", formal_core)
    require_lean_installer_outside_worktree("core-tests Lean installer", core_tests)
    require_lean_installer_outside_worktree(
        "security-adversarial Lean installer",
        security_adversarial,
    )
    require_executable_command(
        "dependency-audit waiver gate",
        dependency_steps,
        "scripts/dependency-audit-gate.sh",
    )
    require_executable_command(
        "app no-SSH E2E gate",
        app_steps,
        "scripts/check-app-no-ssh-e2e.sh",
    )
    require_executable_command(
        "app UI guard install", app_steps, "npm", ("ci", "--prefix", "hegemon-app")
    )
    require_executable_command(
        "app UI guard gate",
        app_steps,
        "npm",
        ("--prefix", "hegemon-app", "run", "check:ui-guards"),
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
    require_contains(
        "release-build needs app-no-SSH E2E",
        release_build,
        "- app-no-ssh-e2e",
    )
    build_index = require_executable_command(
        "release-build build command", release_steps, "scripts/check-core.sh", ("build",)
    )
    audit_index = require_binary_audit(
        "release-build binary audit",
        release_steps,
        "target/release/hegemon-node",
        "target/release/wallet",
        "target/release/walletd",
        "target/release/hegemon-release-artifacts.json",
    )
    require_step_order("release-build build/audit order", build_index, audit_index)
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
    security_steps = workflow_steps(workflow, "security-gates")
    app_steps = workflow_steps(workflow, "app-no-ssh-e2e")
    require_executable_command(
        "release security-gates", security_steps, "scripts/dependency-audit-gate.sh"
    )
    require_executable_command(
        "release security-gates cargo-audit pin",
        security_steps,
        "cargo",
        ("install", "cargo-audit", "--version", "0.22.2", "--locked"),
    )
    require_contains("release security-gates elan hash", security_gates, "ELAN_INIT_SHA256:")
    require_contains("release security-gates elan hash check", security_gates, "sha256sum -c -")
    require_lean_installer_outside_worktree(
        "release security-gates Lean installer",
        security_gates,
    )
    require_executable_command(
        "release security-gates", security_steps, "scripts/check_formal_core.sh"
    )
    require_executable_command(
        "release security-gates",
        security_steps,
        "scripts/verify_native_backend_review_package.sh",
    )
    require_executable_command(
        "release security-gates",
        security_steps,
        "scripts/check_native_backend_release_posture.sh",
    )
    require_contains("release app no-SSH needs", app_no_ssh, "needs: security-gates")
    require_executable_command(
        "release app no-SSH gate",
        app_steps,
        "scripts/check-app-no-ssh-e2e.sh",
    )
    require_executable_command(
        "release app UI guard install", app_steps, "npm", ("ci", "--prefix", "hegemon-app")
    )
    require_executable_command(
        "release app UI guard gate",
        app_steps,
        "npm",
        ("--prefix", "hegemon-app", "run", "check:ui-guards"),
    )
    for job_name in (
        "build-linux",
        "build-macos-intel",
        "build-macos-arm",
        "build-windows",
    ):
        block = job_block(workflow, job_name)
        steps = workflow_steps(workflow, job_name)
        require_contains(f"{job_name} needs security-gates", block, "security-gates")
        require_contains(f"{job_name} needs app-no-SSH E2E", block, "app-no-ssh-e2e")
        build_index = require_executable_command(
            f"{job_name} attested build",
            steps,
            "scripts/build_release_artifacts.sh",
        )
        if job_name == "build-macos-intel":
            manifest_path = "target/x86_64-apple-darwin/release/hegemon-release-artifacts.json"
            node_bin = "target/x86_64-apple-darwin/release/hegemon-node"
            wallet_bin = "target/x86_64-apple-darwin/release/wallet"
            walletd_bin = "target/x86_64-apple-darwin/release/walletd"
            asset_suffix = "macos-x86_64"
            asset_manifest = "hegemon-release-assets-macos-x86_64.json"
        elif job_name == "build-windows":
            manifest_path = "target/release/hegemon-release-artifacts.json"
            node_bin = "target/release/hegemon-node.exe"
            wallet_bin = "target/release/wallet.exe"
            walletd_bin = "target/release/walletd.exe"
            asset_suffix = "windows-x86_64.exe"
            asset_manifest = "hegemon-release-assets-windows-x86_64.json"
        elif job_name == "build-macos-arm":
            manifest_path = "target/release/hegemon-release-artifacts.json"
            node_bin = "target/release/hegemon-node"
            wallet_bin = "target/release/wallet"
            walletd_bin = "target/release/walletd"
            asset_suffix = "macos-arm64"
            asset_manifest = "hegemon-release-assets-macos-arm64.json"
        else:
            manifest_path = "target/release/hegemon-release-artifacts.json"
            node_bin = "target/release/hegemon-node"
            wallet_bin = "target/release/wallet"
            walletd_bin = "target/release/walletd"
            asset_suffix = "linux-x86_64"
            asset_manifest = "hegemon-release-assets-linux-x86_64.json"
        manifest_index = require_executable_command(
            f"{job_name} manifest verification",
            steps,
            "scripts/release_artifact_manifest.py",
            (
                "verify",
                "--manifest",
                manifest_path,
                "--expect",
                f"hegemon-node:hegemon-node:{node_bin}",
                "--expect",
                f"wallet:wallet:{wallet_bin}",
                "--expect",
                f"walletd:walletd:{walletd_bin}",
            ),
        )
        audit_index = require_binary_audit(
            f"{job_name} binary audit",
            steps,
            node_bin,
            wallet_bin,
            walletd_bin,
            manifest_path,
        )
        package_index = require_asset_package(
            f"{job_name} manifest-bound asset package",
            steps,
            manifest_path,
            node_bin,
            wallet_bin,
            walletd_bin,
            f"hegemon-node-{asset_suffix}",
            f"wallet-{asset_suffix}",
            f"walletd-{asset_suffix}",
            asset_manifest,
        )
        upload_index = require_action(
            f"{job_name} artifact upload", steps, "actions/upload-artifact"
        )
        require_step_order(
            f"{job_name} attestation/package order",
            build_index,
            manifest_index,
            audit_index,
            package_index,
            upload_index,
        )
    intel_runner = re.search(
        r"(?m)^    runs-on:\s*([^#\s]+)", job_block(workflow, "build-macos-intel")
    )
    if intel_runner is None or _yaml_scalar(intel_runner.group(1)) != "macos-15-intel":
        raise SystemExit("build-macos-intel must execute on native macos-15-intel")

    create_steps = workflow_steps(workflow, "create-release")
    download_index = require_action(
        "create-release artifact download", create_steps, "actions/download-artifact"
    )
    prepare_index = require_executable_command(
        "create-release manifest-bound asset assembly",
        create_steps,
        "scripts/release_artifact_manifest.py",
        (
            "assemble",
            "--bundle-manifest",
            "artifacts/linux-binary/hegemon-release-assets-linux-x86_64.json",
            "--bundle-manifest",
            "artifacts/macos-intel-binary/hegemon-release-assets-macos-x86_64.json",
            "--bundle-manifest",
            "artifacts/macos-arm-binary/hegemon-release-assets-macos-arm64.json",
            "--bundle-manifest",
            "artifacts/windows-binary/hegemon-release-assets-windows-x86_64.json",
            "--output-dir",
            "release-assets",
        ),
    )
    release_index = require_action(
        "create-release publication", create_steps, "softprops/action-gh-release"
    )
    require_step_order(
        "create-release download/prepare/publish order",
        download_index,
        prepare_index,
        release_index,
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
