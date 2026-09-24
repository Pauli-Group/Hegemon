#!/usr/bin/env python3
"""Check Lean-generated CI release-gate vectors and workflow wiring."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
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

PINNED_CHECKOUT_ACTION = (
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
)
PINNED_UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
)
PINNED_RELEASE_WORKFLOW_SHA512 = (
    "f08ffb8a3567293bc1c77f16ba089d260626c70db897f5bc9f85a0271ffd9588e"
    "b2537b5eeb458762aef9f5da385a459e32567099c196f58eac909ae57f0ed6b"
)
SUCCESSOR_CHECKER_RELATIVE_PATH = Path(
    "scripts/check_transaction_proof_successor_authorization.py"
)
SUCCESSOR_REGISTRY_RELATIVE_PATH = Path(
    "scripts/transaction_proof_successor_authorized_registry.py"
)
FORMAL_CRYPTO_POSEIDON2_V8_TRIGGER_PATHS = (
    "circuits/transaction/src/smallwood_poseidon2_v8_program.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_security.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_zk_refinement.rs",
    "config/smallwood-v8-poseidon2-profile-manifest.json",
    "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json",
    "docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json",
    "scripts/check_transaction_proof_successor_authorization.py",
    "scripts/test_check_transaction_proof_successor_authorization.py",
    "scripts/check_ci_release_gate_policy.py",
    "scripts/test_check_ci_release_gate_policy.py",
)


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


def require_canonical_workflow_syntax(workflow: str) -> None:
    """Reject YAML spellings that the deliberately small parser cannot audit safely."""
    if "\t" in workflow:
        raise SystemExit("workflow YAML must not contain tabs")
    if re.search(
        r'''(?m)^ *(?:-\s+)?(?:"(?:[^"\\]|\\.)*"|'[^']*') *:''',
        workflow,
    ):
        raise SystemExit("workflow YAML must not use quoted mapping keys")
    if re.search(r"(?m)^\s*(?:-\s+)?\?\s+", workflow):
        raise SystemExit("workflow YAML must not use explicit/complex mapping keys")
    if re.search(r"(?m)^\s*(?:-\s+)?!{1,2}(?:[A-Za-z_]|<)", workflow):
        raise SystemExit("workflow YAML must not use tagged mapping keys")
    if re.search(r"(?m)^\s*(?:-\s+)?<<\s*:", workflow):
        raise SystemExit("workflow YAML must not use merge keys")
    if re.search(r"(?m)(?<!\S)[&*][A-Za-z_][A-Za-z0-9_-]*\b", workflow):
        raise SystemExit("workflow YAML must not use anchors or aliases")
    if re.search(
        r"(?m)^\s*(?:-\s+)?[A-Za-z_][A-Za-z0-9_-]*\s+:", workflow
    ):
        raise SystemExit("workflow YAML mapping keys must use canonical key: syntax")

    top_level_keys = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_-]*):", workflow)
    duplicates = sorted(
        key for key in set(top_level_keys) if top_level_keys.count(key) > 1
    )
    if duplicates:
        raise SystemExit(
            f"workflow YAML contains duplicate top-level keys: {duplicates!r}"
        )
    if top_level_keys.count("jobs") != 1:
        raise SystemExit("workflow YAML must contain exactly one canonical jobs mapping")


def require_commit_rooted_successor_authority(repository_root: Path) -> None:
    """Require the checker and its registry to come from the release checkout."""

    root = repository_root.resolve(strict=True)

    def source_text(relative: Path, label: str) -> str:
        lexical = root / relative
        if lexical.is_symlink() or not lexical.is_file():
            raise SystemExit(f"{label} must be a regular nonsymlink file in the checkout")
        resolved = lexical.resolve(strict=True)
        try:
            observed = resolved.relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"{label} must stay inside the release checkout") from exc
        if observed != relative:
            raise SystemExit(f"{label} path must be canonical inside the release checkout")
        return resolved.read_text(encoding="utf-8")

    checker = source_text(SUCCESSOR_CHECKER_RELATIVE_PATH, "successor checker")
    registry = source_text(SUCCESSOR_REGISTRY_RELATIVE_PATH, "successor registry")
    registry_path = SUCCESSOR_REGISTRY_RELATIVE_PATH.as_posix()
    for marker in (
        f'"{registry_path}"',
        "def load_source_owned_registry(",
        "repository_root = checker.parents[1]",
        "_, registry_payload = read_regular_file_beneath(",
        "registry_module = ast.parse(",
        "def parse_registry_literal(",
        "source-owned authorized registry may contain only a module",
        "AUTHORIZED_PROFILES: dict[str, AuthorizedProfile] = load_source_owned_registry()",
        "SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS",
        "SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS",
        "HERMETIC_RELEASE_AUTHORITY_SCHEMA",
        "HERMETIC_RELEASE_AUTHORITY_KEYS",
        "HERMETIC_RELEASE_REQUIRED_BOOTSTRAP_ROLES",
        "HERMETIC_RELEASE_REQUIRED_COMMAND_ROLES",
        '"PATH": ""',
        "SOURCE_BOUND_HERMETIC_RELEASE_ROOTS",
        "def require_source_bound_hermetic_release_authority(",
        "source-owned hermetic release root authority is absent",
        "hermetic release runtime is not provisioned in this revision",
        "if artifact_command_runner is run_artifact_verifier_command:",
        "SOURCE_COMMAND_RECEIPT_SCHEMA",
        "source command output is not bound",
        "SOURCE_EVIDENCE_PATHS_BY_ID",
        "if declared_path != expected_path:",
        "RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES",
        "RETAINED_SOURCE_INVENTORY_ROOT_FEATURES",
        "load_excluded_local_package",
        "inactive_in_source_owned_default_feature_graph",
        "resolve_checkout_source_revision",
        "requires a clean tracked and untracked tree",
        "run_with_source_inventory_guard",
        "source revision changed during execution",
        "run_descriptor_bound_executable",
        "execution requires Linux sealed memfd authority",
        "os.memfd_create(",
        "MFD_ALLOW_SEALING",
        "fcntl.F_ADD_SEALS",
        "fcntl.F_GET_SEALS",
        "fcntl.F_SEAL_WRITE",
        "fcntl.F_SEAL_GROW",
        "fcntl.F_SEAL_SHRINK",
        "fcntl.F_SEAL_SEAL",
        'execution_path = f"/proc/self/fd/{sealed_descriptor}"',
        "pass_fds=(sealed_descriptor,)",
        "artifact verification path must be absolute",
        "sealed memfd differs from the opened verifier",
        "sealed verifier bytes changed during execution",
        "opened bytes changed during execution",
        "CAPABILITY_IDENTITY_FIELDS",
        '"production_capability_manifest": "manifest"',
        '"production_value_balance_zero_projection_receipt": "receipt"',
        "capability_identity_sha512",
        "native_projection_enforces_zero",
        "SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS",
        "LIFECYCLE_STATE_BINDING_KEYS",
        "candidate_height must equal parent_height + 1",
        "note anchor does not match capability note_genesis_root",
        "does not match capability stablecoin genesis",
        "integration command inventory",
        "command_runner(argv, root)",
        "lifecycle command output digest mismatch",
        "lifecycle proof digest is not the retained primary",
        "parser_stage_labels_used_as_authority",
        "validity_shortcuts_used",
        "SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS",
        "INDEPENDENT_REVIEW_ARTIFACT_SCHEMA",
        "ML_DSA_87_PUBLIC_KEY_BYTES",
        "FORMAL_SECURITY_RECEIPT_BINDINGS",
        "deployed_smz9_adaptive_qrom_whole_view_release_receipt",
        "deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le",
        "must name the exact required global QROM lifetime receipt",
    ):
        if marker not in checker:
            raise SystemExit(
                "successor checker does not load the reviewed registry from its own checkout"
            )
    if '"release_authorization_checker_source": "source"' in checker:
        raise SystemExit("successor checker must not hash itself through its evidence bundle")
    if "AUTHORIZED_PROFILE_RECORDS =" not in registry:
        raise SystemExit("successor registry does not expose source-owned profile records")


def top_level_scalar_mapping(workflow: str, key: str) -> dict[str, str]:
    """Parse one canonical top-level scalar mapping without YAML ambiguities."""

    lines = workflow.splitlines()
    headers = [index for index, line in enumerate(lines) if line == f"{key}:"]
    if len(headers) != 1:
        raise SystemExit(f"workflow must contain exactly one canonical top-level {key} mapping")
    result: dict[str, str] = {}
    for line in lines[headers[0] + 1 :]:
        if line and not line.startswith(" "):
            break
        if not line.strip() or re.fullmatch(r"\s*#.*", line):
            continue
        match = re.fullmatch(r"  ([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*", line)
        if match is None:
            raise SystemExit(f"workflow top-level {key} mapping is non-canonical")
        name, value = match.groups()
        if name in result:
            raise SystemExit(f"workflow top-level {key} mapping duplicates {name}")
        result[name] = _yaml_scalar(value)
    return result


def require_exact_release_trigger(workflow: str) -> None:
    """Pin release authority to one reviewed v-prefixed tag push event."""

    lines = workflow.splitlines()
    headers = [index for index, line in enumerate(lines) if line == "on:"]
    if len(headers) != 1:
        raise SystemExit("release workflow must contain exactly one canonical on mapping")
    block: list[str] = []
    for line in lines[headers[0] :]:
        if block and line and not line.startswith(" "):
            break
        block.append(line)
    while block and not block[-1]:
        block.pop()
    if block != ["on:", "  push:", "    tags:", "      - 'v*'"]:
        raise SystemExit(
            "release workflow trigger must be exactly push.tags=['v*'] with no other events"
        )


def require_exact_job_execution_context(
    workflow: str,
    job_name: str,
    *,
    runner: str,
    allowed_env: dict[str, str] | None = None,
) -> None:
    """Pin the host/shell context for jobs that carry release authority."""

    body = job_block(workflow, job_name)
    job_keys = re.findall(r"(?m)^    ([A-Za-z_][A-Za-z0-9_-]*):", body)
    forbidden_keys = {"container", "defaults", "services", "uses"}
    if allowed_env is None:
        forbidden_keys.add("env")
    forbidden = sorted(forbidden_keys.intersection(job_keys))
    if forbidden:
        raise SystemExit(f"{job_name}: forbidden execution-context keys: {forbidden!r}")
    runners = re.findall(r"(?m)^    runs-on:\s*(.*?)\s*$", body)
    if runners != [runner]:
        raise SystemExit(f"{job_name}: runs-on must equal {runner!r}")
    if allowed_env is not None and job_scalar_mapping(workflow, job_name, "env") != allowed_env:
        raise SystemExit(f"{job_name}: job env must equal the reviewed safe mapping")


def job_scalar_mapping(workflow: str, job_name: str, key: str) -> dict[str, str]:
    body = job_block(workflow, job_name)
    lines = body.splitlines()
    headers = [index for index, line in enumerate(lines) if line == f"    {key}:"]
    if len(headers) != 1:
        raise SystemExit(f"{job_name}: must contain exactly one canonical {key} mapping")
    result: dict[str, str] = {}
    for line in lines[headers[0] + 1 :]:
        if re.match(r"^    [A-Za-z_][A-Za-z0-9_-]*:", line):
            break
        if not line.strip() or re.fullmatch(r"\s*#.*", line):
            continue
        match = re.fullmatch(r"      ([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*", line)
        if match is None:
            raise SystemExit(f"{job_name}: {key} mapping is non-canonical")
        name, value = match.groups()
        if name in result:
            raise SystemExit(f"{job_name}: {key} mapping duplicates {name}")
        result[name] = _yaml_scalar(value)
    return result


def job_block(workflow: str, job_name: str) -> str:
    job_keys = re.findall(rf"(?m)^  {re.escape(job_name)}\s*:", workflow)
    if not job_keys:
        raise SystemExit(f"workflow job missing: {job_name}")
    if len(job_keys) != 1:
        raise SystemExit(f"workflow job duplicated: {job_name}")
    pattern = re.compile(
        rf"(?ms)^  {re.escape(job_name)}:\n"
        rf"(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
    )
    match = pattern.search(workflow)
    if match is None:
        raise SystemExit(f"workflow job must use a canonical block mapping: {job_name}")
    return match.group("body")


def require_contains(name: str, text: str, needle: str) -> None:
    if needle not in text:
        raise SystemExit(f"{name}: missing {needle!r}")


def job_needs(workflow: str, job_name: str) -> tuple[str, ...]:
    body = job_block(workflow, job_name)
    lines = body.splitlines()
    matches = [
        (index, match.group(1) or "")
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"    needs:(?:\s*(.*))?", line))
    ]
    if not matches:
        return ()
    if len(matches) != 1:
        raise SystemExit(f"{job_name}: duplicate needs key")
    index, inline = matches[0]
    inline = inline.strip()
    if inline:
        if re.fullmatch(r"[A-Za-z0-9_-]+", inline):
            return (inline,)
        list_match = re.fullmatch(r"\[\s*([^]]*?)\s*\]", inline)
        if list_match is None:
            raise SystemExit(f"{job_name}: needs must use a canonical scalar or list")
        raw_items = list_match.group(1)
        if not raw_items:
            return ()
        items = tuple(item.strip() for item in raw_items.split(","))
        if not all(re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in items):
            raise SystemExit(f"{job_name}: needs contains a non-canonical job id")
        return items

    items: list[str] = []
    for line in lines[index + 1 :]:
        if not line.strip() or re.fullmatch(r"\s*#.*", line):
            continue
        if re.match(r"^    [A-Za-z_][A-Za-z0-9_-]*:", line):
            break
        item_match = re.fullmatch(r"      - ([A-Za-z0-9_-]+)\s*", line)
        if item_match is None:
            raise SystemExit(f"{job_name}: needs block contains non-canonical YAML")
        items.append(item_match.group(1))
    return tuple(items)


def require_exact_needs(
    workflow: str,
    job_name: str,
    expected: tuple[str, ...],
) -> None:
    observed = job_needs(workflow, job_name)
    if len(observed) != len(set(observed)):
        raise SystemExit(f"{job_name}: needs contains duplicate job ids")
    if set(observed) != set(expected):
        raise SystemExit(
            f"{job_name}: needs must be exactly {sorted(expected)!r}; "
            f"observed {sorted(observed)!r}"
        )


def require_exact_matrix_values(
    workflow: str,
    job_name: str,
    matrix_name: str,
    expected: tuple[str, ...],
) -> None:
    lines = job_block(workflow, job_name).splitlines()
    matrix_lines = [
        index for index, line in enumerate(lines) if line == "      matrix:"
    ]
    if len(matrix_lines) != 1:
        raise SystemExit(f"{job_name}: must contain exactly one canonical matrix block")
    start = matrix_lines[0]
    value_lines = [
        index
        for index in range(start + 1, len(lines))
        if lines[index] == f"        {matrix_name}:"
    ]
    if len(value_lines) != 1:
        raise SystemExit(
            f"{job_name}: must contain exactly one canonical {matrix_name} matrix"
        )
    values: list[str] = []
    for line in lines[value_lines[0] + 1 :]:
        if not line.strip() or re.fullmatch(r"\s*#.*", line):
            continue
        if re.match(r"^        [A-Za-z_][A-Za-z0-9_-]*:", line) or re.match(
            r"^    [A-Za-z_][A-Za-z0-9_-]*:", line
        ):
            break
        item = re.fullmatch(r"          - ([A-Za-z0-9_-]+)\s*", line)
        if item is None:
            raise SystemExit(f"{job_name}: {matrix_name} matrix is non-canonical")
        values.append(item.group(1))
    if len(values) != len(set(values)) or set(values) != set(expected):
        raise SystemExit(
            f"{job_name}: {matrix_name} matrix must be exactly "
            f"{sorted(expected)!r}; observed {sorted(values)!r}"
        )


@dataclass(frozen=True)
class WorkflowStep:
    index: int
    name: str | None
    uses: str | None
    run: str | None
    condition: str | None
    continue_on_error: str | None
    shell: str | None
    working_directory: str | None
    with_fields: tuple[tuple[str, str], ...]
    env_fields: tuple[tuple[str, str], ...]
    keys: tuple[str, ...]


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


def _continue_on_error_is_safely_disabled(value: str | None) -> bool:
    if value is None:
        return True
    normalized = _yaml_scalar(value).strip().lower()
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
        if re.fullmatch(r"      - (?:name|uses|run):(?:\s*.*)?", step_lines[0]) is None:
            raise SystemExit(
                f"{job_name}: step {step_index} must begin with a canonical block "
                "name, uses, or run key"
            )
        first = re.sub(r"^      -\s*", "", step_lines[0], count=1)
        normalized_step_lines = [f"        {first}", *step_lines[1:]]
        step_keys = [
            match.group(1)
            for line in normalized_step_lines
            if (match := re.match(r"^        ([A-Za-z_][A-Za-z0-9_-]*):", line))
        ]
        duplicate_step_keys = sorted(
            key for key in set(step_keys) if step_keys.count(key) > 1
        )
        if duplicate_step_keys:
            raise SystemExit(
                f"{job_name}: step {step_index} contains duplicate keys: "
                f"{duplicate_step_keys!r}"
            )
        parsed_with_fields: list[tuple[str, str]] = []
        with_lines = [
            index
            for index, line in enumerate(normalized_step_lines)
            if line == "        with:"
        ]
        if len(with_lines) > 1:
            raise SystemExit(f"{job_name}: step {step_index} contains duplicate with blocks")
        if with_lines:
            for line in normalized_step_lines[with_lines[0] + 1 :]:
                if re.match(r"^        [A-Za-z_][A-Za-z0-9_-]*:", line):
                    break
                match = re.match(
                    r"^          ([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?$",
                    line,
                )
                if match is not None:
                    parsed_with_fields.append(
                        (match.group(1), _yaml_scalar(match.group(2) or ""))
                    )
            with_keys = [key for key, _ in parsed_with_fields]
            duplicate_with_keys = sorted(
                key for key in set(with_keys) if with_keys.count(key) > 1
            )
            if duplicate_with_keys:
                raise SystemExit(
                    f"{job_name}: step {step_index} contains duplicate with keys: "
                    f"{duplicate_with_keys!r}"
                )
        parsed_env_fields: list[tuple[str, str]] = []
        env_lines = [
            index
            for index, line in enumerate(normalized_step_lines)
            if line == "        env:"
        ]
        if len(env_lines) > 1:
            raise SystemExit(f"{job_name}: step {step_index} contains duplicate env blocks")
        if env_lines:
            for line in normalized_step_lines[env_lines[0] + 1 :]:
                if re.match(r"^        [A-Za-z_][A-Za-z0-9_-]*:", line):
                    break
                match = re.match(
                    r"^          ([A-Za-z_][A-Za-z0-9_]*):(?:\s*(.*))?$",
                    line,
                )
                if match is not None:
                    parsed_env_fields.append(
                        (match.group(1), _yaml_scalar(match.group(2) or ""))
                    )
            env_keys = [key for key, _ in parsed_env_fields]
            duplicate_env_keys = sorted(
                key for key in set(env_keys) if env_keys.count(key) > 1
            )
            if duplicate_env_keys:
                raise SystemExit(
                    f"{job_name}: step {step_index} contains duplicate env keys: "
                    f"{duplicate_env_keys!r}"
                )
        fields: dict[str, str] = {}
        run_lines: list[str] | None = None
        for line_index, line in enumerate(normalized_step_lines):
            match = re.match(
                r"^        (name|uses|if|run|continue-on-error|shell|working-directory):"
                r"(?:\s*(.*))?$",
                line,
            )
            if match is None:
                continue
            key = match.group(1)
            value = match.group(2) or ""
            if key == "run" and re.fullmatch(r"[|>][-+]?", value.strip()):
                run_lines = []
                for continuation in normalized_step_lines[line_index + 1 :]:
                    if continuation.strip() and not continuation.startswith("          "):
                        break
                    run_lines.append(
                        continuation[10:] if continuation.startswith("          ") else ""
                    )
            else:
                fields[key] = _yaml_scalar(value)
        if run_lines is not None:
            fields["run"] = "\n".join(run_lines)
        if (fields.get("uses") is None) == (fields.get("run") is None):
            raise SystemExit(
                f"{job_name}: step {step_index} must contain exactly one uses or run key"
            )
        steps.append(
            WorkflowStep(
                index=step_index,
                name=fields.get("name"),
                uses=fields.get("uses"),
                run=fields.get("run"),
                condition=fields.get("if"),
                continue_on_error=fields.get("continue-on-error"),
                shell=fields.get("shell"),
                working_directory=fields.get("working-directory"),
                with_fields=tuple(parsed_with_fields),
                env_fields=tuple(parsed_env_fields),
                keys=tuple(step_keys),
            )
        )
    if not steps:
        raise SystemExit(f"{job_name}: no executable steps found")
    return steps


def require_job_and_steps_fail_closed(
    workflow: str,
    job_name: str,
    *,
    allow_always_condition: bool = False,
) -> None:
    body = job_block(workflow, job_name)
    job_keys = re.findall(r"(?m)^    ([A-Za-z_][A-Za-z0-9_-]*):", body)
    duplicate_job_keys = sorted(
        key for key in set(job_keys) if job_keys.count(key) > 1
    )
    if duplicate_job_keys:
        raise SystemExit(
            f"{job_name}: duplicate job-level keys: {duplicate_job_keys!r}"
        )
    job_conditions = re.findall(r"(?m)^    if:(?:\s*(.*))?$", body)
    if len(job_conditions) > 1:
        raise SystemExit(f"{job_name}: duplicate job-level if")
    if job_conditions:
        normalized = _yaml_scalar(job_conditions[0]).strip()
        if not allow_always_condition or normalized != "${{ always() }}":
            raise SystemExit(f"{job_name}: job-level if is not permitted")
    job_values = re.findall(
        r"(?m)^    continue-on-error:(?:\s*(.*))?$",
        body,
    )
    if len(job_values) > 1:
        raise SystemExit(f"{job_name}: duplicate job-level continue-on-error")
    if job_values and not _continue_on_error_is_safely_disabled(job_values[0]):
        raise SystemExit(f"{job_name}: job-level continue-on-error must be false")
    for step in workflow_steps(workflow, job_name):
        if not _continue_on_error_is_safely_disabled(step.continue_on_error):
            step_name = step.name or f"step {step.index}"
            raise SystemExit(
                f"{job_name}: {step_name}: continue-on-error must be false"
            )


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
        # Preserve leading assignments and `env`.  A protected workflow step
        # must invoke the reviewed executable in the workflow-declared
        # environment; silently discarding `PYTHONPATH=...`, `PATH=...`, or an
        # `env` wrapper would let a different interpreter/module graph satisfy
        # the textual command check.
        return shlex.split(line, posix=True)
    except ValueError:
        return []


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
    *,
    exact_argument_vectors: tuple[tuple[str, ...], ...] | None = None,
    require_default_execution_context: bool = False,
    exact_interpreter_prefix: tuple[str, ...] | None = None,
) -> bool:
    if (
        step.run is None
        or step.condition is not None
        or not _continue_on_error_is_safely_disabled(step.continue_on_error)
    ):
        return False
    if require_default_execution_context and {
        "env",
        "shell",
        "working-directory",
    }.intersection(step.keys):
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
        if exact_interpreter_prefix is not None:
            prefix_length = len(exact_interpreter_prefix)
            if tuple(tokens[:prefix_length]) != exact_interpreter_prefix:
                continue
            command_index = prefix_length
        else:
            command_index = 0
            if tokens[0] in {"bash", "sh"}:
                command_index = 1
            elif tokens[0] in {"python", "python3", "/usr/bin/python3"}:
                command_index = 1
                # Recognize only isolated mode and the bytecode-cache flag used by
                # the checked-in workflow. Treat every other interpreter option as
                # non-executable evidence so `-c`, `-m`, help/version, or an option
                # with an operand cannot smuggle a different program past the gate.
                while command_index < len(tokens) and tokens[command_index] in {"-B", "-I"}:
                    command_index += 1
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
        if exact_argument_vectors is not None:
            if tuple(command_tokens) in exact_argument_vectors:
                return True
            continue
        if _contains_ordered_tokens(command_tokens, required_tokens):
            return True
    return False


def require_executable_command(
    name: str,
    steps: list[WorkflowStep],
    executable: str,
    required_tokens: tuple[str, ...] = (),
    *,
    exact_argument_vectors: tuple[tuple[str, ...], ...] | None = None,
    require_default_execution_context: bool = False,
    exact_interpreter_prefix: tuple[str, ...] | None = None,
) -> int:
    for step in steps:
        if step_executes_command(
            step,
            executable,
            required_tokens,
            exact_argument_vectors=exact_argument_vectors,
            require_default_execution_context=require_default_execution_context,
            exact_interpreter_prefix=exact_interpreter_prefix,
        ):
            return step.index
    if exact_argument_vectors is not None:
        suffix = f" with exact arguments in {exact_argument_vectors!r}"
    else:
        suffix = "" if not required_tokens else f" with tokens {required_tokens!r}"
    raise SystemExit(f"{name}: executable command {executable!r}{suffix} missing")


def require_action(name: str, steps: list[WorkflowStep], action: str) -> int:
    for step in steps:
        if (
            step.condition is not None
            or step.uses is None
            or not _continue_on_error_is_safely_disabled(step.continue_on_error)
        ):
            continue
        if step.uses.split("@", 1)[0] == action:
            return step.index
    raise SystemExit(f"{name}: enabled action {action!r} missing")


def require_checkout_credentials_disabled(
    name: str,
    steps: list[WorkflowStep],
) -> int:
    checkout_steps = [
        step
        for step in steps
        if step.uses is not None
        and step.uses.split("@", 1)[0] == "actions/checkout"
    ]
    if len(checkout_steps) != 1:
        raise SystemExit(f"{name}: exactly one checkout action is required")
    step = checkout_steps[0]
    if step.uses != PINNED_CHECKOUT_ACTION:
        raise SystemExit(f"{name}: checkout action must use the pinned exact revision")
    if step.condition is not None or not _continue_on_error_is_safely_disabled(
        step.continue_on_error
    ):
        raise SystemExit(f"{name}: checkout must be unconditional and fail closed")
    if tuple(step.with_fields) != (("persist-credentials", "false"),):
        raise SystemExit(
            f"{name}: checkout with-fields must be exactly persist-credentials=false"
        )
    if {"env", "shell", "working-directory"}.intersection(step.keys):
        raise SystemExit(f"{name}: checkout execution context must not be overridden")
    return step.index


def require_step_order(name: str, *indexes: int) -> None:
    if list(indexes) != sorted(indexes) or len(set(indexes)) != len(indexes):
        raise SystemExit(f"{name}: executable release steps are out of order")


def require_exact_step_execution_context(
    name: str,
    step: WorkflowStep,
    *,
    shell: str | None,
) -> None:
    if "env" in step.keys or step.env_fields:
        raise SystemExit(f"{name}: step env is forbidden")
    if step.working_directory is not None or "working-directory" in step.keys:
        raise SystemExit(f"{name}: working-directory override is forbidden")
    if step.shell != shell:
        expected = "the default shell" if shell is None else repr(shell)
        raise SystemExit(f"{name}: shell must equal {expected}")


def require_strict_success_aggregate(
    workflow: str,
    job_name: str,
    prerequisites: tuple[tuple[str, str], ...],
) -> None:
    """Require an always-running aggregate to fail unless every need succeeded."""
    body = job_block(workflow, job_name)
    steps = workflow_steps(workflow, job_name)
    executable_steps = [step for step in steps if step.run is not None]
    if len(executable_steps) != 1:
        raise SystemExit(f"{job_name}: must contain exactly one aggregate run step")
    step = executable_steps[0]
    if (
        step.condition is not None
        or not _continue_on_error_is_safely_disabled(step.continue_on_error)
    ):
        raise SystemExit(f"{job_name}: aggregate run step must be unconditional and fail closed")

    expected_commands: list[str] = []
    for need, variable in prerequisites:
        env_pattern = re.compile(
            rf"(?m)^          {re.escape(variable)}:\s*"
            rf"\$\{{\{{\s*needs\.{re.escape(need)}\.result\s*\}}\}}\s*$"
        )
        if env_pattern.search(body) is None:
            raise SystemExit(
                f"{job_name}: missing exact {variable} binding for needs.{need}.result"
            )
        expected_commands.append(f'test "${variable}" = success')
    if _logical_shell_lines(step.run or "") != expected_commands:
        raise SystemExit(
            f"{job_name}: aggregate must contain only exact strict-success checks"
        )


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
    arguments = (
        "--require-binary",
        "--binary-manifest",
        manifest,
        "--node-bin",
        node_bin,
        "--binary",
        wallet_bin,
        "--binary",
        walletd_bin,
    )
    return require_executable_command(
        name,
        steps,
        "scripts/security-audit.sh",
        arguments,
        exact_argument_vectors=(arguments,),
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
    arguments = (
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
    )
    return require_executable_command(
        name,
        steps,
        "scripts/release_artifact_manifest.py",
        arguments,
        exact_argument_vectors=(arguments,),
        exact_interpreter_prefix=("python3",),
    )


def check_ci_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    require_canonical_workflow_syntax(workflow)
    required_jobs = (
        "rust-lints",
        "dependency-audit",
        "formal-core-checker",
        "formal-core-lean",
        "formal-core-vectors",
        "formal-core-policy",
        "formal-core",
        "formal-crypto-isolation",
        "formal-crypto-sanity",
        "core-test-shards",
        "core-tests",
        "native-path-tests",
        "app-no-ssh-e2e",
        "security-adversarial",
        "native-backend-security",
        "release-binaries",
        "release-build",
    )
    for job_name in required_jobs:
        require_job_and_steps_fail_closed(
            workflow,
            job_name,
            allow_always_condition=job_name
            in {"formal-core", "core-tests", "release-build"},
        )
    for timed_job in (
        "rust-lints",
        "dependency-audit",
        "formal-core-checker",
        "formal-core-lean",
        "formal-core-vectors",
        "formal-core-policy",
        "formal-crypto-isolation",
        "formal-crypto-sanity",
        "core-test-shards",
        "native-path-tests",
        "app-no-ssh-e2e",
        "security-adversarial",
        "native-backend-security",
        "release-binaries",
    ):
        require_contains(
            f"{timed_job} wall-clock budget",
            job_block(workflow, timed_job),
            "timeout-minutes: 30",
        )
    release_build = job_block(workflow, "release-build")
    dependency_audit = job_block(workflow, "dependency-audit")
    formal_core = job_block(workflow, "formal-core")
    formal_core_checker = job_block(workflow, "formal-core-checker")
    formal_core_lean = job_block(workflow, "formal-core-lean")
    formal_core_vectors = job_block(workflow, "formal-core-vectors")
    formal_core_policy = job_block(workflow, "formal-core-policy")
    formal_crypto_isolation = job_block(workflow, "formal-crypto-isolation")
    formal_crypto_sanity = job_block(workflow, "formal-crypto-sanity")
    core_tests = job_block(workflow, "core-tests")
    job_block(workflow, "core-test-shards")
    security_adversarial = job_block(workflow, "security-adversarial")
    native_backend_security = job_block(workflow, "native-backend-security")
    app_no_ssh = job_block(workflow, "app-no-ssh-e2e")
    dependency_steps = workflow_steps(workflow, "dependency-audit")
    app_steps = workflow_steps(workflow, "app-no-ssh-e2e")
    release_steps = workflow_steps(workflow, "release-binaries")
    formal_crypto_isolation_steps = workflow_steps(workflow, "formal-crypto-isolation")
    formal_crypto_sanity_steps = workflow_steps(workflow, "formal-crypto-sanity")
    formal_core_checker_steps = workflow_steps(workflow, "formal-core-checker")
    formal_core_lean_steps = workflow_steps(workflow, "formal-core-lean")
    formal_core_vectors_steps = workflow_steps(workflow, "formal-core-vectors")
    formal_core_policy_steps = workflow_steps(workflow, "formal-core-policy")
    require_strict_success_aggregate(
        workflow,
        "formal-core",
        (
            ("formal-core-checker", "CHECKER_RESULT"),
            ("formal-core-lean", "LEAN_RESULT"),
            ("formal-core-vectors", "VECTORS_RESULT"),
            ("formal-core-policy", "POLICY_RESULT"),
        ),
    )
    require_exact_needs(
        workflow,
        "formal-core",
        (
            "formal-core-checker",
            "formal-core-lean",
            "formal-core-vectors",
            "formal-core-policy",
        ),
    )
    require_strict_success_aggregate(
        workflow,
        "core-tests",
        (("core-test-shards", "SHARD_RESULT"),),
    )
    require_exact_needs(workflow, "core-tests", ("core-test-shards",))
    require_strict_success_aggregate(
        workflow,
        "release-build",
        (
            ("rust-lints", "RUST_LINTS_RESULT"),
            ("dependency-audit", "DEPENDENCY_AUDIT_RESULT"),
            ("formal-core", "FORMAL_CORE_RESULT"),
            ("formal-crypto-isolation", "FORMAL_CRYPTO_ISOLATION_RESULT"),
            ("formal-crypto-sanity", "FORMAL_CRYPTO_SANITY_RESULT"),
            ("core-tests", "CORE_TESTS_RESULT"),
            ("native-path-tests", "NATIVE_PATH_TESTS_RESULT"),
            ("app-no-ssh-e2e", "APP_NO_SSH_E2E_RESULT"),
            ("security-adversarial", "SECURITY_ADVERSARIAL_RESULT"),
            ("native-backend-security", "NATIVE_BACKEND_SECURITY_RESULT"),
            ("release-binaries", "RELEASE_BINARIES_RESULT"),
        ),
    )
    require_exact_needs(
        workflow,
        "release-build",
        (
            "rust-lints",
            "dependency-audit",
            "formal-core",
            "formal-crypto-isolation",
            "formal-crypto-sanity",
            "core-tests",
            "native-path-tests",
            "app-no-ssh-e2e",
            "security-adversarial",
            "native-backend-security",
            "release-binaries",
        ),
    )
    require_contains(
        "release-build aggregate wall-clock budget",
        release_build,
        "timeout-minutes: 2",
    )
    require_contains(
        "release-build aggregate always runs",
        release_build,
        "if: ${{ always() }}",
    )
    require_lean_installer_outside_worktree(
        "formal-core Lean proof-kernel installer", formal_core_lean
    )
    require_lean_installer_outside_worktree(
        "formal-core vectors Lean installer", formal_core_vectors
    )
    require_lean_installer_outside_worktree(
        "formal-crypto sanity Lean installer", formal_crypto_sanity
    )
    require_lean_installer_outside_worktree(
        "security-adversarial Lean installer",
        security_adversarial,
    )
    for label, steps, mode in (
        ("formal-core checker gate", formal_core_checker_steps, "checker"),
        ("formal-core Lean gate", formal_core_lean_steps, "lean"),
        ("formal-core vector gate", formal_core_vectors_steps, "vectors"),
        ("formal-core policy gate", formal_core_policy_steps, "policy"),
    ):
        require_executable_command(
            label,
            steps,
            "scripts/check_formal_core.sh",
            exact_argument_vectors=((mode,),),
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
    require_contains(
        "formal-core aggregate needs checker",
        formal_core,
        "- formal-core-checker",
    )
    require_contains(
        "formal-core aggregate needs Lean proof kernel",
        formal_core,
        "- formal-core-lean",
    )
    require_contains(
        "formal-core aggregate needs vectors",
        formal_core,
        "- formal-core-vectors",
    )
    require_contains(
        "formal-core aggregate needs policy",
        formal_core,
        "- formal-core-policy",
    )
    require_executable_command(
        "formal-crypto isolation gate",
        formal_crypto_isolation_steps,
        "scripts/check_formal_crypto.sh",
        exact_argument_vectors=(("--isolation-only",),),
    )
    formal_crypto_gate_index = require_executable_command(
        "complete formal-crypto gate",
        formal_crypto_sanity_steps,
        "scripts/check_formal_crypto.sh",
        exact_argument_vectors=(("full",),),
    )
    source_security_report_index = require_executable_command(
        "formal-crypto SMZ9 source-security report exact regression",
        formal_crypto_sanity_steps,
        "cargo",
        exact_argument_vectors=(
            (
                "run",
                "--locked",
                "-p",
                "transaction-circuit",
                "--example",
                "smallwood_poseidon2_v8_security_report",
                "--",
                "--check",
                "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json",
            ),
        ),
        require_default_execution_context=True,
    )
    successor_policy_regression_index = require_executable_command(
        "formal-crypto transaction-proof successor authorization regression",
        formal_crypto_sanity_steps,
        "scripts/test_check_transaction_proof_successor_authorization.py",
        exact_argument_vectors=((),),
        require_default_execution_context=True,
        exact_interpreter_prefix=("python3", "-I", "-B"),
    )
    require_step_order(
        "formal-crypto report/authorization fail-fast order",
        source_security_report_index,
        successor_policy_regression_index,
        formal_crypto_gate_index,
    )
    require_exact_needs(
        workflow,
        "formal-crypto-sanity",
        ("formal-crypto-isolation",),
    )
    require_executable_command(
        "formal-crypto production parser refinement regression",
        formal_crypto_sanity_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smallwood_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "formal-crypto SMZ8 parser refinement regression",
        formal_crypto_sanity_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "formal-crypto SMZ9 parser refinement regression",
        formal_crypto_sanity_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "formal-crypto V8 PendingAction private-codec conformance regression",
        formal_crypto_sanity_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "hegemon-node",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
        ),
    )
    required_core_shards = (
        "base",
        "transaction-lib",
        "transaction-integration",
        "wallet-base",
        "wallet-multisig-setup",
        "wallet-multisig-builders",
        "wallet-multisig-drift",
        "node-default",
        "node-minimal",
    )
    require_exact_matrix_values(
        workflow,
        "core-test-shards",
        "shard",
        required_core_shards,
    )
    require_executable_command(
        "core-tests exact matrix dispatch",
        workflow_steps(workflow, "core-test-shards"),
        "scripts/check-core.sh",
        exact_argument_vectors=(("test-${{ matrix.shard }}",),),
    )
    require_contains("core-tests aggregate needs shards", core_tests, "needs: core-test-shards")
    require_contains("release-build needs rust-lints", release_build, "- rust-lints")
    require_contains("release-build needs dependency-audit", release_build, "- dependency-audit")
    require_contains("release-build needs formal-core", release_build, "- formal-core")
    require_contains(
        "release-build needs formal-crypto isolation",
        release_build,
        "- formal-crypto-isolation",
    )
    require_contains(
        "release-build needs complete formal-crypto",
        release_build,
        "- formal-crypto-sanity",
    )
    require_contains("release-build needs core-tests", release_build, "- core-tests")
    require_contains(
        "release-build needs native-path-tests",
        release_build,
        "- native-path-tests",
    )
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
    require_contains(
        "release-build needs release binaries",
        release_build,
        "- release-binaries",
    )
    for job_name, result_name in (
        ("rust-lints", "RUST_LINTS_RESULT"),
        ("dependency-audit", "DEPENDENCY_AUDIT_RESULT"),
        ("formal-core", "FORMAL_CORE_RESULT"),
        ("formal-crypto-isolation", "FORMAL_CRYPTO_ISOLATION_RESULT"),
        ("formal-crypto-sanity", "FORMAL_CRYPTO_SANITY_RESULT"),
        ("core-tests", "CORE_TESTS_RESULT"),
        ("native-path-tests", "NATIVE_PATH_TESTS_RESULT"),
        ("app-no-ssh-e2e", "APP_NO_SSH_E2E_RESULT"),
        ("security-adversarial", "SECURITY_ADVERSARIAL_RESULT"),
        ("native-backend-security", "NATIVE_BACKEND_SECURITY_RESULT"),
        ("release-binaries", "RELEASE_BINARIES_RESULT"),
    ):
        require_contains(
            f"release-build records {job_name} result",
            release_build,
            f"{result_name}: ${{{{ needs.{job_name}.result }}}}",
        )
        require_contains(
            f"release-build requires {job_name} success",
            release_build,
            f'test "${result_name}" = success',
        )
    build_index = require_executable_command(
        "release-binaries build command", release_steps, "scripts/check-core.sh", ("build",)
    )
    audit_index = require_binary_audit(
        "release-binaries binary audit",
        release_steps,
        "target/release/hegemon-node",
        "target/release/wallet",
        "target/release/walletd",
        "target/release/hegemon-release-artifacts.json",
    )
    require_step_order("release-binaries build/audit order", build_index, audit_index)
    print(f"ci workflow release-build gate passed: {path}")


def check_formal_crypto_workflow(path: Path) -> None:
    """Require the focused proof-security triggers and executable refinements."""

    workflow = path.read_text(encoding="utf-8")
    require_canonical_workflow_syntax(workflow)
    try:
        push_start = workflow.index("  push:\n")
        pull_request_start = workflow.index("  pull_request:\n", push_start)
        permissions_start = workflow.index("\npermissions:\n", pull_request_start)
    except ValueError as exc:
        raise SystemExit("focused formal-crypto trigger structure is incomplete") from exc
    trigger_blocks = {
        "push": workflow[push_start:pull_request_start],
        "pull_request": workflow[pull_request_start:permissions_start],
    }
    for event, trigger_block in trigger_blocks.items():
        for trigger_path in FORMAL_CRYPTO_POSEIDON2_V8_TRIGGER_PATHS:
            trigger_line = f"      - '{trigger_path}'\n"
            if trigger_block.count(trigger_line) != 1:
                raise SystemExit(
                    f"focused formal-crypto {event} trigger must contain exactly one "
                    f"{trigger_path} path"
                )
    steps = workflow_steps(workflow, "formal-crypto-sanity")
    formal_crypto_gate_index = require_executable_command(
        "focused complete formal-crypto gate",
        steps,
        "scripts/check_formal_crypto.sh",
        exact_argument_vectors=(("full",),),
    )
    source_security_report_index = require_executable_command(
        "focused SMZ9 source-security report exact regression",
        steps,
        "cargo",
        exact_argument_vectors=(
            (
                "run",
                "--locked",
                "-p",
                "transaction-circuit",
                "--example",
                "smallwood_poseidon2_v8_security_report",
                "--",
                "--check",
                "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json",
            ),
        ),
        require_default_execution_context=True,
    )
    successor_policy_regression_index = require_executable_command(
        "focused transaction-proof successor authorization regression",
        steps,
        "scripts/test_check_transaction_proof_successor_authorization.py",
        exact_argument_vectors=((),),
        require_default_execution_context=True,
        exact_interpreter_prefix=("python3", "-I", "-B"),
    )
    require_step_order(
        "focused report/authorization fail-fast order",
        source_security_report_index,
        successor_policy_regression_index,
        formal_crypto_gate_index,
    )
    for label, test_name in (
        (
            "production parser refinement regression",
            "smallwood_engine::tests::lean_generated_smallwood_proof_wire_vectors_match_production_parser",
        ),
        (
            "SMZ8 parser refinement regression",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
        (
            "SMZ9 parser refinement regression",
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
        ),
    ):
        require_executable_command(
            f"focused {label}",
            steps,
            "scripts/run_exact_cargo_lib_test.sh",
            ("transaction-circuit", test_name),
        )
    require_executable_command(
        "focused V8 PendingAction private-codec conformance regression",
        steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "hegemon-node",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
        ),
    )
    print(f"focused formal-crypto workflow gate passed: {path}")


def check_release_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    if hashlib.sha512(workflow.encode("utf-8")).hexdigest() != PINNED_RELEASE_WORKFLOW_SHA512:
        raise SystemExit("release workflow SHA-512 differs from the reviewed source pin")
    resolved_workflow = path.resolve(strict=True)
    repository_root = resolved_workflow.parents[2]
    if resolved_workflow.relative_to(repository_root).as_posix() != (
        ".github/workflows/release.yml"
    ):
        raise SystemExit("release workflow must be checked from its canonical checkout path")
    require_commit_rooted_successor_authority(repository_root)
    require_canonical_workflow_syntax(workflow)
    top_level_keys = tuple(
        re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_-]*):", workflow)
    )
    if top_level_keys != ("name", "on", "env", "permissions", "jobs"):
        raise SystemExit(
            "release workflow top-level keys must equal the exact reviewed ordered set"
        )
    require_exact_release_trigger(workflow)
    if top_level_scalar_mapping(workflow, "env") != {
        "CARGO_TERM_COLOR": "always",
        "CARGO_NET_RETRY": "10",
        "CARGO_HTTP_TIMEOUT": "600",
    }:
        raise SystemExit("release workflow top-level env must equal the reviewed safe mapping")
    if re.search(r"(?m)^defaults:", workflow):
        raise SystemExit("release workflow must not override default shell or working directory")
    if top_level_scalar_mapping(workflow, "permissions") != {"contents": "read"}:
        raise SystemExit("release workflow permissions must be exactly contents=read")
    required_jobs = (
        "transaction-proof-authorization",
        "security-gates",
        "app-no-ssh-e2e",
        "build-linux",
        "build-macos-intel",
        "build-macos-arm",
        "build-windows",
        "create-release",
    )
    jobs_section = workflow.split("jobs:\n", 1)[1]
    observed_job_names: list[str] = []
    for line in jobs_section.splitlines():
        if not line.strip() or re.fullmatch(r"\s*#.*", line):
            continue
        if line.startswith("  ") and not line.startswith("    "):
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
            if match is None:
                raise SystemExit(
                    "release workflow jobs must use canonical block mappings only"
                )
            observed_job_names.append(match.group(1))
        elif not line.startswith(" "):
            raise SystemExit("release workflow must end with its canonical jobs mapping")
    observed_jobs = tuple(observed_job_names)
    if observed_jobs != required_jobs:
        raise SystemExit(
            "release workflow jobs must equal the exact reviewed ordered set; "
            f"observed={observed_jobs!r}"
        )
    for job_name in required_jobs:
        require_job_and_steps_fail_closed(workflow, job_name)
    require_exact_job_execution_context(
        workflow,
        "transaction-proof-authorization",
        runner="ubuntu-24.04",
    )
    require_exact_job_execution_context(
        workflow,
        "security-gates",
        runner="ubuntu-latest",
    )
    require_exact_job_execution_context(
        workflow,
        "create-release",
        runner="ubuntu-latest",
    )
    require_exact_job_execution_context(
        workflow,
        "app-no-ssh-e2e",
        runner="ubuntu-latest",
        allowed_env={"HEGEMON_E2E_MINE_THREADS": "4"},
    )
    for job_name, runner in (
        ("build-linux", "ubuntu-latest"),
        ("build-macos-intel", "macos-15-intel"),
        ("build-macos-arm", "macos-14"),
        ("build-windows", "windows-latest"),
    ):
        require_exact_job_execution_context(workflow, job_name, runner=runner)
    authorization_gates = job_block(workflow, "transaction-proof-authorization")
    security_gates = job_block(workflow, "security-gates")
    app_no_ssh = job_block(workflow, "app-no-ssh-e2e")
    create_release = job_block(workflow, "create-release")
    if job_scalar_mapping(workflow, "create-release", "permissions") != {
        "contents": "write"
    }:
        raise SystemExit("create-release permissions must be exactly contents=write")
    for job_name in required_jobs:
        if job_name == "create-release":
            continue
        block = job_block(workflow, job_name)
        if re.search(r"(?m)^    permissions(?:\s*:)", block):
            raise SystemExit(f"{job_name}: job-level permissions are forbidden")
    release_steps_by_job = {
        job_name: workflow_steps(workflow, job_name) for job_name in required_jobs
    }
    for job_name, steps in release_steps_by_job.items():
        for step in steps:
            if step.uses is None:
                continue
            if step.uses.count("@") != 1:
                raise SystemExit(
                    f"{job_name}: action reference must contain exactly one ref: {step.uses}"
                )
            _, ref = step.uses.rsplit("@", 1)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                raise SystemExit(
                    f"{job_name}: action ref must be pinned to a full SHA: {step.uses}"
                )
    for job_name in required_jobs:
        checkout_index = require_checkout_credentials_disabled(
            f"release {job_name}", release_steps_by_job[job_name]
        )
        if job_name in {
            "transaction-proof-authorization",
            "security-gates",
            "build-linux",
            "build-macos-intel",
            "build-macos-arm",
            "build-windows",
            "create-release",
        } and checkout_index != 0:
            raise SystemExit(f"release {job_name}: checkout must be the first step")
    require_exact_needs(
        workflow,
        "transaction-proof-authorization",
        (),
    )
    require_exact_needs(
        workflow,
        "security-gates",
        ("transaction-proof-authorization",),
    )
    authorization_steps = workflow_steps(workflow, "transaction-proof-authorization")
    if len(authorization_steps) != 7:
        raise SystemExit(
            "transaction-proof-authorization must contain exactly checkout, verifier build "
            "dependencies, pinned Rust, authorization, workflow policy, and two regressions"
        )
    require_contains(
        "release authorization verifier build dependencies",
        authorization_gates,
        "sudo apt-get update && sudo apt-get install -y protobuf-compiler libclang-dev clang lld",
    )
    require_contains(
        "release authorization pinned Rust action",
        authorization_gates,
        "uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8",
    )
    require_contains(
        "release authorization Rust toolchain",
        authorization_gates,
        'toolchain: "1.91.1"',
    )
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
        "release security-gates",
        security_steps,
        "scripts/check_formal_core.sh",
        exact_argument_vectors=((), ("all",)),
    )
    require_executable_command(
        "release formal-crypto isolation gate",
        security_steps,
        "scripts/check_formal_crypto.sh",
        exact_argument_vectors=(("--isolation-only",),),
    )
    require_executable_command(
        "release complete formal-crypto gate",
        security_steps,
        "scripts/check_formal_crypto.sh",
        exact_argument_vectors=(("full",),),
    )
    require_executable_command(
        "release production parser refinement regression",
        security_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smallwood_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "release SMZ8 parser refinement regression",
        security_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "release SMZ9 parser refinement regression",
        security_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "transaction-circuit",
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
        ),
    )
    require_executable_command(
        "release V8 PendingAction private-codec conformance regression",
        security_steps,
        "scripts/run_exact_cargo_lib_test.sh",
        (
            "hegemon-node",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
        ),
    )
    historical_authorization_regression_index = require_executable_command(
        "release historical SmallWood authorization regression",
        authorization_steps,
        "scripts/test_check_smallwood_production_authorization.py",
        exact_argument_vectors=((),),
        require_default_execution_context=True,
        exact_interpreter_prefix=("/usr/bin/python3", "-I", "-B"),
    )
    successor_authorization_regression_index = require_executable_command(
        "release transaction-proof successor authorization regression",
        authorization_steps,
        "scripts/test_check_transaction_proof_successor_authorization.py",
        exact_argument_vectors=((),),
        require_default_execution_context=True,
        exact_interpreter_prefix=("/usr/bin/python3", "-I", "-B"),
    )
    successor_authorization_index = require_executable_command(
        "release transaction-proof successor authorization gate",
        authorization_steps,
        "scripts/check_transaction_proof_successor_authorization.py",
        exact_argument_vectors=(
            (
                "config/transaction-proof-successor-selection.json",
                "--require-authorized",
                "--verify-retained-artifacts",
            ),
        ),
        require_default_execution_context=True,
        exact_interpreter_prefix=("/usr/bin/python3", "-I", "-B"),
    )
    release_policy_regression_index = require_executable_command(
        "release workflow policy regression",
        authorization_steps,
        "scripts/test_check_ci_release_gate_policy.py",
        exact_argument_vectors=((),),
        require_default_execution_context=True,
        exact_interpreter_prefix=("/usr/bin/python3", "-I", "-B"),
    )
    strict_v5_regression_index = require_executable_command(
        "release SmallWood V5 strict security regression",
        security_steps,
        ".agent/hardening/smallwood-pqc-zk/test_strict_profile.py",
    )
    v5_candidate_gate_index = require_executable_command(
        "release SmallWood V5 candidate manifest gate",
        security_steps,
        "scripts/check_smallwood_v5_candidate_gate.py",
    )
    require_contains(
        "release SmallWood V5 protected trust-root pin",
        security_gates,
        "HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256: "
        "${{ vars.HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256 }}",
    )
    native_review_index = require_executable_command(
        "release security-gates",
        security_steps,
        "scripts/verify_native_backend_review_package.sh",
    )
    native_posture_index = require_executable_command(
        "release security-gates",
        security_steps,
        "scripts/check_native_backend_release_posture.sh",
    )
    require_step_order(
        "release authorization/backend package gate order",
        successor_authorization_index,
        release_policy_regression_index,
        historical_authorization_regression_index,
        successor_authorization_regression_index,
    )
    require_step_order(
        "release backend package gate order",
        strict_v5_regression_index,
        v5_candidate_gate_index,
        native_review_index,
        native_posture_index,
    )
    require_exact_needs(workflow, "app-no-ssh-e2e", ("security-gates",))
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
        expected_step_count = 9 if job_name == "build-windows" else 8
        if len(steps) != expected_step_count:
            raise SystemExit(
                f"{job_name}: must contain exactly {expected_step_count} reviewed steps"
            )
        require_exact_needs(
            workflow,
            job_name,
            ("security-gates", "app-no-ssh-e2e"),
        )
        require_contains(f"{job_name} needs security-gates", block, "security-gates")
        require_contains(f"{job_name} needs app-no-SSH E2E", block, "app-no-ssh-e2e")
        build_arguments = (
            ("--target", "x86_64-apple-darwin")
            if job_name == "build-macos-intel"
            else ()
        )
        build_index = require_executable_command(
            f"{job_name} attested build",
            steps,
            "scripts/build_release_artifacts.sh",
            exact_argument_vectors=(build_arguments,),
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
        manifest_arguments = (
            "verify",
            "--manifest",
            manifest_path,
            "--expect",
            f"hegemon-node:hegemon-node:{node_bin}",
            "--expect",
            f"wallet:wallet:{wallet_bin}",
            "--expect",
            f"walletd:walletd:{walletd_bin}",
        )
        manifest_index = require_executable_command(
            f"{job_name} manifest verification",
            steps,
            "scripts/release_artifact_manifest.py",
            manifest_arguments,
            exact_argument_vectors=(manifest_arguments,),
            exact_interpreter_prefix=("python3",),
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
        upload_step = steps[upload_index]
        upload_name = {
            "build-linux": "linux-binary",
            "build-macos-intel": "macos-intel-binary",
            "build-macos-arm": "macos-arm-binary",
            "build-windows": "windows-binary",
        }[job_name]
        if (
            upload_step.uses != PINNED_UPLOAD_ARTIFACT_ACTION
            or tuple(upload_step.with_fields)
            != (("name", upload_name), ("path", "release/"))
            or upload_step.env_fields
            or {"env", "shell", "working-directory"}.intersection(upload_step.keys)
        ):
            raise SystemExit(f"{job_name}: artifact upload must equal the pinned exact action")
        expected_shell = "bash" if job_name == "build-windows" else None
        for label, index in (
            ("attested build", build_index),
            ("manifest verification", manifest_index),
            ("binary audit", audit_index),
            ("asset package", package_index),
        ):
            require_exact_step_execution_context(
                f"{job_name} {label}",
                steps[index],
                shell=expected_shell,
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
    if len(create_steps) != 4:
        raise SystemExit(
            "create-release must contain exactly checkout, download, assemble, and publish"
        )
    require_exact_needs(
        workflow,
        "create-release",
        ("build-linux", "build-macos-intel", "build-macos-arm", "build-windows"),
    )
    download_index = require_action(
        "create-release artifact download", create_steps, "actions/download-artifact"
    )
    download_step = create_steps[download_index]
    if (
        download_step.uses
        != "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        or tuple(download_step.with_fields) != (("path", "artifacts"),)
        or download_step.env_fields
        or {"env", "shell", "working-directory"}.intersection(download_step.keys)
    ):
        raise SystemExit("create-release download step must equal the pinned exact action")
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
        exact_argument_vectors=(
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
        ),
        require_default_execution_context=True,
        exact_interpreter_prefix=("/usr/bin/python3", "-I", "-B"),
    )
    release_index = require_action(
        "create-release publication", create_steps, "softprops/action-gh-release"
    )
    release_step = create_steps[release_index]
    if (
        release_step.uses
        != "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"
        or tuple(release_step.with_fields)
        != (
            ("draft", "true"),
            ("generate_release_notes", "true"),
            ("files", "release-assets/*"),
        )
        or tuple(release_step.env_fields)
        != (("GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}"),)
        or {"shell", "working-directory"}.intersection(release_step.keys)
    ):
        raise SystemExit("create-release publication step must equal the pinned exact action")
    require_step_order(
        "create-release download/prepare/publish order",
        0,
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
    parser.add_argument("--formal-crypto-workflow", type=Path)
    parser.add_argument("--release-workflow", type=Path)
    parser.add_argument("--ruleset-export", type=Path)
    args = parser.parse_args()

    check_vectors(args.vectors)
    if args.ci_workflow is not None:
        check_ci_workflow(args.ci_workflow)
    if args.formal_crypto_workflow is not None:
        check_formal_crypto_workflow(args.formal_crypto_workflow)
    if args.release_workflow is not None:
        check_release_workflow(args.release_workflow)
    if args.ruleset_export is not None:
        check_ruleset_export(args.ruleset_export)


if __name__ == "__main__":
    main()
