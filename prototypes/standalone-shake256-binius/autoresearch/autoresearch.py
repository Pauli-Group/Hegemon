#!/usr/bin/env python3
"""Disk-bounded, security-gated local proof-size autoresearch controller.

This program is an experiment evaluator, not a proof-system security proof and
not a consensus activation tool.  It keeps weak-profile geometry experiments
separate from strict-PQ128 candidates and never gives security a numeric weight
that proof-size savings can offset.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator, NoReturn, Sequence
import uuid


CAMPAIGN_SCHEMA = "hegemon.proof-autoresearch.campaign.v1"
CANDIDATE_SCHEMA = "hegemon.proof-autoresearch.candidate.v1"
TRIAL_SCHEMA = "hegemon.proof-autoresearch.trial.v1"
MARKER_SCHEMA = "hegemon.proof-autoresearch.run-marker.v1"
BACKEND_SCHEMA = "hegemon.standalone-shake256.backend-measurement.v1"
REPORT_SCHEMA = "hegemon.standalone-shake256.benchmark-report.v1"
FULL_MEASUREMENT_SCHEMA = "hegemon.full-pay1x2-all-private-measurement.v1"
CANDIDATE_RESULT_SCHEMA = "hegemon.proof-autoresearch.candidate-result.v1"

NON_LOWERABLE_FREE_RESERVE_BYTES = 20 * 1024**3
RUN_PREFIX = "hegemon-proof-autoresearch.run."
MARKER_NAME = ".hegemon-proof-autoresearch-owner.json"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SUPPORTED_RESULT_SCHEMAS = {
    BACKEND_SCHEMA,
    REPORT_SCHEMA,
    FULL_MEASUREMENT_SCHEMA,
    CANDIDATE_RESULT_SCHEMA,
}

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
DEFAULT_CAMPAIGN = HERE / "campaign.json"
DEFAULT_STATE_DIR = HERE / "ledger"
CANONICAL_CAMPAIGN_SHA256 = "67ef95373ba5905726d8f2cf374c91c7c17743925cf3f5c1c7790fe4931d1437"

EXPECTED_RUNNER = [
    "sh",
    "{repo}/prototypes/standalone-shake256-binius/autoresearch/run-upstream-candidate.sh",
    "{binius_source}",
    "{candidate_patch}",
]
EXPECTED_AUTHORITY = [
    "python3",
    "{repo}/.agent/hardening/binius-pq128-proof-size/strict_pq_profile.py",
    "--check",
    "--require-release",
]


class ResearchError(ValueError):
    """A candidate, environment, or result violated the campaign contract."""


def _fail(message: str) -> NoReturn:
    raise ResearchError(message)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON constant {value!r}")


def _decoder() -> json.JSONDecoder:
    return json.JSONDecoder(
        object_pairs_hook=_no_duplicate_object,
        parse_constant=_reject_constant,
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, *, cap: int = 1024 * 1024) -> Any:
    try:
        info = path.lstat()
    except OSError as error:
        _fail(f"cannot stat JSON file {path}: {error}")
    if not stat.S_ISREG(info.st_mode):
        _fail(f"JSON path is not a regular file: {path}")
    if info.st_size > cap:
        _fail(f"JSON file exceeds {cap} bytes: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
        return _decoder().decode(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"cannot parse exact JSON {path}: {error}")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{name} must be a JSON object")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{name} must be a non-empty string")
    return value


def _integer(value: Any, name: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        _fail(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        _fail(f"{name} must be at least {minimum}")
    return value


def _number(value: Any, name: str, *, minimum: float = 0.0) -> float:
    if type(value) not in (int, float):
        _fail(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        _fail(f"{name} must be finite and at least {minimum}")
    return result


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        _fail(f"{name} must be a boolean")
    return value


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_repo_path(raw: str, name: str) -> Path:
    value = Path(_string(raw, name))
    path = (REPO_ROOT / value).resolve() if not value.is_absolute() else value.resolve()
    if not _within(path, REPO_ROOT):
        _fail(f"{name} escapes the repository: {raw}")
    return path


def load_campaign(path: Path, *, require_canonical: bool = False) -> dict[str, Any]:
    path = path.resolve()
    if require_canonical:
        if path != DEFAULT_CAMPAIGN.resolve():
            _fail("the executable controller accepts only the sealed canonical campaign")
        if _sha256_file(path) != CANONICAL_CAMPAIGN_SHA256:
            _fail("canonical campaign digest does not match the sealed controller value")
    campaign = _object(_read_json(path), "campaign")
    if campaign.get("schema") != CAMPAIGN_SCHEMA:
        _fail(f"campaign.schema must equal {CAMPAIGN_SCHEMA!r}")
    campaign_id = _string(campaign.get("campaign_id"), "campaign_id")
    if not IDENTIFIER.fullmatch(campaign_id):
        _fail("campaign_id has an invalid character or length")

    relation = _object(campaign.get("relation"), "relation")
    fixed_relation = {
        "full_relation_required": True,
        "geometry_proxy_forbidden": True,
        "standalone_proof_required": True,
        "aggregation_forbidden": True,
        "sidecar_authority_forbidden": True,
        "expected_public_statement_bytes": 478,
        "minimum_shake256_permutations": 40,
        "proof_hard_cap_bytes": 1_048_576,
    }
    for key, required_value in fixed_relation.items():
        if relation.get(key) != required_value:
            _fail(f"sealed relation field {key} has drifted")
    _integer(relation.get("proof_target_bytes"), "relation.proof_target_bytes", minimum=1)
    _integer(relation.get("proof_hard_cap_bytes"), "relation.proof_hard_cap_bytes", minimum=1)
    if relation["proof_target_bytes"] > relation["proof_hard_cap_bytes"]:
        _fail("proof target cannot exceed the hard cap")

    resources = _object(campaign.get("resources"), "resources")
    admission = _integer(
        resources.get("heavy_run_admission_free_bytes"),
        "resources.heavy_run_admission_free_bytes",
        minimum=NON_LOWERABLE_FREE_RESERVE_BYTES,
    )
    abort = _integer(
        resources.get("hard_abort_free_bytes"),
        "resources.hard_abort_free_bytes",
        minimum=NON_LOWERABLE_FREE_RESERVE_BYTES,
    )
    if admission < abort:
        _fail("heavy-run admission must be at least the hard-abort reserve")
    for key in (
        "max_run_root_bytes",
        "max_cargo_target_bytes",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_result_json_bytes",
        "max_wall_seconds",
        "poll_milliseconds",
        "disk_size_poll_milliseconds",
        "cargo_build_jobs",
        "reported_peak_rss_hard_cap_bytes",
        "stale_run_hours",
    ):
        _integer(resources.get(key), f"resources.{key}", minimum=1)
    if resources["max_cargo_target_bytes"] > resources["max_run_root_bytes"]:
        _fail("Cargo target cap cannot exceed the complete run-root cap")

    paths = _object(campaign.get("paths"), "paths")
    _string(paths.get("binius_source"), "paths.binius_source")
    temporary_parent = Path(_string(paths.get("temporary_parent"), "paths.temporary_parent"))
    if not temporary_parent.is_absolute() or not temporary_parent.is_dir():
        _fail("paths.temporary_parent must be an existing absolute directory")
    candidate_inbox = Path(_string(paths.get("candidate_inbox"), "paths.candidate_inbox"))
    if not candidate_inbox.is_absolute():
        _fail("paths.candidate_inbox must be absolute")

    runner = _object(campaign.get("runner"), "runner")
    argv = runner.get("argv")
    if not isinstance(argv, list) or not argv:
        _fail("runner.argv must be a non-empty JSON array")
    for index, item in enumerate(argv):
        _string(item, f"runner.argv[{index}]")
    if argv != EXPECTED_RUNNER:
        _fail("runner.argv has drifted from the sealed evaluator")

    security = _object(campaign.get("security"), "security")
    if security.get("authority_check") != EXPECTED_AUTHORITY:
        _fail("security authority command has drifted from the sealed evaluator")
    sealed_security = {
        "post_quantum_bits_min": 128,
        "semantic_hash": "SHAKE256-448",
        "proof_hash": "SHAKE256-512",
        "challenge_field": "GF(2^384)",
        "fri_classical_bits_min": 264,
        "qrom_accounting_complete_required": True,
        "zero_knowledge_required": True,
        "release_qualification_required": True,
        "independent_composed_verifier_required": True,
        "independent_composed_verifier_available": False,
    }
    for key, required_value in sealed_security.items():
        if security.get(key) != required_value:
            _fail(f"sealed security field {key} has drifted")
    if _integer(
        campaign.get("strict_reproductions_required"),
        "strict_reproductions_required",
        minimum=2,
    ) != 2:
        _fail("strict completion requires exactly two clean reproductions")

    sandbox = _object(campaign.get("sandbox"), "sandbox")
    if sandbox.get("required") is not True:
        _fail("the candidate OS sandbox may not be disabled")
    if sandbox.get("network_denied") is not True:
        _fail("the candidate sandbox must deny network access")
    if sandbox.get("run_root_only_writable") is not True:
        _fail("the candidate sandbox must restrict writes to the run root")
    for key in (
        "source_read_only_during_candidate_execution",
        "external_signals_denied",
        "process_group_escape_denied",
        "candidate_compile_host_reads_denied",
        "candidate_runtime_host_reads_denied",
        "candidate_runtime_no_fork_exec_job",
    ):
        if sandbox.get(key) is not True:
            _fail(f"sealed sandbox field {key} may not be disabled")
    if Path(_string(sandbox.get("executable"), "sandbox.executable")) != Path(
        "/usr/bin/sandbox-exec"
    ):
        _fail("the sealed sandbox executable must be /usr/bin/sandbox-exec")
    profile = _resolve_repo_path(
        _string(sandbox.get("profile"), "sandbox.profile"), "sandbox.profile"
    )
    if not profile.is_file() or profile.is_symlink():
        _fail("sandbox profile must be an immutable regular repository file")
    sandbox["_profile_path"] = profile

    patch_policy = _object(campaign.get("patch_policy"), "patch_policy")
    _integer(patch_policy.get("max_patch_bytes"), "patch_policy.max_patch_bytes", minimum=1)
    prefixes = patch_policy.get("allowed_prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        _fail("patch_policy.allowed_prefixes must be a non-empty array")
    for index, prefix in enumerate(prefixes):
        value = _string(prefix, f"patch_policy.allowed_prefixes[{index}]")
        if value.startswith("/") or ".." in Path(value).parts:
            _fail("patch allowed prefixes must be safe relative paths")

    required = campaign.get("verification_required_true")
    if not isinstance(required, list) or not required:
        _fail("verification_required_true must be a non-empty array")
    for index, item in enumerate(required):
        _string(item, f"verification_required_true[{index}]")

    immutable = campaign.get("immutable_artifacts")
    if not isinstance(immutable, list) or not immutable:
        _fail("immutable_artifacts must be a non-empty campaign-owned array")
    immutable_paths: list[Path] = []
    for index, raw in enumerate(immutable):
        artifact = _resolve_repo_path(raw, f"immutable_artifacts[{index}]")
        try:
            mode = artifact.lstat().st_mode
        except OSError as error:
            _fail(f"cannot stat immutable artifact {artifact}: {error}")
        if not stat.S_ISREG(mode):
            _fail(f"immutable artifact is not a regular file: {artifact}")
        immutable_paths.append(artifact)
    campaign["_immutable_paths"] = immutable_paths
    campaign["_path"] = path
    campaign["_sha256"] = _sha256_file(path)

    return campaign


def _candidate_location_allowed(path: Path, campaign: dict[str, Any]) -> bool:
    inbox = Path(campaign["paths"]["candidate_inbox"]).resolve()
    return _within(path, (HERE / "candidates").resolve()) or _within(path, inbox)


def _resolve_candidate_patch(raw: str, candidate_path: Path, campaign: dict[str, Any]) -> Path:
    value = Path(_string(raw, "candidate.candidate_patch"))
    if value.is_absolute():
        patch = value.resolve()
    elif _within(candidate_path, REPO_ROOT):
        patch = (REPO_ROOT / value).resolve()
    else:
        patch = (candidate_path.parent / value).resolve()
    inbox = Path(campaign["paths"]["candidate_inbox"]).resolve()
    if not (_within(patch, REPO_ROOT) or _within(patch, inbox)):
        _fail("candidate patch escapes both the repository and the isolated inbox")
    return patch


def load_candidate(path: Path, campaign: dict[str, Any]) -> dict[str, Any]:
    path = path.resolve()
    if not _candidate_location_allowed(path, campaign):
        _fail("candidate manifest must be in the sealed repository directory or candidate inbox")
    candidate = _object(_read_json(path), "candidate")
    if candidate.get("schema") != CANDIDATE_SCHEMA:
        _fail(f"candidate.schema must equal {CANDIDATE_SCHEMA!r}")
    identifier = _string(candidate.get("id"), "candidate.id")
    if not IDENTIFIER.fullmatch(identifier):
        _fail("candidate.id has an invalid character or length")
    parent = candidate.get("parent_id")
    if parent is not None and (not isinstance(parent, str) or not IDENTIFIER.fullmatch(parent)):
        _fail("candidate.parent_id must be null or a valid identifier")
    _string(candidate.get("hypothesis"), "candidate.hypothesis")

    claims = _object(candidate.get("relation_claims"), "candidate.relation_claims")
    expected = {
        "full_v5_delta_pay1x2": True,
        "geometry_proxy": False,
        "standalone_proof": True,
        "aggregation": False,
        "sidecar_authority": False,
    }
    for key, required in expected.items():
        actual = _boolean(claims.get(key), f"candidate.relation_claims.{key}")
        if actual is not required:
            _fail(f"candidate relation claim {key} violates the fixed architecture")

    if "artifacts" in candidate:
        _fail("immutable artifacts are campaign-owned and may not be candidate-selected")
    candidate["_artifact_paths"] = list(campaign["_immutable_paths"])
    candidate["_path"] = path
    candidate["_campaign_sha256"] = campaign["_sha256"]

    patch_raw = candidate.get("candidate_patch")
    if patch_raw is None:
        candidate["_patch_path"] = None
    else:
        patch = _resolve_candidate_patch(patch_raw, path, campaign)
        validate_patch(patch, campaign)
        candidate["_patch_path"] = patch
    return candidate


def validate_patch(path: Path, campaign: dict[str, Any]) -> None:
    policy = _object(campaign["patch_policy"], "patch_policy")
    try:
        info = path.lstat()
    except OSError as error:
        _fail(f"cannot stat candidate patch {path}: {error}")
    if not stat.S_ISREG(info.st_mode):
        _fail("candidate patch must be a regular file")
    if info.st_size <= 0 or info.st_size > policy["max_patch_bytes"]:
        _fail("candidate patch is empty or exceeds the configured cap")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        _fail(f"candidate patch is not exact UTF-8 text: {error}")
    if "GIT binary patch" in text or "Binary files " in text:
        _fail("binary candidate patches are forbidden")
    if "deleted file mode" in text or "+++ /dev/null" in text:
        _fail("candidate patch deletions are forbidden")
    if "new file mode" in text or "--- /dev/null" in text:
        _fail("candidate patch additions are forbidden")
    if "rename from " in text or "rename to " in text or "copy from " in text:
        _fail("candidate patch renames and copies are forbidden")
    if re.search(r"^(?:old mode|new mode|new file mode) ", text, flags=re.MULTILINE):
        _fail("candidate patch mode changes are forbidden")

    allowed = tuple(policy["allowed_prefixes"])
    diff_lines = re.findall(r"^diff --git .*?$", text, flags=re.MULTILINE)
    records = list(
        re.finditer(
            r"^diff --git a/(\S+) b/(\S+)\n(.*?)(?=^diff --git |\Z)",
            text,
            flags=re.MULTILINE | re.DOTALL,
        )
    )
    if not records:
        _fail("candidate patch has no git diff records")
    if len(records) != len(diff_lines):
        _fail("candidate patch contains an unparseable or quoted diff path")
    binius_source = Path(campaign["paths"]["binius_source"]).resolve()
    forbidden_added_code = re.compile(
        r"(?:std::process|Command::|std::fs|OpenOptions|File::create|"
        r"TcpStream|UdpSocket|setsid|\bfork\s*\(|libc::)"
    )
    for record in records:
        left, right, body = record.group(1), record.group(2), record.group(3)
        if left != right:
            _fail("candidate patch may not rename paths")
        parts = Path(left).parts
        if (
            not parts
            or Path(left).is_absolute()
            or ".." in parts
            or "." in parts
            or "\\" in left
        ):
            _fail(f"candidate patch path is not canonical: {left}")
        if not left.startswith(allowed):
            _fail(f"candidate patch path is outside the allowlist: {left}")
        if "tests" in parts or left.endswith("_test.rs") or left.endswith("tests.rs"):
            _fail(f"candidate patch may not modify tests: {left}")
        if "/src/" not in f"/{left}" or not left.endswith(".rs"):
            _fail(f"candidate patch may modify only existing Rust source files: {left}")
        source_path = (binius_source / left).resolve()
        if not _within(source_path, binius_source):
            _fail(f"candidate patch source path escapes the pinned tree: {left}")
        try:
            source_mode = source_path.lstat().st_mode
        except OSError as error:
            _fail(f"candidate patch source does not exist: {left}: {error}")
        if not stat.S_ISREG(source_mode) or source_path.is_symlink():
            _fail(f"candidate patch source is not an existing regular file: {left}")

        minus_headers = re.findall(r"^--- (\S+)$", body, flags=re.MULTILINE)
        plus_headers = re.findall(r"^\+\+\+ (\S+)$", body, flags=re.MULTILINE)
        if minus_headers != [f"a/{left}"] or plus_headers != [f"b/{right}"]:
            _fail(f"candidate patch file headers do not match diff path: {left}")
        added_lines = [
            line[1:]
            for line in body.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        if any(forbidden_added_code.search(line) for line in added_lines):
            _fail(f"candidate patch introduces forbidden process, file, or network code: {left}")


def candidate_provenance(candidate: dict[str, Any]) -> dict[str, Any]:
    canonical = {
        key: value
        for key, value in candidate.items()
        if not key.startswith("_")
    }
    artifacts = {
        str(path.relative_to(REPO_ROOT)): _sha256_file(path)
        for path in candidate["_artifact_paths"]
    }
    patch = candidate["_patch_path"]
    return {
        "campaign_sha256": candidate["_campaign_sha256"],
        "candidate_sha256": _sha256_bytes(_canonical_bytes(canonical)),
        "candidate_file_sha256": _sha256_file(candidate["_path"]),
        "artifacts_sha256": artifacts,
        "candidate_patch_sha256": _sha256_file(patch) if patch is not None else None,
    }


def _nested(root: dict[str, Any], dotted: str) -> Any:
    current: Any = root
    for component in dotted.split("."):
        if not isinstance(current, dict) or component not in current:
            return None
        current = current[component]
    return current


def _extract_result_objects(raw: str) -> list[dict[str, Any]]:
    decoder = _decoder()
    objects: list[dict[str, Any]] = []
    cursor = 0
    while True:
        start = raw.find("{", cursor)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(raw, start)
        except (json.JSONDecodeError, ResearchError):
            cursor = start + 1
            continue
        cursor = max(end, start + 1)
        if isinstance(value, dict) and value.get("schema") in SUPPORTED_RESULT_SCHEMAS:
            objects.append(value)
    return objects


def _verification_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    verification = payload.get("verification")
    return _object(verification, "measurement.verification")


def normalize_measurement(payload: dict[str, Any]) -> dict[str, Any]:
    schema = payload.get("schema")
    proof_artifact_relpath: str | None = None
    authority_report = None
    if schema == CANDIDATE_RESULT_SCHEMA:
        benchmark = _object(payload.get("benchmark"), "candidate result benchmark")
        if benchmark.get("schema") not in {BACKEND_SCHEMA, REPORT_SCHEMA}:
            _fail("candidate result benchmark has an unsupported schema")
        proof_artifact_relpath = _string(
            payload.get("proof_artifact_relpath"), "proof_artifact_relpath"
        )
        authority_report = payload.get("strict_authority")
        payload = benchmark
        schema = payload.get("schema")

    if schema == FULL_MEASUREMENT_SCHEMA:
        selected = _object(payload.get("selected"), "measurement.selected")
        relation = _object(payload.get("relation"), "measurement.relation")
        constraints = _object(payload.get("constraint_system"), "measurement.constraint_system")
        rss = _object(payload.get("rate3_rss_harness_repeat"), "measurement.rss")
        if relation.get("full_v5_delta_circuit") is not True:
            _fail("full measurement is not the exact full V5/Delta relation")
        if relation.get("geometry_proxy") is not False:
            _fail("full measurement is a geometry proxy")
        if relation.get("exact_composed_envelope_verifier") is not True:
            _fail("full measurement lacks the exact composed envelope verifier")
        if relation.get("prospective_kernel_route") != "V5/Delta family=1 action=7":
            _fail("full measurement route drifted")
        if constraints.get("private_witness_bytes") != 2_448:
            _fail("full measurement private witness size drifted")
        selected_rate = None
        for row in payload.get("rate_sweep", []):
            if isinstance(row, dict) and row.get("log_inverse_rate") == selected.get("log_inverse_rate"):
                selected_rate = row
                break
        if selected_rate is None:
            _fail("full measurement does not contain its selected rate")
        if selected_rate.get("proof_bytes") != selected.get("proof_bytes"):
            _fail("selected proof bytes do not match the selected rate row")
        if selected_rate.get("envelope_bytes") != selected.get("envelope_bytes"):
            _fail("selected envelope bytes do not match the selected rate row")
        if selected_rate.get("all_gates_passed") is not True:
            _fail("selected full-measurement rate did not pass every gate")
        normalized = {
            "source_schema": schema,
            "proof_bytes": _integer(selected.get("proof_bytes"), "selected.proof_bytes", minimum=1),
            "envelope_bytes": _integer(selected.get("envelope_bytes"), "selected.envelope_bytes", minimum=1),
            "prove_ms": _number(selected_rate.get("prove_ms"), "selected.prove_ms"),
            "verify_ms": _number(selected_rate.get("verify_ms"), "selected.verify_ms"),
            "peak_rss_bytes": _integer(rss.get("peak_rss_bytes"), "rss.peak_rss_bytes", minimum=1),
            "shake256_permutations": _integer(relation.get("shake256_permutations"), "relation.shake256_permutations", minimum=1),
            "public_statement_bytes": _integer(relation.get("canonical_statement_bytes"), "relation.canonical_statement_bytes", minimum=1),
            "compiled_constraints": _integer(constraints.get("compiled_constraints"), "constraint_system.compiled_constraints", minimum=1),
            "padded_constraints": _integer(constraints.get("padded_constraints"), "constraint_system.padded_constraints", minimum=1),
            "verification": _verification_from_payload(payload),
            "security_profile": _object(payload.get("security_profile"), "security_profile"),
            "reported_policy_mode": "prototype_only",
            "proof_artifact_relpath": proof_artifact_relpath,
            "strict_authority": authority_report,
        }
    elif schema == REPORT_SCHEMA:
        measurement = _object(payload.get("measurement"), "measurement")
        policy = _object(payload.get("policy"), "policy")
        normalized = {
            "source_schema": schema,
            "proof_bytes": _integer(measurement.get("canonical_proof_bytes"), "measurement.canonical_proof_bytes", minimum=1),
            "envelope_bytes": _integer(measurement.get("envelope_bytes"), "measurement.envelope_bytes", minimum=1),
            "prove_ms": _number(measurement.get("prove_ms"), "measurement.prove_ms"),
            "verify_ms": _number(measurement.get("verify_ms"), "measurement.verify_ms"),
            "peak_rss_bytes": (
                None
                if measurement.get("peak_rss_bytes") is None
                else _integer(measurement.get("peak_rss_bytes"), "measurement.peak_rss_bytes", minimum=1)
            ),
            "shake256_permutations": _integer(measurement.get("shake256_permutations"), "measurement.shake256_permutations", minimum=1),
            "public_statement_bytes": None,
            "compiled_constraints": None,
            "padded_constraints": None,
            "verification": _verification_from_payload(payload),
            "security_profile": _object(payload.get("security_profile"), "security_profile"),
            "reported_policy_mode": _string(policy.get("mode"), "policy.mode"),
            "proof_artifact_relpath": proof_artifact_relpath,
            "strict_authority": authority_report,
        }
    elif schema == BACKEND_SCHEMA:
        selected_row = None
        rate_sweep = payload.get("rate_sweep")
        if isinstance(rate_sweep, list):
            candidates = [
                row
                for row in rate_sweep
                if isinstance(row, dict)
                and row.get("canonical_proof_bytes") == payload.get("canonical_proof_bytes")
            ]
            if candidates:
                selected_row = min(
                    candidates,
                    key=lambda row: (
                        row.get("verify_ms", math.inf),
                        row.get("prove_ms", math.inf),
                    ),
                )
        normalized = {
            "source_schema": schema,
            "proof_bytes": _integer(payload.get("canonical_proof_bytes"), "canonical_proof_bytes", minimum=1),
            "envelope_bytes": _integer(payload.get("envelope_bytes"), "envelope_bytes", minimum=1),
            "prove_ms": _number(
                payload.get("prove_ms")
                if payload.get("prove_ms") is not None
                else None if selected_row is None else selected_row.get("prove_ms"),
                "prove_ms",
            ),
            "verify_ms": _number(
                payload.get("verify_ms")
                if payload.get("verify_ms") is not None
                else None if selected_row is None else selected_row.get("verify_ms"),
                "verify_ms",
            ),
            "peak_rss_bytes": (
                None
                if payload.get("peak_rss_bytes") is None
                else _integer(payload.get("peak_rss_bytes"), "peak_rss_bytes", minimum=1)
            ),
            "shake256_permutations": _integer(payload.get("shake256_permutations"), "shake256_permutations", minimum=1),
            "public_statement_bytes": _nested(payload, "constraint_system.public_statement_bytes"),
            "compiled_constraints": _nested(payload, "constraint_system.compiled_constraints"),
            "padded_constraints": _nested(payload, "constraint_system.padded_constraints"),
            "verification": _verification_from_payload(payload),
            "security_profile": _object(payload.get("security_profile"), "security_profile"),
            "reported_policy_mode": "backend_raw",
            "proof_artifact_relpath": proof_artifact_relpath,
            "strict_authority": authority_report,
        }
    else:
        _fail(f"unsupported measurement schema {schema!r}")
    if normalized["envelope_bytes"] != normalized["proof_bytes"] + 12:
        _fail("canonical HGSP envelope must be exactly proof bytes plus 12")
    return normalized


def _normalize_live_payload(
    payload: dict[str, Any], run_dir: Path, campaign: dict[str, Any]
) -> dict[str, Any]:
    """Cross-check the RSS wrapper with the immutable backend sweep output."""

    wrapped = normalize_measurement(payload)
    sweep_path = run_dir / "outputs" / "full-pay1x2-candidate-sweep.json"
    sweep_payload = _object(
        _read_json(sweep_path, cap=1024 * 1024), "candidate backend sweep"
    )
    if sweep_payload.get("schema") != BACKEND_SCHEMA:
        _fail("candidate sweep has the wrong backend schema")
    sweep = normalize_measurement(sweep_payload)
    for key in ("proof_bytes", "envelope_bytes", "shake256_permutations"):
        if wrapped.get(key) != sweep.get(key):
            _fail(f"measurement wrapper disagrees with backend sweep for {key}")
    for key in ("public_statement_bytes", "compiled_constraints", "padded_constraints"):
        wrapped[key] = sweep.get(key)
    if wrapped["public_statement_bytes"] is None:
        _fail("live backend sweep omitted the exact public statement length")
    for required_path in campaign["verification_required_true"]:
        if _nested(wrapped["verification"], required_path) is not True:
            _fail(f"measurement wrapper failed required fact {required_path}")
        if _nested(sweep["verification"], required_path) is not True:
            _fail(f"backend sweep failed required fact {required_path}")
    return wrapped


def _strict_security_fields_pass(security: dict[str, Any], campaign: dict[str, Any]) -> bool:
    required = campaign["security"]
    zero_knowledge = security.get("zero_knowledge")
    if zero_knowledge is None:
        zero_knowledge = security.get("zero_knowledge_established")
    return bool(
        security.get("status") == "supported"
        and security.get("release_qualified") is True
        and security.get("semantic_hash") == required["semantic_hash"]
        and security.get("proof_hash") == required["proof_hash"]
        and security.get("challenge_field") == required["challenge_field"]
        and type(security.get("fri_classical_bits")) is int
        and security["fri_classical_bits"] >= required["fri_classical_bits_min"]
        and security.get("qrom_accounting_complete") is True
        and type(security.get("composed_pq_bits")) in (int, float)
        and math.isfinite(float(security["composed_pq_bits"]))
        and float(security["composed_pq_bits"]) >= required["post_quantum_bits_min"]
        and zero_knowledge is True
    )


def evaluate_measurement(
    normalized: dict[str, Any],
    candidate: dict[str, Any],
    campaign: dict[str, Any],
    *,
    authority_passed: bool = False,
) -> dict[str, Any]:
    failures: list[str] = []
    relation = campaign["relation"]
    if normalized["proof_bytes"] > relation["proof_hard_cap_bytes"]:
        failures.append("proof exceeds the 1 MiB hard cap")
    if normalized["envelope_bytes"] > relation["proof_hard_cap_bytes"]:
        failures.append("envelope exceeds the 1 MiB hard cap")
    if normalized["shake256_permutations"] < relation["minimum_shake256_permutations"]:
        failures.append("SHAKE workload is below the fixed full-relation minimum")
    statement_bytes = normalized.get("public_statement_bytes")
    if statement_bytes != relation["expected_public_statement_bytes"]:
        failures.append("public statement length drifted from 478 bytes")

    verification = normalized["verification"]
    for path in campaign["verification_required_true"]:
        if _nested(verification, path) is not True:
            failures.append(f"required verification fact is not true: {path}")

    peak = normalized.get("peak_rss_bytes")
    if peak is not None and peak > campaign["resources"]["reported_peak_rss_hard_cap_bytes"]:
        failures.append("reported peak RSS exceeds the campaign cap")

    strict_fields = _strict_security_fields_pass(normalized["security_profile"], campaign)
    strict = strict_fields and authority_passed
    lane = "strict" if strict else "prototype"
    if strict_fields and not authority_passed:
        failures.append("strict security fields lack an independent passing authority check")

    eligible = not failures
    capacity = (64 * 1024 * 1024 - 2525) // (4967 + normalized["envelope_bytes"])
    return {
        "eligible": eligible,
        "classification": (
            "STRICT_FRONTIER_CANDIDATE"
            if eligible and lane == "strict"
            else "PROXY_FRONTIER_CANDIDATE"
            if eligible
            else "REJECTED"
        ),
        "security_lane": lane if eligible else None,
        "strict_security_fields_pass": strict_fields,
        "strict_authority_passed": authority_passed,
        "target_met": eligible and normalized["envelope_bytes"] <= relation["proof_target_bytes"],
        "actions_per_64mib_block": capacity,
        "failures": failures,
    }


def _ensure_state_dir(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        _fail("state directory may not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path.resolve()


@contextmanager
def _exclusive_lock(path: Path, label: str) -> Iterator[int]:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        _fail(f"cannot open {label} lock {path}: {error}")
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode):
            _fail(f"{label} lock is not an owned regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail(f"another {label} process already holds {path}")
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _validate_trial_entry(entry: dict[str, Any], campaign: dict[str, Any]) -> None:
    if entry.get("campaign_id") != campaign["campaign_id"]:
        _fail("ledger entry belongs to a different campaign")
    if entry.get("origin") not in {"seed", "live"}:
        _fail("ledger entry has an invalid origin")
    provenance = _object(entry.get("provenance"), "ledger provenance")
    if provenance.get("campaign_sha256") != campaign["_sha256"]:
        _fail("ledger entry campaign digest does not match the sealed campaign")
    measurement = _object(entry.get("measurement"), "ledger measurement")
    security_profile = _object(entry.get("security_profile"), "ledger security profile")
    verification = _object(entry.get("verification"), "ledger verification")
    if entry.get("verification_sha256") != _sha256_bytes(_canonical_bytes(verification)):
        _fail("ledger verification digest mismatch")
    normalized = dict(measurement)
    normalized["security_profile"] = security_profile
    normalized["verification"] = verification
    normalized["proof_artifact_relpath"] = None
    normalized["strict_authority"] = None
    if entry.get("evaluation", {}).get("strict_authority_passed") is True:
        _fail("sealed ledger cannot retain a strict authority pass before that authority exists")
    expected = evaluate_measurement(
        normalized,
        {},
        campaign,
        authority_passed=False,
    )
    if expected != entry.get("evaluation"):
        _fail("ledger evaluation is not derivable from retained evidence")


def _read_ledger(path: Path, campaign: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        _fail("ledger must be a regular non-symlink file")
    entries: list[dict[str, Any]] = []
    previous: str | None = None
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                _fail(f"ledger line {line_number} is not newline-terminated")
            try:
                entry = _decoder().decode(line)
            except (json.JSONDecodeError, ResearchError) as error:
                _fail(f"ledger line {line_number} is invalid: {error}")
            entry = _object(entry, f"ledger line {line_number}")
            if entry.get("schema") != TRIAL_SCHEMA:
                _fail(f"ledger line {line_number} has the wrong schema")
            if entry.get("previous_digest") != previous:
                _fail(f"ledger chain breaks at line {line_number}")
            claimed = _string(entry.get("entry_digest"), f"ledger line {line_number} digest")
            unhashed = dict(entry)
            del unhashed["entry_digest"]
            actual = _sha256_bytes(_canonical_bytes(unhashed))
            if claimed != actual:
                _fail(f"ledger digest mismatch at line {line_number}")
            if campaign is not None:
                _validate_trial_entry(entry, campaign)
            previous = claimed
            entries.append(entry)
    return entries


def _append_ledger(
    state_dir: Path, entry: dict[str, Any], campaign: dict[str, Any] | None = None
) -> dict[str, Any]:
    state = _ensure_state_dir(state_dir)
    ledger = state / "results.jsonl"
    with _exclusive_lock(state / "ledger.lock", "campaign-ledger"):
        entries = _read_ledger(ledger, campaign)
        record = dict(entry)
        record["schema"] = TRIAL_SCHEMA
        record["previous_digest"] = entries[-1]["entry_digest"] if entries else None
        if campaign is not None:
            preview = dict(record)
            preview["entry_digest"] = "pending"
            _validate_trial_entry(preview, campaign)
        record["entry_digest"] = _sha256_bytes(_canonical_bytes(record))
        encoded = _canonical_bytes(record) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(ledger, flags, 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        return record


def _trial_entry(
    campaign: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    normalized: dict[str, Any],
    evaluation: dict[str, Any],
    *,
    origin: str,
    environment: dict[str, Any],
) -> dict[str, Any]:
    return {
        "campaign_id": campaign["campaign_id"],
        "trial_id": f"{candidate['id']}-{origin}-{uuid.uuid4().hex[:12]}",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "origin": origin,
        "candidate_id": candidate["id"],
        "parent_id": candidate.get("parent_id"),
        "hypothesis": candidate["hypothesis"],
        "provenance": provenance,
        "measurement": {
            key: normalized.get(key)
            for key in (
                "source_schema",
                "proof_bytes",
                "envelope_bytes",
                "prove_ms",
                "verify_ms",
                "peak_rss_bytes",
                "shake256_permutations",
                "public_statement_bytes",
                "compiled_constraints",
                "padded_constraints",
                "reported_policy_mode",
            )
        },
        "security_profile": normalized["security_profile"],
        "verification": normalized["verification"],
        "verification_sha256": _sha256_bytes(_canonical_bytes(normalized["verification"])),
        "evaluation": evaluation,
        "environment": environment,
    }


def _free_bytes(campaign: dict[str, Any]) -> int:
    temp_parent = Path(campaign["paths"]["temporary_parent"])
    return min(shutil.disk_usage(REPO_ROOT).free, shutil.disk_usage(temp_parent).free)


def _directory_bytes(path: Path, *, missing_ok: bool = False) -> int:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        if missing_ok:
            return 0
        _fail(f"cannot measure missing temporary directory {path}")
    except OSError as error:
        _fail(f"cannot stat temporary directory {path}: {error}")
    if not stat.S_ISDIR(mode):
        _fail(f"temporary path is not a real directory: {path}")
    # Cargo atomically creates, renames, and removes thousands of files while a
    # build is active. macOS `du` reports status 1 if one of those entries
    # disappears mid-walk even though the root is intact. Retry that transient
    # race; never reinterpret a missing or replaced root as zero.
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["du", "-sk", str(path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
                timeout=2,
            )
        except subprocess.TimeoutExpired:
            result = None
        if result is not None and result.returncode == 0:
            try:
                kib = int(result.stdout.split()[0])
            except (IndexError, ValueError):
                _fail(f"du returned invalid output for {path}")
            return kib * 1024
        try:
            current_mode = path.lstat().st_mode
        except FileNotFoundError:
            if missing_ok:
                return 0
            _fail(f"temporary directory disappeared while measuring: {path}")
        if not stat.S_ISDIR(current_mode):
            _fail(f"temporary path changed type while measuring: {path}")
        if attempt < 2:
            time.sleep(0.1)
    _fail(f"cannot measure temporary directory after retries: {path}")


def _process_group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    pgid = process.pid
    if _process_group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while _process_group_alive(pgid) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)
        if _process_group_alive(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while _process_group_alive(pgid) and time.monotonic() < deadline:
                process.poll()
                time.sleep(0.05)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _process_group_rss_bytes(pgid: int) -> int:
    result = subprocess.run(
        ["ps", "-axo", "pgid=,rss="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=1,
    )
    if result.returncode != 0:
        _fail("cannot measure candidate process-group RSS")
    total_kib = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            if int(fields[0]) == pgid:
                total_kib += int(fields[1])
    return total_kib * 1024


def _process_start_token(pid: int) -> str | None:
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=1,
    )
    token = result.stdout.strip()
    return token if result.returncode == 0 and token else None


def _current_uid_process_count() -> int:
    result = subprocess.run(
        ["ps", "-axo", "uid="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=2,
    )
    if result.returncode != 0:
        _fail("cannot count current user processes for the child-process limit")
    uid = os.getuid()
    return sum(1 for line in result.stdout.splitlines() if line.strip() == str(uid))


def _child_nproc_limit() -> int:
    # RLIMIT_NPROC is per real UID on macOS, not per candidate process group.
    # A fixed limit of 128 can already be below a live Codex desktop's process
    # count and makes the first shell fork fail with EAGAIN. Keep meaningful
    # fork-bomb headroom while leaving the candidate runtime's no-fork Seatbelt
    # rule and the controller's RSS/time/disk supervision authoritative.
    current = _current_uid_process_count()
    desired = max(1024, current + 256)
    _soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    if hard != resource.RLIM_INFINITY:
        desired = min(desired, hard)
    if desired <= current:
        _fail("host process limit leaves no safe candidate headroom")
    return desired


def _child_limits(nproc_limit: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    one_gib = 1024**3
    resource.setrlimit(resource.RLIMIT_FSIZE, (one_gib, one_gib))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc_limit, nproc_limit))
    if hasattr(resource, "RLIMIT_CPU"):
        resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))


def _validate_owned_run_dir(path: Path, campaign: dict[str, Any]) -> dict[str, Any]:
    temp_parent = Path(campaign["paths"]["temporary_parent"]).resolve()
    if path.is_symlink() or not path.is_dir():
        _fail(f"run root is not a real directory: {path}")
    resolved = path.resolve()
    if resolved.parent != temp_parent or not resolved.name.startswith(RUN_PREFIX):
        _fail(f"run root is outside the exact owned namespace: {path}")
    marker_path = resolved / MARKER_NAME
    marker = _object(_read_json(marker_path, cap=64 * 1024), "run marker")
    if marker.get("schema") != MARKER_SCHEMA:
        _fail("run marker schema mismatch")
    if marker.get("campaign_id") != campaign["campaign_id"]:
        _fail("run marker campaign mismatch")
    if marker.get("uid") != os.getuid():
        _fail("run marker uid mismatch")
    run_id = _string(marker.get("run_id"), "marker.run_id")
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        _fail("run marker UUID is malformed")
    if not resolved.name.startswith(f"{RUN_PREFIX}{run_id}."):
        _fail("run marker identity mismatch")
    return marker


def _remove_owned_run_dir(path: Path, campaign: dict[str, Any]) -> None:
    _validate_owned_run_dir(path, campaign)
    # The trusted preparation phase removes write bits from candidate sources.
    # Restore owner permissions only inside this exact validated UUID root so
    # cleanup cannot be blocked by read-only source directories.
    for current, directories, files in os.walk(path, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            child = current_path / name
            if not child.is_symlink():
                child.chmod(0o600)
        for name in directories:
            child = current_path / name
            if not child.is_symlink():
                child.chmod(0o700)
        current_path.chmod(0o700)
    shutil.rmtree(path)


def _create_run_dir(campaign: dict[str, Any], candidate_id: str) -> Path:
    temp_parent = Path(campaign["paths"]["temporary_parent"]).resolve()
    run_id = uuid.uuid4().hex
    path = Path(tempfile.mkdtemp(prefix=f"{RUN_PREFIX}{run_id}.", dir=temp_parent))
    path.chmod(0o700)
    marker = {
        "schema": MARKER_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "candidate_id": candidate_id,
        "run_id": run_id,
        "uid": os.getuid(),
        "pid": os.getpid(),
        "pid_start_token": _process_start_token(os.getpid()),
        "worker_pgid": None,
        "created_unix": time.time(),
    }
    marker_path = path / MARKER_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(marker_path, flags, 0o600)
    try:
        os.write(fd, _canonical_bytes(marker) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    for name in ("target", "tmp", "logs", "outputs", "home", "cargo-home"):
        (path / name).mkdir(mode=0o700)
    return path


def _update_worker_pgid(run_dir: Path, campaign: dict[str, Any], pgid: int) -> None:
    marker = _validate_owned_run_dir(run_dir, campaign)
    marker["worker_pgid"] = pgid
    marker_path = run_dir / MARKER_NAME
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(marker_path, flags)
    try:
        os.write(fd, _canonical_bytes(marker) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def _prepare_cargo_home(run_dir: Path) -> Path:
    source = Path.home() / ".cargo"
    destination = run_dir / "cargo-home"
    for name in ("registry", "git"):
        target = source / name
        link = destination / name
        if target.exists() and not link.exists():
            os.symlink(target, link, target_is_directory=True)
    for name in (".global-cache", ".package-cache", ".package-cache-mutate"):
        source_file = source / name
        destination_file = destination / name
        if source_file.is_file() and not destination_file.exists():
            shutil.copy2(source_file, destination_file)
        elif not destination_file.exists():
            destination_file.touch(mode=0o600)
    return destination


def _snapshot_candidate_patch(candidate: dict[str, Any], run_dir: Path) -> Path | None:
    source = candidate["_patch_path"]
    if source is None:
        return None
    expected = _sha256_file(source)
    inputs = run_dir / "inputs"
    inputs.mkdir(mode=0o700)
    destination = inputs / "candidate.patch"
    data = source.read_bytes()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o400)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail("short write while snapshotting candidate patch")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if _sha256_file(destination) != expected:
        _fail("candidate patch changed while it was snapshotted")
    return destination


def _expand_runner(
    campaign: dict[str, Any], candidate_patch: Path | None, run_dir: Path
) -> list[str]:
    values = {
        "repo": str(REPO_ROOT),
        "run_dir": str(run_dir),
        "target_dir": str(run_dir / "target"),
        "binius_source": campaign["paths"]["binius_source"],
        "candidate_patch": str(candidate_patch) if candidate_patch is not None else "-",
    }
    command: list[str] = []
    for raw in campaign["runner"]["argv"]:
        try:
            value = raw.format_map(values)
        except KeyError as error:
            _fail(f"unknown runner placeholder {error}")
        if "\x00" in value or "\n" in value:
            _fail("runner argument contains a forbidden control character")
        command.append(value)
    return command


def _run_supervised(
    campaign: dict[str, Any], candidate: dict[str, Any], run_dir: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    resources_cfg = campaign["resources"]
    if _free_bytes(campaign) < resources_cfg["heavy_run_admission_free_bytes"]:
        _fail("heavy run is below the non-lowerable 28 GiB admission floor")

    patch_snapshot = _snapshot_candidate_patch(candidate, run_dir)
    runner_command = _expand_runner(campaign, patch_snapshot, run_dir)
    # The hash-sealed runner is a trusted, non-candidate-controlled
    # orchestrator. It launches preparation and compilation as sibling Seatbelt
    # jobs, then runtime.sb wraps each exact candidate-linked binary. Wrapping
    # the orchestrator itself would stack sandbox.sb and compile.sb and causes
    # macOS Seatbelt to reject Cargo's first fork.
    command = runner_command
    stdout_path = run_dir / "logs" / "stdout.log"
    stderr_path = run_dir / "logs" / "stderr.log"
    cargo_home = _prepare_cargo_home(run_dir)
    environment = {
        "PATH": "/Users/pldd/.cargo/bin:/Library/Developer/CommandLineTools/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(run_dir / "home"),
        "USER": os.environ.get("USER", "pldd"),
        "LOGNAME": os.environ.get("LOGNAME", os.environ.get("USER", "pldd")),
        "LANG": "C",
        "LC_ALL": "C",
        "RUSTUP_HOME": str(Path.home() / ".rustup"),
        "CARGO_HOME": str(cargo_home),
        "HEGEMON_AUTORESEARCH_HOST_CARGO_BIN": str(Path.home() / ".cargo" / "bin"),
        "HEGEMON_AUTORESEARCH_HOST_CARGO_REGISTRY": str(
            Path.home() / ".cargo" / "registry"
        ),
        "HEGEMON_AUTORESEARCH_HOST_CARGO_GIT": str(Path.home() / ".cargo" / "git"),
        "HEGEMON_AUTORESEARCH_RUN_DIR": str(run_dir),
        "CARGO_TARGET_DIR": str(run_dir / "target"),
        "TMPDIR": str(run_dir / "tmp"),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_DEBUG": "0",
        "CARGO_PROFILE_TEST_DEBUG": "0",
        "CARGO_PROFILE_RELEASE_DEBUG": "0",
        "CARGO_BUILD_JOBS": str(resources_cfg["cargo_build_jobs"]),
        "RUSTFLAGS": "-Ctarget-cpu=native",
    }

    free_before = _free_bytes(campaign)
    start = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    interrupted: list[int] = []
    old_handlers: dict[int, Any] = {}

    def handle_signal(signum: int, _frame: Any) -> None:
        interrupted.append(signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        old_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, handle_signal)

    abort_reason: str | None = None
    last_size_check = 0.0
    max_run_bytes_seen = 0
    max_target_bytes_seen = 0
    max_group_rss_seen = 0
    child_nproc_limit = _child_nproc_limit()
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                command,
                cwd=run_dir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                preexec_fn=lambda: _child_limits(child_nproc_limit),
            )
            _update_worker_pgid(run_dir, campaign, process.pid)
            while process.poll() is None:
                now = time.monotonic()
                if interrupted:
                    abort_reason = f"received signal {interrupted[0]}"
                    break
                if now - start > resources_cfg["max_wall_seconds"]:
                    abort_reason = "candidate exceeded the wall-time cap"
                    break
                if _free_bytes(campaign) < resources_cfg["hard_abort_free_bytes"]:
                    abort_reason = "candidate crossed the non-lowerable 20 GiB reserve"
                    break
                if stdout_path.stat().st_size > resources_cfg["max_stdout_bytes"]:
                    abort_reason = "candidate stdout exceeded its cap"
                    break
                if stderr_path.stat().st_size > resources_cfg["max_stderr_bytes"]:
                    abort_reason = "candidate stderr exceeded its cap"
                    break
                group_rss = _process_group_rss_bytes(process.pid)
                max_group_rss_seen = max(max_group_rss_seen, group_rss)
                if group_rss > resources_cfg["reported_peak_rss_hard_cap_bytes"]:
                    abort_reason = "candidate process group exceeded the 8 GiB RSS cap"
                    break
                if now - last_size_check >= resources_cfg["disk_size_poll_milliseconds"] / 1000:
                    run_bytes = _directory_bytes(run_dir)
                    target_bytes = _directory_bytes(run_dir / "target", missing_ok=True)
                    max_run_bytes_seen = max(max_run_bytes_seen, run_bytes)
                    max_target_bytes_seen = max(max_target_bytes_seen, target_bytes)
                    if run_bytes > resources_cfg["max_run_root_bytes"]:
                        abort_reason = "candidate run root exceeded 5 GiB"
                        break
                    if target_bytes > resources_cfg["max_cargo_target_bytes"]:
                        abort_reason = "candidate Cargo target exceeded 4 GiB"
                        break
                    last_size_check = now
                time.sleep(resources_cfg["poll_milliseconds"] / 1000)

            if abort_reason is not None:
                _terminate_group(process)
                _fail(abort_reason)
            return_code = process.wait()
            stdout_bytes = stdout_path.stat().st_size
            stderr_bytes = stderr_path.stat().st_size
            if stdout_bytes > resources_cfg["max_stdout_bytes"]:
                _fail("candidate stdout exceeded its cap")
            if stderr_bytes > resources_cfg["max_stderr_bytes"]:
                _fail("candidate stderr exceeded its cap")
            run_bytes = _directory_bytes(run_dir)
            target_bytes = _directory_bytes(run_dir / "target")
            max_run_bytes_seen = max(max_run_bytes_seen, run_bytes)
            max_target_bytes_seen = max(max_target_bytes_seen, target_bytes)
            if run_bytes > resources_cfg["max_run_root_bytes"]:
                _fail("candidate run root exceeded 5 GiB")
            if target_bytes > resources_cfg["max_cargo_target_bytes"]:
                _fail("candidate Cargo target exceeded 4 GiB")
            if _free_bytes(campaign) < resources_cfg["hard_abort_free_bytes"]:
                _fail("candidate crossed the non-lowerable 20 GiB reserve")
            if return_code != 0:
                stderr.flush()
                tail = stderr_path.read_bytes()[-8192:].decode("utf-8", errors="replace")
                _fail(f"candidate runner exited with status {return_code}: {tail.strip()}")
    finally:
        if process is not None:
            _terminate_group(process)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)

    raw = stdout_path.read_text(encoding="utf-8", errors="strict")
    objects = _extract_result_objects(raw)
    if len(objects) != 1:
        _fail("candidate runner must emit exactly one supported result JSON")
    payload = objects[0]
    if len(_canonical_bytes(payload)) > resources_cfg["max_result_json_bytes"]:
        _fail("candidate result JSON exceeds 1 MiB")
    environment_report = {
        "command": command,
        "wall_ms": (time.monotonic() - start) * 1000,
        "free_bytes_before": free_before,
        "free_bytes_after_command": _free_bytes(campaign),
        "max_run_root_bytes_seen": max_run_bytes_seen,
        "max_target_bytes_seen": max_target_bytes_seen,
        "max_process_group_rss_bytes_seen": max_group_rss_seen,
        "child_nproc_limit": child_nproc_limit,
        "stdout_bytes": stdout_path.stat().st_size,
        "stderr_bytes": stderr_path.stat().st_size,
        "stdout_sha256": _sha256_file(stdout_path),
        "stderr_sha256": _sha256_file(stderr_path),
        "backend_sweep_sha256": _sha256_file(
            run_dir / "outputs" / "full-pay1x2-candidate-sweep.json"
        ),
    }
    return payload, environment_report


def _run_authority_if_needed(
    normalized: dict[str, Any], campaign: dict[str, Any], run_dir: Path
) -> bool:
    # The current arithmetic profile checker is not an independent HGSP parser
    # and composed action/statement verifier.  Strict admission remains
    # unreachable until that separate authority is implemented and sealed.
    if campaign["security"].get("independent_composed_verifier_available") is not True:
        return False
    if not _strict_security_fields_pass(normalized["security_profile"], campaign):
        return False
    relpath = normalized.get("proof_artifact_relpath")
    if not relpath:
        return False
    proof = (run_dir / relpath).resolve()
    if not _within(proof, run_dir.resolve()) or proof.is_symlink() or not proof.is_file():
        _fail("strict proof artifact is not an owned regular run file")
    if proof.stat().st_size != normalized["envelope_bytes"]:
        _fail("strict proof artifact bytes do not match the measured envelope")
    command = [
        item.format_map({"repo": str(REPO_ROOT)})
        for item in campaign["security"]["authority_check"]
    ] + ["--proof-file", str(proof)]
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        return False
    try:
        report = _decoder().decode(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ResearchError):
        return False
    return isinstance(report, dict) and report.get("release_authorized") is True


def _assert_provenance_unchanged(before: dict[str, Any], candidate: dict[str, Any]) -> None:
    after = candidate_provenance(candidate)
    if after != before:
        _fail("candidate or immutable evaluator artifacts changed during the run")


def _sandbox_smoke(campaign: dict[str, Any]) -> tuple[bool, str]:
    temporary_parent = Path(campaign["paths"]["temporary_parent"]).resolve()
    smoke = Path(tempfile.mkdtemp(prefix="hegemon-proof-autoresearch.sandbox-smoke.", dir=temporary_parent))
    escape = temporary_parent / f"hegemon-proof-autoresearch.escape.{uuid.uuid4().hex}"
    secret = temporary_parent / f"hegemon-proof-autoresearch.secret.{uuid.uuid4().hex}"
    marker = smoke / "marker"
    writable = smoke / "writable"
    readonly = smoke / "readonly"
    writable.mkdir(mode=0o700)
    readonly.mkdir(mode=0o700)
    marker.write_text("immutable\n", encoding="utf-8")
    secret.write_text("must-not-be-readable\n", encoding="utf-8")
    sentinel = subprocess.Popen(
        ["/bin/sleep", "30"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    smoke_nproc_limit = _child_nproc_limit()
    try:
        command = [
            campaign["sandbox"]["executable"],
            "-D",
            f"WRITE_A={writable}",
            "-D",
            f"WRITE_B={writable}",
            "-D",
            f"WRITE_C={writable}",
            "-D",
            f"WRITE_D={writable}",
            "-D",
            f"WRITE_E={writable}",
            "-D",
            f"WRITE_F={writable}",
            "-D",
            f"MARKER={marker}",
            "-f",
            str(campaign["sandbox"]["_profile_path"]),
            "/bin/sh",
            "-c",
            'printf ok > "$1/inside"; '
            'if printf source > "$2/source"; then exit 8; fi; '
            'if printf escape > "$3"; then exit 9; fi; '
            'if printf marker > "$4"; then exit 10; fi; '
            'if kill -TERM "$5"; then exit 11; fi; '
            "if /usr/bin/python3 -c 'import os; os.setpgid(0, 0)'; then exit 12; fi",
            "sandbox-smoke",
            str(writable),
            str(readonly),
            str(escape),
            str(marker),
            str(sentinel.pid),
        ]
        result = subprocess.run(
            command,
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        inside_path = writable / "inside"
        inside_ok = (
            inside_path.is_file()
            and inside_path.read_text(encoding="utf-8") == "ok"
        )
        source_blocked = not (readonly / "source").exists()
        marker_ok = marker.read_text(encoding="utf-8") == "immutable\n"
        escape_blocked = not escape.exists()
        signal_blocked = sentinel.poll() is None
        compile_policy_passed = (
            result.returncode == 0
            and inside_ok
            and source_blocked
            and marker_ok
            and escape_blocked
            and signal_blocked
        )
        compile_read_denied = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"RUN_DIR={smoke}",
                "-D",
                f"RUN_PARENT={temporary_parent}",
                "-D",
                f"USER_ROOT={Path.home()}",
                "-D",
                f"CARGO_PARENT={Path.home() / '.cargo'}",
                "-D",
                f"EVALUATOR_DIR={HERE}",
                "-D",
                f"MEASURE_SCRIPT={REPO_ROOT / 'scripts' / 'measure_standalone_shake256_prototype.py'}",
                "-D",
                f"CARGO_BIN={Path.home() / '.cargo' / 'bin'}",
                "-D",
                f"CARGO_REGISTRY={Path.home() / '.cargo' / 'registry'}",
                "-D",
                f"CARGO_GIT={Path.home() / '.cargo' / 'git'}",
                "-D",
                f"RUSTUP_ROOT={Path.home() / '.rustup'}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"OUTPUTS_DIR={writable}",
                "-D",
                f"HOME_DIR={writable}",
                "-D",
                f"CARGO_HOME={writable}",
                "-D",
                f"LOGS_DIR={writable}",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(HERE / "compile.sb"),
                "/usr/bin/perl",
                "-e",
                'open my $fh, "<", $ARGV[0] or exit 42; exit 43',
                str(secret),
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        compile_fork_ok = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"RUN_DIR={smoke}",
                "-D",
                f"RUN_PARENT={temporary_parent}",
                "-D",
                f"USER_ROOT={Path.home()}",
                "-D",
                f"CARGO_PARENT={Path.home() / '.cargo'}",
                "-D",
                f"EVALUATOR_DIR={HERE}",
                "-D",
                f"MEASURE_SCRIPT={REPO_ROOT / 'scripts' / 'measure_standalone_shake256_prototype.py'}",
                "-D",
                f"CARGO_BIN={Path.home() / '.cargo' / 'bin'}",
                "-D",
                f"CARGO_REGISTRY={Path.home() / '.cargo' / 'registry'}",
                "-D",
                f"CARGO_GIT={Path.home() / '.cargo' / 'git'}",
                "-D",
                f"RUSTUP_ROOT={Path.home() / '.rustup'}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"OUTPUTS_DIR={writable}",
                "-D",
                f"HOME_DIR={writable}",
                "-D",
                f"CARGO_HOME={writable}",
                "-D",
                f"LOGS_DIR={writable}",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(HERE / "compile.sb"),
                "/bin/sh",
                "-c",
                "/usr/bin/true; /usr/bin/true",
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            start_new_session=True,
            preexec_fn=lambda: _child_limits(smoke_nproc_limit),
        )
        runtime_profile = HERE / "runtime.sb"
        runtime_ok = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                "EXECUTABLE=/usr/bin/true",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(runtime_profile),
                "/usr/bin/true",
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            start_new_session=True,
            preexec_fn=lambda: _child_limits(smoke_nproc_limit),
        )
        runtime_exec_denied = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                "EXECUTABLE=/usr/bin/perl",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(runtime_profile),
                "/usr/bin/perl",
                "-e",
                'exec "/usr/bin/true"; exit 42',
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        runtime_read_denied = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                "EXECUTABLE=/usr/bin/perl",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(runtime_profile),
                "/usr/bin/perl",
                "-e",
                'open my $fh, "<", $ARGV[0] or exit 42; exit 43',
                str(secret),
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        runtime_process_info_denied = subprocess.run(
            [
                campaign["sandbox"]["executable"],
                "-D",
                f"TMP_DIR={writable}",
                "-D",
                f"TARGET_DIR={writable}",
                "-D",
                "EXECUTABLE=/bin/ps",
                "-D",
                f"MARKER={marker}",
                "-f",
                str(runtime_profile),
                "/bin/ps",
                "-p",
                str(sentinel.pid),
                "-o",
                "pid=",
            ],
            cwd=writable,
            env={"PATH": "/usr/bin:/bin", "HOME": str(smoke), "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        passed = (
            compile_policy_passed
            and compile_read_denied.returncode == 42
            and compile_fork_ok.returncode == 0
            and runtime_ok.returncode == 0
            and runtime_exec_denied.returncode == 42
            and runtime_read_denied.returncode == 42
            and runtime_process_info_denied.returncode != 0
        )
        detail = (
            f"status={result.returncode}; "
            f"runtime={runtime_ok.returncode}; "
            f"runtime_exec={runtime_exec_denied.returncode}; "
            f"compile_read={compile_read_denied.returncode}; "
            f"compile_fork={compile_fork_ok.returncode}; "
            f"runtime_read={runtime_read_denied.returncode}; "
            f"runtime_process_info={runtime_process_info_denied.returncode}; "
            f"child_nproc={smoke_nproc_limit}; "
            + result.stderr.decode("utf-8", errors="replace")[-512:].strip()
        )
        return passed, detail
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as error:
        return False, str(error)
    finally:
        if sentinel.poll() is None:
            os.killpg(sentinel.pid, signal.SIGKILL)
        sentinel.wait(timeout=5)
        if escape.exists() and escape.is_file() and not escape.is_symlink():
            escape.unlink()
        if secret.exists() and secret.is_file() and not secret.is_symlink():
            secret.unlink()
        shutil.rmtree(smoke)


def command_doctor(campaign: dict[str, Any]) -> dict[str, Any]:
    binius = Path(campaign["paths"]["binius_source"])
    pinned = campaign["pinned"]["binius_revision"]
    revision = subprocess.run(
        ["git", "-C", str(binius), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    status = subprocess.run(
        ["git", "-C", str(binius), "status", "--porcelain"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    free = _free_bytes(campaign)
    sandbox_operational, sandbox_detail = _sandbox_smoke(campaign)
    binius_revision_matches = revision.returncode == 0 and revision.stdout.strip() == pinned
    binius_clean = status.returncode == 0 and not status.stdout.strip()
    return {
        "schema": "hegemon.proof-autoresearch.doctor.v1",
        "campaign_id": campaign["campaign_id"],
        "repo_root": str(REPO_ROOT),
        "binius_source": str(binius),
        "binius_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "binius_revision_matches": binius_revision_matches,
        "binius_clean": binius_clean,
        "sandbox_operational": sandbox_operational,
        "sandbox_detail": sandbox_detail,
        "free_bytes": free,
        "heavy_run_admitted": bool(
            free >= campaign["resources"]["heavy_run_admission_free_bytes"]
            and binius_revision_matches
            and binius_clean
            and sandbox_operational
        ),
        "heavy_run_admission_free_bytes": campaign["resources"]["heavy_run_admission_free_bytes"],
        "hard_abort_free_bytes": campaign["resources"]["hard_abort_free_bytes"],
        "strict_lane_available": False,
        "strict_lane_note": "strict_pq_profile.py intentionally has no established backend capabilities yet",
    }


def _dominates(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_m = left["measurement"]
    right_m = right["measurement"]
    keys = ("envelope_bytes", "verify_ms", "prove_ms")
    comparable = all(left_m.get(key) is not None and right_m.get(key) is not None for key in keys)
    if not comparable:
        return False
    no_worse = all(left_m[key] <= right_m[key] for key in keys)
    strictly_better = any(left_m[key] < right_m[key] for key in keys)
    if left_m.get("peak_rss_bytes") is not None and right_m.get("peak_rss_bytes") is not None:
        no_worse = no_worse and left_m["peak_rss_bytes"] <= right_m["peak_rss_bytes"]
        strictly_better = strictly_better or left_m["peak_rss_bytes"] < right_m["peak_rss_bytes"]
    return no_worse and strictly_better


def summarize(entries: list[dict[str, Any]], campaign: dict[str, Any]) -> dict[str, Any]:
    eligible = [entry for entry in entries if entry.get("evaluation", {}).get("eligible") is True]
    lanes: dict[str, Any] = {}
    for lane in ("strict", "prototype"):
        rows = [entry for entry in eligible if entry["evaluation"]["security_lane"] == lane]
        rows.sort(
            key=lambda entry: (
                entry["measurement"]["envelope_bytes"],
                entry["measurement"]["verify_ms"],
                entry["measurement"]["prove_ms"],
                entry["measurement"].get("peak_rss_bytes") or sys.maxsize,
            )
        )
        frontier = [
            entry for entry in rows if not any(_dominates(other, entry) for other in rows if other is not entry)
        ]
        lanes[lane] = {
            "winner": None if not rows else {
                "candidate_id": rows[0]["candidate_id"],
                "trial_id": rows[0]["trial_id"],
                "envelope_bytes": rows[0]["measurement"]["envelope_bytes"],
                "proof_bytes": rows[0]["measurement"]["proof_bytes"],
                "target_met": rows[0]["evaluation"]["target_met"],
            },
            "pareto": [
                {
                    "candidate_id": entry["candidate_id"],
                    "trial_id": entry["trial_id"],
                    "envelope_bytes": entry["measurement"]["envelope_bytes"],
                    "prove_ms": entry["measurement"]["prove_ms"],
                    "verify_ms": entry["measurement"]["verify_ms"],
                    "peak_rss_bytes": entry["measurement"].get("peak_rss_bytes"),
                }
                for entry in frontier
            ],
        }
    strict_reproductions: dict[tuple[str, str, int, int], int] = {}
    for entry in eligible:
        if (
            entry.get("origin") == "live"
            and entry.get("evaluation", {}).get("security_lane") == "strict"
            and entry.get("evaluation", {}).get("target_met") is True
        ):
            provenance_digest = _sha256_bytes(_canonical_bytes(entry.get("provenance")))
            key = (
                entry["candidate_id"],
                provenance_digest,
                entry["measurement"]["proof_bytes"],
                entry["measurement"]["envelope_bytes"],
            )
            strict_reproductions[key] = strict_reproductions.get(key, 0) + 1
    required_reproductions = campaign["strict_reproductions_required"]
    strict_goal_complete = any(
        count >= required_reproductions for count in strict_reproductions.values()
    )
    return {
        "schema": "hegemon.proof-autoresearch.status.v1",
        "campaign_id": campaign["campaign_id"],
        "ledger_entries": len(entries),
        "eligible_entries": len(eligible),
        "strict_admissible": lanes["strict"]["winner"] is not None,
        "strict_goal_complete": strict_goal_complete,
        "strict_reproductions_required": required_reproductions,
        "maximum_matching_strict_reproductions": max(strict_reproductions.values(), default=0),
        "lanes": lanes,
    }


def command_seed(
    campaign: dict[str, Any], candidate: dict[str, Any], measurement_path: Path, state: Path
) -> dict[str, Any]:
    declared = _string(candidate.get("seed_measurement"), "candidate.seed_measurement")
    expected_path = _resolve_repo_path(declared, "candidate.seed_measurement")
    if measurement_path.resolve() != expected_path:
        _fail("seed measurement path does not match the candidate's frozen declaration")
    expected_digest = _string(
        candidate.get("seed_measurement_sha256"), "candidate.seed_measurement_sha256"
    )
    actual_digest = _sha256_file(measurement_path)
    if actual_digest != expected_digest:
        _fail("seed measurement digest does not match the candidate declaration")
    payload = _object(
        _read_json(measurement_path, cap=campaign["resources"]["max_result_json_bytes"]),
        "seed measurement",
    )
    if payload.get("schema") != FULL_MEASUREMENT_SCHEMA:
        _fail("only the frozen full-measurement schema may seed a ledger")
    normalized = normalize_measurement(payload)
    evaluation = evaluate_measurement(normalized, candidate, campaign, authority_passed=False)
    if not evaluation["eligible"]:
        _fail("seed measurement violates the campaign: " + "; ".join(evaluation["failures"]))
    provenance = candidate_provenance(candidate)
    entry = _trial_entry(
        campaign,
        candidate,
        provenance,
        normalized,
        evaluation,
        origin="seed",
        environment={
            "measurement_path": str(measurement_path.resolve()),
            "measurement_sha256": actual_digest,
            "live_execution": False,
        },
    )
    return _append_ledger(state, entry, campaign)


def command_run(
    campaign: dict[str, Any], candidate: dict[str, Any], state: Path
) -> dict[str, Any]:
    temp_parent = Path(campaign["paths"]["temporary_parent"]).resolve()
    host_lock = temp_parent / "hegemon-proof-autoresearch.lock"
    with _exclusive_lock(host_lock, "host-wide-autoresearch"):
        run_dir = _create_run_dir(campaign, candidate["id"])
        provenance = candidate_provenance(candidate)
        free_after_cleanup: int | None = None
        try:
            payload, environment = _run_supervised(campaign, candidate, run_dir)
            normalized = _normalize_live_payload(payload, run_dir, campaign)
            if normalized.get("peak_rss_bytes") is None:
                observed_peak = _integer(
                    environment.get("max_process_group_rss_bytes_seen"),
                    "environment.max_process_group_rss_bytes_seen",
                    minimum=1,
                )
                normalized["peak_rss_bytes"] = observed_peak
            authority_passed = _run_authority_if_needed(normalized, campaign, run_dir)
            evaluation = evaluate_measurement(
                normalized, candidate, campaign, authority_passed=authority_passed
            )
            _assert_provenance_unchanged(provenance, candidate)
        finally:
            _remove_owned_run_dir(run_dir, campaign)
            free_after_cleanup = _free_bytes(campaign)
        environment["free_bytes_after_cleanup"] = free_after_cleanup
        entry = _trial_entry(
            campaign,
            candidate,
            provenance,
            normalized,
            evaluation,
            origin="live",
            environment=environment,
        )
        return _append_ledger(state, entry, campaign)


def command_gc(campaign: dict[str, Any]) -> dict[str, Any]:
    temp_parent = Path(campaign["paths"]["temporary_parent"]).resolve()
    threshold = campaign["resources"]["stale_run_hours"] * 3600
    removed: list[str] = []
    retained: list[dict[str, Any]] = []
    with _exclusive_lock(temp_parent / "hegemon-proof-autoresearch.lock", "host-wide-autoresearch"):
        for path in temp_parent.iterdir():
            if not path.name.startswith(RUN_PREFIX):
                continue
            if path.is_symlink() or not path.is_dir():
                retained.append({"path": str(path), "reason": "not a real directory"})
                continue
            try:
                marker = _validate_owned_run_dir(path, campaign)
            except ResearchError as error:
                retained.append({"path": str(path), "reason": str(error)})
                continue
            age = time.time() - _number(marker.get("created_unix"), "marker.created_unix")
            if age < threshold:
                retained.append({"path": str(path), "reason": "younger than stale horizon"})
                continue
            pid = _integer(marker.get("pid"), "marker.pid", minimum=1)
            recorded_start = marker.get("pid_start_token")
            if not isinstance(recorded_start, str) or not recorded_start:
                retained.append({"path": str(path), "reason": "controller start token is absent"})
                continue
            worker_pgid = marker.get("worker_pgid")
            if worker_pgid is not None:
                worker_pgid = _integer(worker_pgid, "marker.worker_pgid", minimum=1)
                if _process_group_alive(worker_pgid):
                    retained.append({"path": str(path), "reason": "recorded worker group is still live"})
                    continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                _remove_owned_run_dir(path, campaign)
                removed.append(str(path))
            except PermissionError:
                retained.append({"path": str(path), "reason": "pid ownership is ambiguous"})
            else:
                if _process_start_token(pid) != recorded_start:
                    _remove_owned_run_dir(path, campaign)
                    removed.append(str(path))
                else:
                    retained.append({"path": str(path), "reason": "recorded controller is still live"})
    return {
        "schema": "hegemon.proof-autoresearch.gc.v1",
        "removed": removed,
        "retained": retained,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="validate pinned inputs and resource admission")
    seed = subparsers.add_parser("seed", help="import a frozen exact measurement")
    seed.add_argument("--candidate", type=Path, required=True)
    seed.add_argument("--measurement", type=Path, required=True)
    run = subparsers.add_parser("run", help="run one candidate under hard resource limits")
    run.add_argument("--candidate", type=Path, required=True)
    subparsers.add_parser("status", help="show separate strict and prototype frontiers")
    subparsers.add_parser("verify-ledger", help="verify the complete hash chain")
    subparsers.add_parser("gc", help="remove only stale UUID-marked run roots")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        campaign = load_campaign(args.campaign.resolve(), require_canonical=True)
        state = args.state_dir.resolve()
        if args.command == "doctor":
            result = command_doctor(campaign)
        elif args.command == "seed":
            candidate = load_candidate(args.candidate.resolve(), campaign)
            result = command_seed(
                campaign, candidate, args.measurement.resolve(), state
            )
        elif args.command == "run":
            candidate = load_candidate(args.candidate.resolve(), campaign)
            result = command_run(campaign, candidate, state)
        elif args.command == "status":
            entries = _read_ledger(_ensure_state_dir(state) / "results.jsonl", campaign)
            result = summarize(entries, campaign)
        elif args.command == "verify-ledger":
            entries = _read_ledger(_ensure_state_dir(state) / "results.jsonl", campaign)
            result = {
                "schema": "hegemon.proof-autoresearch.ledger-verification.v1",
                "valid": True,
                "entries": len(entries),
                "head": entries[-1]["entry_digest"] if entries else None,
            }
        elif args.command == "gc":
            result = command_gc(campaign)
        else:
            raise AssertionError(args.command)
    except ResearchError as error:
        print(f"proof autoresearch rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
