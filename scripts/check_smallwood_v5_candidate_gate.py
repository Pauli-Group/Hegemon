#!/usr/bin/env python3
"""Validate the dormant SmallWood V5 manifest or require full authorization."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import NoReturn


PROFILE_ID = "smallwood-v5-conventional-hash-inline-v1"
STRICT_SECURITY_PROFILE_ID = (
    "hegemon.smallwood.v5-delta.shake256-448-sha512.strict.v1"
)
STRICT_SECURITY_REPORT_SCHEMA = "hegemon.smallwood.strict-evaluation-report.v1"
STRICT_GATE_DIRECTORY = Path(".agent/hardening/smallwood-pqc-zk")
STRICT_PROFILE_PATH = STRICT_GATE_DIRECTORY / "target-profile.json"
STRICT_CERTIFICATE_PATH = STRICT_GATE_DIRECTORY / "candidate-certificate.json"
STRICT_TRUST_ROOT_PATH = STRICT_GATE_DIRECTORY / "trust-root.json"
STRICT_GATE_MODULE_PATH = STRICT_GATE_DIRECTORY / "strict_profile.py"
STRICT_TRUST_ROOT_DIGEST_ENV = "HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256"
EXPECTED_IDENTITY = {
    "circuit": 5,
    "crypto_suite": 4,
    "backend_wire_id": 2,
    "envelope_magic_ascii": "SWV5",
    "envelope_version": 1,
    "profile_wire_id": 1,
    "proof_mode": "inline_only",
    "family_id": 1,
    "action_id": 7,
    "public_value_count": 78,
    "public_values_bytes": 624,
    "balance_tag_bytes": 48,
    "statement_bytes": 672,
    "header_bytes": 80,
    "max_envelope_bytes": 524_288,
    "max_proof_bytes": 523_536,
}
REQUIRED_CAPABILITIES = (
    "production_version_mapping_enabled",
    "kernel_manifest_enabled",
    "proof_system_implemented",
    "complete_zero_knowledge_proved",
    "proof_of_knowledge_extraction_proved",
    "complete_transcript_simulator_proved",
    "abort_conditioned_zk_proved",
    "compiled_prover_distribution_refinement_proved",
    "composed_qrom_pq128_proved",
    "global_multi_target_qrom_composition_bounded",
    "deployed_hash_instantiation_bounded",
    "relation_hash_collision_preimage_losses_bounded",
    "rust_verifier_refinement_proved",
    "formal_relation_refinement_proved",
    "byte_artifact_verified",
    "end_to_end_identical_bytes_verified",
)
REQUIRED_ARTIFACTS = (
    "proof",
    "zero_knowledge_simulator",
    "proof_of_knowledge_extraction",
    "qrom_security",
    "relation_hash_security",
    "formal_relation_refinement",
    "rust_verifier_refinement",
    "end_to_end_identical_bytes",
    "strict_security_evaluation",
)
EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "profile_id",
    "strict_security_profile_id",
    "identity",
    "production_active",
    "capabilities",
    "security",
    "relation_binding_hex",
    "measured_proof_bytes",
    "artifacts",
    "claim_boundary",
}


class CandidateGateError(ValueError):
    """The candidate manifest is malformed or not authorized."""


def reject(message: str) -> NoReturn:
    raise CandidateGateError(f"{PROFILE_ID}: {message}")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            reject(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        reject(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        reject(
            f"{label} keys mismatch; missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def check_identity(document: dict[str, object]) -> None:
    schema_version = document.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        reject("schema_version must be integer 1")
    if document.get("profile_id") != PROFILE_ID:
        reject("profile_id mismatch")
    if document.get("strict_security_profile_id") != STRICT_SECURITY_PROFILE_ID:
        reject("strict_security_profile_id mismatch")
    identity = require_object(document.get("identity"), "identity")
    require_exact_keys(identity, set(EXPECTED_IDENTITY), "identity")
    for name, expected in EXPECTED_IDENTITY.items():
        observed = identity[name]
        if type(observed) is not type(expected):
            reject(f"identity.{name} has the wrong JSON type")
    if identity != EXPECTED_IDENTITY:
        reject("identity does not exactly match the compiled V5 wire")


def check_capabilities(document: dict[str, object]) -> bool:
    capabilities = require_object(document.get("capabilities"), "capabilities")
    require_exact_keys(capabilities, set(REQUIRED_CAPABILITIES), "capabilities")
    for name in REQUIRED_CAPABILITIES:
        if not isinstance(capabilities[name], bool):
            reject(f"capabilities.{name} must be a boolean")
    return all(capabilities[name] is True for name in REQUIRED_CAPABILITIES)


def check_hex(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length:
        reject(f"{label} must be {length} lowercase hexadecimal characters")
    if value != value.lower():
        reject(f"{label} must be lowercase hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise CandidateGateError(f"{PROFILE_ID}: {label} is not hexadecimal") from exc
    if len(decoded) != length // 2:
        reject(f"{label} must not contain whitespace or separators")
    return value


def check_artifact(value: object, label: str, root: Path) -> bytes:
    artifact = require_object(value, f"artifacts.{label}")
    require_exact_keys(artifact, {"path", "bytes", "sha256"}, f"artifacts.{label}")
    path_value = artifact.get("path")
    byte_count = artifact.get("bytes")
    digest = check_hex(artifact.get("sha256"), 64, f"artifacts.{label}.sha256")
    if not isinstance(path_value, str) or not path_value:
        reject(f"artifacts.{label}.path must be a nonempty repository-relative path")
    relative = Path(path_value)
    if relative.is_absolute() or any(part in {".", ".."} for part in relative.parts):
        reject(f"artifacts.{label}.path must stay inside the repository")
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count <= 0:
        reject(f"artifacts.{label}.bytes must be a positive integer")
    root = root.resolve()
    path = root / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if path.is_symlink():
            reject(f"artifacts.{label}.path must not be a symbolic link")
        payload = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise CandidateGateError(
            f"{PROFILE_ID}: cannot read artifacts.{label}.path {path}: {exc}"
        ) from exc
    if len(payload) != byte_count:
        reject(
            f"artifacts.{label}.bytes mismatch: manifest={byte_count} actual={len(payload)}"
        )
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != digest:
        reject(f"artifacts.{label}.sha256 mismatch")
    return payload


def check_strict_security_authorization(root: Path) -> dict[str, object]:
    """Derive strict authority from a checker-owned profile and protected trust root."""

    root = root.resolve()
    trust_root = root / STRICT_TRUST_ROOT_PATH
    pinned_digest = os.environ.get(STRICT_TRUST_ROOT_DIGEST_ENV)
    if (
        pinned_digest is None
        or len(pinned_digest) != 64
        or any(character not in "0123456789abcdef" for character in pinned_digest)
    ):
        reject(
            f"active authorization requires protected {STRICT_TRUST_ROOT_DIGEST_ENV}"
        )
    try:
        actual_digest = hashlib.sha256(trust_root.read_bytes()).hexdigest()
    except OSError as exc:
        raise CandidateGateError(
            f"{PROFILE_ID}: cannot read strict trust root {trust_root}: {exc}"
        ) from exc
    if actual_digest != pinned_digest:
        reject("strict security trust-root digest does not match the protected pin")

    module_path = root / STRICT_GATE_MODULE_PATH
    spec = importlib.util.spec_from_file_location(
        "hegemon_smallwood_v5_strict_profile", module_path
    )
    if spec is None or spec.loader is None:
        reject(f"cannot load strict security gate from {module_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        report = module.evaluate(
            module.load_json_strict(root / STRICT_PROFILE_PATH),
            module.load_json_strict(root / STRICT_CERTIFICATE_PATH),
            module.load_json_strict(trust_root),
            root,
        )
    except Exception as exc:
        raise CandidateGateError(
            f"{PROFILE_ID}: strict security gate could not derive authority: {exc}"
        ) from exc
    if not isinstance(report, dict):
        reject("strict security gate returned a malformed report")
    if report.get("schema") != STRICT_SECURITY_REPORT_SCHEMA:
        reject("strict security report schema mismatch")
    if report.get("input_valid") is not True:
        reject("strict security report input is not valid")
    if report.get("profile_id") != STRICT_SECURITY_PROFILE_ID:
        reject("strict security report profile mismatch")
    capabilities = require_object(
        report.get("capabilities"), "strict security report capabilities"
    )
    if capabilities != {
        "complete_zk": True,
        "pq128": True,
        "production_authorized": True,
    }:
        reject("strict security gate did not derive complete-ZK and PQ128 authority")
    required = report.get("required_evidence_count")
    verified = report.get("verified_evidence_count")
    if (
        isinstance(required, bool)
        or not isinstance(required, int)
        or required <= 0
        or verified != required
    ):
        reject("strict security report does not verify every required receipt")
    if report.get("profile_gate_pass") is not True:
        reject("strict security target profile did not pass")
    if report.get("complete_zk_evidence_pass") is not True:
        reject("strict security report lacks complete-ZK evidence closure")
    if report.get("pq128_evidence_pass") is not True:
        reject("strict security report lacks PQ128 evidence closure")
    soundness = require_object(report.get("soundness"), "strict security soundness")
    if (
        soundness.get("low_advantage_gate_pass") is not True
        or soundness.get("work_factor_gate_pass") is not True
    ):
        reject("strict security report does not pass both composed soundness gates")
    zero_knowledge = require_object(
        report.get("zero_knowledge"), "strict security zero_knowledge"
    )
    if zero_knowledge.get("numeric_gate_pass") is not True:
        reject("strict security report does not pass the quantitative ZK gate")
    return report


def check_document(document: object, root: Path, require_authorized: bool) -> bool:
    if not isinstance(document, dict):
        reject("manifest must be an object")
    require_exact_keys(document, EXPECTED_TOP_LEVEL_KEYS, "manifest")
    check_identity(document)
    all_capabilities = check_capabilities(document)
    active = document.get("production_active")
    if not isinstance(active, bool):
        reject("production_active must be a boolean")

    security = require_object(document.get("security"), "security")
    require_exact_keys(
        security,
        {
            "concrete_pq_security_bits",
            "relation_hash_output_bits",
            "proof_transcript_hash_output_bits",
        },
        "security",
    )
    artifacts = require_object(document.get("artifacts"), "artifacts")
    require_exact_keys(artifacts, set(REQUIRED_ARTIFACTS), "artifacts")
    claim_boundary = document.get("claim_boundary")
    if not isinstance(claim_boundary, str) or not claim_boundary.strip():
        reject("claim_boundary must be a nonempty string")

    pq_bits = security.get("concrete_pq_security_bits")
    if pq_bits is not None and (
        isinstance(pq_bits, bool) or not isinstance(pq_bits, int) or pq_bits < 128
    ):
        reject("security.concrete_pq_security_bits must be null or an integer at least 128")
    relation_bits = security.get("relation_hash_output_bits")
    if relation_bits is not None and (
        isinstance(relation_bits, bool)
        or not isinstance(relation_bits, int)
        or relation_bits != 448
    ):
        reject(
            "security.relation_hash_output_bits must be null or integer 448 for the strict profile; "
            "384 bits has no generic quantum-collision composition margin"
        )
    transcript_bits = security.get("proof_transcript_hash_output_bits")
    if transcript_bits is not None and (
        isinstance(transcript_bits, bool)
        or not isinstance(transcript_bits, int)
        or transcript_bits != 512
    ):
        reject(
            "security.proof_transcript_hash_output_bits must be null or integer 512"
        )
    relation_binding_value = document.get("relation_binding_hex")
    if relation_binding_value is not None:
        relation_binding = check_hex(
            relation_binding_value, 96, "relation_binding_hex"
        )
        if set(relation_binding) == {"0"}:
            reject("relation_binding_hex must be nonzero")
    proof_bytes = document.get("measured_proof_bytes")
    if proof_bytes is not None and (
        isinstance(proof_bytes, bool)
        or not isinstance(proof_bytes, int)
        or proof_bytes <= 0
        or proof_bytes > EXPECTED_IDENTITY["max_proof_bytes"]
    ):
        reject(
            "measured_proof_bytes must be null or a positive integer no greater than "
            f"{EXPECTED_IDENTITY['max_proof_bytes']}"
        )
    artifact_payloads: dict[str, bytes] = {}
    for label in REQUIRED_ARTIFACTS:
        if artifacts[label] is not None:
            artifact_payloads[label] = check_artifact(artifacts[label], label, root)

    if not active:
        if require_authorized:
            reject("production_active must be true")
        return False

    if not all_capabilities:
        missing = [
            name
            for name in REQUIRED_CAPABILITIES
            if document["capabilities"][name] is not True
        ]
        reject("production_active requires every capability; missing " + ", ".join(missing))

    if pq_bits is None:
        reject("security.concrete_pq_security_bits must be an integer at least 128")
    if relation_bits is None:
        reject(
            "security.relation_hash_output_bits must be integer 448 for the strict profile; "
            "384 bits has no generic quantum-collision composition margin"
        )
    if transcript_bits is None:
        reject("security.proof_transcript_hash_output_bits must be integer 512")
    if relation_binding_value is None:
        reject("relation_binding_hex must be 96 lowercase hexadecimal characters")
    if proof_bytes is None:
        reject(
            "measured_proof_bytes must be a positive integer no greater than "
            f"{EXPECTED_IDENTITY['max_proof_bytes']}"
        )
    for label in REQUIRED_ARTIFACTS:
        if artifacts[label] is None:
            reject(f"artifacts.{label} must be an object")
    strict_report = check_strict_security_authorization(root)
    canonical_report = (
        json.dumps(strict_report, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if artifact_payloads["strict_security_evaluation"] != canonical_report:
        reject(
            "artifacts.strict_security_evaluation is not the exact derived strict report"
        )
    return True


def load_document(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateGateError(f"cannot read valid JSON from {path}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path("config/smallwood-v5-conventional-hash-candidate.json"),
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--require-authorized", action="store_true")
    args = parser.parse_args()
    try:
        active = check_document(
            load_document(args.manifest),
            args.root.resolve(),
            args.require_authorized,
        )
    except CandidateGateError as exc:
        raise SystemExit(f"SmallWood V5 candidate gate rejected: {exc}") from exc
    posture = "authorized" if active else "inactive"
    print(f"SmallWood V5 candidate gate passed: profile={PROFILE_ID} posture={posture}")


if __name__ == "__main__":
    main()
