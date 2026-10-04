#!/usr/bin/env python3
"""Fail-closed admission for Hegemon production proof-size frontier points.

This gate intentionally does not benchmark or prove cryptographic claims.  It
admits a byte measurement only when separately produced, content-addressed
certificates cover every non-negotiable production obligation.  Candidate
patches cannot substitute a narrower relation or a self-attested security flag.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
from typing import Any, NoReturn


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
DEFAULT_POLICY = HERE / "policy.json"
DEFAULT_CANDIDATE = HERE / "candidates" / "m4-padding-fiber-weak-profile.json"
POLICY_SCHEMA = "hegemon.proof-frontier.policy.v1"
HEX64 = frozenset("0123456789abcdef")
# Filled with the canonical policy digest.  The CLI never accepts a replacement
# policy; unit tests exercise policy parsing through the library entrypoint.
CANONICAL_POLICY_SHA256 = "dff0c11e730b743857bdec47b9b2c6f161bd41ca4cd754c11b99f70a022cd1d6"


class GateError(ValueError):
    pass


def fail(message: str) -> NoReturn:
    raise GateError(message)


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON constant {value!r}")


DECODER = json.JSONDecoder(
    object_pairs_hook=no_duplicate_object,
    parse_constant=reject_constant,
)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX64 for character in value)
    )


def require_sha256(value: Any, name: str) -> str:
    if not is_sha256(value):
        fail(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{name} must be a non-empty string")
    return value


def require_bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        fail(f"{name} must be a boolean")
    return value


def require_int(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{name} must be an integer at least {minimum}")
    return value


def require_exact_keys(
    value: dict[str, Any], name: str, expected: set[str]
) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        fail(f"{name} key mismatch; missing={missing}, extra={extra}")


def ensure_no_symlinks(path: Path, root: Path) -> None:
    resolved_root = root.resolve()
    try:
        relative = path.relative_to(resolved_root)
    except ValueError:
        fail(f"path escapes repository: {path}")
    cursor = resolved_root
    for component in relative.parts:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except OSError as error:
            fail(f"cannot stat {cursor}: {error}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"symlink forbidden in evidence path: {cursor}")


def resolve_repo_file(root: Path, raw: Any, name: str) -> Path:
    text = require_string(raw, name)
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"{name} must be a repository-relative path")
    root = root.resolve()
    path = root / relative
    ensure_no_symlinks(path, root)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"{name} is not a regular file")
    return path


def read_json_exact(
    path: Path, *, cap: int = 1024 * 1024, canonical: bool = False
) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        fail(f"invalid or oversized JSON file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
        value, end = DECODER.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse exact JSON {path}: {error}")
    if text[end:].strip():
        fail(f"trailing non-whitespace after JSON value: {path}")
    result = require_object(value, str(path))
    if canonical and raw != canonical_bytes(result):
        fail(f"certificate is not canonical JSON: {path}")
    return result


def load_policy(path: Path, *, require_sealed: bool) -> dict[str, Any]:
    path = path.resolve()
    if require_sealed:
        if path != DEFAULT_POLICY.resolve():
            fail("CLI accepts only the sealed production frontier policy")
        if sha256_file(path) != CANONICAL_POLICY_SHA256:
            fail("production frontier policy digest does not match the gate")
    policy = read_json_exact(path, canonical=True)
    require_exact_keys(
        policy,
        "policy",
        {
            "schema",
            "authorized_certificate_sha256",
            "policy_id",
            "manifest_schema",
            "certificate_schema",
            "gates",
            "gate_issuers",
            "evidence_root",
            "production_surface_paths",
            "relation",
            "requirements",
        },
    )
    if policy["schema"] != POLICY_SCHEMA:
        fail(f"policy.schema must be {POLICY_SCHEMA!r}")
    gates = policy["gates"]
    if gates != ["relation", "binding", "zk", "pq128", "parser", "formal_differential"]:
        fail("policy gates or ordering drifted")
    if set(policy["gate_issuers"]) != set(gates):
        fail("policy must name exactly one issuer for each gate")
    authorized = require_object(
        policy["authorized_certificate_sha256"], "authorized_certificate_sha256"
    )
    if set(authorized) != set(gates):
        fail("policy must carry an authorization list for every gate")
    for gate in gates:
        digests = authorized[gate]
        if not isinstance(digests, list) or len(digests) != len(set(digests)):
            fail(f"authorized certificate list for {gate} is invalid")
        for index, digest in enumerate(digests):
            require_sha256(digest, f"authorized_certificate_sha256.{gate}[{index}]")
    return policy


def production_surface_sha256(root: Path, policy: dict[str, Any]) -> str:
    digest = hashlib.sha256(b"hegemon-production-proof-surface-v1\0")
    paths = policy["production_surface_paths"]
    if not isinstance(paths, list) or not paths:
        fail("production_surface_paths must be a non-empty list")
    if len(paths) != len(set(paths)):
        fail("production_surface_paths contains duplicates")
    for index, raw in enumerate(paths):
        relative = require_string(raw, f"production_surface_paths[{index}]")
        path = resolve_repo_file(root, relative, f"production_surface_paths[{index}]")
        framed_path = relative.encode("utf-8")
        content = path.read_bytes()
        digest.update(len(framed_path).to_bytes(4, "little"))
        digest.update(framed_path)
        digest.update(len(content).to_bytes(8, "little"))
        digest.update(content)
    return digest.hexdigest()


def validate_activation(value: Any) -> dict[str, Any]:
    activation = require_object(value, "activation")
    require_exact_keys(
        activation,
        "activation",
        {
            "circuit_version",
            "crypto_suite",
            "backend",
            "profile",
            "family_id",
            "action_ids",
            "standalone_proof",
            "aggregation",
            "sidecar_authority",
            "network_binding_fields",
        },
    )
    require_int(activation["circuit_version"], "activation.circuit_version", 1)
    require_int(activation["crypto_suite"], "activation.crypto_suite", 1)
    require_string(activation["backend"], "activation.backend")
    require_string(activation["profile"], "activation.profile")
    require_int(activation["family_id"], "activation.family_id", 1)
    action_ids = activation["action_ids"]
    if not isinstance(action_ids, list) or not action_ids:
        fail("activation.action_ids must be non-empty")
    if len(action_ids) != len(set(action_ids)):
        fail("activation.action_ids contains duplicates")
    for index, action_id in enumerate(action_ids):
        require_int(action_id, f"activation.action_ids[{index}]", 1)
    for field in ("standalone_proof", "aggregation", "sidecar_authority"):
        require_bool(activation[field], f"activation.{field}")
    if activation["standalone_proof"] is not True:
        fail("frontier proof must be standalone")
    if activation["aggregation"] is not False:
        fail("aggregation cannot satisfy the transaction-proof frontier")
    if activation["sidecar_authority"] is not False:
        fail("sidecar authority cannot satisfy the transaction-proof frontier")
    if activation["network_binding_fields"] != [
        "chain-id",
        "genesis-block-id",
        "rules-hash",
    ]:
        fail("activation must bind chain-id, genesis-block-id, and rules-hash")
    return activation


def validate_measurement(
    value: Any, root: Path, candidate_digest: str
) -> tuple[dict[str, Any], list[str]]:
    measurement = require_object(value, "measurement")
    require_exact_keys(
        measurement,
        "measurement",
        {"proof_bytes", "envelope_bytes", "proof_artifacts"},
    )
    proof_bytes = require_int(measurement["proof_bytes"], "measurement.proof_bytes", 1)
    envelope_bytes = require_int(
        measurement["envelope_bytes"], "measurement.envelope_bytes", proof_bytes
    )
    artifacts = measurement["proof_artifacts"]
    if not isinstance(artifacts, list):
        fail("measurement.proof_artifacts must be a list")
    artifact_failures: list[str] = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(artifacts):
        artifact = require_object(raw, f"proof_artifacts[{index}]")
        require_exact_keys(
            artifact,
            f"proof_artifacts[{index}]",
            {"path", "sha256", "bytes", "candidate_source_sha256"},
        )
        relative = require_string(artifact["path"], f"proof_artifacts[{index}].path")
        if relative in seen_paths:
            fail("duplicate proof artifact path")
        seen_paths.add(relative)
        expected_hash = require_sha256(
            artifact["sha256"], f"proof_artifacts[{index}].sha256"
        )
        expected_bytes = require_int(
            artifact["bytes"], f"proof_artifacts[{index}].bytes", 1
        )
        if artifact["candidate_source_sha256"] != candidate_digest:
            artifact_failures.append(
                f"proof artifact {index} is not bound to candidate source digest"
            )
            continue
        try:
            path = resolve_repo_file(root, relative, f"proof_artifacts[{index}].path")
        except GateError as error:
            artifact_failures.append(str(error))
            continue
        actual_bytes = path.stat().st_size
        if actual_bytes != expected_bytes or expected_bytes != proof_bytes:
            artifact_failures.append(
                f"proof artifact {index} byte count does not match measured proof bytes"
            )
        if sha256_file(path) != expected_hash:
            artifact_failures.append(f"proof artifact {index} digest mismatch")
    return measurement, artifact_failures


def validate_certificate_common(
    certificate: dict[str, Any],
    *,
    gate: str,
    policy: dict[str, Any],
    candidate_id: str,
    candidate_digest: str,
    surface_digest: str,
) -> dict[str, Any]:
    require_exact_keys(
        certificate,
        f"{gate} certificate",
        {
            "schema",
            "gate",
            "candidate_id",
            "candidate_source_sha256",
            "production_surface_sha256",
            "issuer",
            "independent_of_candidate",
            "passed",
            "details",
        },
    )
    if certificate["schema"] != policy["certificate_schema"]:
        fail(f"{gate} certificate schema mismatch")
    if certificate["gate"] != gate:
        fail(f"{gate} certificate labels a different gate")
    if certificate["candidate_id"] != candidate_id:
        fail(f"{gate} certificate candidate id mismatch")
    if certificate["candidate_source_sha256"] != candidate_digest:
        fail(f"{gate} certificate candidate digest mismatch")
    if certificate["production_surface_sha256"] != surface_digest:
        fail(f"{gate} certificate production surface is stale")
    if certificate["issuer"] != policy["gate_issuers"][gate]:
        fail(f"{gate} certificate issuer is not trusted for this gate")
    if certificate["independent_of_candidate"] is not True:
        fail(f"{gate} certificate is not independent of the candidate")
    if certificate["passed"] is not True:
        fail(f"{gate} certificate did not pass")
    return require_object(certificate["details"], f"{gate} certificate details")


def validate_relation(details: dict[str, Any], policy: dict[str, Any]) -> None:
    require_exact_keys(
        details,
        "relation details",
        {
            "semantic_relation_id",
            "parameters",
            "covered_predicates",
            "activity_mask_cases",
            "positive_cases",
            "negative_cases",
            "differential_cases",
            "reference_candidate_mismatches",
            "canonical_semantic_refinement_closed",
        },
    )
    expected = policy["relation"]
    if details["semantic_relation_id"] != expected["semantic_relation_id"]:
        fail("candidate proves a different semantic relation")
    parameters = dict(expected)
    parameters.pop("semantic_relation_id")
    parameters.pop("covered_predicates")
    parameters.pop("activity_mask_cases")
    if details["parameters"] != parameters:
        fail("candidate relation parameters do not equal production parameters")
    if details["covered_predicates"] != expected["covered_predicates"]:
        fail("candidate does not cover the exact production predicate inventory")
    if details["activity_mask_cases"] != expected["activity_mask_cases"]:
        fail("candidate does not cover all production activity masks")
    positive_cases = require_int(details["positive_cases"], "relation.positive_cases", 1)
    if positive_cases != expected["accepted_activity_masks"]:
        fail("relation certificate does not prove exactly the nine accepted masks")
    negative_cases = require_int(details["negative_cases"], "relation.negative_cases", 1)
    if negative_cases < expected["rejected_activity_masks"]:
        fail("relation certificate omits one or more of the seven rejected masks")
    require_int(details["differential_cases"], "relation.differential_cases", 16)
    if details["reference_candidate_mismatches"] != 0:
        fail("candidate/reference relation differential has mismatches")
    if details["canonical_semantic_refinement_closed"] is not True:
        fail("exact-map-to-canonical semantic refinement remains open")


def validate_binding(
    details: dict[str, Any], policy: dict[str, Any], activation: dict[str, Any]
) -> None:
    require_exact_keys(
        details,
        "binding details",
        {
            "activation",
            "bound_fields",
            "mutation_cases",
            "release_manifest_authorized",
            "action_projection_exact",
            "network_binding_in_transcript",
        },
    )
    requirements = policy["requirements"]["binding"]
    if details["activation"] != activation:
        fail("binding certificate activation differs from candidate activation")
    if activation["family_id"] != requirements["family_id"]:
        fail("candidate is not bound to the shielded-pool family")
    if details["bound_fields"] != requirements["required_bound_fields"]:
        fail("binding certificate omits a required statement field")
    if details["mutation_cases"] != requirements["mutation_cases"]:
        fail("binding mutation inventory is incomplete")
    for field in (
        "release_manifest_authorized",
        "action_projection_exact",
        "network_binding_in_transcript",
    ):
        if details[field] is not True:
            fail(f"binding evidence failed {field}")


def validate_zk(details: dict[str, Any]) -> None:
    require_exact_keys(
        details,
        "zk details",
        {
            "definition",
            "complete_witness_privacy_proved",
            "simulator_defined_for_full_relation",
            "proof_bytes_leakage_audit_passed",
            "selective_opening_accounted",
            "qrom_zk_composition_accounted",
            "external_review_id",
        },
    )
    if details["definition"] != "computational-zero-knowledge-full-witness":
        fail("ZK certificate uses the wrong security definition")
    for field in (
        "complete_witness_privacy_proved",
        "simulator_defined_for_full_relation",
        "proof_bytes_leakage_audit_passed",
        "selective_opening_accounted",
        "qrom_zk_composition_accounted",
    ):
        if details[field] is not True:
            fail(f"complete ZK evidence failed {field}")
    require_string(details["external_review_id"], "zk.external_review_id")


def validate_pq128(details: dict[str, Any], policy: dict[str, Any]) -> None:
    require_exact_keys(
        details,
        "pq128 details",
        {
            "composed_post_quantum_bits",
            "knowledge_soundness_post_quantum_bits",
            "commitment_binding_post_quantum_bits",
            "semantic_collision_post_quantum_bits",
            "challenge_field_bits",
            "semantic_hash",
            "proof_hash",
            "fiat_shamir_qrom_complete",
            "component_losses_complete",
            "composed_verifier_checked",
            "external_review_id",
        },
    )
    required = policy["requirements"]["pq128"]
    for field in (
        "composed_post_quantum_bits",
        "knowledge_soundness_post_quantum_bits",
        "commitment_binding_post_quantum_bits",
        "semantic_collision_post_quantum_bits",
    ):
        require_int(details[field], f"pq128.{field}", required["composed_post_quantum_bits_min"])
    require_int(
        details["challenge_field_bits"],
        "pq128.challenge_field_bits",
        required["challenge_field_bits_min"],
    )
    if details["semantic_hash"] != required["semantic_hash"]:
        fail("semantic hash does not match the strict profile")
    if details["proof_hash"] != required["proof_hash"]:
        fail("proof hash does not match the strict profile")
    for field in (
        "fiat_shamir_qrom_complete",
        "component_losses_complete",
        "composed_verifier_checked",
    ):
        if details[field] is not True:
            fail(f"strict PQ128 evidence failed {field}")
    require_string(details["external_review_id"], "pq128.external_review_id")


def validate_parser(details: dict[str, Any], policy: dict[str, Any], measurement: dict[str, Any]) -> None:
    require_exact_keys(
        details,
        "parser details",
        {
            "parser_entrypoint",
            "proof_artifacts",
            "clean_reproductions",
            "exact_consumption",
            "canonical_reencode",
            "trailing_bytes_rejected",
            "truncations_rejected",
            "declared_length_mismatch_rejected",
            "unknown_backend_rejected",
            "unknown_version_rejected",
        },
    )
    require_string(details["parser_entrypoint"], "parser.parser_entrypoint")
    required = policy["requirements"]["parser"]["minimum_clean_reproductions"]
    if details["proof_artifacts"] != measurement["proof_artifacts"]:
        fail("parser certificate does not bind the exact proof artifacts")
    if len(measurement["proof_artifacts"]) < required:
        fail(f"strict frontier requires at least {required} exact proof artifacts")
    require_int(details["clean_reproductions"], "parser.clean_reproductions", required)
    for field in (
        "exact_consumption",
        "canonical_reencode",
        "trailing_bytes_rejected",
        "truncations_rejected",
        "declared_length_mismatch_rejected",
        "unknown_backend_rejected",
        "unknown_version_rejected",
    ):
        if details[field] is not True:
            fail(f"exact parser evidence failed {field}")


def validate_formal(details: dict[str, Any], policy: dict[str, Any]) -> None:
    require_exact_keys(
        details,
        "formal differential details",
        {
            "lean_kernel_build_passed",
            "axiom_audit_passed",
            "sorry_count",
            "proved_obligations",
            "residual_semantic_or_refinement_assumptions",
            "differential_activity_masks",
            "differential_cases",
            "differential_mismatches",
            "negative_mutation_cases",
        },
    )
    required = policy["requirements"]["formal_differential"]
    for field in ("lean_kernel_build_passed", "axiom_audit_passed"):
        if details[field] is not True:
            fail(f"formal evidence failed {field}")
    if details["sorry_count"] != 0:
        fail("formal evidence contains sorry")
    if details["proved_obligations"] != required["proved_obligations"]:
        fail("formal evidence does not prove every required obligation")
    if details["residual_semantic_or_refinement_assumptions"] != []:
        fail("formal semantic/refinement closure retains assumptions")
    if details["differential_activity_masks"] != policy["relation"]["activity_mask_cases"]:
        fail("formal differential does not cover all activity masks")
    require_int(
        details["differential_cases"],
        "formal.differential_cases",
        required["minimum_differential_cases"],
    )
    if details["differential_mismatches"] != 0:
        fail("formal differential has mismatches")
    require_int(details["negative_mutation_cases"], "formal.negative_mutation_cases", 1)


def evaluate_candidate(
    candidate_path: Path,
    policy: dict[str, Any],
    *,
    root: Path,
) -> dict[str, Any]:
    root = root.resolve()
    candidate = read_json_exact(candidate_path)
    require_exact_keys(
        candidate,
        "candidate",
        {
            "schema",
            "candidate_id",
            "candidate_artifact",
            "activation",
            "measurement",
            "claims",
        },
    )
    if candidate["schema"] != policy["manifest_schema"]:
        fail("candidate manifest schema mismatch")
    candidate_id = require_string(candidate["candidate_id"], "candidate_id")
    artifact = require_object(candidate["candidate_artifact"], "candidate_artifact")
    require_exact_keys(artifact, "candidate_artifact", {"path", "sha256"})
    candidate_digest = require_sha256(artifact["sha256"], "candidate_artifact.sha256")
    artifact_path = resolve_repo_file(root, artifact["path"], "candidate_artifact.path")
    if sha256_file(artifact_path) != candidate_digest:
        fail("candidate artifact digest mismatch")
    activation = validate_activation(candidate["activation"])
    measurement, artifact_failures = validate_measurement(
        candidate["measurement"], root, candidate_digest
    )
    minimum_artifacts = policy["requirements"]["parser"]["minimum_clean_reproductions"]
    if len(measurement["proof_artifacts"]) < minimum_artifacts:
        artifact_failures.append(
            f"parser: requires at least {minimum_artifacts} retained exact proof artifacts"
        )
    surface_digest = production_surface_sha256(root, policy)

    claims = require_object(candidate["claims"], "claims")
    if set(claims) != set(policy["gates"]):
        fail("claims must contain every gate exactly once")
    failures = list(artifact_failures)
    certificate_digests: dict[str, str] = {}
    evidence_root = (root / policy["evidence_root"]).resolve()
    for gate in policy["gates"]:
        claim = require_object(claims[gate], f"claims.{gate}")
        require_exact_keys(claim, f"claims.{gate}", {"status", "certificate"})
        if claim["status"] != "verified":
            failures.append(f"{gate}: status is not verified")
            if claim["certificate"] is not None:
                failures.append(f"{gate}: non-verified claim must not attach a certificate")
            continue
        reference = require_object(claim["certificate"], f"claims.{gate}.certificate")
        require_exact_keys(reference, f"claims.{gate}.certificate", {"path", "sha256"})
        expected_digest = require_sha256(reference["sha256"], f"claims.{gate}.certificate.sha256")
        try:
            if expected_digest not in policy["authorized_certificate_sha256"][gate]:
                fail(f"{gate} certificate digest is not authorized by the sealed policy")
            certificate_path = resolve_repo_file(
                root, reference["path"], f"claims.{gate}.certificate.path"
            )
            certificate_path.resolve().relative_to(evidence_root)
            if sha256_file(certificate_path) != expected_digest:
                fail(f"{gate} certificate digest mismatch")
            certificate = read_json_exact(certificate_path, canonical=True)
            details = validate_certificate_common(
                certificate,
                gate=gate,
                policy=policy,
                candidate_id=candidate_id,
                candidate_digest=candidate_digest,
                surface_digest=surface_digest,
            )
            if gate == "binding":
                validate_binding(details, policy, activation)
            elif gate == "parser":
                validate_parser(details, policy, measurement)
            elif gate == "relation":
                validate_relation(details, policy)
            elif gate == "zk":
                validate_zk(details)
            elif gate == "pq128":
                validate_pq128(details, policy)
            elif gate == "formal_differential":
                validate_formal(details, policy)
            else:
                fail(f"unsupported policy gate {gate!r}")
            certificate_digests[gate] = expected_digest
        except (GateError, ValueError) as error:
            failures.append(f"{gate}: {error}")

    admitted = not failures and len(certificate_digests) == len(policy["gates"])
    return {
        "schema": "hegemon.proof-frontier.decision.v1",
        "policy_id": policy["policy_id"],
        "candidate_id": candidate_id,
        "admitted": admitted,
        "proof_bytes": measurement["proof_bytes"],
        "envelope_bytes": measurement["envelope_bytes"],
        "production_surface_sha256": surface_digest,
        "verified_certificates": certificate_digests,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", nargs="?", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--surface-digest", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(DEFAULT_POLICY, require_sealed=True)
        if args.surface_digest:
            print(production_surface_sha256(REPO_ROOT, policy))
            return 0
        decision = evaluate_candidate(args.candidate.resolve(), policy, root=REPO_ROOT)
        print(json.dumps(decision, sort_keys=True, indent=2))
        return 0 if decision["admitted"] else 1
    except (GateError, OSError) as error:
        print(f"proof frontier gate error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
