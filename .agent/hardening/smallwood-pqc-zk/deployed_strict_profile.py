#!/usr/bin/env python3
"""Fail-closed security-profile gate for the retained SmallWood V4/Gamma path.

This checker describes the protocol that the native transaction verifier
actually selects today.  It is deliberately separate from the inactive V5/V6
candidate screens in this directory: changing a successor profile cannot make
the deployed V4 route look stronger, and changing a JSON capability bit cannot
authorize anything.  ``complete_zk`` and ``pq128`` are derived only from the
exact profile, exact rational error calculation, and independently pinned
deployed-end-to-end evidence receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
from fractions import Fraction
from pathlib import Path
from typing import Any, NoReturn


PROFILE_SCHEMA = "hegemon.smallwood.deployed-profile.v1"
CERTIFICATE_SCHEMA = "hegemon.smallwood.deployed-certificate.v1"
TRUST_ROOT_SCHEMA = "hegemon.smallwood.deployed-trust-root.v1"
RECEIPT_SCHEMA = "hegemon.smallwood.deployed-evidence-receipt.v1"
REPORT_SCHEMA = "hegemon.smallwood.deployed-evaluation-report.v2"
PROFILE_ID = "hegemon.smallwood.v4.gamma.level5.sha512.v1"

GOLDILOCKS_ORDER = 0xFFFF_FFFF_0000_0001
TRANSCRIPT_HASH_BITS = 512
MIN_COMMITMENT_DIGEST_BITS = 384
LOW_QUERY_EXPONENT = 64
LOW_TARGET_BITS = 128
HIGH_QUERY_EXPONENT = 128
HIGH_SUCCESS_LIMIT = Fraction(1, 2)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class GateInputError(ValueError):
    """The profile, certificate, or evidence input is malformed."""


def _fail(message: str) -> NoReturn:
    raise GateInputError(message)


def _policy(
    claim: str,
    capabilities: tuple[str, ...],
    quantitative_claims: tuple[str, ...] = (),
    kinds: tuple[str, ...] = ("formal-proof",),
) -> dict[str, object]:
    return {
        "claim": claim,
        "kinds": kinds,
        "capabilities": capabilities,
        "quantitative_claims": quantitative_claims,
    }


# Every capability is tied to a concrete receipt.  In particular, a measured
# interactive error is not allowed to stand in for a simulator, extractor,
# compiled-verifier refinement, or deployed hash reduction.
EVIDENCE_POLICY: dict[str, dict[str, object]] = {
    "proof_system_implemented": _policy(
        "the exact V4/Gamma SmallWood prover and verifier are implemented",
        ("complete_zk", "pq128"),
        kinds=("implementation-refinement", "formal-proof"),
    ),
    "active_parameter_geometry": _policy(
        "the deployed relation and LVCS/DECS geometry are source-bound",
        ("pq128",),
        kinds=("measurement-certificate", "implementation-refinement"),
    ),
    "interactive_soundness_theorem": _policy(
        "the four exact SmallWood interactive error terms are proved for V4/Gamma",
        ("pq128",),
        kinds=("formal-proof", "quantitative-proof"),
    ),
    "protocol_transcript_inventory": _policy(
        "every deployed prover message, challenge, hash request, and abort is inventoried",
        ("complete_zk", "pq128"),
    ),
    "decs_domain_and_leaf_hiding": _policy(
        "the deployed DECS domain and Merkle leaves satisfy the hiding theorem",
        ("complete_zk", "pq128"),
    ),
    "compiled_prover_distribution_refinement": _policy(
        "compiled prover randomness, rejection events, and serialized bytes refine the modeled distribution",
        ("complete_zk",),
    ),
    "whole_proof_simulator": _policy(
        "one simulator covers the complete serialized verifier view",
        ("complete_zk",),
    ),
    "abort_conditioned_simulator": _policy(
        "canonical nonce selection and fixed DECS sampling aborts are simulated",
        ("complete_zk",),
    ),
    "qrom_zk_reduction": _policy(
        "the complete interactive simulator lifts through the deployed QROM Fiat-Shamir transform",
        ("complete_zk",),
    ),
    "zk_quantitative_bound": _policy(
        "the complete-view ZK distinguishing advantage meets both query gates",
        ("complete_zk",),
        ("zk_advantage_at_2pow64", "zk_advantage_at_2pow128"),
    ),
    "proof_of_knowledge_extractor": _policy(
        "the noninteractive extractor returns a witness for every accepted deployed proof",
        ("pq128",),
        ("extraction_loss_at_2pow64", "extraction_loss_at_2pow128"),
    ),
    "pcs_binding_extraction": _policy(
        "LVCS, DECS, and Merkle openings bind one extractable committed oracle",
        ("pq128",),
        ("commitment_binding_loss_at_2pow64", "commitment_binding_loss_at_2pow128"),
    ),
    "compiled_verifier_refinement": _policy(
        "every accepted Rust proof constructs the exact modeled verifier evidence",
        ("pq128",),
        kinds=("implementation-refinement", "formal-proof"),
    ),
    "sha512_qrom_instantiation": _policy(
        "the deployed SHA-512 transcript reduces to the ideal logical oracle with a quantified loss",
        ("pq128",),
        ("sha512_instantiation_loss_at_2pow64", "sha512_instantiation_loss_at_2pow128"),
        kinds=("quantitative-proof",),
    ),
    "global_multi_target_composition": _policy(
        "one global budget covers adaptive blocks, prior proofs, and all transcript queries",
        ("pq128",),
        ("multi_target_loss_at_2pow64", "multi_target_loss_at_2pow128"),
        kinds=("quantitative-proof",),
    ),
    "canonical_relation_refinement": _policy(
        "the exact V4 relation refines canonical Hegemon transaction semantics",
        ("pq128",),
        kinds=("formal-proof", "implementation-refinement"),
    ),
    "relation_hash_security": _policy(
        "Poseidon2 relation commitments have reviewed collision and preimage losses",
        ("pq128",),
        ("relation_hash_loss_at_2pow64", "relation_hash_loss_at_2pow128"),
        kinds=("quantitative-review", "quantitative-proof"),
    ),
    "transcript_hash_security": _policy(
        "SHA-512 transcript and Merkle commitments have reviewed collision and preimage losses",
        ("pq128",),
        ("transcript_hash_loss_at_2pow64", "transcript_hash_loss_at_2pow128"),
        kinds=("quantitative-review", "quantitative-proof"),
    ),
    "wire_and_parser_refinement": _policy(
        "canonical proof bytes exact-decode to the modeled transcript",
        ("complete_zk", "pq128"),
        kinds=("implementation-refinement", "formal-proof"),
    ),
    "end_to_end_same_bytes": _policy(
        "wallet, relay, block, replay, and reorg verify identical self-contained proof bytes",
        ("complete_zk", "pq128"),
        kinds=("end-to-end-test", "implementation-refinement"),
    ),
    "independent_composed_security_review": _policy(
        "an independent review accepts the composed complete-ZK and PQ128 argument",
        ("complete_zk", "pq128"),
        kinds=("independent-review",),
    ),
}

ZK_EVIDENCE = tuple(
    evidence_id
    for evidence_id, policy in EVIDENCE_POLICY.items()
    if "complete_zk" in policy["capabilities"]
)
PQ_EVIDENCE = tuple(
    evidence_id
    for evidence_id, policy in EVIDENCE_POLICY.items()
    if "pq128" in policy["capabilities"]
)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> object:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise GateInputError(f"cannot stat {path}: {exc}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        _fail(f"JSON input must be a non-symlink regular file: {path}")
    if file_stat.st_size > MAX_JSON_BYTES:
        _fail(f"JSON input exceeds {MAX_JSON_BYTES} bytes: {path}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateInputError(f"cannot read valid JSON from {path}: {exc}") from exc


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{path} must be an object")
    return value


def _array(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{path} must be an array")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{path} must be a nonempty string")
    return value


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{path} must be an integer >= {minimum}")
    return value


def _sha256_hex(value: object, path: str) -> str:
    digest = _string(value, path)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        _fail(f"{path} must be a lowercase SHA-256 digest")
    return digest


def _safe_regular_file(repo_root: Path, relative: object, *, max_bytes: int) -> Path:
    rel = Path(_string(relative, "artifact path"))
    if rel.is_absolute() or "." in rel.parts or ".." in rel.parts:
        _fail(f"artifact path must be repository-relative without dot segments: {rel}")
    root = repo_root.resolve()
    current = root
    for part in rel.parts:
        current /= part
        if current.is_symlink():
            _fail(f"artifact path traverses a symlink: {rel}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
        file_stat = resolved.stat()
    except (OSError, ValueError) as exc:
        raise GateInputError(f"unsafe or missing artifact {rel}: {exc}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        _fail(f"artifact is not a regular file: {rel}")
    if file_stat.st_size > max_bytes:
        _fail(f"artifact exceeds {max_bytes} bytes: {rel}")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fraction(value: object, path: str) -> Fraction:
    encoded = _object(value, path)
    if set(encoded) != {"numerator", "denominator"}:
        _fail(f"{path} must contain exactly numerator and denominator")
    numerator_text = _string(encoded["numerator"], f"{path}.numerator")
    denominator_text = _string(encoded["denominator"], f"{path}.denominator")
    if not numerator_text.isdecimal() or not denominator_text.isdecimal():
        _fail(f"{path} numerator and denominator must be unsigned decimal strings")
    numerator = int(numerator_text)
    denominator = int(denominator_text)
    if denominator == 0 or numerator > denominator:
        _fail(f"{path} must be a probability in [0,1]")
    return Fraction(numerator, denominator)


def falling_product(value: int, count: int) -> int:
    if value < 0 or count < 0 or count > value:
        raise ValueError("invalid falling-product arguments")
    product = 1
    for offset in range(count):
        product *= value - offset
    return product


def _fraction_report(value: Fraction) -> dict[str, object]:
    if value == 0:
        approximate_bits: float | str = "infinity"
        floor_bits: int | str = "infinity"
    else:
        approximate_bits = math.log2(value.denominator) - math.log2(value.numerator)
        candidate = max(0, value.denominator.bit_length() - value.numerator.bit_length() - 1)
        while value <= Fraction(1, 2 ** (candidate + 1)):
            candidate += 1
        while candidate > 0 and value > Fraction(1, 2**candidate):
            candidate -= 1
        floor_bits = candidate
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "security_bits_floor": floor_bits,
        "security_bits_approx": approximate_bits,
    }


EXPECTED_IDENTITY = {
    "circuit_version": 4,
    "crypto_suite": 3,
    "backend": "SmallwoodCandidate",
    "backend_wire_id": 2,
    "arithmetization": "DirectPacked64CompressedLevel5",
    "proof_wire_magic": "SMW2",
    "transcript_domain": "hegemon.sha512-level5-field-xof.v1",
}
EXPECTED_PARAMETERS = {
    "rho": 5,
    "piop_openings": 5,
    "beta": 2,
    "opening_pow_bits": 0,
    "decs_domain_size": 1_048_576,
    "decs_openings": 23,
    "decs_eta": 5,
    "decs_pow_bits": 0,
    "packing_factor": 64,
    "piop_nonce_trials": 16,
    "decs_candidate_count": 50,
    "canonical_first_valid_piop_nonce": True,
    "fixed_first_distinct_decs_sampler": True,
}
EXPECTED_GEOMETRY = {
    "public_value_count": 78,
    "raw_witness_len": 241,
    "row_count": 699,
    "constraint_count": 890,
    "effective_constraint_degree": 8,
    "witness_polynomial_degree": 68,
    "consistency_discrepancy_degree": 544,
    "pcs_polynomial_count": 709,
    "lvcs_row_count": 138,
    "lvcs_column_count": 375,
    "base_game_arity_upper_bound": 1_048_576,
}


def _profile_failures(
    profile: dict[str, object],
) -> tuple[list[str], dict[str, int] | None, list[str]]:
    failures: list[str] = []
    zk_blockers: list[str] = []
    if profile.get("schema") != PROFILE_SCHEMA:
        failures.append(f"profile.schema must equal {PROFILE_SCHEMA}")
    if profile.get("profile_id") != PROFILE_ID:
        failures.append(f"profile.profile_id must equal {PROFILE_ID}")

    deployment = _object(profile.get("deployment"), "profile.deployment")
    for name, expected in EXPECTED_IDENTITY.items():
        if deployment.get(name) != expected:
            failures.append(f"deployment.{name} must equal {expected!r}")
    if deployment.get("production_active") is not False:
        failures.append("deployment.production_active must remain false for the retained profile")

    protocol = _object(profile.get("protocol"), "profile.protocol")
    if protocol.get("proof_system") != "SmallWood-LPPC-PACS-PIOP-LVCS-DECS":
        failures.append("proof system identity is not the deployed SmallWood core")
    field = _object(protocol.get("challenge_field"), "profile.protocol.challenge_field")
    if field.get("name") != "Goldilocks" or field.get("order") != str(GOLDILOCKS_ORDER):
        failures.append("all algebraic challenges must use the exact Goldilocks field")

    hashes = _object(profile.get("hash_policy"), "profile.hash_policy")
    if hashes.get("accepted_conventional_algorithms") != ["SHA-512", "SHAKE256"]:
        failures.append("only the pinned SHA-512/SHAKE256 conventional hash family is allowed")
    if hashes.get("minimum_commitment_digest_bits") != MIN_COMMITMENT_DIGEST_BITS:
        failures.append("minimum commitment digest width must be 384 bits")

    transcript = _object(protocol.get("transcript"), "profile.protocol.transcript")
    expected_transcript = {
        "algorithm": "SHA-512",
        "output_bits": TRANSCRIPT_HASH_BITS,
        "counter_mode": "sha512-counter-mode",
        "physical_fiat_shamir_rounds": 4,
    }
    for name, expected in expected_transcript.items():
        if transcript.get(name) != expected:
            failures.append(f"transcript.{name} must equal {expected!r}")

    commitment = _object(profile.get("commitment"), "profile.commitment")
    if commitment.get("algorithm") not in {"SHA-512", "SHAKE256"}:
        failures.append("commitment algorithm must be SHA-512 or SHAKE256")
    commitment_bits = commitment.get("output_bits")
    if isinstance(commitment_bits, bool) or not isinstance(commitment_bits, int):
        failures.append("commitment.output_bits is missing")
    elif commitment_bits < MIN_COMMITMENT_DIGEST_BITS:
        failures.append("commitment digest must be at least 384 bits")
    elif commitment_bits != TRANSCRIPT_HASH_BITS:
        failures.append("deployed SmallWood commitment output must be exactly 512 bits")
    if commitment.get("bytes") != 64 or commitment.get("algorithm") != "SHA-512":
        failures.append("deployed SmallWood commitments must be full 64-byte SHA-512 digests")

    semantic_hash = _object(profile.get("semantic_hash"), "profile.semantic_hash")
    if semantic_hash.get("algorithm") != "Poseidon2" or semantic_hash.get("output_bits") != 384:
        failures.append("deployed V4 semantic relation must remain the six-limb Poseidon2 surface")

    parameters = _object(protocol.get("parameters"), "profile.protocol.parameters")
    for name, expected in EXPECTED_PARAMETERS.items():
        if parameters.get(name) != expected:
            failures.append(f"protocol parameter {name} must equal {expected!r}")
    if parameters.get("decs_evaluation_domain") != "radix2-subgroup-v1":
        failures.append("deployed V4 DECS domain must be the exact radix-2 subgroup")
    if parameters.get("decs_leaf_index_bound") is not False:
        failures.append("the deployed SMW2 leaf grammar must report its missing index binding")
    if parameters.get("independent_decs_leaf_tapes") is not False:
        failures.append("the deployed SMW2 leaf grammar must report its missing independent tapes")

    geometry_object = _object(profile.get("geometry"), "profile.geometry")
    geometry: dict[str, int] = {}
    for name, expected in EXPECTED_GEOMETRY.items():
        value = geometry_object.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            failures.append(f"geometry.{name} is not measured")
        else:
            geometry[name] = value
            if value != expected:
                failures.append(f"geometry.{name} must equal {expected}")

    expected_witness_degree = EXPECTED_PARAMETERS["packing_factor"] + EXPECTED_PARAMETERS["piop_openings"] - 1
    if geometry.get("witness_polynomial_degree") != expected_witness_degree:
        failures.append("witness polynomial degree does not match packing/opening geometry")
    expected_dq = (
        EXPECTED_GEOMETRY["effective_constraint_degree"] * expected_witness_degree
        - EXPECTED_PARAMETERS["packing_factor"]
    )
    if geometry.get("consistency_discrepancy_degree") != expected_dq + EXPECTED_PARAMETERS["packing_factor"]:
        failures.append("consistency discrepancy degree does not match d_Q + packing factor")

    boundary = _object(profile.get("known_zk_boundary"), "profile.known_zk_boundary")
    if boundary.get("domain_disjoint_from_lvcs_points") is not False:
        failures.append("known V4 domain boundary must state that DECS/LVCS domains intersect")
    if boundary.get("leaf_index_and_tape_bound") is not False:
        failures.append("known V4 leaf boundary must state missing index/tape binding")
    if boundary.get("witness_recovery_probability") != {"numerator": "23", "denominator": "1048576"}:
        failures.append("known V4 witness-recovery probability must be 23/2^20")
    if boundary.get("witness_recovery_probability_bits") != "greater-than-2^-16":
        failures.append("known V4 witness-recovery probability boundary drifted")
    if boundary.get("complete_zk_safe") is not False:
        failures.append("the deployed SMW2 profile cannot assert complete-ZK-safe")
    if not failures:
        zk_blockers.extend(
            (
                "retained SMW2 radix-2 DECS domain intersects LVCS interpolation points; "
                "the fixed 23/2^20 witness-recovery event blocks complete ZK",
                "retained SMW2 Merkle leaf hashes omit the leaf index and independent per-leaf tape",
                "no whole-proof simulator covers the serialized PCS/LVCS/DECS/Merkle/abort view",
            )
        )
    return failures, geometry if len(geometry) == len(EXPECTED_GEOMETRY) else None, zk_blockers


def select_parameter_profile(profile_document: object) -> dict[str, object]:
    """Select only the exact deployed SmallWood parameter tuple.

    The selector is intentionally a pure identity/geometry check.  A selected
    profile is not a security authorization: the returned structural blockers
    and the later evidence receipt gate still have to be empty before either
    capability can be derived.
    """
    profile = _object(profile_document, "profile")
    failures, geometry, zk_blockers = _profile_failures(profile)
    return {
        "profile_id": profile.get("profile_id"),
        "selected": not failures,
        "geometry": geometry,
        "profile_failures": failures,
        "zero_knowledge_blockers": zk_blockers,
    }


def _interactive_terms(profile: dict[str, object], geometry: dict[str, int]) -> dict[str, Fraction]:
    protocol = _object(profile["protocol"], "protocol")
    parameters = _object(protocol["parameters"], "parameters")
    rho = _integer(parameters["rho"], "rho", minimum=1)
    eta = _integer(parameters["decs_eta"], "decs_eta", minimum=1)
    piop_openings = _integer(parameters["piop_openings"], "piop_openings", minimum=1)
    packing_factor = _integer(parameters["packing_factor"], "packing_factor", minimum=1)
    decs_domain = _integer(parameters["decs_domain_size"], "decs_domain_size", minimum=1)
    decs_openings = _integer(parameters["decs_openings"], "decs_openings", minimum=1)
    discrepancy = geometry["consistency_discrepancy_degree"]
    piop_domain = GOLDILOCKS_ORDER - packing_factor
    decs_bad_set = geometry["lvcs_column_count"] + decs_openings - 1
    if discrepancy < piop_openings or piop_domain < piop_openings:
        _fail("PIOP geometry cannot support the opening count")
    if decs_bad_set < decs_openings or decs_domain < decs_openings:
        _fail("DECS geometry cannot support the opening count")
    return {
        "epsilon1_decs_uniform_matrix": Fraction(1, GOLDILOCKS_ORDER**eta),
        "epsilon2_piop_constraint_batching": Fraction(1, GOLDILOCKS_ORDER**rho),
        "epsilon3_piop_opening": Fraction(
            falling_product(discrepancy, piop_openings),
            falling_product(piop_domain, piop_openings),
        ),
        "epsilon4_decs_opening": Fraction(
            falling_product(decs_bad_set, decs_openings),
            falling_product(decs_domain, decs_openings),
        ),
    }


def _cms_envelope(interactive_error: Fraction, queries: int, arity: int) -> Fraction:
    return (
        12 * queries**2 * interactive_error
        + Fraction(48 * queries**3, 2**TRANSCRIPT_HASH_BITS)
        + Fraction(2 * arity**2, 2**TRANSCRIPT_HASH_BITS)
    )


def _validate_receipt(
    repo_root: Path,
    evidence_id: str,
    entry: dict[str, object],
    trusted_digests: list[object],
) -> tuple[bool, str | None, dict[str, Fraction]]:
    receipt_path = _safe_regular_file(repo_root, entry.get("receipt_path"), max_bytes=MAX_JSON_BYTES)
    declared = _sha256_hex(entry.get("receipt_sha256"), f"evidence.{evidence_id}.receipt_sha256")
    actual = _sha256_file(receipt_path)
    if actual != declared:
        return False, f"{evidence_id}: receipt digest mismatch", {}
    trusted = {_sha256_hex(value, f"trust_root.{evidence_id}[]") for value in trusted_digests}
    if actual not in trusted:
        return False, f"{evidence_id}: receipt digest is not trust-root pinned", {}
    receipt = _object(load_json_strict(receipt_path), f"receipt {receipt_path}")
    policy = EVIDENCE_POLICY[evidence_id]
    checks = (
        (receipt.get("schema") == RECEIPT_SCHEMA, "wrong receipt schema"),
        (receipt.get("profile_id") == PROFILE_ID, "wrong receipt profile"),
        (receipt.get("evidence_id") == evidence_id, "wrong receipt evidence id"),
        (receipt.get("claim") == policy["claim"], "wrong receipt claim"),
        (receipt.get("kind") in policy["kinds"], "wrong receipt kind"),
        (receipt.get("result") == "pass", "receipt did not pass"),
        (receipt.get("authority_scope") == "deployed-end-to-end", "receipt lacks deployed scope"),
        (receipt.get("assumption_only") is False, "receipt is assumption-only"),
        (receipt.get("machine_checked") is True, "receipt is not machine checked"),
    )
    for passed, reason in checks:
        if not passed:
            return False, f"{evidence_id}: {reason}", {}
    checker = _object(receipt.get("checker"), f"receipt.{evidence_id}.checker")
    _string(checker.get("name"), f"receipt.{evidence_id}.checker.name")
    _string(checker.get("version"), f"receipt.{evidence_id}.checker.version")
    _sha256_hex(checker.get("command_sha256"), f"receipt.{evidence_id}.checker.command_sha256")
    if checker.get("exit_code") != 0:
        return False, f"{evidence_id}: checker exit code is not zero", {}
    artifacts = _array(receipt.get("artifacts"), f"receipt.{evidence_id}.artifacts")
    if not artifacts:
        return False, f"{evidence_id}: receipt has no bound artifacts", {}
    for index, value in enumerate(artifacts):
        artifact = _object(value, f"receipt.{evidence_id}.artifacts[{index}]")
        path = _safe_regular_file(repo_root, artifact.get("path"), max_bytes=MAX_ARTIFACT_BYTES)
        if _sha256_file(path) != _sha256_hex(
            artifact.get("sha256"), f"receipt.{evidence_id}.artifacts[{index}].sha256"
        ):
            return False, f"{evidence_id}: bound artifact digest mismatch", {}
    quantitative = _object(
        receipt.get("quantitative_claims", {}), f"receipt.{evidence_id}.quantitative_claims"
    )
    required = policy["quantitative_claims"]
    if set(quantitative) != set(required):
        return False, f"{evidence_id}: quantitative claim set does not match policy", {}
    return True, None, {
        claim: _fraction(quantitative[claim], f"receipt.{evidence_id}.{claim}")
        for claim in required
    }


def evaluate(
    profile_document: object,
    certificate_document: object,
    trust_root_document: object,
    repo_root: Path,
) -> dict[str, object]:
    profile = _object(profile_document, "profile")
    certificate = _object(certificate_document, "certificate")
    trust_root = _object(trust_root_document, "trust_root")
    if certificate.get("schema") != CERTIFICATE_SCHEMA:
        _fail(f"certificate.schema must equal {CERTIFICATE_SCHEMA}")
    if trust_root.get("schema") != TRUST_ROOT_SCHEMA:
        _fail(f"trust_root.schema must equal {TRUST_ROOT_SCHEMA}")
    if profile.get("profile_id") != PROFILE_ID:
        _fail(f"profile.profile_id must equal {PROFILE_ID}")
    if certificate.get("profile_id") != PROFILE_ID or trust_root.get("profile_id") != PROFILE_ID:
        _fail("certificate and trust-root profile_id must match the deployed profile")
    if set(certificate) != {"schema", "profile_id", "evidence"}:
        _fail("certificate has unknown or missing top-level keys")
    if set(trust_root) != {"schema", "profile_id", "accepted_receipts"}:
        _fail("trust root has unknown or missing top-level keys")
    evidence = _object(certificate.get("evidence"), "certificate.evidence")
    accepted = _object(trust_root.get("accepted_receipts"), "trust_root.accepted_receipts")
    expected_ids = set(EVIDENCE_POLICY)
    if set(evidence) != expected_ids or set(accepted) != expected_ids:
        _fail("certificate and trust-root evidence identifiers must exactly match policy")

    blockers: list[str] = []
    verified: dict[str, bool] = {}
    quantitative: dict[str, Fraction] = {}
    for evidence_id in EVIDENCE_POLICY:
        entry = _object(evidence[evidence_id], f"certificate.evidence.{evidence_id}")
        status = entry.get("status")
        if status not in {"missing", "partial", "assumption", "verified"}:
            _fail(f"evidence.{evidence_id}.status is invalid")
        if status != "verified":
            verified[evidence_id] = False
            blockers.append(f"evidence not verified: {evidence_id} ({status})")
            continue
        trusted = _array(accepted[evidence_id], f"trust_root.accepted_receipts.{evidence_id}")
        try:
            passed, reason, claims = _validate_receipt(repo_root, evidence_id, entry, trusted)
        except GateInputError as exc:
            passed, reason, claims = False, f"{evidence_id}: {exc}", {}
        verified[evidence_id] = passed
        if not passed:
            blockers.append(reason or f"evidence rejected: {evidence_id}")
        else:
            quantitative.update(claims)

    selection = select_parameter_profile(profile)
    static_failures = selection["profile_failures"]
    geometry = selection["geometry"]
    zk_blockers = selection["zero_knowledge_blockers"]
    blockers.extend(static_failures)
    blockers.extend(zk_blockers)

    soundness: dict[str, object] = {
        "parameter_bound_status": "unavailable",
        "production_bound_status": "unavailable",
        "interactive_terms": None,
        "interactive_aggregate": None,
        "ideal_cms_at_2pow64": None,
        "ideal_cms_at_2pow128": None,
        "deployment_losses_at_2pow64": None,
        "deployment_losses_at_2pow128": None,
        "composed_at_2pow64": None,
        "composed_at_2pow128": None,
        "conditional_low_advantage_gate_pass": False,
        "conditional_work_factor_gate_pass": False,
        "low_advantage_gate_pass": False,
        "work_factor_gate_pass": False,
    }
    if geometry is not None and not static_failures:
        terms = _interactive_terms(profile, geometry)
        interactive_error = sum(terms.values(), Fraction(0))
        ideal64 = _cms_envelope(interactive_error, 2**LOW_QUERY_EXPONENT, geometry["base_game_arity_upper_bound"])
        ideal128 = _cms_envelope(interactive_error, 2**HIGH_QUERY_EXPONENT, geometry["base_game_arity_upper_bound"])
        quantitative_pairs = (
            "commitment_binding_loss",
            "sha512_instantiation_loss",
            "extraction_loss",
            "multi_target_loss",
            "relation_hash_loss",
            "transcript_hash_loss",
        )
        missing: list[str] = []
        loss64 = Fraction(0)
        loss128 = Fraction(0)
        for claim in quantitative_pairs:
            at64 = f"{claim}_at_2pow64"
            at128 = f"{claim}_at_2pow128"
            if at64 not in quantitative or at128 not in quantitative:
                missing.append(claim)
            else:
                loss64 += quantitative[at64]
                loss128 += quantitative[at128]
        if missing:
            blockers.append(
                "production soundness bound unavailable; missing quantitative losses: "
                + ", ".join(missing)
            )
        total64 = ideal64 + loss64
        total128 = ideal128 + loss128
        conditional_low_pass = ideal64 <= Fraction(1, 2**LOW_TARGET_BITS)
        conditional_work_pass = ideal128 < HIGH_SUCCESS_LIMIT
        low_pass = not missing and total64 <= Fraction(1, 2**LOW_TARGET_BITS)
        work_pass = not missing and total128 < HIGH_SUCCESS_LIMIT
        if not missing and not low_pass:
            blockers.append("composed soundness exceeds 2^-128 at 2^64 quantum queries")
        if not missing and not work_pass:
            blockers.append("composed half-success work factor is below 2^128 quantum queries")
        soundness = {
            "parameter_bound_status": "conditional_model_bound",
            "production_bound_status": "available" if not missing else "unavailable",
            "interactive_terms": {name: _fraction_report(value) for name, value in terms.items()},
            "interactive_aggregate": _fraction_report(interactive_error),
            "ideal_cms_at_2pow64": _fraction_report(ideal64),
            "ideal_cms_at_2pow128": _fraction_report(ideal128),
            "deployment_losses_at_2pow64": _fraction_report(loss64) if not missing else None,
            "deployment_losses_at_2pow128": _fraction_report(loss128) if not missing else None,
            "composed_at_2pow64": _fraction_report(total64) if not missing else None,
            "composed_at_2pow128": _fraction_report(total128) if not missing else None,
            "conditional_low_advantage_gate_pass": conditional_low_pass,
            "conditional_work_factor_gate_pass": conditional_work_pass,
            "low_advantage_gate_pass": low_pass,
            "work_factor_gate_pass": work_pass,
        }

    zk_evidence_pass = all(verified.get(evidence_id, False) for evidence_id in ZK_EVIDENCE)
    zk64 = quantitative.get("zk_advantage_at_2pow64")
    zk128 = quantitative.get("zk_advantage_at_2pow128")
    zk_numeric_pass = (
        zk64 is not None
        and zk128 is not None
        and zk64 <= Fraction(1, 2**LOW_TARGET_BITS)
        and zk128 < HIGH_SUCCESS_LIMIT
    )
    if zk64 is None or zk128 is None:
        blockers.append("complete-view ZK bound unavailable")
    elif not zk_numeric_pass:
        blockers.append("complete-view ZK advantage does not meet both PQ128 gates")
    complete_zk = (
        not static_failures
        and not zk_blockers
        and zk_evidence_pass
        and zk_numeric_pass
    )
    pq_evidence_pass = all(verified.get(evidence_id, False) for evidence_id in PQ_EVIDENCE)
    conditional_parameter_pq128 = (
        soundness["conditional_low_advantage_gate_pass"] is True
        and soundness["conditional_work_factor_gate_pass"] is True
    )
    production_soundness_pq128 = (
        pq_evidence_pass
        and soundness["low_advantage_gate_pass"] is True
        and soundness["work_factor_gate_pass"] is True
    )
    production_authorized = complete_zk and production_soundness_pq128

    return {
        "schema": REPORT_SCHEMA,
        "profile_id": PROFILE_ID,
        "input_valid": True,
        "profile_gate_pass": not static_failures,
        "selector": {
            "selected_backend": "SmallwoodCandidate",
            "selected_arithmetization": "DirectPacked64CompressedLevel5",
            "selected_transcript": "SHA-512 / sha512-counter-mode",
            "commitment_digest_bits": 512,
            "minimum_commitment_digest_bits": MIN_COMMITMENT_DIGEST_BITS,
            "rejected_alternatives": ["M4", "Binius", "unbound successor backend"],
        },
        "capabilities": {
            "conditional_parameter_pq128": conditional_parameter_pq128,
            "production_soundness_pq128": production_soundness_pq128,
            "complete_zk": complete_zk,
            "production_authorized": production_authorized,
        },
        "production_status": {
            "status": "authorized" if production_authorized else "disabled",
            "composed_pq_security_bits": None if not production_authorized else LOW_TARGET_BITS,
            "parameter_bound_is_not_production_authority": True,
        },
        "security_definition": {
            "low_advantage": "advantage <= 2^-128 at a global 2^64 quantum-query budget",
            "work_factor": "success < 1/2 at a global 2^128 quantum-query budget",
        },
        "verified_evidence_count": sum(verified.values()),
        "required_evidence_count": len(EVIDENCE_POLICY),
        "complete_zk_evidence_pass": zk_evidence_pass,
        "pq128_evidence_pass": pq_evidence_pass,
        "soundness": soundness,
        "zero_knowledge": {
            "structural_gate_pass": not zk_blockers and not static_failures,
            "quantitative_bound_available": zk64 is not None and zk128 is not None,
            "at_2pow64": _fraction_report(zk64) if zk64 is not None else None,
            "at_2pow128": _fraction_report(zk128) if zk128 is not None else None,
            "numeric_gate_pass": zk_numeric_pass,
        },
        "attack_record": {
            "smw2_witness_privacy_failure": {
                "status": "reproduced",
                "probability": {"numerator": "23", "denominator": "1048576"},
                "soundness_forgery": False,
                "description": "An opened subgroup leaf can expose one packed witness row.",
            },
            "end_to_end_smallwood_forgery": {
                "status": "none_recorded",
                "work_factor": None,
            },
            "strongest_documented_component_attack": {
                "target": "Poseidon2 384-bit semantic digest collision resistance",
                "algorithm": "generic quantum collision search",
                "quantum_query_exponent": 128.0,
                "classical_query_exponent": 192.0,
                "end_to_end_transaction_forgery": False,
                "source": "docs/crypto/poseidon2_degree_annihilation_report.json",
            },
            "interpretation": (
                "The component collision algorithm is not a SmallWood proof forgery. "
                "No retained artifact turns it into an accepted transaction without a witness."
            ),
        },
        "shortest_concrete_gap": {
            "kind": "missing-formal-constructor",
            "location": "formal/crypto/HegemonCrypto/SecurityAuthority.lean",
            "symbol": "deployedEndToEnd",
            "description": (
                "SecurityAuthority has no constructor that turns arbitrary accepted compiled "
                "SmallWood Rust bytes into modeled verifier evidence, then composes the exact "
                "SHA-512 QROM loss, extractor, and canonical semantic refinement."
            ),
            "required_evidence": [
                "compiled_verifier_refinement",
                "qrom_zk_reduction",
                "proof_of_knowledge_extractor",
                "canonical_relation_refinement",
            ],
        },
        "blocking_reasons": sorted(set(blockers)),
        "claim_ceiling": (
            "deployed complete-ZK and composed PQ128"
            if production_authorized
            else "exact retained SmallWood parameter/error screen only; no security authority"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--trust-root", type=Path, required=True)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
        help="repository root used for evidence artifact paths",
    )
    args = parser.parse_args()
    try:
        report = evaluate(
            load_json_strict(args.profile),
            load_json_strict(args.certificate),
            load_json_strict(args.trust_root),
            args.repo_root,
        )
    except GateInputError as exc:
        print(
            json.dumps(
                {
                    "schema": REPORT_SCHEMA,
                    "input_valid": False,
                    "capabilities": {
                        "conditional_parameter_pq128": False,
                        "production_soundness_pq128": False,
                        "complete_zk": False,
                        "production_authorized": False,
                    },
                    "blocking_reasons": [str(exc)],
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(1) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["capabilities"]["production_authorized"] else 2)


if __name__ == "__main__":
    main()
