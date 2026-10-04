#!/usr/bin/env python3
"""Fail-closed complete-ZK and post-quantum gate for Hegemon SmallWood.

The checker derives capabilities.  It never reads a ``complete_zk``, ``pq128``,
or ``production_authorized`` assertion from candidate-controlled input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any, NoReturn


PROFILE_SCHEMA = "hegemon.smallwood.strict-profile.v1"
CERTIFICATE_SCHEMA = "hegemon.smallwood.strict-certificate.v1"
TRUST_ROOT_SCHEMA = "hegemon.smallwood.security-trust-root.v1"
RECEIPT_SCHEMA = "hegemon.smallwood.security-evidence-receipt.v1"
TARGET_PROFILE_ID = "hegemon.smallwood.v6.shake256-448.sha512.complete-zk.v1"

GOLDILOCKS_ORDER = 0xFFFF_FFFF_0000_0001
LOW_ADVANTAGE_QUERY_EXPONENT = 64
LOW_ADVANTAGE_TARGET_BITS = 128
WORK_FACTOR_QUERY_EXPONENT = 128
WORK_FACTOR_MAX_SUCCESS = Fraction(1, 2)
TARGET_RELATION_HASH_BITS = 448
MIN_TRANSCRIPT_HASH_BITS = 512
LOW_QUERY_EXPONENT = 64
WORK_QUERY_EXPONENT = 128
TRANSCRIPT_WORST_CASE_SHA512_CALLS = 11_574
RELATION_HASH_TARGET_COUNT = 79
RELATION_HASH_COLLISION_FACTOR = 4
TRANSCRIPT_HASH_COLLISION_FACTOR = 4
CMS_FIAT_SHAMIR_FACTOR = 12
CMS_TRANSCRIPT_COLLISION_FACTOR = 48
CMS_ORACLE_BRIDGE_FACTOR = 2
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_ARTIFACT_BYTES = 64 * 1024 * 1024


class GateInputError(ValueError):
    """The gate input is malformed or unsafe."""


def _fail(message: str) -> NoReturn:
    raise GateInputError(message)


def _receipt_policy(
    claim: str,
    kinds: tuple[str, ...],
    capabilities: tuple[str, ...],
    quantitative_claims: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "claim": claim,
        "kinds": kinds,
        "capabilities": capabilities,
        "quantitative_claims": quantitative_claims,
    }


EVIDENCE_POLICY: dict[str, dict[str, object]] = {
    "proof_system_implemented": _receipt_policy(
        "exact conventional-hash SmallWood prover and verifier are implemented",
        ("implementation-refinement",),
        ("pq128", "complete_zk"),
    ),
    "compiled_prover_distribution_refinement": _receipt_policy(
        "the compiled prover randomness, messages, aborts, and serialized bytes refine the modeled ZK distribution",
        ("implementation-refinement", "formal-proof"),
        ("complete_zk",),
    ),
    "protocol_transcript_inventory": _receipt_policy(
        "every prover message, verifier challenge, hash request, and abort is inventoried",
        ("formal-proof",),
        ("complete_zk", "pq128"),
    ),
    "witness_polynomial_simulator": _receipt_policy(
        "the five-opening witness-polynomial view is simulatable",
        ("formal-proof",),
        ("complete_zk",),
    ),
    "piop_mask_simulator": _receipt_policy(
        "nonlinear and zero-sum linear PIOP masks have a proved simulator",
        ("formal-proof",),
        ("complete_zk",),
    ),
    "decs_domain_and_leaf_hiding": _receipt_policy(
        "the profile-bound DECS domain is disjoint from every LVCS interpolation point and every leaf binds its index and an independent random tape",
        ("formal-proof",),
        ("complete_zk", "pq128"),
    ),
    "joint_pcs_lvcs_decs_merkle_simulator": _receipt_policy(
        "the correlated PCS, LVCS, DECS, opened-row, and Merkle view has one simulator",
        ("formal-proof",),
        ("complete_zk",),
    ),
    "abort_conditioned_simulator": _receipt_policy(
        "canonical PIOP nonce and fixed DECS sampler aborts are simulated",
        ("formal-proof",),
        ("complete_zk",),
    ),
    "qrom_zk_reduction": _receipt_policy(
        "the complete interactive simulator survives noninteractive QROM Fiat-Shamir",
        ("formal-proof", "quantitative-proof"),
        ("complete_zk",),
    ),
    "qrom_zk_independent_review": _receipt_policy(
        "an independent review accepts the complete QROM zero-knowledge reduction",
        ("independent-review",),
        ("complete_zk",),
    ),
    "rng_refinement": _receipt_policy(
        "all prover masks and salts use the production OS RNG with no reuse",
        ("implementation-refinement",),
        ("complete_zk",),
    ),
    "zk_quantitative_bound": _receipt_policy(
        "the complete-view distinguishing advantage is quantitatively bounded",
        ("quantitative-proof",),
        ("complete_zk",),
        ("zk_advantage_at_2pow64", "zk_advantage_at_2pow128"),
    ),
    "relation_geometry": _receipt_policy(
        "the exact production relation geometry is source-bound and measured",
        ("measurement-certificate", "implementation-refinement"),
        ("pq128",),
    ),
    "interactive_rbr_extraction": _receipt_policy(
        "round-by-round knowledge extraction targets the exact production relation",
        ("formal-proof",),
        ("pq128",),
    ),
    "pcs_binding_extraction": _receipt_policy(
        "accepted LVCS, DECS, and Merkle openings bind one extractable committed oracle",
        ("formal-proof", "quantitative-proof"),
        ("pq128",),
        (
            "commitment_binding_loss_at_2pow64",
            "commitment_binding_loss_at_2pow128",
        ),
    ),
    "compiled_verifier_refinement": _receipt_policy(
        "every accepted compiled verifier execution constructs the exact modeled evidence",
        ("implementation-refinement", "formal-proof"),
        ("pq128",),
    ),
    "sha512_standard_to_ideal_qrom": _receipt_policy(
        "the deployed SHA-512 standard-QROM game reduces to the ideal logical oracle",
        ("quantitative-proof",),
        ("pq128",),
        (
            "sha512_instantiation_loss_at_2pow64",
            "sha512_instantiation_loss_at_2pow128",
        ),
    ),
    "proof_of_knowledge_extractor": _receipt_policy(
        "the noninteractive extractor returns a valid witness for the exact accepted bytes",
        ("formal-proof", "quantitative-proof"),
        ("pq128",),
        ("extraction_loss_at_2pow64", "extraction_loss_at_2pow128"),
    ),
    "global_multi_target_composition": _receipt_policy(
        "one global budget covers adaptive blocks, prior proofs, and all transcript queries",
        ("quantitative-proof",),
        ("pq128",),
        ("multi_target_loss_at_2pow64", "multi_target_loss_at_2pow128"),
    ),
    "canonical_relation_refinement": _receipt_policy(
        "the exact proof relation refines canonical Hegemon transaction semantics",
        ("formal-proof", "implementation-refinement"),
        ("pq128",),
    ),
    "relation_hash_security": _receipt_policy(
        "relation commitments have reviewed post-quantum collision and preimage bounds",
        ("quantitative-review", "quantitative-proof"),
        ("pq128",),
        ("relation_hash_loss_at_2pow64", "relation_hash_loss_at_2pow128"),
    ),
    "proof_transcript_hash_security": _receipt_policy(
        "proof transcript and Merkle hashing have reviewed collision and preimage bounds",
        ("quantitative-review", "quantitative-proof"),
        ("pq128",),
        ("transcript_hash_loss_at_2pow64", "transcript_hash_loss_at_2pow128"),
    ),
    "wire_and_parser_refinement": _receipt_policy(
        "canonical proof bytes exact-decode and refine the modeled transcript",
        ("implementation-refinement", "formal-proof"),
        ("complete_zk", "pq128"),
    ),
    "end_to_end_same_bytes": _receipt_policy(
        "wallet, relay, block, replay, and reorg verify the identical self-contained bytes",
        ("end-to-end-test", "implementation-refinement"),
        ("complete_zk", "pq128"),
    ),
    "independent_composed_security_review": _receipt_policy(
        "an independent review accepts the complete composed ZK and PQ128 argument",
        ("independent-review",),
        ("complete_zk", "pq128"),
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


def _hex_digest(value: object, path: str) -> str:
    digest = _string(value, path)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        _fail(f"{path} must be a lowercase SHA-256 digest")
    return digest


def _safe_regular_file(repo_root: Path, relative: object, *, max_bytes: int) -> Path:
    rel = Path(_string(relative, "artifact path"))
    if rel.is_absolute() or ".." in rel.parts:
        _fail(f"artifact path must be repository-relative without '..': {rel}")
    root = repo_root.resolve()
    current = root
    for part in rel.parts:
        current = current / part
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
    if denominator == 0:
        _fail(f"{path}.denominator must be nonzero")
    if numerator > denominator:
        _fail(f"{path} must be a probability in [0,1]")
    return Fraction(numerator, denominator)


def falling_product(value: int, count: int) -> int:
    if value < 0 or count < 0 or count > value:
        raise ValueError("invalid falling-product arguments")
    product = 1
    for offset in range(count):
        product *= value - offset
    return product


def _stirling_second_kind(value: int, blocks: int) -> int:
    """Return the exact number of onto partitions of ``value`` items into ``blocks``."""

    if value < 0 or blocks < 0:
        raise ValueError("invalid Stirling-number arguments")
    if value == 0:
        return 1 if blocks == 0 else 0
    if blocks == 0 or blocks > value:
        return 0
    row = [0] * (blocks + 1)
    row[0] = 1
    for item in range(1, value + 1):
        next_row = [0] * (blocks + 1)
        for block in range(1, min(item, blocks) + 1):
            next_row[block] = row[block - 1] + block * row[block]
        row = next_row
    return row[blocks]


def _piop_sampler_exhaustion_probability(
    field_order: int,
    packing_factor: int,
    openings: int,
    nonce_trials: int,
) -> Fraction:
    """Exact upper bound for all canonical first-valid PIOP nonce trials aborting."""

    if field_order <= 0 or packing_factor < 0 or openings < 0 or nonce_trials < 0:
        raise ValueError("invalid PIOP sampler arguments")
    if openings > field_order or packing_factor > field_order:
        raise ValueError("PIOP sampler domain is too small")
    valid = Fraction(
        falling_product(field_order - packing_factor, openings),
        field_order**openings,
    )
    return (1 - valid) ** nonce_trials


def _decs_sampler_exhaustion_probability(
    field_order: int,
    domain_size: int,
    openings: int,
    candidate_count: int,
) -> Fraction:
    """Exact first-distinct DECS sampler exhaustion probability.

    The active field order is congruent to one modulo the DECS domain size.  Each raw
    candidate therefore has one distinguished residue bucket and the first-distinct
    sampler fails exactly when fewer than ``openings`` distinct residues occur in the
    candidate stream.  The count below is the closed finite sum over the number of
    accepted candidates and their distinct residue partitions.
    """

    if field_order <= 0 or domain_size <= 0 or openings < 0 or candidate_count < 0:
        raise ValueError("invalid DECS sampler arguments")
    if field_order % domain_size != 1:
        raise ValueError("DECS sampler requires field_order congruent to one modulo domain_size")
    if openings > domain_size:
        raise ValueError("DECS opening count exceeds DECS domain")
    bucket = (field_order - 1) // domain_size
    bad_raw_streams = 0
    for accepted_count in range(candidate_count + 1):
        # Choose which candidate positions land in the usable residue bucket.
        position_choices = math.comb(candidate_count, accepted_count)
        # A stream with ``distinct`` residues has an ordered residue assignment
        # falling_factorial(N, distinct) and a partition count S(k, distinct).
        bad_index_sequences = sum(
            falling_product(domain_size, distinct) * _stirling_second_kind(accepted_count, distinct)
            for distinct in range(min(openings - 1, accepted_count) + 1)
        )
        bad_raw_streams += position_choices * bucket**accepted_count * bad_index_sequences
    return Fraction(bad_raw_streams, field_order**candidate_count)


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


def _security_accounting_failures(profile: dict[str, object]) -> list[str]:
    """Check the finite-QROM ledger constants bound to the profile.

    These values are deliberately part of the signed/profile-bound input rather than
    hidden in the checker.  A changed request count, union policy, or retry policy must
    invalidate the profile before any capability can be derived.
    """

    failures: list[str] = []
    accounting_value = profile.get("security_accounting")
    if not isinstance(accounting_value, dict):
        return ["security_accounting is missing or is not an object"]
    accounting = accounting_value
    expected: dict[str, object] = {
        "low_query_exponent": LOW_QUERY_EXPONENT,
        "low_target_bits": LOW_ADVANTAGE_TARGET_BITS,
        "work_query_exponent": WORK_QUERY_EXPONENT,
        "relation_hash_targets": RELATION_HASH_TARGET_COUNT,
        "relation_hash_collision_factor": RELATION_HASH_COLLISION_FACTOR,
        "transcript_hash_worst_case_requests": TRANSCRIPT_WORST_CASE_SHA512_CALLS,
        "transcript_hash_collision_factor": TRANSCRIPT_HASH_COLLISION_FACTOR,
        "cms_fiat_shamir_factor": CMS_FIAT_SHAMIR_FACTOR,
        "cms_transcript_collision_factor": CMS_TRANSCRIPT_COLLISION_FACTOR,
        "cms_oracle_bridge_factor": CMS_ORACLE_BRIDGE_FACTOR,
        "global_history_union_multiplier": 1,
        "per_proof_history_union_forbidden": True,
        "opening_pow_bits": 0,
        "decs_pow_bits": 0,
        "piop_nonce_trials": 16,
        "decs_candidate_count": 50,
    }
    expected_keys = set(expected) | {"work_max_success"}
    if set(accounting) != expected_keys:
        missing = sorted(expected_keys - set(accounting))
        extra = sorted(set(accounting) - expected_keys)
        failures.append(
            f"security_accounting keys mismatch; missing={missing} extra={extra}"
        )
    for name, value in expected.items():
        if accounting.get(name) != value:
            failures.append(f"security accounting {name} must equal {value!r}")
    if accounting.get("work_max_success") != {"numerator": "1", "denominator": "2"}:
        failures.append("security accounting work_max_success must equal 1/2")

    protocol = profile.get("protocol")
    if isinstance(protocol, dict):
        parameters = protocol.get("parameters")
        if isinstance(parameters, dict):
            if accounting.get("opening_pow_bits") != parameters.get("opening_pow_bits"):
                failures.append("security accounting opening_pow_bits must match protocol parameters")
            if accounting.get("decs_pow_bits") != parameters.get("decs_pow_bits"):
                failures.append("security accounting decs_pow_bits must match protocol parameters")
            if accounting.get("piop_nonce_trials") != parameters.get("piop_nonce_trials"):
                failures.append("security accounting piop_nonce_trials must match protocol parameters")
            if accounting.get("decs_candidate_count") != parameters.get("decs_candidate_count"):
                failures.append("security accounting decs_candidate_count must match protocol parameters")
    relation_identity = profile.get("transaction_relation")
    if isinstance(relation_identity, dict):
        if accounting.get("relation_hash_targets") != relation_identity.get("semantic_hash_calls"):
            failures.append("security accounting relation_hash_targets must match semantic_hash_calls")
    return failures


def _profile_failures(profile: dict[str, object]) -> tuple[list[str], dict[str, int] | None]:
    failures: list[str] = []
    if profile.get("schema") != PROFILE_SCHEMA:
        failures.append(f"profile.schema must equal {PROFILE_SCHEMA}")
    if profile.get("profile_id") != TARGET_PROFILE_ID:
        failures.append(f"profile.profile_id must equal {TARGET_PROFILE_ID}")
    failures.extend(_security_accounting_failures(profile))

    protocol = _object(profile.get("protocol"), "profile.protocol")
    if protocol.get("proof_system") != "SmallWood-LPPC-PACS-PIOP-LVCS-DECS":
        failures.append("proof system identity is not the reviewed SmallWood core")
    field = _object(protocol.get("challenge_field"), "profile.protocol.challenge_field")
    if field.get("name") != "Goldilocks" or field.get("order") != str(GOLDILOCKS_ORDER):
        failures.append("all algebraic challenges must use the exact Goldilocks field")

    transcript = _object(protocol.get("transcript"), "profile.protocol.transcript")
    if transcript.get("algorithm") != "SHA-512":
        failures.append("the reviewed V6 proof transcript must use SHA-512")
    transcript_bits = transcript.get("output_bits")
    if isinstance(transcript_bits, bool) or not isinstance(transcript_bits, int):
        failures.append("proof transcript output_bits is missing")
    elif transcript_bits != MIN_TRANSCRIPT_HASH_BITS:
        failures.append("the reviewed V6 proof transcript output must be exactly 512 bits")
    if transcript.get("physical_fiat_shamir_rounds") != 4:
        failures.append("SmallWood transcript must bind exactly four physical challenge families")

    relation_hash = _object(profile.get("relation_hash"), "profile.relation_hash")
    if relation_hash.get("algorithm") != "SHAKE256":
        failures.append("the reviewed V6 relation hash must use SHAKE256")
    relation_bits = relation_hash.get("output_bits")
    if isinstance(relation_bits, bool) or not isinstance(relation_bits, int):
        failures.append("relation hash output_bits is missing")
    elif relation_bits != TARGET_RELATION_HASH_BITS:
        failures.append(
            "the reviewed relation hash output must be exactly 448 bits; 384/3 has no PQ128 composition margin"
        )

    identity = _object(profile.get("transaction_relation"), "profile.transaction_relation")
    expected_identity = {
        "circuit_version": 6,
        "crypto_suite": 5,
        "family": 1,
        "action": 8,
        "backend": 2,
        "profile": 2,
        "domain_set": 1,
        "statement_magic": "HGF6ST01",
        "semantic_tag": "HEG-F6V1",
        "envelope_magic": "SWV6",
        "envelope_version": 1,
        "statement_bytes": 893,
        "limb_bytes": 7,
        "public_limb_count": 128,
        "intent_payload_bytes": 725,
        "intent_frame_bytes": 744,
        "semantic_hash_calls": 79,
        "keccak_f1600_permutations": 124,
    }
    for name, expected in expected_identity.items():
        if identity.get(name) != expected:
            failures.append(f"transaction relation identity {name} must equal {expected!r}")

    expected_parameters = {
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
    }
    parameters = _object(protocol.get("parameters"), "profile.protocol.parameters")
    for name, expected in expected_parameters.items():
        if parameters.get(name) != expected:
            failures.append(f"protocol parameter {name} must equal {expected}")
    if parameters.get("canonical_first_valid_piop_nonce") is not True:
        failures.append("PIOP nonce must be the canonical first valid nonce")
    if parameters.get("fixed_first_distinct_decs_sampler") is not True:
        failures.append("DECS sampler must take the fixed first distinct candidates")
    if parameters.get("decs_evaluation_domain") != "radix2-disjoint-coset-v1":
        failures.append("complete-ZK DECS evaluation domain must be the reviewed disjoint coset")
    if parameters.get("decs_leaf_index_bound") is not True:
        failures.append("every DECS leaf hash must bind its canonical leaf index")
    if parameters.get("decs_leaf_tape_bytes") != 64:
        failures.append("every DECS leaf must use an independent 64-byte random tape")
    if parameters.get("independent_decs_leaf_tapes") is not True:
        failures.append("DECS leaf tapes must be sampled independently")

    geometry_object = _object(profile.get("geometry"), "profile.geometry")
    geometry_names = (
        "row_count",
        "constraint_count",
        "effective_constraint_degree",
        "witness_polynomial_degree",
        "consistency_discrepancy_degree",
        "lvcs_column_count",
        "base_game_arity_upper_bound",
    )
    geometry: dict[str, int] = {}
    for name in geometry_names:
        value = geometry_object.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            failures.append(f"production geometry {name} is not measured")
        else:
            geometry[name] = value
    if len(geometry) != len(geometry_names):
        return failures, None

    expected_witness_degree = expected_parameters["packing_factor"] + expected_parameters["piop_openings"] - 1
    if geometry["witness_polynomial_degree"] != expected_witness_degree:
        failures.append(
            f"witness polynomial degree must equal {expected_witness_degree} for the fixed profile"
        )
    expected_discrepancy = geometry["effective_constraint_degree"] * geometry["witness_polynomial_degree"]
    if geometry["consistency_discrepancy_degree"] != expected_discrepancy:
        failures.append(
            "consistency discrepancy degree must equal effective degree times witness degree"
        )
    if geometry["base_game_arity_upper_bound"] < expected_parameters["decs_domain_size"]:
        failures.append("base-game arity cap cannot be smaller than the committed DECS oracle")
    return failures, geometry


def _interactive_terms(profile: dict[str, object], geometry: dict[str, int]) -> dict[str, Fraction]:
    parameters = _object(_object(profile["protocol"], "protocol")["parameters"], "parameters")
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
        _fail("PIOP geometry cannot support the declared without-replacement opening count")
    if decs_bad_set < decs_openings or decs_domain < decs_openings:
        _fail("DECS geometry cannot support the declared opening count")
    return {
        "decs_uniform_matrix": Fraction(1, GOLDILOCKS_ORDER**eta),
        "piop_constraint_batching": Fraction(1, GOLDILOCKS_ORDER**rho),
        "piop_opening": Fraction(
            falling_product(discrepancy, piop_openings),
            falling_product(piop_domain, piop_openings),
        ),
        "decs_opening": Fraction(
            falling_product(decs_bad_set, decs_openings),
            falling_product(decs_domain, decs_openings),
        ),
    }


def _cms_envelope(interactive_error: Fraction, queries: int, base_game_arity: int) -> Fraction:
    return (
        12 * queries**2 * interactive_error
        + Fraction(48 * queries**3, 2**512)
        + Fraction(2 * base_game_arity**2, 2**512)
    )


def _finite_qrom_terms(
    profile: dict[str, object],
    geometry: dict[str, int],
    queries: int,
) -> dict[str, Fraction]:
    """Return every ideal finite-QROM loss in the strict profile ledger.

    The first three terms are the proved CMS envelope already exposed by
    ``SmallWoodBcsQrom``.  The sampler, concrete-hash, and global-union terms are
    retained as separate terms so that a report cannot silently collapse them into
    an informal "negligible" remainder.  Deployment reductions remain receipt-bound
    losses in ``evaluate`` and are never replaced by arithmetic here.
    """

    protocol = _object(profile["protocol"], "protocol")
    parameters = _object(protocol["parameters"], "protocol.parameters")
    transcript = _object(protocol["transcript"], "protocol.transcript")
    relation_hash = _object(profile["relation_hash"], "relation_hash")
    accounting = _object(profile["security_accounting"], "security_accounting")
    transcript_bits = _integer(transcript["output_bits"], "transcript.output_bits", minimum=1)
    relation_bits = _integer(relation_hash["output_bits"], "relation_hash.output_bits", minimum=1)
    relation_targets = _integer(
        accounting["relation_hash_targets"],
        "security_accounting.relation_hash_targets",
        minimum=1,
    )
    transcript_requests = _integer(
        accounting["transcript_hash_worst_case_requests"],
        "security_accounting.transcript_hash_worst_case_requests",
        minimum=1,
    )
    cms_fiat_shamir_factor = _integer(
        accounting["cms_fiat_shamir_factor"],
        "security_accounting.cms_fiat_shamir_factor",
        minimum=1,
    )
    cms_transcript_factor = _integer(
        accounting["cms_transcript_collision_factor"],
        "security_accounting.cms_transcript_collision_factor",
        minimum=1,
    )
    cms_oracle_bridge_factor = _integer(
        accounting["cms_oracle_bridge_factor"],
        "security_accounting.cms_oracle_bridge_factor",
        minimum=1,
    )
    relation_collision_factor = _integer(
        accounting["relation_hash_collision_factor"],
        "security_accounting.relation_hash_collision_factor",
        minimum=1,
    )
    transcript_collision_factor = _integer(
        accounting["transcript_hash_collision_factor"],
        "security_accounting.transcript_hash_collision_factor",
        minimum=1,
    )
    nonce_trials = _integer(
        accounting["piop_nonce_trials"],
        "security_accounting.piop_nonce_trials",
        minimum=0,
    )
    candidate_count = _integer(
        accounting["decs_candidate_count"],
        "security_accounting.decs_candidate_count",
        minimum=0,
    )
    opening_pow_bits = _integer(
        accounting["opening_pow_bits"],
        "security_accounting.opening_pow_bits",
        minimum=0,
    )
    decs_pow_bits = _integer(
        accounting["decs_pow_bits"],
        "security_accounting.decs_pow_bits",
        minimum=0,
    )
    if opening_pow_bits != 0 or decs_pow_bits != 0:
        _fail("strict finite-QROM profile only supports the measured no-grinding sampler")

    terms = _interactive_terms(profile, geometry)
    interactive_error = sum(terms.values(), Fraction(0, 1))
    base_game_arity = geometry["base_game_arity_upper_bound"]
    packing_factor = _integer(parameters["packing_factor"], "packing_factor", minimum=1)
    piop_openings = _integer(parameters["piop_openings"], "piop_openings", minimum=1)
    decs_domain_size = _integer(parameters["decs_domain_size"], "decs_domain_size", minimum=1)
    decs_openings = _integer(parameters["decs_openings"], "decs_openings", minimum=1)
    return {
        # This is exactly 12*q^2*sum(PCS/IOP/DECS knowledge errors).
        "pcs_iop_fiat_shamir_amplification": Fraction(
            cms_fiat_shamir_factor * queries**2
        ) * interactive_error,
        "transcript_hash_collision_instability": Fraction(
            cms_transcript_factor * queries**3,
            2**transcript_bits,
        ),
        "pcs_oracle_database_bridge": Fraction(
            cms_oracle_bridge_factor * base_game_arity**2,
            2**transcript_bits,
        ),
        "canonical_piop_nonce_exhaustion": _piop_sampler_exhaustion_probability(
            GOLDILOCKS_ORDER,
            packing_factor,
            piop_openings,
            nonce_trials,
        ),
        "fixed_decs_sampler_exhaustion": _decs_sampler_exhaustion_probability(
            GOLDILOCKS_ORDER,
            decs_domain_size,
            decs_openings,
            candidate_count,
        ),
        "relation_hash_collision_union": Fraction(
            relation_collision_factor * relation_targets * queries**3,
            2**relation_bits,
        ),
        "transcript_hash_request_union": Fraction(
            transcript_collision_factor * transcript_requests * queries**3,
            2**transcript_bits,
        ),
        # Both proof-of-work knobs are profile-bound to zero.  This explicit zero
        # is the machine-checked no-grinding premise, not an omitted term.
        "grinding": Fraction(0, 1),
        # One global history budget is already represented by ``queries`` in every
        # q-dependent term; no independent per-proof union is permitted.
        "global_history_union": Fraction(0, 1),
    }


def _validate_receipt(
    repo_root: Path,
    profile_id: str,
    evidence_id: str,
    entry: dict[str, object],
    trusted_digests: list[object],
) -> tuple[bool, str | None, dict[str, Fraction]]:
    receipt_path = _safe_regular_file(
        repo_root, entry.get("receipt_path"), max_bytes=MAX_JSON_BYTES
    )
    actual_digest = _sha256_file(receipt_path)
    declared_digest = _hex_digest(entry.get("receipt_sha256"), f"evidence.{evidence_id}.receipt_sha256")
    if actual_digest != declared_digest:
        return False, f"{evidence_id}: receipt digest mismatch", {}
    trusted = {_hex_digest(value, f"trust_root.{evidence_id}[]") for value in trusted_digests}
    if actual_digest not in trusted:
        return False, f"{evidence_id}: receipt digest is not independently trust-root pinned", {}
    receipt = _object(load_json_strict(receipt_path), f"receipt {receipt_path}")
    policy = EVIDENCE_POLICY[evidence_id]
    checks = (
        (receipt.get("schema") == RECEIPT_SCHEMA, "wrong receipt schema"),
        (receipt.get("profile_id") == profile_id, "wrong receipt profile"),
        (receipt.get("evidence_id") == evidence_id, "wrong receipt evidence id"),
        (receipt.get("claim") == policy["claim"], "wrong receipt claim"),
        (receipt.get("kind") in policy["kinds"], "unapproved receipt kind"),
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
    _hex_digest(checker.get("command_sha256"), f"receipt.{evidence_id}.checker.command_sha256")
    if checker.get("exit_code") != 0:
        return False, f"{evidence_id}: checker exit code is not zero", {}

    artifacts = _array(receipt.get("artifacts"), f"receipt.{evidence_id}.artifacts")
    if not artifacts:
        return False, f"{evidence_id}: receipt has no bound artifacts", {}
    for index, artifact_value in enumerate(artifacts):
        artifact = _object(artifact_value, f"receipt.{evidence_id}.artifacts[{index}]")
        artifact_path = _safe_regular_file(
            repo_root, artifact.get("path"), max_bytes=MAX_EVIDENCE_ARTIFACT_BYTES
        )
        expected = _hex_digest(
            artifact.get("sha256"), f"receipt.{evidence_id}.artifacts[{index}].sha256"
        )
        if _sha256_file(artifact_path) != expected:
            return False, f"{evidence_id}: bound artifact digest mismatch", {}

    quantitative = _object(
        receipt.get("quantitative_claims", {}),
        f"receipt.{evidence_id}.quantitative_claims",
    )
    required_claims = policy["quantitative_claims"]
    if set(quantitative) != set(required_claims):
        return False, f"{evidence_id}: quantitative claim set does not match policy", {}
    parsed = {
        claim: _fraction(quantitative[claim], f"receipt.{evidence_id}.{claim}")
        for claim in required_claims
    }
    return True, None, parsed


def evaluate(
    profile_document: object,
    certificate_document: object,
    trust_root_document: object,
    repo_root: Path,
) -> dict[str, object]:
    profile = _object(profile_document, "profile")
    certificate = _object(certificate_document, "certificate")
    trust_root = _object(trust_root_document, "trust_root")
    profile_id = _string(profile.get("profile_id"), "profile.profile_id")
    if certificate.get("schema") != CERTIFICATE_SCHEMA:
        _fail(f"certificate.schema must equal {CERTIFICATE_SCHEMA}")
    if certificate.get("profile_id") != profile_id:
        _fail("certificate profile_id does not match the profile")
    if trust_root.get("schema") != TRUST_ROOT_SCHEMA:
        _fail(f"trust_root.schema must equal {TRUST_ROOT_SCHEMA}")
    if trust_root.get("profile_id") != profile_id:
        _fail("trust-root profile_id does not match the profile")

    evidence = _object(certificate.get("evidence"), "certificate.evidence")
    accepted_receipts = _object(trust_root.get("accepted_receipts"), "trust_root.accepted_receipts")
    expected_ids = set(EVIDENCE_POLICY)
    if set(evidence) != expected_ids:
        missing = sorted(expected_ids - set(evidence))
        extra = sorted(set(evidence) - expected_ids)
        _fail(f"certificate evidence ids mismatch; missing={missing} extra={extra}")
    if set(accepted_receipts) != expected_ids:
        missing = sorted(expected_ids - set(accepted_receipts))
        extra = sorted(set(accepted_receipts) - expected_ids)
        _fail(f"trust-root evidence ids mismatch; missing={missing} extra={extra}")

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
        trusted_values = _array(
            accepted_receipts[evidence_id], f"trust_root.accepted_receipts.{evidence_id}"
        )
        passed, reason, claims = _validate_receipt(
            repo_root, profile_id, evidence_id, entry, trusted_values
        )
        verified[evidence_id] = passed
        if not passed:
            blockers.append(reason or f"evidence rejected: {evidence_id}")
        else:
            quantitative.update(claims)

    static_failures, geometry = _profile_failures(profile)
    blockers.extend(static_failures)

    soundness_report: dict[str, object] = {
        "available": False,
        "low_advantage_gate_pass": False,
        "work_factor_gate_pass": False,
    }
    if geometry is not None and not static_failures:
        terms = _interactive_terms(profile, geometry)
        interactive_error = sum(terms.values(), Fraction(0, 1))
        q64 = 2**LOW_ADVANTAGE_QUERY_EXPONENT
        q128 = 2**WORK_FACTOR_QUERY_EXPONENT
        ideal64 = _cms_envelope(interactive_error, q64, geometry["base_game_arity_upper_bound"])
        ideal128 = _cms_envelope(interactive_error, q128, geometry["base_game_arity_upper_bound"])
        finite_terms64 = _finite_qrom_terms(profile, geometry, q64)
        finite_terms128 = _finite_qrom_terms(profile, geometry, q128)
        ideal_finite64 = sum(finite_terms64.values(), Fraction(0, 1))
        ideal_finite128 = sum(finite_terms128.values(), Fraction(0, 1))
        required_deployment_claims = (
            "commitment_binding_loss",
            "sha512_instantiation_loss",
            "extraction_loss",
            "multi_target_loss",
            "relation_hash_loss",
            "transcript_hash_loss",
        )
        missing_claims: list[str] = []
        deployment64 = Fraction(0, 1)
        deployment128 = Fraction(0, 1)
        for claim in required_deployment_claims:
            at64 = f"{claim}_at_2pow64"
            at128 = f"{claim}_at_2pow128"
            if at64 not in quantitative or at128 not in quantitative:
                missing_claims.append(claim)
            else:
                deployment64 += quantitative[at64]
                deployment128 += quantitative[at128]
        if missing_claims:
            blockers.append(
                "quantitative deployment losses missing: " + ", ".join(missing_claims)
            )
            total64 = ideal_finite64
            total128 = ideal_finite128
        else:
            total64 = ideal_finite64 + deployment64
            total128 = ideal_finite128 + deployment128
        low_pass = not missing_claims and total64 <= Fraction(1, 2**LOW_ADVANTAGE_TARGET_BITS)
        work_pass = not missing_claims and total128 < WORK_FACTOR_MAX_SUCCESS
        if not missing_claims and not low_pass:
            blockers.append("composed soundness exceeds 2^-128 at 2^64 quantum queries")
        if not missing_claims and not work_pass:
            blockers.append("composed half-success work factor is below 2^128 quantum queries")
        soundness_report = {
            "available": not missing_claims,
            "interactive_terms": {name: _fraction_report(value) for name, value in terms.items()},
            "interactive_aggregate": _fraction_report(interactive_error),
            "ideal_cms_at_2pow64": _fraction_report(ideal64),
            "ideal_cms_at_2pow128": _fraction_report(ideal128),
            "finite_qrom_terms_at_2pow64": {
                name: _fraction_report(value) for name, value in finite_terms64.items()
            },
            "finite_qrom_terms_at_2pow128": {
                name: _fraction_report(value) for name, value in finite_terms128.items()
            },
            "ideal_finite_qrom_at_2pow64": _fraction_report(ideal_finite64),
            "ideal_finite_qrom_at_2pow128": _fraction_report(ideal_finite128),
            "deployment_losses_at_2pow64": _fraction_report(deployment64),
            "deployment_losses_at_2pow128": _fraction_report(deployment128),
            "composed_at_2pow64": _fraction_report(total64),
            "composed_at_2pow128": _fraction_report(total128),
            "low_advantage_gate_pass": low_pass,
            "work_factor_gate_pass": work_pass,
        }

    zk_evidence_pass = all(verified.get(evidence_id, False) for evidence_id in ZK_EVIDENCE)
    zk64 = quantitative.get("zk_advantage_at_2pow64")
    zk128 = quantitative.get("zk_advantage_at_2pow128")
    zk_numeric_pass = (
        zk64 is not None
        and zk128 is not None
        and zk64 <= Fraction(1, 2**LOW_ADVANTAGE_TARGET_BITS)
        and zk128 < WORK_FACTOR_MAX_SUCCESS
    )
    if not zk_numeric_pass:
        blockers.append("complete-view ZK advantage does not meet both PQ128 gates")
    complete_zk = zk_evidence_pass and zk_numeric_pass and not static_failures

    pq_evidence_pass = all(verified.get(evidence_id, False) for evidence_id in PQ_EVIDENCE)
    pq128 = (
        complete_zk
        and pq_evidence_pass
        and soundness_report["low_advantage_gate_pass"] is True
        and soundness_report["work_factor_gate_pass"] is True
    )
    production_authorized = complete_zk and pq128

    return {
        "schema": "hegemon.smallwood.strict-evaluation-report.v1",
        "profile_id": profile_id,
        "input_valid": True,
        "capabilities": {
            "complete_zk": complete_zk,
            "pq128": pq128,
            "production_authorized": production_authorized,
        },
        "security_definition": {
            "low_advantage": "advantage <= 2^-128 at a global 2^64 quantum-query budget",
            "work_factor": "success < 1/2 at a global 2^128 quantum-query budget",
        },
        "profile_gate_pass": not static_failures,
        "verified_evidence_count": sum(verified.values()),
        "required_evidence_count": len(EVIDENCE_POLICY),
        "complete_zk_evidence_pass": zk_evidence_pass,
        "pq128_evidence_pass": pq_evidence_pass,
        "soundness": soundness_report,
        "zero_knowledge": {
            "quantitative_bound_available": zk64 is not None and zk128 is not None,
            "at_2pow64": _fraction_report(zk64) if zk64 is not None else None,
            "at_2pow128": _fraction_report(zk128) if zk128 is not None else None,
            "numeric_gate_pass": zk_numeric_pass,
        },
        "blocking_reasons": sorted(set(blockers)),
        "claim_ceiling": (
            "deployed complete-ZK and composed PQ128"
            if production_authorized
            else "parameter/profile audit only; no deployed security authority"
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
        help="repository root used for all evidence paths",
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
        error_report = {
            "schema": "hegemon.smallwood.strict-evaluation-report.v1",
            "input_valid": False,
            "capabilities": {
                "complete_zk": False,
                "pq128": False,
                "production_authorized": False,
            },
            "blocking_reasons": [str(exc)],
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        raise SystemExit(1) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["capabilities"]["production_authorized"] else 2)


if __name__ == "__main__":
    main()
