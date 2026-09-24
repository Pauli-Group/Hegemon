#!/usr/bin/env python3
"""Exact, fail-closed code/profile screen for the CFW26 Section 11 carrier.

This module deliberately does not prove, compile, or benchmark a transaction
proof.  It instantiates the paper's 105 encoded-oracle shape with plain
Reed--Solomon zero-knowledge encodings and the paper's non-succinct base IOPP,
then computes the exact interactive communication and a theorem-faithful
bit-leaf BCS wire projection.  Missing theorem repairs, MCA bounds, QROM
lifting, and a deployed SHAKE reduction keep every production flag false.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import struct
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
SCHEMA = "hegemon.cfw26.code-profile-screen.v1"
PROFILE_STATUS = "DISQUALIFIED_SOURCE_ONLY"

GOLDILOCKS_MODULUS = (1 << 64) - (1 << 32) + 1
EXTENSION_DEGREE = 5
EXTENSION_POLYNOMIAL = "X^5-3"
FIELD_ORDER = GOLDILOCKS_MODULUS**EXTENSION_DEGREE
FIELD_BYTES = 40
FIELD_BITS = 320

ELL = 1 << 25
LOG_ELL = 25
SUMCHECK_ROUNDS = LOG_ELL + 1
INNER_ORACLES = 3 * SUMCHECK_ROUNDS
OUTER_ORACLES = SUMCHECK_ROUNDS
SECTION11_ORACLES = 1 + INNER_ORACLES + OUTER_ORACLES

QUERY_COUNT_MAIN = 512
QUERY_COUNT_MASK = 512
MAIN_RANDOMNESS = QUERY_COUNT_MAIN
MASK_RANDOMNESS = QUERY_COUNT_MASK
MAIN_BLOCK = 1 << 26
MASK_BLOCK = 1 << 10
MAIN_DIMENSION = ELL + MAIN_RANDOMNESS
INNER_EFFECTIVE_MESSAGE = 4
OUTER_EFFECTIVE_MESSAGE = 8
MASK_STORAGE_MESSAGE = 8
MASK_DIMENSION = MASK_STORAGE_MESSAGE + MASK_RANDOMNESS

MAIN_DELTA = Fraction(65_535, 262_144)
MASK_DELTA = Fraction(63, 256)
MAIN_DISTANCE = Fraction(MAIN_BLOCK - MAIN_DIMENSION + 1, MAIN_BLOCK)
MASK_DISTANCE = Fraction(MASK_BLOCK - MASK_DIMENSION + 1, MASK_BLOCK)

CFW_DIRECT_FIELDS = SUMCHECK_ROUNDS * (OUTER_EFFECTIVE_MESSAGE + 1) + 4
BASE_TARGET_FIELDS = 1 + INNER_ORACLES * 2 + OUTER_ORACLES
BASE_ANSWER_FIELDS = MAIN_DIMENSION + (INNER_ORACLES + OUTER_ORACLES) * MASK_DIMENSION
ONE_LAYER_ORACLE_FIELDS = MAIN_BLOCK + (INNER_ORACLES + OUTER_ORACLES) * MASK_BLOCK
TOTAL_INTERACTIVE_FIELDS = (
    ONE_LAYER_ORACLE_FIELDS
    + CFW_DIRECT_FIELDS
    + ONE_LAYER_ORACLE_FIELDS
    + BASE_TARGET_FIELDS
    + BASE_ANSWER_FIELDS
)
TOTAL_INTERACTIVE_BITS = TOTAL_INTERACTIVE_FIELDS * FIELD_BITS
TOTAL_INTERACTIVE_BYTES = TOTAL_INTERACTIVE_BITS // 8

BCS_TARGET_BITS = 128
BCS_LAMBDA = 664
BCS_DIGEST_BYTES = BCS_LAMBDA // 8
BCS_SALT_BYTES = 2 * BCS_DIGEST_BYTES
WIRE_HEADER_BYTES = 176

SOURCE_HASHES = {
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json":
        "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py":
        "62bd836c41fac8691e2ff97414c33d3bb955ae2b5cb833721e811e3e52b43c1793676a98178007fc3727bad825545cd8075d06b44c467d4d54b6a3cdf70226b5",
    ".agent/hardening/cfw26-section11-repair-audit/ARTIFACT_MANIFEST.json":
        "fa6cede381a60323975cb66ae78855ca05d7edfd37492f957e21f70d3662442c88eab0772a718d9f7501e721f2ab8b9c7880763f17abf55c09c04eeaff4d5209",
}


class ProfileError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def exact_fraction(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def ceil_log2(value: int) -> int:
    if value <= 0:
        raise ProfileError("ceil_log2 requires a positive integer")
    return (value - 1).bit_length()


def strict_below_pow2(value: Fraction, bits: int) -> bool:
    return value < Fraction(1, 1 << bits)


def bcs_privacy_term(proof_bits: int, lambda_bits: int) -> Fraction:
    if proof_bits <= 0 or lambda_bits < 8 or lambda_bits % 4:
        raise ProfileError("invalid BCS parameters")
    exponent = lambda_bits // 4 - 2
    if exponent < 0:
        return Fraction(proof_bits * (1 << -exponent), 1)
    return Fraction(proof_bits, 1 << exponent)


def minimum_bcs_lambda_multiple_of_four(proof_bits: int) -> int:
    candidate = 8
    while not strict_below_pow2(bcs_privacy_term(proof_bits, candidate), BCS_TARGET_BITS):
        candidate += 4
    return candidate


def minimum_bcs_lambda_byte_aligned(proof_bits: int) -> int:
    candidate = 8
    while candidate % 8 or not strict_below_pow2(
        bcs_privacy_term(proof_bits, candidate), BCS_TARGET_BITS
    ):
        candidate += 4
    return candidate


def encode_e320(coefficients: Sequence[int]) -> bytes:
    if len(coefficients) != EXTENSION_DEGREE:
        raise ProfileError("E320 needs exactly five coefficients")
    out = bytearray()
    for coefficient in coefficients:
        if not isinstance(coefficient, int) or not 0 <= coefficient < GOLDILOCKS_MODULUS:
            raise ProfileError("noncanonical Goldilocks coefficient")
        out += struct.pack("<Q", coefficient)
    return bytes(out)


def decode_e320(encoded: bytes) -> tuple[int, ...]:
    if len(encoded) != FIELD_BYTES:
        raise ProfileError("E320 encoding must be exactly 40 bytes")
    coefficients = struct.unpack("<5Q", encoded)
    if any(value >= GOLDILOCKS_MODULUS for value in coefficients):
        raise ProfileError("noncanonical Goldilocks coefficient")
    return coefficients


def rs_encode(
    message: Sequence[int], randomness: Sequence[int], domain: Sequence[int], modulus: int
) -> tuple[int, ...]:
    """Encode r || msg as low-to-high polynomial coefficients.

    Random low coefficients give the exact Proposition 3.19 Vandermonde
    simulator for at most ``len(randomness)`` distinct queries.
    """

    if modulus <= 2 or len(set(x % modulus for x in domain)) != len(domain):
        raise ProfileError("RS domain must contain distinct field points")
    coefficients = [int(x) % modulus for x in randomness] + [int(x) % modulus for x in message]
    if len(coefficients) > len(domain):
        raise ProfileError("RS dimension exceeds block length")
    output: list[int] = []
    for point in domain:
        acc = 0
        for coefficient in reversed(coefficients):
            acc = (acc * point + coefficient) % modulus
        output.append(acc)
    return tuple(output)


def verify_linear_combination_queries(
    left: Sequence[int], right: Sequence[int], combined: Sequence[int], gamma: int,
    indices: Iterable[int], modulus: int,
) -> bool:
    if not (len(left) == len(right) == len(combined)):
        return False
    for index in indices:
        if not 0 <= index < len(left):
            return False
        if combined[index] % modulus != (left[index] + gamma * right[index]) % modulus:
            return False
    return True


def toy_simulator_distribution(
    message: Sequence[int], indices: Sequence[int], *, modulus: int = 17,
    domain: Sequence[int] = (1, 2, 3, 4, 5, 6), randomness_length: int = 2,
) -> Counter[tuple[int, ...]]:
    if len(set(indices)) > randomness_length:
        raise ProfileError("toy query set exceeds simulator budget")
    distribution: Counter[tuple[int, ...]] = Counter()
    total = modulus**randomness_length
    for serial in range(total):
        value = serial
        randomness = []
        for _ in range(randomness_length):
            randomness.append(value % modulus)
            value //= modulus
        word = rs_encode(message, randomness, domain, modulus)
        distribution[tuple(word[i] for i in indices)] += 1
    return distribution


def codeword_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = [
        {
            "id": "witness",
            "role": "main",
            "instance": 0,
            "block_length_symbols": MAIN_BLOCK,
            "alphabet": "GoldilocksE5",
            "alphabet_width_field_elements": 1,
            "canonical_symbol_bytes": FIELD_BYTES,
            "raw_codeword_bytes": MAIN_BLOCK * FIELD_BYTES,
            "effective_message_field_elements": ELL,
            "storage_message_field_elements": ELL,
            "randomness_field_elements": MAIN_RANDOMNESS,
            "rs_dimension": MAIN_DIMENSION,
            "rate": exact_fraction(Fraction(MAIN_DIMENSION, MAIN_BLOCK)),
        }
    ]
    instance = 0
    for matrix in ("A", "B", "C"):
        for round_index in range(SUMCHECK_ROUNDS):
            records.append(
                {
                    "id": f"inner.{matrix}.{round_index:02d}",
                    "role": "inner-mask",
                    "instance": instance,
                    "block_length_symbols": MASK_BLOCK,
                    "alphabet": "GoldilocksE5",
                    "alphabet_width_field_elements": 1,
                    "canonical_symbol_bytes": FIELD_BYTES,
                    "raw_codeword_bytes": MASK_BLOCK * FIELD_BYTES,
                    "effective_message_field_elements": INNER_EFFECTIVE_MESSAGE,
                    "storage_message_field_elements": MASK_STORAGE_MESSAGE,
                    "zero_padding_field_elements": MASK_STORAGE_MESSAGE - INNER_EFFECTIVE_MESSAGE,
                    "randomness_field_elements": MASK_RANDOMNESS,
                    "rs_dimension": MASK_DIMENSION,
                    "rate": exact_fraction(Fraction(MASK_DIMENSION, MASK_BLOCK)),
                }
            )
            instance += 1
    for round_index in range(SUMCHECK_ROUNDS):
        records.append(
            {
                "id": f"outer.{round_index:02d}",
                "role": "outer-mask",
                "instance": round_index,
                "block_length_symbols": MASK_BLOCK,
                "alphabet": "GoldilocksE5",
                "alphabet_width_field_elements": 1,
                "canonical_symbol_bytes": FIELD_BYTES,
                "raw_codeword_bytes": MASK_BLOCK * FIELD_BYTES,
                "effective_message_field_elements": OUTER_EFFECTIVE_MESSAGE,
                "storage_message_field_elements": MASK_STORAGE_MESSAGE,
                "zero_padding_field_elements": 0,
                "randomness_field_elements": MASK_RANDOMNESS,
                "rs_dimension": MASK_DIMENSION,
                "rate": exact_fraction(Fraction(MASK_DIMENSION, MASK_BLOCK)),
            }
        )
    return records


def bcs_rounds() -> list[dict[str, Any]]:
    lengths_fields = [ONE_LAYER_ORACLE_FIELDS + 1]
    lengths_fields.extend([OUTER_EFFECTIVE_MESSAGE] * SUMCHECK_ROUNDS)
    lengths_fields.append(OUTER_ORACLES + 3)
    lengths_fields.append(ONE_LAYER_ORACLE_FIELDS + BASE_TARGET_FIELDS)
    lengths_fields.append(BASE_ANSWER_FIELDS)

    query_bits = [(QUERY_COUNT_MAIN + (INNER_ORACLES + OUTER_ORACLES) * QUERY_COUNT_MASK) * FIELD_BITS]
    query_bits.extend([OUTER_EFFECTIVE_MESSAGE * FIELD_BITS] * SUMCHECK_ROUNDS)
    query_bits.append((OUTER_ORACLES + 3) * FIELD_BITS)
    query_bits.append(
        (QUERY_COUNT_MAIN + (INNER_ORACLES + OUTER_ORACLES) * QUERY_COUNT_MASK + BASE_TARGET_FIELDS)
        * FIELD_BITS
    )
    query_bits.append(BASE_ANSWER_FIELDS * FIELD_BITS)

    labels = ["cfw.initial-oracles-and-mu"]
    labels.extend(f"cfw.sumcheck-h.{index:02d}" for index in range(SUMCHECK_ROUNDS))
    labels.extend(("cfw.outer-evaluations-and-v", "base.new-oracles-and-targets", "base.answers"))
    rounds: list[dict[str, Any]] = []
    for index, (label, fields, queries) in enumerate(zip(labels, lengths_fields, query_bits, strict=True)):
        bits = fields * FIELD_BITS
        depth = ceil_log2(bits)
        per_opening = 1 + BCS_SALT_BYTES + depth * BCS_DIGEST_BYTES
        rounds.append(
            {
                "round": index,
                "label": label,
                "field_elements": fields,
                "message_bits": bits,
                "merkle_real_bit_leaves": bits,
                "merkle_padded_bit_leaves": 1 << depth,
                "authentication_path_depth": depth,
                "bit_queries": queries,
                "root_bytes": BCS_DIGEST_BYTES,
                "opened_value_bytes": queries,
                "opened_salt_bytes": queries * BCS_SALT_BYTES,
                "authentication_sibling_digests": queries * depth,
                "authentication_sibling_bytes": queries * depth * BCS_DIGEST_BYTES,
                "canonical_opening_bytes": queries * per_opening,
            }
        )
    return rounds


def field_symbol_projection() -> dict[str, Any]:
    tree_count = 2 * SECTION11_ORACLES
    root_record_bytes = 12 + BCS_DIGEST_BYTES
    roots_bytes = tree_count * root_record_bytes
    main_openings = 2 * QUERY_COUNT_MAIN
    mask_openings = 2 * (INNER_ORACLES + OUTER_ORACLES) * QUERY_COUNT_MASK
    opening_header = 16
    main_opening_bytes = opening_header + FIELD_BYTES + BCS_SALT_BYTES + 26 * BCS_DIGEST_BYTES
    mask_opening_bytes = opening_header + FIELD_BYTES + BCS_SALT_BYTES + 10 * BCS_DIGEST_BYTES
    direct_fields = CFW_DIRECT_FIELDS + BASE_TARGET_FIELDS + BASE_ANSWER_FIELDS
    direct_bytes = direct_fields * FIELD_BYTES + 3 * 12
    total = (
        WIRE_HEADER_BYTES
        + roots_bytes
        + main_openings * main_opening_bytes
        + mask_openings * mask_opening_bytes
        + direct_bytes
    )
    return {
        "status": "NON_THEOREM_FIELD_SYMBOL_BATCHING_SENSITIVITY_ONLY",
        "bcs16_bit_query_theorem_applies": False,
        "tree_count": tree_count,
        "root_record_bytes": root_record_bytes,
        "roots_bytes": roots_bytes,
        "main_openings": main_openings,
        "mask_openings": mask_openings,
        "main_opening_bytes_each": main_opening_bytes,
        "mask_opening_bytes_each": mask_opening_bytes,
        "direct_field_elements": direct_fields,
        "direct_section_bytes": direct_bytes,
        "wire_equation": (
            "176 + 210*(12+83) + 1024*(16+40+166+26*83) + "
            "106496*(16+40+166+10*83) + 3*12 + 33609445*40"
        ),
        "projected_wire_bytes": total,
    }


def build_profile() -> dict[str, Any]:
    records = codeword_records()
    rounds = bcs_rounds()
    privacy = bcs_privacy_term(TOTAL_INTERACTIVE_BITS, BCS_LAMBDA)
    previous = bcs_privacy_term(TOTAL_INTERACTIVE_BITS, BCS_LAMBDA - 4)
    bit_opening_bytes = sum(row["canonical_opening_bytes"] for row in rounds)
    bit_roots_bytes = len(rounds) * BCS_DIGEST_BYTES
    bit_wire_bytes = (
        WIRE_HEADER_BYTES + bit_roots_bytes + BCS_DIGEST_BYTES + bit_opening_bytes
    )
    profile: dict[str, Any] = {
        "schema": SCHEMA,
        "status": PROFILE_STATUS,
        "production_authorized": False,
        "winner": None,
        "proof_bytes": None,
        "field": {
            "name": "GoldilocksE5",
            "base_modulus_decimal": str(GOLDILOCKS_MODULUS),
            "extension_degree": EXTENSION_DEGREE,
            "extension_polynomial": EXTENSION_POLYNOMIAL,
            "order_decimal": str(FIELD_ORDER),
            "order_floor_log2": FIELD_ORDER.bit_length() - 1,
            "characteristic_is_odd": True,
            "canonical_encoding": "five canonical Goldilocks coefficients, little-endian u64, low degree first",
            "canonical_field_element_bytes": FIELD_BYTES,
            "two_adicity": 32,
        },
        "r1cs_carrier": {
            "ell": ELL,
            "n0": ELL,
            "log2_ell": LOG_ELL,
            "total_carrier": 2 * ELL,
            "source_relation_digest_shake256_512": "81f88efeb9d1ae2f9ef8afec5a29f7d42ca5e77c7789beb7a55c9d228b83904c48a1071005853b0d39c9c60ea2218113c81a012142991052471286e381475254",
        },
        "codes": {
            "construction": "plain Reed-Solomon over explicit distinct integer embeddings",
            "evaluation_domains": {
                "main": "L_main={0,...,2^26-1} embedded in GoldilocksE5",
                "mask": "L_mask={0,...,2^10-1} embedded in GoldilocksE5",
                "main_points": MAIN_BLOCK,
                "mask_points": MASK_BLOCK,
                "domain_points_distinct": True,
                "domain_below_field_order": True,
            },
            "coefficient_order": "randomness first in degrees [0,r), then message in degrees [r,r+ell)",
            "main": {
                "message": ELL,
                "randomness": MAIN_RANDOMNESS,
                "dimension": MAIN_DIMENSION,
                "block": MAIN_BLOCK,
                "rate": exact_fraction(Fraction(MAIN_DIMENSION, MAIN_BLOCK)),
                "minimum_distance": exact_fraction(MAIN_DISTANCE),
                "proximity_delta": exact_fraction(MAIN_DELTA),
                "queries": QUERY_COUNT_MAIN,
                "spotcheck_error": exact_fraction((1 - MAIN_DELTA) ** QUERY_COUNT_MAIN),
            },
            "inner": {
                "effective_message": INNER_EFFECTIVE_MESSAGE,
                "storage_message": MASK_STORAGE_MESSAGE,
                "zero_padding": MASK_STORAGE_MESSAGE - INNER_EFFECTIVE_MESSAGE,
                "randomness": MASK_RANDOMNESS,
                "dimension": MASK_DIMENSION,
                "block": MASK_BLOCK,
                "rate": exact_fraction(Fraction(MASK_DIMENSION, MASK_BLOCK)),
                "minimum_distance": exact_fraction(MASK_DISTANCE),
                "proximity_delta": exact_fraction(MASK_DELTA),
                "queries": QUERY_COUNT_MASK,
            },
            "outer": {
                "effective_message": OUTER_EFFECTIVE_MESSAGE,
                "storage_message": MASK_STORAGE_MESSAGE,
                "zero_padding": 0,
                "randomness": MASK_RANDOMNESS,
                "dimension": MASK_DIMENSION,
                "block": MASK_BLOCK,
                "rate": exact_fraction(Fraction(MASK_DIMENSION, MASK_BLOCK)),
                "minimum_distance": exact_fraction(MASK_DISTANCE),
                "proximity_delta": exact_fraction(MASK_DELTA),
                "queries": QUERY_COUNT_MASK,
                "spotcheck_error": exact_fraction((1 - MASK_DELTA) ** QUERY_COUNT_MASK),
            },
            "proposition_3_19_per_oracle_zeta": exact_fraction(Fraction(0, 1)),
            "cfw_hvzk_union_coefficient": SECTION11_ORACLES,
            "cfw_hvzk_ideal_interactive_error": exact_fraction(Fraction(0, 1)),
        },
        "section11_oracles": {
            "count": len(records),
            "inner_count": INNER_ORACLES,
            "outer_count": OUTER_ORACLES,
            "witness_count": 1,
            "records": records,
            "raw_field_elements": ONE_LAYER_ORACLE_FIELDS,
            "raw_bytes": ONE_LAYER_ORACLE_FIELDS * FIELD_BYTES,
        },
        "base_iopp": {
            "construction": "CFW26 Construction 7.2 non-succinct base IOPP",
            "mask_oracles_n": INNER_ORACLES + OUTER_ORACLES,
            "additional_encoded_oracles": SECTION11_ORACLES,
            "additional_oracle_field_elements": ONE_LAYER_ORACLE_FIELDS,
            "target_field_elements_explicitly_sent_by_construction": BASE_TARGET_FIELDS,
            "theorem_7_1_displayed_communication_omits_target_fields": True,
            "answer_field_elements": BASE_ANSWER_FIELDS,
            "main_symbol_queries_per_original_and_new_tree": QUERY_COUNT_MAIN,
            "mask_symbol_queries_per_original_and_new_tree": QUERY_COUNT_MASK,
            "mca_main_bound": None,
            "mca_mask_interleaving_bound": None,
            "rbr_soundness_complete": False,
        },
        "interactive_proof": {
            "rounds": len(rounds),
            "field_elements": TOTAL_INTERACTIVE_FIELDS,
            "bits_p_of_x": TOTAL_INTERACTIVE_BITS,
            "bytes": TOTAL_INTERACTIVE_BYTES,
            "equation_field_elements": (
                "(m+104*mzk) + 238 + (m+104*mzk) + 183 + "
                "(ell+r+104*(ellzk+rzk))"
            ),
            "equation_values": "67215360+238+67215360+183+33609024=168040165",
            "round_messages": rounds,
        },
        "bcs_classical_privacy": {
            "source_scope": "BCS16 Lemma 3.4 and Lemma 7.5, explicitly programmable classical ROM only",
            "source_expression": "p(x)*2^(-lambda/4+2)",
            "p_bits": TOTAL_INTERACTIVE_BITS,
            "minimum_multiple_of_four_lambda": minimum_bcs_lambda_multiple_of_four(TOTAL_INTERACTIVE_BITS),
            "minimum_byte_aligned_lambda": minimum_bcs_lambda_byte_aligned(TOTAL_INTERACTIVE_BITS),
            "selected_lambda_bits": BCS_LAMBDA,
            "selected_digest_bytes": BCS_DIGEST_BYTES,
            "selected_salt_bits_per_leaf": 2 * BCS_LAMBDA,
            "selected_salt_bytes_per_leaf": BCS_SALT_BYTES,
            "term_at_selected_lambda": exact_fraction(privacy),
            "term_at_selected_lambda_strictly_below_2^-128": strict_below_pow2(privacy, BCS_TARGET_BITS),
            "term_at_lambda_minus_four": exact_fraction(previous),
            "term_at_lambda_minus_four_strictly_below_2^-128": strict_below_pow2(previous, BCS_TARGET_BITS),
            "qrom_theorem": None,
        },
        "bcs_bit_leaf_wire_projection": {
            "status": "EXACT_CANONICAL_PROJECTION_NOT_AN_IMPLEMENTED_PROOF",
            "leaf_value_encoding": "one byte restricted to 0x00 or 0x01",
            "hash": "SHAKE256 with 83-byte output and injective role/length framing",
            "salt_bytes_per_real_leaf": BCS_SALT_BYTES,
            "message_tree_count": len(rounds),
            "root_bytes": bit_roots_bytes,
            "final_sigma_bytes": BCS_DIGEST_BYTES,
            "bit_queries": sum(row["bit_queries"] for row in rounds),
            "authentication_sibling_digests": sum(row["authentication_sibling_digests"] for row in rounds),
            "opened_value_bytes": sum(row["opened_value_bytes"] for row in rounds),
            "opened_salt_bytes": sum(row["opened_salt_bytes"] for row in rounds),
            "authentication_sibling_bytes": sum(row["authentication_sibling_bytes"] for row in rounds),
            "opening_bytes": bit_opening_bytes,
            "header_bytes": WIRE_HEADER_BYTES,
            "wire_equation": "176 + 30*83 + 83 + sum_round q_i*(1 + 166 + depth_i*83)",
            "projected_wire_bytes": bit_wire_bytes,
        },
        "field_symbol_batching_projection": field_symbol_projection(),
        "security": {
            "repaired_factor_two_consistent": True,
            "repaired_st2_is_pow_one": True,
            "typed_row_M_alpha": True,
            "corrected_rbr_numerator_and_premise_used": True,
            "independent_repair_theorem_complete": False,
            "cfw_theorem_inherited": False,
            "mca_terms_complete": False,
            "interactive_complete_hvzk": False,
            "bcs_classical_rom_complete_zk": False,
            "cms_modified_bcs_qrom_transform": None,
            "adv_qro_inst_shake256_664": None,
            "shake256_capacity_and_indifferentiability_qrom_bridge": None,
            "hash_call_grinding_retry_rng_union_terms": None,
            "composed_advantage": None,
            "composed_pq_security_bits": None,
            "strictly_greater_than_128_pq_qrom": False,
        },
        "admission": {
            "source_wire_max_envelope_bytes_diagnostic": 17 * 1024 * 1024,
            "bit_leaf_projection_fits_source_wire_cap": bit_wire_bytes <= 17 * 1024 * 1024,
            "field_symbol_projection_fits_source_wire_cap": field_symbol_projection()["projected_wire_bytes"] <= 17 * 1024 * 1024,
            "measured_retained_proof_artifact": False,
            "proof_bytes": None,
            "disqualified": True,
            "reason": (
                "the exact primary bit-leaf compiler projects to tens of terabytes; even the unproved "
                "field-symbol batching projection exceeds one gigabyte, while CFW repair inheritance, "
                "MCA soundness, QROM Fiat-Shamir, and deployed SHAKE terms remain absent"
            ),
        },
        "source": {
            "cfw26_pdf_sha512": "be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd",
            "cfw26_anchors": ["Definition 3.18", "Proposition 3.19", "Theorem 7.1", "Construction 7.2", "Theorem 11.3", "Construction 11.4"],
            "bcs16_pdf_sha512": "66557007b59ec3ce3657b22b6b4c5047ef60762b2e6b7d0c2baff16ad5d4dfa77b2f3aa5e8f068f8d260ae9919cf862a23ff685ff0c82356d207ebac3c3f6914",
            "bcs16_anchors": ["Lemma 3.4", "Theorem 7.1", "Lemma 7.5"],
            "local_sha512": SOURCE_HASHES,
        },
    }
    profile_digest_material = copy.deepcopy(profile)
    profile["profile_digest_shake256_512"] = hashlib.shake_256(
        canonical_json_bytes(profile_digest_material)
    ).hexdigest(64)
    return profile


def refresh_profile_digest(profile: dict[str, Any]) -> None:
    profile.pop("profile_digest_shake256_512", None)
    profile["profile_digest_shake256_512"] = hashlib.shake_256(
        canonical_json_bytes(profile)
    ).hexdigest(64)


def _fraction(record: dict[str, str]) -> Fraction:
    return Fraction(int(record["numerator"]), int(record["denominator"]))


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema") != SCHEMA or profile.get("status") != PROFILE_STATUS:
        raise ProfileError("schema/status drift")
    if profile.get("production_authorized") or profile.get("winner") is not None:
        raise ProfileError("fail-closed production gate drift")
    if profile.get("proof_bytes") is not None or profile["admission"]["proof_bytes"] is not None:
        raise ProfileError("unmeasured proof bytes must remain null")
    records = profile["section11_oracles"]["records"]
    if len(records) != SECTION11_ORACLES or profile["section11_oracles"]["count"] != SECTION11_ORACLES:
        raise ProfileError("105-oracle count drift")
    if profile["section11_oracles"]["inner_count"] != 78 or profile["section11_oracles"]["outer_count"] != 26:
        raise ProfileError("declared oracle multiplicity drift")
    roles = Counter(record["role"] for record in records)
    if roles != Counter({"main": 1, "inner-mask": 78, "outer-mask": 26}):
        raise ProfileError("oracle role multiplicity drift")
    if records != codeword_records():
        raise ProfileError("codeword table drift")
    for record in records:
        if record["canonical_symbol_bytes"] != FIELD_BYTES:
            raise ProfileError("field encoding width drift")
        if record["rs_dimension"] > record["block_length_symbols"]:
            raise ProfileError("RS dimension exceeds block")
        if record["raw_codeword_bytes"] != record["block_length_symbols"] * FIELD_BYTES:
            raise ProfileError("raw codeword byte drift")
    if profile["codes"]["main"]["queries"] != profile["codes"]["main"]["randomness"]:
        raise ProfileError("main ZK query/randomness mismatch")
    if profile["codes"]["inner"]["queries"] != profile["codes"]["inner"]["randomness"]:
        raise ProfileError("mask ZK query/randomness mismatch")
    if profile["codes"]["inner"]["effective_message"] != 4 or profile["codes"]["outer"]["effective_message"] != 8:
        raise ProfileError("CFW inner/outer message geometry drift")
    if 2 * _fraction(profile["codes"]["main"]["proximity_delta"]) >= _fraction(profile["codes"]["main"]["minimum_distance"]):
        raise ProfileError("main unique-decoding radius drift")
    if 2 * _fraction(profile["codes"]["outer"]["proximity_delta"]) >= _fraction(profile["codes"]["outer"]["minimum_distance"]):
        raise ProfileError("mask unique-decoding radius drift")
    interactive = profile["interactive_proof"]
    if interactive["field_elements"] != TOTAL_INTERACTIVE_FIELDS or interactive["bits_p_of_x"] != TOTAL_INTERACTIVE_BITS:
        raise ProfileError("interactive p(x) drift")
    rounds = interactive["round_messages"]
    if len(rounds) != 30 or sum(row["message_bits"] for row in rounds) != TOTAL_INTERACTIVE_BITS:
        raise ProfileError("BCS round partition drift")
    if rounds != bcs_rounds():
        raise ProfileError("BCS round detail drift")
    bcs = profile["bcs_classical_privacy"]
    if bcs["minimum_byte_aligned_lambda"] != BCS_LAMBDA or bcs["selected_lambda_bits"] != BCS_LAMBDA:
        raise ProfileError("BCS lambda drift")
    if bcs["selected_digest_bytes"] != BCS_DIGEST_BYTES or bcs["selected_salt_bytes_per_leaf"] != BCS_SALT_BYTES:
        raise ProfileError("BCS digest/salt mismatch")
    if _fraction(bcs["term_at_selected_lambda"]) != bcs_privacy_term(TOTAL_INTERACTIVE_BITS, BCS_LAMBDA):
        raise ProfileError("BCS exact term drift")
    if not bcs["term_at_selected_lambda_strictly_below_2^-128"] or bcs["term_at_lambda_minus_four_strictly_below_2^-128"]:
        raise ProfileError("BCS strict boundary drift")
    bit_wire = profile["bcs_bit_leaf_wire_projection"]
    expected_wire = WIRE_HEADER_BYTES + 30 * BCS_DIGEST_BYTES + BCS_DIGEST_BYTES + sum(
        row["canonical_opening_bytes"] for row in rounds
    )
    if bit_wire["projected_wire_bytes"] != expected_wire:
        raise ProfileError("bit-leaf wire equation drift")
    if profile["field_symbol_batching_projection"] != field_symbol_projection():
        raise ProfileError("field-symbol projection drift")
    if profile["base_iopp"]["mca_main_bound"] is not None or profile["base_iopp"]["mca_mask_interleaving_bound"] is not None:
        raise ProfileError("unproved MCA bound must remain null")
    security = profile["security"]
    forbidden_true = (
        "independent_repair_theorem_complete", "cfw_theorem_inherited", "mca_terms_complete",
        "interactive_complete_hvzk", "bcs_classical_rom_complete_zk",
        "strictly_greater_than_128_pq_qrom",
    )
    if any(security[key] for key in forbidden_true):
        raise ProfileError("security overclaim")
    if any(security[key] is not None for key in (
        "cms_modified_bcs_qrom_transform", "adv_qro_inst_shake256_664",
        "shake256_capacity_and_indifferentiability_qrom_bridge",
        "hash_call_grinding_retry_rng_union_terms", "composed_advantage",
        "composed_pq_security_bits",
    )):
        raise ProfileError("missing QROM/security terms must remain null")
    if not profile["admission"]["disqualified"] or profile["admission"]["measured_retained_proof_artifact"]:
        raise ProfileError("admission gate drift")
    if profile["admission"]["bit_leaf_projection_fits_source_wire_cap"] or profile["admission"]["field_symbol_projection_fits_source_wire_cap"]:
        raise ProfileError("oversize projection admitted")
    digest = profile.pop("profile_digest_shake256_512", None)
    try:
        expected = hashlib.shake_256(canonical_json_bytes(profile)).hexdigest(64)
    finally:
        profile["profile_digest_shake256_512"] = digest
    if digest != expected:
        raise ProfileError("profile digest mismatch")


def write_profile(path: Path = HERE / "profile.json") -> None:
    profile = build_profile()
    validate_profile(profile)
    path.write_bytes(canonical_json_bytes(profile))


if __name__ == "__main__":
    write_profile()
    profile = build_profile()
    print(f"section11_oracles={profile['section11_oracles']['count']}")
    print(f"p_bits={profile['interactive_proof']['bits_p_of_x']}")
    print(f"bcs_lambda={profile['bcs_classical_privacy']['minimum_byte_aligned_lambda']}")
    print(f"bit_leaf_projection_bytes={profile['bcs_bit_leaf_wire_projection']['projected_wire_bytes']}")
    print("proof_bytes=null production_authorized=false")
