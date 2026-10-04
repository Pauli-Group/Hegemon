#!/usr/bin/env python3
"""Validate the fail-closed E384 complete-ZK candidate certificate."""

from __future__ import annotations

import argparse
import functools
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CANDIDATE = Path(__file__).with_name("candidate.json")
REQUIRED_FALSE_CAPABILITIES = (
    "complete_zk",
    "strict_pq128",
    "proof_size_measured",
    "frontend_integrated",
    "production_authorized",
)
REQUIRED_SOURCE_TOKENS = (
    "pub trait WholeProofViewSimulator",
    "pub struct RawOpeningModel",
    "mask_rank == combined_rank",
    "pub fn two_b128_dummy_endpoint_counterexample",
    "pub fn endpoint_statistical_bound",
    "pub struct CompleteZkOverheadGeometry",
    "pub struct B128RawOpeningModel",
    "pub struct DiamondConstruction41Geometry",
    "pub fn diamond_construction_4_1_wire_delta",
    "pub const fn current_diamond_construction_4_1_backend_assessment",
    "pub fn maximum_distinct_opened_b128_coordinates",
    "pub struct VanishingCodewordMaskConstruction",
    "pub fn conservative_basefold_opened_coordinates",
    "pub fn plan_conservative_vanishing_mask_basefold",
    "whole_proof_gate_closed: false",
    "RetryOnWitnessPredicate",
    "production_authorized: false",
)
PROVISIONAL_SCREEN_SOURCE = (
    ".agent/hardening/binius-e384-complete-zk/provisional_live_rank.rs"
)
PROVISIONAL_ENCODER_SOURCE = (
    "prototypes/standalone-shake256-binius/strict-mixed-field/src/mixed_basefold_pcs.rs"
)
REQUIRED_ENCODER_TOKENS = (
    "pub const MAX_LOG_DIMENSION: usize = 20;",
    "pub const MAX_LOG_INV_RATE: usize = 6;",
    "pub const MAX_LOG_CODEWORD: usize = 26;",
    "data.push(message[bit_reverse(index & (message.len() - 1), d)]);",
    "let twiddle = gao_mateer_twiddle(&basis, layer, block);",
    "u += v * twiddle;",
    "let mut available = SparsePermutation::identity(pair_count);",
    "selected.push(pair * 2);",
    "selected.push(pair * 2 + 1);",
    "writer.write_base_value(value.coefficients()[0]);",
    "writer.write_tape(&leaf.index_tape);",
)
REQUIRED_SCREEN_TOKENS = (
    "pub fn prove_systematic_zero_leaf_for_supported_geometry",
    "pub const fn initial_joint_pi_omega_wire_exposure",
    "pub fn screen_all_distinct_pair_query_subsets",
    "hegemon_relation_specific_rank=false",
    "complete_zk=false",
    "production_authorized=false",
)

B128_MASK = (1 << 128) - 1
B128_REDUCTION = 0x87
GHASH_TRACE_ONE = 1 << 121


class CandidateError(ValueError):
    """A fail-closed certificate invariant was violated."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_unique_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(), object_pairs_hook=_unique_object)
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read candidate: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError("candidate root must be an object")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError(f"{name} must be an object")
    return value


def _repo_source(path_value: Any, name: str) -> tuple[Path, bytes]:
    if not isinstance(path_value, str):
        raise CandidateError(f"{name} must be a repository-relative string")
    path = (REPO_ROOT / path_value).resolve()
    try:
        path.relative_to(REPO_ROOT.resolve())
    except ValueError as error:
        raise CandidateError(f"{name} escapes repository root") from error
    try:
        return path, path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read {name}: {error}") from error


def _b128_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(128):
        if right & 1:
            result ^= left
        right >>= 1
        carry = left >> 127
        left = (left << 1) & B128_MASK
        if carry:
            left ^= B128_REDUCTION
    return result


def _b128_pow(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _b128_mul(result, value)
        value = _b128_mul(value, value)
        exponent >>= 1
    return result


def _b128_rank(matrix: list[list[int]]) -> int:
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise CandidateError("internal B128 screen matrix is ragged")
    work = [row[:] for row in matrix]
    pivot_row = 0
    for column in range(width):
        pivot = next(
            (row for row in range(pivot_row, len(work)) if work[row][column]),
            None,
        )
        if pivot is None:
            continue
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        inverse = _b128_pow(work[pivot_row][column], B128_MASK - 1)
        work[pivot_row] = [
            _b128_mul(entry, inverse) for entry in work[pivot_row]
        ]
        for row in range(len(work)):
            if row == pivot_row or not work[row][column]:
                continue
            factor = work[row][column]
            work[row] = [
                entry ^ _b128_mul(factor, pivot_entry)
                for entry, pivot_entry in zip(work[row], work[pivot_row])
            ]
        pivot_row += 1
    return pivot_row


def _bit_reverse(value: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


@functools.lru_cache(maxsize=None)
def _gao_mateer_basis(log_domain: int) -> tuple[int, ...]:
    beta = GHASH_TRACE_ONE
    for _ in range(128 - log_domain):
        beta = _b128_mul(beta, beta) ^ beta
    basis = [0] * log_domain
    basis[-1] = beta
    for index in range(log_domain - 1, 0, -1):
        basis[index - 1] = _b128_mul(basis[index], basis[index]) ^ basis[index]
    if basis[0] != 1:
        raise CandidateError("mirrored Gao--Mateer basis does not normalize to one")
    return tuple(basis)


def _gao_mateer_twiddle(basis: tuple[int, ...], layer: int, block: int) -> int:
    value = 0
    for bit in range(layer):
        if (block >> bit) & 1:
            value ^= basis[bit + 1]
    return value


def _encode_b128(message: list[int], log_inv_rate: int) -> list[int]:
    log_dimension = len(message).bit_length() - 1
    log_codeword = log_dimension + log_inv_rate
    basis = _gao_mateer_basis(log_codeword)
    codeword_len = 1 << log_codeword
    data = [
        message[_bit_reverse(index & (len(message) - 1), log_dimension)]
        for index in range(codeword_len)
    ]
    for layer in range(log_inv_rate, log_codeword):
        block_count = 1 << layer
        half = 1 << (log_codeword - layer - 1)
        for block in range(block_count):
            twiddle = _gao_mateer_twiddle(basis, layer, block)
            start = block << (log_codeword - layer)
            for low in range(start, start + half):
                high = low | half
                u = data[low] ^ _b128_mul(data[high], twiddle)
                v = data[high] ^ u
                data[low] = u
                data[high] = v
    return data


@functools.lru_cache(maxsize=None)
def _paired_screen(
    log_dimension: int,
    log_inv_rate: int,
    active_columns: int,
    dummy_start: int,
    dummy_columns: int,
    query_count: int,
) -> dict[str, Any]:
    message_len = 1 << log_dimension
    columns = []
    for column in range(message_len):
        unit = [0] * message_len
        unit[column] = 1
        columns.append(_encode_b128(unit, log_inv_rate))
    generator = [list(row) for row in zip(*columns)]
    pair_count = len(generator) // 2
    schedules = 0
    full_dummy_rank = 0
    leaking = 0
    minimum_rank = dummy_columns
    first_pairs: list[int] | None = None
    first_leaves: list[int] | None = None
    first_left_null: list[int] | None = None
    first_exposed_active: list[int] | None = None
    for pairs in itertools.combinations(range(pair_count), query_count):
        schedules += 1
        leaves = [leaf for pair in pairs for leaf in (2 * pair, 2 * pair + 1)]
        witness_rows = [generator[row][:active_columns] for row in leaves]
        mask_rows = [
            generator[row][dummy_start : dummy_start + dummy_columns]
            for row in leaves
        ]
        mask_rank = _b128_rank(mask_rows)
        combined_rank = _b128_rank(
            [mask + witness for mask, witness in zip(mask_rows, witness_rows)]
        )
        minimum_rank = min(minimum_rank, mask_rank)
        if mask_rank == dummy_columns:
            full_dummy_rank += 1
        if mask_rank != combined_rank:
            leaking += 1
            if first_pairs is None:
                first_pairs = list(pairs)
                first_leaves = leaves
                if all(value == 0 for value in mask_rows[0]) and any(
                    value != 0 for value in witness_rows[0]
                ):
                    first_left_null = [1] + [0] * (len(leaves) - 1)
                    first_exposed_active = witness_rows[0]
    return {
        "message": message_len,
        "codeword": len(generator),
        "active": active_columns,
        "dummy_start": dummy_start,
        "dummy_columns": dummy_columns,
        "queries": query_count,
        "query_pair_population": pair_count,
        "query_schedules": schedules,
        "full_dummy_column_rank_schedules": full_dummy_rank,
        "leaking_schedules": leaking,
        "minimum_mask_rank": minimum_rank,
        "first_leaking_query_pairs": first_pairs,
        "first_leaking_opened_leaves": first_leaves,
        "first_left_null_combination": first_left_null,
        "first_exposed_active_functional": first_exposed_active,
    }


def validate_candidate(candidate_path: Path = DEFAULT_CANDIDATE) -> dict[str, Any]:
    candidate = _load_unique_json(candidate_path)
    if candidate.get("schema") != "hegemon.binius-e384-complete-zk-candidate.v1":
        raise CandidateError("unexpected schema")

    _, source = _repo_source(candidate.get("source"), "source")
    source_digest = hashlib.sha256(source).hexdigest()
    if candidate.get("source_sha256") != source_digest:
        raise CandidateError("source_sha256 mismatch")
    source_text = source.decode("utf-8")
    for token in REQUIRED_SOURCE_TOKENS:
        if token not in source_text:
            raise CandidateError(f"required source token missing: {token}")

    no_go = _mapping(
        candidate.get("provisional_live_encoder_no_go"),
        "provisional_live_encoder_no_go",
    )
    if no_go.get("screen_source") != PROVISIONAL_SCREEN_SOURCE:
        raise CandidateError("unexpected provisional screen source")
    _, screen_source = _repo_source(no_go.get("screen_source"), "screen_source")
    screen_digest = hashlib.sha256(screen_source).hexdigest()
    if no_go.get("screen_source_sha256") != screen_digest:
        raise CandidateError("screen_source_sha256 mismatch")
    screen_text = screen_source.decode("utf-8")
    for token in REQUIRED_SCREEN_TOKENS:
        if token not in screen_text:
            raise CandidateError(f"required screen token missing: {token}")

    if no_go.get("encoder_source") != PROVISIONAL_ENCODER_SOURCE:
        raise CandidateError("unexpected provisional encoder source")
    _, encoder_source = _repo_source(no_go.get("encoder_source"), "encoder_source")
    encoder_digest = hashlib.sha256(encoder_source).hexdigest()
    if no_go.get("encoder_source_sha256") != encoder_digest:
        raise CandidateError("encoder_source_sha256 mismatch")
    encoder_text = encoder_source.decode("utf-8")
    for token in REQUIRED_ENCODER_TOKENS:
        if token not in encoder_text:
            raise CandidateError(f"required encoder token missing: {token}")

    geometry = _mapping(no_go.get("supported_geometry"), "supported_geometry")
    expected_geometry = {
        "log_dimension_min": 1,
        "log_dimension_max": 20,
        "log_inv_rate_min": 1,
        "log_inv_rate_max": 6,
        "max_log_codeword": 26,
        "admitted_pairs": 120,
        "leaf_zero_invariant_all_admitted_pairs": True,
        "proof_method": "bit_reverse(0)=0; only block 0 touches leaf 0; twiddle(layer,0)=0",
    }
    if geometry != expected_geometry:
        raise CandidateError("supported_geometry proof record mismatch")
    admitted = 0
    for log_dimension in range(1, 21):
        for log_inv_rate in range(1, 7):
            if log_dimension + log_inv_rate <= 26:
                admitted += 1
                basis = _gao_mateer_basis(log_dimension + log_inv_rate)
                if _bit_reverse(0, log_dimension) != 0:
                    raise CandidateError("bit_reverse(0) invariant failed")
                for layer in range(log_inv_rate, log_dimension + log_inv_rate):
                    if _gao_mateer_twiddle(basis, layer, 0) != 0:
                        raise CandidateError("block-zero twiddle invariant failed")
    if admitted != 120:
        raise CandidateError("supported geometry enumeration mismatch")

    exact_true_fields = (
        "leaf_zero_equals_message_zero",
        "leaf_zero_appended_dummy_coefficients_all_zero",
        "paired_query_opens_both_siblings",
    )
    for key in exact_true_fields:
        if no_go.get(key) is not True:
            raise CandidateError(f"provisional_live_encoder_no_go.{key} must be true")
    if no_go.get("relation_scope") != (
        "generic valid transparent relation only; exact Hegemon same-statement G_w remains absent"
    ):
        raise CandidateError("relation-specific claim boundary mismatch")
    if no_go.get("conditional_statistical_distance") != "1":
        raise CandidateError("conditional statistical distance must be one")
    if no_go.get("without_replacement_query_population") != "L=2^(d+r-1) pair indices":
        raise CandidateError("without-replacement query population mismatch")
    if no_go.get("leaf_zero_event_probability") != "q/L":
        raise CandidateError("leaf-zero event probability mismatch")
    if no_go.get("whole_view_statistical_distance_lower_bound") != "q/L":
        raise CandidateError("whole-view statistical lower bound mismatch")
    if no_go.get("equivalent_codeword_leaf_probability") != "2q/2^(d+r)":
        raise CandidateError("codeword-leaf probability mismatch")
    if no_go.get("maximum_pair_population_log") != 25:
        raise CandidateError("maximum pair-population log must be 25")
    if no_go.get("statistical_security_upper_bits") != 25:
        raise CandidateError("statistical security upper bits must be 25")

    exposure = _mapping(no_go.get("wire_exposure"), "wire_exposure")
    expected_exposure = {
        "conditional_group_mapping": {"pi": 0, "omega": 1},
        "round": 0,
        "serialized_field_path": "layer_openings[0].opened_leaves[*].values[group].coefficients()[0]",
        "pi_value_bytes": 16,
        "omega_value_bytes": 16,
        "index_tape_bytes": 64,
        "pi_and_omega_serialized_separately": True,
        "affine_combined_before_serialization": False,
        "index_tape_is_algebraic_mask": False,
        "live_m4_group_mapping_refined": False,
    }
    if exposure != expected_exposure:
        raise CandidateError("raw pi/omega wire exposure record mismatch")

    expected_screens = [
        _paired_screen(3, 1, 4, 4, 3, 3),
        _paired_screen(3, 1, 5, 5, 3, 3),
    ]
    if no_go.get("small_geometry_screens") != expected_screens:
        raise CandidateError("paired-query exact screen mismatch")

    diamond = _mapping(
        candidate.get("preferred_complete_zk_repair"),
        "preferred_complete_zk_repair",
    )
    expected_diamond_true = (
        "paper_perfect_iop_zero_knowledge_theorem",
        "fresh_blind_polynomial_commitment",
        "virtual_masked_combination_oracle",
        "interleaved_sumcheck_fri",
    )
    for key in expected_diamond_true:
        if diamond.get(key) is not True:
            raise CandidateError(f"preferred_complete_zk_repair.{key} must be true")
    expected_diamond_false = (
        "current_mixed_b128_e384_backend_matches",
        "large_field_relation_lowering_implemented",
        "setup_ell_plus_one_implemented",
        "kappa_high_coefficients_implemented",
        "fresh_blind_commitment_implemented",
        "virtual_oracle_interleaving_implemented",
        "bcs_salted_opening_grammar_implemented",
        "higher_level_transaction_piop_simulator_implemented",
        "fiat_shamir_qrom_composed",
        "production_geometry_frozen",
        "complete_zk",
        "production_authorized",
    )
    for key in expected_diamond_false:
        if diamond.get(key) is not False:
            raise CandidateError(f"preferred_complete_zk_repair.{key} must remain false")
    expected_diamond_scalars = {
        "construction": "Diamond ePrint 2025/1015 Construction 4.1 Zero-Knowledge Binary BaseFold",
        "primary_source": "https://eprint.iacr.org/2025/1015",
        "primary_source_pdf_sha256": "b6db1430de0cd46cba2719b1d1b23ebdc0f0e14a8e546df767fd011800beaeaf",
        "theorem_scope": "large-field Binary BaseFold IOP; not higher-level transaction PIOP, ring switch, Fiat-Shamir, or QROM composition",
        "setup_log_dimension": "ell+1",
        "setup_code_dimension_multiplier": 2,
        "random_high_coefficients": "kappa=gamma*2^theta",
        "opened_points_per_oracle": "kappa=gamma*2^theta",
        "terminal_clear_field_elements": 2,
        "paper_bcs_leaf_salt_bytes_at_lambda128": 32,
        "hegemon_strict_qrom_leaf_tape_bytes": 64,
        "fixed_schedule_wire_delta": "64 + 2*B + kappa*B + sum_i(MP(d_i+1)-MP(d_i)) + MP(d_0+1) + (T+1)*gamma*S",
    }
    for key, expected in expected_diamond_scalars.items():
        if diamond.get(key) != expected:
            raise CandidateError(f"preferred_complete_zk_repair.{key} mismatch")
    if diamond.get("serializer_measured_total_bytes") is not None:
        raise CandidateError("unimplemented Diamond serializer requires null measured bytes")

    raw = _mapping(candidate.get("raw_opening_gate"), "raw_opening_gate")
    for key in (
        "exact_observation_matrix_exported",
        "mask_span_verified",
        "compiler_bound_witness_delta_rank",
    ):
        if raw.get(key) is not False:
            raise CandidateError(f"raw_opening_gate.{key} must remain false")

    assumptions = _mapping(candidate.get("assumptions"), "assumptions")
    if any(value is not False for value in assumptions.values()):
        raise CandidateError("every unresolved assumption must remain false")

    capabilities = _mapping(candidate.get("capabilities"), "capabilities")
    for key in REQUIRED_FALSE_CAPABILITIES:
        if capabilities.get(key) is not False:
            raise CandidateError(f"capabilities.{key} must remain false")

    overhead = _mapping(candidate.get("overhead"), "overhead")
    if overhead.get("geometry_frozen") is not False or overhead.get("total_bytes") is not None:
        raise CandidateError("unfrozen geometry requires total_bytes=null")
    if overhead.get("widened_endpoint_values") != 3:
        raise CandidateError("exactly three A/B/C endpoint values must be widened")
    if overhead.get("fixed_endpoint_widening_bytes") != 96:
        raise CandidateError("three E384 endpoint widenings must add exactly 96 bytes")

    endpoint = _mapping(candidate.get("endpoint"), "endpoint")
    if endpoint.get("rejected_two_b128_rank") != 2:
        raise CandidateError("two-B128 counterexample rank must be two")
    if endpoint.get("rejected_augmented_rank") != 3:
        raise CandidateError("two-B128 augmented rank must be three")
    if endpoint.get("rejected_exact_statistical_distance") != "1":
        raise CandidateError("two-B128 translation must have distance one")
    if endpoint.get("selected_full_e384_dummy_rows") != 2:
        raise CandidateError("repair requires exactly two full-E384 dummy rows")

    repair = _mapping(candidate.get("masked_codeword_repair"), "masked_codeword_repair")
    if repair.get("selected_implementation_authority") is not False:
        raise CandidateError("ad hoc vanishing mask cannot be selected authority")
    if repair.get("published_complete_zk_theorem") is not False:
        raise CandidateError("ad hoc vanishing mask has no published complete-ZK theorem")
    if repair.get("construction") != (
        "P_masked(X)=P(X)+Z_H(X)*R(X) on a commitment domain disjoint from relation domain H"
    ):
        raise CandidateError("unexpected masked-codeword repair")
    if repair.get("required_b128_mask_coefficients") != (
        "per group m=u0+3*sum(u_l,l>0)+3*t; total independent coefficients=g*m"
    ):
        raise CandidateError("repair mask count must come from the full opening inventory")
    if repair.get("mask_degree_bound") != (
        "deg(R_g)<m for every independently encoded group g"
    ):
        raise CandidateError("repair mask degree bound mismatch")
    if repair.get("initial_distinct_query_matrix") != (
        "diag(Z_H(x_i))*Vandermonde(x_i,0..m)"
    ):
        raise CandidateError("repair initial matrix mismatch")
    if repair.get("initial_raw_opening_rank_sufficient") is not True:
        raise CandidateError("repair initial rank contract must be recorded")
    for key in (
        "whole_proof_simulator_sufficient",
        "relation_kernel_refined_to_live_compiler",
        "commitment_domain_disjointness_enforced",
        "relation_free_tail_refinement_proved",
        "vanishing_polynomial_basis_lowering_refined",
        "exact_live_mixed_depth_view_rank_exported",
        "smallest_live_geometry_derived",
        "spare_degree_fit_established",
        "implemented_in_live_backend",
    ):
        if repair.get(key) is not False:
            raise CandidateError(f"masked_codeword_repair.{key} must remain false")
    if repair.get("required_mask_coefficients_for_live_geometry") is not None:
        raise CandidateError("unfrozen live geometry requires null mask coefficient count")
    if repair.get("live_relation_domain_cardinality") is not None:
        raise CandidateError("unrefined live relation domain requires null cardinality")
    if repair.get("spare_degree_symbols") is not None:
        raise CandidateError("unrefined compiler requires null spare degree")
    if repair.get("full_domain_relation_forces_dimension_growth") is not True:
        raise CandidateError("a full-domain relation must force mask dimension growth")
    if repair.get("conservative_fixed_point_geometry_api_implemented") is not True:
        raise CandidateError("conservative fixed-point geometry API must remain source-bound")
    if repair.get("direct_mask_payload_bytes") != 0:
        raise CandidateError("mask coefficients must not be serialized directly")
    if repair.get("conditional_pcs_wire_delta_if_refined_relation_free_capacity_fits") != 0:
        raise CandidateError("refined unchanged PCS topology must have zero conditional delta")
    if repair.get("live_exact_pcs_wire_delta") is not None:
        raise CandidateError("unrefined live PCS wire delta must remain null")
    if repair.get("dimension_growth_wire_delta") is not None:
        raise CandidateError("unfrozen dimension-growth wire delta must remain null")
    if repair.get("dimension_growth_requires_serializer_schedule_recompute") is not True:
        raise CandidateError("dimension growth must force serializer schedule recomputation")
    impact = _mapping(repair.get("conditional_geometry_impact"), "conditional_geometry_impact")
    expected_impact = {
        "degree": "smallest d_prime with 2^d_prime >= |H| + m(d_prime,r,g,q)",
        "rate": "log_inv_rate r unchanged",
        "queries": "q unchanged",
        "new_fold_layers": "d_prime-d",
        "minimum_new_root_bytes": "64*(d_prime-d)",
        "opened_value_tape_frontier_delta": None,
        "exact_total_wire_delta": None,
    }
    if impact != expected_impact:
        raise CandidateError("conditional BaseFold geometry impact mismatch")

    validation = _mapping(candidate.get("validation"), "validation")
    if validation.get("current_source_digest_direct_rustc_passed") is not False:
        raise CandidateError("current Rust source has not passed the deferred direct-rustc gate")
    if validation.get("current_screen_digest_direct_rustc_passed") is not False:
        raise CandidateError("current Rust screen has not passed the deferred direct-rustc gate")
    if validation.get("disk_gate_gib") != 28:
        raise CandidateError("unexpected disk gate")

    return {
        "candidate_valid": True,
        "source_sha256": source_digest,
        "encoder_source_sha256": encoder_digest,
        "screen_source_sha256": screen_digest,
        "complete_zk": False,
        "production_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    arguments = parser.parse_args()
    try:
        result = validate_candidate(arguments.candidate)
    except (CandidateError, OSError, UnicodeDecodeError) as error:
        print(f"candidate_valid=false\nerror={error}")
        return 1
    for key, value in result.items():
        if isinstance(value, bool):
            value = str(value).lower()
        print(f"{key}={value}")
    # A valid negative certificate is deliberately not an authorization pass.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
