#!/usr/bin/env python3
"""Dependency-free, fail-closed SmallWood/HX512 direct-trace screen."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCREEN_PATH = HERE / "screen.json"

P = 0xFFFF_FFFF_0000_0001
NU = 7
ROUNDS = 12
G_PER_ROUND = 8
COMPRESSIONS = 213
PHYSICAL_CALLS = 90
TERNARY_ADDS_PER_G = 2
BINARY_ADDS_PER_G = 2
ROTATED_XORS_PER_G = 4
FEEDFORWARD_XORS_PER_COMPRESSION = 16
FEEDFORWARD_XOR_STAGES = 2
FEEDFORWARD_XORS_PER_STAGE = 8
CONTROL_XORS_PER_COMPRESSION = 3
FIXED_CONTROL_POSITIONS = 205
PRIVATE_MODE_CONTROL_POSITIONS = 8
SELECTED_CONTROL_WORDS = 16
# The authorization arm has two mode-gated state2/state3 digest-link surfaces.
# The conservative screen materializes one full packed selector batch and one
# full packed broadcast/alias batch so no private-mode digest edge is obtained
# by host-side selection.  At K=1024 these are exactly two rows; the formulas
# below retain the correct padding for every screened K.
MODE_GATED_AUTH_LINK_CELLS = 1_024
SOURCE_BITS = 97_704
MESSAGE_WORD_SLOTS = COMPRESSIONS * 16
MAX_U16 = (1 << 16) - 1
MAX_SCREENED_PACKING = MAX_U16 // 2
FULL_AUTH_PATH_NODES = 23 * 20

PROFILE = {
    "rho": 5,
    "nb_opened_evals": 5,
    "beta": 2,
    "opening_pow_bits": 0,
    "decs_nb_evals": 1 << 20,
    "decs_nb_opened_evals": 23,
    "decs_eta": 5,
    "decs_pow_bits": 0,
}

SOURCE_PATHS = (
    "circuits/transaction/src/smallwood_engine.rs",
    "circuits/transaction/src/smallwood_semantics.rs",
    "circuits/transaction/src/smallwood_frontend.rs",
    "circuits/transaction/src/smallwood_blake2b384.rs",
    ".agent/hardening/hx512-semantic-suite/hx512_suite.py",
    ".agent/hardening/hx512-semantic-suite/suite_report.json",
    ".agent/hardening/hx512-full-relation-compile/verifier_profile.py",
    ".agent/hardening/hx512-full-relation-compile/test_compiler.py",
    ".agent/hardening/aurora-binary-relation-compile/certificate.json",
    ".agent/hardening/ligero-backup-screen/ledger.json",
    ".agent/hardening/strict-odd-field-composition/ledger.json",
    ".agent/hardening/smallwood-hx512-trace-screen/trace_screen.py",
    ".agent/hardening/smallwood-hx512-trace-screen/check_trace_screen.py",
    ".agent/hardening/smallwood-hx512-trace-screen/test_trace_screen.py",
)


class Reject(ValueError):
    """A fail-closed certificate rejection."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise Reject("invalid ceil-div arguments")
    return (numerator + denominator - 1) // denominator


def f(value: int) -> int:
    return value % P


def digit_low(value: int) -> int:
    """Low bit on the radix-4 domain as a degree-three polynomial."""
    return f((2 * value**3 - 9 * value**2 + 10 * value) * pow(3, -1, P))


def digit_high(value: int) -> int:
    """High bit on the radix-4 domain as a degree-three polynomial."""
    return f((-2 * value**3 + 9 * value**2 - 7 * value) * pow(6, -1, P))


def xor_bit(left: int, right: int) -> int:
    return f(left + right - 2 * left * right)


def xor_digit(left: int, right: int) -> int:
    lo = xor_bit(digit_low(left), digit_low(right))
    hi = xor_bit(digit_high(left), digit_high(right))
    return f(lo + 2 * hi)


def digit_membership(value: int) -> int:
    return f(value * (value - 1) * (value - 2) * (value - 3))


def carry3_membership(value: int) -> int:
    return f(value * (value - 1) * (value - 2))


def bit_membership(value: int) -> int:
    return f(value * (value - 1))


def radix4_add_accepts(
    operands: tuple[int, ...], carry_in: int, total_digit: int, carry_out: int
) -> bool:
    equation = f(sum(operands) + carry_in - total_digit - 4 * carry_out)
    return (
        equation == 0
        and digit_membership(total_digit) == 0
        and carry3_membership(carry_out) == 0
    )


def three_xor(left: int, right: int, carry: int) -> int:
    return xor_bit(xor_bit(left, right), carry)


def majority(left: int, right: int, carry: int) -> int:
    return f(left * right + left * carry + right * carry - 2 * left * right * carry)


def bit_add_pair_accepts(
    left: int, right: int, carry_in: int, total_bit: int, carry_out: int
) -> bool:
    """Alternative two-residual Boolean adder aggregation, not the selected design."""
    sum_residual = f(total_bit - three_xor(left, right, carry_in))
    carry_residual = f(carry_out - majority(left, right, carry_in))
    return f(sum_residual * sum_residual - NU * carry_residual * carry_residual) == 0


@lru_cache(maxsize=None)
def xor_table_top_coefficient(chunk_bits: int) -> int:
    """Coefficient of x^(B-1)y^(B-1) in the reduced XOR table polynomial."""
    radix = 1 << chunk_bits
    weights = []
    for value in range(radix):
        denominator = math.factorial(value) * math.factorial(radix - 1 - value)
        if (radix - 1 - value) & 1:
            denominator = -denominator
        weights.append(pow(denominator % P, -1, P))
    return f(
        sum(
            (left ^ right) * weights[left] * weights[right]
            for left in range(radix)
            for right in range(radix)
        )
    )


def exhaustive_arithmetic_receipt() -> dict[str, Any]:
    if pow(NU, (P - 1) // 2, P) != P - 1:
        raise Reject("7 is not a quadratic nonresidue in Goldilocks")

    digit_projection_cases = 0
    for value in range(4):
        if digit_low(value) != (value & 1) or digit_high(value) != ((value >> 1) & 1):
            raise Reject("radix-4 bit interpolation failed")
        digit_projection_cases += 1

    xor_cases = 0
    for left in range(4):
        for right in range(4):
            if xor_digit(left, right) != (left ^ right):
                raise Reject("radix-4 XOR interpolation failed")
            xor_cases += 1

    rotate_cases = 0
    for current in range(4):
        for previous in range(4):
            observed = f(digit_high(previous) + 2 * digit_low(current))
            expected = ((previous >> 1) & 1) | ((current & 1) << 1)
            if observed != expected:
                raise Reject("63-bit rotation digit recomposition failed")
            rotate_cases += 1

    binary_add_cases = 0
    for left in range(4):
        for right in range(4):
            for carry_in in range(3):
                expected_digit = (left + right + carry_in) % 4
                expected_carry = (left + right + carry_in) // 4
                for total_digit in range(4):
                    for carry_out in range(3):
                        expected = total_digit == expected_digit and carry_out == expected_carry
                        observed = radix4_add_accepts(
                            (left, right), carry_in, total_digit, carry_out
                        )
                        if observed != expected:
                            raise Reject("radix-4 binary-add relation is not exact")
                        binary_add_cases += 1

    ternary_add_cases = 0
    for left in range(4):
        for right in range(4):
            for third in range(4):
                for carry_in in range(3):
                    expected_digit = (left + right + third + carry_in) % 4
                    expected_carry = (left + right + third + carry_in) // 4
                    for total_digit in range(4):
                        for carry_out in range(3):
                            expected = total_digit == expected_digit and carry_out == expected_carry
                            observed = radix4_add_accepts(
                                (left, right, third), carry_in, total_digit, carry_out
                            )
                            if observed != expected:
                                raise Reject("radix-4 ternary-add relation is not exact")
                            ternary_add_cases += 1

    bit_add_cases = 0
    for left in range(2):
        for right in range(2):
            for carry_in in range(2):
                expected_sum = left + right + carry_in
                for total_bit in range(2):
                    for carry_out in range(2):
                        expected = total_bit == (expected_sum & 1) and carry_out == (expected_sum >> 1)
                        if bit_add_pair_accepts(
                            left, right, carry_in, total_bit, carry_out
                        ) != expected:
                            raise Reject("anisotropic Boolean full-adder relation is not exact")
                        bit_add_cases += 1

    xor_top_coefficients = {
        str(chunk_bits): str(xor_table_top_coefficient(chunk_bits))
        for chunk_bits in (1, 2, 4, 8)
    }
    if any(int(value) == 0 for value in xor_top_coefficients.values()):
        raise Reject("a screened XOR table degree is not exact")

    return {
        "nonresidue_euler_value": str(P - 1),
        "digit_projection_cases": digit_projection_cases,
        "xor_cases": xor_cases,
        "odd_rotation_cases": rotate_cases,
        "radix4_binary_addition_cases": binary_add_cases,
        "radix4_ternary_addition_cases": ternary_add_cases,
        "bit_full_adder_cases": bit_add_cases,
        "xor_table_top_coefficients": xor_top_coefficients,
        "all_pass": True,
    }


def matrix_bytes(rows: int, cols: int, dimension_bytes: int) -> int:
    if rows < 0 or cols < 0 or (rows == 0) != (cols == 0):
        raise Reject("invalid matrix shape")
    if dimension_bytes == 4 and (rows > MAX_U16 or cols > MAX_U16):
        raise Reject("matrix shape is not encodable by the current u16 wire")
    if dimension_bytes not in (4, 8):
        raise Reject("only u16-pair or hypothetical u32-pair dimensions are screened")
    return dimension_bytes + 8 * rows * cols


def matrix_bytes_u16(rows: int, cols: int) -> int:
    return matrix_bytes(rows, cols, 4)


def proof_geometry(row_count: int, constraint_degree: int, packing: int) -> dict[str, Any]:
    openings = PROFILE["nb_opened_evals"]
    rho = PROFILE["rho"]
    beta = PROFILE["beta"]
    decs_openings = PROFILE["decs_nb_opened_evals"]
    witness_degree = packing + openings - 1
    mpol_degree = constraint_degree * witness_degree - packing
    mlin_degree = witness_degree + packing - 1
    ppol_cols = mpol_degree + 1 - openings
    plin_cols = mlin_degree + 1 - (openings + 1)
    mpol_width = ceil_div(mpol_degree + 1 - openings, packing)
    mlin_width = ceil_div(mlin_degree + 1 - openings, packing)
    nb_polys = row_count + 2 * rho
    nb_unstacked_cols = row_count + rho * mpol_width + rho * mlin_width
    nb_lvcs_rows = (packing + openings) * beta
    nb_lvcs_cols = ceil_div(nb_unstacked_cols, beta)
    nb_lvcs_opened_combi = beta * openings
    partial_cols = nb_unstacked_cols - nb_polys
    matrix_shapes = {
        "ppol_highs": [rho, ppol_cols],
        "plin_highs": [rho, plin_cols],
        "rcombi_tails": [nb_lvcs_opened_combi, decs_openings],
        "subset_evals": [decs_openings, nb_lvcs_rows - nb_lvcs_opened_combi],
        "partial_evals": [openings, partial_cols],
        "masking_evals": [decs_openings, PROFILE["decs_eta"]],
        "high_coeffs": [PROFILE["decs_eta"], nb_lvcs_cols],
        "opened_witness_row_scalars": [openings, nb_polys],
    }
    max_matrix_dimension = max(dimension for shape in matrix_shapes.values() for dimension in shape)
    return {
        "row_count": row_count,
        "packing_factor": packing,
        "constraint_degree": constraint_degree,
        "witness_degree": witness_degree,
        "mpol_degree": mpol_degree,
        "mlin_degree": mlin_degree,
        "ppol_high_columns": ppol_cols,
        "plin_high_columns": plin_cols,
        "mpol_width": mpol_width,
        "mlin_width": mlin_width,
        "nb_polys": nb_polys,
        "nb_unstacked_cols": nb_unstacked_cols,
        "nb_lvcs_rows": nb_lvcs_rows,
        "nb_lvcs_cols": nb_lvcs_cols,
        "nb_lvcs_opened_combi": nb_lvcs_opened_combi,
        "partial_eval_columns": partial_cols,
        "decs_polynomial_length": nb_lvcs_cols + decs_openings,
        "matrix_shapes": matrix_shapes,
        "max_matrix_dimension": max_matrix_dimension,
        "current_u16_matrix_dimensions_fit": max_matrix_dimension <= MAX_U16,
        "decs_domain_length_fits": nb_lvcs_cols + decs_openings <= PROFILE["decs_nb_evals"],
    }


def proof_payload_components(
    row_count: int,
    constraint_degree: int,
    packing: int,
    auth_nodes: int,
    auxiliary_words: int,
    dimension_bytes: int,
) -> dict[str, int]:
    geometry = proof_geometry(row_count, constraint_degree, packing)
    shapes = geometry["matrix_shapes"]
    components = {
        "magic_salt_nonce_sha512_digest": 4 + 32 + 4 + 64,
        "ppol_highs": matrix_bytes(*shapes["ppol_highs"], dimension_bytes),
        "plin_highs": matrix_bytes(*shapes["plin_highs"], dimension_bytes),
        "rcombi_tails": matrix_bytes(*shapes["rcombi_tails"], dimension_bytes),
        "subset_evals": matrix_bytes(*shapes["subset_evals"], dimension_bytes),
        "partial_evals": matrix_bytes(*shapes["partial_evals"], dimension_bytes),
        "auth_paths": 2 + PROFILE["decs_nb_opened_evals"] + 64 * auth_nodes,
        "opened_leaf_tapes": PROFILE["decs_nb_opened_evals"] * 64,
        "masking_evals": matrix_bytes(*shapes["masking_evals"], dimension_bytes),
        "high_coeffs": matrix_bytes(*shapes["high_coeffs"], dimension_bytes),
        "opened_witness": (
            1
            + matrix_bytes(*shapes["opened_witness_row_scalars"], dimension_bytes)
            + 8
            + 8 * auxiliary_words
        ),
    }
    components["total"] = sum(components.values())
    return components


def projected_payload_bytes(
    row_count: int,
    constraint_degree: int,
    auth_nodes: int,
    auxiliary_words: int,
    dimension_bytes: int,
    packing: int,
) -> int:
    return proof_payload_components(
        row_count,
        constraint_degree,
        packing,
        auth_nodes,
        auxiliary_words,
        dimension_bytes,
    )["total"]


def chunk_maximum_degree(chunk_bits: int) -> int:
    if chunk_bits == 1:
        return 3  # ternary carry range; XOR itself is degree two
    return 2 * ((1 << chunk_bits) - 1)


@lru_cache(maxsize=None)
def chunk_layout(chunk_bits: int, packing: int) -> dict[str, Any]:
    if chunk_bits not in (1, 2, 4, 8):
        raise Reject("only 1/2/4/8-bit chunks are screened")
    digits_per_word = 64 // chunk_bits
    if packing <= 0:
        raise Reject("packing must be positive")

    additions_per_compression = G_PER_ROUND * ROUNDS * (
        TERNARY_ADDS_PER_G + BINARY_ADDS_PER_G
    )
    ternary_adds_per_compression = G_PER_ROUND * ROUNDS * TERNARY_ADDS_PER_G
    binary_adds_per_compression = G_PER_ROUND * ROUNDS * BINARY_ADDS_PER_G
    even_xors_per_compression = G_PER_ROUND * ROUNDS * 3
    odd_xors_per_compression = G_PER_ROUND * ROUNDS
    feed_xors_per_compression = FEEDFORWARD_XORS_PER_COMPRESSION
    feed_xors_per_stage = FEEDFORWARD_XORS_PER_STAGE
    control_xors_per_compression = CONTROL_XORS_PER_COMPRESSION

    addition_words = additions_per_compression * COMPRESSIONS
    even_xor_words = even_xors_per_compression * COMPRESSIONS
    odd_xor_words = odd_xors_per_compression * COMPRESSIONS
    feed_xor_words = feed_xors_per_compression * COMPRESSIONS
    feed_xor_words_per_stage = feed_xors_per_stage * COMPRESSIONS
    all_rotated_xor_words = even_xor_words + odd_xor_words

    addition_digit_cells = addition_words * digits_per_word
    even_xor_digit_cells = even_xor_words * digits_per_word
    odd_xor_digit_cells = odd_xor_words * digits_per_word
    feed_xor_digit_cells = feed_xor_words * digits_per_word
    selected_control_digit_cells = SELECTED_CONTROL_WORDS * digits_per_word

    addition_sum_rows = ceil_div(addition_digit_cells, packing)
    addition_carry_rows = ceil_div(addition_digit_cells, packing)
    final_carry_rows = ceil_div(addition_words, packing)
    if chunk_bits == 1:
        rotated_xor_result_rows = ceil_div(
            (even_xor_digit_cells + odd_xor_digit_cells), packing
        )
        rotated_alias_rows = rotated_xor_result_rows
        even_xor_result_rows = None
        even_rotation_alias_rows = None
        odd_xor_result_rows = None
        odd_shifted_alias_rows = None
        odd_rotated_output_rows = None
        rotation_rows = 2 * rotated_xor_result_rows
        rotation_nonlinear = rotated_xor_result_rows
    else:
        even_xor_result_rows = ceil_div(even_xor_digit_cells, packing)
        even_rotation_alias_rows = even_xor_result_rows
        odd_xor_result_rows = ceil_div(odd_xor_digit_cells, packing)
        odd_shifted_alias_rows = odd_xor_result_rows
        odd_rotated_output_rows = odd_xor_result_rows
        rotated_xor_result_rows = None
        rotated_alias_rows = None
        rotation_rows = (
            even_xor_result_rows
            + even_rotation_alias_rows
            + odd_xor_result_rows
            + odd_shifted_alias_rows
            + odd_rotated_output_rows
        )
        rotation_nonlinear = even_xor_result_rows + 2 * odd_xor_result_rows
    # h xor v xor v' is two dependent binary-XOR stages.  Pooling both stages
    # into one ceil would place some second-stage outputs beside unrelated
    # first-stage intermediates.  Preserve one independently padded batch per
    # stage unless a higher-degree ternary-XOR relation is selected.
    feedforward_stage_rows = ceil_div(
        feed_xor_words_per_stage * digits_per_word, packing
    )
    feedforward_rows = FEEDFORWARD_XOR_STAGES * feedforward_stage_rows
    selected_control_rows = ceil_div(selected_control_digit_cells, packing)
    mode_gated_auth_link_nonlinear_rows = ceil_div(
        MODE_GATED_AUTH_LINK_CELLS, packing
    )
    mode_gated_auth_link_broadcast_rows = ceil_div(
        MODE_GATED_AUTH_LINK_CELLS, packing
    )
    core_rows = (
        addition_sum_rows
        + addition_carry_rows
        + final_carry_rows
        + rotation_rows
        + feedforward_rows
        + selected_control_rows
        + mode_gated_auth_link_nonlinear_rows
        + mode_gated_auth_link_broadcast_rows
    )
    core_nonlinear = (
        addition_sum_rows
        + addition_carry_rows
        + final_carry_rows
        + rotation_nonlinear
        + feedforward_rows
        + mode_gated_auth_link_nonlinear_rows
    )

    addition_scalar_equations = addition_digit_cells
    carry_zero_boundaries = addition_words
    rotation_copy_equalities = all_rotated_xor_words * digits_per_word
    core_linear_checks = (
        addition_scalar_equations
        + carry_zero_boundaries
        + rotation_copy_equalities
        + selected_control_digit_cells
        + MODE_GATED_AUTH_LINK_CELLS
    )

    unpadded_core_field_cells = (
        2 * addition_digit_cells
        + addition_words
        + 2 * even_xor_digit_cells
        + (2 if chunk_bits == 1 else 3) * odd_xor_digit_cells
        + feed_xor_digit_cells
        + selected_control_digit_cells
        + 2 * MODE_GATED_AUTH_LINK_CELLS
    )
    padded_core_field_cells = core_rows * packing
    core_padding_zero_checks = padded_core_field_cells - unpadded_core_field_cells

    source_digits = SOURCE_BITS // chunk_bits
    source_rows = ceil_div(source_digits, packing)
    message_digits = MESSAGE_WORD_SLOTS * digits_per_word
    message_rows = ceil_div(message_digits, packing)
    direct_base_rows = core_rows + source_rows + message_rows
    maximum_degree = chunk_maximum_degree(chunk_bits)
    geometry = proof_geometry(direct_base_rows, maximum_degree, packing)
    grammar_fit = bool(
        geometry["current_u16_matrix_dimensions_fit"]
        and geometry["decs_domain_length_fits"]
    )
    static_components = None
    static_bytes = None
    if grammar_fit:
        static_components = proof_payload_components(
            direct_base_rows,
            maximum_degree,
            packing,
            FULL_AUTH_PATH_NODES,
            0,
            4,
        )
        static_bytes = static_components["total"]

    return {
        "chunk_bits": chunk_bits,
        "radix": 1 << chunk_bits,
        "packing_factor": packing,
        "digits_per_word": digits_per_word,
        "whole_words_per_packed_row": packing // digits_per_word,
        "words_per_packed_row_ratio": {
            "numerator": packing,
            "denominator": digits_per_word,
        },
        "word_boundary_aligned": packing % digits_per_word == 0,
        "maximum_constraint_degree": maximum_degree,
        "xor_interpolation_total_degree": 2 * ((1 << chunk_bits) - 1),
        "xor_top_coefficient_nonzero": xor_table_top_coefficient(chunk_bits) != 0,
        "locally_active_degree_ceiling": 8,
        "degree_ceiling_pass": maximum_degree <= 8,
        "dense_role_batching": {
            "enabled": True,
            "justification": "same polynomial identity in every used lane; arbitrary scalar linear checks bind dependencies across rows and lanes",
            "layer_local_padding_required": False,
            "feedforward_stage_boundary_preserved": True,
            "cell_index_map": "public lexicographic (role, call, compression, round, half-round, G-index, word, digit), then row=floor(index/K), lane=index mod K",
            "witness_or_mask_dependent_shape": False,
            "all_16_masks_and_all_authorization_modes_use_same_shape": True,
            "padding_cells_are_fixed_zero": True,
        },
        "schedule": {
            "ternary_add64_per_compression": ternary_adds_per_compression,
            "binary_add64_per_compression": binary_adds_per_compression,
            "fused_addition_relations_per_compression": additions_per_compression,
            "unfused_binary_add64_equivalent_per_compression": 576,
            "even_rotated_xor64_per_compression": even_xors_per_compression,
            "odd_63_rotated_xor64_per_compression": odd_xors_per_compression,
            "feedforward_xor64_per_compression": feed_xors_per_compression,
            "feedforward_xor_stages": FEEDFORWARD_XOR_STAGES,
            "feedforward_xor64_per_stage_per_compression": feed_xors_per_stage,
            "rfc_control_xor64_per_compression": control_xors_per_compression,
            "fixed_control_compression_positions": FIXED_CONTROL_POSITIONS,
            "private_mode_control_compression_positions": PRIVATE_MODE_CONTROL_POSITIONS,
            "selector_bound_initial_control_words": SELECTED_CONTROL_WORDS,
        },
        "row_breakdown": {
            "addition_sum_rows": addition_sum_rows,
            "addition_carry_rows": addition_carry_rows,
            "shared_final_carry_rows": final_carry_rows,
            "rotated_xor_result_rows": rotated_xor_result_rows,
            "rotated_alias_rows": rotated_alias_rows,
            "even_xor_result_rows": even_xor_result_rows,
            "even_rotation_alias_rows": even_rotation_alias_rows,
            "odd_xor_result_rows": odd_xor_result_rows,
            "odd_shifted_alias_rows": odd_shifted_alias_rows,
            "odd_rotated_output_rows": odd_rotated_output_rows,
            "feedforward_rows_per_stage": feedforward_stage_rows,
            "feedforward_rows": feedforward_rows,
            "selector_bound_initial_control_rows": selected_control_rows,
            "mode_gated_auth_state_digest_nonlinear_rows": mode_gated_auth_link_nonlinear_rows,
            "mode_gated_auth_state_digest_broadcast_rows": mode_gated_auth_link_broadcast_rows,
            "core_rows": core_rows,
            "source_rows": source_rows,
            "materialized_message_rows": message_rows,
            "direct_base_rows": direct_base_rows,
        },
        "constraint_accounting": {
            "core_nonlinear_output_polynomials": core_nonlinear,
            "source_digit_membership_output_polynomials": source_rows,
            "known_direct_minimum_output_polynomials": core_nonlinear + source_rows,
            "core_scalar_linear_checks": core_linear_checks,
            "core_dependency_linear_checks": core_linear_checks,
            "core_arithmetic_and_copy_linear_checks_before_control_selection": (
                addition_scalar_equations
                + carry_zero_boundaries
                + rotation_copy_equalities
            ),
            "core_padding_zero_checks": core_padding_zero_checks,
            "core_total_scalar_linear_checks_including_padding": (
                core_linear_checks + core_padding_zero_checks
            ),
            "addition_digit_equations": addition_scalar_equations,
            "initial_carry_zero_checks": carry_zero_boundaries,
            "rotation_copy_equalities": rotation_copy_equalities,
            "selected_control_digit_checks": selected_control_digit_cells,
            "mode_gated_auth_state_digest_broadcast_copy_checks": MODE_GATED_AUTH_LINK_CELLS,
            "source_and_message_padding_zero_checks": (
                source_rows * packing - source_digits
                + message_rows * packing - message_digits
            ),
            "known_direct_minimum_linear_checks_including_padding": (
                core_linear_checks
                + core_padding_zero_checks
                + source_rows * packing
                - source_digits
                + message_rows * packing
                - message_digits
            ),
            "message_and_nonhash_binding_linear_checks": None,
            "nonhash_output_polynomials": None,
            "full_cfg_constraint_count": None,
            "full_cfg_linear_constraint_count": None,
            "auth_path_nodes_H": FULL_AUTH_PATH_NODES,
            "H_is_not_constraint_count": True,
        },
        "cell_accounting": {
            "unpadded_core_field_cells": unpadded_core_field_cells,
            "padded_core_field_cells": padded_core_field_cells,
            "core_padding_cells": core_padding_zero_checks,
            "source_digits": source_digits,
            "source_padding_cells": source_rows * packing - source_digits,
            "message_digits": message_digits,
            "message_padding_cells": message_rows * packing - message_digits,
            "direct_base_field_cells": direct_base_rows * packing,
            "direct_base_u64_witness_bytes": direct_base_rows * packing * 8,
        },
        "relation": {
            "addition_equation": "sum(operands)+c_i-s-B*c_(i+1)=0",
            "ternary_carry_domain": [0, 1, 2],
            "binary_carry_domain_inherited_by_induction": [0, 1],
            "carry_range_polynomial": "c*(c-1)*(c-2)",
            "sum_digit_range_degree": 1 << chunk_bits,
            "addition_equation_is_separate_scalar_linear_check": True,
            "range_roots_are_not_unsafely_summed": True,
            "radix4_xor_low": "(2*x^3-9*x^2+10*x)/3" if chunk_bits == 2 else None,
            "radix4_xor_high": "(-2*x^3+9*x^2-7*x)/6" if chunk_bits == 2 else None,
            "odd_rotation": "left-rotate one via shifted predecessor alias and digit recomposition" if chunk_bits > 1 else "bit permutation alias",
            "odd_rotation_degree": (1 << chunk_bits) - 1 if chunk_bits > 1 else 1,
            "control_initialization": {
                "fixed_positions_constant_folded": FIXED_CONTROL_POSITIONS,
                "private_mode_positions": PRIVATE_MODE_CONTROL_POSITIONS,
                "selector_bound_precomputed_words": SELECTED_CONTROL_WORDS,
                "selector_rule": "each radix digit is a linear combination of canonical authorization selectors and precomputed RFC control constants",
                "fixed_tuple_profile_digest_bound": False,
                "all_control_tuple_kats_and_mutations_retained": False,
            },
            "mode_gated_auth_state_digest_link": {
                "logical_cells": MODE_GATED_AUTH_LINK_CELLS,
                "nonlinear_selector_batch_rows": mode_gated_auth_link_nonlinear_rows,
                "broadcast_alias_batch_rows": mode_gated_auth_link_broadcast_rows,
                "broadcast_copy_linear_checks": MODE_GATED_AUTH_LINK_CELLS,
                "purpose": "bind the selected authorization arm's state2/state3 digest into the common hash topology without host-side selection",
                "executable_indexer_and_refinement_retained": False,
            },
        },
        "geometry": geometry,
        "wire": {
            "current_matrix_dimension_grammar": "u16 rows || u16 cols",
            "current_matrix_grammar_fits": grammar_fit,
            "existing_arithmetization_enum_supports_packing": packing in (16, 32, 64, 128),
            "existing_strict_v6_profile_supports_packing": packing == 64,
            "existing_parser_and_wire_identity_accepts_candidate": False,
            "fresh_profile_identity_required": True,
        },
        "proof_screen": {
            "static_inner_payload_bytes": static_bytes,
            "static_inner_payload_components": static_components,
            "full_path_auth_nodes": FULL_AUTH_PATH_NODES,
            "auxiliary_words_assumed": 0 if static_bytes is not None else None,
            "current_profile_proof_bytes": None,
            "full_relation_proof_bytes": None,
            "measured_proof_bytes": None,
            "retained_proof_artifact": False,
            "claim_boundary": "exact serializer-shape arithmetic for the direct base only; not an accepted profile, proof, measurement, lower bound, or upper bound",
        },
    }


@lru_cache(maxsize=None)
def optimize_chunk(chunk_bits: int) -> dict[str, Any]:
    digits_per_word = 64 // chunk_bits
    candidates = []
    feasible = 0
    # Every positive K is admissible to the generic polynomial geometry: a
    # word may straddle rows because copy checks address flattened scalar
    # cells.  The current subset-evaluation matrix has exactly 2*K columns,
    # so its u16 column field proves K <= floor(65535/2).  This loop is thus
    # exhaustive for the current compact matrix grammar, not a heuristic grid.
    for packing in range(1, MAX_SCREENED_PACKING + 1):
        layout = chunk_layout(chunk_bits, packing)
        size = layout["proof_screen"]["static_inner_payload_bytes"]
        if size is None:
            continue
        feasible += 1
        candidates.append((size, packing, layout))
    if not candidates:
        raise Reject("no u16-serializable packing candidate")
    size, packing, selected = min(
        candidates,
        key=lambda item: (
            item[0],
            item[2]["cell_accounting"]["direct_base_field_cells"],
            not item[2]["word_boundary_aligned"],
            item[1],
        ),
    )
    co_minima = [
        {
            "packing": candidate_packing,
            "direct_base_rows": layout["row_breakdown"]["direct_base_rows"],
            "core_nonlinear_output_polynomials": layout["constraint_accounting"]["core_nonlinear_output_polynomials"],
            "direct_base_field_cells": layout["cell_accounting"]["direct_base_field_cells"],
            "direct_total_padding_cells": (
                layout["cell_accounting"]["core_padding_cells"]
                + layout["cell_accounting"]["source_padding_cells"]
                + layout["cell_accounting"]["message_padding_cells"]
            ),
            "word_boundary_aligned": layout["word_boundary_aligned"],
        }
        for candidate_size, candidate_packing, layout in candidates
        if candidate_size == size
    ]
    selected = dict(selected)
    selected["packing_search"] = {
        "minimum_packing": 1,
        "maximum_packing": MAX_SCREENED_PACKING,
        "packing_step": 1,
        "upper_bound_proof": "subset_evals has 2*K columns under beta=2/openings=5, so current u16 dimensions require K<=32767",
        "word_alignment_required": False,
        "digits_per_word": digits_per_word,
        "u16_serializable_candidates": feasible,
        "objective": "minimum exact static inner payload bytes, then minimum allocated direct-base cells, then word alignment, then minimum K",
        "co_minimal_payload_packings": co_minima,
        "selected_packing": packing,
        "selected_static_inner_payload_bytes": size,
    }
    return selected


def privacy_width_sensitivity(base_bytes: int) -> dict[str, Any]:
    """Conditional wire deltas; no theorem is asserted for the custom transform."""
    profiles: dict[str, Any] = {}
    for lambda_bits in (768, 1024):
        digest_bytes = lambda_bits // 8
        leaf_tape_bytes = (2 * lambda_bits) // 8
        merkle_delta = (
            FULL_AUTH_PATH_NODES * (digest_bytes - 64)
            + PROFILE["decs_nb_opened_evals"] * (leaf_tape_bytes - 64)
        )
        privacy_merkle_bytes = base_bytes + merkle_delta
        smallwood_2lambda_bytes = (2 * lambda_bits) // 8
        # The current serializer has one 32-byte global salt and one 64-byte
        # h_piop.  This is only the delta if a fresh grammar serializes exactly
        # one theorem-width salt and one theorem-width final h value.
        transcript_delta = (
            smallwood_2lambda_bytes - 32
            + smallwood_2lambda_bytes - 64
        )
        profiles[str(lambda_bits)] = {
            "lambda_bits": lambda_bits,
            "bcs_oracle_output_bytes": digest_bytes,
            "bcs_leaf_salt_or_tape_bytes": leaf_tape_bytes,
            "authentication_node_count": FULL_AUTH_PATH_NODES,
            "opened_tape_count": PROFILE["decs_nb_opened_evals"],
            "privacy_merkle_delta_bytes": merkle_delta,
            "privacy_merkle_only_static_inner_bytes": privacy_merkle_bytes,
            "bcs_p_bits": None,
            "bcs_term": None,
            "isolated_p_equals_one_exponent_bits": lambda_bits // 4 - 2,
            "smallwood_theorem10_salt_bytes": smallwood_2lambda_bytes,
            "smallwood_theorem10_h_bytes": smallwood_2lambda_bytes,
            "conditional_one_salt_one_h_delta_bytes": transcript_delta,
            "conditional_privacy_merkle_plus_one_salt_one_h_bytes": (
                privacy_merkle_bytes + transcript_delta
            ),
            "claim_boundary": "size sensitivity only; BCS p and a refinement from the custom SmallWood transform to either theorem are null",
        }
    return {
        "current_sha512": {
            "lambda_bits_if_hash_output_is_lambda": 512,
            "hash_output_bytes": 64,
            "current_leaf_tape_bytes": 64,
            "bcs_required_2lambda_leaf_salt_bytes": 128,
            "leaf_tape_width_matches_bcs": False,
            "bcs_p_bits": None,
            "bcs_term": None,
            "best_case_p_equals_one_term": "2^-126",
            "best_case_p_equals_one_security_bits": 126,
            "strict_gt_128_even_at_p_equals_one": False,
        },
        "conditional_fresh_profiles": profiles,
        "smallwood_theorem10_distinction": {
            "salt_bits": "2*lambda",
            "fiat_shamir_h_bits": "2*lambda",
            "not_the_same_width_rule_as_bcs_merkle": True,
            "current_global_salt_bytes": 32,
            "current_serialized_h_piop_bytes": 64,
            "number_of_theorem_h_values_serialized_by_a_fresh_profile": None,
            "full_theorem_faithful_wire_bytes": None,
        },
        "primary_sources": {
            "bcs16_116": {
                "title": "Interactive Oracle Proofs",
                "anchors": ["Definition 3.3", "Lemma 3.4", "Lemma 7.5"],
                "sha512": "66557007b59ec3ce3657b22b6b4c5047ef60762b2e6b7d0c2baff16ad5d4dfa77b2f3aa5e8f068f8d260ae9919cf862a23ff685ff0c82356d207ebac3c3f6914",
                "scope": "explicitly programmable classical random oracle; p(x)*2^(-lambda/4+2)",
            },
            "smallwood_2025_1085": {
                "title": "SmallWood",
                "anchors": ["proof composition and size", "Theorem 10"],
                "sha512": "cd035a0739d3c7f2f82fd4a089e3e1bb748cd16c5fa30addc16f2197e49f972be2ed97f760b3eafee480bd978030e9b339a93341a0661daca11738fdc128a8e2",
                "scope": "ROM simulator samples salt and Fiat-Shamir h_i values from {0,1}^{2lambda}",
            },
        },
    }


def isolated_epsilon4_receipt(nb_lvcs_cols: int) -> dict[str, Any]:
    opened = PROFILE["decs_nb_opened_evals"]
    domain = PROFILE["decs_nb_evals"]
    numerator = math.prod(nb_lvcs_cols + index for index in range(opened))
    denominator = math.prod(domain - index for index in range(opened))
    bits = math.log2(denominator) - math.log2(numerator)
    return {
        "formula": "product_(i=0..ell-1)(n_cols+i)/(N-i)",
        "ell": opened,
        "N": domain,
        "n_cols": nb_lvcs_cols,
        "numerator": str(numerator),
        "denominator": str(denominator),
        "negative_log2_approx": round(bits, 12),
        "isolated_classical_term_only": True,
        "composed_security_bits": None,
    }


def source_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        path = ROOT / relative
        if not path.is_file():
            raise Reject(f"missing source input: {relative}")
        pins[relative] = sha512_file(path)
    return pins


def build_screen() -> dict[str, Any]:
    tournament = {str(chunk_bits): optimize_chunk(chunk_bits) for chunk_bits in (1, 2, 4, 8)}
    selected = tournament["2"]
    local_k64 = chunk_layout(2, 64)
    local_k128 = chunk_layout(2, 128)
    selected_bytes = selected["proof_screen"]["static_inner_payload_bytes"]
    if selected_bytes is None:
        raise Reject("selected static size unexpectedly null")
    lig128 = 8_652_192
    lig264 = 16_437_920
    result = {
        "artifact_schema": "hegemon.smallwood-hx512-trace-screen.v2",
        "artifact": "fail-closed direct SmallWood HX512 trace/copy architecture screen",
        "status": "conditional_static_size_viable_fresh_profile_required_fail_closed",
        "schedule": {
            "profile": "HX512B01",
            "physical_calls": PHYSICAL_CALLS,
            "blake2b512_compressions": COMPRESSIONS,
            "rounds_per_compression": ROUNDS,
            "g_functions_per_round": G_PER_ROUND,
            "g_functions_per_compression": ROUNDS * G_PER_ROUND,
            "ternary_add64_per_g": TERNARY_ADDS_PER_G,
            "binary_add64_per_g": BINARY_ADDS_PER_G,
            "fused_addition_relations_per_compression": 384,
            "unfused_binary_add64_equivalent_per_compression": 576,
            "g_xor64_per_compression": ROUNDS * G_PER_ROUND * ROTATED_XORS_PER_G,
            "feedforward_xor64_per_compression": FEEDFORWARD_XORS_PER_COMPRESSION,
            "feedforward_xor_stages": FEEDFORWARD_XOR_STAGES,
            "feedforward_xor64_per_stage": FEEDFORWARD_XORS_PER_STAGE,
            "rfc_control_xor64_per_compression": CONTROL_XORS_PER_COMPRESSION,
            "total_rfc_xor64_per_compression": (
                ROUNDS * G_PER_ROUND * ROTATED_XORS_PER_G
                + FEEDFORWARD_XORS_PER_COMPRESSION
                + CONTROL_XORS_PER_COMPRESSION
            ),
            "fixed_control_positions": FIXED_CONTROL_POSITIONS,
            "private_mode_control_positions": PRIVATE_MODE_CONTROL_POSITIONS,
            "selector_bound_control_words": SELECTED_CONTROL_WORDS,
            "source_bits": SOURCE_BITS,
            "message_word_slots": MESSAGE_WORD_SLOTS,
        },
        "field": {
            "name": "Goldilocks",
            "modulus": str(P),
            "selected_packing_factor": selected["packing_factor"],
            "local_existing_packings": [16, 32, 64, 128],
            "local_strict_v6_packing": 64,
            "active_relation_degree_ceiling": 8,
            "selected_constraint_degree": selected["maximum_constraint_degree"],
            "anisotropic_coefficient": NU,
            "euler_certificate_exponent": str((P - 1) // 2),
            "euler_certificate_value": str(pow(NU, (P - 1) // 2, P)),
            "quadratic_nonresidue": True,
            "nonresidue_use": "verified alternative two-residual Boolean adder only; selected radix-4 design keeps range roots separate at degree six",
        },
        "arithmetic_receipt": exhaustive_arithmetic_receipt(),
        "layouts": {
            "packing_tournament": tournament,
            "selected_chunk_bits": 2,
            "selected_packing": selected["packing_factor"],
            "selected": selected,
            "locally_enumerated_k64": local_k64,
            "locally_enumerated_k128": local_k128,
            "selection_reason": "minimum exact static current-u16 serializer expression among k=1/2/4/8 and every integer K in 1..32767; the 2*K subset width proves this search exhaustive",
            "correction_history": [
                {
                    "candidate": "radix4 K992 phase-local",
                    "core_rows": 11_413,
                    "direct_base_rows": 11_573,
                    "static_inner_bytes": 1_374_178,
                    "retained": False,
                    "reason": "arbitrary scalar linear checks permit denser public same-role batching",
                },
                {
                    "candidate": "radix4 K1024 pooled feedforward",
                    "core_rows": 11_050,
                    "direct_base_rows": 11_205,
                    "static_inner_bytes": 1_372_834,
                    "retained": False,
                    "reason": "the two feedforward XOR stages are dependent and require independent padding at degree six",
                },
                {
                    "candidate": "radix4 K1024 dependency-safe",
                    "core_rows": 11_051,
                    "direct_base_rows": 11_206,
                    "static_inner_bytes": 1_372_874,
                    "retained": False,
                    "reason": "omitted the private authorization-mode RFC counter/final control selection",
                },
                {
                    "candidate": "radix4 K1024 dependency-safe plus selected control initialization",
                    "core_rows": 11_052,
                    "direct_base_rows": 11_207,
                    "static_inner_bytes": 1_372_954,
                    "retained": False,
                    "reason": "omitted the mode-gated authorization state2/state3 digest linkage",
                },
                {
                    "candidate": "radix4 K1024 conservative mode-gated authorization digest linkage",
                    "core_rows": 11_054,
                    "direct_base_rows": 11_209,
                    "static_inner_bytes": 1_373_074,
                    "retained": True,
                    "correction": "+1,024-cell nonlinear selector batch, +1,024-cell broadcast/alias batch, and +1,024 scalar broadcast-copy checks",
                },
            ],
        },
        "flat_occurrence_comparison": {
            "corrected_hx512_source_projection_constraints": 29_509_887,
            "projection_kind": "source-static odd-field scalar occurrence projection; not frozen executable sparse R1CS",
            "direct_trace_base_rows": selected["row_breakdown"]["direct_base_rows"],
            "direct_trace_base_field_cells": selected["cell_accounting"]["direct_base_field_cells"],
            "direct_trace_avoids_occurrence_duplication": "each state/message/sum/carry digit is committed once per role batch; arbitrary scalar linear checks bind cross-row and cross-lane reuse instead of allocating a fresh witness occurrence per scalar gate",
            "like_for_like_numeric_ratio_available": False,
            "reason_ratio_is_null": "29,509,887 counts projected full-relation scalar constraints while the selected packed direct-base witness rows exclude nonhash adapter rows",
            "flat_adapter_proof_bytes": None,
        },
        "dense_topology_gate": {
            "arithmetic_projection_exact_given_shape": True,
            "public_secret_independent_indexer_specified": True,
            "public_secret_independent_indexer_implemented": False,
            "per_operation_operand_result_alignment_checked": False,
            "alias_cycle_double_use_and_omission_checked": False,
            "every_padding_cell_zero_checked_by_executable_adapter": False,
            "exact_executable_hash_trace_row_count": None,
            "required_index_key": "(role, call, compression, round, half-round, G-index, word, digit)",
            "claim_boundary": "dense counts and bytes are exact conditional projections, not executable adapter evidence",
        },
        "wire_and_profile_feasibility": {
            "generic_engine_geometry_computable": True,
            "all_selected_matrix_dimensions_fit_current_u16_grammar": True,
            "selected_decs_polynomial_length_fits_2pow20": True,
            "current_arithmetization_enum_supports_selected_packing": False,
            "current_parser_accepts_selected_profile": False,
            "current_wire_identity_binds_selected_profile": False,
            "fresh_profile_enum_parser_wire_domain_required": True,
            "fresh_profile_implemented": False,
            "exact_full_cfg_constraint_count": None,
            "exact_full_cfg_linear_constraint_count": None,
            "exact_full_relation_row_count": None,
            "current_profile_proof_bytes": None,
            "measured_full_relation_proof_bytes": None,
        },
        "prover_feasibility": {
            "selected_direct_base_u64_witness_bytes": selected["cell_accounting"]["direct_base_u64_witness_bytes"],
            "selected_lvcs_u64_cells": selected["geometry"]["nb_lvcs_rows"] * selected["geometry"]["nb_lvcs_cols"],
            "selected_lvcs_u64_bytes": selected["geometry"]["nb_lvcs_rows"] * selected["geometry"]["nb_lvcs_cols"] * 8,
            "committed_leaf_tape_rng_bytes": PROFILE["decs_nb_evals"] * 64,
            "source_static_memory_floor_only": True,
            "peak_memory_bytes": None,
            "prover_time_seconds": None,
            "verifier_time_seconds": None,
            "heavy_build_or_benchmark_run": False,
        },
        "complete_zero_knowledge": {
            "known_point_64_leak": True,
            "ordinary_radix2_subgroup_allowed": False,
            "selected_packing_interpolation_points": "0..1023",
            "selected_decs_polynomial_length": selected["geometry"]["decs_polynomial_length"],
            "required_domain": "deterministic multiplicative coset disjoint from every final witness, PIOP, PCS, and DECS interpolation coordinate",
            "final_geometry_coset_search_executed": False,
            "leaf_tape_bytes": 64,
            "committed_leaf_tape_count": 1 << 20,
            "committed_leaf_tape_rng_bytes": (1 << 20) * 64,
            "opened_leaf_tape_count": 23,
            "opened_leaf_tape_bytes": 23 * 64,
            "independent_tape_per_committed_leaf_required": True,
            "leaf_index_domain_and_tape_length_hash_binding_required": True,
            "full_view_simulator_required": True,
            "full_view_simulator_scope": [
                "witness and masking polynomials",
                "PIOP and PCS commitments and transcripts",
                "opened row scalars subset partial and rcombi values",
                "DECS leaves authentication paths and opened tapes",
                "adaptive query indices retries aborts and grinding",
                "all verifier-visible joint correlations",
            ],
            "retained_full_view_simulator_theorem": False,
            "native_simulator_refinement": False,
            "complete_zero_knowledge": False,
        },
        "privacy_width_sensitivity": privacy_width_sensitivity(selected_bytes),
        "security_geometry_sensitivity": {
            "historical_n_cols_375": isolated_epsilon4_receipt(375),
            "selected_conditional_n_cols": isolated_epsilon4_receipt(
                selected["geometry"]["nb_lvcs_cols"]
            ),
            "full_relation_n_cols": None,
            "K1024_final_profile_selected": False,
            "joint_optimizer_required_variables": [
                "packing K",
                "DECS openings ell",
                "DECS domain N",
                "eta",
                "rho",
                "digest lambda",
                "leaf-tape lambda",
                "exact full-relation R and degree",
                "every composed PQ/QROM and consensus-union term",
            ],
            "claim_boundary": "serializer-byte co-minimum is not a security/profile optimum; full nonhash rows can increase n_cols and every composed term remains unavailable",
        },
        "transcript_and_qrom": {
            "required_commitment_and_transcript_width_bits": 512,
            "required_primitives": ["SHA-512", "SHAKE256-512"],
            "fresh_smz2_sha512_dispatch_available": False,
            "generic_256_bit_merkle_or_transcript_allowed": False,
            "required_terms": [
                "LPPC/DECS PCS binding proximity and list error",
                "PIOP/RBR knowledge error",
                "complete whole-view ZK error",
                "BCS/CMS finite-QROM Fiat-Shamir loss",
                "explicit conventional-hash-as-QRO instantiation advantage",
                "quantum collision and preimage terms",
                "grinding retry abort and RNG failure",
                "multi-proof action block epoch history and consensus unions",
                "parser native-verifier and formal refinement error",
            ],
            "pcs_error": None,
            "iop_knowledge_error": None,
            "complete_zk_error": None,
            "qrom_fiat_shamir_error": None,
            "hash_qro_instantiation_advantage": None,
            "grinding_retry_rng_error": None,
            "consensus_history_union_error": None,
            "refinement_error": None,
            "composed_security_bits": None,
            "strict_gt_128": False,
        },
        "comparisons": {
            "smallwood_selected_static_direct_base": {
                "bytes": selected_bytes,
                "kind": "exact current-u16 serializer-shape expression for an unimplemented fresh-profile direct base; excludes nonhash rows and auxiliary words",
            },
            "ligero_source128_hash512": {
                "bytes": lig128,
                "kind": "conditional paper expression; not measured and not a bound",
                "selected_smallwood_delta": selected_bytes - lig128,
            },
            "ligero_source264_hash640": {
                "bytes": lig264,
                "kind": "conditional paper expression; not measured and not a bound",
                "selected_smallwood_delta": selected_bytes - lig264,
            },
            "aurora": {
                "proof_bytes": None,
                "ordering_available": False,
                "reason": "no canonical serializer or retained proof-byte expression/artifact",
            },
            "strict_size_winner": None,
        },
        "capabilities": {
            "exact_fused_hash_schedule_static": True,
            "exact_conditional_direct_base_projection": True,
            "exact_conditional_serializer_expression": True,
            "exact_executable_hash_trace_adapter": False,
            "exact_full_relation_compiled": False,
            "accepted_profile_and_wire_identity": False,
            "retained_proof_artifact": False,
            "measured_same_relation_proof_bytes": False,
            "complete_zero_knowledge": False,
            "composed_strict_gt_128_pq_qrom": False,
            "native_verifier_refinement": False,
            "consensus_lifecycle_refinement": False,
            "production_authorized": False,
        },
        "verdict": {
            "local_identities_algebraically_representable_in_generic_row_polynomial_api": True,
            "whole_trace_topology_represented": False,
            "current_profile_compatible": False,
            "conditional_size_viable_for_architecture_tournament": True,
            "retains_compact_architecture_as_source_static_candidate": True,
            "current_smallest_defensible_winner": False,
            "reason": "the direct radix-4 trace has a 1.37 MB static base expression below retained Ligero paper lanes and avoids flat occurrence duplication, but no selected profile, full adapter, proof, complete-ZK theorem, QROM composition, or refinement exists",
        },
        "source_anchors": {
            "smallwood_engine": [
                "SmallwoodConfig::new_with_profile",
                "shape_u16_v1",
                "encode_smallwood_proof_bytes_v1",
                "validate_pcs_opening_shape",
                "SmallwoodArithmetization",
            ],
            "smallwood_semantics": [
                "linear_constraints",
                "evaluate_constraints",
                "packing_factor",
                "constraint_count",
            ],
            "blake_boolean_occurrence_adapter": [
                "Blake2bConstraintTrace",
                "Blake2bConstraint::FullAdderSum",
                "Blake2bConstraint::FullAdderCarry",
                "row_accounting",
            ],
            "hx512_scalar_projection": [
                "verifier_profile.py::odd_field_projection",
                "test_compiler.py corrected m_constraints=29_509_887",
            ],
        },
        "source_pins_sha512": source_pins(),
    }
    validate_screen(result, verify_pins=False)
    return result


def validate_screen(value: dict[str, Any], verify_pins: bool = True) -> None:
    if value.get("artifact_schema") != "hegemon.smallwood-hx512-trace-screen.v2":
        raise Reject("wrong schema")
    if value.get("status") != "conditional_static_size_viable_fresh_profile_required_fail_closed":
        raise Reject("screen status drift")
    schedule = value["schedule"]
    if schedule["physical_calls"] != 90 or schedule["blake2b512_compressions"] != 213:
        raise Reject("HX512 schedule drift")
    if schedule["fused_addition_relations_per_compression"] != 384:
        raise Reject("fused addition count drift")
    if value["field"]["selected_packing_factor"] != 1024:
        raise Reject("selected packing drift")
    if value["field"]["selected_constraint_degree"] != 6:
        raise Reject("selected degree drift")
    if value["field"]["anisotropic_coefficient"] != 7:
        raise Reject("nonresidue drift")
    if int(value["field"]["euler_certificate_value"]) != P - 1:
        raise Reject("invalid nonresidue certificate")
    if value["arithmetic_receipt"] != exhaustive_arithmetic_receipt():
        raise Reject("arithmetic receipt drift")

    expected_tournament = {
        str(chunk_bits): optimize_chunk(chunk_bits) for chunk_bits in (1, 2, 4, 8)
    }
    layouts = value["layouts"]
    if layouts["packing_tournament"] != expected_tournament:
        raise Reject("packing tournament drift")
    selected = layouts["selected"]
    if selected != expected_tournament["2"]:
        raise Reject("selected layout drift")
    if layouts["locally_enumerated_k64"] != chunk_layout(2, 64):
        raise Reject("K64 screen drift")
    if layouts["locally_enumerated_k128"] != chunk_layout(2, 128):
        raise Reject("K128 screen drift")
    co_minima = selected["packing_search"]["co_minimal_payload_packings"]
    if [entry["packing"] for entry in co_minima] != [1024, 1029]:
        raise Reject("radix-4 co-minimum drift")
    if selected["packing_search"]["packing_step"] != 1:
        raise Reject("packing search is not exhaustive over integers")

    rows = selected["row_breakdown"]
    constraints = selected["constraint_accounting"]
    geometry = selected["geometry"]
    if rows["core_rows"] != 11_054 or rows["source_rows"] != 48:
        raise Reject("selected core/source row drift")
    if rows["materialized_message_rows"] != 107 or rows["direct_base_rows"] != 11_209:
        raise Reject("selected message/base row drift")
    if rows["mode_gated_auth_state_digest_nonlinear_rows"] != 1:
        raise Reject("mode-gated authorization nonlinear row drift")
    if rows["mode_gated_auth_state_digest_broadcast_rows"] != 1:
        raise Reject("mode-gated authorization broadcast row drift")
    if constraints["core_nonlinear_output_polynomials"] != 8_496:
        raise Reject("selected nonlinear constraint drift")
    if constraints["core_arithmetic_and_copy_linear_checks_before_control_selection"] != 5_316_480:
        raise Reject("selected linear constraint drift")
    if constraints["selected_control_digit_checks"] != 512:
        raise Reject("selected control check drift")
    if constraints["mode_gated_auth_state_digest_broadcast_copy_checks"] != 1_024:
        raise Reject("mode-gated authorization broadcast-copy check drift")
    if constraints["core_dependency_linear_checks"] != 5_318_016:
        raise Reject("control-inclusive dependency check drift")
    if constraints["core_padding_zero_checks"] != 2_176:
        raise Reject("selected core padding count drift")
    if constraints["known_direct_minimum_linear_checks_including_padding"] != 5_321_004:
        raise Reject("selected direct padding/check count drift")
    if constraints["full_cfg_constraint_count"] is not None:
        raise Reject("full cfg constraint count must remain null")
    if constraints["H_is_not_constraint_count"] is not True:
        raise Reject("auth-node/constraint-count distinction lost")
    expected_geometry = {
        "nb_polys": 11_219,
        "ppol_high_columns": 5_140,
        "plin_high_columns": 2_046,
        "nb_unstacked_cols": 11_249,
        "nb_lvcs_rows": 2_058,
        "nb_lvcs_cols": 5_625,
        "partial_eval_columns": 30,
        "decs_polynomial_length": 5_648,
    }
    for key, expected in expected_geometry.items():
        if geometry[key] != expected:
            raise Reject(f"selected geometry drift: {key}")
    if not geometry["current_u16_matrix_dimensions_fit"]:
        raise Reject("selected matrix grammar must fit")

    proof_screen = selected["proof_screen"]
    if proof_screen["static_inner_payload_bytes"] != 1_373_074:
        raise Reject("selected static byte expression drift")
    if proof_screen["static_inner_payload_components"]["opened_witness"] != 448_773:
        raise Reject("opened witness matrix byte count drift")
    if any(
        proof_screen[key] is not None
        for key in ("current_profile_proof_bytes", "full_relation_proof_bytes", "measured_proof_bytes")
    ):
        raise Reject("proof-byte authority must remain null")

    if value["flat_occurrence_comparison"]["corrected_hx512_source_projection_constraints"] != 29_509_887:
        raise Reject("flat occurrence comparison drift")
    if value["flat_occurrence_comparison"]["like_for_like_numeric_ratio_available"]:
        raise Reject("unlike scalar/row geometries cannot be ratioed")
    topology = value["dense_topology_gate"]
    if topology["public_secret_independent_indexer_implemented"]:
        raise Reject("unimplemented topology indexer was promoted")
    if topology["exact_executable_hash_trace_row_count"] is not None:
        raise Reject("executable hash row count must remain null")
    wire = value["wire_and_profile_feasibility"]
    if not wire["all_selected_matrix_dimensions_fit_current_u16_grammar"]:
        raise Reject("selected matrix grammar fit drift")
    if wire["current_arithmetization_enum_supports_selected_packing"]:
        raise Reject("unsupported packing was promoted")
    for key in (
        "exact_full_cfg_constraint_count",
        "exact_full_cfg_linear_constraint_count",
        "exact_full_relation_row_count",
        "current_profile_proof_bytes",
        "measured_full_relation_proof_bytes",
    ):
        if wire[key] is not None:
            raise Reject(f"unavailable wire/profile value must be null: {key}")

    if value["complete_zero_knowledge"]["complete_zero_knowledge"]:
        raise Reject("complete ZK is not established")
    sensitivity = value["privacy_width_sensitivity"]
    current_privacy = sensitivity["current_sha512"]
    if current_privacy["bcs_p_bits"] is not None or current_privacy["bcs_term"] is not None:
        raise Reject("custom-transform BCS p/term must remain null")
    if current_privacy["best_case_p_equals_one_security_bits"] != 126:
        raise Reject("SHA-512 BCS best-case no-go drift")
    if current_privacy["strict_gt_128_even_at_p_equals_one"]:
        raise Reject("SHA-512 cannot pass strict BCS privacy")
    expected_sensitivity = {
        "768": (1_390_738, 1_391_026),
        "1024": (1_406_930, 1_407_346),
    }
    for key, expected in expected_sensitivity.items():
        profile = sensitivity["conditional_fresh_profiles"][key]
        if (
            profile["privacy_merkle_only_static_inner_bytes"],
            profile["conditional_privacy_merkle_plus_one_salt_one_h_bytes"],
        ) != expected:
            raise Reject(f"privacy width sensitivity drift: {key}")
        if profile["bcs_p_bits"] is not None or profile["bcs_term"] is not None:
            raise Reject("conditional BCS terms must remain null")
    distinction = sensitivity["smallwood_theorem10_distinction"]
    if distinction["full_theorem_faithful_wire_bytes"] is not None:
        raise Reject("full theorem-faithful wire remains unknown")
    geometry_sensitivity = value["security_geometry_sensitivity"]
    if geometry_sensitivity["selected_conditional_n_cols"] != isolated_epsilon4_receipt(5_625):
        raise Reject("selected epsilon4 geometry drift")
    if geometry_sensitivity["historical_n_cols_375"] != isolated_epsilon4_receipt(375):
        raise Reject("historical epsilon4 comparison drift")
    if geometry_sensitivity["full_relation_n_cols"] is not None:
        raise Reject("full-relation n_cols must remain null")
    if geometry_sensitivity["K1024_final_profile_selected"]:
        raise Reject("serializer co-minimum cannot select the security profile")
    qrom = value["transcript_and_qrom"]
    if qrom["composed_security_bits"] is not None or qrom["strict_gt_128"]:
        raise Reject("composed security must remain null/fail closed")
    for key in (
        "pcs_error",
        "iop_knowledge_error",
        "complete_zk_error",
        "qrom_fiat_shamir_error",
        "hash_qro_instantiation_advantage",
        "grinding_retry_rng_error",
        "consensus_history_union_error",
        "refinement_error",
    ):
        if qrom[key] is not None:
            raise Reject(f"missing security term must remain null: {key}")
    if value["comparisons"]["aurora"]["proof_bytes"] is not None:
        raise Reject("Aurora proof bytes must remain null")
    if value["comparisons"]["strict_size_winner"] is not None:
        raise Reject("no strict winner exists")

    allowed_true = {
        "exact_fused_hash_schedule_static",
        "exact_conditional_direct_base_projection",
        "exact_conditional_serializer_expression",
    }
    for key, enabled in value["capabilities"].items():
        if enabled and key not in allowed_true:
            raise Reject(f"unauthorized capability: {key}")
    if value["capabilities"]["production_authorized"]:
        raise Reject("production must remain disabled")
    if value["verdict"]["current_smallest_defensible_winner"]:
        raise Reject("screen cannot select a defensible winner")

    components = proof_payload_components(11_209, 6, 1_024, 460, 0, 4)
    if components != proof_screen["static_inner_payload_components"]:
        raise Reject("serializer component formula drift")
    closed_form = (
        6_722
        + 648 * 1_024
        + 64 * 460
        + 40 * 11_209
        + 40 * ceil_div(11_209 + 40, 2)
    )
    if closed_form != 1_373_074:
        raise Reject("closed-form serializer arithmetic failed")

    if verify_pins and value.get("source_pins_sha512") != source_pins():
        raise Reject("source pin drift")


def write_screen() -> None:
    SCREEN_PATH.write_bytes(canonical_json(build_screen()))


def check_screen() -> None:
    expected = canonical_json(build_screen())
    if not SCREEN_PATH.is_file() or SCREEN_PATH.read_bytes() != expected:
        raise Reject("stale or missing screen.json")
    validate_screen(json.loads(SCREEN_PATH.read_text()), verify_pins=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    if sum((args.write, args.check, args.summary)) != 1:
        parser.error("select exactly one of --write, --check, or --summary")
    if args.write:
        write_screen()
    elif args.check:
        check_screen()
    else:
        screen = build_screen()
        selected = screen["layouts"]["selected"]
        print(
            "PASS",
            f"packing={selected['packing_factor']}",
            f"core_rows={selected['row_breakdown']['core_rows']}",
            f"base_rows={selected['row_breakdown']['direct_base_rows']}",
            f"static_inner_bytes={selected['proof_screen']['static_inner_payload_bytes']}",
            "proof_bytes=null",
            "security_bits=null",
            "production=false",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
