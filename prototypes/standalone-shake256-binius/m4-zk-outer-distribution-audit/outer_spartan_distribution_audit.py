#!/usr/bin/env python3
"""Executable finite-field rejection certificate for the outer IronSpartan ZK layer.

This is a source/math audit, not a prover and not a complete ZK simulator.  It
checks the exact distribution induced by the two dummy multiplication rows,
the linear rank of the Libra mask transcript, and the source-visible BaseFold
and FRI bad-event boundaries.  A successful exit means that the fail-closed
certificate is internally consistent; it never promotes CompleteZK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from itertools import product
from pathlib import Path
from typing import Sequence


PINNED_REVISION = "3f96163049f680b2909f6545690bd929f1b48c44"
B128_ORDER = 1 << 128
DEFAULT_PINNED_CHECKOUT = Path("/private/tmp/hegemon-zk-structural-patch")
AUDIT_DIR = Path(__file__).resolve().parent


SOURCE_ANCHORS = (
    {
        "id": "CLEAR_ENDPOINTS",
        "path": "crates/spartan-prover/src/lib.rs",
        "lines": "452-478",
        "snippets": (
            "let r_mulcheck = channel.sample_many(mask.n_vars());",
            "channel.send_many(&[a_eval, b_eval, c_eval]);",
        ),
    },
    {
        "id": "DUMMY_MULTIPLICATION_TRIPLES",
        "path": "crates/spartan-prover/src/lib.rs",
        "lines": "521-537",
        "snippets": (
            "for i in 0..blinding_info.n_dummy_constraints",
            "let c = a * b;",
            "buffer.set(constraint_wire_base + 3 * i + 2, c);",
        ),
    },
    {
        "id": "TWO_PRIVATE_DUMMY_ROWS",
        "path": "crates/spartan-verifier/src/lib.rs",
        "lines": "249-260",
        "snippets": (
            "let n_test_queries = fri::calculate_n_test_queries(SECURITY_BITS, log_inv_rate);",
            "n_dummy_wires: n_test_queries,",
            "n_dummy_constraints: 2,",
        ),
    },
    {
        "id": "DUMMY_ROWS_APPENDED_BEFORE_PADDING",
        "path": "crates/spartan-verifier/src/constraint_system.rs",
        "lines": "39-95",
        "snippets": (
            "mul_constraints.push(MulConstraint",
            "mul_constraints.resize(",
            "mask_buffer_dimensions(log_mul_constraints, mask_degree, blinding_info.n_dummy_wires)",
        ),
    },
    {
        "id": "LIBRA_MASK_SHAPE",
        "path": "crates/ip-prover/src/sumcheck/zk_mlecheck.rs",
        "lines": "163-183,232-239,281-305",
        "snippets": (
            "g_at_0 = self.get_coeff(i, 0)",
            "g_at_1 = self.evaluate_univariate(i, F::ONE)",
            "round_coeffs_vec[0] += constant_offset;",
            "self.prefix_sum += self.mask.evaluate_univariate(var_idx, challenge);",
        ),
    },
    {
        "id": "LIBRA_TRANSCRIPT",
        "path": "crates/ip-prover/src/sumcheck/zk_mlecheck.rs",
        "lines": "361-407",
        "snippets": (
            "channel.send_one(mask_eval);",
            "let batch_challenge: F = channel.sample();",
            "mask_round_coeffs * batch_challenge",
            "channel.send_one(mask_eval_out);",
        ),
    },
    {
        "id": "LIBRA_VERIFIER",
        "path": "crates/ip/src/mlecheck.rs",
        "lines": "114-144",
        "snippets": (
            "let batch_challenge = channel.sample();",
            "let batch_eval = eval + batch_challenge.clone() * mask_eval;",
            "let eval_out = batch_eval_out - batch_challenge * mask_eval_out.clone();",
        ),
    },
    {
        "id": "BASEFOLD_GAMMA",
        "path": "crates/iop-prover/src/basefold/channel.rs",
        "lines": "248-334",
        "snippets": (
            "let gamma = channel.sample();",
            "*message_i = extrapolate_line(*message_i, mask_i, gamma_broadcast);",
            "extrapolate_line(claim, sigma, gamma)",
            "channel.send_many(&alphas);",
        ),
    },
    {
        "id": "RAW_FRI_OPENINGS",
        "path": "crates/iop-prover/src/fri/query.rs",
        "lines": "68-80,116-123,215-241",
        "snippets": (
            "channel.send_openings(&self.commitment, self.codeword.to_ref(), &lifted_indices);",
            "for oracle in &self.oracles",
            "self.codeword_oracle.open_queries(indices, channel);",
        ),
    },
    {
        "id": "FULL_TERMINAL_CODEWORD",
        "path": "crates/iop-prover/src/fri/fold.rs",
        "lines": "352-377",
        "snippets": (
            "let n_test_queries = self.params.n_test_queries();",
            "query_prover.prove_queries(&indices, channel);",
            "channel.send_committed_vector(&terminal_commitment, terminate_codeword.to_ref());",
        ),
    },
)


@dataclass(frozen=True)
class GF2m:
    degree: int
    reduction_low: int

    @property
    def order(self) -> int:
        return 1 << self.degree

    def add(self, left: int, right: int) -> int:
        return left ^ right

    def mul(self, left: int, right: int) -> int:
        result = 0
        mask = self.order - 1
        for _ in range(self.degree):
            if right & 1:
                result ^= left
            right >>= 1
            carry = left >> (self.degree - 1)
            left = (left << 1) & mask
            if carry:
                left ^= self.reduction_low
        return result

    def square(self, value: int) -> int:
        return self.mul(value, value)

    def pow(self, value: int, exponent: int) -> int:
        result = 1
        while exponent:
            if exponent & 1:
                result = self.mul(result, value)
            value = self.square(value)
            exponent >>= 1
        return result

    def inv(self, value: int) -> int:
        if value == 0:
            raise ZeroDivisionError("zero has no inverse")
        return self.pow(value, self.order - 2)


GF4 = GF2m(2, 0b11)  # x^2 + x + 1
GF8 = GF2m(3, 0b11)  # x^3 + x + 1


def endpoint_distribution(field: GF2m, u: int, v: int) -> Counter[tuple[int, int, int]]:
    """Distribution of two random dummy triples weighted by u and v."""
    counts: Counter[tuple[int, int, int]] = Counter()
    for a1, b1, a2, b2 in product(range(field.order), repeat=4):
        x = field.add(field.mul(u, a1), field.mul(v, a2))
        y = field.add(field.mul(u, b1), field.mul(v, b2))
        z = field.add(
            field.mul(u, field.mul(a1, b1)),
            field.mul(v, field.mul(a2, b2)),
        )
        counts[x, y, z] += 1
    return counts


def translate_distribution(
    field: GF2m,
    counts: Counter[tuple[int, int, int]],
    delta: tuple[int, int, int],
) -> Counter[tuple[int, int, int]]:
    translated: Counter[tuple[int, int, int]] = Counter()
    for point, count in counts.items():
        translated[tuple(field.add(point[i], delta[i]) for i in range(3))] += count
    return translated


def statistical_distance(
    left: Counter[tuple[int, int, int]], right: Counter[tuple[int, int, int]]
) -> Fraction:
    total = sum(left.values())
    if total != sum(right.values()):
        raise ValueError("distribution masses differ")
    keys = left.keys() | right.keys()
    return Fraction(sum(abs(left[key] - right[key]) for key in keys), 2 * total)


def translated_distance(
    field: GF2m,
    counts: Counter[tuple[int, int, int]],
    delta: tuple[int, int, int],
) -> Fraction:
    return statistical_distance(counts, translate_distribution(field, counts, delta))


def predicted_endpoint_distance(
    field: GF2m, u: int, v: int, delta: tuple[int, int, int]
) -> Fraction:
    """Closed-form translation distance, including every degenerate case."""
    q = field.order
    dx, dy, _ = delta
    if delta == (0, 0, 0):
        return Fraction(0)
    if u == 0 and v == 0:
        return Fraction(1)
    if (u == 0) ^ (v == 0):
        return Fraction(1) if dx == dy == 0 else Fraction(q - 1, q)
    if field.add(u, v) != 0:
        return Fraction(1, q) if dx == dy == 0 else Fraction(q - 1, q * q)
    return Fraction(1, q * q) if dx == dy == 0 else Fraction(2 * (q - 1), q**3)


def mixed_extension_two_weight_counterexample(field: GF2m) -> dict[str, object]:
    """Degree-three extension analogue for B128-valued dummies and E384 endpoints.

    We do not need extension multiplication: the A endpoint is B128-linear in
    the two dummy values.  Choose the two weights as the first two basis vectors
    of F^3 and translate by the third.  The two supports are disjoint cosets.
    """
    original: Counter[tuple[int, int, int]] = Counter(
        (a1, a2, 0) for a1, a2 in product(range(field.order), repeat=2)
    )
    translated: Counter[tuple[int, int, int]] = Counter(
        (a1, a2, 1) for a1, a2 in product(range(field.order), repeat=2)
    )
    distance = statistical_distance(original, translated)
    return {
        "base_field_order": field.order,
        "extension_degree": 3,
        "maximum_two_weight_span_dimension": 2,
        "translation_outside_span_tv": fraction_text(distance),
        "passed": distance == 1,
    }


def endpoint_mass_shape_holds(field: GF2m, u: int, v: int) -> bool:
    counts = endpoint_distribution(field, u, v)
    q = field.order
    if u == 0 and v == 0:
        return counts == Counter({(0, 0, 0): q**4})
    if (u == 0) ^ (v == 0):
        coefficient = u or v
        inverse = field.inv(coefficient)
        return all(
            count == q * q
            and z == field.mul(inverse, field.mul(x, y))
            for (x, y, z), count in counts.items()
        ) and len(counts) == q * q
    if field.add(u, v) != 0:
        inverse_sum = field.inv(field.add(u, v))
        for x, y, z in product(range(q), repeat=3):
            on_surface = z == field.mul(inverse_sum, field.mul(x, y))
            if counts[x, y, z] != (2 * q - 1 if on_surface else q - 1):
                return False
        return True
    for x, y, z in product(range(q), repeat=3):
        expected = q * q if (x, y, z) == (0, 0, 0) else 0 if x == y == 0 else q
        if counts[x, y, z] != expected:
            return False
    return True


def eq_weight(field: GF2m, point: Sequence[int], row: Sequence[int]) -> int:
    result = 1
    for coordinate, bit in zip(point, row, strict=True):
        factor = coordinate if bit else field.add(1, coordinate)
        result = field.mul(result, factor)
    return result


def both_nonzero_count(field_order: int, n_vars: int, distance: int) -> int:
    return (field_order - 1) ** (n_vars - distance) * (field_order - 2) ** distance


def equal_nonzero_count_char2(field_order: int, n_vars: int, distance: int) -> int:
    numerator = (field_order - 2) ** distance + (field_order - 2) * ((-1) ** distance)
    quotient, remainder = divmod(numerator, field_order - 1)
    if remainder:
        raise AssertionError("character sum must be integral")
    return (field_order - 1) ** (n_vars - distance) * quotient


def verify_eq_weight_event_formulas(field: GF2m, max_n: int = 3) -> bool:
    for n_vars in range(1, max_n + 1):
        rows = list(product(range(2), repeat=n_vars))
        for index, left in enumerate(rows):
            for right in rows[index + 1 :]:
                distance = sum(a != b for a, b in zip(left, right, strict=True))
                both_nonzero = 0
                equal_nonzero = 0
                for point in product(range(field.order), repeat=n_vars):
                    u = eq_weight(field, point, left)
                    v = eq_weight(field, point, right)
                    if u and v:
                        both_nonzero += 1
                        equal_nonzero += u == v
                if both_nonzero != both_nonzero_count(field.order, n_vars, distance):
                    return False
                if equal_nonzero != equal_nonzero_count_char2(
                    field.order, n_vars, distance
                ):
                    return False
    return True


def matrix_rank(field: GF2m, matrix: Sequence[Sequence[int]]) -> int:
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("ragged matrix")
    rows = [list(row) for row in matrix]
    pivot_row = 0
    for column in range(width):
        pivot = next(
            (row for row in range(pivot_row, len(rows)) if rows[row][column]), None
        )
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = field.inv(rows[pivot_row][column])
        rows[pivot_row] = [field.mul(value, inverse) for value in rows[pivot_row]]
        for row in range(len(rows)):
            if row == pivot_row or rows[row][column] == 0:
                continue
            factor = rows[row][column]
            rows[row] = [
                field.add(value, field.mul(factor, pivot_value))
                for value, pivot_value in zip(rows[row], rows[pivot_row], strict=True)
            ]
        pivot_row += 1
        if pivot_row == len(rows):
            break
    return pivot_row


def libra_mask_matrix(
    field: GF2m,
    eval_point: Sequence[int],
    round_point: Sequence[int],
    beta: int,
) -> list[list[int]]:
    """Rows are mask_eval, two transmitted mask coefficients/round, mask_eval_out."""
    if len(eval_point) != len(round_point):
        raise ValueError("Libra point lengths differ")
    n_vars = len(eval_point)
    initial = [0] * (3 * n_vars)
    for index, z_i in enumerate(eval_point):
        initial[3 * index] = 1
        initial[3 * index + 1] = z_i
        initial[3 * index + 2] = z_i
    rows = [initial]
    for index in range(n_vars):
        linear = [0] * (3 * n_vars)
        quadratic = [0] * (3 * n_vars)
        linear[3 * index + 1] = beta
        quadratic[3 * index + 2] = beta
        rows.extend((linear, quadratic))
    final = [0] * (3 * n_vars)
    for index, r_i in enumerate(round_point):
        final[3 * index] = 1
        final[3 * index + 1] = r_i
        final[3 * index + 2] = field.square(r_i)
    rows.append(final)
    return rows


def verify_libra_rank_formula(field: GF2m, n_vars: int = 2) -> bool:
    points = product(range(field.order), repeat=n_vars)
    for eval_point in points:
        for round_point in product(range(field.order), repeat=n_vars):
            for beta in range(1, field.order):
                if matrix_rank(
                    field, libra_mask_matrix(field, eval_point, round_point, beta)
                ) != 2 * n_vars + 1:
                    return False
            if matrix_rank(
                field, libra_mask_matrix(field, eval_point, round_point, 0)
            ) > 2:
                return False
    return True


def fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def source_checks(pinned_checkout: Path) -> dict[str, object]:
    try:
        revision = subprocess.run(
            ["git", "-C", str(pinned_checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "UNAVAILABLE"

    anchor_results = []
    for anchor in SOURCE_ANCHORS:
        source_path = pinned_checkout / str(anchor["path"])
        try:
            source = source_path.read_text()
        except OSError:
            source = ""
        missing = [snippet for snippet in anchor["snippets"] if snippet not in source]
        anchor_results.append(
            {
                "id": anchor["id"],
                "source": f"{anchor['path']}:{anchor['lines']}",
                "passed": not missing,
                "missing_snippets": missing,
            }
        )
    canonical_anchors = "\n".join(
        f"{anchor['id']}|{anchor['path']}|{anchor['lines']}|"
        + "|".join(anchor["snippets"])
        for anchor in SOURCE_ANCHORS
    )
    all_passed = revision == PINNED_REVISION and all(
        result["passed"] for result in anchor_results
    )
    return {
        "pinned_revision_expected": PINNED_REVISION,
        "pinned_revision_observed": revision,
        "anchor_set_sha256": hashlib.sha256(canonical_anchors.encode()).hexdigest(),
        "anchors": anchor_results,
        "all_passed": all_passed,
    }


def model_checks() -> dict[str, object]:
    endpoint_fields = {}
    for name, field in (("GF4", GF4), ("GF8", GF8)):
        cases = {
            "generic_distinct": (1, 2),
            "equal_nonzero": (1, 1),
            "one_zero": (1, 0),
            "both_zero": (0, 0),
        }
        results = {}
        for case, (u, v) in cases.items():
            counts = endpoint_distribution(field, u, v)
            pure_z = translated_distance(field, counts, (0, 0, 1))
            x_shift = translated_distance(field, counts, (1, 0, 0))
            expected_z = predicted_endpoint_distance(field, u, v, (0, 0, 1))
            expected_x = predicted_endpoint_distance(field, u, v, (1, 0, 0))
            results[case] = {
                "mass_shape_passed": endpoint_mass_shape_holds(field, u, v),
                "pure_z_translation_tv": fraction_text(pure_z),
                "x_translation_tv": fraction_text(x_shift),
                "translation_formulas_passed": pure_z == expected_z and x_shift == expected_x,
            }
        endpoint_fields[name] = {
            "order": field.order,
            "cases": results,
            "eq_weight_events_through_n3_passed": verify_eq_weight_event_formulas(field),
        }

    libra_gf4 = verify_libra_rank_formula(GF4, 2)
    representative_z = [0, 1, 2]
    representative_r = [3, 2, 1]
    libra_gf8_nonzero_rank = matrix_rank(
        GF8, libra_mask_matrix(GF8, representative_z, representative_r, 2)
    )
    libra_gf8_zero_rank = matrix_rank(
        GF8, libra_mask_matrix(GF8, representative_z, representative_r, 0)
    )
    all_endpoint = all(
        field_result["eq_weight_events_through_n3_passed"]
        and all(
            case["mass_shape_passed"] and case["translation_formulas_passed"]
            for case in field_result["cases"].values()
        )
        for field_result in endpoint_fields.values()
    )
    libra_passed = (
        libra_gf4 and libra_gf8_nonzero_rank == 7 and libra_gf8_zero_rank <= 2
    )
    mixed_field = mixed_extension_two_weight_counterexample(GF4)
    return {
        "endpoint": {"fields": endpoint_fields, "all_passed": all_endpoint},
        "libra": {
            "gf4_exhaustive_n2_passed": libra_gf4,
            "gf8_representative_n3_beta_nonzero_rank": libra_gf8_nonzero_rank,
            "gf8_representative_n3_beta_zero_rank": libra_gf8_zero_rank,
            "all_passed": libra_passed,
        },
        "mixed_field_two_weight_counterexample": mixed_field,
        "all_passed": all_endpoint and libra_passed and mixed_field["passed"],
    }


def run_audit(pinned_checkout: Path = DEFAULT_PINNED_CHECKOUT) -> dict[str, object]:
    checks = model_checks()
    certificate: dict[str, object] = {
        "schema": "hegemon.outer-spartan-zk-distribution-audit.v1",
        "source_checks": source_checks(pinned_checkout),
        "model_checks": checks,
        "endpoint_distribution": {
            "variables": {
                "Q": "field order",
                "n": "log2 of the padded outer multiplication-constraint count",
                "M": "outer base multiplication-constraint count before the two dummy rows",
                "d": "HammingWeight(M xor (M+1)) = 1 + trailing_ones(M)",
                "u_v": "eq(M,r), eq(M+1,r) at the exposed reduced point r",
            },
            "conditional_cases": {
                "u_v_u_plus_v_nonzero": {
                    "mass": "(2Q-1)/Q^4 on z=x*y/(u+v), (Q-1)/Q^4 otherwise",
                    "pure_c_translation_tv": "1/Q",
                    "translation_with_nonzero_a_or_b_tv": "(Q-1)/Q^2",
                },
                "u_v_nonzero_u_plus_v_zero": {
                    "scope": "in characteristic two this is u=v!=0",
                    "mass": "1/Q^2 at (0,0,0), 0 at (0,0,z!=0), 1/Q^3 otherwise",
                    "pure_c_translation_tv": "1/Q^2",
                    "translation_with_nonzero_a_or_b_tv": "2(Q-1)/Q^3",
                },
                "exactly_one_of_u_v_zero": {
                    "mass": "uniform on the multiplication graph z=x*y/nonzero_weight",
                    "pure_c_translation_tv": "1",
                    "translation_with_nonzero_a_or_b_tv": "1-1/Q",
                },
                "u_v_both_zero": {"mass": "point mass", "nonzero_translation_tv": "1"},
            },
            "challenge_events": {
                "G_both_nonzero": "(1-1/Q)^(n-d) * (1-2/Q)^d",
                "E_equal_nonzero_char2": "((Q-1)^(n-d)/Q^n) * (((Q-2)^d + (Q-2)(-1)^d)/(Q-1))",
                "exact_joint_pure_c_tv": "(1-G) + (G-E)/Q + E/Q^2",
                "simple_upper_bound": "(1-G) + 1/Q",
            },
            "actual_outer_tier": {
                "n_compiled": False,
                "M_compiled": False,
                "d_compiled": False,
                "reason": "the maximum outer Hegemon relation tier was not compiled under this source/math-only task",
            },
            "b128": {
                "field_order": "2^128",
                "asymptotic_pure_c_tv": "approximately (n+d+1)*2^-128",
                "single_event_only_128_bit_scale": True,
                "strict_composed_pq128": False,
            },
            "strict_mixed_field_endpoint": {
                "same_field_formula_applies": False,
                "dummy_value_field": "B128",
                "endpoint_weight_field": "E384",
                "extension_dimension_over_b128": 3,
                "two_dummy_a_endpoint_support": "Span_B128{u,v}, dimension at most 2",
                "counterexample": "for any allowed witness translation delta_A outside Span_B128{u,v}, the A-endpoint supports are disjoint cosets and joint TV is exactly 1",
                "minimum_linear_coverage_requirement": "at least three B128-linearly independent dummy weights are necessary for A/B coverage",
                "three_rows_sufficient_for_joint_abc": False,
                "reason": "the correlated C=sum_i u_i*a_i*b_i distribution still requires a new extension-field proof",
                "current_two_rows_strict_statistical_zk": False,
            },
        },
        "libra": {
            "mask_coefficients": "g_i(X)=g_i0+g_i1*X+g_i2*X^2",
            "mask_eval": "sum_i(g_i0 + z_i*g_i1 + z_i*g_i2)",
            "transmitted_round_mask_rows": "beta*g_i1 and beta*g_i2 for each of n rounds",
            "mask_eval_out": "sum_i(g_i0 + r_i*g_i1 + r_i^2*g_i2)",
            "beta_nonzero_rank": "2n+1 of 2n+2 rows",
            "unique_linear_relation": "mask_eval_out-mask_eval = sum_i((r_i-z_i)/beta)*(beta*g_i1) + ((r_i^2-z_i)/beta)*(beta*g_i2)",
            "conditional_local_verdict": "the mask image is exactly the valid-transcript consistency hyperplane when beta!=0",
            "bad_events": [
                {
                    "coefficient": "beta",
                    "value": "0",
                    "probability": "1/Q",
                    "effect": "all 2n main round coefficients are unmasked; mask-map rank is at most 2",
                }
            ],
            "other_z_or_r_zero_events": "none for this linear rank; the proof never divides by z_i or r_i",
            "adaptive_fiat_shamir_simulator_proved": False,
        },
        "basefold": {
            "masked_message": "pi'=(1-gamma)*pi + gamma*omega",
            "masked_claim": "s'=(1-gamma)*s + gamma*sigma, sigma=<omega,T>",
            "bad_events": [
                {
                    "coefficient": "gamma",
                    "value": "0",
                    "probability": "1/Q",
                    "property": "privacy",
                    "effect": "pi'=pi and s'=s; the first FRI unbatch selects the witness codeword",
                },
                {
                    "coefficient": "1-gamma",
                    "value": "0 (gamma=1)",
                    "probability": "1/Q",
                    "property": "soundness",
                    "effect": "pi'=omega and s'=sigma; the opening no longer checks the committed witness half",
                },
            ],
            "gamma_nonzero_local_privacy_coefficient_invertible": True,
            "sigma_alpha_fri_merkle_joint_simulator_proved": False,
            "gamma_rejection_or_nonzero_sampler_present": False,
            "strict_mixed_field_seam": "existing BaseFold is same-BinaryField only; an E384 gamma applied to B128 pi/omega widens the folded values unless a coefficient-lane PCS is proved",
        },
        "dummy_wire_openings": {
            "source_configuration": "n_dummy_wires = n_test_queries",
            "dimensionally_necessary": True,
            "sufficient_rank_proved": False,
            "required_missing_certificate": "for every admitted query transcript, prove full row rank of the map from dummy coordinates to all distinct raw message-codeword openings and every terminal linear view, then construct the joint simulator",
            "source_observation": "FRI opens each original committed codeword directly for every sampled query and sends the terminal codeword in full",
            "duplicate_queries": "reduce the number of distinct raw constraints but do not replace the missing all-transcript rank proof",
        },
        "security_accounting": {
            "privacy_bad_events": ["endpoint u=0 or v=0", "Libra beta=0", "BaseFold gamma=0"],
            "soundness_bad_events": ["BaseFold gamma=1"],
            "b128_union_floor": "endpoint exact TV + 1/Q for beta=0 + 1/Q for gamma=0, before PCS/FRI and QROM losses",
            "strict_field_requirement": "E384 (not three independent B128 coordinates) plus a composed QROM proof",
        },
        "assumptions": {
            "grouped_precommit_private_repair_applied": "assumed; this audit does not verify that separate patch",
            "challenge_model": "independent uniform finite-field challenges; abort-conditioned ROM/QROM behavior is open",
            "same_statement_witness_translation": True,
        },
        "claims": {
            "endpoint_distribution_derived": True,
            "libra_linear_rank_derived": True,
            "current_parameters_complete_statistical_zk_certified": False,
            "basefold_joint_simulator_proved": False,
            "full_outer_spartan_simulator_proved": False,
            "qrom_composed": False,
            "strict_pq128": False,
            "complete_zk": False,
        },
        "decision": {
            "status": "REJECT_COMPLETE_ZK_OUTER_LOCAL_DISTRIBUTIONS_ONLY",
            "frontier_eligible": False,
            "reason_codes": [
                "B128_UNION_LOSS_BELOW_STRICT_128",
                "TWO_B128_DUMMIES_DO_NOT_SPAN_E384_ENDPOINT",
                "DUMMY_WIRE_OPENING_RANK_UNPROVED",
                "BASEFOLD_JOINT_SIMULATOR_OPEN",
                "OUTER_ADAPTIVE_SIMULATOR_OPEN",
                "QROM_COMPOSITION_OPEN",
                "STRICT_E384_BACKEND_OPEN",
            ],
        },
    }
    validate_certificate(certificate)
    return certificate


def validate_certificate(certificate: dict[str, object]) -> None:
    if certificate.get("schema") != "hegemon.outer-spartan-zk-distribution-audit.v1":
        raise ValueError("unexpected schema")
    source = certificate["source_checks"]
    models = certificate["model_checks"]
    claims = certificate["claims"]
    decision = certificate["decision"]
    dummy = certificate["dummy_wire_openings"]
    endpoint = certificate["endpoint_distribution"]
    if not source["all_passed"]:
        raise ValueError("pinned source anchors failed")
    if not models["all_passed"]:
        raise ValueError("finite-field model checks failed")
    if claims["current_parameters_complete_statistical_zk_certified"]:
        raise ValueError("current parameters cannot be promoted without the opening rank and simulator")
    if claims["complete_zk"] or claims["strict_pq128"]:
        raise ValueError("complete_zk/strict_pq128 reward hack")
    if dummy["sufficient_rank_proved"]:
        raise ValueError("dummy-wire FRI opening rank is not proved")
    if endpoint["b128"]["strict_composed_pq128"]:
        raise ValueError("B128 union accounting is not strict PQ128")
    if endpoint["strict_mixed_field_endpoint"]["current_two_rows_strict_statistical_zk"]:
        raise ValueError("two B128 dummy weights cannot span an E384 endpoint")
    if decision["frontier_eligible"]:
        raise ValueError("audit certificate is not frontier eligible")


def load_frozen_certificate() -> dict[str, object]:
    return json.loads((AUDIT_DIR / "certificate.json").read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pinned-checkout", type=Path, default=DEFAULT_PINNED_CHECKOUT)
    parser.add_argument("--json", action="store_true", help="print the generated certificate")
    parser.add_argument(
        "--check-certificate", action="store_true", help="compare against certificate.json"
    )
    args = parser.parse_args()

    certificate = run_audit(args.pinned_checkout)
    if args.check_certificate and certificate != load_frozen_certificate():
        raise SystemExit("frozen certificate does not match executable audit")
    if args.json:
        print(json.dumps(certificate, indent=2, sort_keys=True))
    else:
        print("endpoint_distribution=exact")
        print("libra_rank=conditional_beta_nonzero")
        print("dummy_wire_opening_rank=unproved")
        print("complete_zk=false")
        print("strict_pq128=false")


if __name__ == "__main__":
    main()
