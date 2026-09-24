#!/usr/bin/env python3
"""Executable checks for a parametric repair of CFW26 Construction 11.4.

The repaired family uses a public nonzero field element ``c`` in every inner
mask occurrence.  Hegemon's candidate selects ``c = 1`` and Definition 5.4's
``times(identity)``.  This module checks only finite-field algebra, affine-map
ranks, and explicit counterexamples to unsupported proof steps.  It is not an
IOR, an encoding implementation, or a cryptographic proof.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
from collections import Counter
from fractions import Fraction
from typing import Iterable, Sequence


SCHEMA = "hegemon.cfw26-parametric-repair-proof.experiment.v1"
HEGEMON_C = 1


class AuditError(ValueError):
    pass


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))


def require_prime(prime: int) -> None:
    if not is_prime(prime):
        raise AuditError(f"expected a prime field modulus, got {prime}")


def poly_eval(coefficients: Sequence[int], point: int, prime: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * point + coefficient) % prime
    return result


def endpoint_zero_polynomials(prime: int, length: int) -> Iterable[tuple[int, ...]]:
    require_prime(prime)
    if length < 2:
        raise AuditError("endpoint-zero polynomials need at least two coefficients")
    for tail in itertools.product(range(prime), repeat=length - 2):
        yield (0, (-sum(tail)) % prime, *tail)


def value_histogram(prime: int, length: int, alpha: int, coefficient: int) -> Counter[int]:
    return Counter(
        coefficient * poly_eval(polynomial, alpha, prime) % prime
        for polynomial in endpoint_zero_polynomials(prime, length)
    )


def matrix_rank(matrix: Sequence[Sequence[int]], prime: int) -> int:
    require_prime(prime)
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise AuditError("ragged matrix")
    work = [[value % prime for value in row] for row in matrix]
    rank = 0
    for column in range(width):
        pivot = next((row for row in range(rank, len(work)) if work[row][column]), None)
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        inverse = pow(work[rank][column], -1, prime)
        work[rank] = [value * inverse % prime for value in work[rank]]
        for row in range(len(work)):
            if row == rank or work[row][column] == 0:
                continue
            factor = work[row][column]
            work[row] = [
                (left - factor * right) % prime
                for left, right in zip(work[row], work[rank])
            ]
        rank += 1
        if rank == len(work):
            break
    return rank


def _zero_masks(rounds: int, length: int) -> list[list[int]]:
    return [[0] * length for _ in range(rounds)]


def outer_transcript_linear_part(
    masks: Sequence[Sequence[int]], alpha: Sequence[int], prime: int
) -> tuple[int, ...]:
    """Map outer masks to (mu_tilde, all h coefficients, all evaluations).

    This is exactly the mask-linear part of Construction 11.4 Steps 4, 6,
    and 7.  The inner/R1CS term is an affine constant and is intentionally
    omitted.  The output order is ``mu, h_1, ..., h_d, eval_1, ..., eval_d``.
    """

    require_prime(prime)
    rounds = len(masks)
    if rounds < 1 or len(alpha) != rounds:
        raise AuditError("outer map arity mismatch")
    length = len(masks[0])
    if length < 1 or any(len(mask) != length for mask in masks):
        raise AuditError("outer masks must have one common positive length")

    mu_tilde = 0
    for bits in itertools.product((0, 1), repeat=rounds):
        mu_tilde += sum(
            poly_eval(masks[index], bits[index], prime) for index in range(rounds)
        )
    mu_tilde %= prime

    h_coefficients: list[int] = []
    for round_index in range(rounds):
        coefficients = [0] * length
        remaining = rounds - round_index - 1
        for suffix in itertools.product((0, 1), repeat=remaining):
            constant = sum(
                poly_eval(masks[index], alpha[index], prime)
                for index in range(round_index)
            )
            constant += sum(
                poly_eval(masks[index], suffix[index - round_index - 1], prime)
                for index in range(round_index + 1, rounds)
            )
            coefficients[0] = (coefficients[0] + constant) % prime
            for coefficient_index, value in enumerate(masks[round_index]):
                coefficients[coefficient_index] = (
                    coefficients[coefficient_index] + value
                ) % prime
        h_coefficients.extend(coefficients)

    evaluations = [
        poly_eval(mask, alpha[index], prime) for index, mask in enumerate(masks)
    ]
    return (mu_tilde, *h_coefficients, *evaluations)


def outer_map_matrix(
    prime: int, rounds: int, length: int, alpha: Sequence[int]
) -> list[list[int]]:
    input_dimension = rounds * length
    columns: list[tuple[int, ...]] = []
    for flat_index in range(input_dimension):
        masks = _zero_masks(rounds, length)
        masks[flat_index // length][flat_index % length] = 1
        columns.append(outer_transcript_linear_part(masks, alpha, prime))
    output_dimension = 1 + rounds * length + rounds
    return [
        [columns[column][row] for column in range(input_dimension)]
        for row in range(output_dimension)
    ]


def _h_offset(round_index: int, length: int) -> int:
    return 1 + round_index * length


def _evaluation_offset(rounds: int, length: int) -> int:
    return 1 + rounds * length


def outer_constraint_matrix(
    prime: int, rounds: int, length: int, alpha: Sequence[int]
) -> list[list[int]]:
    """Homogeneous constraints defining the affine transcript space T(v)."""

    require_prime(prime)
    if len(alpha) != rounds:
        raise AuditError("constraint alpha arity mismatch")
    width = 1 + rounds * length + rounds
    rows: list[list[int]] = []

    # h_1(0) + h_1(1) = mu_tilde.
    row = [0] * width
    row[0] = -1 % prime
    h0 = _h_offset(0, length)
    row[h0] = 2 % prime
    for coefficient in range(1, length):
        row[h0 + coefficient] = 1
    rows.append(row)

    # h_j(0) + h_j(1) = h_{j-1}(alpha_{j-1}).
    for round_index in range(1, rounds):
        row = [0] * width
        current = _h_offset(round_index, length)
        previous = _h_offset(round_index - 1, length)
        row[current] = 2 % prime
        for coefficient in range(1, length):
            row[current + coefficient] = 1
        for coefficient, value in enumerate(
            _powers(alpha[round_index - 1], length, prime)
        ):
            row[previous + coefficient] = (
                row[previous + coefficient] - value
            ) % prime
        rows.append(row)

    # sum_j eval_j = h_d(alpha_d), after removing the fixed R1CS affine term.
    row = [0] * width
    final_h = _h_offset(rounds - 1, length)
    for coefficient, value in enumerate(_powers(alpha[-1], length, prime)):
        row[final_h + coefficient] = -value % prime
    eval_offset = _evaluation_offset(rounds, length)
    for index in range(rounds):
        row[eval_offset + index] = 1
    rows.append(row)
    return rows


def _powers(value: int, length: int, prime: int) -> tuple[int, ...]:
    result: list[int] = []
    accumulator = 1
    for _ in range(length):
        result.append(accumulator)
        accumulator = accumulator * value % prime
    return tuple(result)


def matrix_product(
    left: Sequence[Sequence[int]], right: Sequence[Sequence[int]], prime: int
) -> list[list[int]]:
    if not left or not right:
        return []
    if len(left[0]) != len(right):
        raise AuditError("matrix product shape mismatch")
    columns = len(right[0])
    return [
        [
            sum(left_value * right[row][column] for row, left_value in enumerate(left_row))
            % prime
            for column in range(columns)
        ]
        for left_row in left
    ]


def outer_rank_case(prime: int, rounds: int, length: int) -> dict[str, int | bool]:
    # For every retained odd field, 2 is an allowed final challenge outside
    # {0,1}.  Characteristic two is deliberately an impossible-domain
    # negative control.
    alpha = (2 % prime,) * rounds
    map_matrix = outer_map_matrix(prime, rounds, length, alpha)
    constraints = outer_constraint_matrix(prime, rounds, length, alpha)
    product = matrix_product(constraints, map_matrix, prime)
    output_dimension = 1 + rounds * length + rounds
    constraint_rank = matrix_rank(constraints, prime)
    return {
        "prime": prime,
        "rounds": rounds,
        "length": length,
        "input_dimension": rounds * length,
        "output_dimension": output_dimension,
        "map_rank": matrix_rank(map_matrix, prime),
        "constraint_rank": constraint_rank,
        "constraint_kernel_dimension": output_dimension - constraint_rank,
        "image_satisfies_constraints": all(value == 0 for row in product for value in row),
    }


def initial_rbr_degree_counterexample(
    prime: int = 101, rounds: int = 10, inner_length: int = 4, outer_length: int = 8
) -> dict[str, object]:
    """Counterexample to replacing the initial degree by outer_length.

    An invalid R1CS can have Boolean residual one only at the all-one row.  Its
    multilinear extension is P(r)=prod_i r_i.  With a matching outer target,
    the initial consistency equation accepts iff epsilon*P(r)=0.
    """

    require_prime(prime)
    if outer_length < 2 * inner_length:
        raise AuditError("counterexample must retain the paper's outer-length premise")
    actual = Fraction(prime ** (rounds + 1) - (prime - 1) ** (rounds + 1), prime ** (rounds + 1))
    printed_bound = Fraction(outer_length + 1, prime)
    dimension_bound = Fraction(rounds + 1, prime)
    return {
        "prime": prime,
        "rounds_d": rounds,
        "ell": 1 << (rounds - 1),
        "inner_length": inner_length,
        "outer_length": outer_length,
        "paper_length_premise_holds": outer_length >= 2 * inner_length
        and inner_length >= 4,
        "invalid_residual_mle": "P(r)=product_i r_i",
        "sparse_r1cs_realization": (
            "take z_0=1 and every other assignment coordinate zero; set only the "
            "first column so A*z=B*z=1 on every row and C*z=1 except C*z=0 "
            "at the all-one row"
        ),
        "committed_messages": (
            "encode the zero witness and choose every inner and outer mask message zero"
        ),
        "accepting_path_when_initial_polynomial_vanishes": (
            "run honest sumcheck for the actual invalid residual polynomial; reveal v_M=u_M; "
            "all endpoint, outer-evaluation, terminal-sumcheck, and joint target equations hold"
        ),
        "source_relation_has_no_witness": True,
        "downstream_target_relation_has_witness_on_accepting_event": True,
        "acceptance_probability": _fraction_record(actual),
        "printed_first_coordinate_without_list_factor": _fraction_record(printed_bound),
        "dimension_aware_schwartz_zippel_bound": _fraction_record(dimension_bound),
        "violates_printed_bound": actual > printed_bound,
        "respects_dimension_aware_bound": actual <= dimension_bound,
    }


def degree_ledger(rounds: int, inner_length: int, outer_length: int) -> dict[str, int | bool]:
    if rounds < 1 or inner_length < 2 or outer_length < 1:
        raise AuditError("invalid degree-ledger parameters")
    # In one sumcheck variable, each masked matrix factor has degree at most
    # inner_length-1.  A*B has degree at most 2*inner_length-2 and eq adds one.
    terminal_univariate_degree = 2 * inner_length - 1
    return {
        "rounds_d": rounds,
        "inner_length": inner_length,
        "outer_length": outer_length,
        "maximum_h_univariate_degree": terminal_univariate_degree,
        "h_space_maximum_degree": outer_length - 1,
        "outer_length_closes_h_degree": outer_length >= 2 * inner_length,
        "initial_consistency_total_degree": rounds + 1,
        "printed_initial_numerator": outer_length + 1,
        "printed_initial_bound_has_needed_dimension_domination": outer_length >= rounds,
    }


def _fraction_record(value: Fraction) -> dict[str, int | float | str]:
    return {
        "exact": f"{value.numerator}/{value.denominator}",
        "numerator": value.numerator,
        "denominator": value.denominator,
        "decimal": float(value),
    }


def pointer_encoding_word(prime: int, message: int, pointer: int) -> tuple[int, ...]:
    """A toy randomized encoding separating fixed-set and adaptive queries."""

    require_prime(prime)
    if not 0 <= message < prime or not 0 <= pointer < prime:
        raise AuditError("non-canonical pointer-encoding input")
    word = [0] * (prime + 1)
    word[0] = pointer
    word[1 + pointer] = message
    return tuple(word)


def observation_distribution(
    prime: int, message: int, positions: Sequence[int]
) -> Counter[tuple[int, ...]]:
    if len(set(positions)) != len(positions):
        raise AuditError("duplicate query positions")
    if any(position < 0 or position > prime for position in positions):
        raise AuditError("query position out of range")
    return Counter(
        tuple(pointer_encoding_word(prime, message, pointer)[position] for position in positions)
        for pointer in range(prime)
    )


def statistical_distance_counts(
    first: Counter[tuple[int, ...]], second: Counter[tuple[int, ...]]
) -> Fraction:
    first_total = sum(first.values())
    second_total = sum(second.values())
    if first_total != second_total or first_total == 0:
        raise AuditError("distribution totals mismatch")
    keys = set(first) | set(second)
    return Fraction(
        sum(abs(first[key] - second[key]) for key in keys), 2 * first_total
    )


def adaptive_query_counterexample(prime: int = 11, query_bound: int = 2) -> dict[str, object]:
    """Show Definition 3.16's fixed-set simulator does not imply online ZK."""

    if query_bound != 2:
        raise AuditError("retained pointer example is specialized to two queries")
    require_prime(prime)
    # Sim(message=0) is one simulator for every message and every fixed set.
    # We enumerate the full Definition-3.16 quantifier over messages and sets,
    # rather than comparing just one convenient pair of messages.
    max_fixed = Fraction(0, 1)
    maximizing_message = 0
    maximizing_set: tuple[int, ...] = ()
    positions = range(prime + 1)
    for message in range(prime):
        for size in range(query_bound + 1):
            for query_set in itertools.combinations(positions, size):
                simulated = observation_distribution(prime, 0, query_set)
                real = observation_distribution(prime, message, query_set)
                distance = statistical_distance_counts(simulated, real)
                if distance > max_fixed:
                    max_fixed = distance
                    maximizing_message = message
                    maximizing_set = query_set

    encoded_words = {
        pointer_encoding_word(prime, message, pointer)
        for message in range(prime)
        for pointer in range(prime)
    }

    # The online strategy first reads the pointer and then its indicated cell.
    adaptive_one = Counter((pointer, 1) for pointer in range(prime))
    adaptive_two = Counter((pointer, 2) for pointer in range(prime))
    adaptive_distance = statistical_distance_counts(adaptive_one, adaptive_two)
    return {
        "prime": prime,
        "query_bound": query_bound,
        "message_length": 1,
        "randomness_length": 1,
        "block_length": prime + 1,
        "encoding_is_injective": len(encoded_words) == prime * prime,
        "fixed_set_simulator": "use the message-0 marginal for the chosen set",
        "all_messages_and_fixed_sets_enumerated": True,
        "maximum_fixed_set_distance": _fraction_record(max_fixed),
        "maximizing_message": maximizing_message,
        "maximizing_fixed_set": list(maximizing_set),
        "adaptive_strategy": "query position 0 for pointer J, then query position 1+J",
        "adaptive_distance": _fraction_record(adaptive_distance),
        "fixed_set_bound_does_not_imply_adaptive_bound": adaptive_distance > max_fixed,
    }


def factor_c_experiment() -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for prime in (5, 7, 11):
        for coefficient in range(prime):
            histogram = value_histogram(prime, 4, 2, coefficient)
            cases.append(
                {
                    "prime": prime,
                    "c": coefficient,
                    "nonzero": coefficient != 0,
                    "support": len(histogram),
                    "uniform": len(set(histogram.values())) == 1,
                    "expected_full_support": coefficient != 0,
                }
            )
    summaries = [
        {
            "prime": prime,
            "coefficients_checked": prime,
            "nonzero_coefficients_checked": prime - 1,
            "all_nonzero_full_support_uniform": all(
                case["support"] == prime and case["uniform"]
                for case in cases
                if case["prime"] == prime and case["nonzero"]
            ),
            "zero_coefficient_support": next(
                case["support"]
                for case in cases
                if case["prime"] == prime and not case["nonzero"]
            ),
        }
        for prime in (5, 7, 11)
    ]
    return {
        "hegemon_selected_c": HEGEMON_C,
        "fields": summaries,
        "total_coefficients_checked": len(cases),
        "all_nonzero_coefficients_are_uniform": all(
            case["support"] == case["prime"] and case["uniform"]
            for case in cases
            if case["nonzero"]
        ),
        "all_zero_coefficients_collapse": all(
            case["support"] == 1 for case in cases if not case["nonzero"]
        ),
    }


def endpoint_state_counterexample(prime: int = 5, length: int = 4) -> dict[str, object]:
    """Separate polynomial evaluation at one from the printed basis vector."""

    require_prime(prime)
    if length < 3:
        raise AuditError("X^2-X counterexample needs at least three coefficients")
    polynomial = (0, -1 % prime, 1, *((0,) * (length - 3)))
    printed_st1 = (1, *((0,) * (length - 1)))
    printed_st2 = (0, 1, *((0,) * (length - 2)))
    repaired_st2 = (1,) * length
    dot = lambda left, right: sum(a * b for a, b in zip(left, right)) % prime
    return {
        "prime": prime,
        "coefficient_vector": list(polynomial),
        "polynomial": "X^2-X",
        "evaluation_at_zero": poly_eval(polynomial, 0, prime),
        "evaluation_at_one": poly_eval(polynomial, 1, prime),
        "printed_st1_dot": dot(printed_st1, polynomial),
        "printed_st2": list(printed_st2),
        "printed_st2_dot": dot(printed_st2, polynomial),
        "repaired_st2_pow_one": list(repaired_st2),
        "repaired_st2_dot": dot(repaired_st2, polynomial),
        "printed_endpoint_relation_rejects_honest_mask": dot(printed_st2, polynomial) != 0,
        "repaired_endpoint_relation_accepts_honest_mask": dot(repaired_st2, polynomial) == 0,
    }


def factor_occurrence_ledger() -> dict[str, object]:
    """Classify every semantically distinct occurrence of a factor two.

    Repeated occurrences of one semantic term (for example, the same mask
    coefficient in the Step-8 value line and the page-71 value proof) are
    individually named.  Structural twos are retained, not rewritten as c.
    """

    return {
        "replace_by_c": [
            {
                "site": "Construction 11.4 Step 8 second displayed equality",
                "source_term": "2 * sum_i s_(M,i)(alpha_i)",
                "repair": "c * sum_i s_(M,i)(alpha_i)",
                "requires_matching_changes": ["Step 3", "Step 6", "Step 9"],
            },
            {
                "site": "Theorem 11.3 HVZK proof page 71 value decomposition",
                "source_term": "2 * sum_i s_(M,i)(alpha_i)",
                "repair": "c * sum_i s_(M,i)(alpha_i)",
                "preserved_exactly_when": "c != 0",
            },
            {
                "site": "Theorem 11.3 HVZK proof page 71 conditioned last-mask value",
                "source_term": "const_M + 2 * s_(M,d)(alpha_d)",
                "repair": "const_M + c * s_(M,d)(alpha_d)",
                "preserved_exactly_when": "c != 0",
            },
        ],
        "retain_structural_two": [
            {
                "site": "Theorem 11.3 and Lemma 6.4 characteristic premise",
                "term": "char(F) != 2",
                "reason": "needed by the outer-mask powers-of-two rank argument even when c=1",
            },
            {
                "site": "Theorem 11.3 length premise",
                "term": "L_out >= 2 * L_in",
                "reason": "bounds the quadratic masked-factor degree; unrelated to coefficient c",
            },
            {
                "site": "Lemma 6.4 outer affine map",
                "term": "2^(d-j) multiplicities",
                "reason": "counts Boolean suffix assignments and must remain invertible",
            },
            {
                "site": "Construction 11.4 final challenge and RBR denominator",
                "term": "alpha_d in F minus {0,1}, denominator |F|-2",
                "reason": "excludes both roots of endpoint-zero masks",
            },
            {
                "site": "Construction 11.4 R1CS geometry",
                "term": "2*ell rows/columns and log2(ell)+1 variables",
                "reason": "encodes the public/witness concatenation geometry",
            },
            {
                "site": "Construction 11.4 multilinear extensions",
                "term": "individual degree < 2 and Boolean domain {0,1}",
                "reason": "defines multilinear interpolation, not a mask scalar",
            },
            {
                "site": "Definition 11.1 inner endpoint form",
                "term": "two endpoint rows",
                "reason": "enforces evaluation at zero and one",
            },
            {
                "site": "ACFY25 Appendix A source RBR geometry",
                "term": "n=2k and the quadratic R1CS predicate",
                "reason": "source-reduction geometry/degree; replacement by c is inapplicable",
            },
        ],
        "introduced_c_occurrences": [
            "Step 3 A mask sum",
            "Step 3 B mask sum",
            "Step 3 C mask sum",
            "Step 6 inherited partial polynomial",
            "Step 8 defining value for A",
            "Step 8 defining value for B",
            "Step 8 defining value for C",
            "Step 8 decomposition equality",
            "Step 9 each of 3d inner joint forms",
            "page-71 value distribution argument",
            "conditional RBR terminal discrepancy",
        ],
        "hegemon_selected_c": HEGEMON_C,
        "selection_is_author_erratum": False,
    }


def build_report() -> dict[str, object]:
    odd_rank_cases = [
        outer_rank_case(prime, rounds, length)
        for prime in (5, 7, 11)
        for rounds in (1, 2, 3, 4)
        for length in (4, 5, 8)
    ]
    characteristic_two_cases = [outer_rank_case(2, rounds, 4) for rounds in (2, 3, 4)]
    return {
        "schema": SCHEMA,
        "claim_boundary": (
            "Parametric algebra, formal-class HVZK delta, and counterexamples only; "
            "no inherited Theorem 11.3, adaptive complete ZK, QROM, PQ128, or production authority."
        ),
        "factor_c": factor_c_experiment(),
        "factor_occurrences": factor_occurrence_ledger(),
        "endpoint_state_counterexample": endpoint_state_counterexample(),
        "main_linear_form_typing": {
            "printed_form": "identity",
            "printed_state": "full matrix description M (alpha omitted)",
            "required_output_dimension": "ell witness-column coefficients",
            "repair": "row_M(M,alpha)[b] = MLE_M(alpha,(b,1))",
            "printed_literal_well_typed": False,
            "parametric_restatement_well_typed": True,
        },
        "outer_transcript": {
            "odd_characteristic_primes": [5, 7, 11],
            "round_counts": [1, 2, 3, 4],
            "message_lengths": [4, 5, 8],
            "odd_characteristic_case_count": len(odd_rank_cases),
            "all_odd_images_equal_constraint_kernels": all(
                case["image_satisfies_constraints"]
                and case["map_rank"] == case["input_dimension"]
                and case["constraint_kernel_dimension"] == case["input_dimension"]
                for case in odd_rank_cases
            ),
            "characteristic_two_negative_controls": [
                {
                    "rounds": case["rounds"],
                    "input_dimension": case["input_dimension"],
                    "map_rank": case["map_rank"],
                    "constraint_kernel_dimension": case["constraint_kernel_dimension"],
                }
                for case in characteristic_two_cases
            ],
            "some_characteristic_two_rank_collapses": any(
                case["map_rank"] < case["input_dimension"]
                for case in characteristic_two_cases
            ),
        },
        "degree_ledger": {
            "counterexample_case": degree_ledger(10, 4, 8),
            "hegemon_scale_example_d26": degree_ledger(26, 4, 8),
            "repair_options": [
                "replace the first RBR numerator by d+1",
                "or add the missing premise outer_length >= d",
            ],
        },
        "initial_rbr_degree_counterexample": initial_rbr_degree_counterexample(),
        "adaptive_query_counterexample": adaptive_query_counterexample(),
        "profile_counts": {
            "ell": 1 << 25,
            "d_log2_ell_plus_one": 26,
            "inner_oracles": 78,
            "outer_oracles": 26,
            "main_oracles": 1,
            "encoding_hybrid_terms": 105,
            "printed_rbr_error_coordinates": 29,
        },
        "authority": {
            "parametric_construction_well_typed_for_nonzero_c": True,
            "perfect_completeness_proved": True,
            "outer_transcript_affine_bijection_proved_in_odd_characteristic": True,
            "value_slice_uniform_for_nonzero_c": True,
            "formal_nonadaptive_whole_hvzk_conditional_on_encoding_zk": True,
            "printed_rbr_error_vector_proved": False,
            "full_rbr_theorem_proved": False,
            "adaptive_query_hvzk_proved": False,
            "theorem_11_3_inherited": False,
            "complete_zero_knowledge": False,
            "qrom_security": False,
            "pq128_composition": False,
            "production_authorized": False,
        },
    }


def self_check(report: dict[str, object] | None = None) -> None:
    report = build_report() if report is None else report
    factor = report["factor_c"]
    if not factor["all_nonzero_coefficients_are_uniform"]:
        raise AssertionError("a nonzero coefficient lost value hiding")
    if not factor["all_zero_coefficients_collapse"]:
        raise AssertionError("zero-coefficient negative control")
    endpoint = report["endpoint_state_counterexample"]
    if not endpoint["printed_endpoint_relation_rejects_honest_mask"]:
        raise AssertionError("printed endpoint-state defect disappeared")
    if not endpoint["repaired_endpoint_relation_accepts_honest_mask"]:
        raise AssertionError("pow(1) endpoint repair failed")
    if report["main_linear_form_typing"]["printed_literal_well_typed"]:
        raise AssertionError("main identity abuse was promoted to a typed form")
    outer = report["outer_transcript"]
    if not outer["all_odd_images_equal_constraint_kernels"]:
        raise AssertionError("outer affine-map proof matrix failed")
    if not outer["some_characteristic_two_rank_collapses"]:
        raise AssertionError("outer characteristic-two negative control")
    degree = report["initial_rbr_degree_counterexample"]
    if not degree["paper_length_premise_holds"] or not degree["violates_printed_bound"]:
        raise AssertionError("initial RBR degree counterexample")
    if not degree["respects_dimension_aware_bound"]:
        raise AssertionError("dimension-aware replacement bound")
    degree_cases = report["degree_ledger"]
    for case in (
        degree_cases["counterexample_case"],
        degree_cases["hegemon_scale_example_d26"],
    ):
        if not case["outer_length_closes_h_degree"]:
            raise AssertionError("per-round h degree no longer closes")
        if case["printed_initial_bound_has_needed_dimension_domination"]:
            raise AssertionError("negative degree-premise case unexpectedly closes")
    adaptive = report["adaptive_query_counterexample"]
    if not adaptive["encoding_is_injective"]:
        raise AssertionError("pointer encoding is not injective")
    if not adaptive["all_messages_and_fixed_sets_enumerated"]:
        raise AssertionError("fixed-set premise was not exhaustively checked")
    if adaptive["maximum_fixed_set_distance"]["exact"] != "2/11":
        raise AssertionError("unexpected universal fixed-set distance")
    if not adaptive["fixed_set_bound_does_not_imply_adaptive_bound"]:
        raise AssertionError("adaptive-query separation")
    if adaptive["adaptive_distance"]["exact"] != "1/1":
        raise AssertionError("adaptive-query separation is not perfect")
    counts = report["profile_counts"]
    if counts["encoding_hybrid_terms"] != 105:
        raise AssertionError("Hegemon-scale encoding-hybrid count")
    if counts["printed_rbr_error_coordinates"] != 29:
        raise AssertionError("Hegemon-scale RBR-coordinate count")
    authority = report["authority"]
    allowed_true = {
        "parametric_construction_well_typed_for_nonzero_c",
        "perfect_completeness_proved",
        "outer_transcript_affine_bijection_proved_in_odd_characteristic",
        "value_slice_uniform_for_nonzero_c",
        "formal_nonadaptive_whole_hvzk_conditional_on_encoding_zk",
    }
    for key, value in authority.items():
        if key in allowed_true:
            if value is not True:
                raise AssertionError(f"closed local lemma lost: {key}")
        elif value is not False:
            raise AssertionError(f"authority escaped fail-closed state: {key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    report = build_report()
    if args.self_check:
        self_check(report)
    print(json.dumps(report, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
