#!/usr/bin/env python3
"""Independent, dependency-free SmallWood LVCS leakage reproduction.

This deliberately does not import the Rust implementation.  It recomputes the
active Level-5 geometry and the Goldilocks-domain algebra from the constants and
formulas used by ``smallwood_engine.rs``.  Keeping it isolated makes it useful
as a regression oracle while the production worker changes that file.
"""

from __future__ import annotations

import json
import math
from fractions import Fraction
from typing import Iterable, Sequence


FIELD_ORDER = 0xFFFF_FFFF_0000_0001
GOLDILOCKS_TWO_ADIC_ROOT = 0x1856_29DC_DA58_878C
GOLDILOCKS_TWO_ADICITY = 32

PACKING = 64
PIOP_OPENINGS = 5
BETA = 2
RHO = 5
CONSTRAINT_DEGREE = 8
WITNESS_POLYS = 699
DECS_DOMAIN_SIZE = 1 << 20
DECS_OPENINGS = 23

WITNESS_DEGREE = PACKING + PIOP_OPENINGS - 1
MPOL_DEGREE = CONSTRAINT_DEGREE * WITNESS_DEGREE - PACKING
MLIN_DEGREE = WITNESS_DEGREE + PACKING - 1
NB_POLYS = WITNESS_POLYS + 2 * RHO


def width(degree: int) -> int:
    return math.ceil((degree + 1 - PIOP_OPENINGS) / PACKING)


WITNESS_WIDTH = width(WITNESS_DEGREE)
MPOL_WIDTH = width(MPOL_DEGREE)
MLIN_WIDTH = width(MLIN_DEGREE)
UNSTACKED_ROWS = PACKING + PIOP_OPENINGS
UNSTACKED_COLS = (
    WITNESS_POLYS * WITNESS_WIDTH + RHO * MPOL_WIDTH + RHO * MLIN_WIDTH
)
LVCS_ROWS = UNSTACKED_ROWS * BETA
LVCS_COLS = math.ceil(UNSTACKED_COLS / BETA)
LVCS_FULLRANK_ROWS = tuple(
    layer * UNSTACKED_ROWS + opening
    for layer in range(BETA)
    for opening in range(PIOP_OPENINGS)
)
ROTATED_ROW_LENGTH = LVCS_COLS + DECS_OPENINGS
ROTATED_DATA_OFFSET = DECS_OPENINGS


def subgroup_root() -> int:
    return pow(
        GOLDILOCKS_TWO_ADIC_ROOT,
        1 << (GOLDILOCKS_TWO_ADICITY - DECS_DOMAIN_SIZE.bit_length() + 1),
        FIELD_ORDER,
    )


def leaf_point(index: int, shift: int = 1) -> int:
    if not 0 <= index < DECS_DOMAIN_SIZE:
        raise ValueError("leaf index outside the active DECS domain")
    return shift * pow(subgroup_root(), index, FIELD_ORDER) % FIELD_ORDER


def poly_eval(coefficients: Sequence[int], point: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * point + coefficient) % FIELD_ORDER
    return result


def matrix_rank(matrix: Sequence[Sequence[int]]) -> int:
    if not matrix:
        return 0
    work = [[value % FIELD_ORDER for value in row] for row in matrix]
    rows, columns = len(work), len(work[0])
    pivot_row = 0
    for column in range(columns):
        pivot = next(
            (row for row in range(pivot_row, rows) if work[row][column]), None
        )
        if pivot is None:
            continue
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        inverse = pow(work[pivot_row][column], -1, FIELD_ORDER)
        work[pivot_row] = [value * inverse % FIELD_ORDER for value in work[pivot_row]]
        for row in range(rows):
            if row == pivot_row:
                continue
            factor = work[row][column]
            if factor:
                work[row] = [
                    (left - factor * right) % FIELD_ORDER
                    for left, right in zip(work[row], work[pivot_row])
                ]
        pivot_row += 1
        if pivot_row == rows:
            break
    return pivot_row


def solve_square(matrix: Sequence[Sequence[int]], values: Sequence[int]) -> list[int]:
    size = len(matrix)
    if size == 0 or len(values) != size or any(len(row) != size for row in matrix):
        raise ValueError("expected a non-empty square system")
    work = [
        [entry % FIELD_ORDER for entry in row] + [value % FIELD_ORDER]
        for row, value in zip(matrix, values)
    ]
    for column in range(size):
        pivot = next((row for row in range(column, size) if work[row][column]), None)
        if pivot is None:
            raise ValueError("singular system")
        work[column], work[pivot] = work[pivot], work[column]
        inverse = pow(work[column][column], -1, FIELD_ORDER)
        work[column] = [value * inverse % FIELD_ORDER for value in work[column]]
        for row in range(size):
            if row == column:
                continue
            factor = work[row][column]
            if factor:
                work[row] = [
                    (left - factor * right) % FIELD_ORDER
                    for left, right in zip(work[row], work[column])
                ]
    return [row[-1] for row in work]


def target_layout(witness_poly: int) -> dict[str, object]:
    if not 0 <= witness_poly < WITNESS_POLYS:
        raise ValueError("target is not a witness polynomial")
    layer, lvcs_data_column = divmod(witness_poly, LVCS_COLS)
    if layer >= BETA:
        raise AssertionError("active witness polynomial exceeded the two stacking layers")
    rotated_coordinate = ROTATED_DATA_OFFSET + lvcs_data_column
    coefficient_rows = tuple(
        layer * UNSTACKED_ROWS + coefficient for coefficient in range(UNSTACKED_ROWS)
    )
    revealed_coefficients = tuple(
        coefficient
        for coefficient, row in enumerate(coefficient_rows)
        if row not in LVCS_FULLRANK_ROWS
    )
    return {
        "witness_poly": witness_poly,
        "stacking_layer": layer,
        "lvcs_data_column": lvcs_data_column,
        "rotated_interpolation_coordinate": rotated_coordinate,
        "coefficient_lvcs_rows": coefficient_rows,
        "subset_revealed_coefficients": revealed_coefficients,
    }


def recovery_matrix(opening_points: Sequence[int]) -> list[list[int]]:
    equations: list[list[int]] = []
    for coefficient in range(PIOP_OPENINGS, WITNESS_DEGREE + 1):
        equation = [0] * (WITNESS_DEGREE + 1)
        equation[coefficient] = 1
        equations.append(equation)
    for point in opening_points:
        equations.append(
            [pow(point, coefficient, FIELD_ORDER) for coefficient in range(WITNESS_DEGREE + 1)]
        )
    return equations


def synthetic_coefficients(witness_poly: int) -> list[int]:
    return [
        (
            (witness_poly + 17) * pow(coefficient + 11, 3, FIELD_ORDER)
            + 0x9E37_79B9 * coefficient
            + 0xA5A5_A5A5
        )
        % FIELD_ORDER
        for coefficient in range(WITNESS_DEGREE + 1)
    ]


def recover_target(witness_poly: int, opening_points: Sequence[int]) -> dict[str, object]:
    layout = target_layout(witness_poly)
    expected_revealed = tuple(range(PIOP_OPENINGS, WITNESS_DEGREE + 1))
    if layout["subset_revealed_coefficients"] != expected_revealed:
        raise AssertionError("subset does not expose the expected coefficient suffix")
    coefficients = synthetic_coefficients(witness_poly)
    equations = recovery_matrix(opening_points)
    right_hand_side = coefficients[PIOP_OPENINGS:] + [
        poly_eval(coefficients, point) for point in opening_points
    ]
    recovered = solve_square(equations, right_hand_side)
    packed_expected = [poly_eval(coefficients, point) for point in range(PACKING)]
    packed_recovered = [poly_eval(recovered, point) for point in range(PACKING)]
    return {
        **layout,
        "system_rows": len(equations),
        "system_columns": WITNESS_DEGREE + 1,
        "system_rank": matrix_rank(equations),
        "coefficient_recovery_exact": recovered == coefficients,
        "packed_value_recovery_exact": packed_recovered == packed_expected,
        "packed_value_count": len(packed_recovered),
    }


def subgroup_interpolation_collisions(point_count: int) -> list[int]:
    return [
        point
        for point in range(1, point_count)
        if pow(point, DECS_DOMAIN_SIZE, FIELD_ORDER) == 1
    ]


def coset_is_disjoint(shift: int, point_count: int) -> bool:
    if not 0 < shift < FIELD_ORDER:
        return False
    inverse = pow(shift, -1, FIELD_ORDER)
    return all(
        pow(point * inverse % FIELD_ORDER, DECS_DOMAIN_SIZE, FIELD_ORDER) != 1
        for point in range(1, point_count)
    )


def first_disjoint_shift(point_count: int, search_limit: int = 1 << 12) -> int:
    for shift in range(point_count, point_count + search_limit):
        if coset_is_disjoint(shift, point_count):
            return shift
    raise ValueError("disjoint-coset search exhausted")


def wire_tape_overheads() -> dict[str, object]:
    return {
        "16_byte_classical_example": DECS_OPENINGS * 16,
        "32_byte_candidate": DECS_OPENINGS * 32,
        "64_byte_candidate": DECS_OPENINGS * 64,
        "formula": "decs_openings * tape_bytes",
        "qrom_note": (
            "No tape width is certified here: a PQ128/QROM profile must derive it "
            "from its quantum-query and union bounds."
        ),
    }


def produce_report() -> dict[str, object]:
    root = subgroup_root()
    vulnerable_leaf = 163_840
    opening_points = (1009, 1237, 2027, 4099, 8191)
    shift = first_disjoint_shift(ROTATED_ROW_LENGTH)
    probability = Fraction(DECS_OPENINGS, DECS_DOMAIN_SIZE)
    four_opening_rank = matrix_rank(recovery_matrix(opening_points[:4]))
    report = {
        "schema": "hegemon.smallwood-independent-zk-leak-audit.v1",
        "field": {
            "order": FIELD_ORDER,
            "two_adic_root": GOLDILOCKS_TWO_ADIC_ROOT,
            "subgroup_size": DECS_DOMAIN_SIZE,
            "subgroup_generator": root,
            "generator_has_exact_order": (
                pow(root, DECS_DOMAIN_SIZE, FIELD_ORDER) == 1
                and pow(root, DECS_DOMAIN_SIZE // 2, FIELD_ORDER) != 1
            ),
        },
        "geometry": {
            "packing": PACKING,
            "piop_openings": PIOP_OPENINGS,
            "witness_degree": WITNESS_DEGREE,
            "mpol_degree": MPOL_DEGREE,
            "mlin_degree": MLIN_DEGREE,
            "witness_width": WITNESS_WIDTH,
            "mpol_width": MPOL_WIDTH,
            "mlin_width": MLIN_WIDTH,
            "nb_polys": NB_POLYS,
            "unstacked_rows": UNSTACKED_ROWS,
            "unstacked_cols": UNSTACKED_COLS,
            "lvcs_rows": LVCS_ROWS,
            "lvcs_cols": LVCS_COLS,
            "lvcs_random_tail": DECS_OPENINGS,
            "rotated_row_length": ROTATED_ROW_LENGTH,
            "fullrank_rows": LVCS_FULLRANK_ROWS,
        },
        "collision": {
            "leaf_index": vulnerable_leaf,
            "subgroup_point": leaf_point(vulnerable_leaf),
            "expected_point": 64,
            "old_subgroup_interpolation_collisions": subgroup_interpolation_collisions(
                ROTATED_ROW_LENGTH
            ),
        },
        "openings": {
            "representative_valid_piop_points": opening_points,
            "five_opening_system_rank": matrix_rank(recovery_matrix(opening_points)),
            "four_opening_system_rank": four_opening_rank,
            "rank_claim_is_universal": (
                "The unknown c0..c4 block is a 5x5 Vandermonde matrix; every "
                "canonical set of five distinct opening points has rank five."
            ),
        },
        "targets": [recover_target(target, opening_points) for target in (41, 416)],
        "sampling": {
            "fixed_leaf_inclusion_fraction": f"{probability.numerator}/{probability.denominator}",
            "fixed_leaf_inclusion_decimal": float(probability),
            "negative_log2_probability": -math.log2(float(probability)),
            "expected_proofs_per_hit": float(1 / probability),
            "condition": "conditioned on successful exact uniform sampling without replacement",
        },
        "repair": {
            "first_search_candidate": ROTATED_ROW_LENGTH,
            "selected_shift": shift,
            "coset_is_disjoint_from_all_interpolation_points": coset_is_disjoint(
                shift, ROTATED_ROW_LENGTH
            ),
            "old_leaf_point_after_shift": leaf_point(vulnerable_leaf, shift),
            "internal_collision_free_from_exact_root_order": True,
            "domain_size_unchanged": True,
            "row_polynomial_degree_unchanged": True,
            "shift_wire_bytes": 0,
            "opened_tape_wire_overheads": wire_tape_overheads(),
        },
    }
    return report


def assert_report(report: dict[str, object]) -> None:
    assert report["collision"]["subgroup_point"] == 64
    assert report["collision"]["old_subgroup_interpolation_collisions"] == [1, 8, 64]
    assert report["openings"]["five_opening_system_rank"] == 69
    assert report["openings"]["four_opening_system_rank"] == 68
    for target in report["targets"]:
        assert target["lvcs_data_column"] == 41
        assert target["rotated_interpolation_coordinate"] == 64
        assert target["subset_revealed_coefficients"] == tuple(range(5, 69))
        assert target["system_rank"] == 69
        assert target["coefficient_recovery_exact"]
        assert target["packed_value_recovery_exact"]
    assert report["repair"]["selected_shift"] == 398
    assert report["repair"]["coset_is_disjoint_from_all_interpolation_points"]


def main() -> None:
    report = produce_report()
    assert_report(report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
