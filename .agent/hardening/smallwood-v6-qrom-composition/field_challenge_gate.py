#!/usr/bin/env python3
"""Exact-integer screening for binary challenge-field and FRI-query choices.

This is deliberately not a soundness reduction.  It evaluates the symbolic
screen documented in FIELD_CHALLENGE_AUDIT.md and keeps every authority flag
false.  In particular, callers must supply the total bad-set coefficient and
the QROM reduction constant; this module never derives either from a circuit.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
from dataclasses import asdict, dataclass


RETAINED_M4_TREE_DEPTHS = (13, 18, 20, 11, 16, 12, 9)
RETAINED_M4_LEAF_B128_VALUES = (2, 2, 2, 2, 16, 16, 8)
RETAINED_M4_TERMINAL_VALUES = 512
RETAINED_M4_EXPLICIT_FIELD_MESSAGES = 984
RETAINED_M4_ROOTS = 8
RETAINED_M4_MAX_QUERY_COUNT = 512
PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES = 512 * 1024

_PROFILE = (
    b"hegemon.strict-mixed-field.mixed-basefold-pcs.b128-e384.sha512.v1\0"
)
_TRANSCRIPT_DOMAIN = b"hegemon.mixed-basefold.transcript.sha512.v1\0"
_QUERY_DOMAIN = b"hegemon.mixed-basefold.query.sha512.v1\0"
_M4_PROJECTION_DOMAIN = (
    b"hegemon.strict-mixed-field.retained-m4-mixed-depth-projection.sha512.v1\0"
)
_M4_PROJECTION_ROOT_DOMAIN = (
    b"hegemon.strict-mixed-field.retained-m4-synthetic-root.sha512.v1\0"
)


def _positive(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def collision_pairs(challenge_draws: int) -> int:
    """Return C(challenge_draws, 2) exactly."""

    draws = _nonnegative("challenge_draws", challenge_draws)
    return draws * (draws - 1) // 2


def aggregate_bad_set(
    *,
    challenge_draws: int,
    schwartz_zippel_degree: int,
    sumcheck_round_degree: int,
    batching_degree: int,
    fri_folding_bad_set: int,
) -> int:
    """Add the field-denominator numerators without hiding a union term."""

    terms = (
        collision_pairs(challenge_draws),
        _nonnegative("schwartz_zippel_degree", schwartz_zippel_degree),
        _nonnegative("sumcheck_round_degree", sumcheck_round_degree),
        _nonnegative("batching_degree", batching_degree),
        _nonnegative("fri_folding_bad_set", fri_folding_bad_set),
    )
    total = sum(terms)
    return _positive("aggregate bad-set coefficient", total)


def charged_coefficient(
    bad_set: int, *, qrom_constant: int = 1, union_count: int = 1
) -> int:
    return (
        _positive("bad_set", bad_set)
        * _positive("qrom_constant", qrom_constant)
        * _positive("union_count", union_count)
    )


def minimum_effective_bits(
    coefficient: int,
    *,
    low_query_bits: int = 64,
    low_target_bits: int = 128,
    work_query_bits: int = 128,
    work_success_denominator_bits: int = 1,
) -> int:
    """Minimum denominator bits satisfying both strict integer gates.

    For C = ``coefficient``, the two gates are

        C * 2^(2*low_query_bits) / 2^m < 2^-low_target_bits
        C * 2^(2*work_query_bits) / 2^m < 2^-work_success_denominator_bits.

    Strict inequality accounts for the final ``+ 1`` in each threshold.
    """

    coefficient = _positive("coefficient", coefficient)
    low_query_bits = _nonnegative("low_query_bits", low_query_bits)
    low_target_bits = _nonnegative("low_target_bits", low_target_bits)
    work_query_bits = _nonnegative("work_query_bits", work_query_bits)
    work_success_denominator_bits = _nonnegative(
        "work_success_denominator_bits", work_success_denominator_bits
    )
    floor_log_coefficient = coefficient.bit_length() - 1
    low_min = (
        floor_log_coefficient + 2 * low_query_bits + low_target_bits + 1
    )
    work_min = (
        floor_log_coefficient
        + 2 * work_query_bits
        + work_success_denominator_bits
        + 1
    )
    return max(low_min, work_min)


def strict_field_gate(
    field_bits: int,
    coefficient: int,
    *,
    transcript_entropy_bits: int,
    low_query_bits: int = 64,
    low_target_bits: int = 128,
    work_query_bits: int = 128,
    work_success_denominator_bits: int = 1,
) -> bool:
    """Evaluate both inequalities with integers and an entropy cap."""

    field_bits = _positive("field_bits", field_bits)
    transcript_entropy_bits = _positive(
        "transcript_entropy_bits", transcript_entropy_bits
    )
    coefficient = _positive("coefficient", coefficient)
    effective_bits = min(field_bits, transcript_entropy_bits)

    low_lhs = coefficient << (2 * low_query_bits + low_target_bits)
    work_lhs = coefficient << (
        2 * work_query_bits + work_success_denominator_bits
    )
    denominator = 1 << effective_bits
    return low_lhs < denominator and work_lhs < denominator


def fri_query_passes(
    *, log_inverse_rate: int, query_count: int, target_bits: int
) -> bool:
    """Check (((1 + 2^-ell) / 2)^q) < 2^-target exactly."""

    ell = _positive("log_inverse_rate", log_inverse_rate)
    q = _nonnegative("query_count", query_count)
    target = _nonnegative("target_bits", target_bits)
    numerator = (2**ell + 1) ** q
    denominator = 2 ** ((ell + 1) * q)
    return (numerator << target) < denominator


def minimum_fri_queries(*, log_inverse_rate: int, target_bits: int) -> int:
    ell = _positive("log_inverse_rate", log_inverse_rate)
    target = _nonnegative("target_bits", target_bits)
    q = 0
    while not fri_query_passes(
        log_inverse_rate=ell, query_count=q, target_bits=target
    ):
        q += 1
    return q


def dp24_bad_pair_count(*, pair_count: int, log_inverse_rate: int) -> int:
    """Return the integral DP24 unique-radius bad set for this domain.

    The pinned query calculator's miss fraction is
    ``(2^ell + 1) / 2^(ell + 1)``.  Therefore the corresponding fixed bad
    fraction is ``(2^ell - 1) / 2^(ell + 1)``.  We reject geometries where
    that fraction is not an exact integer count instead of rounding a bound.
    """

    pairs = _positive("pair_count", pair_count)
    ell = _positive("log_inverse_rate", log_inverse_rate)
    denominator = 1 << (ell + 1)
    if pairs % denominator:
        raise ValueError("pair_count does not realize the DP24 fraction exactly")
    return pairs // denominator * ((1 << ell) - 1)


def fixed_bad_set_miss_passes(
    *, pair_count: int, bad_pair_count: int, query_count: int, target_bits: int
) -> bool:
    """Check the exact without-replacement fixed-bad-set miss product.

    This is only the finite-population product.  It is not an adaptive FRI,
    Fiat--Shamir, PCS, or QROM theorem.
    """

    pairs = _positive("pair_count", pair_count)
    bad = _nonnegative("bad_pair_count", bad_pair_count)
    queries = _nonnegative("query_count", query_count)
    target = _nonnegative("target_bits", target_bits)
    if bad > pairs:
        raise ValueError("bad_pair_count exceeds pair_count")
    if queries > pairs:
        raise ValueError("query_count exceeds pair_count")
    good = pairs - bad
    numerator = 1
    denominator = 1
    for draw in range(queries):
        numerator *= max(good - draw, 0)
        denominator *= pairs - draw
    return (numerator << target) < denominator


def minimum_distinct_queries(
    *, pair_count: int, bad_pair_count: int, target_bits: int
) -> int:
    pairs = _positive("pair_count", pair_count)
    bad = _nonnegative("bad_pair_count", bad_pair_count)
    target = _nonnegative("target_bits", target_bits)
    if bad == 0 or bad > pairs:
        raise ValueError("bad_pair_count must be in 1..pair_count")
    for queries in range(pairs + 1):
        if fixed_bad_set_miss_passes(
            pair_count=pairs,
            bad_pair_count=bad,
            query_count=queries,
            target_bits=target,
        ):
            return queries
    raise AssertionError("a positive bad set must be hit after exhausting the domain")


def fixed_bad_set_diagnostic_bits(
    *, pair_count: int, bad_pair_count: int, query_count: int
) -> float:
    """Diagnostic ``-log2`` of the exact product; never an integer gate."""

    pairs = _positive("pair_count", pair_count)
    bad = _nonnegative("bad_pair_count", bad_pair_count)
    queries = _nonnegative("query_count", query_count)
    if bad > pairs or queries > pairs - bad:
        raise ValueError("invalid fixed-bad-set diagnostic geometry")
    good = pairs - bad
    return -math.fsum(
        math.log2((good - draw) / (pairs - draw)) for draw in range(queries)
    )


def incomplete_scaffold_composed_bits(
    *, pair_count: int, bad_pair_count: int, query_count: int
) -> float:
    """Reproduce the old twelve-term float scaffold, without authority.

    The eleven frozen non-FRI terms are five 132-bit modeled protocol terms,
    SHA-512 and SHAKE256-448 generic collision screens, and four 192-bit
    statistical/search terms.  The query product receives the scaffold's
    square-root QROM heuristic.  Missing reductions make this diagnostic only.
    """

    query_bits = fixed_bad_set_diagnostic_bits(
        pair_count=pair_count,
        bad_pair_count=bad_pair_count,
        query_count=query_count,
    )
    non_fri = (
        5 * math.exp2(-132)
        + math.exp2(-(512 / 3))
        + math.exp2(-(448 / 3))
        + 4 * math.exp2(-192)
    )
    return -math.log2(non_fri + math.exp2(-(query_bits / 2)))


def minimum_incomplete_scaffold_queries(
    *, pair_count: int, bad_pair_count: int, target_bits: int
) -> int:
    """Minimum of the explicitly non-authoritative float scaffold."""

    pairs = _positive("pair_count", pair_count)
    bad = _nonnegative("bad_pair_count", bad_pair_count)
    target = _nonnegative("target_bits", target_bits)
    if bad == 0 or bad > pairs:
        raise ValueError("bad_pair_count must be in 1..pair_count")
    for queries in range(pairs - bad + 1):
        if (
            incomplete_scaffold_composed_bits(
                pair_count=pairs,
                bad_pair_count=bad,
                query_count=queries,
            )
            > target
        ):
            return queries
    raise AssertionError("incomplete scaffold never crossed its target")


def _domain_hash(domain: bytes, payload: bytes) -> bytes:
    return hashlib.sha512(domain + len(payload).to_bytes(8, "little") + payload).digest()


def _append_frame(state: bytes, tag: int, payload: bytes) -> bytes:
    return state + bytes((tag,)) + len(payload).to_bytes(8, "little") + payload


def _retained_m4_global_queries(query_count: int) -> list[int]:
    """Port the source-pinned SHA-512/Fisher--Yates projection exactly."""

    queries = _positive("query_count", query_count)
    if queries > RETAINED_M4_MAX_QUERY_COUNT:
        raise ValueError("query_count exceeds retained projection maximum")
    global_depth = max(RETAINED_M4_TREE_DEPTHS)
    global_width = 1 << global_depth
    context = _domain_hash(_M4_PROJECTION_DOMAIN, _M4_PROJECTION_DOMAIN)
    state = _TRANSCRIPT_DOMAIN
    state = _append_frame(state, 1, _domain_hash(_PROFILE, _PROFILE))
    state = _append_frame(state, 2, context)
    geometry = b"".join(
        value.to_bytes(8, "little")
        for value in (global_depth, 1, len(RETAINED_M4_TREE_DEPTHS), queries)
    )
    state = _append_frame(state, 3, geometry)
    for tree in range(RETAINED_M4_ROOTS):
        depth = (
            RETAINED_M4_TREE_DEPTHS[tree]
            if tree < len(RETAINED_M4_TREE_DEPTHS)
            else RETAINED_M4_TREE_DEPTHS[-1]
        )
        payload = b"".join(
            value.to_bytes(8, "little") for value in (tree, depth, queries)
        )
        root = _domain_hash(_M4_PROJECTION_ROOT_DOMAIN, payload)
        observed = (
            tree.to_bytes(8, "little")
            + (1 << depth).to_bytes(8, "little")
            + root
        )
        state = _append_frame(state, 4, observed)

    moved: dict[int, int] = {}

    def get(position: int) -> int:
        return moved.get(position, position)

    def set_value(position: int, value: int) -> None:
        if position == value:
            moved.pop(position, None)
        else:
            moved[position] = value

    selected: list[int] = []
    u64_max = (1 << 64) - 1
    for ordinal in range(queries):
        remaining = global_width - ordinal
        zone = u64_max - (u64_max % remaining)
        for nonce in range(65_536):
            payload = b"".join(
                value.to_bytes(8, "little")
                for value in (ordinal, global_width, remaining, nonce)
            )
            preimage = state + _QUERY_DOMAIN
            preimage = _append_frame(preimage, 7, payload)
            digest = hashlib.sha512(preimage).digest()
            raw = int.from_bytes(digest[:8], "little")
            if raw >= zone:
                continue
            chosen_position = ordinal + raw % remaining
            left = get(ordinal)
            right = get(chosen_position)
            set_value(ordinal, right)
            set_value(chosen_position, left)
            index = get(ordinal)
            response = (
                digest
                + chosen_position.to_bytes(8, "little")
                + index.to_bytes(8, "little")
                + nonce.to_bytes(8, "little")
            )
            state = _append_frame(state, 8, response)
            selected.append(index)
            break
        else:
            raise RuntimeError("retained query sampler exhausted its public counter")
    return selected


def _compact_frontier_count(log_width: int, selected: list[int]) -> int:
    width = 1 << log_width
    if not selected or selected != sorted(set(selected)):
        raise ValueError("selected leaves must be nonempty, sorted, and distinct")
    if selected[-1] >= width:
        raise ValueError("selected leaf exceeds tree width")

    def recurse(start: int, span: int, lo: int, hi: int) -> int:
        if lo == hi:
            return 1
        if span == 1:
            return 0
        midpoint = start + span // 2
        split = bisect.bisect_left(selected, midpoint, lo, hi)
        return recurse(start, span // 2, lo, split) + recurse(
            midpoint, span // 2, split, hi
        )

    return recurse(0, width, 0, len(selected))


def retained_m4_projection(query_count: int) -> dict[str, object]:
    """Exact fixed-synthetic-transcript retained-tree serializer projection.

    This is not a measurement or a transcript-independent lower bound.  It
    deliberately charges no framing or complete-ZK repair geometry.
    """

    global_queries = _retained_m4_global_queries(query_count)
    global_depth = max(RETAINED_M4_TREE_DEPTHS)
    opened: list[int] = []
    frontiers: list[int] = []
    for depth in RETAINED_M4_TREE_DEPTHS:
        shift = global_depth - depth
        selected = sorted({index >> shift for index in global_queries})
        opened.append(len(selected))
        frontiers.append(_compact_frontier_count(depth, selected))

    input_b128_values = sum(opened[i] * 2 for i in range(4))
    fold_e384_values = sum(
        opened[i] * RETAINED_M4_LEAF_B128_VALUES[i] for i in range(4, 7)
    )
    index_tapes = sum(opened)
    authentication_nodes = sum(frontiers)
    e384_values = (
        fold_e384_values
        + RETAINED_M4_TERMINAL_VALUES
        + RETAINED_M4_EXPLICIT_FIELD_MESSAGES
    )
    digest_units = RETAINED_M4_ROOTS + index_tapes + authentication_nodes
    e384_bytes = 16 * input_b128_values + 48 * e384_values + 64 * digest_units
    e512_mixed_bytes = e384_bytes + 16 * e384_values
    e512_stock_bytes = e512_mixed_bytes + 48 * input_b128_values
    return {
        "query_count": query_count,
        "tree_depths": list(RETAINED_M4_TREE_DEPTHS),
        "opened_leaves": opened,
        "frontier_nodes": frontiers,
        "input_b128_values": input_b128_values,
        "fold_wide_values": fold_e384_values,
        "terminal_wide_values": RETAINED_M4_TERMINAL_VALUES,
        "explicit_wide_messages": RETAINED_M4_EXPLICIT_FIELD_MESSAGES,
        "index_tapes": index_tapes,
        "authentication_nodes": authentication_nodes,
        "e384_projection_bytes": e384_bytes,
        "e512_mixed_projection_bytes": e512_mixed_bytes,
        "e512_stock_scalar_projection_bytes": e512_stock_bytes,
        "under_provisional_512kib_screen": {
            "e384": e384_bytes <= PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES,
            "e512_mixed": e512_mixed_bytes
            <= PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES,
            "e512_stock_scalar": e512_stock_bytes
            <= PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES,
        },
        "is_measurement": False,
        "is_transcript_independent_lower_bound": False,
        "fixed_synthetic_transcript": True,
        "complete_zk_repair_bytes_charged": 0,
        "zero_zk_cost_counterfactual": True,
        "complete_zk_geometry_recomputed": False,
    }


@dataclass(frozen=True)
class FieldScreen:
    field: str
    field_bits: int
    transcript_entropy_bits: int
    effective_bits: int
    minimum_effective_bits: int
    integer_bit_slack: int
    passes: bool


def screen_field(
    name: str, field_bits: int, coefficient: int, transcript_entropy_bits: int
) -> FieldScreen:
    minimum = minimum_effective_bits(coefficient)
    effective = min(field_bits, transcript_entropy_bits)
    return FieldScreen(
        field=name,
        field_bits=field_bits,
        transcript_entropy_bits=transcript_entropy_bits,
        effective_bits=effective,
        minimum_effective_bits=minimum,
        integer_bit_slack=effective - minimum,
        passes=strict_field_gate(
            field_bits,
            coefficient,
            transcript_entropy_bits=transcript_entropy_bits,
        ),
    )


def report() -> dict[str, object]:
    # A deliberately loose whole-proof algebraic/QROM/union screen.  It is an
    # input assumption, not a derived Binius theorem; see the audit.
    coefficient = 1 << 64
    fields = [
        screen_field("E256-with-wide-transcript", 256, coefficient, 512),
        screen_field("E384-with-wide-transcript", 384, coefficient, 512),
        screen_field("E512-with-wide-transcript", 512, coefficient, 512),
        screen_field("E384-current-SHA256-cap", 384, coefficient, 256),
        screen_field("E512-current-SHA256-cap", 512, coefficient, 256),
    ]
    fri = {
        str(log_rate): {
            "strictly_below_2^-128": minimum_fri_queries(
                log_inverse_rate=log_rate, target_bits=128
            ),
            "strictly_below_2^-129": minimum_fri_queries(
                log_inverse_rate=log_rate, target_bits=129
            ),
        }
        for log_rate in range(1, 5)
    }
    retained_pair_count = 1 << max(RETAINED_M4_TREE_DEPTHS)
    retained_bad_pairs = dp24_bad_pair_count(
        pair_count=retained_pair_count, log_inverse_rate=3
    )
    retained_target_bits = 264
    retained_min_queries = minimum_distinct_queries(
        pair_count=retained_pair_count,
        bad_pair_count=retained_bad_pairs,
        target_bits=retained_target_bits,
    )
    retained_min_projection = retained_m4_projection(retained_min_queries)
    retained_scaffold_queries = minimum_incomplete_scaffold_queries(
        pair_count=retained_pair_count,
        bad_pair_count=retained_bad_pairs,
        target_bits=128,
    )
    retained_scaffold_projection = retained_m4_projection(retained_scaffold_queries)
    retained_q116_projection = retained_m4_projection(116)
    retained_q319_projection = retained_m4_projection(319)
    return {
        "schema": "hegemon.proof-field-challenge-screen.v2",
        "charged_coefficient": coefficient,
        "charged_coefficient_is_derived_theorem": False,
        "fields": [asdict(field) for field in fields],
        "fri_minimum_queries": fri,
        "historical_rate3_queries": 116,
        "historical_rate3_strict_128_passes": fri_query_passes(
            log_inverse_rate=3, query_count=116, target_bits=128
        ),
        "live_sha256_96bit_profile": {
            "status": "rejected negative control",
            "transcript": "SHA-256",
            "field": "B128",
            "query_target_bits": 96,
            "unmodified_live_profile_accepted": False,
        },
        "candidate_sha512_distinct_query_profile": {
            "status": "source-static rejected candidate",
            "transcript": "SHA-512",
            "inverse_rate_log": 3,
            "global_pair_depth": max(RETAINED_M4_TREE_DEPTHS),
            "pair_count": retained_pair_count,
            "bad_pair_count": retained_bad_pairs,
            "bad_fraction": "7/16",
            "historical_264_component_target_bits": retained_target_bits,
            "historical_264_component_minimum_query_count": retained_min_queries,
            "historical_264_component_one_fewer_passes": fixed_bad_set_miss_passes(
                pair_count=retained_pair_count,
                bad_pair_count=retained_bad_pairs,
                query_count=retained_min_queries - 1,
                target_bits=retained_target_bits,
            ),
            "historical_264_component_projection": retained_min_projection,
            "incomplete_scaffold_composed_gt128": {
                "minimum_query_count": retained_scaffold_queries,
                "one_fewer_composed_bits": incomplete_scaffold_composed_bits(
                    pair_count=retained_pair_count,
                    bad_pair_count=retained_bad_pairs,
                    query_count=retained_scaffold_queries - 1,
                ),
                "minimum_composed_bits": incomplete_scaffold_composed_bits(
                    pair_count=retained_pair_count,
                    bad_pair_count=retained_bad_pairs,
                    query_count=retained_scaffold_queries,
                ),
                "projection": retained_scaffold_projection,
                "uses_exact_integer_composition": False,
                "production_selectable": False,
            },
            "production_minimum_query_count": None,
            "historical_q116_projection": retained_q116_projection,
            "historical_q319_projection": retained_q319_projection,
            "provisional_parser_safety_screen_bytes": PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES,
            "provisional_screen_is_consensus_authority": False,
            "retained_b128_comparator_bytes": 1_344_828,
            "q310_e384_minus_retained_comparator_bytes": retained_scaffold_projection[
                "e384_projection_bytes"
            ]
            - 1_344_828,
            "q116_e384_over_provisional_screen_bytes": retained_q116_projection[
                "e384_projection_bytes"
            ]
            - PROVISIONAL_PARSER_SAFETY_SCREEN_BYTES,
            "universal_basefold_lower_bound": False,
            "fixed_bad_set_product_is_adaptive_fri_theorem": False,
            "fiat_shamir_qrom_reduction_present": False,
            "complete_zero_knowledge": False,
            "production_authorized": False,
        },
        "exact_same_schedule_e512_minus_e384_bytes": {
            "incomplete_scaffold_q_mixed": retained_scaffold_projection[
                "e512_mixed_projection_bytes"
            ]
            - retained_scaffold_projection["e384_projection_bytes"],
            "incomplete_scaffold_q_all_scalar": retained_scaffold_projection[
                "e512_stock_scalar_projection_bytes"
            ]
            - retained_scaffold_projection["e384_projection_bytes"],
            "historical_264_component_q_mixed": retained_min_projection[
                "e512_mixed_projection_bytes"
            ]
            - retained_min_projection["e384_projection_bytes"],
            "historical_264_component_q_all_scalar": retained_min_projection[
                "e512_stock_scalar_projection_bytes"
            ]
            - retained_min_projection["e384_projection_bytes"],
            "q319_mixed": retained_q319_projection[
                "e512_mixed_projection_bytes"
            ]
            - retained_q319_projection["e384_projection_bytes"],
            "q319_all_scalar": retained_q319_projection[
                "e512_stock_scalar_projection_bytes"
            ]
            - retained_q319_projection["e384_projection_bytes"],
            "is_measurement": False,
        },
        "exact_qrom_reduction_present": False,
        "exact_fri_folding_bound_present": False,
        "complete_zero_knowledge": False,
        "production_authorized": False,
        "composed_pq128": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
