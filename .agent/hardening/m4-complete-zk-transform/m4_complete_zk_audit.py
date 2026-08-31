#!/usr/bin/env python3
"""Dependency-free complete-ZK audit for the retained M4/BaseFold topology.

This executable deliberately proves a negative statement.  It models the
opened-leaf slice implemented by the pinned BaseFold ZK encoder:

    leaf_x = (RS(message)[x], RS(mask)[x]).

Both coordinates are opened.  Independent randomness in the second coordinate
and a randomized Merkle leaf tape do not hide the first coordinate.  The small
GF(2^4) model exhaustively enumerates the full opened view, including a SHA-512
leaf digest, and computes exact total-variation distances.

The arithmetic and byte ledgers use only Python's standard library.  They are
certificates and source-static projections, not a proof-system implementation,
PCS theorem, Fiat--Shamir theorem, or production authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Iterable, Mapping, Sequence


SCHEMA = "hegemon.m4-complete-zk-transform-disqualification.v1"
B128_BYTES = 16
SHA512_BYTES = 64
PROOF_CAP_BYTES = 512 * 1024

# Exact retained mixed-depth geometry exported by mixed_basefold_pcs.rs.
RETAINED_TREE_DEPTHS = (13, 18, 20, 11, 16, 12, 9)
RETAINED_LEAF_B128_VALUES = (2, 2, 2, 2, 16, 16, 8)
RETAINED_OPENED_LEAVES_Q319 = (315, 319, 319, 296, 318, 310, 233)
RETAINED_FRONTIER_NODES_Q319 = (1224, 2807, 3445, 637, 2171, 919, 197)
RETAINED_TERMINAL_VALUES = 512
RETAINED_EXPLICIT_FIELD_MESSAGES = 984
RETAINED_ROOTS = 8

# One-level n16 Ligerito source-static decompositions.  Wide values are the
# 113 M4 reductions, 12 sumcheck coefficients, and 1024 terminal values.
ONE_LEVEL_WIDE_VALUES = 113 + 12 + 1024
ONE_LEVEL_ROWS = 64
ONE_LEVEL_PROFILES = {
    38: {"authentication_bytes": 50_304, "encoded_oracle_bytes": 64 * 1024**3},
    61: {"authentication_bytes": 50_944, "encoded_oracle_bytes": 512 * 1024**2},
}

# Exact DP24 query screen used by the retained rate-1/8 scaffold.
QUERY_DOMAIN = 1 << 20
QUERY_MISS_SET = 589_824  # (9/16) * 2^20
CMS_QUERY_BUDGET = 1 << 64
CMS_ARITY_CAP = 1 << 64  # conservative executable ceiling, not an M4 theorem
CMS_HASH_BITS = 512
CMS_TARGET_BITS = 128
STRICT_COMPONENT_BITS = 264
STRICT_COMPONENT_COUNT = 12


@dataclass(frozen=True)
class BinaryField:
    """Tiny polynomial-basis binary field used only for exhaustive identities."""

    bits: int
    reduction: int

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def add(self, left: int, right: int) -> int:
        return (left ^ right) & self.mask

    def mul(self, left: int, right: int) -> int:
        result = 0
        left &= self.mask
        right &= self.mask
        for _ in range(self.bits):
            if right & 1:
                result ^= left
            carry = left >> (self.bits - 1)
            left = (left << 1) & self.mask
            if carry:
                left ^= self.reduction
            right >>= 1
        return result


GF8 = BinaryField(3, 0b011)  # Y^3 + Y + 1
GF16 = BinaryField(4, 0b0011)  # X^4 + X + 1


def rank_binary_columns(columns: Sequence[int], rows: int) -> int:
    """Rank of bit-vector columns over GF(2)."""

    basis = [0] * rows
    rank = 0
    for column in columns:
        value = column
        if value >> rows:
            raise ValueError("column exceeds declared row count")
        while value:
            pivot = value.bit_length() - 1
            if basis[pivot]:
                value ^= basis[pivot]
            else:
                basis[pivot] = value
                rank += 1
                break
    return rank


def affine_distribution(mask_columns: Sequence[int], shift: int = 0) -> Counter[int]:
    """Exact distribution of shift + A*r for independent uniform GF(2) coins."""

    counts: Counter[int] = Counter()
    for selector in range(1 << len(mask_columns)):
        value = shift
        for index, column in enumerate(mask_columns):
            if selector >> index & 1:
                value ^= column
        counts[value] += 1
    return counts


def total_variation(left: Mapping[object, int], right: Mapping[object, int]) -> Fraction:
    """Exact TV distance between finite count distributions."""

    left_total = sum(left.values())
    right_total = sum(right.values())
    if left_total <= 0 or right_total <= 0:
        raise ValueError("distributions must have positive mass")
    keys = set(left) | set(right)
    distance = sum(
        abs(Fraction(left.get(key, 0), left_total) - Fraction(right.get(key, 0), right_total))
        for key in keys
    )
    return distance / 2


def opened_leaf_frame(
    *,
    oracle_group: int,
    layer: int,
    leaf_index: int,
    lanes: Sequence[bytes],
    tape: bytes,
) -> bytes:
    """Canonical index-bound frame analogous to complete_zk::OpenedLeafFrame."""

    if not 0 <= oracle_group < 1 << 16 or not 0 <= layer < 1 << 16:
        raise ValueError("group/layer out of range")
    if not 0 <= leaf_index < 1 << 64:
        raise ValueError("leaf index out of range")
    if not lanes or len(lanes) >= 1 << 16:
        raise ValueError("invalid lane count")
    if any(len(lane) != B128_BYTES for lane in lanes):
        raise ValueError("every lane must be one canonical B128 value")
    if len(tape) != SHA512_BYTES:
        raise ValueError("leaf tape must have 512 bits")
    header = b"hegemon.m4.complete-zk.opened-leaf.sha512.v1\0"
    header += struct.pack(">HHHQ", oracle_group, layer, len(lanes), leaf_index)
    return header + b"".join(lanes) + tape


def leaf_digest(**kwargs: object) -> bytes:
    return hashlib.sha512(opened_leaf_frame(**kwargs)).digest()


def _toy_tape(selector: int) -> bytes:
    if not 0 <= selector < 4:
        raise ValueError("toy tape selector")
    return bytes([selector]) * SHA512_BYTES


def current_opened_view(message_symbol: int) -> Counter[tuple[bytes, int, int, int]]:
    """Full tiny opened view for `(message, random_mask)` plus tape and root."""

    if not 0 <= message_symbol < 16:
        raise ValueError("message symbol must be in GF(2^4)")
    views: Counter[tuple[bytes, int, int, int]] = Counter()
    for mask_symbol in range(16):
        for tape_selector in range(4):
            tape = _toy_tape(tape_selector)
            lanes = (
                message_symbol.to_bytes(B128_BYTES, "little"),
                mask_symbol.to_bytes(B128_BYTES, "little"),
            )
            root = leaf_digest(
                oracle_group=0,
                layer=0,
                leaf_index=0,
                lanes=lanes,
                tape=tape,
            )
            # Opened values remain part of the view; a root collision cannot
            # make the first raw coordinate disappear.
            views[(root, message_symbol, mask_symbol, tape_selector)] += 1
    return views


def masked_only_view(message_symbol: int) -> Counter[tuple[bytes, int, int]]:
    """Required local mutation: open only message+mask, never either summand."""

    if not 0 <= message_symbol < 16:
        raise ValueError("message symbol must be in GF(2^4)")
    views: Counter[tuple[bytes, int, int]] = Counter()
    for mask_symbol in range(16):
        for tape_selector in range(4):
            opened = GF16.add(message_symbol, mask_symbol)
            tape = _toy_tape(tape_selector)
            lanes = (opened.to_bytes(B128_BYTES, "little"),)
            root = leaf_digest(
                oracle_group=0,
                layer=0,
                leaf_index=0,
                lanes=lanes,
                tape=tape,
            )
            views[(root, opened, tape_selector)] += 1
    return views


def masked_and_mask_view(message_symbol: int) -> Counter[tuple[int, int]]:
    """Mutation negative control: opening the mask recovers the message."""

    views: Counter[tuple[int, int]] = Counter()
    for mask_symbol in range(16):
        views[(GF16.add(message_symbol, mask_symbol), mask_symbol)] += 1
    return views


def raw_opening_counterexample() -> dict[str, object]:
    real_zero = current_opened_view(0)
    real_one = current_opened_view(1)
    masked_zero = masked_only_view(0)
    masked_one = masked_only_view(1)
    reopened_zero = masked_and_mask_view(0)
    reopened_one = masked_and_mask_view(1)
    raw_tv = total_variation(real_zero, real_one)
    masked_tv = total_variation(masked_zero, masked_one)
    reopened_tv = total_variation(reopened_zero, reopened_one)
    if raw_tv != 1 or masked_tv != 0 or reopened_tv != 1:
        raise AssertionError("opened-view identity drifted")
    for (masked, mask), _count in reopened_one.items():
        if GF16.add(masked, mask) != 1:
            raise AssertionError("opening the mask did not recover the witness symbol")
    return {
        "relation": "empty public input; private Boolean b; tautological constraint b*b=b",
        "valid_witnesses": [0, 1],
        "current_leaf": "(RS(message)[x], RS(mask)[x], 512-bit tape, SHA-512 root/path)",
        "current_conditional_total_variation": str(raw_tv),
        "single_masked_share_total_variation": str(masked_tv),
        "masked_share_plus_open_mask_total_variation": str(reopened_tv),
        "whole_simulator_consequence": (
            "one public-only distribution cannot be close to both real views; "
            "by triangle inequality at least one distance is at least 1/2"
        ),
        "commitment_programming_does_not_help": True,
    }


def _fold_weights(field: BinaryField, rounds: int, challenge: int) -> list[int]:
    weights: list[int] = []
    for lane in range(1 << rounds):
        weight = 1
        for variable in range(rounds):
            factor = challenge if lane >> variable & 1 else field.add(1, challenge)
            weight = field.mul(weight, factor)
        weights.append(weight)
    return weights


def extension_rank_counterexample(degree: int) -> dict[str, object]:
    """Exact E384 and E512 B128-coordinate rank failures."""

    if degree == 3:
        field, rounds, label = GF8, 2, "E384=B128[Y]/(Y^3+Y+1)"
        expected_weights = [0b101, 0b110, 0b110, 0b100]
    elif degree == 4:
        field, rounds, label = GF16, 3, "E512 degree-four executable analogue"
        expected_weights = [15, 10, 10, 12, 10, 12, 12, 8]
    else:
        raise ValueError("only degree three and four are audited")
    challenge = 0b010
    weights = _fold_weights(field, rounds, challenge)
    if weights != expected_weights:
        raise AssertionError("fold weights drifted")
    # lane0=lane1 is the only public relation; toggling them together and
    # toggling every remaining lane are same-public witness directions.
    witness_images = [weights[0] ^ weights[1], *weights[2:]]
    constant_trace_shift = 0
    for weight in weights:
        constant_trace_shift ^= weight
    current_masks = [constant_trace_shift]
    full_masks = [1 << coordinate for coordinate in range(degree)]
    current_rank = rank_binary_columns(current_masks, degree)
    joined_rank = rank_binary_columns(current_masks + witness_images, degree)
    full_rank = rank_binary_columns(full_masks, degree)
    full_joined_rank = rank_binary_columns(full_masks + witness_images, degree)
    outer_b128_rank = rank_binary_columns([1, 2], degree)
    outer_joined_rank = rank_binary_columns([1, 2, 1 << (degree - 1)], degree)
    if current_rank != 1 or joined_rank != degree:
        raise AssertionError("current trace-mask rank unexpectedly closed")
    if full_rank != degree or full_joined_rank != degree:
        raise AssertionError("full coordinate masks did not close the local span")
    if outer_b128_rank != 2 or outer_joined_rank != 3:
        raise AssertionError("two-B128 endpoint counterexample drifted")
    current_tv = total_variation(
        affine_distribution(current_masks),
        affine_distribution(current_masks, witness_images[-1]),
    )
    missing_coordinate_masks = full_masks[:-1]
    missing_tv = total_variation(
        affine_distribution(missing_coordinate_masks),
        affine_distribution(missing_coordinate_masks, 1 << (degree - 1)),
    )
    full_tv = total_variation(
        affine_distribution(full_masks),
        affine_distribution(full_masks, 1 << (degree - 1)),
    )
    if current_tv != 1 or missing_tv != 1 or full_tv != 0:
        raise AssertionError("affine-support distances drifted")
    return {
        "field": label,
        "degree_over_b128": degree,
        "fold_rounds": rounds,
        "fold_challenge_basis_bits": challenge,
        "lane_weights_basis_bits": weights,
        "same_public_witness_images_basis_bits": witness_images,
        "witness_image_rank": rank_binary_columns(witness_images, degree),
        "current_constant_shift_rank": current_rank,
        "current_joined_rank": joined_rank,
        "current_rank_gate": current_rank == joined_rank,
        "current_conditional_total_variation": str(current_tv),
        "required_independent_b128_mask_columns": degree,
        "full_mask_rank": full_rank,
        "full_mask_joined_rank": full_joined_rank,
        "full_local_affine_total_variation": str(full_tv),
        "one_missing_mask_coordinate_total_variation": str(missing_tv),
        "two_b128_outer_dummy_rank": outer_b128_rank,
        "outer_rank_after_extension_translation": outer_joined_rank,
        "two_b128_outer_dummy_total_variation": "1",
        "warning": "local rank closure is necessary, never a whole-proof simulator theorem",
    }


def direct_mask_geometry(*, log_relation_size: int, fold_variables: int, q: int, degree: int) -> dict[str, int]:
    """Exact mixed B128/E(128d) one-level direct-payload floor."""

    if not 0 < fold_variables <= log_relation_size or q <= 0 or degree <= 0:
        raise ValueError("invalid direct-mask geometry")
    data_columns = 1 << fold_variables
    message_rows = 1 << (log_relation_size - fold_variables)
    wide_bytes = degree * B128_BYTES
    opened_mask_column_bytes = q * degree * B128_BYTES
    padding_vector_bytes = q * wide_bytes
    mask_evaluation_bytes = degree * wide_bytes
    claim_bytes = wide_bytes
    floor = (
        opened_mask_column_bytes
        + padding_vector_bytes
        + mask_evaluation_bytes
        + claim_bytes
    )
    closed_form = 32 * degree * q + 16 * degree * (degree + 1)
    if floor != closed_form:
        raise AssertionError("direct-mask closed form drifted")
    return {
        "log_relation_size": log_relation_size,
        "fold_variables": fold_variables,
        "query_count": q,
        "extension_degree": degree,
        "wide_element_bytes": wide_bytes,
        "data_columns": data_columns,
        "message_rows_before_padding": message_rows,
        "random_padding_b128_elements": q * data_columns,
        "random_mask_columns": degree,
        "random_mask_b128_elements": (message_rows + q) * degree,
        "opened_mask_column_bytes": opened_mask_column_bytes,
        "rlc_padding_vector_bytes": padding_vector_bytes,
        "mask_column_evaluation_bytes": mask_evaluation_bytes,
        "rlc_evaluation_claim_bytes": claim_bytes,
        "direct_payload_floor_bytes": floor,
    }


def one_level_bytes(q: int, degree: int, *, all_scalar: bool = False) -> dict[str, int]:
    """Same-schedule n16 one-level serializer arithmetic."""

    if q not in ONE_LEVEL_PROFILES or degree not in (3, 4):
        raise ValueError("unsupported audited one-level profile")
    wide_bytes = degree * B128_BYTES
    row_bytes = wide_bytes if all_scalar else B128_BYTES
    profile = ONE_LEVEL_PROFILES[q]
    baseline = (
        64
        + ONE_LEVEL_WIDE_VALUES * wide_bytes
        + 64
        + q * ONE_LEVEL_ROWS * row_bytes
        + profile["authentication_bytes"]
    )
    if all_scalar:
        # Once the base field itself is E512, this is a degree-one analogue,
        # not the requested B128/E512 degree-four mask geometry.
        direct_floor = 2 * q * wide_bytes + 2 * wide_bytes
    else:
        direct_floor = direct_mask_geometry(
            log_relation_size=16,
            fold_variables=6,
            q=q,
            degree=degree,
        )["direct_payload_floor_bytes"]
    return {
        "query_count": q,
        "degree": degree,
        "all_scalar": int(all_scalar),
        "baseline_non_zk_bytes": baseline,
        "direct_mask_floor_bytes": direct_floor,
        "baseline_plus_direct_floor_bytes": baseline + direct_floor,
        "encoded_oracle_bytes": profile["encoded_oracle_bytes"] * (row_bytes // B128_BYTES),
    }


def retained_projection(degree: int, *, all_scalar: bool = False) -> dict[str, int]:
    """Exact q319 retained synthetic-schedule serializer decomposition."""

    if degree not in (3, 4):
        raise ValueError("unsupported retained field degree")
    wide_bytes = degree * B128_BYTES
    input_bytes_per_value = wide_bytes if all_scalar else B128_BYTES
    input_values = sum(
        opened * width
        for opened, width in zip(
            RETAINED_OPENED_LEAVES_Q319[:4], RETAINED_LEAF_B128_VALUES[:4], strict=True
        )
    )
    fold_values = sum(
        opened * width
        for opened, width in zip(
            RETAINED_OPENED_LEAVES_Q319[4:], RETAINED_LEAF_B128_VALUES[4:], strict=True
        )
    )
    wide_values = fold_values + RETAINED_TERMINAL_VALUES + RETAINED_EXPLICIT_FIELD_MESSAGES
    tapes = sum(RETAINED_OPENED_LEAVES_Q319)
    frontier = sum(RETAINED_FRONTIER_NODES_Q319)
    digest_units = RETAINED_ROOTS + tapes + frontier
    total = input_values * input_bytes_per_value + wide_values * wide_bytes + digest_units * SHA512_BYTES
    return {
        "query_count": 319,
        "degree": degree,
        "all_scalar": int(all_scalar),
        "input_values": input_values,
        "fold_values": fold_values,
        "terminal_values": RETAINED_TERMINAL_VALUES,
        "explicit_field_messages": RETAINED_EXPLICIT_FIELD_MESSAGES,
        "wide_values": wide_values,
        "roots": RETAINED_ROOTS,
        "opened_leaf_tapes": tapes,
        "frontier_nodes": frontier,
        "input_value_bytes": input_values * input_bytes_per_value,
        "wide_value_bytes": wide_values * wide_bytes,
        "digest_and_tape_bytes": digest_units * SHA512_BYTES,
        "raw_projection_bytes": total,
        "over_512k_cap_bytes": total - PROOF_CAP_BYTES,
    }


def full_shape_bytes() -> dict[str, object]:
    e384 = retained_projection(3)
    e512_mixed = retained_projection(4)
    e512_all = retained_projection(4, all_scalar=True)
    e384_floor = direct_mask_geometry(log_relation_size=16, fold_variables=6, q=319, degree=3)
    e512_floor = direct_mask_geometry(log_relation_size=16, fold_variables=6, q=319, degree=4)
    # Counterfactual degree-one mask once every base symbol is already E512.
    e512_all_floor = 2 * 319 * 64 + 2 * 64
    if e384["raw_projection_bytes"] != 1_548_704:
        raise AssertionError("E384 retained projection drifted")
    if e512_mixed["raw_projection_bytes"] != 1_763_232:
        raise AssertionError("mixed E512 retained projection drifted")
    if e512_all["raw_projection_bytes"] != 1_883_136:
        raise AssertionError("all-E512 retained projection drifted")
    return {
        "claim_ceiling": "fixed-synthetic-schedule serializer projection plus direct-payload floor only",
        "e384_mixed": {
            **e384,
            "direct_mask_floor_bytes": e384_floor["direct_payload_floor_bytes"],
            "projection_plus_direct_floor_bytes": e384["raw_projection_bytes"] + e384_floor["direct_payload_floor_bytes"],
        },
        "e512_mixed_degree_four": {
            **e512_mixed,
            "direct_mask_floor_bytes": e512_floor["direct_payload_floor_bytes"],
            "projection_plus_direct_floor_bytes": e512_mixed["raw_projection_bytes"] + e512_floor["direct_payload_floor_bytes"],
            "raw_delta_vs_e384_bytes": e512_mixed["raw_projection_bytes"] - e384["raw_projection_bytes"],
            "direct_floor_delta_vs_e384_bytes": e512_floor["direct_payload_floor_bytes"] - e384_floor["direct_payload_floor_bytes"],
            "combined_delta_vs_e384_bytes": (
                e512_mixed["raw_projection_bytes"]
                + e512_floor["direct_payload_floor_bytes"]
                - e384["raw_projection_bytes"]
                - e384_floor["direct_payload_floor_bytes"]
            ),
        },
        "e512_all_scalar_counterfactual": {
            **e512_all,
            "degree_one_direct_mask_floor_bytes": e512_all_floor,
            "projection_plus_direct_floor_bytes": e512_all["raw_projection_bytes"] + e512_all_floor,
            "topology_changes_m4_packing": True,
        },
    }


def distinct_miss_probability(q: int) -> Fraction:
    if not 0 <= q <= QUERY_MISS_SET:
        raise ValueError("invalid query count")
    result = Fraction(1)
    for index in range(q):
        result *= Fraction(QUERY_MISS_SET - index, QUERY_DOMAIN - index)
    return result


def cms_envelope(epsilon: Fraction, *, t: int = CMS_QUERY_BUDGET, k: int = CMS_ARITY_CAP) -> Fraction:
    if epsilon < 0 or t < 0 or k < 0:
        raise ValueError("negative CMS parameter")
    return (
        12 * t * t * epsilon
        + Fraction(48 * t**3, 1 << CMS_HASH_BITS)
        + Fraction(2 * k * k, 1 << CMS_HASH_BITS)
    )


def _minimum_q_for_cms(component_multiplier: int) -> int:
    target = Fraction(1, 1 << CMS_TARGET_BITS)
    for q in range(QUERY_MISS_SET + 1):
        if cms_envelope(component_multiplier * distinct_miss_probability(q)) <= target:
            return q
    raise AssertionError("no q satisfies CMS target")


def _fraction_record(value: Fraction) -> dict[str, str]:
    canonical = f"{value.numerator}/{value.denominator}".encode("ascii")
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def qrom_accounting() -> dict[str, object]:
    query_only_min = _minimum_q_for_cms(1)
    twelve_equal_min = _minimum_q_for_cms(STRICT_COMPONENT_COUNT)
    q317 = distinct_miss_probability(317)
    q318 = distinct_miss_probability(318)
    strict_union = Fraction(STRICT_COMPONENT_COUNT, 1 << STRICT_COMPONENT_BITS)
    strict_bound = cms_envelope(strict_union)
    target = Fraction(1, 1 << CMS_TARGET_BITS)
    first_term_scaled = Fraction(
        12 * CMS_QUERY_BUDGET**2 * STRICT_COMPONENT_COUNT,
        1 << STRICT_COMPONENT_BITS,
    ) * (1 << CMS_TARGET_BITS)
    if query_only_min != 313 or twelve_equal_min != 317:
        raise AssertionError("CMS query threshold drifted")
    if not q317 > Fraction(1, 1 << STRICT_COMPONENT_BITS):
        raise AssertionError("q317 unexpectedly meets the 264-bit component gate")
    if not q318 < Fraction(1, 1 << STRICT_COMPONENT_BITS):
        raise AssertionError("q318 no longer meets the 264-bit component gate")
    if first_term_scaled != Fraction(9, 16) or not strict_bound < target:
        raise AssertionError("strict CMS union arithmetic drifted")
    return {
        "model": "conditional ideal CMS envelope; not an M4 theorem",
        "formula": "12*t^2*epsilon + 48*t^3/2^512 + 2*k^2/2^512",
        "t": CMS_QUERY_BUDGET,
        "k_ceiling_assumption": CMS_ARITY_CAP,
        "distinct_query_epsilon": "(589824)_q/(1048576)_q",
        "query_only_minimum_q": query_only_min,
        "twelve_equal_components_minimum_q": twelve_equal_min,
        "strict_component_bits": STRICT_COMPONENT_BITS,
        "strict_component_count": STRICT_COMPONENT_COUNT,
        "strict_component_minimum_q": 318,
        "q317_epsilon": _fraction_record(q317),
        "q318_epsilon": _fraction_record(q318),
        "strict_union_epsilon": _fraction_record(strict_union),
        "cms_bound_at_strict_union": _fraction_record(strict_bound),
        "cms_first_term_fraction_of_2^-128": "9/16",
        "e384_conditionally_sufficient": True,
        "e512_structurally_required": False,
        "production_qualifying_q": None,
        "production_blocker": (
            "the exact M4 interactive epsilon union, RBR/special soundness, whole-view HVZK, "
            "and BCS/CMS applicability are unproved"
        ),
    }


def one_coordinate_query_probability(q: int, population: int) -> Fraction:
    if not 0 <= q <= population:
        raise ValueError("invalid distinct-query geometry")
    return Fraction(q, population)


def source_contract() -> dict[str, object]:
    """Source-static topology anchors; hashes are frozen in source-manifest.json."""

    return {
        "pinned_binius_revision": "3f961630",
        "observed": [
            "encode_masked concatenates message || mask with log_batch_size=1",
            "send_openings writes every scalar of the selected leaf",
            "send_committed_vector writes the entire terminal vector",
            "ProverM4 uses create_channel_without_zk_from_transcript",
            "WholeProofViewSimulator consumes only SimulatorPublicInput and has no implementation",
        ],
        "inferred": [
            "an opened interleaved leaf exposes RS(message)[x] separately from RS(mask)[x]",
            "Merkle tapes and programmable roots authenticate but do not mask an opened scalar",
        ],
    }


def hiding_whir_assessment() -> dict[str, object]:
    """Pin the theorem-transfer boundary for ePrint 2026/391 / Plonky3 #1767.

    These are source-static architecture claims, not a local implementation or
    an import of the paper's theorem.  In particular, the group order argument
    below is exact: GF(2^m)^* has odd order 2^m-1 and therefore has no
    non-trivial power-of-two multiplicative evaluation subgroup.
    """

    return {
        "paper": "https://eprint.iacr.org/2026/391",
        "merged_implementation": "https://github.com/Plonky3/Plonky3/pull/1767",
        "status": "VIABLE_REPLACEMENT_DIRECTION_NOT_DROP_IN_M4_REPAIR",
        "paper_scope": (
            "interactive HVZK IOPP for constrained interleaved linear codes with "
            "round-by-round knowledge soundness and a straightline extractor"
        ),
        "privacy_topology": [
            "append t random field coefficients before Reed-Solomon encoding",
            "open randomized evaluations rather than separable message and mask evaluations",
            "use fresh encoded masks in each reduction round",
            "privatize out-of-domain samples with a full-rank random block",
            "finish through a masked base case instead of exposing the terminal object",
        ],
        "plonky3_interface": "HidingWhirPcs implements MultilinearPcs",
        "r1cs_required_by_pcs": False,
        "r1cs_boundary": (
            "the hiding PCS itself is not an R1CS-only API, but CFW26's ready-made full-ZK R1CS "
            "clause assumes characteristic different from two; B128 is therefore outside that "
            "application theorem. The exact M4 committed relation and every non-PCS transcript "
            "message still need a theorem-preserving adapter or a new reduction"
        ),
        "cfw26_r1cs_characteristic_not_two": True,
        "why_existing_binary_additive_stack_is_not_covered": [
            "Plonky3's committer and configuration require TwoAdicField multiplicative DFT domains",
            "GF(2^m)^* has odd order 2^m-1, so a binary field has no non-trivial radix-2 multiplicative subgroup",
            "retained M4 uses Binius additive Gao-Mateer domains and a different folding/transcript relation",
            "CFW26's full-ZK R1CS clause excludes characteristic two, hence excludes B128",
            "the merged path is a parallel protocol because its carried relation differs from plain WHIR",
            "no exact M4-to-HVZK-WHIR relation, serializer, or public-only whole-view simulator is present",
        ],
        "conventional_hash_requirement": (
            "instantiate commitments and the challenger with SHA-512/SHAKE256-512, canonical "
            "domain separation, and an exact QROM BCS/CMS proof; Poseidon-family benchmark "
            "profiles are evidence only and are ineligible here"
        ),
        "theorem_gates_before_qualification": [
            "prove the randomized additive-code encoder's t-query perfect/statistical privacy, or change fields/stacks",
            "instantiate private zero-evader, HVZK sumcheck, code switch, and masked base case for the exact M4 relation",
            "implement a public-only simulator covering all 17 canonical M4 proof-view classes",
            "prove exact round-by-round or special soundness and straightline extraction after the adapter",
            "compose the interactive theorems through the exact conventional-hash Fiat-Shamir transcript in the QROM",
            "freeze and machine-check the resulting serializer and maximum-shape byte ledger",
        ],
        "next_theorem_valid_routes": [
            "compile the retained Boolean relation to R1CS over an odd two-adic field and adopt the full Hiding-WHIR stack",
            "prove and implement a new characteristic-two constrained-code/HVZK theorem for the B128 additive M4 relation",
        ],
        "published_plonky3_size_numbers_are_not_m4_bytes": True,
        "exact_m4_total_delta_bytes": None,
    }


def build_certificate() -> dict[str, object]:
    q319_one_coordinate = one_coordinate_query_probability(319, 1 << 20)
    e384_one_level = {str(q): one_level_bytes(q, 3) for q in ONE_LEVEL_PROFILES}
    e512_one_level = {str(q): one_level_bytes(q, 4) for q in ONE_LEVEL_PROFILES}
    e512_all_one_level = {
        str(q): one_level_bytes(q, 4, all_scalar=True) for q in ONE_LEVEL_PROFILES
    }
    for q in ONE_LEVEL_PROFILES:
        e512_one_level[str(q)]["combined_delta_vs_e384_bytes"] = (
            e512_one_level[str(q)]["baseline_plus_direct_floor_bytes"]
            - e384_one_level[str(q)]["baseline_plus_direct_floor_bytes"]
        )
    return {
        "schema": SCHEMA,
        "decision": {
            "status": "DISQUALIFIED_CURRENT_M4_RAW_OPENING_TOPOLOGY",
            "candidate_eligible": False,
            "reason_codes": [
                "OPENED_MESSAGE_CODEWORD_COORDINATE",
                "PUBLIC_ONLY_WHOLE_VIEW_SIMULATOR_IMPOSSIBLE_FOR_GENERIC_M4_RELATIONS",
                "CURRENT_M4_COMPOSITE_IS_TRANSPARENT",
                "RAW_TERMINAL_VECTOR_SERIALIZED",
                "LOCAL_MASK_RANK_NOT_WHOLE_VIEW_ZK",
                "PCS_HIDING_AND_SIMULATABLE_OPENING_THEOREM_ABSENT",
                "M4_RBR_SPECIAL_SOUNDNESS_ABSENT",
                "M4_BCS_CMS_QROM_INSTANTIATION_ABSENT",
                "HIDING_WHIR_THEOREM_NOT_INSTANTIATED_FOR_M4_BINARY_ADDITIVE_STACK",
            ],
        },
        "authority": {
            "complete_zero_knowledge": False,
            "whole_view_simulator_implemented": False,
            "exact_indistinguishability_theorem": False,
            "exact_m4_rbr_special_soundness": False,
            "pcs_hiding_theorem": False,
            "pcs_extraction_theorem": False,
            "fiat_shamir_qrom_composed": False,
            "strict_pq128": False,
            "hiding_whir_instantiated_for_m4": False,
            "production_authorized": False,
        },
        "source_contract": source_contract(),
        "counterexample": {
            **raw_opening_counterexample(),
            "one_differing_depth20_coordinate_hit_probability": _fraction_record(q319_one_coordinate),
            "constant_nonzero_codeword_case_total_variation": "1",
        },
        "rank_checks": {
            "e384": extension_rank_counterexample(3),
            "e512": extension_rank_counterexample(4),
        },
        "one_level_bytes": {
            "claim_ceiling": "same-schedule serializer arithmetic plus direct-payload floor; not complete ZK",
            "e384_mixed": e384_one_level,
            "e512_mixed_degree_four": e512_one_level,
            "e512_all_scalar_counterfactual": e512_all_one_level,
        },
        "maximum_shape_bytes": full_shape_bytes(),
        "qrom": qrom_accounting(),
        "hiding_whir": hiding_whir_assessment(),
        "minimal_viable_topology_change": {
            "commitment": (
                "commit a randomized codeword or linear secret sharing whose opened shares are "
                "witness-independent; never commit/open `(RS(message),RS(mask))` as separable lanes"
            ),
            "opening": (
                "open only masked shares plus index-bound 512-bit tapes and authentication data; "
                "never open a mask share that algebraically recovers the witness share"
            ),
            "relation": (
                "prove mask consistency, low degree/proximity, and the original M4 relation inside "
                "a new hiding PCS/IOP without exposing an unmasking value"
            ),
            "randomness": (
                "at least q independent B128 padding coefficients per data column and d independent "
                "B128 mask columns for a degree-d extension, plus one fresh 512-bit tape per opened leaf"
            ),
            "e384_q319_direct_payload_floor_bytes": direct_mask_geometry(
                log_relation_size=16, fold_variables=6, q=319, degree=3
            )["direct_payload_floor_bytes"],
            "e512_q319_direct_payload_floor_bytes": direct_mask_geometry(
                log_relation_size=16, fold_variables=6, q=319, degree=4
            )["direct_payload_floor_bytes"],
            "exact_total_pcs_delta_bytes": None,
            "why_total_is_unknown": (
                "the required PCS changes codeword dimension/tree schedules and no source-local "
                "whole-view simulator or canonical serializer exists"
            ),
        },
        "unproved_assumptions": [
            "full-view HVZK simulator for the exact M4 interactive proof and all 17 serialized view classes",
            "adaptive hiding and position binding of the randomized codeword commitment under SHA-512/SHAKE256-512",
            "knowledge extraction and low-degree/proximity soundness for the exact distinct-query schedule",
            "nonlinear mask consistency without revealing any unmasking share",
            "round-by-round or special soundness of the exact compiled M4 IOP, including chip-call binding",
            "BCS/CMS QROM transfer for that exact IOP with the stated t and k budgets",
            "QROM-programmable conventional-hash idealization, canonical retry/abort refinement, and exact parser refinement",
        ],
    }


def validate_certificate(certificate: Mapping[str, object]) -> None:
    """Fail closed on mutations of any decision-critical certificate field."""

    expected = build_certificate()
    if certificate != expected:
        raise ValueError("certificate differs from executable canonical result")
    authority = certificate.get("authority")
    if not isinstance(authority, Mapping) or any(value is not False for value in authority.values()):
        raise ValueError("every authority flag must remain false")


def check_repo_sources(repo: Path) -> list[str]:
    """Check the exact source snippets required by the no-go."""

    required: dict[str, tuple[str, ...]] = {
        "prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs": (
            "pub trait WholeProofViewSimulator",
            "public: &SimulatorPublicInput",
            "joint_simulator_implemented: false",
        ),
        "prototypes/standalone-shake256-binius/strict-mixed-field/src/mixed_basefold_pcs.rs": (
            "pub const STRICT_SCREEN_QUERY_COUNT: usize = 319;",
            "assert_eq!(report.e384_lower_bound_bytes, 1_548_704);",
            "assert_eq!(report.e512_mixed_lower_bound_bytes, 1_763_232);",
            "assert_eq!(report.e512_stock_scalar_lower_bound_bytes, 1_883_136);",
        ),
    }
    failures: list[str] = []
    for relative, snippets in required.items():
        path = repo / relative
        if not path.is_file():
            failures.append(f"missing:{relative}")
            continue
        text = path.read_text(encoding="utf-8")
        failures.extend(f"snippet:{relative}:{snippet}" for snippet in snippets if snippet not in text)
    return failures


def check_pinned_binius_sources(root: Path) -> list[str]:
    required: dict[str, tuple[str, ...]] = {
        "crates/iop-prover/src/fri/encode.rs": (
            "concatenates `message || mask`",
            "combined_values.extend_from_slice(message.as_ref());",
            "combined_values.extend_from_slice(mask.as_ref());",
        ),
        "crates/iop-prover/src/merkle_channel.rs": (
            "advice.write_scalar_iter(leaf.iter_scalars());",
            "advice.write_scalar_iter(data.iter_scalars());",
        ),
        "crates/m4-prover/src/composite.rs": (
            "A composite proof is transparent: every oracle is committed without a mask",
            "create_channel_without_zk_from_transcript",
        ),
    }
    failures: list[str] = []
    for relative, snippets in required.items():
        path = root / relative
        if not path.is_file():
            failures.append(f"missing:{relative}")
            continue
        text = path.read_text(encoding="utf-8")
        failures.extend(f"snippet:{relative}:{snippet}" for snippet in snippets if snippet not in text)
    return failures


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-certificate", type=Path)
    parser.add_argument("--check-repo", type=Path)
    parser.add_argument("--check-pinned-binius", type=Path)
    parser.add_argument("--compact", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    certificate = build_certificate()
    if args.check_certificate:
        loaded = json.loads(args.check_certificate.read_text(encoding="utf-8"))
        validate_certificate(loaded)
    failures: list[str] = []
    if args.check_repo:
        failures.extend(check_repo_sources(args.check_repo))
    if args.check_pinned_binius:
        failures.extend(check_pinned_binius_sources(args.check_pinned_binius))
    if failures:
        raise SystemExit("\n".join(failures))
    print(json.dumps(certificate, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
