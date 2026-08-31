#!/usr/bin/env python3
"""Fail-closed byte and theorem screen for strict mixed-field PCS candidates.

This is a deterministic lower-bound screen, not a proof-system implementation.
It deliberately reports no admitted construction until the missing ZK,
mixed-field extraction, parallel-repetition, and QROM certificates are present.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from fractions import Fraction


RAW_CAP_BYTES = 124_068
ENVELOPE_BYTES = 12
RELATION_LOG = 15
RELATION_SYMBOLS = 1 << RELATION_LOG
CLASSICAL_TARGET_BITS = 264
DEGREE_LOG_BOUND = 120
# Proof commitments and Fiat--Shamir are SHAKE256-512 in the strict Hegemon
# profile.  The semantic SHAKE256-448 width is not a permissible PCS digest.
HASH_BYTES = 64
NON_STRICT_HISTORICAL_HASH_BYTES = 56
B128_BYTES = 16
E256_BYTES = 32
E384_BYTES = 48
BCS_SALT_BYTES = 32


@dataclass(frozen=True)
class RateScreen:
    rate_denominator: int
    queries: int
    oracle_symbols: int
    frontier_nodes_max: int
    one_tree_bytes: int
    tensor_e384_first_level_bytes: int
    tensor_e384_first_level_fits: bool
    one_tree_storage_bytes: int
    best_leaf_group_symbols: int
    best_grouped_frontier_nodes_max: int
    best_grouped_tree_bytes: int
    best_grouped_tensor_e384_first_level_bytes: int
    best_grouped_tensor_e384_first_level_fits: bool
    best_grouped_tensor_e256x2_first_level_bytes: int
    best_grouped_tensor_e256x2_first_level_fits: bool
    best_grouped_tree_storage_bytes: int
    best_grouped_salted_tree_storage_bytes: int
    best_grouped_salted_tensor_e384_first_level_bytes: int
    best_grouped_salted_tensor_e256x2_first_level_bytes: int
    one_e384_value_per_query_bytes: int
    two_e256_values_per_query_bytes: int


@dataclass(frozen=True)
class SecurityScreen:
    e384_classical_polynomial_bits: int
    e256_single_classical_polynomial_bits: int
    e256_ideal_two_repeat_classical_bits: int
    e256_ideal_two_repeat_qrom_bits: int
    e384_mask_b128_lanes: int
    two_e256_mask_b128_lanes: int
    e384_degree_is_power_of_two: bool
    e256_degree_is_power_of_two: bool
    mixed_field_extraction_proved: bool
    characteristic_two_zk_ring_switch_proved: bool
    parallel_rbr_extraction_proved: bool
    complete_zk_proved: bool
    composed_qrom_proved: bool
    strict_admitted: bool


def strict_query_count(rate: Fraction, bits: int = CLASSICAL_TARGET_BITS) -> int:
    """Optimistic TensorSwitch leading query term for distance 1-rate."""
    if not 0 < rate < 1:
        raise ValueError("rate must lie strictly between zero and one")
    rate_float = float(rate)
    per_query_bits = -math.log2(1.0 - (1.0 - rate_float) ** 2)
    return math.ceil(bits / per_query_bits)


def canonical_frontier_max(oracle_symbols: int, queries: int) -> int:
    """Maximum canonical binary Merkle multiproof sibling count."""
    if oracle_symbols <= 0 or oracle_symbols & (oracle_symbols - 1):
        raise ValueError("oracle_symbols must be a power of two")
    if not 1 <= queries <= oracle_symbols:
        raise ValueError("queries must be within the oracle")
    level = math.floor(math.log2(oracle_symbols / queries))
    return queries * (level - 1) + oracle_symbols // (1 << level)


def grouped_tree_bytes(
    oracle_symbols: int, queries: int, leaf_group_symbols: int
) -> tuple[int, int, int]:
    """Return (wire, frontier nodes, storage) for fixed-size grouped leaves.

    This is the worst-query-set wire lower bound. It reveals every B128 symbol
    in each queried group, so a ZK compiler must hide the full union rather
    than only the selected coordinate.
    """
    if leaf_group_symbols <= 0 or leaf_group_symbols & (leaf_group_symbols - 1):
        raise ValueError("leaf_group_symbols must be a power of two")
    if oracle_symbols % leaf_group_symbols:
        raise ValueError("leaf group must divide the oracle")
    leaf_count = oracle_symbols // leaf_group_symbols
    frontier_nodes = canonical_frontier_max(leaf_count, queries)
    wire = (
        HASH_BYTES
        + queries * leaf_group_symbols * B128_BYTES
        + frontier_nodes * HASH_BYTES
    )
    storage = (
        oracle_symbols * B128_BYTES
        + (leaf_count - 1) * HASH_BYTES
    )
    return wire, frontier_nodes, storage


def screen_rate(rate_denominator: int) -> RateScreen:
    if rate_denominator <= 1 or rate_denominator & (rate_denominator - 1):
        raise ValueError("rate denominator must be a power of two greater than one")
    rate = Fraction(1, rate_denominator)
    queries = strict_query_count(rate)
    oracle_symbols = RELATION_SYMBOLS * rate_denominator**2
    frontier_nodes = canonical_frontier_max(oracle_symbols, queries)
    one_tree_bytes = HASH_BYTES + queries * B128_BYTES + frontier_nodes * HASH_BYTES

    # TensorSwitch Lemma 8.3 contributes at least 5*q E384 elements for
    # one commitment. Two additional roots and two explicit E384 scalars are
    # charged, but recursion, ZK, salts, and framing are still omitted.
    tensor_first_level = (
        one_tree_bytes
        + 5 * queries * E384_BYTES
        + 2 * HASH_BYTES
        + 2 * E384_BYTES
    )
    storage = B128_BYTES * oracle_symbols + HASH_BYTES * (oracle_symbols - 1)
    grouped_candidates = []
    for leaf_group_symbols in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        leaf_count = oracle_symbols // leaf_group_symbols
        if leaf_count < queries:
            continue
        wire, grouped_frontier, grouped_storage = grouped_tree_bytes(
            oracle_symbols, queries, leaf_group_symbols
        )
        grouped_candidates.append(
            (wire, leaf_group_symbols, grouped_frontier, grouped_storage)
        )
    best_wire, best_group, best_frontier, best_storage = min(grouped_candidates)
    best_tensor_first_level = (
        best_wire
        + 5 * queries * E384_BYTES
        + 2 * HASH_BYTES
        + 2 * E384_BYTES
    )
    best_tensor_e256x2_first_level = (
        best_wire
        + 5 * queries * 2 * E256_BYTES
        + 2 * HASH_BYTES
        + 4 * E256_BYTES
    )
    salted_storage = best_storage + (
        oracle_symbols // best_group
    ) * BCS_SALT_BYTES
    salted_e384_first_level = best_tensor_first_level + queries * BCS_SALT_BYTES
    salted_e256x2_first_level = (
        best_tensor_e256x2_first_level + queries * BCS_SALT_BYTES
    )
    return RateScreen(
        rate_denominator=rate_denominator,
        queries=queries,
        oracle_symbols=oracle_symbols,
        frontier_nodes_max=frontier_nodes,
        one_tree_bytes=one_tree_bytes,
        tensor_e384_first_level_bytes=tensor_first_level,
        tensor_e384_first_level_fits=tensor_first_level <= RAW_CAP_BYTES,
        one_tree_storage_bytes=storage,
        best_leaf_group_symbols=best_group,
        best_grouped_frontier_nodes_max=best_frontier,
        best_grouped_tree_bytes=best_wire,
        best_grouped_tensor_e384_first_level_bytes=best_tensor_first_level,
        best_grouped_tensor_e384_first_level_fits=(
            best_tensor_first_level <= RAW_CAP_BYTES
        ),
        best_grouped_tensor_e256x2_first_level_bytes=(
            best_tensor_e256x2_first_level
        ),
        best_grouped_tensor_e256x2_first_level_fits=(
            best_tensor_e256x2_first_level <= RAW_CAP_BYTES
        ),
        best_grouped_tree_storage_bytes=best_storage,
        best_grouped_salted_tree_storage_bytes=salted_storage,
        best_grouped_salted_tensor_e384_first_level_bytes=(
            salted_e384_first_level
        ),
        best_grouped_salted_tensor_e256x2_first_level_bytes=(
            salted_e256x2_first_level
        ),
        one_e384_value_per_query_bytes=queries * E384_BYTES,
        two_e256_values_per_query_bytes=queries * 2 * E256_BYTES,
    )


def security_screen() -> SecurityScreen:
    e384_bits = 384 - DEGREE_LOG_BOUND
    e256_bits = 256 - DEGREE_LOG_BOUND
    ideal_product_bits = 2 * e256_bits
    # This is only the arithmetic value that a missing independent
    # parallel-RBR theorem would need to justify.
    ideal_qrom_bits = ideal_product_bits // 2
    missing_gate = False
    return SecurityScreen(
        e384_classical_polynomial_bits=e384_bits,
        e256_single_classical_polynomial_bits=e256_bits,
        e256_ideal_two_repeat_classical_bits=ideal_product_bits,
        e256_ideal_two_repeat_qrom_bits=ideal_qrom_bits,
        e384_mask_b128_lanes=3,
        two_e256_mask_b128_lanes=4,
        e384_degree_is_power_of_two=False,
        e256_degree_is_power_of_two=True,
        mixed_field_extraction_proved=missing_gate,
        characteristic_two_zk_ring_switch_proved=missing_gate,
        parallel_rbr_extraction_proved=missing_gate,
        complete_zk_proved=missing_gate,
        composed_qrom_proved=missing_gate,
        strict_admitted=missing_gate,
    )


def report() -> dict[str, object]:
    rates = [screen_rate(denominator) for denominator in (2, 4, 8, 16, 32)]
    security = security_screen()
    return {
        "schema": "hegemon.strict-mixed-pcs-screen.v2",
        "relation_log": RELATION_LOG,
        "raw_cap_bytes": RAW_CAP_BYTES,
        "envelope_cap_bytes": RAW_CAP_BYTES + ENVELOPE_BYTES,
        "proof_commitment_hash": "SHAKE256-512",
        "proof_commitment_digest_bytes": HASH_BYTES,
        "historical_56_byte_rows_strict": False,
        "rates": [asdict(rate) for rate in rates],
        "security": asdict(security),
        "frontier_eligible": False,
        "verdict": (
            "no published strict transparent PQ ZK B128-to-wide-field PCS "
            "passes both the byte and theorem gates"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = report()
    if args.check:
        rate_eighth = next(
            rate for rate in payload["rates"] if rate["rate_denominator"] == 8
        )
        assert rate_eighth["tensor_e384_first_level_bytes"] == 146_656
        assert rate_eighth["best_leaf_group_symbols"] == 4
        assert rate_eighth["best_grouped_tensor_e384_first_level_bytes"] == 136_496
        assert not rate_eighth["best_grouped_tensor_e384_first_level_fits"]
        assert rate_eighth["best_grouped_tensor_e256x2_first_level_bytes"] == 146_688
        assert not rate_eighth["best_grouped_tensor_e256x2_first_level_fits"]
        assert rate_eighth["best_grouped_salted_tensor_e384_first_level_bytes"] == 140_560
        assert not payload["security"]["strict_admitted"]
        assert not payload["frontier_eligible"]
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
