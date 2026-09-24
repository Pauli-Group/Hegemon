#!/usr/bin/env python3
from __future__ import annotations

import itertools
import math
import unittest
from fractions import Fraction

import strict_mixed_pcs_screen as screen


class StrictMixedPcsScreenTests(unittest.TestCase):
    def test_strict_query_counts_match_frozen_screen(self) -> None:
        expected = {2: 637, 4: 222, 8: 127, 16: 87, 32: 66}
        self.assertEqual(
            {
                denominator: screen.strict_query_count(Fraction(1, denominator))
                for denominator in expected
            },
            expected,
        )

    def test_worst_one_tree_bytes_match_frozen_screen(self) -> None:
        expected = {2: 320_400, 4: 162_080, 8: 115_952, 16: 93_168, 32: 81_120}
        self.assertEqual(
            {
                denominator: screen.screen_rate(denominator).one_tree_bytes
                for denominator in expected
            },
            expected,
        )

    def test_rate_eighth_tensor_first_level_already_exceeds_cap(self) -> None:
        rate = screen.screen_rate(8)
        self.assertEqual(rate.tensor_e384_first_level_bytes, 146_656)
        self.assertEqual(rate.tensor_e384_first_level_bytes - screen.RAW_CAP_BYTES, 22_588)
        self.assertFalse(rate.tensor_e384_first_level_fits)

    def test_four_symbol_leaf_is_the_wire_optimum(self) -> None:
        rate = screen.screen_rate(8)
        self.assertEqual(rate.best_leaf_group_symbols, 4)
        self.assertEqual(rate.best_grouped_tree_bytes, 105_792)
        self.assertEqual(rate.best_grouped_tensor_e384_first_level_bytes, 136_496)
        self.assertEqual(
            rate.best_grouped_tensor_e384_first_level_bytes - screen.RAW_CAP_BYTES,
            12_428,
        )
        self.assertFalse(rate.best_grouped_tensor_e384_first_level_fits)
        self.assertEqual(rate.best_grouped_tree_storage_bytes, 67_108_800)
        self.assertEqual(rate.best_grouped_salted_tensor_e384_first_level_bytes, 140_560)
        self.assertEqual(rate.best_grouped_salted_tree_storage_bytes, 83_886_016)

    def test_grouped_leaf_reveals_full_payload(self) -> None:
        rate = screen.screen_rate(16)
        self.assertEqual(rate.best_leaf_group_symbols, 4)
        self.assertEqual(rate.best_grouped_tree_bytes, 86_208)
        self.assertEqual(rate.best_grouped_tensor_e384_first_level_bytes, 107_312)
        self.assertEqual(rate.best_grouped_tensor_e256x2_first_level_bytes, 114_304)
        self.assertEqual(rate.best_grouped_salted_tensor_e256x2_first_level_bytes, 117_088)
        self.assertEqual(rate.best_grouped_tree_storage_bytes, 268_435_392)

    def test_e256x2_rate_thirty_two_has_only_model_headroom(self) -> None:
        rate = screen.screen_rate(32)
        self.assertEqual(rate.best_grouped_tensor_e256x2_first_level_bytes, 97_216)
        self.assertEqual(rate.best_grouped_salted_tensor_e256x2_first_level_bytes, 99_328)
        self.assertEqual(
            screen.RAW_CAP_BYTES - rate.best_grouped_tensor_e256x2_first_level_bytes,
            26_852,
        )
        self.assertTrue(rate.best_grouped_tensor_e256x2_first_level_fits)
        self.assertGreater(rate.best_grouped_tree_storage_bytes, 959 * 1024 * 1024)
        self.assertGreater(
            rate.best_grouped_salted_tree_storage_bytes, 1_215 * 1024 * 1024
        )
        self.assertFalse(screen.security_screen().parallel_rbr_extraction_proved)

    def test_lower_rate_storage_cost_is_explicit(self) -> None:
        rate = screen.screen_rate(16)
        self.assertEqual(rate.oracle_symbols, 1 << 23)
        self.assertGreater(rate.one_tree_storage_bytes, 575 * 1024 * 1024)

    def test_wide_mask_lane_costs_are_not_interchanged(self) -> None:
        security = screen.security_screen()
        self.assertEqual(security.e384_mask_b128_lanes, 3)
        self.assertEqual(security.two_e256_mask_b128_lanes, 4)
        rate = screen.screen_rate(8)
        self.assertEqual(rate.one_e384_value_per_query_bytes, 127 * 48)
        self.assertEqual(rate.two_e256_values_per_query_bytes, 127 * 64)

    def test_e256_product_is_only_an_unproved_arithmetic_target(self) -> None:
        security = screen.security_screen()
        self.assertEqual(security.e256_single_classical_polynomial_bits, 136)
        self.assertEqual(security.e256_ideal_two_repeat_classical_bits, 272)
        self.assertEqual(security.e256_ideal_two_repeat_qrom_bits, 136)
        self.assertFalse(security.parallel_rbr_extraction_proved)
        self.assertFalse(security.strict_admitted)

    def test_power_of_two_ring_switch_boundary(self) -> None:
        security = screen.security_screen()
        self.assertFalse(security.e384_degree_is_power_of_two)
        self.assertTrue(security.e256_degree_is_power_of_two)

    def test_frontier_formula_matches_bruteforce_on_small_trees(self) -> None:
        for oracle_symbols in (8, 16):
            height = int(math.log2(oracle_symbols))
            for queries in range(1, min(4, oracle_symbols) + 1):
                observed = []
                for leaves in itertools.combinations(range(oracle_symbols), queries):
                    active = set(leaves)
                    siblings = 0
                    for _ in range(height):
                        parents = {index // 2 for index in active}
                        siblings += 2 * len(parents) - len(active)
                        active = parents
                    observed.append(siblings)
                self.assertEqual(
                    max(observed),
                    screen.canonical_frontier_max(oracle_symbols, queries),
                )

    def test_grouped_tree_one_symbol_matches_baseline(self) -> None:
        rate = screen.screen_rate(8)
        wire, frontier, storage = screen.grouped_tree_bytes(
            rate.oracle_symbols, rate.queries, 1
        )
        self.assertEqual(wire, rate.one_tree_bytes)
        self.assertEqual(frontier, rate.frontier_nodes_max)
        self.assertEqual(storage, rate.one_tree_storage_bytes)

    def test_report_is_fail_closed(self) -> None:
        payload = screen.report()
        self.assertFalse(payload["frontier_eligible"])
        self.assertFalse(payload["security"]["mixed_field_extraction_proved"])
        self.assertFalse(payload["security"]["complete_zk_proved"])
        self.assertFalse(payload["security"]["composed_qrom_proved"])
        self.assertEqual(payload["proof_commitment_hash"], "SHAKE256-512")
        self.assertEqual(payload["proof_commitment_digest_bytes"], 64)
        self.assertFalse(payload["historical_56_byte_rows_strict"])


if __name__ == "__main__":
    unittest.main()
