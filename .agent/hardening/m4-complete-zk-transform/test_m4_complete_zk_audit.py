#!/usr/bin/env python3
"""Dependency-free mutation and algebra tests for the M4 complete-ZK no-go."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
MODULE_PATH = HERE / "m4_complete_zk_audit.py"
SPEC = importlib.util.spec_from_file_location("m4_complete_zk_audit", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load audit module")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class FieldAndViewTests(unittest.TestCase):
    def test_gf16_field_identities_exhaustively(self) -> None:
        field = AUDIT.GF16
        for left in range(16):
            self.assertEqual(field.add(left, 0), left)
            self.assertEqual(field.mul(left, 0), 0)
            self.assertEqual(field.mul(left, 1), left)
            for right in range(16):
                self.assertEqual(field.add(left, right), field.add(right, left))
                self.assertEqual(field.mul(left, right), field.mul(right, left))
                for third in range(16):
                    self.assertEqual(
                        field.mul(left, field.add(right, third)),
                        field.add(field.mul(left, right), field.mul(left, third)),
                    )

    def test_raw_opening_has_disjoint_support(self) -> None:
        zero = AUDIT.current_opened_view(0)
        one = AUDIT.current_opened_view(1)
        self.assertEqual(AUDIT.total_variation(zero, one), 1)
        self.assertFalse(set(zero).intersection(one))

    def test_masked_share_is_witness_independent(self) -> None:
        zero = AUDIT.masked_only_view(0)
        one = AUDIT.masked_only_view(1)
        self.assertEqual(zero, one)
        self.assertEqual(AUDIT.total_variation(zero, one), 0)

    def test_reopening_mask_restores_full_leak(self) -> None:
        zero = AUDIT.masked_and_mask_view(0)
        one = AUDIT.masked_and_mask_view(1)
        self.assertEqual(AUDIT.total_variation(zero, one), 1)
        for (masked, mask), count in one.items():
            self.assertEqual(count, 1)
            self.assertEqual(AUDIT.GF16.add(masked, mask), 1)

    def test_leaf_digest_binds_every_opening_dimension(self) -> None:
        base = {
            "oracle_group": 1,
            "layer": 2,
            "leaf_index": 3,
            "lanes": (bytes(16), bytes([1]) * 16),
            "tape": bytes(64),
        }
        digest = AUDIT.leaf_digest(**base)
        mutations = [
            {**base, "oracle_group": 2},
            {**base, "layer": 3},
            {**base, "leaf_index": 4},
            {**base, "lanes": (bytes([1]) * 16, bytes([1]) * 16)},
            {**base, "tape": bytes([1]) * 64},
        ]
        for mutated in mutations:
            self.assertNotEqual(digest, AUDIT.leaf_digest(**mutated))


class RankAndByteTests(unittest.TestCase):
    def test_e384_rank_failure_and_minimum_local_masks(self) -> None:
        result = AUDIT.extension_rank_counterexample(3)
        self.assertEqual(result["witness_image_rank"], 3)
        self.assertEqual(result["current_constant_shift_rank"], 1)
        self.assertFalse(result["current_rank_gate"])
        self.assertEqual(result["required_independent_b128_mask_columns"], 3)
        self.assertEqual(result["one_missing_mask_coordinate_total_variation"], "1")

    def test_e512_rank_failure_and_minimum_local_masks(self) -> None:
        result = AUDIT.extension_rank_counterexample(4)
        self.assertEqual(result["witness_image_rank"], 4)
        self.assertEqual(result["current_constant_shift_rank"], 1)
        self.assertFalse(result["current_rank_gate"])
        self.assertEqual(result["required_independent_b128_mask_columns"], 4)
        self.assertEqual(result["one_missing_mask_coordinate_total_variation"], "1")

    def test_one_level_degree_four_deltas(self) -> None:
        expected = {
            38: (148_336, 168_064, 19_728),
            61: (174_736, 195_200, 20_464),
        }
        for q, (e384_total, e512_total, delta) in expected.items():
            e384 = AUDIT.one_level_bytes(q, 3)
            e512 = AUDIT.one_level_bytes(q, 4)
            self.assertEqual(e384["baseline_plus_direct_floor_bytes"], e384_total)
            self.assertEqual(e512["baseline_plus_direct_floor_bytes"], e512_total)
            self.assertEqual(e512_total - e384_total, delta)

    def test_maximum_shape_e384_e512_deltas(self) -> None:
        result = AUDIT.full_shape_bytes()
        e384 = result["e384_mixed"]
        e512 = result["e512_mixed_degree_four"]
        all_e512 = result["e512_all_scalar_counterfactual"]
        self.assertEqual(e384["raw_projection_bytes"], 1_548_704)
        self.assertEqual(e384["projection_plus_direct_floor_bytes"], 1_579_520)
        self.assertEqual(e512["raw_projection_bytes"], 1_763_232)
        self.assertEqual(e512["projection_plus_direct_floor_bytes"], 1_804_384)
        self.assertEqual(e512["combined_delta_vs_e384_bytes"], 224_864)
        self.assertEqual(all_e512["projection_plus_direct_floor_bytes"], 1_924_096)


class QromAndCertificateTests(unittest.TestCase):
    def test_exact_cms_thresholds(self) -> None:
        result = AUDIT.qrom_accounting()
        self.assertEqual(result["query_only_minimum_q"], 313)
        self.assertEqual(result["twelve_equal_components_minimum_q"], 317)
        self.assertEqual(result["strict_component_minimum_q"], 318)
        self.assertGreater(AUDIT.distinct_miss_probability(317), Fraction(1, 1 << 264))
        self.assertLess(AUDIT.distinct_miss_probability(318), Fraction(1, 1 << 264))
        strict_union = Fraction(12, 1 << 264)
        self.assertLess(AUDIT.cms_envelope(strict_union), Fraction(1, 1 << 128))

    def test_one_coordinate_probability_is_exact(self) -> None:
        self.assertEqual(AUDIT.one_coordinate_query_probability(319, 1 << 20), Fraction(319, 1 << 20))

    def test_hiding_whir_is_not_an_m4_theorem_bridge(self) -> None:
        result = AUDIT.hiding_whir_assessment()
        self.assertEqual(result["status"], "VIABLE_REPLACEMENT_DIRECTION_NOT_DROP_IN_M4_REPAIR")
        self.assertFalse(result["r1cs_required_by_pcs"])
        self.assertTrue(result["cfw26_r1cs_characteristic_not_two"])
        self.assertIsNone(result["exact_m4_total_delta_bytes"])

    def test_all_authority_flags_are_false(self) -> None:
        certificate = AUDIT.build_certificate()
        self.assertTrue(certificate["authority"])
        self.assertTrue(all(value is False for value in certificate["authority"].values()))
        AUDIT.validate_certificate(certificate)

    def test_frozen_certificate_if_present(self) -> None:
        path = HERE / "certificate.json"
        if path.is_file():
            AUDIT.validate_certificate(json.loads(path.read_text(encoding="utf-8")))

    def test_repo_source_contract(self) -> None:
        self.assertEqual(AUDIT.check_repo_sources(REPO), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
