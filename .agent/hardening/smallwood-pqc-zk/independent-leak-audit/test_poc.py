#!/usr/bin/env python3
"""Lightweight regression tests for the independent SmallWood leak PoC."""

import unittest

import poc


class IndependentSmallwoodLeakTest(unittest.TestCase):
    def test_exact_subgroup_leaf_collision(self) -> None:
        root = poc.subgroup_root()
        self.assertEqual(pow(root, poc.DECS_DOMAIN_SIZE, poc.FIELD_ORDER), 1)
        self.assertNotEqual(pow(root, poc.DECS_DOMAIN_SIZE // 2, poc.FIELD_ORDER), 1)
        self.assertEqual(poc.leaf_point(163_840), 64)
        self.assertNotEqual(poc.leaf_point(163_839), 64)
        self.assertNotEqual(poc.leaf_point(163_841), 64)

    def test_both_witness_targets_share_rotated_coordinate_64(self) -> None:
        low = poc.target_layout(41)
        high = poc.target_layout(416)
        self.assertEqual((low["stacking_layer"], low["lvcs_data_column"]), (0, 41))
        self.assertEqual((high["stacking_layer"], high["lvcs_data_column"]), (1, 41))
        for target in (low, high):
            self.assertEqual(target["rotated_interpolation_coordinate"], 64)
            self.assertEqual(target["subset_revealed_coefficients"], tuple(range(5, 69)))

    def test_one_subset_leaf_plus_five_openings_recovers_each_target(self) -> None:
        points = (1009, 1237, 2027, 4099, 8191)
        self.assertEqual(poc.matrix_rank(poc.recovery_matrix(points)), 69)
        for target in (41, 416):
            result = poc.recover_target(target, points)
            self.assertTrue(result["coefficient_recovery_exact"])
            self.assertTrue(result["packed_value_recovery_exact"])
            self.assertEqual(result["packed_value_count"], 64)

    def test_four_openings_leave_one_degree_of_freedom(self) -> None:
        self.assertEqual(
            poc.matrix_rank(poc.recovery_matrix((1009, 1237, 2027, 4099))), 68
        )

    def test_disjoint_coset_removes_all_398_coordinate_collisions(self) -> None:
        self.assertEqual(poc.subgroup_interpolation_collisions(398), [1, 8, 64])
        self.assertFalse(poc.coset_is_disjoint(397, 398))
        self.assertEqual(poc.first_disjoint_shift(398), 398)
        self.assertTrue(poc.coset_is_disjoint(398, 398))
        self.assertNotIn(poc.leaf_point(163_840, 398), range(398))

    def test_exact_sampler_probability_and_wire_costs(self) -> None:
        probability = poc.Fraction(poc.DECS_OPENINGS, poc.DECS_DOMAIN_SIZE)
        self.assertEqual(probability, poc.Fraction(23, 1 << 20))
        self.assertEqual(poc.wire_tape_overheads()["16_byte_classical_example"], 368)
        self.assertEqual(poc.wire_tape_overheads()["32_byte_candidate"], 736)


if __name__ == "__main__":
    unittest.main()
