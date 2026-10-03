import unittest

from wire_terms import (
    diamond_zk_delta,
    merkle_auth_bytes,
    n15_two_branch_wire_report,
    query_count,
    ring_switch_standalone_bytes,
    salted_tree_opening_bytes,
    shared_input_two_branch_opening_bytes,
)


class WireTermsTests(unittest.TestCase):
    def test_dp24_query_counts(self):
        self.assertEqual(query_count(96, 1), 232)
        self.assertEqual(query_count(96, 2), 142)
        self.assertEqual(query_count(132, 3), 160)
        self.assertEqual(query_count(264, 3), 319)

    def test_pinned_merkle_formula(self):
        # ceil(log2(160)) = 8: 160 branches across 12 levels plus a 256-node cap.
        self.assertEqual(merkle_auth_bytes(20, 160), ((20 - 8) * 160 + 256) * 64)

    def test_salt_is_per_leaf(self):
        auth = merkle_auth_bytes(20, 160)
        expected = auth + 160 * (16 * 32 + 32)
        self.assertEqual(salted_tree_opening_bytes(20, 160, 16), expected)

    def test_degree_two_ring_switch(self):
        self.assertEqual(ring_switch_standalone_bytes(14), 32 * (2 + 28 + 1))

    def test_diamond_fixed_schedule_delta_breakdown(self):
        depths = [20, 16, 12]
        delta = diamond_zk_delta(depths, n_queries=160, fold_arity=4)
        expected_auth = sum(
            merkle_auth_bytes(depth + 1, 160) - merkle_auth_bytes(depth, 160)
            for depth in depths
        ) + merkle_auth_bytes(21, 160)
        self.assertEqual(delta.root, 64)
        self.assertEqual(delta.clear, 64)
        self.assertEqual(delta.blind_values, 160 * 16 * 32)
        self.assertEqual(delta.authentication, expected_auth)
        self.assertEqual(delta.salts, 4 * 160 * 32)
        self.assertEqual(
            delta.total,
            delta.root
            + delta.clear
            + delta.blind_values
            + delta.authentication
            + delta.salts,
        )

    def test_two_branch_union_is_full_two_q(self):
        expected = salted_tree_opening_bytes(20, 320, 16)
        self.assertEqual(shared_input_two_branch_opening_bytes(20, 160, 16), expected)

    def test_n15_two_branch_wire_report(self):
        report = n15_two_branch_wire_report()
        self.assertEqual(report["packed_e256_variables"], 14)
        self.assertEqual(report["queries_per_branch"], 160)
        self.assertEqual(report["initial_tree_depth"], 16)
        self.assertEqual(report["diamond_high_coefficients_per_branch"], 640)
        self.assertEqual(report["diamond_shared_input_high_coefficients"], 1280)
        self.assertEqual(report["shared_input_authentication_bytes"], 176_128)
        self.assertEqual(report["separate_input_authentication_bytes"], 196_608)
        self.assertEqual(report["input_authentication_savings_bytes"], 20_480)
        self.assertEqual(report["shared_input_values_bytes"], 40_960)
        self.assertEqual(report["shared_input_salts_bytes"], 10_240)
        self.assertEqual(report["shared_input_total_bytes"], 227_392)
        self.assertEqual(
            report["separate_openings_shared_root_total_bytes"], 247_872
        )
        self.assertEqual(report["separate_commitments_total_bytes"], 247_936)
        self.assertEqual(report["branch_blind_tree_bytes"], 123_968)
        self.assertEqual(report["branch_later_trees_bytes"], 347_520)
        self.assertEqual(report["branch_clear_algebra_bytes"], 1_056)
        self.assertEqual(report["full_shared_wire_skeleton_bytes"], 1_172_480)
        self.assertEqual(
            report["full_separate_openings_shared_root_bytes"], 1_192_960
        )
        self.assertEqual(report["full_shared_savings_bytes"], 20_480)


if __name__ == "__main__":
    unittest.main()
