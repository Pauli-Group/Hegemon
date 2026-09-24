import unittest

from field_challenge_gate import (
    aggregate_bad_set,
    collision_pairs,
    dp24_bad_pair_count,
    fixed_bad_set_miss_passes,
    fri_query_passes,
    incomplete_scaffold_composed_bits,
    minimum_distinct_queries,
    minimum_effective_bits,
    minimum_fri_queries,
    minimum_incomplete_scaffold_queries,
    retained_m4_projection,
    report,
    strict_field_gate,
)


class FieldChallengeGateTests(unittest.TestCase):
    def test_collision_pairs(self):
        self.assertEqual(collision_pairs(0), 0)
        self.assertEqual(collision_pairs(1), 0)
        self.assertEqual(collision_pairs(4), 6)

    def test_aggregate_keeps_every_symbolic_class(self):
        self.assertEqual(
            aggregate_bad_set(
                challenge_draws=4,
                schwartz_zippel_degree=3,
                sumcheck_round_degree=5,
                batching_degree=7,
                fri_folding_bad_set=11,
            ),
            6 + 3 + 5 + 7 + 11,
        )

    def test_equality_fails_closed(self):
        # At Q=2^64 this is exactly 2^-128, which is not strictly below it.
        self.assertFalse(
            strict_field_gate(256, 1, transcript_entropy_bits=512)
        )

    def test_single_term_minimum_is_258_bits(self):
        self.assertEqual(minimum_effective_bits(1), 258)
        self.assertFalse(
            strict_field_gate(257, 1, transcript_entropy_bits=512)
        )
        self.assertTrue(
            strict_field_gate(258, 1, transcript_entropy_bits=512)
        )

    def test_screened_coefficient_requires_322_bits(self):
        coefficient = 1 << 64
        self.assertEqual(minimum_effective_bits(coefficient), 322)
        self.assertTrue(
            strict_field_gate(384, coefficient, transcript_entropy_bits=512)
        )
        self.assertTrue(
            strict_field_gate(512, coefficient, transcript_entropy_bits=512)
        )

    def test_current_sha256_entropy_cap_rejects_both_wide_fields(self):
        coefficient = 1 << 64
        self.assertFalse(
            strict_field_gate(384, coefficient, transcript_entropy_bits=256)
        )
        self.assertFalse(
            strict_field_gate(512, coefficient, transcript_entropy_bits=256)
        )

    def test_e384_exact_coefficient_boundary(self):
        self.assertTrue(
            strict_field_gate(384, (1 << 127) - 1, transcript_entropy_bits=512)
        )
        self.assertFalse(
            strict_field_gate(384, 1 << 127, transcript_entropy_bits=512)
        )

    def test_fri_query_minima_are_exact(self):
        self.assertEqual(
            [
                minimum_fri_queries(log_inverse_rate=ell, target_bits=128)
                for ell in range(1, 5)
            ],
            [309, 189, 155, 141],
        )
        self.assertFalse(
            fri_query_passes(
                log_inverse_rate=3, query_count=154, target_bits=128
            )
        )
        self.assertTrue(
            fri_query_passes(
                log_inverse_rate=3, query_count=155, target_bits=128
            )
        )
        self.assertFalse(
            fri_query_passes(
                log_inverse_rate=3, query_count=116, target_bits=128
            )
        )

    def test_fixed_bad_set_product_is_exact(self):
        # Product is (6/8)*(5/7)*(4/6) = 5/14.
        self.assertFalse(
            fixed_bad_set_miss_passes(
                pair_count=8,
                bad_pair_count=2,
                query_count=3,
                target_bits=2,
            )
        )
        self.assertTrue(
            fixed_bad_set_miss_passes(
                pair_count=8,
                bad_pair_count=2,
                query_count=6,
                target_bits=2,
            )
        )

    def test_retained_m4_distinct_query_minimum_is_318(self):
        pair_count = 1 << 20
        bad_pairs = dp24_bad_pair_count(
            pair_count=pair_count, log_inverse_rate=3
        )
        self.assertEqual(bad_pairs, 458_752)
        self.assertEqual(
            minimum_distinct_queries(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                target_bits=264,
            ),
            318,
        )
        self.assertFalse(
            fixed_bad_set_miss_passes(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                query_count=317,
                target_bits=264,
            )
        )
        self.assertTrue(
            fixed_bad_set_miss_passes(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                query_count=318,
                target_bits=264,
            )
        )

    def test_retained_q319_projection_matches_source_pin(self):
        projection = retained_m4_projection(319)
        self.assertEqual(
            projection["opened_leaves"], [315, 319, 319, 296, 318, 310, 233]
        )
        self.assertEqual(
            projection["frontier_nodes"],
            [1224, 2807, 3445, 637, 2171, 919, 197],
        )
        self.assertEqual(projection["e384_projection_bytes"], 1_548_704)
        self.assertEqual(
            projection["e512_mixed_projection_bytes"], 1_763_232
        )
        self.assertEqual(
            projection["e512_stock_scalar_projection_bytes"], 1_883_136
        )
        self.assertFalse(projection["is_transcript_independent_lower_bound"])
        self.assertTrue(projection["zero_zk_cost_counterfactual"])

    def test_retained_q116_projection_already_exceeds_provisional_screen(self):
        projection = retained_m4_projection(116)
        self.assertEqual(
            projection["opened_leaves"], [116, 116, 116, 115, 116, 116, 105]
        )
        self.assertEqual(
            projection["frontier_nodes"],
            [620, 1200, 1432, 390, 968, 504, 183],
        )
        self.assertEqual(projection["e384_projection_bytes"], 695_840)
        self.assertEqual(
            projection["under_provisional_512kib_screen"]["e384"], False
        )

    def test_retained_q318_candidate_is_exact_and_over_provisional_screen(self):
        projection = retained_m4_projection(318)
        self.assertEqual(
            projection["opened_leaves"], [313, 318, 318, 295, 318, 305, 244]
        )
        self.assertEqual(
            projection["frontier_nodes"],
            [1244, 2821, 3457, 662, 2185, 947, 191],
        )
        self.assertEqual(projection["e384_projection_bytes"], 1_555_840)
        self.assertEqual(
            projection["e512_mixed_projection_bytes"], 1_770_496
        )
        self.assertEqual(
            projection["e512_stock_scalar_projection_bytes"], 1_889_920
        )
        self.assertEqual(
            projection["under_provisional_512kib_screen"],
            {"e384": False, "e512_mixed": False, "e512_stock_scalar": False},
        )

    def test_incomplete_scaffold_minimum_is_q310_not_production(self):
        pair_count = 1 << 20
        bad_pairs = dp24_bad_pair_count(
            pair_count=pair_count, log_inverse_rate=3
        )
        self.assertLessEqual(
            incomplete_scaffold_composed_bits(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                query_count=309,
            ),
            128,
        )
        self.assertGreater(
            incomplete_scaffold_composed_bits(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                query_count=310,
            ),
            128,
        )
        self.assertEqual(
            minimum_incomplete_scaffold_queries(
                pair_count=pair_count,
                bad_pair_count=bad_pairs,
                target_bits=128,
            ),
            310,
        )
        projection = retained_m4_projection(310)
        self.assertEqual(
            projection["opened_leaves"], [305, 310, 310, 292, 310, 301, 237]
        )
        self.assertEqual(
            projection["frontier_nodes"],
            [1234, 2771, 3391, 654, 2151, 937, 194],
        )
        self.assertEqual(projection["e384_projection_bytes"], 1_528_928)

    def test_report_never_authorizes(self):
        payload = report()
        self.assertFalse(payload["charged_coefficient_is_derived_theorem"])
        self.assertFalse(payload["exact_qrom_reduction_present"])
        self.assertFalse(payload["exact_fri_folding_bound_present"])
        self.assertFalse(payload["complete_zero_knowledge"])
        self.assertFalse(payload["production_authorized"])
        self.assertFalse(payload["composed_pq128"])
        candidate = payload["candidate_sha512_distinct_query_profile"]
        self.assertEqual(
            candidate["historical_264_component_minimum_query_count"], 318
        )
        self.assertFalse(candidate["historical_264_component_one_fewer_passes"])
        self.assertEqual(
            candidate["incomplete_scaffold_composed_gt128"][
                "minimum_query_count"
            ],
            310,
        )
        self.assertFalse(
            candidate["incomplete_scaffold_composed_gt128"][
                "production_selectable"
            ]
        )
        self.assertIsNone(candidate["production_minimum_query_count"])
        self.assertFalse(candidate["provisional_screen_is_consensus_authority"])
        self.assertEqual(
            candidate["q310_e384_minus_retained_comparator_bytes"], 184_100
        )
        self.assertEqual(
            candidate["q116_e384_over_provisional_screen_bytes"], 171_552
        )
        self.assertFalse(candidate["universal_basefold_lower_bound"])
        self.assertFalse(candidate["fixed_bad_set_product_is_adaptive_fri_theorem"])
        self.assertFalse(candidate["complete_zero_knowledge"])

    def test_invalid_inputs_fail(self):
        with self.assertRaises(ValueError):
            minimum_effective_bits(0)
        with self.assertRaises(ValueError):
            collision_pairs(-1)
        with self.assertRaises(ValueError):
            minimum_fri_queries(log_inverse_rate=0, target_bits=128)
        with self.assertRaises(ValueError):
            dp24_bad_pair_count(pair_count=8, log_inverse_rate=3)
        with self.assertRaises(ValueError):
            fixed_bad_set_miss_passes(
                pair_count=8,
                bad_pair_count=9,
                query_count=1,
                target_bits=1,
            )


if __name__ == "__main__":
    unittest.main()
