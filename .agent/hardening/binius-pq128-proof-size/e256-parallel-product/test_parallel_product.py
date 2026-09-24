#!/usr/bin/env python3
from __future__ import annotations

import unittest
from fractions import Fraction

import parallel_product as product


class ConditionalProductTheoremTests(unittest.TestCase):
    def test_two_complete_132_bit_conditional_errors_multiply(self) -> None:
        error = Fraction(1, 1 << 132)
        self.assertEqual(
            product.conditional_product_bound(error, error),
            Fraction(1, 1 << 264),
        )

    def test_finite_branch_local_exhaustion_reaches_exact_product(self) -> None:
        self.assertEqual(product.exhaustive_branch_local_max(2), Fraction(1, 4))
        self.assertEqual(product.exhaustive_branch_local_max(3), Fraction(1, 9))
        self.assertEqual(product.exhaustive_branch_local_max(4), Fraction(1, 16))

    def test_fixed_oracle_independent_query_positive_control(self) -> None:
        experiment = product.fixed_oracle_independent_queries(4, 1)
        self.assertEqual(experiment.marginal_a, Fraction(1, 4))
        self.assertEqual(experiment.marginal_b, Fraction(1, 4))
        self.assertEqual(experiment.joint, Fraction(1, 16))
        self.assertFalse(experiment.violates_product)

    def test_probability_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            product.conditional_product_bound(Fraction(-1, 2), Fraction(1, 2))
        with self.assertRaises(ValueError):
            product.conditional_product_bound(Fraction(1, 2), Fraction(3, 2))


class CounterexampleTests(unittest.TestCase):
    def test_shared_query_does_not_square_proximity_miss(self) -> None:
        experiment = product.shared_query_schedule_counterexample()
        self.assertEqual(experiment.joint, Fraction(1, 2))
        self.assertEqual(experiment.naive_product, Fraction(1, 4))
        self.assertTrue(experiment.violates_product)

    def test_independent_domains_do_not_constrain_cross_branch_response(self) -> None:
        experiment = product.adaptive_cross_branch_counterexample()
        self.assertEqual(experiment.marginal_a, Fraction(1, 2))
        self.assertEqual(experiment.marginal_b, Fraction(1, 2))
        self.assertEqual(experiment.joint, Fraction(1, 2))
        self.assertTrue(experiment.violates_product)

    def test_marginal_bounds_do_not_replace_pointwise_conditioning(self) -> None:
        experiment = product.average_only_counterexample()
        self.assertEqual(experiment.joint, Fraction(1, 2))
        self.assertTrue(experiment.violates_product)

    def test_arbitrary_joint_predicates_reach_half_with_half_marginals(self) -> None:
        self.assertEqual(
            product.exhaustive_correlated_marginal_max(), Fraction(1, 2)
        )

    def test_commitment_grinding_survives_domain_separation(self) -> None:
        self.assertEqual(
            product.commitment_grinding_counterexample(1).joint,
            Fraction(1, 4),
        )
        self.assertEqual(
            product.commitment_grinding_counterexample(2).joint,
            Fraction(7, 16),
        )
        self.assertEqual(
            product.commitment_grinding_counterexample(3).joint,
            Fraction(37, 64),
        )

    def test_split_relation_does_not_get_two_detection_chances(self) -> None:
        experiment = product.split_relation_counterexample()
        self.assertEqual(experiment.joint, Fraction(1, 2))
        self.assertEqual(experiment.naive_product, Fraction(1, 4))
        self.assertTrue(experiment.violates_product)


class TranscriptContractTests(unittest.TestCase):
    def test_current_source_is_only_root_and_domain_plumbing(self) -> None:
        evidence = product.CURRENT_SOURCE_EVIDENCE
        self.assertTrue(evidence.shared_oracle_fixed_before_any_challenge)
        self.assertTrue(evidence.distinct_length_framed_branch_domains)
        self.assertFalse(evidence.ideal_product_instantiated)
        self.assertFalse(evidence.qrom_product_instantiated)
        self.assertIn(
            "pointwise_history_conditional_branch_bound", evidence.ideal_missing()
        )

    def test_every_required_contract_bit_is_explicit(self) -> None:
        required = product.REQUIRED_IDEAL_CONTRACT
        self.assertTrue(required.ideal_product_instantiated)
        self.assertTrue(required.qrom_product_instantiated)

    def test_transcript_order_fixes_root_before_challenges(self) -> None:
        order = product.transcript_order()
        self.assertEqual([stage["stage"] for stage in order], list(range(5)))
        self.assertIn("immutable B128 oracle root", order[0]["message"])
        self.assertIn("proximity queries are not shared", order[2]["message"])
        self.assertEqual(
            order[3]["cross_branch_dependency_allowed"], "only_if_quantified"
        )

    def test_exact_sha512_branch_framing_is_disjoint_and_order_binding(self) -> None:
        common = product.canonical_common_prefix(
            profile=b"strict-profile",
            statement=b"maximum-relation-statement",
            shared_root=bytes(range(64)),
            prechallenge_commitments=(b"first", b"second"),
        )
        reordered = product.canonical_common_prefix(
            profile=b"strict-profile",
            statement=b"maximum-relation-statement",
            shared_root=bytes(range(64)),
            prechallenge_commitments=(b"second", b"first"),
        )
        seed_a = product.branch_challenge_seed(
            common_prefix=common,
            branch="A",
            round_index=0,
            local_prefix=b"local",
        )
        seed_b = product.branch_challenge_seed(
            common_prefix=common,
            branch="B",
            round_index=0,
            local_prefix=b"local",
        )
        reordered_a = product.branch_challenge_seed(
            common_prefix=reordered,
            branch="A",
            round_index=0,
            local_prefix=b"local",
        )
        self.assertEqual(len(seed_a), 64)
        self.assertNotEqual(seed_a, seed_b)
        self.assertNotEqual(seed_a, reordered_a)
        self.assertEqual(product.e256_challenge_bytes(seed_a), seed_a[:32])

    def test_strict_transcript_rejects_wrong_root_and_branch(self) -> None:
        with self.assertRaises(ValueError):
            product.canonical_common_prefix(
                profile=b"p",
                statement=b"s",
                shared_root=bytes(56),
                prechallenge_commitments=(),
            )
        with self.assertRaises(ValueError):
            product.branch_challenge_seed(
                common_prefix=b"common",
                branch="shared",
                round_index=0,
                local_prefix=b"",
            )


class ParameterAndLossTests(unittest.TestCase):
    def test_half_budget_query_counts(self) -> None:
        self.assertEqual(product.query_count(16), 44)
        self.assertEqual(product.query_count(32), 33)
        self.assertGreaterEqual(product.rate_profile(16).query_term_bits_per_branch, 132)
        self.assertGreaterEqual(product.rate_profile(32).query_term_bits_per_branch, 132)

    def test_r16_wire_is_reproduced_independently(self) -> None:
        profile = product.rate_profile(16)
        self.assertEqual(profile.merkle_digest_bytes, 64)
        self.assertTrue(profile.strict_proof_commitment_width)
        self.assertEqual(profile.salt_bytes_per_opened_leaf, 32)
        self.assertFalse(profile.salt_sufficient_for_qrom_zk)
        self.assertEqual(profile.union_opened_leaves, 88)
        self.assertEqual(profile.frontier_nodes_max, 920)
        self.assertEqual(profile.merkle_wire_bytes, 67_392)
        self.assertEqual(profile.algebraic_wire_bytes, 14_208)
        self.assertEqual(profile.raw_wire_bytes, 83_712)
        self.assertEqual(profile.envelope_wire_bytes, 83_724)
        self.assertEqual(profile.raw_headroom_bytes, 40_356)
        self.assertFalse(profile.product_bytes_are_security_authorized)

    def test_r32_wire_is_reproduced_independently(self) -> None:
        profile = product.rate_profile(32)
        self.assertEqual(profile.merkle_digest_bytes, 64)
        self.assertTrue(profile.strict_proof_commitment_width)
        self.assertEqual(profile.union_opened_leaves, 66)
        self.assertEqual(profile.frontier_nodes_max, 788)
        self.assertEqual(profile.merkle_wire_bytes, 56_832)
        self.assertEqual(profile.algebraic_wire_bytes, 10_688)
        self.assertEqual(profile.raw_wire_bytes, 69_632)
        self.assertEqual(profile.envelope_wire_bytes, 69_644)
        self.assertEqual(profile.raw_headroom_bytes, 54_436)
        self.assertFalse(profile.product_bytes_are_security_authorized)

    def test_direct_bcs_classical_salt_is_priced_but_not_qrom(self) -> None:
        rate16 = product.direct_bcs_classical_rate_profile(16)
        rate32 = product.direct_bcs_classical_rate_profile(32)
        self.assertEqual(rate16.salt_bytes_per_opened_leaf, 148)
        self.assertEqual(rate16.raw_wire_bytes, 93_920)
        self.assertEqual(rate32.salt_bytes_per_opened_leaf, 148)
        self.assertEqual(rate32.raw_wire_bytes, 77_288)
        self.assertTrue(rate32.direct_bcs_n18_salt_floor_met)
        self.assertFalse(rate32.direct_bcs_common_lambda_parameter_match)
        self.assertFalse(rate32.direct_bcs_classical_theorem_instantiated)
        self.assertFalse(rate32.salt_sufficient_for_qrom_zk)
        self.assertFalse(rate32.product_bytes_are_security_authorized)

    def test_old_63320_row_is_named_nonstrict_negative_control(self) -> None:
        legacy = product.rejected_legacy_rate_profile(32)
        self.assertEqual(legacy.merkle_digest_bytes, 56)
        self.assertEqual(legacy.raw_wire_bytes, 63_320)
        self.assertFalse(legacy.strict_proof_commitment_width)
        self.assertFalse(legacy.product_bytes_are_security_authorized)

    def test_union_loss_consumes_the_four_bit_qrom_margin(self) -> None:
        self.assertEqual(product.union_bound_bits([132.0] * 16), 128.0)
        self.assertLess(product.union_bound_bits([132.0] * 17), 128.0)
        screen = product.conditional_security_screen()
        self.assertEqual(
            screen["single_term_qrom_loss_budget_before_pq128_bits"], 4.0
        )
        self.assertFalse(screen["project_square_root_is_qrom_theorem"])
        self.assertFalse(screen["strict_pq128_admitted"])

    def test_source_pins_match(self) -> None:
        self.assertTrue(all(record["matches"] for record in product.source_records()))


if __name__ == "__main__":
    unittest.main()
