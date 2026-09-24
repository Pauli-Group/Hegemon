#!/usr/bin/env python3
"""Tests for the CFW26 nonzero-coefficient theorem-delta artifact."""

from __future__ import annotations

import itertools
import unittest
from fractions import Fraction

import cfw26_parametric_repair as repair


class FactorCTests(unittest.TestCase):
    def test_every_nonzero_coefficient_is_a_value_bijection(self) -> None:
        for prime in (3, 5, 7, 11, 13):
            for coefficient in range(1, prime):
                histogram = repair.value_histogram(prime, 4, 2, coefficient)
                self.assertEqual(set(histogram), set(range(prime)))
                self.assertEqual(set(histogram.values()), {prime})

    def test_zero_coefficient_collapses_value_hiding(self) -> None:
        for prime in (3, 5, 7, 11):
            histogram = repair.value_histogram(prime, 4, 2, 0)
            self.assertEqual(histogram, {0: prime**2})

    def test_endpoint_challenge_collapses_even_nonzero_coefficient(self) -> None:
        for endpoint in (0, 1):
            self.assertEqual(repair.value_histogram(7, 4, endpoint, 3), {0: 49})

    def test_hegemon_selects_one_without_claiming_author_intent(self) -> None:
        report = repair.build_report()
        self.assertEqual(report["factor_c"]["hegemon_selected_c"], 1)
        self.assertFalse(report["authority"]["theorem_11_3_inherited"])

    def test_printed_endpoint_state_rejects_x_squared_minus_x(self) -> None:
        case = repair.endpoint_state_counterexample()
        self.assertEqual(case["evaluation_at_zero"], 0)
        self.assertEqual(case["evaluation_at_one"], 0)
        self.assertNotEqual(case["printed_st2_dot"], 0)
        self.assertTrue(case["printed_endpoint_relation_rejects_honest_mask"])

    def test_pow_one_endpoint_state_repairs_the_relation(self) -> None:
        case = repair.endpoint_state_counterexample()
        self.assertEqual(case["repaired_st2_dot"], 0)
        self.assertTrue(case["repaired_endpoint_relation_accepts_honest_mask"])


class OuterTranscriptRankTests(unittest.TestCase):
    def test_odd_characteristic_map_is_bijection_onto_constraint_kernel(self) -> None:
        for prime, rounds, length in itertools.product(
            (3, 5, 7, 11), (1, 2, 3, 4), (3, 4, 6)
        ):
            case = repair.outer_rank_case(prime, rounds, length)
            self.assertTrue(case["image_satisfies_constraints"])
            self.assertEqual(case["map_rank"], rounds * length)
            self.assertEqual(case["constraint_kernel_dimension"], rounds * length)
            self.assertEqual(case["constraint_rank"], rounds + 1)

    def test_characteristic_two_map_loses_rank(self) -> None:
        for rounds in (2, 3, 4):
            case = repair.outer_rank_case(2, rounds, 4)
            self.assertLess(case["map_rank"], case["input_dimension"])
            self.assertTrue(case["image_satisfies_constraints"])

    def test_map_outputs_satisfy_every_sumcheck_constraint(self) -> None:
        prime = 7
        rounds = 3
        length = 5
        alpha = (2, 4, 3)
        map_matrix = repair.outer_map_matrix(prime, rounds, length, alpha)
        constraints = repair.outer_constraint_matrix(prime, rounds, length, alpha)
        product = repair.matrix_product(constraints, map_matrix, prime)
        self.assertTrue(all(value == 0 for row in product for value in row))

    def test_output_dimension_and_constraint_count(self) -> None:
        case = repair.outer_rank_case(11, 5, 8)
        self.assertEqual(case["input_dimension"], 40)
        self.assertEqual(case["output_dimension"], 46)
        self.assertEqual(case["constraint_rank"], 6)


class DegreeAndRBRTests(unittest.TestCase):
    def test_per_round_degree_premise_is_distinct_from_initial_degree(self) -> None:
        case = repair.degree_ledger(rounds=10, inner_length=4, outer_length=8)
        self.assertEqual(case["maximum_h_univariate_degree"], 7)
        self.assertEqual(case["h_space_maximum_degree"], 7)
        self.assertTrue(case["outer_length_closes_h_degree"])
        self.assertEqual(case["initial_consistency_total_degree"], 11)
        self.assertFalse(case["printed_initial_bound_has_needed_dimension_domination"])

    def test_initial_rbr_counterexample_violates_printed_numerator(self) -> None:
        case = repair.initial_rbr_degree_counterexample()
        actual = Fraction(
            case["acceptance_probability"]["numerator"],
            case["acceptance_probability"]["denominator"],
        )
        printed = Fraction(9, 101)
        corrected = Fraction(11, 101)
        self.assertGreater(actual, printed)
        self.assertLessEqual(actual, corrected)
        self.assertTrue(case["paper_length_premise_holds"])
        self.assertTrue(case["source_relation_has_no_witness"])
        self.assertTrue(case["downstream_target_relation_has_witness_on_accepting_event"])

    def test_sparse_invalid_r1cs_residual_has_product_mle(self) -> None:
        # Delta at the all-one Boolean point has multilinear extension prod r_i.
        prime = 7
        rounds = 4
        for point in itertools.product(range(prime), repeat=rounds):
            mle = 1
            for coordinate in point:
                mle = mle * coordinate % prime
            direct = 0
            for boolean_row in itertools.product((0, 1), repeat=rounds):
                residual = int(all(boolean_row))
                eq = 1
                for coordinate, bit in zip(point, boolean_row):
                    eq = eq * (coordinate if bit else 1 - coordinate) % prime
                direct = (direct + residual * eq) % prime
            self.assertEqual(mle, direct)

    def test_dimension_bound_closes_when_outer_length_dominates_rounds(self) -> None:
        case = repair.degree_ledger(rounds=8, inner_length=4, outer_length=8)
        self.assertTrue(case["outer_length_closes_h_degree"])
        self.assertTrue(case["printed_initial_bound_has_needed_dimension_domination"])


class AdaptiveQuerySeparationTests(unittest.TestCase):
    def test_every_fixed_two_query_set_is_close(self) -> None:
        case = repair.adaptive_query_counterexample(11, 2)
        self.assertEqual(case["maximum_fixed_set_distance"]["exact"], "2/11")
        self.assertTrue(case["all_messages_and_fixed_sets_enumerated"])

    def test_pointer_encoding_is_injective(self) -> None:
        case = repair.adaptive_query_counterexample(11, 2)
        self.assertTrue(case["encoding_is_injective"])

    def test_two_adaptive_queries_distinguish_perfectly(self) -> None:
        case = repair.adaptive_query_counterexample(11, 2)
        self.assertEqual(case["adaptive_distance"]["exact"], "1/1")
        self.assertTrue(case["fixed_set_bound_does_not_imply_adaptive_bound"])

    def test_pointer_strategy_recovers_each_message(self) -> None:
        prime = 11
        for message, pointer in itertools.product(range(prime), repeat=2):
            word = repair.pointer_encoding_word(prime, message, pointer)
            observed_pointer = word[0]
            self.assertEqual(word[1 + observed_pointer], message)


class ReportBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = repair.build_report()

    def test_self_check(self) -> None:
        repair.self_check(self.report)

    def test_only_bounded_conditional_results_are_true(self) -> None:
        authority = self.report["authority"]
        self.assertTrue(authority["perfect_completeness_proved"])
        self.assertTrue(authority["formal_nonadaptive_whole_hvzk_conditional_on_encoding_zk"])
        for key in (
            "printed_rbr_error_vector_proved",
            "full_rbr_theorem_proved",
            "adaptive_query_hvzk_proved",
            "theorem_11_3_inherited",
            "complete_zero_knowledge",
            "qrom_security",
            "pq128_composition",
            "production_authorized",
        ):
            self.assertFalse(authority[key], key)

    def test_factor_c_does_not_replace_structural_twos(self) -> None:
        ledger = self.report["factor_occurrences"]
        self.assertEqual(ledger["hegemon_selected_c"], 1)
        self.assertFalse(ledger["selection_is_author_erratum"])
        structural = " ".join(item["term"] for item in ledger["retain_structural_two"])
        self.assertIn("char(F) != 2", structural)
        self.assertIn("2^(d-j)", structural)
        self.assertIn("|F|-2", structural)

    def test_exact_hegemon_scale_counts(self) -> None:
        counts = self.report["profile_counts"]
        self.assertEqual(counts["inner_oracles"], 78)
        self.assertEqual(counts["outer_oracles"], 26)
        self.assertEqual(counts["main_oracles"], 1)
        self.assertEqual(counts["encoding_hybrid_terms"], 105)
        self.assertEqual(counts["printed_rbr_error_coordinates"], 29)


if __name__ == "__main__":
    unittest.main()
