#!/usr/bin/env python3
"""Tests for the isolated CFW26 Section 11 repair audit."""

from __future__ import annotations

import inspect
import itertools
import random
import unittest

import cfw26_section11_repair_audit as audit


class FieldAndR1CSTests(unittest.TestCase):
    def test_random_generator_plants_valid_witnesses(self) -> None:
        rng = random.Random(0xCF026)
        for prime, ell in itertools.product((3, 5, 7, 11), (1, 2, 4)):
            for _ in range(8):
                instance, witness = audit.random_valid_r1cs(prime, ell, rng)
                self.assertEqual(audit.r1cs_residuals(instance, witness), (0,) * (2 * ell))

    def test_matrix_mle_recovers_each_boolean_row(self) -> None:
        rng = random.Random(991)
        instance, _ = audit.random_valid_r1cs(11, 4, rng)
        for matrix in (instance.A, instance.B, instance.C):
            for row_index, row in enumerate(matrix):
                point = audit.index_bits(row_index, instance.sumcheck_variables)
                self.assertEqual(audit.mle_combined_row(matrix, point, 11), row)

    def test_endpoint_zero_sampler(self) -> None:
        rng = random.Random(123)
        for prime in (3, 5, 7, 11, 13):
            for length in (2, 3, 4, 7):
                for _ in range(32):
                    polynomial = audit.sample_endpoint_zero_polynomial(prime, length, rng)
                    self.assertEqual(audit.poly_eval(polynomial, 0, prime), 0)
                    self.assertEqual(audit.poly_eval(polynomial, 1, prime), 0)

    def test_endpoint_masks_preserve_every_boolean_constraint(self) -> None:
        rng = random.Random(777)
        for prime in audit.EXPERIMENT_PRIMES:
            instance, witness = audit.random_valid_r1cs(prime, 4, rng)
            masks = audit.sample_masks(
                prime, instance.sumcheck_variables, audit.INNER_MESSAGE_LENGTH, rng
            )
            for branch in audit.BRANCHES.values():
                self.assertFalse(
                    any(audit.masked_boolean_residuals(instance, witness, masks, branch))
                )

    def test_evaluate_trial_rejects_invalid_witness(self) -> None:
        rng = random.Random(998)
        instance, witness = audit.random_valid_r1cs(11, 2, rng)
        bad = list(witness)
        # Search for a mutation that is not another accidental witness.
        for delta in range(1, instance.prime):
            bad[0] = (witness[0] + delta) % instance.prime
            if any(audit.r1cs_residuals(instance, bad)):
                break
        else:
            self.fail("random instance unexpectedly accepts every first-coordinate mutation")
        d = instance.sumcheck_variables
        masks = audit.sample_masks(11, d, 4, rng)
        with self.assertRaises(audit.AuditError):
            audit.evaluate_trial(
                instance,
                tuple(bad),
                masks,
                (2,) * d,
                3,
                audit.BRANCHES[audit.CANDIDATE],
            )


class BranchDifferentialTests(unittest.TestCase):
    def fixture(self):
        rng = random.Random(20260391)
        while True:
            instance, witness = audit.random_valid_r1cs(13, 4, rng)
            d = instance.sumcheck_variables
            masks = audit.sample_masks(13, d, 4, rng)
            alpha = tuple(rng.randrange(13) for _ in range(d - 1)) + (2,)
            rho = rng.randrange(13)
            printed = audit.evaluate_trial(
                instance,
                witness,
                masks,
                alpha,
                rho,
                audit.BRANCHES[audit.PRINTED],
            )
            if printed.charitable_printed_residual != 0:
                return instance, witness, masks, alpha, rho, printed

    def test_printed_identity_form_rejects_pair_state(self) -> None:
        with self.assertRaises(audit.IllTypedLinearFormState):
            audit.relation_mask_vector(audit.BRANCHES[audit.PRINTED], 2, 3, 4, 5)

    def test_printed_charitable_projection_has_nonzero_residual(self) -> None:
        *_, printed = self.fixture()
        self.assertFalse(printed.well_typed)
        self.assertNotEqual(printed.charitable_printed_residual, 0)

    def test_candidate_coefficient_one_times_identity_is_complete(self) -> None:
        instance, witness, masks, alpha, rho, _ = self.fixture()
        result = audit.evaluate_trial(
            instance,
            witness,
            masks,
            alpha,
            rho,
            audit.BRANCHES[audit.CANDIDATE],
        )
        self.assertTrue(result.well_typed)
        self.assertEqual(result.typed_lhs, result.target_mu)
        self.assertEqual(result.typed_residual, 0)

    def test_coefficient_two_scaled_branch_is_complete(self) -> None:
        instance, witness, masks, alpha, rho, _ = self.fixture()
        result = audit.evaluate_trial(
            instance,
            witness,
            masks,
            alpha,
            rho,
            audit.BRANCHES[audit.SCALED_TWO],
        )
        self.assertTrue(result.well_typed)
        self.assertEqual(result.typed_lhs, result.target_mu)
        self.assertEqual(result.typed_residual, 0)

    def test_local_joint_relation_algebra_is_exhaustive_over_five(self) -> None:
        prime = 5
        for witness_term, mask, ze_coordinate in itertools.product(range(prime), repeat=3):
            for branch_name in (audit.CANDIDATE, audit.SCALED_TWO):
                branch = audit.BRANCHES[branch_name]
                target = ze_coordinate * (
                    witness_term + branch.step8_mask_coefficient * mask
                ) % prime
                lhs = ze_coordinate * witness_term + (
                    branch.output_mask_scale * ze_coordinate * mask
                )
                self.assertEqual(lhs % prime, target)

    def test_coefficient_one_two_hybrid_is_not_an_identity(self) -> None:
        mutations = audit.mutation_experiment()
        self.assertTrue(mutations["step3_one_step8_two_hybrid_rejects"])
        self.assertTrue(mutations["scaled_two_unscaled_output_rejects"])


class DistributionTests(unittest.TestCase):
    def test_endpoint_evaluation_is_exactly_uniform_interior(self) -> None:
        for prime in (3, 5, 7, 11):
            for alpha in range(2, prime):
                histogram = audit.endpoint_evaluation_histogram(prime, 4, alpha)
                self.assertEqual(set(histogram), set(range(prime)))
                self.assertEqual(set(histogram.values()), {prime})

    def test_endpoint_evaluation_collapses_at_zero_and_one(self) -> None:
        for alpha in (0, 1):
            histogram = audit.endpoint_evaluation_histogram(7, 4, alpha)
            self.assertEqual(histogram, {0: 49})

    def test_candidate_value_slice_is_exactly_witness_independent(self) -> None:
        common = dict(
            prime=5,
            length=4,
            alpha_last=2,
            mask_coefficient=1,
            public_terms=(1, 3, 4),
            ze=(1, 2, 4),
        )
        first = audit.value_slice_distribution(witness_terms=(0, 1, 2), **common)
        second = audit.value_slice_distribution(witness_terms=(4, 2, 3), **common)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 5**3)
        self.assertEqual(set(first.values()), {5**3})

    def test_scaled_two_value_slice_is_uniform_only_because_two_is_invertible(self) -> None:
        report = audit.public_slice_experiment()
        self.assertTrue(report["same_public_r1cs_valid_for_both_witnesses"])
        self.assertNotEqual(
            report["witness_contribution_one"], report["witness_contribution_two"]
        )
        scaled = report["branches"][audit.SCALED_TWO]
        self.assertTrue(scaled["two_witness_distributions_equal"])
        self.assertEqual(scaled["support"], 125)
        self.assertEqual(
            report["negative_controls"]["characteristic_two_factor_two_support"], 1
        )

    def test_public_slice_function_has_no_oracle_or_transcript_claim(self) -> None:
        parameters = inspect.signature(audit.value_slice_distribution).parameters
        self.assertNotIn("oracle", parameters)
        self.assertNotIn("transcript", parameters)
        report = audit.public_slice_experiment()
        for branch in report["branches"].values():
            self.assertIn("not the full protocol view", branch["scope"])


class RetainedReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = audit.build_report()

    def test_self_check(self) -> None:
        audit.self_check(self.report)

    def test_random_campaign_exact_counts(self) -> None:
        branches = self.report["randomized_r1cs"]["branches"]
        total = len(audit.EXPERIMENT_PRIMES) * audit.TRIALS_PER_PRIME
        self.assertEqual(branches[audit.CANDIDATE]["typed_relation_passes"], total)
        self.assertEqual(branches[audit.SCALED_TWO]["typed_relation_passes"], total)
        self.assertEqual(branches[audit.PRINTED]["typed_trials"], 0)
        self.assertGreater(branches[audit.PRINTED]["charitable_projection_failures"], 0)

    def test_mutation_corpus_all_discriminates(self) -> None:
        mutations = self.report["mutations"]
        self.assertGreaterEqual(len(mutations), 15)
        self.assertTrue(all(mutations.values()))

    def test_all_authority_flags_remain_false(self) -> None:
        authority = self.report["authority"]
        self.assertTrue(authority["local_candidate_completeness_lemma"])
        for name, value in authority.items():
            if name != "local_candidate_completeness_lemma":
                self.assertFalse(value, name)


if __name__ == "__main__":
    unittest.main()
