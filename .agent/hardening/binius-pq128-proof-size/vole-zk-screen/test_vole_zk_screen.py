#!/usr/bin/env python3

import unittest

from vole_zk_screen import (
    FAEST_256S_SHAPE,
    HARD_CAP_BYTES,
    M4,
    M4Relation,
    STRICT_PQ128_SCREEN,
    VoleProfile,
    best_checkpoint_estimate,
    best_keccak_degree_split,
    checkpoint_estimate,
    faest_v2_signature_bytes,
    paper_linear_screens,
)


class VoleZkScreenTests(unittest.TestCase):
    def test_m4_boolean_gate_mapping(self) -> None:
        self.assertEqual(M4.word_ands, 49_800)
        self.assertEqual(M4.boolean_ands, 3_187_200)
        self.assertEqual(M4.private_bits, 42_944)
        self.assertEqual(M4.public_bits, 7_296)

    def test_word_and_reward_hack_is_explicit(self) -> None:
        screen = paper_linear_screens()
        self.assertEqual(screen["voleith_16_bits_per_boolean_and_bytes"], 6_374_400)
        self.assertEqual(screen["limbo_42_bits_per_boolean_and_bytes"], 16_732_800)
        self.assertEqual(screen["invalid_16_bits_per_word_and_reward_hack_bytes"], 99_600)
        self.assertLess(screen["invalid_16_bits_per_word_and_reward_hack_bytes"], HARD_CAP_BYTES)
        self.assertGreater(screen["voleith_16_bits_per_boolean_and_bytes"], HARD_CAP_BYTES)

    def test_degree_16_keccak_checkpoint_matches_primary_construction(self) -> None:
        split = best_keccak_degree_split(6)
        self.assertEqual(split.forward_rounds, 4)
        self.assertEqual(split.inverse_rounds, 2)
        self.assertEqual(split.max_degree, 16)
        estimate = checkpoint_estimate(6, FAEST_256S_SHAPE)
        # Four 1,600-bit checkpoint states per permutation = 800 bytes.
        self.assertEqual(estimate.checkpoint_bits // M4.keccak_permutations // 8, 800)

    def test_one_permutation_calibrates_to_pomfrit_14900_byte_result(self) -> None:
        one_permutation = M4Relation(
            keccak_permutations=1,
            private_words=0,
            public_words=0,
        )
        faest128_forest = VoleProfile(
            name="faest128s-forest",
            lambda_bits=128,
            tau=11,
            small_vole_k=12,
        )
        estimate = checkpoint_estimate(6, faest128_forest, one_permutation)
        # The primary implementation reports 14.9 KB. The independent section
        # model gives 14,690 bytes without fitting a free constant to that row.
        self.assertEqual(estimate.sections.total, 14_690)
        self.assertLess(abs(estimate.sections.total - 14_900), 300)

    def test_official_faest_v2_rows_reproduce_spec_sizes(self) -> None:
        self.assertEqual(
            faest_v2_signature_bytes(
                lambda_bits=128,
                tau=11,
                witness_bits=1_280,
                degree=3,
                consistency_padding_bits=16,
                tree_opening_seeds=102,
                leaf_commitment_blocks=3,
            ),
            4_506,
        )
        self.assertEqual(
            faest_v2_signature_bytes(
                lambda_bits=256,
                tau=22,
                witness_bits=3_104,
                degree=3,
                consistency_padding_bits=16,
                tree_opening_seeds=245,
                leaf_commitment_blocks=3,
            ),
            20_696,
        )

    def test_strict_screen_never_promotes(self) -> None:
        best = best_checkpoint_estimate(STRICT_PQ128_SCREEN)
        self.assertFalse(best.frontier_admitted)
        self.assertFalse(best.security.admitted)
        self.assertGreater(best.sections.total, HARD_CAP_BYTES)
        self.assertTrue(best.security.numeric_pq128_pass)
        self.assertGreater(
            STRICT_PQ128_SCREEN.tau * M4.private_bits // 8,
            HARD_CAP_BYTES,
        )

    def test_faest256_degree_loss_is_not_silently_pq128(self) -> None:
        best = best_checkpoint_estimate(FAEST_256S_SHAPE)
        self.assertLess(best.security.conservative_numeric_bits, 128)
        self.assertFalse(best.security.numeric_pq128_pass)


if __name__ == "__main__":
    unittest.main()
