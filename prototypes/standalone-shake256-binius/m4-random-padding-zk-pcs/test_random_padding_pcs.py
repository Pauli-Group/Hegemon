#!/usr/bin/env python3
"""Adversarial tests for the random-padding PCS rank and wire audit."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("random_padding_pcs.py")
SPEC = importlib.util.spec_from_file_location("random_padding_pcs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pcs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pcs
SPEC.loader.exec_module(pcs)


class FieldAndRankTests(unittest.TestCase):
    def test_b128_reduction_inverse_and_distributivity(self) -> None:
        high = 1 << 127
        self.assertEqual(pcs.B128.mul(high, 2), 0x87)
        value = 0x0123456789ABCDEFFEDCBA9876543210
        inverse = pcs.B128.inverse(value)
        self.assertEqual(pcs.B128.mul(value, inverse), 1)
        a, b, c = 0x1234, 0x5678, 0x9ABC
        self.assertEqual(
            pcs.B128.mul(a, b ^ c),
            pcs.B128.mul(a, b) ^ pcs.B128.mul(a, c),
        )

    def test_exact_matrix_rank(self) -> None:
        rows = ((1, 0, 1), (0, 1, 1), (1, 1, 0))
        self.assertEqual(pcs.matrix_rank(rows, pcs.GF16), 2)
        self.assertEqual(pcs.matrix_rank(((1, 0), (0, 1)), pcs.GF16), 2)
        with self.assertRaises(ValueError):
            pcs.matrix_rank(((1,), (1, 2)), pcs.GF16)

    def test_full_padding_rank_is_exactly_uniform_and_source_free(self) -> None:
        # Y = [x+r0, x+r1] has an identity padding block.
        rows = ((1, 1, 0), (1, 0, 1))
        audit = pcs.audit_observation_matrix(
            rows, 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertTrue(audit.padding_full_row_rank)
        self.assertTrue(audit.witness_independent_for_fixed_matrix)
        self.assertTrue(audit.full_uniform_for_fixed_matrix)
        self.assertTrue(audit.lemma_applies)
        first = pcs.exhaustive_distribution(rows, (3,), pcs.GF16)
        second = pcs.exhaustive_distribution(rows, (11,), pcs.GF16)
        self.assertEqual(first, second)
        self.assertEqual(len(first), pcs.GF16.size**2)
        self.assertEqual(set(first.values()), {1})

    def test_rank_deficiency_exposes_a_witness_coset(self) -> None:
        # Padding shifts both observations together; their difference is x.
        rows = ((1, 1), (0, 1))
        audit = pcs.audit_observation_matrix(
            rows, 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertEqual(audit.padding_rank, 1)
        self.assertEqual(audit.joint_rank, 2)
        self.assertFalse(audit.witness_independent_for_fixed_matrix)
        self.assertFalse(audit.lemma_applies)
        zero = pcs.exhaustive_distribution(rows, (0,), pcs.GF16)
        one = pcs.exhaustive_distribution(rows, (1,), pcs.GF16)
        self.assertTrue(set(zero).isdisjoint(set(one)))

    def test_rank_deficient_can_be_source_free_but_not_fully_uniform(self) -> None:
        # Both active and padding columns span the same one-dimensional image.
        rows = ((1, 1), (1, 1))
        audit = pcs.audit_observation_matrix(
            rows, 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertEqual(audit.padding_rank, 1)
        self.assertEqual(audit.joint_rank, 1)
        self.assertTrue(audit.witness_independent_for_fixed_matrix)
        self.assertFalse(audit.full_uniform_for_fixed_matrix)
        self.assertTrue(audit.lemma_applies)

    def test_exhaustive_gf2_matrices_match_both_rank_criteria(self) -> None:
        # Exhaust every 1-row and 2-row matrix with one active and two random
        # columns, not only hand-picked examples.
        for observations in (1, 2):
            matrix_entries = observations * 3
            for encoded in range(1 << matrix_entries):
                rows = tuple(
                    tuple(
                        (encoded >> (row * 3 + column)) & 1
                        for column in range(3)
                    )
                    for row in range(observations)
                )
                audit = pcs.audit_observation_matrix(
                    rows, 1, pcs.GF2, schedule_independent_of_padding=True
                )
                zero = pcs.exhaustive_distribution(rows, (0,), pcs.GF2)
                one = pcs.exhaustive_distribution(rows, (1,), pcs.GF2)
                self.assertEqual(
                    zero == one,
                    audit.witness_independent_for_fixed_matrix,
                    rows,
                )
                fully_uniform = (
                    len(zero) == (1 << observations)
                    and len(set(zero.values())) == 1
                )
                self.assertEqual(
                    fully_uniform,
                    audit.full_uniform_for_fixed_matrix,
                    rows,
                )


class RsAndUnionTests(unittest.TestCase):
    def test_vandermonde_tail_certificate_matches_exact_b128_rank(self) -> None:
        active, total, observations = 3, 9, 5
        points = tuple(pcs.affine_domain_point(index, 8) for index in range(observations))
        certificate = pcs.vandermonde_tail_certificate(
            points, active, total, pcs.B128
        )
        self.assertTrue(certificate.full_row_rank)
        rows = [
            pcs.polynomial_evaluation_row(point, total, pcs.B128)
            for point in points
        ]
        self.assertEqual(
            pcs.matrix_rank([row[active:] for row in rows], pcs.B128),
            observations,
        )

    def test_zero_domain_point_leaks_the_constant_coefficient(self) -> None:
        # At alpha=0 all positive powers vanish, so a high-coefficient pad has
        # no effect on the opened constant coefficient.
        row = pcs.polynomial_evaluation_row(0, 4, pcs.GF16)
        self.assertEqual(row, (1, 0, 0, 0))
        certificate = pcs.vandermonde_tail_certificate((0,), 1, 4, pcs.GF16)
        self.assertFalse(certificate.points_nonzero)
        self.assertFalse(certificate.full_row_rank)
        audit = pcs.audit_observation_matrix(
            (row,), 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertEqual(audit.padding_rank, 0)
        self.assertEqual(audit.joint_rank, 1)
        self.assertNotEqual(
            pcs.exhaustive_distribution((row,), (3,), pcs.GF16),
            pcs.exhaustive_distribution((row,), (7,), pcs.GF16),
        )

    def test_affine_domain_is_nonzero_distinct_additive_coset(self) -> None:
        points = tuple(pcs.affine_domain_point(index, 10) for index in range(1 << 10))
        self.assertNotIn(0, points)
        self.assertEqual(len(set(points)), len(points))
        shift = pcs.AFFINE_DOMAIN_SHIFT
        self.assertEqual({point ^ shift for point in points}, set(range(1 << 10)))

    def test_query_terminal_and_fri_union_is_uniform_when_full_rank(self) -> None:
        # One opened RS symbol plus one E256 terminal/fold functional yields
        # three B128 rows.  The padding submatrix is triangular and full-rank.
        functional = (
            (0, 0),
            (0, 0),
            (1, 0),
            (0, 1),
        )
        rows = pcs.observation_union_matrix((2,), (functional,), 4, pcs.GF16)
        self.assertEqual(len(rows), 3)
        audit = pcs.audit_observation_matrix(
            rows, 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertEqual(audit.padding_rank, 3)
        self.assertTrue(audit.full_uniform_for_fixed_matrix)
        first = pcs.exhaustive_distribution(rows, (4,), pcs.GF16)
        second = pcs.exhaustive_distribution(rows, (13,), pcs.GF16)
        self.assertEqual(first, second)
        self.assertEqual(len(first), pcs.GF16.size**3)
        self.assertEqual(set(first.values()), {1})

    def test_terminal_fri_row_can_destroy_full_union_rank(self) -> None:
        duplicated = (
            (0, 0),
            (0, 0),
            (1, 1),
            (0, 0),
        )
        rows = pcs.observation_union_matrix((2,), (duplicated,), 4, pcs.GF16)
        audit = pcs.audit_observation_matrix(
            rows, 1, pcs.GF16, schedule_independent_of_padding=True
        )
        self.assertLess(audit.padding_rank, len(rows))
        self.assertFalse(audit.full_uniform_for_fixed_matrix)

    def test_functional_width_mismatch_rejects(self) -> None:
        with self.assertRaises(ValueError):
            pcs.observation_union_matrix((2,), (((1, 2),),), 4, pcs.GF16)


class AdaptivityAndReuseTests(unittest.TestCase):
    def test_adaptive_full_rank_per_realized_row_is_not_uniform(self) -> None:
        # Every selected one-row matrix is nonzero (rank one), but selection is
        # correlated with the pad.  The result has 3/4 bias toward the witness.
        zero = pcs.adaptive_selector_distribution(0)
        one = pcs.adaptive_selector_distribution(1)
        self.assertEqual(zero, {0: 3, 1: 1})
        self.assertEqual(one, {1: 3, 0: 1})
        self.assertNotEqual(zero, one)
        audit = pcs.audit_observation_matrix(
            ((1, 1),), 1, pcs.GF2, schedule_independent_of_padding=False
        )
        self.assertTrue(audit.padding_full_row_rank)
        self.assertFalse(audit.lemma_applies)

    def test_reusing_padding_cancels_it_exactly(self) -> None:
        rows = ((1, 1, 0), (1, 0, 1))
        first_active = (3,)
        second_active = (12,)
        reused = (7, 9)
        observed_delta = pcs.key_reuse_delta(
            rows, first_active, second_active, reused, pcs.GF16
        )
        expected = pcs.apply_matrix(
            rows,
            (first_active[0] ^ second_active[0], 0, 0),
            pcs.GF16,
        )
        self.assertEqual(observed_delta, expected)
        self.assertEqual(observed_delta, (15, 15))


class HashAndTranscriptTests(unittest.TestCase):
    def test_salted_four_symbol_leaf_is_position_and_salt_bound(self) -> None:
        symbols = (1, 2, 3, 4)
        salt = bytes(range(pcs.CANDIDATE_SALT_BYTES))
        digest = pcs.salted_leaf_hash(7, symbols, salt)
        self.assertEqual(len(digest), pcs.STRICT_SHAKE512_BYTES)
        self.assertNotEqual(digest, pcs.salted_leaf_hash(8, symbols, salt))
        changed = bytearray(salt)
        changed[0] ^= 1
        self.assertNotEqual(digest, pcs.salted_leaf_hash(7, symbols, bytes(changed)))
        self.assertNotEqual(digest, pcs.salted_leaf_hash(7, (1, 2, 3, 5), salt))

    def test_merkle_node_domain_is_separate_from_leaf_domain(self) -> None:
        salt = b"s" * pcs.CANDIDATE_SALT_BYTES
        left = pcs.salted_leaf_hash(0, (0, 1, 2, 3), salt)
        right = pcs.salted_leaf_hash(1, (4, 5, 6, 7), salt)
        parent = pcs.merkle_node_hash(0, 0, left, right)
        self.assertEqual(len(parent), pcs.STRICT_SHAKE512_BYTES)
        self.assertNotEqual(parent, left)
        self.assertNotEqual(parent, pcs.merkle_node_hash(0, 0, right, left))

    def test_two_e256_branches_share_root_but_are_domain_separated(self) -> None:
        root = bytes(range(pcs.STRICT_SHAKE512_BYTES))
        context = b"maximum83/public/context"
        digest = pcs.branch_transcript_digest(root, context, 0, 0)
        self.assertEqual(len(digest), pcs.FIAT_SHAMIR_DIGEST_BYTES)
        first_a = pcs.branch_challenge_e256(root, context, 0, 0)
        first_b = pcs.branch_challenge_e256(root, context, 1, 0)
        self.assertNotEqual(first_a, first_b)
        self.assertEqual(first_a, pcs.branch_challenge_e256(root, context, 0, 0))
        self.assertNotEqual(first_a, pcs.branch_challenge_e256(root, context, 0, 1))

    def test_shake448_leaf_and_node_exist_only_as_nonstrict_controls(self) -> None:
        salt = b"n" * pcs.CANDIDATE_SALT_BYTES
        left = pcs.salted_leaf_hash_nonstrict_shake448(0, (0, 1, 2, 3), salt)
        right = pcs.salted_leaf_hash_nonstrict_shake448(1, (4, 5, 6, 7), salt)
        parent = pcs.merkle_node_hash_nonstrict_shake448(0, 0, left, right)
        self.assertEqual(len(left), pcs.NON_STRICT_SHAKE448_BYTES)
        self.assertEqual(len(parent), pcs.NON_STRICT_SHAKE448_BYTES)
        strict = pcs.salted_leaf_hash(0, (0, 1, 2, 3), salt)
        self.assertEqual(len(strict), pcs.STRICT_SHAKE512_BYTES)
        self.assertNotEqual(strict[: pcs.NON_STRICT_SHAKE448_BYTES], left)


class WireAndGateTests(unittest.TestCase):
    def test_exact_low_rate_wire_models(self) -> None:
        expected = {
            (16, "shared"): (96_800, 27_268, 4_544),
            (16, "independent-worst-union"): (152_320, -28_252, 4_196),
            (32, "shared"): (80_192, 43_876, 5_048),
            (32, "independent-worst-union"): (128_512, -4_444, 4_784),
        }
        for key, values in expected.items():
            profile = pcs.WireProfile(*key)
            self.assertEqual(
                (profile.raw_wire_bytes,
                 pcs.RAW_PROOF_CAP_BYTES - profile.raw_wire_bytes,
                 profile.padding_rank_capacity_headroom),
                values,
            )
            self.assertEqual(profile.codeword_symbols, pcs.MESSAGE_SYMBOLS * key[0])
            self.assertEqual(profile.tree_storage_bytes, {
                16: 20_971_456,
                32: 41_942_976,
            }[key[0]])
            self.assertTrue(profile.strict_hash_profile)

    def test_independent_rate32_is_only_a_screen_not_a_point(self) -> None:
        profile = pcs.WireProfile(32, "independent-worst-union")
        self.assertEqual(profile.queries_per_branch, 66)
        self.assertEqual(profile.union_opened_leaves, 132)
        self.assertEqual(profile.frontier_nodes_max, 1_444)
        self.assertEqual(profile.opened_b128_symbols, 528)
        self.assertEqual(profile.e256_elements_per_branch, 332)
        self.assertEqual(profile.auxiliary_two_branch_wire_bytes, 2_048)
        self.assertEqual(profile.conservative_b128_observation_rows, 1_984)
        self.assertEqual(profile.maximum_active_symbols_for_full_rank_capacity, 30_784)
        self.assertEqual(profile.raw_wire_bytes, 128_512)
        self.assertFalse(profile.raw_wire_bytes <= pcs.RAW_PROOF_CAP_BYTES)

    def test_conditional_half_budget_parallel_profiles_are_separate(self) -> None:
        rate16 = pcs.WireProfile(
            16,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
        )
        rate32 = pcs.WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
        )
        self.assertEqual(rate16.queries_per_branch, 44)
        self.assertEqual(rate16.union_opened_leaves, 88)
        self.assertEqual(rate16.raw_wire_bytes, 83_712)
        self.assertEqual(rate16.padding_rank_capacity_headroom, 5_400)
        self.assertEqual(rate32.queries_per_branch, 33)
        self.assertEqual(rate32.union_opened_leaves, 66)
        self.assertEqual(rate32.raw_wire_bytes, 69_632)
        self.assertEqual(rate32.padding_rank_capacity_headroom, 5_708)
        for profile in (rate16, rate32):
            record = profile.record()
            self.assertTrue(record["conditional_half_budget_parallel_profile"])
            self.assertFalse(record["half_budget_product_theorem_proved"])
            self.assertEqual(record["local_char2_two_branch_n15_bytes"], 1_920)
            self.assertEqual(record["fused_ring_switch_bytes"], 128)
            self.assertFalse(record["entire_source_static_interval_has_rank_capacity"])
            self.assertTrue(record["source_static_interval_intersects_rank_capacity"])

    def test_salt_profiles_are_separate_and_never_promotable(self) -> None:
        candidate = pcs.WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
        )
        direct_bcs = pcs.WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
            leaf_salt_bytes=pcs.DIRECT_BCS_N18_SALT_BYTES,
        )
        self.assertEqual(candidate.raw_wire_bytes, 69_632)
        self.assertEqual(direct_bcs.raw_wire_bytes, 77_288)
        self.assertEqual(direct_bcs.tree_storage_bytes, 72_351_680)
        candidate_record = candidate.record()
        direct_record = direct_bcs.record()
        self.assertFalse(candidate_record["candidate_32_byte_salt_pq128_proved"])
        self.assertTrue(direct_record["direct_bcs_n18_salt_floor_met"])
        self.assertFalse(direct_record["direct_bcs_common_lambda_parameter_match"])
        self.assertFalse(direct_record["direct_bcs_is_qrom_theorem"])
        self.assertFalse(direct_record["salt_profile_promotable"])

    def test_old_56_byte_wire_rows_are_nonstrict_negative_controls(self) -> None:
        full = pcs.WireProfile(
            32,
            "independent-worst-union",
            commitment_digest_bytes=pcs.NON_STRICT_SHAKE448_BYTES,
        )
        half = pcs.WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
            commitment_digest_bytes=pcs.NON_STRICT_SHAKE448_BYTES,
        )
        self.assertEqual(full.raw_wire_bytes, 116_952)
        self.assertEqual(half.raw_wire_bytes, 63_320)
        for profile in (full, half):
            record = profile.record()
            self.assertFalse(record["strict_hash_profile"])
            self.assertTrue(record["non_strict_negative_control"])

    def test_source_static_geometry_range_never_becomes_an_assumption(self) -> None:
        self.assertEqual(pcs.SOURCE_STATIC_ACTIVE_SYMBOLS_MIN, 23_594)
        self.assertEqual(pcs.SOURCE_STATIC_ACTIVE_SYMBOLS_MAX, 32_668)
        self.assertEqual(pcs.SOURCE_STATIC_RANDOM_TAIL_MIN, 100)
        self.assertEqual(pcs.SOURCE_STATIC_RANDOM_TAIL_MAX, 9_174)
        profile = pcs.WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=pcs.HALF_BRANCH_QUERY_TERM_BITS,
        )
        record = profile.record()
        self.assertFalse(record["active_symbols_sensitivity_authoritative"])
        self.assertEqual(record["worst_static_tail_capacity_headroom"], -960)
        self.assertTrue(all(item["matches"] for item in pcs.source_dependency_records()))

    def test_rank_capacity_rejects_too_large_an_active_prefix(self) -> None:
        admissible = pcs.WireProfile(
            32, "independent-worst-union", active_symbols_assumption=30_784
        )
        rejected = pcs.WireProfile(
            32, "independent-worst-union", active_symbols_assumption=30_785
        )
        self.assertEqual(admissible.padding_rank_capacity_headroom, 0)
        self.assertEqual(rejected.padding_rank_capacity_headroom, -1)
        self.assertFalse(rejected.record()["rank_capacity_possible_under_assumption"])

    def test_report_is_fail_closed(self) -> None:
        report = pcs.report()
        self.assertEqual(
            report["schema"], "hegemon.m4-random-padding-zk-pcs-screen.v2"
        )
        self.assertEqual(report["commitment"]["immutable_root_count"], 1)
        self.assertEqual(report["commitment"]["algebraic_branches"], 2)
        self.assertTrue(report["claim"]["fixed_matrix_rank_lemma"])
        self.assertFalse(report["claim"]["adaptive_schedule_covered"])
        self.assertTrue(all(value is False for value in report["gates"].values()))
        self.assertFalse(report["source_inventory"]["active_symbols_frozen"])
        self.assertEqual(len(report["strict_profiles"]), 6)
        self.assertEqual(len(report["theorem_scoped_salt_profiles"]), 2)
        self.assertEqual(len(report["non_strict_shake448_negative_controls"]), 2)
        self.assertFalse(report["salt_theorem_scope"]["any_salt_profile_promotable"])


if __name__ == "__main__":
    unittest.main()
