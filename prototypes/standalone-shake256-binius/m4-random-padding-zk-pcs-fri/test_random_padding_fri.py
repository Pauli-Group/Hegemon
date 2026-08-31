#!/usr/bin/env python3
"""Adversarial tests for the executable random-padding PCS/FRI seam."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("random_padding_fri.py")
SPEC = importlib.util.spec_from_file_location("random_padding_fri", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
fri = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fri
SPEC.loader.exec_module(fri)


def slow_b128_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(128):
        if right & 1:
            result ^= left
        right >>= 1
        carry = left >> 127
        left = (left << 1) & ((1 << 128) - 1)
        if carry:
            left ^= 0x87
    return result


def dot(row, vector):
    result = 0
    for left, right in zip(row, vector):
        result ^= fri.b128_mul(left, right)
    return result


class FieldTests(unittest.TestCase):
    def test_b128_matches_shift_reference_and_inverts(self) -> None:
        vectors = (
            (0, 0),
            (1 << 127, 2),
            (0x123456789ABCDEF, 0xFEDCBA987654321),
            ((1 << 128) - 1, 0xDEADBEEF),
        )
        for left, right in vectors:
            self.assertEqual(fri.b128_mul(left, right), slow_b128_mul(left, right))
        value = 0x0123456789ABCDEFFEDCBA9876543210
        self.assertEqual(fri.b128_mul(value, fri.b128_inv(value)), 1)

    def test_true_e256_relation_and_distributivity(self) -> None:
        y = (0, 1)
        self.assertEqual(fri.e256_mul(y, y), (2, 2))
        left = (0x1234, 0x5678)
        right = (0x9ABC, 0xDEF0)
        third = (0x1111, 0x2222)
        self.assertEqual(
            fri.e256_mul(left, fri.e256_add(right, third)),
            fri.e256_add(fri.e256_mul(left, right), fri.e256_mul(left, third)),
        )

    def test_nonzero_affine_domain_and_zero_negative(self) -> None:
        points = fri.affine_domain(64)
        self.assertNotIn(0, points)
        self.assertEqual(len(set(points)), 64)
        with self.assertRaisesRegex(ValueError, "zero-containing"):
            fri.affine_domain(2, shift=1)

    def test_encode_and_interpolate_roundtrip(self) -> None:
        coefficients, codeword = fri.encode((1, 2, 3, 4), (5, 6, 7, 8), 2)
        recovered = fri.interpolate_b128(fri.affine_domain(len(codeword)), codeword)
        self.assertEqual(recovered[: len(coefficients)], coefficients)
        self.assertEqual(set(recovered[len(coefficients) :]), {0})


class MerkleAndTranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.symbols = tuple(range(32))
        self.tree = fri.commit(self.symbols, fri.deterministic_salts(b"merkle", 8))

    def test_partial_canonical_multiproof_roundtrip(self) -> None:
        indices = (0, 3, 6)
        payloads, frontier = fri.open_commitment(self.tree, indices)
        self.assertEqual(len(self.tree.root), 64)
        self.assertTrue(all(len(node) == 64 for node in frontier))
        self.assertEqual(len(frontier), len(fri.frontier_positions(8, indices)))
        fri.verify_merkle_opening(self.tree.root, 8, indices, payloads, frontier)

    def test_mutated_leaf_and_frontier_reject(self) -> None:
        indices = (0, 3, 6)
        payloads = list(fri._leaf_payload(self.tree, index) for index in indices)
        symbols, salt = payloads[0]
        payloads[0] = ((symbols[0] ^ 1,) + symbols[1:], salt)
        frontier = fri.merkle_frontier(self.tree, indices)
        with self.assertRaisesRegex(fri.ProofError, "root mismatch"):
            fri.verify_merkle_opening(self.tree.root, 8, indices, payloads, frontier)
        payloads[0] = fri._leaf_payload(self.tree, indices[0])
        changed = list(frontier)
        changed[0] = bytes([changed[0][0] ^ 1]) + changed[0][1:]
        with self.assertRaisesRegex(fri.ProofError, "root mismatch"):
            fri.verify_merkle_opening(self.tree.root, 8, indices, payloads, changed)

    def test_root_derived_branch_and_layer_queries_differ(self) -> None:
        roots = (
            self.tree.root,
            b"a" * fri.PROOF_DIGEST_BYTES,
            b"b" * fri.PROOF_DIGEST_BYTES,
        )
        first = fri.derive_query_indices(roots, b"ctx", 0, 0, 4, 8)
        second = fri.derive_query_indices(roots, b"ctx", 1, 0, 4, 8)
        folded = fri.derive_query_indices(roots, b"ctx", 0, 1, 4, 8)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, folded)
        self.assertEqual(len(set(first)), 4)

    def test_two_true_e256_transcripts_are_separate(self) -> None:
        base = self.tree.root
        self.assertNotEqual(
            fri.beta_challenge(base, b"ctx", 0),
            fri.beta_challenge(base, b"ctx", 1),
        )
        self.assertNotEqual(
            fri.terminal_challenge(
                base, b"f" * fri.PROOF_DIGEST_BYTES, b"ctx", 0
            ),
            fri.beta_challenge(base, b"ctx", 0),
        )


class ProofRoundtripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proof, cls.context = fri.toy_fixture()
        cls.parsed = fri.verify(cls.proof, cls.context)

    def test_honest_exhaustive_roundtrip_and_exact_wire(self) -> None:
        self.assertEqual(len(self.proof), 2_736)
        self.assertEqual(self.parsed.flags, fri.FLAG_EXHAUSTIVE_LOW_DEGREE)
        self.assertEqual(self.parsed.query_count, self.parsed.leaf_count)
        self.assertEqual(self.parsed.base_indices, tuple(range(8)))
        self.assertEqual(self.parsed.fold_indices, (tuple(range(8)), tuple(range(8))))
        self.assertEqual(self.parsed.base_frontier, ())
        self.assertEqual(self.parsed.fold_frontiers, ((), ()))

    def test_partial_membership_is_not_accepted_as_low_degree(self) -> None:
        proof = fri.prove(
            (1, 2, 3, 4),
            (5, 6, 7, 8),
            2,
            self.context,
            query_count=2,
            salt_seed=b"partial",
        )
        parsed = fri.verify_membership(proof, self.context)
        self.assertEqual(parsed.flags, 0)
        with self.assertRaisesRegex(fri.ProofError, "not an authorized low-degree"):
            fri.verify(proof, self.context)

    def test_mutation_rejects(self) -> None:
        changed = bytearray(self.proof)
        changed[-1] ^= 1
        with self.assertRaises(fri.ProofError):
            fri.verify(bytes(changed), self.context)

    def test_truncation_and_trailing_bytes_reject(self) -> None:
        for cut in (1, fri.FIXED_WIRE_BYTES - 1, len(self.proof) - 1):
            with self.assertRaisesRegex(fri.ProofError, "truncated"):
                fri.parse_proof(self.proof[:cut], self.context)
        with self.assertRaisesRegex(fri.ProofError, "trailing"):
            fri.parse_proof(self.proof + b"\0", self.context)

    def test_root_mutation_rejects_before_membership(self) -> None:
        changed = bytearray(self.proof)
        changed[fri.HEADER_BYTES] ^= 1
        with self.assertRaisesRegex(fri.ProofError, "query|canonical"):
            fri.parse_proof(bytes(changed), self.context)

    def test_query_digest_mutation_rejects(self) -> None:
        changed = bytearray(self.proof)
        digest_offset = fri.HEADER_BYTES + fri.ROOT_COUNT * fri.PROOF_DIGEST_BYTES
        changed[digest_offset] ^= 1
        with self.assertRaisesRegex(fri.ProofError, "query schedule mismatch"):
            fri.parse_proof(bytes(changed), self.context)

    def test_public_context_changes_root_derived_queries(self) -> None:
        with self.assertRaisesRegex(fri.ProofError, "query|canonical"):
            fri.parse_proof(self.proof, self.context + b"changed")

    def test_noncanonical_header_counts_and_flags_reject(self) -> None:
        fields = list(fri.HEADER_STRUCT.unpack_from(self.proof))
        fields[2] = 2
        changed = fri.HEADER_STRUCT.pack(*fields) + self.proof[fri.HEADER_BYTES :]
        with self.assertRaisesRegex(fri.ProofError, "flags"):
            fri.parse_proof(changed, self.context)
        fields = list(fri.HEADER_STRUCT.unpack_from(self.proof))
        fields[8] += 1  # base opened count
        changed = fri.HEADER_STRUCT.pack(*fields) + self.proof[fri.HEADER_BYTES :]
        with self.assertRaisesRegex(fri.ProofError, "query or frontier counts"):
            fri.parse_proof(changed, self.context)

    def test_claim_mutation_keeps_membership_but_fails_terminal(self) -> None:
        changed = bytearray(self.proof)
        claims_offset = (
            fri.HEADER_BYTES
            + fri.ROOT_COUNT * fri.PROOF_DIGEST_BYTES
            + fri.QUERY_DIGEST_BYTES
        )
        changed[claims_offset] ^= 1
        fri.verify_membership(bytes(changed), self.context)
        with self.assertRaisesRegex(fri.ProofError, "terminal claim"):
            fri.verify(bytes(changed), self.context)


class ObservationAndReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        proof, cls.context = fri.toy_fixture()
        cls.parsed = fri.verify(proof, cls.context)
        cls.matrix = fri.export_observation_matrix(cls.parsed, cls.context)

    def test_full_export_has_point_fold_and_terminal_rows(self) -> None:
        self.assertEqual(len(self.matrix.rows), 104)
        self.assertEqual(len(self.matrix.labels), 104)
        self.assertTrue(any(label.startswith("base.point") for label in self.matrix.labels))
        self.assertTrue(any("fold-point" in label for label in self.matrix.labels))
        self.assertTrue(any("terminal" in label for label in self.matrix.labels))
        self.assertTrue(all(len(row) == 8 for row in self.matrix.rows))

    def test_exported_rows_reproduce_every_serialized_observation(self) -> None:
        coefficients = (1, 2, 3, 4, 0xA1, 0xB2, 0xC3, 0xD4)
        observed = []
        observed.extend(symbol for symbols, _salt in self.parsed.base_payloads for symbol in symbols)
        for branch in range(fri.BRANCHES):
            observed.extend(
                symbol
                for symbols, _salt in self.parsed.fold_payloads[branch]
                for symbol in symbols
            )
            for claim in self.parsed.claims[branch]:
                observed.extend(claim)
        calculated = [dot(row, coefficients) for row in self.matrix.rows]
        self.assertEqual(calculated, observed)

    def test_rank_is_computed_not_inferred_from_row_count(self) -> None:
        audit = fri.audit_observation_matrix(
            self.matrix, schedule_fixed_independently_of_padding=False
        )
        self.assertEqual(audit.observations, 104)
        self.assertEqual(audit.padding_rank, 4)
        self.assertEqual(audit.joint_rank, 8)
        self.assertFalse(audit.full_row_rank_on_padding)
        self.assertFalse(audit.witness_independent_for_fixed_matrix)
        self.assertFalse(audit.zero_knowledge_conclusion_authorized)

    def test_reused_padding_cancels_in_a_fixed_view(self) -> None:
        point = fri.affine_domain(8)[3]
        observed, expected = fri.reused_padding_fixed_view_delta(
            (1, 2, 3, 4),
            (9, 10, 11, 12),
            (0xA1, 0xB2, 0xC3, 0xD4),
            point,
        )
        self.assertEqual(observed, expected)
        self.assertNotEqual(observed, 0)


class ProductionModelAndGatesTests(unittest.TestCase):
    def test_n15_model_prices_actual_three_tree_serializer(self) -> None:
        conditional, full, conditional_148, full_148 = fri.production_topologies()
        self.assertEqual(conditional.query_only_one_round_bytes, 118_192)
        self.assertEqual(conditional.query_only_one_round_bytes - 63_320, 54_872)
        self.assertEqual(full.query_only_one_round_bytes, 219_056)
        self.assertEqual(full.query_only_one_round_bytes - 116_952, 102_104)
        self.assertEqual(conditional_148.query_only_one_round_bytes, 133_504)
        self.assertEqual(full_148.query_only_one_round_bytes, 249_680)
        self.assertEqual((conditional.salt_bytes, conditional_148.salt_bytes), (32, 148))
        for profile in (conditional, full):
            self.assertEqual(profile.leaves_per_tree, 262_144)
            self.assertEqual(profile.exhaustive_honest_bytes, 75_497_904)
        for profile in (conditional_148, full_148):
            self.assertEqual(profile.exhaustive_honest_bytes, 166_724_016)

    def test_real_proximity_terms_are_explicit_and_unproved(self) -> None:
        report = fri.report()
        correction = report["screen_correction"]
        hash_profile = report["hash_and_salt_profiles"]
        rank_boundary = report["production_rank_boundary"]
        self.assertEqual(hash_profile["strict_proof_digest_bytes"], 64)
        self.assertTrue(hash_profile["legacy_56_byte_digest_is_non_strict_negative_control"])
        self.assertFalse(hash_profile["direct_bcs_theorem_integrated"])
        self.assertEqual(
            (rank_boundary["source_static_random_tail_min"], rank_boundary["source_static_random_tail_max"]),
            (100, 9_174),
        )
        self.assertIsNone(rank_boundary["exact_full_matrix_rank"])
        self.assertFalse(rank_boundary["conditional_q33_security_authorized"])
        self.assertTrue(correction["real_proximity_check_adds_missing_terms"])
        self.assertIsNone(correction["optimized_complete_fri_increment_bytes"])
        self.assertIn(
            "two folded-layer SHAKE256-512 roots",
            correction["terms_missing_from_63320_116952_as_instantiated"],
        )
        self.assertTrue(all(value is False for value in report["gates"].values()))

    def test_combined_fold_tree_best_case_keeps_authentication(self) -> None:
        combined = fri.combined_fold_tree_best_case()
        self.assertEqual(combined["query_only_one_round_bytes"], 89_744)
        self.assertEqual(combined["theorem_scoped_salt_one_round_bytes"], 101_261)
        self.assertEqual(combined["base_theorem_scoped_salt_bytes"], 148)
        self.assertEqual(combined["combined_fold_theorem_scoped_salt_bytes"], 149)
        self.assertEqual(combined["maximum_structural_savings_bytes"], 28_448)
        self.assertEqual(combined["base_frontier_nodes"], 788)
        self.assertEqual(combined["combined_fold_frontier_nodes"], 460)
        self.assertTrue(combined["branch_commitments_retained"])
        self.assertTrue(combined["all_openings_authenticated"])
        self.assertEqual(combined["verifier_known_terminal_elision_bytes"], 0)
        self.assertFalse(combined["terminal_elision_justified"])
        self.assertFalse(combined["shared_fold_query_schedule_product_soundness_proved"])

    def test_fifteen_round_structural_floor_is_not_a_complete_fri(self) -> None:
        floor = fri.all_rounds_structural_floor()
        self.assertEqual(floor["one_round_degree_reduction_factor"], 2)
        self.assertEqual(floor["rounds_required_to_constant"], 15)
        self.assertEqual(floor["additional_rounds_after_the_executable_one"], 14)
        self.assertEqual(floor["authenticated_structural_floor_bytes"], 325_424)
        self.assertEqual(floor["theorem_scoped_salt_structural_floor_bytes"], 387_427)
        self.assertEqual(floor["additional_bytes_over_combined_one_round"], 235_680)
        self.assertIsNone(floor["complete_fri_bytes"])
        self.assertFalse(floor["complete_fri_authorized"])
        verdict = fri.report()["full_low_degree_cap_verdict"]
        self.assertEqual(verdict["raw_cap_bytes"], 124_068)
        self.assertTrue(verdict["combined_one_round_fits_raw_cap"])
        self.assertFalse(verdict["combined_one_round_is_full_low_degree"])
        self.assertFalse(
            verdict["any_implemented_or_screened_full_low_degree_profile_under_cap"]
        )


if __name__ == "__main__":
    unittest.main()
