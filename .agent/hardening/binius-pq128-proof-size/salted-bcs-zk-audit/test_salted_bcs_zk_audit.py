#!/usr/bin/env python3
"""Adversarial controls for the fail-closed salted BCS/QROM audit."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("salted_bcs_zk_audit.py")
SPEC = importlib.util.spec_from_file_location("salted_bcs_zk_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class ExactFramingTests(unittest.TestCase):
    def test_pinned_sources_and_exact_digest_length(self) -> None:
        self.assertTrue(
            all(record["matches"] for record in audit.source_records().values())
        )
        digest = audit.actual_leaf_hash(9, (1, 2, 3, 4), bytes(32))
        self.assertEqual(len(digest), 64)

    def test_index_is_bound(self) -> None:
        symbols = (1, 2, 3, 4)
        salt = bytes(range(32))
        self.assertNotEqual(
            audit.actual_leaf_hash(1, symbols, salt),
            audit.actual_leaf_hash(2, symbols, salt),
        )

    def test_reuse_is_deterministically_linkable(self) -> None:
        symbols = (5, 6, 7, 8)
        salt = b"s" * 32
        first = audit.actual_leaf_hash(4, symbols, salt)
        second = audit.actual_leaf_hash(4, symbols, salt)
        self.assertEqual(first, second)

    def test_fresh_salts_change_the_leaf(self) -> None:
        symbols = (5, 6, 7, 8)
        self.assertNotEqual(
            audit.actual_leaf_hash(4, symbols, b"a" * 32),
            audit.actual_leaf_hash(4, symbols, b"b" * 32),
        )

    def test_toy_truncation_collision_control(self) -> None:
        collision = audit.find_toy_collision()
        self.assertEqual(len(bytes.fromhex(collision["digest_hex"])), 1)
        self.assertNotEqual(
            (collision["first_variant"], collision["first_salt_byte"]),
            (collision["second_variant"], collision["second_salt_byte"]),
        )


class AdaptivityFailureAndReuseTests(unittest.TestCase):
    def test_adaptive_full_rank_realizations_still_leak(self) -> None:
        self.assertEqual(audit.adaptive_selector_distribution(0), {0: 3, 1: 1})
        self.assertEqual(audit.adaptive_selector_distribution(1), {1: 3, 0: 1})

    def test_selective_failure_accepted_transcript_reveals_witness(self) -> None:
        zero = audit.selective_failure_distribution(0)
        one = audit.selective_failure_distribution(1)
        self.assertEqual(zero, {"0": 1, "abort": 1})
        self.assertEqual(one, {"1": 1, "abort": 1})
        self.assertNotEqual(zero, one)

    def test_reused_padding_cancels_exactly(self) -> None:
        delta = audit.reused_padding_delta((3, 9), (12, 5), (7, 11))
        self.assertEqual(delta, (15, 12, 0, 0))


class BoundAndGateTests(unittest.TestCase):
    def test_bcs_parameterization_does_not_match(self) -> None:
        record = audit.report()["classical_bcs_direct_application"]
        self.assertEqual(record["lambda_from_actual_salt_bits"], 128)
        self.assertEqual(record["lambda_from_actual_digest_bits"], 512)
        self.assertFalse(record["one_common_lambda_exists"])
        self.assertFalse(record["direct_parameter_match"])

    def test_bcs_concrete_bound_is_below_target(self) -> None:
        self.assertEqual(
            audit.bcs_classical_privacy_bits(lambda_bits=128, leaves=1 << 18),
            12,
        )
        self.assertEqual(
            audit.bcs_classical_privacy_bits(lambda_bits=512, leaves=1 << 18),
            108,
        )
        self.assertEqual(
            audit.minimum_bcs_lambda_bits(target_bits=128, leaves=1 << 18),
            592,
        )

    def test_multitarget_grover_screen_loses_nine_bits(self) -> None:
        self.assertEqual(
            audit.grover_any_target_work_bits(salt_bits=256, targets=1 << 18),
            119,
        )

    def test_unruh_sigma_protocol_bound_does_not_close_this_lane(self) -> None:
        bits = audit.unruh_corollary35_unpredictability_term_bits(
            commitment_collision_entropy_bits=512,
            proof_queries=1,
            hash_queries=0,
        )
        self.assertLess(bits, 128)
        scope = audit.report()["primary_theorem_scopes"]["unruh_2017_398"]
        self.assertFalse(scope["covers_this_multi_round_iop_merkle_simulator"])
        self.assertEqual(
            audit.minimum_salt_bits_for_multitarget_work(
                target_bits=128, targets=1 << 18
            ),
            274,
        )

    def test_adaptive_reprogramming_screen_is_borderline_even_once(self) -> None:
        bits = audit.adaptive_reprogramming_security_bits(
            salt_bits=256, reprogrammings=1, quantum_queries_log2=0
        )
        self.assertLess(bits, 128)
        self.assertGreater(bits, 127)
        self.assertGreaterEqual(
            audit.minimum_salt_bits_for_reprogramming(
                target_bits=128, reprogrammings=1, quantum_queries_log2=0
            ),
            257,
        )

    def test_query_and_reprogramming_multiplicity_consume_margin(self) -> None:
        one = audit.adaptive_reprogramming_security_bits(
            salt_bits=256, reprogrammings=1, quantum_queries_log2=32
        )
        many = audit.adaptive_reprogramming_security_bits(
            salt_bits=256,
            reprogrammings=audit.RATE32_ONE_ROUND_SEPARATE_OPENED_LEAVES,
            quantum_queries_log2=32,
        )
        self.assertLess(many, one)
        self.assertLess(many, 128)

    def test_direct_bcs_salt_is_computed_per_tree(self) -> None:
        self.assertEqual(
            audit.direct_bcs_salt_bytes(target_bits=128, leaves=1 << 18), 148
        )
        self.assertEqual(
            audit.direct_bcs_salt_bytes(target_bits=128, leaves=1 << 19), 149
        )

    def test_current_strict_and_fri_rows_are_pinned(self) -> None:
        rows = audit.current_artifact_rows()
        self.assertEqual(
            rows["strict_random_padding_precursor"][
                "conditional_q33_salt32_bytes"
            ],
            69_632,
        )
        self.assertEqual(
            rows["strict_random_padding_precursor"][
                "double_full_q66_salt32_bytes"
            ],
            128_512,
        )
        self.assertEqual(
            rows["one_round_separate_fold_trees"][
                "conditional_q33_salt32_bytes"
            ],
            118_192,
        )
        self.assertEqual(
            rows["one_round_separate_fold_trees"][
                "double_full_q66_salt32_bytes"
            ],
            219_056,
        )

    def test_fri_rows_match_exact_per_tree_recomputation(self) -> None:
        rows = audit.corrected_direct_bcs_rows()
        self.assertEqual(rows["combined_one_round_corrected_bytes"], 101_261)
        self.assertEqual(rows["artifact_per_tree_combined_bytes"], 101_261)
        self.assertTrue(rows["artifact_matches_recomputed_combined"])
        self.assertEqual(rows["all_rounds_corrected_bytes"], 387_427)
        self.assertEqual(rows["artifact_per_tree_all_rounds_bytes"], 387_427)
        self.assertTrue(rows["artifact_matches_recomputed_all_rounds"])
        self.assertFalse(rows["qrom_applicable"])
        self.assertFalse(rows["strict_security_result"])
        self.assertFalse(rows["frontier_eligible"])

    def test_report_fails_closed(self) -> None:
        record = audit.report()
        self.assertFalse(record["simulator_contract"]["all_required"])
        self.assertEqual(
            record["verdict"]["salt_charge_status"], "UNPROVED_FOR_PQ128"
        )
        self.assertFalse(record["verdict"]["strict_pq128"])
        self.assertFalse(record["verdict"]["frontier_eligible"])


if __name__ == "__main__":
    unittest.main()
