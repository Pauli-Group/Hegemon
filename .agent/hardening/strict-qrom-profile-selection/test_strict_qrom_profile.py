#!/usr/bin/env python3
"""Dependency-free negative and exact-arithmetic tests for the QROM screen."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import sys
import unittest
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "strict_qrom_profile.py"
SPEC = importlib.util.spec_from_file_location("strict_qrom_profile_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load strict QROM profile module")
qrom = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qrom
SPEC.loader.exec_module(qrom)


class ExactArithmeticTests(unittest.TestCase):
    def test_q129_fails_and_q130_passes_e384(self) -> None:
        def total(q: int) -> Fraction:
            source = qrom.source_error_terms(field_bits=384, p=5, r=2048, m=4096, q=q)[
                "source_total"
            ]
            return qrom.cms_policy_terms(source, union_terms=1, k_cap=4096)[
                "conditional_total"
            ]

        self.assertFalse(qrom.strictly_below_target(total(129)))
        self.assertTrue(qrom.strictly_below_target(total(130)))

    def test_q129_fails_and_q130_passes_e512(self) -> None:
        def total(q: int) -> Fraction:
            source = qrom.source_error_terms(field_bits=512, p=6, r=1024, m=2048, q=q)[
                "source_total"
            ]
            return qrom.cms_policy_terms(source, union_terms=1, k_cap=2048)[
                "conditional_total"
            ]

        self.assertFalse(qrom.strictly_below_target(total(129)))
        self.assertTrue(qrom.strictly_below_target(total(130)))

    def test_target_equality_rejects_and_non_fraction_rejects(self) -> None:
        self.assertFalse(qrom.strictly_below_target(qrom.STRICT_TARGET))
        with self.assertRaises(TypeError):
            qrom.strictly_below_target(2.0**-129)  # type: ignore[arg-type]

    def test_cms_second_term_is_three_over_two_to_316(self) -> None:
        terms = qrom.cms_policy_terms(Fraction(0), union_terms=1, k_cap=1)
        self.assertEqual(terms["ideal_ro_collision_path"], Fraction(3, 1 << 316))

    def test_source_equation_terms_are_exact(self) -> None:
        terms = qrom.source_error_terms(field_bits=384, p=5, r=2048, m=4096, q=130)
        self.assertEqual(terms["proximity_query"], Fraction(2047, 8192) ** 130)
        self.assertEqual(terms["algebraic_reduction"], Fraction(20490, 1 << 384))

    def test_frontier_closed_form_matches_small_known_cases(self) -> None:
        self.assertEqual(qrom.max_frontier_nodes(3, 1), 3)
        self.assertEqual(qrom.max_frontier_nodes(3, 2), 4)
        self.assertEqual(qrom.max_frontier_nodes(3, 3), 4)
        self.assertEqual(qrom.max_frontier_nodes(3, 8), 0)

    def test_decision_source_has_no_float_conversion(self) -> None:
        source = MODULE_PATH.read_text()
        ast.parse(source)
        self.assertNotIn("float(", source)
        self.assertIn("Fraction", source)


class ConditionalProfileTests(unittest.TestCase):
    def test_global_e384_source_screen(self) -> None:
        profile = qrom.select_conditional_profile(384, 1)
        self.assertEqual((profile.fold_variables, profile.log_inv_rate, profile.query_count), (5, 1, 130))
        self.assertEqual((profile.proof_bytes, profile.frontier_sha512_nodes), (206992, 646))

    def test_global_e512_source_screen(self) -> None:
        profile = qrom.select_conditional_profile(512, 1)
        self.assertEqual((profile.fold_variables, profile.log_inv_rate, profile.query_count), (6, 1, 130))
        self.assertEqual((profile.proof_bytes, profile.frontier_sha512_nodes), (232768, 516))

    def test_two_source_terms_force_q131(self) -> None:
        for bits in (384, 512):
            one = qrom.select_conditional_profile(bits, 1)
            two = qrom.select_conditional_profile(bits, 2)
            source = qrom.source_error_terms(
                field_bits=bits,
                p=one.fold_variables,
                r=one.message_rows,
                m=one.codeword_rows,
                q=one.query_count,
            )["source_total"]
            self.assertFalse(
                qrom.strictly_below_target(
                    qrom.cms_policy_terms(source, union_terms=2, k_cap=one.codeword_rows)[
                        "conditional_total"
                    ]
                )
            )
            self.assertEqual(two.query_count, 131)

    def test_equal_source_union_thresholds(self) -> None:
        expected = {
            384: [(1, 130, 206992), (2, 131, 207696), (8, 132, 208400), (16, 132, 208400), (64, 133, 209104)],
            512: [(1, 130, 232768), (2, 131, 233920), (8, 132, 235072), (16, 132, 235072), (64, 133, 236224)],
        }
        for bits, rows in expected.items():
            actual = [
                (u, qrom.select_conditional_profile(bits, u).query_count, qrom.select_conditional_profile(bits, u).proof_bytes)
                for u in qrom.UNION_MULTIPLIERS
            ]
            self.assertEqual(actual, rows)

    def test_wire_ledgers_are_exact(self) -> None:
        e384 = qrom.wire_ledger(field_bytes=48, p=5, r=2048, m=4096, q=130)
        self.assertEqual(e384["total"], 206992)
        self.assertEqual(e384["authentication"], 646 * 64)
        e512 = qrom.wire_ledger(field_bytes=64, p=6, r=1024, m=2048, q=130)
        self.assertEqual(e512["total"], 232768)
        self.assertEqual(e512["authentication"], 516 * 64)


class ZeroKnowledgeAndTheoremTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(qrom.MANIFEST_PATH.read_text())
        self.theorems = json.loads(qrom.THEOREM_MAP_PATH.read_text())

    def test_bcs_lambda512_direct_bound_is_below_target(self) -> None:
        # "Below target" here means fewer security bits, i.e. a larger error.
        self.assertEqual(qrom.bcs_direct_zk_bound(committed_units=4096, lambda_bits=512), Fraction(1, 1 << 114))
        self.assertEqual(qrom.bcs_direct_zk_bound(committed_units=2048, lambda_bits=512), Fraction(1, 1 << 115))
        self.assertGreater(Fraction(1, 1 << 114), qrom.STRICT_TARGET)
        self.assertGreater(Fraction(1, 1 << 115), qrom.STRICT_TARGET)

    def test_hvzk_whir_lane_remains_conditional_and_knowledge_null(self) -> None:
        lane = self.manifest["hvzk_whir_conditional_lane"]
        self.assertEqual(lane["cms_soundness_shape_applicable"], "conditional")
        self.assertEqual(lane["cms_zk_shape_applicable"], "conditional")
        self.assertIsNone(lane["cms_knowledge_applicable"])
        self.assertFalse(lane["rbr_notion_matches_cms_definition_8_5"])
        self.assertIsNone(lane["exact_epsilon"])

    def test_block_special_soundness_does_not_authorize_knowledge(self) -> None:
        entries = {entry["id"]: entry for entry in self.theorems["premises"]}
        self.assertFalse(entries["block_no_knowledge_implication"]["satisfied"])
        self.assertFalse(entries["bcfw_relaxed_rbr_mismatch"]["satisfied"])

    def test_full_ledger_stays_null(self) -> None:
        ledger = self.manifest["full_composed_ledger"]
        self.assertIsNone(ledger["overall_total"])
        self.assertIsNone(ledger["strict_pq_bits"])
        null_terms = [entry for entry in ledger["terms"] if entry["value"] is None]
        self.assertGreaterEqual(len(null_terms), 10)


class FailClosedMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(qrom.MANIFEST_PATH.read_text())
        self.theorems = json.loads(qrom.THEOREM_MAP_PATH.read_text())

    def assert_manifest_rejects(self, mutate) -> None:
        candidate = copy.deepcopy(self.manifest)
        mutate(candidate)
        with self.assertRaises(AssertionError):
            qrom.validate_manifest(candidate)

    def test_any_capability_true_rejects(self) -> None:
        for gate in self.manifest["capabilities"]:
            self.assert_manifest_rejects(lambda value, gate=gate: value["capabilities"].__setitem__(gate, True))

    def test_production_profile_or_query_selection_rejects(self) -> None:
        self.assert_manifest_rejects(lambda value: value.__setitem__("production_profile", "E512"))
        self.assert_manifest_rejects(lambda value: value.__setitem__("selected_query_count", 130))

    def test_filling_one_unproved_union_term_rejects(self) -> None:
        def mutate(value) -> None:
            for entry in value["full_composed_ledger"]["terms"]:
                if entry["id"] == "grinding_and_retry_union":
                    entry["value"] = "2^-512"
                    return
            raise AssertionError("test fixture missing term")

        self.assert_manifest_rejects(mutate)

    def test_policy_or_profile_drift_rejects(self) -> None:
        self.assert_manifest_rejects(
            lambda value: value["local_policy_envelope"].__setitem__("t_augmented", (1 << 64) - 1)
        )
        self.assert_manifest_rejects(
            lambda value: value["conditional_source_screens"]["E512"].__setitem__("query_count", 129)
        )

    def test_source_closure_or_mutability_relabel_rejects(self) -> None:
        self.assert_manifest_rejects(
            lambda value: value["source_binding"].__setitem__("retained_source_closure", True)
        )
        self.assert_manifest_rejects(
            lambda value: value["source_binding"].__setitem__("live_mutable_dependency", False)
        )

    def test_whir_relaxed_rbr_relabel_rejects(self) -> None:
        self.assert_manifest_rejects(
            lambda value: value["hvzk_whir_conditional_lane"].__setitem__(
                "rbr_notion_matches_cms_definition_8_5", True
            )
        )

    def test_theorem_overclaims_reject(self) -> None:
        candidate = copy.deepcopy(self.theorems)
        entries = {entry["id"]: entry for entry in candidate["premises"]}
        entries["cms19_big_o_theorem"]["exact_constant_bound_provided"] = True
        with self.assertRaises(AssertionError):
            qrom.validate_theorem_map(candidate)

    def test_canonical_json_and_live_source_checks(self) -> None:
        self.assertEqual(qrom.MANIFEST_PATH.read_text(), qrom.canonical_json(self.manifest))
        self.assertEqual(qrom.THEOREM_MAP_PATH.read_text(), qrom.canonical_json(self.theorems))
        qrom.validate_source_binding(self.manifest)


if __name__ == "__main__":
    unittest.main()
