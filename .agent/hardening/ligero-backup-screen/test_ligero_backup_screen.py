#!/usr/bin/env python3
"""Mutation and arithmetic tests for the canonical Ligero screen."""

from __future__ import annotations

import copy
import json
import unittest
from fractions import Fraction

import ligero_backup_screen as screen


class LigeroBackupScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger = screen.build_ledger()

    def test_exact_frozen_geometry(self) -> None:
        relation = self.ledger["exact_frozen_relation"]
        self.assertEqual(relation["m_constraints"], 20_457_227)
        self.assertEqual(relation["n_nonconstant_variables"], 19_311_555)
        self.assertEqual(relation["l_public_variables"], 10_152)
        self.assertEqual(relation["private_transport_variables"], 77_376)
        self.assertEqual(relation["derived_auxiliary_variables"], 19_224_027)
        self.assertEqual(relation["matrix_nonzeros_total"], 94_551_238)

    def test_source128_hash512_optimizer(self) -> None:
        value = screen.conditional_ligero_screen(source_bits=128, hash_bits=512)
        self.assertEqual((value["k"], value["ell"], value["rows"]), (32_768, 32_524, 629))
        self.assertEqual((value["sigma"], value["t"]), (3, 222))
        self.assertEqual(value["direct_test_field_elements"], 490_782)
        self.assertEqual(value["opened_view_field_elements"], 560_550)
        self.assertEqual(value["paper_core_expression_bytes"], 8_652_192)

    def test_source264_hash640_optimizer(self) -> None:
        value = screen.conditional_ligero_screen(source_bits=264, hash_bits=640)
        self.assertEqual((value["k"], value["ell"], value["rows"]), (32_768, 32_267, 634))
        self.assertEqual((value["sigma"], value["t"]), (5, 455))
        self.assertEqual(value["direct_test_field_elements"], 816_685)
        self.assertEqual(value["opened_view_field_elements"], 1_160_705)
        self.assertEqual(value["paper_core_expression_bytes"], 16_437_920)

    def test_source_error_is_exact_fraction_below_target(self) -> None:
        value = screen.conditional_ligero_screen(source_bits=264, hash_bits=640)
        error = screen.ligero_source_error(k=value["k"], sigma=value["sigma"], t=value["t"])
        self.assertIsInstance(error, Fraction)
        self.assertLessEqual(error, Fraction(1, 1 << 264))
        previous = screen.ligero_source_error(k=value["k"], sigma=value["sigma"], t=value["t"] - 1)
        self.assertGreater(previous, Fraction(1, 1 << 264))
        self.assertFalse(value["printed_theorem_4_7_direct_parameter_conditions_satisfied"])
        self.assertTrue(value["appendix_c_refined_analysis_used"])

    def test_bcs_p_is_bits_not_merkle_leaves(self) -> None:
        bcs = self.ledger["bcs_complete_zk_floor"]
        self.assertEqual(bcs["source264_optimistic_p_floor_bits"], 126_552_960)
        self.assertEqual(bcs["minimum_multiple_of_four_lambda_from_floor_only"], 628)
        self.assertEqual(bcs["minimum_byte_aligned_lambda_from_floor_only"], 632)
        self.assertLess(bcs["lambda512"]["bcs_direct_zk_floor_security_bits_display"], 100)
        self.assertFalse(bcs["lambda512"]["partial_floor_strictly_below_2^-128"])
        self.assertTrue(bcs["lambda632"]["partial_floor_strictly_below_2^-128"])
        self.assertFalse(bcs["lambda632"]["authoritative_composed_bound"])

    def test_no_proof_byte_claim(self) -> None:
        artifact = self.ledger["proof_artifact"]
        self.assertIsNone(artifact["same_relation_proof_bytes"])
        self.assertIsNone(artifact["proof_bytes_lower_bound"])
        self.assertIsNone(artifact["proof_bytes_upper_bound"])
        for value in self.ledger["conditional_ligero_paper_screens"].values():
            if isinstance(value, dict):
                self.assertIsNone(value["proof_bytes"])

    def test_all_candidates_fail_closed(self) -> None:
        for candidate in self.ledger["candidate_matrix"]:
            self.assertFalse(candidate["eligible"])
            self.assertFalse(candidate["production_candidate"])
            self.assertIsNone(candidate["same_relation_proof_bytes"])

    def test_each_authority_mutation_is_rejected(self) -> None:
        for gate in self.ledger["authority"]:
            mutated = copy.deepcopy(self.ledger)
            mutated["authority"][gate] = True
            with self.assertRaises(AssertionError, msg=gate):
                screen.validate_ledger(mutated)

    def test_candidate_promotion_is_rejected(self) -> None:
        for index, candidate in enumerate(self.ledger["candidate_matrix"]):
            mutated = copy.deepcopy(self.ledger)
            mutated["candidate_matrix"][index]["eligible"] = True
            with self.assertRaises(AssertionError, msg=candidate["id"]):
                screen.validate_ledger(mutated)

    def test_proof_byte_mutation_is_rejected(self) -> None:
        for key in ("same_relation_proof_bytes", "proof_bytes_lower_bound", "proof_bytes_upper_bound", "retained_qualifying_proof"):
            mutated = copy.deepcopy(self.ledger)
            mutated["proof_artifact"][key] = 1
            with self.assertRaises(AssertionError, msg=key):
                screen.validate_ledger(mutated)

    def test_composition_categories_are_explicit(self) -> None:
        categories = {term["category"] for term in self.ledger["composition"]["required_terms"]}
        self.assertTrue({"pcs", "iop", "fiat-shamir", "hash", "grinding", "union"} <= categories)

    def test_cfw_and_provekit_no_go(self) -> None:
        cfw = self.ledger["comparators"]["cfw26_105_oracle_carrier"]
        self.assertEqual(cfw["encoded_oracles"]["total"], 105)
        self.assertFalse(cfw["printed_theorem_inheritance"])
        self.assertIn("s=X^2-X", cfw["defects"][2])
        provekit = self.ledger["comparators"]["provekit"]
        self.assertAlmostEqual(provekit["generic_quantum_collision_ceiling_bits"], 256 / 3)
        self.assertFalse(provekit["eligible"])

    def test_canonical_ledger_readback(self) -> None:
        retained = json.loads(screen.LEDGER_PATH.read_text(encoding="utf-8"))
        self.assertEqual(retained, self.ledger)
        self.assertEqual(screen.LEDGER_PATH.read_text(encoding="utf-8"), screen.canonical_json(retained))

    def test_relation_and_repo_source_hashes(self) -> None:
        screen.validate_relation_source()
        screen.validate_repo_sources()

    def test_local_primary_pdf_hashes(self) -> None:
        screen.validate_primary_pdfs(require_present=True)


if __name__ == "__main__":
    unittest.main()
