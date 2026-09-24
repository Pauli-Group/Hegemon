#!/usr/bin/env python3
"""Arithmetic, source, structure, and fail-open mutation tests."""

from __future__ import annotations

import copy
import json
import unittest
from fractions import Fraction

import aurora_pq128_screen as screen


class AuroraPQ128ScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = screen.build_certificate()

    def test_theorem_9_2_exact_core_expression(self) -> None:
        theorem = self.document["aurora_theorem_9_2"]
        self.assertEqual(
            theorem["full_iop_oracle_length_symbols"],
            "(4+2*lambda_i+(lambda_i_prime*lambda_i_FRI)/3)*|L|",
        )
        self.assertEqual(
            theorem["condition"], "2*max(m,n+1)+2*b <= rho*|L|"
        )
        self.assertEqual(
            theorem["ordinary_soundness_upper_bound"], "epsilon_i+epsilon_q"
        )
        self.assertFalse(theorem["core_expression_is_proof_bytes"])
        self.assertTrue(
            all(value is None for value in theorem["selected_parameters"].values())
        )

    def test_definition_4_4_is_complete_bounded_query_view_zk(self) -> None:
        definition = self.document["zero_knowledge"]["aurora_definition_4_4"]
        self.assertTrue(definition["perfect"])
        self.assertTrue(definition["whole_view"])
        self.assertTrue(definition["straightline"])
        self.assertTrue(definition["queries_during_interaction_allowed"])
        self.assertTrue(definition["adaptive_within_bound"])
        self.assertTrue(definition["identical_distribution"])

    def test_complete_nizk_zk_stays_false(self) -> None:
        zk = self.document["zero_knowledge"]
        self.assertFalse(zk["complete_nizk_zk_gate"])
        self.assertIsNone(zk["modified_bcs"]["exact_total_p_bits"])
        self.assertIsNone(zk["modified_bcs"]["lambda_BCS"])
        self.assertIsNone(zk["modified_bcs"]["statistical_nizk_error"])

    def test_bcs_lemma_7_5_exact_arithmetic(self) -> None:
        p_bits = 15_032_385_536
        self.assertEqual(
            screen.bcs_direct_zk_term(p_bits, 512), Fraction(p_bits, 1 << 126)
        )
        self.assertEqual(screen.first_strict_bcs_lambda(p_bits), 656)
        self.assertFalse(
            screen.bcs_direct_zk_term(p_bits, 652) < screen.strict_target()
        )
        self.assertTrue(
            screen.bcs_direct_zk_term(p_bits, 656) < screen.strict_target()
        )

    def test_source_projection_domain_and_p_floor(self) -> None:
        floor = self.document["source_projection_bcs_privacy_floor"]
        theory = floor["theorem_minimal_binary_field"]
        self.assertEqual(theory["l_floor"], 1 << 27)
        self.assertEqual(theory["field_bits"], 28)
        self.assertEqual(theory["p_iop_bits_floor"], 15_032_385_536)
        self.assertAlmostEqual(
            theory["lambda512_direct_zk_security_bits_upper_bound"],
            92.192645077943,
        )
        self.assertEqual(theory["minimum_multiple_of_four_lambda_for_floor"], 656)
        self.assertTrue(theory["not_a_proof_byte_bound"])
        self.assertIsNone(theory["proof_bytes"])

    def test_supported_implementation_fields_all_fail_sha512(self) -> None:
        floors = self.document["source_projection_bcs_privacy_floor"][
            "pinned_libiop_supported_fields"
        ]
        self.assertEqual(
            {
                key: value["minimum_multiple_of_four_lambda_for_floor"]
                for key, value in floors.items()
            },
            {"gf2_64": 664, "gf2_128": 668, "gf2_192": 668, "gf2_256": 672},
        )
        self.assertTrue(all(not value["lambda512_strict_gt_128"] for value in floors.values()))

    def test_source_projection_is_not_binary_relation(self) -> None:
        relation = self.document["relation"]
        projection = relation["source_static_projection"]
        self.assertEqual(projection["m_constraints"], 29_509_133)
        self.assertEqual(projection["n_nonconstant_variables_upper_bound"], 29_606_837)
        self.assertFalse(projection["exact_binary_r1cs_geometry"])
        self.assertFalse(relation["exact_binary_compile"]["compiled"])
        self.assertFalse(relation["exact_binary_compile"]["semantic_refinement"])
        self.assertIsNone(relation["exact_binary_compile"]["matrix_digest"])

    def test_unfrozen_binary_macro_projection_is_not_promoted(self) -> None:
        projection = self.document["relation"][
            "unfrozen_binary_source_macro_projection"
        ]
        self.assertEqual(
            (
                projection["m_constraints"],
                projection["n_nonconstant_variables"],
                projection["l_public_bits"],
                projection["sparse_nonzeros_projection"],
            ),
            (37_364_095, 21_531_353, 9_704, 156_526_483),
        )
        self.assertEqual(
            projection["aurora_padding"]["injected_canonical_public_zero_inputs"],
            6_679,
        )
        self.assertFalse(projection["executable_sparse_matrices_retained"])
        self.assertFalse(projection["typed_symbolic_ir_frozen"])
        self.assertFalse(projection["verified_ir_to_binary_sparse_lowering"])
        self.assertFalse(projection["accepted_geometry"])
        self.assertFalse(projection["used_for_bcs_privacy_floor"])
        self.assertIsNone(projection["proof_bytes"])

    def test_whole_aurora_rbr_is_not_inferred_from_fri(self) -> None:
        rbr = self.document["round_by_round_soundness"]
        self.assertFalse(rbr["whole_aurora_direct_rbr_theorem"])
        self.assertFalse(rbr["fri_component_rbr_is_whole_aurora_rbr"])
        self.assertFalse(rbr["fri_2023_1071_scope_includes_aurora"])
        self.assertFalse(rbr["aurora_proved_generalized_special_soundness"])
        self.assertFalse(rbr["cms_applicable_to_current_profile"])

    def test_generic_cms_root_fallback_stays_symbolic(self) -> None:
        fallback = self.document["round_by_round_soundness"][
            "cms_appendix_b_generic_fallback"
        ]
        self.assertEqual(fallback["expression"], "mu^(1/(k+1))")
        self.assertIsNone(fallback["exact_k"])
        self.assertIsNone(fallback["exact_mu"])
        self.assertFalse(fallback["instantiated"])
        self.assertIsNone(fallback["finite_concrete_error"])

    def test_implementation_has_no_canonical_binary_wire(self) -> None:
        implementation = self.document["implementation"]
        self.assertFalse(implementation["canonical_final_transcript_serialization"])
        self.assertFalse(
            implementation["binary_or_nonalgebraic_serialization_implemented"]
        )
        self.assertFalse(
            implementation["binary_or_nonalgebraic_deserialization_implemented"]
        )
        self.assertFalse(implementation["logical_size_counter_includes_query_positions"])
        self.assertFalse(implementation["logical_size_counter_is_canonical_proof_bytes"])
        self.assertFalse(implementation["sha512_supported"])
        self.assertFalse(implementation["shake_supported"])
        self.assertEqual(implementation["license_spdx"], "MIT")
        self.assertEqual(
            (
                implementation["static_include_closure"]["files"],
                implementation["static_include_closure"]["lines"],
                implementation["static_include_closure"]["bytes"],
            ),
            (113, 18_818, 783_493),
        )
        self.assertFalse(implementation["static_include_closure"]["built_or_linked"])

    def test_physical_proof_hash_calls_stay_null(self) -> None:
        hashes = self.document["physical_hash_calls"]
        self.assertEqual(hashes["semantic_relation"]["physical_hash_calls"], 90)
        self.assertEqual(hashes["semantic_relation"]["compression_calls"], 213)
        self.assertTrue(
            all(value is None for value in hashes["proof_backend"].values())
        )
        self.assertFalse(hashes["physical_call_accounting_complete"])

    def test_composition_categories_and_null_terms(self) -> None:
        composition = self.document["composition"]
        categories = {term["category"] for term in composition["required_terms"]}
        self.assertTrue(
            {"pcs", "iop", "fiat-shamir", "hash", "grinding", "union"}
            <= categories
        )
        self.assertTrue(all(term["value"] is None for term in composition["required_terms"]))
        self.assertIsNone(composition["overall_advantage"])
        self.assertIsNone(composition["composed_security_bits"])
        self.assertFalse(composition["strictly_below_2^-128"])

    def test_no_proof_byte_or_artifact_claim(self) -> None:
        artifact = self.document["proof_artifact"]
        for key in (
            "same_relation_proof_bytes",
            "proof_bytes_lower_bound",
            "proof_bytes_upper_bound",
            "canonical_serialized_proof",
            "retained_qualifying_proof",
            "parser",
        ):
            self.assertIsNone(artifact[key])
        self.assertFalse(artifact["historical_measurement_promoted"])
        self.assertIsNone(self.document["verdict"]["proof_bytes"])

    def test_cfw_and_provekit_remain_disqualified(self) -> None:
        comparators = self.document["comparators"]
        cfw = comparators["cfw26_105_oracle_carrier"]
        self.assertEqual(cfw["encoded_oracles"], 105)
        self.assertFalse(cfw["printed_theorem_inheritance"])
        self.assertIn("s=X^2-X", cfw["defects"][2])
        self.assertFalse(cfw["eligible"])
        provekit = comparators["provekit"]
        self.assertFalse(provekit["complete_whole_view_witness_zk"])
        self.assertFalse(provekit["witness_hiding_enabled"])
        self.assertEqual(provekit["transcript_and_mmcs_hash_bits"], 256)
        self.assertFalse(provekit["eligible"])

    def test_historical_aurora_sizes_are_not_same_relation(self) -> None:
        historical = self.document["comparators"]["historical_aurora"]
        self.assertEqual(historical["reported_range_kib"], [40, 130])
        self.assertFalse(historical["same_relation_measurement"])
        self.assertFalse(historical["use_in_tournament_ranking"])
        self.assertIsNone(historical["proof_bytes"])

    def test_every_authority_mutation_rejects(self) -> None:
        for gate in screen.AUTHORITY_GATES:
            mutated = copy.deepcopy(self.document)
            mutated["authority"][gate] = True
            with self.assertRaises(AssertionError, msg=gate):
                screen.validate_certificate(mutated)

    def test_proof_artifact_mutations_reject(self) -> None:
        for key in (
            "same_relation_proof_bytes",
            "proof_bytes_lower_bound",
            "proof_bytes_upper_bound",
            "canonical_serialized_proof",
            "retained_qualifying_proof",
            "parser",
        ):
            mutated = copy.deepcopy(self.document)
            mutated["proof_artifact"][key] = 1
            with self.assertRaises(AssertionError, msg=key):
                screen.validate_certificate(mutated)

    def test_rbr_and_binary_relation_mutations_reject(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["round_by_round_soundness"]["whole_aurora_direct_rbr_theorem"] = True
        with self.assertRaises(AssertionError):
            screen.validate_certificate(mutated)
        mutated = copy.deepcopy(self.document)
        mutated["relation"]["exact_binary_compile"]["compiled"] = True
        with self.assertRaises(AssertionError):
            screen.validate_certificate(mutated)

    def test_canonical_certificate_readback(self) -> None:
        raw = screen.CERTIFICATE_PATH.read_text(encoding="utf-8")
        retained = json.loads(raw)
        self.assertEqual(retained, self.document)
        self.assertEqual(raw, screen.canonical_json(retained))

    def test_repo_and_local_source_hashes(self) -> None:
        screen.validate_repo_sources()
        screen.validate_primary_sources(require_present=True)
        screen.validate_libiop_sources(require_present=True)


if __name__ == "__main__":
    unittest.main()
