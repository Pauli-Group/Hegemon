#!/usr/bin/env python3
"""Regression and fail-closed mutation tests for the composition ledger."""

from __future__ import annotations

import copy
import json
import unittest
from fractions import Fraction

import composition_ledger as ledger


class ExactArithmeticTests(unittest.TestCase):
    def test_strict_equality_rejects(self) -> None:
        self.assertFalse(ledger.strict_gt_128(Fraction(1, 1 << 128)))
        self.assertTrue(ledger.strict_gt_128(Fraction(1, 1 << 129)))

    def test_missing_required_term_never_composes(self) -> None:
        values = {term_id: Fraction(0, 1) for term_id in ledger.REQUIRED_TERM_IDS}
        values[ledger.REQUIRED_TERM_IDS[0]] = None
        self.assertIsNone(ledger.compose_required(values))

    def test_bcs_ell_only_weaker_sensitivity_is_2_pow_minus_101(self) -> None:
        self.assertEqual(
            ledger.bcs_direct_term(ledger.CFW_HALF_LENGTH, 512),
            Fraction(1, 1 << 101),
        )

    def test_bcs_e320_communication_floor_and_lambda(self) -> None:
        self.assertEqual(ledger.CFW_PROVER_FIELD_ELEMENT_FLOOR, 33_555_190)
        self.assertEqual(ledger.BCS_PROOF_LENGTH_BITS_FLOOR, 10_737_660_800)
        self.assertEqual(
            ledger.bcs_direct_term(ledger.BCS_PROOF_LENGTH_BITS_FLOOR, 512),
            Fraction(ledger.BCS_PROOF_LENGTH_BITS_FLOOR, 1 << 126),
        )
        self.assertEqual(
            ledger.minimum_bcs_lambda_multiple_of_four(
                ledger.BCS_PROOF_LENGTH_BITS_FLOOR
            ),
            656,
        )
        self.assertFalse(
            ledger.strict_gt_128(
                ledger.bcs_direct_term(ledger.BCS_PROOF_LENGTH_BITS_FLOOR, 648)
            )
        )
        self.assertTrue(
            ledger.strict_gt_128(
                ledger.bcs_direct_term(ledger.BCS_PROOF_LENGTH_BITS_FLOOR, 656)
            )
        )

    def test_256_bit_width_is_immediate_no_go(self) -> None:
        screen = ledger.local_hash_width_terms(256)
        self.assertEqual(
            ledger.from_factored(screen["collision_unit_policy"]["exact_fraction"]),
            Fraction(1, 1 << 64),
        )
        self.assertEqual(
            ledger.from_factored(
                screen["optimistic_preimage_unit_policy"]["exact_fraction"]
            ),
            Fraction(1, 1 << 128),
        )
        self.assertFalse(screen["collision_unit_policy"]["strictly_below_2^-128"])
        self.assertFalse(
            screen["optimistic_preimage_unit_policy"]["strictly_below_2^-128"]
        )

    def test_512_bit_unit_width_screen_has_headroom_only(self) -> None:
        screen = ledger.local_hash_width_terms(512)
        self.assertTrue(screen["collision_unit_policy"]["strictly_below_2^-128"])
        self.assertTrue(
            screen["optimistic_preimage_unit_policy"]["strictly_below_2^-128"]
        )
        self.assertIsNone(screen["physical_call_cap"])
        self.assertIsNone(screen["theorem_exact_constant"])

    def test_semantic_secret_prefix_no_go_terms(self) -> None:
        self.assertEqual(ledger.ideal_secret_prefix_term(384), Fraction(1, 1 << 127))
        self.assertEqual(
            ledger.ideal_secret_prefix_term(448, 2 * (1 << 32)),
            Fraction(1, 1 << 126),
        )
        self.assertEqual(
            ledger.ideal_secret_prefix_term(448, 15 * (1 << 32)),
            Fraction(15, 1 << 127),
        )

    def test_ghcm21_corrected_smallwood_bounds(self) -> None:
        self.assertEqual(ledger.SMALLWOOD_GHCM_REPROGRAM_POINT_CAP, 2_097_160)
        current_single = ledger.ghcm21_prop2_reprogramming_term(
            ledger.SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
            1 << 64,
            512,
        )
        self.assertEqual(
            current_single,
            Fraction(3 * 2_097_160, 2 * (1 << 224)),
        )
        current_history = ledger.ghcm21_prop2_reprogramming_term(
            ledger.SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
            1 << 64,
            512,
            proof_instances=1 << 64,
        )
        widened_history = ledger.ghcm21_prop2_reprogramming_term(
            ledger.SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
            1 << 64,
            576,
            proof_instances=1 << 64,
        )
        self.assertEqual(ledger.integer_security_bits(current_history), 138)
        self.assertEqual(ledger.integer_security_bits(widened_history), 170)
        self.assertTrue(ledger.strict_gt_128(current_history))
        self.assertTrue(ledger.strict_gt_128(widened_history))

    def test_ghcm21_heterogeneous_leaf_and_chain_history(self) -> None:
        leaf_history = ledger.ghcm21_prop2_reprogramming_term(
            2 * (1 << 20),
            1 << 64,
            576,
            proof_instances=1 << 64,
        )
        chain_history = ledger.ghcm21_prop2_reprogramming_term(
            8,
            1 << 64,
            512,
            proof_instances=1 << 64,
        )
        self.assertEqual(leaf_history, Fraction(3, 1 << 172))
        self.assertEqual(chain_history, Fraction(3, 1 << 158))
        self.assertEqual(
            leaf_history + chain_history,
            Fraction(49_155, 1 << 172),
        )
        self.assertEqual(ledger.integer_security_bits(leaf_history + chain_history), 156)
        self.assertTrue(ledger.strict_gt_128(leaf_history + chain_history))

    def test_current_32_byte_salt_breaks_direct_ghcm_route(self) -> None:
        first_program = ledger.ghcm21_prop2_reprogramming_term(1, 1 << 64, 256)
        self.assertEqual(first_program, Fraction(3, 1 << 97))
        self.assertFalse(ledger.strict_gt_128(first_program))

    def test_wide_tape_and_salt_byte_sensitivity(self) -> None:
        self.assertEqual(ledger.SMALLWOOD_WIDENED_OPENED_TAPE_DELTA_BYTES, 184)
        self.assertEqual(ledger.SMALLWOOD_GLOBAL_SALT_DELTA_BYTES, 32)
        self.assertEqual(
            {
                query_count: (
                    ledger.widened_opened_tape_delta_bytes(query_count),
                    ledger.widened_opened_tape_delta_bytes(query_count)
                    + ledger.SMALLWOOD_GLOBAL_SALT_DELTA_BYTES,
                )
                for query_count in (23, 48, 55)
            },
            {23: (184, 216), 48: (384, 416), 55: (440, 472)},
        )

    def test_negative_opened_tape_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ledger.widened_opened_tape_delta_bytes(-1)


class LedgerStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = ledger.build_ledger()

    def test_canonical_artifact_matches_generator(self) -> None:
        raw = ledger.LEDGER_PATH.read_text(encoding="utf-8")
        self.assertEqual(raw, ledger.canonical_json(json.loads(raw)))
        self.assertEqual(json.loads(raw), self.document)

    def test_every_missing_composition_term_is_null(self) -> None:
        terms = self.document["composition"]["required_terms"]
        self.assertEqual(len(terms), len(ledger.REQUIRED_TERM_IDS))
        self.assertTrue(all(term["value"] is None for term in terms))
        self.assertIsNone(self.document["composition"]["overall_advantage"])

    def test_exact_mixed_and_split_geometry(self) -> None:
        relation = self.document["architecture"]["hegemon_odd_field_r1cs"]
        mixed = relation["source_geometry"]
        split = relation["split_sha3_512_control_geometry"]
        self.assertEqual(mixed["m_constraints"], 20_457_227)
        self.assertEqual(mixed["n_nonconstant_variables"], 19_311_555)
        self.assertEqual(mixed["matrix_nonzeros_total"], 94_551_238)
        self.assertEqual(split["m_constraints"], 23_727_052)
        self.assertEqual(split["n_nonconstant_variables"], 23_613_572)

    def test_cfw_equal_halves_are_not_whir_variable_count(self) -> None:
        relation = self.document["architecture"]["hegemon_odd_field_r1cs"]
        embedding = relation["cfw26_candidate_embedding"]
        self.assertEqual(embedding["ell_half_length"], 1 << 25)
        self.assertEqual(embedding["total_carrier_elements"], 1 << 26)
        self.assertIsNone(embedding["whir_polynomial_num_variables"])

    def test_bcs_p_is_total_proof_bits_and_remains_unknown(self) -> None:
        bcs = self.document["bcs_direct_zk"]
        self.assertEqual(bcs["minimum_cfw_prover_field_elements"], 33_555_190)
        self.assertEqual(bcs["proof_length_bits_floor"], 10_737_660_800)
        self.assertIsNone(bcs["exact_total_iop_proof_length_bits_p_of_x"])
        self.assertIsNone(bcs["required_lambda_for_exact_p"])

    def test_section11_oracle_hvzk_and_rbr_counts(self) -> None:
        section11 = self.document["cfw26_section11_theorem_geometry"]
        self.assertEqual(section11["encoded_oracles"]["inner_mask"], 78)
        self.assertEqual(section11["encoded_oracles"]["outer_mask"], 26)
        self.assertEqual(section11["encoded_oracles"]["total"], 105)
        self.assertEqual(section11["hvzk_statistical_error"]["coefficient"], 105)
        self.assertIsNone(section11["hvzk_statistical_error"]["zeta"])
        self.assertEqual(section11["rbr_middle_sumcheck_coordinate_terms"], 26)
        self.assertEqual(section11["rbr_total_coordinate_terms"], 29)

    def test_exactly_fifteen_security_bearing_roles(self) -> None:
        roles = self.document["semantic_hash_ledger"]["roles"]
        self.assertEqual(len(roles), 15)
        self.assertEqual(len({role["role_id"] for role in roles}), 15)
        self.assertTrue(
            all(role["enforced_conditional_min_entropy_bits"] is None for role in roles)
        )

    def test_theorem_and_assumption_lanes_are_separate(self) -> None:
        lanes = self.document["hash_assumption_lanes"]
        theorem = lanes["A_theorem_only_concrete_deployed_hash"]
        assumed = lanes["B_conventional_hash_as_qro_assumption"]
        self.assertIsNone(theorem["concrete_instantiation_advantage"])
        self.assertTrue(all(value is None for value in assumed["assumption_advantages"].values()))
        self.assertFalse(assumed["zero_instantiation_advantage_counterfactual_passes"])

    def test_direct_ghcm_route_is_numeric_only_and_soundness_separate(self) -> None:
        ghcm = self.document["smallwood_direct_ghcm21_qrom_zk"]
        self.assertFalse(ghcm["strict_complete_zk_authority"])
        self.assertFalse(
            ghcm["applicability"]["whole_protocol_hybrid_reprogram_bound_proved"]
        )
        self.assertFalse(
            ghcm["cms_boundary"][
                "soundness_inherited_without_new_bcs_or_cms_refinement"
            ]
        )
        self.assertIsNone(
            ghcm["concrete_hash_boundary"]["Adv_QRO-inst(SHA-512)"]
        )
        self.assertEqual(
            ghcm["bound"][
                "homogeneous_512_bit_all_programs_u2^64_history_sensitivity_only"
            ][
                "integer_security_bits_display"
            ],
            138,
        )
        self.assertEqual(
            ghcm["bound"][
                "homogeneous_576_bit_all_programs_u2^64_history_sensitivity_only"
            ][
                "integer_security_bits_display"
            ],
            170,
        )
        self.assertEqual(
            ghcm["bound"]["heterogeneous_576_leaf_512_chain_u2^64_history"][
                "integer_security_bits_display"
            ],
            156,
        )
        self.assertEqual(
            ghcm["bound"][
                "heterogeneous_576_leaf_512_chain_approximate_security_bits_display"
            ],
            "156.4149494468487",
        )
        self.assertFalse(ghcm["bound"]["homogeneous_sensitivity_has_protocol_authority"])
        self.assertFalse(
            ghcm["applicability"][
                "one_global_salt_proves_later_chain_program_entropy"
            ]
        )
        self.assertIsNone(
            ghcm["applicability"]["later_chain_program_entropy_source_proved"]
        )

    def test_only_e320_has_total_carrier_field_headroom(self) -> None:
        fields = {item["field_id"]: item for item in self.document["field_options"]}
        self.assertTrue(
            fields["goldilocks-e320-binomial"]["local_cfw_total_carrier_sensitivity"][
                "strictly_below_2^-128"
            ]
        )
        for field_id in (
            "goldilocks-e128-binomial",
            "koalabear-degree8-binomial",
            "babybear-degree8-binomial",
        ):
            self.assertFalse(
                fields[field_id]["local_cfw_total_carrier_sensitivity"][
                    "strictly_below_2^-128"
                ]
            )

    def test_no_unsupported_goldilocks_extension_is_invented(self) -> None:
        fields = self.document["field_options"]
        gold_degrees = {
            item["extension_degree"]
            for item in fields
            if item["base_field"] == "Goldilocks"
        }
        self.assertEqual(gold_degrees, {2, 5})
        by_degree = {
            item["extension_degree"]: item
            for item in fields
            if item["base_field"] == "Goldilocks"
        }
        self.assertEqual(by_degree[2]["two_adicity"], 33)
        self.assertEqual(by_degree[5]["two_adicity"], 32)
        self.assertTrue(by_degree[5]["standard_uniform_distribution_implemented"])

    def test_provekit_is_doubly_disqualified(self) -> None:
        candidate = self.document["architecture"]["provekit_main"]
        self.assertFalse(candidate["witness_complete_zk"])
        self.assertEqual(candidate["merkle_digest_bytes"], 32)
        self.assertFalse(candidate["pq128_numeric_parameter_is_qrom_composition"])

    def test_conjectural_and_approximate_whir_profiles_reject(self) -> None:
        whir = self.document["whir_parameterization"]
        self.assertFalse(whir["capacity_bound"]["authoritative"])
        self.assertFalse(whir["johnson_bound_local_implementation"]["authoritative"])
        self.assertIsNone(whir["selected_profile"])

    def test_runtime_caps_do_not_fill_union_terms(self) -> None:
        unions = self.document["union_and_runtime_ledger"]
        runtime = self.document["wire_sampling_grinding_rng_ledger"]
        self.assertEqual(unions["max_proofs_per_block_source_policy"], 10_000)
        self.assertFalse(unions["consensus_history_cap_enforced"])
        self.assertIsNone(unions["multi_proof_union_advantage"])
        self.assertEqual(runtime["max_mmcs_leaves_source_wire_cap"], 1 << 20)
        self.assertIsNone(runtime["physical_hash_call_cap"])
        self.assertIsNone(runtime["rng_entropy_failure_and_reuse"])

    def test_production_is_fail_closed(self) -> None:
        self.assertTrue(not any(self.document["capabilities"].values()))
        self.assertIsNone(self.document["architecture"]["winner"])
        self.assertIsNone(self.document["proof_bytes"])


class MutationTests(unittest.TestCase):
    def test_zero_substitution_for_missing_term_rejects(self) -> None:
        mutated = copy.deepcopy(ledger.build_ledger())
        mutated["composition"]["required_terms"][0]["value"] = {
            "denominator": "1",
            "numerator": "0",
        }
        with self.assertRaises(AssertionError):
            ledger.validate_ledger(mutated)

    def test_architecture_promotion_rejects(self) -> None:
        mutated = copy.deepcopy(ledger.build_ledger())
        mutated["architecture"]["winner"] = "goldilocks-e320-hvzk-whir"
        with self.assertRaises(AssertionError):
            ledger.validate_ledger(mutated)

    def test_hash_assumption_zeroing_rejects(self) -> None:
        mutated = copy.deepcopy(ledger.build_ledger())
        assumptions = mutated["hash_assumption_lanes"][
            "B_conventional_hash_as_qro_assumption"
        ]["assumption_advantages"]
        assumptions["Adv_QRO-inst(SHA-512)"] = {
            "denominator": "1",
            "numerator": "0",
        }
        with self.assertRaises(AssertionError):
            ledger.validate_ledger(mutated)

    def test_whir_variable_count_fabrication_rejects(self) -> None:
        mutated = copy.deepcopy(ledger.build_ledger())
        mutated["local_policy"]["whir_polynomial_num_variables"] = 26
        with self.assertRaises(AssertionError):
            ledger.validate_ledger(mutated)

    def test_source_pins_and_full_checker_pass(self) -> None:
        ledger.validate_ledger(ledger.build_ledger())


if __name__ == "__main__":
    unittest.main()
