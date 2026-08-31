from __future__ import annotations

import copy
import json
import unittest

import trace_screen as screen


class TraceScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.value = screen.build_screen()

    def test_canonical_screen_validates(self) -> None:
        screen.validate_screen(self.value, verify_pins=True)

    def test_arithmetic_receipt_is_exhaustive(self) -> None:
        receipt = screen.exhaustive_arithmetic_receipt()
        self.assertEqual(receipt["radix4_binary_addition_cases"], 576)
        self.assertEqual(receipt["radix4_ternary_addition_cases"], 2_304)
        self.assertEqual(receipt["bit_full_adder_cases"], 32)
        self.assertTrue(receipt["all_pass"])

    def test_generated_artifact_is_canonical(self) -> None:
        expected = screen.canonical_json(self.value)
        self.assertEqual(expected, screen.SCREEN_PATH.read_bytes())
        self.assertEqual(json.loads(expected), self.value)

    def test_u16_shape_boundary_and_selected_shapes(self) -> None:
        selected = self.value["layouts"]["selected"]
        for rows, cols in selected["geometry"]["matrix_shapes"].values():
            self.assertGreater(screen.matrix_bytes_u16(rows, cols), 0)
        local_k64 = self.value["layouts"]["locally_enumerated_k64"]
        rows, cols = local_k64["geometry"]["matrix_shapes"]["opened_witness_row_scalars"]
        with self.assertRaises(screen.Reject):
            screen.matrix_bytes_u16(rows, cols)

    def test_exhaustive_integer_packing_co_minimum(self) -> None:
        selected = self.value["layouts"]["selected"]
        search = selected["packing_search"]
        self.assertEqual(search["packing_step"], 1)
        self.assertEqual(search["maximum_packing"], 32_767)
        self.assertEqual(
            [entry["packing"] for entry in search["co_minimal_payload_packings"]],
            [1_024, 1_029],
        )
        self.assertEqual(selected["packing_factor"], 1_024)
        self.assertTrue(selected["word_boundary_aligned"])

    def test_exact_serializer_components(self) -> None:
        selected = self.value["layouts"]["selected"]
        components = selected["proof_screen"]["static_inner_payload_components"]
        self.assertEqual(
            components,
            {
                "magic_salt_nonce_sha512_digest": 104,
                "ppol_highs": 205_604,
                "plin_highs": 81_844,
                "rcombi_tails": 1_844,
                "subset_evals": 376_836,
                "partial_evals": 1_204,
                "auth_paths": 29_465,
                "opened_leaf_tapes": 1_472,
                "masking_evals": 924,
                "high_coeffs": 225_004,
                "opened_witness": 448_773,
                "total": 1_373_074,
            },
        )

    def test_mode_gated_auth_digest_link_is_explicit(self) -> None:
        selected = self.value["layouts"]["selected"]
        rows = selected["row_breakdown"]
        checks = selected["constraint_accounting"]
        relation = selected["relation"]["mode_gated_auth_state_digest_link"]
        self.assertEqual(rows["mode_gated_auth_state_digest_nonlinear_rows"], 1)
        self.assertEqual(rows["mode_gated_auth_state_digest_broadcast_rows"], 1)
        self.assertEqual(
            checks["mode_gated_auth_state_digest_broadcast_copy_checks"], 1_024
        )
        self.assertEqual(relation["logical_cells"], 1_024)
        self.assertFalse(relation["executable_indexer_and_refinement_retained"])

    def test_zero_knowledge_width_sensitivities_fail_closed(self) -> None:
        sensitivity = self.value["privacy_width_sensitivity"]
        self.assertEqual(
            sensitivity["current_sha512"]["best_case_p_equals_one_security_bits"], 126
        )
        self.assertIsNone(sensitivity["current_sha512"]["bcs_p_bits"])
        self.assertEqual(
            sensitivity["conditional_fresh_profiles"]["768"]["privacy_merkle_only_static_inner_bytes"],
            1_390_738,
        )
        self.assertEqual(
            sensitivity["conditional_fresh_profiles"]["1024"]["conditional_privacy_merkle_plus_one_salt_one_h_bytes"],
            1_407_346,
        )

    def test_mutations_fail_closed(self) -> None:
        mutations = []

        def mutate(path: tuple[str, ...], replacement: object) -> None:
            value = copy.deepcopy(self.value)
            cursor = value
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = replacement
            mutations.append((".".join(path), value))

        mutate(("status",), "winner")
        mutate(("schedule", "blake2b512_compressions"), 212)
        mutate(("schedule", "fused_addition_relations_per_compression"), 383)
        mutate(("field", "selected_packing_factor"), 1_029)
        mutate(("field", "anisotropic_coefficient"), 2)
        mutate(("arithmetic_receipt", "all_pass"), False)
        mutate(("layouts", "selected", "row_breakdown", "core_rows"), 11_052)
        mutate(("layouts", "selected", "row_breakdown", "direct_base_rows"), 11_207)
        mutate(("layouts", "selected", "constraint_accounting", "core_nonlinear_output_polynomials"), 8_495)
        mutate(("layouts", "selected", "constraint_accounting", "selected_control_digit_checks"), 0)
        mutate(("layouts", "selected", "constraint_accounting", "mode_gated_auth_state_digest_broadcast_copy_checks"), 0)
        mutate(("layouts", "selected", "constraint_accounting", "core_padding_zero_checks"), 0)
        mutate(("layouts", "selected", "constraint_accounting", "full_cfg_constraint_count"), 1)
        mutate(("layouts", "selected", "packing_search", "packing_step"), 32)
        mutate(("layouts", "selected", "proof_screen", "static_inner_payload_bytes"), 1_372_954)
        mutate(("layouts", "selected", "proof_screen", "current_profile_proof_bytes"), 1)
        mutate(("layouts", "selected", "proof_screen", "full_relation_proof_bytes"), 1)
        mutate(("flat_occurrence_comparison", "corrected_hx512_source_projection_constraints"), 29_509_133)
        mutate(("dense_topology_gate", "public_secret_independent_indexer_implemented"), True)
        mutate(("dense_topology_gate", "exact_executable_hash_trace_row_count"), 11_209)
        mutate(("wire_and_profile_feasibility", "current_arithmetization_enum_supports_selected_packing"), True)
        mutate(("complete_zero_knowledge", "complete_zero_knowledge"), True)
        mutate(("privacy_width_sensitivity", "current_sha512", "bcs_p_bits"), 1)
        mutate(("privacy_width_sensitivity", "current_sha512", "strict_gt_128_even_at_p_equals_one"), True)
        mutate(("security_geometry_sensitivity", "K1024_final_profile_selected"), True)
        mutate(("transcript_and_qrom", "composed_security_bits"), 129)
        mutate(("comparisons", "aurora", "proof_bytes"), 1)
        mutate(("comparisons", "strict_size_winner"), "smallwood")
        mutate(("capabilities", "exact_executable_hash_trace_adapter"), True)
        mutate(("capabilities", "production_authorized"), True)
        mutate(("verdict", "current_smallest_defensible_winner"), True)

        for name, value in mutations:
            with self.subTest(name=name), self.assertRaises(screen.Reject):
                screen.validate_screen(value, verify_pins=False)


if __name__ == "__main__":
    unittest.main()
