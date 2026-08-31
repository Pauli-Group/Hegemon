#!/usr/bin/env python3
"""Dependency-free adversarial checks for the inactive HX512B01 compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
COMPILER_PATH = HERE / "compiler.py"


def load_compiler():
    spec = importlib.util.spec_from_file_location("hegemon_hx512_full_relation", COMPILER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(COMPILER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


C = load_compiler()


class Hx512FullRelationTests(unittest.TestCase):
    def reject(self, fn, *args) -> str:
        with self.assertRaises(C.Reject) as caught:
            fn(*args)
        return str(caught.exception)

    def valid(self) -> tuple[bytes, bytes, bytes]:
        return C.sample_valid_case()

    def mutate(self, raw: bytes, offset: int, mask: int = 1) -> bytes:
        changed = bytearray(raw)
        changed[offset] ^= mask
        return bytes(changed)

    def test_dependency_contracts_and_primitive_rows(self) -> None:
        C.source_contracts()
        C.BASE.check_primitive_rows()
        C.AUTHORITY.check()
        self.assertEqual(
            C.SUITE.r1cs_costs()["blake2b512_rfc"]["m_constraints_source_static"],
            29_510_157,
        )

    def test_exact_statement_context_and_witness_grammars(self) -> None:
        statement, context, witness = self.valid()
        parsed = C.parse_statement(statement)
        self.assertEqual(len(statement), 1141)
        self.assertEqual(len(context), 72)
        self.assertEqual(len(witness), 11_000)
        self.assertEqual(parsed["magic"], b"HX512B01")
        self.assertEqual(context[64:], (50).to_bytes(8, "little"))
        self.assertEqual(statement[861:869], (50).to_bytes(8, "big"))
        decoded = C.VerifierContext.decode(context)
        self.assertEqual(decoded.encode(), context)
        self.assertEqual(decoded.manifest_root, statement[733:797])
        self.assertNotEqual(decoded.manifest_root, statement[797:861])
        self.assertEqual(statement[528:532], bytes(4))
        private = C.parse_witness(witness, True)
        self.assertEqual(private.auth_mode, 0)
        self.assertEqual(private.sections["manifest_membership"][-5:], bytes(5))
        self.reject(C.parse_statement, statement[:-1])
        self.reject(C.VerifierContext.decode, context + b"\0")
        self.reject(C.parse_witness, witness[:-1], True)

    def test_statement_identity_and_consensus_bindings_reject(self) -> None:
        statement, _, _ = self.valid()
        for offset in (0, 8, 933, 935, 937, 939, 941, 945, 946, 947, 949, 1013, 1077):
            with self.subTest(offset=offset):
                self.reject(C.parse_statement, self.mutate(statement, offset))

    def test_statement_parser_rejects_noncanonical_scalars(self) -> None:
        statement, _, _ = self.valid()
        changed = bytearray(statement)
        changed[10] = 2
        self.reject(C.parse_statement, bytes(changed))
        changed = bytearray(statement)
        changed[10:14] = bytes(4)
        self.reject(C.parse_statement, bytes(changed))
        changed = bytearray(statement)
        changed[510] = 1
        changed[511:519] = bytes(8)
        self.reject(C.parse_statement, bytes(changed))
        changed = bytearray(statement)
        changed[470:478] = (1).to_bytes(8, "big")
        self.reject(C.parse_statement, bytes(changed))
        changed = bytearray(statement)
        changed[486:494] = (1001).to_bytes(8, "big")
        self.reject(C.parse_statement, bytes(changed))

    def test_all_sixteen_masks_all_five_modes(self) -> None:
        rows = C.SUITE.activity_mode_matrix()
        self.assertEqual(len(rows), 80)
        accepted = 0
        for row in rows:
            flags = tuple(bool(row["mask"] & (1 << bit)) for bit in range(4))
            mode = (
                "single_key",
                "accumulator_init",
                "approval_step",
                "value_lock_creation",
                "final_threshold_spend",
            ).index(row["mode"])
            observed = C.activity_shape_accepts(mode, flags)
            self.assertEqual(observed, row["accept"], row)
            accepted += int(observed)
        self.assertEqual((accepted, len(rows) - accepted), (33, 47))

    def test_diagnostic_mask_language_is_not_the_active_native_route(self) -> None:
        audit = C.live_route_semantics_audit()
        self.assertEqual(audit["bit_order"], ["input0", "input1", "output0", "output1"])
        self.assertEqual(
            (
                audit["diagnostic_accepted_pairs"],
                audit["live_route_accepted_pairs"],
                audit["diagnostic_only_pairs"],
                audit["live_route_rejected_pairs"],
            ),
            (33, 26, 7, 54),
        )
        self.assertEqual(audit["live_route_accepted_by_mode"], [9, 6, 2, 6, 3])
        self.assertTrue(audit["binding_value_balance_is_fixed_zero"])
        self.assertTrue(audit["diagnostic_relation_allows_nonzero_value_balance"])
        self.assertFalse(audit["diagnostic_grammar_matches_active_route"])

    def test_ciphertext_bytes_size_hash_and_padding_are_bound(self) -> None:
        statement, context, witness = self.valid()
        C.verify_reference(statement, context, witness)
        self.reject(
            C.verify_reference,
            statement,
            context,
            self.mutate(witness, 777 * 8),
        )
        self.reject(
            C.verify_reference,
            self.mutate(statement, 334),
            context,
            witness,
        )
        self.reject(
            C.parse_witness,
            self.mutate(witness, (777 + 269) * 8 - 1),
            True,
        )
        changed = bytearray(statement)
        changed[462:466] = (2146).to_bytes(4, "big")
        self.reject(C.parse_statement, bytes(changed))

    def test_four_former_host_only_forgeries_now_reject(self) -> None:
        evidence = C.executed_reference_mutations()
        self.assertEqual(len(evidence), 6)
        self.assertTrue(all(item["observed"] == "reject" for item in evidence))
        observed = {item["name"] for item in evidence}
        self.assertTrue(
            {
                "forged_policy_hash_derivation",
                "forged_selected_entry_membership",
                "forged_whole_manifest_or_path_root",
                "forged_consensus_expected_root",
                "forged_consensus_expected_height",
            }.issubset(observed)
        )

    def test_manifest_row_path_and_context_mutations_reject(self) -> None:
        statement, context, witness = self.valid()
        offsets = (
            C.MANIFEST_OFFSET,
            C.MANIFEST_OFFSET + 4,
            C.MANIFEST_OFFSET + 4 + 72,
            C.MANIFEST_OFFSET + 4 + 85,
            C.MANIFEST_OFFSET + 4 + 214,
            C.MANIFEST_OFFSET + 4 + 215,
        )
        for offset in offsets:
            with self.subTest(offset=offset):
                self.reject(
                    C.verify_reference,
                    statement,
                    context,
                    self.mutate(witness, offset),
                )
        for offset in (541, 605, 669, 733, 797, 861):
            with self.subTest(statement_offset=offset):
                self.reject(
                    C.verify_reference,
                    self.mutate(statement, offset),
                    context,
                    witness,
                )
        for offset in (0, 64):
            with self.subTest(context_offset=offset):
                self.reject(
                    C.verify_reference,
                    statement,
                    self.mutate(context, offset),
                    witness,
                )

    def test_manifest_transport_index_boolean_and_retirement_canonicality(self) -> None:
        statement, context, witness = self.valid()
        self.reject(
            C.parse_witness,
            self.mutate(witness, C.MANIFEST_OFFSET + 479),
            True,
        )
        changed = bytearray(witness)
        changed[C.MANIFEST_OFFSET + 3] = 1
        self.reject(C.parse_witness, bytes(changed), True)
        for row_offset in (72, 85, 214):
            changed = bytearray(witness)
            changed[C.MANIFEST_OFFSET + 4 + row_offset] |= 2
            self.reject(C.parse_witness, bytes(changed), True)
        changed = bytearray(witness)
        changed[C.MANIFEST_OFFSET + 4 + 72] = 0
        changed[C.MANIFEST_OFFSET + 4 + 73] = 1
        self.reject(C.parse_witness, bytes(changed), True)
        C.verify_reference(statement, context, witness)

    def test_disabled_stablecoin_is_uniquely_zero(self) -> None:
        fixture = C.EXECUTABLE.build_fixture(0, 0b1111)
        disabled_statement = fixture.statement
        disabled_witness = fixture.witness
        context = fixture.context
        C.verify_reference(disabled_statement, context, disabled_witness)
        self.reject(
            C.verify_reference,
            disabled_statement,
            self.mutate(context, 0),
            disabled_witness,
        )
        self.reject(
            C.parse_witness,
            self.mutate(disabled_witness, C.MANIFEST_OFFSET),
            False,
        )
        changed = bytearray(disabled_statement)
        changed[733] = 1
        self.reject(C.parse_statement, bytes(changed))

    def test_composite_domain_schedule_and_kats(self) -> None:
        counts = C.SUITE.profile_counts(C.IDENTITY_NAME)
        self.assertEqual(
            (
                counts["core_physical_calls"],
                counts["authority_physical_calls"],
                counts["core_blake2b512_compressions"],
                counts["authority_blake2b512_compressions"],
            ),
            (83, 7, 205, 8),
        )
        values = C.kats()
        suite = C.SUITE.kats()
        self.assertEqual(values["all_w64_policy"], suite["authority_blake_policy"])
        self.assertEqual(values["all_w64_oracle"], suite["authority_blake_oracle"])
        self.assertEqual(values["all_w64_attestation"], suite["authority_blake_attestation"])
        self.assertEqual(values["all_w64_root_cap16"], suite["authority_blake_manifest_root_cap16"])
        self.assertEqual(values["all_w64_snapshot_height50"], suite["authority_blake_snapshot_height50"])
        self.assertFalse(
            C.SUITE.authority_schedule(C.IDENTITY_NAME)[
                "alternate_generic_hx512_authority_frames_accepted"
            ]
        )

    def test_exact_macro_geometry_and_group_ledger(self) -> None:
        program = C.compile_relation()
        geometry = program.geometry()
        self.assertEqual(
            geometry,
            {
                "m_constraints": 29_509_887,
                "n_nonconstant_variables": 21_531_579,
                "l_public_variables": 9_704,
                "auxiliary_variables_total": 21_521_875,
                "private_transport_variables": 88_000,
                "derived_auxiliary_variables": 21_433_875,
                "matrix_nonzeros_total": 123_197_556,
                "z_vector_length_including_constant_one": 21_531_580,
            },
        )
        groups = program.export_groups()
        self.assertEqual(sum(group["rows"] for group in groups), geometry["m_constraints"])
        authority = {
            group["name"]: group["rows"]
            for group in groups
            if group["name"] in C.AUTHORITY_GROUPS
        }
        self.assertEqual(list(authority.values()), [186, 1088, 512, 5696, 1934, 2176])
        self.assertEqual(sum(authority.values()), 11_592)
        self.assertEqual(groups[15]["rows"], 28_874)
        self.assertEqual(groups[16]["rows"], 9_847)
        suite_rows = C.SUITE.r1cs_costs()["blake2b512_rfc"]["m_constraints_source_static"]
        self.assertEqual(suite_rows, 29_510_157)

    def test_executable_ir_covers_all_masks_modes_stablecoin_and_hash_controls(self) -> None:
        certificate = C.EXECUTABLE.executable_ir_certificate()
        self.assertTrue(certificate["semantic_source_operands_named"])
        self.assertFalse(certificate["numeric_r1cs_operand_ids_assigned"])
        self.assertFalse(certificate["intermediate_r1cs_variables_allocated"])
        self.assertTrue(certificate["executable_evaluator"])
        self.assertTrue(certificate["all_33_accepted_mask_mode_pairs_evaluated"])
        self.assertTrue(certificate["all_33_stablecoin_enabled_mask_mode_pairs_evaluated"])
        self.assertFalse(certificate["exact_full_production_relation"])
        self.assertTrue(certificate["known_accepted_production_counterexamples"])
        self.assertEqual(len(certificate["accepted_fixtures"]), 66)
        self.assertEqual(len(certificate["hash_calls"]), 90)
        matrix = certificate["activity_stablecoin_matrix"]
        self.assertEqual(
            (matrix["total_cells"], matrix["positive_cells"], matrix["negative_cells"]),
            (160, 66, 94),
        )
        self.assertTrue(matrix["all_negative_cells_reach_activity_mask_mode"])
        self.assertFalse(certificate["sparse_r1cs_rows_emitted"])
        fixture = C.EXECUTABLE.build_fixture(0, 1)
        evaluation = C.EXECUTABLE.evaluate(fixture.statement, fixture.context, fixture.witness)
        for call in evaluation.hash_calls[75:79]:
            self.assertEqual(call.fixed_compressions, 3)
            self.assertEqual(len(call.counters), 3)
            self.assertEqual(len(call.final_flags), 3)
            self.assertEqual(call.final_flags, (False, True, False))
            self.assertEqual(call.selected_digest_state_after_compression, 2)

        expected_states = {
            0: (2, 2, 2, 2),
            1: (3, 2, 3, 2),
            2: (3, 3, 3, 3),
            3: (2, 2, 2, 2),
            4: (3, 2, 3, 2),
        }
        for mode, states in expected_states.items():
            fixture = C.EXECUTABLE.build_fixture(mode, 15)
            evaluation = C.EXECUTABLE.evaluate(
                fixture.statement, fixture.context, fixture.witness
            )
            self.assertEqual(
                tuple(
                    call.selected_digest_state_after_compression
                    for call in evaluation.hash_calls[75:79]
                ),
                states,
            )

    def test_shared_kernel_registry_uses_exact_export_line_contract(self) -> None:
        lib_path = C.rel(C.KERNEL_LIB_PATH)
        self.assertNotIn(lib_path, C.EXPECTED_DEPENDENCY_SHA512)
        self.assertEqual(
            C.KERNEL_LIB_PATH.read_text().splitlines().count(C.KERNEL_V2_EXPORT_LINE),
            1,
        )
        entries = {
            item["path"]: item for item in C.source_entries()
        }
        contract = entries[lib_path + "#exact-export-line"]
        encoded = C.KERNEL_V2_EXPORT_LINE.encode("utf-8")
        self.assertEqual(contract["bytes"], len(encoded))
        self.assertEqual(contract["occurrences"], 1)
        self.assertEqual(contract["sha512"], hashlib.sha512(encoded).hexdigest())

    def test_active_route_divergence_uses_exact_source_line_contracts(self) -> None:
        entries = {item["path"]: item for item in C.source_entries()}
        source_lines = [line.strip() for line in C.LIVE_ADMISSION_PATH.read_text().splitlines()]
        for name, exact_line in C.LIVE_ADMISSION_EXACT_LINES:
            with self.subTest(name=name):
                self.assertEqual(source_lines.count(exact_line), 1)
                key = C.rel(C.LIVE_ADMISSION_PATH) + f"#exact-line::{name}"
                contract = entries[key]
                encoded = exact_line.encode("utf-8")
                self.assertEqual(contract["bytes"], len(encoded))
                self.assertEqual(contract["occurrences"], 1)
                self.assertEqual(contract["sha512"], hashlib.sha512(encoded).hexdigest())

    def test_redteam_core_mutations_have_named_residuals(self) -> None:
        residuals = C.EXECUTABLE.mutation_residuals()
        self.assertGreaterEqual(len(residuals), 37)
        self.assertTrue(all(item["observed"] == "reject" for item in residuals))
        names = {item["name"] for item in residuals}
        self.assertTrue(
            {
                "statement_anchor",
                "statement_nullifier",
                "statement_commitment",
                "input_spend_master",
                "input_merkle_sibling",
                "output_note",
                "authorization_auxiliary",
                "policy_master",
                "approval_master_continuity",
                "final_intent",
                "final_threshold",
            }.issubset(names)
        )

    def test_streaming_boolean_blake2b_rows_and_independent_oracle(self) -> None:
        trace = C.boolean_hash_trace_certificate()
        self.assertEqual(trace["physical_calls"], 90)
        self.assertEqual(trace["total_compressions"], 213)
        self.assertEqual(trace["compression_rows_per_fixture"], 29_049_792)
        self.assertEqual(trace["parameter_not_rows_per_fixture"], 0)
        self.assertEqual(trace["total_boolean_hash_rows_per_fixture"], 29_049_792)
        self.assertEqual(trace["all_fixture_call_records"], 5_940)
        self.assertEqual(trace["all_fixture_fixed_compressions"], 14_058)
        self.assertTrue(trace["all_66_call_digests_equal_independent_hashlib"])
        self.assertEqual(trace["selected_exhaustive_bit_rows"], 0)
        self.assertEqual(trace["selected_exhaustive_planned_rows"], 87_149_376)
        self.assertFalse(trace["selected_exhaustive_trace_executed"])
        self.assertTrue(trace["semantic_gate_failed_before_expensive_trace"])
        self.assertEqual(trace["selected_exhaustive_traces"], [])
        self.assertEqual(
            trace["constant_folded_parameter_state_kats"]["unique_fixed_parameter_blocks"],
            8,
        )
        self.assertTrue(trace["frame_role_swap_rejects"])
        self.assertTrue(trace["personalization_bit_swap_rejects"])
        self.assertFalse(trace["caller_supplied_parameters_accepted"])
        self.assertFalse(trace["expanded_sparse_rows_retained"])

    def test_diagnostic_rules_hash_is_not_a_final_proof_profile(self) -> None:
        profile = C.PROFILE.descriptor()
        self.assertEqual(
            profile["artifact_schema"],
            "hegemon.hx512b01.diagnostic-relation-profile.v1",
        )
        self.assertFalse(
            profile["diagnostic_relation_identity"]["final_consensus_rules_hash_frozen"]
        )
        self.assertFalse(
            profile["diagnostic_relation_identity"]["production_identity_allocated"]
        )
        self.assertIsNone(
            profile["diagnostic_relation_identity"]["final_consensus_rules_hash_hex"]
        )
        proof = profile["proof_system_required_but_unallocated"]
        for key in (
            "fresh_arithmetization_identity",
            "packing_factor",
            "pcs_parameters",
            "piop_parameters",
            "decs_parameters",
            "complete_zk_mask_width_and_tape_grammar",
            "fiat_shamir_transcript",
            "transcript_domain_registry",
            "inner_wire_magic",
            "outer_envelope_magic",
            "outer_envelope_version",
            "statement_and_context_binding_preamble",
        ):
            self.assertIsNone(proof[key], key)
        self.assertIn("SMZ2", proof["rejected_legacy_identities"])
        blockers = profile["known_production_semantic_blockers"]
        for key in (
            "positive_issuance_requires_issuer_or_collateral_capability",
            "minimum_collateral_ratio_evaluated",
            "epoch_mint_cap_is_cumulative_and_atomic",
            "no_input_anchor_is_canonical_or_verifier_authenticated",
            "activity_mask_mode_grammar_matches_active_native_route",
            "live_route_value_balance_zero_enforced",
        ):
            self.assertFalse(blockers[key], key)
        statement, _, _ = self.valid()
        self.assertEqual(statement[1077:1141], C.PROFILE.DIAGNOSTIC_RULES_HASH)
        self.reject(C.parse_statement, self.mutate(statement, 1077))

    def test_parameterized_section11_projection(self) -> None:
        projection = C.section11_projection(C.compile_relation().geometry())
        self.assertEqual(projection["ell"], 1 << 25)
        self.assertEqual(projection["matrix_shape"], [1 << 26, 1 << 26])
        self.assertEqual(projection["encoded_oracles"]["total"], 105)
        self.assertEqual(projection["witness_zero_padding"], 12_032_557)
        self.assertEqual(projection["row_zero_padding"], 25_566_420)
        self.assertEqual(projection["carrier_nonzeros"], 147_262_670)
        self.assertGreaterEqual(projection["public_zero_padding"], 0)
        self.assertGreaterEqual(projection["witness_zero_padding"], 0)
        self.assertGreaterEqual(projection["row_zero_padding"], 0)
        self.assertFalse(projection["section11_theorem_instantiated"])
        self.assertFalse(projection["complete_hvzk_proved"])

    def test_mutation_corpus_contains_all_80_pairs(self) -> None:
        corpus = C.mutation_corpus()
        matrix = corpus["all_sixteen_masks_all_five_authorization_modes"]
        self.assertEqual(len(matrix), 80)
        self.assertEqual(sum(row["accept"] for row in matrix), 33)
        self.assertEqual(corpus["rejected_mask_mode_pairs"], 47)
        matrix160 = corpus["all_160_activity_mode_stablecoin_cells"]
        self.assertEqual(
            (matrix160["total_cells"], matrix160["positive_cells"], matrix160["negative_cells"]),
            (160, 66, 94),
        )
        self.assertGreaterEqual(corpus["retained_mutations"], 50)
        blockers = corpus["production_blocking_accepted_counterexamples"]
        self.assertTrue(blockers["all_three_reproduced_as_accepted"])
        self.assertFalse(blockers["exact_full_production_relation"])

    def test_three_production_blocking_counterexamples_are_retained(self) -> None:
        blockers = C.blocking_accepted_counterexamples()
        self.assertTrue(blockers["all_three_reproduced_as_accepted"])
        self.assertEqual(
            [item["name"] for item in blockers["cases"]],
            [
                "permissionless_positive_stablecoin_issuance",
                "noncumulative_max_mint_per_epoch",
                "arbitrary_anchor_when_no_inputs_are_active",
            ],
        )
        permissionless, cumulative, anchor = blockers["cases"]
        self.assertEqual(permissionless["active_inputs"], 1)
        self.assertTrue(permissionless["active_native_route_shape"])
        self.assertFalse(permissionless["minimum_collateral_ratio_evaluated"])
        self.assertEqual(cumulative["cumulative_issuance"], 2)
        self.assertEqual(cumulative["selected_max_mint_per_epoch"], 1)
        self.assertTrue(cumulative["shared_parent_state"])
        self.assertEqual(anchor["active_inputs"], 0)

    def test_artifacts_are_canonical_and_read_back_exactly(self) -> None:
        C.check_outputs()
        expected = C.outputs()
        for path, payload in expected.items():
            self.assertEqual(path.read_bytes(), payload)
            decoded = json.loads(payload)
            self.assertEqual(C.canonical_json(decoded), payload)
        manifest = json.loads(C.MANIFEST_PATH.read_text())
        certificate = json.loads(C.CERTIFICATE_PATH.read_text())
        self.assertEqual(certificate["geometry"], manifest["r1cs"]["geometry"])
        self.assertEqual(certificate["proof_bytes"], None)
        self.assertFalse(certificate["production_authorized"])

    def test_every_security_and_production_authority_stays_false(self) -> None:
        manifest = C.build_manifest()
        authority = manifest["authority"]
        self.assertTrue(authority["known_accepted_production_counterexamples"])
        for key in (
            "source_macro_full_relation_compiled",
            "exact_full_production_relation",
            "stablecoin_issuer_or_collateral_capability_enforced",
            "stablecoin_minimum_collateral_ratio_evaluated",
            "stablecoin_epoch_cap_cumulative_and_atomic",
            "no_input_anchor_canonical_or_authenticated",
            "all_four_former_host_predicates_emitted_as_sparse_r1cs",
            "expanded_sparse_matrix_retained",
            "scalar_to_macro_refinement_proved",
            "complete_zero_knowledge_proved",
            "composed_qrom_pq128_proved",
            "exact_native_verifier_refinement_proved",
            "consensus_parent_state_authentication_refined",
            "production_authorized",
            "release_manifest_authorized",
        ):
            self.assertFalse(authority[key], key)
        self.assertIsNone(manifest["proof"]["artifact"])
        self.assertIsNone(manifest["proof"]["bytes"])
        self.assertFalse(manifest["parent_state_boundary"]["native_verifier_derives_context_from_authenticated_parent"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
