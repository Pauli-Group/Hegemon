#!/usr/bin/env python3
"""Dependency-free acceptance tests for the HX512 compiler red team."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
AUDIT_PATH = HERE / "audit.py"


def load_audit():
    spec = importlib.util.spec_from_file_location(
        "hegemon_hx512_full_relation_redteam_audit", AUDIT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(AUDIT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A = load_audit()


class Hx512CompilerRedTeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = A.build_report()
        cls.corpus = A.build_counterfeit_corpus()

    def test_generated_artifacts_are_exact_and_canonical(self) -> None:
        A.check_outputs()
        for path, payload in A.outputs().items():
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(A.canonical_json(json.loads(payload)), payload)

    def test_independent_group_and_geometry_recount_has_no_padding(self) -> None:
        recount = self.report["geometry_recount"]
        self.assertTrue(recount["arithmetic_ledger_reconciles"])
        self.assertTrue(all(item["match"] for item in recount["groups"]))
        geometry = recount["expected_geometry"]
        self.assertEqual(
            sum(recount["group_rows_no_padding"].values()),
            geometry["m_constraints"],
        )
        self.assertEqual(
            recount["group_rows_no_padding"][
                "all-W64 manifest transport and selected-row canonicality"
            ],
            186,
        )
        self.assertEqual(
            sum(
                recount["group_rows_no_padding"][name]
                for name in A.C.AUTHORITY_GROUPS
            ),
            11_592,
        )

    def test_ledger_has_no_variable_or_row_semantics(self) -> None:
        recount = self.report["geometry_recount"]
        self.assertGreater(recount["invocations"], 0)
        self.assertEqual(recount["invocations_with_operand_or_wire_identity"], 0)
        self.assertFalse(recount["sparse_rows_retained"])
        self.assertFalse(recount["witness_constructor_retained"])
        self.assertFalse(recount["row_evaluator_retained"])

    def test_every_transport_byte_is_exercised(self) -> None:
        scan = self.report["byte_mutation_scan"]
        self.assertTrue(scan["baseline_accepted"])
        self.assertTrue(scan["coverage_complete"])
        self.assertEqual(scan["evaluations"], 1_141 + 72 + 11_000)
        self.assertEqual(scan["statement"]["bytes"], 1_141)
        self.assertEqual(scan["verifier_context"]["bytes"], 72)
        self.assertEqual(scan["private_witness"]["bytes"], 11_000)
        self.assertGreater(scan["statement"]["accepted"], 0)
        self.assertGreater(scan["private_witness"]["accepted"], 0)
        self.assertEqual(scan["verifier_context"]["accepted"], 0)

    def test_core_counterfeit_corpus_is_executable(self) -> None:
        self.assertEqual(len(self.corpus["cases"]), 14)
        self.assertTrue(self.corpus["all_expected_core_counterfeits_accepted"])
        self.assertTrue(all(item["reference_accepted"] for item in self.corpus["cases"]))
        families = {item["semantic_family"] for item in self.corpus["cases"]}
        self.assertTrue(
            {
                "Merkle anchor",
                "nullifier",
                "output commitment",
                "authorization transition",
                "native balance",
                "stablecoin signed balance",
                "balance tag",
            }.issubset(families)
        )

    def test_all_boolean_byte_high_bits_reject_at_host_parser(self) -> None:
        result = self.report["boolean_byte_high_bits"]
        self.assertTrue(result["all_noncanonical_high_bits_rejected_by_host_parser"])
        self.assertEqual(len(result["checks"]), 10)
        self.assertFalse(result["relation_evaluator_exists"])

    def test_all_sixteen_masks_and_all_five_modes_are_host_only(self) -> None:
        result = self.report["all_16_masks_all_5_modes"]
        self.assertEqual(len(result["rows"]), 80)
        self.assertTrue(result["all_80_host_shape_cases_match"])
        self.assertEqual((result["accepted"], result["rejected"]), (33, 47))
        self.assertFalse(result["relation_coverage_proved"])

    def test_exact_v2_context_is_manifest_root_then_little_endian_height(self) -> None:
        context = self.report["layout_and_endianness"]["context"]
        self.assertEqual(
            context["grammar"], "manifest_root64 || parent_height:u64le"
        )
        self.assertTrue(context["sample_prefix_equals_statement_manifest_root"])
        self.assertFalse(context["sample_prefix_equals_statement_snapshot"])
        self.assertTrue(context["sample_height_little_endian"])

    def test_policy_version_zero_is_canonical_and_accepted(self) -> None:
        result = self.report["policy_version_zero"]
        self.assertEqual(result["policy_version"], 0)
        self.assertTrue(result["statement_parser_accepted"])
        self.assertTrue(result["full_host_reference_accepted"])
        self.assertFalse(result["nonzero_constraint_required"])

    def test_policy_master_schedule_and_exact_row_delta(self) -> None:
        result = self.report["policy_master_modes"]
        self.assertTrue(result["schedule_exact_match"])
        self.assertTrue(result["host_checker_complete_for_five_modes"])
        self.assertEqual(
            result["required_additional_template_rows"],
            {
                "selected_current_or_next_policy_call_master": 512,
                "approval_current_equals_next": 512,
                "total": 1_024,
                "padding": 0,
            },
        )
        observed = result["observed_group_rows"]
        self.assertIn(
            (observed["accumulator_metadata"], observed["approval_transition"]),
            ((28_362, 9_335), (28_874, 9_847)),
        )
        self.assertFalse(result["operand_wiring_retained"])
        self.assertFalse(result["compiled_schedule_confirmed"])

    def test_all_w64_host_gates_and_endianness_vectors_are_executed(self) -> None:
        result = self.report["all_w64_authority_host_gates"]
        self.assertTrue(result["baseline_accepted"])
        self.assertEqual(len(result["lifecycle_dispute_cap_checks"]), 8)
        self.assertTrue(result["all_internally_consistent_invalid_rows_rejected"])
        self.assertEqual(len(result["endianness_vectors"]), 4)
        self.assertTrue(result["all_wrong_endian_vectors_rejected"])
        self.assertTrue(result["all_former_host_mutations_rejected_by_host_reference"])
        self.assertFalse(result["emitted_relation_evaluated"])
        self.assertFalse(result["native_parent_state_authentication_refined"])
        self.assertFalse(
            result["global_manifest_sorted_unique_cap16_state_writer_refined"]
        )

    def test_all_hash_frames_and_rfc_controls_are_unwired(self) -> None:
        result = self.report["hash_frames_counters_final_flags_outputs"]
        self.assertEqual(result["expected"]["total_calls"], 90)
        self.assertEqual(result["expected"]["total_compressions"], 213)
        self.assertEqual(result["ledger"]["core_frame_source_wiring_rows"], 0)
        for key in (
            "exact_message_byte_wires_retained",
            "exact_little_endian_message_word_wires_retained",
            "per_compression_counter_wires_retained",
            "per_compression_final_flag_wires_retained",
            "per_call_parameter_block_wires_retained",
            "per_call_digest_output_wires_retained",
            "hash_output_to_semantic_link_operands_retained",
        ):
            self.assertFalse(result[key], key)

    def test_characteristic_two_counterexamples_block_binary_reinterpretation(self) -> None:
        result = self.report["characteristic_two"]
        self.assertTrue(result["all_counterexamples_hold"])
        self.assertEqual(len(result["cases"]), 4)
        for case in result["cases"]:
            self.assertNotEqual(case["odd_goldilocks_residual"], 0)
            self.assertEqual(case["gf2_residual"], 0)
        self.assertIn("add64", result["unsafe_macros"])

    def test_layouts_consume_exact_width_without_claiming_sublayout(self) -> None:
        result = self.report["layout_and_endianness"]
        self.assertTrue(result["statement"]["contiguous_exact_consumption"])
        self.assertTrue(result["witness"]["contiguous_exact_consumption"])
        self.assertEqual(result["witness"]["source_bitness_rows_expected"], 97_704)
        self.assertFalse(result["witness"]["section_sublayouts_with_field_offsets_retained"])
        self.assertFalse(result["witness"]["per_field_endianness_and_wire_mapping_retained"])
        self.assertEqual(result["ciphertext"]["zero_padding_bytes_each"], 5)
        self.assertEqual(result["manifest"]["zero_padding_bytes"], 5)

    def test_every_authority_gate_remains_false(self) -> None:
        authority = self.report["authority"]
        self.assertTrue(all(value is False for key, value in authority.items() if key != "proof_bytes"))
        self.assertIsNone(authority["proof_bytes"])
        self.assertEqual(
            self.report["verdict"],
            "COUNT_LEDGER_ONLY_NOT_AN_EXECUTABLE_RELATION_PRODUCTION_FAIL_CLOSED",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
