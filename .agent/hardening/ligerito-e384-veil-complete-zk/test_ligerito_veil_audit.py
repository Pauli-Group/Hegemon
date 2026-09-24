#!/usr/bin/env python3
"""Dependency-free tests for the fail-closed VEIL/Ligerito audit."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "ligerito_veil_audit.py"
SPEC = importlib.util.spec_from_file_location("ligerito_veil_audit", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load audit module")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class LigeritoVeilAuditTests(unittest.TestCase):
    def test_current_prefix_masks_have_rank_one_against_rank_three_view(self) -> None:
        result = AUDIT.ligerito_prefix_rank_counterexample()
        self.assertEqual(result["current_mask_rank"], 1)
        self.assertEqual(result["current_joined_rank"], 3)
        self.assertFalse(result["rank_gate_passes_current"])
        self.assertEqual(result["conditional_total_variation"], "1")

    def test_three_extension_coordinate_masks_only_close_local_nonzero_case(self) -> None:
        result = AUDIT.ligerito_prefix_rank_counterexample()
        self.assertEqual(result["veil_three_coordinate_mask_rank"], 3)
        self.assertEqual(result["veil_joined_rank"], 3)
        self.assertTrue(result["rank_gate_passes_local_veil_nonzero_coefficient"])
        self.assertFalse(result["rank_gate_passes_veil_zero_coefficient"])

    def test_q_padding_coordinates_are_necessary_in_executable_analogue(self) -> None:
        result = AUDIT.query_padding_rank_example()
        self.assertEqual(result["query_count"], 3)
        self.assertEqual(result["observation_rank"], 3)
        self.assertTrue(result["rank_gate_passes"])
        self.assertEqual(result["q_minus_one_padding_rank"], 2)
        self.assertFalse(result["q_minus_one_rank_gate_passes"])

    def test_source_geometry_direct_payload_floors(self) -> None:
        q38 = AUDIT.source_geometry(16, 6, 38)
        self.assertEqual(q38["data_columns"], 64)
        self.assertEqual(q38["message_rows_before_padding"], 1024)
        self.assertEqual(q38["random_padding_b128_elements"], 2432)
        self.assertEqual(q38["random_mask_b128_elements"], 3186)
        self.assertEqual(q38["source_structure_direct_payload_floor_bytes"], 3840)

        q61 = AUDIT.source_geometry(16, 6, 61)
        self.assertEqual(q61["source_structure_direct_payload_floor_bytes"], 6048)
        self.assertEqual(
            q61["source_structure_direct_payload_floor_bytes"], 96 * 61 + 192
        )

    def test_paper_symbolic_formula_uses_sha512_and_e384_widths(self) -> None:
        result = AUDIT.paper_symbolic_overhead_bytes(
            base_query_count=2,
            stacking_log=3,
            pcs_path_log=5,
            inner_security_padding=7,
            linear_code_path_log=11,
            multiplicative_code_path_log=13,
            r1cs_height=17,
            direct_message_count=19,
            zk_padding=23,
        )
        self.assertEqual(result["digest_count"], 181)
        self.assertEqual(result["field_element_count"], 225)
        self.assertEqual(result["total_bytes"], 22384)

    def test_certificate_is_fail_closed(self) -> None:
        certificate = AUDIT.build_certificate()
        self.assertEqual(AUDIT.validate_certificate(certificate), [])
        self.assertFalse(certificate["decision"]["frontier_eligible"])
        for claim in AUDIT.FORBIDDEN_TRUE_CLAIMS:
            self.assertIs(certificate["claims"][claim], False)

    def test_mutated_authority_claim_is_rejected(self) -> None:
        certificate = copy.deepcopy(AUDIT.build_certificate())
        certificate["claims"]["complete_zk"] = True
        self.assertIn("claims.complete_zk", AUDIT.validate_certificate(certificate))

    def test_mutated_rank_certificate_is_rejected(self) -> None:
        certificate = copy.deepcopy(AUDIT.build_certificate())
        certificate["rank_counterexample"]["current_mask_rank"] = 3
        self.assertIn(
            "rank_counterexample.current_mask_rank",
            AUDIT.validate_certificate(certificate),
        )

    def test_primary_source_and_checkout_pins(self) -> None:
        self.assertEqual(
            AUDIT.source_checks(AUDIT.DEFAULT_PAPER, AUDIT.DEFAULT_SLOP), []
        )


if __name__ == "__main__":
    unittest.main()
