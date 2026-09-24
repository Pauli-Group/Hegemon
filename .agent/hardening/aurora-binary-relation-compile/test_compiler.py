#!/usr/bin/env python3
"""Dependency-free tests for the Aurora negative relation closeout."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "hegemon_aurora_negative_closeout", HERE / "compiler.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import closeout checker")
C = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C
SPEC.loader.exec_module(C)


class NegativeCloseoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = C.expected_manifest()

    def test_retained_artifacts_match_exact_closeout(self) -> None:
        C.check()

    def test_every_authority_is_false(self) -> None:
        authority = self.manifest["authority"]
        self.assertTrue(authority)
        self.assertTrue(all(value is False for value in authority.values()))

    def test_no_corrected_geometry_or_proof_is_fabricated(self) -> None:
        final = self.manifest["corrected_final_geometry"]
        self.assertIsNone(final["m_constraints"])
        self.assertIsNone(final["n_nonconstant_variables"])
        self.assertIsNone(final["matrix_nonzeros_total"])
        self.assertIsNone(self.manifest["proof"]["artifact"])
        self.assertIsNone(self.manifest["proof"]["bytes"])
        self.assertIsNone(self.manifest["aurora_theorem_9_2"]["security_bits"])

    def test_projection_is_explicitly_pre_correction_only(self) -> None:
        projection = self.manifest["last_reproducible_pre_correction_projection"]
        self.assertEqual(
            (
                projection["m_constraints"],
                projection["n_nonconstant_variables"],
                projection["l_public_variables"],
                projection["matrix_nonzeros_total"],
            ),
            (37364095, 21531353, 9704, 156526483),
        )
        self.assertFalse(projection["expanded_coordinates_retained"])
        self.assertFalse(projection["verified_ir_to_matrix_lowering"])

    def test_policy_master_gap_is_retained(self) -> None:
        policy = self.manifest["policy_master_drift"]
        self.assertEqual(
            (
                policy["retained_pre_correction_rows"],
                policy["live_semantic_required_rows"],
                policy["missing_rows"],
            ),
            (1536, 2560, 1024),
        )
        self.assertEqual(
            policy["current_policy_master"], {"offset_bytes": 6088, "bytes": 64}
        )
        self.assertEqual(
            policy["next_policy_master"], {"offset_bytes": 6152, "bytes": 64}
        )
        self.assertFalse(policy["corrected_binary_geometry_recomputed"])

    def test_v2_context_is_manifest_root_not_snapshot(self) -> None:
        context = self.manifest["all_w64_v2_mapping"]["context"]
        self.assertEqual(context["grammar"], "manifest_root64 || parent_height:u64le")
        self.assertEqual(
            context["snapshot_preimage"], "parent_height:u64le || manifest_root64"
        )
        self.assertFalse(context["snapshot_substitution_for_context_allowed"])
        self.assertFalse(context["native_parent_authentication_refined"])

    def test_hx512_identity_is_pinned_but_not_matrix_bound(self) -> None:
        identity = self.manifest["hx512_identity"]
        self.assertEqual(identity["statement_magic"], "HX512B01")
        self.assertEqual(identity["circuit_version_hex"], "0x5121")
        self.assertEqual(identity["crypto_suite_hex"], "0x512b")
        self.assertEqual(identity["domain_set_hex"], "0x5127")
        self.assertFalse(identity["identity_bound_by_executable_binary_matrix"])

    def test_padding_is_projection_not_authority(self) -> None:
        padding = self.manifest["aurora_padding_projection"]
        self.assertEqual(
            (
                padding["h1_padded_constraints"],
                padding["h2_padded_z_including_constant"],
                padding["adapter_k_explicit_public_inputs"],
                padding["public_zero_padding"],
            ),
            (1 << 26, 1 << 25, (1 << 14) - 1, 6679),
        )
        self.assertFalse(
            padding["strict_degree_greater_than_codeword_dimension_witnessed"]
        )
        self.assertFalse(padding["shifted_domain_disjointness_proved"])

    def test_positive_authority_mutation_rejects(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["authority"]["executable_characteristic_two_sparse_r1cs"] = True
        with self.assertRaises(C.Reject):
            C.validate_fail_closed(mutated)

    def test_final_geometry_mutation_rejects(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["corrected_final_geometry"]["m_constraints"] = 37365119
        with self.assertRaises(C.Reject):
            C.validate_fail_closed(mutated)

    def test_checker_rejects_changed_manifest_object(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["verdict"] = "EXECUTABLE"
        real_read = C._read_object

        def substitute(path: Path):
            if path == C.MANIFEST_PATH:
                return mutated
            return real_read(path)

        with mock.patch.object(C, "_read_object", side_effect=substitute):
            with self.assertRaises(C.Reject):
                C.check()


if __name__ == "__main__":
    unittest.main()
