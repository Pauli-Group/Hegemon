#!/usr/bin/env python3
"""Focused mutation and exact-arithmetic tests for the fail-closed checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER = HERE / "check_certificate.py"
CERTIFICATE = HERE / "certificate.json"
REPO_ROOT = HERE.parents[2]

SPEC = importlib.util.spec_from_file_location("hx512_joint_zk_checker", CHECKER)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class JointZkCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(CERTIFICATE.read_text(encoding="utf-8"))

    def test_certificate_validates_but_stays_fail_closed(self) -> None:
        report = checker.validate_certificate(
            self.data,
            REPO_ROOT,
            check_sources=False,
            check_pdfs=False,
        )
        self.assertEqual(report["arithmetic"]["smallwood_theorem10_classical_rom_floor_bits"], 191)
        self.assertGreaterEqual(report["arithmetic"]["all_sampler_abort_union_floor_bits"], 4096)
        self.assertTrue(all(value is False for value in report["authority_flags"].values()))

    def test_require_complete_is_an_executable_negative_gate(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--skip-live-source-pins",
                "--require-complete",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn('"status": "BLOCKED"', result.stdout)

    def test_authority_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["authority_flags"]["complete_zero_knowledge"] = True
        with self.assertRaisesRegex(checker.CertificateError, "authority flag"):
            checker.validate_certificate(mutated, REPO_ROOT, check_sources=False)

    def test_nonce_reintroduction_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        nonce = next(field for field in mutated["view_fields"] if field["name"] == "PiopNonce")
        nonce["wire_state"] = "inner-u32"
        nonce["serialized_bytes"] = 4
        with self.assertRaisesRegex(checker.CertificateError, "nonce must be absent"):
            checker.validate_certificate(mutated, REPO_ROOT, check_sources=False)

    def test_theorem10_oracle_or_deferred_query_relabel_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["transcript_schedule"][5]["smallwood_theorem10_oracle"] = "XOF_4"
        with self.assertRaisesRegex(checker.CertificateError, "logical-oracle mapping"):
            checker.validate_certificate(mutated, REPO_ROOT, check_sources=False)

        mutated = copy.deepcopy(self.data)
        mutated["oracle_refinement_contract"]["deferred_claim_checks"][0]["new_program_event"] = True
        with self.assertRaisesRegex(checker.CertificateError, "same-query accounting"):
            checker.validate_certificate(mutated, REPO_ROOT, check_sources=False)

    def test_local_uniformity_does_not_hide_a_joint_correlation(self) -> None:
        # Y1=r and Y2=r+w. Each coordinate has a rank-one randomness map,
        # while the two-coordinate view exposes w as Y2-Y1.
        self.assertEqual(checker.rank_mod([[1]]), 1)
        self.assertEqual(checker.rank_mod([[1]]), 1)
        self.assertFalse(checker.affine_witness_is_hidden([[1], [1]], [[0], [1]]))
        self.assertTrue(checker.affine_witness_is_hidden([[1, 0], [0, 1]], [[0], [1]]))

    def test_duplicate_points_destroy_the_representative_vandermonde_rank(self) -> None:
        points = [1025, 1026, 1027, 1028, 1029, 1029]
        self.assertEqual(checker.rank_mod(checker.vandermonde(points, 6)), 5)

    def test_exact_integer_security_boundaries_are_retained(self) -> None:
        report = checker.arithmetic_report(self.data)
        self.assertTrue(report["cms_s6_strict_gt_128"])
        self.assertFalse(report["cms_s5_strict_gt_128"])
        self.assertFalse(report["bcs16_direct_lambda512_can_exceed_128_for_nonempty_proof"])
        self.assertEqual(report["decs_index_abort_exact_floor_bits"], 7346)


if __name__ == "__main__":
    unittest.main()
