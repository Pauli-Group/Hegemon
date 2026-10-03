#!/usr/bin/env python3
"""Regression tests for the standalone strict-PQ profile scaffold."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR))

import strict_pq_profile as profile  # noqa: E402


class StrictPqProfileTests(unittest.TestCase):
    def test_selected_profile_has_one_rounded_bit_of_composed_margin(self) -> None:
        report = profile.evaluate_profile(profile.STRICT_PQ_SCAFFOLD)
        self.assertTrue(report["security"]["static_profile_gate_pass"])
        self.assertEqual(report["security"]["composed_union_bound_bits_floor"], 129)
        self.assertGreater(
            report["security"]["composed_union_bound_bits"],
            profile.POST_QUANTUM_TARGET_BITS + 1,
        )

    def test_parameter_scaffold_never_claims_backend_or_release_support(self) -> None:
        report = profile.evaluate_profile(profile.STRICT_PQ_SCAFFOLD)
        self.assertFalse(report["release_authorized"])
        self.assertIn("scaffold only", report["claim_ceiling"])
        self.assertIn(
            "backend capability not established: strict_profile_implemented",
            report["blocking_reasons"],
        )

    def test_current_upstream_profile_is_rejected(self) -> None:
        report = profile.evaluate_profile(profile.UPSTREAM_NEGATIVE_CONTROL)
        self.assertFalse(report["security"]["static_profile_gate_pass"])
        failures = "\n".join(report["security"]["static_profile_failures"])
        self.assertIn("SHAKE256-448", failures)
        self.assertIn("SHAKE256-512", failures)
        self.assertIn("GF(2^384)", failures)
        self.assertIn("below 264", failures)
        self.assertIn("spend-secret entropy is below 384 bits", failures)
        self.assertLess(report["security"]["composed_union_bound_bits_floor"], 128)

    def test_259_bits_for_every_qrom_protocol_term_has_no_union_margin(self) -> None:
        minimum_only = replace(
            profile.STRICT_PQ_SCAFFOLD,
            max_algebraic_union_degree_log2=125,  # 384 - 125 = 259
            fri_classical_bits=259,
            fiat_shamir_classical_bits=259,
            multi_target_classical_bits=259,
        )
        report = profile.evaluate_profile(minimum_only)
        self.assertEqual(report["security"]["composed_union_bound_bits_floor"], 126)
        self.assertFalse(report["security"]["static_profile_gate_pass"])

    def test_256_bit_spend_secret_has_no_composition_margin(self) -> None:
        short_secret = replace(
            profile.STRICT_PQ_SCAFFOLD,
            spend_secret_entropy_bits=256,
        )
        report = profile.evaluate_profile(short_secret)
        self.assertEqual(report["security"]["composed_union_bound_bits_floor"], 127)
        self.assertFalse(report["security"]["static_profile_gate_pass"])
        failures = "\n".join(report["security"]["static_profile_failures"])
        self.assertIn("spend-secret entropy is below 384 bits", failures)

    def test_selected_profile_accounts_for_secret_and_hiding_search(self) -> None:
        report = profile.evaluate_profile(profile.STRICT_PQ_SCAFFOLD)
        terms = {term["name"]: term for term in report["security"]["terms"]}
        self.assertEqual(terms["spend-key recovery"]["post_quantum_bits"], 192)
        self.assertEqual(terms["note-commitment hiding"]["post_quantum_bits"], 192)
        self.assertEqual(terms["rho search privacy"]["post_quantum_bits"], 192)

    def test_exact_target_and_cap_block_capacities(self) -> None:
        target = profile.capacity_for_proof_bytes(
            profile.PROOF_OPTIMIZATION_TARGET_BYTES
        )
        hard_cap = profile.capacity_for_proof_bytes(profile.PROOF_HARD_CAP_BYTES)
        self.assertEqual(target["max_actions"], 126)
        self.assertEqual(target["action_bytes"], 529_255)
        self.assertEqual(hard_cap["max_actions"], 63)
        self.assertEqual(hard_cap["action_bytes"], 1_053_543)

    def test_serialized_file_is_measured_and_bound_by_shake256_512(self) -> None:
        payload = b"canonical-proof-envelope" * 31
        with tempfile.TemporaryDirectory() as directory:
            proof_path = Path(directory) / "proof.bin"
            proof_path.write_bytes(payload)
            measurement = profile.measure_serialized_proof(proof_path)
            report = profile.evaluate_profile(profile.STRICT_PQ_SCAFFOLD, measurement)

        self.assertEqual(measurement.serialized_proof_bytes, len(payload))
        self.assertEqual(measurement.shake256_512, hashlib.shake_256(payload).hexdigest(64))
        self.assertTrue(report["proof_size"]["byte_gate_pass"])
        self.assertEqual(
            report["proof_size"]["capacity"]["max_actions"],
            (profile.BLOCK_CAP_BYTES - profile.BLOCK_FIXED_BYTES)
            // (profile.NON_PROOF_ACTION_BYTES + len(payload)),
        )
        # Backend evidence remains absent even when the artifact is small.
        self.assertFalse(report["release_authorized"])

    def test_oversized_file_rejects_before_digest_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proof_path = Path(directory) / "oversized.bin"
            with proof_path.open("wb") as proof_file:
                proof_file.truncate(profile.PROOF_HARD_CAP_BYTES + 1)
            measurement = profile.measure_serialized_proof(proof_path)
            report = profile.evaluate_profile(profile.STRICT_PQ_SCAFFOLD, measurement)

        self.assertIsNone(measurement.shake256_512)
        self.assertEqual(
            measurement.digest_skipped_reason,
            "artifact exceeds the 1 MiB hard cap",
        )
        self.assertFalse(report["proof_size"]["byte_gate_pass"])

    def test_cli_returns_nonzero_for_upstream_negative_control(self) -> None:
        command = [
            sys.executable,
            str(THIS_DIR / "strict_pq_profile.py"),
            "--profile",
            "upstream-negative-control",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(report["security"]["static_profile_gate_pass"])


if __name__ == "__main__":
    unittest.main()
