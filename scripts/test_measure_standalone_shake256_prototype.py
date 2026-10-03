#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import measure_standalone_shake256_prototype as measure


def backend_payload(
    *,
    proof_bytes: int = 500_000,
    envelope_bytes: int = 500_016,
    status: str = "supported",
    release_qualified: bool = True,
    composed_pq_bits: int | None = 128,
) -> dict[str, object]:
    return {
        "schema": measure.BACKEND_SCHEMA,
        "profile": "pay1x2",
        "canonical_proof_bytes": proof_bytes,
        "envelope_bytes": envelope_bytes,
        "prove_ms": 125.25,
        "verify_ms": 3.5,
        "peak_rss_bytes": 64 * 1024 * 1024,
        "shake256_permutations": 36,
        "security_profile": {
            "status": status,
            "release_qualified": release_qualified,
            "semantic_hash": "SHAKE256-448",
            "proof_hash": "SHAKE256-512",
            "challenge_field": "GF(2^384)",
            "fri_classical_bits": 264,
            "qrom_accounting_complete": True,
            "composed_pq_bits": composed_pq_bits,
            "zero_knowledge": True,
        },
        "verification": {
            "valid": True,
            "mutation_rejected": True,
            "canonical_roundtrip": True,
        },
    }


class StandaloneShake256MeasurementTests(unittest.TestCase):
    def test_strict_supported_profile_reports_capacity(self) -> None:
        backend = measure.validate_backend_payload(backend_payload())
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=False,
        )
        self.assertEqual(failures, [])
        self.assertTrue(report["policy"]["accepted"])
        self.assertEqual(report["policy"]["mode"], "strict")
        self.assertTrue(report["limits"]["target_met"])
        expected = (64 * 1024 * 1024 - 2_525) // (4_967 + 500_016)
        self.assertEqual(report["capacity"]["actions_per_64mib_block"], expected)

    def test_unsupported_profile_fails_without_override(self) -> None:
        payload = backend_payload(
            status="prototype", release_qualified=False, composed_pq_bits=None
        )
        backend = measure.validate_backend_payload(payload)
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=False,
        )
        self.assertTrue(failures)
        self.assertFalse(report["policy"]["accepted"])
        self.assertIn("not Hegemon release-qualified", " ".join(failures))

    def test_explicit_prototype_override_is_labeled(self) -> None:
        payload = backend_payload(
            status="prototype", release_qualified=False, composed_pq_bits=None
        )
        backend = measure.validate_backend_payload(payload)
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=True,
        )
        self.assertEqual(failures, [])
        self.assertTrue(report["policy"]["accepted"])
        self.assertEqual(report["policy"]["mode"], "prototype_only")
        self.assertTrue(report["policy"]["strict_security_failures"])

    def test_prototype_override_never_relaxes_one_mib_cap(self) -> None:
        payload = backend_payload(
            proof_bytes=1_048_577,
            envelope_bytes=1_048_593,
            status="prototype",
            release_qualified=False,
            composed_pq_bits=None,
        )
        backend = measure.validate_backend_payload(payload)
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=True,
        )
        self.assertFalse(report["policy"]["accepted"])
        self.assertIn("canonical proof exceeds the 1 MiB hard cap", failures)
        self.assertIn("standalone proof envelope exceeds the 1 MiB hard cap", failures)

    def test_mutation_acceptance_fails_even_in_prototype_mode(self) -> None:
        payload = backend_payload(
            status="prototype", release_qualified=False, composed_pq_bits=None
        )
        payload["verification"]["mutation_rejected"] = False
        backend = measure.validate_backend_payload(payload)
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=True,
        )
        self.assertFalse(report["policy"]["accepted"])
        self.assertIn("backend accepted a deterministic proof mutation", failures)

    def test_envelope_cannot_be_smaller_than_raw_proof(self) -> None:
        with self.assertRaisesRegex(measure.MeasurementError, "cannot be smaller"):
            measure.validate_backend_payload(
                backend_payload(proof_bytes=10_000, envelope_bytes=9_999)
            )

    def test_non_finite_json_is_rejected(self) -> None:
        raw = json.dumps(backend_payload()).replace("125.25", "NaN")
        with self.assertRaisesRegex(measure.MeasurementError, "non-finite"):
            measure.parse_backend_json(raw)

    def test_reference_capacities_are_exact(self) -> None:
        self.assertEqual(measure.capacity_for_envelope(512 * 1024), 126)
        self.assertEqual(measure.capacity_for_envelope(1024 * 1024), 63)

    def test_stronger_fri_budget_is_not_rejected(self) -> None:
        payload = backend_payload()
        payload["security_profile"]["fri_classical_bits"] = 272
        backend = measure.validate_backend_payload(payload)
        report, failures = measure.build_report(
            backend,
            allow_unsupported_prototype=False,
        )
        self.assertEqual(failures, [])
        self.assertTrue(report["policy"]["accepted"])


if __name__ == "__main__":
    unittest.main()
