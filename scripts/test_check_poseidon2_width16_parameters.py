#!/usr/bin/env python3
"""Mutation tests for the width-16 Poseidon2 parameter assurance gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_poseidon2_width16_parameters.py"
MANIFEST = ROOT / "config/poseidon2-width16-v1.json"

SPEC = importlib.util.spec_from_file_location("poseidon2_width16_parameter_gate", CHECKER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Poseidon2 width-16 parameter gate")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Poseidon2Width16ParameterGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text())
        GATE.validate_manifest(cls.manifest)

    def assert_rejected(self, mutate: Callable[[dict], None]) -> None:
        candidate = copy.deepcopy(self.manifest)
        mutate(candidate)
        with self.assertRaises(GATE.GateError):
            GATE.validate_manifest(candidate)

    def test_baseline_is_candidate_only(self) -> None:
        self.assertFalse(self.manifest["production_authorized"])
        self.assertTrue(self.manifest["required_external_review"])

    def test_production_flip_is_rejected(self) -> None:
        self.assert_rejected(lambda manifest: manifest.__setitem__("production_authorized", True))

    def test_round_tuple_drift_is_rejected(self) -> None:
        self.assert_rejected(lambda manifest: manifest["parameters"].__setitem__("partial_rounds", 21))

    def test_matrix_orientation_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda manifest: manifest["parameters"].__setitem__(
                "external_matrix_orientation", "P4_kron_M4"
            )
        )

    def test_round_constant_digest_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda manifest: manifest["digests"].__setitem__(
                "round_constants_sha256", "0" * 64
            )
        )

    def test_known_answer_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda manifest: manifest["known_answer_tests"]["permutation_zero"].__setitem__(
                0, "0x0000000000000000"
            )
        )

    def test_provenance_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda manifest: manifest["provenance"].__setitem__("horizen_commit", "0" * 40)
        )

    def test_attack_disposition_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda manifest: manifest["cryptanalysis_screen"]["eprint_2026_306"].__setitem__(
                "disposition", "approved"
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
