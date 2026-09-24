#!/usr/bin/env python3
"""Adversarial source-only tests for the HX512 formal-refinement gate."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER = HERE / "check_refinement.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("hx512_formal_refinement_gate", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


C = load_checker()


class FormalRefinementGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = C.load_contract()

    def test_retained_boundary_is_integral_but_unqualified(self) -> None:
        report = C.audit(self.contract)
        self.assertEqual(report["integrity_errors"], [])
        self.assertFalse(report["qualified"])
        self.assertFalse(report["production_authorized"])
        self.assertIn(
            "missing_refinement:engine_source_readback",
            report["qualification_blockers"],
        )

    def test_boolean_spoof_cannot_authorize(self) -> None:
        mutated = copy.deepcopy(self.contract)
        for field in mutated["rust_to_lean"]:
            mutated["rust_to_lean"][field] = True
        report = C.audit(mutated)
        self.assertFalse(report["qualified"])
        self.assertFalse(report["production_authorized"])
        self.assertTrue(
            any(
                item.startswith("inactive_flag_must_remain_false:")
                for item in report["integrity_errors"]
            )
        )

    def test_source_pin_mutation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.contract)
        path = "circuits/transaction/src/smallwood_hx512_transcript.rs"
        mutated["frozen_sources"][path]["sha512"] = "00" * 64
        report = C.audit(mutated)
        self.assertTrue(
            any(item.startswith(f"source_drift:{path}:") for item in report["integrity_errors"])
        )
        self.assertFalse(report["production_authorized"])

    def test_identity_and_engine_pins_are_explicitly_absent(self) -> None:
        self.assertIsNone(
            self.contract["frozen_sources"]
            ["circuits/transaction/src/smallwood_engine.rs"]["sha512"]
        )
        self.assertFalse(
            self.contract["rust_to_lean"]["canonical_protocol_identity_allocated"]
        )
        report = C.audit(self.contract)
        self.assertIn(
            "unfrozen_source:circuits/transaction/src/smallwood_engine.rs",
            report["qualification_blockers"],
        )

    def test_q48_s6_eta5_equation14_term_stays_disqualified(self) -> None:
        field = "smallwood_equation14_high_degree_codeword_weight_discharged"
        report = C.audit(self.contract)
        self.assertIn(
            f"missing_refinement:{field}",
            report["qualification_blockers"],
        )
        mutated = copy.deepcopy(self.contract)
        mutated["rust_to_lean"][field] = True
        changed = C.audit(mutated)
        self.assertIn(
            f"inactive_flag_must_remain_false:{field}",
            changed["integrity_errors"],
        )
        self.assertFalse(changed["production_authorized"])


if __name__ == "__main__":
    unittest.main()
