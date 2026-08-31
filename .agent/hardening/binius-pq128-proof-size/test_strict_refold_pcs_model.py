#!/usr/bin/env python3
"""Regression tests for the strict refold PCS byte/soundness screen."""

from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("strict_refold_pcs_model.py")
SPEC = importlib.util.spec_from_file_location("strict_refold_pcs_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class StrictRefoldPcsModelTests(unittest.TestCase):
    def test_exact_merkle_frontier_extremes(self) -> None:
        self.assertEqual(model.max_compact_merkle_frontier_nodes(10, 1), 10)
        self.assertEqual(model.max_compact_merkle_frontier_nodes(10, 1 << 10), 0)
        self.assertEqual(model.max_compact_merkle_frontier_nodes(17, 68), 740)

    def test_fixed_q319_is_over_cap_before_authentication(self) -> None:
        lower_bound = model.best_fixed_q_plan(charge_authentication=False)
        self.assertEqual(lower_bound.folds, (3, 1))
        self.assertEqual(lower_bound.proof_bytes, 126_800)
        self.assertEqual(lower_bound.proof_bytes - model.PROOF_CAP_BYTES, 2_732)

    def test_fixed_q319_authenticated_optimum(self) -> None:
        plan = model.best_fixed_q_plan(charge_authentication=True)
        self.assertEqual(plan.folds, (4,))
        self.assertEqual(plan.proof_bytes, 190_032)

    def test_johnson_core_exact_bytes_and_security(self) -> None:
        plan = model.johnson_ligerito_core_candidate()
        level = plan.levels[0]
        self.assertEqual(level.query_count, 68)
        self.assertEqual(level.opened_row_bytes, 34_816)
        self.assertEqual(level.authentication_bytes, 47_360)
        self.assertEqual(plan.terminal_bytes, 24_576)
        self.assertEqual(plan.sumcheck_bytes, 480)
        self.assertEqual(plan.proof_bytes, 112_784)
        self.assertEqual(plan.envelope_bytes, 112_796)
        self.assertEqual(plan.headroom_bytes, 11_284)
        self.assertIsNotNone(level.security)
        assert level.security is not None
        self.assertGreaterEqual(level.security.minimum_bits, 264)
        # Regression for BCHKS/Flock App. C: m=ceil(sqrt(rho)/eta)=16 and
        # the complete 2^5-1 nonempty-fold event union is charged.
        self.assertAlmostEqual(level.security.mca_bits, 330.4087954870661)
        self.assertFalse(plan.complete_zero_knowledge)
        self.assertFalse(plan.strict_admitted)

        fail_closed = model._assemble_plan(
            name="test-composition-gate",
            log_relation_size=plan.log_relation_size,
            active_symbols=plan.active_symbols,
            folds=plan.folds,
            levels=plan.levels,
            complete_zero_knowledge=True,
            blocking_reason="test only",
        )
        self.assertFalse(fail_closed.strict_admitted)

    def test_fixture_is_exact_but_explicitly_non_zk(self) -> None:
        plan = model.johnson_ligerito_core_candidate()
        fixture = model.serialize_size_fixture(plan)
        self.assertEqual(len(fixture), plan.proof_bytes)
        header = struct.unpack(">8sHH32s4B4H2I", fixture[: model.PROOF_HEADER_BYTES])
        self.assertEqual(header[0], b"HGRFPCS1")
        self.assertEqual(header[1], 2)
        self.assertEqual(header[2], 0)  # non-ZK fixture flag
        self.assertEqual(header[8], 68)  # q
        self.assertEqual(header[13], model.PAY1X2_MODELED_ACTIVE_SYMBOLS)

    def test_unfrozen_n15_n16_screens_are_not_mislabeled(self) -> None:
        n15 = model.best_one_level_johnson_plan(
            log_relation_size=15,
            active_symbols=1 << 15,
        )
        n16 = model.best_one_level_johnson_plan(
            log_relation_size=16,
            active_symbols=1 << 16,
        )
        assert n15 is not None and n16 is not None
        self.assertEqual(n15.proof_bytes, 117_488)
        self.assertEqual(n15.levels[0].encoded_oracle_bytes, 32 * 1024**3)
        self.assertEqual(n16.proof_bytes, 144_496)
        self.assertEqual(n16.levels[0].encoded_oracle_bytes, 64 * 1024**3)
        self.assertFalse(n15.strict_admitted)
        self.assertFalse(n16.strict_admitted)


if __name__ == "__main__":
    unittest.main()
