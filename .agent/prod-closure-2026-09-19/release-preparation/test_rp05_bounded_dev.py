#!/usr/bin/env python3
"""Cheap limit and provenance checks for the reviewed RP05 lifecycle guard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import rp05_bounded_dev as guard


def canonical_limits() -> dict[str, int | float]:
    return {
        "wall_seconds": 3600,
        "child_stop_seconds": 3400,
        "peak_rss_bytes": 16 * 1024**3,
        "stop_group_rss_bytes": 16 * 1024**3 - 512 * 1024**2,
        "scratch_bytes": 1024**3,
        "stop_scratch_bytes": 960 * 1024**2,
        "minimum_free_bytes": 20 * 1024**3,
        "max_sample_gap_seconds": 5,
    }


class BoundedDevelopmentGuardTests(unittest.TestCase):
    def test_canonical_limits_fit_ceiling_and_keep_hard_stop_margin(self) -> None:
        limits = canonical_limits()
        guard._validate_limits(limits)
        self.assertLessEqual(
            limits["child_stop_seconds"],
            limits["wall_seconds"] - guard.HARD_STOP_MARGIN_SECONDS,
        )

    def test_child_limit_cannot_consume_hard_stop_margin(self) -> None:
        limits = canonical_limits()
        limits["child_stop_seconds"] = limits["wall_seconds"] - guard.HARD_STOP_MARGIN_SECONDS + 1
        with self.assertRaisesRegex(ValueError, "hard-stop margin"):
            guard._validate_limits(limits)

    def test_limits_reject_rss_scratch_and_disk_expansion(self) -> None:
        for key, value in (
            ("peak_rss_bytes", 16 * 1024**3 + 1),
            ("scratch_bytes", 1024**3 + 1),
            ("minimum_free_bytes", 20 * 1024**3 - 1),
        ):
            with self.subTest(key=key):
                limits = canonical_limits()
                limits[key] = value
                with self.assertRaises(ValueError):
                    guard._validate_limits(limits)

    def test_guard_is_source_bound_to_immutable_reviewed_supervisor_inputs(self) -> None:
        self.assertEqual(len(guard.REFERENCE_GUARD_SHA256), 64)
        self.assertEqual(len(guard.PROCESS_GROUP_HELPER_SHA256), 64)
        self.assertTrue(guard.REFERENCE_GUARD.is_file())
        self.assertTrue(guard.PROCESS_GROUP_HELPER.is_file())
        self.assertEqual(guard.sha256_file(guard.REFERENCE_GUARD), guard.REFERENCE_GUARD_SHA256)
        self.assertEqual(
            guard.sha256_file(guard.PROCESS_GROUP_HELPER), guard.PROCESS_GROUP_HELPER_SHA256
        )

    def test_guard_never_advertises_execution_or_production_authority(self) -> None:
        source = (HERE / "rp05_bounded_dev.py").read_text(encoding="utf-8")
        self.assertIn('"production_authorized": False', source)
        self.assertIn('"production_eligible": False', source)
        self.assertIn('"execution_receipts_authenticated": False', source)


if __name__ == "__main__":
    unittest.main()
