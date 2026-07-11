#!/usr/bin/env python3
"""Focused tests for the Lean claims and assumption-closure axiom input."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from check_lean_claim_axioms import (
    audited_theorem_union,
    load_claimed_theorems,
    load_closure_theorems,
)


class LeanClaimAxiomInputTests(unittest.TestCase):
    def write_json(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_load_closure_theorems_reads_only_closed_tracks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(
                Path(directory),
                "matrix.json",
                {
                    "mechanized_assumption_closure": {
                        "tracks": [
                            {
                                "id": "test.closed",
                                "status": "closed",
                                "lean_theorems": ["Hegemon.Test.closed"],
                            },
                            {
                                "id": "test.open",
                                "status": "open",
                                "lean_theorems": [],
                            },
                        ]
                    }
                },
            )
            self.assertEqual(load_closure_theorems(path), ["Hegemon.Test.closed"])

    def test_open_track_cannot_claim_closure_theorem(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(
                Path(directory),
                "matrix.json",
                {
                    "mechanized_assumption_closure": {
                        "tracks": [
                            {
                                "id": "test.open",
                                "status": "open",
                                "lean_theorems": ["Hegemon.Test.not_closed"],
                            }
                        ]
                    }
                },
            )
            with self.assertRaisesRegex(SystemExit, "must not claim closure theorems"):
                load_closure_theorems(path)

    def test_closure_theorem_must_be_covered_by_claims(self) -> None:
        with self.assertRaisesRegex(SystemExit, "missing from formal security claims"):
            audited_theorem_union(
                ["Hegemon.Test.claimed"],
                ["Hegemon.Test.claimed", "Hegemon.Test.closure_only"],
            )

    def test_valid_claim_and_closure_union_is_sorted_and_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            claims_path = self.write_json(
                Path(directory),
                "claims.json",
                {
                    "claims": [
                        {
                            "claim_class": "lean_theorem",
                            "lean_theorems": [
                                "Hegemon.Test.second",
                                "Hegemon.Test.closed",
                            ],
                        },
                        {
                            "claim_class": "formal_model",
                            "lean_theorems": ["Hegemon.Test.ignored"],
                        },
                    ]
                },
            )
            claimed = load_claimed_theorems(claims_path)
            self.assertEqual(
                audited_theorem_union(claimed, ["Hegemon.Test.closed"]),
                ["Hegemon.Test.closed", "Hegemon.Test.second"],
            )


if __name__ == "__main__":
    unittest.main()
