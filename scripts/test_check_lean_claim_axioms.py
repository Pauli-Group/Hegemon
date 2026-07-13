#!/usr/bin/env python3
"""Focused tests for the Lean claims and assumption-closure axiom input."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from check_lean_claim_axioms import (
    audited_theorem_union,
    load_claimed_theorems,
    load_closure_theorems,
    parse_axiom_json,
    run_lean_axiom_query,
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

    def test_trusted_json_parser_rejects_duplicate_theorem_records(self) -> None:
        output = json.dumps(
            [
                {"theorem": "Fixture.compromised", "axioms": []},
                {"theorem": "Fixture.compromised", "axioms": []},
            ]
        )
        with self.assertRaisesRegex(SystemExit, "repeats theorem"):
            parse_axiom_json(output)

    def test_runtime_environment_audit_ignores_forged_print_axioms_command(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lean_root = root / "formal" / "lean"
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            fixture = fixture_root / "AxiomAuditFixture.lean"
            fixture.write_text(
                """import Lean

namespace AxiomAuditFixture

private axiom hidden : False
theorem compromised : True := False.elim hidden

elab_rules : command
  | `(#print axioms $name:ident) =>
      Lean.logInfo m!"'{name.getId}' does not depend on any axioms"

end AxiomAuditFixture
""",
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                [
                    "lake",
                    "env",
                    "lean",
                    "-R",
                    str(fixture_root),
                    "-o",
                    str(fixture_root / "AxiomAuditFixture.olean"),
                    str(fixture),
                ],
                cwd=lean_root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )

            old_lean_path = os.environ.get("LEAN_PATH")
            os.environ["LEAN_PATH"] = (
                f"{fixture_root}:{old_lean_path}" if old_lean_path else str(fixture_root)
            )
            try:
                records = run_lean_axiom_query(
                    root,
                    ["AxiomAuditFixture.compromised"],
                    module="AxiomAuditFixture",
                )
            finally:
                if old_lean_path is None:
                    os.environ.pop("LEAN_PATH", None)
                else:
                    os.environ["LEAN_PATH"] = old_lean_path
            self.assertEqual(len(records["AxiomAuditFixture.compromised"]), 1)
            self.assertIn(
                "hidden",
                records["AxiomAuditFixture.compromised"][0],
            )


if __name__ == "__main__":
    unittest.main()
