#!/usr/bin/env python3
"""Regression controls for the nonpublishing release-preparation lane."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "preparation", ROOT / "scripts/prepare_premainnet_release.py"
)
assert SPEC and SPEC.loader
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)


class PreparationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = (ROOT / ".github/workflows/release.yml").read_text()
        cls.workflow = preparation.expected_workflow(cls.release)

    def test_checked_in_workflow_matches_all_release_checks(self) -> None:
        self.assertTrue(all(line == line.rstrip() for line in self.workflow.splitlines()))
        preparation.verify_preparation(
            self.release,
            (ROOT / ".github/workflows/prepare-premainnet-release.yml").read_text(),
        )

    def test_gate_removal_or_soft_failure_rejects(self) -> None:
        command = "./scripts/security-audit.sh --require-binary"
        self.assertIn(command, self.workflow)
        for mutation in (
            self.workflow.replace(command, "true # " + command, 1),
            self.workflow.replace("  security-gates:\n", "  security-gates:\n    continue-on-error: true\n", 1),
            self.workflow.replace("    needs: preparation-policy\n", "", 1),
        ):
            with self.subTest(mutation=mutation[:60]), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_publication_or_write_permissions_reject(self) -> None:
        self.assertNotIn("softprops/action-gh-release", self.workflow)
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("\n  push:", self.workflow)
        for mutation in (
            self.workflow.replace("contents: read", "contents: write", 1),
            self.workflow + "\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh release create v0.11\n",
        ):
            with self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_successor_checks_do_not_remove_original_authorization(self) -> None:
        self.assertEqual(self.workflow.count("scripts/materialize_v011_predecessor.py"), 5)
        self.assertEqual(self.workflow.count("scripts/check_v011_release_successor.py"), 5)
        self.assertEqual(self.workflow.count("--require-final-artifact"), 4)
        self.assertEqual(self.workflow.count("scripts/check_private_spend_launch_authorization.py"), 5)
        self.assertIn("scripts/test_premainnet_launcher.py", self.workflow)
        for mutation in (
            self.workflow.replace("scripts/check_private_spend_launch_authorization.py", "scripts/removed_original_gate.py", 1),
            self.workflow.replace(" --require-final-artifact", "", 1),
            self.workflow.replace(" --require-authorized", "", 1),
            self.workflow.replace("scripts/materialize_v011_predecessor.py", "scripts/unreviewed.py", 1),
            self.workflow.replace("--predecessor-root target/v011-predecessor", "--predecessor-root untrusted", 1),
        ):
            with self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_new_release_job_requires_review(self) -> None:
        with self.assertRaises(ValueError):
            preparation.expected_workflow(self.release.replace(
                "\n  create-release:\n", "\n  unreviewed-gate:\n    runs-on: ubuntu-latest\n\n  create-release:\n", 1,
            ))


if __name__ == "__main__":
    unittest.main()
