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

    def test_only_explicit_successor_adapter_changes_authorization(self) -> None:
        self.assertEqual(self.workflow.count("scripts/materialize_v011_predecessor.py"), 5)
        self.assertEqual(self.workflow.count("scripts/check_v011_release_successor.py"), 7)
        self.assertEqual(self.workflow.count("--require-final-artifact"), 4)
        self.assertNotIn("scripts/check_private_spend_launch_authorization.py", self.workflow)
        self.assertIn("scripts/test_premainnet_launcher.py", self.workflow)
        for mutation in (
            self.workflow.replace(" --require-final-artifact", "", 1),
            self.workflow.replace(" --require-authorized", "", 1),
            self.workflow.replace("scripts/materialize_v011_predecessor.py", "scripts/unreviewed.py", 1),
            self.workflow.replace("--predecessor-root target/v011-predecessor", "--predecessor-root untrusted", 1),
        ):
            with self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_all_current_successor_controls_are_required_after_restore(self) -> None:
        source_job = self.workflow.split("  transaction-proof-authorization:\n", 1)[1].split("\n  security-gates:\n", 1)[0]
        restore = source_job.index("scripts/materialize_v011_predecessor.py")
        authorization = source_job.index("scripts/check_v011_release_successor.py --require-authorized")
        for suite in (
            "scripts/tests/v011_current_successor/test_successor_scope.py",
            "scripts/tests/v011_current_successor/test_successor_consumer.py",
            "scripts/tests/v011_current_successor/test_security_audit_scope.py",
            "scripts/tests/v011_current_successor/test_artifact_gate_identity.py",
            "scripts/test_check_v011_current_binary_proofs.py",
        ):
            with self.subTest(suite=suite):
                self.assertEqual(self.workflow.count(suite), 1)
                self.assertLess(restore, source_job.index(suite))
                self.assertLess(source_job.index(suite), authorization)
                with self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(suite, "scripts/unreviewed.py", 1))
        self.assertIn("--launcher-helper scripts/check_release_launcher_policy.py", source_job)

    def test_new_release_job_requires_review(self) -> None:
        with self.assertRaises(ValueError):
            preparation.expected_workflow(self.release.replace(
                "\n  create-release:\n", "\n  unreviewed-gate:\n    runs-on: ubuntu-latest\n\n  create-release:\n", 1,
            ))


if __name__ == "__main__":
    unittest.main()
