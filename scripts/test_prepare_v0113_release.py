#!/usr/bin/env python3
"""Reject v0.11.3 preparation routing drift without running builds or nodes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "v0113_preparation", ROOT / "scripts/prepare_premainnet_release.py")
assert SPEC and SPEC.loader
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)


class V0113PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (ROOT / ".github/workflows/release.yml").read_text()
        cls.historical = preparation.expected_workflow(cls.release)
        cls.workflow = preparation.expected_workflow(cls.release, v0113=True)

    def test_checked_in_current_lane_is_exact(self):
        preparation.verify_preparation(self.release, self.workflow, v0113=True)
        self.assertEqual(self.workflow,
                         (ROOT / ".github/workflows/prepare-premainnet-release.yml").read_text())
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("softprops/action-gh-release", self.workflow)
        self.assertEqual((ROOT / ".github/workflows/release.yml").read_text(), self.release)
        with self.assertRaises(ValueError):
            preparation.verify_preparation(self.release, self.historical, v0113=True)

    def test_only_explicit_additive_substitutions_change_inherited_lane(self):
        result = self.workflow.replace(
            "scripts/check_v0113_release_successor.py --require-authorized",
            "scripts/check_v011_sync_import_successor.py --require-authorized")
        result = result.replace(
            "scripts/test_check_v0113_release_successor.py --source-root . "
            "--predecessor-root target/v011-predecessor",
            "scripts/test_sync_import_successor_scope.py --source-root . "
            "--predecessor-root target/v011-predecessor", 1)
        result = result.replace(
            "      - name: v0.11.3 successor policy rejection controls\n"
            "        run: /usr/bin/python3 -I -B scripts/test_check_v0113_release_successor.py\n"
            "      - name: v0.11.3 preparation routing regression controls\n"
            "        run: /usr/bin/python3 -I -B scripts/test_prepare_v0113_release.py\n",
            "      - name: Sync and import successor policy rejection controls\n"
            "        run: /usr/bin/python3 -I -B scripts/test_check_v011_sync_import_successor.py\n", 1)
        result = result.replace("scripts/check_v0113_formatting.py --manifest ",
                                "scripts/check_sync_import_formatting.py --manifest ")
        result = result.replace("scripts/test_check_v0113_formatting.py",
                                "scripts/test_check_sync_import_formatting.py", 1)
        result = result.replace("v0.11.3 formatting policy rejection controls",
                                "Sync and import formatting policy rejection controls", 1)
        result = result.replace("v0.11.3 successor formatting gates",
                                "Sync and import successor formatting gates", 1)
        marker = "      - name: v0.11.3 public HTTP admission and catalog regressions\n"
        start = result.index(marker)
        end = result.index("      - name: Formal-core checker controls for PR review\n", start)
        result = result[:start] + result[end:]
        self.assertEqual(result, self.historical)

    def test_exact_source_and_four_final_artifact_gates(self):
        gate = "scripts/check_v0113_release_successor.py --require-authorized"
        self.assertEqual(self.workflow.count(gate), 5)
        self.assertEqual(self.workflow.count("--require-final-artifact"), 4)
        self.assertEqual(self.workflow.count("scripts/materialize_v011_predecessor.py"), 5)
        self.assertEqual(self.workflow.count("scripts/test_check_v0113_release_successor.py"), 2)
        source = self.workflow.split("  transaction-proof-authorization:\n", 1)[1].split(
            "\n  security-gates:\n", 1)[0]
        self.assertLess(source.index("scripts/materialize_v011_predecessor.py"),
                        source.index("scripts/test_check_v0113_release_successor.py"))
        self.assertLess(source.index("scripts/test_check_v0113_release_successor.py"), source.index(gate))
        for job in ("build-linux", "build-macos-arm", "build-macos-intel", "build-windows"):
            block = re.split(r"\n  [A-Za-z0-9_-]+:\n",
                             self.workflow.split(f"  {job}:\n", 1)[1], maxsplit=1)[0]
            self.assertIn(gate, block)
            self.assertIn("--require-final-artifact", block)
        self.assertIn("--checker scripts/check_v011_release_successor.py", source)
        self.assertIn("scripts/tests/v011_current_successor/test_successor_consumer.py", source)

    def test_all_http_and_catalog_tests_are_exact_unconditional_selectors(self):
        expected = []
        for module in ("public_rpc_http_tests", "public_rpc_formal_tests"):
            text = (ROOT / f"node/src/native/{module}.rs").read_text()
            names = re.findall(r"#\[(?:tokio::)?test(?:\([^\n]*\))?\]\s*"
                               r"(?:async )?fn ([A-Za-z0-9_]+)\(", text)
            expected.extend(f"native::{module}::{name}" for name in names)
        self.assertEqual(tuple(expected), preparation.PUBLIC_RPC_REGRESSIONS)
        self.assertEqual(len(expected), 17)
        security = self.workflow.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        marker = "      - name: v0.11.3 public HTTP admission and catalog regressions\n"
        step = security.split(marker, 1)[1].split("\n      - name: ", 1)[0]
        self.assertTrue(step.startswith("        run: |\n          set -euo pipefail\n"))
        self.assertNotIn("if:", step)
        self.assertNotIn("continue-on-error", step)
        for name in expected:
            command = f"./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features"
            self.assertEqual(step.count(command + "\n"), 1)
        self.assertLess(security.index("Native sync and import liveness regressions"), security.index(marker))
        self.assertLess(security.index(marker), security.index("Formal-core checker controls for PR review"))

    def test_omissions_soft_failures_and_historical_route_substitutions_reject(self):
        commands = [
            "scripts/check_v0113_release_successor.py --require-authorized",
            "scripts/test_check_v0113_release_successor.py",
            "scripts/test_prepare_v0113_release.py",
            "scripts/test_check_v0113_formatting.py",
            "scripts/check_v0113_formatting.py --manifest workspace",
            "scripts/check_v0113_formatting.py --manifest htlc",
            "scripts/check_v0113_formatting.py --manifest proof-backend",
        ] + [f"./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features"
             for name in preparation.PUBLIC_RPC_REGRESSIONS]
        for command in commands:
            for replacement in ("true", command + " || true", "# " + command):
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release,
                        self.workflow.replace(command, replacement, 1), v0113=True)
        for before, after in (
            ("--require-final-artifact", ""),
            ("--predecessor-root target/v011-predecessor", "--predecessor-root untrusted"),
            ("check_v0113_release_successor.py --require-authorized", "check_v011_sync_import_successor.py --require-authorized"),
            ("      - name: v0.11.3 public HTTP admission and catalog regressions\n",
             "      - name: v0.11.3 public HTTP admission and catalog regressions\n        if: github.event_name != 'pull_request'\n"),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release,
                    self.workflow.replace(before, after, 1), v0113=True)

    def test_changed_adaptation_anchors_reject(self):
        for anchor in (
            "scripts/check_v011_sync_import_successor.py --require-authorized",
            "scripts/test_sync_import_successor_scope.py --source-root . --predecessor-root target/v011-predecessor",
            "      - name: Sync and import successor policy rejection controls\n",
            "scripts/check_sync_import_formatting.py --manifest ",
            "      - name: Native sync and import liveness regressions\n",
            "      - name: Formal-core checker controls for PR review\n",
        ):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                preparation.adapt_v0113_successor(self.historical.replace(anchor, "", 1))


if __name__ == "__main__":
    unittest.main()
