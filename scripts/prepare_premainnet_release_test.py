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

KNOWN_LOSER_REGRESSIONS = (
    "native::tests::mining_recovery_qualification_tests::duplicate_stored_loser_compact_hints_never_close_gate_for_retained_asic_solution",
    "native::tests::mining_recovery_qualification_tests::unknown_equal_height_and_higher_hints_keep_retained_asic_solution_gated_without_write",
    "native::tests::sync_liveness_tests::stored_loser_classification_preserves_a_newer_unknown_target_and_backfill",
)


class PreparationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = (ROOT / ".github/workflows/release.yml").read_text()
        cls.workflow = preparation.expected_workflow(cls.release)

    def test_checked_in_workflow_matches_all_release_checks(self) -> None:
        self.assertTrue(all(line == line.rstrip() for line in self.workflow.splitlines()))
        self.assertEqual(self.workflow.count("./scripts/check-app-no-ssh-e2e.sh --review-only"), 1)
        self.assertIn("fundedTransactionsExercised:false", self.workflow)
        preparation.verify_preparation(
            self.release,
            (ROOT / ".github/workflows/prepare-premainnet-release.yml").read_text(),
        )

    def test_pr_scope_defers_only_exhaustive_formal_steps(self) -> None:
        security = self.workflow.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        for mode in ("checker", "policy"):
            self.assertEqual(security.count(
                "        if: github.event_name == 'pull_request'\n"
                f"        run: bash scripts/check_formal_core.sh {mode}\n"
            ), 1)
        for name in ("Install Lean toolchain manager", "Formal-core release gate", "Complete formal cryptography release gate"):
            self.assertEqual(security.count(
                f"      - name: {name}\n"
                "        if: github.event_name != 'pull_request'\n"
            ), 1)
        self.assertEqual(security.count("        if: "), 5)
        self.assertIn("PR review defers exhaustive Lean/vector checks", self.workflow)
        # Inverting just the reviewed formal substitutions restores all inherited
        # build-job bytes, including every runtime, parser and artifact check.
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_version_only_successor(jobs)
        adapted = preparation.adapt_pr_formal_scope(inherited)
        for mode, label in (("checker", "checker controls"), ("policy", "policy checks")):
            adapted = adapted.replace(
                f"      - name: Formal-core {label} for PR review\n"
                "        if: github.event_name == 'pull_request'\n"
                f"        run: bash scripts/check_formal_core.sh {mode}\n\n", "", 1)
        adapted = adapted.replace("        if: github.event_name != 'pull_request'\n", "")
        self.assertEqual(adapted, inherited)

    def test_formal_deferral_mutations_reject(self) -> None:
        non_pr = "        if: github.event_name != 'pull_request'\n"
        pr = "        if: github.event_name == 'pull_request'\n"
        for before, after in (
            (non_pr, ""),
            (non_pr, pr),
            (pr, non_pr),
            ("bash scripts/check_formal_core.sh checker", "bash scripts/check_formal_core.sh lean"),
            ("bash scripts/check_formal_core.sh policy", "true"),
            ("bash scripts/check_formal_crypto.sh full", "bash scripts/check_formal_crypto.sh full || true"),
            ("      - name: Formal-core release gate\n", "      - name: Formal-core release gate\n        continue-on-error: true\n"),
        ):
            self.assertIn(before, self.workflow)
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(before, after, 1))
        for name in ("Install Lean toolchain manager", "Formal-core release gate", "Complete formal cryptography release gate"):
            changed_release = self.release.replace(f"      - name: {name}\n", f"      - name: Unreviewed {name}\n", 1)
            with self.subTest(name=name), self.assertRaises(ValueError):
                preparation.expected_workflow(changed_release)

    def test_gate_removal_or_soft_failure_rejects(self) -> None:
        command = "./scripts/security-audit.sh --require-binary"
        self.assertIn(command, self.workflow)
        for mutation in (
            self.workflow.replace(command, "true # " + command, 1),
            self.workflow.replace("  security-gates:\n", "  security-gates:\n    continue-on-error: true\n", 1),
            self.workflow.replace("    needs: preparation-policy\n", "", 1),
            self.workflow.replace("./scripts/check-app-no-ssh-e2e.sh --review-only", "./scripts/check-app-no-ssh-e2e.sh", 1),
            self.workflow.replace("./scripts/check-app-no-ssh-e2e.sh --review-only", "./scripts/check-app-no-ssh-e2e.sh --review-only --skip", 1),
            self.workflow.replace("./scripts/check-app-no-ssh-e2e.sh --review-only", "", 1),
            self.workflow.replace("./scripts/check-app-no-ssh-e2e.sh --review-only", "./scripts/check-app-no-ssh-e2e.sh --review-only || true", 1),
        ):
            with self.subTest(mutation=mutation[:60]), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_transport_and_adapter_regressions_run_unconditionally_before_release_gates(self) -> None:
        policy = self.workflow.split("  preparation-policy:\n", 1)[1].split("\n  transaction-proof-authorization:\n", 1)[0]
        adapter = (
            "      - name: ASIC adapter solution-retention regressions\n"
            "        run: python3 -I -B scripts/test_bitcoin_asic_stratum.py\n"
        )
        self.assertEqual(policy.count(adapter), 1)
        security = self.workflow.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        transport = security.split("      - name: Network transport progress regressions\n", 1)[1].split("\n      - name: ", 1)[0]
        self.assertTrue(transport.startswith("        run: |\n          set -euo pipefail\n"))
        self.assertNotIn("        if:", transport)
        self.assertNotIn("continue-on-error", transport)
        self.assertEqual(len(preparation.TRANSPORT_REGRESSIONS), 8)
        for name in preparation.TRANSPORT_REGRESSIONS:
            command = f"./scripts/run_exact_cargo_lib_test.sh network {name}"
            self.assertEqual(transport.count(command + "\n"), 1)
            self.assertLess(security.index(command), security.index("Formal-core checker controls for PR review"))
        self.assertLess(security.index('toolchain: "1.91.1"'), security.index("Network transport progress regressions"))

    def test_transport_and_adapter_gate_removal_or_soft_failure_rejects(self) -> None:
        commands = ["python3 -I -B scripts/test_bitcoin_asic_stratum.py"] + [
            f"./scripts/run_exact_cargo_lib_test.sh network {name}"
            for name in preparation.TRANSPORT_REGRESSIONS
        ]
        for command in commands:
            for replacement in ("true", command + " || true", "# " + command):
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(command, replacement, 1))
        for name in ("ASIC adapter solution-retention regressions", "Network transport progress regressions"):
            marker = f"      - name: {name}\n"
            for bypass in ("        continue-on-error: true\n", "        if: github.event_name != 'pull_request'\n"):
                with self.subTest(name=name, bypass=bypass), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(marker, marker + bypass, 1))

    def test_transport_gate_reordering_rejects(self) -> None:
        start = self.workflow.index("      - name: Network transport progress regressions\n")
        end = self.workflow.index("      - name: Formal-core checker controls for PR review\n", start)
        step = self.workflow[start:end]
        reordered = self.workflow[:start] + self.workflow[end:]
        marker = "      - name: Formal-crypto isolation release gate\n"
        reordered = reordered.replace(marker, step + marker, 1)
        with self.assertRaises(ValueError):
            preparation.verify_preparation(self.release, reordered)

    def test_known_loser_regressions_are_exact_unconditional_and_ordered(self) -> None:
        self.assertEqual(preparation.KNOWN_LOSER_REGRESSIONS, KNOWN_LOSER_REGRESSIONS)
        security = self.workflow.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        marker = "      - name: Known-loser announcement admission regressions\n"
        self.assertEqual(security.count(marker), 1)
        step = security.split(marker, 1)[1].split("\n      - name: ", 1)[0]
        expected = "        run: |\n          set -euo pipefail\n" + "".join(
            f"          ./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features\n"
            for name in KNOWN_LOSER_REGRESSIONS
        )
        self.assertEqual(step, expected)
        self.assertLess(security.index('toolchain: "1.91.1"'), security.index("Network transport progress regressions"))
        self.assertLess(security.index("Network transport progress regressions"), security.index(marker))
        self.assertLess(security.index(marker), security.index("Formal-core checker controls for PR review"))

    def test_known_loser_gate_removal_rename_or_soft_failure_rejects(self) -> None:
        marker = "      - name: Known-loser announcement admission regressions\n"
        for name in KNOWN_LOSER_REGRESSIONS:
            command = f"./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features"
            for replacement in (
                "", "true", "# " + command, command + " || true",
                command.replace(name, name + "_renamed"),
                command.replace(" --no-default-features", ""),
                command.replace("run_exact_cargo_lib_test.sh", "unreviewed_test_runner.sh"),
            ):
                with self.subTest(name=name, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(command, replacement, 1))
        for replacement in ("", marker.replace("regressions", "renamed regressions")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(marker, replacement, 1))

    def test_known_loser_gate_event_guards_or_reordering_rejects(self) -> None:
        marker = "      - name: Known-loser announcement admission regressions\n"
        for bypass in (
            "        continue-on-error: true\n",
            "        if: github.event_name == 'pull_request'\n",
            "        if: github.event_name != 'pull_request'\n",
        ):
            with self.subTest(bypass=bypass), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(marker, marker + bypass, 1))
        start = self.workflow.index(marker)
        end = self.workflow.index("      - name: Formal-core checker controls for PR review\n", start)
        step = self.workflow[start:end]
        without = self.workflow[:start] + self.workflow[end:]
        for before in (
            "      - name: Install build dependencies\n",
            "      - name: Network transport progress regressions\n",
            "      - name: Formal-crypto isolation release gate\n",
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, without.replace(before, step + before, 1))

    def test_known_loser_generator_rejects_changed_security_step_order(self) -> None:
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_transport_regressions(
            preparation.adapt_pr_formal_scope(preparation.adapt_version_only_successor(jobs))
        )
        prefix, security = inherited.split("  security-gates:\n", 1)
        security, suffix = security.split("\n  app-no-ssh-e2e:\n", 1)
        for anchor in (
            "      - name: Network transport progress regressions\n",
            "      - name: Formal-core checker controls for PR review\n",
            '          toolchain: "1.91.1"\n',
        ):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                preparation.adapt_known_loser_regressions(
                    prefix + "  security-gates:\n" + security.replace(anchor, "", 1)
                    + "\n  app-no-ssh-e2e:\n" + suffix
                )
        start = inherited.index("      - name: Network transport progress regressions\n")
        end = inherited.index("      - name: Formal-core checker controls for PR review\n", start)
        step = inherited[start:end]
        without = inherited[:start] + inherited[end:]
        for before in ("      - name: Install build dependencies\n", "      - name: Formal-crypto isolation release gate\n"):
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.adapt_known_loser_regressions(without.replace(before, step + before, 1))

    def test_full_formal_gate_keeps_each_exact_known_loser_selector(self) -> None:
        formal = (ROOT / "scripts/check_formal_core.sh").read_text()
        for name in KNOWN_LOSER_REGRESSIONS:
            command = f"run_exact_lib_test \\\n  hegemon-node \\\n  {name} \\\n  --no-default-features\n"
            with self.subTest(name=name):
                self.assertEqual(formal.count(command), 1)
                self.assertEqual(formal.count(name), 1)

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

    def test_historical_native_identity_and_fetch_are_preserved(self) -> None:
        fetch = "git fetch --no-tags --depth=1 origin 4810888722e8c9a2440e31b139f8cb10b060acee"
        verify = "./scripts/verify_native_backend_review_package.sh --historical-release"
        self.assertEqual(self.workflow.count(fetch), 1)
        self.assertEqual(self.workflow.count(verify), 1)
        self.assertLess(self.workflow.index(fetch), self.workflow.index(verify))
        for before, after in (
            (fetch, "true"),
            (fetch, fetch.replace("--depth=1", "--unshallow")),
            (verify, verify.replace(" --historical-release", "")),
            (verify, verify + " || true"),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(before, after, 1))

    def test_new_release_job_requires_review(self) -> None:
        with self.assertRaises(ValueError):
            preparation.expected_workflow(self.release.replace(
                "\n  create-release:\n", "\n  unreviewed-gate:\n    runs-on: ubuntu-latest\n\n  create-release:\n", 1,
            ))


if __name__ == "__main__":
    unittest.main()
