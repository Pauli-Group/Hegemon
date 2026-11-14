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


SYNC_IMPORT_REGRESSIONS = (
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_returns_without_waiting_for_canonical_state",
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_wrong_chain_rejects_before_lookup_or_snapshot",
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_poisoned_storage_rejects_before_lookup_or_snapshot",
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_malformed_metadata_rejects_without_snapshot",
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_key_alias_rejects_without_snapshot",
    "native::node_impl::announcement_snapshot_precheck_tests::stored_announcement_work_hash_alias_rejects_without_snapshot",
    "native::node_impl::announcement_snapshot_precheck_tests::concurrent_stored_announcement_insertion_keeps_post_snapshot_guard",
    "native::node_impl::announcement_snapshot_precheck_tests::unknown_and_competing_announcements_retain_validation_and_durable_fork_choice",
    "native::node_impl::announcement_snapshot_precheck_tests::unknown_announcement_invalid_state_root_is_not_admitted",
    "native::node_impl::announcement_snapshot_precheck_tests::admitted_sync_request_token_is_the_exact_reserved_request",
    "native::node_impl::announcement_snapshot_precheck_tests::local_capacity_wait_preserves_exact_request_and_import_ownership",
    "native::node_impl::announcement_snapshot_precheck_tests::local_capacity_wait_retries_after_existing_pacing_window_with_exact_context",
    "native::node_impl::announcement_snapshot_precheck_tests::local_capacity_wait_retains_normal_freshness_boundary_and_target_expiry",
    "native::node_impl::announcement_snapshot_precheck_tests::stale_sync_send_token_cannot_mutate_a_replaced_request",
    "native::service::sync_control_backpressure_tests::sync_control_saturated_real_sender_blocks_old_send_but_not_body_control",
    "native::service::sync_control_backpressure_tests::sync_control_full_target_scheduler_preserves_request_context_and_target",
    "native::service::sync_control_backpressure_tests::sync_control_full_direct_request_preserves_target_without_peer_penalty",
    "native::service::sync_control_backpressure_tests::sync_control_closed_direct_request_preserves_target_without_peer_penalty",
    "native::service::sync_control_backpressure_tests::sync_control_full_channel_drains_and_readmits_the_same_recovery_request",
    "native::service::sync_control_backpressure_tests::sync_control_held_announce_encoder_keeps_runtime_ticks_and_completions_responsive",
    "native::service::sync_control_backpressure_tests::sync_control_prepared_announce_preserves_eligibility_and_rechecks_tip_without_blocking",
    "native::service::sync_control_backpressure_tests::sync_control_failed_announce_preparation_releases_slot_for_retry",
    "native::service::sync_body_backpressure::tests::body_local_full_preserves_range_origin_retry_age_suffix_and_other_reservations",
    "native::service::sync_body_backpressure::tests::body_local_full_stale_callback_cannot_remove_newer_locator_with_same_hash",
    "native::service::sync_body_backpressure::tests::body_local_full_cannot_abort_progress_or_another_reservation_epoch",
    "native::service::sync_body_backpressure::tests::body_local_full_eventually_readmits_after_global_item_and_byte_capacity_frees",
    "native::service::sync_body_backpressure::tests::body_local_full_moves_existing_slot_at_full_peer_and_global_queue_limits",
    "native::service::sync_body_backpressure::tests::body_local_full_repeated_deferral_cannot_extend_absolute_lifetime",
    "native::service::sync_body_backpressure::tests::body_local_full_rollback_leaves_normal_idle_retry_and_expiry_unchanged",
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
        checked_in = (ROOT / ".github/workflows/prepare-premainnet-release.yml").read_text()
        if (ROOT / "config/ntime-rolling-v0115.json").is_file():
            spec = importlib.util.spec_from_file_location("v0115_current_preparation",
                    ROOT / "scripts/prepare_v0115_release.py")
            current = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(current)
            current.verify_preparation(self.release, checked_in)
        else:
            preparation.verify_preparation(
                self.release, checked_in, v0113=True,
                combined=(ROOT / "config/combined-upgrade-candidate-20261108.json").is_file(),
            )

    def test_preparation_arm_runner_override_preserves_tag_workflow(self) -> None:
        old = "  build-macos-arm:\n    runs-on: macos-14\n"
        new = "  build-macos-arm:\n    runs-on: macos-15\n"
        self.assertEqual(self.release.count(old), 1)
        self.assertEqual(self.workflow.count(new), 1)
        self.assertNotIn(old, self.workflow)
        self.assertEqual(preparation.adapt_preparation_arm_runner(self.release),
                         self.release.replace(old, new, 1))
        self.assertEqual((ROOT / ".github/workflows/release.yml").read_text(), self.release)
        for runner in ("macos-14", "self-hosted", "macos-15-intel"):
            with self.subTest(runner=runner), self.assertRaises(ValueError):
                preparation.verify_preparation(
                    self.release, self.workflow.replace(new, new.replace("macos-15", runner), 1)
                )

    def test_preparation_arm_runner_anchor_is_exact_and_unique(self) -> None:
        old = "  build-macos-arm:\n    runs-on: macos-14\n"
        for changed in (
            self.release.replace(old, "", 1),
            self.release + old,
            self.release.replace(old, old.replace("macos-14", "macos-15"), 1),
            self.release.replace(old, old.replace("macos-14", "self-hosted"), 1),
        ):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                preparation.adapt_preparation_arm_runner(changed)
        with self.assertRaises(ValueError):
            preparation.expected_workflow(
                self.release.replace(old, old.replace("macos-14", "macos-15"), 1)
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

    def test_sync_import_regressions_are_exact_unconditional_and_additive(self) -> None:
        self.assertEqual(len(SYNC_IMPORT_REGRESSIONS), 29)
        self.assertEqual(len(set(SYNC_IMPORT_REGRESSIONS)), 29)
        self.assertEqual(preparation.SYNC_IMPORT_REGRESSIONS, SYNC_IMPORT_REGRESSIONS)
        marker = "      - name: Native sync and import liveness regressions\n"
        security = self.workflow.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        expected = (
            marker + "        run: |\n          set -euo pipefail\n"
            + "".join(
                f"          ./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features\n"
                for name in SYNC_IMPORT_REGRESSIONS
            ) + "\n"
        )
        self.assertEqual(security.count(expected), 1)
        self.assertLess(security.index("Known-loser announcement admission regressions"), security.index(marker))
        self.assertLess(security.index(marker), security.index("Formal-core checker controls for PR review"))
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_known_loser_regressions(
            preparation.adapt_transport_regressions(
                preparation.adapt_pr_formal_scope(preparation.adapt_version_only_successor(jobs))
            )
        )
        adapted = preparation.adapt_sync_import_regressions(inherited)
        self.assertEqual(adapted.replace(expected, "", 1), inherited)

    def test_sync_import_each_exact_command_removal_rename_ignore_or_soft_failure_rejects(self) -> None:
        commands = [
            f"./scripts/run_exact_cargo_lib_test.sh hegemon-node {name} --no-default-features"
            for name in SYNC_IMPORT_REGRESSIONS
        ]
        for command, name in zip(commands, SYNC_IMPORT_REGRESSIONS):
            for replacement in (
                "", "true", "# " + command, command + " || true",
                command.replace(name, name + "_renamed"),
                command.replace(" --no-default-features", ""),
                command.replace("run_exact_cargo_lib_test.sh", "unreviewed_test_runner.sh"),
                command + " -- --ignored",
                "if false; then " + command + "; fi",
            ):
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(command, replacement, 1))
        for left, right in zip(commands, commands[1:]):
            before = "          " + left + "\n          " + right + "\n"
            after = "          " + right + "\n          " + left + "\n"
            self.assertEqual(self.workflow.count(before), 1)
            with self.subTest(reordered=left), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(before, after, 1))

    def test_sync_import_step_removal_rename_event_guard_soft_failure_or_reordering_rejects(self) -> None:
        marker = "      - name: Native sync and import liveness regressions\n"
        start = self.workflow.index(marker)
        end = self.workflow.index("      - name: Formal-core checker controls for PR review\n", start)
        step = self.workflow[start:end]
        without = self.workflow[:start] + self.workflow[end:]
        mutations = [without, self.workflow.replace(marker, marker.replace("liveness", "renamed"), 1)]
        for bypass in (
            "        continue-on-error: true\n",
            "        if: github.event_name == 'pull_request'\n",
            "        if: github.event_name != 'pull_request'\n",
            "        if: false\n",
        ):
            mutations.append(self.workflow.replace(marker, marker + bypass, 1))
        mutations.append(self.workflow.replace(step, step.replace("set -euo pipefail", "set +e", 1), 1))
        for before in (
            "      - name: Network transport progress regressions\n",
            "      - name: Known-loser announcement admission regressions\n",
            "      - name: Formal-crypto isolation release gate\n",
        ):
            mutations.append(without.replace(before, step + before, 1))
        for mutation in mutations:
            with self.subTest(mutation=mutation[start:start + 120]), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_sync_import_generator_rejects_missing_or_reordered_security_anchors(self) -> None:
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_known_loser_regressions(
            preparation.adapt_transport_regressions(
                preparation.adapt_pr_formal_scope(preparation.adapt_version_only_successor(jobs))
            )
        )
        prefix, security = inherited.split("  security-gates:\n", 1)
        security, suffix = security.split("\n  app-no-ssh-e2e:\n", 1)
        for anchor in (
            '          toolchain: "1.91.1"\n',
            "      - name: Network transport progress regressions\n",
            "      - name: Known-loser announcement admission regressions\n",
            "      - name: Formal-core checker controls for PR review\n",
        ):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                preparation.adapt_sync_import_regressions(
                    prefix + "  security-gates:\n" + security.replace(anchor, "", 1)
                    + "\n  app-no-ssh-e2e:\n" + suffix
                )
        marker = "      - name: Known-loser announcement admission regressions\n"
        start = inherited.index(marker)
        end = inherited.index("      - name: Formal-core checker controls for PR review\n", start)
        step = inherited[start:end]
        without = inherited[:start] + inherited[end:]
        for before in (
            "      - name: Network transport progress regressions\n",
            "      - name: Formal-crypto isolation release gate\n",
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                preparation.adapt_sync_import_regressions(without.replace(before, step + before, 1))

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

    def test_sync_import_focused_policy_suites_are_required_once_and_before_builds(self) -> None:
        policy = self.workflow.split("  preparation-policy:\n", 1)[1].split("\n  transaction-proof-authorization:\n", 1)[0]
        for name in (
            "scripts/test_check_v011_sync_import_successor.py",
            "scripts/test_check_sync_import_formatting.py",
        ):
            with self.subTest(name=name):
                self.assertEqual(self.workflow.count(name), 1)
                self.assertIn("        run: /usr/bin/python3 -I -B " + name + "\n", policy)
                self.assertLess(policy.index("ASIC adapter solution-retention regressions"), policy.index(name))

    def test_sync_import_focused_policy_removal_event_guards_and_bypasses_reject(self) -> None:
        for label, filename in (
            ("Sync and import successor policy rejection controls", "test_check_v011_sync_import_successor.py"),
            ("Sync and import formatting policy rejection controls", "test_check_sync_import_formatting.py"),
        ):
            step = f"      - name: {label}\n        run: /usr/bin/python3 -I -B scripts/{filename}\n"
            self.assertEqual(self.workflow.count(step), 1)
            for replacement in (
                "", step.replace(filename, "unreviewed.py"),
                step.replace("        run:", "        if: github.event_name == 'pull_request'\n        run:"),
                step.replace("        run:", "        if: github.event_name != 'pull_request'\n        run:"),
                step.replace("        run:", "        continue-on-error: true\n        run:"),
                step.rstrip("\n") + " || true\n",
            ):
                with self.subTest(filename=filename, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(step, replacement, 1))
            removed = self.workflow.replace(step, "", 1)
            moved = removed.replace("      - name: Network transport progress regressions\n", step + "      - name: Network transport progress regressions\n", 1)
            with self.subTest(moved=filename), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, moved)

    def test_sync_import_binding_routes_preserve_other_gates_and_add_three_formatters(self) -> None:
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_version_only_successor(jobs)
        adapted = preparation.adapt_sync_import_release_binding(inherited)
        formatting = (
            "      - name: Sync and import successor formatting gates\n"
            "        run: |\n          set -euo pipefail\n"
            + "".join(
                f"          python3 -I -B scripts/check_sync_import_formatting.py --manifest {name}\n"
                for name in ("workspace", "htlc", "proof-backend")
            ) + "\n"
        )
        self.assertEqual(adapted.count(formatting), 1)
        restored = adapted.replace(formatting, "", 1).replace(
            "scripts/check_v011_sync_import_successor.py --require-authorized",
            "scripts/check_v011_release_successor.py --require-authorized",
        ).replace("          components: rust-src, rustfmt\n", "          components: rust-src\n", 1).replace(
            "scripts/test_sync_import_successor_scope.py --source-root . --predecessor-root target/v011-predecessor",
            "scripts/tests/v011_current_successor/test_successor_scope.py --checker scripts/check_v011_release_successor.py",
            1,
        )
        self.assertEqual(restored, inherited)
        self.assertEqual(adapted.count("--checker scripts/check_v011_release_successor.py"), 1)
        self.assertEqual(adapted.count("--require-final-artifact"), 4)
        security = adapted.split("  security-gates:\n", 1)[1].split("\n  app-no-ssh-e2e:\n", 1)[0]
        self.assertEqual(security.count("          components: rust-src, rustfmt\n"), 1)
        self.assertLess(security.index('toolchain: "1.91.1"'), security.index(formatting))
        self.assertLess(security.index(formatting), security.index("Install cargo-audit"))

    def test_sync_import_each_gate_route_or_final_artifact_bypass_rejects(self) -> None:
        gates = [line for line in self.workflow.splitlines(keepends=True)
                 if "scripts/check_v011_sync_import_successor.py --require-authorized" in line]
        self.assertEqual(len(gates), 5)
        for line in gates:
            for replacement in (
                "",
                line.replace("check_v011_sync_import_successor.py", "check_v011_release_successor.py"),
                line.replace("--require-authorized", ""),
                line.replace("--predecessor-root target/v011-predecessor", "--predecessor-root untrusted"),
                line.rstrip("\n") + " || true\n",
                "        if: github.event_name == 'pull_request'\n" + line,
                "        continue-on-error: true\n" + line,
            ):
                with self.subTest(line=line, replacement=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(line, replacement, 1))
            if "--require-final-artifact" in line:
                with self.subTest(line=line), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(line, line.replace(" --require-final-artifact", ""), 1))

    def test_sync_import_formatting_routes_and_unconditional_order_cannot_be_bypassed(self) -> None:
        marker = "      - name: Sync and import successor formatting gates\n"
        start = self.workflow.index(marker)
        end = self.workflow.index("      - name: Install cargo-audit\n", start)
        step = self.workflow[start:end]
        without = self.workflow[:start] + self.workflow[end:]
        mutations = [without, self.workflow.replace(marker, marker.replace("gates", "renamed gates"), 1)]
        for components in ("rust-src", "rustfmt", "rust-src, clippy"):
            mutations.append(self.workflow.replace("components: rust-src, rustfmt", "components: " + components, 1))
        for name in ("workspace", "htlc", "proof-backend"):
            command = f"python3 -I -B scripts/check_sync_import_formatting.py --manifest {name}"
            for replacement in (
                "true", "# " + command, command + " || true",
                command.replace("check_sync_import_formatting.py", "check_qualified_formatting.py"),
                command.replace(name, "unreviewed"),
            ):
                mutations.append(self.workflow.replace(command, replacement, 1))
        for bypass in (
            "        if: false\n", "        if: github.event_name == 'pull_request'\n",
            "        if: github.event_name != 'pull_request'\n", "        continue-on-error: true\n",
        ):
            mutations.append(self.workflow.replace(marker, marker + bypass, 1))
        mutations.append(without.replace("      - name: Network transport progress regressions\n", step + "      - name: Network transport progress regressions\n", 1))
        for mutation in mutations:
            with self.subTest(mutation=mutation[start:start + 120]), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, mutation)

    def test_sync_import_binding_generator_requires_all_five_old_calls(self) -> None:
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_version_only_successor(jobs)
        old = "scripts/check_v011_release_successor.py --require-authorized"
        for mutated in (inherited.replace(old, "true", 1), inherited + old):
            with self.subTest(mutated=mutated[-100:]), self.assertRaises(ValueError):
                preparation.adapt_sync_import_release_binding(mutated)

    def test_sync_import_scope_route_is_exact_and_cannot_skip_inherited_controls(self) -> None:
        command = (
            "python3 -I -B scripts/test_sync_import_successor_scope.py --source-root . "
            "--predecessor-root target/v011-predecessor"
        )
        step = "      - name: Current successor scope rejection controls\n        run: " + command + "\n\n"
        self.assertEqual(self.workflow.count(step), 1)
        self.assertNotIn("scripts/tests/v011_current_successor/test_successor_scope.py", self.workflow)
        self.assertEqual(self.workflow.count(
            "scripts/tests/v011_current_successor/test_artifact_gate_identity.py --checker scripts/check_v011_release_successor.py"
        ), 1)
        for replacement in (
            "true", command + " || true",
            command.replace("scripts/test_sync_import_successor_scope.py", "scripts/tests/v011_current_successor/test_successor_scope.py"),
            command.replace(" --source-root .", ""),
            command.replace("--source-root .", "--source-root untrusted"),
            command.replace(" --predecessor-root target/v011-predecessor", ""),
            command.replace("--predecessor-root target/v011-predecessor", "--predecessor-root untrusted"),
            command + " --checker scripts/check_v011_release_successor.py",
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(command, replacement, 1))
        for bypass in (
            "        if: false\n", "        if: github.event_name == 'pull_request'\n",
            "        if: github.event_name != 'pull_request'\n", "        continue-on-error: true\n",
        ):
            changed = step.replace("        run:", bypass + "        run:", 1)
            with self.subTest(bypass=bypass), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(step, changed, 1))
        for changed in (
            self.workflow.replace(step, "", 1),
            self.workflow.replace(step, step + step, 1),
            self.workflow.replace(step, "", 1).replace(
                "      - name: Restore authenticated unchanged v0.11 predecessor\n",
                step + "      - name: Restore authenticated unchanged v0.11 predecessor\n", 1,
            ),
        ):
            with self.subTest(changed=changed[:80]), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, changed)

    def test_sync_import_scope_adapter_requires_exactly_one_historical_invocation(self) -> None:
        jobs = self.release.split("\njobs:\n", 1)[1].split("\n  create-release:\n", 1)[0]
        inherited = preparation.adapt_version_only_successor(jobs)
        old = (
            "scripts/tests/v011_current_successor/test_successor_scope.py "
            "--checker scripts/check_v011_release_successor.py"
        )
        self.assertEqual(inherited.count(old), 1)
        for changed in (inherited.replace(old, "true", 1), inherited + old):
            with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                preparation.adapt_sync_import_release_binding(changed)

    def test_only_explicit_successor_adapter_changes_authorization(self) -> None:
        self.assertEqual(self.workflow.count("scripts/materialize_v011_predecessor.py"), 5)
        self.assertEqual(self.workflow.count("scripts/check_v011_release_successor.py"), 1)
        self.assertEqual(self.workflow.count("scripts/check_v011_sync_import_successor.py --require-authorized"), 5)
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
        authorization = source_job.index("scripts/check_v011_sync_import_successor.py --require-authorized")
        for suite in (
            "scripts/test_sync_import_successor_scope.py",
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
