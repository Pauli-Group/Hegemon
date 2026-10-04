from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "autoresearch.py"
SPEC = importlib.util.spec_from_file_location("hegemon_proof_autoresearch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUTORESEARCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTORESEARCH)

ROOT = MODULE_PATH.parents[3]
CAMPAIGN_PATH = MODULE_PATH.parent / "campaign.json"
CANDIDATE_PATH = MODULE_PATH.parent / "candidates" / "baseline-all-private-r3.json"
RUNNER_PATH = MODULE_PATH.parent / "run-upstream-candidate.sh"
BASELINE_MEASUREMENT = (
    ROOT
    / "prototypes"
    / "standalone-shake256-binius"
    / "all-private-patch"
    / "full-pay1x2-measurement-2026-08-19.json"
)
HARNESS_MEASUREMENT = (
    ROOT
    / "prototypes"
    / "standalone-shake256-binius"
    / "pay1x2-backend"
    / "measurements"
    / "rate3-harness-2026-08-19.json"
)
BACKEND_SWEEP = (
    ROOT
    / "prototypes"
    / "standalone-shake256-binius"
    / "pay1x2-backend"
    / "measurements"
    / "full-pay1x2-rate-sweep-2026-08-19.json"
)


class AutoresearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.campaign = AUTORESEARCH.load_campaign(CAMPAIGN_PATH)
        self.candidate = AUTORESEARCH.load_candidate(CANDIDATE_PATH, self.campaign)
        self.baseline_payload = AUTORESEARCH._read_json(BASELINE_MEASUREMENT)

    def test_frozen_baseline_is_eligible_only_in_prototype_lane(self) -> None:
        normalized = AUTORESEARCH.normalize_measurement(self.baseline_payload)
        evaluation = AUTORESEARCH.evaluate_measurement(
            normalized, self.candidate, self.campaign, authority_passed=False
        )
        self.assertTrue(evaluation["eligible"])
        self.assertEqual(evaluation["security_lane"], "prototype")
        self.assertEqual(normalized["proof_bytes"], 350_800)
        self.assertEqual(normalized["envelope_bytes"], 350_812)
        self.assertFalse(evaluation["strict_security_fields_pass"])

    def test_missing_prebuild_target_measures_zero_only_when_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "target"
            self.assertEqual(AUTORESEARCH._directory_bytes(missing, missing_ok=True), 0)
            with self.assertRaisesRegex(
                AUTORESEARCH.ResearchError, "missing temporary directory"
            ):
                AUTORESEARCH._directory_bytes(missing)

    def test_smaller_result_with_failed_mutation_is_rejected(self) -> None:
        payload = copy.deepcopy(self.baseline_payload)
        payload["selected"]["proof_bytes"] = 1
        payload["selected"]["envelope_bytes"] = 13
        selected_rate = next(
            row
            for row in payload["rate_sweep"]
            if row["log_inverse_rate"] == payload["selected"]["log_inverse_rate"]
        )
        selected_rate["proof_bytes"] = 1
        selected_rate["envelope_bytes"] = 13
        payload["verification"]["changed_proof_rejected"] = False
        normalized = AUTORESEARCH.normalize_measurement(payload)
        evaluation = AUTORESEARCH.evaluate_measurement(
            normalized, self.candidate, self.campaign, authority_passed=False
        )
        self.assertFalse(evaluation["eligible"])
        self.assertIn(
            "required verification fact is not true: changed_proof_rejected",
            evaluation["failures"],
        )

    def test_strict_lane_dominates_smaller_prototype_in_status(self) -> None:
        base = {
            "schema": AUTORESEARCH.TRIAL_SCHEMA,
            "trial_id": "proxy",
            "candidate_id": "proxy",
            "measurement": {
                "envelope_bytes": 100,
                "proof_bytes": 88,
                "verify_ms": 1.0,
                "prove_ms": 2.0,
                "peak_rss_bytes": 3,
            },
            "evaluation": {"eligible": True, "security_lane": "prototype", "target_met": True},
        }
        strict = copy.deepcopy(base)
        strict["trial_id"] = "strict"
        strict["candidate_id"] = "strict"
        strict["measurement"]["envelope_bytes"] = 200
        strict["measurement"]["proof_bytes"] = 188
        strict["evaluation"]["security_lane"] = "strict"
        status = AUTORESEARCH.summarize([base, strict], self.campaign)
        self.assertEqual(status["lanes"]["strict"]["winner"]["candidate_id"], "strict")
        self.assertEqual(status["lanes"]["prototype"]["winner"]["candidate_id"], "proxy")
        self.assertFalse(status["strict_goal_complete"])
        self.assertEqual(status["maximum_matching_strict_reproductions"], 0)

    def test_ledger_hash_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            entry = {
                "campaign_id": self.campaign["campaign_id"],
                "trial_id": "trial-1",
                "recorded_at": "2026-08-19T00:00:00+00:00",
                "origin": "test",
                "candidate_id": "baseline-all-private-r3",
                "parent_id": None,
                "hypothesis": "test",
                "provenance": {},
                "measurement": {},
                "security_profile": {},
                "evaluation": {},
                "environment": {},
            }
            AUTORESEARCH._append_ledger(state, entry)
            ledger = state / "results.jsonl"
            self.assertEqual(len(AUTORESEARCH._read_ledger(ledger)), 1)
            record = json.loads(ledger.read_text())
            record["candidate_id"] = "tampered"
            ledger.write_text(json.dumps(record, sort_keys=True) + "\n")
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "digest mismatch"):
                AUTORESEARCH._read_ledger(ledger)

    def test_ledger_cannot_self_attest_a_strict_authority_pass(self) -> None:
        normalized = AUTORESEARCH.normalize_measurement(self.baseline_payload)
        evaluation = AUTORESEARCH.evaluate_measurement(
            normalized, self.candidate, self.campaign, authority_passed=False
        )
        entry = AUTORESEARCH._trial_entry(
            self.campaign,
            self.candidate,
            AUTORESEARCH.candidate_provenance(self.candidate),
            normalized,
            evaluation,
            origin="seed",
            environment={"source": "test"},
        )
        entry["evaluation"]["strict_authority_passed"] = True
        with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "cannot retain"):
            AUTORESEARCH._validate_trial_entry(entry, self.campaign)

    def test_second_nonblocking_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with AUTORESEARCH._exclusive_lock(path, "test"):
                with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "already holds"):
                    with AUTORESEARCH._exclusive_lock(path, "test"):
                        pass

    def test_patch_policy_rejects_test_changes_and_deletions(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            test_patch = Path(directory) / "test.patch"
            test_patch.write_text(
                "diff --git a/crates/ip/tests/bad.rs b/crates/ip/tests/bad.rs\n"
                "--- a/crates/ip/tests/bad.rs\n+++ b/crates/ip/tests/bad.rs\n@@ -1 +1 @@\n-a\n+b\n"
            )
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "modify tests"):
                AUTORESEARCH.validate_patch(test_patch, self.campaign)
            test_patch.write_text(
                "diff --git a/crates/ip/src/a.rs b/crates/ip/src/a.rs\n"
                "deleted file mode 100644\n--- a/crates/ip/src/a.rs\n+++ /dev/null\n"
            )
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "deletions"):
                AUTORESEARCH.validate_patch(test_patch, self.campaign)

    def test_patch_policy_rejects_mismatched_apply_header_and_addition(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            patch = Path(directory) / "escape.patch"
            patch.write_text(
                "diff --git a/crates/ip/src/lib.rs b/crates/ip/src/lib.rs\n"
                "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-a\n+b\n"
            )
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "headers do not match"):
                AUTORESEARCH.validate_patch(patch, self.campaign)
            patch.write_text(
                "diff --git a/crates/ip/src/new.rs b/crates/ip/src/new.rs\n"
                "new file mode 100644\n--- /dev/null\n+++ b/crates/ip/src/new.rs\n@@ -0,0 +1 @@\n+x\n"
            )
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "additions"):
                AUTORESEARCH.validate_patch(patch, self.campaign)

    def test_noisy_stdout_exposes_multiple_supported_results(self) -> None:
        report = AUTORESEARCH._read_json(HARNESS_MEASUREMENT)
        raw = "cargo noise {not json}\n" + json.dumps(self.baseline_payload) + "\n" + json.dumps(report)
        objects = AUTORESEARCH._extract_result_objects(raw)
        self.assertEqual(len(objects), 2)
        self.assertEqual(objects[-1]["schema"], AUTORESEARCH.REPORT_SCHEMA)

    def test_config_cannot_lower_twenty_gib_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = json.loads(CAMPAIGN_PATH.read_text())
            bad["resources"]["hard_abort_free_bytes"] = 19 * 1024**3
            path = Path(directory) / "campaign.json"
            path.write_text(json.dumps(bad))
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "at least"):
                AUTORESEARCH.load_campaign(path)

    def test_child_process_limit_leaves_live_desktop_headroom(self) -> None:
        current = AUTORESEARCH._current_uid_process_count()
        limit = AUTORESEARCH._child_nproc_limit()
        self.assertGreater(limit, current)
        self.assertGreaterEqual(limit, 1024)

    def test_sandbox_blocks_source_marker_escape_signal_and_new_process_group(self) -> None:
        passed, detail = AUTORESEARCH._sandbox_smoke(self.campaign)
        self.assertTrue(passed, detail)

    def test_runner_uses_sibling_prepare_compile_and_runtime_sandboxes(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("PHASE=${3:-orchestrate}", runner)
        self.assertIn('"$CANDIDATE_PATCH" prepare', runner)
        self.assertIn("compile_sandbox cargo", runner)
        self.assertIn("run_candidate_binary", runner)
        prepare = runner.index('if [ "$PHASE" = prepare ]')
        orchestrate = runner.index('if [ "$PHASE" != orchestrate ]')
        self.assertIn("exit 0", runner[prepare:orchestrate])
        self.assertNotIn("compile.sb", runner[prepare:orchestrate])
        self.assertIn('if ! TEST_BINARIES=$(python3 -c', runner)
        self.assertIn('if len(seen) != 2:', runner)
        self.assertNotIn("exec /usr/bin/sandbox-exec", runner)

    def test_seed_and_status_use_separate_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            AUTORESEARCH.command_seed(
                self.campaign, self.candidate, BASELINE_MEASUREMENT, state
            )
            entries = AUTORESEARCH._read_ledger(state / "results.jsonl")
            status = AUTORESEARCH.summarize(entries, self.campaign)
            self.assertIsNone(status["lanes"]["strict"]["winner"])
            self.assertEqual(
                status["lanes"]["prototype"]["winner"]["envelope_bytes"], 350_812
            )

    def test_seed_rejects_substituted_path_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            substitute = Path(directory) / "measurement.json"
            substitute.write_bytes(BASELINE_MEASUREMENT.read_bytes())
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "path does not match"):
                AUTORESEARCH.command_seed(
                    self.campaign, self.candidate, substitute, Path(directory) / "state"
                )
            candidate = copy.deepcopy(self.candidate)
            candidate["seed_measurement_sha256"] = "00" * 32
            with self.assertRaisesRegex(AUTORESEARCH.ResearchError, "digest does not match"):
                AUTORESEARCH.command_seed(
                    self.campaign,
                    candidate,
                    BASELINE_MEASUREMENT,
                    Path(directory) / "state2",
                )

    def test_live_tiny_runner_cleans_exact_marked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_parent, tempfile.TemporaryDirectory() as state_dir:
            campaign = copy.deepcopy(self.campaign)
            campaign["paths"]["temporary_parent"] = temporary_parent
            campaign["resources"]["heavy_run_admission_free_bytes"] = 20 * 1024**3
            campaign["runner"]["argv"] = [
                sys.executable,
                "-c",
                "import os,pathlib,shutil; r=pathlib.Path(os.environ['HEGEMON_AUTORESEARCH_RUN_DIR']); "
                "shutil.copyfile(r'" + str(BACKEND_SWEEP) + "', r/'outputs/full-pay1x2-candidate-sweep.json'); "
                "print(pathlib.Path(r'" + str(HARNESS_MEASUREMENT) + "').read_text())",
            ]
            entry = AUTORESEARCH.command_run(campaign, self.candidate, Path(state_dir))
            self.assertTrue(entry["evaluation"]["eligible"])
            leftovers = [
                path
                for path in Path(temporary_parent).iterdir()
                if path.name.startswith(AUTORESEARCH.RUN_PREFIX)
            ]
            self.assertEqual(leftovers, [])

    def test_gc_removes_only_old_owned_dead_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_parent:
            campaign = copy.deepcopy(self.campaign)
            campaign["paths"]["temporary_parent"] = temporary_parent
            campaign["resources"]["stale_run_hours"] = 1
            run_id = "deadbeef" * 4
            owned = Path(temporary_parent) / f"{AUTORESEARCH.RUN_PREFIX}{run_id}.extra"
            owned.mkdir()
            marker = {
                "schema": AUTORESEARCH.MARKER_SCHEMA,
                "campaign_id": campaign["campaign_id"],
                "candidate_id": "test",
                "run_id": run_id,
                "uid": os.getuid(),
                "pid": 2_000_000_000,
                "pid_start_token": "definitely-not-live",
                "worker_pgid": None,
                "created_unix": time.time() - 7200,
            }
            (owned / AUTORESEARCH.MARKER_NAME).write_text(json.dumps(marker))
            unmarked = Path(temporary_parent) / f"{AUTORESEARCH.RUN_PREFIX}unmarked"
            unmarked.mkdir()
            result = AUTORESEARCH.command_gc(campaign)
            self.assertFalse(owned.exists())
            self.assertTrue(unmarked.exists())
            self.assertIn(str(owned.resolve()), result["removed"])


if __name__ == "__main__":
    unittest.main()
