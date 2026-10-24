#!/usr/bin/env python3
"""Exercise the isolation CLI using disposable Cargo/libtest subprocesses only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


RUNNER = Path(__file__).with_name("isolate_transaction_lib.py")
ALLOWED_A = "private_multisig_accumulator::tests::private_multisig_accumulator_matches_lean_vectors"
ALLOWED_B = "proof::tests::lean_generated_transaction_proof_wrapper_wire_vectors_match_production"
DECLARED_SKIPS = (
    ALLOWED_A,
    ALLOWED_B,
    "smallwood_frontend::tests::lean_generated_smallwood_candidate_wrapper_admission_vectors_match_production",
    "smallwood_frontend::tests::lean_generated_smallwood_production_constraint_maps_match_every_production_row",
    "smallwood_frontend::tests::lean_generated_legacy_level5_transcript_binding_vectors_match_runtime_codec",
    "asset_recovery_capsule_v1::tests::actual_graph_rejects_wrong_secret_owner_commitment_and_ciphertext",
    "asset_recovery_capsule_v1::tests::segment_graphs_repeat_opening_checks_and_cover_exact_chacha_stream",
    "asset_recovery_chacha_v1::tests::four_block_240_byte_graph_matches_host_and_rejects_mutations",
    "asset_recovery_geometry_v1::emit_exact_graph_costs",
    "asset_spend_v1::tests::asset_spend_combined_graph_reuses_policy_for_all_operations",
    "asset_spend_v1::tests::asset_spend_combined_policy_credentials_cover_entire_reference_window",
    "asset_spend_v1::tests::asset_spend_credential_horizon_covers_later_policy_branch",
    "asset_spend_v1::tests::asset_spend_policy_height_authority_and_release_are_mandatory",
    "asset_spend_v1::tests::asset_spend_recovery_shares_nullifier_and_cannot_bypass_current_policy",
    "asset_spend_v1::tests::asset_spend_policy_credentials_bind_full_owner_and_zero_change",
    "smallwood_frontend::tests::lean_generated_smallwood_verifier_statement_projection_vectors_match_production",
    "smallwood_recursive::tests::lean_generated_smallwood_recursive_envelope_wire_vectors_match_production",
    "smallwood_htlc_transport::tests::strict_source_projection_stays_inside_independent_carrier_cap",
)

FAKE_CARGO = r'''
import json, os, pathlib, sys
fixture = json.loads(pathlib.Path(os.environ["FAKE_FIXTURE"]).read_text())
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"kind": "cargo", "args": sys.argv[1:]}) + "\n")
artifact = {
    "reason": "compiler-artifact",
    "package_id": "path+file:///fake/circuits/transaction#transaction-circuit@0.1.0",
    "target": {"kind": ["lib"], "name": "transaction_circuit"},
    "profile": {"test": True},
    "executable": os.environ["FAKE_BINARY"],
}
artifact.update(fixture.get("artifact_override", {}))
if "cargo_output" in fixture:
    print(fixture["cargo_output"])
    sys.exit(fixture.get("cargo_exit_code", 0))
for _ in range(fixture.get("artifact_count", 1)):
    print(json.dumps(artifact))
print(json.dumps({"reason": "build-finished", "success": True}))
sys.exit(fixture.get("cargo_exit_code", 0))
'''

FAKE_BINARY = r'''
import json, os, pathlib, sys
fixture = json.loads(pathlib.Path(os.environ["FAKE_FIXTURE"]).read_text())
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"kind": "binary", "args": args, "pid": os.getpid(),
                          "cwd": os.getcwd()}) + "\n")
if "--list" in args:
    key = "ignored" if "--ignored" in args else "names"
    override = "ignored_listing" if "--ignored" in args else "listing"
    print(fixture.get(override, "\n".join(name + ": test" for name in fixture[key])))
    sys.exit(0)
name = args[0]
behavior = fixture.get("behavior", {}).get(name, {})
print("running 1 test")
print("test " + name + " ... ok")
filtered = len(fixture["names"]) - 1
print(behavior.get("result", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; " + str(filtered) + " filtered out; finished in 0.01s"))
sys.exit(behavior.get("exit_code", 0))
'''


class IsolationSubprocessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hegemon-isolation-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fixture_path = self.root / "fixture.json"
        self.log_path = self.root / "commands.jsonl"
        self.cargo = self.root / "fake-cargo"
        self.binary = self.root / "fake-libtest"
        for path, body in ((self.cargo, FAKE_CARGO), (self.binary, FAKE_BINARY)):
            path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body))
            path.chmod(0o700)
        self.env = dict(os.environ, FAKE_FIXTURE=str(self.fixture_path),
                        FAKE_LOG=str(self.log_path), FAKE_BINARY=str(self.binary))

    def run_cli(self, names, ignored=(), skips=(), **extra):
        fixture = {"names": list(names), "ignored": list(ignored), **extra}
        self.fixture_path.write_text(json.dumps(fixture))
        self.log_path.write_text("")
        command = [sys.executable, str(RUNNER), "--cargo", str(self.cargo),
                   "--timeout", "5"]
        for name in skips:
            command += ["--skip", name]
        result = subprocess.run(command, cwd=self.root, env=self.env,
                                text=True, capture_output=True, timeout=20)
        self.calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        return result

    def executions(self):
        return [call["args"] for call in self.calls
                if call["kind"] == "binary" and "--list" not in call["args"]]

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_sorted_selection_and_ignore_accounting(self):
        names = ["zeta::works", ALLOWED_A, "alpha::works", "ignored::expensive", ALLOWED_B]
        result = self.run_cli(names, ignored=["ignored::expensive"], skips=[ALLOWED_A, ALLOWED_B])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual({key: summary[key] for key in
                          ("discovered", "ignored", "excluded", "executed")},
                         {"discovered": 5, "ignored": 1, "excluded": 2, "executed": 2})
        self.assertEqual(summary["status"].upper(), "PASS")
        self.assertEqual(self.calls[0], {"kind": "cargo", "args": [
            "test", "--locked", "-p", "transaction-circuit", "--lib", "--no-run", "--message-format=json"]})
        self.assertEqual([call["args"] for call in self.calls if call["kind"] == "binary"][:2],
                         [["--list", "--format", "terse"], ["--ignored", "--list", "--format", "terse"]])
        self.assertEqual(self.executions(), [["alpha::works", "--exact", "--nocapture", "--test-threads=1"],
                                            ["zeta::works", "--exact", "--nocapture", "--test-threads=1"]])
        execution_calls = [call for call in self.calls
                           if call["kind"] == "binary" and "--list" not in call["args"]]
        self.assertEqual(len({call["pid"] for call in execution_calls}), 2)
        self.assertTrue(all(Path(call["cwd"]).resolve() == self.root.resolve()
                            for call in execution_calls))
        self.assertIn("test alpha::works ... ok", result.stdout)

    def test_unmatched_allowed_skip_rejects(self):
        result = self.run_cli(["ordinary::works"], skips=[ALLOWED_A])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_all_eighteen_declared_skips_are_authorized_when_discovered(self):
        self.assertEqual(len(set(DECLARED_SKIPS)), 18)
        result = self.run_cli([*DECLARED_SKIPS, "ordinary::works"], skips=DECLARED_SKIPS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual({key: summary[key] for key in
                          ("discovered", "ignored", "excluded", "selected", "executed", "status")},
                         {"discovered": 19, "ignored": 0, "excluded": 18,
                          "selected": 1, "executed": 1, "status": "PASS"})
        self.assertEqual(summary["inventory"]["excluded"], sorted(DECLARED_SKIPS))
        self.assertEqual(self.executions(), [["ordinary::works", "--exact", "--nocapture",
                                             "--test-threads=1"]])

    def test_empty_full_inventory_rejects_without_execution(self):
        result = self.run_cli([])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_all_ignored_inventory_rejects_without_execution(self):
        result = self.run_cli(["ignored::only"], ignored=["ignored::only"])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_duplicate_skip_rejects(self):
        result = self.run_cli([ALLOWED_A, "ordinary::works"], skips=[ALLOWED_A, ALLOWED_A])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_listed_but_unauthorized_skip_rejects(self):
        result = self.run_cli(["ordinary::works"], skips=["ordinary::works"])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_duplicate_discovered_name_rejects(self):
        result = self.run_cli(["ordinary::works", "ordinary::works"])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_duplicate_ignored_name_rejects(self):
        result = self.run_cli(["ordinary::works"], ignored=["ordinary::works", "ordinary::works"])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_ignored_names_must_be_discovered(self):
        result = self.run_cli(["ordinary::works"], ignored=["unknown::test"])
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_malformed_nonempty_listing_rejects(self):
        result = self.run_cli(["ordinary::works"], listing="ordinary::works: test\nunparsed output")
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_multiple_compiler_artifacts_reject(self):
        result = self.run_cli(["ordinary::works"], artifact_count=2)
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_missing_compiler_artifact_rejects(self):
        result = self.run_cli(["ordinary::works"], artifact_count=0)
        self.assert_rejected(result)
        self.assertEqual(self.executions(), [])

    def test_wrong_package_artifact_rejects(self):
        for package_id in ("path+file:///fake#other-circuit@0.1.0",
                           "path+file:///fake#transaction-circuit",
                           "path+file:///fake#transaction-circuit@0.1.0-extra#other@0.1.0"):
            with self.subTest(package_id=package_id):
                result = self.run_cli(["ordinary::works"],
                                      artifact_override={"package_id": package_id})
                self.assert_rejected(result)
                self.assertEqual([call["kind"] for call in self.calls], ["cargo"])

    def test_wrong_target_artifact_rejects(self):
        for target in ({"kind": ["lib"], "name": "other_circuit"},
                       {"kind": ["bin"], "name": "transaction_circuit"}):
            with self.subTest(target=target):
                result = self.run_cli(["ordinary::works"], artifact_override={"target": target})
                self.assert_rejected(result)
                self.assertEqual([call["kind"] for call in self.calls], ["cargo"])

    def test_non_test_profile_artifact_rejects(self):
        result = self.run_cli(["ordinary::works"], artifact_override={"profile": {"test": False}})
        self.assert_rejected(result)
        self.assertEqual([call["kind"] for call in self.calls], ["cargo"])

    def test_malformed_cargo_json_rejects(self):
        result = self.run_cli(["ordinary::works"], cargo_output="{not valid JSON}")
        self.assert_rejected(result)
        self.assertEqual([call["kind"] for call in self.calls], ["cargo"])

    def test_nonzero_cargo_exit_rejects_valid_artifact(self):
        result = self.run_cli(["ordinary::works"], cargo_exit_code=17)
        self.assert_rejected(result)
        self.assertEqual([call["kind"] for call in self.calls], ["cargo"])

    def test_nonzero_test_process_fails_even_with_success_text(self):
        result = self.run_cli(["ordinary::works"], behavior={"ordinary::works": {"exit_code": 1}})
        self.assert_rejected(result)

    def test_failed_libtest_summary_rejects_even_with_zero_exit(self):
        result = self.run_cli(["ordinary::works"], behavior={"ordinary::works": {
            "result": "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"}})
        self.assert_rejected(result)

    def test_zero_tests_rejects_even_with_success_exit(self):
        result = self.run_cli(["ordinary::works"], behavior={"ordinary::works": {
            "result": "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;"}})
        self.assert_rejected(result)

    def test_missing_result_summary_rejects(self):
        result = self.run_cli(["ordinary::works"], behavior={"ordinary::works": {"result": ""}})
        self.assert_rejected(result)


if __name__ == "__main__":
    unittest.main()
