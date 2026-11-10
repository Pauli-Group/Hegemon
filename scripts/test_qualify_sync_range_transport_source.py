#!/usr/bin/env python3
"""Offline source-boundary controls using disposable Git history only.

No Cargo, native executable, host, RPC, network, or service operation runs.
Fixture pins are overridden locally; they grant no candidate qualification.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "sync_recovery_source_under_test",
    Path(__file__).with_name("qualify_sync_range_transport_source.py"),
)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

NODE = "node/src/native/node_impl.rs"
TESTS = "node/src/native/sync_liveness_tests.rs"
SERVICE = "node/src/native/service.rs"
WORKFLOW = ".github/workflows/qualify-sync-range-transport-linux.yml"
OVERLAY = {
    WORKFLOW,
    "scripts/qualify_sync_range_transport_source.py",
    "scripts/test_qualify_sync_range_transport_source.py",
    "scripts/qualify_sync_range_transport_linux.py",
}
CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
SAFE_WORKFLOW = (
    "name: Offline sync recovery fixture\n"
    "on:\n  workflow_dispatch:\n"
    "permissions:\n  contents: read\n"
    "jobs:\n  qualify:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@" + CHECKOUT_PIN + "\n"
    "      - run: python3 -I -B scripts/qualify_sync_range_transport_source.py\n"
).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SourceBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sync-source-controls-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Offline source fixture")
        self.git("config", "user.email", "source-fixture@example.invalid")
        self.before = {
            NODE: b"// synthetic predecessor runtime\n",
            TESTS: b"// synthetic predecessor tests\n",
            SERVICE: b"// unchanged service fixture\n",
            "DESIGN.md": b"Synthetic predecessor design.\n",
            "METHODS.md": b"Synthetic predecessor methods.\n",
            "Cargo.toml": b"[workspace]\nmembers = []\n",
            "Cargo.lock": b"# synthetic lock fixture\nversion = 3\n",
            "consensus/src/lib.rs": b"// unchanged consensus fixture\n",
        }
        for name, raw in self.before.items():
            self.write(name, raw)
        self.commit("synthetic baseline")
        self.baseline = self.head()
        self.after = {
            NODE: b"// synthetic pinned recovery scheduling postimage\n",
            TESTS: b"// synthetic pinned recovery regressions postimage\n",
            "DESIGN.md": b"Synthetic bounded recovery design.\n",
            "METHODS.md": b"Synthetic exact-target recovery methods.\n",
        }
        for name, raw in self.after.items():
            self.write(name, raw)
        self.write(WORKFLOW, SAFE_WORKFLOW)
        for name in OVERLAY - {WORKFLOW}:
            self.write(name, b"# synthetic non-executed overlay fixture\n")
        self.commit("synthetic approved source and CI overlay")
        self.expected_baseline = {name: sha(raw) for name, raw in self.before.items()}
        self.expected_source = {
            name: sha(self.after.get(name, raw)) for name, raw in self.before.items()
        }
        self.allowed = set(self.after) | OVERLAY
        self.overrides = contextlib.ExitStack()
        self.addCleanup(self.overrides.close)
        for name, value in {
            "BASELINE_COMMIT": self.baseline,
            "EXPECTED_BASELINE_FILES": self.expected_baseline,
            "EXPECTED_SOURCE_FILES": self.expected_source,
            "ALLOWED_CHANGED_PATHS": self.allowed,
            "WORKFLOW_PATH": WORKFLOW,
        }.items():
            self.overrides.enter_context(patch.object(validator, name, value))

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=/dev/null",
             "-c", "commit.gpgSign=false", *args],
            cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15,
        ).stdout

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)

    def head(self):
        return self.git("rev-parse", "HEAD").decode().strip()

    def exact_delta(self, head="HEAD"):
        return sha(self.git("diff", "--binary", "--full-index", "--no-ext-diff",
                            self.baseline, head))

    def validate(self, source=None, delta=None):
        return validator.validate_source(
            self.root, self.head() if source is None else source,
            self.exact_delta() if delta is None else delta,
        )

    def assert_rejected(self, **kwargs):
        with self.assertRaises(ValueError):
            self.validate(**kwargs)

    def test_exact_pinned_clean_candidate_is_accepted(self):
        receipt = self.validate()
        self.assertIsInstance(receipt, dict)
        self.assertEqual(receipt["source_head"], self.head())
        self.assertEqual(receipt["baseline_commit"], self.baseline)
        self.assertEqual(receipt["delta_sha256"], self.exact_delta())
        for field in ("production_authorized", "deployment_verified",
                      "release_publication_authorized"):
            self.assertIs(receipt[field], False)

    def test_delta_digest_matches_complete_binary_full_index_diff_bytes(self):
        self.assertEqual(validator.delta_digest(self.root), self.exact_delta())
        self.assertEqual(validator.delta_digest(self.root, self.baseline),
                         self.exact_delta(self.baseline))

    def test_delta_digest_includes_binary_patch_payload(self):
        self.write("scripts/synthetic.bin", b"\x00\xffsynthetic binary fixture\x00")
        self.commit("synthetic binary delta only; never execute")
        raw = self.git("diff", "--binary", "--full-index", "--no-ext-diff",
                       self.baseline, "HEAD")
        self.assertIn(b"GIT binary patch", raw)
        self.assertEqual(validator.delta_digest(self.root), sha(raw))

    def test_wrong_head_is_rejected_even_with_correct_delta(self):
        self.assert_rejected(source=self.baseline)

    def test_source_pin_requires_exact_lowercase_full_commit(self):
        for bad in (self.head()[:12], self.head().upper(), "0" * 40, "x" * 40):
            with self.subTest(source=bad):
                self.assert_rejected(source=bad)

    def test_delta_pin_requires_exact_lowercase_sha256(self):
        actual = self.exact_delta()
        for bad in ("0" * 64, actual[:12], actual.upper(), "z" * 64):
            with self.subTest(delta=bad):
                self.assert_rejected(delta=bad)

    def test_unstaged_tracked_change_is_rejected(self):
        self.write(NODE, self.after[NODE] + b"// dirty runtime\n")
        self.assert_rejected()

    def test_staged_tracked_change_is_rejected(self):
        self.write(TESTS, self.after[TESTS] + b"// dirty staged tests\n")
        self.git("add", TESTS)
        self.assert_rejected()

    def test_untracked_build_inputs_are_rejected(self):
        for name, raw in {
            "node/src/native/unreviewed.rs": b"// untracked Rust\n",
            "build.rs": b"fn main() {}\n",
            ".cargo/config.toml": b"[build]\nrustflags = []\n",
        }.items():
            with self.subTest(path=name):
                self.write(name, raw)
                try:
                    self.assert_rejected()
                finally:
                    (self.root / name).unlink()

    def test_ignored_untracked_rust_still_cannot_enter_build_inventory(self):
        self.write(".gitignore", b"node/src/native/ignored.rs\n")
        self.commit("synthetic ignore rule outside approved delta")
        # Admit the ignore rule itself, isolating the ignored Rust inventory check.
        self.allowed.add(".gitignore")
        self.write("node/src/native/ignored.rs", b"// ignored Rust build input\n")
        self.assert_rejected()

    def test_extra_committed_production_path_is_rejected_with_fresh_pins(self):
        self.write("consensus/src/lib.rs", b"// forbidden consensus change\n")
        self.commit("synthetic forbidden production change")
        self.assert_rejected()

    def test_unapproved_overlay_script_is_rejected(self):
        self.write("scripts/unreviewed_build.py", b"# forbidden extra build helper\n")
        self.commit("synthetic unapproved overlay helper")
        self.assert_rejected()

    def test_committed_workflow_write_cannot_pass_with_a_fresh_delta_pin(self):
        self.write(WORKFLOW, SAFE_WORKFLOW + b"      - run: git push origin HEAD\n")
        self.commit("synthetic forbidden generated workflow operation")
        self.assert_rejected()

    def test_push_pin_provenance_requires_external_root_acceptance(self):
        receipt = validator.validate_source(
            self.root, self.head(), validator.delta_digest(self.root),
            pin_provenance="root-external-check-required")
        self.assertEqual(receipt["status"], "PASS_EXACT_FUNCTIONAL_POSTIMAGES_ROOT_DELTA_CHECK_PENDING")
        self.assertTrue(receipt["external_expected_delta_check_required_root"])
        self.assertFalse(receipt["production_authorized"])
        self.assertFalse(receipt["deployment_verified"])

    def test_runtime_postimage_mismatch_is_rejected_after_commit(self):
        self.write(NODE, self.after[NODE] + b"// committed unauthorized runtime\n")
        self.commit("synthetic runtime postimage mismatch")
        self.assert_rejected()

    def test_regression_postimage_mismatch_is_rejected_after_commit(self):
        self.write(TESTS, self.after[TESTS] + b"// committed unauthorized regression\n")
        self.commit("synthetic regression postimage mismatch")
        self.assert_rejected()

    def test_baseline_preimage_pin_is_enforced(self):
        with patch.dict(validator.EXPECTED_BASELINE_FILES, {NODE: "0" * 64}):
            self.assert_rejected()

    def test_unchanged_service_pin_is_enforced(self):
        with patch.dict(validator.EXPECTED_SOURCE_FILES, {SERVICE: "0" * 64}):
            self.assert_rejected()

    def test_functional_postimage_cannot_be_replaced_by_a_symlink(self):
        node = self.root / NODE
        node.unlink()
        node.symlink_to("service.rs")
        self.git("add", NODE)
        self.git("commit", "--quiet", "-m", "synthetic linked runtime")
        self.assert_rejected()


class WorkflowBoundaryControls(unittest.TestCase):
    def test_actual_workflow_excludes_disposable_node_state_from_upload(self):
        workflow = Path(__file__).resolve().parents[1] / WORKFLOW
        text = workflow.read_text()
        self.assertNotIn("            target/sync-recovery-qualification/\n", text)
        self.assertNotIn("**", text)
        self.assertNotIn("donor-state", text)
        self.assertNotIn("importer-state", text)
        self.assertIn("target/sync-range-components/current-binary-proofs/*.json", text)
        self.assertIn("target/sync-range-components/current-binary-proofs/*.log", text)
        self.assertIn("branches: [codex/sync-range-inline-20261110]", text)

    def test_read_only_pinned_workflow_is_accepted(self):
        validator.validate_workflow(SAFE_WORKFLOW)

    def test_generated_workflow_requires_explicit_contents_read(self):
        for replacement in (b"", b"permissions: read-all\n",
                            b"permissions:\n  contents: write\n"):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                validator.validate_workflow(SAFE_WORKFLOW.replace(
                    b"permissions:\n  contents: read\n", replacement))

    def test_generated_workflow_rejects_malicious_extra_operations(self):
        additions = (
            b"      - run: gh release create fixture\n",
            b"      - run: git push origin HEAD\n",
            b"      - run: echo '${{ secrets.FIXTURE_TOKEN }}'\n",
            b"      - uses: actions/upload-artifact@v4\n",
        )
        for extra in additions:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validator.validate_workflow(SAFE_WORKFLOW + extra)

    def test_generated_workflow_rejects_privileged_trigger(self):
        with self.assertRaises(ValueError):
            validator.validate_workflow(SAFE_WORKFLOW.replace(
                b"  workflow_dispatch:\n", b"  pull_request_target:\n"))

    def test_generated_workflow_rejects_job_level_write_permissions(self):
        for scope in (b"actions", b"checks", b"issues", b"statuses", b"deployments"):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validator.validate_workflow(SAFE_WORKFLOW.replace(
                    b"    runs-on: ubuntu-latest\n",
                    b"    permissions:\n      " + scope + b": write\n"
                    b"    runs-on: ubuntu-latest\n"))
        with self.assertRaises(ValueError):
            validator.validate_workflow(SAFE_WORKFLOW.replace(
                b"    runs-on: ubuntu-latest\n",
                b"    permissions: write-all\n    runs-on: ubuntu-latest\n"))

    def test_generated_workflow_rejects_unpinned_checkout(self):
        with self.assertRaises(ValueError):
            validator.validate_workflow(SAFE_WORKFLOW.replace(
                CHECKOUT_PIN.encode(), b"main"))


class SelectorFailureParserControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('range_runner_parser',Path(__file__).with_name('qualify_sync_range_transport_linux.py'));cls.runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.runner)
    def fixture(self,interleaved=False):
        name=self.runner.TEST_PREFIX+'requested_range_batches_across_unsolicited_announce_threshold'
        first=f'test {name} ...'+(' \n'if interleaved else' FAILED\n')
        return name,('running 1 test\n'+first+f"thread '{name}' (123) panicked at node/src/native/service.rs:7620:9:\nassertion `left == right` failed\n"+('FAILED\n'if interleaved else'')+f'\nfailures:\n\nfailures:\n    {name}\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.01s\n')
    def test_exact_contiguous_and_interleaved_assertions(self):
        for interleaved in(False,True):
            name,text=self.fixture(interleaved);self.runner.verify_selector_failure(101,text,name,7620)
    def test_wrong_compile_or_signal_is_not_a_negative(self):
        name,text=self.fixture()
        for code in(0,1,124,-9,None,True):
            with self.subTest(code=code),self.assertRaises(RuntimeError):self.runner.verify_selector_failure(code,text,name,7620)
        with self.assertRaises(RuntimeError):self.runner.verify_selector_failure(101,'error[E0308]: wrong\n'+text,name,7620)
    def test_zero_ignored_extra_results_wrong_names_reject(self):
        name,text=self.fixture()
        for bad in(text.replace('running 1 test','running 0 tests'),text.replace('0 ignored','1 ignored'),text+text,text.replace(name,'wrong::test'),text.replace('    '+name+'\n','    '+name+'\n    other::test\n')):
            with self.assertRaises(RuntimeError):self.runner.verify_selector_failure(101,bad,name,7620)
    def test_wrong_panic_location_or_assertion_rejects(self):
        name,text=self.fixture()
        for bad in(text.replace('7620:9:','7621:9:'),text.replace('7620:9:','7620:10:'),text.replace('assertion `left == right` failed','unrelated panic')):
            with self.assertRaises(RuntimeError):self.runner.verify_selector_failure(101,bad,name,7620)

if __name__=='__main__':unittest.main()
