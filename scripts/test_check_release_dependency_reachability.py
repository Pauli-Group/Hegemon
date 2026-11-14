#!/usr/bin/env python3
"""Negative release-dependency scope regressions; no builds or network."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_dependency_scope", ROOT / "scripts/check_release_dependency_reachability.py")
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ReleaseDependencyReachabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-dependency-scope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = json.loads((ROOT / "config/dependency-audit-waivers.json").read_text())
        for name in self.policy[scope.BINDING_KEY]["source_sha256"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        self.paths = set(self.policy[scope.BINDING_KEY]["source_sha256"])
        self.patch = patch.object(scope, "source_paths", return_value=self.paths)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    @staticmethod
    def clean_runner(command, **kwargs):
        package = command[command.index("-p") + 1]
        return subprocess.CompletedProcess(command, 0, f"{package} v0.10.0 (/selected)\nserde v1.0.228\n", "")

    def test_all_twelve_exact_graph_commands(self):
        seen = []
        def runner(command, **kwargs):
            seen.append(command)
            return self.clean_runner(command, **kwargs)
        self.assertEqual(scope.check(self.root, self.policy, runner=runner), 12)
        expected = {(t, p, flags) for t in scope.TARGETS for p, flags in scope.PACKAGES}
        actual = set()
        for command in seen:
            self.assertIn("--locked", command)
            self.assertEqual(command[command.index("--edges")+1], "normal,build")
            package = command[command.index("-p")+1]
            flags = tuple(command[command.index("{p}")+1:])
            actual.add((command[command.index("--target")+1], package, flags))
        self.assertEqual(actual, expected)

    def test_each_reviewed_absent_dependency_activation_rejects(self):
        for name in scope.EXCLUDED:
            with self.subTest(package=name):
                def runner(command, **kwargs):
                    result = self.clean_runner(command, **kwargs)
                    result.stdout += f"{name} v1.1.4\n"
                    return result
                with self.assertRaisesRegex(scope.ReachabilityError, "dependency activated"):
                    scope.check(self.root, self.policy, runner=runner)

    def test_graph_resolution_failure_rejects(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 101, "", "missing dependency")
        with self.assertRaisesRegex(scope.ReachabilityError, "failed dependency resolution"):
            scope.check(self.root, self.policy, runner=runner)

    def test_empty_and_malformed_graphs_reject(self):
        for text in ("", "not a Cargo package", "wallet v0.10.0\n"):
            with self.subTest(text=text):
                def runner(command, **kwargs):
                    return subprocess.CompletedProcess(command, 0, text, "")
                with self.assertRaises(scope.ReachabilityError):
                    scope.check(self.root, self.policy, runner=runner)

    def test_lock_drift_rejects(self):
        (self.root / "Cargo.lock").write_text("changed proof relation")
        with self.assertRaisesRegex(scope.ReachabilityError, "source binding changed: Cargo.lock"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_repinning_changed_lock_also_rejects(self):
        self.policy[scope.BINDING_KEY]["source_sha256"]["Cargo.lock"] = "0"*64
        with self.assertRaisesRegex(scope.ReachabilityError, "proof-bound Cargo.lock identity"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_packaging_feature_drift_rejects_even_if_hash_rebound(self):
        name = "scripts/build_release_artifacts.sh"
        path = self.root / name
        path.write_text(path.read_text().replace("--features rpc-client", "--features rpc-client,http3"))
        self.policy[scope.BINDING_KEY]["source_sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(scope.ReachabilityError, "packaging package/feature commands differ"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_package_feature_matrix_drift_rejects(self):
        self.policy[scope.BINDING_KEY]["packages"][0]["feature_args"] = ["--all-features"]
        with self.assertRaisesRegex(scope.ReachabilityError, "package/features or exclusions changed"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_incomplete_target_scope_rejects(self):
        self.policy[scope.BINDING_KEY]["targets"].pop()
        with self.assertRaisesRegex(scope.ReachabilityError, "four-platform scope"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_source_manifest_or_guard_drift_rejects(self):
        for name in ("node/Cargo.toml", "scripts/check_release_dependency_reachability.py"):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n# changed\n")
                with self.assertRaisesRegex(scope.ReachabilityError, "source binding changed"):
                    scope.check(self.root, self.policy, runner=self.clean_runner)
                path.write_bytes(original)

    def test_removed_binding_cannot_turn_reviewed_exception_into_generic_waiver(self):
        del self.policy[scope.BINDING_KEY]
        with self.assertRaisesRegex(scope.ReachabilityError, "source-bound release scope"):
            scope.check(self.root, self.policy, runner=self.clean_runner)

    def test_omitted_or_duplicate_exact_exception_rejects(self):
        for duplicate in (False, True):
            policy = copy.deepcopy(self.policy)
            if duplicate:
                policy["waivers"].append(copy.deepcopy(policy["waivers"][0]))
            else:
                policy["waivers"].pop()
            with self.assertRaisesRegex(scope.ReachabilityError, "four reviewed exact findings"):
                scope.check(self.root, policy, runner=self.clean_runner)

    def test_expired_and_excessive_expiry_reject(self):
        for expiry in ("2026-11-01", "2026-12-15"):
            policy = copy.deepcopy(self.policy)
            policy["waivers"][0]["expires"] = expiry
            with self.assertRaisesRegex(scope.ReachabilityError, "expired or exceeds"):
                scope.check(self.root, policy, runner=self.clean_runner)

    def test_sources_rechecked_after_resolution(self):
        seen = []
        def runner(command, **kwargs):
            seen.append(command)
            if len(seen) == 12:
                (self.root / "Cargo.lock").write_text("concurrent lock edit")
            return self.clean_runner(command, **kwargs)
        with self.assertRaisesRegex(scope.ReachabilityError, "source binding changed: Cargo.lock"):
            scope.check(self.root, self.policy, runner=runner)

    def test_existing_generic_policy_does_not_invoke_cargo(self):
        def runner(*args, **kwargs):
            self.fail("ordinary legacy policy fixture should not invoke cargo")
        self.assertEqual(scope.check(self.root, {"waivers": []}, runner=runner), 0)

    def test_audit_gate_cannot_bypass_missing_source_binding(self):
        policy = copy.deepcopy(self.policy)
        del policy[scope.BINDING_KEY]
        policy_path = self.root / "policy.json"
        audit_path = self.root / "audit.json"
        policy_path.write_text(json.dumps(policy))
        audit_path.write_text(json.dumps({"vulnerabilities": {"list": []}, "warnings": {}}))
        proc = subprocess.run(["bash", str(ROOT / "scripts/dependency-audit-gate.sh"), "--policy", str(policy_path), "--audit-json", str(audit_path)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("source-bound release scope", proc.stderr)


if __name__ == "__main__":
    unittest.main()
