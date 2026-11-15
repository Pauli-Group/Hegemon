#!/usr/bin/env python3
"""Mutation controls for the distinct v0.11.5 executed software consumer."""
from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "v0115_crypto_consumer", ROOT / "scripts/check_release_crypto_profile.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


def fixtures():
    identity = {
        "schema": "hegemon.private-spend.native-launch-identity.v2",
        "kind": "PrivateSpend", "network_profile": "pre-mainnet",
        "relation_id": "Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4",
        "public_words": 86, "chain_id": "1" * 64, "genesis_hash": "2" * 64,
        "manifest_digest": "3" * 128, "relation_digest": "4" * 128,
    }
    artifacts = [dict(package=package, binary=name, path="target/release/" + name,
                      sha256=str(index) * 64)
                 for index, (package, name) in enumerate(consumer.PRIVATE_LAUNCH_ARTIFACTS, 1)]
    manifest = {"target_triple": "aarch64-apple-darwin", "artifacts": artifacts}
    receipt = {
        "software_version": "0.11.5",
        "status": "PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE",
        "final_artifact_scope": consumer.NTIME_SCOPE,
        "artifact_manifest_sha256": "a" * 64,
        "target_triple": manifest["target_triple"],
        "actual_new_binary_proof_verification": True,
        "affected_lifecycle_verified": True,
        **{field: False for field in consumer.NTIME_FALSE_BOUNDARIES},
        "candidate_binding_sha256": "b" * 64,
        "source_inventory_sha256": "c" * 64,
        "artifact_sha256": {row["binary"]: row["sha256"] for row in artifacts},
        "identity": identity,
    }
    return receipt, manifest, identity


@contextmanager
def routing_fixture(receipt=None):
    original, manifest, identity = fixtures()
    receipt = original if receipt is None else receipt
    with tempfile.TemporaryDirectory(prefix="v0115-crypto-route-") as directory:
        root = Path(directory).resolve()
        for config in (consumer.NTIME_CONFIG, consumer.COMBINED_CONFIG,
                       "config/v0113-release-successor.json"):
            path = root / config
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}")
        (root / "scripts").mkdir()
        (root / "scripts/private_spend_launch_authorized_registry.json").write_text("{}")
        manifest_path = root / "target/release/artifact-manifest.json"
        snapshot = (manifest, "a" * 64, tuple(root / row["path"] for row in manifest["artifacts"]), ())
        helper = SimpleNamespace(CandidateError=ValueError,
                                 validate_final_receipt=Mock(return_value=identity))
        completed = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(receipt))
        with patch.object(consumer, "SOURCE_ROOT", root), \
                patch.object(consumer, "private_launch_snapshot", return_value=snapshot) as snapshots, \
                patch.object(consumer, "ntime_helper", return_value=helper) as selected, \
                patch.object(consumer, "combined_helper") as historical, \
                patch.object(consumer, "v0113_helper") as v0113, \
                patch.object(consumer, "sync_import_helper") as sync, \
                patch.object(consumer, "validate_binary_profile_markers") as markers, \
                patch.object(consumer, "run_profile", return_value=None) as profiles, \
                patch.object(consumer.subprocess, "run", return_value=completed) as run:
            yield SimpleNamespace(root=root, manifest_path=manifest_path, manifest=manifest,
                                  receipt=receipt, identity=identity, helper=helper,
                                  completed=completed, snapshots=snapshots, selected=selected,
                                  historical=historical, v0113=v0113, sync=sync,
                                  markers=markers, profiles=profiles, run=run)


class ReceiptBoundaryControls(unittest.TestCase):
    def check(self, receipt, manifest):
        consumer.validate_ntime_receipt_boundary(receipt, manifest, "a" * 64)

    def test_complete_envelope_passes_without_granting_authority(self):
        receipt, manifest, _ = fixtures()
        self.check(receipt, manifest)

    def test_every_required_boundary_is_typed_and_present(self):
        receipt, manifest, _ = fixtures()
        fields = ["software_version", "status", "final_artifact_scope",
                  "artifact_manifest_sha256", "target_triple",
                  "actual_new_binary_proof_verification", "affected_lifecycle_verified",
                  *consumer.NTIME_FALSE_BOUNDARIES, "candidate_binding_sha256",
                  "source_inventory_sha256", "artifact_sha256"]
        for field in fields:
            bad = copy.deepcopy(receipt)
            del bad[field]
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.check(bad, manifest)
        for field in consumer.NTIME_FALSE_BOUNDARIES:
            for value in (True, 0, "false", None):
                bad = dict(receipt, **{field: value})
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.check(bad, manifest)
        for field in ("actual_new_binary_proof_verification", "affected_lifecycle_verified"):
            for value in (False, 1, "true", None):
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.check(dict(receipt, **{field: value}), manifest)
        for field in consumer.NTIME_ADDITIONAL_FALSE_BOUNDARIES:
            for value in (True, 0, "false", None):
                with self.subTest(extra=field, value=value), self.assertRaises(SystemExit):
                    self.check(dict(receipt, **{field: value}), manifest)

    def test_other_scope_version_target_and_manifest_reject(self):
        receipt, manifest, _ = fixtures()
        for field, value in (("final_artifact_scope", consumer.COMBINED_SCOPE),
                             ("software_version", "0.11.4"), ("target_triple", "x86_64-unknown-linux-gnu"),
                             ("artifact_manifest_sha256", "d" * 64)):
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.check(dict(receipt, **{field: value}), manifest)

    def test_malformed_digests_and_wrong_exact_artifacts_reject(self):
        receipt, manifest, _ = fixtures()
        for field in ("candidate_binding_sha256", "source_inventory_sha256", "artifact_manifest_sha256"):
            for value in (True, None, "d" * 63, "D" * 64, "z" * 64):
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.check(dict(receipt, **{field: value}), manifest)
        for binary in receipt["artifact_sha256"]:
            for operation in ("missing", "changed"):
                bad = copy.deepcopy(receipt)
                if operation == "missing":
                    del bad["artifact_sha256"][binary]
                else:
                    bad["artifact_sha256"][binary] = "f" * 64
                with self.subTest(binary=binary, operation=operation), self.assertRaises(SystemExit):
                    self.check(bad, manifest)
        bad = copy.deepcopy(receipt)
        bad["artifact_sha256"]["extra"] = "f" * 64
        with self.assertRaises(SystemExit):
            self.check(bad, manifest)
        for operation in ("missing", "duplicate", "reordered", "wrong-package"):
            bad_manifest = copy.deepcopy(manifest)
            if operation == "missing":
                bad_manifest["artifacts"].pop()
            elif operation == "duplicate":
                bad_manifest["artifacts"].append(dict(bad_manifest["artifacts"][-1]))
            elif operation == "reordered":
                bad_manifest["artifacts"].reverse()
            else:
                bad_manifest["artifacts"][-1]["package"] = "private-spend"
            with self.subTest(manifest=operation), self.assertRaises(SystemExit):
                self.check(receipt, bad_manifest)

    def test_json_rejects_duplicate_nonfinite_and_nonobject_receipts(self):
        for raw in ('{"passed":true,"passed":false}', '{"nested":{"x":1,"x":2}}',
                    '{"number":NaN}', '{"number":Infinity}', '[]', 'true', '{}{}'):
            with self.subTest(raw=raw), self.assertRaises(SystemExit):
                consumer.ntime_execution_receipt(raw)


class ExecutedRouteControls(unittest.TestCase):
    def test_v0115_route_executes_exact_checker_before_history_and_returns_distinct_mode(self):
        with routing_fixture() as fixture:
            result = consumer.private_launch_profile(fixture.root, fixture.manifest_path)
            fixture.run.assert_called_once_with(
                [sys.executable, "-I", "-B", str(fixture.root / consumer.NTIME_CHECKER),
                 "--require-authorized", "--artifact-manifest", "target/release/artifact-manifest.json",
                 "--require-final-artifact"], cwd=fixture.root, capture_output=True, text=True, timeout=44400)
            self.assertEqual(fixture.snapshots.call_count, 2)
            self.assertEqual(fixture.markers.call_count, 4)
            self.assertEqual(fixture.profiles.call_count, 4)
            fixture.historical.assert_not_called()
            fixture.v0113.assert_not_called()
            fixture.sync.assert_not_called()
            fixture.helper.validate_final_receipt.assert_called_once_with(
                fixture.receipt, fixture.manifest, "a" * 64, fixture.root)
            self.assertEqual(result["mode"], "executed-ntime-rolling-software-candidate")
            self.assertEqual(result["authorization_scope"], consumer.NTIME_SCOPE)
            for field in (*consumer.NTIME_FALSE_BOUNDARIES, *consumer.NTIME_ADDITIONAL_FALSE_BOUNDARIES):
                self.assertIs(result[field], False)

    def test_authentication_or_execution_failure_never_falls_back_to_old_receipts(self):
        with routing_fixture() as fixture:
            fixture.selected.side_effect = SystemExit("source changed")
            with self.assertRaisesRegex(SystemExit, "source changed"):
                consumer.private_launch_profile(fixture.root, fixture.manifest_path)
            fixture.run.assert_not_called()
            fixture.historical.assert_not_called()
        for status, stderr in ((1, "failed proof"), (0, "unexpected warning")):
            with routing_fixture() as fixture:
                fixture.completed.returncode, fixture.completed.stderr = status, stderr
                with self.assertRaises(SystemExit):
                    consumer.private_launch_profile(fixture.root, fixture.manifest_path)
                fixture.helper.validate_final_receipt.assert_not_called()
                fixture.historical.assert_not_called()

    def test_replayed_historical_scope_and_unexecuted_claims_reject(self):
        receipt, _, _ = fixtures()
        mutations = [dict(receipt, final_artifact_scope=consumer.COMBINED_SCOPE),
                     dict(receipt, actual_new_binary_proof_verification=False),
                     dict(receipt, affected_lifecycle_verified=False)]
        for bad in mutations:
            with self.subTest(bad=bad), routing_fixture(bad) as fixture, self.assertRaises(SystemExit):
                consumer.private_launch_profile(fixture.root, fixture.manifest_path)

    def test_after_snapshot_change_rejects_even_after_fresh_checks_pass(self):
        with routing_fixture() as fixture:
            original = fixture.snapshots.return_value
            fixture.snapshots.side_effect = [original, (*original[:3], (("source", "changed"),))]
            with self.assertRaisesRegex(SystemExit, "changed during validation"):
                consumer.private_launch_profile(fixture.root, fixture.manifest_path)
            fixture.run.assert_called_once()


class SourceSnapshotControls(unittest.TestCase):
    def test_ntime_first_snapshot_pins_complete_consumer_authority_and_exact_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="v0115-crypto-snapshot-") as directory:
            root = Path(directory).resolve()
            receipt, manifest, _ = fixtures()
            review = "release-evidence/ntime-rolling-v0115/review.json"
            for name in (consumer.NTIME_CONFIG, consumer.COMBINED_CONFIG, consumer.NTIME_CHECKER,
                         "scripts/check_release_crypto_profile.py", "scripts/security-audit.sh", review):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(name)
            for row in manifest["artifacts"]:
                file = root / row["path"]
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(row["binary"])
                row["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            manifest_path = root / "artifact-manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            helper = SimpleNamespace(load_config=Mock(return_value={"independent_review": {"path": review}}))
            with patch.object(consumer, "rustc_host", return_value=manifest["target_triple"]), \
                    patch.object(consumer, "ntime_helper", return_value=helper) as selected, \
                    patch.object(consumer, "combined_helper") as historical:
                before = consumer.private_launch_snapshot(root, manifest_path)
                self.assertEqual(len(before[2]), 4)
                self.assertEqual({Path(path).relative_to(root).as_posix() for path, _ in before[3]}, {
                    consumer.NTIME_CONFIG, consumer.NTIME_CHECKER, "scripts/check_release_crypto_profile.py",
                    "scripts/security-audit.sh", review})
                historical.assert_not_called()
                selected.assert_called_once_with(root)
                (root / "scripts/security-audit.sh").write_text("changed source")
                self.assertNotEqual(consumer.private_launch_snapshot(root, manifest_path), before)
                (root / manifest["artifacts"][0]["path"]).write_text("changed artifact")
                with self.assertRaisesRegex(SystemExit, "artifact digest"):
                    consumer.private_launch_snapshot(root, manifest_path)
                manifest["artifacts"] = manifest["artifacts"][:-1]
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(SystemExit, "exactly node/wallet"):
                    consumer.private_launch_snapshot(root, manifest_path)


class SecurityAuditScopeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "scripts/security-audit.sh").read_text()
        match = re.search(r"PROFILE_SCOPE=\$\(python3 -c '(.*?)' <<<", source, re.S)
        if match is None:
            raise AssertionError("pure security-audit classification predicate is absent")
        cls.predicate = compile(match[1], "<v0115-security-audit-scope>", "exec")

    def classify(self, result):
        output = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO(json.dumps(result))), redirect_stdout(output):
            exec(self.predicate, {})
        return output.getvalue().strip()

    def result(self):
        with routing_fixture() as fixture:
            return consumer.private_launch_profile(fixture.root, fixture.manifest_path)

    def test_distinct_ntime_mode_has_narrow_authority(self):
        self.assertEqual(self.classify(self.result()), "ntime-software-candidate")

    def test_each_scope_field_and_boolean_type_is_required(self):
        base = self.result()
        for field in base:
            bad = copy.deepcopy(base)
            del bad[field]
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.classify(bad)
        for field in (*consumer.NTIME_FALSE_BOUNDARIES, *consumer.NTIME_ADDITIONAL_FALSE_BOUNDARIES):
            for value in (True, 0, "false", None):
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.classify(dict(base, **{field: value}))
        for field in ("passed", "actual_new_binary_proof_verification", "affected_lifecycle_verified",
                      "fresh_ntime_lifecycle_verified"):
            for value in (False, 1, "true", None):
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.classify(dict(base, **{field: value}))

    def test_scope_hash_identity_and_artifact_mutations_reject(self):
        base = self.result()
        mutations = [("authorization_scope", consumer.COMBINED_SCOPE), ("software_version", "0.11.4"),
                     ("candidate_binding_sha256", "g" * 64), ("source_inventory_sha256", 1),
                     ("artifact_manifest_sha256", "b" * 63), ("target_triple", "marker-only"),
                     ("artifact_sha256", {})]
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.classify(dict(base, **{field: value}))
        for field in base["identity"]:
            bad = copy.deepcopy(base)
            del bad["identity"][field]
            with self.subTest(identity=field), self.assertRaises(SystemExit):
                self.classify(bad)
        bad = copy.deepcopy(base)
        bad["identity"]["public_words"] = True
        with self.assertRaises(SystemExit):
            self.classify(bad)


if __name__ == "__main__":
    unittest.main()
