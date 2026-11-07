#!/usr/bin/env python3
"""Candidate-inventory controls; synthetic metadata, no binary qualification."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from . import prepare_v0113_candidate as candidate
except ImportError:
    import prepare_v0113_candidate as candidate


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative, version in candidate.PACKAGE_VERSIONS.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'[package]\nname = "fixture"\nversion = "{version}"\n')
        (self.root / "Cargo.lock").write_bytes((Path(__file__).resolve().parents[1] / "Cargo.lock").read_bytes())
        path = self.root / "protocol/versioning/src/lib.rs"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('pub const RELEASE_VERSION: &str = "0.11.3";\n')
        path = self.root / "config/v0112-release-artifacts.json"
        path.parent.mkdir(parents=True)
        self.old = {"build_source_head": "a" * 40, "build_index_tree": "b" * 40, "source_tree_sha256": "c" * 64}
        path.write_text(json.dumps(self.old))
        self.manifest_path = self.root / "manifest.json"
        self.manifest_path.write_text('{}\n')
        self.manifest = {"source_head": "d" * 40, "source_index_tree": "e" * 40, "source_tree_sha256": "f" * 64, "artifacts": []}

    def test_candidate_preserves_verified_manifest_and_never_grants_authority(self):
        with mock.patch.object(candidate.artifacts, "verify_manifest", return_value=self.manifest) as verify:
            record = candidate.prepare(self.root, self.manifest_path, ["exact:expected:path"])
        verify.assert_called_once_with(self.root, self.manifest_path, ["exact:expected:path"])
        self.assertIs(record["artifact_manifest"], self.manifest)
        self.assertEqual(record["status"], "candidate_unqualified")
        self.assertFalse(record["production_authority"])
        self.assertFalse(record["publication_authorized"])
        self.assertFalse(record["deployment_authorized"])
        self.assertTrue(record["remaining_release_gates"])
        self.assertEqual(record["internal_package_versions"], candidate.PACKAGE_VERSIONS)
        self.assertEqual(record["frozen_cargo_lock_sha256"], candidate.FROZEN_CARGO_LOCK_SHA256)

    def test_rejects_each_reused_old_provenance_identity(self):
        for new, old in (("source_head", "build_source_head"), ("source_index_tree", "build_index_tree"), ("source_tree_sha256", "source_tree_sha256")):
            manifest = dict(self.manifest, **{new: self.old[old]})
            with self.subTest(field=new), mock.patch.object(candidate.artifacts, "verify_manifest", return_value=manifest), self.assertRaisesRegex(ValueError, "cannot be relabeled"):
                candidate.prepare(self.root, self.manifest_path, [])

    def test_verifier_failure_propagates_without_candidate_record(self):
        with mock.patch.object(candidate.artifacts, "verify_manifest", side_effect=candidate.artifacts.ManifestError("binary checksum mismatch")), self.assertRaises(candidate.artifacts.ManifestError):
            candidate.prepare(self.root, self.manifest_path, [])

    def test_changed_internal_package_or_product_release_version_rejects_before_verification(self):
        for relative in (*candidate.PACKAGE_FILES, "protocol/versioning/src/lib.rs"):
            path = self.root / relative
            saved = path.read_text()
            expected = candidate.PACKAGE_VERSIONS.get(relative, "0.11.3")
            path.write_text(saved.replace(expected, "0.99.0"))
            with self.subTest(path=relative), mock.patch.object(candidate.artifacts, "verify_manifest") as verify, self.assertRaises(ValueError):
                candidate.prepare(self.root, self.manifest_path, [])
            verify.assert_not_called()
            path.write_text(saved)

    def test_any_lock_byte_drift_rejects_before_artifact_verification(self):
        path = self.root / "Cargo.lock"
        path.write_bytes(path.read_bytes() + b"\n")
        with mock.patch.object(candidate.artifacts, "verify_manifest") as verify, self.assertRaisesRegex(ValueError, "exact relation-bound Cargo.lock"):
            candidate.prepare(self.root, self.manifest_path, [])
        verify.assert_not_called()

    def test_checkout_preserves_relation_bound_package_and_lock_identity(self):
        candidate.require_candidate_versions(Path(__file__).resolve().parents[1])

    def test_retained_record_and_symlink_never_overwritten(self):
        output = self.root / "record.json"
        candidate.write_record(output, {"status": "candidate_unqualified"})
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            candidate.write_record(output, {})
        self.assertEqual(output.read_bytes(), before)
        link = self.root / "record-link.json"
        link.symlink_to(output)
        with self.assertRaises(FileExistsError):
            candidate.write_record(link, {})
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
