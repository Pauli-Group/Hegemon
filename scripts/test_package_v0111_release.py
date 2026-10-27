#!/usr/bin/env python3
"""Focused v0.11.1 profile controls using synthetic native headers, no execution."""
import copy
import io
import json
from pathlib import Path
import unittest
from unittest import mock

try:
    from . import package_v0111_release as hotfix
    from . import package_v011_release as base
    from . import test_package_v011_release as historical
except ImportError:
    import package_v0111_release as hotfix
    import package_v011_release as base
    import test_package_v011_release as historical


class HotfixProfileTests(unittest.TestCase):
    def setUp(self):
        self.fixture = historical.PackagingTests("test_four_platform_native_formats_and_architectures")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source, self.assets = self.fixture.source, self.fixture.assets
        actual = Path(__file__).absolute().parent.parent
        for name in (hotfix.WRAPPER_PATH, hotfix.PROFILE_PATH):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((actual / name).read_bytes())
        self.profile = dict(schema="hegemon.v0111.release-artifacts.v1", status="accepted", network_release="v0.11", software_release="v0.11.1", software_version="0.11.1", release_source_head="e" * 40, build_source_head="b" * 40, build_index_tree="c" * 40, source_tree_sha256="d" * 64, cargo_lock_sha256=base.CARGO_LOCK_SHA256, platform_manifests_sha256={})
        self.old_manifests = {selected: (self.assets / f"hegemon-release-assets-{selected}.json").read_bytes() for selected in base.PLATFORMS}
        for selected in base.PLATFORMS:
            path = self.assets / f"hegemon-release-assets-{selected}.json"
            manifest = json.loads(path.read_bytes())
            manifest.update(source_head=self.profile["build_source_head"], source_index_tree=self.profile["build_index_tree"], source_tree_sha256=self.profile["source_tree_sha256"])
            raw = base.encoded(manifest)
            path.write_bytes(raw)
            self.profile["platform_manifests_sha256"][selected] = base.sha(raw)
        (self.source / hotfix.PROFILE_PATH).write_bytes(base.encoded(self.profile))
        release_path = self.source / "config/testnet/0.11/release.json"
        release = json.loads(release_path.read_bytes())
        release.update(software_release="v0.11.1", software_version="0.11.1")
        release_path.write_bytes(base.encoded(release))

    def test_exact_profile_packages_four_hotfix_archives_and_keeps_network(self):
        output = self.fixture.root / "hotfix-output"
        with hotfix.artifact_profile(hotfix.load_profile(self.source)):
            manifests = base.validate_assets(self.assets)
            for selected in base.PLATFORMS:
                entries = base.members(self.source, self.assets, selected, manifests[selected], "f" * 40)
                bundle = json.loads(entries["bundle.json"][0])
                self.assertEqual((bundle["release"], bundle["software_release"], bundle["software_version"]), ("v0.11", "v0.11.1", "0.11.1"))
                self.assertEqual(bundle["binary_build_source_head"], self.profile["build_source_head"])
                self.assertIn(hotfix.WRAPPER_PATH, bundle["packaging_inputs"])
                self.assertIn(hotfix.PROFILE_PATH, bundle["packaging_inputs"])
                self.assertEqual(entries[f"provenance/hegemon-release-assets-{selected}.json"][0], manifests[selected][1])
                self.assertIn(b"v0.11.1 software", entries["QUICKSTART.md"][0])
                self.assertEqual(base.sha(entries["config/testnet/0.11/network-manifest.json"][0]), base.join.NETWORK_SHA256)
            base.package(self.source, self.assets, output, "f" * 40)
        archives = [path.name for path in output.iterdir() if path.name.endswith((".tar.gz", ".zip"))]
        self.assertEqual(set(archives), {f"hegemon-v0.11.1-{selected}" + (".zip" if selected.startswith("windows") else ".tar.gz") for selected in base.PLATFORMS})

    def test_pending_partial_wrong_labels_and_null_pins_rejected(self):
        for key in self.profile:
            value = copy.deepcopy(self.profile)
            value[key] = None
            with self.subTest(null_field=key), self.assertRaises(ValueError):
                hotfix.validate_profile(value)
        for selected in base.PLATFORMS:
            for replacement in (None, "invalid"):
                value = copy.deepcopy(self.profile)
                value["platform_manifests_sha256"][selected] = replacement
                with self.subTest(platform=selected, value=replacement), self.assertRaises(ValueError):
                    hotfix.validate_profile(value)
        value = copy.deepcopy(self.profile)
        value["status"] = "pending-ci-artifact-acceptance"
        (self.source / hotfix.PROFILE_PATH).write_bytes(base.encoded(value))
        with self.assertRaises(ValueError):
            hotfix.load_profile(self.source)
        output = self.fixture.root / "never-created"
        with mock.patch.object(hotfix, "load_profile", side_effect=ValueError("pending")), mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(hotfix.main(["--assets", str(self.assets), "--output", str(output), "--packaging-commit", "f" * 40]), 1)
        self.assertFalse(output.exists())

    def test_historical_profile_restored_after_success_and_failure(self):
        keys = ("SOFTWARE_RELEASE", "SOFTWARE_VERSION", "BUILD_SOURCE", "BUILD_TREE", "SOURCE_TREE_SHA256", "CARGO_LOCK_SHA256", "APPROVED_MANIFESTS", "SOURCE_FILES", "RELEASE_SOURCE")
        original = {key: copy.deepcopy(getattr(base, key)) for key in keys}
        with hotfix.artifact_profile(self.profile):
            self.assertEqual(base.SOFTWARE_RELEASE, "v0.11.1")
        self.assertEqual({key: getattr(base, key) for key in keys}, original)
        with self.assertRaises(RuntimeError):
            with hotfix.artifact_profile(self.profile):
                raise RuntimeError("simulated packaging failure")
        self.assertEqual({key: getattr(base, key) for key in keys}, original)

    def test_cross_profile_relabel_and_wrong_manifest_or_build_rejected(self):
        with self.assertRaises(ValueError):
            base.validate_assets(self.assets)
        for selected, raw in self.old_manifests.items():
            (self.assets / f"hegemon-release-assets-{selected}.json").write_bytes(raw)
        base.validate_assets(self.assets)
        with hotfix.artifact_profile(self.profile), self.assertRaises(ValueError):
            base.validate_assets(self.assets)
        for field, original in (("build_source_head", base.BUILD_SOURCE), ("build_index_tree", base.BUILD_TREE), ("source_tree_sha256", base.SOURCE_TREE_SHA256)):
            value = copy.deepcopy(self.profile)
            value[field] = original
            with self.subTest(field=field), self.assertRaises(ValueError):
                hotfix.validate_profile(value)
        value = copy.deepcopy(self.profile)
        value["platform_manifests_sha256"] = dict(base.APPROVED_MANIFESTS)
        with self.assertRaises(ValueError):
            hotfix.validate_profile(value)

    def test_old_profile_cannot_package_hotfix_metadata(self):
        for selected, raw in self.old_manifests.items():
            (self.assets / f"hegemon-release-assets-{selected}.json").write_bytes(raw)
        manifests = base.validate_assets(self.assets)
        with self.assertRaisesRegex(ValueError, "software metadata"):
            base.members(self.source, self.assets, "linux-x86_64", manifests["linux-x86_64"], "f" * 40)

    def test_new_authority_inputs_require_clean_committed_source(self):
        with hotfix.artifact_profile(self.profile):
            self.assertIn(hotfix.PROFILE_PATH, base.SOURCE_FILES)
            self.assertIn(hotfix.WRAPPER_PATH, base.SOURCE_FILES)
            tracked_without_profile = "\n".join(name for name in base.SOURCE_FILES if name != hotfix.PROFILE_PATH)
            with mock.patch.object(base.subprocess, "check_output", side_effect=["f" * 40, tracked_without_profile]), mock.patch.object(base.subprocess, "run"), self.assertRaisesRegex(ValueError, "committed"):
                base.require_committed_source(self.source, "f" * 40)


if __name__ == "__main__":
    unittest.main()
