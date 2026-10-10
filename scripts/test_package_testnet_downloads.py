#!/usr/bin/env python3
"""Exercise downloadable ZIP bindings using real assembled synthetic bundles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_testnet_downloads as downloads
import release_artifact_manifest as manifest


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()


def native_bytes(target, label):
    if "windows" in target:
        value = bytearray(68)
        value[0:2] = b"MZ"
        value[60:64] = (64).to_bytes(4, "little")
        value[64:68] = b"PE\0\0"
        return bytes(value) + label.encode()
    prefix = b"\x7fELF" if "linux" in target else b"\xcf\xfa\xed\xfe"
    return prefix + label.encode()


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hegemon-download-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.launchers = self.root / "release"
        self.launchers.mkdir()
        (self.root / "Cargo.lock").write_text("fixture lock\n")
        for name in ("TESTNET-README.txt", "testnet-start.sh", "testnet-start.ps1", "testnet-start.cmd"):
            (self.launchers / name).write_text(f"fixture {name}\n")
        git(self.root, "init", "--quiet")
        git(self.root, "add", "Cargo.lock", "release")
        git(self.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.provenance = {
            "source_head": git(self.root, "rev-parse", "HEAD"),
            "source_index_tree": git(self.root, "write-tree"),
            "source_tree_sha256": manifest.source_tree_sha256(self.root),
            "cargo_lock_sha256": downloads.digest((self.root / "Cargo.lock").read_bytes()),
        }
        self.bundle_manifests = []
        for platform, target in downloads.PLATFORMS.items():
            directory = self.root / "raw" / platform
            directory.mkdir(parents=True)
            assets = []
            for package, binary in manifest.EXPECTED_ARTIFACTS:
                suffix = ".exe" if "windows" in platform else ""
                name = f"{binary}-{platform}{suffix}"
                data = native_bytes(target, f"{platform}/{binary}")
                checksum = downloads.digest(data)
                (directory / name).write_bytes(data)
                (directory / f"{name}.sha256").write_text(f"{checksum}  {name}\n")
                assets.append({"package": package, "binary": binary, "name": name, "sha256": checksum, "size": len(data), "native_format": manifest.expected_format(target), "checksum_name": f"{name}.sha256"})
            payload = {"schema_version": 1, **self.provenance, "target_triple": target, "source_manifest_sha256": downloads.digest(f"source/{platform}".encode()), "assets": assets}
            path = directory / f"hegemon-release-assets-{platform}.json"
            path.write_text(json.dumps(payload, sort_keys=True) + "\n")
            self.bundle_manifests.append(path)
        self.assets = self.root / "assembled"
        # Use the production assembler rather than pretending the input was assembled.
        manifest.assemble_release_assets(self.root, self.bundle_manifests, self.assets)
        self.originals = {path.name: path.read_bytes() for path in self.assets.iterdir()}

    def package(self, assets=None):
        return downloads.package_downloads(self.root, assets or self.assets, self.launchers, "0.10.1")

    def assert_no_archives(self):
        self.assertFalse(list(self.assets.glob("*.zip")))
        self.assertFalse(list(self.assets.glob("hegemon-testnet-downloads-*")))

    def test_contents_modes_checksums_and_source_binding(self):
        result = self.package()
        self.assertEqual({field: result[field] for field in downloads.PROVENANCE_FIELDS}, self.provenance)
        self.assertEqual(result["release_version"], "0.10.1")
        self.assertEqual(len(result["archives"]), 4)
        for entry in result["archives"]:
            data = (self.assets / entry["name"]).read_bytes()
            self.assertEqual(entry["size"], len(data))
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual((self.assets / entry["checksum_name"]).read_text(), f"{entry['sha256']}  {entry['name']}\n")
            self.assertEqual(entry["asset_manifest_sha256"], downloads.digest(self.originals[entry["asset_manifest_name"]]))
            raw = json.loads(self.originals[entry["asset_manifest_name"]])
            binary_names = {item["name"] for item in raw["assets"]}
            expected = {entry["asset_manifest_name"], *downloads.launcher_names(entry["platform"])}
            for item in raw["assets"]:
                expected.update((item["name"], item["checksum_name"]))
            with zipfile.ZipFile(self.assets / entry["name"]) as archive:
                self.assertEqual(set(archive.namelist()), expected)
                self.assertEqual(archive.namelist(), sorted(expected))
                for info in archive.infolist():
                    self.assertEqual(info.date_time, downloads.FIXED_TIME)
                    mode = (info.external_attr >> 16) & 0o777
                    self.assertEqual(mode, 0o755 if info.filename in binary_names or info.filename == "testnet-start.sh" else 0o644)
                    source = self.originals.get(info.filename)
                    if source is None:
                        source = (self.launchers / info.filename).read_bytes()
                    self.assertEqual(archive.read(info), source)
        for name, data in self.originals.items():
            self.assertEqual((self.assets / name).read_bytes(), data)
        persisted = json.loads((self.assets / "hegemon-testnet-downloads-0.10.1.json").read_text())
        self.assertEqual(result, persisted)

    def test_reproducible_archives(self):
        second = self.root / "second"
        manifest.assemble_release_assets(self.root, self.bundle_manifests, second)
        first_result = self.package()
        self.assertEqual(first_result, self.package(second))
        for entry in first_result["archives"]:
            self.assertEqual((self.assets / entry["name"]).read_bytes(), (second / entry["name"]).read_bytes())

    def test_corrupt_binary_rejected_before_any_output(self):
        path = self.assets / "wallet-windows-x86_64.exe"
        path.write_bytes(path.read_bytes() + b"corrupted")
        with self.assertRaisesRegex(manifest.ManifestError, "does not match its manifest"):
            self.package()
        self.assert_no_archives()

    def test_corrupt_checksum_rejected(self):
        (self.assets / "wallet-linux-x86_64.sha256").write_text("wrong checksum\n")
        with self.assertRaisesRegex(manifest.ManifestError, "checksum does not match"):
            self.package()
        self.assert_no_archives()

    def test_platform_provenance_disagreement_rejected(self):
        path = self.assets / "hegemon-release-assets-windows-x86_64.json"
        payload = json.loads(path.read_text())
        payload["source_head"] = "a" * 40
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(manifest.ManifestError, "do not share source provenance"):
            self.package()
        self.assert_no_archives()

    def test_common_provenance_must_match_current_checkout(self):
        for path in self.assets.glob("hegemon-release-assets-*.json"):
            payload = json.loads(path.read_text())
            payload["source_head"] = "a" * 40
            path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(manifest.ManifestError, "differs from checkout: source_head"):
            self.package()
        self.assert_no_archives()

    def test_manifest_change_between_preflight_and_packaging_rejected(self):
        original = downloads.load_bundle
        counts = {}
        def swapping(root, assets, platform):
            counts[platform] = counts.get(platform, 0) + 1
            if counts[platform] == 2:
                path = assets / f"hegemon-release-assets-{platform}.json"
                path.write_text(path.read_text() + " ")
            return original(root, assets, platform)
        with patch.object(downloads, "load_bundle", side_effect=swapping):
            with self.assertRaisesRegex(manifest.ManifestError, "changed during packaging"):
                self.package()
        self.assert_no_archives()

    def test_launcher_must_match_committed_source(self):
        (self.launchers / "testnet-start.sh").write_text("unreviewed launcher\n")
        with self.assertRaisesRegex(manifest.ManifestError, "differs from committed source"):
            self.package()
        self.assert_no_archives()

    def test_symlink_and_portable_fallback_rejected(self):
        path = self.assets / "wallet-linux-x86_64"
        target = self.root / "external-wallet"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        for portable in (False, True):
            with self.subTest(portable=portable):
                with patch.object(manifest, "_descriptor_relative_io_available", return_value=not portable):
                    with self.assertRaises(manifest.ManifestError):
                        self.package()
        self.assert_no_archives()

    def test_extra_file_or_existing_outputs_rejected_without_overwrite(self):
        extra = self.assets / "surprise.txt"
        extra.write_text("unexpected\n")
        with self.assertRaisesRegex(manifest.ManifestError, "file-set mismatch"):
            self.package()
        self.assert_no_archives()
        extra.unlink()
        result = self.package()
        originals = {entry["name"]: (self.assets / entry["name"]).read_bytes() for entry in result["archives"]}
        with self.assertRaisesRegex(manifest.ManifestError, "file-set mismatch"):
            self.package()
        for name, data in originals.items():
            self.assertEqual((self.assets / name).read_bytes(), data)

    def test_missing_launcher_or_platform_rejected(self):
        missing = self.launchers / "testnet-start.cmd"
        missing.unlink()
        with self.assertRaises(manifest.ManifestError):
            self.package()
        self.assert_no_archives()


if __name__ == "__main__":
    unittest.main()
