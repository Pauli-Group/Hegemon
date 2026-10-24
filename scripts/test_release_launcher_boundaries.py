#!/usr/bin/env python3
"""Portable source-policy and exact-file-set release boundary regressions.

The native bytes here are inert format fixtures, never executed. Every test uses
a tiny temporary Git checkout; no maintained source tree is hashed or built.
"""

from __future__ import annotations

import json
import os
import stat
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
import release_artifact_manifest as manifest


IDENTITIES = (("hegemon-node", "hegemon-node"), ("wallet", "wallet"), ("walletd", "walletd"))
FORMATS = {
    "elf": "x86_64-unknown-linux-gnu",
    "mach_o": "aarch64-apple-darwin",
    "pe": "x86_64-pc-windows-msvc",
}
ORIGINAL_BYPASS = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0testnet-start.ps1" %*\n'


def native_bytes(kind: str, discriminator: int) -> bytes:
    """Enough header bytes for the manifest's native-format detector only."""
    suffix = b"inert-release-fixture-" + str(discriminator).encode("ascii")
    if kind == "elf":
        return b"\x7fELF" + suffix
    if kind == "mach_o":
        return b"\xcf\xfa\xed\xfe" + suffix
    if kind == "pe":
        header = bytearray(64)
        header[:2] = b"MZ"
        header[60:64] = (64).to_bytes(4, "little")
        return bytes(header) + b"PE\0\0" + suffix
    raise ValueError(kind)


class ReleaseLauncherBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="hegemon-release-boundaries-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.policy = self.root / "config/release-launcher-policy.json"
        self.policy.parent.mkdir()
        self.policy.write_text(json.dumps({"schema_version": 1, "launchers": []}) + "\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        self.producer = self.root / "scripts/build_release_artifacts.sh"
        self.producer.parent.mkdir()
        self.producer.write_text("#!/usr/bin/env bash\nset -euo pipefail\n", encoding="utf-8")
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("add", ".gitignore", "Cargo.lock", "config", "scripts")
        self.git("-c", "user.name=Release Fixture", "-c", "user.email=release-fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={self.root / '.git/hooks'}",
                 "commit", "--quiet", "--no-verify", "-m", "Create inert source fixture")

    def git(self, *arguments: str) -> None:
        environment = os.environ.copy()
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            environment.pop(key, None)
        subprocess.run(["git", "-C", str(self.root), *arguments], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)

    def prepare_bundle(self, kind: str = "elf") -> tuple[list[str], Path, Path, list[str]]:
        suffix = ".exe" if kind == "pe" else ""
        binary_directory = self.target / "native"
        binary_directory.mkdir()
        specs: list[str] = []
        assets: list[str] = []
        for index, (package, binary) in enumerate(IDENTITIES):
            source = binary_directory / f"{binary}{suffix}"
            source.write_bytes(native_bytes(kind, index))
            specs.append(f"{package}:{binary}:{source}")
            assets.append(f"{package}:{binary}:{binary}-{kind}{suffix}")
        manifest_path = self.target / "native-manifest.json"
        payload = manifest.create_manifest(self.root, manifest_path, FORMATS[kind], specs)
        self.assertEqual(manifest.verify_manifest(self.root, manifest_path, specs), payload)
        bundle = self.target / "bundle"
        asset_manifest_name = f"hegemon-release-assets-{kind}.json"
        manifest.package_artifacts(self.root, manifest_path, specs, assets, bundle, asset_manifest_name)
        return specs, manifest_path, bundle / asset_manifest_name, assets

    @staticmethod
    def snapshot(directory: Path) -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in directory.iterdir()}

    def check_positive_chain(self, kind: str) -> None:
        specs, manifest_path, bundle_manifest, assets = self.prepare_bundle(kind)
        output = self.target / "assembled"
        payload = manifest.assemble_release_assets(self.root, [bundle_manifest], output)
        names = [spec.split(":", 2)[2] for spec in assets]
        expected = {bundle_manifest.name, *names, *(f"{name}.sha256" for name in names)}
        self.assertEqual(set(payload["files"]), expected)
        self.assertEqual(set(self.snapshot(output)), expected)
        self.assertEqual(self.snapshot(output), self.snapshot(bundle_manifest.parent))
        source_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        for key in ("source_head", "source_index_tree", "source_tree_sha256", "cargo_lock_sha256"):
            self.assertEqual(payload[key], source_payload[key])
        self.assertEqual(manifest.verify_manifest(self.root, manifest_path, specs), source_payload)

    def mutate_source(self, mutation: str) -> str:
        if mutation == "missing_policy":
            self.policy.unlink()
            return r"missing required file: config/release-launcher-policy\.json"
        if mutation == "original_bypass":
            self.producer.write_text(ORIGINAL_BYPASS, encoding="utf-8")
            return r"execution-policy weakening is forbidden: scripts/build_release_artifacts\.sh"
        if mutation == "unlisted_cmd":
            helper = self.root / "testnet-release/added.cmd"
            helper.parent.mkdir()
            helper.write_text('@echo off\n"%~dp0hegemon-node.exe" --testnet %*\n', encoding="utf-8")
            return r"release files are missing from the reviewed policy"
        raise ValueError(mutation)

    def check_source_boundary(self, boundary: str, mutation: str) -> None:
        specs, existing_manifest, bundle_manifest, assets = self.prepare_bundle()
        existing_bytes = existing_manifest.read_bytes()
        bundle_before = self.snapshot(bundle_manifest.parent)
        reason = self.mutate_source(mutation)
        output = self.target / f"rejected-{boundary}"
        with self.assertRaisesRegex(manifest.ManifestError, reason):
            if boundary == "create":
                manifest.create_manifest(self.root, output / "manifest.json", FORMATS["elf"], specs)
            elif boundary == "verify":
                # A missing manifest makes policy-before-manifest-read explicit.
                manifest.verify_manifest(self.root, output / "manifest.json", specs)
            elif boundary == "package":
                manifest.package_artifacts(self.root, existing_manifest, specs, assets, output,
                                           "hegemon-release-assets-rejected.json")
            elif boundary == "assemble":
                manifest.assemble_release_assets(self.root, [bundle_manifest], output)
            else:
                raise ValueError(boundary)
        self.assertFalse(output.exists(), "the rejected boundary created output")
        self.assertEqual(existing_manifest.read_bytes(), existing_bytes)
        self.assertEqual(self.snapshot(bundle_manifest.parent), bundle_before)

    def check_unexpected_bundle_file(self, suffix: str) -> None:
        _specs, _existing_manifest, bundle_manifest, _assets = self.prepare_bundle()
        bundle = bundle_manifest.parent
        original = self.snapshot(bundle)
        unexpected = bundle / f"unexpected{suffix}"
        unexpected.write_bytes(b"unexpected, inert archive/file fixture\n")
        changed = self.snapshot(bundle)
        output = self.target / "rejected-assembly"
        with self.assertRaisesRegex(manifest.ManifestError, r"release asset bundle file-set mismatch"):
            manifest.assemble_release_assets(self.root, [bundle_manifest], output)
        self.assertFalse(output.exists(), "assembly emitted output before rejecting an extra file")
        self.assertEqual(self.snapshot(bundle), changed, "rejection changed the input bundle")
        unexpected.unlink()
        self.assertEqual(self.snapshot(bundle), original)
        manifest.assemble_release_assets(self.root, [bundle_manifest], self.target / "restored-assembly")


    def tracked_source(self, name: str, *, executable: bool = False) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"same reviewed source bytes\n")
        path.chmod(0o755 if executable else 0o644)
        self.git("add", "--", name)
        self.git("update-index", "--chmod=+x" if executable else "--chmod=-x", "--", name)
        return path

    def test_tracked_modes_match_simulated_windows(self) -> None:
        self.tracked_source("ordinary.txt")
        self.tracked_source("executable.sh", executable=True)
        expected = manifest.source_tree_sha256(self.root)

        def windows_fstat(fd: int):
            value = os.fstat(fd)
            fields = {key: getattr(value, key) for key in dir(value) if key.startswith("st_")}
            fields["st_mode"] = (value.st_mode & ~0o777) | (
                0o777 if value.st_mode & stat.S_IXUSR else 0o666
            )
            return SimpleNamespace(**fields)

        windows_os = SimpleNamespace(**{**vars(os), "name": "nt", "fstat": windows_fstat})
        with mock.patch.object(manifest, "os", windows_os):
            self.assertEqual(manifest.source_tree_sha256(self.root), expected)

    def test_tracked_git_mode_changes_identity(self) -> None:
        path = self.tracked_source("mode.txt")
        before = manifest.source_tree_sha256(self.root)
        path.chmod(0o755)
        self.git("update-index", "--chmod=+x", "--", "mode.txt")
        self.assertNotEqual(manifest.source_tree_sha256(self.root), before)

    @unittest.skipUnless(os.name == "posix", "POSIX executable-bit consistency")
    def test_tracked_executable_mismatch_rejects(self) -> None:
        for executable in (False, True):
            with self.subTest(executable=executable):
                path = self.tracked_source("mode.txt", executable=executable)
                path.chmod(0o644 if executable else 0o755)
                with self.assertRaisesRegex(manifest.ManifestError, "executable mode disagrees"):
                    manifest.source_tree_sha256(self.root)
                path.chmod(0o755 if executable else 0o644)

    def test_tracked_hashes_unstaged_bytes(self) -> None:
        path = self.tracked_source("source.txt")
        before = manifest.source_tree_sha256(self.root)
        path.write_bytes(b"changed unstaged source bytes\n")
        self.assertNotEqual(manifest.source_tree_sha256(self.root), before)

    def test_untracked_source_bytes_and_native_mode_remain_bound(self) -> None:
        before = manifest.source_tree_sha256(self.root)
        path = self.root / "untracked.txt"
        path.write_bytes(b"untracked source bytes\n")
        path.chmod(0o644)
        created = manifest.source_tree_sha256(self.root)
        self.assertNotEqual(created, before)
        path.write_bytes(b"modified untracked source bytes\n")
        modified = manifest.source_tree_sha256(self.root)
        self.assertNotEqual(modified, created)
        if os.name == "posix":
            path.chmod(0o755)
            self.assertNotEqual(manifest.source_tree_sha256(self.root), modified)

    def test_malformed_unmerged_and_unsupported_index_reject(self) -> None:
        oid = b"1" * 40
        valid = b"100644 " + oid + b" 0\tCargo.lock\0"
        records = (
            b"not a Git index record\0",
            b"100644 " + oid + b" 1\tCargo.lock\0",
            b"120000 " + oid + b" 0\tCargo.lock\0",
            b"160000 " + oid + b" 0\tCargo.lock\0",
            valid + valid,
        )
        original = manifest.run_git
        for record in records:
            with self.subTest(record=record):
                def git(root, *args):
                    return record if args == ("ls-files", "--stage", "-z") else original(root, *args)
                with mock.patch.object(manifest, "run_git", side_effect=git):
                    with self.assertRaises(manifest.ManifestError):
                        manifest.source_tree_sha256(self.root)

    def test_missing_tracked_source_rejects(self) -> None:
        self.tracked_source("missing.txt").unlink()
        with self.assertRaisesRegex(manifest.ManifestError, "non-symlink"):
            manifest.source_tree_sha256(self.root)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink fixture")
    def test_tracked_source_symlinks_reject_on_both_io_paths(self) -> None:
        path = self.tracked_source("source.txt")
        data = path.read_bytes()
        destination = self.target / "source-copy.txt"
        destination.write_bytes(data)
        path.unlink()
        path.symlink_to(destination)
        for descriptor_io in (True, False):
            with self.subTest(descriptor_io=descriptor_io):
                with mock.patch.object(manifest, "_descriptor_relative_io_available", return_value=descriptor_io):
                    with self.assertRaisesRegex(manifest.ManifestError, "non-symlink|symlink"):
                        manifest.source_tree_sha256(self.root)
        path.unlink()
        path.write_bytes(data)
        path.chmod(0o644)
        nested = self.tracked_source("nested/source.txt")
        nested.unlink()
        nested.parent.rmdir()
        nested.parent.symlink_to(self.target, target_is_directory=True)
        for descriptor_io in (True, False):
            with self.subTest(ancestor=True, descriptor_io=descriptor_io):
                with mock.patch.object(manifest, "_descriptor_relative_io_available", return_value=descriptor_io):
                    with self.assertRaisesRegex(manifest.ManifestError, "non-symlink|symlink"):
                        manifest.source_tree_sha256(self.root)

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO fixture")
    def test_tracked_source_fifo_rejects_without_opening(self) -> None:
        path = self.tracked_source("source.txt")
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(manifest.ManifestError, "non-symlink"):
            manifest.source_tree_sha256(self.root)

    @unittest.skipUnless(os.name == "posix", "POSIX tab/newline filenames")
    def test_index_filename_tabs_and_newlines_are_preserved(self) -> None:
        path = self.tracked_source("source\twith\nseparators.txt")
        before = manifest.source_tree_sha256(self.root)
        path.write_bytes(b"different actual bytes\n")
        self.assertNotEqual(manifest.source_tree_sha256(self.root), before)

    def test_all_source_provenance_fields_still_reject_changes(self) -> None:
        specs, manifest_path, _bundle, _assets = self.prepare_bundle()
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        for field in ("source_head", "source_index_tree", "source_tree_sha256", "cargo_lock_sha256"):
            with self.subTest(field=field):
                changed = {**payload, field: "00" * 32}
                manifest_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(manifest.ManifestError, field + " does not match current source"):
                    manifest.verify_manifest(self.root, manifest_path, specs)
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")

def positive_case(kind: str):
    def test(self: ReleaseLauncherBoundaryTests) -> None:
        self.check_positive_chain(kind)
    return test


def source_case(boundary: str, mutation: str):
    def test(self: ReleaseLauncherBoundaryTests) -> None:
        self.check_source_boundary(boundary, mutation)
    return test


def bundle_case(suffix: str):
    def test(self: ReleaseLauncherBoundaryTests) -> None:
        self.check_unexpected_bundle_file(suffix)
    return test


for _kind in FORMATS:
    setattr(ReleaseLauncherBoundaryTests, f"test_native_{_kind}_chain", positive_case(_kind))
for _boundary in ("create", "verify", "package", "assemble"):
    for _mutation in ("missing_policy", "original_bypass", "unlisted_cmd"):
        setattr(ReleaseLauncherBoundaryTests, f"test_{_boundary}_rejects_{_mutation}", source_case(_boundary, _mutation))
for _suffix in (".cmd", ".ps1", ".zip"):
    setattr(ReleaseLauncherBoundaryTests, f"test_assembly_rejects_unexpected_{_suffix[1:]}", bundle_case(_suffix))


if __name__ == "__main__":
    unittest.main()
