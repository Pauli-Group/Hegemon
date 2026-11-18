#!/usr/bin/env python3
"""Check local candidate provenance and archives with fixture executable headers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("v0116_candidate_packager", ROOT / "scripts/package_v0116_candidate.py")
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def native_header(selected):
    data = bytearray(256)
    if selected == "linux-x86_64":
        data[:6] = b"\x7fELF\x02\x01"
        data[18:20] = (62).to_bytes(2, "little")
    elif selected.startswith("macos"):
        data[:4] = b"\xcf\xfa\xed\xfe"
        data[4:8] = (0x0100000C if selected.endswith("arm64") else 0x01000007).to_bytes(4, "little")
    else:
        data[:2] = b"MZ"
        data[60:64] = (128).to_bytes(4, "little")
        data[128:134] = b"PE\0\0\x64\x86"
    return bytes(data)


def archive_files(archive):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            return {name: handle.read(name) for name in handle.namelist()}
    with tarfile.open(archive, "r:gz") as handle:
        return {member.name: handle.extractfile(member).read() for member in handle.getmembers()}


class CandidatePackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="v0116-candidate-")
        self.addCleanup(temporary.cleanup)
        self.area = Path(temporary.name).resolve()
        self.root = self.area / "source"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        (self.root / ".gitignore").write_text("/target/\n", encoding="ascii")
        for name in (
            "Cargo.lock",
            "protocol/versioning/src/lib.rs",
            "config/release-launcher-policy.json",
            "config/testnet/0.11/network-manifest.json",
            "config/testnet/0.11/release-v0115.json",
            "config/testnet/0.11/release-v0116.json",
            "scripts/v011_join.py",
            "runbooks/miner_wallet_quickstart.md",
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.notes = self.root / "docs/releases/V0.11.6_PREPARATION.md"
        self.notes.parent.mkdir(parents=True)
        self.notes.write_text("Fixture local candidate notes.\n", encoding="ascii")
        self.git("add", ".")
        self.git("commit", "-qm", "candidate fixture")
        self.artifacts = self.root / "target/release"
        self.artifacts.mkdir(parents=True)
        self.manifest = self.root / "target/source-manifest.json"
        self.output = self.area / "output"
        # Fixture headers are platform-specific data. The actual manifest and
        # archive verifiers run, while the CLI execution gate has a stand-in.
        cli = mock.patch.object(pack, "verify_product_cli", autospec=True)
        self.cli = cli.start()
        self.addCleanup(cli.stop)

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Packaging Tests", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", "-C", str(self.root), *args],
            text=True,
        ).strip()

    def make_manifest(self, selected):
        suffix = ".exe" if selected.startswith("windows") else ""
        specs = []
        for package, binary in pack.artifacts.EXPECTED_ARTIFACTS:
            path = self.artifacts / (binary + suffix)
            path.write_bytes(native_header(selected) + binary.encode("ascii"))
            path.chmod(0o755)
            specs.append(f"{package}:{binary}:{path.relative_to(self.root).as_posix()}")
        pack.artifacts.create_manifest(self.root, self.manifest, pack.base.PLATFORMS[selected][0], specs)

    def test_candidate_archives_preserve_source_and_assets_on_each_platform(self):
        for selected, (triple, _) in pack.base.PLATFORMS.items():
            with self.subTest(platform=selected):
                self.make_manifest(selected)
                archive = pack.package(self.root, selected, self.manifest, self.output / selected)
                self.assertEqual(self.cli.call_args.args[1], selected)
                prefix = f"hegemon-v0.11.6-local-candidate-{selected}"
                windows = selected.startswith("windows")
                self.assertEqual(archive.name, prefix + (".zip" if windows else ".tar.gz"))
                files = archive_files(archive)
                self.assertTrue(all(name.startswith(prefix + "/") for name in files))
                files = {name.removeprefix(prefix + "/"): data for name, data in files.items()}
                record = json.loads(files["bundle.json"])
                assets_bytes = files[f"provenance/hegemon-release-assets-{selected}.json"]
                assets = json.loads(assets_bytes)
                self.assertEqual(record["build_channel"], "local-candidate")
                self.assertEqual(record["software_version"], "0.11.6")
                self.assertEqual(record["platform"], selected)
                self.assertEqual(record["binary_build_source_head"], self.git("rev-parse", "HEAD"))
                self.assertEqual(record["binary_build_index_tree"], self.git("rev-parse", "HEAD^{tree}"))
                self.assertEqual(record["original_manifest_sha256"], sha(assets_bytes))
                self.assertEqual(assets["target_triple"], triple)
                self.assertEqual(assets["source_manifest_sha256"], sha(self.manifest.read_bytes()))
                self.assertEqual(files["provenance/hegemon-release-artifacts.json"], self.manifest.read_bytes())
                self.assertEqual({name for name in files if name.startswith("provenance/")}, {
                    "provenance/hegemon-release-artifacts.json",
                    f"provenance/hegemon-release-assets-{selected}.json",
                })
                self.assertEqual(files["RELEASE_NOTES.md"], self.notes.read_bytes())
                self.assertEqual(files["config/testnet/0.11/release.json"],
                                 (self.root / "config/testnet/0.11/release-v0116.json").read_bytes())
                for row in assets["assets"]:
                    binary = row["binary"] + (".exe" if windows else "")
                    data = files["bin/" + binary]
                    self.assertEqual(data, (self.artifacts / binary).read_bytes())
                    self.assertEqual(row["sha256"], sha(data))
                expected_sums = "".join(f"{sha(data)}  {name}\n" for name, data in sorted(files.items())
                                        if name != "SHA256SUMS")
                self.assertEqual(files["SHA256SUMS"], expected_sums.encode("ascii"))
                self.assertEqual(archive.with_name(archive.name + ".sha256").read_text(encoding="ascii"),
                                 f"{sha(archive.read_bytes())}  {archive.name}\n")

    def test_changed_binary_and_committed_source_rejected_before_output(self):
        self.make_manifest("linux-x86_64")
        binary = self.artifacts / "wallet"
        original = binary.read_bytes()
        binary.write_bytes(original + b"changed")
        with self.assertRaisesRegex(pack.artifacts.ManifestError, "digest/metadata mismatch"):
            pack.package(self.root, "linux-x86_64", self.manifest, self.output)
        self.assertFalse(self.output.exists())
        binary.write_bytes(original)
        self.notes.write_text("Modified notes.\n", encoding="ascii")
        self.git("add", str(self.notes))
        self.git("commit", "-qm", "changed source")
        with self.assertRaisesRegex(pack.artifacts.ManifestError, "source_head"):
            pack.package(self.root, "linux-x86_64", self.manifest, self.output)
        self.assertFalse(self.output.exists())
        self.cli.assert_not_called()

    def test_rejects_wrong_platform_and_failed_product_check_without_output(self):
        self.make_manifest("macos-arm64")
        with self.assertRaisesRegex(ValueError, "target triple"):
            pack.package(self.root, "macos-x86_64", self.manifest, self.output)
        self.assertFalse(self.output.exists())
        self.cli.assert_not_called()
        self.cli.side_effect = ValueError("candidate reports the wrong product version")
        with self.assertRaisesRegex(ValueError, "wrong product version"):
            pack.package(self.root, "macos-arm64", self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_candidate_output_is_never_overwritten(self):
        self.make_manifest("linux-x86_64")
        archive = pack.package(self.root, "linux-x86_64", self.manifest, self.output)
        sidecar = archive.with_name(archive.name + ".sha256")
        archive.write_bytes(b"existing archive")
        sidecar.write_bytes(b"existing checksum")
        with self.assertRaisesRegex(ValueError, "empty directory"):
            pack.package(self.root, "linux-x86_64", self.manifest, self.output)
        self.assertEqual(archive.read_bytes(), b"existing archive")
        self.assertEqual(sidecar.read_bytes(), b"existing checksum")


if __name__ == "__main__":
    unittest.main()
