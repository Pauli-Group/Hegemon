#!/usr/bin/env python3
"""Focused archive/launcher checks; no node, wallet or proof is executed."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from types import SimpleNamespace

try:
    from . import package_v011_release as pack
    from . import v011_join as join
except ImportError:  # Direct script invocation.
    import package_v011_release as pack
    import v011_join as join


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.assets = self.root / "assets"
        self.source.mkdir()
        self.assets.mkdir()
        actual = Path(__file__).absolute().parent.parent
        for name in pack.SOURCE_FILES:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((actual / name).read_bytes())
        release_path = self.source / "config/testnet/0.11/release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release.update(cutover_status="ready", public_genesis_pending=False, software_release="v0.11", software_version="0.11.0")
        release_path.write_bytes(pack.encoded(release))
        pins = {}
        for selected, (triple, fmt) in pack.PLATFORMS.items():
            rows = []
            for binary in pack.IDENTITIES:
                name = f"{binary}-{selected}" + (".exe" if selected.startswith("windows") else "")
                data = self.native(selected)
                (self.assets / name).write_bytes(data)
                digest = pack.sha(data)
                (self.assets / (name + ".sha256")).write_text(f"{digest}  {name}\n", encoding="ascii")
                rows.append(dict(package="wallet" if binary == "private-spend" else binary, binary=binary, name=name, sha256=digest, size=len(data), native_format=fmt, checksum_name=name + ".sha256"))
            raw = pack.encoded(dict(schema_version=1, source_head=pack.BUILD_SOURCE, source_index_tree=pack.BUILD_TREE, source_tree_sha256=pack.SOURCE_TREE_SHA256, cargo_lock_sha256=pack.CARGO_LOCK_SHA256, target_triple=triple, source_manifest_sha256="a" * 64, assets=rows))
            (self.assets / f"hegemon-release-assets-{selected}.json").write_bytes(raw)
            pins[selected] = pack.sha(raw)
        # Synthetic native headers replace only the fixture's reviewed manifest hashes.
        self.patch = mock.patch.dict(pack.APPROVED_MANIFESTS, pins, clear=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    @staticmethod
    def native(selected):
        data = bytearray(256)
        if selected.startswith("linux"):
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

    def fixture_bundle(self, selected="linux-x86_64"):
        manifests = pack.validate_assets(self.assets)
        entries = pack.members(self.source, self.assets, selected, manifests[selected], "b" * 40)
        bundle = self.root / ("bundle-" + selected)
        bundle.mkdir()
        for name, (data, mode) in entries.items():
            path = bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        return bundle, entries

    def test_four_platform_native_formats_and_architectures(self):
        self.assertEqual(set(pack.validate_assets(self.assets)), set(pack.PLATFORMS))
        for selected in pack.PLATFORMS:
            wrong = bytearray(self.native(selected))
            wrong[18 if selected.startswith("linux") else 4 if selected.startswith("macos") else 132] ^= 1
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                pack.native(wrong, selected)

    def test_exact_36_files_and_no_symlinks(self):
        for name in sorted(pack.expected_inputs()):
            original = self.assets / name
            saved = original.read_bytes()
            original.unlink()
            with self.subTest(missing=name), self.assertRaises((ValueError, OSError)):
                pack.validate_assets(self.assets)
            original.write_bytes(saved)
        (self.assets / "unexpected").write_bytes(b"x")
        with self.assertRaises(ValueError):
            pack.validate_assets(self.assets)
        (self.assets / "unexpected").unlink()
        binary = self.assets / "hegemon-node-linux-x86_64"
        saved = binary.read_bytes()
        binary.unlink()
        binary.symlink_to(self.source / "scripts/v011_join.py")
        with self.assertRaises(ValueError):
            pack.validate_assets(self.assets)
        binary.unlink()
        binary.write_bytes(saved)

    def test_changed_binary_sidecar_or_manifest_rejected(self):
        for name in ("wallet-linux-x86_64", "wallet-linux-x86_64.sha256", "hegemon-release-assets-linux-x86_64.json"):
            path = self.assets / name
            saved = path.read_bytes()
            path.write_bytes(saved + b"x")
            with self.subTest(name=name), self.assertRaises(ValueError):
                pack.validate_assets(self.assets)
            path.write_bytes(saved)

    def test_all_archives_deterministic_safe_modes_and_original_provenance(self):
        manifests = pack.validate_assets(self.assets)
        for selected in pack.PLATFORMS:
            with self.subTest(selected=selected):
                entries = pack.members(self.source, self.assets, selected, manifests[selected], "b" * 40)
                windows = selected.startswith("windows")
                first, second = self.root / (selected + ".one"), self.root / (selected + ".two")
                pack.write_archive(first, "bundle", entries, windows)
                pack.write_archive(second, "bundle", entries, windows)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                if windows:
                    with zipfile.ZipFile(first) as archive:
                        data = {name: archive.read(name) for name in archive.namelist()}
                        self.assertTrue(all(stat.S_ISREG(info.external_attr >> 16) for info in archive.infolist()))
                else:
                    with tarfile.open(first) as archive:
                        data = {entry.name: archive.extractfile(entry).read() for entry in archive}
                        self.assertTrue(all(entry.isfile() and entry.uid == entry.gid == entry.mtime == 0 and entry.mode in (0o644, 0o755) for entry in archive.getmembers()))
                self.assertEqual(set(data), {"bundle/" + name for name in entries})
                self.assertEqual(data[f"bundle/provenance/hegemon-release-assets-{selected}.json"], manifests[selected][1])
                self.assertNotIn(b"ExecutionPolicy", b"".join(value for key, value in data.items() if key.endswith((".cmd", ".sh"))))
                mapping = json.loads(data["bundle/bundle.json"])
                self.assertEqual(mapping["binary_build_source_head"], pack.BUILD_SOURCE)
                self.assertEqual(mapping["packaging_source_commit"], "b" * 40)
                self.assertEqual(len(mapping["binaries"]), 4)
                for line in data["bundle/SHA256SUMS"].decode().splitlines():
                    digest, name = line.split("  ")
                    self.assertEqual(digest, pack.sha(data["bundle/" + name]))

    def test_runtime_bundle_integrity_and_metadata(self):
        bundle, _ = self.fixture_bundle()
        self.assertEqual(join.verify_bundle(bundle, check_host=False), bundle / "bin/hegemon-node")
        (bundle / "bin/wallet").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            join.verify_bundle(bundle, check_host=False)

    def test_pending_metadata_prevents_any_output(self):
        path = self.source / "config/testnet/0.11/release.json"
        value = json.loads(path.read_bytes())
        value["cutover_status"] = "pending"
        path.write_bytes(pack.encoded(value))
        output = self.root / "output"
        with self.assertRaises(ValueError):
            pack.package(self.source, self.assets, output, "b" * 40)
        self.assertFalse(output.exists())

    def test_output_never_overwrites(self):
        output = self.root / "output"
        output.mkdir()
        marker = output / "retained"
        marker.write_text("keep")
        with self.assertRaises(ValueError):
            pack.package(self.source, self.assets, output, "b" * 40)
        self.assertEqual(marker.read_text(), "keep")

    def test_sync_and_wallet_rpc_arguments_never_start_a_node(self):
        bundle, _ = self.fixture_bundle()
        binary = bundle / "bin/hegemon-node"
        with mock.patch.object(join, "verify_bundle", return_value=binary):
            command, env = join.launch_command(bundle, join.arguments([]), {"HEGEMON_BOOTSTRAP_AUTHORING": "1", "HEGEMON_MINE": "0"})
            self.assertEqual(command[command.index("--rpc-methods") + 1], "safe")
            self.assertEqual(env["HEGEMON_MINE"], "0")
            self.assertEqual(env["HEGEMON_BOOTSTRAP_AUTHORING"], "0")
            self.assertEqual(env["HEGEMON_SEEDS"], ",".join(join.SEEDS))
            self.assertNotIn("--dev", command)
            self.assertNotIn("--rpc-external", command)
            self.assertNotIn("--tmp", command)
            command, _ = join.launch_command(bundle, join.arguments(["--wallet-rpc", "--data-dir", str(self.root / "chosen-state")]), {})
            self.assertEqual(command[command.index("--rpc-methods") + 1], "unsafe")
            self.assertNotIn("--rpc-external", command)

    def test_explicit_mining_requires_public_address_and_fixed_seeds(self):
        bundle, _ = self.fixture_bundle()
        with mock.patch.object(join, "verify_bundle", return_value=bundle / "bin/hegemon-node"):
            for argv, environment in ((["--mine"], {}), ([], {"HEGEMON_MINE": "true"}), ([], {"HEGEMON_SEEDS": "other:30333"}), ([], {"HEGEMON_NODE_BIN": "/other/node"}), ([], {"HEGEMON_MINER_ADDRESS": "shca1" + "q" * 110})):
                with self.subTest(argv=argv, environment=environment), self.assertRaises(ValueError):
                    join.launch_command(bundle, join.arguments(argv), environment)
            public = "shca1" + "q" * 110
            # Syntax-only launcher hygiene; the native node validates the real address.
            _, env = join.launch_command(bundle, join.arguments(["--mine", "--miner-address", public]), {})
            self.assertEqual(env["HEGEMON_MINE"], "1")
            self.assertEqual(env["HEGEMON_MINER_ADDRESS"], public)

    def test_port_arguments_use_native_flags_without_external_rpc(self):
        bundle, _ = self.fixture_bundle()
        with mock.patch.object(join, "verify_bundle", return_value=bundle / "bin/hegemon-node"):
            for argv, rpc, peer in (([], "9944", "30333"), (["--rpc-port", "39944", "--p2p-port", "30335"], "39944", "30335"), (["--rpc-port", "1", "--p2p-port", "65535"], "1", "65535")):
                command, _ = join.launch_command(bundle, join.arguments(argv), {})
                self.assertEqual(command[command.index("--rpc-port") + 1], rpc)
                self.assertEqual(command[command.index("--port") + 1], peer)
                self.assertNotIn("--rpc-external", command)

    def test_port_arguments_reject_out_of_range_or_non_integer(self):
        for option in ("--rpc-port", "--p2p-port"):
            for value in ("0", "65536", "-1", "1.5", "text"):
                with self.subTest(option=option, value=value), mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                    join.arguments([option, value])

    def test_checksum_path_traversal_and_symlink_rejected(self):
        bundle, _ = self.fixture_bundle()
        (bundle / "SHA256SUMS").write_text("a" * 64 + "  ../outside\n", encoding="ascii")
        with self.assertRaises(ValueError):
            join.verify_bundle(bundle, check_host=False)
        with self.assertRaises(ValueError):
            join.safe_file(bundle, "bin/../../outside")

    def test_windows_path_and_descriptor_timestamp_semantics(self):
        base = dict(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_birthtime_ns=5)
        path_stat = SimpleNamespace(**base, st_ctime_ns=5)
        opened_stat = SimpleNamespace(**base, st_ctime_ns=6)
        with mock.patch.object(join.os, "name", "nt"):
            self.assertTrue(join.path_matches_open_file(path_stat, opened_stat))
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns"):
                changed = dict(base)
                changed[key] += 1
                with self.subTest(field=key):
                    self.assertFalse(join.path_matches_open_file(path_stat, SimpleNamespace(**changed, st_ctime_ns=6)))


class AcceptedInputsTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("HEGEMON_V011_ACCEPTED_ASSETS"), "set HEGEMON_V011_ACCEPTED_ASSETS for the retained real 36-file set")
    def test_actual_accepted_16_binaries_and_manifests(self):
        manifests = pack.validate_assets(Path(os.environ["HEGEMON_V011_ACCEPTED_ASSETS"]))
        self.assertEqual(sum(len(value[0]["assets"]) for value in manifests.values()), 16)


if __name__ == "__main__":
    unittest.main()
