#!/usr/bin/env python3
"""Exercise v0.11 launcher boundaries using a fake node, never a live peer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PreMainnetLauncherTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="hegemon-v011-launcher-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "release source"
        self.root.mkdir()
        shutil.copyfile(ROOT / "start.sh", self.root / "start.sh")
        self.release_dir = self.root / "config/testnet/0.11"
        self.release_dir.mkdir(parents=True)
        self.home = Path(self.scratch.name) / "operator home"
        self.home.mkdir()
        self.node = self.root / "target/release/hegemon-node"
        self.node.parent.mkdir(parents=True)
        self.node.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "print(json.dumps({'argv': sys.argv[1:], 'env': {key: os.getenv(key) for key in "
            "('HEGEMON_MINE', 'HEGEMON_MINER_ADDRESS', 'HEGEMON_SEEDS', 'HEGEMON_BOOTSTRAP_AUTHORING')}}))\n"
        )
        self.node.chmod(0o755)
        self.manifest = self.release_dir / "network-manifest.json"
        self.manifest.write_text(json.dumps({"profile": "pre-mainnet"}) + "\n")
        self.record = {
            "schema": "hegemon.pre-mainnet.release.v1",
            "release": "v0.11",
            "network": "pre-mainnet",
            "cutover_status": "ready",
            "network_manifest_sha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            "seeds": ["hegemon.pauli.group:30333", "devnet.hegemonprotocol.com:30333"],
        }
        self.write_record()

    def write_record(self):
        (self.release_dir / "release.json").write_text(json.dumps(self.record) + "\n")

    def launch(self, overrides=None, arguments=()):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home)}
        env.update(overrides or {})
        return subprocess.run(
            ["bash", str(self.root / "start.sh"), *arguments],
            env=env, cwd=self.home, capture_output=True, text=True, timeout=10,
            check=False,
        )

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def rejected(self, result, reason):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "", "fake node must not run on rejection")
        self.assertIn(reason, result.stderr)

    def test_default_is_manifest_bound_sync_only_with_new_state(self):
        result = self.success(self.launch({"HEGEMON_BOOTSTRAP_AUTHORING": "1"}))
        self.assertEqual(result["argv"], [
            "--network", "pre-mainnet",
            "--network-manifest", str(self.manifest),
            "--base-path", str(self.home / ".hegemon-node-v0.11"),
            "--rpc-port", "9944", "--rpc-methods", "safe", "--name", "Hegemon-v0.11",
        ])
        self.assertNotIn("--dev", result["argv"])
        self.assertEqual(result["env"], {
            "HEGEMON_MINE": "0", "HEGEMON_MINER_ADDRESS": "",
            "HEGEMON_SEEDS": ",".join(self.record["seeds"]),
            "HEGEMON_BOOTSTRAP_AUTHORING": "0",
        })

    def test_mining_requires_explicit_public_recipient(self):
        result = self.success(self.launch({
            "HEGEMON_MINE": "1", "HEGEMON_MINER_ADDRESS": "public-test-recipient",
        }))
        self.assertEqual(result["env"]["HEGEMON_MINE"], "1")
        self.assertEqual(result["env"]["HEGEMON_MINER_ADDRESS"], "public-test-recipient")
        for value in ("", " \t "):
            self.rejected(self.launch({"HEGEMON_MINE": "1", "HEGEMON_MINER_ADDRESS": value}),
                          "HEGEMON_MINER_ADDRESS must")

    def test_nonbinary_mining_flag_rejects(self):
        self.rejected(self.launch({"HEGEMON_MINE": "true"}), "HEGEMON_MINE must be 0 or 1")

    def test_pending_cutover_cannot_be_bypassed_by_environment(self):
        self.record["cutover_status"] = "pending"
        self.write_record()
        self.rejected(self.launch({"HEGEMON_CUTOVER_READY": "1"}), "cutover is pending")

    def test_manifest_tampering_rejects(self):
        self.manifest.write_text('{"profile":"pre-mainnet","changed":true}\n')
        self.rejected(self.launch(), "network-manifest SHA-256 mismatch")

    def test_missing_network_record_rejects(self):
        (self.release_dir / "release.json").unlink()
        self.rejected(self.launch(), "Cannot start v0.11")

    def test_wrong_release_identity_rejects(self):
        self.record["release"] = "v0.10.3"
        self.write_record()
        self.rejected(self.launch(), "release/network identity mismatch")

    def test_wrong_manifest_profile_rejects_even_when_rehashed(self):
        self.manifest.write_text('{"profile":"development"}\n')
        self.record["network_manifest_sha256"] = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.write_record()
        self.rejected(self.launch(), "network manifest must select pre-mainnet")

    def test_seed_rotation_and_legacy_environment_reject(self):
        self.rejected(self.launch({"HEGEMON_SEEDS": "devnet.hegemonprotocol.com:30333"}),
                      "differs from the versioned release seed list")
        self.record["seeds"].reverse()
        self.write_record()
        self.rejected(self.launch(), "primary seed must be")

    def test_invalid_or_duplicate_seeds_reject(self):
        for seeds in ([], ["hegemon.pauli.group:30333"] * 2,
                      ["hegemon.pauli.group:99999"], ["hegemon.pauli.group:30333\n"]):
            self.record["seeds"] = seeds
            self.write_record()
            self.rejected(self.launch(), "Cannot start v0.11")

    def test_positional_arguments_cannot_override_frozen_network(self):
        self.rejected(self.launch(arguments=("--dev",)), "Usage:")

    def test_existing_chain_and_wallet_files_are_preserved(self):
        markers = []
        for name in (".hegemon-node", ".hegemon-node-v0.11", ".hegemon-wallet"):
            directory = self.home / name
            directory.mkdir()
            marker = directory / "existing-data"
            marker.write_bytes(b"keep existing bytes\x00\xff")
            markers.append(marker)
        self.success(self.launch())
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"keep existing bytes\x00\xff")

    def test_explicit_binary_and_state_paths_are_preserved(self):
        override = self.root / "installed node"
        shutil.copyfile(self.node, override)
        override.chmod(0o755)
        state = self.home / "selected v011 node"
        result = self.success(self.launch({"HEGEMON_NODE_BIN": str(override), "HEGEMON_NODE_PATH": str(state)}))
        self.assertEqual(result["argv"][result["argv"].index("--base-path") + 1], str(state))
        self.assertFalse(state.exists(), "launcher must leave state initialization to the node")

    def test_nonexecutable_binary_rejects(self):
        self.node.chmod(0o644)
        self.rejected(self.launch(), "Node binary is not executable")


if __name__ == "__main__":
    unittest.main()
