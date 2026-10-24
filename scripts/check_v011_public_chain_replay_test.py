#!/usr/bin/env python3
"""Public fixture extraction and replay failure controls; no live nodes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

MODULE = Path(__file__).with_name("check_v011_public_chain_replay.py")
SPEC = importlib.util.spec_from_file_location("public_replay", MODULE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def sample():
    files = [{"path": "native-chain.sled/" + name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in (("db", b"public ledger"), ("conf", b"configuration"))]
    bodies = [{"height": height, "block_hash": "0x" + f"{height:064x}", "body_sha256": "a" * 64} for height in range(1, 164)]
    proofs = {name: {"height": height, "block_hash": bodies[height - 1]["block_hash"], "canonical_body_sha256": "a" * 64, "action_sha256": "b" * 64, "bytes": 5, "action_body_hash": "0x" + "c" * 96} for height, name in enumerate(sorted(m.CASES), 1)}
    return {"schema": "hegemon.public-qualification-chain-fixture.v1", "genesis_hash": "0x" + "0" * 64, "chain_id": "1" * 64, "network_manifest_sha256": "2" * 64, "archive": {"path": "native-chain.sled.tar.gz", "sha256": "3" * 64, "bytes": 1}, "files": files, "canonical_bodies": bodies, "proof_cases": proofs, "proof_count": 6, "contains_wallets_or_peer_seeds": False}


class PublicReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hegemon-public-replay-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.manifest = sample()

    def bundle(self, entries=None):
        archive = self.root / "native-chain.sled.tar.gz"
        if entries is None:
            entries = [("native-chain.sled/db", b"public ledger", tarfile.REGTYPE), ("native-chain.sled/conf", b"configuration", tarfile.REGTYPE)]
        with tarfile.open(archive, "w:gz") as output:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                info.linkname = "../../outside" if kind != tarfile.REGTYPE else ""
                output.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        self.manifest["archive"].update(bytes=archive.stat().st_size, sha256=m.sha(archive))
        return archive

    def test_real_public_fixture_manifest_is_complete(self):
        fixture = MODULE.parents[1] / "release-evidence/v0.11-public-chain-fixture/manifest.json"
        self.assertEqual(len(m.validate_fixture(m.read_json(fixture))), 26)

    def test_verified_extract_writes_only_fresh_donor(self):
        archive = self.bundle()
        donor = self.root / "donor"
        m.extract_fixture(self.manifest, archive, donor)
        self.assertEqual((donor / "native-chain.sled/db").read_bytes(), b"public ledger")
        self.assertFalse((self.root / "importer").exists())
        with self.assertRaises(FileExistsError):
            m.extract_fixture(self.manifest, archive, donor)

    def test_archive_hash_mismatch_rejects_before_creating_state(self):
        archive = self.bundle()
        self.manifest["archive"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(m.ReplayError, "archive digest"):
            m.extract_fixture(self.manifest, archive, self.root / "donor")
        self.assertFalse((self.root / "donor").exists())

    def test_path_traversal_absolute_windows_and_secret_files_reject(self):
        for index, name in enumerate(("../escape", "/escape", "native-chain.sled/../escape", "native-chain.sled\\db", "C:/escape", "pq-identity.seed", "wallet.store")):
            archive = self.bundle([(name, b"malicious", tarfile.REGTYPE)])
            with self.assertRaises(m.ReplayError):
                m.extract_fixture(self.manifest, archive, self.root / f"donor-{index}")
        self.assertFalse((self.root / "escape").exists())

    def test_links_special_files_and_duplicate_entries_reject(self):
        for index, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE)):
            archive = self.bundle([("native-chain.sled/db", b"", kind)])
            with self.assertRaises(m.ReplayError):
                m.extract_fixture(self.manifest, archive, self.root / f"donor-{index}")
        archive = self.bundle([("native-chain.sled/db", b"public ledger", tarfile.REGTYPE)] * 2)
        with self.assertRaisesRegex(m.ReplayError, "duplicate"):
            m.extract_fixture(self.manifest, archive, self.root / "duplicate")

    def test_missing_file_or_changed_file_rejects(self):
        for index, entries in enumerate(([('native-chain.sled/db', b'public ledger', tarfile.REGTYPE)], [('native-chain.sled/db', b'altered bytes', tarfile.REGTYPE)])):
            archive = self.bundle(entries)
            with self.assertRaises(m.ReplayError):
                m.extract_fixture(self.manifest, archive, self.root / f"donor-{index}")

    def test_manifest_rejects_secret_inventory_oversize_and_partial_cases(self):
        variants = []
        value = copy.deepcopy(self.manifest); value['files'][0]['path'] = 'native-chain.sled/pq-identity.seed'; variants.append(value)
        value = copy.deepcopy(self.manifest); value['files'][0]['bytes'] = m.MAX_EXPANDED + 1; variants.append(value)
        value = copy.deepcopy(self.manifest); value['proof_cases'].pop('claim'); variants.append(value)
        value = copy.deepcopy(self.manifest); value['canonical_bodies'].pop(); variants.append(value)
        value = copy.deepcopy(self.manifest); value['contains_wallets_or_peer_seeds'] = True; variants.append(value)
        for value in variants:
            with self.assertRaises(m.ReplayError):
                m.validate_fixture(value)

    def test_scale_decoder_rejects_truncation_noncanonical_and_trailing(self):
        self.assertEqual(m.actions(bytes([4, 12]) + b'abc'), [b'abc'])
        for encoded in (b'', b'\x01\x00', b'\x04\x0cxy', b'\x00x'):
            with self.assertRaises(m.ReplayError):
                m.actions(encoded)

    def test_duplicate_json_keys_reject(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(m.ReplayError, "duplicate"):
            m.read_json(path)

    def test_artifact_hash_and_exact_path_are_bound(self):
        node = self.root / 'target/node'
        node.parent.mkdir()
        node.write_bytes(b'new executable')
        artifact = self.root / 'artifact.json'
        row = {'package':'hegemon-node','binary':'hegemon-node','path':'target/node','size':node.stat().st_size,'sha256':m.sha(node)}
        artifact.write_text(json.dumps({'schema_version':1,'artifacts':[row]}))
        with patch.object(m, 'ROOT', self.root):
            m.bind_artifact(artifact, node)
            node.write_bytes(b'changed executable')
            with self.assertRaisesRegex(m.ReplayError, 'does not match'):
                m.bind_artifact(artifact, node)

    def test_failure_receipt_reaps_owned_nodes_and_never_passes(self):
        output = self.root / 'failed-run'
        fake = Mock(stopped=False)
        def stop():
            fake.stopped = True
        fake.stop.side_effect = stop
        def failure(_args, _receipt, owned):
            owned.append(fake)
            raise m.ReplayError('injected import failure')
        with patch.object(m, 'run', side_effect=failure), patch('builtins.print'):
            code = m.main(['--node-bin', str(self.root / 'node'), '--artifact-manifest', str(self.root / 'artifacts.json'), '--output', str(output)])
        self.assertEqual(code, 1)
        result = json.loads((output / 'receipt.json').read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['actual_proof_verification'])
        self.assertTrue(result['processes_reaped'])
        fake.stop.assert_called_once()

    def test_cleanup_failure_prevents_pass_receipt(self):
        output = self.root / 'cleanup-failed'
        fake = Mock(stopped=True)
        fake.stop.side_effect = m.ReplayError('forced cleanup')
        def success(_args, receipt, owned):
            owned.append(fake)
            receipt['actual_proof_verification'] = True
        with patch.object(m, 'run', side_effect=success), patch('builtins.print'):
            code = m.main(['--node-bin', str(self.root / 'node'), '--artifact-manifest', str(self.root / 'artifacts.json'), '--output', str(output)])
        self.assertEqual(code, 1)
        result = json.loads((output / 'receipt.json').read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['processes_reaped'])

    @unittest.skipIf(os.name == 'nt', 'POSIX branch control; Windows uses actual job/CTRL-Break CI')
    def test_graceful_reap_and_forced_cleanup_failure(self):
        def owned():
            node = m.OwnedNode.__new__(m.OwnedNode)
            node.process = Mock(pid=123456, returncode=0)
            node.process.poll.side_effect = [None, 0]
            node.job = None
            node.stopped = False
            node.group_active = Mock(return_value=False)
            return node
        node = owned()
        with patch.object(m.os, 'killpg') as kill:
            node.stop()
            kill.assert_called_once_with(123456, m.signal.SIGTERM)
        self.assertTrue(node.stopped)
        node = owned()
        node.process.wait.side_effect = [subprocess.TimeoutExpired('node', 30), 0]
        with patch.object(m.os, 'killpg') as kill:
            with self.assertRaisesRegex(m.ReplayError, 'forced cleanup'):
                node.stop()
            self.assertEqual(kill.call_count, 2)
        self.assertTrue(node.stopped)


if __name__ == '__main__':
    unittest.main()
