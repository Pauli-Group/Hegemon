#!/usr/bin/env python3
"""Negative controls for the exact release-display and Cargo preservation boundary."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('successor',Path(__file__).with_name('check_v011_release_successor.py'))
successor=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=successor
spec.loader.exec_module(successor)

class VersionBoundary(unittest.TestCase):
    def test_unchanged_bytes_are_accepted(self):
        successor.validate_runtime_change('Cargo.lock',b'original',b'original')
    def test_every_cargo_version_bump_is_rejected(self):
        for path in successor.UNCHANGED_CARGO_PATHS:
            with self.subTest(path=path),self.assertRaises(successor.SuccessorError):
                successor.validate_runtime_change(path,b'version = "0.10.0"',b'version = "0.11.0"')
    def test_cargo_whitespace_and_dependency_changes_are_rejected(self):
        for after in (b'original\n',b'new-dependency',b'reordered'):
            with self.subTest(after=after),self.assertRaises(successor.SuccessorError):
                successor.validate_runtime_change('Cargo.lock',b'original',after)
    def test_unreviewed_source_path_is_rejected(self):
        with self.assertRaises(successor.SuccessorError):
            successor.validate_runtime_change('circuits/transaction/src/proof.rs',b'a',b'b')
    def test_exact_reviewed_postimage_is_accepted(self):
        from unittest.mock import patch
        pair=(successor.digest_bytes(b'before'),successor.digest_bytes(b'after'))
        with patch.dict(successor.REVIEWED_RUNTIME_DELTAS,{'exact/src/lib.rs':pair},clear=True):
            successor.validate_runtime_change('exact/src/lib.rs',b'before',b'after')
    def test_reviewed_path_does_not_allow_other_bytes(self):
        from unittest.mock import patch
        pair=(successor.digest_bytes(b'before'),successor.digest_bytes(b'after'))
        with patch.dict(successor.REVIEWED_RUNTIME_DELTAS,{'exact/src/lib.rs':pair},clear=True):
            for before,after in ((b'before',b'after\n'),(b'wrong',b'after')):
                with self.subTest(before=before,after=after),self.assertRaises(successor.SuccessorError):
                    successor.validate_runtime_change('exact/src/lib.rs',before,after)
    def test_runtime_allowance_has_only_three_display_sites_and_shutdown(self):
        self.assertEqual(set(successor.REVIEWED_RUNTIME_DELTAS),{'protocol/versioning/src/lib.rs','node/src/native/rpc.rs','wallet/src/bin/wallet.rs','node/src/native/util.rs'})
        self.assertFalse(set(successor.UNCHANGED_CARGO_PATHS)&set(successor.REVIEWED_RUNTIME_DELTAS))
    def test_escape_and_symlink_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'file').write_bytes(b'abc')
            for name in ('../file','/file','file/../file'):
                with self.assertRaises(successor.SuccessorError):
                    successor.safe_file(root,name)
            try:
                (root/'link').symlink_to(root/'file')
            except (OSError,NotImplementedError):
                return
            with self.assertRaises(successor.SuccessorError):
                successor.safe_file(root,'link')

class ReplayBoundary(unittest.TestCase):
    def receipt(self):
        return {'status':'PASS', 'actual_proof_verification':True,
                'node_sha256':'11'*32, 'artifact_manifest_sha256':'22'*32,
                'fixture_manifest_sha256':'16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0',
                'network_manifest_sha256':'ffda566f04cee22b2a7ba5c2be88f625e9c668f47a7765f36fb377c79ea25758',
                'canonical_blocks_verified':163, 'proof_cases_verified':6,
                'importer_started_at_genesis':True, 'importer_fixture_copied':False,
                'restart_verified':True, 'processes_reaped':True}
    def test_exact_replay_scope_is_accepted(self):
        successor.validate_replay(self.receipt(),'11'*32,'22'*32)
    def test_every_missing_replay_obligation_is_rejected(self):
        for key in self.receipt():
            with self.subTest(key=key):
                changed=self.receipt();del changed[key]
                with self.assertRaises(successor.SuccessorError):
                    successor.validate_replay(changed,'11'*32,'22'*32)
    def test_old_binary_or_wrong_artifact_receipt_is_rejected(self):
        for key in ('node_sha256','artifact_manifest_sha256','fixture_manifest_sha256','network_manifest_sha256'):
            with self.subTest(key=key):
                changed=self.receipt();changed[key]='ff'*32
                with self.assertRaises(successor.SuccessorError):
                    successor.validate_replay(changed,'11'*32,'22'*32)
    def test_partial_replay_and_copied_importer_are_rejected(self):
        for key,value in {'proof_cases_verified':5,'canonical_blocks_verified':162,'actual_proof_verification':False,'importer_started_at_genesis':False,'importer_fixture_copied':True,'restart_verified':False,'processes_reaped':False}.items():
            with self.subTest(key=key):
                changed=self.receipt();changed[key]=value
                with self.assertRaises(successor.SuccessorError):
                    successor.validate_replay(changed,'11'*32,'22'*32)
    def test_bool_cannot_replace_numeric_coverage(self):
        changed=self.receipt();changed['proof_cases_verified']=True
        with self.assertRaises(successor.SuccessorError):
            successor.validate_replay(changed,'11'*32,'22'*32)

if __name__=='__main__':
    unittest.main()
