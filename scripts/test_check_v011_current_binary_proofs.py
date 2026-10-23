#!/usr/bin/env python3
"""Strict negative controls; fake subprocesses confer no proof authority."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('current_binary_proofs', ROOT / 'scripts/check_v011_current_binary_proofs.py')
policy = importlib.util.module_from_spec(spec); sys.modules[spec.name] = policy; spec.loader.exec_module(policy)

class CurrentBinaryProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hegemon-current-proof-tests-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
    def fixture(self):
        destination = self.directory / 'public'
        shutil.copytree(ROOT / 'release-evidence/v0.11-current-proof-fixture', destination)
        return destination / 'manifest.json'
    def test_real_public_fixture_and_current_source_inputs(self):
        m, files = policy.validate_fixture(self.fixture(), ROOT)
        self.assertEqual([r['name'] for r in m['cases']], list(policy.CASES))
        self.assertEqual(sum(r[k]['bytes'] for r in m['cases'] for k in ('proof','statement')), 859845)
        self.assertEqual(len(m['source_inputs']), 41)
        self.assertEqual(len(files), 53)
    def test_fixture_requires_exact_case_order_types_caps_and_public_boundary(self):
        p = self.fixture(); original = json.loads(p.read_text())
        mutations = []
        for field, value in (('schema','wrong'),('relation_digest','ab'*64),('cargo_lock_sha256','aa'*32),('cases',original['cases'][::-1]),('cases',original['cases'][:-1]),('source_inputs',[])):
            changed = copy.deepcopy(original); changed[field] = value; mutations.append(changed)
        for key, value in (('bytes',True),('bytes',policy.PROOF_CAP+1),('path','../ordinary.proof'),('sha256','aa'*32)):
            changed = copy.deepcopy(original); changed['cases'][0]['proof'][key] = value; mutations.append(changed)
        changed = copy.deepcopy(original); changed['disclosure']['wallets_or_keys_included'] = True; mutations.append(changed)
        changed = copy.deepcopy(original); changed['cases'][0]['statement']['bytes'] = 687; mutations.append(changed)
        for m in mutations:
            with self.subTest(m=m):
                p.write_text(json.dumps(m))
                with self.assertRaises(policy.CheckError): policy.validate_fixture(p, ROOT)
    def test_fixture_rejects_extra_file_and_modified_public_bytes(self):
        p = self.fixture(); extra = p.parent/'unlisted.key'; extra.write_bytes(b'not-a-real-key')
        with self.assertRaises(policy.CheckError): policy.validate_fixture(p, ROOT)
        extra.unlink(); proof=p.parent/'ordinary.proof'; raw=proof.read_bytes();proof.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaises(policy.CheckError): policy.validate_fixture(p, ROOT)
    def test_duplicate_json_keys_and_non_object_fail(self):
        p=self.directory/'value.json'
        for data in ('{"x":1,"x":2}','[]'):
            p.write_text(data)
            with self.assertRaises(policy.CheckError): policy.strict_json(p)
    def test_regular_directory_fifo_and_symlink_boundaries(self):
        with self.assertRaises(policy.CheckError): policy.regular(self.directory)
        p=self.directory/'file';p.write_bytes(b'data')
        with self.assertRaises(policy.CheckError): policy.regular(p,3)
        if os.name != 'nt':
            link=self.directory/'link';link.symlink_to(p)
            with self.assertRaises(policy.CheckError): policy.regular(link)
            real=self.directory/'real';real.mkdir();(real/'data').write_bytes(b'x')
            alias=self.directory/'alias';alias.symlink_to(real,target_is_directory=True)
            with self.assertRaises(policy.CheckError): policy.regular(alias/'data')
            fifo=self.directory/'fifo';os.mkfifo(fifo)
            with self.assertRaises(policy.CheckError): policy.regular(fifo)
    def test_success_output_is_exact_and_scoped(self):
        expected={'schema':'hegemon.offline-private-spend-verification.v1','verified':True,'scope':'cryptographic-verification-only','transaction_or_state_acceptance':False,'relation_digest':'ab'*64,'proof_bytes':171281,'public_bytes':688}
        policy.validate_success(expected,'ab'*64,171281)
        for key, value in (('verified',False),('transaction_or_state_acceptance',True),('scope','network'),('relation_digest','cd'*64),('proof_bytes',True),('public_bytes',True),('extra',True)):
            changed=dict(expected);changed[key]=value
            with self.subTest(key=key),self.assertRaises(policy.CheckError): policy.validate_success(changed,'ab'*64,171281)
    def test_negative_exit_codes_exclude_acceptance_panics_signals_and_ntstatus(self):
        policy.validate_rejection({'exit_code':1})
        for code in (0,101,-9,0xC0000005):
            with self.subTest(code=code),self.assertRaises(policy.CheckError):policy.validate_rejection({'exit_code':code})
    def test_windows_job_assignment_failure_kills_and_waits_owned_child(self):
        child=SimpleNamespace(returncode=None,killed=False,waited=False)
        child.poll=lambda:child.returncode
        def kill():child.killed=True;child.returncode=1
        def wait(timeout):child.waited=True;return child.returncode
        child.kill=kill;child.wait=wait
        with patch.object(policy,'os',SimpleNamespace(name='nt',environ=dict(os.environ))),patch.object(policy.subprocess,'CREATE_NEW_PROCESS_GROUP',512,create=True),patch.object(policy.subprocess,'Popen',return_value=child),patch.object(policy,'WindowsJob',side_effect=policy.CheckError('job assignment failed')):
            with self.assertRaisesRegex(policy.CheckError,'job assignment'):
                policy.run_command(['not-executed'],self.directory,'windows-job-failure',time.monotonic()+3)
        self.assertTrue(child.killed);self.assertTrue(child.waited)
    def test_hash_snapshot_detects_change(self):
        p=self.directory/'data';p.write_bytes(b'a');before=policy.snapshot([p]);p.write_bytes(b'b')
        self.assertNotEqual(before,policy.snapshot([p]))
    def test_owned_success_and_error_processes_are_reaped(self):
        for code in (0,1,101):
            r=policy.run_command([sys.executable,'-I','-B','-c',f'raise SystemExit({code})'],self.directory,str(code),time.monotonic()+3)
            self.assertEqual(r['exit_code'],code);self.assertTrue(r['processes_reaped'])
    def test_timeout_is_a_failed_check_and_owned_child_is_reaped(self):
        with self.assertRaisesRegex(policy.CheckError,'timeout'):
            policy.run_command([sys.executable,'-I','-B','-c','import time;time.sleep(20)'],self.directory,'timeout',time.monotonic()+0.1)
    def test_log_overflow_is_a_failed_check(self):
        with self.assertRaisesRegex(policy.CheckError,'output exceeds bound'):
            policy.run_command([sys.executable,'-I','-B','-c','print("x"*70000)'],self.directory,'overflow',time.monotonic()+3)
    @unittest.skipIf(os.name == 'nt','POSIX descendant process-group control')
    def test_surviving_descendant_is_never_a_pass(self):
        code='import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"])'
        with self.assertRaisesRegex(policy.CheckError,'descendants'):
            policy.run_command([sys.executable,'-I','-B','-c',code],self.directory,'descendant',time.monotonic()+3)
    def test_artifact_helper_pin_matches_reviewed_canonical_bytes(self):
        self.assertEqual(policy.sha(ROOT / 'scripts/release_artifact_manifest.py'), policy.ARTIFACT_HELPER_SHA256)
        self.assertEqual(policy.sha(ROOT / 'scripts/check_release_launcher_policy.py'), policy.LAUNCHER_POLICY_SHA256)
    def test_changed_artifact_helper_is_rejected_before_import(self):
        root = self.directory / 'changed-helper-root'; root.mkdir()
        (root / 'Cargo.lock').write_bytes(b'lock')
        (root / 'scripts').mkdir()
        helper = root / 'scripts/release_artifact_manifest.py'
        helper.write_text('raise AssertionError("unreviewed helper executed")\n')
        artifacts = []
        for package, binary in (('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'), ('walletd', 'walletd')):
            f = root / binary; f.write_bytes(b'inert-' + binary.encode())
            artifacts.append({'package': package, 'binary': binary, 'path': binary, 'size': f.stat().st_size, 'sha256': policy.sha(f)})
        manifest = root / 'artifacts.json'
        manifest.write_text(json.dumps({'schema_version': 1, 'cargo_lock_sha256': policy.sha(root / 'Cargo.lock'), 'artifacts': artifacts}))
        with patch.object(policy.importlib.util, 'spec_from_file_location') as loader:
            with self.assertRaisesRegex(policy.CheckError, 'helper changed before import'):
                policy.verify_artifacts(root / 'hegemon-node', manifest, root)
            loader.assert_not_called()
    def test_changed_transitive_launcher_policy_is_rejected_before_helper_import(self):
        root = self.directory / 'changed-launcher-root'; root.mkdir()
        (root / 'Cargo.lock').write_bytes(b'lock')
        (root / 'scripts').mkdir()
        shutil.copyfile(ROOT / 'scripts/release_artifact_manifest.py', root / 'scripts/release_artifact_manifest.py')
        (root / 'scripts/check_release_launcher_policy.py').write_text('raise AssertionError("unreviewed launcher policy executed")\n')
        artifacts = []
        for package, binary in (('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'), ('walletd', 'walletd')):
            f = root / binary; f.write_bytes(b'inert-' + binary.encode())
            artifacts.append({'package': package, 'binary': binary, 'path': binary, 'size': f.stat().st_size, 'sha256': policy.sha(f)})
        manifest = root / 'artifacts.json'
        manifest.write_text(json.dumps({'schema_version': 1, 'cargo_lock_sha256': policy.sha(root / 'Cargo.lock'), 'artifacts': artifacts}))
        with patch.object(policy.importlib.util, 'spec_from_file_location') as loader:
            with self.assertRaisesRegex(policy.CheckError, 'launcher policy changed before helper import'):
                policy.verify_artifacts(root / 'hegemon-node', manifest, root)
            loader.assert_not_called()
    def test_artifact_manifest_requires_exact_three_files_before_execution(self):
        root=self.directory/'root';root.mkdir();(root/'Cargo.lock').write_bytes(b'lock')
        node=root/'node';node.write_bytes(b'inert')
        m=root/'artifacts.json';m.write_text(json.dumps({'schema_version':1,'cargo_lock_sha256':policy.sha(root/'Cargo.lock'),'artifacts':[]}))
        with self.assertRaisesRegex(policy.CheckError,'three artifacts'):policy.verify_artifacts(node,m,root)
        payload=json.loads(m.read_text());payload['artifacts']=[{'package':a,'binary':b,'path':'../outside','size':1,'sha256':'ab'*32} for a,b in (('hegemon-node','hegemon-node'),('wallet','wallet'),('walletd','walletd'))];m.write_text(json.dumps(payload))
        with self.assertRaisesRegex(policy.CheckError,'path invalid'):policy.verify_artifacts(node,m,root)

if __name__ == '__main__': unittest.main()
