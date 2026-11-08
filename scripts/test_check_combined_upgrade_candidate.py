#!/usr/bin/env python3
"""Lightweight fail-closed candidate and preparation routing mutation controls."""
from __future__ import annotations
import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);out=importlib.util.module_from_spec(spec);spec.loader.exec_module(out);return out
gate=module('combined_gate_tests',ROOT/'scripts/check_combined_upgrade_candidate.py')
prep=module('combined_preparation_tests',ROOT/'scripts/prepare_premainnet_release.py')

class CandidateTests(unittest.TestCase):
    def test_real_source_relation_and_historical_authority(self):
        gate.authenticate(ROOT)
        self.assertEqual(gate.proof_identity(ROOT),gate.load_config(ROOT)['proof_identity'])

    def test_pending_cannot_authorize(self):
        c=gate.load_config(ROOT)
        if c['status']=='pending':
            with self.assertRaisesRegex(gate.CandidateError,'pending'):
                gate.review_check(ROOT,c)
        result=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/check_combined_upgrade_candidate.py'),'--prepare','--require-final-artifact'],capture_output=True)
        self.assertNotEqual(result.returncode,0)

    def test_config_rejects_authority_baseline_and_schema_mutations(self):
        for field,value in [('baseline_commit','0'*40),('scope','production'),('schema','old'),('status','approved')]:
            c=copy.deepcopy(gate.load_config(ROOT));c[field]=value
            with self.subTest(field=field),self.assertRaises(gate.CandidateError):gate.validate_config(c)
        for name in gate.BOUNDARIES:
            c=copy.deepcopy(gate.load_config(ROOT));c['boundaries'][name]=True
            with self.subTest(name=name),self.assertRaises(gate.CandidateError):gate.validate_config(c)

    def test_pending_cannot_smuggle_receipts_or_inventory(self):
        c=copy.deepcopy(gate.load_config(ROOT));c.update(status='pending',source_inventory=[],source_inventory_sha256=None,reviewed_delta=[],independent_review=None,qualification_commands=[])
        for field,value in [('independent_review',{'status':'PASS'}),('source_inventory',[{'path':'fake'}]),('qualification_commands',[{'name':'asert'}]),('reviewed_delta',[{'path':'fake'}])]:
            bad=copy.deepcopy(c);bad[field]=value
            with self.subTest(field=field),self.assertRaises(gate.CandidateError):gate.validate_config(bad)

    def test_evidence_paths_and_duplicate_json_reject(self):
        for raw in (b'{"status":1,"status":2}',b'[]'):
            with self.assertRaises(gate.CandidateError):gate.strict_json(raw)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'real').write_text('test');(root/'linked').symlink_to(root/'real')
            for path in ('../real','/etc/passwd','./real','linked'):
                with self.subTest(path=path),self.assertRaises(gate.CandidateError):gate.safe_file(root,path)
            with self.assertRaises(gate.CandidateError):gate.pinned_json(root,{'path':'real','bytes':4,'sha256':gate.sha(b'test')})

    def test_public_wire_evidence_is_bounded_regular_and_nonexecutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);subprocess.run(['git','init','-q',str(root)],check=True)
            # Ignoring the namespace must not hide executable or private files.
            (root/'.gitignore').write_text('release-evidence/\n')
            base=root/gate.EVIDENCE_ROOT;base.mkdir(parents=True)
            examples={'.smzl':b'SMZL'+bytes(128),'.hgps':b'HGPSLC02'+bytes(128),
                      '.action':bytes(48)+bytes.fromhex('0c00070001000f00')+bytes(128)}
            for suffix,raw in examples.items():
                path=base/('public'+suffix);path.write_bytes(raw)
            gate.inventory(root)
            for suffix in ('.py','.sh','.exe','.wallet','.seed'):
                path=base/('private-or-code'+suffix);path.write_bytes(b'not-public-wire')
                with self.subTest(suffix=suffix),self.assertRaises(gate.CandidateError):gate.inventory(root)
                path.unlink()
            for suffix,limit in (('.smzl',171848),('.hgps',177632),('.action',177857)):
                path=base/('public'+suffix);original=path.read_bytes();path.write_bytes(original+bytes(limit+1-len(original)))
                with self.subTest(cap=suffix),self.assertRaises(gate.CandidateError):gate.inventory(root)
                path.write_bytes(b'wrong-frame')
                with self.subTest(frame=suffix),self.assertRaises(gate.CandidateError):gate.inventory(root)
                path.write_bytes(original)
            executable=base/'public.smzl';executable.chmod(0o755)
            if executable.stat().st_mode & 0o111:
                with self.assertRaises(gate.CandidateError):gate.inventory(root)
            executable.chmod(0o644)
            relative=executable.relative_to(root).as_posix()
            subprocess.run(['git','-C',str(root),'add','-f',relative],check=True)
            subprocess.run(['git','-C',str(root),'update-index','--chmod=+x',relative],check=True)
            with self.assertRaises(gate.CandidateError):gate.inventory(root)
            subprocess.run(['git','-C',str(root),'update-index','--chmod=-x',relative],check=True)
            original=executable.read_bytes();executable.unlink();(root/'outside').write_bytes(original);executable.symlink_to(root/'outside')
            with self.assertRaises(gate.CandidateError):gate.inventory(root)

    def test_combined_workflow_has_source_diagnostics_and_four_final_gates(self):
        release=(ROOT/'.github/workflows/release.yml').read_text();workflow=prep.expected_workflow(release,combined=True)
        prep.verify_preparation(release,workflow,combined=True)
        self.assertEqual(workflow,(ROOT/'.github/workflows/prepare-premainnet-release.yml').read_text())
        self.assertEqual(workflow.count('scripts/check_combined_upgrade_candidate.py --prepare'),1)
        self.assertEqual(workflow.count('scripts/check_combined_upgrade_candidate.py --require-authorized'),4)
        self.assertEqual(workflow.count('--require-final-artifact'),4)
        self.assertIn('fetch-depth: 0',workflow)
        self.assertNotIn('contents: write',workflow)
        self.assertNotIn('softprops/action-gh-release',workflow)
        self.assertIn("if: github.event_name != 'pull_request'",workflow)
        for job in ('build-linux','build-macos-intel','build-macos-arm','build-windows'):
            block=re.split(r'\n  [A-Za-z0-9_-]+:\n',workflow.split('  '+job+':\n',1)[1],maxsplit=1)[0]
            self.assertIn('Install candidate qualification Lean toolchain',block)
            self.assertIn('formal/asert/lean-toolchain',block)
            self.assertLess(block.index('Install candidate qualification Lean toolchain'),block.index('Validate final common proof authorization'))
        ci=(ROOT/'.github/workflows/ci.yml').read_text().split('  release-binaries:\n',1)[1].split('\n  release-build:\n',1)[0]
        self.assertIn(prep.combined_lean_setup(),ci)
        commands=['scripts/check_combined_upgrade_candidate.py --prepare','scripts/check_combined_upgrade_candidate.py --require-authorized','--require-final-artifact','scripts/test_check_combined_upgrade_candidate.py','fetch-depth: 0','Install candidate qualification Lean toolchain','toolchain install','exact elan asset SHA256 unavailable']
        for command in commands:
            for changed in ('true',command+' || true','# '+command):
                with self.subTest(command=command,changed=changed),self.assertRaises(ValueError):prep.verify_preparation(release,workflow.replace(command,changed,1),combined=True)
        old=prep.expected_workflow(release,v0113=True)
        self.assertEqual(old.count('scripts/check_v0113_release_successor.py --require-authorized'),5)
        self.assertNotIn('scripts/check_combined_upgrade_candidate.py',old)

    def test_actual_check_exact_artifacts_source_scope_and_gate_inventory(self):
        # Parser fixture only; this is never written as qualification evidence.
        config={'source_inventory_sha256':'1'*64}
        artifacts={'artifact_manifest_sha256':'2'*64,'artifact_sha256':{'hegemon-node':'3'*64},'target_triple':'test-only'}
        for name in gate.CHECKS:
            value={'schema':'hegemon.combined-upgrade.actual-check.v1','name':name,'status':'PASS',
                   'candidate_binding_sha256':gate.binding(config),'source_inventory_sha256':'1'*64,
                   **artifacts,'actual_execution':True,'processes_reaped':True,**gate.BOUNDARIES,
                   'gates':dict.fromkeys(gate.REQUIRED_GATES[name],True)}
            gate.validate_check(value,name,config,artifacts)
            for field in ('candidate_binding_sha256','source_inventory_sha256','artifact_manifest_sha256','artifact_sha256','target_triple','actual_execution','processes_reaped','status'):
                changed=copy.deepcopy(value);changed[field]=False
                with self.subTest(name=name,field=field),self.assertRaises(gate.CandidateError):gate.validate_check(changed,name,config,artifacts)
            for flag in gate.BOUNDARIES:
                changed=copy.deepcopy(value);changed[flag]=True
                with self.subTest(name=name,flag=flag),self.assertRaises(gate.CandidateError):gate.validate_check(changed,name,config,artifacts)
            for required in gate.REQUIRED_GATES[name]:
                for bad in (False,1,None):
                    changed=copy.deepcopy(value);changed['gates'][required]=bad
                    with self.subTest(name=name,required=required,bad=bad),self.assertRaises(gate.CandidateError):gate.validate_check(changed,name,config,artifacts)
                changed=copy.deepcopy(value);del changed['gates'][required]
                with self.assertRaises(gate.CandidateError):gate.validate_check(changed,name,config,artifacts)
            changed=copy.deepcopy(value);changed['gates']['invented']=True
            with self.assertRaises(gate.CandidateError):gate.validate_check(changed,name,config,artifacts)

    def test_all_41_inputs_reject_changed_lock_and_symlink(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for item in gate.proof_identity(ROOT)['source_inputs']:
                path=root/item['path'];path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/item['path'],path)
            self.assertEqual(gate.proof_identity(root),gate.proof_identity(ROOT))
            lock=root/'Cargo.lock';original=lock.read_bytes();lock.write_bytes(original+b'\n')
            with self.assertRaises(gate.CandidateError):gate.proof_identity(root)
            lock.write_bytes(original);link=root/'crypto/src/traits.rs';data=link.read_bytes();link.unlink();(root/'replacement').write_bytes(data);link.symlink_to(root/'replacement')
            with self.assertRaises(gate.CandidateError):gate.proof_identity(root)

    def test_formatting_pending_and_new_debt_are_closed(self):
        from unittest import mock
        formatting=module('combined_formatting_mutations',ROOT/'scripts/check_combined_candidate_formatting.py')
        if gate.load_config(ROOT)['status']=='pending':
            with self.assertRaisesRegex(formatting.gate.CandidateError,'frozen'):
                formatting.policy(ROOT)
        synthetic={'status':'frozen','reviewed_delta':[],
                   'formatting_debt_migrations':[{'path':'new.rs','before_sha256':None,'after_sha256':'0'*64,'bytes':1}]}
        with mock.patch.object(formatting.gate,'load_config',return_value=synthetic),mock.patch.object(formatting.gate,'source_check'):
            with self.assertRaisesRegex(formatting.gate.CandidateError,'debt'):
                formatting.policy(ROOT)

    def test_ignored_automatic_rust_target_is_in_source_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);subprocess.run(['git','init','-q',str(root)],check=True)
            (root/'.gitignore').write_text('bin/\n')
            path=root/'wallet/src/bin/ignored.rs';path.parent.mkdir(parents=True);path.write_text('fn main() {}\n')
            found={r['path']:r for r in gate.inventory(root)}
            self.assertIn('wallet/src/bin/ignored.rs',found)
            self.assertEqual(found['wallet/src/bin/ignored.rs']['mode'],'100644')
            path.chmod(0o755)
            found={r['path']:r for r in gate.inventory(root)}
            self.assertEqual(found['wallet/src/bin/ignored.rs']['mode'],'100755')

    def test_binary_or_manifest_changes_after_qualification_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'node';binary.write_bytes(b'original')
            data={'artifacts':[{'binary':'hegemon-node','path':'node','sha256':gate.sha(b'original'),'size':8}]}
            manifest=root/'manifest.json';manifest.write_bytes(gate.canonical(data))
            receipt={'artifact_manifest_sha256':gate.sha(manifest.read_bytes()),'artifact_sha256':{'hegemon-node':gate.sha(b'original')}}
            gate.recheck_artifacts(root,manifest,receipt)
            binary.write_bytes(b'modified')
            with self.assertRaises(gate.CandidateError):gate.recheck_artifacts(root,manifest,receipt)
            binary.write_bytes(b'original');manifest.write_bytes(manifest.read_bytes()+b'\n')
            with self.assertRaises(gate.CandidateError):gate.recheck_artifacts(root,manifest,receipt)

    def test_final_receipt_cannot_pass_with_names_only(self):
        with self.assertRaises((gate.CandidateError,KeyError)):
            gate.validate_final_receipt({'final_artifact_scope':gate.SCOPE,'affected_checks':[{'name':n} for n in gate.CHECKS]}, {'target_triple':'fake','artifacts':[]},'0'*64,ROOT)

if __name__=='__main__':unittest.main()
