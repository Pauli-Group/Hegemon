#!/usr/bin/env python3
"""Lightweight fail-closed candidate and preparation routing mutation controls."""
from __future__ import annotations
import copy
from contextlib import ExitStack, contextmanager
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);out=importlib.util.module_from_spec(spec);spec.loader.exec_module(out);return out
gate=module('combined_gate_tests',ROOT/'scripts/check_combined_upgrade_candidate.py')
prep=module('combined_preparation_tests',ROOT/'scripts/prepare_premainnet_release.py')
profile=module('combined_profile_routing_tests',ROOT/'scripts/check_release_crypto_profile.py')

@contextmanager
def profile_routing_fixture(configs, receipt):
    """Run the actual profile consumer with file presence and mocked proof boundaries."""
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        root=Path(tmp).resolve()
        for relative in configs:
            path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
        registry=root/'scripts/private_spend_launch_authorized_registry.json'
        registry.parent.mkdir(parents=True,exist_ok=True);registry.write_text('{}')
        manifest_path=root/'target/release/artifact-manifest.json'
        names=('hegemon-node','wallet','walletd','private-spend')
        manifest={'artifacts':[{'binary':name} for name in names],'target_triple':'fixture-only'}
        snapshot=(manifest,'manifest-fixture-digest',tuple(root/name for name in names),())
        stack.enter_context(patch.object(profile,'SOURCE_ROOT',root))
        stack.enter_context(patch.object(profile,'private_launch_snapshot',return_value=snapshot))
        stack.enter_context(patch.object(profile,'validate_binary_profile_markers'))
        stack.enter_context(patch.object(profile,'run_profile',return_value=None))
        stack.enter_context(patch.object(profile,'validate_private_launch_receipt',return_value={'fixture':True}))
        events=[]
        helpers={name:stack.enter_context(patch.object(profile,name,
            side_effect=lambda _root,name=name:events.append(name)))
            for name in ('combined_helper','sync_import_helper','v0113_helper')}
        run=stack.enter_context(patch.object(profile.subprocess,'run',return_value=
            subprocess.CompletedProcess([],0,json.dumps(receipt),'')))
        yield root,manifest_path,helpers,run,events

class V0114AdapterTests(unittest.TestCase):
    """Synthetic release-tuple controls; no native or historical execution."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.metadata = {'schema': 'hegemon.pre-mainnet.release.v1', 'release': 'v0.11',
                         'network': 'pre-mainnet', 'software_release': 'v0.11.4',
                         'software_version': '0.11.4'}
        self.write('config/testnet/0.11/release.json', json.dumps(self.metadata))
        self.write('protocol/versioning/src/lib.rs', 'pub const RELEASE_VERSION: &str = "0.11.4";\n')
        self.write('consensus-light-client/src/pow_rules.rs',
                   'pub const PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT: Option<u64> = Some(18_660);\n')

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_exact_release_tuple_and_current_source_are_accepted(self):
        gate.release_tuple(self.root)
        gate.release_tuple(ROOT)

    def test_release_metadata_missing_stale_and_nonstring_fields_reject(self):
        for field in self.metadata:
            for changed in ('missing', 'v0.11.3', None, False, 114, [], {}):
                metadata = dict(self.metadata)
                if changed == 'missing':
                    del metadata[field]
                else:
                    metadata[field] = changed
                self.write('config/testnet/0.11/release.json', json.dumps(metadata))
                with self.subTest(field=field, changed=changed), self.assertRaises(gate.CandidateError):
                    gate.release_tuple(self.root)

    def test_duplicate_release_metadata_rejects(self):
        self.write('config/testnet/0.11/release.json',
                   json.dumps(self.metadata)[:-1] + ',"software_version":"0.11.4"}')
        with self.assertRaisesRegex(gate.CandidateError, 'duplicate JSON key'):
            gate.release_tuple(self.root)

    def test_stale_missing_and_duplicate_product_declarations_reject(self):
        canonical = (self.root / 'protocol/versioning/src/lib.rs').read_text()
        for changed in (canonical.replace('0.11.4', '0.11.3'),
                        canonical.replace('0.11.4', '0.11.4-rc1'), '', canonical * 2):
            self.write('protocol/versioning/src/lib.rs', changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(gate.CandidateError, 'product version'):
                gate.release_tuple(self.root)

    def test_inactive_wrong_missing_and_duplicate_schedule_declarations_reject(self):
        canonical = (self.root / 'consensus-light-client/src/pow_rules.rs').read_text()
        for changed in (canonical.replace('Some(18_660)', 'None'),
                        canonical.replace('18_660', '18_720'),
                        canonical.replace('18_660', '120'), '', canonical * 2):
            self.write('consensus-light-client/src/pow_rules.rs', changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(gate.CandidateError, 'activation declaration'):
                gate.release_tuple(self.root)

    def test_linked_release_tuple_inputs_reject(self):
        for relative in ('config/testnet/0.11/release.json', 'protocol/versioning/src/lib.rs',
                         'consensus-light-client/src/pow_rules.rs'):
            path = self.root / relative
            raw = path.read_bytes()
            replacement = self.root / 'linked-copy'
            replacement.write_bytes(raw)
            path.unlink()
            path.symlink_to(replacement)
            with self.subTest(relative=relative), self.assertRaisesRegex(gate.CandidateError, 'symlink'):
                gate.release_tuple(self.root)
            path.unlink()
            path.write_bytes(raw)

    def test_source_preparation_checks_tuple_before_historical_authentication(self):
        config = {'status': 'pending', 'proof_identity': {}}
        self.write('protocol/versioning/src/lib.rs', 'pub const RELEASE_VERSION: &str = "0.11.3";\n')
        with patch.object(gate, 'authenticate') as authenticate, \
                patch.object(gate, 'proof_identity') as proof, patch.object(gate, 'inventory') as inventory:
            with self.assertRaisesRegex(gate.CandidateError, 'product version'):
                gate.source_check(self.root, config)
            authenticate.assert_not_called()
            proof.assert_not_called()
            inventory.assert_not_called()
        self.write('protocol/versioning/src/lib.rs', 'pub const RELEASE_VERSION: &str = "0.11.4";\n')
        with patch.object(gate, 'authenticate', return_value={}) as authenticate, \
                patch.object(gate, 'proof_identity', return_value={}) as proof:
            result = gate.source_check(self.root, config)
        authenticate.assert_called_once_with(self.root)
        proof.assert_called_once_with(self.root)
        self.assertEqual(result['status'], 'PASS_PENDING_SOURCE_PREPARATION')
        self.assertFalse(result['source_frozen'])
        for name in gate.BOUNDARIES:
            self.assertIs(result[name], False)

    def test_active_executor_receives_v0114_override_and_keeps_authority_false(self):
        self.write('scripts/check_v011_release_successor.py', '# authenticated executor fixture\n')
        self.write('node/src/bin/native_node.rs', '// source fixture\n')
        self.write('config/v0113-release-successor.json', json.dumps({'current_identity': {'fixture': True}}))
        self.write('config/testnet/0.11/network-manifest.json', '{}')
        helper = SimpleNamespace(CURRENT_RUNTIME_DELTAS={})
        observed = []
        def artifact_gate(root, predecessor, manifest, receipt, network, reserve):
            observed.append((helper.CURRENT_NEW_VERSION, helper.CURRENT_SOURCE_KIND, helper.CURRENT_SCOPE))
            return receipt
        helper.artifact_gate = Mock(side_effect=artifact_gate)
        helper.final_replay = Mock(side_effect=lambda root, manifest, receipt, reserve: receipt)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
        config = {'source_inventory_sha256': '1' * 64, 'independent_review': None}
        manifest = self.root / 'artifact-manifest.json'
        with patch.object(gate.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(gate.importlib.util, 'module_from_spec', return_value=helper), \
                patch.object(gate, 'fresh_checks', return_value=[]), \
                patch.object(gate, 'recheck_artifacts'), patch.object(gate, 'load_config', return_value=config), \
                patch.object(gate, 'source_check'), patch.object(gate, 'review_check'):
            result = gate.final_artifacts(self.root, config, manifest, 4)
        self.assertEqual(observed, [('0.11.4', gate.KIND, gate.SCOPE)])
        helper.artifact_gate.assert_called_once()
        helper.final_replay.assert_called_once()
        spec.loader.exec_module.assert_called_once_with(helper)
        self.assertEqual(result['status'], 'PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE')
        for name in gate.BOUNDARIES:
            self.assertIs(result[name], False)

class CandidateTests(unittest.TestCase):
    def test_profile_combined_route_skips_present_historical_helpers(self):
        configs=(profile.COMBINED_CONFIG,'config/v011-release-successor.json',
            'config/v011-sync-import-successor-20261106.json','config/v0113-release-successor.json')
        receipt={'final_artifact_scope':profile.COMBINED_SCOPE,'candidate_binding_sha256':'a'*64}
        with profile_routing_fixture(configs,receipt) as (root,manifest,helpers,run,events):
            result=profile.private_launch_profile(root,manifest)
            self.assertEqual(events,['combined_helper'])
            helpers['combined_helper'].assert_called_once_with(root)
            helpers['sync_import_helper'].assert_not_called()
            helpers['v0113_helper'].assert_not_called()
            run.assert_called_once_with([sys.executable,'-I','-B',
                str(root/'scripts/check_combined_upgrade_candidate.py'),'--require-authorized',
                '--artifact-manifest','target/release/artifact-manifest.json',
                '--require-final-artifact'],cwd=root,capture_output=True,text=True,timeout=44400)
            self.assertEqual(result['mode'],'executed-combined-upgrade-software-candidate')
            for field in ('production_authority','private_spend_launch_authority',
                    'current_network_G8_qualified','public_cutover_authorized',
                    'mainnet_authorized','activation_authorized','physical_asic_qualified'):
                self.assertIs(result[field],False)

    def test_profile_combined_helper_failure_cannot_fall_back_to_history(self):
        configs=(profile.COMBINED_CONFIG,'config/v011-release-successor.json',
            'config/v011-sync-import-successor-20261106.json','config/v0113-release-successor.json')
        with profile_routing_fixture(configs,{}) as (root,manifest,helpers,run,events):
            helpers['combined_helper'].side_effect=SystemExit('combined authentication failed')
            with self.assertRaisesRegex(SystemExit,'combined authentication failed'):
                profile.private_launch_profile(root,manifest)
            helpers['combined_helper'].assert_called_once_with(root)
            helpers['sync_import_helper'].assert_not_called()
            helpers['v0113_helper'].assert_not_called()
            run.assert_not_called()
            self.assertEqual(events,[])

    def test_profile_combined_executor_failure_cannot_fall_back_to_history(self):
        configs=(profile.COMBINED_CONFIG,'config/v011-release-successor.json',
            'config/v011-sync-import-successor-20261106.json','config/v0113-release-successor.json')
        with profile_routing_fixture(configs,{}) as (root,manifest,helpers,run,events):
            run.return_value=subprocess.CompletedProcess([],1,'','combined qualification failed')
            with self.assertRaisesRegex(SystemExit,'combined qualification failed'):
                profile.private_launch_profile(root,manifest)
            self.assertEqual(events,['combined_helper'])
            helpers['sync_import_helper'].assert_not_called()
            helpers['v0113_helper'].assert_not_called()
            self.assertEqual(run.call_count,1)
            self.assertEqual(Path(run.call_args.args[0][3]).name,'check_combined_upgrade_candidate.py')

    def test_profile_without_combined_preserves_historical_helper_order_and_priority(self):
        sync='config/v011-sync-import-successor-20261106.json'
        v0113='config/v0113-release-successor.json'
        for configs,events_expected,checker in (
                ((),[],'check_private_spend_launch_authorization.py'),
                ((sync,),['sync_import_helper'],'check_v011_sync_import_successor.py'),
                ((v0113,),['v0113_helper'],'check_v0113_release_successor.py'),
                ((sync,v0113),['sync_import_helper','v0113_helper'],'check_v0113_release_successor.py')):
            with self.subTest(configs=configs),profile_routing_fixture(
                    ('config/v011-release-successor.json',*configs),{}) as (root,manifest,helpers,run,events):
                profile.private_launch_profile(root,manifest)
                self.assertEqual(events,events_expected)
                helpers['combined_helper'].assert_not_called()
                expected=[sys.executable,'-I','-B',str(root/'scripts'/checker),
                    '--require-authorized','--artifact-manifest','target/release/artifact-manifest.json']
                if configs:expected.append('--require-final-artifact')
                run.assert_called_once_with(expected,cwd=root,capture_output=True,text=True,timeout=1300)

    def test_nested_failed_qualification_reports_bounded_child_reason(self):
        command = {'name': 'restart_reorg_fresh_sync', 'timeout_seconds': 7200,
                   'argv': ['python3', '-I', '-B', 'scripts/qualify_combined_upgrade.py',
                            '--artifact-manifest', '{artifact_manifest}']}
        config = {'source_inventory': [{'path': command['argv'][3]}],
                  'qualification_commands': [command]}
        root = Path('/public-fixture-only')
        stdout = b'old-stdout-prefix\n' + b'x' * 10000 + b'\npublic stdout context\n'
        stderr = b'old-stderr-prefix\n' + b'\xff' * 10000 + b'\nqualification command failed: exit=101; native panic: InsufficientWork\n'
        for exit_code, child_stderr in ((1, stderr), (0, b'unexpected stderr')):
            with self.subTest(exit_code=exit_code), patch.object(gate.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], exit_code, stdout, child_stderr)), \
                    patch.object(gate, 'validate_check') as validate:
                with self.assertRaises(gate.CandidateError) as failed:
                    gate.fresh_checks(root, config, {}, root / 'artifact.json')
                validate.assert_not_called()
            diagnostic = str(failed.exception)
            self.assertIn('fresh qualification failed: restart_reorg_fresh_sync', diagnostic)
            self.assertIn('exit=' + str(exit_code), diagnostic)
            self.assertIn('public stdout context', diagnostic)
            self.assertNotIn('old-stdout-prefix', diagnostic)
            stderr_tail, stdout_tail = diagnostic.split('stderr tail (4096 bytes):\n', 1)[1].split('\nstdout tail (4096 bytes):\n', 1)
            self.assertLessEqual(len(stderr_tail.encode('utf-8')), 4096)
            self.assertLessEqual(len(stdout_tail.encode('utf-8')), 4096)
            if exit_code:
                self.assertIn('native panic: InsufficientWork', diagnostic)
                self.assertIn('exit=101', diagnostic)
                self.assertNotIn('old-stderr-prefix', diagnostic)
            else:
                self.assertIn('unexpected stderr', diagnostic)

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
