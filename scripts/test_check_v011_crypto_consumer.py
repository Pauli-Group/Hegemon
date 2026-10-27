#!/usr/bin/env python3
"""Synthetic controls for the proposed bounded successor receipt consumer."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
spec=importlib.util.spec_from_file_location('consumer',Path(__file__).with_name('check_release_crypto_profile.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class SuccessorConsumer(unittest.TestCase):
    def fixture(self):
        identity=dict(c.PRIVATE_LAUNCH_PROFILE,network_profile='pre-mainnet',chain_id='11'*32,genesis_hash='22'*32,manifest_digest='33'*64)
        artifacts=[{'binary':name,'sha256':str(i)*64} for i,(_,name) in enumerate(c.PRIVATE_LAUNCH_ARTIFACTS,1)]
        manifest={'target_triple':'synthetic-test','artifacts':artifacts}
        registry={'schema':'hegemon.private-spend.source-authorized-registry.v2','release':{'identity':identity},'final_artifacts':[]}
        r={'schema':'hegemon.private-spend.release-authorization.v2','authorization_kind':'qualified_source_tuple','status':'PASS_VERSION_SUCCESSOR_ARTIFACTS_AND_PUBLIC_PROOF_REPLAY','final_artifact_scope':'version_and_exact_platform_shutdown_successor_public_proof_replay','production_artifacts_verified':False,'affected_lifecycle_verified':False,'production_authorized':False,'deployment_verified':False,'public_cutover_authorized':False,'fresh_public_genesis_qualified':False,'predecessor_lifecycle_reexecuted':False,'version_only_artifacts_verified':True,'actual_new_binary_proof_verification':True,'unchanged_evidence_reused':True,'proof_and_protocol_runtime_unchanged':True,'cargo_metadata_unchanged':True,'runtime_files_compared':598,'new_version':'0.11.0','artifact_manifest_sha256':'aa'*32,'identity':identity,'qualified_identity':identity,'target_triple':'synthetic-test','artifact_sha256':{x['binary']:x['sha256'] for x in artifacts},'runtime_inventory_sha256':'dfd71b6a265e954261ed209c2ad3c34c97285016557f0f003f7f17f39ff541d0','changed_paths':['node/src/native/rpc.rs', 'node/src/native/util.rs', 'protocol/versioning/src/lib.rs', 'wallet/src/bin/wallet.rs']}
        r['public_proof_replay']={'status':'PASS','actual_proof_verification':True,'node_sha256':'1'*64,'artifact_manifest_sha256':'aa'*32,'fixture_manifest_sha256':'16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0','network_manifest_sha256':'ffda566f04cee22b2a7ba5c2be88f625e9c668f47a7765f36fb377c79ea25758','canonical_blocks_verified':163,'proof_cases_verified':6,'importer_started_at_genesis':True,'importer_fixture_copied':False,'restart_verified':True,'processes_reaped':True}
        return r,manifest,registry
    def check(self,r,m,g):return c.validate_private_launch_receipt(r,m,'aa'*32,g)
    def test_complete_synthetic_bounded_receipt_passes(self):
        r,m,g=self.fixture();self.assertEqual(self.check(r,m,g),r['identity'])
    def test_legacy_mode_does_not_accept_hotfix_version(self):
        r,m,g=self.fixture();r['new_version']='0.11.1'
        with self.assertRaises(SystemExit):self.check(r,m,g)
    def test_each_missing_top_level_obligation_rejects(self):
        r,m,g=self.fixture()
        for key in r:
            if key=='public_proof_replay':continue
            with self.subTest(key=key):
                bad=copy.deepcopy(r);del bad[key]
                with self.assertRaises(SystemExit):self.check(bad,m,g)
    def test_legacy_flags_must_stay_false(self):
        for key in ('production_artifacts_verified','affected_lifecycle_verified','production_authorized','deployment_verified','public_cutover_authorized','fresh_public_genesis_qualified','predecessor_lifecycle_reexecuted'):
            r,m,g=self.fixture();r[key]=True
            with self.subTest(key=key),self.assertRaises(SystemExit):self.check(r,m,g)
    def test_each_missing_replay_obligation_rejects(self):
        r,m,g=self.fixture()
        for key in r['public_proof_replay']:
            bad=copy.deepcopy(r);del bad['public_proof_replay'][key]
            with self.subTest(key=key),self.assertRaises(SystemExit):self.check(bad,m,g)
    def test_wrong_hashes_scope_or_coverage_rejects(self):
        for key,value in {'node_sha256':'ff'*32,'canonical_blocks_verified':162,'proof_cases_verified':5,'importer_fixture_copied':True,'restart_verified':False,'processes_reaped':False,'actual_proof_verification':False}.items():
            r,m,g=self.fixture();r['public_proof_replay'][key]=value
            with self.subTest(key=key),self.assertRaises(SystemExit):self.check(r,m,g)
    def test_bool_cannot_replace_count(self):
        r,m,g=self.fixture();r['runtime_files_compared']=True
        with self.assertRaises(SystemExit):self.check(r,m,g)
    def test_different_network_cannot_use_predecessor_evidence(self):
        r,m,g=self.fixture();r['identity']=dict(r['identity'],chain_id='ff'*32)
        with self.assertRaises(SystemExit):self.check(r,m,g)
    def test_wrong_binary_or_target_rejects(self):
        for key,value in [('artifact_sha256',{}),('target_triple','other')]:
            r,m,g=self.fixture();r[key]=value
            with self.subTest(key=key),self.assertRaises(SystemExit):self.check(r,m,g)
class LiteralDispatchBoundary(unittest.TestCase):
    def dispatch(self,argv):
        import ast,tempfile,types
        path=Path(__file__).with_name('check_private_spend_launch_authorization.py')
        parsed=ast.parse(path.read_text())
        dispatch=next(node for node in parsed.body if isinstance(node,ast.FunctionDef) and node.name=='main').body[0]
        self.assertIsInstance(dispatch,ast.If)
        wrapper=ast.parse('def main():\n    return 99\n')
        wrapper.body[0].body.insert(0,dispatch)
        ast.fix_missing_locations(wrapper)
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'config').mkdir();(root/'config/v011-release-successor.json').write_text('{}')
            def capture(command,cwd):
                self.assertEqual(cwd,root);calls.append(command);return 0
            scope={'ROOT':root,'sys':types.SimpleNamespace(executable=sys.executable,argv=['checker',*argv]),'subprocess':types.SimpleNamespace(call=capture)}
            exec(compile(wrapper,str(path),'exec'),scope)
            self.assertEqual(scope['main'](),0)
        self.assertEqual(len(calls),1)
        return calls[0]
    def test_both_literal_artifact_flag_forms_require_final_replay(self):
        for args in (['--artifact-manifest','proof.json'],['--artifact-manifest=proof.json']):
            with self.subTest(args=args):
                command=self.dispatch(['--require-authorized',*args])
                self.assertEqual(command[-1],'--require-final-artifact')
                self.assertEqual(command[4:-1],['--require-authorized',*args])
    def test_nonartifact_source_call_does_not_claim_artifact_phase(self):
        self.assertNotIn('--require-final-artifact',self.dispatch(['--require-authorized']))
    def test_similar_nonoption_is_not_recognized_as_artifact(self):
        self.assertNotIn('--require-final-artifact',self.dispatch(['--artifact-manifest-extra=proof.json']))

if __name__=='__main__':unittest.main()
