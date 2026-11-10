#!/usr/bin/env python3
"""Build/component qualification only; normal current-chain inline replay remains mandatory."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, re, shutil, signal, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LEGACY_SHA='9ae765ffda1d334c4d0b0989887b59d68464bfaf8a82b1006a75cca792bee1f0'
LEGACY_SOURCE_SHA='21986c9da9276ab3f9de193e85d203552d4f0629f130e176e852131da009a5dd'
TEST_PREFIX='native::service::native_sync_inline_prefix_tests::'
TRANSPORT_TESTS=tuple(TEST_PREFIX+x for x in (
 'mixed_range_preserves_small_prefix_before_body_above_range_budget',
 'oversized_first_body_keeps_exact_single_locator',
 'requested_range_batches_across_unsolicited_announce_threshold',
 'inline_prefix_stops_at_existing_body_and_encrypted_frame_caps',
 'medium_proof_sized_bodies_batch_and_roundtrip_within_existing_budget',
 'medium_range_body_does_not_relax_unsolicited_announce_budget',
 'requested_range_does_not_skip_body_that_exceeds_remaining_budget',
 'body_egress_worst_case_reservation_keeps_one_positive_body_per_window',
 'empty_response_and_mismatched_encoding_count_keep_existing_contract'))
def need(v,m):
 if not v:raise RuntimeError(m)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
def write(path,value):
 with path.open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
def passed_once(text):
 return re.findall(r'^running .*$',text,re.M)==['running 1 test'] and len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;',text,re.M))==1

def verify_selector_failure(code,text,name,line):
 need(type(code)is int and code==101,'selector negative exit differs')
 need(re.findall(r'^running .*$',text,re.M)==['running 1 test'],'selector negative cardinality differs')
 summaries=re.findall(r'^test result: .*$',text,re.M)
 need(len(summaries)==1 and re.fullmatch(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s',summaries[0]),'selector negative summary differs')
 statuses=re.findall(r'^test (\S+) \.\.\.[^\n]*$',text,re.M)
 need(statuses==[name] and len(re.findall(r'^(?:FAILED|test '+re.escape(name)+r' \.\.\. FAILED)$',text,re.M))==1,'selector negative status differs')
 panics=re.findall(r"^thread '([^']+)'(?: \([0-9]+\))? panicked at ([^\n]+)$",text,re.M)
 location=f'node/src/native/service.rs:{line}:9:'
 need(panics==[(name,location)] and re.search(r"^thread '"+re.escape(name)+r"'(?: \([0-9]+\))? panicked at "+re.escape(location)+r"\nassertion `left == right` failed$",text,re.M),'selector negative panic attribution differs')
 failures=[]
 for block in re.findall(r'^failures:\n((?:[ \t]*\n|[ \t]+[^\n]+\n)*)',text,re.M):
  values=[v.strip()for v in block.splitlines()if v.strip()]
  if values:failures.append(values)
 need(failures==[[name]]and not re.search(r'^error(?:\[E[0-9]+\]:|: could not compile)',text,re.M),'selector negative failure names/compilation differs')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--expected-source-sha',required=True);p.add_argument('--expected-delta-sha256',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--pin-provenance',choices=('dispatch-inputs','root-external-check-required'),default='dispatch-inputs');a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 source=load('range_source',ROOT/'scripts/qualify_sync_range_transport_source.py')
 need(sha(ROOT/'scripts/qualify_sync_recovery_linux.py')==LEGACY_SHA and sha(ROOT/'scripts/qualify_sync_recovery_source.py')==LEGACY_SOURCE_SHA,'inherited executor source differs')
 old=load('range_legacy',ROOT/'scripts/qualify_sync_recovery_linux.py')
 receipt={'schema':'hegemon.sync-range-transport.components.v1','status':'RUNNING','source_head':a.expected_source_sha,'commands':[],'normal_inline_genuine_proof_import_verified':False,'fresh_current_chain_import_restart_verified':False,'full_scratch_replay_verified':False,'production_authorized':False,'deployment_verified':False,'historical_fixture_waived_or_relabelled':False,'root_external_acceptance_performed':False,'pin_provenance':a.pin_provenance,'external_expected_delta_check_required_root':a.pin_provenance=='root-external-check-required'}
 baseline=None
 def execute(argv,label,cwd=ROOT,timeout=1800):
  row,text=old.run(argv,out,label,cwd=cwd,timeout=timeout);receipt['commands'].append(row);return row,text
 try:
  before=source.validate_source(ROOT,a.expected_source_sha,a.expected_delta_sha256,pin_provenance=a.pin_provenance);write(out/'source-before.json',before)
  for path,pin in old.INHERITED.items():need(sha(ROOT/path)==pin,'inherited proof/build helper differs: '+path)
  need(sha(ROOT/'config/testnet/0.11/network-manifest.json')=='386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754','current manifest differs')
  inputs=ROOT/'target/build-inputs.json';need(inputs.is_file(),'fresh clone make setup/make node build receipt absent');receipt['build_inputs_sha256']=sha(inputs)
  for label,argv in [('rustc-version',['rustc','-vV']),('cargo-version',['cargo','-vV'])]:
   row,text=execute(argv,label,timeout=30);need(row['exit_code']==0,'compiler readback failed')
   if label=='rustc-version':need('release: 1.91.1\n'in text and 'host: x86_64-unknown-linux-gnu\n'in text,'actual compiler/platform differs')
  row,text=execute(old.cargo('hegemon-node')+['--','--list'],'transport-inventory')
  names=[x[:-6]for x in text.splitlines()if x.startswith(TEST_PREFIX)and x.endswith(': test')]
  need(row['exit_code']==0 and set(names)==set(TRANSPORT_TESTS)and len(names)==9,'exact nine transport-test inventory differs')
  baseline=Path(tempfile.mkdtemp(prefix='sync-range-selector-ablation-'))/'source'
  row,_=execute(['git','worktree','add','--detach',str(baseline),a.expected_source_sha],'selector-worktree',timeout=120);need(row['exit_code']==0,'cannot create owned selector ablation')
  service=baseline/'node/src/native/service.rs';text=service.read_text();needle='        if *body_len > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {\n';need(text.count(needle)==1,'selector ablation seam differs');service.write_text(text.replace(needle,'        if *body_len > MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES {\n',1))
  negative=TEST_PREFIX+'requested_range_batches_across_unsolicited_announce_threshold'
  row,text=execute(old.cargo('hegemon-node')+[negative,'--','--exact','--nocapture'],'selector-negative',cwd=baseline)
  pinned_text=(ROOT/'node/src/native/service.rs').read_text();function_start=pinned_text.index('    fn requested_range_batches_across_unsolicited_announce_threshold()');assertion=pinned_text.index('        assert_eq!(prefix, blocks);',function_start);assertion_line=pinned_text[:assertion].count('\n')+1
  verify_selector_failure(row['exit_code'],text,negative,assertion_line)
  receipt['restored_selector_negative_verified']=True
  for i,name in enumerate(TRANSPORT_TESTS+old.NEW_TESTS+old.CONTROLS):
   row,text=execute(old.cargo('hegemon-node')+[name,'--','--exact','--nocapture'],'exact-'+str(i));need(row['exit_code']==0 and passed_once(text),'exact test did not pass once: '+name)
  for i,(package,prefix)in enumerate(old.MODULES):
   row,text=execute(old.cargo(package)+['--','--list'],'module-list-'+str(i));names=[x[:-6]for x in text.splitlines()if x.startswith(prefix)and x.endswith(': test')];need(row['exit_code']==0 and names and len(names)==len(set(names)),'module inventory empty/duplicate')
   row,text=execute(old.cargo(package)+[prefix,'--','--nocapture'],'module-'+str(i));need(row['exit_code']==0 and re.search(r'test result: ok\. '+str(len(names))+r' passed; 0 failed; 0 ignored;',text),'module tests incomplete: '+prefix)
  row,_=execute(['bash','scripts/build_release_artifacts.sh'],'build-release',timeout=3600);need(row['exit_code']==0,'release build failed')
  artifact=ROOT/'target/release/hegemon-release-artifacts.json';manifest=json.loads(artifact.read_text());need(manifest['source_head']==a.expected_source_sha and manifest['target_triple']=='x86_64-unknown-linux-gnu','artifact source/platform mismatch');receipt['artifact_manifest_sha256']=sha(artifact);receipt['artifact_sha256']={r['binary']:r['sha256']for r in manifest['artifacts']};shutil.copyfile(artifact,out/'hegemon-release-artifacts.json')
  h0=old.load('range_h0',ROOT/'scripts/check_v011_release_successor.py');h0.CURRENT_NEW_VERSION='0.11.4';identity=json.loads((ROOT/'config/v0113-release-successor.json').read_text())['current_identity'];network=json.loads((ROOT/'config/testnet/0.11/network-manifest.json').read_text());smoke=h0.artifact_gate(ROOT,ROOT,artifact,{'authorization_kind':h0.CURRENT_SOURCE_KIND,'identity':identity},network,4);need(smoke['identity_smoke']['height']==0 and smoke['identity_smoke']['peers']==0 and smoke['identity_smoke']['owned_node_reaped']is True,'isolated H0 incomplete');write(out/'h0-identity-smoke.json',smoke)
  argv=[sys.executable,'-I','-B','scripts/check_v011_current_binary_proofs.py','--node-bin',str(ROOT/'target/release/hegemon-node'),'--artifact-manifest',str(artifact),'--output',str(out/'current-binary-proofs'),'--min-free-gib','4'];row,_=execute(argv,'current-binary-proofs',timeout=600);need(row['exit_code']==0,'current proof cases failed');proof=json.loads((out/'current-binary-proofs/receipt.json').read_text());need(proof.get('processes_reaped')is True and proof.get('node_sha256')==receipt['artifact_sha256']['hegemon-node']and proof.get('artifact_manifest_sha256')==receipt['artifact_manifest_sha256'],'proof binary binding mismatch');receipt['current_binary_proofs']=proof
  need(sha(artifact)==receipt['artifact_manifest_sha256']and sha(inputs)==receipt['build_inputs_sha256'],'build inputs/artifact manifest changed')
  for row in manifest['artifacts']:need(sha(ROOT/row['path'])==row['sha256'],'artifact changed')
  after=source.validate_source(ROOT,a.expected_source_sha,a.expected_delta_sha256,pin_provenance=a.pin_provenance);need(after==before,'source changed');write(out/'source-after.json',after)
  receipt.update(status='BUILD_AND_COMPONENT_GATES_PASSED_RUNTIME_PENDING',source_inventory_sha256=before['source_inventory_sha256'],delta_sha256=before['delta_sha256'],transport_exact_tests=9,recovery_exact_tests=12,modules=6,h0_verified=True,backend_proof_cases=5,qualification_contract_sha256=sha(ROOT/'release-evidence/sync-range-transport-qualification-contract.json'))
 except BaseException as error:
  receipt.update(status='FAIL',error_type=type(error).__name__,error=str(error));raise
 finally:
  if baseline is not None and baseline.exists():
   r=subprocess.run(['git','-C',str(ROOT),'worktree','remove','--force',str(baseline)],capture_output=True,timeout=120);receipt['owned_ablation_removed']=r.returncode==0
   if r.returncode:receipt.update(status='FAIL',cleanup_error='owned selector ablation removal failed')
  write(out/'receipt.json',receipt)
 need(receipt['status']=='BUILD_AND_COMPONENT_GATES_PASSED_RUNTIME_PENDING','component gate or cleanup failed')
if __name__=='__main__':
 def interrupt(number,frame):raise RuntimeError('component qualification interrupted')
 signal.signal(signal.SIGTERM,interrupt);main()
