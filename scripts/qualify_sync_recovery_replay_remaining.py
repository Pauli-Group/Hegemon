#!/usr/bin/env python3
"""Supplement only the missing public replay gate on an existing exact binary."""
import argparse, hashlib, json, os, re, stat, subprocess, sys, time, zipfile, signal, shutil
from pathlib import Path
SOURCE='de7a4f31b280eb52ed0c09e055840cec60d1f652'
ZIP_SHA='b433544857fdf07ebd5ea8c33d86be272a725322fd992e49118d1440026a83ce'
ZIP_BYTES=23805039
NODE_SHA='408ca4728459ff9109a5b3555be96cc337c45aab146aa9a74065e62874987235'
MANIFEST_SHA='139ae2d776101af7e30769037133e210edd76ab5fe29680a13892378b628a44b'
REPLAY_SHA='29c6655f1d8ced3ffa5a042e3c66f0567fc0ef465eda70de473e7a35054159dc'
HIST_COMMIT='8075a9b2b20adfb5ac5f292fa33260bb3582da06'
HIST_SHA='ffda566f04cee22b2a7ba5c2be88f625e9c668f47a7765f36fb377c79ea25758'
LIVE_SHA='386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754'
PRIOR_RECEIPT_SHA='403f2e28789a2ce78716294f92dad8ffe6e4cd0b40b0c3a1248610fd812aa8c6'
RUN_ID=42725500285
ARTIFACT_ID=13723231865
class Rejected(Exception): pass
def need(value,code):
    if not value: raise Rejected(code)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb')as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(p):
    p=Path(p);need(p.is_file() and not p.is_symlink() and p.stat().st_size<8*1024**2,'JSON_INPUT')
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'DUPLICATE_JSON');d[k]=v
        return d
    return json.loads(p.read_bytes(),object_pairs_hook=pairs)
def write(p,v):
    with Path(p).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def git(source,*args):return subprocess.check_output(['git','-C',str(source),*args],stderr=subprocess.DEVNULL,timeout=120)
def extract(bundle,destination):
    need(bundle.stat().st_size==ZIP_BYTES and sha(bundle)==ZIP_SHA,'EXACT_PRIOR_ARTIFACT_ZIP')
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(bundle)as z:
        rows=z.infolist();need(len(rows)<2000 and sum(r.file_size for r in rows)<512*1024**2,'ZIP_BOUND')
        seen=set()
        for row in rows:
            p=Path(row.filename)
            need(not p.is_absolute() and '..'not in p.parts and '\\'not in row.filename and row.filename not in seen and not row.is_dir(),'ZIP_PATH')
            mode=row.external_attr>>16;need(not stat.S_ISLNK(mode),'ZIP_SYMLINK');seen.add(row.filename)
            target=destination/p;target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
            with target.open('xb')as f:f.write(z.read(row))
    return destination

def validate_prior(source,ex):
    q=ex/'sync-recovery-qualification';rp=q/'receipt.json';need(sha(rp)==PRIOR_RECEIPT_SHA,'PRIOR_RECEIPT_PIN');prior=read(rp)
    need(prior['status']=='FAIL' and prior['error']=='public-chain-replay failed' and prior['baseline_worktree_removed']is True,'PRIOR_SCOPE')
    need(prior['core_ablation_expected_failure_verified']is True and prior['completion_owner_ablation']['expected_failure_verified']is True,'PRIOR_NEGATIVES')
    commands=prior['commands'];need(len(commands)==33 and len({r['log']for r in commands})==33,'PRIOR_COMMAND_INVENTORY')
    negatives={'core-ablation-negative-0.log','core-ablation-negative-1.log','completion-owner-ablation-negative.log'}
    for row in commands:
        name=row['log'];need(Path(name).name==name and sha(q/name)==row['log_sha256'] and row['owned_leader_reaped']is True,'PRIOR_COMMAND_LOG')
        need(row['exit_code']==(101 if name in negatives else 1 if name=='public-chain-replay.log' else 0),'PRIOR_COMMAND_EXIT')
    byname={r['log']:r for r in commands}
    for i in range(12):need(re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', (q/('exact-'+str(i)+'.log')).read_text()),'PRIOR_EXACT_TEST')
    for i in range(6):
        name='module-'+str(i)+'.log';n=len(byname[name]['required_tests']);need(n>0 and f'test result: ok. {n} passed; 0 failed; 0 ignored;'in(q/name).read_text(),'PRIOR_MODULE')
    old=read(q/'public-chain-replay/receipt.json');need(old['status']=='FAIL' and old['error']=='network manifest does not match public fixture' and old['owned_node_runs']==0 and old['processes_reaped']is True,'PRIOR_FAILED_BEFORE_NODE_START')
    manifest=ex/'release/hegemon-release-artifacts.json';need(sha(manifest)==MANIFEST_SHA,'ARTIFACT_MANIFEST_PIN');m=read(manifest)
    need(m['source_head']==SOURCE and m['target_triple']=='x86_64-unknown-linux-gnu','ARTIFACT_SOURCE')
    artifacts={r['binary']:r for r in m['artifacts']};need(artifacts['hegemon-node']['sha256']==NODE_SHA,'MANIFEST_NODE')
    for binary,row in artifacts.items():need(sha(ex/'release'/binary)==row['sha256'],'ACTUAL_BINARY_PIN')
    proof=read(q/'current-binary-proofs/receipt.json');need(proof['status']=='PASS_CURRENT_BINARY_BACKEND_PROOFS' and proof['cases_verified']==5 and proof['processes_reaped']is True and proof['node_sha256']==NODE_SHA and proof['artifact_manifest_sha256']==MANIFEST_SHA,'PRIOR_FIVE_PROOF_CASES')
    h0=read(q/'h0-identity-smoke.json');need(h0['artifact_manifest_sha256']==MANIFEST_SHA and h0['identity_smoke']['height']==0 and h0['identity_smoke']['owned_node_reaped']is True and h0['identity_smoke']['peers']==0,'PRIOR_LIVE_MANIFEST_H0')
    before=read(q/'source-before.json');need(before['source_head']==SOURCE and before['status']=='PASS_EXACT_FUNCTIONAL_POSTIMAGES_ROOT_DELTA_CHECK_PENDING','SOURCE_BEFORE')
    need(git(source,'rev-parse','HEAD').decode().strip()==SOURCE and git(source,'status','--porcelain')==b'','FROZEN_SOURCE_HEAD')
    files=before['source_inventory'];need(set(git(source,'ls-files','-z').decode().split('\0')[:-1])=={r['path']for r in files},'SOURCE_INVENTORY')
    for row in files:
        p=source/row['path'];need(p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],'FROZEN_SOURCE_FILE')
    need(digest(json.dumps(files,sort_keys=True,separators=(',',':')).encode())==before['source_inventory_sha256']=='e9bd9a32719b5488a7dff57b4a3fcf7ad712b66f3db3a0b195544d25a1bff3fb','SOURCE_INVENTORY_DIGEST')
    need(sha(source/'scripts/check_v011_public_chain_replay.py')==REPLAY_SHA and sha(source/'config/testnet/0.11/network-manifest.json')==LIVE_SHA,'UNCHANGED_REPLAY_AND_LIVE_MANIFEST')
    return {'prior_receipt_sha256':sha(rp),'source_inventory_sha256':before['source_inventory_sha256'],'prior_commands_validated':len(commands),'prior_exact_tests':12,'prior_modules':6,'prior_proof_cases':5,'prior_live_manifest_h0_preserved':True}

def validate_replay(replay,returncode):
    need(returncode==0 and replay['status']=='PASS' and replay['source_head']==SOURCE and replay['node_sha256']==NODE_SHA and replay['artifact_manifest_sha256']==MANIFEST_SHA and replay['network_manifest_sha256']==HIST_SHA and replay['canonical_blocks_verified']==163 and replay['proof_cases_verified']==6 and replay['actual_proof_verification']is True and replay['restart_verified']is True and replay['processes_reaped']is True and replay['owned_node_runs']==4,'ACTUAL_SAME_BINARY_REPLAY_FAILED')

def owned_replay(argv,source,log,receipt):
    child=subprocess.Popen(argv,cwd=source,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    receipt.update(replay_checker_pid=child.pid,replay_checker_reaped=False,cleanup_uncertain=False)
    def interrupted(number,frame):raise Rejected('REPLAY_WRAPPER_INTERRUPTED')
    handlers={number:signal.signal(number,interrupted)for number in (signal.SIGINT,signal.SIGTERM)}
    try:
        try:return child.wait(timeout=1450)
        except BaseException:
            if child.poll()is None:
                child.send_signal(signal.SIGTERM)
                try:child.wait(timeout=180)
                except subprocess.TimeoutExpired:receipt['cleanup_uncertain']=True
            raise
    finally:
        receipt['replay_checker_reaped']=child.poll()is not None
        receipt['replay_checker_returncode']=child.poll()
        if child.poll()is None:receipt['cleanup_uncertain']=True
        for number,handler in handlers.items():signal.signal(number,handler)

def run(a):
    source=a.source.resolve();out=a.output.resolve();out.mkdir(mode=0o700)
    executor=Path(__file__).resolve().parents[1];need(git(executor,'rev-parse','HEAD').decode().strip()==a.executor_commit,'EXECUTOR_COMMIT')
    receipt={'schema':'hegemon.sync-recovery.remaining-public-replay.v1','status':'RUNNING','artifact_source_commit':SOURCE,'executor_commit':a.executor_commit,'prior_run_id':RUN_ID,'prior_artifact_id':ARTIFACT_ID,'prior_artifact_zip_sha256':ZIP_SHA,'node_sha256':NODE_SHA,'artifact_manifest_sha256':MANIFEST_SHA,'rebuild_performed':False,'prior_qualification_rerun':False,'executor_script_sha256':sha(Path(__file__).resolve()),'executor_workflow_sha256':sha(executor/'.github/workflows/qualify-sync-recovery-replay-remaining.yml'),'root_external_acceptance_performed':False,'production_authorized':False,'deployment_verified':False,'release_publication_authorized':False}
    try:
        ex=extract(a.artifact_zip.resolve(),out/'prior-artifact');prior_identity=validate_prior(source,ex);receipt.update(prior_identity)
        historical=git(source,'show',HIST_COMMIT+':config/testnet/0.11/network-manifest.json');need(digest(historical)==HIST_SHA,'HISTORICAL_FIXTURE_MANIFEST_PIN')
        manifest=out/'historical-fixture-network-manifest.json';manifest.write_bytes(historical)
        fixture=read(source/'release-evidence/v0.11-public-chain-fixture/manifest.json');need(fixture['network_manifest_sha256']==HIST_SHA,'FIXTURE_MANIFEST_BINDING')
        binary=source/'target/release/hegemon-node';binary.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with (ex/'release/hegemon-node').open('rb')as old, binary.open('xb')as new:shutil.copyfileobj(old,new);new.flush();os.fsync(new.fileno())
        binary.chmod(0o700);need(sha(binary)==NODE_SHA,'COPIED_EXACT_NODE')
        argv=[sys.executable,'-I','-B',str(source/'scripts/check_v011_public_chain_replay.py'),'--node-bin',str(binary),'--artifact-manifest',str(ex/'release/hegemon-release-artifacts.json'),'--network-manifest',str(manifest),'--output',str(out/'replay'),'--min-free-gib','4','--timeout-seconds','1200']
        with(out/'replay-command.log').open('xb')as log:
            returncode=owned_replay(argv,source,log,receipt)
        replay=read(out/'replay/receipt.json');validate_replay(replay,returncode)
        need(validate_prior(source,ex)==prior_identity,'POST_REPLAY_SOURCE_INVENTORY')
        need(sha(binary)==NODE_SHA and sha(source/'config/testnet/0.11/network-manifest.json')==LIVE_SHA,'POST_RUN_INPUT_PIN')
        receipt.update(status='PASS_REMAINING_REPLAY_ROOT_ACCEPTANCE_PENDING',replay_receipt_sha256=sha(out/'replay/receipt.json'),live_network_manifest_sha256=LIVE_SHA,historical_fixture_manifest_sha256=HIST_SHA,historical_fixture_manifest_commit=HIST_COMMIT,actual_replay=163,proof_cases_verified=6,processes_reaped=True,live_manifest_modified=False)
    except BaseException as error:
        receipt.update(status='FAIL',error_type=type(error).__name__,error=str(error))
        raise
    finally:write(out/'SUPPLEMENT_RECEIPT.json',receipt)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--source',type=Path);p.add_argument('--artifact-zip',type=Path);p.add_argument('--output',type=Path);p.add_argument('--executor-commit');a=p.parse_args()
    if not a.run:print(json.dumps({'status':'PREPARATION_ONLY_NO_CALLS'}));return
    need(all((a.source,a.artifact_zip,a.output,a.executor_commit)) and re.fullmatch('[0-9a-f]{40}',a.executor_commit),'EXECUTOR_ARGUMENTS');run(a)
if __name__=='__main__':main()
