#!/usr/bin/env python3
"""Fresh current-network public import/restart; existing binary, no build."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,sys,time
from pathlib import Path
HELPER_SHA='669f98b91c65f01b583365a19a171508072b41c0ab767bf2b3a116cf861cc5e0'
REPLAY_SHA='29c6655f1d8ced3ffa5a042e3c66f0567fc0ef465eda70de473e7a35054159dc'
FIXTURE_SHA='9331504f7175100a043b8e679bc9e6fbc6e0fe5a0dbea04a485dd60d40574a54'
SEEDS='hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333'
GENESIS='0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3'
CHAIN='0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49'
class Rejected(Exception):pass
def need(v,c):
 if not v:raise Rejected(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(path,pin,name):
 need(sha(path)==pin,'SOURCE_PIN');spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def validate_fixture(v):
 need(v.get('schema')=='hegemon.sync-recovery.current-network-public-baseline.v1' and v['genesis']==GENESIS and v['chain_id']==CHAIN and v['public_chain_data_only']is True and v['wallet_or_operator_data']is False,'FIXTURE_IDENTITY')
 need(v['target']=={'height':14460,'hash':'0x000000000000072a257e397fd410e30428cc7c020802f428e028129f395bf319'} and len(v['blocks'])==27 and v['ordinary_actions']==7,'FIXTURE_SCOPE')
 for i,b in enumerate(v['blocks']):
  need(b['height']==14344+i and set(b)=={'height','hash','parent_hash','body_sha256','actions'},'FIXTURE_BLOCK_SCHEMA')
  if i:need(b['parent_hash']==v['blocks'][i-1]['hash'],'FIXTURE_PARENT')
  for a in b['actions']:need(set(a)=={'sha256','bytes','route'} and a['route']in(12,15) and type(a['bytes'])is int and a['bytes']>0 and re.fullmatch('[0-9a-f]{64}',a['sha256']),'FIXTURE_ACTION_SCHEMA')
 need(sum(a['route']==15 for b in v['blocks']for a in b['actions'])==7,'FIXTURE_ORDINARY_COUNT')
 return v

def project_logs(owned):
 rows=[]
 for node in owned:
  raw=node.log.read_bytes()if node.log.exists()else b'';text=raw.decode(errors='replace');matches=[]
  for line in text.splitlines():
   if 'native V8 canonical scratch proof replay completed'in line:
    number=re.search(r'blocks_verified[=\s]+([0-9]+)',re.sub(r'\x1b\[[0-9;]*m','',line))
    if number:matches.append(int(number[1]))
  rows.append({'run':node.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'scratch_replay_completed_blocks':matches,'shutdown_complete':'native Hegemon node shutdown complete'in text,'shutdown_flush_failure':'failed to flush native db during shutdown'in text,'source_authority_rejection':'exact network has no active source-owned proof capability'in text,'owned_process_reaped':node.stopped and not node.group_active()})
 return rows

def main_run(a):
 source=a.source.resolve();executor=Path(__file__).resolve().parents[1];helper=load(executor/'scripts/qualify_sync_recovery_replay_remaining.py',HELPER_SHA,'frozen_prior_qualification');out=a.output.resolve();out.mkdir(mode=0o700)
 receipt={'schema':'hegemon.sync-recovery.current-network-public-import.v1','status':'RUNNING','artifact_source_commit':helper.SOURCE,'executor_commit':a.executor_commit,'prior_run_id':helper.RUN_ID,'prior_artifact_id':helper.ARTIFACT_ID,'prior_artifact_zip_sha256':helper.ZIP_SHA,'prior_qualification_helper_sha256':HELPER_SHA,'reused_public_helper_sha256':REPLAY_SHA,'node_sha256':helper.NODE_SHA,'artifact_manifest_sha256':helper.MANIFEST_SHA,'network_manifest_sha256':helper.LIVE_SHA,'fixture_sha256':FIXTURE_SHA,'genesis':GENESIS,'chain_id':CHAIN,'rebuild_performed':False,'production_authorized':False,'deployment_verified':False,'root_external_acceptance_performed':False,'historical_fixture_status':'FAILED_INAPPLICABLE_EXACT_NETWORK_SOURCE_CAPABILITY','historical_six_case_fixture_coverage_claimed':False,'current_backend_proof_cases_separate':5,'wallet_or_financial_actions':False,'database_copy_or_donor_bootstrap':False,'actual_full_genesis_sync':False,'processes_reaped':False}
 owned=[];old={};h=None
 def interrupted(number,frame):raise Rejected('QUALIFICATION_INTERRUPTED')
 try:
  need(helper.git(executor,'rev-parse','HEAD').decode().strip()==a.executor_commit,'EXECUTOR_COMMIT');receipt['executor_script_sha256']=sha(Path(__file__));receipt['executor_workflow_sha256']=sha(executor/'.github/workflows/qualify-sync-recovery-current-network.yml')
  ex=helper.extract(a.artifact_zip.resolve(),out/'prior-artifact');before=helper.validate_prior(source,ex);receipt.update(before)
  fixture_path=executor/'release-evidence/current-network-public-import-controls.json';need(sha(fixture_path)==FIXTURE_SHA,'FIXTURE_PIN');fixture=validate_fixture(helper.read(fixture_path))
  h=load(source/'scripts/check_v011_public_chain_replay.py',REPLAY_SHA,'frozen_public_import_helpers');binary=source/'target/release/hegemon-node';binary.parent.mkdir(parents=True,exist_ok=True)
  with(ex/'release/hegemon-node').open('rb')as f,binary.open('xb')as g:shutil.copyfileobj(f,g);g.flush();os.fsync(g.fileno())
  binary.chmod(0o700);need(sha(binary)==helper.NODE_SHA,'COPIED_BINARY');manifest=source/'config/testnet/0.11/network-manifest.json';h.bind_artifact(ex/'release/hegemon-release-artifacts.json',binary)
  deadline=time.monotonic()+2700;h.RPC_DEADLINE=deadline
  for number in(signal.SIGINT,signal.SIGTERM):old[number]=signal.signal(number,interrupted)
  state=out/'fresh-state';need(not state.exists(),'FRESH_STATE_REQUIRED');state.mkdir(mode=0o700);ports=h.free_ports();p2p,rpc_port=ports[:2]
  def budget():
   need(time.monotonic()<deadline,'TOTAL_DEADLINE');need(shutil.disk_usage(out).free>=8*1024**3,'DISK_RESERVE')
   for node in owned:
    need(node.log.stat().st_size<=64*1024**2,'LOG_BOUND')
    if not node.stopped:need(node.process.poll()is None,'OWNED_NODE_EXITED')
  def wait(fn,label,seconds):
   end=min(deadline,time.monotonic()+seconds)
   while time.monotonic()<end:
    budget()
    try:
     value=fn()
     if value:return value
    except(OSError,ValueError,h.http.client.HTTPException,h.ReplayError):pass
    time.sleep(.5)
   raise Rejected(label)
  def start(label,seeds):
   receipt['phase']='START_'+label.upper();node=h.OwnedNode(binary,manifest,state,out/(label+'.private.log'),p2p,rpc_port,seeds,'current-public-'+label);owned.append(node);wait(lambda:h.rpc(node.url,'system_health'),'STARTUP_DEADLINE',700)
   config=h.rpc(node.url,'hegemon_nodeConfig');need(config['chainId']==CHAIN and config['nodeName']==node.name and Path(config['basePath']).resolve()==state.resolve() and config['networkProfile']=='pre-mainnet' and config['bootstrapNodes']==(seeds.split(',')if seeds else[]) and config['bootstrapMiningAuthoring']is False and config['p2pListenAddr']==f'127.0.0.1:{p2p}','OWNED_NODE_CONFIG')
   mining=h.rpc(node.url,'hegemon_miningStatus');need(mining['is_mining']is False and mining['bootstrap_authoring']is False,'MINING_DISABLED');return node
  def tip(node):
   header=h.rpc(node.url,'chain_getHeader');need(header['chainId']==CHAIN,'CHAIN_ID');height=int(header['number'],16);return {'height':height,'hash':h.rpc(node.url,'chain_getBlockHash',[height])}
  def identity(node):need(h.rpc(node.url,'chain_getBlockHash',[0])==GENESIS,'GENESIS')
  def audit(node):
   identity(node);rows=[];ordinary=0
   for b in fixture['blocks']:
    budget();need(h.rpc(node.url,'chain_getBlockHash',[b['height']])==b['hash'],'PUBLIC_BLOCK_HASH');header=h.rpc(node.url,'chain_getHeader',[b['hash']]);need(int(header['number'],16)==b['height'] and header['chainId']==CHAIN and header['parentHash']==b['parent_hash'],'PUBLIC_HEADER')
    actions,meta,raw=h.body(node,b['hash']);need(hashlib.sha256(raw).hexdigest()==b['body_sha256'] and meta['height']==b['height'] and meta['parent_hash']==b['parent_hash'],'PUBLIC_BODY')
    actual=[{'sha256':hashlib.sha256(x).hexdigest(),'bytes':len(x),'route':int.from_bytes(x[54:56],'little')}for x in actions];need(actual==b['actions'],'ORDERED_PUBLIC_ACTIONS');ordinary+=sum(x['route']==15 for x in actual);need(h.rpc(node.url,'chain_getBlockHash',[b['height']])==b['hash'],'AUDIT_REORG');rows.append({'height':b['height'],'hash':b['hash'],'body_sha256':b['body_sha256'],'action_count':len(actions)})
   need(ordinary==7 and h.rpc(node.url,'chain_getBlockHash',[14460])==fixture['target']['hash'],'FIXED_TARGET_CANONICAL');return rows
  node=start('genesis','');identity(node);initial=tip(node);need(initial=={'height':0,'hash':GENESIS} and h.rpc(node.url,'system_health')['peers']==0,'ISOLATED_H0');node.stop();receipt['initial_isolated_genesis']=initial
  node=start('sync',SEEDS)
  def synced():
   current=tip(node);health=h.rpc(node.url,'system_health');mining=h.rpc(node.url,'hegemon_miningStatus');receipt['last_observation']={'height':current['height'],'peers':health['peers'],'is_syncing':health['isSyncing'],'mining_syncing':mining['syncing'],'mining_gate_open':mining['mining_sync_gate_open'],'is_mining':mining['is_mining']};need(mining['is_mining']is False and mining['bootstrap_authoring']is False,'MINING_DISABLED')
   return current if current['height']>=14460 and health['peers']>0 and health['isSyncing']is False and mining['syncing']is False and mining['mining_sync_gate_open']is True else None
  receipt['phase']='FRESH_CURRENT_NETWORK_SYNC';wait(synced,'FULL_CURRENT_NETWORK_SYNC_DEADLINE',2400);receipt['phase']='AUDIT_IMPORTED_PUBLIC_PREFIX';first=audit(node);captured=tip(node);node.stop();receipt.update(actual_full_genesis_sync=True,captured_before_clean_stop=captured,fixed_target=fixture['target'],canonical_public_blocks_checked=27,ordinary_proof_carriers_checked=7)
  node=start('restart','');receipt['phase']='SEEDLESS_RESTART_AUDIT';restarted=tip(node);identity(node);need(restarted['height']>=captured['height'] and h.rpc(node.url,'chain_getBlockHash',[captured['height']])==captured['hash'] and h.rpc(node.url,'system_health')['peers']==0,'SEEDLESS_RESTART_PREFIX');need(audit(node)==first,'RESTART_PUBLIC_BODY_CHANGED');node.stop()
  projections=project_logs(owned);need(all(r['shutdown_complete'] and not r['shutdown_flush_failure'] and r['owned_process_reaped']for r in projections),'CLEAN_SHUTDOWN_MARKERS');need(max(projections[-1]['scratch_replay_completed_blocks'],default=-1)>=captured['height'],'FULL_STARTUP_SCRATCH_PROOF_REPLAY')
  need(helper.validate_prior(source,ex)==before and sha(binary)==helper.NODE_SHA,'POST_RUN_SOURCE_AND_BINARY');receipt.update(phase='COMPLETE_CURRENT_NETWORK_QUALIFICATION',status='PASS_CURRENT_NETWORK_PUBLIC_IMPORT_ROOT_ACCEPTANCE_PENDING',restart_verified=True,restarted=restarted,clean_stop_drain_growth=restarted['height']-captured['height'],audited_public_blocks=first,owned_node_runs=len(owned))
 except BaseException as error:
  receipt.update(status='FAIL',error_type=type(error).__name__,error_code=error.args[0]if type(error)is Rejected and len(error.args)==1 else'CURRENT_NETWORK_QUALIFICATION_FAILED_PRESERVE_EVIDENCE')
 finally:
  cleanup=[]
  for node in reversed(owned):
   try:node.stop()
   except BaseException:cleanup.append('OWNED_NODE_CLEANUP_FAILED')
  for number,handler in old.items():signal.signal(number,handler)
  receipt['processes_reaped']=len(owned)==3 and all(n.stopped and not n.group_active()for n in owned)and not cleanup;receipt['owned_node_runs']=len(owned);receipt['native_log_projection']=project_logs(owned)
  if cleanup or not receipt['processes_reaped']:receipt.update(status='FAIL',cleanup_codes=cleanup)
  helper.write(out/'CURRENT_NETWORK_RECEIPT.json',receipt)
 return 0 if receipt['status']=='PASS_CURRENT_NETWORK_PUBLIC_IMPORT_ROOT_ACCEPTANCE_PENDING'else 1

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--source',type=Path);p.add_argument('--artifact-zip',type=Path);p.add_argument('--output',type=Path);p.add_argument('--executor-commit');a=p.parse_args()
 if not a.run:print(json.dumps({'status':'PREPARATION_ONLY_NO_CALLS'}));return 0
 need(all((a.source,a.artifact_zip,a.output,a.executor_commit))and re.fullmatch('[0-9a-f]{40}',a.executor_commit),'ARGUMENTS');return main_run(a)
if __name__=='__main__':raise SystemExit(main())
