#!/usr/bin/env python3
"""Observe a previously rehearsed claim on a copied peerless Development chain."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from check_native_asset_lifecycle import pending_action_public_args
from hegemon_preimage_observer import observe_hegemon_preimage
from hegemon_observer_cli_check import check_hegemon_observer_cli
from htlc_counterpart import ROOT
from local_private_spend_swap import mine,port,require,stop
from release_private_spend_lifecycle_io import height,rpc
from unlock_swap_backup import unlock_backup


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--node',type=Path,default=ROOT/'target/release/hegemon-node')
    a=p.parse_args();os.umask(0o077);source=a.source.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False)
    shutil.copytree(source/'chain',out/'chain');shutil.copy2(source/'manifest.json',out/'manifest.json');manifest=json.loads((out/'manifest.json').read_text())
    carrier,_=pending_action_public_args((source/'claim.action').read_bytes());secret=bytearray(carrier[536:568]);digest=hashlib.sha256(secret).hexdigest()
    require(int.from_bytes(carrier[528:536],'little')==1,'fixture claim does not release a preimage')
    rp,pp=port(),port();url=f'http://127.0.0.1:{rp}';node=None;result={'status':'failed','checks':{}}
    try:
        env={k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')};env.update(HEGEMON_MINER_ADDRESS=manifest['funding_address'],HEGEMON_SEEDS='',HEGEMON_MINE='0',HEGEMON_BOOTSTRAP_AUTHORING='1',RAYON_NUM_THREADS='2',RUST_LOG='warn')
        node=subprocess.Popen([a.node,'--dev','--network','development','--network-manifest',out/'manifest.json','--development-candidate','--base-path',out/'chain','--rpc-port',str(rp),'--rpc-methods','unsafe','--listen-addr',f'127.0.0.1:{pp}','--port',str(pp)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        deadline=time.monotonic()+120
        while True:
            require(node.poll() is None,'copied Hegemon node exited')
            try:genesis=rpc(url,'chain_getBlockHash',[0]);break
            except (OSError,RuntimeError):require(time.monotonic()<deadline,'copied Hegemon node unavailable');time.sleep(.1)
        start=max(1,height(url)-12);mine(url,height(url)+2)
        recovered,snapshot=observe_hegemon_preimage(url,manifest=out/'manifest.json',genesis=genesis,hashlock=digest,start_height=start,confirmations=2,timeout=30)
        try:require(recovered==secret and snapshot['confirmations']>=2,'Hegemon observed preimage mismatch')
        finally:recovered[:]=b'\0'*len(recovered)
        watched,phrase=check_hegemon_observer_cli(url=url,manifest=out/'manifest.json',genesis=genesis,hashlock=digest,start_height=start,output=out,secret=secret)
        recovered=unlock_backup(watched['saved'],phrase)
        try:require(recovered==secret,'Hegemon observer backup mismatch')
        finally:recovered[:]=b'\0'*len(recovered)
        require(rpc(url,'system_health')['peers']==0,'Hegemon acquired a peer')
        result={'status':'passed','checks':{'confirmed_preimage_matches':True,'terminal_cli':True,'encrypted_backup_roundtrip':True,'zero_peers':True},'snapshot':snapshot}
    finally:
        secret[:]=b'\0'*len(secret);stop(node);(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(out/'summary.json')}),flush=True)

if __name__=='__main__':main()
