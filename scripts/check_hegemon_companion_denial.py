#!/usr/bin/env python3
"""Test local denial of a Hegemon wallet read on a copied isolated chain."""
import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from hegemon_companion_check import check_hegemon_companion
from local_private_spend_swap import ROOT, port, require, stop
from release_private_spend_lifecycle_io import rpc, json_line


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--existing-run',type=Path,required=True,help='completed private local Hegemon scenario directory')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--node',type=Path,default=ROOT/'target/release/hegemon-node')
    p.add_argument('--wallet',type=Path,default=ROOT/'target/release/private-spend')
    a=p.parse_args();os.umask(0o077)
    source=a.existing_run.resolve();output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    record={'status':'failed'};node=None;log=None
    try:
        prior=json.loads((source/'receipt.json').read_text());genesis=prior['genesis']
        alice=json_line((source/'alice-bootstrap-new.log').read_text())['address']
        bob=json_line((source/'bob-bootstrap-new.log').read_text())['address']
        shutil.copytree(source/'chain',output/'chain')
        rp,pp=port(),port();url=f'http://127.0.0.1:{rp}'
        env={k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')}
        env.update(HEGEMON_MINER_ADDRESS=alice,HEGEMON_SEEDS='',HEGEMON_MINE='0',HEGEMON_BOOTSTRAP_AUTHORING='1',RUST_LOG='warn')
        log=(output/'node.log').open('wb')
        node=subprocess.Popen([a.node,'--dev','--network','development','--network-manifest',source/'manifest.json',
            '--development-candidate','--base-path',output/'chain','--rpc-port',str(rp),'--rpc-methods','unsafe',
            '--listen-addr',f'127.0.0.1:{pp}','--port',str(pp)],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        deadline=time.monotonic()+120
        while True:
            require(node.poll() is None,'node exited')
            try:
                require(rpc(url,'chain_getBlockHash',[0])==genesis,'genesis differs');break
            except (OSError,RuntimeError):
                require(time.monotonic()<deadline,'node did not start');time.sleep(.2)
        require(rpc(url,'system_health')['peers']==0,'unexpected Hegemon peer')
        check=check_hegemon_companion(output/'companion',binary=a.wallet,wallet_path=source/'bob.store',
            manifest=source/'manifest.json',genesis=genesis,rpc_url=url,phrase=b'not-used-in-denial-test',
            terms={'locked':'0','claim':bob,'refund':alice,'hashlock':'00'*32,'timeout':'999999',
                   'amount':'100000','min_confirmations':'2','min_remaining_blocks':'2'},only_denial=True)
        record.update(status='passed',checks=check)
    finally:
        stop(node)
        if log:log.close()
        (output/'summary.json').write_text(json.dumps(record,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
