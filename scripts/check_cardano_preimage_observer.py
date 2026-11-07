#!/usr/bin/env python3
"""Verify Cardano preimage observation against a fresh peerless local node."""
import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
from pathlib import Path
from cardano_preimage_observer import observe_local_preimage
from htlc_counterpart import Cardano,TOOLS,wait_for
from local_private_spend_swap import port,require,stop
from unlock_swap_backup import save_recovered_backup,unlock_backup
from cardano_observer_cli_check import check_observer_cli
from swap_engine.tools import tool_default


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
    p.add_argument('--ogmios',type=Path,default=tool_default('ogmios'))
    a=p.parse_args();os.umask(0o077);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False);chain=Cardano(out/'chain',a.tools,test_tokens=True,epoch_length=5000);ogmios=None
    receipt={'status':'failed','checks':{}}
    try:
        secret=os.urandom(32);digest=hashlib.sha256(secret).hexdigest();chain.lock(bytes.fromhex(digest));tip=chain.tip();checkpoint={'slot':tip['slot'],'id':tip['hash']};outref=chain.locked
        chain.claim(secret);local_port=port()
        ogmios=subprocess.Popen([a.ogmios,'--node-socket',chain.socket,'--node-config',chain.net/'configuration.yaml','--host','127.0.0.1','--port',str(local_port),'--include-transaction-cbor','--log-level','Error'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        def ready():
            if ogmios.poll() is not None:raise RuntimeError('local Ogmios exited')
            try:return urllib.request.urlopen('http://127.0.0.1:'+str(local_port)+'/health',timeout=1).status==200
            except OSError:return False
        wait_for(ready,'local Ogmios health',seconds=30)
        genesis_hash=hashlib.sha256((chain.net/'shelley-genesis.json').read_bytes()).hexdigest()
        recovered,snapshot=observe_local_preimage(url='ws://127.0.0.1:'+str(local_port),ogmios_pid=ogmios.pid,node_pid=chain.proc.pid,node_socket=chain.socket,network_dir=chain.net,genesis_hash=genesis_hash,checkpoint=checkpoint,outref=outref,hashlock=digest,confirmations=2,timeout=60)
        try:
            require(recovered==secret and snapshot['confirmations']>=2,'confirmed preimage mismatch')
            password=bytearray(b'local disposable backup passphrase');path=save_recovered_backup(out,recovered,password);unlocked=unlock_backup(path,password)
            try:require(unlocked==secret and secret.hex() not in path.read_text() and path.stat().st_mode&0o077==0,'observed backup mismatch')
            finally:unlocked[:]=b'\0'*len(unlocked);password[:]=b'\0'*len(password)
        finally:recovered[:]=b'\0'*len(recovered)
        cli,cli_phrase=check_observer_cli(url='ws://127.0.0.1:'+str(local_port),ogmios_pid=ogmios.pid,chain=chain,genesis=genesis_hash,checkpoint=checkpoint,outref=outref,hashlock=digest,output=out,secret=secret)
        unlocked=unlock_backup(cli['saved'],cli_phrase)
        try:require(unlocked==secret,'observer terminal backup mismatch')
        finally:unlocked[:]=b'\0'*len(unlocked)
        chain.isolated();receipt.update(status='passed',ogmios_sha256=hashlib.sha256(a.ogmios.read_bytes()).hexdigest(),snapshot=snapshot,
            checks={'confirmed_preimage_matches':True,'exact_escrow_input':True,'encrypted_backup_roundtrip':True,'terminal_cli':True,'zero_peers':True})
    finally:
        stop(ogmios);chain.close();(out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(out/'summary.json')}),flush=True)

if __name__=='__main__':main()
