#!/usr/bin/env python3
"""Swap local Ethereum fixture tokens for local Cardano fixture tokens."""
import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
from pathlib import Path
from htlc_counterpart import Ethereum, Cardano, TOOLS, ROOT, wait_for
from cardano_escrow_verifier import verify_cardano_htlc
from local_private_spend_swap import port, stop, require


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--tools',type=Path,default=TOOLS)
    p.add_argument('--ethereum-token',choices=['erc20','erc721','erc1155'],default='erc20')
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    eth=cardano=companion_proc=companion_log=None
    receipt={'status':'failed','note':'Local disposable fixtures; no production timing or finality claim.'}
    try:
        eth=Ethereum(output/'eth',a.tools,test_token=a.ethereum_token)
        cardano=Cardano(output/'ada',a.tools,test_tokens=True,epoch_length=5000)
        eth.isolated();cardano.isolated()
        secret=os.urandom(32);digest=hashlib.sha256(secret).digest()
        # Ethereum bob and Cardano alice are participant B; Ethereum alice and
        # Cardano bob are participant A. B locks first with the longer deadline.
        eth.lock(digest)
        cardano.lock(digest,ttl_slots=900)
        terms={'outref':cardano.locked,'hashlock':digest.hex(),
               'claimant':cardano.actors['alice']['hash'],'refundee':cardano.actors['bob']['hash'],
               'expiry_ms':cardano.expiry_ms,'expected_value':{'lovelace':cardano.amount,**cardano.tokens},
               'genesis_sha256':hashlib.sha256((cardano.net/'shelley-genesis.json').read_bytes()).hexdigest(),
               'aiken':a.tools/'aiken/aiken-x86_64-unknown-linux-musl/aiken'}
        snapshot=verify_cardano_htlc(cardano,**terms)
        companion_dir=output/'companion';companion_dir.mkdir(mode=0o700)
        companion_log=(companion_dir/'companion.log').open('wb')
        cp=port();token_file=companion_dir/'token'
        companion_proc=subprocess.Popen([sys.executable,ROOT/'scripts/local_swap_companion.py',
            '--cardano-socket',cardano.socket,'--cardano-network-dir',cardano.net,
            '--cardano-cli',a.tools/'cardano/bin/cardano-cli','--aiken',terms['aiken'],
            '--token-file',token_file,'--port',str(cp)],stdout=companion_log,stderr=subprocess.STDOUT,start_new_session=True)
        token=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'companion token')
        def companion_call(path,body=None,credential=None,origin='http://127.0.0.1:8787'):
            connection=http.client.HTTPConnection('127.0.0.1',cp,timeout=90)
            try:
                headers={'Origin':origin,'Authorization':'Bearer '+(credential or token)}
                if body is not None:headers['Content-Type']='application/json'
                connection.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
                response=connection.getresponse();return response.status,json.loads(response.read())
            finally:connection.close()
        wait_for(lambda:companion_call('/health')[0]==200,'companion server')
        require(companion_call('/health',credential='0'*64)[0]==403,'companion accepted wrong token')
        require(companion_call('/health',origin='http://attacker.invalid')[0]==403,'companion accepted wrong origin')
        head_status,head=companion_call('/cardano/head')
        require(head_status==200 and head.get('genesis')==terms['genesis_sha256'] and int(head['time_ms'])>0,'companion Cardano head mismatch')
        public_terms={k:v for k,v in terms.items() if k!='aiken'}
        public_terms['expiry_ms']=str(public_terms['expiry_ms'])
        public_terms['expected_value']={k:(str(v) if k=='lovelace' else {name:str(q) for name,q in v.items()}) for k,v in public_terms['expected_value'].items()}
        status,checked=companion_call('/cardano/verify',public_terms)
        require(status==200 and checked.get('verified') and checked['snapshot']['confirmations'] is None,'companion did not verify Cardano snapshot: '+str(checked))
        require(companion_call('/cardano/verify',{**public_terms,'hashlock':'00'*32})[0]==400,'companion accepted altered Cardano hash')
        for bad in ({**terms,'hashlock':'00'*32},{**terms,'claimant':cardano.actors['outsider']['hash']},
                    {**terms,'expiry_ms':cardano.expiry_ms+1},{**terms,'expected_value':{'lovelace':cardano.amount}}):
            try:verify_cardano_htlc(cardano,**bad)
            except ValueError:pass
            else:raise RuntimeError('Cardano verifier accepted altered terms')
        # B claims A's shorter escrow. A observes the confirmed secret and uses
        # it to claim B's longer Ethereum escrow.
        revealed=cardano.claim(secret)
        try:verify_cardano_htlc(cardano,**terms)
        except ValueError:pass
        else:raise RuntimeError('Cardano verifier accepted a spent output')
        require(companion_call('/cardano/verify',public_terms)[0]==400,'companion accepted a spent Cardano output')
        assert hashlib.sha256(revealed).digest()==digest
        assert eth.claim(revealed)==revealed
        eth.isolated();cardano.isolated()
        receipt.update(status='passed',ethereum=eth.receipt,cardano=cardano.receipt,cardano_snapshot=snapshot,companion_checks='passed')
    finally:
        stop(companion_proc)
        if companion_log:companion_log.close()
        if cardano:cardano.close()
        if eth:eth.close()
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
