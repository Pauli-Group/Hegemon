#!/usr/bin/env python3
"""Exercise a Bitcoin/token swap on isolated fresh local chains."""
import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from htlc_counterpart import Ethereum, Cardano, TOOLS, ROOT, wait_for
from local_private_spend_swap import descriptor, port, stop, require
from development_atomic_swap_rehearsal import BitcoinRPC, rehearsal_bitcoin_key, spend_contract, confirmed_bitcoin_preimage, wait_bitcoin_confirmations
from bitcoin_escrow_verifier import verify_bitcoin_htlc


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--tools',type=Path,default=TOOLS)
    p.add_argument('--bitcoind',type=Path,default=Path('/workspace/bitcoin-32.1/bin/bitcoind'))
    p.add_argument('--counterpart',choices=['ethereum','cardano'],default='ethereum')
    p.add_argument('--ethereum-token',choices=['erc20','erc721','erc1155'],default='erc20')
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    eth=bitcoin=companion_proc=None; receipt={'status':'failed','note':'Disposable isolated chains; deadlines are not public-network qualified.'}
    try:
        bd=output/'btc';bd.mkdir(mode=0o700);bp=port()
        bitcoin=subprocess.Popen([a.bitcoind,'-regtest',f'-datadir={bd}','-server=1','-listen=0','-connect=0','-discover=0','-dnsseed=0','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1',f'-rpcport={bp}','-fallbackfee=0.0002','-printtoconsole=0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        btc=BitcoinRPC(f'http://127.0.0.1:{bp}',bd/'regtest/.cookie')
        deadline=time.monotonic()+30
        while True:
            require(bitcoin.poll() is None,'Bitcoin exited')
            try:
                require(btc.call('getblockchaininfo')['chain']=='regtest','wrong Bitcoin chain');break
            except (OSError,RuntimeError):
                require(time.monotonic()<deadline,'Bitcoin RPC unavailable');time.sleep(.2)
        for name in ('alice','bob'):btc.call('createwallet',name,False,False,'',False,True)
        alicepub,alicekey=rehearsal_bitcoin_key();bobpub,bobkey=rehearsal_bitcoin_key()
        dest=btc.call('getnewaddress',wallet='bob');btc.call('generatetoaddress',101,dest)
        refund=btc.call('getblockcount')+20
        secret=os.urandom(32);digest=hashlib.sha256(secret).digest()
        def desc(claim,refundkey):return f'wsh(or_i(and_v(v:sha256({digest.hex()}),pk({claim})),and_v(v:after({refund}),pk({refundkey}))))'
        public=btc.call('getdescriptorinfo',desc(alicepub,bobpub))['descriptor']
        contract=btc.call('deriveaddresses',public)[0]
        descriptor(btc,'alice',desc(alicekey,bobpub));descriptor(btc,'bob',desc(alicepub,bobkey))
        # Participant B funds the longer Bitcoin escrow first. Participant A
        # then funds the other chain; its alice is Bitcoin's bob.
        tx=btc.call('sendtoaddress',contract,0.001,wallet='bob');btc.call('generatetoaddress',2,dest)
        funding=btc.call('gettransaction',tx,wallet='bob')
        decoded=btc.call('getrawtransaction',tx,True,funding['blockhash'])
        vout=next(v for v in decoded['vout'] if v['scriptPubKey'].get('address')==contract)
        info=btc.call('getaddressinfo',contract,wallet='alice')
        witness=bytes.fromhex(info['hex']);script=bytes.fromhex(vout['scriptPubKey']['hex'])
        terms={'txid':tx,'vout':vout['n'],'amount_sats':100000,'hashlock':digest.hex(),
               'claimant_key':alicepub,'refund_key':bobpub,'refund_height':refund,'genesis_hash':btc.call('getblockhash',0)}
        snapshot=verify_bitcoin_htlc(btc,**terms)
        for bad in ({**terms,'amount_sats':99999},{**terms,'hashlock':'00'*32},
                    {**terms,'claimant_key':bobpub},{**terms,'refund_height':refund+1}):
            try:verify_bitcoin_htlc(btc,**bad)
            except ValueError:pass
            else:raise RuntimeError('Bitcoin verifier accepted altered terms')
        companion_dir=output/'companion';companion_dir.mkdir(mode=0o700)
        cp=port();token_file=companion_dir/'token'
        companion_proc=subprocess.Popen([sys.executable,ROOT/'scripts/local_swap_companion.py',
            '--bitcoin-rpc',f'http://127.0.0.1:{bp}','--bitcoin-cookie',bd/'regtest/.cookie',
            '--token-file',token_file,'--port',str(cp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        companion_token=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'companion token')
        def companion_call(path,body=None,token=None,origin='http://127.0.0.1:8787'):
            connection=http.client.HTTPConnection('127.0.0.1',cp,timeout=30)
            try:
                headers={'Origin':origin,'Authorization':'Bearer '+(token or companion_token)}
                if body is not None:headers['Content-Type']='application/json'
                connection.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
                response=connection.getresponse();return response.status,json.loads(response.read())
            finally:connection.close()
        wait_for(lambda:companion_call('/health')[0]==200,'companion server')
        require(companion_call('/health',token='0'*64)[0]==403,'companion accepted wrong token')
        require(companion_call('/health',origin='http://attacker.invalid')[0]==403,'companion accepted wrong origin')
        head_status,head=companion_call('/bitcoin/head')
        require(head_status==200 and head.get('genesis')==terms['genesis_hash'] and int(head['height'])==btc.call('getblockcount'),'companion Bitcoin head mismatch')
        status,check=companion_call('/bitcoin/verify',terms)
        require(status==200 and check.get('verified') and check['snapshot']['txid']==tx,'companion did not verify Bitcoin escrow')
        require(companion_call('/bitcoin/verify',{**terms,'amount_sats':99999})[0]==400,'companion accepted altered Bitcoin amount')
        eth=(Ethereum(output/'eth',a.tools,test_token=a.ethereum_token) if a.counterpart=='ethereum'
             else Cardano(output/'ada',a.tools,test_tokens=True))
        eth.isolated();require(btc.call('getconnectioncount')==0,'Bitcoin acquired a peer')
        eth.lock(digest)
        revealed=eth.claim(secret)
        require(hashlib.sha256(revealed).digest()==digest,'counterpart secret mismatch')
        target=btc.call('getnewaddress',wallet='alice')
        claim=spend_contract(btc,'alice',tx,vout['n'],100000,script,witness,target,0xffffffff,0,revealed)
        wait_bitcoin_confirmations(btc,claim,'alice',1,dest)
        require(confirmed_bitcoin_preimage(btc,claim,'alice',digest)==secret,'Bitcoin secret mismatch')
        try:verify_bitcoin_htlc(btc,**terms)
        except ValueError:pass
        else:raise RuntimeError('Bitcoin verifier accepted spent escrow')
        require(companion_call('/bitcoin/verify',terms)[0]==400,'companion accepted a spent Bitcoin output')
        require(btc.call('getconnectioncount')==0,'Bitcoin acquired a peer');eth.isolated()
        receipt.update(status='passed',bitcoin={'chain':'regtest','funding_txid':tx,'claim_txid':claim,'peers':0,'verified_snapshot':snapshot,'companion_checks':'passed'},counterpart=eth.receipt)
    finally:
        if eth:eth.close()
        stop(companion_proc)
        stop(bitcoin)
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
