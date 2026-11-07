#!/usr/bin/env python3
"""Stage a Bitcoin testnet4 HTLC refund without syncing a public node."""
import argparse
import hashlib
import json
import re
import secrets
from pathlib import Path
from embit import script
from public_btc_eth_rehearsal import _bitcoin_lock,_directory,_locked,_write
from public_bitcoin_driver import fund,load_test_key,spend_contract
from public_testnet_probe import BITCOIN,request
from public_testnet_submit import verify_network

AMOUNT=1500


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='bitcoin-refund' or not re.fullmatch('[0-9a-f]{64}',s.get('hashlock','')):raise ValueError('Invalid Bitcoin refund state')
    return s
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);verify_network('bitcoin-testnet4');alice=load_test_key(root/'alice/bitcoin-testnet4.key');bob=load_test_key(root/'bob/bitcoin-testnet4.key')
    terms={'btc_refund':alice.get_public_key().sec().hex(),'btc_claimant':bob.get_public_key().sec().hex()};work=root/'bitcoin-refund';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'scenario':'bitcoin-refund','phase':'lock','hashlock':hashlib.sha256(secret).hexdigest(),'terms':terms,'btc_amount_sats':AMOUNT};_save(work,state,True);return {'phase':'lock'}


def advance(root):
    root=_directory(root);work=_directory(root/'bitcoin-refund');state=_state(work);phase=state['phase'];terms=state['terms']
    if load_test_key(root/'alice/bitcoin-testnet4.key').get_public_key().sec().hex()!=terms['btc_refund'] or load_test_key(root/'bob/bitcoin-testnet4.key').get_public_key().sec().hex()!=terms['btc_claimant']:raise ValueError('Bitcoin refund wallets changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain Bitcoin refund action; inspect journal and chain')
    if phase=='lock':
        verify_network('bitcoin-testnet4');height=int(request(BITCOIN+'/blocks/tip/height'));state['btc_refund_height']=height+6
        _begin(work,state,'lock');result=fund(work,root/'alice/bitcoin-testnet4.key',state['hashlock'],terms['btc_claimant'],state['btc_refund_height'],AMOUNT,rehearsal_short_refund=True);state.update(phase='lock_submitted',btc_lock=result['txid']);_save(work,state)
    elif phase=='lock_submitted':
        if _bitcoin_lock(state) is not None:state['phase']='wait_refund';_save(work,state)
    elif phase=='wait_refund':
        verify_network('bitcoin-testnet4');height=int(request(BITCOIN+'/blocks/tip/height'))
        if height<state['btc_refund_height']:
            try:spend_contract(work,root/'alice/bitcoin-testnet4.key',state['btc_lock'],0,AMOUNT,state['hashlock'],terms['btc_claimant'],terms['btc_refund'],state['btc_refund_height'])
            except ValueError as error:
                if 'not yet eligible' not in str(error):raise
                state['early_refund_rejected']=True;_save(work,state)
            else:raise ValueError('Premature Bitcoin refund unexpectedly succeeded')
        else:
            _begin(work,state,'refund');result=spend_contract(work,root/'alice/bitcoin-testnet4.key',state['btc_lock'],0,AMOUNT,state['hashlock'],terms['btc_claimant'],terms['btc_refund'],state['btc_refund_height']);state.update(phase='refund_submitted',refund=result['txid']);_save(work,state)
    elif phase=='refund_submitted':
        verify_network('bitcoin-testnet4');tx=json.loads(request(BITCOIN+'/tx/'+state['refund']));status=tx.get('status',{});height=status.get('block_height');tip=int(request(BITCOIN+'/blocks/tip/height'))
        if status.get('confirmed') is True and type(height) is int and tip-height+1>=2:
            if tx.get('txid')!=state['refund'] or request(BITCOIN+'/block-height/'+str(height)).decode().strip()!=status.get('block_hash'):raise ValueError('Bitcoin refund not canonical')
            inputs=[x for x in tx.get('vin',[]) if x.get('txid')==state['btc_lock'] and x.get('vout')==0]
            expected=script.p2wpkh(load_test_key(root/'alice/bitcoin-testnet4.key').get_public_key()).data.hex();outputs=tx.get('vout',[])
            if len(inputs)!=1 or not any(x.get('scriptpubkey')==expected and type(x.get('value')) is int and x['value']>=546 for x in outputs):raise ValueError('Bitcoin refund input or recipient mismatch')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown Bitcoin refund phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted') or state['phase']=='wait_refund'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:result=initialize(root) if args.operation=='init' else advance(root) if args.operation=='advance' else _state(_directory(root/'bitcoin-refund'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
