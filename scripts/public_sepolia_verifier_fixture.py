#!/usr/bin/env python3
"""Fund a temporary Sepolia escrow for read-only UI verification, then refund it."""
import argparse
import hashlib
import json
import secrets
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_ethereum_verify import verify_native
from public_sepolia_driver import load_test_wallet,send
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
AMOUNT=10**14
def save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)

def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia')
    _,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    work=root/'sepolia-ui-fixture';work.mkdir(mode=0o700)
    state={'version':1,'scenario':'sepolia-ui-fixture','phase':'deploy','hashlock':hashlib.sha256(secrets.token_bytes(32)).hexdigest(),'refundee':alice,'claimant':bob,'amount':str(AMOUNT)}
    save(work,state,True);return {'phase':'deploy'}

def advance(root):
    root=_directory(root);work=_directory(root/'sepolia-ui-fixture');s=json.loads((work/'state.json').read_text());phase=s.get('phase')
    if s.get('version')!=1 or s.get('scenario')!='sepolia-ui-fixture' or not isinstance(phase,str):raise ValueError('Invalid fixture state')
    if phase.endswith('_inflight'):raise ValueError('Uncertain fixture submission: inspect its journal and chain')
    _,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    if (alice,bob)!=(s['refundee'],s['claimant']):raise ValueError('Fixture wallet identity changed')
    if phase=='deploy':
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);s['expiry']=int(head['timestamp'],16)+1200
        template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['bytes32','address','uint256'],[bytes.fromhex(s['hashlock']),bob,s['expiry']])
        s['phase']='deploy_inflight';save(work,s);result=send(work,root/'alice/ethereum-sepolia.key',None,AMOUNT,data);s.update(phase='deploy_submitted',lock=result['txid']);save(work,s)
    elif phase=='deploy_submitted':
        receipt=_receipt(s['lock'])
        if receipt is not None:
            contract=receipt.get('contractAddress');verify_native(contract,s['hashlock'],bob,alice,s['expiry'],AMOUNT);s.update(phase='wait_refund',contract=contract);save(work,s)
    elif phase=='wait_refund':
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False])
        if int(head['timestamp'],16)>=s['expiry']:
            s['phase']='refund_inflight';save(work,s);result=send(work,root/'alice/ethereum-sepolia.key',s['contract'],0,keccak(text='refund()')[:4]);s.update(phase='refund_submitted',refund=result['txid']);save(work,s)
    elif phase=='refund_submitted':
        if _receipt(s['refund']) is not None:
            if int(rpc('eth_getBalance',[s['contract'],'latest']),16)!=0:raise ValueError('Fixture refund did not empty escrow')
            s['phase']='complete';save(work,s)
    elif phase!='complete':raise ValueError('Unknown fixture phase')
    return {'phase':s['phase'],'pending':s['phase']!='complete'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['init','advance','status']);p.add_argument('--directory',type=Path,required=True);a=p.parse_args()
    with _locked(a.directory) as root:
        result=initialize(root) if a.operation=='init' else advance(root) if a.operation=='advance' else json.loads((_directory(root/'sepolia-ui-fixture')/'state.json').read_text())
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
