#!/usr/bin/env python3
"""Test-only signer for the hosted Sepolia form; never expose this as a service."""
import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path
from eth_abi import encode
from public_btc_eth_rehearsal import _directory,_locked
from public_sepolia_driver import load_test_wallet,send
from public_sepolia_verifier_fixture import AMOUNT,ROOT,save
from public_testnet_probe import rpc
from public_testnet_submit import verify_network


def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia');_,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    head=rpc('eth_getBlockByNumber',['latest',False]);work=root/'sepolia-ui-action-fixture';work.mkdir(mode=0o700)
    state={'version':1,'scenario':'sepolia-ui-fixture','phase':'await_wallet','hashlock':hashlib.sha256(secrets.token_bytes(32)).hexdigest(),'refundee':alice,'claimant':bob,'amount':str(AMOUNT),'expiry':int(head['timestamp'],16)+1800}
    save(work,state,True);return {'phase':state['phase']}


def submit(root,tx):
    root=_directory(root);work=_directory(root/'sepolia-ui-action-fixture');s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='sepolia-ui-fixture' or s.get('phase')!='await_wallet':raise ValueError('Unexpected fixture state; inspect the journal')
    template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['bytes32','address','uint256'],[bytes.fromhex(s['hashlock']),s['claimant'],s['expiry']])
    if not isinstance(tx,dict) or set(tx)!={'from','data','value'} or str(tx['from']).lower()!=s['refundee'].lower() or tx['data'].lower()!='0x'+data.hex() or int(tx['value'],16)!=AMOUNT:raise ValueError('Wallet action differs from the test fixture')
    s['phase']='deploy_inflight';save(work,s);result=send(work,root/'alice/ethereum-sepolia.key',None,AMOUNT,data)
    s.update(phase='deploy_submitted',lock=result['txid']);save(work,s);return {'txid':'0x'+result['txid']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['init','submit']);p.add_argument('--directory',type=Path,required=True);a=p.parse_args()
    if a.operation=='submit':
        raw=sys.stdin.read(200001)
        if len(raw)>200000:raise ValueError('Wallet action too large')
        tx=json.loads(raw)
    with _locked(a.directory) as root:result=initialize(root) if a.operation=='init' else submit(root,tx)
    print(json.dumps(result))

if __name__=='__main__':main()
