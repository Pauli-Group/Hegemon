#!/usr/bin/env python3
"""Exercise a short native-ETH refund on Sepolia with private journaling."""
import argparse
import hashlib
import json
import re
import secrets
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_ethereum_verify import verify_native
from public_sepolia_driver import load_test_wallet,send
from public_testnet_probe import ETHEREUM,request,rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
AMOUNT=10**14


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1 or state.get('scenario')!='ethereum-refund' or not re.fullmatch('[0-9a-f]{64}',state.get('hashlock','')):raise ValueError('Invalid Ethereum refund state')
    return state
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def _early_refund_rejected(address,refundee):
    data='0x'+keccak(text='refund()')[:4].hex();payload={'jsonrpc':'2.0','id':1,'method':'eth_call','params':[{'from':refundee,'to':address,'data':data},'latest']}
    result=json.loads(request(ETHEREUM,payload));error=result.get('error')
    expected='0x'+(keccak(text='Error(string)')[:4]+encode(['string'],['refund premature'])).hex()
    if result.get('id')!=1 or not isinstance(error,dict) or str(error.get('data','')).lower()!=expected:raise ValueError('Early refund did not return the expected contract rejection')


def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia');_,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    work=root/'ethereum-refund';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'scenario':'ethereum-refund','phase':'deploy','hashlock':hashlib.sha256(secret).hexdigest(),'refundee':alice,'claimant':bob}
    _save(work,state,True);return {'phase':'deploy','hashlock':state['hashlock']}


def advance(root):
    root=_directory(root);work=_directory(root/'ethereum-refund');state=_state(work);phase=state['phase'];_,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    if (alice,bob)!=(state['refundee'],state['claimant']):raise ValueError('Ethereum refund wallets changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain refund action; inspect journal and chain before recovery')
    if phase=='deploy':
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);state['expiry']=int(head['timestamp'],16)+300
        template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['bytes32','address','uint256'],[bytes.fromhex(state['hashlock']),bob,state['expiry']])
        _begin(work,state,'deploy');result=send(work,root/'alice/ethereum-sepolia.key',None,AMOUNT,data);state.update(phase='deploy_submitted',lock=result['txid']);_save(work,state)
    elif phase=='deploy_submitted':
        receipt=_receipt(state['lock'])
        if receipt is not None:
            address=receipt.get('contractAddress');verify_native(address,state['hashlock'],bob,alice,state['expiry'],AMOUNT)
            state.update(phase='wait_refund',contract=address);_save(work,state)
    elif phase=='wait_refund':
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);now=int(head['timestamp'],16)
        data='0x'+keccak(text='refund()')[:4].hex()
        if now<state['expiry']:
            _early_refund_rejected(state['contract'],alice);state['early_refund_rejected']=True;_save(work,state)
        else:
            _begin(work,state,'refund');result=send(work,root/'alice/ethereum-sepolia.key',state['contract'],0,bytes.fromhex(data[2:]));state.update(phase='refund_submitted',refund=result['txid']);_save(work,state)
    elif phase=='refund_submitted':
        if _receipt(state['refund']) is not None:
            if int(rpc('eth_getBalance',[state['contract'],'latest']),16)!=0:raise ValueError('Refunded escrow still has ETH')
            selector='0x'+keccak(text='spent()')[:4].hex()
            if int(rpc('eth_call',[{'to':state['contract'],'data':selector},'latest']),16)!=1:raise ValueError('Refunded escrow is not marked spent')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown Ethereum refund phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted') or state['phase']=='wait_refund'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:result=_state(_directory(root/'ethereum-refund'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
