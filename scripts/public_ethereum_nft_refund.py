#!/usr/bin/env python3
"""Stage an ERC-721 fixture refund on Sepolia, with no automatic retry."""
import argparse
import hashlib
import json
import re
import secrets
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_ethereum_refund_rehearsal import _early_refund_rejected
from public_ethereum_setup import _state as fixture_state
from public_ethereum_token_verify import expected_runtime,verify_token
from public_samechain_ethereum_rehearsal import _holding
from public_sepolia_driver import load_test_wallet,send
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='ethereum-nft-refund' or not re.fullmatch('[0-9a-f]{64}',s.get('hashlock','')):raise ValueError('Invalid NFT refund state')
    return s
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia');setup=fixture_state(_directory(root/'ethereum-setup'))
    nft_case=json.loads((root/'eth-cardano-erc721-nft/state.json').read_text())
    if setup['phase']!='complete' or nft_case['phase']!='complete':raise ValueError('Complete the NFT cross-chain test first')
    _,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key');token=setup['contracts']['erc721']['address'];leg={'kind':1,'token':token,'id':42,'amount':1}
    if _holding(leg,bob)!=bob.lower():raise ValueError('Refund wallet does not own NFT fixture')
    work=root/'ethereum-nft-refund';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'scenario':'ethereum-nft-refund','phase':'deploy','hashlock':hashlib.sha256(secret).hexdigest(),'refundee':bob,'claimant':alice,'token':token}
    _save(work,state,True);return {'phase':'deploy','hashlock':state['hashlock']}


def advance(root):
    root=_directory(root);work=_directory(root/'ethereum-nft-refund');state=_state(work);phase=state['phase'];_,alice=load_test_wallet(root/'alice/ethereum-sepolia.key');_,bob=load_test_wallet(root/'bob/ethereum-sepolia.key')
    if (alice,bob)!=(state['claimant'],state['refundee']):raise ValueError('NFT refund wallets changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain NFT refund action; inspect journal and chain')
    if phase=='deploy':
        verify_network('ethereum-sepolia');now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16);state['expiry']=now+300
        template=json.loads((ROOT/'swap-ui/token-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['uint8','address','uint256','uint256','bytes32','address','uint256'],[1,state['token'],42,1,bytes.fromhex(state['hashlock']),alice,state['expiry']])
        _begin(work,state,'deploy');result=send(work,root/'bob/ethereum-sepolia.key',None,0,data);state.update(phase='deploy_submitted',pending=result['txid']);_save(work,state)
    elif phase=='deploy_submitted':
        receipt=_receipt(state['pending'])
        if receipt is not None:
            address=receipt.get('contractAddress');runtime=expected_runtime(1,state['token'],42,1,state['hashlock'],alice,bob,state['expiry'])
            if str(rpc('eth_getCode',[address,'latest'])).lower()!=runtime:raise ValueError('NFT refund escrow mismatch')
            state.update(phase='approve',contract=address);state.pop('pending');_save(work,state)
    elif phase=='approve':
        data=keccak(text='approve(address,uint256)')[:4]+encode(['address','uint256'],[state['contract'],42]);_begin(work,state,'approve');result=send(work,root/'bob/ethereum-sepolia.key',state['token'],0,data);state.update(phase='approve_submitted',pending=result['txid']);_save(work,state)
    elif phase=='approve_submitted':
        if _receipt(state['pending']) is not None:state['phase']='fund';state.pop('pending');_save(work,state)
    elif phase=='fund':
        _begin(work,state,'fund');result=send(work,root/'bob/ethereum-sepolia.key',state['contract'],0,keccak(text='fund()')[:4]);state.update(phase='fund_submitted',lock=result['txid']);_save(work,state)
    elif phase=='fund_submitted':
        if _receipt(state['lock']) is not None:verify_token(state['contract'],1,state['token'],42,1,state['hashlock'],alice,bob,state['expiry']);state['phase']='wait_refund';_save(work,state)
    elif phase=='wait_refund':
        verify_network('ethereum-sepolia');now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)
        if now<state['expiry']:_early_refund_rejected(state['contract'],bob);state['early_refund_rejected']=True;_save(work,state)
        else:
            _begin(work,state,'refund');result=send(work,root/'bob/ethereum-sepolia.key',state['contract'],0,keccak(text='refund()')[:4]);state.update(phase='refund_submitted',refund=result['txid']);_save(work,state)
    elif phase=='refund_submitted':
        if _receipt(state['refund']) is not None:
            leg={'kind':1,'token':state['token'],'id':42,'amount':1}
            if _holding(leg,bob)!=bob.lower():raise ValueError('Refunded NFT was not returned')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown NFT refund phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted') or state['phase']=='wait_refund'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        result=initialize(root) if args.operation=='init' else advance(root) if args.operation=='advance' else _state(_directory(root/'ethereum-nft-refund'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
