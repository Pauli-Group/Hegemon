#!/usr/bin/env python3
"""Stage a Bitcoin testnet4/Sepolia ERC-20 fixture swap without full nodes."""
import argparse
import hashlib
import json
import re
import secrets
import stat
import os
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_btc_eth_rehearsal import _bitcoin_lock,_directory,_locked,_receipt,_wallets,_write
from public_bitcoin_driver import fund,spend_contract
from public_ethereum_setup import _state as fixture_state
from public_ethereum_token_verify import expected_runtime,verify_token
from public_samechain_ethereum_rehearsal import _holding
from public_sepolia_driver import send
from public_testnet_observers import bitcoin_claim,ethereum_claim
from public_testnet_probe import BITCOIN,request,rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
BTC_AMOUNT=1500
TOKEN_AMOUNT=10


BTC_REFUND_BLOCKS=150  # the Bitcoin driver refuses less than the policy floor of 145 blocks


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='btc-erc20' or not re.fullmatch('[0-9a-f]{64}',s.get('hashlock','')):raise ValueError('Invalid BTC/ERC20 state')
    return s
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);verify_network('bitcoin-testnet4');verify_network('ethereum-sepolia');terms=_wallets(root);setup=fixture_state(_directory(root/'ethereum-setup'))
    if setup['phase']!='complete':raise ValueError('Ethereum fixture setup incomplete')
    token=setup['contracts']['erc20']['address'];leg={'kind':0,'token':token,'id':0,'amount':TOKEN_AMOUNT};alice=_holding(leg,terms['eth_refundee']);bob=_holding(leg,terms['eth_claimant'])
    if alice<TOKEN_AMOUNT:raise ValueError('Insufficient ERC-20 fixture balance')
    work=root/'btc-erc20';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'scenario':'btc-erc20','phase':'btc_lock','hashlock':hashlib.sha256(secret).hexdigest(),'terms':terms,'btc_amount_sats':BTC_AMOUNT,'token':token,'alice_before':alice,'bob_before':bob};_save(work,state,True)
    return {'phase':'btc_lock','hashlock':state['hashlock']}


def _verify(state):
    t=state['terms'];return verify_token(state['eth_contract'],0,state['token'],0,TOKEN_AMOUNT,state['hashlock'],t['eth_claimant'],t['eth_refundee'],state['eth_expiry'])


def advance(root):
    root=_directory(root);work=_directory(root/'btc-erc20');state=_state(work);phase=state['phase'];t=state['terms']
    if t!=_wallets(root):raise ValueError('BTC/ERC20 wallet identities changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before recovery')
    if phase=='btc_lock':
        verify_network('bitcoin-testnet4');tip=int(request(BITCOIN+'/blocks/tip/height'));state['btc_refund_height']=tip+BTC_REFUND_BLOCKS
        _begin(work,state,phase);result=fund(work,root/'alice/bitcoin-testnet4.key',state['hashlock'],t['btc_claimant'],state['btc_refund_height'],BTC_AMOUNT);state.update(phase='btc_lock_submitted',btc_lock=result['txid']);_save(work,state)
    elif phase=='btc_lock_submitted':
        if _bitcoin_lock(state) is not None:state['phase']='deploy_eth';_save(work,state)
    elif phase=='deploy_eth':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<72:raise ValueError('Bitcoin refund margin too small')
        verify_network('ethereum-sepolia');now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16);state['eth_expiry']=now+3600
        template=json.loads((ROOT/'swap-ui/token-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['uint8','address','uint256','uint256','bytes32','address','uint256'],[0,state['token'],0,TOKEN_AMOUNT,bytes.fromhex(state['hashlock']),t['eth_claimant'],state['eth_expiry']])
        _begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',None,0,data);state.update(phase='deploy_eth_submitted',pending=result['txid']);_save(work,state)
    elif phase=='deploy_eth_submitted':
        receipt=_receipt(state['pending'])
        if receipt is not None:
            address=receipt.get('contractAddress');runtime=expected_runtime(0,state['token'],0,TOKEN_AMOUNT,state['hashlock'],t['eth_claimant'],t['eth_refundee'],state['eth_expiry'])
            if str(rpc('eth_getCode',[address,'latest'])).lower()!=runtime:raise ValueError('ERC-20 escrow deployment mismatch')
            state.update(phase='approve_eth',eth_contract=address);state.pop('pending');_save(work,state)
    elif phase=='approve_eth':
        data=keccak(text='approve(address,uint256)')[:4]+encode(['address','uint256'],[state['eth_contract'],TOKEN_AMOUNT]);_begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',state['token'],0,data);state.update(phase='approve_eth_submitted',pending=result['txid']);_save(work,state)
    elif phase=='approve_eth_submitted':
        if _receipt(state['pending']) is not None:state['phase']='fund_eth';state.pop('pending');_save(work,state)
    elif phase=='fund_eth':
        _begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',state['eth_contract'],0,keccak(text='fund()')[:4]);state.update(phase='fund_eth_submitted',eth_lock=result['txid']);_save(work,state)
    elif phase=='fund_eth_submitted':
        if _receipt(state['eth_lock']) is not None:_verify(state);state['phase']='both_verified';_save(work,state)
    elif phase=='both_verified':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<36:raise ValueError('Bitcoin refund margin too small')
        _verify(state);head=rpc('eth_getBlockByNumber',['latest',False])
        if state['eth_expiry']-int(head['timestamp'],16)<600:raise ValueError('Ethereum deadline too close')
        path=work/'secret';st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[secret]);_begin(work,state,'eth_claim');result=send(work,root/'bob/ethereum-sepolia.key',state['eth_contract'],0,data);state.update(phase='eth_claim_submitted',eth_claim=result['txid']);_save(work,state)
    elif phase=='eth_claim_submitted':
        if _receipt(state['eth_claim']) is not None:
            secret,_=ethereum_claim(state['eth_claim'],state['eth_contract'],state['hashlock'])
            try:
                _begin(work,state,'btc_claim');result=spend_contract(work,root/'bob/bitcoin-testnet4.key',state['btc_lock'],0,BTC_AMOUNT,state['hashlock'],t['btc_claimant'],t['btc_refund'],state['btc_refund_height'],bytes(secret));state.update(phase='btc_claim_submitted',btc_claim=result['txid']);_save(work,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='btc_claim_submitted':
        try:secret,_=bitcoin_claim(state['btc_claim'],state['btc_lock'],0,state['hashlock'])
        except ValueError as error:
            if 'unconfirmed' in str(error) or 'lacks canonical confirmations' in str(error):return {'phase':phase,'pending':True}
            raise
        secret[:]=b'\0'*len(secret);leg={'kind':0,'token':state['token'],'id':0,'amount':TOKEN_AMOUNT}
        if _holding(leg,t['eth_refundee'])!=state['alice_before']-TOKEN_AMOUNT or _holding(leg,t['eth_claimant'])!=state['bob_before']+TOKEN_AMOUNT:raise ValueError('ERC-20 payout mismatch')
        state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown BTC/ERC20 phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:result=initialize(root) if args.operation=='init' else advance(root) if args.operation=='advance' else _state(_directory(root/'btc-erc20'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
