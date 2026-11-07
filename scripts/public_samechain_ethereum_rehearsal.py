#!/usr/bin/env python3
"""Run staged same-chain Sepolia fixture token swaps with private journaling.

This is a testnet-only rehearsal using minimal fixtures. Each advance makes at
most one public submission, and an uncertain inflight action is never retried.

Superseded for new runs by the swap engine (`swap_engine_cli.py`) and the same-chain local checks (`check_samechain_ethereum_swap.py`).
Kept as the record of how the 2026 same-chain Sepolia rehearsal was staged.
"""
import argparse
import hashlib
import json
import re
import secrets
import stat
from pathlib import Path
from eth_abi import encode,decode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_ethereum_setup import _state as setup_state
from public_ethereum_token_verify import expected_runtime,verify_token
from public_sepolia_driver import load_test_wallet,send
from public_testnet_observers import ethereum_claim
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
CASES={'erc20-erc721':({'kind':0,'fixture':'erc20','id':0,'amount':100,'funder':'alice','claimant':'bob'},{'kind':1,'fixture':'erc721','id':42,'amount':1,'funder':'bob','claimant':'alice'}),'erc1155-erc20':({'kind':2,'fixture':'erc1155','id':7,'amount':30,'funder':'alice','claimant':'bob'},{'kind':0,'fixture':'erc20','id':0,'amount':25,'funder':'bob','claimant':'alice'})}


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1 or state.get('case') not in CASES or not re.fullmatch('[0-9a-f]{64}',state.get('hashlock','')):raise ValueError('Invalid same-chain test state')
    return state


def _call(to,signature,types,args,returns):
    data='0x'+(keccak(text=signature)[:4]+encode(types,args)).hex();raw=rpc('eth_call',[{'to':to,'data':data},'latest'])
    return decode(returns,bytes.fromhex(raw.removeprefix('0x')))[0]


def _holding(leg,address):
    if leg['kind']==0:return _call(leg['token'],'balanceOf(address)',['address'],[address],['uint256'])
    if leg['kind']==1:return _call(leg['token'],'ownerOf(uint256)',['uint256'],[leg['id']],['address']).lower()
    return _call(leg['token'],'balanceOf(address,uint256)',['address','uint256'],[address,leg['id']],['uint256'])


def initialize(root,case):
    root=_directory(root)
    if case not in CASES:raise ValueError('Unknown same-chain test')
    verify_network('ethereum-sepolia');fixtures=setup_state(_directory(root/'ethereum-setup'))
    if fixtures['phase']!='complete':raise ValueError('Ethereum token fixtures are not ready')
    actors={name:load_test_wallet(root/name/'ethereum-sepolia.key')[1] for name in ('alice','bob')}
    if any(actors[name].lower()!=fixtures['actors'][name].lower() for name in actors):raise ValueError('Ethereum fixture wallets changed')
    now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16);legs={}
    for index,name in enumerate(('long','short')):
        term=dict(CASES[case][index]);term.update(token=fixtures['contracts'][term['fixture']]['address'],expiry=now+(7200 if name=='long' else 3600))
        term['funder_before']=_holding(term,actors[term['funder']]);term['claimant_before']=_holding(term,actors[term['claimant']])
        if term['kind']==1:
            if term['funder_before']!=actors[term['funder']].lower():raise ValueError('Fixture NFT is not owned by funder')
        elif term['funder_before']<term['amount']:raise ValueError('Fixture token balance is insufficient')
        legs[name]=term
    work=root/('ethereum-'+case);work.mkdir(mode=0o700);secret=secrets.token_bytes(32);digest=hashlib.sha256(secret).hexdigest();_write(work/'secret',secret,True)
    state={'version':1,'case':case,'phase':'deploy_long','actors':actors,'hashlock':digest,'legs':legs};_save(work,state,True)
    return {'phase':state['phase'],'hashlock':digest}


def _verify(state,name):
    leg=state['legs'][name];actors=state['actors']
    return verify_token(leg['escrow'],leg['kind'],leg['token'],leg['id'],leg['amount'],state['hashlock'],actors[leg['claimant']],actors[leg['funder']],leg['expiry'])


def _begin(work,state,action):state['phase']=action+'_inflight';_save(work,state)


def advance(root,case):
    root=_directory(root);work=_directory(root/('ethereum-'+case));state=_state(work);phase=state['phase'];actors=state['actors'];legs=state['legs']
    if any(load_test_wallet(root/name/'ethereum-sepolia.key')[1].lower()!=actors[name].lower() for name in actors):raise ValueError('Same-chain wallet identity changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before recovery')
    if phase.startswith(('deploy_','approve_','fund_','revoke_')) and not phase.endswith('_submitted'):
        action,name=phase.split('_');leg=legs[name];key=root/leg['funder']/'ethereum-sepolia.key'
        if action=='deploy':
            template=json.loads((ROOT/'swap-ui/token-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['uint8','address','uint256','uint256','bytes32','address','uint256'],[leg['kind'],leg['token'],leg['id'],leg['amount'],bytes.fromhex(state['hashlock']),actors[leg['claimant']],leg['expiry']]);target=None
        elif action in ('approve','revoke'):
            if action=='revoke' and leg['kind']!=2:raise ValueError('Only ERC-1155 operator approvals need this revocation')
            if leg['kind']==2:signature='setApprovalForAll(address,bool)';types=['address','bool'];args=[leg['escrow'],action=='approve']
            else:signature='approve(address,uint256)';types=['address','uint256'];args=[leg['escrow'],leg['id'] if leg['kind']==1 else leg['amount']]
            data=keccak(text=signature)[:4]+encode(types,args);target=leg['token']
        else:data=keccak(text='fund()')[:4];target=leg['escrow']
        _begin(work,state,phase);result=send(work,key,target,0,data);state.update(phase=phase+'_submitted',pending_tx=result['txid']);_save(work,state)
    elif phase.endswith('_submitted') and phase.startswith(('deploy_','approve_','fund_','revoke_')):
        action,name,_=phase.split('_');leg=legs[name];receipt=_receipt(state['pending_tx'])
        if receipt is not None:
            if action=='deploy':
                address=receipt.get('contractAddress');runtime=expected_runtime(leg['kind'],leg['token'],leg['id'],leg['amount'],state['hashlock'],actors[leg['claimant']],actors[leg['funder']],leg['expiry'])
                if str(rpc('eth_getCode',[address,'latest'])).lower()!=runtime:raise ValueError('Deployed token escrow mismatch')
                leg['escrow']=address
            if action=='fund':_verify(state,name)
            if action=='revoke' and _call(leg['token'],'approved(address,address)',['address','address'],[actors[leg['funder']],leg['escrow']],['bool']):raise ValueError('ERC-1155 operator approval was not revoked')
            next_phase='deploy_short' if name=='long' else 'both_verified'
            state['phase']={'deploy':'approve_'+name,'approve':'fund_'+name,'fund':'revoke_'+name if leg['kind']==2 else next_phase,'revoke':next_phase}[action]
            state.pop('pending_tx');_save(work,state)
    elif phase=='both_verified':
        _verify(state,'long');_verify(state,'short');now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)
        if legs['short']['expiry']-now<600 or legs['long']['expiry']-legs['short']['expiry']<1800:raise ValueError('Same-chain deadlines are too close')
        path=work/'secret';st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=__import__('os').getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[secret]);_begin(work,state,'claim_short')
        result=send(work,root/legs['short']['claimant']/'ethereum-sepolia.key',legs['short']['escrow'],0,data);state.update(phase='claim_short_submitted',short_claim=result['txid']);_save(work,state)
    elif phase=='claim_short_submitted':
        if _receipt(state['short_claim']) is not None:
            secret,_=ethereum_claim(state['short_claim'],legs['short']['escrow'],state['hashlock'])
            try:
                data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[bytes(secret)]);_begin(work,state,'claim_long')
                result=send(work,root/legs['long']['claimant']/'ethereum-sepolia.key',legs['long']['escrow'],0,data);state.update(phase='claim_long_submitted',long_claim=result['txid']);_save(work,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='claim_long_submitted':
        if _receipt(state['long_claim']) is not None:
            secret,_=ethereum_claim(state['long_claim'],legs['long']['escrow'],state['hashlock']);secret[:]=b'\0'*len(secret)
            for leg in legs.values():
                after_funder=_holding(leg,actors[leg['funder']]);after_claimant=_holding(leg,actors[leg['claimant']])
                if leg['kind']==1:
                    if after_claimant!=actors[leg['claimant']].lower():raise ValueError('Fixture NFT recipient mismatch')
                elif after_funder!=leg['funder_before']-leg['amount'] or after_claimant!=leg['claimant_before']+leg['amount']:raise ValueError('Fixture token payout mismatch')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown same-chain phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--case',choices=list(CASES),required=True);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root,args.case)
        elif args.operation=='advance':result=advance(root,args.case)
        else:
            state=_state(_directory(root/('ethereum-'+args.case)));result={k:v for k,v in state.items() if k!='actors'}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
