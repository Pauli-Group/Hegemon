#!/usr/bin/env python3
"""Stage Sepolia-token/Cardano-native-fixture swaps through public services.

Inflight records forbid automatic retries. RPC services are trusted; these
deadlines, confirmations and fixture contracts are for testnets only.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_setup import actor,status_confirmations
from public_cardano_transactions import CLI,build_balanced
from public_cardano_verify import AIKEN,verify_preview
from public_eth_cardano_rehearsal import _actors,_choose,_input,_tip
from public_ethereum_setup import _state as eth_setup
from public_ethereum_token_verify import expected_runtime,verify_token
from public_samechain_ethereum_rehearsal import _call,_holding
from public_samechain_cardano_rehearsal import _choose_fee
from public_sepolia_driver import load_test_wallet,send
from public_testnet_observers import cardano_claim,ethereum_claim
from public_testnet_probe import rpc
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
ADA_AMOUNT=4_000_000
CASES={'erc20-fungible':(0,'erc20',0,10,'46554e47',7),'erc721-nft':(1,'erc721',42,1,'4e4654',1),'erc1155-fungible':(2,'erc1155',7,5,'46554e47',9)}


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1 or state.get('case') not in CASES or not re.fullmatch('[0-9a-f]{64}',state.get('hashlock','')):raise ValueError('Invalid ETH/Cardano token scenario')
    return state
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root,case):
    root=_directory(root)
    if case not in CASES:raise ValueError('Unknown token case')
    verify_network('ethereum-sepolia');verify_network('cardano-preview')
    fixtures=eth_setup(_directory(root/'ethereum-setup'));cardano_setup=json.loads((root/'cardano-setup/state.json').read_text());pair=json.loads((root/'cardano-native-pair/state.json').read_text())
    if fixtures['phase']!='complete' or pair['phase']!='complete':raise ValueError('Same-chain fixture swaps must complete first')
    actors=_actors(root);kind,fixture,token_id,amount,name,quantity=CASES[case];token=fixtures['contracts'][fixture]['address'];asset=cardano_setup['policy']+'.'+name
    leg={'kind':kind,'token':token,'id':token_id,'amount':amount};initial_funder=_holding(leg,actors['eth_refundee']);initial_claimant=_holding(leg,actors['eth_claimant'])
    if kind==1:
        if initial_funder!=actors['eth_refundee'].lower():raise ValueError('Ethereum fixture NFT not held by funder')
    elif initial_funder<amount:raise ValueError('Ethereum fixture amount unavailable')
    rows=cardano_utxos(actors['ada_refund_address']);matches=[x for x in rows if x['assets'].get(asset,0)>=quantity and status_confirmations(x['outref'].split('#')[0])>=2]
    if len(matches)!=1:raise ValueError('Cardano fixture asset unavailable or ambiguous')
    work=root/('eth-cardano-'+case);work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'case':case,'phase':'deploy_eth','hashlock':hashlib.sha256(secret).hexdigest(),'actors':actors,'eth':leg,'ada_asset':asset,'ada_quantity':quantity,'funder_before':initial_funder,'claimant_before':initial_claimant,'alice_collateral':pair['alice_collateral'],'bob_collateral':pair['bob_collateral']}
    _save(work,state,True);return {'phase':state['phase'],'hashlock':state['hashlock']}


def _eth_verify(state):
    e=state['eth'];a=state['actors'];return verify_token(e['escrow'],e['kind'],e['token'],e['id'],e['amount'],state['hashlock'],a['eth_claimant'],a['eth_refundee'],e['expiry'])


def _ada_verify(work,state):
    a=state['actors'];return verify_preview(work/'validator.plutus',state['ada_lock']+'#0',state['hashlock'],a['ada_claimant'],a['ada_refundee'],state['ada_expiry_ms'],ADA_AMOUNT,{state['ada_asset']:state['ada_quantity']})


def advance(root,case):
    root=_directory(root);work=_directory(root/('eth-cardano-'+case));state=_state(work);phase=state['phase'];actors=state['actors'];e=state['eth']
    if actors!=_actors(root):raise ValueError('ETH/Cardano token wallet identities changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before recovery')
    if phase=='deploy_eth':
        verify_network('ethereum-sepolia');now=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16);e['expiry']=now+21600
        template=json.loads((ROOT/'swap-ui/token-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['uint8','address','uint256','uint256','bytes32','address','uint256'],[e['kind'],e['token'],e['id'],e['amount'],bytes.fromhex(state['hashlock']),actors['eth_claimant'],e['expiry']])
        _begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',None,0,data);state.update(phase='deploy_eth_submitted',pending_tx=result['txid']);_save(work,state)
    elif phase=='deploy_eth_submitted':
        receipt=_receipt(state['pending_tx'])
        if receipt is not None:
            address=receipt.get('contractAddress');runtime=expected_runtime(e['kind'],e['token'],e['id'],e['amount'],state['hashlock'],actors['eth_claimant'],actors['eth_refundee'],e['expiry'])
            if str(rpc('eth_getCode',[address,'latest'])).lower()!=runtime:raise ValueError('Ethereum token escrow deployment mismatch')
            e['escrow']=address;state.update(phase='approve_eth');state.pop('pending_tx');_save(work,state)
    elif phase in ('approve_eth','revoke_eth'):
        revoke=phase=='revoke_eth'
        if revoke and e['kind']!=2:raise ValueError('Unexpected operator revocation')
        if e['kind']==2:signature='setApprovalForAll(address,bool)';types=['address','bool'];args=[e['escrow'],not revoke]
        else:signature='approve(address,uint256)';types=['address','uint256'];args=[e['escrow'],e['id'] if e['kind']==1 else e['amount']]
        data=keccak(text=signature)[:4]+encode(types,args);_begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',e['token'],0,data);state.update(phase=phase+'_submitted',pending_tx=result['txid']);_save(work,state)
    elif phase in ('approve_eth_submitted','revoke_eth_submitted'):
        if _receipt(state['pending_tx']) is not None:
            if phase=='revoke_eth_submitted' and _call(e['token'],'approved(address,address)',['address','address'],[actors['eth_refundee'],e['escrow']],['bool']):raise ValueError('ERC-1155 fixture operator approval remains active')
            state['phase']='fund_eth' if phase=='approve_eth_submitted' else 'eth_lock_confirmed';state.pop('pending_tx');_save(work,state)
    elif phase=='fund_eth':
        data=keccak(text='fund()')[:4];_begin(work,state,phase);result=send(work,root/'alice/ethereum-sepolia.key',e['escrow'],0,data);state.update(phase='fund_eth_submitted',eth_lock=result['txid']);_save(work,state)
    elif phase=='fund_eth_submitted':
        if _receipt(state['eth_lock']) is not None:_eth_verify(state);state['phase']='revoke_eth' if e['kind']==2 else 'eth_lock_confirmed';_save(work,state)
    elif phase=='eth_lock_confirmed':
        _eth_verify(state);slot=_tip();state['ada_expiry_slot']=slot+7200;state['ada_expiry_ms']=(1666656000+state['ada_expiry_slot'])*1000
        head=rpc('eth_getBlockByNumber',['latest',False])
        if e['expiry']-int(head['timestamp'],16)<10800:raise ValueError('Ethereum refund margin too small')
        outputs=cardano_utxos(actors['ada_refund_address']);asset=[x for x in outputs if x['assets'].get(state['ada_asset'],0)>=state['ada_quantity'] and status_confirmations(x['outref'].split('#')[0])>=2]
        if len(asset)!=1:raise ValueError('Cardano asset input unavailable or ambiguous')
        fee=None if asset[0]['lovelace']>=ADA_AMOUNT+3_000_000 else _choose_fee(outputs,5_000_000,(asset[0]['outref'],state['alice_collateral']))
        params=work/'params.json';_write(params,(json.dumps(preview_protocol_parameters())+'\n').encode(),True)
        compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);script=work/'validator.plutus';_write(script,compiled,True)
        address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(script),'--testnet-magic','2'],text=True,timeout=30).strip()
        datum={'constructor':0,'fields':[{'bytes':state['hashlock']},{'bytes':actors['ada_claimant']},{'bytes':actors['ada_refundee']},{'int':state['ada_expiry_ms']}]};datum_file=work/'datum.json';_write(datum_file,(json.dumps(datum)+'\n').encode(),True)
        inputs=[_input(asset[0])]+([] if fee is None else [_input(fee)])
        body=work/'ada-lock.body';build_balanced(inputs=inputs,outputs=[{'address':address,'lovelace':ADA_AMOUNT,'assets':{state['ada_asset']:state['ada_quantity']},'datum':datum_file}],change_address=actors['ada_refund_address'],params=params,body=body)
        _begin(work,state,'ada_lock');result=sign_and_submit(work,body,actor(root,'alice')['skey']);state.update(phase='ada_lock_submitted',ada_lock=result['txid']);_save(work,state)
    elif phase=='ada_lock_submitted':
        if status_confirmations(state['ada_lock'])>=2:_ada_verify(work,state);state['phase']='both_verified';_save(work,state)
    elif phase=='both_verified':
        _eth_verify(state);_ada_verify(work,state)
        if state['ada_expiry_slot']-_tip()<600:raise ValueError('Cardano token deadline too close')
        path=work/'secret';st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        rows=cardano_utxos(actors['ada_claim_address']);reserved=[]
        refund_state=root/'cardano-refund/state.json'
        if refund_state.exists():
            pending_refund=json.loads(refund_state.read_text())
            if str(pending_refund.get('phase','')).endswith('_inflight'):raise ValueError('Cardano refund submission is uncertain; resolve it before selecting a fee input')
            if pending_refund.get('phase')!='complete' and pending_refund.get('lock'):reserved.append(pending_refund['lock']+'#1')
        fee=_choose(rows,5_000_000,(state['bob_collateral'],*reserved))
        if not any(x['outref']==state['bob_collateral'] and not x['assets'] for x in rows):raise ValueError('Cardano collateral unavailable')
        redeemer=work/'redeemer.json';_write(redeemer,(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]})+'\n').encode(),True)
        locked={'outref':state['ada_lock']+'#0','lovelace':ADA_AMOUNT,'assets':{state['ada_asset']:state['ada_quantity']},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
        body=work/'ada-claim.body';build_balanced(inputs=[locked,_input(fee)],outputs=[{'address':actors['ada_claim_address'],'lovelace':ADA_AMOUNT,'assets':{state['ada_asset']:state['ada_quantity']}}],change_address=actors['ada_claim_address'],params=work/'params.json',body=body,collateral=state['bob_collateral'],required_signer=actors['ada_claimant'],invalid_hereafter=state['ada_expiry_slot'])
        _begin(work,state,'ada_claim');result=sign_and_submit(work,body,actor(root,'bob')['skey']);state.update(phase='ada_claim_submitted',ada_claim=result['txid']);_save(work,state)
    elif phase=='ada_claim_submitted':
        if status_confirmations(state['ada_claim'])>=2:
            secret,_=cardano_claim(state['ada_claim'],state['ada_lock']+'#0',state['hashlock'])
            try:
                data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[bytes(secret)]);_begin(work,state,'eth_claim')
                result=send(work,root/'bob/ethereum-sepolia.key',e['escrow'],0,data);state.update(phase='eth_claim_submitted',eth_claim=result['txid']);_save(work,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='eth_claim_submitted':
        if _receipt(state['eth_claim']) is not None:
            secret,_=ethereum_claim(state['eth_claim'],e['escrow'],state['hashlock']);secret[:]=b'\0'*len(secret)
            claimant_after=_holding(e,actors['eth_claimant']);funder_after=_holding(e,actors['eth_refundee'])
            if e['kind']==1:
                if claimant_after!=actors['eth_claimant'].lower():raise ValueError('Ethereum NFT recipient mismatch')
            elif claimant_after!=state['claimant_before']+e['amount'] or funder_after!=state['funder_before']-e['amount']:raise ValueError('Ethereum token payout mismatch')
            rows=cardano_utxos(actors['ada_claim_address'])
            if not any(x['outref'].startswith(state['ada_claim']+'#') and x['assets'].get(state['ada_asset'])==state['ada_quantity'] for x in rows):raise ValueError('Cardano native token recipient mismatch')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown ETH/Cardano token phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--case',choices=list(CASES),required=True);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root,args.case)
        elif args.operation=='advance':result=advance(root,args.case)
        else:
            state=_state(_directory(root/('eth-cardano-'+args.case)));result={k:v for k,v in state.items() if k!='actors'}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
