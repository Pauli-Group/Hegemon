#!/usr/bin/env python3
"""Step a native ETH/Sepolia and ADA/preview HTLC testnet rehearsal.

The first participant uses Ethereum Alice and Cardano Bob; the second uses
Cardano Alice and Ethereum Bob. Each advance makes at most one public
submission. Inflight states require manual journal inspection after failure.
This is testnet-only and relies on trusted public endpoints, not light clients.

Superseded for new runs by the swap engine (`swap_engine_cli.py`), which plans both expiries with the timelock policy.
Kept as the record of how the 2026 ETH/ADA rehearsal was staged.
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
from public_cardano_setup import actor,status as setup_status,status_confirmations
from public_cardano_transactions import CLI,build_balanced
from public_cardano_verify import AIKEN,verify_preview
from public_ethereum_verify import verify_native
from public_sepolia_driver import load_test_wallet,send as ethereum_send
from public_testnet_observers import cardano_claim,ethereum_claim
from public_testnet_probe import CARDANO,request,rpc
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
ETH_AMOUNT=10**14
ADA_AMOUNT=10_000_000


def _actors(root):
    ada_a=actor(root,'alice');ada_b=actor(root,'bob')
    _,eth_a=load_test_wallet(root/'alice/ethereum-sepolia.key');_,eth_b=load_test_wallet(root/'bob/ethereum-sepolia.key')
    return {'eth_refundee':eth_a,'eth_claimant':eth_b,'ada_refundee':ada_a['keyhash'],'ada_claimant':ada_b['keyhash'],'ada_refund_address':ada_a['address'],'ada_claim_address':ada_b['address']}


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    value=json.loads((work/'state.json').read_text())
    if value.get('version')!=1 or value.get('scenario')!='eth-cardano' or not re.fullmatch('[0-9a-f]{64}',value.get('hashlock','')):raise ValueError('Invalid ETH/Cardano scenario state')
    return value


def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia');verify_network('cardano-preview')
    if setup_status(root)['phase']!='confirmed':raise ValueError('Cardano participant setup is not confirmed')
    actors=_actors(root);public=json.loads((root/'addresses.json').read_text())
    if any(actors['ada_'+kind+'_address']!=public[name]['cardano_preview'] for kind,name in (('refund','alice'),('claim','bob'))):raise ValueError('Cardano test address mismatch')
    if any(actors['eth_'+kind].lower()!=public[name]['ethereum_sepolia'].lower() for kind,name in (('refundee','alice'),('claimant','bob'))):raise ValueError('Ethereum test address mismatch')
    work=root/'eth-cardano';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);digest=hashlib.sha256(secret).hexdigest()
    _write(work/'secret',secret,True)
    state={'version':1,'scenario':'eth-cardano','phase':'created','hashlock':digest,'actors':actors,'eth_amount_wei':str(ETH_AMOUNT),'ada_amount_lovelace':ADA_AMOUNT}
    _save(work,state,True);return {'phase':'created','hashlock':digest}


def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def _tip():
    verify_network('cardano-preview');rows=json.loads(request(CARDANO+'/tip'))
    if len(rows)!=1 or type(rows[0].get('abs_slot')) is not int:raise ValueError('Cardano preview tip unavailable')
    return rows[0]['abs_slot']


def _choose(utxos,minimum,excluded=()):
    items=[x for x in utxos if x['outref'] not in excluded and not x['assets'] and x['lovelace']>=minimum and status_confirmations(x['outref'].split('#')[0])>=2]
    if not items:raise ValueError('No confirmed ADA-only output is available')
    return min(items,key=lambda x:x['lovelace'])


def _input(item):return {key:item[key] for key in ('outref','lovelace','assets')}


def _ada_verify(work,state):
    return verify_preview(work/'validator.plutus',state['ada_lock']+'#0',state['hashlock'],state['actors']['ada_claimant'],state['actors']['ada_refundee'],state['ada_expiry_ms'],ADA_AMOUNT,{})


def advance(root):
    root=_directory(root);work=_directory(root/'eth-cardano');state=_state(work);actors=state['actors'];phase=state['phase']
    if actors!=_actors(root):raise ValueError('Scenario wallet identities changed')
    if not isinstance(phase,str) or phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before manual recovery')
    if phase=='created':
        if setup_status(root)['phase']!='confirmed':raise ValueError('Cardano participant setup is not confirmed')
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);state['eth_expiry']=int(head['timestamp'],16)+21600
        template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['bytes32','address','uint256'],[bytes.fromhex(state['hashlock']),actors['eth_claimant'],state['eth_expiry']])
        _begin(work,state,'eth_lock');result=ethereum_send(work,root/'alice/ethereum-sepolia.key',None,ETH_AMOUNT,data)
        state.update(phase='eth_lock_submitted',eth_lock=result['txid']);_save(work,state)
    elif phase=='eth_lock_submitted':
        receipt=_receipt(state['eth_lock'])
        if receipt is not None:
            contract=receipt.get('contractAddress');verify_native(contract,state['hashlock'],actors['eth_claimant'],actors['eth_refundee'],state['eth_expiry'],ETH_AMOUNT)
            state.update(phase='eth_lock_confirmed',eth_contract=contract);_save(work,state)
    elif phase=='eth_lock_confirmed':
        verify_native(state['eth_contract'],state['hashlock'],actors['eth_claimant'],actors['eth_refundee'],state['eth_expiry'],ETH_AMOUNT)
        slot=_tip();state['ada_expiry_slot']=slot+7200;state['ada_expiry_ms']=(1666656000+state['ada_expiry_slot'])*1000
        head=rpc('eth_getBlockByNumber',['latest',False])
        if state['eth_expiry']-int(head['timestamp'],16)<10800:raise ValueError('Ethereum refund margin too small')
        coin=_choose(cardano_utxos(actors['ada_refund_address']),ADA_AMOUNT+3_000_000)
        params=work/'params.json';_write(params,(json.dumps(preview_protocol_parameters())+'\n').encode(),True)
        compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);script=work/'validator.plutus';_write(script,compiled,True)
        address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(script),'--testnet-magic','2'],text=True,timeout=30).strip()
        datum={'constructor':0,'fields':[{'bytes':state['hashlock']},{'bytes':actors['ada_claimant']},{'bytes':actors['ada_refundee']},{'int':state['ada_expiry_ms']}]}
        datum_file=work/'datum.json';_write(datum_file,(json.dumps(datum)+'\n').encode(),True)
        body=work/'ada-lock.body';build_balanced(inputs=[_input(coin)],outputs=[{'address':address,'lovelace':ADA_AMOUNT,'assets':{},'datum':datum_file}],change_address=actors['ada_refund_address'],params=params,body=body)
        _begin(work,state,'ada_lock');result=sign_and_submit(work,body,actor(root,'alice')['skey'])
        state.update(phase='ada_lock_submitted',ada_lock=result['txid']);_save(work,state)
    elif phase=='ada_lock_submitted':
        if status_confirmations(state['ada_lock'])>=2:
            _ada_verify(work,state);state['phase']='both_verified';_save(work,state)
    elif phase=='both_verified':
        verify_native(state['eth_contract'],state['hashlock'],actors['eth_claimant'],actors['eth_refundee'],state['eth_expiry'],ETH_AMOUNT);_ada_verify(work,state)
        if state['ada_expiry_slot']-_tip()<600:raise ValueError('Cardano deadline too close')
        secret_path=work/'secret';st=secret_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=secret_path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        utxos=cardano_utxos(actors['ada_claim_address']);fee=_choose(utxos,5_000_000);collateral=_choose(utxos,5_000_000,(fee['outref'],))
        redeemer=work/'claim-redeemer.json';_write(redeemer,(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]})+'\n').encode(),True)
        script_input={'outref':state['ada_lock']+'#0','lovelace':ADA_AMOUNT,'assets':{},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
        body=work/'ada-claim.body';build_balanced(inputs=[script_input,_input(fee)],outputs=[{'address':actors['ada_claim_address'],'lovelace':ADA_AMOUNT,'assets':{}}],change_address=actors['ada_claim_address'],params=work/'params.json',body=body,collateral=collateral['outref'],required_signer=actors['ada_claimant'],invalid_hereafter=state['ada_expiry_slot'])
        _begin(work,state,'ada_claim');result=sign_and_submit(work,body,actor(root,'bob')['skey'])
        state.update(phase='ada_claim_submitted',ada_claim=result['txid']);_save(work,state)
    elif phase=='ada_claim_submitted':
        if status_confirmations(state['ada_claim'])>=2:
            secret,_=cardano_claim(state['ada_claim'],state['ada_lock']+'#0',state['hashlock'])
            try:
                data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[bytes(secret)])
                _begin(work,state,'eth_claim');result=ethereum_send(work,root/'bob/ethereum-sepolia.key',state['eth_contract'],0,data)
                state.update(phase='eth_claim_submitted',eth_claim=result['txid']);_save(work,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='eth_claim_submitted':
        if _receipt(state['eth_claim']) is not None:
            secret,_=ethereum_claim(state['eth_claim'],state['eth_contract'],state['hashlock']);secret[:]=b'\0'*len(secret)
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown ETH/Cardano scenario phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:
            state=_state(_directory(root/'eth-cardano'));result={k:v for k,v in state.items() if k!='actors'}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
