#!/usr/bin/env python3
"""Stage a Bitcoin testnet4/ADA preview swap using public-service snapshots.

The long Bitcoin refund deadline is a test choice, not a safety guarantee.
Actions are journaled and uncertain inflight submissions are never retried.
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
from public_btc_eth_rehearsal import _bitcoin_lock,_directory,_locked,_write
from public_bitcoin_driver import fund as bitcoin_fund,load_test_key,spend_contract
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_setup import actor,status_confirmations
from public_cardano_transactions import CLI,build_balanced
from public_cardano_verify import AIKEN,verify_preview
from public_eth_cardano_rehearsal import _choose,_input,_tip
from public_testnet_observers import bitcoin_claim,cardano_claim
from public_testnet_probe import BITCOIN,request
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
BTC_AMOUNT=1500
ADA_AMOUNT=10_000_000


def _actors(root):
    a=load_test_key(root/'alice/bitcoin-testnet4.key');b=load_test_key(root/'bob/bitcoin-testnet4.key');ca=actor(root,'alice');cb=actor(root,'bob')
    return {'btc_refund':a.get_public_key().sec().hex(),'btc_claimant':b.get_public_key().sec().hex(),'ada_refundee':ca['keyhash'],'ada_claimant':cb['keyhash'],'ada_refund_address':ca['address'],'ada_claim_address':cb['address']}
def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    value=json.loads((work/'state.json').read_text())
    if value.get('version')!=1 or value.get('scenario')!='btc-cardano' or not re.fullmatch('[0-9a-f]{64}',value.get('hashlock','')):raise ValueError('Invalid BTC/Cardano scenario state')
    return value
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);verify_network('bitcoin-testnet4');verify_network('cardano-preview');terms=_actors(root)
    outputs=cardano_utxos(terms['ada_claim_address']);first=_choose(outputs,5_000_000);_choose(outputs,5_000_000,(first['outref'],))
    work=root/'btc-cardano';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    state={'version':1,'scenario':'btc-cardano','phase':'created','hashlock':hashlib.sha256(secret).hexdigest(),'terms':terms,'btc_amount_sats':BTC_AMOUNT,'ada_amount_lovelace':ADA_AMOUNT}
    _save(work,state,True);return {'phase':'created','hashlock':state['hashlock']}


def _ada_verify(work,state):
    t=state['terms'];return verify_preview(work/'validator.plutus',state['ada_lock']+'#0',state['hashlock'],t['ada_claimant'],t['ada_refundee'],state['ada_expiry_ms'],ADA_AMOUNT,{})


def advance(root):
    root=_directory(root);work=_directory(root/'btc-cardano');state=_state(work);terms=state['terms'];phase=state['phase']
    if terms!=_actors(root):raise ValueError('BTC/Cardano wallet identities changed')
    if not isinstance(phase,str) or phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before recovery')
    if phase=='created':
        verify_network('bitcoin-testnet4');tip=int(request(BITCOIN+'/blocks/tip/height'));state['btc_refund_height']=tip+144
        _begin(work,state,'btc_lock');result=bitcoin_fund(work,root/'alice/bitcoin-testnet4.key',state['hashlock'],terms['btc_claimant'],state['btc_refund_height'],BTC_AMOUNT)
        state.update(phase='btc_lock_submitted',btc_lock=result['txid']);_save(work,state)
    elif phase=='btc_lock_submitted':
        if _bitcoin_lock(state) is not None:state['phase']='btc_lock_confirmed';_save(work,state)
    elif phase=='btc_lock_confirmed':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<72:raise ValueError('Bitcoin escrow unconfirmed or refund margin too small')
        slot=_tip();state['ada_expiry_slot']=slot+7200;state['ada_expiry_ms']=(1666656000+state['ada_expiry_slot'])*1000
        coin=_choose(cardano_utxos(terms['ada_refund_address']),ADA_AMOUNT+3_000_000)
        params=work/'params.json';_write(params,(json.dumps(preview_protocol_parameters())+'\n').encode(),True)
        compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);script=work/'validator.plutus';_write(script,compiled,True)
        address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(script),'--testnet-magic','2'],text=True,timeout=30).strip()
        datum={'constructor':0,'fields':[{'bytes':state['hashlock']},{'bytes':terms['ada_claimant']},{'bytes':terms['ada_refundee']},{'int':state['ada_expiry_ms']}]};datum_file=work/'datum.json';_write(datum_file,(json.dumps(datum)+'\n').encode(),True)
        body=work/'ada-lock.body';build_balanced(inputs=[_input(coin)],outputs=[{'address':address,'lovelace':ADA_AMOUNT,'assets':{},'datum':datum_file}],change_address=terms['ada_refund_address'],params=params,body=body)
        _begin(work,state,'ada_lock');result=sign_and_submit(work,body,actor(root,'alice')['skey']);state.update(phase='ada_lock_submitted',ada_lock=result['txid']);_save(work,state)
    elif phase=='ada_lock_submitted':
        if status_confirmations(state['ada_lock'])>=2:_ada_verify(work,state);state['phase']='both_verified';_save(work,state)
    elif phase=='both_verified':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<36:raise ValueError('Bitcoin escrow unconfirmed or refund margin too small')
        _ada_verify(work,state)
        if state['ada_expiry_slot']-_tip()<600:raise ValueError('Cardano deadline too close')
        path=work/'secret';st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        outputs=cardano_utxos(terms['ada_claim_address']);fee=_choose(outputs,5_000_000);collateral=_choose(outputs,5_000_000,(fee['outref'],))
        redeemer=work/'claim-redeemer.json';_write(redeemer,(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]})+'\n').encode(),True)
        scripted={'outref':state['ada_lock']+'#0','lovelace':ADA_AMOUNT,'assets':{},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
        body=work/'ada-claim.body';build_balanced(inputs=[scripted,_input(fee)],outputs=[{'address':terms['ada_claim_address'],'lovelace':ADA_AMOUNT,'assets':{}}],change_address=terms['ada_claim_address'],params=work/'params.json',body=body,collateral=collateral['outref'],required_signer=terms['ada_claimant'],invalid_hereafter=state['ada_expiry_slot'])
        _begin(work,state,'ada_claim');result=sign_and_submit(work,body,actor(root,'bob')['skey']);state.update(phase='ada_claim_submitted',ada_claim=result['txid']);_save(work,state)
    elif phase=='ada_claim_submitted':
        if status_confirmations(state['ada_claim'])>=2:
            secret,_=cardano_claim(state['ada_claim'],state['ada_lock']+'#0',state['hashlock'])
            try:
                _begin(work,state,'btc_claim');result=spend_contract(work,root/'bob/bitcoin-testnet4.key',state['btc_lock'],0,BTC_AMOUNT,state['hashlock'],terms['btc_claimant'],terms['btc_refund'],state['btc_refund_height'],bytes(secret))
                state.update(phase='btc_claim_submitted',btc_claim=result['txid']);_save(work,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='btc_claim_submitted':
        try:secret,_=bitcoin_claim(state['btc_claim'],state['btc_lock'],0,state['hashlock'])
        except ValueError as error:
            if 'unconfirmed' in str(error) or 'lacks canonical confirmations' in str(error):return {'phase':phase,'pending':True}
            raise
        secret[:]=b'\0'*len(secret);state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown BTC/Cardano scenario phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:
            state=_state(_directory(root/'btc-cardano'));result={k:v for k,v in state.items() if k!='terms'}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
