#!/usr/bin/env python3
"""Stage a native-ADA preview refund without syncing a public node."""
import argparse
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path
from public_btc_eth_rehearsal import _directory,_locked,_write
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_setup import actor,status_confirmations
from public_cardano_transactions import CLI,build_balanced
from public_cardano_verify import AIKEN,verify_preview
from public_eth_cardano_rehearsal import _input,_tip
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
AMOUNT=4_000_000


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1 or state.get('scenario')!='cardano-refund' or not re.fullmatch('[0-9a-f]{64}',state.get('hashlock','')):raise ValueError('Invalid Cardano refund state')
    return state
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);pair=json.loads((root/'cardano-native-pair/state.json').read_text())
    if pair.get('phase')!='complete':raise ValueError('Complete the Cardano same-chain fixture swap first')
    alice=actor(root,'alice');bob=actor(root,'bob');outputs=cardano_utxos(bob['address'])
    candidates=[x for x in outputs if x['outref']!=pair['bob_collateral'] and not x['assets'] and x['lovelace']>=10_000_000 and status_confirmations(x['outref'].split('#')[0])>=2]
    if not candidates:raise ValueError('No confirmed ADA-only refund funding output')
    source=max(candidates,key=lambda x:x['lovelace']);work=root/'cardano-refund';work.mkdir(mode=0o700)
    secret=secrets.token_bytes(32);_write(work/'secret',secret,True);params=preview_protocol_parameters();_write(work/'params.json',(json.dumps(params)+'\n').encode(),True)
    compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);script=work/'validator.plutus';_write(script,compiled,True)
    address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(script),'--testnet-magic','2'],text=True,timeout=30).strip();expiry_slot=_tip()+300
    state={'version':1,'scenario':'cardano-refund','phase':'lock','hashlock':hashlib.sha256(secret).hexdigest(),'claimant':alice['keyhash'],'refundee':bob['keyhash'],'refund_address':bob['address'],'collateral':pair['bob_collateral'],'input':source['outref'],'expiry_slot':expiry_slot,'expiry_ms':(1666656000+expiry_slot)*1000,'script_address':address}
    _save(work,state,True);return {'phase':'lock','hashlock':state['hashlock']}


def _verify(work,state,allow_expired=False):
    return verify_preview(work/'validator.plutus',state['lock']+'#0',state['hashlock'],state['claimant'],state['refundee'],state['expiry_ms'],AMOUNT,{},minimum_remaining_ms=1000,allow_expired=allow_expired)


def advance(root):
    root=_directory(root);work=_directory(root/'cardano-refund');state=_state(work);phase=state['phase'];bob=actor(root,'bob');alice=actor(root,'alice')
    if bob['keyhash']!=state['refundee'] or bob['address']!=state['refund_address'] or alice['keyhash']!=state['claimant']:raise ValueError('Cardano refund wallets changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain refund action; inspect journal and chain before recovery')
    if phase=='lock':
        rows=cardano_utxos(bob['address']);items=[x for x in rows if x['outref']==state['input'] and not x['assets']]
        if len(items)!=1:raise ValueError('Cardano refund funding output unavailable')
        datum={'constructor':0,'fields':[{'bytes':state['hashlock']},{'bytes':state['claimant']},{'bytes':state['refundee']},{'int':state['expiry_ms']}]};datum_file=work/'datum.json';_write(datum_file,(json.dumps(datum)+'\n').encode(),True)
        body=work/'lock.body';build_balanced(inputs=[_input(items[0])],outputs=[{'address':state['script_address'],'lovelace':AMOUNT,'assets':{},'datum':datum_file}],change_address=bob['address'],params=work/'params.json',body=body)
        _begin(work,state,'lock');result=sign_and_submit(work,body,bob['skey']);state.update(phase='lock_submitted',lock=result['txid']);_save(work,state)
    elif phase=='lock_submitted':
        if status_confirmations(state['lock'])>=2:_verify(work,state,allow_expired=True);state['phase']='wait_refund';_save(work,state)
    elif phase=='wait_refund':
        if _tip()>=state['expiry_slot']:
            _verify(work,state,allow_expired=True);rows=cardano_utxos(bob['address']);reserve=[x for x in rows if x['outref']==state['lock']+'#1' and not x['assets']]
            if len(reserve)!=1 or not any(x['outref']==state['collateral'] and not x['assets'] for x in rows):raise ValueError('Cardano refund fee or collateral output unavailable')
            redeemer=work/'redeemer.json';_write(redeemer,b'{"constructor":1,"fields":[]}\n',True)
            scripted={'outref':state['lock']+'#0','lovelace':AMOUNT,'assets':{},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
            body=work/'refund.body';build_balanced(inputs=[scripted,_input(reserve[0])],outputs=[{'address':bob['address'],'lovelace':AMOUNT,'assets':{}}],change_address=bob['address'],params=work/'params.json',body=body,collateral=state['collateral'],required_signer=state['refundee'],invalid_before=state['expiry_slot'])
            _begin(work,state,'refund');result=sign_and_submit(work,body,bob['skey']);state.update(phase='refund_submitted',refund=result['txid']);_save(work,state)
    elif phase=='refund_submitted':
        if status_confirmations(state['refund'])>=2:
            outputs=cardano_utxos(bob['address']);locked=cardano_utxos(state['script_address'])
            if not any(x['outref'].startswith(state['refund']+'#') and x['lovelace']==AMOUNT and not x['assets'] for x in outputs) or any(x['outref']==state['lock']+'#0' for x in locked):raise ValueError('Cardano refund payout or spend mismatch')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown Cardano refund phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted') or state['phase']=='wait_refund'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:result=_state(_directory(root/'cardano-refund'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
