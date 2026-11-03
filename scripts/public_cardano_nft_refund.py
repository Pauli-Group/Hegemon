#!/usr/bin/env python3
"""Stage a Cardano preview fixture-NFT refund without a public full node."""
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
    s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='cardano-nft-refund' or not re.fullmatch('[0-9a-f]{64}',s.get('hashlock','')):raise ValueError('Invalid Cardano NFT refund state')
    return s
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)


def initialize(root):
    root=_directory(root);nft_case=json.loads((root/'eth-cardano-erc721-nft/state.json').read_text());pair=json.loads((root/'cardano-native-pair/state.json').read_text())
    if nft_case.get('phase')!='complete' or pair.get('phase')!='complete':raise ValueError('Complete the NFT swaps first')
    alice=actor(root,'alice');bob=actor(root,'bob');asset=nft_case['ada_asset'];outputs=cardano_utxos(bob['address'])
    nft=[x for x in outputs if x['assets']=={asset:1} and status_confirmations(x['outref'].split('#')[0])>=2]
    fees=[x for x in outputs if x['outref']!=pair['bob_collateral'] and not x['assets'] and x['lovelace']>=10_000_000 and status_confirmations(x['outref'].split('#')[0])>=2]
    if len(nft)!=1 or not fees:raise ValueError('NFT or confirmed ADA fee output unavailable')
    fee=max(fees,key=lambda x:x['lovelace']);work=root/'cardano-nft-refund';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    _write(work/'params.json',(json.dumps(preview_protocol_parameters())+'\n').encode(),True);compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);_write(work/'validator.plutus',compiled,True)
    address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(work/'validator.plutus'),'--testnet-magic','2'],text=True,timeout=30).strip();expiry=_tip()+300
    s={'version':1,'scenario':'cardano-nft-refund','phase':'lock','hashlock':hashlib.sha256(secret).hexdigest(),'claimant':alice['keyhash'],'refundee':bob['keyhash'],'refund_address':bob['address'],'collateral':pair['bob_collateral'],'nft':asset,'nft_input':nft[0]['outref'],'fee_input':fee['outref'],'expiry_slot':expiry,'expiry_ms':(1666656000+expiry)*1000,'script_address':address}
    _save(work,s,True);return {'phase':'lock'}


def _verify(work,s,allow_expired=False):return verify_preview(work/'validator.plutus',s['lock']+'#0',s['hashlock'],s['claimant'],s['refundee'],s['expiry_ms'],AMOUNT,{s['nft']:1},minimum_remaining_ms=1000,allow_expired=allow_expired)


def advance(root):
    root=_directory(root);work=_directory(root/'cardano-nft-refund');s=_state(work);phase=s['phase'];bob=actor(root,'bob');alice=actor(root,'alice')
    if bob['keyhash']!=s['refundee'] or bob['address']!=s['refund_address'] or alice['keyhash']!=s['claimant']:raise ValueError('Cardano NFT refund wallets changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain NFT refund action; inspect journal and chain')
    if phase=='lock':
        rows=cardano_utxos(bob['address']);nft=[x for x in rows if x['outref']==s['nft_input'] and x['assets']=={s['nft']:1}];fee=[x for x in rows if x['outref']==s['fee_input'] and not x['assets']]
        if len(nft)!=1 or len(fee)!=1:raise ValueError('NFT or fee input unavailable')
        datum={'constructor':0,'fields':[{'bytes':s['hashlock']},{'bytes':s['claimant']},{'bytes':s['refundee']},{'int':s['expiry_ms']}]};_write(work/'datum.json',(json.dumps(datum)+'\n').encode(),True)
        body=work/'lock.body';build_balanced(inputs=[_input(nft[0]),_input(fee[0])],outputs=[{'address':s['script_address'],'lovelace':AMOUNT,'assets':{s['nft']:1},'datum':work/'datum.json'}],change_address=bob['address'],params=work/'params.json',body=body)
        _begin(work,s,'lock');result=sign_and_submit(work,body,bob['skey']);s.update(phase='lock_submitted',lock=result['txid']);_save(work,s)
    elif phase=='lock_submitted':
        if status_confirmations(s['lock'])>=2:_verify(work,s,True);s['phase']='wait_refund';_save(work,s)
    elif phase=='wait_refund':
        if _tip()>=s['expiry_slot']:
            _verify(work,s,True);rows=cardano_utxos(bob['address']);reserve=[x for x in rows if x['outref']==s['lock']+'#1' and not x['assets']]
            if len(reserve)!=1 or not any(x['outref']==s['collateral'] and not x['assets'] for x in rows):raise ValueError('NFT refund fee or collateral unavailable')
            redeemer=work/'redeemer.json';_write(redeemer,b'{"constructor":1,"fields":[]}\n',True)
            locked={'outref':s['lock']+'#0','lovelace':AMOUNT,'assets':{s['nft']:1},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
            body=work/'refund.body';build_balanced(inputs=[locked,_input(reserve[0])],outputs=[{'address':bob['address'],'lovelace':AMOUNT,'assets':{s['nft']:1}}],change_address=bob['address'],params=work/'params.json',body=body,collateral=s['collateral'],required_signer=s['refundee'],invalid_before=s['expiry_slot'])
            _begin(work,s,'refund');result=sign_and_submit(work,body,bob['skey']);s.update(phase='refund_submitted',refund=result['txid']);_save(work,s)
    elif phase=='refund_submitted':
        if status_confirmations(s['refund'])>=2:
            outs=cardano_utxos(bob['address']);locked=cardano_utxos(s['script_address'])
            if not any(x['outref'].startswith(s['refund']+'#') and x['assets']=={s['nft']:1} for x in outs) or any(x['outref']==s['lock']+'#0' for x in locked):raise ValueError('Cardano NFT refund payout mismatch')
            s['phase']='complete';_save(work,s)
    elif phase!='complete':raise ValueError('Unknown NFT refund phase')
    return {'phase':s['phase'],'pending':s['phase'].endswith('_submitted') or s['phase']=='wait_refund'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:result=initialize(root) if args.operation=='init' else advance(root) if args.operation=='advance' else _state(_directory(root/'cardano-nft-refund'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
