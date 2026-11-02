#!/usr/bin/env python3
"""Prepare Cardano preview test actors and mint disposable fixture tokens.

`prepare` builds but does not sign or submit; `submit` journals and sends once;
`status` reports provider-confirmed outputs. An inflight state must be inspected
manually after interruption. This is only for disposable preview test wallets.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from public_btc_eth_rehearsal import _directory,_locked,_write
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_transactions import CLI,build_balanced
from public_testnet_probe import CARDANO,request
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

BOB_OUTPUT=20_000_000
FIXTURE_ADA=5_000_000


def actor(directory,name):
    if name not in ('alice','bob'):raise ValueError('Unknown test participant')
    base=directory/name;vkey=base/'cardano.vkey';skey=base/'cardano.skey'
    address=subprocess.check_output([str(CLI),'conway','address','build','--payment-verification-key-file',str(vkey),'--testnet-magic','2'],text=True,timeout=30).strip()
    keyhash=subprocess.check_output([str(CLI),'conway','address','key-hash','--payment-verification-key-file',str(vkey)],text=True,timeout=30).strip()
    if not re.fullmatch('addr_test1[ac-hj-np-z02-9]+',address) or not re.fullmatch('[0-9a-f]{56}',keyhash):raise ValueError('Invalid Cardano test identity')
    return {'address':address,'keyhash':keyhash,'skey':skey}


def status_confirmations(txid):
    if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('Invalid Cardano transaction ID')
    verify_network('cardano-preview');rows=json.loads(request(CARDANO+'/tx_status',{'_tx_hashes':[txid]}))
    if not rows:return 0
    if len(rows)!=1 or rows[0].get('tx_hash')!=txid:raise ValueError('Cardano transaction status mismatch')
    value=rows[0].get('num_confirmations')
    if value is None:return 0
    if type(value) is not int or value<0:raise ValueError('Invalid Cardano confirmation count')
    return value


def prepare(directory):
    root=_directory(directory);work=root/'cardano-setup';work.mkdir(mode=0o700)
    alice=actor(root,'alice');bob=actor(root,'bob')
    public=json.loads((root/'addresses.json').read_text())
    if alice['address']!=public['alice']['cardano_preview'] or bob['address']!=public['bob']['cardano_preview']:raise ValueError('Cardano test addresses do not match keys')
    coins=cardano_utxos(alice['address']);eligible=[x for x in coins if not x['assets'] and x['lovelace']>2*BOB_OUTPUT+FIXTURE_ADA+2_000_000 and status_confirmations(x['outref'].split('#')[0])>=2]
    if not eligible:raise ValueError('No confirmed Cardano preview funding output')
    selected=min(eligible,key=lambda x:x['lovelace'])
    params=work/'params.json';_write(params,(json.dumps(preview_protocol_parameters())+'\n').encode(),True)
    policy_file=work/'policy.json';_write(policy_file,(json.dumps({'type':'sig','keyHash':alice['keyhash']})+'\n').encode(),True)
    policy=subprocess.check_output([str(CLI),'conway','transaction','policyid','--script-file',str(policy_file)],text=True,timeout=30).strip()
    if not re.fullmatch('[0-9a-f]{56}',policy):raise ValueError('Invalid fixture mint policy')
    minted={policy+'.46554e47':1000,policy+'.4e4654':1}
    body=work/'setup.body';fee=build_balanced(inputs=[{k:selected[k] for k in ('outref','lovelace','assets')}],outputs=[{'address':bob['address'],'lovelace':BOB_OUTPUT,'assets':{}},{'address':bob['address'],'lovelace':BOB_OUTPUT,'assets':{}},{'address':alice['address'],'lovelace':FIXTURE_ADA,'assets':minted}],change_address=alice['address'],params=params,body=body,mint=minted,mint_script=policy_file)
    state={'version':1,'phase':'prepared','policy':policy,'input':selected['outref'],'fee_lovelace':fee,'minted':minted,'alice_address':alice['address'],'bob_address':bob['address']}
    _write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),True)
    return state


def _state(work):
    value=json.loads((work/'state.json').read_text())
    if value.get('version')!=1 or not re.fullmatch('[0-9a-f]{56}',value.get('policy','')):raise ValueError('Invalid Cardano setup state')
    return value


def _save(work,state):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode())


def send(directory):
    root=_directory(directory);work=_directory(root/'cardano-setup');state=_state(work)
    if state['phase']!='prepared':raise ValueError('Cardano setup was already attempted; inspect journal and chain')
    state['phase']='submit_inflight';_save(work,state)
    result=sign_and_submit(work,work/'setup.body',actor(root,'alice')['skey'])
    state.update(phase='submitted',txid=result['txid']);_save(work,state)
    return {'phase':state['phase'],'txid':state['txid'],'confirmed':False}


def status(directory):
    root=_directory(directory);work=_directory(root/'cardano-setup');state=_state(work)
    if state['phase']!='submitted':return {'phase':state['phase']}
    depth=status_confirmations(state['txid'])
    if depth<2:return {'phase':'submitted','confirmations':depth}
    alice=cardano_utxos(state['alice_address']);bob=cardano_utxos(state['bob_address']);prefix=state['txid']+'#'
    fixtures=[x for x in alice if x['outref'].startswith(prefix) and x['lovelace']==FIXTURE_ADA and x['assets']==state['minted']]
    bob_outputs=[x for x in bob if x['outref'].startswith(prefix) and x['lovelace']==BOB_OUTPUT and not x['assets']]
    if len(fixtures)!=1 or len(bob_outputs)!=2:raise ValueError('Cardano confirmed setup outputs do not match the plan')
    return {'phase':'confirmed','txid':state['txid'],'confirmations':depth,'policy':state['policy'],'fixture_outref':fixtures[0]['outref'],'bob_outrefs':[x['outref'] for x in bob_outputs]}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['prepare','submit','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as directory:result={'prepare':prepare,'submit':send,'status':status}[args.operation](directory)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
