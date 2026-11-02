#!/usr/bin/env python3
"""Swap disposable Cardano preview fungible and NFT fixtures in stages.

Each advance submits at most one transaction and records an inflight state
before signing. Public indexers are trusted and the deadlines are test-only.
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
from public_btc_eth_rehearsal import _directory,_locked,_write
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_setup import actor,status_confirmations
from public_cardano_transactions import CLI,build_balanced
from public_cardano_verify import AIKEN,verify_preview
from public_testnet_observers import cardano_claim
from public_testnet_probe import CARDANO,request
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
LOCK_ADA=4_000_000
COLLATERAL_ADA=20_000_000


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    value=json.loads((work/'state.json').read_text())
    if value.get('version')!=1 or value.get('scenario')!='cardano-native-pair' or not re.fullmatch('[0-9a-f]{64}',value.get('hashlock','')):raise ValueError('Invalid Cardano same-chain state')
    return value
def _input(item):return {key:item[key] for key in ('outref','lovelace','assets')}
def _begin(work,state,name):state['phase']=name+'_inflight';_save(work,state)
def _tip():
    verify_network('cardano-preview');rows=json.loads(request(CARDANO+'/tip'))
    if len(rows)!=1 or type(rows[0].get('abs_slot')) is not int:raise ValueError('Cardano preview tip unavailable')
    return rows[0]['abs_slot']
def _choose(rows,minimum,excluded=()):
    options=[x for x in rows if x['outref'] not in excluded and not x['assets'] and x['lovelace']>=minimum and status_confirmations(x['outref'].split('#')[0])>=2]
    if not options:raise ValueError('No confirmed ADA-only fee output')
    return min(options,key=lambda x:x['lovelace'])
def _choose_fee(rows,minimum,excluded=()):
    try:return _choose(rows,minimum,excluded)
    except ValueError:
        # The offline builder returns every unspent native asset in change.
        options=[x for x in rows if x['outref'] not in excluded and x['assets'] and x['lovelace']>=minimum and status_confirmations(x['outref'].split('#')[0])>=2]
        if not options:raise ValueError('No confirmed fee output with sufficient ADA')
        return min(options,key=lambda x:x['lovelace'])
def _assets(rows,asset,quantity):
    options=[x for x in rows if x['assets'].get(asset,0)>=quantity and status_confirmations(x['outref'].split('#')[0])>=2]
    if len(options)!=1:raise ValueError('Expected exactly one confirmed fixture asset output')
    return options[0]


def initialize(root):
    root=_directory(root);verify_network('cardano-preview');setup=json.loads((root/'cardano-setup/state.json').read_text())
    if setup.get('phase')!='submitted' or status_confirmations(setup['txid'])<2:raise ValueError('Cardano fixture mint is not confirmed')
    policy=setup['policy'];fungible=policy+'.46554e47';nft=policy+'.4e4654'
    alice=actor(root,'alice');bob=actor(root,'bob');rows=cardano_utxos(alice['address'])
    fixture=_assets(rows,nft,1)
    if fixture['assets'].get(fungible)!=1000:raise ValueError('Minted fixture bundle differs from expected')
    work=root/'cardano-native-pair';work.mkdir(mode=0o700);secret=secrets.token_bytes(32);_write(work/'secret',secret,True)
    params=preview_protocol_parameters();_write(work/'params.json',(json.dumps(params)+'\n').encode(),True)
    validator=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30);_write(work/'validator.plutus',validator,True)
    address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(work/'validator.plutus'),'--testnet-magic','2'],text=True,timeout=30).strip()
    slot=_tip();actors={'alice':{'address':alice['address'],'keyhash':alice['keyhash']},'bob':{'address':bob['address'],'keyhash':bob['keyhash']}}
    state={'version':1,'scenario':'cardano-native-pair','phase':'distribute','hashlock':hashlib.sha256(secret).hexdigest(),'actors':actors,'fungible':fungible,'nft':nft,'script_address':address,'expiry_slots':{'long':slot+7200,'short':slot+3600}}
    _save(work,state,True);return {'phase':'distribute','hashlock':state['hashlock']}


def _verify(work,state,name):
    funder='alice' if name=='long' else 'bob';claimant='bob' if name=='long' else 'alice'
    asset=state['fungible'] if name=='long' else state['nft'];qty=10 if name=='long' else 1
    return verify_preview(work/'validator.plutus',state[name+'_lock']+'#0',state['hashlock'],state['actors'][claimant]['keyhash'],state['actors'][funder]['keyhash'],(1666656000+state['expiry_slots'][name])*1000,LOCK_ADA,{asset:qty})


def advance(root):
    root=_directory(root);work=_directory(root/'cardano-native-pair');state=_state(work);phase=state['phase'];actors=state['actors']
    for name in ('alice','bob'):
        current=actor(root,name)
        if current['address']!=actors[name]['address'] or current['keyhash']!=actors[name]['keyhash']:raise ValueError('Cardano same-chain wallet changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before recovery')
    if phase=='distribute':
        rows=cardano_utxos(actors['alice']['address']);fixture=_assets(rows,state['nft'],1);fee=_choose(rows,COLLATERAL_ADA+10_000_000,(fixture['outref'],))
        body=work/'distribute.body';build_balanced(inputs=[_input(fixture),_input(fee)],outputs=[{'address':actors['bob']['address'],'lovelace':LOCK_ADA,'assets':{state['nft']:1}},{'address':actors['alice']['address'],'lovelace':LOCK_ADA,'assets':{state['fungible']:1000}},{'address':actors['alice']['address'],'lovelace':COLLATERAL_ADA,'assets':{}}],change_address=actors['alice']['address'],params=work/'params.json',body=body)
        _begin(work,state,'distribute');result=sign_and_submit(work,body,actor(root,'alice')['skey']);state.update(phase='distribute_submitted',distribution=result['txid']);_save(work,state)
    elif phase=='distribute_submitted':
        if status_confirmations(state['distribution'])>=2:
            alice=cardano_utxos(actors['alice']['address']);bob=cardano_utxos(actors['bob']['address']);prefix=state['distribution']+'#'
            if not any(x['outref']==prefix+'0' and x['assets']=={state['nft']:1} for x in bob) or not any(x['outref']==prefix+'1' and x['assets']=={state['fungible']:1000} for x in alice) or not any(x['outref']==prefix+'2' and x['lovelace']==COLLATERAL_ADA and not x['assets'] for x in alice):raise ValueError('Fixture distribution outputs mismatch')
            bob_collateral=_choose(bob,COLLATERAL_ADA)
            state.update(phase='fund_long',alice_collateral=prefix+'2',bob_collateral=bob_collateral['outref']);_save(work,state)
    elif phase in ('fund_long','fund_short'):
        name=phase.removeprefix('fund_');funder='alice' if name=='long' else 'bob';claimant='bob' if name=='long' else 'alice';asset=state['fungible'] if name=='long' else state['nft'];qty=10 if name=='long' else 1
        if name=='short':_verify(work,state,'long')
        if state['expiry_slots'][name]-_tip()<600:raise ValueError('Cardano test deadline too close')
        rows=cardano_utxos(actors[funder]['address']);fixture=_assets(rows,asset,qty);fee=_choose(rows,5_000_000,(fixture['outref'],state[funder+'_collateral']))
        expiry=(1666656000+state['expiry_slots'][name])*1000;datum={'constructor':0,'fields':[{'bytes':state['hashlock']},{'bytes':actors[claimant]['keyhash']},{'bytes':actors[funder]['keyhash']},{'int':expiry}]}
        datum_file=work/(name+'-datum.json');_write(datum_file,(json.dumps(datum)+'\n').encode(),True);body=work/(name+'-lock.body')
        build_balanced(inputs=[_input(fixture),_input(fee)],outputs=[{'address':state['script_address'],'lovelace':LOCK_ADA,'assets':{asset:qty},'datum':datum_file}],change_address=actors[funder]['address'],params=work/'params.json',body=body)
        _begin(work,state,phase);result=sign_and_submit(work,body,actor(root,funder)['skey']);state.update(phase=phase+'_submitted',**{name+'_lock':result['txid']});_save(work,state)
    elif phase in ('fund_long_submitted','fund_short_submitted'):
        name=phase.split('_')[1]
        if status_confirmations(state[name+'_lock'])>=2:
            _verify(work,state,name);state['phase']='fund_short' if name=='long' else 'both_verified';_save(work,state)
    elif phase=='both_verified':
        _verify(work,state,'long');_verify(work,state,'short')
        if state['expiry_slots']['short']-_tip()<600 or state['expiry_slots']['long']-state['expiry_slots']['short']<1800:raise ValueError('Cardano swap deadlines are too close')
        secret_path=work/'secret';st=secret_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=secret_path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup mismatch')
        _claim(root,work,state,'short',secret)
    elif phase=='claim_short_submitted':
        if status_confirmations(state['short_claim'])>=2:
            secret,_=cardano_claim(state['short_claim'],state['short_lock']+'#0',state['hashlock'])
            try:_claim(root,work,state,'long',bytes(secret))
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='claim_long_submitted':
        if status_confirmations(state['long_claim'])>=2:
            secret,_=cardano_claim(state['long_claim'],state['long_lock']+'#0',state['hashlock']);secret[:]=b'\0'*len(secret)
            alice=cardano_utxos(actors['alice']['address']);bob=cardano_utxos(actors['bob']['address'])
            if not any(x['outref'].startswith(state['short_claim']+'#') and x['assets'].get(state['nft'])==1 for x in alice) or not any(x['outref'].startswith(state['long_claim']+'#') and x['assets'].get(state['fungible'])==10 for x in bob):raise ValueError('Cardano fixture token recipients do not match')
            state['phase']='complete';_save(work,state)
    elif phase!='complete':raise ValueError('Unknown Cardano same-chain phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def _claim(root,work,state,name,secret):
    claimant='bob' if name=='long' else 'alice';funder='alice' if name=='long' else 'bob';asset=state['fungible'] if name=='long' else state['nft'];qty=10 if name=='long' else 1;actors=state['actors']
    if _tip()>=state['expiry_slots'][name]-60:raise ValueError('Cardano claim deadline too close')
    _verify(work,state,name);rows=cardano_utxos(actors[claimant]['address']);fee=_choose_fee(rows,5_000_000,(state[claimant+'_collateral'],))
    if not any(x['outref']==state[claimant+'_collateral'] and not x['assets'] for x in rows):raise ValueError('Cardano collateral unavailable')
    redeemer=work/(name+'-redeemer.json');_write(redeemer,(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]})+'\n').encode(),True)
    script_input={'outref':state[name+'_lock']+'#0','lovelace':LOCK_ADA,'assets':{asset:qty},'script':work/'validator.plutus','redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
    body=work/(name+'-claim.body');build_balanced(inputs=[script_input,_input(fee)],outputs=[{'address':actors[claimant]['address'],'lovelace':LOCK_ADA,'assets':{asset:qty}}],change_address=actors[claimant]['address'],params=work/'params.json',body=body,collateral=state[claimant+'_collateral'],required_signer=actors[claimant]['keyhash'],invalid_hereafter=state['expiry_slots'][name])
    _begin(work,state,'claim_'+name);result=sign_and_submit(work,body,actor(root,claimant)['skey']);state.update(phase='claim_'+name+'_submitted',**{name+'_claim':result['txid']});_save(work,state)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:
            state=_state(_directory(root/'cardano-native-pair'));result={k:v for k,v in state.items() if k!='actors'}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
