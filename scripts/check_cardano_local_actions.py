#!/usr/bin/env python3
"""Exercise Cardano wallet actions and native assets on fresh peerless nodes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from cardano_local_actions import run_cardano_action
from htlc_counterpart import Cardano,TOOLS,wait_for
from local_private_spend_swap import require
from cardano_companion_actions_check import TestCardanoActions


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS);p.add_argument('--exercise-companion',action='store_true');p.add_argument('--exercise-backup-claim',action='store_true');p.add_argument('--scenario',choices=('all','claim','refund'),default='all')
    a=p.parse_args();os.umask(0o077)
    if a.exercise_backup_claim and not a.exercise_companion:p.error('backup claim requires the companion')
    out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False);results=[];scenarios=('claim','refund') if a.scenario=='all' else (a.scenario,)
    try:
        for scenario in scenarios:
            chain=Cardano(out/scenario,a.tools,test_tokens=True,epoch_length=5000);checks={};clients={}
            try:
                chain.isolated();genesis_hash=hashlib.sha256((chain.net/'shelley-genesis.json').read_bytes()).hexdigest()
                journals={actor:out/(scenario+'-'+actor+'-journal') for actor in ('alice','bob')}
                for directory in journals.values():directory.mkdir(mode=0o700)
                secret=os.urandom(32);digest=hashlib.sha256(secret).hexdigest();backup=None;backup_phrase=None
                if scenario=='claim' and a.exercise_backup_claim:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    backup_phrase=b'local disposable backup passphrase';salt=os.urandom(16);iv=os.urandom(12)
                    key=hashlib.pbkdf2_hmac('sha256',backup_phrase,salt,600000,32);ciphertext=AESGCM(key).encrypt(iv,secret,('hegemon.swap.secret.v1:'+digest).encode())
                    backup=out/'encrypted-preimage.json';backup.write_text(json.dumps({'label':'local fixture','envelope':{'version':1,'iterations':600000,'hashlock':digest,'salt':salt.hex(),'iv':iv.hex(),'ciphertext':ciphertext.hex()}}))
                if a.exercise_companion:
                    for actor in ('alice','bob'):clients[actor]=TestCardanoActions(out/(scenario+'-'+actor+'-companion'),chain=chain,key=chain.actors[actor]['skey'],genesis=genesis_hash,backup=backup if actor=='alice' else None,backup_phrase=backup_phrase if actor=='alice' else None)
                    require(clients['bob'].request('/cardano/action',{'operation':'lock'},credential='0'*64)[0]==403,'Cardano action accepted bad credential')
                    require(clients['bob'].request('/cardano/action',{'operation':'lock','secret':'forbidden'})[0]==400,'Cardano action accepted secret field')
                expiry_slot=chain.tip()['slot']+180
                value={'lovelace':str(chain.amount),**{policy:{name:str(q) for name,q in assets.items()} for policy,assets in chain.tokens.items()}}
                terms={'operation':'lock','hashlock':digest,'claimant':chain.actors['alice']['hash'],'refundee':chain.actors['bob']['hash'],
                       'expiry_ms':str(chain.start_ms+expiry_slot*chain.slot_ms),'expected_value':value,'inputs':[chain.fee_input('bob'),chain.token_input]}
                def invoke(request,actor,secret_value=None):
                    if clients:result=clients[actor].action(request,secret=secret_value);directory=clients[actor].journal
                    else:
                        directory=journals[actor];result=run_cardano_action(chain=chain,pid=chain.proc.pid,genesis_hash=genesis_hash,signing_key=chain.actors[actor]['skey'],journal_dir=directory,request=request,confirm=lambda _:'APPROVE',password=lambda _:secret_value.hex() if secret_value else 'unused')
                    record=directory/result['journal_record'];saved=record.read_text();data=json.loads(saved)
                    require(data['state']=='prepared_or_submitted' and data['txid']==result['txid'] and (record.stat().st_mode&0o077)==0,'Cardano recovery record is invalid')
                    if secret_value:require(secret_value.hex() not in saved,'Cardano recovery record contains the preimage')
                    return result
                def reject(request,actor):
                    if clients:clients[actor].action(request,expected=False);return
                    try:invoke(request,actor)
                    except ValueError:return
                    raise RuntimeError('invalid Cardano action succeeded')
                if clients:clients['bob'].action(terms,expected=False,approve=False);checks['local_denial']=True
                reject(terms,'alice');checks['wrong_signer_rejected']=True
                lock=invoke(terms,'bob');require(lock['submitted'] and not lock['confirmed'],'invalid Cardano funding acknowledgement')
                found=wait_for(lambda:{k:v for k,v in chain.utxos(chain.address).items() if k.startswith(lock['txid']+'#')},'Cardano lock inclusion')
                locked=next(k for k,v in found.items() if v['value'].get('lovelace')==chain.amount and chain.has_tokens(v))
                confirmed=chain.tip()['block'];wait_for(lambda:chain.tip()['block']>=confirmed+2,'Cardano local blocks')
                spend={k:v for k,v in terms.items() if k!='inputs'};spend.update(operation=scenario,outref=locked,fee_input=chain.fee_input('alice' if scenario=='claim' else 'bob'),collateral=chain.actors['alice' if scenario=='claim' else 'bob']['collateral'])
                bad={**spend,'expected_value':{**value,'lovelace':str(chain.amount-1)}};reject(bad,'alice' if scenario=='claim' else 'bob');checks['altered_value_rejected']=True
                if scenario=='refund':
                    reject(spend,'bob');checks['early_refund_rejected']=True
                    wait_for(lambda:chain.tip()['slot']>=expiry_slot,'Cardano refund slot',seconds=90)
                result=invoke(spend,'alice' if scenario=='claim' else 'bob',secret if scenario=='claim' else None)
                if backup:checks['encrypted_backup_claim']=True
                wait_for(lambda:locked not in chain.utxos(chain.address),'Cardano spent output')
                target=chain.actors['alice' if scenario=='claim' else 'bob']['address']
                payout=wait_for(lambda:{k:v for k,v in chain.utxos(target).items() if k.startswith(result['txid']+'#')},'Cardano payout')
                require(any(v['value'].get('lovelace')==chain.amount and chain.has_tokens(v) for v in payout.values()),'Cardano payout value mismatch')
                reject(spend,'alice' if scenario=='claim' else 'bob');chain.isolated();checks.update(spend_confirmed=True,zero_peers=True)
                results.append({'scenario':scenario,'status':'passed','checks':checks});print(scenario,'passed',flush=True)
            finally:
                for client in clients.values():client.close()
                chain.close()
    finally:(out/'summary.json').write_text(json.dumps({'status':'passed' if len(results)==len(scenarios) else 'failed','scenarios':results},indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(out/'summary.json')}),flush=True)

if __name__=='__main__':main()
