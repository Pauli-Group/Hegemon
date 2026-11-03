#!/usr/bin/env python3
"""Split preview test ADA into participant fee outputs, preserving assets."""
import argparse
import json
from pathlib import Path
from public_btc_eth_rehearsal import _directory,_locked,_write
from public_cardano_driver import preview_protocol_parameters,sign_and_submit
from public_cardano_setup import actor,status_confirmations
from public_cardano_transactions import build_balanced
from public_testnet_utxos import cardano_utxos

FEE_OUTPUT=30_000_000


def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    s=json.loads((work/'state.json').read_text())
    if s.get('version')!=1 or s.get('scenario')!='cardano-refuel':raise ValueError('Invalid Cardano refuel state')
    return s


def prepare(root):
    root=_directory(root);alice=actor(root,'alice');bob=actor(root,'bob');pair=json.loads((root/'cardano-native-pair/state.json').read_text())
    outputs=cardano_utxos(alice['address']);options=[x for x in outputs if x['outref']!=pair['alice_collateral'] and x['lovelace']>2*FEE_OUTPUT+5_000_000 and status_confirmations(x['outref'].split('#')[0])>=2]
    if not options:raise ValueError('No confirmed Cardano output can supply fee funds')
    coin=max(options,key=lambda x:x['lovelace']);work=root/'cardano-refuel';work.mkdir(mode=0o700);params=work/'params.json';_write(params,(json.dumps(preview_protocol_parameters())+'\n').encode(),True)
    body=work/'refuel.body';fee=build_balanced(inputs=[{k:coin[k] for k in ('outref','lovelace','assets')}],outputs=[{'address':alice['address'],'lovelace':FEE_OUTPUT,'assets':{}},{'address':bob['address'],'lovelace':FEE_OUTPUT,'assets':{}}],change_address=alice['address'],params=params,body=body)
    state={'version':1,'scenario':'cardano-refuel','phase':'prepared','input':coin['outref'],'assets_in_change':coin['assets'],'fee_lovelace':fee,'alice':alice['address'],'bob':bob['address']};_save(work,state,True);return {'phase':'prepared'}


def send(root):
    root=_directory(root);work=_directory(root/'cardano-refuel');state=_state(work)
    if state['phase']!='prepared':raise ValueError('Refuel action already attempted; inspect the journal')
    state['phase']='submit_inflight';_save(work,state);result=sign_and_submit(work,work/'refuel.body',actor(root,'alice')['skey']);state.update(phase='submitted',txid=result['txid']);_save(work,state)
    return {'phase':'submitted','txid':state['txid']}


def status(root):
    root=_directory(root);work=_directory(root/'cardano-refuel');state=_state(work)
    if state['phase']!='submitted':return {'phase':state['phase']}
    depth=status_confirmations(state['txid'])
    if depth<2:return {'phase':'submitted','confirmations':depth}
    alice=cardano_utxos(state['alice']);bob=cardano_utxos(state['bob']);prefix=state['txid']+'#'
    if not any(x['outref']==prefix+'0' and x['lovelace']==FEE_OUTPUT and not x['assets'] for x in alice) or not any(x['outref']==prefix+'1' and x['lovelace']==FEE_OUTPUT and not x['assets'] for x in bob) or not any(x['outref']==prefix+'2' and x['assets']==state['assets_in_change'] for x in alice):raise ValueError('Cardano refuel outputs or preserved assets mismatch')
    return {'phase':'confirmed','txid':state['txid'],'confirmations':depth}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['prepare','submit','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:result={'prepare':prepare,'submit':send,'status':status}[args.operation](root)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
