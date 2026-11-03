#!/usr/bin/env python3
"""Split confirmed testnet4 wallet funds for independent test scenarios."""
import argparse
import json
from pathlib import Path
from embit import networks,script
from public_bitcoin_driver import _fee,load_test_key
from public_bitcoin_transactions import split
from public_btc_eth_rehearsal import _directory,_locked,_write
from public_testnet_submit import submit,verify_network
from public_testnet_utxos import bitcoin_utxos


def save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)


def initialize(root):
    root=_directory(root);work=root/'bitcoin-split';work.mkdir(mode=0o700)
    save(work,{'version':1,'phase':'created'},True);return {'phase':'created'}


def advance(root):
    root=_directory(root);work=_directory(root/'bitcoin-split');state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1:raise ValueError('Invalid split state')
    if state['phase']=='inflight':raise ValueError('Uncertain split submission; inspect journal and chain before recovery')
    if state['phase']=='created':
        verify_network('bitcoin-testnet4');key=load_test_key(root/'alice/bitcoin-testnet4.key')
        address=script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['test']);fee=_fee()
        coins=[c for c in bitcoin_utxos(address) if c['amount_sats']>=4*7000+fee+546]
        if not coins:return {'phase':'created','pending':True}
        coin=min(coins,key=lambda c:c['amount_sats']);amounts=[7000]*4+[coin['amount_sats']-28000-fee]
        tx=split(coin['txid'],coin['vout'],coin['amount_sats'],key,amounts,fee)
        state.update(phase='inflight',input_txid=coin['txid'],input_vout=coin['vout'],txid=tx.txid().hex(),amounts=amounts,fee=fee);save(work,state)
        result=submit(work,'bitcoin-testnet4',tx.serialize())
        if result['txid']!=state['txid']:raise ValueError('Split transaction mismatch')
        state['phase']='submitted';save(work,state)
    return {'phase':state['phase'],'txid':state.get('txid'),'pending':state['phase']=='created'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        result=initialize(root) if args.operation=='init' else advance(root) if args.operation=='advance' else json.loads((_directory(root/'bitcoin-split')/'state.json').read_text())
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
