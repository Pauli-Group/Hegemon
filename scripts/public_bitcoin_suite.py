#!/usr/bin/env python3
"""Advance prepared Bitcoin testnet cases using independently funded inputs.

Each action is journaled by its scenario. A failure stops the runner: inspect
all inflight states and chain records before restarting. It is not a service or
a production swap coordinator.
"""
import argparse
import json
import time
import urllib.error
from pathlib import Path
from embit import networks,script
from public_bitcoin_driver import load_test_key
from public_btc_eth_rehearsal import _directory,_locked,advance as eth_advance
from public_bitcoin_split import advance as split_advance
from public_btc_cardano_rehearsal import advance as cardano_advance
from public_btc_erc20_rehearsal import advance as erc20_advance
from public_bitcoin_refund_rehearsal import advance as refund_advance
from public_testnet_utxos import bitcoin_utxos
from public_testnet_observers import IndexerDataPending

CASES=(('btc-cardano','created'),('btc-cardano-token','created'),('btc-erc20','btc_lock'),('bitcoin-refund','lock'))


def states(root):
    result={name:json.loads((root/name/'state.json').read_text()) for name,_ in CASES}
    for name,s in result.items():
        if not isinstance(s.get('phase'),str) or s['phase'].endswith('_inflight'):raise ValueError('Uncertain '+name+' action; inspect its private journal and chain')
    return result


def check_retry_safe(root):
    states(root)
    for path in (root/'btc-eth-state.json',root/'bitcoin-split/state.json'):
        phase=json.loads(path.read_text()).get('phase')
        if not isinstance(phase,str) or phase.endswith('_inflight') or phase=='inflight':raise ValueError('Uncertain action; inspect the private journal and chain')


def step(root):
    root=_directory(root);eth=eth_advance(root)
    with _locked(root):
        split=split_advance(root);current=states(root)
        if split['phase']!='submitted':return {'btc_eth':eth['phase'],'split':split['phase'],**{n:s['phase'] for n,s in current.items()}}
        split_inputs=set()
        if any(current[name]['phase']==initial for name,initial in CASES):
            key=load_test_key(root/'alice/bitcoin-testnet4.key');address=script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['test'])
            available=bitcoin_utxos(address)
            split_inputs={(x['txid'],x['vout']) for x in available if x['txid']==split['txid'] and x['vout']<4 and x['amount_sats']==7000}
        for name,initial in CASES:
            state=current[name];phase=state['phase']
            if phase=='complete':continue
            if phase==initial:
                if not split_inputs:continue
                # One new Bitcoin spend per pass; refresh indexer snapshots next pass.
                if name=='btc-cardano':cardano_advance(root)
                elif name=='btc-cardano-token':cardano_advance(root,True)
                elif name=='btc-erc20':erc20_advance(root)
                else:refund_advance(root)
                break
            if name=='btc-cardano-token' and phase not in ('btc_lock_submitted',):
                # Both Cardano scenarios share fee and collateral wallets.
                if current['btc-cardano']['phase'] not in ('btc_claim_submitted','complete'):continue
            if name=='btc-cardano':cardano_advance(root)
            elif name=='btc-cardano-token':cardano_advance(root,True)
            elif name=='btc-erc20':erc20_advance(root)
            else:refund_advance(root)
        current=states(root)
    return {'btc_eth':eth['phase'],'split':split['phase'],**{n:s['phase'] for n,s in current.items()}}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--once',action='store_true');args=parser.parse_args()
    last=None
    while True:
        try:result=step(args.directory)
        except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError,IndexerDataPending) as error:
            if isinstance(error,urllib.error.HTTPError) and error.code not in (429,500,502,503,504):raise
            # No retry if any submission might have been signed or sent.
            with _locked(args.directory) as root:
                check_retry_safe(root)
            if args.once:raise
            print('Public provider temporarily unavailable; will recheck recorded states.',flush=True)
            time.sleep(60);continue
        if result!=last:print(json.dumps(result,sort_keys=True),flush=True);last=result
        if args.once or all(result.get(name)=='complete' for name in ('btc_eth',*(n for n,_ in CASES))):return
        time.sleep(60)


if __name__=='__main__':main()
