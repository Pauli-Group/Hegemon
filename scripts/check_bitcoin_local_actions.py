#!/usr/bin/env python3
"""Exercise terminal-approved Bitcoin actions on a fresh, peerless regtest."""
import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from bitcoin_local_actions import run_bitcoin_action
from development_atomic_swap_rehearsal import BitcoinRPC,rehearsal_bitcoin_key
from local_private_spend_swap import descriptor,port,require,stop
from bitcoin_companion_actions_check import TestBitcoinActions


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bitcoind',type=Path,default=Path('/workspace/bitcoin-32.1/bin/bitcoind'))
    p.add_argument('--exercise-companion',action='store_true',help='run actions through locally approved companion terminals')
    p.add_argument('--encrypted-wallets',action='store_true',help='use encrypted disposable wallets')
    a=p.parse_args();os.umask(0o077);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False)
    data=out/'bitcoin';data.mkdir(mode=0o700);rpcport=port();process=None;clients={};receipt={'status':'failed','checks':{}}
    try:
        process=subprocess.Popen([a.bitcoind,'-regtest',f'-datadir={data}','-listen=0','-connect=0','-discover=0','-dnsseed=0',f'-rpcport={rpcport}','-fallbackfee=0.0002','-printtoconsole=0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        btc=BitcoinRPC(f'http://127.0.0.1:{rpcport}',data/'regtest/.cookie')
        deadline=time.monotonic()+30
        while True:
            require(process.poll() is None,'Bitcoin process exited')
            try:require(btc.call('getblockchaininfo')['chain']=='regtest','wrong chain');break
            except (OSError,RuntimeError):require(time.monotonic()<deadline,'Bitcoin startup failed');time.sleep(.1)
        wallet_phrase='local disposable Bitcoin passphrase' if a.encrypted_wallets else ''
        for name in ('claim','refund'):btc.call('createwallet',name,False,False,wallet_phrase,False,True,sensitive=True)
        claimpub,claimkey=rehearsal_bitcoin_key();refundpub,refundkey=rehearsal_bitcoin_key()
        miner=btc.call('getnewaddress',wallet='refund');btc.call('generatetoaddress',101,miner);genesis=btc.call('getblockhash',0)
        destination=btc.call('getnewaddress',wallet='claim');refund_destination=btc.call('getnewaddress',wallet='refund')
        if a.exercise_companion:
            for name in ('claim','refund'):clients[name]=TestBitcoinActions(out/(name+'-companion'),url=f'http://127.0.0.1:{rpcport}',cookie=data/'regtest/.cookie',wallet=name,genesis=genesis,wallet_phrase=wallet_phrase.encode() if wallet_phrase else None)
            require(clients['refund'].request('/bitcoin/action',{'operation':'lock'},credential='0'*64)[0]==403,'Bitcoin action accepted bad credential')
            require(clients['refund'].request('/bitcoin/action',{'operation':'lock','secret':'forbidden'})[0]==400,'Bitcoin action accepted secret field')
        def act(action,wallet,secret=None):
            if clients:return clients[wallet].action(action,secret=secret)
            return run_bitcoin_action(btc=btc,wallet=wallet,genesis=genesis,request=action,confirm=lambda _:'APPROVE',password=lambda prompt:wallet_phrase if prompt.startswith('Bitcoin wallet') else secret.hex() if secret else 'unused')
        def fail(action,wallet):
            if clients:clients[wallet].action(action,expected=False);return
            try:run_bitcoin_action(btc=btc,wallet=wallet,genesis=genesis,request=action,confirm=lambda _:'APPROVE',password=lambda _:wallet_phrase or 'unused')
            except ValueError:return
            raise RuntimeError('invalid Bitcoin action succeeded')
        for scenario in ('claim','refund'):
            secret=os.urandom(32);digest=hashlib.sha256(secret).hexdigest();height=btc.call('getblockcount')+15
            def desc(c,r):return f'wsh(or_i(and_v(v:sha256({digest}),pk({c})),and_v(v:after({height}),pk({r}))))'
            for name in ('claim','refund'):
                if wallet_phrase:btc.call('walletpassphrase',wallet_phrase,120,wallet=name,sensitive=True)
                try:descriptor(btc,name,desc(claimkey,refundpub) if name=='claim' else desc(claimpub,refundkey))
                finally:
                    if wallet_phrase:btc.call('walletlock',wallet=name,sensitive=True)
            terms={'operation':'lock','hashlock':digest,'claimant_key':claimpub,'refund_key':refundpub,'refund_height':str(height),'amount_sats':'100000'}
            if clients:clients['refund'].action(terms,expected=False,approve=False);receipt['checks']['local_denial']=True
            fail(terms,'claim');receipt['checks'][scenario+'_wrong_refund_key_rejected']=True
            result=act(terms,'refund')
            require(result['submitted'] and not result['confirmed'],'invalid funding acknowledgement')
            btc.call('generatetoaddress',1,miner);funding=btc.call('gettransaction',result['txid'],wallet='refund')
            decoded=btc.call('getrawtransaction',result['txid'],True,funding['blockhash'])
            output=next(v for v in decoded['vout'] if v['scriptPubKey'].get('address')==result['address'])
            action={**terms,'operation':scenario,'txid':result['txid'],'vout':str(output['n']),'destination':destination if scenario=='claim' else refund_destination}
            fail({**action,'amount_sats':'99999'},scenario)
            if scenario=='refund':
                fail(action,'refund');receipt['checks']['early_refund_rejected']=True
                btc.call('generatetoaddress',height-btc.call('getblockcount')+1,miner)
            answer=act(action,scenario,secret=secret if scenario=='claim' else None)
            btc.call('generatetoaddress',1,miner)
            require(btc.call('gettxout',result['txid'],output['n'],True) is None,'Bitcoin output remained unspent')
            require(btc.call('gettransaction',answer['txid'],wallet=scenario)['confirmations']>=1,'spend not confirmed')
            if wallet_phrase:require(btc.call('getwalletinfo',wallet=scenario)['unlocked_until']==0,'wallet remained unlocked')
            fail(action,scenario);receipt['checks'][scenario+'_confirmed']=True
        require(btc.call('getconnectioncount')==0,'Bitcoin acquired a peer');receipt['checks']['zero_peers']=True;receipt['status']='passed'
    finally:
        for client in clients.values():client.close()
        stop(process);(out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(out/'summary.json')}),flush=True)

if __name__=='__main__':main()
