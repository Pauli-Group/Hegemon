#!/usr/bin/env python3
"""Exercise a complete manual BTC/Cardano fixture swap via local companions.

The second participant obtains the preimage from confirmed Cardano blocks via
local Ogmios and imports only an encrypted backup into its Bitcoin companion.
All keys and networks are disposable; this is not a production coordinator.
"""
import argparse
import hashlib
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from bitcoin_companion_actions_check import TestBitcoinActions
from bitcoin_escrow_verifier import verify_bitcoin_htlc
from bitcoin_preimage_observer import observe_bitcoin_preimage
from cardano_companion_actions_check import TestCardanoActions
from cardano_escrow_verifier import verify_cardano_htlc
from cardano_local_actions import value_terms
from cardano_preimage_observer import observe_local_preimage
from development_atomic_swap_rehearsal import BitcoinRPC,rehearsal_bitcoin_key
from htlc_counterpart import Cardano,TOOLS,wait_for
from local_private_spend_swap import descriptor,port,require,stop
from unlock_swap_backup import save_recovered_backup


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
    p.add_argument('--bitcoind',type=Path,default=Path('/workspace/bitcoin-32.1/bin/bitcoind'));p.add_argument('--ogmios',type=Path,default=Path('/workspace/chain-tools/ogmios/bin/ogmios'))
    a=p.parse_args();os.umask(0o077);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False)
    cardano=bitcoin=ogmios=None;clients=[];receipt={'status':'failed','checks':{}};secret=bytearray(os.urandom(32))
    try:
        digest=hashlib.sha256(secret).hexdigest();cardano=Cardano(out/'ada',a.tools,test_tokens=True,epoch_length=5000);cardano.isolated()
        cgenesis=hashlib.sha256((cardano.net/'shelley-genesis.json').read_bytes()).hexdigest()
        backup_phrase=b'local disposable Cardano backup passphrase';initial_backup=save_recovered_backup(out,secret,backup_phrase,label='Local fixture')
        alice=TestCardanoActions(out/'cardano-alice',chain=cardano,key=cardano.actors['alice']['skey'],genesis=cgenesis,backup=initial_backup,backup_phrase=backup_phrase);clients.append(alice)
        bob=TestCardanoActions(out/'cardano-bob',chain=cardano,key=cardano.actors['bob']['skey'],genesis=cgenesis);clients.append(bob)
        bd=out/'btc';bd.mkdir(mode=0o700);rp=port()
        bitcoin=subprocess.Popen([a.bitcoind,'-regtest',f'-datadir={bd}','-listen=0','-connect=0','-discover=0','-dnsseed=0',f'-rpcport={rp}','-fallbackfee=0.0002','-printtoconsole=0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        btc=BitcoinRPC(f'http://127.0.0.1:{rp}',bd/'regtest/.cookie');deadline=time.monotonic()+30
        while True:
            require(bitcoin.poll() is None,'Bitcoin node exited')
            try:require(btc.call('getblockchaininfo')['chain']=='regtest','wrong Bitcoin chain');break
            except (OSError,RuntimeError):require(time.monotonic()<deadline,'Bitcoin startup failed');time.sleep(.1)
        phrase='local disposable Bitcoin wallet passphrase'
        for name in ('alice','bob'):btc.call('createwallet',name,False,False,phrase,False,True,sensitive=True)
        claimpub,claimkey=rehearsal_bitcoin_key();refundpub,refundkey=rehearsal_bitcoin_key()
        miner=btc.call('getnewaddress',wallet='alice');btc.call('generatetoaddress',101,miner);bgenesis=btc.call('getblockhash',0);start_height=btc.call('getblockcount');refund_height=start_height+20
        def desc(c,r):return f'wsh(or_i(and_v(v:sha256({digest}),pk({c})),and_v(v:after({refund_height}),pk({r}))))'
        for wallet,policy in (('alice',desc(claimpub,refundkey)),('bob',desc(claimkey,refundpub))):
            btc.call('walletpassphrase',phrase,120,wallet=wallet,sensitive=True)
            try:descriptor(btc,wallet,policy)
            finally:btc.call('walletlock',wallet=wallet,sensitive=True)
        btc_alice=TestBitcoinActions(out/'bitcoin-alice',url=f'http://127.0.0.1:{rp}',cookie=bd/'regtest/.cookie',wallet='alice',genesis=bgenesis,wallet_phrase=phrase.encode());clients.append(btc_alice)
        bitcoin_terms={'operation':'lock','hashlock':digest,'claimant_key':claimpub,'refund_key':refundpub,'refund_height':str(refund_height),'amount_sats':'100000'}
        funding=btc_alice.action(bitcoin_terms);btc.call('generatetoaddress',2,miner)
        tx=btc.call('gettransaction',funding['txid'],wallet='alice');decoded=btc.call('getrawtransaction',funding['txid'],True,tx['blockhash'])
        vout=next(v['n'] for v in decoded['vout'] if v['scriptPubKey'].get('address')==funding['address'])
        verify_bitcoin_htlc(btc,txid=funding['txid'],vout=vout,amount_sats=100000,hashlock=digest,claimant_key=claimpub,refund_key=refundpub,refund_height=refund_height,genesis_hash=bgenesis);receipt['checks']['bitcoin_leg_verified']=True
        expiry_slot=cardano.tip()['slot']+600;value={'lovelace':str(cardano.amount),**{policy:{name:str(q) for name,q in assets.items()} for policy,assets in cardano.tokens.items()}}
        cardano_terms={'operation':'lock','hashlock':digest,'claimant':cardano.actors['alice']['hash'],'refundee':cardano.actors['bob']['hash'],
            'expiry_ms':str(cardano.start_ms+expiry_slot*cardano.slot_ms),'expected_value':value,'inputs':[cardano.fee_input('bob'),cardano.token_input]}
        clock=bob.action(cardano_terms);outputs=wait_for(lambda:{k:v for k,v in cardano.utxos(cardano.address).items() if k.startswith(clock['txid']+'#')},'Cardano funding inclusion')
        outref=next(k for k,v in outputs.items() if v['value'].get('lovelace')==cardano.amount and cardano.has_tokens(v));seen=cardano.tip()['block'];wait_for(lambda:cardano.tip()['block']>=seen+2,'Cardano fixture depth')
        verify_cardano_htlc(cardano,outref=outref,hashlock=digest,claimant=cardano_terms['claimant'],refundee=cardano_terms['refundee'],expiry_ms=int(cardano_terms['expiry_ms']),expected_value=value_terms(value),genesis_sha256=cgenesis);receipt['checks']['cardano_leg_verified']=True
        before=cardano.tip();checkpoint={'slot':before['slot'],'id':before['hash']};ogport=port()
        ogmios=subprocess.Popen([a.ogmios,'--node-socket',cardano.socket,'--node-config',cardano.net/'configuration.yaml','--host','127.0.0.1','--port',str(ogport),'--include-transaction-cbor','--log-level','Error'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        def ready():
            if ogmios.poll() is not None:raise RuntimeError('local Ogmios exited')
            try:return urllib.request.urlopen('http://127.0.0.1:'+str(ogport)+'/health',timeout=1).status==200
            except OSError:return False
        wait_for(ready,'local Ogmios',seconds=30)
        cclaim={k:v for k,v in cardano_terms.items() if k!='inputs'};cclaim.update(operation='claim',outref=outref,fee_input=cardano.fee_input('alice'),collateral=cardano.actors['alice']['collateral'])
        claim=alice.action(cclaim,secret=secret);wait_for(lambda:outref not in cardano.utxos(cardano.address),'Cardano claim inclusion')
        seen=cardano.tip()['block'];wait_for(lambda:cardano.tip()['block']>=seen+2,'Cardano claim depth');receipt['checks']['cardano_claim_confirmed']=True
        observed,snapshot=observe_local_preimage(url='ws://127.0.0.1:'+str(ogport),ogmios_pid=ogmios.pid,node_pid=cardano.proc.pid,node_socket=cardano.socket,network_dir=cardano.net,genesis_hash=cgenesis,checkpoint=checkpoint,outref=outref,hashlock=digest,confirmations=2,timeout=60)
        observed_phrase=b'local disposable observed backup passphrase'
        try:require(hashlib.sha256(observed).hexdigest()==digest,'Cardano observer mismatch');observed_backup=save_recovered_backup(out,observed,observed_phrase,label='Observed Cardano claim')
        finally:observed[:]=b'\0'*len(observed)
        receipt['checks']['cardano_secret_observed_from_chain']=True
        btc_bob=TestBitcoinActions(out/'bitcoin-bob',url=f'http://127.0.0.1:{rp}',cookie=bd/'regtest/.cookie',wallet='bob',genesis=bgenesis,wallet_phrase=phrase.encode(),backup=observed_backup,backup_phrase=observed_phrase);clients.append(btc_bob)
        destination=btc.call('getnewaddress',wallet='bob');bclaim={**bitcoin_terms,'operation':'claim','txid':funding['txid'],'vout':str(vout),'destination':destination}
        claimed=btc_bob.action(bclaim,secret=secret);btc.call('generatetoaddress',2,miner)
        require(btc.call('gettransaction',claimed['txid'],wallet='bob')['confirmations']>=2,'Bitcoin claim not confirmed')
        public,_=observe_bitcoin_preimage(btc,genesis=bgenesis,txid=funding['txid'],vout=vout,hashlock=digest,start_height=start_height,confirmations=2,timeout=30)
        try:require(hashlib.sha256(public).hexdigest()==digest,'Bitcoin observed preimage mismatch')
        finally:public[:]=b'\0'*len(public)
        require(btc.call('getconnectioncount')==0,'Bitcoin acquired a peer');cardano.isolated()
        receipt.update(status='passed',checks={**receipt['checks'],'bitcoin_claim_confirmed':True,'bitcoin_secret_observed_from_chain':True,'zero_peers':True},cardano_observation=snapshot)
    finally:
        secret[:]=b'\0'*len(secret)
        for client in clients:client.close()
        stop(ogmios);stop(bitcoin)
        if cardano:cardano.close()
        (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(out/'summary.json')}),flush=True)

if __name__=='__main__':main()
