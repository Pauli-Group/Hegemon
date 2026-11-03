"""Consensus-check offline-signed testnet-style scripts on peerless regtest."""
import hashlib
import tempfile
import time
import unittest
import subprocess
from pathlib import Path
from embit import ec,networks,script
from development_atomic_swap_rehearsal import BitcoinRPC
from local_private_spend_swap import port,stop
from public_bitcoin_transactions import contract,funding,spend,split


class PublicBitcoinTransactionsTest(unittest.TestCase):
    def test_signed_funding_claim_and_refund_against_core(self):
        with tempfile.TemporaryDirectory(prefix='btc-offline-sign-') as directory:
            rpcport=port();node=subprocess.Popen(['/workspace/bitcoin-32.1/bin/bitcoind','-regtest',f'-datadir={directory}','-listen=0','-connect=0','-dnsseed=0',f'-rpcport={rpcport}','-fallbackfee=0.0002'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            try:
                rpc=BitcoinRPC(f'http://127.0.0.1:{rpcport}',Path(directory)/'regtest/.cookie')
                deadline=time.monotonic()+30
                while True:
                    try:rpc.call('getblockchaininfo');break
                    except (FileNotFoundError,OSError,RuntimeError):
                        if node.poll() is not None or time.monotonic()>deadline:raise
                        time.sleep(.1)
                rpc.call('createwallet','fixtures')
                miner=rpc.call('getnewaddress',wallet='fixtures');rpc.call('generatetoaddress',101,miner)
                alice=ec.PrivateKey(b'\x11'*32);bob=ec.PrivateKey(b'\x22'*32)
                addr=script.p2wpkh(bob.get_public_key()).address(networks.NETWORKS['regtest'])
                deposit=rpc.call('sendtoaddress',addr,0.0012,wallet='fixtures');rpc.call('generatetoaddress',1,miner)
                info=rpc.call('gettransaction',deposit,wallet='fixtures');decoded=rpc.call('getrawtransaction',deposit,True,info['blockhash'])
                index=next(v['n'] for v in decoded['vout'] if v['scriptPubKey'].get('address')==addr)
                divided=split(deposit,index,120000,bob,[30000,30000,30000,29000],1000)
                self.assertTrue(rpc.call('testmempoolaccept',[divided.serialize().hex()])[0]['allowed'])
                self.assertEqual([v.value for v in divided.vout],[30000,30000,30000,29000])
                preimage=b'\x44'*32;digest=hashlib.sha256(preimage).hexdigest();height=rpc.call('getblockcount')+5
                claimant=alice.get_public_key().sec().hex();refund=bob.get_public_key().sec().hex();witness,output=contract(digest,claimant,refund,height)
                lock=funding(deposit,index,120000,bob,output,60000,1000)
                self.assertTrue(rpc.call('testmempoolaccept',[lock.serialize().hex()])[0]['allowed'])
                lock_id=rpc.call('sendrawtransaction',lock.serialize().hex());self.assertEqual(lock.txid().hex(),lock_id);rpc.call('generatetoaddress',1,miner)
                dest=script.p2wpkh(alice.get_public_key())
                terms={'hashlock':digest,'claimant':claimant,'refund':refund,'contract_refund_height':height}
                with self.assertRaisesRegex(ValueError,'Preimage'):spend(lock_id,0,60000,alice,witness,dest,1000,preimage=b'\x55'*32,**terms)
                with self.assertRaisesRegex(ValueError,'Signing key'):spend(lock_id,0,60000,bob,witness,dest,1000,preimage=preimage,**terms)
                early=spend(lock_id,0,60000,bob,witness,dest,1000,**terms)
                self.assertFalse(rpc.call('testmempoolaccept',[early.serialize().hex()])[0]['allowed'])
                claim=spend(lock_id,0,60000,alice,witness,dest,1000,preimage=preimage,**terms)
                self.assertTrue(rpc.call('testmempoolaccept',[claim.serialize().hex()])[0]['allowed'])
                # Use a second output for refund so the first claim remains independent.
                second=funding(lock_id,1,59000,bob,output,30000,1000)
                second_id=rpc.call('sendrawtransaction',second.serialize().hex());rpc.call('generatetoaddress',1,miner)
                rpc.call('sendrawtransaction',claim.serialize().hex());rpc.call('generatetoaddress',height-rpc.call('getblockcount')+1,miner)
                refund_tx=spend(second_id,0,30000,bob,witness,dest,1000,**terms)
                self.assertTrue(rpc.call('testmempoolaccept',[refund_tx.serialize().hex()])[0]['allowed'])
                rpc.call('sendrawtransaction',refund_tx.serialize().hex());self.assertEqual(rpc.call('getconnectioncount'),0)
            finally:stop(node)

if __name__=='__main__':unittest.main()
