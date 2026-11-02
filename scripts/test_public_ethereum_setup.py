import json
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch
from local_private_spend_swap import port,stop
from public_ethereum_setup import initialize,advance
from public_samechain_ethereum_rehearsal import initialize as initialize_swap,advance as advance_swap
from public_swap_journal import prepare
from test_public_btc_eth_rehearsal import wallets

class PublicEthereumSetupTest(unittest.TestCase):
    def test_local_fixture_deployments_and_ownership(self):
        with tempfile.TemporaryDirectory(prefix='eth-public-fixtures-') as d:
            root=Path(d);wallets(root);addresses={name:{'ethereum_sepolia':(root/name/'ethereum-sepolia.key').read_text().split()[0]} for name in ('alice','bob')};(root/'addresses.json').write_text(json.dumps(addresses))
            n=port();node=subprocess.Popen(['/workspace/chain-tools/foundry/anvil','--host','127.0.0.1','--port',str(n),'--chain-id','11155111','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            def rpc(method,params):
                req=urllib.request.Request(f'http://127.0.0.1:{n}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=5) as response:out=json.load(response)
                if 'error' in out:raise RuntimeError(str(out['error']))
                return out['result']
            try:
                deadline=time.monotonic()+20
                while True:
                    try:rpc('eth_chainId',[]);break
                    except OSError:
                        if node.poll() is not None or time.monotonic()>deadline:raise
                        time.sleep(.1)
                rpc('anvil_setBalance',[addresses['alice']['ethereum_sepolia'],hex(10**18)])
                def broadcast(directory,chain,raw):
                    record=prepare(directory,chain,raw);ident=rpc('eth_sendRawTransaction',['0x'+raw.hex()])[2:];deadline=time.monotonic()+10
                    while rpc('eth_getTransactionReceipt',['0x'+ident]) is None:
                        if time.monotonic()>deadline:raise RuntimeError('Local transaction not mined')
                        time.sleep(.05)
                    rpc('evm_mine',[]);self.assertEqual(record['txid'],ident);return {'txid':ident,'confirmed':False}
                patches=[patch('public_ethereum_setup.verify_network'),patch('public_sepolia_driver.verify_network'),patch('public_btc_eth_rehearsal.verify_network'),patch('public_samechain_ethereum_rehearsal.verify_network'),patch('public_ethereum_token_verify.verify_network'),patch('public_testnet_observers.verify_network'),patch('public_ethereum_setup.rpc',side_effect=rpc),patch('public_sepolia_driver.rpc',side_effect=rpc),patch('public_btc_eth_rehearsal.rpc',side_effect=rpc),patch('public_samechain_ethereum_rehearsal.rpc',side_effect=rpc),patch('public_ethereum_token_verify.rpc',side_effect=rpc),patch('public_testnet_observers.rpc',side_effect=rpc),patch('public_sepolia_driver.submit',side_effect=broadcast)]
                for item in patches:item.start()
                try:
                    initialize(root)
                    for _ in range(12):
                        result=advance(root)
                        if result['phase']=='complete':break
                    self.assertEqual(result['phase'],'complete');self.assertEqual(set(result['contracts']),{'erc20','erc721','erc1155'})
                    for case in ('erc20-erc721','erc1155-erc20'):
                        initialize_swap(root,case)
                        for _ in range(30):
                            result=advance_swap(root,case)
                            if result['phase']=='complete':break
                        self.assertEqual(result['phase'],'complete')
                finally:
                    for item in reversed(patches):item.stop()
            finally:stop(node)

if __name__=='__main__':unittest.main()
