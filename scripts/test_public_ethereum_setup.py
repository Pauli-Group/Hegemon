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
from public_ethereum_nft_refund import initialize as initialize_refund,advance as advance_refund
from public_sepolia_driver import send
from eth_abi import encode
from eth_utils import keccak
from public_swap_journal import prepare
from test_public_btc_eth_rehearsal import wallets
from swap_engine.tools import tool, skip_unless_tools

class PublicEthereumSetupTest(unittest.TestCase):
    @skip_unless_tools('anvil')
    def test_local_fixture_deployments_and_ownership(self):
        with tempfile.TemporaryDirectory(prefix='eth-public-fixtures-') as d:
            root=Path(d);wallets(root);addresses={name:{'ethereum_sepolia':(root/name/'ethereum-sepolia.key').read_text().split()[0]} for name in ('alice','bob')};(root/'addresses.json').write_text(json.dumps(addresses))
            n=port();node=subprocess.Popen([str(tool('anvil')),'--host','127.0.0.1','--port',str(n),'--chain-id','11155111','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
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
                patches=[patch('public_ethereum_setup.verify_network'),patch('public_sepolia_driver.verify_network'),patch('public_btc_eth_rehearsal.verify_network'),patch('public_samechain_ethereum_rehearsal.verify_network'),patch('public_ethereum_nft_refund.verify_network'),patch('public_ethereum_nft_refund._early_refund_rejected'),patch('public_ethereum_token_verify.verify_network'),patch('public_testnet_observers.verify_network'),patch('public_ethereum_setup.rpc',side_effect=rpc),patch('public_ethereum_nft_refund.rpc',side_effect=rpc),patch('public_sepolia_driver.rpc',side_effect=rpc),patch('public_btc_eth_rehearsal.rpc',side_effect=rpc),patch('public_samechain_ethereum_rehearsal.rpc',side_effect=rpc),patch('public_ethereum_token_verify.rpc',side_effect=rpc),patch('public_testnet_observers.rpc',side_effect=rpc),patch('public_sepolia_driver.submit',side_effect=broadcast)]
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
                    # Emulate the completed cross-chain NFT payout to Bob.
                    token=json.loads((root/'ethereum-setup/state.json').read_text())['contracts']['erc721']['address'];alice=addresses['alice']['ethereum_sepolia'];bob=addresses['bob']['ethereum_sepolia']
                    data=keccak(text='safeTransferFrom(address,address,uint256)')[:4]+encode(['address','address','uint256'],[alice,bob,42]);send(root,root/'alice/ethereum-sepolia.key',token,0,data)
                    (root/'eth-cardano-erc721-nft').mkdir();(root/'eth-cardano-erc721-nft/state.json').write_text('{"phase":"complete"}')
                    initialize_refund(root)
                    for _ in range(20):
                        result=advance_refund(root)
                        if result['phase']=='wait_refund':
                            state=json.loads((root/'ethereum-nft-refund/state.json').read_text());rpc('evm_setNextBlockTimestamp',[state['expiry']]);rpc('evm_mine',[])
                        if result['phase']=='complete':break
                    self.assertEqual(result['phase'],'complete')
                finally:
                    for item in reversed(patches):item.stop()
            finally:stop(node)

if __name__=='__main__':unittest.main()
