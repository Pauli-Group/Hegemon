"""Exercise the staged public driver using peerless local fixture chains."""
import json
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch
from embit import ec,networks,script
from development_atomic_swap_rehearsal import BitcoinRPC
from local_private_spend_swap import port,stop
from public_btc_eth_rehearsal import initialize,advance
from public_bitcoin_refund_rehearsal import initialize as initialize_refund,advance as advance_refund
from public_swap_journal import prepare
from public_testnet_probe import BITCOIN
from test_public_btc_eth_rehearsal import wallets
from swap_engine.tools import tool, skip_unless_tools


class PublicBtcEthIntegrationTest(unittest.TestCase):
    @skip_unless_tools('bitcoind', 'anvil')
    def test_full_staged_rehearsal_on_local_nodes(self):
        with tempfile.TemporaryDirectory(prefix='btc-eth-stages-') as d:
            root=Path(d);wallets(d);bd=root/'bitcoin';bd.mkdir();bp=port();ep=port()
            btc_node=subprocess.Popen([str(tool('bitcoind')),'-regtest',f'-datadir={bd}','-listen=0','-connect=0','-dnsseed=0','-txindex=1',f'-rpcport={bp}','-fallbackfee=0.0002'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            eth_node=subprocess.Popen([str(tool('anvil')),'--host','127.0.0.1','--port',str(ep),'--chain-id','11155111','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            btc=BitcoinRPC(f'http://127.0.0.1:{bp}',bd/'regtest/.cookie')
            def eth(method,params):
                req=urllib.request.Request(f'http://127.0.0.1:{ep}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=10) as response:out=json.load(response)
                if 'error' in out:raise RuntimeError(str(out['error']))
                return out['result']
            try:
                deadline=time.monotonic()+30
                while True:
                    try:btc.call('getblockchaininfo');eth('eth_chainId',[]);break
                    except (OSError,RuntimeError):
                        if btc_node.poll() is not None or eth_node.poll() is not None or time.monotonic()>deadline:raise
                        time.sleep(.1)
                btc.call('createwallet','fixtures');miner=btc.call('getnewaddress',wallet='fixtures');btc.call('generatetoaddress',101,miner)
                alice_btc=ec.PrivateKey(bytes.fromhex((root/'alice/bitcoin-testnet4.key').read_text()));address=script.p2wpkh(alice_btc.get_public_key()).address(networks.NETWORKS['regtest'])
                deposit=btc.call('sendtoaddress',address,0.0001,wallet='fixtures');btc.call('generatetoaddress',2,miner)
                initial=btc.call('gettransaction',deposit,wallet='fixtures');decoded=btc.call('getrawtransaction',deposit,True,initial['blockhash']);index=next(v['n'] for v in decoded['vout'] if v['scriptPubKey'].get('address')==address)
                alice_eth=(root/'alice/ethereum-sepolia.key').read_text().split()[0];eth('anvil_setBalance',[alice_eth,hex(10**18)])
                def read(url,body=None):
                    endpoint=url.removeprefix(BITCOIN)
                    if endpoint=='/blocks/tip/height':return str(btc.call('getblockcount')).encode()
                    if endpoint=='/fee-estimates':return b'{"6":1}'
                    if endpoint.startswith('/block-height/'):return btc.call('getblockhash',int(endpoint.rsplit('/',1)[1])).encode()
                    if endpoint.startswith('/tx/'):
                        parts=endpoint.split('/');txid=parts[2]
                        if len(parts)>3:return json.dumps({'spent':btc.call('gettxout',txid,int(parts[-1])) is None}).encode()
                        raw=btc.call('getrawtransaction',txid,True);block=raw.get('blockhash');status={'confirmed':bool(block)}
                        if block:status.update(block_hash=block,block_height=btc.call('getblockheader',block)['height'])
                        return json.dumps({'txid':txid,'status':status,'vout':[{'value':round(v['value']*100_000_000),'scriptpubkey':v['scriptPubKey']['hex']} for v in raw['vout']],'vin':[{'txid':i.get('txid'),'vout':i.get('vout'),'witness':i.get('txinwitness',[])} for i in raw['vin']]}).encode()
                    raise AssertionError(endpoint)
                def broadcast(directory,chain,raw):
                    record=prepare(directory,chain,raw)
                    if chain=='bitcoin-testnet4':
                        ident=btc.call('sendrawtransaction',raw.hex());btc.call('generatetoaddress',2,miner)
                    else:
                        ident=eth('eth_sendRawTransaction',['0x'+raw.hex()])[2:]
                        deadline=time.monotonic()+10
                        while eth('eth_getTransactionReceipt',['0x'+ident]) is None:
                            if time.monotonic()>deadline:raise RuntimeError('Local Ethereum transaction was not mined')
                            time.sleep(.05)
                        eth('evm_mine',[])
                    self.assertEqual(ident,record['txid']);return {'txid':ident,'confirmed':False}
                patches=[patch(name) for name in ('public_btc_eth_rehearsal.verify_network','public_bitcoin_refund_rehearsal.verify_network','public_bitcoin_driver.verify_network','public_sepolia_driver.verify_network','public_ethereum_verify.verify_network','public_testnet_observers.verify_network')]
                patches += [patch(name,side_effect=read) for name in ('public_btc_eth_rehearsal.request','public_bitcoin_refund_rehearsal.request','public_bitcoin_driver.request','public_testnet_observers.request')]
                patches += [patch(name,side_effect=eth) for name in ('public_btc_eth_rehearsal.rpc','public_sepolia_driver.rpc','public_ethereum_verify.rpc','public_testnet_observers.rpc')]
                patches += [patch('public_bitcoin_driver.bitcoin_utxos',return_value=[{'txid':deposit,'vout':index,'amount_sats':10000}]),patch('public_bitcoin_driver.submit',side_effect=broadcast),patch('public_sepolia_driver.submit',side_effect=broadcast)]
                for item in patches:item.start()
                try:
                    initialize(root);phases=[]
                    for _ in range(12):
                        state=advance(root);phases.append(state['phase'])
                        if state['phase']=='complete':break
                    self.assertEqual(phases[-1],'complete');self.assertIn('both_verified',phases);self.assertEqual(btc.call('getconnectioncount'),0)
                    # The BTC lock's change is a fresh confirmed Alice output.
                    first=json.loads((root/'btc-eth-state.json').read_text());lock=btc.call('getrawtransaction',first['btc_lock'],True)
                    change=round(lock['vout'][1]['value']*100_000_000)
                    with patch('public_bitcoin_driver.bitcoin_utxos',return_value=[{'txid':first['btc_lock'],'vout':1,'amount_sats':change}]):
                        initialize_refund(root);self.assertEqual(advance_refund(root)['phase'],'lock_submitted');self.assertEqual(advance_refund(root)['phase'],'wait_refund')
                        self.assertEqual(advance_refund(root)['phase'],'wait_refund')
                        refund_state=json.loads((root/'bitcoin-refund/state.json').read_text());self.assertTrue(refund_state['early_refund_rejected'])
                        btc.call('generatetoaddress',refund_state['btc_refund_height']-btc.call('getblockcount'),miner)
                        self.assertEqual(advance_refund(root)['phase'],'refund_submitted');self.assertEqual(advance_refund(root)['phase'],'complete')
                finally:
                    for item in reversed(patches):item.stop()
            finally:stop(eth_node);stop(btc_node)

if __name__=='__main__':unittest.main()
