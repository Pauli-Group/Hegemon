import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from embit import ec
from eth_account import Account
from public_btc_eth_rehearsal import initialize,advance


def wallets(directory):
    for index,name in enumerate(('alice','bob'),1):
        root=Path(directory)/name;root.mkdir(mode=0o700)
        bitcoin=ec.PrivateKey(bytes([index])*32);(root/'bitcoin-testnet4.key').write_text(bitcoin.secret.hex());os.chmod(root/'bitcoin-testnet4.key',0o600)
        key=bytes([index+10])*32;account=Account.from_key(key);(root/'ethereum-sepolia.key').write_text(account.address+' 0x'+key.hex());os.chmod(root/'ethereum-sepolia.key',0o600)


class PublicBtcEthRehearsalTest(unittest.TestCase):
    def test_all_stages_use_observed_secret_and_persist_no_plaintext(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);wallets(d);secret_path=Path(d)/'btc-eth.secret';state_path=Path(d)/'btc-eth-state.json'
            def rpc(method,params):
                return {'eth_getBalance':hex(10**18),'eth_getBlockByNumber':{'timestamp':hex(100000),'baseFeePerGas':'0x1'},'eth_maxPriorityFeePerGas':'0x1'}[method]
            def eth_send(*args):return {'txid':('aa' if args[2] is None else 'bb')*32}
            def eth_observe(*args):return bytearray(secret_path.read_bytes()),{'confirmations':2}
            def btc_observe(*args):return bytearray(secret_path.read_bytes()),{'confirmations':2}
            with patch('public_btc_eth_rehearsal.verify_network'),patch('public_btc_eth_rehearsal.rpc',side_effect=rpc),patch('public_btc_eth_rehearsal.request',return_value=b'100'),patch('public_btc_eth_rehearsal.bitcoin_fund',return_value={'txid':'11'*32}),patch('public_btc_eth_rehearsal._bitcoin_lock',return_value=100),patch('public_btc_eth_rehearsal.ethereum_send',side_effect=eth_send),patch('public_btc_eth_rehearsal._receipt',return_value={'contractAddress':'0x'+'22'*20}),patch('public_btc_eth_rehearsal.verify_native',return_value={'confirmations':2}),patch('public_btc_eth_rehearsal.ethereum_claim',side_effect=eth_observe),patch('public_btc_eth_rehearsal.spend_contract',return_value={'txid':'33'*32}),patch('public_btc_eth_rehearsal.bitcoin_claim',side_effect=btc_observe):
                self.assertEqual(initialize(d)['phase'],'created')
                phases=[advance(d)['phase'] for _ in range(8)]
            self.assertEqual(phases,['gas_ready','btc_lock_submitted','btc_lock_confirmed','eth_lock_submitted','both_verified','eth_claim_submitted','btc_claim_submitted','complete'])
            secret=secret_path.read_bytes();self.assertEqual(hashlib.sha256(secret).hexdigest(),json.loads(state_path.read_text())['hashlock']);self.assertNotIn(secret.hex(),state_path.read_text())
    def test_lost_response_stops_before_retry(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);wallets(d)
            def rpc(method,params):return {'eth_getBalance':hex(10**18),'eth_getBlockByNumber':{'baseFeePerGas':'0x1'},'eth_maxPriorityFeePerGas':'0x1'}[method]
            with patch('public_btc_eth_rehearsal.verify_network'),patch('public_btc_eth_rehearsal.rpc',side_effect=rpc),patch('public_btc_eth_rehearsal.request',return_value=b'100'),patch('public_btc_eth_rehearsal.bitcoin_fund',side_effect=TimeoutError('lost')) as fund:
                initialize(d);self.assertEqual(advance(d)['phase'],'gas_ready')
                with self.assertRaises(TimeoutError):advance(d)
                with self.assertRaisesRegex(ValueError,'Uncertain action'):advance(d)
                self.assertEqual(fund.call_count,1)

if __name__=='__main__':unittest.main()
