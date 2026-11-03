import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from embit import ec
from public_bitcoin_suite import step,CASES


class BitcoinSuiteTest(unittest.TestCase):
    def test_waits_for_split_then_funds_only_one_new_case_per_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            for name,phase in CASES:
                work=root/name;work.mkdir();(work/'state.json').write_text(json.dumps({'phase':phase}))
            with patch('public_bitcoin_suite.eth_advance',return_value={'phase':'btc_claim_submitted'}),patch('public_bitcoin_suite.split_advance',return_value={'phase':'created'}),patch('public_bitcoin_suite.cardano_advance') as cardano:
                self.assertEqual(step(root)['split'],'created');cardano.assert_not_called()
            split={'phase':'submitted','txid':'12'*32};coin={'txid':split['txid'],'vout':0,'amount_sats':7000}
            with patch('public_bitcoin_suite.eth_advance',return_value={'phase':'btc_claim_submitted'}),patch('public_bitcoin_suite.split_advance',return_value=split),patch('public_bitcoin_suite.load_test_key',return_value=ec.PrivateKey(b'\x11'*32)),patch('public_bitcoin_suite.bitcoin_utxos',return_value=[coin]),patch('public_bitcoin_suite.cardano_advance') as cardano,patch('public_bitcoin_suite.erc20_advance') as erc20:
                step(root);cardano.assert_called_once_with(root);erc20.assert_not_called()
    def test_refuses_uncertain_scenario(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            for name,phase in CASES:
                work=root/name;work.mkdir();(work/'state.json').write_text(json.dumps({'phase':'btc_lock_inflight' if name=='btc-cardano' else phase}))
            with patch('public_bitcoin_suite.eth_advance',return_value={'phase':'btc_claim_submitted'}),patch('public_bitcoin_suite.split_advance',return_value={'phase':'created'}):
                with self.assertRaisesRegex(ValueError,'Uncertain'):step(root)


if __name__=='__main__':unittest.main()
