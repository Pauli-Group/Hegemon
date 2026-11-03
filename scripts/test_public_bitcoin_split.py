import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from embit import transaction
from public_bitcoin_split import advance,initialize


class BitcoinSplitTest(unittest.TestCase):
    def test_waits_for_confirmation_and_journals_before_submission(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);(root/'alice').mkdir();key=root/'alice/bitcoin-testnet4.key';key.write_text('11'*32);os.chmod(key,0o600)
            initialize(root)
            def submit(work,chain,raw):
                state=json.loads((work/'state.json').read_text());tx=transaction.Transaction.parse(raw)
                self.assertEqual(state['phase'],'inflight');self.assertEqual(chain,'bitcoin-testnet4')
                self.assertEqual([o.value for o in tx.vout],[7000,7000,7000,7000,21500]);return {'txid':tx.txid().hex()}
            with patch('public_bitcoin_split.verify_network'),patch('public_bitcoin_split._fee',return_value=500),patch('public_bitcoin_split.bitcoin_utxos',side_effect=[[],[{'txid':'22'*32,'vout':0,'amount_sats':50000}]]),patch('public_bitcoin_split.submit',side_effect=submit):
                self.assertEqual(advance(root)['phase'],'created')
                self.assertEqual(advance(root)['phase'],'submitted')
                self.assertEqual(advance(root)['phase'],'submitted')


if __name__=='__main__':unittest.main()
