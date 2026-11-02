import json
import os
import tempfile
import unittest
from pathlib import Path
import cbor2
from embit import ec,script
from eth_account import Account
from public_bitcoin_transactions import contract,funding
from public_ethereum_transactions import sign_transaction
from public_swap_journal import prepare,transaction_id

class PublicSwapJournalTest(unittest.TestCase):
    def test_exclusive_private_signed_record(self):
        key=b'\x33'*32;sender=Account.from_key(key).address
        raw,txid=sign_transaction(key,sender,nonce=0,to='0x'+'2'*40,value=1,data=b'test data',gas=21000,max_fee=100,priority_fee=1)
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);record=prepare(d,'ethereum-sepolia',raw)
            self.assertEqual(record['txid'],txid[2:]);self.assertEqual(record['state'],'prepared_or_submitted')
            files=list(Path(d).iterdir());self.assertEqual(len(files),2)
            self.assertTrue(all(p.stat().st_mode&0o077==0 for p in files))
            metadata=json.loads(next(p for p in files if p.suffix=='.json').read_text())
            self.assertEqual(set(metadata),{'version','chain','txid','state'});self.assertNotIn(key.hex(),json.dumps(metadata))
            with self.assertRaises(FileExistsError):prepare(d,'ethereum-sepolia',raw)
            os.chmod(d,0o755)
            with self.assertRaisesRegex(ValueError,'private'):prepare(d,'ethereum-sepolia',raw)
    def test_wrong_transaction_format_is_rejected(self):
        with self.assertRaises(ValueError):transaction_id('ethereum-sepolia',b'\x01')
        with self.assertRaises(ValueError):transaction_id('bitcoin-testnet4',b'\x02')
        with self.assertRaises(ValueError):transaction_id('bitcoin-mainnet',b'\x02')
    def test_bitcoin_and_cardano_transaction_ids(self):
        alice=ec.PrivateKey(b'\x11'*32);bob=ec.PrivateKey(b'\x22'*32)
        _,output=contract('44'*32,alice.get_public_key().sec().hex(),bob.get_public_key().sec().hex(),200)
        tx=funding('55'*32,0,50000,bob,output,30000,1000)
        self.assertEqual(transaction_id('bitcoin-testnet4',tx.serialize()),tx.txid().hex())
        raw=cbor2.dumps([{0:[]},{},True,None]);import hashlib,io
        source=io.BytesIO(raw);source.seek(1);cbor2.CBORDecoder(source).decode()
        self.assertEqual(transaction_id('cardano-preview',raw),hashlib.blake2b(raw[1:source.tell()],digest_size=32).hexdigest())

if __name__=='__main__':unittest.main()
