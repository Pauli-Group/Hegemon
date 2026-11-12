import hashlib
import unittest

from scripts.hegemon_swap_observer import observe_claim_request,verify_lock_action_output,observe_exact_note_spend
from scripts.hegemon_preimage_observer import IDENTITY
from scripts.probe_hegemon_testnet import RELATION


class HegemonSwapObserverTests(unittest.TestCase):
    def setUp(self):
        self.secret = bytearray(b'\x01' * 32)
        self.digest = hashlib.sha256(self.secret).hexdigest()
        self.request = {'hashlock': self.digest, 'start_height': '100'}
        self.snapshot = {'chain': 'hegemon-v0.11-pre-mainnet', 'action_id': 'ab' * 48,
                         'block_hash': '0x' + 'cd' * 32, 'block_height': 101,
                         'confirmations': 3, 'node_height': 103, 'reference_height': 103}

    def test_returns_only_a_confirmed_matching_public_preimage_and_wipes_the_buffer(self):
        def scan(rpc, **options):
            self.assertEqual(rpc, 'loopback')
            self.assertEqual(options['confirmations'], 2)
            self.assertEqual(options['start_height'], 100)
            return self.secret, self.snapshot
        result = observe_claim_request(self.request, 'loopback', scan=scan, confirmations=lambda: 2)
        self.assertEqual(result['state'], 'secret-revealed')
        self.assertEqual(result['preimage'], '01' * 32)
        self.assertEqual(self.secret, bytearray(32))

    def test_pending_and_refusals_do_not_treat_missing_or_wrong_evidence_as_a_claim(self):
        self.assertEqual(observe_claim_request(self.request, 'loopback', scan=lambda *a, **k: None,
                                              confirmations=lambda: 2), {'state': 'pending'})
        for change in ({'confirmations': 1}, {'node_height': 102}, {'block_hash': '00' * 32},
                       {'action_id': 'ab' * 32}, {'block_height': 99}):
            secret = bytearray(b'\x01' * 32)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'Invalid Hegemon claim'):
                observe_claim_request(self.request, 'loopback', scan=lambda *a, **k: (secret, {**self.snapshot, **change}),
                                      confirmations=lambda: 2)
            self.assertEqual(secret, bytearray(32))
        with self.assertRaisesRegex(ValueError, 'observation request'):
            observe_claim_request({**self.request, 'start_height': '-1'}, 'loopback')

    def test_wrong_secret_is_rejected_and_wiped(self):
        secret = bytearray(b'\x02' * 32)
        with self.assertRaisesRegex(ValueError, 'Invalid Hegemon claim'):
            observe_claim_request(self.request, 'loopback', scan=lambda *a, **k: (secret, self.snapshot),
                                  confirmations=lambda: 2)
        self.assertEqual(secret, bytearray(32))

    def test_lock_action_binds_the_private_note_commitment_to_the_canonical_action(self):
        action_id='ab'*48;chain_id='0x'+'cd'*32;block_hash='0x'+'ef'*32
        action=bytearray.fromhex(action_id)+bytearray(8)
        for i,n in enumerate((12,7,1,15)):action[48+i*2:50+i*2]=n.to_bytes(2,'little')
        carrier=bytearray(5788);carrier[:8]=b'HGPSLC02';carrier[8:24]=IDENTITY
        carrier[24:72]=bytes.fromhex(RELATION[:96]);carrier[72:104]=bytes.fromhex(chain_id[2:]);carrier[5784:]=b'SMZL'
        commitment=b''.join(n.to_bytes(8,'little') for n in range(1,8));carrier[320:376]=commitment
        kwargs={'url':'loopback','block_height':101,'block_hash':block_hash,'action_id':action_id,'commitment':commitment.hex(),'chain_id':chain_id,
                'read':lambda *_:block_hash,'body':lambda *_:([action],{'height':101},b''),'parse':lambda _: (carrier,{'vector_counts':[0,0,2,2]})}
        self.assertTrue(verify_lock_action_output(**kwargs))
        for change in ({'commitment':'11'*56},{'action_id':'00'*48},{'chain_id':'0x'+'00'*32},
                       {'read':lambda *_:'0x'+'00'*32},{'body':lambda *_:([action],{'height':102},b'')}):
            with self.subTest(change=change),self.assertRaises(ValueError):verify_lock_action_output(**{**kwargs,**change})
        changed=bytearray(carrier);changed[320:328]=(0xffffffff00000001).to_bytes(8,'little')
        with self.assertRaisesRegex(ValueError,'commitment'):
            verify_lock_action_output(**{**kwargs,'parse':lambda _: (changed,{'vector_counts':[0,0,2,2]})})

    def test_spend_classification_requires_the_exact_private_nullifier_in_the_canonical_action(self):
        action_id='ab'*48;chain_id='0x'+'cd'*32;block_hash='0x'+'ef'*32
        action=bytearray.fromhex(action_id)+bytearray(8)
        for i,n in enumerate((12,7,1,15)):action[48+i*2:50+i*2]=n.to_bytes(2,'little')
        carrier=bytearray(5788);carrier[:8]=b'HGPSLC02';carrier[8:24]=IDENTITY
        carrier[24:72]=bytes.fromhex(RELATION[:96]);carrier[72:104]=bytes.fromhex(chain_id[2:]);carrier[5784:]=b'SMZL'
        nullifier=b''.join(n.to_bytes(8,'little') for n in range(1,8));carrier[208:264]=nullifier
        kwargs={'url':'loopback','block_height':101,'block_hash':block_hash,'nullifier':nullifier.hex(),'chain_id':chain_id,'hashlock':self.digest,
                'read':lambda *_:block_hash,'body':lambda *_:([action],{'height':101},b''),'parse':lambda _: (carrier,{'vector_counts':[0,0,2,2]})}
        self.assertEqual(observe_exact_note_spend(**kwargs),{'state':'refunded','action_id':action_id})
        carrier[528:536]=(1).to_bytes(8,'little');carrier[536:568]=bytes(self.secret)
        self.assertEqual(observe_exact_note_spend(**kwargs),{'state':'claimed','action_id':action_id,'preimage':'01'*32})
        for change in ({'nullifier':'11'*56},{'chain_id':'0x'+'00'*32},{'hashlock':'22'*32},{'read':lambda *_:'0x'+'00'*32}):
            with self.subTest(change=change),self.assertRaises(ValueError):observe_exact_note_spend(**{**kwargs,**change})
