"""The hosted page's Bitcoin PSBT transactions against bitcoind consensus rules, signed by an independent signer.

Starts a private bitcoind regtest node. Run from scripts/ with:
PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_bitcoin_browser
"""
import unittest

try:
    from swap_engine.tools import find_tool
    from swap_engine import bitcoin_browser_harness as harness
except ImportError:  # pragma: no cover
    from tools import find_tool
    import bitcoin_browser_harness as harness


@unittest.skipUnless(find_tool('bitcoind') and harness.node_binary(), 'bitcoind and node are required')
class BitcoinBrowserConsensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = harness.BitcoinHarness()
        cls.alice, cls.bob = cls.h.wallet('alice'), cls.h.wallet('bob')

    @classmethod
    def tearDownClass(cls):
        cls.h.close()

    def spend(self, op, terms, escrow, signer, preimage=None, destination=None, flag=b'\x01'):
        destination = destination or (self.bob if op == 'claim' else self.alice)['address']
        built = self.h.page('build', op, terms, destination, escrow=escrow)
        signed = self.h.sign_spend(built['psbt'], signer['key'], flag)
        return self.h.page('finalize', op, terms, destination, escrow=escrow, signedPsbt=signed, preimage=preimage), built

    def test_fund_then_claim_is_accepted_by_bitcoind_and_reveals_the_preimage(self):
        terms, preimage = self.h.terms(self.bob, self.alice)
        escrow = self.h.fund('alice', terms)
        done, built = self.spend('claim', terms, escrow, self.bob, preimage)
        self.assertEqual(done['txid'], built['txid'])
        txid = self.h.accept(done['txHex'])
        raw = self.h.profile._call('getrawtransaction', txid, True)
        self.assertEqual(raw['vin'][0]['txinwitness'][1], preimage)
        self.assertEqual(raw['vin'][0]['txinwitness'][2], '01')
        self.assertEqual(round(raw['vout'][0]['value'] * 100_000_000), 60_000 - int(built['fee']))

    def test_qualification_signer_signs_fund_and_claim_that_bitcoind_accepts_and_refuses_foreign_keys(self):
        import json, os, stat, tempfile
        from pathlib import Path
        import qualification_signer as qs
        terms, preimage = self.h.terms(self.bob, self.alice)

        def key_file(person):
            handle = tempfile.NamedTemporaryFile('w', delete=False)
            handle.write(person['key'].secret.hex() + '\n'); handle.close(); os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
            return Path(handle.name)
        files = {'alice': key_file(self.alice), 'bob': key_file(self.bob)}
        try:
            built = self.h.page('build', 'fund', terms, self.alice['address'], inputs=self.h.coins('alice'), feeRate=2)
            with self.assertRaises(ValueError):
                qs.btc_sign(files['bob'], {'psbt': built['psbt']})  # Bob holds none of the funding inputs
            signed = qs.btc_sign(files['alice'], {'psbt': built['psbt']})['psbt']
            done = self.h.page('finalize', 'fund', terms, self.alice['address'], inputs=self.h.coins('alice'), feeRate=2, signedPsbt=signed)
            txid = self.h.accept(done['txHex'])
            raw = self.h.profile._call('getrawtransaction', txid, True)
            vout = next(i for i, o in enumerate(raw['vout']) if o['scriptPubKey']['hex'].startswith('0020'))
            escrow = {'txid': txid, 'vout': vout, 'amount': str(terms['amount_sats'])}
            built = self.h.page('build', 'claim', terms, self.bob['address'], escrow=escrow)
            with self.assertRaises(ValueError):
                self._foreign(qs, files, built)
            signed = qs.btc_sign(files['bob'], {'psbt': built['psbt']})['psbt']
            done = self.h.page('finalize', 'claim', terms, self.bob['address'], escrow=escrow, signedPsbt=signed, preimage=preimage)
            claimed = self.h.accept(done['txHex'])
            self.assertEqual(self.h.profile._call('getrawtransaction', claimed, True)['vin'][0]['txinwitness'][1], preimage)
        finally:
            for path in files.values():
                path.unlink(missing_ok=True)

    @staticmethod
    def _foreign(qs, files, built):
        # A key that is neither the claimant nor the refunder must not sign an HTLC spend.
        import os, stat, tempfile
        from pathlib import Path
        handle = tempfile.NamedTemporaryFile('w', delete=False)
        handle.write('07' * 32 + '\n'); handle.close(); os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
        try:
            return qs.btc_sign(Path(handle.name), {'psbt': built['psbt']})
        finally:
            Path(handle.name).unlink(missing_ok=True)

    def test_claim_transaction_equals_the_one_the_existing_driver_builds(self):
        import public_bitcoin_transactions as driver
        from embit import script, transaction, ec
        terms, preimage = self.h.terms(self.bob, self.alice)
        escrow = self.h.fund('alice', terms)
        done, built = self.spend('claim', terms, escrow, self.bob, preimage)
        witness_script, _ = driver.contract(terms['hashlock'], terms['claimant_key'], terms['refund_key'], terms['refund_height'])
        destination = script.p2wpkh(self.bob['key'].get_public_key())
        reference = driver.spend(escrow['txid'], escrow['vout'], 60_000, self.bob['key'], witness_script, destination, int(built['fee']),
                                 hashlock=terms['hashlock'], claimant=terms['claimant_key'], refund=terms['refund_key'],
                                 contract_refund_height=terms['refund_height'], preimage=bytes.fromhex(preimage))
        self.assertEqual(done['txHex'], reference.serialize().hex(), 'page and driver produce byte-identical claim transactions')

    def test_refund_only_after_the_height_and_by_the_refund_key(self):
        terms, _ = self.h.terms(self.bob, self.alice, blocks=8)
        escrow = self.h.fund('alice', terms)
        done, _ = self.spend('refund', terms, escrow, self.alice)
        self.assertIn('non-final', self.h.reject_reason(done['txHex']) or '', 'bitcoind refuses the refund before the height')
        while self.h.tip() < terms['refund_height']:
            self.h.profile.mine(1)
        txid = self.h.accept(done['txHex'])
        raw = self.h.profile._call('getrawtransaction', txid, True)
        self.assertEqual(raw['locktime'], terms['refund_height'])
        self.assertEqual(len(raw['vin'][0]['txinwitness']), 3)

    def test_claim_refund_roles_and_signatures_are_enforced_before_bitcoind_sees_anything(self):
        terms, preimage = self.h.terms(self.bob, self.alice)
        escrow = self.h.fund('alice', terms)
        with self.assertRaises(harness.PageRefused) as wrong_key:
            self.spend('claim', terms, escrow, self.alice, preimage)
        self.assertIn('single signature', str(wrong_key.exception))
        with self.assertRaises(harness.PageRefused) as wrong_preimage:
            self.spend('claim', terms, escrow, self.bob, '00' * 32)
        self.assertIn('hashlock', str(wrong_preimage.exception))
        with self.assertRaises(harness.PageRefused) as hash_type:
            self.spend('claim', terms, escrow, self.bob, preimage, flag=b'\x02')
        self.assertIn('SIGHASH_ALL', str(hash_type.exception))

    def test_a_signer_that_cheats_on_the_amount_produces_a_signature_the_page_refuses(self):
        terms, preimage = self.h.terms(self.bob, self.alice)
        escrow = self.h.fund('alice', terms)
        built = self.h.page('build', 'claim', terms, self.bob['address'], escrow=escrow)
        import base64
        from embit.psbt import PSBT
        psbt = PSBT.parse(base64.b64decode(built['psbt']))
        item = psbt.inputs[0]
        digest = psbt.tx.sighash_segwit(0, item.witness_script, item.witness_utxo.value + 1)
        item.partial_sigs[self.bob['key'].get_public_key()] = self.bob['key'].sign(digest).serialize() + b'\x01'
        with self.assertRaises(harness.PageRefused) as caught:
            self.h.page('finalize', 'claim', terms, self.bob['address'], escrow=escrow, signedPsbt=base64.b64encode(psbt.serialize()).decode(), preimage=preimage)
        self.assertIn('does not verify', str(caught.exception))

    def test_a_signed_fund_psbt_whose_outputs_were_changed_is_refused(self):
        import base64
        from embit.psbt import PSBT
        from embit import transaction
        terms, _ = self.h.terms(self.bob, self.alice)
        w = self.h.wallet('alice')
        built = self.h.page('build', 'fund', terms, w['address'], inputs=self.h.coins('alice'))
        psbt = PSBT.parse(base64.b64decode(built['psbt']))
        psbt.outputs[0].value -= 1000
        psbt.outputs.append(transaction.TransactionOutput(1000, psbt.outputs[1].script_pubkey))
        psbt.outputs[-1] = type(psbt.outputs[0])(vout=psbt.outputs[-1])
        tampered = base64.b64encode(psbt.serialize()).decode()
        signed = self.h.sign_fund(tampered, w['key'])
        self.assertEqual(len(PSBT.parse(base64.b64decode(tampered)).tx.vout), 3, 'the tampering is really in the PSBT')
        with self.assertRaises(harness.PageRefused):
            self.h.page('finalize', 'fund', terms, w['address'], inputs=self.h.coins('alice'), signedPsbt=signed)


if __name__ == '__main__':
    unittest.main()
