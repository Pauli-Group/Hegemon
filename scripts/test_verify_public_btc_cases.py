"""Offline tests for the public Bitcoin case verifier.

Builds real funding, claim and refund transactions with embit, serves them through a fake
provider, and mutates one fact at a time. Every mutation must make the verifier fail, so a
verifier that only checked the shape of a case would be caught here.
"""
import copy
import hashlib
import unittest

from embit import ec, script, transaction

import public_bitcoin_transactions as btc
import verify_public_btc_cases as v

CLAIM_KEY = ec.PrivateKey(bytes.fromhex('11' * 32))
REFUND_KEY = ec.PrivateKey(bytes.fromhex('22' * 32))
FUNDER_KEY = ec.PrivateKey(bytes.fromhex('33' * 32))
PREIMAGE = bytes(range(32))
HASHLOCK = hashlib.sha256(PREIMAGE).hexdigest()
CLAIMANT = CLAIM_KEY.get_public_key().sec().hex()
REFUND = REFUND_KEY.get_public_key().sec().hex()
HEIGHT = 158927
AMOUNT = 1500


class FakeChain:
    def __init__(self, kind):
        self.witness_script, self.output = btc.contract(HASHLOCK, CLAIMANT, REFUND, HEIGHT)
        self.fund = btc.funding('aa' * 32, 0, 7000, FUNDER_KEY, self.output, AMOUNT, 250)
        fund_id = self.fund.txid().hex()
        if kind == 'claim':
            self.spend = btc.spend(fund_id, 0, AMOUNT, CLAIM_KEY, self.witness_script, script.p2wpkh(CLAIM_KEY.get_public_key()), 250,
                                   hashlock=HASHLOCK, claimant=CLAIMANT, refund=REFUND, contract_refund_height=HEIGHT, preimage=PREIMAGE)
        else:
            self.spend = btc.spend(fund_id, 0, AMOUNT, REFUND_KEY, self.witness_script, script.p2wpkh(REFUND_KEY.get_public_key()), 250,
                                   hashlock=HASHLOCK, claimant=CLAIMANT, refund=REFUND, contract_refund_height=HEIGHT)
        self.height = {fund_id: 158786, self.spend.txid().hex(): 158797 if kind == 'claim' else 158930}

    def install(self, fund=None, spend=None, confirmed=True):
        fund, spend = fund or self.fund, spend or self.spend
        txs = {self.fund.txid().hex(): fund, self.spend.txid().hex(): spend}

        def fake_raw(base, txid):
            tx = txs[txid]
            return tx, tx.serialize()

        def fake_status(base, txid):
            return {'confirmed': confirmed, 'block_height': self.height[txid], 'block_hash': 'h%d' % self.height[txid], 'block_time': 1793700000}

        v.btc_raw, v.btc_status = fake_raw, fake_status
        v._get = lambda url, *a, **k: b'159471'


def state(**changes):
    base = {
        'btc_lock': None, 'btc_amount_sats': AMOUNT, 'btc_refund_height': HEIGHT, 'hashlock': HASHLOCK,
        'terms': {'btc_claimant': CLAIMANT, 'btc_refund': REFUND}, 'phase': 'complete',
    }
    for key, value in changes.items():
        if key == 'terms':
            base['terms'] = {**base['terms'], **value}
        else:
            base[key] = value
    return base


def run(chain, kind, mutate_state=None, fund=None, spend=None):
    chain.install(fund=fund, spend=spend)
    st = state(**(mutate_state or {}))
    st['btc_lock'] = chain.fund.txid().hex()
    check = v.Check('t')
    facts = v.check_bitcoin_leg(check, st, chain.spend.txid().hex(), kind, ['fake'])
    return check, facts


def failed(check):
    return [i['check'] for i in check.items if not i['ok']]


def reparse(tx):
    return transaction.Transaction.parse(tx.serialize())


class VerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = (v.btc_raw, v.btc_status, v._get)

    @classmethod
    def tearDownClass(cls):
        v.btc_raw, v.btc_status, v._get = cls.saved

    def test_a_genuine_claim_and_refund_pass_every_check(self):
        for kind in ('claim', 'refund'):
            check, facts = run(FakeChain(kind), kind)
            self.assertEqual(failed(check), [], kind)
            self.assertEqual(facts['payout_sats'], AMOUNT - 250)

    def test_script_parser_round_trips_and_rejects_every_single_byte_change(self):
        witness_script, _ = btc.contract(HASHLOCK, CLAIMANT, REFUND, HEIGHT)
        parsed = v.parse_htlc_script(witness_script.data)
        self.assertEqual(parsed, {'hashlock': HASHLOCK, 'claimant': CLAIMANT, 'refund': REFUND, 'height': HEIGHT})
        original = witness_script.data
        for index in range(len(original)):
            changed = bytearray(original)
            changed[index] ^= 1
            try:
                again = v.parse_htlc_script(bytes(changed))
            except ValueError:
                continue
            self.assertNotEqual(again, parsed, f'byte {index} changed without changing the parsed terms')
        with self.assertRaises(ValueError):
            v.parse_htlc_script(original + b'\x00')

    def test_each_wrong_recorded_term_is_caught(self):
        other_key = ec.PrivateKey(bytes.fromhex('44' * 32)).get_public_key().sec().hex()
        cases = {
            'hashlock': {'hashlock': hashlib.sha256(b'other').hexdigest()},
            'claim key': {'terms': {'btc_claimant': other_key}},
            'refund key': {'terms': {'btc_refund': other_key}},
            'refund height': {'btc_refund_height': HEIGHT + 1},
            'amount': {'btc_amount_sats': AMOUNT + 1},
        }
        for name, change in cases.items():
            check, _ = run(FakeChain('claim'), 'claim', change)
            self.assertTrue(failed(check), f'{name} was not caught')

    def test_wrong_preimage_in_the_witness_is_caught_even_with_a_valid_signature(self):
        chain = FakeChain('claim')
        bad = reparse(chain.spend)
        items = [bytes(i) for i in bad.vin[0].witness.items]
        items[1] = bytes(32)
        bad.vin[0].witness = transaction.Witness(items)
        check, _ = run(chain, 'claim', spend=bad)
        self.assertIn('SHA-256 of the witness preimage equals the hashlock', failed(check))

    def test_payout_to_a_different_script_is_caught(self):
        chain = FakeChain('claim')
        bad = reparse(chain.spend)
        bad.vout[0] = transaction.TransactionOutput(bad.vout[0].value, script.p2wpkh(FUNDER_KEY.get_public_key()))
        bad.vin[0].txid = bytes.fromhex(chain.fund.txid().hex())
        check, _ = run(chain, 'claim', spend=bad)
        self.assertTrue(any('pays only the key owner' in item or 'txid' in item for item in failed(check)))

    def test_signature_by_the_wrong_key_is_caught(self):
        chain = FakeChain('claim')
        bad = reparse(chain.spend)
        digest = bad.sighash_segwit(0, chain.witness_script, AMOUNT)
        items = [bytes(i) for i in bad.vin[0].witness.items]
        items[0] = FUNDER_KEY.sign(digest).serialize() + b'\x01'
        bad.vin[0].witness = transaction.Witness(items)
        check, _ = run(chain, 'claim', spend=bad)
        self.assertIn('claim signature verifies against the claim key', failed(check))

    def test_refund_with_the_wrong_locktime_or_a_final_sequence_is_caught(self):
        chain = FakeChain('refund')
        early = reparse(chain.spend)
        early.locktime = HEIGHT - 1
        check, _ = run(chain, 'refund', spend=early)
        self.assertIn('refund locktime equals the refund height', failed(check))
        final = reparse(chain.spend)
        final.vin[0].sequence = 0xffffffff
        check, _ = run(chain, 'refund', spend=final)
        self.assertIn('refund input sequence is not final', failed(check))

    def test_refund_mined_at_or_below_the_locktime_is_caught(self):
        chain = FakeChain('refund')
        chain.height[chain.spend.txid().hex()] = HEIGHT
        check, _ = run(chain, 'refund')
        self.assertIn('refund was mined at a height above its locktime', failed(check))

    def test_claim_mined_at_or_after_the_refund_height_is_caught(self):
        chain = FakeChain('claim')
        chain.height[chain.spend.txid().hex()] = HEIGHT
        check, _ = run(chain, 'claim')
        self.assertIn('claim was mined before the refund height', failed(check))

    def test_unconfirmed_transactions_are_not_reported_as_confirmed(self):
        chain = FakeChain('claim')
        chain.install(confirmed=False)
        st = state()
        st['btc_lock'] = chain.fund.txid().hex()
        check = v.Check('t')
        v.check_bitcoin_leg(check, st, chain.spend.txid().hex(), 'claim', ['fake'])
        self.assertTrue(any('confirmed on' in item for item in failed(check)))

    def test_a_funding_output_with_a_different_amount_or_script_is_caught(self):
        chain = FakeChain('claim')
        # The spend commits to the funding txid, so a changed funding transaction is a different transaction.
        other = reparse(chain.fund)
        other.vout[0] = transaction.TransactionOutput(AMOUNT + 5, other.vout[0].script_pubkey)
        chain.install(fund=other)
        v.btc_raw = lambda base, txid: ((other, other.serialize()) if txid == chain.fund.txid().hex() else (chain.spend, chain.spend.serialize()))
        st = state()
        st['btc_lock'] = chain.fund.txid().hex()
        check = v.Check('t')
        v.check_bitcoin_leg(check, st, chain.spend.txid().hex(), 'claim', ['fake'])
        self.assertIn('funding raw bytes hash to the recorded txid', failed(check))

    def test_only_public_state_fields_are_loaded(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / 'x'
            d.mkdir()
            (d / 'state.json').write_text(json.dumps({'scenario': 'x', 'phase': 'complete', 'secret': 'deadbeef', 'preimage': 'aa', 'hashlock': 'bb'}))
            loaded = v.load_state(Path(tmp), 'x')
            self.assertEqual(set(loaded), {'scenario', 'phase', 'hashlock'})


CARDANO_HASH = hashlib.sha256(PREIMAGE).hexdigest()


def cardano_fixture():
    import json
    pinned = json.loads(v.SCRIPT_FILE.read_text())
    st = {
        'hashlock': HASHLOCK, 'ada_amount_lovelace': 4000000, 'ada_assets': {'aa.bb': 5}, 'ada_expiry_ms': 1793738933000,
        'ada_expiry_slot': 127082933, 'ada_lock': '11' * 32, 'ada_claim': '22' * 32,
        'terms': {'ada_claimant': 'c1' * 28, 'ada_refundee': 'c2' * 28, 'ada_claim_address': 'addr_test1claim'},
    }
    lock = {'tx_hash': st['ada_lock'], 'block_height': 10, 'tx_timestamp': 100, 'outputs': [
        {'tx_index': 0, 'value': '4000000', 'payment_addr': {'bech32': pinned['address']}, 'asset_list': [{'policy_id': 'aa', 'asset_name': 'bb', 'quantity': '5'}],
         'inline_datum': {'value': {'fields': [{'bytes': HASHLOCK}, {'bytes': 'c1' * 28}, {'bytes': 'c2' * 28}, {'int': 1793738933000}]}}}]}
    claim = {'tx_hash': st['ada_claim'], 'block_height': 12, 'tx_timestamp': 200, 'invalid_after': '127082000', 'outputs': [
        {'tx_index': 0, 'value': '4000000', 'payment_addr': {'bech32': 'addr_test1claim'}, 'asset_list': [{'policy_id': 'aa', 'asset_name': 'bb', 'quantity': '5'}]}],
        'plutus_contracts': [{'script_hash': pinned['hash'], 'valid_contract': True, 'spends_input': {'tx_hash': st['ada_lock'], 'tx_index': 0},
                              'input': {'redeemer': {'datum': {'value': {'fields': [{'bytes': PREIMAGE.hex()}]}}}}}]}
    return st, lock, claim


def run_cardano(mutate):
    st, lock, claim = cardano_fixture()
    mutate(st, lock, claim)
    infos = {lock['tx_hash']: lock, claim['tx_hash']: claim}
    saved = (v.koios, v.get_json)
    v.koios = lambda path, body: [infos[body['_tx_hashes'][0]]]
    v.get_json = lambda url, body=None: [{'block_no': 20}] if url.endswith('/tip') else []
    try:
        check = v.Check('c')
        v.check_cardano_leg(check, st, {})
        return check
    finally:
        v.koios, v.get_json = saved


class CardanoLegTest(unittest.TestCase):
    def test_genuine_leg_passes(self):
        self.assertEqual(failed(run_cardano(lambda *a: None)), [])

    def test_each_mutation_is_caught(self):
        def redeemer(st, lock, claim):
            claim['plutus_contracts'][0]['input']['redeemer']['datum']['value']['fields'][0]['bytes'] = '00' * 32

        def datum_claimant(st, lock, claim):
            lock['outputs'][0]['inline_datum']['value']['fields'][1] = {'bytes': 'c3' * 28}

        def datum_expiry(st, lock, claim):
            st['ada_expiry_ms'] += 1

        def wrong_address(st, lock, claim):
            lock['outputs'][0]['payment_addr']['bech32'] = 'addr_test1other'

        def invalid_script(st, lock, claim):
            claim['plutus_contracts'][0]['valid_contract'] = False

        def wrong_script(st, lock, claim):
            claim['plutus_contracts'][0]['script_hash'] = '00' * 28

        def short_amount(st, lock, claim):
            claim['outputs'][0]['value'] = '3999999'

        def missing_token(st, lock, claim):
            claim['outputs'][0]['asset_list'][0]['quantity'] = '4'

        def wrong_payee(st, lock, claim):
            claim['outputs'][0]['payment_addr']['bech32'] = 'addr_test1thief'

        def late_claim(st, lock, claim):
            claim['invalid_after'] = str(st['ada_expiry_slot'] + 1)

        def wrong_input(st, lock, claim):
            claim['plutus_contracts'][0]['spends_input'] = {'tx_hash': '33' * 32, 'tx_index': 0}

        def lock_amount(st, lock, claim):
            lock['outputs'][0]['value'] = '3999999'

        for mutate in (redeemer, datum_claimant, datum_expiry, wrong_address, invalid_script, wrong_script, short_amount,
                       missing_token, wrong_payee, late_claim, wrong_input, lock_amount):
            self.assertTrue(failed(run_cardano(mutate)), mutate.__name__ + ' was not caught')


class EthereumLegTest(unittest.TestCase):
    def fixture(self):
        st = {
            'hashlock': HASHLOCK, 'eth_contract': '0x' + '55' * 20, 'eth_lock': '66' * 32, 'eth_claim': '77' * 32, 'eth_expiry': 2000,
            'eth_amount_wei': '100', 'terms': {'eth_claimant': '0x' + 'cc' * 20, 'eth_refundee': '0x' + 'dd' * 20}}
        contract = st['eth_contract']
        lock = {'status': 'ok', 'from': {'hash': st['terms']['eth_refundee']}, 'to': {'hash': contract}, 'value': '100', 'timestamp': '2026-11-03T18:00:00Z', 'block_number': 1}
        claim = {'status': 'ok', 'from': {'hash': st['terms']['eth_claimant']}, 'to': {'hash': contract}, 'timestamp': '2026-11-03T18:10:00Z', 'block_number': 2,
                 'decoded_input': {'parameters': [{'value': '0x' + PREIMAGE.hex()}]}}
        return st, lock, claim

    def execute(self, mutate):
        st, lock, claim = self.fixture()
        st['eth_expiry'] = v._utc('2026-11-03T19:00:00Z')
        extra = {'internal': [{'to': {'hash': st['terms']['eth_claimant']}, 'value': '100'}], 'code': 'RUNTIME', 'spent': 1}
        mutate(st, lock, claim, extra)
        saved = (v.blockscout, v.rpc)
        import public_ethereum_verify as pev
        saved_runtime = pev.expected_runtime
        pev.expected_runtime = lambda *a: 'RUNTIME'

        def fake_blockscout(path):
            if path.endswith('/internal-transactions'):
                return {'items': extra['internal']}
            return {('0x' + st['eth_lock']): lock, ('0x' + st['eth_claim']): claim}[path.split('/transactions/')[1]]

        def fake_rpc(method, params):
            if method == 'eth_getCode':
                return extra['code']
            if method == 'eth_call':
                return hex(extra['spent'])
            return None

        v.blockscout, v.rpc = fake_blockscout, fake_rpc
        try:
            check = v.Check('e')
            v.check_ethereum_leg(check, st, {}, True)
            return check
        finally:
            v.blockscout, v.rpc = saved
            pev.expected_runtime = saved_runtime

    def test_genuine_leg_passes(self):
        self.assertEqual(failed(self.execute(lambda *a: None)), [])

    def test_each_mutation_is_caught(self):
        def code(st, lock, claim, extra):
            extra['code'] = 'OTHER'

        def unspent(st, lock, claim, extra):
            extra['spent'] = 0

        def preimage(st, lock, claim, extra):
            claim['decoded_input']['parameters'][0]['value'] = '0x' + '00' * 32

        def wrong_sender(st, lock, claim, extra):
            claim['from']['hash'] = '0x' + 'ee' * 20

        def lock_value(st, lock, claim, extra):
            lock['value'] = '99'

        def payout(st, lock, claim, extra):
            extra['internal'] = [{'to': {'hash': '0x' + 'ee' * 20}, 'value': '100'}]

        def late(st, lock, claim, extra):
            claim['timestamp'] = '2026-11-03T19:30:00Z'

        def failed_claim(st, lock, claim, extra):
            claim['status'] = 'error'

        for mutate in (code, unspent, preimage, wrong_sender, lock_value, payout, late, failed_claim):
            self.assertTrue(failed(self.execute(mutate)), mutate.__name__ + ' was not caught')


if __name__ == '__main__':
    unittest.main()
