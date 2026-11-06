"""Adapter contract tests against in-memory providers, plus an offline check of the Cardano script.

The Bitcoin adapter runs unchanged against a fake Esplora that models blocks, the mempool and
reorgs; transactions are built and signed by the real public_bitcoin_transactions code and parsed
back to find the witness. The Cardano adapter's inspect runs against canned Koios rows. Public and
local-chain behaviour is covered by the live runs recorded in .agent/SWAP_ENGINE_EXECPLAN.md.
"""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from embit import ec, transaction

from swap_engine import engine
from swap_engine import timelock_policy as policy
from swap_engine.adapter import ActionRefused, ChainUnavailable, check_observation
from swap_engine.adapters.bitcoin import BitcoinAdapter
from swap_engine.adapters.cardano import CardanoAdapter
from swap_engine.adapters.ethereum import EthereumAdapter
from swap_engine.adapters.hegemon_stub import HegemonStubAdapter
from swap_engine.store import Store, journal_ids
from swap_engine.tools import find_tool

PREIMAGE = bytes(range(1, 33))
HASHLOCK = hashlib.sha256(PREIMAGE).hexdigest()


def private_directory():
    handle = tempfile.TemporaryDirectory()
    os.chmod(handle.name, 0o700)
    return handle, Path(handle.name)


class FakeEsplora:
    """The subset of Esplora the adapter uses."""
    name = 'bitcoin'
    journal_chain = 'bitcoin-testnet4'
    network = 'test'

    def __init__(self):
        self.height = 1000
        self.hashes = {}
        self.txs = {}
        self.spent = {}
        self.coins = {}
        self.fail = False
        self.clock = 1_800_000_000

    def now(self):
        return self.clock

    def load_key(self, path):
        return ec.PrivateKey(bytes.fromhex(Path(path).read_text().strip()))

    def _guard(self):
        if self.fail:
            raise OSError('provider down')

    def tip_height(self):
        self._guard()
        return self.height

    def block_hash(self, height):
        return self.hashes.setdefault(height, f'{height:064x}')

    def tx(self, txid):
        self._guard()
        return self.txs.get(txid)

    def outspend(self, txid, vout):
        self._guard()
        spender = self.spent.get((txid, vout))
        return {'spent': True, 'txid': spender} if spender else {'spent': False}

    def utxos(self, address):
        return list(self.coins.get(address, []))

    def fee(self):
        return 250

    def submit(self, journal, raw):
        import public_swap_journal
        record = public_swap_journal.prepare(journal, 'bitcoin-testnet4', raw)
        tx = transaction.Transaction.parse(raw)
        txid = record['txid']
        self.txs[txid] = {'txid': txid, 'status': {'confirmed': False},
                          'vin': [{'txid': i.txid.hex(), 'vout': i.vout, 'witness': [w.hex() for w in i.witness.items]} for i in tx.vin],
                          'vout': [{'value': o.value, 'scriptpubkey': o.script_pubkey.data.hex()} for o in tx.vout]}
        for i in tx.vin:
            self.spent[(i.txid.hex(), i.vout)] = txid
        return {'txid': txid}

    def confirm(self, txid, depth=2):
        self.txs[txid]['status'] = {'confirmed': True, 'block_height': self.height - depth + 1, 'block_hash': self.block_hash(self.height - depth + 1)}


class BitcoinAdapterTests(unittest.TestCase):
    def setUp(self):
        handle, self.root = private_directory()
        self.addCleanup(handle.cleanup)
        self.chain = FakeEsplora()
        self.alice = self.wallet('alice', 11)
        self.bob = self.wallet('bob', 12)
        self.journal = self.root / 'journal'
        self.journal.mkdir(mode=0o700)
        self.leg = {'chain': 'bitcoin', 'amount': 50_000, 'refundee': self.alice.identity(), 'claimant': self.bob.identity(),
                    'expiry': self.chain.height + 40, 'hashlock': HASHLOCK}

    def wallet(self, name, seed):
        path = self.root / (name + '.key')
        path.write_text(bytes([seed]) * 32 and (bytes([seed]) * 32).hex() + '\n')
        path.chmod(0o600)
        adapter = BitcoinAdapter(self.chain, path)
        from embit import networks, script
        key = self.chain.load_key(path)
        address = script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['test'])
        self.chain.coins[address] = [{'txid': f'{seed:064x}', 'vout': 0, 'amount_sats': 200_000, 'confirmations': 5, 'block_hash': 'aa' * 32}]
        return adapter

    def funded(self):
        txid = self.alice.fund(self.leg, self.journal)['txid']
        self.chain.confirm(txid)
        return {'txid': txid, 'vout': 0}

    def test_fund_then_inspect_verifies_the_exact_output(self):
        ref = self.alice.escrow_ref(self.leg, self.alice.fund(self.leg, self.journal)['txid'])
        self.assertEqual(self.alice.inspect(self.leg, ref)['confirmations'], 0)
        self.chain.confirm(ref['txid'], 3)
        seen = check_observation(self.bob.inspect(self.leg, ref))
        self.assertTrue(seen['verified'])
        self.assertEqual((seen['confirmations'], seen['spent']), (3, None))
        self.assertEqual(journal_ids(self.journal, 'bitcoin-testnet4'), [ref['txid']])

    def test_inspect_reports_mismatch_as_a_problem_not_an_error(self):
        ref = self.funded()
        for change, word in (({'amount': 50_001}, 'amount'), ({'expiry': self.leg['expiry'] + 1}, 'script'), ({'claimant': self.alice.identity(), 'refundee': self.bob.identity()}, 'script')):
            seen = self.bob.inspect({**self.leg, **change}, ref)
            self.assertFalse(seen['verified'], change)
            self.assertIn(word, seen['problem'])

    def test_unknown_and_reorged_transactions(self):
        self.assertFalse(self.bob.inspect(self.leg, {'txid': '77' * 32, 'vout': 0})['found'])
        ref = self.funded()
        self.chain.hashes[self.chain.height - 1] = 'ff' * 32  # the block is no longer canonical
        seen = self.bob.inspect(self.leg, ref)
        self.assertEqual((seen['found'], seen['confirmations']), (True, 0))

    def test_provider_failure_is_unavailable(self):
        ref = self.funded()
        self.chain.fail = True
        for call in (lambda: self.bob.head(), lambda: self.bob.inspect(self.leg, ref), lambda: self.bob.transaction_seen(ref['txid'])):
            with self.assertRaises(ChainUnavailable):
                call()

    def test_claim_reveals_the_preimage_even_from_the_mempool(self):
        ref = self.funded()
        txid = self.bob.claim(self.leg, ref, bytearray(PREIMAGE), self.journal)['txid']
        seen = self.alice.inspect(self.leg, ref)
        self.assertEqual((seen['spent'], seen['spend_txid'], seen['spend_confirmations'], seen['preimage']), ('claimed', txid, 0, PREIMAGE.hex()))
        self.chain.confirm(txid, 2)
        self.assertEqual(self.alice.inspect(self.leg, ref)['spend_confirmations'], 2)

    def test_two_candidate_preimages_is_unavailable_not_a_guess(self):
        ref = self.funded()
        txid = self.bob.claim(self.leg, ref, bytearray(PREIMAGE), self.journal)['txid']
        self.chain.txs[txid]['vin'][0]['witness'].append(PREIMAGE.hex())
        with self.assertRaises(ChainUnavailable):
            self.alice.inspect(self.leg, ref)

    def test_refund_waits_for_the_height_and_shows_no_preimage(self):
        ref = self.funded()
        with self.assertRaisesRegex(ActionRefused, 'not yet due'):
            self.alice.refund(self.leg, ref, self.journal)
        self.chain.height = self.leg['expiry']
        txid = self.alice.refund(self.leg, ref, self.journal)['txid']
        seen = self.bob.inspect(self.leg, ref)
        self.assertEqual((seen['spent'], seen['spend_txid'], seen['preimage']), ('refunded', txid, None))

    def test_claim_refused_once_refundable(self):
        ref = self.funded()
        self.chain.height = self.leg['expiry']
        before = journal_ids(self.journal, 'bitcoin-testnet4')
        with self.assertRaisesRegex(ActionRefused, 'refundable'):
            self.bob.claim(self.leg, ref, bytearray(PREIMAGE), self.journal)
        self.assertEqual(journal_ids(self.journal, 'bitcoin-testnet4'), before)

    def test_wrong_wallet_and_wrong_preimage_refused_before_signing(self):
        ref = self.funded()
        with self.assertRaises(ActionRefused):
            self.alice.claim(self.leg, ref, bytearray(PREIMAGE), self.journal)
        with self.assertRaises(ActionRefused):
            self.bob.claim(self.leg, ref, bytearray(b'x' * 32), self.journal)
        with self.assertRaises(ActionRefused):
            self.bob.fund(self.leg, self.journal)
        self.assertEqual(len(journal_ids(self.journal, 'bitcoin-testnet4')), 1)

    def test_funding_refused_without_a_coin_or_with_a_dust_escrow(self):
        with self.assertRaises(ActionRefused):
            self.alice.fund({**self.leg, 'amount': 5_000_000}, self.journal)
        with self.assertRaises(ActionRefused):
            self.alice.fund({**self.leg, 'amount': 600}, self.journal)
        self.chain.height = self.leg['expiry']
        with self.assertRaises(ActionRefused):
            self.alice.fund(self.leg, self.journal)
        self.assertEqual(journal_ids(self.journal, 'bitcoin-testnet4'), [])


class EthereumReadTests(unittest.TestCase):
    class Profile:
        journal_chain = 'ethereum-sepolia'

        def __init__(self):
            self.answers, self.fail = {}, False

        def load_wallet(self, path):
            return None, '0x' + 'ab' * 20

        def rpc(self, method, params):
            if self.fail:
                raise OSError('rpc down')
            return self.answers.get(method)

        def now(self):
            return 1_800_000_000

    def setUp(self):
        self.profile = self.Profile()
        self.adapter = EthereumAdapter(self.profile, '/nonexistent')
        self.leg = {'chain': 'ethereum', 'amount': 5, 'refundee': self.adapter.identity(), 'claimant': '0x' + 'cd' * 20, 'expiry': 1_800_003_600, 'hashlock': HASHLOCK}
        self.ref = {'txid': '44' * 32}

    def test_identity_is_lowercase_and_head_reads_the_block_time(self):
        self.assertEqual(self.adapter.identity(), '0x' + 'ab' * 20)
        self.profile.answers['eth_getBlockByNumber'] = {'timestamp': hex(1_800_000_001)}
        self.assertEqual(self.adapter.head(), {'observedAt': 1_800_000_000, 'timestamp': 1_800_000_001})

    def test_unknown_transaction_is_not_found(self):
        self.assertFalse(self.adapter.inspect(self.leg, self.ref)['found'])

    def test_mined_transaction_without_a_receipt_is_a_lagging_provider_not_a_missing_escrow(self):
        self.profile.answers['eth_getTransactionByHash'] = {'blockNumber': '0x10'}
        with self.assertRaises(ChainUnavailable):
            self.adapter.inspect(self.leg, self.ref)

    def test_failed_creation_is_a_problem_and_rpc_failure_is_unavailable(self):
        self.profile.answers['eth_getTransactionReceipt'] = {'status': '0x0'}
        self.assertIn('failed', self.adapter.inspect(self.leg, self.ref)['problem'])
        self.profile.fail = True
        for call in (self.adapter.head, lambda: self.adapter.inspect(self.leg, self.ref), lambda: self.adapter.transaction_seen('44' * 32)):
            with self.assertRaises(ChainUnavailable):
                call()

    def test_writes_refuse_the_wrong_actor_before_signing(self):
        handle, root = private_directory()
        self.addCleanup(handle.cleanup)
        for call in (lambda: self.adapter.claim(self.leg, self.ref, bytearray(PREIMAGE), root), lambda: self.adapter.fund({**self.leg, 'refundee': '0x' + 'ee' * 20}, root)):
            with self.assertRaises(ActionRefused):
                call()
        self.assertEqual(journal_ids(root), [])


class StubTests(unittest.TestCase):
    def test_reads_are_unavailable_and_writes_are_refused(self):
        stub = HegemonStubAdapter()
        for call in (stub.head, lambda: stub.inspect({}, {}), lambda: stub.transaction_seen('00' * 32)):
            with self.assertRaises(ChainUnavailable):
                call()
        for call in (lambda: stub.fund({}, '.'), lambda: stub.claim({}, {}, b'', '.'), lambda: stub.refund({}, {}, '.')):
            with self.assertRaises(ActionRefused):
                call()
        self.assertEqual(stub.journal_ids('.'), [])

    def test_engine_waits_and_never_acts_on_an_absent_chain(self):
        handle, root = private_directory()
        self.addCleanup(handle.cleanup)
        initiator, responder = 'a' * 64, 'b' * 64
        terms = {'version': 1, 'hashlock': HASHLOCK, 'legs': {
            'long': {'chain': 'hegemon', 'amount': 5, 'refundee': initiator, 'claimant': responder, 'expiry': 1_800_009_000},
            'short': {'chain': 'hegemon', 'amount': 5, 'refundee': responder, 'claimant': initiator, 'expiry': 1_800_005_000}}}
        store = Store(root / 'swaps')
        store.create('0123456789abcdef', 'initiator', terms, 1_800_000_000, PREIMAGE)
        adapters = {'long': HegemonStubAdapter(initiator), 'short': HegemonStubAdapter(initiator)}
        with store.locked('0123456789abcdef') as swap:
            result = engine.advance(swap, adapters, policy.load_timing(), 1_800_000_000)
            self.assertEqual(result['status'], 'waiting')
            self.assertIsNone(swap.record['inflight'])
            self.assertEqual(swap.record['state'], 'terms_saved')


@unittest.skipUnless(find_tool('aiken') and find_tool('cardano-cli'), 'aiken and cardano-cli are required')
class CardanoInspectTests(unittest.TestCase):
    KEYS = {'claimant': 'cc' * 28, 'refundee': 'dd' * 28}

    class Profile:
        name = 'cardano'
        journal_chain = 'cardano-preview'
        system_start = 1666656000
        testnet_args = ['--testnet-magic', '2']

        def __init__(self):
            self.depths, self.rows, self.spenders, self.preimages, self.fail = {}, {}, {}, {}, False

        def now(self):
            return 1_800_000_000

        def tip_slot(self):
            return 1_800_000_000 - self.system_start

        def confirmations(self, txid):
            if self.fail:
                raise OSError('koios down')
            return self.depths.get(txid, 0)

        def utxo_info(self, outref):
            return self.rows.get(outref)

        def spender(self, address, outref, height):
            return self.spenders.get(outref)

        def claim_preimage(self, txid, outref, hashlock):
            return self.preimages[txid]() if callable(self.preimages[txid]) else self.preimages[txid]

    def setUp(self):
        self.profile = self.Profile()
        self.adapter = CardanoAdapter(self.profile, {'skey': '/nonexistent', 'keyhash': self.KEYS['claimant'], 'address': 'addr_test1vzygjsmekg63qtxzu4d3l90g2aasd6vfv6p6n45yjkl4vtc4r6w3k'})
        self.leg = {'chain': 'cardano', 'amount': 5_000_000, 'refundee': self.KEYS['refundee'], 'claimant': self.KEYS['claimant'],
                    'expiry': 1_800_003_600, 'hashlock': HASHLOCK}
        self.ref = {'txid': '11' * 32, 'vout': 0}
        self.row = {'address': self.adapter.script_address(), 'value': '5000000', 'asset_list': [], 'is_spent': False, 'block_height': 10,
                    'inline_datum': {'bytes': '00', 'value': CardanoAdapter._datum(self.leg)}}
        self.profile.depths[self.ref['txid']] = 3
        self.profile.rows['11' * 32 + '#0'] = self.row

    def test_script_address_matches_the_historical_preview_escrows(self):
        self.assertEqual(self.adapter.script_address(), 'addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv')

    def test_verifies_exact_terms_and_flags_each_difference(self):
        seen = check_observation(self.adapter.inspect(self.leg, self.ref))
        self.assertEqual((seen['verified'], seen['confirmations']), (True, 3))
        for name, change in (('value', {'amount': 5_000_001}), ('datum', {'expiry': self.leg['expiry'] + 1}), ('datum', {'claimant': 'ee' * 28})):
            seen = self.adapter.inspect({**self.leg, **change}, self.ref)
            self.assertFalse(seen['verified'])
            self.assertIn(name, seen['problem'])
        self.row['asset_list'] = [{'policy_id': 'aa' * 28, 'asset_name': '', 'quantity': '1'}]
        self.assertIn('value', self.adapter.inspect(self.leg, self.ref)['problem'])
        self.row['asset_list'] = []
        self.row['address'] = 'addr_test1vzygjsmekg63qtxzu4d3l90g2aasd6vfv6p6n45yjkl4vtc4r6w3k'
        self.assertIn('script address', self.adapter.inspect(self.leg, self.ref)['problem'])

    def test_unknown_unindexed_and_failing_reads(self):
        self.assertFalse(self.adapter.inspect(self.leg, {'txid': '22' * 32, 'vout': 0})['found'])
        del self.profile.rows['11' * 32 + '#0']
        with self.assertRaises(ChainUnavailable):
            self.adapter.inspect(self.leg, self.ref)
        self.profile.fail = True
        with self.assertRaises(ChainUnavailable):
            self.adapter.inspect(self.leg, self.ref)

    def test_claimed_refunded_and_not_yet_visible_spends(self):
        self.row['is_spent'] = True
        with self.assertRaises(ChainUnavailable):
            self.adapter.inspect(self.leg, self.ref)  # spent, spender unknown
        self.profile.spenders['11' * 32 + '#0'] = '33' * 32
        self.profile.depths['33' * 32] = 2
        self.profile.preimages['33' * 32] = bytearray(PREIMAGE)
        seen = self.adapter.inspect(self.leg, self.ref)
        self.assertEqual((seen['spent'], seen['spend_txid'], seen['spend_confirmations'], seen['preimage']), ('claimed', '33' * 32, 2, PREIMAGE.hex()))
        self.profile.preimages['33' * 32] = None
        seen = self.adapter.inspect(self.leg, self.ref)
        self.assertEqual((seen['spent'], seen['preimage']), ('refunded', None))

        def pending():
            raise RuntimeError('spending transaction bytes are not indexed yet')
        self.profile.preimages['33' * 32] = pending
        with self.assertRaises(ChainUnavailable):
            self.adapter.inspect(self.leg, self.ref)

    def test_head_time_comes_from_the_slot(self):
        self.assertEqual(self.adapter.head()['timestamp'], 1_800_000_000)

    def test_writes_refuse_wrong_roles_and_closed_windows_before_signing(self):
        handle, root = private_directory()
        self.addCleanup(handle.cleanup)
        with self.assertRaises(ActionRefused):  # the wallet is the claimant, not the refundee
            self.adapter.fund(self.leg, root)
        with self.assertRaises(ActionRefused):
            self.adapter.refund(self.leg, self.ref, root)
        late = {**self.leg, 'expiry': 1_800_000_010}
        with self.assertRaises(ActionRefused):
            self.adapter.claim(late, self.ref, bytearray(PREIMAGE), root)
        self.assertEqual(journal_ids(root), [])


if __name__ == '__main__':
    unittest.main()
