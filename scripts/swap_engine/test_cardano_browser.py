"""The hosted page's Cardano transactions against a real ledger and the real Plutus validator.

Runs a private one-node cluster (about 30 s to start). Skipped when cardano, aiken-compiled script or node are missing.
Run from scripts/ with: PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_cardano_browser
"""
import json
import time
import unittest

try:
    from swap_engine.tools import find_tool
    from swap_engine import cardano_browser_harness as harness
except ImportError:  # pragma: no cover
    from tools import find_tool
    import cardano_browser_harness as harness


class ScriptPinTests(unittest.TestCase):
    def test_hosted_script_is_the_compiled_validator(self):
        blueprint = json.loads((harness.ROOT / 'contracts/cardano/plutus.json').read_text())
        spend = next(v for v in blueprint['validators'] if v['title'] == 'htlc.htlc.spend')
        pinned = harness.SCRIPT
        self.assertEqual(pinned['compiledCode'], spend['compiledCode'])
        self.assertEqual(pinned['hash'], spend['hash'])
        self.assertEqual(pinned['language'], 'PlutusV3')
        self.assertEqual(blueprint['preamble']['plutusVersion'], 'v3')

    def test_fixed_budget_is_set_and_inside_the_network_limits(self):
        units = harness.SCRIPT['executionUnits']
        self.assertTrue(0 < units['memory'] <= 14_000_000 and 0 < units['steps'] <= 10_000_000_000)


@unittest.skipUnless(find_tool('cardano-cli') and find_tool('cardano-node') and harness.node_binary(), 'cardano-cli, cardano-node and node are required')
class CardanoBrowserLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = harness.Harness()
        cls.units = harness.SCRIPT['executionUnits']

    @classmethod
    def tearDownClass(cls):
        cls.h.close()

    def fund(self, name='alice', **kw):
        terms, preimage = self.h.terms(funder=name, **kw)
        out = self.h.run_page('fund', name, terms)
        txid = self.h.submit_hex(out['signedHex'])
        self.assertEqual(txid, out['txid'])
        escrow = self.h.escrow_utxo(txid)
        self.assertIsNotNone(escrow, 'the real ledger accepted the escrow output at the pinned validator address')
        terms['outref'] = escrow['outref']
        return terms, preimage, escrow, out

    def test_fund_then_claim_with_fixed_budget_reveals_preimage(self):
        terms, preimage, escrow, _ = self.fund(seconds=200)
        before = self.h.balance('bob')[0]
        out = self.h.run_page('claim', 'bob', terms, preimage=preimage)
        self.assertEqual(out['journal'], ['completed'])
        cost = self.h.script_cost(out['signedHex'])
        self.assertLess(cost['memory'] * 2, self.units['memory'], 'budget keeps at least 2x headroom over measured memory')
        self.assertLess(cost['steps'] * 2, self.units['steps'], 'budget keeps at least 2x headroom over measured steps')
        txid = self.h.submit_hex(out['signedHex'])
        self.assertIsNone(self.h.escrow_utxo(escrow['outref'].split('#')[0]), 'the escrow output is spent')
        self.assertEqual(self.h.profile.spender(None, escrow['outref'], None), txid)
        self.assertEqual(bytes(self.h.profile.claim_preimage(txid, escrow['outref'], terms['hashlock'])).hex(), preimage)
        gained = self.h.balance('bob')[0] - before
        self.assertEqual(gained, 10_000_000 - int(out['fee']))

    def test_refund_only_after_the_deadline(self):
        terms, _, escrow, _ = self.fund(seconds=20)
        with self.assertRaises(harness.PageRefused) as early:
            self.h.run_page('refund', 'alice', terms)
        self.assertIn('before its deadline', str(early.exception))
        while self.h.tip_unix() < int(terms['expiry_ms']) // 1000 + 1:
            time.sleep(1)
        with self.assertRaises(harness.PageRefused) as late:
            self.h.run_page('claim', 'bob', terms, preimage='00' * 32)
        self.assertRegex(str(late.exception), r'deadline|passed|closed')
        out = self.h.run_page('refund', 'alice', terms)
        cost = self.h.script_cost(out['signedHex'])
        self.assertLess(cost['memory'] * 2, self.units['memory'])
        self.assertLess(cost['steps'] * 2, self.units['steps'])
        txid = self.h.submit_hex(out['signedHex'])
        self.assertEqual(self.h.profile.spender(None, escrow['outref'], None), txid)

    def test_native_tokens_are_locked_claimed_and_unrelated_tokens_survive(self):
        locked = self.h.mint('alice', '686772', 1000)
        other = self.h.mint('alice', '6f74686572', 77)
        before = self.h.balance('alice')[1]
        self.assertEqual((before[locked], before[other]), (1000, 77))
        terms, preimage, escrow, _ = self.fund(seconds=200, assets=f'{locked}=600')
        mid = self.h.balance('alice')[1]
        self.assertEqual((mid[locked], mid[other]), (400, 77), 'only the agreed token amount left the wallet; unrelated tokens remained')
        self.assertEqual(escrow['assets'], {locked: 600})
        bob_before = self.h.balance('bob')[1].get(locked, 0)
        out = self.h.run_page('claim', 'bob', terms, preimage=preimage)
        self.h.submit_hex(out['signedHex'])
        self.assertEqual(self.h.balance('bob')[1].get(locked, 0) - bob_before, 600)

    def test_a_token_bearing_fee_input_returns_its_unrelated_tokens(self):
        # Claim with only a token-carrying UTxO available for fees: it must come back in the claim's output.
        other = self.h.mint('bob', '686774', 5)
        terms, preimage, escrow, _ = self.fund(seconds=200)
        carrying = [u for u in self.h.wallet_utxos('bob') if other in u['assets']]
        self.assertTrue(carrying)
        out = self.h.run_page('claim', 'bob', terms, preimage=preimage, extra={'utxos': carrying + [u for u in self.h.wallet_utxos('bob') if u['assets'] == {} and u['lovelace'] >= 5_000_000][:1]})
        self.h.submit_hex(out['signedHex'])
        self.assertEqual(self.h.balance('bob')[1][other], 5)

    def test_a_budget_far_below_the_measured_cost_is_rejected_by_the_node_and_the_escrow_is_untouched(self):
        terms, preimage, escrow, _ = self.fund(seconds=200)
        out = self.h.run_page('claim', 'bob', terms, preimage=preimage, budget={'memory': 1000, 'steps': 1000})
        with self.assertRaises(RuntimeError):
            self.h.submit_hex(out['signedHex'], wait=False)
        self.assertIsNotNone(self.h.escrow_utxo(escrow['outref'].split('#')[0]), 'the escrow is untouched')


if __name__ == '__main__':
    unittest.main()
