"""The page's JavaScript decision code is tested against config/swap/flow-vectors.json; this keeps that file current."""
import json
import unittest

from swap_engine import engine, ui_vectors


class FlowVectors(unittest.TestCase):
    def test_checked_in_vectors_are_current(self):
        self.assertTrue(ui_vectors.PATH.exists(), 'run: python3 -m swap_engine.ui_vectors')
        self.assertEqual(ui_vectors.PATH.read_text(), ui_vectors.dump(ui_vectors.build()),
                         'config/swap/flow-vectors.json is stale; regenerate with python3 -m swap_engine.ui_vectors')

    def test_vectors_cover_every_transition(self):
        data = json.loads(ui_vectors.PATH.read_text())
        self.assertEqual(data['transitions'], [list(row) for row in engine.TRANSITIONS])
        seen = {(c['record']['role'], c['record']['state'], c['decision'].get('to')) for c in data['decide'] if c['decision'].get('to')}
        for role, source, target, _ in engine.TRANSITIONS:
            if target != 'aborted':
                self.assertIn((role, source, target), seen)


class WorkerConstants(unittest.TestCase):
    """Constants the Worker hard-codes for Sepolia escrow events and calls must equal the keccak hashes of the contract signatures."""

    def test_event_topics_and_spent_selector(self):
        import re
        from pathlib import Path
        from eth_utils import keccak
        source = (Path(__file__).resolve().parents[2] / 'swap-service' / 'cloudflare' / 'worker.mjs').read_text()
        topics = dict(re.findall(r"'(0x[0-9a-f]{64})':'(claimed|refunded)'", source))
        expected = {'0x' + keccak(text=sig).hex(): kind for sig, kind in [
            ('Claimed(bytes32,address,uint256)', 'claimed'), ('Claimed(bytes32)', 'claimed'), ('Refunded(address,uint256)', 'refunded'), ('Refunded()', 'refunded')]}
        self.assertEqual(topics, expected)
        self.assertIn("SPENT_CALL='0x" + keccak(text='spent()').hex() + "'", source)
        self.assertEqual(engine_topic('Claimed(bytes32,address,uint256)'), '0x' + keccak(text='Claimed(bytes32,address,uint256)').hex())


def engine_topic(signature):
    from swap_engine.adapters import ethereum
    return {'Claimed(bytes32,address,uint256)': ethereum.CLAIMED}[signature]


if __name__ == '__main__':
    unittest.main()
