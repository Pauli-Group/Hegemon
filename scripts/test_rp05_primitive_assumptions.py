#!/usr/bin/env python3
"""Regression checks for stale evidence and overclaimed audit results."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rp05_primitive_assumptions as ledger


class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ledger.ROOT / ledger.LEDGER).read_text())

    def rejected(self, mutate):
        data = copy.deepcopy(self.data)
        mutate(data)
        with self.assertRaises(ValueError):
            ledger.validate(ledger.ROOT, data)

    def test_current_audit_is_conditional(self):
        result = ledger.validate(ledger.ROOT, self.data)
        self.assertEqual(result['status'], 'PASS_AUDIT_INTEGRITY')
        self.assertEqual(result['concrete_bounds'], 0)
        self.assertFalse(result['production_authorized'])

    def test_quantified_gate_stays_closed(self):
        with self.assertRaisesRegex(ValueError, 'unquantified'):
            ledger.validate(ledger.ROOT, self.data, True)

    def test_stale_source(self):
        self.rejected(lambda d: d['evidence'][0].update(sha256='0' * 64))

    def test_missing_term(self):
        self.rejected(lambda d: d['terms'].pop())

    def test_wrong_event(self):
        self.rejected(lambda d: d['terms'][0].update(event='unrelatedGame'))

    def test_legacy_nullifier_domain(self):
        self.rejected(lambda d: d['terms'][2].update(domain='2'))

    def test_generic_screen_cannot_be_promoted_to_concrete_bound(self):
        self.rejected(lambda d: d['primitive_suite'].update(
            generic_work_or_reduced_round_screen_is_concrete_advantage_bound=True))

    def test_invented_numerical_bound(self):
        self.rejected(lambda d: d['terms'][0].update(concrete_advantage_bound='2^-131'))

    def test_wrong_resource_inference(self):
        self.rejected(lambda d: d.update(primitive_query_cap_inferred_from_proof_cap=True))

    def test_projection_boundary_is_required(self):
        self.rejected(lambda d: d['additional_boundaries'].pop(1))

    def test_invented_refinement(self):
        self.rejected(lambda d: d['additional_boundaries'][2].update(status='proved'))

    def test_invented_authority(self):
        self.rejected(lambda d: d.update(production_authorized=True))

    def test_paths_cannot_escape(self):
        for path in ('../secret', '/tmp/secret', 'formal//file', './file', 'a\\b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                ledger.regular(ledger.ROOT, path)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'real').write_text('x')
            (root / 'alias').symlink_to(root / 'real')
            with self.assertRaises(ValueError):
                ledger.regular(root, 'alias')

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"status":false,"status":true}', object_pairs_hook=ledger.unique_object)


if __name__ == '__main__':
    unittest.main()
