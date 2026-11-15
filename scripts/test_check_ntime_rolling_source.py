#!/usr/bin/env python3
"""Mutation controls for source preparation; no binaries, network or Git needed."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ntime_source_tests',
        ROOT / 'scripts/check_ntime_rolling_source.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class SourcePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Real, bounded proof inputs make mutation checks exercise the actual
        # relation digest instead of mocking the qualification boundary.
        cls.identity = gate.proof_helper.proof_identity(ROOT)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        names = {row['path'] for row in self.identity['source_inputs']}
        names.update((gate.CONFIG, 'protocol/versioning/src/lib.rs',
                      'consensus-light-client/src/pow_rules.rs', 'consensus/src/reward.rs',
                      'circuits/transaction/src/private_spend.rs',
                      'circuits/transaction/src/private_spend/types.rs', 'Cargo.lock'))
        total = sum((ROOT / name).stat().st_size for name in names)
        self.assertLess(total, 16 * 1024 * 1024)
        for name in names:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def config(self, mutate):
        path = self.root / gate.CONFIG
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value))

    def replace(self, name, old, new):
        path = self.root / name
        original = path.read_text()
        self.assertIn(old, original)
        path.write_text(original.replace(old, new))

    def test_real_source_passes_with_explicitly_limited_single_line_receipt(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(gate.main(['--root', str(self.root)]), 0)
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt['scope'], 'source-preparation-only')
        self.assertEqual(receipt['proof_source_input_count'], 41)
        for name in (*gate.BOUNDARIES, 'behavior_verified', 'rules_preimage_hash_verified'):
            self.assertIs(receipt[name], False)

    def test_config_activation_drift_rejects(self):
        self.config(lambda c: c.update(ntime_activation_height=28_920))
        with self.assertRaisesRegex(gate.SourceError, 'activation height differs'):
            gate.verify_source(self.root)

    def test_source_activation_drift_rejects(self):
        self.replace('consensus-light-client/src/pow_rules.rs', 'Some(28_860)', 'Some(28_920)')
        with self.assertRaisesRegex(gate.SourceError, 'activation height differs'):
            gate.verify_source(self.root)

    def test_product_label_mismatch_rejects(self):
        self.replace('protocol/versioning/src/lib.rs', '"0.11.5"', '"0.11.4"')
        with self.assertRaisesRegex(gate.SourceError, 'product version'):
            gate.verify_source(self.root)

    def test_config_profile_hash_drift_rejects(self):
        self.config(lambda c: c.update(ntime_rules_hash='01' * 32))
        with self.assertRaisesRegex(gate.SourceError, 'rules hash differs'):
            gate.verify_source(self.root)

    def test_proof_input_mutation_rejects(self):
        name = next(row['path'] for row in self.identity['source_inputs'] if row['path'] != 'Cargo.lock')
        with (self.root / name).open('ab') as output:
            output.write(b'\n// source preparation mutation control\n')
        with self.assertRaises(gate.SourceError):
            gate.verify_source(self.root)

    def test_lock_mutation_rejects(self):
        with (self.root / 'Cargo.lock').open('ab') as output:
            output.write(b'\n# changed proof input\n')
        with self.assertRaisesRegex(gate.SourceError, 'proof relation or Cargo.lock differs'):
            gate.verify_source(self.root)

    def test_any_authority_true_rejects(self):
        path = self.root / gate.CONFIG
        original = path.read_bytes()
        for name in gate.BOUNDARIES:
            path.write_bytes(original)
            self.config(lambda c, name=name: c['boundaries'].update({name: True}))
            with self.subTest(name=name), self.assertRaisesRegex(gate.SourceError, 'cannot grant'):
                gate.verify_source(self.root)

    def test_chain_and_genesis_drift_reject(self):
        path = self.root / gate.CONFIG
        original = path.read_bytes()
        for name in ('chain_id', 'genesis_hash'):
            path.write_bytes(original)
            self.config(lambda c, name=name: c.update({name: '00' * 32}))
            with self.subTest(name=name), self.assertRaisesRegex(gate.SourceError, 'chain or genesis'):
                gate.verify_source(self.root)

    def test_future_bound_drift_rejects(self):
        self.replace('consensus/src/reward.rs', '90_000;', '91_000;')
        with self.assertRaisesRegex(gate.SourceError, 'future-skew bound differs'):
            gate.verify_source(self.root)

    def test_activation_date_cannot_become_authority(self):
        self.config(lambda c: c['planned_activation'].update(planning_only=False))
        with self.assertRaisesRegex(gate.SourceError, 'planning-only'):
            gate.verify_source(self.root)


if __name__ == '__main__':
    unittest.main()
