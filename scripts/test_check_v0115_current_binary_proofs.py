#!/usr/bin/env python3
"""Synthetic source/receipt controls; no actual proof or release qualification."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_v0115_proof_harness_controls', ROOT / 'scripts/check_v0115_current_binary_proofs.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def ownership(windows):
    value = {'schema': 'hegemon.v0115.process-ownership.v1',
        'backend': 'windows-creation-job-list' if windows else 'posix-session-process-group',
        'owned_before_execution': True, 'processes_reaped': True, 'active_processes_after': 0,
        'stdio_handle_allowlist': True, 'stdout_limit_bytes': 65536, 'stderr_limit_bytes': 65536,
        'reader_threads_joined': True, 'accounting': {'active_processes': 0}}
    if windows:
        value.update(kill_on_close=True, creation_time_job_association=True,
            suspended_primary_thread_retained=True, exact_job_membership_checked_before_resume=True,
            resume_prior_suspend_count=1, job_handle_inherited=False,
            accounting={'total_processes': 1, 'active_processes': 0, 'terminated_processes': 0})
    return value


class HarnessControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in (h.HISTORICAL, h.WRAPPER, h.OWNER):
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        self.config = {'schema': 'hegemon.ntime-rolling.candidate.v1', 'status': 'frozen',
            'source_inventory': [{'path': name, 'bytes': (self.root / name).stat().st_size,
                'sha256': h.digest(self.root / name), 'mode': '100644'}
                for name in (h.HISTORICAL, h.WRAPPER, h.OWNER)], 'source_inventory_sha256': 'a' * 64}
        self.write_config()
    def write_config(self):
        path = self.root / h.CONFIG; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.config))
    def fixture(self, windows=False):
        config, pins = h.frozen_sources(self.root)
        harness = {'schema': h.SCHEMA, 'contract': h.CONTRACT,
            'historical_proof_logic_sha256': h.HISTORICAL_SHA256,
            'wrapper_path': h.WRAPPER, 'process_owner_path': h.OWNER,
            'runtime_platform': 'windows' if windows else 'posix',
            'source_inventory_sha256': config['source_inventory_sha256'],
            'source_pins': pins, 'source_inputs_before': pins, 'source_inputs_after': pins,
            'historical_run_command_replaced': True, 'proof_predicates_unchanged': True,
            'actual_owned_runs': 35, 'all_runs_owned_and_reaped': True}
        cases = [{'process_ownership': ownership(windows),
                  'negative_controls': {str(index): {'process_ownership': ownership(windows)} for index in range(6)}}
                 for _ in range(5)]
        return {'target_triple': 'x86_64-pc-windows-msvc' if windows else 'x86_64-unknown-linux-gnu',
                'execution_harness': harness, 'cases': cases}
    def test_preimport_hashes_are_frozen_and_historical_logic_has_independent_constant(self):
        historical, owner, config, pins = h.load_modules(self.root)
        self.assertEqual(pins[h.HISTORICAL], h.HISTORICAL_SHA256)
        self.assertTrue(callable(historical.execute)); self.assertTrue(callable(owner.run_command))
        (self.root / h.OWNER).write_text('raise RuntimeError("must not import changed bytes")')
        with patch.object(h, 'import_source') as imported, self.assertRaisesRegex(h.HarnessError, 'pre-import'):
            h.load_modules(self.root)
        imported.assert_not_called()
    def test_pending_missing_duplicate_and_forged_historical_pins_fail_before_import(self):
        mutations = [lambda value: value.__setitem__('status', 'pending'),
            lambda value: value['source_inventory'].pop(),
            lambda value: value['source_inventory'].append(value['source_inventory'][0]),
            lambda value: value['source_inventory'][0].__setitem__('sha256', '0' * 64)]
        original = copy.deepcopy(self.config)
        for mutate in mutations:
            self.config = copy.deepcopy(original); mutate(self.config); self.write_config()
            with patch.object(h, 'import_source') as imported, self.assertRaises(h.HarnessError):
                h.load_modules(self.root)
            imported.assert_not_called()
    def test_import_uses_same_checked_source_bytes_and_ignores_forged_unchecked_pyc(self):
        source = self.root / 'source.py'
        source.write_text('VALUE="forged-cache"\n')
        py_compile.compile(str(source), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        source.write_text('VALUE="verified-source"\n')
        expected = sha(source.read_bytes())
        module = h.import_source(source, '_v0115_bytecache_control', expected)
        self.assertEqual(module.VALUE, 'verified-source')
        with self.assertRaises(h.HarnessError):
            h.import_source(source, '_v0115_wrong_pin_control', '0' * 64)
    def test_every_harness_field_is_mandatory_and_source_snapshots_cannot_change(self):
        receipt = self.fixture(); h.validate_harness(receipt, self.root)
        for key in receipt['execution_harness']:
            changed = copy.deepcopy(receipt); changed['execution_harness'].pop(key)
            with self.subTest(missing=key), self.assertRaises(h.HarnessError):
                h.validate_harness(changed, self.root)
        changed = copy.deepcopy(receipt); changed['execution_harness']['source_inputs_after'][h.OWNER] = '0' * 64
        with self.assertRaises(h.HarnessError): h.validate_harness(changed, self.root)
        changed = copy.deepcopy(receipt); changed['execution_harness']['actual_owned_runs'] = True
        with self.assertRaises(h.HarnessError): h.validate_harness(changed, self.root)
    def test_all_thirty_five_runs_need_individual_typed_ownership(self):
        for windows in (False, True):
            receipt = self.fixture(windows); h.validate_harness(receipt, self.root)
            for case_index in range(5):
                for control in (None, *map(str, range(6))):
                    changed = copy.deepcopy(receipt)
                    case = changed['cases'][case_index]
                    execution = case if control is None else case['negative_controls'][control]
                    execution.pop('process_ownership')
                    with self.subTest(windows=windows, case=case_index, control=control), self.assertRaises(h.HarnessError):
                        h.validate_harness(changed, self.root)
    def test_windows_ownership_claims_types_and_descendant_accounting_are_closed(self):
        original = ownership(True); h.validate_ownership(original, True)
        for key in original:
            changed = copy.deepcopy(original); changed.pop(key)
            with self.subTest(key=key), self.assertRaises(h.HarnessError): h.validate_ownership(changed, True)
        for path, value in ((('owned_before_execution',), 1), (('job_handle_inherited',), True),
            (('resume_prior_suspend_count',), True), (('accounting', 'total_processes'), 0),
            (('accounting', 'active_processes'), 1), (('accounting', 'terminated_processes'), 1),
            (('accounting', 'active_processes'), False)):
            changed = copy.deepcopy(original); target = changed
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(h.HarnessError): h.validate_ownership(changed, True)
    def test_legacy_summary_without_new_execution_harness_cannot_pass(self):
        receipt = self.fixture(); receipt.pop('execution_harness')
        with self.assertRaises(h.HarnessError): h.validate_harness(receipt, self.root)
    def test_execution_replaces_only_historical_process_callback(self):
        # Synthetic routing boundary only, never an actual proof receipt.
        receipt = self.fixture(windows=os.name == 'nt'); observed = []
        historical = types.SimpleNamespace(ROOT=None, run_command=object())
        owner = types.SimpleNamespace(run_command=object())
        def execute(args):
            observed.append(historical.run_command is owner.run_command)
            return copy.deepcopy(receipt)
        historical.execute = execute
        args = types.SimpleNamespace(output=self.root / 'output'); args.output.mkdir()
        config, pins = h.frozen_sources(self.root)
        with patch.object(h, 'load_modules', return_value=(historical, owner, config, pins)):
            value = h.execute(args, self.root)
        self.assertEqual(observed, [True])
        self.assertEqual(value['execution_harness']['source_pins'], pins)


if __name__ == '__main__':
    unittest.main()
