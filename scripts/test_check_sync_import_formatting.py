#!/usr/bin/env python3
"""Pure rejection controls for the additive formatting policy; no Cargo calls."""
from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sync_import_formatting', ROOT/'scripts/check_sync_import_formatting.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FormattingSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        for relative in [gate.CONFIG, gate.HISTORICAL_CHECKER, gate.HISTORICAL_BASELINE,
                         gate.NODE_IMPL, *gate.DIRECT_MODULES]:
            target = self.root/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/relative, target)
        self.process_guard = mock.patch.object(gate.subprocess, 'run', side_effect=AssertionError('Cargo must not run in pure controls'))
        self.process_guard.start()
        self.addCleanup(self.process_guard.stop)

    def alter(self, relative):
        with (self.root/relative).open('ab') as f:
            f.write(b'\n')

    def test_exact_node_postimage_keeps_authenticated_predecessor_debt(self):
        baseline = gate.verify_observed_failures(self.root, {gate.NODE_IMPL})
        self.assertEqual(baseline[gate.NODE_IMPL], '05f84c22738c43c937201470a27649a3d73e4b8ce9dfbc87c7d6e95abd462e3c')

    def test_clean_formatting_does_not_need_a_debt_exception(self):
        gate.verify_observed_failures(self.root, set())

    def test_changed_historical_checker_rejects_before_import(self):
        (self.root/gate.HISTORICAL_CHECKER).write_text('raise RuntimeError("must never execute unauthenticated checker")\n')
        with self.assertRaisesRegex(ValueError, 'input pin differs'):
            gate.verify_observed_failures(self.root, set())

    def test_changed_historical_baseline_rejects(self):
        self.alter(gate.HISTORICAL_BASELINE)
        with self.assertRaisesRegex(ValueError, 'input pin differs'):
            gate.verify_observed_failures(self.root, set())

    def test_changed_successor_configuration_rejects(self):
        self.alter(gate.CONFIG)
        with self.assertRaisesRegex(ValueError, 'input pin differs'):
            gate.verify_observed_failures(self.root, set())

    def test_changed_node_postimage_rejects_even_when_formatting_is_clean(self):
        self.alter(gate.NODE_IMPL)
        with self.assertRaisesRegex(ValueError, 'input pin differs'):
            gate.verify_observed_failures(self.root, set())

    def test_new_source_path_cannot_gain_formatting_debt(self):
        extra = 'node/src/native/new_unreviewed_module.rs'
        (self.root/extra).write_text('fn newly_added_debt( ) {}\n')
        with self.assertRaisesRegex(ValueError, 'new formatting debt is not allowed'):
            gate.verify_observed_failures(self.root, {extra})

    def test_other_reviewed_postimage_cannot_change(self):
        extra = 'node/src/native/asset_state.rs'
        (self.root/extra).write_text('unreviewed change\n')
        with self.assertRaisesRegex(ValueError, 'changed unrelated bytes'):
            gate.verify_observed_failures(self.root, {extra})

    def test_original_policy_files_are_not_mutated_by_specialization(self):
        original = {p:(self.root/p).read_bytes() for p in [gate.HISTORICAL_CHECKER, gate.HISTORICAL_BASELINE]}
        old, baseline = gate.load_authorized(self.root)
        self.assertEqual(next(r for r in old.REVIEWED_SOURCE_MIGRATIONS if r['path']==gate.NODE_IMPL)['postimage_sha256'], gate.NODE_IMPL_SHA256)
        # The original loader is untouched: after specializing the tuple, a new
        # historical-load attempt correctly rejects that now-different tuple.
        with self.assertRaisesRegex(ValueError, 'reviewed source migration tuples differ'):
            old.load_baseline(self.root/gate.HISTORICAL_BASELINE)
        for path, raw in original.items():
            self.assertEqual((self.root/path).read_bytes(), raw)
        self.assertEqual(hashlib.sha256(original[gate.HISTORICAL_CHECKER]).hexdigest(), gate.HISTORICAL_CHECKER_SHA256)
        self.assertEqual(hashlib.sha256(original[gate.HISTORICAL_BASELINE]).hexdigest(), gate.HISTORICAL_BASELINE_SHA256)

    def test_changed_included_module_rejects_even_with_clean_cargo_formatting(self):
        self.alter(next(iter(gate.DIRECT_MODULES)))
        with self.assertRaisesRegex(ValueError, 'input pin differs'):
            gate.verify_observed_failures(self.root, set())

    def mocked_formatter_results(self, direct_code=0, direct_stdout='', direct_stderr=''):
        return [subprocess.CompletedProcess([], 0, 'rustfmt 1.8.0-stable (ed61e7d7e2 2025-11-07)\n', ''),
                subprocess.CompletedProcess([], 0, '', ''),
                subprocess.CompletedProcess([], direct_code, direct_stdout, direct_stderr)]

    def run_mocked_workspace(self, results):
        with mock.patch.object(gate.subprocess, 'run', side_effect=results) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                gate.run(self.root, 'workspace')
            return run.call_args_list

    def test_workspace_requires_exact_direct_rustfmt_for_both_included_modules(self):
        calls = self.run_mocked_workspace(self.mocked_formatter_results())
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0].args[0], ['cargo', '+1.91.1', 'fmt', '--version'])
        self.assertEqual(calls[1].args[0], ['cargo', '+1.91.1', 'fmt', '--all', '--', '--check', '--color', 'never'])
        self.assertEqual(calls[2].args[0], ['rustup', 'run', '1.91.1', 'rustfmt', '--check',
                         '--edition', '2021', '--color', 'never',
                         *(str(self.root/p) for p in sorted(gate.DIRECT_MODULES))])
        self.assertEqual(calls[2].kwargs['cwd'], self.root)

    def test_direct_module_formatting_debt_is_not_waived_after_cargo_success(self):
        with self.assertRaisesRegex(ValueError, 'included modules must pass'):
            self.run_mocked_workspace(self.mocked_formatter_results(direct_code=1, direct_stdout='Diff in included module'))

    def test_direct_module_stderr_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'included modules must pass'):
            self.run_mocked_workspace(self.mocked_formatter_results(direct_stderr='unexpected diagnostic'))

    def test_direct_module_unexpected_success_output_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'included modules must pass'):
            self.run_mocked_workspace(self.mocked_formatter_results(direct_stdout='unexpected output'))

    def test_nonworkspace_invocation_keeps_original_manifest_command(self):
        with mock.patch.object(gate.subprocess, 'run', side_effect=self.mocked_formatter_results()[:2]) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                gate.run(self.root, 'htlc')
            self.assertEqual(len(run.call_args_list), 2)
            self.assertEqual(run.call_args_list[1].args[0], ['cargo', '+1.91.1', 'fmt',
                             '--manifest-path', 'experimental/htlc-prototype/Cargo.toml',
                             '--all', '--', '--check', '--color', 'never'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
