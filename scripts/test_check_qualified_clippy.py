#!/usr/bin/env python3
"""Negative controls for the exact two qualified padding-lint exceptions."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
SPEC = importlib.util.spec_from_file_location('qualified_clippy', Path(__file__).with_name('check_qualified_clippy.py'))
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)

class ClippyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = gate.ROOT.resolve()
        self.sources = gate.pinned_sources(self.root)
    def diagnostic(self, relative=None):
        relative = relative or next(iter(gate.EXCEPTIONS))
        row = gate.EXCEPTIONS[relative]
        span = {'file_name': relative, 'is_primary': True, 'expansion': None,
                'line_start': row['line'], 'line_end': row['line'],
                **{key: row[key] for key in ('column_start', 'column_end', 'byte_start', 'byte_end')}}
        return {'level': 'warning', 'code': {'code': gate.LINT}, 'spans': [span], 'children': []}
    def test_exact_two_hash_pinned_spans_pass(self):
        for relative in gate.EXCEPTIONS:
            gate.inspect_message(self.root, self.diagnostic(relative), self.sources)
    def test_each_shifted_or_boolean_span_rejects(self):
        for key in ('line_start', 'line_end', 'column_start', 'column_end', 'byte_start', 'byte_end'):
            for value in (True, self.diagnostic()['spans'][0][key] + 1):
                d = self.diagnostic(); d['spans'][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(gate.Rejected):
                    gate.inspect_message(self.root, d, self.sources)
    def test_new_path_macro_or_multiple_primary_rejects(self):
        for change in ({'file_name': '/outside.rs'}, {'file_name': 'new.rs'}, {'expansion': {}}, {'is_primary': False}):
            d = self.diagnostic(); d['spans'][0].update(change)
            with self.subTest(change=change), self.assertRaises(gate.Rejected):
                gate.inspect_message(self.root, d, self.sources)
        d = self.diagnostic(); d['spans'].append(copy.deepcopy(d['spans'][0]))
        with self.assertRaises(gate.Rejected): gate.inspect_message(self.root, d, self.sources)
    def test_changed_source_bytes_reject_even_without_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, raw in self.sources.items():
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            gate.pinned_sources(root)
            (root / next(iter(gate.EXCEPTIONS))).write_bytes(next(iter(self.sources.values())) + b'\n')
            with self.assertRaises(gate.Rejected): gate.pinned_sources(root)
    def test_other_errors_and_child_empty_ranges_reject(self):
        for level in ('error', 'ice', 'failure-note'):
            with self.subTest(level=level), self.assertRaises(gate.Rejected):
                gate.inspect_message(self.root, {'level': level}, self.sources)
        d = self.diagnostic(); d['children'] = [dict(self.diagnostic(), spans=[])]
        with self.assertRaises(gate.Rejected): gate.inspect_message(self.root, d, self.sources)
        d = self.diagnostic(); d['level'] = 'error'
        with self.assertRaises(gate.Rejected): gate.inspect_message(self.root, d, self.sources)
    def test_other_warning_remains_visible_and_nonblocking(self):
        gate.inspect_message(self.root, {'level': 'warning', 'code': {'code': 'unused_imports'}}, self.sources)
    def test_only_specific_lint_is_warn_with_other_deny_flags_preserved(self):
        command = gate.cargo_command(['-p', 'transaction-circuit', '--all-targets'])
        self.assertEqual(command[:3], ['cargo', 'clippy', '--message-format=json'])
        self.assertEqual(command[-10:], gate.DENY + ['-W', gate.LINT])
        for args in ([], ['-p', 'x'], ['-p', 'x', '--all-targets', '--', '-A', 'warnings'], ['-p', 'x', '--all-targets', '--message-format=human'], ['--all-targets']):
            with self.subTest(args=args), self.assertRaises(gate.Rejected): gate.cargo_command(args)
    def fake_run(self, rows, code):
        process = unittest.mock.MagicMock()
        process.__enter__.return_value = process
        process.stdout = io.BytesIO(b''.join((json.dumps(row) + '\n').encode() for row in rows))
        process.wait.return_value = code
        with patch.object(gate.subprocess, 'Popen', return_value=process):
            return gate.run(self.root, ['-p', 'transaction-circuit', '--all-targets'])
    def test_nonzero_cargo_status_is_preserved(self):
        self.assertEqual(self.fake_run([], 101), 101)
    def test_new_range_rejects_even_if_cargo_returns_zero(self):
        d = self.diagnostic(); d['spans'][0]['line_start'] += 1
        self.assertEqual(self.fake_run([{'reason': 'compiler-message', 'message': d}], 0), 1)
    def test_failed_build_and_unknown_json_reject_even_with_zero_status(self):
        for row in ({'reason': 'build-finished', 'success': False}, {'reason': 'unknown'}):
            with self.subTest(row=row): self.assertEqual(self.fake_run([row], 0), 1)
    def test_missing_or_duplicate_completion_rejects(self):
        self.assertEqual(self.fake_run([], 0), 1)
        complete = {'reason': 'build-finished', 'success': True}
        self.assertEqual(self.fake_run([complete, complete], 0), 1)
    def test_existing_package_sets_and_all_targets_are_preserved(self):
        import re, shlex
        text = (self.root / 'scripts/check-core.sh').read_text()
        matches = re.findall(r'python3 -I -B scripts/check_qualified_clippy.py (.*?--all-targets)', text, re.S)
        self.assertEqual(len(matches), 2)
        expected = [
            ['hegemon-node', 'protocol-kernel', 'protocol-shielded-pool', 'wallet', 'network', 'consensus', 'consensus-light-client', 'synthetic-crypto', 'transaction-circuit', 'block-circuit', 'cashvm-bridge'],
            ['superneo-backend-lattice', 'superneo-hegemon', 'superneo-bench', 'native-backend-ref', 'native-backend-timing']]
        for source, packages in zip(matches, expected):
            args = shlex.split(source.replace(chr(92) + chr(10), ' '))
            self.assertEqual(args, [part for name in packages for part in ('-p', name)] + ['--all-targets'])
            gate.cargo_command(args)
    def test_all_exact_diagnostics_and_success_pass(self):
        rows = [{'reason': 'compiler-message', 'message': self.diagnostic(p)} for p in gate.EXCEPTIONS]
        self.assertEqual(self.fake_run(rows + [{'reason': 'build-finished', 'success': True}], 0), 0)

if __name__ == '__main__':
    unittest.main()
