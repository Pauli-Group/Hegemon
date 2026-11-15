#!/usr/bin/env python3
"""Formatting-only controls; these tests grant no software-release authority."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ntime_formatting_tests',
        ROOT / 'scripts/check_ntime_candidate_formatting.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
ACTUAL_GIT = gate.git


class NtimeFormattingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ('scripts/check_qualified_formatting.py', 'config/qualified-formatting-baseline.json'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.predecessor = b'fn inherited( ){ }\n'
        self.receipt = {'scope': 'source-preparation-only',
                        **{name: False for name in gate.source.BOUNDARIES}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.verify = self.stack.enter_context(patch.object(gate.source, 'verify_source', return_value=self.receipt))
        self.git = self.stack.enter_context(patch.object(gate, 'git', side_effect=self.git_bytes))

    def git_bytes(self, root, *args):
        self.assertEqual(root, self.root)
        if args == ('rev-parse', gate.BASELINE_COMMIT + '^{commit}'):
            return (gate.BASELINE_COMMIT + '\n').encode()
        if args == ('merge-base', '--is-ancestor', gate.BASELINE_COMMIT, 'HEAD'):
            return b''
        self.assertEqual(args[0], 'show')
        self.assertTrue(args[1].startswith(gate.BASELINE_COMMIT + ':'))
        return self.predecessor

    def debt(self, name, data=None):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.predecessor if data is None else data)

    def test_exact_existing_debt_passes_and_migrations_are_disabled(self):
        old, inherited = gate.policy(self.root)
        self.assertEqual(len(inherited), 38)
        self.verify.assert_called_once_with(self.root)
        self.assertEqual(old.REVIEWED_SOURCE_MIGRATIONS, [])
        self.assertIsNone(old.VERSION_DISPLAY_MIGRATION['path'])
        self.debt('node/src/native/node_impl.rs')
        old.verify_failures(self.root, {'node/src/native/node_impl.rs'}, inherited)
        self.assertEqual(inherited['node/src/native/node_impl.rs'], hashlib.sha256(self.predecessor).hexdigest())

    def test_modified_predecessor_debt_rejects(self):
        old, inherited = gate.policy(self.root)
        self.debt('node/src/native/node_impl.rs', b'fn modified( ){ }\n')
        with self.assertRaisesRegex(old.Rejected, 'changed file must pass formatting'):
            old.verify_failures(self.root, {'node/src/native/node_impl.rs'}, inherited)

    def test_new_debt_rejects(self):
        old, inherited = gate.policy(self.root)
        self.debt('node/src/native/new_unformatted.rs')
        with self.assertRaisesRegex(old.Rejected, 'new formatting debt'):
            old.verify_failures(self.root, {'node/src/native/new_unformatted.rs'}, inherited)

    def test_formatted_changed_file_needs_no_exception(self):
        old, inherited = gate.policy(self.root)
        self.debt('node/src/native/node_impl.rs', b'fn modified() {}\n')
        old.verify_failures(self.root, old.parse_failure(self.root, 0, '', ''), inherited)

    def test_source_gate_authority_true_rejects(self):
        for name in gate.source.BOUNDARIES:
            self.receipt[name] = True
            with self.subTest(name=name), self.assertRaisesRegex(gate.source.SourceError, 'cannot grant'):
                gate.policy(self.root)
            self.receipt[name] = False

    def test_missing_baseline_commit_rejects(self):
        self.git.side_effect = gate.source.SourceError('immutable formatting baseline unavailable')
        with self.assertRaisesRegex(gate.source.SourceError, 'baseline unavailable'):
            gate.policy(self.root)

    def test_nonancestor_baseline_rejects(self):
        def not_ancestor(root, *args):
            if args[0] == 'merge-base':
                raise gate.source.SourceError('immutable formatting baseline not an ancestor')
            return self.git_bytes(root, *args)
        self.git.side_effect = not_ancestor
        with self.assertRaisesRegex(gate.source.SourceError, 'not an ancestor'):
            gate.policy(self.root)

    def test_missing_or_changed_original_baseline_rejects(self):
        path = self.root / 'config/qualified-formatting-baseline.json'
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'baseline source pin differs'):
            gate.policy(self.root)
        path.unlink()
        with self.assertRaises(OSError):
            gate.policy(self.root)

    def test_failed_git_command_is_not_an_empty_ancestor_or_empty_blob(self):
        with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'unknown revision')):
            with self.assertRaisesRegex(gate.source.SourceError, 'baseline unavailable'):
                ACTUAL_GIT(self.root, 'rev-parse', gate.BASELINE_COMMIT + '^{commit}')


if __name__ == '__main__':
    unittest.main()
