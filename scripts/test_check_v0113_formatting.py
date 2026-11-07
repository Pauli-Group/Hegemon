#!/usr/bin/env python3
"""Pure v0.11.3 formatting policy and exact-migration rejection controls."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "v0113_formatting_controls", ROOT / "scripts/check_v0113_formatting.py")
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class V0113FormattingTests(unittest.TestCase):
    def test_real_source_composes_without_replacing_historical_baseline(self):
        old, baseline, direct = checker.load_authorized(ROOT)
        original = checker.load_module(ROOT, 'scripts/check_qualified_formatting.py',
            '_v0113_formatting_test_original',
            'be7732c0e30f9b770ef5395be762ec9ea133d39f7fc52170d17639e2579a71a9')
        original_baseline = original.load_baseline(ROOT / original.BASELINE)
        self.assertEqual(baseline, original_baseline)
        self.assertEqual(set(direct) & set(baseline), set())
        changed = [(before['path'], after['path']) for before, after in
                   zip(original.REVIEWED_SOURCE_MIGRATIONS, old.REVIEWED_SOURCE_MIGRATIONS)
                   if before != after]
        self.assertEqual(changed, [('node/src/native/node_impl.rs', 'node/src/native/node_impl.rs')])
        self.assertIn('node/src/native/public_admission.rs', direct)
        self.assertIn('node/src/native/service/sync_body_backpressure.rs', direct)
        old.verify_failures(ROOT, {'node/src/native/node_impl.rs'}, baseline)
        for name in ('new-unlisted-debt.rs', 'node/src/native/public_admission.rs'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                old.verify_failures(ROOT, {name}, baseline)

    def test_reviewed_node_postimage_mutation_rejects(self):
        old, baseline, _ = checker.load_authorized(ROOT)
        relative = 'node/src/native/node_impl.rs'
        with tempfile.TemporaryDirectory(prefix='v0113-format-node-') as directory:
            scratch = Path(directory).resolve()
            node = scratch / relative
            node.parent.mkdir(parents=True)
            raw = (ROOT / relative).read_bytes()
            node.write_bytes(raw)
            old.verify_failures(scratch, {relative}, baseline)
            node.write_bytes(raw + b'\n// unreviewed bytes\n')
            with self.assertRaises(ValueError):
                old.verify_failures(scratch, {relative}, baseline)

    def migration_fixture(self):
        node = 'node/src/native/node_impl.rs'
        migration = {'path': node, 'qualified_sha256': '1' * 64,
                     'historical_postimage_sha256': '2' * 64,
                     'postimage_sha256': '3' * 64, 'scope': 'retained-debt'}
        row = {'path': node, 'qualified_sha256': '1' * 64,
               'postimage_sha256': '2' * 64, 'scope': 'retained-debt'}
        other = {'path': 'unchanged.rs', 'qualified_sha256': '4' * 64,
                 'postimage_sha256': '5' * 64, 'scope': 'unchanged'}
        old = SimpleNamespace(REVIEWED_SOURCE_MIGRATIONS=[row, other])
        sync = SimpleNamespace(NODE_IMPL=node, NODE_IMPL_SHA256='3' * 64)
        baseline = {node: '1' * 64}
        overlay = {'before_sha256': '3' * 64, 'after_sha256': '6' * 64}
        return old, baseline, sync, {'migration': migration}, overlay

    def test_only_one_existing_migration_is_specialized(self):
        old, baseline, sync, config, overlay = self.migration_fixture()
        before = copy.deepcopy(old.REVIEWED_SOURCE_MIGRATIONS)
        baseline_before = dict(baseline)
        checker.compose_existing_migration(old, baseline, sync, config, overlay)
        expected = copy.deepcopy(before)
        expected[0]['postimage_sha256'] = '6' * 64
        self.assertEqual(old.REVIEWED_SOURCE_MIGRATIONS, expected)
        self.assertEqual(baseline, baseline_before)

    def test_wrong_predecessor_baseline_scope_or_nonunique_row_rejects(self):
        def bad_predecessor(args): args[4]['before_sha256'] = '0' * 64
        def bad_postimage(args): args[4]['after_sha256'] = 'not-a-digest'
        def bad_baseline(args): args[1][args[2].NODE_IMPL] = '0' * 64
        def bad_scope(args): args[0].REVIEWED_SOURCE_MIGRATIONS[0]['scope'] = 'expanded'
        def bad_old_postimage(args): args[0].REVIEWED_SOURCE_MIGRATIONS[0]['postimage_sha256'] = '0' * 64
        def bad_sync_pin(args): args[3]['migration']['postimage_sha256'] = '0' * 64
        def duplicate(args): args[0].REVIEWED_SOURCE_MIGRATIONS.append(dict(args[0].REVIEWED_SOURCE_MIGRATIONS[0]))
        def missing(args): args[0].REVIEWED_SOURCE_MIGRATIONS.pop(0)
        for mutate in (bad_predecessor, bad_postimage, bad_baseline, bad_scope,
                       bad_old_postimage, bad_sync_pin, duplicate, missing):
            args = self.migration_fixture()
            mutate(args)
            with self.subTest(mutation=mutate.__name__), self.assertRaises(ValueError):
                checker.compose_existing_migration(*args)

    def test_historical_helper_must_authenticate_before_import(self):
        with tempfile.TemporaryDirectory(prefix='v0113-format-authority-') as directory:
            scratch = Path(directory).resolve()
            path = scratch / checker.SYNC_FORMATTING
            path.parent.mkdir()
            raw = (ROOT / checker.SYNC_FORMATTING).read_bytes()
            path.write_bytes(raw + b'\nraise RuntimeError("unreviewed import executed")\n')
            with self.assertRaisesRegex(ValueError, 'historical formatting authority differs'):
                checker.load_module(scratch, checker.SYNC_FORMATTING, '_unreviewed_formatting',
                                    checker.SYNC_FORMATTING_SHA256)

    def test_manifest_and_direct_checks_keep_original_commands_and_reauthenticate(self):
        for manifest in checker.MANIFESTS:
            with self.subTest(manifest=manifest):
                old = SimpleNamespace(RUSTFMT_VERSION='pinned-rustfmt',
                                      parse_failure=mock.Mock(return_value=set()),
                                      verify_failures=mock.Mock())
                results = [SimpleNamespace(returncode=0, stdout='pinned-rustfmt\n', stderr=''),
                           SimpleNamespace(returncode=0, stdout='', stderr='')]
                if manifest == 'workspace':
                    results.append(SimpleNamespace(returncode=0, stdout='', stderr=''))
                with mock.patch.object(checker, 'load_authorized',
                        return_value=(old, {}, {'new-module.rs': 'a' * 64})) as load, \
                     mock.patch.object(checker.subprocess, 'run', side_effect=results) as run, \
                     mock.patch('builtins.print'):
                    checker.run(ROOT, manifest)
                self.assertEqual(load.call_count, 2)
                self.assertEqual(run.call_args_list[0].args[0], ['cargo', '+1.91.1', 'fmt', '--version'])
                expected = ['cargo', '+1.91.1', 'fmt']
                if checker.MANIFESTS[manifest]:
                    expected += ['--manifest-path', checker.MANIFESTS[manifest]]
                self.assertEqual(run.call_args_list[1].args[0], expected + ['--all', '--', '--check', '--color', 'never'])
                if manifest == 'workspace':
                    self.assertEqual(run.call_args_list[2].args[0],
                        ['rustup', 'run', '1.91.1', 'rustfmt', '--check', '--edition',
                         '2021', '--color', 'never', str(ROOT / 'new-module.rs')])
                old.verify_failures.assert_called_once_with(ROOT, set(), {})


if __name__ == '__main__':
    unittest.main()
