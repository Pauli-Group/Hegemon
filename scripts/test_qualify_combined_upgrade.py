#!/usr/bin/env python3
"""Producer mutation controls. Synthetic fixtures grant no qualification."""
import copy
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('producer', Path(__file__).with_name('qualify_combined_upgrade.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProducerTests(unittest.TestCase):
    def test_unittest_crlf_success_and_nonexact_or_failed_results(self):
        p.unittest_output(b'.\r\n----------------------------------------------------------------------\r\nRan 1 test in 0.01s\r\n\r\nOK\r\n')
        p.unittest_output(b'.\nRan 1 test in 0.01s\n\nOK\n')
        for raw in (b'Ran 0 tests in 0.01s\r\nOK\r\n',
                    b'Ran 2 tests in 0.01s\r\nOK\r\n',
                    b'Ran 1 test in 0.01s\r\nFAILED (failures=1)\r\n',
                    b'Ran 1 test in 0.01s\r\nOK (skipped=1)\r\n',
                    b'Ran 1 test in 0.01s\r\nOK\r\nFAILED (errors=1)\r\n'):
            with self.subTest(raw=raw),self.assertRaises(RuntimeError):p.unittest_output(raw)

    def test_crlf_parser_preserves_raw_command_log_and_hash(self):
        raw=b'.\r\nRan 1 test in 0.01s\r\n\r\nOK\r\n'
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            with patch.object(p,'ROOT',base),patch.object(p.subprocess,'Popen') as popen:
                process=popen.return_value;process.returncode=0;process.communicate.return_value=(b'',raw)
                result=p.run_command(['synthetic-unittest-output-only'],base,unittest=True)
            log=base/result['log']
            self.assertEqual(log.read_bytes(),raw)
            self.assertEqual(result['log_sha256'],p.gate.sha(raw))

    def test_exact_test_must_execute_once_without_ignored(self):
        p.exact_test_output(b'test x ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 7 filtered out\n')
        p.exact_test_output(b'test x ... ok\r\ntest result: ok. 1 passed; 0 failed; 0 ignored; 7 filtered out\r\n')
        for raw in (b'test result: ok. 0 passed; 0 failed; 0 ignored;',
                    b'test result: ok. 0 passed; 0 failed; 1 ignored;',
                    b'test result: ok. 2 passed; 0 failed; 0 ignored;',
                    b'test result: ok. 1 passed; 0 failed; 0 ignored;\ntest result: ok. 1 passed; 0 failed; 0 ignored;'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                p.exact_test_output(raw)

    def test_ignored_lifecycle_is_explicit_and_exact(self):
        with patch.object(p, 'run_command', return_value={}) as run:
            p.rust_test('hegemon-node', p.LIFECYCLE, Path('/unused'), True, p.FEATURES)
        argv = run.call_args.args[0]
        self.assertIn('--ignored', argv)
        self.assertIn('--exact', argv)
        self.assertIn('--locked', argv)
        self.assertEqual(argv[argv.index('--features') + 1], p.FEATURES)
        self.assertTrue(run.call_args.kwargs['exact'])

    def test_focused_native_failure_is_not_pass_ingestion(self):
        with patch.object(p, 'rust_test', side_effect=RuntimeError('actual child failed')) as run:
            with self.assertRaisesRegex(RuntimeError, 'actual child failed'):
                p.local_suites('timestamp_admission', Path('/unused'))
        self.assertEqual(run.call_count, 1)

    def test_missing_runtime_does_not_receive_htlc_credit(self):
        with patch.object(p, 'rust_test', return_value={}):
            done, commands = p.local_suites('current_smzl_htlc', Path('/unused'))
        self.assertFalse(done)
        self.assertEqual(len(commands), 3)
        with self.assertRaises(RuntimeError):
            p.runtime_gates({'gates': {}}, Path('/unused'))

    def test_packed_witness_is_not_counted_as_actual_treasury_proof(self):
        with patch.object(p, 'rust_test', return_value={}):
            done, commands = p.local_suites('treasury_cadence', Path('/unused'))
        self.assertTrue(commands)
        self.assertNotIn('unchanged_relation_spend', done)

    def test_adapter_gates_run_individually_selected_tests(self):
        with patch.object(p, 'run_command', return_value={}) as run:
            done, _ = p.local_suites('version_rolling', Path('/unused'))
        self.assertEqual(run.call_count, len(p.VERSION_TESTS))
        self.assertEqual({r.args[0][-1] for r in run.call_args_list}, set(p.VERSION_TESTS))
        self.assertNotIn('nonzero_rolled_block', done)
        self.assertNotIn('independent_import', done)

    def test_transcript_content_must_match_pinned_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / 'observations.json'
            value = {'before': {'height': 120}, 'after': {'height': 123}}
            path.write_text(json.dumps(value))
            value['transcript'] = {'path': path.name, 'sha256': p.digest(path)}
            p.checked_transcript(base, value)
            value['after']['height'] = 124
            with self.assertRaises(RuntimeError):
                p.checked_transcript(base, value)

    def fixture(self, base):
        records = [{'path': 'example.rs', 'bytes': 1, 'sha256': 'a' * 64, 'mode': '100644'}]
        solver='scripts/combined_upgrade_acceptance/exact80_solver.rs'
        records.append({**p.gate.row(p.ROOT,solver),'mode':'100644'})
        inv = base / 'inventory.json'
        inv.write_text(json.dumps(records))
        source_sha = p.gate.sha(p.gate.canonical(records))
        value = {'schema': 'hegemon.combined-upgrade.actual-process-acceptance.v1',
            'status': 'PASS_LOCAL_COMBINED_CANDIDATE', 'completed': True,
            'production_authorized': False, 'deployment_verified': False,
            'all_owned_reaped': True, 'all_owned_exit0': True, 'rpc_closed': True,
            'harness': {'run_combined.py': 'b' * 64, 'combined_io.py': 'c' * 64,'exact80_solver.rs':records[1]['sha256']},
            'actual_invocation': ['python3', 'run_combined.py', '--node-binary', '/nonexistent/synthetic-node', '--private-spend-binary', '/nonexistent/synthetic-wallet', '--out', '/synthetic'],
            'rehearsal_features': {'hegemon-node': ['development-candidate', 'combined-upgrade-rehearsal'],
                'private-spend': ['rpc-client', 'private-spend-dev-artifacts'],
                'metadata_kind': 'declared build features; runtime activation and CLI paths independently checked'},
            'source': {'complete_candidate_inventory': {'canonical_records_sha256': source_sha, 'path': inv.name, 'sha256': p.digest(inv)}},
            'binaries': {'hegemon-node': {'path': '/nonexistent/synthetic-node', 'sha256': 'd' * 64},
                         'private-spend': {'path': '/nonexistent/synthetic-wallet', 'sha256': 'e' * 64}},
            'owned_processes': [{'exit_code': 0, 'forced': False} for _ in range(7)]}
        return value, {'source_inventory': records, 'source_inventory_sha256': source_sha}

    def validate(self, base, value, config):
        path = base / 'receipt.json'
        path.write_text(json.dumps(value))
        return p.runtime_evidence(path, p.digest(path), config, 'b' * 64, 'c' * 64,
            {'hegemon-node': 'd' * 64, 'private-spend': 'e' * 64})

    def test_external_rehearsal_has_separate_reviewed_executable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            value, config = self.fixture(base)
            self.assertEqual(self.validate(base, value, config), value)
            for key in ('harness', 'source', 'binaries', 'rehearsal_features', 'actual_invocation'):
                broken = copy.deepcopy(value)
                broken[key] = {}
                with self.subTest(key=key), self.assertRaises((RuntimeError, KeyError, IndexError)):
                    self.validate(base, broken, config)

    def test_external_posix_argv_is_preserved_on_windows(self):
        class UnavailableWindowsPath(PureWindowsPath):
            def exists(self):
                return False
        def platform_path(value):
            if isinstance(value,str) and value.startswith('/nonexistent/'):
                return UnavailableWindowsPath(value)
            return Path(value)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);value,config=self.fixture(base)
            original=value['actual_invocation'][:]
            recorded=value['binaries']['hegemon-node']['path']
            self.assertNotEqual(str(PureWindowsPath(recorded)),recorded)
            with patch.object(p,'Path',side_effect=platform_path):
                self.assertEqual(self.validate(base,value,config),value)
            self.assertEqual(value['actual_invocation'],original)

    def test_recorded_executable_paths_must_be_nonempty_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);value,config=self.fixture(base)
            for binary in ('hegemon-node','private-spend'):
                for invalid in ('',None,7):
                    broken=copy.deepcopy(value);broken['binaries'][binary]['path']=invalid
                    with self.subTest(binary=binary,invalid=invalid),self.assertRaisesRegex(RuntimeError,'nonempty recorded'):
                        self.validate(base,broken,config)

    def test_runtime_only_and_nonclosed_processes_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            value, config = self.fixture(base)
            for key, replacement in (('completed', False), ('all_owned_reaped', False),
                    ('all_owned_exit0', False), ('production_authorized', True),
                    ('status', 'RUNTIME_ONLY_PASS_PROOFS_NOT_RUN')):
                broken = copy.deepcopy(value)
                broken[key] = replacement
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    self.validate(base, broken, config)

    def test_actual_three_file_harness_requires_exact_frozen_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);value,config=self.fixture(base)
            self.validate(base,value,config)
            for replacement in (None,'0'*64):
                broken=copy.deepcopy(value)
                if replacement is None:
                    del broken['harness']['exact80_solver.rs']
                else:
                    broken['harness']['exact80_solver.rs']=replacement
                with self.subTest(replacement=replacement),self.assertRaises(RuntimeError):self.validate(base,broken,config)
            broken=copy.deepcopy(value);broken['harness']['extra-executable']='f'*64
            with self.assertRaises(RuntimeError):self.validate(base,broken,config)

    def test_changed_inventory_and_unpinned_receipt_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            value, config = self.fixture(base)
            self.validate(base, value, config)
            (base / 'inventory.json').write_text('[]')
            with self.assertRaises(RuntimeError):
                self.validate(base, value, config)
            with self.assertRaises(RuntimeError):
                p.runtime_evidence(base / 'receipt.json', None, config, 'b' * 64, 'c' * 64, {})


if __name__ == '__main__':
    unittest.main()
