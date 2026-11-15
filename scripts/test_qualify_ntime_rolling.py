#!/usr/bin/env python3
"""Runner/parser controls only; synthetic outputs never qualify a candidate."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_ntime_runner_controls', ROOT / 'scripts/qualify_ntime_rolling.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def rust_output(name='native::fixture', *, passed=1, failed=0, ignored=0, measured=0):
    return ('test ' + name + ' ... ok\n\ntest result: ok. ' + str(passed)
            + ' passed; ' + str(failed) + ' failed; ' + str(ignored) + ' ignored; '
            + str(measured) + ' measured; 100 filtered out; finished in 0.01s\n').encode()


class RunnerControls(unittest.TestCase):
    def test_exact_parser_requires_one_named_nonignored_executed_test(self):
        for raw in (rust_output(), rust_output().replace(b'\n', b'\r\n')):
            self.assertEqual(p.exact_test_output(raw, 'native::fixture'),
                             {'passed': 1, 'failed': 0, 'ignored': 0, 'measured': 0})
        rejected = (b'', rust_output(passed=0), rust_output(passed=2),
                    rust_output(failed=1), rust_output(ignored=1), rust_output(measured=1),
                    rust_output('native::different'), rust_output() + rust_output(),
                    rust_output().replace(b'test native::fixture ... ok\n', b''),
                    rust_output() + b'test other ... ignored\n',
                    rust_output() + b'test other ... FAILED\n',
                    rust_output() + b'test result: FAILED. 0 passed; 1 failed\n')
        for raw in rejected:
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                p.exact_test_output(raw, 'native::fixture')

    def test_adapter_parser_requires_exact_positive_count_without_skips(self):
        raw = b'.\nRan 59 tests in 0.01s\n\nOK\n'
        for accepted in (raw, raw.replace(b'\n', b'\r\n')):
            self.assertEqual(p.unittest_output(accepted)['passed'], 59)
        for rejected in (b'', raw.replace(b'59', b'0'), raw.replace(b'59', b'58'),
                         raw.replace(b'OK', b'OK (skipped=1)'),
                         raw.replace(b'OK', b'FAILED (errors=1)'),
                         raw + b'FAILED (failures=1)\n', raw + raw,
                         raw + b'FAIL: case\n', raw + b'ERROR: case\n'):
            with self.subTest(raw=rejected), self.assertRaises(RuntimeError):
                p.unittest_output(rejected)
        for count in (0, -1, True, None):
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                p.unittest_output(raw, count)

    def test_fixed_suite_inventory_and_nonempty_counts(self):
        expected = {'ntime': 11, 'asert': 8, 'treasury': 14, 'adapter': 1, 'sync': 4}
        for suite, count in expected.items():
            with self.subTest(suite=suite):
                plan = p.suite_plan(suite)
                self.assertEqual(len(plan), count)
                self.assertEqual(len({tuple(row['argv']) for row in plan}), count)
                for row in plan:
                    if row['argv'][:2] == ['cargo', 'test']:
                        self.assertIn('--locked', row['argv'])
                        self.assertIn('--release', row['argv'])
                        self.assertIn('--no-default-features', row['argv'])
                        self.assertIn('--exact', row['argv'])
                        self.assertIn('--lib', row['argv'])
                        self.assertIn(row['exact_name'], row['argv'])
                    elif suite == 'adapter':
                        self.assertEqual(row['adapter_count'], 59)
                        self.assertEqual(row['argv'], [sys.executable, '-I', '-B', 'scripts/test_bitcoin_asic_stratum.py'])
                    else:
                        self.assertEqual(row['argv'], ['cargo', 'check', '--locked', '-p', 'consensus-light-client', '--no-default-features'])
        with self.assertRaises(RuntimeError):
            p.suite_plan('unreviewed-suite')

    def test_native_executions_share_one_exact_rehearsal_feature_build(self):
        for suite in p.CHECKS:
            for row in p.suite_plan(suite):
                argv = row['argv']
                if '--features' in argv:
                    features = argv[argv.index('--features') + 1].split(',')
                    if 'hegemon-node' in argv:
                        self.assertEqual(','.join(features), p.FEATURES)
                        self.assertIn('asert-rehearsal', features)
                        self.assertIn('combined-upgrade-rehearsal', features)

    def test_inherited_ignored_lifecycle_is_explicitly_selected_once(self):
        selected = [row for row in p.suite_plan('sync') if p.TREASURY_LIFECYCLE_TEST in row['argv']]
        self.assertEqual(len(selected), 1)
        self.assertIn('--ignored', selected[0]['argv'])
        self.assertEqual(selected[0]['exact_name'], p.TREASURY_LIFECYCLE_TEST)
        ignored = [row for suite in p.CHECKS for row in p.suite_plan(suite) if '--ignored' in row['argv']]
        self.assertEqual(ignored, selected)

    def test_current_source_suite_retains_exact_legacy_coverage(self):
        legacy_spec = importlib.util.spec_from_file_location('_ntime_legacy_qualifier_controls', ROOT / 'scripts/qualify_combined_upgrade.py')
        legacy = importlib.util.module_from_spec(legacy_spec)
        legacy_spec.loader.exec_module(legacy)
        selected = {row.get('exact_name') for suite in p.CHECKS for row in p.suite_plan(suite)}
        for test in legacy.TIMESTAMP_TESTS:
            self.assertIn(legacy.TS + test, selected)
        for test in legacy.ASERT_TESTS:
            self.assertIn(legacy.ASERT + test, selected)
        for test in legacy.TREASURY_TESTS:
            self.assertIn(legacy.TREASURY + test, selected)
        self.assertIn(legacy.LIFECYCLE, selected)

    def test_failed_execution_stops_the_suite_immediately(self):
        with patch.object(p, 'run_command', side_effect=RuntimeError('actual child failed')) as run:
            with self.assertRaisesRegex(RuntimeError, 'actual child failed'):
                p.local_suite('ntime', Path('/unused'))
        self.assertEqual(run.call_count, 1)

    def test_raw_crlf_log_and_hash_are_retained(self):
        raw = rust_output().replace(b'\n', b'\r\n')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = Mock(returncode=0, communicate=Mock(return_value=(raw, b'')))
            with patch.object(p, 'ROOT', base), patch.object(p.subprocess, 'Popen', return_value=child) as popen:
                result = p.run_command(['parser-fixture-control-only'], base, exact_name='native::fixture')
            log = base / result['log']
            self.assertEqual(log.read_bytes(), raw)
            self.assertEqual(result['log_sha256'], p.digest(log))
            self.assertEqual(result['tests_passed'], 1)
            self.assertEqual(result['test_counts']['passed'], 1)
            self.assertIs(result['processes_reaped'], True)
            self.assertIs(result['process_reaped'], True)
            self.assertEqual(result['command_kind'], 'rust-test')
            self.assertNotIn('shell', popen.call_args.kwargs)

    def test_spawn_environment_strips_simulation_and_network_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = Mock(returncode=0, communicate=Mock(return_value=(b'', b'')))
            with patch.object(p, 'ROOT', base), patch.dict(p.os.environ, {'HEGEMON_MINE': '1', 'HEGEMON_TEST_HOOK': 'fixture'}), \
                    patch.object(p.subprocess, 'Popen', return_value=child) as popen:
                p.run_command(['cargo', 'check'], base)
            environment = popen.call_args.kwargs['env']
            self.assertFalse(any(key.startswith('HEGEMON_') for key in environment))
            self.assertEqual(environment['CARGO_TERM_COLOR'], 'never')
            self.assertEqual(environment['CARGO_INCREMENTAL'], '0')

    def test_timeout_kills_owned_group_reaps_and_retains_log(self):
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            timeout = subprocess.TimeoutExpired(['fixture-control-only'], 1)
            child = Mock(pid=777, returncode=-9)
            child.communicate.side_effect = [timeout, (b'partial stdout', b'partial stderr')]
            with patch.object(p, 'ROOT', base), patch.object(p.subprocess, 'Popen', return_value=child), \
                    patch.object(p, 'kill_owned_process_group') as cleanup:
                with self.assertRaises(subprocess.TimeoutExpired):
                    p.run_command(['fixture-control-only'], base, timeout=1)
            cleanup.assert_called_once_with(child)
            self.assertEqual(child.communicate.call_args.kwargs['timeout'], 30)
            self.assertEqual((base / 'command-000.log').read_bytes(), b'partial stdoutpartial stderr')
        self.assertEqual({signum: signal.getsignal(signum) for signum in previous}, previous)

    def test_windows_control_break_handler_is_registered_and_restored(self):
        handlers = {signal.SIGTERM: object(), signal.SIGINT: object(), 9876: object()}
        with patch.object(p.signal, 'SIGBREAK', 9876, create=True), \
                patch.object(p.signal, 'getsignal', side_effect=handlers.__getitem__), \
                patch.object(p.signal, 'signal') as register:
            with p.interruption_handlers():
                installed = register.call_args_list[:]
                self.assertEqual([row.args[0] for row in installed], [signal.SIGTERM, signal.SIGINT, 9876])
                self.assertTrue(all(callable(row.args[1]) for row in installed))
            self.assertEqual([row.args for row in register.call_args_list[3:]], list(handlers.items()))

    @unittest.skipUnless(os.name == 'posix', 'POSIX signal and process-group cleanup control')
    def test_outer_termination_reaps_a_real_owned_python_child(self):
        # This is a bounded runner cleanup control, not a candidate suite or an
        # actual-check receipt. It executes no Cargo command or node process.
        code = '''import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("cleanup_control", sys.argv[1])
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner.ROOT = pathlib.Path(sys.argv[2])
child = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); print('child-started', flush=True); time.sleep(60)"
runner.run_command([sys.executable, '-I', '-B', '-c', child, str(runner.ROOT / 'child.pid')], runner.ROOT)
'''
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                helper = subprocess.Popen([sys.executable, '-I', '-B', '-c', code,
                                           str(ROOT / 'scripts/qualify_ntime_rolling.py'), str(base)],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          start_new_session=True)
                child_pid = None
                try:
                    deadline = time.monotonic() + 5
                    pid_file = base / 'child.pid'
                    while not pid_file.exists() and helper.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(pid_file.exists(), 'cleanup-control child did not start')
                    child_pid = int(pid_file.read_text())
                    os.kill(helper.pid, signum)
                    stdout, stderr = helper.communicate(timeout=5)
                    self.assertNotEqual(helper.returncode, 0)
                    self.assertIn(b'qualification interrupted by signal', stderr)
                    self.assertEqual(stdout, b'')
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                    self.assertIn(b'child-started', (base / 'command-000.log').read_bytes())
                finally:
                    if helper.poll() is None:
                        os.killpg(helper.pid, signal.SIGKILL)
                        helper.communicate(timeout=5)
                    if child_pid is not None:
                        try:
                            os.killpg(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_failed_child_retains_bytes_and_bounded_diagnostic(self):
        raw = b'earlier-output\n' + b'x' * 9000 + b'\xff' * 5000 + b'\nactual failure\n'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = Mock(returncode=101, communicate=Mock(return_value=(b'', raw)))
            with patch.object(p, 'ROOT', base), patch.object(p.subprocess, 'Popen', return_value=child):
                with self.assertRaises(RuntimeError) as failed:
                    p.run_command(['fixture-control-only'], base)
            message = str(failed.exception)
            self.assertIn('exit=101', message)
            self.assertIn('actual failure', message)
            self.assertNotIn('earlier-output', message)
            tail = message.split('output tail (4096 bytes):\n', 1)[1]
            self.assertLessEqual(len(tail.encode()), 4096)
            self.assertEqual((base / 'command-000.log').read_bytes(), raw)

    def test_failed_parser_keeps_the_original_log(self):
        raw = rust_output(passed=0)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = Mock(returncode=0, communicate=Mock(return_value=(raw, b'')))
            with patch.object(p, 'ROOT', base), patch.object(p.subprocess, 'Popen', return_value=child):
                with self.assertRaises(RuntimeError):
                    p.run_command(['fixture-control-only'], base, exact_name='native::fixture')
            self.assertEqual((base / 'command-000.log').read_bytes(), raw)

    def test_actual_runner_refuses_unfrozen_or_missing_final_manifest(self):
        for status in ('preparing', 'frozen'):
            gate = Mock(CHECKS=p.CHECKS)
            gate.load_config.return_value = {'status': status}
            with patch.object(p, 'load_gate', return_value=gate), patch.object(p, 'local_suite') as run, \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(p.main(['--suite', 'ntime']), 1)
            self.assertEqual(output.getvalue(), '')
            run.assert_not_called()
            gate.artifact_identity.assert_not_called()

    def test_command_arguments_and_timeout_are_bounded(self):
        for argv, timeout in (([], 1), ([''], 1), (['command'], 0), (['command'], 7201), (['command'], True)):
            with self.subTest(argv=argv, timeout=timeout), self.assertRaises(RuntimeError):
                p.run_command(argv, Path('/unused'), timeout=timeout)


if __name__ == '__main__':
    unittest.main()
