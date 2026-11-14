#!/usr/bin/env python3
"""Policy controls plus mandatory real Windows job ownership regressions.

--require-windows fails on other hosts; Windows CI cannot pass by skipping the
native cases. Synthetic kernel tests are policy tests, not Windows evidence.
"""
from __future__ import annotations
import ctypes as c
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_v0115_owned_process_tests', ROOT / 'scripts/v0115_process_ownership.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
THIS = Path(__file__).resolve()


class FakeKernel:
    """Explicit synthetic policy model; never used by the proof executor."""
    def __init__(self, fail=None, member=True, resume=1, exit_code=0):
        self.fail = fail; self.member = member; self.resume_count = resume; self.code = exit_code
        self.events = []; self.closed = []; self.killed = False; self.process_open = False
    def step(self, name):
        self.events.append(name)
        if name == self.fail:
            raise p.OwnershipError(name + ' failed; Win32 GetLastError=5: synthetic policy control')
    def create_job(self): self.step('create_job'); return 10
    def configure_job(self, job): self.step('configure_job'); assert job == 10
    def create_suspended(self, argv, cwd, env, stdio, job, information=None):
        self.step('create_suspended'); assert job == 10 and stdio == (1, 2, 3)
        self.process_open = True
        if information is not None:
            information.hProcess, information.hThread, information.dwProcessId = 20, 30, 40
        return 20, 30, 40
    def in_job(self, process, job): self.step('in_job'); assert (process, job) == (20, 10); return self.member
    def resume(self, thread): self.step('resume'); assert thread == 30; return self.resume_count
    def close(self, handle):
        self.step('close_' + str(handle)); self.closed.append(handle)
        if handle == 20: self.process_open = False
    def wait(self, process, ms): self.step('wait'); return True
    def exit_code(self, process): self.step('exit_code'); return self.code
    def accounting(self, job):
        self.step('accounting')
        return {'total_processes': 1, 'active_processes': int(self.process_open), 'terminated_processes': int(self.killed)}
    def terminate_job(self, job): self.step('terminate_job'); self.killed = True
    def terminate_process(self, process): self.step('terminate_process')


class PortableControls(unittest.TestCase):
    def invocation(self): return [sys.executable, '-c', 'pass'], Path.cwd(), {'A': 'b'}, (1, 2, 3)
    def test_exact_member_checked_before_one_resume_then_references_close_before_accounting(self):
        kernel = FakeKernel(); process = p.WindowsProcess(*self.invocation(), kernel=kernel)
        self.assertLess(kernel.events.index('in_job'), kernel.events.index('resume'))
        self.assertEqual(process.poll(), 0)
        self.assertEqual(process.finish(time.monotonic() + 2)['active_processes'], 0)
        self.assertLess(kernel.events.index('close_20'), kernel.events.index('accounting'))
        process.close(); self.assertEqual(sorted(kernel.closed), [10, 20, 30])
    def test_failed_containment_never_resumes_and_closes_all_handles(self):
        for failure, member in (('configure_job', True), ('create_suspended', True), ('in_job', True), (None, False)):
            kernel = FakeKernel(fail=failure, member=member)
            with self.subTest(failure=failure, member=member), self.assertRaises(p.OwnershipError):
                p.WindowsProcess(*self.invocation(), kernel=kernel)
            self.assertNotIn('resume', kernel.events)
            self.assertIn('close_10', kernel.events)
            if 'in_job' in kernel.events:
                self.assertEqual(sorted(kernel.closed), [10, 20, 30])
    def test_failed_resume_and_nonexact_suspend_count_never_pass(self):
        for failure, count in (('resume', 1), (None, 0), (None, 2), (None, 0xFFFFFFFF)):
            kernel = FakeKernel(fail=failure, resume=count)
            with self.subTest(failure=failure, count=count), self.assertRaises(p.OwnershipError):
                p.WindowsProcess(*self.invocation(), kernel=kernel)
            self.assertTrue(kernel.killed)
            self.assertEqual(sorted(kernel.closed), [10, 20, 30])
    def test_cleanup_error_preserves_original_win32_diagnostic(self):
        kernel = FakeKernel(fail='in_job')
        def fail_cleanup(job): raise p.OwnershipError('TerminateJobObject failed; Win32 GetLastError=6')
        kernel.terminate_job = fail_cleanup
        with self.assertRaisesRegex(p.OwnershipError, 'in_job failed; Win32 GetLastError=5.*GetLastError=6'):
            p.WindowsProcess(*self.invocation(), kernel=kernel)
    def test_exited_code_259_is_not_treated_as_running(self):
        kernel = FakeKernel(exit_code=259); process = p.WindowsProcess(*self.invocation(), kernel=kernel)
        self.assertEqual(process.poll(), 259); process.finish(time.monotonic() + 2); process.close()
    def test_reject_nuls_environment_collision_and_relative_program(self):
        valid = ([sys.executable, '', 'space argument', 'café'], Path.cwd(), {'A': 'b'})
        p.validate_invocation(*valid)
        for argv, directory, env in ((['relative'], Path.cwd(), {'A': 'b'}),
            ([sys.executable, 'bad\0argument'], Path.cwd(), {'A': 'b'}),
            ([sys.executable], Path.cwd(), {'A': 'b\0c'}),
            ([sys.executable], Path.cwd(), {'A=B': 'c'}),
            ([sys.executable], Path.cwd(), {'PATH': 'a', 'Path': 'b'})):
            with self.subTest(argv=argv, env=env), self.assertRaises(p.OwnershipError):
                p.validate_invocation(argv, directory, env)
    def test_fixed_width_windows_abi_layout(self):
        self.assertEqual(c.sizeof(p.Accounting), 48)
        if c.sizeof(c.c_void_p) == 8:
            self.assertEqual(c.sizeof(p.BasicLimits), 64)
            self.assertEqual(c.sizeof(p.ExtendedLimits), 144)
            self.assertEqual(c.sizeof(p.StartupInfo), 104)
            self.assertEqual(c.sizeof(p.StartupInfoEx), 112)
            self.assertEqual(c.sizeof(p.ProcessInformation), 24)


class FakeDll:
    """Portable native-call policy model: no Windows execution evidence."""
    def __init__(self, fail=None):
        self.fail = fail; self.last_error = 0; self.events = []; self.duplicates = []
        self.closed = []; self.attributes = {}; self.initialized = False; self.process_open = False
    def GetCurrentProcess(self): return 999
    def CreateJobObjectW(self, *args): self.events.append('job'); return 10
    def SetInformationJobObject(self, job, kind, limits, size):
        assert kind == 9 and limits._obj.BasicLimitInformation.LimitFlags == p.KILL_ON_JOB_CLOSE
        self.events.append('kill-on-close'); return 1
    def SetHandleInformation(self, handle, mask, flags):
        assert (handle, mask, flags) == (10, 1, 0); self.events.append('job-not-inherited'); return 1
    def DuplicateHandle(self, *args):
        if self.fail == 'duplicate' and self.duplicates: self.last_error = 5; return 0
        value = 100 + len(self.duplicates); self.duplicates.append(value); args[3]._obj.value = value
        assert args[5] is True; return 1
    def InitializeProcThreadAttributeList(self, attributes, count, flags, size):
        assert count == 2 and flags == 0
        if attributes is None:
            size._obj.value = 128; self.last_error = 122; return 0
        if self.fail == 'initialize': self.last_error = 5; return 0
        self.initialized = True; return 1
    def UpdateProcThreadAttribute(self, attributes, flags, name, values, size, previous, returned):
        if self.fail == name: self.last_error = 5; return 0
        self.attributes[name] = [c.cast(values, c.POINTER(p.HANDLE))[i] for i in range(size // c.sizeof(p.HANDLE))]
        return 1
    def DeleteProcThreadAttributeList(self, attributes):
        assert self.initialized; self.events.append('delete-attributes')
        if self.fail == 'delete': raise RuntimeError('injected attribute deletion interruption')
    def CreateProcessW(self, executable, command, psa, tsa, inherit, flags, env, cwd, info, process):
        assert self.attributes[p.HANDLE_LIST] == self.duplicates and self.attributes[p.JOB_LIST] == [10]
        assert 10 not in self.attributes[p.HANDLE_LIST] and inherit is True
        assert flags == p.CREATE_SUSPENDED | p.CREATE_NEW_PROCESS_GROUP | p.CREATE_UNICODE_ENVIRONMENT | p.EXTENDED_STARTUPINFO_PRESENT
        assert info._obj.StartupInfo.cb == c.sizeof(p.StartupInfoEx)
        assert [info._obj.StartupInfo.hStdInput, info._obj.StartupInfo.hStdOutput, info._obj.StartupInfo.hStdError] == self.duplicates
        self.events.append('create-suspended-in-job')
        if self.fail == 'create': self.last_error = 5; return 0
        process._obj.hProcess, process._obj.hThread, process._obj.dwProcessId = 201, 202, 203
        self.process_open = True
        if self.fail == 'after-create': raise RuntimeError('injected interruption after CreateProcessW')
        return 1
    def IsProcessInJob(self, process, job, member):
        assert (process, job) == (201, 10); self.events.append('exact-membership'); member._obj.value = 1; return 1
    def ResumeThread(self, thread): self.events.append('resume'); return 1
    def WaitForSingleObject(self, process, timeout): return p.WAIT_OBJECT_0
    def GetExitCodeProcess(self, process, code): code._obj.value = 0; return 1
    def QueryInformationJobObject(self, job, kind, value, size, returned):
        value._obj.TotalProcesses = 1; value._obj.ActiveProcesses = int(self.process_open); return 1
    def TerminateJobObject(self, job, code): self.events.append('terminate-job'); return 1
    def TerminateProcess(self, process, code): self.events.append('terminate-process'); return 1
    def CloseHandle(self, handle):
        self.closed.append(handle)
        if handle == 201: self.process_open = False
        return 1


class NativeApiPolicyControls(unittest.TestCase):
    def kernel(self, dll):
        kernel = p.WindowsKernel.__new__(p.WindowsKernel)
        kernel.dll = dll
        kernel.msvcrt = type('SyntheticDescriptors', (), {'get_osfhandle': staticmethod(lambda fd: fd + 1000)})
        kernel.error = lambda operation, code=None: p.OwnershipError(operation + ' failed; Win32 GetLastError=' + str(dll.last_error if code is None else code))
        return kernel
    def patches(self, dll):
        import contextlib
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(c, 'get_last_error', side_effect=lambda: dll.last_error, create=True))
        stack.enter_context(patch.object(c, 'set_last_error', side_effect=lambda value: setattr(dll, 'last_error', value), create=True))
        return stack
    def test_real_api_protocol_sets_job_list_and_exact_stdio_in_same_creation(self):
        dll = FakeDll()
        with self.patches(dll):
            owned = p.WindowsProcess([sys.executable], Path.cwd(), {'A': 'b'}, (1, 2, 3), kernel=self.kernel(dll))
            self.assertLess(dll.events.index('kill-on-close'), dll.events.index('create-suspended-in-job'))
            self.assertLess(dll.events.index('exact-membership'), dll.events.index('resume'))
            owned.poll(); owned.finish(time.monotonic() + 1); owned.close()
        self.assertEqual(sorted(dll.closed), [10, 100, 101, 102, 201, 202])
        self.assertEqual(len(dll.closed), len(set(dll.closed)))
    def test_each_preexecution_api_failure_and_postcreation_interruption_reaps_all_handles(self):
        for stage in ('duplicate', 'initialize', p.HANDLE_LIST, p.JOB_LIST, 'create', 'after-create', 'delete'):
            dll = FakeDll(stage)
            with self.subTest(stage=stage), self.patches(dll), self.assertRaises((p.OwnershipError, RuntimeError)):
                p.WindowsProcess([sys.executable], Path.cwd(), {'A': 'b'}, (1, 2, 3), kernel=self.kernel(dll))
            self.assertNotIn('resume', dll.events)
            self.assertIn(10, dll.closed)
            self.assertTrue(all(handle in dll.closed for handle in dll.duplicates))
            if stage in ('after-create', 'delete'):
                self.assertIn(201, dll.closed); self.assertIn(202, dll.closed)
            self.assertEqual(len(dll.closed), len(set(dll.closed)))
    def test_signal_during_creation_is_deferred_until_handles_are_owned_and_never_resumes(self):
        dll = FakeDll()
        original = dll.CreateProcessW
        def interrupted(*args):
            result = original(*args)
            signal.raise_signal(signal.SIGTERM)
            return result
        dll.CreateProcessW = interrupted
        with self.patches(dll), self.assertRaisesRegex(p.OwnershipError, 'interrupted during process adoption'):
            p.WindowsProcess([sys.executable], Path.cwd(), {'A': 'b'}, (1, 2, 3), kernel=self.kernel(dll))
        self.assertNotIn('resume', dll.events)
        self.assertIn(201, dll.closed); self.assertIn(202, dll.closed)


class ProcessControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
    def run_child(self, mode, *args, seconds=10, label='child'):
        return p.run_command([sys.executable, str(THIS), '--child', mode, *map(str, args)],
                             self.directory, label, time.monotonic() + seconds)
    def test_real_exit_and_exact_bounded_stdio(self):
        result = self.run_child('echo', 'space argument', 'quote"value', 'trailing\\', 'café漢字', '')
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(json.loads((self.directory / 'child.stdout.log').read_text()),
                         ['space argument', 'quote"value', 'trailing\\', 'café漢字', ''])
        self.assertEqual((self.directory / 'child.stderr.log').read_bytes(), b'owned stderr\n')
        self.assertTrue(result['process_ownership']['reader_threads_joined'])
        self.assertEqual(result['process_ownership']['active_processes_after'], 0)
    def test_timeout_reaps_root_and_joins_readers(self):
        pidfile = self.directory / 'root.pid'
        with self.assertRaisesRegex(p.OwnershipError, 'timeout'):
            self.run_child('sleep', pidfile, seconds=0.3)
        self.assertTrue(pidfile.exists())
        self.assertFalse(pid_alive(int(pidfile.read_text())))
    def test_output_is_hard_capped_and_overflow_fails(self):
        with self.assertRaisesRegex(p.OwnershipError, 'output exceeds bound'):
            self.run_child('output')
        self.assertLessEqual((self.directory / 'child.stdout.log').stat().st_size, p.OUTPUT_CAP)
        self.assertLessEqual((self.directory / 'child.stderr.log').stat().st_size, p.OUTPUT_CAP)


@unittest.skipUnless(os.name == 'nt', 'native Windows job controls')
class NativeWindowsControls(ProcessControls):
    def test_rapid_exit_zero_and_one_32_times_are_always_owned(self):
        for index in range(32):
            code = index % 2
            result = self.run_child('exit', code, label='rapid-' + str(index))
            self.assertEqual(result['exit_code'], code)
            ownership = result['process_ownership']
            self.assertIs(ownership['creation_time_job_association'], True)
            self.assertIs(ownership['kill_on_close'], True)
            self.assertIs(ownership['job_handle_inherited'], False)
            self.assertEqual(ownership['accounting']['total_processes'], 1)
            self.assertEqual(ownership['accounting']['active_processes'], 0)
    def test_root_exit_with_leaf_retaining_writers_fails_and_kills_leaf(self):
        leaf = self.directory / 'leaf.pid'
        with self.assertRaisesRegex(p.OwnershipError, 'descendants'):
            self.run_child('spawn-exit', leaf)
        self.assertTrue(leaf.exists()); self.assertFalse(pid_alive(int(leaf.read_text())))
    def test_timeout_with_leaf_kills_both_and_joins_pipe_readers(self):
        root, leaf = self.directory / 'root.pid', self.directory / 'leaf.pid'
        with self.assertRaisesRegex(p.OwnershipError, 'timeout'):
            self.run_child('spawn-wait', root, leaf, seconds=1)
        self.assertFalse(pid_alive(int(root.read_text())))
        self.assertFalse(pid_alive(int(leaf.read_text())))
    def test_refused_membership_never_resumes_real_suspended_process(self):
        sentinel = self.directory / 'must-not-exist'
        class RefuseKernel(p.WindowsKernel):
            def in_job(self, process, job):
                if not super().in_job(process, job): raise AssertionError('creation-time job association failed')
                return False
            def resume(self, thread): raise AssertionError('failed containment must never resume')
        null = os.open(os.devnull, os.O_RDWR)
        try:
            with self.assertRaisesRegex(p.OwnershipError, 'exact owned job'):
                p.WindowsProcess([sys.executable, str(THIS), '--child', 'sentinel', str(sentinel)],
                    self.directory, dict(os.environ), (null, null, null), kernel=RefuseKernel())
        finally:
            os.close(null)
        self.assertFalse(sentinel.exists())
    def test_forced_parent_exit_closes_noninherited_job_and_kills_root_and_leaf(self):
        root, leaf = self.directory / 'parent-root.pid', self.directory / 'parent-leaf.pid'
        result = subprocess.run([sys.executable, str(THIS), '--controller-kill', str(root), str(leaf)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 77, result.stderr.decode(errors='replace'))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(pid_alive(int(path.read_text())) for path in (root, leaf)):
            time.sleep(0.01)
        self.assertFalse(pid_alive(int(root.read_text()))); self.assertFalse(pid_alive(int(leaf.read_text())))
    def test_nested_creation_time_jobs_work_without_breakaway(self):
        result = self.run_child('nested', self.directory, seconds=15)
        self.assertEqual(result['exit_code'], 0)
        nested = json.loads((self.directory / 'child.stdout.log').read_text())
        self.assertEqual(nested['process_ownership']['accounting']['active_processes'], 0)
        self.assertTrue(nested['process_ownership']['creation_time_job_association'])


def pid_alive(pid):
    if os.name != 'nt':
        try: os.kill(pid, 0); return True
        except ProcessLookupError: return False
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [p.DWORD, p.BOOL, p.DWORD]; kernel.OpenProcess.restype = p.HANDLE
    kernel.WaitForSingleObject.argtypes = [p.HANDLE, p.DWORD]; kernel.WaitForSingleObject.restype = p.DWORD
    kernel.CloseHandle.argtypes = [p.HANDLE]; kernel.CloseHandle.restype = p.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)
    if not handle:
        code = c.get_last_error()
        if code == 87: return False
        raise AssertionError('OpenProcess failed; Win32 GetLastError=' + str(code))
    try:
        result = kernel.WaitForSingleObject(handle, 0)
        if result == 0xFFFFFFFF:
            raise AssertionError('WaitForSingleObject failed; Win32 GetLastError=' + str(c.get_last_error()))
        if result not in (p.WAIT_OBJECT_0, p.WAIT_TIMEOUT):
            raise AssertionError('unexpected Windows wait status: ' + str(result))
        return result == p.WAIT_TIMEOUT
    finally:
        if not kernel.CloseHandle(handle):
            raise AssertionError('CloseHandle failed; Win32 GetLastError=' + str(c.get_last_error()))


def child_main(argv):
    mode, *args = argv
    if mode == 'exit': return int(args[0])
    if mode == 'echo':
        print(json.dumps(args)); sys.stderr.buffer.write(b'owned stderr\n'); return 0
    if mode == 'sentinel': Path(args[0]).write_text('uncontained code executed'); return 0
    if mode == 'output':
        sys.stdout.buffer.write(b'x' * (p.OUTPUT_CAP * 4)); sys.stdout.buffer.flush(); return 0
    if mode == 'sleep':
        Path(args[0]).write_text(str(os.getpid())); time.sleep(60); return 0
    if mode in ('spawn-exit', 'spawn-wait'):
        root = Path(args[0]) if mode == 'spawn-wait' else None
        leaf = Path(args[-1])
        if root: root.write_text(str(os.getpid()))
        subprocess.Popen([sys.executable, str(THIS), '--child', 'sleep', str(leaf)], close_fds=False)
        limit = time.monotonic() + 5
        while not leaf.exists() and time.monotonic() < limit: time.sleep(0.01)
        if not leaf.exists(): return 2
        if mode == 'spawn-wait': time.sleep(60)
        return 0
    if mode == 'nested':
        result = p.run_command([sys.executable, str(THIS), '--child', 'exit', '0'],
                               Path(args[0]), 'nested', time.monotonic() + 10)
        print(json.dumps(result)); return 0
    raise ValueError('unknown child mode')


def controller_kill(root, leaf):
    directory = Path(root).parent
    def stop():
        limit = time.monotonic() + 10
        while time.monotonic() < limit:
            if Path(root).exists() and Path(leaf).exists(): os._exit(77)
            time.sleep(0.01)
        os._exit(78)
    threading.Thread(target=stop, daemon=True).start()
    p.run_command([sys.executable, str(THIS), '--child', 'spawn-wait', root, leaf],
                  directory, 'forced-parent', time.monotonic() + 15)
    return 79


if __name__ == '__main__':
    if '--child' in sys.argv:
        raise SystemExit(child_main(sys.argv[sys.argv.index('--child') + 1:]))
    if '--controller-kill' in sys.argv:
        raise SystemExit(controller_kill(*sys.argv[2:]))
    if '--require-windows' in sys.argv:
        if os.name != 'nt':
            print('native Windows process containment required; refusing skipped success', file=sys.stderr)
            raise SystemExit(2)
        sys.argv.remove('--require-windows')
    unittest.main()
