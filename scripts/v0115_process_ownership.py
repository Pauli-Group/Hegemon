#!/usr/bin/env python3
"""Bounded v0.11.5 verifier process ownership; no proof or release authority.

Windows uses creation-time PROC_THREAD_ATTRIBUTE_JOB_LIST, not assignment of an
already-running child. Only the three duplicated stdio handles are inherited.
The kill-on-close job exists before CreateProcessW; the primary thread remains
suspended until exact job membership is checked. No breakaway/fallback exists.
POSIX retains new-session process-group ownership and rejects live descendants.
"""
from __future__ import annotations

import contextlib
import ctypes as c
import hashlib
import math
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

SCHEMA = 'hegemon.v0115.process-ownership.v1'
OUTPUT_CAP = 65536
CLEANUP_SECONDS = 5
MAX_JOB_MEMBERS = 4096
JOB_LIST = 0x0002000D
HANDLE_LIST = 0x00020002
KILL_ON_JOB_CLOSE = 0x00002000
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
DWORD = c.c_uint32
BOOL = c.c_int32
WORD = c.c_uint16
HANDLE = c.c_void_p
SIZE_T = c.c_size_t


class OwnershipError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise OwnershipError(message)


class BasicLimits(c.Structure):
    _fields_ = [('PerProcessUserTimeLimit', c.c_int64), ('PerJobUserTimeLimit', c.c_int64),
                ('LimitFlags', DWORD), ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', DWORD),
                ('Affinity', SIZE_T), ('PriorityClass', DWORD), ('SchedulingClass', DWORD)]


class IoCounters(c.Structure):
    _fields_ = [(name, c.c_uint64) for name in ('ReadOperationCount', 'WriteOperationCount',
                'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class ExtendedLimits(c.Structure):
    _fields_ = [('BasicLimitInformation', BasicLimits), ('IoInfo', IoCounters),
                ('ProcessMemoryLimit', SIZE_T), ('JobMemoryLimit', SIZE_T),
                ('PeakProcessMemoryUsed', SIZE_T), ('PeakJobMemoryUsed', SIZE_T)]


class Accounting(c.Structure):
    _fields_ = [(name, c.c_int64) for name in ('TotalUserTime', 'TotalKernelTime',
                'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime')] + [
                (name, DWORD) for name in ('TotalPageFaultCount', 'TotalProcesses',
                'ActiveProcesses', 'TotalTerminatedProcesses')]


class StartupInfo(c.Structure):
    _fields_ = [('cb', DWORD), ('lpReserved', c.c_wchar_p), ('lpDesktop', c.c_wchar_p),
                ('lpTitle', c.c_wchar_p)] + [(name, DWORD) for name in ('dwX', 'dwY',
                'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars', 'dwFillAttribute',
                'dwFlags')] + [('wShowWindow', WORD), ('cbReserved2', WORD),
                ('lpReserved2', c.c_void_p), ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE), ('hStdError', HANDLE)]


class StartupInfoEx(c.Structure):
    _fields_ = [('StartupInfo', StartupInfo), ('lpAttributeList', c.c_void_p)]


class ProcessInformation(c.Structure):
    _fields_ = [('hProcess', HANDLE), ('hThread', HANDLE), ('dwProcessId', DWORD),
                ('dwThreadId', DWORD)]


def validate_invocation(argv, cwd, env):
    require(isinstance(argv, list) and argv and bool(argv[0]) and all(isinstance(v, str) and '\0' not in v for v in argv),
            'nonempty NUL-free argv required')
    require(Path(argv[0]).is_absolute(), 'absolute executable path required')
    require(isinstance(cwd, Path) and cwd.is_absolute() and '\0' not in str(cwd), 'absolute NUL-free working directory required')
    require(isinstance(env, dict) and env, 'explicit environment required')
    keys = []
    for key, value in env.items():
        require(isinstance(key, str) and key and '=' not in key and '\0' not in key
                and isinstance(value, str) and '\0' not in value, 'invalid environment entry')
        keys.append(key.casefold())
    require(len(keys) == len(set(keys)), 'case-insensitive environment collision')


class WindowsKernel:
    """Narrow typed Win32 API; its protocol is replaceable in policy tests only."""
    def __init__(self):
        require(os.name == 'nt', 'native Windows kernel required')
        import msvcrt
        self.msvcrt = msvcrt
        self.dll = c.WinDLL('kernel32', use_last_error=True)
        signatures = (
            ('CreateJobObjectW', [c.c_void_p, c.c_wchar_p], HANDLE),
            ('SetInformationJobObject', [HANDLE, c.c_int32, c.c_void_p, DWORD], BOOL),
            ('QueryInformationJobObject', [HANDLE, c.c_int32, c.c_void_p, DWORD, c.c_void_p], BOOL),
            ('SetHandleInformation', [HANDLE, DWORD, DWORD], BOOL),
            ('GetCurrentProcess', [], HANDLE),
            ('DuplicateHandle', [HANDLE, HANDLE, HANDLE, c.POINTER(HANDLE), DWORD, BOOL, DWORD], BOOL),
            ('InitializeProcThreadAttributeList', [c.c_void_p, DWORD, DWORD, c.POINTER(SIZE_T)], BOOL),
            ('UpdateProcThreadAttribute', [c.c_void_p, DWORD, SIZE_T, c.c_void_p, SIZE_T, c.c_void_p, c.c_void_p], BOOL),
            ('DeleteProcThreadAttributeList', [c.c_void_p], None),
            ('CreateProcessW', [c.c_wchar_p, c.c_wchar_p, c.c_void_p, c.c_void_p, BOOL,
                               DWORD, c.c_void_p, c.c_wchar_p, c.POINTER(StartupInfoEx),
                               c.POINTER(ProcessInformation)], BOOL),
            ('IsProcessInJob', [HANDLE, HANDLE, c.POINTER(BOOL)], BOOL),
            ('ResumeThread', [HANDLE], DWORD),
            ('WaitForSingleObject', [HANDLE, DWORD], DWORD),
            ('GetExitCodeProcess', [HANDLE, c.POINTER(DWORD)], BOOL),
            ('OpenProcess', [DWORD, BOOL, DWORD], HANDLE),
            ('TerminateJobObject', [HANDLE, c.c_uint32], BOOL),
            ('TerminateProcess', [HANDLE, c.c_uint32], BOOL),
            ('CloseHandle', [HANDLE], BOOL),
        )
        for name, arguments, result in signatures:
            fn = getattr(self.dll, name); fn.argtypes = arguments; fn.restype = result

    def error(self, operation, code=None):
        # Save GetLastError before any formatting, cleanup or subsequent API.
        code = c.get_last_error() if code is None else code
        return OwnershipError(operation + ' failed; Win32 GetLastError=' + str(code) + ': ' + c.FormatError(code).strip())

    def checked(self, name, *args):
        value = getattr(self.dll, name)(*args)
        if not value:
            raise self.error(name)
        return value

    def create_job(self):
        return self.checked('CreateJobObjectW', None, None)

    def configure_job(self, job):
        limits = ExtendedLimits(); limits.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE
        self.checked('SetInformationJobObject', job, 9, c.byref(limits), c.sizeof(limits))
        self.checked('SetHandleInformation', job, 1, 0)  # Job is never inherited.

    def close(self, handle):
        self.checked('CloseHandle', handle)

    def create_suspended(self, argv, cwd, env, stdio, job, information=None):
        duplicates = []
        attributes = None
        initialized = False
        primary_error = None
        result = None
        process = information if information is not None else ProcessInformation()
        try:
            current = self.dll.GetCurrentProcess()
            for descriptor in stdio:
                duplicate = HANDLE()
                self.checked('DuplicateHandle', current, self.msvcrt.get_osfhandle(descriptor),
                             current, c.byref(duplicate), 0, True, 2)
                duplicates.append(duplicate.value)
            require(len(set(duplicates)) == 3 and job not in duplicates, 'exact distinct stdio handle allowlist required')
            size = SIZE_T()
            c.set_last_error(0)
            sizing = self.dll.InitializeProcThreadAttributeList(None, 2, 0, c.byref(size))
            sizing_error = c.get_last_error()
            require(not sizing and sizing_error == 122 and size.value > 0,
                    'InitializeProcThreadAttributeList sizing failed; Win32 GetLastError=' + str(sizing_error))
            attributes = c.create_string_buffer(size.value)
            self.checked('InitializeProcThreadAttributeList', attributes, 2, 0, c.byref(size))
            initialized = True
            # These arrays and the attribute buffer remain alive through delete.
            handles = (HANDLE * 3)(*duplicates)
            jobs = (HANDLE * 1)(job)
            self.checked('UpdateProcThreadAttribute', attributes, 0, HANDLE_LIST,
                         handles, c.sizeof(handles), None, None)
            self.checked('UpdateProcThreadAttribute', attributes, 0, JOB_LIST,
                         jobs, c.sizeof(jobs), None, None)
            info = StartupInfoEx(); info.StartupInfo.cb = c.sizeof(info)
            info.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
            info.StartupInfo.hStdInput, info.StartupInfo.hStdOutput, info.StartupInfo.hStdError = duplicates
            info.lpAttributeList = c.cast(attributes, c.c_void_p)
            command_text = subprocess.list2cmdline(argv)
            command = c.create_unicode_buffer(command_text, len(command_text.encode('utf-16-le')) // 2 + 1)
            block_text = '\0'.join(key + '=' + env[key] for key in sorted(env, key=str.casefold)) + '\0'
            block = c.create_unicode_buffer(block_text, len(block_text.encode('utf-16-le')) // 2 + 1)
            flags = CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
            self.checked('CreateProcessW', argv[0], command, None, None, True, flags,
                         c.cast(block, c.c_void_p), str(cwd), c.byref(info), c.byref(process))
            result = (process.hProcess, process.hThread, int(process.dwProcessId))
            require(process.hProcess and process.hThread and process.dwProcessId, 'CreateProcessW returned incomplete process ownership')
        except BaseException as error:
            primary_error = error
        finally:
            failures = []
            if initialized:
                try:
                    self.dll.DeleteProcThreadAttributeList(attributes)
                except BaseException as error:
                    failures.append(str(error))
            for handle in reversed(duplicates):
                try:
                    self.close(handle)
                except BaseException as error:
                    failures.append(str(error))
            if failures:
                primary_error = OwnershipError(str(primary_error or 'stdio handle cleanup failed') + '; cleanup: ' + '; '.join(failures))
        if primary_error:
            # If CreateProcess succeeded, transfer its still-suspended handles to
            # the caller even if parent duplicate cleanup failed, for termination.
            if process.hProcess or process.hThread:
                primary_error.created_process = (process.hProcess, process.hThread, int(process.dwProcessId))
            raise primary_error
        return result

    def in_job(self, process, job):
        member = BOOL()
        self.checked('IsProcessInJob', process, job, c.byref(member))
        return member.value != 0

    def resume(self, thread):
        previous = self.dll.ResumeThread(thread)
        if previous == 0xFFFFFFFF:
            raise self.error('ResumeThread')
        return int(previous)

    def wait(self, process, milliseconds):
        result = self.dll.WaitForSingleObject(process, milliseconds)
        if result == 0xFFFFFFFF:
            raise self.error('WaitForSingleObject')
        require(result in (WAIT_OBJECT_0, WAIT_TIMEOUT), 'unexpected Windows wait result: ' + str(result))
        return result == WAIT_OBJECT_0

    def exit_code(self, process):
        result = DWORD(); self.checked('GetExitCodeProcess', process, c.byref(result))
        return int(result.value)

    def accounting(self, job):
        value = Accounting()
        self.checked('QueryInformationJobObject', job, 1, c.byref(value), c.sizeof(value), None)
        return {'total_processes': int(value.TotalProcesses), 'active_processes': int(value.ActiveProcesses),
                'terminated_processes': int(value.TotalTerminatedProcesses)}

    def retain_members(self, job):
        """Retain a bounded exact job snapshot before requesting termination."""
        class ProcessIds(c.Structure):
            _fields_ = [('assigned', DWORD), ('listed', DWORD), ('pids', SIZE_T * MAX_JOB_MEMBERS)]
        value = ProcessIds(); retained = []
        try:
            self.checked('QueryInformationJobObject', job, 3, c.byref(value), c.sizeof(value), None)
            require(value.assigned == value.listed and value.listed <= MAX_JOB_MEMBERS,
                    'incomplete or oversized Windows job member snapshot')
            pids = [int(value.pids[index]) for index in range(value.listed)]
            require(len(pids) == len(set(pids)) and all(0 < pid <= 0xFFFFFFFF for pid in pids),
                    'invalid Windows job member identifiers')
            for pid in pids:
                handle = self.checked('OpenProcess', 0x00101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION.
                retained.append((pid, handle))
                require(self.in_job(handle, job), 'retained process is not in the exact owned job')
            return retained
        except BaseException as error:
            failures = []
            for _pid, handle in reversed(retained):
                try:
                    self.close(handle)
                except BaseException as cleanup:
                    failures.append(str(cleanup))
            if failures:
                raise OwnershipError(str(error) + '; member handle cleanup: ' + '; '.join(failures)) from error
            raise

    def terminate_job(self, job):
        self.checked('TerminateJobObject', job, 1)

    def terminate_process(self, process):
        self.checked('TerminateProcess', process, 1)


class WindowsProcess:
    def __init__(self, argv, cwd, env, stdio, kernel=None):
        self.kernel = kernel or WindowsKernel()
        self.job = self.process = self.thread = None
        self.code = None; self.pid = None; self.last_accounting = None
        self.information = ProcessInformation()
        creating = True
        try:
            with deferred_interruption():
                self.job = self.kernel.create_job()
                self.kernel.configure_job(self.job)
                try:
                    self.process, self.thread, self.pid = self.kernel.create_suspended(
                        argv, cwd, env, stdio, self.job, self.information)
                except BaseException as error:
                    if getattr(error, 'created_process', None):
                        self.process, self.thread, self.pid = error.created_process
                    raise
                require(self.kernel.in_job(self.process, self.job), 'created suspended process is not in the exact owned job')
                creating = False
            previous = self.kernel.resume(self.thread)
            require(previous == 1, 'ResumeThread prior suspend count must be exactly one; observed=' + str(previous))
            self.kernel.close(self.thread); self.thread = None
        except BaseException as error:
            if creating and (self.information.hProcess or self.information.hThread):
                self.process, self.thread, self.pid = (self.information.hProcess, self.information.hThread, int(self.information.dwProcessId))
            try:
                self.abort()
            except BaseException as cleanup:
                raise OwnershipError(str(error) + '; cleanup: ' + str(cleanup)) from error
            raise

    def poll(self):
        if self.code is not None:
            return self.code
        if not self.kernel.wait(self.process, 0):
            return None
        self.code = self.kernel.exit_code(self.process)
        # Windows job active accounting includes open process/thread references.
        # Save the exit code, then release ours before querying descendant liveness.
        self.kernel.close(self.process); self.process = None
        return self.code

    def accounting(self):
        self.last_accounting = self.kernel.accounting(self.job)
        return self.last_accounting

    def finish(self, deadline):
        require(self.poll() is not None, 'owned Windows process has not exited')
        limit = min(deadline, time.monotonic() + 1)
        while self.accounting()['active_processes']:
            require(time.monotonic() < limit, 'offline verifier left Windows job descendants')
            time.sleep(0.01)
        return self.last_accounting

    def close(self):
        require(self.process is None and self.thread is None, 'process/thread handles must be reaped before job close')
        if self.job is not None:
            self.kernel.close(self.job); self.job = None

    def abort(self):
        failures = []
        retained = []
        total_before = None
        deadline = time.monotonic() + CLEANUP_SECONDS
        job_termination_requested = False
        if self.job is not None:
            try:
                total_before = self.accounting()['total_processes']
                with deferred_interruption():
                    retained = self.kernel.retain_members(self.job)
                known_pids = {pid for pid, _handle in retained}
                if self.pid is not None:
                    known_pids.add(self.pid)
                require(len(known_pids) == total_before,
                        'Windows job has historical members without retained identities')
            except BaseException as error:
                failures.append(str(error))
            try:
                self.kernel.terminate_job(self.job)
                job_termination_requested = True
            except BaseException as error:
                failures.append(str(error))
        if self.process is not None:
            if not job_termination_requested:
                try:
                    if not self.kernel.wait(self.process, 0):
                        self.kernel.terminate_process(self.process)
                except BaseException as error:
                    failures.append(str(error))
            try:
                # A successful job termination already requests root termination.
                # A redundant TerminateProcess may race that asynchronous exit.
                # Always wait on the retained identity, even if a request failed.
                remaining = max(0, int((deadline - time.monotonic()) * 1000))
                require(self.kernel.wait(self.process, remaining), 'owned Windows root did not terminate')
                self.code = self.kernel.exit_code(self.process)
            except BaseException as error:
                failures.append(str(error))
        for pid, handle in retained:
            try:
                remaining = max(0, int((deadline - time.monotonic()) * 1000))
                require(self.kernel.wait(handle, remaining), 'owned Windows member did not terminate: ' + str(pid))
            except BaseException as error:
                failures.append(str(error))
        for _pid, handle in reversed(retained):
            try:
                self.kernel.close(handle)
            except BaseException as error:
                failures.append(str(error))
        for name in ('thread', 'process'):
            handle = getattr(self, name)
            if handle is not None:
                try:
                    self.kernel.close(handle); setattr(self, name, None)
                except BaseException as error:
                    failures.append(str(error))
        if self.job is not None:
            try:
                while self.accounting()['active_processes']:
                    require(time.monotonic() < deadline, 'Windows owned job did not drain after termination')
                    time.sleep(0.01)
                require(total_before is not None and self.last_accounting['total_processes'] == total_before,
                        'Windows job membership changed during termination capture')
            except BaseException as error:
                failures.append(str(error))
            try:
                self.kernel.close(self.job); self.job = None
            except BaseException as error:
                failures.append(str(error))
        require(not failures, 'Windows cleanup failed: ' + '; '.join(failures))


class PosixProcess:
    def __init__(self, argv, cwd, env, stdio):
        self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdio[0], stdout=stdio[1],
                                        stderr=stdio[2], close_fds=True, start_new_session=True)
        self.pid = self.process.pid

    def poll(self):
        return self.process.poll()

    def active(self):
        try:
            os.killpg(self.pid, 0); return True
        except ProcessLookupError:
            return False

    def finish(self, deadline):
        self.process.wait(timeout=max(0.001, min(CLEANUP_SECONDS, deadline - time.monotonic())))
        require(not self.active(), 'offline verifier left POSIX process-group descendants')
        return {'active_processes': 0}

    def close(self):
        pass

    def abort(self):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=CLEANUP_SECONDS)
        limit = time.monotonic() + CLEANUP_SECONDS
        while self.active():
            require(time.monotonic() < limit, 'POSIX owned process group did not drain after termination')
            time.sleep(0.01)


@contextlib.contextmanager
def deferred_interruption():
    # A native call can return a live HANDLE before Python assigns its result.
    # Defer catchable signals only across this short ownership-adoption window.
    # No child is resumed until its handles and exact job membership are owned.
    saved, pending = {}, []
    def defer(number, _frame):
        pending.append(number)
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if hasattr(signal, 'SIGBREAK') else [])):
            saved[signum] = signal.getsignal(signum); signal.signal(signum, defer)
        yield
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)
    if pending:
        raise OwnershipError('owned verifier interrupted during process adoption by signal ' + str(pending[0]))


@contextlib.contextmanager
def interruption_handlers():
    saved = {}
    def interrupted(number, _frame):
        for signum in saved:
            signal.signal(signum, signal.SIG_IGN)
        raise OwnershipError('owned verifier interrupted by signal ' + str(number))
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if hasattr(signal, 'SIGBREAK') else [])):
            saved[signum] = signal.getsignal(signum); signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)


def run_command(argv, directory, label, deadline):
    """Historical verifier callback with bounded logs and mandatory containment."""
    directory = Path(directory).absolute()
    require(isinstance(label, str) and label and all(v.isalnum() or v in '-_' for v in label), 'safe output label required')
    require(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline, 'future monotonic deadline required')
    env = {k: v for k, v in os.environ.items() if not k.startswith('HEGEMON_') and k not in ('PQ_IDENTITY_SEED', 'PQ_IDENTITY_SEED_PATH')}
    env.update(HOME=str(directory), USERPROFILE=str(directory), RAYON_NUM_THREADS='2')
    validate_invocation(argv, directory, env)
    stdout = directory / (label + '.stdout.log'); stderr = directory / (label + '.stderr.log')
    descriptors = []; readers = []; failures = []; overflow = threading.Event(); actor = None
    primary = None; statistics = None; code = None
    def read_pipe(fd, log):
        try:
            retained = 0
            with os.fdopen(fd, 'rb', buffering=0) as source:
                while True:
                    raw = source.read(4096)
                    if not raw:
                        break
                    remaining = OUTPUT_CAP - retained
                    if remaining > 0:
                        chunk = raw[:remaining]; log.write(chunk); log.flush(); retained += len(chunk)
                    if len(raw) > remaining:
                        overflow.set()
        except BaseException as error:
            failures.append(str(error)); overflow.set()
    with stdout.open('xb') as out, stderr.open('xb') as err, interruption_handlers():
        try:
            with deferred_interruption():
                stdin = os.open(os.devnull, os.O_RDONLY); descriptors.append(stdin)
                out_read, out_write = os.pipe(); descriptors.extend((out_read, out_write))
                err_read, err_write = os.pipe(); descriptors.extend((err_read, err_write))
            actor_class = WindowsProcess if os.name == 'nt' else PosixProcess
            with deferred_interruption():
                actor = actor_class(argv, directory, env, (stdin, out_write, err_write))
            for descriptor in (stdin, out_write, err_write):
                os.close(descriptor); descriptors.remove(descriptor)
            for descriptor, retained in ((out_read, out), (err_read, err)):
                with deferred_interruption():
                    thread = threading.Thread(target=read_pipe, args=(descriptor, retained), daemon=True)
                    thread.start(); readers.append(thread); descriptors.remove(descriptor)
            while actor.poll() is None:
                require(time.monotonic() < deadline, 'offline verifier timeout')
                require(not overflow.is_set(), 'offline verifier output exceeds bound or reader failed')
                time.sleep(0.01)
            code = actor.poll(); statistics = actor.finish(deadline)
            for thread in readers:
                thread.join(timeout=max(0.001, min(CLEANUP_SECONDS, deadline - time.monotonic())))
            require(all(not thread.is_alive() for thread in readers), 'offline verifier retained stdio reader')
            require(not overflow.is_set() and not failures, 'offline verifier output exceeds bound or reader failed')
            actor.close(); actor = None
        except BaseException as error:
            primary = error
        finally:
            cleanup = []
            if actor is not None:
                try:
                    actor.abort()
                except BaseException as error:
                    cleanup.append(str(error))
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError as error:
                    cleanup.append(str(error))
            for thread in readers:
                thread.join(timeout=CLEANUP_SECONDS)
                if thread.is_alive():
                    cleanup.append('owned stdio reader did not finish')
            if cleanup:
                primary = OwnershipError(str(primary or 'owned process cleanup failed') + '; cleanup: ' + '; '.join(cleanup))
        if primary is not None:
            raise primary
    def row(path):
        raw = path.read_bytes()
        require(len(raw) <= OUTPUT_CAP, 'retained output exceeds hard bound')
        return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    ownership = {'schema': SCHEMA, 'backend': 'windows-creation-job-list' if os.name == 'nt' else 'posix-session-process-group',
                 'owned_before_execution': True, 'processes_reaped': True, 'active_processes_after': 0,
                 'stdio_handle_allowlist': True, 'stdout_limit_bytes': OUTPUT_CAP, 'stderr_limit_bytes': OUTPUT_CAP,
                 'reader_threads_joined': True, 'accounting': statistics}
    if os.name == 'nt':
        ownership.update(kill_on_close=True, creation_time_job_association=True,
                         suspended_primary_thread_retained=True, exact_job_membership_checked_before_resume=True,
                         resume_prior_suspend_count=1, job_handle_inherited=False)
    return {'exit_code': code, 'processes_reaped': True, 'argv': argv,
            'stdout': row(stdout), 'stderr': row(stderr), 'process_ownership': ownership}
