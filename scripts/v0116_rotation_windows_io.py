"""Native Windows I/O for the isolated payout-rotation release rehearsal."""

import ctypes as c
import hashlib
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
from contextlib import ExitStack

import v0115_process_ownership as owned


PSEUDOCONSOLE = 0x00020016
OUTPUT_LIMIT = 4 * 1024 * 1024
# OSC (including the console title), CSI, then other two-character VT escapes.
VT = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")


class Coord(c.Structure):
    _fields_ = [("X", c.c_short), ("Y", c.c_short)]


class ConsoleKernel(owned.WindowsKernel):
    """Attach the child to a private pseudoconsole and its kill-on-close job at creation."""

    def __init__(self):
        super().__init__()
        self.console = owned.HANDLE()
        self.dll.CreatePseudoConsole.argtypes = [
            Coord, owned.HANDLE, owned.HANDLE, owned.DWORD, c.POINTER(owned.HANDLE),
        ]
        self.dll.CreatePseudoConsole.restype = c.c_int32
        self.dll.ClosePseudoConsole.argtypes = [owned.HANDLE]
        self.dll.ClosePseudoConsole.restype = None

    def open_console(self, input_fd, output_fd):
        # Leave room for whole machine-readable wallet addresses on one line.
        result = self.dll.CreatePseudoConsole(
            Coord(16384, 24), self.msvcrt.get_osfhandle(input_fd),
            self.msvcrt.get_osfhandle(output_fd), 0, c.byref(self.console),
        )
        if result != 0:
            raise OSError(f"CreatePseudoConsole failed (HRESULT 0x{result & 0xffffffff:08x})")

    def close_console(self):
        if self.console.value:
            self.dll.ClosePseudoConsole(self.console)
            self.console = owned.HANDLE()

    def create_suspended(self, argv, cwd, env, stdio, job, information=None):
        size = owned.SIZE_T()
        c.set_last_error(0)
        sized = self.dll.InitializeProcThreadAttributeList(None, 2, 0, c.byref(size))
        if sized or c.get_last_error() != 122 or not size.value:
            raise self.error("size console process attribute list")
        attributes = c.create_string_buffer(size.value)
        self.checked("InitializeProcThreadAttributeList", attributes, 2, 0, c.byref(size))
        try:
            jobs = (owned.HANDLE * 1)(job)
            self.checked("UpdateProcThreadAttribute", attributes, 0, owned.JOB_LIST,
                         jobs, c.sizeof(jobs), None, None)
            # The pseudoconsole attribute takes the HPCON *value*. The job list
            # attribute takes the address of an array of HANDLEs.
            self.checked("UpdateProcThreadAttribute", attributes, 0, PSEUDOCONSOLE,
                         self.console, c.sizeof(self.console), None, None)
            info = owned.StartupInfoEx()
            info.StartupInfo.cb = c.sizeof(info)
            info.lpAttributeList = c.cast(attributes, c.c_void_p)
            command_text = subprocess.list2cmdline(argv)
            command = c.create_unicode_buffer(command_text, len(command_text.encode("utf-16-le")) // 2 + 1)
            env_text = "\0".join(f"{key}={env[key]}" for key in sorted(env, key=str.casefold))
            env_block = c.create_unicode_buffer(env_text + "\0", len(env_text.encode("utf-16-le")) // 2 + 2)
            flags = (owned.CREATE_SUSPENDED | owned.CREATE_UNICODE_ENVIRONMENT
                     | owned.EXTENDED_STARTUPINFO_PRESENT)
            # No inheritable handles, shell, or redirected terminal file. The
            # child opens CONIN$ and CONOUT$ in its own console through rpassword.
            self.checked("CreateProcessW", argv[0], command, None, None, False, flags,
                         c.cast(env_block, c.c_void_p), str(cwd), c.byref(info), c.byref(information))
            return information.hProcess, information.hThread, int(information.dwProcessId)
        finally:
            self.dll.DeleteProcThreadAttributeList(attributes)


def _ensure_node_console():
    # CTRL_BREAK_EVENT reaches a process group attached to the caller's console.
    # Console-less Windows service/CI launches need a console before node startup.
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleProcessList.argtypes = [c.POINTER(owned.DWORD), owned.DWORD]
    kernel.GetConsoleProcessList.restype = owned.DWORD
    if kernel.GetConsoleProcessList((owned.DWORD * 1)(), 1):
        return
    kernel.AllocConsole.argtypes = []
    kernel.AllocConsole.restype = owned.BOOL
    if not kernel.AllocConsole():
        raise c.WinError(c.get_last_error())
    kernel.GetConsoleWindow.argtypes = []
    kernel.GetConsoleWindow.restype = owned.HANDLE
    window = kernel.GetConsoleWindow()
    if window:
        user = c.WinDLL("user32", use_last_error=True)
        user.ShowWindow.argtypes = [owned.HANDLE, c.c_int]
        user.ShowWindow.restype = owned.BOOL
        user.ShowWindow(window, 0)


def start_node(exe_argv, env, stdout):
    argv = [str(arg) for arg in exe_argv]
    cwd = Path.cwd()
    owned.validate_invocation(argv, cwd, env)
    _ensure_node_console()
    with open(os.devnull, "rb") as stdin:
        return owned.WindowsProcess(argv, cwd, env, (stdin.fileno(), stdout.fileno(), stdout.fileno()))


def stop_node(proc, grace=20):
    forced = False
    if proc.job is None:
        return {"pid": proc.pid, "exit_code": proc.code, "reaped": True, "forced": False}
    try:
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
            except OSError:
                if proc.poll() is None:
                    raise
        deadline = time.monotonic() + grace
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if proc.poll() is None:
            forced = True
            proc.abort()
        else:
            proc.finish(time.monotonic() + owned.CLEANUP_SECONDS)
            proc.close()
    except BaseException:
        if proc.job is not None:
            proc.abort()
        raise
    return {"pid": proc.pid, "exit_code": proc.code, "reaped": True, "forced": forced}


def _text(output):
    return VT.sub(b"", output).replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _bytes(value):
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def wallet_cli(binary, arguments, prompts, log_path, timeout, check=True):
    argv = [str(binary), *map(str, arguments)]
    cwd = Path.cwd()
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("HEGEMON_") and k.upper() not in ("PQ_IDENTITY_SEED", "PQ_IDENTITY_SEED_PATH")}
    env.update(RAYON_NUM_THREADS="1", RUST_LOG="warn")
    owned.validate_invocation(argv, cwd, env)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("wallet requires a positive timeout")
    prompts = [(_bytes(needle), _bytes(answer)) for needle, answer in prompts]
    if any(not needle.strip() or not answer or len(answer) > 256
           or any(ch in answer for ch in (b"\r", b"\n", b"\0")) for needle, answer in prompts):
        raise ValueError("invalid wallet prompt or answer")

    kernel = ConsoleKernel()
    started = time.monotonic()
    deadline = started + timeout
    output = bytearray()
    changed = threading.Event()
    lock = threading.Lock()
    overflow = threading.Event()
    read_errors = []

    # Continue draining while closing the pseudoconsole. On Windows Server
    # 2022 ClosePseudoConsole is synchronous and may emit a final screen update.
    def drain(stream):
        try:
            with stream:
                while chunk := stream.read(65536):
                    with lock:
                        free = OUTPUT_LIMIT - len(output)
                        output.extend(chunk[:free])
                        if len(chunk) > free:
                            overflow.set()
                    changed.set()
        except OSError as error:
            # The pipe closes when the pseudoconsole is torn down.
            if getattr(error, "winerror", None) != 109 and error.errno != 32:
                read_errors.append(error)
        finally:
            changed.set()

    sent = consumed = 0
    actor = None
    reader = None
    with ExitStack() as stack:
        in_read, in_write = os.pipe()
        writer = stack.enter_context(os.fdopen(in_write, "wb", buffering=0))
        console_input = stack.enter_context(os.fdopen(in_read, "rb", buffering=0))
        out_read, out_write = os.pipe()
        console_output = stack.enter_context(os.fdopen(out_write, "wb", buffering=0))
        output_stream = stack.enter_context(os.fdopen(out_read, "rb", buffering=0))
        try:
            kernel.open_console(console_input.fileno(), console_output.fileno())
            reader = threading.Thread(target=drain, args=(output_stream,), daemon=True)
            reader.start()
            actor = owned.WindowsProcess(argv, cwd, env, (), kernel=kernel)
            console_input.close()
            console_output.close()
            while actor.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Windows wallet CLI timed out")
                if overflow.is_set() or read_errors or not reader.is_alive():
                    raise RuntimeError("Windows wallet terminal disconnected or exceeded output limit")
                if changed.wait(min(remaining, 0.05)):
                    changed.clear()
                    if sent < len(prompts):
                        with lock:
                            visible = _text(output)
                        # ConPTY can elide trailing spaces at the cursor.
                        needle, answer = prompts[sent]
                        needle = needle.rstrip(b" ")
                        index = visible.find(needle, consumed)
                        if index >= 0:
                            if writer.write(answer + b"\r") != len(answer) + 1:
                                raise RuntimeError("Windows wallet terminal accepted partial input")
                            sent += 1
                            consumed = index + len(needle)
            actor.finish(deadline)
            actor.close()
        finally:
            try:
                if actor is not None and actor.job is not None:
                    actor.abort()
            finally:
                console_input.close()
                console_output.close()
                writer.close()
                if reader is None or not reader.is_alive():
                    output_stream.close()
                kernel.close_console()
                if reader is not None:
                    reader.join(owned.CLEANUP_SECONDS)
                    if reader.is_alive():
                        raise RuntimeError("Windows wallet console reader did not exit")
    if overflow.is_set() or read_errors:
        raise RuntimeError("Windows wallet terminal output incomplete")
    visible = _text(output)
    for _, answer in prompts:
        visible = visible.replace(answer, b"<redacted>")
    with Path(log_path).open("xb") as log:
        log.write(visible)
    if check and (actor.code != 0 or sent != len(prompts)):
        raise RuntimeError(f"wallet failed or exited before its expected prompts; see {Path(log_path).name}")
    return visible.decode("utf-8", "replace"), {
        "pid": actor.pid, "exit_code": actor.code, "elapsed_seconds": time.monotonic() - started,
        "prompts_answered": sent, "log_sha256": hashlib.sha256(visible).hexdigest(),
    }
