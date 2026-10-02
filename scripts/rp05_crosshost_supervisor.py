#!/usr/bin/env python3
"""Remote SOURCE-only test broker. It never starts or changes a testnet service."""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

PREFIX = "HEGEMON_RETAINED_SMZ9_SOCKET_V1 "
LAUNCH_ID = (1 << 64) - 2
EXIT_ID = (1 << 64) - 3
CHILD_TEST = "native::poseidon2_v8_verifier::tests::retained_rp03_socket_child"
MAX_LINE = 8 * 1024 * 1024
STOP_TIMEOUT = 40
FAILURE_TIMEOUT = 3


def enable_subreaper():
    # Linux reparents orphaned descendants to this exact broker, allowing
    # cleanup/reaping without treating a recycled numeric process-group ID as
    # authority. Other platforms are used only by the fake-process unit tests.
    if sys.platform != "linux":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot own orphaned test descendants")
    return True


def proc_identity(pid):
    fields = Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))


def reap_adopted(session):
    if sys.platform != "linux":
        return
    deadline = time.monotonic() + 5
    while True:
        found = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                identity = proc_identity(pid)
                # Only our real adopted children in the created node session.
                if identity[0] != os.getpid() or identity[2] != session:
                    continue
                found = True
                descriptor = os.pidfd_open(pid) if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal") else None
                try:
                    if proc_identity(pid) != identity:
                        raise ChildProcessError("adopted descendant identity changed")
                    if descriptor is not None:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    else:
                        # An unreaped direct child retains its PID, preventing reuse.
                        os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            except (FileNotFoundError, ProcessLookupError, ChildProcessError):
                continue
        if not found:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("owned adopted descendants failed cleanup deadline")


def read_frame(stream):
    raw = stream.readline(MAX_LINE + 1)
    if not raw:
        return None
    if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
        raise ValueError("oversized or unterminated supervisor frame")
    return raw


def digest(path):
    result = hashlib.sha512()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def validate_launch(request):
    required = {"session", "workspace", "executable", "executable_sha512", "manifest", "manifest_sha512", "profile", "artifact_role"}
    if set(request) != required:
        raise ValueError("exact supervisor launch grammar required")
    if len(request["session"]) != 32 or any(c not in "0123456789abcdef" for c in request["session"]):
        raise ValueError("invalid control session")
    for field in ("executable_sha512", "manifest_sha512"):
        if len(request[field]) != 128 or any(c not in "0123456789abcdef" for c in request[field]):
            raise ValueError("invalid expected digest")
    workspace = Path(request["workspace"]).resolve(strict=True)
    executable = Path(request["executable"]).resolve(strict=True)
    temporary = Path(tempfile.gettempdir()).resolve()
    if temporary not in workspace.parents or workspace == temporary:
        raise ValueError("remote workspace must be a dedicated temporary child")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("remote executable must be an executable regular file")
    relative = Path(request["manifest"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("manifest must be workspace relative")
    manifest = (workspace / relative).resolve(strict=True)
    if workspace not in manifest.parents or not manifest.is_file():
        raise ValueError("manifest escaped workspace")
    if request["profile"] not in ("SMZA", "SMZ9"):
        raise ValueError("unsupported test profile")
    if request["artifact_role"] not in ("retained_proof_primary", "retained_proof_independent"):
        raise ValueError("unsupported artifact role")
    if digest(executable) != request["executable_sha512"] or digest(manifest) != request["manifest_sha512"]:
        raise ValueError("remote executable or exact manifest bytes changed")
    return workspace, executable, manifest


def listener_closed(address):
    host, port = address.rsplit(":", 1)
    if host != "127.0.0.1" or not 0 < int(port) < 65536:
        raise ValueError("remote child listener must be numeric IPv4 loopback")
    with socket.socket() as probe:
        probe.settimeout(0.25)
        return probe.connect_ex((host, int(port))) != 0


def supervise(request, input_stream=sys.stdin.buffer, output_stream=sys.stdout.buffer):
    workspace, executable, manifest = validate_launch(request)
    if platform.system() != "Linux":
        raise ValueError("remote SOURCE supervisor requires Linux")
    subreaper = enable_subreaper()
    session = request["session"]
    write_lock = threading.Lock()

    def emit(identifier, result):
        raw = (PREFIX + session + " " + json.dumps({"session": session, "id": identifier, "result": result}, separators=(",", ":")) + "\n").encode()
        with write_lock:
            output_stream.write(raw)
            output_stream.flush()

    base = tempfile.mkdtemp(prefix="hegemon-rp05-crosshost-")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        p2p = "127.0.0.1:" + str(reservation.getsockname()[1])
    environment = {k: v for k, v in os.environ.items() if not k.startswith("HEGEMON_") and k not in ("PQ_IDENTITY_SEED", "PQ_IDENTITY_SEED_PATH")}
    environment.update({
        "HEGEMON_SEEDS": "", "HEGEMON_MAX_PEERS": "4", "HEGEMON_MINE": "0",
        "HEGEMON_MINE_THREADS": "1", "HEGEMON_BOOTSTRAP_AUTHORING": "0",
        "HEGEMON_TEST_RETAINED_SMZ9_CHILD_SESSION": session,
        "HEGEMON_TEST_RETAINED_CARRIER_PROFILE": request["profile"],
        "HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512": request["manifest_sha512"],
        "HEGEMON_TEST_RETAINED_SMZ9_CHILD_ROLE": "source",
        "HEGEMON_TEST_RETAINED_SMZ9_CHILD_BASE_PATH": base,
        "HEGEMON_TEST_RETAINED_SMZ9_CHILD_P2P_ADDR": p2p,
        "HEGEMON_TEST_RETAINED_SMZ9_CHILD_ARTIFACT_ROLE": request["artifact_role"],
        "HEGEMON_TEST_CROSSHOST_SOURCE": "1",
        ("HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH" if request["profile"] == "SMZA" else "HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_PATH"): request["manifest"],
    })
    child = subprocess.Popen([str(executable), "--ignored", "--exact", CHILD_TEST, "--nocapture", "--test-threads=1"], cwd=workspace, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    pidfd = None
    owned_group = None
    clean_exit = False
    rpc = []
    reader_errors = []

    def relay(source, destination, is_stdout):
        try:
            while True:
                raw = read_frame(source)
                if raw is None:
                    return
                if is_stdout and raw.startswith((PREFIX + session + " ").encode()):
                    frame = json.loads(raw[len(PREFIX + session + " "):])
                    if frame["id"] == 0:
                        rpc.append(frame["result"]["rpc"])
                with write_lock:
                    destination.write(raw)
                    destination.flush()
        except Exception as error:
            reader_errors.append(str(error))

    readers = []
    try:
        pgid = os.getpgid(child.pid)
        if pgid != child.pid:
            raise ValueError("remote node did not acquire its own process group")
        owned_group = pgid
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                pidfd = os.pidfd_open(child.pid)
            except OSError:
                pidfd = None
        identity = {"pid": child.pid, "process_group": pgid, "p2p": p2p, "base": base, "system": platform.system(), "machine": platform.machine(), "workspace": str(workspace), "executable": str(executable), "executable_sha512": digest(executable), "manifest_sha512": digest(manifest), "broker_sha512": digest(__file__), "seeds_empty": True, "pidfd_bound": pidfd is not None, "subreaper_enabled": subreaper}
        emit(LAUNCH_ID, identity)
        for source, destination, is_stdout in ((child.stdout, output_stream, True), (child.stderr, sys.stderr.buffer, False)):
            reader = threading.Thread(target=relay, args=(source, destination, is_stdout), daemon=True)
            reader.start()
            readers.append(reader)
        child.stdin.write((json.dumps({"session": session, "pid": child.pid, "process_group": pgid}) + "\n").encode())
        child.stdin.flush()
        while True:
            if reader_errors:
                raise ValueError("remote reader failed: " + repr(reader_errors))
            if child.poll() is not None:
                raise ChildProcessError("remote node exited before supervised clean shutdown")
            if not select.select([input_stream], [], [], 0.2)[0]:
                continue
            raw = read_frame(input_stream)
            if raw is None:
                raise EOFError("SSH control input closed before remote clean shutdown")
            frame = json.loads(raw)
            if frame == {"session": session, "supervisor": "terminate"}:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                else:
                    if child.poll() is not None or os.getpgid(child.pid) != child.pid:
                        raise ChildProcessError("remote node ownership changed before signal")
                    os.kill(child.pid, signal.SIGTERM)
                child.stdin.close()
                status = child.wait(timeout=STOP_TIMEOUT)
                for reader in readers:
                    reader.join(timeout=2)
                if reader_errors or any(reader.is_alive() for reader in readers):
                    raise ValueError("remote readers failed or remained live: " + repr(reader_errors))
                try:
                    os.killpg(pgid, 0)
                    group_absent = False
                except ProcessLookupError:
                    group_absent = True
                if not rpc:
                    raise ValueError("remote node never reported its real RPC listener")
                receipt = dict(identity, exit_code=status, reaped=True, process_group_absent=group_absent, rpc_closed=listener_closed(rpc[0]), p2p_closed=listener_closed(p2p), forced_kill=False, executable_unchanged=digest(executable) == request["executable_sha512"], manifest_unchanged=digest(manifest) == request["manifest_sha512"], broker_unchanged=digest(__file__) == identity["broker_sha512"])
                if status != 0 or not all(receipt[key] for key in ("process_group_absent", "rpc_closed", "p2p_closed", "executable_unchanged", "manifest_unchanged", "broker_unchanged")):
                    raise ValueError("remote node failed clean exit checks: " + repr(receipt))
                emit(EXIT_ID, receipt)
                clean_exit = True
                return
            if frame.get("session") != session or set(frame) != {"session", "id", "command"}:
                raise ValueError("foreign or malformed remote node control frame")
            child.stdin.write(raw)
            child.stdin.flush()
    finally:
        # Failure-only cleanup is never evidence of a clean node exit.
        if child.poll() is None:
            if os.getpgid(child.pid) != child.pid:
                raise ChildProcessError("remote cleanup process group ownership changed")
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            else:
                os.kill(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=FAILURE_TIMEOUT)
            except subprocess.TimeoutExpired:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    os.kill(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
        if not clean_exit and owned_group is not None:
            reap_adopted(owned_group)
        for reader in readers:
            reader.join(timeout=2)
        if pidfd is not None:
            os.close(pidfd)


def main():
    launch = read_frame(sys.stdin.buffer)
    if launch is None:
        raise EOFError("missing supervisor launch frame")
    supervise(json.loads(launch))


if __name__ == "__main__":
    main()
