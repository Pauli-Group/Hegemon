"""Bounded broker tests with fake processes, never a proof/node qualification."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "rp05_crosshost_supervisor.py"
SPEC = importlib.util.spec_from_file_location("crosshost", SCRIPT)
BROKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BROKER)

FAKE = r'''
import json, os, signal, socket, subprocess, sys, time
session = os.environ["HEGEMON_TEST_RETAINED_SMZ9_CHILD_SESSION"]
prefix = "HEGEMON_RETAINED_SMZ9_SOCKET_V1 " + session + " "
mode = os.environ.get("FAKE_CROSSHOST_MODE", "clean")
if mode == "early": sys.exit(7)
startup = json.loads(sys.stdin.readline())
assert startup == {"session": session, "pid": os.getpid(), "process_group": os.getpgrp()}
assert os.environ["HEGEMON_SEEDS"] == ""
assert "HEGEMON_TEST_RETAINED_SMZ9_OUTER_PGID" not in os.environ
rpc = socket.socket(); rpc.bind(("127.0.0.1", 0)); rpc.listen()
p2p = socket.socket(); p2p.bind(("127.0.0.1", int(os.environ["HEGEMON_TEST_RETAINED_SMZ9_CHILD_P2P_ADDR"].split(":")[1]))); p2p.listen()
def emit(identifier, result):
    print(prefix + json.dumps({"session": session, "id": identifier, "result": result}), flush=True)
def stop(*_):
    rpc.close(); p2p.close()
    emit((1 << 64) - 1, {"stopped": True, "authority_denied": True})
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if mode == "ignore" else stop)
emit(0, {"pid": os.getpid(), "rpc": "127.0.0.1:" + str(rpc.getsockname()[1])})
if mode == "descendant":
    code = "import signal,socket,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); s=socket.socket(fileno=int(sys.argv[1])); time.sleep(120)"
    descendant = subprocess.Popen([sys.executable, "-c", code, str(p2p.fileno())], pass_fds=(p2p.fileno(),))
    emit(20, {"descendant_pid": descendant.pid, "p2p": os.environ["HEGEMON_TEST_RETAINED_SMZ9_CHILD_P2P_ADDR"]})
    os._exit(7)
if mode == "malformed":
    print(prefix + "{", flush=True)
if mode == "oversized":
    print(prefix + "x" * (8 * 1024 * 1024), flush=True)
for raw in sys.stdin:
    request = json.loads(raw)
    emit(request["id"], {"tracked_idle": True})
while True: time.sleep(.01)
'''


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rp05-broker-test-")
        self.workspace = Path(self.temporary.name).resolve()
        self.executable = self.workspace / "fake-child"
        self.executable.write_text("#!" + sys.executable + "\n" + FAKE)
        self.executable.chmod(0o700)
        self.manifest = self.workspace / "pair.json"
        self.manifest.write_text('{"exact": "bytes"}\n')
        self.launch = dict(session="a" * 32, workspace=str(self.workspace), executable=str(self.executable), executable_sha512=BROKER.digest(self.executable), manifest="pair.json", manifest_sha512=BROKER.digest(self.manifest), profile="SMZA", artifact_role="retained_proof_primary")
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        self.temporary.cleanup()

    def start(self, mode="clean"):
        code = "import runpy; d=runpy.run_path(" + repr(str(SCRIPT)) + "); d['supervise'].__globals__['platform'].system=lambda:'Linux'; d['supervise'].__globals__['STOP_TIMEOUT']=.15; d['supervise'].__globals__['FAILURE_TIMEOUT']=.15; d['main']()"
        environment = dict(os.environ, FAKE_CROSSHOST_MODE=mode, HEGEMON_SEEDS="active-service-must-not-be-inherited", HEGEMON_TEST_RETAINED_SMZ9_OUTER_PGID="999")
        process = subprocess.Popen([sys.executable, "-B", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        self.processes.append(process)
        self.send(process, self.launch)
        return process

    def send(self, process, frame):
        process.stdin.write((json.dumps(frame) + "\n").encode())
        process.stdin.flush()

    def frame(self, process):
        raw = process.stdout.readline()
        self.assertTrue(raw.startswith((BROKER.PREFIX + self.launch["session"] + " ").encode()), raw if raw else process.stderr.read())
        return json.loads(raw[len(BROKER.PREFIX + self.launch["session"] + " "):])

    def test_true_remote_pid_and_independent_clean_receipt(self):
        process = self.start()
        identity = self.frame(process)
        ready = self.frame(process)
        self.assertEqual(identity["id"], BROKER.LAUNCH_ID)
        self.assertNotEqual(identity["result"]["pid"], process.pid)
        self.assertEqual(identity["result"]["pid"], identity["result"]["process_group"])
        self.assertEqual(ready["result"]["pid"], identity["result"]["pid"])
        self.send(process, dict(session=self.launch["session"], id=1, command={"kind": "shutdown"}))
        self.assertEqual(self.frame(process)["id"], 1)
        self.send(process, dict(session=self.launch["session"], supervisor="terminate"))
        self.assertEqual(self.frame(process)["id"], (1 << 64) - 1)
        receipt = self.frame(process)
        self.assertEqual(receipt["id"], BROKER.EXIT_ID)
        self.assertEqual(receipt["result"]["exit_code"], 0)
        for key in ("reaped", "process_group_absent", "rpc_closed", "p2p_closed", "executable_unchanged", "manifest_unchanged"):
            self.assertTrue(receipt["result"][key], key)
        self.assertFalse(receipt["result"]["forced_kill"])
        self.assertEqual(process.wait(timeout=5), 0, process.stderr.read())

    def test_early_exit_never_produces_success_receipt(self):
        process = self.start("early")
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertNotIn(b'"reaped":true', process.stdout.read())

    def test_disconnect_cleans_node_without_clean_credit(self):
        process = self.start()
        identity = self.frame(process)["result"]
        self.frame(process)
        process.stdin.close()
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertNotIn(b'"reaped":true', process.stdout.read())
        with self.assertRaises(ProcessLookupError):
            os.kill(identity["pid"], 0)

    def test_timeout_kills_reaps_without_clean_credit(self):
        process = self.start("ignore")
        identity = self.frame(process)["result"]
        self.frame(process)
        self.send(process, dict(session=self.launch["session"], supervisor="terminate"))
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertNotIn(b'"reaped":true', process.stdout.read())
        with self.assertRaises(ProcessLookupError):
            os.kill(identity["pid"], 0)

    @unittest.skipUnless(sys.platform == "linux", "Linux adopted-descendant ownership requires /proc and subreaper")
    def test_exited_leader_descendant_listener_is_reaped_without_clean_credit(self):
        process = self.start("descendant")
        self.frame(process)
        self.frame(process)
        descendant = self.frame(process)["result"]
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertNotIn(b'"reaped":true', process.stdout.read())
        with self.assertRaises(ProcessLookupError):
            os.kill(descendant["descendant_pid"], 0)
        self.assertTrue(BROKER.listener_closed(descendant["p2p"]))

    def test_child_reader_errors_surface_without_waiting_for_parent_input(self):
        for mode in ("malformed", "oversized"):
            process = self.start(mode)
            identity = self.frame(process)["result"]
            self.frame(process)
            self.assertNotEqual(process.wait(timeout=5), 0)
            self.assertNotIn(b'"reaped":true', process.stdout.read())
            with self.assertRaises(ProcessLookupError):
                os.kill(identity["pid"], 0)

    def test_changed_manifest_or_executable_rejected_before_spawn(self):
        for field in ("manifest_sha512", "executable_sha512"):
            changed = dict(self.launch, **{field: "b" * 128})
            with self.assertRaisesRegex(ValueError, "changed"):
                BROKER.validate_launch(changed)

    def test_launch_grammar_rejects_extra_role_path_and_session(self):
        for changed in (dict(self.launch, role="relay"), dict(self.launch, artifact_role="anything"), dict(self.launch, manifest="../pair.json"), dict(self.launch, session="../"), dict(self.launch, workspace="/")):
            with self.assertRaises(ValueError):
                BROKER.validate_launch(changed)

    def test_oversized_and_partial_frames_rejected(self):
        self.assertEqual(BROKER.read_frame(io.BytesIO(b"{}\n")), b"{}\n")
        self.assertIsNone(BROKER.read_frame(io.BytesIO(b"")))
        for raw in (b"{}", b"x" * (BROKER.MAX_LINE + 1) + b"\n"):
            with self.assertRaises(ValueError):
                BROKER.read_frame(io.BytesIO(raw))


if __name__ == "__main__":
    unittest.main()
