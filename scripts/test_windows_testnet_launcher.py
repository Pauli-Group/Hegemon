#!/usr/bin/env python3
"""Exercise the Windows CMD launcher with a fake node and loopback-only RPC.

Run this on Windows with Python and rustc installed. The Rust fixture uses only
the standard library; no real node, wallet, PowerShell, or external network is
used. Non-Windows hosts skip these checks rather than claim Windows coverage.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import itertools
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
LAUNCHER = REPOSITORY / "testnet-release" / "testnet-start.cmd"
NODE_NAME = "hegemon-node-windows-x86_64.exe"
APPROVED_SEEDS = "hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
EXPECTED_GENESIS = "0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59"
ENV_NAMES = (
    "HEGEMON_SEEDS", "HEGEMON_MINE", "HEGEMON_BOOTSTRAP_AUTHORING",
    "HEGEMON_MINER_ADDRESS", "HEGEMON_MINE_THREADS", "RUST_LOG", "NO_COLOR",
)
GENESIS_REPLY = json.dumps(
    {"id": 3, "jsonrpc": "2.0", "result": EXPECTED_GENESIS},
    separators=(",", ":"), sort_keys=True,
).encode("utf-8")
FAKE_NODE = r'''
use std::{env, fs, process};
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let names = ["HEGEMON_SEEDS", "HEGEMON_MINE", "HEGEMON_BOOTSTRAP_AUTHORING",
        "HEGEMON_MINER_ADDRESS", "HEGEMON_MINE_THREADS", "RUST_LOG", "NO_COLOR"];
    let mut records = vec![args.len().to_string()];
    records.extend(args);
    for name in names {
        records.push(name.into());
        records.push(env::var(name).unwrap_or_else(|_| "<unset>".into()));
    }
    fs::write(env::var("TESTNET_FIXTURE_NODE_LOG").unwrap(), records.join("\0")).unwrap();
    process::exit(env::var("TESTNET_FIXTURE_EXIT_CODE").unwrap_or_else(|_| "0".into())
        .parse().unwrap());
}
'''


class TestWindowsLauncherSource(unittest.TestCase):
    """Portable contract checks; these do not claim CMD runtime coverage."""

    @classmethod
    def setUpClass(cls):
        cls.source = LAUNCHER.read_text(encoding="utf-8")
        cls.lines = cls.source.splitlines()

    def test_native_launcher_has_no_script_policy_or_dynamic_evaluation(self):
        self.assertNotRegex(self.source.lower(), r"powershell|pwsh|executionpolicy|encodedcommand")
        self.assertIn("setlocal EnableExtensions DisableDelayedExpansion", self.source)
        self.assertNotRegex(self.source.lower(), r"enabledelayedexpansion|\bpause\b|cmd(?:\.exe)?\s+/c")
        self.assertEqual(re.findall(r"(?im)^call\s+(.+)$", self.source),
                         [":validate_port", ":validate_port"])

    def test_node_profile_and_exit_are_preserved(self):
        launches = [line for line in self.lines if line.startswith('"%launcher_binary%" ')]
        self.assertEqual(launches, [
            '"%launcher_binary%" --dev --base-path "%launcher_data_argument%" '
            '--rpc-methods safe --rpc-port %launcher_rpc_port% --port %launcher_port% '
            '--name HegemonTestnet',
        ])
        self.assertIn('set "launcher_binary=%~dp0' + NODE_NAME + '"', self.lines)
        self.assertIn('set "HEGEMON_SEEDS=' + APPROVED_SEEDS + '"', self.lines)
        self.assertIn('set "launcher_mine=0"', self.lines)
        self.assertIn('set "HEGEMON_BOOTSTRAP_AUTHORING=0"', self.lines)
        self.assertIn('set "launcher_node_exit=%errorlevel%"', self.lines)
        self.assertIn('endlocal & exit /b %launcher_node_exit%', self.lines)
        self.assertNotRegex(self.source, r'(?im)^set\s+"?HEGEMON_(?:MINER_ADDRESS|MINE_THREADS)=')

    def test_port_input_is_filtered_before_arithmetic(self):
        validator = self.source.split(":validate_port\n", 1)[1]
        for digit in "0123456789":
            self.assertIn(":" + digit + "=%", validator)
        reject = validator.index("if defined launcher_port_invalid exit /b 1")
        arithmetic = validator.index("set /a launcher_valid_port=")
        self.assertLess(reject, arithmetic)
        self.assertIn('if not "%launcher_port_input:~5,1%"=="" exit /b 1', validator)
        self.assertIn("if %launcher_valid_port% GTR 65535 exit /b 1", validator)
        self.assertIn(":trim_port_zeroes", validator)

    def test_status_uses_fixed_curl_and_only_validated_loopback_url(self):
        self.assertIn('set "launcher_curl=%SystemRoot%\\System32\\curl.exe"', self.lines)
        requests = [line for line in self.lines if line.startswith('"%launcher_curl%" ')]
        self.assertEqual(len(requests), 2)
        for request in requests:
            self.assertIn('--disable --noproxy "*" --proto =http', request)
            self.assertIn('--fail --silent --show-error --max-time 15', request)
            self.assertTrue(request.endswith('"http://127.0.0.1:%launcher_rpc_port%/"'))
        self.assertIn('if not defined launcher_status_created exit /b 1', self.lines)
        self.assertIn('set "launcher_status_created="', self.lines)
        self.assertIn('set "launcher_status_dir="', self.lines)
        self.assertNotRegex(self.source.lower(), r"\brmdir\s+/s|\brd\s+/s")

    def test_value_options_reject_switches_before_shifting(self):
        value_handler = self.source.split(":argument_value\n", 1)[1].split(":arguments_parsed", 1)[0]
        for switch in ("-Mine", "-Status", "-Help", "-DataDir", "-RpcPort", "-Port"):
            check = 'if /i "%~2"=="' + switch + '" goto missing_argument_value'
            self.assertIn(check, value_handler)
            self.assertLess(value_handler.index(check), value_handler.index("shift"))

    def test_genesis_verification_compares_complete_json_bytes(self):
        prefix = '<nul set /p "='
        suffix = '" > "%launcher_status_dir%\\expected.json"'
        templates = [line[len(prefix):-len(suffix)] for line in self.lines
                     if line.startswith(prefix) and line.endswith(suffix)]
        keys = ("id", "jsonrpc", "result")
        values = {"id": 3, "jsonrpc": "2.0", "result": EXPECTED_GENESIS}
        expected = {
            json.dumps({key: values[key] for key in order}, separators=(",", ":"))
            for order in itertools.permutations(keys)
        }
        rendered = [item.replace("%launcher_expected_genesis%", EXPECTED_GENESIS)
                    for item in templates]
        self.assertEqual(len(rendered), 6)
        self.assertEqual(set(rendered), expected)
        compares = [line for line in self.lines if '\\fc.exe" /b ' in line]
        self.assertEqual(len(compares), 6)
        for compare in compares:
            self.assertIn('"%launcher_status_dir%\\genesis.json" '
                          '"%launcher_status_dir%\\expected.json" >nul', compare)
        self.assertNotRegex(self.source, r'findstr[^\n]*launcher_expected_genesis')


@unittest.skipUnless(os.name == "nt", "CMD launcher behavior requires Windows")
class TestWindowsTestnetLauncher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler_fixture = tempfile.TemporaryDirectory(prefix="hegemon-cmd-compiler-")
        cls.addClassCleanup(cls.compiler_fixture.cleanup)
        compiler_root = Path(cls.compiler_fixture.name)
        source = compiler_root / "fake_node.rs"
        source.write_text(FAKE_NODE, encoding="utf-8")
        cls.compiled_node = compiler_root / NODE_NAME
        rustc = shutil.which("rustc")
        if rustc is None:
            raise AssertionError("Windows launcher checks require installed rustc")
        compilation = subprocess.run(
            [rustc, str(source), "-o", str(cls.compiled_node)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if compilation.returncode:
            raise AssertionError(compilation.stdout + compilation.stderr)

    def setUp(self):
        self.assertTrue(LAUNCHER.is_file(), f"Missing release launcher: {LAUNCHER}")
        fixture = tempfile.TemporaryDirectory(prefix="hegemon-cmd-test-")
        self.addCleanup(fixture.cleanup)
        self.fixture_root = Path(fixture.name)
        # Delayed expansion and CMD metacharacters must not corrupt these paths.
        self.bundle = self.fixture_root / "download ! folder & (spaces)"
        self.bundle.mkdir()
        self.launcher = self.bundle / "testnet-start.cmd"
        shutil.copyfile(LAUNCHER, self.launcher)
        shutil.copyfile(self.compiled_node, self.bundle / NODE_NAME)
        self.caller = self.fixture_root / "unrelated caller ! & (directory)"
        self.caller.mkdir()
        self.profile = self.fixture_root / "user profile ! & (spaces)"
        self.profile.mkdir()
        self.node_log = self.fixture_root / "node-call.bin"
        self.rpc_requests = []
        self.environment = os.environ.copy()
        self.environment.update({
            "USERPROFILE": str(self.profile),
            "TESTNET_FIXTURE_NODE_LOG": str(self.node_log),
            "TESTNET_FIXTURE_EXIT_CODE": "0",
            "HEGEMON_SEEDS": "unapproved.example:1234",
            "HEGEMON_MINE": "1",
            "HEGEMON_BOOTSTRAP_AUTHORING": "1",
            "HEGEMON_MINER_ADDRESS": "hgm1fixture_public_receive_address",
            "HEGEMON_MINE_THREADS": "3",
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        self.cmd = str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe")

    def run_launcher(self, *args, overrides=None):
        if self.node_log.exists():
            self.node_log.unlink()
        environment = self.environment.copy()
        for name, value in (overrides or {}).items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        # CMD's /s /c requires an extra outer quote when the executable is quoted.
        # Quote every argument so hostile port inputs remain data at this boundary.
        tokens = [str(self.launcher), *args]
        if any('"' in token for token in tokens):
            raise ValueError("Fixture arguments must not contain embedded quotes")
        command = '"' + " ".join('"' + token + '"' for token in tokens) + '"'
        # Supply the command line directly: subprocess.list2cmdline escapes its
        # inner quotes for the C runtime, whereas CMD has its own quote rules.
        return subprocess.run(
            '"' + self.cmd + '" /d /v:off /s /c ' + command,
            executable=self.cmd,
            cwd=self.caller, env=environment, capture_output=True,
            text=True, timeout=20, check=False,
        )

    def read_node_call(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.node_log.is_file(), result.stdout + result.stderr)
        records = self.node_log.read_bytes().decode("utf-8").split("\0")
        arg_count = int(records[0])
        args = records[1:arg_count + 1]
        pairs = records[arg_count + 1:]
        self.assertEqual(len(pairs), 2 * len(ENV_NAMES))
        return {"args": args, "env": dict(zip(pairs[::2], pairs[1::2]))}

    def assert_safe_profile(self, call):
        self.assertEqual(call["env"]["HEGEMON_SEEDS"], APPROVED_SEEDS)
        self.assertEqual(call["env"]["HEGEMON_BOOTSTRAP_AUTHORING"], "0")
        self.assertIn("--dev", call["args"])
        self.assertEqual(call["args"][call["args"].index("--rpc-methods") + 1], "safe")
        self.assertNotIn("--rpc-external", call["args"])
        self.assertNotIn("--tmp", call["args"])

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.node_log.exists(), "Rejected request must not start a node")
        self.assertFalse(self.rpc_requests, "Rejected arguments must not query RPC")

    def start_rpc(self, genesis_reply=GENESIS_REPLY, *, fail_batch=False, fail_genesis=False):
        requests = self.rpc_requests
        batch_reply = json.dumps([
            {"jsonrpc": "2.0", "id": 1, "result": {"peers": 1, "isSyncing": False}},
            {"jsonrpc": "2.0", "id": 2, "result": {"number": "0x1"}},
            {"jsonrpc": "2.0", "id": 3, "result": EXPECTED_GENESIS},
            {"jsonrpc": "2.0", "id": 4, "result": {}},
            {"jsonrpc": "2.0", "id": 5, "result": "fixture"},
        ], separators=(",", ":")).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_POST(handler):
                raw = handler.rfile.read(int(handler.headers.get("Content-Length", "0")))
                try:
                    request = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    request = {"invalid_raw_request": raw.decode("utf-8", errors="replace")}
                requests.append(request)
                is_batch = isinstance(request, list)
                status = 503 if (fail_batch if is_batch else fail_genesis) else 200
                body = batch_reply if is_batch else genesis_reply
                handler.send_response(status)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop_server)
        return str(server.server_port)

    def test_relay_resets_inherited_mining_and_uses_persistent_profile(self):
        call = self.read_node_call(self.run_launcher(overrides={"HEGEMON_MINER_ADDRESS": None}))
        self.assert_safe_profile(call)
        self.assertEqual(call["env"]["HEGEMON_MINE"], "0")
        self.assertEqual(call["args"], [
            "--dev", "--base-path", str(self.profile / ".hegemon-testnet"),
            "--rpc-methods", "safe", "--rpc-port", "9944", "--port", "30333",
            "--name", "HegemonTestnet",
        ])

    def test_explicit_mining_keeps_payout_and_thread_count(self):
        call = self.read_node_call(self.run_launcher("-mInE"))
        self.assert_safe_profile(call)
        self.assertEqual(call["env"]["HEGEMON_MINE"], "1")
        self.assertEqual(call["env"]["HEGEMON_MINER_ADDRESS"], "hgm1fixture_public_receive_address")
        self.assertEqual(call["env"]["HEGEMON_MINE_THREADS"], "3")

    def test_missing_or_blank_mining_payout_rejects(self):
        for address in (None, "", " \t "):
            with self.subTest(address=address):
                self.assert_rejected(self.run_launcher(
                    "-Mine", overrides={"HEGEMON_MINER_ADDRESS": address},
                ))

    def test_explicit_directory_with_metacharacters_and_ports_preserves_state(self):
        directory = self.fixture_root / "existing ! data & (with spaces)"
        directory.mkdir()
        retained = directory / "retained-state.txt"
        retained.write_text("retain this existing fixture", encoding="utf-8")
        call = self.read_node_call(self.run_launcher(
            "-DataDir", str(directory), "-RpcPort", "9945", "-Port", "30334",
        ))
        self.assert_safe_profile(call)
        for option, expected in (
            ("--base-path", str(directory)), ("--rpc-port", "9945"), ("--port", "30334"),
        ):
            self.assertEqual(call["args"][call["args"].index(option) + 1], expected)
        self.assertEqual(retained.read_text(encoding="utf-8"), "retain this existing fixture")
        self.assertEqual(list(directory.iterdir()), [retained])

    def test_blank_directory_rejects(self):
        for directory in ("", " \t "):
            with self.subTest(directory=directory):
                self.assert_rejected(self.run_launcher("-DataDir", directory))

    def test_invalid_ports_reject_before_node_or_rpc(self):
        for option in ("-RpcPort", "-Port"):
            for port in ("0", "65536", "not-a-port", "1&echo injected", "1|echo injected", "(1)",
                         "1!echo injected", "1>injected.txt", "1<injected.txt", "1^echo injected",
                         "%PATH%", "1=2", "+1", "-1", "1 2", "1\t2", "99999999999999999"):
                with self.subTest(option=option, port=port):
                    self.assert_rejected(self.run_launcher(option, port))
        self.assert_rejected(self.run_launcher("-Status", "-RpcPort", "0"))

    def test_unknown_or_missing_arguments_reject(self):
        for args in (("-Unknown",), ("-DataDir",), ("-RpcPort",), ("-Port",)):
            with self.subTest(args=args):
                self.assert_rejected(self.run_launcher(*args))

    def test_value_options_do_not_consume_known_switches(self):
        for option in ("-DataDir", "-RpcPort", "-Port"):
            for switch in ("-Mine", "-Status", "-Help", "-DataDir", "-RpcPort", "-Port"):
                with self.subTest(option=option, switch=switch):
                    self.assert_rejected(self.run_launcher(option, switch))

    def test_help_succeeds_without_binary_or_rpc(self):
        (self.bundle / NODE_NAME).unlink()
        result = self.run_launcher("-Help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Usage", result.stdout)
        self.assertFalse(self.node_log.exists())
        self.assertFalse(self.rpc_requests)

    def test_missing_binary_rejects(self):
        (self.bundle / NODE_NAME).unlink()
        self.assert_rejected(self.run_launcher())

    def test_node_exit_status_is_preserved(self):
        result = self.run_launcher(overrides={"TESTNET_FIXTURE_EXIT_CODE": "42"})
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertTrue(self.node_log.exists())

    def test_decimal_ports_with_leading_zeroes_are_not_octal(self):
        call = self.read_node_call(self.run_launcher("-RpcPort", "00009948", "-Port", "000030338"))
        self.assertEqual(call["args"][call["args"].index("--rpc-port") + 1], "9948")
        self.assertEqual(call["args"][call["args"].index("--port") + 1], "30338")

    def test_trailing_backslash_is_preserved_in_node_argv(self):
        directory = str(self.profile) + "\\"
        call = self.read_node_call(self.run_launcher("-DataDir", directory))
        self.assertEqual(call["args"][call["args"].index("--base-path") + 1], directory)

    def test_caller_environment_is_restored_after_call(self):
        wrapper = self.bundle / "testnet-caller.cmd"
        environment_log = self.fixture_root / "caller-environment.txt"
        wrapper.write_text(
            '@echo off\nsetlocal DisableDelayedExpansion\n'
            'call "%~dp0testnet-start.cmd"\nset "caller_exit=%errorlevel%"\n'
            'set HEGEMON_SEEDS > "%TESTNET_FIXTURE_CALLER_ENV%"\n'
            'set HEGEMON_MINE >> "%TESTNET_FIXTURE_CALLER_ENV%"\n'
            'set HEGEMON_BOOTSTRAP_AUTHORING >> "%TESTNET_FIXTURE_CALLER_ENV%"\n'
            'exit /b %caller_exit%\n', encoding="utf-8",
        )
        original_launcher = self.launcher
        self.launcher = wrapper
        try:
            call = self.read_node_call(self.run_launcher(overrides={
                "TESTNET_FIXTURE_CALLER_ENV": str(environment_log),
            }))
        finally:
            self.launcher = original_launcher
        self.assert_safe_profile(call)
        observed = dict(line.split("=", 1) for line in environment_log.read_text().splitlines())
        for name in ("HEGEMON_SEEDS", "HEGEMON_MINE", "HEGEMON_BOOTSTRAP_AUTHORING"):
            self.assertEqual(observed[name], self.environment[name])

    def test_matching_status_uses_safe_loopback_rpc_without_node_binary(self):
        (self.bundle / NODE_NAME).unlink()
        result = self.run_launcher("-Status", "-RpcPort", self.start_rpc())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.node_log.exists())
        self.assertIn(EXPECTED_GENESIS, result.stdout)
        self.assertEqual(len(self.rpc_requests), 2)
        batch, genesis = self.rpc_requests
        self.assertEqual([request["method"] for request in batch], [
            "system_health", "chain_getHeader", "chain_getBlockHash",
            "hegemon_miningStatus", "system_version",
        ])
        self.assertEqual(batch[2]["params"], [0])
        self.assertEqual(genesis, {
            "jsonrpc": "2.0", "id": 3, "method": "chain_getBlockHash", "params": [0],
        })

    def test_dispatcher_order_genesis_reply_is_accepted(self):
        reply = json.dumps({"jsonrpc": "2.0", "result": EXPECTED_GENESIS, "id": 3},
                           separators=(",", ":")).encode("utf-8")
        result = self.run_launcher("-Status", "-RpcPort", self.start_rpc(reply))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.node_log.exists())

    def test_all_compact_json_member_orders_are_accepted(self):
        values = {"id": 3, "jsonrpc": "2.0", "result": EXPECTED_GENESIS}
        for order in itertools.permutations(values):
            with self.subTest(order=order):
                self.rpc_requests.clear()
                reply = json.dumps({key: values[key] for key in order},
                                   separators=(",", ":")).encode("utf-8")
                result = self.run_launcher("-Status", "-RpcPort", self.start_rpc(reply))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.node_log.exists())

    def test_status_rejects_mismatching_or_untrusted_genesis_response(self):
        replies = {
            "wrong genesis": GENESIS_REPLY.replace(EXPECTED_GENESIS.encode(), b"0xwrong"),
            "RPC error containing expected hash": json.dumps({
                "id": 3, "jsonrpc": "2.0", "error": {"code": -1, "message": EXPECTED_GENESIS},
            }, separators=(",", ":"), sort_keys=True).encode(),
            "unrelated field containing expected hash": json.dumps({
                "id": 3, "jsonrpc": "2.0", "result": "0xwrong", "other": EXPECTED_GENESIS,
            }, separators=(",", ":"), sort_keys=True).encode(),
            "result plus error": GENESIS_REPLY[:-1] + b',"error":{"code":-1}}',
            "duplicate result": GENESIS_REPLY[:-1] + b',"result":"0xwrong"}',
            "duplicate id": GENESIS_REPLY[:-1] + b',"id":99}',
            "wrong id": GENESIS_REPLY.replace(b'"id":3', b'"id":99'),
            "trailing garbage": GENESIS_REPLY + b"garbage",
            "second line": GENESIS_REPLY + b"\n" + GENESIS_REPLY,
            "multiline JSON": json.dumps({"id": 3, "jsonrpc": "2.0", "result": EXPECTED_GENESIS},
                                         indent=2).encode(),
            "null": b"null",
        }
        for description, reply in replies.items():
            with self.subTest(reply=description):
                self.rpc_requests.clear()
                result = self.run_launcher("-Status", "-RpcPort", self.start_rpc(reply))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.node_log.exists())
                self.assertTrue(self.rpc_requests)

    def test_status_rejects_http_failure(self):
        for failure in ("batch", "genesis"):
            with self.subTest(failure=failure):
                self.rpc_requests.clear()
                result = self.run_launcher("-Status", "-RpcPort", self.start_rpc(
                    fail_batch=failure == "batch", fail_genesis=failure == "genesis",
                ))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.node_log.exists())

    def test_status_failure_does_not_clean_inherited_directory(self):
        retained_directory = self.fixture_root / "caller-owned status ! & (directory)"
        retained_directory.mkdir()
        names = ("batch.json", "genesis.json", "expected.json")
        for name in names:
            (retained_directory / name).write_text("retain caller-owned file", encoding="utf-8")
        result = self.run_launcher("-Status", overrides={
            "TEMP": None,
            "launcher_status_created": "1",
            "launcher_status_dir": str(retained_directory),
        })
        self.assert_rejected(result)
        self.assertEqual(sorted(item.name for item in retained_directory.iterdir()), sorted(names))
        for name in names:
            self.assertEqual((retained_directory / name).read_text(encoding="utf-8"),
                             "retain caller-owned file")


if __name__ == "__main__":
    unittest.main()
