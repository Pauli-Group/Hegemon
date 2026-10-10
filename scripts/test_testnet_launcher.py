#!/usr/bin/env python3
"""Exercise release launcher behavior with temporary fake node/RPC executables.

No Cargo build, real node, wallet, or network connection is used. Windows
PowerShell syntax is checked separately by the Windows release job.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
LAUNCHER = REPOSITORY / "testnet-release" / "testnet-start.sh"
APPROVED_SEEDS = "hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
EXPECTED_GENESIS = "0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59"

FAKE_NODE = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
names = (
    "HEGEMON_SEEDS", "HEGEMON_MINE", "HEGEMON_BOOTSTRAP_AUTHORING",
    "HEGEMON_MINER_ADDRESS", "HEGEMON_MINE_THREADS", "RUST_LOG", "NO_COLOR",
)
Path(os.environ["TESTNET_FIXTURE_NODE_LOG"]).write_text(json.dumps({
    "binary": Path(sys.argv[0]).name,
    "args": sys.argv[1:],
    "env": {name: os.environ.get(name) for name in names},
}), encoding="utf-8")
"""
FAKE_UNAME = r"""#!/usr/bin/env python3
import os
import sys
if sys.argv[1:] == ["-s"]:
    print(os.environ["TESTNET_FIXTURE_SYSTEM"])
elif sys.argv[1:] == ["-m"]:
    print(os.environ["TESTNET_FIXTURE_ARCH"])
else:
    raise SystemExit("Unexpected uname arguments")
"""
FAKE_CURL = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
Path(os.environ["TESTNET_FIXTURE_CURL_LOG"]).write_text(
    json.dumps(sys.argv[1:]), encoding="utf-8")
print('[{"jsonrpc":"2.0","id":1,"result":{"peers":1,"isSyncing":false}}]')
"""


@unittest.skipUnless(os.name == "posix", "POSIX launcher fixtures require Bash")
class TestTestnetLauncher(unittest.TestCase):
    def setUp(self):
        self.assertTrue(LAUNCHER.is_file(), f"Missing release launcher: {LAUNCHER}")
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "Bash is required for launcher checks")
        fixture = tempfile.TemporaryDirectory(prefix="hegemon-launcher-test-")
        self.addCleanup(fixture.cleanup)
        self.fixture_root = Path(fixture.name)
        self.bundle = self.fixture_root / "download folder with spaces"
        self.bundle.mkdir()
        self.launcher = self.bundle / "testnet-start.sh"
        shutil.copyfile(LAUNCHER, self.launcher)
        self.fake_bin = self.fixture_root / "fake tools"
        self.fake_bin.mkdir()
        self.caller = self.fixture_root / "unrelated caller directory"
        self.caller.mkdir()
        self.node_log = self.fixture_root / "node-call.json"
        self.curl_log = self.fixture_root / "curl-call.json"
        for name in (
            "hegemon-node-linux-x86_64",
            "hegemon-node-macos-x86_64",
            "hegemon-node-macos-arm64",
        ):
            self.write_executable(self.bundle / name, FAKE_NODE)
        self.write_executable(self.fake_bin / "uname", FAKE_UNAME)
        self.write_executable(self.fake_bin / "curl", FAKE_CURL)
        self.environment = os.environ.copy()
        self.environment.update({
            "PATH": str(self.fake_bin) + os.pathsep + self.environment.get("PATH", ""),
            "TESTNET_FIXTURE_SYSTEM": "Linux",
            "TESTNET_FIXTURE_ARCH": "x86_64",
            "TESTNET_FIXTURE_NODE_LOG": str(self.node_log),
            "TESTNET_FIXTURE_CURL_LOG": str(self.curl_log),
            "HEGEMON_SEEDS": "unapproved.example:1234",
            "HEGEMON_MINE": "1",
            "HEGEMON_BOOTSTRAP_AUTHORING": "1",
            "HEGEMON_MINER_ADDRESS": "hgm1fixture_public_receive_address",
            "HEGEMON_MINE_THREADS": "3",
        })

    @staticmethod
    def write_executable(path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def run_launcher(self, *args, overrides=None):
        for marker in (self.node_log, self.curl_log):
            if marker.exists():
                marker.unlink()
        environment = self.environment.copy()
        for name, value in (overrides or {}).items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return subprocess.run(
            [self.bash, str(self.launcher), *args],
            cwd=self.caller,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def read_node_call(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.node_log.is_file(), result.stdout + result.stderr)
        self.assertFalse(self.curl_log.exists(), "Launch must not invoke RPC")
        return json.loads(self.node_log.read_text(encoding="utf-8"))

    def assert_safe_profile(self, call):
        self.assertEqual(call["env"]["HEGEMON_SEEDS"], APPROVED_SEEDS)
        self.assertEqual(call["env"]["HEGEMON_BOOTSTRAP_AUTHORING"], "0")
        self.assertIn("--dev", call["args"])
        index = call["args"].index("--rpc-methods")
        self.assertEqual(call["args"][index + 1], "safe")
        self.assertNotIn("--rpc-external", call["args"])
        self.assertNotIn("--tmp", call["args"])

    def test_matching_platform_binary_is_found_beside_launcher(self):
        cases = (
            ("Linux", "x86_64", "hegemon-node-linux-x86_64"),
            ("Darwin", "x86_64", "hegemon-node-macos-x86_64"),
            ("Darwin", "arm64", "hegemon-node-macos-arm64"),
            ("Darwin", "aarch64", "hegemon-node-macos-arm64"),
        )
        for system, architecture, binary in cases:
            with self.subTest(system=system, architecture=architecture):
                call = self.read_node_call(self.run_launcher(overrides={
                    "TESTNET_FIXTURE_SYSTEM": system,
                    "TESTNET_FIXTURE_ARCH": architecture,
                }))
                self.assertEqual(call["binary"], binary)
                self.assert_safe_profile(call)

    def test_relay_overrides_inherited_mining_and_has_stable_data_path(self):
        call = self.read_node_call(self.run_launcher(overrides={"HEGEMON_MINER_ADDRESS": None}))
        self.assert_safe_profile(call)
        self.assertEqual(call["env"]["HEGEMON_MINE"], "0")
        self.assertEqual(call["args"], [
            "--dev", "--base-path", str(Path(self.environment["HOME"]) / ".hegemon-testnet"),
            "--rpc-methods", "safe", "--rpc-port", "9944", "--port", "30333",
            "--name", "HegemonTestnet",
        ])

    def test_explicit_spaced_directory_and_ports_preserve_existing_files(self):
        data_directory = self.fixture_root / "existing node state with spaces"
        data_directory.mkdir()
        retained = data_directory / "retained-state.txt"
        retained.write_text("retain this existing fixture", encoding="utf-8")
        call = self.read_node_call(self.run_launcher(
            "--data-dir", str(data_directory), "--rpc-port", "9945", "--port", "30334",
        ))
        self.assert_safe_profile(call)
        for option, expected in (
            ("--base-path", str(data_directory)), ("--rpc-port", "9945"), ("--port", "30334"),
        ):
            self.assertEqual(call["args"][call["args"].index(option) + 1], expected)
        self.assertEqual(retained.read_text(encoding="utf-8"), "retain this existing fixture")
        self.assertEqual(list(data_directory.iterdir()), [retained])

    def test_explicit_mining_keeps_public_payout_and_thread_configuration(self):
        call = self.read_node_call(self.run_launcher("--mine"))
        self.assert_safe_profile(call)
        self.assertEqual(call["env"]["HEGEMON_MINE"], "1")
        self.assertEqual(call["env"]["HEGEMON_MINER_ADDRESS"], "hgm1fixture_public_receive_address")
        self.assertEqual(call["env"]["HEGEMON_MINE_THREADS"], "3")

    def test_missing_or_blank_mining_address_rejects_without_launch(self):
        for address in (None, "", " \t "):
            with self.subTest(address=address):
                result = self.run_launcher("--mine", overrides={"HEGEMON_MINER_ADDRESS": address})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("HEGEMON_MINER_ADDRESS", result.stderr)
                self.assertFalse(self.node_log.exists())
                self.assertFalse(self.curl_log.exists())

    def test_status_queries_only_safe_loopback_rpc_without_launching(self):
        result = self.run_launcher("--status", "--rpc-port", "9950")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.node_log.exists(), "Status must not start a node")
        curl_args = json.loads(self.curl_log.read_text(encoding="utf-8"))
        self.assertEqual(curl_args[-1], "http://127.0.0.1:9950/")
        requests = json.loads(curl_args[curl_args.index("--data") + 1])
        self.assertEqual([request["method"] for request in requests], [
            "system_health", "chain_getHeader", "chain_getBlockHash",
            "hegemon_miningStatus", "system_version",
        ])
        self.assertEqual(requests[2]["params"], [0])
        self.assertIn(EXPECTED_GENESIS, result.stdout)

    def test_invalid_ports_reject_without_node_or_rpc(self):
        for port in ("0", "65536", "not-a-port"):
            with self.subTest(port=port):
                result = self.run_launcher("--rpc-port", port)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.node_log.exists())
                self.assertFalse(self.curl_log.exists())


if __name__ == "__main__":
    unittest.main()
