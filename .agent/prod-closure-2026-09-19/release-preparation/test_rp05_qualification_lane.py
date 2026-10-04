#!/usr/bin/env python3
"""Cheap configuration tests for the RP05 qualification lane."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import rp05_qualification_lane as lane
import rp05_bounded_dev as bounded_guard


class QualificationLaneConfigurationTests(unittest.TestCase):
    def test_run_id_is_single_safe_component(self) -> None:
        self.assertEqual(lane.validate_run_id("rp05-identity-20261001"), "rp05-identity-20261001")
        for value in ("", ".", "..", "../outside", "has space", "/absolute", "x" * 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lane.validate_run_id(value)

    def test_output_directory_creation_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "new-run"
            lane.create_directory(target)
            self.assertTrue(target.is_dir())
            with self.assertRaises(RuntimeError):
                lane.create_directory(target)

    def test_command_plan_has_exact_order_and_test_selectors(self) -> None:
        pair = Path("/repo/.agent/artifacts/smallwood-poseidon2-v8-smza/rp05-qualification-lanes/run/pair")
        plan = lane.command_plan("/toolchain/cargo", "/usr/bin/python3", pair)
        self.assertEqual(
            [item["stage"] for item in plan],
            [
                "emit_relation_fixture",
                "write_transcript_vector",
                "check_transcript_vector",
                "check_rust_transcript_vector_consumer",
                "build_qualification_generator",
                "generate_one_proof_pair",
                "verify_proof_pair",
                "build_native_lifecycle_test_binary",
                "inprocess_native_lifecycle",
                "actual_socket_process_lifecycle",
            ],
        )
        self.assertIn("--features", plan[4]["argv"])
        self.assertIn("rp05-dev-artifacts", plan[4]["argv"])
        self.assertEqual(plan[4]["argv"][2:5], ["--locked", "--offline", "--profile"])
        self.assertEqual(plan[4]["argv"][5], lane.GENERATOR_PROFILE)
        self.assertEqual(plan[5]["argv"][-2:], ["generate", str(pair)])
        self.assertIn("target/retained-proof/examples/rp05_smza_qualification_artifact", plan[5]["argv"][0])
        self.assertEqual(plan[6]["argv"][-2:], ["verify", str(pair)])
        self.assertIn("poseidon2-v8-retained-test-support", plan[7]["argv"])
        self.assertEqual(plan[8]["argv"][6], lane.INPROCESS_TEST)
        self.assertEqual(plan[8]["argv"][:3], ["/usr/bin/sandbox-exec", "-f", "<inprocess-sandbox-profile>"])
        self.assertEqual(plan[9]["argv"][:3], ["/usr/bin/sandbox-exec", "-f", "<socket-sandbox-profile>"])
        self.assertEqual(plan[9]["argv"][4:6], ["-I", "-B"])

    def test_mode_specific_sandbox_is_outside_shared_native_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repo"
            root.mkdir()
            run_root = root / "run"
            run_root.mkdir()
            guard_root = base / "scratch"
            guard_root.mkdir()
            pair = root / "pair"
            pair.mkdir()
            (pair / "manifest.json").write_text("{}", encoding="utf-8")
            binary = root / "hegemon_node-test"
            binary.write_bytes(b"test executable")
            toolchain = base / "toolchain"
            toolchain.mkdir()
            cargo = toolchain / "cargo"
            cargo.write_bytes(b"cargo placeholder")
            outer_guard = SimpleNamespace(CARGO=cargo)

            def pin_mode_inputs(_root, _manifest, _binary, profile, wrapper, _python, _guard):
                result = {str(profile.resolve()): lane.sha256_file(profile)}
                if wrapper is not None:
                    result[str(wrapper.resolve())] = lane.sha256_file(wrapper)
                return result

            with patch.object(lane, "_lifecycle_input_pins", side_effect=pin_mode_inputs):
                _, inprocess = lane._build_lifecycle_config(
                    root, run_root, guard_root, pair, "a" * 128,
                    binary, outer_guard, "inprocess",
                )
                _, socket = lane._build_lifecycle_config(
                    root, run_root, guard_root, pair, "a" * 128,
                    binary, outer_guard, "socket",
                )

            self.assertEqual(inprocess["socket_binding"], socket["socket_binding"])
            self.assertNotEqual(inprocess["sandbox_profile"], socket["sandbox_profile"])
            for config in (inprocess, socket):
                profile = config["sandbox_profile"]
                self.assertEqual(config["commands"][0]["argv"][2], profile["path"])
                self.assertEqual(config["inputs"][profile["path"]], profile["sha256"])

    def test_identity_array_parser_accepts_actual_named_sizes_and_numeric_sizes(self) -> None:
        source = (
            lane.ROOT / "circuits/transaction/src/smallwood_poseidon2_v8_program.rs"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            len(lane._array_constant(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512")),
            64,
        )
        self.assertEqual(
            len(lane._array_constant(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST")),
            48,
        )
        self.assertEqual(
            lane._array_constant("const EXAMPLE: [u8; 2] = [0x01, 0x02];", "EXAMPLE"),
            b"\x01\x02",
        )
        identity = lane.validate_current_identity(lane.ROOT)
        self.assertEqual(identity["program"]["bytes"], 848_231)
        self.assertFalse(identity["identity_regeneration_required"])


    def test_socket_test_uses_exact_pinned_parent_and_inherits_outer_group(self) -> None:
        source = lane._socket_wrapper(
            Path("/run/CONFIG_SOCKET.json"),
            Path("/target/debug/deps/hegemon_node-test"),
            lane.SOCKET_TEST,
        ).decode("utf-8")
        self.assertIn(f'"full_name": {lane.SOCKET_TEST!r}', source)
        self.assertIn('"HEGEMON_TEST_RETAINED_CARRIER_PROFILE" not in os.environ', source)
        self.assertIn('environment["HEGEMON_TEST_RETAINED_SMZ9_OUTER_PGID"] = str(os.getpid())', source)
        self.assertIn('os.execve(binary, arguments, environment)', source)

    def test_preparation_guard_uses_measured_disk_budget_separate_from_temp_scratch(self) -> None:
        guard = SimpleNamespace()
        lane._configure_guard(guard)
        self.assertEqual(guard.RSS, 16 * 1024**3)
        self.assertEqual(guard.SCRATCH, 1024**3)
        self.assertEqual(guard.WALL, 3600)
        self.assertEqual(guard.CHILD_STOP, 3500)
        self.assertEqual(guard.MINFREE, 20 * 1024**3)

    def test_environment_pins_only_test_identity_not_production_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "scratch"
            guard = SimpleNamespace(CARGO=Path("/toolchain/bin/cargo"))
            with patch.dict(os.environ, {
                "HEGEMON_SEEDS": "example.invalid:30333",
                "HEGEMON_MINE": "1",
                "HEGEMON_TEST_RETAINED_CARRIER_PROFILE": "SMZ9",
                "PQ_IDENTITY_SEED": "not-forwarded",
            }):
                env = lane._environment(
                    guard,
                    scratch,
                    ".agent/artifacts/smallwood-poseidon2-v8-smza/run/pair/manifest.json",
                    "a" * 128,
                    smza_socket=True,
                )
            self.assertTrue((scratch / "cache").is_dir())
            self.assertEqual(env["HEGEMON_TEST_RETAINED_CARRIER_PROFILE"], "SMZA")
            self.assertEqual(
                env["HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH"],
                ".agent/artifacts/smallwood-poseidon2-v8-smza/run/pair/manifest.json",
            )
            self.assertEqual(env["HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512"], "a" * 128)
            self.assertNotIn("HEGEMON_PRODUCTION_AUTHORIZED", env)
            self.assertNotIn("HEGEMON_SEEDS", env)
            self.assertNotIn("HEGEMON_MINE", env)
            self.assertNotIn("PQ_IDENTITY_SEED", env)
            self.assertEqual(env["CARGO_BUILD_JOBS"], "1")
            self.assertEqual(env["CARGO_NET_OFFLINE"], "true")

    def test_lifecycle_environment_uses_parent_selector_without_profile_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard_root = Path(directory) / "guard-root"
            guard = SimpleNamespace(CARGO=Path("/toolchain/bin/cargo"))
            env = lane._lifecycle_environment(
                guard, guard_root, "artifacts/pair/manifest.json", "a" * 128
            )
            self.assertEqual(
                env["HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH"],
                "artifacts/pair/manifest.json",
            )
            self.assertNotIn("HEGEMON_TEST_RETAINED_CARRIER_PROFILE", env)
            self.assertEqual(env["TMPDIR"], str(guard_root / "tmp"))
            self.assertNotIn("HEGEMON_PRODUCTION_AUTHORIZED", env)

    def test_exact_test_log_accepts_interleaved_libtest_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            selector = "smallwood_poseidon2_v8_program::tests::emit_hgv8rp05_program_fixture"
            log.write_text(
                f"running 1 test\ntest {selector} ... Validated /repo/testdata/program.bin\n"
                "SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES=848231\n"
                "SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512=4b0acd4289abd6ae\n"
                "ok\n\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "488 filtered out; finished in 0.16s\n",
                encoding="utf-8",
            )
            lane.exact_rust_test_passed(log, selector)

    def test_exact_test_log_rejects_wrong_selector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            log.write_text(
                "running 1 test\ntest other::test ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "42 filtered out; finished in 0.00s\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                lane.exact_rust_test_passed(log, "native::poseidon2_v8_verifier::tests::example")

    def test_exact_test_log_rejects_zero_or_multiple_tests(self) -> None:
        selector = "native::poseidon2_v8_verifier::tests::example"
        invalid_logs = (
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; "
            "0 measured; 43 filtered out; finished in 0.00s\n",
            f"running 2 tests\ntest {selector} ... ok\n"
            "test another::test ... ok\n"
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; "
            "41 filtered out; finished in 0.00s\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            for contents in invalid_logs:
                with self.subTest(contents=contents):
                    log.write_text(contents, encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        lane.exact_rust_test_passed(log, selector)

    def test_exact_test_log_rejects_failure_or_mismatched_result(self) -> None:
        selector = "native::poseidon2_v8_verifier::tests::example"
        invalid_logs = (
            f"running 1 test\ntest {selector} ... FAILED\n"
            "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; "
            "42 filtered out; finished in 0.00s\n",
            f"running 1 test\ntest {selector} ... ok\n"
            "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; "
            "42 filtered out; finished in 0.00s\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            for contents in invalid_logs:
                with self.subTest(contents=contents):
                    log.write_text(contents, encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        lane.exact_rust_test_passed(log, selector)

    def test_socket_receipt_must_bind_manifest_inventory_and_supervisor_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            receipt_path = scratch / "actual-socket-carrier-receipt.json"
            manifest = ".agent/artifacts/smallwood-poseidon2-v8-smza/run/pair/manifest.json"
            manifest_sha = "a" * 128
            inventory_sha = "b" * 128
            binary_path = "/target/debug/deps/hegemon_node-test"
            binary_sha = "c" * 128
            socket_binding = {"native_binary": binary_path, "native_sha512": binary_sha}
            guard_execution = {"pid": 12345, "pgid": 12345}
            receipt = {
                "schema": "hegemon.retained-smza.actual-socket-carriers-v1",
                "pass": True,
                "manifest": manifest,
                "manifest_sha512": manifest_sha,
                "source_inventory_root_sha512": inventory_sha,
                "source_inventory_verified_before_and_after": True,
                "production_authority_denied": True,
                "supervisor_owned_process_group": 12345,
                "parent_pid": 12345,
                "test_executable": {"path": binary_path, "sha512": binary_sha},
                "episodes": [{}, {}],
            }
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            log = scratch / "socket.log"
            log.write_text(f"Retained actual-socket carrier receipt: {receipt_path}\n", encoding="utf-8")
            verified = lane.verify_socket_receipt(
                log, scratch, manifest, manifest_sha, inventory_sha,
                socket_binding=socket_binding, guard_execution=guard_execution,
            )
            self.assertEqual(verified["sha512"], lane.sha512_file(receipt_path)["sha512"])
            self.assertEqual(verified["supervisor_owned_process_group"], 12345)
            self.assertEqual(verified["parent_pid"], 12345)
            self.assertEqual(verified["test_executable"]["path"], binary_path)

            mismatches = (
                ("parent pid", lambda bad: bad.update(parent_pid=12346), guard_execution),
                ("supervisor group", lambda bad: bad.update(supervisor_owned_process_group=12346), guard_execution),
                ("executable path", lambda bad: bad["test_executable"].update(path="/other/test"), guard_execution),
                ("executable digest", lambda bad: bad["test_executable"].update(sha512="d" * 128), guard_execution),
                ("guard pgid", lambda bad: None, {"pid": 12345, "pgid": 12346}),
            )
            for label, mutate, expected_execution in mismatches:
                with self.subTest(label=label):
                    bad_receipt = json.loads(json.dumps(receipt))
                    mutate(bad_receipt)
                    receipt_path.write_text(json.dumps(bad_receipt), encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        lane.verify_socket_receipt(
                            log, scratch, manifest, manifest_sha, inventory_sha,
                            socket_binding=socket_binding,
                            guard_execution=expected_execution,
                        )

            receipt_path.write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                lane.verify_socket_receipt(
                    log, scratch, manifest, manifest_sha, inventory_sha,
                    socket_binding=socket_binding, guard_execution=guard_execution,
                )

    def test_cumulative_scratch_monitor_rejects_symlink_spill(self) -> None:
        class FakeLegacyGuard:
            bytes_under = staticmethod(lambda *_roots: 0)

            def run(self, _argv, _environment, _log, owned, baseline):
                return self.bytes_under(*owned) + baseline

        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "scratch"
            scratch.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (scratch / "spill").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink directory"):
                lane.run_with_cumulative_scratch_census(
                    FakeLegacyGuard(), bounded_guard.census, [], {}, scratch / "run.log",
                    scratch, 0,
                )


if __name__ == "__main__":
    unittest.main()
