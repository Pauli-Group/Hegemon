"""Isolated orchestration tests for the post-PASS fourth RP05 gate."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("build_rp05_lifecycle_review_gate.py")
SPEC = importlib.util.spec_from_file_location("rp05_lifecycle_review_gate", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class LifecycleReviewGateTests(unittest.TestCase):
    def setup_fixture(self, repo: Path, scratch_base: Path):
        inventory_root = "a" * 128
        inventory = {"root_sha512": inventory_root, "file_count": 0, "entries": []}
        lane_dir = repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/rp05-qualification-lanes/run-pass"
        pair = lane_dir / "pair"
        pair.mkdir(parents=True)
        (lane_dir / "inprocess").mkdir()
        (lane_dir / "socket").mkdir()
        manifest = {"proof_source_inventory": inventory}
        manifest_path = pair / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        for relative in (
            "inprocess/CONFIG_INPROCESS.json", "inprocess/receipt.json",
            "socket/CONFIG_SOCKET.json", "socket/receipt.json",
        ):
            (lane_dir / relative).write_text("{}\n", encoding="utf-8")
        generator = repo / "target/retained-proof/examples/rp05_smza_qualification_artifact"
        generator.parent.mkdir(parents=True)
        generator.write_bytes(b"pinned generator executable")
        generator_hash = hashlib.sha512(generator.read_bytes()).hexdigest()
        scratch = scratch_base.resolve() / "lane-scratch"
        scratch.mkdir(parents=True)
        socket_path = scratch / "socket-receipt.json"
        socket_bytes = b'{"schema":"socket-test-fixture"}\n'
        socket_path.write_bytes(socket_bytes)
        socket_pin = {"path": str(socket_path), "bytes": len(socket_bytes),
                      "sha512": hashlib.sha512(socket_bytes).hexdigest()}
        lane = {
            "schema": builder.LANE_SCHEMA,
            "scratch_directory": str(scratch),
            "qualification_generator_binary": {"path": str(generator.resolve()), "sha512": generator_hash},
            "source_pins_frozen_before_build_proof_lifecycle": {
                "proof_source_inventory_root_sha512": inventory_root,
            },
            "source_pins_after_build_proof_lifecycle": {
                "proof_source_inventory_root_sha512": inventory_root,
            },
            "stages": [
                {"stage": builder.INPROCESS_STAGE, "status": "PASS_DEVELOPMENT_ONLY"},
                {"stage": builder.SOCKET_STAGE, "status": "PASS_DEVELOPMENT_ONLY",
                 "retained_socket_receipt": socket_pin},
            ],
        }
        (lane_dir / "receipt.json").write_text(json.dumps(lane), encoding="utf-8")
        return lane_dir, generator, generator_hash, socket_bytes, manifest_path, inventory

    def fake_adapter(self, manifest_path: Path, inventory: dict):
        report = {
            "schema": builder.checker.REPORT_SCHEMA,
            "artifact_manifest_sha512": builder.checker.digest(manifest_path.read_bytes()),
            "source_root_sha512": inventory["root_sha512"],
        }

        def run(argv, **kwargs):
            self.assertIn("--socket-carrier-receipt", argv)
            self.assertIn("--socket-carrier-receipt-sha256", argv)
            self.assertEqual(kwargs["check"], False)
            return type("Completed", (), {
                "returncode": 0, "stdout": json.dumps(report).encode(), "stderr": b"",
            })()
        return run

    def test_create_only_preparation_copies_and_validates_exact_fourth_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"; repo.mkdir()
            tmp_root = base / "tmp"; tmp_root.mkdir()
            lane, generator, gen_hash, socket_bytes, manifest, inventory = self.setup_fixture(repo, tmp_root)
            output = lane / "recorded-lifecycle-review"
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()), \
                    patch.object(builder.checker.legacy, "recompute_source_inventory", return_value=inventory), \
                    patch.object(builder.checker, "validate_recorded_gate") as validate:
                result = builder.prepare(
                    run_root=lane.relative_to(repo).as_posix(),
                    output=output.relative_to(repo).as_posix(),
                    generator=generator.relative_to(repo).as_posix(),
                    generator_sha512=gen_hash,
                    compiler_idle_confirmed=True,
                    repo=repo,
                    run_adapter=self.fake_adapter(manifest, inventory),
                )
            copied = output / "actual_socket_carrier_receipt.json"
            self.assertEqual(copied.read_bytes(), socket_bytes)
            wrapper = json.loads((output / (builder.GATE + ".json")).read_text())
            self.assertEqual(wrapper["gate"], builder.GATE)
            self.assertEqual(wrapper["source_inventory"], inventory)
            self.assertFalse(wrapper["execution_receipts_authenticated"])
            self.assertFalse(wrapper["production_authorized"])
            self.assertEqual(set(wrapper["records"]), {
                "artifact_manifest", "adapter_report", "inprocess_config", "inprocess_receipt",
                "socket_config", "socket_receipt", "socket_carrier_receipt",
            })
            self.assertEqual(result["status"], "PREPARED_RECORDED_METADATA_ONLY")
            self.assertFalse(result["production_authorized"])
            validate.assert_called_once_with(repo.resolve(), wrapper, builder.GATE, inventory)

    def test_rejects_missing_idle_confirmation_and_keeps_output_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); repo = base / "repo"; repo.mkdir()
            tmp_root = base / "tmp"; tmp_root.mkdir()
            lane, generator, gen_hash, _, _, _ = self.setup_fixture(repo, tmp_root)
            output = lane / "gate"
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "compiler is idle"):
                    builder.prepare(run_root=lane.relative_to(repo).as_posix(),
                                    output=output.relative_to(repo).as_posix(),
                                    generator=generator.relative_to(repo).as_posix(),
                                    generator_sha512=gen_hash, compiler_idle_confirmed=False,
                                    repo=repo)
            self.assertFalse(output.exists())

    def test_rejects_socket_receipt_hash_mismatch_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); repo = base / "repo"; repo.mkdir()
            tmp_root = base / "tmp"; tmp_root.mkdir()
            lane, generator, gen_hash, _, _, inventory = self.setup_fixture(repo, tmp_root)
            receipt_path = lane / "receipt.json"
            lane_receipt = json.loads(receipt_path.read_text())
            lane_receipt["stages"][1]["retained_socket_receipt"]["sha512"] = "0" * 128
            receipt_path.write_text(json.dumps(lane_receipt))
            output = lane / "gate"
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()), \
                    patch.object(builder.checker.legacy, "recompute_source_inventory", return_value=inventory):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "bytes/hash differ"):
                    builder.prepare(run_root=lane.relative_to(repo).as_posix(),
                                    output=output.relative_to(repo).as_posix(),
                                    generator=generator.relative_to(repo).as_posix(),
                                    generator_sha512=gen_hash, compiler_idle_confirmed=True,
                                    repo=repo, run_adapter=lambda *_a, **_k: self.fail("adapter must not run"))
            self.assertFalse(output.exists())

    def test_rejects_stale_inventory_and_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); repo = base / "repo"; repo.mkdir()
            tmp_root = base / "tmp"; tmp_root.mkdir()
            lane, generator, gen_hash, _, _, inventory = self.setup_fixture(repo, tmp_root)
            output = lane / "gate"
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()), \
                    patch.object(builder.checker.legacy, "recompute_source_inventory",
                                 return_value={"root_sha512": "b" * 128, "entries": []}):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "not current"):
                    builder.prepare(run_root=lane.relative_to(repo).as_posix(),
                                    output=output.relative_to(repo).as_posix(),
                                    generator=generator.relative_to(repo).as_posix(),
                                    generator_sha512=gen_hash, compiler_idle_confirmed=True,
                                    repo=repo)
            self.assertFalse(output.exists())
            output.mkdir(); sentinel = output / "keep"; sentinel.write_bytes(b"original")
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "absent path"):
                    builder.prepare(run_root=lane.relative_to(repo).as_posix(),
                                    output=output.relative_to(repo).as_posix(),
                                    generator=generator.relative_to(repo).as_posix(),
                                    generator_sha512=gen_hash, compiler_idle_confirmed=True,
                                    repo=repo)
            self.assertEqual(sentinel.read_bytes(), b"original")

    def test_adapter_failure_leaves_only_create_only_copy_no_wrapper(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); repo = base / "repo"; repo.mkdir()
            tmp_root = base / "tmp"; tmp_root.mkdir()
            lane, generator, gen_hash, socket_bytes, manifest, inventory = self.setup_fixture(repo, tmp_root)
            output = lane / "gate"
            def reject(*_args, **_kwargs):
                return type("Completed", (), {"returncode": 1, "stdout": b"", "stderr": b"failed"})()
            with patch.object(builder, "TMP_ROOT", tmp_root.resolve()), \
                    patch.object(builder.checker.legacy, "recompute_source_inventory", return_value=inventory):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "adapter rejected"):
                    builder.prepare(run_root=lane.relative_to(repo).as_posix(),
                                    output=output.relative_to(repo).as_posix(),
                                    generator=generator.relative_to(repo).as_posix(),
                                    generator_sha512=gen_hash, compiler_idle_confirmed=True,
                                    repo=repo, run_adapter=reject)
            self.assertEqual((output / "actual_socket_carrier_receipt.json").read_bytes(), socket_bytes)
            self.assertFalse((output / "adapter_report.json").exists())
            self.assertFalse((output / (builder.GATE + ".json")).exists())


if __name__ == "__main__":
    unittest.main()
