"""Small orchestration tests; mocked records are not Lean or release evidence."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("install_rp05_recorded_security_gates.py")
SPEC = importlib.util.spec_from_file_location("rp05_q38_installer", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class RecordedGateInstallPreparationTests(unittest.TestCase):
    def fixture(self, repo: Path):
        scripts = repo / "scripts"
        scripts.mkdir()
        for relative in (
            "scripts/check_smallwood_poseidon2_v8_smza_artifacts.py",
            "scripts/check_rp05_smza_review_bundle.py",
            "scripts/rp05_smza_q38_evidence_contract.json",
        ):
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(installer.REPO / relative, target)
        gate_paths = {}
        for argument, gate_name in installer.GATE_ARGUMENTS:
            path = repo / "recordings" / (argument + ".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"gate": gate_name, "records": []}) + "\n", encoding="utf-8")
            gate_paths[argument] = path.relative_to(repo)
        return gate_paths

    def mocks(self):
        return (
            patch.object(installer.checker.legacy, "recompute_source_inventory",
                         return_value={"root_sha512": "ab" * 64, "file_count": 1, "entries": []}),
            patch.object(installer.checker, "validate_recorded_gate"),
        )

    def test_prepares_deterministic_proposals_without_installing_them(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary)
            gate_paths = self.fixture(repo)
            (repo / "out-a").parent.mkdir(exist_ok=True)
            with self.mocks()[0] as inventory, self.mocks()[1] as validate:
                first = installer.prepare("out-a", gate_paths, repo=repo)
                second = installer.prepare("out-b", gate_paths, repo=repo)
            self.assertEqual(validate.call_count, 8)
            self.assertEqual(first["status"], "DRY_RUN_PREPARED_NOT_INSTALLED")
            self.assertFalse(first["production_authorized"])
            self.assertFalse(first["execution_receipts_authenticated"])
            self.assertFalse(first["contract_installed"])
            output_a, output_b = repo / "out-a", repo / "out-b"
            for name in (installer.EVIDENCE_NAME, installer.CONTRACT_NAME, installer.PATCH_NAME):
                self.assertEqual((output_a / name).read_bytes(), (output_b / name).read_bytes())
            evidence = json.loads((output_a / installer.EVIDENCE_NAME).read_text())
            self.assertEqual([item["gate"] for item in evidence["gates"]], list(installer.ORDERED_GATES))
            contract = json.loads((output_a / installer.CONTRACT_NAME).read_text())
            self.assertEqual(contract["status"], "installed")
            self.assertEqual(contract["evidence_sha512"], first["evidence_sha512"])
            self.assertFalse(contract["production_authorized"])
            patch_text = (output_a / installer.PATCH_NAME).read_text()
            self.assertIn(first["proposed_contract_sha512"][:64], patch_text)
            self.assertIn(first["proposed_contract_sha512"][64:], patch_text)
            self.assertNotIn("status = ", patch_text)
            self.assertEqual(len(list(output_a.iterdir())), 3)

    def test_rejects_wrong_gate_order_and_symlink_before_writing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary)
            gates = self.fixture(repo)
            swapped = dict(gates)
            swapped["soundness"], swapped["privacy"] = swapped["privacy"], swapped["soundness"]
            with self.mocks()[0], self.mocks()[1]:
                with self.assertRaisesRegex(installer.checker.EvidenceError, "wrong gate or order"):
                    installer.prepare("bad-order", swapped, repo=repo)
            self.assertFalse((repo / "bad-order").exists())

            source = repo / gates["soundness"]
            alias = repo / "recordings/linked.json"
            alias.symlink_to(source)
            linked = dict(gates)
            linked["soundness"] = alias.relative_to(repo)
            with self.mocks()[0], self.mocks()[1]:
                with self.assertRaisesRegex(installer.checker.EvidenceError, "symlink path forbidden"):
                    installer.prepare("bad-link", linked, repo=repo)
            self.assertFalse((repo / "bad-link").exists())

    def test_validator_failure_writes_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary)
            gates = self.fixture(repo)
            with self.mocks()[0], patch.object(installer.checker, "validate_recorded_gate",
                                               side_effect=installer.checker.EvidenceError("invalid gate")):
                with self.assertRaisesRegex(installer.checker.EvidenceError, "invalid gate"):
                    installer.prepare("rejected", gates, repo=repo)
            self.assertFalse((repo / "rejected").exists())

    def test_write_failure_cleans_staging_and_never_leaves_partial_destination(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary)
            gates = self.fixture(repo)
            original = installer._write_new
            calls = 0

            def fail_after_one(path, raw):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated write failure")
                original(path, raw)

            with self.mocks()[0], self.mocks()[1], patch.object(installer, "_write_new", side_effect=fail_after_one):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    installer.prepare("partial", gates, repo=repo)
            self.assertFalse((repo / "partial").exists())
            self.assertEqual(list(repo.glob(".partial.stage-*")), [])

    def test_existing_output_is_create_only(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary)
            gates = self.fixture(repo)
            output = repo / "existing"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_bytes(b"original")
            with self.mocks()[0], self.mocks()[1] as validate:
                with self.assertRaisesRegex(installer.checker.EvidenceError, "already exists"):
                    installer.prepare("existing", gates, repo=repo)
            validate.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
