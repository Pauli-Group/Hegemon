"""Cheap builder orchestration tests; synthetic fixtures are not Lean receipts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("build_rp05_recorded_security_gates.py")
SPEC = importlib.util.spec_from_file_location("rp05_recorded_gate_builder", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class RecordedGateBuilderTests(unittest.TestCase):
    def fixtures(self, repo):
        (repo / builder.BUILD).mkdir(parents=True)
        receipts = {}
        for gate, labels in builder.GATES:
            for label, (module, _) in zip(labels, builder.checker.ENDPOINTS[gate]):
                source = repo / (module + ".lean")
                source.write_text("-- synthetic, not a checked theorem\n")
                (repo / builder.BUILD / (module + ".olean")).write_bytes(b"synthetic non-object")
                compile_path = repo / (label + "-compile.json")
                compile_path.write_text(json.dumps({"module": module, "source": str(source)}))
                audit = repo / (label + "-body.json")
                audit.write_text('{"synthetic":true}')
                receipts[label] = (compile_path, audit)
        return receipts

    def mocks(self):
        return patch.object(builder.checker.legacy, "recompute_source_inventory",
                            return_value={"root_sha512": "synthetic inventory"})

    def test_prepares_exact_three_wrappers_only_after_checker_validation(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate") as validate:
                result = builder.build(output, receipts, repo=repo)
            self.assertEqual(validate.call_count, 3)
            self.assertEqual(set(result["wrappers"]), {gate for gate, _ in builder.GATES})
            self.assertEqual(len(list(output.iterdir())), 3)
            self.assertEqual(result["status"], "PREPARED_RECORDED_METADATA_ONLY")
            self.assertFalse(result["production_authorized"])
            self.assertFalse(result["execution_receipts_authenticated"])
            self.assertFalse(result["contract_installed"])
            privacy = json.loads((output / "adaptive_whole_view_privacy.json").read_text())
            self.assertEqual(privacy["records"][0]["root"],
                "HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint.current_rp05_initialized_two_witness_privacy")
            self.assertEqual(privacy["scope"], "reviewed_recorded_evidence_only")
            self.assertEqual(len(json.loads((output / "relation_and_ledger_composition.json").read_text())["records"]), 2)
            for call in validate.call_args_list:
                actual_repo, wrapper, gate, inventory = call.args
                self.assertEqual(actual_repo, repo)
                self.assertEqual(wrapper["gate"], gate)
                self.assertEqual(wrapper["source_inventory"], inventory)
                for record in wrapper["records"]:
                    for field in ("source", "object", "compile_receipt", "body_audit"):
                        builder.checker.pinned_record(repo, record[field])

    def test_checker_rejection_writes_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate",
                                           side_effect=builder.checker.EvidenceError("missing strict body audit")):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "strict body audit"):
                    builder.build(output, receipts, repo=repo)
            self.assertFalse(output.exists())

    def test_real_checker_never_qualifies_the_synthetic_fixture(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            with self.mocks():
                with self.assertRaises((builder.checker.EvidenceError, KeyError)):
                    builder.build(output, receipts, repo=repo)
            self.assertFalse(output.exists())

    def test_wrong_endpoint_or_missing_body_audit_writes_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            compile_path, audit = receipts["p"]
            original = compile_path.read_bytes()
            changed = json.loads(original); changed["module"] = "Q38Rp05FullAdaptivePrivacyEndpoint"
            compile_path.write_text(json.dumps(changed))
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate"):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "wrong endpoint"):
                    builder.build(output, receipts, repo=repo)
            compile_path.write_bytes(original)
            receipts["p"] = (compile_path, repo / "absent-body.json")
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate"):
                with self.assertRaises(FileNotFoundError):
                    builder.build(output, receipts, repo=repo)
            self.assertFalse(output.exists())

    def test_input_drift_after_validation_writes_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            def drift(_, wrapper, gate, inventory):
                if gate == "relation_and_ledger_composition":
                    (repo / wrapper["records"][0]["source"]["path"]).write_text("changed")
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate", side_effect=drift):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "stale/substituted"):
                    builder.build(output, receipts, repo=repo)
            self.assertFalse(output.exists())

    def test_source_inventory_drift_writes_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            with patch.object(builder.checker.legacy, "recompute_source_inventory",
                              side_effect=[{"root_sha512":"before"},{"root_sha512":"after"}]), \
                    patch.object(builder.checker, "validate_recorded_gate"):
                with self.assertRaisesRegex(builder.checker.EvidenceError, "inventory changed"):
                    builder.build(output, receipts, repo=repo)
            self.assertFalse(output.exists())

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); receipts = self.fixtures(repo); output = repo / "wrappers"
            output.mkdir(); sentinel = output / "keep"; sentinel.write_bytes(b"original")
            with self.mocks(), patch.object(builder.checker, "validate_recorded_gate") as validate:
                with self.assertRaisesRegex(builder.checker.EvidenceError, "create-only"):
                    builder.build(output, receipts, repo=repo)
                validate.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"original")

    def test_paths_reject_escape_alias_and_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo = Path(temporary); (repo / "actual").mkdir()
            (repo / "linked").symlink_to(repo / "actual", target_is_directory=True)
            for value in ("../outside", "./alias", "a//b", "a\\b", "linked/file", repo.parent / "outside"):
                with self.subTest(value=value), self.assertRaises(builder.checker.EvidenceError):
                    builder.repository_path(repo, value)


if __name__ == "__main__":
    unittest.main()
