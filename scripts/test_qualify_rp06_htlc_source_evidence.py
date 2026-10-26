"""Focused adversarial checks for the RP06/HTLC evidence inventory."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout

import qualify_rp06_htlc_source_evidence as adapter


class QualificationInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = dict(adapter.EXPECTED_NETWORK)
        self.receipt_path = self.root / "receipt.json"
        self.context_path = self.root / "context.json"
        self.precondition_path = self.root / "precondition.json"
        self.soak_path = self.root / "soak.json"
        self.receipt = {
            "schema": "test.public-evidence.v1",
            "source_commit": adapter.RUNTIME_SOURCE_COMMIT,
            "production_authorized": False,
        }
        self.pin = {
            "role": {
                "path": str(self.receipt_path),
                "sha256": self.write_json(self.receipt_path, self.receipt),
                "schema": "test.public-evidence.v1",
                "source_commit": adapter.RUNTIME_SOURCE_COMMIT,
            }
        }
        context = {
            "chain_id": self.network["chain_id"],
            "genesis_hash": self.network["genesis_hash"],
            "manifest_digest": self.network["manifest_digest"],
            "activation_height": 1,
            "deactivation_height_exclusive": 10001,
        }
        self.context_digest = self.write_json(self.context_path, context)
        self.precondition = {
            "schema": "hegemon.development-rehearsal-precondition-v1",
            "source_commit": adapter.RUNTIME_SOURCE_COMMIT,
            "status": "PASS",
            "completed": True,
            "production_authorized": False,
            "network_identity": self.network,
            "evidence": {
                "role": {"path": str(self.receipt_path), "sha256": self.pin["role"]["sha256"]}
            },
        }
        self.precondition_digest = self.write_json(self.precondition_path, self.precondition)
        self.soak = {
            "schema": "hegemon.development-soak-summary-v1",
            "source_commit": adapter.RUNTIME_SOURCE_COMMIT,
            "precondition_receipt": str(self.precondition_path),
            "precondition_status": "PASS",
            "production_authorized": False,
            "status": "RUNNING",
        }
        self.write_json(self.soak_path, self.soak)

    @staticmethod
    def write_json(path: Path, value: object) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def inspect(self, **kwargs: object) -> dict[str, object]:
        return adapter.inspect_public_evidence(
            self.precondition_path,
            self.context_path,
            self.soak_path,
            pins=self.pin,
            precondition_sha256=self.precondition_digest,
            context_sha256=self.context_digest,
            expected_network=self.network,
            **kwargs,
        )

    def test_running_soak_is_inventory_success_but_incomplete(self) -> None:
        report = self.inspect()
        self.assertEqual(report["measured_soak"]["status"], "RUNNING")
        self.assertFalse(report["measured_soak"]["monitor_reported_operational_pass"])
        self.assertFalse(report["measured_soak"]["counts_as_qualification"])

    def test_terminal_pass_is_monitor_report_only_and_checks_24h_fields(self) -> None:
        self.soak.update({
            "status": "PASS",
            "elapsed_seconds": 86400,
            "sample_count": 2880,
            "target_hours": 24,
            "target_samples_minimum": 2880,
        })
        self.write_json(self.soak_path, self.soak)
        report = self.inspect()["measured_soak"]
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["monitor_reported_operational_pass"])
        self.assertTrue(report["monitor_reported_duration_and_sample_thresholds_satisfied"])
        self.assertFalse(report["monitor_report_bytes_authenticated"])
        self.assertFalse(report["body_equality_independently_verified"])
        self.assertFalse(report["process_continuity_independently_verified"])
        self.assertFalse(report["counts_as_qualification"])

    def test_terminal_fail_is_reported_as_monitor_outcome(self) -> None:
        self.soak["status"] = "FAIL"
        self.write_json(self.soak_path, self.soak)
        report = self.inspect()["measured_soak"]
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["monitor_reported_operational_pass"])
        self.assertFalse(report["counts_as_qualification"])

    def test_unsupported_monitor_status_is_rejected(self) -> None:
        self.soak["status"] = "COMPLETED"
        self.write_json(self.soak_path, self.soak)
        with self.assertRaisesRegex(adapter.QualificationInputError, "unsupported monitor status"):
            self.inspect()

    def test_pass_with_nan_duration_is_rejected(self) -> None:
        self.soak.update({"status": "PASS", "elapsed_seconds": float("nan"), "sample_count": 2880,
                          "target_hours": 24, "target_samples_minimum": 2880})
        self.write_json(self.soak_path, self.soak)
        with self.assertRaisesRegex(adapter.QualificationInputError, "invalid duration/sample numeric fields"):
            self.inspect()

    def test_pass_without_24h_sample_fields_is_rejected(self) -> None:
        self.soak.update({"status": "PASS", "elapsed_seconds": 86399, "sample_count": 2880,
                          "target_hours": 24, "target_samples_minimum": 2880})
        self.write_json(self.soak_path, self.soak)
        with self.assertRaisesRegex(adapter.QualificationInputError, "PASS lacks 24-hour/sample evidence"):
            self.inspect()

    def test_fixed_filename_bundle_is_relocatable_and_preserves_original_paths(self) -> None:
        bundle = self.root / "bundle"
        bundle.mkdir()
        shutil.copyfile(self.precondition_path, bundle / adapter.BUNDLE_PRECONDITION_FILENAME)
        shutil.copyfile(self.context_path, bundle / adapter.BUNDLE_CONTEXT_FILENAME)
        shutil.copyfile(self.soak_path, bundle / adapter.BUNDLE_SOAK_FILENAME)
        shutil.copyfile(self.receipt_path, bundle / "role.json")
        report = self.inspect(
            evidence_bundle_dir=bundle,
            bundle_role_filenames={"role": "role.json"},
            precondition_provenance_path=self.precondition_path,
        )
        self.assertEqual(report["retained_public_receipts"]["role"]["path"], str(self.receipt_path))
        self.assertEqual(report["retained_public_receipts"]["role"]["bundle_member"], "role.json")
        self.assertEqual(report["precondition"]["path"], str(self.precondition_path))

    def test_bundle_does_not_follow_precondition_paths(self) -> None:
        self.precondition["evidence"]["role"]["path"] = "/etc/passwd"
        self.precondition_digest = self.write_json(self.precondition_path, self.precondition)
        bundle = self.root / "bundle"
        bundle.mkdir()
        shutil.copyfile(self.precondition_path, bundle / adapter.BUNDLE_PRECONDITION_FILENAME)
        shutil.copyfile(self.context_path, bundle / adapter.BUNDLE_CONTEXT_FILENAME)
        shutil.copyfile(self.soak_path, bundle / adapter.BUNDLE_SOAK_FILENAME)
        shutil.copyfile(self.receipt_path, bundle / "role.json")
        with self.assertRaisesRegex(adapter.QualificationInputError, "source-owned path/digest mismatch"):
            self.inspect(
                evidence_bundle_dir=bundle,
                bundle_role_filenames={"role": "role.json"},
                precondition_provenance_path=self.precondition_path,
            )

    def test_changed_receipt_bytes_fail_immutable_digest(self) -> None:
        self.receipt["status"] = "PASS"
        self.write_json(self.receipt_path, self.receipt)
        with self.assertRaisesRegex(adapter.QualificationInputError, "immutable digest mismatch"):
            self.inspect()

    def test_malformed_public_receipt_is_reported_as_invalid_input(self) -> None:
        self.receipt_path.write_bytes(b"{not-json")
        with self.assertRaisesRegex(adapter.QualificationInputError, "malformed or unreadable JSON"):
            self.inspect()

    def test_missing_required_role_fails_closed(self) -> None:
        self.precondition["evidence"] = {}
        self.precondition_digest = self.write_json(self.precondition_path, self.precondition)
        with self.assertRaisesRegex(adapter.QualificationInputError, "role set mismatch"):
            self.inspect()

    def test_context_mismatch_is_detected_even_when_file_digest_is_updated(self) -> None:
        context = json.loads(self.context_path.read_text())
        context["chain_id"] = "0x" + "00" * 32
        self.context_digest = self.write_json(self.context_path, context)
        with self.assertRaisesRegex(adapter.QualificationInputError, "public context: network chain_id mismatch"):
            self.inspect()

    def test_old_wallet_source_provenance_cannot_be_relabelled_as_node_source(self) -> None:
        old_flow = dict(self.receipt, source_commit=adapter.HISTORICAL_WALLET_COMMIT)
        digest = self.write_json(self.receipt_path, old_flow)
        self.pin["role"]["sha256"] = digest
        self.precondition["evidence"]["role"]["sha256"] = digest
        self.precondition_digest = self.write_json(self.precondition_path, self.precondition)
        with self.assertRaisesRegex(adapter.QualificationInputError, "provenance mismatch"):
            self.inspect()

    def test_source_role_inventories_are_separate_and_compare_exact_blobs(self) -> None:
        files = {p for role in adapter.SOURCE_ROLES.values() for p in role}
        calls: list[tuple[str, str]] = []

        def reader(revision: str, path: str) -> bytes:
            calls.append((revision, path))
            return ("bytes:" + path).encode()

        result = adapter.inspect_sources(
            self.root,
            blob_reader=reader,
            current_reader=lambda path: ("bytes:" + path).encode(),
        )
        self.assertEqual(set(result["roles"]), {"shared_engine", "rp06", "htlc"})
        self.assertTrue(all(r["unchanged_from_historical_7b"] for r in result["roles"].values()))
        self.assertTrue(all(r["source_inventory_sha256"] for r in result["roles"].values()))
        self.assertTrue(all(revision in {adapter.RUNTIME_SOURCE_COMMIT, adapter.HISTORICAL_WALLET_COMMIT}
                            for revision, _ in calls))
        self.assertTrue(files)

    def test_working_source_mutation_is_not_hidden_by_frozen_blob_digest(self) -> None:
        def reader(revision: str, path: str) -> bytes:
            return b"frozen bytes"

        with self.assertRaisesRegex(adapter.QualificationInputError, "working source differs"):
            adapter.inspect_sources(
                self.root,
                blob_reader=reader,
                current_reader=lambda path: b"mutated bytes" if path == adapter.SHARED_ENGINE[0] else b"frozen bytes",
            )

    def test_require_qualified_returns_nonzero_while_gates_remain_open(self) -> None:
        open_report = {"inventory_status": "OPEN", "gates": {name: "OPEN" for name in adapter.OPEN_GATES}}
        with mock.patch.object(adapter, "build_report", return_value=open_report):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(adapter.main(["--require-qualified"]), 1)


if __name__ == "__main__":
    unittest.main()
