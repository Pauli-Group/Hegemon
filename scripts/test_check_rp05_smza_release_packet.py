from __future__ import annotations

import hashlib
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_rp05_smza_release_packet as packet


class ReleasePacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(packet.__file__).resolve().parents[1]
        self._temporary = tempfile.TemporaryDirectory(
            prefix="rp05-release-packet-test-", dir="/private/tmp"
        )
        self.addCleanup(self._temporary.cleanup)
        self.artifact_dir = Path(self._temporary.name) / "pair"
        self.artifact_dir.mkdir()
        self.generator = self.repo / "target/retained-proof/examples/rp05_smza_qualification_artifact"
        self.lean_root = Path("/mock/.elan/toolchains/leanprover--lean4---v4.32.2")
        self.inventory = {"root_sha512": "b" * 128, "entries": []}
        self.primary = b"primary-proof"
        self.independent = b"independent-proof"
        self.manifest = {
            "identity": packet.artifacts.relation_identity(packet.artifacts.RP05_PROFILE),
            "proof_source_inventory": self.inventory,
            "generator": {"executable": {"sha512": "a" * 128}},
        }
        self.pair = {
            "primary": {"proof.bin": self.primary},
            "independent": {"proof.bin": self.independent},
        }
        self.manifest_raw = b"synthetic Q38-pinned manifest bytes for a mocked positive API test"
        (self.artifact_dir / "manifest.json").write_bytes(self.manifest_raw)
        self.recorded_roots = {"reviewed/repository": self.repo}

    def _successful_checker_setup(self):
        readback = {
            "schema": "hegemon-smallwood-poseidon2-v8-smza-readback-v1",
            "production_eligible": False,
            "production_authorized": False,
            "distinct_proofs": True,
            "distinct_salts_and_roots": True,
            "artifacts": {
                "primary": {
                    "source_owned_verification": True,
                    "unchanged_carriers": True,
                    "proof_sha512": hashlib.sha512(self.primary).hexdigest(),
                },
                "independent": {
                    "source_owned_verification": True,
                    "unchanged_carriers": True,
                    "proof_sha512": hashlib.sha512(self.independent).hexdigest(),
                },
            },
        }
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(
            packet.artifacts.legacy, "recompute_source_inventory", return_value=self.inventory
        ))
        stack.enter_context(patch.object(
            packet, "_validate_rp05_transcript_vector", return_value={"status": "PASS"}
        ))
        stack.enter_context(patch.object(
            packet.artifacts, "validate_bundle", return_value=(self.manifest, self.pair)
        ))
        stack.enter_context(patch.object(
            packet.artifacts, "recorded_path_roots", return_value=self.recorded_roots
        ))
        full_q38 = stack.enter_context(patch.object(
            packet.artifacts, "require_complete_security_contract"
        ))
        stack.enter_context(patch.object(
            packet, "_q38_reviewed_manifest", return_value=(
                self.artifact_dir / "manifest.json", self.manifest_raw, b"contract", b"evidence"
            )
        ))
        verify_pair = stack.enter_context(patch.object(
            packet.artifacts, "verify_source_owned", return_value=readback
        ))
        return full_q38, verify_pair

    def _validate(self):
        return packet.validate_release_packet(
            str(self.repo), str(self.artifact_dir), str(self.generator), str(self.lean_root)
        )

    def test_pr_packet_pass_is_not_activation_authority(self) -> None:
        full_q38, verify_pair = self._successful_checker_setup()
        report = self._validate()

        self.assertEqual(report["technical_status"], "PASS_PR_ONLY")
        self.assertFalse(report["production_authorized"])
        self.assertFalse(report["production_eligible"])
        self.assertEqual(report["q38_contract"]["status"], "PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED")
        self.assertFalse(report["q38_contract"]["execution_receipts_authenticated"])
        self.assertFalse(report["activation"]["production_authorized"])
        self.assertEqual(report["activation"]["activation_status"], "not_selected")
        self.assertTrue(report["activation"]["source_capability_disabled"])
        self.assertEqual(report["activation"]["profile_selection"], "unselected")
        self.assertEqual(report["activation"]["source_release_evidence_command_count"], 0)
        self.assertEqual(report["activation"]["independent_review_trust_root_count"], 0)
        full_q38.assert_called_once_with(
            self.manifest["identity"], supplied_evidence=None, recorded_roots=self.recorded_roots
        )
        verify_pair.assert_called_once_with(
            self.repo, self.artifact_dir, self.generator, "a" * 128, self.manifest
        )

    def test_wrong_relation_identity_rejects_before_q38_or_proof_verification(self) -> None:
        self._successful_checker_setup()
        self.manifest["identity"] = packet.artifacts.relation_identity(packet.artifacts.PROFILE)

        with self.assertRaises(packet.PacketError):
            self._validate()

    def test_stale_proof_source_root_rejects(self) -> None:
        self._successful_checker_setup()
        self.manifest["proof_source_inventory"] = {"root_sha512": "c" * 128, "entries": []}

        with self.assertRaises(packet.PacketError):
            self._validate()

    def test_missing_installed_contract_cannot_be_reported_as_technical_pass(self) -> None:
        real_q38_pin_reader = packet._q38_reviewed_manifest
        self._successful_checker_setup()
        with patch.object(packet, "_q38_reviewed_manifest", side_effect=real_q38_pin_reader):
            with patch.object(packet.q38_contract, "validate_q38_evidence_contract", return_value="not_installed"):
                with self.assertRaisesRegex(packet.PacketError, "installed source-pinned Q38"):
                    self._validate()

    def test_missing_or_reordered_q38_gate_api_result_rejects(self) -> None:
        self._successful_checker_setup()
        with patch.object(
            packet.artifacts,
            "require_complete_security_contract",
            side_effect=packet.artifacts.EvidenceError("exact ordered Q38 gates required"),
        ):
            with self.assertRaisesRegex(packet.artifacts.EvidenceError, "exact ordered Q38 gates"):
                self._validate()

    def test_missing_reviewed_generator_pin_rejects_before_verifier(self) -> None:
        _, verify_pair = self._successful_checker_setup()
        del self.manifest["generator"]["executable"]["sha512"]

        with self.assertRaisesRegex(packet.PacketError, "generator executable SHA-512"):
            self._validate()
        verify_pair.assert_not_called()

    def test_failed_source_owned_verification_rejects(self) -> None:
        _, verify_pair = self._successful_checker_setup()
        verify_pair.return_value["artifacts"]["primary"]["source_owned_verification"] = False

        with self.assertRaisesRegex(packet.PacketError, "source verification did not bind unchanged primary"):
            self._validate()

    def test_changed_carrier_readback_rejects(self) -> None:
        _, verify_pair = self._successful_checker_setup()
        verify_pair.return_value["artifacts"]["independent"]["unchanged_carriers"] = False

        with self.assertRaisesRegex(packet.PacketError, "source verification did not bind unchanged independent"):
            self._validate()

    def test_q38_evidence_change_after_verification_rejects(self) -> None:
        _, _ = self._successful_checker_setup()
        helper = packet._q38_reviewed_manifest
        initial = (self.artifact_dir / "manifest.json", self.manifest_raw, b"contract", b"evidence")
        changed = (self.artifact_dir / "manifest.json", self.manifest_raw, b"contract", b"changed evidence")
        helper.side_effect = [initial, changed]

        with self.assertRaisesRegex(packet.PacketError, "changed during validation"):
            self._validate()

    def test_current_finite_transcript_vector_matches_source_fixture(self) -> None:
        result = packet._validate_rp05_transcript_vector(self.repo)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["program_sha512"], packet.artifacts.RP05_PROFILE.program_sha512)
        self.assertFalse(result["production_authority"])


if __name__ == "__main__":
    unittest.main()
