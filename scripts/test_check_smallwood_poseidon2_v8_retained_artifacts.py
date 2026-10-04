#!/usr/bin/env python3
"""Focused regressions for the HGV8RP03 retained-artifact manifest."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check_smallwood_poseidon2_v8_retained_artifacts.py")
SPEC = importlib.util.spec_from_file_location("retained_artifact_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class RetainedArtifactManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parent.parent
        cls.pointer = cls.repository / Path(CHECKER.MANIFEST_PATH.as_posix())
        cls.source_manifest = json.loads(cls.pointer.read_text(encoding="utf-8"))
        cls.artifact_relative = Path(cls.source_manifest["artifact_root"])
        cls.source_root = cls.repository / cls.artifact_relative
        primary_report = (
            cls.source_root
            / Path(cls.source_manifest["proofs"][0]["directory"])
            / "artifact-report.json"
        )
        cls.source_inventory = json.loads(
            primary_report.read_text(encoding="utf-8")
        )["proof_source_inventory"]
        cls.generator_source = cls.repository / CHECKER.GENERATOR_SOURCE

    def copied_repository(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        repository = Path(temporary.name).resolve()
        root = repository / self.artifact_relative
        root.parent.mkdir(parents=True)
        shutil.copytree(self.source_root, root)
        pointer = repository / Path(CHECKER.MANIFEST_PATH.as_posix())
        pointer.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.pointer, pointer)
        copied_generator_source = repository / CHECKER.GENERATOR_SOURCE
        copied_generator_source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.generator_source, copied_generator_source)
        return temporary, repository, root, pointer

    @staticmethod
    def load_manifest(pointer: Path) -> dict:
        return json.loads(pointer.read_text(encoding="utf-8"))

    @staticmethod
    def write_manifest(pointer: Path, manifest: dict) -> None:
        pointer.write_bytes(CHECKER.canonical_json(manifest))

    def verify_copy(self, repository: Path, pointer: Path) -> dict:
        with mock.patch.object(
            CHECKER, "recompute_source_inventory",
            return_value=copy.deepcopy(self.source_inventory),
        ), mock.patch.object(CHECKER, "run_frozen_verifiers"):
            return CHECKER.verify_manifest(pointer, repository_root=repository)

    @staticmethod
    def reseal_report(root: Path, manifest: dict, record: dict, report: dict) -> None:
        relative = Path(record["directory"]) / "artifact-report.json"
        payload = CHECKER.canonical_json(report)
        (root / relative).write_bytes(payload)
        matches = [entry for entry in manifest["files"] if entry["path"] == relative.as_posix()]
        if len(matches) != 1:
            raise AssertionError(f"manifest report entry count for {relative}: {len(matches)}")
        matches[0]["bytes"] = len(payload)
        matches[0]["sha512"] = CHECKER.sha512_bytes(payload)

    @staticmethod
    def reseal_payload(manifest: dict) -> None:
        manifest["files"].sort(key=lambda entry: entry["path"])
        manifest["payload_file_count"] = len(manifest["files"])
        manifest["payload_total_bytes"] = sum(entry["bytes"] for entry in manifest["files"])
        manifest["payload_inventory_sha512"] = CHECKER.inventory_sha512(manifest["files"])

    @staticmethod
    def reseal_chain(root: Path, manifest: dict, chain: dict) -> None:
        relative = Path("retained-chain-verification.json")
        payload = CHECKER.canonical_json(chain)
        (root / relative).write_bytes(payload)
        manifest["chain_verification"]["bytes"] = len(payload)
        manifest["chain_verification"]["sha512"] = CHECKER.sha512_bytes(payload)
        matches = [entry for entry in manifest["files"] if entry["path"] == relative.as_posix()]
        if len(matches) != 1:
            raise AssertionError(f"manifest chain entry count: {len(matches)}")
        matches[0]["bytes"] = len(payload)
        matches[0]["sha512"] = CHECKER.sha512_bytes(payload)

    def mutate_both_reports(
        self,
        root: Path,
        manifest: dict,
        mutation,
    ) -> None:
        for record in manifest["proofs"]:
            report_path = root / Path(record["directory"]) / "artifact-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            mutation(report)
            self.reseal_report(root, manifest, record, report)
        self.reseal_payload(manifest)

    def test_fixed_v2_manifest_passes(self) -> None:
        summary = CHECKER.verify_manifest()
        self.assertTrue(summary["verified"])
        self.assertFalse(summary["production_capability_enabled"])
        self.assertEqual(summary["payload_file_count"], 29)
        self.assertEqual(
            summary["source_inventory_root_sha512"],
            self.source_manifest["source_inventory"]["root_sha512"],
        )

    def test_unlisted_file_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        (root / "unlisted.bin").write_bytes(b"not retained")
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "file set"):
            self.verify_copy(repository, pointer)

    def test_byte_identical_hardlink_alias_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        primary = root / Path(manifest["proofs"][0]["directory"]) / "public-statement.bin"
        independent = root / Path(manifest["proofs"][1]["directory"]) / "public-statement.bin"
        independent.unlink()
        os.link(primary, independent)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "hardlink"):
            self.verify_copy(repository, pointer)

    def test_authority_claim_fails_closed(self) -> None:
        temporary, repository, _, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        manifest["authority"] = copy.deepcopy(manifest["authority"])
        manifest["authority"]["production_capability_enabled"] = True
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "authority"):
            self.verify_copy(repository, pointer)

    def test_old_v1_manifest_schema_fails_closed(self) -> None:
        temporary, repository, _, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        manifest["schema"] = "hegemon-smallwood-poseidon2-v8-retained-manifest-v1"
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "manifest schema"):
            self.verify_copy(repository, pointer)

    def test_artifact_root_traversal_fails_closed(self) -> None:
        temporary, repository, _, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        manifest["artifact_root"] = ".agent/artifacts/smallwood-poseidon2-v8/../escape"
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "noncanonical path"):
            self.verify_copy(repository, pointer)

    def test_artifact_root_alias_spelling_fails_closed(self) -> None:
        temporary, repository, _, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        manifest["artifact_root"] = manifest["artifact_root"].replace(
            "/smallwood-poseidon2-v8/", "/smallwood-poseidon2-v8//"
        )
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "noncanonical path spelling"):
            self.verify_copy(repository, pointer)

    def test_resealed_proof_substitution_fails_carrier_binding(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        primary_dir = Path(manifest["proofs"][0]["directory"])
        primary_rel = primary_dir / "proof.bin"
        proof_path = root / primary_rel
        payload = bytearray(proof_path.read_bytes())
        payload[len(payload) // 2] ^= 1
        proof_path.write_bytes(payload)
        proof_hash = CHECKER.sha512_bytes(bytes(payload))
        for entry in manifest["files"]:
            if entry["path"] == primary_rel.as_posix():
                entry["sha512"] = proof_hash
                break
        else:
            self.fail("primary proof missing from manifest")
        manifest["proofs"][0]["proof"]["sha512"] = proof_hash
        manifest["payload_inventory_sha512"] = CHECKER.inventory_sha512(manifest["files"])
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(
            CHECKER.RetainedArtifactError,
            "exact frozen proof identities",
        ):
            self.verify_copy(repository, pointer)

    def test_resealed_source_inventory_entry_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["proof_source_inventory"]["entries"][0]["sha512"] = "0" * 128

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "complete source inventory"):
            self.verify_copy(repository, pointer)

    def test_resealed_generator_source_hash_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        manifest["generator_binaries"]["source_sha512"] = "0" * 128

        def mutate(report: dict) -> None:
            report["generation_provenance"]["generator_source_sha512"] = "0" * 128

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "generator record source"):
            self.verify_copy(repository, pointer)

    def test_resealed_coinbase_fixture_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["fixture"]["input_values"][0] += 1
            report["fixture"]["coinbase_opening_words_sha512"][0] = "0" * 128

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "exact canonical coinbase fixture"):
            self.verify_copy(repository, pointer)

    def test_resealed_provenance_source_identity_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["generation_provenance"]["source_revision"] = "0" * 40
            report["provenance_transition"]["source_inventory_root_sha512"] = "0" * 128

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "source revision"):
            self.verify_copy(repository, pointer)

    def test_resealed_transition_source_root_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["provenance_transition"]["source_inventory_root_sha512"] = "0" * 128

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "provenance transition"):
            self.verify_copy(repository, pointer)

    def test_listed_arbitrary_root_file_fails_exact_allowlist(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        relative = Path("release-authority.json")
        payload = CHECKER.canonical_json({"production_capability_enabled": True})
        (root / relative).write_bytes(payload)
        manifest["files"].append({
            "bytes": len(payload),
            "executable": False,
            "path": relative.as_posix(),
            "sha512": CHECKER.sha512_bytes(payload),
        })
        self.reseal_payload(manifest)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "payload path allowlist"):
            self.verify_copy(repository, pointer)

    def test_resealed_chain_fixture_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        chain_path = root / "retained-chain-verification.json"
        chain = json.loads(chain_path.read_text(encoding="utf-8"))
        chain["canonical_input_positions"] = [1, 0]
        chain["coinbase_input_values"][0] += 1
        chain["coinbase_opening_words_sha512"][0] = "0" * 128
        self.reseal_chain(root, manifest, chain)
        self.reseal_payload(manifest)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "chain canonical input positions"):
            self.verify_copy(repository, pointer)

    def test_resealed_generation_independence_scope_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["generation_provenance"]["independence_scope"] = (
                "independently_attested_generation"
            )

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "independence scope"):
            self.verify_copy(repository, pointer)

    def test_resealed_provenance_authority_claim_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["provenance_transition"]["claim"] = "production_authorized"

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "provenance transition"):
            self.verify_copy(repository, pointer)

    def test_resealed_profile_forgery_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["identity"]["profile"]["rho"] = 0

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "identity, profile, and transport"):
            self.verify_copy(repository, pointer)

    def test_added_report_production_authority_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["production_capability_enabled"] = True

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "artifact report fields"):
            self.verify_copy(repository, pointer)

    def test_added_verification_production_authority_fails_closed(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["verification"]["production_capability_enabled"] = True

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "verification fields"):
            self.verify_copy(repository, pointer)

    def test_semantically_unused_reseal_fails_frozen_manifest_digest(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)

        def mutate(report: dict) -> None:
            report["generated_unix_seconds"] += 1

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "exact frozen manifest"):
            self.verify_copy(repository, pointer)

    def test_resealed_noop_generator_binaries_fail_frozen_identity(self) -> None:
        temporary, repository, root, pointer = self.copied_repository()
        self.addCleanup(temporary.cleanup)
        manifest = self.load_manifest(pointer)
        payload = b"#!/bin/sh\nexit 0\n"
        digest = CHECKER.sha512_bytes(payload)
        for relative in CHECKER.GENERATOR_PATHS:
            path = root / Path(relative.as_posix())
            path.write_bytes(payload)
            path.chmod(0o755)
            entry = next(item for item in manifest["files"] if item["path"] == str(relative))
            entry["bytes"] = len(payload)
            entry["sha512"] = digest
        manifest["generator_binaries"]["bytes"] = len(payload)
        manifest["generator_binaries"]["sha512"] = digest

        def mutate(report: dict) -> None:
            report["generation_provenance"]["generator_binary_bytes"] = len(payload)
            report["generation_provenance"]["generator_binary_sha512"] = digest

        self.mutate_both_reports(root, manifest, mutate)
        self.write_manifest(pointer, manifest)
        with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "frozen identity"):
            self.verify_copy(repository, pointer)

    def test_nonzero_retained_verifier_exit_fails_closed(self) -> None:
        completed = CHECKER.subprocess.CompletedProcess(
            args=["pinned-generator", "verify-v5", "artifact"],
            returncode=1,
            stdout=b"",
            stderr=b"invalid proof",
        )
        with mock.patch.object(CHECKER, "verifier_environment", return_value={}), \
                mock.patch.object(CHECKER.subprocess, "run", return_value=completed) as runner:
            with self.assertRaisesRegex(CHECKER.RetainedArtifactError, "invalid proof"):
                CHECKER.run_retained_verifier(
                    Path("/fixed/pinned-generator"),
                    ("verify-v5", "artifact"),
                    self.repository,
                )
        self.assertEqual(
            runner.call_args.args[0],
            ["/fixed/pinned-generator", "verify-v5", "artifact"],
        )
        self.assertNotIn("shell", runner.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
