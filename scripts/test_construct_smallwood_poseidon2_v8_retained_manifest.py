#!/usr/bin/env python3
"""Focused tests for candidate HGV8RP03 retained-manifest construction."""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name(
    "construct_smallwood_poseidon2_v8_retained_manifest.py"
)
SPEC = importlib.util.spec_from_file_location("retained_candidate_constructor", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONSTRUCTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONSTRUCTOR
SPEC.loader.exec_module(CONSTRUCTOR)


class CandidateRetainedManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_repository = Path(__file__).resolve().parent.parent
        cls.fixed_pointer = (
            cls.source_repository / Path(CONSTRUCTOR.CHECKER.MANIFEST_PATH.as_posix())
        )
        cls.fixed_manifest = json.loads(cls.fixed_pointer.read_text(encoding="utf-8"))
        cls.artifact_relative = Path(cls.fixed_manifest["artifact_root"])
        cls.source_root = cls.source_repository / cls.artifact_relative
        cls.generator_source_relative = Path(CONSTRUCTOR.CHECKER.GENERATOR_SOURCE)
        cls.generator_source = cls.source_repository / cls.generator_source_relative
        primary_report = (
            cls.source_root
            / Path(cls.fixed_manifest["proofs"][0]["directory"])
            / "artifact-report.json"
        )
        report = json.loads(primary_report.read_text(encoding="utf-8"))
        cls.source_inventory = report["proof_source_inventory"]
        cls.source_revision = report["generation_provenance"]["source_revision"]

    def copied_candidate(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        repository = Path(temporary.name).resolve()
        root = repository / self.artifact_relative
        root.parent.mkdir(parents=True)
        shutil.copytree(self.source_root, root)
        generator_source = repository / self.generator_source_relative
        generator_source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.generator_source, generator_source)
        output = root.parent / "retained-artifact-manifest.candidate.json"
        return temporary, repository, root, output

    def candidate_patches(self, *, mock_verifiers: bool = True) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(mock.patch.object(
            CONSTRUCTOR.CHECKER,
            "recompute_source_inventory",
            return_value=copy.deepcopy(self.source_inventory),
        ))
        stack.enter_context(mock.patch.object(
            CONSTRUCTOR,
            "current_source_revision",
            return_value=self.source_revision,
        ))
        if mock_verifiers:
            stack.enter_context(mock.patch.object(CONSTRUCTOR, "run_candidate_verifiers"))
        return stack

    def construct(self, repository: Path, output: Path) -> dict:
        with self.candidate_patches():
            return CONSTRUCTOR.construct_candidate_manifest(
                self.artifact_relative,
                output.relative_to(repository),
                repository_root=repository,
            )

    def verify(self, repository: Path, output: Path) -> dict:
        with self.candidate_patches():
            return CONSTRUCTOR.verify_candidate_manifest(
                output.relative_to(repository),
                self.artifact_relative,
                repository_root=repository,
            )

    def test_constructs_and_verifies_exact_schema_v2_candidate(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        fixed = repository / Path(CONSTRUCTOR.CHECKER.MANIFEST_PATH.as_posix())
        self.assertFalse(fixed.exists())
        summary = self.construct(repository, output)
        self.assertTrue(summary["written"])
        self.assertTrue(summary["verified_before_atomic_publish"])
        self.assertEqual(summary["payload_file_count"], 29)
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], CONSTRUCTOR.CHECKER.MANIFEST_SCHEMA)
        self.assertEqual(manifest["authority"], CONSTRUCTOR.CHECKER.AUTHORITY)
        self.assertEqual(len(manifest["files"]), 29)
        self.assertEqual(
            manifest["generator_binaries"]["paths"],
            [path.as_posix() for path in CONSTRUCTOR.CHECKER.GENERATOR_PATHS],
        )
        self.assertTrue(manifest["generator_binaries"]["byte_identical"])
        verified = self.verify(repository, output)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["payload_file_count"], 29)
        self.assertFalse(fixed.exists())

    def test_candidate_verification_delegates_to_dual_frozen_verifier(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        self.construct(repository, output)
        with self.candidate_patches(mock_verifiers=False), mock.patch.object(
            CONSTRUCTOR.CHECKER, "run_frozen_verifiers"
        ) as frozen_verifiers:
            summary = CONSTRUCTOR.verify_candidate_manifest(
                output.relative_to(repository),
                self.artifact_relative,
                repository_root=repository,
            )
        self.assertTrue(summary["verified"])
        frozen_verifiers.assert_called_once()
        self.assertEqual(
            [record["artifact_role"] for record in frozen_verifiers.call_args.args[3]],
            list(CONSTRUCTOR.CHECKER.ROLE_ORDER),
        )
        self.assertEqual(
            frozen_verifiers.call_args.args[4]["schema"],
            CONSTRUCTOR.CHECKER.CHAIN_SCHEMA,
        )

    def test_frozen_checker_keeps_hardcoded_source_revision_default(self) -> None:
        parameter = inspect.signature(CONSTRUCTOR.CHECKER.check_report).parameters[
            "expected_source_revision"
        ]
        self.assertEqual(parameter.default, CONSTRUCTOR.CHECKER.SOURCE_REVISION)

    def test_refuses_overwrite_without_changing_existing_output(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        sentinel = b"do-not-overwrite\n"
        output.write_bytes(sentinel)
        with self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "refusing overwrite"
        ):
            self.construct(repository, output)
        self.assertEqual(output.read_bytes(), sentinel)

    def test_refuses_fixed_pointer_as_candidate_output(self) -> None:
        temporary, repository, _, _ = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        fixed = repository / Path(CONSTRUCTOR.CHECKER.MANIFEST_PATH.as_posix())
        with self.candidate_patches(), self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "fixed retained pointer"
        ):
            CONSTRUCTOR.construct_candidate_manifest(
                self.artifact_relative,
                fixed.relative_to(repository),
                repository_root=repository,
            )
        self.assertFalse(fixed.exists())

    def test_refuses_manifest_path_escape(self) -> None:
        temporary, repository, _, _ = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        outside = Path(tempfile.gettempdir()) / "hegemon-forbidden-candidate.json"
        with self.candidate_patches(), self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "escapes the repository"
        ):
            CONSTRUCTOR.construct_candidate_manifest(
                self.artifact_relative,
                outside,
                repository_root=repository,
            )

    def test_refuses_candidate_outside_retained_artifact_parent(self) -> None:
        temporary, repository, _, _ = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        output = repository / ".agent" / "retained-artifact-manifest.candidate.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        with self.candidate_patches(), self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "direct child"
        ):
            CONSTRUCTOR.construct_candidate_manifest(
                self.artifact_relative,
                output.relative_to(repository),
                repository_root=repository,
            )

    def test_refuses_non_candidate_output_name(self) -> None:
        temporary, repository, root, _ = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        output = root.parent / "not-a-candidate.json"
        with self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "explicit candidate JSON name"
        ):
            self.construct(repository, output)

    def test_extra_payload_fails_exact_29_file_layout(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        (root / "unlisted.bin").write_bytes(b"unlisted")
        with self.assertRaisesRegex(
            CONSTRUCTOR.CandidateManifestError, "exact 29-file layout"
        ):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_symlink_payload_fails_closed(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        proof = root / Path(self.fixed_manifest["proofs"][0]["directory"]) / "proof.bin"
        target = proof.with_name("public-statement.bin")
        proof.unlink()
        proof.symlink_to(target.name)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "symlink"):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_hardlink_payload_alias_fails_closed(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        primary = (
            root / Path(self.fixed_manifest["proofs"][0]["directory"])
            / "public-statement.bin"
        )
        independent = (
            root / Path(self.fixed_manifest["proofs"][1]["directory"])
            / "public-statement.bin"
        )
        independent.unlink()
        os.link(primary, independent)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "hardlink"):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_nonidentical_generator_binaries_fail_closed(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        binary = root / Path(CONSTRUCTOR.CHECKER.GENERATOR_PATHS[1].as_posix())
        payload = bytearray(binary.read_bytes())
        payload[len(payload) // 2] ^= 1
        binary.write_bytes(payload)
        binary.chmod(0o755)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "not byte identical"):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_manifest_proof_common_randomness_chain_source_and_authority_tamper_fail(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        self.construct(repository, output)
        original = json.loads(output.read_text(encoding="utf-8"))

        def proof(manifest: dict) -> None:
            manifest["proofs"][0]["proof"]["sha512"] = "0" * 128

        def common(manifest: dict) -> None:
            manifest["common_payload"]["network-id.bin"]["bytes"] += 1

        def randomness(manifest: dict) -> None:
            manifest["proofs"][0]["wire_salt_hex"] = "0" * 64

        def chain(manifest: dict) -> None:
            manifest["chain_verification"]["sha512"] = "0" * 128

        def source(manifest: dict) -> None:
            manifest["source_inventory"]["root_sha512"] = "0" * 128

        def authority(manifest: dict) -> None:
            manifest["authority"]["production_capability_enabled"] = True

        for label, mutation in (
            ("proof", proof),
            ("common", common),
            ("randomness", randomness),
            ("chain", chain),
            ("source", source),
            ("authority", authority),
        ):
            with self.subTest(label=label):
                tampered = copy.deepcopy(original)
                mutation(tampered)
                output.write_bytes(CONSTRUCTOR.CHECKER.canonical_json(tampered))
                with self.assertRaisesRegex(
                    CONSTRUCTOR.CandidateManifestError,
                    "exact derived schema-v2 manifest",
                ):
                    self.verify(repository, output)
        output.write_bytes(CONSTRUCTOR.CHECKER.canonical_json(original))

    def test_candidate_manifest_hardlink_alias_fails_closed(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        self.construct(repository, output)
        alias = output.with_name("candidate-alias.json")
        os.link(output, alias)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "hardlink"):
            self.verify(repository, output)

    def test_atomic_publish_leaves_no_temporary_candidate(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        self.construct(repository, output)
        prefix = f"{output.stem}.tmp-"
        leftovers = [path for path in output.parent.iterdir() if path.name.startswith(prefix)]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
