#!/usr/bin/env python3
"""Focused tests for candidate HGV8RP03 retained-manifest construction."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
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
        # Keep the historical pointer immutable; exercise the constructor with
        # the repaired proof fixture and its actual inventory-bound source.
        cls.historical_manifest = json.loads(cls.fixed_pointer.read_text(encoding="utf-8"))
        # Load the frozen fixture manifest, not a new snapshot of today's tree.
        # Each construction test below rechecks its copied payload and the
        # inventory-authenticated historical identity source.
        cls.fixed_manifest = json.loads((
            cls.fixed_pointer.parent
            / "retained-artifact-manifest.candidate-b1e5c143f7abf052.json"
        ).read_text(encoding="utf-8"))
        if cls.fixed_manifest["artifact_root"] != (
                ".agent/artifacts/smallwood-poseidon2-v8/hgv8rp03-b1e5c143f7abf052"):
            raise AssertionError("historical fixture root changed")
        cls.artifact_relative = Path(cls.fixed_manifest["artifact_root"])
        cls.source_root = cls.source_repository / cls.artifact_relative
        cls.generator_source_relative = Path(CONSTRUCTOR.CHECKER.GENERATOR_SOURCE)
        primary_report = (
            cls.source_root
            / Path(cls.fixed_manifest["proofs"][0]["directory"])
            / "artifact-report.json"
        )
        report = json.loads(primary_report.read_text(encoding="utf-8"))
        cls.source_inventory = report["proof_source_inventory"]
        cls.source_revision = report["generation_provenance"]["source_revision"]
        cls.historical_relation_program = (
            cls.source_root
            / Path(cls.fixed_manifest["proofs"][0]["directory"])
            / "relation-program.bin"
        ).read_bytes()
        def historical_source(relative: str) -> bytes:
            payload = subprocess.run(
                ["git", "-C", str(cls.source_repository), "show",
                 f"{cls.source_revision}:{relative}"],
                check=True,
                capture_output=True,
            ).stdout
            inventory_entry = next(
                entry for entry in cls.source_inventory["entries"]
                if entry["path"] == relative
            )
            if (len(payload) != inventory_entry["bytes"]
                    or hashlib.sha512(payload).hexdigest() != inventory_entry["sha512"]):
                raise AssertionError(f"historical source is not inventory-authenticated: {relative}")
            return payload

        cls.historical_identity_source = historical_source(CONSTRUCTOR.RELATION_IDENTITY_SOURCE)
        cls.historical_generator_source = historical_source(CONSTRUCTOR.CHECKER.GENERATOR_SOURCE)
        if (len(cls.historical_relation_program)
                != CONSTRUCTOR.CHECKER.REPAIRED_RELATION_PROFILE.program_bytes
                or hashlib.sha512(cls.historical_relation_program).hexdigest()
                != CONSTRUCTOR.CHECKER.REPAIRED_RELATION_PROFILE.program_sha512):
            raise AssertionError("historical fixture relation program is not the repaired pin")
        if cls.historical_identity_source == (
                cls.source_repository / CONSTRUCTOR.RELATION_IDENTITY_SOURCE).read_bytes():
            raise AssertionError("current relation source substituted for historical source")

    def copied_candidate(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        repository = Path(temporary.name).resolve()
        root = repository / self.artifact_relative
        root.parent.mkdir(parents=True)
        shutil.copytree(self.source_root, root)
        root.chmod(root.stat().st_mode | 0o700)
        for path in root.rglob("*"):
            path.chmod(path.stat().st_mode | (0o700 if path.is_dir() else 0o200))
        generator_source = repository / self.generator_source_relative
        generator_source.parent.mkdir(parents=True, exist_ok=True)
        generator_source.write_bytes(self.historical_generator_source)
        for relative in (CONSTRUCTOR.RELATION_PROGRAM_SOURCE, CONSTRUCTOR.RELATION_IDENTITY_SOURCE):
            destination = repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if relative == CONSTRUCTOR.RELATION_PROGRAM_SOURCE:
                destination.write_bytes(self.historical_relation_program)
            else:
                destination.write_bytes(self.historical_identity_source)
        if (repository / CONSTRUCTOR.RELATION_IDENTITY_SOURCE).read_bytes() == (
                self.source_repository / CONSTRUCTOR.RELATION_IDENTITY_SOURCE).read_bytes():
            raise AssertionError("copied candidate substituted current relation source")
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
        self.assertEqual(manifest["identity"]["relation_program_sha512"],
                         CONSTRUCTOR.CHECKER.REPAIRED_RELATION_PROFILE.program_sha512)
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
        self.assertEqual(frozen_verifiers.call_args.kwargs["relation_profile"],
                         CONSTRUCTOR.CHECKER.REPAIRED_RELATION_PROFILE)

    def test_historical_fixture_rejects_current_generator_source(self) -> None:
        temporary, repository, _, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        current = (self.source_repository / self.generator_source_relative).read_bytes()
        self.assertNotEqual(current, self.historical_generator_source)
        (repository / self.generator_source_relative).write_bytes(current)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError,
                                    "generator source is not exactly bound"):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_frozen_checker_keeps_hardcoded_source_revision_default(self) -> None:
        parameter = inspect.signature(CONSTRUCTOR.CHECKER.check_report).parameters[
            "expected_source_revision"
        ]
        self.assertEqual(parameter.default, CONSTRUCTOR.CHECKER.SOURCE_REVISION)

    def test_frozen_helpers_keep_historical_relation_defaults(self) -> None:
        checker = CONSTRUCTOR.CHECKER
        for name in ("parse_native_leaf", "check_report", "check_chain_report",
                     "run_frozen_verifiers", "check_relation_program"):
            self.assertEqual(inspect.signature(getattr(checker, name)).parameters[
                "relation_profile"].default, checker.HISTORICAL_RELATION_PROFILE)
        historical_bundle = (self.source_repository / self.historical_manifest["artifact_root"]
                             / self.historical_manifest["proofs"][0]["directory"])
        checker.parse_native_leaf(historical_bundle)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "pinned exact identity"):
            checker.parse_native_leaf(historical_bundle,
                                      relation_profile=checker.REPAIRED_RELATION_PROFILE)
        current_bundle = self.source_root / self.fixed_manifest["proofs"][0]["directory"]
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "pinned exact identity"):
            checker.parse_native_leaf(current_bundle)

    def test_metadata_corrected_source_selects_its_own_exact_profile(self) -> None:
        checker = CONSTRUCTOR.CHECKER
        source = (self.source_repository / CONSTRUCTOR.RELATION_IDENTITY_SOURCE).read_bytes()
        # Exercise only source_relation_profile's identity-entry boundary here;
        # this single-entry inventory is not a complete artifact inventory.
        inventory = {"entries": [{
            "path": CONSTRUCTOR.RELATION_IDENTITY_SOURCE,
            "bytes": len(source),
            "sha512": hashlib.sha512(source).hexdigest(),
        }]}
        profile, program, identities = CONSTRUCTOR.source_relation_profile(
            self.source_repository, inventory
        )
        self.assertEqual(profile, checker.METADATA_CORRECTED_RELATION_PROFILE)
        self.assertNotEqual(profile, checker.REPAIRED_RELATION_PROFILE)
        self.assertEqual(len(identities), 2)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "pinned exact identity"):
            checker.check_relation_program(program, checker.REPAIRED_RELATION_PROFILE)
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "source inventory"):
            CONSTRUCTOR.source_relation_profile(self.source_repository, self.source_inventory)

    def test_source_relation_requires_exact_inventory_and_source_bytes(self) -> None:
        temporary, repository, _, _ = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        source = repository / CONSTRUCTOR.RELATION_IDENTITY_SOURCE
        original = source.read_bytes()
        inventory = copy.deepcopy(self.source_inventory)
        profile, _, _ = CONSTRUCTOR.source_relation_profile(repository, inventory)
        self.assertEqual(profile, CONSTRUCTOR.CHECKER.REPAIRED_RELATION_PROFILE)
        for label, replacement, message in (
            ("magic", b'*b"HGV8RPXX"', "source magic"),
            ("length", None, "unsupported exact relation identity"),
            ("unknown_hash", None, "unsupported exact relation identity"),
            ("digest", None, "source digest prefix"),
        ):
            with self.subTest(label=label):
                if label == "magic":
                    mutated = original.replace(b'*b"HGV8RP03"', replacement)
                elif label == "length":
                    mutated = original.replace(b"853_429", b"853_430")
                elif label == "unknown_hash":
                    mutated = original.replace(b"0x18, 0x0f, 0xca, 0x50", b"0x19, 0x0f, 0xca, 0x50")
                else:
                    before, after = original.split(b"pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST:", 1)
                    mutated = before + b"pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST:" + after.replace(b"0x18", b"0x19", 1)
                source.write_bytes(mutated)
                with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "source inventory"):
                    CONSTRUCTOR.source_relation_profile(repository, inventory)
                resealed = copy.deepcopy(inventory)
                for entry in resealed["entries"]:
                    if entry["path"] == CONSTRUCTOR.RELATION_IDENTITY_SOURCE:
                        entry.update(bytes=len(mutated), sha512=CONSTRUCTOR.CHECKER.sha512_bytes(mutated))
                with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, message):
                    CONSTRUCTOR.source_relation_profile(repository, resealed)
        source.write_bytes(original)
        vector = repository / CONSTRUCTOR.RELATION_PROGRAM_SOURCE
        program = vector.read_bytes()
        for mutated in (b"UNKNOWN!" + program[8:], program[:-1] + bytes([program[-1] ^ 1])):
            vector.write_bytes(mutated)
            with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "pinned exact identity"):
                CONSTRUCTOR.source_relation_profile(repository, inventory)

    def test_repaired_candidate_rejects_historical_program_and_geometry(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        bundle = root / self.fixed_manifest["proofs"][0]["directory"]
        historical = (self.source_repository / self.historical_manifest["artifact_root"]
                      / self.historical_manifest["proofs"][0]["directory"] / "relation-program.bin")
        program = bundle / "relation-program.bin"
        original = program.read_bytes()
        program.write_bytes(historical.read_bytes())
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "canonical source program"):
            self.construct(repository, output)
        program.write_bytes(original)
        report_path = bundle / "artifact-report.json"
        report = json.loads(report_path.read_bytes())
        report["geometry"]["linear_constraints"] = 19899
        report_path.write_bytes(CONSTRUCTOR.CHECKER.canonical_json(report))
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "pinned relation geometry"):
            self.construct(repository, output)
        self.assertFalse(output.exists())

    def test_recorded_generation_revision_need_not_equal_current_head(self) -> None:
        git_result = mock.Mock(returncode=0, stdout=(self.source_revision + "\n").encode())
        with mock.patch.object(CONSTRUCTOR.subprocess, "run", return_value=git_result) as run:
            self.assertEqual(CONSTRUCTOR.current_source_revision(
                self.source_repository, self.source_revision), self.source_revision)
        self.assertEqual(run.call_args.args[0][-1], self.source_revision + "^{commit}")
        self.assertNotIn("HEAD", run.call_args.args[0])

    def test_candidate_rejects_disagreeing_generation_revisions(self) -> None:
        temporary, repository, root, output = self.copied_candidate()
        self.addCleanup(temporary.cleanup)
        report_path = root / self.fixed_manifest["proofs"][1]["directory"] / "artifact-report.json"
        report = json.loads(report_path.read_bytes())
        report["generation_provenance"]["source_revision"] = "ab" * 20
        report_path.write_bytes(CONSTRUCTOR.CHECKER.canonical_json(report))
        with self.assertRaisesRegex(CONSTRUCTOR.CandidateManifestError, "generation revisions differ"):
            self.construct(repository, output)

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
