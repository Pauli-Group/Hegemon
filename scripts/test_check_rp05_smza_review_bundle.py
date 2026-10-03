#!/usr/bin/env python3
"""Focused mutation tests for the non-authorizing RP05 SMZA bundle checker."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "check_rp05_smza_review_bundle.py"
SPEC = importlib.util.spec_from_file_location("rp05_smza_review_bundle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
sys.path.insert(0, str(ROOT / "scripts"))
import check_transaction_proof_successor_authorization as successor

PROGRAM_FIXTURE = ROOT / "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05.bin"


def file_metadata(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {"bytes": len(payload), "sha512": hashlib.sha512(payload).hexdigest()}


def make_pinned_uninstalled_contract_fixture(repository: Path) -> None:
    """Copy the frozen checker into an isolated repo with a pinned sentinel."""
    scripts = repository / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    contract = {
        "schema": checker.Q38_CONTRACT_SCHEMA,
        "status": "not_installed",
        "profile": "V8/SMZA",
        "decs_openings": 38,
        "required_gates": list(checker.MISSING_Q38_GATES),
        "evidence_path": checker.Q38_EVIDENCE_PATH,
        "evidence_sha512": None,
        "production_authorized": False,
    }
    raw = json.dumps(contract, sort_keys=True).encode("utf-8")
    (scripts / checker.Q38_CONTRACT_PATH.rsplit("/", 1)[1]).write_bytes(raw)
    source = MODULE_PATH.read_text(encoding="utf-8")
    sentinel_sha512 = hashlib.sha512(raw).hexdigest()
    source, replacements = re.subn(
        r'Q38_CONTRACT_SHA512\s*=\s*\(\s*"[0-9a-f]+"\s*"[0-9a-f]+"\s*\)',
        'Q38_CONTRACT_SHA512 = (\n    "' + sentinel_sha512[:64] + '"\n    "' + sentinel_sha512[64:] + '"\n)',
        source,
        count=1,
    )
    if replacements != 1:
        raise AssertionError("isolated sentinel checker pin could not be prepared")
    (scripts / "check_rp05_smza_review_bundle.py").write_text(source, encoding="utf-8")


class Rp05SmzaReviewBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rp05-smza-review-")
        self.bundle = Path(self.temporary.name)
        shutil.copyfile(PROGRAM_FIXTURE, self.bundle / "relation-program.bin")
        (self.bundle / "proof.bin").write_bytes(b"SMZA" + bytes(range(64)))
        (self.bundle / "review-vectors.json").write_text(
            '{"schema":"untrusted-fixture","cases":[]}', encoding="utf-8"
        )
        self.source_contract = checker._check_q38_contract_source(ROOT)
        self.write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, mutate=None) -> dict[str, object]:
        manifest: dict[str, object] = {
            "schema": checker.SCHEMA,
            "identity": checker.EXPECTED_IDENTITY.copy(),
            "files": {
                name: file_metadata(self.bundle / name)
                for name in checker.EXPECTED_FILES
            },
            "q38_evidence_contract": checker._expected_contract(self.source_contract),
            "production_authorized": False,
        }
        if mutate is not None:
            mutate(manifest)
        (self.bundle / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        return manifest

    def test_exact_rp05_smza_bundle_is_candidate_only(self) -> None:
        report = checker.check_bundle(self.bundle)
        self.assertEqual(report["candidate_bundle_integrity"], "pass")
        self.assertEqual(report["file_bytes"]["proof.bin"], 68)
        self.assertEqual(report["q38_evidence_contract"], "source_pinned_evidence_bytes_verified")
        self.assertIs(report["production_authorized"], False)

    def test_current_installed_contract_checks_bytes_not_security_semantics(self) -> None:
        status = checker.validate_q38_evidence_contract(ROOT)
        evidence_path = ROOT / checker.Q38_EVIDENCE_PATH
        contract_path = ROOT / checker.Q38_CONTRACT_PATH
        source = checker._check_q38_contract_source(ROOT)
        self.assertEqual(source["status"], "installed")
        self.assertEqual(source["evidence_sha512"], hashlib.sha512(evidence_path.read_bytes()).hexdigest())
        self.assertEqual(hashlib.sha512(contract_path.read_bytes()).hexdigest(), checker.Q38_CONTRACT_SHA512)
        self.assertEqual(status, "source_pinned_evidence_bytes_verified")
        self.assertNotEqual(status, "semantic_pass")

    def test_rejects_profile_mismatch(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["identity"].__setitem__("profile_wire_id", 6)
        )
        with self.assertRaisesRegex(checker.BundleError, "identity"):
            checker.check_bundle(self.bundle)

    def test_rejects_v5_suite(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["identity"].__setitem__("crypto_suite", 4)
        )
        with self.assertRaisesRegex(checker.BundleError, "identity"):
            checker.check_bundle(self.bundle)

    def test_rejects_relation_digest_mismatch(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["identity"].__setitem__("relation_digest_hex", "00" * 48)
        )
        with self.assertRaisesRegex(checker.BundleError, "identity"):
            checker.check_bundle(self.bundle)

    def test_rejects_production_claim(self) -> None:
        self.write_manifest(lambda manifest: manifest.__setitem__("production_authorized", True))
        with self.assertRaisesRegex(checker.BundleError, "production_authorized"):
            checker.check_bundle(self.bundle)

    def test_rejects_caller_spoof_that_installed_contract_is_not_installed(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["q38_evidence_contract"].__setitem__(
                "status", "not_installed"
            )
        )
        with self.assertRaisesRegex(checker.BundleError, "q38 evidence contract"):
            checker.check_bundle(self.bundle)

    def test_rejects_unreviewed_q38_evidence_path(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["q38_evidence_contract"].__setitem__(
                "evidence_path", "evidence/q38.json"
            )
        )
        with self.assertRaisesRegex(checker.BundleError, "q38 evidence contract"):
            checker.check_bundle(self.bundle)

    def test_rejects_mismatched_q38_contract_hash(self) -> None:
        self.write_manifest(
            lambda manifest: manifest["q38_evidence_contract"].__setitem__(
                "sha512", "00" * 64
            )
        )
        with self.assertRaisesRegex(checker.BundleError, "q38 evidence contract"):
            checker.check_bundle(self.bundle)

    def test_successor_candidate_branch_passes_integrity_without_authority(self) -> None:
        report = successor.check_rp05_smza_candidate_bundle(self.bundle, ROOT)
        self.assertEqual(report["candidate_bundle_integrity"], "pass")
        self.assertEqual(report["q38_evidence_contract"], "source_pinned_evidence_bytes_verified")
        self.assertIs(report["production_authorized"], False)

    def test_successor_cli_candidate_mode_is_non_authorizing(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check_transaction_proof_successor_authorization.py"),
                "--root",
                str(ROOT),
                "--check-rp05-smza-candidate",
                str(self.bundle),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("integrity=pass q38=source_pinned_evidence_bytes_verified", completed.stdout)
        self.assertIn("production_authorized=false", completed.stdout)

    def test_successor_candidate_branch_rejects_absent_q38_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rp05-smza-no-contract-") as temp:
            repo = Path(temp)
            scripts = repo / "scripts"
            scripts.mkdir()
            shutil.copyfile(
                ROOT / "scripts/check_rp05_smza_review_bundle.py",
                scripts / "check_rp05_smza_review_bundle.py",
            )
            with self.assertRaisesRegex(
                successor.SuccessorAuthorizationError,
                "q38 evidence contract",
            ):
                successor.check_rp05_smza_candidate_bundle(self.bundle, repo)

    def test_successor_candidate_branch_rejects_mismatched_q38_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rp05-smza-bad-contract-") as temp:
            repo = Path(temp)
            scripts = repo / "scripts"
            scripts.mkdir()
            shutil.copyfile(
                ROOT / "scripts/check_rp05_smza_review_bundle.py",
                scripts / "check_rp05_smza_review_bundle.py",
            )
            (scripts / "rp05_smza_q38_evidence_contract.json").write_text(
                '{"status":"installed","production_authorized":true}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                successor.SuccessorAuthorizationError,
                "q38 evidence contract",
            ):
                successor.check_rp05_smza_candidate_bundle(self.bundle, repo)

    def test_production_profile_gate_rejects_uninstalled_q38_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rp05-smza-pinned-sentinel-") as temp:
            repo = Path(temp)
            make_pinned_uninstalled_contract_fixture(repo)
            with self.assertRaisesRegex(
                successor.SuccessorAuthorizationError,
                "q38 evidence remains absent",
            ):
                successor.require_release_profile_evidence_contract(
                    {"profile_wire_id": 9, "domain_set": 5}, repo
                )

    def test_rejects_over_cap_proof(self) -> None:
        (self.bundle / "proof.bin").write_bytes(b"SMZA" + bytes(checker.PROOF_CAP_BYTES - 3))
        self.write_manifest()
        with self.assertRaisesRegex(checker.BundleError, "exceeds its cap"):
            checker.check_bundle(self.bundle)

    def test_rejects_wrong_proof_magic(self) -> None:
        (self.bundle / "proof.bin").write_bytes(b"SMZ9" + bytes(range(64)))
        self.write_manifest()
        with self.assertRaisesRegex(checker.BundleError, "SMZA wire magic"):
            checker.check_bundle(self.bundle)

    def test_rejects_mutated_relation_program_even_with_updated_file_digest(self) -> None:
        relation = self.bundle / "relation-program.bin"
        content = bytearray(relation.read_bytes())
        content[-1] ^= 1
        relation.write_bytes(content)
        self.write_manifest()
        with self.assertRaisesRegex(checker.BundleError, "canonical HGV8RP05"):
            checker.check_bundle(self.bundle)

    def test_rejects_changed_file_after_manifest_creation(self) -> None:
        with (self.bundle / "proof.bin").open("ab") as stream:
            stream.write(b"x")
        with self.assertRaisesRegex(checker.BundleError, "size or SHA-512 mismatch"):
            checker.check_bundle(self.bundle)

    def test_rejects_unlisted_file(self) -> None:
        (self.bundle / "old-v4-proof.bin").write_bytes(b"SMW2")
        with self.assertRaisesRegex(checker.BundleError, "unlisted files"):
            checker.check_bundle(self.bundle)

    def test_rejects_duplicate_manifest_keys(self) -> None:
        (self.bundle / "manifest.json").write_text(
            '{"schema":"wrong","schema":"wrong-again"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(checker.BundleError, "duplicate JSON key"):
            checker.check_bundle(self.bundle)

    def test_rejects_symlinked_proof(self) -> None:
        target = self.bundle / "proof-target.bin"
        target.write_bytes(b"SMZA" + bytes(range(64)))
        proof = self.bundle / "proof.bin"
        proof.unlink()
        try:
            proof.symlink_to(target.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(checker.BundleError, "symlink forbidden"):
            checker.check_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
