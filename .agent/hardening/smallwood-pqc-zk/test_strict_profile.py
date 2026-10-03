from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("strict_profile.py")
SPEC = importlib.util.spec_from_file_location("smallwood_strict_profile", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load strict_profile.py")
strict = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(strict)


def probability(numerator: int, denominator: int) -> dict[str, str]:
    return {
        "numerator": str(numerator),
        "denominator": str(denominator),
    }


def write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def active_profile() -> dict[str, object]:
    return {
        "schema": strict.PROFILE_SCHEMA,
        "profile_id": strict.TARGET_PROFILE_ID,
        "protocol": {
            "proof_system": "SmallWood-LPPC-PACS-PIOP-LVCS-DECS",
            "challenge_field": {
                "name": "Goldilocks",
                "order": str(strict.GOLDILOCKS_ORDER),
            },
            "transcript": {
                "algorithm": "SHA-512",
                "output_bits": 512,
                "physical_fiat_shamir_rounds": 4,
            },
            "parameters": {
                "rho": 5,
                "piop_openings": 5,
                "beta": 2,
                "opening_pow_bits": 0,
                "decs_domain_size": 1_048_576,
                "decs_openings": 23,
                "decs_eta": 5,
                "decs_pow_bits": 0,
                "packing_factor": 64,
                "piop_nonce_trials": 16,
                "decs_candidate_count": 50,
                "canonical_first_valid_piop_nonce": True,
                "fixed_first_distinct_decs_sampler": True,
                "decs_evaluation_domain": "radix2-disjoint-coset-v1",
                "decs_leaf_index_bound": True,
                "decs_leaf_tape_bytes": 64,
                "independent_decs_leaf_tapes": True,
            },
        },
        "transaction_relation": {
            "circuit_version": 6,
            "crypto_suite": 5,
            "family": 1,
            "action": 8,
            "backend": 2,
            "profile": 2,
            "domain_set": 1,
            "statement_magic": "HGF6ST01",
            "semantic_tag": "HEG-F6V1",
            "envelope_magic": "SWV6",
            "envelope_version": 1,
            "statement_bytes": 893,
            "limb_bytes": 7,
            "public_limb_count": 128,
            "intent_payload_bytes": 725,
            "intent_frame_bytes": 744,
            "semantic_hash_calls": 79,
            "keccak_f1600_permutations": 124,
        },
        "relation_hash": {
            "algorithm": "SHAKE256",
            "output_bits": 448,
        },
        "security_accounting": {
            "low_query_exponent": 64,
            "low_target_bits": 128,
            "work_query_exponent": 128,
            "work_max_success": probability(1, 2),
            "relation_hash_targets": 79,
            "relation_hash_collision_factor": 4,
            "transcript_hash_worst_case_requests": 11_574,
            "transcript_hash_collision_factor": 4,
            "cms_fiat_shamir_factor": 12,
            "cms_transcript_collision_factor": 48,
            "cms_oracle_bridge_factor": 2,
            "global_history_union_multiplier": 1,
            "per_proof_history_union_forbidden": True,
            "opening_pow_bits": 0,
            "decs_pow_bits": 0,
            "piop_nonce_trials": 16,
            "decs_candidate_count": 50,
        },
        "geometry": {
            "row_count": 699,
            "constraint_count": 890,
            "effective_constraint_degree": 8,
            "witness_polynomial_degree": 68,
            "consistency_discrepancy_degree": 544,
            "lvcs_column_count": 375,
            "base_game_arity_upper_bound": 1_048_576,
        },
    }


def empty_certificate() -> dict[str, object]:
    return {
        "schema": strict.CERTIFICATE_SCHEMA,
        "profile_id": strict.TARGET_PROFILE_ID,
        "evidence": {
            evidence_id: {"status": "missing"}
            for evidence_id in strict.EVIDENCE_POLICY
        },
    }


def empty_trust_root() -> dict[str, object]:
    return {
        "schema": strict.TRUST_ROOT_SCHEMA,
        "profile_id": strict.TARGET_PROFILE_ID,
        "accepted_receipts": {
            evidence_id: [] for evidence_id in strict.EVIDENCE_POLICY
        },
    }


def quantitative_value(claim: str) -> dict[str, str]:
    if claim == "zk_advantage_at_2pow64":
        return probability(1, 2**192)
    if claim == "zk_advantage_at_2pow128":
        return probability(1, 8)
    if claim.endswith("_at_2pow64"):
        return probability(1, 2**300)
    if claim.endswith("_at_2pow128"):
        return probability(1, 2**20)
    raise AssertionError(f"unexpected quantitative claim {claim}")


def full_synthetic_fixture(
    repo_root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    profile = active_profile()
    certificate = empty_certificate()
    trust_root = empty_trust_root()
    evidence = certificate["evidence"]
    accepted = trust_root["accepted_receipts"]
    assert isinstance(evidence, dict)
    assert isinstance(accepted, dict)

    for evidence_id, policy in strict.EVIDENCE_POLICY.items():
        artifact_rel = Path("artifacts") / f"{evidence_id}.txt"
        artifact_path = repo_root / artifact_rel
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            f"isolated synthetic positive fixture for {evidence_id}\n",
            encoding="utf-8",
        )
        required_claims = policy["quantitative_claims"]
        receipt = {
            "schema": strict.RECEIPT_SCHEMA,
            "profile_id": strict.TARGET_PROFILE_ID,
            "evidence_id": evidence_id,
            "claim": policy["claim"],
            "kind": policy["kinds"][0],
            "result": "pass",
            "authority_scope": "deployed-end-to-end",
            "assumption_only": False,
            "machine_checked": True,
            "checker": {
                "name": "isolated-test-checker",
                "version": "1",
                "command_sha256": hashlib.sha256(b"isolated test command").hexdigest(),
                "exit_code": 0,
            },
            "artifacts": [
                {
                    "path": artifact_rel.as_posix(),
                    "sha256": sha256(artifact_path),
                }
            ],
            "quantitative_claims": {
                claim: quantitative_value(claim) for claim in required_claims
            },
        }
        receipt_rel = Path("receipts") / f"{evidence_id}.json"
        receipt_path = repo_root / receipt_rel
        write_json(receipt_path, receipt)
        receipt_digest = sha256(receipt_path)
        evidence[evidence_id] = {
            "status": "verified",
            "receipt_path": receipt_rel.as_posix(),
            "receipt_sha256": receipt_digest,
        }
        accepted[evidence_id] = [receipt_digest]
    return profile, certificate, trust_root


def rewrite_receipt(
    repo_root: Path,
    certificate: dict[str, object],
    trust_root: dict[str, object],
    evidence_id: str,
    mutate,
) -> None:
    evidence = certificate["evidence"]
    accepted = trust_root["accepted_receipts"]
    assert isinstance(evidence, dict)
    assert isinstance(accepted, dict)
    entry = evidence[evidence_id]
    assert isinstance(entry, dict)
    receipt_path = repo_root / str(entry["receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    mutate(receipt)
    write_json(receipt_path, receipt)
    digest = sha256(receipt_path)
    entry["receipt_sha256"] = digest
    accepted[evidence_id] = [digest]


class StrictProfileTests(unittest.TestCase):
    maxDiff = None

    def test_checked_in_candidate_fails_closed(self) -> None:
        repo_root = MODULE_PATH.resolve().parents[3]
        directory = MODULE_PATH.parent
        report = strict.evaluate(
            strict.load_json_strict(directory / "target-profile.json"),
            strict.load_json_strict(directory / "candidate-certificate.json"),
            strict.load_json_strict(directory / "trust-root.json"),
            repo_root,
        )
        self.assertEqual(
            report["capabilities"],
            {
                "complete_zk": False,
                "pq128": False,
                "production_authorized": False,
            },
        )
        self.assertFalse(report["profile_gate_pass"])
        self.assertEqual(report["verified_evidence_count"], 0)
        self.assertIn(
            "production geometry row_count is not measured",
            report["blocking_reasons"],
        )

    def test_exact_active_interactive_and_cms_arithmetic(self) -> None:
        profile = active_profile()
        report = strict.evaluate(
            profile,
            empty_certificate(),
            empty_trust_root(),
            MODULE_PATH.resolve().parents[3],
        )
        soundness = report["soundness"]
        self.assertEqual(
            soundness["interactive_terms"]["decs_uniform_matrix"]["denominator"],
            str(strict.GOLDILOCKS_ORDER**5),
        )
        self.assertEqual(
            soundness["interactive_terms"]["piop_constraint_batching"]["denominator"],
            str(strict.GOLDILOCKS_ORDER**5),
        )
        self.assertAlmostEqual(
            soundness["interactive_aggregate"]["security_bits_approx"],
            262.3777366177216,
            places=10,
        )
        self.assertAlmostEqual(
            soundness["ideal_cms_at_2pow64"]["security_bits_approx"],
            130.79277411700048,
            places=10,
        )
        self.assertAlmostEqual(
            soundness["ideal_cms_at_2pow128"]["security_bits_approx"],
            2.7927741170004645,
            places=10,
        )
        self.assertFalse(soundness["available"])

    def test_complete_finite_qrom_inventory_meets_both_ideal_gates(self) -> None:
        report = strict.evaluate(
            active_profile(),
            empty_certificate(),
            empty_trust_root(),
            MODULE_PATH.resolve().parents[3],
        )
        soundness = report["soundness"]
        low = soundness["ideal_finite_qrom_at_2pow64"]
        work = soundness["ideal_finite_qrom_at_2pow128"]
        low_fraction = strict.Fraction(int(low["numerator"]), int(low["denominator"]))
        work_fraction = strict.Fraction(int(work["numerator"]), int(work["denominator"]))
        self.assertLessEqual(low_fraction, strict.Fraction(1, 2**128))
        self.assertLess(work_fraction, strict.Fraction(1, 2))
        self.assertAlmostEqual(low["security_bits_approx"], 130.7927741170006, places=10)
        self.assertAlmostEqual(work["security_bits_approx"], 2.7927741170006, places=10)
        for label in (
            "pcs_iop_fiat_shamir_amplification",
            "transcript_hash_collision_instability",
            "pcs_oracle_database_bridge",
            "canonical_piop_nonce_exhaustion",
            "fixed_decs_sampler_exhaustion",
            "relation_hash_collision_union",
            "transcript_hash_request_union",
            "grinding",
            "global_history_union",
        ):
            self.assertIn(label, soundness["finite_qrom_terms_at_2pow64"])
            self.assertIn(label, soundness["finite_qrom_terms_at_2pow128"])
        self.assertEqual(
            soundness["finite_qrom_terms_at_2pow64"]["grinding"]["numerator"],
            "0",
        )
        # Numeric ideal arithmetic is reportable, but no capability is derived
        # without the receipt-bound deployment reductions.
        self.assertFalse(soundness["available"])
        self.assertFalse(report["capabilities"]["pq128"])

    def test_security_accounting_drift_fails_closed(self) -> None:
        for field, value, reason in (
            (
                "global_history_union_multiplier",
                2,
                "security accounting global_history_union_multiplier must equal 1",
            ),
            (
                "transcript_hash_worst_case_requests",
                11_573,
                "security accounting transcript_hash_worst_case_requests must equal 11574",
            ),
            (
                "opening_pow_bits",
                1,
                "security accounting opening_pow_bits must equal 0",
            ),
        ):
            profile = active_profile()
            profile["security_accounting"][field] = value
            report = strict.evaluate(
                profile,
                empty_certificate(),
                empty_trust_root(),
                MODULE_PATH.resolve().parents[3],
            )
            self.assertFalse(report["profile_gate_pass"])
            self.assertIn(reason, report["blocking_reasons"])

    def test_384_bit_relation_hash_is_rejected(self) -> None:
        profile = active_profile()
        profile["relation_hash"]["output_bits"] = 384
        report = strict.evaluate(
            profile,
            empty_certificate(),
            empty_trust_root(),
            MODULE_PATH.resolve().parents[3],
        )
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn(
            "the reviewed relation hash output must be exactly 448 bits; 384/3 has no PQ128 composition margin",
            report["blocking_reasons"],
        )

    def test_relation_and_transcript_algorithms_are_profile_bound(self) -> None:
        profile = active_profile()
        profile["relation_hash"]["algorithm"] = "BLAKE2b"
        profile["protocol"]["transcript"]["algorithm"] = "SHAKE256"
        report = strict.evaluate(
            profile,
            empty_certificate(),
            empty_trust_root(),
            MODULE_PATH.resolve().parents[3],
        )
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn(
            "the reviewed V6 relation hash must use SHAKE256",
            report["blocking_reasons"],
        )
        self.assertIn(
            "the reviewed V6 proof transcript must use SHA-512",
            report["blocking_reasons"],
        )

    def test_fully_pinned_synthetic_fixture_can_derive_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertTrue(report["profile_gate_pass"])
        self.assertEqual(report["verified_evidence_count"], len(strict.EVIDENCE_POLICY))
        self.assertTrue(report["complete_zk_evidence_pass"])
        self.assertTrue(report["pq128_evidence_pass"])
        self.assertTrue(report["soundness"]["low_advantage_gate_pass"])
        self.assertTrue(report["soundness"]["work_factor_gate_pass"])
        self.assertEqual(
            report["capabilities"],
            {
                "complete_zk": True,
                "pq128": True,
                "production_authorized": True,
            },
        )

    def test_assumption_only_receipt_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            evidence_id = "qrom_zk_reduction"
            rewrite_receipt(
                repo_root,
                certificate,
                trust_root,
                evidence_id,
                lambda receipt: receipt.__setitem__("assumption_only", True),
            )
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertIn(
            "qrom_zk_reduction: receipt is assumption-only",
            report["blocking_reasons"],
        )

    def test_untrusted_receipt_digest_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            trust_root["accepted_receipts"]["compiled_verifier_refinement"] = []
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["capabilities"]["pq128"])
        self.assertIn(
            "compiled_verifier_refinement: receipt digest is not independently trust-root pinned",
            report["blocking_reasons"],
        )

    def test_bound_artifact_digest_mismatch_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            artifact = repo_root / "artifacts" / "end_to_end_same_bytes.txt"
            artifact.write_text("tampered\n", encoding="utf-8")
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["capabilities"]["production_authorized"])
        self.assertIn(
            "end_to_end_same_bytes: bound artifact digest mismatch",
            report["blocking_reasons"],
        )

    def test_missing_joint_simulator_alone_blocks_complete_zk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            certificate["evidence"]["joint_pcs_lvcs_decs_merkle_simulator"] = {
                "status": "missing"
            }
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["complete_zk_evidence_pass"])
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertIn(
            "evidence not verified: joint_pcs_lvcs_decs_merkle_simulator (missing)",
            report["blocking_reasons"],
        )

    def test_missing_decs_domain_and_leaf_hiding_blocks_both_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            certificate["evidence"]["decs_domain_and_leaf_hiding"] = {
                "status": "missing"
            }
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["complete_zk_evidence_pass"])
        self.assertFalse(report["pq128_evidence_pass"])
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertFalse(report["capabilities"]["pq128"])
        self.assertIn(
            "evidence not verified: decs_domain_and_leaf_hiding (missing)",
            report["blocking_reasons"],
        )

    def test_subgroup_domain_cannot_qualify_as_complete_zk(self) -> None:
        profile = active_profile()
        profile["protocol"]["parameters"]["decs_evaluation_domain"] = (
            "radix2-subgroup-v1"
        )
        report = strict.evaluate(
            profile,
            empty_certificate(),
            empty_trust_root(),
            Path.cwd(),
        )
        self.assertFalse(report["profile_gate_pass"])
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertIn(
            "complete-ZK DECS evaluation domain must be the reviewed disjoint coset",
            report["blocking_reasons"],
        )

    def test_v6_statement_identity_drift_cannot_qualify(self) -> None:
        profile = active_profile()
        profile["transaction_relation"]["statement_bytes"] = 853
        profile["transaction_relation"]["public_limb_count"] = 122
        report = strict.evaluate(
            profile,
            empty_certificate(),
            empty_trust_root(),
            Path.cwd(),
        )
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn(
            "transaction relation identity statement_bytes must equal 893",
            report["blocking_reasons"],
        )
        self.assertIn(
            "transaction relation identity public_limb_count must equal 128",
            report["blocking_reasons"],
        )

    def test_missing_compiled_prover_refinement_alone_blocks_complete_zk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary).resolve()
            profile, certificate, trust_root = full_synthetic_fixture(repo_root)
            certificate["evidence"]["compiled_prover_distribution_refinement"] = {
                "status": "missing"
            }
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertFalse(report["complete_zk_evidence_pass"])
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertIn(
            "evidence not verified: compiled_prover_distribution_refinement (missing)",
            report["blocking_reasons"],
        )

    def test_candidate_capability_booleans_are_ignored(self) -> None:
        certificate = empty_certificate()
        certificate["capabilities"] = {
            "complete_zk": True,
            "pq128": True,
            "production_authorized": True,
        }
        report = strict.evaluate(
            active_profile(),
            certificate,
            empty_trust_root(),
            MODULE_PATH.resolve().parents[3],
        )
        self.assertEqual(
            report["capabilities"],
            {
                "complete_zk": False,
                "pq128": False,
                "production_authorized": False,
            },
        )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
            with self.assertRaisesRegex(strict.GateInputError, "duplicate JSON key"):
                strict.load_json_strict(path)

    def test_invalid_falling_product_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            strict.falling_product(0, 1)
        with self.assertRaises(ValueError):
            strict.falling_product(3, 4)
        self.assertEqual(strict.falling_product(544, 5), 544 * 543 * 542 * 541 * 540)

    def test_cli_returns_two_for_checked_in_candidate(self) -> None:
        directory = MODULE_PATH.parent
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(MODULE_PATH),
                "--profile",
                str(directory / "target-profile.json"),
                "--certificate",
                str(directory / "candidate-certificate.json"),
                "--trust-root",
                str(directory / "trust-root.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["input_valid"])
        self.assertFalse(report["capabilities"]["production_authorized"])


if __name__ == "__main__":
    unittest.main()
