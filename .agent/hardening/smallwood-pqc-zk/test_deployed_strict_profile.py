from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("deployed_strict_profile.py")
SPEC = importlib.util.spec_from_file_location("smallwood_deployed_strict_profile", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load deployed_strict_profile.py")
strict = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(strict)


def load_fixture() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    directory = MODULE_PATH.parent
    return (
        strict.load_json_strict(directory / "deployed-profile.json"),
        strict.load_json_strict(directory / "deployed-certificate.json"),
        strict.load_json_strict(directory / "deployed-trust-root.json"),
    )


class DeployedStrictProfileTests(unittest.TestCase):
    maxDiff = None

    def test_checked_in_deployed_certificate_fails_closed(self) -> None:
        profile, certificate, trust_root = load_fixture()
        selection = strict.select_parameter_profile(profile)
        self.assertTrue(selection["selected"])
        self.assertEqual(selection["geometry"]["row_count"], 699)
        self.assertEqual(len(selection["zero_knowledge_blockers"]), 3)
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        self.assertTrue(report["input_valid"])
        self.assertTrue(report["profile_gate_pass"])
        self.assertEqual(
            report["capabilities"],
            {
                "conditional_parameter_pq128": True,
                "production_soundness_pq128": False,
                "complete_zk": False,
                "production_authorized": False,
            },
        )
        self.assertFalse(report["zero_knowledge"]["structural_gate_pass"])
        self.assertIn(
            "retained SMW2 radix-2 DECS domain intersects LVCS interpolation points; "
            "the fixed 23/2^20 witness-recovery event blocks complete ZK",
            report["blocking_reasons"],
        )
        self.assertEqual(report["verified_evidence_count"], 0)

    def test_exact_deployed_interactive_terms_and_cms_screen(self) -> None:
        profile, certificate, trust_root = load_fixture()
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        soundness = report["soundness"]
        terms = soundness["interactive_terms"]
        self.assertEqual(
            terms["epsilon1_decs_uniform_matrix"]["denominator"],
            str(strict.GOLDILOCKS_ORDER**5),
        )
        self.assertEqual(
            terms["epsilon2_piop_constraint_batching"]["denominator"],
            str(strict.GOLDILOCKS_ORDER**5),
        )
        self.assertEqual(
            terms["epsilon3_piop_opening"]["numerator"],
            str(
                (
                    strict.Fraction(strict.falling_product(544, 5), strict.falling_product(strict.GOLDILOCKS_ORDER - 64, 5))
                ).numerator
            ),
        )
        self.assertEqual(
            terms["epsilon4_decs_opening"]["numerator"],
            str(
                (
                    strict.Fraction(strict.falling_product(397, 23), strict.falling_product(1_048_576, 23))
                ).numerator
            ),
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
        self.assertEqual(soundness["parameter_bound_status"], "conditional_model_bound")
        self.assertEqual(soundness["production_bound_status"], "unavailable")
        self.assertTrue(soundness["conditional_low_advantage_gate_pass"])
        self.assertTrue(soundness["conditional_work_factor_gate_pass"])
        self.assertIsNone(soundness["deployment_losses_at_2pow64"])
        self.assertIsNone(soundness["deployment_losses_at_2pow128"])
        self.assertIsNone(soundness["composed_at_2pow64"])
        self.assertIsNone(soundness["composed_at_2pow128"])
        self.assertEqual(report["production_status"]["status"], "disabled")
        self.assertIsNone(report["production_status"]["composed_pq_security_bits"])
        self.assertEqual(
            report["attack_record"]["end_to_end_smallwood_forgery"]["status"],
            "none_recorded",
        )
        self.assertEqual(
            report["attack_record"]["strongest_documented_component_attack"][
                "quantum_query_exponent"
            ],
            128.0,
        )
        self.assertFalse(
            report["attack_record"]["strongest_documented_component_attack"][
                "end_to_end_transaction_forgery"
            ]
        )

    def test_hash_floor_and_transcript_are_pinned(self) -> None:
        profile, certificate, trust_root = load_fixture()
        profile = copy.deepcopy(profile)
        profile["commitment"]["output_bits"] = 383
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn("commitment digest must be at least 384 bits", report["blocking_reasons"])

        profile, certificate, trust_root = load_fixture()
        profile = copy.deepcopy(profile)
        profile["commitment"]["output_bits"] = 384
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn(
            "deployed SmallWood commitment output must be exactly 512 bits",
            report["blocking_reasons"],
        )

        profile, certificate, trust_root = load_fixture()
        profile = copy.deepcopy(profile)
        profile["protocol"]["transcript"]["algorithm"] = "BLAKE3"
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        self.assertFalse(report["profile_gate_pass"])
        self.assertIn("transcript.algorithm must equal 'SHA-512'", report["blocking_reasons"])

    def test_m4_or_binius_identity_cannot_be_selected(self) -> None:
        profile, certificate, trust_root = load_fixture()
        profile = copy.deepcopy(profile)
        profile["deployment"]["backend"] = "Binius"
        report = strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])
        self.assertFalse(report["profile_gate_pass"])
        self.assertFalse(report["capabilities"]["production_soundness_pq128"])
        self.assertIn(
            "deployment.backend must equal 'SmallwoodCandidate'",
            report["blocking_reasons"],
        )

    def test_setting_capability_booleans_is_not_an_input(self) -> None:
        profile, certificate, trust_root = load_fixture()
        certificate = copy.deepcopy(certificate)
        certificate["capabilities"] = {
            "complete_zk": True,
            "pq128": True,
            "production_authorized": True,
        }
        with self.assertRaises(strict.GateInputError):
            strict.evaluate(profile, certificate, trust_root, MODULE_PATH.parents[3])

    def test_one_receipt_cannot_promote_the_deployed_profile(self) -> None:
        profile, certificate, trust_root = load_fixture()
        certificate = copy.deepcopy(certificate)
        trust_root = copy.deepcopy(trust_root)
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            artifact = repo_root / "artifact.txt"
            artifact.write_text("source-bound partial evidence\n", encoding="utf-8")
            receipt = {
                "schema": strict.RECEIPT_SCHEMA,
                "profile_id": strict.PROFILE_ID,
                "evidence_id": "proof_system_implemented",
                "claim": strict.EVIDENCE_POLICY["proof_system_implemented"]["claim"],
                "kind": "formal-proof",
                "result": "pass",
                "authority_scope": "deployed-end-to-end",
                "assumption_only": False,
                "machine_checked": True,
                "checker": {
                    "name": "test-checker",
                    "version": "1",
                    "command_sha256": hashlib.sha256(b"test command").hexdigest(),
                    "exit_code": 0,
                },
                "artifacts": [
                    {
                        "path": "artifact.txt",
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    }
                ],
                "quantitative_claims": {},
            }
            receipt_path = repo_root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            certificate["evidence"]["proof_system_implemented"] = {
                "status": "verified",
                "receipt_path": "receipt.json",
                "receipt_sha256": digest,
            }
            trust_root["accepted_receipts"]["proof_system_implemented"] = [digest]
            report = strict.evaluate(profile, certificate, trust_root, repo_root)
        self.assertEqual(report["verified_evidence_count"], 1)
        self.assertFalse(report["capabilities"]["complete_zk"])
        self.assertFalse(report["capabilities"]["production_soundness_pq128"])
        self.assertIn(
            "evidence not verified: decs_domain_and_leaf_hiding (missing)",
            report["blocking_reasons"],
        )

    def test_cli_reports_well_formed_but_unauthorized_status(self) -> None:
        directory = MODULE_PATH.parent
        completed = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--profile",
                str(directory / "deployed-profile.json"),
                "--certificate",
                str(directory / "deployed-certificate.json"),
                "--trust-root",
                str(directory / "deployed-trust-root.json"),
            ],
            cwd=MODULE_PATH.parents[3],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        report = json.loads(completed.stdout)
        self.assertEqual(report["capabilities"]["production_authorized"], False)
        self.assertEqual(report["shortest_concrete_gap"]["symbol"], "deployedEndToEnd")


if __name__ == "__main__":
    unittest.main()
