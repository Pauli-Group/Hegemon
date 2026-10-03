from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "frontier_gate.py"
SPEC = importlib.util.spec_from_file_location("hegemon_frontier_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

VECTOR_BRIDGE_SURFACE_PATHS = (
    "formal/lean/Hegemon/FullShakeRelation/GenerateFullShakeRelationVectors.lean",
    "formal/lean/lakefile.lean",
    "formal/lean/lake-manifest.json",
    "formal/lean/lean-toolchain",
    "testdata/formal_core_vectors/full_shake_relation.json",
    "circuits/standalone-full-shake256-relation-prototype/tests/lean_full_shake_relation_vectors.rs",
)


class FrontierGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.production_policy = GATE.load_policy(
            GATE.DEFAULT_POLICY, require_sealed=True
        )

    def write(self, root: Path, relative: str, payload: bytes) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def build_complete_bundle(
        self, root: Path, *, surface_paths: tuple[str, ...] = ("surface.txt",)
    ):
        policy = copy.deepcopy(self.production_policy)
        policy["production_surface_paths"] = list(surface_paths)
        policy["evidence_root"] = "evidence/verified"
        for index, surface_path in enumerate(surface_paths):
            payload = (
                b"production relation\n"
                if surface_path == "surface.txt"
                else f"vector bridge surface {index}\n".encode()
            )
            self.write(root, surface_path, payload)
        source = self.write(root, "candidate/source.patch", b"candidate source\n")
        source_digest = GATE.sha256_file(source)

        proof_artifacts = []
        for index, body in enumerate((b"proof-one", b"proof-two")):
            path = self.write(root, f"evidence/proof-artifacts/proof-{index}.bin", body)
            proof_artifacts.append(
                {
                    "path": str(path.relative_to(root)),
                    "sha256": GATE.sha256_file(path),
                    "bytes": len(body),
                    "candidate_source_sha256": source_digest,
                }
            )

        activation = {
            "circuit_version": 5,
            "crypto_suite": 4,
            "backend": "binary-pq128",
            "profile": "strict-v1",
            "family_id": 1,
            "action_ids": [7],
            "standalone_proof": True,
            "aggregation": False,
            "sidecar_authority": False,
            "network_binding_fields": [
                "chain-id",
                "genesis-block-id",
                "rules-hash",
            ],
        }
        measurement = {
            "proof_bytes": len(b"proof-one"),
            "envelope_bytes": len(b"proof-one") + 12,
            "proof_artifacts": proof_artifacts,
        }
        relation = policy["relation"]
        relation_parameters = dict(relation)
        relation_parameters.pop("semantic_relation_id")
        relation_parameters.pop("covered_predicates")
        relation_parameters.pop("activity_mask_cases")
        details = {
            "relation": {
                "semantic_relation_id": relation["semantic_relation_id"],
                "parameters": relation_parameters,
                "covered_predicates": relation["covered_predicates"],
                "activity_mask_cases": relation["activity_mask_cases"],
                "positive_cases": 9,
                "negative_cases": 64,
                "differential_cases": 80,
                "reference_candidate_mismatches": 0,
                "canonical_semantic_refinement_closed": True,
            },
            "binding": {
                "activation": activation,
                "bound_fields": policy["requirements"]["binding"][
                    "required_bound_fields"
                ],
                "mutation_cases": policy["requirements"]["binding"][
                    "mutation_cases"
                ],
                "release_manifest_authorized": True,
                "action_projection_exact": True,
                "network_binding_in_transcript": True,
            },
            "zk": {
                "definition": "computational-zero-knowledge-full-witness",
                "complete_witness_privacy_proved": True,
                "simulator_defined_for_full_relation": True,
                "proof_bytes_leakage_audit_passed": True,
                "selective_opening_accounted": True,
                "qrom_zk_composition_accounted": True,
                "external_review_id": "zk-review-test",
            },
            "pq128": {
                "composed_post_quantum_bits": 128,
                "knowledge_soundness_post_quantum_bits": 128,
                "commitment_binding_post_quantum_bits": 128,
                "semantic_collision_post_quantum_bits": 128,
                "challenge_field_bits": 384,
                "semantic_hash": "SHAKE256-448",
                "proof_hash": "SHAKE256-512",
                "fiat_shamir_qrom_complete": True,
                "component_losses_complete": True,
                "composed_verifier_checked": True,
                "external_review_id": "pq-review-test",
            },
            "parser": {
                "parser_entrypoint": "independent::parse_exact",
                "proof_artifacts": proof_artifacts,
                "clean_reproductions": 2,
                "exact_consumption": True,
                "canonical_reencode": True,
                "trailing_bytes_rejected": True,
                "truncations_rejected": True,
                "declared_length_mismatch_rejected": True,
                "unknown_backend_rejected": True,
                "unknown_version_rejected": True,
            },
            "formal_differential": {
                "lean_kernel_build_passed": True,
                "axiom_audit_passed": True,
                "sorry_count": 0,
                "proved_obligations": policy["requirements"]["formal_differential"][
                    "proved_obligations"
                ],
                "residual_semantic_or_refinement_assumptions": [],
                "differential_activity_masks": 16,
                "differential_cases": 80,
                "differential_mismatches": 0,
                "negative_mutation_cases": 64,
            },
        }

        surface_digest = GATE.production_surface_sha256(root, policy)
        claims = {}
        for gate in policy["gates"]:
            certificate = {
                "schema": policy["certificate_schema"],
                "gate": gate,
                "candidate_id": "complete-candidate",
                "candidate_source_sha256": source_digest,
                "production_surface_sha256": surface_digest,
                "issuer": policy["gate_issuers"][gate],
                "independent_of_candidate": True,
                "passed": True,
                "details": details[gate],
            }
            path = self.write(
                root,
                f"evidence/verified/{gate}.json",
                GATE.canonical_bytes(certificate),
            )
            claims[gate] = {
                "status": "verified",
                "certificate": {
                    "path": str(path.relative_to(root)),
                    "sha256": GATE.sha256_file(path),
                },
            }
            policy["authorized_certificate_sha256"][gate].append(
                GATE.sha256_file(path)
            )

        candidate = {
            "schema": policy["manifest_schema"],
            "candidate_id": "complete-candidate",
            "candidate_artifact": {
                "path": str(source.relative_to(root)),
                "sha256": source_digest,
            },
            "activation": activation,
            "measurement": measurement,
            "claims": claims,
        }
        candidate_path = self.write(
            root, "candidate.json", GATE.canonical_bytes(candidate)
        )
        return policy, candidate, candidate_path

    def rewrite_candidate(self, path: Path, candidate: dict) -> None:
        path.write_bytes(GATE.canonical_bytes(candidate))

    def rewrite_certificate(
        self, root: Path, candidate: dict, gate: str, mutate
    ) -> None:
        ref = candidate["claims"][gate]["certificate"]
        path = root / ref["path"]
        certificate = json.loads(path.read_text())
        mutate(certificate)
        path.write_bytes(GATE.canonical_bytes(certificate))
        ref["sha256"] = GATE.sha256_file(path)

    def test_complete_independent_bundle_admits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, _, candidate_path = self.build_complete_bundle(root)
            decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
            self.assertTrue(decision["admitted"], decision["failures"])
            self.assertEqual(len(decision["verified_certificates"]), 6)

    def test_every_gate_is_independently_mandatory(self) -> None:
        for missing_gate in self.production_policy["gates"]:
            with self.subTest(gate=missing_gate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, candidate, candidate_path = self.build_complete_bundle(root)
                candidate["claims"][missing_gate] = {
                    "status": "failed",
                    "certificate": None,
                }
                self.rewrite_candidate(candidate_path, candidate)
                decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
                self.assertFalse(decision["admitted"])
                self.assertIn(
                    f"{missing_gate}: status is not verified", decision["failures"]
                )

    def test_narrow_relation_cannot_self_attest_full_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, candidate, candidate_path = self.build_complete_bundle(root)
            self.rewrite_certificate(
                root,
                candidate,
                "relation",
                lambda cert: cert["details"].update(
                    semantic_relation_id="hegemon.pay1x2-only"
                ),
            )
            policy["authorized_certificate_sha256"]["relation"] = [
                candidate["claims"]["relation"]["certificate"]["sha256"]
            ]
            self.rewrite_candidate(candidate_path, candidate)
            decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
            self.assertFalse(decision["admitted"])
            self.assertTrue(
                any("different semantic relation" in item for item in decision["failures"])
            )

    def test_sealed_policy_is_the_full_fixed_slot_v5_delta_relation(self) -> None:
        relation = self.production_policy["relation"]
        self.assertEqual(relation["canonical_statement_magic"], "HGF4ST02")
        self.assertEqual(relation["canonical_statement_bytes"], 853)
        self.assertEqual(relation["semantic_digest_bytes"], 56)
        self.assertEqual(relation["m4_public_words"], 114)
        self.assertEqual(relation["private_words"], 671)
        self.assertEqual(relation["accepted_activity_masks"], 9)
        self.assertEqual(relation["rejected_activity_masks"], 7)
        self.assertEqual(
            relation["note_kinds"], ["ordinary", "accumulator", "value-lock"]
        )
        self.assertEqual(
            relation["private_authorization_modes"],
            [
                "single-key",
                "accumulator-init",
                "approval-step",
                "value-lock-creation",
                "final-threshold-spend",
            ],
        )
        self.assertEqual(relation["value_balance"], "canonical-zero")
        self.assertEqual(
            relation["stablecoin_issuance"], "enabled-nonzero-signed"
        )
        self.assertTrue(
            all(
                not digests
                for digests in self.production_policy[
                    "authorized_certificate_sha256"
                ].values()
            )
        )
        for path in (
            "formal/lean/Hegemon/FullShakeRelation.lean",
            "formal/lean/Hegemon/FullShakeRelation/Core.lean",
            "formal/lean/Hegemon/FullShakeRelation/StateMachine.lean",
            "formal/lean/Hegemon/FullShakeRelation/Grammar.lean",
            "formal/lean/Hegemon/FullShakeRelation/SecurityBoundary.lean",
            ".agent/FULL_SHAKE_RELATION_FORMAL_EXECPLAN.md",
        ):
            self.assertIn(path, self.production_policy["production_surface_paths"])
        for path in VECTOR_BRIDGE_SURFACE_PATHS:
            self.assertIn(path, self.production_policy["production_surface_paths"])

    def test_each_vector_bridge_surface_mutation_stales_every_certificate(self) -> None:
        for mutated_path in VECTOR_BRIDGE_SURFACE_PATHS:
            with self.subTest(path=mutated_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, _, candidate_path = self.build_complete_bundle(
                    root, surface_paths=VECTOR_BRIDGE_SURFACE_PATHS
                )
                path = root / mutated_path
                path.write_bytes(path.read_bytes() + b"mutated\n")
                decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
                self.assertFalse(decision["admitted"])
                self.assertEqual(
                    sum(
                        "production surface is stale" in item
                        for item in decision["failures"]
                    ),
                    len(policy["gates"]),
                )

    def test_each_vector_bridge_surface_deletion_fails_closed(self) -> None:
        for missing_path in VECTOR_BRIDGE_SURFACE_PATHS:
            with self.subTest(path=missing_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, _, candidate_path = self.build_complete_bundle(
                    root, surface_paths=VECTOR_BRIDGE_SURFACE_PATHS
                )
                (root / missing_path).unlink()
                with self.assertRaisesRegex(GATE.GateError, "cannot stat"):
                    GATE.evaluate_candidate(candidate_path, policy, root=root)

    def test_wrong_nine_seven_mask_certificate_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, candidate, candidate_path = self.build_complete_bundle(root)
            self.rewrite_certificate(
                root,
                candidate,
                "relation",
                lambda cert: cert["details"].update(positive_cases=8),
            )
            policy["authorized_certificate_sha256"]["relation"] = [
                candidate["claims"]["relation"]["certificate"]["sha256"]
            ]
            self.rewrite_candidate(candidate_path, candidate)
            decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
            self.assertFalse(decision["admitted"])
            self.assertTrue(
                any("exactly the nine accepted masks" in item for item in decision["failures"])
            )

    def test_transparent_or_127_bit_candidate_rejects(self) -> None:
        mutations = {
            "zk": lambda cert: cert["details"].update(
                complete_witness_privacy_proved=False
            ),
            "pq128": lambda cert: cert["details"].update(
                composed_post_quantum_bits=127
            ),
        }
        for gate, mutation in mutations.items():
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, candidate, candidate_path = self.build_complete_bundle(root)
                self.rewrite_certificate(root, candidate, gate, mutation)
                policy["authorized_certificate_sha256"][gate] = [
                    candidate["claims"][gate]["certificate"]["sha256"]
                ]
                self.rewrite_candidate(candidate_path, candidate)
                decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
                self.assertFalse(decision["admitted"])

    def test_production_source_drift_stales_all_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, _, candidate_path = self.build_complete_bundle(root)
            (root / "surface.txt").write_bytes(b"changed production relation\n")
            decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
            self.assertFalse(decision["admitted"])
            self.assertEqual(
                sum("production surface is stale" in item for item in decision["failures"]),
                6,
            )

    def test_proof_artifact_deletion_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, _, candidate_path = self.build_complete_bundle(root)
            (root / "evidence/proof-artifacts/proof-0.bin").unlink()
            decision = GATE.evaluate_candidate(candidate_path, policy, root=root)
            self.assertFalse(decision["admitted"])
            self.assertTrue(
                any("cannot stat" in item for item in decision["failures"])
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}\n')
            with self.assertRaisesRegex(GATE.GateError, "duplicate JSON key"):
                GATE.read_json_exact(path)

    def test_current_65440_byte_point_has_zero_frontier_status(self) -> None:
        decision = GATE.evaluate_candidate(
            GATE.DEFAULT_CANDIDATE,
            self.production_policy,
            root=GATE.REPO_ROOT,
        )
        self.assertFalse(decision["admitted"])
        self.assertEqual(decision["proof_bytes"], 65_440)
        self.assertEqual(decision["verified_certificates"], {})
        self.assertIn(
            "parser: requires at least 2 retained exact proof artifacts",
            decision["failures"],
        )


if __name__ == "__main__":
    unittest.main()
