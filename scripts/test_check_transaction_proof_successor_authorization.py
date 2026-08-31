#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_transaction_proof_successor_authorization as gate


TEST_PROFILE_ID = "hegemon.smallwood.poseidon2.v8-eta.smz9.v1"
TEST_BUNDLE_PATH = "config/smallwood-v8-poseidon2-successor-evidence-bundle.json"
TEST_SOURCE_REVISION = "ab" * 20
TEST_REVIEW_TRUST_ROOT_ID = "test-only-independent-review-root"
TEST_REVIEW_PUBLIC_KEY_PATH = (
    ".agent/artifacts/smallwood-poseidon2-v8/review/test-reviewer-ml-dsa-87.pub"
)
TEST_REVIEW_ARTIFACT_PATH = (
    ".agent/artifacts/smallwood-poseidon2-v8/review/test-independent-review.json"
)
TEST_REVIEW_SIGNATURE_PATH = (
    ".agent/artifacts/smallwood-poseidon2-v8/review/test-independent-review.sig"
)
TEST_REVIEW_PUBLIC_KEY_PAYLOAD = bytes(
    (index % 251) + 1 for index in range(gate.ML_DSA_87_PUBLIC_KEY_BYTES)
)
TEST_REVIEW_SIGNATURE_PAYLOAD = bytes(
    ((index * 7) % 251) + 1 for index in range(gate.ML_DSA_87_SIGNATURE_BYTES)
)
TEST_REVIEW_TRUST_ROOT = {
    "trust_root_id": TEST_REVIEW_TRUST_ROOT_ID,
    "reviewer_identity": "test-only independent reviewer",
    "signature_scheme": "ML-DSA-87",
    "public_key_path": TEST_REVIEW_PUBLIC_KEY_PATH,
    "public_key_bytes": len(TEST_REVIEW_PUBLIC_KEY_PAYLOAD),
    "public_key_sha512": hashlib.sha512(TEST_REVIEW_PUBLIC_KEY_PAYLOAD).hexdigest(),
    "review_artifact_path": TEST_REVIEW_ARTIFACT_PATH,
    "signature_path": TEST_REVIEW_SIGNATURE_PATH,
    "verification_command": (
        "test-only-evidence:authenticated_independent_security_review"
    ),
}
STRICT_ARTIFACT_BINARY_PAYLOAD = b"test-only command-contract executable"
TEST_LIFECYCLE_COMMANDS = {
    evidence_id: tuple(
        (stage, f"test-only:{evidence_id}:{stage}") for stage in stages
    )
    for evidence_id, stages in gate.LIFECYCLE_INTEGRATION_EVIDENCE.items()
}
TEST_RELEASE_EVIDENCE_COMMANDS = {
    evidence_id: (f"test-only-evidence:{evidence_id}",)
    for evidence_id in gate.SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS
}

REAL_SHAPED_EVIDENCE_PATHS = {
    **gate.SOURCE_EVIDENCE_PATHS_BY_ID,
    **gate.FIXED_NON_SOURCE_EVIDENCE_PATHS_BY_ID,
    "relation_program": (
        ".agent/artifacts/smallwood-poseidon2-v8/relation-program.bin"
    ),
    "relation_source_supply_chain_manifest": (
        "config/smallwood-v8-poseidon2-relation-source-manifest.json"
    ),
    "relation_manifest": "config/smallwood-v8-poseidon2-relation-manifest.json",
    "profile_manifest": "config/smallwood-v8-poseidon2-profile-manifest.json",
    "verifier_program": (
        ".agent/artifacts/smallwood-poseidon2-v8/verifier-program.bin"
    ),
    "verifier_binary_manifest": (
        "config/smallwood-v8-poseidon2-verifier-binary-manifest.json"
    ),
    "transcript_manifest": (
        "config/smallwood-v8-poseidon2-transcript-manifest.json"
    ),
    "cryptographic_role_manifest": (
        "config/smallwood-v8-poseidon2-cryptographic-role-manifest.json"
    ),
    "retained_proof_primary": (
        ".agent/artifacts/smallwood-poseidon2-v8/retained_proof_primary/"
        "smz9-structural-test-primary/proof.bin"
    ),
    "retained_proof_independent": (
        ".agent/artifacts/smallwood-poseidon2-v8/retained_proof_independent/"
        "smz9-structural-test-independent/proof.bin"
    ),
    "successor_release_manifest": (
        "config/smallwood-v8-poseidon2-successor-release-manifest.json"
    ),
}


def test_identity() -> dict[str, object]:
    return {
        "network_id": 0x4847_4D38,
        "circuit_version": 8,
        "crypto_suite": 7,
        "family_id": 1,
        "action_id": 10,
        "coinbase_action_id": 11,
        "backend_wire_id": 2,
        "profile_wire_id": 6,
        "domain_set": 4,
        "statement_magic_hex": "4847563850423032",
        "statement_bytes": 960,
        "envelope_magic_hex": "535750384c433032",
        "envelope_version": 1,
        "native_leaf_magic_hex": "4847563854583032",
        "native_leaf_version": 1,
        "inner_proof_wire_magic_hex": "534d5a39",
        "inner_proof_wire_version": 1,
        "proof_mode": "inline_self_contained",
        "consensus_binding_digest_bytes": 48,
        "transaction_digest_bytes": 56,
        "stablecoin_policy_hash_bytes": 48,
        "stablecoin_oracle_commitment_bytes": 48,
        "stablecoin_attestation_commitment_bytes": 48,
        "transcript_digest_bytes": 64,
        "proof_commitment_bytes": 64,
        "chain_id_hex": hashlib.sha512(b"test chain id").digest()[:48].hex(),
        "genesis_id_hex": hashlib.sha512(b"test genesis id").digest()[:48].hex(),
        "rules_hash_hex": hashlib.sha512(b"test rules hash").digest()[:48].hex(),
        "relation_digest_hex": "",
        "activation_height": 2,
        "deactivation_height_exclusive": 2 + gate.RETAINED_SECURITY_EPOCH_BLOCKS,
        "activation_genesis_hash": hashlib.sha256(
            b"test activation genesis block"
        ).hexdigest(),
        "stablecoin_genesis_root": [11, 12, 13, 14, 15, 16, 17],
        "note_genesis_root": list(gate.RETAINED_NOTE_GENESIS_ROOT),
        "relation_program_sha512": "",
        "relation_manifest_sha512": "",
        "profile_manifest_sha512": "",
        "verifier_program_sha512": "",
        "verifier_binary_manifest_sha512": "",
        "transcript_manifest_sha512": "",
        "cryptographic_role_manifest_sha512": "",
        "source_derived_security_report_sha512": "",
        "security_epoch_max_proofs": 2_097_152,
        "max_proofs_per_block": 512,
        "max_proof_actions_per_block": 512,
        "claimed_security_bits": 128,
        "max_proof_bytes": 122_863,
        "max_outer_envelope_bytes": 131_068,
        "max_inline_route_args_bytes": 131_072,
        "max_v8_pending_action_bytes": 131_297,
    }


def write_canonical(path: Path, document: object) -> bytes:
    payload = gate.canonical_json_bytes(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def test_lifecycle_state_binding(identity: dict[str, object]) -> dict[str, object]:
    note_root_after = list(identity["note_genesis_root"])
    note_root_after[0] = (note_root_after[0] + 1) % gate.GOLDILOCKS_MODULUS
    return {
        "parent_height": identity["activation_height"] - 1,
        "candidate_height": identity["activation_height"],
        "relation_digest_hex": identity["relation_digest_hex"],
        "note_anchor": list(identity["note_genesis_root"]),
        "note_root_after": note_root_after,
        "stablecoin_current_root": list(identity["stablecoin_genesis_root"]),
        "stablecoin_root_before": list(identity["stablecoin_genesis_root"]),
        "stablecoin_root_after": list(identity["stablecoin_genesis_root"]),
    }


def lifecycle_command_output(
    evidence_id: str,
    stages: list[str],
    proof_sha512: str,
    proof_bytes: int,
    identity: dict[str, object],
) -> str:
    state_binding = test_lifecycle_state_binding(identity)
    return gate.canonical_json_bytes(
        {
            "schema": gate.LIFECYCLE_COMMAND_RECEIPT_SCHEMA,
            "evidence_id": evidence_id,
            "profile_id": TEST_PROFILE_ID,
            "relation_program_sha512": identity["relation_program_sha512"],
            "source_revision": TEST_SOURCE_REVISION,
            "execution_kind": "actual_subsystem_integration",
            "retained_proof_id": "retained_proof_primary",
            "proof_sha512": proof_sha512,
            "proof_bytes": proof_bytes,
            "capability": {
                field: identity[field] for field in gate.CAPABILITY_IDENTITY_FIELDS
            },
            "capability_identity_sha512": gate.capability_identity_sha512(identity),
            "state_binding": state_binding,
            "production_verifier_used": True,
            "parser_stage_labels_used_as_authority": False,
            "validity_shortcuts_used": False,
            "stages": [
                {
                    "stage": stage,
                    "passed": True,
                    "proof_sha512": proof_sha512,
                    "proof_bytes": proof_bytes,
                    "state_binding": state_binding,
                }
                for stage in stages
            ],
        }
    ).decode("utf-8")


def source_evidence_command_output(
    evidence_id: str,
    kind: str,
    source_inventory_sha512: str,
    primary_proof_sha512: str,
    independent_proof_sha512: str,
    identity: dict[str, object],
    result: dict[str, object],
) -> str:
    return gate.canonical_json_bytes(
        {
            "schema": gate.SOURCE_COMMAND_RECEIPT_SCHEMA,
            "evidence_id": evidence_id,
            "kind": kind,
            "profile_id": TEST_PROFILE_ID,
            "relation_program_sha512": identity["relation_program_sha512"],
            "source_revision": TEST_SOURCE_REVISION,
            "source_inventory_sha512": source_inventory_sha512,
            "retained_proof_primary_sha512": primary_proof_sha512,
            "retained_proof_independent_sha512": independent_proof_sha512,
            "source_derived_security_report_sha512": identity[
                "source_derived_security_report_sha512"
            ],
            "capability_identity_sha512": gate.capability_identity_sha512(identity),
            "evidence_claim_sha512": gate.release_evidence_claim_sha512(
                evidence_id, result
            ),
            "release_workflow_sha512": gate.RELEASE_WORKFLOW_SHA512,
            "passed": True,
            "unresolved_premises": [],
        }
    ).decode("utf-8")


def canonical_smz9_wire_fixture(independent: bool) -> bytes:
    vectors = json.loads(
        (ROOT / "testdata/formal_crypto_vectors/smallwood_smz9_proof_wire.json")
        .read_text(encoding="utf-8")
    )
    case = next(case for case in vectors["cases"] if case["accepted"] is True)
    proof = bytearray.fromhex(case["proof_hex"].removeprefix("0x"))
    proof[4] = 2 if independent else 1
    return bytes(proof)


def make_fixture(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], gate.AuthorizedProfile]:
    (root / "circuits/transaction/src").mkdir(parents=True, exist_ok=True)
    (root / "node/src").mkdir(parents=True, exist_ok=True)
    (root / "wallet/src").mkdir(parents=True, exist_ok=True)
    (root / "walletd/src").mkdir(parents=True, exist_ok=True)
    (root / ".cargo").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "2"\nmembers = ["circuits/transaction", "node", "wallet", "walletd"]\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "hegemon-node"\nversion = "0.1.0"\n'
        '\n[[package]]\nname = "transaction-circuit"\nversion = "0.1.0"\n'
        '\n[[package]]\nname = "wallet"\nversion = "0.1.0"\n'
        '\n[[package]]\nname = "walletd"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (root / "circuits/transaction/Cargo.toml").write_text(
        '[package]\nname = "transaction-circuit"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (root / "node/Cargo.toml").write_text(
        '[package]\nname = "hegemon-node"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (root / "node/src/lib.rs").write_text(
        "// test-only node release source root\n", encoding="utf-8"
    )
    (root / "wallet/Cargo.toml").write_text(
        '[package]\nname = "wallet"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (root / "wallet/src/lib.rs").write_text(
        "// test-only wallet release source root\n", encoding="utf-8"
    )
    (root / "walletd/Cargo.toml").write_text(
        '[package]\nname = "walletd"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (root / "walletd/src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / ".cargo/config.toml").write_text(
        "[net]\noffline = true\n", encoding="utf-8"
    )
    (root / ".gitignore").write_text(
        ".agent/artifacts/smallwood-poseidon2-v8/\n", encoding="utf-8"
    )
    (root / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.91.1"\n', encoding="utf-8"
    )
    imported_formal_dependency = (
        root / "formal/crypto/HegemonCrypto/InventoryImportedDependency.lean"
    )
    imported_formal_dependency.parent.mkdir(parents=True, exist_ok=True)
    imported_formal_dependency.write_text(
        "def inventoryImportedDependency : Nat := 1\n", encoding="utf-8"
    )
    (root / "formal/crypto/lakefile.toml").write_text(
        'name = "fixture"\n', encoding="utf-8"
    )
    (root / "formal/crypto/lean-toolchain").write_text(
        "leanprover/lean4:v4.21.0\n", encoding="utf-8"
    )
    (root / "formal/lean/Hegemon").mkdir(parents=True, exist_ok=True)
    (root / "formal/lean/Hegemon/InventoryDependency.lean").write_text(
        "def inventoryLeanDependency : Nat := 1\n", encoding="utf-8"
    )
    (root / "formal/lean/lakefile.lean").write_text(
        "import Lake\n", encoding="utf-8"
    )
    (root / "formal/lean/lean-toolchain").write_text(
        "leanprover/lean4:v4.21.0\n", encoding="utf-8"
    )
    for ignored_tree in (
        root / "formal/crypto/.lake/build",
        root / "formal/lean/.lake/build",
    ):
        ignored_tree.mkdir(parents=True, exist_ok=True)
        (ignored_tree / "ignored.olean").write_bytes(b"ignored build output")
    for binding in gate.FORMAL_SECURITY_RECEIPT_BINDINGS.values():
        formal_path = root / str(binding["formal_source_path"])
        formal_path.parent.mkdir(parents=True, exist_ok=True)
        theorem_leaf = str(binding["release_theorem"]).rsplit(".", 1)[-1]
        formal_path.write_text(
            "import HegemonCrypto.InventoryImportedDependency\n"
            f"theorem {theorem_leaf} : True := by trivial\n",
            encoding="utf-8",
        )
    (root / "circuits/transaction/src/lib.rs").write_text(
        "// test-only proof source inventory root\n", encoding="utf-8"
    )
    (root / "circuits/transaction/src/proof_config.rs").write_text(
        "// test-only independently inventoried proof configuration\n", encoding="utf-8"
    )
    generator_source = (ROOT / gate.RETAINED_GENERATOR_SOURCE_PATH).read_bytes()
    generator_source_path = root / gate.RETAINED_GENERATOR_SOURCE_PATH
    generator_source_path.parent.mkdir(parents=True, exist_ok=True)
    generator_source_path.write_bytes(generator_source)
    identity = test_identity()
    canonical_relation_program = (
        ROOT / "testdata/formal_core_vectors/poseidon2_v8_relation_program.bin"
    ).read_bytes()
    identity["relation_program_sha512"] = hashlib.sha512(
        canonical_relation_program
    ).hexdigest()
    identity["relation_digest_hex"] = identity["relation_program_sha512"][:96]
    entries: list[dict[str, object]] = []
    for index, (evidence_id, kind) in enumerate(
        sorted(gate.REQUIRED_EVIDENCE_KINDS.items())
    ):
        relative = REAL_SHAPED_EVIDENCE_PATHS.get(
            evidence_id,
            ".agent/artifacts/smallwood-poseidon2-v8/release-evidence/"
            f"{evidence_id}.json",
        )
        if evidence_id in gate.RETAINED_PROOF_IDS:
            payload = canonical_smz9_wire_fixture(
                evidence_id == "retained_proof_independent"
            )
            relative = (
                ".agent/artifacts/smallwood-poseidon2-v8/"
                f"{evidence_id}/smz9-{hashlib.sha512(payload).hexdigest()[:24]}/proof.bin"
            )
        elif evidence_id == "relation_program":
            payload = canonical_relation_program
        elif kind == "program":
            magic = b"HGV8RP03" if evidence_id == "relation_program" else b"HGV8VP01"
            payload = magic + bytes([index]) + evidence_id.encode("ascii")
        elif kind == "source":
            payload = (
                f"// exact V8 release fixture source {index}: {evidence_id}\n"
            ).encode("utf-8")
        elif evidence_id == "source_derived_composed_security_report":
            security_report = json.loads(
                (
                    ROOT
                    / gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH
                ).read_text(encoding="utf-8")
            )
            for assumption in security_report["assumptions"]:
                assumption["satisfied"] = True
            security_report["unbounded_history_theorem_required"] = (
                gate.GLOBAL_QROM_LIFETIME_SCHEMA
            )

            activation = identity["activation_height"]
            deactivation = activation + gate.RETAINED_SECURITY_EPOCH_BLOCKS
            security_report["budget"]["capability_activation_height"] = activation
            security_report["budget"][
                "capability_deactivation_height_exclusive"
            ] = deactivation
            security_report["lifetime_binding"].update(
                {
                    "capability_activation_height": activation,
                    "capability_deactivation_height_exclusive": deactivation,
                    "capability_window_blocks": gate.RETAINED_SECURITY_EPOCH_BLOCKS,
                    "capability_max_proof_interactions": identity[
                        "security_epoch_max_proofs"
                    ],
                    "capability_window_within_analysis_budget": True,
                    "consensus_budget_binding_receipt_present": True,
                }
            )
            security_report["proof_exposure_accounting"].update(
                {
                    "observed_honest_proof_views": identity[
                        "security_epoch_max_proofs"
                    ],
                    "observed_honest_proof_views_model_receipt_present": True,
                    "analyzed_proof_views": identity["security_epoch_max_proofs"],
                    "analyzed_proof_views_are_canonical_count_diagnostic_only": False,
                }
            )
            for screen in security_report["conditional_global_query_work_screens"]:
                screen[
                    "exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated"
                ] = True
            security_report["adaptive_first_program_no_go"][
                "paper_hypotheses_instantiated_for_exact_smz9_program_point"
            ] = False
            security_report["adaptive_final_piop_programming_screen"][
                "paper_and_executable_hypotheses_instantiated"
            ] = True
            full_tree = security_report["adaptive_full_tree_programming_screen"]
            full_tree["paper_and_all_points_hypotheses_instantiated"] = True
            full_tree["leaf_input_fiber_refinement_instantiated"] = True
            full_tree["hidden_child_internal_node_propagation_instantiated"] = True
            lazy = security_report["adaptive_lazy_merkle_programming_screen"]
            lazy["executable_rng_to_ideal_fresh_inputs_refinement_instantiated"] = True
            lazy["adaptive_lazy_completion_qrom_reduction_instantiated"] = True
            lazy["concrete_sha512_qro_instantiated"] = True
            lazy["global_prior_query_schedule_instantiated"] = True
            security_report["claim_ledger"]["absent_reductions"] = []
            security_report["claim_ledger"]["public_attack_inventory_complete"] = True
            for attack in security_report["known_attacks"]:
                attack["independently_reviewed"] = True

            def power_of_two_loss(term_id: str, bits: int) -> dict[str, object]:
                return {
                    "approximate_security_bits": float(bits),
                    "denominator_decimal": str(1 << bits),
                    "id": term_id,
                    "numerator_decimal": "1",
                    "security_bits_floor": bits,
                }

            def exact_loss(
                term_id: str, numerator: int, denominator: int
            ) -> dict[str, object]:
                floor = gate.exact_ratio_security_bits_floor(numerator, denominator)
                return {
                    "approximate_security_bits": float(floor),
                    "denominator_decimal": str(denominator),
                    "id": term_id,
                    "numerator_decimal": str(numerator),
                    "security_bits_floor": floor,
                }

            honest_exposures = (
                (2 * (1 << 23)) * identity["security_epoch_max_proofs"]
            )

            def primitive_bound_receipt(sha512_mode: bool) -> dict[str, object]:
                prefix = "sha512" if sha512_mode else "poseidon2_width16"
                primitive_honest_exposures = (
                    honest_exposures
                    if sha512_mode
                    else 128 * identity["security_epoch_max_proofs"]
                )
                screens = []
                for query_log2 in (64, 128, 142, 143):
                    query_count = 1 << query_log2
                    if sha512_mode:
                        total = query_count + primitive_honest_exposures
                        collision_numerator = 48 * total**3
                        preimage_numerator = total**2
                        denominator = 1 << 512
                    else:
                        total = query_count + primitive_honest_exposures
                        collision_numerator = total**3
                        preimage_numerator = total**2
                        denominator = gate.GOLDILOCKS_MODULUS**7
                    screens.append(
                        {
                            "quantum_query_log2": query_log2,
                            "collision_advantage_upper_bound": exact_loss(
                                f"{prefix}_collision_at_2pow{query_log2}",
                                collision_numerator,
                                denominator,
                            ),
                            "preimage_advantage_upper_bound": exact_loss(
                                f"{prefix}_preimage_at_2pow{query_log2}",
                                preimage_numerator,
                                denominator,
                            ),
                        }
                    )
                return {
                    "schema": "hegemon.smallwood.poseidon2-v8.primitive-security-bound.v2",
                    "receipt_id": (
                        "sha512-smz9-qrom-primitive-bound"
                        if sha512_mode
                        else "poseidon2-width16-smz9-primitive-bound"
                    ),
                    "primitive_id": (
                        "SHA-512"
                        if sha512_mode
                        else "hegemon-p2w16-v1-114a4e7eb2684d29"
                    ),
                    "exact_primitive_profile_identity": (
                        "sha512-fips180-4-full-64-byte-output-role-framed-smz9"
                        if sha512_mode
                        else (
                            "hegemon-p2w16-v1-114a4e7eb2684d29;"
                            "sha256=114a4e7eb2684d293d13d306a756b03f"
                            "c734f19edbfb80a07126ab1b2ad9e529"
                        )
                    ),
                    "source_inventory_sha512_hex": "11" * 64,
                    "theorem_or_reduction_id": "test-only-exact-primitive-bound",
                    "theorem_source_sha512_hex": "22" * 64,
                    "advantage_function": (
                        "cms-collision=48*T^3/2^512;preimage=T^2/2^512;T=Q+H"
                        if sha512_mode
                        else (
                            "collision=T^3/p^7;preimage=T^2/p^7;"
                            "T=Q+128*V;p=2^64-2^32+1"
                        )
                    ),
                    "advantage_scope": "global-once",
                    "adversarial_query_log2_max": 143,
                    "honest_programmed_oracle_exposures_decimal": str(
                        primitive_honest_exposures
                    ),
                    "bound_uses_queries_plus_honest_exposures": True,
                    "max_proof_actions_per_block": gate.RETAINED_MAX_PROOFS_PER_BLOCK,
                    "max_proof_interactions": identity["security_epoch_max_proofs"],
                    "validity_activation_height": activation,
                    "validity_deactivation_height_exclusive": deactivation,
                    "work_screens": screens,
                    "review_artifact_sha512_hex": "33" * 64,
                    "independently_reviewed": True,
                }

            security_report["sha512_primitive_security_bound"] = (
                primitive_bound_receipt(True)
            )
            security_report["poseidon2_primitive_security_bound"] = (
                primitive_bound_receipt(False)
            )
            security_report[
                "sha512_to_indexed_product_oracle_reduction_bound"
            ] = power_of_two_loss("sha512_to_indexed_product_oracle_reduction", 152)

            security_report["external_whole_view_terms"] = [
                power_of_two_loss(term_id, 152)
                for term_id in (
                    "adaptive_merkle_programming",
                    "adaptive_final_piop_programming",
                    "concrete_sha512_instantiation",
                    "residual_whole_view",
                )
            ]
            base_term = security_report[
                "conditional_global_query_composed_reduction_failure"
            ]
            composed_numerator = int(base_term["numerator_decimal"])
            composed_denominator = int(base_term["denominator_decimal"])

            def add_loss(term: dict[str, object], scale: int = 1) -> None:
                nonlocal composed_numerator, composed_denominator
                numerator = int(term["numerator_decimal"]) * scale
                denominator = int(term["denominator_decimal"])
                composed_numerator, composed_denominator = (
                    composed_numerator * denominator
                    + numerator * composed_denominator,
                    composed_denominator * denominator,
                )

            add_loss(
                security_report[
                    "sha512_to_indexed_product_oracle_reduction_bound"
                ]
            )
            for term in security_report["external_whole_view_terms"]:
                add_loss(term, identity["security_epoch_max_proofs"])
            security_report["deployed_finite_history_composed"] = exact_loss(
                "deployed_finite_history_composed",
                composed_numerator,
                composed_denominator,
            )
            security_report["deployed_composed_security_bits_floor"] = (
                gate.exact_ratio_security_bits_floor(
                    composed_numerator, composed_denominator
                )
            )
            security_report["meets_128_bit_deployed_floor"] = True
            security_report["production_eligible"] = True
            security_report["blockers"] = []
            payload = gate.canonical_json_bytes(security_report)
        elif evidence_id == gate.EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID:
            payload = (
                ROOT / gate.EXECUTABLE_ZK_REFINEMENT_REPORT_PATH
            ).read_bytes()
        else:
            payload = gate.canonical_json_bytes(
                {
                    "authority_conferred": False,
                    "claim_boundary": (
                        "test-only positive schema fixture; source registry remains empty"
                    ),
                    "evidence_id": evidence_id,
                    "kind": kind,
                    "profile_id": TEST_PROFILE_ID,
                    "relation_program_sha512": identity["relation_program_sha512"],
                    "release_gate_passed": True,
                    "schema": gate.RELEASE_EVIDENCE_SCHEMA_OVERRIDES.get(
                        evidence_id,
                        f"hegemon.smallwood.poseidon2-v8.{evidence_id}.v1",
                    ),
                }
            )
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        entries.append(
            {
                "bytes": len(payload),
                "id": evidence_id,
                "kind": kind,
                "path": relative,
                "sha512": hashlib.sha512(payload).hexdigest(),
            }
        )
        identity_pin_field = gate.PINNED_EVIDENCE_DIGEST_FIELDS.get(evidence_id)
        if identity_pin_field is not None:
            identity[identity_pin_field] = hashlib.sha512(payload).hexdigest()

    entries_by_id = {entry["id"]: entry for entry in entries}
    release_source_inventory = gate.recompute_retained_proof_source_inventory(root)
    release_source_inventory_sha512 = release_source_inventory["root_sha512"]
    source_files = sorted(
        (
            {"path": entry["path"], "sha512": entry["sha512"]}
            for entry in entries
            if entry["kind"] == "source"
        ),
        key=lambda source: source["path"],
    )
    for entry in entries:
        evidence_id = entry["id"]
        if entry["kind"] not in {
            "certificate",
            "report",
            "receipt",
            "manifest",
            "attestation",
        }:
            continue
        if evidence_id in {"relation_manifest", "profile_manifest"}:
            continue
        if evidence_id == "source_derived_composed_security_report":
            continue
        if evidence_id == gate.EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID:
            continue
        evidence_path = root / entry["path"]
        document = json.loads(evidence_path.read_text(encoding="utf-8"))
        document["source_files"] = source_files
        document["source_revision"] = TEST_SOURCE_REVISION
        result = {
            "status": "passed",
            "passed": True,
            "profile_id": TEST_PROFILE_ID,
            "semantic_relation": gate.RETAINED_SEMANTIC_RELATION,
            "relation_program_sha512": identity["relation_program_sha512"],
            "source_revision": TEST_SOURCE_REVISION,
            "unresolved_premises": [],
            "checks": [
                {
                    "name": f"{evidence_id}-structural-test",
                    "command": f"test-only:{evidence_id}",
                    "exit_code": 0,
                    "passed": True,
                    "output_sha512": hashlib.sha512(
                        f"test-only:{evidence_id}".encode("ascii")
                    ).hexdigest(),
                }
            ],
        }
        if evidence_id == "source_derived_composed_security_report":
            result["deployed_security"] = {
                "production_eligible": True,
                "meets_128_bit_deployed_floor": True,
                "deployed_composed_security_bits_floor": 128,
                "global_quantum_query_budget_log2": 64,
                "proof_interactions": 2_097_152,
                "blockers": [],
            }
        if evidence_id == gate.PRODUCTION_CAPABILITY_MANIFEST_EVIDENCE_ID:
            result["capability"] = {
                field: identity[field] for field in gate.CAPABILITY_IDENTITY_FIELDS
            }
        if evidence_id == gate.PRODUCTION_VALUE_BALANCE_EVIDENCE_ID:
            result["projection"] = {
                "transparent_pool_enabled": False,
                "relation_enforces_zero": True,
                "wallet_projection_enforces_zero": True,
                "native_projection_enforces_zero": True,
            }
        if evidence_id == gate.PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID:
            result["proof_lifetime_accounting"] = {
                "scope": "canonical_accepted_smallwood_v8_transaction_proofs",
                "conditional_max_proofs_per_block": 512,
                "conditional_accounting_window_blocks": 4_096,
                "conditional_accounting_window_proofs": 2_097_152,
                "conditional_max_total_proofs_at_128_bits": 621_730_874,
                "persistent_checked_canonical_count": True,
                "count_overflow_rejected": True,
                "lifetime_limit_rejected": True,
                "restart_deterministic": True,
                "sync_replay_deterministic": True,
                "reorg_restores_ancestor_count": True,
                "fresh_replay_exact_rows": True,
                "accounting_window_is_cryptographic_reset": False,
                "counts_all_verifier_invocations": False,
                "conditional_accounting_only": True,
                "deployed_security_claimed": False,
            }
        if evidence_id in gate.FORMAL_SECURITY_RECEIPT_BINDINGS:
            binding = gate.FORMAL_SECURITY_RECEIPT_BINDINGS[evidence_id]
            formal_source_path = str(binding["formal_source_path"])
            formal_source_payload = (root / formal_source_path).read_bytes()
            result["formal_receipt"] = {
                "scope": binding["scope"],
                "formal_source_path": formal_source_path,
                "formal_source_sha512": hashlib.sha512(
                    formal_source_payload
                ).hexdigest(),
                "release_theorem": binding["release_theorem"],
                "release_receipt_constructed": True,
                "all_release_inputs_instantiated": True,
                "concrete_security_bits_floor": 128,
                "source_inventory_sha512": release_source_inventory_sha512,
                "capability_identity_sha512": gate.capability_identity_sha512(
                    identity
                ),
                "retained_proof_primary_sha512": entries_by_id[
                    "retained_proof_primary"
                ]["sha512"],
                "retained_proof_independent_sha512": entries_by_id[
                    "retained_proof_independent"
                ]["sha512"],
            }
        if evidence_id == gate.INDEPENDENT_REVIEW_EVIDENCE_ID:
            review_artifact_payload = write_canonical(
                root / TEST_REVIEW_ARTIFACT_PATH,
                {
                    "schema": gate.INDEPENDENT_REVIEW_ARTIFACT_SCHEMA,
                    "review_id": evidence_id,
                    "reviewer_identity": TEST_REVIEW_TRUST_ROOT[
                        "reviewer_identity"
                    ],
                    "reviewed_source_revision": TEST_SOURCE_REVISION,
                    "reviewed_source_inventory_sha512": (
                        release_source_inventory_sha512
                    ),
                    "reviewed_capability_identity_sha512": (
                        gate.capability_identity_sha512(identity)
                    ),
                    "reviewed_primary_proof_sha512": entries_by_id[
                        "retained_proof_primary"
                    ]["sha512"],
                    "reviewed_independent_proof_sha512": entries_by_id[
                        "retained_proof_independent"
                    ]["sha512"],
                    "security_conclusion": (
                        "independent_review_confirms_release_security_and_implementation"
                    ),
                    "approved_for_production": True,
                    "blockers": [],
                },
            )
            public_key_path = root / TEST_REVIEW_PUBLIC_KEY_PATH
            public_key_path.parent.mkdir(parents=True, exist_ok=True)
            public_key_path.write_bytes(TEST_REVIEW_PUBLIC_KEY_PAYLOAD)
            signature_path = root / TEST_REVIEW_SIGNATURE_PATH
            signature_path.parent.mkdir(parents=True, exist_ok=True)
            signature_path.write_bytes(TEST_REVIEW_SIGNATURE_PAYLOAD)
            result["review_attestation"] = {
                "trust_root_id": TEST_REVIEW_TRUST_ROOT_ID,
                "public_key_path": TEST_REVIEW_PUBLIC_KEY_PATH,
                "public_key_bytes": len(TEST_REVIEW_PUBLIC_KEY_PAYLOAD),
                "public_key_sha512": hashlib.sha512(
                    TEST_REVIEW_PUBLIC_KEY_PAYLOAD
                ).hexdigest(),
                "review_artifact_path": TEST_REVIEW_ARTIFACT_PATH,
                "review_artifact_bytes": len(review_artifact_payload),
                "review_artifact_sha512": hashlib.sha512(
                    review_artifact_payload
                ).hexdigest(),
                "signature_path": TEST_REVIEW_SIGNATURE_PATH,
                "signature_bytes": len(TEST_REVIEW_SIGNATURE_PAYLOAD),
                "signature_sha512": hashlib.sha512(
                    TEST_REVIEW_SIGNATURE_PAYLOAD
                ).hexdigest(),
                "reviewed_source_revision": TEST_SOURCE_REVISION,
                "reviewed_source_inventory_sha512": release_source_inventory_sha512,
                "reviewed_capability_identity_sha512": gate.capability_identity_sha512(
                    identity
                ),
                "reviewed_primary_proof_sha512": entries_by_id[
                    "retained_proof_primary"
                ]["sha512"],
                "reviewed_independent_proof_sha512": entries_by_id[
                    "retained_proof_independent"
                ]["sha512"],
                "verification_command": TEST_RELEASE_EVIDENCE_COMMANDS[evidence_id][
                    0
                ],
            }
        if evidence_id in gate.SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS:
            source_command = TEST_RELEASE_EVIDENCE_COMMANDS[evidence_id][0]
            source_command_output = source_evidence_command_output(
                evidence_id,
                entry["kind"],
                release_source_inventory_sha512,
                entries_by_id["retained_proof_primary"]["sha512"],
                entries_by_id["retained_proof_independent"]["sha512"],
                identity,
                result,
            )
            result["checks"] = [
                {
                    "name": f"{evidence_id}-source-command",
                    "command": source_command,
                    "exit_code": 0,
                    "passed": True,
                    "output_sha512": hashlib.sha512(
                        source_command_output.encode("utf-8")
                    ).hexdigest(),
                }
            ]
        if evidence_id in gate.LIFECYCLE_INTEGRATION_EVIDENCE:
            primary_proof_sha512 = entries_by_id["retained_proof_primary"]["sha512"]
            lifecycle_output_by_stage = {
                stage: lifecycle_command_output(
                    evidence_id,
                    [stage],
                    primary_proof_sha512,
                    entries_by_id["retained_proof_primary"]["bytes"],
                    identity,
                )
                for stage in gate.LIFECYCLE_INTEGRATION_EVIDENCE[evidence_id]
            }
            lifecycle_checks = [
                {
                    "name": f"{evidence_id}-{stage}-actual-subsystem",
                    "command": dict(TEST_LIFECYCLE_COMMANDS[evidence_id])[stage],
                    "exit_code": 0,
                    "passed": True,
                    "output_sha512": hashlib.sha512(
                        lifecycle_output_by_stage[stage].encode("utf-8")
                    ).hexdigest(),
                }
                for stage in gate.LIFECYCLE_INTEGRATION_EVIDENCE[evidence_id]
            ]
            result["checks"].extend(lifecycle_checks)
            result["integration"] = {
                "execution_kind": "actual_subsystem_integration",
                "retained_proof_id": "retained_proof_primary",
                "proof_sha512": primary_proof_sha512,
                "proof_bytes": entries_by_id["retained_proof_primary"]["bytes"],
                "capability": {
                    field: identity[field]
                    for field in gate.CAPABILITY_IDENTITY_FIELDS
                },
                "capability_identity_sha512": gate.capability_identity_sha512(identity),
                "state_binding": test_lifecycle_state_binding(identity),
                "same_proof_bytes_at_every_stage": True,
                "production_verifier_used": True,
                "parser_stage_labels_used_as_authority": False,
                "validity_shortcuts_used": False,
                "release_workflow_sha512": gate.RELEASE_WORKFLOW_SHA512,
                "stage_results": [
                    {
                        "stage": stage,
                        "command": dict(TEST_LIFECYCLE_COMMANDS[evidence_id])[stage],
                        "passed": True,
                        "output_sha512": hashlib.sha512(
                            lifecycle_output_by_stage[stage].encode("utf-8")
                        ).hexdigest(),
                        "proof_sha512": primary_proof_sha512,
                        "proof_bytes": entries_by_id["retained_proof_primary"][
                            "bytes"
                        ],
                        "state_binding": test_lifecycle_state_binding(identity),
                    }
                    for stage in gate.LIFECYCLE_INTEGRATION_EVIDENCE[evidence_id]
                ],
            }
        document["result"] = result
        payload = write_canonical(evidence_path, document)
        entry["bytes"] = len(payload)
        entry["sha512"] = hashlib.sha512(payload).hexdigest()
        identity_pin_field = gate.PINNED_EVIDENCE_DIGEST_FIELDS.get(evidence_id)
        if identity_pin_field is not None:
            identity[identity_pin_field] = entry["sha512"]

    relation_entry = entries_by_id["relation_manifest"]
    relation_program_sha512 = identity["relation_program_sha512"]
    relation_id = relation_program_sha512[: 48 * 2]
    relation_payload = write_canonical(
        root / relation_entry["path"],
        {
            "compiled_relation": {
                "program_sha512": relation_program_sha512,
                "relation_id": relation_id,
            },
            "profile_id": TEST_PROFILE_ID,
            "schema": "hegemon.smallwood.poseidon2-relation-manifest.v1",
            "semantic_target": {
                "binding_limbs": 7,
                "field": "goldilocks",
                "id": "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2",
                "statement_words": 120,
            },
        },
    )
    relation_manifest_sha512 = hashlib.sha512(relation_payload).hexdigest()
    relation_entry.update(
        {
            "bytes": len(relation_payload),
            "sha512": relation_manifest_sha512,
        }
    )
    identity["relation_manifest_sha512"] = relation_manifest_sha512

    profile_entry = entries_by_id["profile_manifest"]
    profile_payload = write_canonical(
        root / profile_entry["path"],
        {
            "consensus_identity": {
                "action_id": identity["action_id"],
                "backend_wire_id": identity["backend_wire_id"],
                "circuit_version": identity["circuit_version"],
                "crypto_suite": identity["crypto_suite"],
                "domain_set": identity["domain_set"],
                "family_id": identity["family_id"],
                "profile_wire_id": identity["profile_wire_id"],
                "proof_mode": identity["proof_mode"],
            },
            "profile_id": TEST_PROFILE_ID,
            "diagnostic_source_security_report": {
                "bytes": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_BYTES,
                "path": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH,
                "production_authorizing": False,
                "schema": gate.SOURCE_SECURITY_REPORT_SCHEMA,
                "sha512": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512,
            },
            "executable_zk_refinement_report": {
                "bytes": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES,
                "direct_256_bit_first_program_route_used": False,
                "exact_lazy_program_keys_exclude_salt_only_point": True,
                "path": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_PATH,
                "production_eligible": False,
                "salt_only_oracle_program_count": 0,
                "schema": gate.EXECUTABLE_ZK_REFINEMENT_SCHEMA,
                "sha512": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512,
            },
            "relation_manifest": {
                "path": relation_entry["path"],
                "relation_id": relation_id,
                "sha512": relation_manifest_sha512,
            },
            "required_release_receipts": {
                "executable_zk_refinement_report_sha512": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512,
                "relation_manifest_sha512": relation_manifest_sha512,
                "source_derived_composed_security_report_sha512": None,
            },
            "schema": "hegemon.smallwood.poseidon2-profile-manifest.v1",
            "size_posture": {
                "maximum_inline_route_args_cap_bytes": identity[
                    "max_inline_route_args_bytes"
                ],
                "maximum_outer_envelope_cap_bytes": identity[
                    "max_outer_envelope_bytes"
                ],
                "maximum_v8_pending_action_cap_bytes": identity[
                    "max_v8_pending_action_bytes"
                ],
                "projected_inner_proof_bytes": identity["max_proof_bytes"],
                "projected_two_output_inline_route_args_bytes": 128_297,
                "projected_two_output_outer_envelope_bytes": 128_293,
                "projected_two_output_pending_action_bytes": 128_522,
            },
            "transport_identity": {
                "inner_proof_magic_ascii": bytes.fromhex(
                    identity["inner_proof_wire_magic_hex"]
                ).decode("ascii"),
                "inner_proof_version": identity["inner_proof_wire_version"],
                "native_leaf_magic_ascii": bytes.fromhex(
                    identity["native_leaf_magic_hex"]
                ).decode("ascii"),
                "native_leaf_version": identity["native_leaf_version"],
                "outer_grammar": identity["envelope_version"],
                "outer_magic_ascii": bytes.fromhex(
                    identity["envelope_magic_hex"]
                ).decode("ascii"),
            },
        },
    )
    profile_manifest_sha512 = hashlib.sha512(profile_payload).hexdigest()
    profile_entry.update(
        {
            "bytes": len(profile_payload),
            "sha512": profile_manifest_sha512,
        }
    )
    identity["profile_manifest_sha512"] = profile_manifest_sha512

    relation_program_bytes = (
        root / entries_by_id["relation_program"]["path"]
    ).read_bytes()
    proof_source_inventory = gate.recompute_retained_proof_source_inventory(root)
    generator_binary_payload = b"test-only-distinct-generator-binary"
    generator_binary_sha512 = hashlib.sha512(generator_binary_payload).hexdigest()
    if generator_binary_sha512 == hashlib.sha512(
        STRICT_ARTIFACT_BINARY_PAYLOAD
    ).hexdigest():
        raise SystemExit("cross-binary provenance fixture collapsed to one binary")
    for artifact_index, artifact_role in enumerate(gate.RETAINED_PROOF_IDS, start=1):
        proof_entry = entries_by_id[artifact_role]
        artifact_directory = (root / proof_entry["path"]).parent
        proof = (artifact_directory / "proof.bin").read_bytes()
        artifact_files = {
            "public-statement.bin": bytes(120 * 8),
            "ciphertexts.bin": bytes(2 * 2147),
            "network-id.bin": int(identity["network_id"]).to_bytes(4, "little"),
            "relation-digest.bin": bytes.fromhex(relation_id),
            "relation-binding.bin": bytes(7 * 8),
            "relation-program.bin": relation_program_bytes,
            "transcript-preamble.bin": b"HGV8PB02" + bytes(1096),
            "native-leaf.bin": b"HGV8TX02" + bytes(5390) + proof,
            "rpc-envelope.bin": b"SWP8LC02" + bytes(24)
            + b"HGV8TX02" + bytes(5390) + proof,
            "scale-inline-args.bin": bytes(4) + b"SWP8LC02" + bytes(24)
            + b"HGV8TX02" + bytes(5390) + proof,
        }
        artifact_files["pending-action.bin"] = (
            bytes(217) + artifact_files["scale-inline-args.bin"] + bytes(8)
        )
        for name, payload in artifact_files.items():
            (artifact_directory / name).write_bytes(payload)
        inline_args_bytes = len(artifact_files["scale-inline-args.bin"])
        pending_action_bytes = len(artifact_files["pending-action.bin"])
        honest_map = deepcopy(gate.RETAINED_HONEST_MAP_AUDIT)
        honest_map.update(gate.RETAINED_ACCEPTED_PROOF_REFINEMENT)
        honest_map.update(
            {
                "proof_bytes": len(proof),
                "proof_sha512": hashlib.sha512(proof).hexdigest(),
            }
        )
        opening_surface = {
            field: (
                True
                if field == "subset_eval_shape_matches_beta_packing_identity"
                else 1
            )
            for field in gate.RETAINED_OPENING_SURFACE_FIELDS
        }
        opening_surface["total_inner_proof_bytes"] = len(proof)
        report = {
            "artifact_role": artifact_role,
            "generation_provenance": {
                "schema": gate.RETAINED_GENERATION_PROVENANCE_SCHEMA,
                "independence_scope": gate.RETAINED_GENERATION_METADATA_SCOPE,
                "artifact_role": artifact_role,
                "source_revision": TEST_SOURCE_REVISION,
                "generator_source_path": gate.RETAINED_GENERATOR_SOURCE_PATH,
                "generator_source_sha512": hashlib.sha512(
                    generator_source
                ).hexdigest(),
                "generator_binary_bytes": len(generator_binary_payload),
                "generator_binary_sha512": generator_binary_sha512,
                "run_id_hex": f"{artifact_index:02x}" * 32,
                "process_id": 100 + artifact_index,
                "started_unix_seconds": 1,
                "proof_sha512": hashlib.sha512(proof).hexdigest(),
            },
            "proof_source_inventory": deepcopy(proof_source_inventory),
            "provenance_transition": {
                "schema": gate.RETAINED_PROVENANCE_TRANSITION_SCHEMA,
                "kind": "direct_generation",
                "source_inventory_scope": "generation_start_and_prepublication",
                "source_inventory_root_sha512": proof_source_inventory[
                    "root_sha512"
                ],
                "parent_artifact_report_path": None,
                "parent_artifact_report_bytes": 0,
                "parent_artifact_report_sha512": None,
                "v4_verifier_binary_bytes": 0,
                "v4_verifier_binary_sha512": None,
                "v4_verifier_output_sha512": None,
                "proof_bytes_preserved_from_parent": False,
                "pending_action_bytes_preserved_from_parent": False,
                "generation_independence_established": False,
                "claim": "two_distinct_source_verified_proofs",
            },
            "proof_randomness_binding": {
                "wire_salt_hex": proof[4:36].hex(),
                "decs_transcript_root_hex": hashlib.sha512(
                    b"test-only-decs-root" + proof
                ).hexdigest(),
            },
            "bytes": {
                "measured_inner_proof": len(proof),
                "projected_max_inner_proof": 122_863,
                "relation_program": len(relation_program_bytes),
                "native_leaf": len(artifact_files["native-leaf.bin"]),
                "measured_rpc_envelope": len(artifact_files["rpc-envelope.bin"]),
                "projected_max_rpc_envelope": 128_293,
                "measured_scale_inline_args": inline_args_bytes,
                "projected_max_scale_inline_args": 128_297,
                "measured_pending_action": pending_action_bytes,
                "projected_max_pending_action": 128_522,
                "fixed_pending_action_overhead": 225,
                "max_inline_route_args_bytes": 131_072,
                "max_outer_envelope_bytes": 131_068,
                "max_v8_pending_action_bytes": 131_297,
                "fixed_action": 1_140,
                "inline_ciphertexts": len(artifact_files["ciphertexts.bin"]),
            },
            "fixture": {
                "activity_mask": 15,
                "authorization_mode": "SingleKey",
                "active_inputs": 2,
                "active_outputs": 2,
                "ciphertext_bytes_per_output": 2147,
                "inline_ciphertext_bytes": 4294,
                "fee": 1,
            },
            "geometry": deepcopy(gate.RETAINED_ARTIFACT_GEOMETRY),
            "identity": {
                "inner_magic": "SMZ9",
                "network_id": identity["network_id"],
                "relation_digest_hex": relation_id,
                "relation_program": {
                    "magic": gate.RETAINED_RELATION_PROGRAM_MAGIC,
                    "bytes": gate.RETAINED_RELATION_PROGRAM_BYTES,
                    "sha512": identity["relation_program_sha512"],
                },
                "semantic_relation": gate.RETAINED_SEMANTIC_RELATION,
                "transport": {
                    "native_leaf_magic": "HGV8TX02",
                    "rpc_envelope_magic": "SWP8LC02",
                },
                "consensus_tuple": {
                    "circuit_version": identity["circuit_version"],
                    "crypto_suite": identity["crypto_suite"],
                    "family_id": identity["family_id"],
                    "action_id": identity["action_id"],
                    "backend_id": identity["backend_wire_id"],
                    "profile_id": identity["profile_wire_id"],
                    "domain_set": identity["domain_set"],
                },
                "profile": deepcopy(gate.RETAINED_ARTIFACT_PROFILE),
            },
            "opening_surface": opening_surface,
            "retains_private_witness": False,
            "schema": gate.RETAINED_ARTIFACT_SCHEMA,
            "sha512": {
                "proof": hashlib.sha512(proof).hexdigest(),
                "public_statement": hashlib.sha512(
                    artifact_files["public-statement.bin"]
                ).hexdigest(),
                "ciphertexts": hashlib.sha512(
                    artifact_files["ciphertexts.bin"]
                ).hexdigest(),
                "relation_binding": hashlib.sha512(
                    artifact_files["relation-binding.bin"]
                ).hexdigest(),
                "relation_program": hashlib.sha512(
                    relation_program_bytes
                ).hexdigest(),
                "transcript_preamble": hashlib.sha512(
                    artifact_files["transcript-preamble.bin"]
                ).hexdigest(),
                "native_leaf": hashlib.sha512(
                    artifact_files["native-leaf.bin"]
                ).hexdigest(),
                "rpc_envelope": hashlib.sha512(
                    artifact_files["rpc-envelope.bin"]
                ).hexdigest(),
                "scale_inline_action": hashlib.sha512(
                    artifact_files["scale-inline-args.bin"]
                ).hexdigest(),
                "pending_action": hashlib.sha512(
                    artifact_files["pending-action.bin"]
                ).hexdigest(),
            },
            "successor_evidence": {
                "proof": {
                    "bytes": len(proof),
                    "id": artifact_role,
                    "kind": "proof",
                    "path": "proof.bin",
                    "sha512": hashlib.sha512(proof).hexdigest(),
                },
                "relation_program": {
                    "bytes": len(relation_program_bytes),
                    "id": "relation_program",
                    "kind": "program",
                    "path": "relation-program.bin",
                    "sha512": hashlib.sha512(relation_program_bytes).hexdigest(),
                },
            },
            "timing_milliseconds": {
                "projection_and_relation_mutations": 1,
                "prove_and_internal_verify": 1,
                "independent_source_factory_verify": 1,
                "honest_map_audit": 1,
            },
            "verification": {
                "source_factory_immediate": True,
                "readback_before_publish": True,
                "same_smz9_bytes_at_every_layer": True,
                "node_pending_action_lifecycle": {
                    field: True
                    for field in gate.RETAINED_NODE_PENDING_ACTION_LIFECYCLE_FIELDS
                },
                "honest_map_audit": honest_map,
                "transport_parser_stage_checks": [
                    {"stage": stage, "exact_bytes": True}
                    for stage in gate.RETAINED_TRANSPORT_PARSER_STAGES
                ],
                "relation_mutations": [
                    {"name": name, "rejected": True}
                    for name in gate.RETAINED_RELATION_MUTATIONS
                ],
                "proof_and_input_mutations": [
                    {"name": name, "rejected": True, "error": "rejected"}
                    for name in gate.RETAINED_PROOF_MUTATIONS
                ],
                "transport_mutations": [
                    {"name": name, "rejected": True}
                    for name in gate.RETAINED_TRANSPORT_MUTATIONS
                ],
                "pending_action_mutations": [
                    {"name": name, "rejected": True}
                    for name in gate.RETAINED_PENDING_ACTION_MUTATIONS
                ],
                "ciphertext_mutation": {
                    "name": "ciphertext_byte",
                    "rejected": True,
                },
            },
            "generated_unix_seconds": 1,
        }
        report_payload = write_canonical(
            artifact_directory / "artifact-report.json", report
        )
        proof_entry["artifact_report_bytes"] = len(report_payload)
        proof_entry["artifact_report_sha512"] = hashlib.sha512(
            report_payload
        ).hexdigest()

    bundle = {
        "schema": gate.EVIDENCE_BUNDLE_SCHEMA,
        "profile_id": TEST_PROFILE_ID,
        "identity": deepcopy(identity),
        "source_revision": TEST_SOURCE_REVISION,
        "source_inventory_sha512": release_source_inventory_sha512,
        "evidence_files": entries,
    }
    bundle_payload = write_canonical(root / TEST_BUNDLE_PATH, bundle)
    profile = gate.AuthorizedProfile(
        profile_id=TEST_PROFILE_ID,
        identity=deepcopy(identity),
        evidence_bundle_path=TEST_BUNDLE_PATH,
        evidence_bundle_sha512=hashlib.sha512(bundle_payload).hexdigest(),
        max_proof_bytes=identity["max_proof_bytes"],
    )
    selection = {
        "schema": gate.SELECTION_SCHEMA,
        "selection": "selected",
        "profile_id": TEST_PROFILE_ID,
        "identity": deepcopy(identity),
        "evidence_bundle_path": TEST_BUNDLE_PATH,
        "claim_boundary": "test-only source-owned registry fixture",
    }
    return selection, bundle, profile


def registry_record(profile: gate.AuthorizedProfile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id,
        "identity": deepcopy(dict(profile.identity)),
        "evidence_bundle_path": profile.evidence_bundle_path,
        "evidence_bundle_sha512": profile.evidence_bundle_sha512,
        "max_proof_bytes": profile.max_proof_bytes,
    }


def repin_bundle(
    root: Path, bundle: dict[str, object], profile: gate.AuthorizedProfile
) -> gate.AuthorizedProfile:
    payload = write_canonical(root / TEST_BUNDLE_PATH, bundle)
    return replace(profile, evidence_bundle_sha512=hashlib.sha512(payload).hexdigest())


def expect_rejected(name: str, expected: str, operation) -> None:
    try:
        operation()
    except gate.SuccessorAuthorizationError as exc:
        if expected not in str(exc):
            raise SystemExit(f"{name}: wrong rejection: {exc}") from exc
        return
    raise SystemExit(f"{name}: unauthorized fixture unexpectedly passed")


STRICT_ARTIFACT_COMMANDS: list[tuple[tuple[str, ...], Path]] = []
STRICT_ARTIFACT_BINARY: Path | None = None
STRICT_SECURITY_BINARY: Path | None = None


def strict_artifact_command_runner(
    command: list[str], root: Path
) -> tuple[int, str]:
    """Exercise the exact production command seam without bypassing validation."""

    global STRICT_ARTIFACT_BINARY, STRICT_SECURITY_BINARY
    if len(command) == 1 and command[0].startswith("test-only-evidence:"):
        evidence_id = command[0].split(":", 1)[1]
        bundle = json.loads((root / TEST_BUNDLE_PATH).read_text(encoding="utf-8"))
        entries_by_id = {
            entry["id"]: entry for entry in bundle["evidence_files"]
        }
        evidence_document = json.loads(
            (root / entries_by_id[evidence_id]["path"]).read_text(encoding="utf-8")
        )
        output = source_evidence_command_output(
            evidence_id,
            gate.REQUIRED_EVIDENCE_KINDS[evidence_id],
            bundle["source_inventory_sha512"],
            entries_by_id["retained_proof_primary"]["sha512"],
            entries_by_id["retained_proof_independent"]["sha512"],
            bundle["identity"],
            evidence_document["result"],
        )
        STRICT_ARTIFACT_COMMANDS.append((tuple(command), root))
        return 0, output
    if len(command) == 1 and command[0].startswith("test-only:"):
        _, evidence_id, stage = command[0].split(":", 2)
        bundle = json.loads((root / TEST_BUNDLE_PATH).read_text(encoding="utf-8"))
        primary_entry = next(
            entry
            for entry in bundle["evidence_files"]
            if entry["id"] == "retained_proof_primary"
        )
        output = lifecycle_command_output(
            evidence_id,
            [stage],
            primary_entry["sha512"],
            primary_entry["bytes"],
            bundle["identity"],
        )
        STRICT_ARTIFACT_COMMANDS.append((tuple(command), root))
        return 0, output
    expected_build_prefix = [
        "cargo",
        "build",
        "--locked",
        "--quiet",
        "-p",
        "transaction-circuit",
        "--profile",
        gate.RETAINED_BUILD_PROFILE,
        "--example",
        gate.RETAINED_ARTIFACT_EXAMPLE,
        "--example",
        gate.SOURCE_SECURITY_REPORT_EXAMPLE,
    ]
    if (
        len(command) == len(expected_build_prefix) + 2
        and command[: len(expected_build_prefix)] == expected_build_prefix
        and command[-2] == "--target-dir"
    ):
        target_directory = Path(command[-1])
        STRICT_ARTIFACT_BINARY = (
            target_directory
            / gate.RETAINED_BUILD_PROFILE
            / "examples"
            / gate.RETAINED_ARTIFACT_EXAMPLE
        )
        STRICT_ARTIFACT_BINARY.parent.mkdir(parents=True, exist_ok=True)
        STRICT_ARTIFACT_BINARY.write_bytes(STRICT_ARTIFACT_BINARY_PAYLOAD)
        STRICT_ARTIFACT_BINARY.chmod(0o700)
        STRICT_SECURITY_BINARY = (
            target_directory
            / gate.RETAINED_BUILD_PROFILE
            / "examples"
            / gate.SOURCE_SECURITY_REPORT_EXAMPLE
        )
        STRICT_SECURITY_BINARY.write_bytes(b"test-only deployed-security verifier")
        STRICT_SECURITY_BINARY.chmod(0o700)
        STRICT_ARTIFACT_COMMANDS.append((tuple(command), root))
        return 0, ""
    expected_security_binary = (
        str(STRICT_SECURITY_BINARY) if STRICT_SECURITY_BINARY else ""
    )
    if command == [expected_security_binary, "--require-deployed"]:
        bundle = json.loads((root / TEST_BUNDLE_PATH).read_text(encoding="utf-8"))
        report_entry = next(
            entry
            for entry in bundle["evidence_files"]
            if entry["id"] == "source_derived_composed_security_report"
        )
        output = (root / report_entry["path"]).read_text(encoding="utf-8")
        STRICT_ARTIFACT_COMMANDS.append((tuple(command), root))
        return 0, output
    expected_binary = str(STRICT_ARTIFACT_BINARY) if STRICT_ARTIFACT_BINARY else ""
    if len(command) != 3 or command[:2] != [expected_binary, "verify"]:
        raise gate.SuccessorAuthorizationError(
            f"test command contract drifted: {command!r}"
        )
    artifact_directory = Path(command[-1])
    report = json.loads(
        (artifact_directory / "artifact-report.json").read_text(encoding="utf-8")
    )
    role = report.get("artifact_role")
    if role not in gate.RETAINED_PROOF_IDS or artifact_directory.name != role:
        raise gate.SuccessorAuthorizationError("test command snapshot role drifted")
    identity = report["identity"]
    verification = report["verification"]
    proof = (artifact_directory / "proof.bin").read_bytes()
    rpc_envelope = (artifact_directory / "rpc-envelope.bin").read_bytes()
    inline_args = (artifact_directory / "scale-inline-args.bin").read_bytes()
    pending_action = (artifact_directory / "pending-action.bin").read_bytes()
    result = {
        "artifact": str(artifact_directory),
        "proof_bytes": len(proof),
        "rpc_envelope_bytes": len(rpc_envelope),
        "scale_inline_args_bytes": len(inline_args),
        "pending_action_bytes": len(pending_action),
        "proof_sha512": hashlib.sha512(proof).hexdigest(),
        "pending_action_sha512": hashlib.sha512(pending_action).hexdigest(),
        "relation_id": (artifact_directory / "relation-digest.bin").read_bytes().hex(),
        "relation_program_sha512": hashlib.sha512(
            (artifact_directory / "relation-program.bin").read_bytes()
        ).hexdigest(),
        "semantic_relation": identity["semantic_relation"],
        "native_leaf_magic": identity["transport"]["native_leaf_magic"],
        "rpc_envelope_magic": identity["transport"]["rpc_envelope_magic"],
        "consensus_tuple": identity["consensus_tuple"],
        "generation_provenance": report["generation_provenance"],
        "verifier_provenance": {
            "schema": gate.RETAINED_VERIFIER_PROVENANCE_SCHEMA,
            "binary_bytes": len(STRICT_ARTIFACT_BINARY_PAYLOAD),
            "binary_sha512": hashlib.sha512(
                STRICT_ARTIFACT_BINARY_PAYLOAD
            ).hexdigest(),
            "target_os": "test-os",
            "target_arch": "test-arch",
            "rustc_verbose_sha512": hashlib.sha512(b"test-rustc").hexdigest(),
            "source_inventory_root_sha512": report["proof_source_inventory"][
                "root_sha512"
            ],
            "generator_binary_equality_required": False,
        },
        "proof_randomness_binding": report["proof_randomness_binding"],
        "source_factory_verified": True,
        "canonical_transport_verified": True,
        "canonical_pending_action_verified": True,
        "hash_manifest_verified": True,
        "honest_map_audit": verification["honest_map_audit"],
        "node_pending_action_lifecycle": verification[
            "node_pending_action_lifecycle"
        ],
        "proof_and_input_mutations": verification["proof_and_input_mutations"],
        "transport_mutations": verification["transport_mutations"],
        "pending_action_mutations": verification["pending_action_mutations"],
        "ciphertext_mutation_rejected": True,
    }
    STRICT_ARTIFACT_COMMANDS.append((tuple(command), root))
    return 0, json.dumps(result)


def check(
    selection: object,
    root: Path,
    profile: gate.AuthorizedProfile,
    *,
    registry: dict[str, gate.AuthorizedProfile] | None = None,
) -> str | None:
    selected_registry = (
        {TEST_PROFILE_ID: profile} if registry is None else registry
    )
    return gate.check_selection_document(
        selection,
        root,
        require_authorized=True,
        registry=selected_registry,
        artifact_command_runner=strict_artifact_command_runner,
    )


def main() -> None:
    active_max_views = 1_537_228_672_809_129_301
    if gate.total_oracle_exposure_log2_ceiling(64, 1) != 65:
        raise SystemExit("small-T total oracle-exposure ceiling drift")
    maximum_ratio = gate.ghhm_adaptive_programming_ratio(
        entropy_bits=512,
        query_log2=64,
        proof_views=active_max_views,
        programming_events=(1 << 24) * active_max_views,
    )
    successor_ratio = gate.ghhm_adaptive_programming_ratio(
        entropy_bits=512,
        query_log2=64,
        proof_views=active_max_views + 1,
        programming_events=(1 << 24) * (active_max_views + 1),
    )
    if not (
        maximum_ratio[0] * (1 << 128) < maximum_ratio[1]
        and successor_ratio[0] * (1 << 128) >= successor_ratio[1]
        and gate.total_oracle_exposure_log2_ceiling(64, (1 << 64) - 1) == 89
    ):
        raise SystemExit("observed-proof-view strict-128 ceiling regression")

    required_v8_evidence = {
        "relation_program_transcript_spec": "certificate",
        "relation_program_digest_conformance_report": "report",
        "executable_csr_program_refinement_receipt": "receipt",
        "executable_nonlinear_program_refinement_receipt": "receipt",
        "relation_source_supply_chain_manifest": "manifest",
        "piop_correction_aware_sampling_refinement_receipt": "receipt",
        "adaptive_qrom_whole_view_zk_receipt": "receipt",
        "production_capability_manifest": "manifest",
        "production_value_balance_zero_projection_receipt": "receipt",
        "source_derived_composed_security_report": "report",
    }
    if gate.RETAINED_TRANSPORT_MUTATIONS != (
        "native_leaf_magic",
        "native_leaf_proof_length",
        "rpc_envelope_magic",
        "scale_compact_length",
        "scale_inline_trailing_byte",
        "native_leaf_statement_rewrap",
        "native_leaf_relation_binding_rewrap",
    ):
        raise SystemExit("retained SMZ9 transport mutation inventory drifted")
    for evidence_id, kind in required_v8_evidence.items():
        if gate.REQUIRED_EVIDENCE_KINDS.get(evidence_id) != kind:
            raise SystemExit(f"{evidence_id} is not release-required as {kind}")
    complete_capability_identity = test_identity()
    capability_digest = gate.capability_identity_sha512(complete_capability_identity)
    for field, replacement in (
        (
            "deactivation_height_exclusive",
            complete_capability_identity["deactivation_height_exclusive"] + 1,
        ),
        ("activation_genesis_hash", "34" * 32),
        ("coinbase_action_id", 12),
        ("max_proof_actions_per_block", 513),
        ("claimed_security_bits", 129),
    ):
        mutated_capability_identity = deepcopy(complete_capability_identity)
        mutated_capability_identity[field] = replacement
        if (
            gate.capability_identity_sha512(mutated_capability_identity)
            == capability_digest
        ):
            raise SystemExit(
                f"capability identity digest omitted security-critical field {field}"
            )
    real_source_inventory = gate.recompute_retained_proof_source_inventory(ROOT)
    retired_v1_root = gate.proof_source_inventory_root_sha512(
        real_source_inventory["entries"], gate.RETIRED_SOURCE_INVENTORY_V1_DOMAIN
    )
    if retired_v1_root == real_source_inventory["root_sha512"]:
        raise SystemExit("release source inventory v2 reused the retired v1 hash domain")
    if "third_party/reed-solomon-erasure/Cargo.toml" not in set(
        real_source_inventory["package_manifests"]
    ):
        raise SystemExit("active workspace-excluded reed-solomon source is not inventoried")
    if "walletd/Cargo.toml" not in set(real_source_inventory["package_manifests"]):
        raise SystemExit("shipped walletd transaction submission source is not inventoried")
    inactive_optional_dependencies = real_source_inventory[
        "inactive_optional_local_dependencies"
    ]
    if not any(
        dependency["dependency_path"]
        == "circuits/standalone-full-shake256-relation-prototype"
        and dependency["reason"]
        == "inactive_in_source_owned_default_feature_graph"
        for dependency in inactive_optional_dependencies
    ):
        raise SystemExit("inactive optional SHAKE replacement is not explicitly excluded")
    if "circuits/standalone-full-shake256-relation-prototype/Cargo.toml" in set(
        real_source_inventory["package_manifests"]
    ):
        raise SystemExit("inactive optional SHAKE replacement entered production closure")
    inventoried_paths = {
        entry["path"] for entry in real_source_inventory["entries"]
    }
    for required_path in gate.RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_FILES:
        if required_path not in inventoried_paths:
            raise SystemExit(f"required release root file is not inventoried: {required_path}")
    for required_path in (
        "formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean",
        "formal/crypto/lakefile.toml",
        "formal/crypto/lean-toolchain",
        "formal/lean/lakefile.lean",
        "formal/lean/lean-toolchain",
    ):
        if required_path not in inventoried_paths:
            raise SystemExit(f"required formal source tree file is not inventoried: {required_path}")
    if any("/.lake/" in path for path in inventoried_paths):
        raise SystemExit("Lean build output entered the release source inventory")
    with tempfile.TemporaryDirectory() as executable_directory:
        executable_root = Path(executable_directory)
        executable_path = executable_root / "descriptor-bound-test"
        executable_payload = b"#!/bin/sh\nprintf immutable-copy-ok\n"
        executable_path.write_bytes(executable_payload)
        executable_path.chmod(0o700)
        executable_sha512 = hashlib.sha512(executable_payload).hexdigest()
        original_platform = gate.sys.platform
        original_subprocess_run = gate.subprocess.run
        nonlinux_runner_called = False
        malicious_marker = executable_root / "malicious-verifier-executed"

        def forbidden_nonlinux_runner(*args, **kwargs):
            nonlocal nonlinux_runner_called
            nonlinux_runner_called = True
            malicious_marker.touch()
            raise SystemExit("non-Linux release verifier was invoked")

        gate.sys.platform = "darwin"
        gate.subprocess.run = forbidden_nonlinux_runner
        try:
            expect_rejected(
                "non-Linux external verifier execution",
                "execution requires Linux sealed memfd authority",
                lambda: gate.run_descriptor_bound_executable(
                    [str(executable_path)],
                    executable_root,
                    executable_path,
                    len(executable_payload),
                    executable_sha512,
                    "test verifier",
                ),
            )
            if nonlinux_runner_called or malicious_marker.exists():
                raise SystemExit(
                    "non-Linux release authorization invoked an external verifier"
                )
        finally:
            gate.subprocess.run = original_subprocess_run
            gate.sys.platform = original_platform

        missing_attribute = object()
        os_attribute_names = (
            "memfd_create",
            "MFD_ALLOW_SEALING",
            "MFD_CLOEXEC",
        )
        fcntl_attribute_names = (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        )
        saved_os_attributes = {
            name: getattr(gate.os, name, missing_attribute)
            for name in os_attribute_names
        }
        saved_fcntl_attributes = {
            name: getattr(gate.fcntl, name, missing_attribute)
            for name in fcntl_attribute_names
        }
        original_fcntl_call = gate.fcntl.fcntl
        original_proc_available = gate.linux_proc_fd_available
        original_proc_identity = gate.linux_proc_descriptor_identity
        fake_seals: dict[int, int] = {}
        fake_runner_calls = 0
        report_incomplete_seals = False
        fake_memfd_path = executable_root / "fake-linux-sealed-memfd"
        fake_f_add_seals = 10_033
        fake_f_get_seals = 10_034
        fake_seal_write = 0x08
        fake_seal_grow = 0x04
        fake_seal_shrink = 0x02
        fake_seal_seal = 0x01
        fake_required_seals = (
            fake_seal_write
            | fake_seal_grow
            | fake_seal_shrink
            | fake_seal_seal
        )

        def fake_memfd_create(name: str, flags: int) -> int:
            if name != "hegemon-release-verifier" or flags != 0x03:
                raise SystemExit("Linux fixture received the wrong memfd identity")
            descriptor = os.open(
                fake_memfd_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            fake_memfd_path.unlink()
            fake_seals[descriptor] = 0
            return descriptor

        def fake_fcntl_call(descriptor: int, operation: int, argument: int = 0):
            if operation == fake_f_add_seals:
                fake_seals[descriptor] = argument
                return 0
            if operation == fake_f_get_seals:
                observed = fake_seals.get(descriptor, 0)
                if report_incomplete_seals:
                    observed &= ~fake_seal_write
                return observed
            return original_fcntl_call(descriptor, operation, argument)

        def fake_proc_identity(
            descriptor: int,
        ) -> tuple[int, int, int, int, int, int, int, int]:
            return gate._owned_file_identity(os.fstat(descriptor))

        def fake_linux_runner(command, *args, **kwargs):
            nonlocal fake_runner_calls
            fake_runner_calls += 1
            pass_fds = kwargs.get("pass_fds")
            if not isinstance(pass_fds, tuple) or len(pass_fds) != 1:
                raise SystemExit("Linux fixture did not inherit exactly one memfd")
            descriptor = pass_fds[0]
            if command[0] != f"/proc/self/fd/{descriptor}":
                raise SystemExit("Linux fixture did not execute the sealed proc fd")
            if kwargs.get("executable") != command[0]:
                raise SystemExit("Linux fixture executable bypassed the sealed proc fd")
            if fake_seals.get(descriptor) != fake_required_seals:
                raise SystemExit("Linux fixture executed before applying every seal")
            executed_payload = os.pread(
                descriptor, gate.MAX_VERIFIER_BINARY_BYTES, 0
            )
            if executed_payload != executable_payload:
                malicious_marker.touch()
                output = "MALICIOUS"
            else:
                output = "immutable-copy-ok"
            return subprocess.CompletedProcess(command, 0, output)

        for name, value in (
            ("MFD_ALLOW_SEALING", 0x02),
            ("MFD_CLOEXEC", 0x01),
        ):
            setattr(gate.os, name, value)
        gate.os.memfd_create = fake_memfd_create
        for name, value in (
            ("F_ADD_SEALS", fake_f_add_seals),
            ("F_GET_SEALS", fake_f_get_seals),
            ("F_SEAL_WRITE", fake_seal_write),
            ("F_SEAL_GROW", fake_seal_grow),
            ("F_SEAL_SHRINK", fake_seal_shrink),
            ("F_SEAL_SEAL", fake_seal_seal),
        ):
            setattr(gate.fcntl, name, value)
        gate.fcntl.fcntl = fake_fcntl_call
        gate.linux_proc_fd_available = lambda: True
        gate.linux_proc_descriptor_identity = fake_proc_identity
        gate.sys.platform = "linux"
        gate.subprocess.run = fake_linux_runner
        try:
            status, output = gate.run_descriptor_bound_executable(
                [str(executable_path)],
                executable_root,
                executable_path,
                len(executable_payload),
                executable_sha512,
                "test verifier",
            )
            if status != 0 or output != "immutable-copy-ok":
                raise SystemExit("mocked Linux sealed verifier ran different bytes")
            calls_before_incomplete_seals = fake_runner_calls
            report_incomplete_seals = True
            expect_rejected(
                "Linux incomplete memfd seals",
                "does not carry the exact required seals",
                lambda: gate.run_descriptor_bound_executable(
                    [str(executable_path)],
                    executable_root,
                    executable_path,
                    len(executable_payload),
                    executable_sha512,
                    "test verifier",
                ),
            )
            report_incomplete_seals = False
            if fake_runner_calls != calls_before_incomplete_seals:
                raise SystemExit("Linux fixture executed a verifier with missing seals")

            saved_executable = executable_root / "mock-linux-source-saved"
            sealed_swap_outputs: list[str] = []

            def fake_linux_path_swap_runner(command, *args, **kwargs):
                executable_path.rename(saved_executable)
                executable_path.write_text(
                    "#!/bin/sh\n"
                    "printf MALICIOUS\n"
                    f'touch "{malicious_marker}"\n',
                    encoding="utf-8",
                )
                executable_path.chmod(0o700)
                try:
                    completed = fake_linux_runner(command, *args, **kwargs)
                    sealed_swap_outputs.append(completed.stdout)
                    return completed
                finally:
                    executable_path.unlink()
                    saved_executable.rename(executable_path)

            gate.subprocess.run = fake_linux_path_swap_runner
            try:
                try:
                    status, output = gate.run_descriptor_bound_executable(
                        [str(executable_path)],
                        executable_root,
                        executable_path,
                        len(executable_payload),
                        executable_sha512,
                        "test verifier",
                    )
                    if status != 0 or output != "immutable-copy-ok":
                        raise SystemExit(
                            "mocked Linux source swap changed verifier output"
                        )
                except gate.SuccessorAuthorizationError as exc:
                    if "opened inode changed during execution" not in str(exc):
                        raise
                if sealed_swap_outputs != ["immutable-copy-ok"]:
                    raise SystemExit("mocked Linux source swap selected replacement bytes")
                if malicious_marker.exists():
                    raise SystemExit(
                        "mocked Linux source swap produced a malicious side effect"
                    )
            finally:
                gate.subprocess.run = fake_linux_runner
        finally:
            gate.subprocess.run = original_subprocess_run
            gate.sys.platform = original_platform
            gate.linux_proc_descriptor_identity = original_proc_identity
            gate.linux_proc_fd_available = original_proc_available
            gate.fcntl.fcntl = original_fcntl_call
            for name, saved in saved_fcntl_attributes.items():
                if saved is missing_attribute:
                    delattr(gate.fcntl, name)
                else:
                    setattr(gate.fcntl, name, saved)
            for name, saved in saved_os_attributes.items():
                if saved is missing_attribute:
                    delattr(gate.os, name)
                else:
                    setattr(gate.os, name, saved)

        if sys.platform.startswith("linux"):
            status, output = gate.run_descriptor_bound_executable(
                [str(executable_path)],
                executable_root,
                executable_path,
                len(executable_payload),
                executable_sha512,
                "test verifier",
            )
            if status != 0 or output != "immutable-copy-ok":
                raise SystemExit("sealed verifier execution did not run exact bytes")
            expect_rejected(
                "sealed verifier stale digest",
                "bytes differ from the private build identity",
                lambda: gate.run_descriptor_bound_executable(
                    [str(executable_path)],
                    executable_root,
                    executable_path,
                    len(executable_payload),
                    hashlib.sha512(b"substituted executable").hexdigest(),
                    "test verifier",
                ),
            )

            original_subprocess_run = gate.subprocess.run
            pathname_swap_outputs: list[str] = []
            saved_executable = executable_root / "descriptor-bound-test-saved"

            def pathname_swap_runner(command, *args, **kwargs):
                if not command or not command[0].startswith("/proc/self/fd/"):
                    raise SystemExit("Linux verifier did not execute through /proc fd")
                pass_fds = kwargs.get("pass_fds")
                if not isinstance(pass_fds, tuple) or len(pass_fds) != 1:
                    raise SystemExit("Linux verifier did not pass one sealed memfd")
                executable_path.rename(saved_executable)
                malicious = executable_path
                malicious.write_text(
                    "#!/bin/sh\n"
                    "printf MALICIOUS\n"
                    f'touch "{malicious_marker}"\n',
                    encoding="utf-8",
                )
                malicious.chmod(0o700)
                try:
                    completed = original_subprocess_run(command, *args, **kwargs)
                    pathname_swap_outputs.append(completed.stdout)
                    return completed
                finally:
                    executable_path.unlink()
                    saved_executable.rename(executable_path)

            gate.subprocess.run = pathname_swap_runner
            try:
                try:
                    status, output = gate.run_descriptor_bound_executable(
                        [str(executable_path)],
                        executable_root,
                        executable_path,
                        len(executable_payload),
                        executable_sha512,
                        "test verifier",
                    )
                    if status != 0 or output != "immutable-copy-ok":
                        raise SystemExit("Linux pathname race changed verifier output")
                except gate.SuccessorAuthorizationError as exc:
                    if "opened inode changed during execution" not in str(exc):
                        raise
                if pathname_swap_outputs != ["immutable-copy-ok"]:
                    raise SystemExit("Linux pathname race executed replacement bytes")
                if malicious_marker.exists():
                    raise SystemExit(
                        "Linux pathname race verifier produced a malicious side effect"
                    )
            finally:
                gate.subprocess.run = original_subprocess_run
    with tempfile.TemporaryDirectory() as git_directory:
        git_root = Path(git_directory)
        subprocess.run(["git", "init", "--quiet"], cwd=git_root, check=True)
        tracked = git_root / "tracked.txt"
        tracked.write_text("clean\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=git_root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Hegemon test",
                "-c",
                "user.email=test@hegemon.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "test release revision",
            ],
            cwd=git_root,
            check=True,
        )
        if gate.resolve_checkout_source_revision(git_root) != subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=git_root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip():
            raise SystemExit("clean checkout revision did not bind HEAD")
        tracked.write_text("dirty\n", encoding="utf-8")
        expect_rejected(
            "dirty tracked release revision",
            "requires a clean tracked and untracked tree",
            lambda: gate.resolve_checkout_source_revision(git_root),
        )
        tracked.write_text("clean\n", encoding="utf-8")
        (git_root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        expect_rejected(
            "untracked release revision",
            "requires a clean tracked and untracked tree",
            lambda: gate.resolve_checkout_source_revision(git_root),
        )
    if "release_authorization_checker_source" in gate.REQUIRED_EVIDENCE_KINDS:
        raise SystemExit("checker source must not re-enter its own evidence bundle")
    if gate.AUTHORIZED_PROFILES:
        raise SystemExit("checked-in source registry must remain empty and fail closed")
    with tempfile.TemporaryDirectory() as registry_directory:
        registry_root = Path(registry_directory)
        checker_source = registry_root / "scripts/checker.py"
        registry_source = registry_root / gate.SOURCE_REGISTRY_RELATIVE_PATH
        checker_source.parent.mkdir(parents=True, exist_ok=True)
        checker_source.write_text("# test checker\n", encoding="utf-8")
        registry_source.write_text(
            '"""test data-only registry"""\nAUTHORIZED_PROFILE_RECORDS = {}\n',
            encoding="utf-8",
        )
        if gate.load_source_owned_registry(checker_source) != {}:
            raise SystemExit("data-only empty source registry did not parse")
        for name, expected_rejection, malicious_registry in (
            (
                "registry import execution",
                "source-owned authorized registry",
                "import os\nAUTHORIZED_PROFILE_RECORDS = {}\n",
            ),
            (
                "registry call execution",
                "AUTHORIZED_PROFILE_RECORDS",
                "AUTHORIZED_PROFILE_RECORDS = dict()\n",
            ),
            (
                "registry comprehension execution",
                "AUTHORIZED_PROFILE_RECORDS",
                "AUTHORIZED_PROFILE_RECORDS = {str(i): {} for i in range(1)}\n",
            ),
            (
                "registry attribute execution",
                "AUTHORIZED_PROFILE_RECORDS",
                "AUTHORIZED_PROFILE_RECORDS = object.__dict__\n",
            ),
            (
                "registry duplicate assignment",
                "source-owned authorized registry",
                "AUTHORIZED_PROFILE_RECORDS = {}\nAUTHORIZED_PROFILE_RECORDS = {}\n",
            ),
            (
                "registry duplicate literal key",
                "AUTHORIZED_PROFILE_RECORDS",
                'AUTHORIZED_PROFILE_RECORDS = {"x": {}, "x": {}}\n',
            ),
        ):
            registry_source.write_text(malicious_registry, encoding="utf-8")
            expect_rejected(
                name,
                expected_rejection,
                lambda: gate.load_source_owned_registry(checker_source),
            )
    if gate.AUTHORITY_SOURCE_PATHS != {
        "scripts/check_transaction_proof_successor_authorization.py",
        "scripts/transaction_proof_successor_authorized_registry.py",
    }:
        raise SystemExit("release authority source exclusion set drifted")
    diagnostic_payload = (
        ROOT / gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH
    ).read_bytes()
    if len(diagnostic_payload) != gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_BYTES:
        raise SystemExit("current-source diagnostic security report length drifted")
    if (
        hashlib.sha512(diagnostic_payload).hexdigest()
        != gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512
    ):
        raise SystemExit("current-source diagnostic security report digest drifted")
    diagnostic_report = gate.load_canonical_json_bytes(
        diagnostic_payload,
        "current-source diagnostic security report",
        gate.MAX_EVIDENCE_FILE_BYTES,
    )
    if (
        diagnostic_report.get("schema")
        != "hegemon.smallwood.poseidon2-v8.smz9.source-security-report.v3"
        or diagnostic_report.get("production_eligible") is not False
        or diagnostic_report.get("meets_128_bit_deployed_floor") is not False
        or diagnostic_report.get("deployed_composed_security_bits_floor") is not None
        or not diagnostic_report.get("blockers")
    ):
        raise SystemExit("current-source diagnostic security report became authorizing")
    executable_zk_payload = (
        ROOT / gate.EXECUTABLE_ZK_REFINEMENT_REPORT_PATH
    ).read_bytes()
    if len(executable_zk_payload) != gate.EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES:
        raise SystemExit("executable-ZK raw report length drifted")
    if (
        hashlib.sha512(executable_zk_payload).hexdigest()
        != gate.EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512
    ):
        raise SystemExit("executable-ZK raw report digest drifted")
    executable_zk_document = json.loads(executable_zk_payload.decode("utf-8"))
    executable_zk_identity = test_identity()
    executable_zk_identity["relation_program_sha512"] = executable_zk_document[
        "relation_program_sha512_hex"
    ]
    executable_zk_identity["relation_digest_hex"] = executable_zk_document[
        "relation_digest_hex"
    ]
    gate.validate_executable_zk_refinement_report(
        executable_zk_payload, executable_zk_identity
    )
    checked_profile_manifest = json.loads(
        (ROOT / "config/smallwood-v8-poseidon2-profile-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    if checked_profile_manifest.get("executable_zk_refinement_report") != {
        "bytes": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES,
        "direct_256_bit_first_program_route_used": False,
        "exact_lazy_program_keys_exclude_salt_only_point": True,
        "path": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_PATH,
        "production_eligible": False,
        "salt_only_oracle_program_count": 0,
        "schema": gate.EXECUTABLE_ZK_REFINEMENT_SCHEMA,
        "sha512": gate.EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512,
    }:
        raise SystemExit("profile manifest executable-ZK report pin drifted")
    if checked_profile_manifest.get("diagnostic_source_security_report") != {
        "bytes": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_BYTES,
        "path": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH,
        "production_authorizing": False,
        "schema": gate.SOURCE_SECURITY_REPORT_SCHEMA,
        "sha512": gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512,
    }:
        raise SystemExit("profile manifest diagnostic source-security report pin drifted")
    if checked_profile_manifest.get("required_release_receipts", {}).get(
        "executable_zk_refinement_report_sha512"
    ) != gate.EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512:
        raise SystemExit("profile manifest executable-ZK release receipt pin drifted")

    def expect_executable_zk_mutation_rejected(
        name: str, expected: str, mutate
    ) -> None:
        document = deepcopy(executable_zk_document)
        mutate(document)
        payload = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        expect_rejected(
            name,
            expected,
            lambda: gate.validate_executable_zk_refinement_report(
                payload, executable_zk_identity
            ),
        )

    expect_executable_zk_mutation_rejected(
        "executable-ZK schema mutation",
        "schema mismatch",
        lambda document: document.__setitem__("schema", "wrong-schema"),
    )
    expect_executable_zk_mutation_rejected(
        "executable-ZK salt-only program mutation",
        "salt_only_oracle_program_count must equal integer zero",
        lambda document: document.__setitem__("salt_only_oracle_program_count", 1),
    )
    expect_executable_zk_mutation_rejected(
        "executable-ZK lazy-key exclusion mutation",
        "exact_lazy_program_keys_exclude_salt_only_point must equal true",
        lambda document: document.__setitem__(
            "exact_lazy_program_keys_exclude_salt_only_point", False
        ),
    )
    expect_executable_zk_mutation_rejected(
        "executable-ZK direct first-program route mutation",
        "direct_256_bit_first_program_route_used must equal false",
        lambda document: document.__setitem__(
            "direct_256_bit_first_program_route_used", True
        ),
    )
    expect_executable_zk_mutation_rejected(
        "executable-ZK production posture mutation",
        "production_eligible must equal false",
        lambda document: document.__setitem__("production_eligible", True),
    )
    expect_rejected(
        "executable-ZK exact byte length mutation",
        "byte length must equal the source-pinned 4230 bytes",
        lambda: gate.validate_executable_zk_refinement_report(
            executable_zk_payload + b" ", executable_zk_identity
        ),
    )
    same_length_hash_mutation = executable_zk_payload.replace(
        executable_zk_document["simulator_binding_sha512_hex"].encode("ascii"),
        (
            (
                "0"
                if executable_zk_document["simulator_binding_sha512_hex"][0]
                != "0"
                else "1"
            )
            + executable_zk_document["simulator_binding_sha512_hex"][1:]
        ).encode("ascii"),
        1,
    )
    expect_rejected(
        "executable-ZK full SHA-512 mutation",
        "SHA-512 does not match the source-pinned raw report",
        lambda: gate.validate_executable_zk_refinement_report(
            same_length_hash_mutation, executable_zk_identity
        ),
    )
    gate.require_release_workflow_binding(ROOT)
    with tempfile.TemporaryDirectory() as workflow_directory:
        workflow_root = Path(workflow_directory)
        workflow_path = workflow_root / gate.RELEASE_WORKFLOW_PATH
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_bytes(
            (ROOT / gate.RELEASE_WORKFLOW_PATH).read_bytes() + b"# unauthorized drift\n"
        )
        expect_rejected(
            "release workflow source pin",
            "release workflow SHA-512 does not match",
            lambda: gate.require_release_workflow_binding(workflow_root),
        )
    checked_in = gate.check_selection_file(
        ROOT / gate.DEFAULT_SELECTION_PATH,
        ROOT,
        require_authorized=False,
    )
    if checked_in is not None:
        raise SystemExit("checked-in successor selection must remain unselected")
    expect_rejected(
        "checked-in authorization",
        "no transaction-proof successor is source-authorized",
        lambda: gate.check_selection_file(
            ROOT / gate.DEFAULT_SELECTION_PATH,
            ROOT,
            require_authorized=True,
        ),
    )
    if gate.SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS:
        raise SystemExit(
            "production lifecycle command inventory must remain empty until real tests land"
        )
    if gate.SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS:
        raise SystemExit(
            "production executable evidence command inventory must remain empty "
            "until real gates land"
        )
    if gate.SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS:
        raise SystemExit(
            "production independent-review trust-root inventory must remain empty"
        )
    if gate.SOURCE_BOUND_HERMETIC_RELEASE_ROOTS:
        raise SystemExit(
            "production hermetic release-root inventory must remain empty"
        )
    gate.SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS[
        TEST_REVIEW_TRUST_ROOT_ID
    ] = deepcopy(TEST_REVIEW_TRUST_ROOT)
    gate.SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS.update(
        TEST_RELEASE_EVIDENCE_COMMANDS
    )
    gate.SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS.update(
        TEST_LIFECYCLE_COMMANDS
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        selection, bundle, profile = make_fixture(root)
        fake_path = root / "fake-release-path"
        fake_path.mkdir()
        fake_tool_marker = root / "fake-path-tool-executed"
        for tool in ("git", "cargo"):
            fake_tool = fake_path / tool
            fake_tool.write_text(
                "#!/bin/sh\n"
                f'touch "{fake_tool_marker}"\n'
                "exit 0\n",
                encoding="utf-8",
            )
            fake_tool.chmod(0o700)
        original_path = os.environ.get("PATH")
        original_platform = gate.sys.platform
        os.environ["PATH"] = str(fake_path)
        gate.sys.platform = "linux"
        try:
            expect_rejected(
                "fake PATH git and cargo before hermetic authority",
                "source-owned hermetic release root authority is absent",
                lambda: gate.validate_evidence_bundle(bundle, root, profile),
            )
            if fake_tool_marker.exists():
                raise SystemExit(
                    "release authorization invoked fake PATH git or cargo before "
                    "hermetic authority"
                )
        finally:
            gate.sys.platform = original_platform
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
        evidence_by_id = {
            entry["id"]: entry for entry in bundle["evidence_files"]
        }
        primary_entry = evidence_by_id["retained_proof_primary"]
        primary_proof_path = root / primary_entry["path"]
        primary_proof = primary_proof_path.read_bytes()
        primary_report_path = primary_proof_path.parent / "artifact-report.json"
        primary_report_payload = primary_report_path.read_bytes()

        def validate_primary_source_inventory() -> None:
            report_payload = primary_report_path.read_bytes()
            gate.validate_retained_smz9_artifact_report(
                root,
                "retained_proof_primary",
                primary_entry["path"],
                primary_proof,
                profile.identity,
                len(report_payload),
                hashlib.sha512(report_payload).hexdigest(),
                TEST_SOURCE_REVISION,
            )

        validate_primary_source_inventory()
        gate.validate_retained_smz9_artifact_report(
            root,
            "retained_proof_primary",
            primary_entry["path"],
            primary_proof,
            profile.identity,
            len(primary_report_payload),
            hashlib.sha512(primary_report_payload).hexdigest(),
            "cd" * 20,
        )
        imported_formal_path = (
            root / "formal/crypto/HegemonCrypto/InventoryImportedDependency.lean"
        )
        imported_formal_payload = imported_formal_path.read_bytes()
        imported_formal_path.write_bytes(
            imported_formal_payload + b"-- imported formal dependency mutation\n"
        )
        expect_rejected(
            "imported formal source mutation",
            "proof source inventory differs from current source",
            validate_primary_source_inventory,
        )
        imported_formal_path.write_bytes(imported_formal_payload)
        source_path = root / "circuits/transaction/src/lib.rs"
        source_payload = source_path.read_bytes()
        source_path.write_bytes(source_payload + b"// proof-affecting mutation\n")
        expect_rejected(
            "proof source content mutation",
            "proof source inventory differs from current source",
            validate_primary_source_inventory,
        )
        source_path.write_bytes(source_payload)
        extra_source_path = root / "circuits/transaction/src/proof_config.rs"
        extra_source_payload = extra_source_path.read_bytes()
        extra_source_path.unlink()
        expect_rejected(
            "missing inventoried proof source",
            "proof source inventory differs from current source",
            validate_primary_source_inventory,
        )
        extra_source_path.write_bytes(extra_source_payload)

        for name, mutate in (
            (
                "proof source inventory omission",
                lambda report: report["proof_source_inventory"]["entries"].pop(),
            ),
            (
                "proof source inventory order drift",
                lambda report: report["proof_source_inventory"]["entries"].__setitem__(
                    slice(0, 2),
                    list(reversed(report["proof_source_inventory"]["entries"][:2])),
                ),
            ),
            (
                "proof source inventory path drift",
                lambda report: report["proof_source_inventory"]["entries"][0].__setitem__(
                    "path", "proof-source-path-drift"
                ),
            ),
        ):
            mutated_report = json.loads(primary_report_payload.decode("utf-8"))
            mutate(mutated_report)
            primary_report_path.write_bytes(gate.canonical_json_bytes(mutated_report))
            expect_rejected(
                name,
                "proof source inventory differs from current source",
                validate_primary_source_inventory,
            )
            primary_report_path.write_bytes(primary_report_payload)

        exact_source_inventory = gate.recompute_retained_proof_source_inventory(root)
        gate.recompute_retained_proof_source_inventory = (
            lambda _root: deepcopy(exact_source_inventory)
        )
        gate.resolve_checkout_source_revision = lambda _root: TEST_SOURCE_REVISION
        loaded_registry = gate.authorized_profiles_from_records(
            {TEST_PROFILE_ID: registry_record(profile)}
        )
        executable_zk_path_substitution = deepcopy(bundle)
        executable_zk_path_entry = next(
            entry
            for entry in executable_zk_path_substitution["evidence_files"]
            if entry["id"] == gate.EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID
        )
        executable_zk_path_entry["path"] = (
            "docs/crypto/not-the-source-pinned-executable-zk-report.json"
        )
        expect_rejected(
            "executable-ZK canonical path mutation",
            "path must equal the source-owned canonical path",
            lambda: gate.validate_evidence_bundle(
                executable_zk_path_substitution,
                root,
                profile,
                artifact_command_runner=strict_artifact_command_runner,
            ),
        )
        gate.SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS.clear()
        expect_rejected(
            "unauthenticated independent review",
            "has no source-bound authenticated review trust root",
            lambda: check(selection, root, profile, registry=loaded_registry),
        )
        gate.SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS[
            TEST_REVIEW_TRUST_ROOT_ID
        ] = deepcopy(TEST_REVIEW_TRUST_ROOT)
        gate.SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS.clear()
        expect_rejected(
            "unbound executable release evidence",
            "has no source-bound executable evidence command inventory",
            lambda: check(selection, root, profile, registry=loaded_registry),
        )
        gate.SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS.update(
            TEST_RELEASE_EVIDENCE_COMMANDS
        )
        gate.SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS.clear()
        expect_rejected(
            "unbound production lifecycle receipts",
            "has no source-bound actual lifecycle integration command inventory",
            lambda: check(selection, root, profile, registry=loaded_registry),
        )
        gate.SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS.update(
            TEST_LIFECYCLE_COMMANDS
        )
        STRICT_ARTIFACT_COMMANDS.clear()
        global STRICT_ARTIFACT_BINARY, STRICT_SECURITY_BINARY
        STRICT_ARTIFACT_BINARY = None
        STRICT_SECURITY_BINARY = None
        if check(selection, root, profile, registry=loaded_registry) != TEST_PROFILE_ID:
            raise SystemExit(
                "strict-command structural fixture did not traverse the library gate"
            )
        expected_lifecycle_command_count = sum(
            len(commands) for commands in TEST_LIFECYCLE_COMMANDS.values()
        )
        expected_release_evidence_command_count = sum(
            len(commands) for commands in TEST_RELEASE_EVIDENCE_COMMANDS.values()
        )
        if len(STRICT_ARTIFACT_COMMANDS) != (
            4
            + expected_lifecycle_command_count
            + expected_release_evidence_command_count
        ):
            raise SystemExit(
                "source-bound executable evidence and lifecycle commands, source verifier "
                "build, deployed-security gate, and both role commands were not all invoked"
            )
        observed_release_evidence_commands = {
            command
            for command, _ in STRICT_ARTIFACT_COMMANDS
            if len(command) == 1 and command[0].startswith("test-only-evidence:")
        }
        expected_release_evidence_commands = {
            (command,)
            for commands in TEST_RELEASE_EVIDENCE_COMMANDS.values()
            for command in commands
        }
        if observed_release_evidence_commands != expected_release_evidence_commands:
            raise SystemExit(
                "source-bound executable evidence command inventory drifted"
            )
        observed_lifecycle_commands = {
            command
            for command, _ in STRICT_ARTIFACT_COMMANDS
            if len(command) == 1 and command[0].startswith("test-only:")
        }
        expected_lifecycle_commands = {
            (command,)
            for commands in TEST_LIFECYCLE_COMMANDS.values()
            for _, command in commands
        }
        if observed_lifecycle_commands != expected_lifecycle_commands:
            raise SystemExit("source-bound lifecycle command execution inventory drifted")
        diagnostic_identity = deepcopy(dict(profile.identity))
        diagnostic_identity["source_derived_security_report_sha512"] = (
            gate.NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512
        )
        expect_rejected(
            "diagnostic security report substitution",
            "may not pin the non-authorizing current-source diagnostic report",
            lambda: gate.validate_identity(
                diagnostic_identity, "diagnostic identity"
            ),
        )
        verify_commands = [
            (command, cwd)
            for command, cwd in STRICT_ARTIFACT_COMMANDS
            if len(command) == 3 and command[1] == "verify"
        ]
        if len(verify_commands) != 2:
            raise SystemExit("both retained roles did not invoke the source verifier binary")
        invoked_roles = {
            Path(command[-1]).name for command, _ in verify_commands
        }
        if invoked_roles != set(gate.RETAINED_PROOF_IDS):
            raise SystemExit("source verifier command did not cover both retained roles")
        security_commands = [
            command
            for command, _ in STRICT_ARTIFACT_COMMANDS
            if len(command) == 2 and command[1] == "--require-deployed"
        ]
        if security_commands != [
            (str(STRICT_SECURITY_BINARY), "--require-deployed")
        ]:
            raise SystemExit("source deployed-security verifier command was not exact")
        if any(cwd != root for _, cwd in STRICT_ARTIFACT_COMMANDS):
            raise SystemExit("source verifier command ran from the wrong repository root")
        build_commands = [
            command for command, _ in STRICT_ARTIFACT_COMMANDS if command[0] == "cargo"
        ]
        if len(build_commands) != 1 or build_commands[0][-2] != "--target-dir":
            raise SystemExit("source verifier was not built in one explicit private target")
        private_target = Path(build_commands[0][-1])
        if not private_target.is_absolute() or root.resolve() in private_target.parents:
            raise SystemExit("source verifier target was not private from the repository")

        def check_with_runner(runner) -> str | None:
            return gate.check_selection_document(
                selection,
                root,
                require_authorized=True,
                registry=loaded_registry,
                artifact_command_runner=runner,
            )

        def failed_build_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            if command and command[0] == "cargo":
                return 1, "synthetic build failure"
            return strict_artifact_command_runner(command, command_root)

        expect_rejected(
            "source verifier build failure",
            "source artifact verifier failed to build",
            lambda: check_with_runner(failed_build_runner),
        )

        def mismatched_private_binary_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if command and command[0] == "cargo":
                if STRICT_ARTIFACT_BINARY is None:
                    raise SystemExit("strict runner did not publish its private binary")
                STRICT_ARTIFACT_BINARY.write_bytes(b"different private verifier binary")
                STRICT_ARTIFACT_BINARY.chmod(0o700)
            return status, output

        expect_rejected(
            "private verifier binary mismatch",
            "source verifier self-attestation mismatch",
            lambda: check_with_runner(mismatched_private_binary_runner),
        )

        def failed_security_gate_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 2 and command[1] == "--require-deployed":
                return 1, "synthetic deployed-security rejection"
            return status, output

        expect_rejected(
            "source deployed-security gate failure",
            "source deployed-security verifier rejected current source",
            lambda: check_with_runner(failed_security_gate_runner),
        )

        def mismatched_security_report_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 2 and command[1] == "--require-deployed":
                output += "\n"
            return status, output

        expect_rejected(
            "source deployed-security report byte mismatch",
            "source deployed-security verifier report bytes do not match evidence",
            lambda: check_with_runner(mismatched_security_report_runner),
        )

        def false_verifier_result_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 3 and command[1] == "verify":
                result = json.loads(output)
                result["source_factory_verified"] = False
                output = json.dumps(result)
            return status, output

        expect_rejected(
            "false source verifier result",
            "source artifact verifier result mismatch",
            lambda: check_with_runner(false_verifier_result_runner),
        )

        def false_verifier_binary_result_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 3 and command[1] == "verify":
                result = json.loads(output)
                result["verifier_provenance"]["binary_sha512"] = hashlib.sha512(
                    b"substituted verifier binary"
                ).hexdigest()
                output = json.dumps(result)
            return status, output

        expect_rejected(
            "fresh verifier binary result substitution",
            "source verifier self-attestation mismatch",
            lambda: check_with_runner(false_verifier_binary_result_runner),
        )

        def post_verify_binary_mutation_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 3 and command[1] == "verify":
                if STRICT_ARTIFACT_BINARY is None:
                    raise SystemExit("strict runner lost its private binary")
                STRICT_ARTIFACT_BINARY.write_bytes(b"post-verification substitution")
                STRICT_ARTIFACT_BINARY.chmod(0o700)
            return status, output

        expect_rejected(
            "post-verification binary substitution",
            "source artifact verifier binary changed after the private build",
            lambda: check_with_runner(post_verify_binary_mutation_runner),
        )

        def snapshot_mutation_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 3 and command[1] == "verify":
                proof_path = Path(command[-1]) / "proof.bin"
                proof_path.chmod(0o600)
                proof_path.write_bytes(proof_path.read_bytes() + b"mutation")
            return status, output

        expect_rejected(
            "artifact snapshot TOCTOU mutation",
            "artifact snapshot changed during verification",
            lambda: check_with_runner(snapshot_mutation_runner),
        )

        evidence_by_id = {
            entry["id"]: entry for entry in bundle["evidence_files"]
        }
        relation_manifest_entry = evidence_by_id["relation_manifest"]
        profile_manifest_binding_entry = evidence_by_id["profile_manifest"]
        relation_manifest_payload = (
            root / relation_manifest_entry["path"]
        ).read_bytes()
        profile_manifest_binding_payload = (
            root / profile_manifest_binding_entry["path"]
        ).read_bytes()

        def validate_manifest_pair(
            relation_payload: bytes, profile_payload: bytes
        ) -> None:
            gate.validate_relation_profile_manifest_binding(
                profile,
                profile.identity,
                {
                    "relation_manifest": relation_payload,
                    "profile_manifest": profile_payload,
                },
                {
                    "relation_manifest": relation_manifest_entry["path"],
                    "profile_manifest": profile_manifest_binding_entry["path"],
                },
                {
                    "relation_manifest": hashlib.sha512(
                        relation_manifest_payload
                    ).hexdigest(),
                    "profile_manifest": hashlib.sha512(
                        profile_manifest_binding_payload
                    ).hexdigest(),
                },
            )

        wrong_semantic_relation = json.loads(
            relation_manifest_payload.decode("utf-8")
        )
        wrong_semantic_relation["semantic_target"]["id"] = (
            "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v3"
        )
        expect_rejected(
            "semantic relation v3 substitution",
            "semantic target must equal the source V8 relation v2",
            lambda: validate_manifest_pair(
                gate.canonical_json_bytes(wrong_semantic_relation),
                profile_manifest_binding_payload,
            ),
        )
        wrong_consensus_profile = json.loads(
            profile_manifest_binding_payload.decode("utf-8")
        )
        wrong_consensus_profile["consensus_identity"]["profile_wire_id"] = 5
        expect_rejected(
            "profile consensus tuple substitution",
            "profile manifest consensus identity profile_wire_id mismatch",
            lambda: validate_manifest_pair(
                relation_manifest_payload,
                gate.canonical_json_bytes(wrong_consensus_profile),
            ),
        )
        wrong_transport_profile = json.loads(
            profile_manifest_binding_payload.decode("utf-8")
        )
        wrong_transport_profile["transport_identity"][
            "inner_proof_magic_ascii"
        ] = "SMZ8"
        expect_rejected(
            "profile transport tuple substitution",
            "profile manifest transport identity inner_proof_magic_ascii mismatch",
            lambda: validate_manifest_pair(
                relation_manifest_payload,
                gate.canonical_json_bytes(wrong_transport_profile),
            ),
        )
        wrong_diagnostic_profile = json.loads(
            profile_manifest_binding_payload.decode("utf-8")
        )
        wrong_diagnostic_profile["diagnostic_source_security_report"]["bytes"] += 1
        expect_rejected(
            "profile diagnostic source-security pin substitution",
            "diagnostic source-security report pin mismatch",
            lambda: validate_manifest_pair(
                relation_manifest_payload,
                gate.canonical_json_bytes(wrong_diagnostic_profile),
            ),
        )
        wrong_executable_zk_profile = json.loads(
            profile_manifest_binding_payload.decode("utf-8")
        )
        wrong_executable_zk_profile["executable_zk_refinement_report"][
            "production_eligible"
        ] = True
        expect_rejected(
            "profile executable-ZK pin substitution",
            "executable-ZK report pin mismatch",
            lambda: validate_manifest_pair(
                relation_manifest_payload,
                gate.canonical_json_bytes(wrong_executable_zk_profile),
            ),
        )

        primary_entry = evidence_by_id["retained_proof_primary"]
        primary_proof_path = root / primary_entry["path"]
        primary_report_path = primary_proof_path.parent / "artifact-report.json"
        primary_report_original = primary_report_path.read_bytes()
        wrong_report = json.loads(primary_report_original.decode("utf-8"))
        wrong_report["schema"] = "hegemon-smallwood-poseidon2-v8-retained-artifact-v1"
        wrong_report_payload = gate.canonical_json_bytes(wrong_report)
        primary_report_path.write_bytes(wrong_report_payload)
        wrong_report_bundle = deepcopy(bundle)
        wrong_report_entry = next(
            entry
            for entry in wrong_report_bundle["evidence_files"]
            if entry["id"] == "retained_proof_primary"
        )
        wrong_report_entry["artifact_report_bytes"] = len(wrong_report_payload)
        wrong_report_entry["artifact_report_sha512"] = hashlib.sha512(
            wrong_report_payload
        ).hexdigest()
        wrong_report_profile = repin_bundle(root, wrong_report_bundle, profile)
        expect_rejected(
            "retained artifact stale report schema",
            "artifact report schema mismatch",
            lambda: check(selection, root, wrong_report_profile),
        )
        primary_report_path.write_bytes(primary_report_original)
        profile = repin_bundle(root, bundle, profile)

        def expect_report_rejected(name: str, expected: str, mutate) -> None:
            document = json.loads(primary_report_original.decode("utf-8"))
            mutate(document)
            payload = gate.canonical_json_bytes(document)
            primary_report_path.write_bytes(payload)
            changed_bundle = deepcopy(bundle)
            changed_entry = next(
                entry
                for entry in changed_bundle["evidence_files"]
                if entry["id"] == "retained_proof_primary"
            )
            changed_entry["artifact_report_bytes"] = len(payload)
            changed_entry["artifact_report_sha512"] = hashlib.sha512(
                payload
            ).hexdigest()
            changed_profile = repin_bundle(root, changed_bundle, profile)
            expect_rejected(
                name,
                expected,
                lambda: check(selection, root, changed_profile),
            )
            primary_report_path.write_bytes(primary_report_original)
            write_canonical(root / TEST_BUNDLE_PATH, bundle)

        expect_report_rejected(
            "retained artifact unknown top-level field",
            "artifact report keys mismatch",
            lambda report: report.__setitem__("production_authorized", True),
        )
        expect_report_rejected(
            "retained artifact false immediate verification",
            "source_factory_immediate must equal true",
            lambda report: report["verification"].__setitem__(
                "source_factory_immediate", False
            ),
        )
        expect_report_rejected(
            "retained artifact stale lifecycle label",
            "artifact verification keys mismatch",
            lambda report: report["verification"].__setitem__(
                "lifecycle_stages",
                report["verification"].pop("transport_parser_stage_checks"),
            ),
        )
        expect_report_rejected(
            "retained artifact false transport parser-stage check",
            "transport parser-stage checks[0].exact_bytes must equal true",
            lambda report: report["verification"][
                "transport_parser_stage_checks"
            ][0].__setitem__("exact_bytes", False),
        )
        expect_report_rejected(
            "retained artifact geometry mutation",
            "artifact geometry mismatch",
            lambda report: report["geometry"].__setitem__("witness_rows", 685),
        )
        expect_report_rejected(
            "retained artifact pending-action projection mutation",
            "artifact byte report mismatch",
            lambda report: report["bytes"].__setitem__(
                "projected_max_pending_action", 128_297
            ),
        )
        expect_report_rejected(
            "retained artifact false node PendingAction lifecycle",
            "canonical_scale_decode must equal true",
            lambda report: report["verification"][
                "node_pending_action_lifecycle"
            ].__setitem__("canonical_scale_decode", False),
        )
        expect_report_rejected(
            "retained artifact LVCS honest-map inventory mutation",
            "artifact honest-map inventory mismatch",
            lambda report: report["verification"]["honest_map_audit"].__setitem__(
                "lvcs_joint_view_count", 2_799
            ),
        )
        expect_report_rejected(
            "retained artifact accepted-proof Lean-model substitution",
            "accepted-proof refinement lean_wire_model mismatch",
            lambda report: report["verification"]["honest_map_audit"].__setitem__(
                "lean_wire_model", "unbound-model"
            ),
        )
        expect_report_rejected(
            "retained artifact accepted-proof digest substitution",
            "accepted-proof refinement proof digest mismatch",
            lambda report: report["verification"]["honest_map_audit"].__setitem__(
                "proof_sha512", "00" * 64
            ),
        )
        expect_report_rejected(
            "retained artifact external QROM claim substitution",
            "accepted-proof refinement external_sha512_qrom_claim mismatch",
            lambda report: report["verification"]["honest_map_audit"].__setitem__(
                "external_sha512_qrom_claim", True
            ),
        )
        expect_report_rejected(
            "retained artifact accepted PendingAction outer-field mutation",
            "PendingAction mutations[0].rejected must equal true",
            lambda report: report["verification"][
                "pending_action_mutations"
            ][0].__setitem__("rejected", False),
        )
        expect_report_rejected(
            "retained artifact missing statement-rewrap mutation",
            "transport mutations must contain the exact ordered mutation inventory",
            lambda report: report["verification"]["transport_mutations"].pop(-2),
        )
        expect_report_rejected(
            "retained artifact swapped rewrap mutation order",
            "transport mutations[5] mutation name mismatch",
            lambda report: report["verification"]["transport_mutations"].__setitem__(
                slice(5, 7),
                list(reversed(report["verification"]["transport_mutations"][5:7])),
            ),
        )
        for name, expected, mutate in (
            (
                "retained artifact relation magic mutation",
                "relation-program identity mismatch",
                lambda report: report["identity"]["relation_program"].__setitem__(
                    "magic", "HGV8RP01"
                ),
            ),
            (
                "retained artifact relation byte-count mutation",
                "relation-program identity mismatch",
                lambda report: report["identity"]["relation_program"].__setitem__(
                    "bytes", 89_310
                ),
            ),
            (
                "retained artifact relation hash mutation",
                "relation-program identity mismatch",
                lambda report: report["identity"]["relation_program"].__setitem__(
                    "sha512", hashlib.sha512(b"wrong relation").hexdigest()
                ),
            ),
            (
                "retained artifact semantic relation mutation",
                "semantic relation mismatch",
                lambda report: report["identity"].__setitem__(
                    "semantic_relation",
                    "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v3",
                ),
            ),
            (
                "retained artifact native transport mutation",
                "transport identity mismatch",
                lambda report: report["identity"]["transport"].__setitem__(
                    "native_leaf_magic", "HGV8TX01"
                ),
            ),
            (
                "retained artifact RPC transport mutation",
                "transport identity mismatch",
                lambda report: report["identity"]["transport"].__setitem__(
                    "rpc_envelope_magic", "SWP8LC01"
                ),
            ),
            (
                "retained artifact circuit tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "circuit_version", 7
                ),
            ),
            (
                "retained artifact crypto-suite tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "crypto_suite", 6
                ),
            ),
            (
                "retained artifact family tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "family_id", 2
                ),
            ),
            (
                "retained artifact action tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "action_id", 9
                ),
            ),
            (
                "retained artifact backend tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "backend_id", 1
                ),
            ),
            (
                "retained artifact profile tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "profile_id", 5
                ),
            ),
            (
                "retained artifact domain tuple mutation",
                "consensus tuple mismatch",
                lambda report: report["identity"]["consensus_tuple"].__setitem__(
                    "domain_set", 3
                ),
            ),
        ):
            expect_report_rejected(name, expected, mutate)

        primary_report_path.write_bytes(primary_report_original + b"\n")
        expect_rejected(
            "retained artifact report digest binding",
            "artifact report byte length mismatch",
            lambda: check(selection, root, profile),
        )
        primary_report_path.write_bytes(primary_report_original)
        write_canonical(root / TEST_BUNDLE_PATH, bundle)

        wrong_magic_bundle = deepcopy(bundle)
        wrong_magic_entry = next(
            entry
            for entry in wrong_magic_bundle["evidence_files"]
            if entry["id"] == "retained_proof_primary"
        )
        primary_proof_original = primary_proof_path.read_bytes()
        wrong_magic_proof = b"SMZ8" + primary_proof_original[4:]
        primary_proof_path.write_bytes(wrong_magic_proof)
        original_artifact_directory = primary_proof_path.parent
        wrong_magic_artifact_directory = original_artifact_directory.with_name(
            f"smz9-{hashlib.sha512(wrong_magic_proof).hexdigest()[:24]}"
        )
        original_artifact_directory.rename(wrong_magic_artifact_directory)
        wrong_magic_proof_path = wrong_magic_artifact_directory / "proof.bin"
        wrong_magic_entry.update(
            {
                "bytes": len(wrong_magic_proof),
                "path": wrong_magic_proof_path.relative_to(root).as_posix(),
                "sha512": hashlib.sha512(wrong_magic_proof).hexdigest(),
            }
        )
        wrong_magic_profile = repin_bundle(root, wrong_magic_bundle, profile)
        expect_rejected(
            "retained artifact SMZ8 substitution",
            "formal receipt retained_proof_primary_sha512 mismatch",
            lambda: check(selection, root, wrong_magic_profile),
        )
        wrong_magic_artifact_directory.rename(original_artifact_directory)
        primary_proof_path.write_bytes(primary_proof_original)
        profile = repin_bundle(root, bundle, profile)

        receipt_id = "adaptive_qrom_whole_view_zk_receipt"
        receipt_entry = evidence_by_id[receipt_id]
        receipt_path = root / receipt_entry["path"]
        receipt_original = receipt_path.read_bytes()
        false_receipt = json.loads(receipt_original.decode("utf-8"))
        false_receipt["release_gate_passed"] = False
        false_receipt_payload = gate.canonical_json_bytes(false_receipt)
        receipt_path.write_bytes(false_receipt_payload)
        false_receipt_bundle = deepcopy(bundle)
        false_receipt_entry = next(
            entry
            for entry in false_receipt_bundle["evidence_files"]
            if entry["id"] == receipt_id
        )
        false_receipt_entry.update(
            {
                "bytes": len(false_receipt_payload),
                "sha512": hashlib.sha512(false_receipt_payload).hexdigest(),
            }
        )
        false_receipt_profile = repin_bundle(root, false_receipt_bundle, profile)
        expect_rejected(
            "false positive receipt",
            "release_gate_passed must equal true",
            lambda: check(selection, root, false_receipt_profile),
        )
        receipt_path.write_bytes(receipt_original)
        profile = repin_bundle(root, bundle, profile)

        def expect_release_document_rejected(
            evidence_id: str, name: str, expected: str, mutate
        ) -> None:
            entry = evidence_by_id[evidence_id]
            path = root / entry["path"]
            original = path.read_bytes()
            document = json.loads(original.decode("utf-8"))
            mutate(document)
            payload = gate.canonical_json_bytes(document)
            path.write_bytes(payload)
            changed_bundle = deepcopy(bundle)
            changed_entry = next(
                item
                for item in changed_bundle["evidence_files"]
                if item["id"] == evidence_id
            )
            digest = hashlib.sha512(payload).hexdigest()
            changed_entry["bytes"] = len(payload)
            changed_entry["sha512"] = digest
            changed_identity = deepcopy(dict(profile.identity))
            pin_field = gate.PINNED_EVIDENCE_DIGEST_FIELDS.get(evidence_id)
            if pin_field is not None:
                changed_identity[pin_field] = digest
                changed_bundle["identity"][pin_field] = digest
            changed_profile = replace(profile, identity=changed_identity)
            changed_profile = repin_bundle(root, changed_bundle, changed_profile)
            changed_selection = deepcopy(selection)
            changed_selection["identity"] = deepcopy(changed_identity)
            expect_rejected(
                name,
                expected,
                lambda: check(changed_selection, root, changed_profile),
            )
            path.write_bytes(original)
            write_canonical(root / TEST_BUNDLE_PATH, bundle)

        expect_release_document_rejected(
            "adaptive_qrom_whole_view_zk_receipt",
            "receipt unresolved premise",
            "unresolved premises must be empty",
            lambda document: document["result"]["unresolved_premises"].append(
                "adaptive SHA-512/QROM bridge absent"
            ),
        )
        expect_release_document_rejected(
            gate.ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID,
            "conditional adaptive theorem substitution",
            "formal receipt release_theorem mismatch",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "release_theorem",
                "HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge."
                "smz9_adaptive_qrom_whole_view_indistinguishability_given_release_receipt",
            ),
        )
        expect_release_document_rejected(
            gate.GLOBAL_QROM_LIFETIME_EVIDENCE_ID,
            "global lifetime formal source substitution",
            "formal receipt formal_source_path mismatch",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "formal_source_path",
                gate.ADAPTIVE_QROM_WHOLE_VIEW_FORMAL_SOURCE_PATH,
            ),
        )
        expect_release_document_rejected(
            gate.GLOBAL_QROM_LIFETIME_EVIDENCE_ID,
            "global lifetime formal source digest substitution",
            "formal receipt source digest mismatch",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "formal_source_sha512", hashlib.sha512(b"stale formal source").hexdigest()
            ),
        )
        expect_release_document_rejected(
            gate.GLOBAL_QROM_LIFETIME_EVIDENCE_ID,
            "global lifetime weak security floor",
            "formal receipt security floor is below 128 bits",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "concrete_security_bits_floor", 127
            ),
        )
        expect_release_document_rejected(
            gate.ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID,
            "adaptive receipt not constructed",
            "release_receipt_constructed must equal true",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "release_receipt_constructed", False
            ),
        )
        expect_release_document_rejected(
            gate.GLOBAL_QROM_LIFETIME_EVIDENCE_ID,
            "global lifetime inputs not instantiated",
            "all_release_inputs_instantiated must equal true",
            lambda document: document["result"]["formal_receipt"].__setitem__(
                "all_release_inputs_instantiated", False
            ),
        )
        expect_release_document_rejected(
            gate.INDEPENDENT_REVIEW_EVIDENCE_ID,
            "independent review signature path substitution",
            "review signature_path mismatch",
            lambda document: document["result"]["review_attestation"].__setitem__(
                "signature_path", "docs/not-a-review-signature.bin"
            ),
        )
        expect_release_document_rejected(
            gate.INDEPENDENT_REVIEW_EVIDENCE_ID,
            "independent review signature digest substitution",
            "independent review signature mismatch",
            lambda document: document["result"]["review_attestation"].__setitem__(
                "signature_sha512", hashlib.sha512(b"stale signature").hexdigest()
            ),
        )
        expect_release_document_rejected(
            "production_capability_manifest",
            "production capability note root substitution",
            "capability tuple mismatch",
            lambda document: document["result"]["capability"][
                "note_genesis_root"
            ].__setitem__(0, 1),
        )
        for field, replacement in (
            (
                "deactivation_height_exclusive",
                profile.identity["deactivation_height_exclusive"] + 1,
            ),
            ("activation_genesis_hash", "34" * 32),
            ("coinbase_action_id", 12),
            ("max_proof_actions_per_block", 513),
            ("claimed_security_bits", 129),
        ):
            expect_release_document_rejected(
                "production_capability_manifest",
                f"production capability {field} substitution",
                "capability tuple mismatch",
                lambda document, field=field, replacement=replacement: document[
                    "result"
                ]["capability"].__setitem__(field, replacement),
            )
        expect_release_document_rejected(
            "production_value_balance_zero_projection_receipt",
            "native nonzero value balance admission",
            "native_projection_enforces_zero must equal true",
            lambda document: document["result"]["projection"].__setitem__(
                "native_projection_enforces_zero", False
            ),
        )
        expect_release_document_rejected(
            gate.PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID,
            "conditional V8 lifetime maximum substitution",
            "conditional_max_total_proofs_at_128_bits mismatch",
            lambda document: document["result"]["proof_lifetime_accounting"].__setitem__(
                "conditional_max_total_proofs_at_128_bits", 621_730_875
            ),
        )
        expect_release_document_rejected(
            gate.PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID,
            "V8 accounting window promoted to cryptographic reset",
            "accounting_window_is_cryptographic_reset must equal false",
            lambda document: document["result"]["proof_lifetime_accounting"].__setitem__(
                "accounting_window_is_cryptographic_reset", True
            ),
        )
        expect_release_document_rejected(
            gate.PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID,
            "conditional V8 counter promoted to deployed security",
            "deployed_security_claimed must equal false",
            lambda document: document["result"]["proof_lifetime_accounting"].__setitem__(
                "deployed_security_claimed", True
            ),
        )
        expect_release_document_rejected(
            "source_derived_composed_security_report",
            "false deployed-security report",
            "source command output is not bound to its positive check receipt",
            lambda document: document.__setitem__("production_eligible", False),
        )
        security_report_entry = evidence_by_id[
            "source_derived_composed_security_report"
        ]
        string_only_history_report = json.loads(
            (root / security_report_entry["path"]).read_text(encoding="utf-8")
        )
        string_only_history_report["unbounded_history_theorem_required"] = "yes"
        expect_rejected(
            "string-only unbounded history closure",
            "must name the exact required global QROM lifetime receipt",
            lambda: gate.validate_source_security_report_document(
                gate.canonical_json_bytes(string_only_history_report),
                profile.identity,
            ),
        )

        def expect_security_report_rejected(
            name: str,
            expected_rejection: str,
            mutate,
        ) -> None:
            document = json.loads(
                (root / security_report_entry["path"]).read_text(encoding="utf-8")
            )
            mutate(document)
            expect_rejected(
                name,
                expected_rejection,
                lambda: gate.validate_source_security_report_document(
                    gate.canonical_json_bytes(document), profile.identity
                ),
            )

        expect_security_report_rejected(
            "honest abort relabeled as soundness",
            "global-query screen mismatch",
            lambda document: document["conditional_global_query_work_screens"][0].__setitem__(
                "abort_terms_excluded_from_soundness_and_reduction_failure", False
            ),
        )
        expect_security_report_rejected(
            "byte quotient promoted to interaction cap",
            "byte-quotient diagnostic mismatch",
            lambda document: document["byte_quotient_diagnostic"].__setitem__(
                "is_upper_bound_on_proof_interactions", True
            ),
        )
        expect_security_report_rejected(
            "CMS instability omits honest programmed SHA exposures",
            "global-query screen mismatch",
            lambda document: document["conditional_global_query_work_screens"][0].__setitem__(
                "cms_instability_uses_queries_plus_honest_programmed_exposures", False
            ),
        )
        expect_security_report_rejected(
            "adaptive programming uses adversarial exponent only",
            "global-query screen mismatch",
            lambda document: document["conditional_global_query_work_screens"][0].__setitem__(
                "adaptive_programming_query_log2_ceiling", 64
            ),
        )
        expect_security_report_rejected(
            "SHA primitive receipt profile substitution",
            "identity, accounting, validity, or review mismatch",
            lambda document: document["sha512_primitive_security_bound"].__setitem__(
                "exact_primitive_profile_identity", "SHA-512"
            ),
        )
        expect_security_report_rejected(
            "Poseidon primitive receipt numerator substitution",
            "exact primitive work-screen ratio mismatch",
            lambda document: document["poseidon2_primitive_security_bound"]["work_screens"][
                0
            ]["collision_advantage_upper_bound"].__setitem__("numerator_decimal", "1"),
        )
        expect_security_report_rejected(
            "missing quantitative SHA-to-product reduction bound",
            "must be an object",
            lambda document: document.__setitem__(
                "sha512_to_indexed_product_oracle_reduction_bound", None
            ),
        )
        expect_security_report_rejected(
            "SHA-to-product loss omitted from deployed composition",
            "deployed composition omits, duplicates, or mis-scales",
            lambda document: document["deployed_finite_history_composed"].__setitem__(
                "numerator_decimal",
                str(
                    int(
                        document["deployed_finite_history_composed"][
                            "numerator_decimal"
                        ]
                    )
                    + 1
                ),
            ),
        )
        expect_security_report_rejected(
            "missing exact lazy Merkle input recording",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"].__setitem__(
                "source_role_framed_io_recording_refinement_instantiated", False
            ),
        )
        expect_security_report_rejected(
            "lazy internal entropy collapsed to one digest",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"].__setitem__(
                "internal_node_conditional_entropy_bits", 512
            ),
        )
        expect_security_report_rejected(
            "lazy independent internal maximum substituted at leaf cap",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"].__setitem__(
                "internal_node_program_cap_when_leaf_programs_equal_20", 372
            ),
        )
        expect_security_report_rejected(
            "lazy old 372-event internal ratio substituted",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"][
                "conditional_internal_node_loss"
            ].__setitem__("numerator_decimal", "2340421632"),
        )
        expect_security_report_rejected(
            "lazy strict-128 observed-view maximum mutation",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"].__setitem__(
                "maximum_observed_honest_proof_views_for_strict_128_decimal",
                "18889465930379069227008",
            ),
        )
        expect_security_report_rejected(
            "lazy first-failing observed-view posture mutation",
            "lazy-Merkle screen mismatch",
            lambda document: document["adaptive_lazy_merkle_programming_screen"].__setitem__(
                "first_failing_observed_honest_proof_views_supports_strict_128", True
            ),
        )
        expect_security_report_rejected(
            "missing all-points adaptive conditioning",
            "full-tree screen mismatch",
            lambda document: document["adaptive_full_tree_programming_screen"].__setitem__(
                "paper_and_all_points_hypotheses_instantiated", False
            ),
        )
        expect_security_report_rejected(
            "incomplete public attack inventory",
            "claim ledger mismatch",
            lambda document: document["claim_ledger"].__setitem__(
                "public_attack_inventory_complete", False
            ),
        )
        expect_security_report_rejected(
            "capability lifetime exceeds analyzed budget",
            "budget mismatch",
            lambda document: document["budget"].__setitem__(
                "capability_deactivation_height_exclusive",
                profile.identity["activation_height"]
                + gate.RETAINED_SECURITY_EPOCH_BLOCKS
                + 1,
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "missing actual lifecycle integration command",
            "must cover the exact lifecycle stage inventory",
            lambda document: document["result"]["integration"][
                "stage_results"
            ].pop(),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "substituted actual lifecycle integration command",
            "lifecycle command mismatch",
            lambda document: document["result"]["integration"][
                "stage_results"
            ][0].__setitem__("command", "test-only:parser-stage-substitution"),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "stale SMZ8 lifecycle command substitution",
            "lifecycle command mismatch",
            lambda document: document["result"]["integration"][
                "stage_results"
            ][0].__setitem__(
                "command",
                "cargo test retained_smz8_parser_only",
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "parser labels promoted to lifecycle authority",
            "parser_stage_labels_used_as_authority must equal false",
            lambda document: document["result"]["integration"].__setitem__(
                "parser_stage_labels_used_as_authority", True
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "scripted verifier substituted for production verifier",
            "production_verifier_used must equal true",
            lambda document: document["result"]["integration"].__setitem__(
                "production_verifier_used", False
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "cache receipt or sidecar used for validity",
            "validity_shortcuts_used must equal false",
            lambda document: document["result"]["integration"].__setitem__(
                "validity_shortcuts_used", True
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "retained independent proof substituted for lifecycle primary",
            "must exercise retained_proof_primary",
            lambda document: document["result"]["integration"].__setitem__(
                "retained_proof_id", "retained_proof_independent"
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle retained proof digest substitution",
            "lifecycle proof digest is not the retained primary",
            lambda document: document["result"]["integration"].__setitem__(
                "proof_sha512", hashlib.sha512(b"stale proof").hexdigest()
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle capability identity substitution",
            "lifecycle capability identity mismatch",
            lambda document: document["result"]["integration"].__setitem__(
                "capability_identity_sha512",
                hashlib.sha512(b"stale capability").hexdigest(),
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle complete capability field substitution",
            "does not match the complete source capability",
            lambda document: document["result"]["integration"]["capability"].__setitem__(
                "network_id", 1
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle proof byte length substitution",
            "lifecycle proof byte length mismatch",
            lambda document: document["result"]["integration"].__setitem__(
                "proof_bytes", 1
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "zero lifecycle parent height",
            "parent_height must be a positive integer",
            lambda document: document["result"]["integration"][
                "state_binding"
            ].__setitem__("parent_height", 0),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle note anchor substitution",
            "note anchor does not match capability note_genesis_root",
            lambda document: document["result"]["integration"][
                "state_binding"
            ]["note_anchor"].__setitem__(0, 1),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle stablecoin root drift",
            "stablecoin_root_after does not match capability stablecoin genesis",
            lambda document: document["result"]["integration"][
                "state_binding"
            ]["stablecoin_root_after"].__setitem__(0, 1),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "one lifecycle stage proof digest substitution",
            "lifecycle stage proof digest mismatch",
            lambda document: document["result"]["integration"][
                "stage_results"
            ][0].__setitem__(
                "proof_sha512", hashlib.sha512(b"stage proof drift").hexdigest()
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "self asserted lifecycle command output digest",
            "lifecycle command output digest mismatch",
            lambda document: document["result"]["integration"][
                "stage_results"
            ][0].__setitem__(
                "output_sha512", hashlib.sha512(b"not executed output").hexdigest()
            ),
        )
        expect_release_document_rejected(
            "lifecycle_same_bytes_report",
            "lifecycle stage detached from positive check receipt",
            "not bound to its positive check receipt",
            lambda document: document["result"]["checks"][1].__setitem__(
                "output_sha512", hashlib.sha512(b"stale check output").hexdigest()
            ),
        )
        expect_release_document_rejected(
            "restart_reorg_fresh_node_report",
            "failed actual lifecycle integration stage",
            "stage_results[0].passed must equal true",
            lambda document: document["result"]["integration"][
                "stage_results"
            ][0].__setitem__("passed", False),
        )

        def failed_lifecycle_command_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            if len(command) == 1 and command[0].startswith("test-only:"):
                return 1, "synthetic actual lifecycle failure"
            return strict_artifact_command_runner(command, command_root)

        expect_rejected(
            "source-bound lifecycle command failure",
            "source-bound lifecycle command for lifecycle_same_bytes_report rejected",
            lambda: check_with_runner(failed_lifecycle_command_runner),
        )

        def stale_lifecycle_command_output_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            if len(command) == 1 and command[0].startswith("test-only:"):
                return 0, "stale substituted lifecycle receipt"
            return strict_artifact_command_runner(command, command_root)

        expect_rejected(
            "source-bound lifecycle command output substitution",
            "source-bound lifecycle command receipt for lifecycle_same_bytes_report is not valid",
            lambda: check_with_runner(stale_lifecycle_command_output_runner),
        )

        def mutated_lifecycle_source_state_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 1 and command[0].startswith("test-only:"):
                receipt = json.loads(output)
                receipt["state_binding"]["note_anchor"][0] = 1
                output = gate.canonical_json_bytes(receipt).decode("utf-8")
            return status, output

        expect_rejected(
            "executed lifecycle source note anchor substitution",
            "note anchor does not match capability note_genesis_root",
            lambda: check_with_runner(mutated_lifecycle_source_state_runner),
        )

        def mutated_lifecycle_source_capability_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            status, output = strict_artifact_command_runner(command, command_root)
            if len(command) == 1 and command[0].startswith("test-only:"):
                receipt = json.loads(output)
                receipt["capability"]["network_id"] = 1
                output = gate.canonical_json_bytes(receipt).decode("utf-8")
            return status, output

        expect_rejected(
            "executed lifecycle source capability substitution",
            "does not match the complete source capability",
            lambda: check_with_runner(mutated_lifecycle_source_capability_runner),
        )

        def failed_release_evidence_command_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            if len(command) == 1 and command[0].startswith("test-only-evidence:"):
                return 1, "synthetic executable evidence failure"
            return strict_artifact_command_runner(command, command_root)

        expect_rejected(
            "source-bound executable evidence command failure",
            "source-bound evidence command for",
            lambda: check_with_runner(failed_release_evidence_command_runner),
        )

        def stale_release_evidence_command_output_runner(
            command: list[str], command_root: Path
        ) -> tuple[int, str]:
            if len(command) == 1 and command[0].startswith("test-only-evidence:"):
                return 0, "stale substituted executable evidence receipt"
            return strict_artifact_command_runner(command, command_root)

        expect_rejected(
            "source-bound executable evidence output substitution",
            "source command output is not bound to its positive check receipt",
            lambda: check_with_runner(stale_release_evidence_command_output_runner),
        )

        for authority_path in sorted(gate.AUTHORITY_SOURCE_PATHS):
            authority_payload = (
                f"# committed release authority fixture: {authority_path}\n"
            ).encode("utf-8")
            authority_file = root / authority_path
            authority_file.parent.mkdir(parents=True, exist_ok=True)
            authority_file.write_bytes(authority_payload)
            authority_cycle = deepcopy(bundle)
            authority_entry = next(
                entry
                for entry in authority_cycle["evidence_files"]
                if entry["id"] == "canonical_statement_and_parser_source"
            )
            authority_entry.update(
                {
                    "bytes": len(authority_payload),
                    "path": authority_path,
                    "sha512": hashlib.sha512(authority_payload).hexdigest(),
                }
            )
            authority_cycle_profile = repin_bundle(root, authority_cycle, profile)
            expect_rejected(
                f"authority source cycle {authority_path}",
                "may not include a release authority source",
                lambda authority_cycle_profile=authority_cycle_profile: check(
                    selection, root, authority_cycle_profile
                ),
            )
        profile = repin_bundle(root, bundle, profile)

        substituted_consensus_source = b"not consensus dispatch source\n"
        substituted_consensus_path = root / "docs/not-consensus.txt"
        substituted_consensus_path.parent.mkdir(parents=True, exist_ok=True)
        substituted_consensus_path.write_bytes(substituted_consensus_source)
        consensus_source_substitution = deepcopy(bundle)
        consensus_source_entry = next(
            entry
            for entry in consensus_source_substitution["evidence_files"]
            if entry["id"] == "consensus_dispatch_source"
        )
        consensus_source_entry.update(
            {
                "bytes": len(substituted_consensus_source),
                "path": "docs/not-consensus.txt",
                "sha512": hashlib.sha512(substituted_consensus_source).hexdigest(),
            }
        )
        consensus_source_profile = repin_bundle(
            root, consensus_source_substitution, profile
        )
        expect_rejected(
            "consensus dispatch source path substitution",
            "source path must equal the source-owned canonical path",
            lambda: check(selection, root, consensus_source_profile),
        )
        profile = repin_bundle(root, bundle, profile)

        bundle_self_reference = deepcopy(bundle)
        bundle_self_entry = next(
            entry
            for entry in bundle_self_reference["evidence_files"]
            if entry["id"] == "canonical_statement_and_parser_source"
        )
        bundle_self_entry.update(
            {
                "bytes": 1,
                "path": TEST_BUNDLE_PATH,
                "sha512": hashlib.sha512(b"x").hexdigest(),
            }
        )
        bundle_self_profile = repin_bundle(root, bundle_self_reference, profile)
        expect_rejected(
            "evidence bundle file self-reference",
            "may not include the evidence bundle itself",
            lambda: check(selection, root, bundle_self_profile),
        )
        profile = repin_bundle(root, bundle, profile)

        manifest_cycle = deepcopy(bundle)
        manifest_entry = next(
            entry
            for entry in manifest_cycle["evidence_files"]
            if entry["id"] == "successor_release_manifest"
        )
        manifest_path = root / manifest_entry["path"]
        original_manifest = manifest_path.read_bytes()
        cycle_digest = hashlib.sha512(b"bundle cycle sentinel").hexdigest()
        cycle_manifest_payload = gate.canonical_json_bytes(
            {
                "evidence_bundle_path": TEST_BUNDLE_PATH,
                "evidence_bundle_sha512": cycle_digest,
                "schema": "hegemon.test.forbidden-bundle-self-reference.v1",
            }
        )
        manifest_path.write_bytes(cycle_manifest_payload)
        manifest_entry.update(
            {
                "bytes": len(cycle_manifest_payload),
                "sha512": hashlib.sha512(cycle_manifest_payload).hexdigest(),
            }
        )
        manifest_cycle_profile = replace(
            profile,
            evidence_bundle_sha512=cycle_digest,
        )
        expect_rejected(
            "manifest to evidence bundle cycle",
            "may not reference its evidence bundle",
            lambda: gate.validate_evidence_bundle(
                manifest_cycle,
                root,
                manifest_cycle_profile,
                artifact_command_runner=strict_artifact_command_runner,
            ),
        )
        manifest_path.write_bytes(original_manifest)

        authority_manifest_cycle = deepcopy(bundle)
        authority_manifest_entry = next(
            entry
            for entry in authority_manifest_cycle["evidence_files"]
            if entry["id"] == "successor_release_manifest"
        )
        authority_manifest_path = root / authority_manifest_entry["path"]
        authority_manifest_payload = gate.canonical_json_bytes(
            {
                "schema": "hegemon.test.forbidden-authority-reference.v1",
                "source_path": gate.SOURCE_REGISTRY_RELATIVE_PATH,
            }
        )
        authority_manifest_path.write_bytes(authority_manifest_payload)
        authority_manifest_entry.update(
            {
                "bytes": len(authority_manifest_payload),
                "sha512": hashlib.sha512(authority_manifest_payload).hexdigest(),
            }
        )
        expect_rejected(
            "manifest to source registry cycle",
            "release authority sources",
            lambda: gate.validate_evidence_bundle(
                authority_manifest_cycle,
                root,
                profile,
                artifact_command_runner=strict_artifact_command_runner,
            ),
        )
        authority_manifest_path.write_bytes(original_manifest)

        expect_rejected(
            "empty source registry",
            "absent from the source-owned authorized registry",
            lambda: check(selection, root, profile, registry={}),
        )

        identity_mismatch = deepcopy(selection)
        identity_mismatch["identity"]["statement_bytes"] += 1
        expect_rejected(
            "selection identity mismatch",
            "identity does not match",
            lambda: check(identity_mismatch, root, profile),
        )

        network_mismatch = deepcopy(selection)
        network_mismatch["identity"]["network_id"] += 1
        expect_rejected(
            "network identity mismatch",
            "identity does not match",
            lambda: check(network_mismatch, root, profile),
        )

        for name, invalid_network_id in (
            ("boolean", True),
            ("negative", -1),
            ("above-u32", 0x1_0000_0000),
        ):
            invalid_network = deepcopy(selection)
            invalid_network["identity"]["network_id"] = invalid_network_id
            expect_rejected(
                f"{name} network id",
                "must be an integer in 0..=4294967295",
                lambda invalid_network=invalid_network: check(
                    invalid_network, root, profile
                ),
            )

        program_pin_mismatch = deepcopy(selection)
        program_pin_mismatch["identity"]["verifier_program_sha512"] = hashlib.sha512(
            b"different verifier program"
        ).hexdigest()
        expect_rejected(
            "program pin identity mismatch",
            "identity does not match",
            lambda: check(program_pin_mismatch, root, profile),
        )

        relation_program_pin_mismatch = deepcopy(selection)
        relation_program_pin_mismatch["identity"]["relation_program_sha512"] = (
            hashlib.sha512(b"different exact V8 relation program").hexdigest()
        )
        expect_rejected(
            "relation-program frozen identity mismatch",
            "relation_digest_hex must equal the first 48 bytes",
            lambda: check(relation_program_pin_mismatch, root, profile),
        )

        relation_digest_mismatch = deepcopy(selection)
        relation_digest_mismatch["identity"]["relation_digest_hex"] = "01" * 48
        expect_rejected(
            "capability relation digest mismatch",
            "relation_digest_hex must equal the first 48 bytes",
            lambda: check(relation_digest_mismatch, root, profile),
        )

        oversized_activation = deepcopy(selection)
        oversized_activation["identity"]["activation_height"] = 1 << 63
        expect_rejected(
            "capability activation scalar overflow",
            "activation_height exceeds the V8 relation scalar range",
            lambda: check(oversized_activation, root, profile),
        )

        wrong_deactivation = deepcopy(selection)
        wrong_deactivation["identity"]["deactivation_height_exclusive"] += 1
        expect_rejected(
            "capability deactivation lifetime substitution",
            "deactivation_height_exclusive must equal activation_height + 4096",
            lambda: check(wrong_deactivation, root, profile),
        )

        short_activation_genesis = deepcopy(selection)
        short_activation_genesis["identity"]["activation_genesis_hash"] = "01" * 31
        expect_rejected(
            "capability activation genesis truncation",
            "activation_genesis_hash must be exactly 32 bytes",
            lambda: check(short_activation_genesis, root, profile),
        )

        mismatched_action_cap = deepcopy(selection)
        mismatched_action_cap["identity"]["max_proof_actions_per_block"] = 511
        expect_rejected(
            "capability action cap substitution",
            "max_proof_actions_per_block must equal max_proofs_per_block",
            lambda: check(mismatched_action_cap, root, profile),
        )

        short_stablecoin_root = deepcopy(selection)
        short_stablecoin_root["identity"]["stablecoin_genesis_root"] = [1] * 6
        expect_rejected(
            "capability stablecoin root truncation",
            "must be an array of exactly 7 canonical field limbs",
            lambda: check(short_stablecoin_root, root, profile),
        )

        noncanonical_note_root = deepcopy(selection)
        noncanonical_note_root["identity"]["note_genesis_root"][0] = (
            gate.GOLDILOCKS_MODULUS
        )
        expect_rejected(
            "capability noncanonical note root",
            "must be a canonical Goldilocks field limb",
            lambda: check(noncanonical_note_root, root, profile),
        )

        substituted_note_root = deepcopy(selection)
        substituted_note_root["identity"]["note_genesis_root"][0] ^= 1
        expect_rejected(
            "capability nonempty note genesis substitution",
            "identity does not match the frozen V8/SMZ9 profile",
            lambda: check(substituted_note_root, root, profile),
        )

        wrong_chain_length = deepcopy(selection)
        wrong_chain_length["identity"]["chain_id_hex"] = "01"
        expect_rejected(
            "chain id digest-width mismatch",
            "to match consensus_binding_digest_bytes",
            lambda: check(wrong_chain_length, root, profile),
        )

        zero_transaction_digest_width = deepcopy(selection)
        zero_transaction_digest_width["identity"]["transaction_digest_bytes"] = 0
        expect_rejected(
            "zero transaction digest width",
            "must be a positive integer",
            lambda: check(zero_transaction_digest_width, root, profile),
        )

        wrong_stablecoin_width = deepcopy(selection)
        wrong_stablecoin_width["identity"]["stablecoin_policy_hash_bytes"] = 56
        expect_rejected(
            "stablecoin policy width identity mutation",
            "identity does not match",
            lambda: check(wrong_stablecoin_width, root, profile),
        )

        wrong_oracle_width = deepcopy(selection)
        wrong_oracle_width["identity"]["stablecoin_oracle_commitment_bytes"] = 56
        expect_rejected(
            "stablecoin oracle width identity mutation",
            "identity does not match",
            lambda: check(wrong_oracle_width, root, profile),
        )

        wrong_attestation_width = deepcopy(selection)
        wrong_attestation_width["identity"][
            "stablecoin_attestation_commitment_bytes"
        ] = 56
        expect_rejected(
            "stablecoin attestation width identity mutation",
            "identity does not match",
            lambda: check(wrong_attestation_width, root, profile),
        )

        zero_stablecoin_width = deepcopy(selection)
        zero_stablecoin_width["identity"]["stablecoin_policy_hash_bytes"] = 0
        expect_rejected(
            "zero stablecoin policy width",
            "must be a positive integer",
            lambda: check(zero_stablecoin_width, root, profile),
        )

        truncated_transcript_width = deepcopy(selection)
        truncated_transcript_width["identity"]["transcript_digest_bytes"] = 48
        expect_rejected(
            "truncated transcript digest width",
            "must equal full SHA-512 output width 64",
            lambda: check(truncated_transcript_width, root, profile),
        )

        zero_genesis = deepcopy(selection)
        zero_genesis["identity"]["genesis_id_hex"] = (
            "00" * zero_genesis["identity"]["consensus_binding_digest_bytes"]
        )
        expect_rejected(
            "all-zero genesis id",
            "must not be the all-zero",
            lambda: check(zero_genesis, root, profile),
        )

        sha256_identity_pin = deepcopy(selection)
        sha256_identity_pin["identity"]["relation_program_sha512"] = hashlib.sha256(
            b"relation program"
        ).hexdigest()
        expect_rejected(
            "identity SHA-256-as-SHA-512 confusion",
            "exactly 128 lowercase SHA-512",
            lambda: check(sha256_identity_pin, root, profile),
        )

        identity_algorithm_field = deepcopy(selection)
        identity_algorithm_field["identity"]["relation_program_sha256"] = hashlib.sha256(
            b"relation program"
        ).hexdigest()
        expect_rejected(
            "identity digest algorithm field confusion",
            "keys mismatch",
            lambda: check(identity_algorithm_field, root, profile),
        )

        malformed_inner_magic = deepcopy(selection)
        malformed_inner_magic["identity"]["inner_proof_wire_magic_hex"] = "not-hex"
        expect_rejected(
            "malformed inner proof wire identity",
            "must be 1..32 bytes of lowercase hexadecimal",
            lambda: check(malformed_inner_magic, root, profile),
        )

        zero_epoch_cap = deepcopy(selection)
        zero_epoch_cap["identity"]["security_epoch_max_proofs"] = 0
        expect_rejected(
            "zero security epoch proof cap",
            "must be a positive integer",
            lambda: check(zero_epoch_cap, root, profile),
        )

        zero_block_cap = deepcopy(selection)
        zero_block_cap["identity"]["max_proofs_per_block"] = 0
        expect_rejected(
            "zero per-block proof cap",
            "must be a positive integer",
            lambda: check(zero_block_cap, root, profile),
        )

        inverted_consensus_caps = deepcopy(selection)
        inverted_consensus_caps["identity"]["security_epoch_max_proofs"] = 99
        expect_rejected(
            "inverted consensus proof caps",
            "must be at least max_proofs_per_block",
            lambda: check(inverted_consensus_caps, root, profile),
        )

        stale_inline_only_block_quotient = deepcopy(selection)
        stale_inline_only_block_quotient["identity"]["max_proofs_per_block"] = 522
        expect_rejected(
            "stale inline-only block quotient",
            "must equal the shared consensus proof-bearing-action cap 512",
            lambda: check(stale_inline_only_block_quotient, root, profile),
        )

        stale_inline_only_epoch = deepcopy(selection)
        stale_inline_only_epoch["identity"]["security_epoch_max_proofs"] = 2_138_112
        expect_rejected(
            "stale inline-only security epoch",
            "must equal 512 * 4096 = 2097152",
            lambda: check(stale_inline_only_epoch, root, profile),
        )

        inline_route_cap_drift = deepcopy(selection)
        inline_route_cap_drift["identity"]["max_inline_route_args_bytes"] -= 1
        expect_rejected(
            "inline route and envelope cap drift",
            "must equal max_outer_envelope_bytes + 4",
            lambda: check(inline_route_cap_drift, root, profile),
        )

        pending_action_cap_drift = deepcopy(selection)
        pending_action_cap_drift["identity"]["max_v8_pending_action_bytes"] -= 1
        expect_rejected(
            "V8 PendingAction cap drift",
            "must equal max_inline_route_args_bytes + 225",
            lambda: check(pending_action_cap_drift, root, profile),
        )

        bundle_identity = deepcopy(bundle)
        bundle_identity["identity"]["statement_bytes"] += 1
        bundle_identity_profile = repin_bundle(root, bundle_identity, profile)
        expect_rejected(
            "bundle identity mismatch",
            "identity does not match",
            lambda: check(selection, root, bundle_identity_profile),
        )
        profile = repin_bundle(root, bundle, profile)

        missing = deepcopy(bundle)
        missing["evidence_files"].pop()
        missing_profile = repin_bundle(root, missing, profile)
        expect_rejected(
            "missing evidence",
            "evidence id set mismatch",
            lambda: check(selection, root, missing_profile),
        )

        extra = deepcopy(bundle)
        extra["evidence_files"].append(
            {
                "bytes": 1,
                "id": "zz_extra_authority",
                "kind": "certificate",
                "path": "evidence/extra.bin",
                "sha512": hashlib.sha512(b"x").hexdigest(),
            }
        )
        (root / "evidence").mkdir(exist_ok=True)
        (root / "evidence/extra.bin").write_bytes(b"x")
        extra_profile = repin_bundle(root, extra, profile)
        expect_rejected(
            "extra evidence",
            "evidence id set mismatch",
            lambda: check(selection, root, extra_profile),
        )

        traversal = deepcopy(bundle)
        traversal["evidence_files"][0]["path"] = "../outside.bin"
        traversal_profile = repin_bundle(root, traversal, profile)
        expect_rejected(
            "path traversal",
            "must stay inside the repository",
            lambda: check(selection, root, traversal_profile),
        )

        symlinked = deepcopy(bundle)
        target = root / "symlink-target.bin"
        target_payload = b"unique symlink target"
        target.write_bytes(target_payload)
        symlink = root / "evidence/symlink.bin"
        symlink.symlink_to(target)
        next(
            entry
            for entry in symlinked["evidence_files"]
            if entry["id"] == "complete_zero_knowledge_certificate"
        ).update(
            {
                "path": "evidence/symlink.bin",
                "bytes": len(target_payload),
                "sha512": hashlib.sha512(target_payload).hexdigest(),
            }
        )
        symlink_profile = repin_bundle(root, symlinked, profile)
        expect_rejected(
            "symlink evidence",
            "symlink",
            lambda: check(selection, root, symlink_profile),
        )

        nonregular = deepcopy(bundle)
        directory_path = root / "evidence/not-a-file"
        directory_path.mkdir()
        next(
            entry
            for entry in nonregular["evidence_files"]
            if entry["id"] == "complete_zero_knowledge_certificate"
        ).update(
            {
                "path": "evidence/not-a-file",
                "bytes": 1,
                "sha512": hashlib.sha512(b"x").hexdigest(),
            }
        )
        nonregular_profile = repin_bundle(root, nonregular, profile)
        expect_rejected(
            "nonregular evidence",
            "not a regular file",
            lambda: check(selection, root, nonregular_profile),
        )

        profile = repin_bundle(root, bundle, profile)

        pinned_program_substitution = deepcopy(bundle)
        relation_entry = next(
            entry
            for entry in pinned_program_substitution["evidence_files"]
            if entry["id"] == "relation_program"
        )
        relation_path = root / relation_entry["path"]
        relation_original = relation_path.read_bytes()
        relation_substitute = relation_original + b"unreviewed substitute"
        relation_path.write_bytes(relation_substitute)
        relation_entry["bytes"] = len(relation_substitute)
        relation_entry["sha512"] = hashlib.sha512(relation_substitute).hexdigest()
        substituted_profile = repin_bundle(root, pinned_program_substitution, profile)
        expect_rejected(
            "pinned relation program substitution",
            "does not match exact identity pin",
            lambda: check(selection, root, substituted_profile),
        )
        relation_path.write_bytes(relation_original)
        profile = repin_bundle(root, bundle, profile)

        pinned_profile_manifest_substitution = deepcopy(bundle)
        profile_manifest_entry = next(
            entry
            for entry in pinned_profile_manifest_substitution["evidence_files"]
            if entry["id"] == "profile_manifest"
        )
        profile_manifest_path = root / profile_manifest_entry["path"]
        profile_manifest_original = profile_manifest_path.read_bytes()
        profile_manifest_substitute = profile_manifest_original + b"unreviewed profile drift"
        profile_manifest_path.write_bytes(profile_manifest_substitute)
        profile_manifest_entry["bytes"] = len(profile_manifest_substitute)
        profile_manifest_entry["sha512"] = hashlib.sha512(
            profile_manifest_substitute
        ).hexdigest()
        substituted_profile_manifest_profile = repin_bundle(
            root, pinned_profile_manifest_substitution, profile
        )
        expect_rejected(
            "pinned profile manifest substitution",
            "does not match exact identity pin",
            lambda: check(selection, root, substituted_profile_manifest_profile),
        )
        profile_manifest_path.write_bytes(profile_manifest_original)
        profile = repin_bundle(root, bundle, profile)

        stale_relation_pin_bundle = deepcopy(bundle)
        stale_relation_pin_entry = next(
            entry
            for entry in stale_relation_pin_bundle["evidence_files"]
            if entry["id"] == "profile_manifest"
        )
        stale_relation_pin_document = json.loads(
            profile_manifest_original.decode("utf-8")
        )
        stale_relation_pin_document["relation_manifest"]["sha512"] = hashlib.sha512(
            b"stale relation manifest"
        ).hexdigest()
        stale_relation_pin_payload = write_canonical(
            profile_manifest_path, stale_relation_pin_document
        )
        stale_relation_profile_digest = hashlib.sha512(
            stale_relation_pin_payload
        ).hexdigest()
        stale_relation_pin_entry.update(
            {
                "bytes": len(stale_relation_pin_payload),
                "sha512": stale_relation_profile_digest,
            }
        )
        stale_relation_identity = deepcopy(profile.identity)
        stale_relation_identity["profile_manifest_sha512"] = (
            stale_relation_profile_digest
        )
        stale_relation_pin_bundle["identity"] = deepcopy(stale_relation_identity)
        stale_relation_selection = deepcopy(selection)
        stale_relation_selection["identity"] = deepcopy(stale_relation_identity)
        stale_relation_profile = replace(
            profile, identity=deepcopy(stale_relation_identity)
        )
        stale_relation_profile = repin_bundle(
            root, stale_relation_pin_bundle, stale_relation_profile
        )
        expect_rejected(
            "profile stale relation manifest pin",
            "profile manifest relation SHA-512 does not match recomputed manifest",
            lambda: check(
                stale_relation_selection, root, stale_relation_profile
            ),
        )
        profile_manifest_path.write_bytes(profile_manifest_original)
        profile = repin_bundle(root, bundle, profile)

        pinned_crypto_role_substitution = deepcopy(bundle)
        crypto_role_entry = next(
            entry
            for entry in pinned_crypto_role_substitution["evidence_files"]
            if entry["id"] == "cryptographic_role_manifest"
        )
        crypto_role_path = root / crypto_role_entry["path"]
        crypto_role_original = crypto_role_path.read_bytes()
        crypto_role_substitute = crypto_role_original + b"unreviewed primitive-role drift"
        crypto_role_path.write_bytes(crypto_role_substitute)
        crypto_role_entry["bytes"] = len(crypto_role_substitute)
        crypto_role_entry["sha512"] = hashlib.sha512(crypto_role_substitute).hexdigest()
        substituted_crypto_role_profile = repin_bundle(
            root, pinned_crypto_role_substitution, profile
        )
        expect_rejected(
            "pinned cryptographic role manifest substitution",
            "does not match exact identity pin",
            lambda: check(selection, root, substituted_crypto_role_profile),
        )
        crypto_role_path.write_bytes(crypto_role_original)
        profile = repin_bundle(root, bundle, profile)

        tiny_cap = replace(profile, max_evidence_file_bytes=1)
        expect_rejected(
            "oversize evidence",
            "exceeds 1 bytes",
            lambda: check(selection, root, tiny_cap),
        )

        mutated_path = root / bundle["evidence_files"][0]["path"]
        original = mutated_path.read_bytes()
        mutated_path.write_bytes(original + b"mutation")
        expect_rejected(
            "artifact mutation",
            "byte length mismatch",
            lambda: check(selection, root, profile),
        )
        mutated_path.write_bytes(original)

        sha256_confusion = deepcopy(bundle)
        payload = (root / sha256_confusion["evidence_files"][0]["path"]).read_bytes()
        sha256_confusion["evidence_files"][0]["sha512"] = hashlib.sha256(payload).hexdigest()
        sha256_profile = repin_bundle(root, sha256_confusion, profile)
        expect_rejected(
            "SHA-256-as-SHA-512 confusion",
            "exactly 128 lowercase SHA-512",
            lambda: check(selection, root, sha256_profile),
        )

        algorithm_field = deepcopy(bundle)
        algorithm_field["evidence_files"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
        algorithm_profile = repin_bundle(root, algorithm_field, profile)
        expect_rejected(
            "digest algorithm field confusion",
            "keys mismatch",
            lambda: check(selection, root, algorithm_profile),
        )

        wrong_bundle_digest = replace(
            profile, evidence_bundle_sha512=hashlib.sha256(gate.canonical_json_bytes(bundle)).hexdigest()
        )
        expect_rejected(
            "bundle digest algorithm confusion",
            "exactly 128 lowercase SHA-512",
            lambda: check(selection, root, wrong_bundle_digest),
        )

        trailing_payload = gate.canonical_json_bytes(bundle) + b" "
        (root / TEST_BUNDLE_PATH).write_bytes(trailing_payload)
        trailing_profile = replace(
            profile, evidence_bundle_sha512=hashlib.sha512(trailing_payload).hexdigest()
        )
        expect_rejected(
            "bundle trailing byte",
            "not exact canonical JSON or contains trailing bytes",
            lambda: check(selection, root, trailing_profile),
        )
        profile = repin_bundle(root, bundle, profile)

        path_mismatch = deepcopy(selection)
        path_mismatch["evidence_bundle_path"] = "authority/other.json"
        expect_rejected(
            "bundle path mismatch",
            "path does not match",
            lambda: check(path_mismatch, root, profile),
        )

        extra_selection_key = deepcopy(selection)
        extra_selection_key["production_authorized"] = True
        expect_rejected(
            "boolean authority injection",
            "keys mismatch",
            lambda: check(extra_selection_key, root, profile),
        )

        missing_selection_key = deepcopy(selection)
        del missing_selection_key["identity"]
        expect_rejected(
            "missing selection key",
            "keys mismatch",
            lambda: check(missing_selection_key, root, profile),
        )

        selection_path = root / "selection.json"
        selection_payload = write_canonical(selection_path, selection)
        selection_path.write_bytes(selection_payload + b"\n")
        expect_rejected(
            "selection trailing byte",
            "not exact canonical JSON or contains trailing bytes",
            lambda: gate.check_selection_file(
                selection_path,
                root,
                require_authorized=True,
                registry={TEST_PROFILE_ID: profile},
            ),
        )

    gate.SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS.clear()
    gate.SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS.clear()
    gate.SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS.clear()
    print(
        "Transaction-proof successor authorization fixtures: artifact-v5 source "
        "inventory, cross-binary verifier provenance, and canonical relation bytes "
        "validated before exact Rust artifact and deployed-security command seams; "
        "executable evidence and real lifecycle commands remain source-unbound, no "
        "synthetic proof is production evidence, and the checked-in registry remains empty"
    )


if __name__ == "__main__":
    main()
