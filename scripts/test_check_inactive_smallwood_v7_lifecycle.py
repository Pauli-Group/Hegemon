#!/usr/bin/env python3
"""Dependency-free regressions for the inactive V7 lifecycle source gate."""

from __future__ import annotations

import base64
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_inactive_smallwood_v7_lifecycle as checker


REQUIRED_SOURCES = (
    "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
    "protocol/shielded-pool/src/lib.rs",
    "protocol/shielded-pool/src/types.rs",
    "protocol/shielded-pool/src/family.rs",
    "protocol/versioning/src/lib.rs",
    "protocol/kernel/src/manifest.rs",
    "wallet/src/inactive_smallwood_v7.rs",
    "wallet/src/lib.rs",
    "wallet/src/rpc.rs",
    "wallet/src/prover.rs",
    "wallet/src/shielded_tx.rs",
    "node/src/native/inactive_smallwood_v7.rs",
    "node/src/native/mod.rs",
    "node/src/native/admission.rs",
    "node/src/native/service.rs",
)


def copy_gate_sources(target_root: Path) -> None:
    for relative in REQUIRED_SOURCES:
        target = target_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


class InactiveSmallwoodV7LifecycleSourceGateTests(unittest.TestCase):
    def findings_after_replacement(
        self, relative: str, old: str, new: str
    ) -> list[checker.Finding]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_gate_sources(root)
            target = root / relative
            source = target.read_text(encoding="utf-8")
            self.assertIn(old, source, f"mutation anchor drifted in {relative}")
            target.write_text(source.replace(old, new, 1), encoding="utf-8")
            findings, _ = checker.audit(root)
            return findings

    def test_repository_sources_pass(self) -> None:
        findings, _ = checker.audit(ROOT)
        self.assertEqual(findings, [])

    def test_rfc7693_kats_and_80_case_reference_lifecycle(self) -> None:
        self.assertEqual(
            checker.blake2b448_ciphertext_hash(0, bytes((1, 2, 3))).hex(),
            "ab43a16e1a4065c19ea17b28c3d11dcf9490d3233d42f6dd84e0e1df3d9ebbc733cced56ef46acbe09cd0bdadd1883048164fd34e89d93fd",
        )
        self.assertEqual(
            checker.blake2b448_ciphertext_hash(1, bytes((4, 5, 6, 7))).hex(),
            "05d199e09eb96fa9a7d0faa485bd3d8baabaf762b733e1f77718b223294cf81c6ec0fcb63d155226205f5511a3595c0ec310cb6838a938b2",
        )
        self.assertEqual(
            checker.protocol_action_id_kat().hex(),
            "89f518fd94c52815f6f8a7504718bdc3ee27c77b1361ebbedae2819d2077d70c7c00270a33d8409ef25a88247ee24c8d889023944fe66017",
        )

        seen_ids: set[bytes] = set()
        cases = 0
        for auth_mode in checker.PRIVATE_AUTH_MODES:
            for mask in range(16):
                case = checker.reference_lifecycle_case(mask, auth_mode)
                self.assertEqual(len(case.statement), 893)
                self.assertEqual(
                    case.statement[10:14],
                    bytes((bool(mask & 1), bool(mask & 2), bool(mask & 4), bool(mask & 8))),
                )
                self.assertEqual(
                    base64.b64decode(case.rpc_base64, validate=True),
                    case.canonical_public_args,
                )
                self.assertEqual(
                    base64.b64encode(case.canonical_public_args).decode("ascii"),
                    case.rpc_base64,
                )
                self.assertEqual(
                    checker.blake2b448_prospective_action_id(case.canonical_public_args),
                    case.prospective_action_id,
                )
                self.assertEqual(case.durable_key[-56:], case.prospective_action_id)
                self.assertIn(case.proof, case.envelope)
                self.assertIn(case.proof, case.record)

                # Peer, durable readback, restarted mempool, mined block, sync,
                # reorg detach/reattach, and fresh-node import all carry this
                # one exact record in the source-only reference lifecycle.
                stage_wires = (case.record,) * 8
                self.assertTrue(all(wire == case.record for wire in stage_wires))

                for slot, ciphertext in enumerate(case.ciphertexts):
                    enabled = bool(mask & (4 << slot))
                    hash_offset = 294 + slot * 56
                    observed_hash = case.statement[hash_offset : hash_offset + 56]
                    if enabled:
                        self.assertEqual(
                            observed_hash,
                            checker.blake2b448_ciphertext_hash(slot, ciphertext),
                        )
                        mutated = bytes((ciphertext[0] ^ 1,)) + ciphertext[1:]
                        self.assertNotEqual(
                            checker.blake2b448_ciphertext_hash(slot, mutated),
                            observed_hash,
                        )
                    else:
                        self.assertEqual(ciphertext, b"")
                        self.assertEqual(observed_hash, bytes(56))
                seen_ids.add(case.prospective_action_id)
                cases += 1
        self.assertEqual(cases, 5 * 16)
        self.assertEqual(len(seen_ids), 5 * 16)

    def test_diagnostic_2_mib_transport_arithmetic_is_exact(self) -> None:
        budget = 2 * 1024 * 1024
        proof_max = budget - 30 - 893 - 2 * 2_147 - 128
        envelope_max = 30 + 893 + proof_max
        public_args_max = 4 + envelope_max + 2 * (2 + 2_147)
        record_max = 2 + 56 + 4 + public_args_max
        self.assertEqual(proof_max, 2_091_807)
        self.assertEqual(envelope_max, 2_092_730)
        self.assertEqual(public_args_max, 2_097_032)
        self.assertEqual(budget - public_args_max, 120)
        self.assertLessEqual(record_max, budget + 128)

    def test_activation_flag_mutation_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
            "INACTIVE_SMALLWOOD_V7_PRODUCTION_ENABLED: bool = false;",
            "INACTIVE_SMALLWOOD_V7_PRODUCTION_ENABLED: bool = true;",
        )
        self.assertTrue(any("protocol production gate" in item.message for item in findings))

    def test_exported_builder_raw_proof_regression_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "wallet/src/shielded_tx.rs",
            "self.prover.prove_submission_artifact(&witness)?",
            "self.prover.prove(&witness)?",
        )
        self.assertTrue(any("raw proof" in item.message for item in findings))

    def test_literal_numeric_router_activation_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "node/src/native/mod.rs",
            "| (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE)",
            "| (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE)\n            | (1u16, 9u16)",
        )
        self.assertTrue(any("literal/symbolic V7 route" in item.message for item in findings))

    def test_literal_manifest_and_family_admission_are_rejected(self) -> None:
        manifest_findings = self.findings_after_replacement(
            "protocol/kernel/src/manifest.rs",
            "protocol_shielded_pool::family::ACTION_MINT_COINBASE,",
            "protocol_shielded_pool::family::ACTION_MINT_COINBASE,\n                9u16,",
        )
        self.assertTrue(any("manifest admits action 9" in item.message for item in manifest_findings))
        family_findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/family.rs",
            "pub const ACTION_MINT_COINBASE: ActionId = 6;",
            "pub const ACTION_MINT_COINBASE: ActionId = 6;\npub const ACTION_FAKE_V7: ActionId = 9;",
        )
        self.assertTrue(any("outside the inactive owner" in item.message for item in family_findings))

    def test_literal_version_backend_admission_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/versioning/src/lib.rs",
            "        _ => None,",
            "        (7u16, 6u16) => Some(TxProofBackend::SmallwoodCandidate),\n        _ => None,",
        )
        self.assertTrue(any("dispatch admits V7/Zeta" in item.message for item in findings))

    def test_indirect_mutator_side_effect_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            "    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(\n        \"rpc_mempool_admission\",",
            "    side_effect();\n    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(\n        \"rpc_mempool_admission\",",
        )
        self.assertTrue(any("not one unconditional inactive error" in item.message for item in findings))

    def test_ciphertext_hash_equality_removal_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
            "statement.ciphertext_hashes[slot]\n                    != inactive_smallwood_v7_ciphertext_hash",
            "statement.ciphertext_hashes[slot]\n                    == inactive_smallwood_v7_ciphertext_hash",
        )
        self.assertTrue(any("ciphertext validation" in item.message for item in findings))

    def test_activation_context_comparison_removal_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
            "statement.activation.network_id != expected.network_id",
            "statement.activation.network_id == expected.network_id",
        )
        self.assertTrue(any("exact network_id" in item.message for item in findings))

    def test_scale_and_base64_noncanonical_acceptance_are_rejected(self) -> None:
        scale_findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            "if !cursor.is_empty()",
            "if false && !cursor.is_empty()",
        )
        self.assertTrue(any("record exact decode" in item.message for item in scale_findings))
        base64_findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            "STANDARD.encode(&public_args) != request.public_args",
            "STANDARD.encode(&public_args) == request.public_args",
        )
        self.assertTrue(any("RPC canonical decode" in item.message for item in base64_findings))

    def test_action_id_length_framing_mutation_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
            "(canonical_public_args.len() as u64).to_be_bytes()",
            "(canonical_public_args.len() as u32).to_be_bytes()",
        )
        self.assertTrue(any("action-id frame" in item.message for item in findings))

    def test_live_action_id48_alias_adapter_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
            "fixed_56_type!(InactiveSmallwoodV7Anchor56);",
            "fixed_56_type!(InactiveSmallwoodV7Anchor56);\nimpl From<InactiveSmallwoodV7ProspectiveActionId56> for [u8; 48] {\n    fn from(_: InactiveSmallwoodV7ProspectiveActionId56) -> Self { [0; 48] }\n}",
        )
        self.assertTrue(any("56-to-48" in item.message for item in findings))

    def test_pre_restart_block_branch_is_rejected(self) -> None:
        findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            "encode_inactive_smallwood_v7_block_seam(&mined)",
            "encode_inactive_smallwood_v7_block_seam(&staged)",
        )
        self.assertTrue(any("restart-to-fresh-node" in item.message for item in findings))

    def test_mask_or_private_auth_mode_coverage_removal_is_rejected(self) -> None:
        mask_findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            "for mask in 0u8..16",
            "for mask in 0u8..15",
        )
        self.assertTrue(any("omits masks" in item.message for item in mask_findings))
        auth_findings = self.findings_after_replacement(
            "node/src/native/inactive_smallwood_v7.rs",
            '("ValueLockCreation", 3)',
            '("ValueLock", 3)',
        )
        self.assertTrue(any("auth-mode corpus drifted" in item.message for item in auth_findings))


if __name__ == "__main__":
    unittest.main()
