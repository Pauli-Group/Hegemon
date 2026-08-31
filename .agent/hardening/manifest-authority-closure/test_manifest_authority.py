#!/usr/bin/env python3
"""Unittest wrapper for the dependency-free manifest-authority reference."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "manifest_authority", HERE / "manifest_authority.py"
)
assert SPEC is not None and SPEC.loader is not None
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


class ManifestAuthorityTests(unittest.TestCase):
    def test_retained_artifacts_and_exhaustive_mutations(self) -> None:
        evidence = M.check()
        self.assertEqual(evidence["entry_bytes_exhaustively_mutated"], 183)
        self.assertEqual(
            evidence["fresh_v2_entry_bytes_exhaustively_mutated"], 199
        )
        self.assertEqual(
            evidence["fresh_v2_all_w64_entry_bytes_exhaustively_mutated"],
            215,
        )
        self.assertEqual(evidence["index_paths_verified"], 16)
        self.assertEqual(evidence["fresh_v2_all_w64_index_paths_verified"], 16)

    def test_exact_compression_and_width_deltas(self) -> None:
        report = M.cost_report()
        self.assertEqual(
            report["profiles"]["compat183-merkle-w56"]["hash_schedule"]
            ["total_relation_compressions"],
            8,
        )
        self.assertEqual(
            report["profiles"]["compat183-full-w56"]["hash_schedule"]
            ["total_relation_compressions"],
            25,
        )
        self.assertEqual(
            report["deltas"]["compat183_merkle_w64_minus_w56"]
            ["semantic_witness_bytes"],
            32,
        )
        self.assertEqual(
            report["deltas"]["compat183_merkle_w64_minus_w56"]["r1cs_rows"],
            1024,
        )
        self.assertEqual(
            report["profiles"]["fresh-v2-merkle-w56"]["hash_schedule"]
            ["total_relation_compressions"],
            7,
        )
        self.assertEqual(
            report["deltas"]["fresh_v2_merkle_w56_minus_compat183"]
            ["semantic_witness_bytes"],
            16,
        )
        self.assertEqual(
            report["deltas"]["fresh_v2_merkle_root_w64_minus_w56"]
            ["semantic_witness_bytes"],
            32,
        )
        self.assertEqual(
            report["deltas"]["fresh_v2_merkle_root_w64_minus_w56"]
            ["r1cs_rows"],
            1024,
        )
        self.assertEqual(
            report["profiles"]["fresh-v2-all-w64-merkle-w64"]
            ["semantic_witness_bytes"],
            475,
        )

    def test_parent_authentication_is_not_membership(self) -> None:
        entry = M.sample_entry()
        entries = (entry,)
        root = M.merkle_root(entries, 56)
        public = M.PublicAuthority(root, 50)
        witness = M.prove_merkle(entries, 0, 56)
        parent = M.ParentStateAuthority.from_state(root, 50, 56)
        M.verify_merkle_authority(
            M.binding_for(entry), public, witness, parent, 56
        )
        forged_parent = M.ParentStateAuthority(
            bytes([root[0] ^ 1]) + root[1:], 50, parent.snapshot
        )
        with self.assertRaises(M.Reject):
            M.verify_merkle_authority(
                M.binding_for(entry), public, witness, forged_parent, 56
            )

    def test_production_flags_fail_closed(self) -> None:
        ledger = M.capability_ledger()
        self.assertFalse(ledger["production_authorized"])
        self.assertFalse(ledger["security"]["concrete_blake2b_qrom_bridge"])
        self.assertFalse(ledger["security"]["w56_strict_pq128_candidate"])
        self.assertFalse(
            ledger["width_migration"]["fresh_oracle_constructor_authority"]
        )
        self.assertFalse(
            ledger["width_migration"]
            ["fresh_attestation_constructor_authority"]
        )
        self.assertEqual(
            ledger["width_migration"]
            ["w56_baseline_manifest_authority_root_bytes"],
            56,
        )
        self.assertEqual(
            ledger["width_migration"]
            ["minimum_surviving_manifest_authority_root_bytes"],
            64,
        )
        self.assertTrue(
            all(value is False for value in ledger["current_authority"].values())
        )


if __name__ == "__main__":
    unittest.main()
