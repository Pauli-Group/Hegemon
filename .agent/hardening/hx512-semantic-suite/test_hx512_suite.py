#!/usr/bin/env python3
"""Dependency-free tests for the prospective HX512 source certificate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hx512_suite", HERE / "hx512_suite.py")
assert SPEC is not None and SPEC.loader is not None
hx = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hx
SPEC.loader.exec_module(hx)


class Hx512SuiteTests(unittest.TestCase):
    def test_frozen_source_pins(self) -> None:
        pins = hx.source_pins()
        self.assertTrue(pins["all_match"])
        self.assertIn(
            "protocol/kernel/src/stablecoin_manifest_authority_v2.rs",
            pins["frozen_source_sha512"],
        )
        self.assertIn(
            "protocol/kernel/check_stablecoin_manifest_authority_v2.py",
            pins["frozen_source_sha512"],
        )
        self.assertIn(
            "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py",
            pins["frozen_source_sha512"],
        )
        self.assertEqual(pins["source_contract"]["physical_hash_calls"], 83)
        self.assertEqual(pins["source_contract"]["accepted_mask_mode_pairs"], 33)

    def test_statement_layout_and_round_trip(self) -> None:
        self.assertEqual(hx.OFFSETS["end"], 1141)
        self.assertEqual(sum(item["bytes"] for item in hx.statement_layout()), 1141)
        for profile in hx.IDENTITIES:
            raw = hx.sample_statement(profile)
            decoded = hx.parse_statement(raw, profile)
            self.assertEqual(decoded["manifest_root"], bytes([0x54]) * 64)
            self.assertEqual(decoded["state_root"], bytes([0x55]) * 64)
            self.assertEqual(decoded["state_height"], (42).to_bytes(8, "big"))

    def test_statement_identity_mutations_reject(self) -> None:
        raw = bytearray(hx.sample_statement())
        for offset in (0, 8, 933, 941, 945, 946, 947, 949, 1013, 1077):
            mutated = bytearray(raw)
            mutated[offset] ^= 1
            with self.assertRaises(hx.Reject, msg=f"offset={offset}"):
                hx.parse_statement(bytes(mutated), "blake2b512_rfc")
        mutated = bytearray(raw)
        mutated[10] = 2
        with self.assertRaises(hx.Reject):
            hx.parse_statement(bytes(mutated), "blake2b512_rfc")
        with self.assertRaises(hx.Reject):
            hx.parse_statement(bytes(869), "blake2b512_rfc")

    def test_all_masks_and_all_modes(self) -> None:
        matrix = hx.activity_mode_matrix()
        self.assertEqual(len(matrix), 80)
        self.assertEqual(sum(row["accept"] for row in matrix), 33)
        self.assertEqual(sum(not row["accept"] for row in matrix), 47)
        self.assertEqual({row["mask"] for row in matrix}, set(range(16)))
        self.assertEqual(len({row["mode"] for row in matrix}), 5)

    def test_exact_core_frames(self) -> None:
        calls = hx.core_frame_schedule(hx.BLAKE_PROFILE)
        self.assertEqual(sum(call["calls"] for call in calls), 83)
        self.assertEqual(
            [(call["family"], call["calls"], call["maximum_frame_bytes"]) for call in calls],
            [
                ("note_commitment", 4, 256),
                ("nullifier", 2, 143),
                ("merkle_node", 64, 149),
                ("spend_key_lane_a", 2, 93),
                ("spend_key_lane_b", 2, 93),
                ("authorization_policy", 1, 499),
                ("authorization_lane_a", 2, 263),
                ("authorization_lane_b", 2, 263),
                ("intent", 1, 968),
                ("balance_tag", 1, 100),
                ("ciphertext_hash", 2, 2182),
            ],
        )

    def test_exact_profile_counts(self) -> None:
        blake = hx.profile_counts("blake2b512_rfc")
        split = hx.profile_counts("sha512_shake256_control")
        self.assertEqual(blake["core_blake2b512_compressions"], 205)
        self.assertEqual(blake["authority_blake2b512_compressions"], 8)
        self.assertEqual(blake["relation_blake2b512_compressions"], 213)
        self.assertEqual(split["sha512_compressions"], 37)
        self.assertEqual(split["core_shake256_permutations"], 171)
        self.assertEqual(split["authority_shake256_permutations"], 12)
        self.assertEqual(split["relation_shake256_permutations"], 183)

    def test_frozen_specialized_node_is_one_compression(self) -> None:
        schedule = hx.authority_schedule("blake2b512_rfc")["in_relation"]
        node = next(item for item in schedule if item["family"] == "manifest_node")
        self.assertEqual(node["raw_preimage_bytes"], 128)
        self.assertEqual(hx.blake_blocks(2 * 64), 1)
        self.assertFalse(
            hx.authority_schedule("blake2b512_rfc")[
                "alternate_generic_hx512_authority_frames_accepted"
            ]
        )

    def test_statement_and_witness_expansion(self) -> None:
        report = hx.build_report()
        self.assertEqual(report["statement"]["delta_vs_hx448c02"]["bytes"], 272)
        self.assertEqual(report["statement"]["seven_byte_limbs"], 163)
        self.assertEqual(report["statement"]["public_words_with_context"], 152)
        self.assertEqual(report["witness"]["bytes"], 11000)
        self.assertEqual(report["witness"]["delta_vs_hx448c02"]["bytes"], 1328)
        self.assertEqual(report["witness"]["delta_vs_hx448c02"]["words"], 166)
        self.assertEqual(report["witness"]["independent_512_bit_sources"]["total_bytes"], 512)

    def test_manifest_row_canonicality(self) -> None:
        row = hx.encode_manifest_row()
        self.assertEqual(len(row), 215)
        decoded = hx.parse_manifest_row(row)
        self.assertEqual(decoded["asset_id"], 1001)
        for offset in (72, 85, 214):
            bad = bytearray(row)
            bad[offset] = 2
            with self.assertRaises(hx.Reject):
                hx.parse_manifest_row(bytes(bad))
        bad = bytearray(row)
        bad[72] = 0
        with self.assertRaises(hx.Reject):
            hx.parse_manifest_row(bytes(bad))

    def test_manifest_order_duplicates_and_cap_reject(self) -> None:
        row = hx.encode_manifest_row()
        with self.assertRaises(hx.Reject):
            hx.manifest_root("blake2b512_rfc", [row, row])
        with self.assertRaises(hx.Reject):
            hx.manifest_root("blake2b512_rfc", [row] * 17)

    def test_manifest_and_state_mutations_change_roots(self) -> None:
        row = hx.encode_manifest_row()
        root = hx.manifest_root("blake2b512_rfc", [row])
        mutated = bytearray(row)
        mutated[100] ^= 1
        other = hx.manifest_root("blake2b512_rfc", [bytes(mutated)])
        self.assertNotEqual(root, other)
        self.assertNotEqual(hx.state_root("blake2b512_rfc", root, 42), hx.state_root("blake2b512_rfc", root, 43))
        self.assertNotEqual(
            hx.state_root("blake2b512_rfc", root, 42),
            hx.state_root("sha512_shake256_control", hx.manifest_root("sha512_shake256_control", [row]), 42),
        )

    def test_verifier_context_is_manifest_root_not_snapshot(self) -> None:
        row = hx.canonical_authority_row()
        manifest = hx.manifest_root("blake2b512_rfc", [row])
        height = 0x0102_0304_0506_0708
        snapshot = hx.state_root("blake2b512_rfc", manifest, height)
        context = hx.encode_verifier_context(manifest, height)
        self.assertEqual(context[:64], manifest)
        self.assertNotEqual(context[:64], snapshot)
        self.assertEqual(context[64:], height.to_bytes(8, "little"))
        self.assertEqual(
            hx.parse_verifier_context(context),
            {"manifest_root": manifest, "parent_height": height},
        )
        hx.require_verifier_context(context, manifest, height)
        with self.assertRaises(hx.Reject):
            hx.require_verifier_context(
                hx.encode_verifier_context(snapshot, height), manifest, height
            )
        with self.assertRaises(hx.Reject):
            hx.require_verifier_context(
                manifest + height.to_bytes(8, "big"), manifest, height
            )

    def test_policy_version_zero_is_canonical_and_bound(self) -> None:
        row_zero = hx.canonical_authority_row(policy_version=0)
        row_one = hx.canonical_authority_row(policy_version=1)
        self.assertEqual(hx.parse_manifest_row(row_zero)["policy_version"], 0)
        self.assertNotEqual(
            hx.stable_policy_hash("blake2b512_rfc", row_zero),
            hx.stable_policy_hash("blake2b512_rfc", row_one),
        )
        root = hx.manifest_root("blake2b512_rfc", [row_zero, row_one])
        self.assertEqual(len(root), 64)

    def test_policy_master_mode_schedule_and_negative_cases(self) -> None:
        schedule = hx.policy_master_mode_schedule()
        self.assertEqual(
            [row["mode"] for row in schedule], list(hx.AUTHORIZATION_MODES)
        )
        self.assertEqual(
            schedule[2]["auth_call_masters"],
            {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": "next",
                "slot1_lane_b": "next",
            },
        )
        zero = bytes(64)
        current = bytes([0x71]) * 64
        next_ = bytes([0x72]) * 64
        hx.require_policy_masters("single_key", zero, zero)
        hx.require_policy_masters("accumulator_init", zero, next_)
        hx.require_policy_masters("approval_step", current, current)
        hx.require_policy_masters("value_lock_creation", current, zero)
        hx.require_policy_masters("final_threshold_spend", current, zero)
        for mode, bad_current, bad_next in (
            ("single_key", current, zero),
            ("single_key", zero, next_),
            ("accumulator_init", current, next_),
            ("approval_step", current, next_),
            ("value_lock_creation", current, next_),
            ("final_threshold_spend", current, next_),
        ):
            with self.subTest(mode=mode):
                with self.assertRaises(hx.Reject):
                    hx.require_policy_masters(mode, bad_current, bad_next)

    def test_exact_policy_tuple(self) -> None:
        row = hx.encode_manifest_row()
        preimage = hx.stable_policy_tuple(row)
        self.assertEqual(len(preimage), 61)
        changed = bytearray(row)
        changed[0] ^= 1
        self.assertNotEqual(preimage, hx.stable_policy_tuple(bytes(changed)))

    def test_standard_kats(self) -> None:
        self.assertEqual(len(hx.kats()), 16)
        self.assertEqual(
            hx.kats()["authority_blake_manifest_root_cap16"],
            "0c6cbb840c5523b58c3aae93e08fe17f956c7b22f7c43d05ef7d10f6d1dcdd1e7c4556ae983ed506d510bc8f607d7d3a714db420c9943ad4c7a6e75dd7ea9939",
        )

    def test_source_static_r1cs_geometry(self) -> None:
        costs = hx.r1cs_costs()
        blake = costs["blake2b512_rfc"]
        split = costs["sha512_shake256_control"]
        self.assertEqual(blake["m_constraints_source_static"], 29_510_157)
        self.assertEqual(blake["delta_vs_frozen_hx448c02"], 9_052_930)
        self.assertEqual(blake["n_nonconstant_variables_upper_bound"], 29_607_861)
        self.assertLess(blake["n_nonconstant_variables_upper_bound"], 1 << 25)
        self.assertEqual(split["m_constraints_source_static"], 36_868_145)
        self.assertGreater(split["m_constraints_source_static"], 1 << 25)
        self.assertEqual(split["delta_vs_blake2b512_rfc"], 7_357_988)
        shared = costs["fresh_shared"]
        self.assertEqual(shared["manifest_and_state_non_bitness_rows"], 11_592)
        self.assertEqual(
            sum(shared["manifest_and_state_non_bitness_groups"].values()), 11_592
        )
        self.assertEqual(
            shared["manifest_and_state_non_bitness_groups"]
            ["manifest_transport_and_selected_row_canonicality"],
            186,
        )
        canonicality = shared[
            "manifest_transport_and_selected_row_canonicality_breakdown"
        ]
        self.assertEqual(canonicality["three_row_boolean_bytes_high_seven_zero"], 21)
        self.assertEqual(canonicality["absent_retired_at_zero"], 64)
        self.assertEqual(sum(canonicality.values()), 186)
        recomputation = shared[
            "selected_leaf_and_depth_four_root_recomputation_breakdown"
        ]
        self.assertEqual(
            recomputation["recomputed_root_equals_statement_manifest_root"], 512
        )
        self.assertEqual(sum(recomputation.values()), 5_696)
        context = shared["snapshot_and_verifier_context_equality_breakdown"]
        self.assertEqual(
            context[
                "statement_manifest_root_equals_verifier_context_manifest_root"
            ],
            512,
        )
        self.assertEqual(sum(context.values()), 2_176)
        policy_masters = shared["policy_master_constraint_breakdown"]
        self.assertEqual(policy_masters["approval_current_equals_next"], 512)
        self.assertEqual(
            policy_masters["selected_current_or_next_master_for_policy_call"],
            512,
        )
        self.assertEqual(sum(policy_masters.values()), 2_560)
        self.assertEqual(shared["policy_master_constraint_rows_delta"], 1_024)
        self.assertEqual(
            shared["policy_master_constraint_equations_per_bit"],
            [
                "s_single * current = 0",
                "s_single * next = 0",
                "s_init * (next-current) = selected-current",
                "(s_init+s_value_lock+s_final) * (current+next-selected) = 0",
                "s_approval * (current-next) = 0",
            ],
        )
        self.assertEqual(shared["policy_version_nonzero_rows"], 0)
        self.assertEqual(shared["manifest_authority_local_surface_rows"], 6_237)

    def test_theorem_only_ledger_fails_closed(self) -> None:
        ledger = hx.security_ledgers()["theorem_only"]
        self.assertIsNone(ledger["overall_advantage"])
        self.assertIsNone(ledger["adv_qro_inst"])
        self.assertFalse(ledger["strict_gt_128"])
        self.assertFalse(ledger["production_authorized"])

    def test_conditional_ledger_is_nonzero_and_strict(self) -> None:
        ledger = hx.security_ledgers()["conditional_hash_as_qro"]
        self.assertTrue(ledger["adv_qro_inst_is_nonzero"])
        self.assertTrue(ledger["known_semantic_slice_strict_gt_128"])
        self.assertGreater(ledger["known_semantic_slice_total"]["security_bits_display"], 128)
        for term in ledger["terms"].values():
            value = Fraction(int(term["numerator"]), int(term["denominator"]))
            self.assertGreater(value, 0)
            self.assertLess(value, Fraction(1, 1 << 128))
        self.assertIsNone(ledger["overall_advantage"])
        self.assertFalse(ledger["overall_strict_gt_128"])

    def test_bcs_lambda_is_separate_and_still_blocking(self) -> None:
        bcs = hx.security_ledgers()["bcs_cross_stack_blocker"]
        self.assertFalse(bcs["lambda512"]["strictly_below_2^-128"])
        self.assertFalse(bcs["lambda648"]["strictly_below_2^-128"])
        self.assertTrue(bcs["lambda656"]["strictly_below_2^-128"])
        self.assertTrue(bcs["actual_code_lengths_make_p_larger"])
        self.assertTrue(bcs["proof_salt_lambda_is_not_semantic_digest_width"])

    def test_all_fifteen_roles_are_explicit(self) -> None:
        roles = hx.role_ledger()
        self.assertEqual(len(roles), 15)
        self.assertEqual({row["id"] for row in roles}, set(hx.SECURITY_ROLES))
        self.assertTrue(all(not row["concrete_qrom_reduction_present"] for row in roles))

    def test_domains_are_unique_and_fresh(self) -> None:
        self.assertNotEqual(hx.BLAKE_PROFILE, hx.SPLIT_PROFILE)
        self.assertEqual(len(set(hx.CORE_ROLES)), len(hx.CORE_ROLES))
        self.assertNotIn(b"HX448C02", (hx.BLAKE_PROFILE, hx.SPLIT_PROFILE))
        self.assertNotEqual(hx.LANE_A, hx.LANE_B)

    def test_mutation_corpus_is_retained(self) -> None:
        corpus = hx.mutation_corpus()
        self.assertEqual(corpus["retained_mutations"], 56)
        self.assertEqual(len({case["name"] for case in corpus["cases"]}), 56)

    def test_production_and_proof_bytes_fail_closed(self) -> None:
        report = hx.build_report()
        self.assertIsNone(report["proof"]["bytes"])
        self.assertFalse(report["proof"]["complete_zero_knowledge"])
        self.assertFalse(report["proof"]["composed_pq128"])
        self.assertFalse(report["capabilities"]["production_authorized"])
        self.assertFalse(report["capabilities"]["exact_full_relation_compiled"])


if __name__ == "__main__":
    unittest.main()
