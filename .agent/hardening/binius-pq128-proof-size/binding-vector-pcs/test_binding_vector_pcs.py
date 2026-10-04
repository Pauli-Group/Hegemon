#!/usr/bin/env python3
"""Adversarial tests for the isolated binding-vector PCS model."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("binding_vector_pcs.py")
SPEC = importlib.util.spec_from_file_location("binding_vector_pcs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pcs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pcs
SPEC.loader.exec_module(pcs)


class BindingVectorPcsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = pcs.toy_params()
        cls.context = pcs.shake512(b"HVBPCS/test/context/v1")[: pcs.PUBLIC_CONTEXT_BYTES]
        cls.source = pcs.deterministic_source(cls.params)
        cls.proof = pcs.prove(cls.source, cls.params, cls.context)
        if not pcs.verify(cls.proof, cls.params, cls.context):
            raise AssertionError("honest toy proof did not verify")

    def assert_tamper_rejects(self, offset: int) -> None:
        changed = bytearray(self.proof)
        changed[offset] ^= 1
        self.assertFalse(pcs.verify(bytes(changed), self.params, self.context))

    def test_real_e384_and_product_ring_negative_control(self) -> None:
        self.assertTrue(pcs.e384_cubic_is_irreducible())
        self.assertTrue(pcs.product_ring_zero_divisor_counterexample())
        a = pcs.E384(1, 2, 3)
        b = pcs.E384(7, 11, 13)
        c = pcs.E384(17, 19, 23)
        self.assertEqual((a * b) * c, a * (b * c))
        self.assertEqual(pcs.E384.from_bytes(a.to_bytes()), a)
        transcript = pcs.Transcript()
        challenge = transcript.challenge_e384(b"test")
        self.assertIsInstance(challenge, pcs.E384)
        self.assertEqual(len(challenge.to_bytes()), pcs.E384_BYTES)

    def test_strict_query_budget_and_frontier(self) -> None:
        self.assertEqual(pcs.strict_query_count(), 68)
        self.assertGreaterEqual(
            pcs.strict_query_count() * pcs.query_bits(pcs.LOG_INV_RATE),
            pcs.STRICT_CLASSICAL_BITS,
        )
        params = pcs.strict_params()
        self.assertEqual(params.frontier_nodes, 740)
        self.assertEqual(params.opened_symbol_bytes, 34_816)
        self.assertEqual(params.authentication_bytes, 47_360)
        self.assertEqual(params.vector_opening_bytes, 82_304)
        self.assertEqual(params.encoded_oracle_bytes, 64 * 1024 * 1024)

    def test_exact_no_go_and_compact_target_boundary(self) -> None:
        result = pcs.report()
        concrete = result["concrete_merkle_opening"]
        self.assertEqual(concrete["vector_opening_bytes"], 82_304)
        self.assertEqual(concrete["over_budget_bytes"], 44_988)
        self.assertTrue(concrete["exact_no_go"])
        self.assertFalse(concrete["hiding"])
        compact = result["compact_target"]
        self.assertEqual(compact["vector_target_bytes"], 8_832)
        self.assertEqual(compact["algebraic_zk_target_messages"], 593)
        self.assertEqual(compact["algebraic_zk_target_bytes"], 28_464)
        self.assertEqual(compact["total_target_bytes"], 37_296)
        self.assertEqual(compact["headroom_bytes"], 20)
        self.assertTrue(compact["fits_budget"])
        self.assertTrue(compact["target_only"])
        self.assertFalse(result["strict_admitted"])
        n15 = result["n15_fixed_32_lane_screen"]
        self.assertEqual(n15["frontier_nodes"], 808)
        self.assertEqual(n15["vector_opening_bytes"], 86_656)
        self.assertEqual(n15["over_budget_bytes"], 49_340)
        self.assertEqual(n15["encoded_oracle_bytes"], 128 * 1024 * 1024)
        self.assertTrue(n15["exact_no_go"])
        n15_opening = result["n15ish_concrete_opening"]
        self.assertEqual(n15_opening["vector_opening_bytes"], 86_656)
        self.assertEqual(n15_opening["frontier_bytes"], 51_712)
        self.assertEqual(n15_opening["over_budget_bytes"], 49_340)
        self.assertTrue(n15_opening["exact_no_go"])

    def test_exact_parser_roundtrip_and_trailing_or_truncated_rejection(self) -> None:
        parsed = pcs.MerkleVectorProof.parse(self.proof, self.params)
        self.assertEqual(parsed.serialize(self.params), self.proof)
        self.assertFalse(pcs.verify(self.proof + b"\x00", self.params, self.context))
        self.assertFalse(pcs.verify(self.proof[:-1], self.params, self.context))
        wrong_context = bytearray(self.context)
        wrong_context[0] ^= 1
        self.assertFalse(pcs.verify(self.proof, self.params, bytes(wrong_context)))
        with self.assertRaises(ValueError):
            pcs.MerkleVectorProof.parse(self.proof + b"\x00", self.params)
        with self.assertRaises(ValueError):
            pcs.MerkleVectorProof.parse(self.proof[:-1], self.params)

    def test_header_root_opened_symbol_and_frontier_tamper(self) -> None:
        self.assert_tamper_rejects(0)
        root_offset = pcs.HEADER_BYTES
        self.assert_tamper_rejects(root_offset)
        rows_offset = root_offset + pcs.DIGEST_BYTES
        self.assert_tamper_rejects(rows_offset)
        last_row_offset = rows_offset + self.params.opened_symbol_bytes - 1
        self.assert_tamper_rejects(last_row_offset)
        frontier_offset = rows_offset + self.params.opened_symbol_bytes
        self.assert_tamper_rejects(frontier_offset)
        self.assert_tamper_rejects(
            frontier_offset + self.params.authentication_bytes - 1
        )

    def test_header_profile_and_symbol_width_are_canonical(self) -> None:
        wrong_magic = bytearray(self.proof)
        wrong_magic[0] ^= 1
        with self.assertRaises(ValueError):
            pcs.MerkleVectorProof.parse(bytes(wrong_magic), self.params)
        wrong_width = bytearray(self.proof)
        # Header layout: magic(8), version(2), flags(2), profile(32), then
        # log_n/fold/rate/symbol_bytes at offsets 44..47.
        wrong_width[47] = pcs.B128_BYTES - 1
        with self.assertRaises(ValueError):
            pcs.MerkleVectorProof.parse(bytes(wrong_width), self.params)

    def test_masked_merkle_attempt_is_explicitly_not_hiding(self) -> None:
        attempt = pcs.masked_merkle_attempt(self.source, self.params, self.context)
        self.assertTrue(attempt.source_recoverable)
        self.assertEqual(
            attempt.wire_bytes,
            self.params.vector_opening_bytes + self.params.opened_symbol_bytes,
        )
        self.assertFalse(pcs.report()["masked_merkle_attempt"]["hiding"])
        self.assertTrue(pcs.report()["masked_merkle_attempt"]["exact_no_go"])

    def test_two_share_direct_and_hidden_openings(self) -> None:
        direct = pcs.prove_share_direct(self.source, self.params, self.context)
        hidden = pcs.prove_share_hidden(self.source, self.params, self.context)
        self.assertTrue(pcs.verify_share_direct(direct, self.params, self.context))
        self.assertTrue(pcs.verify_share_hidden(hidden, self.params, self.context))

        direct_parsed = pcs.ShareOpening.parse(direct, self.params)
        hidden_parsed = pcs.ShareOpening.parse(hidden, self.params)
        self.assertEqual(direct_parsed.flags, pcs.SHARE_DIRECT_FLAGS)
        self.assertEqual(hidden_parsed.flags, pcs.SHARE_HIDDEN_FLAGS)
        self.assertEqual(len(hidden_parsed.mask_rows), 0)
        self.assertEqual(len(hidden_parsed.mask_frontier), 0)
        recovered = pcs._share_recovered_rows(direct_parsed)
        self.assertEqual(len(recovered), self.params.query_count)
        self.assertTrue(all(len(row) == self.params.lanes for row in recovered))

        share_screen = pcs.report()["hash_only_share_screen"]
        self.assertEqual(share_screen["hidden_wire_bytes"], 86_720)
        self.assertEqual(share_screen["hidden_wire_over_budget_bytes"], 49_404)
        self.assertEqual(share_screen["direct_wire_bytes"], 173_248)
        self.assertFalse(share_screen["hidden_opening_binding_to_source"])
        self.assertTrue(share_screen["direct_binding_under_shake_assumption"])
        self.assertFalse(share_screen["direct_hiding"])
        self.assertTrue(share_screen["exact_no_go"])
        search = pcs.report()["hash_only_share_geometry_search"]
        best = search["best_hidden_share_profile"]
        self.assertEqual(search["profiles_screened"], 197)
        self.assertEqual(search["maximum_admitted_log_inv_rate"], 15)
        self.assertEqual(best["fold_variables"], 2)
        self.assertEqual(best["log_inv_rate"], 13)
        self.assertEqual(best["query_count"], 44)
        self.assertEqual(best["frontier_nodes"], 900)
        self.assertEqual(best["hidden_wire_bytes"], 60_608)
        self.assertEqual(best["encoded_oracle_bytes"], 4 * 1024**3)
        self.assertEqual(search["best_hidden_over_budget_bytes"], 23_292)
        self.assertTrue(search["exact_no_go_for_this_family"])
        self.assertFalse(search["binding_hiding_construction_exists"])
        lower = pcs.report()["hash_only_two_share_lower_bound"]
        self.assertEqual(lower["profiles_screened"], 197)
        self.assertEqual(lower["hidden_commitment_lower_bound"]["wire_bytes"], 60_544)
        self.assertEqual(lower["hidden_lower_bound_over_budget"], 23_228)
        self.assertEqual(lower["direct_binding_lower_bound"]["wire_bytes"], 63_104)
        self.assertEqual(lower["direct_lower_bound_over_budget"], 25_788)
        self.assertEqual(
            lower["optimistic_hidden_linkage_lower_bound"]["wire_bytes"], 115_328
        )
        self.assertEqual(lower["optimistic_linkage_over_budget"], 78_012)
        self.assertEqual(lower["implemented_two_root_hidden"]["wire_bytes"], 60_608)
        self.assertEqual(lower["implemented_two_root_direct"]["wire_bytes"], 121_024)
        self.assertTrue(lower["exact_dichotomy_no_binding_hiding"])
        self.assertTrue(lower["exact_byte_no_go_even_before_zk"])
        self.assertFalse(lower["strict_admitted"])

    def test_two_share_direct_wire_regions_tamper(self) -> None:
        direct = pcs.prove_share_direct(self.source, self.params, self.context)
        parsed = pcs.ShareOpening.parse(direct, self.params)
        root_offset = pcs.HEADER_BYTES
        self.assertFalse(
            pcs.verify_share_direct(
                direct[:root_offset] + bytes([direct[root_offset] ^ 1]) + direct[root_offset + 1 :],
                self.params,
                self.context,
            )
        )
        first_masked_row = root_offset + 2 * pcs.DIGEST_BYTES
        self.assertFalse(
            pcs.verify_share_direct(
                direct[:first_masked_row]
                + bytes([direct[first_masked_row] ^ 1])
                + direct[first_masked_row + 1 :],
                self.params,
                self.context,
            )
        )
        mask_rows_offset = first_masked_row + self.params.opened_symbol_bytes
        self.assertFalse(
            pcs.verify_share_direct(
                direct[:mask_rows_offset]
                + bytes([direct[mask_rows_offset] ^ 1])
                + direct[mask_rows_offset + 1 :],
                self.params,
                self.context,
            )
        )
        masked_frontier_offset = mask_rows_offset + self.params.opened_symbol_bytes
        self.assertFalse(
            pcs.verify_share_direct(
                direct[:masked_frontier_offset]
                + bytes([direct[masked_frontier_offset] ^ 1])
                + direct[masked_frontier_offset + 1 :],
                self.params,
                self.context,
            )
        )
        last_byte = len(direct) - 1
        self.assertFalse(
            pcs.verify_share_direct(
                direct[:last_byte] + bytes([direct[last_byte] ^ 1]),
                self.params,
                self.context,
            )
        )
        self.assertEqual(parsed.serialize(self.params), direct)

    def test_non_merkle_whole_digest_control_and_tamper(self) -> None:
        encoded = pcs.prove_whole_vector_full(
            self.source, self.params, self.context
        )
        self.assertTrue(
            pcs.verify_whole_vector_full(encoded, self.params, self.context)
        )
        parsed = pcs.WholeVectorCommitment.parse_full(encoded, self.params)
        self.assertEqual(parsed.serialize_full(self.params), encoded)
        digest_offset = pcs.HEADER_BYTES
        for offset in (
            digest_offset,
            digest_offset + pcs.DIGEST_BYTES,
            len(encoded) - 1,
        ):
            changed = bytearray(encoded)
            changed[offset] ^= 1
            self.assertFalse(
                pcs.verify_whole_vector_full(
                    bytes(changed), self.params, self.context
                )
            )
        self.assertFalse(
            pcs.verify_whole_vector_full(
                encoded + b"\x00", self.params, self.context
            )
        )
        screen = pcs.report()["non_merkle_hash_screen"]
        self.assertTrue(screen["transparent"])
        self.assertFalse(screen["partial_opening_verifiable"])
        self.assertEqual(screen["commitment_bytes"], 64)
        self.assertEqual(screen["full_vector_symbol_bytes"], 524_288)
        self.assertEqual(screen["full_opening_wire_bytes"], 524_448)
        self.assertEqual(screen["full_opening_over_budget_bytes"], 487_132)
        self.assertTrue(screen["exact_no_go"])
        self.assertFalse(screen["strict_admitted"])

    def test_simulator_target_is_source_free_but_not_admission(self) -> None:
        root = pcs.MerkleVectorProof.parse(self.proof, self.params).root
        simulator = pcs.simulate_algebraic_target(
            self.params,
            self.context,
            root,
            pcs.shake512(b"HVBPCS/test/simulator-seed/v1")[:32],
        )
        self.assertTrue(simulator.source_independent)
        self.assertTrue(simulator.programmable_rom)
        self.assertEqual(simulator.setup_bytes, 0)
        self.assertEqual(simulator.pairing_operations, 0)
        self.assertFalse(simulator.aggregation)
        self.assertEqual(simulator.wire_bytes, 593 * pcs.E384_BYTES)
        self.assertEqual(len(simulator.serialize()), simulator.wire_bytes)
        self.assertFalse(pcs.report()["strict_admitted"])

    def test_in_place_relation_commit_prove_verify_and_simulator(self) -> None:
        source = pcs.deterministic_relation_source(self.params, 0)
        self.assertTrue(pcs.relation_holds_coefficients(source, self.params))
        with self.assertRaises(ValueError):
            pcs.prove_in_place(self.source, self.params, self.context, b"x" * 32)
        coins = pcs.shake512(b"HVBPCS/test/in-place/coins/v1")[:32]
        encoded = pcs.prove_in_place(source, self.params, self.context, coins)
        self.assertTrue(pcs.verify_in_place(encoded, self.params, self.context))
        parsed = pcs.InPlaceZkProof.parse(encoded, self.params)
        self.assertEqual(
            pcs.in_place_commit(source, self.params, self.context, coins),
            parsed.root,
        )
        self.assertEqual(len(encoded), pcs.in_place_toy_wire_bytes(self.params))
        self.assertEqual(parsed.serialize(self.params), encoded)

        simulation = pcs.simulate_in_place(
            self.params,
            self.context,
            pcs.shake512(b"HVBPCS/test/in-place/simulator/v1")[:32],
        )
        self.assertTrue(simulation.source_independent)
        self.assertTrue(simulation.affine_fiber_sampler)
        self.assertFalse(simulation.complete_zk_theorem)
        self.assertFalse(simulation.qrom_composed)
        self.assertEqual(simulation.wire_bytes, len(simulation.encoded))
        self.assertTrue(
            pcs.verify_in_place(simulation.encoded, self.params, self.context)
        )

    def test_in_place_affine_witness_pair_and_relation_binding(self) -> None:
        source_a = pcs.deterministic_relation_source(self.params, 0)
        source_b = pcs.deterministic_relation_source(self.params, 1)
        coins = pcs.shake512(b"HVBPCS/test/in-place/relabel/v1")[:32]
        mask_a = pcs.in_place_mask_coefficients(self.params, coins)
        mask_b = pcs.relabel_in_place_mask(
            source_a, source_b, mask_a, self.params
        )
        self.assertTrue(pcs.relation_holds_coefficients(mask_b, self.params))
        self.assertEqual(
            pcs.in_place_apply_mask(source_a, mask_a, self.params),
            pcs.in_place_apply_mask(source_b, mask_b, self.params),
        )
        proof_a = pcs.prove_in_place_with_mask(
            source_a, mask_a, self.params, self.context
        )
        proof_b = pcs.prove_in_place_with_mask(
            source_b, mask_b, self.params, self.context
        )
        self.assertEqual(proof_a, proof_b)
        self.assertTrue(pcs.verify_in_place(proof_a, self.params, self.context))

        # Build a Merkle-valid opening of a source that violates the relation.
        # The Merkle check passes, but the E384 relation check must reject it.
        bad_source = list(source_a)
        bad_source[0] ^= 1
        columns = pcs._encode_source(bad_source, self.params)
        levels = pcs._merkle_levels(columns)
        root = levels[-1][0]
        queries, _ = pcs._in_place_queries(self.params, self.context, root)
        malformed_relation = pcs.InPlaceZkProof(
            pcs.E384.zero(),
            root,
            tuple(columns[index] for index in queries),
            pcs._compact_frontier(levels, queries, self.params),
        ).serialize(self.params)
        self.assertFalse(
            pcs.verify_in_place(malformed_relation, self.params, self.context)
        )

    def test_in_place_parser_and_every_wire_region_tamper(self) -> None:
        source = pcs.deterministic_relation_source(self.params, 0)
        encoded = pcs.prove_in_place(
            source,
            self.params,
            self.context,
            pcs.shake512(b"HVBPCS/test/in-place/tamper/v1")[:32],
        )
        parsed = pcs.InPlaceZkProof.parse(encoded, self.params)
        self.assertEqual(parsed.serialize(self.params), encoded)
        self.assertFalse(pcs.verify_in_place(encoded + b"\x00", self.params, self.context))
        self.assertFalse(pcs.verify_in_place(encoded[:-1], self.params, self.context))
        wrong_context = bytearray(self.context)
        wrong_context[0] ^= 1
        self.assertFalse(
            pcs.verify_in_place(encoded, self.params, bytes(wrong_context))
        )

        claim_offset = pcs.HEADER_BYTES
        root_offset = claim_offset + pcs.E384_BYTES
        rows_offset = root_offset + pcs.DIGEST_BYTES
        frontier_offset = rows_offset + self.params.opened_symbol_bytes
        for offset in (
            0,
            claim_offset,
            root_offset,
            rows_offset,
            frontier_offset,
            len(encoded) - 1,
        ):
            changed = bytearray(encoded)
            changed[offset] ^= 1
            self.assertFalse(
                pcs.verify_in_place(bytes(changed), self.params, self.context)
            )
        with self.assertRaises(ValueError):
            pcs.InPlaceZkProof.parse(encoded + b"\x00", self.params)
        with self.assertRaises(ValueError):
            pcs.InPlaceZkProof.parse(encoded[:-1], self.params)

    def test_full_m4_joint_mask_search_is_explicitly_non_strict(self) -> None:
        result = pcs.report()["full_m4_masked_production_search"]
        self.assertEqual(result["oracle_cap_bytes"], 28 * 1024**3)
        self.assertEqual(result["envelope_cap_bytes"], 512 * 1024)
        self.assertEqual(result["merkle_node_bytes"], 56)
        self.assertEqual(result["fiat_shamir_digest_bytes"], 64)
        self.assertEqual(result["mask_coordinate_copies"], 3)
        self.assertEqual(result["mask_share_dimensions"], 2)
        self.assertEqual(result["gamma_zero_event_bits"], 256)
        self.assertEqual(result["source_inventory"]["keccak_permutations"], 83)
        self.assertEqual(result["source_inventory"]["bitand_constraints"], 3_187_200)
        self.assertEqual(result["source_inventory"]["transport_b128_symbols"], 336)
        self.assertFalse(result["source_inventory"]["active_trace_symbols_frozen"])
        n15 = result["by_n"]["15"]["best"]
        self.assertEqual(n15["fold_variables"], 5)
        self.assertEqual(n15["log_inv_rate"], 13)
        self.assertEqual(n15["query_count"], 44)
        self.assertEqual(n15["frontier_nodes"], 768)
        self.assertEqual(n15["merkle_node_bytes"], 56)
        self.assertEqual(n15["mask_coordinate_copies"], 3)
        self.assertEqual(n15["mask_share_dimensions"], 2)
        self.assertEqual(n15["joint_query_row_bytes"], 135_168)
        self.assertEqual(n15["joint_vector_opening_bytes"], 178_296)
        self.assertEqual(n15["algebraic_claim_bytes"], 110_112)
        self.assertEqual(n15["raw_proof_bytes"], 288_408)
        self.assertEqual(n15["envelope_bytes"], 288_420)
        self.assertFalse(n15["fits_original_pcs_zk_budget"])
        self.assertTrue(n15["oracle_cap_admitted"])
        self.assertFalse(n15["nonlinear_cross_terms_priced"])
        self.assertTrue(n15["nonlinear_cross_terms_required"])
        n16 = result["by_n"]["16"]["best"]
        self.assertEqual(n16["fold_variables"], 5)
        self.assertEqual(n16["log_inv_rate"], 12)
        self.assertEqual(n16["query_count"], 47)
        self.assertEqual(n16["frontier_nodes"], 816)
        self.assertEqual(n16["joint_vector_opening_bytes"], 190_200)
        self.assertEqual(n16["algebraic_claim_bytes"], 208_416)
        self.assertEqual(n16["raw_proof_bytes"], 398_616)
        self.assertEqual(n16["envelope_bytes"], 398_628)
        self.assertFalse(n16["fits_original_pcs_zk_budget"])
        self.assertTrue(result["best_overall"]["envelope_bytes"] < 512 * 1024)
        self.assertFalse(result["full_m4_nonlinear_relation_theorem"])
        self.assertFalse(result["complete_zk_simulator_proved"])
        self.assertFalse(result["qrom_composed"])
        self.assertFalse(result["binding_hiding_construction_implemented"])
        self.assertFalse(result["binding_hiding_candidate_under_budget"])
        self.assertTrue(result["hypothetical_all_terminal_elision_still_over_budget"])
        self.assertEqual(
            result["hypothetical_all_terminal_target_elision"]["15"]["raw_proof_bytes"],
            72_472,
        )
        self.assertFalse(result["strict_admitted"])

    def test_m4_source_bound_inventory_and_gate_tamper_controls(self) -> None:
        statement = bytes(pcs.M4_PUBLIC_BYTES)
        intent = tuple(0 for _ in range(pcs.M4_DERIVED_INTENT_WORDS))
        private = tuple(0 for _ in range(pcs.M4_PRIVATE_WORDS))
        transcript = pcs.m4_source_bound_transcript(
            statement,
            intent,
            private,
            bitand_samples=((0xAA, 0x0F, 0x0A),),
            shift_samples=((0x10, 2, 0x40, "left"),),
        )
        self.assertEqual(len(transcript.private_transport_symbols), 336)
        self.assertTrue(transcript.bitand_samples_valid)
        self.assertTrue(transcript.shift_samples_valid)
        self.assertFalse(transcript.full_constraint_evaluation)
        self.assertFalse(transcript.relation_soundness_theorem)
        self.assertFalse(pcs.m4_bitand_holds(0xAA, 0x0F, 0x0B))
        masked_result = 0x0A ^ (0xAA & 0x03) ^ (0x55 & 0x0F) ^ (0x55 & 0x03)
        self.assertEqual(
            pcs.m4_masked_bitand_cross_terms(0xAA, 0x0F, 0x55, 0x03),
            (0xAA & 0x03, 0x55 & 0x0F, 0x55 & 0x03),
        )
        self.assertTrue(
            pcs.m4_masked_bitand_holds(0xAA, 0x0F, 0x0A, 0x55, 0x03, masked_result)
        )
        self.assertFalse(
            pcs.m4_masked_bitand_holds(0xAA, 0x0F, 0x0A, 0x55, 0x03, masked_result ^ 1)
        )
        self.assertFalse(pcs.m4_shift_holds(0x10, 2, 0x20, "left"))
        with self.assertRaises(ValueError):
            pcs.m4_unpack_public_words(statement[:-1], intent)
        with self.assertRaises(ValueError):
            pcs.m4_unpack_public_words(statement, intent[:-1])
        with self.assertRaises(ValueError):
            pcs.m4_pack_u64_words(private[:-1])

    def test_joint_mask_parser_and_every_wire_region_tamper(self) -> None:
        source = tuple(0 for _ in range(1 << self.params.log_relation_size))
        context = self.context
        encoded = pcs.prove_joint_mask_toy(
            source,
            self.params,
            context,
            pcs.shake512(b"HVBPCS/test/joint-mask/coins/v1")[:32],
        )
        self.assertTrue(pcs.verify_joint_mask_toy(encoded, self.params, context))
        parsed = pcs.JointMaskProof.parse(encoded, self.params)
        self.assertEqual(parsed.serialize(self.params), encoded)
        self.assertEqual(len(encoded), pcs.joint_mask_toy_wire_bytes(self.params))
        offsets = (
            0,
            pcs.HEADER_BYTES,
            pcs.HEADER_BYTES + pcs.E384_BYTES,
            pcs.HEADER_BYTES + 2 * pcs.E384_BYTES,
            pcs.HEADER_BYTES + 2 * pcs.E384_BYTES + pcs.MERKLE_DIGEST_BYTES,
            len(encoded) - 1,
        )
        for offset in offsets:
            changed = bytearray(encoded)
            changed[offset] ^= 1
            self.assertFalse(
                pcs.verify_joint_mask_toy(bytes(changed), self.params, context)
            )
        self.assertFalse(pcs.verify_joint_mask_toy(encoded + b"\x00", self.params, context))
        self.assertFalse(pcs.verify_joint_mask_toy(encoded[:-1], self.params, context))

    def test_ghash_sq_two_rep_screen_keeps_composition_unproved(self) -> None:
        result = pcs.report()["ghash_sq256b_two_rep_screen"]
        self.assertEqual(result["field_bits"], 256)
        self.assertEqual(result["log_degree_bound"], 120)
        self.assertEqual(result["single_repetition_classical_error_bits"], 136)
        self.assertEqual(result["joint_classical_error_bits"], 272)
        self.assertEqual(result["conservative_composed_bits"], 136)
        self.assertEqual(result["mask_coordinate_copies"], 2)
        self.assertTrue(result["shared_joint_commitment"])
        self.assertFalse(result["independence_theorem"])
        self.assertFalse(result["qrom_composed"])
        best = result["best_two_rep"]
        self.assertEqual(best["field_bytes"], 32)
        self.assertEqual(best["mask_coordinate_copies"], 2)
        self.assertEqual(best["repetitions"], 2)
        self.assertFalse(result["strict_admitted"])

    def test_hash_widths_and_multi_target_ledger_are_separate(self) -> None:
        ledger = pcs.report()["hash_collision_multi_target_ledger"]
        self.assertEqual(ledger["target_count"], 83 * 68)
        self.assertEqual(ledger["merkle"]["output_bits"], 448.0)
        self.assertEqual(ledger["fiat_shamir"]["output_bits"], 512.0)
        self.assertGreater(
            ledger["fiat_shamir"]["classical_birthday_bits"],
            ledger["merkle"]["classical_birthday_bits"],
        )
        self.assertGreater(
            ledger["fiat_shamir"]["generic_qrom_collision_bits"],
            ledger["merkle"]["generic_qrom_collision_bits"],
        )
        self.assertFalse(ledger["composition_proved"])
        self.assertFalse(ledger["strict_admitted"])

    def test_toy_command_contract(self) -> None:
        result = pcs.run_toy_check()
        self.assertTrue(result["verified"])
        self.assertEqual(result["proof_bytes"], result["formula_bytes"])
        self.assertTrue(result["e384_real_field"])
        self.assertFalse(result["strict_admitted"])


if __name__ == "__main__":
    unittest.main()
