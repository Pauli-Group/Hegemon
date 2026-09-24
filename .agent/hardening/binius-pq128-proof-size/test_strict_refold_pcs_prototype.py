#!/usr/bin/env python3
"""Adversarial tests for the disk-light refold PCS core.

These tests establish byte/parser/transcript behavior for the toy core only.
They exercise the post-claim random zero-padding functional but deliberately
do not promote it to a formal/QROM, ZK, or strict-security result.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("strict_refold_pcs_prototype.py")
SPEC = importlib.util.spec_from_file_location("strict_refold_pcs_prototype", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pcs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pcs
SPEC.loader.exec_module(pcs)


class StrictRefoldPcsPrototypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = pcs.toy_parameters()
        cls.context = pcs.TOY_PUBLIC_CONTEXT
        cls.source = pcs.deterministic_toy_source(cls.params)
        cls.proof = pcs.prove(cls.source, cls.params, cls.context)
        assert pcs.verify(cls.proof, cls.params, cls.context)

    def assert_mutation_rejects(self, offset: int) -> None:
        changed = bytearray(self.proof)
        changed[offset] ^= 1
        self.assertFalse(pcs.verify(bytes(changed), self.params, self.context))

    def test_exact_roundtrip_and_context_binding(self) -> None:
        parsed = pcs.Proof.parse(self.proof, self.params)
        self.assertEqual(parsed.serialize(self.params), self.proof)
        wrong = bytearray(self.context)
        wrong[-1] ^= 1
        self.assertFalse(pcs.verify(self.proof, self.params, bytes(wrong)))
        self.assertFalse(pcs.verify(self.proof + b"\x00", self.params, self.context))

    def test_pay1x2_model_fixture_matches_actual_parser_grammar(self) -> None:
        params = pcs.pay1x2_parameters()
        self.assertEqual(params.sumcheck_count, params.fold_variables)
        plan = pcs.wire_model.johnson_ligerito_core_candidate()
        fixture = pcs.wire_model.serialize_size_fixture(plan)
        parsed = pcs.Proof.parse(fixture, params)
        self.assertEqual(parsed.serialize(params), fixture)
        self.assertEqual(len(fixture), params.proof_bytes)
        self.assertEqual(params.proof_bytes, 112_784)

    def test_header_root_and_every_wide_claim_are_bound(self) -> None:
        self.assert_mutation_rejects(0)
        root_offset = pcs.HEADER_BYTES
        self.assert_mutation_rejects(root_offset)
        wide_offset = root_offset + pcs.DIGEST_BYTES
        for index in range(self.params.wide_count):
            self.assert_mutation_rejects(wide_offset + index * pcs.E384_BYTES)

    def test_sumcheck_terminal_opening_and_frontier_are_bound(self) -> None:
        wide_offset = pcs.HEADER_BYTES + pcs.DIGEST_BYTES
        sumcheck_offset = wide_offset + self.params.wide_count * pcs.E384_BYTES
        self.assert_mutation_rejects(sumcheck_offset)
        self.assert_mutation_rejects(
            sumcheck_offset
            + (self.params.sumcheck_count - 1) * 2 * pcs.E384_BYTES
        )
        terminal_offset = (
            sumcheck_offset + self.params.sumcheck_count * 2 * pcs.E384_BYTES
        )
        self.assert_mutation_rejects(terminal_offset)
        rows_offset = terminal_offset + self.params.terminal_count * pcs.E384_BYTES
        self.assert_mutation_rejects(rows_offset)

        frontier_offset = (
            rows_offset
            + self.params.query_count * self.params.lanes * pcs.B128_BYTES
        )
        parsed = pcs.Proof.parse(self.proof, self.params)
        transcript = pcs._new_transcript(self.params, self.context, parsed.root)
        evaluation_point = tuple(
            transcript.challenge_e384(b"evaluation/" + index.to_bytes(2, "big"))
            for index in range(self.params.log_relation_size)
        )
        pcs._observe_wide(transcript, parsed.wide)
        basis = pcs._padding_augmented_basis(transcript, evaluation_point, self.params)
        for round_index, message in enumerate(parsed.sumcheck):
            pcs._observe_sumcheck(transcript, round_index, message)
            challenge = transcript.challenge_e384(
                b"sumcheck/" + round_index.to_bytes(2, "big")
            )
            basis = pcs._fold(basis, challenge)
        # Recompute the non-serialized checksum at its original Fiat--Shamir
        # position. The verification path performs the same reconstruction.
        terminal_message = pcs._round_message(parsed.terminal, basis)
        pcs._observe_sumcheck(transcript, self.params.fold_variables, terminal_message)
        transcript.observe(
            b"terminal", b"".join(value.to_bytes() for value in parsed.terminal)
        )
        sampled = transcript.distinct_indices(
            b"columns", self.params.query_count, self.params.codeword_leaves
        )
        queries = tuple(sorted(sampled))
        current = set(queries)
        actual_count = 0
        for _ in range(self.params.residual_variables + self.params.log_inv_rate):
            actual_count += sum(1 for index in current if (index ^ 1) not in current)
            current = {index >> 1 for index in current}
        self.assertGreater(actual_count, 0)
        self.assertLess(actual_count, self.params.frontier_nodes)
        self.assert_mutation_rejects(frontier_offset)
        self.assert_mutation_rejects(
            frontier_offset + (self.params.frontier_nodes - 1) * pcs.DIGEST_BYTES
        )

    def test_noncanonical_inactive_source_hits_post_claim_padding_check(self) -> None:
        changed = list(self.source)
        changed[self.params.active_symbols] = 1
        with self.assertRaisesRegex(ValueError, "canonical zero padding"):
            pcs.prove(changed, self.params, self.context)

        # Rebuild only the tiny malicious commitment while bypassing the
        # honest-prover guard.  The target is fixed and observed first; the
        # later padding challenges make the combined claim inconsistent.
        columns = pcs._encode_source(
            changed, self.params, enforce_zero_padding=False
        )
        levels = pcs._merkle_levels(columns)
        root = levels[-1][0]
        transcript = pcs._new_transcript(self.params, self.context, root)
        evaluation_point = tuple(
            transcript.challenge_e384(b"evaluation/" + index.to_bytes(2, "big"))
            for index in range(self.params.log_relation_size)
        )
        values = [pcs.E384.embed(value) for value in changed]
        target = pcs._mle_evaluate(values, evaluation_point)
        wide = (target,) + tuple(
            pcs._supplemental_wide(root, target, index)
            for index in range(1, self.params.wide_count)
        )
        pcs._observe_wide(transcript, wide)
        augmented = pcs._padding_augmented_basis(
            transcript, evaluation_point, self.params
        )
        self.assertNotEqual(target, pcs._inner_product(values, augmented))

        result = pcs.run_toy_check()
        self.assertTrue(result["toy"]["inactive_zero_padding_transcript_bound"])
        self.assertFalse(result["toy"]["inactive_zero_padding_formally_proved"])
        self.assertFalse(result["pay1x2_size_only"]["strict_admitted"])


if __name__ == "__main__":
    unittest.main()
