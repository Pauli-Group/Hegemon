#!/usr/bin/env python3
"""Adversarial tests for the exact one-level E384 Ligerito core.

All executable instances are deliberately tiny.  The production-size screen is
formula-only and never constructs a witness, Reed--Solomon oracle, or proof.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ligerito_e384_core.py")
SPEC = importlib.util.spec_from_file_location("ligerito_e384_core", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)


class FieldAndParameterTests(unittest.TestCase):
    def test_b128_and_e384_fixed_polynomials(self) -> None:
        samples = (0, 1, 2, (1 << 127), core.B128_MASK)
        for value in samples:
            self.assertEqual(core.b128_mul(value, 0), 0)
            self.assertEqual(core.b128_mul(value, 1), value)
            self.assertEqual(
                core.b128_from_bytes(core.b128_to_bytes(value)), value
            )

        y = core.E384(0, 1, 0)
        self.assertEqual(y * y * y, y + core.E384.one())
        a = core.E384(3, 5, 7)
        b = core.E384(11, 13, 17)
        c = core.E384(19, 23, 29)
        self.assertEqual(a * (b + c), a * b + a * c)
        self.assertEqual(core.E384.from_bytes(a.to_bytes()), a)

    def test_sha512_framing_and_domain_separation(self) -> None:
        first = core._sha512(b"domain/a", b"left", b"right")
        self.assertEqual(len(first), core.SHA512_BYTES)
        self.assertEqual(first, core._sha512(b"domain/a", b"left", b"right"))
        self.assertNotEqual(first, core._sha512(b"domain/b", b"left", b"right"))
        self.assertNotEqual(first, core._sha512(b"domain/a", b"leftright"))

    def test_exact_source_equation_15_parameterization(self) -> None:
        params = core.toy_parameters()
        query_log2, field_log2, union_log2 = params.source_soundness_log2_terms
        self.assertLess(query_log2, 0)
        self.assertLess(field_log2, -300)
        self.assertLessEqual(union_log2, -params.source_security_bits)
        if params.query_count > 1:
            previous = core.source_ligerito_log2_error(
                message_rows=params.message_rows,
                codeword_rows=params.codeword_rows,
                fold_variables=params.fold_variables,
                query_count=params.query_count - 1,
            )[2]
            self.assertGreater(previous, -params.source_security_bits)

    def test_full_bucket_screen_is_formula_only_and_fail_closed(self) -> None:
        params = core.best_full_bucket_screen()
        self.assertEqual(params.log_relation_size, 16)
        self.assertLessEqual(params.encoded_oracle_bytes, 512 * 1024 * 1024)
        self.assertGreater(params.query_count, 68)
        self.assertGreaterEqual(params.source_soundness_bits, 264)
        resources = params.resource_ledger
        self.assertEqual(
            resources.encoded_oracle_b128_elements * core.B128_BYTES,
            resources.encoded_oracle_bytes,
        )
        self.assertEqual(
            resources.rs_horner_steps,
            params.codeword_rows * params.data_columns * params.message_rows,
        )
        self.assertEqual(
            resources.merkle_leaf_hashes + resources.merkle_internal_hashes,
            2 * params.codeword_rows - 1,
        )
        self.assertFalse(core.complete_zk_contract(params)["production_authorized"])


class OneLevelCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = core.toy_parameters()
        cls.source = core.deterministic_toy_source(cls.params)
        cls.statement = core.deterministic_toy_statement(cls.source, cls.params)
        cls.proof = core.prove(cls.source, cls.params, cls.statement)
        cls.parsed = core.Proof.parse(cls.proof, cls.params)
        cls.view = core.extract_interactive_view(
            cls.proof, cls.params, cls.statement
        )

    def mutate_and_reject(self, offset: int) -> None:
        changed = bytearray(self.proof)
        changed[offset] ^= 1
        self.assertFalse(core.verify(bytes(changed), self.params, self.statement))

    def test_honest_exact_roundtrip_and_ledger(self) -> None:
        self.assertTrue(core.verify(self.proof, self.params, self.statement))
        self.assertEqual(self.parsed.serialize(self.params), self.proof)
        self.assertEqual(len(self.proof), self.params.proof_bytes)
        self.assertEqual(self.params.wire_ledger.total, len(self.proof))
        self.assertEqual(self.proof[: core.HEADER_BYTES], self.params.header())

    def test_parser_rejects_truncation_trailing_and_profile_drift(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical"):
            core.Proof.parse(self.proof[:-1], self.params)
        with self.assertRaisesRegex(ValueError, "canonical"):
            core.Proof.parse(self.proof + b"\x00", self.params)
        self.mutate_and_reject(0)
        # Reserved header bytes are externally pinned zero and cannot carry aliases.
        self.mutate_and_reject(core.HEADER_BYTES - 1)

        other = core.Parameters.for_source_security(
            log_relation_size=self.params.log_relation_size,
            fold_variables=1,
            log_inv_rate=self.params.log_inv_rate,
            source_security_bits=self.params.source_security_bits,
        )
        self.assertFalse(core.verify(self.proof, other, self.statement))

    def test_statement_context_functional_and_claim_are_bound(self) -> None:
        wrong_context = bytearray(self.statement.public_context)
        wrong_context[0] ^= 1
        changed_context = core.OpeningStatement(
            bytes(wrong_context), self.statement.weights, self.statement.claimed_value
        )
        self.assertFalse(core.verify(self.proof, self.params, changed_context))

        weights = list(self.statement.weights)
        weights[0] = weights[0] + core.E384.one()
        changed_weights = core.OpeningStatement(
            self.statement.public_context, tuple(weights), self.statement.claimed_value
        )
        self.assertFalse(core.verify(self.proof, self.params, changed_weights))

        changed_claim = core.OpeningStatement(
            self.statement.public_context,
            self.statement.weights,
            self.statement.claimed_value + core.E384.one(),
        )
        self.assertFalse(core.verify(self.proof, self.params, changed_claim))

        source = list(self.source)
        source[0] ^= 1
        with self.assertRaisesRegex(ValueError, "public opening claim"):
            core.prove(source, self.params, self.statement)

    def test_every_wire_section_is_mutation_bound(self) -> None:
        ledger = self.params.wire_ledger
        statement_offset = ledger.header
        root_offset = statement_offset + ledger.statement_id
        claim_offset = root_offset + ledger.commitment_root
        sumcheck_offset = claim_offset + ledger.claimed_value
        terminal_offset = sumcheck_offset + ledger.sumcheck
        rows_offset = terminal_offset + ledger.terminal
        frontier_offset = rows_offset + ledger.opened_rows

        for offset in (
            statement_offset,
            root_offset,
            claim_offset,
            sumcheck_offset,
            sumcheck_offset + ledger.sumcheck - 1,
            terminal_offset,
            terminal_offset + ledger.terminal - 1,
            rows_offset,
            rows_offset + ledger.opened_rows - 1,
            frontier_offset,
            frontier_offset + ledger.authentication - 1,
        ):
            self.mutate_and_reject(offset)

    def test_queries_are_post_terminal_distinct_and_canonicalized(self) -> None:
        sampled = self.view.sampled_query_order
        canonical = self.view.canonical_query_order
        self.assertEqual(len(sampled), self.params.query_count)
        self.assertEqual(len(set(sampled)), len(sampled))
        self.assertEqual(canonical, tuple(sorted(sampled)))

        # A terminal mutation changes either the transcript queries or the
        # terminal/row equations, and in all cases rejects.
        terminal_offset = (
            core.HEADER_BYTES
            + core.SHA512_BYTES
            + core.SHA512_BYTES
            + core.E384_BYTES
            + self.params.wire_ledger.sumcheck
        )
        self.mutate_and_reject(terminal_offset)

    def test_compact_multiproof_padding_is_canonical(self) -> None:
        encoded_rows = core._encode_source(
            self.source,
            self.params,
            allocation_limit_bytes=self.params.encoded_oracle_bytes,
        )
        levels = core._merkle_levels(encoded_rows, self.params)
        queries = tuple(range(self.params.query_count))
        frontier = core._compact_multiproof(levels, queries, self.params)
        actual = core._actual_frontier_count(
            queries, self.params.log_codeword_rows
        )
        self.assertLess(actual, self.params.frontier_nodes)
        rows = tuple(encoded_rows[index] for index in queries)
        self.assertTrue(
            core._verify_compact_multiproof(
                root=levels[-1][0],
                queries=queries,
                rows=rows,
                frontier=frontier,
                params=self.params,
            )
        )
        changed = list(frontier)
        tail = bytearray(changed[-1])
        tail[-1] ^= 1
        changed[-1] = bytes(tail)
        self.assertFalse(
            core._verify_compact_multiproof(
                root=levels[-1][0],
                queries=queries,
                rows=rows,
                frontier=changed,
                params=self.params,
            )
        )

    def test_explicit_allocation_gate_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "allocation limit"):
            core.prove(
                self.source,
                self.params,
                self.statement,
                allocation_limit_bytes=self.params.encoded_oracle_bytes - 1,
            )

    def test_interactive_surface_and_exact_observation_rows(self) -> None:
        self.assertTrue(self.view.fixed_format_public_coin)
        self.assertTrue(self.view.accepted)
        self.assertEqual(len(self.view.commitments), 1)
        self.assertEqual(self.view.commitments[0].field, "B128")
        self.assertEqual(
            len(self.view.verifier_coins[0].e384_values),
            self.params.fold_variables,
        )
        surface = core.export_observation_rows(
            self.params,
            self.statement,
            self.view.verifier_coins[0].e384_values,
            self.view.canonical_query_order,
        )
        expected_e384 = [
            value for message in self.parsed.sumcheck for value in message
        ] + list(self.parsed.terminal)
        self.assertEqual(
            [row.evaluate(self.source) for row in surface.e384_rows],
            expected_e384,
        )
        self.assertEqual(
            [row.evaluate(self.source) for row in surface.b128_rows],
            [value for row in self.parsed.opened_rows for value in row],
        )
        self.assertFalse(surface.relation_witness_generator_supplied)
        self.assertFalse(surface.wrapper_mask_generator_supplied)

    def test_underlying_interactive_state_machine_precedes_fiat_shamir(self) -> None:
        prover = core.OneLevelInteractiveProver(
            self.source, self.params, self.statement
        )
        with self.assertRaisesRegex(ValueError, "cannot precede"):
            prover.receive_sumcheck_coin(core.E384.one())
        with self.assertRaisesRegex(ValueError, "cannot precede"):
            prover.open_rows(self.view.sampled_query_order)

        messages = []
        coins = self.view.verifier_coins[0].e384_values
        for coin in coins:
            message = prover.next_sumcheck_message()
            messages.append(message)
            with self.assertRaisesRegex(ValueError, "pending"):
                prover.next_sumcheck_message()
            prover.receive_sumcheck_coin(coin)
        terminal = prover.terminal_message()
        opening = prover.open_rows(self.view.sampled_query_order)
        self.assertEqual(tuple(messages), self.parsed.sumcheck)
        self.assertEqual(terminal, self.parsed.terminal)
        self.assertEqual(opening.opened_rows, self.parsed.opened_rows)
        self.assertEqual(opening.frontier, self.parsed.frontier)
        self.assertTrue(
            core.verify_interactive(
                params=self.params,
                statement=self.statement,
                root=prover.root,
                sumcheck_messages=messages,
                sumcheck_coins=coins,
                terminal=terminal,
                sampled_queries=self.view.sampled_query_order,
                opening=opening,
            )
        )
        wrong_coins = list(coins)
        wrong_coins[0] = wrong_coins[0] + core.E384.one()
        self.assertFalse(
            core.verify_interactive(
                params=self.params,
                statement=self.statement,
                root=prover.root,
                sumcheck_messages=messages,
                sumcheck_coins=wrong_coins,
                terminal=terminal,
                sampled_queries=self.view.sampled_query_order,
                opening=opening,
            )
        )

    def test_complete_zk_interface_cannot_authorize(self) -> None:
        contract = core.complete_zk_contract(self.params)
        self.assertTrue(contract["raw_observation_operator_O_exported"])
        for key in (
            "one_declared_theorem_field_refinement",
            "at_most_one_evaluation_query_per_commitment_or_conversion",
            "acceptance_only_polynomial_constraints",
            "full_relation_witness_generator_Gw_supplied",
            "wrapper_mask_generator_Gr_supplied",
            "all_q_projections_full_rank",
            "three_independent_B128_random_columns",
            "nonzero_random_column_coefficient_proved",
            "fixed_randomness_whole_view_simulator",
            "fiat_shamir_qrom_composition",
            "complete_zk",
            "strict_pq128",
            "frontier_eligible",
            "production_authorized",
        ):
            self.assertIs(contract[key], False, key)

    def test_report_does_not_mislabel_ligerito_as_tensorswitch(self) -> None:
        report = core.report()
        self.assertEqual(report["protocol_source"]["error_equation"], 15)
        self.assertFalse(report["protocol_source"]["johnson_flock_extension_used"])
        self.assertFalse(report["protocol_source"]["tensorswitch_used"])
        self.assertFalse(report["comparator"]["absolute_no_go_proved"])
        self.assertTrue(
            report["comparator"][
                "fixed_max_frontier_grammar_disadvantage_established"
            ]
        )
        self.assertFalse(report["capabilities"]["production_authorized"])


if __name__ == "__main__":
    unittest.main()
