#!/usr/bin/env python3
"""Dependency-free conformance and mutation tests for the CFW26 reference."""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "cfw26_r1cs_ior.py"
SPEC = importlib.util.spec_from_file_location("cfw26_r1cs_ior_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load CFW26 source reference")
cfw = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cfw
SPEC.loader.exec_module(cfw)


BINDING = cfw.sha512_frame(b"test-only-unbound-compiler", b"fixture").hex()
SEED = b"cfw26-reference-fixture"


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.instance, self.witness = cfw.toy_instance(BINDING)
        self.profile = cfw.ReferenceProfile()

    def run_for(self, convention: str):
        return cfw.honest_prove(
            self.instance,
            self.witness,
            self.profile,
            seed=SEED,
            convention=convention,
        )


class FieldAndR1CSTests(Fixture):
    def test_goldilocks_codec_is_exact_little_endian(self) -> None:
        self.assertEqual(cfw.fe_hex(1), "0100000000000000")
        self.assertEqual(cfw.parse_fe_hex("0100000000000000"), 1)
        with self.assertRaises(cfw.ReferenceError):
            cfw.field(cfw.GOLDILOCKS_MODULUS)
        with self.assertRaises(cfw.ReferenceError):
            cfw.parse_fe_hex(cfw.GOLDILOCKS_MODULUS.to_bytes(8, "little").hex())
        with self.assertRaises(cfw.ReferenceError):
            cfw.field(True)

    def test_compiler_digest_and_dimensions_have_one_in_memory_form(self) -> None:
        with self.assertRaises(cfw.ReferenceError):
            replace(self.instance, compiler_binding_digest=BINDING.upper())
        with self.assertRaises(cfw.ReferenceError):
            replace(self.instance, ell=True, n0=True)
        with self.assertRaises(cfw.ReferenceError):
            cfw.ReferenceProfile(t_queries=True)

    def test_little_endian_boolean_bijection_and_mle(self) -> None:
        values = tuple(range(8))
        for index, bits in enumerate(cfw.bit_vectors(3)):
            self.assertEqual(cfw.multilinear_eval(values, bits), index)

    def test_toy_r1cs_binds_every_witness_coordinate(self) -> None:
        self.assertTrue(self.instance.is_satisfied(self.witness))
        for index in range(self.instance.ell):
            mutated = list(self.witness)
            mutated[index] = cfw.fadd(mutated[index], 1)
            self.assertFalse(self.instance.is_satisfied(mutated), index)

    def test_honest_prover_rejects_unsatisfied_witness(self) -> None:
        mutated = list(self.witness)
        mutated[2] = cfw.fadd(mutated[2], 1)
        with self.assertRaises(cfw.ReferenceError):
            cfw.honest_prove(
                self.instance,
                mutated,
                self.profile,
                seed=SEED,
                convention=cfw.CONSTRUCTION_LITERAL,
            )

    def test_instance_requires_exact_section11_geometry(self) -> None:
        with self.assertRaises(cfw.ReferenceError):
            replace(self.instance, n0=2)
        with self.assertRaises(cfw.ReferenceError):
            replace(self.instance, ell=3)

    def test_reported_hegemon_geometry_is_only_an_exact_padding_projection(self) -> None:
        projection = cfw.section11_padding_projection(
            cfw.REPORTED_HEGEMON_MIXED_SOURCE_GEOMETRY
        )
        self.assertEqual(
            projection,
            {
                "authoritative_carrier": False,
                "candidate_embedded_matrix_nonzeros": 123_057_296,
                "carrier_matrix_side": 67_108_864,
                "carrier_nonconstant_variables": 67_108_863,
                "ell": 33_554_432,
                "matrix_embedding_constructed": False,
                "n0": 33_554_432,
                "parser_padding_binding_proved": False,
                "public_zero_padding_elements": 33_544_279,
                "remaining_zero_rows": 32_398_608,
                "section11_hvzk_oracle_hybrid_count": 105,
                "section11_main_message_elements": 33_554_432,
                "section11_sumcheck_variables": 26,
                "semantic_refinement_proved": False,
                "source_constraints": 20_457_227,
                "source_matrix_nonzeros": 94_551_238,
                "source_nonconstant_variables": 19_311_555,
                "source_public_variables": 10_152,
                "source_witness_variables": 19_301_403,
                "witness_zero_padding_elements_and_rows": 14_253_029,
                "whir_codeword_elements_defined": False,
            },
        )
        with self.assertRaises(cfw.ReferenceError):
            cfw.GeneralR1CSGeometry(10, 9, 10, 20)
        with self.assertRaises(cfw.ReferenceError):
            cfw.GeneralR1CSGeometry(True, 9, 1, 20)

    def test_inner_mask_sampling_has_two_zero_targets(self) -> None:
        rng = cfw.DeterministicFieldRng(b"mask", b"test")
        for _ in range(20):
            mask = cfw.sample_inner_mask(4, rng)
            self.assertEqual(cfw.poly_eval(mask, 0), 0)
            self.assertEqual(cfw.poly_eval(mask, 1), 0)

    def test_rs_encoding_has_exact_one_query_uniform_shift(self) -> None:
        spec = cfw.RSZKEncodingSpec("test", 4, 1, 10)
        message_a = (1, 2, 3, 4)
        message_b = (8, 9, 10, 11)
        point_index = 4
        target = 12345
        # The constant random coefficient can force any chosen single
        # evaluation to any field value, independently of the message.
        point = spec.evaluation_points[point_index]
        tail_a = cfw.poly_eval((0,) + message_a, point)
        tail_b = cfw.poly_eval((0,) + message_b, point)
        code_a = spec.encode(message_a, (cfw.fsub(target, tail_a),))
        code_b = spec.encode(message_b, (cfw.fsub(target, tail_b),))
        self.assertEqual(code_a[point_index], target)
        self.assertEqual(code_b[point_index], target)


class HonestTranscriptTests(Fixture):
    def test_both_source_branches_execute_deterministically(self) -> None:
        outputs = {}
        for convention in cfw.MASK_FACTORS:
            first = self.run_for(convention)
            second = self.run_for(convention)
            self.assertEqual(first, second)
            cfw.verify_direct(self.instance, self.profile, first.transcript)
            cfw.verify_derived_output_relation(
                self.instance, self.profile, first.transcript, first.output_witness
            )
            outputs[convention] = first.transcript.to_bytes()
        self.assertNotEqual(outputs[cfw.CONSTRUCTION_LITERAL], outputs[cfw.PROOF_SKETCH])

    def test_explicit_honest_prover_verifier_objects(self) -> None:
        prover = cfw.HonestProver(
            self.instance,
            self.profile,
            SEED,
            cfw.CONSTRUCTION_LITERAL,
        )
        verifier = cfw.HonestVerifier(self.instance, self.profile)
        run = prover.prove(self.witness)
        verifier.reduce(run.transcript)
        verifier.verify_derived_output(run.transcript, run.output_witness)
        with self.assertRaises(cfw.PaperAmbiguityError):
            verifier.verify_paper_output(run.transcript, run.output_witness)

    def test_transcript_roundtrip_is_canonical(self) -> None:
        run = self.run_for(cfw.CONSTRUCTION_LITERAL)
        encoded = run.transcript.to_bytes()
        parsed = cfw.Transcript.from_bytes(encoded)
        self.assertEqual(parsed, run.transcript)
        self.assertEqual(parsed.to_bytes(), encoded)

    def test_parser_rejects_truncation_trailing_and_unknown_keys(self) -> None:
        encoded = self.run_for(cfw.CONSTRUCTION_LITERAL).transcript.to_bytes()
        for mutated in (encoded[:-1], encoded + b"\n", b" " + encoded):
            with self.assertRaises(cfw.ReferenceError):
                cfw.Transcript.from_bytes(mutated)
        value = json.loads(encoded)
        value["unknown"] = 0
        with self.assertRaises(cfw.ReferenceError):
            cfw.Transcript.from_bytes(cfw.canonical_json(value))

    def test_parser_rejects_duplicate_keys_bool_version_and_wrong_nested_type(self) -> None:
        encoded = self.run_for(cfw.CONSTRUCTION_LITERAL).transcript.to_bytes()
        duplicate_schema = b'{"schema":"' + cfw.SCHEMA.encode() + b'",' + encoded[1:]
        with self.assertRaises(cfw.ReferenceError):
            cfw.Transcript.from_bytes(duplicate_schema)
        value = json.loads(encoded)
        value["version"] = True
        with self.assertRaises(cfw.ReferenceError):
            cfw.Transcript.from_bytes(cfw.canonical_json(value))
        value = json.loads(encoded)
        value["inner_oracles"][0] = 7
        with self.assertRaises(cfw.ReferenceError):
            cfw.Transcript.from_bytes(cfw.canonical_json(value))
        with self.assertRaises(cfw.ReferenceError):
            cfw.Transcript.from_bytes(encoded.decode())

    def test_exact_dimensions_match_theorem_formula(self) -> None:
        dimensions = cfw.exact_dimensions(self.instance, self.profile)
        self.assertEqual(dimensions["sumcheck_variables"], 3)
        self.assertEqual(dimensions["inner_oracle_count"], 9)
        self.assertEqual(dimensions["outer_oracle_count"], 3)
        self.assertEqual(dimensions["oracle_prover_field_elements"], 154)
        self.assertEqual(dimensions["main_oracle_field_elements"], 10)
        self.assertEqual(dimensions["inner_oracle_field_elements"], 90)
        self.assertEqual(dimensions["outer_oracle_field_elements"], 54)
        self.assertEqual(dimensions["direct_prover_field_elements"], 31)
        self.assertEqual(dimensions["sumcheck_polynomial_field_elements"], 24)
        self.assertEqual(dimensions["outer_evaluation_field_elements"], 3)
        self.assertEqual(dimensions["other_direct_field_elements"], 4)
        self.assertEqual(dimensions["total_prover_field_elements"], 185)
        self.assertEqual(dimensions["hvzk_encoding_hybrid_count"], 13)
        self.assertEqual(
            dimensions["direct_prover_field_elements"],
            dimensions["sumcheck_variables"] * (self.profile.outer_message_length + 1) + 4,
        )

    def test_statement_matrix_and_compiler_bindings_are_exact(self) -> None:
        run = self.run_for(cfw.CONSTRUCTION_LITERAL)
        with self.assertRaises(cfw.ReferenceError):
            cfw.verify_direct(
                replace(self.instance, compiler_binding_digest="00" * 64),
                self.profile,
                run.transcript,
            )
        changed_A = [list(row) for row in self.instance.A]
        changed_A[0][0] = cfw.fadd(changed_A[0][0], 1)
        changed_instance = replace(self.instance, A=tuple(tuple(row) for row in changed_A))
        with self.assertRaises(cfw.ReferenceError):
            cfw.verify_direct(changed_instance, self.profile, run.transcript)

    def test_direct_transcript_mutation_corpus_rejects(self) -> None:
        transcript = self.run_for(cfw.CONSTRUCTION_LITERAL).transcript
        mutations = [
            replace(transcript, instance_digest="00" * 64),
            replace(transcript, compiler_binding_digest="00" * 64),
            replace(transcript, profile_digest="00" * 64),
            replace(transcript, mu_tilde=cfw.fadd(transcript.mu_tilde, 1)),
            replace(transcript, epsilon=cfw.fadd(transcript.epsilon, 1)),
            replace(transcript, r=(cfw.fadd(transcript.r[0], 1),) + transcript.r[1:]),
            replace(transcript, outer_evaluations=(cfw.fadd(transcript.outer_evaluations[0], 1),) + transcript.outer_evaluations[1:]),
            replace(transcript, v_values=(cfw.fadd(transcript.v_values[0], 1),) + transcript.v_values[1:]),
            replace(transcript, u_values=(cfw.fadd(transcript.u_values[0], 1),) + transcript.u_values[1:]),
            replace(transcript, rho=cfw.fadd(transcript.rho, 1)),
            replace(transcript, joint_mu=cfw.fadd(transcript.joint_mu, 1)),
        ]
        first_round = transcript.rounds[0]
        changed_coefficients = (cfw.fadd(first_round.coefficients[0], 1),) + first_round.coefficients[1:]
        mutations.append(
            replace(
                transcript,
                rounds=(replace(first_round, coefficients=changed_coefficients),) + transcript.rounds[1:],
            )
        )
        mutations.append(
            replace(
                transcript,
                rounds=transcript.rounds[:-1] + (replace(transcript.rounds[-1], alpha=0),),
            )
        )
        for index, mutated in enumerate(mutations):
            with self.assertRaises(cfw.ReferenceError, msg=str(index)):
                cfw.verify_direct(self.instance, self.profile, mutated)

    def test_oracle_shape_mutations_reject_directly(self) -> None:
        transcript = self.run_for(cfw.CONSTRUCTION_LITERAL).transcript
        inner = transcript.inner_oracles[0]
        mutations = [
            replace(transcript, inner_oracles=(replace(inner, name="inner/B/0"),) + transcript.inner_oracles[1:]),
            replace(transcript, inner_oracles=(replace(inner, spec_digest="00" * 64),) + transcript.inner_oracles[1:]),
            replace(transcript, inner_oracles=(replace(inner, values=inner.values[:-1]),) + transcript.inner_oracles[1:]),
            replace(transcript, outer_oracles=transcript.outer_oracles[:-1]),
        ]
        for mutated in mutations:
            with self.assertRaises(cfw.ReferenceError):
                cfw.verify_direct(self.instance, self.profile, mutated)

    def test_queryless_direct_verifier_does_not_overclaim_oracle_contents(self) -> None:
        run = self.run_for(cfw.CONSTRUCTION_LITERAL)
        witness_oracle = run.transcript.witness_oracle
        values = (cfw.fadd(witness_oracle.values[0], 1),) + witness_oracle.values[1:]
        mutated = replace(run.transcript, witness_oracle=replace(witness_oracle, values=values))
        # Construction 11.4 is queryless, so the direct verifier sees only the
        # oracle handle/shape. The output relation is what rejects its content.
        cfw.verify_direct(self.instance, self.profile, mutated)
        with self.assertRaises(cfw.ReferenceError):
            cfw.verify_derived_output_relation(
                self.instance, self.profile, mutated, run.output_witness
            )

    def test_output_witness_mutations_reject(self) -> None:
        run = self.run_for(cfw.PROOF_SKETCH)
        witness = run.output_witness
        changed_main = (cfw.fadd(witness.witness_message[0], 1),) + witness.witness_message[1:]
        changed_inner = list(witness.inner_messages)
        changed_inner[0] = (1,) + changed_inner[0][1:]
        changed_outer = list(witness.outer_messages)
        changed_outer[0] = (cfw.fadd(changed_outer[0][0], 1),) + changed_outer[0][1:]
        for mutated in (
            replace(witness, witness_message=changed_main),
            replace(witness, inner_messages=tuple(changed_inner)),
            replace(witness, outer_messages=tuple(changed_outer)),
        ):
            with self.assertRaises(cfw.ReferenceError):
                cfw.verify_derived_output_relation(
                    self.instance, self.profile, run.transcript, mutated
                )


class SimulatorAndBoundaryTests(Fixture):
    def query_plan(self):
        return {name: (0,) for name in cfw.all_oracle_specs(self.instance, self.profile)}

    def test_public_simulator_has_no_witness_parameter(self) -> None:
        self.assertNotIn("witness", inspect.signature(cfw.simulate_public_view).parameters)
        for convention in cfw.MASK_FACTORS:
            view = cfw.simulate_public_view(
                self.instance,
                self.profile,
                self.query_plan(),
                seed=b"public-simulator",
                convention=convention,
            )
            cfw.verify_public_view(self.instance, self.profile, view)

    def test_honest_and_simulated_views_have_exact_same_shape(self) -> None:
        run = self.run_for(cfw.CONSTRUCTION_LITERAL)
        honest = cfw.extract_public_view(
            self.instance, self.profile, run.transcript, self.query_plan()
        )
        simulated = cfw.simulate_public_view(
            self.instance,
            self.profile,
            self.query_plan(),
            seed=b"public-simulator",
            convention=cfw.CONSTRUCTION_LITERAL,
        )
        self.assertEqual(len(honest.rounds), len(simulated.rounds))
        self.assertEqual(
            tuple(len(round_message.coefficients) for round_message in honest.rounds),
            tuple(len(round_message.coefficients) for round_message in simulated.rounds),
        )
        self.assertEqual(
            tuple((name, indexes) for name, indexes, _ in honest.oracle_queries),
            tuple((name, indexes) for name, indexes, _ in simulated.oracle_queries),
        )

    def test_query_plan_over_bound_or_duplicate_rejects(self) -> None:
        with self.assertRaises(cfw.ReferenceError):
            cfw.simulate_public_view(
                self.instance,
                self.profile,
                {"witness": (0, 1)},
                seed=b"public-simulator",
                convention=cfw.CONSTRUCTION_LITERAL,
            )
        with self.assertRaises(cfw.ReferenceError):
            cfw.extract_public_view(
                self.instance,
                self.profile,
                self.run_for(cfw.CONSTRUCTION_LITERAL).transcript,
                {"witness": (0, 0)},
            )

    def test_public_view_mutations_reject(self) -> None:
        view = cfw.simulate_public_view(
            self.instance,
            self.profile,
            self.query_plan(),
            seed=b"public-simulator",
            convention=cfw.PROOF_SKETCH,
        )
        mutations = [
            replace(view, joint_mu=cfw.fadd(view.joint_mu, 1)),
            replace(view, mu_tilde=cfw.fadd(view.mu_tilde, 1)),
            replace(view, u_values=(cfw.fadd(view.u_values[0], 1),) + view.u_values[1:]),
            replace(view, oracle_queries=view.oracle_queries + (view.oracle_queries[0],)),
        ]
        for mutated in mutations:
            with self.assertRaises(cfw.ReferenceError):
                cfw.verify_public_view(self.instance, self.profile, mutated)

    def test_paper_literal_output_relation_always_fails_closed(self) -> None:
        run = self.run_for(cfw.CONSTRUCTION_LITERAL)
        with self.assertRaises(cfw.PaperAmbiguityError):
            cfw.verify_paper_literal_output_relation(
                self.instance, self.profile, run.transcript, run.output_witness
            )

    def test_printed_step9_state_is_ill_typed_and_both_repairs_agree(self) -> None:
        with self.assertRaises(cfw.SuccinctLinearFormTypeError):
            cfw.evaluate_paper_printed_inner_state((1, 2, 3, 4), 9, 11)
        with self.assertRaises(cfw.SuccinctLinearFormTypeError):
            cfw.evaluate_paper_printed_main_state(self.instance, self.witness)
        for convention in cfw.MASK_FACTORS:
            run = self.run_for(convention)
            claims = tuple(
                cfw.typed_joint_output_claim(
                    self.instance,
                    self.profile,
                    run.transcript,
                    run.output_witness,
                    repair=repair,
                )
                for repair in cfw.TYPED_OUTPUT_REPAIRS
            )
            self.assertEqual(claims, (run.transcript.joint_mu,) * 2)
            other = (
                cfw.PROOF_SKETCH
                if convention == cfw.CONSTRUCTION_LITERAL
                else cfw.CONSTRUCTION_LITERAL
            )
            with self.assertRaises(cfw.ReferenceError):
                cfw.verify_derived_output_relation(
                    self.instance,
                    self.profile,
                    replace(run.transcript, convention=other),
                    run.output_witness,
                )

    def test_capability_boundary_keeps_authority_false(self) -> None:
        capabilities = cfw.source_capabilities()
        for gate in (
            "unequal_geometry_native_paper_carrier",
            "full_hegemon_section11_carrier",
            "exact_padding_parser_refinement",
            "paper_output_relation_unambiguous",
            "paper_hvzk_reduction_instantiated",
            "plonky3_section11_carrier",
            "rbr_bound_instantiated",
            "complete_zk",
            "strict_pq128",
            "production_authorized",
        ):
            self.assertFalse(capabilities[gate])


if __name__ == "__main__":
    unittest.main()
