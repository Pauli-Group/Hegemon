#!/usr/bin/env python3
"""Dependency-free mutation tests for the HX448C02 source certificate."""

from __future__ import annotations

import copy
import sys
import unittest

sys.dont_write_bytecode = True

import check_certificate as checker


class CertificateMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate = checker.load_json(checker.CERTIFICATE_PATH)
        cls.corpus = checker.load_json(checker.CORPUS_PATH)
        cls.context = checker.collect_source_context(cls.certificate)

    def validate(self, certificate=None, corpus=None, context=None):
        return checker.validate_all(
            certificate if certificate is not None else self.certificate,
            corpus if corpus is not None else self.corpus,
            context if context is not None else self.context,
        )

    def assert_rejected(self, mutate_certificate=None, mutate_corpus=None) -> None:
        certificate = copy.deepcopy(self.certificate)
        corpus = copy.deepcopy(self.corpus)
        if mutate_certificate is not None:
            mutate_certificate(certificate)
        if mutate_corpus is not None:
            mutate_corpus(corpus)
        with self.assertRaises(checker.CertificateError):
            self.validate(certificate, corpus)

    def test_00_live_certificate_passes(self) -> None:
        result = self.validate()
        self.assertEqual(result["calls"], 83)
        self.assertFalse(result["executed_scalar_m4_parity"])
        self.assertFalse(result["production_authorized"])

    def test_source_byte_mutation_rejects(self) -> None:
        payloads = dict(self.context.payloads)
        scalar_path = "circuits/transaction/src/full_blake2b448_relation.rs"
        mutated = bytearray(payloads[scalar_path])
        mutated[0] ^= 1
        payloads[scalar_path] = bytes(mutated)
        context = checker.SourceContext(
            payloads=payloads,
            texts=dict(self.context.texts),
            binius_files=self.context.binius_files,
            binius_tree_sha512=self.context.binius_tree_sha512,
        )
        with self.assertRaises(checker.CertificateError):
            self.validate(context=context)

    def test_source_hash_mutation_rejects(self) -> None:
        def mutate(value):
            pin = value["source_pins"]["circuits/transaction/src/full_blake2b448_relation.rs"]
            pin["sha512"] = "00" * 64

        self.assert_rejected(mutate_certificate=mutate)

    def test_codec_width_mutation_rejects(self) -> None:
        self.assert_rejected(mutate_certificate=lambda value: value["codec"].__setitem__("bytes", 868))

    def test_frame_source_slice_mutation_rejects(self) -> None:
        def mutate(value):
            layout = next(
                layout
                for layout in value["frame_layouts"]["layouts"]
                if layout["id"] == "intent"
            )
            layout["fields"][0]["source_ranges"] = [[0, 13], [181, 869]]

        self.assert_rejected(mutate_certificate=mutate)

    def test_stablecoin_width_mutation_rejects(self) -> None:
        def mutate(value):
            field = next(
                field for field in value["codec"]["fields"] if field["name"] == "stable_policy_hash"
            )
            field["bytes"] = 56

        self.assert_rejected(mutate_certificate=mutate)

    def test_call_index_mutation_rejects(self) -> None:
        def mutate(value):
            family = next(family for family in value["call_families"] if family["id"] == "nullifier")
            family["start"] = 3

        self.assert_rejected(mutate_certificate=mutate)

    def test_call_74_relabel_mutation_rejects(self) -> None:
        def mutate(value):
            family = next(
                family for family in value["call_families"] if family["id"] == "private_auth_policy"
            )
            family["id"] = "stablecoin_policy"

        self.assert_rejected(mutate_certificate=mutate)

    def test_primitive_core_mutation_rejects(self) -> None:
        self.assert_rejected(
            mutate_certificate=lambda value: value["profiles"][0].__setitem__(
                "total_cores", value["profiles"][0]["total_cores"] + 1
            )
        )

    def test_mask_partition_mutation_rejects(self) -> None:
        self.assert_rejected(
            mutate_corpus=lambda value: value["accepted_mask_mode_cases_per_profile"].pop()
        )

    def test_stablecoin_case_mutation_rejects(self) -> None:
        def mutate(value):
            value["stablecoin_cases"] = [
                case for case in value["stablecoin_cases"] if case["id"] != "enabled-oracle-stale"
            ]

        self.assert_rejected(mutate_corpus=mutate)

    def test_semantic_mapping_mutation_rejects(self) -> None:
        def mutate(value):
            mapping = next(
                mapping
                for mapping in value["semantic_mappings"]
                if mapping["id"] == "approval-transition"
            )
            mapping["m4"]["anchors"] = ["nonexistent_approval_constraint_anchor"]

        self.assert_rejected(mutate_certificate=mutate)

    def test_semantic_edge_label_mutation_rejects(self) -> None:
        def mutate(value):
            value["semantic_mappings"][0]["edges"][0] = "plausible-but-uncertified-edge"

        self.assert_rejected(mutate_certificate=mutate)

    def test_optional_positive_corpus_mutation_rejects(self) -> None:
        def mutate(value):
            value["positive_semantic_cases_per_profile"][0] = "uncertified-positive-case"

        self.assert_rejected(mutate_corpus=mutate)

    def test_missing_equality_execution_credit_rejects(self) -> None:
        def mutate(value):
            value["missing_executed_graph"]["per_call_frame_digest_comparisons_executed"] = 1

        self.assert_rejected(mutate_certificate=mutate)

    def test_strict_stablecoin_margin_claim_rejects(self) -> None:
        self.assert_rejected(
            mutate_certificate=lambda value: value["stablecoin_boundary"].__setitem__(
                "strict_stablecoin_pq_margin", True
            )
        )

    def test_production_authority_claim_rejects(self) -> None:
        self.assert_rejected(
            mutate_certificate=lambda value: value["authority"].__setitem__(
                "production_authorized", True
            )
        )

    def test_program_digest_mutation_rejects(self) -> None:
        self.assert_rejected(
            mutate_certificate=lambda value: value["profiles"][0].__setitem__(
                "program_sha512", "00" * 64
            )
        )

    def test_policy_tuple_kat_mutation_rejects(self) -> None:
        def mutate(value):
            kat = value["stablecoin_boundary"]["kat"]
            kat["tuple_hex"] = (bytes.fromhex(kat["tuple_hex"])[:-1] + b"\x01").hex()

        self.assert_rejected(mutate_certificate=mutate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
