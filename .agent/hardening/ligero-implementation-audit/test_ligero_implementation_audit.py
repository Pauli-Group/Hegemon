#!/usr/bin/env python3
"""Mutation tests for the fail-closed Ligero implementation audit."""

from __future__ import annotations

import copy
import json
import unittest

from check_audit import validation_errors
from ligero_implementation_audit import build_ledger, canonical_json


class LigeroImplementationAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = build_ledger()

    def assert_rejected(self, mutation) -> None:
        value = copy.deepcopy(self.ledger)
        mutation(value)
        self.assertTrue(validation_errors(value))

    def test_generated_ledger_is_canonical_json(self) -> None:
        encoded = canonical_json(self.ledger)
        self.assertEqual(encoded, canonical_json(json.loads(encoded)))

    def test_unmodified_ledger_passes_semantic_checks(self) -> None:
        self.assertEqual(validation_errors(self.ledger), [])

    def test_authority_cannot_be_promoted(self) -> None:
        self.assert_rejected(lambda value: value["authority"].__setitem__("pq128", True))

    def test_proof_bytes_cannot_be_invented(self) -> None:
        self.assert_rejected(
            lambda value: value["executable_wire_and_size"].__setitem__("proof_bytes", 1)
        )

    def test_security_bits_cannot_be_invented(self) -> None:
        self.assert_rejected(
            lambda value: value["qrom_and_zk_composition"].__setitem__(
                "composed_security_bits", 128
            )
        )

    def test_paper_route_cannot_be_promoted_to_executable(self) -> None:
        self.assert_rejected(
            lambda value: value["qrom_and_zk_composition"][
                "paper_only_conditional_route"
            ].__setitem__("executable_composition_established", True)
        )

    def test_protocol_match_cannot_be_asserted(self) -> None:
        self.assert_rejected(
            lambda value: value["pinned_executable"].__setitem__(
                "matches_exact_2022_section_4_7", True
            )
        )

    def test_2022_simulator_cannot_be_inherited(self) -> None:
        self.assert_rejected(
            lambda value: value["pinned_executable"]["theorem_inheritance"].__setitem__(
                "lemma_4_15_simulator_applies", True
            )
        )

    def test_mask_bug_cannot_be_hidden(self) -> None:
        self.assert_rejected(
            lambda value: value["pinned_executable"]["zero_knowledge"].__setitem__(
                "encoding_independence", 128
            )
        )

    def test_cms_chain_cannot_be_claimed(self) -> None:
        self.assert_rejected(
            lambda value: value["hash_and_transcript"]["cms_modified_chain"].__setitem__(
                "implemented", True
            )
        )

    def test_provisional_relation_geometry_cannot_be_frozen(self) -> None:
        self.assert_rejected(
            lambda value: value["exact_relation"].__setitem__("constraints_m", 29_510_157)
        )

    def test_blocker_cannot_be_removed(self) -> None:
        self.assert_rejected(lambda value: value["critical_blockers"].pop())

    def test_backup_cannot_be_qualified(self) -> None:
        self.assert_rejected(
            lambda value: value["verdict"].__setitem__("backup_qualified", True)
        )


if __name__ == "__main__":
    unittest.main()
