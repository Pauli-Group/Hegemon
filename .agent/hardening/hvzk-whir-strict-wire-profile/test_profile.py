#!/usr/bin/env python3
"""Standard-library tests for the HVZK-WHIR source wire profile."""

from __future__ import annotations

import json
import struct
import unittest

import hvzk_whir_profile as profile


class ProfileTests(unittest.TestCase):
    def test_wire_sizes_and_roundtrip(self) -> None:
        raw, parsed = profile.fixture()
        self.assertEqual(profile.HEADER_BYTES, 168)
        self.assertEqual(profile.STATEMENT_HEADER_BYTES, 92)
        self.assertEqual(profile.SECTION_HEADER_BYTES, 8)
        self.assertEqual(len(raw), 459)
        self.assertEqual(profile.encode_envelope(parsed.statement, parsed.sections), raw)
        self.assertTrue(profile.profile_report()["fixture_accounting"]["formula_holds"])

    def test_known_answer_profile_digest(self) -> None:
        self.assertEqual(
            profile.profile_digest().hex(),
            "a505fee2df5c4b81f80f45cc04d75b6588581bf3a3a4ec9d1dcac2da1e297fd40637c202180203dada7ea57d73ec4d78fa977d895cf3988a0ece2ad9a6744f78",
        )

    def test_hash_framing_and_roles_are_injective_at_boundaries(self) -> None:
        self.assertNotEqual(
            profile.shake_role("source.manifest", (b"a", b"bc")),
            profile.shake_role("source.manifest", (b"ab", b"c")),
        )
        self.assertNotEqual(
            profile.shake_role("source.manifest", (b"same",)),
            profile.shake_role("relation.manifest", (b"same",)),
        )
        with self.assertRaisesRegex(profile.ProfileError, "^unknown_hash_role"):
            profile.shake_role("not-registered", (b"x",))

    def test_canonical_json(self) -> None:
        value = {"z": 1, "a": ["x", False]}
        self.assertEqual(profile.canonical_json_bytes(value), b'{"a":["x",false],"z":1}\n')
        self.assertEqual(json.loads(profile.canonical_json_bytes(value)), value)

    def test_statement_rejects_trailing_bytes(self) -> None:
        _raw, parsed = profile.fixture()
        with self.assertRaisesRegex(profile.ProfileError, "^statement_trailing_bytes"):
            profile.decode_statement(parsed.raw_statement + b"\x00")

    def test_envelope_rejects_trailing_and_binding_mutation(self) -> None:
        raw, _parsed = profile.fixture()
        parsed, error = profile.parse_envelope_safe(raw + b"\x00")
        self.assertIsNone(parsed)
        self.assertEqual(error, "trailing_bytes")
        changed = bytearray(raw)
        changed[80] ^= 1
        parsed, error = profile.parse_envelope_safe(changed)
        self.assertIsNone(parsed)
        self.assertEqual(error, "network_binding_mismatch")

    def test_safe_parser_contains_wrong_types(self) -> None:
        parsed, error = profile.parse_envelope_safe(object())
        self.assertIsNone(parsed)
        self.assertEqual(error, "invalid_type")

    def test_section_instances_are_canonical(self) -> None:
        _raw, parsed = profile.fixture()
        bad = (profile.ProofSection(parsed.sections[0].role_id, 1, b"x"),)
        with self.assertRaisesRegex(profile.ProfileError, "^noncanonical_section_instance"):
            profile.encode_envelope(parsed.statement, bad)

    def test_payload_integrity_changes_transcript(self) -> None:
        raw, original = profile.fixture()
        statement_len = struct.unpack_from("<I", raw, 152)[0]
        payload_offset = profile.HEADER_BYTES + statement_len + profile.SECTION_HEADER_BYTES
        changed = bytearray(raw)
        changed[payload_offset] ^= 1
        mutated = profile.parse_envelope(bytes(changed))
        self.assertNotEqual(profile.transcript_digest(original), profile.transcript_digest(mutated))

    def test_goldilocks_canonical_encoding(self) -> None:
        for value in (0, 1, profile.GOLDILOCKS_MODULUS - 1):
            self.assertEqual(profile.decode_goldilocks(profile.encode_goldilocks(value)), value)
        for value in (-1, profile.GOLDILOCKS_MODULUS, 1 << 64):
            with self.assertRaisesRegex(profile.ProfileError, "^noncanonical_goldilocks"):
                profile.encode_goldilocks(value)
        with self.assertRaisesRegex(profile.ProfileError, "^noncanonical_goldilocks"):
            profile.decode_goldilocks(profile.GOLDILOCKS_MODULUS.to_bytes(8, "little"))
        with self.assertRaisesRegex(profile.ProfileError, "^goldilocks_length"):
            profile.decode_goldilocks(b"\x00" * 7)

    def test_mmcs_shape_and_role_binding(self) -> None:
        leaves = (b"aa", b"bb", b"cc", b"dd")
        root = profile.mmcs_root(leaves, tree_role=0x0201)
        self.assertEqual(len(root), profile.DIGEST_BYTES)
        self.assertNotEqual(root, profile.mmcs_root(leaves, tree_role=0x0202))
        self.assertNotEqual(root, profile.mmcs_root((b"aa", b"bb", b"cc", b"de"), tree_role=0x0201))
        with self.assertRaisesRegex(profile.ProfileError, "^mmcs_leaf_count"):
            profile.mmcs_root((b"a", b"b", b"c"), tree_role=1)
        with self.assertRaisesRegex(profile.ProfileError, "^mmcs_leaf_width"):
            profile.mmcs_root((b"a", b"bb"), tree_role=1)

    def test_challenge_bounds_and_determinism(self) -> None:
        _raw, parsed = profile.fixture()
        state = profile.transcript_digest(parsed)
        self.assertEqual(
            profile.challenge_bytes(state, "pcs.sumcheck-fold", 3, 100),
            profile.challenge_bytes(state, "pcs.sumcheck-fold", 3, 100),
        )
        self.assertNotEqual(
            profile.challenge_bytes(state, "pcs.sumcheck-fold", 3),
            profile.challenge_bytes(state, "pcs.code-switch", 3),
        )
        with self.assertRaisesRegex(profile.ProfileError, "^challenge_output_length"):
            profile.challenge_bytes(state, "pcs.sumcheck-fold", 0, 0)
        with self.assertRaisesRegex(profile.ProfileError, "^sample_upper_range"):
            profile.sample_uniform_index(state, 0, 0)

    def test_security_and_authority_fail_closed(self) -> None:
        ledger = profile.security_ledger()
        self.assertEqual(len(ledger["terms"]), 20)
        self.assertTrue(all(term["exact_value"] is None for term in ledger["terms"]))
        self.assertIsNone(ledger["overall_total"])
        self.assertFalse(ledger["composed_strict_gt_128"])
        self.assertFalse(ledger["production_authorized"])
        self.assertIn("unresolved coefficient-1/coefficient-2", " ".join(profile.production_blockers()))
        with self.assertRaises(profile.ProductionAuthorizationError):
            profile.require_production_authority()


if __name__ == "__main__":
    unittest.main(verbosity=2)
