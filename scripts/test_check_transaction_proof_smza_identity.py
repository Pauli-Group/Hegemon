#!/usr/bin/env python3
"""Focused SMZA identity tests; no artifacts, subprocesses, keys or builds."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_transaction_proof_successor_authorization as gate
from test_check_transaction_proof_successor_authorization import test_identity


def identity(smza: bool) -> dict[str, object]:
    value = test_identity()
    for field in gate.SHA512_IDENTITY_PIN_FIELDS:
        value[field] = hashlib.sha512(("test-only:" + field).encode()).hexdigest()
    value["relation_program_sha512"] = gate.RETAINED_RELATION_PROGRAM_SHA512
    value["relation_digest_hex"] = value["relation_program_sha512"][:96]
    if smza:
        value.update(deepcopy(gate.SMZA_FIXED_IDENTITY_VALUES))
        value["deactivation_height_exclusive"] = 1 + gate.RETAINED_SECURITY_EPOCH_BLOCKS
    return value


class SmzaIdentityTests(unittest.TestCase):
    def test_both_exact_identities(self):
        for smza in (False, True):
            value = identity(smza)
            self.assertEqual(gate.validate_identity(value, "test identity"), value)

    def test_no_mixed_profile_domain(self):
        for profile, domain in ((9, 4), (6, 5), (7, 4), (9, 6)):
            value = identity(True)
            value.update(profile_wire_id=profile, domain_set=domain)
            with self.subTest(profile=profile, domain=domain):
                with self.assertRaisesRegex(gate.SuccessorAuthorizationError, "unknown or mixed"):
                    gate.validate_identity(value, "test identity")

    def test_no_cross_profile_magic_or_cap(self):
        fields = ("envelope_magic_hex", "native_leaf_magic_hex", "inner_proof_wire_magic_hex",
                  "max_proof_bytes", "max_outer_envelope_bytes", "max_inline_route_args_bytes",
                  "max_v8_pending_action_bytes")
        for smza in (False, True):
            for field in fields:
                value = identity(smza)
                value[field] = identity(not smza)[field]
                with self.subTest(smza=smza, field=field):
                    with self.assertRaises(gate.SuccessorAuthorizationError):
                        gate.validate_identity(value, "test identity")

    def test_fresh_chain_and_full_hash_width(self):
        for field, wrong in (("activation_height", 2), ("transcript_digest_bytes", 56),
                             ("proof_commitment_bytes", 56)):
            value = identity(True)
            value[field] = wrong
            if field == "activation_height":
                value["deactivation_height_exclusive"] = wrong + gate.RETAINED_SECURITY_EPOCH_BLOCKS
            with self.subTest(field=field):
                with self.assertRaises(gate.SuccessorAuthorizationError):
                    gate.validate_identity(value, "test identity")

    def test_q20_evidence_not_rebranded(self):
        gate.require_release_profile_evidence_contract(identity(False))
        with self.assertRaisesRegex(gate.SuccessorAuthorizationError, "q38 security evidence contract"):
            gate.require_release_profile_evidence_contract(identity(True))
        profile = gate.AuthorizedProfile("test-only-smza", identity(True), "config/test-only.json",
                                         "12" * 64, 164113)
        with self.assertRaisesRegex(gate.SuccessorAuthorizationError, "q38 security evidence contract"):
            gate.validate_registry_entry(profile.profile_id, profile)

    def test_unselected_still_denied_and_registry_absent(self):
        value = {"schema": gate.SELECTION_SCHEMA, "selection": "unselected",
                 "profile_id": None, "identity": None, "evidence_bundle_path": None,
                 "claim_boundary": "test-only unselected posture"}
        self.assertIsNone(gate.check_selection_document(value, ROOT, require_authorized=False))
        with self.assertRaisesRegex(gate.SuccessorAuthorizationError, "no transaction-proof successor"):
            gate.check_selection_document(value, ROOT, require_authorized=True)
        value.update(selection="selected", profile_id="test-only-smza", identity=identity(True),
                     evidence_bundle_path="config/test-only.json")
        with self.assertRaisesRegex(gate.SuccessorAuthorizationError, "absent from the source-owned"):
            gate.check_selection_document(value, ROOT, require_authorized=True, registry={})


if __name__ == "__main__":
    unittest.main()
