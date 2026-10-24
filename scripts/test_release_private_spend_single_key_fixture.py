#!/usr/bin/env python3
"""Pure custody-schema checks: no node, proof build or live wallet creation."""
import copy
import unittest

import release_private_spend_lifecycle as lifecycle


def fixture():
    signers = [
        {"wallet": {"path": "unused", "sha256": "00" * 32},
         "passphrase": {"path": "unused", "sha256": "00" * 32},
         "public": {"signer_tag": f"{i:02x}" * 56,
                    "signer_receive_address": f"public-fixture-address-{i}"}}
        for i in range(3)
    ]
    return {"schema": "hegemon.private-spend.private-release-fixture.v2",
            "chain_id": "11" * 32, "custody": "single-key",
            "funding_address": signers[0]["public"]["signer_receive_address"],
            "signers": signers}


class CustodyFixtureTests(unittest.TestCase):
    def test_single_key_has_no_private_policy_or_account(self):
        self.assertEqual(lifecycle.fixture_custody(fixture()), "single-key")

    def test_funding_recipient_cannot_differ_from_actual_custodian(self):
        value = fixture()
        value["funding_address"] = "unapproved-recipient"
        with self.assertRaisesRegex(RuntimeError, "supplied first actor"):
            lifecycle.fixture_custody(value)

    def test_all_three_lifecycle_actors_are_required(self):
        value = fixture()
        value["signers"].pop()
        with self.assertRaisesRegex(RuntimeError, "three existing"):
            lifecycle.fixture_custody(value)

    def test_duplicate_credentials_cannot_impersonate_distinct_actors(self):
        value = fixture()
        value["signers"][1] = copy.deepcopy(value["signers"][0])
        with self.assertRaisesRegex(RuntimeError, "distinct credentials"):
            lifecycle.fixture_custody(value)

    def test_unknown_fields_cannot_enable_a_bypass(self):
        value = fixture()
        value["development_candidate"] = True
        with self.assertRaisesRegex(RuntimeError, "schema"):
            lifecycle.fixture_custody(value)

    def test_existing_two_of_three_schema_remains_supported(self):
        value = fixture()
        value["schema"] = "hegemon.private-spend.private-release-fixture.v1"
        value.pop("custody")
        value.update(account_id="22" * 32, descriptor={"path": "unused", "sha256": "00" * 32})
        self.assertEqual(lifecycle.fixture_custody(value), "2-of-3")


if __name__ == "__main__":
    unittest.main()
