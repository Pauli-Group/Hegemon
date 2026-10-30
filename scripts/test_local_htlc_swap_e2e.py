#!/usr/bin/env python3
"""Daemon-free checks for the local HTLC swap harness."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import htlc_swap_lib as lib
from local_htlc_swap_e2e import core_verified


class TimeoutMarginTest(unittest.TestCase):
    def test_matches_wallet_height_and_direction_cases(self):
        # HtlcOffer::check_timeout_margin(hegemon, bitcoin, 10s, 600s, 600s)
        # on an offer whose Hegemon timeout is 1000 and Bitcoin refund is 120.
        self.assertTrue(lib.timeout_margin_holds(1, 119, 1000, 120))
        self.assertFalse(lib.timeout_margin_holds(999, 119, 1000, 120))
        self.assertFalse(lib.timeout_margin_holds(1, 120, 1000, 120))
        self.assertFalse(lib.timeout_margin_holds(1, 119, 1000, 120, hegemon_block_seconds=0))

    def test_planned_deadlines_keep_hegemon_as_the_longer_leg(self):
        timeout, refund = lib.plan_swap_deadlines(121, 101, lifetime_exclusive=10_001)
        self.assertGreater(timeout, 121)
        self.assertEqual(refund, 109)
        self.assertTrue(lib.timeout_margin_holds(121, 101, timeout, refund))
        self.assertLess(timeout, 10_001)

    def test_local_regtest_gap_stays_inside_one_retarget_stretch(self):
        from local_htlc_swap_e2e import (
            LOCAL_BTC_BLOCK_SECONDS, LOCAL_HGN_BLOCK_SECONDS, LOCAL_SAFETY_SECONDS,
        )
        timeout, refund = lib.plan_swap_deadlines(
            121, 101, 10_001,
            hegemon_block_seconds=LOCAL_HGN_BLOCK_SECONDS,
            bitcoin_block_seconds=LOCAL_BTC_BLOCK_SECONDS,
            safety_seconds=LOCAL_SAFETY_SECONDS)
        self.assertEqual(refund, 109)
        self.assertGreaterEqual(timeout - 121, 4)
        self.assertLessEqual(timeout - 121, 20)
        self.assertTrue(lib.timeout_margin_holds(
            121, 101, timeout, refund,
            LOCAL_HGN_BLOCK_SECONDS, LOCAL_BTC_BLOCK_SECONDS, LOCAL_SAFETY_SECONDS))


class RoleTest(unittest.TestCase):
    def test_alice_claim_key_is_not_in_bobs_descriptor(self):
        descriptors = lib.party_bitcoin_descriptors(
            "ab" * 32, "02" + "11" * 32, "alice-wif", "03" + "22" * 32, "bob-wif", 120)
        self.assertIn("alice-wif", descriptors["alice"])
        self.assertNotIn("bob-wif", descriptors["alice"])
        self.assertIn("bob-wif", descriptors["bob"])
        self.assertNotIn("alice-wif", descriptors["bob"])
        self.assertNotIn("wif", descriptors["public"])
        self.assertIn("02" + "11" * 32, descriptors["public"])
        self.assertIn("03" + "22" * 32, descriptors["public"])


class ManifestTest(unittest.TestCase):
    def test_private_spend_only_pin_is_removed_and_pow_is_easy(self):
        manifest = lib.htlc_capable_manifest({
            "profile": "development",
            "pow_bits": 123,
            "development_candidate": {
                "private_spend_only": True,
                "private_spend_source": {"relation_digest": "abc"},
                "activation_height": 1,
                "max_proof_bytes": 64,
            },
        })
        candidate = manifest["development_candidate"]
        self.assertNotIn("private_spend_only", candidate)
        self.assertNotIn("private_spend_source", candidate)
        self.assertEqual(candidate["activation_height"], 1)
        self.assertEqual(candidate["max_proof_bytes"], lib.HTLC_MAX_PROOF_BYTES)
        self.assertEqual(manifest["pow_bits"], lib.EASY_POW_BITS)

    def test_non_development_manifest_is_refused(self):
        with self.assertRaises(lib.RehearsalError):
            lib.htlc_capable_manifest({"profile": "mainnet", "development_candidate": {}})


class BoundaryTest(unittest.TestCase):
    def test_rpc_must_be_loopback(self):
        lib.require_loopback_http("http://127.0.0.1:9944")
        with self.assertRaises(lib.RehearsalError):
            lib.require_loopback_http("http://example.com:9944")
        with self.assertRaises(lib.RehearsalError):
            lib.require_loopback_http("https://127.0.0.1:9944")

    def test_private_root_must_be_empty(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            fresh = parent / "empty"
            lib.require_fresh_directory(fresh)
            (fresh / "leftover").write_text("x")
            with self.assertRaises(lib.RehearsalError):
                lib.require_fresh_directory(fresh)

    def test_core_cache_requires_the_pinned_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = Path(raw)
            self.assertFalse(core_verified(cache))


if __name__ == "__main__":
    unittest.main()
