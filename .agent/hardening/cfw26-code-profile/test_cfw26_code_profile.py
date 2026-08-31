#!/usr/bin/env python3
"""Focused controls for the exact CFW26 code/profile screen."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from fractions import Fraction
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("cfw26_code_profile.py")
SPEC = importlib.util.spec_from_file_location("cfw26_code_profile_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
profile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profile
SPEC.loader.exec_module(profile)


class GeometryTests(unittest.TestCase):
    def test_exact_105_oracles(self) -> None:
        document = profile.build_profile()
        records = document["section11_oracles"]["records"]
        self.assertEqual(len(records), 105)
        self.assertEqual(sum(row["role"] == "main" for row in records), 1)
        self.assertEqual(sum(row["role"] == "inner-mask" for row in records), 78)
        self.assertEqual(sum(row["role"] == "outer-mask" for row in records), 26)

    def test_exact_interactive_p(self) -> None:
        document = profile.build_profile()
        self.assertEqual(document["interactive_proof"]["field_elements"], 168_040_165)
        self.assertEqual(document["interactive_proof"]["bits_p_of_x"], 53_772_852_800)
        self.assertEqual(document["interactive_proof"]["bytes"], 6_721_606_600)
        self.assertEqual(sum(row["message_bits"] for row in document["interactive_proof"]["round_messages"]), 53_772_852_800)

    def test_unique_decoding_radii_and_spotchecks(self) -> None:
        self.assertLess(2 * profile.MAIN_DELTA, profile.MAIN_DISTANCE)
        self.assertLess(2 * profile.MASK_DELTA, profile.MASK_DISTANCE)
        self.assertLess((1 - profile.MAIN_DELTA) ** 512, Fraction(1, 1 << 128))
        self.assertLess((1 - profile.MASK_DELTA) ** 512, Fraction(1, 1 << 128))


class EncodingTests(unittest.TestCase):
    def test_small_field_two_query_perfect_simulation(self) -> None:
        left = profile.toy_simulator_distribution((3, 7), (0, 3))
        right = profile.toy_simulator_distribution((14, 2), (0, 3))
        self.assertEqual(left, right)
        self.assertEqual(len(left), 17**2)
        self.assertEqual(set(left.values()), {1})

    def test_query_verifier_rejects_mutation(self) -> None:
        modulus = 257
        domain = tuple(range(1, 9))
        f = profile.rs_encode((4, 9), (2, 6), domain, modulus)
        g = profile.rs_encode((8, 3), (1, 7), domain, modulus)
        gamma = 13
        combined = tuple((a + gamma * b) % modulus for a, b in zip(g, f, strict=True))
        self.assertTrue(profile.verify_linear_combination_queries(g, f, combined, gamma, (1, 5), modulus))
        forged = list(combined)
        forged[5] = (forged[5] + 1) % modulus
        self.assertFalse(profile.verify_linear_combination_queries(g, f, forged, gamma, (1, 5), modulus))

    def test_e320_encoding_is_exact_and_canonical(self) -> None:
        values = (0, 1, 2, 3, profile.GOLDILOCKS_MODULUS - 1)
        encoded = profile.encode_e320(values)
        self.assertEqual(len(encoded), 40)
        self.assertEqual(profile.decode_e320(encoded), values)
        with self.assertRaises(profile.ProfileError):
            profile.encode_e320((0, 1, 2, 3, profile.GOLDILOCKS_MODULUS))
        with self.assertRaises(profile.ProfileError):
            profile.decode_e320(encoded + b"\0")


class BcsAndAdmissionTests(unittest.TestCase):
    def test_exact_bcs_boundary(self) -> None:
        self.assertFalse(profile.strict_below_pow2(profile.bcs_privacy_term(profile.TOTAL_INTERACTIVE_BITS, 660), 128))
        self.assertTrue(profile.strict_below_pow2(profile.bcs_privacy_term(profile.TOTAL_INTERACTIVE_BITS, 664), 128))
        self.assertEqual(profile.minimum_bcs_lambda_byte_aligned(profile.TOTAL_INTERACTIVE_BITS), 664)

    def test_exact_wire_projections_stay_nonproofs(self) -> None:
        document = profile.build_profile()
        self.assertEqual(document["bcs_bit_leaf_wire_projection"]["projected_wire_bytes"], 32_252_325_377_789)
        self.assertEqual(document["field_symbol_batching_projection"]["projected_wire_bytes"], 1_458_868_874)
        self.assertIsNone(document["proof_bytes"])
        self.assertFalse(document["production_authorized"])
        self.assertTrue(document["admission"]["disqualified"])

    def test_validator_rejects_security_overclaim(self) -> None:
        document = profile.build_profile()
        document["security"]["cfw_theorem_inherited"] = True
        profile.refresh_profile_digest(document)
        with self.assertRaises(profile.ProfileError):
            profile.validate_profile(document)


if __name__ == "__main__":
    unittest.main()
