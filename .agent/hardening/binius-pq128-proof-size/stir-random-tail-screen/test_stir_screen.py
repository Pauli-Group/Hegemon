#!/usr/bin/env python3
"""Dependency-free tests for the STIR random-tail byte screen."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("stir_screen.py")
SPEC = importlib.util.spec_from_file_location("stir_screen", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
stir = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stir
SPEC.loader.exec_module(stir)


class StirScreenTests(unittest.TestCase):
    def test_reference_repetitions(self) -> None:
        self.assertEqual(stir.reference_provable_repetitions(4), 66)
        self.assertEqual(stir.reference_provable_repetitions(5), 53)
        self.assertEqual(stir.reference_provable_repetitions(9), 30)

    def test_direct_bcs_salt_is_tree_specific(self) -> None:
        self.assertEqual(stir.direct_bcs_salt_bytes(1 << 18), 148)
        self.assertEqual(stir.direct_bcs_salt_bytes(1 << 17), 147)

    def test_paper_query_floor_includes_lambda_plus_one(self) -> None:
        self.assertEqual(stir.paper_provable_query_floor(0, 5), 54)
        self.assertEqual(stir.paper_provable_query_floor(1, 6), 45)
        self.assertEqual(stir.paper_provable_query_floor(2, 7), 38)

    def test_rate_improves_after_every_factor_four_fold(self) -> None:
        rounds = stir.round_schedule(5, 32)
        self.assertEqual(
            [item.degree_before_fold for item in rounds],
            [32768, 8192, 2048, 512, 128],
        )
        self.assertEqual(
            [item.codeword_symbols for item in rounds],
            [1048576, 524288, 262144, 131072, 65536],
        )
        self.assertEqual([item.log_inverse_rate for item in rounds], [5, 6, 7, 8, 9])

    def test_initial_union_shares_only_one_tree(self) -> None:
        candidate = stir.profile(
            digest_bytes=56,
            salt_bytes=32,
            starting_rate_log=5,
            stopping_degree=32,
        )
        self.assertEqual(candidate.initial_opened_leaves_union, 108)
        expected = stir.opening_cost(
            leaf_count=1 << 18,
            opened_leaves=108,
            symbol_bytes=16,
            digest_bytes=56,
            salt_bytes=32,
        )
        self.assertEqual(candidate.initial_opening_bytes, expected.total_bytes)

    def test_later_oracles_are_wide_and_branch_local(self) -> None:
        candidate = stir.profile(
            digest_bytes=56,
            salt_bytes=32,
            starting_rate_log=5,
            stopping_degree=32,
        )
        rounds = stir.round_schedule(5, 32)
        expected = 0
        for shape in rounds[1:]:
            per_branch = stir.opening_cost(
                leaf_count=shape.codeword_symbols * 2 // 4,
                opened_leaves=shape.queries_per_branch * 2,
                symbol_bytes=16,
                digest_bytes=56,
                salt_bytes=32,
            )
            expected += 2 * per_branch.total_bytes
        self.assertEqual(candidate.later_opening_bytes, expected)

    def test_terminal_polynomial_is_e256_per_branch(self) -> None:
        candidate = stir.profile(
            digest_bytes=56,
            salt_bytes=32,
            starting_rate_log=5,
            stopping_degree=32,
        )
        self.assertEqual(candidate.final_e256_elements, 64)
        self.assertEqual(candidate.final_polynomial_bytes, 2_048)

    def test_reference_source_serializes_recomputable_polynomials(self) -> None:
        candidate = stir.profile(
            digest_bytes=56,
            salt_bytes=32,
            starting_rate_log=5,
            stopping_degree=32,
        )
        self.assertGreater(candidate.reference_extra_e256_elements, 0)
        self.assertEqual(
            candidate.reference_raw_bytes,
            candidate.canonical_raw_bytes + candidate.reference_extra_bytes,
        )

    def test_sha512_never_beats_sha448_for_same_geometry(self) -> None:
        for rate in (4, 5):
            for stop in (2, 8, 32, 128, 512, 2048, 8192):
                short = stir.profile(
                    digest_bytes=56,
                    salt_bytes=32,
                    starting_rate_log=rate,
                    stopping_degree=stop,
                )
                long = stir.profile(
                    digest_bytes=64,
                    salt_bytes=32,
                    starting_rate_log=rate,
                    stopping_degree=stop,
                )
                self.assertGreater(long.canonical_raw_bytes, short.canonical_raw_bytes)

    def test_direct_bcs_salt_floor_increases_every_opening(self) -> None:
        compact = stir.profile(
            digest_bytes=64,
            salt_bytes=32,
            starting_rate_log=5,
            stopping_degree=512,
        )
        theorem_scoped = stir.profile(
            digest_bytes=64,
            salt_bytes=148,
            starting_rate_log=5,
            stopping_degree=512,
        )
        self.assertTrue(theorem_scoped.direct_bcs_salt_n18_priced)
        self.assertFalse(theorem_scoped.direct_bcs_common_lambda_parameter_match)
        self.assertGreater(
            theorem_scoped.canonical_raw_bytes,
            compact.canonical_raw_bytes,
        )

    def test_best_strict_transport_floor_does_not_fit(self) -> None:
        strict = stir.report()["best_strict_transport_floor"]
        self.assertEqual(strict["digest_bytes"], 64)
        self.assertEqual(strict["salt_bytes"], 148)
        self.assertFalse(strict["direct_bcs_common_lambda_parameter_match"])
        self.assertFalse(strict["canonical_fits"])

    def test_strict_floor_fails_even_with_free_authentication(self) -> None:
        floor = stir.report()["best_strict_authentication_free_floor"]
        self.assertEqual(floor["digest_bytes"], 64)
        self.assertEqual(floor["salt_bytes"], 148)
        self.assertFalse(floor["authentication_free_fits"])
        self.assertEqual(
            floor["authentication_free_raw_bytes"],
            floor["canonical_raw_bytes"] - floor["authentication_bytes"],
        )

    def test_all_authority_gates_fail_closed(self) -> None:
        payload = stir.report()
        self.assertFalse(payload["gates"]["published_stir_on_characteristic_two_additive_domain"])
        self.assertFalse(payload["gates"]["strict_admitted"])
        self.assertTrue(all(not item.strict_admitted for item in stir.all_profiles()))

    def test_no_profile_covers_conservative_static_tail(self) -> None:
        self.assertTrue(
            all(not item.covers_static_tail_interval for item in stir.all_profiles())
        )


if __name__ == "__main__":
    unittest.main()
