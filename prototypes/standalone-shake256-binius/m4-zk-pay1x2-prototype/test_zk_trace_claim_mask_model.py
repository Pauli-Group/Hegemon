#!/usr/bin/env python3
"""Property and fail-closed tests for the trace-claim mask model."""

from __future__ import annotations

import random
import unittest

from zk_trace_claim_mask_model import (
    B128_MASK,
    ClearClaimInventory,
    add,
    derive_test_key,
    eq_basis,
    evaluate,
    masked_claim,
    release_gate,
    shift_trace,
    verify_shift_identity,
)


class TraceClaimMaskModelTests(unittest.TestCase):
    def test_eq_basis_sums_to_one_and_shift_has_no_bad_point(self) -> None:
        rng = random.Random(0x484547454D4F4E)
        for n_vars in range(0, 9):
            for _ in range(12):
                point = tuple(rng.getrandbits(128) for _ in range(n_vars))
                trace = tuple(rng.getrandbits(128) for _ in range(1 << n_vars))
                key = rng.getrandbits(128)
                basis_sum = 0
                for value in eq_basis(point):
                    basis_sum = add(basis_sum, value)
                self.assertEqual(basis_sum, 1)
                claim = masked_claim(trace, point, key)
                self.assertTrue(verify_shift_identity(trace, point, key, claim))
                self.assertEqual(evaluate(shift_trace(trace, key), point), claim)

    def test_claim_is_one_time_pad_but_key_reuse_leaks_claim_difference(self) -> None:
        # XOR by a fixed secret claim permutes the entire B128 key space, so a
        # uniform key makes c uniform.  The executable test checks a complete
        # 8-bit projection of that permutation rather than sampling it.
        secret = 0xA7
        outputs = {secret ^ key for key in range(256)}
        self.assertEqual(outputs, set(range(256)))

        point = (3, 5)
        left = (1, 2, 3, 4)
        right = (9, 8, 7, 6)
        key = 11
        leaked = add(masked_claim(left, point, key), masked_claim(right, point, key))
        self.assertEqual(leaked, add(evaluate(left, point), evaluate(right, point)))

    def test_compiler_inventory_is_exact_and_fail_closed(self) -> None:
        eligible = ClearClaimInventory(1, 0, 0, 0, True)
        self.assertTrue(eligible.eligible)
        self.assertFalse(release_gate(eligible)["complete_zero_knowledge"])
        for rejected in (
            ClearClaimInventory(0, 0, 0, 0, True),
            ClearClaimInventory(2, 0, 0, 0, True),
            ClearClaimInventory(1, 1, 0, 0, True),
            ClearClaimInventory(1, 0, 1, 0, True),
            ClearClaimInventory(1, 0, 0, 1, True),
            ClearClaimInventory(1, 0, 0, 0, False),
        ):
            self.assertFalse(rejected.eligible)
            self.assertTrue(rejected.rejection_reasons())
            self.assertFalse(release_gate(rejected)["frontier_eligible"])

    def test_test_key_derivation_binds_statement_and_nonce(self) -> None:
        entropy = bytes(range(32))
        statement = bytes(range(64))
        nonce = bytes(reversed(range(32)))
        baseline = derive_test_key(entropy, statement, nonce)
        self.assertLessEqual(baseline, B128_MASK)
        changed_statement = bytearray(statement)
        changed_statement[0] ^= 1
        changed_nonce = bytearray(nonce)
        changed_nonce[-1] ^= 1
        self.assertNotEqual(
            baseline, derive_test_key(entropy, bytes(changed_statement), nonce)
        )
        self.assertNotEqual(
            baseline, derive_test_key(entropy, statement, bytes(changed_nonce))
        )
        with self.assertRaises(ValueError):
            derive_test_key(b"short", statement, nonce)


if __name__ == "__main__":
    unittest.main()
