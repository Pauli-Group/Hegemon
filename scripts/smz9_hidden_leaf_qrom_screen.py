#!/usr/bin/env python3
"""Exact arithmetic for one conditional SMZ9 hidden-leaf hybrid, not a security certificate.

The external adaptive-reprogramming theorem and its source-shaped reduction are
documented in docs/crypto/smz9-campaign/hidden-leaf-qrom-step.md. This diagnostic
checks their displayed formula only; it neither proves that theorem nor supplies
runtime randomness, complete privacy, or a permitted production history budget.
"""

import argparse
import json
from math import log2, sqrt
import unittest

LEAVES_PER_PROOF = 2**23


def term_at_most(other_queries: int, attempts: int, query_multiplier: int = 1,
                 target_bits: int = 128) -> bool:
    """Exact comparison after isolating the square root and checking its sign."""
    if min(other_queries, attempts) < 0 or query_multiplier not in (1, 2):
        raise ValueError('nonnegative counts and multiplier one or two required')
    if not 0 <= target_bits <= 513:
        raise ValueError('target bits must be between zero and 513')
    programs = attempts * LEAVES_PER_PROOF
    queries = query_multiplier * other_queries + programs
    remainder = 2 ** (513 - target_bits) - programs * queries
    return remainder >= 0 and programs**2 * queries * 2**514 <= remainder**2


def maximum_attempts(other_queries: int, query_multiplier: int = 1) -> int:
    lower, upper = 0, 1
    while term_at_most(other_queries, upper, query_multiplier):
        lower, upper = upper, upper * 2
    while upper - lower > 1:
        middle = (upper + lower) // 2
        if term_at_most(other_queries, middle, query_multiplier):
            lower = middle
        else:
            upper = middle
    return lower


def approximate_bits(other_queries: int, attempts: int, query_multiplier: int) -> float:
    programs = attempts * LEAVES_PER_PROOF
    queries = query_multiplier * other_queries + programs
    # Decimals explain magnitude only; never determine a pass/fail result.
    return -log2(programs * sqrt(queries) / 2**256 + programs * queries / 2**513)


def report() -> dict:
    cases = []
    for multiplier in (1, 2):
        for exponent in (64, 128):
            other = 2**exponent
            maximum = maximum_attempts(other, multiplier)
            case = {'accounting': 'inclusive raw oracle' if multiplier == 1 else
                    'independent complement table and two-query full-oracle simulation',
                    'other_queries_power_of_two': exponent,
                    'general_query_multiplier': multiplier,
                    'maximum_attempts_for_isolated_128_bit_formula': maximum,
                    'maximum_passes_exact': term_at_most(other, maximum, multiplier),
                    'successor_fails_exact': not term_at_most(other, maximum + 1, multiplier),
                    'approximate_bits_at_one_proof': approximate_bits(other, 1, multiplier),
                    'approximate_bits_at_2pow74_attempts': approximate_bits(other, 2**74, multiplier)}
            if multiplier == 1:
                case['necessary_full_proof_count_limit_from_internal_merkle_queries'] = \
                    other // (LEAVES_PER_PROOF - 1)
                case['merkle_count_caveat'] = 'Necessary only; excludes all other honest costs, '
                case['merkle_count_caveat'] += 'and applies to full proofs, not every aborted attempt.'
            cases.append(case)
    return {'leaf_events_per_attempt_upper_bound': LEAVES_PER_PROOF,
            'fresh_tape_bits': 512,
            'cases': cases,
            'claim_boundary': 'The entire 2^-128 allocation is assigned to one externally justified '
                              'ideal-QROM transition. These are not attacks above the thresholds, '
                              'whole-privacy bounds, feasible budgets without query accounting, '
                              'or protocol-authorized history limits.'}


class ArithmeticTests(unittest.TestCase):
    def test_known_exact_boundaries(self):
        expected = {(1, 64): 5810359557114882582,
                    (1, 128): 2199023255551,
                    (2, 64): 5810358824107408150,
                    (2, 128): 1554944255987}
        for (multiplier, exponent), maximum in expected.items():
            self.assertEqual(maximum_attempts(2**exponent, multiplier), maximum)
            self.assertTrue(term_at_most(2**exponent, maximum, multiplier))
            self.assertFalse(term_at_most(2**exponent, maximum + 1, multiplier))

    def test_zero_and_validation(self):
        self.assertTrue(term_at_most(2**1024, 0))
        for other, attempts, multiplier in ((-1, 1, 1), (1, -1, 1), (1, 1, 0)):
            with self.assertRaises(ValueError):
                term_at_most(other, attempts, multiplier)

    def test_inclusive_operational_constraint(self):
        self.assertEqual(2**64 // (LEAVES_PER_PROOF - 1), 2199023517696)
        self.assertLess(2**64 // (LEAVES_PER_PROOF - 1), maximum_attempts(2**64))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArithmeticTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not result.wasSuccessful())
    print(json.dumps(report(), indent=2))


if __name__ == '__main__':
    main()
