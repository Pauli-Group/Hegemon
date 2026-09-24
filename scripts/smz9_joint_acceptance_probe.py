#!/usr/bin/env python3
"""Exhaustive SMALL-FIELD DECS agreement diagnostic, not a security certificate.

Source words and masks are fixed before a uniform matrix. Responses may depend
on that matrix but are fixed before a fresh uniform subset of query positions.
This probe maximizes over responses via all interpolation supports, counts
exact probabilities, and independently checks the optimization on tiny cases.
It neither implements a witness extractor nor models Fiat-Shamir/QROM queries.
"""

from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
from itertools import combinations, product
import json
from math import comb, log2
import unittest


def rank_mod(rows: list[list[int]], modulus: int) -> int:
    """Gaussian elimination over a prime field; does not mutate its input."""
    if not rows:
        return 0
    matrix = [[value % modulus for value in row] for row in rows]
    pivot_row = 0
    for column in range(len(matrix[0])):
        pivot = next((i for i in range(pivot_row, len(matrix))
                      if matrix[i][column]), None)
        if pivot is None:
            continue
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        inverse = pow(matrix[pivot_row][column], -1, modulus)
        matrix[pivot_row] = [(v * inverse) % modulus for v in matrix[pivot_row]]
        for i in range(len(matrix)):
            if i != pivot_row:
                factor = matrix[i][column]
                matrix[i] = [(a - factor * b) % modulus
                             for a, b in zip(matrix[i], matrix[pivot_row])]
        pivot_row += 1
        if pivot_row == len(matrix):
            break
    return pivot_row


def interpolate_at(points: tuple[int, ...], values: tuple[int, ...],
                   target: int, modulus: int) -> int:
    value = 0
    for i, point in enumerate(points):
        numerator = denominator = 1
        for j, other in enumerate(points):
            if i != j:
                numerator = numerator * (target - other) % modulus
                denominator = denominator * (point - other) % modulus
        value += values[i] * numerator * pow(denominator, -1, modulus)
    return value % modulus


def residual_vectors(domain: tuple[int, ...], words: tuple[tuple[int, ...], ...],
                     support: tuple[int, ...], dimension: int,
                     modulus: int) -> list[list[int]]:
    anchors = support[:dimension]
    points = tuple(domain[i] for i in anchors)
    return [[(word[index] - interpolate_at(
        points, tuple(word[i] for i in anchors), domain[index], modulus)) % modulus
        for word in words] for index in support[dimension:]]


def validate(modulus: int, domain: tuple[int, ...], dimension: int,
             words: tuple[tuple[int, ...], ...],
             masks: tuple[tuple[int, ...], ...], queries: int) -> None:
    if modulus < 2 or any(modulus % d == 0 for d in range(2, int(modulus**0.5) + 1)):
        raise ValueError('modulus must be prime')
    if len(set(domain)) != len(domain) or any(not 0 <= x < modulus for x in domain):
        raise ValueError('domain must have distinct canonical field elements')
    if not 1 <= dimension < len(domain) or not 1 <= queries <= len(domain):
        raise ValueError('invalid code dimension or query count')
    if not words or not masks:
        raise ValueError('at least one data word and mask row required')
    if any(len(word) != len(domain) for word in words + masks):
        raise ValueError('all words must have the domain length')
    if any(not 0 <= x < modulus for word in words + masks for x in word):
        raise ValueError('word values must be canonical')
    if modulus ** (len(words) * len(masks)) > 1_000_000:
        raise ValueError('exhaustive matrix budget exceeds one million')


def rational(value: Fraction) -> dict[str, int | float | None]:
    return {'numerator': value.numerator, 'denominator': value.denominator,
            'negative_log2': None if not value else
            log2(value.denominator) - log2(value.numerator)}


def analyze_source(modulus: int, domain: tuple[int, ...], dimension: int,
                   words: tuple[tuple[int, ...], ...],
                   masks: tuple[tuple[int, ...], ...], queries: int) -> dict:
    validate(modulus, domain, dimension, words, masks, queries)
    length, width, eta = len(domain), len(words), len(masks)
    # Descending support size lets the least set bit identify maximal agreement.
    supports = [support for size in range(length, dimension, -1)
                for support in combinations(range(length), size)]
    data_residuals = [residual_vectors(domain, words, s, dimension, modulus)
                      for s in supports]
    mask_residuals = [residual_vectors(domain, masks, s, dimension, modulus)
                      for s in supports]
    ranks = [rank_mod(residual, modulus) for residual in data_residuals]
    coefficients = tuple(product(range(modulus), repeat=width))
    # For each matrix row, precompute every support whose response interpolant
    # exists. A mask is fixed data, so row-specific affine targets are retained.
    row_bits = []
    for row in range(eta):
        choices = []
        for coefficient in coefficients:
            accepted = 0
            for index, (data, mask) in enumerate(zip(data_residuals, mask_residuals)):
                if all((sum(a * b for a, b in zip(coefficient, residual)) +
                        mask[j][row]) % modulus == 0
                       for j, residual in enumerate(data)):
                    accepted |= 1 << index
            choices.append(accepted)
        row_bits.append(choices)
    bad_bits = sum(1 << i for i, rank in enumerate(ranks) if rank > 0)
    histogram: Counter[int] = Counter()
    bad_histogram: Counter[int] = Counter()
    rank_size_masks = {(a, r): sum(1 << i for i, s in enumerate(supports)
                                 if len(s) >= a and ranks[i] >= r)
                       for a in range(dimension + 1, length + 1)
                       for r in range(1, min(width, length - dimension) + 1)}
    tail_counts: Counter[tuple[int, int]] = Counter()
    weighted_tail_counts: Counter[tuple[int, int]] = Counter()
    all_bits = (1 << len(supports)) - 1
    for selected_rows in product(*row_bits):
        accepted = all_bits
        for selected in selected_rows:
            accepted &= selected
        best = len(supports[(accepted & -accepted).bit_length() - 1]) \
            if accepted else dimension
        histogram[best] += 1
        bad = accepted & bad_bits
        best_bad = len(supports[(bad & -bad).bit_length() - 1]) if bad else 0
        bad_histogram[best_bad] += 1
        for key, event_bits in rank_size_masks.items():
            qualifying = accepted & event_bits
            if qualifying:
                tail_counts[key] += 1
                size = len(supports[(qualifying & -qualifying).bit_length() - 1])
                weighted_tail_counts[key] += comb(size, queries)
    matrices = modulus ** (width * eta)
    sample_count = comb(length, queries)
    acceptance = Fraction(sum(count * comb(size, queries)
                              for size, count in histogram.items()), matrices * sample_count)
    bad_acceptance = Fraction(sum(count * comb(size, queries)
                                  for size, count in bad_histogram.items()), matrices * sample_count)
    existence = Fraction(matrices - bad_histogram[0], matrices)
    # Check all applicable fixed-support affine counts independently of unioning.
    support_checks = 0
    for i, rank in enumerate(ranks):
        allowed_counts = [sum(bool(bits & (1 << i)) for bits in rows) for rows in row_bits]
        expected_nonzero = modulus ** (width - rank)
        if any(count not in (0, expected_nonzero) for count in allowed_counts):
            raise AssertionError('fixed-support affine rank count failed')
        support_checks += 1
    tails = []
    for (threshold, rank), event_bits in rank_size_masks.items():
        minimum_size = max(threshold, dimension + rank)
        if minimum_size > length:
            bound = Fraction(0)
        else:
            bound = Fraction(comb(length, dimension) * comb(length - dimension, rank),
                             comb(minimum_size, dimension) * modulus ** (eta * rank))
        observed = Fraction(tail_counts[threshold, rank], matrices)
        if observed > bound:
            raise AssertionError(f'high-rank incidence bound failed: {(threshold, rank)}')
        tail = {'minimum_agreement': threshold, 'minimum_residual_rank': rank,
                'observed': rational(observed), 'incidence_upper_bound': rational(bound)}
        if queries <= dimension:
            # Do NOT first clamp bound to one: the binomial ratio is evaluated
            # at the threshold, not the adversary's possibly larger agreement.
            weighted_bound = bound * Fraction(comb(minimum_size, queries), sample_count)
            weighted = Fraction(weighted_tail_counts[threshold, rank], matrices * sample_count)
            if weighted > weighted_bound:
                raise AssertionError(f'weighted incidence bound failed: {(threshold, rank)}')
            tail.update(sampled_observed=rational(weighted),
                        sampled_incidence_upper_bound=rational(weighted_bound))
        tails.append(tail)
    return {'modulus': modulus, 'domain': list(domain), 'dimension': dimension,
            'data_rows': width, 'matrix_rows': eta, 'queries': queries,
            'matrices_enumerated': matrices, 'support_rank_checks': support_checks,
            'maximum_agreement_histogram': dict(sorted(histogram.items())),
            'bad_completion_agreement_histogram': dict(sorted(bad_histogram.items())),
            'bad_completion_exists_probability': rational(existence),
            'optimal_sampled_acceptance_probability': rational(acceptance),
            'optimal_sampled_bad_completion_probability': rational(bad_acceptance),
            'high_rank_tail_checks': tails,
            'bad_completion_definition': 'A response full-agreement set on which some fixed '
                                         'data word is not a degree-bounded codeword; this '
                                         'does not imply witness extraction failure.',
            'claim_boundary': 'Exact small-field ideal experiment, not witness extraction, '
                              'Goldilocks security, Fiat-Shamir, or quantum security.'}


def brute_response_histogram(modulus, domain, dimension, words, masks):
    """Independent literal response enumeration; used only for tiny test cases."""
    polynomials = [tuple(sum(c * pow(x, i, modulus) for i, c in enumerate(coeff)) % modulus
                         for x in domain)
                   for coeff in product(range(modulus), repeat=dimension)]
    histogram = Counter()
    for matrix in product(tuple(product(range(modulus), repeat=len(words))), repeat=len(masks)):
        combined = [tuple((sum(c * w[i] for c, w in zip(row, words)) + mask[i]) % modulus
                          for i in range(len(domain))) for row, mask in zip(matrix, masks)]
        best = max(sum(all(combined[j][i] == response[j][i] for j in range(len(masks)))
                       for i in range(len(domain)))
                   for response in product(polynomials, repeat=len(masks)))
        histogram[best] += 1
    return dict(sorted(histogram.items()))


def current_profile_screen() -> dict:
    """Exact arithmetic for a CONDITIONAL rank partition, never a security receipt."""
    modulus, length, dimension, queries, eta = 2**64 - 2**32 + 1, 2**23, 388, 20, 5
    rows = []
    for threshold, rank in [(400, 21), (410, 20), (416, 20), (448, 20), (512, 20)]:
        minimum = max(threshold, dimension + rank)
        incidence = Fraction(comb(length, dimension) * comb(length - dimension, rank),
                             comb(minimum, dimension) * modulus ** (eta * rank))
        weighted = incidence * Fraction(comb(minimum, queries), comb(length, queries))
        small = Fraction(comb(threshold - 1, queries), comb(length, queries))
        total = small + weighted
        # This sum bounds only small agreement OR sufficiently high residual
        # rank. It deliberately does not cover the low-rank/large-agreement case.
        largest_floor = total.denominator.bit_length() - total.numerator.bit_length()
        while total > Fraction(1, 2**largest_floor):
            largest_floor -= 1
        rows.append({'large_agreement_threshold': threshold, 'high_rank_cutoff': rank,
                     'unweighted_tail_bits': log2(incidence.denominator) - log2(incidence.numerator),
                     'sampled_high_rank_bits': log2(weighted.denominator) - log2(weighted.numerator),
                     'small_agreement_bits': log2(small.denominator) - log2(small.numerator),
                     'partial_sum_bits': log2(total.denominator) - log2(total.numerator),
                     'partial_sum_exact_integer_floor': largest_floor,
                     'exact_floor_check': total.numerator * 2**largest_floor <= total.denominator,
                     'uncovered_residual_ranks': [1, rank - 1]})
    return {'reference_parameters': {'p': modulus, 'N': length, 'k': dimension,
                                    'queries': queries, 'matrix_rows': eta},
            'cases': rows,
            'claim_boundary': 'Conditional ideal-sampling arithmetic for the derived incidence '
                              'argument. Low-rank large-agreement extraction, runtime sampling '
                              'and quantum security remain unproved.'}


def patch_cover_screen() -> dict:
    """Conditional arithmetic for a verified fixed patch cover; no source coverage claim."""
    modulus, length, degree, queries, eta = 2**64 - 2**32 + 1, 2**23, 387, 20, 5
    rows = []
    for patches, exceptions in ((1, 0), (2, 0), (2, 274), (2, 275), (3, 0)):
        cutoff = patches * degree + exceptions
        small = Fraction(comb(cutoff, queries), comb(length, queries))
        mismatch = Fraction(patches, modulus**eta)
        total = small + mismatch
        illustrative_scaled = total * (12 * 2**128)
        rows.append({'fixed_patches': patches, 'uncovered_positions': exceptions,
                     'small_agreement_cutoff': cutoff,
                     'small_agreement_bits': log2(small.denominator) - log2(small.numerator),
                     'fixed_family_mismatch_bits': log2(mismatch.denominator) - log2(mismatch.numerator),
                     'conditional_classical_sum_bits': log2(total.denominator) - log2(total.numerator),
                     'isolated_12Q2_bits_at_Q_2pow64':
                         log2(illustrative_scaled.denominator) - log2(illustrative_scaled.numerator),
                     'isolated_strict_128_exact_check':
                         illustrative_scaled.numerator * 2**128 < illustrative_scaled.denominator})
    return {'reference_parameters': {'p': modulus, 'N': length, 'degree': degree,
                                    'queries': queries, 'matrix_rows': eta},
            'cases': rows,
            'claim_boundary': 'Requires an independently verified fixed polynomial patch cover. '
                              'The isolated 12Q^2 multiplication is arithmetic, not a proved CMS '
                              'reduction. Arbitrary-source coverage, semantic extraction, all other '
                              'losses and quantum security remain unproved.'}


class ProbeTests(unittest.TestCase):
    def test_rank(self):
        self.assertEqual(rank_mod([[1, 2], [2, 4]], 5), 1)
        self.assertEqual(rank_mod([[1, 2], [2, 0]], 5), 2)
        self.assertEqual(rank_mod([[0, 0]], 5), 0)

    def test_interpolation(self):
        for x in range(5):
            self.assertEqual(interpolate_at((0, 1), (2, 0), x, 5), (2 + 3 * x) % 5)

    def test_literal_response_enumeration(self):
        cases = [
            (3, (0, 1, 2), 1, ((0, 1, 1), (1, 0, 1)), ((0, 0, 0),)),
            (3, (0, 1, 2), 1, ((0, 1, 1),), ((0, 1, 0), (1, 0, 0))),
            (5, (1, 2, 4, 3), 2, ((1, 4, 1, 4),), ((0, 0, 0, 0),)),
        ]
        for case in cases:
            with self.subTest(case=case):
                report = analyze_source(*case, queries=2)
                self.assertEqual(report['maximum_agreement_histogram'],
                                 brute_response_histogram(*case))

    def test_codeword_source(self):
        report = analyze_source(5, (1, 2, 4, 3), 2,
                                ((1, 2, 4, 3),), ((0, 0, 0, 0),), 2)
        self.assertEqual(report['optimal_sampled_acceptance_probability']['numerator'], 1)
        self.assertEqual(report['bad_completion_exists_probability']['numerator'], 0)

    def test_existence_is_not_sampled_acceptance(self):
        domain = (1, 2, 4, 3)
        words = tuple(tuple(pow(x, degree, 5) for x in domain) for degree in (2, 3))
        report = analyze_source(5, domain, 2, words, ((0, 0, 0, 0),), 3)
        existence = report['bad_completion_exists_probability']
        sampled = report['optimal_sampled_bad_completion_probability']
        self.assertGreater(Fraction(existence['numerator'], existence['denominator']),
                           Fraction(sampled['numerator'], sampled['denominator']))

    def test_invalid_parameters(self):
        for modulus, domain in [(4, (0, 1, 2)), (5, (0, 0, 1))]:
            with self.assertRaises(ValueError):
                analyze_source(modulus, domain, 1, ((0, 0, 0),), ((0, 0, 0),), 2)

    def test_current_parameter_partial_screens(self):
        rows = current_profile_screen()['cases']
        self.assertEqual(rows[2]['partial_sum_exact_integer_floor'], 286)
        self.assertTrue(all(row['exact_floor_check'] for row in rows))

    def test_weighted_incidence_with_affine_masks(self):
        domain = tuple(range(1, 7))
        words = tuple(tuple(pow(x, degree, 7) for x in domain) for degree in (3, 4))
        masks = ((0,) * 6, tuple(pow(x, 5, 7) for x in domain))
        report = analyze_source(7, domain, 3, words, masks, 2)
        self.assertEqual(report['matrices_enumerated'], 2401)
        self.assertTrue(all('sampled_incidence_upper_bound' in row
                            for row in report['high_rank_tail_checks']))

    def test_patch_cover_exact_screen(self):
        cases = patch_cover_screen()['cases']
        self.assertEqual([case['isolated_strict_128_exact_check'] for case in cases],
                         [True, True, True, False, False])

    def test_piecewise_response_coverage(self):
        # Two degree-one patches, two data rows, one matrix row, all matrices
        # and all possible degree-one responses. The list precedes the matrix.
        modulus, domain = 7, tuple(range(6))
        words = (tuple(int(x < 3) for x in domain),
                 tuple(x if x < 3 else 0 for x in domain))
        for a, b in product(range(modulus), repeat=2):
            combined = tuple((a * words[0][i] + b * words[1][i]) % modulus
                             for i in range(len(domain)))
            for constant, linear in product(range(modulus), repeat=2):
                agreement = sum((constant + linear * x) % modulus == combined[i]
                                for i, x in enumerate(domain))
                if agreement > 2:
                    self.assertIn((constant, linear), ((0, 0), (a, b)))

    def test_fixed_candidate_joint_mismatch(self):
        # Two matrix rows: choose one mismatching position from each fixed
        # query subset before counting matrices. No factor of query count.
        modulus, domain = 7, tuple(range(6))
        words = (tuple(int(x < 3) for x in domain),
                 tuple(x if x < 3 else 0 for x in domain))
        query_sets = tuple(combinations(range(len(domain)), 2))
        for candidate in (tuple((0, 0) for _ in domain), tuple((1, x) for x in domain)):
            mismatches = {i for i in range(len(domain))
                          if (words[0][i], words[1][i]) != candidate[i]}
            count = 0
            for coefficients in product(range(modulus), repeat=4):
                accepted = {i for i in range(len(domain)) if all(
                    (coefficients[2 * row] * (words[0][i] - candidate[i][0]) +
                     coefficients[2 * row + 1] * (words[1][i] - candidate[i][1])) % modulus == 0
                    for row in range(2))}
                count += sum(set(query).issubset(accepted) and bool(set(query) & mismatches)
                             for query in query_sets)
            hit_count = sum(bool(set(query) & mismatches) for query in query_sets)
            self.assertLessEqual(count * modulus**2, modulus**4 * hit_count)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--current-profile-screen', action='store_true')
    parser.add_argument('--patch-cover-screen', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not result.wasSuccessful())
    if args.current_profile_screen:
        print(json.dumps(current_profile_screen(), indent=2))
        return
    if args.patch_cover_screen:
        print(json.dumps(patch_cover_screen(), indent=2))
        return
    domain = (1, 2, 4, 3)
    monomials = tuple(tuple(pow(x, degree, 5) for x in domain) for degree in (2, 3))
    spikes = tuple(tuple(int(i == j) for i in range(4)) for j in range(3))
    larger_domain = tuple(3 * pow(2, i, 17) % 17 for i in range(8))
    larger_words = tuple(tuple(pow(x, degree, 17) for x in larger_domain) for degree in (2, 3))
    cases = {'two_monomials_f5': (5, domain, 2, monomials, ((0,) * 4,) * 2, 2),
             'three_spikes_f5': (5, domain, 2, spikes, ((0,) * 4,) * 2, 2),
             'two_monomials_f17': (17, larger_domain, 2, larger_words, ((0,) * 8,) * 2, 3)}
    print(json.dumps({name: analyze_source(*case) for name, case in cases.items()}, indent=2))


if __name__ == '__main__':
    main()
