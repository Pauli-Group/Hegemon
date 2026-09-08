#!/usr/bin/env python3
"""Exact arithmetic only: conditional shift bound and legal large-gcd source."""

from fractions import Fraction
from math import comb


def main():
    p = 2**64 - 2**32 + 1
    size, dimension = 2**23, 388

    def weight(agreement):
        return Fraction(comb(agreement, 20), comb(size, 20))

    agreement = 833
    slack = agreement - dimension - 1
    assert slack == 444
    assert size - agreement + 1 == 8_387_776
    for delta in range(1, 223):
        assert agreement >= dimension + 2 * delta
        assert (444 + delta) - delta <= slack
        assert 444 - delta == slack - delta
        assert max(1, delta) <= 222
    allowance = (p - 1) * p**4 * (Fraction(1, 1280 * 2**256) - weight(415))
    conditional = p**5 * weight(832) + 222
    strong_conditional = p**5 * weight(812) + 212
    assert conditional < allowance
    assert strong_conditional < 2**53
    assert 813 - dimension - 1 == 424
    assert (813 - dimension) // 2 == 212

    core = 812
    degree = dimension - 1
    counterfamily_bound = (
        core * weight(size - core + 1)
        + (size - core) * weight(core + 1)
        + (p**5 - size) * weight(2 * degree)
    )
    assert 2 * degree == 774 < core + 1
    assert size - core - core**2 == 7_728_452
    assert 5 * core == 4_060
    assert core + 213 == 1_025
    assert counterfamily_bound < 2**52
    residual = 2**53 - p**5 * weight(812)
    assert residual > 2 * size**2
    best_agreement = (20 * (size + 1) - 1) // 21 + 1
    assert best_agreement == 7_989_152
    charge = (size + 1 - best_agreement) * weight(best_agreement)
    assert 1 < charge < 150_552
    assert (size + 2 - best_agreement) * weight(best_agreement - 1) <= charge
    assert (size - best_agreement) * weight(best_agreement + 1) <= charge
    max_families = residual // charge
    assert max_families == 1_375_681_552
    assert p**5 * weight(812) + max_families * charge <= 2**53
    assert p**5 * weight(812) + (max_families + 1) * charge > 2**53
    print("PASS: all integer/rational inequalities")
    print("Conditional 833 bound / allowance:", float(conditional / allowance))
    print("Conditional 813 bound / 2^53:", float(strong_conditional / 2**53))
    print("Legal counterfamily bound / 2^52:", float(counterfamily_bound / 2**52))
    print("Residual at 813 exceeds 2 N^2; no universal tail bound asserted.")
    print("Sharp per-affine-family charge:", float(charge))
    print("Sufficient family count (cover not established):", max_families)


if __name__ == "__main__":
    main()
