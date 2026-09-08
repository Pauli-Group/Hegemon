#!/usr/bin/env python3
"""Exact arithmetic only for SMZ9 stress branches and conditional cover bounds."""

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
    support_cap = 56_977
    tails = 2**44 + 2**36
    cover_margin = residual - tails
    assert cover_margin > 0
    capped_charge = (size + 1 - support_cap) * weight(support_cap)
    capped_families = cover_margin // capped_charge
    assert capped_families > 2**168
    assert p**5 * weight(812) + capped_families * capped_charge + tails <= 2**53
    assert p**5 * weight(812) + (capped_families + 1) * capped_charge + tails > 2**53
    graph_charge = Fraction(size - dimension + 1, support_cap - dimension + 1) * weight(support_cap)
    graph_degree = cover_margin // graph_charge
    assert graph_degree == 29363621245169047705124401626686126827795598631859831321
    assert graph_degree > 2**184
    assert p**5 * weight(812) + graph_degree * graph_charge + tails <= 2**53
    assert p**5 * weight(812) + (graph_degree + 1) * graph_charge + tails > 2**53
    for support in range(813, support_cap):
        assert 19 * (support + 1) - 20 * (dimension - 1) > 0
    for core_size in range(dimension):
        assert Fraction(size - core_size, support_cap - core_size) <= Fraction(
            size - dimension + 1, support_cap - dimension + 1
        )
    assert size - 812 == 8_387_796
    assert (size - dimension) // 425 == 19_736
    assert p**5 * weight(812) + (size - 812) < 2**53
    print("PASS: all integer/rational inequalities")
    print("Conditional 833 bound / allowance:", float(conditional / allowance))
    print("Conditional 813 bound / 2^53:", float(strong_conditional / 2**53))
    print("Legal counterfamily bound / 2^52:", float(counterfamily_bound / 2**52))
    print("Residual at 813 exceeds 2 N^2; no universal tail bound asserted.")
    print("Sharp per-affine-family charge:", float(charge))
    print("Sufficient family count (cover not established):", max_families)
    print("Sufficient capped affine count (cover not established):", capped_families)
    print("Sufficient rational graph degree (cover not established):", graph_degree)
    print("Conditional capped affine budget / 2^53:", float((p**5 * weight(812) + 2**168 * capped_charge + tails) / 2**53))
    print("Conditional graph budget / 2^53:", float((p**5 * weight(812) + 2**184 * graph_charge + tails) / 2**53))
    print("Zero-stress branch budget / 2^53:", float((p**5 * weight(812) + size - 812) / 2**53))


if __name__ == "__main__":
    main()
