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
    cofactor_rank_bound = size - 812
    assert 0 < cofactor_rank_bound < p
    stress_twenty_count = comb(832, 19)
    assert stress_twenty_count == 202917499647411935202774832309045124800
    middle_twenty = cofactor_rank_bound**5 + (p**2 * stress_twenty_count) // (p - cofactor_rank_bound)
    assert middle_twenty == 3743167183203034151303853822236727914500710913488939544761
    fractional_middle = cofactor_rank_bound**5 + Fraction(p**2 * stress_twenty_count, p - cofactor_rank_bound)
    assert middle_twenty <= fractional_middle < middle_twenty + 1
    budget_twenty = p**5 * weight(812) + middle_twenty * weight(support_cap) + tails
    assert budget_twenty < 2**53
    for source_rank in (1, 20, 813, 100000, cofactor_rank_bound - 1):
        assert source_rank**5 + Fraction(p**2 * stress_twenty_count, p - source_rank) <= fractional_middle
    middle_twenty_one = cofactor_rank_bound**5 + (p**2 * comb(833, 20)) // (p - cofactor_rank_bound)
    assert p**5 * weight(812) + middle_twenty_one * weight(support_cap) + tails > 2**53
    assert 813**2 > 387 * 1707
    assert 4096**2 * 813**2 >= 4097**2 * 387 * 1707
    assert Fraction(387, 1707) > Fraction(1, 5)
    assert Fraction(387, 1707) > Fraction(4, 25)
    small_union = Fraction(25 * 1707 * (2 * 4097**5 + 3 * 4097), 6) + Fraction(5 * 4097, 2)
    assert small_union == 16420338088483447085805 < 2**76
    union_fiber = Fraction(1708, 1708 - 2 * 813) * comb(831, 18)
    assert union_fiber == 96521439648185566973505641095408249150 > 2**76
    union_middle_fraction = cofactor_rank_bound**5 + Fraction(p**2, p - cofactor_rank_bound) * union_fiber
    union_middle = union_middle_fraction.numerator // union_middle_fraction.denominator
    assert union_middle == 1780506294402334431843840135889800907721994892128331979526
    assert union_middle <= union_middle_fraction < union_middle + 1
    union_budget = p**5 * weight(812) + union_middle * weight(support_cap) + tails
    assert union_budget < 2**53
    next_fiber = Fraction(1708, 82) * comb(832, 19)
    next_middle = cofactor_rank_bound**5 + Fraction(p**2, p - cofactor_rank_bound) * next_fiber
    assert p**5 * weight(812) + (next_middle.numerator // next_middle.denominator) * weight(support_cap) + tails > 2**53
    first_tail_count = 19415238057946677331930434730749083756
    direct_tail_count = 424128388239503090
    assert first_tail_count < 2**124 and direct_tail_count < 2**59
    assert weight(65535) < Fraction(1, 2**140)
    assert weight(size // 16 - 1) < Fraction(1, 2**80)
    refined_tail = 2**36 + Fraction(1, 2**16) + Fraction(1, 2**21)
    assert first_tail_count * weight(65535) + direct_tail_count * weight(size // 16 - 1) + 2**36 < refined_tail < tails
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
    print("Conditional stress<=20 middle count:", middle_twenty)
    print("Conditional stress<=20 budget / 2^53:", float(budget_twenty / 2**53))
    print("Conditional union-sensitive stress<=21 budget / 2^53:", float(union_budget / 2**53))
    print("Refined universal tail upper bound:", refined_tail)


if __name__ == "__main__":
    main()
