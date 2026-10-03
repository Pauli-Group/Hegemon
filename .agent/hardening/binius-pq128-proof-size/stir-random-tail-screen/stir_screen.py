#!/usr/bin/env python3
"""Fail-closed STIR wire screen for the n15 random-tail candidate.

The model instantiates the most favorable theorem-compatible lower-bound round
structure from STIR Section 5.3 with folding factor four: a degree-four fold, a
factor-two domain shrink, one OOD sample per nonterminal round, and query counts
that ignore the theorem's positive ``eta`` correction.  It replaces the
reference Merkle tree with the requested four-symbol, 32-byte-salted
SHAKE256-448 or SHAKE256-512 tree and runs two independently sampled E256
branches over one shared initial B128 commitment.

This is a source-only byte lower-bound and theorem-compatibility screen.  It
does not implement STIR, a PCS, a simulator, or a parser.  In particular, the
published/reference STIR construction uses multiplicative FFT domains and does
not instantiate on the requested characteristic-two additive domain.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


SOURCE_DEGREE = 1 << 15
BRANCH_SECURITY_BITS = 132
BRANCHES = 2
FOLDING_FACTOR = 4
DOMAIN_SHRINK = 2
B128_BYTES = 16
E256_BYTES = 32
LEAF_SYMBOLS = 4
UNPROVED_COMPACT_SALT_BYTES = 32
# Direct BCS theorem-scoped salt floor supplied for an n=2^18 initial leaf
# tree.  It is priced on every opened leaf in the strict screen; this is a
# conservative transport charge, not a claim that the missing ZK/QROM theorem
# has been instantiated.
DIRECT_BCS_SALT_BYTES_N18 = 148
PARSER_HEADER_BYTES = 64
LOCAL_CHAR2_TWO_BRANCH_BYTES = 1_920
FUSED_RING_SWITCH_BYTES = 128
RAW_CAP_BYTES = 124_068
ACTIVE_SYMBOLS_ASSUMPTION = 26_000
STATIC_TAIL_MIN = 100
STATIC_TAIL_MAX = 9_174

STIR_EPRINT = "https://eprint.iacr.org/2024/390"
STIR_REFERENCE_COMMIT = "51064ebd45667dae3b499539f4476ba6d8527610"
STIR_REFERENCE = (
    "https://github.com/WizardOfMenlo/stir/tree/"
    + STIR_REFERENCE_COMMIT
)


def canonical_frontier_max(leaf_count: int, opened_leaves: int) -> int:
    """Maximum sibling count for a canonical binary Merkle multiproof."""

    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("leaf_count must be a positive power of two")
    if not 1 <= opened_leaves <= leaf_count:
        raise ValueError("opened_leaves must lie within the tree")
    level = math.floor(math.log2(leaf_count / opened_leaves))
    return opened_leaves * (level - 1) + leaf_count // (1 << level)


def direct_bcs_salt_bytes(leaf_count: int) -> int:
    """Direct classical BCS Lemma 3.4 salt floor for 128-bit privacy.

    For a power-of-two tree, the privacy exponent is
    ``lambda/4 - 2 - log2(leaves)``.  Requiring 128 bits gives oracle-output
    parameter ``lambda >= 4*(128+2+log2(leaves))`` and a ``2*lambda``-bit
    salt, exactly ``130+log2(leaves)`` bytes.
    """

    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("direct BCS screen requires a power-of-two tree")
    return 130 + int(math.log2(leaf_count))


def effective_salt_bytes(salt_profile_bytes: int, leaf_count: int) -> int:
    if salt_profile_bytes == UNPROVED_COMPACT_SALT_BYTES:
        return salt_profile_bytes
    if salt_profile_bytes == DIRECT_BCS_SALT_BYTES_N18:
        return direct_bcs_salt_bytes(leaf_count)
    raise ValueError("unknown salt profile")


def reference_provable_repetitions(log_inverse_rate: int) -> int:
    """Pinned Rust ``SoundnessType::Provable`` heuristic schedule."""

    if log_inverse_rate <= 0:
        raise ValueError("log inverse rate must be positive")
    return math.ceil(2 * BRANCH_SECURITY_BITS / log_inverse_rate)


def paper_provable_query_floor(round_index: int, log_inverse_rate: int) -> int:
    """Optimistic lower bound implied by STIR Section 5.3.

    The published provable setting uses ``lambda + 1`` in each repetition
    bound and a positive ``eta`` correction.  For the initial round its tested
    distance is at most ``1-sqrt(1.05*rho)``.  Later and final rounds contain
    ``sqrt(rho)+eta``.  Dropping positive eta only *reduces* the query count,
    so this is a rigorous wire lower bound, never a sufficient parameter set.
    """

    if round_index < 0 or log_inverse_rate <= 0:
        raise ValueError("invalid round/rate")
    if round_index == 0:
        failure = math.sqrt(1.05 * 2.0 ** (-log_inverse_rate))
        bits_per_query = -math.log2(failure)
        return math.ceil((BRANCH_SECURITY_BITS + 1) / bits_per_query)
    return math.ceil(2 * (BRANCH_SECURITY_BITS + 1) / log_inverse_rate)


@dataclass(frozen=True)
class RoundShape:
    index: int
    degree_before_fold: int
    degree_after_fold: int
    log_inverse_rate: int
    codeword_symbols: int
    leaf_count: int
    queries_per_branch: int
    terminal: bool


def round_schedule(starting_rate_log: int, stopping_degree: int) -> tuple[RoundShape, ...]:
    """Return the exact factor-four/factor-two STIR round geometry."""

    if stopping_degree <= 0 or stopping_degree & (stopping_degree - 1):
        raise ValueError("stopping_degree must be a positive power of two")
    degree = SOURCE_DEGREE
    rate_log = starting_rate_log
    rounds: list[RoundShape] = []
    index = 0
    while True:
        if degree % FOLDING_FACTOR:
            raise ValueError("degree is not divisible by the folding factor")
        codeword_symbols = degree << rate_log
        if codeword_symbols % LEAF_SYMBOLS:
            raise ValueError("four-symbol leaves do not divide the oracle")
        degree_after = degree // FOLDING_FACTOR
        terminal = degree_after <= stopping_degree
        rounds.append(
            RoundShape(
                index=index,
                degree_before_fold=degree,
                degree_after_fold=degree_after,
                log_inverse_rate=rate_log,
                codeword_symbols=codeword_symbols,
                leaf_count=codeword_symbols // LEAF_SYMBOLS,
                queries_per_branch=paper_provable_query_floor(index, rate_log),
                terminal=terminal,
            )
        )
        if terminal:
            break
        degree = degree_after
        rate_log += int(math.log2(FOLDING_FACTOR // DOMAIN_SHRINK))
        index += 1
    return tuple(rounds)


@dataclass(frozen=True)
class OpeningCost:
    leaf_count: int
    opened_leaves: int
    symbol_bytes: int
    salt_bytes_per_leaf: int
    frontier_nodes: int
    values_bytes: int
    salts_bytes: int
    authentication_bytes: int
    total_bytes: int


def opening_cost(
    *,
    leaf_count: int,
    opened_leaves: int,
    symbol_bytes: int,
    digest_bytes: int,
    salt_bytes: int,
) -> OpeningCost:
    frontier = canonical_frontier_max(leaf_count, opened_leaves)
    values = opened_leaves * LEAF_SYMBOLS * symbol_bytes
    salts = opened_leaves * salt_bytes
    authentication = frontier * digest_bytes
    return OpeningCost(
        leaf_count=leaf_count,
        opened_leaves=opened_leaves,
        symbol_bytes=symbol_bytes,
        salt_bytes_per_leaf=salt_bytes,
        frontier_nodes=frontier,
        values_bytes=values,
        salts_bytes=salts,
        authentication_bytes=authentication,
        total_bytes=values + salts + authentication,
    )


@dataclass(frozen=True)
class StirProfile:
    profile_name: str
    digest_bytes: int
    salt_bytes: int
    direct_bcs_salt_profile: bool
    strict_hash_profile: bool
    direct_bcs_salt_n18_priced: bool
    direct_bcs_common_lambda_parameter_match: bool
    starting_rate_log: int
    stopping_degree: int
    rounds: int
    queries: tuple[int, ...]
    initial_codeword_symbols: int
    initial_leaf_count: int
    roots: int
    roots_bytes: int
    initial_opened_leaves_union: int
    initial_opened_payload_bytes: int
    initial_opening_bytes: int
    later_opened_payload_bytes: int
    later_opening_bytes: int
    authentication_bytes: int
    ood_e256_elements: int
    ood_bytes: int
    final_e256_elements: int
    final_polynomial_bytes: int
    parser_header_bytes: int
    local_char2_bytes: int
    ring_switch_bytes: int
    canonical_raw_bytes: int
    canonical_headroom_bytes: int
    canonical_fits: bool
    authentication_free_raw_bytes: int
    authentication_free_headroom_bytes: int
    authentication_free_fits: bool
    reference_extra_e256_elements: int
    reference_extra_bytes: int
    reference_raw_bytes: int
    reference_headroom_bytes: int
    reference_fits: bool
    conservative_b128_observation_rows: int
    tail_headroom_at_assumed_active_prefix: int
    covers_static_tail_interval: bool
    published_binary_additive_domain_supported: bool
    reference_binary_field_supported: bool
    mixed_b128_e256_theorem_proved: bool
    two_branch_product_theorem_proved: bool
    adaptive_salted_bcs_zk_proved: bool
    qrom_fiat_shamir_proved: bool
    parser_refinement_proved: bool
    strict_admitted: bool


def profile(
    *,
    digest_bytes: int,
    salt_bytes: int,
    starting_rate_log: int,
    stopping_degree: int,
) -> StirProfile:
    if digest_bytes not in (56, 64):
        raise ValueError("digest must be SHAKE256-448 or SHAKE256-512")
    if salt_bytes not in (UNPROVED_COMPACT_SALT_BYTES, DIRECT_BCS_SALT_BYTES_N18):
        raise ValueError("unknown salt profile")
    schedule = round_schedule(starting_rate_log, stopping_degree)
    first = schedule[0]
    initial_salt_bytes = effective_salt_bytes(salt_bytes, first.leaf_count)

    initial_union = BRANCHES * first.queries_per_branch
    initial = opening_cost(
        leaf_count=first.leaf_count,
        opened_leaves=initial_union,
        symbol_bytes=B128_BYTES,
        digest_bytes=digest_bytes,
        salt_bytes=initial_salt_bytes,
    )

    later_opening_bytes = 0
    later_opened_payload_bytes = 0
    later_authentication_bytes = 0
    observation_rows = initial_union * LEAF_SYMBOLS
    for round_shape in schedule[1:]:
        # Every E256 value serializes as two B128 coefficient lanes.  A STIR
        # fold query reads four E256 values, hence eight lanes and exactly two
        # physical four-B128-symbol leaves.  Treating four E256 values as one
        # leaf would silently violate the frozen leaf grammar.
        later_leaf_count = round_shape.codeword_symbols * 2 // LEAF_SYMBOLS
        per_branch = opening_cost(
            leaf_count=later_leaf_count,
            opened_leaves=round_shape.queries_per_branch * 2,
            symbol_bytes=B128_BYTES,
            digest_bytes=digest_bytes,
            salt_bytes=effective_salt_bytes(salt_bytes, later_leaf_count),
        )
        later_opening_bytes += BRANCHES * per_branch.total_bytes
        later_opened_payload_bytes += BRANCHES * (
            per_branch.values_bytes + per_branch.salts_bytes
        )
        later_authentication_bytes += (
            BRANCHES * per_branch.authentication_bytes
        )
        observation_rows += (
            BRANCHES * round_shape.queries_per_branch * LEAF_SYMBOLS * 2
        )

    nonterminal = schedule[:-1]
    # One shared initial root plus one branch-local root for every
    # nonterminal round and branch.
    roots = 1 + BRANCHES * len(nonterminal)
    roots_bytes = roots * digest_bytes
    # STIR Section 5.3's provable setting has s=1.  The pinned Rust prototype
    # hard-wires two OOD samples; the extra source field is charged below.
    ood_elements = BRANCHES * len(nonterminal)
    ood_bytes = ood_elements * E256_BYTES
    observation_rows += ood_elements * 2

    final_elements = BRANCHES * schedule[-1].degree_after_fold
    final_bytes = final_elements * E256_BYTES
    observation_rows += final_elements * 2

    canonical = (
        PARSER_HEADER_BYTES
        + roots_bytes
        + initial.total_bytes
        + later_opening_bytes
        + ood_bytes
        + final_bytes
        + LOCAL_CHAR2_TWO_BRANCH_BYTES
        + FUSED_RING_SWITCH_BYTES
    )
    authentication_bytes = (
        initial.authentication_bytes + later_authentication_bytes
    )
    authentication_free = canonical - authentication_bytes

    # The pinned Rust prototype serializes both ans_polynomial (at most q+2
    # coefficients) and shake_polynomial (at most q+1 coefficients) in every
    # nonterminal round.  They are deterministic from already-visible answers
    # and can be recomputed by a proof-size-minimal verifier, so canonical omits
    # them while this source-faithful upper row exposes their cost.
    reference_extra_elements = (
        # One extra OOD reply per branch/round in the pinned source.
        BRANCHES * len(nonterminal)
        + BRANCHES
        * sum(2 * shape.queries_per_branch + 3 for shape in nonterminal)
    )
    reference_extra_bytes = reference_extra_elements * E256_BYTES
    reference_raw = canonical + reference_extra_bytes

    observation_rows += (
        LOCAL_CHAR2_TWO_BRANCH_BYTES + FUSED_RING_SWITCH_BYTES
    ) // B128_BYTES
    assumed_tail = SOURCE_DEGREE - ACTIVE_SYMBOLS_ASSUMPTION

    return StirProfile(
        profile_name=(
            "strict-shake512-direct-bcs-salt148"
            if digest_bytes == 64 and salt_bytes == DIRECT_BCS_SALT_BYTES_N18
            else (
                "unproved-shake512-salt32"
                if digest_bytes == 64
                else "legacy-shake448-salt32"
            )
        ),
        digest_bytes=digest_bytes,
        salt_bytes=initial_salt_bytes,
        direct_bcs_salt_profile=(salt_bytes == DIRECT_BCS_SALT_BYTES_N18),
        strict_hash_profile=digest_bytes == 64,
        direct_bcs_salt_n18_priced=(
            salt_bytes == DIRECT_BCS_SALT_BYTES_N18
            and first.leaf_count == 1 << 18
        ),
        direct_bcs_common_lambda_parameter_match=False,
        starting_rate_log=starting_rate_log,
        stopping_degree=stopping_degree,
        rounds=len(schedule),
        queries=tuple(shape.queries_per_branch for shape in schedule),
        initial_codeword_symbols=first.codeword_symbols,
        initial_leaf_count=first.leaf_count,
        roots=roots,
        roots_bytes=roots_bytes,
        initial_opened_leaves_union=initial_union,
        initial_opened_payload_bytes=(initial.values_bytes + initial.salts_bytes),
        initial_opening_bytes=initial.total_bytes,
        later_opened_payload_bytes=later_opened_payload_bytes,
        later_opening_bytes=later_opening_bytes,
        authentication_bytes=authentication_bytes,
        ood_e256_elements=ood_elements,
        ood_bytes=ood_bytes,
        final_e256_elements=final_elements,
        final_polynomial_bytes=final_bytes,
        parser_header_bytes=PARSER_HEADER_BYTES,
        local_char2_bytes=LOCAL_CHAR2_TWO_BRANCH_BYTES,
        ring_switch_bytes=FUSED_RING_SWITCH_BYTES,
        canonical_raw_bytes=canonical,
        canonical_headroom_bytes=RAW_CAP_BYTES - canonical,
        canonical_fits=canonical <= RAW_CAP_BYTES,
        authentication_free_raw_bytes=authentication_free,
        authentication_free_headroom_bytes=RAW_CAP_BYTES - authentication_free,
        authentication_free_fits=authentication_free <= RAW_CAP_BYTES,
        reference_extra_e256_elements=reference_extra_elements,
        reference_extra_bytes=reference_extra_bytes,
        reference_raw_bytes=reference_raw,
        reference_headroom_bytes=RAW_CAP_BYTES - reference_raw,
        reference_fits=reference_raw <= RAW_CAP_BYTES,
        conservative_b128_observation_rows=observation_rows,
        tail_headroom_at_assumed_active_prefix=assumed_tail - observation_rows,
        covers_static_tail_interval=STATIC_TAIL_MIN >= observation_rows,
        published_binary_additive_domain_supported=False,
        reference_binary_field_supported=False,
        mixed_b128_e256_theorem_proved=False,
        two_branch_product_theorem_proved=False,
        adaptive_salted_bcs_zk_proved=False,
        qrom_fiat_shamir_proved=False,
        parser_refinement_proved=False,
        strict_admitted=False,
    )


def all_profiles() -> tuple[StirProfile, ...]:
    profiles = []
    transport_profiles = (
        (56, UNPROVED_COMPACT_SALT_BYTES),
        (64, UNPROVED_COMPACT_SALT_BYTES),
        (64, DIRECT_BCS_SALT_BYTES_N18),
    )
    for digest, salt in transport_profiles:
        for rate_log in (4, 5):
            for stop in (2, 8, 32, 128, 512, 2_048, 8_192):
                profiles.append(
                    profile(
                        digest_bytes=digest,
                        salt_bytes=salt,
                        starting_rate_log=rate_log,
                        stopping_degree=stop,
                    )
                )
    return tuple(profiles)


def report() -> dict[str, object]:
    profiles = all_profiles()
    best_canonical = min(profiles, key=lambda item: item.canonical_raw_bytes)
    best_reference = min(profiles, key=lambda item: item.reference_raw_bytes)
    strict_profiles = [
        item
        for item in profiles
        if item.digest_bytes == 64
        and item.direct_bcs_salt_profile
        and item.starting_rate_log == 5
    ]
    best_strict_transport = min(
        strict_profiles, key=lambda item: item.canonical_raw_bytes
    )
    best_strict_authentication_free = min(
        strict_profiles, key=lambda item: item.authentication_free_raw_bytes
    )
    return {
        "schema": "hegemon.stir-random-tail-screen.v1",
        "sources": {
            "paper": STIR_EPRINT,
            "reference_commit": STIR_REFERENCE_COMMIT,
            "reference": STIR_REFERENCE,
        },
        "fixed_parameters": {
            "source_degree": SOURCE_DEGREE,
            "branches": BRANCHES,
            "security_bits_per_branch": BRANCH_SECURITY_BITS,
            "folding_factor": FOLDING_FACTOR,
            "domain_shrink": DOMAIN_SHRINK,
            "leaf_symbols": LEAF_SYMBOLS,
            "unproved_compact_salt_bytes": UNPROVED_COMPACT_SALT_BYTES,
            "direct_bcs_salt_bytes_at_n18": DIRECT_BCS_SALT_BYTES_N18,
            "direct_bcs_salt_formula_power_of_two_tree": (
                "130+log2(leaves) bytes"
            ),
            "raw_cap_bytes": RAW_CAP_BYTES,
        },
        "best_canonical": asdict(best_canonical),
        "best_reference_source_wire": asdict(best_reference),
        "best_strict_transport_floor": asdict(best_strict_transport),
        "best_strict_authentication_free_floor": asdict(
            best_strict_authentication_free
        ),
        "profiles": [asdict(item) for item in profiles],
        "gates": {
            "published_stir_on_characteristic_two_additive_domain": False,
            "reference_source_on_binary_field": False,
            "b128_committed_e256_fold_extraction": False,
            "independent_132_bit_branch_product": False,
            "random_tail_adaptive_bcs_zero_knowledge": False,
            "direct_bcs_common_lambda_parameter_match": False,
            "salted_shake_qrom_simulator": False,
            "canonical_parser_and_refinement": False,
            "strict_admitted": False,
        },
        "verdict": (
            "STIR is not an admitted proximity layer: the published domain "
            "and mixed-field theorems do not cover this construction; byte "
            "fit is reported only as a hypothetical transport floor"
        ),
    }


def self_check() -> None:
    assert canonical_frontier_max(1 << 18, 106) == 1_188
    assert reference_provable_repetitions(4) == 66
    assert reference_provable_repetitions(5) == 53
    assert paper_provable_query_floor(0, 5) == 54
    assert paper_provable_query_floor(1, 6) == 45
    schedule = round_schedule(5, 32)
    assert [shape.degree_before_fold for shape in schedule] == [32768, 8192, 2048, 512, 128]
    assert [shape.log_inverse_rate for shape in schedule] == [5, 6, 7, 8, 9]
    assert [shape.queries_per_branch for shape in schedule] == [54, 45, 38, 34, 30]
    payload = report()
    best = payload["best_canonical"]
    strict = payload["best_strict_transport_floor"]
    auth_free = payload["best_strict_authentication_free_floor"]
    assert best["strict_admitted"] is False
    assert strict["digest_bytes"] == 64
    assert strict["salt_bytes"] == DIRECT_BCS_SALT_BYTES_N18
    assert strict["starting_rate_log"] == 5
    assert not strict["canonical_fits"]
    assert not auth_free["authentication_free_fits"]
    assert payload["gates"]["strict_admitted"] is False
    assert all(not item["covers_static_tail_interval"] for item in payload["profiles"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("STIR_RANDOM_TAIL_SCREEN_PASS")
    if args.report:
        print(json.dumps(report(), sort_keys=True, separators=(",", ":")))
    if not args.check and not args.report:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
