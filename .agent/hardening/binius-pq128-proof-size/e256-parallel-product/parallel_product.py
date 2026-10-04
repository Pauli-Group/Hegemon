#!/usr/bin/env python3
"""Fail-closed product-soundness contract for two E256 branches.

This module proves one elementary information-theoretic implication, checks
finite counterexamples to its missing hypotheses, and reproduces the q=44 and
q=33 byte screens.  It does not prove the current Fiat--Shamir protocol sound
in the ROM or QROM.  In particular, domain-separated SHAKE256 calls are not a
parallel-repetition theorem.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Iterable, Sequence


BRANCHES = 2
BRANCH_TARGET_BITS = 132
IDEAL_PRODUCT_BITS = BRANCHES * BRANCH_TARGET_BITS
PQ_TARGET_BITS = 128

MESSAGE_LOG = 15
MESSAGE_SYMBOLS = 1 << MESSAGE_LOG
LEAF_GROUP_SYMBOLS = 4
B128_BYTES = 16
E256_BYTES = 32
UNPROVED_CANDIDATE_SALT_BYTES = 32
DIRECT_BCS_CLASSICAL_SALT_BYTES = 148
LEGACY_SHAKE256_448_BYTES = 56
SHAKE256_512_BYTES = 64
HEADER_BYTES = 64
ENVELOPE_BYTES = 12
LOCAL_CHAR2_TWO_BRANCH_BYTES = 1_920
FUSED_RING_SWITCH_BYTES = 128
RAW_CAP_BYTES = 124_068
TRANSCRIPT_DOMAIN = b"hegemon.e256-parallel-product.transcript.v1\0"
CHALLENGE_DOMAIN = b"hegemon.e256-parallel-product.challenge.v1\0"
BRANCH_LABELS = {"A": b"branch-A", "B": b"branch-B"}

REPO_ROOT = Path(__file__).resolve().parents[4]
SOURCE_PINS = {
    "prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs":
        "7c7b4328d934d01cbe5b243291863237544c561b31f3306d3ac98e7867513693",
    "prototypes/standalone-shake256-binius/strict-e256x2-iop/security-manifest.json":
        "f56e047aa4b78de7740aa92dbba2d8ceb8d1c5ae8cf2775c39f14dabbe071d9f",
    ".agent/hardening/binius-pq128-proof-size/strict_pq_profile.py":
        "6536c5825c557759689057d0674a053d5bb02c135cfda1438656f6c0a356e53d",
}
UNFROZEN_SOURCE_PATHS = (
    "prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/random_padding_pcs.py",
    ".agent/hardening/binius-pq128-proof-size/salted-bcs-zk-audit/salted_bcs_zk_audit.py",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_records() -> list[dict[str, object]]:
    records = []
    for relative, expected in SOURCE_PINS.items():
        actual = _sha256_file(REPO_ROOT / relative)
        records.append(
            {
                "path": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": actual == expected,
            }
        )
    return records


def unfrozen_source_records() -> list[dict[str, object]]:
    """Report moving research inputs without turning their current bytes into authority."""

    return [
        {
            "path": relative,
            "observed_sha256": _sha256_file(REPO_ROOT / relative),
            "pinned": False,
            "matches": None,
        }
        for relative in UNFROZEN_SOURCE_PATHS
    ]


def frame(tag: int, payload: bytes) -> bytes:
    """Canonical one-byte tag plus u64-LE length frame."""

    if not 0 <= tag <= 0xFF:
        raise ValueError("frame tag must fit one byte")
    if len(payload) >= 1 << 64:
        raise ValueError("frame payload is too long")
    return bytes((tag,)) + len(payload).to_bytes(8, "little") + payload


def canonical_common_prefix(
    *,
    profile: bytes,
    statement: bytes,
    shared_root: bytes,
    prechallenge_commitments: Sequence[bytes],
) -> bytes:
    """Freeze one exact strict prechallenge transcript prefix."""

    if not profile:
        raise ValueError("profile must be nonempty")
    if not statement:
        raise ValueError("statement must be nonempty")
    if len(shared_root) != SHAKE256_512_BYTES:
        raise ValueError("strict shared root must be exactly 64 bytes")
    if len(prechallenge_commitments) >= 1 << 32:
        raise ValueError("too many prechallenge commitments")
    prefix = bytearray(TRANSCRIPT_DOMAIN)
    prefix.extend(frame(1, profile))
    prefix.extend(frame(2, statement))
    prefix.extend(frame(3, shared_root))
    prefix.extend(frame(4, len(prechallenge_commitments).to_bytes(4, "little")))
    for index, commitment in enumerate(prechallenge_commitments):
        prefix.extend(frame(5, index.to_bytes(4, "little") + commitment))
    return bytes(prefix)


def branch_challenge_seed(
    *, common_prefix: bytes, branch: str, round_index: int, local_prefix: bytes
) -> bytes:
    """Return a 64-byte SHAKE256 seed on one disjoint branch domain."""

    if branch not in BRANCH_LABELS:
        raise ValueError("branch must be A or B")
    if not 0 <= round_index < 1 << 64:
        raise ValueError("round index must fit u64")
    preimage = bytearray(CHALLENGE_DOMAIN)
    preimage.extend(frame(1, common_prefix))
    preimage.extend(frame(2, BRANCH_LABELS[branch]))
    preimage.extend(frame(3, round_index.to_bytes(8, "little")))
    preimage.extend(frame(4, local_prefix))
    return hashlib.shake_256(preimage).digest(SHAKE256_512_BYTES)


def e256_challenge_bytes(seed: bytes) -> bytes:
    """Project the frozen 64-byte seed to one canonical 32-byte E256 sample."""

    if len(seed) != SHAKE256_512_BYTES:
        raise ValueError("challenge seed must be exactly 64 bytes")
    return seed[:E256_BYTES]


@dataclass(frozen=True)
class TranscriptEvidence:
    """Evidence needed to instantiate the ideal product theorem.

    The first eight fields are classical/information-theoretic obligations.
    The final two fields are additional Fiat--Shamir and QROM obligations.
    """

    shared_oracle_fixed_before_any_challenge: bool
    every_branch_commitment_fixed_before_its_challenge: bool
    distinct_length_framed_branch_domains: bool
    every_verifier_coin_branch_independent: bool
    both_branches_check_same_complete_invalid_relation: bool
    post_challenge_messages_branch_local_or_conditionally_quantified: bool
    per_branch_error_is_complete_not_one_term: bool
    pointwise_history_conditional_branch_bound: bool
    fiat_shamir_rom_direct_product_proved: bool
    multi_point_qrom_compiler_proved: bool

    def ideal_missing(self) -> tuple[str, ...]:
        fields = asdict(self)
        return tuple(
            name
            for name, present in list(fields.items())[:8]
            if not present
        )

    def fs_qrom_missing(self) -> tuple[str, ...]:
        fields = asdict(self)
        return tuple(
            name
            for name, present in list(fields.items())[8:]
            if not present
        )

    @property
    def ideal_product_instantiated(self) -> bool:
        return not self.ideal_missing()

    @property
    def qrom_product_instantiated(self) -> bool:
        return self.ideal_product_instantiated and not self.fs_qrom_missing()


REQUIRED_IDEAL_CONTRACT = TranscriptEvidence(
    shared_oracle_fixed_before_any_challenge=True,
    every_branch_commitment_fixed_before_its_challenge=True,
    distinct_length_framed_branch_domains=True,
    every_verifier_coin_branch_independent=True,
    both_branches_check_same_complete_invalid_relation=True,
    post_challenge_messages_branch_local_or_conditionally_quantified=True,
    per_branch_error_is_complete_not_one_term=True,
    pointwise_history_conditional_branch_bound=True,
    fiat_shamir_rom_direct_product_proved=True,
    multi_point_qrom_compiler_proved=True,
)

# These values are a source audit, not an aspiration.  The current arithmetic
# seam fixes one root and two labels, but it has no complete PCS/PIOP transcript
# from which the remaining obligations could be established.
CURRENT_SOURCE_EVIDENCE = TranscriptEvidence(
    shared_oracle_fixed_before_any_challenge=True,
    every_branch_commitment_fixed_before_its_challenge=False,
    distinct_length_framed_branch_domains=True,
    every_verifier_coin_branch_independent=False,
    both_branches_check_same_complete_invalid_relation=False,
    post_challenge_messages_branch_local_or_conditionally_quantified=False,
    per_branch_error_is_complete_not_one_term=False,
    pointwise_history_conditional_branch_bound=False,
    fiat_shamir_rom_direct_product_proved=False,
    multi_point_qrom_compiler_proved=False,
)


def conditional_product_bound(
    first_error: Fraction, second_conditional_error: Fraction
) -> Fraction:
    """Return the chain-rule bound epsilon_1 * epsilon_2.

    The caller must establish that ``second_conditional_error`` bounds branch
    two after *every* positive-probability accepting branch-one history,
    including all residual prover state.  This function intentionally does not
    infer that premise from marginal probabilities.
    """

    for value in (first_error, second_conditional_error):
        if value < 0 or value > 1:
            raise ValueError("error probabilities must lie in [0, 1]")
    return first_error * second_conditional_error


def probability_bits(probability: Fraction | float) -> float:
    value = float(probability)
    if value <= 0 or value > 1:
        raise ValueError("probability must lie in (0, 1]")
    return -math.log2(value)


def union_bound_bits(term_bits: Iterable[float]) -> float:
    terms = tuple(float(bits) for bits in term_bits)
    if not terms or any(not math.isfinite(bits) or bits < 0 for bits in terms):
        raise ValueError("union terms must be a nonempty finite sequence")
    floor = min(terms)
    scaled = math.fsum(2.0 ** (floor - bits) for bits in terms)
    return floor - math.log2(scaled)


@dataclass(frozen=True)
class FiniteExperiment:
    name: str
    marginal_a: Fraction
    marginal_b: Fraction
    joint: Fraction
    naive_product: Fraction
    violates_product: bool
    explanation: str

    def record(self) -> dict[str, object]:
        def ratio(value: Fraction) -> dict[str, int]:
            return {"numerator": value.numerator, "denominator": value.denominator}

        return {
            "name": self.name,
            "marginal_a": ratio(self.marginal_a),
            "marginal_b": ratio(self.marginal_b),
            "joint": ratio(self.joint),
            "naive_product": ratio(self.naive_product),
            "violates_product": self.violates_product,
            "explanation": self.explanation,
        }


def fixed_oracle_independent_queries(
    domain_size: int = 2, bad_points: int = 1
) -> FiniteExperiment:
    """Positive control: fixed bad set and independent branch queries."""

    if not 0 < bad_points < domain_size:
        raise ValueError("bad set must be a proper nonempty subset")
    total = domain_size * domain_size
    accepts_a = accepts_b = accepts_both = 0
    for query_a, query_b in itertools.product(range(domain_size), repeat=2):
        event_a = query_a < bad_points
        event_b = query_b < bad_points
        accepts_a += event_a
        accepts_b += event_b
        accepts_both += event_a and event_b
    marginal_a = Fraction(accepts_a, total)
    marginal_b = Fraction(accepts_b, total)
    joint = Fraction(accepts_both, total)
    return FiniteExperiment(
        name="fixed-oracle-independent-queries",
        marginal_a=marginal_a,
        marginal_b=marginal_b,
        joint=joint,
        naive_product=marginal_a * marginal_b,
        violates_product=joint > marginal_a * marginal_b,
        explanation="fixed bad set and independent branch-local verifier coins",
    )


def shared_query_schedule_counterexample(
    domain_size: int = 2, bad_points: int = 1
) -> FiniteExperiment:
    """Both branches use the same proximity query despite other labels."""

    if not 0 < bad_points < domain_size:
        raise ValueError("bad set must be a proper nonempty subset")
    marginal = Fraction(bad_points, domain_size)
    return FiniteExperiment(
        name="shared-query-schedule",
        marginal_a=marginal,
        marginal_b=marginal,
        joint=marginal,
        naive_product=marginal * marginal,
        violates_product=marginal > marginal * marginal,
        explanation=(
            "domain-separated algebraic challenges do not square one reused "
            "proximity miss event"
        ),
    )


def adaptive_cross_branch_counterexample() -> FiniteExperiment:
    """Independent challenge bits, but one cross-branch accept selector.

    Let z=a XOR b be chosen after both domain-separated challenges.  Both
    branch verifiers accept exactly when z=0.  Each marginal is one half and
    the joint event is also one half, rather than one quarter.
    """

    total = accepts_a = accepts_b = accepts_both = 0
    for challenge_a, challenge_b in itertools.product(range(2), repeat=2):
        total += 1
        selector = challenge_a ^ challenge_b
        event_a = selector == 0
        event_b = selector == 0
        accepts_a += event_a
        accepts_b += event_b
        accepts_both += event_a and event_b
    marginal_a = Fraction(accepts_a, total)
    marginal_b = Fraction(accepts_b, total)
    joint = Fraction(accepts_both, total)
    return FiniteExperiment(
        name="adaptive-cross-branch-message",
        marginal_a=marginal_a,
        marginal_b=marginal_b,
        joint=joint,
        naive_product=marginal_a * marginal_b,
        violates_product=joint > marginal_a * marginal_b,
        explanation="independent challenge domains do not constrain joint responses",
    )


def average_only_counterexample() -> FiniteExperiment:
    """Marginal bounds averaged over a shared prestate do not multiply."""

    marginal = Fraction(1, 2)
    return FiniteExperiment(
        name="average-only-shared-prestate",
        marginal_a=marginal,
        marginal_b=marginal,
        joint=marginal,
        naive_product=marginal * marginal,
        violates_product=True,
        explanation=(
            "both branches accept exactly on one shared prestate; the bound "
            "must hold pointwise after conditioning on that state"
        ),
    )


def commitment_grinding_counterexample(candidate_commitments: int = 2) -> FiniteExperiment:
    """Exact ROM grinding over roots, each with two independent challenge bits."""

    if not 1 <= candidate_commitments <= 8:
        raise ValueError("finite checker supports one through eight commitments")
    total = success = 0
    for oracle_table in itertools.product(
        range(2), repeat=BRANCHES * candidate_commitments
    ):
        total += 1
        pairs = zip(oracle_table[::2], oracle_table[1::2])
        success += any(left == 0 and right == 0 for left, right in pairs)
    joint = Fraction(success, total)
    fixed_root = Fraction(1, 4)
    return FiniteExperiment(
        name=f"post-hash-root-selection-{candidate_commitments}",
        marginal_a=Fraction(1, 2),
        marginal_b=Fraction(1, 2),
        joint=joint,
        naive_product=fixed_root,
        violates_product=joint > fixed_root,
        explanation=(
            "each root has independent branch labels, but selecting a root "
            "after oracle queries raises success to 1-(3/4)^N"
        ),
    )


def split_relation_counterexample() -> FiniteExperiment:
    """One branch checks the violated family while the other checks another."""

    first_error = Fraction(1, 2)
    second_accepts = Fraction(1, 1)
    return FiniteExperiment(
        name="split-invalid-relation",
        marginal_a=first_error,
        marginal_b=second_accepts,
        joint=first_error,
        naive_product=first_error * first_error,
        violates_product=True,
        explanation=(
            "an oracle violating only family A gets no second independent "
            "chance of detection when branch B checks only family B"
        ),
    )


def exhaustive_branch_local_max(challenge_size: int = 2) -> Fraction:
    """Exhaust all local accept sets with at most one/challenge_size error."""

    if not 2 <= challenge_size <= 4:
        raise ValueError("finite checker supports challenge sizes two through four")
    allowed_masks = [
        mask
        for mask in range(1 << challenge_size)
        if mask.bit_count() <= 1
    ]
    maximum = Fraction(0, 1)
    for mask_a, mask_b in itertools.product(allowed_masks, repeat=2):
        accepts = 0
        for challenge_a, challenge_b in itertools.product(
            range(challenge_size), repeat=2
        ):
            accepts += bool(mask_a & (1 << challenge_a)) and bool(
                mask_b & (1 << challenge_b)
            )
        maximum = max(maximum, Fraction(accepts, challenge_size**2))
    return maximum


def exhaustive_correlated_marginal_max() -> Fraction:
    """Max joint event with two independent bits but arbitrary joint predicates."""

    universe_size = 4
    half_masks = [
        mask
        for mask in range(1 << universe_size)
        if mask.bit_count() <= universe_size // 2
    ]
    maximum = 0
    for mask_a, mask_b in itertools.product(half_masks, repeat=2):
        maximum = max(maximum, (mask_a & mask_b).bit_count())
    return Fraction(maximum, universe_size)


def canonical_frontier_max(leaf_count: int, opened_leaves: int) -> int:
    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("leaf count must be a power of two")
    if not 1 <= opened_leaves <= leaf_count:
        raise ValueError("opened leaves must lie within the tree")
    level = math.floor(math.log2(leaf_count / opened_leaves))
    return opened_leaves * (level - 1) + leaf_count // (1 << level)


def query_bits_per_opening(rate_denominator: int) -> float:
    if rate_denominator <= 1 or rate_denominator & (rate_denominator - 1):
        raise ValueError("rate denominator must be a power of two greater than one")
    rate = 1.0 / rate_denominator
    return -math.log2(1.0 - (1.0 - rate) ** 2)


def query_count(rate_denominator: int, branch_bits: int = BRANCH_TARGET_BITS) -> int:
    if branch_bits <= 0:
        raise ValueError("branch bits must be positive")
    return math.ceil(branch_bits / query_bits_per_opening(rate_denominator))


@dataclass(frozen=True)
class RateProfile:
    profile_label: str
    rate_denominator: int
    merkle_digest_bytes: int
    salt_bytes_per_opened_leaf: int
    strict_proof_commitment_width: bool
    direct_bcs_n18_salt_floor_met: bool
    direct_bcs_common_lambda_parameter_match: bool
    direct_bcs_classical_theorem_instantiated: bool
    salt_sufficient_for_qrom_zk: bool
    queries_per_branch: int
    query_term_bits_per_branch: float
    union_opened_leaves: int
    frontier_nodes_max: int
    merkle_wire_bytes: int
    algebraic_wire_bytes: int
    auxiliary_wire_bytes: int
    raw_wire_bytes: int
    envelope_wire_bytes: int
    raw_headroom_bytes: int
    tree_storage_bytes: int
    product_bytes_are_security_authorized: bool


def rate_profile(
    rate_denominator: int,
    *,
    salt_bytes: int = UNPROVED_CANDIDATE_SALT_BYTES,
    merkle_digest_bytes: int = SHAKE256_512_BYTES,
    profile_label: str = "strict-hash-unproved-32-byte-salt",
) -> RateProfile:
    if salt_bytes <= 0:
        raise ValueError("salt bytes must be positive")
    if merkle_digest_bytes not in (
        LEGACY_SHAKE256_448_BYTES,
        SHAKE256_512_BYTES,
    ):
        raise ValueError("unsupported Merkle digest width")
    queries = query_count(rate_denominator)
    codeword_symbols = MESSAGE_SYMBOLS * rate_denominator
    leaf_count = codeword_symbols // LEAF_GROUP_SYMBOLS
    union = BRANCHES * queries
    frontier = canonical_frontier_max(leaf_count, union)
    merkle = (
        merkle_digest_bytes
        + union * (LEAF_GROUP_SYMBOLS * B128_BYTES + salt_bytes)
        + frontier * merkle_digest_bytes
    )
    algebraic = BRANCHES * (5 * queries + 2) * E256_BYTES
    auxiliary = LOCAL_CHAR2_TWO_BRANCH_BYTES + FUSED_RING_SWITCH_BYTES
    raw = HEADER_BYTES + merkle + algebraic + auxiliary
    tree_storage = (
        codeword_symbols * B128_BYTES
        + (leaf_count - 1) * merkle_digest_bytes
        + leaf_count * salt_bytes
    )
    return RateProfile(
        profile_label=profile_label,
        rate_denominator=rate_denominator,
        merkle_digest_bytes=merkle_digest_bytes,
        salt_bytes_per_opened_leaf=salt_bytes,
        strict_proof_commitment_width=(
            merkle_digest_bytes == SHAKE256_512_BYTES
        ),
        direct_bcs_n18_salt_floor_met=(
            salt_bytes == DIRECT_BCS_CLASSICAL_SALT_BYTES
        ),
        direct_bcs_common_lambda_parameter_match=(
            salt_bytes * 8 == 2 * merkle_digest_bytes * 8
        ),
        direct_bcs_classical_theorem_instantiated=(
            salt_bytes == DIRECT_BCS_CLASSICAL_SALT_BYTES
            and salt_bytes * 8 == 2 * merkle_digest_bytes * 8
        ),
        salt_sufficient_for_qrom_zk=False,
        queries_per_branch=queries,
        query_term_bits_per_branch=(
            queries * query_bits_per_opening(rate_denominator)
        ),
        union_opened_leaves=union,
        frontier_nodes_max=frontier,
        merkle_wire_bytes=merkle,
        algebraic_wire_bytes=algebraic,
        auxiliary_wire_bytes=auxiliary,
        raw_wire_bytes=raw,
        envelope_wire_bytes=raw + ENVELOPE_BYTES,
        raw_headroom_bytes=RAW_CAP_BYTES - raw,
        tree_storage_bytes=tree_storage,
        product_bytes_are_security_authorized=False,
    )


def direct_bcs_classical_rate_profile(rate_denominator: int) -> RateProfile:
    """Price the salt required by the direct BCS Lemma 3.4 n=2^18 screen.

    The 148-byte value makes that classical theorem's parameter inequality
    reach 128 bits at 2^18 leaves.  It is still not a QROM simulator theorem.
    """

    return rate_profile(
        rate_denominator,
        salt_bytes=DIRECT_BCS_CLASSICAL_SALT_BYTES,
        merkle_digest_bytes=SHAKE256_512_BYTES,
        profile_label="strict-hash-148-byte-direct-bcs-salt-floor",
    )


def rejected_legacy_rate_profile(rate_denominator: int) -> RateProfile:
    """Retain the old SHAKE256-448 row only as a named negative control."""

    return rate_profile(
        rate_denominator,
        salt_bytes=UNPROVED_CANDIDATE_SALT_BYTES,
        merkle_digest_bytes=LEGACY_SHAKE256_448_BYTES,
        profile_label="rejected-nonstrict-shake448-32-byte-salt",
    )


def conditional_security_screen() -> dict[str, object]:
    """Numerical scaffold with every reduction/evidence boundary explicit."""

    branch_error = Fraction(1, 1 << BRANCH_TARGET_BITS)
    ideal_error = conditional_product_bound(branch_error, branch_error)
    ideal_bits = probability_bits(ideal_error)
    # Hegemon's existing conservative engineering screen halves a classical
    # exponent.  That arithmetic is not a Fiat--Shamir/QROM theorem.
    square_root_scaffold_bits = ideal_bits / 2.0
    hash_ceiling_union = union_bound_bits(
        (
            square_root_scaffold_bits,
            512.0 / 3.0,
        )
    )
    return {
        "complete_conditional_branch_error_bits_assumed": BRANCH_TARGET_BITS,
        "complete_conditional_branch_error_certificate_exists": False,
        "ideal_interactive_product_probability": {
            "numerator": ideal_error.numerator,
            "denominator": ideal_error.denominator,
        },
        "ideal_interactive_product_bits": ideal_bits,
        "project_square_root_scaffold_bits": square_root_scaffold_bits,
        "project_square_root_is_qrom_theorem": False,
        "multi_round_measure_reprogram": {
            "asymptotic_loss_shape": "O(q_H^(2*n)) for 2*n+1 public-coin rounds",
            "challenge_pair_count_n": None,
            "quantum_oracle_query_bound_q_H": None,
            "hidden_constant": None,
            "concrete_loss_bits": None,
            "exact_protocol_instantiated": False,
        },
        "conditional_union_with_strict_commitment_collision_ceiling_bits": (
            hash_ceiling_union
        ),
        "generic_hash_terms_are_reductions_for_this_protocol": False,
        "single_term_qrom_loss_budget_before_pq128_bits": (
            square_root_scaffold_bits - PQ_TARGET_BITS
        ),
        "maximum_equal_132_bit_terms_at_or_above_pq128": 16,
        "seventeen_equal_132_bit_terms_union_bits": union_bound_bits([132.0] * 17),
        "shared_failure_rule": (
            "Adv <= product_error + delta_binding + delta_hash + "
            "delta_parser + delta_FS_QROM + sum(delta_other)"
        ),
        "external_failure_ledger_supplied": False,
        "composed_qrom_bound_reviewed": False,
        "strict_pq128_admitted": False,
    }


def transcript_order() -> list[dict[str, object]]:
    """Canonical interactive order required by the conditional theorem."""

    return [
        {
            "stage": 0,
            "actor": "prover",
            "message": (
                "canonical statement, one immutable B128 oracle root, and every "
                "branch commitment needed before the first challenge"
            ),
            "cross_branch_dependency_allowed": False,
        },
        {
            "stage": 1,
            "actor": "verifier",
            "message": (
                "freeze the exact parsed common prefix; reject root, profile, "
                "statement, commitment-count, or order ambiguity"
            ),
            "cross_branch_dependency_allowed": False,
        },
        {
            "stage": 2,
            "actor": "verifier",
            "message": (
                "sample all A verifier coins from the framed A domain and all B "
                "coins from the disjoint B domain; proximity queries are not shared"
            ),
            "cross_branch_dependency_allowed": False,
        },
        {
            "stage": 3,
            "actor": "prover",
            "message": (
                "emit branch-local responses only; any cross-branch state moves "
                "to the history filtration and requires a pointwise conditional "
                "branch-two theorem"
            ),
            "cross_branch_dependency_allowed": "only_if_quantified",
        },
        {
            "stage": 4,
            "actor": "verifier",
            "message": (
                "authenticate the full independent query union against the one "
                "root and require both branches to check the same complete relation"
            ),
            "cross_branch_dependency_allowed": False,
        },
    ]


def report() -> dict[str, object]:
    experiments = [
        fixed_oracle_independent_queries(),
        shared_query_schedule_counterexample(),
        adaptive_cross_branch_counterexample(),
        average_only_counterexample(),
        commitment_grinding_counterexample(2),
        split_relation_counterexample(),
    ]
    return {
        "schema": "hegemon.e256-parallel-product-contract.v1",
        "claim_ceiling": (
            "conditional information-theoretic theorem and byte screen only; "
            "not an instantiated ROM/QROM, PCS, ZK, or production-security proof"
        ),
        "theorem": {
            "filtration_statement": (
                "If Pr[E1|F0] <= eps1 and Pr[E2|F1] <= eps2 for every "
                "positive-probability reachable accepting F1 history, then "
                "Pr[E1 and E2|F0] <= eps1*eps2."
            ),
            "proof_identity": (
                "E[1_E1*Pr(E2|F1)|F0] <= eps2*Pr(E1|F0)"
            ),
            "shared_oracle_allowed": True,
            "shared_oracle_sufficient": False,
            "two_complete_132_bit_conditional_errors_give_bits": IDEAL_PRODUCT_BITS,
        },
        "required_contract": asdict(REQUIRED_IDEAL_CONTRACT),
        "current_source_evidence": {
            **asdict(CURRENT_SOURCE_EVIDENCE),
            "ideal_missing": CURRENT_SOURCE_EVIDENCE.ideal_missing(),
            "fs_qrom_missing": CURRENT_SOURCE_EVIDENCE.fs_qrom_missing(),
            "ideal_product_instantiated": (
                CURRENT_SOURCE_EVIDENCE.ideal_product_instantiated
            ),
            "qrom_product_instantiated": (
                CURRENT_SOURCE_EVIDENCE.qrom_product_instantiated
            ),
        },
        "transcript_order": transcript_order(),
        "transcript_framing": {
            "common_domain_hex": TRANSCRIPT_DOMAIN.hex(),
            "challenge_domain_hex": CHALLENGE_DOMAIN.hex(),
            "branch_labels": {
                branch: label.decode("ascii")
                for branch, label in BRANCH_LABELS.items()
            },
            "frame": "u8 tag || u64le payload length || payload",
            "strict_shared_root_bytes": SHAKE256_512_BYTES,
            "challenge_seed_bytes": SHAKE256_512_BYTES,
            "e256_projection_bytes": E256_BYTES,
            "implemented_here_as_plumbing_not_security_theorem": True,
        },
        "finite_experiments": [experiment.record() for experiment in experiments],
        "exhaustive_small_domain": {
            "branch_local_max_joint": {
                "numerator": exhaustive_branch_local_max().numerator,
                "denominator": exhaustive_branch_local_max().denominator,
            },
            "arbitrary_joint_predicate_max_with_half_marginals": {
                "numerator": exhaustive_correlated_marginal_max().numerator,
                "denominator": exhaustive_correlated_marginal_max().denominator,
            },
        },
        "profiles": [
            asdict(profile)
            for rate in (16, 32)
            for profile in (
                rate_profile(rate),
                direct_bcs_classical_rate_profile(rate),
            )
        ],
        "rejected_legacy_profiles": [
            asdict(rejected_legacy_rate_profile(rate)) for rate in (16, 32)
        ],
        "security": conditional_security_screen(),
        "source_records": source_records(),
        "unfrozen_source_records": unfrozen_source_records(),
        "frontier_eligible": False,
        "verdict": (
            "strict SHAKE256-512 q=44/r16 and q=33/r32 rows remain conditional; "
            "the old 63,320-byte SHAKE448 row is non-strict and no salt profile "
            "instantiates the product or QROM theorem"
        ),
    }


def self_check() -> None:
    branch_error = Fraction(1, 1 << BRANCH_TARGET_BITS)
    assert conditional_product_bound(branch_error, branch_error) == Fraction(
        1, 1 << IDEAL_PRODUCT_BITS
    )
    assert fixed_oracle_independent_queries().joint == Fraction(1, 4)
    assert not fixed_oracle_independent_queries().violates_product
    assert shared_query_schedule_counterexample().joint == Fraction(1, 2)
    assert shared_query_schedule_counterexample().violates_product
    assert adaptive_cross_branch_counterexample().joint == Fraction(1, 2)
    assert average_only_counterexample().joint == Fraction(1, 2)
    assert commitment_grinding_counterexample(2).joint == Fraction(7, 16)
    assert split_relation_counterexample().joint == Fraction(1, 2)
    assert exhaustive_branch_local_max() == Fraction(1, 4)
    assert exhaustive_correlated_marginal_max() == Fraction(1, 2)
    common = canonical_common_prefix(
        profile=b"profile",
        statement=b"statement",
        shared_root=bytes(SHAKE256_512_BYTES),
        prechallenge_commitments=(b"c0", b"c1"),
    )
    seed_a = branch_challenge_seed(
        common_prefix=common, branch="A", round_index=0, local_prefix=b"local"
    )
    seed_b = branch_challenge_seed(
        common_prefix=common, branch="B", round_index=0, local_prefix=b"local"
    )
    assert len(seed_a) == SHAKE256_512_BYTES
    assert seed_a != seed_b
    assert e256_challenge_bytes(seed_a) == seed_a[:E256_BYTES]
    rate16 = rate_profile(16)
    rate32 = rate_profile(32)
    assert rate16.queries_per_branch == 44
    assert rate16.raw_wire_bytes == 83_712
    assert rate16.envelope_wire_bytes == 83_724
    assert rate32.queries_per_branch == 33
    assert rate32.raw_wire_bytes == 69_632
    assert rate32.envelope_wire_bytes == 69_644
    assert direct_bcs_classical_rate_profile(16).raw_wire_bytes == 93_920
    assert direct_bcs_classical_rate_profile(32).raw_wire_bytes == 77_288
    assert rejected_legacy_rate_profile(32).raw_wire_bytes == 63_320
    assert all(record["matches"] for record in source_records())
    assert not CURRENT_SOURCE_EVIDENCE.ideal_product_instantiated
    security = conditional_security_screen()
    assert not security["strict_pq128_admitted"]
    assert not security["multi_round_measure_reprogram"][
        "exact_protocol_instantiated"
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("E256_PARALLEL_PRODUCT_CHECK_PASS")
    if args.report:
        print(json.dumps(report(), sort_keys=True, separators=(",", ":")))
    if not args.check and not args.report:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
