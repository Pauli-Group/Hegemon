#!/usr/bin/env python3
"""Source-only audit of random high-coefficient padding for a compact PCS.

This module proves and tests one narrow statement.  If a *fixed*, B128-linear
view of ``[active coefficients || fresh random padding coefficients]`` has
full row rank on the padding columns, then that view is uniform and independent
of the active coefficients.  It also prices a proposed low-rate univariate
Reed--Solomon commitment with four B128 symbols and one salt per strict
SHAKE256-512 Merkle leaf, shared by two domain-separated E256 algebraic
branches.  SHAKE256-448 rows survive only as explicit non-strict controls.

It is not a PCS, FRI, PIOP, zero-knowledge, or QROM proof.  The production
matrix and compiled active-prefix length are deliberately left uninhabited.
No production oracle is allocated.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


B128_BITS = 128
B128_BYTES = 16
B128_REDUCTION = 0x87
E256_BYTES = 32
STRICT_SHAKE512_BYTES = 64
NON_STRICT_SHAKE448_BYTES = 56
FIAT_SHAMIR_DIGEST_BYTES = 64
CANDIDATE_SALT_BYTES = 32
DIRECT_BCS_N18_SALT_BYTES = 148
DIRECT_BCS_N18_REQUIRED_LAMBDA_BITS = 592
LEAF_GROUP_SYMBOLS = 4
HEADER_BYTES = 64
ENVELOPE_BYTES = 12
RAW_PROOF_CAP_BYTES = 124_068

MESSAGE_LOG = 15
MESSAGE_SYMBOLS = 1 << MESSAGE_LOG
# The frozen source does not emit a compiled active-symbol count.  This is the
# existing architecture sensitivity value, never a measurement.
ACTIVE_SYMBOLS_ASSUMPTION = 26_000
# Source-static interval from the pinned allocation-free maximum-relation
# geometry counter.  Neither endpoint is a compiled count.  The upper endpoint
# leaves only 100 n15 coefficients, so the 26,000 sensitivity value is never an
# authority premise.
SOURCE_STATIC_ACTIVE_SYMBOLS_MIN = 23_594
SOURCE_STATIC_ACTIVE_SYMBOLS_MAX = 32_668
SOURCE_STATIC_RANDOM_TAIL_MIN = MESSAGE_SYMBOLS - SOURCE_STATIC_ACTIVE_SYMBOLS_MAX
SOURCE_STATIC_RANDOM_TAIL_MAX = MESSAGE_SYMBOLS - SOURCE_STATIC_ACTIVE_SYMBOLS_MIN
M4_KECCAK_PERMUTATIONS = 83
M4_KECCAK_BITAND_CONSTRAINTS = 3_187_200
M4_PRIVATE_WORDS = 671
M4_PACKED_PRIVATE_B128 = 336

CLASSICAL_QUERY_TERM_BITS = 264
HALF_BRANCH_QUERY_TERM_BITS = 132
ALGEBRAIC_BRANCHES = 2
ALGEBRAIC_E256_PER_QUERY_PER_BRANCH = 5
ALGEBRAIC_TERMINAL_E256_PER_BRANCH = 2
# Separate from the optimistic 5*q opening term.  These source-only floors are
# the local characteristic-two two-branch n15 kernel and one fused ring switch.
LOCAL_CHAR2_TWO_BRANCH_N15_BYTES = 1_920
FUSED_RING_SWITCH_BYTES = 128
AUXILIARY_TWO_BRANCH_BYTES = (
    LOCAL_CHAR2_TWO_BRANCH_N15_BYTES + FUSED_RING_SWITCH_BYTES
)

# The affine domain is (1 << 127) + span(1, X, ..., X^(log_domain-1)).  It is
# disjoint from zero for every screened domain and remains an additive coset.
AFFINE_DOMAIN_SHIFT = 1 << 127

REPO_ROOT = Path(__file__).resolve().parents[3]
PINNED_SOURCE_FILES = {
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/main.rs":
        "d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c",
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs":
        "67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91",
    ".agent/hardening/binius-pq128-proof-size/max-relation-geometry/static_geometry.py":
        "3173bed7cd489e3f9f9e58c7767464a64cc3406f85ca3ed566931e0aa08791df",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_dependency_records() -> list[dict[str, object]]:
    records = []
    for relative, expected in PINNED_SOURCE_FILES.items():
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


@dataclass(frozen=True)
class BinaryField:
    """Polynomial-basis GF(2^m) with modulus x^m + ``reduction``."""

    bits: int
    reduction: int

    def __post_init__(self) -> None:
        if self.bits <= 0:
            raise ValueError("field width must be positive")
        if not 0 < self.reduction < (1 << self.bits):
            raise ValueError("reduction polynomial tail is not canonical")

    @property
    def size(self) -> int:
        return 1 << self.bits

    @property
    def mask(self) -> int:
        return self.size - 1

    def element(self, value: int) -> int:
        if not 0 <= value < self.size:
            raise ValueError("non-canonical field element")
        return value

    def add(self, left: int, right: int) -> int:
        return self.element(left) ^ self.element(right)

    def mul(self, left: int, right: int) -> int:
        left = self.element(left)
        right = self.element(right)
        result = 0
        for _ in range(self.bits):
            if right & 1:
                result ^= left
            right >>= 1
            carry = left >> (self.bits - 1)
            left = (left << 1) & self.mask
            if carry:
                left ^= self.reduction
        return result

    def pow(self, value: int, exponent: int) -> int:
        if exponent < 0:
            raise ValueError("negative field exponent")
        value = self.element(value)
        result = 1
        while exponent:
            if exponent & 1:
                result = self.mul(result, value)
            value = self.mul(value, value)
            exponent >>= 1
        return result

    def inverse(self, value: int) -> int:
        value = self.element(value)
        if value == 0:
            raise ZeroDivisionError("zero has no field inverse")
        return self.pow(value, self.size - 2)


B128 = BinaryField(B128_BITS, B128_REDUCTION)
GF16 = BinaryField(4, 0b0011)  # x^4 + x + 1
GF2 = BinaryField(1, 0b1)  # x + 1


def matrix_rank(rows: Sequence[Sequence[int]], field: BinaryField) -> int:
    """Return exact row rank over ``field`` by reduced row elimination."""

    if not rows:
        return 0
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError("ragged matrix")
    matrix = [[field.element(value) for value in row] for row in rows]
    pivot_row = 0
    for column in range(width):
        pivot = next(
            (index for index in range(pivot_row, len(matrix)) if matrix[index][column]),
            None,
        )
        if pivot is None:
            continue
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        inverse = field.inverse(matrix[pivot_row][column])
        matrix[pivot_row] = [field.mul(value, inverse) for value in matrix[pivot_row]]
        for index, row in enumerate(matrix):
            if index == pivot_row or row[column] == 0:
                continue
            factor = row[column]
            matrix[index] = [
                value ^ field.mul(factor, pivot_value)
                for value, pivot_value in zip(row, matrix[pivot_row])
            ]
        pivot_row += 1
        if pivot_row == len(matrix):
            break
    return pivot_row


def apply_matrix(
    rows: Sequence[Sequence[int]], vector: Sequence[int], field: BinaryField
) -> tuple[int, ...]:
    if any(len(row) != len(vector) for row in rows):
        raise ValueError("matrix/vector shape mismatch")
    return tuple(
        _dot(row, vector, field)
        for row in rows
    )


def _dot(left: Sequence[int], right: Sequence[int], field: BinaryField) -> int:
    if len(left) != len(right):
        raise ValueError("dot-product shape mismatch")
    result = 0
    for a, b in zip(left, right):
        result ^= field.mul(a, b)
    return result


@dataclass(frozen=True)
class RankAudit:
    observations: int
    active_columns: int
    padding_columns: int
    padding_rank: int
    joint_rank: int
    padding_full_row_rank: bool
    witness_independent_for_fixed_matrix: bool
    full_uniform_for_fixed_matrix: bool
    schedule_independent_of_padding: bool
    lemma_applies: bool


def audit_observation_matrix(
    rows: Sequence[Sequence[int]],
    active_columns: int,
    field: BinaryField,
    *,
    schedule_independent_of_padding: bool,
) -> RankAudit:
    """Audit the exact fixed-matrix hiding criterion.

    For observations ``Y = W_active*x + W_pad*r`` with uniform ``r``, the
    distribution is independent of ``x`` iff every active shift lies in the
    image of ``W_pad``.  In rank form this is

        rank([W_pad | W_active]) == rank(W_pad).

    The stronger ``rank(W_pad) == rows`` makes ``Y`` uniform on the entire
    observation space.  Neither conclusion applies when the row schedule is a
    function of ``r``; callers must set the explicit independence flag.
    """

    if active_columns < 0:
        raise ValueError("negative active-column count")
    if not rows:
        raise ValueError("an audit needs at least one observation")
    width = len(rows[0])
    if active_columns > width or any(len(row) != width for row in rows):
        raise ValueError("invalid observation matrix shape")
    active = [list(row[:active_columns]) for row in rows]
    padding = [list(row[active_columns:]) for row in rows]
    padding_rank = matrix_rank(padding, field)
    joint_rank = matrix_rank(
        [pad_row + active_row for pad_row, active_row in zip(padding, active)],
        field,
    )
    independent = joint_rank == padding_rank
    full = padding_rank == len(rows)
    return RankAudit(
        observations=len(rows),
        active_columns=active_columns,
        padding_columns=width - active_columns,
        padding_rank=padding_rank,
        joint_rank=joint_rank,
        padding_full_row_rank=full,
        witness_independent_for_fixed_matrix=independent,
        full_uniform_for_fixed_matrix=full,
        schedule_independent_of_padding=schedule_independent_of_padding,
        lemma_applies=schedule_independent_of_padding and independent,
    )


def exhaustive_distribution(
    rows: Sequence[Sequence[int]],
    active: Sequence[int],
    field: BinaryField,
    *,
    maximum_assignments: int = 1_000_000,
) -> Counter[tuple[int, ...]]:
    """Enumerate a toy field exactly; used to validate the rank theorem."""

    if not rows:
        raise ValueError("empty observation matrix")
    width = len(rows[0])
    if len(active) > width:
        raise ValueError("active prefix exceeds matrix width")
    padding_columns = width - len(active)
    assignments = field.size**padding_columns
    if assignments > maximum_assignments:
        raise ValueError("exhaustive distribution exceeds configured limit")
    distribution: Counter[tuple[int, ...]] = Counter()
    for padding in itertools.product(range(field.size), repeat=padding_columns):
        distribution[apply_matrix(rows, tuple(active) + padding, field)] += 1
    return distribution


def polynomial_evaluation_row(
    point: int, coefficient_count: int, field: BinaryField
) -> tuple[int, ...]:
    point = field.element(point)
    if coefficient_count <= 0:
        raise ValueError("coefficient count must be positive")
    row = []
    power = 1
    for _ in range(coefficient_count):
        row.append(power)
        power = field.mul(power, point)
    return tuple(row)


def expand_e256_functional(
    coefficients: Sequence[tuple[int, int]], field: BinaryField
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Expand one E256-linear claim on B128 inputs into two B128 rows.

    Multiplying an embedded B128 input by ``c0 + c1*Y`` yields coordinate
    rows ``c0`` and ``c1``.  This does not assume that two E256 repetitions
    form one larger field.
    """

    first = tuple(field.element(pair[0]) for pair in coefficients)
    second = tuple(field.element(pair[1]) for pair in coefficients)
    return first, second


def observation_union_matrix(
    query_points: Sequence[int],
    terminal_and_fri_e256_functionals: Sequence[Sequence[tuple[int, int]]],
    coefficient_count: int,
    field: BinaryField,
) -> tuple[tuple[int, ...], ...]:
    """Build the complete base-field view that one rank audit must cover.

    Every opened RS symbol contributes one B128 evaluation row.  Every
    terminal or fold/FRI E256 functional contributes both of its B128
    coordinate rows.  Checking only the query rows is deliberately impossible
    through this interface: callers pass the entire union to one rank audit.
    """

    rows = [
        polynomial_evaluation_row(point, coefficient_count, field)
        for point in query_points
    ]
    for functional in terminal_and_fri_e256_functionals:
        if len(functional) != coefficient_count:
            raise ValueError("terminal/FRI functional width mismatch")
        rows.extend(expand_e256_functional(functional, field))
    return tuple(rows)


@dataclass(frozen=True)
class VandermondeTailCertificate:
    observations: int
    active_columns: int
    padding_columns: int
    points_distinct: bool
    points_nonzero: bool
    enough_padding_columns: bool
    full_row_rank: bool
    determinant_argument: str


def vandermonde_tail_certificate(
    points: Sequence[int],
    active_columns: int,
    total_columns: int,
    field: BinaryField,
) -> VandermondeTailCertificate:
    """Certify full padding rank for distinct nonzero RS evaluation points.

    The first ``t`` padding columns at points x_i are
    ``diag(x_i^active) * [1, x_i, ..., x_i^(t-1)]``.  Their determinant is a
    nonzero row-scaling product times the Vandermonde product exactly when the
    points are nonzero and distinct and at least ``t`` padding columns exist.
    """

    if not 0 <= active_columns <= total_columns:
        raise ValueError("invalid active/total coefficient counts")
    canonical = tuple(field.element(point) for point in points)
    distinct = len(set(canonical)) == len(canonical)
    nonzero = all(point != 0 for point in canonical)
    padding = total_columns - active_columns
    enough = len(points) <= padding
    full = bool(points) and distinct and nonzero and enough
    return VandermondeTailCertificate(
        observations=len(points),
        active_columns=active_columns,
        padding_columns=padding,
        points_distinct=distinct,
        points_nonzero=nonzero,
        enough_padding_columns=enough,
        full_row_rank=full,
        determinant_argument=(
            "det=product_i(x_i^active)*product_{i<j}(x_j+x_i) in characteristic two"
        ),
    )


def affine_domain_point(index: int, log_domain_size: int) -> int:
    """Return one nonzero point in a fixed additive affine B128 coset."""

    if not 0 <= log_domain_size < 127:
        raise ValueError("affine domain log must be in 0..126")
    if not 0 <= index < (1 << log_domain_size):
        raise ValueError("domain index out of range")
    return AFFINE_DOMAIN_SHIFT ^ index


def _frame(domain: bytes, *parts: bytes) -> bytes:
    framed = bytearray(domain)
    for part in parts:
        framed.extend(len(part).to_bytes(8, "big"))
        framed.extend(part)
    return bytes(framed)


def _b128_bytes(value: int) -> bytes:
    return B128.element(value).to_bytes(B128_BYTES, "little")


def _validate_leaf(index: int, symbols: Sequence[int], salt: bytes) -> bytes:
    if not 0 <= index < (1 << 64):
        raise ValueError("leaf index must fit u64")
    if len(symbols) != LEAF_GROUP_SYMBOLS:
        raise ValueError("each leaf must contain exactly four B128 symbols")
    if len(salt) not in {CANDIDATE_SALT_BYTES, DIRECT_BCS_N18_SALT_BYTES}:
        raise ValueError("leaf salt must match a declared 32-byte or 148-byte profile")
    return b"".join(_b128_bytes(symbol) for symbol in symbols)


def salted_leaf_hash(index: int, symbols: Sequence[int], salt: bytes) -> bytes:
    """Authoritative strict SHAKE256-512 leaf framing."""

    payload = _validate_leaf(index, symbols, salt)
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-LEAF-SHAKE512-v2\0",
            index.to_bytes(8, "big"),
            salt,
            payload,
        )
    ).digest(STRICT_SHAKE512_BYTES)


def salted_leaf_hash_nonstrict_shake448(
    index: int, symbols: Sequence[int], salt: bytes
) -> bytes:
    """Non-strict 56-byte negative control retained for byte comparison."""

    payload = _validate_leaf(index, symbols, salt)
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-LEAF-SHAKE448-NONSTRICT-v1\0",
            index.to_bytes(8, "big"),
            salt,
            payload,
        )
    ).digest(NON_STRICT_SHAKE448_BYTES)


def merkle_node_hash(level: int, index: int, left: bytes, right: bytes) -> bytes:
    if not 0 <= level < (1 << 16) or not 0 <= index < (1 << 64):
        raise ValueError("Merkle position out of range")
    if len(left) != STRICT_SHAKE512_BYTES or len(right) != STRICT_SHAKE512_BYTES:
        raise ValueError("strict Merkle children must be SHAKE256-512 digests")
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-NODE-SHAKE512-v2\0",
            level.to_bytes(2, "big"),
            index.to_bytes(8, "big"),
            left,
            right,
        )
    ).digest(STRICT_SHAKE512_BYTES)


def merkle_node_hash_nonstrict_shake448(
    level: int, index: int, left: bytes, right: bytes
) -> bytes:
    """Non-strict SHAKE256-448 node negative control."""

    if not 0 <= level < (1 << 16) or not 0 <= index < (1 << 64):
        raise ValueError("Merkle position out of range")
    if (
        len(left) != NON_STRICT_SHAKE448_BYTES
        or len(right) != NON_STRICT_SHAKE448_BYTES
    ):
        raise ValueError("non-strict children must be SHAKE256-448 digests")
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-NODE-SHAKE448-NONSTRICT-v1\0",
            level.to_bytes(2, "big"),
            index.to_bytes(8, "big"),
            left,
            right,
        )
    ).digest(NON_STRICT_SHAKE448_BYTES)


def branch_transcript_digest(
    root: bytes, public_context: bytes, branch: int, counter: int
) -> bytes:
    """Return the authoritative 64-byte SHAKE256 Fiat--Shamir digest."""

    if len(root) != STRICT_SHAKE512_BYTES:
        raise ValueError("one immutable strict root must be 64 bytes")
    if not 0 <= branch < ALGEBRAIC_BRANCHES or not 0 <= counter < (1 << 32):
        raise ValueError("branch/counter out of range")
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-E256-BRANCH-SHAKE512-v2\0",
            branch.to_bytes(1, "big"),
            counter.to_bytes(4, "big"),
            root,
            public_context,
        )
    ).digest(FIAT_SHAMIR_DIGEST_BYTES)


def branch_challenge_e256(
    root: bytes, public_context: bytes, branch: int, counter: int
) -> tuple[int, int]:
    digest = branch_transcript_digest(root, public_context, branch, counter)
    return (
        int.from_bytes(digest[:B128_BYTES], "little"),
        int.from_bytes(digest[B128_BYTES:E256_BYTES], "little"),
    )


def strict_query_count(
    rate_denominator: int, query_term_bits: int = CLASSICAL_QUERY_TERM_BITS
) -> int:
    """Optimistic leading query term retained from the existing screen."""

    if rate_denominator <= 1 or rate_denominator & (rate_denominator - 1):
        raise ValueError("rate denominator must be a power of two greater than one")
    if query_term_bits <= 0:
        raise ValueError("query-term bits must be positive")
    rate = 1.0 / rate_denominator
    bits_per_query = -math.log2(1.0 - (1.0 - rate) ** 2)
    return math.ceil(query_term_bits / bits_per_query)


def canonical_frontier_max(leaf_count: int, opened_leaves: int) -> int:
    """Maximum sibling count in a canonical binary Merkle multiproof."""

    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("leaf count must be a power of two")
    if not 1 <= opened_leaves <= leaf_count:
        raise ValueError("opened leaves must lie within the tree")
    level = math.floor(math.log2(leaf_count / opened_leaves))
    return opened_leaves * (level - 1) + leaf_count // (1 << level)


@dataclass(frozen=True)
class WireProfile:
    rate_denominator: int
    schedule_mode: str
    active_symbols_assumption: int = ACTIVE_SYMBOLS_ASSUMPTION
    query_term_bits_per_branch: int = CLASSICAL_QUERY_TERM_BITS
    commitment_digest_bytes: int = STRICT_SHAKE512_BYTES
    leaf_salt_bytes: int = CANDIDATE_SALT_BYTES

    def __post_init__(self) -> None:
        strict_query_count(self.rate_denominator, self.query_term_bits_per_branch)
        if self.schedule_mode not in {"shared", "independent-worst-union"}:
            raise ValueError("unknown schedule mode")
        if not 0 <= self.active_symbols_assumption <= MESSAGE_SYMBOLS:
            raise ValueError("active-symbol assumption exceeds n15 message")
        if self.commitment_digest_bytes not in {
            STRICT_SHAKE512_BYTES,
            NON_STRICT_SHAKE448_BYTES,
        }:
            raise ValueError("commitment digest must be strict 64 or control 56 bytes")
        if self.leaf_salt_bytes not in {
            CANDIDATE_SALT_BYTES,
            DIRECT_BCS_N18_SALT_BYTES,
        }:
            raise ValueError("unknown leaf-salt profile")

    @property
    def queries_per_branch(self) -> int:
        return strict_query_count(
            self.rate_denominator, self.query_term_bits_per_branch
        )

    @property
    def codeword_symbols(self) -> int:
        # Ordinary univariate RS rate: N coefficients, N/rho evaluations.
        return MESSAGE_SYMBOLS * self.rate_denominator

    @property
    def leaf_count(self) -> int:
        return self.codeword_symbols // LEAF_GROUP_SYMBOLS

    @property
    def union_opened_leaves(self) -> int:
        multiplier = 1 if self.schedule_mode == "shared" else ALGEBRAIC_BRANCHES
        return multiplier * self.queries_per_branch

    @property
    def frontier_nodes_max(self) -> int:
        return canonical_frontier_max(self.leaf_count, self.union_opened_leaves)

    @property
    def opened_b128_symbols(self) -> int:
        return self.union_opened_leaves * LEAF_GROUP_SYMBOLS

    @property
    def merkle_wire_bytes(self) -> int:
        return (
            self.commitment_digest_bytes
            + self.union_opened_leaves
            * (LEAF_GROUP_SYMBOLS * B128_BYTES + self.leaf_salt_bytes)
            + self.frontier_nodes_max * self.commitment_digest_bytes
        )

    @property
    def e256_elements_per_branch(self) -> int:
        return (
            ALGEBRAIC_E256_PER_QUERY_PER_BRANCH * self.queries_per_branch
            + ALGEBRAIC_TERMINAL_E256_PER_BRANCH
        )

    @property
    def algebraic_wire_bytes(self) -> int:
        return ALGEBRAIC_BRANCHES * self.e256_elements_per_branch * E256_BYTES

    @property
    def auxiliary_two_branch_wire_bytes(self) -> int:
        return AUXILIARY_TWO_BRANCH_BYTES

    @property
    def raw_wire_bytes(self) -> int:
        return (
            HEADER_BYTES
            + self.merkle_wire_bytes
            + self.algebraic_wire_bytes
            + self.auxiliary_two_branch_wire_bytes
        )

    @property
    def envelope_wire_bytes(self) -> int:
        return self.raw_wire_bytes + ENVELOPE_BYTES

    @property
    def tree_storage_bytes(self) -> int:
        return (
            self.codeword_symbols * B128_BYTES
            + (self.leaf_count - 1) * self.commitment_digest_bytes
            + self.leaf_count * self.leaf_salt_bytes
        )

    @property
    def strict_hash_profile(self) -> bool:
        return self.commitment_digest_bytes == STRICT_SHAKE512_BYTES

    @property
    def salt_profile(self) -> str:
        if self.leaf_salt_bytes == CANDIDATE_SALT_BYTES:
            return "candidate-32-byte-unproved"
        return "direct-classical-bcs-n18-148-byte-floor"

    @property
    def direct_bcs_n18_salt_floor_met(self) -> bool:
        return (
            self.leaf_count == 1 << 18
            and self.leaf_salt_bytes >= DIRECT_BCS_N18_SALT_BYTES
        )

    @property
    def random_padding_symbols(self) -> int:
        return MESSAGE_SYMBOLS - self.active_symbols_assumption

    @property
    def conservative_b128_observation_rows(self) -> int:
        # Each possibly witness-dependent E256 value exposes two B128
        # coordinates.  This is a capacity upper bound, not a frozen FRI matrix.
        return (
            self.opened_b128_symbols
            + ALGEBRAIC_BRANCHES * self.e256_elements_per_branch * 2
            # Both auxiliary floors are E256-priced.  Until their exact
            # source/free-randomness split is frozen, conservatively count all
            # 2,048 bytes as possibly witness-dependent B128 coordinates.
            + self.auxiliary_two_branch_wire_bytes // B128_BYTES
        )

    @property
    def maximum_active_symbols_for_full_rank_capacity(self) -> int:
        return MESSAGE_SYMBOLS - self.conservative_b128_observation_rows

    @property
    def padding_rank_capacity_headroom(self) -> int:
        return self.random_padding_symbols - self.conservative_b128_observation_rows

    def record(self) -> dict[str, object]:
        return {
            "rate": f"1/{self.rate_denominator}",
            "schedule_mode": self.schedule_mode,
            "hash_profile": (
                "strict-SHAKE256-512"
                if self.strict_hash_profile
                else "NONSTRICT-SHAKE256-448-negative-control"
            ),
            "commitment_digest_bytes": self.commitment_digest_bytes,
            "fiat_shamir_digest_bytes": FIAT_SHAMIR_DIGEST_BYTES,
            "strict_hash_profile": self.strict_hash_profile,
            "non_strict_negative_control": not self.strict_hash_profile,
            "leaf_salt_bytes": self.leaf_salt_bytes,
            "salt_profile": self.salt_profile,
            "candidate_32_byte_salt_pq128_proved": False,
            "direct_bcs_n18_salt_floor_met": self.direct_bcs_n18_salt_floor_met,
            "direct_bcs_n18_required_lambda_bits": (
                DIRECT_BCS_N18_REQUIRED_LAMBDA_BITS
            ),
            "direct_bcs_common_lambda_parameter_match": False,
            "direct_bcs_is_qrom_theorem": False,
            "salt_profile_promotable": False,
            "query_term_bits_per_branch": self.query_term_bits_per_branch,
            "conditional_half_budget_parallel_profile": (
                self.query_term_bits_per_branch == HALF_BRANCH_QUERY_TERM_BITS
            ),
            "half_budget_product_theorem_proved": False,
            "queries_per_branch": self.queries_per_branch,
            "codeword_symbols": self.codeword_symbols,
            "leaf_count": self.leaf_count,
            "leaf_group_symbols": LEAF_GROUP_SYMBOLS,
            "union_opened_leaves": self.union_opened_leaves,
            "opened_b128_symbols": self.opened_b128_symbols,
            "frontier_nodes_max": self.frontier_nodes_max,
            "root_count": 1,
            "merkle_wire_bytes": self.merkle_wire_bytes,
            "e256_elements_per_branch": self.e256_elements_per_branch,
            "algebraic_wire_bytes": self.algebraic_wire_bytes,
            "local_char2_two_branch_n15_bytes": (
                LOCAL_CHAR2_TWO_BRANCH_N15_BYTES
            ),
            "fused_ring_switch_bytes": FUSED_RING_SWITCH_BYTES,
            "auxiliary_two_branch_wire_bytes": self.auxiliary_two_branch_wire_bytes,
            "raw_wire_bytes": self.raw_wire_bytes,
            "envelope_wire_bytes": self.envelope_wire_bytes,
            "raw_cap_bytes": RAW_PROOF_CAP_BYTES,
            "raw_headroom_bytes": RAW_PROOF_CAP_BYTES - self.raw_wire_bytes,
            "fits_raw_screen": self.raw_wire_bytes <= RAW_PROOF_CAP_BYTES,
            "tree_storage_bytes": self.tree_storage_bytes,
            "active_symbols_assumption": self.active_symbols_assumption,
            "active_symbols_sensitivity_authoritative": False,
            "active_symbols_frozen": False,
            "source_static_active_symbols_min": SOURCE_STATIC_ACTIVE_SYMBOLS_MIN,
            "source_static_active_symbols_max": SOURCE_STATIC_ACTIVE_SYMBOLS_MAX,
            "source_static_random_tail_min": SOURCE_STATIC_RANDOM_TAIL_MIN,
            "source_static_random_tail_max": SOURCE_STATIC_RANDOM_TAIL_MAX,
            "random_padding_symbols": self.random_padding_symbols,
            "conservative_b128_observation_rows": (
                self.conservative_b128_observation_rows
            ),
            "maximum_active_symbols_for_full_rank_capacity": (
                self.maximum_active_symbols_for_full_rank_capacity
            ),
            "padding_rank_capacity_headroom": self.padding_rank_capacity_headroom,
            "rank_capacity_possible_under_assumption": (
                self.padding_rank_capacity_headroom >= 0
            ),
            "entire_source_static_interval_has_rank_capacity": (
                SOURCE_STATIC_ACTIVE_SYMBOLS_MAX
                <= self.maximum_active_symbols_for_full_rank_capacity
            ),
            "source_static_interval_intersects_rank_capacity": (
                SOURCE_STATIC_ACTIVE_SYMBOLS_MIN
                <= self.maximum_active_symbols_for_full_rank_capacity
            ),
            "worst_static_tail_capacity_headroom": (
                SOURCE_STATIC_RANDOM_TAIL_MIN
                - self.conservative_b128_observation_rows
            ),
            "exact_production_padding_rank": None,
        }


def adaptive_selector_distribution(witness: int) -> Counter[int]:
    """GF(2) counterexample to applying fixed-matrix rank adaptively.

    The selector is the first random pad bit.  If it is zero, observe pad[0];
    otherwise observe pad[1].  Each realized one-row padding matrix has rank
    one, yet ``witness + selected_pad`` equals the witness with probability
    3/4, not 1/2, because the selected row depends on the padding.
    """

    witness = GF2.element(witness)
    result: Counter[int] = Counter()
    for first, second in itertools.product(range(2), repeat=2):
        selector = first
        selected = (first, second)[selector]
        result[witness ^ selected] += 1
    return result


def key_reuse_delta(
    rows: Sequence[Sequence[int]],
    first_active: Sequence[int],
    second_active: Sequence[int],
    reused_padding: Sequence[int],
    field: BinaryField,
) -> tuple[int, ...]:
    """Return the exact cancellation visible when a random tail is reused."""

    first = apply_matrix(rows, tuple(first_active) + tuple(reused_padding), field)
    second = apply_matrix(rows, tuple(second_active) + tuple(reused_padding), field)
    return tuple(a ^ b for a, b in zip(first, second))


def report() -> dict[str, object]:
    strict_profiles = []
    for rate in (16, 32):
        strict_profiles.extend(
            WireProfile(rate, mode).record()
            for mode in ("shared", "independent-worst-union")
        )
        strict_profiles.append(
            WireProfile(
                rate,
                "independent-worst-union",
                query_term_bits_per_branch=HALF_BRANCH_QUERY_TERM_BITS,
            ).record()
        )
    theorem_scoped_salt_profiles = [
        WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=bits,
            leaf_salt_bytes=DIRECT_BCS_N18_SALT_BYTES,
        ).record()
        for bits in (CLASSICAL_QUERY_TERM_BITS, HALF_BRANCH_QUERY_TERM_BITS)
    ]
    non_strict_controls = [
        WireProfile(
            32,
            "independent-worst-union",
            query_term_bits_per_branch=bits,
            commitment_digest_bytes=NON_STRICT_SHAKE448_BYTES,
        ).record()
        for bits in (CLASSICAL_QUERY_TERM_BITS, HALF_BRANCH_QUERY_TERM_BITS)
    ]
    gates = {
        "compiled_m4_active_symbols_frozen": False,
        "random_tail_excluded_from_relation_proved": False,
        "actual_pcs_fri_functionals_frozen": False,
        "full_observation_union_exported": False,
        "actual_production_padding_submatrix_full_rank": False,
        "fiat_shamir_schedule_independent_of_padding_proved": False,
        "adaptive_bcs_zero_knowledge_proved": False,
        "univariate_rs_proximity_and_extraction_proved": False,
        "fri_proximity_proved": False,
        "maximum_m4_piop_binding_proved": False,
        "candidate_32_byte_salt_pq128_proved": False,
        "direct_bcs_148_byte_salt_profile_promotable": False,
        "salted_shake512_merkle_hiding_qrom_proved": False,
        "shake256_512_commitment_instantiation_proved": False,
        "two_e256_parallel_soundness_proved": False,
        "half_budget_parallel_rbr_product_theorem_proved": False,
        "complete_transcript_simulator_proved": False,
        "global_simulator_proved": False,
        "composed_qrom_pq128_proved": False,
        "canonical_parser_and_verifier_refinement_proved": False,
        "strict_admitted": False,
        "frontier_eligible": False,
    }
    return {
        "schema": "hegemon.m4-random-padding-zk-pcs-screen.v2",
        "claim": {
            "fixed_matrix_rank_lemma": True,
            "full_uniform_condition": "rank(W_pad)=number_of_observations",
            "witness_independence_condition": (
                "rank([W_pad|W_active])=rank(W_pad)"
            ),
            "adaptive_schedule_covered": False,
        },
        "source_inventory": {
            "message_log": MESSAGE_LOG,
            "message_symbols": MESSAGE_SYMBOLS,
            "active_symbols_assumption": ACTIVE_SYMBOLS_ASSUMPTION,
            "active_symbols_sensitivity_authoritative": False,
            "active_symbols_frozen": False,
            "source_static_active_symbols_min": SOURCE_STATIC_ACTIVE_SYMBOLS_MIN,
            "source_static_active_symbols_max": SOURCE_STATIC_ACTIVE_SYMBOLS_MAX,
            "source_static_random_tail_min": SOURCE_STATIC_RANDOM_TAIL_MIN,
            "source_static_random_tail_max": SOURCE_STATIC_RANDOM_TAIL_MAX,
            "m4_keccak_permutations": M4_KECCAK_PERMUTATIONS,
            "m4_keccak_bitand_constraints": M4_KECCAK_BITAND_CONSTRAINTS,
            "m4_private_words": M4_PRIVATE_WORDS,
            "m4_packed_private_b128": M4_PACKED_PRIVATE_B128,
            "source_dependencies": source_dependency_records(),
        },
        "commitment": {
            "encoding": "univariate RS over a nonzero additive affine B128 coset",
            "leaf_symbols": LEAF_GROUP_SYMBOLS,
            "authoritative_leaf_salt_bytes": CANDIDATE_SALT_BYTES,
            "authoritative_merkle_digest": "SHAKE256-512",
            "authoritative_merkle_digest_bytes": STRICT_SHAKE512_BYTES,
            "fiat_shamir_digest": "SHAKE256-512",
            "fiat_shamir_digest_bytes": FIAT_SHAMIR_DIGEST_BYTES,
            "non_strict_control_digest": "SHAKE256-448",
            "non_strict_control_digest_bytes": NON_STRICT_SHAKE448_BYTES,
            "immutable_root_count": 1,
            "algebraic_branches": ALGEBRAIC_BRANCHES,
            "algebraic_field_per_branch": "E256",
            "branch_domain_separation": True,
        },
        "strict_profiles": strict_profiles,
        "theorem_scoped_salt_profiles": theorem_scoped_salt_profiles,
        "non_strict_shake448_negative_controls": non_strict_controls,
        "salt_theorem_scope": {
            "candidate_32_byte_salt_status": "UNPROVED_FOR_PQ128",
            "rate32_leaf_count": 1 << 18,
            "direct_classical_bcs_lambda_bits_for_128_bound": (
                DIRECT_BCS_N18_REQUIRED_LAMBDA_BITS
            ),
            "direct_classical_bcs_salt_bytes_floor": DIRECT_BCS_N18_SALT_BYTES,
            "strict_digest_bits": STRICT_SHAKE512_BYTES * 8,
            "one_common_bcs_lambda_parameter_exists": False,
            "classical_bcs_result_is_qrom": False,
            "any_salt_profile_promotable": False,
        },
        "gates": gates,
        "verdict": (
            "rank lemma and wire screen survive; production ZK/PCS/security does not"
        ),
    }


def self_check() -> None:
    assert B128.mul(0x1234, 1) == 0x1234
    assert B128.mul(0x80000000000000000000000000000000, 2) == 0x87
    assert strict_query_count(16) == 87
    assert strict_query_count(32) == 66
    assert strict_query_count(16, HALF_BRANCH_QUERY_TERM_BITS) == 44
    assert strict_query_count(32, HALF_BRANCH_QUERY_TERM_BITS) == 33
    profile = WireProfile(32, "independent-worst-union")
    assert profile.raw_wire_bytes == 128_512
    assert profile.padding_rank_capacity_headroom == 4_784
    assert profile.raw_wire_bytes > RAW_PROOF_CAP_BYTES
    half = WireProfile(
        32,
        "independent-worst-union",
        query_term_bits_per_branch=HALF_BRANCH_QUERY_TERM_BITS,
    )
    assert half.raw_wire_bytes == 69_632
    assert half.padding_rank_capacity_headroom == 5_708
    non_strict_half = WireProfile(
        32,
        "independent-worst-union",
        query_term_bits_per_branch=HALF_BRANCH_QUERY_TERM_BITS,
        commitment_digest_bytes=NON_STRICT_SHAKE448_BYTES,
    )
    assert non_strict_half.raw_wire_bytes == 63_320
    bcs_salt_half = WireProfile(
        32,
        "independent-worst-union",
        query_term_bits_per_branch=HALF_BRANCH_QUERY_TERM_BITS,
        leaf_salt_bytes=DIRECT_BCS_N18_SALT_BYTES,
    )
    assert bcs_salt_half.raw_wire_bytes == 77_288
    assert SOURCE_STATIC_RANDOM_TAIL_MIN == 100
    assert SOURCE_STATIC_RANDOM_TAIL_MAX == 9_174
    assert all(record["matches"] for record in source_dependency_records())
    assert not report()["gates"]["strict_admitted"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("RANDOM_PADDING_PCS_CHECK_PASS")
    if args.report:
        print(json.dumps(report(), sort_keys=True, separators=(",", ":")))
    if not args.check and not args.report:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
