#!/usr/bin/env python3
"""Exact, fail-closed one-level mixed-field Ligerito opening core.

This module implements the base case described in Section 5 of the Ligerito
paper.  It is deliberately narrower than a transaction proof system:

* source symbols and committed Reed--Solomon rows are in ``B128``;
* public functionals, partial-sumcheck messages, and verifier coins are in
  the cubic extension ``E384``;
* every commitment/transcript/profile/parser digest is conventional SHA-512;
* the proof grammar is fixed, exact-length, and externally parameter pinned;
* the parameter report uses Ligerito equation (15), not the unproved local
  Johnson/Flock shortcut; and
* the complete-ZK and production interfaces are explicit and always false.

The implementation is dependency-free.  Production-size proving is guarded by
an explicit allocation limit so importing or checking this module cannot build
a large oracle accidentally.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import struct
from dataclasses import asdict, dataclass
from typing import Sequence


B128_BITS = 128
B128_BYTES = 16
B128_MASK = (1 << B128_BITS) - 1
# x^128 + x^7 + x^2 + x + 1, in the standard GCM polynomial basis.
B128_REDUCTION = 0x87
E384_BYTES = 48
SHA512_BYTES = 64
PUBLIC_CONTEXT_BYTES = 64

MAGIC = b"HGL1E384"
VERSION = 1
FLAGS = 0
HEADER_FORMAT = ">8sHH64s4B3H3IQ22s"
HEADER_BYTES = struct.calcsize(HEADER_FORMAT)
if HEADER_BYTES != 128:
    raise AssertionError("canonical Ligerito header must remain 128 bytes")

MAX_DEFAULT_ORACLE_BYTES = 8 * 1024 * 1024
CURRENT_M4_COMPARATOR_BYTES = 1_344_828
SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES = 118_070
HISTORICAL_RAW_PROOF_CAP_BYTES = 124_068


def b128(value: int) -> int:
    """Return one canonical ``GF(2^128)`` polynomial-basis element."""

    if not isinstance(value, int) or not 0 <= value <= B128_MASK:
        raise ValueError("non-canonical B128 value")
    return value


def b128_add(left: int, right: int) -> int:
    return b128(left) ^ b128(right)


def b128_mul(left: int, right: int) -> int:
    """Multiply in ``GF(2^128)`` modulo the fixed GCM polynomial."""

    multiplicand = b128(left)
    multiplier = b128(right)
    result = 0
    for _ in range(B128_BITS):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        carry = multiplicand >> (B128_BITS - 1)
        multiplicand = (multiplicand << 1) & B128_MASK
        if carry:
            multiplicand ^= B128_REDUCTION
    return result


def b128_to_bytes(value: int) -> bytes:
    return b128(value).to_bytes(B128_BYTES, "little")


def b128_from_bytes(encoded: bytes) -> int:
    if len(encoded) != B128_BYTES:
        raise ValueError("a B128 element is exactly 16 bytes")
    return int.from_bytes(encoded, "little")


@dataclass(frozen=True)
class E384:
    """``B128[Y] / (Y^3 + Y + 1)`` in the basis ``(1,Y,Y^2)``."""

    c0: int
    c1: int
    c2: int

    def __post_init__(self) -> None:
        b128(self.c0)
        b128(self.c1)
        b128(self.c2)

    @classmethod
    def zero(cls) -> "E384":
        return cls(0, 0, 0)

    @classmethod
    def one(cls) -> "E384":
        return cls(1, 0, 0)

    @classmethod
    def embed(cls, value: int) -> "E384":
        return cls(b128(value), 0, 0)

    @classmethod
    def from_bytes(cls, encoded: bytes) -> "E384":
        if len(encoded) != E384_BYTES:
            raise ValueError("an E384 element is exactly 48 bytes")
        return cls(
            b128_from_bytes(encoded[0:16]),
            b128_from_bytes(encoded[16:32]),
            b128_from_bytes(encoded[32:48]),
        )

    def to_bytes(self) -> bytes:
        return b"".join(
            (b128_to_bytes(self.c0), b128_to_bytes(self.c1), b128_to_bytes(self.c2))
        )

    def __add__(self, other: "E384") -> "E384":
        if not isinstance(other, E384):
            return NotImplemented
        return E384(self.c0 ^ other.c0, self.c1 ^ other.c1, self.c2 ^ other.c2)

    def __sub__(self, other: "E384") -> "E384":
        # Characteristic two.
        return self + other

    def __mul__(self, other: "E384") -> "E384":
        if not isinstance(other, E384):
            return NotImplemented
        a0, a1, a2 = self.c0, self.c1, self.c2
        b0, b1, b2 = other.c0, other.c1, other.c2
        d0 = b128_mul(a0, b0)
        d1 = b128_mul(a0, b1) ^ b128_mul(a1, b0)
        d2 = b128_mul(a0, b2) ^ b128_mul(a1, b1) ^ b128_mul(a2, b0)
        d3 = b128_mul(a1, b2) ^ b128_mul(a2, b1)
        d4 = b128_mul(a2, b2)
        # Y^3 = Y + 1 and Y^4 = Y^2 + Y.
        return E384(d0 ^ d3, d1 ^ d3 ^ d4, d2 ^ d4)


def _sha512(domain: bytes, *parts: bytes) -> bytes:
    """Full-output SHA-512 with one unambiguous length-delimited frame."""

    if not isinstance(domain, bytes) or len(domain) > 0xFFFF:
        raise ValueError("invalid SHA-512 domain")
    if len(parts) > 0xFFFF:
        raise ValueError("too many SHA-512 frame parts")
    digest = hashlib.sha512()
    digest.update(b"HEGEMON-LIGERITO-SHA512-FRAME-v1\x00")
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(parts).to_bytes(2, "big"))
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("SHA-512 frame parts must be bytes")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


class Transcript:
    """Deterministic SHA-512 Fiat--Shamir wrapper for the public-coin MIOP."""

    def __init__(self) -> None:
        self._state = _sha512(b"transcript/init")

    def observe(self, label: bytes, value: bytes) -> None:
        self._state = _sha512(b"transcript/observe", self._state, label, value)

    def challenge_e384(self, label: bytes) -> E384:
        raw = _sha512(b"transcript/e384", self._state, label)
        value = E384.from_bytes(raw[:E384_BYTES])
        self.observe(b"coin/e384/" + label, value.to_bytes())
        return value

    def distinct_indices(self, label: bytes, count: int, upper: int) -> tuple[int, ...]:
        """Sample unbiased, ordered, distinct indices without replacement."""

        if not 0 <= count <= upper or not 0 < upper < (1 << 32):
            raise ValueError("invalid distinct-query geometry")
        selected: list[int] = []
        seen: set[int] = set()
        rejection_limit = (1 << 64) - ((1 << 64) % upper)
        counter = 0
        while len(selected) < count:
            block = _sha512(
                b"transcript/index",
                self._state,
                label,
                counter.to_bytes(8, "big"),
            )
            counter += 1
            candidate = int.from_bytes(block[:8], "big")
            if candidate >= rejection_limit:
                continue
            index = candidate % upper
            if index not in seen:
                seen.add(index)
                selected.append(index)
        encoded = b"".join(index.to_bytes(4, "big") for index in selected)
        self.observe(b"coin/indices/" + label, encoded)
        return tuple(selected)


@functools.lru_cache(maxsize=None)
def max_compact_merkle_frontier_nodes(log_leaves: int, opened: int) -> int:
    """Exact maximum compact frontier for ``opened`` complete-tree leaves."""

    if log_leaves < 0 or opened < 0 or opened > (1 << log_leaves):
        raise ValueError("invalid Merkle geometry")
    if opened == 0 or (log_leaves == 0 and opened == 1):
        return 0
    if log_leaves == 0:
        raise ValueError("invalid Merkle leaf count")
    child_capacity = 1 << (log_leaves - 1)
    left_min = max(0, opened - child_capacity)
    left_max = min(opened, child_capacity)
    best = -1
    for left in range(left_min, left_max + 1):
        right = opened - left
        if left == 0:
            candidate = 1 + max_compact_merkle_frontier_nodes(log_leaves - 1, right)
        elif right == 0:
            candidate = 1 + max_compact_merkle_frontier_nodes(log_leaves - 1, left)
        else:
            candidate = (
                max_compact_merkle_frontier_nodes(log_leaves - 1, left)
                + max_compact_merkle_frontier_nodes(log_leaves - 1, right)
            )
        best = max(best, candidate)
    return best


def _log2_sum(left: float, right: float) -> float:
    """Return ``log2(2**left + 2**right)`` without underflow."""

    high = max(left, right)
    low = min(left, right)
    return high + math.log2(1.0 + math.exp2(low - high))


def source_ligerito_log2_error(
    *,
    message_rows: int,
    codeword_rows: int,
    fold_variables: int,
    query_count: int,
) -> tuple[float, float, float]:
    """Ligerito equation (15) terms and their composed log2 error.

    The returned tuple is ``(query_term, field_terms, union)`` in log2
    probability.  ``|F|`` is the declared E384 challenge field, ``2^384``.
    """

    if not 0 < message_rows < codeword_rows:
        raise ValueError("invalid Reed--Solomon dimensions")
    if not 0 < fold_variables or not 0 < query_count <= codeword_rows:
        raise ValueError("invalid Ligerito soundness geometry")
    numerator = codeword_rows - message_rows - 1
    if numerator <= 0:
        raise ValueError("unique-decoding miss probability is not positive")
    query_log2 = query_count * (
        math.log2(numerator) - math.log2(2 * codeword_rows)
    )
    # m*k'/|F| + 2*k'/|F| = k'*(m+2)/2^384.
    field_log2 = math.log2(fold_variables * (codeword_rows + 2)) - 384.0
    return query_log2, field_log2, _log2_sum(query_log2, field_log2)


def query_count_for_source_security(
    *,
    message_rows: int,
    codeword_rows: int,
    fold_variables: int,
    target_bits: int,
) -> int:
    """Smallest ``q`` making the exact equation-(15) union at most ``2^-target``."""

    if not 1 <= target_bits <= 65535:
        raise ValueError("invalid source-security target")
    _, field_log2, _ = source_ligerito_log2_error(
        message_rows=message_rows,
        codeword_rows=codeword_rows,
        fold_variables=fold_variables,
        query_count=1,
    )
    if field_log2 >= -target_bits:
        raise ValueError("E384 field term cannot meet the requested source target")
    per_query_bits = -source_ligerito_log2_error(
        message_rows=message_rows,
        codeword_rows=codeword_rows,
        fold_variables=fold_variables,
        query_count=1,
    )[0]
    query_count = max(1, math.ceil(target_bits / per_query_bits))
    while True:
        union_log2 = source_ligerito_log2_error(
            message_rows=message_rows,
            codeword_rows=codeword_rows,
            fold_variables=fold_variables,
            query_count=query_count,
        )[2]
        if union_log2 <= -target_bits:
            return query_count
        query_count += 1
        if query_count > codeword_rows:
            raise ValueError("distinct-query domain cannot meet the source target")


@dataclass(frozen=True)
class WireLedger:
    header: int
    statement_id: int
    commitment_root: int
    claimed_value: int
    sumcheck: int
    terminal: int
    opened_rows: int
    authentication: int

    @property
    def total(self) -> int:
        return sum(asdict(self).values())


@dataclass(frozen=True)
class ResourceLedger:
    """Exact geometry-derived counts for this concrete source algorithm.

    Data-dependent SHA-512 query-rejection/duplicate draws require an actual
    transcript and are deliberately identified as not fixed by geometry.
    """

    source_b128_elements: int
    source_b128_bytes: int
    public_weight_e384_elements: int
    public_weight_e384_bytes: int
    encoded_oracle_b128_elements: int
    encoded_oracle_bytes: int
    rs_codeword_symbol_evaluations: int
    rs_horner_steps: int
    merkle_leaf_hashes: int
    merkle_internal_hashes: int
    sumcheck_rounds: int
    prover_sumcheck_message_pairs: int
    prover_value_fold_pairs: int
    prover_basis_fold_pairs: int
    terminal_e384_elements: int
    opened_b128_elements: int
    authentication_sha512_digests: int
    verifier_terminal_rs_horner_steps: int
    verifier_row_fold_pairs: int
    verifier_basis_fold_pairs: int
    transcript_query_hashes_fixed_by_geometry: bool


@dataclass(frozen=True)
class Parameters:
    """Externally pinned one-level geometry and source soundness target."""

    log_relation_size: int
    fold_variables: int
    log_inv_rate: int
    query_count: int
    source_security_bits: int

    def __post_init__(self) -> None:
        if not 2 <= self.log_relation_size <= 30:
            raise ValueError("unsupported relation bucket")
        if not 1 <= self.fold_variables < self.log_relation_size:
            raise ValueError("fold variables must leave a nonempty terminal")
        if not 1 <= self.log_inv_rate <= 30:
            raise ValueError("invalid inverse-rate logarithm")
        if not 1 <= self.query_count <= self.codeword_rows:
            raise ValueError("invalid distinct-query count")
        if not 1 <= self.source_security_bits <= 65535:
            raise ValueError("invalid source-security target")
        if self.codeword_rows >= (1 << 32):
            raise ValueError("wire indexes are fixed to 32 bits")
        if self.query_count > 65535:
            raise ValueError("wire query count exceeds 16 bits")
        if self.terminal_count >= (1 << 32):
            raise ValueError("wire terminal count exceeds 32 bits")
        if self.frontier_nodes >= (1 << 32):
            raise ValueError("wire frontier exceeds 32 bits")
        if self.encoded_oracle_bytes >= (1 << 64):
            raise ValueError("wire resource count exceeds 64 bits")
        if self.source_soundness_bits + 1e-12 < self.source_security_bits:
            raise ValueError("query count does not meet the pinned source target")

    @classmethod
    def for_source_security(
        cls,
        *,
        log_relation_size: int,
        fold_variables: int,
        log_inv_rate: int,
        source_security_bits: int,
    ) -> "Parameters":
        message_rows = 1 << (log_relation_size - fold_variables)
        codeword_rows = message_rows << log_inv_rate
        query_count = query_count_for_source_security(
            message_rows=message_rows,
            codeword_rows=codeword_rows,
            fold_variables=fold_variables,
            target_bits=source_security_bits,
        )
        return cls(
            log_relation_size=log_relation_size,
            fold_variables=fold_variables,
            log_inv_rate=log_inv_rate,
            query_count=query_count,
            source_security_bits=source_security_bits,
        )

    @property
    def residual_variables(self) -> int:
        return self.log_relation_size - self.fold_variables

    @property
    def source_symbols(self) -> int:
        return 1 << self.log_relation_size

    @property
    def data_columns(self) -> int:
        return 1 << self.fold_variables

    @property
    def message_rows(self) -> int:
        return 1 << self.residual_variables

    @property
    def codeword_rows(self) -> int:
        return self.message_rows << self.log_inv_rate

    @property
    def log_codeword_rows(self) -> int:
        return self.residual_variables + self.log_inv_rate

    @property
    def terminal_count(self) -> int:
        return self.message_rows

    @property
    def sumcheck_count(self) -> int:
        return self.fold_variables

    @property
    def frontier_nodes(self) -> int:
        return max_compact_merkle_frontier_nodes(
            self.log_codeword_rows, self.query_count
        )

    @property
    def encoded_oracle_bytes(self) -> int:
        return self.codeword_rows * self.data_columns * B128_BYTES

    @property
    def source_soundness_log2_terms(self) -> tuple[float, float, float]:
        return source_ligerito_log2_error(
            message_rows=self.message_rows,
            codeword_rows=self.codeword_rows,
            fold_variables=self.fold_variables,
            query_count=self.query_count,
        )

    @property
    def source_soundness_bits(self) -> float:
        return -self.source_soundness_log2_terms[2]

    @property
    def profile_id(self) -> bytes:
        material = b"|".join(
            (
                b"hegemon-ligerito-e384-core-v1",
                b"source=Ligerito-section5-equation15-unique-decoding",
                b"hash=SHA-512-full-output-framed-v1",
                b"B128=x128+x7+x2+x+1:LE16",
                b"E384=Y3+Y+1:3xLE16",
                b"layout=vecX[row+R*column]:column-stacked",
                b"code=coefficient-RS:point=index+1",
                b"fold=column-bits-LSB-first",
                f"n={self.log_relation_size}".encode(),
                f"p={self.fold_variables}".encode(),
                f"rate_inv=2^{self.log_inv_rate}".encode(),
                f"q={self.query_count}".encode(),
                f"source_bits={self.source_security_bits}".encode(),
            )
        )
        return _sha512(b"profile", material)

    @property
    def wire_ledger(self) -> WireLedger:
        return WireLedger(
            header=HEADER_BYTES,
            statement_id=SHA512_BYTES,
            commitment_root=SHA512_BYTES,
            claimed_value=E384_BYTES,
            sumcheck=self.sumcheck_count * 2 * E384_BYTES,
            terminal=self.terminal_count * E384_BYTES,
            opened_rows=self.query_count * self.data_columns * B128_BYTES,
            authentication=self.frontier_nodes * SHA512_BYTES,
        )

    @property
    def proof_bytes(self) -> int:
        return self.wire_ledger.total

    @property
    def resource_ledger(self) -> ResourceLedger:
        encoded_elements = self.codeword_rows * self.data_columns
        all_sumcheck_pairs = self.source_symbols - self.terminal_count
        return ResourceLedger(
            source_b128_elements=self.source_symbols,
            source_b128_bytes=self.source_symbols * B128_BYTES,
            public_weight_e384_elements=self.source_symbols,
            public_weight_e384_bytes=self.source_symbols * E384_BYTES,
            encoded_oracle_b128_elements=encoded_elements,
            encoded_oracle_bytes=self.encoded_oracle_bytes,
            rs_codeword_symbol_evaluations=encoded_elements,
            rs_horner_steps=encoded_elements * self.message_rows,
            merkle_leaf_hashes=self.codeword_rows,
            merkle_internal_hashes=self.codeword_rows - 1,
            sumcheck_rounds=self.fold_variables,
            prover_sumcheck_message_pairs=all_sumcheck_pairs,
            prover_value_fold_pairs=all_sumcheck_pairs,
            prover_basis_fold_pairs=all_sumcheck_pairs,
            terminal_e384_elements=self.terminal_count,
            opened_b128_elements=self.query_count * self.data_columns,
            authentication_sha512_digests=self.frontier_nodes,
            verifier_terminal_rs_horner_steps=(
                self.query_count * self.terminal_count
            ),
            verifier_row_fold_pairs=(
                self.query_count * (self.data_columns - 1)
            ),
            verifier_basis_fold_pairs=all_sumcheck_pairs,
            transcript_query_hashes_fixed_by_geometry=False,
        )

    def header(self) -> bytes:
        encoded = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            FLAGS,
            self.profile_id,
            self.log_relation_size,
            self.fold_variables,
            self.log_inv_rate,
            B128_BYTES,
            self.query_count,
            self.source_security_bits,
            self.sumcheck_count,
            self.terminal_count,
            self.frontier_nodes,
            self.source_symbols,
            self.encoded_oracle_bytes,
            bytes(22),
        )
        if len(encoded) != HEADER_BYTES:
            raise AssertionError("canonical header size drift")
        return encoded


@dataclass(frozen=True)
class OpeningStatement:
    """Public functional and expected inner-product claim."""

    public_context: bytes
    weights: tuple[E384, ...]
    claimed_value: E384

    def __post_init__(self) -> None:
        if len(self.public_context) != PUBLIC_CONTEXT_BYTES:
            raise ValueError("public context must be exactly 64 bytes")
        object.__setattr__(self, "weights", tuple(self.weights))
        if not all(isinstance(value, E384) for value in self.weights):
            raise TypeError("public weights must be E384 elements")
        if not isinstance(self.claimed_value, E384):
            raise TypeError("claimed value must be E384")

    def validate(self, params: Parameters) -> None:
        if len(self.weights) != params.source_symbols:
            raise ValueError("public functional does not match the relation bucket")

    def weights_bytes(self) -> bytes:
        return b"".join(value.to_bytes() for value in self.weights)

    def weights_digest(self, params: Parameters) -> bytes:
        self.validate(params)
        return _sha512(b"statement/weights", params.profile_id, self.weights_bytes())

    def identifier(self, params: Parameters) -> bytes:
        self.validate(params)
        return _sha512(
            b"statement/id",
            params.profile_id,
            self.public_context,
            self.weights_digest(params),
            self.claimed_value.to_bytes(),
        )


def _fold(values: Sequence[E384], challenge: E384) -> list[E384]:
    if len(values) == 0 or len(values) % 2:
        raise ValueError("fold input must have nonzero even length")
    one_plus = E384.one() + challenge
    return [
        values[index] * one_plus + values[index + 1] * challenge
        for index in range(0, len(values), 2)
    ]


def _inner_product(left: Sequence[E384], right: Sequence[E384]) -> E384:
    if len(left) != len(right):
        raise ValueError("inner-product length mismatch")
    result = E384.zero()
    for left_value, right_value in zip(left, right):
        result = result + left_value * right_value
    return result


def _round_message(
    values: Sequence[E384], basis: Sequence[E384]
) -> tuple[E384, E384]:
    """Return ``(constant, quadratic)`` for one characteristic-two round.

    The linear coefficient is reconstructed as ``previous_claim + quadratic``;
    therefore exactly two E384 values encode the degree-two polynomial while
    enforcing ``g(0)+g(1)=previous_claim`` by construction.
    """

    if len(values) != len(basis) or len(values) == 0 or len(values) % 2:
        raise ValueError("sumcheck round geometry mismatch")
    constant = E384.zero()
    quadratic = E384.zero()
    for index in range(0, len(values), 2):
        f0, f1 = values[index], values[index + 1]
        w0, w1 = basis[index], basis[index + 1]
        constant = constant + f0 * w0
        quadratic = quadratic + (f0 + f1) * (w0 + w1)
    return constant, quadratic


def _round_evaluate(
    message: tuple[E384, E384], previous_claim: E384, challenge: E384
) -> E384:
    constant, quadratic = message
    linear = previous_claim + quadratic
    return constant + challenge * linear + (challenge * challenge) * quadratic


def _source_to_row_major_e384(source: Sequence[int], params: Parameters) -> list[E384]:
    """Transpose column-stacked ``vec(X)`` for adjacent column-variable folds."""

    if len(source) != params.source_symbols:
        raise ValueError("source length does not match the relation bucket")
    rows = params.message_rows
    columns = params.data_columns
    return [
        E384.embed(b128(source[row + rows * column]))
        for row in range(rows)
        for column in range(columns)
    ]


def _weights_to_row_major(statement: OpeningStatement, params: Parameters) -> list[E384]:
    statement.validate(params)
    rows = params.message_rows
    columns = params.data_columns
    return [
        statement.weights[row + rows * column]
        for row in range(rows)
        for column in range(columns)
    ]


def _rs_evaluate_b128(coefficients: Sequence[int], point: int) -> int:
    accumulator = 0
    for coefficient in reversed(coefficients):
        accumulator = b128_mul(accumulator, point) ^ b128(coefficient)
    return accumulator


def _rs_evaluate_e384(coefficients: Sequence[E384], point: int) -> E384:
    accumulator = E384.zero()
    embedded_point = E384.embed(point)
    for coefficient in reversed(coefficients):
        accumulator = accumulator * embedded_point + coefficient
    return accumulator


def _domain_point(index: int) -> int:
    if not 0 <= index < B128_MASK:
        raise ValueError("B128 Reed--Solomon domain exhausted")
    return index + 1


def _encode_source(
    source: Sequence[int],
    params: Parameters,
    *,
    allocation_limit_bytes: int,
) -> list[tuple[int, ...]]:
    if len(source) != params.source_symbols:
        raise ValueError("source length does not match the relation bucket")
    if any(not isinstance(value, int) or not 0 <= value <= B128_MASK for value in source):
        raise ValueError("source contains a non-canonical B128 value")
    if allocation_limit_bytes < params.encoded_oracle_bytes:
        raise ValueError(
            "encoded oracle exceeds the explicit allocation limit: "
            f"need {params.encoded_oracle_bytes}, limit {allocation_limit_bytes}"
        )
    rows = params.message_rows
    columns = params.data_columns
    source_columns = [
        [source[row + rows * column] for row in range(rows)]
        for column in range(columns)
    ]
    encoded_rows: list[tuple[int, ...]] = []
    for row_index in range(params.codeword_rows):
        point = _domain_point(row_index)
        encoded_rows.append(
            tuple(_rs_evaluate_b128(column, point) for column in source_columns)
        )
    return encoded_rows


def _leaf_bytes(row: Sequence[int]) -> bytes:
    return b"".join(b128_to_bytes(value) for value in row)


def _leaf_hash(params: Parameters, index: int, row: Sequence[int]) -> bytes:
    if len(row) != params.data_columns:
        raise ValueError("Merkle leaf width mismatch")
    return _sha512(
        b"merkle/leaf",
        params.profile_id,
        index.to_bytes(4, "big"),
        params.data_columns.to_bytes(4, "big"),
        _leaf_bytes(row),
    )


def _node_hash(
    params: Parameters,
    level: int,
    parent_index: int,
    left: bytes,
    right: bytes,
) -> bytes:
    if len(left) != SHA512_BYTES or len(right) != SHA512_BYTES:
        raise ValueError("invalid Merkle child digest")
    return _sha512(
        b"merkle/node",
        params.profile_id,
        level.to_bytes(2, "big"),
        parent_index.to_bytes(4, "big"),
        left,
        right,
    )


def _merkle_levels(
    encoded_rows: Sequence[Sequence[int]], params: Parameters
) -> list[list[bytes]]:
    if len(encoded_rows) != params.codeword_rows:
        raise ValueError("Merkle tree row count mismatch")
    levels = [
        [_leaf_hash(params, index, row) for index, row in enumerate(encoded_rows)]
    ]
    level_index = 0
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [
                _node_hash(
                    params,
                    level_index,
                    index // 2,
                    current[index],
                    current[index + 1],
                )
                for index in range(0, len(current), 2)
            ]
        )
        level_index += 1
    return levels


def _query_set_digest(params: Parameters, queries: Sequence[int]) -> bytes:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("Merkle query indexes are not canonical")
    return _sha512(
        b"merkle/query-set",
        params.profile_id,
        b"".join(query.to_bytes(4, "big") for query in queries),
    )


def _merkle_padding(
    *,
    params: Parameters,
    root: bytes,
    query_digest: bytes,
    actual_count: int,
    position: int,
) -> bytes:
    return _sha512(
        b"merkle/padding",
        params.profile_id,
        root,
        query_digest,
        actual_count.to_bytes(4, "big"),
        position.to_bytes(4, "big"),
    )


def _actual_frontier_count(queries: Sequence[int], log_leaves: int) -> int:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("Merkle query indexes are not canonical")
    current = set(queries)
    count = 0
    for _ in range(log_leaves):
        count += sum(1 for index in current if (index ^ 1) not in current)
        current = {index >> 1 for index in current}
    return count


def _compact_multiproof(
    levels: Sequence[Sequence[bytes]],
    queries: Sequence[int],
    params: Parameters,
) -> tuple[bytes, ...]:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("Merkle query indexes are not canonical")
    current = set(queries)
    frontier: list[bytes] = []
    for level in levels[:-1]:
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                frontier.append(level[sibling])
        current = {index >> 1 for index in current}
    if len(frontier) > params.frontier_nodes:
        raise AssertionError("exact maximum Merkle frontier was violated")
    root = levels[-1][0]
    actual_count = len(frontier)
    query_digest = _query_set_digest(params, queries)
    for position in range(actual_count, params.frontier_nodes):
        frontier.append(
            _merkle_padding(
                params=params,
                root=root,
                query_digest=query_digest,
                actual_count=actual_count,
                position=position,
            )
        )
    return tuple(frontier)


def _verify_compact_multiproof(
    *,
    root: bytes,
    queries: Sequence[int],
    rows: Sequence[Sequence[int]],
    frontier: Sequence[bytes],
    params: Parameters,
) -> bool:
    if (
        len(root) != SHA512_BYTES
        or len(queries) != len(rows)
        or tuple(queries) != tuple(sorted(set(queries)))
        or any(len(row) != params.data_columns for row in rows)
        or len(frontier) != params.frontier_nodes
        or any(len(node) != SHA512_BYTES for node in frontier)
    ):
        return False
    current = {
        index: _leaf_hash(params, index, row)
        for index, row in zip(queries, rows)
    }
    cursor = 0
    for level_index in range(params.log_codeword_rows):
        next_level: dict[int, bytes] = {}
        processed: set[int] = set()
        for index in sorted(current):
            parent = index >> 1
            if parent in processed:
                continue
            sibling = index ^ 1
            if sibling in current:
                left = current[index & ~1]
                right = current[index | 1]
            else:
                if cursor >= len(frontier):
                    return False
                sibling_hash = frontier[cursor]
                cursor += 1
                if index & 1:
                    left, right = sibling_hash, current[index]
                else:
                    left, right = current[index], sibling_hash
            next_level[parent] = _node_hash(
                params, level_index, parent, left, right
            )
            processed.add(parent)
        current = next_level
    if current.get(0) != root:
        return False
    query_digest = _query_set_digest(params, queries)
    actual_count = cursor
    for position in range(cursor, len(frontier)):
        if frontier[position] != _merkle_padding(
            params=params,
            root=root,
            query_digest=query_digest,
            actual_count=actual_count,
            position=position,
        ):
            return False
    return True


@dataclass(frozen=True)
class Proof:
    statement_id: bytes
    root: bytes
    claimed_value: E384
    sumcheck: tuple[tuple[E384, E384], ...]
    terminal: tuple[E384, ...]
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]

    def serialize(self, params: Parameters) -> bytes:
        if len(self.statement_id) != SHA512_BYTES:
            raise ValueError("statement identifier length mismatch")
        if len(self.root) != SHA512_BYTES:
            raise ValueError("commitment root length mismatch")
        if not isinstance(self.claimed_value, E384):
            raise TypeError("claimed value must be E384")
        if len(self.sumcheck) != params.sumcheck_count:
            raise ValueError("sumcheck message count mismatch")
        if any(
            len(message) != 2 or not all(isinstance(value, E384) for value in message)
            for message in self.sumcheck
        ):
            raise ValueError("sumcheck message geometry mismatch")
        if len(self.terminal) != params.terminal_count or not all(
            isinstance(value, E384) for value in self.terminal
        ):
            raise ValueError("terminal geometry mismatch")
        if len(self.opened_rows) != params.query_count or any(
            len(row) != params.data_columns for row in self.opened_rows
        ):
            raise ValueError("opened-row geometry mismatch")
        if len(self.frontier) != params.frontier_nodes or any(
            len(node) != SHA512_BYTES for node in self.frontier
        ):
            raise ValueError("authentication frontier geometry mismatch")

        encoded = bytearray(params.header())
        encoded.extend(self.statement_id)
        encoded.extend(self.root)
        encoded.extend(self.claimed_value.to_bytes())
        for constant, quadratic in self.sumcheck:
            encoded.extend(constant.to_bytes())
            encoded.extend(quadratic.to_bytes())
        for value in self.terminal:
            encoded.extend(value.to_bytes())
        for row in self.opened_rows:
            encoded.extend(_leaf_bytes(row))
        for node in self.frontier:
            encoded.extend(node)
        if len(encoded) != params.proof_bytes:
            raise AssertionError("serializer and exact wire ledger disagree")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: Parameters) -> "Proof":
        if len(encoded) != params.proof_bytes:
            raise ValueError("proof length is not canonical")
        if encoded[:HEADER_BYTES] != params.header():
            raise ValueError("proof header/profile does not match expected parameters")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated proof")
            value = encoded[cursor:end]
            cursor = end
            return value

        statement_id = take(SHA512_BYTES)
        root = take(SHA512_BYTES)
        claimed_value = E384.from_bytes(take(E384_BYTES))
        sumcheck = tuple(
            (E384.from_bytes(take(E384_BYTES)), E384.from_bytes(take(E384_BYTES)))
            for _ in range(params.sumcheck_count)
        )
        terminal = tuple(
            E384.from_bytes(take(E384_BYTES)) for _ in range(params.terminal_count)
        )
        opened_rows = tuple(
            tuple(b128_from_bytes(take(B128_BYTES)) for _ in range(params.data_columns))
            for _ in range(params.query_count)
        )
        frontier = tuple(take(SHA512_BYTES) for _ in range(params.frontier_nodes))
        if cursor != len(encoded):
            raise ValueError("trailing proof bytes")
        proof = cls(
            statement_id,
            root,
            claimed_value,
            sumcheck,
            terminal,
            opened_rows,
            frontier,
        )
        if proof.serialize(params) != encoded:
            raise ValueError("proof is not its canonical re-encoding")
        return proof


def _new_transcript(
    params: Parameters,
    statement: OpeningStatement,
    root: bytes,
    claimed_value: E384,
) -> Transcript:
    statement.validate(params)
    transcript = Transcript()
    transcript.observe(b"profile", params.profile_id)
    transcript.observe(b"context", statement.public_context)
    # Source order: commit first, then receive the verifier's public functional,
    # then send the claimed value.
    transcript.observe(b"oracle/root", root)
    transcript.observe(b"statement/weights", statement.weights_digest(params))
    transcript.observe(b"statement/id", statement.identifier(params))
    transcript.observe(b"direct/claim", claimed_value.to_bytes())
    return transcript


def _observe_sumcheck(
    transcript: Transcript,
    round_index: int,
    message: tuple[E384, E384],
) -> None:
    transcript.observe(
        b"direct/sumcheck/" + round_index.to_bytes(2, "big"),
        message[0].to_bytes() + message[1].to_bytes(),
    )


def _sumcheck_coin(transcript: Transcript, round_index: int) -> E384:
    return transcript.challenge_e384(
        b"sumcheck/" + round_index.to_bytes(2, "big")
    )


def _observe_terminal(transcript: Transcript, terminal: Sequence[E384]) -> None:
    transcript.observe(
        b"direct/terminal", b"".join(value.to_bytes() for value in terminal)
    )


@dataclass(frozen=True)
class InteractiveOpeningResponse:
    """Authenticated response to the interactive verifier's row queries."""

    sampled_query_order: tuple[int, ...]
    canonical_query_order: tuple[int, ...]
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]


class OneLevelInteractiveProver:
    """Stateful Section-5 prover before Fiat--Shamir.

    The caller obtains the commitment and claim, requests exactly one direct
    sumcheck message at a time, supplies the corresponding public coin, then
    obtains the terminal and supplies the final distinct row-query set.  The
    state machine prevents a later coin from being supplied before the direct
    message on which it is meant to depend.
    """

    def __init__(
        self,
        source: Sequence[int],
        params: Parameters,
        statement: OpeningStatement,
        *,
        allocation_limit_bytes: int = MAX_DEFAULT_ORACLE_BYTES,
    ) -> None:
        statement.validate(params)
        values = _source_to_row_major_e384(source, params)
        basis = _weights_to_row_major(statement, params)
        if _inner_product(values, basis) != statement.claimed_value:
            raise ValueError("source does not satisfy the public opening claim")
        encoded_rows = _encode_source(
            source,
            params,
            allocation_limit_bytes=allocation_limit_bytes,
        )
        levels = _merkle_levels(encoded_rows, params)

        self.params = params
        self.statement = statement
        self.root = levels[-1][0]
        self._encoded_rows = encoded_rows
        self._levels = levels
        self._values = values
        self._basis = basis
        self._running_claim = statement.claimed_value
        self._round_index = 0
        self._pending_message: tuple[E384, E384] | None = None
        self._terminal: tuple[E384, ...] | None = None
        self._opened = False

    @property
    def claimed_value(self) -> E384:
        return self.statement.claimed_value

    @property
    def round_index(self) -> int:
        return self._round_index

    def next_sumcheck_message(self) -> tuple[E384, E384]:
        if self._terminal is not None or self._round_index >= self.params.fold_variables:
            raise ValueError("all interactive sumcheck rounds are complete")
        if self._pending_message is not None:
            raise ValueError("the pending sumcheck message needs a verifier coin")
        self._pending_message = _round_message(self._values, self._basis)
        return self._pending_message

    def receive_sumcheck_coin(self, coin: E384) -> None:
        if not isinstance(coin, E384):
            raise TypeError("the sumcheck verifier coin must be E384")
        if self._pending_message is None:
            raise ValueError("a verifier coin cannot precede its direct message")
        self._running_claim = _round_evaluate(
            self._pending_message, self._running_claim, coin
        )
        self._values = _fold(self._values, coin)
        self._basis = _fold(self._basis, coin)
        if self._running_claim != _inner_product(self._values, self._basis):
            raise AssertionError("honest interactive sumcheck invariant failed")
        self._pending_message = None
        self._round_index += 1

    def terminal_message(self) -> tuple[E384, ...]:
        if self._pending_message is not None:
            raise ValueError("the pending sumcheck message needs a verifier coin")
        if self._round_index != self.params.fold_variables:
            raise ValueError("interactive sumcheck rounds are incomplete")
        if self._terminal is None:
            self._terminal = tuple(self._values)
        return self._terminal

    def open_rows(self, sampled_queries: Sequence[int]) -> InteractiveOpeningResponse:
        if self._terminal is None:
            raise ValueError("row queries cannot precede the terminal message")
        if self._opened:
            raise ValueError("the fixed-format protocol has one row-opening phase")
        sampled = tuple(sampled_queries)
        if (
            len(sampled) != self.params.query_count
            or len(set(sampled)) != len(sampled)
            or any(not 0 <= query < self.params.codeword_rows for query in sampled)
        ):
            raise ValueError("interactive row queries must be distinct and in range")
        canonical = tuple(sorted(sampled))
        opened_rows = tuple(self._encoded_rows[index] for index in canonical)
        frontier = _compact_multiproof(self._levels, canonical, self.params)
        self._opened = True
        return InteractiveOpeningResponse(
            sampled, canonical, opened_rows, frontier
        )


def verify_interactive(
    *,
    params: Parameters,
    statement: OpeningStatement,
    root: bytes,
    sumcheck_messages: Sequence[tuple[E384, E384]],
    sumcheck_coins: Sequence[E384],
    terminal: Sequence[E384],
    sampled_queries: Sequence[int],
    opening: InteractiveOpeningResponse,
) -> bool:
    """Verify the underlying public-coin protocol at caller-supplied coins."""

    try:
        statement.validate(params)
        if len(root) != SHA512_BYTES:
            return False
        if (
            len(sumcheck_messages) != params.fold_variables
            or len(sumcheck_coins) != params.fold_variables
            or not all(isinstance(coin, E384) for coin in sumcheck_coins)
            or len(terminal) != params.terminal_count
            or not all(isinstance(value, E384) for value in terminal)
        ):
            return False
        sampled = tuple(sampled_queries)
        canonical = opening.canonical_query_order
        if (
            len(sampled) != params.query_count
            or len(set(sampled)) != len(sampled)
            or any(not 0 <= query < params.codeword_rows for query in sampled)
            or opening.sampled_query_order != sampled
            or canonical != tuple(sorted(sampled))
        ):
            return False

        running_claim = statement.claimed_value
        basis = _weights_to_row_major(statement, params)
        for message, coin in zip(sumcheck_messages, sumcheck_coins):
            if len(message) != 2 or not all(
                isinstance(value, E384) for value in message
            ):
                return False
            running_claim = _round_evaluate(message, running_claim, coin)
            basis = _fold(basis, coin)
        if running_claim != _inner_product(terminal, basis):
            return False
        if not _verify_compact_multiproof(
            root=root,
            queries=canonical,
            rows=opening.opened_rows,
            frontier=opening.frontier,
            params=params,
        ):
            return False
        for query, row in zip(canonical, opening.opened_rows):
            folded = [E384.embed(value) for value in row]
            for coin in sumcheck_coins:
                folded = _fold(folded, coin)
            if (
                len(folded) != 1
                or folded[0] != _rs_evaluate_e384(terminal, _domain_point(query))
            ):
                return False
        return True
    except (AssertionError, IndexError, TypeError, ValueError):
        return False


def prove(
    source: Sequence[int],
    params: Parameters,
    statement: OpeningStatement,
    *,
    allocation_limit_bytes: int = MAX_DEFAULT_ORACLE_BYTES,
) -> bytes:
    """Produce one exact authenticated opening proof.

    ``allocation_limit_bytes`` is mandatory authority for the encoded oracle;
    the default only permits tiny development instances.
    """

    interactive = OneLevelInteractiveProver(
        source,
        params,
        statement,
        allocation_limit_bytes=allocation_limit_bytes,
    )
    transcript = _new_transcript(
        params, statement, interactive.root, interactive.claimed_value
    )

    sumcheck: list[tuple[E384, E384]] = []
    for round_index in range(params.fold_variables):
        message = interactive.next_sumcheck_message()
        sumcheck.append(message)
        _observe_sumcheck(transcript, round_index, message)
        coin = _sumcheck_coin(transcript, round_index)
        interactive.receive_sumcheck_coin(coin)

    terminal = interactive.terminal_message()
    _observe_terminal(transcript, terminal)
    sampled_queries = transcript.distinct_indices(
        b"encoded-rows", params.query_count, params.codeword_rows
    )
    opening = interactive.open_rows(sampled_queries)
    proof = Proof(
        statement.identifier(params),
        interactive.root,
        statement.claimed_value,
        tuple(sumcheck),
        terminal,
        opening.opened_rows,
        opening.frontier,
    )
    return proof.serialize(params)


@dataclass(frozen=True)
class OracleCommitment:
    label: str
    field: str
    leaf_count: int
    leaf_width: int
    digest: bytes


@dataclass(frozen=True)
class DirectFieldMessage:
    label: str
    field: str
    values: tuple[E384, ...]
    polynomial_degree: int | None
    witness_dependent: bool
    independently_masked: bool


@dataclass(frozen=True)
class VerifierCoin:
    label: str
    field: str
    e384_values: tuple[E384, ...]
    index_values: tuple[int, ...]


@dataclass(frozen=True)
class OracleOpening:
    commitment_label: str
    index: int
    values: tuple[int, ...]


@dataclass(frozen=True)
class AcceptanceConstraint:
    label: str
    kind: str
    satisfied: bool


@dataclass(frozen=True)
class InteractiveMiopView:
    """Typed pre-Fiat--Shamir protocol surface reconstructed at fixed coins."""

    commitments: tuple[OracleCommitment, ...]
    direct_messages: tuple[DirectFieldMessage, ...]
    verifier_coins: tuple[VerifierCoin, ...]
    sampled_query_order: tuple[int, ...]
    canonical_query_order: tuple[int, ...]
    openings: tuple[OracleOpening, ...]
    algebraic_constraints: tuple[AcceptanceConstraint, ...]
    computational_checks: tuple[AcceptanceConstraint, ...]
    fixed_format_public_coin: bool
    accepted: bool


def _verify_detailed(
    encoded: bytes,
    params: Parameters,
    statement: OpeningStatement,
) -> tuple[bool, InteractiveMiopView | None]:
    try:
        statement.validate(params)
        proof = Proof.parse(encoded, params)
        parser_ok = True
        statement_ok = (
            proof.statement_id == statement.identifier(params)
            and proof.claimed_value == statement.claimed_value
        )
        if not statement_ok:
            return False, None

        transcript = _new_transcript(
            params, statement, proof.root, proof.claimed_value
        )
        running_claim = proof.claimed_value
        basis = _weights_to_row_major(statement, params)
        coins: list[E384] = []
        direct_messages: list[DirectFieldMessage] = [
            DirectFieldMessage(
                "claim",
                "E384",
                (proof.claimed_value,),
                1,
                False,
                False,
            )
        ]
        algebraic: list[AcceptanceConstraint] = []
        for round_index, message in enumerate(proof.sumcheck):
            direct_messages.append(
                DirectFieldMessage(
                    f"sumcheck/{round_index}",
                    "E384",
                    message,
                    2,
                    True,
                    False,
                )
            )
            # The compact two-coefficient grammar reconstructs the linear
            # coefficient so g(0)+g(1)=the prior claim identically.
            algebraic.append(
                AcceptanceConstraint(
                    f"sumcheck/{round_index}/boolean-sum",
                    "polynomial",
                    True,
                )
            )
            _observe_sumcheck(transcript, round_index, message)
            coin = _sumcheck_coin(transcript, round_index)
            coins.append(coin)
            running_claim = _round_evaluate(message, running_claim, coin)
            basis = _fold(basis, coin)

        terminal_ok = running_claim == _inner_product(proof.terminal, basis)
        algebraic.append(
            AcceptanceConstraint(
                "sumcheck/terminal-inner-product", "polynomial", terminal_ok
            )
        )
        direct_messages.append(
            DirectFieldMessage(
                "terminal",
                "E384",
                proof.terminal,
                1,
                True,
                False,
            )
        )
        _observe_terminal(transcript, proof.terminal)
        sampled_queries = transcript.distinct_indices(
            b"encoded-rows", params.query_count, params.codeword_rows
        )
        queries = tuple(sorted(sampled_queries))

        merkle_ok = _verify_compact_multiproof(
            root=proof.root,
            queries=queries,
            rows=proof.opened_rows,
            frontier=proof.frontier,
            params=params,
        )
        row_checks: list[bool] = []
        for query, row in zip(queries, proof.opened_rows):
            folded = [E384.embed(value) for value in row]
            for coin in coins:
                folded = _fold(folded, coin)
            row_ok = (
                len(folded) == 1
                and folded[0]
                == _rs_evaluate_e384(proof.terminal, _domain_point(query))
            )
            row_checks.append(row_ok)
            algebraic.append(
                AcceptanceConstraint(
                    f"opening/{query}/encoded-row", "polynomial", row_ok
                )
            )

        computational = (
            AcceptanceConstraint("parser/canonical", "parser", parser_ok),
            AcceptanceConstraint("statement/exact", "parser", statement_ok),
            AcceptanceConstraint("transcript/sha512", "hash", True),
            AcceptanceConstraint("merkle/sha512", "hash", merkle_ok),
        )
        accepted = terminal_ok and merkle_ok and all(row_checks)
        view = InteractiveMiopView(
            commitments=(
                OracleCommitment(
                    "encoded-matrix",
                    "B128",
                    params.codeword_rows,
                    params.data_columns,
                    proof.root,
                ),
            ),
            direct_messages=tuple(direct_messages),
            verifier_coins=(
                VerifierCoin(
                    "partial-sumcheck",
                    "E384",
                    tuple(coins),
                    (),
                ),
                VerifierCoin(
                    "distinct-encoded-rows",
                    "u32-without-replacement",
                    (),
                    sampled_queries,
                ),
            ),
            sampled_query_order=sampled_queries,
            canonical_query_order=queries,
            openings=tuple(
                OracleOpening("encoded-matrix", query, row)
                for query, row in zip(queries, proof.opened_rows)
            ),
            algebraic_constraints=tuple(algebraic),
            computational_checks=computational,
            fixed_format_public_coin=True,
            accepted=accepted,
        )
        return accepted, view
    except (AssertionError, IndexError, TypeError, ValueError, struct.error):
        return False, None


def verify(
    encoded: bytes,
    params: Parameters,
    statement: OpeningStatement,
) -> bool:
    return _verify_detailed(encoded, params, statement)[0]


def extract_interactive_view(
    encoded: bytes,
    params: Parameters,
    statement: OpeningStatement,
) -> InteractiveMiopView:
    accepted, view = _verify_detailed(encoded, params, statement)
    if not accepted or view is None:
        raise ValueError("cannot export an interactive view from a rejected proof")
    return view


@dataclass(frozen=True)
class SparseE384ObservationRow:
    label: str
    terms: tuple[tuple[int, E384], ...]

    def evaluate(self, source: Sequence[int]) -> E384:
        result = E384.zero()
        for source_index, coefficient in self.terms:
            if not 0 <= source_index < len(source):
                raise ValueError("observation row/source geometry mismatch")
            result = result + E384.embed(b128(source[source_index])) * coefficient
        return result


@dataclass(frozen=True)
class RsB128ObservationRow:
    """Exact lazy row for one B128 RS opening and one data column."""

    label: str
    column: int
    domain_point: int
    message_rows: int
    source_symbols: int

    def coefficient(self, source_index: int) -> int:
        if not 0 <= source_index < self.source_symbols:
            raise ValueError("source index outside observation row")
        row = source_index % self.message_rows
        column = source_index // self.message_rows
        if column != self.column:
            return 0
        result = 1
        for _ in range(row):
            result = b128_mul(result, self.domain_point)
        return result

    def evaluate(self, source: Sequence[int]) -> int:
        if len(source) != self.source_symbols:
            raise ValueError("observation row/source geometry mismatch")
        start = self.column * self.message_rows
        coefficients = source[start : start + self.message_rows]
        return _rs_evaluate_b128(coefficients, self.domain_point)


@dataclass(frozen=True)
class ObservationSurface:
    """Exact algebraic observation operator after fixed verifier coins."""

    e384_rows: tuple[SparseE384ObservationRow, ...]
    b128_rows: tuple[RsB128ObservationRow, ...]
    commitment_hash_is_separate: bool
    relation_witness_generator_supplied: bool
    wrapper_mask_generator_supplied: bool


LinearForm = dict[int, E384]


def _form_scaled(form: LinearForm, scalar: E384) -> LinearForm:
    if scalar == E384.zero():
        return {}
    return {
        index: coefficient * scalar
        for index, coefficient in form.items()
        if coefficient * scalar != E384.zero()
    }


def _form_add(left: LinearForm, right: LinearForm) -> LinearForm:
    result = dict(left)
    for index, coefficient in right.items():
        combined = result.get(index, E384.zero()) + coefficient
        if combined == E384.zero():
            result.pop(index, None)
        else:
            result[index] = combined
    return result


def _row_from_form(label: str, form: LinearForm) -> SparseE384ObservationRow:
    return SparseE384ObservationRow(label, tuple(sorted(form.items())))


def export_observation_rows(
    params: Parameters,
    statement: OpeningStatement,
    sumcheck_coins: Sequence[E384],
    canonical_queries: Sequence[int],
) -> ObservationSurface:
    """Export exact raw-observation rows for fixed interactive verifier coins.

    These are the ``O`` rows needed by a future complete-ZK rank check.  The
    relation-specific witness generator ``G_w`` and wrapper mask generator
    ``G_r`` are deliberately not invented here; callers must compose them and
    prove ``rank(O G_r) = rank([O G_r | O G_w])`` for every admitted branch.
    """

    statement.validate(params)
    if len(sumcheck_coins) != params.fold_variables or not all(
        isinstance(coin, E384) for coin in sumcheck_coins
    ):
        raise ValueError("sumcheck coin geometry mismatch")
    if (
        len(canonical_queries) != params.query_count
        or tuple(canonical_queries) != tuple(sorted(set(canonical_queries)))
        or any(not 0 <= query < params.codeword_rows for query in canonical_queries)
    ):
        raise ValueError("canonical query geometry mismatch")

    rows = params.message_rows
    columns = params.data_columns
    forms: list[LinearForm] = [
        {row + rows * column: E384.one()}
        for row in range(rows)
        for column in range(columns)
    ]
    basis = _weights_to_row_major(statement, params)
    e384_rows: list[SparseE384ObservationRow] = []

    for round_index, coin in enumerate(sumcheck_coins):
        constant: LinearForm = {}
        quadratic: LinearForm = {}
        for index in range(0, len(forms), 2):
            f0, f1 = forms[index], forms[index + 1]
            w0, w1 = basis[index], basis[index + 1]
            constant = _form_add(constant, _form_scaled(f0, w0))
            quadratic = _form_add(
                quadratic,
                _form_scaled(_form_add(f0, f1), w0 + w1),
            )
        e384_rows.append(
            _row_from_form(f"sumcheck/{round_index}/constant", constant)
        )
        e384_rows.append(
            _row_from_form(f"sumcheck/{round_index}/quadratic", quadratic)
        )

        one_plus = E384.one() + coin
        forms = [
            _form_add(
                _form_scaled(forms[index], one_plus),
                _form_scaled(forms[index + 1], coin),
            )
            for index in range(0, len(forms), 2)
        ]
        basis = _fold(basis, coin)

    if len(forms) != params.terminal_count:
        raise AssertionError("terminal observation geometry drift")
    for row_index, form in enumerate(forms):
        e384_rows.append(_row_from_form(f"terminal/{row_index}", form))

    b128_rows = tuple(
        RsB128ObservationRow(
            f"opening/{query}/column/{column}",
            column,
            _domain_point(query),
            params.message_rows,
            params.source_symbols,
        )
        for query in canonical_queries
        for column in range(params.data_columns)
    )
    return ObservationSurface(
        tuple(e384_rows),
        b128_rows,
        True,
        False,
        False,
    )


def complete_zk_contract(params: Parameters) -> dict[str, object]:
    """Return the immutable, fail-closed VEIL-style wrapper boundary."""

    return {
        "schema": "hegemon.ligerito-e384-core.complete-zk-interface.v1",
        "profile_id_sha512": params.profile_id.hex(),
        "interactive_fixed_format_public_coin_miop_exposed": True,
        "typed_direct_messages_exposed": True,
        "typed_oracle_commitment_exposed": True,
        "actual_distinct_query_indexes_exposed": True,
        "raw_observation_operator_O_exported": True,
        "one_declared_theorem_field_refinement": False,
        "at_most_one_evaluation_query_per_commitment_or_conversion": False,
        "acceptance_only_polynomial_constraints": False,
        "full_relation_witness_generator_Gw_supplied": False,
        "wrapper_mask_generator_Gr_supplied": False,
        "all_q_projections_full_rank": False,
        "three_independent_B128_random_columns": False,
        "nonzero_random_column_coefficient_proved": False,
        "joint_padded_and_masked_commitment": False,
        "independent_direct_field_masks": False,
        "fixed_randomness_whole_view_simulator": False,
        "abort_and_selective_failure_bound": False,
        "fiat_shamir_qrom_composition": False,
        "complete_zk": False,
        "strict_pq128": False,
        "frontier_eligible": False,
        "production_authorized": False,
        "required_rank_equation": "rank(O*Gr)=rank([O*Gr|O*Gw]) on every admitted branch",
        "required_random_padding_b128_per_data_column": params.query_count,
        "required_random_E384_column_coordinates": 3,
        "reason": (
            "the authenticated core exposes raw terminal and row values; no mixed-field "
            "refinement, qualifying zk-code, masks, simulator, or QROM theorem is supplied"
        ),
    }


def best_full_bucket_screen(
    *,
    log_relation_size: int = 16,
    source_security_bits: int = 264,
    max_encoded_oracle_bytes: int = 512 * 1024 * 1024,
) -> Parameters:
    """Source-only byte/resource screen; never allocates an encoded oracle."""

    candidates: list[Parameters] = []
    for fold_variables in range(1, log_relation_size):
        for log_inv_rate in range(1, 17):
            try:
                candidate = Parameters.for_source_security(
                    log_relation_size=log_relation_size,
                    fold_variables=fold_variables,
                    log_inv_rate=log_inv_rate,
                    source_security_bits=source_security_bits,
                )
            except ValueError:
                continue
            if candidate.encoded_oracle_bytes <= max_encoded_oracle_bytes:
                candidates.append(candidate)
    if not candidates:
        raise ValueError("no source Ligerito geometry fits the oracle cap")
    return min(candidates, key=lambda candidate: candidate.proof_bytes)


def toy_parameters() -> Parameters:
    return Parameters.for_source_security(
        log_relation_size=5,
        fold_variables=2,
        log_inv_rate=2,
        source_security_bits=4,
    )


def deterministic_toy_source(params: Parameters) -> tuple[int, ...]:
    return tuple(
        int.from_bytes(
            _sha512(b"toy/source", params.profile_id, index.to_bytes(4, "big"))[
                :B128_BYTES
            ],
            "little",
        )
        for index in range(params.source_symbols)
    )


def deterministic_toy_statement(
    source: Sequence[int], params: Parameters
) -> OpeningStatement:
    context = _sha512(b"toy/public-context", params.profile_id)
    weights = tuple(
        E384.from_bytes(
            _sha512(b"toy/weight", params.profile_id, index.to_bytes(4, "big"))[
                :E384_BYTES
            ]
        )
        for index in range(params.source_symbols)
    )
    source_values = [E384.embed(b128(value)) for value in source]
    claim = _inner_product(source_values, weights)
    return OpeningStatement(context, weights, claim)


def run_toy_check() -> dict[str, object]:
    """Tiny deterministic executable check; never called by import or report."""

    params = toy_parameters()
    source = deterministic_toy_source(params)
    statement = deterministic_toy_statement(source, params)
    encoded = prove(source, params, statement)
    if len(encoded) != params.proof_bytes:
        raise AssertionError("serialized bytes disagree with the exact ledger")
    proof = Proof.parse(encoded, params)
    if proof.serialize(params) != encoded:
        raise AssertionError("canonical roundtrip failed")
    if not verify(encoded, params, statement):
        raise AssertionError("honest one-level proof did not verify")
    view = extract_interactive_view(encoded, params, statement)
    surface = export_observation_rows(
        params,
        statement,
        view.verifier_coins[0].e384_values,
        view.canonical_query_order,
    )
    expected_e384 = [
        value
        for message in proof.sumcheck
        for value in message
    ] + list(proof.terminal)
    observed_e384 = [row.evaluate(source) for row in surface.e384_rows]
    if observed_e384 != expected_e384:
        raise AssertionError("exported E384 observation rows do not reproduce the proof")
    observed_b128 = [row.evaluate(source) for row in surface.b128_rows]
    expected_b128 = [value for row in proof.opened_rows for value in row]
    if observed_b128 != expected_b128:
        raise AssertionError("exported B128 observation rows do not reproduce the proof")
    return {
        "claim_ceiling": (
            "toy authenticated one-level core only; no full relation, complete ZK, "
            "QROM composition, or production authority"
        ),
        "verified": True,
        "proof_bytes": len(encoded),
        "proof_sha512": hashlib.sha512(encoded).hexdigest(),
        "profile_id_sha512": params.profile_id.hex(),
        "statement_id_sha512": statement.identifier(params).hex(),
        "wire_ledger": asdict(params.wire_ledger) | {"total": params.proof_bytes},
        "encoded_oracle_bytes": params.encoded_oracle_bytes,
        "source_soundness_bits_modeled": params.source_soundness_bits,
        "production_authorized": False,
    }


def report() -> dict[str, object]:
    best = best_full_bucket_screen()
    query_log2, field_log2, union_log2 = best.source_soundness_log2_terms
    veil_direct_floor = 96 * best.query_count + 192
    optimistic = best_full_bucket_screen(source_security_bits=128)
    optimistic_query, optimistic_field, optimistic_union = (
        optimistic.source_soundness_log2_terms
    )
    optimistic_veil_floor = 96 * optimistic.query_count + 192
    return {
        "schema": "hegemon.ligerito-e384-core.source-screen.v1",
        "claim_ceiling": (
            "source-complete authenticated opening core and source-only size screen; "
            "not a full transaction relation, complete-ZK proof, QROM certificate, or artifact"
        ),
        "protocol_source": {
            "name": "Ligerito Section 5 base case (ell=2)",
            "error_equation": 15,
            "decoder_regime": "Reed-Solomon unique decoding",
            "johnson_flock_extension_used": False,
            "tensorswitch_used": False,
            "tensorswitch_reason": "TensorSwitch Lemma 8.3 assumes M>=2 recursive iterations",
        },
        "n16_optimistic_source128_under_512mib": {
            "claim_boundary": (
                "source equation (15) only; not a composed Fiat-Shamir/QROM target"
            ),
            "log_relation_size": optimistic.log_relation_size,
            "fold_variables": optimistic.fold_variables,
            "log_inv_rate": optimistic.log_inv_rate,
            "query_count": optimistic.query_count,
            "source_security_target_bits": optimistic.source_security_bits,
            "equation15_query_log2_error": optimistic_query,
            "equation15_field_log2_error": optimistic_field,
            "equation15_union_log2_error": optimistic_union,
            "proof_bytes": optimistic.proof_bytes,
            "wire_ledger": asdict(optimistic.wire_ledger),
            "resource_ledger": asdict(optimistic.resource_ledger),
            "encoded_oracle_bytes": optimistic.encoded_oracle_bytes,
            "profile_id_sha512": optimistic.profile_id.hex(),
            "veil_source_structure_direct_floor_bytes": optimistic_veil_floor,
            "core_plus_direct_floor_only_bytes": (
                optimistic.proof_bytes + optimistic_veil_floor
            ),
            "complete_zk_estimate": False,
        },
        "n16_best_under_512mib": {
            "claim_boundary": (
                "264-bit source term inherited as a conservative screen; no QROM "
                "composition theorem establishes that this is sufficient or necessary"
            ),
            "log_relation_size": best.log_relation_size,
            "fold_variables": best.fold_variables,
            "log_inv_rate": best.log_inv_rate,
            "query_count": best.query_count,
            "source_security_target_bits": best.source_security_bits,
            "equation15_query_log2_error": query_log2,
            "equation15_field_log2_error": field_log2,
            "equation15_union_log2_error": union_log2,
            "proof_bytes": best.proof_bytes,
            "wire_ledger": asdict(best.wire_ledger),
            "resource_ledger": asdict(best.resource_ledger),
            "encoded_oracle_bytes": best.encoded_oracle_bytes,
            "profile_id_sha512": best.profile_id.hex(),
            "veil_source_structure_direct_floor_bytes": veil_direct_floor,
            "core_plus_direct_floor_only_bytes": best.proof_bytes + veil_direct_floor,
            "complete_zk_estimate": False,
        },
        "comparator": {
            "smallwood_active_like_report_bytes": SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES,
            "smallwood_report_production_qualified": False,
            "optimistic_source128_core_minus_smallwood_report_bytes": (
                optimistic.proof_bytes - SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES
            ),
            "optimistic_source128_core_percent_larger_than_smallwood_report": (
                100.0
                * (optimistic.proof_bytes - SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES)
                / SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES
            ),
            "optimistic_source128_core_over_historical_cap_bytes": (
                optimistic.proof_bytes - HISTORICAL_RAW_PROOF_CAP_BYTES
            ),
            "ligerito_core_minus_smallwood_report_bytes": (
                best.proof_bytes - SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES
            ),
            "ligerito_core_percent_larger_than_smallwood_report": (
                100.0
                * (best.proof_bytes - SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES)
                / SMALLWOOD_ACTIVE_LIKE_REPORT_BYTES
            ),
            "historical_raw_proof_cap_bytes": HISTORICAL_RAW_PROOF_CAP_BYTES,
            "ligerito_core_over_historical_cap_bytes": (
                best.proof_bytes - HISTORICAL_RAW_PROOF_CAP_BYTES
            ),
            "current_weak_m4_artifact_bytes": CURRENT_M4_COMPARATOR_BYTES,
            "weak_m4_artifact_has_same_relation_or_security": False,
            "ligerito_core_smaller_than_weak_m4_artifact": (
                best.proof_bytes < CURRENT_M4_COMPARATOR_BYTES
            ),
            "absolute_no_go_proved": False,
            "fixed_max_frontier_grammar_disadvantage_established": True,
            "reason": (
                "the source Ligerito opening core alone is already larger than the "
                "checked-in active-like SmallWood report, but neither route has a qualified "
                "new relation/complete-ZK artifact, so this is not an absolute final-size theorem"
            ),
        },
        "capabilities": complete_zk_contract(best),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the source-only parameter/resource screen (no oracle allocation)",
    )
    parser.add_argument(
        "--toy-check",
        action="store_true",
        help="run only the tiny deterministic proof/parser/mutation-free core check",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.report == args.toy_check:
        raise SystemExit("choose exactly one of --report or --toy-check")
    result = report() if args.report else run_toy_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
