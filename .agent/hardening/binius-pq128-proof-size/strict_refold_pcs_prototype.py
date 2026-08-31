#!/usr/bin/env python3
"""Disk-light executable core for the one-level mixed-field refold PCS.

The default command proves and verifies only a tiny deterministic instance.
Production geometry is available as a byte-only parameter object; this module
never allocates the 64 MiB Pay1x2 oracle unless a caller explicitly supplies a
production-size witness.

This is an executable algebra/commitment/wire prototype, not a complete-ZK or
strict-security artifact.  It implements:

* GF(2^128) source rows and a cubic GF(2^384) extension;
* interleaved Reed--Solomon rows committed by SHAKE256-512 Merkle trees;
* a characteristic-two quadratic evaluation sumcheck;
* post-commit Fiat--Shamir challenges and distinct column queries;
* canonical compact multiproofs padded to the exact worst-case frontier; and
* an exact, externally parameter-pinned serializer/parser.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import strict_refold_pcs_model as wire_model


B128_BITS = 128
B128_BYTES = 16
B128_MASK = (1 << B128_BITS) - 1
# x^128 + x^7 + x^2 + x + 1 (the GCM polynomial basis).
B128_REDUCTION = 0x87
E384_BYTES = 48
DIGEST_BYTES = 64
HEADER_BYTES = 64
MAGIC = b"HGRFPCS1"
VERSION = 2
HEADER_FORMAT = ">8sHH32s4B4H2I"
PUBLIC_CONTEXT_BYTES = 32
TOY_PUBLIC_CONTEXT = hashlib.shake_256(
    b"Hegemon strict refold PCS toy public context v1"
).digest(PUBLIC_CONTEXT_BYTES)


def b128(value: int) -> int:
    if not 0 <= value <= B128_MASK:
        raise ValueError("non-canonical GF(2^128) value")
    return value


def b128_mul(left: int, right: int) -> int:
    """Multiply in GF(2^128) in the fixed polynomial basis."""

    left = b128(left)
    right = b128(right)
    result = 0
    multiplicand = left
    multiplier = right
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
        raise ValueError("GF(2^128) elements are exactly 16 bytes")
    return int.from_bytes(encoded, "little")


@dataclass(frozen=True)
class E384:
    """GF((2^128)^3) with u^3 + u + 1 = 0."""

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
            raise ValueError("GF(2^384) elements are exactly 48 bytes")
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
        return E384(self.c0 ^ other.c0, self.c1 ^ other.c1, self.c2 ^ other.c2)

    def __sub__(self, other: "E384") -> "E384":
        # Characteristic two.
        return self + other

    def __mul__(self, other: "E384") -> "E384":
        a0, a1, a2 = self.c0, self.c1, self.c2
        b0, b1, b2 = other.c0, other.c1, other.c2
        d0 = b128_mul(a0, b0)
        d1 = b128_mul(a0, b1) ^ b128_mul(a1, b0)
        d2 = b128_mul(a0, b2) ^ b128_mul(a1, b1) ^ b128_mul(a2, b0)
        d3 = b128_mul(a1, b2) ^ b128_mul(a2, b1)
        d4 = b128_mul(a2, b2)
        # u^3 = u + 1 and u^4 = u^2 + u.
        return E384(d0 ^ d3, d1 ^ d3 ^ d4, d2 ^ d4)


def _hash(domain: bytes, *parts: bytes, length: int = DIGEST_BYTES) -> bytes:
    framed = bytearray(domain)
    for part in parts:
        framed.extend(len(part).to_bytes(8, "big"))
        framed.extend(part)
    return hashlib.shake_256(bytes(framed)).digest(length)


class Transcript:
    def __init__(self) -> None:
        self._state = _hash(b"HGRF-TRANSCRIPT-INIT-v1")

    def observe(self, label: bytes, value: bytes) -> None:
        self._state = _hash(b"HGRF-TRANSCRIPT-OBS-v1", self._state, label, value)

    def challenge_bytes(self, label: bytes, length: int) -> bytes:
        value = _hash(
            b"HGRF-TRANSCRIPT-CHALLENGE-v1",
            self._state,
            label,
            length.to_bytes(4, "big"),
            length=length,
        )
        self.observe(b"challenge/" + label, value)
        return value

    def challenge_e384(self, label: bytes) -> E384:
        return E384.from_bytes(self.challenge_bytes(label, E384_BYTES))

    def distinct_indices(self, label: bytes, count: int, upper: int) -> tuple[int, ...]:
        if not 0 <= count <= upper or not 0 < upper < (1 << 32):
            raise ValueError("invalid query geometry")
        selected: list[int] = []
        seen: set[int] = set()
        rejection_limit = (1 << 64) - ((1 << 64) % upper)
        counter = 0
        while len(selected) < count:
            block = _hash(
                b"HGRF-TRANSCRIPT-QUERY-v1",
                self._state,
                label,
                counter.to_bytes(8, "big"),
                length=8,
            )
            counter += 1
            candidate = int.from_bytes(block, "big")
            if candidate >= rejection_limit:
                continue
            index = candidate % upper
            if index not in seen:
                seen.add(index)
                selected.append(index)
        encoded = b"".join(index.to_bytes(4, "big") for index in selected)
        self.observe(b"queries/" + label, encoded)
        return tuple(selected)


@dataclass(frozen=True)
class Parameters:
    log_relation_size: int
    active_symbols: int
    fold_variables: int
    log_inv_rate: int
    query_count: int
    security_bits: int
    wide_count: int

    def __post_init__(self) -> None:
        if not 1 <= self.log_relation_size <= 31:
            raise ValueError("unsupported relation dimension")
        if not 0 < self.active_symbols <= (1 << self.log_relation_size):
            raise ValueError("active symbols must fit the committed bucket")
        if not 1 <= self.fold_variables <= self.log_relation_size:
            raise ValueError("invalid fold dimension")
        if not 1 <= self.log_inv_rate <= 31:
            raise ValueError("invalid inverse-rate logarithm")
        if not 1 <= self.query_count <= self.codeword_leaves:
            raise ValueError("invalid distinct-query count")
        if not 1 <= self.security_bits <= 65535:
            raise ValueError("invalid security target")
        counts = (self.query_count, self.wide_count, self.terminal_count, self.sumcheck_count)
        if any(not 0 <= count <= 65535 for count in counts):
            raise ValueError("wire count exceeds the canonical header")
        if self.frontier_nodes >= (1 << 32):
            raise ValueError("Merkle frontier exceeds the canonical header")

    @property
    def residual_variables(self) -> int:
        return self.log_relation_size - self.fold_variables

    @property
    def lanes(self) -> int:
        return 1 << self.fold_variables

    @property
    def message_columns(self) -> int:
        return 1 << self.residual_variables

    @property
    def codeword_leaves(self) -> int:
        return 1 << (self.residual_variables + self.log_inv_rate)

    @property
    def terminal_count(self) -> int:
        return self.message_columns

    @property
    def sumcheck_count(self) -> int:
        # The terminal consistency polynomial is reconstructed from the
        # authenticated terminal vector and observed at the same transcript
        # position. It is not prover advice and therefore is not serialized.
        return self.fold_variables

    @property
    def frontier_nodes(self) -> int:
        return wire_model.max_compact_merkle_frontier_nodes(
            self.residual_variables + self.log_inv_rate,
            self.query_count,
        )

    @property
    def profile_id(self) -> bytes:
        material = (
            b"Hegemon strict refold PCS v1|SHAKE256-512 framed-v1|"
            b"B128:x128+x7+x2+x+1:LE16|E384:Y3+Y+1:3xLE16|"
            b"layout:f[lane+2^k*column]:LSB-first-fold|"
            + f"n{self.log_relation_size}|active{self.active_symbols}|".encode()
            + f"k{self.fold_variables}|rate{1 << self.log_inv_rate}|".encode()
            + f"q{self.query_count}|eta1/256|M4-wide{self.wide_count}|".encode()
            + f"security{self.security_bits}".encode()
        )
        return hashlib.shake_256(material).digest(32)

    def header(self) -> bytes:
        encoded = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            0,  # non-ZK core
            self.profile_id,
            self.log_relation_size,
            self.fold_variables,
            self.log_inv_rate,
            B128_BYTES,
            self.query_count,
            self.wide_count,
            self.terminal_count,
            self.sumcheck_count,
            self.frontier_nodes,
            self.active_symbols,
        )
        if len(encoded) != HEADER_BYTES:
            raise AssertionError("canonical header size drift")
        return encoded

    @property
    def proof_bytes(self) -> int:
        return (
            HEADER_BYTES
            + self.wide_count * E384_BYTES
            + DIGEST_BYTES
            + self.sumcheck_count * 2 * E384_BYTES
            + self.terminal_count * E384_BYTES
            + self.query_count * self.lanes * B128_BYTES
            + self.frontier_nodes * DIGEST_BYTES
        )

    @property
    def encoded_oracle_bytes(self) -> int:
        return self.codeword_leaves * self.lanes * B128_BYTES


def toy_parameters() -> Parameters:
    log_inv_rate = 2
    target_bits = 8
    return Parameters(
        log_relation_size=8,
        active_symbols=211,
        fold_variables=3,
        log_inv_rate=log_inv_rate,
        query_count=wire_model.johnson_query_count(log_inv_rate, target_bits=target_bits),
        security_bits=target_bits,
        wide_count=3,
    )


def pay1x2_parameters() -> Parameters:
    """Production-size grammar only; the log-14 relation is Pay1x2, not full M4."""

    return Parameters(
        log_relation_size=14,
        active_symbols=wire_model.PAY1X2_MODELED_ACTIVE_SYMBOLS,
        fold_variables=5,
        log_inv_rate=8,
        query_count=wire_model.johnson_query_count(8),
        security_bits=wire_model.STRICT_CLASSICAL_BITS,
        wide_count=wire_model.M4_WIDE_RECEIVES,
    )


def _fold(values: Sequence[E384], challenge: E384) -> list[E384]:
    if len(values) == 0 or len(values) % 2:
        raise ValueError("fold input must have nonzero even length")
    return [
        values[index] + (values[index] + values[index + 1]) * challenge
        for index in range(0, len(values), 2)
    ]


def _inner_product(left: Sequence[E384], right: Sequence[E384]) -> E384:
    if len(left) != len(right):
        raise ValueError("inner-product length mismatch")
    result = E384.zero()
    for a, b in zip(left, right):
        result = result + a * b
    return result


def _eq_basis(point: Sequence[E384]) -> list[E384]:
    basis = [E384.one()]
    one = E384.one()
    for coordinate in point:
        old_length = len(basis)
        extended = [E384.zero()] * (2 * old_length)
        for index, value in enumerate(basis):
            extended[index] = value * (one + coordinate)
            extended[index + old_length] = value * coordinate
        basis = extended
    return basis


def _mle_evaluate(values: Sequence[E384], point: Sequence[E384]) -> E384:
    if len(values) != 1 << len(point):
        raise ValueError("MLE geometry mismatch")
    folded = list(values)
    for coordinate in point:
        folded = _fold(folded, coordinate)
    if len(folded) != 1:
        raise AssertionError("MLE fold did not terminate")
    return folded[0]


def _round_message(values: Sequence[E384], basis: Sequence[E384]) -> tuple[E384, E384]:
    if len(values) != len(basis) or len(values) == 0 or len(values) % 2:
        raise ValueError("sumcheck round geometry mismatch")
    constant = E384.zero()
    quadratic = E384.zero()
    for index in range(0, len(values), 2):
        f0, f1 = values[index], values[index + 1]
        b0, b1 = basis[index], basis[index + 1]
        constant = constant + f0 * b0
        quadratic = quadratic + (f0 + f1) * (b0 + b1)
    return constant, quadratic


def _round_evaluate(
    message: tuple[E384, E384], current_claim: E384, challenge: E384
) -> E384:
    constant, quadratic = message
    linear = current_claim + quadratic
    return constant + challenge * linear + (challenge * challenge) * quadratic


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
        raise ValueError("codeword domain exhausted")
    return index + 1


def _encode_source(
    source: Sequence[int],
    params: Parameters,
    *,
    enforce_zero_padding: bool = True,
) -> list[tuple[int, ...]]:
    expected = 1 << params.log_relation_size
    if len(source) != expected:
        raise ValueError("source length does not match relation bucket")
    if enforce_zero_padding and any(
        value != 0 for value in source[params.active_symbols :]
    ):
        raise ValueError("inactive relation symbols must be canonical zero padding")
    rows = [
        [b128(source[lane + params.lanes * column]) for column in range(params.message_columns)]
        for lane in range(params.lanes)
    ]
    columns: list[tuple[int, ...]] = []
    for column_index in range(params.codeword_leaves):
        point = _domain_point(column_index)
        columns.append(tuple(_rs_evaluate_b128(row, point) for row in rows))
    return columns


def _leaf_bytes(row: Sequence[int]) -> bytes:
    return b"".join(b128_to_bytes(value) for value in row)


def _leaf_hash(index: int, row: Sequence[int]) -> bytes:
    return _hash(b"HGRF-MERKLE-LEAF-v1", index.to_bytes(4, "big"), _leaf_bytes(row))


def _node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != DIGEST_BYTES or len(right) != DIGEST_BYTES:
        raise ValueError("invalid Merkle child digest")
    return _hash(b"HGRF-MERKLE-NODE-v1", left, right)


def _merkle_levels(columns: Sequence[Sequence[int]]) -> list[list[bytes]]:
    if len(columns) == 0 or len(columns) & (len(columns) - 1):
        raise ValueError("Merkle leaves must be a nonzero power of two")
    levels = [[_leaf_hash(index, row) for index, row in enumerate(columns)]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [_node_hash(current[index], current[index + 1]) for index in range(0, len(current), 2)]
        )
    return levels


def _query_set_digest(params: Parameters, queries: Sequence[int]) -> bytes:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("Merkle queries must be distinct and canonically sorted")
    encoded = b"".join(query.to_bytes(4, "big") for query in queries)
    return _hash(b"HGRF-MERKLE-QUERIES-v1", params.profile_id, encoded)


def _merkle_padding(
    *,
    params: Parameters,
    root: bytes,
    query_digest: bytes,
    actual_count: int,
    position: int,
) -> bytes:
    return _hash(
        b"HGRF-MERKLE-PADDING-v2",
        params.profile_id,
        root,
        query_digest,
        actual_count.to_bytes(4, "big"),
        position.to_bytes(4, "big"),
    )


def _compact_multiproof(
    levels: Sequence[Sequence[bytes]], queries: Sequence[int], params: Parameters
) -> tuple[bytes, ...]:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("Merkle queries must be distinct and canonically sorted")
    current = set(queries)
    frontier: list[bytes] = []
    for level in levels[:-1]:
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                frontier.append(level[sibling])
        current = {index >> 1 for index in current}
    if len(frontier) > params.frontier_nodes:
        raise AssertionError("exact frontier maximum was violated")
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
        len(queries) != len(rows)
        or tuple(queries) != tuple(sorted(set(queries)))
        or len(frontier) != params.frontier_nodes
    ):
        return False
    current = {index: _leaf_hash(index, row) for index, row in zip(queries, rows)}
    cursor = 0
    for _ in range(params.residual_variables + params.log_inv_rate):
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
            next_level[parent] = _node_hash(left, right)
            processed.add(parent)
        current = next_level
    if current.get(0) != root:
        return False
    actual_count = cursor
    query_digest = _query_set_digest(params, queries)
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
    wide: tuple[E384, ...]
    root: bytes
    sumcheck: tuple[tuple[E384, E384], ...]
    terminal: tuple[E384, ...]
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]

    def serialize(self, params: Parameters) -> bytes:
        if len(self.wide) != params.wide_count:
            raise ValueError("wide-message count mismatch")
        if len(self.root) != DIGEST_BYTES:
            raise ValueError("root length mismatch")
        if len(self.sumcheck) != params.sumcheck_count:
            raise ValueError("sumcheck-message count mismatch")
        if len(self.terminal) != params.terminal_count:
            raise ValueError("terminal count mismatch")
        if len(self.opened_rows) != params.query_count or any(
            len(row) != params.lanes for row in self.opened_rows
        ):
            raise ValueError("opened-row geometry mismatch")
        if len(self.frontier) != params.frontier_nodes or any(
            len(node) != DIGEST_BYTES for node in self.frontier
        ):
            raise ValueError("frontier geometry mismatch")
        # Wire order matches transcript order: profile/header, root, then the
        # wide evaluation claims.  The old prototype serialized wide values
        # first and parsed ahead to observe the later root.
        encoded = bytearray(params.header())
        encoded.extend(self.root)
        for value in self.wide:
            encoded.extend(value.to_bytes())
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
            raise AssertionError("serializer disagrees with exact byte formula")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: Parameters) -> "Proof":
        if len(encoded) != params.proof_bytes:
            raise ValueError("proof length is not canonical (including trailing bytes)")
        if encoded[:HEADER_BYTES] != params.header():
            raise ValueError("proof header/profile is not the externally expected profile")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated proof")
            value = encoded[cursor:end]
            cursor = end
            return value

        root = take(DIGEST_BYTES)
        wide = tuple(E384.from_bytes(take(E384_BYTES)) for _ in range(params.wide_count))
        sumcheck = tuple(
            (E384.from_bytes(take(E384_BYTES)), E384.from_bytes(take(E384_BYTES)))
            for _ in range(params.sumcheck_count)
        )
        terminal = tuple(
            E384.from_bytes(take(E384_BYTES)) for _ in range(params.terminal_count)
        )
        opened_rows = tuple(
            tuple(b128_from_bytes(take(B128_BYTES)) for _ in range(params.lanes))
            for _ in range(params.query_count)
        )
        frontier = tuple(take(DIGEST_BYTES) for _ in range(params.frontier_nodes))
        if cursor != len(encoded):
            raise ValueError("trailing proof bytes")
        return cls(wide, root, sumcheck, terminal, opened_rows, frontier)


def _new_transcript(params: Parameters, public_context: bytes, root: bytes) -> Transcript:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public relation context must be exactly 32 bytes")
    transcript = Transcript()
    transcript.observe(b"profile", params.profile_id)
    transcript.observe(b"public-context", public_context)
    transcript.observe(b"root", root)
    return transcript


def _supplemental_wide(root: bytes, target: E384, index: int) -> E384:
    return E384.from_bytes(
        _hash(
            b"HGRF-TOY-WIDE-v1",
            root,
            target.to_bytes(),
            index.to_bytes(4, "big"),
            length=E384_BYTES,
        )
    )


def _observe_wide(transcript: Transcript, wide: Sequence[E384]) -> None:
    transcript.observe(b"wide", b"".join(value.to_bytes() for value in wide))


def _padding_augmented_basis(
    transcript: Transcript,
    evaluation_point: Sequence[E384],
    params: Parameters,
) -> list[E384]:
    """Bind the canonical-zero inactive tail after the evaluation claim.

    The evaluation target is observed before these challenges.  The verifier
    then adds a random multilinear functional of the inactive coefficients to
    the same sumcheck basis while retaining the public padding claim zero.
    Thus a nonzero inactive tail must make a post-claim random polynomial
    evaluation vanish.  This is a concrete check, but its ROM/QROM composition
    is deliberately not claimed by this prototype.
    """

    padding_point = tuple(
        transcript.challenge_e384(b"padding/" + index.to_bytes(2, "big"))
        for index in range(params.log_relation_size)
    )
    mix = transcript.challenge_e384(b"padding/mix")
    basis = _eq_basis(evaluation_point)
    padding_basis = _eq_basis(padding_point)
    for index in range(params.active_symbols, 1 << params.log_relation_size):
        basis[index] = basis[index] + mix * padding_basis[index]
    return basis


def _observe_sumcheck(
    transcript: Transcript, round_index: int, message: tuple[E384, E384]
) -> None:
    transcript.observe(
        b"sumcheck/" + round_index.to_bytes(2, "big"),
        message[0].to_bytes() + message[1].to_bytes(),
    )


def prove(source: Sequence[int], params: Parameters, public_context: bytes) -> bytes:
    columns = _encode_source(source, params)
    levels = _merkle_levels(columns)
    root = levels[-1][0]
    transcript = _new_transcript(params, public_context, root)
    evaluation_point = tuple(
        transcript.challenge_e384(b"evaluation/" + index.to_bytes(2, "big"))
        for index in range(params.log_relation_size)
    )

    values = [E384.embed(b128(value)) for value in source]
    target = _mle_evaluate(values, evaluation_point)
    wide = (target,) + tuple(
        _supplemental_wide(root, target, index) for index in range(1, params.wide_count)
    )
    _observe_wide(transcript, wide)

    # The target is transcript-bound before the random zero-padding
    # functional, preventing the prover from folding a nonzero tail into the
    # claimed evaluation value after seeing the padding challenge.
    basis = _padding_augmented_basis(transcript, evaluation_point, params)
    claim = target
    sumcheck: list[tuple[E384, E384]] = []
    lane_challenges: list[E384] = []
    for round_index in range(params.fold_variables):
        message = _round_message(values, basis)
        sumcheck.append(message)
        _observe_sumcheck(transcript, round_index, message)
        challenge = transcript.challenge_e384(
            b"sumcheck/" + round_index.to_bytes(2, "big")
        )
        lane_challenges.append(challenge)
        claim = _round_evaluate(message, claim, challenge)
        values = _fold(values, challenge)
        basis = _fold(basis, challenge)
        if claim != _inner_product(values, basis):
            raise AssertionError("honest sumcheck invariant failed")

    terminal = tuple(values)
    terminal_message = _round_message(terminal, basis)
    _observe_sumcheck(transcript, params.fold_variables, terminal_message)
    transcript.observe(b"terminal", b"".join(value.to_bytes() for value in terminal))
    sampled_queries = transcript.distinct_indices(
        b"columns", params.query_count, params.codeword_leaves
    )
    queries = tuple(sorted(sampled_queries))
    opened_rows = tuple(columns[index] for index in queries)
    frontier = _compact_multiproof(levels, queries, params)
    proof = Proof(wide, root, tuple(sumcheck), terminal, opened_rows, frontier)
    return proof.serialize(params)


def verify(encoded: bytes, params: Parameters, public_context: bytes) -> bool:
    try:
        proof = Proof.parse(encoded, params)
        transcript = _new_transcript(params, public_context, proof.root)
        evaluation_point = tuple(
            transcript.challenge_e384(b"evaluation/" + index.to_bytes(2, "big"))
            for index in range(params.log_relation_size)
        )
        if not proof.wide:
            return False
        target = proof.wide[0]
        expected_wide = (target,) + tuple(
            _supplemental_wide(proof.root, target, index)
            for index in range(1, params.wide_count)
        )
        if proof.wide != expected_wide:
            return False
        _observe_wide(transcript, proof.wide)

        basis = _padding_augmented_basis(transcript, evaluation_point, params)
        claim = target
        lane_challenges: list[E384] = []
        for round_index in range(params.fold_variables):
            message = proof.sumcheck[round_index]
            _observe_sumcheck(transcript, round_index, message)
            challenge = transcript.challenge_e384(
                b"sumcheck/" + round_index.to_bytes(2, "big")
            )
            lane_challenges.append(challenge)
            claim = _round_evaluate(message, claim, challenge)
            basis = _fold(basis, challenge)

        if claim != _inner_product(proof.terminal, basis):
            return False
        terminal_message = _round_message(proof.terminal, basis)
        _observe_sumcheck(transcript, params.fold_variables, terminal_message)
        transcript.observe(
            b"terminal", b"".join(value.to_bytes() for value in proof.terminal)
        )
        sampled_queries = transcript.distinct_indices(
            b"columns", params.query_count, params.codeword_leaves
        )
        queries = tuple(sorted(sampled_queries))
        if not _verify_compact_multiproof(
            root=proof.root,
            queries=queries,
            rows=proof.opened_rows,
            frontier=proof.frontier,
            params=params,
        ):
            return False

        for query, row in zip(queries, proof.opened_rows):
            folded_row = [E384.embed(value) for value in row]
            for challenge in lane_challenges:
                folded_row = _fold(folded_row, challenge)
            if len(folded_row) != 1:
                return False
            expected = _rs_evaluate_e384(proof.terminal, _domain_point(query))
            if folded_row[0] != expected:
                return False
        return True
    except (AssertionError, ValueError, IndexError, struct.error):
        return False


def deterministic_toy_source(params: Parameters) -> tuple[int, ...]:
    values = []
    for index in range(1 << params.log_relation_size):
        if index >= params.active_symbols:
            values.append(0)
        else:
            encoded = _hash(
                b"HGRF-TOY-SOURCE-v1", index.to_bytes(4, "big"), length=B128_BYTES
            )
            values.append(int.from_bytes(encoded, "little"))
    return tuple(values)


def run_toy_check() -> dict[str, object]:
    params = toy_parameters()
    encoded = prove(deterministic_toy_source(params), params, TOY_PUBLIC_CONTEXT)
    parsed = Proof.parse(encoded, params)
    if parsed.serialize(params) != encoded:
        raise AssertionError("parse/serialize roundtrip failed")
    if not verify(encoded, params, TOY_PUBLIC_CONTEXT):
        raise AssertionError("honest toy proof did not verify")
    wrong_context = bytearray(TOY_PUBLIC_CONTEXT)
    wrong_context[0] ^= 1
    if verify(encoded, params, bytes(wrong_context)):
        raise AssertionError("proof replayed under a different public relation context")
    if len(encoded) != params.proof_bytes:
        raise AssertionError("actual proof length disagrees with byte formula")
    production = pay1x2_parameters()
    if production.proof_bytes != wire_model.johnson_ligerito_core_candidate().proof_bytes:
        raise AssertionError("production grammar disagrees with byte model")
    return {
        "claim_ceiling": (
            "toy-scale executable non-ZK PCS core; not a strict proof artifact or full M4"
        ),
        "toy": {
            "verified": True,
            "proof_bytes_formula": params.proof_bytes,
            "proof_bytes_serialized": len(encoded),
            "encoded_oracle_bytes": params.encoded_oracle_bytes,
            "frontier_nodes_padded": params.frontier_nodes,
            "public_context_bound": True,
            "inactive_zero_padding_transcript_bound": True,
            "inactive_zero_padding_formally_proved": False,
            "shake256_512": hashlib.shake_256(encoded).hexdigest(64),
        },
        "pay1x2_size_only": {
            "log_relation_size": production.log_relation_size,
            "active_symbols": production.active_symbols,
            "proof_bytes_formula": production.proof_bytes,
            "encoded_oracle_bytes": production.encoded_oracle_bytes,
            "allocated_or_proved": False,
            "relation_stats_frozen": False,
            "complete_zero_knowledge": False,
            "inactive_zero_padding_transcript_bound": True,
            "inactive_zero_padding_formally_proved": False,
            "strict_admitted": False,
        },
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--toy-check",
        action="store_true",
        help="generate and verify the tiny deterministic instance (never the 64 MiB oracle)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.toy_check:
        raise SystemExit("refusing implicit work: pass --toy-check for the disk-light instance")
    print(json.dumps(run_toy_check(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
