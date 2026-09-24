#!/usr/bin/env python3
"""Executable small-n PCS/one-round-FRI seam for random high coefficients.

This is deliberately an *exhaustive* toy verifier.  It commits a B128
Reed--Solomon codeword on a nonzero affine coset, derives two independent
E256 coefficient-fold challenges from the shared root, commits each folded
E256 table as B128 coordinate lanes, and exact-decodes all three salted
Merkle openings.  In exhaustive mode the verifier interpolates every table,
checks the base degree, checks both folds coefficient by coefficient, and
checks both E256 terminal functionals.

The full reveal makes the small-n low-degree check honest but non-succinct.
The production n15 model prices the same serializer topology with query-only
openings.  That query-only form is *not* a proved FRI and every production,
ZK, PQ, QROM, formal, and frontier flag remains false.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import secrets
import struct
from dataclasses import asdict, dataclass
from typing import Sequence


B128_BITS = 128
B128_BYTES = 16
B128_REDUCTION = 0x87
B128_MASK = (1 << B128_BITS) - 1
E256_BYTES = 32
# Strict proof commitments and Fiat--Shamir digests use 64-byte SHAKE256
# output.  The precursor's 56-byte width is retained only in report metadata
# as a rejected non-strict screen.
PROOF_DIGEST_BYTES = 64
LEGACY_NON_STRICT_DIGEST_BYTES = 56
SALT_BYTES = 32
THEOREM_SCOPED_SALT_BYTES = 148  # Direct-BCS diagnostic at 2^18 leaves.
LEAF_GROUP_SYMBOLS = 4
AFFINE_DOMAIN_SHIFT = 1 << 127

MAGIC = b"HGRPFRI1"
VERSION = 1
FLAG_EXHAUSTIVE_LOW_DEGREE = 1
HEADER_STRUCT = struct.Struct("<8sBBBBIIIIIIIII")
HEADER_BYTES = HEADER_STRUCT.size  # 48
QUERY_DIGEST_BYTES = PROOF_DIGEST_BYTES
BRANCHES = 2
CLAIMS_PER_BRANCH = 2
ROOT_COUNT = 1 + BRANCHES
FIXED_WIRE_BYTES = (
    HEADER_BYTES
    + ROOT_COUNT * PROOF_DIGEST_BYTES
    + QUERY_DIGEST_BYTES
    + BRANCHES * CLAIMS_PER_BRANCH * E256_BYTES
)
OPENED_LEAF_BYTES = LEAF_GROUP_SYMBOLS * B128_BYTES + SALT_BYTES
MAX_TOY_MESSAGE_LOG = 8
MAX_TOY_RATE_LOG = 5

PRODUCTION_MESSAGE_LOG = 15
SOURCE_STATIC_ACTIVE_SYMBOLS_MIN = 23_594
SOURCE_STATIC_ACTIVE_SYMBOLS_MAX = 32_668
SOURCE_STATIC_RANDOM_TAIL_MIN = 100
SOURCE_STATIC_RANDOM_TAIL_MAX = 9_174
LEGACY_SCREEN_CONDITIONAL_BYTES = 63_320
LEGACY_SCREEN_DOUBLE_FULL_BYTES = 116_952
STRICT_PRECURSOR_CONDITIONAL_BYTES = 69_632
STRICT_PRECURSOR_DOUBLE_FULL_BYTES = 128_512
RAW_PROOF_CAP_BYTES = 124_068


class ProofError(ValueError):
    """Canonical proof or verification failure."""


def b128(value: int) -> int:
    if not 0 <= value <= B128_MASK:
        raise ValueError("non-canonical B128 element")
    return value


def b128_mul(left: int, right: int) -> int:
    left = b128(left)
    right = b128(right)
    product = 0
    while right:
        if right & 1:
            product ^= left
        right >>= 1
        left <<= 1
    modulus = (1 << 128) | B128_REDUCTION
    while product.bit_length() > 128:
        product ^= modulus << (product.bit_length() - 129)
    return product


def b128_pow(value: int, exponent: int) -> int:
    if exponent < 0:
        raise ValueError("negative exponent")
    result = 1
    value = b128(value)
    while exponent:
        if exponent & 1:
            result = b128_mul(result, value)
        value = b128_mul(value, value)
        exponent >>= 1
    return result


@functools.lru_cache(maxsize=4096)
def b128_inv(value: int) -> int:
    value = b128(value)
    if value == 0:
        raise ZeroDivisionError("zero has no inverse")
    return b128_pow(value, (1 << 128) - 2)


E256 = tuple[int, int]
E256_ZERO: E256 = (0, 0)
E256_ONE: E256 = (1, 0)


def e256(value: Sequence[int]) -> E256:
    if len(value) != 2:
        raise ValueError("E256 needs two B128 coefficients")
    return (b128(value[0]), b128(value[1]))


def e256_add(left: E256, right: E256) -> E256:
    return (left[0] ^ right[0], left[1] ^ right[1])


def e256_mul(left: E256, right: E256) -> E256:
    """Pinned GhashSq256b multiplication, Y^2 = X*Y + X."""

    a, b = e256(left)
    c, d = e256(right)
    bd_x = b128_mul(b128_mul(b, d), 2)
    return (
        b128_mul(a, c) ^ bd_x,
        b128_mul(a, d) ^ b128_mul(b, c) ^ bd_x,
    )


def e256_pow(value: E256, exponent: int) -> E256:
    if exponent < 0:
        raise ValueError("negative exponent")
    result = E256_ONE
    value = e256(value)
    while exponent:
        if exponent & 1:
            result = e256_mul(result, value)
        value = e256_mul(value, value)
        exponent >>= 1
    return result


def e256_to_bytes(value: E256) -> bytes:
    low, high = e256(value)
    return low.to_bytes(16, "little") + high.to_bytes(16, "little")


def e256_from_bytes(value: bytes) -> E256:
    if len(value) != E256_BYTES:
        raise ProofError("non-canonical E256 byte length")
    return (
        int.from_bytes(value[:16], "little"),
        int.from_bytes(value[16:], "little"),
    )


def _frame(domain: bytes, *parts: bytes) -> bytes:
    encoded = bytearray(domain)
    for part in parts:
        encoded.extend(len(part).to_bytes(8, "big"))
        encoded.extend(part)
    return bytes(encoded)


def affine_domain(count: int, *, shift: int = AFFINE_DOMAIN_SHIFT) -> tuple[int, ...]:
    if count <= 0 or count & (count - 1):
        raise ValueError("domain size must be a positive power of two")
    if count > (1 << 126):
        raise ValueError("affine domain is too large")
    shift = b128(shift)
    points = tuple(shift ^ index for index in range(count))
    if 0 in points:
        raise ValueError("zero-containing evaluation domain is forbidden")
    if len(set(points)) != count:
        raise ValueError("evaluation domain points are not distinct")
    return points


def evaluate_b128(coefficients: Sequence[int], point: int) -> int:
    point = b128(point)
    result = 0
    for coefficient in reversed(coefficients):
        result = b128_mul(result, point) ^ b128(coefficient)
    return result


def evaluate_e256(coefficients: Sequence[E256], point: E256) -> E256:
    point = e256(point)
    result = E256_ZERO
    for coefficient in reversed(coefficients):
        result = e256_add(e256_mul(result, point), e256(coefficient))
    return result


def encode(
    active_coefficients: Sequence[int],
    random_padding: Sequence[int],
    rate_log: int,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    coefficients = tuple(map(b128, active_coefficients)) + tuple(map(b128, random_padding))
    if len(coefficients) < 2 or len(coefficients) & (len(coefficients) - 1):
        raise ValueError("message coefficient count must be a power of two >= 2")
    if not 1 <= rate_log <= MAX_TOY_RATE_LOG:
        raise ValueError("toy rate log is out of range")
    domain = affine_domain(len(coefficients) << rate_log)
    return coefficients, tuple(evaluate_b128(coefficients, point) for point in domain)


def interpolate_b128(points: Sequence[int], values: Sequence[int]) -> tuple[int, ...]:
    """Exact Newton interpolation in the pinned B128 field."""

    if not points or len(points) != len(values) or len(set(points)) != len(points):
        raise ValueError("interpolation requires equal nonempty distinct inputs")
    xs = tuple(map(b128, points))
    divided = list(map(b128, values))
    count = len(xs)
    for order in range(1, count):
        for index in range(count - 1, order - 1, -1):
            numerator = divided[index] ^ divided[index - 1]
            denominator = xs[index] ^ xs[index - order]
            divided[index] = b128_mul(numerator, b128_inv(denominator))

    result = [0] * count
    basis = [1]
    for index, coefficient in enumerate(divided):
        for degree, basis_coefficient in enumerate(basis):
            result[degree] ^= b128_mul(coefficient, basis_coefficient)
        if index + 1 != count:
            root = xs[index]
            next_basis = [0] * (len(basis) + 1)
            for degree, basis_coefficient in enumerate(basis):
                next_basis[degree] ^= b128_mul(basis_coefficient, root)
                next_basis[degree + 1] ^= basis_coefficient
            basis = next_basis
    return tuple(result)


def fold_coefficients(coefficients: Sequence[int], beta: E256) -> tuple[E256, ...]:
    if len(coefficients) < 2 or len(coefficients) & 1:
        raise ValueError("fold needs a positive even coefficient count")
    beta = e256(beta)
    return tuple(
        e256_add((b128(coefficients[index]), 0), e256_mul(beta, (b128(coefficients[index + 1]), 0)))
        for index in range(0, len(coefficients), 2)
    )


def encode_folded(coefficients: Sequence[E256], rate_log: int) -> tuple[E256, ...]:
    domain = affine_domain(len(coefficients) << rate_log)
    return tuple(evaluate_e256(coefficients, (point, 0)) for point in domain)


def salted_leaf_hash(index: int, symbols: Sequence[int], salt: bytes) -> bytes:
    if not 0 <= index < (1 << 64):
        raise ValueError("leaf index does not fit u64")
    if len(symbols) != LEAF_GROUP_SYMBOLS:
        raise ValueError("leaf must contain exactly four B128 symbols")
    if len(salt) != SALT_BYTES:
        raise ValueError("leaf salt must be exactly 32 bytes")
    payload = b"".join(b128(symbol).to_bytes(16, "little") for symbol in symbols)
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-LEAF-v1\0",
            index.to_bytes(8, "big"),
            salt,
            payload,
        )
    ).digest(PROOF_DIGEST_BYTES)


def merkle_node_hash(level: int, index: int, left: bytes, right: bytes) -> bytes:
    if not 0 <= level < (1 << 16) or not 0 <= index < (1 << 64):
        raise ValueError("Merkle position out of range")
    if len(left) != PROOF_DIGEST_BYTES or len(right) != PROOF_DIGEST_BYTES:
        raise ValueError("Merkle child digest has wrong length")
    return hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-NODE-v1\0",
            level.to_bytes(2, "big"),
            index.to_bytes(8, "big"),
            left,
            right,
        )
    ).digest(PROOF_DIGEST_BYTES)


@dataclass(frozen=True)
class MerkleTree:
    symbols: tuple[int, ...]
    salts: tuple[bytes, ...]
    levels: tuple[tuple[bytes, ...], ...]

    @property
    def leaf_count(self) -> int:
        return len(self.salts)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]


def commit(symbols: Sequence[int], salts: Sequence[bytes]) -> MerkleTree:
    symbols = tuple(map(b128, symbols))
    salts = tuple(bytes(salt) for salt in salts)
    if not symbols or len(symbols) % LEAF_GROUP_SYMBOLS:
        raise ValueError("committed symbol count must be a nonzero multiple of four")
    leaf_count = len(symbols) // LEAF_GROUP_SYMBOLS
    if leaf_count & (leaf_count - 1):
        raise ValueError("Merkle leaf count must be a power of two")
    if len(salts) != leaf_count or any(len(salt) != SALT_BYTES for salt in salts):
        raise ValueError("one exact 32-byte salt is required per leaf")
    leaves = tuple(
        salted_leaf_hash(
            index,
            symbols[index * 4 : index * 4 + 4],
            salts[index],
        )
        for index in range(leaf_count)
    )
    levels: list[tuple[bytes, ...]] = [leaves]
    level = 0
    while len(levels[-1]) > 1:
        previous = levels[-1]
        levels.append(
            tuple(
                merkle_node_hash(level, index // 2, previous[index], previous[index + 1])
                for index in range(0, len(previous), 2)
            )
        )
        level += 1
    return MerkleTree(symbols, salts, tuple(levels))


def deterministic_salts(label: bytes, leaf_count: int) -> tuple[bytes, ...]:
    if leaf_count <= 0:
        raise ValueError("salt count must be positive")
    return tuple(
        hashlib.shake_256(
            _frame(b"HEG-RPPCS-FRI-TEST-SALT-v1\0", label, index.to_bytes(8, "big"))
        ).digest(SALT_BYTES)
        for index in range(leaf_count)
    )


def frontier_positions(leaf_count: int, opened_indices: Sequence[int]) -> tuple[tuple[int, int], ...]:
    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("leaf count must be a power of two")
    current = set(opened_indices)
    if not current or any(not 0 <= index < leaf_count for index in current):
        raise ValueError("opened leaf index out of range")
    if len(current) != len(opened_indices):
        raise ValueError("opened leaf indices must be unique")
    positions: list[tuple[int, int]] = []
    for level in range(leaf_count.bit_length() - 1):
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                positions.append((level, sibling))
        current = {index >> 1 for index in current}
    return tuple(positions)


def merkle_frontier(tree: MerkleTree, opened_indices: Sequence[int]) -> tuple[bytes, ...]:
    return tuple(tree.levels[level][index] for level, index in frontier_positions(tree.leaf_count, opened_indices))


def open_commitment(
    tree: MerkleTree, opened_indices: Sequence[int]
) -> tuple[tuple[tuple[tuple[int, ...], bytes], ...], tuple[bytes, ...]]:
    """Open canonical sorted leaves and their minimal Merkle frontier."""

    indices = tuple(opened_indices)
    if indices != tuple(sorted(indices)):
        raise ValueError("commitment opening indices must be canonically sorted")
    # frontier_positions performs range and uniqueness validation.
    frontier = merkle_frontier(tree, indices)
    payloads = tuple(_leaf_payload(tree, index) for index in indices)
    return payloads, frontier


def verify_merkle_opening(
    root: bytes,
    leaf_count: int,
    opened_indices: Sequence[int],
    opened_payloads: Sequence[tuple[tuple[int, ...], bytes]],
    frontier: Sequence[bytes],
) -> None:
    if len(root) != PROOF_DIGEST_BYTES or len(opened_indices) != len(opened_payloads):
        raise ProofError("invalid Merkle opening shape")
    positions = frontier_positions(leaf_count, opened_indices)
    if len(frontier) != len(positions) or any(len(node) != PROOF_DIGEST_BYTES for node in frontier):
        raise ProofError("non-canonical Merkle frontier length")
    frontier_map = dict(zip(positions, frontier))
    current = {
        index: salted_leaf_hash(index, symbols, salt)
        for index, (symbols, salt) in zip(opened_indices, opened_payloads)
    }
    for level in range(leaf_count.bit_length() - 1):
        parents: dict[int, bytes] = {}
        for parent in sorted({index >> 1 for index in current}):
            left_index = parent << 1
            right_index = left_index + 1
            left = current.get(left_index, frontier_map.get((level, left_index)))
            right = current.get(right_index, frontier_map.get((level, right_index)))
            if left is None or right is None:
                raise ProofError("Merkle frontier is incomplete")
            parents[parent] = merkle_node_hash(level, parent, left, right)
        current = parents
    if current.get(0) != root:
        raise ProofError("Merkle root mismatch")


def _branch_e256(
    label: bytes,
    base_root: bytes,
    fold_root: bytes,
    public_context: bytes,
    branch: int,
) -> E256:
    if len(base_root) != PROOF_DIGEST_BYTES or len(fold_root) != PROOF_DIGEST_BYTES:
        raise ValueError("transcript roots have wrong length")
    if branch not in range(BRANCHES):
        raise ValueError("branch is out of range")
    raw = hashlib.shake_256(
        _frame(
            b"HEG-RPPCS-FRI-E256-v1\0",
            label,
            branch.to_bytes(1, "big"),
            base_root,
            fold_root,
            public_context,
        )
    ).digest(E256_BYTES)
    return e256_from_bytes(raw)


def beta_challenge(base_root: bytes, public_context: bytes, branch: int) -> E256:
    # The all-zero placeholder is part of the pre-fold transcript; the real
    # folded root cannot be known before beta is sampled.
    return _branch_e256(b"beta", base_root, bytes(PROOF_DIGEST_BYTES), public_context, branch)


def terminal_challenge(
    base_root: bytes, fold_root: bytes, public_context: bytes, branch: int
) -> E256:
    return _branch_e256(b"terminal", base_root, fold_root, public_context, branch)


def derive_query_indices(
    roots: Sequence[bytes],
    public_context: bytes,
    branch: int,
    layer: int,
    count: int,
    leaf_count: int,
) -> tuple[int, ...]:
    if len(roots) != ROOT_COUNT or any(len(root) != PROOF_DIGEST_BYTES for root in roots):
        raise ValueError("query transcript needs exactly three roots")
    if branch not in range(BRANCHES) or layer not in range(ROOT_COUNT):
        raise ValueError("query branch/layer is out of range")
    if not 1 <= count <= leaf_count:
        raise ValueError("query count is out of range")
    limit = (1 << 64) - ((1 << 64) % leaf_count)
    selected: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(selected) < count:
        raw = hashlib.shake_256(
            _frame(
                b"HEG-RPPCS-FRI-QUERY-v1\0",
                branch.to_bytes(1, "big"),
                layer.to_bytes(1, "big"),
                counter.to_bytes(8, "big"),
                b"".join(roots),
                public_context,
            )
        ).digest(8)
        counter += 1
        candidate = int.from_bytes(raw, "big")
        if candidate >= limit:
            continue
        index = candidate % leaf_count
        if index not in seen:
            seen.add(index)
            selected.append(index)
    return tuple(selected)


def query_schedules(
    roots: Sequence[bytes], public_context: bytes, count: int, leaf_count: int
) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    schedules = tuple(
        (
            derive_query_indices(roots, public_context, branch, 0, count, leaf_count),
            derive_query_indices(
                roots, public_context, branch, branch + 1, count, leaf_count
            ),
        )
        for branch in range(BRANCHES)
    )
    base_union = tuple(sorted(set(schedules[0][0]) | set(schedules[1][0])))
    return schedules, base_union


def query_schedule_digest(schedules: Sequence[Sequence[Sequence[int]]]) -> bytes:
    body = bytearray()
    for branch_layers in schedules:
        for indices in branch_layers:
            body.extend(len(indices).to_bytes(4, "little"))
            for index in indices:
                body.extend(index.to_bytes(4, "little"))
    return hashlib.shake_256(
        _frame(b"HEG-RPPCS-FRI-QUERY-DIGEST-v1\0", bytes(body))
    ).digest(QUERY_DIGEST_BYTES)


def _flatten_e256(values: Sequence[E256]) -> tuple[int, ...]:
    return tuple(coordinate for value in values for coordinate in e256(value))


def _leaf_payload(tree: MerkleTree, index: int) -> tuple[tuple[int, ...], bytes]:
    return (
        tree.symbols[index * 4 : index * 4 + 4],
        tree.salts[index],
    )


@dataclass(frozen=True)
class ParsedProof:
    flags: int
    message_log: int
    rate_log: int
    active_count: int
    padding_count: int
    query_count: int
    roots: tuple[bytes, bytes, bytes]
    schedule_digest: bytes
    claims: tuple[tuple[E256, E256], tuple[E256, E256]]
    schedules: tuple[tuple[tuple[int, ...], ...], ...]
    base_indices: tuple[int, ...]
    fold_indices: tuple[tuple[int, ...], tuple[int, ...]]
    base_payloads: tuple[tuple[tuple[int, ...], bytes], ...]
    fold_payloads: tuple[tuple[tuple[tuple[int, ...], bytes], ...], ...]
    base_frontier: tuple[bytes, ...]
    fold_frontiers: tuple[tuple[bytes, ...], tuple[bytes, ...]]

    @property
    def message_symbols(self) -> int:
        return 1 << self.message_log

    @property
    def codeword_symbols(self) -> int:
        return 1 << (self.message_log + self.rate_log)

    @property
    def leaf_count(self) -> int:
        return self.codeword_symbols // LEAF_GROUP_SYMBOLS


def prove(
    active_coefficients: Sequence[int],
    random_padding: Sequence[int],
    rate_log: int,
    public_context: bytes,
    *,
    query_count: int | None = None,
    salt_seed: bytes | None = None,
) -> bytes:
    if not active_coefficients or not random_padding:
        raise ValueError("active coefficients and random padding must both be nonempty")
    if salt_seed is None:
        salt_seed = secrets.token_bytes(32)
    coefficients, base_codeword = encode(active_coefficients, random_padding, rate_log)
    message_log = len(coefficients).bit_length() - 1
    if message_log > MAX_TOY_MESSAGE_LOG:
        raise ValueError("executable prototype is intentionally small-n")
    leaf_count = len(base_codeword) // LEAF_GROUP_SYMBOLS
    if query_count is None:
        query_count = leaf_count
    if not 1 <= query_count <= leaf_count:
        raise ValueError("query count is out of range")

    base_tree = commit(
        base_codeword,
        deterministic_salts(_frame(b"base", salt_seed), leaf_count),
    )
    fold_trees: list[MerkleTree] = []
    folded_coefficients: list[tuple[E256, ...]] = []
    for branch in range(BRANCHES):
        beta = beta_challenge(base_tree.root, public_context, branch)
        folded = fold_coefficients(coefficients, beta)
        folded_coefficients.append(folded)
        encoded = encode_folded(folded, rate_log)
        tree = commit(
            _flatten_e256(encoded),
            deterministic_salts(
                _frame(b"fold", branch.to_bytes(1, "big"), salt_seed),
                leaf_count,
            ),
        )
        fold_trees.append(tree)
    roots = (base_tree.root, fold_trees[0].root, fold_trees[1].root)
    schedules, base_indices = query_schedules(roots, public_context, query_count, leaf_count)
    fold_indices = (tuple(sorted(schedules[0][1])), tuple(sorted(schedules[1][1])))

    claims: list[tuple[E256, E256]] = []
    embedded = tuple((coefficient, 0) for coefficient in coefficients)
    for branch in range(BRANCHES):
        point = terminal_challenge(roots[0], roots[branch + 1], public_context, branch)
        claims.append(
            (
                evaluate_e256(embedded, point),
                evaluate_e256(folded_coefficients[branch], point),
            )
        )

    base_frontier = merkle_frontier(base_tree, base_indices)
    fold_frontiers = (
        merkle_frontier(fold_trees[0], fold_indices[0]),
        merkle_frontier(fold_trees[1], fold_indices[1]),
    )
    flags = FLAG_EXHAUSTIVE_LOW_DEGREE if query_count == leaf_count else 0
    header = HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        flags,
        message_log,
        rate_log,
        len(active_coefficients),
        len(random_padding),
        query_count,
        len(base_indices),
        len(base_frontier),
        len(fold_indices[0]),
        len(fold_frontiers[0]),
        len(fold_indices[1]),
        len(fold_frontiers[1]),
    )
    out = bytearray(header)
    out.extend(b"".join(roots))
    out.extend(query_schedule_digest(schedules))
    for branch_claims in claims:
        for claim in branch_claims:
            out.extend(e256_to_bytes(claim))

    def append_opening(tree: MerkleTree, indices: Sequence[int], frontier: Sequence[bytes]) -> None:
        for index in indices:
            symbols, salt = _leaf_payload(tree, index)
            for symbol in symbols:
                out.extend(symbol.to_bytes(16, "little"))
            out.extend(salt)
        out.extend(b"".join(frontier))

    append_opening(base_tree, base_indices, base_frontier)
    append_opening(fold_trees[0], fold_indices[0], fold_frontiers[0])
    append_opening(fold_trees[1], fold_indices[1], fold_frontiers[1])
    return bytes(out)


def parse_proof(proof: bytes, public_context: bytes) -> ParsedProof:
    if len(proof) < FIXED_WIRE_BYTES:
        raise ProofError("proof truncated")
    fields = HEADER_STRUCT.unpack_from(proof)
    (
        magic,
        version,
        flags,
        message_log,
        rate_log,
        active_count,
        padding_count,
        query_count,
        base_opened_count,
        base_frontier_count,
        fold0_opened_count,
        fold0_frontier_count,
        fold1_opened_count,
        fold1_frontier_count,
    ) = fields
    if magic != MAGIC or version != VERSION:
        raise ProofError("invalid proof magic or version")
    if flags not in (0, FLAG_EXHAUSTIVE_LOW_DEGREE):
        raise ProofError("non-canonical proof flags")
    if not 1 <= message_log <= MAX_TOY_MESSAGE_LOG or not 1 <= rate_log <= MAX_TOY_RATE_LOG:
        raise ProofError("toy proof dimensions are out of range")
    message_symbols = 1 << message_log
    if active_count + padding_count != message_symbols or active_count == 0 or padding_count == 0:
        raise ProofError("active and padding counts do not form the message")
    codeword_symbols = 1 << (message_log + rate_log)
    leaf_count = codeword_symbols // LEAF_GROUP_SYMBOLS
    if not 1 <= query_count <= leaf_count:
        raise ProofError("query count is out of range")
    cursor = HEADER_BYTES
    roots = tuple(
        proof[cursor + index * PROOF_DIGEST_BYTES : cursor + (index + 1) * PROOF_DIGEST_BYTES]
        for index in range(ROOT_COUNT)
    )
    cursor += ROOT_COUNT * PROOF_DIGEST_BYTES
    schedule_digest = proof[cursor : cursor + QUERY_DIGEST_BYTES]
    cursor += QUERY_DIGEST_BYTES
    flat_claims = tuple(
        e256_from_bytes(proof[cursor + index * E256_BYTES : cursor + (index + 1) * E256_BYTES])
        for index in range(BRANCHES * CLAIMS_PER_BRANCH)
    )
    cursor += BRANCHES * CLAIMS_PER_BRANCH * E256_BYTES
    claims = ((flat_claims[0], flat_claims[1]), (flat_claims[2], flat_claims[3]))

    schedules, base_indices = query_schedules(roots, public_context, query_count, leaf_count)
    fold_indices = (tuple(sorted(schedules[0][1])), tuple(sorted(schedules[1][1])))
    expected_counts = (
        len(base_indices),
        len(frontier_positions(leaf_count, base_indices)),
        len(fold_indices[0]),
        len(frontier_positions(leaf_count, fold_indices[0])),
        len(fold_indices[1]),
        len(frontier_positions(leaf_count, fold_indices[1])),
    )
    encoded_counts = (
        base_opened_count,
        base_frontier_count,
        fold0_opened_count,
        fold0_frontier_count,
        fold1_opened_count,
        fold1_frontier_count,
    )
    if encoded_counts != expected_counts:
        raise ProofError("non-canonical query or frontier counts")
    expected_length = FIXED_WIRE_BYTES + OPENED_LEAF_BYTES * (
        base_opened_count + fold0_opened_count + fold1_opened_count
    ) + PROOF_DIGEST_BYTES * (
        base_frontier_count + fold0_frontier_count + fold1_frontier_count
    )
    if len(proof) < expected_length:
        raise ProofError("proof truncated")
    if len(proof) > expected_length:
        raise ProofError("proof has trailing bytes")
    if schedule_digest != query_schedule_digest(schedules):
        raise ProofError("root-derived query schedule mismatch")

    def read_opening(opened_count: int, frontier_count: int):
        nonlocal cursor
        payloads = []
        for _ in range(opened_count):
            symbols = tuple(
                int.from_bytes(proof[cursor + offset * 16 : cursor + (offset + 1) * 16], "little")
                for offset in range(LEAF_GROUP_SYMBOLS)
            )
            cursor += LEAF_GROUP_SYMBOLS * B128_BYTES
            salt = proof[cursor : cursor + SALT_BYTES]
            cursor += SALT_BYTES
            payloads.append((symbols, salt))
        frontier = tuple(
            proof[cursor + index * PROOF_DIGEST_BYTES : cursor + (index + 1) * PROOF_DIGEST_BYTES]
            for index in range(frontier_count)
        )
        cursor += frontier_count * PROOF_DIGEST_BYTES
        return tuple(payloads), frontier

    base_payloads, base_frontier = read_opening(base_opened_count, base_frontier_count)
    fold0_payloads, fold0_frontier = read_opening(fold0_opened_count, fold0_frontier_count)
    fold1_payloads, fold1_frontier = read_opening(fold1_opened_count, fold1_frontier_count)
    if cursor != len(proof):
        raise ProofError("parser did not exactly consume proof")
    return ParsedProof(
        flags=flags,
        message_log=message_log,
        rate_log=rate_log,
        active_count=active_count,
        padding_count=padding_count,
        query_count=query_count,
        roots=(roots[0], roots[1], roots[2]),
        schedule_digest=schedule_digest,
        claims=claims,
        schedules=schedules,
        base_indices=base_indices,
        fold_indices=fold_indices,
        base_payloads=base_payloads,
        fold_payloads=(fold0_payloads, fold1_payloads),
        base_frontier=base_frontier,
        fold_frontiers=(fold0_frontier, fold1_frontier),
    )


def verify_membership(proof: bytes, public_context: bytes) -> ParsedProof:
    parsed = parse_proof(proof, public_context)
    verify_merkle_opening(
        parsed.roots[0], parsed.leaf_count, parsed.base_indices, parsed.base_payloads, parsed.base_frontier
    )
    for branch in range(BRANCHES):
        verify_merkle_opening(
            parsed.roots[branch + 1],
            parsed.leaf_count,
            parsed.fold_indices[branch],
            parsed.fold_payloads[branch],
            parsed.fold_frontiers[branch],
        )
    return parsed


def _all_symbols(
    indices: Sequence[int], payloads: Sequence[tuple[tuple[int, ...], bytes]], leaf_count: int
) -> tuple[int, ...]:
    if tuple(indices) != tuple(range(leaf_count)):
        raise ProofError("exhaustive verifier requires every leaf in canonical order")
    return tuple(symbol for symbols, _salt in payloads for symbol in symbols)


def verify(proof: bytes, public_context: bytes) -> ParsedProof:
    parsed = verify_membership(proof, public_context)
    if parsed.flags != FLAG_EXHAUSTIVE_LOW_DEGREE or parsed.query_count != parsed.leaf_count:
        raise ProofError("query-only opening is not an authorized low-degree proof")
    base_codeword = _all_symbols(parsed.base_indices, parsed.base_payloads, parsed.leaf_count)
    base_domain = affine_domain(parsed.codeword_symbols)
    interpolated = interpolate_b128(base_domain, base_codeword)
    if any(interpolated[parsed.message_symbols :]):
        raise ProofError("base codeword exceeds the claimed degree bound")
    coefficients = interpolated[: parsed.message_symbols]

    embedded = tuple((coefficient, 0) for coefficient in coefficients)
    fold_domain_size = (parsed.message_symbols // 2) << parsed.rate_log
    fold_domain = affine_domain(fold_domain_size)
    for branch in range(BRANCHES):
        flat = _all_symbols(
            parsed.fold_indices[branch], parsed.fold_payloads[branch], parsed.leaf_count
        )
        values = tuple((flat[index], flat[index + 1]) for index in range(0, len(flat), 2))
        low_polynomial = interpolate_b128(fold_domain, tuple(value[0] for value in values))
        high_polynomial = interpolate_b128(fold_domain, tuple(value[1] for value in values))
        folded_message = tuple(
            (low_polynomial[index], high_polynomial[index])
            for index in range(parsed.message_symbols // 2)
        )
        if any(low_polynomial[parsed.message_symbols // 2 :]) or any(
            high_polynomial[parsed.message_symbols // 2 :]
        ):
            raise ProofError("folded codeword exceeds the claimed degree bound")
        beta = beta_challenge(parsed.roots[0], public_context, branch)
        expected_fold = fold_coefficients(coefficients, beta)
        if folded_message != expected_fold:
            raise ProofError("folded coefficients do not match the base polynomial")
        point = terminal_challenge(
            parsed.roots[0], parsed.roots[branch + 1], public_context, branch
        )
        expected_claims = (
            evaluate_e256(embedded, point),
            evaluate_e256(expected_fold, point),
        )
        if parsed.claims[branch] != expected_claims:
            raise ProofError("E256 terminal claim mismatch")
    return parsed


def polynomial_evaluation_row(point: int, width: int) -> tuple[int, ...]:
    row = []
    power = 1
    for _ in range(width):
        row.append(power)
        power = b128_mul(power, point)
    return tuple(row)


def _e256_weights_to_rows(weights: Sequence[E256]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    return (
        tuple(weight[0] for weight in weights),
        tuple(weight[1] for weight in weights),
    )


def _terminal_weights(point: E256, width: int) -> tuple[E256, ...]:
    weights = []
    power = E256_ONE
    for _ in range(width):
        weights.append(power)
        power = e256_mul(power, point)
    return tuple(weights)


def _fold_weights(beta: E256, point: E256, width: int) -> tuple[E256, ...]:
    weights = []
    power = E256_ONE
    for index in range(width):
        weights.append(power if index % 2 == 0 else e256_mul(beta, power))
        if index % 2 == 1:
            power = e256_mul(power, point)
    return tuple(weights)


@dataclass(frozen=True)
class ObservationMatrix:
    rows: tuple[tuple[int, ...], ...]
    labels: tuple[str, ...]
    active_columns: int
    padding_columns: int


def export_observation_matrix(parsed: ParsedProof, public_context: bytes) -> ObservationMatrix:
    """Export every opened B128 coordinate and every terminal/fold row."""

    width = parsed.message_symbols
    rows: list[tuple[int, ...]] = []
    labels: list[str] = []
    base_domain = affine_domain(parsed.codeword_symbols)
    for leaf_index in parsed.base_indices:
        for offset in range(LEAF_GROUP_SYMBOLS):
            point_index = leaf_index * LEAF_GROUP_SYMBOLS + offset
            rows.append(polynomial_evaluation_row(base_domain[point_index], width))
            labels.append(f"base.point[{point_index}]")

    fold_domain_size = (width // 2) << parsed.rate_log
    fold_domain = affine_domain(fold_domain_size)
    for branch in range(BRANCHES):
        beta = beta_challenge(parsed.roots[0], public_context, branch)
        for leaf_index in parsed.fold_indices[branch]:
            for value_offset in range(2):
                point_index = leaf_index * 2 + value_offset
                weights = []
                power = 1
                for coefficient_index in range(width):
                    embedded_power: E256 = (power, 0)
                    weights.append(
                        embedded_power
                        if coefficient_index % 2 == 0
                        else e256_mul(beta, embedded_power)
                    )
                    if coefficient_index % 2 == 1:
                        power = b128_mul(power, fold_domain[point_index])
                coordinate_rows = _e256_weights_to_rows(weights)
                rows.extend(coordinate_rows)
                labels.extend(
                    (
                        f"branch[{branch}].fold-point[{point_index}].coord[0]",
                        f"branch[{branch}].fold-point[{point_index}].coord[1]",
                    )
                )
        point = terminal_challenge(
            parsed.roots[0], parsed.roots[branch + 1], public_context, branch
        )
        for claim_name, weights in (
            ("terminal", _terminal_weights(point, width)),
            ("fold-terminal", _fold_weights(beta, point, width)),
        ):
            coordinate_rows = _e256_weights_to_rows(weights)
            rows.extend(coordinate_rows)
            labels.extend(
                (
                    f"branch[{branch}].{claim_name}.coord[0]",
                    f"branch[{branch}].{claim_name}.coord[1]",
                )
            )
    return ObservationMatrix(
        tuple(rows), tuple(labels), parsed.active_count, parsed.padding_count
    )


def matrix_rank(rows: Sequence[Sequence[int]]) -> int:
    if not rows:
        return 0
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError("ragged matrix")
    matrix = [list(map(b128, row)) for row in rows]
    pivot_row = 0
    for column in range(width):
        pivot = next(
            (index for index in range(pivot_row, len(matrix)) if matrix[index][column]),
            None,
        )
        if pivot is None:
            continue
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        inverse = b128_inv(matrix[pivot_row][column])
        matrix[pivot_row] = [b128_mul(value, inverse) for value in matrix[pivot_row]]
        for index, row in enumerate(matrix):
            if index == pivot_row or row[column] == 0:
                continue
            factor = row[column]
            matrix[index] = [
                value ^ b128_mul(factor, pivot_value)
                for value, pivot_value in zip(row, matrix[pivot_row])
            ]
        pivot_row += 1
        if pivot_row == len(matrix):
            break
    return pivot_row


@dataclass(frozen=True)
class RankAudit:
    observations: int
    active_columns: int
    padding_columns: int
    padding_rank: int
    joint_rank: int
    full_row_rank_on_padding: bool
    witness_independent_for_fixed_matrix: bool
    schedule_fixed_independently_of_padding: bool
    zero_knowledge_conclusion_authorized: bool


def audit_observation_matrix(
    matrix: ObservationMatrix, *, schedule_fixed_independently_of_padding: bool
) -> RankAudit:
    padding_rows = tuple(row[matrix.active_columns :] for row in matrix.rows)
    padding_rank = matrix_rank(padding_rows)
    joint_rank = matrix_rank(matrix.rows)
    independent = joint_rank == padding_rank
    full = padding_rank == len(matrix.rows)
    return RankAudit(
        observations=len(matrix.rows),
        active_columns=matrix.active_columns,
        padding_columns=matrix.padding_columns,
        padding_rank=padding_rank,
        joint_rank=joint_rank,
        full_row_rank_on_padding=full,
        witness_independent_for_fixed_matrix=independent,
        schedule_fixed_independently_of_padding=schedule_fixed_independently_of_padding,
        zero_knowledge_conclusion_authorized=(
            schedule_fixed_independently_of_padding and independent
        ),
    )


def reused_padding_fixed_view_delta(
    first_active: Sequence[int],
    second_active: Sequence[int],
    reused_padding: Sequence[int],
    point: int,
) -> tuple[int, int]:
    first = tuple(first_active) + tuple(reused_padding)
    second = tuple(second_active) + tuple(reused_padding)
    observed = evaluate_b128(first, point) ^ evaluate_b128(second, point)
    expected = evaluate_b128(
        tuple(left ^ right for left, right in zip(first_active, second_active))
        + tuple(0 for _ in reused_padding),
        point,
    )
    return observed, expected


def canonical_frontier_max(leaf_count: int, opened_leaves: int) -> int:
    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("leaf count must be a power of two")
    if not 1 <= opened_leaves <= leaf_count:
        raise ValueError("opened leaves out of range")
    level = math.floor(math.log2(leaf_count / opened_leaves))
    return opened_leaves * (level - 1) + leaf_count // (1 << level)


def direct_bcs_salt_bytes(leaf_count: int) -> int:
    """Price the external classical lemma for one power-of-two tree.

    This `130 + log2(leaves)` diagnostic is not a QROM or common-parameter
    certificate.
    """

    if leaf_count <= 0 or leaf_count & (leaf_count - 1):
        raise ValueError("direct-BCS salt pricing requires a power-of-two tree")
    return 130 + (leaf_count.bit_length() - 1)


@dataclass(frozen=True)
class ProductionTopology:
    label: str
    rate_log: int
    queries_per_branch: int
    legacy_screen_bytes: int
    strict_precursor_screen_bytes: int
    salt_bytes: int
    salt_security_scope: str
    message_symbols: int = 1 << PRODUCTION_MESSAGE_LOG

    @property
    def codeword_symbols(self) -> int:
        return self.message_symbols << self.rate_log

    @property
    def leaves_per_tree(self) -> int:
        return self.codeword_symbols // LEAF_GROUP_SYMBOLS

    @property
    def base_opened_leaves_worst_union(self) -> int:
        return 2 * self.queries_per_branch

    @property
    def fold_opened_leaves(self) -> int:
        return self.queries_per_branch

    @property
    def serialized_opened_leaves(self) -> int:
        return self.base_opened_leaves_worst_union + 2 * self.fold_opened_leaves

    @property
    def base_frontier_nodes(self) -> int:
        return canonical_frontier_max(
            self.leaves_per_tree, self.base_opened_leaves_worst_union
        )

    @property
    def folded_frontier_nodes_each(self) -> int:
        return canonical_frontier_max(self.leaves_per_tree, self.fold_opened_leaves)

    @property
    def serialized_frontier_nodes(self) -> int:
        return self.base_frontier_nodes + 2 * self.folded_frontier_nodes_each

    @property
    def opened_leaf_bytes(self) -> int:
        return LEAF_GROUP_SYMBOLS * B128_BYTES + self.salt_bytes

    @property
    def query_only_one_round_bytes(self) -> int:
        return (
            FIXED_WIRE_BYTES
            + self.serialized_opened_leaves * self.opened_leaf_bytes
            + self.serialized_frontier_nodes * PROOF_DIGEST_BYTES
        )

    @property
    def exhaustive_honest_bytes(self) -> int:
        return (
            FIXED_WIRE_BYTES
            + ROOT_COUNT * self.leaves_per_tree * self.opened_leaf_bytes
        )

    def record(self) -> dict[str, object]:
        return {
            **asdict(self),
            "codeword_symbols": self.codeword_symbols,
            "leaves_per_tree": self.leaves_per_tree,
            "root_count": ROOT_COUNT,
            "proof_digest_bytes": PROOF_DIGEST_BYTES,
            "fixed_wire_bytes": FIXED_WIRE_BYTES,
            "opened_leaf_bytes": self.opened_leaf_bytes,
            "base_opened_leaves_worst_union": self.base_opened_leaves_worst_union,
            "fold_opened_leaves_each": self.fold_opened_leaves,
            "serialized_opened_leaves": self.serialized_opened_leaves,
            "base_frontier_nodes": self.base_frontier_nodes,
            "folded_frontier_nodes_each": self.folded_frontier_nodes_each,
            "serialized_frontier_nodes": self.serialized_frontier_nodes,
            "query_only_one_round_bytes": self.query_only_one_round_bytes,
            "increment_over_legacy_screen_bytes": (
                self.query_only_one_round_bytes - self.legacy_screen_bytes
            ),
            "increment_over_strict_precursor_screen_bytes": (
                self.query_only_one_round_bytes
                - self.strict_precursor_screen_bytes
            ),
            "exhaustive_honest_bytes": self.exhaustive_honest_bytes,
            "query_only_is_a_proved_fri": False,
            "exhaustive_is_succinct": False,
            "salt_security_theorem_integrated": False,
        }


def production_topologies() -> tuple[ProductionTopology, ...]:
    return (
        ProductionTopology(
            "conditional-q33-rate32-salt32-unproved",
            5,
            33,
            LEGACY_SCREEN_CONDITIONAL_BYTES,
            STRICT_PRECURSOR_CONDITIONAL_BYTES,
            SALT_BYTES,
            "32-byte salt has no integrated direct BCS/QROM theorem",
        ),
        ProductionTopology(
            "double-full-q66-rate32-salt32-unproved",
            5,
            66,
            LEGACY_SCREEN_DOUBLE_FULL_BYTES,
            STRICT_PRECURSOR_DOUBLE_FULL_BYTES,
            SALT_BYTES,
            "32-byte salt has no integrated direct BCS/QROM theorem",
        ),
        ProductionTopology(
            "conditional-q33-rate32-salt148-theorem-scope",
            5,
            33,
            LEGACY_SCREEN_CONDITIONAL_BYTES,
            STRICT_PRECURSOR_CONDITIONAL_BYTES,
            THEOREM_SCOPED_SALT_BYTES,
            "148-byte salt is the external direct-BCS n=2^18 theorem scope; not integrated here",
        ),
        ProductionTopology(
            "double-full-q66-rate32-salt148-theorem-scope",
            5,
            66,
            LEGACY_SCREEN_DOUBLE_FULL_BYTES,
            STRICT_PRECURSOR_DOUBLE_FULL_BYTES,
            THEOREM_SCOPED_SALT_BYTES,
            "148-byte salt is the external direct-BCS n=2^18 theorem scope; not integrated here",
        ),
    )


def combined_fold_tree_best_case() -> dict[str, object]:
    """Maximum structural saving with one root binding both E256 folds.

    One combined leaf has the fixed lane order
    ``[branch0.low, branch0.high, branch1.low, branch1.high]`` for one folded
    evaluation point.  The best case lets both branches query the same 33
    folded positions.  This is an exact serializer screen, not an independence
    or product-soundness theorem.
    """

    base_leaf_count = 1 << 18
    combined_fold_leaf_count = 1 << 19
    base_opened = 66
    fold_opened_union = 33
    base_frontier = canonical_frontier_max(base_leaf_count, base_opened)
    fold_frontier = canonical_frontier_max(
        combined_fold_leaf_count, fold_opened_union
    )
    fixed_bytes = (
        HEADER_BYTES
        + 2 * PROOF_DIGEST_BYTES
        + QUERY_DIGEST_BYTES
        + BRANCHES * CLAIMS_PER_BRANCH * E256_BYTES
    )
    total = (
        fixed_bytes
        + (base_opened + fold_opened_union) * OPENED_LEAF_BYTES
        + (base_frontier + fold_frontier) * PROOF_DIGEST_BYTES
    )
    theorem_salt_total = (
        fixed_bytes
        + base_opened
        * (LEAF_GROUP_SYMBOLS * B128_BYTES + direct_bcs_salt_bytes(base_leaf_count))
        + fold_opened_union
        * (
            LEAF_GROUP_SYMBOLS * B128_BYTES
            + direct_bcs_salt_bytes(combined_fold_leaf_count)
        )
        + (base_frontier + fold_frontier) * PROOF_DIGEST_BYTES
    )
    separate_tree_total = production_topologies()[0].query_only_one_round_bytes
    return {
        "label": "q33-rate32-single-combined-fold-tree-salt32-best-case",
        "combined_leaf_lane_order": [
            "branch0.low",
            "branch0.high",
            "branch1.low",
            "branch1.high",
        ],
        "base_leaf_count": base_leaf_count,
        "combined_fold_leaf_count": combined_fold_leaf_count,
        "base_opened_leaves": base_opened,
        "combined_fold_opened_union": fold_opened_union,
        "base_frontier_nodes": base_frontier,
        "combined_fold_frontier_nodes": fold_frontier,
        "root_count": 2,
        "fixed_wire_bytes": fixed_bytes,
        "query_only_one_round_bytes": total,
        "theorem_scoped_salt_one_round_bytes": theorem_salt_total,
        "base_theorem_scoped_salt_bytes": direct_bcs_salt_bytes(base_leaf_count),
        "combined_fold_theorem_scoped_salt_bytes": direct_bcs_salt_bytes(
            combined_fold_leaf_count
        ),
        "separate_fold_tree_bytes": separate_tree_total,
        "maximum_structural_savings_bytes": separate_tree_total - total,
        "verifier_known_terminal_elision_bytes": 0,
        "terminal_elision_justified": False,
        "terminal_elision_reason": (
            "both original and folded E256 terminal values depend on hidden "
            "coefficients and are not verifier-known in this PCS seam"
        ),
        "branch_commitments_retained": True,
        "all_openings_authenticated": True,
        "shared_fold_query_schedule_product_soundness_proved": False,
        "query_only_is_a_proved_fri": False,
    }


def all_rounds_structural_floor() -> dict[str, object]:
    """Price all 15 coefficient halvings under the combined-tree best case.

    The result is only an authenticated Merkle/opening structural floor.  It
    does not price an actual local consistency grammar, PIOP messages,
    extraction, or security composition.
    """

    query_count = 33
    base_leaf_count = 1 << 18
    base_opened = 66
    rounds_required = PRODUCTION_MESSAGE_LOG
    root_count = 1 + rounds_required
    fixed_bytes = (
        HEADER_BYTES
        + root_count * PROOF_DIGEST_BYTES
        + QUERY_DIGEST_BYTES
        + BRANCHES * CLAIMS_PER_BRANCH * E256_BYTES
    )
    base_frontier = canonical_frontier_max(base_leaf_count, base_opened)
    total_opened_leaves = base_opened
    total_frontier_nodes = base_frontier
    total = (
        fixed_bytes
        + base_opened * OPENED_LEAF_BYTES
        + base_frontier * PROOF_DIGEST_BYTES
    )
    rounds = []
    for round_number in range(1, rounds_required + 1):
        leaf_count = 1 << (20 - round_number)
        opened = min(query_count, leaf_count)
        frontier = canonical_frontier_max(leaf_count, opened)
        wire_bytes = (
            opened * OPENED_LEAF_BYTES + frontier * PROOF_DIGEST_BYTES
        )
        total += wire_bytes
        total_opened_leaves += opened
        total_frontier_nodes += frontier
        rounds.append(
            {
                "round": round_number,
                "maximum_coefficient_count": 1 << (15 - round_number),
                "combined_fold_leaf_count": leaf_count,
                "opened_leaves": opened,
                "frontier_nodes": frontier,
                "wire_bytes_excluding_root": wire_bytes,
            }
        )
    one_round_combined = combined_fold_tree_best_case()["query_only_one_round_bytes"]
    theorem_salt_payload = base_opened * (
        LEAF_GROUP_SYMBOLS * B128_BYTES + direct_bcs_salt_bytes(base_leaf_count)
    )
    theorem_salt_payload += sum(
        round_info["opened_leaves"]
        * (
            LEAF_GROUP_SYMBOLS * B128_BYTES
            + direct_bcs_salt_bytes(round_info["combined_fold_leaf_count"])
        )
        for round_info in rounds
    )
    theorem_salt_total = (
        fixed_bytes
        + theorem_salt_payload
        + total_frontier_nodes * PROOF_DIGEST_BYTES
    )
    return {
        "initial_maximum_coefficient_count": 1 << PRODUCTION_MESSAGE_LOG,
        "one_round_degree_reduction_factor": 2,
        "rounds_required_to_constant": rounds_required,
        "additional_rounds_after_the_executable_one": rounds_required - 1,
        "root_count": root_count,
        "salt_bytes": SALT_BYTES,
        "fixed_wire_bytes": fixed_bytes,
        "rounds": rounds,
        "authenticated_structural_floor_bytes": total,
        "theorem_scoped_salt_structural_floor_bytes": theorem_salt_total,
        "total_opened_leaves": total_opened_leaves,
        "total_frontier_nodes": total_frontier_nodes,
        "additional_bytes_over_combined_one_round": total - one_round_combined,
        "additional_bytes_over_separate_one_round_118192": total - 118_192,
        "verifier_known_terminal_elision_bytes": 0,
        "complete_fri_bytes": None,
        "complete_fri_authorized": False,
        "floor_omits": [
            "a proved cross-layer local consistency grammar",
            "maximum-M4 PIOP messages",
            "characteristic-two ZK messages",
            "FRI extraction and adaptive BCS simulation",
            "two-branch product soundness and QROM composition",
        ],
    }


def toy_fixture() -> tuple[bytes, bytes]:
    context = b"hegemon.maximum83.toy-context.v1"
    proof = prove(
        (1, 2, 3, 4),
        (0xA1, 0xB2, 0xC3, 0xD4),
        2,
        context,
        salt_seed=b"fixture-0",
    )
    return proof, context


def report() -> dict[str, object]:
    proof, context = toy_fixture()
    parsed = verify(proof, context)
    matrix = export_observation_matrix(parsed, context)
    audit = audit_observation_matrix(
        matrix, schedule_fixed_independently_of_padding=False
    )
    gates = {
        "compiled_maximum_m4_active_prefix_frozen": False,
        "production_random_tail_capacity_sufficient": False,
        "production_full_observation_matrix_exported": False,
        "production_padding_submatrix_full_rank": False,
        "adaptive_bcs_zero_knowledge_proved": False,
        "succinct_fri_proximity_proved": False,
        "fri_extraction_proved": False,
        "two_e256_parallel_product_theorem_proved": False,
        "salted_merkle_qrom_hiding_binding_proved": False,
        "composed_pq128_qrom_proved": False,
        "production_canonical_parser_refinement_proved": False,
        "formal_security_proved": False,
        "strict_admitted": False,
        "frontier_eligible": False,
    }
    return {
        "schema": "hegemon.m4-random-padding-zk-pcs-fri.v1",
        "hash_and_salt_profiles": {
            "strict_proof_digest": "SHAKE256-512",
            "strict_proof_digest_bytes": PROOF_DIGEST_BYTES,
            "legacy_56_byte_digest_is_non_strict_negative_control": True,
            "legacy_non_strict_digest_bytes": LEGACY_NON_STRICT_DIGEST_BYTES,
            "executable_toy_salt_bytes": SALT_BYTES,
            "executable_toy_salt_security_proved": False,
            "direct_bcs_n18_theorem_scoped_salt_bytes": THEOREM_SCOPED_SALT_BYTES,
            "direct_bcs_theorem_integrated": False,
        },
        "toy": {
            "proof_bytes": len(proof),
            "message_symbols": parsed.message_symbols,
            "codeword_symbols": parsed.codeword_symbols,
            "leaves_per_tree": parsed.leaf_count,
            "roots": ROOT_COUNT,
            "exhaustive_low_degree_verified": True,
            "one_coefficient_fold_per_e256_branch_verified": True,
            "observation_rows_exported": len(matrix.rows),
            "observation_labels_exported": len(matrix.labels),
            "rank_audit": asdict(audit),
            "zero_knowledge": False,
        },
        "production_n15_topologies": [profile.record() for profile in production_topologies()],
        "combined_fold_tree_best_case": combined_fold_tree_best_case(),
        "all_rounds_structural_floor": all_rounds_structural_floor(),
        "full_low_degree_cap_verdict": {
            "raw_cap_bytes": RAW_PROOF_CAP_BYTES,
            "combined_one_round_bytes": 89_744,
            "combined_one_round_fits_raw_cap": True,
            "combined_one_round_is_full_low_degree": False,
            "fifteen_round_structural_floor_bytes": 325_424,
            "fifteen_round_structural_floor_fits_raw_cap": False,
            "any_implemented_or_screened_full_low_degree_profile_under_cap": False,
            "universal_impossibility_claim": False,
        },
        "production_rank_boundary": {
            "compiled_active_symbols_frozen": False,
            "source_static_active_symbols_min": SOURCE_STATIC_ACTIVE_SYMBOLS_MIN,
            "source_static_active_symbols_max": SOURCE_STATIC_ACTIVE_SYMBOLS_MAX,
            "source_static_random_tail_min": SOURCE_STATIC_RANDOM_TAIL_MIN,
            "source_static_random_tail_max": SOURCE_STATIC_RANDOM_TAIL_MAX,
            "exact_full_matrix_rank": None,
            "conditional_q33_ideal_algebraic_bits_approx": 132.606,
            "conditional_q33_security_authorized": False,
        },
        "screen_correction": {
            "real_proximity_check_adds_missing_terms": True,
            "terms_missing_from_63320_116952_as_instantiated": [
                "two folded-layer SHAKE256-512 roots",
                "one salted four-B128-symbol opening per folded query and branch",
                "one canonical Merkle frontier per folded layer and branch",
                "explicit original and folded E256 terminal values",
                "cross-layer coefficient-fold consistency checks",
                "later FRI rounds or an alternative terminal degree proof",
            ],
            "optimized_complete_fri_increment_bytes": None,
            "reason_null": "no succinct binary-field FRI serializer or extraction theorem is implemented",
        },
        "gates": gates,
        "verdict": "honest exhaustive toy; query-only production topology is not a FRI proof",
    }


def self_check() -> None:
    assert HEADER_BYTES == 48
    assert FIXED_WIRE_BYTES == 432
    assert b128_mul(1 << 127, 2) == 0x87
    assert e256_mul((0, 1), (0, 1)) == (2, 2)
    proof, context = toy_fixture()
    parsed = verify(proof, context)
    assert len(proof) == 2_736
    matrix = export_observation_matrix(parsed, context)
    audit = audit_observation_matrix(matrix, schedule_fixed_independently_of_padding=False)
    assert len(matrix.rows) == 104
    assert audit.padding_rank == 4
    assert audit.joint_rank == 8
    assert not audit.zero_knowledge_conclusion_authorized
    profiles = production_topologies()
    assert profiles[0].query_only_one_round_bytes == 118_192
    assert profiles[1].query_only_one_round_bytes == 219_056
    assert profiles[2].query_only_one_round_bytes == 133_504
    assert profiles[3].query_only_one_round_bytes == 249_680
    combined = combined_fold_tree_best_case()
    assert combined["query_only_one_round_bytes"] == 89_744
    assert combined["theorem_scoped_salt_one_round_bytes"] == 101_261
    assert combined["maximum_structural_savings_bytes"] == 28_448
    all_rounds = all_rounds_structural_floor()
    assert all_rounds["rounds_required_to_constant"] == 15
    assert all_rounds["authenticated_structural_floor_bytes"] == 325_424
    assert all_rounds["theorem_scoped_salt_structural_floor_bytes"] == 387_427
    assert all(value is False for value in report()["gates"].values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("RANDOM_PADDING_FRI_CHECK_PASS")
    if args.report:
        print(json.dumps(report(), sort_keys=True, separators=(",", ":")))
    if not args.check and not args.report:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
