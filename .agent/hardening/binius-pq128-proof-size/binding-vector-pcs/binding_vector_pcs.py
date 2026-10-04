#!/usr/bin/env python3
"""Disk-light mixed-field vector-opening PCS experiment.

This module deliberately has two different products:

* ``MerkleVectorProof`` is an executable, canonical, SHAKE256-512 Merkle
  opening for interleaved B128 symbols.  It exercises real B128 arithmetic,
  real E384 Fiat--Shamir challenges, exact parsing, and tamper rejection.  It
  is binding under the stated hash assumption, but it is *not hiding*: the
  opened B128 rows are on the wire.
* ``compact_target_plan`` is a byte envelope for the missing hiding/vector
  PCS plus an algebraic ZK transcript.  Its 128-byte query record is a target,
  not an implementation.  ``SimulatorTarget`` supplies a source-independent
  programmable-ROM simulation shape so the missing simulator cannot be
  hidden behind a byte counter.
* ``JointMaskProof`` is the replacement toy for the failed affine lane mask.
  It commits one joint ``[pi || omega]`` leaf, samples a true E384 scalar
  challenge after the commitment, opens both authenticated mask dimensions,
  and derives ``pi' = (1-gamma)pi + gamma omega``.  The three B128
  coefficients of every E384 scalar are explicit in the wire model.  This is
  an executable parser/tamper seam, not a production nonlinear-ZK theorem.

The old ``InPlaceZkProof`` affine-fiber code remains as a negative regression
control only.  It is deliberately excluded from the production report:
full M4 contains shared quadratic BitAnd constraints, and an affine kernel
translation is not relation preserving for that relation (nor does one
single B128 lane hide an E384 scalar).

The production geometry is evaluated without allocating its 64 MiB oracle.
Only the tiny toy instance allocates a codeword.  No Cargo, network, setup,
pairing, aggregation, or external package is required.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import struct
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# Fixed profile constants

B128_BITS = 128
B128_BYTES = 16
B128_MASK = (1 << B128_BITS) - 1
# x^128 + x^7 + x^2 + x + 1, the pinned GHASH polynomial basis.
B128_REDUCTION = 0x87
E384_BYTES = 48
DIGEST_BYTES = 64
# Merkle nodes are independently priced at SHAKE256-448.  Fiat--Shamir and
# commitment/transcript challenges remain SHAKE256-512.  Keeping these widths
# separate prevents a 64-byte FS digest from silently becoming a Merkle node.
MERKLE_DIGEST_BYTES = 56
FS_DIGEST_BYTES = 64
HEADER_BYTES = 64
MAGIC = b"HVBPCS01"
VERSION = 1
HEADER_FORMAT = ">8sHH32s4B4H2I"
PUBLIC_CONTEXT_BYTES = 32

STRICT_CLASSICAL_BITS = 264
JOHNSON_ETA = 1 / 256
LOG_INV_RATE = 8
STRICT_QUERY_COUNT = 68
LANES = 32
STRICT_LOG_RELATION_SIZE = 14
N15_LOG_RELATION_SIZE = 15
STRICT_ACTIVE_SYMBOLS = 14_658 + 325 + 512
STRICT_FOLD_VARIABLES = 5

VEIL_MIXED_FIELD_RAW_BYTES = 86_752
RAW_PROOF_CAP_BYTES = 124_068
PCS_ZK_BUDGET_BYTES = RAW_PROOF_CAP_BYTES - VEIL_MIXED_FIELD_RAW_BYTES
COMPACT_QUERY_RECORD_BYTES = 16 + 64 + 48  # B128 + SHAKE-512 + E384
ALGEBRAIC_ZK_ELEMENT_BYTES = E384_BYTES
ALGEBRAIC_ZK_TARGET_MESSAGES = 593

# The in-place toy mode is a separate wire profile.  Its one public E384
# relation claim is serialized so the parser has an exact algebraic region;
# the production size model charges the larger one-level Ligerito transcript
# below.  Twelve bytes model an outer envelope tag/length owned by the parent
# VEIL container and are not silently folded into the raw proof count.
IN_PLACE_ZK_FLAGS = 5
IN_PLACE_RELATION_ID = b"lane0=lane1/v1"
IN_PLACE_TOY_CLAIM_ELEMENTS = 1
LIGERITO_PER_FOLD_CLAIM_ELEMENTS = 2
LIGERITO_ENVELOPE_BYTES = 12
LIGERITO_ENVELOPE_CAP_BYTES = 512 * 1024

# Frozen source anchors for the isolated full-production M4 relation.  These
# values are copied from
# ``prototypes/standalone-shake256-binius/m4-full-production-prototype``;
# the Python model never builds the Rust circuit or allocates its oracle.
M4_SOURCE_REVISION = "3f96163049f680b2909f6545690bd929f1b48c44"
M4_PUBLIC_BYTES = 853
M4_STATEMENT_WORDS = 107
M4_DERIVED_INTENT_WORDS = 7
M4_PUBLIC_WORDS = 114
M4_PRIVATE_WORDS = 671
M4_INPUT_WORDS = 261
M4_OUTPUT_WORDS = 30
M4_AUTH_WORDS = 89
M4_KECCAK_PERMUTATIONS = 83
M4_KECCAK_BITAND_PERMUTATION = 24 * 5 * 5 * 64
M4_KECCAK_BITAND_CONSTRAINTS = (
    M4_KECCAK_PERMUTATIONS * M4_KECCAK_BITAND_PERMUTATION
)
# Expanding a masked quadratic/Boolean AND relation introduces three product
# families: a*Omega_b, Omega_a*b, and Omega_a*Omega_b. This is the explicit
# naive cross-term price; no compressed nonlinear compiler is claimed.
M4_BITAND_CROSS_TERM_PRODUCTS_PER_GATE = 3
# The source has these static helper call sites.  Loop expansion is not
# claimed here; the exact dynamic nonlinear count above is the 83*38400
# Keccak chi inventory emitted by the frozen source's main.rs.
M4_STATIC_SHIFT_CALL_SITES = 5 + 3  # builder.shl + builder.shr
M4_STATIC_PUBLIC_ASSERT_CALL_SITES = 50
M4_TRANSPORT_B128_SYMBOLS = (M4_PRIVATE_WORDS + 1) // 2
# Full-M4 active trace rows are not emitted by source-only Rust.  26,000 is a
# sensitivity assumption requested by the architecture audit, never a frozen
# measurement.  The n15/n16 bucket and all byte formulas remain exact once a
# real compiled artifact supplies this value.
M4_ACTIVE_TRACE_SYMBOLS_ASSUMPTION = 26_000
M4_N15_TRACE_BUCKET = 1 << 15
M4_N16_TRACE_BUCKET = 1 << 16

# The prior one-level model used 113 wide E384 reduction values.  Retain this
# only as an explicit optimistic reduction assumption; it is not a count of
# all M4 gates and does not close the nonlinear relation proof.
M4_OPTIMISTIC_WIDE_CLAIMS = 113
M4_E384_MASK_COORDINATES = 3
M4_MASK_SHARE_DIMENSIONS = 2  # [pi || omega]
M4_GAMMA_CANDIDATES = 2
M4_GAMMA_BYTES_PER_CANDIDATE = B128_BYTES
M4_GAMMA_ZERO_EVENT_BITS = M4_GAMMA_CANDIDATES * B128_BITS
M4_RELATION_ID = b"full-m4-source-bound/v1"


def _frame(domain: bytes, *parts: bytes) -> bytes:
    """Length-frame every transcript/commitment input."""

    output = bytearray(domain)
    for part in parts:
        output.extend(len(part).to_bytes(8, "big"))
        output.extend(part)
    return bytes(output)


def shake512(domain: bytes, *parts: bytes) -> bytes:
    """Return one SHAKE256-512 digest for commitments and Fiat--Shamir."""

    return hashlib.shake_256(_frame(domain, *parts)).digest(FS_DIGEST_BYTES)


def shake448(domain: bytes, *parts: bytes) -> bytes:
    """Return one SHAKE256-448 digest for Merkle nodes."""

    return hashlib.shake_256(_frame(domain, *parts)).digest(MERKLE_DIGEST_BYTES)


def _check_digest(value: bytes) -> bytes:
    if len(value) != DIGEST_BYTES:
        raise ValueError("SHAKE256-512 digest must be exactly 64 bytes")
    return value


def _check_merkle_digest(value: bytes) -> bytes:
    if len(value) != MERKLE_DIGEST_BYTES:
        raise ValueError("SHAKE256-448 Merkle digest must be exactly 56 bytes")
    return value


# ---------------------------------------------------------------------------
# Real binary fields: B128 and E384 = B128[Y]/(Y^3 + Y + 1)


def b128(value: int) -> int:
    if not 0 <= value <= B128_MASK:
        raise ValueError("non-canonical B128 element")
    return value


def b128_mul(left: int, right: int) -> int:
    """Multiply in GF(2^128) using the fixed polynomial basis."""

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
        raise ValueError("B128 elements are exactly 16 bytes")
    return b128(int.from_bytes(encoded, "little"))


@dataclass(frozen=True)
class E384:
    """The real cubic extension GF(2^384), not the product ring B128^3."""

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
            raise ValueError("E384 elements are exactly 48 bytes")
        return cls(
            b128_from_bytes(encoded[0:16]),
            b128_from_bytes(encoded[16:32]),
            b128_from_bytes(encoded[32:48]),
        )

    def to_bytes(self) -> bytes:
        return b"".join(
            b128_to_bytes(component)
            for component in (self.c0, self.c1, self.c2)
        )

    def __add__(self, other: "E384") -> "E384":
        return E384(self.c0 ^ other.c0, self.c1 ^ other.c1, self.c2 ^ other.c2)

    __sub__ = __add__

    def __mul__(self, other: "E384") -> "E384":
        a0, a1, a2 = self.c0, self.c1, self.c2
        b0, b1, b2 = other.c0, other.c1, other.c2
        d0 = b128_mul(a0, b0)
        d1 = b128_mul(a0, b1) ^ b128_mul(a1, b0)
        d2 = b128_mul(a0, b2) ^ b128_mul(a1, b1) ^ b128_mul(a2, b0)
        d3 = b128_mul(a1, b2) ^ b128_mul(a2, b1)
        d4 = b128_mul(a2, b2)
        # Y^3 = Y + 1 and Y^4 = Y^2 + Y.
        return E384(d0 ^ d3, d1 ^ d3 ^ d4, d2 ^ d4)

    def pow(self, exponent: int) -> "E384":
        if exponent < 0:
            raise ValueError("E384 exponent must be nonnegative")
        result = E384.one()
        base = self
        while exponent:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result

    def inverse(self) -> "E384":
        if self == E384.zero():
            raise ZeroDivisionError("zero has no E384 inverse")
        # E384 is a field of size 2^384 once the cubic is irreducible.
        return self.pow((1 << (B128_BITS * 3)) - 2)

    def __truediv__(self, other: "E384") -> "E384":
        return self * other.inverse()


def _poly_add(left: Sequence[int], right: Sequence[int]) -> list[int]:
    length = max(len(left), len(right))
    result = [0] * length
    for index in range(length):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        result[index] = a ^ b
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result


def _poly_mul(left: Sequence[int], right: Sequence[int]) -> list[int]:
    result = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[i + j] ^= b128_mul(a, b)
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result


def _poly_divmod(numerator: Sequence[int], denominator: Sequence[int]) -> tuple[list[int], list[int]]:
    denominator = list(denominator)
    while len(denominator) > 1 and denominator[-1] == 0:
        denominator.pop()
    if not denominator or denominator[-1] == 0:
        raise ValueError("polynomial division by zero")
    remainder = list(numerator)
    quotient = [0] * max(1, (len(remainder) - len(denominator) + 1))
    # The only inverses needed by this degree-three irreducibility check are
    # leading coefficients, which are one for all polynomials we construct.
    if denominator[-1] != 1:
        raise ValueError("irreducibility helper expects monic polynomials")
    while len(remainder) >= len(denominator) and any(remainder):
        shift = len(remainder) - len(denominator)
        coefficient = remainder[-1]
        quotient[shift] = coefficient
        for index, value in enumerate(denominator):
            remainder[index + shift] ^= b128_mul(coefficient, value)
        while len(remainder) > 1 and remainder[-1] == 0:
            remainder.pop()
    while len(quotient) > 1 and quotient[-1] == 0:
        quotient.pop()
    return quotient, remainder


def _poly_mod(numerator: Sequence[int], denominator: Sequence[int]) -> list[int]:
    return _poly_divmod(numerator, denominator)[1]


def _poly_gcd(left: Sequence[int], right: Sequence[int]) -> list[int]:
    a, b = list(left), list(right)
    while any(b):
        a, b = b, _poly_mod(a, b)
    if not any(a):
        return [0]
    # All polynomials in this check are monic, so no field inversion is needed.
    scale = a[-1]
    if scale == 1:
        return a
    raise ValueError("non-monic polynomial gcd is outside the tiny checker")


def _poly_pow_x(exponent: int, modulus: Sequence[int]) -> list[int]:
    result = [1]
    base = [0, 1]
    while exponent:
        if exponent & 1:
            result = _poly_mod(_poly_mul(result, base), modulus)
        base = _poly_mod(_poly_mul(base, base), modulus)
        exponent >>= 1
    return result


def e384_cubic_is_irreducible() -> bool:
    """Check the cubic's no-root condition over B128.

    A cubic over a field is irreducible exactly when it has no root.  The
    standard finite-field test checks gcd(f, Y^q - Y) = 1 for q=2^128.
    Characteristic two turns subtraction into XOR, so the executable test
    uses ``Y^q + Y``.
    """

    modulus = [1, 1, 0, 1]  # Y^3 + Y + 1
    frobenius = _poly_pow_x(1 << B128_BITS, modulus)
    return _poly_gcd(modulus, _poly_add(frobenius, [0, 1])) == [1]


def product_ring_zero_divisor_counterexample() -> bool:
    """Independent B128 coordinates form a product ring, not E384."""

    left = (1, 0, 0)
    right = (0, 1, 0)
    return tuple(a * b for a, b in zip(left, right)) == (0, 0, 0)


# ---------------------------------------------------------------------------
# Source-bound full-M4 relation inventory (no circuit build)


@dataclass(frozen=True)
class M4ConstraintInventory:
    """Frozen source facts and explicit uncompiled boundaries.

    The full M4 Rust source has 83 Keccak-f calls. Each permutation contains
    24*5*5*64 chi BitAnd constraints, so the nonlinear inventory is exactly
    3,187,200. The Python artifact exercises representative BitAnd/shift and
    canonical public-transport checks, but it intentionally does not pretend
    that those probes execute all dynamic CircuitBuilder gates.
    """

    source_revision: str
    public_bytes: int
    statement_words: int
    derived_intent_words: int
    public_words: int
    private_words: int
    input_words: int
    output_words: int
    auth_words: int
    keccak_permutations: int
    bitand_per_keccak: int
    bitand_constraints: int
    static_shift_call_sites: int
    static_public_assert_call_sites: int
    transport_b128_symbols: int
    active_trace_symbols_assumption: int
    active_trace_symbols_frozen: bool
    full_constraint_evaluation: bool
    relation_soundness_theorem: bool


def m4_constraint_inventory() -> M4ConstraintInventory:
    return M4ConstraintInventory(
        source_revision=M4_SOURCE_REVISION,
        public_bytes=M4_PUBLIC_BYTES,
        statement_words=M4_STATEMENT_WORDS,
        derived_intent_words=M4_DERIVED_INTENT_WORDS,
        public_words=M4_PUBLIC_WORDS,
        private_words=M4_PRIVATE_WORDS,
        input_words=M4_INPUT_WORDS,
        output_words=M4_OUTPUT_WORDS,
        auth_words=M4_AUTH_WORDS,
        keccak_permutations=M4_KECCAK_PERMUTATIONS,
        bitand_per_keccak=M4_KECCAK_BITAND_PERMUTATION,
        bitand_constraints=M4_KECCAK_BITAND_CONSTRAINTS,
        static_shift_call_sites=M4_STATIC_SHIFT_CALL_SITES,
        static_public_assert_call_sites=M4_STATIC_PUBLIC_ASSERT_CALL_SITES,
        transport_b128_symbols=M4_TRANSPORT_B128_SYMBOLS,
        active_trace_symbols_assumption=M4_ACTIVE_TRACE_SYMBOLS_ASSUMPTION,
        active_trace_symbols_frozen=False,
        full_constraint_evaluation=False,
        relation_soundness_theorem=False,
    )


def m4_pack_u64_words(words: Sequence[int]) -> tuple[int, ...]:
    """Pack the frozen 671 little-endian M4 words two-at-a-time into B128."""

    if len(words) != M4_PRIVATE_WORDS:
        raise ValueError("full-M4 private transport must contain 671 u64 words")
    for word in words:
        if not 0 <= word < (1 << 64):
            raise ValueError("M4 private words must be canonical u64 values")
    packed: list[int] = []
    for index in range(0, len(words), 2):
        high = words[index + 1] if index + 1 < len(words) else 0
        packed.append(words[index] | (high << 64))
    if len(packed) != M4_TRANSPORT_B128_SYMBOLS:
        raise AssertionError("M4 transport packing count drift")
    return tuple(packed)


def m4_unpack_public_words(statement: bytes, derived_intent: Sequence[int]) -> tuple[int, ...]:
    """Decode the exact 853-byte statement plus seven derived intent words."""

    if len(statement) != M4_PUBLIC_BYTES:
        raise ValueError("M4 canonical statement is exactly 853 bytes")
    if len(derived_intent) != M4_DERIVED_INTENT_WORDS:
        raise ValueError("M4 derived intent must contain exactly seven words")
    words = [
        int.from_bytes(statement[index : index + 8].ljust(8, b"\x00"), "little")
        for index in range(0, M4_PUBLIC_BYTES, 8)
    ]
    if len(words) != M4_STATEMENT_WORDS:
        raise AssertionError("M4 statement word count drift")
    # The source asserts the unused high 24 bits of the final five-byte word.
    if words[-1] >> (8 * (M4_PUBLIC_BYTES % 8)):
        raise ValueError("nonzero high padding in the final M4 statement word")
    if any(not 0 <= word < (1 << 64) for word in derived_intent):
        raise ValueError("derived intent words must be canonical u64 values")
    return tuple(words) + tuple(derived_intent)


def m4_bitand_holds(left: int, right: int, result: int) -> bool:
    """Executable u64 BitAnd gate used by the frozen M4 source."""

    return (
        0 <= left < (1 << 64)
        and 0 <= right < (1 << 64)
        and 0 <= result < (1 << 64)
        and result == (left & right)
    )


def m4_masked_bitand_cross_terms(
    left: int, right: int, left_mask: int, right_mask: int
) -> tuple[int, int, int]:
    """Return the three Boolean cross terms needed after XOR masking."""

    words = (left, right, left_mask, right_mask)
    if any(not 0 <= word < (1 << 64) for word in words):
        raise ValueError("masked M4 BitAnd operands must be canonical u64 values")
    return left & right_mask, left_mask & right, left_mask & right_mask


def m4_masked_bitand_holds(
    left: int,
    right: int,
    result: int,
    left_mask: int,
    right_mask: int,
    masked_result: int,
) -> bool:
    """Check the explicit nonlinear cross-term expansion for a masked AND."""

    if not m4_bitand_holds(left, right, result):
        return False
    if not 0 <= masked_result < (1 << 64):
        return False
    first, second, third = m4_masked_bitand_cross_terms(
        left, right, left_mask, right_mask
    )
    return masked_result == result ^ first ^ second ^ third


def m4_shift_holds(value: int, shift: int, result: int, direction: str) -> bool:
    """Executable logical u64 shift gate used by M4 packing/position paths."""

    if not 0 <= value < (1 << 64) or not 0 <= result < (1 << 64):
        return False
    if not 0 <= shift < 64:
        return False
    if direction == "left":
        return result == ((value << shift) & ((1 << 64) - 1))
    if direction == "right":
        return result == (value >> shift)
    return False


@dataclass(frozen=True)
class M4RelationTranscript:
    """Source-bound transcript metadata, not a full M4 proof."""

    public_words: tuple[int, ...]
    private_transport_symbols: tuple[int, ...]
    relation_digest: bytes
    bitand_samples_checked: int
    shift_samples_checked: int
    bitand_samples_valid: bool
    shift_samples_valid: bool
    canonical_public_transport: bool
    full_constraint_evaluation: bool
    relation_soundness_theorem: bool


def m4_source_bound_transcript(
    statement: bytes,
    derived_intent: Sequence[int],
    private_words: Sequence[int],
    *,
    bitand_samples: Sequence[tuple[int, int, int]] = (),
    shift_samples: Sequence[tuple[int, int, int, str]] = (),
) -> M4RelationTranscript:
    """Build a tiny source-bound M4 transcript without allocating a trace.

    The digest binds the exact public transport and private u64 witness
    layout. Optional samples execute the same BitAnd and shift primitives
    named by the Rust source. This is deliberately an inventory/probe: it is
    not a substitute for the 83-permutation CircuitBuilder execution.
    """

    public_words = m4_unpack_public_words(statement, derived_intent)
    packed = m4_pack_u64_words(private_words)
    bitand_ok = all(m4_bitand_holds(*sample) for sample in bitand_samples)
    shift_ok = all(m4_shift_holds(*sample) for sample in shift_samples)
    relation_digest = shake448(
        M4_RELATION_ID,
        M4_SOURCE_REVISION.encode("ascii"),
        statement,
        b"".join(word.to_bytes(8, "little") for word in derived_intent),
        b"".join(word.to_bytes(8, "little") for word in private_words),
    )
    return M4RelationTranscript(
        public_words=public_words,
        private_transport_symbols=packed,
        relation_digest=relation_digest,
        bitand_samples_checked=len(bitand_samples),
        shift_samples_checked=len(shift_samples),
        bitand_samples_valid=bitand_ok,
        shift_samples_valid=shift_ok,
        canonical_public_transport=True,
        full_constraint_evaluation=False,
        relation_soundness_theorem=False,
    )


# ---------------------------------------------------------------------------
# SHAKE transcript and strict query budget


class Transcript:
    def __init__(self) -> None:
        self.state = shake512(b"HVBPCS/transcript/init/v1")

    def observe(self, label: bytes, value: bytes) -> None:
        self.state = shake512(b"HVBPCS/transcript/observe/v1", self.state, label, value)

    def challenge_e384(self, label: bytes) -> E384:
        full = shake512(b"HVBPCS/transcript/challenge/v1", self.state, label)
        value = E384.from_bytes(full[:E384_BYTES])
        # Observe all 512 bits, not only the 384-bit projection.
        self.observe(b"challenge/" + label, full)
        return value

    def distinct_indices(self, label: bytes, count: int, upper: int) -> tuple[int, ...]:
        if not 0 <= count <= upper or not 0 < upper < (1 << 32):
            raise ValueError("invalid query geometry")
        selected: list[int] = []
        seen: set[int] = set()
        rejection_limit = (1 << 64) - ((1 << 64) % upper)
        counter = 0
        while len(selected) < count:
            full = shake512(
                b"HVBPCS/transcript/query/v1",
                self.state,
                label,
                counter.to_bytes(8, "big"),
            )
            counter += 1
            candidate = int.from_bytes(full[:8], "big")
            if candidate >= rejection_limit:
                continue
            index = candidate % upper
            if index not in seen:
                seen.add(index)
                selected.append(index)
        encoded = b"".join(index.to_bytes(4, "big") for index in selected)
        self.observe(b"queries/" + label, encoded)
        return tuple(selected)


def query_bits(log_inv_rate: int, eta: float = JOHNSON_ETA) -> float:
    rho_sqrt = math.exp2(-log_inv_rate / 2)
    if not 0 < eta < 1 - rho_sqrt:
        raise ValueError("eta must be inside the Johnson radius")
    return -math.log2(rho_sqrt + eta)


def strict_query_count(
    target_bits: int = STRICT_CLASSICAL_BITS,
    log_inv_rate: int = LOG_INV_RATE,
    eta: float = JOHNSON_ETA,
) -> int:
    return math.ceil(target_bits / query_bits(log_inv_rate, eta))


def _strict_query_budget() -> dict[str, object]:
    per_query = query_bits(LOG_INV_RATE)
    count = strict_query_count()
    return {
        "target_bits": STRICT_CLASSICAL_BITS,
        "log_inv_rate": LOG_INV_RATE,
        "eta": "1/256",
        "per_query_bits": per_query,
        "q": count,
        "query_term_bits": count * per_query,
        "meets_264_classical_query_term": count * per_query >= STRICT_CLASSICAL_BITS,
        "composition_proved": False,
    }


# ---------------------------------------------------------------------------
# Exact vector geometry and canonical Merkle opening


@functools.lru_cache(maxsize=None)
def max_frontier_nodes(log_leaves: int, opened: int) -> int:
    """Exact maximum compact Merkle frontier for a complete binary tree."""

    if log_leaves < 0 or opened < 0 or opened > (1 << log_leaves):
        raise ValueError("invalid Merkle geometry")
    if opened == 0 or (log_leaves == 0 and opened == 1):
        return 0
    if log_leaves == 0:
        raise ValueError("invalid Merkle geometry")
    child_capacity = 1 << (log_leaves - 1)
    best = -1
    left_min = max(0, opened - child_capacity)
    left_max = min(opened, child_capacity)
    for left in range(left_min, left_max + 1):
        right = opened - left
        if left == 0:
            candidate = 1 + max_frontier_nodes(log_leaves - 1, right)
        elif right == 0:
            candidate = 1 + max_frontier_nodes(log_leaves - 1, left)
        else:
            candidate = max_frontier_nodes(log_leaves - 1, left) + max_frontier_nodes(
                log_leaves - 1, right
            )
        best = max(best, candidate)
    return best


@dataclass(frozen=True)
class PCSParams:
    log_relation_size: int
    active_symbols: int
    fold_variables: int
    log_inv_rate: int
    query_count: int
    security_bits: int

    def __post_init__(self) -> None:
        if not 1 <= self.log_relation_size <= 31:
            raise ValueError("invalid relation dimension")
        if not 0 < self.active_symbols <= (1 << self.log_relation_size):
            raise ValueError("active symbols exceed relation bucket")
        if not 1 <= self.fold_variables <= self.log_relation_size:
            raise ValueError("invalid fold dimension")
        if not 1 <= self.log_inv_rate <= 31:
            raise ValueError("invalid inverse-rate logarithm")
        if not 1 <= self.query_count <= self.codeword_leaves:
            raise ValueError("invalid query count")
        if not 1 <= self.security_bits <= 65535:
            raise ValueError("invalid security target")
        if self.frontier_nodes >= (1 << 16):
            raise ValueError("frontier does not fit canonical header")

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
    def log_codeword_leaves(self) -> int:
        return self.residual_variables + self.log_inv_rate

    @property
    def codeword_leaves(self) -> int:
        return 1 << self.log_codeword_leaves

    @property
    def frontier_nodes(self) -> int:
        return max_frontier_nodes(self.log_codeword_leaves, self.query_count)

    @property
    def profile_id(self) -> bytes:
        material = struct.pack(
            ">6I",
            self.log_relation_size,
            self.active_symbols,
            self.fold_variables,
            self.log_inv_rate,
            self.query_count,
            self.security_bits,
        )
        return shake512(
            b"HVBPCS/profile/v1|B128-ghash|E384-Y3+Y+1|SHAKE256-512",
            material,
        )[:32]

    def header(self, flags: int = 0) -> bytes:
        if not 0 <= flags <= 65535:
            raise ValueError("header flags exceed canonical u16")
        encoded = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            flags,
            self.profile_id,
            self.log_relation_size,
            self.fold_variables,
            self.log_inv_rate,
            B128_BYTES,
            self.query_count,
            self.lanes,
            self.log_codeword_leaves,
            self.frontier_nodes,
            self.active_symbols,
            self.security_bits,
        )
        if len(encoded) != HEADER_BYTES:
            raise AssertionError("header size drift")
        return encoded

    @property
    def opened_symbol_bytes(self) -> int:
        return self.query_count * self.lanes * B128_BYTES

    @property
    def authentication_bytes(self) -> int:
        return self.frontier_nodes * DIGEST_BYTES

    @property
    def vector_opening_bytes(self) -> int:
        return HEADER_BYTES + DIGEST_BYTES + self.opened_symbol_bytes + self.authentication_bytes

    @property
    def encoded_oracle_bytes(self) -> int:
        return self.codeword_leaves * self.lanes * B128_BYTES


def toy_params() -> PCSParams:
    return PCSParams(
        log_relation_size=6,
        active_symbols=48,
        fold_variables=2,
        log_inv_rate=2,
        query_count=4,
        security_bits=8,
    )


def strict_params() -> PCSParams:
    count = strict_query_count()
    if count != STRICT_QUERY_COUNT:
        raise AssertionError("strict q regression")
    return PCSParams(
        log_relation_size=STRICT_LOG_RELATION_SIZE,
        active_symbols=STRICT_ACTIVE_SYMBOLS,
        fold_variables=STRICT_FOLD_VARIABLES,
        log_inv_rate=LOG_INV_RATE,
        query_count=count,
        security_bits=STRICT_CLASSICAL_BITS,
    )


def _rs_evaluate(coefficients: Sequence[int], point: int) -> int:
    accumulator = 0
    for coefficient in reversed(coefficients):
        accumulator = b128_mul(accumulator, point) ^ b128(coefficient)
    return accumulator


def _encode_source(source: Sequence[int], params: PCSParams) -> list[tuple[int, ...]]:
    expected = 1 << params.log_relation_size
    if len(source) != expected:
        raise ValueError("source length does not match relation bucket")
    if any(value != 0 for value in source[params.active_symbols :]):
        raise ValueError("inactive symbols must be canonical zero padding")
    rows = [
        [
            b128(source[lane + params.lanes * column])
            for column in range(params.message_columns)
        ]
        for lane in range(params.lanes)
    ]
    columns: list[tuple[int, ...]] = []
    for column_index in range(params.codeword_leaves):
        point = column_index + 1
        columns.append(tuple(_rs_evaluate(row, point) for row in rows))
    return columns


def _leaf_bytes(row: Sequence[int]) -> bytes:
    return b"".join(b128_to_bytes(value) for value in row)


def _leaf_hash(index: int, row: Sequence[int]) -> bytes:
    return shake512(
        b"HVBPCS/merkle/leaf/v1",
        index.to_bytes(4, "big"),
        _leaf_bytes(row),
    )


def _node_hash(left: bytes, right: bytes) -> bytes:
    _check_digest(left)
    _check_digest(right)
    return shake512(b"HVBPCS/merkle/node/v1", left, right)


def _merkle_levels(columns: Sequence[Sequence[int]]) -> list[list[bytes]]:
    if not columns or len(columns) & (len(columns) - 1):
        raise ValueError("Merkle leaves must be a nonzero power of two")
    levels = [[_leaf_hash(index, row) for index, row in enumerate(columns)]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [
                _node_hash(current[index], current[index + 1])
                for index in range(0, len(current), 2)
            ]
        )
    return levels


# ---------------------------------------------------------------------------
# Joint [pi || omega] E384-mask toy (SHAKE256-448 Merkle nodes)


JOINT_MASK_FLAGS = 11


def joint_mask_row_width(params: PCSParams) -> int:
    """B128 row width for two E384-valued dimensions, [pi || omega]."""

    return params.lanes * M4_MASK_SHARE_DIMENSIONS * M4_E384_MASK_COORDINATES


def _joint_leaf_bytes(row: Sequence[int]) -> bytes:
    return b"".join(b128_to_bytes(value) for value in row)


def _joint_leaf_hash(index: int, row: Sequence[int]) -> bytes:
    return shake448(
        b"HVBPCS/joint-merkle/leaf/v1",
        index.to_bytes(4, "big"),
        _joint_leaf_bytes(row),
    )


def _joint_node_hash(left: bytes, right: bytes) -> bytes:
    _check_merkle_digest(left)
    _check_merkle_digest(right)
    return shake448(b"HVBPCS/joint-merkle/node/v1", left, right)


def _joint_merkle_levels(columns: Sequence[Sequence[int]]) -> list[list[bytes]]:
    if not columns or len(columns) & (len(columns) - 1):
        raise ValueError("joint Merkle leaves must be a nonzero power of two")
    width = len(columns[0])
    if width <= 0 or any(len(row) != width for row in columns):
        raise ValueError("joint Merkle row widths must be constant")
    levels = [[_joint_leaf_hash(index, row) for index, row in enumerate(columns)]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [
                _joint_node_hash(current[index], current[index + 1])
                for index in range(0, len(current), 2)
            ]
        )
    return levels


def _joint_padding_hash(
    params: PCSParams,
    root: bytes,
    query_digest: bytes,
    actual_count: int,
    position: int,
) -> bytes:
    return shake448(
        b"HVBPCS/joint-merkle/padding/v1",
        params.profile_id,
        root,
        query_digest,
        actual_count.to_bytes(4, "big"),
        position.to_bytes(4, "big"),
    )


def _joint_query_digest(params: PCSParams, queries: Sequence[int]) -> bytes:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("joint queries must be distinct and sorted")
    return shake512(
        b"HVBPCS/joint-merkle/query-set/v1",
        params.profile_id,
        b"".join(index.to_bytes(4, "big") for index in queries),
    )


def _joint_compact_frontier(
    levels: Sequence[Sequence[bytes]], queries: Sequence[int], params: PCSParams
) -> tuple[bytes, ...]:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("joint queries must be distinct and sorted")
    current = set(queries)
    frontier: list[bytes] = []
    for level in levels[:-1]:
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                frontier.append(level[sibling])
        current = {index >> 1 for index in current}
    if len(frontier) > params.frontier_nodes:
        raise AssertionError("joint frontier exceeded exact maximum")
    root = levels[-1][0]
    query_digest = _joint_query_digest(params, queries)
    actual_count = len(frontier)
    while len(frontier) < params.frontier_nodes:
        frontier.append(
            _joint_padding_hash(params, root, query_digest, actual_count, len(frontier))
        )
    return tuple(frontier)


def _joint_verify_frontier(
    root: bytes,
    queries: Sequence[int],
    rows: Sequence[Sequence[int]],
    frontier: Sequence[bytes],
    params: PCSParams,
) -> bool:
    if (
        len(queries) != len(rows)
        or tuple(queries) != tuple(sorted(set(queries)))
        or len(frontier) != params.frontier_nodes
        or any(len(row) != joint_mask_row_width(params) for row in rows)
    ):
        return False
    _check_merkle_digest(root)
    if any(len(node) != MERKLE_DIGEST_BYTES for node in frontier):
        return False
    current = {
        index: _joint_leaf_hash(index, row)
        for index, row in zip(queries, rows)
    }
    cursor = 0
    for _ in range(params.log_codeword_leaves):
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
            next_level[parent] = _joint_node_hash(left, right)
            processed.add(parent)
        current = next_level
    if current.get(0) != root:
        return False
    query_digest = _joint_query_digest(params, queries)
    actual_count = cursor
    return all(
        frontier[position]
        == _joint_padding_hash(params, root, query_digest, actual_count, position)
        for position in range(cursor, len(frontier))
    )


def _e384_triplet(row: Sequence[int], offset: int) -> E384:
    return E384(row[offset], row[offset + 1], row[offset + 2])


def _joint_affine_pi_prime(pi: E384, omega: E384, gamma: E384) -> E384:
    # Characteristic two: 1-gamma == 1+gamma.
    return (E384.one() + gamma) * pi + gamma * omega


def _joint_linear_eval(
    queries: Sequence[int], rows: Sequence[Sequence[int]], params: PCSParams, share: int
) -> E384:
    """A tiny transparent E384 linear functional for the toy relation claim."""

    result = E384.zero()
    share_offset = share * params.lanes * M4_E384_MASK_COORDINATES
    for query, row in zip(queries, rows):
        value = _e384_triplet(row, share_offset)
        weight = E384.from_bytes(
            shake512(
                b"HVBPCS/joint-linear-functional/v1",
                params.profile_id,
                query.to_bytes(4, "big"),
            )[:E384_BYTES]
        )
        result = result + weight * value
    return result


def _joint_mask_columns(
    source_columns: Sequence[Sequence[int]], params: PCSParams, coins: bytes
) -> list[tuple[int, ...]]:
    _validate_coins(coins)
    result: list[tuple[int, ...]] = []
    for column, source_row in enumerate(source_columns):
        if len(source_row) != params.lanes:
            raise ValueError("joint source row width mismatch")
        row: list[int] = []
        for lane in range(params.lanes):
            for coordinate in range(M4_E384_MASK_COORDINATES):
                row.append(
                    b128_from_bytes(
                        shake512(
                            b"HVBPCS/joint-mask/omega/v1",
                            coins,
                            column.to_bytes(4, "big"),
                            lane.to_bytes(2, "big"),
                            coordinate.to_bytes(1, "big"),
                        )[:B128_BYTES]
                    )
                )
        result.append(tuple(row))
    return result


def _joint_source_columns(
    source_columns: Sequence[Sequence[int]], params: PCSParams
) -> list[tuple[int, ...]]:
    result: list[tuple[int, ...]] = []
    for source_row in source_columns:
        if len(source_row) != params.lanes:
            raise ValueError("joint source row width mismatch")
        # The toy source is B128-valued; it is embedded in c0 and has explicit
        # zero c1/c2 coefficients. Production M4 must commit all three lanes.
        row: list[int] = []
        for value in source_row:
            row.extend((b128(value), 0, 0))
        result.append(tuple(row))
    return result


def _joint_transcript(
    params: PCSParams, public_context: bytes, root: bytes
) -> tuple[tuple[int, ...], E384]:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    _check_merkle_digest(root)
    transcript = Transcript()
    transcript.observe(b"joint/profile", params.profile_id)
    transcript.observe(b"joint/relation", M4_RELATION_ID)
    transcript.observe(b"joint/context", public_context)
    transcript.observe(b"joint/root-448", root)
    candidates = tuple(
        transcript.challenge_e384(
            b"joint/gamma/" + index.to_bytes(1, "big")
        )
        for index in range(M4_GAMMA_CANDIDATES)
    )
    gamma = next((candidate for candidate in candidates if candidate != E384.zero()), None)
    if gamma is None:
        raise ValueError("all E384 gamma candidates were zero")
    queries = tuple(
        sorted(
            transcript.distinct_indices(
                b"joint-columns", params.query_count, params.codeword_leaves
            )
        )
    )
    return queries, gamma


def joint_mask_toy_wire_bytes(params: PCSParams) -> int:
    return (
        HEADER_BYTES
        + 2 * E384_BYTES  # alpha and sigma
        + MERKLE_DIGEST_BYTES
        + params.query_count * joint_mask_row_width(params) * B128_BYTES
        + params.frontier_nodes * MERKLE_DIGEST_BYTES
    )


@dataclass(frozen=True)
class JointMaskProof:
    """Canonical toy opening of a joint [pi || omega] commitment.

    The two E384 fields model alpha=<pi',T> and sigma=<omega,T>. They prove
    only a linear relation claim in this toy. No BitAnd/Keccak relation is
    accepted by this verifier; that missing nonlinear compiler is explicit.
    """

    alpha: E384
    sigma: E384
    root: bytes
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]

    def serialize(self, params: PCSParams) -> bytes:
        if len(self.opened_rows) != params.query_count or any(
            len(row) != joint_mask_row_width(params) for row in self.opened_rows
        ):
            raise ValueError("joint opened-row geometry mismatch")
        _check_merkle_digest(self.root)
        if len(self.frontier) != params.frontier_nodes or any(
            len(node) != MERKLE_DIGEST_BYTES for node in self.frontier
        ):
            raise ValueError("joint frontier geometry mismatch")
        encoded = bytearray(params.header(JOINT_MASK_FLAGS))
        encoded.extend(self.alpha.to_bytes())
        encoded.extend(self.sigma.to_bytes())
        encoded.extend(self.root)
        for row in self.opened_rows:
            encoded.extend(_joint_leaf_bytes(row))
        encoded.extend(b"".join(self.frontier))
        if len(encoded) != joint_mask_toy_wire_bytes(params):
            raise AssertionError("joint serializer disagrees with exact byte count")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: PCSParams) -> "JointMaskProof":
        if len(encoded) != joint_mask_toy_wire_bytes(params):
            raise ValueError("joint proof length is not canonical")
        if encoded[:HEADER_BYTES] != params.header(JOINT_MASK_FLAGS):
            raise ValueError("wrong joint profile, flags, or header geometry")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated joint proof")
            value = encoded[cursor:end]
            cursor = end
            return value

        alpha = E384.from_bytes(take(E384_BYTES))
        sigma = E384.from_bytes(take(E384_BYTES))
        root = _check_merkle_digest(take(MERKLE_DIGEST_BYTES))
        rows = tuple(
            tuple(
                b128_from_bytes(take(B128_BYTES))
                for _ in range(joint_mask_row_width(params))
            )
            for _ in range(params.query_count)
        )
        frontier = tuple(
            take(MERKLE_DIGEST_BYTES) for _ in range(params.frontier_nodes)
        )
        if cursor != len(encoded):
            raise ValueError("trailing joint proof bytes")
        return cls(alpha, sigma, root, rows, frontier)


def prove_joint_mask_toy(
    source: Sequence[int], params: PCSParams, public_context: bytes, coins: bytes
) -> bytes:
    """Prove the zero linear claim for an all-zero toy source."""

    if any(source):
        raise ValueError("joint toy uses the zero public linear-claim witness")
    source_columns = _encode_source(source, params)
    pi_columns = _joint_source_columns(source_columns, params)
    omega_columns = _joint_mask_columns(source_columns, params, coins)
    columns = [pi + omega for pi, omega in zip(pi_columns, omega_columns)]
    levels = _joint_merkle_levels(columns)
    root = levels[-1][0]
    queries, gamma = _joint_transcript(params, public_context, root)
    rows = tuple(columns[index] for index in queries)
    alpha = E384.zero()
    sigma = _joint_linear_eval(queries, rows, params, 1)
    # For the zero pi claim, alpha=<pi',T>=gamma*<omega,T>.
    alpha = gamma * sigma
    return JointMaskProof(
        alpha, sigma, root, rows, _joint_compact_frontier(levels, queries, params)
    ).serialize(params)


def verify_joint_mask_toy(
    encoded: bytes, params: PCSParams, public_context: bytes
) -> bool:
    try:
        proof = JointMaskProof.parse(encoded, params)
        queries, gamma = _joint_transcript(params, public_context, proof.root)
        if gamma == E384.zero():
            return False
        if not _joint_verify_frontier(
            proof.root, queries, proof.opened_rows, proof.frontier, params
        ):
            return False
        sigma = _joint_linear_eval(queries, proof.opened_rows, params, 1)
        # This is the masked linear claim only. The full M4 nonlinear relation
        # is deliberately not checked by this toy verifier.
        return proof.sigma == sigma and proof.alpha == gamma * sigma
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


def _query_digest(params: PCSParams, queries: Sequence[int]) -> bytes:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("queries must be distinct and sorted")
    return shake512(
        b"HVBPCS/merkle/query-set/v1",
        params.profile_id,
        b"".join(index.to_bytes(4, "big") for index in queries),
    )


def _padding_hash(
    params: PCSParams,
    root: bytes,
    query_digest: bytes,
    actual_count: int,
    position: int,
) -> bytes:
    return shake512(
        b"HVBPCS/merkle/padding/v1",
        params.profile_id,
        root,
        query_digest,
        actual_count.to_bytes(4, "big"),
        position.to_bytes(4, "big"),
    )


def _compact_frontier(
    levels: Sequence[Sequence[bytes]], queries: Sequence[int], params: PCSParams
) -> tuple[bytes, ...]:
    if tuple(queries) != tuple(sorted(set(queries))):
        raise ValueError("queries must be distinct and sorted")
    current = set(queries)
    frontier: list[bytes] = []
    for level in levels[:-1]:
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                frontier.append(level[sibling])
        current = {index >> 1 for index in current}
    if len(frontier) > params.frontier_nodes:
        raise AssertionError("frontier exceeded exact maximum")
    root = levels[-1][0]
    query_digest = _query_digest(params, queries)
    actual_count = len(frontier)
    while len(frontier) < params.frontier_nodes:
        frontier.append(
            _padding_hash(params, root, query_digest, actual_count, len(frontier))
        )
    return tuple(frontier)


def _verify_frontier(
    root: bytes,
    queries: Sequence[int],
    rows: Sequence[Sequence[int]],
    frontier: Sequence[bytes],
    params: PCSParams,
) -> bool:
    if (
        len(queries) != len(rows)
        or tuple(queries) != tuple(sorted(set(queries)))
        or len(frontier) != params.frontier_nodes
    ):
        return False
    current = {
        index: _leaf_hash(index, row)
        for index, row in zip(queries, rows)
    }
    cursor = 0
    for _ in range(params.log_codeword_leaves):
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
    query_digest = _query_digest(params, queries)
    actual_count = cursor
    for position in range(cursor, len(frontier)):
        if frontier[position] != _padding_hash(
            params, root, query_digest, actual_count, position
        ):
            return False
    return True


def _new_transcript(params: PCSParams, public_context: bytes, root: bytes) -> Transcript:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    _check_digest(root)
    transcript = Transcript()
    transcript.observe(b"profile", params.profile_id)
    transcript.observe(b"context", public_context)
    transcript.observe(b"root", root)
    # A real E384 challenge is part of the query schedule.  It is deliberately
    # consumed before the query indices; a triple of B128 values is rejected.
    transcript.challenge_e384(b"algebraic-opening-challenge")
    return transcript


@dataclass(frozen=True)
class MerkleVectorProof:
    root: bytes
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]

    def serialize(self, params: PCSParams) -> bytes:
        _check_digest(self.root)
        if len(self.opened_rows) != params.query_count or any(
            len(row) != params.lanes for row in self.opened_rows
        ):
            raise ValueError("opened-row geometry mismatch")
        if len(self.frontier) != params.frontier_nodes or any(
            len(node) != DIGEST_BYTES for node in self.frontier
        ):
            raise ValueError("frontier geometry mismatch")
        encoded = bytearray(params.header())
        encoded.extend(self.root)
        for row in self.opened_rows:
            encoded.extend(_leaf_bytes(row))
        for node in self.frontier:
            encoded.extend(node)
        if len(encoded) != params.vector_opening_bytes:
            raise AssertionError("serializer disagrees with exact vector byte count")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: PCSParams) -> "MerkleVectorProof":
        if len(encoded) != params.vector_opening_bytes:
            raise ValueError("proof length is not canonical")
        if encoded[:HEADER_BYTES] != params.header():
            raise ValueError("wrong profile, version, flags, or header geometry")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated proof")
            value = encoded[cursor:end]
            cursor = end
            return value

        root = _check_digest(take(DIGEST_BYTES))
        rows = tuple(
            tuple(
                b128_from_bytes(take(B128_BYTES))
                for _ in range(params.lanes)
            )
            for _ in range(params.query_count)
        )
        frontier = tuple(take(DIGEST_BYTES) for _ in range(params.frontier_nodes))
        if cursor != len(encoded):
            raise ValueError("trailing proof bytes")
        return cls(root, rows, frontier)


def prove(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> bytes:
    """Create the tiny non-ZK Merkle opening; production params are size-only."""

    columns = _encode_source(source, params)
    levels = _merkle_levels(columns)
    root = levels[-1][0]
    transcript = _new_transcript(params, public_context, root)
    queries = tuple(sorted(transcript.distinct_indices(
        b"columns", params.query_count, params.codeword_leaves
    )))
    opened = tuple(columns[index] for index in queries)
    frontier = _compact_frontier(levels, queries, params)
    return MerkleVectorProof(root, opened, frontier).serialize(params)


def verify(encoded: bytes, params: PCSParams, public_context: bytes) -> bool:
    try:
        proof = MerkleVectorProof.parse(encoded, params)
        transcript = _new_transcript(params, public_context, proof.root)
        queries = tuple(sorted(transcript.distinct_indices(
            b"columns", params.query_count, params.codeword_leaves
        )))
        return _verify_frontier(
            proof.root,
            queries,
            proof.opened_rows,
            proof.frontier,
            params,
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


SHARE_DIRECT_FLAGS = 2
SHARE_HIDDEN_FLAGS = 3


def share_wire_bytes(params: PCSParams, flags: int) -> int:
    """Exact two-share wire size; flags select direct or hidden opening."""

    if flags == SHARE_HIDDEN_FLAGS:
        return (
            HEADER_BYTES
            + 2 * DIGEST_BYTES
            + params.opened_symbol_bytes
            + params.authentication_bytes
        )
    if flags == SHARE_DIRECT_FLAGS:
        return (
            HEADER_BYTES
            + 2 * DIGEST_BYTES
            + 2 * params.opened_symbol_bytes
            + 2 * params.authentication_bytes
        )
    raise ValueError("unknown share-opening flags")


def _share_transcript(
    params: PCSParams,
    public_context: bytes,
    masked_root: bytes,
    mask_root: bytes,
) -> Transcript:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    _check_digest(masked_root)
    _check_digest(mask_root)
    transcript = Transcript()
    transcript.observe(b"share/profile", params.profile_id)
    transcript.observe(b"share/context", public_context)
    transcript.observe(b"share/masked-root", masked_root)
    transcript.observe(b"share/mask-root", mask_root)
    transcript.challenge_e384(b"share/algebraic-opening-challenge")
    return transcript


def _share_queries(
    params: PCSParams,
    public_context: bytes,
    masked_root: bytes,
    mask_root: bytes,
) -> tuple[int, ...]:
    transcript = _share_transcript(
        params, public_context, masked_root, mask_root
    )
    return tuple(
        sorted(
            transcript.distinct_indices(
                b"share-columns", params.query_count, params.codeword_leaves
            )
        )
    )


def _share_masks(
    params: PCSParams, public_context: bytes
) -> list[tuple[int, ...]]:
    """Derive toy masks; production code never calls this with n15 params."""

    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    return [
        tuple(
            int.from_bytes(
                shake512(
                    b"HVBPCS/share-mask/v1",
                    public_context,
                    column.to_bytes(4, "big"),
                    lane.to_bytes(2, "big"),
                )[:B128_BYTES],
                "little",
            )
            for lane in range(params.lanes)
        )
        for column in range(params.codeword_leaves)
    ]


def _share_material(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> tuple[
    list[tuple[int, ...]],
    list[tuple[int, ...]],
    list[list[bytes]],
    list[list[bytes]],
]:
    columns = _encode_source(source, params)
    masks = _share_masks(params, public_context)
    masked_columns = [
        tuple(value ^ mask for value, mask in zip(column, masks[index]))
        for index, column in enumerate(columns)
    ]
    return (
        columns,
        masked_columns,
        _merkle_levels(masked_columns),
        _merkle_levels(masks),
    )


@dataclass(frozen=True)
class ShareOpening:
    """Two-share SHAKE/Merkle opening control.

    The direct mode is binding under the hash assumption but exposes source
    rows after XOR reconstruction. The hidden mode sends only masked rows and
    a commitment root for the masks; it is hiding under fresh-mask idealization
    but is not a complete source opening because the mask values at queries are
    not authenticated to ``mask_root``.
    """

    flags: int
    masked_root: bytes
    mask_root: bytes
    masked_rows: tuple[tuple[int, ...], ...]
    mask_rows: tuple[tuple[int, ...], ...]
    masked_frontier: tuple[bytes, ...]
    mask_frontier: tuple[bytes, ...]

    def serialize(self, params: PCSParams) -> bytes:
        if self.flags not in (SHARE_DIRECT_FLAGS, SHARE_HIDDEN_FLAGS):
            raise ValueError("unknown share-opening flags")
        _check_digest(self.masked_root)
        _check_digest(self.mask_root)
        if len(self.masked_rows) != params.query_count or any(
            len(row) != params.lanes for row in self.masked_rows
        ):
            raise ValueError("masked-row geometry mismatch")
        if len(self.masked_frontier) != params.frontier_nodes or any(
            len(node) != DIGEST_BYTES for node in self.masked_frontier
        ):
            raise ValueError("masked-frontier geometry mismatch")
        direct = self.flags == SHARE_DIRECT_FLAGS
        if direct and (
            len(self.mask_rows) != params.query_count
            or any(len(row) != params.lanes for row in self.mask_rows)
            or len(self.mask_frontier) != params.frontier_nodes
            or any(len(node) != DIGEST_BYTES for node in self.mask_frontier)
        ):
            raise ValueError("direct mask-opening geometry mismatch")
        if not direct and (self.mask_rows or self.mask_frontier):
            raise ValueError("hidden opening must not serialize mask openings")
        encoded = bytearray(params.header(self.flags))
        encoded.extend(self.masked_root)
        encoded.extend(self.mask_root)
        for row in self.masked_rows:
            encoded.extend(_leaf_bytes(row))
        if direct:
            for row in self.mask_rows:
                encoded.extend(_leaf_bytes(row))
        for node in self.masked_frontier:
            encoded.extend(node)
        if direct:
            for node in self.mask_frontier:
                encoded.extend(node)
        expected = share_wire_bytes(params, self.flags)
        if len(encoded) != expected:
            raise AssertionError("share serializer disagrees with exact byte count")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: PCSParams) -> "ShareOpening":
        if len(encoded) < HEADER_BYTES:
            raise ValueError("truncated share opening header")
        flags = struct.unpack(">H", encoded[10:12])[0]
        if flags not in (SHARE_DIRECT_FLAGS, SHARE_HIDDEN_FLAGS):
            raise ValueError("unknown share-opening flags")
        expected = share_wire_bytes(params, flags)
        if len(encoded) != expected:
            raise ValueError("share opening length is not canonical")
        if encoded[:HEADER_BYTES] != params.header(flags):
            raise ValueError("wrong share profile or header")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated share opening")
            value = encoded[cursor:end]
            cursor = end
            return value

        masked_root = _check_digest(take(DIGEST_BYTES))
        mask_root = _check_digest(take(DIGEST_BYTES))
        masked_rows = tuple(
            tuple(b128_from_bytes(take(B128_BYTES)) for _ in range(params.lanes))
            for _ in range(params.query_count)
        )
        direct = flags == SHARE_DIRECT_FLAGS
        mask_rows = (
            tuple(
                tuple(b128_from_bytes(take(B128_BYTES)) for _ in range(params.lanes))
                for _ in range(params.query_count)
            )
            if direct
            else ()
        )
        masked_frontier = tuple(take(DIGEST_BYTES) for _ in range(params.frontier_nodes))
        mask_frontier = (
            tuple(take(DIGEST_BYTES) for _ in range(params.frontier_nodes))
            if direct
            else ()
        )
        if cursor != len(encoded):
            raise ValueError("trailing share-opening bytes")
        return cls(
            flags,
            masked_root,
            mask_root,
            masked_rows,
            mask_rows,
            masked_frontier,
            mask_frontier,
        )


def prove_share_direct(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> bytes:
    """Concrete binding two-share opening; source rows are recoverable."""

    columns, masked_columns, masked_levels, mask_levels = _share_material(
        source, params, public_context
    )
    masked_root = masked_levels[-1][0]
    mask_root = mask_levels[-1][0]
    queries = _share_queries(params, public_context, masked_root, mask_root)
    return ShareOpening(
        SHARE_DIRECT_FLAGS,
        masked_root,
        mask_root,
        tuple(masked_columns[index] for index in queries),
        tuple(
            tuple(columns[index][lane] ^ masked_columns[index][lane] for lane in range(params.lanes))
            for index in queries
        ),
        _compact_frontier(masked_levels, queries, params),
        _compact_frontier(mask_levels, queries, params),
    ).serialize(params)


def prove_share_hidden(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> bytes:
    """Concrete masked commitment opening without mask values.

    This authenticates the masked rows only. It is useful as a negative
    control: source hiding is present under fresh pads, but source-opening
    binding is absent because the queried masks are not opened to mask_root.
    """

    _, masked_columns, masked_levels, mask_levels = _share_material(
        source, params, public_context
    )
    masked_root = masked_levels[-1][0]
    mask_root = mask_levels[-1][0]
    queries = _share_queries(params, public_context, masked_root, mask_root)
    return ShareOpening(
        SHARE_HIDDEN_FLAGS,
        masked_root,
        mask_root,
        tuple(masked_columns[index] for index in queries),
        (),
        _compact_frontier(masked_levels, queries, params),
        (),
    ).serialize(params)


def _share_recovered_rows(proof: ShareOpening) -> tuple[tuple[int, ...], ...]:
    if proof.flags != SHARE_DIRECT_FLAGS:
        raise ValueError("hidden share opening has no recoverable source rows")
    return tuple(
        tuple(masked ^ mask for masked, mask in zip(masked_row, mask_row))
        for masked_row, mask_row in zip(proof.masked_rows, proof.mask_rows)
    )


def verify_share_direct(
    encoded: bytes, params: PCSParams, public_context: bytes
) -> bool:
    try:
        proof = ShareOpening.parse(encoded, params)
        if proof.flags != SHARE_DIRECT_FLAGS:
            return False
        queries = _share_queries(
            params, public_context, proof.masked_root, proof.mask_root
        )
        return _verify_frontier(
            proof.masked_root,
            queries,
            proof.masked_rows,
            proof.masked_frontier,
            params,
        ) and _verify_frontier(
            proof.mask_root,
            queries,
            proof.mask_rows,
            proof.mask_frontier,
            params,
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


def verify_share_hidden(
    encoded: bytes, params: PCSParams, public_context: bytes
) -> bool:
    try:
        proof = ShareOpening.parse(encoded, params)
        if proof.flags != SHARE_HIDDEN_FLAGS:
            return False
        queries = _share_queries(
            params, public_context, proof.masked_root, proof.mask_root
        )
        # Deliberately no mask-root opening is available. This checks the
        # masked commitment only and is not a source-vector opening verifier.
        return _verify_frontier(
            proof.masked_root,
            queries,
            proof.masked_rows,
            proof.masked_frontier,
            params,
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


def deterministic_source(params: PCSParams) -> tuple[int, ...]:
    values: list[int] = []
    for index in range(1 << params.log_relation_size):
        if index >= params.active_symbols:
            values.append(0)
        else:
            values.append(
                int.from_bytes(
                    shake512(
                        b"HVBPCS/toy-source/v1",
                        index.to_bytes(4, "big"),
                    )[:B128_BYTES],
                    "little",
                )
            )
    return tuple(values)


# ---------------------------------------------------------------------------
# In-place hiding toy: one relation-preserving low-degree mask, one root


def _validate_coins(coins: bytes, label: str = "coins") -> bytes:
    if len(coins) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes")
    return coins


def relation_holds_coefficients(
    source: Sequence[int], params: PCSParams
) -> bool:
    """Check the toy public relation on coefficient rows.

    The relation is deliberately small but nontrivial: lane zero and lane one
    are equal coefficient-by-coefficient, including canonical zero padding.
    Reed--Solomon evaluation preserves that equality at every codeword point.
    The other lanes are unconstrained.  This is the affine relation fiber in
    which the in-place one-time pad is sampled.
    """

    expected = 1 << params.log_relation_size
    if len(source) != expected:
        return False
    try:
        if any(b128(value) != value for value in source):
            return False
    except ValueError:
        return False
    if any(value != 0 for value in source[params.active_symbols :]):
        return False
    for column in range(params.message_columns):
        left_index = params.lanes * column
        right_index = left_index + 1
        if source[left_index] != source[right_index]:
            return False
    return True


def relation_holds_row(row: Sequence[int], params: PCSParams) -> bool:
    """Check the opened-codeword form of the same public relation."""

    if len(row) != params.lanes:
        return False
    try:
        return b128(row[0]) == b128(row[1])
    except (IndexError, ValueError):
        return False


def deterministic_relation_source(
    params: PCSParams, variant: int = 0
) -> tuple[int, ...]:
    """Make a relation-valid toy witness without allocating a production oracle."""

    if variant < 0:
        raise ValueError("relation-source variant must be nonnegative")
    variant_bytes = variant.to_bytes(8, "big")
    expected = 1 << params.log_relation_size
    values = [0] * expected
    for column in range(params.message_columns):
        right_index = 1 + params.lanes * column
        pair = (
            b128_from_bytes(
                shake512(
                    b"HVBPCS/in-place/relation-source/pair/v1",
                    variant_bytes,
                    column.to_bytes(4, "big"),
                )[:B128_BYTES]
            )
            if right_index < params.active_symbols
            else 0
        )
        for lane in range(params.lanes):
            index = lane + params.lanes * column
            if index >= params.active_symbols:
                continue
            if lane in (0, 1):
                values[index] = pair
            else:
                values[index] = b128_from_bytes(
                    shake512(
                        b"HVBPCS/in-place/relation-source/lane/v1",
                        variant_bytes,
                        column.to_bytes(4, "big"),
                        lane.to_bytes(2, "big"),
                    )[:B128_BYTES]
                )
    result = tuple(values)
    if not relation_holds_coefficients(result, params):
        raise AssertionError("deterministic relation source is not relation-valid")
    return result


def in_place_mask_coefficients(
    params: PCSParams, coins: bytes
) -> tuple[int, ...]:
    """Sample a relation-kernel mask over B128 coefficient rows.

    Each active lane-zero/lane-one pair receives the same fresh B128 value;
    other active lanes receive independent SHAKE-derived values.  Inactive
    coefficient padding is fixed to zero.  This is a source-free PRF model of
    a uniform mask in the toy relation kernel, and no mask value is serialized.
    """

    _validate_coins(coins)
    expected = 1 << params.log_relation_size
    values = [0] * expected
    for column in range(params.message_columns):
        left_index = params.lanes * column
        right_index = left_index + 1
        pair_is_active = right_index < params.active_symbols
        pair = (
            b128_from_bytes(
                shake512(
                    b"HVBPCS/in-place/mask/pair/v1",
                    coins,
                    column.to_bytes(4, "big"),
                )[:B128_BYTES]
            )
            if pair_is_active
            else 0
        )
        for lane in range(params.lanes):
            index = lane + params.lanes * column
            if index >= params.active_symbols:
                continue
            if lane in (0, 1):
                values[index] = pair
            else:
                values[index] = b128_from_bytes(
                    shake512(
                        b"HVBPCS/in-place/mask/lane/v1",
                        coins,
                        column.to_bytes(4, "big"),
                        lane.to_bytes(2, "big"),
                    )[:B128_BYTES]
                )
    result = tuple(values)
    if not relation_holds_coefficients(result, params):
        raise AssertionError("in-place mask escaped relation kernel")
    return result


def in_place_apply_mask(
    source: Sequence[int], mask: Sequence[int], params: PCSParams
) -> tuple[int, ...]:
    """Add a B128 (XOR) relation-kernel mask in coefficient space."""

    expected = 1 << params.log_relation_size
    if len(source) != expected or len(mask) != expected:
        raise ValueError("source and mask lengths do not match relation bucket")
    if not relation_holds_coefficients(source, params):
        raise ValueError("source does not satisfy the in-place public relation")
    if not relation_holds_coefficients(mask, params):
        raise ValueError("mask does not satisfy the in-place relation kernel")
    masked = tuple(b128(source[index]) ^ b128(mask[index]) for index in range(expected))
    if not relation_holds_coefficients(masked, params):
        raise AssertionError("relation was not preserved by in-place mask")
    return masked


def relabel_in_place_mask(
    source_a: Sequence[int],
    source_b: Sequence[int],
    mask_a: Sequence[int],
    params: PCSParams,
) -> tuple[int, ...]:
    """Apply the exact affine-fiber coupling ``r_b = r_a + x_a + x_b``."""

    expected = 1 << params.log_relation_size
    if len(source_a) != expected or len(source_b) != expected:
        raise ValueError("witness lengths do not match relation bucket")
    if not relation_holds_coefficients(source_a, params):
        raise ValueError("source_a does not satisfy the public relation")
    if not relation_holds_coefficients(source_b, params):
        raise ValueError("source_b does not satisfy the public relation")
    if not relation_holds_coefficients(mask_a, params):
        raise ValueError("mask_a does not satisfy the relation kernel")
    mask_b = tuple(
        b128(mask_a[index]) ^ b128(source_a[index]) ^ b128(source_b[index])
        for index in range(expected)
    )
    if not relation_holds_coefficients(mask_b, params):
        raise AssertionError("affine mask relabeling left relation kernel")
    if in_place_apply_mask(source_a, mask_a, params) != in_place_apply_mask(
        source_b, mask_b, params
    ):
        raise AssertionError("affine mask relabeling did not preserve masked vector")
    return mask_b


def _in_place_transcript(
    params: PCSParams, public_context: bytes, root: bytes
) -> tuple[Transcript, E384]:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    _check_digest(root)
    transcript = Transcript()
    transcript.observe(b"in-place/profile", params.profile_id)
    transcript.observe(b"in-place/relation", IN_PLACE_RELATION_ID)
    transcript.observe(b"in-place/context", public_context)
    transcript.observe(b"in-place/root", root)
    challenge = transcript.challenge_e384(b"in-place/algebraic-opening-challenge")
    return transcript, challenge


def _in_place_queries(
    params: PCSParams, public_context: bytes, root: bytes
) -> tuple[tuple[int, ...], E384]:
    transcript, challenge = _in_place_transcript(params, public_context, root)
    queries = tuple(
        sorted(
            transcript.distinct_indices(
                b"in-place-columns", params.query_count, params.codeword_leaves
            )
        )
    )
    return queries, challenge


def in_place_toy_wire_bytes(params: PCSParams) -> int:
    """Exact toy wire: header, one E384 claim, one root, rows, frontier."""

    return (
        HEADER_BYTES
        + IN_PLACE_TOY_CLAIM_ELEMENTS * E384_BYTES
        + DIGEST_BYTES
        + params.opened_symbol_bytes
        + params.authentication_bytes
    )


@dataclass(frozen=True)
class InPlaceZkProof:
    """One-root in-place relation opening for the allocated toy instance.

    The E384 claim is the public relation value (zero for ``lane0=lane1``).
    The random mask is in coefficient space and therefore changes the one
    committed codeword, but it contributes no separate root, row, or frontier
    on the wire.  Binding is to the masked relation fiber under SHAKE and the
    query soundness model; complete production soundness is not asserted.
    """

    algebraic_claim: E384
    root: bytes
    opened_rows: tuple[tuple[int, ...], ...]
    frontier: tuple[bytes, ...]

    def serialize(self, params: PCSParams) -> bytes:
        if self.algebraic_claim != E384.zero():
            raise ValueError("toy relation claim must be canonical E384 zero")
        _check_digest(self.root)
        if len(self.opened_rows) != params.query_count or any(
            len(row) != params.lanes for row in self.opened_rows
        ):
            raise ValueError("in-place opened-row geometry mismatch")
        if len(self.frontier) != params.frontier_nodes or any(
            len(node) != DIGEST_BYTES for node in self.frontier
        ):
            raise ValueError("in-place frontier geometry mismatch")
        encoded = bytearray(params.header(IN_PLACE_ZK_FLAGS))
        encoded.extend(self.algebraic_claim.to_bytes())
        encoded.extend(self.root)
        for row in self.opened_rows:
            encoded.extend(_leaf_bytes(row))
        for node in self.frontier:
            encoded.extend(node)
        if len(encoded) != in_place_toy_wire_bytes(params):
            raise AssertionError("in-place serializer disagrees with exact byte count")
        return bytes(encoded)

    @classmethod
    def parse(cls, encoded: bytes, params: PCSParams) -> "InPlaceZkProof":
        if len(encoded) != in_place_toy_wire_bytes(params):
            raise ValueError("in-place proof length is not canonical")
        if encoded[:HEADER_BYTES] != params.header(IN_PLACE_ZK_FLAGS):
            raise ValueError("wrong in-place profile, flags, or header geometry")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated in-place proof")
            value = encoded[cursor:end]
            cursor = end
            return value

        claim = E384.from_bytes(take(E384_BYTES))
        root = _check_digest(take(DIGEST_BYTES))
        rows = tuple(
            tuple(b128_from_bytes(take(B128_BYTES)) for _ in range(params.lanes))
            for _ in range(params.query_count)
        )
        frontier = tuple(take(DIGEST_BYTES) for _ in range(params.frontier_nodes))
        if cursor != len(encoded):
            raise ValueError("trailing in-place proof bytes")
        return cls(claim, root, rows, frontier)


def _prove_in_place_masked(
    masked_source: Sequence[int], params: PCSParams, public_context: bytes
) -> bytes:
    if not relation_holds_coefficients(masked_source, params):
        raise ValueError("masked source does not satisfy in-place relation")
    columns = _encode_source(masked_source, params)
    levels = _merkle_levels(columns)
    root = levels[-1][0]
    queries, _ = _in_place_queries(params, public_context, root)
    return InPlaceZkProof(
        E384.zero(),
        root,
        tuple(columns[index] for index in queries),
        _compact_frontier(levels, queries, params),
    ).serialize(params)


def in_place_commit(
    source: Sequence[int], params: PCSParams, public_context: bytes, coins: bytes
) -> bytes:
    """Return the one SHAKE Merkle commitment to ``source + mask``."""

    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    mask = in_place_mask_coefficients(params, _validate_coins(coins))
    masked_source = in_place_apply_mask(source, mask, params)
    columns = _encode_source(masked_source, params)
    return _merkle_levels(columns)[-1][0]


def prove_in_place(
    source: Sequence[int], params: PCSParams, public_context: bytes, coins: bytes
) -> bytes:
    """Prove the toy relation with a fresh mask inside one committed codeword."""

    mask = in_place_mask_coefficients(params, _validate_coins(coins))
    return _prove_in_place_masked(
        in_place_apply_mask(source, mask, params), params, public_context
    )


def prove_in_place_with_mask(
    source: Sequence[int],
    mask: Sequence[int],
    params: PCSParams,
    public_context: bytes,
) -> bytes:
    """Testing seam for the exact affine coupling; mask is not a wire field."""

    return _prove_in_place_masked(
        in_place_apply_mask(source, mask, params), params, public_context
    )


def verify_in_place(
    encoded: bytes, params: PCSParams, public_context: bytes
) -> bool:
    """Verify the one-root opening and its E384 relation claim."""

    try:
        proof = InPlaceZkProof.parse(encoded, params)
        if proof.algebraic_claim != E384.zero():
            return False
        queries, challenge = _in_place_queries(params, public_context, proof.root)
        if not _verify_frontier(
            proof.root,
            queries,
            proof.opened_rows,
            proof.frontier,
            params,
        ):
            return False
        for row in proof.opened_rows:
            if not relation_holds_row(row, params):
                return False
            discrepancy = E384.embed(row[0]) + E384.embed(row[1])
            if discrepancy != proof.algebraic_claim:
                return False
            # Consume the real E384 challenge in the relation check.  The raw
            # equality check above prevents the negligible challenge-zero
            # event from becoming a relation bypass in this toy verifier.
            if challenge * discrepancy != E384.zero():
                return False
        return True
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


@dataclass(frozen=True)
class InPlaceSimulation:
    """Executable source-free affine-fiber simulator result."""

    encoded: bytes
    source_independent: bool
    affine_fiber_sampler: bool
    complete_zk_theorem: bool
    qrom_composed: bool

    @property
    def wire_bytes(self) -> int:
        return len(self.encoded)


def simulate_in_place(
    params: PCSParams, public_context: bytes, simulator_coins: bytes
) -> InPlaceSimulation:
    """Simulate a masked proof without accepting any witness input.

    For relation-valid witnesses x and x', the bijection
    ``r' = r + x + x'`` maps masks in the kernel to masks in the kernel and
    preserves ``x+r = x'+r'``.  Sampling a fresh kernel element directly is
    therefore the uniform-fiber simulator in the idealized SHAKE-PRF mask
    model.  The finite 32-byte seed expansion is a computational PRF model,
    not a standalone statistical-uniformity theorem.  The returned flags
    remain non-strict until a production Ligero/Ligerito simulator and QROM
    reduction are independently supplied.
    """

    mask = in_place_mask_coefficients(params, _validate_coins(simulator_coins))
    encoded = _prove_in_place_masked(mask, params, public_context)
    return InPlaceSimulation(
        encoded=encoded,
        source_independent=True,
        affine_fiber_sampler=True,
        complete_zk_theorem=False,
        qrom_composed=False,
    )


# ---------------------------------------------------------------------------
# Hiding attempt and simulator target


@dataclass(frozen=True)
class MaskedMerkleAttempt:
    """The concrete one-time-pad attempt, intentionally marked non-ZK.

    If masks are included, the verifier can recover every opened source row.
    If masks are omitted, the root authenticates only the masked vector and no
    longer binds the source vector.  This object records the first branch so
    the failure is executable rather than a prose caveat.
    """

    masked_proof: bytes
    masks: tuple[tuple[int, ...], ...]

    @property
    def wire_bytes(self) -> int:
        return len(self.masked_proof) + sum(
            len(row) * B128_BYTES for row in self.masks
        )

    @property
    def source_recoverable(self) -> bool:
        return True


def masked_merkle_attempt(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> MaskedMerkleAttempt:
    columns = _encode_source(source, params)
    masks = tuple(
        tuple(
            int.from_bytes(
                shake512(
                    b"HVBPCS/mask/v1",
                    index.to_bytes(4, "big"),
                    lane.to_bytes(2, "big"),
                    public_context,
                )[:B128_BYTES],
                "little",
            )
            for lane in range(params.lanes)
        )
        for index in range(params.codeword_leaves)
    )
    masked_columns = [
        tuple(value ^ mask for value, mask in zip(column, masks[index]))
        for index, column in enumerate(columns)
    ]
    levels = _merkle_levels(masked_columns)
    root = levels[-1][0]
    transcript = _new_transcript(params, public_context, root)
    queries = tuple(sorted(transcript.distinct_indices(
        b"columns", params.query_count, params.codeword_leaves
    )))
    opened = tuple(masked_columns[index] for index in queries)
    frontier = _compact_frontier(levels, queries, params)
    proof = MerkleVectorProof(root, opened, frontier).serialize(params)
    selected_masks = tuple(masks[index] for index in queries)
    return MaskedMerkleAttempt(proof, selected_masks)


@dataclass(frozen=True)
class SimulatorTarget:
    """Source-independent algebraic transcript shape for the missing ZK proof.

    The simulator is intentionally modeled in a programmable random-oracle
    target.  It does not certify that the concrete Merkle opening is hiding;
    ``strict_admitted`` remains false until a real commitment/opening protocol
    and a composed simulator proof replace this target.
    """

    messages: tuple[E384, ...]
    challenges: tuple[E384, ...]
    source_independent: bool
    programmable_rom: bool
    setup_bytes: int
    pairing_operations: int
    aggregation: bool

    @property
    def wire_bytes(self) -> int:
        return len(self.messages) * E384_BYTES

    def serialize(self) -> bytes:
        return b"".join(message.to_bytes() for message in self.messages)


def simulate_algebraic_target(
    params: PCSParams,
    public_context: bytes,
    commitment: bytes,
    simulator_seed: bytes,
) -> SimulatorTarget:
    """Generate the source-free transcript reserved by the compact target."""

    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    _check_digest(commitment)
    if len(simulator_seed) != 32:
        raise ValueError("simulator seed must be exactly 32 bytes")
    transcript = _new_transcript(params, public_context, commitment)
    challenges = tuple(
        transcript.challenge_e384(
            b"simulator/challenge/" + index.to_bytes(2, "big")
        )
        for index in range(5)
    )
    messages = tuple(
        E384.from_bytes(
            shake512(
                b"HVBPCS/simulator/message/v1",
                params.profile_id,
                public_context,
                commitment,
                simulator_seed,
                index.to_bytes(4, "big"),
            )[:E384_BYTES]
        )
        for index in range(ALGEBRAIC_ZK_TARGET_MESSAGES)
    )
    return SimulatorTarget(
        messages=messages,
        challenges=challenges,
        source_independent=True,
        programmable_rom=True,
        setup_bytes=0,
        pairing_operations=0,
        aggregation=False,
    )


# ---------------------------------------------------------------------------
# Exact wire report and fail-closed gates


def compact_target_plan() -> dict[str, object]:
    params = strict_params()
    vector_target = HEADER_BYTES + DIGEST_BYTES + params.query_count * COMPACT_QUERY_RECORD_BYTES
    algebraic_budget = PCS_ZK_BUDGET_BYTES - vector_target
    algebraic_target = (
        algebraic_budget // ALGEBRAIC_ZK_ELEMENT_BYTES
    ) * ALGEBRAIC_ZK_ELEMENT_BYTES
    total = vector_target + algebraic_target
    return {
        "vector_query_record": {
            "b128_symbol_bytes": B128_BYTES,
            "shake256_512_digest_bytes": DIGEST_BYTES,
            "e384_bytes": E384_BYTES,
            "record_bytes": COMPACT_QUERY_RECORD_BYTES,
            "query_count": params.query_count,
        },
        "vector_target_bytes": vector_target,
        "algebraic_zk_budget_bytes": algebraic_budget,
        "algebraic_zk_target_messages": ALGEBRAIC_ZK_TARGET_MESSAGES,
        "algebraic_zk_target_bytes": algebraic_target,
        "total_target_bytes": total,
        "headroom_bytes": PCS_ZK_BUDGET_BYTES - total,
        "fits_budget": total <= PCS_ZK_BUDGET_BYTES,
        "target_only": True,
        "implemented_binding": False,
        "implemented_hiding": False,
        "complete_zk_proved": False,
    }


def fixed_lane_n15_screen() -> dict[str, object]:
    """Screen the n15-ish fixed-32-lane variant without allocating its oracle."""

    params = PCSParams(
        log_relation_size=15,
        active_symbols=1 << 15,
        fold_variables=STRICT_FOLD_VARIABLES,
        log_inv_rate=LOG_INV_RATE,
        query_count=STRICT_QUERY_COUNT,
        security_bits=STRICT_CLASSICAL_BITS,
    )
    return {
        "relation_stats_frozen": False,
        "assumed_active_symbols": 1 << 15,
        "lanes": params.lanes,
        "query_count": params.query_count,
        "frontier_nodes": params.frontier_nodes,
        "encoded_oracle_bytes": params.encoded_oracle_bytes,
        "vector_opening_bytes": params.vector_opening_bytes,
        "over_budget_bytes": params.vector_opening_bytes - PCS_ZK_BUDGET_BYTES,
        "exact_no_go": params.vector_opening_bytes > PCS_ZK_BUDGET_BYTES,
        "hiding": False,
        "complete_zk": False,
    }


def n15ish_concrete_opening() -> dict[str, object]:
    """Name the n15-ish exact no-go separately for parent reports."""

    screen = fixed_lane_n15_screen()
    return {
        "formula": "64 header + 64 root + 68*32*16 B128 + 808*64 frontier",
        "header_bytes": HEADER_BYTES,
        "root_bytes": DIGEST_BYTES,
        "opened_b128_symbol_bytes": 68 * 32 * B128_BYTES,
        "frontier_nodes": screen["frontier_nodes"],
        "frontier_bytes": screen["frontier_nodes"] * DIGEST_BYTES,
        "vector_opening_bytes": screen["vector_opening_bytes"],
        "budget_bytes": PCS_ZK_BUDGET_BYTES,
        "over_budget_bytes": screen["over_budget_bytes"],
        "exact_no_go": screen["exact_no_go"],
        "hiding": False,
        "complete_zk": False,
    }


def hash_only_share_screen() -> dict[str, object]:
    """Exact scope boundary for a two-Merkle-root mask-share PCS."""

    params = PCSParams(
        log_relation_size=15,
        active_symbols=1 << 15,
        fold_variables=STRICT_FOLD_VARIABLES,
        log_inv_rate=LOG_INV_RATE,
        query_count=STRICT_QUERY_COUNT,
        security_bits=STRICT_CLASSICAL_BITS,
    )
    hidden_bytes = share_wire_bytes(params, SHARE_HIDDEN_FLAGS)
    direct_bytes = share_wire_bytes(params, SHARE_DIRECT_FLAGS)
    return {
        "construction": "two SHAKE256-512 Merkle roots for masked and mask codewords",
        "relation_stats_frozen": False,
        "q": params.query_count,
        "frontier_nodes_per_tree": params.frontier_nodes,
        "hidden_wire_formula": (
            "64 header + 2*64 roots + 68*32*16 masked B128 + 808*64 frontier"
        ),
        "hidden_wire_bytes": hidden_bytes,
        "hidden_wire_over_budget_bytes": hidden_bytes - PCS_ZK_BUDGET_BYTES,
        "hidden_wire_fits": hidden_bytes <= PCS_ZK_BUDGET_BYTES,
        "hidden_commitment_hiding_under_fresh_masks": True,
        "hidden_opening_binding_to_source": False,
        "hidden_opening_complete": False,
        "direct_wire_formula": (
            "64 header + 2*64 roots + 2*(68*32*16) B128 + 2*(808*64) frontier"
        ),
        "direct_wire_bytes": direct_bytes,
        "direct_wire_over_budget_bytes": direct_bytes - PCS_ZK_BUDGET_BYTES,
        "direct_binding_under_shake_assumption": True,
        "direct_hiding": False,
        "exact_no_go": hidden_bytes > PCS_ZK_BUDGET_BYTES,
        "no_go_reason": (
            "even the hidden masked-row branch needs two roots and one authenticated "
            "Merkle opening before any algebraic ZK; authenticating mask queries "
            "requires the larger direct branch, which reveals the source"
        ),
        "complete_zk": False,
        "strict_admitted": False,
    }


def _n15_profiles_under_oracle_cap(
    oracle_cap: int = 28 * 1024**3,
) -> list[PCSParams]:
    """Enumerate every one-level n15 profile under the no-heavy-run cap."""

    profiles: list[PCSParams] = []
    for rate in range(1, 32):
        q = strict_query_count(STRICT_CLASSICAL_BITS, rate)
        for fold in range(1, N15_LOG_RELATION_SIZE + 1):
            try:
                params = PCSParams(
                    log_relation_size=N15_LOG_RELATION_SIZE,
                    active_symbols=1 << N15_LOG_RELATION_SIZE,
                    fold_variables=fold,
                    log_inv_rate=rate,
                    query_count=q,
                    security_bits=STRICT_CLASSICAL_BITS,
                )
            except ValueError:
                continue
            if params.encoded_oracle_bytes <= oracle_cap:
                profiles.append(params)
    return profiles


def _profile_geometry_record(params: PCSParams) -> dict[str, int]:
    return {
        "fold_variables": params.fold_variables,
        "log_inv_rate": params.log_inv_rate,
        "query_count": params.query_count,
        "frontier_nodes": params.frontier_nodes,
        "hidden_wire_bytes": share_wire_bytes(params, SHARE_HIDDEN_FLAGS),
        "direct_wire_bytes": share_wire_bytes(params, SHARE_DIRECT_FLAGS),
        "encoded_oracle_bytes": params.encoded_oracle_bytes,
    }


def hash_only_share_geometry_search() -> dict[str, object]:
    """Search all one-level fold/rate choices allowed by the disk gate.

    The encoded oracle size is independent of the fold for fixed n and rate:
    ``2^(n + rate) * 16`` bytes. With a 28 GiB cap, rate 16 is already 32 GiB
    and is excluded; rates 1..15 and every fold are screened exactly.
    """

    oracle_cap = 28 * 1024**3
    params_list = _n15_profiles_under_oracle_cap(oracle_cap)
    candidates = [_profile_geometry_record(params) for params in params_list]
    if not candidates:
        raise AssertionError("geometry search unexpectedly found no candidates")
    candidates.sort(
        key=lambda item: (
            item["hidden_wire_bytes"],
            item["log_inv_rate"],
            item["fold_variables"],
        )
    )
    best = candidates[0]
    return {
        "oracle_cap_bytes": oracle_cap,
        "relation_stats_frozen": False,
        "profiles_screened": len(candidates),
        "maximum_admitted_log_inv_rate": max(
            item["log_inv_rate"] for item in candidates
        ),
        "best_hidden_share_profile": best,
        "best_hidden_over_budget_bytes": best["hidden_wire_bytes"]
        - PCS_ZK_BUDGET_BYTES,
        "best_hidden_fits_budget": best["hidden_wire_bytes"]
        <= PCS_ZK_BUDGET_BYTES,
        "exact_no_go_for_this_family": best["hidden_wire_bytes"]
        > PCS_ZK_BUDGET_BYTES,
        "binding_hiding_construction_exists": False,
        "complete_zk": False,
        "strict_admitted": False,
    }


def hash_only_two_share_lower_bound() -> dict[str, object]:
    """Exact dichotomy for hash-only two-share one-level openings.

    Assumptions are intentionally narrow and executable: each share is bound
    by a SHAKE Merkle root, each directly authenticated query needs the exact
    compact frontier, and there is no algebraic homomorphism or recursive
    hash-preimage ZK linkage proof. A hidden branch reveals one share; a direct
    binding branch must reveal both shares. The ``optimistic_linkage`` row
    charges a second frontier while still omitting the hidden share values, so
    it is a lower bound, not a claimed verifier.
    """

    oracle_cap = 28 * 1024**3
    params_list = _n15_profiles_under_oracle_cap(oracle_cap)
    if not params_list:
        raise AssertionError("no profiles for lower-bound search")

    def record(params: PCSParams, *, roots: int, rows: int, frontiers: int) -> dict[str, int]:
        return {
            "fold_variables": params.fold_variables,
            "log_inv_rate": params.log_inv_rate,
            "query_count": params.query_count,
            "frontier_nodes": params.frontier_nodes,
            "roots": roots,
            "row_copies": rows,
            "frontier_copies": frontiers,
            "wire_bytes": (
                HEADER_BYTES
                + roots * DIGEST_BYTES
                + rows * params.opened_symbol_bytes
                + frontiers * params.authentication_bytes
            ),
            "encoded_oracle_bytes": params.encoded_oracle_bytes,
        }

    # Hidden commitment-only branch: one share is visible and authenticated.
    # This is the minimum hiding wire, but it has no source-opening binding.
    hidden = min(
        (record(params, roots=1, rows=1, frontiers=1) for params in params_list),
        key=lambda item: (item["wire_bytes"], item["log_inv_rate"], item["fold_variables"]),
    )
    # Direct hash-only branch: both shares are visible, so binding is direct
    # but hiding is impossible. One root/frontier is an optimistic shared-tree
    # lower bound; two roots/two frontiers are the implemented construction.
    direct = min(
        (record(params, roots=1, rows=2, frontiers=1) for params in params_list),
        key=lambda item: (item["wire_bytes"], item["log_inv_rate"], item["fold_variables"]),
    )
    optimistic_linkage = min(
        (record(params, roots=1, rows=1, frontiers=2) for params in params_list),
        key=lambda item: (item["wire_bytes"], item["log_inv_rate"], item["fold_variables"]),
    )
    implemented_hidden = min(
        (record(params, roots=2, rows=1, frontiers=1) for params in params_list),
        key=lambda item: (item["wire_bytes"], item["log_inv_rate"], item["fold_variables"]),
    )
    implemented_direct = min(
        (record(params, roots=2, rows=2, frontiers=2) for params in params_list),
        key=lambda item: (item["wire_bytes"], item["log_inv_rate"], item["fold_variables"]),
    )
    return {
        "assumptions": {
            "n": N15_LOG_RELATION_SIZE,
            "committed_symbol": "B128",
            "challenge_field": "E384",
            "e384_real_field": e384_cubic_is_irreducible(),
            "query_term_target_bits": STRICT_CLASSICAL_BITS,
            "q_rule": "ceil(264 / -log2(2^(-rate/2) + 1/256))",
            "oracle_cap_bytes": oracle_cap,
            "one_level_sha_merkle": True,
            "hash_preimage_zk_linkage": False,
            "algebraic_homomorphism": False,
            "trusted_setup": False,
            "pairings": False,
            "aggregation": False,
        },
        "profiles_screened": len(params_list),
        "hidden_commitment_lower_bound": hidden,
        "direct_binding_lower_bound": direct,
        "optimistic_hidden_linkage_lower_bound": optimistic_linkage,
        "implemented_two_root_hidden": implemented_hidden,
        "implemented_two_root_direct": implemented_direct,
        "budget_bytes": PCS_ZK_BUDGET_BYTES,
        "hidden_lower_bound_over_budget": hidden["wire_bytes"] - PCS_ZK_BUDGET_BYTES,
        "direct_lower_bound_over_budget": direct["wire_bytes"] - PCS_ZK_BUDGET_BYTES,
        "optimistic_linkage_over_budget": optimistic_linkage["wire_bytes"]
        - PCS_ZK_BUDGET_BYTES,
        "exact_dichotomy_no_binding_hiding": True,
        "exact_byte_no_go_even_before_zk": optimistic_linkage["wire_bytes"]
        > PCS_ZK_BUDGET_BYTES,
        "strict_admitted": False,
        "complete_zk": False,
        "claim_ceiling": (
            "exact for this one-level two-share SHAKE/Merkle family; not a universal "
            "lower bound on non-Merkle PCS constructions"
        ),
    }


WHOLE_VECTOR_FLAGS = 4


def _canonical_source_bytes(source: Sequence[int], params: PCSParams) -> bytes:
    expected = 1 << params.log_relation_size
    if len(source) != expected:
        raise ValueError("source length does not match relation bucket")
    if any(value != 0 for value in source[params.active_symbols :]):
        raise ValueError("inactive symbols must be canonical zero padding")
    return b"".join(b128_to_bytes(value) for value in source)


def _whole_vector_digest(
    params: PCSParams, public_context: bytes, salt: bytes, source: Sequence[int]
) -> bytes:
    if len(public_context) != PUBLIC_CONTEXT_BYTES:
        raise ValueError("public context must be exactly 32 bytes")
    if len(salt) != 32:
        raise ValueError("whole-vector salt must be exactly 32 bytes")
    return shake512(
        b"HVBPCS/nonmerkle/full-vector/v1",
        params.profile_id,
        public_context,
        salt,
        _canonical_source_bytes(source, params),
    )


@dataclass(frozen=True)
class WholeVectorCommitment:
    """Non-Merkle whole-vector SHAKE commitment control.

    The digest is transparent and hash-binding, and a secret salt gives a
    commitment-level hiding target. A partial opening cannot be verified from
    a digest over the full vector without either revealing the whole vector or
    adding a separate hash-preimage ZK proof; this class deliberately exposes
    that no-go rather than pretending a digest is a vector PCS.
    """

    digest: bytes
    salt: bytes
    source: tuple[int, ...]

    def serialize_full(self, params: PCSParams) -> bytes:
        _check_digest(self.digest)
        if len(self.salt) != 32:
            raise ValueError("whole-vector salt must be exactly 32 bytes")
        source_bytes = _canonical_source_bytes(self.source, params)
        encoded = bytearray(params.header(WHOLE_VECTOR_FLAGS))
        encoded.extend(self.digest)
        encoded.extend(self.salt)
        encoded.extend(source_bytes)
        expected = whole_vector_full_wire_bytes(params)
        if len(encoded) != expected:
            raise AssertionError("whole-vector serializer size drift")
        return bytes(encoded)

    @classmethod
    def parse_full(
        cls, encoded: bytes, params: PCSParams
    ) -> "WholeVectorCommitment":
        if len(encoded) != whole_vector_full_wire_bytes(params):
            raise ValueError("whole-vector opening length is not canonical")
        if encoded[:HEADER_BYTES] != params.header(WHOLE_VECTOR_FLAGS):
            raise ValueError("wrong whole-vector header/profile")
        cursor = HEADER_BYTES

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(encoded):
                raise ValueError("truncated whole-vector opening")
            value = encoded[cursor:end]
            cursor = end
            return value

        digest = _check_digest(take(DIGEST_BYTES))
        salt = take(32)
        source = tuple(
            b128_from_bytes(take(B128_BYTES))
            for _ in range(1 << params.log_relation_size)
        )
        if cursor != len(encoded):
            raise ValueError("trailing whole-vector opening bytes")
        return cls(digest, salt, source)


def whole_vector_full_wire_bytes(params: PCSParams) -> int:
    return (
        HEADER_BYTES
        + DIGEST_BYTES
        + 32
        + (1 << params.log_relation_size) * B128_BYTES
    )


def whole_vector_partial_wire_bytes(params: PCSParams) -> int:
    """A tempting partial wire, explicitly not a verifiable opening."""

    return HEADER_BYTES + DIGEST_BYTES + params.opened_symbol_bytes


def prove_whole_vector_full(
    source: Sequence[int], params: PCSParams, public_context: bytes
) -> bytes:
    salt = shake512(
        b"HVBPCS/nonmerkle/toy-salt/v1", public_context
    )[:32]
    digest = _whole_vector_digest(params, public_context, salt, source)
    return WholeVectorCommitment(digest, salt, tuple(source)).serialize_full(params)


def verify_whole_vector_full(
    encoded: bytes, params: PCSParams, public_context: bytes
) -> bool:
    try:
        proof = WholeVectorCommitment.parse_full(encoded, params)
        return proof.digest == _whole_vector_digest(
            params, public_context, proof.salt, proof.source
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return False


def non_merkle_hash_screen() -> dict[str, object]:
    """Screen a transparent single-digest vector commitment seam."""

    params = PCSParams(
        log_relation_size=N15_LOG_RELATION_SIZE,
        active_symbols=1 << N15_LOG_RELATION_SIZE,
        fold_variables=2,
        log_inv_rate=13,
        query_count=strict_query_count(STRICT_CLASSICAL_BITS, 13),
        security_bits=STRICT_CLASSICAL_BITS,
    )
    full_bytes = whole_vector_full_wire_bytes(params)
    partial_bytes = whole_vector_partial_wire_bytes(params)
    return {
        "construction": "SHAKE256-512 digest over the complete canonical B128 vector",
        "transparent": True,
        "pq_hash_assumption": True,
        "trusted_setup": False,
        "pairings": False,
        "aggregation": False,
        "commitment_bytes": DIGEST_BYTES,
        "tempting_partial_wire_bytes": partial_bytes,
        "partial_opening_verifiable": False,
        "full_opening_wire_bytes": full_bytes,
        "full_opening_over_budget_bytes": full_bytes - PCS_ZK_BUDGET_BYTES,
        "full_vector_symbol_bytes": (1 << N15_LOG_RELATION_SIZE) * B128_BYTES,
        "hash_preimage_zk_bytes": None,
        "exact_no_go": True,
        "no_go_reason": (
            "a whole-vector digest cannot authenticate a partial opening; direct "
            "hash-only opening reveals all n15 symbols, while a hidden partial "
            "opening requires a separate hash-preimage ZK construction"
        ),
        "complete_zk": False,
        "strict_admitted": False,
    }


# ---------------------------------------------------------------------------
# Full-M4 relation-independent mask wire model


def m4_terminal_padding_geometry(
    params: PCSParams,
    active_trace_symbols: int = M4_ACTIVE_TRACE_SYMBOLS_ASSUMPTION,
) -> dict[str, int | bool]:
    """Return padding-aware terminal prefix/suffix counts.

    The terminal vector has one E384 value per residual message column.  If a
    compiled full-M4 trace proves that only ``active_trace_symbols`` source
    B128 symbols are nonzero, the active prefix is the ceiling by the folded
    lane width.  A random omega over the full bucket destroys the zero suffix;
    therefore the elision is reported but disabled unless an explicit
    zero-padding mask theorem is supplied.
    """

    if not 0 < active_trace_symbols <= params.active_symbols:
        raise ValueError("active M4 trace symbols must fit the profile bucket")
    active_prefix = min(
        params.message_columns,
        (active_trace_symbols + params.lanes - 1) // params.lanes,
    )
    zero_suffix = params.message_columns - active_prefix
    return {
        "active_trace_symbols": active_trace_symbols,
        "active_trace_symbols_frozen": False,
        "terminal_rows": params.message_columns,
        "terminal_active_prefix_rows": active_prefix,
        "terminal_zero_suffix_rows": zero_suffix,
        "padding_elision_safe_for_full_random_omega": False,
        "padding_elision_requires_omega_zero_tail": True,
    }


def m4_relation_claim_elements(
    params: PCSParams, *, terminal_target_elision_rows: int = 0
) -> dict[str, int]:
    """Count the optimistic folded transcript's alpha/sigma relation claims.

    ``113`` is the prior wide-reduction assumption.  It is deliberately
    separated from the source inventory: 3,187,200 Keccak BitAnd constraints
    still need a nonlinear compiler.  Every retained alpha claim receives a
    separate sigma=<omega,T> E384 claim.
    """

    terminal_rows = params.message_columns
    if not 0 <= terminal_target_elision_rows <= terminal_rows:
        raise ValueError("terminal target elision exceeds terminal rows")
    wide = M4_OPTIMISTIC_WIDE_CLAIMS
    sumcheck = 2 * params.fold_variables
    terminal = terminal_rows - terminal_target_elision_rows
    alpha = wide + sumcheck + terminal
    sigma = alpha
    return {
        "wide_alpha_elements": wide,
        "sumcheck_alpha_elements": sumcheck,
        "terminal_alpha_elements": terminal,
        "alpha_elements": alpha,
        "sigma_elements": sigma,
        "masked_relation_elements": alpha + sigma,
        "terminal_target_elision_rows": terminal_target_elision_rows,
    }


def m4_masked_joint_vector_bytes(
    params: PCSParams,
    *,
    merkle_node_bytes: int = MERKLE_DIGEST_BYTES,
    mask_coordinate_copies: int = M4_E384_MASK_COORDINATES,
    share_dimensions: int = M4_MASK_SHARE_DIMENSIONS,
) -> int:
    """Exact joint-root vector opening for [pi || omega]."""

    if merkle_node_bytes != MERKLE_DIGEST_BYTES:
        raise ValueError("production model pins SHAKE256-448 Merkle nodes at 56 bytes")
    if mask_coordinate_copies != 3 or share_dimensions != 2:
        raise ValueError("full-M4 E384 masking requires 3 coordinates and [pi||omega]")
    return (
        HEADER_BYTES
        + merkle_node_bytes
        + params.opened_symbol_bytes * mask_coordinate_copies * share_dimensions
        + params.frontier_nodes * merkle_node_bytes
    )


def m4_masked_joint_oracle_bytes(
    params: PCSParams,
    *,
    mask_coordinate_copies: int = M4_E384_MASK_COORDINATES,
    share_dimensions: int = M4_MASK_SHARE_DIMENSIONS,
) -> int:
    """No-allocation oracle accounting for two E384-valued joint dimensions."""

    return (
        params.encoded_oracle_bytes * mask_coordinate_copies * share_dimensions
    )


def _m4_masked_record(
    params: PCSParams,
    *,
    active_trace_symbols: int = M4_ACTIVE_TRACE_SYMBOLS_ASSUMPTION,
    terminal_target_elision_rows: int = 0,
) -> dict[str, object]:
    claims = m4_relation_claim_elements(
        params, terminal_target_elision_rows=terminal_target_elision_rows
    )
    padding = m4_terminal_padding_geometry(params, active_trace_symbols)
    vector_bytes = m4_masked_joint_vector_bytes(params)
    algebraic_bytes = claims["masked_relation_elements"] * E384_BYTES
    raw_bytes = vector_bytes + algebraic_bytes
    return {
        "log_relation_size": params.log_relation_size,
        "active_symbols_bucket": params.active_symbols,
        "active_trace_symbols_assumption": active_trace_symbols,
        "lanes": params.lanes,
        "fold_variables": params.fold_variables,
        "residual_variables": params.residual_variables,
        "message_columns": params.message_columns,
        "log_inv_rate": params.log_inv_rate,
        "query_count": params.query_count,
        "query_term_bits": params.query_count * query_bits(params.log_inv_rate),
        "meets_264_query_term": params.query_count * query_bits(
            params.log_inv_rate
        )
        >= STRICT_CLASSICAL_BITS,
        "frontier_nodes": params.frontier_nodes,
        "merkle_node_bytes": MERKLE_DIGEST_BYTES,
        "fiat_shamir_digest_bytes": FS_DIGEST_BYTES,
        "mask_coordinate_copies": M4_E384_MASK_COORDINATES,
        "mask_share_dimensions": M4_MASK_SHARE_DIMENSIONS,
        "joint_query_row_bytes": params.opened_symbol_bytes
        * M4_E384_MASK_COORDINATES
        * M4_MASK_SHARE_DIMENSIONS,
        "joint_vector_opening_bytes": vector_bytes,
        "relation_claims": claims,
        "algebraic_claim_bytes": algebraic_bytes,
        "raw_proof_bytes": raw_bytes,
        "envelope_bytes": raw_bytes + LIGERITO_ENVELOPE_BYTES,
        "original_pcs_zk_budget_bytes": PCS_ZK_BUDGET_BYTES,
        "over_original_pcs_zk_budget_bytes": raw_bytes - PCS_ZK_BUDGET_BYTES,
        "fits_original_pcs_zk_budget": raw_bytes <= PCS_ZK_BUDGET_BYTES,
        "envelope_headroom_bytes": LIGERITO_ENVELOPE_CAP_BYTES
        - raw_bytes
        - LIGERITO_ENVELOPE_BYTES,
        "joint_oracle_bytes": m4_masked_joint_oracle_bytes(params),
        "oracle_cap_admitted": m4_masked_joint_oracle_bytes(params)
        <= 28 * 1024**3,
        "padding_terminal_geometry": padding,
        "terminal_target_elision_proved": False,
        "nonlinear_cross_terms_priced": False,
        "nonlinear_cross_terms_required": True,
    }


def _m4_masked_profiles_under_oracle_cap(
    log_relation_size: int, oracle_cap: int
) -> list[PCSParams]:
    profiles: list[PCSParams] = []
    for rate in range(1, 32):
        query_count = strict_query_count(STRICT_CLASSICAL_BITS, rate)
        for fold in range(1, log_relation_size + 1):
            try:
                params = PCSParams(
                    log_relation_size=log_relation_size,
                    active_symbols=1 << log_relation_size,
                    fold_variables=fold,
                    log_inv_rate=rate,
                    query_count=query_count,
                    security_bits=STRICT_CLASSICAL_BITS,
                )
            except ValueError:
                continue
            if m4_masked_joint_oracle_bytes(params) <= oracle_cap:
                profiles.append(params)
    return profiles


def full_m4_masked_production_search() -> dict[str, object]:
    """Search the conservative source-bound [pi||omega] replacement.

    A joint Merkle leaf authenticates both dimensions with one 56-byte root
    and frontier, but every opened row carries 3 E384/B128 coordinates for
    each of pi and omega.  This is the smallest *authenticated* hash-only
    accounting seam; omitting omega rows would make sigma unauthenticated.
    """

    oracle_cap = 28 * 1024**3
    envelope_cap = LIGERITO_ENVELOPE_CAP_BYTES
    by_n: dict[str, dict[str, object]] = {}
    all_records: list[dict[str, object]] = []
    for n in (15, 16):
        profiles = _m4_masked_profiles_under_oracle_cap(n, oracle_cap)
        records = [_m4_masked_record(params) for params in profiles]
        admitted = [record for record in records if record["envelope_bytes"] <= envelope_cap]
        if not records:
            raise AssertionError(f"no full-M4 masked profiles under oracle cap for n={n}")
        admitted.sort(
            key=lambda item: (
                item["envelope_bytes"],
                item["raw_proof_bytes"],
                item["log_inv_rate"],
                item["fold_variables"],
            )
        )
        by_n[str(n)] = {
            "profiles_screened_under_oracle_cap": len(records),
            "profiles_admitted_under_512k_envelope": len(admitted),
            "best": admitted[0] if admitted else None,
            "best_under_oracle_cap": True,
            "best_fits_512k_envelope": bool(admitted),
        }
        all_records.extend(admitted)
    if not all_records:
        # Preserve a deterministic best row even when a future claim model
        # exceeds the envelope cap for every profile.
        all_records = [
            _m4_masked_record(params)
            for params in _m4_masked_profiles_under_oracle_cap(15, oracle_cap)
        ]
    all_records.sort(
        key=lambda item: (
            item["envelope_bytes"],
            item["raw_proof_bytes"],
            item["log_relation_size"],
        )
    )
    best = all_records[0]
    # Even the unsound hypothetical that elides every terminal E384 row is
    # screened so a terminal-target optimization cannot hide the byte no-go.
    all_terminal_elision: dict[str, dict[str, object]] = {}
    for n in (15, 16):
        profiles = _m4_masked_profiles_under_oracle_cap(n, oracle_cap)
        hypothetical = [
            _m4_masked_record(
                params, terminal_target_elision_rows=params.message_columns
            )
            for params in profiles
        ]
        hypothetical.sort(
            key=lambda item: (
                item["raw_proof_bytes"],
                item["log_inv_rate"],
                item["fold_variables"],
            )
        )
        all_terminal_elision[str(n)] = hypothetical[0]
    return {
        "construction": (
            "source-bound full-M4 optimistic reduction with one joint SHAKE256-448 "
            "Merkle commitment to [pi||omega], true three-coordinate E384 mask, "
            "and explicit alpha/sigma claims"
        ),
        "source_revision": M4_SOURCE_REVISION,
        "source_inventory": asdict(m4_constraint_inventory()),
        "full_production_buckets": [15, 16],
        "oracle_cap_bytes": oracle_cap,
        "prover_memory_cap_bytes": oracle_cap,
        "prover_disk_cap_bytes": oracle_cap,
        "envelope_cap_bytes": envelope_cap,
        "merkle_hash": "SHAKE256-448",
        "merkle_node_bytes": MERKLE_DIGEST_BYTES,
        "fiat_shamir_hash": "SHAKE256-512",
        "fiat_shamir_digest_bytes": FS_DIGEST_BYTES,
        "committed_symbol": "B128",
        "challenge_field": "E384 = B128[Y]/(Y^3+Y+1)",
        "e384_real_field": e384_cubic_is_irreducible(),
        "mask_formula": "pi'=(1-gamma)pi+gamma*omega; sigma=<omega,T>; alpha=<pi',T>",
        "mask_coordinate_copies": M4_E384_MASK_COORDINATES,
        "mask_share_dimensions": M4_MASK_SHARE_DIMENSIONS,
        "gamma_candidates": M4_GAMMA_CANDIDATES,
        "gamma_zero_event_bits": M4_GAMMA_ZERO_EVENT_BITS,
        "gamma_zero_event_wire_bytes": 0,
        "joint_root_not_aggregation": True,
        "safe_hash_only_postchallenge_opening": True,
        "source_witness_binding_theorem": False,
        "full_m4_nonlinear_relation_theorem": False,
        "nonlinear_bitand_cross_terms": {
            "keccak_bitand_constraints": M4_KECCAK_BITAND_CONSTRAINTS,
            "cross_term_products_per_gate": M4_BITAND_CROSS_TERM_PRODUCTS_PER_GATE,
            "naive_per_gate_auxiliary_e384_elements": M4_KECCAK_BITAND_CONSTRAINTS
            * M4_BITAND_CROSS_TERM_PRODUCTS_PER_GATE,
            "naive_per_gate_auxiliary_bytes": M4_KECCAK_BITAND_CONSTRAINTS
            * M4_BITAND_CROSS_TERM_PRODUCTS_PER_GATE
            * E384_BYTES,
            "compressed_cross_term_bytes_priced_in_best": 0,
            "status": "unresolved; best row is optimistic and rejected for strict admission",
        },
        "terminal_target_elision": {
            "rank3_b128_coordinates_per_e384_row": 3,
            "padding_aware": True,
            "default_rows_elided": 0,
            "proved": False,
            "reason": (
                "a full random omega masks inactive padding; elision is only safe "
                "after a zero-tail mask theorem and terminal-index binding"
            ),
        },
        "by_n": by_n,
        "best_overall": best,
        "hypothetical_all_terminal_target_elision": all_terminal_elision,
        "hypothetical_all_terminal_elision_still_over_budget": all(
            item["raw_proof_bytes"] > PCS_ZK_BUDGET_BYTES
            for item in all_terminal_elision.values()
        ),
        "exact_no_go_for_37316_budget": best["raw_proof_bytes"] > PCS_ZK_BUDGET_BYTES,
        "binding_hiding_construction_implemented": False,
        "binding_hiding_candidate_under_budget": False,
        "no_go_scope": (
            "exact for the declared joint SHAKE256-448 [pi||omega] model, "
            "three-coordinate E384 mask, optimistic alpha/sigma reduction, "
            "and all one-level n15/n16 profiles under 28 GiB; not a universal "
            "lower bound for every future PCS"
        ),
        "strict_admitted": False,
        "complete_zk_simulator_proved": False,
        "qrom_composed": False,
        "claim_ceiling": (
            "The alpha/sigma and three-coordinate row price is executable and "
            "source anchored, but full M4 BitAnd cross terms, reduction, simulator, "
            "and QROM composition remain unproved. This is not a strict PCS."
        ),
    }


# ---------------------------------------------------------------------------
# GhashSq256b two-repetition comparison seam


GHASH_SQ_FIELD_BITS = 256
GHASH_SQ_LOG_DEGREE_BOUND = 120
GHASH_SQ_SINGLE_ERROR_BITS = GHASH_SQ_FIELD_BITS - GHASH_SQ_LOG_DEGREE_BOUND
GHASH_SQ_REPETITIONS = 2
GHASH_SQ_JOINT_CLASSICAL_BITS = GHASH_SQ_REPETITIONS * GHASH_SQ_SINGLE_ERROR_BITS
GHASH_SQ_CONSERVATIVE_COMPOSED_BITS = GHASH_SQ_JOINT_CLASSICAL_BITS // 2


def _masked_field_wire_record(
    params: PCSParams,
    *,
    field_bytes: int,
    mask_coordinates: int,
    repetitions: int,
    merkle_node_bytes: int = MERKLE_DIGEST_BYTES,
) -> dict[str, int | bool]:
    claims = M4_OPTIMISTIC_WIDE_CLAIMS + 2 * params.fold_variables + params.message_columns
    alpha_sigma_elements = repetitions * 2 * claims
    vector_bytes = (
        HEADER_BYTES
        + merkle_node_bytes
        + params.opened_symbol_bytes * mask_coordinates * M4_MASK_SHARE_DIMENSIONS
        + params.frontier_nodes * merkle_node_bytes
    )
    raw = vector_bytes + alpha_sigma_elements * field_bytes
    return {
        "fold_variables": params.fold_variables,
        "log_inv_rate": params.log_inv_rate,
        "query_count": params.query_count,
        "frontier_nodes": params.frontier_nodes,
        "field_bytes": field_bytes,
        "mask_coordinate_copies": mask_coordinates,
        "repetitions": repetitions,
        "vector_opening_bytes": vector_bytes,
        "alpha_sigma_elements": alpha_sigma_elements,
        "algebraic_claim_bytes": alpha_sigma_elements * field_bytes,
        "raw_proof_bytes": raw,
        "envelope_bytes": raw + LIGERITO_ENVELOPE_BYTES,
        "joint_oracle_bytes": params.encoded_oracle_bytes
        * mask_coordinates
        * M4_MASK_SHARE_DIMENSIONS,
        "strict_budget_fit": raw <= PCS_ZK_BUDGET_BYTES,
    }


def ghash_sq256b_two_rep_screen() -> dict[str, object]:
    """Compare two independent true quadratic 256-bit repetitions.

    This is a wire/error screen for the pinned ``GhashSq256b`` seam. It does
    not assert that the current workspace contains or builds that dependency;
    independence, QROM composition, and the verifier theorem remain false.
    """

    oracle_cap = 28 * 1024**3
    profiles: list[PCSParams] = []
    for rate in range(1, 32):
        q = strict_query_count(STRICT_CLASSICAL_BITS, rate)
        for fold in range(1, 16):
            try:
                params = PCSParams(15, 1 << 15, fold, rate, q, STRICT_CLASSICAL_BITS)
            except ValueError:
                continue
            if params.encoded_oracle_bytes * 4 <= oracle_cap:
                profiles.append(params)
    if not profiles:
        raise AssertionError("no GhashSq256b profiles under oracle cap")
    records = [_masked_field_wire_record(
        params,
        field_bytes=32,
        mask_coordinates=2,
        repetitions=GHASH_SQ_REPETITIONS,
    ) for params in profiles]
    records.sort(key=lambda item: (item["envelope_bytes"], item["fold_variables"], item["log_inv_rate"]))
    best = records[0]
    # One E384 repetition over the same degree bound and geometry, for a
    # direct comparison of three-coordinate masks and 48-byte claims.
    e384_records = [_masked_field_wire_record(
        params,
        field_bytes=E384_BYTES,
        mask_coordinates=3,
        repetitions=1,
    ) for params in profiles if params.encoded_oracle_bytes * 6 <= oracle_cap]
    e384_records.sort(key=lambda item: (item["envelope_bytes"], item["fold_variables"], item["log_inv_rate"]))
    return {
        "construction": "GhashSq256b true quadratic B128 extension, two independently challenged repetitions",
        "source_anchor": "crates/field/src/ghash_sq.rs",
        "source_present_in_this_workspace": False,
        "field_bits": GHASH_SQ_FIELD_BITS,
        "log_degree_bound": GHASH_SQ_LOG_DEGREE_BOUND,
        "single_repetition_classical_error_bits": GHASH_SQ_SINGLE_ERROR_BITS,
        "joint_classical_error_bits": GHASH_SQ_JOINT_CLASSICAL_BITS,
        "conservative_composed_bits": GHASH_SQ_CONSERVATIVE_COMPOSED_BITS,
        "repetitions": GHASH_SQ_REPETITIONS,
        "mask_coordinate_copies": 2,
        "shared_joint_commitment": True,
        "independence_theorem": False,
        "qrom_composed": False,
        "oracle_cap_bytes": oracle_cap,
        "profiles_screened": len(records),
        "best_two_rep": best,
        "one_e384_comparison": e384_records[0] if e384_records else None,
        "strict_admitted": False,
        "claim_ceiling": (
            "The 272-bit product and conservative 136-bit composition are arithmetic "
            "screens only; no independence/QROM/verifier theorem is claimed."
        ),
    }


def hash_collision_multi_target_ledger(
    *,
    target_count: int = M4_KECCAK_PERMUTATIONS * STRICT_QUERY_COUNT,
) -> dict[str, object]:
    """Price SHAKE-448 Merkle and SHAKE-512 FS collision margins separately.

    The quantum collision exponent ``n/3`` is a conservative generic QROM
    screen, not a reduction for this PCS. ``target_count`` is an explicit
    audit multi-target assumption (83 source hash roles times 68 query
    challenges); changing it changes only the arithmetic ledger.
    """

    if target_count <= 0:
        raise ValueError("multi-target count must be positive")
    penalty = math.log2(target_count)

    def margin(output_bits: int) -> dict[str, float]:
        return {
            "output_bits": float(output_bits),
            "classical_birthday_bits": output_bits / 2 - penalty,
            "generic_qrom_collision_bits": output_bits / 3 - penalty,
        }

    merkle = margin(8 * MERKLE_DIGEST_BYTES)
    fiat_shamir = margin(8 * FS_DIGEST_BYTES)
    return {
        "target_count": target_count,
        "target_count_assumption": "83 frozen M4 Keccak roles * 68 strict query challenges",
        "multi_target_penalty_bits": penalty,
        "merkle": merkle,
        "fiat_shamir": fiat_shamir,
        "composed_classical_screen_bits": min(
            merkle["classical_birthday_bits"],
            fiat_shamir["classical_birthday_bits"],
        ),
        "composed_generic_qrom_screen_bits": min(
            merkle["generic_qrom_collision_bits"],
            fiat_shamir["generic_qrom_collision_bits"],
        ),
        "composition_proved": False,
        "strict_admitted": False,
    }


def in_place_algebraic_elements(params: PCSParams) -> int:
    """One-level Ligerito transcript count used by the production byte model.

    The model charges one public relation claim, two E384 messages per fold
    variable, and one E384 terminal message per residual coefficient column.
    This is an explicit accounting seam for a future full sumcheck/FRI proof;
    it is not a theorem that these messages alone establish production
    soundness or zero knowledge.
    """

    return (
        IN_PLACE_TOY_CLAIM_ELEMENTS
        + LIGERITO_PER_FOLD_CLAIM_ELEMENTS * params.fold_variables
        + params.message_columns
    )


def in_place_algebraic_wire_bytes(params: PCSParams) -> int:
    return in_place_algebraic_elements(params) * E384_BYTES


def in_place_raw_wire_bytes(params: PCSParams) -> int:
    return params.vector_opening_bytes + in_place_algebraic_wire_bytes(params)


def in_place_envelope_wire_bytes(params: PCSParams) -> int:
    return in_place_raw_wire_bytes(params) + LIGERITO_ENVELOPE_BYTES


def _in_place_production_profiles(
    log_relation_size: int,
    oracle_cap: int,
) -> list[PCSParams]:
    """Enumerate full-bucket profiles under the oracle cap only."""

    profiles: list[PCSParams] = []
    for rate in range(1, 32):
        query_count = strict_query_count(STRICT_CLASSICAL_BITS, rate)
        for fold in range(1, log_relation_size + 1):
            try:
                params = PCSParams(
                    log_relation_size=log_relation_size,
                    active_symbols=1 << log_relation_size,
                    fold_variables=fold,
                    log_inv_rate=rate,
                    query_count=query_count,
                    security_bits=STRICT_CLASSICAL_BITS,
                )
            except ValueError:
                continue
            if params.encoded_oracle_bytes <= oracle_cap:
                profiles.append(params)
    return profiles


def _in_place_production_record(params: PCSParams) -> dict[str, object]:
    return {
        "log_relation_size": params.log_relation_size,
        "active_symbols": params.active_symbols,
        "lanes": params.lanes,
        "fold_variables": params.fold_variables,
        "residual_variables": params.residual_variables,
        "log_inv_rate": params.log_inv_rate,
        "query_count": params.query_count,
        "query_term_bits": params.query_count * query_bits(params.log_inv_rate),
        "meets_264_query_term": params.query_count * query_bits(
            params.log_inv_rate
        )
        >= STRICT_CLASSICAL_BITS,
        "frontier_nodes": params.frontier_nodes,
        "vector_opening_bytes": params.vector_opening_bytes,
        "algebraic_claim_elements": in_place_algebraic_elements(params),
        "algebraic_claim_bytes": in_place_algebraic_wire_bytes(params),
        "raw_proof_bytes": in_place_raw_wire_bytes(params),
        "envelope_bytes": in_place_envelope_wire_bytes(params),
        "original_pcs_zk_budget_bytes": PCS_ZK_BUDGET_BYTES,
        "over_original_pcs_zk_budget_bytes": in_place_raw_wire_bytes(params)
        - PCS_ZK_BUDGET_BYTES,
        "fits_original_pcs_zk_budget": in_place_raw_wire_bytes(params)
        <= PCS_ZK_BUDGET_BYTES,
        "envelope_headroom_bytes": LIGERITO_ENVELOPE_CAP_BYTES
        - in_place_envelope_wire_bytes(params),
        "encoded_oracle_bytes": params.encoded_oracle_bytes,
    }


def in_place_production_search() -> dict[str, object]:
    """Minimize the explicit in-place model for full production n15/n16.

    Only integer geometry is evaluated.  The function never constructs the
    codeword or its Merkle tree, so the 28 GiB resource gate is a number-only
    admission check rather than a request to allocate a multi-gigabyte object.
    """

    oracle_cap = 28 * 1024**3
    envelope_cap = LIGERITO_ENVELOPE_CAP_BYTES
    by_n: dict[str, dict[str, object]] = {}
    all_records: list[dict[str, object]] = []
    for n in (15, 16):
        profiles = _in_place_production_profiles(n, oracle_cap)
        if not profiles:
            raise AssertionError(f"no in-place profiles admitted for n={n}")
        oracle_records = [_in_place_production_record(params) for params in profiles]
        records = [
            record
            for record in oracle_records
            if record["envelope_bytes"] <= envelope_cap
        ]
        if not records:
            raise AssertionError(f"no in-place envelope profiles admitted for n={n}")
        records.sort(
            key=lambda item: (
                item["envelope_bytes"],
                item["raw_proof_bytes"],
                item["log_inv_rate"],
                item["fold_variables"],
            )
        )
        best = records[0]
        by_n[str(n)] = {
            "profiles_screened_under_oracle_cap": len(oracle_records),
            "profiles_admitted_under_512k_envelope": len(records),
            "best": best,
            "best_fits_512k_envelope": best["envelope_bytes"] <= envelope_cap,
            "best_under_oracle_cap": best["encoded_oracle_bytes"] <= oracle_cap,
        }
        all_records.extend(records)
    all_records.sort(
        key=lambda item: (
            item["envelope_bytes"],
            item["raw_proof_bytes"],
            item["log_relation_size"],
        )
    )
    return {
        "construction": (
            "one binding SHAKE Merkle root over a relation-preserving random "
            "low-degree coefficient mask plus an explicit one-level E384 "
            "Ligerito transcript model"
        ),
        "full_production_buckets": [15, 16],
        "oracle_cap_bytes": oracle_cap,
        "prover_memory_cap_bytes": oracle_cap,
        "prover_disk_cap_bytes": oracle_cap,
        "original_pcs_zk_budget_bytes": PCS_ZK_BUDGET_BYTES,
        "envelope_cap_bytes": envelope_cap,
        "envelope_overhead_bytes": LIGERITO_ENVELOPE_BYTES,
        "q_rule": "ceil(264 / -log2(2^(-rate/2) + 1/256))",
        "committed_symbol": "B128",
        "challenge_field": "E384 = B128[Y]/(Y^3+Y+1)",
        "e384_real_field": e384_cubic_is_irreducible(),
        "commitment_hash": "SHAKE256-512, length-framed",
        "random_mask_in_place": True,
        "mask_serialized_bytes": 0,
        "append_only_mask_rows": False,
        "binding_under_shake_assumption": True,
        "binding_target": "masked low-degree codeword, not an unmasked witness",
        "source_witness_binding_theorem": False,
        "hiding_for_toy_affine_fiber": True,
        "relation": "coefficient lane 0 equals lane 1; opened E384 discrepancy is zero",
        "mask_distribution_assumption": (
            "uniform relation-kernel masks modeled by a domain-separated "
            "SHAKE PRF; finite-seed expansion is computational, not a "
            "statistical-uniformity theorem"
        ),
        "simulator_coupling_exact_for_abstract_uniform_kernel": True,
        "finite_seed_uniformity_theorem": False,
        "relation_soundness_theorem": False,
        "simulator_target_executable": True,
        "complete_zk_simulator_proved": False,
        "qrom_composed": False,
        "trusted_setup": False,
        "pairings": False,
        "aggregation": False,
        "by_n": by_n,
        "best_overall": all_records[0],
        "strict_admitted": False,
        "claim_ceiling": (
            "exact source-only byte model and toy affine-fiber simulator; the "
            "algebraic transcript formula is proposal-level until a complete "
            "Ligero/Ligerito reduction and verifier refinement are supplied"
        ),
    }


def report() -> dict[str, object]:
    params = strict_params()
    compact = compact_target_plan()
    concrete = {
        "header_bytes": HEADER_BYTES,
        "root_bytes": DIGEST_BYTES,
        "opened_b128_symbol_bytes": params.opened_symbol_bytes,
        "frontier_nodes": params.frontier_nodes,
        "frontier_bytes": params.authentication_bytes,
        "vector_opening_bytes": params.vector_opening_bytes,
        "budget_bytes": PCS_ZK_BUDGET_BYTES,
        "over_budget_bytes": params.vector_opening_bytes - PCS_ZK_BUDGET_BYTES,
        "binding_under_shake_assumption": True,
        "hiding": False,
        "complete_zk": False,
        "exact_no_go": params.vector_opening_bytes > PCS_ZK_BUDGET_BYTES,
        "no_go_reason": (
            "the canonical SHAKE Merkle opening must carry 68*32 B128 row symbols "
            "and the exact worst-case 740-node frontier before any algebraic ZK bytes"
        ),
    }
    mask_bytes = params.opened_symbol_bytes
    masked = {
        "explicit_mask_bytes": mask_bytes,
        "wire_bytes_if_masks_are_sent": params.vector_opening_bytes + mask_bytes,
        "source_recoverable": True,
        "hiding": False,
        "binding": True,
        "exact_no_go": params.vector_opening_bytes + mask_bytes > PCS_ZK_BUDGET_BYTES,
        "no_go_reason": (
            "revealing a one-time pad with a masked row reveals the source row; "
            "omitting it authenticates only the masked vector"
        ),
    }
    return {
        "claim_ceiling": (
            "executable toy plus exact wire/no-go model; no complete PCS, ZK theorem, "
            "QROM composition, or production proof artifact"
        ),
        "assumptions": {
            "committed_field": "B128 = GF(2)[X]/(X^128+X^7+X^2+X+1)",
            "challenge_field": "E384 = B128[Y]/(Y^3+Y+1)",
            "e384_is_real_field": e384_cubic_is_irreducible(),
            "product_ring_negative_control": product_ring_zero_divisor_counterexample(),
            "commitment_and_fiat_shamir": "SHAKE256-512 for FS; SHAKE256-448 for Merkle nodes; all domain-separated and length-framed",
            "merkle_node_bytes": MERKLE_DIGEST_BYTES,
            "fiat_shamir_digest_bytes": FS_DIGEST_BYTES,
            "query_security_model": "Johnson query term with rho=2^-8, eta=1/256",
            "q_budget": _strict_query_budget(),
            "setup_bytes": 0,
            "pairing_operations": 0,
            "aggregation": False,
            "production_oracle_allocated": False,
            "full_m4_source_revision": M4_SOURCE_REVISION,
            "full_m4_private_transport_b128_symbols": M4_TRANSPORT_B128_SYMBOLS,
            "full_m4_active_trace_symbols_frozen": False,
            "full_m4_e384_mask_coordinates": M4_E384_MASK_COORDINATES,
        },
        "geometry": {
            "veil_mixed_field_raw_bytes": VEIL_MIXED_FIELD_RAW_BYTES,
            "raw_proof_cap_bytes": RAW_PROOF_CAP_BYTES,
            "remaining_pcs_zk_budget_bytes": PCS_ZK_BUDGET_BYTES,
            "strict": asdict(params),
            "encoded_oracle_bytes": params.encoded_oracle_bytes,
        },
        "n15_fixed_32_lane_screen": fixed_lane_n15_screen(),
        "n15ish_concrete_opening": n15ish_concrete_opening(),
        "hash_only_share_screen": hash_only_share_screen(),
        "hash_only_share_geometry_search": hash_only_share_geometry_search(),
        "hash_only_two_share_lower_bound": hash_only_two_share_lower_bound(),
        "non_merkle_hash_screen": non_merkle_hash_screen(),
        "m4_constraint_inventory": asdict(m4_constraint_inventory()),
        "full_m4_masked_production_search": full_m4_masked_production_search(),
        "ghash_sq256b_two_rep_screen": ghash_sq256b_two_rep_screen(),
        "hash_collision_multi_target_ledger": hash_collision_multi_target_ledger(),
        "legacy_affine_in_place_negative_control": in_place_production_search(),
        "concrete_merkle_opening": concrete,
        "masked_merkle_attempt": masked,
        "compact_target": compact,
        "strict_admitted": False,
        "blocking_reasons": [
            "the concrete Merkle opening is over the PCS+ZK budget before ZK bytes",
            "the concrete opening reveals B128 symbols and is not hiding",
            "the 128-byte/query compact record has no implemented transparent binding",
            "the simulator is a programmable-ROM target, not a complete proof",
            "the old affine lane mask is rejected: full M4 has nonlinear BitAnd constraints and E384 masks have three B128 coordinates",
            "the full-M4 [pi||omega] alpha/sigma model leaves nonlinear BitAnd cross terms and compiled trace dimensions unproved",
            "the GhashSq256b two-repetition screen has only a conservative 136-bit composition margin and no independence/QROM theorem",
            "no composed PQ/QROM failure ledger or independent verifier artifact exists",
        ],
    }


def run_toy_check() -> dict[str, object]:
    params = toy_params()
    context = shake512(b"HVBPCS/toy/context/v1")[:PUBLIC_CONTEXT_BYTES]
    source = deterministic_source(params)
    encoded = prove(source, params, context)
    parsed = MerkleVectorProof.parse(encoded, params)
    if parsed.serialize(params) != encoded:
        raise AssertionError("toy parse/serialize roundtrip failed")
    if not verify(encoded, params, context):
        raise AssertionError("honest toy proof did not verify")
    simulator = simulate_algebraic_target(
        params,
        context,
        parsed.root,
        shake512(b"HVBPCS/toy/simulator-seed/v1")[:32],
    )
    if not simulator.source_independent or simulator.wire_bytes != (
        ALGEBRAIC_ZK_TARGET_MESSAGES * E384_BYTES
    ):
        raise AssertionError("simulator target shape drift")
    if len(simulator.serialize()) != simulator.wire_bytes:
        raise AssertionError("simulator serialization drift")
    if not e384_cubic_is_irreducible():
        raise AssertionError("E384 cubic irreducibility check failed")
    if not product_ring_zero_divisor_counterexample():
        raise AssertionError("product-ring negative control failed")
    statement = bytes(M4_PUBLIC_BYTES)
    derived_intent = tuple(0 for _ in range(M4_DERIVED_INTENT_WORDS))
    private_words = tuple(0 for _ in range(M4_PRIVATE_WORDS))
    source_transcript = m4_source_bound_transcript(
        statement,
        derived_intent,
        private_words,
        bitand_samples=((0xAA, 0x0F, 0x0A),),
        shift_samples=((0x10, 2, 0x40, "left"),),
    )
    if len(source_transcript.private_transport_symbols) != M4_TRANSPORT_B128_SYMBOLS:
        raise AssertionError("M4 private transport packing drift")
    if not source_transcript.bitand_samples_valid or not source_transcript.shift_samples_valid:
        raise AssertionError("M4 source-bound primitive probes failed")
    if not m4_masked_bitand_holds(0xAA, 0x0F, 0x0A, 0x55, 0x03, 0x0A ^ (0xAA & 0x03) ^ (0x55 & 0x0F) ^ (0x55 & 0x03)):
        raise AssertionError("M4 masked BitAnd cross-term expansion failed")
    joint_source = tuple(0 for _ in range(1 << params.log_relation_size))
    joint_coins = shake512(b"HVBPCS/toy/joint-mask-coins/v1")[:32]
    joint_proof = prove_joint_mask_toy(
        joint_source, params, context, joint_coins
    )
    if not verify_joint_mask_toy(joint_proof, params, context):
        raise AssertionError("joint [pi||omega] toy proof did not verify")
    joint_parsed = JointMaskProof.parse(joint_proof, params)
    if joint_parsed.serialize(params) != joint_proof:
        raise AssertionError("joint parser/serializer roundtrip failed")
    return {
        "verified": True,
        "proof_bytes": len(encoded),
        "formula_bytes": params.vector_opening_bytes,
        "encoded_oracle_bytes": params.encoded_oracle_bytes,
        "e384_real_field": True,
        "simulator_target_bytes": simulator.wire_bytes,
        "simulator_source_independent": simulator.source_independent,
        "m4_source_bound_probe": True,
        "m4_transport_b128_symbols": len(source_transcript.private_transport_symbols),
        "m4_keccak_bitand_constraints": M4_KECCAK_BITAND_CONSTRAINTS,
        "joint_mask_verified": True,
        "joint_mask_proof_bytes": len(joint_proof),
        "joint_mask_formula_bytes": joint_mask_toy_wire_bytes(params),
        "joint_mask_merkle_node_bytes": MERKLE_DIGEST_BYTES,
        "joint_mask_e384_coordinates": M4_E384_MASK_COORDINATES,
        "full_m4_nonlinear_theorem": False,
        "strict_admitted": False,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--toy-check",
        action="store_true",
        help="run the tiny allocated Merkle proof and simulator-shape check",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the production-size exact no-go and compact target report",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.toy_check and not args.report:
        raise SystemExit("pass --toy-check or --report; refusing implicit work")
    output: dict[str, object] = {}
    if args.toy_check:
        output["toy"] = run_toy_check()
    if args.report:
        output["report"] = report()
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
