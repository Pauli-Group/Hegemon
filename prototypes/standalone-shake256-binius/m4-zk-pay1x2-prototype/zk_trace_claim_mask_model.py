#!/usr/bin/env python3
"""Executable algebra and admission gate for masking one clear M4 trace claim.

This is not a zero-knowledge proof.  It specifies the narrow structural repair
that may be used only after the trace oracle itself is committed/opened by an
independently hiding PCS.  The repair masks one otherwise-clear multilinear
evaluation claim with a fresh pre-challenge constant and fails closed for any
additional clear witness-dependent claim or unsupported circuit shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence


B128_BITS = 128
B128_MASK = (1 << B128_BITS) - 1
B128_REDUCTION = 0x87
MASK_CONTEXT_DOMAIN = b"hegemon.m4.zk-trace-claim-mask.v1"


def add(left: int, right: int) -> int:
    if not 0 <= left <= B128_MASK or not 0 <= right <= B128_MASK:
        raise ValueError("non-canonical B128 element")
    return left ^ right


def mul(left: int, right: int) -> int:
    if not 0 <= left <= B128_MASK or not 0 <= right <= B128_MASK:
        raise ValueError("non-canonical B128 element")
    result = 0
    multiplicand = left
    multiplier = right
    for _ in range(B128_BITS):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        carry = multiplicand >> 127
        multiplicand = (multiplicand << 1) & B128_MASK
        if carry:
            multiplicand ^= B128_REDUCTION
    return result


def eq_basis(point: Sequence[int]) -> tuple[int, ...]:
    """Return chi_r(x) in low-bit-first Boolean-hypercube order."""

    basis = [1]
    for coordinate in point:
        if not 0 <= coordinate <= B128_MASK:
            raise ValueError("non-canonical evaluation coordinate")
        next_basis = [0] * (2 * len(basis))
        for index, value in enumerate(basis):
            next_basis[index] = mul(value, add(1, coordinate))
            next_basis[index + len(basis)] = mul(value, coordinate)
        basis = next_basis
    return tuple(basis)


def inner_product(left: Sequence[int], right: Sequence[int]) -> int:
    if len(left) != len(right):
        raise ValueError("inner-product length mismatch")
    result = 0
    for a, b in zip(left, right):
        result = add(result, mul(a, b))
    return result


def evaluate(trace: Sequence[int], point: Sequence[int]) -> int:
    if len(trace) != 1 << len(point):
        raise ValueError("trace/evaluation geometry mismatch")
    return inner_product(trace, eq_basis(point))


def shift_trace(trace: Sequence[int], key: int) -> tuple[int, ...]:
    if not 0 <= key <= B128_MASK:
        raise ValueError("non-canonical mask key")
    return tuple(add(value, key) for value in trace)


def masked_claim(trace: Sequence[int], point: Sequence[int], key: int) -> int:
    """The public shifted claim c = <trace, chi_r> + key."""

    return add(evaluate(trace, point), key)


def verify_shift_identity(
    trace: Sequence[int], point: Sequence[int], key: int, claim: int
) -> bool:
    """Check the exact relation the outer proof must enforce internally."""

    shifted = shift_trace(trace, key)
    return evaluate(shifted, point) == claim == masked_claim(trace, point, key)


@dataclass(frozen=True)
class ClearClaimInventory:
    """Compile-time inventory required before the narrow transform is legal."""

    main_trace_equality_claims: int
    other_witness_dependent_clear_claims: int
    numbered_chips: int
    lookup_or_table_relations: int
    trace_pcs_hiding_proved: bool

    def rejection_reasons(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if self.main_trace_equality_claims != 1:
            reasons.append("requires exactly one main trace equality-evaluation claim")
        if self.other_witness_dependent_clear_claims != 0:
            reasons.append("another witness-dependent clear claim remains")
        if self.numbered_chips != 0:
            reasons.append("numbered chips are outside the proved single-main shape")
        if self.lookup_or_table_relations != 0:
            reasons.append("lookup/table relations require independent full-rank masks")
        if not self.trace_pcs_hiding_proved:
            reasons.append("constant claim masking cannot replace a hiding trace PCS")
        return tuple(reasons)

    @property
    def eligible(self) -> bool:
        return not self.rejection_reasons()


def derive_test_key(master_entropy: bytes, statement_digest: bytes, proof_nonce: bytes) -> int:
    """Deterministic test-only key derivation with explicit reuse boundaries.

    Production must start from fresh OS entropy for every proof.  Statement and
    nonce binding prevents accidental deterministic-test reuse from being
    mistaken for an admissible production RNG interface.
    """

    if len(master_entropy) < 32:
        raise ValueError("test master entropy must be at least 256 bits")
    if len(statement_digest) != 64:
        raise ValueError("statement digest must be SHAKE256-512 sized")
    if len(proof_nonce) != 32:
        raise ValueError("proof nonce must be exactly 32 bytes")
    framed = bytearray(MASK_CONTEXT_DOMAIN)
    for value in (master_entropy, statement_digest, proof_nonce):
        framed.extend(len(value).to_bytes(4, "big"))
        framed.extend(value)
    return int.from_bytes(hashlib.shake_256(bytes(framed)).digest(16), "little")


def release_gate(inventory: ClearClaimInventory) -> dict[str, object]:
    """Return a fail-closed capability record for the production frontier."""

    return {
        "algebraic_shift_identity": True,
        "claim_inventory_eligible": inventory.eligible,
        "rejection_reasons": list(inventory.rejection_reasons()),
        "simulator_theorem": False,
        "rng_nonreuse_evidence": False,
        "maximum_relation_compiler_inventory": False,
        "complete_zero_knowledge": False,
        "frontier_eligible": False,
    }

