#!/usr/bin/env python3
"""Dependency-free audit of a characteristic-two HVZK sumcheck kernel.

Passing this checker establishes exact local algebra and distribution facts.
It deliberately does not establish a binding PCS, a complete simulator, a
Fiat--Shamir/QROM theorem, or a production proof-size point.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Callable, Iterable, Sequence, TypeVar


T = TypeVar("T")
Add = Callable[[T, T], T]
Mul = Callable[[T, T], T]


@dataclass(frozen=True)
class BinaryField:
    """Polynomial-basis GF(2^m) with an implicit x^m modulus term."""

    bits: int
    reduction: int

    @property
    def order(self) -> int:
        return 1 << self.bits

    @property
    def mask(self) -> int:
        return self.order - 1

    def add(self, left: int, right: int) -> int:
        return (left ^ right) & self.mask

    def mul(self, left: int, right: int) -> int:
        left &= self.mask
        right &= self.mask
        product = 0
        for _ in range(self.bits):
            if right & 1:
                product ^= left
            carry = left >> (self.bits - 1)
            left = (left << 1) & self.mask
            if carry:
                left ^= self.reduction
            right >>= 1
        return product

    def pow(self, value: int, exponent: int) -> int:
        result = 1
        while exponent:
            if exponent & 1:
                result = self.mul(result, value)
            value = self.mul(value, value)
            exponent >>= 1
        return result


GF4 = BinaryField(bits=2, reduction=0b11)  # x^2 + x + 1
GF8 = BinaryField(bits=3, reduction=0b011)  # x^3 + x + 1
B128 = BinaryField(bits=128, reduction=0x87)
E384 = tuple[int, int, int]
E_ZERO: E384 = (0, 0, 0)
E_ONE: E384 = (1, 0, 0)
E_Y: E384 = (0, 1, 0)
E_Y2: E384 = (0, 0, 1)


def e_add(left: E384, right: E384) -> E384:
    return tuple(a ^ b for a, b in zip(left, right, strict=True))  # type: ignore[return-value]


def e_mul(left: E384, right: E384) -> E384:
    product = [0] * 5
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            product[i + j] ^= B128.mul(a, b)
    # Y^3 = Y + 1 modulo Y^3 + Y + 1.  Reduce degree four first.
    for degree in (4, 3):
        high = product[degree]
        product[degree] = 0
        product[degree - 2] ^= high
        product[degree - 3] ^= high
    return (product[0], product[1], product[2])


def e_from_label(label: str) -> E384:
    raw = hashlib.shake_256(label.encode("utf-8")).digest(48)
    return tuple(
        int.from_bytes(raw[offset : offset + 16], "little")
        for offset in (0, 16, 32)
    )  # type: ignore[return-value]


def poly_eval(coefficients: Sequence[T], point: T, add: Add[T], mul: Mul[T], zero: T) -> T:
    result = zero
    for coefficient in reversed(coefficients):
        result = add(mul(result, point), coefficient)
    return result


def endpoint_sum(coefficients: Sequence[T], one: T, add: Add[T], mul: Mul[T], zero: T) -> T:
    return add(coefficients[0], poly_eval(coefficients, one, add, mul, zero))


def mask_quadratic(
    honest: Sequence[T], incoming_delta: T, constant_mask: T, z_mask: T, add: Add[T]
) -> tuple[T, T, T]:
    if len(honest) != 3:
        raise ValueError("quadratic coefficients required")
    # g + Delta*X + a + b*(X^2+X)
    return (
        add(honest[0], constant_mask),
        add(add(honest[1], incoming_delta), z_mask),
        add(honest[2], z_mask),
    )


def mask_linear(honest: Sequence[T], incoming_delta: T, constant_mask: T, add: Add[T]) -> tuple[T, T]:
    if len(honest) != 2:
        raise ValueError("linear coefficients required")
    return (add(honest[0], constant_mask), add(honest[1], incoming_delta))


def next_delta_linear(
    incoming_delta: T, point: T, constant_mask: T, add: Add[T], mul: Mul[T]
) -> T:
    return add(mul(incoming_delta, point), constant_mask)


def next_delta(
    incoming_delta: T,
    point: T,
    constant_mask: T,
    z_mask: T,
    add: Add[T],
    mul: Mul[T],
    one: T,
) -> T:
    z_at_point = mul(point, add(point, one))
    return add(add(mul(incoming_delta, point), constant_mask), mul(z_mask, z_at_point))


def encode_quadratic_round(coefficients: Sequence[E384], current_claim: E384) -> bytes:
    if len(coefficients) != 3:
        raise ValueError("quadratic coefficients required")
    if e_add(coefficients[1], coefficients[2]) != current_claim:
        raise ValueError("round does not match current claim")
    return e_to_bytes(coefficients[0]) + e_to_bytes(coefficients[1])


def decode_quadratic_round(payload: bytes, current_claim: E384) -> tuple[E384, E384, E384]:
    if len(payload) != 96:
        raise ValueError("canonical quadratic round is exactly 96 bytes")
    c0 = e_from_bytes(payload[:48])
    c1 = e_from_bytes(payload[48:])
    # In characteristic two, current_claim = c1 + c2; the two c0 terms cancel.
    c2 = e_add(current_claim, c1)
    return (c0, c1, c2)


def encode_linear_round(coefficients: Sequence[E384], current_claim: E384) -> bytes:
    if len(coefficients) != 2:
        raise ValueError("linear coefficients required")
    if coefficients[1] != current_claim:
        raise ValueError("linear round does not match current claim")
    return e_to_bytes(coefficients[0])


def decode_linear_round(payload: bytes, current_claim: E384) -> tuple[E384, E384]:
    if len(payload) != 48:
        raise ValueError("canonical linear round is exactly 48 bytes")
    return (e_from_bytes(payload), current_claim)


def e_to_bytes(value: E384) -> bytes:
    return b"".join(coefficient.to_bytes(16, "little") for coefficient in value)


def e_from_bytes(raw: bytes) -> E384:
    if len(raw) != 48:
        raise ValueError("E384 encoding is exactly 48 bytes")
    return tuple(
        int.from_bytes(raw[offset : offset + 16], "little")
        for offset in (0, 16, 32)
    )  # type: ignore[return-value]


def bivariate_eval(coefficients: Sequence[Sequence[int]], x: int, y: int) -> int:
    by_y = [poly_eval(column, x, GF4.add, GF4.mul, 0) for column in zip(*coefficients, strict=True)]
    return poly_eval(by_y, y, GF4.add, GF4.mul, 0)


def first_round(coefficients: Sequence[Sequence[int]]) -> tuple[int, int, int]:
    # Sum f(X,y) over y in {0,1} coefficient by coefficient.
    out = []
    for x_degree in range(3):
        column = coefficients[x_degree]
        at_zero = column[0]
        at_one = poly_eval(column, 1, GF4.add, GF4.mul, 0)
        out.append(GF4.add(at_zero, at_one))
    return tuple(out)  # type: ignore[return-value]


def second_round(coefficients: Sequence[Sequence[int]], x: int) -> tuple[int, int, int]:
    out = []
    for y_degree in range(3):
        column = [coefficients[x_degree][y_degree] for x_degree in range(3)]
        out.append(poly_eval(column, x, GF4.add, GF4.mul, 0))
    return tuple(out)  # type: ignore[return-value]


def transcript_distribution(
    coefficients: Sequence[Sequence[int]], reveal_terminal_delta: bool
) -> Counter[tuple[object, ...]]:
    distribution: Counter[tuple[object, ...]] = Counter()
    g1 = first_round(coefficients)
    elements = range(GF4.order)
    for a1, b1, a2, b2 in itertools.product(elements, repeat=4):
        q1 = mask_quadratic(g1, 0, a1, b1, GF4.add)
        for r1 in elements:
            delta1 = next_delta(0, r1, a1, b1, GF4.add, GF4.mul, 1)
            g2 = second_round(coefficients, r1)
            assert endpoint_sum(g2, 1, GF4.add, GF4.mul, 0) == poly_eval(
                g1, r1, GF4.add, GF4.mul, 0
            )
            q2 = mask_quadratic(g2, delta1, a2, b2, GF4.add)
            assert endpoint_sum(q2, 1, GF4.add, GF4.mul, 0) == poly_eval(
                q1, r1, GF4.add, GF4.mul, 0
            )
            for r2 in elements:
                delta2 = next_delta(delta1, r2, a2, b2, GF4.add, GF4.mul, 1)
                terminal = poly_eval(q2, r2, GF4.add, GF4.mul, 0)
                assert terminal == GF4.add(bivariate_eval(coefficients, r1, r2), delta2)
                key: tuple[object, ...] = (q1, r1, q2, r2, terminal)
                if reveal_terminal_delta:
                    key += (delta2,)
                distribution[key] += 1
    return distribution


def total_variation(left: Counter[object], right: Counter[object]) -> Fraction:
    left_total = sum(left.values())
    right_total = sum(right.values())
    if left_total != right_total:
        raise ValueError("distribution masses differ")
    numerator = sum(abs(left[key] - right[key]) for key in left.keys() | right.keys())
    return Fraction(numerator, 2 * left_total)


def translated_constant(coefficients: Sequence[Sequence[int]], translation: int) -> list[list[int]]:
    out = [list(row) for row in coefficients]
    out[0][0] ^= translation
    return out


def one_round_distribution(
    honest: tuple[int, int, int], masks: Iterable[tuple[int, int]]
) -> Counter[tuple[int, int, int]]:
    return Counter(mask_quadratic(honest, 0, a, b, lambda x, y: x ^ y) for a, b in masks)


def paired_distribution(
    first: tuple[int, int, int],
    second: tuple[int, int, int],
    reuse_constant_mask: bool,
    reuse_z_mask: bool,
) -> Counter[tuple[tuple[int, int, int], tuple[int, int, int]]]:
    elements = range(GF4.order)
    out: Counter[tuple[tuple[int, int, int], tuple[int, int, int]]] = Counter()
    for a1, b1, a2, b2 in itertools.product(elements, repeat=4):
        if reuse_constant_mask and a2 != a1:
            continue
        if reuse_z_mask and b2 != b1:
            continue
        out[(
            mask_quadratic(first, 0, a1, b1, GF4.add),
            mask_quadratic(second, 0, a2, b2, GF4.add),
        )] += 1
    return out


def exhaustive_small_field_tests() -> dict[str, str | int]:
    # Field sanity, including inverses.
    for field in (GF4, GF8):
        for left, right, third in itertools.product(range(field.order), repeat=3):
            assert field.mul(left, right) == field.mul(right, left)
            assert field.mul(left, field.add(right, third)) == field.add(
                field.mul(left, right), field.mul(left, third)
            )
        for value in range(1, field.order):
            assert field.mul(value, field.pow(value, field.order - 2)) == 1

    # a + b Z is exactly the complete kernel fiber, not merely a subset.
    elements = range(GF4.order)
    all_quadratics = list(itertools.product(elements, repeat=3))
    fiber_checks = 0
    linear_fiber_checks = 0
    all_linears = list(itertools.product(elements, repeat=2))
    for honest in all_linears:
        for incoming_delta in elements:
            target = GF4.add(
                endpoint_sum(honest, 1, GF4.add, GF4.mul, 0), incoming_delta
            )
            produced = {
                mask_linear(honest, incoming_delta, a, GF4.add)
                for a in elements
            }
            expected = {
                candidate
                for candidate in all_linears
                if endpoint_sum(candidate, 1, GF4.add, GF4.mul, 0) == target
            }
            assert produced == expected
            assert len(produced) == GF4.order
            linear_fiber_checks += 1

    for honest in all_quadratics:
        for incoming_delta in elements:
            target = GF4.add(
                endpoint_sum(honest, 1, GF4.add, GF4.mul, 0), incoming_delta
            )
            produced = {
                mask_quadratic(honest, incoming_delta, a, b, GF4.add)
                for a, b in itertools.product(elements, repeat=2)
            }
            expected = {
                candidate
                for candidate in all_quadratics
                if endpoint_sum(candidate, 1, GF4.add, GF4.mul, 0) == target
            }
            assert produced == expected
            assert len(produced) == GF4.order**2
            fiber_checks += 1

    witness0 = [[1, 2, 3], [3, 1, 0], [2, 3, 1]]
    witness1 = translated_constant(witness0, 1)
    assert endpoint_sum(first_round(witness0), 1, GF4.add, GF4.mul, 0) == endpoint_sum(
        first_round(witness1), 1, GF4.add, GF4.mul, 0
    )
    visible_tv = total_variation(
        transcript_distribution(witness0, False), transcript_distribution(witness1, False)
    )
    revealed_delta_tv = total_variation(
        transcript_distribution(witness0, True), transcript_distribution(witness1, True)
    )
    assert visible_tv == 0
    assert revealed_delta_tv == 1

    # Omitting the constant mask leaves q(0)'s constant coefficient exposed.
    z_only_masks = ((0, b) for b in elements)
    z_only_left = one_round_distribution((0, 0, 0), z_only_masks)
    z_only_right = one_round_distribution((1, 0, 0), ((0, b) for b in elements))
    assert total_variation(z_only_left, z_only_right) == 1

    # GF(2)-only masks inside GF(8) have disjoint support after an x translation.
    base_masks = list(itertools.product((0, 1), repeat=2))
    restricted_left = one_round_distribution((0, 0, 0), base_masks)
    restricted_right = one_round_distribution((2, 0, 0), base_masks)
    assert total_variation(restricted_left, restricted_right) == 1

    # Fresh masks eliminate a parallel secret difference; mask reuse exposes it.
    first = (0, 1, 0)
    second0 = (2, 1, 0)
    second1 = (3, 1, 0)
    assert endpoint_sum(second0, 1, GF4.add, GF4.mul, 0) == endpoint_sum(
        second1, 1, GF4.add, GF4.mul, 0
    )
    assert total_variation(
        paired_distribution(first, second0, False, False),
        paired_distribution(first, second1, False, False),
    ) == 0
    assert total_variation(
        paired_distribution(first, second0, True, False),
        paired_distribution(first, second1, True, False),
    ) == 1
    second_z_shift = (2, 0, 1)
    assert endpoint_sum(second0, 1, GF4.add, GF4.mul, 0) == endpoint_sum(
        second_z_shift, 1, GF4.add, GF4.mul, 0
    )
    assert total_variation(
        paired_distribution(first, second0, False, False),
        paired_distribution(first, second_z_shift, False, False),
    ) == 0
    assert total_variation(
        paired_distribution(first, second0, False, True),
        paired_distribution(first, second_z_shift, False, True),
    ) == 1

    # Unbound terminal delta makes a false public sum satisfiable.
    false_polynomial = (0, 1, 0)  # f(0)+f(1)=1
    claimed_sum = 0
    forged_round = (0, 0, 0)  # endpoint sum matches the false claim
    challenge = 1
    unbound_delta = GF4.add(
        poly_eval(forged_round, challenge, GF4.add, GF4.mul, 0),
        poly_eval(false_polynomial, challenge, GF4.add, GF4.mul, 0),
    )
    assert endpoint_sum(false_polynomial, 1, GF4.add, GF4.mul, 0) != claimed_sum
    assert endpoint_sum(forged_round, 1, GF4.add, GF4.mul, 0) == claimed_sum
    assert poly_eval(forged_round, challenge, GF4.add, GF4.mul, 0) == GF4.add(
        poly_eval(false_polynomial, challenge, GF4.add, GF4.mul, 0), unbound_delta
    )

    return {
        "linear_affine_fibers_exhausted": linear_fiber_checks,
        "quadratic_affine_fibers_exhausted": fiber_checks,
        "two_round_constant_translation_visible_tv": str(visible_tv),
        "revealed_terminal_delta_constant_translation_tv": str(revealed_delta_tv),
        "missing_constant_mask_tv": "1",
        "proper_subfield_mask_tv": "1",
        "reused_constant_mask_tv": "1",
        "reused_z_mask_tv": "1",
        "unbound_terminal_false_sum_accepts": "true",
    }


def randomized_mixed_field_tests(cases: int = 192) -> dict[str, str | int]:
    # Pin the two reduction identities used by the strict arithmetic prototype.
    assert B128.mul(1 << 127, 2) == 0x87
    assert e_mul(E_Y, E_Y2) == e_add(E_ONE, E_Y)

    for index in range(cases):
        honest = tuple(e_from_label(f"case:{index}:g:{j}") for j in range(3))
        incoming = e_from_label(f"case:{index}:delta")
        a = e_from_label(f"case:{index}:a")
        b = e_from_label(f"case:{index}:b")
        point = e_from_label(f"case:{index}:r")
        masked = mask_quadratic(honest, incoming, a, b, e_add)
        expected_sum = e_add(endpoint_sum(honest, E_ONE, e_add, e_mul, E_ZERO), incoming)
        assert endpoint_sum(masked, E_ONE, e_add, e_mul, E_ZERO) == expected_sum
        delta = next_delta(incoming, point, a, b, e_add, e_mul, E_ONE)
        assert poly_eval(masked, point, e_add, e_mul, E_ZERO) == e_add(
            poly_eval(honest, point, e_add, e_mul, E_ZERO), delta
        )
        # The affine-fiber map is injective and its masks recover uniquely.
        recovered_a = e_add(masked[0], honest[0])
        recovered_b = e_add(masked[2], honest[2])
        assert recovered_a == a
        assert recovered_b == b
        assert masked[1] == e_add(e_add(honest[1], incoming), recovered_b)

        payload = encode_quadratic_round(masked, expected_sum)
        assert len(payload) == 96
        assert decode_quadratic_round(payload, expected_sum) == masked
        assert e_from_bytes(e_to_bytes(a)) == a

        linear_honest = honest[:2]
        linear_masked = mask_linear(linear_honest, incoming, a, e_add)
        linear_sum = e_add(
            endpoint_sum(linear_honest, E_ONE, e_add, e_mul, E_ZERO), incoming
        )
        assert endpoint_sum(linear_masked, E_ONE, e_add, e_mul, E_ZERO) == linear_sum
        linear_delta = next_delta_linear(incoming, point, a, e_add, e_mul)
        assert poly_eval(linear_masked, point, e_add, e_mul, E_ZERO) == e_add(
            poly_eval(linear_honest, point, e_add, e_mul, E_ZERO), linear_delta
        )
        linear_payload = encode_linear_round(linear_masked, linear_sum)
        assert len(linear_payload) == 48
        assert decode_linear_round(linear_payload, linear_sum) == linear_masked

    # Embedded B128 is a proper one-dimensional coefficient subspace of E384.
    # If Y+b0=b1 for embedded b0,b1, then Y=b0+b1 would be embedded, contradicting
    # its nonzero Y coefficient.  Hence the two cosets are disjoint (TV=1).
    assert E_Y[1] == 1 and E_Y[2] == 0
    assert all(e_add(E_Y, (value, 0, 0))[1] == 1 for value in (0, 1, 0x87, 1 << 127))

    return {
        "deterministic_e384_cases": cases,
        "b128_modulus_kat": "pass",
        "e384_y_times_y2_kat": "pass",
        "e384_round_encoding_bytes": 96,
        "e384_linear_round_encoding_bytes": 48,
        "b128_only_mask_cosets_disjoint": "proved",
    }


def expected_certificate() -> dict[str, object]:
    return {
        "artifact": "characteristic-two-hvzk-sumcheck-kernel",
        "scope": "local-degree-aware-linear-and-quadratic-round-view-only",
        "small_field": exhaustive_small_field_tests(),
        "mixed_field": randomized_mixed_field_tests(),
        "construction": {
            "field": "E384=GF(2^128)[Y]/(Y^3+Y+1)",
            "z_polynomial": "X*(X+1)=X^2+X",
            "round_mask": "a_i+b_i*Z(X)",
            "incoming_offset": "Delta_(i-1)*X",
            "delta_recurrence": "Delta_i=Delta_(i-1)*r_i+a_i+b_i*Z(r_i)",
            "fresh_full_extension_masks_per_quadratic_round": 2,
            "fresh_full_extension_masks_per_linear_round": 1,
            "fresh_full_extension_masks_for_degree_d": "d",
        },
        "wire": {
            "e384_bytes": 48,
            "dense_three_coefficient_bytes_per_round": 144,
            "explicit_e384_elements_per_quadratic_round": 2,
            "visible_bytes_per_quadratic_round": 96,
            "visible_bytes_formula": "96*rounds",
            "mixed_degree_visible_bytes_formula": "48*linear_rounds+96*quadratic_rounds",
            "quadratic_round_wire_coefficients": ["c0", "c1"],
            "reconstructed_coefficient": "c2=current_claim+c1",
            "consistency_elision_bytes_per_round": 48,
            "n15_visible_bytes": 1440,
            "private_randomness_bytes_per_round": 96,
            "n15_private_randomness_bytes": 1440,
            "explicit_terminal_delta_bytes": 0,
            "forbidden_revealed_terminal_delta_bytes": 48,
            "raw_hidden_mask_material_formula": "96*rounds",
            "mixed_degree_hidden_mask_material_formula": "48*linear_rounds+96*quadratic_rounds",
            "binding_commitment_and_opening_bytes": None,
            "qualifying_complete_proof_bytes": None,
        },
        "claims": {
            "local_perfect_hiding": True,
            "round_consistency_preserved": True,
            "full_extension_masks_required": True,
            "fresh_independent_masks_required": True,
            "terminal_delta_must_remain_hidden": True,
            "mask_source_must_be_bound_before_challenges": True,
            "e384_irreducibility_reproved_here": False,
            "sound_binding_implemented": False,
            "complete_zk": False,
            "fiat_shamir_qrom": False,
            "strict_pq128": False,
            "frontier_eligible": False,
        },
        "open_obligations": [
            "bind a zero-sum mask polynomial or all round-mask coins before challenges",
            "import the separate E384 irreducibility certificate",
            "prove the hidden terminal relation against the committed witness",
            "open only the combined masked terminal value",
            "jointly simulate commitments, PCS openings, FRI, Merkle, and outer Spartan",
            "prove the Fiat--Shamir/QROM composition and exact abort conditioning",
            "price the binding/hiding PCS rather than treating local zero overhead as complete",
        ],
    }


def main() -> None:
    certificate = expected_certificate()
    certificate_path = Path(__file__).with_name("certificate.json")
    if certificate_path.exists():
        committed = json.loads(certificate_path.read_text(encoding="utf-8"))
        if committed != certificate:
            raise SystemExit("certificate.json does not match executable audit")
    print("LOCAL_KERNEL_PASS")
    print(json.dumps(certificate, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
