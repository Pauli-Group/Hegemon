#!/usr/bin/env python3
"""Fail-closed assurance gate for Hegemon's fresh width-16 Poseidon2 candidate."""

from __future__ import annotations

import argparse
import functools
import hashlib
import itertools
import json
import math
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "circuits/transaction-core/src/poseidon2_width16.rs"
MANIFEST = ROOT / "config/poseidon2-width16-v1.json"
P3_REFERENCE_LOCK = ROOT / "tools/poseidon2-width16-p3-reference/Cargo.lock"

P = 0xFFFF_FFFF_0000_0001
WIDTH = 16
RATE = 8
CAPACITY = 8
DIGEST = 7
ALPHA = 7
RF = 8
RP = 22
SUITE_MARKER = 0x4845_475F_5032_3136
SPONGE_MODE_MARKER = 0x5350_4F4E_4745_5631
MAX_INPUTS = 120
M4 = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
P4 = [[2 if row == column else 1 for column in range(4)] for row in range(4)]
DOMAIN_PREFIX = b"hegemon.poseidon2.goldilocks.width16.v1\0"


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


class GrainLfsr:
    TAPS = (0, 13, 23, 38, 51, 62)

    def __init__(self) -> None:
        bits: list[int] = []
        for value, width in ((1, 2), (0, 4), (64, 12), (WIDTH, 12), (RF, 10), (RP, 10)):
            bits.extend(int(bit) for bit in f"{value:0{width}b}")
        bits.extend([1] * 30)
        require(len(bits) == 80, "Grain initialization is not 80 bits")
        self.state = bits
        for _ in range(160):
            self.clock()

    def clock(self) -> int:
        value = 0
        for tap in self.TAPS:
            value ^= self.state[tap]
        self.state = self.state[1:] + [value]
        return value

    def next_bit(self) -> int:
        while True:
            selector = self.clock()
            value = self.clock()
            if selector == 1:
                return value

    def next_field(self) -> int:
        while True:
            value = 0
            for _ in range(64):
                value = (value << 1) | self.next_bit()
            if value < P:
                return value


def canonical_round_constants() -> tuple[list[int], list[int], list[int]]:
    grain = GrainLfsr()
    initial = [grain.next_field() for _ in range(4 * WIDTH)]
    internal = [grain.next_field() for _ in range(RP)]
    terminal = [grain.next_field() for _ in range(4 * WIDTH)]
    return initial, internal, terminal


def source_hex_words(source: str, start: str, end: str) -> list[int]:
    require(start in source and end in source, f"source marker missing: {start!r} or {end!r}")
    body = source.split(start, 1)[1].split(end, 1)[0]
    return [int(word, 16) for word in re.findall(r"0x[0-9a-fA-F_]+", body)]


def extract_source_parameters(source: str) -> tuple[list[int], list[int]]:
    diag = source_hex_words(
        source,
        "pub const POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    )
    constants = source_hex_words(
        source,
        "pub const POSEIDON2_WIDTH16_ROUND_CONSTANTS",
        "#[inline(always)]\nfn sbox",
    )
    require(len(diag) == WIDTH, f"source internal diagonal has {len(diag)} words, expected 16")
    require(len(constants) == RF * WIDTH + RP, "source round-constant stream is not 150 words")
    for snippet in (
        'pub const POSEIDON2_WIDTH16_PARAMETER_SET_ID: &str = "hegemon-p2w16-v1-114a4e7eb2684d29";',
        '"114a4e7eb2684d293d13d306a756b03fc734f19edbfb80a07126ab1b2ad9e529";',
        "pub const POSEIDON2_WIDTH16_WIDTH: usize = 16;",
        "pub const POSEIDON2_WIDTH16_RATE: usize = 8;",
        "pub const POSEIDON2_WIDTH16_CAPACITY: usize = 8;",
        "pub const POSEIDON2_WIDTH16_DIGEST: usize = 7;",
        "pub const POSEIDON2_WIDTH16_ROUNDS_F: usize = 8;",
        "pub const POSEIDON2_WIDTH16_INTERNAL_ROUNDS: usize = 22;",
        "pub const POSEIDON2_WIDTH16_SPONGE_MAX_INPUTS: usize = 120;",
        "Apply the 2026/306 countermeasure orientation `M4 ⊗ P4`",
    ):
        require(snippet in source, f"source parameter drift: {snippet}")
    return diag, constants


def kron(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    left_rows, right_rows = len(left), len(right)
    return [
        [
            left[row // right_rows][column // right_rows]
            * right[row % right_rows][column % right_rows]
            % P
            for column in range(left_rows * right_rows)
        ]
        for row in range(left_rows * right_rows)
    ]


def internal_matrix(diag: list[int]) -> list[list[int]]:
    return [[((diag[row] if row == column else 0) + 1) % P for column in range(WIDTH)] for row in range(WIDTH)]


def determinant(matrix: list[list[int]]) -> int:
    work = [[value % P for value in row] for row in matrix]
    result = 1
    for column in range(len(work)):
        pivot = next((row for row in range(column, len(work)) if work[row][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            work[column], work[pivot] = work[pivot], work[column]
            result = -result
        pivot_value = work[column][column]
        result = result * pivot_value % P
        inverse = pow(pivot_value, -1, P)
        for row in range(column + 1, len(work)):
            scale = work[row][column] * inverse % P
            for index in range(column, len(work)):
                work[row][index] = (work[row][index] - scale * work[column][index]) % P
    return result % P


def m4_is_mds() -> bool:
    for size in range(1, 5):
        for rows in itertools.combinations(range(4), size):
            for columns in itertools.combinations(range(4), size):
                minor = [[M4[row][column] for column in columns] for row in rows]
                if determinant(minor) == 0:
                    return False
    return True


def matrix_mul(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    size = len(left)
    return [
        [sum(left[row][inner] * right[inner][column] for inner in range(size)) % P for column in range(size)]
        for row in range(size)
    ]


def characteristic_polynomial(matrix: list[list[int]]) -> list[int]:
    size = len(matrix)
    identity = [[int(row == column) for column in range(size)] for row in range(size)]
    power = identity
    traces: list[int] = []
    for _ in range(1, size + 1):
        power = matrix_mul(power, matrix)
        traces.append(sum(power[index][index] for index in range(size)) % P)
    coefficients = [1]
    for degree in range(1, size + 1):
        value = sum(coefficients[degree - index] * traces[index - 1] for index in range(1, degree + 1)) % P
        coefficients.append((-value * pow(degree, -1, P)) % P)
    return list(reversed(coefficients))


def poly_trim(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] % P == 0:
        poly.pop()
    return [value % P for value in poly]


def poly_mul_mod(left: list[int], right: list[int], modulus: list[int]) -> list[int]:
    product = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            product[left_index + right_index] = (
                product[left_index + right_index] + left_value * right_value
            ) % P
    while len(product) >= len(modulus):
        scale = product[-1]
        shift = len(product) - len(modulus)
        for index, value in enumerate(modulus):
            product[index + shift] = (product[index + shift] - scale * value) % P
        poly_trim(product)
    return product


def poly_pow_mod(base: list[int], exponent: int, modulus: list[int]) -> list[int]:
    result = [1]
    while exponent:
        if exponent & 1:
            result = poly_mul_mod(result, base, modulus)
        base = poly_mul_mod(base, base, modulus)
        exponent >>= 1
    return result


def poly_sub(left: list[int], right: list[int]) -> list[int]:
    result = [0] * max(len(left), len(right))
    for index, value in enumerate(left):
        result[index] = (result[index] + value) % P
    for index, value in enumerate(right):
        result[index] = (result[index] - value) % P
    return poly_trim(result)


def poly_remainder(dividend: list[int], divisor: list[int]) -> list[int]:
    dividend, divisor = poly_trim(dividend[:]), poly_trim(divisor[:])
    if len(divisor) == 1:
        return [0]
    inverse = pow(divisor[-1], -1, P)
    while len(dividend) >= len(divisor):
        scale = dividend[-1] * inverse % P
        shift = len(dividend) - len(divisor)
        for index, value in enumerate(divisor):
            dividend[index + shift] = (dividend[index + shift] - scale * value) % P
        poly_trim(dividend)
    return dividend


def poly_gcd(left: list[int], right: list[int]) -> list[int]:
    while right != [0]:
        left, right = right, poly_remainder(left, right)
    inverse = pow(left[-1], -1, P)
    return poly_trim([value * inverse % P for value in left])


def irreducible(poly: list[int]) -> bool:
    degree = len(poly) - 1
    x = [0, 1]
    frobenius = x
    checkpoints = {0: x}
    for index in range(1, degree + 1):
        frobenius = poly_pow_mod(frobenius, P, poly)
        checkpoints[index] = frobenius
    if poly_sub(frobenius, x) != [0]:
        return False
    prime_factors: set[int] = set()
    value, divisor = degree, 2
    while divisor * divisor <= value:
        if value % divisor == 0:
            prime_factors.add(divisor)
            while value % divisor == 0:
                value //= divisor
        divisor += 1
    if value > 1:
        prime_factors.add(value)
    return all(
        len(poly_gcd(poly_sub(checkpoints[degree // factor], x), poly)) == 1
        for factor in prime_factors
    )


@functools.lru_cache(maxsize=1)
def internal_minpoly_certificate(diag_tuple: tuple[int, ...]) -> tuple[bool, ...]:
    matrix = internal_matrix(list(diag_tuple))
    power = [[int(row == column) for column in range(WIDTH)] for row in range(WIDTH)]
    results = []
    for _ in range(1, 2 * WIDTH + 1):
        power = matrix_mul(power, matrix)
        results.append(irreducible(characteristic_polynomial(power)))
    return tuple(results)


def sat_inequalities(rf: int, rp: int) -> bool:
    security = 128
    field_bits = P.bit_length()
    threshold = math.floor(math.log(P, 2) - ((ALPHA - 1) / 2.0)) * (WIDTH + 1)
    requirements = [
        6 if security <= threshold else 10,
        1 + math.ceil(math.log(2, ALPHA) * min(security, field_bits)) + math.ceil(math.log(WIDTH, ALPHA)) - rp,
        math.log(2, ALPHA) * min(security, math.log(P, 2)) - rp,
        WIDTH - 1 + math.log(2, ALPHA) * min(security / (WIDTH + 1), math.log(P, 2) / 2) - rp,
        (WIDTH - 2 + security / (2 * math.log(ALPHA, 2)) - rp) / (WIDTH - 1),
    ]
    temporary = math.floor(WIDTH / 3)
    over = (rf - 1) * WIDTH + rp + temporary + temporary * (rf / 2) + rp + ALPHA
    under = temporary * (rf / 2) + rp + ALPHA
    binomial_bits = math.ceil(2 * math.log2(math.comb(int(over), int(under))))
    return rf >= max(math.ceil(value) for value in requirements) and binomial_bits >= security


def derive_round_schedule() -> tuple[int, int, int, int]:
    best: tuple[int, int, int, int, int] | None = None
    for partial in range(1, 500):
        for full in range(4, 100, 2):
            if sat_inequalities(full, partial):
                margin_full = full + 2
                margin_partial = math.ceil(partial * 1.075)
                row = (WIDTH * margin_full + margin_partial, margin_full, margin_partial, full, partial)
                if best is None or row[:2] < best[:2]:
                    best = row
    require(best is not None, "round inequality search found no candidate")
    _, margin_full, margin_partial, base_full, base_partial = best
    return base_full, base_partial, margin_full, margin_partial


def linear(state: list[int], matrix: list[list[int]]) -> list[int]:
    return [sum(matrix[row][column] * state[column] for column in range(WIDTH)) % P for row in range(WIDTH)]


def permutation(
    state: list[int], diag: list[int], constants: list[int], external: list[list[int]]
) -> list[int]:
    state = linear(state, external)
    cursor = 0
    for _ in range(4):
        state = [pow((value + constants[cursor + lane]) % P, ALPHA, P) for lane, value in enumerate(state)]
        cursor += WIDTH
        state = linear(state, external)
    for _ in range(RP):
        state[0] = pow((state[0] + constants[cursor]) % P, ALPHA, P)
        cursor += 1
        total = sum(state) % P
        state = [(diag[lane] * value + total) % P for lane, value in enumerate(state)]
    for _ in range(4):
        state = [pow((value + constants[cursor + lane]) % P, ALPHA, P) for lane, value in enumerate(state)]
        cursor += WIDTH
        state = linear(state, external)
    require(cursor == len(constants), "permutation did not consume every round constant")
    return state


def compress14(domain: int, left: list[int], right: list[int], diag: list[int], constants: list[int], external: list[list[int]]) -> list[int]:
    return permutation(left + right + [domain, SUITE_MARKER], diag, constants, external)[:DIGEST]


def sponge(domain: int, inputs: list[int], diag: list[int], constants: list[int], external: list[list[int]]) -> list[int]:
    require(len(inputs) <= MAX_INPUTS, "reference sponge input too long")
    state = [0] * WIDTH
    state[8], state[9], state[10], state[15] = domain, len(inputs), SPONGE_MODE_MARKER, SUITE_MARKER
    blocks = max(1, (len(inputs) + RATE - 1) // RATE)
    for block in range(blocks):
        chunk = inputs[block * RATE : (block + 1) * RATE]
        for lane, value in enumerate(chunk):
            state[lane] = (state[lane] + value) % P
        if block + 1 == blocks:
            state[11] = (state[11] + 1) % P
        state = permutation(state, diag, constants, external)
    return state[:DIGEST]


def hash_words(label: str, words: list[int]) -> str:
    digest = hashlib.sha256()
    digest.update(DOMAIN_PREFIX)
    digest.update(label.encode("ascii") + b"\0")
    for word in words:
        digest.update(word.to_bytes(8, "little"))
    return digest.hexdigest()


def hex_words(words: list[int]) -> list[str]:
    return [f"0x{word:016x}" for word in words]


@functools.lru_cache(maxsize=1)
def derive() -> dict[str, Any]:
    source_bytes = SOURCE.read_bytes()
    source = source_bytes.decode("utf-8")
    diag, source_constants = extract_source_parameters(source)
    initial, internal, terminal = canonical_round_constants()
    canonical_constants = initial + internal + terminal
    require(source_constants == canonical_constants, "Rust constants differ from canonical Grain stream")
    require(math.gcd(ALPHA, P - 1) == 1, "x^7 is not a Goldilocks permutation")
    base_rf, base_rp, selected_rf, selected_rp = derive_round_schedule()
    require((base_rf, base_rp, selected_rf, selected_rp) == (6, 20, RF, RP), "round schedule drift")

    external = kron(M4, P4)
    internal_mat = internal_matrix(diag)
    minpoly = internal_minpoly_certificate(tuple(diag))
    require(all(minpoly), "internal minimal-polynomial certificate failed")
    require(m4_is_mds(), "fast M4 is not MDS")
    require(determinant(external) != 0, "external matrix is singular")
    require(determinant(internal_mat) != 0, "internal matrix is singular")

    parameter_words = [
        P, WIDTH, RATE, CAPACITY, DIGEST, ALPHA, RF, RP, 1, SUITE_MARKER,
        SPONGE_MODE_MARKER, MAX_INPUTS,
    ] + [value for row in external for value in row] + diag + canonical_constants
    digest_cardinality = P**DIGEST
    queries = 1 << 128
    result = {
        "parameter_set_id": "hegemon-p2w16-v1-" + hash_words("parameter-set", parameter_words)[:16],
        "digests": {
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "round_constants_sha256": hash_words("round-constants", canonical_constants),
            "internal_diagonal_sha256": hash_words("internal-diagonal", diag),
            "external_matrix_sha256": hash_words("external-matrix-m4-kron-p4", [value for row in external for value in row]),
            "parameter_set_sha256": hash_words("parameter-set", parameter_words),
            "p3_reference_lock_sha256": hashlib.sha256(P3_REFERENCE_LOCK.read_bytes()).hexdigest(),
        },
        "algebra": {
            "alpha_gcd": math.gcd(ALPHA, P - 1),
            "base_full_rounds": base_rf,
            "base_partial_rounds": base_rp,
            "selected_full_rounds": selected_rf,
            "selected_partial_rounds": selected_rp,
            "m4_is_mds": True,
            "external_determinant": str(determinant(external)),
            "internal_determinant": str(determinant(internal_mat)),
            "internal_power_charpolys_irreducible_1_through_32": list(minpoly),
        },
        "security": {
            "digest_cardinality": str(digest_cardinality),
            "generic_bht_collision_work_bits": math.log2(digest_cardinality) / 3,
            "generic_bht_collision_work_meets_128_bit_target": digest_cardinality >= (1 << 384),
            "generic_q_cubed_over_output_success_bound_at_2_pow_128_queries": queries**3
            / digest_cardinality,
            "max_log2_queries_for_2_pow_minus_128_generic_collision_term": (
                math.log2(digest_cardinality) - 128
            )
            / 3,
            "composed_pq128_soundness_established": False,
            "skipping_class_t_over_4": WIDTH // 4,
            "sponge_capacity_meets_transposed_matrix_condition": CAPACITY >= WIDTH // 4,
            "compression_digest_meets_transposed_matrix_condition": DIGEST >= WIDTH // 4,
            "midpoint_two_round_blocks": (RF + RP) // 2,
            "midpoint_direct_source_images": (RF + RP) // 2 + 2,
            "midpoint_direct_count_exceeds_width": (RF + RP) // 2 + 2 > WIDTH,
        },
        "kats": {
            "permutation_zero": hex_words(
                permutation([0] * WIDTH, diag, canonical_constants, external)
            ),
            "permutation_sequential": hex_words(
                permutation(list(range(WIDTH)), diag, canonical_constants, external)
            ),
            "compress14_sequential": hex_words(
                compress14(
                    0x4845_475F_4D45_524B,
                    list(range(7)),
                    list(range(7, 14)),
                    diag,
                    canonical_constants,
                    external,
                )
            ),
            "sponge_sequential": {
                str(length): hex_words(
                    sponge(
                        0x4845_475F_4841_5348,
                        list(range(length)),
                        diag,
                        canonical_constants,
                        external,
                    )
                )
                for length in (0, 7, 8, 9, 16, 34, 120)
            },
        },
    }
    return result


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    expected = derive()
    require(manifest.get("schema") == "hegemon.poseidon2.width16.parameters.v1", "manifest schema mismatch")
    require(manifest.get("parameter_set_id") == expected["parameter_set_id"], "parameter-set id mismatch")
    require(manifest.get("production_authorized") is False, "production authorization must remain false")
    require(manifest.get("review_status") == "candidate_external_review_required", "review status mismatch")
    require(manifest.get("required_external_review") is True, "external review gate must remain required")
    require(manifest.get("parameters") == {
        "field": "Goldilocks",
        "field_modulus": str(P),
        "width": WIDTH,
        "rate": RATE,
        "capacity": CAPACITY,
        "digest_field_elements": DIGEST,
        "sbox_degree": ALPHA,
        "full_rounds": RF,
        "partial_rounds": RP,
        "steps_including_initial_linear": 1 + RF + RP,
        "external_matrix_orientation": "M4_kron_P4",
        "sponge_max_input_elements": MAX_INPUTS,
        "suite_marker_hex": f"0x{SUITE_MARKER:016x}",
        "sponge_mode_marker_hex": f"0x{SPONGE_MODE_MARKER:016x}",
    }, "manifest parameter tuple mismatch")
    require(manifest.get("digests") == expected["digests"], "manifest digest binding mismatch")
    require(manifest.get("algebra") == expected["algebra"], "manifest algebra certificate mismatch")
    require(manifest.get("security") == expected["security"], "manifest security arithmetic mismatch")
    require(manifest.get("known_answer_tests") == expected["kats"], "manifest known-answer vectors mismatch")
    provenance = manifest.get("provenance", {})
    require(provenance.get("round_constants") == "Poseidon Appendix-E Grain LFSR tuple (1,0,64,16,8,22)", "round provenance mismatch")
    require(provenance.get("horizen_commit") == "055bde3f4782731ba5f5ce5888a440a94327eaf3", "Horizen commit mismatch")
    require(provenance.get("horizen_instance_commit") == "bb476b9ca38198cf5092487283c8b8c5d4317c4e", "Horizen instance commit mismatch")
    require(provenance.get("p3_goldilocks_version") == "0.6.3", "p3 version mismatch")
    require(provenance.get("p3_goldilocks_crate_sha256") == "d03b3f31080df31be723b876709246f8f1e532e1c5b82efb5281d705c8304c63", "p3 crate digest mismatch")
    require(provenance.get("p3_poseidon2_crate_sha256") == "43eb8a73a26d14becaed1c67c3e8a047e4311d7909b402383c82ca9643ba17c6", "p3 Poseidon2 crate digest mismatch")
    attacks = manifest.get("cryptanalysis_screen", {})
    require(attacks.get("eprint_2026_306", {}).get("disposition") == "mitigated_by_M4_kron_P4_pending_external_review", "Skipping Class disposition mismatch")
    require(attacks.get("eprint_2026_1760", {}).get("disposition") == "direct_attack_prerequisites_absent_pending_external_review", "Midpoint Reset disposition mismatch")
    return expected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--derive", action="store_true")
    args = parser.parse_args()
    if args.derive:
        print(json.dumps(derive(), indent=2, sort_keys=True))
        return
    if not args.check:
        parser.error("use --check or --derive")
    manifest = json.loads(MANIFEST.read_text())
    expected = validate_manifest(manifest)
    print(
        "poseidon2-width16-parameters: candidate gate passed; "
        f"id={expected['parameter_set_id']} production_authorized=false"
    )


if __name__ == "__main__":
    try:
        main()
    except (GateError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"poseidon2-width16-parameters: FAIL: {error}") from error
