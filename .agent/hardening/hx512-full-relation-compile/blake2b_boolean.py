#!/usr/bin/env python3
"""Streaming RFC 7693 BLAKE2b-512 Boolean-row witness checker.

The checker materializes no matrix.  It executes the exact 64-bit ARX
schedule, validates every bit-level primitive equation when requested, and
counts the same 136,384 rows per compression used by the retained cost
projection: 576 add64 gadgets at 192 rows each and 403 64-bit XOR gadgets.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any, Iterable, Sequence


MASK64 = (1 << 64) - 1
ROWS_PER_ADD64 = 192
ROWS_PER_XOR64 = 64
ADDS_PER_COMPRESSION = 576
XORS_PER_COMPRESSION = 403
ROWS_PER_COMPRESSION = (
    ADDS_PER_COMPRESSION * ROWS_PER_ADD64
    + XORS_PER_COMPRESSION * ROWS_PER_XOR64
)

IV = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
)


class BooleanTraceError(ValueError):
    pass


@dataclasses.dataclass
class Counters:
    add64: int = 0
    xor64: int = 0
    bitness_rows: int = 0
    add_equation_rows: int = 0
    xor_equation_rows: int = 0

    @property
    def rows(self) -> int:
        return self.bitness_rows + self.add_equation_rows + self.xor_equation_rows


def _bit(value: int, index: int) -> int:
    return (value >> index) & 1


def _add64(left: int, right: int, counters: Counters, exhaustive: bool) -> int:
    result = (left + right) & MASK64
    counters.add64 += 1
    counters.bitness_rows += 128
    counters.add_equation_rows += 64
    if exhaustive:
        carry = 0
        for index in range(64):
            x = _bit(left, index)
            y = _bit(right, index)
            out = _bit(result, index)
            next_carry = (x + y + carry) >> 1
            if out not in (0, 1) or next_carry not in (0, 1):
                raise BooleanTraceError("add64 bitness")
            if x + y + carry - out - 2 * next_carry != 0:
                raise BooleanTraceError("add64 equation")
            carry = next_carry
    return result


def _xor64(left: int, right: int, counters: Counters, exhaustive: bool) -> int:
    result = left ^ right
    counters.xor64 += 1
    counters.xor_equation_rows += 64
    if exhaustive:
        for index in range(64):
            x = _bit(left, index)
            y = _bit(right, index)
            out = _bit(result, index)
            if 2 * x * y - x - y + out != 0:
                raise BooleanTraceError("xor equation")
    return result


def _rotr(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def _g(
    v: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    x: int,
    y: int,
    counters: Counters,
    exhaustive: bool,
) -> None:
    v[a] = _add64(_add64(v[a], v[b], counters, exhaustive), x, counters, exhaustive)
    v[d] = _rotr(_xor64(v[d], v[a], counters, exhaustive), 32)
    v[c] = _add64(v[c], v[d], counters, exhaustive)
    v[b] = _rotr(_xor64(v[b], v[c], counters, exhaustive), 24)
    v[a] = _add64(_add64(v[a], v[b], counters, exhaustive), y, counters, exhaustive)
    v[d] = _rotr(_xor64(v[d], v[a], counters, exhaustive), 16)
    v[c] = _add64(v[c], v[d], counters, exhaustive)
    v[b] = _rotr(_xor64(v[b], v[c], counters, exhaustive), 63)


def _compress(
    chaining: Sequence[int],
    block: bytes,
    counter: int,
    final: bool,
    exhaustive: bool,
) -> tuple[tuple[int, ...], Counters]:
    if len(chaining) != 8 or len(block) != 128 or not 0 <= counter < 1 << 128:
        raise BooleanTraceError("compression input shape")
    message = [int.from_bytes(block[index * 8 : (index + 1) * 8], "little") for index in range(16)]
    v = list(chaining) + list(IV)
    counters = Counters()
    v[12] = _xor64(v[12], counter & MASK64, counters, exhaustive)
    v[13] = _xor64(v[13], counter >> 64, counters, exhaustive)
    v[14] = _xor64(v[14], MASK64 if final else 0, counters, exhaustive)
    for round_index, sigma in enumerate(SIGMA):
        del round_index
        _g(v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]], counters, exhaustive)
        _g(v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]], counters, exhaustive)
        _g(v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]], counters, exhaustive)
        _g(v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]], counters, exhaustive)
        _g(v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]], counters, exhaustive)
        _g(v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]], counters, exhaustive)
        _g(v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]], counters, exhaustive)
        _g(v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]], counters, exhaustive)
    output = []
    for index in range(8):
        value = _xor64(chaining[index], v[index], counters, exhaustive)
        output.append(_xor64(value, v[index + 8], counters, exhaustive))
    if (counters.add64, counters.xor64, counters.rows) != (
        ADDS_PER_COMPRESSION,
        XORS_PER_COMPRESSION,
        ROWS_PER_COMPRESSION,
    ):
        raise BooleanTraceError("compression geometry")
    return tuple(output), counters


def parameter_block(personalization: bytes | None) -> bytes:
    person = bytes(16) if personalization is None else personalization
    if len(person) != 16:
        raise BooleanTraceError("personalization width")
    parameter = bytearray(64)
    parameter[0] = 64
    parameter[2] = 1
    parameter[3] = 1
    parameter[48:64] = person
    return bytes(parameter)


def initial_state(personalization: bytes | None) -> tuple[int, ...]:
    parameter = parameter_block(personalization)
    words = [int.from_bytes(parameter[index * 8 : (index + 1) * 8], "little") for index in range(8)]
    return tuple(IV[index] ^ words[index] for index in range(8))


def trace_call(
    call: Any,
    *,
    expected_personalization_hex: str,
    exhaustive_bits: bool = False,
) -> dict[str, Any]:
    message = bytes.fromhex(call.message_hex)
    if len(message) != call.message_bytes:
        raise BooleanTraceError("message width")
    if hashlib.sha512(message).hexdigest() != call.message_sha512:
        raise BooleanTraceError(f"message source digest drift at call {call.index}")
    if call.personalization_hex != expected_personalization_hex:
        raise BooleanTraceError(f"caller-supplied parameter drift at call {call.index}")
    person = bytes.fromhex(expected_personalization_hex)
    state = initial_state(person)
    padded = message + bytes(call.fixed_compressions * 128 - len(message))
    if len(padded) != call.fixed_compressions * 128:
        raise BooleanTraceError("fixed compression capacity")
    selected_state: tuple[int, ...] | None = None
    total = Counters()
    for block_index in range(call.fixed_compressions):
        state, counters = _compress(
            state,
            padded[block_index * 128 : (block_index + 1) * 128],
            call.counters[block_index],
            call.final_flags[block_index],
            exhaustive_bits,
        )
        total.add64 += counters.add64
        total.xor64 += counters.xor64
        total.bitness_rows += counters.bitness_rows
        total.add_equation_rows += counters.add_equation_rows
        total.xor_equation_rows += counters.xor_equation_rows
        if block_index + 1 == call.selected_digest_state_after_compression:
            selected_state = state
    if selected_state is None:
        raise BooleanTraceError("digest-state selection")
    digest = b"".join(word.to_bytes(8, "little") for word in selected_state)
    expected = bytes.fromhex(call.digest_hex)
    if digest != expected:
        raise BooleanTraceError(f"digest mismatch at call {call.index}")
    direct = hashlib.blake2b(message, digest_size=64, person=person or b"").digest()
    if direct != expected:
        raise BooleanTraceError(f"independent hashlib mismatch at call {call.index}")
    return {
        "index": call.index,
        "family": call.family,
        "fixed_compressions": call.fixed_compressions,
        "add64": total.add64,
        "xor64": total.xor64,
        "compression_rows": total.rows,
        "parameter_not_rows": 0,
        "rows": total.rows,
        "personalization_hex": expected_personalization_hex,
        "parameter_block_hex": parameter_block(person).hex(),
        "constant_folded_initial_state_u64le_hex": [f"{word:016x}" for word in initial_state(person)],
        "message_sha512": hashlib.sha512(message).hexdigest(),
        "counters": list(call.counters),
        "final_flags": list(call.final_flags),
        "selected_digest_state_after_compression": call.selected_digest_state_after_compression,
        "digest_hex": digest.hex(),
        "independent_hashlib_equal": True,
        "every_bit_row_evaluated": exhaustive_bits,
    }


def trace_relation(
    calls: Iterable[Any],
    *,
    expected_personalization_hex_by_call: Sequence[str],
    exhaustive_bits: bool = False,
) -> dict[str, Any]:
    call_list = list(calls)
    if len(expected_personalization_hex_by_call) != len(call_list):
        raise BooleanTraceError("fixed personalization schedule width")
    traces = [
        trace_call(
            call,
            expected_personalization_hex=expected_personalization_hex_by_call[index],
            exhaustive_bits=exhaustive_bits,
        )
        for index, call in enumerate(call_list)
    ]
    if [item["index"] for item in traces] != list(range(90)):
        raise BooleanTraceError("call index coverage")
    core = traces[:83]
    authority = traces[83:]
    if (
        sum(item["fixed_compressions"] for item in core),
        sum(item["fixed_compressions"] for item in authority),
    ) != (205, 8):
        raise BooleanTraceError("composite compression schedule")
    return {
        "artifact_schema": "hegemon.hx512b01.blake2b-boolean-trace.v1",
        "calls": traces,
        "physical_calls": len(traces),
        "core_compressions": 205,
        "authority_compressions": 8,
        "total_compressions": 213,
        "compression_rows": sum(item["compression_rows"] for item in traces),
        "parameter_not_rows": sum(item["parameter_not_rows"] for item in traces),
        "total_boolean_hash_rows": sum(item["rows"] for item in traces),
        "every_call_digest_equals_independent_hashlib": all(
            item["independent_hashlib_equal"] for item in traces
        ),
        "every_bit_row_evaluated": exhaustive_bits,
        "expanded_sparse_rows_retained": False,
    }


def parameter_state_kats(personalization_hex_values: Iterable[str]) -> dict[str, Any]:
    unique = []
    seen: set[str] = set()
    for encoded in personalization_hex_values:
        if encoded in seen:
            continue
        seen.add(encoded)
        person = bytes.fromhex(encoded)
        unique.append(
            {
                "personalization_hex": encoded,
                "parameter_block_hex": parameter_block(person).hex(),
                "constant_folded_initial_state_u64le_hex": [
                    f"{word:016x}" for word in initial_state(person)
                ],
            }
        )
    return {
        "unique_fixed_parameter_blocks": len(unique),
        "profiles": unique,
        "parameter_rows": 0,
        "caller_supplied_parameters_accepted": False,
    }
