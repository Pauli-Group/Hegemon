#!/usr/bin/env python3
"""Dependency-free source audit for the dormant Boolean BLAKE2b relation.

This checker never builds Rust and never treats the diagnostic trace as a
production proof relation.  It independently checks RFC 7693 constants and
known answers, reproduces the constraint builder's constant-folded gate
inventory, and pins the exact integration/fail-closed seams named in the
retained certificate.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = Path(__file__).resolve().parent
CERTIFICATE = EVIDENCE / "certificate.json"
EVIDENCE_PATHS = {
    "checker": EVIDENCE / "check.py",
    "mutation_suite": EVIDENCE / "test_check.py",
}

PATHS = {
    "gadget": ROOT / "circuits/transaction/src/smallwood_blake2b384.rs",
    "semantics": ROOT / "circuits/transaction/src/smallwood_blake2b384_semantics.rs",
    "full_hx_scalar": ROOT / "circuits/transaction/src/full_blake2b448_relation.rs",
    "frontend": ROOT / "circuits/transaction/src/smallwood_frontend.rs",
    "crate_root": ROOT / "circuits/transaction/src/lib.rs",
    "hash384_domains": ROOT / "crypto/hash384/src/lib.rs",
    "hx_m4": ROOT
    / "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs",
}

IV = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

MASK64 = (1 << 64) - 1


class AuditError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def normalized(source: str) -> str:
    return " ".join(source.split())


def source_sha512(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def safe_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for name, path in PATHS.items():
        require(path.is_file(), f"missing regular source: {path}")
        require(not path.is_symlink(), f"source must not be a symlink: {path}")
        resolved = path.resolve()
        require(resolved.is_relative_to(ROOT), f"source escapes repository: {path}")
        sources[name] = path.read_text(encoding="utf-8")
    return sources


def extract_array_body(source: str, name: str) -> str:
    match = re.search(
        rf"const\s+{re.escape(name)}\s*:[^=]+?=\s*\[(.*?)\n\];",
        source,
        re.DOTALL,
    )
    require(match is not None, f"cannot parse {name}")
    return match.group(1)


def extract_iv(source: str) -> list[int]:
    body = extract_array_body(source, "BLAKE2B_IV")
    words = [int(token.replace("_", ""), 16) for token in re.findall(r"0x[0-9a-fA-F_]+", body)]
    require(len(words) == 8, "BLAKE2B_IV does not contain eight words")
    return words


def extract_sigma(source: str) -> list[list[int]]:
    body = extract_array_body(source, "BLAKE2B_SIGMA")
    rows = []
    for row in re.findall(r"\[([^\[\]]+)\]", body):
        values = [int(value) for value in re.findall(r"\d+", row)]
        if values:
            rows.append(values)
    require(len(rows) == 12 and all(len(row) == 16 for row in rows), "invalid sigma shape")
    return rows


def rotr64(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def g(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + x) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 63)


def compress(h: list[int], block: bytes, counter: int, final: bool) -> list[int]:
    require(len(block) == 128, "compression block must have 128 bytes")
    words = [int.from_bytes(block[index : index + 8], "little") for index in range(0, 128, 8)]
    v = h[:] + IV[:]
    v[12] ^= counter & MASK64
    v[13] ^= (counter >> 64) & MASK64
    if final:
        v[14] ^= MASK64
    for schedule in SIGMA:
        g(v, 0, 4, 8, 12, words[schedule[0]], words[schedule[1]])
        g(v, 1, 5, 9, 13, words[schedule[2]], words[schedule[3]])
        g(v, 2, 6, 10, 14, words[schedule[4]], words[schedule[5]])
        g(v, 3, 7, 11, 15, words[schedule[6]], words[schedule[7]])
        g(v, 0, 5, 10, 15, words[schedule[8]], words[schedule[9]])
        g(v, 1, 6, 11, 12, words[schedule[10]], words[schedule[11]])
        g(v, 2, 7, 8, 13, words[schedule[12]], words[schedule[13]])
        g(v, 3, 4, 9, 14, words[schedule[14]], words[schedule[15]])
    return [(h[index] ^ v[index] ^ v[index + 8]) & MASK64 for index in range(8)]


def block_schedule(key_len: int, message_len: int) -> list[dict[str, object]]:
    require(0 <= key_len <= 64, "invalid key length")
    message_blocks = 1 if key_len == 0 and message_len == 0 else (message_len + 127) // 128
    result: list[dict[str, object]] = []
    if key_len:
        result.append(
            {
                "kind": "key",
                "offset": 0,
                "absorbed": 128,
                "counter": 128,
                "final": message_len == 0,
            }
        )
    for index in range(message_blocks):
        offset = index * 128
        absorbed = min(max(message_len - offset, 0), 128)
        result.append(
            {
                "kind": "message",
                "offset": offset,
                "absorbed": absorbed,
                "counter": (128 if key_len else 0) + offset + absorbed,
                "final": index + 1 == message_blocks,
            }
        )
    return result


def blake2b_reference(
    message: bytes,
    output_bytes: int,
    key: bytes = b"",
    personalization: bytes = bytes(16),
) -> bytes:
    require(1 <= output_bytes <= 64, "invalid output length")
    require(len(key) <= 64, "invalid key length")
    require(len(personalization) == 16, "invalid personalization length")
    h = IV[:]
    h[0] ^= 0x01010000 ^ (len(key) << 8) ^ output_bytes
    h[6] ^= int.from_bytes(personalization[:8], "little")
    h[7] ^= int.from_bytes(personalization[8:], "little")
    schedule = block_schedule(len(key), len(message))
    for descriptor in schedule:
        if descriptor["kind"] == "key":
            block = key + bytes(128 - len(key))
        else:
            offset = int(descriptor["offset"])
            absorbed = int(descriptor["absorbed"])
            block = message[offset : offset + absorbed] + bytes(128 - absorbed)
        h = compress(h, block, int(descriptor["counter"]), bool(descriptor["final"]))
    return b"".join(word.to_bytes(8, "little") for word in h)[:output_bytes]


@dataclass(frozen=True)
class Bit:
    wire: int
    value: bool
    known: Optional[bool]


class CountBuilder:
    def __init__(self) -> None:
        self.witness: list[bool] = []
        self.counts: Counter[str] = Counter()
        self.zero = self.allocate(False, False)
        self.counts["Constant"] += 1
        self.one = self.allocate(True, True)
        self.counts["Constant"] += 1

    def allocate(self, value: bool, known: Optional[bool]) -> Bit:
        bit = Bit(len(self.witness), value, known)
        self.witness.append(value)
        return bit

    def constant(self, value: bool) -> Bit:
        return self.one if value else self.zero

    def input(self, value: bool) -> Bit:
        bit = self.allocate(value, None)
        self.counts["Boolean"] += 1
        return bit

    def not_(self, value: Bit) -> Bit:
        if value.known is not None:
            return self.constant(not value.known)
        output = self.allocate(not value.value, None)
        self.counts["Not"] += 1
        return output

    def xor(self, left: Bit, right: Bit) -> Bit:
        if left.wire == right.wire:
            return self.zero
        if left.known is not None and right.known is not None:
            return self.constant(left.known ^ right.known)
        if left.known is False:
            return right
        if right.known is False:
            return left
        if left.known is True:
            return self.not_(right)
        if right.known is True:
            return self.not_(left)
        output = self.allocate(left.value ^ right.value, None)
        self.counts["Xor"] += 1
        return output

    def full_adder(self, left: Bit, right: Bit, carry: Bit) -> tuple[Bit, Bit]:
        if left.known is not None and right.known is not None and carry.known is not None:
            total = int(left.known) + int(right.known) + int(carry.known)
            return self.constant(bool(total & 1)), self.constant(total >= 2)
        total = int(left.value) + int(right.value) + int(carry.value)
        output = self.allocate(bool(total & 1), None)
        carry_out = self.allocate(total >= 2, None)
        self.counts["FullAdderSum"] += 1
        self.counts["FullAdderCarry"] += 1
        return output, carry_out

    def word(self, value: int) -> list[Bit]:
        return [self.constant(bool((value >> bit) & 1)) for bit in range(64)]

    def xor_word(self, left: list[Bit], right: list[Bit]) -> list[Bit]:
        return [self.xor(a, b) for a, b in zip(left, right)]

    def not_word(self, word: list[Bit]) -> list[Bit]:
        return [self.not_(bit) for bit in word]

    def add_word(self, left: list[Bit], right: list[Bit]) -> list[Bit]:
        carry = self.zero
        output = []
        for a, b in zip(left, right):
            value, carry = self.full_adder(a, b, carry)
            output.append(value)
        return output


def rotate_word(word: list[Bit], amount: int) -> list[Bit]:
    return [word[(bit + amount) % 64] for bit in range(64)]


def mix_bits(
    builder: CountBuilder,
    work: list[list[Bit]],
    indexes: tuple[int, int, int, int],
    x: list[Bit],
    y: list[Bit],
) -> None:
    a, b, c, d = indexes
    work[a] = builder.add_word(builder.add_word(work[a], work[b]), x)
    work[d] = rotate_word(builder.xor_word(work[d], work[a]), 32)
    work[c] = builder.add_word(work[c], work[d])
    work[b] = rotate_word(builder.xor_word(work[b], work[c]), 24)
    work[a] = builder.add_word(builder.add_word(work[a], work[b]), y)
    work[d] = rotate_word(builder.xor_word(work[d], work[a]), 16)
    work[c] = builder.add_word(work[c], work[d])
    work[b] = rotate_word(builder.xor_word(work[b], work[c]), 63)


def compress_bits(
    builder: CountBuilder,
    state: list[list[Bit]],
    message: list[list[Bit]],
    counter: int,
    final: bool,
) -> list[list[Bit]]:
    work = [word[:] for word in state] + [builder.word(word) for word in IV]
    work[12] = builder.xor_word(work[12], builder.word(counter & MASK64))
    work[13] = builder.xor_word(work[13], builder.word((counter >> 64) & MASK64))
    if final:
        work[14] = builder.not_word(work[14])
    columns = [
        (0, 4, 8, 12),
        (1, 5, 9, 13),
        (2, 6, 10, 14),
        (3, 7, 11, 15),
        (0, 5, 10, 15),
        (1, 6, 11, 12),
        (2, 7, 8, 13),
        (3, 4, 9, 14),
    ]
    for schedule in SIGMA:
        for lane, indexes in enumerate(columns):
            mix_bits(builder, work, indexes, message[schedule[2 * lane]], message[schedule[2 * lane + 1]])
    return [builder.xor_word(state[index], builder.xor_word(work[index], work[index + 8])) for index in range(8)]


def gate_inventory(message: bytes, output_bytes: int = 48, key: bytes = b"", personalization: bytes = bytes(16)) -> dict[str, object]:
    builder = CountBuilder()
    state = [builder.word(word) for word in IV]
    parameter = 0x01010000 ^ (len(key) << 8) ^ output_bytes
    state[0] = builder.xor_word(state[0], builder.word(parameter))
    state[6] = builder.xor_word(state[6], builder.word(int.from_bytes(personalization[:8], "little")))
    state[7] = builder.xor_word(state[7], builder.word(int.from_bytes(personalization[8:], "little")))
    descriptors = block_schedule(len(key), len(message))
    for descriptor in descriptors:
        block_bits = [builder.zero] * (128 * 8)
        if descriptor["kind"] == "key":
            raw = key
        else:
            offset = int(descriptor["offset"])
            absorbed = int(descriptor["absorbed"])
            raw = message[offset : offset + absorbed]
        for byte_index, byte in enumerate(raw):
            for bit in range(8):
                block_bits[byte_index * 8 + bit] = builder.input(bool((byte >> bit) & 1))
        words = [block_bits[index : index + 64] for index in range(0, 1024, 64)]
        state = compress_bits(
            builder,
            state,
            words,
            int(descriptor["counter"]),
            bool(descriptor["final"]),
        )
    scalar_constraints = sum(builder.counts.values())
    input_bindings = (len(key) + len(message)) * 8
    output_bindings = output_bytes * 8
    return {
        "blocks": len(descriptors),
        "wires": len(builder.witness),
        "constraints": dict(sorted(builder.counts.items())),
        "scalar_constraints": scalar_constraints,
        "witness_rows_64": (len(builder.witness) + 63) // 64,
        "constraint_rows_64": (scalar_constraints + 63) // 64,
        "external_input_bindings": input_bindings,
        "external_output_bindings": output_bindings,
        "external_binding_rows_64": (input_bindings + output_bindings + 63) // 64,
    }


def extract_ascii_domain(source: str, name: str) -> bytes:
    match = re.search(
        rf"pub\s+const\s+{re.escape(name)}\s*:\s*&\[u8\]\s*=\s*b\"([^\"]*)\";",
        source,
        re.DOTALL,
    )
    require(match is not None, f"cannot parse domain {name}")
    encoded = match.group(1).encode("ascii")
    return encoded.decode("unicode_escape").encode("latin1")


def dormant_v5_schedule_report(domain_source: str) -> dict[str, int]:
    frame = extract_ascii_domain(domain_source, "BLAKE2B_384_FRAME_V1")
    domains = {
        name: extract_ascii_domain(domain_source, name)
        for name in (
            "SMALLWOOD_SPEND_CREDENTIAL_V5",
            "SMALLWOOD_AUTH_POLICY_V5",
            "SMALLWOOD_AUTH_ACCUMULATOR_V5",
            "SMALLWOOD_AUTH_VALUE_LOCK_V5",
            "CRYPTO_NOTE_COMMITMENT_V2",
            "TRANSACTION_MERKLE_NODE_V3",
            "CRYPTO_NULLIFIER_DERIVATION_V2",
            "SMALLWOOD_AUTH_INTENT_V5",
            "TRANSACTION_BALANCE_TAG_V3",
        )
    }
    entries: list[tuple[bytes, list[int]]] = [
        (domains["SMALLWOOD_SPEND_CREDENTIAL_V5"], [32]),
        (domains["SMALLWOOD_AUTH_POLICY_V5"], [8, 8, 6 * 5 * 8]),
        (domains["SMALLWOOD_AUTH_ACCUMULATOR_V5"], [48, 48, 8, 8, 8, 6 * 8]),
        (domains["SMALLWOOD_AUTH_ACCUMULATOR_V5"], [48, 48, 8, 8, 8, 6 * 8]),
        (domains["SMALLWOOD_AUTH_VALUE_LOCK_V5"], [48, 48]),
    ]
    for _input in range(2):
        entries.append((domains["CRYPTO_NOTE_COMMITMENT_V2"], [8, 8, 32, 32, 32, 32]))
        entries.extend((domains["TRANSACTION_MERKLE_NODE_V3"], [48, 48]) for _level in range(32))
        entries.append((domains["CRYPTO_NULLIFIER_DERIVATION_V2"], [8, 8, 32]))
    entries.extend(
        (domains["CRYPTO_NOTE_COMMITMENT_V2"], [8, 8, 32, 32, 32, 32])
        for _output in range(2)
    )
    entries.extend(
        [
            (domains["SMALLWOOD_AUTH_INTENT_V5"], [78 * 8]),
            (domains["TRANSACTION_BALANCE_TAG_V3"], [8, 4 * 16]),
        ]
    )
    lengths = [
        len(frame) + 8 + len(domain) + sum(8 + part_length for part_length in parts)
        for domain, parts in entries
    ]
    inventory_by_length = {length: gate_inventory(bytes(length)) for length in set(lengths)}
    return {
        "hash_calls": len(lengths),
        "framed_message_bytes": sum(lengths),
        "compressions": sum((length + 127) // 128 for length in lengths),
        "internal_scalar_constraints": sum(
            int(inventory_by_length[length]["scalar_constraints"]) for length in lengths
        ),
        "internal_packed_64_rows": sum(
            int(inventory_by_length[length]["constraint_rows_64"]) for length in lengths
        ),
        "external_input_binding_constraints": sum(length * 8 for length in lengths),
        "external_input_binding_rows": sum((length * 8 + 63) // 64 for length in lengths),
        "external_output_binding_constraints": len(lengths) * 48 * 8,
        "external_output_binding_rows": len(lengths) * 6,
        "external_binding_rows": sum(((length + 48) * 8 + 63) // 64 for length in lengths),
    }


def audit_sources(sources: dict[str, str], check_certificate: bool = True) -> dict[str, object]:
    gadget = sources["gadget"]
    semantics = sources["semantics"]
    full = sources["full_hx_scalar"]
    frontend = sources["frontend"]
    crate_root = sources["crate_root"]
    m4 = sources["hx_m4"]
    hash384_domains = sources["hash384_domains"]
    gadget_norm = normalized(gadget)
    full_norm = normalized(full)
    semantics_norm = normalized(semantics)
    m4_norm = normalized(m4)

    for name in ("gadget", "full_hx_scalar", "hx_m4"):
        require(extract_iv(sources[name]) == IV, f"{name} IV drift")
        require(extract_sigma(sources[name]) == SIGMA, f"{name} sigma drift")

    pre_test = gadget.split("#[cfg(test)]", 1)[0]
    require("blake2b_384(" not in pre_test, "gadget contains a native BLAKE2b digest shortcut")
    require("Blake2bVar" not in pre_test, "gadget contains a native BLAKE2bVar shortcut")
    required_gadget_fragments = [
        "let parameter_word = 0x0101_0000u64 ^ ((key.len() as u64) << 8) ^ OUTPUT_BYTES as u64;",
        "state[6] = builder.xor_word(state[6], builder.constant_word(personalization_words[0]));",
        "state[7] = builder.xor_word(state[7], builder.constant_word(personalization_words[1]));",
        "work[12] = builder.xor_word(work[12], builder.constant_word(counter as u64));",
        "work[13] = builder.xor_word(work[13], builder.constant_word((counter >> 64) as u64));",
        "if is_final { work[14] = builder.not_word(work[14]); }",
        "core::array::from_fn(|bit| word[(bit + amount) % BLAKE2B_WORD_BITS])",
        "field_mul_small(triple, 4)",
        "field_sub(pair_sum, field_mul_small(triple, 2))",
        "if self.blocks != expected_block_descriptors(self.key_len, self.message_len)?",
        "pub fn verify_input_bindings(",
        "external_input_binding_constraints",
        "external_binding_rows",
    ]
    for fragment in required_gadget_fragments:
        require(normalized(fragment) in gadget_norm, f"missing gadget invariant: {fragment}")
    for retained_test_evidence in (
        "every_constraint_family_and_block_metadata_mutation_fails_closed",
        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
        "17717a8ead79718ab6442b2d10d6c3e830fd668463ad566d98ce618e11e8ca9427ab891da9de2f4527b654d6f8272a4d12b0f17064150724",
    ):
        require(retained_test_evidence in gadget, f"missing retained Rust test evidence: {retained_test_evidence}")

    require("pub mod smallwood_blake2b384;" in crate_root, "gadget module is not exported")
    require("pub mod smallwood_blake2b384_semantics;" in crate_root, "semantic adapter is not exported")
    require(
        "trace .verify_input_bindings(&[], &call.framed_message)" in semantics_norm,
        "semantic adapter omits centralized message-source binding",
    )
    require(
        "trace .verify_digest(&call.digest.raw_digest)" in semantics_norm,
        "semantic adapter omits raw digest equality",
    )
    require(
        "pub const fn smallwood_blake2b384_relation_is_production_authorized() -> bool { false }"
        in semantics_norm,
        "dormant 384-bit semantic profile is not fail closed",
    )
    require(
        "pub const fn smallwood_blake2b384_boolean_relation_is_compiled() -> bool { false }"
        in normalized(frontend),
        "legacy SmallWood frontend unexpectedly claims the Boolean relation is compiled",
    )
    require(
        "trace.verify_input_bindings(&[], &frame.bytes)?;" in full_norm,
        "HX scalar caller omits centralized BLAKE message-source binding",
    )
    require(
        "blake2b_relation::<BLAKE2B_448_OUTPUT_BYTES>(&frame.bytes)?" in full_norm,
        "HX scalar candidate does not reuse the generic Boolean BLAKE core",
    )
    require(
        "pub const FULL_BLAKE2B448_AGGREGATE_CONSTRAINT_RELATION_COMPILED: bool = false;" in full,
        "HX scalar candidate incorrectly claims an aggregate relation",
    )
    require(
        "pub const FULL_BLAKE2B448_PRODUCTION_AUTHORIZED: bool = false;" in full,
        "HX scalar candidate incorrectly claims production authority",
    )
    require(
        "use transaction_circuit::full_blake2b448_relation as scalar_candidate;" in m4,
        "M4 parity seam no longer names the HX scalar oracle",
    )
    require(
        "smallwood_blake2b384" not in m4,
        "M4 unexpectedly depends directly on the scalar Boolean trace object",
    )
    for fragment in [
        "h[0] = builder.bxor(h[0], builder.add_constant_64(0x0101_0038));",
        "let counter = ((block + 1) * BLAKE2B_BLOCK_BYTES).min(frame.len_bytes) as u64;",
        "let final_mask = if block + 1 == blocks { u64::MAX } else { 0 };",
        "counter_lo: [ builder.add_constant_64(BLAKE2B_BLOCK_BYTES as u64), builder.add_constant_64(frame.len_bytes as u64), ]",
        "final_mask: [zero, builder.add_constant_64(u64::MAX)]",
    ]:
        require(normalized(fragment) in m4_norm, f"M4 BLAKE schedule drift: {fragment}")

    kat_cases = []
    for output_bytes in (48, 56, 64):
        for length in (0, 1, 3, 127, 128, 129, 255, 256, 257):
            message = bytes((index * 37 + length) & 0xFF for index in range(length))
            ours = blake2b_reference(message, output_bytes)
            native = hashlib.blake2b(message, digest_size=output_bytes).digest()
            require(ours == native, f"independent unkeyed KAT failed: out={output_bytes}, len={length}")
            kat_cases.append((output_bytes, length, ours.hex()))
    keyed_cases = []
    for key_len, message_len in ((1, 0), (48, 0), (48, 13), (64, 128), (64, 129)):
        key = bytes((index * 11 + key_len) & 0xFF for index in range(key_len))
        message = bytes((index * 29 + message_len) & 0xFF for index in range(message_len))
        person = b"HEG-audit-rfc769"
        ours = blake2b_reference(message, 56, key, person)
        native = hashlib.blake2b(message, digest_size=56, key=key, person=person).digest()
        require(ours == native, f"independent keyed KAT failed: key={key_len}, len={message_len}")
        keyed_cases.append((key_len, message_len, ours.hex()))

    expected_counts = {0: (2, 1, 1), 3: (95_054, 1_486, 1_486), 128: (99_349, 1_553, 1_553), 129: (198_560, 3_103, 3_103)}
    inventories: dict[str, object] = {}
    for length, expected in expected_counts.items():
        message = bytes((index * 17 + length) & 0xFF for index in range(length))
        inventory = gate_inventory(message)
        require(
            (
                inventory["scalar_constraints"],
                inventory["witness_rows_64"],
                inventory["constraint_rows_64"],
            )
            == expected,
            f"gate inventory drift for message length {length}",
        )
        alternate = gate_inventory(bytes([0xFF]) * length)
        require(inventory == alternate, f"secret-dependent geometry for message length {length}")
        inventories[str(length)] = inventory

    dormant_v5 = dormant_v5_schedule_report(hash384_domains)
    require(
        dormant_v5
        == {
            "hash_calls": 77,
            "framed_message_bytes": 15_065,
            "compressions": 164,
            "internal_scalar_constraints": 16_322_454,
            "internal_packed_64_rows": 255_100,
            "external_input_binding_constraints": 120_520,
            "external_input_binding_rows": 1_906,
            "external_output_binding_constraints": 29_568,
            "external_output_binding_rows": 462,
            "external_binding_rows": 2_368,
        },
        "independent dormant V5 schedule accounting drift",
    )

    report = {
        "schema": 1,
        "rfc7693_independent_unkeyed_kats": len(kat_cases),
        "rfc7693_independent_keyed_personalized_kats": len(keyed_cases),
        "gate_inventory": inventories,
        "dormant_v5_schedule": dormant_v5,
        "counter_final_boundary_lengths": [0, 1, 127, 128, 129, 255, 256, 257],
        "caller_inventory": {
            "dormant_v5_semantics": "host reference plus independently constrained trace; not aggregate",
            "hx448c02_scalar": "reuses generic BLAKE2b-448 trace with centralized source binding",
            "hx448c02_m4": "independent word-level lowering; no direct gadget object dependency",
            "legacy_smallwood_frontend": "unsupported and fail closed",
        },
        "host_digest_shortcut_in_gadget": False,
        "aggregate_constraint_relation_compiled": False,
        "complete_zero_knowledge": False,
        "composed_pq128": False,
        "production_authorized": False,
    }

    if check_certificate:
        require(CERTIFICATE.is_file() and not CERTIFICATE.is_symlink(), "missing retained certificate")
        certificate = json.loads(CERTIFICATE.read_text(encoding="utf-8"))
        expected_hashes = certificate.get("source_sha512", {})
        actual_hashes = {name: source_sha512(path) for name, path in PATHS.items()}
        require(actual_hashes == expected_hashes, "source SHA-512 set differs from retained certificate")
        expected_evidence_hashes = certificate.get("evidence_sha512", {})
        actual_evidence_hashes = {
            name: source_sha512(path) for name, path in EVIDENCE_PATHS.items()
        }
        require(
            actual_evidence_hashes == expected_evidence_hashes,
            "checker SHA-512 set differs from retained certificate",
        )
        for key in (
            "host_digest_shortcut_in_gadget",
            "aggregate_constraint_relation_compiled",
            "complete_zero_knowledge",
            "composed_pq128",
            "production_authorized",
        ):
            require(certificate.get(key) == report[key], f"certificate capability drift: {key}")
        require(
            certificate.get("dormant_v5_schedule") == report["dormant_v5_schedule"],
            "certificate dormant V5 schedule drift",
        )
    return report


def main() -> int:
    try:
        report = audit_sources(safe_sources())
    except (AuditError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "fail", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "pass", **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
