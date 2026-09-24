#!/usr/bin/env python3
"""Canonical proposed envelope header for the source-only size screen.

This parses only the proposed transport envelope. It is not a cryptographic
verifier and therefore does not satisfy the production-parser admission gate.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


MAGIC = b"HGVITH01"
VERSION = 1
HEADER_BYTES = 200
KNOWN_FLAGS = 0x0001  # embedded 114-word public instance

SECTION_NAMES = (
    "public_instance",
    "correction_vectors",
    "vole_consistency_response",
    "witness_derandomization",
    "quicksilver_response",
    "bavc_seed_opening",
    "bavc_hidden_leaf_commitments",
    "fs_final_challenge",
    "salt",
    "complete_zk_randomizer",
    "counter",
)

# magic, version, flags, total length, 64-byte relation digest, public/private
# word counts, lambda, tau, degree, small-VOLE k, leaf blocks, consistency
# padding, eleven u64 lengths, and six reserved zero bytes.
_HEADER = struct.Struct("<8sHHQ64sIIHHIHHH" + "Q" * len(SECTION_NAMES) + "6s")
assert _HEADER.size == HEADER_BYTES


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Header:
    flags: int
    total_length: int
    relation_digest: bytes
    public_words: int
    private_words: int
    lambda_bits: int
    tau: int
    degree: int
    small_vole_k: int
    leaf_commitment_blocks: int
    consistency_padding_bits: int
    section_lengths: tuple[int, ...]

    def encode(self) -> bytes:
        if self.flags & ~KNOWN_FLAGS:
            raise ParseError("unknown flags")
        if len(self.relation_digest) != 64:
            raise ParseError("relation digest must be SHAKE256-512 (64 bytes)")
        if len(self.section_lengths) != len(SECTION_NAMES):
            raise ParseError("wrong section count")
        if self.consistency_padding_bits % 8:
            raise ParseError("consistency padding is not byte aligned")
        expected_total = HEADER_BYTES + sum(self.section_lengths)
        if self.total_length != expected_total:
            raise ParseError("noncanonical total length")
        return _HEADER.pack(
            MAGIC,
            VERSION,
            self.flags,
            self.total_length,
            self.relation_digest,
            self.public_words,
            self.private_words,
            self.lambda_bits,
            self.tau,
            self.degree,
            self.small_vole_k,
            self.leaf_commitment_blocks,
            self.consistency_padding_bits,
            *self.section_lengths,
            bytes(6),
        )


def parse_header(blob: bytes) -> Header:
    if len(blob) < HEADER_BYTES:
        raise ParseError("truncated header")
    unpacked = _HEADER.unpack_from(blob)
    magic, version, flags, total_length = unpacked[:4]
    if magic != MAGIC:
        raise ParseError("bad magic")
    if version != VERSION:
        raise ParseError("unsupported version")
    if flags & ~KNOWN_FLAGS:
        raise ParseError("unknown flags")
    relation_digest = unpacked[4]
    (
        public_words,
        private_words,
        lambda_bits,
        tau,
        degree,
        small_vole_k,
        leaf_commitment_blocks,
        consistency_padding_bits,
    ) = unpacked[5:13]
    lengths_end = 13 + len(SECTION_NAMES)
    section_lengths = tuple(unpacked[13:lengths_end])
    reserved = unpacked[lengths_end]
    if reserved != bytes(6):
        raise ParseError("reserved bytes must be zero")
    if total_length != HEADER_BYTES + sum(section_lengths):
        raise ParseError("section lengths do not match total")
    if len(blob) != total_length:
        raise ParseError("truncated proof or trailing bytes")
    if public_words != 114 or private_words != 671:
        raise ParseError("wrong frozen M4 geometry")
    if lambda_bits % 8 or lambda_bits < 256:
        raise ParseError("unsupported challenge field")
    if tau == 0 or degree == 0:
        raise ParseError("zero protocol parameter")
    if small_vole_k == 0 or leaf_commitment_blocks == 0:
        raise ParseError("zero vector-commitment parameter")
    if tau * small_vole_k < lambda_bits:
        raise ParseError("small-VOLE challenge space is too small")
    if consistency_padding_bits % 8:
        raise ParseError("consistency padding is not byte aligned")
    lengths = dict(zip(SECTION_NAMES, section_lengths, strict=True))
    expected_fixed_lengths = {
        "public_instance": public_words * 8,
        "vole_consistency_response": (lambda_bits + consistency_padding_bits) // 8,
        "quicksilver_response": degree * lambda_bits // 8,
        "bavc_seed_opening": tau * small_vole_k * lambda_bits // 8,
        "bavc_hidden_leaf_commitments": (
            tau * leaf_commitment_blocks * lambda_bits // 8
        ),
        "fs_final_challenge": 64,
        "salt": 64,
        "complete_zk_randomizer": 4 * lambda_bits // 8,
        "counter": 4,
    }
    for name, expected in expected_fixed_lengths.items():
        if lengths[name] != expected:
            raise ParseError(f"noncanonical {name} length")
    return Header(
        flags=flags,
        total_length=total_length,
        relation_digest=relation_digest,
        public_words=public_words,
        private_words=private_words,
        lambda_bits=lambda_bits,
        tau=tau,
        degree=degree,
        small_vole_k=small_vole_k,
        leaf_commitment_blocks=leaf_commitment_blocks,
        consistency_padding_bits=consistency_padding_bits,
        section_lengths=section_lengths,
    )


def section_slices(header: Header) -> dict[str, slice]:
    offset = HEADER_BYTES
    result: dict[str, slice] = {}
    for name, length in zip(SECTION_NAMES, header.section_lengths, strict=True):
        result[name] = slice(offset, offset + length)
        offset += length
    if offset != header.total_length:
        raise ParseError("internal section accounting error")
    return result
