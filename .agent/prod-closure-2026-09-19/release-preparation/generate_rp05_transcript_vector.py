#!/usr/bin/env python3
"""Derive and validate the RP05 transcript vector from the checked-in fixture.

This is a Rust-source-fixture-bound generator, not a Lean generator or a
production-authority gate. The ignored Rust consumer compares source encoding
and mutations against the emitted vector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "circuits/transaction/src/smallwood_poseidon2_v8_program.rs"
FIXTURE = ROOT / "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05.bin"
OUTPUT = ROOT / "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05_transcript.json"
MAGIC = b"HGV8RP05"
GRAMMAR = 3
SECTION_COUNT = 9
SECTION_NAMES = [
    "geometry",
    "public_map_version_domain",
    "poseidon_parameter_manifest_digest",
    "ordered_nonlinear_identities",
    "linear_csr_compiler_families_and_symbolic_targets",
    "hash_schedule_and_call_roles",
    "binding_descriptors",
    "executable_nonlinear_expression_program",
    "executable_csr_expression_and_attempt_program",
]
MUTATION_CASES = [
    ("magic", True),
    ("grammar", True),
    ("section_order", True),
    ("section_tag", True),
    ("section_item_count", True),
    ("section_payload_length", True),
    ("geometry", True),
    ("public_map_descriptor", True),
    ("poseidon_parameter_manifest_digest", True),
    ("nonlinear_identity_descriptor", True),
    ("nonlinear_identity_order", True),
    ("linear_offset", True),
    ("linear_index", True),
    ("linear_coefficient", True),
    ("symbolic_public_target", True),
    ("linear_compiler_family", True),
    ("linear_compiler_family_order", True),
    ("hash_call_role", True),
    ("binding_descriptor", True),
    ("nonlinear_expression_opcode", True),
    ("nonlinear_expression_operand", True),
    ("nonlinear_expression_root", True),
    ("csr_expression_opcode", True),
    ("csr_expression_operand", True),
    ("csr_attempt_global", True),
    ("csr_attempt_family", True),
    ("csr_attempt_local", True),
    ("csr_attempt_emission", True),
    ("csr_witness_index", True),
    ("csr_coefficient_root", True),
    ("csr_target_root", True),
    ("statement_numeric_value", False),
]


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.data):
            raise ValueError("truncated RP05 transcript")
        out = self.data[self.offset:end]
        self.offset = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def done(self) -> None:
        if self.offset != len(self.data):
            raise ValueError("trailing bytes in RP05 transcript component")


def u8(value: int) -> bytes:
    return struct.pack("<B", value)


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def parse_sections(data: bytes) -> list[dict[str, Any]]:
    reader = Reader(data)
    magic = reader.take(8)
    grammar = reader.u16()
    count = reader.u16()
    if (magic, grammar, count) != (MAGIC, GRAMMAR, SECTION_COUNT):
        raise ValueError("fixture is not canonical HGV8RP05 grammar 3 with nine sections")
    sections = []
    for expected_tag in range(1, SECTION_COUNT + 1):
        tag = reader.u16()
        item_count = reader.u32()
        payload_len = reader.u64()
        payload = reader.take(payload_len)
        if tag != expected_tag:
            raise ValueError(f"section order/tag mismatch at {expected_tag}: {tag}")
        sections.append({"tag": tag, "item_count": item_count, "payload": payload})
    reader.done()
    rebuilt = bytearray(MAGIC + u16(GRAMMAR) + u16(SECTION_COUNT))
    for section in sections:
        payload = section["payload"]
        rebuilt += u16(section["tag"])
        rebuilt += u32(section["item_count"])
        rebuilt += u64(len(payload))
        rebuilt += payload
    if bytes(rebuilt) != data:
        raise ValueError("RP05 transcript does not canonically re-encode")
    return sections


def parse_geometry(payload: bytes) -> list[int]:
    reader = Reader(payload)
    values = [reader.u64() for _ in range(37)]
    reader.done()
    if len(payload) != 37 * 8:
        raise ValueError("RP05 geometry must contain exactly 37 words")
    return values


def parse_descriptors(payload: bytes, expected_count: int) -> list[dict[str, Any]]:
    reader = Reader(payload)
    count = reader.u32()
    if count != expected_count:
        raise ValueError("descriptor section item count mismatch")
    out = []
    rebuilt = bytearray(u32(count))
    for _ in range(count):
        opcode = reader.u16()
        word_count = reader.u16()
        words = [reader.u64() for _ in range(word_count)]
        label_bytes = reader.take(reader.u32())
        label = label_bytes.decode("utf-8")
        out.append({"opcode": opcode, "words": words, "label": label})
        rebuilt += u16(opcode) + u16(word_count)
        rebuilt += b"".join(u64(word) for word in words)
        rebuilt += u32(len(label_bytes)) + label_bytes
    reader.done()
    if bytes(rebuilt) != payload:
        raise ValueError("descriptor payload does not canonically re-encode")
    return out


def parse_expressions(payload: bytes, *, expected_roots: int, allow_witness: bool) -> tuple[int, int]:
    reader = Reader(payload)
    count = reader.u32()
    rebuilt = bytearray(u32(count))
    for node in range(count):
        opcode = reader.u8()
        rebuilt += u8(opcode)
        if opcode == 0x01:
            value = reader.u64()
            if value >= 0xFFFF_FFFF_0000_0001:
                raise ValueError("noncanonical Goldilocks literal")
            rebuilt += u64(value)
        elif opcode in (0x02, 0x03):
            index = reader.u16()
            if opcode == 0x03 and not allow_witness:
                raise ValueError("CSR expression refers to witness rows")
            if opcode == 0x02 and index >= 120:
                raise ValueError("public expression index out of bounds")
            if opcode == 0x03 and index >= 686:
                raise ValueError("witness expression index out of bounds")
            rebuilt += u16(index)
        elif opcode in (0x10, 0x11, 0x12):
            for _ in range(2):
                operand = reader.u32()
                if operand >= node:
                    raise ValueError("expression operand must precede its node")
                rebuilt += u32(operand)
        elif opcode in (0x13, 0x14):
            operand = reader.u32()
            if operand >= node:
                raise ValueError("expression operand must precede its node")
            rebuilt += u32(operand)
        elif opcode == 0x15:
            for _ in range(4):
                operand = reader.u32()
                if operand >= node:
                    raise ValueError("expression operand must precede its node")
                rebuilt += u32(operand)
        elif opcode == 0x16:
            operand = reader.u32()
            lane = reader.u8()
            if operand >= node or lane >= 64:
                raise ValueError("invalid packed-lane expression")
            rebuilt += u32(operand) + u8(lane)
        else:
            raise ValueError(f"unknown RP05 expression opcode {opcode:#x}")
    roots = reader.u32()
    rebuilt += u32(roots)
    if roots != expected_roots:
        raise ValueError("expression root count mismatch")
    for _ in range(roots):
        root = reader.u32()
        if root >= count:
            raise ValueError("expression root index out of bounds")
        rebuilt += u32(root)
    reader.done()
    if bytes(rebuilt) != payload:
        raise ValueError("expression payload does not canonically re-encode")
    return count, roots


def parse_csr(payload: bytes, expected_families: list[dict[str, Any]]) -> tuple[int, int]:
    reader = Reader(payload)
    expression_bytes = reader.u32()
    expression_payload = reader.take(expression_bytes)
    expression_count, expression_roots = parse_expressions(
        expression_payload, expected_roots=0, allow_witness=False
    )
    count = reader.u32()
    if count != 20_588:
        raise ValueError("RP05 CSR attempted-row count mismatch")
    rebuilt = bytearray(u32(len(expression_payload)) + expression_payload + u32(count))
    family_counts = [0] * len(expected_families)
    for expected_global in range(count):
        global_index = reader.u32()
        family = reader.u16()
        local = reader.u32()
        emission = reader.u8()
        term_count = reader.u16()
        terms = [(reader.u32(), reader.u32()) for _ in range(term_count)]
        target = reader.u32()
        if global_index != expected_global or family >= len(expected_families):
            raise ValueError("CSR attempt order or family index mismatch")
        if local != family_counts[family] or emission not in (0, 1):
            raise ValueError("CSR family local index or emission tag mismatch")
        if emission != expected_families[family]["words"][2]:
            raise ValueError("CSR family emission differs from family descriptor")
        if any(index >= 43_904 or coefficient >= expression_count for index, coefficient in terms):
            raise ValueError("CSR term index is out of bounds")
        if target >= expression_count:
            raise ValueError("CSR target root is out of bounds")
        family_counts[family] += 1
        rebuilt += u32(global_index) + u16(family) + u32(local) + u8(emission) + u16(term_count)
        for index, coefficient in terms:
            rebuilt += u32(index) + u32(coefficient)
        rebuilt += u32(target)
    reader.done()
    if family_counts != [family["words"][1] for family in expected_families]:
        raise ValueError("CSR family attempt counts differ from descriptors")
    if bytes(rebuilt) != payload:
        raise ValueError("CSR attempt payload does not canonically re-encode")
    return expression_count, expression_roots


def const_array(source: str, name: str) -> list[int]:
    match = re.search(
        rf"pub const {re.escape(name)}\s*:[^=]+?=\s*\[(.*?)\];",
        source,
        re.S,
    )
    if not match:
        raise ValueError(f"missing source constant {name}")
    return [int(token.replace("_", ""), 0) for token in re.findall(r"0x[0-9a-fA-F]+|\d[\d_]*", match.group(1))]


def source_scalar(source: str, name: str) -> int:
    match = re.search(
        rf"pub const {re.escape(name)}\s*:\s*\w+\s*=\s*([\d_]+)", source
    )
    if not match:
        raise ValueError(f"missing source scalar {name}")
    return int(match.group(1).replace("_", ""))


def vector() -> dict[str, Any]:
    data = FIXTURE.read_bytes()
    source = SOURCE.read_text(encoding="utf-8")
    sha512 = hashlib.sha512(data).digest()
    relation_id = sha512[:48]
    if data[:8] != MAGIC:
        raise ValueError("fixture magic is not HGV8RP05")
    if sha512 != bytes(const_array(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512")):
        raise ValueError("fixture SHA-512 differs from the Rust source identity pin")
    if relation_id != bytes(const_array(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST")):
        raise ValueError("fixture relation id differs from the Rust source identity pin")
    if len(data) != source_scalar(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES"):
        raise ValueError("fixture byte length differs from the Rust source pin")
    if source_scalar(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_GRAMMAR") != GRAMMAR:
        raise ValueError("source grammar is not the RP05 vector grammar")
    if source_scalar(source, "SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT") != SECTION_COUNT:
        raise ValueError("source section count is not nine")

    sections = parse_sections(data)
    expected_counts = [37, 59, 1, 818, 92, 128, 8, 818, 20_588]
    if [section["item_count"] for section in sections] != expected_counts:
        raise ValueError("RP05 section item counts differ from current source geometry")
    geometry = parse_geometry(sections[0]["payload"])
    if geometry != const_array(source, "SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS"):
        raise ValueError("geometry section differs from the Rust source geometry")
    public = parse_descriptors(sections[1]["payload"], expected_counts[1])
    nonlinear = parse_descriptors(sections[3]["payload"], expected_counts[3])
    families = parse_descriptors(sections[4]["payload"], expected_counts[4])
    hashes = parse_descriptors(sections[5]["payload"], expected_counts[5])
    bindings = parse_descriptors(sections[6]["payload"], expected_counts[6])
    if sections[2]["payload"] != bytes(const_array(source, "SMALLWOOD_POSEIDON2_V8_POSEIDON_PARAMETER_SHA256")):
        raise ValueError("Poseidon parameter digest differs from Rust source")
    nonlinear_nodes, nonlinear_roots = parse_expressions(
        sections[7]["payload"], expected_roots=818, allow_witness=True
    )
    csr_nodes, csr_roots = parse_csr(sections[8]["payload"], families)
    if bindings[0] != {
        "opcode": 0x0701,
        "words": [8, 7, 1, 10, 2, 6, 4],
        "label": "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v4\0SMZ9",
    }:
        raise ValueError("RP05 exact relation identity binding mismatch")
    expected_bindings = [
        {"opcode": 0x0701, "words": [8, 7, 1, 10, 2, 6, 4], "label": "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v4\0SMZ9"},
        {"opcode": 0x0702, "words": [120, 0xFFFF_FFFF_0000_0001], "label": "HGV8TX02.statement[0,120)->verifier.public[0,120);canonical-goldilocks"},
        {"opcode": 0x0703, "words": [7, 87, 94], "label": "relation.binding[0,7)=expected-action-intent=call[93].final[0,7)"},
        {"opcode": 0x0704, "words": [0, 247, 247, 5, 252, 31, 283, 364, 647, 39, 686], "label": "rows=raw[0,247);dense[247,252);inline[252,283);hash[283,647);stable[647,686)"},
        {"opcode": 0x0705, "words": [128, 128, 16, 0], "label": "calls[128,128).initial[0,16)=0"},
        {"opcode": 0x0706, "words": [0], "label": "auxiliary-witness-words=0"},
        {"opcode": 0x0707, "words": [64, 8, 818, 19_824, 20_496, 21_314, 5, 6, 2, 23, 20, 5], "label": "DirectPacked64Poseidon2V8Sha512Smz9\0Sha512Poseidon2V8Smz9\0rho5-open6-beta2-N23-q20-eta5"},
        {"opcode": 0x0708, "words": [64, 48], "label": "SHA-512\0HGV8RP05-canonical-executable-program-prefix[0,48)"},
    ]
    if bindings != expected_bindings:
        raise ValueError("one or more RP05 exact binding descriptors differ")
    if bindings[-1]["label"] != "SHA-512\0HGV8RP05-canonical-executable-program-prefix[0,48)":
        raise ValueError("RP05 exact relation digest binding mismatch")
    if source_scalar(source, "SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT") != len(families):
        raise ValueError("CSR family count differs from current Rust source")

    opcode_runs = []
    for descriptor in public:
        opcode = descriptor["opcode"]
        if opcode_runs and opcode_runs[-1][0] == opcode:
            opcode_runs[-1][1] += 1
        else:
            opcode_runs.append([opcode, 1])

    return {
        "schema": "hegemon.poseidon2-v8.relation-program-transcript-v2",
        "claim_scope": "source_bound_rp05_canonical_statement_independent_program_identity_kat",
        "artifact_available": True,
        "generator": "generate_rp05_transcript_vector.py",
        "generator_authority": "Python parser and Rust source-pinned fixture; not Lean-generated",
        "magic_ascii": MAGIC.decode("ascii"),
        "magic_bytes": list(MAGIC),
        "grammar": GRAMMAR,
        "header_bytes": list(MAGIC + u16(GRAMMAR) + u16(SECTION_COUNT)),
        "hash": "SHA-512",
        "digest_bytes": 64,
        "native_relation_id_derivation": "sha512_digest_prefix",
        "native_relation_id_bytes": 48,
        "transcript_bytes": len(data),
        "section_header": "u16le_tag_u32le_item_count_u64le_payload_bytes",
        "section_header_bytes": 14,
        "section_tags": [section["tag"] for section in sections],
        "section_names": SECTION_NAMES,
        "section_item_counts": [section["item_count"] for section in sections],
        "descriptor_opcodes": {
            "public_identity": 513,
            "public_range": 514,
            "intent_zero_range": 515,
            "domain_or_marker": 516,
            "compiler_normalization": 517,
            "nonlinear_identity": 1025,
            "linear_csr_family": 1281,
            "sponge_call": 1537,
            "compress14_call": 1538,
            "binding_start": 1793,
            "binding_stop": 2048,
        },
        "exact_binding_opcodes": [descriptor["opcode"] for descriptor in bindings],
        "exact_binding_descriptors": bindings,
        "compound_label_separator_byte": 0,
        "public_descriptor_count": len(public),
        "public_descriptor_opcode_runs": opcode_runs,
        "poseidon_parameter_set_sha256_bytes": list(sections[2]["payload"]),
        "geometry_words": geometry,
        "fixed_geometry": {
            "statement_words": geometry[8],
            "binding_limbs": geometry[9],
            "relation_rows": geometry[20],
            "proof_geometry_columns": geometry[35],
            "live_hash_calls": geometry[23],
            "padded_hash_calls": geometry[24],
            "nonlinear_identities": geometry[31],
            "minimum_linear_constraints": geometry[32],
            "maximum_linear_constraints": geometry[33],
            "maximum_summed_identity_union": geometry[34],
            "linear_compiler_families": len(families),
            "linear_compiler_family_instances": sum(family["words"][1] for family in families),
            "nonlinear_expression_nodes": nonlinear_nodes,
            "nonlinear_expression_roots": nonlinear_roots,
            "csr_expression_nodes": csr_nodes,
            "csr_expression_roots": csr_roots,
            "hash_call_descriptors": len(hashes),
            "global_binding_descriptors": len(bindings),
            "packed_witness_words": geometry[36],
        },
        "statement_values_serialized": False,
        "final_program_sha512": sha512.hex(),
        "final_relation_id_48": relation_id.hex(),
        "source_recomputation_required": True,
        "production_authority": False,
        "mutation_cases": [
            {"name": name, "expected_relation_id_change": changes}
            for name, changes in MUTATION_CASES
        ],
    }


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="create the vector, or accept byte-identical existing output")
    args = parser.parse_args()
    expected = canonical_bytes(vector())
    if args.write:
        if OUTPUT.is_symlink():
            raise SystemExit("refusing symlink output")
        if OUTPUT.exists():
            if OUTPUT.read_bytes() != expected:
                raise SystemExit("existing RP05 vector differs; refusing overwrite")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            with OUTPUT.open("xb") as output:
                output.write(expected)
                output.flush()
        observed = OUTPUT.read_bytes()
        if observed != expected:
            raise SystemExit("RP05 vector readback mismatch")
        print(f"created-or-confirmed {OUTPUT.relative_to(ROOT)} sha512={hashlib.sha512(observed).hexdigest()}")
    else:
        observed = OUTPUT.read_bytes()
        if observed != expected:
            raise SystemExit("RP05 transcript vector is stale; run with --write")
        print(f"verified {OUTPUT.relative_to(ROOT)} sha512={hashlib.sha512(observed).hexdigest()}")


if __name__ == "__main__":
    main()
