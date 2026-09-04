#!/usr/bin/env python3
"""Generate the exact Lean HGV8RP03 RelationProgramComponents value.

The input is the canonical, statement-independent relation program transcript
emitted by the Rust HGV8RP03 source compiler.  This generator parses every
length-delimited section, rejects trailing or non-canonical data, and emits the
same program as a typed Lean value.  It does not grant production authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence, TypeVar


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = (
    ROOT / "testdata/formal_core_vectors/poseidon2_v8_relation_program.bin"
)
EXPECTED_BYTES = 852_305
EXPECTED_SHA512 = (
    "8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e4"
    "6a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3"
)
EXPECTED_MAGIC = b"HGV8RP03"
EXPECTED_GRAMMAR = 3
EXPECTED_SECTION_COUNT = 9
FIELD_MODULUS = 18_446_744_069_414_584_321
EXPECTED_GEOMETRY = (
    FIELD_MODULUS,
    16,
    8,
    8,
    7,
    7,
    8,
    22,
    120,
    7,
    0,
    247,
    247,
    5,
    252,
    31,
    283,
    364,
    647,
    39,
    686,
    64,
    8,
    125,
    128,
    3,
    2,
    150,
    182,
    166,
    332,
    830,
    19_899,
    20_473,
    21_303,
    368,
    43_904,
)
EXPECTED_PARAMETER_DIGEST = bytes.fromhex(
    "114a4e7eb2684d293d13d306a756b03fc734f19edbfb80a07126ab1b2ad9e529"
)


class DecodeError(ValueError):
    """Raised when the canonical program transcript does not parse exactly."""


class Reader:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.offset = 0

    def _take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.data):
            raise DecodeError(
                f"{self.label}: truncated at byte {self.offset}, need {count} bytes"
            )
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self._take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self._take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self._take(8), "little")

    def blob(self) -> bytes:
        return self._take(self.u32())

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DecodeError(
                f"{self.label}: {len(self.data) - self.offset} trailing bytes"
            )


@dataclass(frozen=True)
class Descriptor:
    opcode: int
    words: tuple[int, ...]
    label: bytes


@dataclass(frozen=True)
class Expression:
    opcode: int
    operands: tuple[int, ...]


@dataclass(frozen=True)
class Attempt:
    global_index: int
    family: int
    local_index: int
    emission: int
    terms: tuple[tuple[int, int], ...]
    target_root: int


@dataclass(frozen=True)
class Components:
    geometry_words: tuple[int, ...]
    public_descriptors: tuple[Descriptor, ...]
    parameter_digest: bytes
    nonlinear_descriptors: tuple[Descriptor, ...]
    csr_family_descriptors: tuple[Descriptor, ...]
    hash_descriptors: tuple[Descriptor, ...]
    binding_descriptors: tuple[Descriptor, ...]
    nonlinear_expressions: tuple[Expression, ...]
    nonlinear_roots: tuple[int, ...]
    csr_expressions: tuple[Expression, ...]
    csr_attempts: tuple[Attempt, ...]


def encode_uint(value: int, width: int, label: str) -> bytes:
    try:
        return value.to_bytes(width, "little")
    except OverflowError as error:
        raise DecodeError(f"{label}: {value} does not fit {width} bytes") from error


def encode_blob(value: bytes) -> bytes:
    return encode_uint(len(value), 4, "blob length") + value


def encode_descriptor(value: Descriptor) -> bytes:
    return (
        encode_uint(value.opcode, 2, "descriptor opcode")
        + encode_uint(len(value.words), 2, "descriptor word count")
        + b"".join(encode_uint(word, 8, "descriptor word") for word in value.words)
        + encode_blob(value.label)
    )


def encode_descriptors(values: Sequence[Descriptor]) -> bytes:
    return encode_uint(len(values), 4, "descriptor count") + b"".join(
        encode_descriptor(value) for value in values
    )


def encode_expression(value: Expression) -> bytes:
    opcode = bytes([value.opcode])
    if value.opcode == 0x01:
        return opcode + encode_uint(value.operands[0], 8, "constant")
    if value.opcode in (0x02, 0x03):
        return opcode + encode_uint(value.operands[0], 2, "short expression operand")
    if value.opcode in (0x10, 0x11, 0x12):
        return opcode + b"".join(
            encode_uint(operand, 4, "binary expression operand")
            for operand in value.operands
        )
    if value.opcode in (0x13, 0x14):
        return opcode + encode_uint(value.operands[0], 4, "unary expression operand")
    if value.opcode == 0x15:
        return opcode + b"".join(
            encode_uint(operand, 4, "select expression operand")
            for operand in value.operands
        )
    if value.opcode == 0x16:
        return (
            opcode
            + encode_uint(value.operands[0], 4, "bit expression operand")
            + encode_uint(value.operands[1], 1, "bit index")
        )
    raise DecodeError(f"cannot encode expression opcode {value.opcode:#04x}")


def encode_expression_program(
    expressions: Sequence[Expression], roots: Sequence[int]
) -> bytes:
    return (
        encode_uint(len(expressions), 4, "expression count")
        + b"".join(encode_expression(value) for value in expressions)
        + encode_uint(len(roots), 4, "expression root count")
        + b"".join(encode_uint(root, 4, "expression root") for root in roots)
    )


def encode_attempt(value: Attempt) -> bytes:
    return (
        encode_uint(value.global_index, 4, "attempt global index")
        + encode_uint(value.family, 2, "attempt family")
        + encode_uint(value.local_index, 4, "attempt local index")
        + encode_uint(value.emission, 1, "attempt emission")
        + encode_uint(len(value.terms), 2, "attempt term count")
        + b"".join(
            encode_uint(witness, 4, "attempt witness index")
            + encode_uint(coefficient, 4, "attempt coefficient root")
            for witness, coefficient in value.terms
        )
        + encode_uint(value.target_root, 4, "attempt target root")
    )


def encode_section(tag: int, item_count: int, payload: bytes) -> bytes:
    return (
        encode_uint(tag, 2, "section tag")
        + encode_uint(item_count, 4, "section item count")
        + encode_uint(len(payload), 8, "section payload length")
        + payload
    )


def encode_components(value: Components) -> bytes:
    nonlinear_program = encode_expression_program(
        value.nonlinear_expressions, value.nonlinear_roots
    )
    csr_program = encode_expression_program(value.csr_expressions, ())
    csr_payload = (
        encode_blob(csr_program)
        + encode_uint(len(value.csr_attempts), 4, "CSR attempt count")
        + b"".join(encode_attempt(attempt) for attempt in value.csr_attempts)
    )
    sections = (
        encode_section(
            1,
            len(value.geometry_words),
            b"".join(encode_uint(word, 8, "geometry word") for word in value.geometry_words),
        ),
        encode_section(
            2,
            len(value.public_descriptors),
            encode_descriptors(value.public_descriptors),
        ),
        encode_section(3, 1, value.parameter_digest),
        encode_section(
            4,
            len(value.nonlinear_descriptors),
            encode_descriptors(value.nonlinear_descriptors),
        ),
        encode_section(
            5,
            len(value.csr_family_descriptors),
            encode_descriptors(value.csr_family_descriptors),
        ),
        encode_section(
            6,
            len(value.hash_descriptors),
            encode_descriptors(value.hash_descriptors),
        ),
        encode_section(
            7,
            len(value.binding_descriptors),
            encode_descriptors(value.binding_descriptors),
        ),
        encode_section(8, len(value.nonlinear_roots), nonlinear_program),
        encode_section(9, len(value.csr_attempts), csr_payload),
    )
    return (
        EXPECTED_MAGIC
        + encode_uint(EXPECTED_GRAMMAR, 2, "grammar")
        + encode_uint(EXPECTED_SECTION_COUNT, 2, "section count")
        + b"".join(sections)
    )


def parse_descriptors(payload: bytes, item_count: int, label: str) -> tuple[Descriptor, ...]:
    reader = Reader(payload, label)
    encoded_count = reader.u32()
    if encoded_count != item_count:
        raise DecodeError(
            f"{label}: descriptor count {encoded_count} != section count {item_count}"
        )
    values: list[Descriptor] = []
    for _ in range(encoded_count):
        opcode = reader.u16()
        word_count = reader.u16()
        words = tuple(reader.u64() for _ in range(word_count))
        descriptor_label = reader.blob()
        if any(byte >= 128 for byte in descriptor_label):
            raise DecodeError(f"{label}: descriptor label is not ASCII")
        values.append(Descriptor(opcode, words, descriptor_label))
    reader.finish()
    return tuple(values)


def parse_expression_program(
    payload: bytes, label: str, *, allow_witness_rows: bool
) -> tuple[tuple[Expression, ...], tuple[int, ...]]:
    reader = Reader(payload, label)
    expression_count = reader.u32()
    expressions: list[Expression] = []
    for node in range(expression_count):
        opcode = reader.u8()
        if opcode == 0x01:
            operands = (reader.u64(),)
        elif opcode in (0x02, 0x03):
            operands = (reader.u16(),)
        elif opcode in (0x10, 0x11, 0x12):
            operands = (reader.u32(), reader.u32())
        elif opcode in (0x13, 0x14):
            operands = (reader.u32(),)
        elif opcode == 0x15:
            operands = (reader.u32(), reader.u32(), reader.u32(), reader.u32())
        elif opcode == 0x16:
            operands = (reader.u32(), reader.u8())
        else:
            raise DecodeError(f"{label}: unknown expression opcode {opcode:#04x} at {node}")
        if opcode == 0x01 and operands[0] >= FIELD_MODULUS:
            raise DecodeError(f"{label}: non-canonical constant at node {node}")
        if opcode == 0x02 and operands[0] >= 120:
            raise DecodeError(f"{label}: public index out of range at node {node}")
        if opcode == 0x03 and (not allow_witness_rows or operands[0] >= 686):
            raise DecodeError(f"{label}: witness index out of range at node {node}")
        if opcode in (0x10, 0x11, 0x12) and any(value >= node for value in operands):
            raise DecodeError(f"{label}: forward binary reference at node {node}")
        if opcode in (0x13, 0x14) and operands[0] >= node:
            raise DecodeError(f"{label}: forward unary reference at node {node}")
        if opcode == 0x15 and any(value >= node for value in operands):
            raise DecodeError(f"{label}: forward select reference at node {node}")
        if opcode == 0x16 and (operands[0] >= node or operands[1] >= 64):
            raise DecodeError(f"{label}: invalid bit reference at node {node}")
        expressions.append(Expression(opcode, operands))
    root_count = reader.u32()
    roots = tuple(reader.u32() for _ in range(root_count))
    if any(root >= expression_count for root in roots):
        raise DecodeError(f"{label}: expression root out of range")
    reader.finish()
    return tuple(expressions), roots


def parse_csr_program(
    payload: bytes, item_count: int
) -> tuple[tuple[Expression, ...], tuple[Attempt, ...]]:
    reader = Reader(payload, "section 9")
    expressions, roots = parse_expression_program(
        reader.blob(), "section 9 expressions", allow_witness_rows=False
    )
    if roots:
        raise DecodeError("section 9: CSR expression program must have no roots")
    attempt_count = reader.u32()
    if attempt_count != item_count:
        raise DecodeError(
            f"section 9: attempt count {attempt_count} != section count {item_count}"
        )
    attempts: list[Attempt] = []
    for expected_global in range(attempt_count):
        global_index = reader.u32()
        family = reader.u16()
        local_index = reader.u32()
        emission = reader.u8()
        if global_index != expected_global:
            raise DecodeError(
                f"section 9: global index {global_index} != {expected_global}"
            )
        if emission not in (0, 1):
            raise DecodeError(f"section 9: invalid emission {emission}")
        term_count = reader.u16()
        terms = tuple((reader.u32(), reader.u32()) for _ in range(term_count))
        target_root = reader.u32()
        if family >= 86:
            raise DecodeError(f"section 9: family {family} out of range")
        if any(witness >= 43_904 or coefficient >= 565 for witness, coefficient in terms):
            raise DecodeError(f"section 9: term out of range at attempt {global_index}")
        if target_root >= 565:
            raise DecodeError(f"section 9: target root out of range at attempt {global_index}")
        attempts.append(
            Attempt(global_index, family, local_index, emission, terms, target_root)
        )
    reader.finish()
    return expressions, tuple(attempts)


def parse_components(data: bytes, *, verify_identity: bool = True) -> Components:
    if verify_identity:
        if len(data) != EXPECTED_BYTES:
            raise DecodeError(f"program has {len(data)} bytes, expected {EXPECTED_BYTES}")
        digest = hashlib.sha512(data).hexdigest()
        if digest != EXPECTED_SHA512:
            raise DecodeError(f"program SHA-512 {digest} != pinned {EXPECTED_SHA512}")

    reader = Reader(data, "HGV8RP03 transcript")
    if reader._take(8) != EXPECTED_MAGIC:
        raise DecodeError("program magic is not HGV8RP03")
    if reader.u16() != EXPECTED_GRAMMAR:
        raise DecodeError("program grammar is not 3")
    if reader.u16() != EXPECTED_SECTION_COUNT:
        raise DecodeError("program section count is not 9")

    sections: list[tuple[int, int, bytes]] = []
    for expected_tag in range(1, EXPECTED_SECTION_COUNT + 1):
        tag = reader.u16()
        item_count = reader.u32()
        payload_size = reader.u64()
        payload = reader._take(payload_size)
        if tag != expected_tag:
            raise DecodeError(f"section tag {tag} != expected {expected_tag}")
        sections.append((tag, item_count, payload))
    reader.finish()

    geometry_reader = Reader(sections[0][2], "section 1")
    geometry_words = tuple(geometry_reader.u64() for _ in range(sections[0][1]))
    geometry_reader.finish()
    if geometry_words != EXPECTED_GEOMETRY:
        raise DecodeError("section 1: geometry differs from exact HGV8RP03 geometry")

    parameter_digest = sections[2][2]
    if sections[2][1] != 1 or len(parameter_digest) != 32:
        raise DecodeError("section 3: expected one 32-byte parameter digest")
    if parameter_digest != EXPECTED_PARAMETER_DIGEST:
        raise DecodeError("section 3: Poseidon2 parameter digest differs from HGV8RP03")

    nonlinear_expressions, nonlinear_roots = parse_expression_program(
        sections[7][2], "section 8", allow_witness_rows=True
    )
    if len(nonlinear_roots) != sections[7][1]:
        raise DecodeError("section 8: root count differs from section item count")
    csr_expressions, csr_attempts = parse_csr_program(sections[8][2], sections[8][1])

    components = Components(
        geometry_words,
        parse_descriptors(sections[1][2], sections[1][1], "section 2"),
        parameter_digest,
        parse_descriptors(sections[3][2], sections[3][1], "section 4"),
        parse_descriptors(sections[4][2], sections[4][1], "section 5"),
        parse_descriptors(sections[5][2], sections[5][1], "section 6"),
        parse_descriptors(sections[6][2], sections[6][1], "section 7"),
        nonlinear_expressions,
        nonlinear_roots,
        csr_expressions,
        csr_attempts,
    )

    exact_counts = (
        len(components.geometry_words),
        len(components.public_descriptors),
        len(components.nonlinear_descriptors),
        len(components.csr_family_descriptors),
        len(components.hash_descriptors),
        len(components.binding_descriptors),
        len(components.nonlinear_expressions),
        len(components.nonlinear_roots),
        len(components.csr_expressions),
        len(components.csr_attempts),
    )
    expected_counts = (37, 56, 830, 86, 125, 8, 8271, 830, 565, 20569)
    if exact_counts != expected_counts:
        raise DecodeError(f"program inventory {exact_counts} != {expected_counts}")

    expected_public_opcodes = (0x0201,) + (0x0202,) * 28 + (0x0203,) * 4 + (0x0204,) * 22 + (0x0205,)
    if tuple(item.opcode for item in components.public_descriptors) != expected_public_opcodes:
        raise DecodeError("section 2: public descriptor opcode run differs from HGV8RP03")
    if any(item.opcode != 0x0401 for item in components.nonlinear_descriptors):
        raise DecodeError("section 4: nonlinear descriptor opcode differs from HGV8RP03")
    if any(item.opcode != 0x0501 for item in components.csr_family_descriptors):
        raise DecodeError("section 5: CSR family descriptor opcode differs from HGV8RP03")
    if any(item.opcode not in (0x0601, 0x0602) for item in components.hash_descriptors):
        raise DecodeError("section 6: hash descriptor opcode differs from HGV8RP03")
    if tuple(item.opcode for item in components.binding_descriptors) != tuple(range(0x0701, 0x0709)):
        raise DecodeError("section 7: binding descriptor opcode run differs from HGV8RP03")

    local_by_family = [0] * 86
    for entry in components.csr_attempts:
        descriptor = components.csr_family_descriptors[entry.family]
        if len(descriptor.words) != 3:
            raise DecodeError(f"section 5: malformed family {entry.family} descriptor")
        if descriptor.words[0] != entry.family:
            raise DecodeError(f"section 5: family index mismatch at {entry.family}")
        if entry.local_index != local_by_family[entry.family]:
            raise DecodeError(
                f"section 9: local index mismatch at attempt {entry.global_index}"
            )
        if entry.emission != descriptor.words[2]:
            raise DecodeError(
                f"section 9: emission mismatch at attempt {entry.global_index}"
            )
        local_by_family[entry.family] += 1
    expected_by_family = [int(item.words[1]) for item in components.csr_family_descriptors]
    if local_by_family != expected_by_family:
        raise DecodeError("section 9: CSR family attempt inventory is incomplete")
    reencoded = encode_components(components)
    if reencoded != data:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(zip(reencoded, data))
                if actual != expected
            ),
            min(len(reencoded), len(data)),
        )
        raise DecodeError(
            f"canonical decode/encode mismatch at byte {mismatch}: "
            f"reencoded {len(reencoded)} bytes, input {len(data)} bytes"
        )
    return components


def expect_decode_error(label: str, operation: Callable[[], object], fragment: str) -> None:
    try:
        operation()
    except DecodeError as error:
        if fragment not in str(error):
            raise AssertionError(
                f"{label}: error {error!s} does not contain {fragment!r}"
            ) from error
    else:
        raise AssertionError(f"{label}: malformed input unexpectedly parsed")


def run_self_test(data: bytes) -> None:
    parse_components(data)

    sha_mutation = bytearray(data)
    sha_mutation[-1] ^= 1
    expect_decode_error(
        "SHA mutation",
        lambda: parse_components(bytes(sha_mutation)),
        "SHA-512",
    )
    expect_decode_error(
        "truncation",
        lambda: parse_components(data[:-1], verify_identity=False),
        "truncated",
    )
    expect_decode_error(
        "trailing byte",
        lambda: parse_components(data + b"\x00", verify_identity=False),
        "trailing bytes",
    )

    # Section 2 begins after the 12-byte transcript header and the exact
    # 14 + 37*8-byte geometry section. Its first descriptor has eight words;
    # overwrite the following label length with a value larger than the file.
    malformed_length = bytearray(data)
    section_two_payload = 12 + 14 + 37 * 8 + 14
    first_label_length = section_two_payload + 4 + 2 + 2 + 8 * 8
    malformed_length[first_label_length : first_label_length + 4] = (2**32 - 1).to_bytes(
        4, "little"
    )
    expect_decode_error(
        "malformed descriptor length",
        lambda: parse_components(bytes(malformed_length), verify_identity=False),
        "truncated",
    )

    malformed_reference = (
        (1).to_bytes(4, "little")
        + bytes([0x10])
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )
    expect_decode_error(
        "forward expression reference",
        lambda: parse_expression_program(
            malformed_reference, "self-test expression", allow_witness_rows=True
        ),
        "forward binary reference",
    )


T = TypeVar("T")


def chunks(values: Sequence[T], size: int = 32) -> Iterable[Sequence[T]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def lean_nat_list(values: Sequence[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def emit_chunked_list(
    out: list[str], name: str, lean_type: str, values: Sequence[T], render: Callable[[T], str]
) -> None:
    out.append(f"def {name} : List {lean_type} :=")
    out.append("  List.flatten [")
    rendered_chunks = list(chunks(values))
    for chunk_index, chunk in enumerate(rendered_chunks):
        suffix = "," if chunk_index + 1 < len(rendered_chunks) else ""
        out.append("    ([" + ", ".join(render(value) for value in chunk) +"] : List " + lean_type + ")" + suffix)
    out.append("  ]")
    out.append("")


def render_descriptor(value: Descriptor) -> str:
    return (
        f"descriptor {value.opcode} {lean_nat_list(value.words)} "
        f"{lean_nat_list(tuple(value.label))}"
    )


def render_expression(value: Expression) -> str:
    names = {
        0x01: "FieldExpression.constant",
        0x02: "FieldExpression.publicWord",
        0x03: "FieldExpression.witnessRow",
        0x10: "FieldExpression.add",
        0x11: "FieldExpression.sub",
        0x12: "FieldExpression.mul",
        0x13: "FieldExpression.neg",
        0x14: "FieldExpression.inverse",
        0x15: "FieldExpression.selectEqual",
        0x16: "FieldExpression.bit",
    }
    return names[value.opcode] + " " + " ".join(str(item) for item in value.operands)


def render_terms(terms: Sequence[tuple[int, int]]) -> str:
    return "[" + ", ".join(f"({left}, {right})" for left, right in terms) + "]"


def render_attempt(value: Attempt) -> str:
    return (
        f"attempt {value.global_index} {value.family} {value.local_index} {value.emission} "
        f"{render_terms(value.terms)} {value.target_root}"
    )


def emit_lean(components: Components, input_path: Path) -> str:
    out = [
        "import Hegemon.Transaction.Poseidon2V8RelationProgram",
        "",
        "set_option maxHeartbeats 0",
        "set_option maxRecDepth 1000000",
        "",
        "/-!",
        "This file is generated by",
        "`scripts/generate_poseidon2_v8_relation_program_components_lean.py` from the exact",
        "852,305-byte HGV8RP03 program artifact. The generator rejects any input whose SHA-512",
        f"differs from `{EXPECTED_SHA512}` and parses every section to exact exhaustion.",
        "Do not edit this file by hand. This value identifies the program; it grants no production",
        "authority and proves no cryptographic hash assumption.",
        "-/",
        "",
        "namespace HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated",
        "",
        "open Hegemon.Transaction.Poseidon2V8RelationProgram",
        "",
        "def asciiLabel (bytes : List Nat) : String :=",
        "  String.ofList (bytes.map Char.ofNat)",
        "",
        "def descriptor (opcode : Nat) (words labelBytes : List Nat) : ProgramDescriptor :=",
        "  { opcode, words, label := asciiLabel labelBytes }",
        "",
        "def attempt (globalIndex family localIndex emission : Nat)",
        "    (terms : List (Nat × Nat)) (targetRoot : Nat) : CsrExecutableAttempt :=",
        "  { globalIndex, family, localIndex, emission, terms, targetRoot }",
        "",
        "def sourceArtifactRelativePath : String := "
        + json.dumps(input_path.relative_to(ROOT).as_posix()),
        f"def sourceArtifactBytes : Nat := {EXPECTED_BYTES}",
        "def sourceArtifactSha512Hex : String := " + json.dumps(EXPECTED_SHA512),
        "",
        f"def exactGeometryWords : List Nat := {lean_nat_list(components.geometry_words)}",
        f"def exactPoseidonParameterManifestDigest : List Nat := {lean_nat_list(tuple(components.parameter_digest))}",
        "",
    ]
    emit_chunked_list(out, "exactPublicMapVersionDomain", "ProgramDescriptor", components.public_descriptors, render_descriptor)
    emit_chunked_list(out, "exactNonlinearIdentities", "ProgramDescriptor", components.nonlinear_descriptors, render_descriptor)
    emit_chunked_list(out, "exactLinearCsrCompilerFamilies", "ProgramDescriptor", components.csr_family_descriptors, render_descriptor)
    emit_chunked_list(out, "exactHashScheduleAndCallRoles", "ProgramDescriptor", components.hash_descriptors, render_descriptor)
    emit_chunked_list(out, "exactBindingDescriptors", "ProgramDescriptor", components.binding_descriptors, render_descriptor)
    emit_chunked_list(out, "exactNonlinearExpressions", "FieldExpression", components.nonlinear_expressions, render_expression)
    out.append(f"def exactNonlinearRoots : List Nat := {lean_nat_list(components.nonlinear_roots)}")
    out.append("")
    emit_chunked_list(out, "exactCsrExpressions", "FieldExpression", components.csr_expressions, render_expression)
    emit_chunked_list(out, "exactCsrAttempts", "CsrExecutableAttempt", components.csr_attempts, render_attempt)
    out.extend(
        [
            "/-- Exact HGV8RP03 executable program consumed by the Rust source adapter. -/",
            "def hgv8rp03ProgramComponents : RelationProgramComponents :=",
            "  { geometryWords := exactGeometryWords",
            "    publicMapVersionDomain := exactPublicMapVersionDomain",
            "    poseidonParameterManifestDigest := exactPoseidonParameterManifestDigest",
            "    nonlinearIdentities := exactNonlinearIdentities",
            "    linearCsrCompilerFamilies := exactLinearCsrCompilerFamilies",
            "    hashScheduleAndCallRoles := exactHashScheduleAndCallRoles",
            "    bindingDescriptors := exactBindingDescriptors",
            "    nonlinearExecutable :=",
            "      { expressions := exactNonlinearExpressions, roots := exactNonlinearRoots }",
            "    csrExpressions := exactCsrExpressions",
            "    csrAttempts := exactCsrAttempts }",
            "",
            "/-- Canonical byte transcript reconstructed from the materialized component value. -/",
            "def hgv8rp03ProgramTranscript : List Nat :=",
            "  canonicalProgramTranscript hgv8rp03ProgramComponents",
            "",
            "theorem exact_program_component_inventory :",
            "    exactGeometryWords.length = 37 ∧",
            "      exactPublicMapVersionDomain.length = 56 ∧",
            "      exactNonlinearIdentities.length = 830 ∧",
            "      exactLinearCsrCompilerFamilies.length = 86 ∧",
            "      exactHashScheduleAndCallRoles.length = 125 ∧",
            "      exactBindingDescriptors.length = 8 ∧",
            "      exactNonlinearExpressions.length = 8271 ∧",
            "      exactNonlinearRoots.length = 830 ∧",
            "      exactCsrExpressions.length = 565 ∧",
            "      exactCsrAttempts.length = 20569 := by",
            "  decide",
            "",
            "theorem exact_program_fixed_identity_fields :",
            "    hgv8rp03ProgramComponents.geometryWords = requiredGeometryWords ∧",
            "      hgv8rp03ProgramComponents.poseidonParameterManifestDigest =",
            "        poseidonParameterSetSha256 ∧",
            "      hgv8rp03ProgramComponents.bindingDescriptors =",
            "        Hegemon.Transaction.Poseidon2V8RelationProgram.exactBindingDescriptors := by",
            "  decide",
            "",
            "/-- Materializing a program value is not production authorization. -/",
            "def productionAuthorized : Bool := false",
            "",
            "/- Canonicality must be proved for this value; a materialization status flag is not evidence. -/",
            "",
            "theorem exact_program_has_no_production_authority :",
            "    productionAuthorized = false := by",
            "  rfl",
            "",
            "end HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated",
            "",
        ]
    )
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    args = parser.parse_args()
    input_path = args.input.resolve()
    try:
        data = input_path.read_bytes()
        if args.self_test:
            run_self_test(data)
            print("HGV8RP03 Lean component generator self-test passed")
            return 0
        components = parse_components(data)
        sys.stdout.write(emit_lean(components, input_path))
    except (DecodeError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
