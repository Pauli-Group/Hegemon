#!/usr/bin/env python3
"""Source-only conventional-hash wire profile for the HVZK-WHIR challenger.

This module is deliberately independent of Plonky3 and of every Hegemon Rust
crate.  It freezes a bounded research envelope, an injectively framed
SHAKE256-512 transcript/MMCS, and a fail-closed security ledger.  It does not
implement the CFW26 R1CS IOR, the constrained-code IOPP, or a production
verifier.  Consequently :func:`require_production_authority` always rejects
the checked profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent

SCHEMA = "hegemon.hvzk-whir-strict-wire-source-profile.v1"
PROFILE_STATUS = "source_only_fail_closed"
RECORDED_PLONKY3_PCS_PIN = "3c84c158c0939345a3becba60a387643935593d2"
LOCAL_PLONKY3_EVIDENCE_PIN = "5df89eeadae18d6935bb874f8a92808dcc200c9d"

DOMAIN_ROOT = b"hegemon.hvzk-whir.strict-wire.source-profile.v1"
HASH_FRAME_MAGIC = b"HGWHASH1"
WIRE_MAGIC = b"HGWHIR01"
STATEMENT_MAGIC = b"HGWHST01"
WIRE_VERSION = 1
STATEMENT_VERSION = 1
DOMAIN_SET_VERSION = 1
HASH_SUITE_ID = 1
DIGEST_BYTES = 64

MAX_PUBLIC_ARGS_BYTES = 65_536
MAX_STATEMENT_BYTES = 65_632
MAX_PROOF_BODY_BYTES = 16 * 1024 * 1024
MAX_SECTION_BYTES = 8 * 1024 * 1024
MAX_SECTIONS = 4_096
MAX_ENVELOPE_BYTES = 17 * 1024 * 1024
MAX_MMCS_LEAVES = 1 << 20
MAX_CHALLENGE_BYTES = 4_096
MAX_REJECTION_DRAWS = 16

HEADER_STRUCT = struct.Struct("<8sHHHH64sIHH64sIHHII")
STATEMENT_HEADER_STRUCT = struct.Struct("<8sHHIHHHH64sI")
SECTION_HEADER_STRUCT = struct.Struct("<HHI")
HEADER_BYTES = HEADER_STRUCT.size
STATEMENT_HEADER_BYTES = STATEMENT_HEADER_STRUCT.size
SECTION_HEADER_BYTES = SECTION_HEADER_STRUCT.size

GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001


HASH_ROLES: tuple[tuple[int, str], ...] = (
    (1, "profile.id"),
    (2, "source.manifest"),
    (3, "relation.manifest"),
    (4, "statement.id"),
    (5, "mmcs.leaf"),
    (6, "mmcs.node"),
    (7, "mmcs.root"),
    (8, "transcript.init"),
    (9, "transcript.absorb.section"),
    (10, "transcript.challenge"),
    (11, "transcript.query-index"),
    (12, "transcript.grinding"),
    (13, "transcript.retry-abort"),
    (14, "proof.id"),
)
HASH_ROLE_IDS = {name: role_id for role_id, name in HASH_ROLES}

SECTION_ROLES: tuple[tuple[int, str], ...] = (
    (0x0101, "ior.public-input-binding"),
    (0x0102, "ior.oracle-commitment"),
    (0x0103, "ior.round-message"),
    (0x0201, "pcs.initial-commitment"),
    (0x0202, "pcs.claimed-evaluations"),
    (0x0203, "pcs.sumcheck-mask-commitment"),
    (0x0204, "pcs.sumcheck-message"),
    (0x0205, "pcs.code-switch-commitment"),
    (0x0206, "pcs.code-switch-mask-commitment"),
    (0x0207, "pcs.out-of-domain-answers"),
    (0x0208, "pcs.grinding-witness"),
    (0x0209, "pcs.query-openings"),
    (0x020A, "pcs.mmcs-multiproof"),
    (0x020B, "pcs.masked-base-case"),
)
SECTION_ROLE_NAMES = dict(SECTION_ROLES)

CHALLENGE_ROLES: tuple[tuple[int, str], ...] = (
    (1, "ior.constraint-combination"),
    (2, "pcs.initial-combination"),
    (3, "pcs.sumcheck-fold"),
    (4, "pcs.code-switch"),
    (5, "pcs.out-of-domain-point"),
    (6, "pcs.query-index"),
    (7, "pcs.mask-coefficient"),
    (8, "pcs.grinding"),
    (9, "pcs.masked-base-case"),
)
CHALLENGE_ROLE_IDS = {name: role_id for role_id, name in CHALLENGE_ROLES}

REQUIRED_SECURITY_TERMS: tuple[tuple[str, str], ...] = (
    ("exact_relation_refinement", "advantage of accepting outside the exact Hegemon relation"),
    ("odd_field_r1cs_compiler", "Boolean/host-semantics to odd-field R1CS refinement loss"),
    ("r1cs_to_cic_ior", "CFW26 Section 11 R1CS-to-constrained-code IOR error"),
    ("constrained_code_iopp", "CFW26 Section 10 IOPP/RBR soundness error"),
    ("whir_pcs_binding", "PCS/MMCS binding error"),
    ("whir_proximity_and_list", "proximity, list-size, distance, and zero-evader errors"),
    ("complete_hvzk_simulation", "whole-view HVZK statistical/computational distance"),
    ("bcs_commitment_hiding", "salted commitment selective-opening/zero-knowledge term"),
    ("cms_qrom_fiat_shamir", "CMS modified-BCS QROM soundness loss"),
    ("shake256_ideal_to_concrete_qrom", "deployed SHAKE256-512 ideal-to-concrete QROM loss"),
    ("mmcs_hash_binding", "SHAKE256-512 MMCS collision/second-preimage term"),
    ("mmcs_selective_opening_hiding", "MMCS leaf hiding and selective-opening term"),
    ("challenge_sampling_abort", "bounded rejection-sampling bias/abort term"),
    ("grinding_retry_abort", "grinding, prover retry, verifier abort, and transcript-restart term"),
    ("rng_failure", "masking entropy/CSPRNG failure and multi-proof reuse term"),
    ("hash_role_union", "union across physical hash roles and calls"),
    ("proof_history_union", "union across proofs, actions, epochs, and adversarial history"),
    ("parser_and_verifier_refinement", "canonical parser, panic containment, and verifier refinement"),
    ("consensus_integration_refinement", "wallet/RPC/relay/storage/block/reorg/fresh-node refinement"),
    ("overall_total", "exact sum of every positive failure term"),
)


class ProfileError(ValueError):
    """A stable, fail-closed parser or profile error."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class ProductionAuthorizationError(RuntimeError):
    """Raised whenever this incomplete research profile is offered for production."""


@dataclass(frozen=True)
class StatementFrame:
    network_id: int
    action_kind: int
    action_version: int
    relation_digest: bytes
    public_args: bytes


@dataclass(frozen=True)
class ProofSection:
    role_id: int
    instance: int
    payload: bytes


@dataclass(frozen=True)
class ProofEnvelope:
    profile_digest: bytes
    statement: StatementFrame
    sections: tuple[ProofSection, ...]
    raw_statement: bytes
    raw_bytes: bytes


def _u16(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ProfileError("integer_range", name)
    return struct.pack("<H", value)


def _u32(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF:
        raise ProfileError("integer_range", name)
    return struct.pack("<I", value)


def _u64(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ProfileError("integer_range", name)
    return struct.pack("<Q", value)


def _bytes(value: bytes | bytearray | memoryview, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProfileError("invalid_type", name)
    return bytes(value)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the only JSON encoding admitted for profile hashing."""

    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "ascii"
    )


def shake_role(role: str, frames: Sequence[bytes], *, output_bytes: int = DIGEST_BYTES) -> bytes:
    """Apply SHAKE256 with injective, length-delimited role framing."""

    try:
        role_id = HASH_ROLE_IDS[role]
    except KeyError as exc:
        raise ProfileError("unknown_hash_role", role) from exc
    if not 1 <= output_bytes <= MAX_CHALLENGE_BYTES:
        raise ProfileError("hash_output_length", str(output_bytes))
    if len(frames) > 0xFFFF:
        raise ProfileError("too_many_hash_frames", str(len(frames)))
    preimage = bytearray(HASH_FRAME_MAGIC)
    preimage += _u16(len(DOMAIN_ROOT), "domain root length")
    preimage += DOMAIN_ROOT
    preimage += _u16(role_id, "hash role")
    preimage += _u16(len(frames), "hash frame count")
    for frame in frames:
        material = _bytes(frame, "hash frame")
        preimage += _u64(len(material), "hash frame length")
        preimage += material
    return hashlib.shake_256(preimage).digest(output_bytes)


def relation_manifest_digest(canonical_manifest: bytes) -> bytes:
    material = _bytes(canonical_manifest, "relation manifest")
    if not material:
        raise ProfileError("empty_relation_manifest")
    return shake_role("relation.manifest", (material,))


def source_manifest_digest(canonical_manifest: bytes) -> bytes:
    material = _bytes(canonical_manifest, "source manifest")
    if not material:
        raise ProfileError("empty_source_manifest")
    return shake_role("source.manifest", (material,))


def profile_core() -> dict[str, Any]:
    """Return the source profile whose canonical bytes define the profile id."""

    return {
        "schema": SCHEMA,
        "status": PROFILE_STATUS,
        "architecture": {
            "name": "CFW26 HVZK-WHIR challenger",
            "paper": "ePrint 2026/391",
            "plonky3_recorded_pcs_pin": RECORDED_PLONKY3_PCS_PIN,
            "plonky3_local_later_evidence_pin": LOCAL_PLONKY3_EVIDENCE_PIN,
            "recorded_pin_scope": "HidingWhirPcs implementation evidence only",
            "local_pin_scope": "later read-only PCS evidence; not the recorded pin and not an R1CS proof system",
            "cfw26_section11_specification_unambiguous": False,
            "cfw26_section11_author_erratum_found": False,
            "cfw26_section11_repair_selected": False,
            "r1cs_ior_implemented": False,
            "full_transaction_nizk_implemented": False,
            "selected_winner": False,
            "production_authorized": False,
        },
        "field_screen": {
            "relation_base_field": "Goldilocks",
            "modulus": str(GOLDILOCKS_MODULUS),
            "canonical_encoding": "8-byte little-endian integer strictly below modulus",
            "compiler_screen_only": True,
            "challenge_extension_field": None,
            "extension_polynomial": None,
            "pcs_parameter_profile": None,
            "production_selected": False,
        },
        "hash_profile": {
            "primitive": "FIPS 202 SHAKE256",
            "named_output": "SHAKE256-512",
            "digest_bytes": DIGEST_BYTES,
            "domain_root_ascii": DOMAIN_ROOT.decode("ascii"),
            "frame": "HGWHASH1 || u16le(domain_len) || domain || u16le(role_id) || u16le(frame_count) || each(u64le(length) || bytes)",
            "roles": [{"id": role_id, "name": name} for role_id, name in HASH_ROLES],
            "poseidon_authority": False,
            "concrete_qrom_bridge": None,
        },
        "wire": {
            "magic_ascii": WIRE_MAGIC.decode("ascii"),
            "wire_version": WIRE_VERSION,
            "statement_magic_ascii": STATEMENT_MAGIC.decode("ascii"),
            "statement_version": STATEMENT_VERSION,
            "domain_set_version": DOMAIN_SET_VERSION,
            "hash_suite_id": HASH_SUITE_ID,
            "endianness": "little",
            "header_bytes": HEADER_BYTES,
            "statement_header_bytes": STATEMENT_HEADER_BYTES,
            "section_header_bytes": SECTION_HEADER_BYTES,
            "section_roles": [{"id": role_id, "name": name} for role_id, name in SECTION_ROLES],
            "network_binding": "u32le duplicated in envelope and statement",
            "action_binding": "u16le action kind and u16le action version duplicated in envelope and statement",
            "relation_binding": "64-byte SHAKE256-512 relation-manifest digest duplicated in envelope and statement",
            "profile_binding": "64-byte profile digest in envelope and transcript initialization",
            "statement_binding": "complete canonical statement bytes absorbed before proof sections",
            "section_rule": "ordered records; per-role instance numbers start at zero and increase without gaps",
            "inner_plonky3_serde_is_consensus_wire": False,
            "exact_inner_message_serializer_implemented": False,
        },
        "limits": {
            "max_public_args_bytes": MAX_PUBLIC_ARGS_BYTES,
            "max_statement_bytes": MAX_STATEMENT_BYTES,
            "max_proof_body_bytes": MAX_PROOF_BODY_BYTES,
            "max_section_bytes": MAX_SECTION_BYTES,
            "max_sections": MAX_SECTIONS,
            "max_envelope_bytes": MAX_ENVELOPE_BYTES,
            "max_mmcs_leaves": MAX_MMCS_LEAVES,
            "max_challenge_bytes": MAX_CHALLENGE_BYTES,
            "max_rejection_draws": MAX_REJECTION_DRAWS,
            "proof_size_measurement_or_bound": None,
        },
        "challenge_roles": [{"id": role_id, "name": name} for role_id, name in CHALLENGE_ROLES],
        "byte_formula": {
            "statement_bytes": "92 + public_args_bytes",
            "proof_body_bytes": "sum_i(8 + section_payload_bytes_i)",
            "envelope_bytes": "168 + statement_bytes + proof_body_bytes",
            "measurement": None,
            "claim": "serializer accounting identity only; no proof bytes generated or estimated",
        },
    }


def profile_digest() -> bytes:
    return shake_role("profile.id", (canonical_json_bytes(profile_core()),))


def encode_statement(statement: StatementFrame) -> bytes:
    relation = _bytes(statement.relation_digest, "relation digest")
    public_args = _bytes(statement.public_args, "public arguments")
    if len(relation) != DIGEST_BYTES or relation == bytes(DIGEST_BYTES):
        raise ProfileError("invalid_relation_digest")
    if not public_args:
        raise ProfileError("empty_public_args")
    if len(public_args) > MAX_PUBLIC_ARGS_BYTES:
        raise ProfileError("public_args_too_large")
    header = STATEMENT_HEADER_STRUCT.pack(
        STATEMENT_MAGIC,
        STATEMENT_VERSION,
        STATEMENT_HEADER_BYTES,
        statement.network_id,
        statement.action_kind,
        statement.action_version,
        DOMAIN_SET_VERSION,
        HASH_SUITE_ID,
        relation,
        len(public_args),
    )
    encoded = header + public_args
    if len(encoded) > MAX_STATEMENT_BYTES:
        raise ProfileError("statement_too_large")
    return encoded


def decode_statement(data: bytes | bytearray | memoryview) -> StatementFrame:
    raw = _bytes(data, "statement")
    if len(raw) < STATEMENT_HEADER_BYTES:
        raise ProfileError("truncated_statement_header")
    if len(raw) > MAX_STATEMENT_BYTES:
        raise ProfileError("statement_too_large")
    (
        magic,
        version,
        header_bytes,
        network_id,
        action_kind,
        action_version,
        domain_version,
        hash_suite,
        relation,
        public_args_len,
    ) = STATEMENT_HEADER_STRUCT.unpack_from(raw)
    if magic != STATEMENT_MAGIC:
        raise ProfileError("bad_statement_magic")
    if version != STATEMENT_VERSION:
        raise ProfileError("bad_statement_version")
    if header_bytes != STATEMENT_HEADER_BYTES:
        raise ProfileError("bad_statement_header_length")
    if domain_version != DOMAIN_SET_VERSION:
        raise ProfileError("bad_statement_domain_version")
    if hash_suite != HASH_SUITE_ID:
        raise ProfileError("bad_statement_hash_suite")
    if relation == bytes(DIGEST_BYTES):
        raise ProfileError("invalid_relation_digest")
    if public_args_len == 0:
        raise ProfileError("empty_public_args")
    if public_args_len > MAX_PUBLIC_ARGS_BYTES:
        raise ProfileError("public_args_too_large")
    expected = STATEMENT_HEADER_BYTES + public_args_len
    if len(raw) < expected:
        raise ProfileError("truncated_public_args")
    if len(raw) > expected:
        raise ProfileError("statement_trailing_bytes")
    return StatementFrame(network_id, action_kind, action_version, relation, raw[STATEMENT_HEADER_BYTES:])


def _validate_sections(sections: Sequence[ProofSection]) -> tuple[ProofSection, ...]:
    if not 1 <= len(sections) <= MAX_SECTIONS:
        raise ProfileError("section_count_range")
    next_instance: dict[int, int] = {}
    normalized: list[ProofSection] = []
    total = 0
    for section in sections:
        if section.role_id not in SECTION_ROLE_NAMES:
            raise ProfileError("unknown_section_role", str(section.role_id))
        expected = next_instance.get(section.role_id, 0)
        if section.instance != expected:
            raise ProfileError("noncanonical_section_instance", f"expected {expected}")
        payload = _bytes(section.payload, "section payload")
        if not payload:
            raise ProfileError("empty_section_payload")
        if len(payload) > MAX_SECTION_BYTES:
            raise ProfileError("section_too_large")
        total += SECTION_HEADER_BYTES + len(payload)
        if total > MAX_PROOF_BODY_BYTES:
            raise ProfileError("proof_body_too_large")
        normalized.append(ProofSection(section.role_id, section.instance, payload))
        next_instance[section.role_id] = expected + 1
    return tuple(normalized)


def encode_envelope(statement: StatementFrame, sections: Sequence[ProofSection]) -> bytes:
    statement_bytes = encode_statement(statement)
    normalized = _validate_sections(sections)
    body = bytearray()
    for section in normalized:
        body += SECTION_HEADER_STRUCT.pack(section.role_id, section.instance, len(section.payload))
        body += section.payload
    total_len = HEADER_BYTES + len(statement_bytes) + len(body)
    if total_len > MAX_ENVELOPE_BYTES:
        raise ProfileError("envelope_too_large")
    header = HEADER_STRUCT.pack(
        WIRE_MAGIC,
        WIRE_VERSION,
        HEADER_BYTES,
        DOMAIN_SET_VERSION,
        HASH_SUITE_ID,
        profile_digest(),
        statement.network_id,
        statement.action_kind,
        statement.action_version,
        statement.relation_digest,
        len(statement_bytes),
        len(normalized),
        0,
        len(body),
        total_len,
    )
    return header + statement_bytes + body


def parse_envelope(data: bytes | bytearray | memoryview) -> ProofEnvelope:
    """Parse and exact-consume one research envelope without allocating from wire lengths."""

    raw = _bytes(data, "proof envelope")
    if len(raw) < HEADER_BYTES:
        raise ProfileError("truncated_header")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ProfileError("envelope_too_large")
    (
        magic,
        wire_version,
        header_bytes,
        domain_version,
        hash_suite,
        encoded_profile_digest,
        network_id,
        action_kind,
        action_version,
        relation_digest,
        statement_len,
        section_count,
        flags,
        body_len,
        total_len,
    ) = HEADER_STRUCT.unpack_from(raw)
    if magic != WIRE_MAGIC:
        raise ProfileError("bad_magic")
    if wire_version != WIRE_VERSION:
        raise ProfileError("bad_wire_version")
    if header_bytes != HEADER_BYTES:
        raise ProfileError("bad_header_length")
    if domain_version != DOMAIN_SET_VERSION:
        raise ProfileError("bad_domain_version")
    if hash_suite != HASH_SUITE_ID:
        raise ProfileError("bad_hash_suite")
    if encoded_profile_digest != profile_digest():
        raise ProfileError("profile_digest_mismatch")
    if relation_digest == bytes(DIGEST_BYTES):
        raise ProfileError("invalid_relation_digest")
    if flags != 0:
        raise ProfileError("nonzero_reserved_flags")
    if not STATEMENT_HEADER_BYTES < statement_len <= MAX_STATEMENT_BYTES:
        raise ProfileError("statement_length_range")
    if not 1 <= section_count <= MAX_SECTIONS:
        raise ProfileError("section_count_range")
    if body_len > MAX_PROOF_BODY_BYTES:
        raise ProfileError("proof_body_too_large")
    expected_total = HEADER_BYTES + statement_len + body_len
    if total_len != expected_total:
        raise ProfileError("declared_total_mismatch")
    if total_len > MAX_ENVELOPE_BYTES:
        raise ProfileError("envelope_too_large")
    if len(raw) < total_len:
        raise ProfileError("truncated_envelope")
    if len(raw) > total_len:
        raise ProfileError("trailing_bytes")

    statement_start = HEADER_BYTES
    statement_end = statement_start + statement_len
    statement_raw = raw[statement_start:statement_end]
    statement = decode_statement(statement_raw)
    if statement.network_id != network_id:
        raise ProfileError("network_binding_mismatch")
    if statement.action_kind != action_kind:
        raise ProfileError("action_kind_binding_mismatch")
    if statement.action_version != action_version:
        raise ProfileError("action_version_binding_mismatch")
    if statement.relation_digest != relation_digest:
        raise ProfileError("relation_binding_mismatch")

    cursor = statement_end
    body_end = cursor + body_len
    sections: list[ProofSection] = []
    next_instance: dict[int, int] = {}
    for _ in range(section_count):
        if body_end - cursor < SECTION_HEADER_BYTES:
            raise ProfileError("truncated_section_header")
        role_id, instance, payload_len = SECTION_HEADER_STRUCT.unpack_from(raw, cursor)
        cursor += SECTION_HEADER_BYTES
        if role_id not in SECTION_ROLE_NAMES:
            raise ProfileError("unknown_section_role", str(role_id))
        expected_instance = next_instance.get(role_id, 0)
        if instance != expected_instance:
            raise ProfileError("noncanonical_section_instance", f"expected {expected_instance}")
        if payload_len == 0:
            raise ProfileError("empty_section_payload")
        if payload_len > MAX_SECTION_BYTES:
            raise ProfileError("section_too_large")
        if body_end - cursor < payload_len:
            raise ProfileError("truncated_section_payload")
        payload = raw[cursor : cursor + payload_len]
        cursor += payload_len
        sections.append(ProofSection(role_id, instance, payload))
        next_instance[role_id] = expected_instance + 1
    if cursor < body_end:
        raise ProfileError("proof_body_trailing_bytes")
    if cursor > body_end:
        raise ProfileError("truncated_section_payload")
    parsed = ProofEnvelope(encoded_profile_digest, statement, tuple(sections), statement_raw, raw)
    if encode_envelope(parsed.statement, parsed.sections) != raw:
        raise ProfileError("noncanonical_reencoding")
    return parsed


def parse_envelope_safe(data: object) -> tuple[ProofEnvelope | None, str | None]:
    """Contain all ordinary parser failures behind one non-panicking result API."""

    try:
        return parse_envelope(data), None  # type: ignore[arg-type]
    except ProfileError as exc:
        return None, exc.code
    except Exception:
        # Unexpected implementation exceptions still fail closed.  The checker
        # treats reaching this branch as a defect, but callers never receive an
        # accepted object from it.
        return None, "internal_parser_error"


def statement_id(statement_bytes: bytes) -> bytes:
    statement = _bytes(statement_bytes, "statement")
    decode_statement(statement)
    return shake_role("statement.id", (statement,))


def transcript_digest(envelope: ProofEnvelope) -> bytes:
    """Replay the exact source-profile transcript over parsed section order."""

    state = shake_role(
        "transcript.init",
        (
            envelope.profile_digest,
            envelope.statement.relation_digest,
            _u32(envelope.statement.network_id, "network id"),
            _u16(envelope.statement.action_kind, "action kind"),
            _u16(envelope.statement.action_version, "action version"),
            envelope.raw_statement,
        ),
    )
    for step, section in enumerate(envelope.sections):
        state = shake_role(
            "transcript.absorb.section",
            (
                state,
                _u32(step, "transcript step"),
                _u16(section.role_id, "section role"),
                _u16(section.instance, "section instance"),
                section.payload,
            ),
        )
    return shake_role("proof.id", (state, statement_id(envelope.raw_statement)))


def challenge_bytes(
    transcript_state: bytes,
    challenge_role: str,
    ordinal: int,
    output_bytes: int = DIGEST_BYTES,
) -> bytes:
    """Derive bounded challenge bytes with explicit role, ordinal, and block counters."""

    state = _bytes(transcript_state, "transcript state")
    if len(state) != DIGEST_BYTES:
        raise ProfileError("transcript_state_length")
    try:
        role_id = CHALLENGE_ROLE_IDS[challenge_role]
    except KeyError as exc:
        raise ProfileError("unknown_challenge_role", challenge_role) from exc
    if not 1 <= output_bytes <= MAX_CHALLENGE_BYTES:
        raise ProfileError("challenge_output_length")
    output = bytearray()
    block = 0
    while len(output) < output_bytes:
        output += shake_role(
            "transcript.challenge",
            (
                state,
                _u16(role_id, "challenge role"),
                _u64(ordinal, "challenge ordinal"),
                _u32(output_bytes, "challenge output bytes"),
                _u32(block, "challenge block"),
            ),
        )
        block += 1
    return bytes(output[:output_bytes])


def sample_uniform_index(transcript_state: bytes, ordinal: int, upper: int) -> int:
    """Return the first unbiased 64-bit sample below ``upper``, or fail closed."""

    if not isinstance(upper, int) or not 1 <= upper <= 1 << 63:
        raise ProfileError("sample_upper_range")
    limit = ((1 << 64) // upper) * upper
    stream = challenge_bytes(
        transcript_state,
        "pcs.query-index",
        ordinal,
        MAX_REJECTION_DRAWS * 8,
    )
    for draw in range(MAX_REJECTION_DRAWS):
        candidate = int.from_bytes(stream[draw * 8 : draw * 8 + 8], "little")
        if candidate < limit:
            return candidate % upper
    raise ProfileError("challenge_rejection_cap")


def encode_goldilocks(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < GOLDILOCKS_MODULUS:
        raise ProfileError("noncanonical_goldilocks")
    return value.to_bytes(8, "little")


def decode_goldilocks(data: bytes | bytearray | memoryview) -> int:
    raw = _bytes(data, "Goldilocks element")
    if len(raw) != 8:
        raise ProfileError("goldilocks_length")
    value = int.from_bytes(raw, "little")
    if value >= GOLDILOCKS_MODULUS:
        raise ProfileError("noncanonical_goldilocks")
    return value


def mmcs_root(leaves: Iterable[bytes], *, tree_role: int, tree_instance: int = 0) -> bytes:
    """Commit a power-of-two, fixed-width leaf vector with SHAKE256-512."""

    material = [_bytes(leaf, "MMCS leaf") for leaf in leaves]
    if not material or len(material) > MAX_MMCS_LEAVES or len(material) & (len(material) - 1):
        raise ProfileError("mmcs_leaf_count")
    width = len(material[0])
    if width == 0 or width > MAX_SECTION_BYTES or any(len(leaf) != width for leaf in material):
        raise ProfileError("mmcs_leaf_width")
    tree = [
        shake_role(
            "mmcs.leaf",
            (
                _u16(tree_role, "tree role"),
                _u16(tree_instance, "tree instance"),
                _u64(index, "leaf index"),
                _u64(len(material), "leaf count"),
                _u32(width, "leaf width"),
                leaf,
            ),
        )
        for index, leaf in enumerate(material)
    ]
    level = 0
    while len(tree) > 1:
        tree = [
            shake_role(
                "mmcs.node",
                (
                    _u16(tree_role, "tree role"),
                    _u16(tree_instance, "tree instance"),
                    _u32(level, "tree level"),
                    _u64(index // 2, "node index"),
                    tree[index],
                    tree[index + 1],
                ),
            )
            for index in range(0, len(tree), 2)
        ]
        level += 1
    return shake_role(
        "mmcs.root",
        (
            _u16(tree_role, "tree role"),
            _u16(tree_instance, "tree instance"),
            _u64(len(material), "leaf count"),
            _u32(width, "leaf width"),
            tree[0],
        ),
    )


def fixture() -> tuple[bytes, ProofEnvelope]:
    """Return a deterministic parser/transcript fixture, never a valid proof."""

    relation = relation_manifest_digest(b'{"fixture":"not-a-production-relation","version":1}\n')
    statement = StatementFrame(
        network_id=0x4857_0001,
        action_kind=0x7001,
        action_version=1,
        relation_digest=relation,
        public_args=b"research-only-public-arguments",
    )
    sections = (
        ProofSection(0x0101, 0, b"unimplemented-r1cs-ior-binding"),
        ProofSection(0x0201, 0, bytes(range(64))),
        ProofSection(0x0204, 0, b"opaque-canonical-section-payload"),
        ProofSection(0x020B, 0, b"not-a-proof"),
    )
    encoded = encode_envelope(statement, sections)
    return encoded, parse_envelope(encoded)


def security_ledger() -> dict[str, Any]:
    return {
        "target": "overall_total < 2^-128",
        "strict_inequality": True,
        "adversary_qrom_query_bound": None,
        "honest_hash_calls_per_proof": None,
        "proofs_per_epoch": None,
        "terms": [
            {"id": term_id, "description": description, "exact_value": None, "authority": "missing"}
            for term_id, description in REQUIRED_SECURITY_TERMS
        ],
        "overall_total": None,
        "composed_pq_security_bits": None,
        "composed_strict_gt_128": False,
        "production_authorized": False,
    }


def production_blockers() -> list[str]:
    return [
        "no expected production network/action/version/domain identity",
        "no authoritative exact relation digest or accepted odd-field R1CS refinement",
        "CFW26 Construction 11.4 has unresolved coefficient-1/coefficient-2 and ill-typed inner linear-form state ambiguities",
        "CFW26 Section 11 R1CS-to-CIC IOR is absent",
        "CFW26 Section 10 full constrained-code IOPP is not integrated as a transaction proof",
        "Plonky3 evidence is HidingWhirPcs only; the recorded and local pins are distinct",
        "no exact canonical serializer for every inner Plonky3/IOR field",
        "no panic-free native verifier/refinement result",
        "no whole Hegemon observation-surface simulator and exact complete-ZK bound",
        "no exact PCS/IOP/Fiat-Shamir/SHAKE/QROM/grinding/retry/union total",
        "no retained same-relation proof artifact or measured proof bytes",
        "no wallet/RPC/relay/mempool/block/reorg/fresh-node integration",
        "no source-bound release identity or authorization manifest",
    ]


def require_production_authority() -> None:
    raise ProductionAuthorizationError("HVZK-WHIR source profile is not production-authorized: " + "; ".join(production_blockers()))


def profile_report() -> dict[str, Any]:
    encoded, parsed = fixture()
    mmcs = mmcs_root((b"leaf-000", b"leaf-001", b"leaf-002", b"leaf-003"), tree_role=0x0201)
    transcript = transcript_digest(parsed)
    return {
        "profile_core": profile_core(),
        "profile_digest_hex": profile_digest().hex(),
        "known_answer_tests": {
            "fixture_relation_digest_hex": parsed.statement.relation_digest.hex(),
            "fixture_statement_id_hex": statement_id(parsed.raw_statement).hex(),
            "fixture_transcript_digest_hex": transcript.hex(),
            "fixture_query_index_upper_1000003": sample_uniform_index(transcript, 0, 1_000_003),
            "four_leaf_mmcs_root_hex": mmcs.hex(),
            "fixture_envelope_sha512_hex": hashlib.sha512(encoded).hexdigest(),
        },
        "fixture_accounting": {
            "classification": "parser/transcript KAT only; not a proof and not a proof-size estimate",
            "header_bytes": HEADER_BYTES,
            "statement_bytes": len(parsed.raw_statement),
            "section_header_bytes": SECTION_HEADER_BYTES * len(parsed.sections),
            "section_payload_bytes": sum(len(section.payload) for section in parsed.sections),
            "envelope_bytes": len(encoded),
            "formula_holds": len(encoded)
            == HEADER_BYTES
            + len(parsed.raw_statement)
            + sum(SECTION_HEADER_BYTES + len(section.payload) for section in parsed.sections),
        },
        "security_ledger": security_ledger(),
        "production_blockers": production_blockers(),
        "proof_bytes": None,
        "winner": None,
        "production_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    if args.require_production:
        require_production_authority()
    print(json.dumps(profile_report(), sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
