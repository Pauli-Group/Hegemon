#!/usr/bin/env python3
"""Dependency-free semantic source gate for the inactive V7 lifecycle seam."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


CIPHERTEXT_HASH_DOMAIN = (
    b"hegemon.smallwood.v7-zeta.ciphertext-hash.blake2b-448.v1"
)
PROSPECTIVE_ACTION_ID_DOMAIN = (
    b"hegemon.smallwood.v7-zeta.prospective-consensus-action-id.blake2b-448.v1"
)
PRIVATE_AUTH_MODES = (
    "SingleKey",
    "AccumulatorInit",
    "ApprovalStep",
    "ValueLockCreation",
    "FinalThresholdSpend",
)


@dataclass(frozen=True)
class Finding:
    path: str
    message: str


@dataclass(frozen=True)
class ReferenceLifecycle:
    mask: int
    auth_mode: str
    proof: bytes
    ciphertexts: tuple[bytes, bytes]
    statement: bytes
    envelope: bytes
    canonical_public_args: bytes
    prospective_action_id: bytes
    record: bytes
    durable_key: bytes
    rpc_base64: str


def blake2b448_ciphertext_hash(slot: int, ciphertext: bytes) -> bytes:
    """Independent RFC 7693 reference for the frozen ciphertext frame."""
    if slot not in (0, 1):
        raise ValueError("ciphertext slot must be 0 or 1")
    if not ciphertext or len(ciphertext) > 2_147:
        raise ValueError("active ciphertext length is outside the frozen bound")
    frame = b"".join(
        (
            struct.pack(">H", len(CIPHERTEXT_HASH_DOMAIN)),
            CIPHERTEXT_HASH_DOMAIN,
            struct.pack(">HHHH", 7, 6, 1, 9),
            struct.pack(">BBH", 3, 4, 3),
            struct.pack(">BI", slot, len(ciphertext)),
            ciphertext,
        )
    )
    return hashlib.blake2b(frame, digest_size=56).digest()


def blake2b448_prospective_action_id(canonical_public_args: bytes) -> bytes:
    """Independent RFC 7693 reference for the prospective 56-byte action id."""
    frame = b"".join(
        (
            struct.pack(">H", len(PROSPECTIVE_ACTION_ID_DOMAIN)),
            PROSPECTIVE_ACTION_ID_DOMAIN,
            struct.pack(">Q", len(canonical_public_args)),
            canonical_public_args,
        )
    )
    return hashlib.blake2b(frame, digest_size=56).digest()


def scale_compact_length(length: int) -> bytes:
    """Canonical SCALE compact encoding for the bounded V7 vector lengths."""
    if not 0 <= length < (1 << 30):
        raise ValueError("reference length is outside the supported SCALE range")
    if length < (1 << 6):
        return bytes((length << 2,))
    if length < (1 << 14):
        return struct.pack("<H", (length << 2) | 1)
    return struct.pack("<I", (length << 2) | 2)


def _reference_statement(mask: int, ciphertexts: tuple[bytes, bytes]) -> bytes:
    if not 0 <= mask < 16:
        raise ValueError("mask must cover exactly four activity bits")
    input_flags = (bool(mask & 1), bool(mask & 2))
    output_flags = (bool(mask & 4), bool(mask & 8))
    chunks = [b"HGF7ST01", struct.pack(">H", 1), bytes((*input_flags, *output_flags))]
    chunks.append(bytes((1,)) * 56)
    for slot, enabled in enumerate(input_flags):
        chunks.append(bytes((2 + slot,)) * 56 if enabled else bytes(56))
    for slot, enabled in enumerate(output_flags):
        chunks.append(bytes((4 + slot,)) * 56 if enabled else bytes(56))
    for slot, enabled in enumerate(output_flags):
        chunks.append(
            blake2b448_ciphertext_hash(slot, ciphertexts[slot])
            if enabled
            else bytes(56)
        )
    chunks.append(
        b"".join(
            struct.pack(">I", len(ciphertexts[slot]) if output_flags[slot] else 0)
            for slot in range(2)
        )
    )
    chunks.append(b"".join(struct.pack(">Q", value) for value in (0, 1, 2, 3)))
    chunks.append(struct.pack(">Q", 7))
    chunks.append(bytes((0,)) + struct.pack(">Q", 0))
    chunks.append(
        bytes((0,))
        + struct.pack(">Q", 0)
        + struct.pack(">I", 0)
        + bytes((0,))
        + struct.pack(">Q", 0)
        + bytes(56 * 3)
    )
    chunks.append(bytes((5,)) * 56)
    chunks.append(
        struct.pack(">HHHHI", 7, 6, 1, 9, 41)
        + bytes((3, 4))
        + struct.pack(">H", 3)
        + bytes((11,)) * 56
        + bytes((12,)) * 56
        + bytes((13,)) * 56
    )
    statement = b"".join(chunks)
    if len(statement) != 893:
        raise AssertionError(f"reference statement width drifted to {len(statement)}")
    return statement


def reference_lifecycle_case(mask: int, auth_mode: str) -> ReferenceLifecycle:
    """Build the dependency-free 2x2/multimode transport reference case."""
    try:
        auth_tag = PRIVATE_AUTH_MODES.index(auth_mode)
    except ValueError as error:
        raise ValueError("unknown private authorization mode") from error
    ciphertexts = (
        bytes((0x40, mask, 0)) if mask & 4 else b"",
        bytes((0x80, mask, 1, 0xFF)) if mask & 8 else b"",
    )
    statement = _reference_statement(mask, ciphertexts)
    proof = bytes((0xA7, auth_tag, mask)) + auth_mode.encode("ascii")
    envelope = b"".join(
        (
            b"SWV7LC01",
            struct.pack(">HHHHHBBHII", 1, 7, 6, 1, 9, 3, 4, 3, 893, len(proof)),
            statement,
            proof,
        )
    )
    canonical_public_args = b"".join(
        (
            scale_compact_length(len(envelope)),
            envelope,
            scale_compact_length(len(ciphertexts[0])),
            ciphertexts[0],
            scale_compact_length(len(ciphertexts[1])),
            ciphertexts[1],
        )
    )
    prospective_action_id = blake2b448_prospective_action_id(canonical_public_args)
    record = (
        struct.pack("<H", 1)
        + prospective_action_id
        + scale_compact_length(len(canonical_public_args))
        + canonical_public_args
    )
    return ReferenceLifecycle(
        mask=mask,
        auth_mode=auth_mode,
        proof=proof,
        ciphertexts=ciphertexts,
        statement=statement,
        envelope=envelope,
        canonical_public_args=canonical_public_args,
        prospective_action_id=prospective_action_id,
        record=record,
        durable_key=b"pending_smallwood_v7_inactive_v1/" + prospective_action_id,
        rpc_base64=base64.b64encode(canonical_public_args).decode("ascii"),
    )


def protocol_action_id_kat() -> bytes:
    ciphertexts = (bytes((1, 2, 3)), b"")
    statement = _reference_statement(0b0101, ciphertexts)
    proof = bytes((9, 8, 7, 6))
    envelope = b"".join(
        (
            b"SWV7LC01",
            struct.pack(">HHHHHBBHII", 1, 7, 6, 1, 9, 3, 4, 3, 893, len(proof)),
            statement,
            proof,
        )
    )
    action = (
        scale_compact_length(len(envelope))
        + envelope
        + scale_compact_length(3)
        + ciphertexts[0]
        + scale_compact_length(0)
    )
    return blake2b448_prospective_action_id(action)


@lru_cache(maxsize=64)
def rust_code_mask(source: str) -> str:
    """Blank Rust comments and literals while preserving offsets and newlines."""
    output = list(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            for cursor in range(index, end):
                output[cursor] = " "
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            for position in range(index, cursor):
                if source[position] != "\n":
                    output[position] = " "
            index = cursor
            continue
        raw = re.match(r'(?:br|r)(?P<marks>#{0,16})"', source[index:])
        if raw is not None:
            terminator = '"' + raw.group("marks")
            cursor = source.find(terminator, index + raw.end())
            cursor = len(source) if cursor < 0 else cursor + len(terminator)
            for position in range(index, cursor):
                if source[position] != "\n":
                    output[position] = " "
            index = cursor
            continue
        quote_index = index + 1 if source.startswith('b"', index) else index
        if quote_index < len(source) and source[quote_index] == '"':
            cursor = quote_index + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                cursor += 1
                if source[cursor - 1] == '"':
                    break
            for position in range(index, min(cursor, len(source))):
                if source[position] != "\n":
                    output[position] = " "
            index = cursor
            continue
        char_literal = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
        if char_literal is not None:
            cursor = index + char_literal.end()
            for position in range(index, cursor):
                output[position] = " "
            index = cursor
            continue
        index += 1
    return "".join(output)


def item_body(source: str, kind: str, name: str) -> str:
    masked = rust_code_mask(source)
    match = re.search(rf"\b{re.escape(kind)}\s+{re.escape(name)}\b", masked)
    if match is None:
        raise ValueError(f"missing {kind} {name}")
    opening = masked.find("{", match.end())
    if opening < 0:
        raise ValueError(f"missing body for {kind} {name}")
    depth = 0
    for index in range(opening, len(masked)):
        byte = masked[index]
        if byte == "{":
            depth += 1
        elif byte == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise ValueError(f"unterminated body for {kind} {name}")


def function_body(source: str, name: str) -> str:
    return item_body(source, "fn", name)


def struct_body(source: str, name: str) -> str:
    return item_body(source, "struct", name)


def compact_code(source: str) -> str:
    return re.sub(r"\s+", "", rust_code_mask(source))


def line_of(source: str, needle: str) -> int:
    offset = source.find(needle)
    return 0 if offset < 0 else source.count("\n", 0, offset) + 1


def require(
    findings: list[Finding], path: str, source: str, needle: str, message: str
) -> None:
    if needle not in source:
        findings.append(Finding(path, message))


def forbid(
    findings: list[Finding], path: str, source: str, needle: str, message: str
) -> None:
    if needle in source:
        findings.append(Finding(path, message))


def require_in_order(
    findings: list[Finding], path: str, source: str, needles: tuple[str, ...], message: str
) -> None:
    cursor = 0
    for needle in needles:
        offset = source.find(needle, cursor)
        if offset < 0:
            findings.append(Finding(path, f"{message}: missing/out-of-order {needle}"))
            return
        cursor = offset + len(needle)


def audit(root: Path) -> tuple[list[Finding], list[str]]:
    paths = {
        "protocol": "protocol/shielded-pool/src/inactive_smallwood_v7.rs",
        "pool_lib": "protocol/shielded-pool/src/lib.rs",
        "pool_types": "protocol/shielded-pool/src/types.rs",
        "family": "protocol/shielded-pool/src/family.rs",
        "versioning": "protocol/versioning/src/lib.rs",
        "manifest": "protocol/kernel/src/manifest.rs",
        "wallet": "wallet/src/inactive_smallwood_v7.rs",
        "wallet_lib": "wallet/src/lib.rs",
        "wallet_rpc": "wallet/src/rpc.rs",
        "prover": "wallet/src/prover.rs",
        "builder": "wallet/src/shielded_tx.rs",
        "node": "node/src/native/inactive_smallwood_v7.rs",
        "node_mod": "node/src/native/mod.rs",
        "admission": "node/src/native/admission.rs",
        "service": "node/src/native/service.rs",
    }
    sources: dict[str, str] = {}
    findings: list[Finding] = []
    anchors: list[str] = []
    for key, relative in paths.items():
        path = root / relative
        try:
            sources[key] = path.read_text(encoding="utf-8")
        except OSError as error:
            findings.append(Finding(relative, f"cannot read required source: {error}"))
            sources[key] = ""

    protocol = sources["protocol"]
    protocol_compact = compact_code(protocol)
    exact_identity = {
        "INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION: u16 = 7;": "fresh circuit 7",
        "INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA: u16 = 6;": "fresh suite Zeta/6",
        "INACTIVE_SMALLWOOD_V7_FAMILY_ID: u16 = 1;": "shielded family 1",
        "INACTIVE_SMALLWOOD_V7_ACTION_ID: u16 = 9;": "fresh action 9",
        "INACTIVE_SMALLWOOD_V7_BACKEND_ID: u8 = 3;": "fresh backend 3",
        "INACTIVE_SMALLWOOD_V7_PROOF_PROFILE: u8 = 4;": "fresh profile 4",
        "INACTIVE_SMALLWOOD_V7_DOMAIN_SET: u16 = 3;": "fresh domain set 3",
        'INACTIVE_SMALLWOOD_V7_STATEMENT_MAGIC: [u8; 8] = *b"HGF7ST01";': "fresh statement magic",
        'INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC: [u8; 8] = *b"SWV7LC01";': "fresh envelope magic",
        "INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES: usize = 893;": "exact statement width",
        "INACTIVE_SMALLWOOD_V7_DIGEST_BYTES: usize = 56;": "exact digest width",
        "INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES: usize = 2 * 1024 * 1024;": "diagnostic transport budget",
        "INACTIVE_SMALLWOOD_V7_PRODUCTION_ENABLED: bool = false;": "protocol production gate",
        "INACTIVE_SMALLWOOD_V7_ADMISSION_ENABLED: bool = false;": "protocol admission gate",
        "INACTIVE_SMALLWOOD_V7_LIVE_STABLECOIN_REFINEMENT_AVAILABLE: bool = false;": "live stablecoin refinement gate",
        "INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_ENABLED: bool = false;": "prospective action-id gate",
        "INACTIVE_SMALLWOOD_V7_LIVE_ACTION_ID48_REFINEMENT_AVAILABLE: bool = false;": "live action-id refinement gate",
    }
    for needle, label in exact_identity.items():
        require(findings, paths["protocol"], protocol, needle, f"missing {label}")

    derived_bound = (
        "pubconstINACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES:usize="
        "INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES-"
        "INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES-"
        "INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES-"
        "(2*INACTIVE_SMALLWOOD_V7_MAX_CIPHERTEXT_BYTES)-"
        "INACTIVE_SMALLWOOD_V7_SCALE_AND_STAGE_HEADROOM_BYTES;"
    )
    if derived_bound not in protocol_compact:
        findings.append(Finding(paths["protocol"], "diagnostic proof bound is not exactly derived"))
    require(
        findings,
        paths["protocol"],
        protocol_compact,
        "pubconstINACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES:usize=INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES;",
        "public-args ceiling no longer equals the diagnostic 2 MiB bound",
    )
    if 2_091_807 + 30 + 893 != 2_092_730 or 2_097_152 - 2_097_032 != 120:
        findings.append(Finding(paths["protocol"], "checker transport arithmetic invariant failed"))

    expected_offsets = {
        "INACTIVE_SMALLWOOD_V7_OFFSET_ANCHOR: usize = 14;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_NULLIFIERS: usize = 70;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_COMMITMENTS: usize = 182;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_CIPHERTEXT_HASHES: usize = 294;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_ACTIVATION: usize = 709;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_NETWORK: usize = 717;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_BACKEND: usize = 721;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_PROFILE: usize = 722;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_DOMAIN_SET: usize = 723;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_CHAIN_ID: usize = 725;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_GENESIS_ID: usize = 781;",
        "INACTIVE_SMALLWOOD_V7_OFFSET_RULES_HASH: usize = 837;",
    }
    for needle in expected_offsets:
        require(findings, paths["protocol"], protocol, needle, f"missing layout anchor {needle}")

    for type_name in (
        "InactiveSmallwoodV7ProspectiveActionId56",
        "InactiveSmallwoodV7Anchor56",
        "InactiveSmallwoodV7Nullifier56",
        "InactiveSmallwoodV7Commitment56",
        "InactiveSmallwoodV7CiphertextHash56",
    ):
        require(
            findings,
            paths["protocol"],
            protocol,
            f"fixed_56_type!({type_name});",
            f"missing {type_name}",
        )

    required_protocol_functions = (
        "encode_inactive_smallwood_v7_statement",
        "decode_inactive_smallwood_v7_statement",
        "validate_inactive_smallwood_v7_activation_context",
        "decode_inactive_smallwood_v7_statement_for_context",
        "project_inactive_smallwood_v7_statement",
        "inactive_smallwood_v7_ciphertext_hash",
        "decode_inactive_smallwood_v7_inline_args",
        "inactive_smallwood_v7_prospective_action_id",
        "inactive_smallwood_v7_reject_live_action_id48_alias",
    )
    protocol_bodies: dict[str, str] = {}
    for function in required_protocol_functions:
        try:
            protocol_bodies[function] = function_body(protocol, function)
            anchors.append(
                f"{paths['protocol']}:{line_of(protocol, f'fn {function}')} {function}"
            )
        except ValueError as error:
            findings.append(Finding(paths["protocol"], str(error)))

    statement_decode = compact_code(
        protocol_bodies.get("decode_inactive_smallwood_v7_statement", "")
    )
    for needle in (
        "ifbytes.len()!=INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES",
        "validate_statement(&statement)?;",
    ):
        require(
            findings,
            paths["protocol"],
            statement_decode,
            needle,
            f"statement exact decode omits {needle}",
        )
    inline_decode = compact_code(
        protocol_bodies.get("decode_inactive_smallwood_v7_inline_args", "")
    )
    for needle in (
        "ifbytes.len()>INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES",
        "InactiveSmallwoodV7InlineArgs::decode(&mutcursor)",
        "if!cursor.is_empty(){returnErr(InactiveSmallwoodV7CodecError::TrailingBytes);}",
        "action.validate()?;",
        "ifaction.encode()!=bytes{returnErr(InactiveSmallwoodV7CodecError::NonCanonicalAction);}",
    ):
        require(
            findings,
            paths["protocol"],
            inline_decode,
            needle,
            f"SCALE action exact decode omits {needle}",
        )

    ciphertext_body = protocol_bodies.get("inactive_smallwood_v7_ciphertext_hash", "")
    for needle in (
        "INACTIVE_SMALLWOOD_V7_CIPHERTEXT_HASH_DOMAIN",
        "INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION",
        "INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA",
        "INACTIVE_SMALLWOOD_V7_FAMILY_ID",
        "INACTIVE_SMALLWOOD_V7_ACTION_ID",
        "INACTIVE_SMALLWOOD_V7_BACKEND_ID",
        "INACTIVE_SMALLWOOD_V7_PROOF_PROFILE",
        "INACTIVE_SMALLWOOD_V7_DOMAIN_SET",
        "slot as u8",
        "ciphertext_len.to_be_bytes()",
        "hasher.update(ciphertext)",
    ):
        require(findings, paths["protocol"], ciphertext_body, needle, f"ciphertext hash frame omits {needle}")
    try:
        validate_action = function_body(protocol, "validate")
    except ValueError as error:
        findings.append(Finding(paths["protocol"], str(error)))
        validate_action = ""
    validate_action_compact = compact_code(validate_action)
    for needle in (
        "statement.ciphertext_hashes[slot]!=inactive_smallwood_v7_ciphertext_hash(slot,&self.ciphertexts[slot])?",
        "CiphertextHashMismatch(slot)",
        "declaredasusize==observed",
        "declared==0&&observed==0",
    ):
        require(
            findings,
            paths["protocol"],
            validate_action_compact,
            needle,
            f"inline ciphertext validation omits {needle}",
        )

    context_body = protocol_bodies.get("validate_inactive_smallwood_v7_activation_context", "")
    for field in ("network_id", "chain_id", "genesis_id", "rules_hash"):
        require(
            findings,
            paths["protocol"],
            compact_code(context_body),
            f"statement.activation.{field}!=expected.{field}",
            f"activation context does not compare exact {field}",
        )

    action_id_body = protocol_bodies.get("inactive_smallwood_v7_prospective_action_id", "")
    for needle in (
        "decode_inactive_smallwood_v7_inline_args(canonical_public_args)?",
        "INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_DOMAIN",
        "(canonical_public_args.len() as u64).to_be_bytes()",
        "hasher.update(canonical_public_args)",
    ):
        require(findings, paths["protocol"], action_id_body, needle, f"prospective action-id frame omits {needle}")

    ciphertext_kats = (
        (
            blake2b448_ciphertext_hash(0, bytes((1, 2, 3))).hex(),
            "ab43a16e1a4065c19ea17b28c3d11dcf9490d3233d42f6dd84e0e1df3d9ebbc733cced56ef46acbe09cd0bdadd1883048164fd34e89d93fd",
        ),
        (
            blake2b448_ciphertext_hash(1, bytes((4, 5, 6, 7))).hex(),
            "05d199e09eb96fa9a7d0faa485bd3d8baabaf762b733e1f77718b223294cf81c6ec0fcb63d155226205f5511a3595c0ec310cb6838a938b2",
        ),
    )
    for computed, expected in ciphertext_kats:
        if computed != expected:
            findings.append(Finding(paths["protocol"], "checker ciphertext KAT drifted"))
        require(findings, paths["protocol"], protocol, expected, "missing ciphertext RFC7693 KAT")
    expected_action_kat = (
        "89f518fd94c52815f6f8a7504718bdc3ee27c77b1361ebbedae2819d2077d70c"
        "7c00270a33d8409ef25a88247ee24c8d889023944fe66017"
    )
    if protocol_action_id_kat().hex() != expected_action_kat:
        findings.append(Finding(paths["protocol"], "checker prospective action-id KAT drifted"))
    require(findings, paths["protocol"], protocol, expected_action_kat, "missing prospective action-id RFC7693/SCALE KAT")

    reject_alias_body = protocol_bodies.get("inactive_smallwood_v7_reject_live_action_id48_alias", "")
    if compact_code(reject_alias_body) != "Err(InactiveSmallwoodV7CodecError::LiveActionId48AliasingForbidden)":
        findings.append(Finding(paths["protocol"], "live ActionId48 boundary is not unconditional rejection"))
    protocol_code = rust_code_mask(protocol)
    for pattern in (
        r"impl\s+(?:core::convert::)?(?:From|TryFrom)\s*<[^>]*(?:ActionId48|\[\s*u8\s*;\s*48\s*\])[^>]*>\s+for\s+InactiveSmallwoodV7ProspectiveActionId56",
        r"impl\s+(?:core::convert::)?(?:From|TryFrom)\s*<InactiveSmallwoodV7ProspectiveActionId56>\s+for\s+[^\{]*(?:ActionId48|\[\s*u8\s*;\s*48\s*\])",
        r"as_bytes\(\)\s*\[\s*\.\.\s*48\s*\]",
        r"truncate\s*\(\s*48\s*\)",
    ):
        if re.search(pattern, protocol_code, re.DOTALL):
            findings.append(Finding(paths["protocol"], "forbidden 56-to-48 action-id adapter present"))
    for forbidden in (
        "InactiveSmallwoodV7LifecycleId56",
        "inactive_smallwood_v7_lifecycle_id",
        "INACTIVE_SMALLWOOD_V7_MAX_PROOF_BYTES",
    ):
        forbid(findings, paths["protocol"], protocol, forbidden, f"forbidden stale/unsafe symbol {forbidden}")

    require(findings, paths["protocol"], protocol, "LiveStablecoinRefinementUnavailable", "enabled stablecoin statements are not fail-closed")
    require(findings, paths["protocol"], protocol, "Live stablecoin authorities are 48-byte values", "prospective stablecoin boundary is undocumented")
    try:
        stablecoin_body = struct_body(sources["pool_types"], "StablecoinPolicyBinding")
        for field in ("policy_hash", "oracle_commitment", "attestation_commitment"):
            require(findings, paths["pool_types"], stablecoin_body, f"pub {field}: [u8; 48]", f"live stablecoin width drifted for {field}")
    except ValueError as error:
        findings.append(Finding(paths["pool_types"], str(error)))

    try:
        inline_body = struct_body(protocol, "InactiveSmallwoodV7InlineArgs")
        inline_fields = re.findall(r"\bpub\s+(\w+)\s*:", rust_code_mask(inline_body))
        if inline_fields != ["envelope", "ciphertexts"]:
            findings.append(Finding(paths["protocol"], f"inline validity surface drifted: {inline_fields}"))
    except ValueError as error:
        findings.append(Finding(paths["protocol"], str(error)))

    require(findings, paths["pool_lib"], sources["pool_lib"], "pub mod inactive_smallwood_v7;", "protocol module is not exported")
    require(findings, paths["wallet_lib"], sources["wallet_lib"], "pub mod inactive_smallwood_v7;", "wallet module is not exported")
    require(findings, paths["node_mod"], sources["node_mod"], "mod inactive_smallwood_v7;", "node lifecycle module is not compiled")

    for key in ("family", "versioning", "manifest", "admission"):
        for forbidden in ("INACTIVE_SMALLWOOD_V7", "HGF7ST01", "SWV7LC01"):
            forbid(findings, paths[key], sources[key], forbidden, f"inactive identity leaked into active {key} source")

    family_code = rust_code_mask(sources["family"])
    if re.search(r"pub\s+const\s+ACTION_[A-Z0-9_]+\s*:[^=;]+\=\s*9(?:u16)?\s*;", family_code):
        findings.append(Finding(paths["family"], "active family reserves/adopts action 9 outside the inactive owner"))
    try:
        manifest_body = function_body(sources["manifest"], "kernel_manifest")
        supported = re.search(r"supported_actions\s*:\s*vec!\s*\[(?P<body>.*?)\]", rust_code_mask(manifest_body), re.DOTALL)
        if supported is None:
            findings.append(Finding(paths["manifest"], "cannot resolve shielded supported_actions"))
        elif re.search(r"(?:\b9(?:u16)?\b|SMALLWOOD_V7|ACTION_[A-Z0-9_]*V7)", supported.group("body")):
            findings.append(Finding(paths["manifest"], "kernel manifest admits action 9/V7"))
    except ValueError as error:
        findings.append(Finding(paths["manifest"], str(error)))
    try:
        protocol_manifest_body = function_body(sources["manifest"], "protocol_manifest")
        require(findings, paths["manifest"], compact_code(protocol_manifest_body), "letversion_bindings=vec![DEFAULT_VERSION_BINDING];", "protocol manifest no longer has the one authorized default binding")
    except ValueError as error:
        findings.append(Finding(paths["manifest"], str(error)))
    try:
        backend_body = function_body(sources["versioning"], "tx_proof_backend_for_version")
        if re.search(r"\(\s*(?:7(?:u16)?|CIRCUIT_V7)\s*,\s*(?:6(?:u16)?|CRYPTO_SUITE_ZETA)\s*\)", rust_code_mask(backend_body)):
            findings.append(Finding(paths["versioning"], "version/backend dispatch admits V7/Zeta"))
    except ValueError as error:
        findings.append(Finding(paths["versioning"], str(error)))

    wallet_rpc = sources["wallet_rpc"]
    for needle in (
        "pub nullifiers: Vec<[u8; 48]>",
        "pub commitments: Vec<[u8; 48]>",
        "pub anchor: [u8; 48]",
    ):
        require(findings, paths["wallet_rpc"], wallet_rpc, needle, f"active wallet schema drifted: {needle}")
    family = sources["family"]
    for needle in (
        "pub commitments: Vec<[u8; 48]>",
        "pub ciphertext_hashes: Vec<[u8; 48]>",
        "pub anchor: [u8; 48]",
    ):
        require(findings, paths["family"], family, needle, f"active action schema drifted: {needle}")
    try:
        pending_body = struct_body(sources["node_mod"], "PendingAction")
        for needle in (
            "tx_hash: ActionId48",
            "anchor: [u8; 48]",
            "nullifiers: Vec<[u8; 48]>",
            "commitments: Vec<[u8; 48]>",
            "ciphertext_hashes: Vec<[u8; 48]>",
        ):
            require(findings, paths["node_mod"], pending_body, needle, f"active pending schema drifted: {needle}")
    except ValueError as error:
        findings.append(Finding(paths["node_mod"], str(error)))

    route_pattern = re.compile(
        r"\(\s*(?:FAMILY_SHIELDED_POOL|1(?:u16)?)\s*,\s*(?:INACTIVE_SMALLWOOD_V7_ACTION_ID|9(?:u16)?)\s*\)"
    )
    for name in ("native_submit_action_route_supported", "native_action_request_route_payload_decodes_exactly"):
        try:
            body = function_body(sources["node_mod"], name)
            if route_pattern.search(rust_code_mask(body)):
                findings.append(Finding(paths["node_mod"], f"{name} activates literal/symbolic V7 route"))
        except ValueError as error:
            findings.append(Finding(paths["node_mod"], str(error)))

    wallet = sources["wallet"]
    require(findings, paths["wallet"], wallet, "prepare_inactive_smallwood_v7_rpc_request", "missing wallet preparation seam")
    require(findings, paths["wallet"], wallet, "new_nullifiers: Vec::new()", "wallet must not use legacy nullifier field")
    require(findings, paths["wallet"], wallet, "INACTIVE_SMALLWOOD_V7_WALLET_SUBMISSION_ENABLED: bool = false;", "wallet submission flag is not false")
    try:
        prepare_body = function_body(wallet, "prepare_inactive_smallwood_v7_rpc_request")
        require(findings, paths["wallet"], prepare_body, "decode_inactive_smallwood_v7_statement_for_context(&statement, expected_activation)", "wallet does not bind caller-supplied activation context")
        require(findings, paths["wallet"], prepare_body, "action.prospective_action_id()", "wallet does not derive prospective action id")
    except ValueError as error:
        findings.append(Finding(paths["wallet"], str(error)))
    forbid(findings, paths["wallet"], rust_code_mask(wallet), ".request(", "inactive wallet module submits RPC")
    forbid(findings, paths["wallet"], rust_code_mask(wallet), "submit_action", "inactive wallet module exposes a submit call")

    node = sources["node"]
    require(findings, paths["node"], node, "Base64NonCanonical", "RPC seam does not reject non-canonical base64")
    for flag in (
        "INACTIVE_SMALLWOOD_V7_NATIVE_PRODUCTION_ENABLED",
        "INACTIVE_SMALLWOOD_V7_RPC_ADMISSION_ENABLED",
        "INACTIVE_SMALLWOOD_V7_PEER_RELAY_ENABLED",
        "INACTIVE_SMALLWOOD_V7_DURABLE_MEMPOOL_ENABLED",
        "INACTIVE_SMALLWOOD_V7_MINING_ENABLED",
        "INACTIVE_SMALLWOOD_V7_BLOCK_IMPORT_ENABLED",
        "INACTIVE_SMALLWOOD_V7_SYNC_ENABLED",
        "INACTIVE_SMALLWOOD_V7_REORG_ENABLED",
        "INACTIVE_SMALLWOOD_V7_FRESH_NODE_ENABLED",
        "INACTIVE_SMALLWOOD_V7_RESTART_RESTORE_ENABLED",
    ):
        require(findings, paths["node"], node, f"{flag}: bool = false;", f"{flag} is not fail-closed")

    try:
        record_body = struct_body(node, "InactiveSmallwoodV7LifecycleRecord")
        record_fields = re.findall(r"\b(\w+)\s*:", rust_code_mask(record_body))
        if record_fields != ["schema", "prospective_action_id", "canonical_public_args"]:
            findings.append(Finding(paths["node"], f"lifecycle record authority surface drifted: {record_fields}"))
    except ValueError as error:
        findings.append(Finding(paths["node"], str(error)))
    for forbidden_pattern in (r"\b\w*sidecar\w*\b", r"\b\w*receipt\w*\b", r"\b\w*cache\w*\b"):
        if re.search(forbidden_pattern, rust_code_mask(protocol + wallet + node), re.IGNORECASE):
            findings.append(Finding(paths["node"], f"inactive validity surface contains {forbidden_pattern}"))

    stage_functions = (
        "decode_inactive_smallwood_v7_rpc_seam",
        "encode_inactive_smallwood_v7_peer_seam",
        "decode_inactive_smallwood_v7_peer_seam",
        "stage_inactive_smallwood_v7_mempool_seam",
        "encode_inactive_smallwood_v7_durable_row_seam",
        "decode_inactive_smallwood_v7_restart_seam",
        "restage_inactive_smallwood_v7_mempool_after_restart_seam",
        "select_inactive_smallwood_v7_for_mining_seam",
        "encode_inactive_smallwood_v7_block_seam",
        "decode_inactive_smallwood_v7_block_seam",
        "encode_inactive_smallwood_v7_sync_seam",
        "decode_inactive_smallwood_v7_sync_seam",
        "detach_inactive_smallwood_v7_reorg_seam",
        "reattach_inactive_smallwood_v7_reorg_seam",
        "encode_inactive_smallwood_v7_fresh_node_seam",
        "decode_inactive_smallwood_v7_fresh_node_seam",
        "validate_inactive_smallwood_v7_import_seam",
    )
    for function in stage_functions:
        try:
            function_body(node, function)
            anchors.append(f"{paths['node']}:{line_of(node, f'fn {function}')} {function}")
        except ValueError as error:
            findings.append(Finding(paths["node"], str(error)))

    try:
        record_decode = function_body(node, "decode_record_exact")
        record_decode_compact = compact_code(record_decode)
        for needle in (
            "ifbytes.len()>INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES+128",
            "InactiveSmallwoodV7LifecycleRecord::decode(&mutcursor)",
            "if!cursor.is_empty(){returnErr(InactiveSmallwoodV7LifecycleError::RecordTrailingBytes);}",
            "record.validate(expected_activation)?;",
            "ifrecord.encode()!=bytes{returnErr(InactiveSmallwoodV7LifecycleError::RecordNonCanonical);}",
        ):
            require(findings, paths["node"], record_decode_compact, needle, f"record exact decode omits {needle}")
        restart_body = function_body(node, "decode_inactive_smallwood_v7_restart_seam")
        require(findings, paths["node"], restart_body, "DurableKeyActionIdMismatch", "durable key is not action-id bound")
        require(findings, paths["node"], restart_body, "decode_record_exact(&row.value, expected_activation)?", "restart does not exact-decode with expected context")
        rpc_body = function_body(node, "decode_inactive_smallwood_v7_rpc_seam")
        rpc_compact = compact_code(rpc_body)
        for needle in (
            "STANDARD.decode(&request.public_args)",
            "ifbase64::engine::general_purpose::STANDARD.encode(&public_args)!=request.public_args{returnErr(InactiveSmallwoodV7LifecycleError::Base64NonCanonical);}",
            "InactiveSmallwoodV7LifecycleRecord::from_public_args(public_args,expected_activation,)?",
        ):
            require(findings, paths["node"], rpc_compact, needle, f"RPC canonical decode omits {needle}")
    except ValueError as error:
        findings.append(Finding(paths["node"], str(error)))

    mutators = (
        "admit_inactive_smallwood_v7_rpc_to_mempool",
        "relay_inactive_smallwood_v7_to_peers",
        "persist_inactive_smallwood_v7_mempool",
        "restore_inactive_smallwood_v7_mempool_after_restart",
        "import_inactive_smallwood_v7_block_to_state",
    )
    for function in mutators:
        try:
            if compact_code(function_body(node, function)) != "Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(,))":
                findings.append(Finding(paths["node"], f"{function} is not one unconditional inactive error"))
        except ValueError as error:
            findings.append(Finding(paths["node"], str(error)))
    try:
        verifier = function_body(node, "verify_inactive_smallwood_v7_for_production")
        if compact_code(verifier) != "Err(InactiveSmallwoodV7LifecycleError::VerifierUnavailable)":
            findings.append(Finding(paths["node"], "production verifier seam is not one unconditional unavailable error"))
    except ValueError as error:
        findings.append(Finding(paths["node"], str(error)))

    lifecycle_test_name = "all_16_masks_and_5_private_auth_modes_follow_one_restart_to_fresh_node_chain"
    try:
        lifecycle_test = function_body(node, lifecycle_test_name)
        require_in_order(
            findings,
            paths["node"],
            lifecycle_test,
            (
                "decode_inactive_smallwood_v7_rpc_seam",
                "encode_inactive_smallwood_v7_peer_seam",
                "decode_inactive_smallwood_v7_peer_seam",
                "stage_inactive_smallwood_v7_mempool_seam",
                "encode_inactive_smallwood_v7_durable_row_seam",
                "decode_inactive_smallwood_v7_restart_seam",
                "restage_inactive_smallwood_v7_mempool_after_restart_seam",
                "select_inactive_smallwood_v7_for_mining_seam",
                "encode_inactive_smallwood_v7_block_seam(&mined)",
                "decode_inactive_smallwood_v7_block_seam",
                "encode_inactive_smallwood_v7_sync_seam",
                "decode_inactive_smallwood_v7_sync_seam",
                "detach_inactive_smallwood_v7_reorg_seam",
                "reattach_inactive_smallwood_v7_reorg_seam",
                "encode_inactive_smallwood_v7_fresh_node_seam",
                "decode_inactive_smallwood_v7_fresh_node_seam",
                "validate_inactive_smallwood_v7_import_seam",
            ),
            "restart-to-fresh-node chain is incomplete",
        )
        require(findings, paths["node"], lifecycle_test, "for mask in 0u8..16", "lifecycle test omits masks")
        require(findings, paths["node"], lifecycle_test, "assert_eq!(cases, 16 * 5)", "lifecycle corpus does not prove 80 cases")
        if lifecycle_test.count("ensure_inactive_smallwood_v7_proof_bytes_unchanged") < 10:
            findings.append(Finding(paths["node"], "lifecycle test does not compare proof bytes at every stage"))
    except ValueError as error:
        findings.append(Finding(paths["node"], str(error)))
    auth_tags = re.findall(r'\("([A-Za-z]+)",\s*\d+\)', node)
    if tuple(auth_tags[:5]) != PRIVATE_AUTH_MODES:
        findings.append(Finding(paths["node"], f"private auth-mode corpus drifted: {auth_tags[:5]}"))
    for test_name in (
        "durable_restart_block_sync_and_fresh_node_reject_mutated_bytes",
        "every_decode_boundary_requires_exact_activation_context",
        "every_state_mutation_and_verifier_seam_remains_fail_closed",
    ):
        require(findings, paths["node"], node, f"fn {test_name}", f"missing test definition {test_name}")

    inactive_authority_functions = (*mutators, "verify_inactive_smallwood_v7_for_production")
    inactive_owner = (root / paths["node"]).resolve()
    for directory in (root / "protocol", root / "wallet", root / "node"):
        if not directory.exists():
            continue
        for candidate in directory.rglob("*.rs"):
            if candidate.resolve() == inactive_owner:
                continue
            try:
                candidate_raw = candidate.read_text(encoding="utf-8")
            except OSError:
                continue
            possible = tuple(
                function for function in inactive_authority_functions if function in candidate_raw
            )
            if not possible:
                continue
            candidate_source = rust_code_mask(candidate_raw)
            for function in possible:
                if re.search(rf"\b{re.escape(function)}\s*\(", candidate_source):
                    findings.append(
                        Finding(
                            str(candidate.relative_to(root)),
                            f"active call site reaches {function}",
                        )
                    )

    prover = sources["prover"]
    builder = sources["builder"]
    try:
        raw_prove = function_body(prover, "prove")
        require(findings, paths["prover"], raw_prove, "proof.stark_proof.clone()", "raw prover API semantics changed")
        artifact_prove = function_body(prover, "prove_submission_artifact")
        for needle in (
            "build_native_tx_leaf_artifact_bytes_with_auth(",
            "SmallwoodPrivateAuthWitness::default()",
            "decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes)",
            "verify_native_tx_leaf_artifact_bytes(",
            "proof_bytes: built.artifact_bytes",
        ):
            require(findings, paths["prover"], artifact_prove, needle, f"submission artifact helper omits {needle}")
        build_body = function_body(builder, "build")
        require(findings, paths["builder"], build_body, "prove_submission_artifact(&witness)", "exported builder uses raw proof bytes")
        if re.search(r"\.prove\s*\(\s*&witness\s*\)", rust_code_mask(build_body)):
            findings.append(Finding(paths["builder"], "exported builder regressed to raw prove"))
    except ValueError as error:
        findings.append(Finding(paths["builder"], str(error)))
    wallet_src = root / "wallet" / "src"
    if wallet_src.exists():
        for candidate in wallet_src.glob("*.rs"):
            if candidate.name == "shielded_tx.rs":
                continue
            try:
                caller_source = rust_code_mask(candidate.read_text(encoding="utf-8"))
            except OSError:
                continue
            if re.search(r"\bShieldedTxBuilder\s*::\s*new\s*\(", caller_source):
                findings.append(Finding(str(candidate.relative_to(root)), "dormant exported builder gained an unverified production caller"))

    require(findings, paths["service"], sources["service"], "No user-submitted V3 route is currently admitted", "peer prefilter comment still claims an active user route")
    anchors.append(f"{paths['wallet']}:{line_of(wallet, 'fn prepare_inactive_smallwood_v7_rpc_request')} wallet preparation")
    anchors.append(f"{paths['prover']}:{line_of(prover, 'fn prove_submission_artifact')} native-artifact builder")
    return findings, anchors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    findings, anchors = audit(args.root.resolve())
    if findings:
        for finding in findings:
            print(f"FAIL {finding.path}: {finding.message}", file=sys.stderr)
        return 1
    print("inactive SmallWood V7 lifecycle source gate: PASS")
    for anchor in anchors:
        print(f"  {anchor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
