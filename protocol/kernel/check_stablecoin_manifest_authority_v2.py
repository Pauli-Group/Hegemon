#!/usr/bin/env python3
"""Dependency-free source/KAT gate for the inactive all-W64 manifest V2 seam."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "protocol/kernel/src/stablecoin_manifest_authority_v2.rs"
LIB = ROOT / "protocol/kernel/src/lib.rs"
LIVE_MANIFEST = ROOT / "protocol/kernel/src/manifest.rs"
LEGACY_MODULE = ROOT / "protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"
SUCCESSOR_GATE = ROOT / "scripts/check_transaction_proof_successor_authorization.py"
SUCCESSOR_SELECTION = ROOT / "config/transaction-proof-successor-selection.json"
FROZEN_DIR = ROOT / ".agent/hardening/manifest-authority-closure"
FROZEN_COST = FROZEN_DIR / "cost_report.json"
FROZEN_LEDGER = FROZEN_DIR / "capability_ledger.json"
FROZEN_MUTATIONS = FROZEN_DIR / "mutation_corpus.json"

CAP = 16
DEPTH = 4
WIDTH = 64
ENTRY_BYTES = 215
SLOT_BYTES = 216
WITNESS_BYTES = 475
PUBLIC_BYTES = 72
PROFILE = 2
PAYLOAD_MAX = 4096

ROLE_FULL = 1
ROLE_LEAF = 2
ROLE_NODE = 3
ROLE_SNAPSHOT = 4
IDENTITY_POLICY = 1
IDENTITY_ORACLE = 2
IDENTITY_ATTESTATION = 3

FROZEN_COST_SHA512 = (
    "d199125742082ad92973d81c4b970eef0f37e57d8e6f47716dd5bbacdbe93381"
    "83eb79056b5123f0a7fd527f512032d3af6444167df8571617825e601f483a4f"
)
FROZEN_LEDGER_SHA512 = (
    "60b3933fc2b674aafbb4c1889d3dc438dceebd5216e82f7d311f80b04a00a629"
    "2d843f5d553fdc2a6b1b6308cb191e389992b5e3744b99f879cc63ddb272d312"
)
FROZEN_MUTATIONS_SHA512 = (
    "075f5d6c48cf093c68ce36f66cfb1af255ff1d081fa3742d95802ba6617e95a1"
    "a0c6b17a8e2fff95ee993cef2e604449d04c22b44c2dd249d998f36e56e08889"
)

POLICY_KAT = bytes.fromhex(
    "866d201343968585d90f58e698c0648c34ff551da13c437e689da6ca29fe1571"
    "9de8ac1fcba7b5b0cdca0db95b641a63a1483e94b9c52aabda5eaba75c7ea345"
)
ORACLE_KAT = bytes.fromhex(
    "4f6600a35de08028d7b4e98cd60d7dcadd2086c67045b4d62272af12cced7686"
    "37aac5215c00b7257e1eff51f56138f5b92e4b486bb870ac6ef64e142e2df25e"
)
ATTESTATION_KAT = bytes.fromhex(
    "7b0434f952f572c2d74aa48461142842d3d504d2ffc01062d4d3c55afbfeddd5"
    "49e07fdbd71709450b1d45d13eb0186dd7eb7b34b5aa83e557a40cda8b25905d"
)
MERKLE_ROOT_KAT = bytes.fromhex(
    "0c6cbb840c5523b58c3aae93e08fe17f956c7b22f7c43d05ef7d10f6d1dcdd1"
    "e7c4556ae983ed506d510bc8f607d7d3a714db420c9943ad4c7a6e75dd7ea9939"
)
FULL_ROOT_KAT = bytes.fromhex(
    "c6dc59c66190e9d6a499374b5147288eae6ba69a10b8a7d5f99b736a4745fc01"
    "287d0309a0c8af9a7cffba77bfa2de908640ee0f4ca995b57f91f56d81a5eaf2"
)
SNAPSHOT_KAT = bytes.fromhex(
    "f7a60b50ef6cd848546be653fe427906c06062c18df3f34f6a887202cff7e576b"
    "cf6c13412d3da08f4397607c5080c53fd94b7decc90cff8200152d3e31004f2"
)


class Reject(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def sha512(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def le(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


@dataclass(frozen=True)
class OracleSource:
    asset_id: int
    policy_version: int
    oracle_feed: int
    submitted_at: int
    source_id: bytes
    payload: bytes

    def encode(self) -> bytes:
        require(len(self.source_id) == 32, "oracle source id width")
        require(1 <= len(self.payload) <= PAYLOAD_MAX, "oracle payload length")
        return b"".join(
            (
                struct.pack("<IIIQ", self.asset_id, self.policy_version, self.oracle_feed, self.submitted_at),
                self.source_id,
                struct.pack("<H", len(self.payload)),
                self.payload,
            )
        )

    @classmethod
    def decode(cls, raw: bytes) -> "OracleSource":
        require(len(raw) >= 55, "oracle source truncated")
        payload_len = le(raw[52:54])
        require(1 <= payload_len <= PAYLOAD_MAX, "oracle payload length")
        require(len(raw) == 54 + payload_len, "oracle source trailing/truncated")
        value = cls(le(raw[0:4]), le(raw[4:8]), le(raw[8:12]), le(raw[12:20]), raw[20:52], raw[54:])
        require(value.encode() == raw, "oracle source noncanonical")
        return value


@dataclass(frozen=True)
class AttestationSource:
    asset_id: int
    policy_version: int
    attestation_id: int
    created_at: int
    issuer_id: bytes
    payload: bytes

    def encode(self) -> bytes:
        require(len(self.issuer_id) == 32, "attestation issuer width")
        require(1 <= len(self.payload) <= PAYLOAD_MAX, "attestation payload length")
        return b"".join(
            (
                struct.pack("<IIQQ", self.asset_id, self.policy_version, self.attestation_id, self.created_at),
                self.issuer_id,
                struct.pack("<H", len(self.payload)),
                self.payload,
            )
        )

    @classmethod
    def decode(cls, raw: bytes) -> "AttestationSource":
        require(len(raw) >= 59, "attestation source truncated")
        payload_len = le(raw[56:58])
        require(1 <= payload_len <= PAYLOAD_MAX, "attestation payload length")
        require(len(raw) == 58 + payload_len, "attestation source trailing/truncated")
        value = cls(le(raw[0:4]), le(raw[4:8]), le(raw[8:16]), le(raw[16:24]), raw[24:56], raw[58:])
        require(value.encode() == raw, "attestation source noncanonical")
        return value


@dataclass(frozen=True)
class Entry:
    asset_id: int
    oracle_feed: int
    attestation_id: int
    min_collateral_ratio_ppm: int
    max_mint_per_epoch: int
    oracle_max_age: int
    oracle_submitted_at: int
    enabled_at: int
    retired_at: int | None
    policy_version: int
    active: bool
    oracle_commitment: bytes
    attestation_commitment: bytes
    attestation_disputed: bool

    @property
    def key(self) -> tuple[int, int]:
        return self.asset_id, self.policy_version

    def encode(self) -> bytes:
        require(len(self.oracle_commitment) == WIDTH, "oracle commitment width")
        require(len(self.attestation_commitment) == WIDTH, "attestation commitment width")
        encoded = bytearray(ENTRY_BYTES)
        encoded[0:4] = struct.pack("<I", self.asset_id)
        encoded[4:8] = struct.pack("<I", self.oracle_feed)
        encoded[8:16] = struct.pack("<Q", self.attestation_id)
        encoded[16:32] = self.min_collateral_ratio_ppm.to_bytes(16, "little")
        encoded[32:48] = self.max_mint_per_epoch.to_bytes(16, "little")
        encoded[48:56] = struct.pack("<Q", self.oracle_max_age)
        encoded[56:64] = struct.pack("<Q", self.oracle_submitted_at)
        encoded[64:72] = struct.pack("<Q", self.enabled_at)
        if self.retired_at is not None:
            encoded[72] = 1
            encoded[73:81] = struct.pack("<Q", self.retired_at)
        encoded[81:85] = struct.pack("<I", self.policy_version)
        encoded[85] = int(self.active)
        encoded[86:150] = self.oracle_commitment
        encoded[150:214] = self.attestation_commitment
        encoded[214] = int(self.attestation_disputed)
        return bytes(encoded)

    @classmethod
    def decode(cls, raw: bytes) -> "Entry":
        require(len(raw) == ENTRY_BYTES, "row width")
        require(raw[72] in (0, 1) and raw[85] in (0, 1) and raw[214] in (0, 1), "row bool")
        require(raw[72] == 1 or raw[73:81] == bytes(8), "absent retirement payload")
        value = cls(
            le(raw[0:4]), le(raw[4:8]), le(raw[8:16]), le(raw[16:32]),
            le(raw[32:48]), le(raw[48:56]), le(raw[56:64]), le(raw[64:72]),
            le(raw[73:81]) if raw[72] else None, le(raw[81:85]), bool(raw[85]),
            raw[86:150], raw[150:214], bool(raw[214]),
        )
        require(value.encode() == raw, "row noncanonical")
        return value

    def policy_tuple(self) -> bytes:
        encoded = b"".join(
            (
                struct.pack("<IIQ", self.asset_id, self.oracle_feed, self.attestation_id),
                self.min_collateral_ratio_ppm.to_bytes(16, "little"),
                self.max_mint_per_epoch.to_bytes(16, "little"),
                struct.pack("<QI", self.oracle_max_age, self.policy_version),
                bytes((int(self.active),)),
            )
        )
        require(len(encoded) == 61, "policy tuple width")
        return encoded


def identity_person(role: int) -> bytes:
    require(role in (1, 2, 3), "identity role")
    return b"HGMAIDV2" + bytes((role, PROFILE, WIDTH)) + bytes(5)


def tree_person(role: int, level: int = 0) -> bytes:
    require(role in (ROLE_FULL, ROLE_LEAF, ROLE_NODE, ROLE_SNAPSHOT), "tree role")
    require((role == ROLE_NODE and 0 <= level < DEPTH) or (role != ROLE_NODE and level == 0), "tree level")
    return b"HGMAROOT" + bytes((role, PROFILE, WIDTH, DEPTH, level, 0, 0, 0))


def digest(message: bytes, person: bytes) -> bytes:
    require(len(person) == 16, "personalization width")
    return hashlib.blake2b(message, digest_size=WIDTH, person=person).digest()


def policy_hash(entry: Entry) -> bytes:
    return digest(entry.policy_tuple(), identity_person(IDENTITY_POLICY))


def oracle_hash(source: OracleSource) -> bytes:
    return digest(source.encode(), identity_person(IDENTITY_ORACLE))


def attestation_hash(source: AttestationSource) -> bytes:
    return digest(source.encode(), identity_person(IDENTITY_ATTESTATION))


def sample_sources(asset_id: int, policy_version: int = 3) -> tuple[OracleSource, AttestationSource]:
    delta = asset_id - 1001
    return (
        OracleSource(
            asset_id, policy_version, 7 + delta, 42,
            bytes((0x31 + delta % 31,)) * 32,
            b"price:i128le=" + (123_456 + delta).to_bytes(16, "little"),
        ),
        AttestationSource(
            asset_id, policy_version, 0x0102030405060708 + delta, 9,
            bytes((0x51 + delta % 31,)) * 32, b"eligible:true",
        ),
    )


def sample_entry(asset_id: int) -> Entry:
    oracle, attestation = sample_sources(asset_id)
    return Entry(
        asset_id, oracle.oracle_feed, attestation.attestation_id, 1_500_000,
        1_000_000_000, 120, oracle.submitted_at, 10, 1000, 3, True,
        oracle_hash(oracle), attestation_hash(attestation), False,
    )


def validate_entries(entries: list[Entry]) -> None:
    require(len(entries) <= CAP, "manifest cap")
    require(all(left.key < right.key for left, right in zip(entries, entries[1:])), "manifest ordering")


def slots(entries: list[Entry]) -> list[bytes]:
    validate_entries(entries)
    result = [b"\x01" + entry.encode() for entry in entries]
    result.extend([bytes(SLOT_BYTES)] * (CAP - len(result)))
    return result


def decode_slots(values: list[bytes]) -> list[Entry]:
    require(len(values) == CAP, "slot count")
    result: list[Entry] = []
    saw_empty = False
    for value in values:
        require(len(value) == SLOT_BYTES and value[0] in (0, 1), "slot shape")
        if value[0] == 0:
            require(value == bytes(SLOT_BYTES), "empty slot padding")
            saw_empty = True
        else:
            require(not saw_empty, "present slot after empty")
            result.append(Entry.decode(value[1:]))
    validate_entries(result)
    return result


def leaf(value: bytes) -> bytes:
    require(len(value) == SLOT_BYTES and value[0] in (0, 1), "leaf shape")
    if value[0] == 0:
        require(value == bytes(SLOT_BYTES), "empty leaf padding")
    else:
        Entry.decode(value[1:])
    return digest(value, tree_person(ROLE_LEAF))


def node(left: bytes, right: bytes, level: int) -> bytes:
    require(len(left) == len(right) == WIDTH, "node width")
    return digest(left + right, tree_person(ROLE_NODE, level))


def levels(entries: list[Entry]) -> list[list[bytes]]:
    result = [[leaf(value) for value in slots(entries)]]
    for level in range(DEPTH):
        prior = result[-1]
        result.append([node(prior[index], prior[index + 1], level) for index in range(0, len(prior), 2)])
    return result


def merkle_root(entries: list[Entry]) -> bytes:
    return levels(entries)[-1][0]


def full_root(entries: list[Entry]) -> bytes:
    return digest(b"".join(slots(entries)), tree_person(ROLE_FULL))


def snapshot(root: bytes, height: int) -> bytes:
    require(len(root) == WIDTH, "snapshot root width")
    return digest(struct.pack("<Q", height) + root, tree_person(ROLE_SNAPSHOT))


def witness(entries: list[Entry], index: int) -> bytes:
    require(0 <= index < len(entries), "selected slot absent")
    tree = levels(entries)
    siblings: list[bytes] = []
    cursor = index
    for level in range(DEPTH):
        siblings.append(tree[level][cursor ^ 1])
        cursor >>= 1
    encoded = struct.pack("<I", index) + entries[index].encode() + b"".join(siblings)
    require(len(encoded) == WITNESS_BYTES, "witness width")
    return encoded


def root_from_witness(raw: bytes) -> bytes:
    require(len(raw) == WITNESS_BYTES, "witness width")
    index = le(raw[:4])
    require(index < CAP, "witness index")
    entry = Entry.decode(raw[4 : 4 + ENTRY_BYTES])
    current = leaf(b"\x01" + entry.encode())
    offset = 4 + ENTRY_BYTES
    cursor = index
    for level in range(DEPTH):
        sibling = raw[offset + level * WIDTH : offset + (level + 1) * WIDTH]
        current = node(current, sibling, level) if cursor & 1 == 0 else node(sibling, current, level)
        cursor >>= 1
    require(cursor == 0, "witness high index bits")
    return current


def rust_code_mask(source: str) -> str:
    """Blank comments and string/character literals for structural checks."""
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
        quote = index + 1 if source.startswith('b"', index) else index
        if quote < len(source) and source[quote] == '"':
            cursor = quote + 1
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
        character = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
        if character:
            cursor = index + character.end()
            for position in range(index, cursor):
                output[position] = " "
            index = cursor
            continue
        index += 1
    return "".join(output)


def function_body(source: str, name: str) -> str:
    masked = rust_code_mask(source)
    match = re.search(rf"\bfn\s+{re.escape(name)}\b", masked)
    require(match is not None, f"missing function {name}")
    opening = masked.find("{", match.end())
    require(opening >= 0, f"missing body {name}")
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise Reject(f"unterminated function {name}")


def rust_kat(source: str, name: str) -> bytes:
    match = re.search(rf"const {name}: \[u8; 64\] = \[(?P<body>.*?)\];", source, re.DOTALL)
    require(match is not None, f"missing Rust KAT {name}")
    value = bytes(int(token, 16) for token in re.findall(r"0x([0-9a-f]{2})", match.group("body")))
    require(len(value) == WIDTH, f"Rust KAT {name} width")
    return value


AUTHORITY_FLAGS = {
    "ACTIVE",
    "KERNEL_GLOBAL_ROOT_INTEGRATED",
    "GENESIS_INTEGRATED",
    "STATE_WRITER_INTEGRATED",
    "ORACLE_CONSTRUCTOR_AUTHORIZED",
    "ATTESTATION_CONSTRUCTOR_AUTHORIZED",
    "RELATION_INTEGRATED",
    "CONSENSUS_ROUTE_AUTHORIZED",
    "QROM_AUTHORIZED",
    "COMPLETE_ZK_AUTHORIZED",
    "FORMAL_REFINEMENT_COMPLETE",
    "PRODUCTION_AUTHORIZED",
}


def source_checks_text(
    module: str,
    lib: str,
    live_manifest: str,
    legacy: str,
    successor_gate: str,
    selection: dict[str, object],
) -> None:
    required = [
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_CAP: usize = 16;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH: usize = 4;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES: usize = 64;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES: usize = 215;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES: usize = 216;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES: usize = 475;",
        "pub const STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES: usize = 72;",
        "pub struct StablecoinPolicyManifestEntryV2",
        "pub struct StablecoinManifestMembershipProofV2",
        "pub struct StablecoinManifestParentStateV2",
        "pub oracle_commitment: StablecoinOracleAuthorityCommitmentV2,",
        "pub attestation_commitment: StablecoinAttestationAuthorityCommitmentV2,",
        "pub fn blake2b512_personalized_v2",
        "pub fn stablecoin_policy_identity_v2",
        "pub fn stablecoin_oracle_authority_commitment_v2",
        "pub fn stablecoin_attestation_authority_commitment_v2",
        "pub fn stablecoin_manifest_leaf_v2",
        "pub fn stablecoin_manifest_node_v2",
        "pub fn stablecoin_manifest_root_v2",
        "pub fn stablecoin_manifest_full_vector_root_v2",
        "pub fn stablecoin_manifest_snapshot_v2",
        "pub fn verify_stablecoin_manifest_parent_v2",
        "pub fn verify_stablecoin_manifest_authority_v2",
        "const AUTHORITY_PROFILE_V2: u8 = 2;",
        "const AUTHORITY_WIDTH_V2: u8 = 64;",
        "const AUTHORITY_CAP_LOG2_V2: u8 = 4;",
        "parameter_block[0] = 64;",
        "parameter_block[2] = 1;",
        "parameter_block[3] = 1;",
        "parameter_block[48..64].copy_from_slice(&personalization);",
        "v[12] ^= count as u64;",
        "v[13] ^= (count >> 64) as u64;",
        "v[14] = !v[14];",
        "blake2b_compress(&mut state, &final_block, message.len() as u128, true);",
        "identity_personalization(IDENTITY_ROLE_POLICY)",
        "identity_personalization(IDENTITY_ROLE_ORACLE)",
        "identity_personalization(IDENTITY_ROLE_ATTESTATION)",
        "tree_personalization(ROLE_LEAF, 0)",
        "tree_personalization(ROLE_NODE, level as u8)",
        "tree_personalization(ROLE_FULL, 0)",
        "tree_personalization(ROLE_SNAPSHOT, 0)",
    ]
    for marker in required:
        require(marker in module, f"missing V2 source invariant: {marker}")

    flag_matches = dict(
        re.findall(
            r"pub const STABLECOIN_MANIFEST_AUTHORITY_V2_([A-Z0-9_]+): bool = (true|false);",
            module,
        )
    )
    require(set(flag_matches) == AUTHORITY_FLAGS, f"V2 authority flag inventory drift: {sorted(flag_matches)}")
    require(all(value == "false" for value in flag_matches.values()), "a V2 authority flag became true")

    expected_offsets = {
        "ASSET_ID": 0, "ORACLE_FEED": 4, "ATTESTATION_ID": 8,
        "MIN_COLLATERAL_RATIO_PPM": 16, "MAX_MINT_PER_EPOCH": 32,
        "ORACLE_MAX_AGE": 48, "ORACLE_SUBMITTED_AT": 56, "ENABLED_AT": 64,
        "RETIRED_PRESENT": 72, "RETIRED_AT": 73, "POLICY_VERSION": 81,
        "ACTIVE": 85, "ORACLE_COMMITMENT": 86, "ATTESTATION_COMMITMENT": 150,
        "ATTESTATION_DISPUTED": 214,
    }
    for name, expected in expected_offsets.items():
        match = re.search(rf"pub const STABLECOIN_ENTRY_V2_{name}_OFFSET: usize = (\d+);", module)
        require(match is not None and int(match.group(1)) == expected, f"V2 row offset drift: {name}")

    iv_match = re.search(
        r"const BLAKE2B_IV: \[u64; 8\] = \[(?P<body>.*?)\];",
        module,
        re.DOTALL,
    )
    require(iv_match is not None, "missing BLAKE2b IV")
    rust_iv = [int(token, 16) for token in re.findall(r"0x([0-9a-f]{16})", iv_match.group("body"))]
    require(
        rust_iv
        == [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        ],
        "RFC 7693 BLAKE2b IV drift",
    )
    sigma_match = re.search(
        r"const BLAKE2B_SIGMA: \[\[usize; 16\]; 12\] = \[(?P<body>.*?)\];",
        module,
        re.DOTALL,
    )
    require(sigma_match is not None, "missing BLAKE2b sigma")
    sigma_rows = [
        [int(token) for token in re.findall(r"\d+", row)]
        for row in re.findall(r"\[([^\[\]]+)\]", sigma_match.group("body"))
    ]
    require(
        sigma_rows
        == [
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
        ],
        "RFC 7693 BLAKE2b sigma drift",
    )

    require(lib.count("pub mod stablecoin_manifest_authority_v2;") == 1, "inactive V2 module export drift")
    require("pub use stablecoin_manifest_authority_v2" not in lib, "inactive V2 symbols were promoted at crate root")
    global_root = rust_code_mask(function_body(live_manifest, "kernel_global_root"))
    require("stablecoin_manifest_authority_v2" not in global_root.lower(), "V2 entered kernel_global_root")
    require("StablecoinManifestRootV2" not in live_manifest, "live manifest acquired a V2 authority field")
    require("[u8; 48]" not in function_body(module, "stablecoin_policy_identity_v2"), "legacy48 entered V2 policy constructor")
    require("[u8; 56]" not in module, "W56 type/conversion entered all-W64 V2 module")
    require("STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false;" in legacy, "legacy root integration became true")
    require("STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED: bool = false;" in legacy, "legacy manifest became authorized")
    require(re.search(r"AUTHORIZED_PROFILES: dict\[str, AuthorizedProfile\] = \{\}", successor_gate) is not None, "successor source registry is no longer empty")
    require(selection.get("selection") == "unselected", "successor selection became active")
    require(selection.get("profile_id") is None and selection.get("identity") is None, "successor identity is non-null")


def source_checks() -> dict[str, str]:
    require(sha512(FROZEN_COST) == FROZEN_COST_SHA512, "frozen cost report SHA-512 drift")
    require(sha512(FROZEN_LEDGER) == FROZEN_LEDGER_SHA512, "frozen capability ledger SHA-512 drift")
    require(sha512(FROZEN_MUTATIONS) == FROZEN_MUTATIONS_SHA512, "frozen mutation corpus SHA-512 drift")
    selection = json.loads(SUCCESSOR_SELECTION.read_text(encoding="utf-8"))
    source_checks_text(
        MODULE.read_text(encoding="utf-8"),
        LIB.read_text(encoding="utf-8"),
        LIVE_MANIFEST.read_text(encoding="utf-8"),
        LEGACY_MODULE.read_text(encoding="utf-8"),
        SUCCESSOR_GATE.read_text(encoding="utf-8"),
        selection,
    )
    return {
        "module_sha512": sha512(MODULE),
        "lib_sha512": sha512(LIB),
        "live_manifest_sha512": sha512(LIVE_MANIFEST),
        "frozen_cost_sha512": FROZEN_COST_SHA512,
        "frozen_ledger_sha512": FROZEN_LEDGER_SHA512,
        "frozen_mutations_sha512": FROZEN_MUTATIONS_SHA512,
    }


def frozen_artifact_checks() -> None:
    cost = json.loads(FROZEN_COST.read_text(encoding="utf-8"))
    ledger = json.loads(FROZEN_LEDGER.read_text(encoding="utf-8"))
    mutations = json.loads(FROZEN_MUTATIONS.read_text(encoding="utf-8"))
    evidence = cost["self_test_evidence"]
    require(evidence["fresh_v2_all_w64_policy_hash_kat"] == POLICY_KAT.hex(), "frozen policy KAT drift")
    require(evidence["fresh_v2_all_w64_oracle_hash_kat"] == ORACLE_KAT.hex(), "frozen oracle KAT drift")
    require(evidence["fresh_v2_all_w64_attestation_hash_kat"] == ATTESTATION_KAT.hex(), "frozen attestation KAT drift")
    require(evidence["fresh_v2_all_w64_merkle_root_cap16_kat"] == MERKLE_ROOT_KAT.hex(), "frozen root KAT drift")
    require(evidence["fresh_v2_all_w64_entry_bytes_exhaustively_mutated"] == ENTRY_BYTES, "frozen row mutation count drift")
    require(evidence["fresh_v2_all_w64_index_paths_verified"] == CAP, "frozen path count drift")
    profile = cost["profiles"]["fresh-v2-all-w64-merkle-w64"]
    require(profile["entry_bytes"] == ENTRY_BYTES and profile["semantic_witness_bytes"] == WITNESS_BYTES, "frozen geometry drift")
    require(profile["hash_schedule"]["total_relation_compressions"] == 7, "frozen hash schedule drift")
    require(cost["decision"]["production_winner"] is None, "frozen screen selected a production winner")
    require(ledger["production_authorized"] is False, "frozen ledger production authority became true")
    require(all(value is False for value in ledger["current_authority"].values()), "frozen authority ledger contains a true flag")
    require(ledger["fresh_v2_all_w64_candidate_predicates"]["all_w64_profile_production_eligible"] is False, "W64 profile became eligible")
    require(mutations["coverage"]["every_fresh_v2_all_w64_entry_byte"] == list(range(ENTRY_BYTES)), "frozen every-byte corpus drift")


def semantic_checks(module_source: str) -> dict[str, int]:
    entries = [sample_entry(1001 + index) for index in range(CAP)]
    oracle, attestation = sample_sources(1001)
    require(policy_hash(entries[0]) == POLICY_KAT, "independent policy KAT")
    require(oracle_hash(oracle) == ORACLE_KAT, "independent oracle KAT")
    require(attestation_hash(attestation) == ATTESTATION_KAT, "independent attestation KAT")
    root = merkle_root(entries)
    require(root == MERKLE_ROOT_KAT, "independent Merkle KAT")
    require(full_root(entries) == FULL_ROOT_KAT, "independent full-root KAT")
    require(snapshot(root, 50) == SNAPSHOT_KAT, "independent snapshot KAT")
    require(decode_slots(slots(entries)) == entries, "slot round trip")

    rust_expected = {
        "POLICY_KAT": POLICY_KAT, "ORACLE_KAT": ORACLE_KAT,
        "ATTESTATION_KAT": ATTESTATION_KAT, "MERKLE_ROOT_KAT": MERKLE_ROOT_KAT,
        "FULL_ROOT_KAT": FULL_ROOT_KAT, "SNAPSHOT_KAT": SNAPSHOT_KAT,
    }
    for name, expected in rust_expected.items():
        require(rust_kat(module_source, name) == expected, f"Rust {name} differs from independent/frozen KAT")

    for index in range(CAP):
        require(root_from_witness(witness(entries, index)) == root, f"path {index} failed")

    selected = witness(entries, 7)
    row_mutations = 0
    for offset in range(4, 4 + ENTRY_BYTES):
        changed = bytearray(selected)
        changed[offset] ^= 1
        try:
            same = root_from_witness(bytes(changed)) == root
        except Reject:
            same = False
        require(not same, f"row byte {offset - 4} was not bound")
        row_mutations += 1

    path_mutations = 0
    for offset in range(4 + ENTRY_BYTES, WITNESS_BYTES):
        changed = bytearray(selected)
        changed[offset] ^= 1
        require(root_from_witness(bytes(changed)) != root, f"path byte {offset} was not bound")
        path_mutations += 1

    index_mutations = 0
    for offset in range(4):
        changed = bytearray(selected)
        changed[offset] ^= 1
        try:
            same = root_from_witness(bytes(changed)) == root
        except Reject:
            same = False
        require(not same, f"index byte {offset} was not bound")
        index_mutations += 1

    root_mutations = 0
    for offset in range(WIDTH):
        changed = bytearray(root)
        changed[offset] ^= 1
        require(bytes(changed) != root and snapshot(bytes(changed), 50) != SNAPSHOT_KAT, f"root byte {offset}")
        root_mutations += 1

    height_mutations = 0
    for offset in range(8):
        changed = bytearray(struct.pack("<Q", 50))
        changed[offset] ^= 1
        require(snapshot(root, le(changed)) != SNAPSHOT_KAT, f"height byte {offset}")
        height_mutations += 1

    source_mutations = 0
    for canonical, decode, hash_fn, expected in (
        (oracle.encode(), OracleSource.decode, oracle_hash, ORACLE_KAT),
        (attestation.encode(), AttestationSource.decode, attestation_hash, ATTESTATION_KAT),
    ):
        for offset in range(len(canonical)):
            changed = bytearray(canonical)
            changed[offset] ^= 1
            try:
                same = hash_fn(decode(bytes(changed))) == expected
            except Reject:
                same = False
            require(not same, f"constructor source byte {offset} was not bound")
            source_mutations += 1

    for invalid in (list(reversed(entries)), [entries[0], entries[0]], [entries[0], replace(entries[0], oracle_feed=8)]):
        try:
            validate_entries(invalid)
        except Reject:
            pass
        else:
            raise Reject("order/duplicate mutation accepted")
    bad_prefix = slots(entries[:1])
    bad_prefix[0] = bytes(SLOT_BYTES)
    bad_prefix[1] = b"\x01" + entries[0].encode()
    try:
        decode_slots(bad_prefix)
    except Reject:
        pass
    else:
        raise Reject("present-after-empty mutation accepted")
    bad_empty = slots(entries[:1])
    bad_empty[1] = b"\x00\x01" + bytes(ENTRY_BYTES - 1)
    try:
        decode_slots(bad_empty)
    except Reject:
        pass
    else:
        raise Reject("nonzero empty padding accepted")

    return {
        "paths_verified": CAP,
        "row_byte_mutations": row_mutations,
        "path_byte_mutations": path_mutations,
        "index_byte_mutations": index_mutations,
        "root_byte_mutations": root_mutations,
        "height_byte_mutations": height_mutations,
        "constructor_source_byte_mutations": source_mutations,
        "ordering_duplicate_prefix_mutations": 5,
    }


def check() -> dict[str, object]:
    hashes = source_checks()
    frozen_artifact_checks()
    mutations = semantic_checks(MODULE.read_text(encoding="utf-8"))
    return {
        "status": "pass",
        "profile": "inactive-fresh-v2-all-w64-cap16",
        "digest": "RFC7693-BLAKE2b-512-personalized",
        "entry_bytes": ENTRY_BYTES,
        "slot_bytes": SLOT_BYTES,
        "witness_bytes": WITNESS_BYTES,
        "public_bytes": PUBLIC_BYTES,
        "kernel_global_root_integrated": False,
        "successor_registry_empty": True,
        "production_authorized": False,
        "authority_flags_false": len(AUTHORITY_FLAGS),
        "mutations": mutations,
        **hashes,
    }


def main() -> None:
    print(json.dumps(check(), sort_keys=True))


if __name__ == "__main__":
    main()
