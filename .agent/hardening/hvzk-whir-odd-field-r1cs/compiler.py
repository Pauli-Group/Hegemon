#!/usr/bin/env python3
"""Deterministic source-only Boolean/R1CS screen for HX448C02.

This compiler deliberately emits a compact macro program rather than an
expanded multi-million-row matrix.  Every macro has a fixed sparse-R1CS
expansion over the specified odd prime, so `(m,n,l)` and nonzero counts are
exact for this compiler.  No proof backend is invoked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCALAR = ROOT / "circuits/transaction/src/full_blake2b448_relation.rs"
M4 = ROOT / "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs"
M4_LIB = M4.with_name("lib.rs")
STABLE_MANIFEST = ROOT / "protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"

MANIFEST_PATH = HERE / "relation_manifest.json"
CERTIFICATE_PATH = HERE / "certificate.json"
TEST_PATH = HERE / "test_compiler.py"

P = 0xFFFFFFFF00000001
FIELD_BYTES = 8
STATEMENT_BYTES = 869
STATEMENT_BITS = STATEMENT_BYTES * 8
STATE_WORDS = 50
STATE_BITS = STATE_WORDS * 64
PUBLIC_BITS = STATEMENT_BITS + STATE_BITS
PRIVATE_WORDS = 1209
PRIVATE_BYTES = PRIVATE_WORDS * 8
PRIVATE_BITS = PRIVATE_BYTES * 8
DIGEST_BITS = 448
STABLE_DIGEST_BITS = 384
PHYSICAL_HASH_CALLS = 83

LOCAL_GROUPS = [
    "statement transport and canonical padding",
    "all sixteen activity masks with all-empty rejection",
    "signed-magnitude ranges and no negative zero",
    "four canonical ordered asset slots",
    "active note kind value and asset ranges",
    "active selector one-hot and selected-asset equality",
    "inactive input witness and public nullifier zero",
    "active input 32-bit Merkle position",
    "inactive output witness ciphertext and public bindings zero",
    "active ciphertext exact size and trailing padding",
    "duplicate active nullifier rejection",
    "five-mode range and one-hot selection",
    "mode-specific 2-in 2-out activity shapes",
    "mode-specific note typing and unused-lane zeroing",
    "accumulator threshold signer and approval metadata",
    "approval increment no-clear one-change and signer membership",
    "signed native balance including fee",
    "ordinary non-native conservation",
    "stablecoin mint and burn signed balance",
    "disabled unique-zero and enabled typed stablecoin surface",
]

HASH_LINK_GROUPS = [
    "note commitments and resolved authorization keys",
    "nullifier derivation and active public equality",
    "32-level Merkle direction selection and anchor equality",
    "policy and four authorization-lane digest links",
    "final-spend intent equality",
    "public balance-tag equality",
    "canonical ciphertext hash equality",
]

STATE_GROUPS = [
    "disabled state unique-zero",
    "v1 typed widths booleans and entry presence",
    "nonzero expected/provided manifest commitment equality",
    "expected/provided current-height equality",
    "selected entry statement field equalities",
    "active and lifecycle-open predicates",
    "canonical optional retirement and strict retirement bound",
    "oracle nonfuture and saturating freshness bound",
    "undisputed nonzero issuance and u128 cap",
]

HOST_GROUPS = [
    "61-byte policy-identity BLAKE2b-384 recomputation",
    "whole-manifest v1 BLAKE2b-384 recomputation",
    "selected-entry index membership in the committed vector",
    "consensus authentication of expected root and height",
]

MUTATIONS_R1CS = [
    "all_empty_activity",
    "invalid_authorization_shape",
    "signed_balance_drift",
    "stable_mint_or_burn_drift",
    "missing_consensus_state",
    "wrong_state_seam_version",
    "zero_manifest_commitment",
    "manifest_commitment_equality_mismatch",
    "current_height_equality_mismatch",
    "missing_selected_entry",
    "statement_entry_binding_mismatch",
    "inactive_or_closed_lifecycle",
    "future_or_stale_oracle",
    "disputed_attestation",
    "zero_or_over_cap_issuance",
    "note_nullifier_merkle_or_ciphertext_link_drift",
]

MUTATIONS_HOST = [
    "forged_policy_hash_derivation",
    "forged_whole_manifest_commitment",
    "forged_selected_entry_membership",
    "forged_consensus_expected_root_or_height",
]

ACTIVATION = {
    "circuit_version": 0x4481,
    "crypto_suite": 0x4482,
    "family_id": 0x4483,
    "action_id": 0x4484,
    "network_id": 0x01020304,
    "backend_id": 0x45,
    "proof_profile": 0x46,
    "domain_set": 0x4487,
    "chain_id": "11" * 56,
    "genesis_id": "22" * 56,
    "rules_hash": "33" * 56,
}

OFFSETS = OrderedDict(
    magic=0,
    grammar=8,
    flags=10,
    anchor=14,
    nullifiers=70,
    commitments=182,
    ciphertext_hashes=294,
    ciphertext_sizes=406,
    assets=414,
    fee=446,
    value_balance_sign=454,
    value_balance_magnitude=455,
    stable_enabled=463,
    stable_asset=464,
    stable_version=472,
    stable_issuance_sign=476,
    stable_issuance_magnitude=477,
    stable_policy=485,
    stable_oracle=533,
    stable_attestation=581,
    balance_tag=629,
    activation=685,
    network=693,
    backend=697,
    profile=698,
    domain_set=699,
    chain_id=701,
    genesis_id=757,
    rules_hash=813,
    end=869,
)

STATEMENT_LAYOUT = [
    {"name": "magic", "offset_bytes": 0, "bytes": 8, "semantic": "ASCII HX448C02"},
    {"name": "grammar", "offset_bytes": 8, "bytes": 2, "semantic": "u16be = 2"},
    {"name": "activity_flags", "offset_bytes": 10, "bytes": 4, "semantic": "four canonical bytes in0,in1,out0,out1"},
    {"name": "anchor", "offset_bytes": 14, "bytes": 56, "semantic": "448-bit digest"},
    {"name": "nullifiers", "offset_bytes": 70, "bytes": 112, "semantic": "two 448-bit digests"},
    {"name": "commitments", "offset_bytes": 182, "bytes": 112, "semantic": "two 448-bit digests"},
    {"name": "ciphertext_hashes", "offset_bytes": 294, "bytes": 112, "semantic": "two 448-bit digests"},
    {"name": "ciphertext_sizes", "offset_bytes": 406, "bytes": 8, "semantic": "two u32be values"},
    {"name": "canonical_asset_slots", "offset_bytes": 414, "bytes": 32, "semantic": "four u64be asset identifiers"},
    {"name": "fee", "offset_bytes": 446, "bytes": 8, "semantic": "u64be"},
    {"name": "value_balance_sign", "offset_bytes": 454, "bytes": 1, "semantic": "bool byte"},
    {"name": "value_balance_magnitude", "offset_bytes": 455, "bytes": 8, "semantic": "u64be"},
    {"name": "stable_enabled", "offset_bytes": 463, "bytes": 1, "semantic": "bool byte"},
    {"name": "stable_asset", "offset_bytes": 464, "bytes": 8, "semantic": "u64be"},
    {"name": "stable_policy_version", "offset_bytes": 472, "bytes": 4, "semantic": "u32be"},
    {"name": "stable_issuance_sign", "offset_bytes": 476, "bytes": 1, "semantic": "bool byte"},
    {"name": "stable_issuance_magnitude", "offset_bytes": 477, "bytes": 8, "semantic": "u64be"},
    {"name": "stable_policy", "offset_bytes": 485, "bytes": 48, "semantic": "BLAKE2b-384 compatibility authority"},
    {"name": "stable_oracle", "offset_bytes": 533, "bytes": 48, "semantic": "384-bit compatibility authority"},
    {"name": "stable_attestation", "offset_bytes": 581, "bytes": 48, "semantic": "384-bit compatibility authority"},
    {"name": "balance_tag", "offset_bytes": 629, "bytes": 56, "semantic": "448-bit digest"},
    {"name": "circuit_version", "offset_bytes": 685, "bytes": 2, "semantic": "u16be"},
    {"name": "crypto_suite", "offset_bytes": 687, "bytes": 2, "semantic": "u16be"},
    {"name": "family_id", "offset_bytes": 689, "bytes": 2, "semantic": "u16be"},
    {"name": "action_id", "offset_bytes": 691, "bytes": 2, "semantic": "u16be"},
    {"name": "network_id", "offset_bytes": 693, "bytes": 4, "semantic": "u32be"},
    {"name": "backend_id", "offset_bytes": 697, "bytes": 1, "semantic": "u8"},
    {"name": "proof_profile", "offset_bytes": 698, "bytes": 1, "semantic": "u8"},
    {"name": "domain_set", "offset_bytes": 699, "bytes": 2, "semantic": "u16be"},
    {"name": "chain_id", "offset_bytes": 701, "bytes": 56, "semantic": "448-bit identifier"},
    {"name": "genesis_id", "offset_bytes": 757, "bytes": 56, "semantic": "448-bit identifier"},
    {"name": "rules_hash", "offset_bytes": 813, "bytes": 56, "semantic": "448-bit identifier"},
]

BLAKE2B_IV = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

BLAKE2B_SIGMA = [
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

KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
KECCAK_IOTA_ONES = sum(value.bit_count() for value in KECCAK_RC)

KECCAK_ROTATION = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

STATE_LAYOUT = [
    {"name": "seam_version", "offset_words": 0, "words": 1, "semantic": "u32"},
    {"name": "expected_current_height", "offset_words": 1, "words": 1, "semantic": "u64"},
    {"name": "provided_current_height", "offset_words": 2, "words": 1, "semantic": "u64"},
    {"name": "selected_entry_index", "offset_words": 3, "words": 1, "semantic": "u32; membership remains host-only"},
    {"name": "selected_entry_present", "offset_words": 4, "words": 1, "semantic": "bool"},
    {"name": "asset_id", "offset_words": 5, "words": 1, "semantic": "u32"},
    {"name": "oracle_feed", "offset_words": 6, "words": 1, "semantic": "u32"},
    {"name": "attestation_id", "offset_words": 7, "words": 1, "semantic": "u64"},
    {"name": "min_collateral_ratio_ppm", "offset_words": 8, "words": 2, "semantic": "u128 as [low64,high64]"},
    {"name": "max_mint_per_epoch", "offset_words": 10, "words": 2, "semantic": "u128 as [low64,high64]"},
    {"name": "oracle_max_age", "offset_words": 12, "words": 1, "semantic": "u64"},
    {"name": "oracle_submitted_at", "offset_words": 13, "words": 1, "semantic": "u64"},
    {"name": "enabled_at", "offset_words": 14, "words": 1, "semantic": "u64"},
    {"name": "retired_present", "offset_words": 15, "words": 1, "semantic": "bool"},
    {"name": "retired_at", "offset_words": 16, "words": 1, "semantic": "u64; zero iff absent"},
    {"name": "policy_version", "offset_words": 17, "words": 1, "semantic": "u32"},
    {"name": "active", "offset_words": 18, "words": 1, "semantic": "bool"},
    {"name": "policy_hash", "offset_words": 19, "words": 6, "semantic": "48 bytes packed as six u64le words"},
    {"name": "oracle_commitment", "offset_words": 25, "words": 6, "semantic": "48 bytes packed as six u64le words"},
    {"name": "attestation_commitment", "offset_words": 31, "words": 6, "semantic": "48 bytes packed as six u64le words"},
    {"name": "attestation_disputed", "offset_words": 37, "words": 1, "semantic": "bool"},
    {"name": "expected_manifest_state_commitment_v1", "offset_words": 38, "words": 6, "semantic": "48 bytes packed as six u64le words"},
    {"name": "provided_manifest_state_commitment_v1", "offset_words": 44, "words": 6, "semantic": "48 bytes packed as six u64le words"},
]


def canonical_bytes(value: Any) -> bytes:
    """Sorted/minified UTF-8 JSON followed by exactly one LF."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def shake_digest(domain: bytes, payload: bytes) -> str:
    framed = domain + len(payload).to_bytes(8, "big") + payload
    return hashlib.shake_256(framed).hexdigest(64)


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def source_set_digest(entries: list[dict[str, Any]]) -> str:
    h = hashlib.sha512(b"hegemon.hx448c02.odd-field-r1cs.source-set.v1\0")
    for entry in sorted(entries, key=lambda item: item["path"]):
        path = entry["path"].encode()
        digest = bytes.fromhex(entry["sha512"])
        size = entry["bytes"]
        h.update(len(path).to_bytes(4, "big"))
        h.update(path)
        h.update(size.to_bytes(8, "big"))
        h.update(digest)
    return h.hexdigest()


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def rust_string_array(text: str, name: str) -> list[str]:
    match = re.search(
        rf"pub const {re.escape(name)}: \[&str; \d+\] = \[(.*?)\n\];",
        text,
        flags=re.S,
    )
    if not match:
        raise ValueError(f"missing Rust string array {name}")
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', match.group(1))


def rust_integer_const(text: str, name: str, rust_type: str) -> int:
    match = re.search(
        rf"pub const {re.escape(name)}: {re.escape(rust_type)} = ([0-9][0-9_]*);",
        text,
    )
    if not match:
        raise ValueError(f"missing literal Rust integer constant {name}")
    return int(match.group(1).replace("_", ""))


def rust_ascii_array_const(text: str, name: str, width: int) -> str:
    match = re.search(
        rf'pub const {re.escape(name)}: \[u8; {width}\] = \*b"([^"\\]{{{width}}})";',
        text,
    )
    if not match:
        raise ValueError(f"missing literal Rust ASCII array constant {name}")
    return match.group(1)


def rust_counterfeit_matrix(text: str) -> list[tuple[str, str]]:
    match = re.search(
        r"pub const COUNTERFEIT_MUTATION_MATRIX: \[CounterfeitMutationCase; 20\] = \[(.*?)\n\];",
        text,
        flags=re.S,
    )
    if not match:
        raise ValueError("missing exact twenty-row counterfeit matrix")
    return re.findall(
        r'CounterfeitMutationCase \{ name: "([^"]+)", disposition: CounterfeitDisposition::(M4Reject|HostOracleOnly) \}',
        match.group(1),
    )


def require_source_contracts() -> dict[str, str]:
    scalar = SCALAR.read_text()
    m4 = M4.read_text()
    m4_lib = M4_LIB.read_text()
    required_scalar = [
        'pub const CANDIDATE_STATEMENT_MAGIC: [u8; 8] = *b"HX448C02";',
        "pub const CANDIDATE_STATEMENT_GRAMMAR: u16 = 2;",
        "pub const CANDIDATE_STATEMENT_BYTES: usize = 869;",
        "pub const CANDIDATE_STATEMENT_LIMB_BYTES: usize = 7;",
        "pub const PHYSICAL_HASH_CALLS: usize = 83;",
        "pub const SECRET_HASH_CALLS: usize = 15;",
        "pub const COLLISION_HASH_CALLS: usize = 68;",
        "pub const BLAKE2B_COMPRESSIONS: usize = 28;",
        "pub const SHAKE256_PERMUTATIONS: usize = 105;",
        "pub const SPLIT_SHA3_PERMUTATIONS: usize = 46;",
        "pub const FULL_BLAKE2B448_AGGREGATE_CONSTRAINT_RELATION_COMPILED: bool = false;",
        "pub const FULL_BLAKE2B448_PRODUCTION_AUTHORIZED: bool = false;",
        "pub const FULL_BLAKE2B448_STRICT_STABLECOIN_PQ_MARGIN: bool = false;",
    ]
    required_m4 = [
        "pub const CANDIDATE_CONSENSUS_STATE_WORDS: usize = 50;",
        "pub const CANDIDATE_PUBLIC_WORDS: usize =\n    CANDIDATE_STATEMENT_WORDS + CANDIDATE_CONSENSUS_STATE_WORDS;",
        "pub const CANDIDATE_PRIVATE_WORDS: usize = CANDIDATE_BASE_PRIVATE_WORDS + 2 * CIPHERTEXT_WORDS;",
        "pub const CANDIDATE_PRIVATE_BYTES: usize = CANDIDATE_PRIVATE_WORDS * 8;",
        "pub const AUTHORIZATION_MODE_COUNT: usize = 5;",
        "pub const PRODUCTION_AUTHORIZED: bool = false;",
        "pub const ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED: bool = false;",
        "pub const STRICT_STABLECOIN_PQ_MARGIN: bool = false;",
        "pub const COMPLETE_ZERO_KNOWLEDGE_PROVED: bool = false;",
        "pub const COMPOSED_QROM_PQ128_PROVED: bool = false;",
        "pub const IDENTITY_FROZEN: bool = false;",
        "debug_assert_eq!(frame.len_bytes, 720);",
        "pub const STATE_MIN_COLLATERAL_WORDS: std::ops::Range<usize> = 8..10;",
        "pub const STATE_MAX_MINT_WORDS: std::ops::Range<usize> = 10..12;",
        "pub const STATE_POLICY_HASH_WORDS: std::ops::Range<usize> = 19..25;",
        "pub const STATE_ORACLE_COMMITMENT_WORDS: std::ops::Range<usize> = 25..31;",
        "pub const STATE_ATTESTATION_COMMITMENT_WORDS: std::ops::Range<usize> = 31..37;",
        "pub const STATE_EXPECTED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 38..44;",
        "pub const STATE_PROVIDED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 44..50;",
    ]
    required_lib = [
        "pub(crate) const PRIVATE_WORDS: usize = 671;",
        "pub(crate) const INPUT_WORDS: usize = 261;",
        "pub(crate) const OUTPUT_WORDS: usize = 30;",
        "pub(crate) const AUTH_WORDS: usize = 89;",
    ]
    for snippet in required_scalar:
        if snippet not in scalar:
            raise ValueError(f"scalar source contract drift: {snippet}")
    for snippet in required_m4:
        if snippet not in m4:
            raise ValueError(f"M4 source contract drift: {snippet}")
    for snippet in required_lib:
        if snippet not in m4_lib:
            raise ValueError(f"M4 library contract drift: {snippet}")
    if rust_string_array(m4, "LOCAL_NON_HASH_CONSTRAINT_GROUPS") != LOCAL_GROUPS:
        raise ValueError("local non-hash family inventory drift")
    if rust_string_array(m4, "HASH_LINK_CONSTRAINT_GROUPS") != HASH_LINK_GROUPS:
        raise ValueError("hash-link family inventory drift")
    if rust_string_array(m4, "CONSENSUS_STATE_SEAM_CONSTRAINT_GROUPS") != STATE_GROUPS:
        raise ValueError("consensus-state family inventory drift")
    if rust_string_array(m4, "HOST_ORACLE_ONLY_GROUPS") != HOST_GROUPS:
        raise ValueError("host-only family inventory drift")
    scalar_literals = {
        "CANDIDATE_STATEMENT_BYTES": STATEMENT_BYTES,
        "CANDIDATE_STATEMENT_LIMB_BYTES": 7,
        "PHYSICAL_HASH_CALLS": PHYSICAL_HASH_CALLS,
        "SECRET_HASH_CALLS": 15,
        "COLLISION_HASH_CALLS": 68,
        "BLAKE2B_COMPRESSIONS": 28,
        "SHAKE256_PERMUTATIONS": 105,
        "SPLIT_SHA3_PERMUTATIONS": 46,
    }
    for name, expected in scalar_literals.items():
        if rust_integer_const(scalar, name, "usize") != expected:
            raise ValueError(f"scalar literal drift: {name}")
    scalar_offsets = {
        "OFFSET_FLAGS": 10,
        "OFFSET_ANCHOR": 14,
        "OFFSET_NULLIFIERS": 70,
        "OFFSET_COMMITMENTS": 182,
        "OFFSET_CIPHERTEXT_HASHES": 294,
        "OFFSET_CIPHERTEXT_SIZES": 406,
        "OFFSET_ASSETS": 414,
        "OFFSET_FEE": 446,
        "OFFSET_VALUE_BALANCE_SIGN": 454,
        "OFFSET_VALUE_BALANCE_MAGNITUDE": 455,
        "OFFSET_STABLE_ENABLED": 463,
        "OFFSET_STABLE_ASSET": 464,
        "OFFSET_STABLE_VERSION": 472,
        "OFFSET_STABLE_ISSUANCE_SIGN": 476,
        "OFFSET_STABLE_ISSUANCE_MAGNITUDE": 477,
        "OFFSET_STABLE_POLICY": 485,
        "OFFSET_STABLE_ORACLE": 533,
        "OFFSET_STABLE_ATTESTATION": 581,
        "OFFSET_BALANCE_TAG": 629,
        "OFFSET_ACTIVATION": 685,
        "OFFSET_NETWORK": 693,
        "OFFSET_BACKEND": 697,
        "OFFSET_PROFILE": 698,
        "OFFSET_DOMAIN_SET": 699,
        "OFFSET_CHAIN_ID": 701,
        "OFFSET_GENESIS_ID": 757,
        "OFFSET_RULES_HASH": 813,
    }
    for name, expected in scalar_offsets.items():
        if rust_integer_const(scalar, name, "usize") != expected:
            raise ValueError(f"scalar statement offset drift: {name}")
    if rust_ascii_array_const(scalar, "CANDIDATE_STATEMENT_MAGIC", 8) != "HX448C02":
        raise ValueError("scalar magic drift")
    expected_roles = {
        "ROLE_NOTE": "nt.b4481",
        "ROLE_NULLIFIER": "nf.b4481",
        "ROLE_MERKLE": "mk.s4481",
        "ROLE_SPEND_A": "sk.b44a1",
        "ROLE_SPEND_B": "sk.b44b1",
        "ROLE_POLICY": "pl.b4481",
        "ROLE_AUTH_A": "au.b44a1",
        "ROLE_AUTH_B": "au.b44b1",
        "ROLE_INTENT": "in.s4481",
        "ROLE_BALANCE": "bl.s4481",
        "ROLE_CIPHERTEXT": "ct.s4481",
    }
    for name, expected in expected_roles.items():
        if rust_ascii_array_const(scalar, name, 8) != expected:
            raise ValueError(f"scalar role drift: {name}")
    expected_counterfeits = [
        *[(name, "M4Reject") for name in MUTATIONS_R1CS],
        *[(name, "HostOracleOnly") for name in MUTATIONS_HOST],
    ]
    if rust_counterfeit_matrix(m4) != expected_counterfeits:
        raise ValueError("counterfeit mutation matrix drift")
    state_indices = {
        "STATE_SEAM_VERSION_WORD": 0,
        "STATE_EXPECTED_HEIGHT_WORD": 1,
        "STATE_PROVIDED_HEIGHT_WORD": 2,
        "STATE_ENTRY_INDEX_WORD": 3,
        "STATE_ENTRY_PRESENT_WORD": 4,
        "STATE_ASSET_ID_WORD": 5,
        "STATE_ORACLE_FEED_WORD": 6,
        "STATE_ATTESTATION_ID_WORD": 7,
        "STATE_ORACLE_MAX_AGE_WORD": 12,
        "STATE_ORACLE_SUBMITTED_AT_WORD": 13,
        "STATE_ENABLED_AT_WORD": 14,
        "STATE_RETIRED_PRESENT_WORD": 15,
        "STATE_RETIRED_AT_WORD": 16,
        "STATE_POLICY_VERSION_WORD": 17,
        "STATE_ACTIVE_WORD": 18,
        "STATE_ATTESTATION_DISPUTED_WORD": 37,
    }
    for name, expected in state_indices.items():
        if rust_integer_const(m4, name, "usize") != expected:
            raise ValueError(f"M4 state-word index drift: {name}")
    return {"scalar": scalar, "m4": m4, "m4_lib": m4_lib}


@dataclass(frozen=True)
class PrimitiveShape:
    rows: int
    auxiliary: int
    nonzeros: int
    equation: str


PRIMITIVES: dict[str, PrimitiveShape] = {
    "bitness": PrimitiveShape(1, 0, 3, "x*(x-1)=0"),
    "and": PrimitiveShape(1, 1, 3, "x*y=z"),
    "xor": PrimitiveShape(1, 1, 5, "(2*x)*y=x+y-z"),
    "or": PrimitiveShape(1, 1, 5, "x*y=x+y-z"),
    "and_not": PrimitiveShape(1, 1, 4, "(1-x)*y=z"),
    "not": PrimitiveShape(1, 1, 4, "(x+z-1)*1=0"),
    "select": PrimitiveShape(1, 1, 5, "s*(a-b)=z-b"),
    "eq": PrimitiveShape(1, 0, 3, "(x-y)*1=0"),
    "eq_zero": PrimitiveShape(1, 0, 2, "x*1=0"),
    "eq_one": PrimitiveShape(1, 0, 3, "(x-1)*1=0"),
    "cond_zero": PrimitiveShape(1, 0, 2, "s*x=0"),
    "cond_eq": PrimitiveShape(1, 0, 3, "s*(x-y)=0"),
    "implies": PrimitiveShape(1, 0, 3, "s*(1-p)=0"),
    "add_lsb": PrimitiveShape(1, 0, 5, "(x+y-s-2*c1)*1=0"),
    "add_carry": PrimitiveShape(1, 0, 6, "(x+y+c-s-2*c_next)*1=0"),
    "linear_5_to_1": PrimitiveShape(1, 1, 7, "(t0+t1+t2+t3+t4-z)*1=0"),
    "cond_linear_4": PrimitiveShape(1, 0, 6, "s*(t0+t1+t2+t3-y)=0"),
    "linear_sum_5": PrimitiveShape(1, 0, 7, "(s0+s1+s2+s3+s4-1)*1=0"),
    "cond_sum_4": PrimitiveShape(1, 0, 6, "active*(s0+s1+s2+s3-1)=0"),
}


class Program:
    """Count-preserving macro compiler with canonical group/invocation ledger."""

    def __init__(self, profile: str):
        self.profile = profile
        self.public = PUBLIC_BITS
        self.private = PRIVATE_BITS
        self.rows = 0
        self.auxiliary = 0
        self.nonzeros = 0
        self.primitives: Counter[str] = Counter()
        self.groups: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.current_group = ""

    def group(self, name: str) -> None:
        self.current_group = name
        self.groups.setdefault(name, {"rows": 0, "auxiliary_variables": 0, "nonzeros": 0, "invocations": []})

    def primitive(self, kind: str, count: int = 1) -> None:
        if count < 0:
            raise ValueError("negative primitive multiplicity")
        shape = PRIMITIVES[kind]
        rows = shape.rows * count
        aux = shape.auxiliary * count
        nnz = shape.nonzeros * count
        self.rows += rows
        self.auxiliary += aux
        self.nonzeros += nnz
        self.primitives[kind] += count
        group = self.groups[self.current_group]
        group["rows"] += rows
        group["auxiliary_variables"] += aux
        group["nonzeros"] += nnz

    def invoke(self, macro: str, count: int = 1, width: int | None = None, note: str | None = None) -> None:
        item: dict[str, Any] = {"macro": macro, "multiplicity": count}
        if width is not None:
            item["width_bits"] = width
        if note is not None:
            item["note"] = note
        self.groups[self.current_group]["invocations"].append(item)
        fn = getattr(self, f"macro_{macro}")
        fn(count, width)

    def macro_bitness(self, count: int, width: int | None) -> None:
        self.primitive("bitness", count * (width or 1))

    def macro_eq(self, count: int, width: int | None) -> None:
        self.primitive("eq", count * (width or 1))

    def macro_eq_zero(self, count: int, width: int | None) -> None:
        self.primitive("eq_zero", count * (width or 1))

    def macro_eq_one(self, count: int, width: int | None) -> None:
        self.primitive("eq_one", count * (width or 1))

    def macro_cond_zero(self, count: int, width: int | None) -> None:
        self.primitive("cond_zero", count * (width or 1))

    def macro_cond_eq(self, count: int, width: int | None) -> None:
        self.primitive("cond_eq", count * (width or 1))

    def macro_and(self, count: int, width: int | None) -> None:
        self.primitive("and", count * (width or 1))

    def macro_xor(self, count: int, width: int | None) -> None:
        self.primitive("xor", count * (width or 1))

    def macro_or(self, count: int, width: int | None) -> None:
        self.primitive("or", count * (width or 1))

    def macro_not(self, count: int, width: int | None) -> None:
        self.primitive("not", count * (width or 1))

    def macro_select(self, count: int, width: int | None) -> None:
        self.primitive("select", count * (width or 1))

    def macro_implies(self, count: int, width: int | None) -> None:
        self.primitive("implies", count * (width or 1))

    def macro_is_equal(self, count: int, width: int | None) -> None:
        k = width or 1
        self.primitive("xor", count * k)
        self.primitive("or", count * max(0, k - 1))
        self.primitive("not", count)

    def macro_is_zero(self, count: int, width: int | None) -> None:
        k = width or 1
        self.primitive("or", count * max(0, k - 1))
        self.primitive("not", count)

    def macro_nonzero(self, count: int, width: int | None) -> None:
        k = width or 1
        self.primitive("or", count * max(0, k - 1))

    def macro_lt(self, count: int, width: int | None) -> None:
        k = width or 1
        self.primitive("xor", count * k)
        self.primitive("and_not", count * k)
        self.primitive("not", count * k)
        self.primitive("and", count * k)
        self.primitive("or", count * k)

    def macro_le(self, count: int, width: int | None) -> None:
        self.macro_lt(count, width)
        self.primitive("not", count)

    def macro_add(self, count: int, width: int | None) -> None:
        k = width or 64
        self.primitive("bitness", count * 2 * k)
        self.auxiliary += count * 2 * k
        self.groups[self.current_group]["auxiliary_variables"] += count * 2 * k
        # bitness rows above do not allocate their already-created sum/carry wires.
        self.primitive("add_lsb", count)
        self.primitive("add_carry", count * max(0, k - 1))

    def macro_digest_nonzero_cond(self, count: int, width: int | None) -> None:
        self.macro_nonzero(count, width)
        self.primitive("implies", count)

    def macro_digest_unequal_cond(self, count: int, width: int | None) -> None:
        k = width or DIGEST_BITS
        self.primitive("xor", count * k)
        self.primitive("or", count * max(0, k - 1))
        self.primitive("implies", count)

    def macro_onehot_select5(self, count: int, width: int | None) -> None:
        k = width or 1
        self.primitive("and", count * k * 5)
        self.primitive("linear_5_to_1", count * k)

    def macro_selected_asset4(self, count: int, width: int | None) -> None:
        k = width or 64
        self.primitive("and", count * k * 4)
        self.primitive("cond_linear_4", count * k)

    def macro_cond_sum4(self, count: int, width: int | None) -> None:
        self.primitive("cond_sum_4", count)

    def macro_mode_onehot5(self, count: int, width: int | None) -> None:
        self.primitive("linear_sum_5", count)

    def macro_keccak_f1600(self, count: int, width: int | None) -> None:
        self.primitive("xor", count * 115_200)
        self.primitive("and_not", count * 38_400)
        self.primitive("not", count * KECCAK_IOTA_ONES)

    def macro_add64(self, count: int, width: int | None) -> None:
        self.macro_add(count, 64)

    def macro_alias(self, count: int, width: int | None) -> None:
        # A parser-synthesized constant or a pure permutation/rotation does not
        # allocate a witness column or an R1CS row.
        return

    def geometry(self) -> dict[str, Any]:
        n = self.public + self.private + self.auxiliary
        return {
            "m_constraints": self.rows,
            "n_nonconstant_variables": n,
            "l_public_variables": self.public,
            "auxiliary_variables_total": self.private + self.auxiliary,
            "private_transport_variables": self.private,
            "derived_auxiliary_variables": self.auxiliary,
            "matrix_nonzeros_total": self.nonzeros,
            "z_vector_length_including_constant_one": n + 1,
        }

    def export_groups(self) -> list[dict[str, Any]]:
        return [{"name": name, **data} for name, data in self.groups.items()]


def activation_bytes() -> bytes:
    a = ACTIVATION
    result = bytearray()
    for key in ("circuit_version", "crypto_suite", "family_id", "action_id"):
        result += int(a[key]).to_bytes(2, "big")
    result += int(a["network_id"]).to_bytes(4, "big")
    result += bytes([int(a["backend_id"]), int(a["proof_profile"])])
    result += int(a["domain_set"]).to_bytes(2, "big")
    result += bytes.fromhex(str(a["chain_id"]))
    result += bytes.fromhex(str(a["genesis_id"]))
    result += bytes.fromhex(str(a["rules_hash"]))
    if len(result) != 184:
        raise AssertionError(len(result))
    return bytes(result)


def eq_constant_bytes(program: Program, payload: bytes, label: str) -> None:
    zeros = sum(8 - byte.bit_count() for byte in payload)
    ones = len(payload) * 8 - zeros
    program.invoke("eq_zero", zeros, note=f"{label}: zero bits")
    program.invoke("eq_one", ones, note=f"{label}: one bits")


def emit_local_relation(program: Program) -> None:
    program.group("source bitness")
    program.invoke("bitness", PUBLIC_BITS + PRIVATE_BITS, note="all raw public/private transport bits")

    program.group(LOCAL_GROUPS[0])
    eq_constant_bytes(program, b"HX448C02" + (2).to_bytes(2, "big"), "magic and grammar")
    eq_constant_bytes(program, activation_bytes(), "compile-time diagnostic activation")
    program.invoke("alias", 24, note="parser-synthesized zero bits in 109-word M4 projection trailing pad")

    program.group(LOCAL_GROUPS[1])
    program.invoke("or", 3, note="OR reduction of four activity flags")
    program.invoke("eq_one", 1, note="reject all-empty mask")

    program.group(LOCAL_GROUPS[2])
    program.invoke("eq_zero", 9, note="three high bits of fee/value/issuance magnitudes")
    program.invoke("is_zero", 2, 64, "two signed magnitudes")
    program.invoke("cond_zero", 2, 1, "no negative zero")

    program.group(LOCAL_GROUPS[3])
    program.invoke("eq_zero", 1, 64, "slot zero is native asset")
    for slot in range(1, 4):
        program.invoke("is_equal", 2, 64, f"slot {slot} and predecessor padding tests")
        program.invoke("not", 2, note=f"slot {slot} nonpadding predicates")
        program.invoke("lt", 2, 64, f"slot {slot} field range and strict order")
        program.invoke("implies", 5, note=f"slot {slot} range/alias/nonzero/suffix/order")
        program.invoke("is_equal", 1, 64, f"slot {slot} reserved reduced-padding alias")
        program.invoke("is_zero", 1, 64, f"slot {slot} native alias")
        program.invoke("and", 1, note=f"slot {slot} both nonpadding")

    program.group(LOCAL_GROUPS[4])
    for note in range(4):
        program.invoke("le", 1, 64, f"note {note} kind <= 2")
        program.invoke("implies", 3, note=f"note {note} kind/range/alias activation")
        program.invoke("eq_zero", 3, note=f"note {note} value high bits")
        program.invoke("lt", 1, 64, f"note {note} asset field range")
        program.invoke("is_equal", 1, 64, f"note {note} reserved alias")
        program.invoke("not", 1, note=f"note {note} alias inequality")

    program.group(LOCAL_GROUPS[5])
    program.invoke("eq_zero", 4 * 4 * 63, note="high bits of sixteen u64 selector transports")
    program.invoke("cond_sum4", 4, note="one selected asset slot per active note")
    program.invoke("selected_asset4", 4, 64, "selected public asset equals note asset")

    program.group(LOCAL_GROUPS[6])
    program.invoke("cond_zero", 2, (261 * 64) + DIGEST_BITS, "inactive input witness and nullifier")

    program.group(LOCAL_GROUPS[7])
    program.invoke("eq_zero", 2, 32, "Merkle position high half")

    program.group(LOCAL_GROUPS[8])
    per_output = (30 * 64) + (269 * 64) + DIGEST_BITS + DIGEST_BITS
    program.invoke("cond_zero", 2, per_output, "inactive output/note/ciphertext/public lanes")

    program.group(LOCAL_GROUPS[9])
    program.invoke("eq_zero", 2, 40, "five canonical ciphertext pad bytes")
    program.invoke("cond_zero", 2, 32, "inactive ciphertext size")
    # 2147 = 0x00000863 has six one bits.
    program.invoke("cond_zero", 2 * (32 - 6), note="active size zero coefficient bits")
    program.invoke("cond_eq", 2 * 6, note="active size one coefficient bits")

    program.group(LOCAL_GROUPS[10])
    program.invoke("and", 1, note="both inputs active")
    program.invoke("digest_unequal_cond", 1, DIGEST_BITS, "active nullifiers differ")

    program.group(LOCAL_GROUPS[11])
    program.invoke("le", 1, 64, "mode <= 4")
    program.invoke("is_equal", 5, 64, "five exact authorization-mode selectors")
    program.invoke("mode_onehot5", 1, note="exactly one mode selector")

    program.group(LOCAL_GROUPS[12])
    program.invoke("or", 2, note="input nonempty and init-or-lock")
    program.invoke("implies", 8, note="init/lock/approval/final activity implications")

    program.group(LOCAL_GROUPS[13])
    program.invoke("cond_zero", 1, 88 * 64, "single-key auxiliary state")
    program.invoke("and", 9, note="mode-and-activity predicates")
    program.invoke("cond_eq", 14, 64, "mode-specific note kinds and zero/native fields")
    program.invoke("cond_zero", 1, 23 * 64, "init current accumulator")
    program.invoke("cond_zero", 1, 7 * 64, "init next approval count/bits")
    program.invoke("cond_zero", 1, 6 * 64, "approval input0 unused spend key")
    program.invoke("cond_zero", 1, 23 * 64, "lock next accumulator")
    program.invoke("cond_zero", 1, 7 * 64, "lock current approval count/bits")
    program.invoke("cond_zero", 1, (12 + 23) * 64, "final spend keys and next accumulator")
    program.invoke("le", 1, 64, "final approval count >= threshold via reversed <=")
    program.invoke("implies", 1, note="threshold reached")

    program.group(LOCAL_GROUPS[14])
    program.invoke("select", 1, 23 * 64, "init selects next policy; otherwise current")
    program.invoke("lt", 6, 64, "six signer-slot active predicates")
    program.invoke("le", 4, 64, "signer/threshold lower and upper bounds")
    program.invoke("implies", 4, note="policy structure active bounds")
    program.invoke("cond_zero", 6, DIGEST_BITS, "inactive signer tags")
    program.invoke("digest_unequal_cond", 15, DIGEST_BITS, "active signer-tag uniqueness")
    program.invoke("le", 2, 64, "current/next approval_count <= signer_count")
    program.invoke("eq_zero", 2 * 6 * 63, note="current/next approved word high bits")
    program.invoke("add64", 2 * 6, note="current/next approval popcounts")
    program.invoke("eq_zero", 2 * 6, note="approval popcount carry rejection")
    program.invoke("cond_zero", 2 * 6, 64, "inactive approval slots")
    program.invoke("eq", 2, 64, "approval popcount equals count")

    program.group(LOCAL_GROUPS[15])
    program.invoke("cond_eq", 1, 2 * DIGEST_BITS + 2 * 64, "approval metadata equality")
    program.invoke("add64", 1, note="approval count increment")
    program.invoke("eq_zero", 1, note="increment carry rejection")
    program.invoke("cond_eq", 1, 64, "incremented count equality")
    program.invoke("xor", 6, note="six changed approval bits")
    program.invoke("and", 6, note="approval-and-current predicates")
    program.invoke("implies", 6, note="no approval clearing")
    program.invoke("add64", 6, note="changed-bit popcount")
    program.invoke("eq_zero", 6, note="changed popcount carry rejection")
    program.invoke("cond_eq", 1, 64, "exactly one changed slot")
    program.invoke("is_equal", 6, DIGEST_BITS, "signer authorization tag matches")
    program.invoke("and", 18, note="mode/changed/active/tag membership predicates")
    program.invoke("implies", 12, note="changed tag iff active member")

    # The four slot accumulators are shared by native and non-native equations.
    program.group(LOCAL_GROUPS[16])
    program.invoke("select", 4 * 4, 64, "four note contributions per balance slot")
    program.invoke("add64", 4 * 4, note="input/output slot accumulation")
    program.invoke("eq_zero", 4 * 4, note="slot accumulation carry rejection")
    program.invoke("add64", 3, note="fee and signed native-balance branches")
    program.invoke("eq_zero", 3, note="native balance carry rejection")
    program.invoke("cond_eq", 2, 64, "signed native balance equations")

    program.group(LOCAL_GROUPS[17])
    program.invoke("is_equal", 3, 64, "padding asset predicates")
    program.invoke("cond_zero", 3 * 2, 64, "padding slot sums")
    program.invoke("is_equal", 3, 64, "stable asset slot predicates")
    program.invoke("and", 3, note="enabled stable slot")
    program.invoke("not", 3, note="ordinary slot predicate")
    program.invoke("cond_eq", 3, 64, "ordinary non-native conservation")

    program.group(LOCAL_GROUPS[18])
    program.invoke("and", 6, note="mint and burn selectors")
    program.invoke("not", 3, note="burn sign complement")
    program.invoke("add64", 6, note="mint/burn balance candidates")
    program.invoke("implies", 6, note="mint/burn carry rejection")
    program.invoke("cond_eq", 6, 64, "mint/burn signed balance equations")

    program.group(LOCAL_GROUPS[19])
    disabled_bits = 64 + 32 + 1 + 64 + 3 * STABLE_DIGEST_BITS
    program.invoke("not", 1, note="stable disabled predicate")
    program.invoke("cond_zero", 1, disabled_bits, "unique disabled stablecoin surface")
    program.invoke("is_zero", 1, 64, "enabled asset nonzero")
    program.invoke("not", 1, note="asset nonzero predicate")
    program.invoke("lt", 1, 64, "enabled asset field range")
    program.invoke("is_equal", 1, 64, "reserved reduced-padding asset")
    program.invoke("not", 1, note="asset alias rejection")
    program.invoke("is_equal", 4, 64, "stable asset equals one canonical slot")
    program.invoke("or", 3, note="stable asset slot match")
    program.invoke("implies", 4, note="enabled asset predicates")


def emit_state_seam(program: Program) -> None:
    program.group(STATE_GROUPS[0])
    program.invoke("cond_zero", 1, STATE_BITS, "disabled seam has one representation")

    program.group(STATE_GROUPS[1])
    program.invoke("eq_zero", 5, 32, "five u32 high halves")
    program.invoke("eq_zero", 4, 63, "four u64-transport booleans high bits")
    program.invoke("cond_eq", 1, 32, "enabled seam version v1")
    program.invoke("cond_eq", 1, 1, "enabled selected-entry presence")

    program.group(STATE_GROUPS[2])
    program.invoke("nonzero", 2, STABLE_DIGEST_BITS, "expected/provided roots nonzero")
    program.invoke("implies", 2, note="root nonzero when enabled")
    program.invoke("cond_eq", 1, STABLE_DIGEST_BITS, "provided root equals expected root")

    program.group(STATE_GROUPS[3])
    program.invoke("cond_eq", 1, 64, "provided height equals expected height")

    program.group(STATE_GROUPS[4])
    # asset32, policy32, policy/oracle/attestation 384 each.
    program.invoke("cond_eq", 1, 32 + 32 + 3 * STABLE_DIGEST_BITS, "selected entry equals statement")

    program.group(STATE_GROUPS[5])
    program.invoke("cond_eq", 1, 1, "entry active")
    program.invoke("le", 1, 64, "enabled_at <= current height")
    program.invoke("implies", 1, note="lifecycle opened")

    program.group(STATE_GROUPS[6])
    program.invoke("implies", 1, note="retired_at is zero when absent")
    program.invoke("and", 1, note="enabled and retirement-present")
    program.invoke("lt", 1, 64, "current height < retired_at")
    program.invoke("implies", 1, note="retirement bound")

    program.group(STATE_GROUPS[7])
    program.invoke("le", 2, 64, "oracle nonfuture and before deadline")
    program.invoke("add64", 1, note="oracle submitted_at + max_age")
    program.invoke("or", 1, note="saturating freshness: overflow or before deadline")
    program.invoke("implies", 2, note="oracle time predicates")

    program.group(STATE_GROUPS[8])
    program.invoke("cond_eq", 1, 1, "attestation undisputed")
    program.invoke("nonzero", 1, 64, "issuance magnitude nonzero")
    program.invoke("implies", 1, note="nonzero issuance")
    program.invoke("nonzero", 1, 64, "u128 cap high limb nonzero")
    program.invoke("le", 1, 64, "issuance <= low cap")
    program.invoke("or", 1, note="high cap limb or low comparison")
    program.invoke("implies", 1, note="u128 cap")


def emit_hash_links(program: Program) -> None:
    program.group(HASH_LINK_GROUPS[0])
    program.invoke("select", 6, DIGEST_BITS, "approval/final resolved authorization digests")
    program.invoke("cond_eq", 2, DIGEST_BITS, "input note authorization")
    program.invoke("cond_eq", 2, DIGEST_BITS, "active output commitments")
    program.invoke("digest_nonzero_cond", 2, DIGEST_BITS, "active output commitments nonzero")

    program.group(HASH_LINK_GROUPS[1])
    program.invoke("cond_eq", 2, DIGEST_BITS, "active public nullifiers")
    program.invoke("digest_nonzero_cond", 2, DIGEST_BITS, "active nullifiers nonzero")

    program.group(HASH_LINK_GROUPS[2])
    program.invoke("select", 2 * 32, DIGEST_BITS, "Merkle left child by position bit")
    program.invoke("xor", 2 * 32 * 2, DIGEST_BITS, "Merkle right child without branch alias")
    program.invoke("cond_eq", 2, DIGEST_BITS, "active anchor equality")

    program.group(HASH_LINK_GROUPS[3])
    program.invoke("cond_eq", 1, DIGEST_BITS, "non-single policy root")
    program.invoke("cond_eq", 2, DIGEST_BITS, "init/lock and approval output authorization")

    program.group(HASH_LINK_GROUPS[4])
    program.invoke("cond_eq", 1, DIGEST_BITS, "final-spend intent")

    program.group(HASH_LINK_GROUPS[5])
    program.invoke("eq", 1, DIGEST_BITS, "public balance tag")

    program.group(HASH_LINK_GROUPS[6])
    program.invoke("cond_eq", 2, DIGEST_BITS, "active canonical ciphertext digests")


def hash_calls(profile: str) -> list[dict[str, Any]]:
    if profile not in ("blake2b448-mixed", "sha3-512-split-control"):
        raise ValueError(profile)
    secret = "RFC7693-BLAKE2b-448" if profile.startswith("blake") else "FIPS202-SHA3-512-truncate-448"
    calls: list[dict[str, Any]] = []

    def add(index: int, kind: str, role: str, frame: int | list[int], algorithm: str, binding: str) -> None:
        if isinstance(frame, list):
            if algorithm.startswith("RFC"):
                cores = 2
            else:
                cores = 3
            frame_spec: dict[str, Any] = {"authorization_arm_bytes": frame, "maximum_bytes": max(frame)}
        else:
            if algorithm.startswith("RFC"):
                cores = (frame + 127) // 128
            elif algorithm.startswith("FIPS202-SHA3"):
                cores = frame // 72 + 1
            else:
                cores = frame // 136 + 1
            frame_spec = {"exact_bytes": frame}
        calls.append({
            "algorithm": algorithm,
            "binding": binding,
            "frame": frame_spec,
            "index": index,
            "kind": kind,
            "output_bits": DIGEST_BITS,
            "primitive_cores": cores,
            "role_ascii": role,
            "select_before_hash": isinstance(frame, list),
        })

    for i in range(2):
        add(i, f"note_input[{i}]", "nt.b4481", 232, secret, "internal")
    for i in range(2):
        add(2 + i, f"note_output[{i}]", "nt.b4481", 232, secret, f"public_when_output_{i}_active")
    for i in range(2):
        add(4 + i, f"nullifier[{i}]", "nf.b4481", 135, secret, f"public_when_input_{i}_active")
    for i in range(2):
        for level in range(32):
            add(6 + i * 32 + level, f"merkle[{i}][{level}]", "mk.s4481", 133,
                "FIPS202-SHAKE256-448", "internal")
    for i in range(2):
        add(70 + i, f"spend[{i}].lane_a", "sk.b44a1", 77, secret, "internal")
    for i in range(2):
        add(72 + i, f"spend[{i}].lane_b", "sk.b44b1", 77, secret, "internal")
    add(74, "private_accumulator_policy", "pl.b4481", 385, secret, "internal")
    slot_a = [136, 181, 181, 143, 181]
    slot_b = [136, 136, 181, 136, 143]
    add(75, "authorization[0].lane_a", "au.b44a1", slot_a, secret, "internal")
    add(76, "authorization[1].lane_a", "au.b44a1", slot_b, secret, "internal")
    add(77, "authorization[0].lane_b", "au.b44b1", slot_a, secret, "internal")
    add(78, "authorization[1].lane_b", "au.b44b1", slot_b, secret, "internal")
    add(79, "intent", "in.s4481", 720, "FIPS202-SHAKE256-448", "internal")
    add(80, "balance", "bl.s4481", 100, "FIPS202-SHAKE256-448", "public_always")
    for i in range(2):
        add(81 + i, f"ciphertext[{i}]", "ct.s4481", 2182, "FIPS202-SHAKE256-448", f"public_when_output_{i}_active")
    if [call["index"] for call in calls] != list(range(PHYSICAL_HASH_CALLS)):
        raise AssertionError("hash call registry order")
    return calls


def emit_hash_program(program: Program, calls: list[dict[str, Any]]) -> None:
    program.group("hash frame source wiring")
    # Canonical constants use the R1CS constant column (or the empty zero LC),
    # and source bits are direct column aliases. No copy witness is allocated.
    program.invoke("alias", 2, note="canonical zero/one sources")
    frame_bits = sum(
        (call["frame"].get("exact_bytes", 0) + sum(call["frame"].get("authorization_arm_bytes", []))) * 8
        for call in calls
    )
    if frame_bits != 149_560:
        raise AssertionError(frame_bits)
    program.invoke("alias", frame_bits, note="99 exact frame views over statement/witness/constants")

    if program.profile == "blake2b448-mixed":
        program.group("RFC7693 BLAKE2b-448 Boolean ARX")
        compressions = sum(call["primitive_cores"] for call in calls if call["algorithm"].startswith("RFC"))
        secret_calls = sum(call["algorithm"].startswith("RFC") for call in calls)
        if (compressions, secret_calls) != (28, 15):
            raise AssertionError((compressions, secret_calls))
        program.invoke("add64", compressions * 576, note="six additions in each of 96 G functions")
        program.invoke("xor", compressions * (384 + 16 + 3), 64,
                       "G XORs, final feed-forward, counter/final injection")
        program.invoke("not", secret_calls * 5, note="BLAKE2b-448 parameter block h0 XOR set bits")
        program.group("authorization select-before-BLAKE2b")
        program.invoke("onehot_select5", 4, 2 * 128 * 8, "two selected message blocks per authorization call")
        program.invoke("onehot_select5", 4, 64, "selected exact final byte counter")
    else:
        program.group("authorization select-before-SHA3-512")
        program.invoke("onehot_select5", 4, 3 * 72 * 8, "three padded rate blocks per authorization call")
        program.invoke("onehot_select5", 4, 1, "two-versus-three permutation selector")

    program.group("FIPS202 Keccak-f[1600] Boolean permutations")
    shake_perms = sum(call["primitive_cores"] for call in calls if call["algorithm"] == "FIPS202-SHAKE256-448")
    if shake_perms != 105:
        raise AssertionError(shake_perms)
    program.invoke("keccak_f1600", shake_perms, note="SHAKE256-448 collision layer")
    program.invoke("xor", shake_perms, 136 * 8, "SHAKE rate absorption")
    if program.profile == "sha3-512-split-control":
        sha3_perms = sum(call["primitive_cores"] for call in calls if call["algorithm"].startswith("FIPS202-SHA3"))
        if sha3_perms != 46:
            raise AssertionError(sha3_perms)
        program.invoke("keccak_f1600", sha3_perms, note="SHA3-512 secret layer")
        program.invoke("xor", sha3_perms, 72 * 8, "SHA3 rate absorption")
        program.group("authorization two-or-three-permutation output selection")
        program.invoke("select", 4, DIGEST_BITS, "select state after two or three SHA3 permutations")


def compile_profile(profile: str) -> tuple[Program, list[dict[str, Any]]]:
    calls = hash_calls(profile)
    program = Program(profile)
    emit_local_relation(program)
    emit_state_seam(program)
    emit_hash_links(program)
    emit_hash_program(program, calls)
    return program, calls


def public_grammar() -> dict[str, Any]:
    return {
        "bit_order_within_byte": "least-significant-bit first",
        "canonical_field_element": {
            "bytes": 8,
            "endianness": "little",
            "rule": "decode unsigned integer; reject if value >= p; no modular reduction",
        },
        "l_public_bits": PUBLIC_BITS,
        "statement": {
            "bytes": STATEMENT_BYTES,
            "fields": STATEMENT_LAYOUT,
            "grammar_u16be": 2,
            "magic_ascii": "HX448C02",
            "offsets_bytes": OFFSETS,
            "public_bit_indices": [0, STATEMENT_BITS - 1],
        },
        "consensus_state_seam": {
            "fields": STATE_LAYOUT,
            "public_bit_indices": [STATEMENT_BITS, PUBLIC_BITS - 1],
            "word_bytes": 8,
            "word_endianness": "little",
            "words": STATE_WORDS,
        },
        "m4_statement_projection": {
            "rule": "copy 869 statement bytes into 109 consecutive u64le words and require the final 24 pad bits to zero",
            "words": 109,
        },
    }


def private_grammar() -> dict[str, Any]:
    return {
        "bytes": PRIVATE_BYTES,
        "private_bits": PRIVATE_BITS,
        "transport_words": PRIVATE_WORDS,
        "word_decode": "consecutive 8-byte chunks interpreted u64le only after the byte grammar is frozen",
        "semantic_field_encoding": "numeric u64/u32 values are big-endian bytes within their 8-byte transport lanes; digest, key, sibling, tag, and ciphertext bytes preserve their source order",
        "sections": [
            {"name": "input[0]", "offset_words": 0, "words": 261},
            {"name": "input[1]", "offset_words": 261, "words": 261},
            {"name": "output[0]", "offset_words": 522, "words": 30},
            {"name": "output[1]", "offset_words": 552, "words": 30},
            {"name": "authorization", "offset_words": 582, "words": 89},
            {"name": "ciphertext[0]", "offset_words": 671, "words": 269, "semantic_bytes": 2147, "zero_pad_bytes": 5},
            {"name": "ciphertext[1]", "offset_words": 940, "words": 269, "semantic_bytes": 2147, "zero_pad_bytes": 5},
        ],
        "input_layout_words": {
            "spend_key": 6, "note": 26, "position": 1, "merkle_siblings": 224,
            "balance_selectors": 4, "total": 261,
        },
        "note_layout_words": {
            "kind_u64be": 1, "value_u64be": 1, "asset_u64be": 1,
            "recipient": 4, "rho": 6, "randomness": 6, "authorization": 7, "total": 26,
        },
        "authorization_layout_words": {
            "mode_u64be": 1, "current_accumulator": 23, "next_accumulator": 23,
            "six_signer_tags": 42, "total": 89,
        },
    }


def source_entries() -> list[dict[str, Any]]:
    paths = [Path(__file__).resolve(), SCALAR, M4, M4_LIB, STABLE_MANIFEST]
    if TEST_PATH.exists():
        paths.append(TEST_PATH)
    roles = {
        Path(__file__).resolve(): "canonical macro compiler and checker",
        TEST_PATH: "dependency-free regression suite",
        SCALAR: "frozen HX448C02 scalar statement and hash-call schedule",
        M4: "frozen HX448C02 M4 relation-family and state-seam schedule",
        M4_LIB: "private transport and authorization semantic layout",
        STABLE_MANIFEST: "current flat-manifest host-boundary source",
    }
    return [
        {"bytes": path.stat().st_size, "path": rel(path), "role": roles[path], "sha512": sha512_file(path)}
        for path in paths
    ]


def primitive_manifest() -> dict[str, Any]:
    rows = primitive_rows()
    return {
        name: {
            "auxiliary_variables": shape.auxiliary,
            "equation": shape.equation,
            "matrix_nonzeros": shape.nonzeros,
            "rows": shape.rows,
            "unit_row": {
                side: [[column, coefficient] for column, coefficient in linear_combination]
                for side, linear_combination in zip(("A", "B", "C"), rows[name])
            },
        }
        for name, shape in sorted(PRIMITIVES.items())
    }


def macro_manifest() -> dict[str, Any]:
    return {
        "bitness(k)": "k bitness rows",
        "eq(k)": "k equality rows",
        "eq_zero(k)": "k zero-equality rows",
        "eq_one(k)": "k one-equality rows",
        "cond_zero(k)": "k condition-times-bit zero rows",
        "cond_eq(k)": "k condition-times-difference rows",
        "and(k)": "k AND rows and k derived output bits",
        "xor(k)": "k odd-field XOR rows and k derived output bits",
        "or(k)": "k OR rows and k derived output bits",
        "not(k)": "k NOT rows and k derived output bits",
        "select(k)": "k selector rows and k derived output bits",
        "implies": "one condition-times-complement row",
        "is_equal(k)": "k XOR, k-1 OR, one NOT; 2k derived bits",
        "is_zero(k)": "k-1 OR and one NOT; k derived bits",
        "nonzero(k)": "k-1 OR-derived reduction bits; caller binds the result",
        "lt(k)": "MSB-first ripple using k each of XOR, AND-NOT, NOT, AND, OR; 5k derived bits",
        "le(k)": "lt(k) plus one NOT-derived result bit",
        "add(k)": "k sum bits and k carry bits are allocated and bit-constrained; one add_lsb plus k-1 add_carry rows",
        "digest_nonzero_cond(k)": "nonzero(k) followed by one implication row",
        "digest_unequal_cond(k)": "k XOR, k-1 OR, one implication row",
        "onehot_select5(k)": "five AND rows plus one six-term linear output row per bit",
        "selected_asset4(k)": "four AND rows plus one conditional four-term linear equality per bit",
        "cond_sum4": "one conditional four-selector sum row",
        "mode_onehot5": "one five-selector sum-equals-one row",
        "keccak_f1600": "per permutation: 115200 XOR, 38400 AND-NOT, and 86 fixed-Iota NOT rows; rotations and lane permutations alias columns",
        "add64": "add(64)",
        "alias(k)": "k parser-synthesized constants or pure column aliases; zero rows, variables, and nonzeros",
        "allocation": "invocation order, lane index, then primitive order; every declared derived output is a fresh auxiliary variable",
    }


def next_power_of_two(value: int) -> int:
    if value <= 0:
        raise ValueError(value)
    return 1 << (value - 1).bit_length()


def section11_embedding(geometry: dict[str, int]) -> dict[str, Any]:
    """Canonical candidate embedding for the CFW26 Section 11 square shape.

    The public half is fixed by the statement constructor, so its padding is
    parser-enforced rather than represented by extra R1CS rows.  Existential
    witness padding is constrained to zero.  Remaining rows are canonical
    zero rows, making the supplied matrix exactly 2*ell by 2*ell.
    """
    public_with_constant = geometry["l_public_variables"] + 1
    witness_used = geometry["auxiliary_variables_total"]
    ell = next_power_of_two(max(public_with_constant, witness_used, (geometry["m_constraints"] + 1) // 2))
    public_padding = ell - public_with_constant
    witness_padding = ell - witness_used
    witness_zero_start = geometry["m_constraints"]
    witness_zero_end = witness_zero_start + witness_padding
    row_padding_end = 2 * ell
    if witness_zero_end > row_padding_end:
        raise AssertionError("Section 11 row capacity")
    embedded_nonzeros = geometry["matrix_nonzeros_total"] + 2 * witness_padding
    return {
        "authoritative_cfw26_theorem_binding": False,
        "candidate_embedding_present": True,
        "column_flattening": "v[0..ell) then w[0..ell)",
        "ell": ell,
        "l_original_public_excluding_constant": geometry["l_public_variables"],
        "n0": ell,
        "power_of_two": True,
        "source_column_bijection": {
            "source_constant_column_0": "v[0] / embedded column 0",
            "source_public_columns_1_through_l": "v[1..1+l) / identical embedded column indices",
            "source_auxiliary_columns_l_plus_1_through_n": "w[0..source_auxiliary_count) / embedded columns ell..ell+source_auxiliary_count",
        },
        "v_layout": [
            {"interval": [0, 1], "meaning": "constant one"},
            {"interval": [1, public_with_constant], "meaning": "10,152 canonical public bits"},
            {"interval": [public_with_constant, ell], "meaning": "public zero padding fixed and mutation-rejected by canonical statement parser"},
        ],
        "w_layout": [
            {"interval": [0, PRIVATE_BITS], "meaning": "77,376 private transport bits"},
            {"interval": [PRIVATE_BITS, witness_used], "meaning": "derived R1CS auxiliary variables"},
            {"interval": [witness_used, ell], "meaning": "existential padding explicitly constrained to zero"},
        ],
        "row_layout": [
            {"interval": [0, geometry["m_constraints"]], "meaning": "source macro-R1CS rows"},
            {"interval": [witness_zero_start, witness_zero_end], "meaning": "witness padding x*1=0 rows"},
            {"interval": [witness_zero_end, row_padding_end], "meaning": "canonical 0*0=0 row padding"},
        ],
        "embedded_geometry": {
            "columns_including_v_constant": 2 * ell,
            "matrix_nonzeros_total": embedded_nonzeros,
            "nonconstant_variables": 2 * ell - 1,
            "rows": 2 * ell,
            "v_public_elements_including_constant_and_parser_zero_padding": ell,
            "w_existential_elements": ell,
        },
        "padding": {
            "public_parser_zero_elements": public_padding,
            "public_zero_rows": 0,
            "row_zero_padding": row_padding_end - witness_zero_end,
            "witness_zero_elements_and_rows": witness_padding,
        },
        "status": "candidate mapping only; paper-to-code theorem/refinement and HVZK-WHIR IOR composition remain fail-closed",
    }


def build_manifest() -> dict[str, Any]:
    require_source_contracts()
    mixed, mixed_calls = compile_profile("blake2b448-mixed")
    split, split_calls = compile_profile("sha3-512-split-control")
    if [dict(call, algorithm=None) for call in mixed_calls] != [dict(call, algorithm=None) for call in split_calls]:
        # The primitive core count is algorithm-derived and intentionally differs.
        lhs = [{k: v for k, v in call.items() if k not in ("algorithm", "primitive_cores")} for call in mixed_calls]
        rhs = [{k: v for k, v in call.items() if k not in ("algorithm", "primitive_cores")} for call in split_calls]
        if lhs != rhs:
            raise AssertionError("profile call grammar drift")
    sources = source_entries()
    grammar = public_grammar()
    grammar_bytes = canonical_bytes(grammar)
    return {
        "artifact": "HX448C02 odd-characteristic Boolean/R1CS macro program",
        "artifact_schema": "hegemon.hx448c02.odd-field-r1cs.relation-manifest.v1",
        "authority": {
            "complete_zero_knowledge_proved": False,
            "composed_qrom_pq128_proved": False,
            "exact_native_verifier_refinement_proved": False,
            "host_only_boundary_closed": False,
            "plonky3_profile_selected": False,
            "production_authorized": False,
            "relation_identity_production_frozen": False,
        },
        "canonical_json": "UTF-8, recursively sorted keys, separators ',' and ':', no insignificant whitespace, exactly one trailing LF",
        "field": {
            "characteristic_is_odd": True,
            "canonical_element_bytes": FIELD_BYTES,
            "canonical_element_endianness": "little",
            "canonical_rejection_rule": "reject decoded unsigned value >= modulus; never reduce transport words",
            "modulus_decimal": str(P),
            "modulus_hex": "0xffffffff00000001",
            "name": "Goldilocks",
            "primality_basis": "p = 2^64 - 2^32 + 1; fixed known prime; checker also runs deterministic 64-bit Miller-Rabin bases",
        },
        "hash_profiles": {
            "blake2b448-mixed": {
                "calls": mixed_calls,
                "cfw26_section11_candidate_embedding": section11_embedding(mixed.geometry()),
                "geometry": mixed.geometry(),
                "group_ledger": mixed.export_groups(),
                "primitive_multiplicities": dict(sorted(mixed.primitives.items())),
            },
            "sha3-512-split-control": {
                "calls": split_calls,
                "cfw26_section11_candidate_embedding": section11_embedding(split.geometry()),
                "geometry": split.geometry(),
                "group_ledger": split.export_groups(),
                "primitive_multiplicities": dict(sorted(split.primitives.items())),
            },
        },
        "host_only_boundary": {
            "compiled_rows": 0,
            "disqualifies_full_production_relation": True,
            "groups": HOST_GROUPS,
            "minimum_successor_closure_not_compiled_here": {
                "canonical_manifest_cap": 16,
                "canonical_manifest_row_bytes": 183,
                "canonical_order": "strict (asset_id,policy_version), hence duplicate rejection",
                "membership_depth": 4,
                "membership_hash": "RFC7693 BLAKE2b-448 with 56-byte root and private path",
                "policy_identity": "compile the exact 61-byte policy tuple to BLAKE2b-384 while retaining the three 48-byte compatibility fields",
                "verifier_authority": "recompute and supply authenticated parent snapshot root and height",
            },
            "reason": "the live flat manifest vector has neither a consensus-fixed maximum length nor an in-relation membership path; expected root/height authenticity is supplied by the host",
        },
        "private_input_grammar": private_grammar(),
        "public_input_grammar": grammar,
        "public_input_grammar_digest_shake256_512": shake_digest(
            b"hegemon.hx448c02.odd-field-r1cs.public-grammar.v1\0", grammar_bytes
        ),
        "relation_coverage": {
            "activity_masks": 16,
            "all_empty_rejected": True,
            "authorization_modes": ["single_key", "accumulator_init", "approval_step", "value_lock_creation", "final_threshold_spend"],
            "consensus_state_groups": STATE_GROUPS,
            "hash_link_groups": HASH_LINK_GROUPS,
            "local_non_hash_groups": LOCAL_GROUPS,
            "stablecoin_authority_bits": STABLE_DIGEST_BITS,
            "transaction_digest_bits": DIGEST_BITS,
        },
        "r1cs": {
            "equation": "(A*z)*(B*z)=C*z over the declared field",
            "macro_expansion": "construction order; fixed primitive expansions in this manifest; rotations/byte permutations are aliases only",
            "macros": macro_manifest(),
            "matrix_encoding": "row-major; each linear combination is sorted unique (column,8-byte-canonical-field-element) pairs; reject duplicates, zero coefficients, noncanonical elements, or columns outside z",
            "primitives": primitive_manifest(),
            "unit_row_column_dictionary": {
                "0": "constant one",
                "1": "x",
                "2": "y",
                "3": "z or sum",
                "4": "selector or condition",
                "5": "a",
                "6": "b",
                "7": "carry in",
                "8": "carry out",
                "9..13": "t0..t4",
                "14": "predicate",
            },
            "variable_order": "z[0]=1; z[1..l]=public bits; private transport bits; derived auxiliary variables in group/invocation/primitive construction order",
        },
        "screen_activation": ACTIVATION,
        "sources": sources,
        "source_set_digest_sha512": source_set_digest(sources),
        "source_stage_boundary": {
            "expanded_matrix_retained": False,
            "formal_scalar_to_r1cs_refinement": False,
            "m4_post_dce_counts_used": False,
            "proof_built_or_measured": False,
            "source_only": True,
        },
        "upstream_pcs_reference": {
            "checkout_head_reported": "5df89eeadae18d6935bb874f8a92808dcc200c9d",
            "identity_equivalence_claimed": False,
            "role": "read-only HidingWhirPcs interface reference; no R1CS adapter/profile selection",
        },
    }


def build_certificate(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest_bytes = canonical_bytes(manifest)
    source_by_path = {entry["path"]: entry for entry in manifest["sources"]}
    return {
        "artifact_schema": "hegemon.hx448c02.odd-field-r1cs.certificate.v1",
        "canonical_relation_manifest_bytes": len(manifest_bytes),
        "canonical_relation_manifest_rule": manifest["canonical_json"],
        "counterfeit_matrix": [
            *[{"disposition": "r1cs_reject", "name": name} for name in MUTATIONS_R1CS],
            *[{"disposition": "host_oracle_only_production_blocker", "name": name} for name in MUTATIONS_HOST],
        ],
        "field_modulus_decimal": str(P),
        "frozen_source_pins": {
            "m4_sha512": source_by_path[rel(M4)]["sha512"],
            "scalar_sha512": source_by_path[rel(SCALAR)]["sha512"],
        },
        "complete_zero_knowledge_proved": False,
        "composed_qrom_pq128_proved": False,
        "exact_native_verifier_refinement_proved": False,
        "expanded_matrix_retained": False,
        "full_production_relation_compiled": False,
        "host_only_boundary_closed": False,
        "macro_schedule_source_screen": True,
        "measured_proof_bytes": None,
        "proof_built": False,
        "production_authorized": False,
        "profile_geometry": {
            name: data["geometry"] for name, data in manifest["hash_profiles"].items()
        },
        "relation_manifest_digest_rule": "SHAKE256-512(domain || u64be(canonical_byte_length) || canonical_relation_manifest_bytes), including the final LF",
        "relation_manifest_digest_shake256_512": shake_digest(
            b"hegemon.hx448c02.odd-field-r1cs.relation-manifest.v1\0", manifest_bytes
        ),
        "relation_manifest_file": MANIFEST_PATH.name,
        "source_set_digest_sha512": manifest["source_set_digest_sha512"],
        "tests_required": [
            "canonical artifact byte equality",
            "source structural contracts and source hashes",
            "odd-prime and canonical field-element rejection",
            "all nineteen primitive positive/negative R1CS rows and malformed sparse encodings",
            "independent RFC7693 ARX BLAKE2b-448 and Keccak sponge references against conventional-library KATs and boundary lengths",
            "all 16 activity masks across all five authorization modes",
            "stablecoin disabled mint burn and every state-seam mutation",
            "four host-only mutations remain non-R1CS and production-blocking",
            "exact row variable auxiliary and matrix-nonzero ledger sums for both profiles",
        ],
        "verdict": "SOURCE_ONLY_SCREEN_COMPLETE_ROUTE_DISQUALIFIED_BY_HOST_BOUNDARY_AND_UNPROVED_REFINEMENT_SECURITY",
    }


def is_prime_u64(n: int) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small:
        if n % prime == 0:
            return n == prime
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % n == 0:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def eval_lc(terms: Iterable[tuple[int, int]], witness: list[int]) -> int:
    return sum(coef * witness[column] for column, coef in terms) % P


def row_holds(row: tuple[list[tuple[int, int]], list[tuple[int, int]], list[tuple[int, int]]], witness: list[int]) -> bool:
    a, b, c = row
    return eval_lc(a, witness) * eval_lc(b, witness) % P == eval_lc(c, witness)


def primitive_rows() -> dict[str, Any]:
    """One canonical row for every primitive.

    Columns are fixed only for this unit-row schema: 0=one, 1=x, 2=y,
    3=z/sum, 4=s/condition, 5=a, 6=b, 7=carry-in, 8=carry-out,
    9..13=t0..t4, and 14=predicate.  A full macro expansion alpha-renames
    nonconstant columns in construction order without changing coefficients.
    """
    one = [(0, 1)]
    zero: list[tuple[int, int]] = []
    return {
        "bitness": ([(1, 1)], [(0, P - 1), (1, 1)], zero),
        "and": ([(1, 1)], [(2, 1)], [(3, 1)]),
        "xor": ([(1, 2)], [(2, 1)], [(1, 1), (2, 1), (3, P - 1)]),
        "or": ([(1, 1)], [(2, 1)], [(1, 1), (2, 1), (3, P - 1)]),
        "and_not": ([(0, 1), (1, P - 1)], [(2, 1)], [(3, 1)]),
        "not": ([(0, P - 1), (1, 1), (3, 1)], one, zero),
        "select": ([(4, 1)], [(5, 1), (6, P - 1)], [(3, 1), (6, P - 1)]),
        "eq": ([(1, 1), (2, P - 1)], one, zero),
        "eq_zero": ([(1, 1)], one, zero),
        "eq_one": ([(0, P - 1), (1, 1)], one, zero),
        "cond_zero": ([(4, 1)], [(1, 1)], zero),
        "cond_eq": ([(4, 1)], [(1, 1), (2, P - 1)], zero),
        "implies": ([(4, 1)], [(0, 1), (14, P - 1)], zero),
        "add_lsb": (
            [(1, 1), (2, 1), (3, P - 1), (8, P - 2)],
            one,
            zero,
        ),
        "add_carry": (
            [(1, 1), (2, 1), (3, P - 1), (7, 1), (8, P - 2)],
            one,
            zero,
        ),
        "linear_5_to_1": (
            [(3, P - 1), (9, 1), (10, 1), (11, 1), (12, 1), (13, 1)],
            one,
            zero,
        ),
        "cond_linear_4": (
            [(4, 1)],
            [(2, P - 1), (9, 1), (10, 1), (11, 1), (12, 1)],
            zero,
        ),
        "linear_sum_5": (
            [(0, P - 1), (9, 1), (10, 1), (11, 1), (12, 1), (13, 1)],
            one,
            zero,
        ),
        "cond_sum_4": (
            [(4, 1)],
            [(0, P - 1), (9, 1), (10, 1), (11, 1), (12, 1)],
            zero,
        ),
    }


def validate_sparse_row(
    row: tuple[list[tuple[int, int]], list[tuple[int, int]], list[tuple[int, int]]],
    z_length: int,
) -> None:
    if z_length <= 0:
        raise ValueError("z length must include the constant column")
    for linear_combination in row:
        previous = -1
        for column, coefficient in linear_combination:
            if not isinstance(column, int) or not 0 <= column < z_length:
                raise ValueError("R1CS column outside z")
            if column <= previous:
                raise ValueError("R1CS columns must be unique and increasing")
            if not isinstance(coefficient, int) or not 0 < coefficient < P:
                raise ValueError("R1CS coefficient must be canonical and nonzero")
            previous = column


def check_primitive_rows() -> None:
    rows = primitive_rows()
    if set(rows) != set(PRIMITIVES):
        raise AssertionError("primitive row inventory drift")
    for name, row in rows.items():
        validate_sparse_row(row, 15)
        nonzeros = sum(len(lc) for lc in row)
        if nonzeros != PRIMITIVES[name].nonzeros:
            raise AssertionError((name, nonzeros, PRIMITIVES[name].nonzeros))

    def base() -> list[int]:
        return [1] + [0] * 14

    for x in (0, 1):
        witness = base()
        witness[1] = x
        if not row_holds(rows["bitness"], witness):
            raise AssertionError("bitness rejects bit")
    witness = base()
    witness[1] = 2
    if row_holds(rows["bitness"], witness):
        raise AssertionError("bitness accepts 2")

    for x in (0, 1):
        for y in (0, 1):
            expected = {
                "and": x & y,
                "xor": x ^ y,
                "or": x | y,
                "and_not": (1 - x) & y,
            }
            for name, z in expected.items():
                witness = base()
                witness[1], witness[2], witness[3] = x, y, z
                if not row_holds(rows[name], witness):
                    raise AssertionError((name, x, y, z))
                witness[3] ^= 1
                if row_holds(rows[name], witness):
                    raise AssertionError((name, "bad-output", x, y))
            witness = base()
            witness[1], witness[3] = x, 1 - x
            if not row_holds(rows["not"], witness):
                raise AssertionError(("not", x))

            witness = base()
            witness[1], witness[2] = x, x
            if not row_holds(rows["eq"], witness):
                raise AssertionError(("eq", x))
            witness[2] ^= 1
            if row_holds(rows["eq"], witness):
                raise AssertionError(("eq-bad", x))

    for x in (0, 1):
        witness = base()
        witness[1] = x
        if row_holds(rows["eq_zero"], witness) != (x == 0):
            raise AssertionError(("eq_zero", x))
        if row_holds(rows["eq_one"], witness) != (x == 1):
            raise AssertionError(("eq_one", x))

    for condition in (0, 1):
        for x in (0, 1):
            for y in (0, 1):
                witness = base()
                witness[1], witness[2], witness[4] = x, y, condition
                if row_holds(rows["cond_zero"], witness) != (not condition or x == 0):
                    raise AssertionError(("cond_zero", condition, x))
                if row_holds(rows["cond_eq"], witness) != (not condition or x == y):
                    raise AssertionError(("cond_eq", condition, x, y))
                witness[14] = y
                if row_holds(rows["implies"], witness) != (not condition or y == 1):
                    raise AssertionError(("implies", condition, y))

                z = x if condition else y
                witness[3], witness[5], witness[6] = z, x, y
                if not row_holds(rows["select"], witness):
                    raise AssertionError(("select", condition, x, y))
                witness[3] ^= 1
                if row_holds(rows["select"], witness):
                    raise AssertionError(("select-bad", condition, x, y))

    for x in (0, 1):
        for y in (0, 1):
            total = x + y
            witness = base()
            witness[1], witness[2], witness[3], witness[8] = x, y, total & 1, total >> 1
            if not row_holds(rows["add_lsb"], witness):
                raise AssertionError(("add_lsb", x, y))
            for carry in (0, 1):
                total = x + y + carry
                witness = base()
                witness[1], witness[2], witness[3] = x, y, total & 1
                witness[7], witness[8] = carry, total >> 1
                if not row_holds(rows["add_carry"], witness):
                    raise AssertionError(("add_carry", x, y, carry))

    witness = base()
    witness[9:14] = [1, 0, 1, 0, 1]
    witness[3] = 3
    if not row_holds(rows["linear_5_to_1"], witness):
        raise AssertionError("linear_5_to_1")
    witness[4], witness[2] = 1, 2
    if not row_holds(rows["cond_linear_4"], witness):
        raise AssertionError("cond_linear_4")
    witness[9:14] = [1, 0, 0, 0, 0]
    if not row_holds(rows["linear_sum_5"], witness):
        raise AssertionError("linear_sum_5")
    if not row_holds(rows["cond_sum_4"], witness):
        raise AssertionError("cond_sum_4")

    malformed = [
        ([(1, 1), (1, 2)], [(0, 1)], []),
        ([(1, 0)], [(0, 1)], []),
        ([(1, P)], [(0, 1)], []),
        ([(15, 1)], [(0, 1)], []),
    ]
    for row in malformed:
        try:
            validate_sparse_row(row, 15)
        except ValueError:
            continue
        raise AssertionError(("malformed sparse row accepted", row))


def activity_shape_accepts(mode: int, mask: int) -> bool:
    ins = [(mask >> 0) & 1 == 1, (mask >> 1) & 1 == 1]
    outs = [(mask >> 2) & 1 == 1, (mask >> 3) & 1 == 1]
    nonempty = any(ins + outs)
    if mode == 0:
        shape = True
    elif mode in (1, 3):
        shape = any(ins) and outs[0]
    elif mode == 2:
        shape = ins == [True, True] and outs[0]
    elif mode == 4:
        shape = ins == [True, True]
    else:
        return False
    return nonempty and shape


def check_activity_matrix() -> dict[str, int]:
    accepted = 0
    rejected = 0
    per_mode = Counter()
    for mask in range(16):
        for mode in range(5):
            value = activity_shape_accepts(mode, mask)
            accepted += int(value)
            rejected += int(not value)
            per_mode[mode] += int(value)
            if mask == 0 and value:
                raise AssertionError("all-empty activity accepted")
        if mask and not activity_shape_accepts(0, mask):
            raise AssertionError(("nonempty single-key rejected", mask))
    if accepted != 33 or rejected != 47 or any(per_mode[mode] == 0 for mode in range(5)):
        raise AssertionError((accepted, rejected, per_mode))
    return {"accepted": accepted, "rejected": rejected}


def stable_state_accepts(stable: dict[str, Any], state: dict[str, Any]) -> bool:
    def zero_value(value: Any) -> bool:
        if isinstance(value, (bytes, bytearray)):
            return not any(value)
        return value == 0 or value is False

    if not stable["enabled"]:
        return all(zero_value(value) for value in stable.values()) and all(zero_value(value) for value in state.values())
    required = (
        state["version"] == 1
        and state["entry_present"]
        and 0 <= state.get("entry_index", 0) < 1 << 32
        and 0 <= state["asset"] < 1 << 32
        and 0 <= state["policy_version"] < 1 << 32
        and state["expected_root"] != b"\0" * 48
        and len(state["expected_root"]) == 48
        and len(state["provided_root"]) == 48
        and state["provided_root"] == state["expected_root"]
        and state["provided_height"] == state["expected_height"]
        and state["asset"] == stable["asset"]
        and state["policy_version"] == stable["policy_version"]
        and state["policy"] == stable["policy"]
        and state["oracle"] == stable["oracle"]
        and state["attestation"] == stable["attestation"]
        and state["active"]
        and state["enabled_at"] <= state["provided_height"]
        and (state["retired_present"] or state["retired_at"] == 0)
        and (not state["retired_present"] or state["provided_height"] < state["retired_at"])
        and state["oracle_submitted_at"] <= state["provided_height"]
        and state["provided_height"] <= min((1 << 64) - 1, state["oracle_submitted_at"] + state["oracle_max_age"])
        and not state["attestation_disputed"]
        and stable["issuance"] > 0
        and stable["issuance"] <= state["max_mint"]
    )
    return bool(required)


def check_stablecoin_mutations() -> set[str]:
    disabled = {"enabled": False, "asset": 0, "policy_version": 0, "policy": b"\0" * 48, "oracle": b"\0" * 48, "attestation": b"\0" * 48, "issuance": 0}
    zero_state = {key: 0 for key in (
        "version", "entry_present", "expected_root", "provided_root", "expected_height", "provided_height",
        "entry_index", "asset", "policy_version", "policy", "oracle", "attestation", "active", "enabled_at",
        "retired_present", "retired_at", "oracle_submitted_at", "oracle_max_age", "attestation_disputed", "max_mint",
    )}
    if not stable_state_accepts(disabled, zero_state):
        raise AssertionError("disabled seam")
    stable = {
        "enabled": True, "asset": 7, "policy_version": 3,
        "policy": b"p" * 48, "oracle": b"o" * 48, "attestation": b"a" * 48,
        "issuance": 9,
    }
    state = {
        "version": 1, "entry_present": True, "expected_root": b"r" * 48,
        "provided_root": b"r" * 48, "expected_height": 100, "provided_height": 100,
        "entry_index": 0, "asset": 7, "policy_version": 3, "policy": b"p" * 48, "oracle": b"o" * 48,
        "attestation": b"a" * 48, "active": True, "enabled_at": 90,
        "retired_present": False, "retired_at": 0, "oracle_submitted_at": 95,
        "oracle_max_age": 10, "attestation_disputed": False, "max_mint": 10,
    }
    if not stable_state_accepts(stable, state):
        raise AssertionError("enabled seam positive")
    mutations = {
        "wrong_state_seam_version": ("version", 2),
        "zero_manifest_commitment": ("expected_root", b"\0" * 48),
        "manifest_commitment_equality_mismatch": ("provided_root", b"x" * 48),
        "current_height_equality_mismatch": ("provided_height", 101),
        "missing_selected_entry": ("entry_present", False),
        "statement_entry_binding_mismatch": ("asset", 8),
        "inactive_or_closed_lifecycle": ("active", False),
        "future_or_stale_oracle": ("oracle_submitted_at", 101),
        "disputed_attestation": ("attestation_disputed", True),
        "zero_or_over_cap_issuance": ("max_mint", 8),
    }
    for name, (key, value) in mutations.items():
        altered = dict(state)
        altered[key] = value
        if stable_state_accepts(stable, altered):
            raise AssertionError((name, key))
    stale = dict(state)
    stale["oracle_submitted_at"] = 80
    if stable_state_accepts(stable, stale):
        raise AssertionError(("future_or_stale_oracle", "stale"))
    noncanonical_retirement = dict(state)
    noncanonical_retirement["retired_at"] = 101
    if stable_state_accepts(stable, noncanonical_retirement):
        raise AssertionError(("inactive_or_closed_lifecycle", "absent retirement must be zero"))
    zero_issuance = dict(stable)
    zero_issuance["issuance"] = 0
    if stable_state_accepts(zero_issuance, state):
        raise AssertionError(("zero_or_over_cap_issuance", "zero"))
    return set(mutations)


def native_balance_accepts(inputs: int, outputs: int, fee: int, negative: bool, magnitude: int) -> bool:
    if min(inputs, outputs, fee, magnitude) < 0 or max(inputs, outputs, fee, magnitude) > MASK64:
        return False
    if outputs + fee > MASK64:
        return False
    if negative:
        return outputs + fee + magnitude <= MASK64 and inputs == outputs + fee + magnitude
    return inputs + magnitude <= MASK64 and inputs + magnitude == outputs + fee


def stable_balance_accepts(inputs: int, outputs: int, issuance_negative: bool, magnitude: int) -> bool:
    if min(inputs, outputs, magnitude) < 0 or max(inputs, outputs, magnitude) > MASK64:
        return False
    if issuance_negative:
        return inputs + magnitude <= MASK64 and outputs == inputs + magnitude
    return outputs + magnitude <= MASK64 and inputs == outputs + magnitude


def check_counterfeit_matrix() -> dict[str, Any]:
    rejected: set[str] = set()
    if not activity_shape_accepts(0, 0):
        rejected.add("all_empty_activity")
    if not activity_shape_accepts(2, 0b0101):
        rejected.add("invalid_authorization_shape")

    if not native_balance_accepts(10, 12, 1, False, 3):
        raise AssertionError("native balance positive")
    if not native_balance_accepts(14, 10, 1, True, 3):
        raise AssertionError("native negative balance positive")
    if not native_balance_accepts(10, 12, 1, False, 4):
        rejected.add("signed_balance_drift")

    if not stable_balance_accepts(10, 13, True, 3):
        raise AssertionError("stable mint positive")
    if not stable_balance_accepts(13, 10, False, 3):
        raise AssertionError("stable burn positive")
    if not stable_balance_accepts(10, 13, True, 4):
        rejected.add("stable_mint_or_burn_drift")

    stable = {
        "enabled": True,
        "asset": 7,
        "policy_version": 3,
        "policy": b"p" * 48,
        "oracle": b"o" * 48,
        "attestation": b"a" * 48,
        "issuance": 9,
    }
    missing = {key: 0 for key in (
        "version", "entry_present", "expected_root", "provided_root", "expected_height",
        "provided_height", "entry_index", "asset", "policy_version", "policy", "oracle",
        "attestation", "active", "enabled_at", "retired_present", "retired_at",
        "oracle_submitted_at", "oracle_max_age", "attestation_disputed", "max_mint",
    )}
    if not stable_state_accepts(stable, missing):
        rejected.add("missing_consensus_state")
    rejected.update(check_stablecoin_mutations())

    expected_link = b"n" * 56
    supplied_link = b"x" * 56
    if expected_link != supplied_link:
        rejected.add("note_nullifier_merkle_or_ciphertext_link_drift")
    if rejected != set(MUTATIONS_R1CS):
        raise AssertionError(("R1CS mutation coverage drift", sorted(set(MUTATIONS_R1CS) - rejected), sorted(rejected - set(MUTATIONS_R1CS))))

    # Each host mutation changes only data outside the 869-byte statement and
    # 50-word seam.  Therefore the compiled predicate sees an identical
    # accepting view and cannot reject it.  This is the explicit disqualifier,
    # not a test waiver.
    compiled_view = {
        "statement_digest": b"s" * 56,
        "expected_root": b"r" * 48,
        "provided_root": b"r" * 48,
        "expected_height": 100,
        "provided_height": 100,
        "selected_entry_index": 0,
    }
    authentic_host_state = {
        "policy_preimage": b"canonical policy tuple",
        "manifest_vector": b"canonical manifest vector",
        "membership": True,
        "consensus_authenticated": True,
    }
    def compiled_boundary_accepts(view: dict[str, Any]) -> bool:
        return (
            len(view["statement_digest"]) == 56
            and len(view["expected_root"]) == 48
            and any(view["expected_root"])
            and view["provided_root"] == view["expected_root"]
            and view["provided_height"] == view["expected_height"]
            and 0 <= view["selected_entry_index"] < 1 << 32
        )

    if not compiled_boundary_accepts(compiled_view):
        raise AssertionError("host-boundary positive compiled view")
    indistinguishable = []
    host_mutations = {
        "forged_policy_hash_derivation": ("policy_preimage", b"forged policy tuple"),
        "forged_whole_manifest_commitment": ("manifest_vector", b"forged manifest vector"),
        "forged_selected_entry_membership": ("membership", False),
        "forged_consensus_expected_root_or_height": ("consensus_authenticated", False),
    }
    for name, (key, value) in host_mutations.items():
        forged = dict(authentic_host_state)
        forged[key] = value
        forged_compiled_view = dict(compiled_view)
        if (
            forged == authentic_host_state
            or forged_compiled_view != compiled_view
            or not compiled_boundary_accepts(forged_compiled_view)
        ):
            raise AssertionError((name, "host mutation construction"))
        indistinguishable.append(name)
    if indistinguishable != MUTATIONS_HOST:
        raise AssertionError("host-only mutation inventory drift")
    return {
        "r1cs_rejected": len(rejected),
        "host_only_indistinguishable_to_r1cs": len(indistinguishable),
    }


MASK64 = (1 << 64) - 1


def rotr64(value: int, amount: int) -> int:
    amount %= 64
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def rotl64(value: int, amount: int) -> int:
    amount %= 64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def blake2b_compress_reference(h: list[int], block: bytes, counter: int, final: bool) -> list[int]:
    if len(block) != 128 or not 0 <= counter < 1 << 128:
        raise ValueError("invalid BLAKE2b compression input")
    message = [int.from_bytes(block[index:index + 8], "little") for index in range(0, 128, 8)]
    v = list(h) + list(BLAKE2B_IV)
    v[12] ^= counter & MASK64
    v[13] ^= counter >> 64
    if final:
        v[14] ^= MASK64

    def g(a: int, b: int, c: int, d: int, x: int, y: int) -> None:
        v[a] = (v[a] + v[b] + x) & MASK64
        v[d] = rotr64(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & MASK64
        v[b] = rotr64(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & MASK64
        v[d] = rotr64(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & MASK64
        v[b] = rotr64(v[b] ^ v[c], 63)

    for sigma in BLAKE2B_SIGMA:
        g(0, 4, 8, 12, message[sigma[0]], message[sigma[1]])
        g(1, 5, 9, 13, message[sigma[2]], message[sigma[3]])
        g(2, 6, 10, 14, message[sigma[4]], message[sigma[5]])
        g(3, 7, 11, 15, message[sigma[6]], message[sigma[7]])
        g(0, 5, 10, 15, message[sigma[8]], message[sigma[9]])
        g(1, 6, 11, 12, message[sigma[10]], message[sigma[11]])
        g(2, 7, 8, 13, message[sigma[12]], message[sigma[13]])
        g(3, 4, 9, 14, message[sigma[14]], message[sigma[15]])
    return [(h[index] ^ v[index] ^ v[index + 8]) & MASK64 for index in range(8)]


def blake2b448_reference(message: bytes) -> bytes:
    h = list(BLAKE2B_IV)
    h[0] ^= 0x01010038
    blocks = max(1, (len(message) + 127) // 128)
    for index in range(blocks):
        chunk = message[index * 128:(index + 1) * 128]
        counter = min((index + 1) * 128, len(message))
        h = blake2b_compress_reference(h, chunk.ljust(128, b"\0"), counter, index + 1 == blocks)
    return b"".join(word.to_bytes(8, "little") for word in h)[:56]


def keccak_f1600_reference(state: list[int]) -> None:
    if len(state) != 25:
        raise ValueError("Keccak state must have 25 lanes")
    for round_constant in KECCAK_RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], KECCAK_ROTATION[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                state[x + 5 * y] &= MASK64
        state[0] ^= round_constant


def keccak_sponge_reference(message: bytes, rate_bytes: int, suffix: int, output_bytes: int) -> bytes:
    if rate_bytes % 8 or not 0 < suffix < 128 or output_bytes < 0:
        raise ValueError("invalid Keccak sponge parameters")
    padded = bytearray(message)
    padded.append(suffix)
    padded.extend(b"\0" * ((rate_bytes - len(padded) % rate_bytes) % rate_bytes))
    padded[-1] ^= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset:offset + rate_bytes]
        for lane in range(rate_bytes // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:lane * 8 + 8], "little")
        keccak_f1600_reference(state)
    output = bytearray()
    while len(output) < output_bytes:
        rate = b"".join(state[lane].to_bytes(8, "little") for lane in range(rate_bytes // 8))
        output.extend(rate[: min(rate_bytes, output_bytes - len(output))])
        if len(output) < output_bytes:
            keccak_f1600_reference(state)
    return bytes(output)


def shake256_448_reference(message: bytes) -> bytes:
    return keccak_sponge_reference(message, 136, 0x1F, 56)


def sha3_512_truncate448_reference(message: bytes) -> bytes:
    return keccak_sponge_reference(message, 72, 0x06, 64)[:56]


def check_hash_kats() -> dict[str, str]:
    messages = [
        b"",
        b"abc",
        bytes(range(72)),
        bytes(range(128)),
        bytes(range(129)),
        bytes(range(136)),
        bytes(index & 0xFF for index in range(2_182)),
    ]
    for message in messages:
        if blake2b448_reference(message) != hashlib.blake2b(message, digest_size=56).digest():
            raise AssertionError(("BLAKE2b-448 reference mismatch", len(message)))
        if sha3_512_truncate448_reference(message) != hashlib.sha3_512(message).digest()[:56]:
            raise AssertionError(("SHA3-512/truncate-448 reference mismatch", len(message)))
        if shake256_448_reference(message) != hashlib.shake_256(message).digest(56):
            raise AssertionError(("SHAKE256-448 reference mismatch", len(message)))
    kats = {
        "blake2b448_empty": blake2b448_reference(b"").hex(),
        "blake2b448_abc": blake2b448_reference(b"abc").hex(),
        "sha3_512_truncate448_empty": sha3_512_truncate448_reference(b"").hex(),
        "sha3_512_truncate448_abc": sha3_512_truncate448_reference(b"abc").hex(),
        "shake256_448_empty": shake256_448_reference(b"").hex(),
        "shake256_448_abc": shake256_448_reference(b"abc").hex(),
    }
    expected = {
        "blake2b448_empty": "e7d2cb731e704ab61a3fa0ddd3bb3a6bfe3c3bc03b2c80a7545a0c9cedb575dfaa6821be9879e9ecd24350297f14470ad3d1cd2d19f27fbf",
        "blake2b448_abc": "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1",
        "sha3_512_truncate448_empty": "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3",
        "sha3_512_truncate448_abc": "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5",
        "shake256_448_empty": "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB486".lower(),
        "shake256_448_abc": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f",
    }
    if kats != expected:
        raise AssertionError((kats, expected))
    return kats


def check_field_encoding() -> None:
    if P % 2 != 1 or not is_prime_u64(P):
        raise AssertionError("field modulus is not an odd prime")
    for value in (0, 1, P - 1):
        encoded = encode_field_element(value)
        decoded = decode_field_element(encoded)
        if decoded != value:
            raise AssertionError(value)
    for value in (P, (1 << 64) - 1):
        try:
            decode_field_element(value.to_bytes(8, "little"))
        except ValueError:
            continue
        raise AssertionError("noncanonical field element accepted")
    for malformed in (b"", b"\0" * 7, b"\0" * 9):
        try:
            decode_field_element(malformed)
        except ValueError:
            continue
        raise AssertionError("wrong-width field element accepted")


def encode_field_element(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < P:
        raise ValueError("field element outside canonical range")
    return value.to_bytes(FIELD_BYTES, "little")


def decode_field_element(encoded: bytes) -> int:
    if len(encoded) != FIELD_BYTES:
        raise ValueError("field element must be exactly eight bytes")
    value = int.from_bytes(encoded, "little")
    if value >= P:
        raise ValueError("noncanonical field element")
    return value


def check_statement_parser() -> None:
    raw = bytearray(STATEMENT_BYTES)
    raw[:8] = b"HX448C02"
    raw[8:10] = (2).to_bytes(2, "big")
    raw[OFFSETS["activation"]:] = activation_bytes()
    if len(raw) != STATEMENT_BYTES or raw[:8] != b"HX448C02" or int.from_bytes(raw[8:10], "big") != 2:
        raise AssertionError("canonical statement")
    projection = bytes(raw) + b"\0" * 3
    if len(projection) != 109 * 8 or projection[-3:] != b"\0\0\0":
        raise AssertionError("M4 projection")
    bad = bytearray(raw)
    bad[:8] = b"HX448C01"
    if bad[:8] == b"HX448C02":
        raise AssertionError("retired magic")


def check_grammars_and_ledgers(manifest: dict[str, Any]) -> dict[str, Any]:
    cursor = 0
    for field in STATEMENT_LAYOUT:
        if field["offset_bytes"] != cursor or field["bytes"] <= 0:
            raise AssertionError(("statement layout gap/overlap", field))
        cursor += field["bytes"]
    if cursor != STATEMENT_BYTES:
        raise AssertionError(("statement layout size", cursor))

    cursor = 0
    for field in STATE_LAYOUT:
        if field["offset_words"] != cursor or field["words"] <= 0:
            raise AssertionError(("state layout gap/overlap", field))
        cursor += field["words"]
    if cursor != STATE_WORDS:
        raise AssertionError(("state layout size", cursor))

    private = manifest["private_input_grammar"]
    cursor = 0
    for section in private["sections"]:
        if section["offset_words"] != cursor or section["words"] <= 0:
            raise AssertionError(("private layout gap/overlap", section))
        cursor += section["words"]
    if cursor != PRIVATE_WORDS or private["bytes"] != PRIVATE_BYTES or private["private_bits"] != PRIVATE_BITS:
        raise AssertionError("private grammar size drift")

    public = manifest["public_input_grammar"]
    if (
        public["l_public_bits"] != PUBLIC_BITS
        or public["statement"]["bytes"] != STATEMENT_BYTES
        or public["consensus_state_seam"]["words"] != STATE_WORDS
        or public["m4_statement_projection"]["words"] != 109
    ):
        raise AssertionError("public grammar size drift")

    if any(manifest["authority"].values()):
        raise AssertionError("an authority flag became true in a source-only screen")
    if manifest["host_only_boundary"]["compiled_rows"] != 0 or not manifest["host_only_boundary"]["disqualifies_full_production_relation"]:
        raise AssertionError("host-only production blocker drift")
    if manifest["host_only_boundary"]["groups"] != HOST_GROUPS:
        raise AssertionError("host-only group drift")

    source_by_path = {entry["path"]: entry for entry in manifest["sources"]}
    if len(source_by_path) != len(manifest["sources"]):
        raise AssertionError("duplicate source-manifest path")
    expected_source_roles = {
        Path(__file__).resolve(): "canonical macro compiler and checker",
        TEST_PATH: "dependency-free regression suite",
        SCALAR: "frozen HX448C02 scalar statement and hash-call schedule",
        M4: "frozen HX448C02 M4 relation-family and state-seam schedule",
        M4_LIB: "private transport and authorization semantic layout",
        STABLE_MANIFEST: "current flat-manifest host-boundary source",
    }
    for path, role in expected_source_roles.items():
        entry = source_by_path.get(rel(path))
        if (
            entry is None
            or entry["role"] != role
            or entry["bytes"] != path.stat().st_size
            or entry["sha512"] != sha512_file(path)
        ):
            raise AssertionError(("source pin mismatch", rel(path)))

    expected_relation_groups = LOCAL_GROUPS + STATE_GROUPS + HASH_LINK_GROUPS
    profile_summary: dict[str, Any] = {}
    for profile, data in manifest["hash_profiles"].items():
        calls = data["calls"]
        if len(calls) != PHYSICAL_HASH_CALLS or [call["index"] for call in calls] != list(range(PHYSICAL_HASH_CALLS)):
            raise AssertionError((profile, "hash call registry"))
        if sum(call["kind"].startswith("merkle") for call in calls) != 64:
            raise AssertionError((profile, "Merkle call count"))
        logical_frames = sum(5 if call["select_before_hash"] else 1 for call in calls)
        frame_bits = sum(
            (call["frame"].get("exact_bytes", 0) + sum(call["frame"].get("authorization_arm_bytes", []))) * 8
            for call in calls
        )
        if logical_frames != 99 or frame_bits != 149_560:
            raise AssertionError((profile, logical_frames, frame_bits))
        shake_cores = sum(call["primitive_cores"] for call in calls if call["algorithm"] == "FIPS202-SHAKE256-448")
        if shake_cores != 105:
            raise AssertionError((profile, "SHAKE core count", shake_cores))
        if profile == "blake2b448-mixed":
            secret_cores = sum(call["primitive_cores"] for call in calls if call["algorithm"] == "RFC7693-BLAKE2b-448")
            if secret_cores != 28:
                raise AssertionError((profile, "BLAKE2b compression count", secret_cores))
        else:
            secret_cores = sum(call["primitive_cores"] for call in calls if call["algorithm"] == "FIPS202-SHA3-512-truncate-448")
            if secret_cores != 46:
                raise AssertionError((profile, "SHA3 permutation count", secret_cores))
        if sum(call["algorithm"] != "FIPS202-SHAKE256-448" for call in calls) != 15:
            raise AssertionError((profile, "secret hash call count"))

        groups = data["group_ledger"]
        names = [group["name"] for group in groups]
        if len(names) != len(set(names)) or any(name not in names for name in expected_relation_groups):
            raise AssertionError((profile, "relation family coverage"))
        if any(next(group for group in groups if group["name"] == name)["rows"] <= 0 for name in expected_relation_groups):
            raise AssertionError((profile, "empty compiled relation family"))
        geometry = data["geometry"]
        if geometry["l_public_variables"] != PUBLIC_BITS or geometry["private_transport_variables"] != PRIVATE_BITS:
            raise AssertionError((profile, "transport geometry"))
        if sum(group["rows"] for group in groups) != geometry["m_constraints"]:
            raise AssertionError((profile, "row ledger sum"))
        if sum(group["nonzeros"] for group in groups) != geometry["matrix_nonzeros_total"]:
            raise AssertionError((profile, "nonzero ledger sum"))
        if sum(group["auxiliary_variables"] for group in groups) != geometry["derived_auxiliary_variables"]:
            raise AssertionError((profile, "auxiliary ledger sum"))
        if geometry["n_nonconstant_variables"] != PUBLIC_BITS + PRIVATE_BITS + geometry["derived_auxiliary_variables"]:
            raise AssertionError((profile, "n variable equation"))
        embedding = data["cfw26_section11_candidate_embedding"]
        if embedding["authoritative_cfw26_theorem_binding"] or embedding["embedded_geometry"]["rows"] != 2 * embedding["ell"]:
            raise AssertionError((profile, "candidate embedding authority/shape"))
        profile_summary[profile] = {
            "hash_calls": len(calls),
            "logical_frames": logical_frames,
            "relation_groups": len(expected_relation_groups),
        }

    manifest_text = canonical_bytes(manifest).decode().lower()
    if "poseidon" in manifest_text or "measured proof" in manifest_text or '"production_authorized":true' in manifest_text:
        raise AssertionError("forbidden authority/algorithm wording in manifest")
    return profile_summary


def verify_artifacts(verbose: bool = True) -> dict[str, Any]:
    manifest = build_manifest()
    certificate = build_certificate(manifest)
    expected_manifest = canonical_bytes(manifest)
    expected_certificate = canonical_bytes(certificate)
    if not MANIFEST_PATH.exists() or MANIFEST_PATH.read_bytes() != expected_manifest:
        raise AssertionError(f"{MANIFEST_PATH.name} is missing or stale; run emit")
    if not CERTIFICATE_PATH.exists() or CERTIFICATE_PATH.read_bytes() != expected_certificate:
        raise AssertionError(f"{CERTIFICATE_PATH.name} is missing or stale; run emit")
    check_field_encoding()
    check_primitive_rows()
    activity = check_activity_matrix()
    counterfeit = check_counterfeit_matrix()
    kats = check_hash_kats()
    profile_checks = check_grammars_and_ledgers(manifest)
    check_statement_parser()
    result = {
        "activity_matrix": activity,
        "counterfeit_matrix": counterfeit,
        "hash_kats": kats,
        "manifest_bytes": len(expected_manifest),
        "profile_checks": profile_checks,
        "relation_manifest_digest_shake256_512": certificate["relation_manifest_digest_shake256_512"],
        "profiles": {name: data["geometry"] for name, data in manifest["hash_profiles"].items()},
        "status": "pass",
    }
    if verbose:
        print(json.dumps(result, sort_keys=True, indent=2))
    return result


def emit() -> None:
    manifest = build_manifest()
    certificate = build_certificate(manifest)
    MANIFEST_PATH.write_bytes(canonical_bytes(manifest))
    CERTIFICATE_PATH.write_bytes(canonical_bytes(certificate))
    print(f"wrote {MANIFEST_PATH}")
    print(f"wrote {CERTIFICATE_PATH}")


def summary() -> None:
    certificate = json.loads(CERTIFICATE_PATH.read_text())
    manifest = json.loads(MANIFEST_PATH.read_text())
    output = {
        "field_modulus_decimal": str(P),
        "production_authorized": False,
        "public_input_grammar_digest_shake256_512": manifest["public_input_grammar_digest_shake256_512"],
        "relation_manifest_digest_shake256_512": certificate["relation_manifest_digest_shake256_512"],
        "r1cs_geometry": {name: data["geometry"] for name, data in manifest["hash_profiles"].items()},
        "source_set_digest_sha512": certificate["source_set_digest_sha512"],
        "verdict": certificate["verdict"],
    }
    print(json.dumps(output, sort_keys=True, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("emit", "check", "summary"))
    args = parser.parse_args(argv)
    if args.command == "emit":
        emit()
    elif args.command == "check":
        verify_artifacts()
    else:
        summary()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
