#!/usr/bin/env python3
"""Source-only certificate for the prospective HX512 semantic hash suite.

This program deliberately does not build or prove anything.  It freezes the
HX448C02 source schedule, defines two fresh 64-byte counterfactual profiles,
counts their exact framed primitive calls under a documented Boolean/R1CS
macro lowering, and emits fail-closed security ledgers.  The selected result
is only the smaller source-cost profile; every production capability remains
false and proof bytes remain null.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import OrderedDict
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

SCALAR_SOURCE = ROOT / "circuits/transaction/src/full_blake2b448_relation.rs"
M4_SOURCE = (
    ROOT
    / "prototypes/standalone-shake256-binius"
    / "m4-full-blake448-e384-candidate/src/mixed_candidate.rs"
)
ODD_COMPILER = ROOT / ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py"
ODD_MANIFEST = ROOT / ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json"
MANIFEST_AUTHORITY_SOURCE = (
    ROOT / ".agent/hardening/manifest-authority-closure/manifest_authority.py"
)
NATIVE_MANIFEST_AUTHORITY_SOURCE = (
    ROOT / "protocol/kernel/src/stablecoin_manifest_authority_v2.rs"
)
NATIVE_MANIFEST_AUTHORITY_CHECKER = (
    ROOT / "protocol/kernel/check_stablecoin_manifest_authority_v2.py"
)
NATIVE_MANIFEST_AUTHORITY_TEST = (
    ROOT / "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py"
)

REPORT_PATH = HERE / "suite_report.json"
SECURITY_PATH = HERE / "security_ledgers.json"
MUTATION_PATH = HERE / "mutation_corpus.json"
PINS_PATH = HERE / "source_pins.json"

EXPECTED_SOURCE_SHA512 = {
    "circuits/transaction/src/full_blake2b448_relation.rs":
        "905ffb7e3b8b2f28ba4600ef498acddba8d9125a859adb1cb10c97a0ec4ebd993858e88b91eda6465d49f05172a31a49057203457abf04717cf9efbe7fd195d9",
    "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs":
        "0cd45615489f2f84bfc803e7d94f0c7309c24a2ef37c8df4fdde0c651d0a81ba63502fe4fdfe41f7e6e3f68477797a951a878da42540a2d2b4e4f1eca624179c",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py":
        "62bd836c41fac8691e2ff97414c33d3bb955ae2b5cb833721e811e3e52b43c1793676a98178007fc3727bad825545cd8075d06b44c467d4d54b6a3cdf70226b5",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json":
        "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e",
    ".agent/hardening/manifest-authority-closure/manifest_authority.py":
        "b225d5dbb832f985f5a78c570b5531b31c2cc6175d6aa19ce4e5955d0774e9bf9dc614a24cec60d207b7b23c1d94bfe93e58277c9ec70690330d313b6f6f824f",
    "protocol/kernel/src/stablecoin_manifest_authority_v2.rs":
        "99268907680ebff599f992e64f15cc9730f451eebd08b6e92776e66ee9afe567d6bf19eb1c1ff2482a3ea4a737a43e941cd04b7cb18f8e533239abdd474d395f",
    "protocol/kernel/check_stablecoin_manifest_authority_v2.py":
        "fe6228df9fce18ea13278ff034f1107d5b5b96408bbaadcfcd63c4fee1ccf95cb72a07e3c6ea8ec0f267fe494250366c54c02d3858a4429ddd6a5f926668e12e",
    "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py":
        "4c5d29d02ea629b2d30aa9bc8b12ed93713d9d84fa16f5a8874d1906fb1351fba28aaa01670f1d94948c5bc92eed12ae6b7db885ca8092092250ef30e0c5b431",
}

SOURCE_PATHS = {
    "circuits/transaction/src/full_blake2b448_relation.rs": SCALAR_SOURCE,
    "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs": M4_SOURCE,
    ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py": ODD_COMPILER,
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json": ODD_MANIFEST,
    ".agent/hardening/manifest-authority-closure/manifest_authority.py": MANIFEST_AUTHORITY_SOURCE,
    "protocol/kernel/src/stablecoin_manifest_authority_v2.rs": NATIVE_MANIFEST_AUTHORITY_SOURCE,
    "protocol/kernel/check_stablecoin_manifest_authority_v2.py": NATIVE_MANIFEST_AUTHORITY_CHECKER,
    "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py": NATIVE_MANIFEST_AUTHORITY_TEST,
}

# Fresh, test-only identifiers.  They are not inserted into any production
# registry.  The control uses a distinct suite/profile so no proof or statement
# can switch primitives while retaining an identity.
BLAKE_PROFILE = b"HX512B01"
SPLIT_PROFILE = b"HX512H01"
STATEMENT_GRAMMAR = 1
NETWORK_ID = 0x48583531  # ASCII "HX51", test-only.

IDENTITIES = {
    "blake2b512_rfc": {
        "statement_magic": BLAKE_PROFILE.decode(),
        "frame_profile": BLAKE_PROFILE.decode(),
        "statement_grammar": STATEMENT_GRAMMAR,
        "circuit_version": 0x5121,
        "crypto_suite": 0x512B,
        "family_id": 0x5123,
        "action_id": 0x5124,
        "network_id": NETWORK_ID,
        "backend_id": 0x51,
        "proof_profile": 0x52,
        "domain_set": 0x5127,
    },
    "sha512_shake256_control": {
        "statement_magic": SPLIT_PROFILE.decode(),
        "frame_profile": SPLIT_PROFILE.decode(),
        "statement_grammar": STATEMENT_GRAMMAR,
        "circuit_version": 0x5121,
        "crypto_suite": 0x512A,
        "family_id": 0x5123,
        "action_id": 0x5124,
        "network_id": NETWORK_ID,
        "backend_id": 0x51,
        "proof_profile": 0x53,
        "domain_set": 0x5128,
    },
}

DOMAIN_REGISTRIES = {
    "blake2b512_rfc": {
        "core": "HX512B01 + exact 8-byte typed role + counted u16be-length fields",
        "manifest_authority": (
            "HGMAIDV2/HGMAROOT profile=2 width=64 cap_log2=4; "
            "frozen specialized BLAKE2b parameter personalizations"
        ),
        "domain_set_id": 0x5127,
    },
    "sha512_shake256_control": {
        "core": "HX512H01 + exact 8-byte typed role + counted u16be-length fields",
        "manifest_authority": (
            "HX512H01 || frozen 16-byte authority personalization || "
            "u16be(raw_len) || raw"
        ),
        "domain_set_id": 0x5128,
    },
}

DIGEST_BYTES = 64
SPEND_MASTER_BYTES = 64
NOTE_BLINDING_BYTES = 64
POLICY_MASTER_BYTES = 64
RHO_BYTES = 48
MAX_INPUTS = 2
MAX_OUTPUTS = 2
MERKLE_DEPTH = 32
MAX_SIGNERS = 6
BALANCE_SLOTS = 4
CANONICAL_CIPHERTEXT_BYTES = 2147
MANIFEST_CAP = 16
MANIFEST_DEPTH = 4
MANIFEST_ROW_BYTES = 215
MANIFEST_WITNESS_SEMANTIC_BYTES = 4 + MANIFEST_ROW_BYTES + MANIFEST_DEPTH * DIGEST_BYTES
MANIFEST_WITNESS_TRANSPORT_BYTES = 480

FROZEN_STATEMENT_BYTES = 869
FROZEN_STATEMENT_LIMBS7 = 125
FROZEN_PUBLIC_WORDS = 159
FROZEN_PRIVATE_WORDS = 1209
FROZEN_PRIVATE_BYTES = 9672
FROZEN_R1CS_ROWS = 20_457_227

STATEMENT_BYTES = 1141
STATEMENT_LIMBS7 = 163
STATEMENT_WORDS8 = 143
# Exact inactive-native `StablecoinManifestPublicAuthorityV2` grammar.  The
# first 64 bytes are the manifest root, not the derived state snapshot.
VERIFIER_CONTEXT_BYTES = 72  # manifest_root[64] || parent_height:u64le
PUBLIC_WORDS8 = 152
PRIVATE_BYTES = 11_000
PRIVATE_WORDS8 = 1375

ROLE_NOTE = b"nt.b5121"
ROLE_NULLIFIER = b"nf.b5121"
ROLE_MERKLE = b"mk.b5121"
ROLE_SPEND_A = b"sk.b51a1"
ROLE_SPEND_B = b"sk.b51b1"
ROLE_AUTH_POLICY = b"pl.b5121"
ROLE_AUTH_A = b"au.b51a1"
ROLE_AUTH_B = b"au.b51b1"
ROLE_INTENT = b"in.b5121"
ROLE_BALANCE = b"bl.b5121"
ROLE_CIPHERTEXT = b"ct.b5121"
ROLE_STABLE_POLICY = b"st.pl512"
ROLE_STABLE_ORACLE = b"st.or512"
ROLE_STABLE_ATTEST = b"st.at512"
ROLE_MANIFEST_LEAF = b"mf.lf512"
ROLE_MANIFEST_NODE = b"mf.nd512"
ROLE_STATE_ROOT = b"st.rt512"
ROLE_PROOF_LEAF = b"pf.lf512"
ROLE_PROOF_TAPE = b"pf.tp512"
LANE_A = b"lane.A51"
LANE_B = b"lane.B51"

# Frozen all-W64 manifest-authority registry.  These values are BLAKE2b
# parameter-block personalizations, not bytes prepended to the selected
# BLAKE2b message.  The SHA-512/SHAKE control absorbs them in an explicit
# control frame because those primitives have no personalization parameter.
AUTH_ID_MAGIC = b"HGMAIDV2"
AUTH_ROOT_MAGIC = b"HGMAROOT"
AUTH_PROFILE = 2
AUTH_WIDTH = 64
AUTH_DEPTH = 4
AUTH_ID_POLICY = 1
AUTH_ID_ORACLE = 2
AUTH_ID_ATTESTATION = 3
AUTH_ROOT_FULL = 1
AUTH_ROOT_LEAF = 2
AUTH_ROOT_NODE = 3
AUTH_ROOT_SNAPSHOT = 4

AUTHORIZATION_MODES = (
    "single_key",
    "accumulator_init",
    "approval_step",
    "value_lock_creation",
    "final_threshold_spend",
)

CORE_ROLES = (
    ROLE_NOTE,
    ROLE_NULLIFIER,
    ROLE_MERKLE,
    ROLE_SPEND_A,
    ROLE_SPEND_B,
    ROLE_AUTH_POLICY,
    ROLE_AUTH_A,
    ROLE_AUTH_B,
    ROLE_INTENT,
    ROLE_BALANCE,
    ROLE_CIPHERTEXT,
)

SECURITY_ROLES = (
    "semantic.note_commitment",
    "semantic.nullifier",
    "semantic.merkle_node",
    "semantic.spend_key_xof",
    "semantic.authorization_policy",
    "semantic.authorization_accumulator",
    "semantic.authorization_value_lock",
    "semantic.intent",
    "semantic.balance_tag",
    "semantic.ciphertext_hash",
    "statement.stablecoin_policy_hash",
    "statement.stablecoin_oracle_commitment",
    "statement.stablecoin_attestation_commitment",
    "proof.merkle_leaf",
    "proof.opened_leaf_random_tape",
)

OFFSETS = OrderedDict(
    magic=0,
    grammar=8,
    flags=10,
    anchor=14,
    nullifiers=78,
    commitments=206,
    ciphertext_hashes=334,
    ciphertext_sizes=462,
    assets=470,
    fee=502,
    value_balance_sign=510,
    value_balance_magnitude=511,
    stable_enabled=519,
    stable_asset=520,
    stable_version=528,
    stable_issuance_sign=532,
    stable_issuance_magnitude=533,
    stable_policy=541,
    stable_oracle=605,
    stable_attestation=669,
    manifest_root=733,
    state_root=797,
    state_height=861,
    balance_tag=869,
    activation=933,
    network=941,
    backend=945,
    profile=946,
    domain_set=947,
    chain_id=949,
    genesis_id=1013,
    rules_hash=1077,
    end=1141,
)


class Reject(ValueError):
    """Canonical parser or gate rejection."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def source_pins() -> dict[str, Any]:
    observed = {name: sha512_file(path) for name, path in SOURCE_PATHS.items()}
    return {
        "artifact_schema": "hegemon.hx512-semantic-suite.source-pins.v1",
        "all_match": observed == EXPECTED_SOURCE_SHA512,
        "frozen_source_sha512": observed,
        "expected_source_sha512": EXPECTED_SOURCE_SHA512,
        "source_contract": {
            "physical_hash_calls": 83,
            "activity_masks": 16,
            "authorization_modes": 5,
            "accepted_mask_mode_pairs": 33,
            "rejected_mask_mode_pairs": 47,
            "statement_magic": "HX448C02",
            "statement_grammar": 2,
            "statement_bytes": 869,
            "public_words": 159,
            "private_words": 1209,
        },
    }


def _require_bytes(name: str, value: bytes, width: int) -> None:
    if type(value) is not bytes or len(value) != width:
        raise Reject(f"{name} must be exactly {width} bytes")


def frame(profile: bytes, role: bytes, fields: Sequence[bytes]) -> bytes:
    _require_bytes("profile", profile, 8)
    _require_bytes("role", role, 8)
    if len(fields) > 255:
        raise Reject("too many frame fields")
    out = bytearray(profile + role + bytes([len(fields)]))
    for field in fields:
        if type(field) is not bytes or len(field) > 65535:
            raise Reject("noncanonical frame field")
        out += len(field).to_bytes(2, "big") + field
    return bytes(out)


def blake_blocks(message_bytes: int) -> int:
    if message_bytes < 0:
        raise Reject("negative message length")
    return max(1, (message_bytes + 127) // 128)


def sha512_blocks(message_bytes: int) -> int:
    if message_bytes < 0:
        raise Reject("negative message length")
    # One 0x80 byte and a 16-byte bit length are always appended.
    return (message_bytes + 17 + 127) // 128


def shake256_permutations(message_bytes: int) -> int:
    if message_bytes < 0:
        raise Reject("negative message length")
    # Domain suffix/padding consumes at least one byte at rate 136.
    return max(1, (message_bytes + 1 + 135) // 136)


def statement_layout() -> list[dict[str, Any]]:
    widths = {
        "magic": 8,
        "grammar": 2,
        "flags": 4,
        "anchor": 64,
        "nullifiers": 128,
        "commitments": 128,
        "ciphertext_hashes": 128,
        "ciphertext_sizes": 8,
        "assets": 32,
        "fee": 8,
        "value_balance_sign": 1,
        "value_balance_magnitude": 8,
        "stable_enabled": 1,
        "stable_asset": 8,
        "stable_version": 4,
        "stable_issuance_sign": 1,
        "stable_issuance_magnitude": 8,
        "stable_policy": 64,
        "stable_oracle": 64,
        "stable_attestation": 64,
        "manifest_root": 64,
        "state_root": 64,
        "state_height": 8,
        "balance_tag": 64,
        "activation": 8,
        "network": 4,
        "backend": 1,
        "profile": 1,
        "domain_set": 2,
        "chain_id": 64,
        "genesis_id": 64,
        "rules_hash": 64,
    }
    result = []
    names = list(OFFSETS)
    for index, name in enumerate(names[:-1]):
        start = OFFSETS[name]
        end = OFFSETS[names[index + 1]]
        if end - start != widths[name]:
            raise AssertionError((name, start, end, widths[name]))
        result.append({"name": name, "offset": start, "bytes": widths[name]})
    if OFFSETS["end"] != STATEMENT_BYTES:
        raise AssertionError("statement width drift")
    return result


def activation_bytes(profile_name: str) -> bytes:
    identity = IDENTITIES[profile_name]
    out = bytearray()
    for key in ("circuit_version", "crypto_suite", "family_id", "action_id"):
        out += int(identity[key]).to_bytes(2, "big")
    out += int(identity["network_id"]).to_bytes(4, "big")
    out += bytes([int(identity["backend_id"]), int(identity["proof_profile"])])
    out += int(identity["domain_set"]).to_bytes(2, "big")
    out += bytes([0x11]) * 64 + bytes([0x22]) * 64 + bytes([0x33]) * 64
    if len(out) != 208:
        raise AssertionError(len(out))
    return bytes(out)


def sample_statement(profile_name: str = "blake2b512_rfc") -> bytes:
    identity = IDENTITIES[profile_name]
    out = bytearray(STATEMENT_BYTES)
    out[0:8] = identity["statement_magic"].encode()
    out[8:10] = STATEMENT_GRAMMAR.to_bytes(2, "big")
    out[10:14] = b"\x01\x01\x01\x01"
    cursor = 14
    for marker, width in ((0x41, 64), (0x42, 128), (0x43, 128), (0x44, 128)):
        out[cursor : cursor + width] = bytes([marker]) * width
        cursor += width
    out[462:466] = CANONICAL_CIPHERTEXT_BYTES.to_bytes(4, "big")
    out[466:470] = CANONICAL_CIPHERTEXT_BYTES.to_bytes(4, "big")
    for index, asset in enumerate((0, 1001, (1 << 64) - 1, (1 << 64) - 1)):
        out[470 + index * 8 : 478 + index * 8] = asset.to_bytes(8, "big")
    out[502:510] = (7).to_bytes(8, "big")
    out[510] = 0
    out[511:519] = (0).to_bytes(8, "big")
    out[519] = 1
    out[520:528] = (1001).to_bytes(8, "big")
    out[528:532] = (3).to_bytes(4, "big")
    out[532] = 0
    out[533:541] = (1).to_bytes(8, "big")
    for offset, marker in (
        (541, 0x51),
        (605, 0x52),
        (669, 0x53),
        (733, 0x54),
        (797, 0x55),
    ):
        out[offset : offset + 64] = bytes([marker]) * 64
    out[861:869] = (42).to_bytes(8, "big")
    out[869:933] = bytes([0x56]) * 64
    out[933:1141] = activation_bytes(profile_name)
    if len(out) != STATEMENT_BYTES:
        raise AssertionError(len(out))
    return bytes(out)


def parse_statement(raw: bytes, profile_name: str) -> dict[str, bytes]:
    _require_bytes("statement", raw, STATEMENT_BYTES)
    identity = IDENTITIES[profile_name]
    if raw[:8] != identity["statement_magic"].encode():
        raise Reject("wrong statement magic")
    if int.from_bytes(raw[8:10], "big") != STATEMENT_GRAMMAR:
        raise Reject("wrong statement grammar")
    if any(flag not in (0, 1) for flag in raw[10:14]) or raw[10:14] == bytes(4):
        raise Reject("noncanonical or all-empty activity flags")
    if raw[933:1141] != activation_bytes(profile_name):
        raise Reject("activation/network/domain identity mismatch")
    return {
        item["name"]: raw[item["offset"] : item["offset"] + item["bytes"]]
        for item in statement_layout()
    }


def encode_verifier_context(manifest_root_bytes: bytes, parent_height: int) -> bytes:
    """Encode the exact inactive-native public-authority suffix.

    `state_root` in the statement is the domain-separated snapshot.  It is
    deliberately not carried here: the verifier-owned context carries the
    canonical manifest root and height used to recompute that snapshot.
    """

    _require_bytes("verifier-context manifest root", manifest_root_bytes, 64)
    if not 0 <= parent_height < 1 << 64:
        raise Reject("verifier-context parent height")
    result = manifest_root_bytes + parent_height.to_bytes(8, "little")
    if len(result) != VERIFIER_CONTEXT_BYTES:
        raise AssertionError("verifier-context width drift")
    return result


def parse_verifier_context(raw: bytes) -> dict[str, Any]:
    _require_bytes("verifier context", raw, VERIFIER_CONTEXT_BYTES)
    decoded = {
        "manifest_root": raw[:64],
        "parent_height": int.from_bytes(raw[64:], "little"),
    }
    if encode_verifier_context(
        decoded["manifest_root"], decoded["parent_height"]
    ) != raw:
        raise Reject("noncanonical verifier context")
    return decoded


def require_verifier_context(
    raw: bytes, manifest_root_bytes: bytes, parent_height: int
) -> None:
    """Require exact verifier-owned root/height equality.

    This models the equality boundary only.  Authenticating the supplied
    parent state remains a native consensus obligation and is not claimed by
    this source-only suite.
    """

    parsed = parse_verifier_context(raw)
    _require_bytes("expected manifest root", manifest_root_bytes, 64)
    if (
        parsed["manifest_root"] != manifest_root_bytes
        or parsed["parent_height"] != parent_height
    ):
        raise Reject("verifier-context manifest root or height mismatch")


def core_frame_schedule(profile: bytes) -> list[dict[str, Any]]:
    zero64 = bytes(64)
    note = frame(
        profile,
        ROLE_NOTE,
        [bytes(64), b"\0", bytes(8), bytes(8), bytes(32), bytes(48), zero64],
    )
    # The first field is the 512-bit note blinding.  Reordering relative to
    # HX448C02 is intentional and keeps the secret immediately after the
    # fixed role grammar for the conditional prefix-QRO argument.
    nullifier = frame(profile, ROLE_NULLIFIER, [zero64, bytes(8), bytes(48)])
    merkle = frame(profile, ROLE_MERKLE, [zero64, zero64])
    spend_a = frame(profile, ROLE_SPEND_A, [LANE_A, zero64])
    spend_b = frame(profile, ROLE_SPEND_B, [LANE_B, zero64])
    policy = frame(
        profile,
        ROLE_AUTH_POLICY,
        [zero64, bytes(8), bytes(8), *([zero64] * MAX_SIGNERS)],
    )
    accumulator = frame(
        profile,
        ROLE_AUTH_A,
        [zero64, LANE_A, zero64, zero64, bytes(8), bytes(8), bytes(8), bytes(6)],
    )
    value_lock = frame(profile, ROLE_AUTH_A, [zero64, LANE_A, zero64, zero64])
    dummy = frame(profile, ROLE_AUTH_A, [bytes(117)])
    statement = sample_statement(
        "blake2b512_rfc" if profile == BLAKE_PROFILE else "sha512_shake256_control"
    )
    intent_payload = statement[:14] + statement[OFFSETS["commitments"] :]
    intent = frame(profile, ROLE_INTENT, [intent_payload])
    balance = frame(
        profile,
        ROLE_BALANCE,
        [bytes(8), b"\0", bytes(8), bytes(32), b"\0", bytes(8), b"\0", bytes(8)],
    )
    ciphertext = frame(
        profile,
        ROLE_CIPHERTEXT,
        [b"\x52", (0x5127).to_bytes(2, "big"), b"\0", CANONICAL_CIPHERTEXT_BYTES.to_bytes(4, "big"), bytes(CANONICAL_CIPHERTEXT_BYTES)],
    )
    if [len(value) for value in (note, nullifier, merkle, spend_a, policy, accumulator, value_lock, dummy, intent, balance, ciphertext)] != [
        256,
        143,
        149,
        93,
        499,
        263,
        225,
        136,
        968,
        100,
        2182,
    ]:
        raise AssertionError("fresh frame length drift")
    families = [
        ("note_commitment", ROLE_NOTE, 4, len(note), "secret"),
        ("nullifier", ROLE_NULLIFIER, 2, len(nullifier), "secret"),
        ("merkle_node", ROLE_MERKLE, 64, len(merkle), "collision"),
        ("spend_key_lane_a", ROLE_SPEND_A, 2, len(spend_a), "secret"),
        ("spend_key_lane_b", ROLE_SPEND_B, 2, len(spend_b), "secret"),
        ("authorization_policy", ROLE_AUTH_POLICY, 1, len(policy), "secret"),
        ("authorization_lane_a", ROLE_AUTH_A, 2, len(accumulator), "secret_mux"),
        ("authorization_lane_b", ROLE_AUTH_B, 2, len(accumulator), "secret_mux"),
        ("intent", ROLE_INTENT, 1, len(intent), "collision"),
        ("balance_tag", ROLE_BALANCE, 1, len(balance), "collision"),
        ("ciphertext_hash", ROLE_CIPHERTEXT, 2, len(ciphertext), "collision"),
    ]
    result = []
    for name, role, calls, size, purpose in families:
        item = {
            "family": name,
            "role_hex": role.hex(),
            "role_ascii": role.decode(),
            "calls": calls,
            "maximum_frame_bytes": size,
            "purpose": purpose,
        }
        if purpose == "secret_mux":
            item["authorization_arm_bytes"] = {
                "dummy": len(dummy),
                "accumulator": len(accumulator),
                "value_lock": len(value_lock),
            }
            item["non_dummy_secret_prefix_bytes"] = POLICY_MASTER_BYTES
            item["dummy_has_secret_prefix"] = False
            item["secret_prefix_source"] = (
                "opening-specific current/next policy master per "
                "policy_master_mode_schedule"
            )
            item["fixed_blake_compressions_per_call"] = 3
            item["fixed_sha512_compressions_per_call"] = 3
        else:
            item["blake_compressions_per_call"] = blake_blocks(size)
            if purpose == "secret":
                item["sha512_compressions_per_call"] = sha512_blocks(size)
            else:
                item["shake256_permutations_per_call"] = shake256_permutations(size)
            if name == "authorization_policy":
                item["secret_prefix_bytes"] = POLICY_MASTER_BYTES
                item["secret_prefix_source"] = (
                    "next for accumulator_init; current for all other modes"
                )
        result.append(item)
    if sum(item["calls"] for item in result) != 83:
        raise AssertionError("83-call schedule drift")
    return result


def authority_identity_personalization(role: int) -> bytes:
    if role not in (AUTH_ID_POLICY, AUTH_ID_ORACLE, AUTH_ID_ATTESTATION):
        raise Reject("unknown manifest identity role")
    out = AUTH_ID_MAGIC + bytes([role, AUTH_PROFILE, AUTH_WIDTH]) + bytes(5)
    if len(out) != 16:
        raise AssertionError(len(out))
    return out


def authority_root_personalization(role: int, level: int = 0) -> bytes:
    if role not in (
        AUTH_ROOT_FULL,
        AUTH_ROOT_LEAF,
        AUTH_ROOT_NODE,
        AUTH_ROOT_SNAPSHOT,
    ):
        raise Reject("unknown manifest root role")
    if role == AUTH_ROOT_NODE:
        if not 0 <= level < AUTH_DEPTH:
            raise Reject("manifest node level")
    elif level != 0:
        raise Reject("only a manifest node may carry a level")
    out = AUTH_ROOT_MAGIC + bytes(
        [role, AUTH_PROFILE, AUTH_WIDTH, AUTH_DEPTH, level, 0, 0, 0]
    )
    if len(out) != 16:
        raise AssertionError(len(out))
    return out


def authority_blake(message: bytes, personalization: bytes) -> bytes:
    _require_bytes("authority personalization", personalization, 16)
    return hashlib.blake2b(
        message, digest_size=AUTH_WIDTH, person=personalization
    ).digest()


def authority_control_frame(personalization: bytes, raw: bytes) -> bytes:
    """Exact split-control absorption for the frozen authority grammar."""

    _require_bytes("authority personalization", personalization, 16)
    if type(raw) is not bytes or len(raw) > 65535:
        raise Reject("authority control raw input")
    return SPLIT_PROFILE + personalization + len(raw).to_bytes(2, "big") + raw


def authority_schedule(profile_name: str) -> dict[str, Any]:
    if profile_name not in IDENTITIES:
        raise Reject("unknown HX512 profile")
    raw = OrderedDict(
        stablecoin_policy_constructor=61,
        manifest_leaf=1 + MANIFEST_ROW_BYTES,
        manifest_node=2 * AUTH_WIDTH,
        state_snapshot=8 + AUTH_WIDTH,
    )
    persons = {
        "stablecoin_policy_constructor": authority_identity_personalization(
            AUTH_ID_POLICY
        ),
        "manifest_leaf": authority_root_personalization(AUTH_ROOT_LEAF),
        "manifest_node": authority_root_personalization(AUTH_ROOT_NODE, 0),
        "state_snapshot": authority_root_personalization(AUTH_ROOT_SNAPSHOT),
    }
    calls = {
        "stablecoin_policy_constructor": 1,
        "manifest_leaf": 1,
        "manifest_node": 4,
        "state_snapshot": 1,
    }
    in_relation = []
    for family, raw_bytes in raw.items():
        item: dict[str, Any] = {
            "family": family,
            "calls": calls[family],
            "raw_preimage_bytes": raw_bytes,
            "personalization_hex": persons[family].hex(),
        }
        if family == "manifest_node":
            item["personalization_rule"] = (
                "HGMAROOT||03||02||40||04||level:u8||000000; level=0..3"
            )
            item["personalization_hex_by_level"] = [
                authority_root_personalization(AUTH_ROOT_NODE, level).hex()
                for level in range(AUTH_DEPTH)
            ]
        if profile_name == "blake2b512_rfc":
            item["message_bytes"] = raw_bytes
            item["blake2b512_compressions_per_call"] = blake_blocks(raw_bytes)
            item["domain_location"] = "BLAKE2b 16-byte personalization parameter"
        else:
            control_bytes = len(
                authority_control_frame(persons[family], bytes(raw_bytes))
            )
            item["message_bytes"] = control_bytes
            item["shake256_permutations_per_call"] = shake256_permutations(
                control_bytes
            )
            item["domain_location"] = (
                "absorbed HX512H01 control frame containing frozen personalization"
            )
        in_relation.append(item)

    state_writer_only = []
    for family, role, raw_min, raw_max in (
        ("stablecoin_oracle_constructor", AUTH_ID_ORACLE, 55, 4150),
        ("stablecoin_attestation_constructor", AUTH_ID_ATTESTATION, 59, 4154),
    ):
        person = authority_identity_personalization(role)
        item = {
            "family": family,
            "calls": 1,
            "raw_source_bytes": {"min": raw_min, "max": raw_max},
            "personalization_hex": person.hex(),
        }
        if profile_name == "blake2b512_rfc":
            item["message_bytes"] = {"min": raw_min, "max": raw_max}
            item["compression_range"] = {
                "min": blake_blocks(raw_min),
                "max": blake_blocks(raw_max),
            }
        else:
            control_min = len(authority_control_frame(person, bytes(raw_min)))
            control_max = len(authority_control_frame(person, bytes(raw_max)))
            item["message_bytes"] = {"min": control_min, "max": control_max}
            item["permutation_range"] = {
                "min": shake256_permutations(control_min),
                "max": shake256_permutations(control_max),
            }
        state_writer_only.append(item)
    return {
        "registry": DOMAIN_REGISTRIES[profile_name]["manifest_authority"],
        "source_pin": (
            ".agent/hardening/manifest-authority-closure/manifest_authority.py"
        ),
        "native_public_context_source_pin": (
            "protocol/kernel/src/stablecoin_manifest_authority_v2.rs"
        ),
        "in_relation": in_relation,
        "state_writer_only": state_writer_only,
        "alternate_generic_hx512_authority_frames_accepted": False,
    }


def profile_counts(profile_name: str) -> dict[str, Any]:
    profile = BLAKE_PROFILE if profile_name == "blake2b512_rfc" else SPLIT_PROFILE
    core = core_frame_schedule(profile)
    authority = authority_schedule(profile_name)
    if profile_name == "blake2b512_rfc":
        core_blake = 0
        for item in core:
            per = item.get("fixed_blake_compressions_per_call")
            if per is None:
                per = item["blake_compressions_per_call"]
            core_blake += item["calls"] * per
        authority_blake = sum(
            item["calls"] * item["blake2b512_compressions_per_call"]
            for item in authority["in_relation"]
        )
        if (core_blake, authority_blake) != (205, 8):
            raise AssertionError((core_blake, authority_blake))
        return {
            "core_physical_calls": 83,
            "authority_physical_calls": 7,
            "relation_physical_calls": 90,
            "core_blake2b512_compressions": core_blake,
            "authority_blake2b512_compressions": authority_blake,
            "relation_blake2b512_compressions": core_blake + authority_blake,
            "sha512_compressions": 0,
            "shake256_permutations": 0,
        }
    sha_compressions = 0
    shake_permutations = 0
    for item in core:
        if item["purpose"].startswith("secret"):
            per = item.get("fixed_sha512_compressions_per_call")
            if per is None:
                per = item["sha512_compressions_per_call"]
            sha_compressions += item["calls"] * per
        else:
            shake_permutations += item["calls"] * item["shake256_permutations_per_call"]
    authority_shake = sum(
        item["calls"] * item["shake256_permutations_per_call"]
        for item in authority["in_relation"]
    )
    if (sha_compressions, shake_permutations, authority_shake) != (37, 171, 12):
        raise AssertionError((sha_compressions, shake_permutations, authority_shake))
    return {
        "core_physical_calls": 83,
        "authority_physical_calls": 7,
        "relation_physical_calls": 90,
        "blake2b512_compressions": 0,
        "sha512_compressions": sha_compressions,
        "core_shake256_permutations": shake_permutations,
        "authority_shake256_permutations": authority_shake,
        "relation_shake256_permutations": shake_permutations + authority_shake,
    }


def r1cs_costs() -> dict[str, Any]:
    # Frozen odd-field compiler macro contract.
    blake_compression_rows = 576 * 192 + 403 * 64
    sha512_compression_rows = 760 * 192 + 160 * 64 + 62_464
    keccak_permutation_with_absorb_rows = 115_200 + 38_400 + 86 + 136 * 8
    if (blake_compression_rows, sha512_compression_rows, keccak_permutation_with_absorb_rows) != (
        136_384,
        218_624,
        154_774,
    ):
        raise AssertionError("primitive macro cost drift")

    frozen_hash_rows = 28 * blake_compression_rows + 75 + 50_688 + 105 * keccak_permutation_with_absorb_rows
    blake_core_rows = 205 * blake_compression_rows + 83 * 3 + 80_456
    blake_authority_hash_rows = 8 * blake_compression_rows + 7 * 3
    split_core_rows = 37 * sha512_compression_rows + 75_776 + 171 * keccak_permutation_with_absorb_rows
    split_authority_hash_rows = 12 * keccak_permutation_with_absorb_rows
    if frozen_hash_rows != 20_120_785:
        raise AssertionError("frozen hash row reconstruction drift")

    # All unchanged source groups are copied from the frozen macro compiler.
    # The changed aggregate widths are explicitly recomputed for 512-bit roots,
    # 64-byte masters, and the fresh manifest witness.
    fresh_non_hash_groups = OrderedDict(
        all_sixteen_activity_masks=4,
        signed_magnitude_ranges=139,
        canonical_asset_slots=3352,
        active_note_ranges=3104,
        selected_asset_equality=2292,
        inactive_input_zero=39_168,
        merkle_position_range=64,
        inactive_output_zero=40_704,
        ciphertext_size_and_padding=208,
        duplicate_nullifier_rejection=1025,
        authorization_mode_onehot=962,
        authorization_activity_shapes=10,
        mode_typing_and_unused_zero=17_291,
        accumulator_metadata=28_874,
        approval_transition=9847,
        native_balance=4819,
        ordinary_non_native_balance=1350,
        stablecoin_signed_balance=1551,
        stablecoin_unique_surface=2731,
        hash_link_note=6144,
        hash_link_nullifier=2048,
        hash_link_merkle=99_328,
        hash_link_policy_and_authorization=1536,
        hash_link_intent=512,
        hash_link_balance=512,
        hash_link_ciphertext=1024,
    )
    non_hash_rows = sum(fresh_non_hash_groups.values())
    if non_hash_rows != 268_599:
        raise AssertionError(non_hash_rows)
    source_bitness_rows = (STATEMENT_BYTES + VERIFIER_CONTEXT_BYTES + PRIVATE_BYTES) * 8
    statement_constant_rows = 10 * 8 + 208 * 8
    # Exact six-group closure emitted by hx512-full-relation-compile.  This is
    # broader than the frozen manifest-authority artifact's 6,237-row local
    # membership surface because it also binds statement fields, lifecycle,
    # disabled branches, snapshot, and verifier context.  There is no padding.
    authority_non_bitness_groups = OrderedDict(
        manifest_transport_and_selected_row_canonicality=186,
        selected_row_to_statement_equality=1_088,
        policy_identity_output_equality=512,
        selected_leaf_and_depth_four_root_recomputation=5_696,
        lifecycle_oracle_dispute_and_cap=1_934,
        snapshot_and_verifier_context_equality=2_176,
    )
    authority_non_bitness_rows = sum(authority_non_bitness_groups.values())
    if authority_non_bitness_rows != 11_592:
        raise AssertionError(authority_non_bitness_rows)
    authority_canonicality_breakdown = OrderedDict(
        selected_index_high_zero=28,
        manifest_transport_zero_padding=40,
        absent_retired_at_zero=64,
        stable_asset_high_zero=32,
        selected_leaf_present=1,
        three_row_boolean_bytes_high_seven_zero=21,
    )
    if sum(authority_canonicality_breakdown.values()) != 186:
        raise AssertionError(authority_canonicality_breakdown)
    manifest_root_recomputation_breakdown = OrderedDict(
        four_left_right_path_pair_selects=4_096,
        manifest_root_nonzero_reduction=511,
        enabled_implies_manifest_root_nonzero=1,
        recomputed_root_equals_statement_manifest_root=512,
        disabled_statement_manifest_root_and_height_zero=576,
    )
    if sum(manifest_root_recomputation_breakdown.values()) != 5_696:
        raise AssertionError(manifest_root_recomputation_breakdown)
    snapshot_context_breakdown = OrderedDict(
        snapshot_output_equals_statement_state_root=512,
        statement_manifest_root_equals_verifier_context_manifest_root=512,
        statement_height_equals_verifier_context_height=64,
        disabled_statement_state_root_and_verifier_context_zero=1_088,
    )
    if sum(snapshot_context_breakdown.values()) != 2_176:
        raise AssertionError(snapshot_context_breakdown)
    policy_master_constraint_breakdown = OrderedDict(
        single_key_current_and_next_zero=1_024,
        selected_current_or_next_master_for_policy_call=512,
        non_single_non_approval_inactive_master_zero=512,
        approval_current_equals_next=512,
    )
    if sum(policy_master_constraint_breakdown.values()) != 2_560:
        raise AssertionError(policy_master_constraint_breakdown)

    blake_total = (
        source_bitness_rows
        + statement_constant_rows
        + non_hash_rows
        + authority_non_bitness_rows
        + blake_core_rows
        + blake_authority_hash_rows
    )
    split_total = (
        source_bitness_rows
        + statement_constant_rows
        + non_hash_rows
        + authority_non_bitness_rows
        + split_core_rows
        + split_authority_hash_rows
    )
    if (blake_total, split_total) != (29_510_157, 36_868_145):
        raise AssertionError((blake_total, split_total))
    carrier_half = 1 << 25
    blake_n_upper_bound = blake_total + source_bitness_rows
    if not blake_n_upper_bound < carrier_half or not split_total > carrier_half:
        raise AssertionError("carrier threshold screen drift")
    return {
        "macro_contract": {
            "blake2b512_compression_rows": blake_compression_rows,
            "blake2b512_schedule": "576 add64; 403 64-bit XOR; RFC parameter 0x01010040 has three one bits per top-level call",
            "sha512_compression_rows": sha512_compression_rows,
            "sha512_schedule": "760 add64 including feed-forward; optimized one-AND Ch and one-AND Maj give 160 word AND; 62,464 bit XOR",
            "shake256_permutation_with_rate_absorb_rows": keccak_permutation_with_absorb_rows,
            "onehot_select5_rows_per_bit": 6,
            "authorization_blake_rows": 80_456,
            "authorization_blake_rows_decomposition": {
                "four_calls_three_padded_128_byte_blocks": 73_728,
                "four_calls_three_selected_64_bit_counters": 4_608,
                "four_calls_three_selected_final_flags": 72,
                "four_512_bit_two_vs_three_compression_state_selects": 2_048,
                "sum": 80_456,
            },
            "authorization_sha512_rows": 75_776,
        },
        "frozen_hx448c02": {
            "m_constraints": FROZEN_R1CS_ROWS,
            "reconstructed_hash_rows": frozen_hash_rows,
        },
        "fresh_shared": {
            "source_bitness_rows": source_bitness_rows,
            "statement_constant_rows": statement_constant_rows,
            "non_hash_groups": fresh_non_hash_groups,
            "non_hash_rows": non_hash_rows,
            "policy_master_constraint_rows": 2_560,
            "policy_master_constraint_rows_pre_correction": 1_536,
            "policy_master_constraint_rows_delta": 1_024,
            "policy_master_constraint_breakdown": (
                policy_master_constraint_breakdown
            ),
            "policy_master_constraint_equations_per_bit": [
                "s_single * current = 0",
                "s_single * next = 0",
                "s_init * (next-current) = selected-current",
                "(s_init+s_value_lock+s_final) * (current+next-selected) = 0",
                "s_approval * (current-next) = 0",
            ],
            "policy_master_equation_boundary": (
                "all mode selectors are the already-enforced Boolean one-hot "
                "selectors; selected is the exact policy-call prefix and the "
                "authorization mux sources current/next directly per schedule"
            ),
            "manifest_and_state_non_bitness_rows": authority_non_bitness_rows,
            "manifest_and_state_non_bitness_groups": authority_non_bitness_groups,
            "manifest_transport_and_selected_row_canonicality_breakdown": (
                authority_canonicality_breakdown
            ),
            "selected_leaf_and_depth_four_root_recomputation_breakdown": (
                manifest_root_recomputation_breakdown
            ),
            "snapshot_and_verifier_context_equality_breakdown": (
                snapshot_context_breakdown
            ),
            "policy_version_nonzero_rows": 0,
            "policy_version_domain": "all canonical u32 values including zero",
            "manifest_authority_local_surface_rows": 6_237,
            "row_count_boundary": (
                "11,592 is the exact broader six-group full-relation closure; "
                "it includes 21 high-byte zero constraints absent from the "
                "frozen 6,237-row authority-local screen, which otherwise "
                "subtracts 3,800 private and 576 public source-bitness rows. "
                "The 512-row recomputed-manifest-root equality is already in "
                "the 5,696-row group; correcting context from snapshot to "
                "manifest root changes no row multiplicity.  Policy version "
                "zero is source-valid and adds no nonzero predicate; no padding"
            ),
        },
        "blake2b512_rfc": {
            "core_hash_rows": blake_core_rows,
            "manifest_state_hash_rows": blake_authority_hash_rows,
            "m_constraints_source_static": blake_total,
            "delta_vs_frozen_hx448c02": blake_total - FROZEN_R1CS_ROWS,
            "n_nonconstant_variables_upper_bound": blake_n_upper_bound,
            "cfw26_half_length_screen": carrier_half,
            "half_length_2pow25_not_forced_to_grow": True,
        },
        "sha512_shake256_control": {
            "core_hash_rows": split_core_rows,
            "manifest_state_hash_rows": split_authority_hash_rows,
            "m_constraints_source_static": split_total,
            "delta_vs_frozen_hx448c02": split_total - FROZEN_R1CS_ROWS,
            "delta_vs_blake2b512_rfc": split_total - blake_total,
            "cfw26_half_length_minimum": 1 << 26,
            "half_length_2pow25_forced_to_grow_by_rows": True,
        },
        "claim_boundary": "exact only for this source macro expansion; no expanded matrix, compiler/DCE artifact, proof, or refinement exists",
    }


def _fraction(value: Fraction) -> dict[str, Any]:
    decimal_bits = -math.log2(value.numerator / value.denominator)
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "security_bits_display": decimal_bits,
        "strictly_below_2^-128": value < Fraction(1, 1 << 128),
    }


def security_ledgers() -> dict[str, Any]:
    q = 1 << 64
    history_role_targets = 15 * (1 << 32)
    conditional_terms = OrderedDict(
        prefix_multi_user_history=Fraction(2 * history_role_targets * q, 1 << 256),
        physical_call_preimage_union=Fraction(4 * 90 * q * q, 1 << 512),
        two_product_oracle_collision_union=Fraction(2 * 648 * (q + 1) ** 3, 1 << 512),
        adv_qro_inst_two_concrete_primitives=Fraction(2, 1 << 160),
        grinding_abort_budget=Fraction(1, 1 << 160),
        rng_failure_budget=Fraction(1, 1 << 160),
        activity_mask_authorization_mode_union=Fraction(80, 1 << 256),
        proof_history_union=Fraction(1 << 32, 1 << 256),
    )
    for name, value in conditional_terms.items():
        if value <= 0 or not value < Fraction(1, 1 << 128):
            raise AssertionError((name, value))
    conditional_total = sum(conditional_terms.values(), Fraction())
    if not conditional_total < Fraction(1, 1 << 128):
        raise AssertionError("conditional semantic slice does not exceed 128 bits")

    bcs_p_bits_floor = 10_737_660_800
    bcs = {
        "loss_formula": "p * 2^(-lambda/4+2)",
        "minimum_rate1_field_elements": 33_555_190,
        "field_element_bits": 320,
        "p_bits_rate1_floor": bcs_p_bits_floor,
        "lambda512": _fraction(Fraction(bcs_p_bits_floor, 1 << 126)),
        "lambda648": _fraction(Fraction(bcs_p_bits_floor, 1 << 160)),
        "lambda656": _fraction(Fraction(bcs_p_bits_floor, 1 << 162)),
        "lambda656_only_passes_rate1_floor": True,
        "actual_code_lengths_make_p_larger": True,
        "proof_salt_lambda_is_not_semantic_digest_width": True,
    }
    if bcs["lambda648"]["strictly_below_2^-128"]:
        raise AssertionError("lambda648 must fail the exact rate-one floor")
    if not bcs["lambda656"]["strictly_below_2^-128"]:
        raise AssertionError("lambda656 must pass only the exact rate-one floor")

    missing_full_terms = [
        "exact compiled relation refinement",
        "PCS binding/proximity/list-decoding/zero-evader",
        "IOP and RBR soundness/knowledge",
        "complete HVZK-to-NIZK simulator including aborts",
        "exact BCS/CMS augmented query expansion",
        "proof Merkle selective-opening hiding",
        "actual grinding and retry distribution",
        "wallet policy-master entropy generation retention and lifecycle",
        "parser/native/formal/lifecycle refinement",
        "release source and retained proof artifact closure",
    ]
    theorem_only = {
        "ledger": "theorem-only concrete deployed hashes",
        "q": str(q),
        "blake2b512_concrete_quantum_reduction": None,
        "sha512_concrete_qro_reduction": None,
        "shake256_concrete_qro_reduction": None,
        "adv_qro_inst": None,
        "overall_advantage": None,
        "security_bits": None,
        "strict_gt_128": False,
        "production_authorized": False,
        "verdict": "unbounded/fail-closed: standards and KATs are not finite deployed-hash QROM reductions",
    }
    conditional = {
        "ledger": "conditional explicit concrete-hash-as-QRO budget",
        "q": str(q),
        "history_role_targets": str(history_role_targets),
        "adv_qro_inst_assumption_per_concrete_primitive": _fraction(Fraction(1, 1 << 160)),
        "adv_qro_inst_is_nonzero": True,
        "terms": {name: _fraction(value) for name, value in conditional_terms.items()},
        "known_semantic_slice_total": _fraction(conditional_total),
        "known_semantic_slice_strict_gt_128": True,
        "missing_full_composition_terms": missing_full_terms,
        "overall_advantage": None,
        "overall_security_bits": None,
        "overall_strict_gt_128": False,
        "production_authorized": False,
        "assumption_boundary": "each of the two exact tagged concrete primitive products is assumed to have distinguishing advantage at most 2^-160; this is a nonzero assumption budget, not a theorem or measurement",
    }
    return {
        "artifact_schema": "hegemon.hx512-semantic-suite.security-ledgers.v1",
        "security_roles": list(SECURITY_ROLES),
        "theorem_only": theorem_only,
        "conditional_hash_as_qro": conditional,
        "bcs_cross_stack_blocker": bcs,
        "capabilities": {
            "complete_zk": False,
            "composed_strict_gt_128": False,
            "concrete_hash_qrom": False,
            "exact_full_relation_compiled": False,
            "measured_proof_bytes": None,
            "production_authorized": False,
        },
    }


def activity_mode_matrix() -> list[dict[str, Any]]:
    result = []
    for mask in range(16):
        i0, i1, o0, o1 = (bool(mask & (1 << bit)) for bit in range(4))
        for mode in AUTHORIZATION_MODES:
            nonempty = mask != 0
            if mode == "single_key":
                valid = nonempty
            elif mode in ("accumulator_init", "value_lock_creation"):
                valid = nonempty and (i0 or i1) and o0
            elif mode == "approval_step":
                valid = nonempty and i0 and i1 and o0
            else:
                valid = nonempty and i0 and i1
            result.append({"mask": mask, "mode": mode, "accept": valid})
    if len(result) != 80 or sum(row["accept"] for row in result) != 33:
        raise AssertionError("mask/mode matrix drift")
    return result


def policy_master_mode_schedule() -> list[dict[str, Any]]:
    """Canonical mapping for the two opening-specific 64-byte masters.

    The four authorization calls are named by slot and lane.  `None` means
    the selected arm is the fixed dummy frame and has no policy-master field.
    Lane A/B roles remain distinct even when they use the same opening master.
    """

    rows = [
        {
            "mode": "single_key",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": None,
                "slot0_lane_b": None,
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["current=zero64", "next=zero64"],
        },
        {
            "mode": "accumulator_init",
            "policy_call_master": "next",
            "auth_call_masters": {
                "slot0_lane_a": "next",
                "slot0_lane_b": "next",
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["current=zero64"],
        },
        {
            "mode": "approval_step",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": "next",
                "slot1_lane_b": "next",
            },
            "master_constraints": ["current=next"],
        },
        {
            "mode": "value_lock_creation",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["next=zero64"],
        },
        {
            "mode": "final_threshold_spend",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": "current",
                "slot1_lane_b": "current",
            },
            "master_constraints": ["next=zero64"],
        },
    ]
    if [row["mode"] for row in rows] != list(AUTHORIZATION_MODES):
        raise AssertionError("policy-master mode order drift")
    return rows


def require_policy_masters(mode: str, current: bytes, next_: bytes) -> None:
    """Check the exact unused-lane and approval-continuity contract."""

    _require_bytes("current policy master", current, POLICY_MASTER_BYTES)
    _require_bytes("next policy master", next_, POLICY_MASTER_BYTES)
    zero = bytes(POLICY_MASTER_BYTES)
    if mode == "single_key":
        valid = current == zero and next_ == zero
    elif mode == "accumulator_init":
        valid = current == zero
    elif mode == "approval_step":
        valid = current == next_
    elif mode in ("value_lock_creation", "final_threshold_spend"):
        valid = next_ == zero
    else:
        raise Reject("unknown authorization mode")
    if not valid:
        raise Reject("policy-master mode constraint")


def encode_manifest_row(marker: int = 1) -> bytes:
    if not 0 <= marker <= 255:
        raise Reject("manifest marker")
    out = bytearray(MANIFEST_ROW_BYTES)
    out[0:4] = (1001).to_bytes(4, "little")
    out[4:8] = (7).to_bytes(4, "little")
    out[8:16] = (0x0102030405060708).to_bytes(8, "little")
    out[16:32] = (1_500_000).to_bytes(16, "little")
    out[32:48] = (1_000_000_000).to_bytes(16, "little")
    out[48:56] = (120).to_bytes(8, "little")
    out[56:64] = (42).to_bytes(8, "little")
    out[64:72] = (10).to_bytes(8, "little")
    out[72] = 1
    out[73:81] = (1000).to_bytes(8, "little")
    out[81:85] = (3).to_bytes(4, "little")
    out[85] = 1
    out[86:150] = bytes([0x60 ^ marker]) * 64
    out[150:214] = bytes([0x70 ^ marker]) * 64
    out[214] = 0
    return bytes(out)


def canonical_oracle_source(asset_id: int = 1001, policy_version: int = 3) -> bytes:
    delta = asset_id - 1001
    if not 0 <= asset_id < 1 << 32 or not 0 <= policy_version < 1 << 32:
        raise Reject("oracle source integer width")
    payload = b"price:i128le=" + (123_456 + delta).to_bytes(16, "little")
    if not 1 <= len(payload) <= 4096:
        raise AssertionError("oracle sample payload")
    return (
        asset_id.to_bytes(4, "little")
        + policy_version.to_bytes(4, "little")
        + (7 + delta).to_bytes(4, "little")
        + (42).to_bytes(8, "little")
        + bytes([0x31 + delta % 31]) * 32
        + len(payload).to_bytes(2, "little")
        + payload
    )


def canonical_attestation_source(
    asset_id: int = 1001, policy_version: int = 3
) -> bytes:
    delta = asset_id - 1001
    if not 0 <= asset_id < 1 << 32 or not 0 <= policy_version < 1 << 32:
        raise Reject("attestation source integer width")
    payload = b"eligible:true"
    return (
        asset_id.to_bytes(4, "little")
        + policy_version.to_bytes(4, "little")
        + (0x0102_0304_0506_0708 + delta).to_bytes(8, "little")
        + (9).to_bytes(8, "little")
        + bytes([0x51 + delta % 31]) * 32
        + len(payload).to_bytes(2, "little")
        + payload
    )


def canonical_authority_row(asset_id: int = 1001, policy_version: int = 3) -> bytes:
    delta = asset_id - 1001
    oracle = authority_blake(
        canonical_oracle_source(asset_id, policy_version),
        authority_identity_personalization(AUTH_ID_ORACLE),
    )
    attestation = authority_blake(
        canonical_attestation_source(asset_id, policy_version),
        authority_identity_personalization(AUTH_ID_ATTESTATION),
    )
    out = bytearray(MANIFEST_ROW_BYTES)
    out[0:4] = asset_id.to_bytes(4, "little")
    out[4:8] = (7 + delta).to_bytes(4, "little")
    out[8:16] = (0x0102_0304_0506_0708 + delta).to_bytes(8, "little")
    out[16:32] = (1_500_000).to_bytes(16, "little")
    out[32:48] = (1_000_000_000).to_bytes(16, "little")
    out[48:56] = (120).to_bytes(8, "little")
    out[56:64] = (42).to_bytes(8, "little")
    out[64:72] = (10).to_bytes(8, "little")
    out[72] = 1
    out[73:81] = (1000).to_bytes(8, "little")
    out[81:85] = policy_version.to_bytes(4, "little")
    out[85] = 1
    out[86:150] = oracle
    out[150:214] = attestation
    out[214] = 0
    parse_manifest_row(bytes(out))
    return bytes(out)


def parse_manifest_row(raw: bytes) -> dict[str, Any]:
    _require_bytes("manifest row", raw, MANIFEST_ROW_BYTES)
    if raw[72] not in (0, 1) or raw[85] not in (0, 1) or raw[214] not in (0, 1):
        raise Reject("manifest booleans are noncanonical")
    if raw[72] == 0 and raw[73:81] != bytes(8):
        raise Reject("absent retirement has nonzero payload")
    return {
        "asset_id": int.from_bytes(raw[0:4], "little"),
        "policy_version": int.from_bytes(raw[81:85], "little"),
        "oracle_root": raw[86:150],
        "attestation_root": raw[150:214],
    }


def authority_digest(
    profile_name: str, raw: bytes, personalization: bytes
) -> bytes:
    if profile_name == "blake2b512_rfc":
        return authority_blake(raw, personalization)
    if profile_name == "sha512_shake256_control":
        return hashlib.shake_256(
            authority_control_frame(personalization, raw)
        ).digest(AUTH_WIDTH)
    raise Reject("unknown HX512 profile")


def stable_policy_hash(profile_name: str, row: bytes) -> bytes:
    return authority_digest(
        profile_name,
        stable_policy_tuple(row),
        authority_identity_personalization(AUTH_ID_POLICY),
    )


def manifest_root(profile_name: str, rows: Sequence[bytes]) -> bytes:
    parsed = [parse_manifest_row(row) for row in rows]
    keys = [(row["asset_id"], row["policy_version"]) for row in parsed]
    if len(rows) > MANIFEST_CAP or any(left >= right for left, right in zip(keys, keys[1:])):
        raise Reject("manifest cap/order/duplicate violation")
    slots = [b"\x01" + row for row in rows]
    slots += [bytes(1 + MANIFEST_ROW_BYTES)] * (MANIFEST_CAP - len(slots))
    level = [
        authority_digest(
            profile_name,
            slot,
            authority_root_personalization(AUTH_ROOT_LEAF),
        )
        for slot in slots
    ]
    tree_level = 0
    while len(level) > 1:
        level = [
            authority_digest(
                profile_name,
                level[i] + level[i + 1],
                authority_root_personalization(AUTH_ROOT_NODE, tree_level),
            )
            for i in range(0, len(level), 2)
        ]
        tree_level += 1
    if tree_level != AUTH_DEPTH:
        raise AssertionError("manifest depth drift")
    return level[0]


def stable_policy_tuple(row: bytes) -> bytes:
    parse_manifest_row(row)
    # Exact live tuple: asset, oracle feed, attestation id, collateral ratio,
    # cap, max age, policy version, active.  All integers remain SCALE LE.
    out = row[0:56] + row[81:86]
    if len(out) != 61:
        raise AssertionError(len(out))
    return out


def state_root(profile_name: str, manifest: bytes, height: int) -> bytes:
    _require_bytes("manifest root", manifest, 64)
    if not 0 <= height < 1 << 64:
        raise Reject("state height")
    return authority_digest(
        profile_name,
        height.to_bytes(8, "little") + manifest,
        authority_root_personalization(AUTH_ROOT_SNAPSHOT),
    )


def kats() -> dict[str, str]:
    expected = {
        "blake2b512_empty": "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        "blake2b512_abc": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        "sha512_empty": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "sha512_abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "shake256_512_empty": "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "shake256_512_abc": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        "authority_blake_policy": "866d201343968585d90f58e698c0648c34ff551da13c437e689da6ca29fe15719de8ac1fcba7b5b0cdca0db95b641a63a1483e94b9c52aabda5eaba75c7ea345",
        "authority_blake_oracle": "4f6600a35de08028d7b4e98cd60d7dcadd2086c67045b4d62272af12cced768637aac5215c00b7257e1eff51f56138f5b92e4b486bb870ac6ef64e142e2df25e",
        "authority_blake_attestation": "7b0434f952f572c2d74aa48461142842d3d504d2ffc01062d4d3c55afbfeddd549e07fdbd71709450b1d45d13eb0186dd7eb7b34b5aa83e557a40cda8b25905d",
        "authority_blake_manifest_root_cap16": "0c6cbb840c5523b58c3aae93e08fe17f956c7b22f7c43d05ef7d10f6d1dcdd1e7c4556ae983ed506d510bc8f607d7d3a714db420c9943ad4c7a6e75dd7ea9939",
        "authority_blake_snapshot_height50": "f7a60b50ef6cd848546be653fe427906c06062c18df3f34f6a887202cff7e576bcf6c13412d3da08f4397607c5080c53fd94b7decc90cff8200152d3e31004f2",
        "authority_control_policy": "05b90c3d3e320a2f59ae3f0ef3d4b8cce796cb21205eed54b3b1c514bbc0502c49edf660dbe603b59da5e9e06020c782c20198dd4f5da596b885e87bee998314",
        "authority_control_oracle": "8d47aba25b9d342fe32738f314ae1f4bfd441a2936468aaf5fe67addff329476a98d2e788867aa8c85fbf206cf3a1bd853a28c09e725881b18c53e9d5a75a557",
        "authority_control_attestation": "e9de667666c40b954287c47d14372c500437907223a62243348591e7004d8be5c7c1f7721c9df6f08131f2408bc64cd3b6d353996dfcc47461d62817887fe939",
        "authority_control_manifest_root_cap16": "2a83857edfdec38d94d31e6d374ea1b3ac3a17a918dc4346eb2831b135142d3c0b4250c63aa684adf90a93769760d565172bd969970e7c9058a4d9355c50a6a3",
        "authority_control_snapshot_height50": "386537281d2206b764afc11e760a8d662aa9754e91501208c192b484a820618a8e2ad017cc03d53fc912606518f60909d13bc00c34656c9321c03b9dd53743df",
    }
    sample_row = canonical_authority_row()
    sample_rows = [canonical_authority_row(1001 + index) for index in range(16)]
    blake_root = manifest_root("blake2b512_rfc", sample_rows)
    control_root = manifest_root("sha512_shake256_control", sample_rows)
    observed = {
        "blake2b512_empty": hashlib.blake2b(b"", digest_size=64).hexdigest(),
        "blake2b512_abc": hashlib.blake2b(b"abc", digest_size=64).hexdigest(),
        "sha512_empty": hashlib.sha512(b"").hexdigest(),
        "sha512_abc": hashlib.sha512(b"abc").hexdigest(),
        "shake256_512_empty": hashlib.shake_256(b"").hexdigest(64),
        "shake256_512_abc": hashlib.shake_256(b"abc").hexdigest(64),
        "authority_blake_policy": stable_policy_hash(
            "blake2b512_rfc", sample_row
        ).hex(),
        "authority_blake_oracle": authority_digest(
            "blake2b512_rfc",
            canonical_oracle_source(),
            authority_identity_personalization(AUTH_ID_ORACLE),
        ).hex(),
        "authority_blake_attestation": authority_digest(
            "blake2b512_rfc",
            canonical_attestation_source(),
            authority_identity_personalization(AUTH_ID_ATTESTATION),
        ).hex(),
        "authority_blake_manifest_root_cap16": blake_root.hex(),
        "authority_blake_snapshot_height50": state_root(
            "blake2b512_rfc", blake_root, 50
        ).hex(),
        "authority_control_policy": stable_policy_hash(
            "sha512_shake256_control", sample_row
        ).hex(),
        "authority_control_oracle": authority_digest(
            "sha512_shake256_control",
            canonical_oracle_source(),
            authority_identity_personalization(AUTH_ID_ORACLE),
        ).hex(),
        "authority_control_attestation": authority_digest(
            "sha512_shake256_control",
            canonical_attestation_source(),
            authority_identity_personalization(AUTH_ID_ATTESTATION),
        ).hex(),
        "authority_control_manifest_root_cap16": control_root.hex(),
        "authority_control_snapshot_height50": state_root(
            "sha512_shake256_control", control_root, 50
        ).hex(),
    }
    if observed != expected:
        raise AssertionError("standard KAT drift")
    return observed


def role_ledger() -> list[dict[str, Any]]:
    mappings = {
        "semantic.note_commitment": ("BLAKE2b-512", "SHA-512", "512-bit note blinding prefix"),
        "semantic.nullifier": ("BLAKE2b-512", "SHA-512", "derived 512-bit authorization key prefix"),
        "semantic.merkle_node": ("BLAKE2b-512", "SHAKE256-512", "public collision binding"),
        "semantic.spend_key_xof": ("two tagged BLAKE2b-512 calls", "two tagged SHA-512 calls", "512-bit spend master"),
        "semantic.authorization_policy": ("BLAKE2b-512", "SHA-512", "mode-selected current/next 512-bit policy master"),
        "semantic.authorization_accumulator": ("BLAKE2b-512", "SHA-512", "opening-specific current/next policy master; approval continuity equality; correlation hybrid required"),
        "semantic.authorization_value_lock": ("BLAKE2b-512", "SHA-512", "current policy master under a distinct lane role; correlation hybrid required"),
        "semantic.intent": ("BLAKE2b-512", "SHAKE256-512", "public collision binding"),
        "semantic.balance_tag": ("BLAKE2b-512", "SHAKE256-512", "public collision binding"),
        "semantic.ciphertext_hash": ("BLAKE2b-512", "SHAKE256-512", "canonical 2147-byte ciphertext"),
        "statement.stablecoin_policy_hash": ("personalized BLAKE2b-512 HGMAIDV2 role01", "SHAKE256-512 HX512H01 authority frame", "exact raw 61-byte tuple"),
        "statement.stablecoin_oracle_commitment": ("personalized BLAKE2b-512 HGMAIDV2 role02", "SHAKE256-512 HX512H01 authority frame", "raw 54-byte header plus 1..4096 payload"),
        "statement.stablecoin_attestation_commitment": ("personalized BLAKE2b-512 HGMAIDV2 role03", "SHAKE256-512 HX512H01 authority frame", "raw 58-byte header plus 1..4096 payload"),
        "proof.merkle_leaf": ("SHA-512 pending backend", "SHA-512 pending backend", "frame/count null until proof wire exists"),
        "proof.opened_leaf_random_tape": ("SHA-512 pending backend", "SHA-512 pending backend", "64-byte independent tape; frame/count null"),
    }
    return [
        {
            "id": role,
            "blake_profile": mappings[role][0],
            "split_profile": mappings[role][1],
            "source_or_property": mappings[role][2],
            "concrete_qrom_reduction_present": False,
        }
        for role in SECURITY_ROLES
    ]


def mutation_corpus() -> dict[str, Any]:
    cases = [
        "wrong_statement_magic",
        "wrong_statement_grammar",
        "all_empty_activity_mask",
        "non_boolean_activity_flag",
        "network_id_drift",
        "circuit_version_drift",
        "hash_suite_drift",
        "action_id_drift",
        "proof_profile_drift",
        "domain_set_drift",
        "chain_id_drift",
        "genesis_id_drift",
        "rules_hash_drift",
        "legacy_hx448c02_reinterpretation",
        "legacy_48_byte_policy_padding",
        "legacy_48_byte_oracle_rehash",
        "legacy_48_byte_attestation_truncation",
        "manifest_row_wrong_width",
        "manifest_retired_absent_nonzero",
        "manifest_non_boolean_active",
        "manifest_non_boolean_disputed",
        "manifest_duplicate_key",
        "manifest_out_of_order_key",
        "manifest_over_cap",
        "manifest_path_sibling_mutation",
        "manifest_index_high_bit",
        "state_height_mismatch",
        "state_root_mismatch",
        "verifier_context_snapshot_substitution",
        "verifier_context_height_big_endian",
        "stable_policy_tuple_byte_mutation",
        "oracle_source_length_mutation",
        "attestation_source_length_mutation",
        "frame_profile_mutation",
        "frame_role_mutation",
        "frame_field_count_mutation",
        "frame_field_length_mutation",
        "lane_a_b_alias",
        "authorization_selector_not_onehot",
        "authorization_selected_block_mutation",
        "authorization_counter_mutation",
        "authorization_final_flag_mutation",
        "policy_master_policy_call_wrong_selection",
        "policy_master_approval_rotation",
        "policy_master_inactive_nonzero",
        "blake_digest_parameter_56_instead_of_64",
        "sha512_padding_length_mutation",
        "shake_suffix_mutation",
        "adv_qro_inst_zero",
        "adv_qro_inst_missing",
        "q_budget_not_2pow64",
        "history_union_missing",
        "grinding_term_zero",
        "proof_bytes_non_null_without_artifact",
        "production_true_without_full_composition",
        "alternate_generic_hx512_authority_frame",
    ]
    if len(cases) != 56 or len(set(cases)) != len(cases):
        raise AssertionError("mutation corpus cardinality")
    return {
        "artifact_schema": "hegemon.hx512-semantic-suite.mutations.v1",
        "cases": [{"name": name, "expected": "reject_or_fail_closed"} for name in cases],
        "retained_mutations": len(cases),
    }


def build_report() -> dict[str, Any]:
    pins = source_pins()
    if not pins["all_match"]:
        raise Reject("frozen source pin mismatch")
    statement = sample_statement()
    parse_statement(statement, "blake2b512_rfc")
    row = canonical_authority_row()
    policy_root = stable_policy_hash("blake2b512_rfc", row)
    manifest = manifest_root("blake2b512_rfc", [row])
    state = state_root("blake2b512_rfc", manifest, 42)
    verifier_context = encode_verifier_context(manifest, 42)
    require_verifier_context(verifier_context, manifest, 42)
    bcounts = profile_counts("blake2b512_rfc")
    scounts = profile_counts("sha512_shake256_control")
    costs = r1cs_costs()
    report = {
        "artifact": "prospective HX512 conventional-hash semantic suite source certificate",
        "artifact_schema": "hegemon.hx512-semantic-suite.report.v1",
        "status": "source-cost winner only; no architecture or production authority",
        "selected_source_cost_profile": "blake2b512_rfc",
        "selection_reason": "29,510,157 source-static R1CS rows stays below 2^25 while the SHA-512/SHAKE256-512 control has 36,868,145 rows and therefore forces at least a 2^26 Section-11 half",
        "identity": IDENTITIES,
        "domain_registries": DOMAIN_REGISTRIES,
        "statement": {
            "bytes": STATEMENT_BYTES,
            "seven_byte_limbs": STATEMENT_LIMBS7,
            "eight_byte_words": STATEMENT_WORDS8,
            "eight_byte_zero_pad_bytes": STATEMENT_WORDS8 * 8 - STATEMENT_BYTES,
            "verifier_context_bytes": VERIFIER_CONTEXT_BYTES,
            "verifier_context": {
                "grammar": "manifest_root64 || parent_height:u64le",
                "layout": [
                    {"name": "manifest_root", "offset": 0, "bytes": 64},
                    {
                        "name": "parent_height_u64le",
                        "offset": 64,
                        "bytes": 8,
                    },
                ],
                "canonical_sample_hex": verifier_context.hex(),
                "snapshot_substitution_allowed": False,
                "native_source": (
                    "protocol/kernel/src/"
                    "stablecoin_manifest_authority_v2.rs::"
                    "StablecoinManifestPublicAuthorityV2"
                ),
            },
            "public_words_with_context": PUBLIC_WORDS8,
            "layout": statement_layout(),
            "delta_vs_hx448c02": {
                "bytes": STATEMENT_BYTES - FROZEN_STATEMENT_BYTES,
                "seven_byte_limbs": STATEMENT_LIMBS7 - FROZEN_STATEMENT_LIMBS7,
                "public_words_including_replaced_state_seam": PUBLIC_WORDS8 - FROZEN_PUBLIC_WORDS,
            },
        },
        "witness": {
            "transaction_base_bytes_before_ciphertexts": 6216,
            "two_padded_ciphertext_transport_bytes": 4304,
            "manifest_membership_semantic_bytes": MANIFEST_WITNESS_SEMANTIC_BYTES,
            "manifest_membership_transport_bytes": MANIFEST_WITNESS_TRANSPORT_BYTES,
            "bytes": PRIVATE_BYTES,
            "words": PRIVATE_WORDS8,
            "delta_vs_hx448c02": {
                "bytes": PRIVATE_BYTES - FROZEN_PRIVATE_BYTES,
                "words": PRIVATE_WORDS8 - FROZEN_PRIVATE_WORDS,
            },
            "independent_512_bit_sources": {
                "four_note_blindings_bytes": 256,
                "two_spend_masters_bytes": 128,
                "two_policy_masters_bytes": 128,
                "total_bytes": 512,
                "delta_vs_current_288_bytes": 224,
            },
            "policy_master_layout": [
                {
                    "name": "current_policy_master",
                    "offset": 6088,
                    "bytes": 64,
                },
                {
                    "name": "next_policy_master",
                    "offset": 6152,
                    "bytes": 64,
                },
            ],
            "policy_master_mode_schedule": policy_master_mode_schedule(),
            "policy_master_call_indices": {
                "policy": 74,
                "slot0_lane_a": 75,
                "slot0_lane_b": 77,
                "slot1_lane_a": 76,
                "slot1_lane_b": 78,
            },
            "policy_master_entropy_boundary": (
                "active masters are canonical 64-byte witnesses; relation "
                "equality/zero constraints do not prove uniform sampling"
            ),
            "transport_layout": [
                {"name": "transaction_base", "offset": 0, "bytes": 6216},
                {"name": "ciphertext_0_and_1_padded", "offset": 6216, "bytes": 4304},
                {"name": "manifest_membership", "offset": 10520, "bytes": 480},
            ],
            "manifest_membership_layout": [
                {"name": "selected_index_u32le", "offset": 0, "bytes": 4},
                {"name": "selected_row215", "offset": 4, "bytes": 215},
                {"name": "siblings_level0_through_3", "offset": 219, "bytes": 256},
                {"name": "canonical_zero_padding", "offset": 475, "bytes": 5},
            ],
        },
        "core_83_call_schedule": core_frame_schedule(BLAKE_PROFILE),
        "authority_schedule": authority_schedule("blake2b512_rfc"),
        "profile_counts": {
            "blake2b512_rfc": bcounts,
            "sha512_shake256_control": scounts,
        },
        "manifest": {
            "cap": MANIFEST_CAP,
            "depth": MANIFEST_DEPTH,
            "row_bytes": MANIFEST_ROW_BYTES,
            "row_layout": [
                ["asset_id_u32le", 0, 4],
                ["oracle_feed_u32le", 4, 4],
                ["attestation_id_u64le", 8, 8],
                ["min_collateral_ratio_ppm_u128le", 16, 16],
                ["max_mint_per_epoch_u128le", 32, 16],
                ["oracle_max_age_u64le", 48, 8],
                ["oracle_submitted_at_u64le", 56, 8],
                ["enabled_at_u64le", 64, 8],
                ["retired_present_bool", 72, 1],
                ["retired_at_u64le", 73, 8],
                ["policy_version_u32le", 81, 4],
                ["active_bool", 85, 1],
                ["oracle_root_512", 86, 64],
                ["attestation_root_512", 150, 64],
                ["attestation_disputed_bool", 214, 1],
            ],
            "strict_order": "numeric (asset_id,policy_version); duplicate and unsorted rows reject",
            "policy_version_domain": (
                "all canonical u32 values including zero; no nonzero predicate"
            ),
            "legacy_48_byte_migration": "reject padding, truncation, and rehash; recompute from canonical V2 source or reject",
            "canonical_sample_row_hex": row.hex(),
            "sample_policy_root": policy_root.hex(),
            "sample_manifest_root": manifest.hex(),
            "sample_state_root": state.hex(),
            "state_snapshot_preimage": "parent_height:u64le || manifest_root64",
            "state_snapshot_authority_boundary": "statement state_root is the derived snapshot; the exact verifier context is manifest_root64 || parent_height:u64le, and the native verifier must separately source and compare authenticated canonical-parent root and height",
            "recomputed_manifest_root_equality": (
                "already present as 512 conditional-equality rows inside the "
                "5,696-row depth-four root group"
            ),
        },
        "coverage": {
            "activity_masks": 16,
            "authorization_modes": 5,
            "mask_mode_pairs": 80,
            "accepted_pairs": 33,
            "rejected_pairs": 47,
            "stablecoin": "policy constructor, row equality, membership, lifecycle, freshness, dispute, nonzero issuance, cap, manifest root, state root, and verifier expected root/height are all in the proposed macro relation",
            "security_roles": role_ledger(),
        },
        "r1cs": costs,
        "kats": kats(),
        "proof": {
            "bytes": None,
            "artifact": None,
            "complete_zero_knowledge": False,
            "composed_pq128": False,
        },
        "capabilities": {
            "source_schedule_certified": True,
            "exact_full_relation_compiled": False,
            "complete_zero_knowledge": False,
            "composed_strict_gt_128": False,
            "native_verifier_refinement": False,
            "consensus_lifecycle_refinement": False,
            "production_authorized": False,
        },
    }
    descriptor = canonical_json(report)
    report["prospective_relation_descriptor_sha512"] = hashlib.sha512(
        b"hegemon.hx512-semantic-suite.relation-descriptor.v1\0" + descriptor
    ).hexdigest()
    return report


def outputs() -> dict[Path, bytes]:
    return {
        REPORT_PATH: canonical_json(build_report()),
        SECURITY_PATH: canonical_json(security_ledgers()),
        MUTATION_PATH: canonical_json(mutation_corpus()),
        PINS_PATH: canonical_json(source_pins()),
    }


def write_outputs() -> None:
    for path, payload in outputs().items():
        path.write_bytes(payload)


def check_outputs() -> None:
    for path, expected in outputs().items():
        if not path.is_file() or path.read_bytes() != expected:
            raise Reject(f"stale or missing generated artifact: {path.name}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    if sum((args.write, args.check, args.summary)) != 1:
        parser.error("select exactly one of --write, --check, --summary")
    if args.write:
        write_outputs()
    elif args.check:
        check_outputs()
    else:
        report = build_report()
        security = security_ledgers()
        print(
            "PASS",
            f"winner={report['selected_source_cost_profile']}",
            f"blake_rows={report['r1cs']['blake2b512_rfc']['m_constraints_source_static']}",
            f"split_rows={report['r1cs']['sha512_shake256_control']['m_constraints_source_static']}",
            f"conditional_bits={security['conditional_hash_as_qro']['known_semantic_slice_total']['security_bits_display']:.6f}",
            "production=false",
            "proof_bytes=null",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
