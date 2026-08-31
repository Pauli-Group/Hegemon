#!/usr/bin/env python3
"""Exact, fail-closed screens for conventional 15-role hash-suite escapes.

This is a source-only design ledger.  It deliberately cannot authorize a
profile: the standard constructions below still lack at least one applicable,
exact concrete-hash/QROM bridge, and the proof-system composition is open.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from dataclasses import asdict, dataclass


TARGET_BITS = 128
LOW_QUERIES = 1 << 64
WORK_QUERIES = 1 << 128
COLLISION_ALPHA = 648

# Frozen facts from the diagnostic-only HX448C02 grammar.  It has eleven
# 56-byte relation/consensus digests and three exact live 48-byte stablecoin
# compatibility authorities.
HX448C02_STATEMENT_BYTES = 869
HX448C02_WIDE_DIGEST_FIELDS = 11
HX448C02_WIDE_DIGEST_BYTES = 56
HX448C02_STABLECOIN_FIELDS = 3
HX448C02_STABLECOIN_BYTES = 48
STATEMENT_LIMB_BYTES = 7

CURRENT_FIXED_SECRET_BYTES = 4 * 48 + 2 * 48
SHA2_TYPED_QRO_SECRET_BYTES = 4 * 64 + 2 * 64 + 2 * 64
KMAC_1568_SECRET_BYTES = 4 * 196 + 2 * 196 + 2 * 196

ESCAPE_PROFILE = "HXQ400A1"


@dataclass(frozen=True)
class RoleSpec:
    role_id: str
    required_property: str
    source_secrecy: str
    construction: str
    domains: tuple[str, ...]
    source_owner: str
    source_grammar_defined: bool
    concrete_bridge: bool = False
    instantiated: bool = False


# This registry is an audit-only proposal. Its exact profile and domains make
# accidental role aliasing visible, but do not allocate a consensus identity or
# turn a concrete conventional hash into an ideal oracle.
ROLE_SPECS = (
    RoleSpec(
        "semantic.note_commitment",
        "collision+commitment-hiding",
        "secret",
        "SHA-512-left400 with fresh 512-bit blinding prefix",
        ("nt.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.nullifier",
        "qPRF+collision",
        "secret",
        "SHA-512-left400 with input spend master prefix",
        ("nf.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.merkle_node",
        "collision",
        "public",
        "SHA-512-left400",
        ("mk.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.spend_key_xof",
        "qPRF+KDF",
        "secret",
        "two independently tagged SHA-512-left400 calls per spend master",
        ("sk.s2a01", "sk.s2b01"),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.authorization_policy",
        "collision+commitment-hiding",
        "secret",
        "SHA-512-left400 with selected policy master prefix",
        ("pl.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.authorization_accumulator",
        "qPRF+collision+commitment-hiding",
        "secret",
        "SHA-512-left400 with opening-specific policy master prefix",
        ("au.ac401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.authorization_value_lock",
        "qPRF+collision+commitment-hiding",
        "secret",
        "separately tagged SHA-512-left400 with policy master prefix",
        ("au.vl401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.intent",
        "collision",
        "public",
        "SHA-512-left400",
        ("in.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.balance_tag",
        "collision",
        "public",
        "SHA-512-left400",
        ("bl.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "semantic.ciphertext_hash",
        "collision",
        "public",
        "SHA-512-left400",
        ("ct.s2401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "statement.stablecoin_policy_hash",
        "robust-collision",
        "public",
        "retain live BLAKE2b-384 field and add SHA-512-left400 constructor",
        ("sc.pl401",),
        "circuits/transaction/src/full_blake2b448_relation.rs",
        True,
    ),
    RoleSpec(
        "statement.stablecoin_oracle_commitment",
        "collision-or-secret-hiding",
        "unknown",
        "retain live field and add typed SHA-512-left400 constructor",
        ("sc.or401",),
        "protocol/kernel/src/manifest.rs",
        False,
    ),
    RoleSpec(
        "statement.stablecoin_attestation_commitment",
        "collision-or-secret-hiding",
        "unknown",
        "retain live field and add typed SHA-512-left400 constructor",
        ("sc.at401",),
        "protocol/kernel/src/manifest.rs",
        False,
    ),
    RoleSpec(
        "proof.merkle_leaf",
        "collision+commitment-hiding",
        "mixed",
        "full typed SHA-512",
        ("pf.lf401",),
        "circuits/transaction/src/smallwood_engine.rs",
        True,
    ),
    RoleSpec(
        "proof.opened_leaf_random_tape",
        "commitment-hiding",
        "secret",
        "full typed SHA-512 over independent 64-byte tape and leaf index",
        ("pf.tp401",),
        "circuits/transaction/src/smallwood_engine.rs",
        True,
    ),
)


def encode_role_registry(roles: tuple[RoleSpec, ...] = ROLE_SPECS) -> bytes:
    return json.dumps(
        {
            "schema": "hegemon.smallwood.qrom-standard-role-registry.v1",
            "profile": ESCAPE_PROFILE,
            "roles": [asdict(role) for role in roles],
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def role_registry_digest(roles: tuple[RoleSpec, ...] = ROLE_SPECS) -> str:
    return hashlib.sha512(encode_role_registry(roles)).hexdigest()


def role_registry_is_valid(roles: tuple[RoleSpec, ...] = ROLE_SPECS) -> bool:
    role_ids = [role.role_id for role in roles]
    domains = [domain for role in roles for domain in role.domains]
    return (
        len(roles) == 15
        and len(set(role_ids)) == len(role_ids)
        and len(set(domains)) == len(domains)
        and len(ESCAPE_PROFILE) == 8
        and all(len(domain) == 8 and domain.isascii() for domain in domains)
        and all(role.source_owner for role in roles)
        and all(not role.concrete_bridge and not role.instantiated for role in roles)
        and {role.role_id for role in roles if not role.source_grammar_defined}
        == {
            "statement.stablecoin_oracle_commitment",
            "statement.stablecoin_attestation_commitment",
        }
    )


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div requires numerator >= 0 and denominator > 0")
    return (numerator + denominator - 1) // denominator


def strict_fraction_below_power_of_two(
    numerator: int, denominator: int, target_bits: int
) -> bool:
    """Return numerator/denominator < 2^-target_bits, using integers only."""

    if numerator < 0 or denominator <= 0 or target_bits < 0:
        raise ValueError("invalid non-negative fraction or target")
    return numerator * (1 << target_bits) < denominator


def ideal_qro_collision_passes(
    output_bits: int, quantum_queries: int, target_bits: int
) -> bool:
    """GMP21 Lemma 6 screen: 648*(q+1)^3/2^output_bits."""

    numerator = COLLISION_ALPHA * (quantum_queries + 1) ** 3
    return strict_fraction_below_power_of_two(
        numerator, 1 << output_bits, target_bits
    )


def minimum_collision_output_bits(
    quantum_queries: int, target_bits: int
) -> int:
    bits = 0
    while not ideal_qro_collision_passes(bits, quantum_queries, target_bits):
        bits += 1
    return bits


def minimum_byte_aligned_collision_output_bits(
    quantum_queries: int, target_bits: int
) -> int:
    return 8 * ceil_div(
        minimum_collision_output_bits(quantum_queries, target_bits), 8
    )


def maximum_passing_collision_power_of_two_query_exponent(
    output_bits: int, target_bits: int
) -> int:
    exponent = 0
    while ideal_qro_collision_passes(output_bits, 1 << exponent, target_bits):
        exponent += 1
    return exponent - 1


def secret_prefix_qprf_passes(
    key_bits: int,
    users: int,
    quantum_queries: int,
    target_bits: int = TARGET_BITS,
) -> bool:
    """Conservative multi-user hybrid of 2*q/sqrt(|K|), exact for even k."""

    if key_bits < 0 or key_bits % 2 or users <= 0 or quantum_queries < 0:
        raise ValueError("key_bits must be even; users positive; queries non-negative")
    return strict_fraction_below_power_of_two(
        2 * users * quantum_queries,
        1 << (key_bits // 2),
        target_bits,
    )


def maximum_passing_power_of_two_query_exponent(
    key_bits: int, users: int, target_bits: int = TARGET_BITS
) -> int:
    exponent = 0
    while secret_prefix_qprf_passes(
        key_bits, users, 1 << exponent, target_bits
    ):
        exponent += 1
    return exponent - 1


def minimum_denominator_bits(
    numerator: int, target_bits: int = TARGET_BITS
) -> int:
    """Minimum lambda with numerator/2^lambda < 2^-target_bits."""

    if numerator <= 0:
        raise ValueError("numerator must be positive")
    bits = target_bits
    while not strict_fraction_below_power_of_two(
        numerator, 1 << bits, target_bits
    ):
        bits += 1
    return bits


def measure_reprogram_best_case_multiplier(quantum_queries: int) -> int:
    """DFM20 Corollary 13 coefficient for the optimistic n=1 case."""

    if quantum_queries < 0:
        raise ValueError("queries must be non-negative")
    return (2 * quantum_queries + 2) ** 2


def replacement_statement_bytes(output_bytes: int) -> int:
    """Replace all fourteen digest authorities (a compatibility migration)."""

    if output_bytes <= 0:
        raise ValueError("output_bytes must be positive")
    removed = (
        HX448C02_WIDE_DIGEST_FIELDS * HX448C02_WIDE_DIGEST_BYTES
        + HX448C02_STABLECOIN_FIELDS * HX448C02_STABLECOIN_BYTES
    )
    return HX448C02_STATEMENT_BYTES - removed + 14 * output_bytes


def redesigned_statement_limbs(output_bytes: int) -> int:
    return ceil_div(replacement_statement_bytes(output_bytes), STATEMENT_LIMB_BYTES)


def fixed_target_compatibility_statement_bytes(output_bytes: int) -> int:
    """Retain the three live 48-byte fields and resize the other eleven."""

    if output_bytes <= 0:
        raise ValueError("output_bytes must be positive")
    return (
        HX448C02_STATEMENT_BYTES
        - HX448C02_WIDE_DIGEST_FIELDS * HX448C02_WIDE_DIGEST_BYTES
        + HX448C02_WIDE_DIGEST_FIELDS * output_bytes
    )


def additive_compatibility_statement_bytes(output_bytes: int) -> int:
    """Retain live fields and add three fresh strict-width constructor outputs."""

    return (
        fixed_target_compatibility_statement_bytes(output_bytes)
        + HX448C02_STABLECOIN_FIELDS * output_bytes
    )


def additive_compatibility_statement_limbs(output_bytes: int) -> int:
    return ceil_div(
        additive_compatibility_statement_bytes(output_bytes), STATEMENT_LIMB_BYTES
    )


@dataclass(frozen=True)
class Frame:
    calls: int
    bytes: int


# A fresh 400-bit grammar preserves HX448C02's canonical application-frame
# rule (8-byte profile, 8-byte role, one-byte arity, and two-byte lengths).
# Intent continues to bind the first fourteen statement bytes and omits only
# anchor + two nullifiers, matching the live diagnostic relation.
SHA512_LEFT400_FRAMES = {
    "note": Frame(4, 242),
    "nullifier": Frame(2, 143),
    "merkle": Frame(64, 121),
    "spend_lane": Frame(4, 93),
    "policy": Frame(1, 415),
    "authorization_lane": Frame(4, 235),
    # The additive compatibility grammar is 953 bytes and omits only the
    # 50-byte anchor and two 50-byte nullifiers: 953-150+19 = 822.
    "intent": Frame(1, 822),
    "balance": Frame(1, 100),
    "ciphertext": Frame(2, 2_182),
}


def sha512_compressions(message_bytes: int) -> int:
    """FIPS 180-4: one 0x80 byte plus one 128-bit length field."""

    return ceil_div(message_bytes + 17, 128)


def sha512_left400_schedule() -> dict[str, object]:
    per_role = {
        role: frame.calls * sha512_compressions(frame.bytes)
        for role, frame in SHA512_LEFT400_FRAMES.items()
    }
    return {
        "logical_invocations": 79,
        "physical_calls": sum(frame.calls for frame in SHA512_LEFT400_FRAMES.values()),
        "compressions_by_role": per_role,
        "compressions": sum(per_role.values()),
    }


def keccak_absorb_permutations(message_bytes: int, rate_bytes: int) -> int:
    """Delimited-suffix padding always contributes a final absorb permutation."""

    if message_bytes < 0 or rate_bytes <= 0:
        raise ValueError("invalid Keccak message or rate")
    return message_bytes // rate_bytes + 1


def split_sha3_shake_schedule() -> dict[str, object]:
    """SHA3-512-left400 secret roles plus SHAKE256-400 public roles."""

    secret_names = (
        "note",
        "nullifier",
        "spend_lane",
        "policy",
        "authorization_lane",
    )
    public_names = ("merkle", "intent", "balance", "ciphertext")
    secret = {
        name: SHA512_LEFT400_FRAMES[name].calls
        * keccak_absorb_permutations(SHA512_LEFT400_FRAMES[name].bytes, 72)
        for name in secret_names
    }
    public = {
        name: SHA512_LEFT400_FRAMES[name].calls
        * keccak_absorb_permutations(SHA512_LEFT400_FRAMES[name].bytes, 136)
        for name in public_names
    }
    return {
        "sha3_512_permutations_by_role": secret,
        "shake256_permutations_by_role": public,
        "sha3_512_permutations": sum(secret.values()),
        "shake256_permutations": sum(public.values()),
        "permutations": sum(secret.values()) + sum(public.values()),
    }


# In HMAC/KDF mode, the independent key is the construction key rather than a
# message field.  Removing that field changes the nullifier/spend/auth messages
# to 77/27/169 bytes.  This is a lower-bound schedule: it assumes already
# uniform keys, no HKDF-Extract, and one HMAC call for each 400-bit lane.
HMAC_SHA512_MESSAGES = {
    "nullifier": Frame(2, 77),
    "spend_lane": Frame(4, 27),
    "authorization_lane": Frame(4, 169),
}


def hmac_sha512_compressions(message_bytes: int) -> int:
    """HMAC-SHA-512 with a <=128-byte key: inner key block + outer two blocks."""

    return 3 + ceil_div(message_bytes + 17, 128)


def hmac_sha512_schedule() -> dict[str, object]:
    raw_roles = {
        "note": SHA512_LEFT400_FRAMES["note"],
        "policy": SHA512_LEFT400_FRAMES["policy"],
        "merkle": SHA512_LEFT400_FRAMES["merkle"],
        "intent": SHA512_LEFT400_FRAMES["intent"],
        "balance": SHA512_LEFT400_FRAMES["balance"],
        "ciphertext": SHA512_LEFT400_FRAMES["ciphertext"],
    }
    raw = sum(
        frame.calls * sha512_compressions(frame.bytes)
        for frame in raw_roles.values()
    )
    keyed_by_role = {
        role: frame.calls * hmac_sha512_compressions(frame.bytes)
        for role, frame in HMAC_SHA512_MESSAGES.items()
    }
    return {
        "raw_sha512_compressions": raw,
        "hmac_sha512_compressions_by_role": keyed_by_role,
        "hmac_sha512_compressions": sum(keyed_by_role.values()),
        "compressions": raw + sum(keyed_by_role.values()),
    }


def kmac_tuplehash_schedule() -> dict[str, object]:
    """KMAC256/TupleHash256 schedule for 1568-bit external keys.

    Customization strings are at most sixteen bytes.  KMAC's cSHAKE prefix is
    one rate block, bytepad(encode_string(K),136) is two blocks, and the
    remaining counts include right_encode(L) and final padding.  TupleHash
    encodes one canonical frame per call and includes its one-block prefix.
    """

    secret = {
        "note": 4 * 5,
        "nullifier": 2 * 4,
        "spend_800": 2 * 4,
        "policy": 1 * 6,
        "authorization_800": 2 * 5,
    }
    public = {
        "merkle": 64 * 2,
        # 822-byte intent frame + three-byte encode_string length +
        # three-byte right_encode(400) occupies seven post-prefix blocks.
        "intent": 1 * 8,
        "balance": 1 * 2,
        "ciphertext": 2 * 18,
    }
    return {
        "secret_kmac_permutations_by_role": secret,
        "public_tuplehash_permutations_by_role": public,
        "secret_kmac_permutations": sum(secret.values()),
        "public_tuplehash_permutations": sum(public.values()),
        "permutations": sum(secret.values()) + sum(public.values()),
    }


def blake2b400_schedule() -> dict[str, object]:
    """RFC 7693 keyed/unkeyed BLAKE2b-400 source-count schedule."""

    # External 64-byte keys consume BLAKE2b's mandatory padded key block.
    keyed_messages = {
        "note": Frame(4, 176),
        "nullifier": Frame(2, 77),
        "spend_lane": Frame(4, 27),
        "policy": Frame(1, 349),
        "authorization_lane": Frame(4, 169),
    }
    public_messages = {
        "merkle": Frame(64, 121),
        "intent": Frame(1, 822),
        "balance": Frame(1, 100),
        "ciphertext": Frame(2, 2_182),
    }
    keyed = {
        role: frame.calls * (1 + ceil_div(frame.bytes, 128))
        for role, frame in keyed_messages.items()
    }
    public = {
        role: frame.calls * ceil_div(frame.bytes, 128)
        for role, frame in public_messages.items()
    }
    return {
        "keyed_compressions_by_role": keyed,
        "public_compressions_by_role": public,
        "keyed_compressions": sum(keyed.values()),
        "public_compressions": sum(public.values()),
        "compressions": sum(keyed.values()) + sum(public.values()),
    }


def full_sha512_schedule() -> dict[str, object]:
    frames = {
        "note": Frame(4, 256),
        "nullifier": Frame(2, 143),
        "merkle": Frame(64, 149),
        "spend_lane": Frame(4, 93),
        "policy": Frame(1, 499),
        "authorization_lane": Frame(4, 263),
        # 1,149-byte additive full-width statement minus three 64-byte
        # anchor/nullifier values plus 19 bytes of canonical frame overhead.
        "intent": Frame(1, 976),
        "balance": Frame(1, 100),
        "ciphertext": Frame(2, 2_182),
    }
    by_role = {
        role: frame.calls * sha512_compressions(frame.bytes)
        for role, frame in frames.items()
    }
    return {"compressions_by_role": by_role, "compressions": sum(by_role.values())}


def report() -> dict[str, object]:
    min_collision_bits = minimum_collision_output_bits(WORK_QUERIES, 1)
    min_collision_byte_bits = minimum_byte_aligned_collision_output_bits(
        WORK_QUERIES, 1
    )
    lnp_lite_min_bits = minimum_denominator_bits(5)
    q2_counterfactual_min_bits = minimum_denominator_bits(
        5 * WORK_QUERIES
    )
    dfm_best_case_multiplier = measure_reprogram_best_case_multiplier(LOW_QUERIES)
    users_epoch = 15 * (1 << 32)
    flags = {
        "standard_suite_selected": False,
        "concrete_hash_qrom_bridge": False,
        "all_15_roles_instantiated": False,
        "proof_system_qrom_composed": False,
        "lazer_pack_qrom_authorized": False,
        "composed_pq128": False,
        "production_authorized": False,
    }
    return {
        "schema": "hegemon.smallwood.qrom-standard-suite-escape-hatch.v1",
        "status": "valid-negative",
        "role_registry": {
            "profile": ESCAPE_PROFILE,
            "encoded_bytes": len(encode_role_registry()),
            "sha512": role_registry_digest(),
            "valid": role_registry_is_valid(),
            "roles": [asdict(role) for role in ROLE_SPECS],
        },
        "target": {
            "strict_advantage_bits": TARGET_BITS,
            "low_quantum_queries": LOW_QUERIES,
            "work_factor_quantum_queries": WORK_QUERIES,
        },
        "ideal_qro_collision": {
            "bound": "648*(q+1)^3/2^n",
            "minimum_integer_output_bits_at_q_2pow128_for_success_lt_half": min_collision_bits,
            "minimum_byte_aligned_output_bits": min_collision_byte_bits,
            "sha384_output_passes": ideal_qro_collision_passes(384, WORK_QUERIES, 1),
            "sha392_output_passes": ideal_qro_collision_passes(392, WORK_QUERIES, 1),
            "sha400_output_passes": ideal_qro_collision_passes(400, WORK_QUERIES, 1),
        },
        "statement": {
            "source_candidate": "HX448C02",
            "source_bytes": HX448C02_STATEMENT_BYTES,
            "source_wide_digest_fields": HX448C02_WIDE_DIGEST_FIELDS,
            "source_stablecoin_compatibility_fields": HX448C02_STABLECOIN_FIELDS,
            "source_stablecoin_compatibility_bytes_each": HX448C02_STABLECOIN_BYTES,
            "redesign_digest_bits": 400,
            "replacement_migration_bytes": replacement_statement_bytes(50),
            "replacement_migration_seven_byte_limbs": redesigned_statement_limbs(50),
            "fixed_target_compatibility_bytes": fixed_target_compatibility_statement_bytes(50),
            "additive_compatibility_bytes": additive_compatibility_statement_bytes(50),
            "additive_compatibility_seven_byte_limbs": additive_compatibility_statement_limbs(50),
        },
        "sha512_left400_typed_qro_candidate": {
            "classification": "FIPS SHA-512 with FIPS 180-4 section-7 left truncation; explicit idealized tagged-product-QRO assumption, not a theorem",
            "secret_key_bytes": SHA2_TYPED_QRO_SECRET_BYTES,
            "secret_key_delta_bytes": SHA2_TYPED_QRO_SECRET_BYTES
            - CURRENT_FIXED_SECRET_BYTES,
            "frames": {name: asdict(frame) for name, frame in SHA512_LEFT400_FRAMES.items()},
            "schedule_before_stablecoin_constructors": sha512_left400_schedule(),
            "stablecoin_constructor_schedule": {
                "calls": 3,
                "policy_tuple_bytes": 61,
                "policy_frame_bytes": 80,
                "policy_sha512_compressions": 1,
                "oracle_source_bytes": None,
                "attestation_source_bytes": None,
                "total_sha512_compressions": "204 + 1 + ceil((oracle_source_bytes+36)/128) + ceil((attestation_source_bytes+36)/128)",
            },
            "idealized_low_budget_terms": {
                "collision_numerator": COLLISION_ALPHA * (LOW_QUERIES + 1) ** 3,
                "collision_denominator": 1 << 400,
                "epoch_secret_prefix_numerator": 15,
                "epoch_secret_prefix_denominator": 1 << 159,
                "full_15_role_hash_composition_available": False,
            },
            "epoch_secret_prefix_log2_bound": math.log2(2 * users_epoch * LOW_QUERIES)
            - 256,
        },
        "hmac_hkdf_sha512_candidate": {
            "classification": "standard construction; deployed-SHA512 QROM bridge and exact HKDF composition absent",
            "schedule": hmac_sha512_schedule(),
        },
        "split_sha3_512_shake256_candidate": {
            "classification": "standard constructions; concrete Keccak/QROM bridge and keyed-role reduction absent",
            "secret_key_bytes": SHA2_TYPED_QRO_SECRET_BYTES,
            "secret_key_delta_bytes": SHA2_TYPED_QRO_SECRET_BYTES
            - CURRENT_FIXED_SECRET_BYTES,
            "schedule": split_sha3_shake_schedule(),
        },
        "kmac256_tuplehash256_candidate": {
            "classification": "QIPM keyed theorem candidate; concrete Keccak bridge absent",
            "uniform_key_bits": 1_568,
            "secret_key_bytes": KMAC_1568_SECRET_BYTES,
            "secret_key_delta_bytes": KMAC_1568_SECRET_BYTES
            - CURRENT_FIXED_SECRET_BYTES,
            "schedule": kmac_tuplehash_schedule(),
        },
        "blake2b400_candidate": {
            "classification": "conventional RFC-specified construction with classical theorem only; no QROM bridge",
            "secret_key_bytes": SHA2_TYPED_QRO_SECRET_BYTES,
            "secret_key_delta_bytes": SHA2_TYPED_QRO_SECRET_BYTES
            - CURRENT_FIXED_SECRET_BYTES,
            "schedule": blake2b400_schedule(),
        },
        "full_sha512_candidate": {
            "statement_bytes": additive_compatibility_statement_bytes(64),
            "statement_seven_byte_limbs": additive_compatibility_statement_limbs(64),
            "schedule": full_sha512_schedule(),
        },
        "conditional_query_caps": {
            "definition_changed": False,
            "consensus_enforceable": False,
            "collision384_low_advantage_max_power": maximum_passing_collision_power_of_two_query_exponent(384, 128),
            "collision384_work_screen_max_power": maximum_passing_collision_power_of_two_query_exponent(384, 1),
            "k384_single_user_max_power": maximum_passing_power_of_two_query_exponent(384, 1),
            "k384_u_2pow33_max_power": maximum_passing_power_of_two_query_exponent(384, 1 << 33),
            "k384_u_15x2pow32_max_power": maximum_passing_power_of_two_query_exponent(384, users_epoch),
            "k448_u_2pow33_max_power": maximum_passing_power_of_two_query_exponent(448, 1 << 33),
            "k448_u_15x2pow32_max_power": maximum_passing_power_of_two_query_exponent(448, users_epoch),
        },
        "lazer_pack_lnp_lite": {
            "stated_leading_term": "5/2^128",
            "stated_leading_term_bits": 128 - math.log2(5),
            "minimum_term_denominator_bits": lnp_lite_min_bits,
            "minimum_byte_aligned_term_denominator_bits": 8
            * ceil_div(lnp_lite_min_bits, 8),
            "official_transcript_state_bytes": 16,
            "shake128_fips_classical_preimage_cap_bits": 128,
            "shake128_generic_quantum_preimage_cap_bits": 64,
            "output_widening_repairs_capacity_cap": False,
            "counterfactual_exact_q_squared_loss_minimum_bits": q2_counterfactual_min_bits,
            "counterfactual_exact_q_squared_loss_minimum_byte_aligned_bits": 8
            * ceil_div(q2_counterfactual_min_bits, 8),
            "dfm20_corollary13_best_case_n": 1,
            "dfm20_corollary13_best_case_multiplier": dfm_best_case_multiplier,
            "dfm20_lnp_leading_term_minimum_bits": minimum_denominator_bits(
                5 * dfm_best_case_multiplier
            ),
            "dfm20_combined_challenge_term": "3*(2*q_H+2)^2/|C| (Pack's 2/|C| plus reduction's 1/|C|)",
            "dfm20_combined_challenge_minimum_bits": minimum_denominator_bits(
                3 * dfm_best_case_multiplier
            ),
            "published_applicable_qrom_transform": False,
        },
        "unresolved_terms": [
            "concrete deployed-hash to QRO/QIPM bridge with explicit constants",
            "multi-user and correlated-key PRF/KDF composition",
            "commitment hiding and selective/adaptive opening",
            "PCS/IOP knowledge soundness",
            "Fiat-Shamir QROM transformation",
            "grinding/retry/abort and global-history union",
            "complete zero knowledge and verifier/refinement binding",
        ],
        "capabilities": flags,
    }


def main() -> int:
    print(json.dumps(report(), indent=2, sort_keys=True))
    return 2


if __name__ == "__main__":
    sys.exit(main())
