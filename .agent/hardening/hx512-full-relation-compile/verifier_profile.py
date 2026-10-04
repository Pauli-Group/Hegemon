#!/usr/bin/env python3
"""Canonical non-self-referential diagnostic relation profile for HX512B01.

The 64-byte SHA-512 digest of :func:`descriptor_bytes` is the test-only value
carried by ``statement.rules_hash`` in this isolated executable model.  The
descriptor contains values only: it contains no source hashes, artifact
digests, generated-manifest digest, or copy of its own digest.  A future native
final consensus value cannot be allocated until the fresh wide-ZK SmallWood
arithmetization, packing, PCS/IOP, transcript, and wire are frozen.  No legacy
K64/SMZ2/SWV6 identity may be reinterpreted for this relation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


FIELD_MODULUS = 0xFFFFFFFF00000001
STATEMENT_BYTES = 1_141
CONTEXT_BYTES = 72
PRIVATE_BYTES = 11_000

BLAKE2B_IV = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

ZERO_PERSON = bytes(16)
POLICY_PERSON = b"HGMAIDV2\x01\x02\x40" + bytes(5)
LEAF_PERSON = b"HGMAROOT\x02\x02\x40\x04\x00" + bytes(3)
NODE_PERSONS = tuple(
    b"HGMAROOT\x03\x02\x40\x04" + bytes([level]) + bytes(3)
    for level in range(4)
)
SNAPSHOT_PERSON = b"HGMAROOT\x04\x02\x40\x04\x00" + bytes(3)

STATEMENT_LAYOUT = (
    ("magic", 0, 8), ("grammar", 8, 2), ("flags", 10, 4),
    ("anchor", 14, 64), ("nullifiers", 78, 128),
    ("commitments", 206, 128), ("ciphertext_hashes", 334, 128),
    ("ciphertext_sizes", 462, 8), ("assets", 470, 32),
    ("fee", 502, 8), ("value_balance_sign", 510, 1),
    ("value_balance_magnitude", 511, 8), ("stable_enabled", 519, 1),
    ("stable_asset", 520, 8), ("stable_version", 528, 4),
    ("stable_issuance_sign", 532, 1),
    ("stable_issuance_magnitude", 533, 8), ("stable_policy", 541, 64),
    ("stable_oracle", 605, 64), ("stable_attestation", 669, 64),
    ("manifest_root", 733, 64), ("state_root", 797, 64),
    ("state_height", 861, 8), ("balance_tag", 869, 64),
    ("activation", 933, 8), ("network", 941, 4), ("backend", 945, 1),
    ("profile", 946, 1), ("domain_set", 947, 2), ("chain_id", 949, 64),
    ("genesis_id", 1013, 64), ("rules_hash", 1077, 64),
)

WITNESS_LAYOUT = (
    ("input[0]", 0, 2_384), ("input[1]", 2_384, 2_384),
    ("output[0]", 4_768, 264), ("output[1]", 5_032, 264),
    ("authorization", 5_296, 792), ("policy_masters", 6_088, 128),
    ("ciphertext[0]", 6_216, 2_152), ("ciphertext[1]", 8_368, 2_152),
    ("manifest_membership", 10_520, 480),
)

SEMANTIC_FAMILIES = (
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
    "note commitments and resolved authorization keys",
    "nullifier derivation and active public equality",
    "32-level Merkle direction selection and anchor equality",
    "policy and four authorization-lane digest links",
    "final-spend intent equality",
    "public balance-tag equality",
    "canonical ciphertext hash equality",
    "all-W64 manifest transport and selected-row canonicality",
    "all-W64 selected row to statement equality",
    "all-W64 policy identity output equality",
    "all-W64 selected leaf and depth-four root recomputation",
    "all-W64 selected lifecycle oracle dispute and cap",
    "all-W64 snapshot reconstruction and verifier context equality",
)

def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def parameter_block(person: bytes) -> bytes:
    if len(person) != 16:
        raise ValueError("BLAKE2b personalization must be exactly 16 bytes")
    value = bytearray(64)
    value[0] = 64  # digest length
    value[1] = 0   # no key
    value[2] = 1   # fanout
    value[3] = 1   # depth
    value[48:64] = person
    return bytes(value)


def constant_folded_initial_state(person: bytes) -> tuple[int, ...]:
    block = parameter_block(person)
    words = tuple(
        int.from_bytes(block[index * 8 : (index + 1) * 8], "little")
        for index in range(8)
    )
    return tuple(BLAKE2B_IV[index] ^ words[index] for index in range(8))


def parameter_profiles() -> tuple[dict[str, Any], ...]:
    values = (
        ("core-zero-person", ZERO_PERSON),
        ("authority-policy", POLICY_PERSON),
        ("authority-leaf", LEAF_PERSON),
        *((f"authority-node-{level}", person) for level, person in enumerate(NODE_PERSONS)),
        ("authority-snapshot", SNAPSHOT_PERSON),
    )
    return tuple(
        {
            "name": name,
            "personalization_hex": person.hex(),
            "parameter_block_hex": parameter_block(person).hex(),
            "constant_folded_initial_state_u64le_hex": [
                f"{word:016x}" for word in constant_folded_initial_state(person)
            ],
        }
        for name, person in values
    )


def _calls(first: int, count: int, family: str, role: bytes, width: int, compressions: int) -> list[dict[str, Any]]:
    return [
        {
            "index": first + offset,
            "family": family,
            "role_hex": role.hex(),
            "message_bytes": width,
            "fixed_compressions": compressions,
            "parameter_profile": "core-zero-person",
        }
        for offset in range(count)
    ]


def hash_call_profiles() -> tuple[dict[str, Any], ...]:
    calls: list[dict[str, Any]] = []
    calls += _calls(0, 4, "note_commitment", b"nt.b5121", 256, 2)
    calls += _calls(4, 2, "nullifier", b"nf.b5121", 143, 2)
    calls += _calls(6, 64, "merkle_node", b"mk.b5121", 149, 2)
    calls += _calls(70, 2, "spend_key_lane_a", b"sk.b51a1", 93, 1)
    calls += _calls(72, 2, "spend_key_lane_b", b"sk.b51b1", 93, 1)
    calls += _calls(74, 1, "authorization_policy", b"pl.b5121", 499, 4)
    calls += _calls(75, 2, "authorization_lane_a", b"au.b51a1", 263, 3)
    calls += _calls(77, 2, "authorization_lane_b", b"au.b51b1", 263, 3)
    calls += _calls(79, 1, "intent", b"in.b5121", 968, 8)
    calls += _calls(80, 1, "balance_tag", b"bl.b5121", 100, 1)
    calls += _calls(81, 2, "ciphertext_hash", b"ct.b5121", 2182, 18)
    authority = (
        (83, "stablecoin_policy_constructor", "authority-policy", POLICY_PERSON, 61, 1),
        (84, "manifest_leaf", "authority-leaf", LEAF_PERSON, 216, 2),
        *((85 + level, f"manifest_node[{level}]", f"authority-node-{level}", person, 128, 1)
          for level, person in enumerate(NODE_PERSONS)),
        (89, "state_snapshot", "authority-snapshot", SNAPSHOT_PERSON, 72, 1),
    )
    for index, family, profile, person, width, compressions in authority:
        calls.append(
            {
                "index": index,
                "family": family,
                "role_hex": person.hex(),
                "message_bytes": width,
                "fixed_compressions": compressions,
                "parameter_profile": profile,
            }
        )
    calls.sort(key=lambda item: item["index"])
    if [item["index"] for item in calls] != list(range(90)):
        raise AssertionError("hash-call profile coverage")
    return tuple(calls)


def expected_personalization_hex_by_call() -> tuple[str, ...]:
    profiles = {item["name"]: item for item in parameter_profiles()}
    return tuple(
        profiles[item["parameter_profile"]]["personalization_hex"]
        for item in hash_call_profiles()
    )


def descriptor() -> dict[str, Any]:
    return {
        "artifact_schema": "hegemon.hx512b01.diagnostic-relation-profile.v1",
        "diagnostic_relation_identity": {
            "statement_magic_ascii": "HX512B01",
            "statement_grammar_u16be": 1,
            "circuit_version_u16be": 0x5121,
            "crypto_suite_u16be": 0x512B,
            "family_id_u16be": 0x5123,
            "action_id_u16be": 0x5124,
            "network_id_u32be": 0x48583531,
            "backend_id_u8": 0x51,
            "proof_profile_u8": 0x52,
            "domain_set_u16be": 0x5127,
            "identity_scope": "isolated source-model fixtures only",
            "production_identity_allocated": False,
            "diagnostic_rules_hash_construction": "test-only SHA-512(canonical diagnostic descriptor bytes including one trailing LF)",
            "final_consensus_rules_hash_frozen": False,
            "final_consensus_rules_hash_hex": None,
        },
        "relation_grammar": {
            "statement_bytes": STATEMENT_BYTES,
            "statement_layout": [list(item) for item in STATEMENT_LAYOUT],
            "verifier_context": "manifest_root64 || parent_height:u64le",
            "verifier_context_bytes": CONTEXT_BYTES,
            "private_witness_bytes": PRIVATE_BYTES,
            "private_witness_layout": [list(item) for item in WITNESS_LAYOUT],
            "activity_masks": 16,
            "authorization_modes": [
                "single_key", "accumulator_init", "approval_step",
                "value_lock_creation", "final_threshold_spend",
            ],
            "accepted_mask_mode_pairs": 33,
            "stablecoin_axis": ["disabled-unique-zero", "enabled-all-W64"],
            "semantic_families": list(SEMANTIC_FAMILIES),
        },
        "relation_hash_program": {
            "algorithm": "RFC7693-BLAKE2b-512",
            "physical_calls": 90,
            "fixed_compressions": 213,
            "parameter_blocks": list(parameter_profiles()),
            "parameter_policy": "all fixed parameter/personalization blocks are constant-folded; caller-supplied parameters reject",
            "parameter_constraint_rows": 0,
            "authorization_control_policy": {
                "fixed_slots_per_call": 3,
                "mode_selected_message_blocks_counters_final_flags_and_digest_state": True,
                "selection_rows": 80_456,
                "constant_folded": False,
            },
            "calls": list(hash_call_profiles()),
        },
        "odd_field_projection": {
            "field_modulus_decimal": str(FIELD_MODULUS),
            "equation": "(A*z)*(B*z)=C*z",
            "m_constraints": 29_509_887,
            "n_nonconstant_variables": 21_531_579,
            "l_public_variables": 9_704,
            "auxiliary_variables_total": 21_521_875,
            "derived_auxiliary_variables": 21_433_875,
            "matrix_nonzeros_total": 123_197_556,
            "z_vector_length_including_constant_one": 21_531_580,
            "section11_half_length": 1 << 25,
            "constraint_degree": 2,
            "sparse_coordinates_emitted": False,
            "exact_full_production_relation": False,
            "projection_scope": "current incomplete diagnostic grammar only",
        },
        "known_production_semantic_blockers": {
            "positive_issuance_requires_issuer_or_collateral_capability": False,
            "minimum_collateral_ratio_evaluated": False,
            "epoch_mint_cap_is_cumulative_and_atomic": False,
            "no_input_anchor_is_canonical_or_verifier_authenticated": False,
            "activity_mask_mode_grammar_matches_active_native_route": False,
            "live_route_value_balance_zero_enforced": False,
            "repair_requires_fresh_grammar_profile_and_consensus_refinement": True,
        },
        "proof_system_required_but_unallocated": {
            "architecture_family": "SmallWood LPPC/PIOP/DECS",
            "fresh_arithmetization_identity": None,
            "packing_factor": None,
            "pcs_parameters": None,
            "piop_parameters": None,
            "decs_parameters": None,
            "complete_zk_mask_width_and_tape_grammar": None,
            "fiat_shamir_transcript": None,
            "transcript_domain_registry": None,
            "inner_wire_magic": None,
            "outer_envelope_magic": None,
            "outer_envelope_version": None,
            "statement_and_context_binding_preamble": None,
            "required_relation_rows": 29_509_887,
            "required_hx512_statement_bytes": STATEMENT_BYTES,
            "required_hx512_verifier_context_bytes": CONTEXT_BYTES,
            "minimum_packing_target_note": "fresh wide-ZK geometry is expected near K=1024 but is not frozen",
            "rejected_legacy_identities": [
                "DirectPacked64CompressedV6Sha512Smz2",
                "SMZ2",
                "SWV6",
                "HGV6PB02",
                "HGS6BC02",
                "K64",
                "64-byte strict-ZK leaf tape",
            ],
            "engine_adapter_integrated": False,
            "final_profile_frozen": False,
        },
    }


def descriptor_bytes() -> bytes:
    return canonical_json(descriptor())


def rules_hash() -> bytes:
    return hashlib.sha512(descriptor_bytes()).digest()


DIAGNOSTIC_RULES_HASH = rules_hash()
