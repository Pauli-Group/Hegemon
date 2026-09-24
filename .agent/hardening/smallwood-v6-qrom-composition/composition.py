#!/usr/bin/env python3
"""Exact, fail-closed PQ/QROM accounting for the prospective SmallWood V6 proof.

This module is deliberately not a production authorizer.  It recomputes the
integer/rational PCS/IOP/CMS/Fiat--Shamir/hash/sampler/history ledger, binds the
calculation to checker-owned source roles, and reports every missing reduction.
No candidate-provided Boolean can turn those missing reductions into authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import stat
import sys
from fractions import Fraction
from pathlib import Path
from typing import NoReturn


PROFILE_SCHEMA = "hegemon.smallwood.v6-qrom-composition-profile.v2"
REPORT_SCHEMA = "hegemon.smallwood.v6-qrom-composition-report.v2"
PROFILE_ID = "hegemon.smallwood.v6.rejected-hgf6hr02-keccak-c1024-xof.sha512.qrom-composition.v2"
SOURCE_MANIFEST_DOMAIN = b"hegemon.smallwood.v6.relation-manifest.sha512.v1\0"
HASH_ROLE_REGISTRY_DOMAIN = b"hegemon.smallwood.v6.hash-role-registry.sha512.v1\0"
HASH_ROLE_REGISTRY_ID = "hegemon.smallwood.v6.hash-role-audit-registry.v2"
RELATION_HASH_ROLE_REGISTRY_MAGIC = b"HGF6HR02"
RELATION_HASH_ROLE_REGISTRY_BYTES = 214

GOLDILOCKS_ORDER = 0xFFFF_FFFF_0000_0001
SHA512_BITS = 512
SHAKE256_SEMANTIC_BITS = 448
STATEMENT_BYTES = 893
STATEMENT_LIMB_BYTES = 7
PUBLIC_FIELD_COUNT = 128
STATEMENT_PADDING_ZERO_BYTES = 3
CONSENSUS_BINDING_BYTES = 56
INTENT_PAYLOAD_BYTES = 725
INTENT_FRAME_BYTES = 744
SEMANTIC_SHAKE_INVOCATIONS = 79
SEMANTIC_KECCAK_PERMUTATIONS = 145
PRIVATE_SHAKE_INVOCATIONS = 75
PRIVATE_KECCAK_PERMUTATIONS = 104
CIPHERTEXT_COUNT = 2
CIPHERTEXT_BYTES = 2_147
CIPHERTEXT_FRAME_BYTES = 2_182
CIPHERTEXT_SHAKE_INVOCATIONS = 2
CIPHERTEXT_KECCAK_PERMUTATIONS = 34
COLLISION_ONLY_SHAKE256_KECCAK_PERMUTATIONS = 105
SHA3_512_SPLIT_SECRET_KECCAK_PERMUTATIONS = 46
SHA3_512_SPLIT_TOTAL_KECCAK_PERMUTATIONS = 151
HMAC_SHA3_512_SPLIT_SECRET_KECCAK_PERMUTATIONS_LOWER_BOUND = 68
HMAC_SHA3_512_SPLIT_TOTAL_KECCAK_PERMUTATIONS_LOWER_BOUND = 173
SUCCESSOR_PRIMITIVE_INVOCATIONS = 83
BLAKE2B_UNKEYED_SECRET_COMPRESSIONS = 28
BLAKE2B_UNKEYED_MIXED_PRIMITIVE_CORES = 133
BLAKE2B_KEYED_SECRET_COMPRESSIONS = 32
BLAKE2B_KEYED_MIXED_PRIMITIVE_CORES = 137
PINNED_CONVENTIONAL_SCALAR_SHA512 = "b029ebec35c9d001d245b843a7ae918a2578ec961f7b0bd6097eb28950644ab2c2a9d9bfc58d87db39ad225b940347eaaaf3f678c3462663d07c3b5c59f0ceab"
PINNED_M4_MIXED_CANDIDATE_SHA512 = "1cf8ca5c3b5202cadc8bfe2b075a0a844f31f69ba4ebc646dde672cca94dc72c50c22c856ce3763939d0005f7c90968b5ac56385174d36cfeb99d46ad6495a14"
PINNED_M4_SOURCE_CHECKER_SHA512 = "29aa5e390f86a3f2d8c31d7d393d24acd4b9115dcd5d324911a4f761d11a5042636c5f96f8d8fc893db4bb56885ab2385bfa864b33669f32790509c7b2fe3ce3"
PINNED_M4_BINIUS_TREE_SHA512 = "1aead2b02df1b30bc217ae4d0337ccf9ab7fa1e42dabcc8f0c0a91aef6059eb7fe55fef123583a9af2e2d769566618f2c5e734b2afce0b0d006c695de8cab052"
OPENED_LEAF_RANDOM_TAPE_BYTES = 64
OPENED_LEAF_TAPE_BYTES_TOTAL = 23 * OPENED_LEAF_RANDOM_TAPE_BYTES

LOW_QUERY_EXPONENT = 64
LOW_TARGET_BITS = 128
WORK_QUERY_EXPONENT = 128
WORK_MAX_SUCCESS = Fraction(1, 2)
SECURITY_EPOCH_PROOF_BUDGET = 2**32
MAX_PROOFS_PER_BLOCK = 10_000

MAX_PROFILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024

EXPECTED_IDENTITY = {
    "circuit": 6,
    "crypto": 5,
    "family": 1,
    "action": 8,
    "backend": 2,
    "profile": 3,
    "domain_set": 2,
}

EXPECTED_SOURCE_ROLES = {
    "smallwood_engine": "circuits/transaction/src/smallwood_engine.rs",
    "statement_owner": "circuits/transaction/src/full_shake448_statement.rs",
    "hash448_registry": "crypto/hash448/src/lib.rs",
    "shake_boolean_relation": "circuits/transaction/src/smallwood_shake256_full_relation.rs",
    "full_relation": "circuits/transaction/src/full_shake448_relation.rs",
    "conventional_scalar_candidate": "circuits/transaction/src/full_blake2b448_relation.rs",
    "m4_mixed_candidate": "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs",
    "m4_source_checker": "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/check_source.py",
    "v6_envelope": "circuits/transaction/src/smallwood_v6_envelope.rs",
    "v6_adapter": "circuits/transaction/src/smallwood_v6_adapter.rs",
    "compiled_verifier": "circuits/transaction/src/smallwood_frontend.rs",
    "composition_checker": ".agent/hardening/smallwood-v6-qrom-composition/composition.py",
}

QUANTITATIVE_EXTERNAL_LOSSES = (
    "lppc_lvcs_decs_pcs_binding",
    "lppc_piop_knowledge_soundness",
    "fiat_shamir_qrom_transform",
    "sha512_standard_to_tagged_product_oracle",
    "sha512_merkle_pcs_binding",
    "sha512_xof_sampling_and_rejection",
    "mixed_shake_relation_instantiation_binding",
    "shake256_collision_binding",
    "nonstandard_keccak_c1024_xof_collision_binding",
    "nonstandard_keccak_c1024_xof_preimage_prf_security",
    "decs_leaf_tape_qrom_hiding",
    "noninteractive_proof_of_knowledge_extraction",
    "global_history_product_oracle_transfer",
    "grinding_retry_abort_composition",
)

STRICT_ROLE_TARGET_BITS = 128
NONSTANDARD_WIDE_XOF = "KECCAK-f1600-rate72-capacity1024-XOF-suffix1f"


def _hash_role(
    role_id: str,
    role_class: str,
    primitive: str,
    output_bits: int,
    domain_owner: str,
    domain_constant: str | None,
    domain_ascii: str | None,
    required_properties: list[str],
    second_preimage_mode: str,
    unavoidable_preimage_or_prf: bool,
    status: str = "required-target",
) -> dict[str, object]:
    return {
        "id": role_id,
        "class": role_class,
        "primitive": primitive,
        "output_bits": output_bits,
        "domain_owner": domain_owner,
        "domain_constant": domain_constant,
        "domain_ascii": domain_ascii,
        "required_properties": required_properties,
        "second_preimage_mode": second_preimage_mode,
        "unavoidable_preimage_or_prf": unavoidable_preimage_or_prf,
        "status": status,
    }


# This inventory is checker-owned.  A profile cannot remove a property, relabel
# a secret derivation as collision-only, or silently move a domain to a wider
# primitive.  Such a migration needs a fresh protocol/profile/domain identity.
EXPECTED_HASH_ROLES: tuple[dict[str, object], ...] = (
    _hash_role(
        "semantic.note_commitment",
        "semantic-commitment",
        NONSTANDARD_WIDE_XOF,
        448,
        "statement_owner",
        "ROLE_NOTE_COMMITMENT",
        "note.cm3",
        ["collision-binding", "preimage-hiding"],
        "reduced-to-collision",
        True,
    ),
    _hash_role(
        "semantic.nullifier",
        "semantic-keyed-prf",
        NONSTANDARD_WIDE_XOF,
        448,
        "statement_owner",
        "ROLE_NULLIFIER",
        "nullif.2",
        ["collision-binding", "prf-key-derivation"],
        "reduced-to-collision",
        True,
    ),
    _hash_role(
        "semantic.merkle_node",
        "semantic-merkle-binding",
        "SHAKE256",
        448,
        "statement_owner",
        "ROLE_MERKLE_NODE",
        "merk.nd2",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
    _hash_role(
        "semantic.spend_key_xof",
        "semantic-secret-xof-kdf",
        NONSTANDARD_WIDE_XOF,
        896,
        "statement_owner",
        "ROLE_SPEND_KEYS",
        "sp.keys2",
        ["preimage-hiding", "prf-key-derivation", "random-oracle-xof"],
        "not-required",
        True,
    ),
    _hash_role(
        "semantic.authorization_policy",
        "semantic-private-policy-commitment",
        NONSTANDARD_WIDE_XOF,
        448,
        "statement_owner",
        "ROLE_POLICY",
        "policy.1",
        ["collision-binding", "preimage-hiding"],
        "reduced-to-collision",
        True,
    ),
    _hash_role(
        "semantic.authorization_accumulator",
        "semantic-private-authorization-kdf",
        NONSTANDARD_WIDE_XOF,
        896,
        "statement_owner",
        "ROLE_ACCUMULATOR",
        "accum.01",
        ["collision-binding", "preimage-hiding", "prf-key-derivation"],
        "reduced-to-collision",
        True,
    ),
    _hash_role(
        "semantic.authorization_value_lock",
        "semantic-private-authorization-kdf",
        NONSTANDARD_WIDE_XOF,
        896,
        "statement_owner",
        "ROLE_VALUE_LOCK",
        "val.lock",
        ["collision-binding", "preimage-hiding", "prf-key-derivation"],
        "reduced-to-collision",
        True,
    ),
    _hash_role(
        "semantic.intent",
        "semantic-public-binding",
        "SHAKE256",
        448,
        "statement_owner",
        "ROLE_INTENT",
        "intent.1",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
    _hash_role(
        "semantic.balance_tag",
        "semantic-public-binding",
        "SHAKE256",
        448,
        "statement_owner",
        "ROLE_BALANCE_TAG",
        "bal.tag1",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
    _hash_role(
        "semantic.ciphertext_hash",
        "semantic-public-ciphertext-binding",
        "SHAKE256",
        448,
        "statement_owner",
        "ROLE_CIPHERTEXT_HASH",
        "ct.hash1",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
    _hash_role(
        "semantic.authorization_dummy",
        "fixed-shape-non-authoritative-padding",
        NONSTANDARD_WIDE_XOF,
        896,
        "full_relation",
        None,
        None,
        [],
        "not-required",
        False,
        "non-authoritative-padding",
    ),
    _hash_role(
        "statement.stablecoin_policy_hash",
        "opaque-public-stablecoin-policy-binding",
        "UNBOUND-OPAQUE-56",
        448,
        "statement_owner",
        None,
        None,
        ["collision-binding"],
        "reduced-to-collision",
        False,
        "opaque-authority-no-v6-construction",
    ),
    _hash_role(
        "statement.stablecoin_oracle_commitment",
        "opaque-public-oracle-record-binding",
        "UNBOUND-OPAQUE-56",
        448,
        "statement_owner",
        None,
        None,
        ["collision-binding"],
        "reduced-to-collision",
        False,
        "opaque-authority-no-v6-construction",
    ),
    _hash_role(
        "statement.stablecoin_attestation_commitment",
        "opaque-public-attestation-record-binding",
        "UNBOUND-OPAQUE-56",
        448,
        "statement_owner",
        None,
        None,
        ["collision-binding"],
        "reduced-to-collision",
        False,
        "opaque-authority-no-v6-construction",
    ),
    *tuple(
        _hash_role(
            role_id,
            role_class,
            "SHAKE256",
            448,
            "hash448_registry" if constant != "TRANSACTION_PROOF_BINDING_V6" else "hash448_registry",
            constant,
            domain,
            ["collision-binding"],
            "reduced-to-collision",
            False,
        )
        for role_id, role_class, constant, domain in (
            ("consensus.rules_manifest", "consensus-manifest-binding", "RULES_MANIFEST_V6", "hegemon.v6.rules-manifest.shake256-448.v1"),
            ("consensus.genesis_id", "consensus-object-binding", "GENESIS_ID_V6", "hegemon.v6.genesis-id.shake256-448.v1"),
            ("consensus.chain_id", "consensus-object-binding", "CHAIN_ID_V6", "hegemon.v6.chain-id.shake256-448.v1"),
            ("consensus.block_id", "consensus-object-binding", "BLOCK_ID_V6", "hegemon.v6.block-id.shake256-448.v1"),
            ("consensus.action_id", "consensus-object-binding", "ACTION_ID_V6", "hegemon.v6.action-id.shake256-448.v1"),
            ("consensus.action_semantic_id", "consensus-object-binding", "ACTION_SEMANTIC_ID_V6", "hegemon.v6.action-semantic-id.shake256-448.v1"),
            ("consensus.action_root", "consensus-merkle-binding", "ACTION_ROOT_V6", "hegemon.v6.action-root.shake256-448.v1"),
            ("consensus.commitment_tree_root", "consensus-merkle-binding", "COMMITMENT_TREE_ROOT_V6", "hegemon.v6.commitment-tree-root.shake256-448.v1"),
            ("consensus.nullifier_accumulator_root", "consensus-accumulator-binding", "NULLIFIER_ACCUMULATOR_ROOT_V6", "hegemon.v6.nullifier-accumulator-root.shake256-448.v1"),
            ("consensus.state_root", "consensus-state-binding", "STATE_ROOT_V6", "hegemon.v6.state-root.shake256-448.v1"),
            ("consensus.transaction_proof_binding", "consensus-proof-binding", "TRANSACTION_PROOF_BINDING_V6", "hegemon.v6.transaction-proof-binding.shake256-448.v1"),
        )
    ),
    *tuple(
        _hash_role(
            role_id,
            role_class,
            "SHA-512",
            512,
            "statement_owner",
            constant,
            domain,
            properties,
            second_preimage,
            unavoidable,
            status,
        )
        for role_id, role_class, constant, domain, properties, second_preimage, unavoidable, status in (
            ("proof.inline_binding", "fiat-shamir-binding", "V6_PROOF_BINDING_DOMAIN", "hegemon.smallwood.v6-epsilon.inline-proof.sha512.v2\0", ["collision-binding", "fiat-shamir-qrom"], "reduced-to-collision", False, "required-target"),
            ("proof.field_xof", "fiat-shamir-field-xof", "V6_TRANSCRIPT_XOF_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.f64-xof.v2", ["random-oracle-xof"], "not-required", False, "required-target"),
            ("proof.compress2", "pcs-compression-binding", "V6_TRANSCRIPT_COMPRESS2_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.f64-compress2.v2", ["collision-binding"], "reduced-to-collision", False, "required-target"),
            ("proof.piop_input", "fiat-shamir-transcript", "V6_TRANSCRIPT_PIOP_INPUT_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.piop-input.v2", ["collision-binding", "fiat-shamir-qrom"], "reduced-to-collision", False, "required-target"),
            ("proof.piop_transcript", "fiat-shamir-transcript", "V6_TRANSCRIPT_PIOP_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.piop-transcript.v2", ["collision-binding", "fiat-shamir-qrom"], "reduced-to-collision", False, "required-target"),
            ("proof.decs_opening", "fiat-shamir-transcript", "V6_TRANSCRIPT_DECS_OPENING_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.decs-opening.v2", ["collision-binding", "fiat-shamir-qrom"], "reduced-to-collision", False, "required-target"),
            ("proof.merkle_leaf", "pcs-leaf-commitment", "V6_TRANSCRIPT_MERKLE_LEAF_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.merkle-leaf.v2", ["collision-binding", "commitment-hiding-preimage"], "reduced-to-collision", True, "required-target"),
            ("proof.merkle_node", "pcs-merkle-binding", "V6_TRANSCRIPT_MERKLE_NODE_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.merkle-node.v2", ["collision-binding"], "reduced-to-collision", False, "required-target"),
            ("proof.merkle_root", "pcs-root-binding", "V6_TRANSCRIPT_MERKLE_ROOT_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.merkle-root.v2", ["collision-binding"], "reduced-to-collision", False, "required-target"),
            ("proof.decs_coefficient", "pcs-random-coefficient-xof", "V6_TRANSCRIPT_DECS_COEFFICIENT_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.decs-coefficient.v2", ["random-oracle-xof"], "not-required", False, "required-target"),
            ("proof.piop_coefficient", "iop-random-coefficient-xof", "V6_TRANSCRIPT_PIOP_COEFFICIENT_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.piop-coefficient.v2", ["random-oracle-xof"], "not-required", False, "required-target"),
            ("proof.piop_opening", "fiat-shamir-query-xof", "V6_TRANSCRIPT_PIOP_OPENING_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.piop-opening.v2", ["fiat-shamir-qrom", "random-oracle-xof"], "not-required", False, "required-target"),
            ("proof.decs_query", "fiat-shamir-query-xof", "V6_TRANSCRIPT_DECS_QUERY_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.decs-query.v2", ["fiat-shamir-qrom", "random-oracle-xof"], "not-required", False, "required-target"),
            ("proof.decs_disjoint_coset", "proof-domain-binding", "V6_TRANSCRIPT_DECS_DISJOINT_COSET_DOMAIN", "hegemon.smallwood.v6-epsilon.decs-disjoint-coset.v2", ["collision-binding"], "reduced-to-collision", False, "required-target"),
            ("proof.opened_leaf_random_tape", "pcs-leaf-hiding", "V6_TRANSCRIPT_OPENED_LEAF_RANDOM_TAPE_DOMAIN", "hegemon.smallwood.v6-epsilon.opened-leaf-random-tape.v2", ["commitment-hiding-preimage"], "not-required", True, "required-target"),
            ("proof.grinding", "disabled-grinding-domain", "V6_TRANSCRIPT_GRINDING_DOMAIN", "hegemon.smallwood.v6-epsilon.sha512.grinding.v2", ["grinding-preimage"], "not-required", False, "disabled-zero-grinding"),
        )
    ),
    _hash_role(
        "manifest.relation_descriptor",
        "release-manifest-binding",
        "SHA-512",
        512,
        "statement_owner",
        "V6_RELATION_BINDING_DOMAIN",
        "hegemon.swv6.relation-manifest.v2\0",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
    _hash_role(
        "manifest.source_binding",
        "evidence-source-binding",
        "SHA-512",
        512,
        "composition_checker",
        "SOURCE_MANIFEST_DOMAIN",
        "hegemon.smallwood.v6.relation-manifest.sha512.v1\0",
        ["collision-binding"],
        "reduced-to-collision",
        False,
    ),
)


EXPECTED_SEMANTIC_CALL_FAMILIES: tuple[dict[str, object], ...] = (
    {"role_ascii": "note.cm3", "purpose_tag": 2, "algorithm_tag": 2, "invocations": 4, "maximum_frame_bytes": 232, "output_bytes": 56, "rate_bytes": 72, "permutations_each": 4},
    {"role_ascii": "nullif.2", "purpose_tag": 3, "algorithm_tag": 2, "invocations": 2, "maximum_frame_bytes": 135, "output_bytes": 56, "rate_bytes": 72, "permutations_each": 2},
    {"role_ascii": "merk.nd2", "purpose_tag": 1, "algorithm_tag": 1, "invocations": 64, "maximum_frame_bytes": 133, "output_bytes": 56, "rate_bytes": 136, "permutations_each": 1},
    {"role_ascii": "sp.keys2", "purpose_tag": 3, "algorithm_tag": 2, "invocations": 2, "maximum_frame_bytes": 77, "output_bytes": 112, "rate_bytes": 72, "permutations_each": 3},
    {"role_ascii": "policy.1", "purpose_tag": 2, "algorithm_tag": 2, "invocations": 1, "maximum_frame_bytes": 385, "output_bytes": 56, "rate_bytes": 72, "permutations_each": 6},
    {"role_ascii": "auth.mux", "purpose_tag": 3, "algorithm_tag": 2, "invocations": 2, "maximum_frame_bytes": 181, "output_bytes": 112, "rate_bytes": 72, "permutations_each": 4},
    {"role_ascii": "intent.1", "purpose_tag": 1, "algorithm_tag": 1, "invocations": 1, "maximum_frame_bytes": 744, "output_bytes": 56, "rate_bytes": 136, "permutations_each": 6},
    {"role_ascii": "bal.tag1", "purpose_tag": 1, "algorithm_tag": 1, "invocations": 1, "maximum_frame_bytes": 100, "output_bytes": 56, "rate_bytes": 136, "permutations_each": 1},
    {"role_ascii": "ct.hash1", "purpose_tag": 1, "algorithm_tag": 1, "invocations": 2, "maximum_frame_bytes": 2_182, "output_bytes": 56, "rate_bytes": 136, "permutations_each": 17},
)

# These are not probabilities that can be filled with a claimed zero.  They
# need executable or universally quantified refinement evidence.  This module
# intentionally owns no receipt language capable of discharging them.
UNEXECUTED_OBLIGATIONS = (
    "v6_round_by_round_extraction_for_exact_relation",
    "compiled_relation_to_lppc_iop_refinement",
    "compiled_verifier_acceptance_refinement",
    "canonical_893_byte_statement_refinement",
    "decs_disjoint_coset_domain_compiled_refinement",
    "opened_leaf_random_tape_and_index_binding_refinement",
    "sha512_field_xof_physical_call_cap_enforced",
    "canonical_first_valid_nonce_compiled_refinement",
    "fixed_decs_sampler_compiled_refinement",
    "abort_conditioned_qrom_simulation",
    "shared_history_budget_consensus_enforcement",
    "wire_parser_exact_bytes_refinement",
    "complete_zero_knowledge",
    "independent_cryptographic_review",
)


class CompositionInputError(ValueError):
    """The profile is malformed or unsafe."""


def _fail(message: str) -> NoReturn:
    raise CompositionInputError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> object:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CompositionInputError(f"cannot stat {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"profile must be a non-symlink regular file: {path}")
    if info.st_size > MAX_PROFILE_BYTES:
        _fail(f"profile exceeds {MAX_PROFILE_BYTES} bytes: {path}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CompositionInputError(f"cannot read valid JSON from {path}: {exc}") from exc


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} keys mismatch; missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def _hex(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length:
        _fail(f"{label} must be {length} lowercase hexadecimal characters")
    if value != value.lower() or any(ch not in "0123456789abcdef" for ch in value):
        _fail(f"{label} must be lowercase hexadecimal")
    return value


def _fraction(value: object, label: str) -> Fraction:
    encoded = _object(value, label)
    _exact_keys(encoded, {"numerator", "denominator"}, label)
    numerator = encoded["numerator"]
    denominator = encoded["denominator"]
    if not isinstance(numerator, str) or not numerator.isdecimal():
        _fail(f"{label}.numerator must be an unsigned decimal string")
    if not isinstance(denominator, str) or not denominator.isdecimal():
        _fail(f"{label}.denominator must be an unsigned decimal string")
    numerator_int = int(numerator)
    denominator_int = int(denominator)
    if denominator_int == 0 or numerator_int > denominator_int:
        _fail(f"{label} must encode a probability in [0,1]")
    return Fraction(numerator_int, denominator_int)


def _fraction_report(value: Fraction) -> dict[str, object]:
    if value < 0:
        raise ValueError("probability accounting cannot contain a negative term")
    if value == 0:
        approximate_bits: float | str = "infinity"
        floor_bits: int | str = "infinity"
    else:
        approximate_bits = math.log2(value.denominator) - math.log2(value.numerator)
        if value > 1:
            floor_bits = 0
        else:
            candidate = max(
                0, value.denominator.bit_length() - value.numerator.bit_length() - 1
            )
            while value <= Fraction(1, 2 ** (candidate + 1)):
                candidate += 1
            while candidate > 0 and value > Fraction(1, 2**candidate):
                candidate -= 1
            floor_bits = candidate
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "security_bits_floor": floor_bits,
        "security_bits_approx": approximate_bits,
    }


def falling_product(value: int, count: int) -> int:
    if value < 0 or count < 0 or count > value:
        raise ValueError("invalid falling-product arguments")
    product = 1
    for offset in range(count):
        product *= value - offset
    return product


def stirling_second(value: int, blocks: int) -> int:
    """Exact S(value, blocks), used by fixed-sampler exhaustion accounting."""

    if value < 0 or blocks < 0 or blocks > value:
        return 0
    row = [0] * (blocks + 1)
    row[0] = 1
    for item in range(1, value + 1):
        upper = min(item, blocks)
        for block_count in range(upper, 0, -1):
            row[block_count] = (
                row[block_count - 1] + block_count * row[block_count]
            )
        row[0] = 0
    return row[blocks]


def piop_sampler_exhaustion_probability(
    *, field_order: int, packing_points: int, openings: int, trials: int
) -> Fraction:
    valid_one = Fraction(
        falling_product(field_order - packing_points, openings),
        field_order**openings,
    )
    return (1 - valid_one) ** trials


def decs_sampler_exhaustion_probability(
    *, field_order: int, domain_size: int, openings: int, candidates: int
) -> Fraction:
    """Exact failure probability of the first-distinct fixed DECS sampler.

    Goldilocks is one modulo every power of two through 2^32.  For the 2^20
    domain, each valid index therefore has exactly ``(q-1)/N`` preimages and
    one field word is rejected.  The Stirling count includes every pattern
    with fewer than ``openings`` distinct accepted indices.
    """

    if field_order % domain_size != 1:
        raise ValueError("field order must be one modulo the DECS domain")
    bucket = (field_order - 1) // domain_size
    bad_raw_streams = 0
    for accepted_count in range(candidates + 1):
        bad_index_sequences = 0
        for distinct in range(min(openings - 1, accepted_count) + 1):
            bad_index_sequences += (
                falling_product(domain_size, distinct)
                * stirling_second(accepted_count, distinct)
            )
        bad_raw_streams += (
            math.comb(candidates, accepted_count)
            * bucket**accepted_count
            * bad_index_sequences
        )
    return Fraction(bad_raw_streams, field_order**candidates)


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def _safe_source(repo_root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or "." in rel.parts:
        _fail(f"unsafe source path: {relative}")
    root = repo_root.resolve()
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            _fail(f"source path traverses a symlink: {relative}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CompositionInputError(f"source escapes repository: {relative}") from exc
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
        _fail(f"source must be a bounded regular file: {relative}")
    return resolved


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _defines_rust_byte_literal(payload: bytes, literal: bytes) -> bool:
    """Recognize a Rust constant definition, ignoring comments/test vectors.

    The statement owner is the sole definition authority.  Merely mentioning a
    wire literal in a conformance test or comment is not a duplicate authority.
    """

    escaped = re.escape(literal.decode("ascii"))
    pattern = rb"(?m)^\s*(?:pub(?:\([^\n)]*\))?\s+)?const\s+[A-Za-z_][A-Za-z0-9_]*[^\n=]*=\s*\*?b\"" + escaped.encode("ascii") + rb"\""
    return re.search(pattern, payload) is not None


def _source_defines_hash_domain(
    payload: bytes, constant: str, domain_ascii: str
) -> bool:
    """Conservatively bind a role to its named source constant and byte string.

    Rust and Python spell the terminal NUL as ``\\0`` in source, while the
    canonical registry stores the actual NUL.  This check supplements the full
    source SHA-512 pin; it is not a parser or compiler-refinement claim.
    """

    source_literal = domain_ascii.replace("\\", "\\\\").replace("\0", "\\0")
    return constant.encode("ascii") in payload and source_literal.encode("ascii") in payload


def _pq_primitive_cap_bits(
    primitive: str, output_bits: int, required_property: str
) -> int | None:
    """Return a conservative generic PQ work-factor cap in whole bits.

    The gate deliberately rounds down.  SHAKE256 has capacity 512, so FIPS
    preimage strength is capped at 256 classical bits and Grover search at 128
    quantum bits, regardless of a 448- or 896-bit squeeze.  Collision work is
    capped by the smaller of the output and capacity generic collision bounds.
    SHA-512 has a 512-bit output, hence 170 whole bits for generic quantum
    collision work and 256 for generic quantum preimage work.
    """

    if primitive == "UNBOUND-OPAQUE-56":
        return 0
    if primitive == "SHAKE256":
        if required_property == "collision-binding":
            return min(output_bits // 3, 512 // 3)
        if required_property in {
            "preimage-hiding",
            "prf-key-derivation",
            "commitment-hiding-preimage",
            "grinding-preimage",
            "native-second-preimage",
        }:
            return min(output_bits // 2, 512 // 4)
    elif primitive == "SHA-512":
        if required_property == "collision-binding":
            return output_bits // 3
        if required_property in {
            "preimage-hiding",
            "prf-key-derivation",
            "commitment-hiding-preimage",
            "grinding-preimage",
            "native-second-preimage",
        }:
            return output_bits // 2
    elif primitive == NONSTANDARD_WIDE_XOF:
        if required_property == "collision-binding":
            return min(output_bits // 3, 1024 // 3)
        if required_property in {
            "preimage-hiding",
            "prf-key-derivation",
            "commitment-hiding-preimage",
            "grinding-preimage",
            "native-second-preimage",
        }:
            return min(output_bits // 2, 1024 // 4)
    if required_property in {"random-oracle-xof", "fiat-shamir-qrom"}:
        return None
    _fail(
        f"no checker-owned primitive cap for {primitive}/{output_bits}/{required_property}"
    )


def _encode_relation_hash_role_registry() -> bytes:
    output = bytearray(RELATION_HASH_ROLE_REGISTRY_MAGIC)
    output.extend((1).to_bytes(2, "big"))
    output.extend(len(EXPECTED_SEMANTIC_CALL_FAMILIES).to_bytes(2, "big"))
    for family in EXPECTED_SEMANTIC_CALL_FAMILIES:
        role = str(family["role_ascii"]).encode("ascii")
        if len(role) != 8:
            raise AssertionError("relation hash role must be exactly eight bytes")
        output.extend(role)
        output.append(int(family["purpose_tag"]))
        output.append(int(family["algorithm_tag"]))
        output.extend(int(family["invocations"]).to_bytes(2, "big"))
        output.extend(int(family["maximum_frame_bytes"]).to_bytes(4, "big"))
        output.extend(int(family["output_bytes"]).to_bytes(2, "big"))
        output.extend(int(family["rate_bytes"]).to_bytes(2, "big"))
        output.extend(int(family["permutations_each"]).to_bytes(2, "big"))
    output.extend(SEMANTIC_SHAKE_INVOCATIONS.to_bytes(2, "big"))
    output.extend(SEMANTIC_KECCAK_PERMUTATIONS.to_bytes(2, "big"))
    if len(output) != RELATION_HASH_ROLE_REGISTRY_BYTES:
        raise AssertionError("checker relation hash-role registry is not 214 bytes")
    return bytes(output)


def _hash_role_gate(
    profile: dict[str, object]
) -> tuple[dict[str, object], list[str]]:
    failures: list[str] = []
    registry = _object(profile["hash_role_registry"], "profile.hash_role_registry")
    expected_registry_keys = {
        "strict_target_bits",
        "comparison",
        "semantic_frame_profile_tag",
        "consensus_frame",
        "relation_registry_magic",
        "relation_registry_sha512",
        "audit_registry_id",
        "audit_registry_sha512",
    }
    _exact_keys(registry, expected_registry_keys, "profile.hash_role_registry")
    if registry["strict_target_bits"] != STRICT_ROLE_TARGET_BITS:
        failures.append("hash-role target must be exactly 128 bits")
    if registry["comparison"] != "primitive-pq-cap-strictly-greater-than-target":
        failures.append("hash-role comparison must require a strict >128-bit primitive cap")
    if registry["semantic_frame_profile_tag"] != "HEG-F6V2":
        failures.append("hash-role registry is not bound to the HEG-F6V2 semantic frame")
    if registry["consensus_frame"] != "hegemon.shake256-448.consensus-frame.v1":
        failures.append("hash-role registry is not bound to the V6 consensus hash frame")
    if registry["relation_registry_magic"] != "HGF6HR02":
        failures.append("relation hash-role registry magic is not HGF6HR02")
    if registry["audit_registry_id"] != HASH_ROLE_REGISTRY_ID:
        failures.append("hash-role audit registry id is not checker-owned V2")

    expected_families = list(EXPECTED_SEMANTIC_CALL_FAMILIES)
    registry_payload = _canonical_json(
        {
            "registry_id": HASH_ROLE_REGISTRY_ID,
            "semantic_call_families": expected_families,
            "roles": list(EXPECTED_HASH_ROLES),
        }
    )
    observed_audit_registry_sha512 = hashlib.sha512(
        HASH_ROLE_REGISTRY_DOMAIN
        + len(registry_payload).to_bytes(8, "little")
        + registry_payload
    ).hexdigest()
    declared_audit_registry_sha512 = _hex(
        registry["audit_registry_sha512"],
        128,
        "profile.hash_role_registry.audit_registry_sha512",
    )
    observed_relation_registry_sha512 = hashlib.sha512(
        _encode_relation_hash_role_registry()
    ).hexdigest()
    declared_relation_registry_sha512 = _hex(
        registry["relation_registry_sha512"],
        128,
        "profile.hash_role_registry.relation_registry_sha512",
    )
    expected_invocations = sum(
        int(family["invocations"]) for family in EXPECTED_SEMANTIC_CALL_FAMILIES
    )
    expected_permutations = sum(
        int(family["invocations"]) * int(family["permutations_each"])
        for family in EXPECTED_SEMANTIC_CALL_FAMILIES
    )
    if expected_invocations != SEMANTIC_SHAKE_INVOCATIONS or expected_permutations != SEMANTIC_KECCAK_PERMUTATIONS:
        raise AssertionError("checker-owned semantic call schedule drifted")

    registry_matches = (
        registry["relation_registry_magic"] == "HGF6HR02"
        and declared_relation_registry_sha512 == observed_relation_registry_sha512
        and registry["audit_registry_id"] == HASH_ROLE_REGISTRY_ID
        and declared_audit_registry_sha512 == observed_audit_registry_sha512
    )
    if not registry_matches:
        failures.append("hash-role registry digest differs from the checker-owned property/domain inventory")

    role_reports: list[dict[str, object]] = []
    migration_required: list[str] = []
    unavoidable_roles: list[str] = []
    selected_nonstandard_wide_xof_secret_roles: list[str] = []
    nonstandard_primitive_roles: list[str] = []
    unbound_authority_roles: list[str] = []
    for role in EXPECTED_HASH_ROLES:
        if role["primitive"] == NONSTANDARD_WIDE_XOF:
            nonstandard_primitive_roles.append(str(role["id"]))
        properties = list(role["required_properties"])
        property_caps: dict[str, int | None] = {}
        for required_property in properties:
            cap = _pq_primitive_cap_bits(
                str(role["primitive"]), int(role["output_bits"]), required_property
            )
            property_caps[required_property] = cap
            if cap is not None and cap <= STRICT_ROLE_TARGET_BITS:
                failures.append(
                    f"hash role {role['id']} has {required_property} PQ cap {cap}, not strictly greater than 128"
                )
        if role["second_preimage_mode"] == "native":
            cap = _pq_primitive_cap_bits(
                str(role["primitive"]), int(role["output_bits"]), "native-second-preimage"
            )
            property_caps["native-second-preimage"] = cap
            if cap is not None and cap <= STRICT_ROLE_TARGET_BITS:
                failures.append(
                    f"hash role {role['id']} has native second-preimage PQ cap {cap}, not strictly greater than 128"
                )
        elif role["second_preimage_mode"] == "reduced-to-collision":
            if "collision-binding" not in properties:
                failures.append(
                    f"hash role {role['id']} claims a collision reduction without collision binding"
                )
        elif role["second_preimage_mode"] != "not-required":
            _fail(f"unknown second-preimage classification for hash role {role['id']}")

        if role["unavoidable_preimage_or_prf"]:
            unavoidable_roles.append(str(role["id"]))
            if role["primitive"] == NONSTANDARD_WIDE_XOF:
                selected_nonstandard_wide_xof_secret_roles.append(str(role["id"]))
            unavoidable_caps = [
                cap
                for prop, cap in property_caps.items()
                if prop
                in {
                    "preimage-hiding",
                    "prf-key-derivation",
                    "commitment-hiding-preimage",
                    "grinding-preimage",
                    "native-second-preimage",
                }
                and cap is not None
            ]
            if not unavoidable_caps:
                failures.append(
                    f"hash role {role['id']} marks an unavoidable preimage/PRF term but exposes no checker-owned cap"
                )
            elif min(unavoidable_caps) <= STRICT_ROLE_TARGET_BITS:
                migration_required.append(str(role["id"]))
            elif role["primitive"] == NONSTANDARD_WIDE_XOF:
                migration_required.append(str(role["id"]))
        if role["status"] == "opaque-authority-no-v6-construction":
            unbound_authority_roles.append(str(role["id"]))
            failures.append(
                f"hash role {role['id']} is an opaque 56-byte statement authority with no typed V6 construction or domain"
            )

        role_reports.append(
            {
                **role,
                "property_pq_cap_bits": property_caps,
                "strict_primitive_margin_pass": all(
                    cap is None or cap > STRICT_ROLE_TARGET_BITS
                    for cap in property_caps.values()
                ),
            }
        )

    if nonstandard_primitive_roles:
        failures.append(
            "HGF6HR02 algorithm tag 2 is a nonstandard rate-72/capacity-1024 Keccak XOF, not a FIPS conventional hash"
        )

    migration_projection = [
        {
            "role": role_id,
            "required_fresh_primitive": (
                "standard SHA3-512 typed construction or another reviewed conventional primitive"
            ),
            "fresh_profile_and_domain_required": True,
            "projected_split_sha3_512_output_preimage_cap_bits": 224,
            "source_entropy_cap_bits_if_known": (
                192
                if role_id
                in {"semantic.note_commitment", "semantic.spend_key_xof"}
                else None
            ),
            "prf_kdf_reduction_required": role_id
            in {
                "semantic.nullifier",
                "semantic.spend_key_xof",
                "semantic.authorization_accumulator",
                "semantic.authorization_value_lock",
            },
        }
        for role_id in migration_required
    ]
    strict_pass = registry_matches and not migration_required and not failures
    bound_role_numeric_margin_pass = registry_matches and all(
        role["strict_primitive_margin_pass"]
        for role in role_reports
        if role["status"] != "opaque-authority-no-v6-construction"
    )
    bound_role_margin_pass = (
        bound_role_numeric_margin_pass and not nonstandard_primitive_roles
    )
    return (
        {
            "strict_target_bits": STRICT_ROLE_TARGET_BITS,
            "comparison": "primitive PQ cap must be strictly greater than 128",
            "registry_matches_checker": registry_matches,
            "relation_registry_magic": "HGF6HR02",
            "relation_registry_bytes": RELATION_HASH_ROLE_REGISTRY_BYTES,
            "declared_relation_registry_sha512": declared_relation_registry_sha512,
            "observed_relation_registry_sha512": observed_relation_registry_sha512,
            "audit_registry_id": HASH_ROLE_REGISTRY_ID,
            "declared_audit_registry_sha512": declared_audit_registry_sha512,
            "observed_audit_registry_sha512": observed_audit_registry_sha512,
            "semantic_call_schedule": {
                "invocations": expected_invocations,
                "keccak_permutations": expected_permutations,
                "families": expected_families,
            },
            "roles": role_reports,
            "unavoidable_preimage_or_prf_roles": unavoidable_roles,
            "selected_nonstandard_wide_xof_preimage_or_prf_roles": selected_nonstandard_wide_xof_secret_roles,
            "nonstandard_primitive_roles": nonstandard_primitive_roles,
            "conventional_hash_authority_pass": not nonstandard_primitive_roles,
            "primitive_migration_required_roles": migration_required,
            "disqualified_uniform_shake256_counterfactual": {
                "roles": selected_nonstandard_wide_xof_secret_roles,
                "classical_preimage_cap_bits": 256,
                "quantum_preimage_cap_bits": 128,
                "strictly_greater_than_128": False,
            },
            "unbound_opaque_statement_authorities": unbound_authority_roles,
            "opaque_authority_resolution": (
                "bind public policy/oracle/attestation records under fresh typed conventional-hash domains; "
                "if any future record hides a secret preimage, a standardized construction with strict >128-bit PQ margin is mandatory"
            ),
            "fresh_wider_capacity_migration": migration_projection,
            "strict_primitive_margin_pass": strict_pass,
            "bound_role_primitive_margin_pass": bound_role_margin_pass,
            "bound_role_numeric_margin_pass": bound_role_numeric_margin_pass,
            "second_preimage_policy": (
                "binding roles require a reduction from two distinct accepted encodings to collision; "
                "no native SHAKE256 second-preimage term is silently assumed"
            ),
        },
        failures,
    )


def _source_binding_report(
    profile: dict[str, object], repo_root: Path
) -> tuple[dict[str, object], list[str]]:
    failures: list[str] = []
    binding = _object(profile["source_binding"], "profile.source_binding")
    _exact_keys(binding, {"files", "relation_manifest_sha512"}, "profile.source_binding")
    entries = _array(binding["files"], "profile.source_binding.files")
    if len(entries) != len(EXPECTED_SOURCE_ROLES):
        _fail("source_binding.files must contain every checker-owned role exactly once")

    observed_files: list[dict[str, object]] = []
    source_payloads: dict[str, bytes] = {}
    seen_roles: set[str] = set()
    for index, entry_value in enumerate(entries):
        entry = _object(entry_value, f"source_binding.files[{index}]")
        _exact_keys(entry, {"role", "path", "sha512"}, f"source_binding.files[{index}]")
        role = entry["role"]
        path = entry["path"]
        if not isinstance(role, str) or role not in EXPECTED_SOURCE_ROLES:
            _fail(f"source_binding.files[{index}].role is not checker-owned")
        if role in seen_roles:
            _fail(f"duplicate source role {role}")
        seen_roles.add(role)
        expected_path = EXPECTED_SOURCE_ROLES[role]
        if path != expected_path:
            _fail(f"source role {role} must use {expected_path}")
        declared = entry["sha512"]
        if declared is not None:
            declared = _hex(declared, 128, f"source_binding.files[{index}].sha512")
        try:
            source_path = _safe_source(repo_root, expected_path)
            payload = source_path.read_bytes()
            actual = hashlib.sha512(payload).hexdigest()
            source_payloads[role] = payload
        except (OSError, CompositionInputError) as exc:
            actual = None
            failures.append(f"source unavailable or unsafe for role {role}: {exc}")
        if declared is None:
            failures.append(f"source digest is not pinned for role {role}")
        elif actual != declared:
            failures.append(f"source digest mismatch for role {role}")
        observed_files.append(
            {"role": role, "path": expected_path, "sha512": actual}
        )

    if set(seen_roles) != set(EXPECTED_SOURCE_ROLES):
        _fail("source roles do not match the checker-owned inventory")

    owner = source_payloads.get("statement_owner", b"")
    for literal in (b"HGF6ST02", b"HEG-F6V2", b"HGF6HR02"):
        if not _defines_rust_byte_literal(owner, literal):
            failures.append(
                f"statement owner does not define canonical literal {literal.decode()}"
            )
        duplicates = [
            role
            for role, payload in source_payloads.items()
            if role != "statement_owner"
            and _defines_rust_byte_literal(payload, literal)
        ]
        if duplicates:
            failures.append(
                f"canonical literal {literal.decode()} is duplicated outside statement owner: "
                + ", ".join(sorted(duplicates))
            )

    for role in EXPECTED_HASH_ROLES:
        constant = role["domain_constant"]
        domain_ascii = role["domain_ascii"]
        if constant is None or domain_ascii is None:
            continue
        owner_role = str(role["domain_owner"])
        payload = source_payloads.get(owner_role)
        if payload is None:
            failures.append(
                f"hash role {role['id']} domain owner {owner_role} is unavailable"
            )
            continue
        if not _source_defines_hash_domain(payload, str(constant), str(domain_ascii)):
            failures.append(
                f"hash role {role['id']} domain {constant}={domain_ascii!r} is not defined by {owner_role}"
            )

    m4_payload = source_payloads.get("m4_mixed_candidate", b"")
    pinned_tree_literal = (
        b'PINNED_BINIUS_TREE_SHA512: &str = "'
        + PINNED_M4_BINIUS_TREE_SHA512.encode("ascii")
        + b'"'
    )
    if pinned_tree_literal not in m4_payload:
        failures.append("M4 mixed candidate does not bind the frozen Binius tree pin")

    normalized_manifest = {
        "profile_id": profile["profile_id"],
        "identity": profile["identity"],
        "statement": profile["statement"],
        "proof_system": profile["proof_system"],
        "hashes": profile["hashes"],
        "hash_role_registry": profile["hash_role_registry"],
        "budgets": profile["budgets"],
        "relation_projection": profile["relation_projection"],
        "geometry": profile["geometry"],
        "files": observed_files,
    }
    payload = _canonical_json(normalized_manifest)
    observed_manifest = hashlib.sha512(
        SOURCE_MANIFEST_DOMAIN + len(payload).to_bytes(8, "little") + payload
    ).hexdigest()
    declared_manifest = binding["relation_manifest_sha512"]
    if declared_manifest is not None:
        declared_manifest = _hex(
            declared_manifest, 128, "source_binding.relation_manifest_sha512"
        )
    if declared_manifest is None:
        failures.append("relation manifest SHA-512 digest is not pinned")
    elif declared_manifest != observed_manifest:
        failures.append("relation manifest SHA-512 digest mismatch")

    return (
        {
            "files": observed_files,
            "observed_relation_manifest_sha512": observed_manifest,
            "declared_relation_manifest_sha512": declared_manifest,
            "binding_pass": not failures,
        },
        failures,
    )


def _conventional_successor_tournament() -> dict[str, object]:
    """Checker-owned no-promotion comparison of the two smallest live options."""

    return {
        "identity_rotation_authorized": False,
        "winner": None,
        "blocking_decision": (
            "freeze identity until a keyed-role construction, entropy contract, exact fixed-shape compiler, and QROM reduction are selected"
        ),
        "sha3_512_split": {
            "standard": "FIPS 202 SHA3-512",
            "rate_bytes": 72,
            "capacity_bits": 1024,
            "domain_suffix": "0x06",
            "full_output_bits": 512,
            "published_output_bits": 448,
            "distinct_half_domains_required": True,
            "relation_families_after_split": 11,
            "primitive_invocations": SUCCESSOR_PRIMITIVE_INVOCATIONS,
            "collision_only_shake256_keccak_permutations": COLLISION_ONLY_SHAKE256_KECCAK_PERMUTATIONS,
            "secret_role_keccak_permutations": SHA3_512_SPLIT_SECRET_KECCAK_PERMUTATIONS,
            "total_relation_keccak_permutations": SHA3_512_SPLIT_TOTAL_KECCAK_PERMUTATIONS,
            "generic_quantum_collision_cap_bits": 149,
            "generic_quantum_output_preimage_cap_bits": 224,
            "spend_seed_bits": 384,
            "spend_seed_grover_cap_bits": 192,
            "raw_domain_hash_commitment_screen_available": True,
            "raw_domain_hash_prf_kdf_authority": False,
            "raw_domain_hash_prf_kdf_blocker": (
                "prefixing a secret into SHA3-512 is not by itself an executed PRF/KDF QROM reduction"
            ),
            "concrete_keccak_sponge_qrom_bridge_present": False,
            "hmac_or_hkdf_unavoidable": False,
            "keyed_construction_and_reduction_unavoidable_for_prf_roles": True,
            "hmac_sha3_512_split_total_keccak_permutations_lower_bound": HMAC_SHA3_512_SPLIT_TOTAL_KECCAK_PERMUTATIONS_LOWER_BOUND,
            "hmac_lower_bound_scope": (
                "key-excluding fresh frames; HKDF extract, fixed authorization mux padding, and compiler rows can only add work"
            ),
        },
        "rfc7693_blake2b_448": {
            "standard": "RFC 7693 BLAKE2b with digest_length=56",
            "published_output_bits": 448,
            "maximum_key_bytes": 64,
            "generic_quantum_collision_cap_bits": 149,
            "generic_quantum_output_preimage_cap_bits": 224,
            "spend_key_bytes": 48,
            "spend_key_grover_cap_bits": 192,
            "derived_or_policy_key_bytes": 56,
            "derived_or_policy_key_grover_cap_bits": 224,
            "primitive_invocations": SUCCESSOR_PRIMITIVE_INVOCATIONS,
            "collision_only_shake256_keccak_permutations": COLLISION_ONLY_SHAKE256_KECCAK_PERMUTATIONS,
            "unkeyed_mixed_secret_compressions": BLAKE2B_UNKEYED_SECRET_COMPRESSIONS,
            "unkeyed_mixed_total_heterogeneous_cores": BLAKE2B_UNKEYED_MIXED_PRIMITIVE_CORES,
            "unkeyed_domain_hash_prf_kdf_authority": False,
            "keyed_personalized_secret_compressions": BLAKE2B_KEYED_SECRET_COMPRESSIONS,
            "keyed_personalized_total_heterogeneous_cores": BLAKE2B_KEYED_MIXED_PRIMITIVE_CORES,
            "keyed_mode_is_conventional_mac": True,
            "keyed_mode_qrom_prf_reduction_executed": False,
            "concrete_blake2b_qro_bridge_present": False,
            "bounded_multi_user_qrom_loss_present": False,
            "hkdf_unavoidable_for_uniform_high_entropy_keys": False,
            "entropy_extraction_required_for_nonuniform_keys": True,
            "fixed_shape_keyed_authorization_geometry_measured": False,
            "authorization_key_entropy_bound": None,
            "frozen_scalar_source_sha512": PINNED_CONVENTIONAL_SCALAR_SHA512,
            "frozen_m4_source_sha512": PINNED_M4_MIXED_CANDIDATE_SHA512,
            "frozen_m4_source_checker_sha512": PINNED_M4_SOURCE_CHECKER_SHA512,
            "frozen_m4_binius_tree_sha512": PINNED_M4_BINIUS_TREE_SHA512,
            "source_pins_are_security_reductions": False,
        },
        "role_routing": {
            "commitment_or_binding": [
                "semantic.note_commitment",
                "semantic.authorization_policy",
            ],
            "requires_keyed_prf_or_kdf_construction": [
                "semantic.nullifier",
                "semantic.spend_key_xof",
                "semantic.authorization_accumulator",
                "semantic.authorization_value_lock",
            ],
            "minimum_entropy_blockers": [
                "note commitment randomness is 384 bits but its hiding reduction is missing",
                "spend key is 384 bits but its generation/uniformity contract is not source-bound here",
                "authorization policy_root is only checked nonzero; no min-entropy contract is enforced",
                "stablecoin policy/oracle/attestation authorities have no constructors or domains",
            ],
        },
        "comparison_limit": (
            "Generic collision, preimage, and key-search work factors are not a concrete QROM instantiation; Keccak permutations and BLAKE2b compression calls are not comparable proof rows or proof bytes; no architecture winner exists without a bounded concrete-hash bridge and emitted fixed-shape geometry"
        ),
    }


def _profile_and_geometry(
    profile: dict[str, object],
) -> tuple[dict[str, int] | None, list[str]]:
    failures: list[str] = []
    expected_top = {
        "schema",
        "profile_id",
        "identity",
        "statement",
        "proof_system",
        "hashes",
        "hash_role_registry",
        "budgets",
        "relation_projection",
        "geometry",
        "source_binding",
        "external_losses",
    }
    _exact_keys(profile, expected_top, "profile")
    if profile["schema"] != PROFILE_SCHEMA:
        failures.append(f"profile.schema must equal {PROFILE_SCHEMA}")
    if profile["profile_id"] != PROFILE_ID:
        failures.append(f"profile.profile_id must equal {PROFILE_ID}")

    identity = _object(profile["identity"], "profile.identity")
    _exact_keys(identity, set(EXPECTED_IDENTITY), "profile.identity")
    if identity != EXPECTED_IDENTITY:
        failures.append("identity is not the fresh V6 circuit6/crypto5/family1/action8 tuple")

    statement = _object(profile["statement"], "profile.statement")
    expected_statement = {
        "magic": "HGF6ST02",
        "profile_tag": "HEG-F6V2",
        "canonical_bytes": STATEMENT_BYTES,
        "limb_bytes": STATEMENT_LIMB_BYTES,
        "public_field_count": PUBLIC_FIELD_COUNT,
        "padding_zero_bytes": STATEMENT_PADDING_ZERO_BYTES,
        "chain_binding_bytes": CONSENSUS_BINDING_BYTES,
        "genesis_binding_bytes": CONSENSUS_BINDING_BYTES,
        "rules_binding_bytes": CONSENSUS_BINDING_BYTES,
        "intent_is_in_proof": True,
        "balance_tag_is_in_proof": True,
    }
    _exact_keys(statement, set(expected_statement), "profile.statement")
    if statement != expected_statement:
        failures.append(
            "statement must be exact HGF6ST02: 893 bytes, 128 lossless limbs with three zero pad bytes and 56-byte chain/genesis/rules bindings; intent and balance tag stay in proof"
        )

    proof = _object(profile["proof_system"], "profile.proof_system")
    expected_proof = {
        "name": "SmallWood-LPPC-PACS-PIOP-LVCS-DECS",
        "field_order": str(GOLDILOCKS_ORDER),
        "rho": 5,
        "piop_openings": 5,
        "beta": 2,
        "packing_factor": 64,
        "opening_pow_bits": 0,
        "piop_nonce_trials": 16,
        "canonical_first_valid_piop_nonce": True,
        "decs_domain_size": 2**20,
        "decs_openings": 23,
        "decs_eta": 5,
        "decs_pow_bits": 0,
        "decs_candidate_count": 50,
        "fixed_first_distinct_decs_sampler": True,
        "decs_evaluation_domain": "disjoint-coset",
        "radix2_subgroup_domain_forbidden": True,
        "opened_leaf_random_tape_index_binding": True,
        "opened_leaf_random_tape_bytes": OPENED_LEAF_RANDOM_TAPE_BYTES,
        "opened_leaf_opening_tape_bytes": OPENED_LEAF_TAPE_BYTES_TOTAL,
        "physical_fiat_shamir_families": 4,
    }
    _exact_keys(proof, set(expected_proof), "profile.proof_system")
    if proof != expected_proof:
        failures.append("proof-system tuple does not match the reviewed no-grinding Level-5 core")

    hashes = _object(profile["hashes"], "profile.hashes")
    expected_hashes = {
        "semantic": "HGF6HR02-rejected-nonstandard-KECCAK-c1024-XOF-plus-SHAKE256-448",
        "semantic_output_bits": SHAKE256_SEMANTIC_BITS,
        "proof_transcript": "SHA-512",
        "proof_transcript_output_bits": SHA512_BITS,
        "relation_manifest": "SHA-512",
        "relation_manifest_output_bits": SHA512_BITS,
    }
    _exact_keys(hashes, set(expected_hashes), "profile.hashes")
    if hashes != expected_hashes:
        failures.append("hash profile must describe the exact rejected HGF6HR02 nonstandard Keccak[c=1024]/FIPS-SHAKE256 registry and full SHA-512 proof/manifest binding")

    projection = _object(profile["relation_projection"], "profile.relation_projection")
    expected_projection = {
        "semantic_shake_invocations": SEMANTIC_SHAKE_INVOCATIONS,
        "semantic_keccak_permutations": SEMANTIC_KECCAK_PERMUTATIONS,
        "private_shake_invocations": PRIVATE_SHAKE_INVOCATIONS,
        "private_keccak_permutations": PRIVATE_KECCAK_PERMUTATIONS,
        "intent_keccak_permutations": 6,
        "intent_payload_bytes": INTENT_PAYLOAD_BYTES,
        "intent_frame_bytes": INTENT_FRAME_BYTES,
        "balance_tag_keccak_permutations": 1,
        "ciphertext_count": CIPHERTEXT_COUNT,
        "ciphertext_bytes_each": CIPHERTEXT_BYTES,
        "ciphertext_frame_bytes_each": CIPHERTEXT_FRAME_BYTES,
        "ciphertext_shake_invocations": CIPHERTEXT_SHAKE_INVOCATIONS,
        "ciphertext_keccak_permutations": CIPHERTEXT_KECCAK_PERMUTATIONS,
        "global_semantic_hash_terms": 3,
        "per_permutation_collision_union": False,
    }
    _exact_keys(projection, set(expected_projection), "profile.relation_projection")
    if projection != expected_projection:
        failures.append("relation projection must count 79 typed SHAKE invocations and 145 permutations, including two in-proof 2,182-byte ciphertext-hash frames")

    budgets = _object(profile["budgets"], "profile.budgets")
    expected_budget_keys = {
        "low_advantage_quantum_queries",
        "low_advantage_target_bits",
        "low_advantage_comparison",
        "work_factor_quantum_queries",
        "work_factor_max_success_numerator",
        "work_factor_max_success_denominator",
        "security_epoch_max_proofs",
        "max_proofs_per_block",
        "history_composition",
        "per_proof_history_union_forbidden",
        "history_cap_consensus_enforced",
        "physical_sha512_call_cap_per_proof",
        "physical_sha512_call_cap_enforced",
    }
    _exact_keys(budgets, expected_budget_keys, "profile.budgets")
    fixed_budgets = {
        "low_advantage_quantum_queries": str(2**LOW_QUERY_EXPONENT),
        "low_advantage_target_bits": LOW_TARGET_BITS,
        "low_advantage_comparison": "strictly-less-than-2^-128",
        "work_factor_quantum_queries": str(2**WORK_QUERY_EXPONENT),
        "work_factor_max_success_numerator": "1",
        "work_factor_max_success_denominator": "2",
        "security_epoch_max_proofs": SECURITY_EPOCH_PROOF_BUDGET,
        "max_proofs_per_block": MAX_PROOFS_PER_BLOCK,
        "history_composition": "shared-tagged-product-oracle",
        "per_proof_history_union_forbidden": True,
    }
    for name, expected in fixed_budgets.items():
        if budgets[name] != expected:
            failures.append(f"budget {name} must equal {expected}")
    if budgets["history_cap_consensus_enforced"] is not True:
        failures.append("the 2^32-proof security epoch is not consensus enforced")
    cap = budgets["physical_sha512_call_cap_per_proof"]
    if cap is None:
        failures.append("physical SHA-512 calls per proof have no hard cap")
    elif isinstance(cap, bool) or not isinstance(cap, int) or cap <= 0:
        _fail("physical_sha512_call_cap_per_proof must be null or a positive integer")
    elif cap * SECURITY_EPOCH_PROOF_BUDGET + (
        SEMANTIC_SHAKE_INVOCATIONS * SECURITY_EPOCH_PROOF_BUDGET
    ) > 2**LOW_QUERY_EXPONENT:
        failures.append(
            "honest history hash calls exceed the 2^64 global low-advantage query envelope"
        )
    if budgets["physical_sha512_call_cap_enforced"] is not True:
        failures.append("physical SHA-512 call cap is not enforced by prover and verifier")

    geometry_object = _object(profile["geometry"], "profile.geometry")
    geometry_names = {
        "row_count",
        "nonlinear_constraint_count",
        "linear_constraint_count",
        "effective_constraint_degree",
        "witness_polynomial_degree",
        "consistency_discrepancy_degree",
        "lvcs_column_count",
        "base_game_arity_upper_bound",
    }
    _exact_keys(geometry_object, geometry_names, "profile.geometry")
    geometry: dict[str, int] = {}
    for name in sorted(geometry_names):
        value = geometry_object[name]
        if value is None:
            failures.append(f"exact V6 geometry is not measured: {name}")
        elif isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            _fail(f"geometry.{name} must be null or a positive integer")
        else:
            geometry[name] = value
    if len(geometry) != len(geometry_names):
        return None, failures

    expected_witness_degree = proof["packing_factor"] + proof["piop_openings"] - 1
    if geometry["witness_polynomial_degree"] != expected_witness_degree:
        failures.append(
            f"witness_polynomial_degree must equal {expected_witness_degree}"
        )
    expected_discrepancy = (
        geometry["effective_constraint_degree"]
        * geometry["witness_polynomial_degree"]
    )
    if geometry["consistency_discrepancy_degree"] != expected_discrepancy:
        failures.append(
            "consistency_discrepancy_degree must equal effective degree times witness degree"
        )
    decs_bad_set = geometry["lvcs_column_count"] + proof["decs_openings"] - 1
    if decs_bad_set > proof["decs_domain_size"]:
        failures.append("LVCS/DECS bad-set degree exceeds the committed domain")
    if geometry["base_game_arity_upper_bound"] < proof["decs_domain_size"]:
        failures.append("base-game arity cap is smaller than the committed DECS oracle")
    return geometry, failures


def _interactive_terms(
    profile: dict[str, object], geometry: dict[str, int]
) -> dict[str, Fraction]:
    proof = _object(profile["proof_system"], "profile.proof_system")
    rho = _integer(proof["rho"], "rho", minimum=1)
    eta = _integer(proof["decs_eta"], "decs_eta", minimum=1)
    openings = _integer(proof["piop_openings"], "piop_openings", minimum=1)
    packing = _integer(proof["packing_factor"], "packing_factor", minimum=1)
    decs_domain = _integer(proof["decs_domain_size"], "decs_domain_size", minimum=1)
    decs_openings = _integer(proof["decs_openings"], "decs_openings", minimum=1)
    discrepancy = geometry["consistency_discrepancy_degree"]
    decs_bad_set = geometry["lvcs_column_count"] + decs_openings - 1
    return {
        "decs_uniform_matrix": Fraction(1, GOLDILOCKS_ORDER**eta),
        "piop_constraint_batching": Fraction(1, GOLDILOCKS_ORDER**rho),
        "piop_opening_without_replacement": Fraction(
            falling_product(discrepancy, openings),
            falling_product(GOLDILOCKS_ORDER - packing, openings),
        ),
        "decs_opening_without_replacement": Fraction(
            falling_product(decs_bad_set, decs_openings),
            falling_product(decs_domain, decs_openings),
        ),
    }


def _cms_terms(
    interactive_error: Fraction, queries: int, base_game_arity: int
) -> dict[str, Fraction]:
    return {
        "cms_rbr_amplification": 12 * queries**2 * interactive_error,
        "cms_sha512_collision_instability": Fraction(48 * queries**3, 2**SHA512_BITS),
        "cms_oracle_database_bridge": Fraction(
            2 * base_game_arity**2, 2**SHA512_BITS
        ),
    }


def _parse_external_losses(
    profile: dict[str, object], query_label: str
) -> tuple[dict[str, Fraction], list[str]]:
    document = _object(profile["external_losses"], "profile.external_losses")
    _exact_keys(document, set(QUANTITATIVE_EXTERNAL_LOSSES), "profile.external_losses")
    parsed: dict[str, Fraction] = {}
    missing: list[str] = []
    for name in QUANTITATIVE_EXTERNAL_LOSSES:
        value = document[name]
        if value is None:
            missing.append(name)
            continue
        at_budgets = _object(value, f"external_losses.{name}")
        _exact_keys(at_budgets, {"at_2pow64", "at_2pow128"}, f"external_losses.{name}")
        parsed[name] = _fraction(
            at_budgets[query_label], f"external_losses.{name}.{query_label}"
        )
    return parsed, missing


def _physical_hash_inventory(
    profile: dict[str, object], geometry: dict[str, int]
) -> dict[str, object]:
    proof = _object(profile["proof_system"], "profile.proof_system")
    rho = int(proof["rho"])
    eta = int(proof["decs_eta"])
    openings = int(proof["piop_openings"])
    trials = int(proof["piop_nonce_trials"])
    decs_candidates = int(proof["decs_candidate_count"])
    decs_domain = int(proof["decs_domain_size"])
    decs_openings = int(proof["decs_openings"])
    beta = int(proof["beta"])
    packing = int(proof["packing_factor"])
    lvcs_rows = (packing + openings) * beta
    decs_words = eta * lvcs_rows
    piop_words = rho * max(
        geometry["nonlinear_constraint_count"], geometry["linear_constraint_count"]
    )
    xof_min = {
        "decs_uniform_matrix": _ceil_div(decs_words, 8),
        "piop_constraint_matrix": _ceil_div(piop_words, 8),
        "one_piop_opening_attempt": _ceil_div(openings, 8),
        # Verification first searches for the canonical first-valid nonce and
        # then recomputes the supplied nonce's points.  Hence even nonce zero
        # costs two XOF calls, and the trial cap costs trials plus one.
        "first_valid_canonical_piop_nonce": 2 * _ceil_div(openings, 8),
        "worst_canonical_piop_nonce": (trials + 1) * _ceil_div(openings, 8),
        "fixed_decs_candidate_pool": _ceil_div(decs_candidates, 8),
    }
    prover_merkle = {
        "leaf_hashes": decs_domain,
        "internal_hashes": decs_domain - 1,
        "root_binding_hashes": 2,
    }
    verifier_merkle_upper = {
        "leaf_hashes": decs_openings,
        "internal_hashes": decs_openings * (decs_domain.bit_length() - 1),
        "root_binding_hashes": 1,
    }
    direct_non_merkle_digest_hashes = {
        "piop_input_hash": 1,
        "piop_transcript_hash": 1,
        "decs_opening_hash": 1,
    }
    prover_min_first_nonce = (
        sum(prover_merkle.values())
        + sum(direct_non_merkle_digest_hashes.values())
        + xof_min["decs_uniform_matrix"]
        + xof_min["piop_constraint_matrix"]
        + xof_min["first_valid_canonical_piop_nonce"]
        + xof_min["fixed_decs_candidate_pool"]
    )
    prover_min_worst_nonce = (
        prover_min_first_nonce
        - xof_min["first_valid_canonical_piop_nonce"]
        + xof_min["worst_canonical_piop_nonce"]
    )
    verifier_upper_min_worst_nonce = (
        sum(verifier_merkle_upper.values())
        + sum(direct_non_merkle_digest_hashes.values())
        + xof_min["decs_uniform_matrix"]
        + xof_min["piop_constraint_matrix"]
        + xof_min["worst_canonical_piop_nonce"]
        + xof_min["fixed_decs_candidate_pool"]
    )
    return {
        "field_xof_minimum_sha512_blocks": xof_min,
        "prover_merkle_hash_requests": prover_merkle,
        "verifier_merkle_hash_request_upper_bound": verifier_merkle_upper,
        "direct_non_merkle_digest_hashes": direct_non_merkle_digest_hashes,
        "minimum_prover_sha512_calls_first_nonce": prover_min_first_nonce,
        "minimum_prover_sha512_calls_worst_canonical_nonce": prover_min_worst_nonce,
        "minimum_verifier_sha512_calls_upper_merkle_worst_nonce": verifier_upper_min_worst_nonce,
        "exact_executed_calls_available": False,
        "reason_exact_unavailable": (
            "Goldilocks rejection sampling has no enforced raw SHA-512 block cap, and the "
            "optimized prover leaf fast path is not included in sha512_digest_calls profiling"
        ),
    }


def _history_query_inventory(profile: dict[str, object]) -> dict[str, object]:
    budgets = _object(profile["budgets"], "profile.budgets")
    cap = budgets["physical_sha512_call_cap_per_proof"]
    sha512_history = (
        None if cap is None else int(cap) * SECURITY_EPOCH_PROOF_BUDGET
    )
    semantic_history = SEMANTIC_SHAKE_INVOCATIONS * SECURITY_EPOCH_PROOF_BUDGET
    combined = None if sha512_history is None else sha512_history + semantic_history
    return {
        "security_epoch_max_proofs": SECURITY_EPOCH_PROOF_BUDGET,
        "semantic_shake_invocations_per_proof": SEMANTIC_SHAKE_INVOCATIONS,
        "semantic_shake_history_invocations": str(semantic_history),
        "physical_sha512_call_cap_per_proof": cap,
        "physical_sha512_history_call_upper_bound": (
            str(sha512_history) if sha512_history is not None else None
        ),
        "combined_honest_history_hash_call_upper_bound": (
            str(combined) if combined is not None else None
        ),
        "low_advantage_global_query_envelope": str(2**LOW_QUERY_EXPONENT),
        "honest_history_fits_low_advantage_envelope": (
            combined <= 2**LOW_QUERY_EXPONENT if combined is not None else False
        ),
        "total_adversary_plus_honest_ledger_enforced": False,
    }


def _soundness_at_budget(
    profile: dict[str, object],
    geometry: dict[str, int],
    queries: int,
    query_label: str,
) -> tuple[dict[str, object], list[str]]:
    interactive_terms = _interactive_terms(profile, geometry)
    interactive_error = sum(interactive_terms.values(), Fraction(0, 1))
    cms_terms = _cms_terms(
        interactive_error, queries, geometry["base_game_arity_upper_bound"]
    )
    ideal_cms = sum(cms_terms.values(), Fraction(0, 1))
    proof = _object(profile["proof_system"], "profile.proof_system")
    piop_abort = piop_sampler_exhaustion_probability(
        field_order=GOLDILOCKS_ORDER,
        packing_points=int(proof["packing_factor"]),
        openings=int(proof["piop_openings"]),
        trials=int(proof["piop_nonce_trials"]),
    )
    decs_abort = decs_sampler_exhaustion_probability(
        field_order=GOLDILOCKS_ORDER,
        domain_size=int(proof["decs_domain_size"]),
        openings=int(proof["decs_openings"]),
        candidates=int(proof["decs_candidate_count"]),
    )
    abort_total = piop_abort + decs_abort

    # These are parameter screens, not deployed SHAKE reductions.  Each
    # primitive/property pair contributes once over the total query budget.
    # The 79 invocations and 145 permutations are deliberately not union
    # multipliers.
    semantic_shake256_collision_screen = Fraction(
        4 * queries**3, 2**SHAKE256_SEMANTIC_BITS
    )
    semantic_nonstandard_xof_collision_screen = Fraction(
        4 * queries**3, 2**SHAKE256_SEMANTIC_BITS
    )
    # HGF6HR02 puts the six unavoidable secret roles on a nonstandard
    # rate-72/capacity-1024 Keccak XOF and calls it SHAKE512.  Its numeric
    # parameter screen is retained solely to explain the rejection boundary.
    # The shortest selected output is 448 bits, so the exact generic Grover
    # screen is Q^2 / 2^448 once over that primitive.  This has 224-bit work
    # factor before composition; the deployed standard-to-ideal/PRF reduction
    # remains external.  The rejected uniform SHAKE256 profile would instead
    # contribute Q^2 / 2^256 and fail at exactly 128 bits.
    semantic_nonstandard_xof_preimage_prf_screen = Fraction(queries**2, 2**448)
    # Strict DECS leaf hiding uses 512-bit independent tape and full SHA-512.
    # This finite guessing/preimage screen is necessary but not the missing
    # adaptive global leaf-hiding reduction.
    sha512_leaf_hiding_screen = Fraction(queries**2, 2**512)
    external, missing = _parse_external_losses(profile, query_label)
    conditional_total: Fraction | None = None
    ideal_global_arithmetic = (
        ideal_cms
        + abort_total
        + semantic_shake256_collision_screen
        + semantic_nonstandard_xof_collision_screen
        + semantic_nonstandard_xof_preimage_prf_screen
        + sha512_leaf_hiding_screen
    )
    if not missing:
        conditional_total = ideal_global_arithmetic + sum(external.values(), Fraction(0, 1))

    history_union_counterfactual = (
        SECURITY_EPOCH_PROOF_BUDGET * ideal_global_arithmetic
    )
    report: dict[str, object] = {
        "quantum_queries": str(queries),
        "interactive_terms": {
            name: _fraction_report(value) for name, value in interactive_terms.items()
        },
        "interactive_aggregate": _fraction_report(interactive_error),
        "ideal_cms_terms": {
            name: _fraction_report(value) for name, value in cms_terms.items()
        },
        "ideal_shared_history_cms_total": _fraction_report(ideal_cms),
        "ideal_global_arithmetic_total": _fraction_report(ideal_global_arithmetic),
        "sampler_terms": {
            "canonical_piop_nonce_exhaustion": _fraction_report(piop_abort),
            "fixed_decs_candidate_exhaustion": _fraction_report(decs_abort),
            "aggregate": _fraction_report(abort_total),
            "prover_grinding_multiplier": 1,
            "declared_grinding_loss": _fraction_report(Fraction(0, 1)),
        },
        "semantic_shake256_collision_screen": {
            **_fraction_report(semantic_shake256_collision_screen),
            "screen_only": True,
            "global_primitive_terms": 1,
            "semantic_shake_invocations": SEMANTIC_SHAKE_INVOCATIONS,
            "semantic_keccak_permutations": SEMANTIC_KECCAK_PERMUTATIONS,
            "per_invocation_or_permutation_union_multiplier": 1,
        },
        "semantic_nonstandard_keccak_c1024_xof_collision_screen": {
            **_fraction_report(semantic_nonstandard_xof_collision_screen),
            "screen_only": True,
            "global_primitive_terms": 1,
            "per_invocation_or_permutation_union_multiplier": 1,
        },
        "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen": {
            **_fraction_report(semantic_nonstandard_xof_preimage_prf_screen),
            "screen_only": True,
            "minimum_selected_output_bits": 448,
            "classical_preimage_cap_bits": 448,
            "quantum_preimage_cap_bits": 224,
            "global_primitive_terms": 1,
            "unavoidable_role_count": 6,
            "strict_primitive_margin_pass": True,
            "uniform_shake256_counterfactual": _fraction_report(
                Fraction(queries**2, 2**256)
            ),
        },
        "sha512_decs_leaf_hiding_screen": {
            **_fraction_report(sha512_leaf_hiding_screen),
            "screen_only": True,
            "random_tape_bits": 512,
            "global_primitive_terms": 1,
        },
        "history_composition": {
            "security_epoch_max_proofs": SECURITY_EPOCH_PROOF_BUDGET,
            "selected_model": "one shared tagged product oracle under one total query run",
            "selected_ideal_multiplier": 1,
            "counterfactual_per_proof_ideal_union": _fraction_report(history_union_counterfactual),
            "counterfactual_union_is_authorized": False,
        },
        "external_losses": {
            name: _fraction_report(value) for name, value in external.items()
        },
        "missing_external_losses": missing,
        "conditional_composed_total": (
            _fraction_report(conditional_total) if conditional_total is not None else None
        ),
    }
    return report, missing


def evaluate(profile_document: object, repo_root: Path) -> dict[str, object]:
    profile = _object(profile_document, "profile")
    geometry, profile_failures = _profile_and_geometry(profile)
    hash_role_report, hash_role_failures = _hash_role_gate(profile)
    source_report, source_failures = _source_binding_report(profile, repo_root)
    blockers = profile_failures + hash_role_failures + source_failures
    _, low_external_missing = _parse_external_losses(profile, "at_2pow64")
    _, work_external_missing = _parse_external_losses(profile, "at_2pow128")
    for name in sorted(set(low_external_missing + work_external_missing)):
        blockers.append(f"quantitative external loss missing: {name}")

    low_report: dict[str, object] | None = None
    work_report: dict[str, object] | None = None
    physical_report: dict[str, object] | None = None
    low_pass = False
    work_pass = False
    if geometry is not None:
        low_report, low_missing = _soundness_at_budget(
            profile, geometry, 2**LOW_QUERY_EXPONENT, "at_2pow64"
        )
        work_report, work_missing = _soundness_at_budget(
            profile, geometry, 2**WORK_QUERY_EXPONENT, "at_2pow128"
        )
        for name in sorted(set(low_missing + work_missing)):
            blockers.append(f"quantitative external loss missing: {name}")
        low_total = low_report["conditional_composed_total"]
        work_total = work_report["conditional_composed_total"]
        if low_total is not None:
            low_fraction = Fraction(
                int(low_total["numerator"]), int(low_total["denominator"])
            )
            low_pass = low_fraction < Fraction(1, 2**LOW_TARGET_BITS)
        if work_total is not None:
            work_fraction = Fraction(
                int(work_total["numerator"]), int(work_total["denominator"])
            )
            work_pass = work_fraction < WORK_MAX_SUCCESS
        if not low_pass:
            blockers.append(
                "conditional composition does not establish strictly <2^-128 at 2^64 queries"
            )
        if not work_pass:
            blockers.append("conditional composition does not establish <1/2 at 2^128 queries")
        physical_report = _physical_hash_inventory(profile, geometry)

    blockers.extend(f"unexecuted obligation: {name}" for name in UNEXECUTED_OBLIGATIONS)
    blockers = sorted(set(blockers))

    return {
        "schema": REPORT_SCHEMA,
        "profile_id": profile.get("profile_id"),
        "input_valid": True,
        "profile_identity": {
            "v6_tuple": EXPECTED_IDENTITY,
            "statement_bytes": STATEMENT_BYTES,
            "public_fields": PUBLIC_FIELD_COUNT,
            "padding_zero_bytes": STATEMENT_PADDING_ZERO_BYTES,
            "rejects_v5_78_or_stale_v6_122_130_reuse": True,
            "strict_decs_identity": {
                "evaluation_domain": "disjoint-coset",
                "radix2_subgroup_forbidden": True,
                "opened_leaf_binding": "random-tape-and-index",
                "random_tape_bytes_per_leaf": OPENED_LEAF_RANDOM_TAPE_BYTES,
                "opened_tape_bytes_total": OPENED_LEAF_TAPE_BYTES_TOTAL,
            },
        },
        "relation_identity": {
            "semantic_hash": "rejected HGF6HR02 nonstandard Keccak[c=1024] XOF plus FIPS SHAKE256-448",
            "statement_magic": "HGF6ST02",
            "semantic_frame_profile": "HEG-F6V2",
            "relation_hash_role_registry_magic": "HGF6HR02",
            "relation_hash_role_registry_sha512": hash_role_report[
                "observed_relation_registry_sha512"
            ],
            "semantic_shake_invocations": SEMANTIC_SHAKE_INVOCATIONS,
            "semantic_keccak_permutations": SEMANTIC_KECCAK_PERMUTATIONS,
            "pre_ciphertext_projection_rejected": {
                "semantic_shake_invocations": 77,
                "semantic_keccak_permutations": 90,
            },
            "ciphertexts": {
                "count": CIPHERTEXT_COUNT,
                "bytes_each": CIPHERTEXT_BYTES,
                "frame_bytes_each": CIPHERTEXT_FRAME_BYTES,
                "keccak_permutations_each": CIPHERTEXT_KECCAK_PERMUTATIONS // CIPHERTEXT_COUNT,
            },
            "global_semantic_primitive_terms": 3,
            "global_semantic_primitive_term_ids": [
                "semantic_shake256_collision_screen",
                "semantic_nonstandard_keccak_c1024_xof_collision_screen",
                "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen",
            ],
            "per_invocation_or_permutation_union_forbidden": True,
        },
        "quantitative_external_loss_inventory": list(QUANTITATIVE_EXTERNAL_LOSSES),
        "global_budgets": {
            "low_advantage": {
                "quantum_queries": str(2**LOW_QUERY_EXPONENT),
                "target": "advantage strictly < 2^-128",
            },
            "work_factor": {
                "quantum_queries": str(2**WORK_QUERY_EXPONENT),
                "target": "success < 1/2",
            },
            "security_epoch_max_proofs": SECURITY_EPOCH_PROOF_BUDGET,
            "max_proofs_per_block": MAX_PROOFS_PER_BLOCK,
        },
        "source_binding": source_report,
        "hash_role_gate": hash_role_report,
        "conventional_successor_tournament": _conventional_successor_tournament(),
        "geometry_available": geometry is not None,
        "geometry": geometry,
        "physical_hash_inventory": physical_report,
        "history_query_inventory": _history_query_inventory(profile),
        "low_advantage_accounting": low_report,
        "work_factor_accounting": work_report,
        "numeric_gates": {
            "low_advantage_pass": low_pass,
            "work_factor_pass": work_pass,
            "hash_role_strict_margin_pass": hash_role_report[
                "strict_primitive_margin_pass"
            ],
        },
        "composition_term_inventory": {
            "pcs_iop": {
                "finite_terms": [
                    "decs_uniform_matrix",
                    "piop_constraint_batching",
                    "piop_opening_without_replacement",
                    "decs_opening_without_replacement",
                    "cms_rbr_amplification",
                    "cms_oracle_database_bridge",
                ],
                "external_losses": [
                    "lppc_lvcs_decs_pcs_binding",
                    "lppc_piop_knowledge_soundness",
                    "noninteractive_proof_of_knowledge_extraction",
                ],
            },
            "fiat_shamir": {
                "finite_terms": ["cms_sha512_collision_instability"],
                "external_losses": [
                    "fiat_shamir_qrom_transform",
                    "sha512_standard_to_tagged_product_oracle",
                    "sha512_xof_sampling_and_rejection",
                ],
            },
            "hash": {
                "finite_terms": [
                    "semantic_shake256_collision_screen",
                    "semantic_nonstandard_keccak_c1024_xof_collision_screen",
                    "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen",
                    "sha512_decs_leaf_hiding_screen",
                ],
                "external_losses": [
                    "mixed_shake_relation_instantiation_binding",
                    "shake256_collision_binding",
                    "nonstandard_keccak_c1024_xof_collision_binding",
                    "nonstandard_keccak_c1024_xof_preimage_prf_security",
                    "sha512_merkle_pcs_binding",
                    "decs_leaf_tape_qrom_hiding",
                ],
            },
            "grinding_retry": {
                "opening_pow_bits": 0,
                "decs_pow_bits": 0,
                "prover_grinding_multiplier": 1,
                "finite_terms": [
                    "canonical_piop_nonce_exhaustion",
                    "fixed_decs_candidate_exhaustion",
                ],
                "external_losses": ["grinding_retry_abort_composition"],
            },
            "union_history": {
                "selected_multiplier": 1,
                "per_proof_union_forbidden": True,
                "external_losses": ["global_history_product_oracle_transfer"],
            },
        },
        "capabilities": {
            "conditional_integer_accounting_complete": (
                geometry is not None
                and source_report["binding_pass"] is True
                and low_pass
                and work_pass
                and hash_role_report["strict_primitive_margin_pass"] is True
            ),
            "composed_pq128": False,
            "production_authorized": False,
        },
        "blocking_reasons": blockers,
        "claim_ceiling": (
            "source-bound conditional arithmetic only; no deployed PQ/QROM or production authority"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
    )
    args = parser.parse_args()
    try:
        report = evaluate(load_json_strict(args.profile), args.repo_root)
    except CompositionInputError as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "input_valid": False,
            "capabilities": {
                "conditional_integer_accounting_complete": False,
                "composed_pq128": False,
                "production_authorized": False,
            },
            "blocking_reasons": [str(exc)],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        raise SystemExit(1) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(2)


if __name__ == "__main__":
    main()
