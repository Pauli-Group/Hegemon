#!/usr/bin/env python3
"""Canonical, fail-closed Aurora PQ/QROM architecture screen.

This module retains exact primary-source expressions and exact arithmetic only.
It does not build Aurora, compile an R1CS matrix, serialize a proof, or infer a
whole-protocol theorem from the FRI subprotocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CERTIFICATE_PATH = HERE / "certificate.json"
SCHEMA = "hegemon.aurora-pq128-screen.v1"

STRICT_TARGET_BITS = 128
SOURCE_STATIC_M = 29_509_133
SOURCE_STATIC_N_UPPER = 29_606_837
SOURCE_STATIC_STATEMENT_BYTES = 1_141
SOURCE_STATIC_VERIFIER_CONTEXT_BYTES = 72
SOURCE_STATIC_PRIVATE_WITNESS_BYTES = 11_000
SOURCE_STATIC_PUBLIC_WORDS_WITH_CONTEXT = 152
SOURCE_STATIC_RELATION_HASH_CALLS = 90
SOURCE_STATIC_RELATION_BLAKE2B_COMPRESSIONS = 213
SOURCE_STATIC_ACTIVITY_MASKS = 16
SOURCE_STATIC_AUTHORIZATION_MODES = 5
SOURCE_STATIC_ACCEPTED_MASK_MODE_PAIRS = 33
SOURCE_STATIC_REJECTED_MASK_MODE_PAIRS = 47
UNFROZEN_BINARY_MACRO_M = 37_364_095
UNFROZEN_BINARY_MACRO_N = 21_531_353
UNFROZEN_BINARY_MACRO_L = 9_704
UNFROZEN_BINARY_MACRO_NNZ = 156_526_483

AURORA_PDF_SHA512 = (
    "ad9351a0f7010d57fb9f3482fa442a213a2f9192f82f319f6bed74cef07733ec"
    "e1f95dad8270523e52c80daa1a7f7a33505fc665afafc32dfbf90e4de5971d41"
)
CMS19_PDF_SHA512 = (
    "1fc3a6cfce5c1ab2e9e0352581f6725c48ee1b52fa6773d456614d4137cb54144"
    "3010c127a9fbdfd642ebf5249c05503c4ff531f2995e2918ad1190df334367f"
)
BCS16_PDF_SHA512 = (
    "66557007b59ec3ce3657b22b6b4c5047ef60762b2e6b7d0c2baff16ad5d4dfa77"
    "b2f3aa5e8f068f8d260ae9919cf862a23ff685ff0c82356d207ebac3c3f6914"
)
BLOCK23_PDF_SHA512 = (
    "24feff318b5ead17f0747e389fdbb03b2257b4c671b92fde8496b689871551ca6"
    "585264935c5078bffb75bc18300b6eb0ee463ed09edd0e6229b182eba5cc23d"
)

LOCAL_PRIMARY_SOURCES = (
    {
        "id": "aurora_2018_828",
        "title": "Aurora: Transparent Succinct Arguments for R1CS",
        "url": "https://eprint.iacr.org/2018/828.pdf",
        "local_path": "/private/tmp/hegemon-mith-sources/aurora-2018-828.pdf",
        "sha512": AURORA_PDF_SHA512,
        "anchors": [
            "Definition 4.4, physical PDF page 17",
            "Theorem 9.2, physical PDF page 40",
            "Figure 5, physical PDF pages 41-42",
            "Appendix C FRI bounds",
        ],
    },
    {
        "id": "cms19_834",
        "title": "Succinct Arguments in the Quantum Random Oracle Model",
        "url": "https://eprint.iacr.org/2019/834.pdf",
        "local_path": "/private/tmp/cms19-834.pdf",
        "sha512": CMS19_PDF_SHA512,
        "anchors": [
            "Theorem 8.6, printed page 40",
            "Appendix B Lemma B.2, printed page 48",
        ],
    },
    {
        "id": "bcs16_116",
        "title": "Interactive Oracle Proofs",
        "url": "https://eprint.iacr.org/2016/116.pdf",
        "local_path": "/private/tmp/bcs-2016-116.pdf",
        "sha512": BCS16_PDF_SHA512,
        "anchors": [
            "Lemma 3.4",
            "Lemma 7.5, physical PDF page 32",
        ],
    },
    {
        "id": "block_2023_1256",
        "title": "On Soundness Notions for Interactive Oracle Proofs",
        "url": "https://eprint.iacr.org/2023/1256.pdf",
        "local_path": "/private/tmp/block-2023-1256.pdf",
        "sha512": BLOCK23_PDF_SHA512,
        "anchors": [
            "generalized special soundness implies generalized RBR soundness",
            "no Aurora-specific application identified",
        ],
    },
)

REMOTE_PRIMARY_SOURCES = (
    {
        "id": "fri_rbr_2023_1071",
        "title": "Fiat-Shamir Security of FRI and Related SNARKs",
        "url": "https://eprint.iacr.org/2023/1071",
        "scope": (
            "FRI, batched FRI, and a stated delta-correlated class including "
            "Plonk-like protocols; the abstract does not claim Aurora"
        ),
    },
    {
        "id": "preon_round1_spec",
        "title": "Preon specification",
        "url": (
            "https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/"
            "round-1/spec-files/Preon-spec-web.pdf"
        ),
        "scope": (
            "Conjectures 4.7, 4.11, and 4.12 leave Aurora state-restoration "
            "and round-by-round knowledge inheritance conjectural"
        ),
    },
    {
        "id": "libiop_master_pin",
        "title": "scipr-lab/libiop",
        "url": "https://github.com/scipr-lab/libiop",
        "commit": "a2ed2ec2f3e85f29b6035951553b02cb737c817a",
    },
)

LOCAL_LIBIOP_SOURCES = {
    "/private/tmp/aurora-pq128-screen-pages/libiop-tree.json": "ced8aab66f3d262e13dbbc48c07072e9597b4afc7a00a6a609b18e3437f828cdd8b1f4dafbc73c8e16d3a027a030d0123dd0e54c61960e81dc5e86375afc464a",
    "/private/tmp/aurora-pq128-screen-pages/aurora_iop.tcc": "fd70ee2a35c874bed7be6ff7a0587fb3b5de7f68950768b23ad0a84151b3d57f3aee336f4761920932c6136fdf2d08b94f260f4646b9e5d08d3a38034786eaaf",
    "/private/tmp/aurora-pq128-screen-pages/fri_ldt.tcc": "0eedb66eb0e3b28a92b9e20ed69835bf4839d755a6d81af5ce07eca7f94df3353ce7915bd5e15c75d9933500edeec551f02a82467306285168346b7c5eb0353e",
    "/private/tmp/aurora-pq128-screen-pages/fri_aux.tcc": "ae252578212ec2a0d653f1d2aca5596e9e2363c838b4ba3a0436a74c88b2a3ead49397b25c044158644b2ad731ab384b85036c275e66830be0ad319ca2a42bcb",
    "/private/tmp/aurora-pq128-screen-pages/argument_size_optimizer.tcc": "5ecfd4c2acdf4b22930df1e890c0d19ac8ff3cf2b34eecad5b4ce225cbe90ccdbcee8ae29fb44533b6c324e310569df7be6b49e8e98f44404d64d51aab49dd60",
    "/private/tmp/aurora-pq128-screen-pages/instrument_aurora_snark.cpp": "3c9d5910582b98eae4c03fa8642718b38459f3701fb240174b3fe9a43004dc7594aa639a9601bb28a70cd114f2d09a724ca3e562261ef06ad94943245181621d",
    "/private/tmp/aurora-pq128-screen-pages/bcs_common.hpp": "3c179cb6fd4673caadcfde55b4dda5b2b52b097181967df9d05b8ee85d7ac30a4b61c8b1cee8912d80f7512065a441ef73c56075c4dd297c3da1c13471230a12",
    "/private/tmp/aurora-pq128-screen-pages/bcs_common.tcc": "8f4af4f53d75783e3b3535dd093f2037d00223df27feebd29a41c329f98a55d9aa3d4305dc4a8f37fc71a6a5148f66843b60c0e6e5fad7702aa2726cfb6c2e02",
    "/private/tmp/aurora-pq128-screen-pages/common_bcs_parameters.tcc": "420a16bfe2066d509d5e6edde55d788794271ad12df8f2b87f92ab0dd84c7c94f1a2ecd6a6745afe850cd13d961f3f7e093cbdbbce1be3c437b6de8de8669fa9",
    "/private/tmp/aurora-pq128-screen-pages/bcs_README.md": "712259dc8251c4c3edf9b95f3c52970a1af83052489be1a1497be1e11007bb8486bd3bf6da7ec2ad56a6b4c0cd2fb01390d36e550eb4c91d8d0f5014aa31bbb7",
    "/private/tmp/aurora-pq128-screen-pages/hash_enum.hpp": "ffea14e478a5bbfd5e2fe0902d7c5bd798e4b34eefdbc33d542c54814b1b172e6ded2cf375e889c0d8093dcdcc15e42803fd1ab7b486be7d03b175be170c4c6c",
    "/private/tmp/aurora-pq128-screen-pages/hash_enum.tcc": "2a1e913b201ec30402efa7876bc5f2761f184437f71cef1aa5c7a7e0a75ae68fd1f98cb424350dde7c1a50012986e2a1bf9d53dec61e124c1978747ea5b8f4a6",
    "/private/tmp/aurora-pq128-screen-pages/blake2b.tcc": "44da54a60d5c3888485abd2e07c16dce21f01415decb29098487e108eabdd610ba924c15293c0b48c88bcd3ce6e17cde83f2849896fa23771cc4f2956a846382",
    "/private/tmp/aurora-pq128-screen-pages/merkle_tree.tcc": "02791aa46f1feead816f4a7859bf4968c188b4d9a785cccb2b0c8d15dbf8f34d8a188727c05db3d139fa27519f9b9d02dfcf17f19472d8a992d979f916dc5746",
    "/private/tmp/aurora-pq128-screen-pages/pow.tcc": "a778df4cd359f5bb63a5e41de95b2ae81051224183ef17febb307e4e808821eedbdc07074f509e6e747a89b8190e99c4ed918b29bf5f4f7d39e3a7a46c07c5b4",
}

LOCAL_REPO_SOURCES = {
    ".agent/hardening/hx512-semantic-suite/suite_report.json": "512306586873a868eb6ae8b8661fc44b9be2b50ec655b62e67a91025aa15242f3da709cfba4e4b521f082cfd73dd4189abf5f2c19e2579ae0678c31df4819952",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json": "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e",
    ".agent/hardening/strict-odd-field-composition/ledger.json": "881bafb101fc4f4c9e9c95612e5ec4914432b8ae34023b5aa2c84e4fb7eb03a6fa892ab40d3e99584ab0bfaa5c2e04ee7af28aaf2ff4e0173fbe54e61ad70f13",
    ".agent/hardening/cfw26-section11-carrier-compiler/carrier_manifest.json": "888f4a42f6d5b37aab132e2ba60318a5ee08d6b71f69046ade2ce206e5af99ab479c6555b9635e8750afa2d68ea7f3da12ecb2d47ac3882834a33b76c03bb730",
    ".agent/hardening/cfw26-section11-carrier-compiler/certificate.json": "c8a170acfde05345512b2ca23485fb3ff3b7a4b1d6e71a344b7c777ed6c091d9635d30723712d00a9d30ba16c8c02189bb485b8e2e6f1109903fa7211375756c",
    ".agent/hardening/provekit-architecture-screen/ledger.json": "c46eb3de05021270d9c90835242a78d918c68c12f300b1a992d6cd0045f18a1d0a4d7626807cdd651641185752cd81370664b014213372a3dee083fd59ce1566",
    ".agent/hardening/aurora-binary-relation-compile/compiler.py": "7870092341873f9c24475d9c5c732da6e9653a15858ea35cdb8377360dea6d882f93a8c7916d608ba8c3287a2d81333a26850642daee9047aecc8e26b2ae3cea",
    ".agent/hardening/aurora-binary-relation-compile/test_compiler.py": "ab5f114e371e57b607e1d754aa4bb12cd98dc11443f4cf624161a9e82f5078a042b5a07818fca492b256c89f5256c7707b5a92ec504798b17bfce3a0577b8d0c",
    ".agent/hardening/aurora-implementation-audit/source_closure.py": "132f98c16efe7159d0de9ec30439197c417ee25097681218808fdcded87d07b9b2d5a17b4daf54c841a78db8c085683ebdd09be87725c27e8a12e273d96a5e5c",
    ".agent/hardening/aurora-implementation-audit/upstream_source_closure.json": "45578f624fc419cf3ec1fa381aa7787f0ed2d8dd52f2650de9e5a12636bb77f5b985ebe5e653775047f2ac941b4ce9a20ab1be08e0f864132bc2498b2f25a0c0",
}

AUTHORITY_GATES = (
    "exact_binary_full_relation",
    "complete_zero_knowledge_nizk",
    "whole_aurora_round_by_round_soundness",
    "composed_strict_gt_128_pq_qrom",
    "canonical_self_contained_parser_and_wire",
    "retained_same_relation_proof",
    "mutation_restart_and_fresh_node_verification",
    "native_verifier_refinement",
    "consensus_lifecycle_binding",
    "architecture_winner",
    "production_authorized",
)

REQUIRED_COMPOSITION_TERMS = (
    ("pcs_salted_merkle_binding", "pcs"),
    ("pcs_salted_merkle_statistical_privacy", "pcs"),
    ("iop_interaction_soundness", "iop"),
    ("iop_query_soundness", "iop"),
    ("whole_aurora_round_by_round_soundness", "iop"),
    ("modified_bcs_fiat_shamir_qrom", "fiat-shamir"),
    ("fiat_shamir_augmented_query_overhead", "fiat-shamir"),
    ("proof_transcript_concrete_hash_qro_instantiation", "hash"),
    ("semantic_hash_role_composition", "hash"),
    ("proof_of_work_or_grinding", "grinding"),
    ("challenge_sampling_retry_and_rng", "grinding"),
    ("multi_proof_block_reorg_history_union", "union"),
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fraction_record(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def security_bits_display(value: Fraction) -> float:
    return round(-math.log2(float(value)), 12)


def strict_target() -> Fraction:
    return Fraction(1, 1 << STRICT_TARGET_BITS)


def next_power_of_two_strictly_greater_than(value: int) -> int:
    if value < 0:
        raise ValueError("value must be nonnegative")
    return 1 << value.bit_length()


def bcs_direct_zk_term(proof_length_bits: int, lambda_bits: int) -> Fraction:
    """Return BCS Lemma 7.5's p*2^(-lambda/4+2) exactly."""

    if proof_length_bits < 1 or lambda_bits < 8 or lambda_bits % 4:
        raise ValueError("positive p and lambda divisible by four required")
    return Fraction(proof_length_bits, 1 << (lambda_bits // 4 - 2))


def first_strict_bcs_lambda(proof_length_bits: int) -> int:
    for lambda_bits in range(8, 4097, 4):
        if bcs_direct_zk_term(proof_length_bits, lambda_bits) < strict_target():
            return lambda_bits
    raise AssertionError("BCS lambda search exhausted")


def source_projection_floor(field_bits: int) -> dict[str, Any]:
    """Conditional p floor from the rejected all-W64 source row projection.

    This is not exact binary relation geometry. It screens any Aurora adapter
    that retains at least SOURCE_STATIC_M constraint rows.
    """

    l_floor = next_power_of_two_strictly_greater_than(4 * SOURCE_STATIC_M)
    p_bits = 4 * l_floor * field_bits
    lambda512 = bcs_direct_zk_term(p_bits, 512)
    first_lambda = first_strict_bcs_lambda(p_bits)
    return {
        "status": "conditional_source_projection_floor_only",
        "source_static_m": SOURCE_STATIC_M,
        "premises": [
            "the Aurora adapter retains at least the source-static m rows",
            "positive proven FRI query gap requires rho<1/2",
            "2*max(m,n+1)+2*b <= rho*|L|",
            "L has power-of-two size",
            "p_symbols coefficient is at least 4",
        ],
        "l_floor": l_floor,
        "l_floor_log2": l_floor.bit_length() - 1,
        "field_bits": field_bits,
        "p_iop_bits_floor": p_bits,
        "p_iop_bytes_floor_for_privacy_arithmetic_only": p_bits // 8,
        "lambda512_direct_zk_term": fraction_record(lambda512),
        "lambda512_direct_zk_security_bits_upper_bound": security_bits_display(lambda512),
        "lambda512_strict_gt_128": lambda512 < strict_target(),
        "minimum_multiple_of_four_lambda_for_floor": first_lambda,
        "minimum_byte_aligned_lambda_for_floor": 8 * ((first_lambda + 7) // 8),
        "exact_total_iop_proof_length_bits": None,
        "required_lambda_for_exact_total_iop_proof": None,
        "proof_bytes": None,
        "not_a_proof_byte_bound": True,
        "claim_boundary": (
            "p is total uncompressed IOP oracle length used only in the BCS "
            "privacy theorem; BCS Merkle commitments compress those oracles"
        ),
    }


def theorem_minimal_projection_floor() -> dict[str, Any]:
    l_floor = next_power_of_two_strictly_greater_than(4 * SOURCE_STATIC_M)
    field_bits_floor = l_floor.bit_length()
    result = source_projection_floor(field_bits_floor)
    result["field_bits_basis"] = (
        "a size-2^27 affine L disjoint from nonempty H needs a binary field "
        "with at least one more vector-space dimension"
    )
    return result


def theorem_9_2() -> dict[str, Any]:
    return {
        "relation": "RR1CS over a binary field F",
        "condition": "2*max(m,n+1)+2*b <= rho*|L|",
        "rho_domain": "rho in (0,1) constant",
        "meaningful_proven_fri_query_gap_requires": "rho<1/2",
        "alphabet": "F",
        "number_of_rounds": "O(log|L|)",
        "exact_number_of_rounds": None,
        "full_iop_oracle_length_symbols": "(4+2*lambda_i+(lambda_i_prime*lambda_i_FRI)/3)*|L|",
        "core_expression_status": "exact_printed_symbolic_expression_uninstantiated",
        "core_expression_is_proof_bytes": False,
        "query_complexity": "O(lambda_i*lambda_i_FRI*lambda_q_FRI*log|L|)",
        "query_complexity_hidden_constant": None,
        "interaction_soundness": (
            "((m+1)/|F|)^lambda_i + (|L|/|F|)^lambda_i_prime "
            "+ epsilon_i_FRI(F,L)^lambda_i_FRI"
        ),
        "query_soundness": "epsilon_q_FRI(L,rho,delta)^lambda_q_FRI",
        "ordinary_soundness_upper_bound": "epsilon_i+epsilon_q",
        "delta": "min((1-2*rho)/2,(1-rho)/3,1-rho)",
        "fri_proven_interaction_base": "3*|L|/|F|",
        "fri_proven_query_base": (
            "1-min(delta,(1-3*rho-2^eta/sqrt(|L|))/4)"
        ),
        "zero_knowledge_query_bound": "b",
        "honest_verifier_condition": "b>=q_pi",
        "h1_size": "m padded upward to a power of two",
        "h2_size": "n+1 padded upward to a power of two",
        "h1_h2_nesting": True,
        "l_disjoint_from_h1_union_h2": True,
        "selected_parameters": {
            "field_bits": None,
            "rho": None,
            "l_size": None,
            "b": None,
            "lambda_i": None,
            "lambda_i_prime": None,
            "lambda_i_FRI": None,
            "lambda_q_FRI": None,
            "eta": None,
            "q_pi": None,
            "k_rounds": None,
        },
    }


def relation_screen() -> dict[str, Any]:
    return {
        "target": "prospective all-W64 HX512 BLAKE2b-512 full Hegemon transaction relation",
        "source_static_projection": {
            "m_constraints": SOURCE_STATIC_M,
            "n_nonconstant_variables_upper_bound": SOURCE_STATIC_N_UPPER,
            "l_public_variables": None,
            "matrix_nonzeros_total": None,
            "statement_bytes": SOURCE_STATIC_STATEMENT_BYTES,
            "verifier_context_bytes": SOURCE_STATIC_VERIFIER_CONTEXT_BYTES,
            "private_witness_bytes": SOURCE_STATIC_PRIVATE_WITNESS_BYTES,
            "public_words_with_context": SOURCE_STATIC_PUBLIC_WORDS_WITH_CONTEXT,
            "relation_hash_calls": SOURCE_STATIC_RELATION_HASH_CALLS,
            "relation_blake2b512_compressions": SOURCE_STATIC_RELATION_BLAKE2B_COMPRESSIONS,
            "activity_masks": SOURCE_STATIC_ACTIVITY_MASKS,
            "authorization_modes": SOURCE_STATIC_AUTHORIZATION_MODES,
            "mask_mode_pairs": 80,
            "accepted_mask_mode_pairs": SOURCE_STATIC_ACCEPTED_MASK_MODE_PAIRS,
            "rejected_mask_mode_pairs": SOURCE_STATIC_REJECTED_MASK_MODE_PAIRS,
            "status": "anonymous_macro_count_projection_not_executable_sparse_r1cs",
            "exact_binary_r1cs_geometry": False,
        },
        "exact_binary_compile": {
            "compiled": False,
            "field_characteristic": 2,
            "m": None,
            "n": None,
            "l": None,
            "nnz": None,
            "matrix_digest": None,
            "deterministic_variable_map_digest": None,
            "canonical_statement_to_field_map": None,
            "canonical_witness_to_field_map": None,
            "public_input_padding": None,
            "semantic_refinement": False,
        },
        "unfrozen_binary_source_macro_projection": {
            "m_constraints": UNFROZEN_BINARY_MACRO_M,
            "n_nonconstant_variables": UNFROZEN_BINARY_MACRO_N,
            "l_public_bits": UNFROZEN_BINARY_MACRO_L,
            "sparse_nonzeros_projection": UNFROZEN_BINARY_MACRO_NNZ,
            "aurora_padding": {
                "m_padded": 67_108_864,
                "h1_size": 67_108_864,
                "n_padded": 33_554_431,
                "n_plus_one_h2_size": 33_554_432,
                "public_inputs_padded": 16_383,
                "public_input_h2_size": 16_384,
                "injected_canonical_public_zero_inputs": 6_679,
                "private_and_derived_index_shift": 6_679,
            },
            "executable_sparse_matrices_retained": False,
            "typed_symbolic_ir_frozen": False,
            "verified_ir_to_binary_sparse_lowering": False,
            "accepted_geometry": False,
            "used_for_bcs_privacy_floor": False,
            "proof_bytes": None,
            "claim_boundary": (
                "exact arithmetic of an unfrozen macro attempt only; not an "
                "accepted R1CS, theorem instance, or proof-system input"
            ),
        },
        "mapping_gaps": [
            "no frozen executable typed relation IR and mutation-residual certificate",
            "no materialized canonical A/B/C rows or exact wire allocation tying all 90 BLAKE calls and seven V2 authority compressions to coordinates",
            "four former host predicates reject only in the reference evaluator and macro schedule, not a verified sparse matrix",
            "no scalar/source-macro-to-binary-matrix refinement",
            "no selected GF(2^s), irreducible polynomial, or strict extension-degree-above-codeword-dimension witness",
            "libiop shifted-domain disjointness TODO remains unproved for a selected field",
            "manifest_root64||parent_height:u64le is not refined to authenticated native parent state",
        ],
        "odd_field_frozen_relation_reusable_as_binary_relation": False,
        "source_projection_is_exact_full_relation": False,
        "all_w64_manifest_predicates_binary_compiled": False,
        "claim_boundary": (
            "the source schedule covers the intended families, but counts and "
            "transport layouts do not constitute an accepted binary R1CS"
        ),
    }


def zero_knowledge_screen() -> dict[str, Any]:
    return {
        "aurora_definition_4_4": {
            "perfect": True,
            "whole_view": True,
            "bounded_query": True,
            "straightline": True,
            "queries_during_interaction_allowed": True,
            "identical_distribution": True,
            "adaptive_within_bound": True,
        },
        "aurora_theorem_9_2": {
            "applies_to_binary_r1cs": True,
            "perfect_b_query_iop_zk": True,
            "b_ge_q_pi_selected": False,
            "parameter_profile_selected": False,
        },
        "modified_bcs": {
            "honest_verifier_zk_preservation_theorem": True,
            "salted_merkle_privacy_expression": "z+p_bits*2^(-lambda_BCS/4+2)",
            "aurora_iop_z": "0 when exact Theorem 9.2 premises hold",
            "exact_total_p_bits": None,
            "lambda_BCS": None,
            "statistical_nizk_error": None,
            "fully_salted_all_secret_oracle_leaves_refined": False,
        },
        "complete_nizk_zk_gate": False,
        "gate_blockers": [
            "exact binary relation and Theorem 9.2 parameters are not selected",
            "b>=q_pi is uninstantiated because q_pi has a hidden big-O constant",
            "exact total IOP proof length p_bits is unknown",
            "pinned implementation selectively salts rounds without a refinement proof to the fully salted theorem",
            "canonical binary-field proof wire is absent",
        ],
    }


def rbr_screen() -> dict[str, Any]:
    return {
        "cms19_requirement": "round-by-round soundness of the complete underlying IOP",
        "cms19_theorem_8_6": {
            "soundness": "O(T^2*epsilon_RBR+T^3/2^lambda_BCS)",
            "hidden_constant": None,
            "attacker_qro_queries": "at most T-O(q*log(ell))",
            "augmented_query_overhead_constant": None,
            "zero_knowledge_preservation": "statistical ZK from honest-verifier ZK",
        },
        "whole_aurora_direct_rbr_theorem": False,
        "fri_component_rbr_is_whole_aurora_rbr": False,
        "fri_2023_1071_scope_includes_aurora": False,
        "aurora_proved_delta_correlated_class_membership": False,
        "aurora_proved_generalized_special_soundness": False,
        "block_2023_1256_implication_applicable": False,
        "preon_conjectural_boundary": {
            "conjecture_4_7": "Aurora restricted state-restoration knowledge error inheritance",
            "conjecture_4_11": "state-restoration knowledge to RBR knowledge",
            "conjecture_4_12": "Aurora RBR knowledge error no worse than ordinary knowledge error",
            "all_proved": False,
        },
        "cms_appendix_b_generic_fallback": {
            "expression": "mu^(1/(k+1))",
            "premise": "k-round IOP with ordinary soundness mu",
            "exact_k": None,
            "exact_mu": None,
            "instantiated": False,
            "finite_concrete_error": None,
        },
        "cms_applicable_to_current_profile": False,
        "claim_boundary": (
            "FRI RBR cannot be inherited across Aurora's lincheck, sumcheck, "
            "masking, random-combination, and reduction layers without a theorem"
        ),
    }


def implementation_screen() -> dict[str, Any]:
    return {
        "repository": "https://github.com/scipr-lab/libiop",
        "commit": "a2ed2ec2f3e85f29b6035951553b02cb737c817a",
        "license_spdx": "MIT",
        "license_sha512": "05c7b8c925af9cc8a58c056f9cb2b9eeccd85146786396c798842448475a4019a9ff82168e9126ff466a0e8b76b929a2b8452833b90ae6b938589b680033ba44",
        "static_include_closure": {
            "files": 113,
            "lines": 18_818,
            "bytes": 783_493,
            "missing_local_includes": [],
            "external_include_counts": {
                "cxx_or_system": 224,
                "libff": 38,
                "libfqfft": 4,
                "libsodium": 5,
            },
            "built_or_linked": False,
        },
        "status": "academic_proof_of_concept_not_production_reviewed",
        "binary_fields_exposed_by_profiler_bits": [64, 128, 192, 256],
        "binary_field_384_or_512_exposed": False,
        "hash_choices": ["BLAKE2b", "Poseidon"],
        "sha512_supported": False,
        "shake_supported": False,
        "poseidon_allowed_by_hegemon_gate": False,
        "blake2b_digest_bits_formula": "2*security_parameter",
        "blake2b_max_digest_bits": 512,
        "hash_personalization_implemented": False,
        "field_element_hashing": "raw sizeof(FieldT) memory",
        "canonical_field_encoding_refined": False,
        "binary_or_nonalgebraic_serialization_implemented": False,
        "binary_or_nonalgebraic_deserialization_implemented": False,
        "canonical_final_transcript_serialization": False,
        "logical_size_counter_includes_query_positions": False,
        "logical_size_counter_is_canonical_proof_bytes": False,
        "proof_of_work_added": True,
        "proof_of_work_qrom_theorem_mapping": False,
        "default_fri_soundness_is_heuristic": True,
        "proven_fri_mode_available": True,
        "selective_zk_round_salting_refined_to_paper": False,
        "implementable_relation_adapter": False,
        "implementation_blockers": [
            "exact binary R1CS adapter and field-byte grammar absent",
            "binary/non-algebraic transcript serialization and parser absent",
            "query-position bytes omitted by size accounting",
            "only BLAKE2b or Poseidon backends; no SHA-512/SHAKE backend",
            "BLAKE2b cannot emit the >512-bit digest required by the current source-projection privacy floor",
            "raw in-memory field hashing is not a canonical network encoding",
            "non-standard proof-of-work and selective salting lack exact theorem/refinement evidence",
        ],
    }


def physical_hash_ledger() -> dict[str, Any]:
    return {
        "semantic_relation": {
            "algorithm": "BLAKE2b-512",
            "physical_hash_calls": SOURCE_STATIC_RELATION_HASH_CALLS,
            "compression_calls": SOURCE_STATIC_RELATION_BLAKE2B_COMPRESSIONS,
            "status": "source-static schedule only",
        },
        "proof_backend": {
            "merkle_leaf_hash_calls": None,
            "merkle_compression_calls": None,
            "hashchain_absorb_calls": None,
            "fiat_shamir_squeeze_calls": None,
            "salt_hash_calls": None,
            "proof_of_work_hash_calls": None,
            "sha512_calls": None,
            "shake_calls": None,
            "total_physical_calls": None,
        },
        "physical_call_accounting_complete": False,
        "conventional_hash_candidate": None,
        "candidate_notes": {
            "SHA-512": "fixed 512-bit output fails the current source-projection BCS privacy floor",
            "SHAKE256": "variable output could exceed the floor, but no backend, concrete QROM bridge, or exact call ledger exists",
            "BLAKE2b-512": "implemented only up to 512 bits and fails the same floor",
        },
    }


def composition_screen() -> dict[str, Any]:
    return {
        "required_terms": [
            {
                "id": term_id,
                "category": category,
                "value": None,
                "authority": "missing",
            }
            for term_id, category in REQUIRED_COMPOSITION_TERMS
        ],
        "pcs_term": None,
        "iop_term": None,
        "fiat_shamir_term": None,
        "hash_term": None,
        "grinding_term": None,
        "union_term": None,
        "symbolic_total": (
            "Adv_relation + Adv_PCS + epsilon_IOP + "
            "C_CMS*(T^2*epsilon_RBR+T^3/2^lambda_BCS) + "
            "p_bits*2^(-lambda_BCS/4+2) + Adv_QRO_inst_proof + "
            "Adv_semantic_hash + Adv_grinding + Adv_rng + N_verify*Adv_one"
        ),
        "cms_big_o_constant": None,
        "qro_query_budget_T": None,
        "bcs_lambda_bits": None,
        "field_bits": None,
        "fri_repetitions": None,
        "overall_advantage": None,
        "composed_security_bits": None,
        "strictly_below_2^-128": False,
        "complete": False,
        "claim_boundary": "null terms are missing authority, never zero advantage",
    }


def comparator_screen() -> dict[str, Any]:
    return {
        "cfw26_105_oracle_carrier": {
            "encoded_oracles": 105,
            "printed_theorem_inheritance": False,
            "proof_bytes": None,
            "defects": [
                "printed coefficient and Step 9 typing defects",
                "main identity requires explicit row_M(M,alpha)",
                "printed st2=(0,1,0,...) selects coefficient one rather than s(1); honest s=X^2-X fails",
                "repair requires st2=pow(1) and a new inherited theorem/refinement",
            ],
            "eligible": False,
        },
        "provekit": {
            "complete_whole_view_witness_zk": False,
            "witness_hiding_enabled": False,
            "transcript_and_mmcs_hash_bits": 256,
            "strict_pq128_qrom": False,
            "proof_bytes": None,
            "eligible": False,
        },
        "historical_aurora": {
            "reported_range_kib": [40, 130],
            "same_relation_measurement": False,
            "strict_qrom_profile": False,
            "canonical_wire": False,
            "proof_bytes": None,
            "use_in_tournament_ranking": False,
        },
    }


def build_certificate() -> dict[str, Any]:
    theoretical_floor = theorem_minimal_projection_floor()
    implementation_floors = {
        f"gf2_{bits}": source_projection_floor(bits)
        for bits in (64, 128, 192, 256)
    }
    return {
        "artifact": "Aurora all-W64 strict PQ/QROM architecture screen",
        "artifact_schema": SCHEMA,
        "status": "valid_negative_conditional_screen_fail_closed",
        "verdict": {
            "eligible": False,
            "tournament_leader": False,
            "architecture_winner": None,
            "production_authorized": False,
            "proof_bytes": None,
            "reason": (
                "exact binary relation, whole-Aurora RBR, concrete hash QROM, "
                "canonical wire, and composed strict security are absent; the "
                "current source-projection privacy floor also rules out 512-bit BCS digests"
            ),
        },
        "relation": relation_screen(),
        "aurora_theorem_9_2": theorem_9_2(),
        "zero_knowledge": zero_knowledge_screen(),
        "round_by_round_soundness": rbr_screen(),
        "source_projection_bcs_privacy_floor": {
            "theorem_minimal_binary_field": theoretical_floor,
            "pinned_libiop_supported_fields": implementation_floors,
            "sha512_is_sufficient": False,
            "exact_relation_authority": False,
            "proof_byte_authority": False,
        },
        "implementation": implementation_screen(),
        "physical_hash_calls": physical_hash_ledger(),
        "composition": composition_screen(),
        "proof_artifact": {
            "same_relation_proof_bytes": None,
            "proof_bytes_lower_bound": None,
            "proof_bytes_upper_bound": None,
            "canonical_serialized_proof": None,
            "retained_qualifying_proof": None,
            "parser": None,
            "historical_measurement_promoted": False,
        },
        "comparators": comparator_screen(),
        "authority": {gate: False for gate in AUTHORITY_GATES},
        "source_binding": {
            "local_primary_pdfs": list(LOCAL_PRIMARY_SOURCES),
            "remote_primary_sources": list(REMOTE_PRIMARY_SOURCES),
            "libiop_local_source_sha512": dict(LOCAL_LIBIOP_SOURCES),
            "repo_source_sha512": dict(LOCAL_REPO_SOURCES),
        },
        "claim_boundary": (
            "This certificate is a negative/conditional architecture receipt. "
            "It is not a proof, proof-size measurement, security certificate, "
            "relation refinement, implementation audit approval, or production authority."
        ),
    }


def validate_certificate(document: Mapping[str, Any]) -> None:
    expected = build_certificate()
    if document != expected:
        raise AssertionError("certificate differs from deterministic builder")
    if document["artifact_schema"] != SCHEMA:
        raise AssertionError("schema drift")
    if any(document["authority"].values()):
        raise AssertionError("authority gate promoted")
    if set(document["authority"]) != set(AUTHORITY_GATES):
        raise AssertionError("authority gate set drift")
    verdict = document["verdict"]
    if verdict["eligible"] or verdict["tournament_leader"] or verdict["production_authorized"]:
        raise AssertionError("Aurora candidate promoted")
    if verdict["architecture_winner"] is not None or verdict["proof_bytes"] is not None:
        raise AssertionError("winner or proof bytes must remain null")

    relation = document["relation"]
    projection = relation["source_static_projection"]
    if projection["m_constraints"] != SOURCE_STATIC_M:
        raise AssertionError("source-static m drift")
    if projection["n_nonconstant_variables_upper_bound"] != SOURCE_STATIC_N_UPPER:
        raise AssertionError("source-static n upper bound drift")
    if projection["exact_binary_r1cs_geometry"]:
        raise AssertionError("source projection cannot become exact binary geometry")
    compiled = relation["exact_binary_compile"]
    if compiled["compiled"] or compiled["semantic_refinement"]:
        raise AssertionError("binary relation gate promoted")
    for key in (
        "m",
        "n",
        "l",
        "nnz",
        "matrix_digest",
        "deterministic_variable_map_digest",
        "canonical_statement_to_field_map",
        "canonical_witness_to_field_map",
        "public_input_padding",
    ):
        if compiled[key] is not None:
            raise AssertionError(f"uncompiled binary relation field became non-null: {key}")
    unfrozen = relation["unfrozen_binary_source_macro_projection"]
    if (
        unfrozen["m_constraints"],
        unfrozen["n_nonconstant_variables"],
        unfrozen["l_public_bits"],
        unfrozen["sparse_nonzeros_projection"],
    ) != (
        UNFROZEN_BINARY_MACRO_M,
        UNFROZEN_BINARY_MACRO_N,
        UNFROZEN_BINARY_MACRO_L,
        UNFROZEN_BINARY_MACRO_NNZ,
    ):
        raise AssertionError("unfrozen binary macro projection drift")
    if any(
        unfrozen[key]
        for key in (
            "executable_sparse_matrices_retained",
            "typed_symbolic_ir_frozen",
            "verified_ir_to_binary_sparse_lowering",
            "accepted_geometry",
            "used_for_bcs_privacy_floor",
        )
    ):
        raise AssertionError("unfrozen binary macro projection promoted")
    if unfrozen["proof_bytes"] is not None:
        raise AssertionError("unfrozen binary macro projection acquired proof bytes")

    theorem = document["aurora_theorem_9_2"]
    if theorem["full_iop_oracle_length_symbols"] != (
        "(4+2*lambda_i+(lambda_i_prime*lambda_i_FRI)/3)*|L|"
    ):
        raise AssertionError("Theorem 9.2 oracle-length expression drift")
    if theorem["core_expression_is_proof_bytes"]:
        raise AssertionError("IOP oracle expression mislabeled as proof bytes")
    if any(value is not None for value in theorem["selected_parameters"].values()):
        raise AssertionError("unselected theorem parameter became concrete")

    zk = document["zero_knowledge"]
    definition = zk["aurora_definition_4_4"]
    if not all(definition.values()):
        raise AssertionError("Definition 4.4 whole-view ZK evidence drift")
    if zk["complete_nizk_zk_gate"]:
        raise AssertionError("incomplete NIZK ZK gate promoted")
    if zk["modified_bcs"]["statistical_nizk_error"] is not None:
        raise AssertionError("exact BCS ZK error is unavailable")

    rbr = document["round_by_round_soundness"]
    if rbr["whole_aurora_direct_rbr_theorem"]:
        raise AssertionError("whole-Aurora RBR cannot be inferred")
    if rbr["fri_component_rbr_is_whole_aurora_rbr"]:
        raise AssertionError("FRI component RBR cannot become whole-Aurora RBR")
    if rbr["cms_applicable_to_current_profile"]:
        raise AssertionError("CMS applicability promoted")
    fallback = rbr["cms_appendix_b_generic_fallback"]
    if fallback["expression"] != "mu^(1/(k+1))":
        raise AssertionError("generic RBR root expression drift")
    if fallback["instantiated"] or fallback["finite_concrete_error"] is not None:
        raise AssertionError("generic RBR fallback must remain uninstantiated")

    floor = document["source_projection_bcs_privacy_floor"]
    theory = floor["theorem_minimal_binary_field"]
    if theory["l_floor"] != 1 << 27 or theory["field_bits"] != 28:
        raise AssertionError("Theorem 9.2 projection-domain floor drift")
    if theory["p_iop_bits_floor"] != 15_032_385_536:
        raise AssertionError("theoretical p floor drift")
    if theory["minimum_multiple_of_four_lambda_for_floor"] != 656:
        raise AssertionError("theoretical BCS lambda floor drift")
    if theory["lambda512_strict_gt_128"]:
        raise AssertionError("lambda512 cannot pass theoretical p floor")
    implementation_floors = floor["pinned_libiop_supported_fields"]
    expected_lambdas = {"gf2_64": 664, "gf2_128": 668, "gf2_192": 668, "gf2_256": 672}
    for field_id, expected_lambda in expected_lambdas.items():
        item = implementation_floors[field_id]
        if item["minimum_multiple_of_four_lambda_for_floor"] != expected_lambda:
            raise AssertionError(f"{field_id} BCS lambda floor drift")
        if item["lambda512_strict_gt_128"]:
            raise AssertionError(f"{field_id} unexpectedly passes lambda512")
    if floor["sha512_is_sufficient"]:
        raise AssertionError("SHA-512 cannot pass source-projection privacy floor")

    implementation = document["implementation"]
    closure = implementation["static_include_closure"]
    if (closure["files"], closure["lines"], closure["bytes"]) != (
        113,
        18_818,
        783_493,
    ):
        raise AssertionError("pinned libiop include closure drift")
    if closure["missing_local_includes"] or closure["built_or_linked"]:
        raise AssertionError("static source audit cannot become a build result")
    for key in (
        "binary_or_nonalgebraic_serialization_implemented",
        "binary_or_nonalgebraic_deserialization_implemented",
        "canonical_final_transcript_serialization",
        "logical_size_counter_includes_query_positions",
        "logical_size_counter_is_canonical_proof_bytes",
        "sha512_supported",
        "shake_supported",
        "implementable_relation_adapter",
    ):
        if implementation[key]:
            raise AssertionError(f"implementation blocker promoted: {key}")

    composition = document["composition"]
    categories = {item["category"] for item in composition["required_terms"]}
    if not {"pcs", "iop", "fiat-shamir", "hash", "grinding", "union"} <= categories:
        raise AssertionError("composition categories incomplete")
    if any(item["value"] is not None for item in composition["required_terms"]):
        raise AssertionError("missing composition term must remain null")
    if composition["overall_advantage"] is not None or composition["composed_security_bits"] is not None:
        raise AssertionError("incomplete composition cannot have a result")
    if composition["strictly_below_2^-128"] or composition["complete"]:
        raise AssertionError("incomplete composition promoted")

    artifact = document["proof_artifact"]
    for key in (
        "same_relation_proof_bytes",
        "proof_bytes_lower_bound",
        "proof_bytes_upper_bound",
        "canonical_serialized_proof",
        "retained_qualifying_proof",
        "parser",
    ):
        if artifact[key] is not None:
            raise AssertionError(f"proof artifact field must remain null: {key}")
    if artifact["historical_measurement_promoted"]:
        raise AssertionError("historical Aurora measurement promoted")
    for candidate in document["comparators"].values():
        if candidate.get("eligible"):
            raise AssertionError("comparator promoted")


def validate_repo_sources() -> None:
    for relative, expected in LOCAL_REPO_SOURCES.items():
        path = REPO / relative
        if not path.is_file():
            raise AssertionError(f"missing repo source: {relative}")
        actual = sha512_file(path)
        if actual != expected:
            raise AssertionError(f"repo source SHA-512 drift: {relative}")


def validate_primary_sources(*, require_present: bool) -> None:
    for source in LOCAL_PRIMARY_SOURCES:
        path = Path(source["local_path"])
        if not path.exists():
            if require_present:
                raise AssertionError(f"missing primary PDF: {path}")
            continue
        if sha512_file(path) != source["sha512"]:
            raise AssertionError(f"primary PDF SHA-512 drift: {path}")


def validate_libiop_sources(*, require_present: bool) -> None:
    for path_name, expected in LOCAL_LIBIOP_SOURCES.items():
        path = Path(path_name)
        if not path.exists():
            if require_present:
                raise AssertionError(f"missing pinned libiop source: {path}")
            continue
        if sha512_file(path) != expected:
            raise AssertionError(f"pinned libiop SHA-512 drift: {path}")


def check_retained_certificate() -> None:
    raw = CERTIFICATE_PATH.read_text(encoding="utf-8")
    retained = json.loads(raw)
    validate_certificate(retained)
    if raw != canonical_json(retained):
        raise AssertionError("certificate is not canonical JSON with one trailing LF")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--require-local-sources", action="store_true")
    args = parser.parse_args()
    document = build_certificate()
    validate_certificate(document)
    validate_repo_sources()
    validate_primary_sources(require_present=args.require_local_sources)
    validate_libiop_sources(require_present=args.require_local_sources)
    rendered = canonical_json(document)
    if args.write:
        CERTIFICATE_PATH.write_text(rendered, encoding="utf-8")
    if args.check or not args.write:
        check_retained_certificate()
    print("PASS: Aurora PQ128 screen remains canonical and fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
