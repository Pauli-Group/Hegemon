#!/usr/bin/env python3
"""Fail-closed checker for the Aurora binary-relation negative closeout.

No executable characteristic-two sparse R1CS was produced. This checker
retains the last reproducible source-macro projection for audit provenance,
but rejects every attempt to treat those counts as an expanded matrix,
Aurora instance, proof measurement, security certificate, or production
authority. It uses only the Python standard library and never invokes a
compiler, prover, Cargo, rustc, or Lake.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST_PATH = HERE / "relation_manifest.json"
CERTIFICATE_PATH = HERE / "certificate.json"
MUTATION_PATH = HERE / "mutation_corpus.json"
KERNEL_V2_PATH = ROOT / "protocol/kernel/src/stablecoin_manifest_authority_v2.rs"

SCHEMA = "hegemon.hx512b01.binary-r1cs.negative-closeout.v1"
VERDICT = "NO_EXECUTABLE_CHARACTERISTIC_TWO_SPARSE_R1CS"
KERNEL_V2_SHA512 = (
    "99268907680ebff599f992e64f15cc9730f451eebd08b6e92776e66ee9afe567d"
    "6bf19eb1c1ff2482a3ea4a737a43e941cd04b7cb18f8e533239abdd474d395f"
)


class Reject(ValueError):
    """A retained closeout artifact drifted or fabricated authority."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha512_bytes(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def sha512_file(path: Path) -> str:
    return sha512_bytes(path.read_bytes())


def expected_manifest() -> dict[str, Any]:
    """Return the exact negative relation-mapping report.

    The numeric tuple is deliberately nested under
    ``last_reproducible_pre_correction_projection``. It is not final relation
    geometry: the live semantic source added 1,024 policy-master rows after
    the count-only macro/artifact used by the projection, and no corrected
    binary lowering or sparse coordinates were retained.
    """

    return {
        "artifact": "Aurora binary relation mapping negative closeout",
        "artifact_schema": SCHEMA,
        "verdict": VERDICT,
        "status": (
            "fail-closed source-macro projection only; no executable binary "
            "sparse relation, backend, proof, security, refinement, or production authority"
        ),
        "authority": {
            "aurora_backend_implemented": False,
            "aurora_theorem_applies_to_a_retained_matrix": False,
            "binary_field_profile_selected": False,
            "complete_zero_knowledge_proved_for_noninteractive_proof": False,
            "composed_qrom_pq128_proved": False,
            "consensus_parent_state_authentication_refined": False,
            "exact_final_geometry_certified": False,
            "exact_native_verifier_refinement_proved": False,
            "executable_characteristic_two_sparse_r1cs": False,
            "expanded_sparse_matrix_retained": False,
            "fiat_shamir_instantiated": False,
            "full_binary_relation_compiled": False,
            "production_authorized": False,
            "proof_artifact_retained": False,
            "proof_bytes_measured": False,
            "release_manifest_authorized": False,
            "round_by_round_knowledge_soundness_proved": False,
            "source_macro_to_binary_matrix_refinement_proved": False,
        },
        "frozen_semantic_inputs": {
            "statement_bytes": 1141,
            "verifier_context_bytes": 72,
            "public_bits_l": 9704,
            "private_transport_bytes": 11000,
            "private_transport_bits": 88000,
            "inputs": 2,
            "outputs": 2,
            "activity_masks": 16,
            "authorization_modes": 5,
            "mask_mode_pairs": 80,
            "accepted_mask_mode_pairs": 33,
            "rejected_mask_mode_pairs": 47,
            "relation_physical_hash_calls": 90,
            "relation_blake2b512_compressions": 213,
            "coverage_in_executable_binary_matrix": False,
        },
        "last_reproducible_pre_correction_projection": {
            "claim_boundary": (
                "source-macro counts only; not final geometry and not retained A/B/C coordinates"
            ),
            "source_odd_field_m_constraints": 29509133,
            "m_constraints": 37364095,
            "n_nonconstant_variables": 21531353,
            "l_public_variables": 9704,
            "matrix_nonzeros_total": 156526483,
            "characteristic_two_row_delta": 7854962,
            "characteristic_two_variable_delta": 16,
            "characteristic_two_nonzero_delta": 33331943,
            "expanded_coordinates_retained": False,
            "verified_ir_to_matrix_lowering": False,
        },
        "corrected_final_geometry": {
            "m_constraints": None,
            "n_nonconstant_variables": None,
            "l_public_variables": 9704,
            "matrix_nonzeros_total": None,
            "reason": (
                "policy-master repair and executable IR never froze; no corrected binary lowering exists"
            ),
        },
        "policy_master_drift": {
            "retained_pre_correction_rows": 1536,
            "live_semantic_required_rows": 2560,
            "missing_rows": 1024,
            "retained_source_projection_m": 29509133,
            "live_semantic_source_m": 29510157,
            "two_independent_masters_bytes": 128,
            "current_policy_master": {"offset_bytes": 6088, "bytes": 64},
            "next_policy_master": {"offset_bytes": 6152, "bytes": 64},
            "mode_contract": {
                "single_key": "current=zero64 and next=zero64",
                "accumulator_init": "current=zero64; policy/auth use next",
                "approval_step": (
                    "current=next; first opening uses current and second uses next"
                ),
                "value_lock_creation": "next=zero64; active lanes use current",
                "final_threshold_spend": "next=zero64; active lanes use current",
            },
            "entropy_caveat": (
                "relation equality and zero constraints do not prove wallet generation, "
                "uniform sampling, retention, erasure, or lifecycle of active 64-byte masters"
            ),
            "corrected_binary_geometry_recomputed": False,
        },
        "all_w64_v2_mapping": {
            "profile": "fresh-v2-all-w64-merkle-w64",
            "native_type": "StablecoinManifestPublicAuthorityV2",
            "kernel_source": "protocol/kernel/src/stablecoin_manifest_authority_v2.rs",
            "kernel_source_sha512": KERNEL_V2_SHA512,
            "module_export_only": True,
            "live_consensus_route": False,
            "row_bytes": 215,
            "slot_bytes": 216,
            "cap": 16,
            "depth": 4,
            "membership_semantic_bytes": 475,
            "membership_transport_bytes": 480,
            "relation_hash_calls": 7,
            "membership_relation_blake2b512_compressions": 7,
            "snapshot_relation_blake2b512_compressions": 1,
            "total_relation_blake2b512_compressions": 8,
            "policy_version_domain": "all canonical u32 values including zero",
            "legacy_48_byte_migration": "reject padding, truncation, and rehash",
            "context": {
                "grammar": "manifest_root64 || parent_height:u64le",
                "bytes": 72,
                "snapshot_preimage": "parent_height:u64le || manifest_root64",
                "snapshot_substitution_for_context_allowed": False,
                "source_macro_equates_statement_manifest_root_and_height": True,
                "native_parent_authentication_refined": False,
            },
        },
        "hx512_identity": {
            "statement_magic": "HX512B01",
            "statement_grammar": 1,
            "circuit_version_hex": "0x5121",
            "crypto_suite_hex": "0x512b",
            "family_id_hex": "0x5123",
            "action_id_hex": "0x5124",
            "network_id_hex": "0x48583531",
            "backend_id_hex": "0x51",
            "proof_profile_hex": "0x52",
            "domain_set_hex": "0x5127",
            "identity_bound_by_executable_binary_matrix": False,
        },
        "aurora_padding_projection": {
            "basis": "last reproducible pre-correction source-macro projection only",
            "h1_padded_constraints": 67108864,
            "h2_padded_z_including_constant": 33554432,
            "t_max_h1_h2": 67108864,
            "adapter_m_constraints": 67108864,
            "adapter_n_variables_excluding_constant": 33554431,
            "adapter_k_explicit_public_inputs": 16383,
            "public_zero_padding": 6679,
            "original_private_and_derived_index_shift": 6679,
            "zero_constraint_rows": 29744769,
            "zero_matrix_witness_variables": 12016399,
            "source_transport_mapping": (
                "each byte is eight separate least-significant-bit-first Boolean field variables; "
                "no 2^i field packing"
            ),
            "field_extension_degree": None,
            "irreducible_polynomial": None,
            "strict_degree_greater_than_codeword_dimension_witnessed": False,
            "shifted_domain_disjointness_proved": False,
            "padding_is_not_backend_or_proof_authority": True,
        },
        "characteristic_two_repairs_screened": {
            "odd_field_add_carry_coefficients_reusable": False,
            "two_row_boolean_full_adder_required_without_selected_beta": True,
            "parity_only_five_way_one_hot_exact": False,
            "pairwise_zero_plus_parity_one_hot_required": True,
            "repairs_lowered_into_full_sparse_matrix": False,
        },
        "decisive_gaps": [
            "no frozen executable typed relation IR or zero-residual mutation certificate",
            "no canonical materialized characteristic-two A/B/C coordinates",
            "no verified wire allocation for all 90 hash calls and seven V2 authority calls",
            "four former host predicates reject only in reference and macro evidence",
            "policy-master source schedule differs by 1024 rows from the retained count projection",
            "no source-macro-to-binary-matrix refinement",
            "no selected binary extension field or irreducible polynomial",
            "no strict extension-degree witness and no shifted-domain disjointness proof",
            "no native derivation of manifest root and height from authenticated canonical parent state",
        ],
        "aurora_theorem_9_2": {
            "paper": "Aurora: Transparent Succinct Arguments for R1CS",
            "paper_sha512": (
                "ad9351a0f7010d57fb9f3482fa442a213a2f9192f82f319f6bed74cef07733ec"
                "e1f95dad8270523e52c80daa1a7f7a33505fc665afafc32dfbf90e4de5971d41"
            ),
            "geometry_condition": "2*max(m,n+1)+2*b <= rho*|L|",
            "applicability_to_target_relation": None,
            "reason": "no retained executable binary-field R1CS instance",
            "proof_symbols": None,
            "proof_bytes": None,
            "security_bits": None,
        },
        "proof": {
            "artifact": None,
            "bytes": None,
            "measured": False,
            "complete_zero_knowledge": False,
            "composed_qrom_strict_gt_128": False,
        },
    }


def expected_certificate(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = canonical_json(manifest)
    return {
        "artifact_schema": "hegemon.hx512b01.binary-r1cs.negative-certificate.v1",
        "verdict": VERDICT,
        "relation_manifest_file": MANIFEST_PATH.name,
        "relation_manifest_canonical_bytes": len(payload),
        "relation_manifest_canonical_sha512": sha512_bytes(payload),
        "last_reproducible_projection": manifest[
            "last_reproducible_pre_correction_projection"
        ],
        "corrected_final_geometry": manifest["corrected_final_geometry"],
        "proof_bytes": None,
        "security_bits": None,
        "all_authority_false": True,
        "production_authorized": False,
    }


def expected_mutation_corpus() -> dict[str, Any]:
    names = [
        "executable_sparse_r1cs_fabricated",
        "expanded_matrix_fabricated",
        "pre_correction_counts_promoted_to_final",
        "policy_master_1024_row_gap_omitted",
        "policy_master_width_reduced_from_64_bytes",
        "policy_master_entropy_claim_fabricated",
        "context_snapshot_substituted_for_manifest_root",
        "context_height_endianness_changed",
        "policy_version_zero_rejected",
        "legacy_48_byte_authority_reinterpreted",
        "public_zero_padding_omitted",
        "private_index_remap_omitted",
        "binary_field_fabricated",
        "extension_degree_fabricated",
        "domain_disjointness_fabricated",
        "proof_bytes_fabricated",
        "security_bits_fabricated",
        "native_parent_authentication_fabricated",
        "production_authority_fabricated",
    ]
    return {
        "artifact_schema": "hegemon.hx512b01.binary-r1cs.negative-mutations.v1",
        "verdict": VERDICT,
        "cases": [
            {"name": name, "expected": "reject_or_remain_fail_closed"}
            for name in names
        ],
        "retained_mutations": len(names),
    }


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise Reject(f"missing closeout artifact: {path.name}")
    try:
        value = json.loads(path.read_bytes())
    except Exception as error:
        raise Reject(f"invalid closeout JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise Reject(f"closeout artifact is not an object: {path.name}")
    return value


def validate_fail_closed(manifest: dict[str, Any]) -> None:
    if manifest.get("verdict") != VERDICT:
        raise Reject("negative verdict drift")
    authority = manifest.get("authority")
    if not isinstance(authority, dict) or not authority:
        raise Reject("authority ledger missing")
    if any(value is not False for value in authority.values()):
        raise Reject("positive or non-Boolean authority fabricated")
    final = manifest["corrected_final_geometry"]
    if any(
        final[key] is not None
        for key in ("m_constraints", "n_nonconstant_variables", "matrix_nonzeros_total")
    ):
        raise Reject("corrected final geometry fabricated")
    context = manifest["all_w64_v2_mapping"]["context"]
    if context["grammar"] != "manifest_root64 || parent_height:u64le":
        raise Reject("V2 verifier-context grammar drift")
    if context["native_parent_authentication_refined"] is not False:
        raise Reject("native parent authority fabricated")
    policy = manifest["policy_master_drift"]
    if (
        policy["retained_pre_correction_rows"],
        policy["live_semantic_required_rows"],
        policy["missing_rows"],
    ) != (1536, 2560, 1024):
        raise Reject("policy-master correction boundary drift")
    if manifest["proof"]["artifact"] is not None or manifest["proof"]["bytes"] is not None:
        raise Reject("proof artifact or bytes fabricated")


def check() -> None:
    manifest = _read_object(MANIFEST_PATH)
    certificate = _read_object(CERTIFICATE_PATH)
    mutations = _read_object(MUTATION_PATH)
    expected = expected_manifest()
    if manifest != expected:
        raise Reject("relation manifest does not match negative closeout")
    validate_fail_closed(manifest)
    if certificate != expected_certificate(manifest):
        raise Reject("negative certificate drift")
    if mutations != expected_mutation_corpus():
        raise Reject("negative mutation corpus drift")
    if not KERNEL_V2_PATH.is_file() or sha512_file(KERNEL_V2_PATH) != KERNEL_V2_SHA512:
        raise Reject("frozen V2 kernel source drift")


def summary() -> str:
    check()
    projection = expected_manifest()["last_reproducible_pre_correction_projection"]
    return (
        f"PASS verdict={VERDICT} "
        f"provisional_m={projection['m_constraints']} "
        f"provisional_n={projection['n_nonconstant_variables']} "
        f"l={projection['l_public_variables']} "
        f"provisional_nnz={projection['matrix_nonzeros_total']} "
        "final_m=null final_n=null final_nnz=null "
        "proof_bytes=null security_bits=null production=false"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.summary:
            print(summary())
        else:
            check()
    except Reject as error:
        print(f"FAIL: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
