#!/usr/bin/env python3
"""Fail-closed VEIL/Ligerito complete-ZK compatibility and rank audit.

This checker is deliberately dependency-free.  It does not prove a protocol,
compile Rust, execute a PCS, or authorize production.  It pins the exact local
one-level Ligerito model and the staged primary VEIL paper/source, proves a
small exact extension-rank counterexample for the currently available Hegemon
masks, and records the minimum geometry of a source-faithful VEIL-style repair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
DEFAULT_PAPER = Path("/private/tmp/veil-2026-683.txt")
DEFAULT_SLOP = Path("/private/tmp/slop-veil-6.4.0.kJf1od/slop-veil-6.4.0")

B128_BYTES = 16
E384_BYTES = 48
SHA512_BYTES = 64
E384_DEGREE_OVER_B128 = 3


REPO_PINS = {
    ".agent/hardening/binius-pq128-proof-size/strict_refold_pcs_prototype.py":
        "82b70ad2e791f5cd0dc3d305c0f92a1e015d544a5cc063017c7b2d7d510b19da",
    ".agent/hardening/binius-pq128-proof-size/strict_refold_pcs_model.py":
        "3cde106361941c6533d19752f7755c366539620d2a7ef0890b6dde5ab2836f55",
    "prototypes/standalone-shake256-binius/char2-hvzk-sumcheck-kernel/char2_hvzk_sumcheck_audit.py":
        "d333eed11a5b025c315d0de684e49841dc03936a74db7adaee5e63fecaf8f08e",
    "prototypes/standalone-shake256-binius/m4-random-tail-integration-patch/hegemon-m4-random-tail-after-zk-stack-3f961630.patch":
        "0602c48f3cc7545186e625d033c3cefe4563431499977531e365144d12232c18",
    "prototypes/standalone-shake256-binius/m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch":
        "684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54",
    "prototypes/standalone-shake256-binius/compact-multiproof-patch/codex-terminal-compact-multiproof-v1.patch":
        "3887fdf4bf52e0fe551dc95dc0a252f15c2d48154e64cfef4fbaa70556229da3",
}

PAPER_SHA256 = "c08a7e40861a082cf7362d07e067e8fd790eb07701a39781e3ba3ab6bd46b790"
SLOP_CRATE_ARCHIVE_SHA512 = (
    "a550dad8843bd826d2e05151c8707b09f979c979593c71a2e2b900d925726236e"
    "f6566a7769fd6eb4ad20f93b4ca9037e267fff4dfaa0e5fd312e31fe80976ba"
)
SLOP_VCS_SHA = "f66b4bff51d0ccff51d152e0f7f66b2ffedf3529"
SLOP_PINS = {
    "Cargo.toml": "9e2fee7e0432c5437b863fcc66382cf7befb7ec6a0cf81226b192e8d80c60dc3",
    "README.md": "4e40ce525b683fb636a18589509a6d54f3aa8d8d47b488bedb791daa1c3073c8",
    ".cargo_vcs_info.json":
        "3c22b32c71efa652d7f9729e244a7ce4daac2957cb8e0928ce7bc7ad44ce6e4c",
    "src/compiler/ctx.rs":
        "e7fed13822b28b62943ce3aff9c289821d1737200536aabbfb01bd56eba4f88b",
    "src/zk/verifier_ctx.rs":
        "96eacaf4d3368b1918b1665808089af83919b45623818b6a47cad2f6f4b011b4",
    "src/zk/inner/pcs_traits.rs":
        "2a022ac56dc958414baf1c63c3a71b3bb710b783ad29112a5a57695264823d3e",
    "src/zk/inner/prover.rs":
        "6928d359467d5eeb79b5219e43492bb73078f633ac714ba9b4ee55034ca9f94e",
    "src/zk/stacked_pcs/mod.rs":
        "4723733d119b008f0f67618c0196b63ce2e544adf6030df45a260e4000ec53e8",
    "src/zk/stacked_pcs/prover.rs":
        "ae0c325fc1e6ed5289db0b690eba57364d8cf56e272438060326dd471885a59e",
    "src/zk/stacked_pcs/verifier.rs":
        "37d931449ed33aa0fbb1d0ff7346a7d89ac36d9f7ddc7be8a68977411788d449",
    "src/zk/stacked_pcs/basefold_verifier_wrapper.rs":
        "9480df87b62ede5c2d8d04b4f2a967e4b8f22a3e07f95bf55dff30f96b3a958b",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_hashes(root: Path, pins: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for relative, expected in pins.items():
        path = root / relative
        if not path.is_file():
            failures.append(f"missing:{path}")
        elif sha256(path) != expected:
            failures.append(f"hash:{path}")
    return failures


def require_snippets(path: Path, snippets: Iterable[str]) -> list[str]:
    if not path.is_file():
        return [f"missing:{path}"]
    text = path.read_text(encoding="utf-8")
    return [f"snippet:{path}:{snippet}" for snippet in snippets if snippet not in text]


def forbid_snippets(path: Path, snippets: Iterable[str]) -> list[str]:
    if not path.is_file():
        return [f"missing:{path}"]
    text = path.read_text(encoding="utf-8")
    return [f"forbidden-snippet:{path}:{snippet}" for snippet in snippets if snippet in text]


@dataclass(frozen=True)
class BinaryField:
    bits: int
    reduction: int

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def add(self, left: int, right: int) -> int:
        return (left ^ right) & self.mask

    def mul(self, left: int, right: int) -> int:
        result = 0
        left &= self.mask
        right &= self.mask
        for _ in range(self.bits):
            if right & 1:
                result ^= left
            carry = left >> (self.bits - 1)
            left = (left << 1) & self.mask
            if carry:
                left ^= self.reduction
            right >>= 1
        return result

    def pow(self, value: int, exponent: int) -> int:
        result = 1
        while exponent:
            if exponent & 1:
                result = self.mul(result, value)
            value = self.mul(value, value)
            exponent >>= 1
        return result

    def inv(self, value: int) -> int:
        if value == 0:
            raise ZeroDivisionError("zero has no inverse")
        return self.pow(value, (1 << self.bits) - 2)


GF8 = BinaryField(bits=3, reduction=0b011)   # Y^3 + Y + 1.
GF16 = BinaryField(bits=4, reduction=0b0011)  # X^4 + X + 1.


def rank_binary_columns(columns: Sequence[int], rows: int) -> int:
    basis = [0] * rows
    rank = 0
    for column in columns:
        value = column
        while value:
            pivot = value.bit_length() - 1
            if pivot >= rows:
                raise ValueError("column exceeds declared row count")
            if basis[pivot]:
                value ^= basis[pivot]
            else:
                basis[pivot] = value
                rank += 1
                break
    return rank


def rank_field_matrix(rows: Sequence[Sequence[int]], field: BinaryField) -> int:
    matrix = [list(row) for row in rows]
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("ragged matrix")
    rank = 0
    for column in range(width):
        pivot = next((r for r in range(rank, len(matrix)) if matrix[r][column]), None)
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        inverse = field.inv(matrix[rank][column])
        matrix[rank] = [field.mul(value, inverse) for value in matrix[rank]]
        for row in range(len(matrix)):
            if row == rank or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [
                field.add(value, field.mul(factor, pivot_value))
                for value, pivot_value in zip(matrix[row], matrix[rank], strict=True)
            ]
        rank += 1
        if rank == len(matrix):
            break
    return rank


def ligerito_prefix_rank_counterexample() -> dict[str, object]:
    """Exact E384/B128-linear counterexample at one fully active residual column.

    Work in the B128 basis (1,Y,Y^2) of E384 and choose both lane-fold
    challenges to be Y.  Four lane weights are then

        (1+Y^2, Y+Y^2, Y+Y^2, Y^2).

    The toy public relation lane0=lane1 leaves three witness directions whose
    terminal images have rank three.  A global B128 constant trace shift has
    image Span{1}, while a suffix random tail has no support at this column.
    """

    one = 0b001
    y = 0b010
    r0 = y
    r1 = y
    weights = [
        GF8.mul(one ^ r0, one ^ r1),
        GF8.mul(r0, one ^ r1),
        GF8.mul(one ^ r0, r1),
        GF8.mul(r0, r1),
    ]
    witness_columns = [weights[0] ^ weights[1], weights[2], weights[3]]
    constant_shift_column = weights[0] ^ weights[1] ^ weights[2] ^ weights[3]
    current_mask_columns = [constant_shift_column]
    veil_mask_columns = [0b001, 0b010, 0b100]
    distinguisher = 0b010

    def dot(left: int, right: int) -> int:
        return (left & right).bit_count() & 1

    current_rank = rank_binary_columns(current_mask_columns, 3)
    joined_rank = rank_binary_columns(current_mask_columns + witness_columns, 3)
    veil_rank = rank_binary_columns(veil_mask_columns, 3)
    veil_joined_rank = rank_binary_columns(veil_mask_columns + witness_columns, 3)
    if weights != [0b101, 0b110, 0b110, 0b100]:
        raise AssertionError("E384 symbolic fold weights drifted")
    if current_rank != 1 or joined_rank != 3:
        raise AssertionError("current prefix leak rank unexpectedly closed")
    if dot(distinguisher, constant_shift_column) != 0:
        raise AssertionError("distinguisher does not annihilate the current mask")
    if dot(distinguisher, witness_columns[0]) != 1:
        raise AssertionError("distinguisher does not separate the selected witnesses")
    if veil_rank != 3 or veil_joined_rank != 3:
        raise AssertionError("three extension-coordinate masks did not close local rank")

    return {
        "field": "E384=B128[Y]/(Y^3+Y+1)",
        "fold_challenges": ["Y", "Y"],
        "lane_weights_b128_basis_bits": weights,
        "same_relation_witness_direction_images": witness_columns,
        "witness_observation_rank_over_b128": rank_binary_columns(witness_columns, 3),
        "random_tail_rank_at_fully_active_prefix_column": 0,
        "constant_trace_shift_image": constant_shift_column,
        "current_mask_rank": current_rank,
        "current_joined_rank": joined_rank,
        "rank_gate_passes_current": current_rank == joined_rank,
        "left_null_distinguisher": distinguisher,
        "conditional_total_variation": "1",
        "veil_three_coordinate_mask_rank": veil_rank,
        "veil_joined_rank": veil_joined_rank,
        "rank_gate_passes_local_veil_nonzero_coefficient": veil_rank == veil_joined_rank,
        "veil_zero_mask_coefficient_rank": 0,
        "rank_gate_passes_veil_zero_coefficient": False,
    }


def query_padding_rank_example() -> dict[str, object]:
    """Vandermonde rank for q random high coefficients and q distinct queries."""

    queries = [1, 2, 4]
    message_columns = 4
    padding_count = len(queries)
    columns = [
        [GF16.pow(point, message_columns + offset) for point in queries]
        for offset in range(padding_count)
    ]
    # rank_field_matrix expects rows, so transpose the observation columns.
    matrix = [list(row) for row in zip(*columns, strict=True)]
    full_rank = rank_field_matrix(matrix, GF16)
    short_rank = rank_field_matrix([row[:-1] for row in matrix], GF16)
    if full_rank != padding_count or short_rank != padding_count - 1:
        raise AssertionError("query-padding Vandermonde rank drifted")
    return {
        "field": "GF(2^4) executable analogue",
        "distinct_queries": queries,
        "message_columns": message_columns,
        "query_count": padding_count,
        "padding_coefficients": padding_count,
        "observation_rank": full_rank,
        "rank_gate_passes": full_rank == padding_count,
        "q_minus_one_padding_rank": short_rank,
        "q_minus_one_rank_gate_passes": short_rank == padding_count,
        "production_requirement": (
            "prove the same full-rank projection for every admitted set of distinct "
            "Ligerito queries over the actual B128 code domain"
        ),
    }


def source_geometry(log_relation_size: int, fold_variables: int, query_count: int) -> dict[str, int]:
    if not 0 < fold_variables <= log_relation_size:
        raise ValueError("invalid fold geometry")
    if query_count <= 0:
        raise ValueError("query count must be positive")
    data_columns = 1 << fold_variables
    message_rows = 1 << (log_relation_size - fold_variables)
    mask_columns = E384_DEGREE_OVER_B128
    mask_query_bytes = query_count * mask_columns * B128_BYTES
    padding_vector_bytes = query_count * E384_BYTES
    mask_evaluation_bytes = mask_columns * E384_BYTES
    rlc_claim_bytes = E384_BYTES
    return {
        "log_relation_size": log_relation_size,
        "fold_variables": fold_variables,
        "data_columns": data_columns,
        "message_rows_before_padding": message_rows,
        "query_count": query_count,
        "random_padding_b128_elements": query_count * data_columns,
        "random_mask_columns": mask_columns,
        "random_mask_b128_elements": (message_rows + query_count) * mask_columns,
        "opened_mask_column_bytes": mask_query_bytes,
        "rlc_padding_vector_bytes": padding_vector_bytes,
        "mask_column_evaluation_bytes": mask_evaluation_bytes,
        "rlc_evaluation_claim_bytes": rlc_claim_bytes,
        "source_structure_direct_payload_floor_bytes": (
            mask_query_bytes
            + padding_vector_bytes
            + mask_evaluation_bytes
            + rlc_claim_bytes
        ),
    }


def paper_symbolic_overhead_bytes(
    *,
    base_query_count: int,
    stacking_log: int,
    pcs_path_log: int,
    inner_security_padding: int,
    linear_code_path_log: int,
    multiplicative_code_path_log: int,
    r1cs_height: int,
    direct_message_count: int,
    zk_padding: int,
) -> dict[str, int]:
    """VEIL paper Sec. 5.2.3 overhead with Hegemon wire widths.

    This is an exact evaluation of the paper's symbolic formula, not evidence
    that the supplied parameters describe Hegemon or that SHA-512 instantiates
    its Merkle/Fiat--Shamir assumptions.
    """

    values = (
        base_query_count,
        stacking_log,
        pcs_path_log,
        inner_security_padding,
        linear_code_path_log,
        multiplicative_code_path_log,
        r1cs_height,
        direct_message_count,
        zk_padding,
    )
    if any(value < 0 for value in values):
        raise ValueError("symbolic overhead inputs must be nonnegative")
    digest_count = (
        base_query_count * pcs_path_log
        + inner_security_padding * (linear_code_path_log + multiplicative_code_path_log)
        + 3
    )
    field_count = (
        (base_query_count + 1) * ((1 << stacking_log) + 1)
        + 3 * r1cs_height
        + direct_message_count
        + 11 * inner_security_padding
        + zk_padding
        + stacking_log
        + 25
    )
    return {
        "digest_count": digest_count,
        "field_element_count": field_count,
        "sha512_digest_bytes": digest_count * SHA512_BYTES,
        "e384_field_bytes": field_count * E384_BYTES,
        "total_bytes": digest_count * SHA512_BYTES + field_count * E384_BYTES,
    }


def build_certificate() -> dict[str, object]:
    rank = ligerito_prefix_rank_counterexample()
    padding = query_padding_rank_example()
    profiles = {
        "n16_q38_64gib_model": source_geometry(16, 6, 38),
        "n16_q61_512mib_model": source_geometry(16, 6, 61),
    }
    profiles["n16_q38_64gib_model"].update(
        {
            "existing_non_zk_model_bytes": 144_496,
            "baseline_plus_direct_floor_only_bytes": 148_336,
        }
    )
    profiles["n16_q61_512mib_model"].update(
        {
            "existing_non_zk_model_bytes": 168_688,
            "baseline_plus_direct_floor_only_bytes": 174_736,
        }
    )
    return {
        "schema": "hegemon.ligerito-e384-veil-complete-zk-audit.v1",
        "decision": {
            "status": "REJECT_CURRENT_TRANSCRIPT_SOURCE_FAITHFUL_PORT_REQUIRED",
            "frontier_eligible": False,
            "reason_codes": [
                "CURRENT_FULL_RESIDUAL_MASK_RANK_FAIL",
                "EXACT_LIGERITO_TRANSCRIPT_NOT_A_VEIL_MIOP",
                "SLOP_BACKEND_BASEFOLD_SPECIFIC",
                "SLOP_TWO_ADIC_FIELD_BOUND_EXCLUDES_BINARY_STACK",
                "NON_ORACLE_HASH_CHECKS_NOT_ARITHMETIZED",
                "FULL_M4_CONSTRAINT_GEOMETRY_UNKNOWN",
                "WHOLE_VIEW_SIMULATOR_NOT_IMPLEMENTED",
                "FIAT_SHAMIR_QROM_COMPOSITION_ABSENT",
                "SOURCE_PROVENANCE_DIRTY",
            ],
        },
        "claims": {
            "current_mask_rank_closed": False,
            "exact_hegemon_ligerito_is_supported_miop": False,
            "source_faithful_veil_ligerito_backend_implemented": False,
            "binary_field_backend_implemented": False,
            "whole_view_simulator_implemented": False,
            "abort_selective_failure_composed": False,
            "qrom_fiat_shamir_composed": False,
            "strict_pq128": False,
            "complete_zk": False,
            "production_authorized": False,
        },
        "current_ligerito_view": {
            "witness_dependent_clear_fields": [
                "wide target and reduction values",
                "two E384 coefficients per lane-fold sumcheck round",
                "full E384 folded residual vector",
                "q by 2^fold_variables raw B128 Reed-Solomon column openings",
                "Merkle root/frontier and Fiat-Shamir schedule as computational views",
            ],
            "terminal_is_serialized_in_full": True,
            "raw_rows_are_serialized_unchanged": True,
            "compact_multiproof_adds_hiding_entropy": False,
        },
        "existing_patch_compatibility": {
            "char2_hvzk_sumcheck": (
                "locally hides round polynomials only; it supplies no mask generator for "
                "the full residual vector and is unsound/privacy-breaking if terminal delta leaks"
            ),
            "m4_random_tail": (
                "suffix B128 entropy; zero rank on every fully active prefix residual column"
            ),
            "m4_coefficient_mask": (
                "one global B128 constant-shift dimension; insufficient for one E384 terminal coordinate"
            ),
            "m4_grouped_relation": (
                "removes one correlated clear BaseFold scalar but does not hide Ligerito residual/openings"
            ),
            "compact_multiproof": (
                "authentication-only compression; leaf values and canonical terminal message remain clear"
            ),
            "outer_libra": (
                "can inform the non-oracle algebraic wrapper but is not wired to the exact Ligerito view"
            ),
        },
        "rank_counterexample": rank,
        "query_padding_rank": padding,
        "veil_required_geometry": {
            "base_field": "B128",
            "challenge_field": "E384",
            "extension_degree": E384_DEGREE_OVER_B128,
            "random_padding": "q independent B128 coordinates per stacked data column",
            "random_column": "three full B128 columns forming one uniform E384 column",
            "proximity_generator": "last/random-column coefficient must be nonzero",
            "same_codeword_length_allowed_only_after_distance_and_query_recomputation": True,
            "profiles": profiles,
            "profile_totals_are_complete_zk_estimates": False,
            "full_wire_formula": (
                "64*(q*m + lambda*(ceil_log2(m_plus)+ceil_log2(m_times)) + 3) + "
                "48*((q+1)*(2^p+1) + 3*m_prime + s + 11*lambda + k_pad + p + 25)"
            ),
            "full_wire_formula_authority": "paper-symbolic-only",
        },
        "veil_premises": {
            "base_protocol_is_sound_fixed_format_public_coin_miop": False,
            "all_oracles_are_multilinear_over_one_declared_field": False,
            "at_most_one_evaluation_query_per_commitment_or_sound_conversion": False,
            "all_non_oracle_acceptance_checks_are_polynomial_constraints": False,
            "zk_code_projection_rank_for_actual_distinct_queries": False,
            "zk_proximity_generator_with_nonzero_random_column_coefficient": False,
            "ligerito_simple_mcs_binding_and_iopp_strength": False,
            "zk_multilinear_pcs_partial_simulator": False,
            "non_oracle_constraint_wrapper_simulator": False,
            "hash_merkle_domain_and_parser_refinement": False,
            "fiat_shamir_qrom_transform": False,
        },
        "published_source": {
            "crate": "slop-veil 6.4.0",
            "crate_archive_sha512": SLOP_CRATE_ARCHIVE_SHA512,
            "vcs_sha": SLOP_VCS_SHA,
            "vcs_dirty": True,
            "warning_experimental_unaudited": True,
            "only_shipped_zk_iop_context": "KoalaBearDegree4Duplex",
            "proof_backend": "BaseFold-specific ZkStackedPcsProof",
            "field_bound": "F and EF implement TwoAdicField",
            "binary_b128_e384_type_compatible": False,
            "sha512_backend_present": False,
            "simulator_api_present": False,
            "qrom_theorem_present": False,
            "unrestricted_mask_batch_coefficient_bad_event": "alpha=0",
        },
        "source_pins": {
            "repo_sha256": REPO_PINS,
            "paper_text_sha256": PAPER_SHA256,
            "slop_sha256": SLOP_PINS,
        },
    }


FORBIDDEN_TRUE_CLAIMS = {
    "current_mask_rank_closed",
    "exact_hegemon_ligerito_is_supported_miop",
    "source_faithful_veil_ligerito_backend_implemented",
    "binary_field_backend_implemented",
    "whole_view_simulator_implemented",
    "abort_selective_failure_composed",
    "qrom_fiat_shamir_composed",
    "strict_pq128",
    "complete_zk",
    "production_authorized",
}


def validate_certificate(certificate: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if certificate.get("schema") != "hegemon.ligerito-e384-veil-complete-zk-audit.v1":
        failures.append("schema")
    decision = certificate.get("decision")
    if not isinstance(decision, dict):
        failures.append("decision")
    else:
        if decision.get("status") != "REJECT_CURRENT_TRANSCRIPT_SOURCE_FAITHFUL_PORT_REQUIRED":
            failures.append("decision.status")
        if decision.get("frontier_eligible") is not False:
            failures.append("decision.frontier_eligible")
    claims = certificate.get("claims")
    if not isinstance(claims, dict):
        failures.append("claims")
    else:
        for claim in sorted(FORBIDDEN_TRUE_CLAIMS):
            if claims.get(claim) is not False:
                failures.append(f"claims.{claim}")
    rank = certificate.get("rank_counterexample")
    if not isinstance(rank, dict):
        failures.append("rank_counterexample")
    else:
        expected = {
            "witness_observation_rank_over_b128": 3,
            "current_mask_rank": 1,
            "current_joined_rank": 3,
            "rank_gate_passes_current": False,
            "conditional_total_variation": "1",
            "veil_three_coordinate_mask_rank": 3,
            "veil_joined_rank": 3,
            "rank_gate_passes_local_veil_nonzero_coefficient": True,
            "rank_gate_passes_veil_zero_coefficient": False,
        }
        for key, value in expected.items():
            if rank.get(key) != value:
                failures.append(f"rank_counterexample.{key}")
    geometry = certificate.get("veil_required_geometry")
    if not isinstance(geometry, dict) or geometry.get("full_wire_formula_authority") != (
        "paper-symbolic-only"
    ):
        failures.append("veil_required_geometry")
    elif geometry.get("profile_totals_are_complete_zk_estimates") is not False:
        failures.append("veil_required_geometry.profile_totals_are_complete_zk_estimates")
    else:
        profiles = geometry.get("profiles")
        expected_floors = {
            "n16_q38_64gib_model": (3_840, 148_336),
            "n16_q61_512mib_model": (6_048, 174_736),
        }
        if not isinstance(profiles, dict):
            failures.append("veil_required_geometry.profiles")
        else:
            for name, (floor, floor_total) in expected_floors.items():
                profile = profiles.get(name)
                if not isinstance(profile, dict):
                    failures.append(f"veil_required_geometry.profiles.{name}")
                    continue
                if profile.get("source_structure_direct_payload_floor_bytes") != floor:
                    failures.append(f"veil_required_geometry.profiles.{name}.direct_floor")
                if profile.get("baseline_plus_direct_floor_only_bytes") != floor_total:
                    failures.append(f"veil_required_geometry.profiles.{name}.floor_total")
    premises = certificate.get("veil_premises")
    if not isinstance(premises, dict):
        failures.append("veil_premises")
    else:
        for premise, value in sorted(premises.items()):
            if value is not False:
                failures.append(f"veil_premises.{premise}")
    return failures


def source_checks(paper: Path, slop_root: Path) -> list[str]:
    failures = check_hashes(REPO, REPO_PINS)
    if not paper.is_file():
        failures.append(f"missing:{paper}")
    elif sha256(paper) != PAPER_SHA256:
        failures.append(f"hash:{paper}")
    failures.extend(check_hashes(slop_root, SLOP_PINS))

    strict = REPO / ".agent/hardening/binius-pq128-proof-size/strict_refold_pcs_prototype.py"
    failures.extend(
        require_snippets(
            strict,
            [
                "terminal = tuple(values)",
                "opened_rows = tuple(columns[index] for index in queries)",
                "for value in self.terminal:",
                "for row in self.opened_rows:",
                "expected = _rs_evaluate_e384(proof.terminal, _domain_point(query))",
                "_supplemental_wide(proof.root, target, index)",
            ],
        )
    )
    random_tail_report = (
        REPO
        / "prototypes/standalone-shake256-binius/m4-random-tail-integration-patch/"
        "hegemon-m4-random-tail-integration-report.md"
    )
    failures.extend(
        require_snippets(
            random_tail_report,
            [
                "The complete clear-observation matrix cannot be exported through current APIs",
                "every codeword/coset symbol and terminal symbol sent for the actual adaptive FRI indices",
            ],
        )
    )
    failures.extend(
        require_snippets(
            paper,
            [
                "Definition 2.13. A Multilinear Interactive Oracle Proof",
                "pads each fℓ with a uniformly random",
                "generates a uniformly random",
                "at most one evaluation query",
                "all oracle queries only happen within the zk-Multilinear-PCS",
                "honest-verifier zero-knowledge",
            ],
        )
    )
    failures.extend(forbid_snippets(paper, ["QROM", "quantum random oracle"]))
    failures.extend(
        require_snippets(
            slop_root / "README.md",
            [
                "experimental, proof-of-concept code",
                "has not been audited",
                "should not be used in production",
            ],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / ".cargo_vcs_info.json",
            [SLOP_VCS_SHA, '"dirty": true', '"path_in_vcs": "slop/crates/veil"'],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "Cargo.toml",
            ["[dependencies.slop-basefold]", "[dependencies.slop-basefold-prover]"],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/inner/pcs_traits.rs",
            [
                "pub trait ZkPcsProver<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>",
                "pub trait ZkPcsVerifier<GC: ZkIopCtx>",
            ],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/verifier_ctx.rs",
            ["pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField>"],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/stacked_pcs/mod.rs",
            ["impl ZkIopCtx for KoalaBearDegree4Duplex"],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/stacked_pcs/prover.rs",
            [
                "pub rlc_eval_proof: BasefoldProof<GC>",
                "let num_mask_cols = GC::EF::D;",
                "let query_count = self.inner.encoder.config().num_queries;",
                "take(query_count * num_data_cols)",
                "take(num_rows * num_mask_cols)",
                "pub rlc_padding_vec: Vec<GC::EF>",
                "alpha_powers[num_claims] * mask_sum_0",
            ],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/stacked_pcs/verifier.rs",
            [
                "GC::EF::two_adic_generator(log_tensor_height)",
                "alpha_powers[num_claims]",
            ],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/stacked_pcs/basefold_verifier_wrapper.rs",
            ["GC::F::TWO_ADICITY", "BaseFoldVerifierError::TwoAdicityOverflow"],
        )
    )
    failures.extend(
        require_snippets(
            slop_root / "src/zk/inner/prover.rs",
            [
                "DuplicateEvalClaim",
                "the simulator's bijection requires `rlc_coeff ≠ 0` and `rlc_coeff ≠ -1`",
                "only statistically zero-knowledge against an",
            ],
        )
    )
    impl_count = sum(
        path.read_text(encoding="utf-8").count("impl ZkIopCtx for")
        for path in (slop_root / "src").rglob("*.rs")
    )
    if impl_count != 1:
        failures.append(f"zk-iop-context-impl-count:{impl_count}")
    qrom_hits = []
    for path in (slop_root / "src").rglob("*.rs"):
        lowered = path.read_text(encoding="utf-8").lower()
        if "qrom" in lowered or "quantum random oracle" in lowered:
            qrom_hits.append(str(path))
    if qrom_hits:
        failures.extend(f"unexpected-qrom-claim:{path}" for path in qrom_hits)
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", type=Path, default=DEFAULT_PAPER)
    parser.add_argument("--slop-root", type=Path, default=DEFAULT_SLOP)
    parser.add_argument("--check-certificate", type=Path)
    parser.add_argument("--write-certificate", type=Path)
    parser.add_argument("--skip-source-pins", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    certificate = build_certificate()
    failures = validate_certificate(certificate)
    if not args.skip_source_pins:
        failures.extend(source_checks(args.paper, args.slop_root))
    if args.check_certificate:
        loaded = json.loads(args.check_certificate.read_text(encoding="utf-8"))
        failures.extend(f"loaded:{failure}" for failure in validate_certificate(loaded))
        if loaded != certificate:
            failures.append("loaded:certificate_drift")
    if args.write_certificate:
        args.write_certificate.write_text(
            json.dumps(certificate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    summary = {
        "status": certificate["decision"]["status"],
        "complete_zk": certificate["claims"]["complete_zk"],
        "strict_pq128": certificate["claims"]["strict_pq128"],
        "production_authorized": certificate["claims"]["production_authorized"],
        "current_mask_rank": certificate["rank_counterexample"]["current_mask_rank"],
        "current_joined_rank": certificate["rank_counterexample"]["current_joined_rank"],
        "local_veil_rank_closure": certificate["rank_counterexample"][
            "rank_gate_passes_local_veil_nonzero_coefficient"
        ],
        "source_checks_passed": not failures,
        "failures": failures,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
