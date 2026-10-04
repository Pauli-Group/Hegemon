#!/usr/bin/env python3
"""Fail-closed audit of the salted Merkle/Fiat--Shamir ZK seam.

This module audits one exact proposal: four B128 symbols and a fresh 32-byte
salt are hashed into each SHAKE256-512 Merkle leaf, and Fiat--Shamir queries are
derived from the resulting root.  It pins and invokes both the random-padding
screen and the executable one-round-FRI seam.

The executable bounds are theorem-shape screens, not a QROM proof.  In
particular, they do not turn the fixed-matrix random-padding rank lemma into an
adaptive simulator.  Every production/security gate therefore fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[4]
RANDOM_PADDING_RELATIVE = Path(
    "prototypes/standalone-shake256-binius/"
    "m4-random-padding-zk-pcs/random_padding_pcs.py"
)
RANDOM_PADDING_SHA256 = (
    "e8311b5b00458f6bd1182637e812e7d879c3fbda9743c5445527e30859975548"
)
RANDOM_PADDING_FRI_RELATIVE = Path(
    "prototypes/standalone-shake256-binius/"
    "m4-random-padding-zk-pcs-fri/random_padding_fri.py"
)
RANDOM_PADDING_FRI_SHA256 = (
    "71800fed15607ff9399c42a522c0741e49bc74da4429e77e2cec0bab3c96e3c4"
)

SALT_BYTES = 32
SALT_BITS = SALT_BYTES * 8
DIGEST_BYTES = 64
DIGEST_BITS = DIGEST_BYTES * 8
LEAF_GROUP_SYMBOLS = 4
B128_BYTES = 16
TARGET_BITS = 128
RATE32_LEAF_COUNT = (1 << 15) * 32 // LEAF_GROUP_SYMBOLS
RATE32_PRECURSOR_OPENED_LEAVES = 66
RATE32_ONE_ROUND_SEPARATE_OPENED_LEAVES = 132


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_record(relative: Path, expected: str) -> dict[str, object]:
    path = REPO_ROOT / relative
    actual = _sha256_file(path)
    return {
        "path": str(relative),
        "expected_sha256": expected,
        "actual_sha256": actual,
        "matches": actual == expected,
    }


def source_record() -> dict[str, object]:
    """Backward-compatible record for the strict random-padding source."""

    return _source_record(RANDOM_PADDING_RELATIVE, RANDOM_PADDING_SHA256)


def source_records() -> dict[str, dict[str, object]]:
    return {
        "random_padding": source_record(),
        "one_round_fri": _source_record(
            RANDOM_PADDING_FRI_RELATIVE, RANDOM_PADDING_FRI_SHA256
        ),
    }


@lru_cache(maxsize=1)
def _random_padding_module():
    record = source_record()
    if not record["matches"]:
        raise RuntimeError("random-padding source hash drift")
    path = REPO_ROOT / RANDOM_PADDING_RELATIVE
    spec = importlib.util.spec_from_file_location(
        "hegemon_salted_bcs_pinned_random_padding", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned random-padding source")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def _random_padding_fri_module():
    record = source_records()["one_round_fri"]
    if not record["matches"]:
        raise RuntimeError("random-padding FRI source hash drift")
    path = REPO_ROOT / RANDOM_PADDING_FRI_RELATIVE
    spec = importlib.util.spec_from_file_location(
        "hegemon_salted_bcs_pinned_random_padding_fri", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned random-padding FRI source")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def actual_leaf_hash(index: int, symbols: Sequence[int], salt: bytes) -> bytes:
    """Invoke the exact pinned leaf framing rather than a local reimplementation."""

    return _random_padding_module().salted_leaf_hash(index, symbols, salt)


def toy_truncated_leaf_hash(
    index: int, symbols: Sequence[int], salt: bytes, digest_bytes: int
) -> bytes:
    if not 1 <= digest_bytes <= DIGEST_BYTES:
        raise ValueError("invalid toy digest length")
    return actual_leaf_hash(index, symbols, salt)[:digest_bytes]


def find_toy_collision() -> dict[str, object]:
    """Find a forced small-output collision while retaining the real framing."""

    seen: dict[bytes, tuple[int, int]] = {}
    for variant, salt_value in itertools.product(range(3), range(256)):
        symbols = (variant, 2, 3, 4)
        salt = bytes([salt_value]) * SALT_BYTES
        digest = toy_truncated_leaf_hash(7, symbols, salt, 1)
        previous = seen.get(digest)
        if previous is not None and previous != (variant, salt_value):
            return {
                "digest_hex": digest.hex(),
                "first_variant": previous[0],
                "first_salt_byte": previous[1],
                "second_variant": variant,
                "second_salt_byte": salt_value,
            }
        seen[digest] = (variant, salt_value)
    raise AssertionError("pigeonhole collision was not found")


def _log2_add(left: float, right: float) -> float:
    high = max(left, right)
    low = min(left, right)
    correction = math.log1p(2.0 ** (low - high)) / math.log(2.0)
    result = high + correction
    # Preserve the strict inequality when the positive correction is below one
    # binary64 ulp.  This matters at the exact 128-bit no-margin boundary.
    if correction > 0.0 and result == high:
        return math.nextafter(high, math.inf)
    return result


def adaptive_reprogramming_security_bits(
    *, salt_bits: int, reprogrammings: int, quantum_queries_log2: float
) -> float:
    """Screen Grilo--Hoevelmanns--Huelsing--Majenz Theorem 1.

    For uniform hidden positions, ``p_max=2^-salt_bits``.  Replacing every
    theorem-specific prefix query count by the total ``q`` gives the explicit
    upper bound

        R * (sqrt(q*p_max) + (q*p_max)/2).

    The returned number is ``-log2(bound)``, capped below at zero.  Applying
    this expression to the Hegemon transcript still requires a proof that its
    programmed positions and classical trigger satisfy that theorem.
    """

    if salt_bits <= 0 or reprogrammings <= 0 or quantum_queries_log2 < 0:
        raise ValueError("invalid adaptive-reprogramming parameters")
    first = 0.5 * (quantum_queries_log2 - salt_bits)
    second = quantum_queries_log2 - salt_bits - 1.0
    log2_bound = math.log2(reprogrammings) + _log2_add(first, second)
    return max(0.0, -min(0.0, log2_bound))


def minimum_salt_bits_for_reprogramming(
    *, target_bits: int, reprogrammings: int, quantum_queries_log2: float
) -> int:
    if target_bits <= 0:
        raise ValueError("target bits must be positive")
    for salt_bits in range(1, 4097):
        if (
            adaptive_reprogramming_security_bits(
                salt_bits=salt_bits,
                reprogrammings=reprogrammings,
                quantum_queries_log2=quantum_queries_log2,
            )
            >= target_bits
        ):
            return salt_bits
    raise ValueError("required salt exceeds calculator range")


def grover_any_target_work_bits(*, salt_bits: int, targets: int) -> float:
    """Generic multi-target search work exponent, not a protocol reduction."""

    if salt_bits <= 0 or targets <= 0:
        raise ValueError("invalid Grover screen parameters")
    return max(0.0, (salt_bits - math.log2(targets)) / 2.0)


def minimum_salt_bits_for_multitarget_work(
    *, target_bits: int, targets: int
) -> int:
    if target_bits <= 0 or targets <= 0:
        raise ValueError("invalid multi-target parameters")
    return math.ceil(2 * target_bits + math.log2(targets))


def bcs_classical_privacy_bits(*, lambda_bits: int, leaves: int) -> float:
    """Return the exponent in BCS Lemma 3.4: n*2^(-lambda/4+2)."""

    if lambda_bits <= 0 or leaves <= 0:
        raise ValueError("invalid BCS parameters")
    return lambda_bits / 4.0 - 2.0 - math.log2(leaves)


def minimum_bcs_lambda_bits(*, target_bits: int, leaves: int) -> int:
    if target_bits <= 0 or leaves <= 0:
        raise ValueError("invalid BCS target")
    return math.ceil(4.0 * (target_bits + 2.0 + math.log2(leaves)))


def direct_bcs_salt_bytes(*, target_bits: int, leaves: int) -> int:
    """Per-tree salt floor obtained from BCS Lemma 3.4.

    For a power-of-two tree, the lemma's classical statistical error

        n * 2^(-lambda/4 + 2)

    is at most ``2^-target_bits`` only when the salt has at least
    ``target_bits + 2 + log2(n)`` bytes.  This is a theorem-scope diagnostic,
    not a QROM or SHAKE256 instantiation result.
    """

    if target_bits <= 0 or leaves <= 0:
        raise ValueError("invalid direct-BCS salt parameters")
    log2_leaves_ceiling = (leaves - 1).bit_length()
    return target_bits + 2 + log2_leaves_ceiling


def _row_by_label(rows: Sequence[dict[str, object]], label: str) -> dict[str, object]:
    matches = [row for row in rows if row.get("label") == label]
    if len(matches) != 1:
        raise RuntimeError(f"expected one row labeled {label!r}")
    return matches[0]


def _strict_padding_row(*, queries: int, salt_bytes: int) -> dict[str, object]:
    report = _random_padding_module().report()
    key = "strict_profiles" if salt_bytes == SALT_BYTES else "theorem_scoped_salt_profiles"
    matches = [
        row
        for row in report[key]
        if row["rate"] == "1/32"
        and row["schedule_mode"] == "independent-worst-union"
        and row["queries_per_branch"] == queries
        and row["leaf_salt_bytes"] == salt_bytes
    ]
    if len(matches) != 1:
        raise RuntimeError("current random-padding byte row is ambiguous")
    return matches[0]


def current_artifact_rows() -> dict[str, object]:
    """Read exact current rows from both pinned executable artifacts."""

    fri_report = _random_padding_fri_module().report()
    topologies = fri_report["production_n15_topologies"]
    return {
        "strict_random_padding_precursor": {
            "conditional_q33_salt32_bytes": _strict_padding_row(
                queries=33, salt_bytes=32
            )["raw_wire_bytes"],
            "double_full_q66_salt32_bytes": _strict_padding_row(
                queries=66, salt_bytes=32
            )["raw_wire_bytes"],
            "conditional_q33_uniform_salt148_bytes": _strict_padding_row(
                queries=33, salt_bytes=148
            )["raw_wire_bytes"],
            "double_full_q66_uniform_salt148_bytes": _strict_padding_row(
                queries=66, salt_bytes=148
            )["raw_wire_bytes"],
        },
        "one_round_separate_fold_trees": {
            "conditional_q33_salt32_bytes": _row_by_label(
                topologies, "conditional-q33-rate32-salt32-unproved"
            )["query_only_one_round_bytes"],
            "double_full_q66_salt32_bytes": _row_by_label(
                topologies, "double-full-q66-rate32-salt32-unproved"
            )["query_only_one_round_bytes"],
            "conditional_q33_uniform_salt148_bytes": _row_by_label(
                topologies, "conditional-q33-rate32-salt148-theorem-scope"
            )["query_only_one_round_bytes"],
            "double_full_q66_uniform_salt148_bytes": _row_by_label(
                topologies, "double-full-q66-rate32-salt148-theorem-scope"
            )["query_only_one_round_bytes"],
        },
        "combined_fold_tree": fri_report["combined_fold_tree_best_case"],
        "all_rounds": fri_report["all_rounds_structural_floor"],
    }


def corrected_direct_bcs_rows() -> dict[str, object]:
    """Reprice the FRI screens with a distinct classical salt per tree."""

    artifact = current_artifact_rows()
    combined = artifact["combined_fold_tree"]
    base_salt = direct_bcs_salt_bytes(target_bits=TARGET_BITS, leaves=1 << 18)
    combined_fold_salt = direct_bcs_salt_bytes(
        target_bits=TARGET_BITS, leaves=1 << 19
    )
    corrected_combined = (
        combined["fixed_wire_bytes"]
        + combined["base_opened_leaves"]
        * (LEAF_GROUP_SYMBOLS * B128_BYTES + base_salt)
        + combined["combined_fold_opened_union"]
        * (LEAF_GROUP_SYMBOLS * B128_BYTES + combined_fold_salt)
        + (
            combined["base_frontier_nodes"]
            + combined["combined_fold_frontier_nodes"]
        )
        * DIGEST_BYTES
    )

    all_rounds = artifact["all_rounds"]
    base_opened = 66
    base_frontier = _random_padding_fri_module().canonical_frontier_max(
        1 << 18, base_opened
    )
    corrected_all_rounds = (
        all_rounds["fixed_wire_bytes"]
        + base_opened * (LEAF_GROUP_SYMBOLS * B128_BYTES + base_salt)
        + base_frontier * DIGEST_BYTES
    )
    round_rows = []
    for row in all_rounds["rounds"]:
        salt_bytes = direct_bcs_salt_bytes(
            target_bits=TARGET_BITS, leaves=row["combined_fold_leaf_count"]
        )
        wire_bytes = (
            row["opened_leaves"]
            * (LEAF_GROUP_SYMBOLS * B128_BYTES + salt_bytes)
            + row["frontier_nodes"] * DIGEST_BYTES
        )
        corrected_all_rounds += wire_bytes
        round_rows.append(
            {
                "round": row["round"],
                "leaf_count": row["combined_fold_leaf_count"],
                "opened_leaves": row["opened_leaves"],
                "direct_bcs_salt_bytes": salt_bytes,
                "wire_bytes_excluding_root": wire_bytes,
                "classical_bcs_scope_only": True,
                "qrom_applicable": False,
                "strict_security_result": False,
            }
        )

    return {
        "formula_for_power_of_two_tree": (
            "salt_bytes = target_bits + 2 + log2(leaves)"
        ),
        "target_bits": TARGET_BITS,
        "base_tree_leaf_count": 1 << 18,
        "base_tree_salt_bytes": base_salt,
        "combined_fold_tree_leaf_count": 1 << 19,
        "combined_fold_tree_salt_bytes": combined_fold_salt,
        "combined_one_round_corrected_bytes": corrected_combined,
        "artifact_per_tree_combined_bytes": combined[
            "theorem_scoped_salt_one_round_bytes"
        ],
        "artifact_matches_recomputed_combined": (
            combined["theorem_scoped_salt_one_round_bytes"] == corrected_combined
        ),
        "all_rounds_corrected_bytes": corrected_all_rounds,
        "artifact_per_tree_all_rounds_bytes": all_rounds[
            "theorem_scoped_salt_structural_floor_bytes"
        ],
        "artifact_matches_recomputed_all_rounds": (
            all_rounds["theorem_scoped_salt_structural_floor_bytes"]
            == corrected_all_rounds
        ),
        "rounds": round_rows,
        "classical_random_oracle_scope_only": True,
        "qrom_applicable": False,
        "strict_security_result": False,
        "frontier_eligible": False,
    }


def unruh_corollary35_unpredictability_term_bits(
    *, commitment_collision_entropy_bits: int, proof_queries: int, hash_queries: int
) -> float:
    """Screen only the first term of Unruh 2017/398, Corollary 35.

    That QROM theorem is for a Fiat--Shamir transformed sigma protocol.  Its
    zero-knowledge advantage contains

      (4+sqrt(2))*qP*sqrt(qP+qH)*epsilon_u^(1/4).

    Supplying ``epsilon_u=2^-collision_entropy`` yields the returned exponent.
    This does not make the theorem applicable to the multi-round IOP here.
    """

    if (
        commitment_collision_entropy_bits <= 0
        or proof_queries <= 0
        or hash_queries < 0
    ):
        raise ValueError("invalid Unruh Corollary 35 parameters")
    coefficient = (
        (4.0 + math.sqrt(2.0))
        * proof_queries
        * math.sqrt(proof_queries + hash_queries)
    )
    return max(
        0.0,
        commitment_collision_entropy_bits / 4.0 - math.log2(coefficient),
    )


def adaptive_selector_distribution(witness: int) -> Counter[int]:
    """Rank-one-per-realization counterexample from the padding audit."""

    if witness not in (0, 1):
        raise ValueError("toy witness must be a bit")
    result: Counter[int] = Counter()
    for first, second in itertools.product(range(2), repeat=2):
        selected = (first, second)[first]
        result[witness ^ selected] += 1
    return result


def selective_failure_distribution(witness: int) -> Counter[str]:
    """One-attempt abort channel whose accepted challenge reveals the witness."""

    if witness not in (0, 1):
        raise ValueError("toy witness must be a bit")
    result: Counter[str] = Counter()
    for challenge in range(2):
        result[str(challenge) if challenge == witness else "abort"] += 1
    return result


def reused_padding_delta(
    first_active: Sequence[int], second_active: Sequence[int], padding: Sequence[int]
) -> tuple[int, ...]:
    """Show exact characteristic-two cancellation under pad reuse."""

    if len(first_active) != len(second_active):
        raise ValueError("active vectors differ in length")
    first = tuple(first_active) + tuple(padding)
    second = tuple(second_active) + tuple(padding)
    return tuple(left ^ right for left, right in zip(first, second))


@dataclass(frozen=True)
class SimulatorContract:
    pinned_leaf_and_node_framing: bool
    pinned_executable_one_round_fri_seam: bool
    fresh_independent_leaf_salts_enforced: bool
    fresh_independent_random_tail_enforced: bool
    compiled_full_observation_matrix_frozen: bool
    adaptive_opening_view_witness_independent: bool
    root_collision_entropy_conditioned_on_side_information_proved: bool
    merkle_root_and_authentication_qrom_simulator_proved: bool
    complete_fri_proximity_and_extraction_proved: bool
    fiat_shamir_program_points_and_order_frozen: bool
    adaptive_reprogramming_theorem_instantiated: bool
    witness_independent_abort_and_retry_distribution_proved: bool
    multi_proof_salt_and_padding_reuse_rejected: bool
    shake256_512_qrom_instantiation_proved: bool
    complete_joint_simulator_proved: bool

    @property
    def all_required(self) -> bool:
        return all(asdict(self).values())


def _reprogramming_rows() -> list[dict[str, object]]:
    rows = []
    scenarios = (
        ("one-program-point", 1),
        ("rate32-precursor-opened-leaf-scale", RATE32_PRECURSOR_OPENED_LEAVES),
        (
            "rate32-one-round-separate-opened-leaf-scale",
            RATE32_ONE_ROUND_SEPARATE_OPENED_LEAVES,
        ),
        ("rate32-all-leaf-scale", RATE32_LEAF_COUNT),
    )
    for name, reprogrammings in scenarios:
        for query_log2 in (0, 32, 64):
            bits = adaptive_reprogramming_security_bits(
                salt_bits=SALT_BITS,
                reprogrammings=reprogrammings,
                quantum_queries_log2=query_log2,
            )
            rows.append(
                {
                    "scenario": name,
                    "reprogrammings": reprogrammings,
                    "quantum_queries_log2": query_log2,
                    "screened_bound_bits_with_256_bit_position_entropy": bits,
                    "meets_128_bits": bits >= TARGET_BITS,
                    "minimum_salt_bits_for_128_bound": (
                        minimum_salt_bits_for_reprogramming(
                            target_bits=TARGET_BITS,
                            reprogrammings=reprogrammings,
                            quantum_queries_log2=query_log2,
                        )
                    ),
                    "theorem_instantiated_for_hegemon": False,
                }
            )
    return rows


def report() -> dict[str, object]:
    sources = source_records()
    lambda_from_salt = SALT_BITS // 2
    lambda_from_digest = DIGEST_BITS
    required_bcs_lambda = minimum_bcs_lambda_bits(
        target_bits=TARGET_BITS, leaves=RATE32_LEAF_COUNT
    )
    contract = SimulatorContract(
        pinned_leaf_and_node_framing=bool(sources["random_padding"]["matches"]),
        pinned_executable_one_round_fri_seam=bool(
            sources["one_round_fri"]["matches"]
        ),
        fresh_independent_leaf_salts_enforced=False,
        fresh_independent_random_tail_enforced=False,
        compiled_full_observation_matrix_frozen=False,
        adaptive_opening_view_witness_independent=False,
        root_collision_entropy_conditioned_on_side_information_proved=False,
        merkle_root_and_authentication_qrom_simulator_proved=False,
        complete_fri_proximity_and_extraction_proved=False,
        fiat_shamir_program_points_and_order_frozen=False,
        adaptive_reprogramming_theorem_instantiated=False,
        witness_independent_abort_and_retry_distribution_proved=False,
        multi_proof_salt_and_padding_reuse_rejected=False,
        shake256_512_qrom_instantiation_proved=False,
        complete_joint_simulator_proved=False,
    )
    return {
        "schema": "hegemon.salted-bcs-zk-audit.v2",
        "sources": sources,
        "exact_framing": {
            "leaf_symbols": LEAF_GROUP_SYMBOLS,
            "leaf_payload_bytes": LEAF_GROUP_SYMBOLS * B128_BYTES,
            "salt_bytes": SALT_BYTES,
            "digest": "SHAKE256-512",
            "digest_bytes": DIGEST_BYTES,
            "leaf_index_bound": True,
            "leaf_and_node_domains_separated": True,
        },
        "fixed_matrix_boundary": {
            "rank_lemma_valid_for_fixed_schedule": True,
            "schedule_depends_on_salted_root_and_fiat_shamir": True,
            "adaptive_rank_counterexample_present": True,
            "fixed_rank_implies_adaptive_zk": False,
        },
        "classical_bcs_direct_application": {
            "paper_scope": (
                "classical explicitly-programmable random oracle; leaf salt 2*lambda "
                "bits; oracle output lambda bits; Lemma 3.4 privacy error "
                "n*2^(-lambda/4+2)"
            ),
            "lambda_from_actual_salt_bits": lambda_from_salt,
            "lambda_from_actual_digest_bits": lambda_from_digest,
            "one_common_lambda_exists": lambda_from_salt == lambda_from_digest,
            "direct_parameter_match": False,
            "hypothetical_bound_bits_at_lambda_from_salt": (
                bcs_classical_privacy_bits(
                    lambda_bits=lambda_from_salt, leaves=RATE32_LEAF_COUNT
                )
            ),
            "hypothetical_bound_bits_at_lambda_from_digest": (
                bcs_classical_privacy_bits(
                    lambda_bits=lambda_from_digest, leaves=RATE32_LEAF_COUNT
                )
            ),
            "salt_bits_required_if_lambda_equals_digest": 2 * DIGEST_BITS,
            "lambda_bits_required_for_128_bound_at_rate32_tree": required_bcs_lambda,
            "salt_bits_required_by_that_classical_lemma": 2 * required_bcs_lambda,
            "per_tree_salt_bytes_formula_for_power_of_two_tree": (
                "target_bits + 2 + log2(leaves)"
            ),
            "rate32_n18_salt_bytes": direct_bcs_salt_bytes(
                target_bits=TARGET_BITS, leaves=RATE32_LEAF_COUNT
            ),
            "fixed_64_byte_digest_lambda_bits": DIGEST_BITS,
            "fixed_64_byte_digest_bound_bits_at_n18": bcs_classical_privacy_bits(
                lambda_bits=DIGEST_BITS, leaves=RATE32_LEAF_COUNT
            ),
            "qrom_result": False,
        },
        "current_artifact_rows": current_artifact_rows(),
        "corrected_direct_bcs_per_tree_rows": corrected_direct_bcs_rows(),
        "primary_theorem_scopes": {
            "bcs_2016_116": {
                "result": "Lemma 3.4 and Lemma 7.5",
                "model": "classical explicitly-programmable random oracle",
                "covers_this_qrom_transcript": False,
            },
            "unruh_2017_398": {
                "result": "Theorem 20 and concrete Corollary 35",
                "requires": (
                    "Fiat-Shamir of a sigma protocol with HVZK, completeness, "
                    "and unpredictable commitments"
                ),
                "optimistic_512_bit_root_first_term_bits_qp1_qh0": (
                    unruh_corollary35_unpredictability_term_bits(
                        commitment_collision_entropy_bits=DIGEST_BITS,
                        proof_queries=1,
                        hash_queries=0,
                    )
                ),
                "covers_this_multi_round_iop_merkle_simulator": False,
            },
            "dfm_2020_282": {
                "result": "Corollary 15",
                "scope": "multi-round Fiat-Shamir preservation of soundness and PoK",
                "supplies_zero_knowledge_simulator": False,
            },
            "grilo_hovelmanns_hulsing_majenz_2020_1361": {
                "result": "Theorem 1 adaptive QROM reprogramming",
                "requires": (
                    "exact R, quantum-query prefixes, maximum point probability, "
                    "and classical reprogramming triggers"
                ),
                "screened_but_instantiated": False,
            },
        },
        "qrom_screens_not_proofs": {
            "adaptive_reprogramming_theorem1_rows": _reprogramming_rows(),
            "single_salt_single_target_grover_work_bits": (
                grover_any_target_work_bits(salt_bits=SALT_BITS, targets=1)
            ),
            "rate32_all_leaf_multitarget_grover_work_bits": (
                grover_any_target_work_bits(
                    salt_bits=SALT_BITS, targets=RATE32_LEAF_COUNT
                )
            ),
            "minimum_salt_bits_for_rate32_all_leaf_128_work_screen": (
                minimum_salt_bits_for_multitarget_work(
                    target_bits=TARGET_BITS, targets=RATE32_LEAF_COUNT
                )
            ),
            "shake512_generic_quantum_preimage_work_bits": DIGEST_BITS / 2.0,
            "shake512_generic_quantum_collision_work_bits": DIGEST_BITS / 3.0,
            "generic_work_factors_are_not_composed_protocol_bounds": True,
        },
        "simulator_contract": {
            **asdict(contract),
            "all_required": contract.all_required,
        },
        "risks": {
            "adaptive_openings": (
                "query rows are selected from a root that depends on padding and salts; "
                "post-selection rank is unsound"
            ),
            "selective_failure": (
                "abort or retry conditioned on challenges, rank, or witness can leak through "
                "success, timing, or the retained transcript"
            ),
            "reuse": (
                "reusing a leaf salt links equal indexed payloads; reusing the random tail "
                "cancels masks across linear views"
            ),
            "qrom_programming": (
                "classical lazy programming does not survive quantum superposition queries "
                "without an entropy- and query-bounded QROM theorem"
            ),
        },
        "verdict": {
            "salt_charge_status": "UNPROVED_FOR_PQ128",
            "direct_bcs_application": "FAILS_PARAMETER_AND_MODEL_SCOPE",
            "salt_is_sufficient_evidence_for_complete_zk": False,
            "strict_pq128": False,
            "frontier_eligible": False,
            "summary": (
                "32 bytes is the asymptotic 2*128 BCS salt charge, but it neither "
                "instantiates BCS Lemma 3.4 with a 512-bit oracle nor closes the "
                "adaptive QROM simulator. A new lazy Merkle/Fiat-Shamir simulator "
                "could use a different bound, so the construction is unproved rather "
                "than universally impossible."
            ),
        },
    }


def self_check() -> None:
    assert all(record["matches"] for record in source_records().values())
    digest = actual_leaf_hash(0, (0, 1, 2, 3), bytes(SALT_BYTES))
    assert len(digest) == DIGEST_BYTES
    assert RATE32_LEAF_COUNT == 1 << 18
    assert bcs_classical_privacy_bits(lambda_bits=128, leaves=1 << 18) == 12
    assert bcs_classical_privacy_bits(lambda_bits=512, leaves=1 << 18) == 108
    assert minimum_bcs_lambda_bits(target_bits=128, leaves=1 << 18) == 592
    assert direct_bcs_salt_bytes(target_bits=128, leaves=1 << 18) == 148
    assert direct_bcs_salt_bytes(target_bits=128, leaves=1 << 19) == 149
    assert unruh_corollary35_unpredictability_term_bits(
        commitment_collision_entropy_bits=512,
        proof_queries=1,
        hash_queries=0,
    ) < 128
    assert grover_any_target_work_bits(salt_bits=256, targets=1 << 18) == 119
    assert minimum_salt_bits_for_multitarget_work(
        target_bits=128, targets=1 << 18
    ) == 274
    assert find_toy_collision()
    result = report()
    rows = result["current_artifact_rows"]
    assert rows["strict_random_padding_precursor"][
        "conditional_q33_salt32_bytes"
    ] == 69_632
    assert rows["strict_random_padding_precursor"][
        "double_full_q66_salt32_bytes"
    ] == 128_512
    assert rows["one_round_separate_fold_trees"][
        "conditional_q33_salt32_bytes"
    ] == 118_192
    assert rows["one_round_separate_fold_trees"][
        "double_full_q66_salt32_bytes"
    ] == 219_056
    corrected = result["corrected_direct_bcs_per_tree_rows"]
    assert corrected["combined_one_round_corrected_bytes"] == 101_261
    assert corrected["artifact_per_tree_combined_bytes"] == 101_261
    assert corrected["artifact_matches_recomputed_combined"]
    assert corrected["all_rounds_corrected_bytes"] == 387_427
    assert corrected["artifact_per_tree_all_rounds_bytes"] == 387_427
    assert corrected["artifact_matches_recomputed_all_rounds"]
    assert not result["simulator_contract"]["all_required"]
    assert result["verdict"]["salt_charge_status"] == "UNPROVED_FOR_PQ128"
    assert not result["verdict"]["frontier_eligible"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("SALTED_BCS_ZK_AUDIT_PASS")
    if args.report:
        print(json.dumps(report(), sort_keys=True, separators=(",", ":")))
    if not args.check and not args.report:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
