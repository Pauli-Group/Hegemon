#!/usr/bin/env python3
"""Fail-closed parameter and byte gate for the standalone Binius prototype.

This module is deliberately not a proof of Binius soundness or zero knowledge.
It makes the proposed assumptions executable, combines their stated failure
probabilities with a union bound, and refuses to call the backend releasable
until implementation and review capabilities are supplied by real evidence.

The current upstream Binius64 profile (96-bit query budget, SHA-256, and
GF(2^128)) is included only as a negative control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


POST_QUANTUM_TARGET_BITS = 128
MIN_CLASSICAL_PROTOCOL_BITS = 264
SELECTED_CLASSICAL_PROTOCOL_BITS = 264
MIN_SECRET_ENTROPY_BITS = 384

BLOCK_CAP_BYTES = 64 * 1024 * 1024
BLOCK_FIXED_BYTES = 2_525
NON_PROOF_ACTION_BYTES = 4_967
PROOF_OPTIMIZATION_TARGET_BYTES = 512 * 1024
PROOF_HARD_CAP_BYTES = 1024 * 1024


@dataclass(frozen=True)
class BackendCapabilities:
    """Evidence flags that code must earn; the prototype cannot self-assert them."""

    strict_profile_implemented: bool
    maximum_relation_zero_knowledge_proved: bool
    composed_qrom_bound_reviewed: bool
    canonical_serialization_measured: bool


@dataclass(frozen=True)
class SecurityProfile:
    """Inputs to the conservative prototype security calculation."""

    name: str
    semantic_hash: str
    semantic_output_bits: int
    proof_hash: str
    proof_output_bits: int
    challenge_field: str
    challenge_field_bits: int
    max_algebraic_union_degree_log2: int
    fri_classical_bits: int
    fiat_shamir_classical_bits: int
    multi_target_classical_bits: int
    zero_knowledge_statistical_bits: int
    spend_secret_entropy_bits: int
    note_randomness_entropy_bits: int
    rho_entropy_bits: int
    capabilities: BackendCapabilities

    @property
    def algebraic_classical_bits(self) -> int:
        # A union of algebraic degrees below 2^d in GF(2^n) contributes at
        # most 2^(d-n) in the stated scalar model. The QROM bridge is then
        # charged a square-root loss below.
        return self.challenge_field_bits - self.max_algebraic_union_degree_log2

    @property
    def semantic_profile_name(self) -> str:
        return f"{self.semantic_hash}-{self.semantic_output_bits}"

    @property
    def proof_profile_name(self) -> str:
        return f"{self.proof_hash}-{self.proof_output_bits}"


SCAFFOLD_CAPABILITIES = BackendCapabilities(
    strict_profile_implemented=False,
    maximum_relation_zero_knowledge_proved=False,
    composed_qrom_bound_reviewed=False,
    canonical_serialization_measured=False,
)


STRICT_PQ_SCAFFOLD = SecurityProfile(
    name="standalone-shake256-binius-pq128-scaffold",
    semantic_hash="SHAKE256",
    semantic_output_bits=448,
    proof_hash="SHAKE256",
    proof_output_bits=512,
    challenge_field="GF(2^384)",
    challenge_field_bits=384,
    # 384 - 120 = 264 classical bits before the modeled QROM loss.
    max_algebraic_union_degree_log2=120,
    fri_classical_bits=SELECTED_CLASSICAL_PROTOCOL_BITS,
    fiat_shamir_classical_bits=SELECTED_CLASSICAL_PROTOCOL_BITS,
    multi_target_classical_bits=SELECTED_CLASSICAL_PROTOCOL_BITS,
    zero_knowledge_statistical_bits=192,
    spend_secret_entropy_bits=384,
    note_randomness_entropy_bits=384,
    rho_entropy_bits=384,
    capabilities=SCAFFOLD_CAPABILITIES,
)


UPSTREAM_NEGATIVE_CONTROL = SecurityProfile(
    name="upstream-binius64-96bit-negative-control",
    semantic_hash="SHA-256",
    semantic_output_bits=256,
    proof_hash="SHA-256",
    proof_output_bits=256,
    challenge_field="GF(2^128)",
    challenge_field_bits=128,
    # This optimistic allowance still leaves only 96 classical field bits.
    max_algebraic_union_degree_log2=32,
    fri_classical_bits=96,
    fiat_shamir_classical_bits=96,
    multi_target_classical_bits=96,
    # The direct upstream path is not end-to-end zero knowledge. Sixty-four
    # is recorded only to keep the negative-control arithmetic finite.
    zero_knowledge_statistical_bits=64,
    spend_secret_entropy_bits=256,
    note_randomness_entropy_bits=256,
    rho_entropy_bits=256,
    capabilities=SCAFFOLD_CAPABILITIES,
)


@dataclass(frozen=True)
class SecurityTerm:
    name: str
    source: str
    source_bits: float
    quantum_rule: str
    post_quantum_bits: float


@dataclass(frozen=True)
class ProofMeasurement:
    path: str
    serialized_proof_bytes: int
    shake256_512: Optional[str]
    digest_skipped_reason: Optional[str]


def _qrom_square_root(classical_bits: int) -> float:
    return classical_bits / 2.0


def _quantum_collision(output_bits: int) -> float:
    # The generic quantum collision cost is modeled as 2^(n/3). This is an
    # engineering ceiling, not a reduction for SHAKE or the complete IOP.
    return output_bits / 3.0


def _grover_search(entropy_bits: int) -> float:
    # Generic exhaustive quantum search halves the exponent.  This is kept
    # separate from collision binding because spend-key recovery and note
    # hiding are preimage/search goals, not collision goals.
    return entropy_bits / 2.0


def security_terms(profile: SecurityProfile) -> tuple[SecurityTerm, ...]:
    algebraic = float(profile.algebraic_classical_bits)
    return (
        SecurityTerm(
            "constraint",
            "challenge field minus the aggregate algebraic degree allowance",
            algebraic,
            "QROM square-root loss",
            _qrom_square_root(profile.algebraic_classical_bits),
        ),
        SecurityTerm(
            "sumcheck",
            "challenge field minus the aggregate algebraic degree allowance",
            algebraic,
            "QROM square-root loss",
            _qrom_square_root(profile.algebraic_classical_bits),
        ),
        SecurityTerm(
            "folding",
            "challenge field minus the aggregate algebraic degree allowance",
            algebraic,
            "QROM square-root loss",
            _qrom_square_root(profile.algebraic_classical_bits),
        ),
        SecurityTerm(
            "FRI",
            "configured complete FRI error budget",
            float(profile.fri_classical_bits),
            "QROM square-root loss",
            _qrom_square_root(profile.fri_classical_bits),
        ),
        SecurityTerm(
            "Merkle binding",
            f"{profile.proof_profile_name} output",
            float(profile.proof_output_bits),
            "generic quantum collision ceiling n/3",
            _quantum_collision(profile.proof_output_bits),
        ),
        SecurityTerm(
            "Fiat-Shamir",
            "configured extractor/programmability budget",
            float(profile.fiat_shamir_classical_bits),
            "QROM square-root loss",
            _qrom_square_root(profile.fiat_shamir_classical_bits),
        ),
        SecurityTerm(
            "multi-target",
            "configured aggregate multi-target budget",
            float(profile.multi_target_classical_bits),
            "QROM square-root loss",
            _qrom_square_root(profile.multi_target_classical_bits),
        ),
        SecurityTerm(
            "zero knowledge",
            "configured statistical simulation distance",
            float(profile.zero_knowledge_statistical_bits),
            "direct statistical failure term",
            float(profile.zero_knowledge_statistical_bits),
        ),
        SecurityTerm(
            "semantic hash binding",
            f"{profile.semantic_profile_name} output",
            float(profile.semantic_output_bits),
            "generic quantum collision ceiling n/3",
            _quantum_collision(profile.semantic_output_bits),
        ),
        SecurityTerm(
            "spend-key recovery",
            "minimum entropy of the wallet spend secret",
            float(profile.spend_secret_entropy_bits),
            "generic Grover key search",
            _grover_search(profile.spend_secret_entropy_bits),
        ),
        SecurityTerm(
            "note-commitment hiding",
            "minimum entropy of per-note commitment randomness",
            float(profile.note_randomness_entropy_bits),
            "generic Grover randomness search",
            _grover_search(profile.note_randomness_entropy_bits),
        ),
        SecurityTerm(
            "rho search privacy",
            "minimum entropy of the per-note rho value",
            float(profile.rho_entropy_bits),
            "generic Grover randomness search",
            _grover_search(profile.rho_entropy_bits),
        ),
    )


def union_bound_bits(terms: Iterable[SecurityTerm]) -> float:
    probabilities = [math.exp2(-term.post_quantum_bits) for term in terms]
    if not probabilities:
        raise ValueError("at least one security term is required")
    return -math.log2(math.fsum(probabilities))


def static_profile_failures(profile: SecurityProfile) -> list[str]:
    failures: list[str] = []
    if profile.semantic_hash != "SHAKE256" or profile.semantic_output_bits < 448:
        failures.append("semantic hash must be SHAKE256-448 or wider")
    if profile.proof_hash != "SHAKE256" or profile.proof_output_bits < 512:
        failures.append("proof commitments and transcript must be SHAKE256-512 or wider")
    if profile.challenge_field != "GF(2^384)" or profile.challenge_field_bits < 384:
        failures.append("algebraic challenges must use GF(2^384) or an explicitly reviewed stronger field")
    if profile.algebraic_classical_bits < MIN_CLASSICAL_PROTOCOL_BITS:
        failures.append("algebraic challenge budget is below 264 classical bits")
    if profile.fri_classical_bits < MIN_CLASSICAL_PROTOCOL_BITS:
        failures.append("FRI budget is below 264 classical bits")
    if profile.fiat_shamir_classical_bits < MIN_CLASSICAL_PROTOCOL_BITS:
        failures.append("Fiat-Shamir budget is below 264 classical bits")
    if profile.multi_target_classical_bits < MIN_CLASSICAL_PROTOCOL_BITS:
        failures.append("multi-target budget is below 264 classical bits")
    if profile.zero_knowledge_statistical_bits < POST_QUANTUM_TARGET_BITS:
        failures.append("zero-knowledge statistical failure budget is below 128 bits")
    if profile.spend_secret_entropy_bits < MIN_SECRET_ENTROPY_BITS:
        failures.append("spend-secret entropy is below 384 bits")
    if profile.note_randomness_entropy_bits < MIN_SECRET_ENTROPY_BITS:
        failures.append("note-randomness entropy is below 384 bits")
    if profile.rho_entropy_bits < MIN_SECRET_ENTROPY_BITS:
        failures.append("rho entropy is below 384 bits")

    composed = union_bound_bits(security_terms(profile))
    if math.floor(composed) < POST_QUANTUM_TARGET_BITS:
        failures.append(
            "composed post-quantum union bound rounds down below 128 bits "
            f"({composed:.6f})"
        )
    return failures


def capacity_for_proof_bytes(proof_bytes: int) -> dict[str, int]:
    if proof_bytes < 0:
        raise ValueError("proof byte length cannot be negative")
    action_bytes = NON_PROOF_ACTION_BYTES + proof_bytes
    if action_bytes <= 0 or BLOCK_CAP_BYTES < BLOCK_FIXED_BYTES:
        raise ValueError("invalid block geometry")
    capacity = (BLOCK_CAP_BYTES - BLOCK_FIXED_BYTES) // action_bytes
    used = BLOCK_FIXED_BYTES + capacity * action_bytes
    return {
        "proof_bytes": proof_bytes,
        "non_proof_action_bytes": NON_PROOF_ACTION_BYTES,
        "action_bytes": action_bytes,
        "block_cap_bytes": BLOCK_CAP_BYTES,
        "block_fixed_bytes": BLOCK_FIXED_BYTES,
        "max_actions": capacity,
        "block_bytes_at_max_actions": used,
        "unused_block_bytes": BLOCK_CAP_BYTES - used,
    }


def measure_serialized_proof(path: Path) -> ProofMeasurement:
    file_stat = path.stat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"proof artifact is not a regular file: {path}")

    size = file_stat.st_size
    if size > PROOF_HARD_CAP_BYTES:
        # Mirror admission order: size rejection must precede hashing or any
        # expensive proof work. The exact serialized size is still reported.
        return ProofMeasurement(
            path=str(path.resolve()),
            serialized_proof_bytes=size,
            shake256_512=None,
            digest_skipped_reason="artifact exceeds the 1 MiB hard cap",
        )

    digest = hashlib.shake_256()
    observed = 0
    with path.open("rb") as proof_file:
        while True:
            chunk = proof_file.read(64 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
    if observed != size:
        raise OSError(
            f"proof artifact changed while being measured: stat={size}, read={observed}"
        )
    return ProofMeasurement(
        path=str(path.resolve()),
        serialized_proof_bytes=size,
        shake256_512=digest.hexdigest(64),
        digest_skipped_reason=None,
    )


def _measurement_report(measurement: Optional[ProofMeasurement]) -> dict[str, Any]:
    reference = {
        "optimization_target": capacity_for_proof_bytes(PROOF_OPTIMIZATION_TARGET_BYTES),
        "hard_cap": capacity_for_proof_bytes(PROOF_HARD_CAP_BYTES),
    }
    if measurement is None:
        return {
            "measured": False,
            "measurement": None,
            "optimization_target_bytes": PROOF_OPTIMIZATION_TARGET_BYTES,
            "hard_cap_bytes": PROOF_HARD_CAP_BYTES,
            "reference_capacity": reference,
            "byte_gate_pass": False,
        }

    size = measurement.serialized_proof_bytes
    return {
        "measured": True,
        "measurement": asdict(measurement),
        "optimization_target_bytes": PROOF_OPTIMIZATION_TARGET_BYTES,
        "hard_cap_bytes": PROOF_HARD_CAP_BYTES,
        "at_or_below_optimization_target": 0 < size <= PROOF_OPTIMIZATION_TARGET_BYTES,
        "at_or_below_hard_cap": 0 < size <= PROOF_HARD_CAP_BYTES,
        "byte_gate_pass": 0 < size <= PROOF_HARD_CAP_BYTES,
        "capacity": capacity_for_proof_bytes(size),
        "reference_capacity": reference,
        "capacity_formula": "floor((67108864 - 2525) / (4967 + measured_proof_bytes))",
    }


def evaluate_profile(
    profile: SecurityProfile,
    measurement: Optional[ProofMeasurement] = None,
) -> dict[str, Any]:
    terms = security_terms(profile)
    composed = union_bound_bits(terms)
    failures = static_profile_failures(profile)
    bytes_report = _measurement_report(measurement)
    capabilities = asdict(profile.capabilities)
    missing_capabilities = [name for name, present in capabilities.items() if not present]

    blocking_reasons = list(failures)
    if measurement is None:
        blocking_reasons.append("no serialized proof artifact was supplied for exact measurement")
    elif not bytes_report["byte_gate_pass"]:
        blocking_reasons.append("serialized proof is empty or exceeds the 1 MiB hard cap")
    blocking_reasons.extend(
        f"backend capability not established: {name}" for name in missing_capabilities
    )

    static_gate_pass = not failures
    release_authorized = (
        static_gate_pass
        and bool(bytes_report["byte_gate_pass"])
        and not missing_capabilities
    )
    return {
        "claim_ceiling": (
            "parameter-and-size scaffold only; not backend support, a QROM proof, "
            "a zero-knowledge theorem, an audit, or consensus authorization"
        ),
        "profile": {
            **asdict(profile),
            "semantic_profile": profile.semantic_profile_name,
            "proof_profile": profile.proof_profile_name,
            "algebraic_classical_bits": profile.algebraic_classical_bits,
        },
        "security": {
            "target_post_quantum_bits": POST_QUANTUM_TARGET_BITS,
            "minimum_classical_protocol_bits": MIN_CLASSICAL_PROTOCOL_BITS,
            "selected_classical_protocol_bits": SELECTED_CLASSICAL_PROTOCOL_BITS,
            "terms": [asdict(term) for term in terms],
            "composed_union_bound_bits": composed,
            "composed_union_bound_bits_floor": math.floor(composed),
            "static_profile_failures": failures,
            "static_profile_gate_pass": static_gate_pass,
        },
        "proof_size": bytes_report,
        "backend_capabilities": capabilities,
        "release_authorized": release_authorized,
        "blocking_reasons": blocking_reasons,
    }


def run_self_check() -> None:
    strict = evaluate_profile(STRICT_PQ_SCAFFOLD)
    upstream = evaluate_profile(UPSTREAM_NEGATIVE_CONTROL)
    assert strict["security"]["composed_union_bound_bits_floor"] == 129
    assert strict["security"]["static_profile_gate_pass"] is True
    assert strict["release_authorized"] is False
    assert upstream["security"]["static_profile_gate_pass"] is False
    assert upstream["security"]["composed_union_bound_bits_floor"] < 128
    assert capacity_for_proof_bytes(PROOF_OPTIMIZATION_TARGET_BYTES)["max_actions"] == 126
    assert capacity_for_proof_bytes(PROOF_HARD_CAP_BYTES)["max_actions"] == 63


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("strict", "upstream-negative-control"),
        default="strict",
    )
    parser.add_argument(
        "--proof-file",
        type=Path,
        help="canonical serialized proof to measure; byte counts are never inferred",
    )
    parser.add_argument("--check", action="store_true", help="run pinned arithmetic checks")
    parser.add_argument(
        "--require-release",
        action="store_true",
        help="exit nonzero unless all static, byte, implementation, and review gates pass",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    if args.check:
        run_self_check()

    profile = (
        STRICT_PQ_SCAFFOLD
        if args.profile == "strict"
        else UPSTREAM_NEGATIVE_CONTROL
    )
    measurement = measure_serialized_proof(args.proof_file) if args.proof_file else None
    report = evaluate_profile(profile, measurement)
    print(json.dumps(report, indent=2, sort_keys=True))

    if not report["security"]["static_profile_gate_pass"]:
        return 2
    if measurement is not None and not report["proof_size"]["byte_gate_pass"]:
        return 2
    if args.require_release and not report["release_authorized"]:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
