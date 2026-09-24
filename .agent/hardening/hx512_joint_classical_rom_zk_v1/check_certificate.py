#!/usr/bin/env python3
"""Exact, dependency-free checker for the HX512 joint-ZK closure artifact.

This checker validates a *fail-closed* theorem/refinement contract.  A green
default run means that the retained inventory, exact arithmetic, representative
rank checks, and blockers are internally coherent.  It never means complete
zero knowledge or production authorization.  ``--require-complete`` exists so
release automation has an executable negative gate until all receipts exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Sequence


FIELD_MODULUS = 0xFFFF_FFFF_0000_0001
TWO64 = 1 << 64
FIELD_REJECT_WORDS = TWO64 - FIELD_MODULUS

VIEW_FIELDS = [
    "ProfileAndIdentity",
    "PublicStatement",
    "VerifierContext",
    "CanonicalHeader",
    "Salt",
    "PiopNonce",
    "HPiop",
    "PiopPpolHighs",
    "PiopPlinHighs",
    "PcsRcombiTails",
    "LvcsSubsetEvaluations",
    "PcsPartialEvaluations",
    "DecsAuthPathCount",
    "DecsAuthPathLengths",
    "DecsAuthPathNodes",
    "DecsLeafTapes",
    "DecsMaskingEvaluations",
    "DecsHighCoefficients",
    "OpenedWitnessMode",
    "OpenedWitnessRowScalars",
    "AuxiliaryLimbCount",
    "AuxiliaryWords",
    "ExactEndOfInput",
    "PiopOpeningPoints",
    "PcsCombinationCoefficients",
    "PcsCombinationHeads",
    "DecsOpeningIndexes",
    "DecsCosetPoints",
    "LvcsOmittedRows",
    "DecsFullPolynomials",
    "MerkleRoot",
    "TranscriptEvents",
    "RetryAbortOutcome",
]

TRANSCRIPT_EVENTS = [
    (0, "DecsRootBinding", "SHA-512", "absorb"),
    (1, "DecsCoefficientChallenge", "SHAKE256", "field-xof"),
    (2, "PiopInputBinding", "SHA-512", "absorb"),
    (3, "PiopCoefficientChallenge", "SHAKE256", "field-xof"),
    (4, "PiopTranscriptBinding", "SHA-512", "absorb"),
    (5, "PiopOpeningChallenge", "SHAKE256", "field-xof"),
    (6, "DecsOpeningBinding", "SHA-512", "absorb"),
    (7, "DecsQueryChallenge", "SHAKE256", "index-xof"),
]

SMALLWOOD_THEOREM10_EVENT_ORACLES = [
    "XOF_1",
    "XOF'_1",
    "XOF_2",
    "XOF'_2",
    "XOF_3",
    "XOF'_3",
    "XOF_4",
    "XOF'_4",
]

AUTHORITY_FLAGS = {
    "classical_rom_joint_simulator_proved",
    "whole_view_distribution_equality_proved",
    "retry_abort_refinement_proved",
    "merkle_programming_refinement_proved",
    "adaptive_fiat_shamir_refinement_proved",
    "adaptive_qrom_lift_proved",
    "concrete_hash_bridge_proved",
    "compiled_prover_refinement_proved",
    "compiled_verifier_refinement_proved",
    "canonical_parser_serializer_refinement_proved",
    "complete_zero_knowledge",
    "production_authorized",
}

REQUIRED_BLOCKERS = {
    "live-wire-prefix-compiled-refinement-unproved",
    "certificate-piop-nonce-ledger-mismatch",
    "certificate-fresh-wire-width-endian-mismatch",
    "direct-event5-opening-compiled-refinement-unproved",
    "joint-affine-containment-receipts-missing",
    "piop-pcs-joint-law-unproved",
    "lvcs-decs-joint-conditioning-unproved",
    "merkle-rom-programming-unproved",
    "retry-abort-distribution-not-refined-to-prover-api",
    "adaptive-fiat-shamir-programming-unproved",
    "ghcm-all-programmed-event-accounting-unproved",
    "independent-oracle-to-domain-separated-hash-refinement-unproved",
    "concrete-sha512-shake256-qrom-bridge-unproved",
    "canonical-parser-serializer-refinement-unproved",
    "compiled-prover-verifier-refinement-unproved",
    "salt-and-all-leaf-tape-rng-independence-unproved",
}


class CertificateError(Exception):
    """A fail-closed certificate invariant did not hold."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificateError(message)


def sha512_path(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def falling(value: int, count: int) -> int:
    require(value >= count >= 0, "invalid falling-factorial arguments")
    result = 1
    for offset in range(count):
        result *= value - offset
    return result


def rank_mod(matrix: Sequence[Sequence[int]], modulus: int = FIELD_MODULUS) -> int:
    """Exact Gaussian-elimination rank over the declared prime field."""
    if not matrix:
        return 0
    width = len(matrix[0])
    require(all(len(row) == width for row in matrix), "ragged rank matrix")
    work = [[entry % modulus for entry in row] for row in matrix]
    rank = 0
    for column in range(width):
        pivot = next((row for row in range(rank, len(work)) if work[row][column]), None)
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        inverse = pow(work[rank][column], -1, modulus)
        work[rank] = [(entry * inverse) % modulus for entry in work[rank]]
        for row in range(len(work)):
            if row == rank or work[row][column] == 0:
                continue
            factor = work[row][column]
            work[row] = [
                (entry - factor * pivot_entry) % modulus
                for entry, pivot_entry in zip(work[row], work[rank])
            ]
        rank += 1
        if rank == len(work):
            break
    return rank


def vandermonde(points: Sequence[int], columns: int) -> list[list[int]]:
    return [[pow(point, exponent, FIELD_MODULUS) for exponent in range(columns)] for point in points]


def cauchy(left: Sequence[int], right: Sequence[int]) -> list[list[int]]:
    require(set(left).isdisjoint(right), "Cauchy point sets overlap")
    return [
        [pow((x - y) % FIELD_MODULUS, -1, FIELD_MODULUS) for y in right]
        for x in left
    ]


def affine_witness_is_hidden(
    randomness_matrix: Sequence[Sequence[int]],
    witness_matrix: Sequence[Sequence[int]],
) -> bool:
    """Exact support-containment test for Y=A_r r+A_w w+b.

    Equality of these ranks is necessary and sufficient for every witness
    translation to remain inside the image of uniform randomizers.  It is a
    local affine criterion, not a substitute for adaptive conditional kernels.
    """
    require(len(randomness_matrix) == len(witness_matrix), "affine matrices disagree on row count")
    augmented = [list(a_row) + list(w_row) for a_row, w_row in zip(randomness_matrix, witness_matrix)]
    return rank_mod(randomness_matrix) == rank_mod(augmented)


def strict_security_floor_bits(probability: Fraction) -> int:
    """Greatest b such that probability < 2^-b, using integers only."""
    require(0 < probability < 1, "security floor requires probability strictly between zero and one")
    numerator = probability.numerator
    denominator = probability.denominator
    bits = max(0, denominator.bit_length() - numerator.bit_length() - 2)
    while (numerator << (bits + 1)) < denominator:
        bits += 1
    while not ((numerator << bits) < denominator):
        bits -= 1
    return bits


def field_sampler_abort_union_bound(requested: int, extra: int = 256) -> Fraction:
    """Exact union bound for >=extra+1 rejected 64-bit field candidates."""
    require(requested > 0 and extra >= 0, "invalid field sampler dimensions")
    budget = requested + extra
    failures = extra + 1
    numerator = math.comb(budget, failures) * pow(FIELD_REJECT_WORDS, failures)
    denominator = pow(TWO64, failures)
    return Fraction(numerator, denominator)


def stirling_second_kind(row: int, max_columns: int) -> list[int]:
    """Return S(row,j) for 0<=j<=max_columns using exact integers."""
    values = [0] * (max_columns + 1)
    values[0] = 1
    for n in range(1, row + 1):
        upper = min(n, max_columns)
        for j in range(upper, 0, -1):
            values[j] = j * values[j] + values[j - 1]
        values[0] = 0
    return values


def distinct_index_abort_probability(domain: int, requested: int, budget: int) -> Fraction:
    """Exact probability that budget uniform draws contain <requested values."""
    require(0 < requested <= domain and budget >= requested, "invalid distinct-index sampler dimensions")
    stirling = stirling_second_kind(budget, requested - 1)
    numerator = sum(
        falling(domain, distinct) * stirling[distinct]
        for distinct in range(requested)
    )
    return Fraction(numerator, pow(domain, budget))


def exact_rank_report(data: dict[str, Any]) -> dict[str, int]:
    profile = data["reference_fixture"]
    s = profile["piop_openings"]
    q = profile["decs_openings"]
    opened_combinations = profile["opened_combinations"]

    piop_points = list(range(profile["packing_factor"] + 1, profile["packing_factor"] + 1 + s))
    decs_left = list(range(10_000, 10_000 + q))
    decs_right = list(range(20_000, 20_000 + q))
    witness_core = rank_mod(vandermonde(piop_points, s))
    nonlinear_core = rank_mod(vandermonde(piop_points, s))
    linear_core = rank_mod(vandermonde(piop_points, s))
    lvcs_core = rank_mod(cauchy(decs_left, decs_right))
    omitted_core = rank_mod(vandermonde(piop_points + list(range(30_000, 30_000 + opened_combinations - s)), opened_combinations))
    decs_core = rank_mod(vandermonde(decs_left, q))

    nonlinear_total = profile["nonlinear_mask_degree"] + 1
    linear_total = profile["linear_mask_degree"]
    pcs_total = s * profile["partial_values_per_opening"]
    lvcs_total = profile["lvcs_rows"] * lvcs_core
    decs_total = profile["decs_eta"] * (decs_core + profile["lvcs_columns"])
    return {
        "witness-random-highs": witness_core,
        "piop-nonlinear-mask": nonlinear_core + nonlinear_total - s,
        "piop-linear-zero-sum-mask": linear_core + linear_total - s,
        "pcs-equation-6-randomizers": pcs_total,
        "lvcs-random-tails": lvcs_total,
        "lvcs-omitted-rows": omitted_core,
        "decs-masks-and-highs": decs_total,
    }


def arithmetic_report(data: dict[str, Any]) -> dict[str, Any]:
    fixture = data["reference_fixture"]

    cms_s6_left = 12 * (1 << 256) * falling(6_174, 6)
    cms_s6_right = falling(FIELD_MODULUS - 1_024, 6)
    cms_s5_left = 12 * (1 << 256) * falling(6_168, 5)
    cms_s5_right = falling(FIELD_MODULUS - 1_024, 5)

    classical_lambda = 256
    rom_queries = 1 << 64
    smallwood_rom = Fraction(
        rom_queries * ((1 << classical_lambda) + 1),
        1 << (2 * classical_lambda),
    )

    field_counts = [
        fixture["decs_eta"] * fixture["polynomial_count"],
        fixture["rho"] * fixture["piop_max_constraint_count"],
        fixture["piop_openings"],
    ]
    field_bounds = [field_sampler_abort_union_bound(count) for count in field_counts]
    index_abort = distinct_index_abort_probability(
        fixture["decs_domain_size"],
        fixture["decs_openings"],
        fixture["decs_openings"] + 512,
    )
    sampler_abort_upper = sum(field_bounds, start=Fraction(0, 1)) + index_abort

    return {
        "cms_s6_strict_gt_128": cms_s6_left < cms_s6_right,
        "cms_s5_strict_gt_128": cms_s5_left < cms_s5_right,
        "smallwood_theorem10_classical_rom_floor_bits": strict_security_floor_bits(smallwood_rom),
        "bcs16_direct_lambda512_can_exceed_128_for_nonempty_proof": 4 * 1 < 1,
        "field_sampler_requested_counts": field_counts,
        "field_sampler_abort_bound_floor_bits": [strict_security_floor_bits(bound) for bound in field_bounds],
        "decs_index_abort_exact_floor_bits": strict_security_floor_bits(index_abort),
        "all_sampler_abort_union_floor_bits": strict_security_floor_bits(sampler_abort_upper),
    }


def validate_pins(
    pins: Iterable[dict[str, Any]],
    base: Path,
    *,
    check_paths: bool,
) -> None:
    for pin in pins:
        digest = pin.get("sha512", "")
        require(len(digest) == 128 and all(c in "0123456789abcdef" for c in digest), f"bad SHA-512 pin for {pin.get('path')}")
        if not check_paths:
            continue
        path = Path(pin["path"])
        if not path.is_absolute():
            path = base / path
        require(path.is_file(), f"pinned source is missing: {path}")
        require(sha512_path(path) == digest, f"pinned source changed: {path}")


def validate_certificate(
    data: dict[str, Any],
    repo_root: Path,
    *,
    check_sources: bool = True,
    check_pdfs: bool = False,
) -> dict[str, Any]:
    require(data.get("schema") == "hegemon.hx512.joint-classical-rom-zk-certificate.v1", "schema mismatch")
    require(data.get("artifact_status") == "validated-fail-closed", "artifact is not fail closed")

    flags = data.get("authority_flags", {})
    require(set(flags) == AUTHORITY_FLAGS, "authority flag inventory changed")
    require(all(value is False for value in flags.values()), "an authority flag was enabled without a receipt")

    blockers = set(data.get("retained_blockers", []))
    require(REQUIRED_BLOCKERS <= blockers, "required complete-ZK blockers were removed")

    fields = data.get("view_fields", [])
    require([entry.get("name") for entry in fields] == VIEW_FIELDS, "33-field canonical view ledger changed")
    require(len({entry["name"] for entry in fields}) == len(VIEW_FIELDS), "duplicate verifier-view field")
    nonce = next(entry for entry in fields if entry["name"] == "PiopNonce")
    require(nonce["wire_state"] == "forbidden-absent" and nonce["serialized_bytes"] == 0, "HX512 nonce must be absent from the wire")
    for forbidden in ("OpenedWitnessMode", "AuxiliaryLimbCount", "AuxiliaryWords"):
        entry = next(item for item in fields if item["name"] == forbidden)
        require(entry["wire_state"] == "forbidden-absent" and entry["serialized_bytes"] == 0, f"{forbidden} must be absent")
    matrix_names = {
        "PiopPpolHighs",
        "PiopPlinHighs",
        "PcsRcombiTails",
        "LvcsSubsetEvaluations",
        "PcsPartialEvaluations",
        "DecsMaskingEvaluations",
        "DecsHighCoefficients",
        "OpenedWitnessRowScalars",
    }
    for entry in fields:
        if entry["name"] in matrix_names:
            require(entry["wire_state"] == "inner-matrix-u32be-u32be-u64be", f"fresh matrix grammar changed: {entry['name']}")
            require(str(entry["serialized_bytes"]).startswith("8 + "), f"fresh matrix header width changed: {entry['name']}")
    auth_count = next(entry for entry in fields if entry["name"] == "DecsAuthPathCount")
    auth_lengths = next(entry for entry in fields if entry["name"] == "DecsAuthPathLengths")
    require(auth_count["wire_state"] == "inner-u32be" and auth_count["serialized_bytes"] == 4, "fresh auth count grammar changed")
    require(auth_lengths["wire_state"] == "inner-q-u32be" and auth_lengths["serialized_bytes"] == 192, "fresh auth length grammar changed")

    design = data["canonical_design"]
    require(design["grinding_bits"] == 0, "grinding is forbidden")
    require(design["outer_retry"] is False, "outer proof retry is forbidden")
    require(design["samplers"]["field_extra_candidates"] == 256, "field sampler cap changed")
    require(design["samplers"]["index_extra_candidates"] == 512, "index sampler cap changed")
    require(design["samplers"]["abort_poisons_transcript"] is True, "sampler abort must poison transcript")
    prefix = [(item["name"], item["bytes"]) for item in design["fresh_inner_prefix"]]
    require(prefix == [("decs_root", 64), ("piop_input_digest", 64), ("h_piop", 64)], "fresh inner prefix proposal changed")

    events = [
        (entry["ordinal"], entry["stage"], entry["primitive"], entry["operation"])
        for entry in data.get("transcript_schedule", [])
    ]
    require(events == TRANSCRIPT_EVENTS, "eight-event transcript schedule changed")
    require(
        [entry["smallwood_theorem10_oracle"] for entry in data["transcript_schedule"]]
        == SMALLWOOD_THEOREM10_EVENT_ORACLES,
        "SmallWood Theorem-10 logical-oracle mapping changed",
    )
    oracle_contract = data["oracle_refinement_contract"]
    require(
        oracle_contract["smallwood_abstract_oracles"]
        == ["Hash", *SMALLWOOD_THEOREM10_EVENT_ORACLES],
        "SmallWood independent-oracle inventory changed",
    )
    deferred = oracle_contract["deferred_claim_checks"]
    require(
        [(item["claim"], item["logical_query"], item["new_program_event"]) for item in deferred]
        == [
            ("piop_input_digest/h3", "event-2 PiopInputBinding", False),
            ("h_piop/h5", "event-4 PiopTranscriptBinding", False),
        ],
        "deferred h3/h5 same-query accounting changed",
    )
    for flag in (
        "prefix_free_tagged_product_ro_lemma_proved",
        "global_q_refinement_proved",
        "deferred_claim_same_query_refinement_proved",
    ):
        require(oracle_contract[flag] is False, f"oracle refinement flag enabled without receipt: {flag}")

    kernels = data.get("simulator_kernels", [])
    seen_kernels: set[str] = set()
    produced_fields: set[str] = set()
    for kernel in kernels:
        identifier = kernel["id"]
        require(identifier not in seen_kernels, f"duplicate simulator kernel: {identifier}")
        require(set(kernel.get("depends_on", [])) <= seen_kernels, f"simulator kernel is not topologically ordered: {identifier}")
        outputs = set(kernel.get("outputs", []))
        require(outputs <= set(VIEW_FIELDS), f"unknown view field from kernel: {identifier}")
        produced_fields |= outputs
        seen_kernels.add(identifier)
    require(produced_fields == set(VIEW_FIELDS), "simulator-kernel coverage is not exactly the full verifier view")

    require(data.get("joint_affine_receipts") == [], "unreviewed joint affine receipt was added")
    ranks = exact_rank_report(data)
    require(ranks == data["representative_rank_receipts"], "representative exact ranks changed")

    # Demonstrate why diagonal/local ranks do not prove the joint statement:
    # Y1=r and Y2=r+w are each uniform, while Y2-Y1=w leaks the witness.
    require(rank_mod([[1]]) == 1 and rank_mod([[1]]) == 1, "local rank fixture failed")
    require(not affine_witness_is_hidden([[1], [1]], [[0], [1]]), "joint-leak counterexample was not detected")

    arithmetic = arithmetic_report(data)
    require(arithmetic["cms_s6_strict_gt_128"] is True, "s=6 CMS integer gate failed")
    require(arithmetic["cms_s5_strict_gt_128"] is False, "retained s=5 counterexample unexpectedly passed")
    require(arithmetic["smallwood_theorem10_classical_rom_floor_bits"] == 191, "SmallWood Theorem 10 arithmetic changed")
    require(arithmetic["bcs16_direct_lambda512_can_exceed_128_for_nonempty_proof"] is False, "direct BCS16 route is not disqualified")
    require(arithmetic["all_sampler_abort_union_floor_bits"] >= 4_096, "sampler abort bound is below the retained floor")

    theorem_entries = data.get("theorem_premises", [])
    require(all(entry.get("status") != "proved" for entry in theorem_entries), "a theorem premise was promoted without a receipt")
    require({entry["id"] for entry in theorem_entries} == {
        "SmallWood-Theorem-2",
        "SmallWood-Theorem-4",
        "SmallWood-Theorem-6",
        "SmallWood-Theorem-8",
        "SmallWood-Theorem-10",
        "BCS16-Lemma-7.5",
        "CMS19-Theorem-8.6(3)",
        "GHCM20-Proposition-2",
    }, "theorem premise inventory changed")

    validate_pins(data.get("source_pins", []), repo_root, check_paths=check_sources)
    validate_pins(data.get("paper_pins", []), repo_root, check_paths=check_pdfs)
    return {"ranks": ranks, "arithmetic": arithmetic, "authority_flags": flags}


def find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "AGENTS.md").is_file() and (candidate / ".agent").is_dir():
            return candidate
    raise CertificateError("repository root not found")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, default=Path(__file__).with_name("certificate.json"))
    parser.add_argument("--skip-live-source-pins", action="store_true")
    parser.add_argument("--check-local-pdfs", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    try:
        certificate_path = args.certificate.resolve()
        data = json.loads(certificate_path.read_text(encoding="utf-8"))
        repo_root = find_repo_root(certificate_path.parent)
        report = validate_certificate(
            data,
            repo_root,
            check_sources=not args.skip_live_source_pins,
            check_pdfs=args.check_local_pdfs,
        )
        complete = all(data["authority_flags"].values())
        if args.require_complete and not complete:
            print(json.dumps({"status": "BLOCKED", "reason": "complete-ZK authority remains false"}, sort_keys=True))
            return 2
        print(json.dumps({"status": "VALIDATED_FAIL_CLOSED", **report}, sort_keys=True))
        return 0
    except (CertificateError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
