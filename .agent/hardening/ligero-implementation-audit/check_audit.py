#!/usr/bin/env python3
"""Fail-closed checker for the Ligero implementation audit package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ligero_implementation_audit import (
    CRITICAL_BLOCKERS,
    LEDGER_PATH,
    LIBIOP_ROOT,
    build_ledger,
    canonical_json,
    sha512_file,
)


def validation_errors(ledger: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if ledger.get("schema") != "hegemon-ligero-implementation-audit-v1":
        errors.append("unexpected schema")

    authority = ledger.get("authority", {})
    if not authority or any(value is not False for value in authority.values()):
        errors.append("every authority gate must be present and false")

    executable = ledger.get("pinned_executable", {})
    if executable.get("selected_source_lines") != 6152:
        errors.append("pinned protocol/BCS/test source surface must remain 6152 logical lines")
    if executable.get("matches_exact_2022_section_4_7") is not False:
        errors.append("libiop must remain protocol-mismatched")
    inheritance = executable.get("theorem_inheritance", {})
    for key in (
        "lemma_4_15_simulator_applies",
        "theorem_4_7_identical_view_applies",
        "section_5_2_rbr_applies",
    ):
        if inheritance.get(key) is not False:
            errors.append(f"theorem inheritance must remain false: {key}")
    zk = executable.get("zero_knowledge", {})
    if zk.get("complete_zk_established") is not False:
        errors.append("complete executable ZK must remain false")
    if zk.get("encoding_independence") != 3:
        errors.append("pinned source must record encoding_independence=3")
    if zk.get("solved_query_bound_forwarded_to_mask_sampler") is not False:
        errors.append("solved query bound is not forwarded to the mask sampler")

    primary = ledger.get("primary_protocol", {})
    optimized = primary.get("optimized_profile_caveat", {})
    if optimized.get("printed_theorem_4_7_premise_satisfied") is not False:
        errors.append("optimized e=k,n=3k profile cannot satisfy printed Theorem 4.7 premise")
    if optimized.get("eligible_for_cms_without_new_rbr_proof") is not False:
        errors.append("optimized profile must not inherit RBR")

    relation = ledger.get("exact_relation", {})
    if relation.get("frozen") is not False:
        errors.append("relation must remain unfrozen")
    for key in (
        "field",
        "constraints_m",
        "variables_n",
        "matrix_nonzeros",
        "relation_manifest_sha512",
        "relation_certificate_sha512",
    ):
        if relation.get(key) is not None:
            errors.append(f"provisional relation value must remain null: {key}")
    stable = relation.get("stable_interface_only", {})
    if stable.get("public_bits_lsb_first") != 9704:
        errors.append("stable public interface must be 9704 bits")
    if stable.get("private_transport_bits") != 88000:
        errors.append("stable private transport must be 88000 bits")

    wire = ledger.get("executable_wire_and_size", {})
    for key in (
        "proof_bytes",
        "proof_bytes_lower_bound",
        "proof_bytes_upper_bound",
        "retained_proof_path",
    ):
        if wire.get(key) is not None:
            errors.append(f"unmeasured proof field must remain null: {key}")
    for key in (
        "reported_size_is_serialized_wire",
        "canonical_bounded_parser",
        "exact_consume_and_trailing_byte_rejection",
        "malformed_shape_safety",
        "round_trip_test_for_binary_field_blake2b_ligero",
    ):
        if wire.get(key) is not False:
            errors.append(f"wire gate must remain false: {key}")

    transcript = ledger.get("hash_and_transcript", {})
    if transcript.get("cms_modified_chain", {}).get("implemented") is not False:
        errors.append("CMS modified BCS chain must remain unimplemented")
    for key in (
        "sha512_available",
        "shake_available",
        "exact_hegemon_domain_framing",
        "statement_relation_context_bound_before_first_challenge",
        "canonical_cross_platform_transcript",
    ):
        if transcript.get(key) is not False:
            errors.append(f"transcript gate must remain false: {key}")

    composition = ledger.get("qrom_and_zk_composition", {})
    paper_route = composition.get("paper_only_conditional_route", {})
    if paper_route.get("executable_composition_established") is not False:
        errors.append("paper-only CMS route must not become executable authority")
    if paper_route.get("composed_security_claim") is not False:
        errors.append("paper-only CMS route must not make a composed-security claim")
    if paper_route.get("optimized_section_5_3_route_included") is not False:
        errors.append("optimized Section 5.3 profile must remain outside the CMS route")
    for key in (
        "underlying_whole_iop_rbr",
        "stronger_rbr_for_original_bcs_chain",
        "exact_total_iop_proof_length_p_bits",
        "exact_random_oracle_output_lambda_bits",
        "augmented_qrom_query_budget",
        "base_game_arity",
        "iop_soundness_advantage",
        "pcs_binding_advantage",
        "pcs_hiding_advantage",
        "fiat_shamir_advantage",
        "concrete_hash_to_qro_advantage",
        "grinding_advantage",
        "rng_failure_advantage",
        "retry_abort_advantage",
        "lifetime_union_advantage",
        "composed_advantage",
        "composed_security_bits",
    ):
        if composition.get(key) is not None:
            errors.append(f"uninstantiated composition field must remain null: {key}")
    for key in (
        "cms_theorem_8_6_applicable",
        "custom_pow_composed",
        "complete_noninteractive_zero_knowledge",
    ):
        if composition.get(key) is not False:
            errors.append(f"composition gate must remain false: {key}")

    blockers = ledger.get("critical_blockers")
    if blockers != CRITICAL_BLOCKERS:
        errors.append("critical blocker list changed or is incomplete")

    verdict = ledger.get("verdict", {})
    if verdict.get("implementation_ready") is not False:
        errors.append("implementation_ready must remain false")
    if verdict.get("backup_qualified") is not False:
        errors.append("backup_qualified must remain false")
    if verdict.get("result") != "DISQUALIFIED":
        errors.append("verdict must remain DISQUALIFIED")

    return errors


def verify_local_sources(*, require: bool) -> list[str]:
    errors: list[str] = []
    expected = build_ledger()["pinned_executable"]["selected_source_map"]
    if not LIBIOP_ROOT.is_dir():
        return [f"missing pinned libiop source root: {LIBIOP_ROOT}"] if require else []
    for entry in expected:
        path = LIBIOP_ROOT / entry["path"]
        if not path.is_file():
            errors.append(f"missing pinned source: {path}")
            continue
        with path.open("rb") as handle:
            lines = sum(1 for _ in handle)
        if lines != entry["lines"]:
            errors.append(f"line count mismatch: {entry['path']}")
        if sha512_file(path) != entry["sha512"]:
            errors.append(f"SHA-512 mismatch: {entry['path']}")
    return errors


def verify_local_pdfs(*, require: bool) -> list[str]:
    errors: list[str] = []
    for entry in build_ledger()["primary_sources"]:
        path = Path(entry["local_path"])
        if not path.is_file():
            if require:
                errors.append(f"missing primary PDF: {path}")
            continue
        if sha512_file(path) != entry["sha512"]:
            errors.append(f"primary PDF SHA-512 mismatch: {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument("--require-local-source", action="store_true")
    parser.add_argument("--require-local-pdfs", action="store_true")
    args = parser.parse_args()

    if not args.ledger.is_file():
        print(f"FAIL: missing ledger: {args.ledger}")
        return 1
    try:
        ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read ledger: {exc}")
        return 1

    errors = validation_errors(ledger)
    if args.ledger.resolve() == LEDGER_PATH.resolve():
        expected = canonical_json(build_ledger())
        actual = args.ledger.read_text(encoding="utf-8")
        if actual != expected:
            errors.append("ledger is not the canonical generator output")
    errors.extend(verify_local_sources(require=args.require_local_source))
    errors.extend(verify_local_pdfs(require=args.require_local_pdfs))

    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: Ligero implementation audit remains canonical and fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
