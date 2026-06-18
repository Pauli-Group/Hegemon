#!/usr/bin/env python3
"""Hegemon Poseidon2 degree-annihilation review helper.

This script is intentionally lightweight: it parses the checked-in Rust constants,
computes the attack-budget quantities relevant to ePrint 2026/1254, and writes a
stable JSON report for review.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONSTANTS_RS = ROOT / "circuits/transaction-core/src/constants.rs"
POSEIDON2_RS = ROOT / "circuits/transaction-core/src/poseidon2.rs"
POSEIDON2_CONSTANTS_RS = ROOT / "circuits/transaction-core/src/poseidon2_constants.rs"
REPORT_JSON = ROOT / "docs/crypto/poseidon2_degree_annihilation_report.json"

PAPER = {
    "url": "https://eprint.iacr.org/2026/1254.pdf",
    "title": "Top Gun: Degree Annihilation Attacks on Poseidon",
    "concrete_target": {
        "family": "reduced-round Poseidon / Poseidon-like zero-test challenges",
        "field": "KoalaBear",
        "sbox_degree": 3,
        "full_rounds": 6,
        "partial_rounds_solved": [7, 8],
        "output_constraints": 2,
    },
}


def strip_rust_int_suffixes(expr: str) -> str:
    expr = expr.replace("usize", "").replace("u128", "").replace("u64", "").replace("u32", "")
    return expr


def safe_eval_int(expr: str, names: dict[str, int]) -> int:
    expr = strip_rust_int_suffixes(expr)
    tree = ast.parse(expr, mode="eval")

    def eval_node(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return eval_node(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id not in names:
                raise ValueError(f"unknown constant {node.id} in expression {expr!r}")
            return names[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -eval_node(node.operand)
        if isinstance(node, ast.BinOp):
            left = eval_node(node.left)
            right = eval_node(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.FloorDiv) or isinstance(node.op, ast.Div):
                if left % right != 0:
                    raise ValueError(f"non-integral division in expression {expr!r}")
                return left // right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.RShift):
                return left >> right
        raise ValueError(f"unsupported expression {expr!r}")

    return eval_node(tree)


def parse_constants() -> dict[str, int]:
    text = CONSTANTS_RS.read_text()
    pattern = re.compile(r"pub const ([A-Z0-9_]+): [^=]+ = ([^;]+);")
    values: dict[str, int] = {}
    for name, expr in pattern.findall(text):
        if name.startswith("POSEIDON") or name == "FIELD_MODULUS":
            values[name] = safe_eval_int(expr.strip(), values)
    return values


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count_array_entries(name: str, source: str) -> int:
    marker = f"pub const {name}:"
    start = source.find(marker)
    if start == -1:
        raise ValueError(f"missing array {name}")
    body_start = source.find("= [", start)
    body_end = source.find("];", body_start)
    if body_start == -1 or body_end == -1:
        raise ValueError(f"could not parse array {name}")
    body = source[body_start:body_end]
    return len(re.findall(r"0x[0-9a-fA-F]+", body))


def cancellation_budget(alpha: int, initial_full_left: int) -> dict[str, int]:
    """Return coefficient counts for the first post-skip partial-round input.

    The paper notes that when RF=8 and alpha=3, two full rounds remaining before
    the first partial round make that coordinate degree 9. Cancelling down to
    degree <= alpha - 1 removes one effective alpha factor. Cancelling down to
    degree <= 1 is the stricter affine target used in the RF=6 two-partial
    construction. We report both.
    """

    degree = alpha**initial_full_left
    return {
        "input_degree_before_first_partial": degree,
        "cancel_to_alpha_minus_one_terms": max(0, degree - (alpha - 1)),
        "cancel_to_affine_terms": max(0, degree - 1),
    }


def build_report() -> dict[str, Any]:
    constants = parse_constants()
    source = POSEIDON2_CONSTANTS_RS.read_text()

    width = constants["POSEIDON2_WIDTH"]
    rate = constants["POSEIDON2_RATE"]
    capacity = constants["POSEIDON2_CAPACITY"]
    alpha = constants["POSEIDON2_SBOX_DEGREE"]
    external_rounds_total = constants["POSEIDON2_ROUNDS_F"]
    external_half = constants["POSEIDON2_EXTERNAL_ROUNDS"]
    internal_rounds = constants["POSEIDON2_INTERNAL_ROUNDS"]
    steps = constants["POSEIDON2_STEPS"]
    modulus = constants["FIELD_MODULUS"]
    field_bits = math.log2(modulus)
    digest_fields = rate
    digest_bits = digest_fields * field_bits
    digest_bytes = digest_fields * 8

    if count_array_entries("INTERNAL_ROUND_CONSTANTS", source) != internal_rounds:
        raise ValueError("Poseidon2 internal-round constant count does not match constants.rs")

    external_constant_entries = count_array_entries("EXTERNAL_ROUND_CONSTANTS", source)
    expected_external_entries = 2 * external_half * width
    if external_constant_entries != expected_external_entries:
        raise ValueError("Poseidon2 external-round constant shape does not match constants.rs")

    if capacity + rate != width:
        raise ValueError("Poseidon2 rate + capacity must equal width")
    if steps != 1 + external_rounds_total + internal_rounds:
        raise ValueError("Poseidon2 step count drifted")

    skipped_round_table = []
    for skipped_initial_full in range(external_half + 1):
        initial_full_left = external_half - skipped_initial_full
        exponent_without_annihilation = initial_full_left + internal_rounds + external_half
        budget = cancellation_budget(alpha, initial_full_left)
        skipped_round_table.append(
            {
                "skipped_initial_full_rounds_granted_to_attacker": skipped_initial_full,
                "initial_full_rounds_left": initial_full_left,
                "degree_exponent_without_partial_annihilation": exponent_without_annihilation,
                "restricted_univariate_degree_log2": exponent_without_annihilation
                * math.log2(alpha),
                **budget,
            }
        )

    conservative_skip = 2
    initial_full_left = external_half - conservative_skip
    base_exponent = initial_full_left + internal_rounds + external_half
    first_budget = cancellation_budget(alpha, initial_full_left)

    annihilation_table = []
    for annihilated_partials in range(0, 7):
        exponent = max(0, base_exponent - annihilated_partials)
        paper_style_controls = 0 if annihilated_partials == 0 else 1 + 2 * annihilated_partials
        if annihilated_partials == 0:
            one_factor_equations = 0
            affine_equations = 0
        else:
            one_factor_equations = (
                first_budget["cancel_to_alpha_minus_one_terms"]
                + (annihilated_partials - 1) * (alpha - 1)
            )
            affine_equations = (
                first_budget["cancel_to_affine_terms"]
                + (annihilated_partials - 1) * (alpha - 1)
            )
        annihilation_table.append(
            {
                "annihilated_partial_rounds": annihilated_partials,
                "degree_exponent_after_annihilation": exponent,
                "restricted_univariate_degree_log2": exponent * math.log2(alpha),
                "paper_style_control_variables": paper_style_controls,
                "one_factor_cancellation_equations": one_factor_equations,
                "affine_cancellation_equations": affine_equations,
                "one_factor_equation_gap_vs_paper_style_controls": max(
                    0, one_factor_equations - paper_style_controls
                ),
                "affine_equation_gap_vs_paper_style_controls": max(
                    0, affine_equations - paper_style_controls
                ),
            }
        )

    residual_output_constraints_after_cico2 = digest_fields - PAPER["concrete_target"]["output_constraints"]
    residual_cico2_bits = residual_output_constraints_after_cico2 * field_bits

    return {
        "schema": "hegemon.poseidon2_degree_annihilation.v1",
        "paper": PAPER,
        "source_files": {
            "constants_rs": str(CONSTANTS_RS.relative_to(ROOT)),
            "poseidon2_rs": str(POSEIDON2_RS.relative_to(ROOT)),
            "poseidon2_constants_rs": str(POSEIDON2_CONSTANTS_RS.relative_to(ROOT)),
            "constants_rs_sha256": sha256_hex(CONSTANTS_RS),
            "poseidon2_rs_sha256": sha256_hex(POSEIDON2_RS),
            "poseidon2_constants_rs_sha256": sha256_hex(POSEIDON2_CONSTANTS_RS),
        },
        "hegemon_poseidon2": {
            "field": "Goldilocks",
            "field_modulus": modulus,
            "field_bits": field_bits,
            "width": width,
            "rate": rate,
            "capacity": capacity,
            "sbox_degree": alpha,
            "initial_linear_layer": True,
            "initial_external_full_rounds": external_half,
            "internal_partial_rounds": internal_rounds,
            "final_external_full_rounds": external_half,
            "total_full_rounds": external_rounds_total,
            "total_steps_including_initial_linear": steps,
            "digest_field_elements": digest_fields,
            "digest_bytes": digest_bytes,
        },
        "security_budget": {
            "digest_bits_from_field_limbs": digest_bits,
            "classical_collision_bits": digest_bits / 2.0,
            "quantum_collision_bits_bht": digest_bits / 3.0,
            "classical_preimage_bits": digest_bits,
            "quantum_preimage_bits_grover": digest_bits / 2.0,
        },
        "degree_budget_model": {
            "description": (
                "Attacker-favorable univariate degree model. It grants skipped initial full "
                "rounds and counts how many high-degree coefficients must be cancelled before "
                "the first remaining partial S-box. The conservative row used by the report "
                "grants two skipped initial full rounds even though Poseidon2's initial linear "
                "layer is designed to obstruct that exact skip."
            ),
            "skipped_round_table": skipped_round_table,
            "conservative_two_full_skip_annihilation_table": annihilation_table,
            "residual_output_constraints_after_reusing_cico2": residual_output_constraints_after_cico2,
            "residual_cico2_check_bits": residual_cico2_bits,
        },
        "local_judgment": {
            "status": "no_practical_break_found",
            "summary": (
                "The paper is a real review trigger, but its concrete reduced-round CICO-2 "
                "attacks do not transfer to Hegemon's full 6-limb Poseidon2-384 digest. Under "
                "a two-full-round skip grant, the first remaining partial input has degree "
                "49; reducing one effective alpha factor requires 43 coefficient cancellations "
                "before output constraints, far beyond the paper-style control budget. A "
                "CICO-2-style solver also leaves four Hegemon output limbs unchecked, adding "
                "about 256 bits of residual field constraints if handled by root filtering."
            ),
            "not_a_proof": (
                "This report is an engineering cryptanalysis note, not a formal lower bound. "
                "It should be handed to an external Poseidon/Poseidon2 reviewer for a full "
                "Groebner/resultant or dedicated algebraic-search assessment."
            ),
        },
    }


def write_report(report: dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def check_report(report: dict[str, Any]) -> None:
    params = report["hegemon_poseidon2"]
    if params["width"] != 12 or params["rate"] != 6 or params["capacity"] != 6:
        raise SystemExit("unexpected Hegemon Poseidon2 width/rate/capacity")
    if params["sbox_degree"] != 7:
        raise SystemExit("unexpected Hegemon Poseidon2 S-box degree")
    if params["total_full_rounds"] != 8 or params["internal_partial_rounds"] != 22:
        raise SystemExit("unexpected Hegemon Poseidon2 round count")
    if report["security_budget"]["quantum_collision_bits_bht"] < 127.9:
        raise SystemExit("digest quantum-collision budget fell below 128-bit target")

    table = report["degree_budget_model"]["conservative_two_full_skip_annihilation_table"]
    first = table[1]
    if first["one_factor_cancellation_equations"] < 43:
        raise SystemExit("first partial cancellation budget unexpectedly weakened")
    if report["degree_budget_model"]["residual_cico2_check_bits"] < 250:
        raise SystemExit("CICO-2 residual-output budget unexpectedly weakened")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the generated report")
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="compute and print the report without updating docs/crypto",
    )
    args = parser.parse_args()

    report = build_report()
    if not args.no_write:
        write_report(report)
    if args.check:
        check_report(report)
    print(json.dumps(report["local_judgment"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
