#!/usr/bin/env python3
"""Compile complete_zk.rs against exact field code while omitting in-flight PCS modules."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
LIB = REPO_ROOT / "prototypes/standalone-shake256-binius/strict-mixed-field/src/lib.rs"
COMPLETE_ZK = LIB.with_name("complete_zk.rs")
HARNESS = Path("/tmp/hegemon-e384-complete-zk-harness.rs")
TEST_BINARY = Path("/tmp/hegemon-e384-complete-zk-tests")
STATUS_BINARY = Path("/tmp/hegemon-e384-complete-zk-status")
OMITTED_MODULE_LINES = {
    "pub mod authenticated_basefold;",
    "pub mod mixed_basefold_pcs;",
    "pub mod complete_zk;",
}


def exact_field_harness(with_status_main: bool) -> str:
    source = LIB.read_text()
    present = {line.strip() for line in source.splitlines()} & OMITTED_MODULE_LINES
    required = {"pub mod authenticated_basefold;", "pub mod mixed_basefold_pcs;"}
    if not required.issubset(present):
        missing = ", ".join(sorted(required - present))
        raise RuntimeError(f"strict field source layout drifted; missing: {missing}")
    kept = [line for line in source.splitlines() if line.strip() not in OMITTED_MODULE_LINES]
    kept.append("")
    kept.append(f"#[path = {json.dumps(str(COMPLETE_ZK))}]")
    kept.append("pub mod complete_zk;")
    if with_status_main:
        kept.extend(
            (
                "",
                "fn main() {",
                "    let status = complete_zk::current_candidate_assessment();",
                '    println!("view_inventory_complete={}", status.view_inventory_complete);',
                '    println!("two_b128_endpoint_disqualified={}", status.two_b128_endpoint_disqualified);',
                '    println!("full_e384_endpoint_repair_specified={}", status.full_e384_endpoint_repair_specified);',
                '    println!("exact_raw_opening_matrix_exported={}", status.exact_raw_opening_matrix_exported);',
                '    println!("whole_proof_simulator_implemented={}", status.whole_proof_simulator_implemented);',
                '    println!("complete_zk={}", status.complete_zk);',
                '    println!("production_authorized={}", status.production_authorized);',
                "}",
            )
        )
    return "\n".join(kept) + "\n"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=REPO_ROOT, check=True)


def run_tests() -> None:
    HARNESS.write_text(exact_field_harness(with_status_main=False))
    run(
        [
            "rustc",
            "--edition",
            "2024",
            "-Dwarnings",
            "--test",
            str(HARNESS),
            "-o",
            str(TEST_BINARY),
        ]
    )
    run([str(TEST_BINARY), "--test-threads=1"])


def run_status() -> None:
    HARNESS.write_text(exact_field_harness(with_status_main=True))
    run(
        [
            "rustc",
            "--edition",
            "2024",
            "-Dwarnings",
            str(HARNESS),
            "-o",
            str(STATUS_BINARY),
        ]
    )
    run([str(STATUS_BINARY)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests-only", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    arguments = parser.parse_args()
    if arguments.tests_only and arguments.status_only:
        parser.error("--tests-only and --status-only are mutually exclusive")
    if not arguments.status_only:
        run_tests()
    if not arguments.tests_only:
        run_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
