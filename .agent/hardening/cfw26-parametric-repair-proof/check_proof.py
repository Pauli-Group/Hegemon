#!/usr/bin/env python3
"""Fail-closed checker for the CFW26 parametric theorem-delta artifact."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import cfw26_parametric_repair as repair


ROOT = Path(__file__).resolve().parent
ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "ast",
    "cfw26_parametric_repair",
    "collections",
    "fractions",
    "hashlib",
    "itertools",
    "json",
    "math",
    "pathlib",
    "typing",
    "unittest",
}
EXPECTED_SOURCE_PAGES = {
    *(f"source-pages/cfw26-{page}.png" for page in range(26, 43)),
    *(f"source-pages/cfw26-{page}.png" for page in range(66, 72)),
    *(f"source-pages/acfy25-whir-{page}.png" for page in range(70, 74)),
}
ALLOWED_TRUE_AUTHORITY = {
    "parametric_construction_well_typed_for_nonzero_c",
    "perfect_completeness_proved",
    "outer_transcript_affine_bijection_proved_in_odd_characteristic",
    "value_slice_uniform_for_nonzero_c",
    "formal_nonadaptive_whole_hvzk_conditional_on_encoding_zk",
}
ALLOWED_TRUE_ADMISSION = {
    "all_source_dependencies_read",
    "typed_parametric_restatement",
    "repaired_perfect_completeness",
    "formal_nonadaptive_hvzk_conditional_on_encoding_zk",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_json(relative: str) -> Any:
    try:
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {relative}: {error}")


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_dependency_boundary() -> None:
    for relative in (
        "cfw26_parametric_repair.py",
        "test_cfw26_parametric_repair.py",
        "check_proof.py",
    ):
        path = ROOT / relative
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            forbidden = roots - ALLOWED_IMPORT_ROOTS
            if forbidden:
                fail(f"non-standard dependency in {relative}: {sorted(forbidden)}")


def check_sources() -> None:
    source_map = load_json("SOURCE_DEPENDENCY_MAP.json")
    if source_map.get("schema") != (
        "hegemon.cfw26-parametric-repair-proof.source-dependency-map.v1"
    ):
        fail("source dependency schema")
    dependencies = source_map.get("dependencies", [])
    if len(dependencies) < 17 or any(item.get("read") is not True for item in dependencies):
        fail("source dependency closure")
    coverage = source_map.get("coverage", {})
    if coverage.get("all_listed_dependencies_read") is not True:
        fail("listed dependencies not all read")
    if coverage.get("external_acfy25_appendix_read") is not True:
        fail("ACFY25 Appendix A dependency missing")
    if coverage.get("author_erratum_or_repair_selected") is not False:
        fail("unsupported author repair selection")

    sources = source_map.get("sources", {})
    expected = {
        "cfw26": (
            972446,
            "be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd",
            "927135c9820fe0f5344601074837f3742b310cb16d8031ec2e9753900b458b72d0c3fabfc6183de1cee54ee6ecbdf378962b3f93211427f52e539b7d5204167d",
        ),
        "acfy25_whir": (
            1271126,
            "0b5fceaa077ee4ff3dc3cbe1ef9d68ec67761a2778c4c7a6caf7bde8dd5b1c3eef42c9c9373303bba997726e836620b508fd470b926475c86c6736fa272d58d9",
            "52212249956b2827e481b98fc20ff88514516e63d0e13eb7a092dea0eb23f15c76aa6193b5b0ade182bd3be0154969816b3e63aaecf39d819d0885cd6f532f44",
        ),
    }
    for source_id, (pdf_bytes, pdf_digest, text_digest) in expected.items():
        record = sources.get(source_id, {})
        if record.get("pdf_bytes") != pdf_bytes or record.get("pdf_sha512") != pdf_digest:
            fail(f"pinned PDF identity: {source_id}")
        if record.get("text_sha512") != text_digest:
            fail(f"pinned extracted-text identity: {source_id}")
        for kind, digest_key, bytes_key in (
            ("pdf", "pdf_sha512", "pdf_bytes"),
            ("text", "text_sha512", "text_bytes"),
        ):
            path = Path(record.get(f"{kind}_path", ""))
            if path.is_file():
                if path.stat().st_size != record.get(bytes_key) or sha512(path) != record.get(
                    digest_key
                ):
                    fail(f"available {source_id} {kind} differs from pin")

    actual_pages = {
        path.relative_to(ROOT).as_posix() for path in (ROOT / "source-pages").glob("*.png")
    }
    if actual_pages != EXPECTED_SOURCE_PAGES:
        fail(f"retained source-page set drift: {sorted(actual_pages ^ EXPECTED_SOURCE_PAGES)}")


def check_report() -> dict[str, Any]:
    retained = load_json("experiment_report.json")
    live = repair.build_report()
    if retained != live:
        fail("retained report is not reproducible")
    try:
        repair.self_check(live)
    except AssertionError as error:
        fail(f"executable invariant: {error}")
    authority = live.get("authority", {})
    for key, value in authority.items():
        if key in ALLOWED_TRUE_AUTHORITY:
            if value is not True:
                fail(f"bounded local lemma lost: {key}")
        elif value is not False:
            fail(f"authority escaped fail-closed state: {key}")
    counterexample = live["initial_rbr_degree_counterexample"]
    if not counterexample["downstream_target_relation_has_witness_on_accepting_event"]:
        fail("RBR counterexample lost its full downstream path")
    return live


def check_theorem_ledger() -> None:
    ledger = load_json("THEOREM_DELTA_LEDGER.json")
    if ledger.get("schema") != (
        "hegemon.cfw26-parametric-repair-proof.theorem-delta-ledger.v1"
    ):
        fail("theorem-delta ledger schema")
    obligations = ledger.get("obligations", [])
    if len(obligations) < 24:
        fail("theorem-delta ledger is incomplete")
    by_id = {item.get("id"): item for item in obligations}
    if len(by_id) != len(obligations):
        fail("duplicate theorem obligation")
    if any(item.get("closes_entire_theorem") is not False for item in obligations):
        fail("individual obligation promoted to full theorem")
    expected_statuses = {
        "printed-endpoint-state": "falsified_and_repaired",
        "perfect-completeness": "closed_for_independent_restatement",
        "whole-formal-hvzk": "conditionally_closed_nonadaptive",
        "adaptive-query-hvzk": "not_implied_and_open",
        "initial-rbr-coordinate": "falsified_under_printed_premises",
        "full-corrected-rbr": "open",
        "fiat-shamir-qrom": "absent",
        "pq128-composition": "absent",
        "implementation-refinement": "absent",
    }
    for obligation, status in expected_statuses.items():
        if by_id.get(obligation, {}).get("status") != status:
            fail(f"theorem obligation drift: {obligation}")
    admission = ledger.get("admission", {})
    for key, value in admission.items():
        if key in ALLOWED_TRUE_ADMISSION:
            if value is not True:
                fail(f"bounded admission result lost: {key}")
        elif value is not False:
            fail(f"admission escaped fail-closed state: {key}")


def check_document() -> None:
    document = (ROOT / "THEOREM_DELTA.md").read_text(encoding="utf-8")
    required = (
        "It does not inherit Theorem 11.3.",
        "The exact repair is",
        "## Entire repaired construction C11.4(c)",
        "## Complete factor-c occurrence audit",
        "The complete structural-two audit is:",
        "## Perfect completeness of C11.4(c)",
        "## Whole-view HVZK for the formal nonadaptive class",
        "for every message and every fixed set of at most\ntwo queries",
        "This is a complete accepting reduction path",
        "Full corrected RBR state/extractor | open",
        "Complete zero knowledge for Hegemon | false",
        "Production authority | false",
    )
    for phrase in required:
        if phrase not in document:
            fail(f"theorem-delta claim boundary missing: {phrase!r}")


def check_execplan() -> None:
    plan = (ROOT / "EXECPLAN.md").read_text(encoding="utf-8")
    for heading in (
        "## Progress",
        "## Surprises & Discoveries",
        "## Decision Log",
        "## Outcomes & Retrospective",
        "## Validation and Acceptance",
    ):
        if heading not in plan:
            fail(f"ExecPlan section missing: {heading}")


def check_manifest() -> None:
    manifest = load_json("ARTIFACT_MANIFEST.json")
    if manifest.get("schema") != (
        "hegemon.cfw26-parametric-repair-proof.artifact-manifest.v1"
    ):
        fail("artifact manifest schema")
    authority = manifest.get("authority", {})
    for key, value in authority.items():
        if key in ALLOWED_TRUE_AUTHORITY:
            if value is not True:
                fail(f"manifest bounded lemma lost: {key}")
        elif value is not False:
            fail(f"manifest authority escaped: {key}")
    files = manifest.get("files", {})
    required_files = {
        "EXECPLAN.md",
        "SOURCE_DEPENDENCY_MAP.json",
        "THEOREM_DELTA.md",
        "THEOREM_DELTA_LEDGER.json",
        "cfw26_parametric_repair.py",
        "test_cfw26_parametric_repair.py",
        "experiment_report.json",
        "check_proof.py",
        *EXPECTED_SOURCE_PAGES,
    }
    if set(files) != required_files:
        fail(f"manifest file set drift: {sorted(set(files) ^ required_files)}")
    for relative, expected_digest in files.items():
        path = ROOT / relative
        if not path.is_file() or sha512(path) != expected_digest:
            fail(f"artifact hash drift: {relative}")


def main() -> int:
    check_dependency_boundary()
    check_sources()
    report = check_report()
    check_theorem_ledger()
    check_document()
    check_execplan()
    check_manifest()
    counterexample = report["initial_rbr_degree_counterexample"]
    outer = report["outer_transcript"]
    print(
        "PASS cfw26-parametric-repair-proof "
        f"tests=22 c_values={report['factor_c']['total_coefficients_checked']} "
        f"outer_rank_cases={outer['odd_characteristic_case_count']} "
        f"rbr_accept={counterexample['acceptance_probability']['decimal']:.10f} "
        "formal_nonadaptive_hvzk=conditional full_rbr=false adaptive_hvzk=false "
        "theorem_inherited=false complete_zk=false qrom=false pq128=false production=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
