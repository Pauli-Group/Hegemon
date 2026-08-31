#!/usr/bin/env python3
"""Fail-closed source checker for the CFW26 Section 11 repair audit."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import cfw26_section11_repair_audit as audit


ROOT = Path(__file__).resolve().parent
ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "ast",
    "cfw26_section11_repair_audit",
    "collections",
    "dataclasses",
    "hashlib",
    "inspect",
    "itertools",
    "json",
    "math",
    "pathlib",
    "random",
    "typing",
    "unittest",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_json(relative: str) -> Any:
    path = ROOT / relative
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {relative}: {error}")


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_source_anchors() -> None:
    anchors = load_json("SOURCE_ANCHORS.json")
    if anchors.get("schema") != "hegemon.cfw26-section11-repair-audit.source-anchors.v1":
        fail("source-anchor schema")
    paper = anchors.get("paper", {})
    if paper.get("sha512") != (
        "be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd"
    ):
        fail("paper source identity")
    pdf = Path(paper.get("local_pdf", ""))
    if pdf.exists():
        if pdf.stat().st_size != paper.get("bytes") or sha512(pdf) != paper.get("sha512"):
            fail("available primary PDF does not match pinned identity")

    expected: dict[str, str] = {}
    for entry in anchors.get("anchors", []):
        if "rendered_file" in entry:
            expected[entry["rendered_file"]] = entry["rendered_sha512"]
        for path, digest in zip(
            entry.get("rendered_files", []), entry.get("rendered_sha512", [])
        ):
            expected[path] = digest
    expected.update(anchors.get("unused_rendered_context", {}))
    required_pages = {35, 38, 39, 40, 66, 67, 68, 69, 70, 71}
    actual_pages = {
        int(path.stem.split("-")[1]) for path in (ROOT / "rendered-source").glob("page-*.png")
    }
    if actual_pages != required_pages:
        fail(f"retained page set drift: {sorted(actual_pages)}")
    for relative, expected_digest in expected.items():
        path = ROOT / relative
        if not path.is_file() or sha512(path) != expected_digest:
            fail(f"rendered source drift: {relative}")


def check_dependency_boundary() -> None:
    for relative in (
        "cfw26_section11_repair_audit.py",
        "test_cfw26_section11_repair_audit.py",
    ):
        path = ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            forbidden = roots - ALLOWED_IMPORT_ROOTS
            if forbidden:
                fail(f"non-stdlib dependency in {relative}: {sorted(forbidden)}")
        source = path.read_text(encoding="utf-8")
        for forbidden_text in ("subprocess", "os.system", "cargo ", "lake ", "rustc "):
            if forbidden_text in source:
                fail(f"heavy/external execution seam in {relative}: {forbidden_text!r}")


def check_report() -> None:
    retained = load_json("experiment_report.json")
    live = audit.build_report()
    if retained != live:
        fail("retained experiment report is not reproducible from source")
    try:
        audit.self_check(live)
    except AssertionError as error:
        fail(f"executable audit invariant: {error}")


def check_premise_ledger() -> None:
    ledger = load_json("THEOREM_PREMISE_LEDGER.json")
    if ledger.get("schema") != "hegemon.cfw26-section11-repair-audit.theorem-premise-ledger.v1":
        fail("premise-ledger schema")
    branches = ledger.get("branches", {})
    printed = branches.get(audit.PRINTED, {})
    candidate = branches.get(audit.CANDIDATE, {})
    scaled = branches.get(audit.SCALED_TWO, {})
    if printed.get("well_typed") is not False or printed.get("honest_completeness") is not False:
        fail("printed branch was promoted")
    if candidate.get("well_typed") is not True or candidate.get("honest_completeness") is not True:
        fail("candidate local lemma missing")
    if candidate.get("full_theorem_status") != "unproved":
        fail("candidate theorem status escaped")
    if scaled.get("full_theorem_status") != "unproved":
        fail("scaled theorem status escaped")
    premises = ledger.get("premises", [])
    if len(premises) < 15 or any(item.get("closes_theorem") is not False for item in premises):
        fail("premise closure overclaimed")
    admission = ledger.get("admission", {})
    if admission.get("candidate_local_completeness_lemma") is not True:
        fail("local candidate lemma not retained")
    for key, value in admission.items():
        if key != "candidate_local_completeness_lemma" and value is not False:
            fail(f"admission flag escaped fail-closed state: {key}")


def check_document_claims() -> None:
    document = (ROOT / "AUDIT.md").read_text(encoding="utf-8")
    required = (
        "residual is `sum_M (1-z_M) S_M`",
        "289 of 384",
        "384/384 typed joint relations pass",
        "It cannot\nclose or inherit Theorem 11.3",
        "all theorem\ninheritance, complete-ZK, QROM, PQ128, and production flags remain false",
    )
    for phrase in required:
        if phrase not in document:
            fail(f"audit claim boundary missing: {phrase!r}")


def check_artifact_manifest() -> None:
    manifest = load_json("ARTIFACT_MANIFEST.json")
    if manifest.get("schema") != "hegemon.cfw26-section11-repair-audit.artifact-manifest.v1":
        fail("artifact-manifest schema")
    authority = manifest.get("authority", {})
    if authority.get("local_candidate_completeness_lemma") is not True:
        fail("manifest lost local lemma")
    for key, value in authority.items():
        if key != "local_candidate_completeness_lemma" and value is not False:
            fail(f"manifest authority escaped: {key}")
    files = manifest.get("files", {})
    if not files:
        fail("empty artifact manifest")
    for relative, expected_digest in files.items():
        path = ROOT / relative
        if not path.is_file() or sha512(path) != expected_digest:
            fail(f"artifact hash drift: {relative}")


def main() -> int:
    check_dependency_boundary()
    check_source_anchors()
    check_report()
    check_premise_ledger()
    check_document_claims()
    check_artifact_manifest()
    report = load_json("experiment_report.json")
    random_branches = report["randomized_r1cs"]["branches"]
    print(
        "PASS cfw26-section11-repair-audit "
        f"branch_trials={sum(item['trials'] for item in random_branches.values())} "
        f"candidate={random_branches[audit.CANDIDATE]['typed_relation_passes']}/384 "
        f"scaled={random_branches[audit.SCALED_TWO]['typed_relation_passes']}/384 "
        f"printed_typed={random_branches[audit.PRINTED]['typed_trials']} "
        "theorem_inherited=false complete_zk=false qrom=false production=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
