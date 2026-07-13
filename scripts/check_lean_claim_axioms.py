#!/usr/bin/env python3
"""Audit Lean axiom dependencies for claims and closed assumption tracks."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_claimed_theorems(claims_path: Path) -> list[str]:
    claims = json.loads(claims_path.read_text())
    theorems: set[str] = set()
    for claim in claims.get("claims", []):
        if claim.get("claim_class") != "lean_theorem":
            continue
        for theorem in claim.get("lean_theorems", []):
            theorems.add(theorem)
    if not theorems:
        raise SystemExit("no Lean theorem-backed claims found")
    return sorted(theorems)


def load_closure_theorems(matrix_path: Path) -> list[str]:
    matrix = json.loads(matrix_path.read_text())
    closure = matrix.get("mechanized_assumption_closure")
    if not isinstance(closure, dict):
        raise SystemExit("matrix does not contain mechanized_assumption_closure")
    tracks = closure.get("tracks")
    if not isinstance(tracks, list) or not tracks:
        raise SystemExit("mechanized assumption closure must contain tracks")

    theorems: set[str] = set()
    for track in tracks:
        if not isinstance(track, dict):
            raise SystemExit("mechanized assumption closure track must be an object")
        track_id = track.get("id")
        status = track.get("status")
        if not isinstance(track_id, str) or not track_id:
            raise SystemExit("mechanized assumption closure track must have an id")
        if status not in {"open", "closed"}:
            raise SystemExit(f"track {track_id} has unsupported status {status!r}")
        names = track.get("lean_theorems", [])
        if not isinstance(names, list) or any(
            not isinstance(name, str) or not name for name in names
        ):
            raise SystemExit(f"track {track_id} has malformed lean_theorems")
        if status == "closed" and not names:
            raise SystemExit(f"closed track {track_id} has no Lean theorem identities")
        if status == "open" and names:
            raise SystemExit(f"open track {track_id} must not claim closure theorems")
        theorems.update(names)

    if not theorems:
        raise SystemExit("no closed-track Lean theorems found")
    return sorted(theorems)


def audited_theorem_union(
    claimed_theorems: list[str], closure_theorems: list[str]
) -> list[str]:
    claimed = set(claimed_theorems)
    closure = set(closure_theorems)
    missing = sorted(closure - claimed)
    if missing:
        raise SystemExit(
            "closed-track Lean theorems are missing from formal security claims: "
            f"{missing}"
        )
    return sorted(claimed | closure)


def run_lean_axiom_query(
    root: Path, theorems: list[str], module: str = "Hegemon"
) -> dict[str, list[str]]:
    lean_root = root / "formal" / "lean"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="hegemon-claim-axioms-", delete=False
    ) as handle:
        handle.write("\n".join(theorems))
        handle.write("\n")
        theorem_list_path = Path(handle.name)

    env = os.environ.copy()
    elan_bin = Path.home() / ".elan" / "bin"
    if elan_bin.is_dir():
        env["PATH"] = f"{elan_bin}:{env.get('PATH', '')}"

    try:
        result = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "-R",
                str(root),
                "--run",
                str(root / "scripts" / "lean_axiom_audit.lean"),
                str(theorem_list_path),
                module,
            ],
            cwd=lean_root,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        theorem_list_path.unlink(missing_ok=True)

    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return parse_axiom_json(result.stdout)


def parse_axiom_json(output: str) -> dict[str, list[str]]:
    try:
        raw_records = json.loads(output)
    except json.JSONDecodeError as error:
        raise SystemExit(f"could not parse trusted Lean axiom JSON: {error}") from error
    if not isinstance(raw_records, list):
        raise SystemExit("trusted Lean axiom output must be a JSON array")

    records: dict[str, list[str]] = {}
    for record in raw_records:
        if not isinstance(record, dict) or set(record) != {"theorem", "axioms"}:
            raise SystemExit("trusted Lean axiom record has an invalid shape")
        theorem = record["theorem"]
        axioms = record["axioms"]
        if not isinstance(theorem, str) or not theorem:
            raise SystemExit("trusted Lean axiom record has an invalid theorem name")
        if theorem in records:
            raise SystemExit(f"trusted Lean axiom output repeats theorem {theorem}")
        if not isinstance(axioms, list) or any(
            not isinstance(axiom, str) or not axiom for axiom in axioms
        ):
            raise SystemExit(f"trusted Lean axiom record for {theorem} has invalid axioms")
        records[theorem] = axioms
    return records


def compile_families(raw_families: list[dict]) -> list[dict]:
    today = dt.date.today()
    families = []
    for family in raw_families:
        expires_on = dt.date.fromisoformat(family["expires_on"])
        expired = expires_on < today
        families.append(
            {
                **family,
                "expired": expired,
                "regex": re.compile(family["axiom_regex"]),
            }
        )
    return families


def audit_axioms(theorem_axioms: dict[str, list[str]], waivers: dict) -> dict:
    allowed_kernel_axioms = set(waivers.get("allowed_kernel_axioms", []))
    families = compile_families(waivers.get("temporary_axiom_families", []))

    kernel_counts: Counter[str] = Counter()
    family_axioms: dict[str, set[str]] = {family["family"]: set() for family in families}
    family_theorems: dict[str, set[str]] = {family["family"]: set() for family in families}
    unwaived = []

    for theorem, axioms in theorem_axioms.items():
        for axiom in axioms:
            if axiom in allowed_kernel_axioms:
                kernel_counts[axiom] += 1
                continue
            matching_family = next(
                (family for family in families if family["regex"].match(axiom)), None
            )
            if matching_family is not None:
                family_axioms[matching_family["family"]].add(axiom)
                family_theorems[matching_family["family"]].add(theorem)
                continue
            unwaived.append({"theorem": theorem, "axiom": axiom})

    family_summaries = []
    budget_violations = []
    for family in families:
        name = family["family"]
        theorem_count = len(family_theorems[name])
        unique_axioms = len(family_axioms[name])
        summary = {
            "family": name,
            "theorems": theorem_count,
            "unique_axioms": unique_axioms,
            "max_theorems": family["max_theorems"],
            "max_unique_axioms": family["max_unique_axioms"],
            "expires_on": family["expires_on"],
            "expired": family["expired"],
        }
        family_summaries.append(summary)
        if family["expired"]:
            budget_violations.append({"family": name, "reason": "waiver expired"})
        if theorem_count > family["max_theorems"]:
            budget_violations.append(
                {
                    "family": name,
                    "reason": "theorem count exceeds waiver budget",
                    "actual": theorem_count,
                    "max": family["max_theorems"],
                }
            )
        if unique_axioms > family["max_unique_axioms"]:
            budget_violations.append(
                {
                    "family": name,
                    "reason": "unique axiom count exceeds waiver budget",
                    "actual": unique_axioms,
                    "max": family["max_unique_axioms"],
                }
            )

    theorem_count = len(theorem_axioms)
    axiom_free = sum(1 for axioms in theorem_axioms.values() if not axioms)
    native_or_temporary = set()
    for theorem_set in family_theorems.values():
        native_or_temporary.update(theorem_set)

    report = {
        "passed": not unwaived and not budget_violations,
        "theorems": theorem_count,
        "axiom_free_theorems": axiom_free,
        "axiom_dependent_theorems": theorem_count - axiom_free,
        "kernel_axiom_dependencies": dict(sorted(kernel_counts.items())),
        "temporary_axiom_families": family_summaries,
        "temporary_axiom_theorems": len(native_or_temporary),
        "unwaived_axiom_dependencies": unwaived,
        "budget_violations": budget_violations,
    }
    return report


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--claims",
        type=Path,
        default=root / "config" / "formal-security-claims.json",
        help="formal security claims JSON path",
    )
    parser.add_argument(
        "--waivers",
        type=Path,
        default=root / "config" / "lean-axiom-waivers.json",
        help="Lean axiom waiver policy JSON path",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=root / "config" / "highest-standard-formal-verification-matrix.json",
        help="highest-standard formal verification matrix JSON path",
    )
    args = parser.parse_args()

    claimed_theorems = load_claimed_theorems(args.claims)
    closure_theorems = load_closure_theorems(args.matrix)
    theorems = audited_theorem_union(claimed_theorems, closure_theorems)
    theorem_axioms = run_lean_axiom_query(root, theorems)
    missing = sorted(set(theorems) - set(theorem_axioms))
    if missing:
        raise SystemExit(f"Lean did not report axiom dependencies for: {missing}")

    waivers = json.loads(args.waivers.read_text())
    report = audit_axioms(theorem_axioms, waivers)
    report["claimed_theorems"] = len(claimed_theorems)
    report["closed_track_theorems"] = len(closure_theorems)
    report["closed_track_theorems_missing_from_claims"] = []
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
