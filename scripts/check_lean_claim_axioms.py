#!/usr/bin/env python3
"""Audit Lean axiom dependencies for theorem-backed security claims."""

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


def run_lean_axiom_query(root: Path, theorems: list[str]) -> str:
    lean_root = root / "formal" / "lean"
    query = "import Hegemon\n" + "".join(f"#print axioms {name}\n" for name in theorems)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".lean", prefix="hegemon-claim-axioms-", delete=False
    ) as handle:
        handle.write(query)
        query_path = Path(handle.name)

    env = os.environ.copy()
    elan_bin = Path.home() / ".elan" / "bin"
    if elan_bin.is_dir():
        env["PATH"] = f"{elan_bin}:{env.get('PATH', '')}"

    try:
        result = subprocess.run(
            ["lake", "env", "lean", str(query_path)],
            cwd=lean_root,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        query_path.unlink(missing_ok=True)

    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def parse_axiom_output(output: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    current_name: str | None = None
    current_body = ""

    def flush_current() -> None:
        nonlocal current_name, current_body
        if current_name is None:
            return
        body = current_body.strip()
        if not body.startswith("[") or not body.endswith("]"):
            raise SystemExit(f"could not parse Lean axiom output for {current_name}: {body}")
        records[current_name] = [
            item.strip() for item in body[1:-1].split(",") if item.strip()
        ]
        current_name = None
        current_body = ""

    for line in output.splitlines():
        starts_record = line.startswith("'") and (
            "depends on axioms:" in line or "does not depend on any axioms" in line
        )
        if starts_record:
            flush_current()
            name = line.split("'", 2)[1]
            if "does not depend on any axioms" in line:
                records[name] = []
                continue
            current_name = name
            current_body = line.split("depends on axioms:", 1)[1].strip()
        elif current_name is not None:
            current_body += " " + line.strip()
    flush_current()
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
    args = parser.parse_args()

    theorems = load_claimed_theorems(args.claims)
    output = run_lean_axiom_query(root, theorems)
    theorem_axioms = parse_axiom_output(output)
    missing = sorted(set(theorems) - set(theorem_axioms))
    if missing:
        raise SystemExit(f"Lean did not report axiom dependencies for: {missing}")

    waivers = json.loads(args.waivers.read_text())
    report = audit_axioms(theorem_axioms, waivers)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
