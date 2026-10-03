#!/usr/bin/env python3
"""Prepare three source-pinned mathematical review wrappers, not release authority.

Run only after the coordinator freezes the final S/P/A/C objects and audits.
Every wrapper is validated by the frozen source-owned artifact checker before
any output directory is created. No Lean, prover, lifecycle command, contract
installation, or execution authentication occurs here. A failed write retains
its partial create-only directory; retry under a new destination after review.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "scripts"))
import check_smallwood_poseidon2_v8_smza_artifacts as checker

CHECKER_SHA256 = "e1dcb73896b1519c89a05a31eb4aa21c31fd92183c1f3e4637be3bf131482447"
BUILD = Path(".agent/prod-closure-2026-09-19/current-compiler/build")
GATES = (
    ("accepted_verifier_soundness", ("s",)),
    ("adaptive_whole_view_privacy", ("p",)),
    ("relation_and_ledger_composition", ("a", "c")),
)


def repository_path(repo: Path, value: Path | str) -> Path:
    """Normalize neither aliases nor symlinks into apparently valid evidence."""
    value = str(value)
    path = Path(value)
    if path.is_absolute():
        try:
            relative = path.relative_to(repo)
        except ValueError as error:
            raise checker.EvidenceError("path is outside repository") from error
        checker.require(str(repo / relative) == value, "noncanonical absolute path")
    else:
        relative = path
        checker.require(relative.as_posix() == value, "noncanonical relative path")
    checker.require(bool(relative.parts) and "\\" not in value and
                    all(part not in ("", ".", "..") for part in value.split("/")[int(path.is_absolute()):]),
                    "normalized repository-relative path required")
    current = repo
    checker.require(not current.is_symlink(), "symlink repository")
    for part in relative.parts:
        current /= part
        checker.require(not current.is_symlink(), "symlink path forbidden")
    return current


def pin(repo: Path, value: Path | str) -> tuple[dict[str, Any], bytes]:
    path = repository_path(repo, value)
    raw = checker.read(path, 128 * 1024**2)
    return {"path": path.relative_to(repo).as_posix(), "bytes": len(raw),
            "sha512": checker.digest(raw)}, raw


def endpoint_record(repo: Path, module: str, theorem: str,
                    compile_receipt: Path, body_audit: Path) -> dict[str, Any]:
    compile_pin, raw = pin(repo, compile_receipt)
    receipt = checker.object_json(raw)
    checker.require(receipt.get("module") == module, "compile receipt names the wrong endpoint")
    source_pin, _ = pin(repo, receipt["source"])
    # The final endpoint must be the current compiler's canonical object,
    # never a historical or diagnostic object's matching filename.
    object_pin, _ = pin(repo, BUILD / (module + ".olean"))
    audit_pin, _ = pin(repo, body_audit)
    return {"module": module, "root": "HegemonCrypto.SmallWood." + module + "." + theorem,
            "source": source_pin, "object": object_pin,
            "compile_receipt": compile_pin, "body_audit": audit_pin}


def build(output: Path, receipts: dict[str, tuple[Path, Path]], *, repo: Path = REPO) -> dict[str, Any]:
    checker.require(set(receipts) == {"s", "p", "a", "c"}, "exact S/P/A/C receipt inputs required")
    checker_source = Path(checker.__file__).resolve()
    checker.require(checker_source == REPO / "scripts/check_smallwood_poseidon2_v8_smza_artifacts.py" and
                    checker.digest(checker.read(checker_source), "sha256") == CHECKER_SHA256,
                    "source-owned checker differs from frozen reviewed version")
    destination = repository_path(repo, output)
    checker.require(not destination.exists() and destination.parent.is_dir(),
                    "create-only destination requires an existing parent and absent directory")
    inventory = checker.legacy.recompute_source_inventory(repo)
    wrappers = {}
    for gate, labels in GATES:
        endpoints = checker.ENDPOINTS[gate]
        checker.require(len(labels) == len(endpoints), "source endpoint mapping drift")
        records = [endpoint_record(repo, module, theorem, *receipts[label])
                   for label, (module, theorem) in zip(labels, endpoints)]
        wrapper = {"schema": checker.GATE_SCHEMA, "gate": gate,
                   "identity": checker.relation_identity(checker.RP05_PROFILE),
                   "scope": checker.RECORDED_SCOPE,
                   "execution_receipts_authenticated": False, "production_authorized": False,
                   "source_inventory": inventory, "records": records}
        checker.validate_recorded_gate(repo, wrapper, gate, inventory)
        wrappers[gate] = wrapper
    checker.require(checker.same(checker.legacy.recompute_source_inventory(repo), inventory),
                    "source inventory changed during preparation")
    for wrapper in wrappers.values():
        for record in wrapper["records"]:
            for name in ("source", "object", "compile_receipt", "body_audit"):
                checker.pinned_record(repo, record[name])
    # Validation failures above write nothing. Directory/file creation cannot
    # replace an earlier run, including an empty or incomplete one.
    destination.mkdir(exist_ok=False)
    written = {}
    for gate, wrapper in wrappers.items():
        path = destination / (gate + ".json")
        raw = json.dumps(wrapper, sort_keys=True, indent=2).encode("utf-8")
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        written[gate] = pin(repo, path)[0]
    return {"status": "PREPARED_RECORDED_METADATA_ONLY", "wrappers": written,
            "source_inventory_root_sha512": inventory["root_sha512"],
            "execution_receipts_authenticated": False, "production_authorized": False,
            "contract_installed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="Absent create-only directory inside the repository")
    for label in ("s", "p", "a", "c"):
        parser.add_argument("--" + label + "-compile-receipt", required=True)
        parser.add_argument("--" + label + "-body-audit", required=True)
    args = parser.parse_args(argv)
    receipts = {label: (getattr(args, label + "_compile_receipt"), getattr(args, label + "_body_audit"))
                for label in ("s", "p", "a", "c")}
    print(json.dumps(build(args.output, receipts), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (checker.EvidenceError, KeyError, ValueError, OSError) as error:
        raise SystemExit("RP05 mathematical wrappers rejected: " + str(error))
