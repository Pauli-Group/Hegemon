#!/usr/bin/env python3
"""Prepare, but never install, the source-pinned RP05 q38 evidence contract.

All four current gate recordings are validated before any output is created.
The outputs are prospective evidence/contract bytes and a checker-pin patch;
they remain inert until reviewed and explicitly installed by the release owner.
This preparer does not authenticate execution or grant production authority.
"""
from __future__ import annotations

import argparse
import ctypes
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

REPO = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "scripts"))
import check_smallwood_poseidon2_v8_smza_artifacts as checker

ARTIFACT_CHECKER_SHA256 = "e1dcb73896b1519c89a05a31eb4aa21c31fd92183c1f3e4637be3bf131482447"
CONTRACT_CHECKER_SHA256 = "d57844ff709aad6cb9ce961b0a1c7e852941c626c98650347300e791ebf8ac38"
CONTRACT_PATH = Path("scripts/rp05_smza_q38_evidence_contract.json")
CONTRACT_CHECKER_PATH = Path("scripts/check_rp05_smza_review_bundle.py")
EVIDENCE_PATH = "docs/crypto/rp05_smza_q38_evidence.json"
EVIDENCE_NAME = "rp05_smza_q38_evidence.proposed.json"
CONTRACT_NAME = "rp05_smza_q38_evidence_contract.proposed.json"
PATCH_NAME = "check_rp05_smza_review_bundle.py.proposed.patch"
ORDERED_GATES = (
    "accepted_verifier_soundness",
    "adaptive_whole_view_privacy",
    "relation_and_ledger_composition",
    "identity_proof_lifecycle_and_release_review",
)
GATE_ARGUMENTS = (
    ("soundness", ORDERED_GATES[0]),
    ("privacy", ORDERED_GATES[1]),
    ("relation-ledger", ORDERED_GATES[2]),
    ("proof-lifecycle-review", ORDERED_GATES[3]),
)


def _relative_path(repo: Path, value: Path | str, label: str) -> Path:
    raw = str(value)
    path = Path(raw)
    checker.require(not path.is_absolute(), f"{label}: use a repository-relative path")
    checker.require(path.as_posix() == raw and "\\" not in raw and
                    bool(path.parts) and all(part not in ("", ".", "..") for part in raw.split("/")),
                    f"{label}: normalized repository-relative path required")
    cursor = repo
    checker.require(not cursor.is_symlink(), f"{label}: symlink repository")
    for part in path.parts:
        cursor = cursor / part
        checker.require(not cursor.is_symlink(), f"{label}: symlink path forbidden")
    return cursor


def _read_pinned(repo: Path, value: Path | str, label: str, cap: int = 128 * 1024**2) -> tuple[Path, bytes, dict[str, Any]]:
    path = _relative_path(repo, value, label)
    raw = checker.read(path, cap)
    return path, raw, {"path": path.relative_to(repo).as_posix(), "bytes": len(raw), "sha512": checker.digest(raw)}


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _checker_patch(source: bytes, new_digest: str) -> bytes:
    text = source.decode("utf-8")
    old_digest = checker.rp05_contract.Q38_CONTRACT_SHA512
    old_assignment = f'Q38_CONTRACT_SHA512 = (\n    "{old_digest[:64]}"\n    "{old_digest[64:]}"\n)'
    new_assignment = f'Q38_CONTRACT_SHA512 = (\n    "{new_digest[:64]}"\n    "{new_digest[64:]}"\n)'
    checker.require(text.count(old_assignment) == 1, "contract checker pin is not the expected frozen assignment")
    updated = text.replace(old_assignment, new_assignment, 1)
    diff = difflib.unified_diff(
        text.splitlines(keepends=True), updated.splitlines(keepends=True),
        fromfile="a/scripts/check_rp05_smza_review_bundle.py",
        tofile="b/scripts/check_rp05_smza_review_bundle.py",
    )
    return "".join(diff).encode("utf-8")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish without replacing any pre-existing path."""
    if sys.platform != "darwin":
        raise checker.EvidenceError("exclusive directory publication is unavailable on this platform")
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = getattr(libc, "renameatx_np", None)
    if renameatx_np is None:
        raise checker.EvidenceError("renameatx_np is unavailable; refusing non-exclusive publication")
    renameatx_np.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameatx_np.restype = ctypes.c_int
    at_fdcwd = -2
    rename_excl = 0x00000004
    result = renameatx_np(at_fdcwd, os.fsencode(source), at_fdcwd, os.fsencode(destination), rename_excl)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(output: Path | str, gate_paths: dict[str, Path | str], *, repo: Path = REPO) -> dict[str, Any]:
    """Validate the exact four records, then atomically create prospective files."""
    repo = repo.resolve(strict=True)
    checker.require(set(gate_paths) == {name for name, _ in GATE_ARGUMENTS}, "exact four gate inputs required")
    checker.require(tuple(gate_paths) == tuple(name for name, _ in GATE_ARGUMENTS), "gate inputs must be in canonical S/P/A+C/R order")

    output_path = _relative_path(repo, output, "output")
    checker.require(output_path.parent.is_dir(), "output parent must already exist")
    checker.require(not output_path.exists(), "create-only output path already exists")

    artifact_checker_path = _relative_path(
        repo, "scripts/check_smallwood_poseidon2_v8_smza_artifacts.py", "artifact checker"
    )
    contract_checker_path = _relative_path(repo, CONTRACT_CHECKER_PATH, "contract checker")
    contract_path = _relative_path(repo, CONTRACT_PATH, "contract")
    artifact_checker_raw = checker.read(artifact_checker_path, 16 * 1024**2)
    contract_checker_raw = checker.read(contract_checker_path, 16 * 1024**2)
    checker.require(checker.digest(artifact_checker_raw, "sha256") == ARTIFACT_CHECKER_SHA256,
                    "frozen recorded-gate validator source differs")
    checker.require(checker.digest(contract_checker_raw, "sha256") == CONTRACT_CHECKER_SHA256,
                    "frozen q38 contract checker source differs")
    current_contract_raw = checker.read(contract_path, 64 * 1024)
    current_contract = checker.object_json(current_contract_raw)
    checker.require(checker.digest(current_contract_raw) == checker.rp05_contract.Q38_CONTRACT_SHA512,
                    "current source-pinned contract bytes differ")
    checker.require(current_contract.get("status") == "not_installed" and
                    current_contract.get("evidence_sha512") is None,
                    "q38 evidence contract is already installed or malformed")
    checker.require(checker.rp05_contract.validate_q38_evidence_contract(repo) == "not_installed",
                    "current q38 contract is not the frozen uninstalled sentinel")

    inventory = checker.legacy.recompute_source_inventory(repo)
    pins: list[dict[str, Any]] = []
    observed_inputs: list[tuple[Path, bytes]] = []
    for argument, expected_gate in GATE_ARGUMENTS:
        path, raw, pin = _read_pinned(repo, gate_paths[argument], argument + " gate")
        wrapper = checker.object_json(raw)
        checker.require(wrapper.get("gate") == expected_gate, f"{argument}: wrong gate or order")
        checker.validate_recorded_gate(repo, wrapper, expected_gate, inventory)
        pins.append({"gate": expected_gate, **pin})
        observed_inputs.append((path, raw))

    checker.require(checker.same(checker.legacy.recompute_source_inventory(repo), inventory),
                    "source inventory changed during evidence validation")
    evidence = {
        "schema": checker.rp05_contract.Q38_EVIDENCE_SCHEMA,
        "profile": "V8/SMZA",
        "decs_openings": 38,
        "gates": pins,
    }
    evidence_raw = _canonical_json(evidence)
    evidence_sha512 = checker.digest(evidence_raw)
    proposed_contract = dict(current_contract)
    proposed_contract["status"] = "installed"
    proposed_contract["evidence_sha512"] = evidence_sha512
    contract_raw = _canonical_json(proposed_contract)
    proposed_contract_sha512 = checker.digest(contract_raw)
    patch_raw = _checker_patch(contract_checker_raw, proposed_contract_sha512)
    checker.require(bool(patch_raw), "prospective checker pin patch is empty")

    # Re-read every supplied record and sentinel before touching the destination.
    for path, original in observed_inputs:
        checker.require(checker.read(path, 128 * 1024**2) == original, "gate input changed after validation")
    checker.require(checker.read(contract_path, 64 * 1024) == current_contract_raw,
                    "source contract changed after validation")
    checker.require(checker.read(contract_checker_path, 16 * 1024**2) == contract_checker_raw,
                    "contract checker changed after validation")
    checker.require(checker.same(checker.legacy.recompute_source_inventory(repo), inventory),
                    "source inventory changed before output publication")

    staging = Path(tempfile.mkdtemp(prefix="." + output_path.name + ".stage-", dir=output_path.parent))
    published = False
    payloads = {EVIDENCE_NAME: evidence_raw, CONTRACT_NAME: contract_raw, PATCH_NAME: patch_raw}
    try:
        for name, raw in payloads.items():
            _write_new(staging / name, raw)
        _fsync_directory(staging)
        checker.require(not output_path.exists() and not output_path.is_symlink(),
                        "create-only output appeared during preparation")
        _rename_directory_exclusive(staging, output_path)
        published = True
        _fsync_directory(output_path.parent)
    except BaseException:
        if staging.exists() and staging.parent == output_path.parent and staging.name.startswith("." + output_path.name + ".stage-"):
            shutil.rmtree(staging)
        elif published and output_path.is_dir() and not output_path.is_symlink():
            # Roll back only the exact create-only directory and bytes this
            # invocation just published; never remove an unexpected occupant.
            names = {entry.name for entry in output_path.iterdir()}
            if names == set(payloads):
                intact = all(
                    not (output_path / name).is_symlink()
                    and (output_path / name).is_file()
                    and (output_path / name).read_bytes() == raw
                    for name, raw in payloads.items()
                )
                if intact:
                    for name in payloads:
                        (output_path / name).unlink()
                    output_path.rmdir()
                    _fsync_directory(output_path.parent)
        raise

    return {
        "status": "DRY_RUN_PREPARED_NOT_INSTALLED",
        "output": output_path.relative_to(repo).as_posix(),
        "evidence_sha512": evidence_sha512,
        "proposed_contract_sha512": proposed_contract_sha512,
        "checker_pin_patch": (output_path / PATCH_NAME).relative_to(repo).as_posix(),
        "source_inventory_root_sha512": inventory["root_sha512"],
        "execution_receipts_authenticated": False,
        "production_authorized": False,
        "contract_installed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="Absent create-only directory, repository-relative")
    for argument, _ in GATE_ARGUMENTS:
        parser.add_argument("--" + argument, required=True, help="Repository-relative validated gate wrapper JSON")
    args = parser.parse_args(argv)
    gates = {argument: getattr(args, argument.replace("-", "_")) for argument, _ in GATE_ARGUMENTS}
    print(json.dumps(prepare(args.output, gates), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (checker.EvidenceError, KeyError, ValueError, OSError) as error:
        raise SystemExit("RP05 contract preparation rejected: " + str(error))
