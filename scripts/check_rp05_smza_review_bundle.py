#!/usr/bin/env python3
"""Check a candidate RP05/SMZA review bundle without granting authority.

This is a read-only identity and byte-integrity check. It is deliberately
separate from the legacy V4/BLAKE production review path and cannot install
the missing q38 security contract or authorize a transaction proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, NoReturn


SCHEMA = "hegemon.smallwood.poseidon2-v8-smza-rp05-review-bundle.v1"
Q38_CONTRACT_SCHEMA = "hegemon.smallwood.poseidon2-v8-smza-q38-evidence-contract.v1"
PROGRAM_BYTES = 848_231
PROGRAM_SHA512 = (
    "4b0acd4289abd6ae2f0544857fd3fd0177dff45c2bae2a400fbf687e375944ff"
    "d4cf62b6d071ec1f29abd9ddce99c7e4e305e214238b0d34e3c64d7b5a0cde97"
)
PROOF_CAP_BYTES = 164_113
OUTER_ENVELOPE_CAP_BYTES = 169_543
INLINE_ACTION_CAP_BYTES = 169_547
PENDING_ACTION_CAP_BYTES = 169_772
REVIEW_VECTORS_CAP_BYTES = 1 << 20
Q38_CONTRACT_PATH = "scripts/rp05_smza_q38_evidence_contract.json"
Q38_CONTRACT_SHA512 = (
    "2f723d421b03c4a3ffb02534432d2ba511242b1622b49536ac9f34d5708964a9"
    "e692f08586ece2b204f94bac5af64bd704c8433df51d1fce9a3537d4fea3c0b3"
)
Q38_EVIDENCE_PATH = "docs/crypto/rp05_smza_q38_evidence.json"
Q38_EVIDENCE_SCHEMA = "hegemon.smallwood.poseidon2-v8-smza-q38-evidence.v1"
EXPECTED_FILES = (
    "relation-program.bin",
    "proof.bin",
    "review-vectors.json",
)
MISSING_Q38_GATES = (
    "accepted_verifier_soundness",
    "adaptive_whole_view_privacy",
    "relation_and_ledger_composition",
    "identity_proof_lifecycle_and_release_review",
)

EXPECTED_IDENTITY: dict[str, Any] = {
    "network_id": 0x48474D38,
    "circuit_version": 8,
    "crypto_suite": 7,
    "family_id": 1,
    "action_id": 10,
    "coinbase_action_id": 11,
    "backend_wire_id": 2,
    "profile_wire_id": 9,
    "domain_set": 5,
    "inner_proof_magic_ascii": "SMZA",
    "native_leaf_magic_ascii": "HGV8TX03",
    "outer_envelope_magic_ascii": "SWP8LC03",
    "proof_mode": "inline_self_contained",
    "relation_program_magic_ascii": "HGV8RP05",
    "relation_program_bytes": PROGRAM_BYTES,
    "relation_program_sha512": PROGRAM_SHA512,
    "relation_digest_hex": PROGRAM_SHA512[:96],
    "rho": 5,
    "piop_openings": 6,
    "beta": 2,
    "decs_domain_size": 1 << 23,
    "decs_openings": 38,
    "decs_eta": 5,
    "transcript_backend": "Sha512Poseidon2V8Smza",
    "max_proof_bytes": PROOF_CAP_BYTES,
    "max_outer_envelope_bytes": OUTER_ENVELOPE_CAP_BYTES,
    "max_inline_action_bytes": INLINE_ACTION_CAP_BYTES,
    "max_pending_action_bytes": PENDING_ACTION_CAP_BYTES,
}


class BundleError(ValueError):
    """The candidate bundle does not match this exact source contract."""


def reject(message: str) -> NoReturn:
    raise BundleError(message)


def same(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int or int/float aliases."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            reject(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _no_symlink(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        reject(f"cannot inspect {path.name}: {error}")
    if stat.S_ISLNK(mode):
        reject(f"symlink forbidden: {path.name}")


def _read_regular(path: Path, cap: int) -> bytes:
    _no_symlink(path)
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
                reject(f"file is not regular or exceeds its cap: {path.name}")
            payload = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        reject(f"cannot read {path.name}: {error}")
    if len(payload) != before.st_size or len(payload) > cap:
        reject(f"file size changed or exceeds its cap: {path.name}")
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        reject(f"file changed while being read: {path.name}")
    return payload


def _expected_contract(source_contract: dict[str, Any] | None = None) -> dict[str, Any]:
    source = source_contract or {
        "status": "not_installed",
        "evidence_path": Q38_EVIDENCE_PATH,
        "evidence_sha512": None,
    }
    installed = source["status"] == "installed"
    return {
        "schema": Q38_CONTRACT_SCHEMA,
        "status": source["status"],
        "path": Q38_CONTRACT_PATH,
        "sha512": Q38_CONTRACT_SHA512,
        "evidence_path": source["evidence_path"],
        "evidence_sha512": source["evidence_sha512"],
        "missing_gates": [] if installed else list(MISSING_Q38_GATES),
        "production_authorized": False,
    }


def _read_repository_file(repository_root: Path, relative: str, cap: int) -> bytes:
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        reject("q38 evidence path must be a normalized repository-relative path")
    current = repository_root
    for component in candidate.parts:
        current = current / component
        _no_symlink(current)
    return _read_regular(current, cap)


def _check_q38_contract_source(repository_root: Path) -> dict[str, Any]:
    contract_path = repository_root / Q38_CONTRACT_PATH
    try:
        payload = _read_regular(contract_path, 64 * 1024)
    except BundleError as error:
        reject(f"q38 evidence contract source is unavailable: {error}")
    actual_digest = hashlib.sha512(payload).hexdigest()
    if actual_digest != Q38_CONTRACT_SHA512:
        reject("source-pinned q38 evidence contract path or SHA-512 mismatch")
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        reject(f"source-pinned q38 evidence contract is invalid JSON: {error}")
    common = {
        "schema": Q38_CONTRACT_SCHEMA,
        "profile": "V8/SMZA",
        "decs_openings": 38,
        "required_gates": list(MISSING_Q38_GATES),
        "evidence_path": Q38_EVIDENCE_PATH,
        "production_authorized": False,
    }
    if type(value) is not dict or not all(
        same(value.get(key), expected) for key, expected in common.items()
    ):
        reject("source-pinned q38 contract does not match the fail-closed RP05 schema")
    if value.get("status") == "not_installed":
        if value.get("evidence_sha512") is not None:
            reject("uninstalled q38 contract must not carry an evidence hash")
        if value.keys() != {*common.keys(), "status", "evidence_sha512"}:
            reject("uninstalled q38 contract has unexpected fields")
        return value
    if value.get("status") != "installed":
        reject("q38 contract status must be not_installed or installed")
    if value.keys() != {*common.keys(), "status", "evidence_sha512"}:
        reject("installed q38 contract has unexpected fields")
    evidence_digest = value["evidence_sha512"]
    if (
        type(evidence_digest) is not str
        or len(evidence_digest) != 128
        or evidence_digest != evidence_digest.lower()
    ):
        reject("installed q38 contract must pin an evidence SHA-512")
    try:
        bytes.fromhex(evidence_digest)
    except ValueError:
        reject("installed q38 evidence SHA-512 is not hexadecimal")
    evidence_payload = _read_repository_file(
        repository_root, Q38_EVIDENCE_PATH, 4 * 1024 * 1024
    )
    if hashlib.sha512(evidence_payload).hexdigest() != evidence_digest:
        reject("q38 evidence bundle does not match the source-pinned SHA-512")
    try:
        evidence = json.loads(evidence_payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        reject(f"q38 evidence bundle is invalid JSON: {error}")
    if type(evidence) is not dict or evidence.keys() != {
        "schema",
        "profile",
        "decs_openings",
        "gates",
    }:
        reject("q38 evidence bundle has an invalid schema")
    if (
        evidence["schema"] != Q38_EVIDENCE_SCHEMA
        or evidence["profile"] != "V8/SMZA"
        or evidence["decs_openings"] != 38
        or type(evidence["gates"]) is not list
        or len(evidence["gates"]) != len(MISSING_Q38_GATES)
    ):
        reject("q38 evidence bundle identity/gate count mismatch")
    for expected_gate, receipt in zip(MISSING_Q38_GATES, evidence["gates"]):
        if type(receipt) is not dict or receipt.keys() != {
            "gate",
            "path",
            "bytes",
            "sha512",
        }:
            reject("q38 evidence receipt has an invalid schema")
        if receipt["gate"] != expected_gate:
            reject("q38 evidence receipt gates are missing, duplicated, or reordered")
        if type(receipt["bytes"]) is not int or receipt["bytes"] < 0:
            reject("q38 receipt byte count must be a nonnegative integer")
        receipt_digest = receipt["sha512"]
        if (
            type(receipt_digest) is not str
            or len(receipt_digest) != 128
            or receipt_digest != receipt_digest.lower()
        ):
            reject("q38 receipt must carry a lowercase SHA-512")
        try:
            bytes.fromhex(receipt_digest)
        except ValueError:
            reject("q38 receipt SHA-512 is not hexadecimal")
        receipt_path = receipt["path"]
        if type(receipt_path) is not str:
            reject("q38 receipt path must be text")
        receipt_payload = _read_repository_file(
            repository_root, receipt_path, 64 * 1024 * 1024
        )
        if (
            len(receipt_payload) != receipt["bytes"]
            or hashlib.sha512(receipt_payload).hexdigest() != receipt_digest
        ):
            reject(f"q38 receipt bytes/hash mismatch: {expected_gate}")
    return value


def validate_q38_evidence_contract(repository_root: Path) -> str:
    """Validate source-pinned q38 evidence bytes, without making an authority decision."""
    source_contract = _check_q38_contract_source(repository_root)
    if source_contract["status"] == "installed":
        return "source_pinned_evidence_bytes_verified"
    return "not_installed"


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = _read_regular(path, 64 * 1024)
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        reject(f"manifest is not valid UTF-8 JSON: {error}")
    if type(value) is not dict:
        reject("manifest must be a JSON object")
    return value


def check_bundle(
    bundle_dir: Path, *, repository_root: Path | None = None
) -> dict[str, Any]:
    """Validate the current candidate's identity and exact three-file bundle."""
    root = bundle_dir.absolute()
    source_root = (
        repository_root.absolute()
        if repository_root is not None
        else Path(__file__).resolve().parents[1]
    )
    source_contract = _check_q38_contract_source(source_root)
    _no_symlink(root)
    if not root.is_dir():
        reject("bundle path must be a directory")
    manifest = _load_manifest(root / "manifest.json")
    required_manifest_keys = {
        "schema",
        "identity",
        "files",
        "q38_evidence_contract",
        "production_authorized",
    }
    if manifest.keys() != required_manifest_keys:
        reject("manifest keys do not match the exact RP05/SMZA schema")
    if manifest["schema"] != SCHEMA:
        reject("manifest schema is not the RP05/SMZA review-bundle schema")
    if not same(manifest["identity"], EXPECTED_IDENTITY):
        reject("bundle identity does not match current HGV8RP05/SMZA source pins")
    if manifest["production_authorized"] is not False:
        reject("candidate review bundles must remain production_authorized=false")
    if not same(manifest["q38_evidence_contract"], _expected_contract(source_contract)):
        reject("q38 evidence contract is not the exact source-owned fail-closed sentinel")

    files = manifest["files"]
    if type(files) is not dict or files.keys() != set(EXPECTED_FILES):
        reject("manifest must bind exactly relation-program.bin, proof.bin, and review-vectors.json")
    expected_sizes = {
        "relation-program.bin": PROGRAM_BYTES,
        "proof.bin": None,
        "review-vectors.json": None,
    }
    caps = {
        "relation-program.bin": PROGRAM_BYTES,
        "proof.bin": PROOF_CAP_BYTES,
        "review-vectors.json": REVIEW_VECTORS_CAP_BYTES,
    }
    digest_report: dict[str, str] = {}
    observed_sizes: dict[str, int] = {}
    for name in EXPECTED_FILES:
        metadata = files[name]
        if type(metadata) is not dict or metadata.keys() != {"bytes", "sha512"}:
            reject(f"file metadata keys are invalid: {name}")
        if type(metadata["bytes"]) is not int or metadata["bytes"] < 0:
            reject(f"file byte count must be a nonnegative integer: {name}")
        if type(metadata["sha512"]) is not str or len(metadata["sha512"]) != 128:
            reject(f"file SHA-512 must be 128 lowercase hex characters: {name}")
        try:
            bytes.fromhex(metadata["sha512"])
        except ValueError:
            reject(f"file SHA-512 is not hexadecimal: {name}")
        if metadata["sha512"] != metadata["sha512"].lower():
            reject(f"file SHA-512 must be lowercase: {name}")
        payload = _read_regular(root / name, caps[name])
        actual_digest = hashlib.sha512(payload).hexdigest()
        if len(payload) != metadata["bytes"] or actual_digest != metadata["sha512"]:
            reject(f"file size or SHA-512 mismatch: {name}")
        if expected_sizes[name] is not None and len(payload) != expected_sizes[name]:
            reject(f"source-pinned file has wrong size: {name}")
        if name == "relation-program.bin":
            if payload[:8] != b"HGV8RP05" or actual_digest != PROGRAM_SHA512:
                reject("relation program does not match the canonical HGV8RP05 bytes")
        elif name == "proof.bin":
            if len(payload) < 4 or payload[:4] != b"SMZA":
                reject("proof does not have exact SMZA wire magic")
        digest_report[name] = actual_digest
        observed_sizes[name] = len(payload)

    try:
        actual_files = {entry.name for entry in root.iterdir()}
    except OSError as error:
        reject(f"cannot enumerate bundle directory: {error}")
    expected_names = {"manifest.json", *EXPECTED_FILES}
    if actual_files != expected_names:
        reject("bundle directory contains missing or unlisted files")

    return {
        "schema": SCHEMA,
        "candidate_bundle_integrity": "pass",
        "identity": EXPECTED_IDENTITY,
        "file_bytes": observed_sizes,
        "file_sha512": digest_report,
        "q38_evidence_contract": (
            "source_pinned_evidence_bytes_verified"
            if source_contract["status"] == "installed"
            else "not_installed"
        ),
        "production_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        result = check_bundle(args.bundle_dir, repository_root=args.root)
    except BundleError as error:
        print(f"RP05 SMZA candidate bundle rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
