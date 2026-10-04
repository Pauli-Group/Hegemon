#!/usr/bin/env python3
"""Read-only RP05 evidence freshness evaluator and checklist renderer.

This reports whether pinned artifacts still match their declared bytes and
dependencies. It does not rerun Lean, cryptography, lifecycle tests, or grant
production authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Callable, Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = Path("docs/crypto/rp05_release_manifest.json")
CHECKLIST_PATH = Path(".agent/prod-closure-2026-09-19/release-preparation/PRODUCTION_CHECKLIST.md")
HISTORY_PATH = ".agent/prod-closure-2026-09-19/release-preparation/history/PRODUCTION_CHECKLIST_2026-10-01.md"
REPORT_SCHEMA = "hegemon.rp05.release-status-report.v1"
MANIFEST_SCHEMA = "hegemon.rp05.release-evidence-manifest.v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
STANDARD_AXIOMS = {"Quot.sound", "Classical.choice", "propext"}
SIZE_CAPS_BYTES = {"inner_proof": 164113, "rpc_envelope": 169543,
                   "inline_args": 169547, "pending_action": 169772}


class StatusError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StatusError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    """Hash a regular, canonical file in bounded memory."""
    path = Path(path)
    if path.is_symlink():
        raise StatusError(f"symlink input: {path}")
    try:
        if path.resolve(strict=True) != path:
            raise StatusError(f"noncanonical input path: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise StatusError(f"missing/unreadable input: {path}: {error}") from error
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        mode = before.st_mode
        if not stat.S_ISREG(mode):
            raise StatusError(f"input is not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        after = os.fstat(fd)
        current_path = os.stat(path, follow_symlinks=False)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        identity_path = (current_path.st_dev, current_path.st_ino, current_path.st_size,
                         current_path.st_mtime_ns, current_path.st_ctime_ns)
        if identity_before != identity_after or identity_after != identity_path:
            raise StatusError(f"input changed while hashing: {path}")
    finally:
        os.close(fd)
    return digest.hexdigest()


def _read_regular(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    if path.is_symlink():
        raise StatusError(f"symlink input: {path}")
    try:
        if path.resolve(strict=True) != path:
            raise StatusError(f"noncanonical input path: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise StatusError(f"missing/unreadable input: {path}: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise StatusError(f"input is not a regular file: {path}")
        chunks: list[bytes] = []
        count = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(min(1024 * 1024, limit + 1 - count)):
                count += len(chunk)
                if count > limit:
                    raise StatusError(f"JSON/input exceeds {limit} bytes: {path}")
                chunks.append(chunk)
        after = os.fstat(fd)
        current_path = os.stat(path, follow_symlinks=False)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        identity_path = (current_path.st_dev, current_path.st_ino, current_path.st_size,
                         current_path.st_mtime_ns, current_path.st_ctime_ns)
        if identity_before != identity_after or identity_after != identity_path:
            raise StatusError(f"input changed while reading: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_json(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object,
                           parse_constant=lambda token: (_ for _ in ()).throw(StatusError(f"non-finite JSON value: {token}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusError(f"invalid JSON: {path}: {error}") from error
    if type(value) is not dict:
        raise StatusError(f"expected JSON object: {path}")
    return value


def _json_file(path: Path) -> dict[str, Any]:
    return _parse_json(_read_regular(path), path)


def _relative(root: Path, value: object) -> Path:
    if type(value) is not str or not value or "\\" in value:
        raise StatusError("pinned path must be normalized repository-relative POSIX text")
    pure = Path(value)
    if pure.is_absolute() or pure.as_posix() != value or any(part in ("", ".", "..") for part in value.split("/")):
        raise StatusError(f"unsafe pinned path: {value}")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise StatusError(f"symlink path component: {current}")
    return current


def _pin(root: Path, descriptor: object, hash_reader: Callable[[Path], str], stale: list[str], label: str) -> tuple[Path | None, str | None]:
    if type(descriptor) is not dict or set(descriptor) != {"path", "sha256"}:
        stale.append(f"{label}: invalid pin descriptor")
        return None, None
    try:
        path = _relative(root, descriptor["path"])
    except StatusError as error:
        stale.append(f"{label}: {error}")
        return None, None
    expected = descriptor["sha256"]
    if type(expected) is not str or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        stale.append(f"{label}: invalid SHA-256 pin")
        return path, None
    try:
        actual = hash_reader(path)
    except (OSError, StatusError) as error:
        stale.append(f"{label}: {error}")
        return path, None
    if actual != expected:
        stale.append(f"{label}: SHA-256 changed")
        return path, actual
    return path, actual


def _pinned_json(root: Path, descriptor: object, hash_reader: Callable[[Path], str], stale: list[str], label: str) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    path, actual = _pin(root, descriptor, hash_reader, stale, label)
    if path is None or actual is None or type(descriptor) is not dict or actual != descriptor.get("sha256"):
        return None, path, actual
    try:
        return _json_file(path), path, actual
    except StatusError as error:
        stale.append(f"{label}: {error}")
        return None, path, actual


def _check_dependencies(root: Path, entries: object, label: str, hash_reader: Callable[[Path], str], stale: list[str], cache: dict[str, str]) -> None:
    if type(entries) is not dict:
        stale.append(f"{label}: dependency pin map missing")
        return
    for raw_path, expected in entries.items():
        if type(raw_path) is not str or not Path(raw_path).is_absolute():
            stale.append(f"{label}: dependency path is not absolute")
            continue
        if type(expected) is not str or len(expected) != 64:
            stale.append(f"{label}: malformed dependency pin {raw_path}")
            continue
        if raw_path not in cache:
            try:
                cache[raw_path] = hash_reader(Path(raw_path))
            except (OSError, StatusError) as error:
                cache[raw_path] = "!missing!"
                stale.append(f"{label}: dependency unavailable {raw_path}: {error}")
        if cache[raw_path] != expected:
            stale.append(f"{label}: dependency changed {raw_path}")


def _body_log_passes(raw: bytes) -> bool:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    try:
        axioms = {item.strip() for item in values["axioms"].split(",")}
        declarations = int(values.get("declarations traversed", "0"))
    except (KeyError, ValueError):
        return False
    return (values.get("result") == "PASS" and values.get("nonstandard axioms") == "" and
            values.get("missing kernel constants") == "" and values.get("missing theorem/opaque bodies") == "" and
            axioms == STANDARD_AXIOMS and declarations > 0)


def _check_endpoint(root: Path, key: str, item: object, audit_source_sha256: str,
                    hash_reader: Callable[[Path], str], stale: list[str], dep_cache: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if type(item) is not dict:
        stale.append(f"{key}: endpoint entry missing")
        return "open", {"status": "open", "note": "endpoint manifest entry missing", "receipt": None}
    start = len(stale)
    pins: dict[str, tuple[Path | None, str | None]] = {}
    for field in ("source", "object", "strict_receipt", "body_fingerprint", "body_log"):
        pins[field] = _pin(root, item.get(field), hash_reader, stale, f"{key}.{field}")
    json_values: dict[str, dict[str, Any] | None] = {}
    for field in ("strict_receipt", "body_fingerprint"):
        path, actual = pins[field]
        descriptor = item.get(field)
        if path is None or actual is None or type(descriptor) is not dict or actual != descriptor.get("sha256"):
            json_values[field] = None
        else:
            try:
                json_values[field] = _json_file(path)
            except StatusError as error:
                stale.append(f"{key}.{field}: {error}")
                json_values[field] = None
    source_path, source_sha = pins["source"]
    object_path, object_sha = pins["object"]
    strict = json_values["strict_receipt"]
    body = json_values["body_fingerprint"]
    if source_path is not None and source_sha is not None and strict is not None:
        strict_source = strict.get("source")
        if type(strict_source) is not str or Path(strict_source).resolve() != source_path.resolve():
            stale.append(f"{key}: strict receipt points at another source")
        if strict.get("module") != item.get("module") or strict.get("exit_code") != 0:
            stale.append(f"{key}: strict receipt module/status mismatch")
        if strict.get("source_sha256_pre") != source_sha or strict.get("source_sha256_post") != source_sha:
            stale.append(f"{key}: source changed during strict check or receipt source pin differs")
        if object_sha is None or strict.get("output_sha256") != object_sha:
            stale.append(f"{key}: strict output does not match pinned object")
        maps = strict.get("dependency_hashes_pre_post")
        if type(maps) is not dict or type(maps.get("pre")) is not dict or type(maps.get("post")) is not dict:
            stale.append(f"{key}: strict dependency hashes changed during check")
        else:
            before, after = maps["pre"], maps["post"]
            added = set(after) - set(before)
            removed = set(before) - set(after)
            tool_keys = {raw_path for raw_path in before if raw_path.endswith("/bin/lean")}
            # Lean's module path can be nested (for example Rp05.Authorization
            # writes Rp05/Authorization.olean), so bind the sole new output to
            # the exact object path already pinned by the manifest.
            expected_output = str(object_path.resolve()) if object_path is not None else None
            output_keys = {raw_path for raw_path in added if raw_path == expected_output}
            shared = set(before) & set(after)
            if (added != output_keys or len(output_keys) != 1 or removed != tool_keys or len(tool_keys) != 1 or
                    after[next(iter(output_keys))] != object_sha or
                    any(before[raw_path] != after[raw_path] for raw_path in shared)):
                stale.append(f"{key}: strict dependency hashes changed during check")
            _check_dependencies(root, before, f"{key}.strict.pre", hash_reader, stale, dep_cache)
            _check_dependencies(root, after, f"{key}.strict.post", hash_reader, stale, dep_cache)
    if body is not None and source_sha is not None:
        if body.get("module") != item.get("module") or body.get("root") != item.get("theorem"):
            stale.append(f"{key}: body audit target mismatch")
        if body.get("exit_code") != 0 or body.get("all_search_path_objects_stable") is not True:
            stale.append(f"{key}: body audit did not pass stable-input checks")
        if body.get("target_source_sha256") != source_sha or body.get("target_olean_sha256") != object_sha:
            stale.append(f"{key}: body audit source/object mismatch")
        if body.get("audit_source_sha256") != audit_source_sha256:
            stale.append(f"{key}: body audit checker source mismatch")
        strict_path, strict_sha = pins["strict_receipt"]
        if body.get("target_receipt_sha256") != strict_sha:
            stale.append(f"{key}: body audit strict-receipt binding mismatch")
        if body.get("input_hashes_pre") != body.get("input_hashes_post"):
            stale.append(f"{key}: body audit input hashes changed during audit")
        if body.get("input_fingerprint_sha256_pre") != body.get("input_fingerprint_sha256_post"):
            stale.append(f"{key}: body audit input fingerprint changed during audit")
        _check_dependencies(root, body.get("input_hashes_post"), f"{key}.body", hash_reader, stale, dep_cache)
    body_log_path, body_log_sha = pins["body_log"]
    if body_log_path is not None and body_log_sha is not None:
        try:
            if not _body_log_passes(_read_regular(body_log_path, 2 * 1024 * 1024)):
                stale.append(f"{key}: body audit log lacks a clean PASS")
        except StatusError as error:
            stale.append(f"{key}: body audit log unreadable: {error}")
    changed = len(stale) > start
    status = "changed" if changed else "checked"
    receipt = {
        "strict": item.get("strict_receipt"),
        "body_audit": item.get("body_fingerprint"),
    }
    return status, {"status": status, "name": item.get("name", key),
                    "note": "strict object and actual-body pins match" if not changed else "one or more endpoint/source/dependency pins changed",
                    "receipt": receipt}


def evaluate(root: Path = ROOT, manifest: Path | None = None, *,
             hash_reader: Callable[[Path], str] = sha256_file,
             inventory_reader: Callable[[Path], dict[str, Any]] | None = None,
             test_only_delta: Path | None = None) -> dict[str, Any]:
    """Evaluate all pinned bytes/dependencies; missing or changed inputs fail closed."""
    root = Path(root).resolve(strict=True)
    manifest_path = Path(manifest) if manifest is not None else root / MANIFEST_PATH
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    stale: list[str] = []
    try:
        manifest_raw = _read_regular(manifest_path)
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        data = _parse_json(manifest_raw, manifest_path)
        if data.get("schema") != MANIFEST_SCHEMA:
            raise StatusError("unsupported evidence manifest schema")
    except (OSError, StatusError) as error:
        stale.append(f"manifest: {error}")
        return _report(root, None, manifest_sha if 'manifest_sha' in locals() else None, stale, {})

    endpoints: dict[str, dict[str, Any]] = {}
    dep_cache: dict[str, str] = {}
    audit_path, audit_sha = _pin(root, data.get("body_audit_source"), hash_reader, stale, "body_audit_source")
    endpoint_entries = data.get("endpoints")
    if type(endpoint_entries) is not dict:
        stale.append("endpoint manifest map missing")
        endpoint_entries = {}
    for key in ("S", "P", "A", "C"):
        _, endpoints[key] = _check_endpoint(root, key, endpoint_entries.get(key), audit_sha or "", hash_reader, stale, dep_cache)

    candidate = data.get("candidate") if type(data.get("candidate")) is dict else {}
    boundary = data.get("release_boundary") if type(data.get("release_boundary")) is dict else {}
    if boundary.get("size_caps_bytes") != SIZE_CAPS_BYTES:
        stale.append("release boundary size caps missing or changed")
    if boundary.get("production_authority_claimed") is not False:
        stale.append("manifest must not claim production authority")
    if boundary.get("r5_scope") != "separate_pr_review_and_publication":
        stale.append("R5 scope must remain PR review/publication")
    inv = _compute_inventory(root, data, candidate, hash_reader, stale, inventory_reader)

    delta_annotation = None
    packet_inventory = inv
    delta_descriptor = candidate.get("test_only_evidence_delta")
    if delta_descriptor is not None:
        delta_annotation = _verify_test_only_delta(root, delta_descriptor, hash_reader, stale)
        if (delta_annotation.get("status") == "reused_test_only_delta" and
                inv.get("status") == "checked" and
                delta_annotation.get("current_root_sha512") == inv.get("current_root_sha512")):
            # The old packet remains bound to its immutable baseline. Only the
            # explicitly verified cfg(test)-only delta permits that baseline
            # for packet checks; R1 still checks the new current root above.
            packet_inventory = dict(inv, current_root_sha512=delta_annotation["baseline_root_sha512"])
        else:
            if delta_annotation.get("status") == "reused_test_only_delta":
                stale.append("test-only delta current root does not equal the freshly recomputed candidate inventory")
                delta_annotation = {**delta_annotation, "status": "changed",
                                    "note": "record did not bind the current candidate root"}
    packet_status, packet_details = _check_packet(root, data.get("packet"), candidate, packet_inventory, hash_reader, stale)
    if delta_annotation is not None and delta_annotation.get("status") == "reused_test_only_delta" and packet_status == "checked":
        packet_details["reuse_status"] = "reused_test_only_delta"
        packet_details["reuse_note"] = "retained pass plus verified test-only delta; not a new proof, technical, or lifecycle run"
    publication = _check_publication(root, boundary.get("publication"), hash_reader, stale)
    release = _release_gates(inv, packet_details, packet_status, stale, publication)
    report = _report(root, manifest_sha, manifest_sha, stale, endpoints,
                     source_inventory=inv, release_gates=release,
                     packet=packet_details, release_boundary=boundary,
                     test_only_evidence_delta=delta_annotation, publication=publication)
    return report


def _verify_test_only_delta(root: Path, descriptor: object, hash_reader: Callable[[Path], str],
                            stale: list[str]) -> dict[str, Any]:
    """Verify the manifest-pinned record and return its two inventory roots."""
    try:
        if type(descriptor) is not dict or set(descriptor) != {"path", "sha256"}:
            raise StatusError("candidate test-only delta must be an exact path/SHA-256 pin")
        record_path, record_sha = _pin(root, descriptor, hash_reader, stale, "candidate.test_only_evidence_delta")
        if record_path is None or record_sha is None or record_sha != descriptor["sha256"]:
            raise StatusError("manifest-pinned test-only delta unavailable or changed")
        script_path = _relative(root, "scripts/check_rp05_test_only_evidence_delta.py")
        script_sha = hash_reader(script_path)
        spec = importlib.util.spec_from_file_location("rp05_test_only_evidence_delta", script_path)
        if spec is None or spec.loader is None:
            raise StatusError("test-only delta verifier unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        verified = module.verify_delta_record(root, record_path)
        if verified.get("checker", {}).get("sha256") != script_sha:
            raise StatusError("test-only delta record binds a different verifier source")
        if verified.get("reuse_decision", {}).get("allowed") is not True or verified.get("source_delta", {}).get("prefix_byte_identical") is not True:
            raise StatusError("test-only delta did not qualify strict pre-test byte identity/reuse")
        return {"status": "reused_test_only_delta", "path": descriptor["path"],
                "sha256": record_sha, "baseline_root_sha512": verified["baseline"]["inventory_root_sha512"],
                "current_root_sha512": verified["current"]["inventory_root_sha512"],
                "scope": "unchanged proof/relation and development-only lifecycle bytes; no fresh pass or authority"}
    except Exception as error:
        stale.append(f"test-only delta record rejected: {error}")
        path = descriptor.get("path") if type(descriptor) is dict else None
        return {"status": "changed", "path": path, "note": "record rejected; no prior evidence reused"}


def _compute_inventory(root: Path, data: dict[str, Any], candidate: dict[str, Any],
                       hash_reader: Callable[[Path], str], stale: list[str],
                       inventory_reader: Callable[[Path], dict[str, Any]] | None = None) -> dict[str, Any]:
    start = len(stale)
    policy_path, policy_sha = _pin(
        root, candidate.get("inventory_policy"), hash_reader, stale,
        "candidate.inventory_policy")
    if policy_path is None or policy_sha is None:
        return {"status": "changed", "expected_root_sha512": candidate.get("source_inventory_root_sha512"),
                "current_root_sha512": None}
    if inventory_reader is None:
        try:
            spec = importlib.util.spec_from_file_location("rp05_status_inventory_policy", policy_path)
            if spec is None or spec.loader is None:
                raise StatusError("cannot load pinned inventory policy")
            policy = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = policy
            spec.loader.exec_module(policy)
            inventory_reader = policy.recompute_retained_proof_source_inventory
        except (KeyError, AttributeError, StatusError, ImportError, OSError) as error:
            stale.append(f"candidate source inventory: policy unavailable: {error}")
            return {"status": "changed", "expected_root_sha512": candidate.get("source_inventory_root_sha512"), "current_root_sha512": None}
    try:
        observed = inventory_reader(root)
        expected = candidate.get("source_inventory_root_sha512")
        count = candidate.get("source_inventory_file_count")
        current = observed.get("root_sha512")
        if current != expected or observed.get("file_count") != count or len(stale) > start:
            stale.append("candidate source inventory root/count changed")
            state = "changed"
        else:
            state = "checked"
        # Keep the detailed observed input descriptor in memory only; chart output stays compact.
        return {"status": state, "expected_root_sha512": expected,
                "current_root_sha512": current, "expected_file_count": count,
                "current_file_count": observed.get("file_count")}
    except Exception as error:
        stale.append(f"candidate source inventory recomputation failed: {error}")
        return {"status": "changed", "expected_root_sha512": candidate.get("source_inventory_root_sha512"), "current_root_sha512": None}


def _check_packet(root: Path, packet: object, candidate: dict[str, Any], inventory: dict[str, Any],
                  hash_reader: Callable[[Path], str], stale: list[str]) -> tuple[str, dict[str, Any]]:
    start = len(stale)
    if type(packet) is not dict:
        stale.append("final packet manifest missing")
        return "changed", {}
    pins: dict[str, tuple[Path | None, str | None]] = {}
    for key in ("pair_manifest", "technical_report", "adapter_report", "lifecycle_review", "socket_carrier_receipt", "inprocess_receipt", "socket_receipt", "q38_contract", "q38_evidence"):
        pins[key] = _pin(root, packet.get(key), hash_reader, stale, f"packet.{key}")
    proof_pins: dict[str, tuple[Path | None, str | None]] = {}
    for role in ("primary", "independent"):
        proof_pins[role] = _pin(root, packet.get("proofs", {}).get(role) if type(packet.get("proofs")) is dict else None, hash_reader, stale, f"packet.proof.{role}")
    pair_path, pair_hash = pins["pair_manifest"]
    report_path, _ = pins["technical_report"]
    adapter_path, _ = pins["adapter_report"]
    lifecycle_path, _ = pins["lifecycle_review"]
    carrier_path, _ = pins["socket_carrier_receipt"]
    inprocess_path, _ = pins["inprocess_receipt"]
    socket_path, _ = pins["socket_receipt"]
    if None in (pair_path, report_path, adapter_path, lifecycle_path, carrier_path, inprocess_path, socket_path):
        return "changed", {"technical_status": "missing_or_changed"}
    try:
        pair = _json_file(pair_path)
        technical = _json_file(report_path)
        adapter = _json_file(adapter_path)
        lifecycle = _json_file(lifecycle_path)
        carrier = _json_file(carrier_path)
        inprocess = _json_file(inprocess_path)
        socket = _json_file(socket_path)
        inventory_root = inventory.get("current_root_sha512")
        if pair.get("proof_source_inventory", {}).get("root_sha512") != inventory_root:
            stale.append("final pair manifest source inventory differs from current candidate")
        for role in ("primary", "independent"):
            descriptor = packet["proofs"][role]
            proof_path, _ = proof_pins[role]
            if proof_path is None:
                continue
            actual_bytes = proof_path.stat().st_size
            actual_sha512 = hashlib.sha512(_read_regular(proof_path, 200_000)).hexdigest()
            pair_role = pair.get("artifacts", {}).get(role, {})
            file_metadata = pair_role.get("files", {}).get("proof.bin", {})
            if file_metadata.get("bytes") != actual_bytes or file_metadata.get("sha512") != actual_sha512:
                stale.append(f"{role} proof differs from pair manifest")
            if actual_bytes > 164113:
                stale.append(f"{role} proof exceeds 164113-byte cap")
        if technical.get("schema") != "hegemon.rp05.smza.pr-technical-release-packet.v1" or technical.get("technical_status") != "PASS_PR_ONLY":
            stale.append("final technical report is not PASS_PR_ONLY")
        if technical.get("q38_contract", {}).get("status") != "PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED":
            stale.append("final technical report lacks the recorded semantic-gate status")
        if technical.get("production_authorized") is not False or technical.get("production_eligible") is not False:
            stale.append("technical packet must deny production authority")
        if technical.get("retained_pair", {}).get("source_inventory_root_sha512") != inventory_root:
            stale.append("technical packet candidate inventory mismatch")
        if adapter.get("schema") != "hegemon.smallwood.poseidon2-v8.smza.software-evidence.v1" or adapter.get("source_root_sha512") != inventory_root:
            stale.append("final adapter source inventory/schema mismatch")
        if adapter.get("production_eligible") is not False or adapter.get("execution_receipts_authenticated") is not False:
            stale.append("adapter must preserve non-authorizing boundary")
        if adapter.get("recorded_inprocess_reorg_evidence_consistent") is not True or adapter.get("recorded_actual_socket_carrier_evidence_consistent") is not True:
            stale.append("adapter does not bind both lifecycle reports")
        if lifecycle.get("schema") != "hegemon.smallwood.poseidon2-v8.smza.reviewed-recorded-gate.v1" or lifecycle.get("gate") != "identity_proof_lifecycle_and_release_review":
            stale.append("lifecycle review wrapper schema/gate mismatch")
        if lifecycle.get("production_authorized") is not False or lifecycle.get("execution_receipts_authenticated") is not False:
            stale.append("lifecycle wrapper must remain non-authorizing")
        if inprocess.get("status") != "PASS_DEVELOPMENT_ONLY" or socket.get("status") != "PASS_DEVELOPMENT_ONLY":
            stale.append("lifecycle guard receipts no longer pass")
        if carrier.get("schema") != "hegemon.retained-smza.actual-socket-carriers-v1" or carrier.get("pass") is not True or carrier.get("production_authority_denied") is not True:
            stale.append("actual socket-carrier lifecycle receipt invalid")
        if carrier.get("source_inventory_root_sha512") != inventory_root:
            stale.append("socket-carrier receipt source inventory changed")
        if not technical.get("retained_pair", {}).get("proofs", {}).get("primary", {}).get("source_owned_verification") or not technical.get("retained_pair", {}).get("proofs", {}).get("independent", {}).get("source_owned_verification"):
            stale.append("technical report does not record both source-owned proof checks")
        details = {"technical_status": technical.get("technical_status"),
                   "q38_recorded_status": technical.get("q38_contract", {}).get("status"),
                   "production_authorized": False,
                   "pair_manifest": packet.get("pair_manifest"),
                   "technical_report": packet.get("technical_report"),
                   "adapter_report": packet.get("adapter_report"),
                   "lifecycle_review": packet.get("lifecycle_review")}
        return ("changed" if len(stale) > start else "checked"), details
    except (AttributeError, KeyError, OSError, StatusError, TypeError, ValueError) as error:
        stale.append(f"final packet content invalid: {error}")
        return "changed", {"technical_status": "invalid"}


def _check_publication(root: Path, descriptor: object, hash_reader: Callable[[Path], str],
                       stale: list[str]) -> dict[str, Any] | None:
    if descriptor is None:
        return None
    start = len(stale)
    if type(descriptor) is not dict or set(descriptor) != {"status", "url", "head_sha", "readback"}:
        stale.append("publication manifest entry must pin status, URL, head SHA, and readback")
        return {"status": "changed", "note": "publication readback pin malformed"}
    url = descriptor.get("url")
    head_sha = descriptor.get("head_sha")
    parsed = urlparse(url) if type(url) is str else None
    if (descriptor.get("status") != "published_for_review" or parsed is None or parsed.scheme != "https" or
            not parsed.path.rstrip("/").endswith("/pull/205") or parsed.query or parsed.fragment):
        stale.append("publication must identify HTTPS PR #205 published for review")
    if type(head_sha) is not str or len(head_sha) != 40 or any(c not in "0123456789abcdef" for c in head_sha):
        stale.append("publication head_sha must be a lowercase 40-character Git commit ID")
    readback, _, _ = _pinned_json(root, descriptor.get("readback"), hash_reader, stale, "publication.readback")
    if readback is not None:
        if (readback.get("number") != 205 or readback.get("url") != url or readback.get("head_sha") != head_sha or
                readback.get("production_authorized") is not False):
            stale.append("publication readback does not match PR #205 URL/head or production-denial boundary")
    if len(stale) > start:
        return {"status": "changed", "note": "publication readback did not validate"}
    path = descriptor["readback"]["path"]
    return {"status": "published_for_review", "url": url, "head_sha": head_sha,
            "readback": {"path": path, "sha256": descriptor["readback"]["sha256"]},
            "note": "PR #205 published for review; independent review/activation not selected"}


def _release_gates(inventory: dict[str, Any], packet: dict[str, Any], packet_status: str, stale: list[str],
                   publication: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    r1 = inventory.get("status") == "checked"
    r2 = packet_status == "checked" and packet.get("technical_status") == "PASS_PR_ONLY"
    r3 = r2 and packet.get("q38_recorded_status") == "PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED"
    r4 = r2 and packet.get("lifecycle_review") is not None
    return {
        "R1": {"status": "checked" if r1 else "changed", "note": "current source inventory and identity pins" if r1 else "source inventory/identity pins need refresh",
               "receipt": ({"root_sha512": inventory.get("current_root_sha512"),
                            "file_count": inventory.get("current_file_count")} if r1 else None)},
        "R2": {"status": "checked" if r2 else "changed", "note": packet.get("reuse_note") if r2 and packet.get("reuse_status") else ("pinned proof pair and technical packet" if r2 else "proof/technical packet needs recheck"), "receipt": packet.get("pair_manifest")},
        "R3": {"status": "checked" if r3 else "changed", "note": ("retained semantic-contract packet plus verified test-only delta; not a new semantic audit" if r3 and packet.get("reuse_status") else "final technical packet records semantic adapter pass; this evaluator checks pins, not semantics") if r3 else "semantic packet evidence needs recheck", "receipt": packet.get("technical_report")},
        "R4": {"status": "checked" if r4 else "changed", "note": packet.get("reuse_note") if r4 and packet.get("reuse_status") else ("recorded in-process/socket lifecycle evidence pins" if r4 else "lifecycle evidence needs recheck"), "receipt": packet.get("lifecycle_review")},
        "R5": {"status": "open", "note": publication["note"] if publication and publication.get("status") == "published_for_review" else "PR #205 review/publication remains open", "receipt": publication.get("readback") if publication else None},
    }


def _report(root: Path, manifest_digest: str | None, evaluation_digest: str | None,
            stale: list[str], endpoints: dict[str, dict[str, Any]], *,
            source_inventory: dict[str, Any] | None = None,
            release_gates: dict[str, dict[str, Any]] | None = None,
            packet: dict[str, Any] | None = None,
            release_boundary: dict[str, Any] | None = None,
            test_only_evidence_delta: dict[str, Any] | None = None,
            publication: dict[str, Any] | None = None) -> dict[str, Any]:
    endpoints = endpoints or {key: {"status": "changed" if stale else "open", "note": "manifest unavailable", "receipt": None} for key in ("S", "P", "A", "C")}
    source_inventory = source_inventory or {"status": "changed", "expected_root_sha512": None, "current_root_sha512": None}
    release_gates = release_gates or {key: {"status": "changed" if stale else "open", "note": "manifest unavailable", "receipt": None} for key in ("R1", "R2", "R3", "R4", "R5")}
    packet = packet or {}
    release_boundary = release_boundary or {"size_caps_bytes": SIZE_CAPS_BYTES,
                                            "production_authority_claimed": False,
                                            "r5_scope": "separate_pr_review_and_publication"}
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "root": str(root),
        "status": "needs_recheck" if stale else "evidence_current",
        "manifest_sha256": manifest_digest,
        "candidate_source_inventory": source_inventory,
        "endpoints": endpoints,
        "release_gates": release_gates,
        "packet": packet,
        "test_only_evidence_delta": test_only_evidence_delta,
        "publication": publication,
        "release_boundary": release_boundary,
        "stale_inputs": sorted(set(stale)),
        "production_authorized": False,
    }
    report["chart"] = {
        "endpoints": endpoints,
        "release_gates": release_gates,
        "root_note": (f"{sum(item['status'] == 'checked' for item in endpoints.values())}/4 endpoint strict/object/body pins match; "
                      f"technical packet {('retained pass under verified test-only delta, not a new run' if packet.get('reuse_status') else 'current') if release_gates.get('R2', {}).get('status') == 'checked' else 'needs recheck'}; "
                      f"R5 {publication['note'] if publication else 'PR #205 review/publication remains open'}. Production authority is not inferred."),
    }
    fingerprint_base = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["fingerprint_sha256"] = hashlib.sha256(fingerprint_base).hexdigest()
    return report


def render_checklist(report: dict[str, Any]) -> str:
    lines = [
        "# RP05 release evidence status",
        "",
        f"Status: **{report['status']}**. Generated from the canonical evidence manifest; this view is not production authorization.",
        "",
        f"Historical detailed checklist retained locally byte-for-byte (not part of the public PR packet): [{Path(HISTORY_PATH).name}](history/{Path(HISTORY_PATH).name}).",
        "",
        f"Manifest SHA-256: `{report.get('manifest_sha256') or 'unavailable'}`",
        "",
        f"Evaluation fingerprint: `{report['fingerprint_sha256']}`",
        "",
        f"Overall: {report['chart']['root_note']}",
        "",
        f"Candidate source inventory: **{report['candidate_source_inventory']['status']}** `{report['candidate_source_inventory'].get('current_root_sha512') or 'unavailable'}` ({report['candidate_source_inventory'].get('current_file_count', 'unknown')} files).",
        "Size caps (bytes): " + ", ".join(f"{key}={value}" for key, value in SIZE_CAPS_BYTES.items()) + ".",
        "",
        "| Endpoint | Evidence status | Receipt pins |",
        "|---|---|---|",
    ]
    delta = report.get("test_only_evidence_delta")
    if delta is not None:
        lines[-2:-2] = [f"Explicit test-only evidence delta: **{delta['status']}**. This annotation does not relabel the historical technical pass, refresh R1, or establish production authority.", ""]
    for key in ("S", "P", "A", "C"):
        item = report["endpoints"][key]
        receipt = item.get("receipt") or {}
        pins = ", ".join(str(v.get("path")) for v in receipt.values() if type(v) is dict) or "—"
        lines.append(f"| {item.get('name', key)} | {item['status']} — {item['note']} | {pins} |")
    lines.extend(["", "| Release gate | Status | Evidence / boundary |", "|---|---|---|"])
    for key in ("R1", "R2", "R3", "R4", "R5"):
        item = report["release_gates"][key]
        lines.append(f"| {key} | {item['status']} | {item['note']} |")
    lines.extend(["", "Pinned byte freshness is not a new Lean run, proof verification, semantic re-audit, execution authentication, or production authority. R5 is the separate PR review/publication step."])
    if report.get("stale_inputs"):
        lines.extend(["", f"The JSON report lists {len(report['stale_inputs'])} exact stale or changed input checks in `stale_inputs`."])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="check the generated checklist without writing")
    modes.add_argument("--write-checklist", action="store_true", help="explicitly export the generated checklist")
    modes.add_argument("--format", choices=("json", "checklist"), default="json")
    args = parser.parse_args(argv)
    report = evaluate(ROOT)
    rendered = render_checklist(report)
    if args.check:
        current = _read_regular(ROOT / CHECKLIST_PATH, 2 * 1024 * 1024).decode("utf-8")
        if current != rendered:
            print("generated checklist is stale; run with --write-checklist after review", file=sys.stderr)
            return 1
        print("checklist current")
        return 0
    if args.write_checklist:
        target = ROOT / CHECKLIST_PATH
        if target.is_symlink():
            raise StatusError("refusing to overwrite checklist symlink")
        target.write_text(rendered, encoding="utf-8")
        print(f"wrote {CHECKLIST_PATH}")
        return 0
    if args.format == "checklist":
        sys.stdout.write(rendered)
    else:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if report["status"] != "evidence_current" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StatusError as error:
        raise SystemExit(f"RP05 status evaluation failed: {error}")
