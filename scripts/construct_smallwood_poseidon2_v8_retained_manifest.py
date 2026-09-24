#!/usr/bin/env python3
"""Construct and verify a fail-closed candidate HGV8RP03 retained manifest.

This tool never writes the fixed retained pointer.  Construction requires an
explicit versioned artifact root and an explicit new candidate output.  The
candidate is first written to a private temporary file, fully verified there,
and then published with an atomic no-overwrite hard-link operation.
"""

from __future__ import annotations

import argparse
import errno
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


CHECKER_PATH = Path(__file__).with_name(
    "check_smallwood_poseidon2_v8_retained_artifacts.py"
)
SPEC = importlib.util.spec_from_file_location("retained_artifact_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import failure is fatal
    raise RuntimeError(f"cannot load retained artifact checker: {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


CandidateManifestError = CHECKER.RetainedArtifactError
CANDIDATE_MANIFEST_PREFIX = "retained-artifact-manifest.candidate"
RELATION_PROGRAM_SOURCE = "testdata/formal_core_vectors/poseidon2_v8_relation_program.bin"
RELATION_IDENTITY_SOURCE = "circuits/transaction/src/smallwood_poseidon2_v8_program.rs"


@dataclass(frozen=True)
class CandidateSnapshot:
    manifest: dict[str, Any]
    artifact_root: PurePosixPath
    root: Path
    roles: dict[str, PurePosixPath]
    reports: dict[str, dict[str, Any]]
    proof_records: list[dict[str, Any]]
    chain_report: dict[str, Any]
    source_inventory: dict[str, Any]
    relation_profile: CHECKER.RelationProfile
    filesystem_identities: frozenset[tuple[int, int]]


def require(condition: bool, message: str) -> None:
    CHECKER.require(condition, message)


def repository_relative_argument(
    repository_root: Path,
    value: str | Path,
    label: str,
) -> tuple[PurePosixPath, Path]:
    """Return one canonical repository-relative path without resolving aliases."""

    raw = str(value)
    pure = PurePosixPath(raw)
    require(raw == pure.as_posix(), f"{label}: noncanonical path spelling")
    if pure.is_absolute():
        absolute = Path(raw)
        try:
            relative_native = absolute.relative_to(repository_root)
        except ValueError:
            CHECKER.reject(f"{label}: path escapes the repository")
        relative = CHECKER.relative_path(relative_native.as_posix(), label)
    else:
        relative = CHECKER.relative_path(raw, label)
        absolute = repository_root / Path(relative.as_posix())
    require(absolute == repository_root / Path(relative.as_posix()),
            f"{label}: canonical repository path mismatch")
    return relative, absolute


def require_existing_regular_file(
    base: Path,
    relative: PurePosixPath,
    label: str,
) -> tuple[Path, os.stat_result]:
    path = CHECKER.ensure_no_symlink_path(base, relative, label)
    metadata = os.lstat(path)
    require(stat.S_ISREG(metadata.st_mode), f"{label}: not a regular file")
    require(metadata.st_nlink == 1, f"{label}: hardlink forbidden")
    return path, metadata


def current_source_revision(repository_root: Path, recorded_revision: str | None = None) -> str:
    # A generation commit is informational provenance. Covered source equality
    # is enforced independently by the complete live source inventory.
    if recorded_revision is not None:
        CHECKER.require_lower_hex(recorded_revision, 20, "recorded generation revision")
    git = shutil.which("git")
    require(git is not None, "git is required to bind the source revision")
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(
            dict.fromkeys((str(Path(git).parent), "/usr/bin", "/bin"))
        ),
        "TZ": "UTC",
    }
    try:
        result = subprocess.run(
            [git, "-C", str(repository_root), "rev-parse", "--verify",
             f"{recorded_revision or 'HEAD'}^{{commit}}"],
            check=False,
            close_fds=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        CHECKER.reject(f"cannot determine source revision: {error}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        CHECKER.reject(f"cannot determine source revision: {detail}")
    revision = result.stdout.decode("ascii", "strict").strip()
    CHECKER.require_lower_hex(revision, 20, "current source revision")
    require(recorded_revision is None or revision == recorded_revision,
            "recorded generation revision does not identify an exact existing commit")
    return revision


def candidate_artifact_root(
    repository_root: Path,
    value: str | Path,
) -> tuple[PurePosixPath, Path]:
    relative, root = repository_relative_argument(
        repository_root, value, "candidate artifact root"
    )
    require(relative.parent == CHECKER.ARTIFACT_PARENT,
            "candidate artifact root must be a direct child of the fixed artifact parent")
    checked = CHECKER.ensure_no_symlink_path(
        repository_root, relative, "candidate artifact root"
    )
    metadata = os.lstat(checked)
    require(stat.S_ISDIR(metadata.st_mode), "candidate artifact root is not a directory")
    require(checked.resolve() == root,
            "candidate artifact root canonical path mismatch")
    return relative, checked


def discover_role_directories(root: Path) -> dict[str, PurePosixPath]:
    roles: dict[str, PurePosixPath] = {}
    for role in CHECKER.ROLE_ORDER:
        parent = root / role
        metadata = os.lstat(parent)
        require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
                f"{role}: role path must be a real directory")
        children = list(parent.iterdir())
        require(len(children) == 1, f"{role}: expected exactly one proof directory")
        child = children[0]
        child_metadata = os.lstat(child)
        require(stat.S_ISDIR(child_metadata.st_mode)
                and not stat.S_ISLNK(child_metadata.st_mode),
                f"{role}: proof path must be a real directory")
        roles[role] = PurePosixPath(role) / child.name
    return roles


def exact_payload_paths(
    root: Path,
    roles: dict[str, PurePosixPath],
) -> tuple[list[PurePosixPath], frozenset[tuple[int, int]]]:
    expected = {
        *CHECKER.GENERATOR_PATHS,
        PurePosixPath("retained-chain-verification.json"),
    }
    for role in CHECKER.ROLE_ORDER:
        expected.update(roles[role] / name for name in CHECKER.ARTIFACT_FILES)
    require(len(expected) == 29, "candidate retained payload must contain exactly 29 files")
    actual_files, actual_directories = CHECKER.walk_exact(root)
    require(actual_files == expected,
            "candidate retained root file set differs from the exact 29-file layout")
    expected_directories = {
        parent
        for path in expected
        for parent in path.parents
        if str(parent) != "."
    }
    require(actual_directories == expected_directories,
            "candidate retained root directory set differs from the exact layout")

    identities: set[tuple[int, int]] = set()
    for relative in sorted(expected):
        path = CHECKER.ensure_no_symlink_path(root, relative, f"candidate payload {relative}")
        metadata = os.lstat(path)
        require(stat.S_ISREG(metadata.st_mode),
                f"candidate payload is not regular: {relative}")
        require(metadata.st_nlink == 1,
                f"candidate retained hardlink forbidden: {relative}")
        identity = (metadata.st_dev, metadata.st_ino)
        require(identity not in identities,
                f"candidate retained filesystem alias forbidden: {relative}")
        identities.add(identity)
    return sorted(expected), frozenset(identities)


def file_records(root: Path, paths: list[PurePosixPath]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    generator_paths = set(CHECKER.GENERATOR_PATHS)
    for relative in paths:
        path = root / Path(relative.as_posix())
        metadata = os.lstat(path)
        payload = path.read_bytes()
        executable = bool(metadata.st_mode & 0o111)
        require(executable is (relative in generator_paths),
                f"candidate executable status is not canonical: {relative}")
        records.append({
            "bytes": len(payload),
            "executable": executable,
            "path": relative.as_posix(),
            "sha512": CHECKER.sha512_bytes(payload),
        })
    return records


def source_inventory_summary(source_inventory: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(source_inventory, dict), "candidate source inventory is not an object")
    for key in ("file_count", "root_sha512", "schema", "total_bytes", "entries"):
        require(key in source_inventory, f"candidate source inventory missing {key}")
    summary = {
        key: source_inventory[key]
        for key in ("file_count", "root_sha512", "schema", "total_bytes")
    }
    require(summary["schema"] == CHECKER.SOURCE_INVENTORY_SCHEMA,
            "candidate source inventory schema")
    CHECKER.require_lower_hex(summary["root_sha512"], 64,
                              "candidate source inventory root")
    require(summary["root_sha512"] != "0" * 128,
            "candidate source inventory root must be nonzero")
    require(isinstance(summary["file_count"], int) and summary["file_count"] > 0,
            "candidate source inventory file count")
    require(isinstance(summary["total_bytes"], int) and summary["total_bytes"] > 0,
            "candidate source inventory byte count")
    return summary


def generator_record(
    repository_root: Path,
    root: Path,
    source_inventory: dict[str, Any],
    payload_identities: frozenset[tuple[int, int]],
) -> tuple[dict[str, Any], tuple[int, int]]:
    payloads = [
        (root / Path(relative.as_posix())).read_bytes()
        for relative in CHECKER.GENERATOR_PATHS
    ]
    require(payloads[0] == payloads[1],
            "candidate generator binaries are not byte identical")
    binary_hash = CHECKER.sha512_bytes(payloads[0])

    source_relative = CHECKER.relative_path(
        CHECKER.GENERATOR_SOURCE, "candidate generator source"
    )
    source_path, source_metadata = require_existing_regular_file(
        repository_root, source_relative, "candidate generator source"
    )
    source_identity = (source_metadata.st_dev, source_metadata.st_ino)
    require(source_identity not in payload_identities,
            "candidate generator source aliases a retained payload")
    source_payload = source_path.read_bytes()
    source_hash = CHECKER.sha512_bytes(source_payload)
    entries = source_inventory.get("entries")
    require(isinstance(entries, list), "candidate source inventory entries")
    matches = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("path") == CHECKER.GENERATOR_SOURCE
    ]
    require(matches == [{
        "bytes": len(source_payload),
        "path": CHECKER.GENERATOR_SOURCE,
        "sha512": source_hash,
    }], "candidate generator source is not exactly bound by the source inventory")
    return ({
        "byte_identical": True,
        "bytes": len(payloads[0]),
        "paths": [relative.as_posix() for relative in CHECKER.GENERATOR_PATHS],
        "sha512": binary_hash,
        "source_path": CHECKER.GENERATOR_SOURCE,
        "source_sha512": source_hash,
    }, source_identity)


def proof_record_from_report(
    role: str,
    directory: PurePosixPath,
    report: dict[str, Any],
    proof: bytes,
) -> dict[str, Any]:
    provenance = report.get("generation_provenance")
    randomness = report.get("proof_randomness_binding")
    require(isinstance(provenance, dict), f"{role}: generation provenance")
    require(isinstance(randomness, dict), f"{role}: proof randomness binding")
    record = {
        "artifact_role": role,
        "decs_transcript_root_hex": randomness.get("decs_transcript_root_hex"),
        "directory": directory.as_posix(),
        "generation_run_id_hex": provenance.get("run_id_hex"),
        "proof": {
            "bytes": len(proof),
            "sha512": CHECKER.sha512_bytes(proof),
        },
        "wire_salt_hex": randomness.get("wire_salt_hex"),
    }
    require(set(record) == {
        "artifact_role", "decs_transcript_root_hex", "directory",
        "generation_run_id_hex", "proof", "wire_salt_hex",
    }, f"{role}: candidate proof record fields")
    proof_hash = CHECKER.require_lower_hex(
        record["proof"]["sha512"], 64, f"{role}: candidate proof hash"
    )
    require(directory.parent == PurePosixPath(role),
            f"{role}: proof directory must be a direct child of its role")
    require(directory.name == f"smz9-{proof_hash[:24]}",
            f"{role}: proof directory does not bind its proof hash")
    CHECKER.require_lower_hex(record["generation_run_id_hex"], 32,
                              f"{role}: candidate generation run id")
    CHECKER.require_lower_hex(record["wire_salt_hex"], 32,
                              f"{role}: candidate wire salt")
    CHECKER.require_lower_hex(record["decs_transcript_root_hex"], 64,
                              f"{role}: candidate transcript root")
    return record


def source_relation_profile(
    repository_root: Path,
    source_inventory: dict[str, Any],
) -> tuple[CHECKER.RelationProfile, bytes, frozenset[tuple[int, int]]]:
    """Select only an exact supported program bound by the live source inventory."""

    source, metadata = require_existing_regular_file(
        repository_root, PurePosixPath(RELATION_PROGRAM_SOURCE), "candidate relation source"
    )
    program = source.read_bytes()
    identity_source, identity_metadata = require_existing_regular_file(
        repository_root, PurePosixPath(RELATION_IDENTITY_SOURCE), "candidate relation identity source"
    )
    identity_payload = identity_source.read_bytes()
    entries = source_inventory.get("entries")
    require(isinstance(entries, list), "candidate source inventory entries")
    matches = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("path") == RELATION_IDENTITY_SOURCE
    ]
    require(matches == [{
        "bytes": len(identity_payload), "path": RELATION_IDENTITY_SOURCE,
        "sha512": CHECKER.sha512_bytes(identity_payload),
    }], "candidate relation identity source is not exactly bound by the source inventory")
    source_text = identity_payload.decode("utf-8", "strict")

    def exact_constant(name: str, suffix: str) -> str:
        matches = re.findall(r"^pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_" + name
                             + suffix, source_text, re.MULTILINE)
        require(len(matches) == 1, f"candidate relation source constant {name}")
        return matches[0]

    magic = exact_constant("MAGIC", r': \[u8; 8\] = \*b"([^"\n]+)";')
    program_bytes = int(exact_constant("TRANSCRIPT_BYTES", r": usize = ([0-9_]+);")
                        .replace("_", ""))

    def byte_constant(name: str, length: int) -> bytes:
        body = exact_constant(name, r": \[u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_"
                              + name + r"_BYTES\] = \[([^\]]+)\];")
        require(re.fullmatch(r"\s*(?:0x[0-9a-f]{2},\s*)+", body) is not None,
                f"candidate relation source {name} byte grammar")
        value = bytes(int(word, 16) for word in re.findall(r"0x[0-9a-f]{2}", body))
        require(len(value) == length, f"candidate relation source {name} length")
        return value

    program_hash = byte_constant("SHA512", 64).hex()
    digest = byte_constant("DIGEST", 48).hex()
    require(magic == CHECKER.RELATION_MAGIC.decode(), "candidate relation source magic")
    require(digest == program_hash[:96], "candidate relation source digest prefix")
    profiles = [
        profile for profile in CHECKER.SUPPORTED_RELATION_PROFILES
        if profile.program_bytes == program_bytes and profile.program_sha512 == program_hash
    ]
    require(len(profiles) == 1, "candidate source has unsupported exact relation identity")
    profile = profiles[0]
    CHECKER.check_relation_program(program, profile)
    return profile, program, frozenset((
        (metadata.st_dev, metadata.st_ino),
        (identity_metadata.st_dev, identity_metadata.st_ino),
    ))


def manifest_identity(relation_profile: CHECKER.RelationProfile) -> dict[str, Any]:
    return {
        "inner_magic": CHECKER.INNER_MAGIC.decode(),
        "network_id": CHECKER.NETWORK_ID,
        "relation_digest_hex": relation_profile.digest_hex,
        "relation_magic": CHECKER.RELATION_MAGIC.decode(),
        "relation_program_bytes": relation_profile.program_bytes,
        "relation_program_sha512": relation_profile.program_sha512,
        "route": CHECKER.ROUTE,
        "semantic_relation": CHECKER.RELATION_NAME,
    }


def build_candidate_snapshot(
    repository_root: Path,
    artifact_root_value: str | Path,
) -> CandidateSnapshot:
    repository_root = repository_root.resolve()
    artifact_root, root = candidate_artifact_root(repository_root, artifact_root_value)
    roles = discover_role_directories(root)
    paths, payload_identities = exact_payload_paths(root, roles)
    records = file_records(root, paths)

    source_inventory = CHECKER.recompute_source_inventory(repository_root)
    relation_profile, source_program, relation_source_identities = source_relation_profile(
        repository_root, source_inventory
    )
    source_summary = source_inventory_summary(source_inventory)
    require(artifact_root.name == f"hgv8rp03-{source_summary['root_sha512'][:16]}",
            "candidate artifact root does not bind the live source inventory root")
    generation_revisions = [
        CHECKER.load_json_exact(root / Path(roles[role].as_posix()) / "artifact-report.json")
        [0].get("generation_provenance", {}).get("source_revision")
        for role in CHECKER.ROLE_ORDER
    ]
    for revision in generation_revisions:
        CHECKER.require_lower_hex(revision, 20, "candidate generation revision")
    require(generation_revisions[0] == generation_revisions[1],
            "candidate generation revisions differ")
    source_revision = current_source_revision(repository_root, generation_revisions[0])
    generator, source_identity = generator_record(
        repository_root, root, source_inventory, payload_identities
    )
    require(relation_source_identities.isdisjoint(payload_identities)
            and source_identity not in relation_source_identities,
            "candidate relation source aliases retained payload or generator source")
    all_identities = frozenset((*payload_identities, source_identity, *relation_source_identities))

    reports: dict[str, dict[str, Any]] = {}
    proof_records: list[dict[str, Any]] = []
    for role in CHECKER.ROLE_ORDER:
        bundle = root / Path(roles[role].as_posix())
        report, _ = CHECKER.load_json_exact(bundle / "artifact-report.json")
        require((bundle / "relation-program.bin").read_bytes() == source_program,
                f"{role}: artifact relation differs from canonical source program")
        native = CHECKER.parse_native_leaf(bundle, relation_profile=relation_profile)
        transport = CHECKER.parse_rpc_and_scale(bundle, native)
        proof = native["proof"]
        require(isinstance(proof, bytes), f"{role}: decoded proof is not bytes")
        CHECKER.parse_pending_action(bundle, transport, proof)
        record = proof_record_from_report(role, roles[role], report, proof)
        checked_report = CHECKER.check_report(
            bundle,
            role,
            record,
            native,
            transport,
            source_inventory,
            generator,
            expected_source_revision=source_revision,
            relation_profile=relation_profile,
        )
        reports[role] = checked_report
        proof_records.append(record)

    require([record["artifact_role"] for record in proof_records]
            == list(CHECKER.ROLE_ORDER), "candidate proof record order")
    for field, label in (
        ("proof", "proof hashes"),
        ("wire_salt_hex", "wire salts"),
        ("decs_transcript_root_hex", "transcript roots"),
        ("generation_run_id_hex", "generation run ids"),
    ):
        values = [
            record[field]["sha512"] if field == "proof" else record[field]
            for record in proof_records
        ]
        require(len(set(values)) == 2, f"candidate retained {label} are not distinct")
    require(reports[CHECKER.ROLE_ORDER[0]]["proof_source_inventory"]
            == reports[CHECKER.ROLE_ORDER[1]]["proof_source_inventory"],
            "candidate retained proof source inventories differ")

    common_payload: dict[str, dict[str, Any]] = {}
    for name in CHECKER.COMMON_FILES:
        payloads = [
            (root / Path(roles[role].as_posix()) / name).read_bytes()
            for role in CHECKER.ROLE_ORDER
        ]
        require(payloads[0] == payloads[1],
                f"candidate common payload differs: {name}")
        common_payload[name] = {
            "bytes": len(payloads[0]),
            "sha512": CHECKER.sha512_bytes(payloads[0]),
        }

    chain_path = root / "retained-chain-verification.json"
    chain_payload = chain_path.read_bytes()
    chain_record = {
        "bytes": len(chain_payload),
        "path": "retained-chain-verification.json",
        "sha512": CHECKER.sha512_bytes(chain_payload),
    }
    manifest = {
        "artifact_root": artifact_root.as_posix(),
        "authority": CHECKER.AUTHORITY,
        "chain_verification": chain_record,
        "common_payload": common_payload,
        "files": records,
        "generator_binaries": generator,
        "identity": manifest_identity(relation_profile),
        "payload_file_count": len(records),
        "payload_inventory_sha512": CHECKER.inventory_sha512(records),
        "payload_total_bytes": sum(record["bytes"] for record in records),
        "proofs": proof_records,
        "schema": CHECKER.MANIFEST_SCHEMA,
        "source_inventory": source_summary,
    }
    chain_report = CHECKER.check_chain_report(
        root, artifact_root, roles, manifest, reports, relation_profile=relation_profile
    )
    return CandidateSnapshot(
        manifest=manifest,
        artifact_root=artifact_root,
        root=root,
        roles=roles,
        reports=reports,
        proof_records=proof_records,
        chain_report=chain_report,
        source_inventory=source_inventory,
        relation_profile=relation_profile,
        filesystem_identities=all_identities,
    )


def candidate_manifest_path(
    repository_root: Path,
    value: str | Path,
    artifact_root: PurePosixPath,
    *,
    must_exist: bool,
) -> tuple[PurePosixPath, Path]:
    relative, path = repository_relative_argument(
        repository_root, value, "candidate manifest"
    )
    require(relative != CHECKER.MANIFEST_PATH,
            "candidate tooling refuses to read or write the fixed retained pointer")
    require(relative.parts[:len(artifact_root.parts)] != artifact_root.parts,
            "candidate manifest must be outside the retained artifact root")
    parent = relative.parent
    require(parent == CHECKER.ARTIFACT_PARENT,
            "candidate manifest must be a direct child of the retained artifact parent")
    require(relative.name.startswith(CANDIDATE_MANIFEST_PREFIX)
            and relative.name.endswith(".json"),
            "candidate manifest must have an explicit candidate JSON name")
    parent_path = CHECKER.ensure_no_symlink_path(
        repository_root, parent, "candidate manifest parent"
    )
    require(stat.S_ISDIR(os.lstat(parent_path).st_mode),
            "candidate manifest parent is not a directory")
    if must_exist:
        checked = CHECKER.ensure_no_symlink_path(
            repository_root, relative, "candidate manifest"
        )
        require(checked == path, "candidate manifest canonical path mismatch")
    return relative, path


def run_candidate_verifiers(
    snapshot: CandidateSnapshot,
    repository_root: Path,
) -> None:
    CHECKER.run_frozen_verifiers(
        snapshot.root,
        snapshot.artifact_root,
        snapshot.roles,
        snapshot.proof_records,
        snapshot.chain_report,
        repository_root,
        relation_profile=snapshot.relation_profile,
        expected_generation_provenance={
            role: snapshot.reports[role]["generation_provenance"] for role in CHECKER.ROLE_ORDER
        },
    )


def verify_candidate_manifest(
    manifest_value: str | Path,
    artifact_root_value: str | Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    repository_root = (
        repository_root if repository_root is not None
        else CHECKER.discover_repository_root()
    ).resolve()
    artifact_root, _ = candidate_artifact_root(repository_root, artifact_root_value)
    _, manifest_path = candidate_manifest_path(
        repository_root, manifest_value, artifact_root, must_exist=True
    )
    metadata = os.lstat(manifest_path)
    require(stat.S_ISREG(metadata.st_mode), "candidate manifest is not a regular file")
    require(metadata.st_nlink == 1, "candidate manifest hardlink forbidden")
    manifest_identity_tuple = (metadata.st_dev, metadata.st_ino)
    manifest, raw = CHECKER.load_json_exact(manifest_path, canonical=True)

    snapshot = build_candidate_snapshot(repository_root, artifact_root.as_posix())
    require(manifest_identity_tuple not in snapshot.filesystem_identities,
            "candidate manifest aliases retained payload or generator source")
    require(manifest == snapshot.manifest,
            "candidate manifest differs from the exact derived schema-v2 manifest")
    run_candidate_verifiers(snapshot, repository_root)

    after = build_candidate_snapshot(repository_root, artifact_root.as_posix())
    require(after.manifest == snapshot.manifest,
            "candidate artifact or source changed during verification")
    require(manifest_path.read_bytes() == raw,
            "candidate manifest changed during verification")
    after_metadata = os.lstat(manifest_path)
    require((after_metadata.st_dev, after_metadata.st_ino) == manifest_identity_tuple
            and after_metadata.st_nlink == 1,
            "candidate manifest filesystem identity changed during verification")
    return {
        "artifact_root": artifact_root.as_posix(),
        "candidate_manifest": str(manifest_path.relative_to(repository_root)),
        "candidate_manifest_sha512": CHECKER.sha512_bytes(raw),
        "generator_binary_sha512": manifest["generator_binaries"]["sha512"],
        "payload_file_count": manifest["payload_file_count"],
        "payload_inventory_sha512": manifest["payload_inventory_sha512"],
        "payload_total_bytes": manifest["payload_total_bytes"],
        "production_capability_enabled": False,
        "schema": "hegemon-smallwood-poseidon2-v8-retained-candidate-check-v2",
        "source_inventory_root_sha512": manifest["source_inventory"]["root_sha512"],
        "verified": True,
    }


def fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def construct_candidate_manifest(
    artifact_root_value: str | Path,
    output_value: str | Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    repository_root = (
        repository_root if repository_root is not None
        else CHECKER.discover_repository_root()
    ).resolve()
    artifact_root, _ = candidate_artifact_root(repository_root, artifact_root_value)
    _, output_path = candidate_manifest_path(
        repository_root, output_value, artifact_root, must_exist=False
    )
    require(not os.path.lexists(output_path),
            "candidate manifest output already exists; refusing overwrite")

    snapshot = build_candidate_snapshot(repository_root, artifact_root.as_posix())
    payload = CHECKER.canonical_json(snapshot.manifest)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{output_path.stem}.tmp-", suffix=".json", dir=output_path.parent
    )
    temporary_path = Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o600)
        verify_candidate_manifest(
            temporary_path,
            artifact_root.as_posix(),
            repository_root=repository_root,
        )
        try:
            os.link(temporary_path, output_path)
        except FileExistsError:
            CHECKER.reject("candidate manifest output already exists; refusing overwrite")
        except OSError as error:
            if error.errno == errno.EEXIST:
                CHECKER.reject("candidate manifest output already exists; refusing overwrite")
            raise
        published = True
        temporary_path.unlink()
        fsync_directory(output_path.parent)
        output_metadata = os.lstat(output_path)
        require(stat.S_ISREG(output_metadata.st_mode) and output_metadata.st_nlink == 1,
                "published candidate manifest is not a unique regular file")
        observed = output_path.read_bytes()
        require(observed == payload,
                "published candidate manifest differs from verified temporary bytes")
        return {
            "artifact_root": artifact_root.as_posix(),
            "candidate_manifest": str(output_path.relative_to(repository_root)),
            "candidate_manifest_sha512": CHECKER.sha512_bytes(observed),
            "payload_file_count": snapshot.manifest["payload_file_count"],
            "payload_inventory_sha512": snapshot.manifest["payload_inventory_sha512"],
            "payload_total_bytes": snapshot.manifest["payload_total_bytes"],
            "production_capability_enabled": False,
            "schema": "hegemon-smallwood-poseidon2-v8-retained-candidate-construction-v2",
            "verified_before_atomic_publish": True,
            "written": True,
        }
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
        if not published:
            fsync_directory(output_path.parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    construct = subparsers.add_parser("construct", help="construct a new candidate manifest")
    construct.add_argument("--artifact-root", required=True,
                           help="explicit repository-contained versioned artifact root")
    construct.add_argument("--output", required=True,
                           help="new retained-artifact-manifest.candidate*.json path; never overwritten")
    verify = subparsers.add_parser("verify", help="verify an existing candidate manifest")
    verify.add_argument("--artifact-root", required=True,
                        help="explicit repository-contained versioned artifact root")
    verify.add_argument("--manifest", required=True,
                        help="retained-artifact-manifest.candidate*.json path; fixed pointer forbidden")
    args = parser.parse_args(argv)
    try:
        if args.command == "construct":
            summary = construct_candidate_manifest(args.artifact_root, args.output)
        else:
            summary = verify_candidate_manifest(args.manifest, args.artifact_root)
    except (OSError, CandidateManifestError, KeyError, TypeError, ValueError) as error:
        print(f"retained candidate manifest failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
