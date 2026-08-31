#!/usr/bin/env python3
"""Generate and independently audit one full SmallWood/BLAKE2b artifact.

This is the byte-level harness for the dormant BLAKE2b-384 profile.  It is
deliberately fail-closed: it will not invoke a prover while the 28 GiB free
disk gate is closed, and it requires an integration marker that says the
Boolean relation and the profile backend are actually compiled.  A semantic
hash transcript or a scalar relation trace is not accepted as proof bytes.

The prover command is an adapter boundary.  It must write one complete
canonical SWV5 envelope to the requested output path.  A verifier command is
also required for generation and must accept the following appended options:

    --verify ARTIFACT --network-id N --family-id 1 --action-id 7
    --relation-binding-hex HEX --statement-hex HEX

The verifier is launched as a fresh process for the original artifact and for
each mutation.  The resulting JSON manifest is evidence of exact byte
handling and measured size only; it does not authorize the profile or claim
strict PQ/ZK security.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn, Sequence


MAGIC = b"SWV5"
ENVELOPE_VERSION = 1
CIRCUIT_VERSION = 5
CRYPTO_SUITE = 4
BACKEND_WIRE_ID = 2
PROFILE_WIRE_ID = 1
INLINE_MODE = 1
FAMILY_ID = 1
ACTION_ID = 7
PUBLIC_VALUE_COUNT = 78
PUBLIC_VALUES_BYTES = PUBLIC_VALUE_COUNT * 8
BALANCE_TAG_BYTES = 48
STATEMENT_BYTES = PUBLIC_VALUES_BYTES + BALANCE_TAG_BYTES
HEADER_BYTES = 80
MAX_ENVELOPE_BYTES = 512 * 1024
MAX_PROOF_BYTES = MAX_ENVELOPE_BYTES - HEADER_BYTES - STATEMENT_BYTES
GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001
MIN_FREE_DISK_BYTES = 28 * 1024**3

OFFSET_MAGIC = 0
OFFSET_ENVELOPE_VERSION = 4
OFFSET_CIRCUIT = 6
OFFSET_CRYPTO = 8
OFFSET_BACKEND = 10
OFFSET_PROFILE = 11
OFFSET_MODE = 12
OFFSET_RESERVED = 13
OFFSET_NETWORK = 16
OFFSET_FAMILY = 20
OFFSET_ACTION = 22
OFFSET_STATEMENT_LEN = 24
OFFSET_PROOF_LEN = 28
OFFSET_RELATION_BINDING = 32

DEFAULT_PROFILE_ID = "smallwood-v5-conventional-hash-blake2b384-inline-v1"
DEFAULT_MARKER = Path(".agent/smallwood-blake2b384-proof-backend-ready.json")


class ArtifactError(ValueError):
    """Malformed bytes, manifest, or failed mutation/verifier evidence."""


def fail(message: str) -> NoReturn:
    raise ArtifactError(message)


@dataclass(frozen=True)
class Envelope:
    raw: bytes
    network_id: int
    relation_binding: bytes
    statement: bytes
    proof: bytes


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _check_statement(statement: bytes) -> None:
    if len(statement) != STATEMENT_BYTES:
        fail(f"statement has {len(statement)} bytes, expected {STATEMENT_BYTES}")
    for index in range(PUBLIC_VALUE_COUNT):
        value = int.from_bytes(statement[index * 8 : index * 8 + 8], "little")
        if value >= GOLDILOCKS_MODULUS:
            fail(f"public statement word {index} is non-canonical")


def parse_envelope(data: bytes) -> Envelope:
    """Parse exactly the canonical envelope without allocating proof regions."""

    if len(data) > MAX_ENVELOPE_BYTES:
        fail(f"envelope exceeds cap: {len(data)} > {MAX_ENVELOPE_BYTES}")
    if len(data) < HEADER_BYTES:
        fail(f"envelope header truncated: {len(data)} < {HEADER_BYTES}")
    if data[OFFSET_MAGIC : OFFSET_MAGIC + 4] != MAGIC:
        fail("invalid envelope magic")
    if _u16(data, OFFSET_ENVELOPE_VERSION) != ENVELOPE_VERSION:
        fail("unsupported envelope version")
    if _u16(data, OFFSET_CIRCUIT) != CIRCUIT_VERSION:
        fail("unsupported circuit version")
    if _u16(data, OFFSET_CRYPTO) != CRYPTO_SUITE:
        fail("unsupported crypto suite")
    if data[OFFSET_BACKEND] != BACKEND_WIRE_ID:
        fail("unsupported backend wire id")
    if data[OFFSET_PROFILE] != PROFILE_WIRE_ID:
        fail("unsupported profile wire id")
    if data[OFFSET_MODE] != INLINE_MODE:
        fail("non-inline proof mode")
    if data[OFFSET_RESERVED : OFFSET_RESERVED + 3] != b"\0\0\0":
        fail("reserved header bytes are nonzero")
    if _u16(data, OFFSET_FAMILY) != FAMILY_ID:
        fail("unsupported family id")
    if _u16(data, OFFSET_ACTION) != ACTION_ID:
        fail("unsupported action id")
    statement_len = _u32(data, OFFSET_STATEMENT_LEN)
    if statement_len != STATEMENT_BYTES:
        fail(f"statement length is {statement_len}, expected {STATEMENT_BYTES}")
    proof_len = _u32(data, OFFSET_PROOF_LEN)
    if proof_len == 0:
        fail("empty proof")
    if proof_len > MAX_PROOF_BYTES:
        fail(f"proof exceeds cap: {proof_len} > {MAX_PROOF_BYTES}")
    total = HEADER_BYTES + statement_len + proof_len
    if len(data) < total:
        fail(f"envelope truncated: {len(data)} < declared {total}")
    if len(data) > total:
        fail(f"envelope has {len(data) - total} trailing bytes")
    relation_binding = data[
        OFFSET_RELATION_BINDING : OFFSET_RELATION_BINDING + BALANCE_TAG_BYTES
    ]
    if relation_binding == b"\0" * BALANCE_TAG_BYTES:
        fail("zero relation binding")
    statement = data[HEADER_BYTES : HEADER_BYTES + STATEMENT_BYTES]
    _check_statement(statement)
    proof = data[HEADER_BYTES + STATEMENT_BYTES : total]
    return Envelope(
        raw=data,
        network_id=_u32(data, OFFSET_NETWORK),
        relation_binding=relation_binding,
        statement=statement,
        proof=proof,
    )


def _repo_relative(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError as exc:
        raise ArtifactError(f"path escapes repository: {path}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read JSON {path}: {exc}") from exc


def require_integration_marker(path: Path) -> dict[str, object]:
    marker = _load_json(path)
    if not isinstance(marker, dict):
        fail("integration marker must be an object")
    for key in ("boolean_relation_compiled", "profile_integrated", "profile_id"):
        if key not in marker:
            fail(f"integration marker missing {key}")
    if marker["boolean_relation_compiled"] is not True:
        fail("BLAKE2b Boolean relation is not compiled")
    if marker["profile_integrated"] is not True:
        fail("BLAKE2b proof backend/profile is not integrated")
    profile_id = marker["profile_id"]
    if not isinstance(profile_id, str) or "blake2b" not in profile_id.lower():
        fail("integration marker profile_id is not a BLAKE2b profile")
    if marker.get("relation_hash_output_bits") != 384:
        fail("integration marker must identify a 384-bit BLAKE2b relation hash")
    return marker


def require_disk(root: Path, minimum_bytes: int = MIN_FREE_DISK_BYTES) -> int:
    usage = shutil.disk_usage(root)
    if usage.free < minimum_bytes:
        free_gib = usage.free / 1024**3
        minimum_gib = minimum_bytes / 1024**3
        fail(
            f"disk gate closed: {free_gib:.2f} GiB free, "
            f"{minimum_gib:.0f} GiB required; prover was not invoked"
        )
    return usage.free


def _command(command: str, substitutions: dict[str, str], extra: Sequence[str]) -> list[str]:
    rendered = command
    for key, value in substitutions.items():
        rendered = rendered.replace("{" + key + "}", value)
    if "{extra}" in rendered:
        rendered = rendered.replace("{extra}", shlex.join(extra))
        extra = ()
    argv = shlex.split(rendered)
    if not argv:
        fail("empty prover/verifier command")
    argv.extend(extra)
    return argv


def _run_command(command: str, substitutions: dict[str, str], extra: Sequence[str]) -> None:
    argv = _command(command, substitutions, extra)
    result = subprocess.run(argv, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        output = (result.stderr or result.stdout).strip()
        fail(f"command failed ({result.returncode}): {' '.join(argv)}\n{output}")


def _verifier_extra(envelope: Envelope, artifact: Path) -> list[str]:
    return [
        "--verify",
        str(artifact),
        "--network-id",
        str(envelope.network_id),
        "--family-id",
        str(FAMILY_ID),
        "--action-id",
        str(ACTION_ID),
        "--relation-binding-hex",
        envelope.relation_binding.hex(),
        "--statement-hex",
        envelope.statement.hex(),
    ]


def verify_with_fresh_process(command: str, envelope: Envelope, artifact: Path) -> None:
    """Run the backend verifier in a new process; callers may invoke twice."""

    _run_command(
        command,
        {"artifact": str(artifact)},
        _verifier_extra(envelope, artifact),
    )


def _run_mutation_verifier(
    command: str, envelope: Envelope, artifact: Path, should_accept: bool
) -> None:
    argv = _command(
        command,
        {"artifact": str(artifact)},
        _verifier_extra(envelope, artifact),
    )
    result = subprocess.run(argv, check=False, text=True, capture_output=True)
    accepted = result.returncode == 0
    if accepted != should_accept:
        output = (result.stderr or result.stdout).strip()
        fail(
            f"verifier mutation result mismatch for {' '.join(argv)}: "
            f"accepted={accepted}, expected={should_accept}\n{output}"
        )


def _mutate(name: str, raw: bytes) -> bytes:
    data = bytearray(raw)
    if name == "statement":
        data[HEADER_BYTES] ^= 1
    elif name == "proof":
        data[-1] ^= 1
    elif name == "relation":
        data[OFFSET_RELATION_BINDING] ^= 1
    elif name == "network":
        data[OFFSET_NETWORK] ^= 1
    elif name == "profile":
        data[OFFSET_PROFILE] ^= 1
    elif name == "version":
        data[OFFSET_CIRCUIT] ^= 1
    elif name == "action":
        data[OFFSET_ACTION] ^= 1
    elif name == "truncated":
        return bytes(data[:-1])
    elif name == "trailing":
        return bytes(data) + b"\0"
    elif name == "empty-proof":
        data[OFFSET_PROOF_LEN : OFFSET_PROOF_LEN + 4] = (0).to_bytes(4, "little")
    elif name == "statement-length":
        data[OFFSET_STATEMENT_LEN : OFFSET_STATEMENT_LEN + 4] = (STATEMENT_BYTES - 8).to_bytes(
            4, "little"
        )
    else:
        fail(f"unknown mutation {name}")
    return bytes(data)


MUTATIONS: tuple[tuple[str, bool], ...] = (
    ("statement", True),
    ("proof", True),
    ("relation", True),
    ("network", True),
    ("profile", False),
    ("version", False),
    ("action", False),
    ("truncated", False),
    ("trailing", False),
    ("empty-proof", False),
    ("statement-length", False),
)


def run_mutation_suite(
    root: Path, envelope: Envelope, verifier_command: str | None
) -> dict[str, str]:
    """Require parser rejection and, where parsing succeeds, backend rejection."""

    outcomes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="hegemon-smallwood-mutations-") as temp:
        temp_root = Path(temp)
        for name, parser_accepts in MUTATIONS:
            mutated = _mutate(name, envelope.raw)
            mutated_path = temp_root / f"{name}.swv5"
            mutated_path.write_bytes(mutated)
            try:
                parsed = parse_envelope(mutated)
            except ArtifactError:
                parsed = None
            accepted = parsed is not None
            if accepted != parser_accepts:
                fail(
                    f"mutation {name} parser result mismatch: "
                    f"accepted={accepted}, expected={parser_accepts}"
                )
            if accepted:
                if verifier_command is None:
                    fail(f"mutation {name} requires a verifier command")
                _run_mutation_verifier(verifier_command, envelope, mutated_path, False)
                outcomes[name] = "backend_rejected"
            else:
                outcomes[name] = "parser_rejected"
    return outcomes


def _manifest(root: Path, artifact_path: Path, envelope: Envelope, marker: dict[str, object],
              mutation_outcomes: dict[str, str], verifier_command: str) -> dict[str, object]:
    proof_hash = _sha256(envelope.proof)
    statement_hash = _sha256(envelope.statement)
    return {
        "schema_version": 1,
        "profile_id": marker["profile_id"],
        "posture": "prototype_only",
        "strict_security_authorized": False,
        "claim_boundary": (
            "One exact maximum-shape BLAKE2b-384 SmallWood artifact and byte-level "
            "verification evidence. This does not establish complete ZK, PQ128, "
            "deployed soundness, formal refinement, or production authorization."
        ),
        "identity": {
            "magic_ascii": MAGIC.decode("ascii"),
            "envelope_version": ENVELOPE_VERSION,
            "circuit": CIRCUIT_VERSION,
            "crypto_suite": CRYPTO_SUITE,
            "backend_wire_id": BACKEND_WIRE_ID,
            "profile_wire_id": PROFILE_WIRE_ID,
            "proof_mode": "inline_only",
            "network_id": envelope.network_id,
            "family_id": FAMILY_ID,
            "action_id": ACTION_ID,
        },
        "relation": {
            "hash": "RFC7693-BLAKE2b-384",
            "hash_output_bits": 384,
            "composition_margin_bits": 0,
            "schedule_digest_hex": envelope.relation_binding.hex(),
            "schedule_digest_bytes": len(envelope.relation_binding),
            "boolean_relation_compiled": marker["boolean_relation_compiled"],
        },
        "shape": {
            "maximum_transaction": True,
            "active_inputs": 2,
            "active_outputs": 2,
            "activity_mask": 15,
            "authorization_mode": "SingleKey",
            "all_active": True,
        },
        "bytes": {
            "header": HEADER_BYTES,
            "statement": len(envelope.statement),
            "public_values": PUBLIC_VALUES_BYTES,
            "balance_tag": BALANCE_TAG_BYTES,
            "proof": len(envelope.proof),
            "envelope": len(envelope.raw),
            "proof_sha256": proof_hash,
            "statement_sha256": statement_hash,
            "envelope_sha256": _sha256(envelope.raw),
            "artifact_path": _repo_relative(root, artifact_path),
        },
        "verifier": {
            "fresh_process_runs": 2,
            "exact_consumption": True,
            "mutation_suite": mutation_outcomes,
            "command": verifier_command,
        },
    }


def write_manifest(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_manifest(root: Path, manifest_path: Path) -> tuple[Envelope, dict[str, object]]:
    document = _load_json(manifest_path)
    if not isinstance(document, dict):
        fail("artifact manifest must be an object")
    if document.get("schema_version") != 1:
        fail("unsupported artifact manifest schema")
    if document.get("posture") != "prototype_only":
        fail("artifact manifest must remain prototype_only")
    if document.get("strict_security_authorized") is not False:
        fail("artifact manifest cannot self-authorize strict security")
    identity = document.get("identity")
    if not isinstance(identity, dict):
        fail("manifest identity missing")
    expected_identity = {
        "magic_ascii": MAGIC.decode("ascii"),
        "envelope_version": ENVELOPE_VERSION,
        "circuit": CIRCUIT_VERSION,
        "crypto_suite": CRYPTO_SUITE,
        "backend_wire_id": BACKEND_WIRE_ID,
        "profile_wire_id": PROFILE_WIRE_ID,
        "proof_mode": "inline_only",
        "family_id": FAMILY_ID,
        "action_id": ACTION_ID,
    }
    for key, expected in expected_identity.items():
        if identity.get(key) != expected:
            fail(f"manifest identity.{key} mismatch")
    bytes_meta = document.get("bytes")
    if not isinstance(bytes_meta, dict):
        fail("manifest bytes missing")
    artifact_value = bytes_meta.get("artifact_path")
    if not isinstance(artifact_value, str) or not artifact_value:
        fail("manifest bytes.artifact_path missing")
    artifact_path = root / artifact_value
    if artifact_path.is_symlink():
        fail("artifact path must not be a symlink")
    try:
        artifact_path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ArtifactError("artifact path escapes repository") from exc
    try:
        raw = artifact_path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"cannot read artifact {artifact_path}: {exc}") from exc
    envelope = parse_envelope(raw)
    if identity.get("network_id") != envelope.network_id:
        fail("manifest network_id mismatch")
    if bytes_meta.get("header") != HEADER_BYTES:
        fail("manifest header byte count mismatch")
    if bytes_meta.get("statement") != len(envelope.statement):
        fail("manifest statement byte count mismatch")
    if bytes_meta.get("public_values") != PUBLIC_VALUES_BYTES:
        fail("manifest public-value byte count mismatch")
    if bytes_meta.get("balance_tag") != BALANCE_TAG_BYTES:
        fail("manifest balance-tag byte count mismatch")
    if bytes_meta.get("proof") != len(envelope.proof):
        fail("manifest proof byte count mismatch")
    if bytes_meta.get("envelope") != len(raw):
        fail("manifest envelope byte count mismatch")
    if bytes_meta.get("proof_sha256") != _sha256(envelope.proof):
        fail("manifest proof hash mismatch")
    if bytes_meta.get("statement_sha256") != _sha256(envelope.statement):
        fail("manifest statement hash mismatch")
    if bytes_meta.get("envelope_sha256") != _sha256(raw):
        fail("manifest envelope hash mismatch")
    relation = document.get("relation")
    if not isinstance(relation, dict):
        fail("manifest relation missing")
    if relation.get("hash") != "RFC7693-BLAKE2b-384":
        fail("manifest relation hash mismatch")
    if relation.get("hash_output_bits") != 384 or relation.get("composition_margin_bits") != 0:
        fail("manifest relation security fields mismatch")
    if relation.get("schedule_digest_hex") != envelope.relation_binding.hex():
        fail("manifest relation schedule digest mismatch")
    shape = document.get("shape")
    if shape != {
        "maximum_transaction": True,
        "active_inputs": 2,
        "active_outputs": 2,
        "activity_mask": 15,
        "authorization_mode": "SingleKey",
        "all_active": True,
    }:
        fail("manifest does not describe the exact full maximum shape")
    return envelope, document


def generate(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    marker = require_integration_marker((root / args.integration_marker).resolve())
    # This check must precede the prover command.  In particular, do not use
    # cargo metadata or cargo run before require_disk has passed.
    require_disk(root)
    artifact_unresolved = root / args.artifact
    manifest_unresolved = root / args.manifest
    if artifact_unresolved.is_symlink():
        fail("requested artifact path must not be a symlink")
    if manifest_unresolved.is_symlink():
        fail("requested manifest path must not be a symlink")
    artifact_path = artifact_unresolved.resolve()
    manifest_path = manifest_unresolved.resolve()
    _repo_relative(root, artifact_path)
    _repo_relative(root, manifest_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    prover_extra = [
        "--generate",
        "--output",
        str(artifact_path),
        "--network-id",
        str(args.network_id),
        "--activity-mask",
        "15",
        "--auth-mode",
        "SingleKey",
        "--maximum-shape",
    ]
    _run_command(args.prover_command, {"artifact": str(artifact_path)}, prover_extra)
    if not artifact_path.is_file() or artifact_path.is_symlink():
        fail("prover did not create a regular artifact file")
    envelope = parse_envelope(artifact_path.read_bytes())
    if envelope.network_id != args.network_id:
        fail("prover emitted an artifact for the wrong network")
    # Two separate verifier processes prove restart/fresh-verifier behavior.
    verify_with_fresh_process(args.verifier_command, envelope, artifact_path)
    verify_with_fresh_process(args.verifier_command, envelope, artifact_path)
    mutation_outcomes = run_mutation_suite(root, envelope, args.verifier_command)
    document = _manifest(
        root, artifact_path, envelope, marker, mutation_outcomes, args.verifier_command
    )
    write_manifest(manifest_path, document)
    # Re-open the manifest and artifact through the independent parser before
    # reporting success; this catches writer/parser drift in the same run.
    verify_manifest(root, manifest_path)
    print(json.dumps(document, indent=2, sort_keys=True))


def verify(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    envelope, document = verify_manifest(root, (root / args.manifest).resolve())
    artifact_path = root / str(document["bytes"]["artifact_path"])
    if args.verifier_command:
        verify_with_fresh_process(args.verifier_command, envelope, artifact_path)
        verify_with_fresh_process(args.verifier_command, envelope, artifact_path)
        outcomes = run_mutation_suite(root, envelope, args.verifier_command)
        expected = document["verifier"]["mutation_suite"]
        if outcomes != expected:
            fail("manifest mutation evidence does not match fresh rerun")
    print(
        f"SmallWood BLAKE2b artifact verified: envelope={len(envelope.raw)} "
        f"proof={len(envelope.proof)} posture={document['posture']}"
    )


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", type=Path, default=Path("."))
    sub = argparse.ArgumentParser(description=__doc__)
    commands = sub.add_subparsers(dest="command", required=True)
    generate_parser = commands.add_parser("generate", parents=[common])
    generate_parser.add_argument("--integration-marker", type=Path, default=DEFAULT_MARKER)
    generate_parser.add_argument("--artifact", type=Path,
                                 default=Path("artifacts/smallwood-blake2b384/full-maximum-single-key.swv5"))
    generate_parser.add_argument("--manifest", type=Path,
                                 default=Path("artifacts/smallwood-blake2b384/full-maximum-single-key.manifest.json"))
    generate_parser.add_argument("--network-id", type=int, required=True)
    generate_parser.add_argument("--prover-command", required=True)
    generate_parser.add_argument("--verifier-command", required=True)
    generate_parser.set_defaults(handler=generate)
    verify_parser = commands.add_parser("verify", parents=[common])
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--verifier-command")
    verify_parser.set_defaults(handler=verify)
    disk_parser = commands.add_parser("check-disk", parents=[common])
    disk_parser.set_defaults(handler=lambda args: print(f"free_bytes={require_disk(args.root.resolve())}"))
    return sub


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        args.handler(args)
    except ArtifactError as exc:
        print(f"SmallWood BLAKE2b artifact gate blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
