#!/usr/bin/env python3
"""Create and validate the RP05 proof/lifecycle/review gate after a PASS lane.

This is metadata preparation only. It neither builds nor grants authority. The
caller must supply the exact lane, generator and hashes, and attest that the
single heavy compiler is idle before the adapter verifies retained proofs.
Output is create-only; partial output is retained on failure for inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[3]
PREP = Path(__file__).resolve().parent
LANE_SCHEMA = "hegemon.rp05.smza.qualification-lane-receipt.v1"
SOCKET_STAGE = "actual_socket_process_lifecycle"
INPROCESS_STAGE = "inprocess_native_lifecycle"
GATE = "identity_proof_lifecycle_and_release_review"
CHECKER_SHA256 = "e1dcb73896b1519c89a05a31eb4aa21c31fd92183c1f3e4637be3bf131482447"
SHA512_RE = re.compile(r"[0-9a-f]{128}\Z")
TMP_ROOT = Path("/private/tmp")

sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "scripts"))
import check_smallwood_poseidon2_v8_smza_artifacts as checker  # noqa: E402


def fail(ok: bool, message: str) -> None:
    if not ok:
        raise checker.EvidenceError(message)


def repo_path(repo: Path, value: str, *, must_exist: bool, directory: bool = False) -> Path:
    path = Path(value)
    fail(not path.is_absolute() and path.as_posix() == value and "\\" not in value and
         bool(path.parts) and all(part not in ("", ".", "..") for part in value.split("/")),
         "normalized repository-relative POSIX path required")
    current = repo
    fail(not repo.is_symlink(), "symlink repository")
    for part in path.parts:
        current /= part
        fail(not current.is_symlink(), "symlink path forbidden: " + str(current))
    if must_exist:
        expected = current.is_dir() if directory else current.is_file()
        fail(expected, ("expected directory: " if directory else "expected regular file: ") + value)
    else:
        fail(current.parent.is_dir() and not current.exists(),
             "create-only destination requires an existing parent and absent path")
    return current


def read_regular(path: Path, *, cap: int = 128 * 1024**2) -> bytes:
    raw = checker.read(path, cap)
    return raw


def pin(repo: Path, path: Path) -> dict[str, Any]:
    raw = read_regular(path)
    return {"path": path.relative_to(repo).as_posix(), "bytes": len(raw),
            "sha512": hashlib.sha512(raw).hexdigest()}


def write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def no_symlink_tmp_source(value: Any, recorded: Any, *, tmp_root: Path) -> tuple[Path, bytes]:
    fail(type(recorded) is dict and set(recorded) >= {"path", "bytes", "sha512"},
         "lane socket receipt pin fields missing")
    fail(type(value) is str and Path(value).is_absolute() and Path(value).as_posix() == value,
         "socket receipt source must be canonical absolute path")
    source = Path(value)
    fail(source != tmp_root and tmp_root in source.parents,
         "socket receipt source must be below the lane temporary root")
    for node in (source, *source.parents):
        fail(not node.is_symlink(), "symlink socket receipt source forbidden: " + str(node))
    fail(source.is_file(), "socket receipt source is not a regular file")
    fail(source.resolve(strict=True) == source, "socket receipt source is not canonical")
    raw = read_regular(source)
    fail(type(recorded["bytes"]) is int and recorded["bytes"] == len(raw) and
         type(recorded["sha512"]) is str and recorded["sha512"] == hashlib.sha512(raw).hexdigest(),
         "socket receipt bytes/hash differ from the lane's retained pin")
    return source, raw


def _lane_stage(receipt: dict[str, Any], name: str) -> dict[str, Any]:
    stages = receipt.get("stages")
    fail(type(stages) is list, "qualification lane stages missing")
    matches = [stage for stage in stages if type(stage) is dict and stage.get("stage") == name]
    fail(len(matches) == 1, "qualification lane must contain exactly one " + name)
    return matches[0]


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def prepare(*, run_root: str, output: str, generator: str, generator_sha512: str,
            compiler_idle_confirmed: bool, repo: Path = REPO,
            run_adapter=subprocess.run) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    fail(compiler_idle_confirmed is True,
         "explicit confirmation that the sole heavy compiler is idle is required")
    fail(SHA512_RE.fullmatch(generator_sha512) is not None,
         "generator SHA-512 must be 128 lowercase hex digits")
    if checker.digest(checker.read(Path(checker.__file__), 16 * 1024**2), "sha256") != CHECKER_SHA256:
        raise checker.EvidenceError("source-owned artifact checker differs from frozen reviewed version")
    lane_dir = repo_path(repo, run_root, must_exist=True, directory=True)
    output_dir = repo_path(repo, output, must_exist=False)
    generator_path = repo_path(repo, generator, must_exist=True)
    lane_receipt_path = lane_dir / "receipt.json"
    fail(not lane_receipt_path.is_symlink() and lane_receipt_path.is_file(),
         "complete successful qualification-lane receipt required")
    lane = checker.object_json(read_regular(lane_receipt_path))
    fail(lane.get("schema") == LANE_SCHEMA, "qualification lane is not a completed PASS receipt")
    inprocess = _lane_stage(lane, INPROCESS_STAGE)
    socket = _lane_stage(lane, SOCKET_STAGE)
    fail(inprocess.get("status") == "PASS_DEVELOPMENT_ONLY" and
         socket.get("status") == "PASS_DEVELOPMENT_ONLY",
         "both exact lifecycle stages must have PASS_DEVELOPMENT_ONLY status")
    frozen = lane.get("source_pins_frozen_before_build_proof_lifecycle")
    final = lane.get("source_pins_after_build_proof_lifecycle")
    fail(type(frozen) is dict and frozen == final,
         "qualification lane source pins did not remain frozen through completion")
    inventory = checker.legacy.recompute_source_inventory(repo)
    inventory_root = inventory["root_sha512"]
    fail(frozen.get("proof_source_inventory_root_sha512") == inventory_root,
         "lane proof source inventory is not current")
    manifest_path = lane_dir / "pair" / "manifest.json"
    manifest = checker.object_json(read_regular(manifest_path))
    fail(manifest.get("proof_source_inventory", {}).get("root_sha512") == inventory_root,
         "retained proof manifest does not bind the current source inventory")
    recorded_generator = lane.get("qualification_generator_binary")
    fail(type(recorded_generator) is dict, "lane generator pin missing")
    fail(recorded_generator.get("path") == str(generator_path),
         "explicit generator path does not match the completed lane: recorded=" +
         repr(recorded_generator.get("path")) + " actual=" + repr(str(generator_path)))
    fail(recorded_generator.get("sha512") == generator_sha512 and
         checker.digest(read_regular(generator_path, cap=160 * 1024**2)) == generator_sha512,
         "explicit generator hash does not match the completed lane")

    retained = socket.get("retained_socket_receipt")
    fail(type(retained) is dict, "successful socket stage lacks retained carrier receipt")
    scratch = lane.get("scratch_directory")
    fail(type(scratch) is str and Path(scratch).is_absolute() and
         Path(scratch).as_posix() == scratch and Path(scratch).parent == TMP_ROOT,
         "qualification lane scratch root must be canonical under /private/tmp")
    source, socket_bytes = no_symlink_tmp_source(
        retained.get("path"), retained, tmp_root=Path(scratch))
    fail(source.parent == Path(scratch) or Path(scratch) in source.parents,
         "socket carrier receipt escaped this qualification lane scratch root")

    # Create first, with exclusive files. On any later rejection, preserve the
    # partial directory as evidence; retries must choose a new output path.
    output_dir.mkdir(exist_ok=False)
    copied_socket_path = output_dir / "actual_socket_carrier_receipt.json"
    write_new(copied_socket_path, socket_bytes)
    adapter_report_path = output_dir / "adapter_report.json"
    wrapper_path = output_dir / (GATE + ".json")
    config_paths = {
        "inprocess_config": lane_dir / "inprocess" / "CONFIG_INPROCESS.json",
        "inprocess_receipt": lane_dir / "inprocess" / "receipt.json",
        "socket_config": lane_dir / "socket" / "CONFIG_SOCKET.json",
        "socket_receipt": lane_dir / "socket" / "receipt.json",
    }
    input_pins = {name: pin(repo, path) for name, path in config_paths.items()}
    manifest_pin = pin(repo, manifest_path)
    copied_socket_pin = pin(repo, copied_socket_path)
    argv = [
        sys.executable, str(repo / "scripts/check_smallwood_poseidon2_v8_smza_artifacts.py"),
        "--repo", str(repo), "--artifact-dir", str(lane_dir / "pair"),
        "--generator", str(generator_path), "--generator-sha512", generator_sha512,
    ]
    for name in ("inprocess_config", "inprocess_receipt", "socket_config", "socket_receipt"):
        path = config_paths[name]
        argv.extend(("--" + name.replace("_", "-"), str(path),
                     "--" + name.replace("_", "-") + "-sha256",
                     checker.digest(read_regular(path), "sha256")))
    argv.extend(("--socket-carrier-receipt", str(copied_socket_path),
                 "--socket-carrier-receipt-sha256",
                 checker.digest(socket_bytes, "sha256")))
    completed = run_adapter(argv, cwd=repo, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=600, check=False)
    fail(completed.returncode == 0, "source-owned artifact adapter rejected the lane: " +
         completed.stderr.decode("utf-8", errors="replace")[-4000:])
    report = checker.object_json(completed.stdout)
    fail(report.get("schema") == checker.REPORT_SCHEMA and
         report.get("artifact_manifest_sha512") == manifest_pin["sha512"] and
         report.get("source_root_sha512") == inventory_root,
         "adapter report does not bind this lane manifest/current inventory")
    write_new(adapter_report_path, _canonical_json(report))
    records = {
        "artifact_manifest": manifest_pin,
        "adapter_report": pin(repo, adapter_report_path),
        "inprocess_config": input_pins["inprocess_config"],
        "inprocess_receipt": input_pins["inprocess_receipt"],
        "socket_config": input_pins["socket_config"],
        "socket_receipt": input_pins["socket_receipt"],
        "socket_carrier_receipt": copied_socket_pin,
    }
    wrapper = {
        "schema": checker.GATE_SCHEMA,
        "gate": GATE,
        "identity": checker.relation_identity(checker.RP05_PROFILE),
        "scope": checker.RECORDED_SCOPE,
        "execution_receipts_authenticated": False,
        "production_authorized": False,
        "source_inventory": inventory,
        "records": records,
    }
    checker.validate_recorded_gate(repo, wrapper, GATE, inventory)
    fail(checker.legacy.recompute_source_inventory(repo) == inventory,
         "source inventory changed during fourth-gate preparation")
    write_new(wrapper_path, _canonical_json(wrapper))
    return {
        "status": "PREPARED_RECORDED_METADATA_ONLY",
        "gate": GATE,
        "wrapper": pin(repo, wrapper_path),
        "adapter_report": records["adapter_report"],
        "source_inventory_root_sha512": inventory_root,
        "execution_receipts_authenticated": False,
        "production_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, help="repository-relative completed lane directory")
    parser.add_argument("--output", required=True, help="absent repository-relative create-only directory")
    parser.add_argument("--generator", required=True, help="repository-relative pinned lane generator binary")
    parser.add_argument("--generator-sha512", required=True)
    parser.add_argument("--confirm-heavy-compiler-idle", action="store_true", required=True,
                        help="attest that the sole heavy compiler has completed")
    args = parser.parse_args(argv)
    try:
        result = prepare(run_root=args.run_root, output=args.output, generator=args.generator,
                         generator_sha512=args.generator_sha512,
                         compiler_idle_confirmed=args.confirm_heavy_compiler_idle)
    except (checker.EvidenceError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("RP05 lifecycle-review gate rejected: " + str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
