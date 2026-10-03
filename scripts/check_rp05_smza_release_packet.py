#!/usr/bin/env python3
"""Validate a source-bound RP05/SMZA PR packet without selecting production.

The packet result is deliberately narrower than production authorization. It
requires the installed, source-pinned four-gate Q38 contract, validates those
recorded gates through the existing checker, and runs the reviewed generator's
source-owned verifier over the exact pair pinned by the lifecycle gate. It
never accepts caller-supplied gate evidence and never writes repository data.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import check_rp05_smza_review_bundle as q38_contract
import check_smallwood_poseidon2_v8_smza_artifacts as artifacts


SCHEMA = "hegemon.rp05.smza.pr-technical-release-packet.v1"
Q38_PASS = "source_pinned_evidence_bytes_verified"
VECTOR_SCRIPT = ".agent/prod-closure-2026-09-19/release-preparation/generate_rp05_transcript_vector.py"
TRANSCRIPT_VECTOR = "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05_transcript.json"
TRANSCRIPT_FIXTURE = "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05.bin"
VECTOR_SCRIPT_SHA256 = "e2019a0c3cdd6bc8c3db5a1286fba65ada7f2638cd70ad9b62612178b255c5d0"
TRANSCRIPT_VECTOR_SHA256 = "25f3234c99d74c9424ff2931fea5dd17f0bcc0941d0364213ef251abe8ecf202"
EXPECTED_LEAN_TOOLCHAIN = "leanprover--lean4---v4.32.2"
EXPECTED_LEAN_SELECTOR = "leanprover/lean4:v4.32.2"


class PacketError(ValueError):
    """A technical release-packet check is incomplete or inconsistent."""


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise PacketError(message)


def _canonical_directory(value: str | Path, label: str) -> Path:
    raw = str(value)
    candidate = Path(raw)
    _require(candidate.is_absolute() and candidate.as_posix() == raw,
             f"{label} must be an absolute canonical POSIX path")
    return candidate


def _validate_rp05_transcript_vector(repo: Path) -> dict[str, Any]:
    """Recompute the finite relation-identity KAT in memory; never write it."""
    source_path = repo / VECTOR_SCRIPT
    fixture_path = repo / TRANSCRIPT_FIXTURE
    vector_path = repo / TRANSCRIPT_VECTOR
    source_bytes = artifacts.read(source_path, 2 * 1024**2)
    fixture_bytes = artifacts.read(fixture_path, artifacts.RP05_PROFILE.program_bytes)
    observed = artifacts.read(vector_path, 2 * 1024**2)
    _require(artifacts.digest(source_bytes, "sha256") == VECTOR_SCRIPT_SHA256,
             "reviewed RP05 transcript-vector generator source changed")
    _require(artifacts.digest(observed, "sha256") == TRANSCRIPT_VECTOR_SHA256,
             "reviewed RP05 transcript-vector bytes changed")
    _require(hashlib.sha512(fixture_bytes).hexdigest() == artifacts.RP05_PROFILE.program_sha512,
             "current RP05 relation fixture identity mismatch")

    spec = importlib.util.spec_from_file_location("rp05_packet_transcript_vector", source_path)
    _require(spec is not None and spec.loader is not None,
             "RP05 transcript-vector source cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _require(module.ROOT == repo and module.SOURCE == repo / "circuits/transaction/src/smallwood_poseidon2_v8_program.rs"
             and module.FIXTURE == fixture_path and module.OUTPUT == vector_path,
             "RP05 transcript-vector generator paths are not repository-local")
    expected = module.canonical_bytes(module.vector())
    _require(expected == observed, "checked-in RP05 transcript vector is stale or noncanonical")
    _require(artifacts.read(source_path, 2 * 1024**2) == source_bytes and
             artifacts.read(fixture_path, artifacts.RP05_PROFILE.program_bytes) == fixture_bytes and
             artifacts.read(vector_path, 2 * 1024**2) == observed,
             "RP05 finite vector inputs changed during recomputation")
    report = artifacts.object_json(observed)
    _require(report.get("schema") == "hegemon.poseidon2-v8.relation-program-transcript-v2"
             and report.get("claim_scope") == "source_bound_rp05_canonical_statement_independent_program_identity_kat"
             and report.get("final_program_sha512") == artifacts.RP05_PROFILE.program_sha512
             and report.get("final_relation_id_48") == artifacts.RP05_PROFILE.digest_hex
             and report.get("source_recomputation_required") is True
             and report.get("production_authority") is False,
             "finite RP05 relation identity/vector contract mismatch")
    return {
        "status": "PASS",
        "claim_scope": report["claim_scope"],
        "program_sha512": report["final_program_sha512"],
        "relation_id_48": report["final_relation_id_48"],
        "transcript_vector_sha512": artifacts.digest(observed),
        "vector_generator_sha256": artifacts.digest(source_bytes, "sha256"),
        "production_authority": False,
    }


def _q38_reviewed_manifest(repo: Path, artifact_dir: Path) -> tuple[Path, bytes, bytes, bytes]:
    """Return gate-4's source-pinned manifest and stable contract/evidence bytes."""
    q38_status = q38_contract.validate_q38_evidence_contract(repo)
    _require(q38_status == Q38_PASS, "installed source-pinned Q38 evidence contract required")
    contract_path = repo / q38_contract.Q38_CONTRACT_PATH
    evidence_path = repo / q38_contract.Q38_EVIDENCE_PATH
    contract_raw = artifacts.read(contract_path, 64 * 1024)
    contract = artifacts.object_json(contract_raw)
    _require(contract.get("status") == "installed" and
             contract.get("production_authorized") is False,
             "Q38 contract must be installed and remain non-authorizing")
    evidence_raw = artifacts.read(evidence_path, 4 * 1024**2)
    _require(artifacts.digest(evidence_raw) == contract.get("evidence_sha512"),
             "installed Q38 evidence digest mismatch")
    evidence = artifacts.object_json(evidence_raw)
    gates = evidence.get("gates")
    _require(type(gates) is list and len(gates) == len(q38_contract.MISSING_Q38_GATES) and
             all(type(entry) is dict for entry in gates) and
             [entry["gate"] for entry in gates] == list(q38_contract.MISSING_Q38_GATES),
             "installed Q38 gate set is missing, duplicated, or reordered")

    gate4 = gates[-1]
    _, gate4_raw = artifacts.pinned_record(repo, {
        key: gate4[key] for key in ("path", "bytes", "sha512")
    })
    wrapper = artifacts.object_json(gate4_raw)
    _require(wrapper.get("gate") == "identity_proof_lifecycle_and_release_review" and
             type(wrapper.get("records")) is dict,
             "Q38 lifecycle/release gate wrapper is malformed")
    manifest_pin = wrapper["records"].get("artifact_manifest")
    _require(type(manifest_pin) is dict, "Q38 lifecycle gate lacks its artifact-manifest pin")
    manifest_path, manifest_raw = artifacts.pinned_record(repo, manifest_pin)
    expected_path = artifact_dir / "manifest.json"
    _require(manifest_path == expected_path,
             "requested retained proof pair is not the exact pair pinned by Q38 gate 4")
    return manifest_path, manifest_raw, contract_raw, evidence_raw


def _authority_boundary(repo: Path) -> dict[str, Any]:
    """Report current source-owned blockers without inferring or granting authority."""
    selection_path = repo / "config/transaction-proof-successor-selection.json"
    selection = artifacts.object_json(artifacts.read(selection_path, 64 * 1024))
    successor_policy = artifacts.policy
    versioning_source = artifacts.read(repo / "protocol/versioning/src/lib.rs", 2 * 1024**2).decode("utf-8")
    capability_pattern = re.compile(
        r"pub const fn smallwood_poseidon2_production_capability\s*\([^)]*\)\s*"
        r"->\s*Option<SmallwoodPoseidon2ProductionCapability>\s*\{\s*None\s*\}",
        re.DOTALL,
    )
    capability_is_disabled = capability_pattern.search(versioning_source) is not None
    commands = getattr(successor_policy, "SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS", None)
    review_roots = getattr(successor_policy, "SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS", None)
    blockers: list[str] = []
    if capability_is_disabled:
        blockers.append("protocol/versioning source returns None for the RP05 production capability")
    if selection.get("selection") != "selected" or selection.get("identity") is None:
        blockers.append("successor selection is unselected and has no approved identity/evidence bundle")
    if type(commands) is dict and not commands:
        blockers.append("source-bound production evidence command registry is empty")
    if type(review_roots) is dict and not review_roots:
        blockers.append("source-bound independent-review trust-root registry is empty")
    blockers.extend([
        "no approved activation tuple is supplied: activation genesis hash, stablecoin/note genesis roots, activation height, and exclusive deactivation height",
        "no authenticated independent production-review signature is supplied by this PR-only packet",
    ])
    return {
        "activation_status": "not_selected",
        "production_authorized": False,
        "production_eligible": False,
        "source_capability_disabled": capability_is_disabled,
        "profile_selection": selection.get("selection"),
        "source_release_evidence_command_count": len(commands) if type(commands) is dict else None,
        "independent_review_trust_root_count": len(review_roots) if type(review_roots) is dict else None,
        "missing_authority_inputs": blockers,
    }


def validate_release_packet(repo: str | Path, artifact_dir: str | Path,
                            generator: str | Path,
                            recorded_lean_toolchain_root: str | Path) -> dict[str, Any]:
    """Validate a source-bound PR-only RP05 packet and return a non-authorizing report."""
    repo_input = _canonical_directory(repo, "repository root")
    repo_path = repo_input.resolve(strict=True)
    _require(repo_input == repo_path, "repository root must not use a symlink alias")
    _require(repo_path == Path(__file__).resolve().parents[1],
             "repository root must be the checkout containing this source-owned validator")
    artifact_path = _canonical_directory(artifact_dir, "artifact directory")
    generator_path = _canonical_directory(generator, "qualification generator")
    lean_root = _canonical_directory(recorded_lean_toolchain_root, "Lean toolchain root")
    _require(lean_root.name == EXPECTED_LEAN_TOOLCHAIN,
             "recorded Lean root must be the Lean 4.32.2 toolchain")
    selector = artifacts.read(repo_path / "formal/crypto/lean-toolchain", 256).decode("ascii").strip()
    _require(selector == EXPECTED_LEAN_SELECTOR,
             "repository Lean selector is not the recorded v4.32.2 toolchain")
    roots = artifacts.recorded_path_roots(repo_path, lean_root)

    inventory = artifacts.legacy.recompute_source_inventory(repo_path)
    vector_report = _validate_rp05_transcript_vector(repo_path)
    manifest, pair = artifacts.validate_bundle(
        repo_path, artifact_path, current_inventory=inventory
    )
    profile = artifacts.select_relation_profile(manifest["identity"])
    _require(profile == artifacts.RP05_PROFILE and
             artifacts.same(manifest["identity"], artifacts.relation_identity(artifacts.RP05_PROFILE)),
             "exact current RP05/SMZA identity required")
    _require(artifacts.same(manifest["proof_source_inventory"], inventory),
             "retained proof pair source inventory is stale")

    # The existing full helper validates the installed four-gate Q38 evidence
    # and every recorded wrapper semantically. It takes no caller evidence.
    artifacts.require_complete_security_contract(
        manifest["identity"], supplied_evidence=None, recorded_roots=roots
    )
    reviewed_manifest_path, reviewed_manifest_raw, contract_raw, evidence_raw = (
        _q38_reviewed_manifest(repo_path, artifact_path)
    )
    manifest_path = artifact_path / "manifest.json"
    manifest_raw = artifacts.read(manifest_path, 16 * 1024**2)
    _require(reviewed_manifest_path == manifest_path and reviewed_manifest_raw == manifest_raw,
             "retained proof pair differs from the reviewed Q38 lifecycle artifact")

    generator_pin = manifest.get("generator", {}).get("executable", {}).get("sha512")
    _require(type(generator_pin) is str and re.fullmatch(r"[0-9a-f]{128}", generator_pin) is not None,
             "Q38-pinned RP05 manifest lacks an exact generator executable SHA-512")
    source_readback = artifacts.verify_source_owned(
        repo_path, artifact_path, generator_path, generator_pin, manifest
    )
    artifacts.validate_rp05_readback_authority(source_readback)
    _require(source_readback.get("distinct_proofs") is True and
             source_readback.get("distinct_salts_and_roots") is True,
             "source-owned verifier did not validate two independently randomized proofs")
    for role in ("primary", "independent"):
        proof = pair[role]["proof.bin"]
        _require(source_readback["artifacts"][role]["source_owned_verification"] is True and
                 source_readback["artifacts"][role]["unchanged_carriers"] is True and
                 source_readback["artifacts"][role]["proof_sha512"] == artifacts.digest(proof),
                 f"source verification did not bind unchanged {role} proof bytes")

    _require(artifacts.legacy.recompute_source_inventory(repo_path) == inventory,
             "proof source inventory changed during packet validation")
    after_manifest_path, after_manifest_raw, after_contract_raw, after_evidence_raw = (
        _q38_reviewed_manifest(repo_path, artifact_path)
    )
    _require(after_manifest_path == reviewed_manifest_path and after_manifest_raw == manifest_raw and
             after_contract_raw == contract_raw and after_evidence_raw == evidence_raw,
             "source-pinned Q38 contract or retained manifest changed during validation")

    authority = _authority_boundary(repo_path)
    return {
        "schema": SCHEMA,
        "technical_status": "PASS_PR_ONLY",
        "production_authorized": False,
        "production_eligible": False,
        "scope": "RP05/SMZA source-bound technical packet; not a production authorization",
        "identity_vector_conformance": vector_report,
        "retained_pair": {
            "status": "PASS_SOURCE_OWNED_VERIFICATION",
            "artifact_manifest_sha512": artifacts.digest(manifest_raw),
            "source_inventory_root_sha512": inventory["root_sha512"],
            "generator_executable_sha512": generator_pin,
            "proofs": {
                role: {
                    "bytes": len(pair[role]["proof.bin"]),
                    "sha512": artifacts.digest(pair[role]["proof.bin"]),
                    "source_owned_verification": True,
                    "unchanged_carriers": True,
                }
                for role in ("primary", "independent")
            },
        },
        "q38_contract": {
            "status": "PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED",
            "gates": list(q38_contract.MISSING_Q38_GATES),
            "execution_receipts_authenticated": False,
            "production_authorized": False,
        },
        "activation": authority,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="canonical absolute repository path")
    parser.add_argument("--artifact-dir", required=True, help="exact Q38-pinned retained RP05 pair")
    parser.add_argument("--generator", required=True, help="source-owned qualification verifier executable")
    parser.add_argument("--recorded-lean-toolchain-root", required=True,
                        help="local Lean 4.32.2 root mapped to the frozen receipt path")
    args = parser.parse_args(argv)
    try:
        report = validate_release_packet(
            args.repo, args.artifact_dir, args.generator,
            args.recorded_lean_toolchain_root,
        )
    except (PacketError, artifacts.EvidenceError, q38_contract.BundleError,
            KeyError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        report = {
            "schema": SCHEMA,
            "technical_status": "BLOCKED",
            "production_authorized": False,
            "activation_status": "not_selected",
            "reason": str(error),
        }
        try:
            report["activation"] = _authority_boundary(Path(args.repo).resolve(strict=True))
        except (OSError, ValueError, KeyError, PacketError):
            report["activation"] = {
                "activation_status": "not_selected",
                "production_authorized": False,
                "production_eligible": False,
            }
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
