#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


PROFILE_MARKER = (
    "HEGEMON_PRODUCTION_CRYPTO_PROFILE:CIRCUIT=3:CRYPTO=2:"
    "BACKEND=smallwood_candidate:ARITH=direct-packed64-committed-bindings-"
    "inline-merkle-skip-initial-mds-v2:RHO=3:OPENINGS=3:DECS_EVALS=32768:"
    "DECS_OPENINGS=24:FLOOR=128"
)
ACTIVE_ARITHMETIZATION = (
    "DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def rustc_host() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    fail("could not determine rustc host triple")


def validate_profile(profile: object, label: str) -> dict:
    if not isinstance(profile, dict):
        fail(f"{label}: cryptographic profile must be a JSON object")
    expected_fields = {
        "schema_version": 1,
        "default_version": {"circuit": 3, "crypto": 2},
        "default_backend": "smallwood_candidate",
        "version_mapped_backend": "smallwood_candidate",
        "producer_entrypoint": "transaction_circuit::proof::prove->smallwood_frontend::prove_smallwood_candidate_with_auth",
        "verifier_entrypoint": "transaction_circuit::proof::verify_transaction_proof_bytes_for_backend->smallwood_frontend::verify_smallwood_candidate_proof_bytes",
        "arithmetization": ACTIVE_ARITHMETIZATION,
        "public_value_count": 78,
        "required_soundness_floor_bits": 128,
        "compiled_profile_marker": PROFILE_MARKER,
    }
    for field, expected in expected_fields.items():
        if profile.get(field) != expected:
            fail(
                f"{label}: profile {field} must be {expected!r}, "
                f"got {profile.get(field)!r}"
            )
    no_grinding = profile.get("no_grinding_profile")
    expected_no_grinding = {
        "rho": 3,
        "nb_opened_evals": 3,
        "beta": 2,
        "opening_pow_bits": 0,
        "decs_nb_evals": 32768,
        "decs_nb_opened_evals": 24,
        "decs_eta": 3,
        "decs_pow_bits": 0,
    }
    if no_grinding != expected_no_grinding:
        fail(f"{label}: active no-grinding profile mismatch: {no_grinding!r}")
    soundness = profile.get("soundness")
    if not isinstance(soundness, dict):
        fail(f"{label}: soundness report missing")
    if soundness.get("profile") != expected_no_grinding:
        fail(f"{label}: soundness report profile mismatch")
    floor = soundness.get("security_floor_bits")
    if not isinstance(floor, (int, float)) or floor < 128:
        fail(f"{label}: computed security floor is below 128 bits: {floor!r}")
    if soundness.get("meets_128_bit_floor") is not True:
        fail(f"{label}: computed soundness report does not meet the 128-bit floor")
    table_digest = profile.get("exact_constraint_table_digest_hex")
    verifier_profile = profile.get("verifier_profile_sha384_hex")
    for field, value, length in (
        ("exact_constraint_table_digest_hex", table_digest, 64),
        ("verifier_profile_sha384_hex", verifier_profile, 96),
    ):
        if not isinstance(value, str) or len(value) != length:
            fail(f"{label}: {field} has the wrong length")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            fail(f"{label}: {field} is not hex: {exc}")
    return profile


def run_profile(binary: Path, binary_name: str) -> dict:
    args = [str(binary)]
    if binary_name == "wallet":
        args.append("print-crypto-profile")
    else:
        args.append("--print-crypto-profile")
    completed = subprocess.run(args, check=True, capture_output=True, text=True)
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"{binary_name}: expected exactly one profile JSON line, got {len(lines)}")
    try:
        return validate_profile(json.loads(lines[0]), binary_name)
    except json.JSONDecodeError as exc:
        fail(f"{binary_name}: invalid profile JSON: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--require-executed",
        action="store_true",
        help="reject cross-target marker-only inspection",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    target = manifest.get("target_triple")
    artifacts = manifest.get("artifacts")
    if not isinstance(target, str) or not isinstance(artifacts, list):
        fail("release manifest lacks target_triple or artifacts")

    profiles: list[dict] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("release manifest artifact must be an object")
        binary_name = artifact.get("binary")
        relative = artifact.get("path")
        if not isinstance(binary_name, str) or not isinstance(relative, str):
            fail("release manifest artifact lacks binary/path")
        binary = (root / relative).resolve()
        if PROFILE_MARKER.encode() not in binary.read_bytes():
            fail(f"{binary_name}: compiled production profile marker is absent")
        if target == rustc_host():
            profiles.append(run_profile(binary, binary_name))

    if profiles and any(profile != profiles[0] for profile in profiles[1:]):
        fail("release binaries disagree on the compiled production cryptographic profile")
    mode = "executed" if profiles else "static-cross-target"
    if args.require_executed and mode != "executed":
        fail(
            "release cryptographic profile attestation must execute target binaries "
            f"natively (manifest target {target}, runner host {rustc_host()})"
        )
    print(json.dumps({"passed": True, "mode": mode, "target_triple": target}, sort_keys=True))


if __name__ == "__main__":
    main()
