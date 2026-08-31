#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


ACTIVE_ARITHMETIZATION = "DirectPacked64CompressedLevel5"
ACTIVE_ARITHMETIZATION_MARKER = "direct-packed64-compressed-level5"
ACTIVE_NO_GRINDING_PROFILE = {
    "rho": 5,
    "nb_opened_evals": 5,
    "beta": 2,
    "opening_pow_bits": 0,
    "decs_nb_evals": 1048576,
    "decs_nb_opened_evals": 23,
    "decs_eta": 5,
    "decs_pow_bits": 0,
}
REQUIRED_SOUNDNESS_FLOOR_BITS = 260
# Independent release ratchets for the exact active verifier surface. These values
# are intentionally not derived from the attested binary: changing either digest
# requires an explicit checker review alongside the Rust verifier/profile change.
CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX = (
    "d4f9cd30c8c3ae7e6bf87a73f929471ae22d09295223925c9f6bfc0777daa5b4"
)
CANONICAL_VERIFIER_PROFILE_SHA384_HEX = (
    "e1a09c264e3025034133c4f70a61da9f1f1ba5e535cd44f7c94e87f90ee71202"
    "5385b0fba1338419c1b2b46ba71b1617"
)
CANONICAL_PROFILE_DIGESTS = {
    "exact_constraint_table_digest_hex": CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX,
    "verifier_profile_sha384_hex": CANONICAL_VERIFIER_PROFILE_SHA384_HEX,
}
PROFILE_MARKER_FIELDS = {
    "CIRCUIT": "4",
    "CRYPTO": "3",
    "BACKEND": "smallwood_candidate",
    "ARITH": ACTIVE_ARITHMETIZATION_MARKER,
    "RHO": str(ACTIVE_NO_GRINDING_PROFILE["rho"]),
    "OPENINGS": str(ACTIVE_NO_GRINDING_PROFILE["nb_opened_evals"]),
    "BETA": str(ACTIVE_NO_GRINDING_PROFILE["beta"]),
    "DECS_EVALS": str(ACTIVE_NO_GRINDING_PROFILE["decs_nb_evals"]),
    "DECS_OPENINGS": str(ACTIVE_NO_GRINDING_PROFILE["decs_nb_opened_evals"]),
    "DECS_ETA": str(ACTIVE_NO_GRINDING_PROFILE["decs_eta"]),
    "FLOOR": str(REQUIRED_SOUNDNESS_FLOOR_BITS),
}
PROFILE_MARKER = "HEGEMON_PRODUCTION_CRYPTO_PROFILE:" + ":".join(
    f"{key}={value}" for key, value in PROFILE_MARKER_FIELDS.items()
)
PROFILE_MARKER_PATTERN = re.compile(
    rb"HEGEMON_PRODUCTION_CRYPTO_PROFILE:"
    rb"CIRCUIT=(?P<CIRCUIT>[0-9]+):"
    rb"CRYPTO=(?P<CRYPTO>[0-9]+):"
    rb"BACKEND=(?P<BACKEND>[a-z0-9_]+):"
    rb"ARITH=(?P<ARITH>[a-z0-9-]+):"
    rb"RHO=(?P<RHO>[0-9]+):"
    rb"OPENINGS=(?P<OPENINGS>[0-9]+):"
    rb"BETA=(?P<BETA>[0-9]+):"
    rb"DECS_EVALS=(?P<DECS_EVALS>[0-9]+):"
    rb"DECS_OPENINGS=(?P<DECS_OPENINGS>[0-9]+):"
    rb"DECS_ETA=(?P<DECS_ETA>[0-9]+):"
    # Rust string data can be packed immediately after this marker without a NUL
    # terminator. Reject both a fourth decimal digit and a marker-field extension.
    rb"FLOOR=(?P<FLOOR>[0-9]{3})(?=$|[^0-9:])"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def rustc_host() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    fail("could not determine rustc host triple")


def validate_profile_marker(marker: object, label: str) -> dict[str, str]:
    if not isinstance(marker, str):
        fail(f"{label}: compiled production profile marker must be a string")
    parts = marker.split(":")
    if not parts or parts[0] != "HEGEMON_PRODUCTION_CRYPTO_PROFILE":
        fail(f"{label}: compiled production profile marker has the wrong prefix")
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            fail(f"{label}: malformed compiled production profile marker field {part!r}")
        key, value = part.split("=", 1)
        if not key or not value or key in fields:
            fail(f"{label}: malformed or duplicate profile marker field {key!r}")
        fields[key] = value
    if fields != PROFILE_MARKER_FIELDS:
        fail(
            f"{label}: compiled production profile marker contradicts the active "
            f"profile: {fields!r} != {PROFILE_MARKER_FIELDS!r}"
        )
    return fields


def validate_binary_profile_markers(binary: Path, binary_name: str) -> None:
    data = binary.read_bytes()
    prefix = b"HEGEMON_PRODUCTION_CRYPTO_PROFILE:"
    offsets: list[int] = []
    offset = data.find(prefix)
    while offset >= 0:
        offsets.append(offset)
        offset = data.find(prefix, offset + len(prefix))
    if not offsets:
        fail(f"{binary_name}: compiled production profile marker is absent")
    markers: set[str] = set()
    for offset in offsets:
        match = PROFILE_MARKER_PATTERN.match(data, offset)
        if match is None:
            fail(f"{binary_name}: malformed compiled production profile marker")
        fields = {
            key: value.decode("ascii") for key, value in match.groupdict().items()
        }
        marker = "HEGEMON_PRODUCTION_CRYPTO_PROFILE:" + ":".join(
            f"{key}={fields[key]}" for key in PROFILE_MARKER_FIELDS
        )
        validate_profile_marker(marker, binary_name)
        markers.add(marker)
    if markers != {PROFILE_MARKER}:
        fail(f"{binary_name}: release binary contains contradictory profile markers")


def validate_profile(profile: object, label: str) -> dict:
    if not isinstance(profile, dict):
        fail(f"{label}: cryptographic profile must be a JSON object")
    expected_fields = {
        "schema_version": 1,
        "default_version": {"circuit": 4, "crypto": 3},
        "default_backend": "smallwood_candidate",
        "version_mapped_backend": "smallwood_candidate",
        "producer_entrypoint": "transaction_circuit::proof::prove->smallwood_frontend::prove_smallwood_candidate_with_auth",
        "verifier_entrypoint": "transaction_circuit::proof::verify_transaction_proof_bytes_for_backend->smallwood_frontend::verify_smallwood_candidate_proof_bytes",
        "arithmetization": ACTIVE_ARITHMETIZATION,
        "public_value_count": 78,
        "required_soundness_floor_bits": REQUIRED_SOUNDNESS_FLOOR_BITS,
    }
    for field, expected in expected_fields.items():
        if profile.get(field) != expected:
            fail(
                f"{label}: profile {field} must be {expected!r}, "
                f"got {profile.get(field)!r}"
            )
    marker_fields = validate_profile_marker(
        profile.get("compiled_profile_marker"), label
    )
    no_grinding = profile.get("no_grinding_profile")
    if no_grinding != ACTIVE_NO_GRINDING_PROFILE:
        fail(f"{label}: active no-grinding profile mismatch: {no_grinding!r}")
    marker_profile = {
        "rho": int(marker_fields["RHO"]),
        "nb_opened_evals": int(marker_fields["OPENINGS"]),
        "beta": int(marker_fields["BETA"]),
        "decs_nb_evals": int(marker_fields["DECS_EVALS"]),
        "decs_nb_opened_evals": int(marker_fields["DECS_OPENINGS"]),
        "decs_eta": int(marker_fields["DECS_ETA"]),
    }
    for field, marker_value in marker_profile.items():
        if no_grinding.get(field) != marker_value:
            fail(
                f"{label}: compiled marker {field}={marker_value} contradicts "
                f"live profile value {no_grinding.get(field)!r}"
            )
    soundness = profile.get("soundness")
    if not isinstance(soundness, dict):
        fail(f"{label}: soundness report missing")
    if soundness.get("profile") != ACTIVE_NO_GRINDING_PROFILE:
        fail(f"{label}: soundness report profile mismatch")
    floor = soundness.get("security_floor_bits")
    if (
        not isinstance(floor, (int, float))
        or floor < REQUIRED_SOUNDNESS_FLOOR_BITS
    ):
        fail(
            f"{label}: computed security floor is below "
            f"{REQUIRED_SOUNDNESS_FLOOR_BITS} bits: {floor!r}"
        )
    if soundness.get("meets_260_bit_floor") is not True:
        fail(f"{label}: computed soundness report does not meet the 260-bit floor")
    for field, expected in CANONICAL_PROFILE_DIGESTS.items():
        value = profile.get(field)
        length = len(expected)
        if not isinstance(value, str) or len(value) != length:
            fail(f"{label}: {field} has the wrong length")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            fail(f"{label}: {field} is not hex: {exc}")
        if value != expected:
            fail(
                f"{label}: {field} contradicts the canonical active release "
                f"ratchet: {value!r} != {expected!r}"
            )
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
        validate_binary_profile_markers(binary, binary_name)
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
