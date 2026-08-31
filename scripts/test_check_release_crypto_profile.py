#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_release_crypto_profile.py"
sys.path.insert(0, str(ROOT / "scripts"))

import check_release_crypto_profile as checker


CANONICAL_MARKER = (
    "HEGEMON_PRODUCTION_CRYPTO_PROFILE:CIRCUIT=4:CRYPTO=3:"
    "BACKEND=smallwood_candidate:ARITH=direct-packed64-compressed-level5:"
    "RHO=5:OPENINGS=5:BETA=2:DECS_EVALS=1048576:"
    "DECS_OPENINGS=23:DECS_ETA=5:FLOOR=260"
)
STALE_MARKER = (
    "HEGEMON_PRODUCTION_CRYPTO_PROFILE:CIRCUIT=4:CRYPTO=3:"
    "BACKEND=smallwood_candidate:ARITH=direct-packed64-compressed-level5:"
    "RHO=5:OPENINGS=5:BETA=7:DECS_EVALS=1048576:"
    "DECS_OPENINGS=20:DECS_ETA=33:FLOOR=260"
)
CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX = (
    "d4f9cd30c8c3ae7e6bf87a73f929471ae22d09295223925c9f6bfc0777daa5b4"
)
CANONICAL_VERIFIER_PROFILE_SHA384_HEX = (
    "e1a09c264e3025034133c4f70a61da9f1f1ba5e535cd44f7c94e87f90ee71202"
    "5385b0fba1338419c1b2b46ba71b1617"
)


def expect_rejected(callable_, expected: str) -> None:
    try:
        callable_()
    except SystemExit as exc:
        if expected not in str(exc):
            raise SystemExit(f"profile rejected for wrong reason: {exc}") from exc
        return
    raise SystemExit("contradictory release profile unexpectedly passed")


def canonical_profile() -> dict:
    no_grinding = dict(checker.ACTIVE_NO_GRINDING_PROFILE)
    return {
        "schema_version": 1,
        "default_version": {"circuit": 4, "crypto": 3},
        "default_backend": "smallwood_candidate",
        "version_mapped_backend": "smallwood_candidate",
        "producer_entrypoint": "transaction_circuit::proof::prove->smallwood_frontend::prove_smallwood_candidate_with_auth",
        "verifier_entrypoint": "transaction_circuit::proof::verify_transaction_proof_bytes_for_backend->smallwood_frontend::verify_smallwood_candidate_proof_bytes",
        "arithmetization": checker.ACTIVE_ARITHMETIZATION,
        "public_value_count": 78,
        "required_soundness_floor_bits": 260,
        "compiled_profile_marker": CANONICAL_MARKER,
        "no_grinding_profile": no_grinding,
        "soundness": {
            "profile": dict(no_grinding),
            "security_floor_bits": 262.3777366,
            "meets_260_bit_floor": True,
        },
        "exact_constraint_table_digest_hex": CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX,
        "verifier_profile_sha384_hex": CANONICAL_VERIFIER_PROFILE_SHA384_HEX,
    }


def main() -> None:
    if checker.PROFILE_MARKER != CANONICAL_MARKER:
        raise SystemExit("checker canonical marker is not the active 2/23/5 profile")
    if (
        checker.CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX
        != CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX
    ):
        raise SystemExit("checker exact constraint-table digest ratchet drifted")
    if (
        checker.CANONICAL_VERIFIER_PROFILE_SHA384_HEX
        != CANONICAL_VERIFIER_PROFILE_SHA384_HEX
    ):
        raise SystemExit("checker verifier-profile digest ratchet drifted")
    checker.validate_binary_profile_markers(
        ROOT / "circuits/transaction/src/proof.rs", "production Rust source"
    )
    expect_rejected(
        lambda: checker.validate_profile_marker(
            CANONICAL_MARKER + ":BETA=7", "extended-marker-fixture"
        ),
        "malformed or duplicate profile marker field",
    )
    with tempfile.NamedTemporaryFile(prefix="adjacent-profile-marker-", delete=False) as handle:
        adjacent_marker_path = Path(handle.name)
        handle.write((CANONICAL_MARKER + "nextRustStringBytes").encode())
    try:
        checker.validate_binary_profile_markers(
            adjacent_marker_path, "adjacent-marker-fixture"
        )
    finally:
        adjacent_marker_path.unlink(missing_ok=True)
    with tempfile.NamedTemporaryFile(prefix="extra-digit-profile-marker-", delete=False) as handle:
        extra_digit_marker_path = Path(handle.name)
        handle.write((CANONICAL_MARKER + "1nextRustStringBytes").encode())
    try:
        expect_rejected(
            lambda: checker.validate_binary_profile_markers(
                extra_digit_marker_path, "extra-digit-marker-fixture"
            ),
            "malformed compiled production profile marker",
        )
    finally:
        extra_digit_marker_path.unlink(missing_ok=True)
    with tempfile.NamedTemporaryFile(prefix="extended-profile-marker-", delete=False) as handle:
        extended_marker_path = Path(handle.name)
        handle.write((CANONICAL_MARKER + ":BETA=7").encode())
    try:
        expect_rejected(
            lambda: checker.validate_binary_profile_markers(
                extended_marker_path, "extended-marker-fixture"
            ),
            "malformed compiled production profile marker",
        )
    finally:
        extended_marker_path.unlink(missing_ok=True)
    checker.validate_profile(canonical_profile(), "canonical-fixture")
    for field, zero_value in (
        ("exact_constraint_table_digest_hex", "00" * 32),
        ("verifier_profile_sha384_hex", "00" * 48),
    ):
        zero_digest_profile = canonical_profile()
        zero_digest_profile[field] = zero_value
        expect_rejected(
            lambda profile=zero_digest_profile: checker.validate_profile(
                profile, "zero-digest-fixture"
            ),
            "contradicts the canonical active release ratchet",
        )
    for field in (
        "exact_constraint_table_digest_hex",
        "verifier_profile_sha384_hex",
    ):
        wrong_digest_profile = canonical_profile()
        canonical_digest = wrong_digest_profile[field]
        wrong_digest_profile[field] = (
            ("0" if canonical_digest[0] != "0" else "1") + canonical_digest[1:]
        )
        expect_rejected(
            lambda profile=wrong_digest_profile: checker.validate_profile(
                profile, "wrong-digest-fixture"
            ),
            "contradicts the canonical active release ratchet",
        )
    stale_profile = canonical_profile()
    stale_profile["compiled_profile_marker"] = STALE_MARKER
    expect_rejected(
        lambda: checker.validate_profile(stale_profile, "stale-fixture"),
        "contradicts the active profile",
    )
    contradictory_live_profile = canonical_profile()
    contradictory_live_profile["no_grinding_profile"]["beta"] = 7
    expect_rejected(
        lambda: checker.validate_profile(
            contradictory_live_profile, "contradictory-live-fixture"
        ),
        "active no-grinding profile mismatch",
    )

    with tempfile.TemporaryDirectory(prefix="release-profile-test-") as raw:
        temp = Path(raw)
        binary = temp / "hegemon-node"
        binary.write_text(
            "prefix\n"
            "HEGEMON_PRODUCTION_CRYPTO_PROFILE:CIRCUIT=4:CRYPTO=3:"
            "BACKEND=smallwood_candidate:ARITH=direct-packed64-compressed-level5:"
            "RHO=5:OPENINGS=5:BETA=2:DECS_EVALS=1048576:"
            "DECS_OPENINGS=23:DECS_ETA=5:FLOOR=260\n",
            encoding="utf-8",
        )
        manifest = temp / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "target_triple": "non-native-security-test-target",
                    "artifacts": [{"binary": "hegemon-node", "path": "hegemon-node"}],
                }
            ),
            encoding="utf-8",
        )

        static = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(manifest),
                "--root",
                str(temp),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if static.returncode != 0 or '"mode": "static-cross-target"' not in static.stdout:
            raise SystemExit("static cross-target diagnostic mode unexpectedly failed")

        required = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(manifest),
                "--root",
                str(temp),
                "--require-executed",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if required.returncode == 0:
            raise SystemExit("required release attestation accepted marker-only inspection")
        if "must execute target binaries natively" not in required.stdout:
            raise SystemExit(
                "required release attestation rejected for the wrong reason:\n"
                + required.stdout
            )

        stale_binary = temp / "stale-hegemon-node"
        stale_binary.write_text(STALE_MARKER + "\n", encoding="utf-8")
        stale_manifest = temp / "stale-manifest.json"
        stale_manifest.write_text(
            json.dumps(
                {
                    "target_triple": "non-native-security-test-target",
                    "artifacts": [
                        {"binary": "hegemon-node", "path": "stale-hegemon-node"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        stale = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(stale_manifest),
                "--root",
                str(temp),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if stale.returncode == 0 or "contradicts the active profile" not in stale.stdout:
            raise SystemExit("stale cross-target profile marker unexpectedly passed")
    print("release crypto profile canonical/contradiction tests passed")


if __name__ == "__main__":
    main()
