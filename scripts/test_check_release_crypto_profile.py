#!/usr/bin/env python3
from __future__ import annotations

import json
import copy
import hashlib
from unittest.mock import patch
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


def write_profile_command(binary: Path, *, stdout: str = "", stderr: str = "", status: int = 0) -> None:
    script = (
        "#!/bin/sh\n"
        + (f"printf '%s\\n' '{stdout}'\n" if stdout else "")
        + (f"printf '%s\\n' '{stderr}' >&2\n" if stderr else "")
        + f"exit {status}\n"
        + CANONICAL_MARKER
        + "\n"
    )
    binary.write_text(script, encoding="utf-8")
    binary.chmod(0o755)


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
        if (
            static.returncode != 0
            or '"mode": "static-cross-target"' not in static.stdout
            or '"production_authority": false' not in static.stdout
        ):
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

        native_manifest = temp / "native-manifest.json"
        native_manifest.write_text(
            json.dumps(
                {
                    "target_triple": checker.rustc_host(),
                    "artifacts": [{"binary": "hegemon-node", "path": "hegemon-node"}],
                }
            ),
            encoding="utf-8",
        )
        refusal = "Error: " + checker.UNAPPROVED_PROFILE_REFUSAL
        write_profile_command(binary, stderr=refusal, status=1)
        strict_refusal = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if strict_refusal.returncode == 0 or "production profile refused" not in strict_refusal.stdout:
            raise SystemExit("strict mode accepted the unapproved profile refusal")

        reviewed_refusal = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
                "--allow-unapproved-profile",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if (
            reviewed_refusal.returncode != 0
            or '"mode": "review-unapproved-profile"' not in reviewed_refusal.stdout
            or '"production_authority": false' not in reviewed_refusal.stdout
        ):
            raise SystemExit(
                "review mode did not report the exact fail-closed refusal without "
                "production authority:\n" + reviewed_refusal.stdout
            )

        write_profile_command(
            binary,
            stdout='{"passed": true}',
            stderr=refusal,
            status=1,
        )
        refusal_with_output = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
                "--allow-unapproved-profile",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if refusal_with_output.returncode == 0:
            raise SystemExit("review mode accepted a refusal mixed with success JSON")

        write_profile_command(binary, stderr=refusal, status=137)
        refusal_with_crash_status = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
                "--allow-unapproved-profile",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if refusal_with_crash_status.returncode == 0:
            raise SystemExit("review mode accepted the refusal with exit status 137")

        write_profile_command(binary, stderr="Error: unrelated runtime failure", status=1)
        unexpected_failure = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
                "--allow-unapproved-profile",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if unexpected_failure.returncode == 0 or "unrelated runtime failure" not in unexpected_failure.stdout:
            raise SystemExit("review mode accepted an unexpected profile-command failure")

        write_profile_command(binary, stdout="not-json")
        malformed_profile = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(native_manifest),
                "--root",
                str(temp),
                "--require-executed",
                "--allow-unapproved-profile",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if malformed_profile.returncode == 0 or "invalid profile JSON" not in malformed_profile.stdout:
            raise SystemExit("review mode accepted malformed profile output")

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




def private_launch_tests() -> None:
    """Synthetic pinned fixtures exercise the adapter, never real authority."""
    controls = 0
    with tempfile.TemporaryDirectory(prefix="private-profile-synthetic-test-") as raw:
        root = Path(raw).resolve()
        (root / "scripts").mkdir()
        manifest_path = root / "manifest.json"
        registry_path = root / "scripts/private_spend_launch_authorized_registry.json"
        authorizer = root / "scripts/check_private_spend_launch_authorization.py"
        receipt_path = root / "synthetic-authorization.json"
        binaries = [root / name for _, name in checker.PRIVATE_LAUNCH_ARTIFACTS]
        refusal = "Error: " + checker.UNAPPROVED_PROFILE_REFUSAL

        def fixture():
            for binary in binaries:
                write_profile_command(binary, stderr=refusal, status=1)
            identity = dict(checker.PRIVATE_LAUNCH_PROFILE,
                network_profile="pre-mainnet", chain_id="01" * 32,
                genesis_hash="02" * 32, manifest_digest="03" * 64,
                deactivation_height_exclusive=None, max_total_proofs=None)
            manifest = {"target_triple": "synthetic-test-host", "artifacts": [
                {"package": package, "binary": name, "path": name,
                 "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
                for (package, name), binary in zip(checker.PRIVATE_LAUNCH_ARTIFACTS, binaries, strict=True)]}
            manifest_path.write_text(json.dumps(manifest))
            registry = {"schema": "hegemon.private-spend.source-authorized-registry.v2",
                "release": {"identity": identity}, "final_artifacts": [{
                "target_triple": "synthetic-test-host", "identity": identity,
                "artifact_sha256": {x["binary"]: x["sha256"] for x in manifest["artifacts"]}}]}
            registry_path.write_text(json.dumps(registry))
            receipt = {"schema": "hegemon.private-spend.release-authorization.v2",
                "authorization_kind": "qualified_source_tuple", "identity": identity,
                "production_artifacts_verified": True, "affected_lifecycle_verified": True,
                "deployment_verified": False, "lifecycle_scope": "hgn_single_key_composite",
                "artifact_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest()}
            receipt_path.write_text(json.dumps(receipt))
            # Only this temporary test root contains a synthetic authorizer.
            # Its argv must match the real strict source/artifact invocation.
            authorizer.write_text("import pathlib,sys\n"
                "root=pathlib.Path(__file__).resolve().parents[1]\n"
                "assert sys.argv[1:]==['--require-authorized','--artifact-manifest','manifest.json']\n"
                "print((root/'synthetic-authorization.json').read_text())\n")
            return manifest, registry, receipt

        def run():
            with patch.object(checker, "SOURCE_ROOT", root), patch.object(checker, "rustc_host", return_value="synthetic-test-host"):
                return checker.private_launch_profile(root, manifest_path)

        fixture()
        passed = run()
        assert passed["private_spend_launch_authority"] is True
        assert passed["production_authority"] is False
        assert passed["authorization_scope"] == checker.PRIVATE_LAUNCH_SCOPE
        assert passed["identity"]["public_words"] == 86
        controls += 1
        expect_rejected(lambda: checker.private_launch_profile(root, manifest_path), "source root")
        controls += 1

        for field, value in [("authorization_kind", "operator_opt_in"),
            ("production_artifacts_verified", False), ("affected_lifecycle_verified", 1),
            ("deployment_verified", True), ("lifecycle_scope", "historical77"),
            ("artifact_manifest_sha256", "00" * 32)]:
            _, _, receipt = fixture()
            receipt[field] = value
            receipt_path.write_text(json.dumps(receipt))
            expect_rejected(run, "final source/artifact/lifecycle authorization")
            controls += 1
        for field, value in [("public_words", 77), ("circuit", 11),
            ("relation_digest", "00" * 64), ("network_profile", "development"),
            ("max_total_proofs", 1000)]:
            _, _, receipt = fixture()
            receipt["identity"][field] = value
            receipt_path.write_text(json.dumps(receipt))
            expect_rejected(run, "current86 ongoing HGN identity")
            controls += 1
        _, registry, _ = fixture()
        registry["release"] = None
        registry_path.write_text(json.dumps(registry))
        expect_rejected(run, "source-owned identity")
        controls += 1
        _, registry, _ = fixture()
        registry["final_artifacts"][0]["artifact_sha256"]["wallet"] = "00" * 32
        registry_path.write_text(json.dumps(registry))
        expect_rejected(run, "source-owned final artifacts")
        controls += 1
        fixture()
        authorizer.write_text("raise SystemExit('unqualified current source')\n")
        expect_rejected(run, "source authorization failed")
        controls += 1
        manifest, _, _ = fixture()
        manifest["target_triple"] = "other-target"
        manifest_path.write_text(json.dumps(manifest))
        expect_rejected(run, "exact native target")
        controls += 1
        for mutation in ("missing", "extra", "reordered", "wrong-package"):
            manifest, _, _ = fixture()
            if mutation == "missing":
                manifest["artifacts"].pop()
            elif mutation == "extra":
                manifest["artifacts"].append(dict(manifest["artifacts"][-1]))
            elif mutation == "reordered":
                manifest["artifacts"][-2:] = reversed(manifest["artifacts"][-2:])
            else:
                manifest["artifacts"][-1]["package"] = "private-spend"
            manifest_path.write_text(json.dumps(manifest))
            expect_rejected(run, "requires exactly node/wallet/walletd/private-spend")
            controls += 1
        manifest, _, _ = fixture()
        manifest["artifacts"][-1]["path"] = manifest["artifacts"][0]["path"]
        manifest["artifacts"][-1]["sha256"] = manifest["artifacts"][0]["sha256"]
        manifest_path.write_text(json.dumps(manifest))
        expect_rejected(run, "artifact paths must be distinct")
        controls += 1
        for index in (1, 3):
            fixture()
            binaries[index].write_text(binaries[index].read_text() + "# changed after manifest\n")
            expect_rejected(run, "digest differs from manifest")
            controls += 1
        for index in (2, 3):
            fixture()
            write_profile_command(binaries[index], stderr="Error: unrelated failure", status=1)
            # Repin the intentionally changed fixture so the execution check runs.
            manifest = json.loads(manifest_path.read_text())
            manifest["artifacts"][index]["sha256"] = hashlib.sha256(binaries[index].read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            expect_rejected(run, "unrelated failure")
            controls += 1
        for index in (1, 3):
            fixture()
            write_profile_command(binaries[index], stdout=json.dumps(canonical_profile()))
            manifest = json.loads(manifest_path.read_text())
            manifest["artifacts"][index]["sha256"] = hashlib.sha256(binaries[index].read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            expect_rejected(run, "every legacy profile to refuse exactly")
            controls += 1
        fixture()
        authorizer.write_text(authorizer.read_text()
            + "pathlib.Path(__file__).write_text(pathlib.Path(__file__).read_text()+'\\n# changed\\n')\n")
        expect_rejected(run, "authority changed during validation")
        controls += 1
    print(f"private launch adapter synthetic controls passed: {controls}")


if __name__ == "__main__":
    main()
    private_launch_tests()
