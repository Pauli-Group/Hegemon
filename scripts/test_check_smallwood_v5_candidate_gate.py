#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_smallwood_v5_candidate_gate as gate


STRICT_REPORT = {
    "schema": gate.STRICT_SECURITY_REPORT_SCHEMA,
    "profile_id": gate.STRICT_SECURITY_PROFILE_ID,
    "input_valid": True,
    "capabilities": {
        "complete_zk": True,
        "pq128": True,
        "production_authorized": True,
    },
    "required_evidence_count": 24,
    "verified_evidence_count": 24,
    "profile_gate_pass": True,
    "complete_zk_evidence_pass": True,
    "pq128_evidence_pass": True,
    "soundness": {
        "low_advantage_gate_pass": True,
        "work_factor_gate_pass": True,
    },
    "zero_knowledge": {"numeric_gate_pass": True},
}


def inactive_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile_id": gate.PROFILE_ID,
        "strict_security_profile_id": gate.STRICT_SECURITY_PROFILE_ID,
        "identity": deepcopy(gate.EXPECTED_IDENTITY),
        "production_active": False,
        "capabilities": {name: False for name in gate.REQUIRED_CAPABILITIES},
        "security": {
            "concrete_pq_security_bits": None,
            "relation_hash_output_bits": None,
            "proof_transcript_hash_output_bits": None,
        },
        "relation_binding_hex": None,
        "measured_proof_bytes": None,
        "artifacts": {name: None for name in gate.REQUIRED_ARTIFACTS},
        "claim_boundary": "test fixture",
    }


def authorized_fixture(root: Path) -> dict[str, object]:
    fixture = inactive_fixture()
    fixture["production_active"] = True
    fixture["capabilities"] = {name: True for name in gate.REQUIRED_CAPABILITIES}
    fixture["security"] = {
        "concrete_pq_security_bits": 128,
        "relation_hash_output_bits": 448,
        "proof_transcript_hash_output_bits": 512,
    }
    fixture["relation_binding_hex"] = "52" * 48
    fixture["measured_proof_bytes"] = 90_000
    artifacts: dict[str, object] = {}
    for index, name in enumerate(gate.REQUIRED_ARTIFACTS):
        relative = Path("artifacts") / f"{name}.bin"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if name == "strict_security_evaluation":
            payload = (json.dumps(STRICT_REPORT, indent=2, sort_keys=True) + "\n").encode()
        else:
            payload = f"{index}:{name}:reviewed evidence".encode()
        path.write_bytes(payload)
        artifacts[name] = {
            "path": relative.as_posix(),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    fixture["artifacts"] = artifacts
    return fixture


def expect_rejected(
    name: str,
    document: object,
    expected: str,
    root: Path,
    require_authorized: bool = True,
) -> None:
    try:
        gate.check_document(document, root, require_authorized)
    except gate.CandidateGateError as exc:
        if expected not in str(exc):
            raise SystemExit(f"{name}: wrong rejection: {exc}") from exc
        return
    raise SystemExit(f"{name}: malformed fixture unexpectedly passed")


def main() -> None:
    if gate.check_document(inactive_fixture(), ROOT, False) is not False:
        raise SystemExit("inactive fixture did not return inactive posture")
    expect_rejected(
        "inactive authorization",
        inactive_fixture(),
        "production_active must be true",
        ROOT,
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        authorized = authorized_fixture(root)
        saved_trust_pin = os.environ.pop(gate.STRICT_TRUST_ROOT_DIGEST_ENV, None)
        try:
            expect_rejected(
                "active without protected trust-root pin",
                authorized,
                gate.STRICT_TRUST_ROOT_DIGEST_ENV,
                root,
            )
        finally:
            if saved_trust_pin is not None:
                os.environ[gate.STRICT_TRUST_ROOT_DIGEST_ENV] = saved_trust_pin
        real_strict_authorizer = gate.check_strict_security_authorization
        gate.check_strict_security_authorization = lambda _root: deepcopy(STRICT_REPORT)
        if gate.check_document(authorized, root, True) is not True:
            raise SystemExit("authorized fixture did not return authorized posture")

        identity = deepcopy(authorized)
        identity["identity"]["circuit"] = 4
        expect_rejected("identity", identity, "identity does not exactly match", root)

        identity_bool = deepcopy(authorized)
        identity_bool["identity"]["profile_wire_id"] = True
        expect_rejected("identity bool", identity_bool, "wrong JSON type", root)

        for capability in gate.REQUIRED_CAPABILITIES:
            partial = deepcopy(authorized)
            partial["capabilities"][capability] = False
            expect_rejected(
                f"partial {capability}", partial, capability, root
            )

        non_boolean = deepcopy(authorized)
        non_boolean["capabilities"]["proof_system_implemented"] = 1
        expect_rejected("non-boolean", non_boolean, "must be a boolean", root)

        pq127 = deepcopy(authorized)
        pq127["security"]["concrete_pq_security_bits"] = 127
        expect_rejected("pq127", pq127, "at least 128", root)

        relation384 = deepcopy(authorized)
        relation384["security"]["relation_hash_output_bits"] = 384
        expect_rejected("relation384", relation384, "integer 448", root)

        inactive_relation384 = inactive_fixture()
        inactive_relation384["security"]["relation_hash_output_bits"] = 384
        expect_rejected(
            "inactive relation384",
            inactive_relation384,
            "integer 448",
            root,
            require_authorized=False,
        )

        transcript511 = deepcopy(authorized)
        transcript511["security"]["proof_transcript_hash_output_bits"] = 511
        expect_rejected("transcript511", transcript511, "integer 512", root)

        zero_relation = deepcopy(authorized)
        zero_relation["relation_binding_hex"] = "00" * 48
        expect_rejected("zero relation", zero_relation, "must be nonzero", root)

        oversized = deepcopy(authorized)
        oversized["measured_proof_bytes"] = gate.EXPECTED_IDENTITY["max_proof_bytes"] + 1
        expect_rejected("oversized", oversized, "no greater than", root)

        bad_digest = deepcopy(authorized)
        bad_digest["artifacts"]["proof"]["sha256"] = "00" * 32
        expect_rejected("artifact digest", bad_digest, "sha256 mismatch", root)

        missing_artifact = deepcopy(authorized)
        missing_artifact["artifacts"]["proof"] = None
        expect_rejected("missing artifact", missing_artifact, "must be an object", root)

        traversal = deepcopy(authorized)
        traversal["artifacts"]["proof"]["path"] = "../proof.bin"
        expect_rejected("artifact traversal", traversal, "stay inside", root)

        extra_key = deepcopy(authorized)
        extra_key["undeclared_authority"] = True
        expect_rejected("extra top-level key", extra_key, "manifest keys mismatch", root)

        strict_report_mismatch = deepcopy(authorized)
        bad_report_path = root / "artifacts" / "strict_security_evaluation_bad.bin"
        bad_report_payload = b'{"production_authorized":true}\n'
        bad_report_path.write_bytes(bad_report_payload)
        strict_report_mismatch["artifacts"]["strict_security_evaluation"] = {
            "path": bad_report_path.relative_to(root).as_posix(),
            "bytes": len(bad_report_payload),
            "sha256": hashlib.sha256(bad_report_payload).hexdigest(),
        }
        expect_rejected(
            "strict report substitution",
            strict_report_mismatch,
            "not the exact derived strict report",
            root,
        )

        manifest = root / "duplicate.json"
        manifest.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
        try:
            gate.load_document(manifest)
        except gate.CandidateGateError as exc:
            if "duplicate JSON key" not in str(exc):
                raise SystemExit(f"duplicate key: wrong rejection: {exc}") from exc
        else:
            raise SystemExit("duplicate-key manifest unexpectedly parsed")
        gate.check_strict_security_authorization = real_strict_authorizer

    checked_in = gate.load_document(
        ROOT / "config" / "smallwood-v5-conventional-hash-candidate.json"
    )
    if gate.check_document(checked_in, ROOT, False) is not False:
        raise SystemExit("checked-in candidate manifest must remain inactive")
    negative_count = 17 + len(gate.REQUIRED_CAPABILITIES)
    print(
        "SmallWood V5 candidate gate fixtures: "
        f"2 positive and {negative_count} negative passed"
    )


if __name__ == "__main__":
    main()
