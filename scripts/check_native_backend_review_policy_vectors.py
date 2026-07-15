#!/usr/bin/env python3
"""Check Lean-generated native backend review-policy vectors."""

from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path


REQUIRED_CASES = (
    ("native_tx_leaf_valid", "native_tx_leaf", True, False, None, "none"),
    ("native_tx_leaf_invalid_spec_digest", "native_tx_leaf", False, True, "spec digest mismatch", "native_tx_leaf.spec_digest.byte0.xor01"),
    ("native_tx_leaf_invalid_params_fingerprint", "native_tx_leaf", False, True, "parameter fingerprint mismatch", "native_tx_leaf.params_fingerprint.byte0.xor01"),
    ("native_tx_leaf_invalid_stark_proof", "native_tx_leaf", False, True, "proof verification failed", "native_tx_leaf.stark_proof.byte0.xor80.receipt_rebound"),
    ("native_tx_leaf_invalid_proof_digest", "native_tx_leaf", False, True, "proof digest mismatch", "native_tx_leaf.leaf.proof_digest.byte0.xor01"),
    ("native_tx_leaf_invalid_trailing_bytes", "native_tx_leaf", False, True, "trailing bytes", "native_tx_leaf.trailing.append_ff"),
    ("receipt_root_valid", "receipt_root", True, False, None, "none"),
    ("receipt_root_invalid_spec_digest", "receipt_root", False, True, "spec digest mismatch", "receipt_root.spec_digest.byte0.xor01"),
    ("receipt_root_invalid_fold_rows", "receipt_root", False, True, "parent rows mismatch", "receipt_root.fold0.parent_row0.coeff0.xor01"),
    ("receipt_root_invalid_root_commitment", "receipt_root", False, True, "root commitment mismatch", "receipt_root.root_commitment.byte0.xor01"),
    ("receipt_root_invalid_trailing_bytes", "receipt_root", False, True, "trailing bytes", "receipt_root.trailing.append_aa"),
)

SUPPORTED_KINDS = {"native_tx_leaf", "receipt_root"}
REVIEW_RECEIPT_FIELDS = (
    "statement_hash_hex",
    "proof_digest_hex",
    "public_inputs_digest_hex",
    "verifier_profile_hex",
)


def require_hex(value: object, byte_len: int, label: str) -> None:
    if not isinstance(value, str) or len(value) != byte_len * 2:
        raise SystemExit(f"{label} must be {byte_len}-byte hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{label} is invalid hex") from exc


def require_review_receipt(receipt: object, label: str) -> None:
    if not isinstance(receipt, dict):
        raise SystemExit(f"{label} must be an object")
    for field in REVIEW_RECEIPT_FIELDS:
        require_hex(receipt.get(field), 48, f"{label}.{field}")


def case_kind_supported(case: dict) -> bool:
    return case.get("kind") in SUPPORTED_KINDS


def case_expectation_valid(case: dict) -> bool:
    if bool(case.get("expected_valid")):
        return not bool(case.get("has_expected_error"))
    return bool(case.get("has_expected_error"))


def case_names_distinct(cases: list[dict]) -> bool:
    seen: set[str] = set()
    for case in cases:
        name = case.get("name")
        if name in seen:
            return False
        seen.add(name)
    return True


def required_case_covered(cases: list[dict], required: tuple) -> bool:
    required_name, required_kind, required_valid, required_has_error = required[:4]
    return any(
        case.get("name") == required_name
        and case.get("kind") == required_kind
        and bool(case.get("expected_valid")) == required_valid
        and bool(case.get("has_expected_error")) == required_has_error
        for case in cases
    )


def required_case_coverage(cases: list[dict]) -> bool:
    return all(required_case_covered(cases, required) for required in REQUIRED_CASES)


def evaluate_case(case: dict) -> tuple[bool, str | None]:
    cases = case.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"{case.get('name', '<unnamed>')}: cases must be a list")
    if not (
        bool(case.get("review_state_candidate_under_review"))
        and bool(case.get("maturity_structural_candidate"))
    ):
        return False, "unsupported_review_posture"
    if not (
        int(case.get("claimed_security_bits", -1)) >= 128
        and int(case.get("soundness_floor_bits", -1))
        >= int(case.get("claimed_security_bits", -1))
        and int(case.get("commitment_binding_bits", -1))
        >= int(case.get("claimed_security_bits", -1))
        and int(case.get("composition_loss_bits", -1))
        <= int(case.get("soundness_floor_bits", -1))
    ):
        return False, "insufficient_security_claim"
    if not case_names_distinct(cases):
        return False, "duplicate_case_name"
    if not all(case_kind_supported(vector_case) for vector_case in cases):
        return False, "unsupported_case_kind"
    if not all(case_expectation_valid(vector_case) for vector_case in cases):
        return False, "invalid_case_expectation"
    if not required_case_coverage(cases):
        return False, "missing_required_case"
    return True, None


def bundle_to_policy_case(bundle: dict) -> dict:
    security_claim = bundle.get("native_security_claim", {})
    backend_params = bundle.get("native_backend_params", {})
    return {
        "name": "checked-in-native-backend-vector-bundle",
        "review_state_candidate_under_review": security_claim.get("review_state")
        == "candidate_under_review",
        "maturity_structural_candidate": backend_params.get("maturity_label")
        == "structural_candidate",
        "claimed_security_bits": security_claim.get("claimed_security_bits"),
        "soundness_floor_bits": security_claim.get("soundness_floor_bits"),
        "commitment_binding_bits": security_claim.get("commitment_binding_bits"),
        "composition_loss_bits": security_claim.get("composition_loss_bits"),
        "cases": [
            {
                "name": vector_case.get("name"),
                "kind": vector_case.get("kind"),
                "expected_valid": bool(vector_case.get("expected_valid")),
                "has_expected_error": bool(vector_case.get("expected_error_substring")),
            }
            for vector_case in bundle.get("cases", [])
        ],
    }


def check_vectors(vectors: dict) -> int:
    if vectors.get("schema_version") != 1:
        raise SystemExit(f"unsupported schema_version: {vectors.get('schema_version')!r}")
    cases = vectors.get("native_backend_review_policy_cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("native_backend_review_policy_cases must be a non-empty list")

    names: set[str] = set()
    for case in cases:
        name = case.get("name")
        if not isinstance(name, str) or not name:
            raise SystemExit("policy case name must be a non-empty string")
        if name in names:
            raise SystemExit(f"duplicate policy case name: {name}")
        names.add(name)
        actual_valid, actual_rejection = evaluate_case(case)
        if actual_valid != bool(case.get("expected_valid")):
            raise SystemExit(
                f"{name}: validity drifted from Lean: {actual_valid} != "
                f"{case.get('expected_valid')}"
            )
        if actual_rejection != case.get("expected_rejection"):
            raise SystemExit(
                f"{name}: rejection drifted from Lean: {actual_rejection!r} != "
                f"{case.get('expected_rejection')!r}"
            )
    return len(cases)


def check_bundle(bundle: dict) -> tuple[int, int]:
    if bundle.get("schema_version") != 1:
        raise SystemExit("checked-in native backend vector bundle must use schema_version 1")
    if bundle.get("generator_id") != "hegemon.superneo-bench.native-review":
        raise SystemExit("checked-in native backend vector bundle generator_id mismatch")
    active = bundle.get("active_tx_profile")
    if not isinstance(active, dict):
        raise SystemExit("checked-in native backend vector bundle lacks active_tx_profile")
    expected_active = {
        "circuit_version": 3,
        "crypto_suite": 2,
        "proof_backend": "SmallwoodCandidate",
        "arithmetization": "DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2",
        "public_value_count": 78,
    }
    for field, expected in expected_active.items():
        if active.get(field) != expected:
            raise SystemExit(
                f"checked-in native backend vector bundle active profile {field} "
                f"must be {expected!r}, got {active.get(field)!r}"
            )
    profile_digest = active.get("verifier_profile_sha384_hex")
    if not isinstance(profile_digest, str) or len(profile_digest) != 96:
        raise SystemExit("active verifier_profile_sha384_hex must be 48-byte hex")
    try:
        bytes.fromhex(profile_digest)
    except ValueError as exc:
        raise SystemExit("active verifier_profile_sha384_hex is invalid hex") from exc

    vector_cases = bundle.get("cases")
    if not isinstance(vector_cases, list) or len(vector_cases) != len(REQUIRED_CASES):
        raise SystemExit(
            f"checked-in native backend vector bundle must contain exactly {len(REQUIRED_CASES)} cases"
        )
    artifact_digests: set[str] = set()
    for index, (case, required) in enumerate(zip(vector_cases, REQUIRED_CASES, strict=True)):
        name, kind, expected_valid, _, expected_error, mutation_id = required
        actual_identity = (
            case.get("name"),
            case.get("kind"),
            bool(case.get("expected_valid")),
            case.get("expected_error_substring"),
            case.get("mutation_id"),
        )
        expected_identity = (name, kind, expected_valid, expected_error, mutation_id)
        if actual_identity != expected_identity:
            raise SystemExit(
                f"checked-in native backend vector case {index} identity mismatch: "
                f"{actual_identity!r} != {expected_identity!r}"
            )
        try:
            artifact = bytes.fromhex(case.get("artifact_hex", ""))
        except ValueError as exc:
            raise SystemExit(f"{name}: artifact_hex is invalid") from exc
        digest = hashlib.sha256(artifact).hexdigest()
        if case.get("artifact_sha256") != digest:
            raise SystemExit(f"{name}: artifact_sha256 mismatch")
        if digest in artifact_digests:
            raise SystemExit(f"{name}: artifact aliases another review case")
        artifact_digests.add(digest)
        if kind == "native_tx_leaf":
            tx_context = case.get("tx_context")
            tx = tx_context.get("tx") if isinstance(tx_context, dict) else None
            if not isinstance(tx, dict) or (
                tx.get("version_circuit"), tx.get("version_crypto")
            ) != (3, 2):
                raise SystemExit(f"{name}: tx context is not active V3 (3,2)")
            require_hex(
                tx_context.get("statement_digest_hex"),
                48,
                f"{name}: tx_context.statement_digest_hex",
            )
            require_review_receipt(
                tx_context.get("receipt"), f"{name}: tx_context.receipt"
            )
        else:
            block_context = case.get("block_context")
            leaves = (
                block_context.get("leaves")
                if isinstance(block_context, dict)
                else None
            )
            if not isinstance(leaves, list) or not leaves:
                raise SystemExit(f"{name}: receipt-root context must include leaves")
            child_digests: set[str] = set()
            for leaf_index, leaf in enumerate(leaves):
                if not isinstance(leaf, dict):
                    raise SystemExit(f"{name}: leaf {leaf_index} must be an object")
                try:
                    child_artifact = bytes.fromhex(leaf.get("artifact_hex", ""))
                except ValueError as exc:
                    raise SystemExit(
                        f"{name}: leaf {leaf_index} artifact_hex is invalid"
                    ) from exc
                child_digest = hashlib.sha256(child_artifact).hexdigest()
                if leaf.get("artifact_sha256") != child_digest:
                    raise SystemExit(f"{name}: leaf {leaf_index} artifact SHA-256 mismatch")
                if child_digest in child_digests:
                    raise SystemExit(f"{name}: receipt-root child artifacts must be distinct")
                child_digests.add(child_digest)
                tx_context = leaf.get("tx_context")
                tx = tx_context.get("tx") if isinstance(tx_context, dict) else None
                if not isinstance(tx, dict) or (
                    tx.get("version_circuit"), tx.get("version_crypto")
                ) != (3, 2):
                    raise SystemExit(
                        f"{name}: leaf {leaf_index} tx context is not active V3 (3,2)"
                    )
                require_review_receipt(
                    tx_context.get("receipt"),
                    f"{name}: leaf {leaf_index} tx_context.receipt",
                )

    valid_case = vector_cases[0]
    invalid_stark_case = vector_cases[3]
    valid_receipt = valid_case["tx_context"]["receipt"]
    invalid_receipt = invalid_stark_case["tx_context"]["receipt"]
    if invalid_receipt.get("proof_digest_hex") == valid_receipt.get("proof_digest_hex"):
        raise SystemExit("invalid-STARK review case must rebind its canonical proof digest")

    policy_case = bundle_to_policy_case(bundle)
    actual_valid, actual_rejection = evaluate_case(policy_case)
    if not actual_valid:
        raise SystemExit(
            "checked-in native backend vector bundle violates Lean review policy: "
            f"{actual_rejection}"
        )
    return len(policy_case["cases"]), len(REQUIRED_CASES)


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(
            "usage: check_native_backend_review_policy_vectors.py "
            "<vectors.json> [native-bundle.json]",
            file=sys.stderr,
        )
        return 2

    vector_count = check_vectors(json.loads(Path(sys.argv[1]).read_text()))
    summary: dict[str, object] = {
        "passed": True,
        "policy_cases": vector_count,
    }
    if len(sys.argv) == 3:
        bundle_case_count, required_case_count = check_bundle(
            json.loads(Path(sys.argv[2]).read_text())
        )
        summary["bundle_cases"] = bundle_case_count
        summary["required_cases"] = required_case_count

    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
