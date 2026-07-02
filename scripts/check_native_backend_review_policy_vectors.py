#!/usr/bin/env python3
"""Check Lean-generated native backend review-policy vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_CASES = (
    ("native_tx_leaf_valid", "native_tx_leaf", True, False),
    ("native_tx_leaf_invalid_spec_digest", "native_tx_leaf", False, True),
    ("native_tx_leaf_invalid_params_fingerprint", "native_tx_leaf", False, True),
    ("native_tx_leaf_invalid_stark_proof", "native_tx_leaf", False, True),
    ("native_tx_leaf_invalid_proof_digest", "native_tx_leaf", False, True),
    ("native_tx_leaf_invalid_trailing_bytes", "native_tx_leaf", False, True),
    ("receipt_root_valid", "receipt_root", True, False),
    ("receipt_root_invalid_spec_digest", "receipt_root", False, True),
    ("receipt_root_invalid_fold_rows", "receipt_root", False, True),
    ("receipt_root_invalid_root_commitment", "receipt_root", False, True),
    ("receipt_root_invalid_trailing_bytes", "receipt_root", False, True),
)

SUPPORTED_KINDS = {"native_tx_leaf", "receipt_root"}


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


def required_case_covered(cases: list[dict], required: tuple[str, str, bool, bool]) -> bool:
    required_name, required_kind, required_valid, required_has_error = required
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
