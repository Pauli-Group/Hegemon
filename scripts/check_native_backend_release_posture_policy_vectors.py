#!/usr/bin/env python3
"""Check Lean-generated native backend release-posture vectors."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path
from typing import Any


CASE_KEY = "native_backend_release_posture_cases"
PACKAGE_ROOT = "native-backend-128b-review-package"
CLAIM_MEMBER = f"{PACKAGE_ROOT}/current_claim.json"
MANIFEST_MEMBER = f"{PACKAGE_ROOT}/review_manifest.json"


def external_review_allowed_for_candidate(case: dict[str, Any]) -> bool:
    return (
        not bool(case.get("external_review_known"))
        or not bool(case.get("external_review_completed"))
    )


def external_review_allowed_for_accepted(case: dict[str, Any]) -> bool:
    return (
        not bool(case.get("external_review_known"))
        or bool(case.get("external_review_completed"))
    )


def evaluate_case(case: dict[str, Any]) -> tuple[bool, str | None]:
    if bool(case.get("require_accepted")):
        if not bool(case.get("review_state_accepted")):
            return False, "accepted_review_state_mismatch"
        if not external_review_allowed_for_accepted(case):
            return False, "accepted_external_review_incomplete"
        if not bool(case.get("acceptance_artifact_present")):
            return False, "accepted_missing_artifact"
        if not (
            bool(case.get("acceptance_artifact_mentions_accepted"))
            and bool(case.get("acceptance_artifact_mentions_external"))
        ):
            return False, "accepted_malformed_artifact"
        return True, None

    if not bool(case.get("review_state_candidate_under_review")):
        return False, "candidate_review_state_mismatch"
    if not bool(case.get("maturity_structural_candidate")):
        return False, "candidate_maturity_mismatch"
    if not external_review_allowed_for_candidate(case):
        return False, "candidate_external_review_complete"
    return True, None


def check_vectors(vectors: dict[str, Any]) -> int:
    if vectors.get("schema_version") != 1:
        raise SystemExit(f"unsupported schema_version: {vectors.get('schema_version')!r}")
    cases = vectors.get(CASE_KEY)
    if not isinstance(cases, list) or not cases:
        raise SystemExit(f"{CASE_KEY} must be a non-empty list")

    names: set[str] = set()
    for case in cases:
        name = case.get("name")
        if not isinstance(name, str) or not name:
            raise SystemExit("release-posture case name must be a non-empty string")
        if name in names:
            raise SystemExit(f"duplicate release-posture case name: {name}")
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


def read_json_member(package_path: Path, member_name: str) -> dict[str, Any]:
    with tarfile.open(package_path, "r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise SystemExit(
                f"{package_path}: missing required package member {member_name}"
            ) from exc
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit(f"{package_path}: package member is not a file: {member_name}")
        return json.loads(extracted.read().decode("utf-8"))


def load_manifest(path: Path | None, package_path: Path | None) -> dict[str, Any] | None:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    if package_path is not None:
        return read_json_member(package_path, MANIFEST_MEMBER)
    return None


def load_claim(path: Path | None, package_path: Path | None) -> dict[str, Any] | None:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    if package_path is not None:
        return read_json_member(package_path, CLAIM_MEMBER)
    return None


def acceptance_artifact_flags(path: Path | None) -> tuple[bool, bool, bool]:
    if path is None or not path.is_file():
        return False, False, False
    text = path.read_text(encoding="utf-8").lower()
    return True, "accepted" in text, "external" in text


def live_case_from_inputs(
    claim: dict[str, Any],
    manifest: dict[str, Any] | None,
    *,
    require_accepted: bool,
    acceptance_artifact: Path | None,
) -> dict[str, Any]:
    claim_body = claim.get("native_security_claim") or {}
    params = claim.get("native_backend_params") or {}
    review_state = claim_body.get("review_state")
    maturity = params.get("maturity_label")

    external_done = None
    if manifest is not None:
        guarantees = manifest.get("guarantee_summary") or {}
        external_done = guarantees.get("external_cryptanalysis_completed")

    artifact_present, artifact_accepted, artifact_external = acceptance_artifact_flags(
        acceptance_artifact
    )
    return {
        "name": "checked-in-native-backend-release-posture",
        "require_accepted": require_accepted,
        "review_state_candidate_under_review": review_state == "candidate_under_review",
        "review_state_accepted": review_state == "accepted",
        "maturity_structural_candidate": maturity == "structural_candidate",
        "external_review_known": external_done is not None,
        "external_review_completed": external_done is True,
        "acceptance_artifact_present": artifact_present,
        "acceptance_artifact_mentions_accepted": artifact_accepted,
        "acceptance_artifact_mentions_external": artifact_external,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="check Lean native-backend release-posture vectors"
    )
    parser.add_argument("vectors", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--claim-json", type=Path)
    parser.add_argument("--review-manifest", type=Path)
    parser.add_argument("--require-accepted", action="store_true")
    parser.add_argument("--acceptance-artifact", type=Path)
    args = parser.parse_args()

    if args.package is not None and args.claim_json is not None:
        raise SystemExit("--package and --claim-json are mutually exclusive")
    if args.package is not None and args.review_manifest is not None:
        raise SystemExit("--package and --review-manifest are mutually exclusive")
    if args.require_accepted and args.acceptance_artifact is None:
        raise SystemExit("--require-accepted requires --acceptance-artifact")

    vector_count = check_vectors(json.loads(args.vectors.read_text(encoding="utf-8")))
    summary: dict[str, Any] = {"passed": True, "policy_cases": vector_count}

    claim = load_claim(args.claim_json, args.package)
    if claim is not None:
        live_case = live_case_from_inputs(
            claim,
            load_manifest(args.review_manifest, args.package),
            require_accepted=args.require_accepted,
            acceptance_artifact=args.acceptance_artifact,
        )
        live_valid, live_rejection = evaluate_case(live_case)
        if not live_valid:
            raise SystemExit(
                "checked-in native backend release posture violates Lean policy: "
                f"{live_rejection}"
            )
        summary["live_case"] = live_case["name"]
        summary["require_accepted"] = args.require_accepted

    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
