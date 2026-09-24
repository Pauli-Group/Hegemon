#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_smallwood_production_authorization as authorization


def historical_fixture() -> dict[str, object]:
    return {
        "schema_version": 2,
        "claims": [
            {"id": "unrelated.claim", "production_eligible": False},
            {
                "id": authorization.CLAIM_ID,
                "status": "research_only",
                "production_eligible": False,
                "authority": {
                    "kind": "conditional_lean",
                    "production_authorized": False,
                    "shipped_rust_verifier_refinement_proved": False,
                    "qrom_failure_bound_composed": False,
                    "deployed_hash_instantiation_loss_bounded": False,
                    "concrete_pq_security_bits": None,
                    "required_assumptions": ["explicit historical assumption"],
                },
            },
        ],
    }


def expect_diagnostic_rejected(name: str, document: object, expected: str) -> None:
    try:
        authorization.check_historical_claim_document(document)
    except authorization.AuthorizationError as exc:
        if expected not in str(exc):
            raise SystemExit(f"{name}: wrong rejection: {exc}") from exc
        return
    raise SystemExit(f"{name}: malformed historical fixture unexpectedly passed")


def expect_authorization_rejected(name: str, document: object, expected: str) -> None:
    try:
        authorization.check_authorization_document(document)
    except authorization.AuthorizationError as exc:
        if expected not in str(exc):
            raise SystemExit(f"{name}: wrong rejection: {exc}") from exc
        return
    raise SystemExit(f"{name}: historical claim unexpectedly authorized a release")


def main() -> None:
    fixture = historical_fixture()
    authorization.check_historical_claim_document(fixture)
    expect_authorization_rejected(
        "unchanged historical claim",
        fixture,
        "historical V4/Gamma conditional evidence cannot authorize",
    )

    flipped = historical_fixture()
    claim = flipped["claims"][1]
    claim["production_eligible"] = True
    for flag in authorization.REQUIRED_AUTHORITY_FLAGS:
        claim["authority"][flag] = True
    claim["authority"]["concrete_pq_security_bits"] = 128
    expect_authorization_rejected(
        "five-boolean-and-bits flip",
        flipped,
        "production_eligible must remain",
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        fixture_path = Path(temp_dir) / "claims.json"
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        authorization.check_historical_claim_file(fixture_path)
        try:
            authorization.check_authorization_file(fixture_path)
        except authorization.AuthorizationError as exc:
            if "cannot authorize" not in str(exc):
                raise SystemExit(f"historical file: wrong rejection: {exc}") from exc
        else:
            raise SystemExit("historical file unexpectedly authorized a release")

        fixture_path.write_text('{"claims": [], "claims": []}', encoding="utf-8")
        try:
            authorization.check_historical_claim_file(fixture_path)
        except authorization.AuthorizationError as exc:
            if "duplicate JSON key" not in str(exc):
                raise SystemExit(f"duplicate key: wrong rejection: {exc}") from exc
        else:
            raise SystemExit("duplicate-key fixture unexpectedly passed")

        fixture_path.write_text("{", encoding="utf-8")
        try:
            authorization.check_historical_claim_file(fixture_path)
        except authorization.AuthorizationError as exc:
            if "cannot read valid JSON" not in str(exc):
                raise SystemExit(f"malformed JSON: wrong rejection: {exc}") from exc
        else:
            raise SystemExit("malformed JSON fixture unexpectedly passed")

    expect_diagnostic_rejected("non-object root", [], "must be a JSON object")
    expect_diagnostic_rejected("missing claims", {}, "claims must be a JSON array")

    missing_claim = historical_fixture()
    missing_claim["claims"] = missing_claim["claims"][:1]
    expect_diagnostic_rejected("missing claim", missing_claim, "found 0")

    duplicate_claim = historical_fixture()
    duplicate_claim["claims"].append(deepcopy(duplicate_claim["claims"][1]))
    expect_diagnostic_rejected("duplicate claim", duplicate_claim, "found 2")

    wrong_status = historical_fixture()
    wrong_status["claims"][1]["status"] = "verified"
    expect_diagnostic_rejected("wrong status", wrong_status, "research_only")

    eligible = historical_fixture()
    eligible["claims"][1]["production_eligible"] = True
    expect_diagnostic_rejected("eligible", eligible, "must remain")

    for flag in authorization.REQUIRED_AUTHORITY_FLAGS:
        true_flag = historical_fixture()
        true_flag["claims"][1]["authority"][flag] = True
        expect_diagnostic_rejected(f"true {flag}", true_flag, f"authority.{flag}")

        missing_flag = historical_fixture()
        del missing_flag["claims"][1]["authority"][flag]
        expect_diagnostic_rejected(
            f"missing {flag}", missing_flag, "historical authority keys mismatch"
        )

        non_boolean_flag = historical_fixture()
        non_boolean_flag["claims"][1]["authority"][flag] = 0
        expect_diagnostic_rejected(
            f"non-boolean {flag}", non_boolean_flag, f"authority.{flag}"
        )

    injected_flag = historical_fixture()
    injected_flag["claims"][1]["authority"]["successor_authorized"] = True
    expect_diagnostic_rejected(
        "injected successor authority", injected_flag, "authority keys mismatch"
    )

    for bits in (0, True, 127, 128, "128"):
        stated_bits = historical_fixture()
        stated_bits["claims"][1]["authority"]["concrete_pq_security_bits"] = bits
        expect_diagnostic_rejected(
            f"historical concrete bits {bits!r}", stated_bits, "must remain null"
        )

    print(
        "SmallWood historical authorization fixtures: diagnostic pass; "
        "release authorization and 26 mutations rejected"
    )


if __name__ == "__main__":
    main()
