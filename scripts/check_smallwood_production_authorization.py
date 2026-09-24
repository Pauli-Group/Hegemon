#!/usr/bin/env python3
"""Validate the historical SmallWood claim without granting release authority.

The claim checked here is the conditional V4/Gamma reduction.  It is retained
as diagnostic evidence and is not an authorization slot for any successor
proof system.  In particular, changing claim-ledger booleans can never make
this program authorize a release.  A future transaction-proof family must use
the separate, source-registry-backed successor authorization gate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import NoReturn


CLAIM_ID = "formal.deployed-smallwood-no-counterfeit-critical-path"
REQUIRED_AUTHORITY_FLAGS = (
    "production_authorized",
    "shipped_rust_verifier_refinement_proved",
    "qrom_failure_bound_composed",
    "deployed_hash_instantiation_loss_bounded",
)
HISTORICAL_AUTHORITY_KEYS = {
    "kind",
    *REQUIRED_AUTHORITY_FLAGS,
    "concrete_pq_security_bits",
    "required_assumptions",
}


class AuthorizationError(ValueError):
    """The claim document does not authorize a production release."""


def _reject(message: str) -> NoReturn:
    raise AuthorizationError(f"{CLAIM_ID}: {message}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def check_historical_claim_document(document: object) -> None:
    """Validate that the retained conditional claim remains non-authoritative."""
    if not isinstance(document, dict):
        _reject("claim document must be a JSON object")
    claims = document.get("claims")
    if not isinstance(claims, list):
        _reject("claims must be a JSON array")

    matches = [
        claim
        for claim in claims
        if isinstance(claim, dict) and claim.get("id") == CLAIM_ID
    ]
    if len(matches) != 1:
        _reject(f"expected exactly one claim, found {len(matches)}")
    claim = matches[0]

    if claim.get("status") != "research_only":
        _reject("historical claim status must remain research_only")
    if claim.get("production_eligible") is not False:
        _reject("historical claim production_eligible must remain the boolean false")

    authority = claim.get("authority")
    if not isinstance(authority, dict):
        _reject("authority must be a JSON object")
    if set(authority) != HISTORICAL_AUTHORITY_KEYS:
        _reject(
            "historical authority keys mismatch; "
            f"missing={sorted(HISTORICAL_AUTHORITY_KEYS - set(authority))} "
            f"extra={sorted(set(authority) - HISTORICAL_AUTHORITY_KEYS)}"
        )
    if authority.get("kind") != "conditional_lean":
        _reject("historical authority.kind must remain conditional_lean")
    for flag in REQUIRED_AUTHORITY_FLAGS:
        if authority.get(flag) is not False:
            _reject(f"historical authority.{flag} must remain the boolean false")

    bits = authority.get("concrete_pq_security_bits")
    if bits is not None:
        _reject("historical authority.concrete_pq_security_bits must remain null")
    assumptions = authority.get("required_assumptions")
    if (
        not isinstance(assumptions, list)
        or not assumptions
        or any(not isinstance(value, str) or not value.strip() for value in assumptions)
    ):
        _reject("historical authority.required_assumptions must remain a nonempty string array")


def check_authorization_document(document: object) -> NoReturn:
    """Always reject release authority after validating the historical posture."""
    check_historical_claim_document(document)
    _reject(
        "historical V4/Gamma conditional evidence cannot authorize a successor release; "
        "use the source-registry-backed transaction-proof successor gate"
    )


def _load_claim_file(path: Path) -> object:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"cannot read valid JSON from {path}: {exc}") from exc
    return document


def check_historical_claim_file(path: Path) -> None:
    check_historical_claim_document(_load_claim_file(path))


def check_authorization_file(path: Path) -> NoReturn:
    check_authorization_document(_load_claim_file(path))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "claims",
        nargs="?",
        type=Path,
        default=Path("config/formal-security-claims.json"),
    )
    parser.add_argument(
        "--diagnostic-only",
        action="store_true",
        help="validate that the historical claim remains explicitly non-authoritative",
    )
    args = parser.parse_args()
    try:
        if args.diagnostic_only:
            check_historical_claim_file(args.claims)
        else:
            check_authorization_file(args.claims)
    except AuthorizationError as exc:
        raise SystemExit(f"SmallWood production release unauthorized: {exc}") from exc
    print(f"SmallWood historical claim diagnostic passed: claim={CLAIM_ID} authority=none")


if __name__ == "__main__":
    main()
