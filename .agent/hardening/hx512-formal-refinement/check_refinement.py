#!/usr/bin/env python3
"""Source-only, fail-closed HX512 Lean/Rust refinement gate.

The default mode verifies the retained inactive boundary.  It succeeds only
when every frozen source matches, the Lean model remains imported, all current
missing-refinement flags remain false, and production remains unauthorized.
`--require-qualified` additionally requires every Rust-to-Lean gate and must
therefore fail until real conformance/refinement evidence replaces this
checkpoint.  The checker never treats a source hash as semantic refinement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONTRACT_PATH = HERE / "contract.json"
FORMAL_ROOT_PATH = ROOT / "formal/crypto/HegemonCrypto.lean"


class RefinementGateError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def safe_source(relative: str) -> bytes:
    path = ROOT / relative
    if not path.is_file() or path.is_symlink():
        raise RefinementGateError(f"missing regular non-symlink source: {relative}")
    if not path.resolve().is_relative_to(ROOT):
        raise RefinementGateError(f"source escapes repository: {relative}")
    return path.read_bytes()


def sha512(raw: bytes) -> str:
    return hashlib.sha512(raw).hexdigest()


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RefinementGateError("missing regular non-symlink refinement contract")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "hegemon-hx512-formal-refinement-v1":
        raise RefinementGateError("unsupported HX512 formal-refinement schema")
    return value


def audit(contract: dict[str, Any]) -> dict[str, Any]:
    integrity_errors: list[str] = []
    blockers: list[str] = []

    sources = contract.get("frozen_sources")
    if not isinstance(sources, dict):
        raise RefinementGateError("frozen_sources must be an object")
    for relative, record in sources.items():
        if not isinstance(relative, str) or not isinstance(record, dict):
            raise RefinementGateError("malformed frozen source entry")
        expected = record.get("sha512")
        if expected is None:
            blockers.append(f"unfrozen_source:{relative}")
            continue
        if not isinstance(expected, str) or len(expected) != 128:
            integrity_errors.append(f"invalid_sha512_pin:{relative}")
            continue
        observed = sha512(safe_source(relative))
        if observed != expected:
            integrity_errors.append(
                f"source_drift:{relative}:expected={expected}:observed={observed}"
            )

    formal_root = FORMAL_ROOT_PATH.read_text(encoding="utf-8")
    required_import = "import HegemonCrypto.SmallWoodHx512Refinement"
    if required_import not in formal_root.splitlines():
        integrity_errors.append("formal_root_import_missing")

    lean_source = safe_source(
        "formal/crypto/HegemonCrypto/SmallWoodHx512Refinement.lean"
    ).decode("utf-8")
    required_markers = (
        "def deferredPrefixBytes : Nat := 3 * digestBytes",
        "def exactDecsQueryCount : Nat := 48",
        "def exactLeafTapeBytes : Nat := 72",
        "theorem decs_root_request_message_exact_136_bytes",
        "requested := geometry.eta * geometry.lvcsRows",
        "max geometry.nonlinearConstraintCount geometry.linearConstraintCount",
        "kind := .canonicalSortedDistinctIndex",
        "structure OracleOutputWidths",
        "def SmallWoodEquation14HighDegreeTermDischarged : Prop := False",
        "theorem q48_s6_eta5_has_no_soundness_authority",
        "theorem decodeFreshCoreExact_encode",
        "theorem decodeFreshCoreExact_sound",
        "theorem decodeFreshCoreExactCapped_sound",
        "theorem decodeFreshCoreExactCapped_rejects_over_cap",
        "theorem canonical_fresh_core_encoding_injective",
        "theorem deferred_acceptance_requires_root_then_h3_then_h5",
        "theorem eager_deferred_equivalence_under_hash_xof_refinement",
        "def frozenEngineSourcePin : Option SourcePin := none",
        "def canonicalFreshProtocolIdentity : Option (List Byte) := none",
        "theorem production_authority_fails_closed",
    )
    for marker in required_markers:
        if marker not in lean_source:
            integrity_errors.append(f"lean_marker_missing:{marker}")

    codec = contract.get("codec")
    transcript = contract.get("transcript")
    refinement = contract.get("rust_to_lean")
    if not isinstance(codec, dict) or not isinstance(transcript, dict):
        raise RefinementGateError("codec/transcript contracts must be objects")
    if not isinstance(refinement, dict):
        raise RefinementGateError("rust_to_lean must be an object")

    expected_codec = {
        "digest_bytes": 64,
        "deferred_prefix_bytes": 192,
        "prefix_fields": [
            "raw_decs_root64",
            "h3_piop_input64",
            "h5_piop_transcript64",
        ],
        "nonce_serialized": False,
        "u32_byte_order": "big",
        "u64_field_byte_order": "big",
        "field_modulus": 18446744069414584321,
        "decs_query_count": 48,
        "leaf_tape_bytes": 72,
        "authentication_path_maximum_depth": 20,
        "exact_consumption": True,
    }
    if codec != expected_codec:
        integrity_errors.append("codec_contract_drift")

    if transcript.get("event_count") != 8:
        integrity_errors.append("transcript_event_count_drift")
    if transcript.get("deferred_readback_order") != [
        "raw_decs_root",
        "h3_piop_input",
        "h5_piop_transcript",
    ]:
        integrity_errors.append("deferred_readback_order_drift")
    if transcript.get("terminal_ninth_event") is not False:
        integrity_errors.append("terminal_ninth_event_must_be_false")
    if transcript.get("decs_root_request_message_bytes") != 136:
        integrity_errors.append("decs_root_request_message_width_drift")
    if transcript.get("xof_requests") != {
        "decs_coefficients": "eta_times_lvcs_rows_goldilocks",
        "piop_coefficients": "rho_times_max_nonlinear_linear_goldilocks",
        "piop_openings": 6,
        "decs_queries": 48,
        "decs_query_domain": 1048576,
        "decs_queries_sorted_distinct": True,
    }:
        integrity_errors.append("xof_request_descriptor_drift")

    required_true_now = ("transcript_source_readback",)
    for field in required_true_now:
        if refinement.get(field) is not True:
            integrity_errors.append(f"required_inactive_evidence_missing:{field}")

    qualification_fields = (
        "engine_source_readback",
        "exact_engine_geometry_frozen",
        "fresh_core_codec_conformance",
        "sha512_request_framing_refinement",
        "shake256_count_modulus_distinct_sampler_refinement",
        "abstract_oracle_output_width_refinement",
        "smallwood_equation14_high_degree_codeword_weight_discharged",
        "eager_deferred_schedule_refinement",
        "compiled_relation_refinement",
        "canonical_protocol_identity_allocated",
    )
    for field in qualification_fields:
        value = refinement.get(field)
        if value is not False:
            integrity_errors.append(f"inactive_flag_must_remain_false:{field}")
        else:
            blockers.append(f"missing_refinement:{field}")
    if refinement.get("production_authorized") is not False:
        integrity_errors.append("production_authorized_must_remain_false")
    else:
        blockers.append("production_unauthorized")

    qualified = not integrity_errors and not blockers
    return {
        "schema": "hegemon-hx512-formal-refinement-report-v1",
        "contract_sha512": sha512((canonical_json(contract) + "\n").encode()),
        "integrity_errors": integrity_errors,
        "qualification_blockers": blockers,
        "qualified": qualified,
        "production_authorized": qualified
        and refinement.get("production_authorized") is True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-qualified", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = audit(load_contract())
    except (OSError, ValueError, RefinementGateError) as error:
        print(f"HX512 formal-refinement gate error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "HX512 formal-refinement source boundary: "
            f"integrity_errors={len(report['integrity_errors'])}, "
            f"qualification_blockers={len(report['qualification_blockers'])}, "
            f"qualified={str(report['qualified']).lower()}, "
            "production_authorized="
            f"{str(report['production_authorized']).lower()}"
        )
    if report["integrity_errors"]:
        return 1
    if args.require_qualified and not report["qualified"]:
        return 1
    if not args.require_qualified and report["production_authorized"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
