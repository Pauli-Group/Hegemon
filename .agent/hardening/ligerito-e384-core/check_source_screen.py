#!/usr/bin/env python3
"""Validate the retained Ligerito source screen without generating a proof."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CORE_PATH = HERE / "ligerito_e384_core.py"
TEST_PATH = HERE / "test_ligerito_e384_core.py"
SCREEN_PATH = HERE / "source_screen.json"


def _load_core():
    spec = importlib.util.spec_from_file_location("ligerito_e384_core", CORE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the owned Ligerito core")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    for path in (CORE_PATH, TEST_PATH, Path(__file__)):
        ast.parse(path.read_text(), filename=str(path))

    certificate = json.loads(SCREEN_PATH.read_text())
    if certificate.get("schema") != "hegemon.ligerito-e384-core.retained-source-screen.v1":
        raise AssertionError("retained source-screen schema drift")
    for name, expected in certificate.get("source_sha256", {}).items():
        path = HERE / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"pinned owned source drift: {name}")

    core_source = CORE_PATH.read_text()
    if "hashlib.sha512" not in core_source or "hashlib.shake" in core_source:
        raise AssertionError("the core is not exclusively on conventional SHA-512")
    required_api = (
        "class OneLevelInteractiveProver",
        "def verify_interactive",
        "class Proof",
        "def prove",
        "def verify",
        "def extract_interactive_view",
        "def export_observation_rows",
        "def complete_zk_contract",
    )
    missing_api = [name for name in required_api if name not in core_source]
    if missing_api:
        raise AssertionError(f"required source API missing: {missing_api}")

    test_source = TEST_PATH.read_text()
    required_mutations = (
        "test_parser_rejects_truncation_trailing_and_profile_drift",
        "test_statement_context_functional_and_claim_are_bound",
        "test_every_wire_section_is_mutation_bound",
        "test_compact_multiproof_padding_is_canonical",
        "test_underlying_interactive_state_machine_precedes_fiat_shamir",
        "test_complete_zk_interface_cannot_authorize",
    )
    missing_tests = [name for name in required_mutations if name not in test_source]
    if missing_tests:
        raise AssertionError(f"required negative-test source missing: {missing_tests}")

    core = _load_core()
    report = core.report()
    retained = certificate["n16_best_under_512mib"]
    live = report["n16_best_under_512mib"]
    exact_pairs = {
        "fold_variables": live["fold_variables"],
        "log_inv_rate": live["log_inv_rate"],
        "query_count": live["query_count"],
        "encoded_oracle_bytes": live["encoded_oracle_bytes"],
        "profile_id_sha512": live["profile_id_sha512"],
        "veil_source_structure_direct_floor_bytes": live[
            "veil_source_structure_direct_floor_bytes"
        ],
        "core_plus_direct_floor_only_bytes": live[
            "core_plus_direct_floor_only_bytes"
        ],
    }
    for key, expected in exact_pairs.items():
        if retained.get(key) != expected:
            raise AssertionError(f"retained source screen drift: {key}")
    if retained["wire"]["total"] != live["proof_bytes"]:
        raise AssertionError("retained proof-byte total drift")
    for key, value in live["wire_ledger"].items():
        if retained["wire"].get(key) != value:
            raise AssertionError(f"retained wire ledger drift: {key}")
    for key, value in live["resource_ledger"].items():
        if retained["resources"].get(key) != value:
            raise AssertionError(f"retained resource ledger drift: {key}")

    optimistic_retained = certificate["n16_optimistic_source128_under_512mib"]
    optimistic_live = report["n16_optimistic_source128_under_512mib"]
    for key in (
        "fold_variables",
        "log_inv_rate",
        "query_count",
        "encoded_oracle_bytes",
        "profile_id_sha512",
        "veil_source_structure_direct_floor_bytes",
        "core_plus_direct_floor_only_bytes",
    ):
        if optimistic_retained.get(key) != optimistic_live.get(key):
            raise AssertionError(f"retained optimistic source screen drift: {key}")
    if optimistic_retained["wire"]["total"] != optimistic_live["proof_bytes"]:
        raise AssertionError("retained optimistic proof-byte total drift")
    for key, value in optimistic_live["wire_ledger"].items():
        if optimistic_retained["wire"].get(key) != value:
            raise AssertionError(f"retained optimistic wire ledger drift: {key}")
    for key, value in optimistic_live["resource_ledger"].items():
        if optimistic_retained["resources"].get(key) != value:
            raise AssertionError(f"retained optimistic resource ledger drift: {key}")

    comparator = report["comparator"]
    retained_comparator = certificate["comparators"]
    comparator_pairs = {
        "smallwood_active_like_report_bytes": comparator[
            "smallwood_active_like_report_bytes"
        ],
        "optimistic_source128_core_minus_smallwood_report_bytes": comparator[
            "optimistic_source128_core_minus_smallwood_report_bytes"
        ],
        "optimistic_source128_core_over_historical_cap_bytes": comparator[
            "optimistic_source128_core_over_historical_cap_bytes"
        ],
        "ligerito_core_minus_smallwood_report_bytes": comparator[
            "ligerito_core_minus_smallwood_report_bytes"
        ],
        "historical_raw_proof_cap_bytes": comparator[
            "historical_raw_proof_cap_bytes"
        ],
        "ligerito_core_over_historical_cap_bytes": comparator[
            "ligerito_core_over_historical_cap_bytes"
        ],
        "absolute_no_go_proved": comparator["absolute_no_go_proved"],
        "fixed_max_frontier_grammar_disadvantage_established": comparator[
            "fixed_max_frontier_grammar_disadvantage_established"
        ],
    }
    for key, expected in comparator_pairs.items():
        if retained_comparator.get(key) != expected:
            raise AssertionError(f"retained comparator drift: {key}")

    false_gates = (
        "full_relation_witness_generator_Gw_supplied",
        "wrapper_mask_generator_Gr_supplied",
        "rank_gate_proved",
        "complete_zk",
        "strict_pq128",
        "frontier_eligible",
        "production_authorized",
    )
    for key in false_gates:
        if certificate["capabilities"].get(key) is not False:
            raise AssertionError(f"fail-closed retained gate drift: {key}")
    for key in ("complete_zk", "strict_pq128", "frontier_eligible", "production_authorized"):
        if report["capabilities"].get(key) is not False:
            raise AssertionError(f"live fail-closed gate drift: {key}")

    validation = certificate["validation"]
    if validation.get("toy_proof_executed") is not False:
        raise AssertionError("source-only certificate cannot claim an executed proof")
    if validation.get("mutation_tests_executed") is not False:
        raise AssertionError("source-only certificate cannot claim executed mutation tests")

    print("LIGERITO_E384_SOURCE_SCREEN_OK")
    print(f"optimistic_source128_proof_bytes={optimistic_live['proof_bytes']}")
    print(f"optimistic_source128_query_count={optimistic_live['query_count']}")
    print(f"proof_bytes_formula={live['proof_bytes']}")
    print(f"query_count={live['query_count']}")
    print("complete_zk=false")
    print("production_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
