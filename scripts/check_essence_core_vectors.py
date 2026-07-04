#!/usr/bin/env python3
import json
import sys
from pathlib import Path


REQUIRED_TYPES = [
    "LedgerState",
    "Action",
    "Block",
    "ObserverView",
    "Transition",
]

REQUIRED_THEOREMS = [
    "Hegemon.Essence.Core.transition_no_counterfeiting",
    "Hegemon.Essence.Core.transition_no_double_spend",
    "Hegemon.Essence.Core.transition_no_theft",
    "Hegemon.Essence.Core.transition_asset_isolation",
    "Hegemon.Essence.Core.transition_per_asset_conservation",
    "Hegemon.Essence.Core.transition_bridge_safety",
    "Hegemon.Essence.Core.transition_privacy_projection",
    "Hegemon.Essence.Core.transition_encoding_no_truncation",
    "Hegemon.Essence.Core.transition_asset_balance_invariants",
    "Hegemon.Essence.Core.transition_nullifiers_unique_derived",
    "Hegemon.Essence.Core.transition_bridge_replay_keys_unique_derived",
    "Hegemon.Essence.Core.action_chain_supply_integrity",
    "Hegemon.Essence.Core.action_chain_nullifiers_unique",
    "Hegemon.Essence.Core.block_transition_supply_integrity",
    "Hegemon.Essence.Core.block_transition_nullifiers_unique",
    "Hegemon.Essence.Core.production_path_refines_core_transition",
    "Hegemon.Essence.Core.production_path_refines_core_security",
    "Hegemon.Essence.Core.production_path_exact_bytes",
    "Hegemon.Essence.Core.failed_production_path_publishes_no_state",
    "Hegemon.Essence.Core.external_assumption_boundary_is_named",
    "Hegemon.Essence.Core.global_privacy_requires_system_model",
    "Hegemon.Essence.Core.canonical_encoding_source_is_core",
    "Hegemon.Essence.Core.canonical_action_encoding_comes_from_core",
    "Hegemon.Essence.Core.canonical_action_term_roundtrip",
    "Hegemon.Essence.Core.canonical_action_term_injective",
    "Hegemon.Essence.Core.canonical_action_term_non_malleable",
]

REQUIRED_STAGES = [
    "parser",
    "admitted_action",
    "replay",
    "storage",
    "publication",
]

REQUIRED_ASSUMPTIONS = [
    "ML-KEM security",
    "ML-DSA security",
    "AEAD security",
    "hash/transcript security",
    "STARK/PCS soundness",
    "DA retention",
    "storage durability",
    "local zero-knowledge",
    "timing privacy",
    "topology privacy",
    "miner-ordering privacy",
    "global traffic privacy",
]

REQUIRED_PROGRESS = {
    "semantic_core_types",
    "core_security_theorems",
    "production_refinement_relation",
    "derived_invariants",
    "asset_ledger_semantics",
    "bridge_receipt_binding",
    "canonical_term_roundtrip",
    "named_assumption_boundary",
    "canonical_encoding_source",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def check_vectors(vectors: dict) -> float:
    require(vectors.get("schema_version") == 1, "unsupported essence vector schema")
    require(
        vectors.get("source_of_truth") == "formal/lean/Hegemon/Essence/Core.lean",
        "unexpected essence source_of_truth",
    )
    require(
        vectors.get("single_canonical_encoding_source") is True,
        "single_canonical_encoding_source must be true",
    )
    require(vectors.get("core_types") == REQUIRED_TYPES, "core type set drifted")
    require(
        vectors.get("production_path_stages") == REQUIRED_STAGES,
        "production path stage order drifted",
    )
    require(
        vectors.get("named_external_assumptions") == REQUIRED_ASSUMPTIONS,
        "named external assumption boundary drifted",
    )
    theorem_set = set(vectors.get("proved_theorems", []))
    missing_theorems = sorted(set(REQUIRED_THEOREMS) - theorem_set)
    require(not missing_theorems, f"missing essence theorem(s): {missing_theorems}")
    progress_items = vectors.get("progress_items", [])
    require(isinstance(progress_items, list), "progress_items must be a list")
    progress_ids = {item.get("id") for item in progress_items}
    require(progress_ids == REQUIRED_PROGRESS, "progress item set drifted")
    total = 0.0
    for item in progress_items:
        percent = float(item.get("completion_percent", -1))
        require(0.0 <= percent <= 100.0, "invalid progress percent")
        total += percent
    weighted = total / len(progress_items)
    require(
        abs(float(vectors.get("overall_completion_percent", -1)) - weighted) < 0.0001,
        "overall_completion_percent does not match progress items",
    )
    cases = vectors.get("cases", [])
    require(len(cases) >= 2, "expected at least two essence vector cases")
    required_case_names = {
        "authorized_transfer_burn",
        "authorized_bridge_replay_mint_exception",
    }
    require(
        required_case_names.issubset({case.get("name") for case in cases}),
        "missing required essence vector cases",
    )
    for case in cases:
        for key in ("before_hex", "action_hex", "after_hex", "observer_hex"):
            value = case.get(key)
            require(isinstance(value, str) and value.startswith("0x"), f"{key} must be hex")
        require(
            case.get("commitment_count") == case.get("ciphertext_count"),
            "commitment/ciphertext count mismatch in vector case",
        )
        require(case.get("spend_authorized") is True, "sample action must be authorized")
        require(
            case.get("proof_statement_bound") is True,
            "sample action must bind proof statement",
        )
    return weighted


def check_progress(progress: dict, vector_percent: float) -> None:
    require(progress.get("schema_version") == 1, "unsupported essence progress schema")
    require(
        progress.get("generated_for_branch") == "codex/superneo-formal-verification",
        "unexpected branch in essence progress",
    )
    require(progress.get("goal_thread_id"), "goal_thread_id must be set")
    require("formal essence" in progress.get("objective", ""), "objective drifted")
    require(
        abs(float(progress.get("overall_completion_percent", -1)) - vector_percent) < 0.0001,
        "progress percent does not match generated vectors",
    )
    require(
        progress.get("required_core_types") == REQUIRED_TYPES,
        "progress type set drifted",
    )
    require(
        progress.get("required_production_path_stages") == REQUIRED_STAGES,
        "progress production stage set drifted",
    )
    require(
        progress.get("named_external_assumptions") == REQUIRED_ASSUMPTIONS,
        "progress assumption boundary drifted",
    )
    require(
        set(progress.get("required_theorems", [])) == set(REQUIRED_THEOREMS),
        "progress theorem set drifted",
    )
    require(
        set(progress.get("progress_item_ids", [])) == REQUIRED_PROGRESS,
        "progress item set drifted",
    )
    for path in progress.get("evidence_paths", []):
        require(Path(path).exists(), f"missing essence evidence path: {path}")
    for gate in progress.get("acceptance_gates", []):
        require(isinstance(gate, str) and gate.strip(), "acceptance gate must be nonempty")


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(
            "usage: check_essence_core_vectors.py <vectors.json> [progress.json]",
            file=sys.stderr,
        )
        return 2
    vector_percent = check_vectors(load_json(Path(argv[1])))
    if len(argv) == 3:
        check_progress(load_json(Path(argv[2])), vector_percent)
    print(f"formal essence core passed: {vector_percent:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
