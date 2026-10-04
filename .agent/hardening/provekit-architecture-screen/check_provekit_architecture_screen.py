#!/usr/bin/env python3
"""Fail-closed, dependency-free checker for the ProveKit stable-v1 source screen.

The default mode checks the retained source ledger and report.  ``--online``
additionally refetches only immutable raw GitHub files at the pinned release
commit and verifies their SHA-256 values.  It never clones, builds, or installs
dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
LEDGER_PATH = ROOT / "ledger.json"
REPORT_PATH = ROOT / "REPORT.md"
RELEASE_COMMIT = "253113f4be6bc256551a43fa56084e84af2db013"
TAG_OBJECT = "add654221a069ac1412caa747777e781e6901474"
STABLE_HEAD = "9b2a6f37c67691eab4b0cec6c35e35c520e93285"
WHIR_CHECKSUM = "35334259c6ad5b1287ecef6bfb3deb3dbb963c9366091951316bdb33c2080fe6"
SPONGEFISH_CHECKSUM = "95a705ff6cb8bc4566a2d1a9f665243db958cbd90a852c3eef0dcc8dc8879ce5"
SOURCE_MANIFEST = {
    "README.md": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/README.md",
        "37f7904fdf4685d6402e09afe5bedae93640e1c4abd6d6887b842407c5300e80",
    ),
    "Cargo.lock": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/Cargo.lock",
        "50970041c6aa662ca8231bed93bb0fb5ba2079bf85c517e035aad3359eb37f7f",
    ),
    "provekit/common/src/lib.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/common/src/lib.rs",
        "2e94651387009ba767da91cfbb3057253cb2f6b2a056ede57fc1657ebf8e7f05",
    ),
    "provekit/common/src/r1cs.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/common/src/r1cs.rs",
        "8f5f8e63be2501e5199eddd451163c5b058ac205a018d8d3b135b53815afce7c",
    ),
    "provekit/common/src/whir_r1cs.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/common/src/whir_r1cs.rs",
        "0b556b8925071e2db1854eebf209eb03587be1ea2c527575ead22c1433f76ae1",
    ),
    "provekit/common/src/noir_proof_scheme.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/common/src/noir_proof_scheme.rs",
        "aaf74c3034a0216c5aeb571f73b1a686dd86e111236d48bf13e3dad962bffeb3",
    ),
    "provekit/common/src/file/bin.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/common/src/file/bin.rs",
        "23d3e2b600f6d7d81dccd64d1f26eb8baaf5a3ff15f1e5ad1c78a402e216badb",
    ),
    "provekit/r1cs-compiler/src/whir_r1cs.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/r1cs-compiler/src/whir_r1cs.rs",
        "4634218945f15f8681c178bca903430deadc56594ad736f380a926bc92156ab5",
    ),
    "provekit/verifier/src/whir_r1cs.rs": (
        f"https://raw.githubusercontent.com/worldfnd/ProveKit/{RELEASE_COMMIT}/provekit/verifier/src/whir_r1cs.rs",
        "32b04c42409e686caebf57bb20bfb09eb94cade8a6454eb6c4bb60345b88e5f5",
    ),
}
DEPENDENCY_SOURCES = (
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/whir_zk/mod.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/whir_zk/committer.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/whir/config.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/irs_commit.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/matrix_commit.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/merkle_tree.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/hash/mod.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/hash/digest_engine.rs",
    "https://docs.rs/crate/provekit-whir/0.1.1/source/src/transcript/mod.rs",
    "https://docs.rs/crate/provekit-spongefish/0.1.0/source/src/lib.rs",
    "https://docs.rs/crate/provekit-spongefish/0.1.0/source/src/instantiations/hash.rs",
)
PRIMARY_PAPERS = {
    "whir": "https://eprint.iacr.org/2024/1586",
    "stir": "https://eprint.iacr.org/2024/390",
    "duplex_sponge_fiat_shamir": "https://eprint.iacr.org/2025/536.pdf",
    "qrom_bcs": "https://eprint.iacr.org/2019/834",
    "quantum_collision_bht": "https://arxiv.org/abs/quant-ph/9705002",
}
EXPECTED_GATES = {
    "exact_full_relation",
    "complete_zero_knowledge",
    "composed_pq_qrom_at_least_128_bits",
    "exact_verifier_consensus_binding",
    "canonical_bounded_parser",
    "same_relation_measured_proof_bytes",
    "mutation_restart_verification",
    "formal_refinement",
    "release_manifest",
    "production_authorized",
}


class CheckFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def at(value: dict[str, Any], path: str) -> Any:
    cursor: Any = value
    for component in path.split("."):
        require(isinstance(cursor, dict) and component in cursor, f"missing {path}")
        cursor = cursor[component]
    return cursor


def require_false(ledger: dict[str, Any], path: str) -> None:
    require(at(ledger, path) is False, f"{path} must remain false")


def require_null(ledger: dict[str, Any], path: str) -> None:
    require(at(ledger, path) is None, f"{path} must remain null")


def check_local(ledger: dict[str, Any], report: str) -> None:
    require(ledger.get("schema_version") == 1, "unexpected schema version")
    require(ledger.get("status") == "fail_closed", "status must be fail_closed")
    require(ledger.get("verdict") == "disqualified", "verdict must be disqualified")
    require(ledger.get("production_authorized") is False, "production must be disabled")
    require(ledger.get("architecture_winner") is None, "no architecture winner is supported")

    require(at(ledger, "upstream_pin.release") == "v1.0.0", "wrong release")
    require(
        at(ledger, "upstream_pin.repository") == "https://github.com/worldfnd/ProveKit",
        "wrong official repository",
    )
    require(
        at(ledger, "upstream_pin.release_url")
        == "https://github.com/worldfnd/provekit/releases/tag/v1.0.0",
        "wrong release URL",
    )
    require(
        at(ledger, "upstream_pin.release_published_at") == "2026-05-12T10:31:21Z",
        "wrong publication time",
    )
    require(at(ledger, "upstream_pin.release_commit") == RELEASE_COMMIT, "wrong release commit")
    require(at(ledger, "upstream_pin.annotated_tag_object") == TAG_OBJECT, "wrong tag object")
    require(
        at(ledger, "upstream_pin.stable_branch_head_observed_2026_08_22") == STABLE_HEAD,
        "wrong observed v1 branch head",
    )
    require(at(ledger, "upstream_pin.release_assets_count") == 0, "release asset count changed")
    require(
        at(ledger, "upstream_pin.comparison_url")
        == f"https://github.com/worldfnd/ProveKit/compare/{RELEASE_COMMIT}...{STABLE_HEAD}",
        "wrong release-to-branch comparison",
    )
    require(at(ledger, "upstream_pin.audit_authority") == "release_commit", "wrong audit authority")

    require(at(ledger, "scope.source_only") is True, "audit must remain source-only")
    require_false(ledger, "scope.clone_performed")
    require_false(ledger, "scope.build_performed")
    require_false(ledger, "scope.dependency_fetch_performed")
    require(at(ledger, "scope.recursive_groth16_excluded") is True, "Groth16 must stay excluded")
    require_false(ledger, "architecture.recursive_groth16_in_scope")

    require(at(ledger, "pinned_dependencies.provekit-whir.version") == "0.1.1", "wrong WHIR version")
    require(
        at(ledger, "pinned_dependencies.provekit-whir.cargo_lock_checksum") == WHIR_CHECKSUM,
        "wrong WHIR checksum",
    )
    require(
        at(ledger, "pinned_dependencies.provekit-spongefish.version") == "0.1.0",
        "wrong Spongefish version",
    )
    require(
        at(ledger, "pinned_dependencies.provekit-spongefish.cargo_lock_checksum")
        == SPONGEFISH_CHECKSUM,
        "wrong Spongefish checksum",
    )

    # Source-supported capability must not be confused with Hegemon qualification.
    require(
        at(ledger, "architecture.relation.arbitrary_r1cs_backend_capability") is True,
        "generic R1CS capability finding missing",
    )
    require_false(ledger, "architecture.relation.stable_noir_frontend_accepts_arbitrary_acir")
    require_false(ledger, "architecture.relation.stable_noir_blake2b_black_box_present")
    require_false(ledger, "architecture.relation.exact_hx448c02_relation_compiled")
    require_false(ledger, "architecture.relation.generic_capability_is_hegemon_refinement_evidence")
    require_false(ledger, "architecture.relation.trusted_relation_artifact_self_consistency_check_located")
    require_false(ledger, "architecture.direct_path_uses_ecc_or_pairings")
    require(at(ledger, "architecture.field.rust_type") == "ark_bn254::Fr", "wrong proof field")
    require(at(ledger, "architecture.pcs_iop.classical_estimator_only") is True, "estimator scope changed")
    require(at(ledger, "architecture.pcs_iop.configured_pow_bits") == 10, "WHIR PoW changed")
    require(at(ledger, "architecture.pcs_iop.source_intended_algebraic_bits") == 118, "split changed")
    require_false(ledger, "architecture.zero_knowledge.exact_custom_construction_primary_theorem_identified")
    require_false(ledger, "architecture.zero_knowledge.whole_view_simulator_artifact_present")
    require_false(ledger, "architecture.zero_knowledge.whole_view_complete_zk_proved")
    require_false(ledger, "architecture.zero_knowledge.adaptive_qrom_zero_knowledge_proved")
    require_false(ledger, "architecture.zero_knowledge.hegemon_complete_zero_knowledge")

    require(
        at(ledger, "hash_and_transcript_surface.fiat_shamir_transcript.construction_security_status")
        == "heuristic",
        "SHA-256 transcript bridge must remain labelled heuristic",
    )
    require(
        at(ledger, "hash_and_transcript_surface.whir_matrix_and_merkle_commitment.digest_bits") == 256,
        "WHIR commitment width changed",
    )
    require(at(ledger, "hash_and_transcript_surface.whir_hash_id") == "SHA2", "WHIR hash ID changed")

    # Exact generic quantum ceilings for a 256-bit conventional hash.
    pq = at(ledger, "post_quantum_qrom")
    require(pq["minimum_conventional_hash_width_bits"] == 256, "hash-width premise changed")
    require(math.isclose(pq["generic_quantum_preimage_ceiling_bits"], 256 / 2), "bad preimage ceiling")
    require(math.isclose(pq["generic_quantum_collision_ceiling_bits"], 256 / 3), "bad collision ceiling")
    require(math.isclose(pq["grover_adjusted_grinding_ceiling_bits"], 10 / 2), "bad grinding ceiling")
    require(math.isclose(pq["heuristic_additive_split_ceiling_bits"], 118 + 10 / 2), "bad split ceiling")
    require(pq["dsfs_paper_states_superposition_query_security_open"] is True, "QROM open problem lost")
    for key in (
        "heuristic_additive_split_is_security_proof",
        "spongefish_sha256_bridge_proven_in_dsfs_model",
        "finite_qrom_query_budget_present",
        "pcs_iop_qrom_bound_present",
        "fiat_shamir_qrom_bound_present",
        "hash_qrom_bound_present",
        "grinding_qrom_bound_present",
        "union_composition_ledger_present",
        "strict_pq128",
    ):
        require(pq[key] is False, f"post_quantum_qrom.{key} must remain false")
    require(pq["composed_security_bits"] is None, "composed security must remain unclaimed")

    require(at(ledger, "proof_and_parser.transcript_narg_eof_checked") is True, "narg EOF evidence lost")
    require(at(ledger, "proof_and_parser.transcript_hints_eof_checked") is True, "hints EOF evidence lost")
    for path in (
        "proof_and_parser.compressed_length_limit_present",
        "proof_and_parser.decompressed_length_limit_present",
        "proof_and_parser.nested_vector_length_limits_present",
        "proof_and_parser.unique_canonical_wire_encoding",
        "proof_and_parser.canonical_bounded_consensus_parser",
    ):
        require_false(ledger, path)

    hegemon_false = (
        "exact_full_2_input_2_output_relation",
        "all_16_activity_masks",
        "stablecoin_rules",
        "all_authorization_modes",
        "parser_statement_action_network_version_domain_binding",
        "ciphertext_balance_nullifier_merkle_intent_binding",
        "poseidon_authority_absent",
        "exact_rust_verifier_refinement",
        "wallet_to_rpc_unchanged_transport",
        "rpc_to_relay_unchanged_transport",
        "relay_to_mempool_unchanged_transport",
        "mempool_to_mining_unchanged_transport",
        "mining_to_block_unchanged_transport",
        "block_sync_reorg_fresh_node_verification",
        "self_contained_consensus_ready",
        "measured_same_relation",
        "proof_size_win",
    )
    for key in hegemon_false:
        require_false(ledger, f"hegemon_hx448c02.{key}")
    require(at(ledger, "hegemon_hx448c02.production_integration_fail_closed") is True, "fail-closed flag lost")
    require_null(ledger, "hegemon_hx448c02.same_hx448c02_proof_bytes")
    require_null(ledger, "hegemon_hx448c02.retained_same_relation_proof_artifact")

    gates = at(ledger, "gates")
    require(set(gates) == EXPECTED_GATES, "required production gate set changed")
    for gate, value in gates.items():
        require(value is False, f"unsupported gate promoted: {gate}")

    manifest = at(ledger, "source_manifest")
    require(set(manifest) == set(SOURCE_MANIFEST), "release source paths are not exactly pinned")
    hex64 = re.compile(r"[0-9a-f]{64}\Z")
    for source_path, (expected_url, expected_sha256) in SOURCE_MANIFEST.items():
        entry = manifest[source_path]
        require(entry == {"url": expected_url, "sha256": expected_sha256}, f"source pin changed: {source_path}")
        require(entry["url"].startswith("https://raw.githubusercontent.com/worldfnd/ProveKit/"), f"nonofficial host: {source_path}")
        require(hex64.fullmatch(entry["sha256"]) is not None, f"bad SHA-256: {source_path}")
    require(
        at(ledger, "versioned_dependency_sources") == list(DEPENDENCY_SOURCES),
        "dependency source URLs changed",
    )
    require(at(ledger, "primary_papers") == PRIMARY_PAPERS, "primary-paper set changed")

    report_markers = (
        "Decision: **disqualified; production remains fail-closed**",
        RELEASE_COMMIT,
        TAG_OBJECT,
        STABLE_HEAD,
        "256 / 3 = 85.33333333333333",
        "same_hx448c02_proof_bytes = null",
        "proof_size_win = false",
        "https://eprint.iacr.org/2025/536.pdf",
        "https://docs.rs/crate/provekit-whir/0.1.1/source/",
        "https://docs.rs/crate/provekit-spongefish/0.1.0/source/",
    )
    for marker in report_markers:
        require(marker in report, f"REPORT.md missing marker: {marker}")
    forbidden_promotions = (
        r"production[ _-]*authorized\s*(?:=|:|\bis\b)?\s*(?:true|yes)",
        r"strict[ _-]*pq128\s*(?:=|:|\bis\b)?\s*(?:true|yes)",
        r"proof[ _-]*size[ _-]*win\s*(?:=|:|\bis\b)?\s*(?:true|yes)",
        r"same[ _-]*hx448c02[ _-]*proof[ _-]*bytes\s*(?:=|:)\s*[0-9]",
    )
    for pattern in forbidden_promotions:
        require(re.search(pattern, report, flags=re.IGNORECASE) is None, f"REPORT.md contains promotion: {pattern}")


def check_online(ledger: dict[str, Any]) -> None:
    opener = urllib.request.build_opener()
    opener.addheaders = [("User-Agent", "Hegemon-ProveKit-source-screen/1")]
    for source_path, entry in at(ledger, "source_manifest").items():
        try:
            with opener.open(entry["url"], timeout=30) as response:
                payload = response.read()
        except Exception as exc:  # pragma: no cover - depends on operator network
            raise CheckFailure(f"failed to fetch {source_path}: {exc}") from exc
        actual = hashlib.sha256(payload).hexdigest()
        require(actual == entry["sha256"], f"source hash mismatch: {source_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--online",
        action="store_true",
        help="refetch immutable official release files and verify retained SHA-256 values",
    )
    args = parser.parse_args()
    try:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        report = REPORT_PATH.read_text(encoding="utf-8")
        check_local(ledger, report)
        if args.online:
            check_online(ledger)
    except (OSError, json.JSONDecodeError, CheckFailure) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    mode = "offline+online-source-hash" if args.online else "offline"
    print(
        "PASS: ProveKit v1.0.0 remains fail-closed; "
        f"release={RELEASE_COMMIT}, mode={mode}, "
        "generic-quantum-collision-ceiling=85.33333333333333 bits, "
        "same-HX448C02-bytes=null"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
