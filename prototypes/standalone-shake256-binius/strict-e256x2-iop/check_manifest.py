#!/usr/bin/env python3
"""Independently audit the fail-closed E256x2 manifest and n15 wire costs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
QUERY_DOMAIN = b"hegemon.strict-e256x2.query-schedule.v1\0"


def frame(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(8, "little") + payload


def derive_unique(
    context: bytes,
    root: bytes,
    log_table_size: int,
    count: int,
    label: bytes,
) -> list[int]:
    mask = (1 << log_table_size) - 1
    result: list[int] = []
    seen: set[int] = set()
    draw = 0
    while len(result) < count:
        preimage = (
            QUERY_DOMAIN
            + frame(1, context)
            + frame(2, root)
            + frame(3, label)
            + frame(4, draw.to_bytes(8, "little"))
        )
        candidate = int.from_bytes(hashlib.shake_256(preimage).digest(8), "little") & mask
        if candidate not in seen:
            result.append(candidate)
            seen.add(candidate)
        draw += 1
    return result


def wire_bytes(costs: dict[str, object], distinct: int) -> int:
    wire = costs["wire"]
    assert isinstance(wire, dict)
    return (
        int(wire["fixed_header_bytes"])
        + int(wire["root_bytes"])
        + int(wire["explicit_e256_terminal_claims"]) * int(wire["e256_bytes_each"])
        + distinct
        * (
            int(wire["b128_bytes_each"])
            + int(costs["log_table_size"]) * int(wire["authentication_node_bytes_each"])
        )
        + int(wire["query_index_bytes"])
    )


def reference_symbol(index: int) -> bytes:
    mask = (1 << 64) - 1
    low = index
    product = (low * 0x9E3779B97F4A7C15) & mask
    high = ((product << 17) | (product >> (64 - 17))) & mask
    return low.to_bytes(8, "little") + high.to_bytes(8, "little")


def reference_merkle_root(log_table_size: int) -> bytes:
    leaf_domain = b"hegemon.strict-e256x2.b128-leaf.v1\0"
    node_domain = b"hegemon.strict-e256x2.b128-node.v1\0"
    level = [
        hashlib.shake_256(
            leaf_domain
            + frame(1, index.to_bytes(8, "little"))
            + frame(2, reference_symbol(index))
        ).digest(64)
        for index in range(1 << log_table_size)
    ]
    for height in range(log_table_size):
        level = [
            hashlib.shake_256(
                node_domain
                + frame(1, height.to_bytes(8, "little"))
                + frame(2, level[index])
                + frame(3, level[index + 1])
            ).digest(64)
            for index in range(0, len(level), 2)
        ]
    assert len(level) == 1
    return level[0]


def main() -> None:
    manifest = json.loads((ROOT / "security-manifest.json").read_text())
    costs = json.loads((ROOT / "n15-wire-costs.json").read_text())

    assert manifest["status"] == "research-only-fail-closed"
    assert manifest["pinned_binius_revision"] == "3f96163049f680b2909f6545690bd929f1b48c44"
    assert manifest["algebra"]["challenge_field_bits_per_stream"] == 256
    assert manifest["algebra"]["streams_are_protocol_repetitions_not_one_field"] is True
    scaffold = manifest["parameter_scaffold_not_a_reduction"]
    assert scaffold["maximum_degree_log2_assumption"] == 120
    assert scaffold["single_stream_field_minus_degree_bits"] == 136
    assert scaffold["arithmetic_sum_for_two_streams_if_product_theorem_existed"] == 272
    assert scaffold["product_theorem_exists"] is False

    forbidden_true = {
        "e256_claims_bound_to_whole_table",
        "pcs_binding_theorem",
        "fri_proximity_or_degree_theorem",
        "dual_stream_conditional_independence_theorem",
        "product_soundness_theorem",
        "complete_zero_knowledge",
        "qrom_composition",
        "strict_pq128",
        "meets_current_384_bit_challenge_policy",
        "production_frontier_eligible",
    }
    capabilities = manifest["capabilities"]
    assert forbidden_true == set(capabilities)
    assert all(capabilities[name] is False for name in forbidden_true)

    assert costs["query_count_is_security_claim"] is False
    assert costs["authority"] == "research-wire-model-only"
    assert costs["grammar_magic"] == "HGE2X2P1"
    boundary = costs["comparison_boundary"]
    assert boundary["rate_expanded_oracle"] is False
    assert boundary["query_policy"] == "fixed-264-unique-indices-per-stream-not-rate-derived"
    assert boundary["leaf_group_symbols"] == 1
    assert boundary["digest_bytes"] == 64
    assert boundary["not_the_strict_mixed_pcs_screen"] is True
    context = costs["context_utf8"].encode()
    root = bytes.fromhex(costs["root_hex"])
    assert len(root) == 64
    log_table_size = int(costs["log_table_size"])
    assert costs["reference_table"]["actual_merkle_root"] is True
    assert int(costs["reference_table"]["symbol_count"]) == 1 << log_table_size
    assert root == reference_merkle_root(log_table_size)
    query_count = int(costs["queries_per_stream"])

    shared = derive_unique(context, root, log_table_size, query_count, b"shared")
    stream_a = derive_unique(context, root, log_table_size, query_count, b"stream-a")
    stream_b = derive_unique(context, root, log_table_size, query_count, b"stream-b")
    shared_union = set(shared)
    independent_union = set(stream_a) | set(stream_b)
    independent_overlap = len(set(stream_a) & set(stream_b))

    assert len(shared_union) == int(costs["shared"]["distinct_opened_symbols"])
    assert query_count == int(costs["shared"]["cross_stream_overlap"])
    assert len(independent_union) == int(costs["independent"]["distinct_opened_symbols"])
    assert independent_overlap == int(costs["independent"]["cross_stream_overlap"])
    assert int(costs["shared"]["authentication_nodes"]) == len(shared_union) * log_table_size
    assert int(costs["independent"]["authentication_nodes"]) == len(independent_union) * log_table_size
    assert int(costs["shared"]["proof_bytes"]) == wire_bytes(costs, len(shared_union))
    assert int(costs["independent"]["proof_bytes"]) == wire_bytes(costs, len(independent_union))

    print(
        "E256X2_MANIFEST_PASS "
        f"shared_bytes={costs['shared']['proof_bytes']} "
        f"independent_bytes={costs['independent']['proof_bytes']} "
        "strict_pq128=false complete_zk=false frontier=false"
    )


if __name__ == "__main__":
    main()
