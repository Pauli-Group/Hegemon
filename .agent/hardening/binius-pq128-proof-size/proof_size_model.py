#!/usr/bin/env python3
"""Reproduce the fixed Hegemon byte and FRI calculations.

The aggregate fields deliberately describe a rejected, unmeasured hypothesis.
They are retained so the false 3.6 MiB headline cannot be repeated as evidence.
"""

from __future__ import annotations

import argparse
import json
import math


BLOCK_CAP = 64 * 1024 * 1024
COINBASE_BYTES = 2_525
CURRENT_ACTION_BYTES = 128_992
CURRENT_ARTIFACT_BYTES = 124_022
ACTION_BYTES_WITH_EMPTY_PROOF = 4_967
AGGREGATE_HARD_CAP = 1_048_576


def fri_queries(classical_bits: int, log_inverse_rate: int) -> int:
    rate = 2.0 ** (-log_inverse_rate)
    bits_per_query = -math.log2((1.0 + rate) / 2.0)
    return math.ceil(classical_bits / bits_per_query)


def max_artifact_bytes(action_count: int) -> int:
    outside_artifact = CURRENT_ACTION_BYTES - CURRENT_ARTIFACT_BYTES
    return (BLOCK_CAP - COINBASE_BYTES) // action_count - outside_artifact


def aggregate_block_bytes(action_count: int, aggregate_bytes: int) -> int:
    return COINBASE_BYTES + action_count * ACTION_BYTES_WITH_EMPTY_PROOF + aggregate_bytes


def report() -> dict[str, object]:
    result = {
        "block_cap": BLOCK_CAP,
        "max_artifact_520": max_artifact_bytes(520),
        "rejected_unmeasured_aggregate_block_520": aggregate_block_bytes(520, AGGREGATE_HARD_CAP),
        "rejected_unmeasured_aggregate_bytes_per_action_520": math.ceil(AGGREGATE_HARD_CAP / 520),
        "fri_queries": {
            str(bits): {str(rate): fri_queries(bits, rate) for rate in range(1, 6)}
            for bits in (96, 128, 256, 259)
        },
    }
    assert result["max_artifact_520"] == 124_080
    assert result["rejected_unmeasured_aggregate_block_520"] == 3_633_941
    assert result["rejected_unmeasured_aggregate_bytes_per_action_520"] == 2_017
    assert result["fri_queries"]["259"]["4"] == 284
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="run pinned assertions")
    args = parser.parse_args()
    result = report()
    if not args.check:
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
