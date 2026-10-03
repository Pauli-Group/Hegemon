#!/usr/bin/env python3
"""Allocation-free certificate for the applied maximum-M4 Merkle selector patch.

The checker does not compile a circuit or allocate an oracle.  It pins the
post-tail-patch source and the relevant upstream gates, checks the frozen patch
in reverse, differentially proves the two selector formulas on deterministic
vectors, and recomputes the conservative hidden-word reduction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import shutil
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SOURCE = REPO_ROOT / "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs"
PATCH = HERE / "hegemon-m4-max-merkle-select-6a37ca5d.patch"
FIRST_PATCH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-max-relation-tail-geometry-patch"
    / "hegemon-m4-max-tail-geometry-67e7f6ac.patch"
)
THIRD_PATCH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-max-relation-one-hot-mux-patch"
    / "hegemon-m4-max-one-hot-mux-56301203.patch"
)
FOURTH_PATCH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-max-relation-policy-dedup-patch"
    / "hegemon-m4-max-policy-dedup-5f8f12b4.patch"
)
DEFAULT_UPSTREAM = Path("/private/tmp/binius64-api-3f961630")

BASE_SOURCE_SHA256 = "6a37ca5d2f2eb826c77c645b9dd7ab1f86ac2522acea86b9099b4ff24956988e"
POST_SECOND_SOURCE_SHA256 = "56301203b5d6d8cd99b1941778fe95887c65cc92957a73ae0413a8565b1f6b9b"
POST_THIRD_SOURCE_SHA256 = "5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976"
APPLIED_SOURCE_SHA256 = "f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b"
PATCH_SHA256 = "4a7289068cb8488d674249501d5b226f2ba4e8f7794014f9af5e65d83cab275c"
FIRST_PATCH_SHA256 = "bb8f8c6edd6495301981d79b683f7e613d92a34be4948e7a35e9a55c98838e70"
THIRD_PATCH_SHA256 = "3d6de7515ba363ba047ef436a3df697af0dcbc1d553487a2247570db637efb72"
FOURTH_PATCH_SHA256 = "c8f2b088f170b6cc4238f1a9ff0593e06b0ed2535e56d7fc8698b8685629f7c9"

SEMANTIC_BOUNDARY_PINS = {
    "circuits/standalone-full-shake256-relation-prototype/src/lib.rs":
        "e251d0d6ade5948cb603de8d50d7a2f655d87dfb15378b327efce7297a74c3f2",
    "circuits/standalone-full-shake256-relation-prototype/src/action_adapter.rs":
        "ce1440a00c3c983f676b6716b686a2ff35d4339c6c5acf40926b81db7431bcc4",
    "circuits/standalone-full-shake256-relation-prototype/src/composed_envelope.rs":
        "b3173460a5e1bcbfcf364ba35b9a69da0881e697e8e16667eacf4b4669fc749e",
}

UPSTREAM_PINS = {
    "crates/frontend/src/builder/mod.rs":
        "8170a7cdeabd42dc123e6507939cdd06dc8928382a49a7ce98b4592454499dff",
    "crates/frontend/src/gates/select.rs":
        "8f46cc1cd8ce3354fae08512667939e5dac60a3409ad35a7b149528b77f96a3e",
    "crates/frontend/src/gates/band.rs":
        "f8c1b46ed8bc2490358af787a2cbf8e6aa2b5fa96ea51c784c4afc59ba6c192c",
    "crates/frontend/src/gates/bxor.rs":
        "2a58db459d6c0c89ea2d04a8da62da1d82dddb7a712c8cfa272725843bf76662",
    "crates/frontend/src/gates/shift.rs":
        "3f73c78c278f7e9fe280ef393df9cb40089ae28ae4f08a6679e9aea2be8f658d",
    "crates/frontend/src/pass/zero_fold.rs":
        "edea72c51412689745bb169c62df3f4eccd5d4b6dc45cf8d5eee797dbef62600",
    "crates/frontend/src/pass/cse.rs":
        "b2923f3afddab5e885487fb4841cc5ebe16ac6ae9306bf4157490de7a81d2e99",
    "crates/frontend/src/pass/fusion/commit_set.rs":
        "9b9838be00105c324b2bb0a9d67172fb58a2e50b6bbe1828479649d7275acbfc",
}

MASK64 = (1 << 64) - 1
INPUT_PATHS = 2
MERKLE_DEPTH = 32
DIGEST_WORDS = 7
POST_FIRST_PATCH_HIDDEN_UPPER = 61_469
N15_SYMBOLS = 1 << 15


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pins(upstream: Path) -> None:
    assert sha256(SOURCE) == APPLIED_SOURCE_SHA256, "applied maximum M4 source drift"
    assert sha256(PATCH) == PATCH_SHA256, "isolated Merkle selector patch drift"
    assert sha256(FIRST_PATCH) == FIRST_PATCH_SHA256, "first geometry patch drift"
    assert sha256(THIRD_PATCH) == THIRD_PATCH_SHA256, "third geometry patch drift"
    assert sha256(FOURTH_PATCH) == FOURTH_PATCH_SHA256, "fourth geometry patch drift"
    for relative, expected in SEMANTIC_BOUNDARY_PINS.items():
        assert sha256(REPO_ROOT / relative) == expected, f"semantic boundary drift: {relative}"
    for relative, expected in UPSTREAM_PINS.items():
        assert sha256(upstream / relative) == expected, f"upstream drift: {relative}"


def verify_patch_shape() -> None:
    relative_source = SOURCE.relative_to(REPO_ROOT)
    with tempfile.TemporaryDirectory(prefix="hegemon-merkle-chain.", dir="/private/tmp") as raw:
        root = Path(raw)
        staged_source = root / relative_source
        staged_source.parent.mkdir(parents=True)
        shutil.copy2(SOURCE, staged_source)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for candidate, expected in (
            (FOURTH_PATCH, POST_THIRD_SOURCE_SHA256),
            (THIRD_PATCH, POST_SECOND_SOURCE_SHA256),
            (PATCH, BASE_SOURCE_SHA256),
        ):
            result = subprocess.run(
                ["git", "apply", "--reverse", str(candidate)],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr
            assert sha256(staged_source) == expected, "geometry patch chain mismatch"
    text = PATCH.read_text()
    required = [
        "builder.select(direction_msb, sibling[word], current[word])",
        "let pair_xor = builder.bxor(current[word], sibling[word]);",
        "builder.bxor(pair_xor, left[word])",
        "-            let mask = builder.sar(direction_msb, 63);",
    ]
    for marker in required:
        assert marker in text, f"missing patch marker: {marker}"
    forbidden_additions = ["+            keccak_f1600", "+pub const MERKLE_DEPTH", "+            let mask ="]
    for marker in forbidden_additions:
        assert marker not in text, f"forbidden patch addition: {marker}"
    assert text.count("diff --git ") == 1
    assert "m4-full-production-prototype/src/lib.rs" in text.splitlines()[0]


def direction_msb(position: int, level: int) -> int:
    assert 0 <= level < MERKLE_DEPTH
    return ((position << (63 - level)) & MASK64) >> 63


def old_order(position: int, level: int, current: int, sibling: int) -> tuple[int, int]:
    bit = direction_msb(position, level)
    mask = MASK64 if bit else 0
    delta = mask & (current ^ sibling)
    return current ^ delta, sibling ^ delta


def new_order(position: int, level: int, current: int, sibling: int) -> tuple[int, int]:
    bit = direction_msb(position, level)
    left = sibling if bit else current
    pair_xor = current ^ sibling
    right = pair_xor ^ left
    return left, right


def differential_merkle_select() -> dict[str, int]:
    rng = random.Random(0x4D3453454C454354)
    positions = [0, MASK64, 0x0123456789ABCDEF, 0xFEDCBA9876543210]
    positions.extend(1 << level for level in range(MERKLE_DEPTH))
    positions.extend(rng.getrandbits(64) for _ in range(256))
    pair_checks = 0
    permutation_checks = 0
    xor_checks = 0
    for position in positions:
        current = rng.getrandbits(64)
        sibling = rng.getrandbits(64)
        for level in range(MERKLE_DEPTH):
            old = old_order(position, level, current, sibling)
            new = new_order(position, level, current, sibling)
            assert new == old
            pair_checks += 1
            assert sorted(new) == sorted((current, sibling))
            permutation_checks += 1
            assert new[0] ^ new[1] == current ^ sibling
            xor_checks += 1
            current = rng.getrandbits(64)
            sibling = rng.getrandbits(64)

    # Exhaust both selector bits independently of a path-position distribution.
    for _ in range(4096):
        current = rng.getrandbits(64)
        sibling = rng.getrandbits(64)
        for bit in (0, 1):
            position = bit
            old = old_order(position, 0, current, sibling)
            new = new_order(position, 0, current, sibling)
            assert new == old
            pair_checks += 1
            assert sorted(new) == sorted((current, sibling))
            permutation_checks += 1
            assert new[0] ^ new[1] == current ^ sibling
            xor_checks += 1
    return {
        "old_equals_new_pair_checks": pair_checks,
        "pair_permutation_checks": permutation_checks,
        "xor_invariant_checks": xor_checks,
        "total_checks": pair_checks + permutation_checks + xor_checks,
    }


def build_report() -> dict[str, object]:
    selector_instances = INPUT_PATHS * MERKLE_DEPTH * DIGEST_WORDS
    old_band_instances = selector_instances
    new_select_instances = selector_instances
    assert selector_instances == 448

    # Per level the existing cone emits one direction shift and one arithmetic
    # sign extension.  Per word it emits diff-XOR, BAND, left-XOR, right-XOR.
    old_direction_outputs = INPUT_PATHS * MERKLE_DEPTH * 2
    old_word_outputs = selector_instances * 4
    old_outputs = old_direction_outputs + old_word_outputs

    # The direction shift is retained.  Per word the patch emits one Select,
    # one pair-XOR and one right-XOR.  Select and BAND are both one nonlinear
    # output/constraint in the pinned frontend, so nonlinear count is unchanged.
    new_direction_outputs = INPUT_PATHS * MERKLE_DEPTH
    new_word_outputs = selector_instances * 3
    new_outputs = new_direction_outputs + new_word_outputs
    cut = old_outputs - new_outputs
    assert (old_outputs, new_outputs, cut) == (1_920, 1_408, 512)
    assert old_band_instances == new_select_instances

    optimized_upper = POST_FIRST_PATCH_HIDDEN_UPPER - cut
    active_symbols_upper = math.ceil(optimized_upper / 2)
    tail_symbols_lower = N15_SYMBOLS - active_symbols_upper
    assert (optimized_upper, active_symbols_upper, tail_symbols_lower) == (60_957, 30_479, 2_289)

    return {
        "status": {
            "patch_applied": True,
            "applied_source_sha256": APPLIED_SOURCE_SHA256,
            "third_patch_applied": True,
            "fourth_patch_applied": True,
            "compiled_exact": False,
            "scalar_equivalence": "algebraic selector identity plus deterministic differential",
            "keccak_count_changed": False,
            "nonlinear_selector_count_changed": False,
            "frontier_promotable": False,
        },
        "differential_checks": differential_merkle_select(),
        "source_static_cost": {
            "post_first_patch_conservative_hidden_words": POST_FIRST_PATCH_HIDDEN_UPPER,
            "old_merkle_selector_outputs": old_outputs,
            "new_merkle_selector_outputs": new_outputs,
            "old_band_nonlinear_instances": old_band_instances,
            "new_select_nonlinear_instances": new_select_instances,
            "additional_conservative_hidden_word_cut": cut,
            "optimized_conservative_hidden_words": optimized_upper,
            "optimized_active_b128_symbols_upper": active_symbols_upper,
            "optimized_n15_random_tail_symbols_lower": tail_symbols_lower,
        },
        "capacity": {
            "conditional_required_b128_symbols": 1_060,
            "conditional_margin_b128_symbols": tail_symbols_lower - 1_060,
            "full_required_b128_symbols": 1_984,
            "full_margin_b128_symbols": tail_symbols_lower - 1_984,
        },
        "claim_boundary": [
            "source-static upper bound only",
            "no Cargo build or circuit compile",
            "no proof or encoded oracle",
            "no strict-security or complete-ZK claim",
            "compile must freeze actual active symbols",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, default=DEFAULT_UPSTREAM)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    verify_pins(args.upstream)
    verify_patch_shape()
    print(json.dumps(build_report(), indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
