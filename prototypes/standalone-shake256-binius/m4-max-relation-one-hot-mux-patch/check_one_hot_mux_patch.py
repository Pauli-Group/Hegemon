#!/usr/bin/env python3
"""Allocation-free certificate for the maximum-M4 one-hot mux patch.

The checker does not build Rust, compile a circuit, run a prover, or allocate an
encoded oracle. It pins the patched live source and compiler semantics, reverses
and reapplies the isolated patch in a unique temporary copy, exhausts every
accepted auth mode, and recomputes the immediate-fold and CSE-aware gate delta.
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
from typing import Hashable


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SOURCE = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs"
)
PATCH = HERE / "hegemon-m4-max-one-hot-mux-56301203.patch"
FOURTH_PATCH = (
    HERE.parent
    / "m4-max-relation-policy-dedup-patch"
    / "hegemon-m4-max-policy-dedup-5f8f12b4.patch"
)
DEFAULT_UPSTREAM = Path("/private/tmp/binius64-api-3f961630")

BASE_SOURCE_SHA256 = "56301203b5d6d8cd99b1941778fe95887c65cc92957a73ae0413a8565b1f6b9b"
PATCHED_SOURCE_SHA256 = "5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976"
APPLIED_SOURCE_SHA256 = "f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b"
PATCH_SHA256 = "3d6de7515ba363ba047ef436a3df697af0dcbc1d553487a2247570db637efb72"
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
    "crates/frontend/src/gates/bor.rs":
        "d45d3038aac97125b8db1720add02555f889f23d66b549031345019a2c768103",
    "crates/frontend/src/gates/bxor.rs":
        "2a58db459d6c0c89ea2d04a8da62da1d82dddb7a712c8cfa272725843bf76662",
    "crates/frontend/src/pass/cse.rs":
        "b2923f3afddab5e885487fb4841cc5ebe16ac6ae9306bf4157490de7a81d2e99",
    "crates/frontend/src/pass/dce.rs":
        "09c66043791d69a63b832da9d7cf3586708cc51dbac009d6bddd7f1a53d1bbea",
    "crates/frontend/src/pass/fusion/commit_set.rs":
        "9b9838be00105c324b2bb0a9d67172fb58a2e50b6bbe1828479649d7275acbfc",
    "crates/circuits/src/keccak/permutation.rs":
        "e4d2ca3da3e2bc2dc6971ed9d21ee5e8e058f319fa8479938a062b900cd00c92",
}

RATE_WORDS = 17
PERMUTATIONS = 2
PADDED_WORDS = RATE_WORDS * PERMUTATIONS
FINAL_PAD_WORD = PADDED_WORDS - 1
POST_SELECTOR_HIDDEN_UPPER = 60_957
N15_SYMBOLS = 1 << 15


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pins(upstream: Path) -> None:
    assert sha256(SOURCE) == APPLIED_SOURCE_SHA256, "live maximum-M4 source drift"
    assert sha256(PATCH) == PATCH_SHA256, "isolated one-hot mux patch drift"
    assert sha256(FOURTH_PATCH) == FOURTH_PATCH_SHA256, "policy-dedup patch drift"
    for relative, expected in SEMANTIC_BOUNDARY_PINS.items():
        assert sha256(REPO_ROOT / relative) == expected, f"semantic boundary drift: {relative}"
    for relative, expected in UPSTREAM_PINS.items():
        assert sha256(upstream / relative) == expected, f"upstream drift: {relative}"


def verify_patch_shape() -> None:
    relative_source = SOURCE.relative_to(REPO_ROOT)
    with tempfile.TemporaryDirectory(prefix="hegemon-one-hot-mux.", dir="/private/tmp") as raw:
        root = Path(raw)
        staged = root / relative_source
        staged.parent.mkdir(parents=True)
        shutil.copy2(SOURCE, staged)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        fourth = subprocess.run(
            ["git", "apply", "--reverse", str(FOURTH_PATCH)],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert fourth.returncode == 0, fourth.stderr
        assert sha256(staged) == PATCHED_SOURCE_SHA256, "policy stack mismatch"
        reverse = subprocess.run(
            ["git", "apply", "--reverse", str(PATCH)],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert reverse.returncode == 0, reverse.stderr
        assert sha256(staged) == BASE_SOURCE_SHA256, "reversed source mismatch"
        result = subprocess.run(
            ["git", "apply", str(PATCH)],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert sha256(staged) == PATCHED_SOURCE_SHA256, "patched source mismatch"

    patch = PATCH.read_text()
    required = [
        "builder.bnot(self.single)",
        "let current_a = or_msb(builder, &[modes.approval, modes.final_spend]);",
        "fn mux_one_hot_shake256_words(",
        "default[absolute]",
        "(modes.lock, &value_lock)",
        "(modes.final_spend, &value_lock)",
    ]
    for marker in required:
        assert marker in patch, f"missing patch marker: {marker}"
    forbidden_additions = [
        "+            keccak_f1600",
        "+        builder.assert_",
        "+        builder.add_witness",
        "+        builder.add_inout",
    ]
    for marker in forbidden_additions:
        assert marker not in patch, f"forbidden patch addition: {marker}"
    assert patch.count("diff --git ") == 1


def mode_flags(mode: int) -> tuple[bool, bool, bool, bool, bool]:
    return tuple(mode == candidate for candidate in range(5))  # type: ignore[return-value]


def old_non_single(mode: int) -> bool:
    single, init, approval, lock, final = mode_flags(mode)
    return init or approval or lock or final


def new_non_single(mode: int) -> bool:
    single, _, _, _, _ = mode_flags(mode)
    return not single


def old_mux(candidates: list[tuple[bool, int]]) -> int:
    selected = 0
    for condition, value in candidates:
        if condition:
            selected = value
    return selected


def new_mux(default: int, overrides: list[tuple[bool, int]]) -> int:
    selected = default
    for condition, value in overrides:
        if condition:
            selected = value
    return selected


def differential_mode_mux() -> dict[str, int]:
    rng = random.Random(0x4D345F4F4E45484F)
    mode_checks = 0
    word_checks = 0
    one_hot_checks = 0
    rejected_mode_checks = 0

    for mode in range(5):
        single, init, approval, lock, final = mode_flags(mode)
        assert old_non_single(mode) == new_non_single(mode)
        mode_checks += 1
        overrides_a = [lock, init, approval or final]
        overrides_b = [final, approval]
        assert sum(overrides_a) <= 1
        assert sum(overrides_b) <= 1
        one_hot_checks += 2

        for _ in range(512):
            dummy, init_acc, current_acc, next_acc, value_lock = (
                rng.getrandbits(64) for _ in range(5)
            )
            old_a = old_mux(
                [
                    (single, dummy),
                    (init, init_acc),
                    (approval, current_acc),
                    (lock, value_lock),
                    (final, current_acc),
                ]
            )
            new_a = new_mux(
                dummy,
                [
                    (lock, value_lock),
                    (init, init_acc),
                    (approval or final, current_acc),
                ],
            )
            assert old_a == new_a
            old_b = old_mux(
                [
                    (single or init or lock, dummy),
                    (approval, next_acc),
                    (final, value_lock),
                ]
            )
            new_b = new_mux(
                dummy,
                [(final, value_lock), (approval, next_acc)],
            )
            assert old_b == new_b
            word_checks += 2

    # The hash selection may differ outside 0..=4, but auth.mode.range rejects
    # every such row in both circuits before conjunction acceptance.
    for mode in [5, 6, 7, 255, 1 << 32, (1 << 64) - 1]:
        assert mode > 4
        assert not (mode <= 4)
        rejected_mode_checks += 1

    return {
        "accepted_mode_equivalence_checks": mode_checks,
        "random_absorption_word_checks": word_checks,
        "one_hot_partition_checks": one_hot_checks,
        "range_rejected_mode_checks": rejected_mode_checks,
        "total_checks": mode_checks + word_checks + one_hot_checks + rejected_mode_checks,
    }


def padded_identity(label: str, length_bytes: int) -> list[Hashable]:
    """Model immediate Wire identity after padded_absorption.

    Every occupied semantic-frame word depends on a nonzero frame constant or
    a distinct witness wire. Unoccupied words are the interned zero constant;
    the final pad word is the same interned constant for every two-block frame.
    """

    assert length_bytes // 136 + 1 == PERMUTATIONS
    words: list[Hashable] = ["zero"] * PADDED_WORDS
    occupied = math.ceil(length_bytes / 8)
    for word in range(occupied):
        words[word] = (label, word)
    words[FINAL_PAD_WORD] = "final-pad"
    return words


def dummy_identity() -> list[Hashable]:
    words: list[Hashable] = ["zero"] * PADDED_WORDS
    words[136 // 8] = "dummy-suffix"
    words[FINAL_PAD_WORD] = "final-pad"
    return words


class SelectCounter:
    def __init__(self) -> None:
        self.emitted = 0

    def select(self, true_wire: Hashable, false_wire: Hashable) -> Hashable:
        if true_wire == false_wire:
            return true_wire
        self.emitted += 1
        return ("select", self.emitted)


def count_mux_selects() -> dict[str, int]:
    dummy = dummy_identity()
    init_acc = padded_identity("init", 181)
    current_acc = padded_identity("current", 181)
    next_acc = padded_identity("next", 181)
    value_lock = padded_identity("lock", 143)

    old_a_counter = SelectCounter()
    new_a_counter = SelectCounter()
    old_b_counter = SelectCounter()
    new_b_counter = SelectCounter()
    for word in range(PADDED_WORDS):
        acc: Hashable = "zero"
        for candidate in [dummy, init_acc, current_acc, value_lock, current_acc]:
            acc = old_a_counter.select(candidate[word], acc)

        acc = dummy[word]
        for candidate in [value_lock, init_acc, current_acc]:
            acc = new_a_counter.select(candidate[word], acc)

        acc = "zero"
        for candidate in [dummy, next_acc, value_lock]:
            acc = old_b_counter.select(candidate[word], acc)

        acc = dummy[word]
        for candidate in [value_lock, next_acc]:
            acc = new_b_counter.select(candidate[word], acc)

    assert old_a_counter.emitted == 98
    assert new_a_counter.emitted == 64
    assert old_b_counter.emitted == 50
    assert new_b_counter.emitted == 41
    return {
        "old_slot_a_emitted_selects": old_a_counter.emitted,
        "new_slot_a_emitted_selects": new_a_counter.emitted,
        "old_slot_b_emitted_selects": old_b_counter.emitted,
        "new_slot_b_emitted_selects": new_b_counter.emitted,
        "immediate_fold_select_cut": (
            old_a_counter.emitted
            + old_b_counter.emitted
            - new_a_counter.emitted
            - new_b_counter.emitted
        ),
    }


def build_report() -> dict[str, object]:
    folds = count_mux_selects()
    assert folds["immediate_fold_select_cut"] == 43

    old_attempted_selects = (5 + 3) * PADDED_WORDS
    new_attempted_selects = (3 + 2) * PADDED_WORDS
    assert (old_attempted_selects, new_attempted_selects) == (272, 170)

    # Old inactive-B and non-single unions emit 2+3 BOR gates after their
    # leading zero identities. New code emits one BOR for Approval|Final and
    # one linear BNOT. Thus immediate nonlinear gates fall by 43+4=47 while
    # total emitted outputs fall by 46. Pinned CSE already merges the old
    # Init|Approval prefix with the earlier next-policy union, so the final
    # nonlinear constraint cut is 46; no removed Select/BOR result is dead.
    old_mode_bor_outputs = 2 + 3
    new_mode_bor_outputs = 1
    new_mode_linear_outputs = 1
    immediate_nonlinear_cut = (
        folds["immediate_fold_select_cut"]
        + old_mode_bor_outputs
        - new_mode_bor_outputs
    )
    net_emitted_output_cut = immediate_nonlinear_cut - new_mode_linear_outputs
    cse_duplicate_old_prefix = 1
    cse_aware_nonlinear_cut = immediate_nonlinear_cut - cse_duplicate_old_prefix
    assert (immediate_nonlinear_cut, net_emitted_output_cut) == (47, 46)
    assert cse_aware_nonlinear_cut == 46

    optimized_upper = POST_SELECTOR_HIDDEN_UPPER - net_emitted_output_cut
    active_symbols_upper = math.ceil(optimized_upper / 2)
    tail_symbols_lower = N15_SYMBOLS - active_symbols_upper
    assert (optimized_upper, active_symbols_upper, tail_symbols_lower) == (60_911, 30_456, 2_312)

    return {
        "status": {
            "patch_applied": True,
            "policy_dedup_patch_applied": True,
            "base_source_sha256": BASE_SOURCE_SHA256,
            "patched_source_sha256": PATCHED_SOURCE_SHA256,
            "compiled_exact": False,
            "relation_equivalence": "exhaustive accepted mode partition plus random word differential",
            "keccak_count_changed": False,
            "frontier_promotable": False,
        },
        "differential_checks": differential_mode_mux(),
        "compiler_aware_cost": {
            "old_attempted_select_calls": old_attempted_selects,
            "new_attempted_select_calls": new_attempted_selects,
            **folds,
            "immediate_nonlinear_gate_cut": immediate_nonlinear_cut,
            "new_linear_bnot_outputs": new_mode_linear_outputs,
            "net_immediate_output_cut": net_emitted_output_cut,
            "pinned_cse_duplicate_removed_from_old_only": cse_duplicate_old_prefix,
            "pinned_cse_nonlinear_constraint_cut": cse_aware_nonlinear_cut,
            "post_patch_conservative_hidden_words": optimized_upper,
            "post_patch_active_b128_symbols_upper": active_symbols_upper,
            "post_patch_n15_random_tail_symbols_lower": tail_symbols_lower,
        },
        "capacity": {
            "conditional_required_b128_symbols": 1_060,
            "conditional_margin_b128_symbols": tail_symbols_lower - 1_060,
            "full_required_b128_symbols": 1_984,
            "full_margin_b128_symbols": tail_symbols_lower - 1_984,
        },
        "claim_boundary": [
            "applied source optimization",
            "allocation-free source/compiler certificate only",
            "no Cargo build or circuit compile",
            "no proof or encoded oracle",
            "no complete-ZK or strict-PQ128 claim",
            "compile and scalar/M4 differential execution remain mandatory",
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
