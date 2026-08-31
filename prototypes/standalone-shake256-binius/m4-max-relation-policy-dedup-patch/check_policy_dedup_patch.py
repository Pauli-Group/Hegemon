#!/usr/bin/env python3
"""Allocation-free certificate for the maximum-M4 policy deduplication patch.

This checker pins and copies the patched live source, reverses and reapplies
the policy patch, pins the relation/compiler boundary, differentially evaluates
the old and new policy predicates, and recomputes the compiler-aware estimate. It
does not invoke Cargo, build a circuit, allocate an oracle, or run a prover.
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
from dataclasses import dataclass, replace
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SOURCE = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs"
)
FIRST_PATCH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-max-relation-one-hot-mux-patch"
    / "hegemon-m4-max-one-hot-mux-56301203.patch"
)
PATCH = HERE / "hegemon-m4-max-policy-dedup-5f8f12b4.patch"
DEFAULT_UPSTREAM = Path("/private/tmp/binius64-api-3f961630")

PRE_ONE_HOT_SOURCE_SHA256 = "56301203b5d6d8cd99b1941778fe95887c65cc92957a73ae0413a8565b1f6b9b"
FIRST_PATCH_SHA256 = "3d6de7515ba363ba047ef436a3df697af0dcbc1d553487a2247570db637efb72"
STACK_BASE_SHA256 = "5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976"
PATCHED_SOURCE_SHA256 = "f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b"
PATCH_SHA256 = "c8f2b088f170b6cc4238f1a9ff0593e06b0ed2535e56d7fc8698b8685629f7c9"

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
    "crates/frontend/src/gates/assert_eq.rs":
        "d32b3007ba4b373422553d0577922cf46b9ea696406a302c2ffaa0611c81b479",
    "crates/frontend/src/gates/assert_eq_cond.rs":
        "32561d7d020b8341379ac23f68e58359281ecdfebe7679efe538c48b9ca697ef",
    "crates/frontend/src/gates/assert_non_zero.rs":
        "9f1116c631512931dfbaa791968df46b4ebdbae6c21dae92e5a16f236dab6984",
    "crates/frontend/src/gates/assert_true.rs":
        "8ddbd1b19fa5f02d7ca88ee2e124ccd0a2348450bcfdbb5b5f3da439539ea1f7",
    "crates/frontend/src/gates/band.rs":
        "f8c1b46ed8bc2490358af787a2cbf8e6aa2b5fa96ea51c784c4afc59ba6c192c",
    "crates/frontend/src/gates/bor.rs":
        "d45d3038aac97125b8db1720add02555f889f23d66b549031345019a2c768103",
    "crates/frontend/src/gates/bxor.rs":
        "2a58db459d6c0c89ea2d04a8da62da1d82dddb7a712c8cfa272725843bf76662",
    "crates/frontend/src/gates/icmp_ult.rs":
        "3b89ac2c05df9afa11b8fbb29f81b080f6afc31ab907a1ad1e76f1641541d6b5",
    "crates/frontend/src/gates/select.rs":
        "8f46cc1cd8ce3354fae08512667939e5dac60a3409ad35a7b149528b77f96a3e",
    "crates/frontend/src/pass/cse.rs":
        "b2923f3afddab5e885487fb4841cc5ebe16ac6ae9306bf4157490de7a81d2e99",
    "crates/frontend/src/pass/dce.rs":
        "09c66043791d69a63b832da9d7cf3586708cc51dbac009d6bddd7f1a53d1bbea",
    "crates/frontend/src/pass/fusion/commit_set.rs":
        "9b9838be00105c324b2bb0a9d67172fb58a2e50b6bbe1828479649d7275acbfc",
    "crates/circuits/src/bytes.rs":
        "9530b11dc3b134bf172e5a6ecdfc51e6cc2716e98589c9d78314ad96d9a5c1b7",
}

MAX_SIGNERS = 6
U64_MAX = (1 << 64) - 1
ONE_HOT_HIDDEN_UPPER = 60_911
N15_SYMBOLS = 1 << 15


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pins(upstream: Path) -> None:
    assert sha256(SOURCE) == PATCHED_SOURCE_SHA256, "policy-dedup maximum-M4 source drift"
    assert sha256(FIRST_PATCH) == FIRST_PATCH_SHA256, "first patch drift"
    assert sha256(PATCH) == PATCH_SHA256, "policy patch drift"
    for relative, expected in SEMANTIC_BOUNDARY_PINS.items():
        assert sha256(REPO_ROOT / relative) == expected, f"semantic boundary drift: {relative}"
    for relative, expected in UPSTREAM_PINS.items():
        assert sha256(upstream / relative) == expected, f"upstream drift: {relative}"


def apply_patch(root: Path, patch: Path) -> None:
    result = subprocess.run(
        ["git", "apply", str(patch)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def verify_patch_shape() -> None:
    relative_source = SOURCE.relative_to(REPO_ROOT)
    with tempfile.TemporaryDirectory(prefix="hegemon-policy-dedup.", dir="/private/tmp") as raw:
        root = Path(raw)
        staged = root / relative_source
        staged.parent.mkdir(parents=True)
        shutil.copy2(SOURCE, staged)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        reverse = subprocess.run(
            ["git", "apply", "--reverse", str(PATCH)],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert reverse.returncode == 0, reverse.stderr
        assert sha256(staged) == STACK_BASE_SHA256, "one-hot stack base mismatch"
        apply_patch(root, PATCH)
        assert sha256(staged) == PATCHED_SOURCE_SHA256, "policy patched source mismatch"
        final_source = staged.read_text()

    patch = PATCH.read_text()
    required_patch_markers = [
        "+struct PolicySelectors {",
        "+        select_accumulator(builder, modes.init, &wires.auth.next, &wires.auth.current);",
        "+    constrain_policy_approval_state(builder, \"auth.current\"",
        "+    constrain_policy_approval_state(builder, \"auth.next\"",
        "+    builder.assert_true(",
        "+    builder.assert_eq(",
        "+                and_msb(builder, slot_active[slot], tag_matches),",
        "-fn constrain_policy_opening(",
    ]
    for marker in required_patch_markers:
        assert marker in patch, f"missing patch marker: {marker}"

    forbidden_additions = [
        "+        builder.add_witness",
        "+        builder.add_inout",
        "+            keccak_f1600",
        "+    shake256_words(",
    ]
    for marker in forbidden_additions:
        assert marker not in patch, f"forbidden patch addition: {marker}"
    assert patch.count("diff --git ") == 1

    final_markers = [
        "builder.bnot(self.single)",
        "constrain_equal_accumulator_metadata(",
        '"auth.single.aux"',
        '"auth.init.current_zero"',
        '"auth.lock.next_zero"',
        '"auth.final.next_zero"',
        "assert_low_bool(builder, &format!(\"{name}.approved[{slot}]\"), approved);",
        "builder.assert_false(format!(\"{name}.approved_sum_overflow[{slot}]\"), carry);",
        "policy_frame(builder, &policy.opening, &wires.auth.signer_tags)",
    ]
    for marker in final_markers:
        assert marker in final_source, f"missing final-source invariant: {marker}"
    assert final_source.count("fn constrain_policy_structure(") == 1
    assert final_source.count("constrain_policy_structure(") == 2
    assert final_source.count("fn constrain_policy_approval_state(") == 1
    assert final_source.count("constrain_policy_approval_state(") == 3
    assert final_source.count(
        "select_accumulator(builder, modes.init, &wires.auth.next, &wires.auth.current)"
    ) == 1


@dataclass(frozen=True)
class Opening:
    policy_root: int
    intent: int
    threshold: int
    signer_count: int
    approval_count: int
    approved: tuple[int, ...]


@dataclass(frozen=True)
class Sample:
    mode: int
    current: Opening
    next: Opening
    tags: tuple[int, ...]
    signer_auth: int
    selected_policy_hash_ok: bool


ZERO_OPENING = Opening(0, 0, 0, 0, 0, (0,) * MAX_SIGNERS)


def is_u64(value: int) -> bool:
    return 0 <= value <= U64_MAX


def sum_without_overflow(values: tuple[int, ...]) -> int | None:
    total = 0
    for value in values:
        if not is_u64(value) or total + value > U64_MAX:
            return None
        total += value
    return total


def bool_and_carry_ok(opening: Opening) -> bool:
    return (
        len(opening.approved) == MAX_SIGNERS
        and all(value in (0, 1) for value in opening.approved)
        and sum_without_overflow(opening.approved) is not None
    )


def structure_ok(opening: Opening) -> bool:
    return (
        is_u64(opening.threshold)
        and is_u64(opening.signer_count)
        and 1 <= opening.signer_count <= MAX_SIGNERS
        and 1 <= opening.threshold <= opening.signer_count
        and opening.intent != 0
    )


def tags_against(tags: tuple[int, ...], signer_count: int) -> bool:
    if len(tags) != MAX_SIGNERS:
        return False
    for slot, tag in enumerate(tags):
        active = slot < signer_count
        if active != (tag != 0):
            return False
        if active and tag in tags[:slot]:
            return False
    return True


def state_against(opening: Opening, signer_count: int) -> bool:
    if not bool_and_carry_ok(opening):
        return False
    if not is_u64(opening.approval_count) or not is_u64(signer_count):
        return False
    if opening.approval_count > signer_count:
        return False
    for slot, approved in enumerate(opening.approved):
        if slot >= signer_count and approved != 0:
            return False
    return sum_without_overflow(opening.approved) == opening.approval_count


def metadata_equal(left: Opening, right: Opening) -> bool:
    return (
        left.policy_root == right.policy_root
        and left.intent == right.intent
        and left.threshold == right.threshold
        and left.signer_count == right.signer_count
    )


def common_mode_constraints(sample: Sample) -> bool:
    mode = sample.mode
    current = sample.current
    next_opening = sample.next
    if mode not in range(5):
        return False
    if mode == 0:
        return current == ZERO_OPENING and next_opening == ZERO_OPENING and not any(sample.tags)
    if mode == 1:
        return (
            current == ZERO_OPENING
            and next_opening.approval_count == 0
            and not any(next_opening.approved)
        )
    if mode == 2:
        if not metadata_equal(current, next_opening):
            return False
        if current.approval_count == U64_MAX:
            return False
        if next_opening.approval_count != current.approval_count + 1:
            return False
        if not bool_and_carry_ok(current) or not bool_and_carry_ok(next_opening):
            return False
        if any(c == 1 and n != 1 for c, n in zip(current.approved, next_opening.approved)):
            return False
        return sum(c ^ n for c, n in zip(current.approved, next_opening.approved)) == 1
    if mode == 3:
        return (
            next_opening == ZERO_OPENING
            and current.approval_count == 0
            and not any(current.approved)
        )
    return next_opening == ZERO_OPENING


def policy_hash_ok(sample: Sample) -> bool:
    return sample.mode == 0 or sample.selected_policy_hash_ok


def membership_ok(sample: Sample, signer_count: int) -> bool:
    if sample.mode != 2:
        return True
    for slot in range(MAX_SIGNERS):
        changed = sample.current.approved[slot] != sample.next.approved[slot]
        tag_matches = sample.signer_auth == sample.tags[slot]
        if changed and not tag_matches:
            return False
        if slot < signer_count and tag_matches and not changed:
            return False
    return True


def final_threshold_ok(sample: Sample, threshold: int) -> bool:
    return sample.mode != 4 or sample.current.approval_count >= threshold


def old_policy_relation(sample: Sample) -> bool:
    if not common_mode_constraints(sample) or not policy_hash_ok(sample):
        return False
    if not bool_and_carry_ok(sample.current) or not bool_and_carry_ok(sample.next):
        return False
    current_active = sample.mode in (2, 3, 4)
    next_active = sample.mode in (1, 2)
    if current_active and not (
        structure_ok(sample.current)
        and tags_against(sample.tags, sample.current.signer_count)
        and state_against(sample.current, sample.current.signer_count)
    ):
        return False
    if next_active and not (
        structure_ok(sample.next)
        and tags_against(sample.tags, sample.next.signer_count)
        and state_against(sample.next, sample.next.signer_count)
    ):
        return False
    return (
        final_threshold_ok(sample, sample.current.threshold)
        and membership_ok(sample, sample.current.signer_count)
    )


def new_policy_relation(sample: Sample) -> bool:
    if not common_mode_constraints(sample) or not policy_hash_ok(sample):
        return False
    selected = sample.next if sample.mode == 1 else sample.current
    if sample.mode != 0 and not structure_ok(selected):
        return False
    if not tags_against(sample.tags, selected.signer_count):
        return False
    if not state_against(sample.current, selected.signer_count):
        return False
    if not state_against(sample.next, selected.signer_count):
        return False
    return (
        final_threshold_ok(sample, selected.threshold)
        and membership_ok(sample, selected.signer_count)
    )


def valid_sample(mode: int, rng: random.Random) -> Sample:
    if mode == 0:
        return Sample(0, ZERO_OPENING, ZERO_OPENING, (0,) * MAX_SIGNERS, 0, True)

    signer_count = rng.randint(1, MAX_SIGNERS)
    threshold = rng.randint(1, signer_count)
    intent = rng.randint(1, 1 << 32)
    root = rng.randint(0, 1 << 32)
    active_tags = rng.sample(range(1, 1 << 20), signer_count)
    tags = tuple(active_tags + [0] * (MAX_SIGNERS - signer_count))

    if mode == 1:
        next_opening = Opening(root, intent, threshold, signer_count, 0, (0,) * MAX_SIGNERS)
        return Sample(mode, ZERO_OPENING, next_opening, tags, active_tags[0], True)

    if mode == 2:
        current_count = rng.randint(0, signer_count - 1)
        current_slots = set(rng.sample(range(signer_count), current_count))
        changed_slot = rng.choice([slot for slot in range(signer_count) if slot not in current_slots])
        current_bits = tuple(1 if slot in current_slots else 0 for slot in range(MAX_SIGNERS))
        next_bits = tuple(
            1 if slot in current_slots or slot == changed_slot else 0
            for slot in range(MAX_SIGNERS)
        )
        current = Opening(root, intent, threshold, signer_count, current_count, current_bits)
        next_opening = Opening(
            root, intent, threshold, signer_count, current_count + 1, next_bits
        )
        return Sample(mode, current, next_opening, tags, tags[changed_slot], True)

    if mode == 3:
        current = Opening(root, intent, threshold, signer_count, 0, (0,) * MAX_SIGNERS)
        return Sample(mode, current, ZERO_OPENING, tags, active_tags[0], True)

    approval_count = rng.randint(threshold, signer_count)
    approved_slots = set(rng.sample(range(signer_count), approval_count))
    approved = tuple(1 if slot in approved_slots else 0 for slot in range(MAX_SIGNERS))
    current = Opening(root, intent, threshold, signer_count, approval_count, approved)
    return Sample(mode, current, ZERO_OPENING, tags, active_tags[0], True)


def arbitrary_opening(rng: random.Random) -> Opening:
    words = [0, 1, 2, 5, 6, 7, 8, U64_MAX, rng.randrange(0, 16), rng.getrandbits(64)]
    return Opening(
        policy_root=rng.randrange(0, 8),
        intent=rng.randrange(0, 8),
        threshold=rng.choice(words),
        signer_count=rng.choice(words),
        approval_count=rng.choice(words),
        approved=tuple(rng.choice([0, 1, 2, U64_MAX]) for _ in range(MAX_SIGNERS)),
    )


def mutate(sample: Sample, rng: random.Random) -> Sample:
    choice = rng.randrange(14)
    if choice == 0:
        return replace(sample, selected_policy_hash_ok=not sample.selected_policy_hash_ok)
    if choice == 1:
        slot = rng.randrange(MAX_SIGNERS)
        tags = list(sample.tags)
        tags[slot] = rng.randrange(0, 4)
        return replace(sample, tags=tuple(tags))
    if choice == 2:
        tags = list(sample.tags)
        tags[rng.randrange(MAX_SIGNERS)] = tags[rng.randrange(MAX_SIGNERS)]
        return replace(sample, tags=tuple(tags))
    lane = "current" if rng.randrange(2) == 0 else "next"
    opening = getattr(sample, lane)
    if choice == 3:
        opening = replace(opening, intent=opening.intent ^ 1)
    elif choice == 4:
        opening = replace(opening, threshold=rng.choice([0, 1, 6, 7, U64_MAX]))
    elif choice == 5:
        opening = replace(opening, signer_count=rng.choice([0, 1, 6, 7, U64_MAX]))
    elif choice == 6:
        opening = replace(opening, approval_count=rng.choice([0, 1, 6, 7, U64_MAX]))
    elif choice in (7, 8, 9):
        approved = list(opening.approved)
        approved[rng.randrange(MAX_SIGNERS)] = rng.choice([0, 1, 2, U64_MAX])
        opening = replace(opening, approved=tuple(approved))
    elif choice == 10:
        opening = replace(opening, policy_root=opening.policy_root ^ 1)
    elif choice == 11:
        return replace(sample, signer_auth=rng.randrange(0, 8))
    elif choice == 12:
        return replace(sample, mode=rng.choice([5, 6, 255, U64_MAX]))
    else:
        opening = arbitrary_opening(rng)
    return replace(sample, **{lane: opening})


def differential_checks() -> dict[str, int]:
    rng = random.Random(0x4D345F504F4C4943)
    valid_checks = 0
    mutated_checks = 0
    arbitrary_checks = 0
    rejected_mode_checks = 0

    for mode in range(5):
        for _ in range(512):
            sample = valid_sample(mode, rng)
            assert old_policy_relation(sample)
            assert new_policy_relation(sample)
            valid_checks += 1
            for _ in range(8):
                sample = mutate(sample, rng)
                assert old_policy_relation(sample) == new_policy_relation(sample)
                mutated_checks += 1

    for _ in range(100_000):
        sample = Sample(
            mode=rng.choice([0, 1, 2, 3, 4, 5, 6, 255, U64_MAX]),
            current=arbitrary_opening(rng),
            next=arbitrary_opening(rng),
            tags=tuple(rng.randrange(0, 8) for _ in range(MAX_SIGNERS)),
            signer_auth=rng.randrange(0, 8),
            selected_policy_hash_ok=bool(rng.randrange(2)),
        )
        assert old_policy_relation(sample) == new_policy_relation(sample)
        arbitrary_checks += 1

    for mode in [5, 6, 7, 255, 1 << 32, U64_MAX]:
        sample = replace(valid_sample(0, rng), mode=mode)
        assert not old_policy_relation(sample) and not new_policy_relation(sample)
        rejected_mode_checks += 1

    return {
        "accepted_valid_fixture_checks": valid_checks,
        "iterated_mutation_checks": mutated_checks,
        "arbitrary_row_checks": arbitrary_checks,
        "range_rejected_mode_checks": rejected_mode_checks,
        "total_relation_checks": (
            valid_checks + mutated_checks + arbitrary_checks + rejected_mode_checks
        ),
    }


def invariant_checks() -> dict[str, int]:
    zero_state_checks = 0
    metadata_state_checks = 0
    prefix_checks = 0
    selected_reuse_checks = 0

    for signer_count in range(MAX_SIGNERS + 1):
        assert state_against(ZERO_OPENING, signer_count)
        zero_state_checks += 1

    for signer_count in range(MAX_SIGNERS + 1):
        for approval_count in range(MAX_SIGNERS + 2):
            for mask in range(1 << MAX_SIGNERS):
                approved = tuple((mask >> slot) & 1 for slot in range(MAX_SIGNERS))
                opening = Opening(3, 5, 1, signer_count, approval_count, approved)
                assert state_against(opening, signer_count) == state_against(
                    opening, opening.signer_count
                )
                metadata_state_checks += 1

    for signer_count in range(MAX_SIGNERS + 1):
        for later in range(MAX_SIGNERS):
            for previous in range(later):
                if later < signer_count:
                    assert previous < signer_count
                prefix_checks += 1

    rng = random.Random(0x53454C4543544544)
    for mode in range(5):
        for _ in range(1_024):
            current = arbitrary_opening(rng)
            next_opening = arbitrary_opening(rng)
            selected = next_opening if mode == 1 else current
            if mode == 4:
                assert selected.threshold == current.threshold
            if mode == 2:
                assert selected.signer_count == current.signer_count
            selected_reuse_checks += 1

    return {
        "zero_inactive_lane_state_checks": zero_state_checks,
        "equal_signer_count_state_checks": metadata_state_checks,
        "prefix_slot_implication_checks": prefix_checks,
        "final_threshold_and_approval_slot_reuse_checks": selected_reuse_checks,
        "total_invariant_checks": (
            zero_state_checks + metadata_state_checks + prefix_checks + selected_reuse_checks
        ),
    }


def compiler_accounting() -> dict[str, object]:
    rows = {
        "active_mode_or_outputs": (5, 3, 5, 3),
        "threshold_signer_byte_swaps": (16, 8, 16, 8),
        "structural_range_implications": (16, 8, 16, 8),
        "intent_validation": (16, 15, 16, 15),
        "slot_predicates": (36, 6, 36, 6),
        "tag_nonzero": (60, 48, 60, 48),
        # New structure emits 36 inactive-tag equalities and the two distinct
        # approval-state checks retain 6 inactive-approved equalities each.
        "inactive_tag_equalities": (84, 48, 0, 0),
        "pairwise_tag_uniqueness": (180, 120, 180, 120),
        "approval_count_upper_bounds": (4, 2, 4, 2),
        "conditional_approval_popcounts": (2, 0, 0, 0),
    }
    old_nonlinear = sum(row[0] for row in rows.values())
    new_nonlinear = sum(row[1] for row in rows.values())
    old_hidden = sum(row[2] for row in rows.values())
    new_hidden = sum(row[3] for row in rows.values())
    assert (old_nonlinear, new_nonlinear) == (419, 258)
    assert (old_hidden, new_hidden) == (333, 210)
    nonlinear_cut = old_nonlinear - new_nonlinear
    hidden_cut = old_hidden - new_hidden
    assert (nonlinear_cut, hidden_cut) == (161, 123)

    hidden_upper = ONE_HOT_HIDDEN_UPPER - hidden_cut
    active_symbols_upper = math.ceil(hidden_upper / 2)
    tail_symbols_lower = N15_SYMBOLS - active_symbols_upper
    assert (hidden_upper, active_symbols_upper, tail_symbols_lower) == (60_788, 30_394, 2_374)
    return {
        "model": "pinned CSE/DCE/fusion source-static prediction; compile required",
        "rows": {
            name: {
                "old_nonlinear": row[0],
                "new_nonlinear": row[1],
                "old_hidden": row[2],
                "new_hidden": row[3],
            }
            for name, row in rows.items()
        },
        "old_nonlinear": old_nonlinear,
        "new_nonlinear": new_nonlinear,
        "predicted_nonlinear_cut": nonlinear_cut,
        "old_hidden": old_hidden,
        "new_hidden": new_hidden,
        "predicted_hidden_word_cut": hidden_cut,
        "stack_base_hidden_words_upper": ONE_HOT_HIDDEN_UPPER,
        "stacked_hidden_words_upper": hidden_upper,
        "stacked_active_b128_symbols_upper": active_symbols_upper,
        "stacked_n15_random_tail_symbols_lower": tail_symbols_lower,
    }


def build_report() -> dict[str, object]:
    differential = differential_checks()
    invariants = invariant_checks()
    accounting = compiler_accounting()
    total_checks = differential["total_relation_checks"] + invariants["total_invariant_checks"]
    return {
        "status": {
            "patch_applied_to_live_source": True,
            "stack_base_sha256": STACK_BASE_SHA256,
            "patched_source_sha256": PATCHED_SOURCE_SHA256,
            "compiled_exact": False,
            "proof_run": False,
            "frontier_promotable": False,
            "deterministic_checks": total_checks,
        },
        "differential": differential,
        "algebraic_invariants": invariants,
        "compiler_aware_cost": accounting,
        "capacity": {
            "conditional_required_b128_symbols": 1_060,
            "conditional_margin_b128_symbols": accounting[
                "stacked_n15_random_tail_symbols_lower"
            ] - 1_060,
            "full_required_b128_symbols": 1_984,
            "full_margin_b128_symbols": accounting[
                "stacked_n15_random_tail_symbols_lower"
            ] - 1_984,
        },
        "claim_boundary": [
            "applied policy-dedup patch stacked after the one-hot rewrite",
            "deterministic abstract relation differential, not a formal proof",
            "compiler count is predicted from pinned gate/CSE/DCE/fusion semantics",
            "no Cargo build, circuit compilation, proof, or encoded oracle",
            "compiled statistics and scalar/M4 differential execution remain mandatory",
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
