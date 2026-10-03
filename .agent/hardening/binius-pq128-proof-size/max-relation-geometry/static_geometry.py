#!/usr/bin/env python3
"""Source-bound, allocation-free geometry audit for the maximum M4 relation.

This script mirrors the fixed Rust loops.  It does not compile the circuit and
does not create a codeword, Merkle tree, proof, or Cargo target directory.
The hidden-word bound is conditional on the pinned gate-fusion behavior shown
by the pinned Keccak snapshot; the exact compiler statistic remains unfrozen.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_UPSTREAM = Path("/private/tmp/binius64-api-3f961630")

PINNED_REPO_FILES = {
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/main.rs":
        "d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c",
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs":
        "67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91",
    ".agent/hardening/binius-pq128-proof-size/strict_refold_pcs_model.py":
        "3cde106361941c6533d19752f7755c366539620d2a7ef0890b6dde5ab2836f55",
    ".agent/hardening/binius-pq128-proof-size/binding-vector-pcs/binding_vector_pcs.py":
        "638257b91c9af945be0efabed7e4a6f597be5faa23f8d393f07eece432840b85",
}

PINNED_UPSTREAM_FILES = {
    "crates/circuits/src/keccak/permutation.rs":
        "e4d2ca3da3e2bc2dc6971ed9d21ee5e8e058f319fa8479938a062b900cd00c92",
    "crates/examples/snapshots/keccak.snap":
        "beb2f886931492453ff3aa7b9c5de983e795335bf9b861ea3f0717fefc4ee308",
    "crates/m4-verifier/src/commit.rs":
        "a589e053baedcf3ce6bab4cb00ddf789829e2a29e6f5370971cdab4a156aa477",
    "crates/frontend/src/builder/mod.rs":
        "8170a7cdeabd42dc123e6507939cdd06dc8928382a49a7ce98b4592454499dff",
    "crates/frontend/src/pass/zero_fold.rs":
        "edea72c51412689745bb169c62df3f4eccd5d4b6dc45cf8d5eee797dbef62600",
    "crates/frontend/src/pass/cse.rs":
        "b2923f3afddab5e885487fb4841cc5ebe16ac6ae9306bf4157490de7a81d2e99",
    "crates/frontend/src/pass/fusion/commit_set.rs":
        "9b9838be00105c324b2bb0a9d67172fb58a2e50b6bbe1828479649d7275acbfc",
}

DIGEST = 7
INPUTS = 2
OUTPUTS = 2
SLOTS = 4
SIGNERS = 6
DEPTH = 32
PUBLIC_WORDS = 114
PRIVATE_WORDS = 671
DECLARED_HIDDEN_WORDS = PUBLIC_WORDS + PRIVATE_WORDS


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pins(upstream: Path) -> None:
    for relative, expected in PINNED_REPO_FILES.items():
        path = REPO_ROOT / relative
        actual = sha256(path)
        if actual != expected:
            raise SystemExit(f"source pin mismatch: {path}: {actual} != {expected}")
    for relative, expected in PINNED_UPSTREAM_FILES.items():
        path = upstream / relative
        actual = sha256(path)
        if actual != expected:
            raise SystemExit(f"upstream pin mismatch: {path}: {actual} != {expected}")


class SourceCount:
    """Conservative output-wire census for the non-Keccak Rust helpers."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()

    def op(self, name: str, count: int = 1) -> None:
        self.counts[name] += count

    def band(self, count: int = 1) -> None:
        self.op("AND.band", count)

    def bor(self, count: int = 1) -> None:
        self.op("AND.bor", count)

    def bxor(self, count: int = 1) -> None:
        self.op("LIN.xor", count)

    def bnot(self, count: int = 1) -> None:
        self.bxor(count)

    def shift(self, count: int = 1) -> None:
        self.op("LIN.shift", count)

    def iadd(self, count: int = 1) -> None:
        self.op("AND.iadd", count)
        self.op("LIN.iadd_sum", count)

    def assertion(self, count: int = 1) -> None:
        self.op("ZERO.assert", count)

    def eqcond(self, count: int = 1) -> None:
        self.op("AND.assert_cond", count)

    def nonzero(self, count: int = 1) -> None:
        # Synthetic one-output allowance: upstream AssertNonZero actually has
        # no IR output, so this deliberately overcounts hidden words.
        self.op("AND.nonzero_aux", count)
        self.op("ZERO.nonzero", count)

    def cmpeq(self, count: int = 1) -> None:
        self.op("AND.cmp_eq", count)

    def cmpult(self, count: int = 1) -> None:
        self.op("AND.cmp_ult", count)

    def cmpne(self, count: int = 1) -> None:
        self.cmpeq(count)
        self.bnot(count)

    def cmpule(self, count: int = 1) -> None:
        self.cmpult(count)
        self.bnot(count)

    def cmpuge(self, count: int = 1) -> None:
        self.cmpult(count)
        self.bnot(count)

    def select(self, count: int = 1) -> None:
        self.op("BMUL.select", count)

    def extract(self, count: int = 1) -> None:
        self.band(count)
        self.shift(count)

    def swap(self, count: int = 1) -> None:
        # Pinned swap_bytes source: 4 BAND, 5 shifts/rotates, 2 XOR.
        self.band(4 * count)
        self.shift(5 * count)
        self.bxor(2 * count)

    def lowmsb(self, count: int = 1) -> None:
        self.shift(count)

    def andmsb(self, count: int = 1) -> None:
        self.band(count)

    def ormsb(self, arity: int, count: int = 1) -> None:
        self.bor(arity * count)

    def implies(self, count: int = 1) -> None:
        self.bnot(count)
        self.bor(count)
        self.assertion(count)

    def bit61(self, count: int = 1) -> None:
        self.shift(count)
        self.assertion(count)

    def lowbool(self, count: int = 1) -> None:
        self.band(count)
        self.assertion(count)

    def digest_nonzero(self, count: int = 1) -> None:
        self.bor(6 * count)
        self.select(count)
        self.nonzero(count)

    def digest_unequal(self, count: int = 1) -> None:
        self.bxor(7 * count)
        self.digest_nonzero(count)

    def digest_eq_msb(self, count: int = 1) -> None:
        self.cmpeq(7 * count)
        self.band(7 * count)

    def select_digest(self, count: int = 1) -> None:
        self.select(7 * count)

    def select_accum(self, count: int = 1) -> None:
        self.select(23 * count)

    @property
    def attempted_internal(self) -> int:
        return sum(
            value
            for name, value in self.counts.items()
            if not name.startswith("ZERO") and name != "AND.assert_cond"
        )

    @property
    def nonlinear_output_upper(self) -> int:
        prefixes = (
            "AND.band",
            "AND.bor",
            "AND.iadd",
            "AND.nonzero_aux",
            "AND.cmp_",
            "BMUL.select",
        )
        return sum(value for name, value in self.counts.items() if name.startswith(prefixes))


def pack_bytes(count: SourceCount, byte_count: int) -> None:
    for start in range(0, byte_count, 8):
        width = min(8, byte_count - start)
        count.shift(width)
        count.bxor(width)


def count_decode_public(count: SourceCount) -> None:
    count.extract(853)
    for _ in range(11):
        pack_bytes(count, 56)
    for width in [8] * 8 + [4]:
        count.shift(width)
        count.bxor(width)


def count_transport(count: SourceCount) -> None:
    count.band()
    count.assertion(1 + 8 + 2 + (853 - 701))
    count.lowbool(7)


def count_slots(count: SourceCount) -> None:
    count.assertion()
    for _ in range(3):
        count.cmpeq()
        count.bnot()
        count.cmpult()
        count.implies()
        count.cmpne()
        count.implies()
        count.cmpne()
        count.implies()
        count.cmpeq()
        count.implies()
        count.bnot()
        count.andmsb()
        count.cmpult()
        count.implies()


def count_stable(count: SourceCount) -> None:
    count.lowmsb()
    count.bnot()
    count.eqcond(4)
    for _ in range(3):
        count.digest_nonzero()
    for operation in ("ne", "ult", "ne", "ne", "ne"):
        getattr(count, "cmpne" if operation == "ne" else "cmpult")()
        count.implies()
    count.cmpeq(4)
    count.ormsb(4)
    count.implies()


def count_note_selectors(count: SourceCount) -> None:
    count.lowmsb()
    count.swap(3)
    count.cmpule()
    count.implies()
    count.bit61()
    count.cmpult()
    count.implies()
    count.cmpne()
    count.implies()
    count.swap(4)
    count.lowbool(4)
    count.iadd(4)
    count.assertion(4)
    count.eqcond()
    count.lowmsb(4)
    count.select(4)
    count.eqcond()


def count_numeric_eq(count: SourceCount) -> None:
    count.swap()
    count.eqcond()


def count_zero_native(count: SourceCount) -> None:
    count_numeric_eq(count)
    count_numeric_eq(count)


def count_optional_output(count: SourceCount) -> None:
    count.lowmsb()
    count.andmsb()
    count_numeric_eq(count)


def count_policy_open(count: SourceCount) -> None:
    count.swap(3)
    for comparison in ("uge", "ule", "uge", "ule", "ule"):
        getattr(count, f"cmp{comparison}")()
        count.implies()
    count.digest_nonzero()
    for slot in range(6):
        count.swap()
        count.lowbool()
        count.iadd()
        count.assertion()
        count.cmpult()
        count.bnot()  # inactive_tag = active & !slot_active
        count.andmsb(2)
        count.digest_nonzero()
        for _ in range(slot):
            count.cmpult()
            count.andmsb()
            count.digest_unequal()
    count.eqcond()


def count_auth(count: SourceCount) -> None:
    count.lowmsb(4)
    for _ in range(4):
        count.andmsb()
        count_numeric_eq(count)
    for _ in range(2):
        count.andmsb()
        count_numeric_eq(count)
    count_numeric_eq(count)
    count_zero_native(count)
    count.swap(1 + 6)
    count.eqcond(1 + 6)
    count_optional_output(count)
    count_numeric_eq(count)
    count_numeric_eq(count)
    count_numeric_eq(count)
    count_zero_native(count)
    count_zero_native(count)
    count_optional_output(count)
    count.eqcond(2 * 7 + 2)
    count.swap(2)
    count.iadd()
    count.assertion()
    count.eqcond()
    for _ in range(2):
        count.andmsb()
        count_numeric_eq(count)
    count_numeric_eq(count)
    count_optional_output(count)
    count.swap(1 + 6)
    count.eqcond(1 + 6)
    count_numeric_eq(count)
    count_numeric_eq(count)
    count_zero_native(count)
    for _ in range(2):
        count.andmsb()
        count_numeric_eq(count)
    count.swap(2)
    count.cmpuge()
    count.implies()
    count.ormsb(3)
    count_policy_open(count)
    count.ormsb(2)
    count_policy_open(count)
    for _ in range(6):
        count.swap(2)
        count.bxor()
        count.lowmsb(2)
        count.andmsb()
        count.implies()
        count.iadd()
        count.assertion()
    count.eqcond()


def count_balance(count: SourceCount) -> None:
    count.lowmsb(2)
    for slot in range(4):
        for _ in range(4):
            count.swap(2)
            count.lowmsb()
            count.select()
            count.iadd()
            count.assertion()
        if slot == 0:
            count.iadd()
            count.assertion(2)
            continue
        count.cmpeq()
        count.eqcond(2)
        count.cmpeq()
        count.andmsb(3)
        count.bnot()  # !issuance_negative
        count.iadd(2)
        count.bnot(2)  # !mint_carry and !burn_carry
        count.implies(2)
        count.eqcond(3)
        count.bnot()  # ordinary = !stable_slot


def count_nonhash(count: SourceCount) -> None:
    count.bor(2)
    count.nonzero(2)
    count.assertion(2)
    count.bit61(2)
    count.cmpeq()
    count.eqcond()
    count_slots(count)
    count_stable(count)
    for _ in range(2):
        count.lowmsb()
        count.bnot()  # inactive
        count_note_selectors(count)
        count.swap()
        count.shift()
        count.lowmsb()
        count.bnot()  # inactive_public
    for _ in range(2):
        count.lowmsb()
        count.bnot()  # inactive
        count_note_selectors(count)
        count.lowmsb()
        count.digest_nonzero()
    count.lowmsb(2)
    count.andmsb()
    count.digest_unequal()
    count.swap()
    count.cmpule()
    count.assertion()
    count.cmpeq(5)
    count_auth(count)
    count_balance(count)


class FrameCounter:
    def __init__(self, count: SourceCount) -> None:
        self.count = count
        self.used = 0

    def word(self, byte_count: int) -> None:
        if byte_count < 8:
            self.count.band()
        remaining = byte_count
        while remaining:
            if self.used == 0 and remaining == 8:
                return
            if self.used == 0:
                self.used = remaining
                return
            take = min(8 - self.used, remaining)
            if take < 8:
                self.count.band()
            self.count.shift()
            self.count.bxor()
            if self.used + take == 8:
                self.used = 0
            else:
                self.used += take
            remaining -= take
            if remaining:
                self.count.shift()

    def bytes(self, byte_count: int) -> None:
        while byte_count:
            width = min(8, byte_count)
            self.word(width)
            byte_count -= width


def semantic_frame(count: SourceCount, fields: list[int]) -> None:
    frame = FrameCounter(count)
    frame.bytes(8)
    frame.bytes(8)
    frame.bytes(1)
    for byte_count in fields:
        frame.bytes(2)
        frame.bytes(byte_count)


def shake_absorb(count: SourceCount, frame_len: int) -> None:
    count.bxor((frame_len // 136) * 17)
    count.bxor(math.ceil((frame_len % 136) / 8))
    count.bxor(2)


def count_hash_nonkeccak(count: SourceCount) -> None:
    count.lowmsb(4)
    for _ in range(2):
        semantic_frame(count, [8, 48])
        shake_absorb(count, 77)
    count.select_accum()
    semantic_frame(count, [8, 8] + [56] * 6)
    shake_absorb(count, 385)
    count.ormsb(4)
    count.eqcond(7)
    dummy = FrameCounter(count)
    dummy.bytes(136)
    for _ in range(3):
        count.swap(6)
        pack_bytes(count, 6)
        semantic_frame(count, [8, 56, 56, 8, 8, 8, 6])
    semantic_frame(count, [8, 56, 56])
    count.bxor(16)  # suffix and final delimiter for 5 + 3 padded candidates
    count.select(2 * 17 * 5)
    count.bxor(2 * 17)
    count.ormsb(3)
    count.select(2 * 17 * 3)
    count.bxor(2 * 17)
    count.select_digest(6)
    count.ormsb(2)
    count.eqcond(14)
    for _ in range(4):
        count.swap()
        semantic_frame(count, [1, 8, 8, 32, 48, 48, 56])
        shake_absorb(count, 232)
    count.digest_nonzero(4)
    count.eqcond((2 + 2) * 7)
    for _ in range(2):
        semantic_frame(count, [56, 8, 48])
        shake_absorb(count, 135)
        count.eqcond(7)
        count.digest_nonzero()
    for _ in range(2):
        count.swap()
        for _ in range(32):
            count.shift(2)
            count.bxor(14)
            count.band(14)
            count.bxor(14)
            semantic_frame(count, [56, 56])
            shake_absorb(count, 133)
        count.eqcond(7)
    count.eqcond(7)
    count.swap()
    for _ in range(6):
        count.swap(2)
        count.bxor()
        count.lowmsb()
        count.cmpult()
        count.digest_eq_msb()
        count.andmsb()
        count.implies()
        count.andmsb(2)
        count.implies()


def source_parts() -> dict[str, SourceCount]:
    parts: dict[str, SourceCount] = {}
    for name, function in (
        ("decode_public", count_decode_public),
        ("transport", count_transport),
        ("nonhash", count_nonhash),
        ("hash_nonkeccak", count_hash_nonkeccak),
    ):
        count = SourceCount()
        function(count)
        parts[name] = count
    return parts


def previous_round_dependencies(live_outputs: set[int]) -> set[int]:
    """Back-propagate live Keccak lanes through chi/rho-pi/theta."""
    pre_chi: set[int] = set()
    for lane in live_outputs:
        x, y = lane % 5, lane // 5
        pre_chi.update(((x + delta) % 5) + 5 * y for delta in (0, 1, 2))

    inverse_rho_pi: dict[int, int] = {}
    for y in range(5):
        for x in range(5):
            source = x + 5 * y
            target = y + 5 * ((2 * x + 3 * y) % 5)
            inverse_rho_pi[target] = source
    post_theta = {inverse_rho_pi[lane] for lane in pre_chi}

    previous: set[int] = set()
    for lane in post_theta:
        x, y = lane % 5, lane // 5
        previous.add(x + 5 * y)
        previous.update((x - 1) % 5 + 5 * row for row in range(5))
        previous.update((x + 1) % 5 + 5 * row for row in range(5))
    return previous


def live_fax_for_outputs(output_lanes: int) -> int:
    live = set(range(output_lanes))
    fax = 0
    for _ in range(24):
        fax += len(live)
        live = previous_round_dependencies(live)
    return fax


def build_report() -> dict[str, object]:
    parts = source_parts()
    total = SourceCount()
    for count in parts.values():
        total.counts.update(count.counts)

    assert parts["decode_public"].attempted_internal == 3_074
    assert parts["transport"].attempted_internal == 8
    assert parts["nonhash"].attempted_internal == 2_787
    assert parts["hash_nonkeccak"].attempted_internal == 10_707
    assert total.attempted_internal == 16_576
    assert total.counts["LIN.xor"] == 6_067
    assert total.nonlinear_output_upper == 5_355

    final_7 = live_fax_for_outputs(7)
    final_14 = live_fax_for_outputs(14)
    full = live_fax_for_outputs(25)
    assert (final_7, final_14, full) == (582, 589, 600)
    live_fax = 71 * final_7 + 4 * final_14 + 8 * full
    assert live_fax == 48_478

    source_fax = 83 * 24 * 25
    bit_ands = source_fax * 64
    assert source_fax == 49_800
    assert bit_ands == 3_187_200

    # These are immediate builder identities, not speculative constant
    # propagation.  CircuitBuilder defaults constant propagation off.
    frame_immediate_band_folds = (
        4 * 14  # note frames
        + 2 * 6  # spend frames
        + 17  # policy frame
        + 3 * 16  # accumulator frames
        + 8  # value-lock frame
        + 2 * 7  # nullifier frames
        + 64 * 5  # Merkle frames
    )
    assert frame_immediate_band_folds == 475
    pack_first_zero_xor_folds = 89
    first_absorption_zero_xor_folds = 1_261
    guaranteed_folds = (
        frame_immediate_band_folds
        + pack_first_zero_xor_folds
        + first_absorption_zero_xor_folds
    )
    assert guaranteed_folds == 1_825

    raw_hidden_upper = DECLARED_HIDDEN_WORDS + source_fax + total.attempted_internal
    hidden_upper = raw_hidden_upper - guaranteed_folds
    # Guarded lower deliberately discounts one entire 25-FAX round per
    # permutation from the syntactic live count for uncompiled CSE uncertainty.
    hidden_lower = DECLARED_HIDDEN_WORDS + live_fax - 83 * 25
    assert (hidden_lower, raw_hidden_upper, hidden_upper) == (47_188, 67_161, 65_336)

    active_lower = math.ceil(hidden_lower / 2)
    active_upper = math.ceil(hidden_upper / 2)
    capacity = 1 << 15
    tail_slack_min = capacity - active_upper
    tail_slack_max = capacity - active_lower
    assert (active_lower, active_upper) == (23_594, 32_668)
    assert (tail_slack_min, tail_slack_max) == (100, 9_174)

    part_report = {
        name: {
            "attempted_internal_upper": count.attempted_internal,
            "nonlinear_output_upper": count.nonlinear_output_upper,
            "operations": dict(sorted(count.counts.items())),
        }
        for name, count in parts.items()
    }

    return {
        "status": {
            "compiled_exact": False,
            "likely_relation_log_b128": 15,
            "strict_or_formal_security": False,
            "frontier_promotable": False,
            "conditioning": "pinned fusion behavior and source mirror",
        },
        "declared": {
            "public_hidden_words": PUBLIC_WORDS,
            "private_witness_words": PRIVATE_WORDS,
            "declared_hidden_words": DECLARED_HIDDEN_WORDS,
            "keccak_permutations": 83,
        },
        "keccak": {
            "source_fax_word_constraints": source_fax,
            "source_bit_ands": bit_ands,
            "live_fax_syntactic": live_fax,
            "final_7_lane_permutations": 71,
            "final_14_lane_permutations": 4,
            "intermediate_full_permutations": 8,
            "live_fax_per_final_7": final_7,
            "live_fax_per_final_14": final_14,
            "live_fax_per_full": full,
        },
        "nonkeccak_source_mirror": {
            "parts": part_report,
            "attempted_internal_upper": total.attempted_internal,
            "nonlinear_output_upper": total.nonlinear_output_upper,
            "operations": dict(sorted(total.counts.items())),
        },
        "hidden_word_bounds": {
            "guarded_lower": hidden_lower,
            "raw_upper_before_immediate_folds": raw_hidden_upper,
            "guaranteed_immediate_folds": guaranteed_folds,
            "conservative_upper": hidden_upper,
            "n15_word_capacity": 1 << 16,
            "upper_headroom_words": (1 << 16) - hidden_upper,
        },
        "b128_active_and_random_tail": {
            "active_symbols_lower": active_lower,
            "active_symbols_upper": active_upper,
            "n15_capacity_symbols": capacity,
            "random_tail_slack_min": tail_slack_min,
            "random_tail_slack_max": tail_slack_max,
        },
        "strict_refold_pcs_screen": {
            "n15": {
                "proof_bytes": 117_488,
                "envelope_bytes": 117_500,
                "raw_cap_headroom_bytes": 6_580,
                "encoded_oracle_bytes": 34_359_738_368,
                "disk_gate": "fails: 32 GiB encoded oracle exceeds 28 GiB admission floor",
            },
            "n16": {
                "proof_bytes": 144_496,
                "envelope_bytes": 144_508,
                "raw_cap_overage_bytes": 20_428,
                "encoded_oracle_bytes": 68_719_476_736,
                "disk_gate": "fails: 64 GiB encoded oracle",
            },
            "strict_admitted": False,
        },
        "binding_vector_screen": {
            "n15_raw_bytes": 288_408,
            "n15_encoded_oracle_bytes": 24 * 1024**3,
            "n16_raw_bytes": 398_616,
            "strict_admitted": False,
            "note": "tier-only price; nonlinear masked-M4 grammar remains unimplemented",
        },
        "compile_required_to_freeze": [
            "circuit.main.circuit.n_hidden_words(Hidden)",
            "CircuitStat AND/ZERO/BMUL constraint counts",
            "exact committed Internal and Scratch counts",
            "exact active B128 symbols and random-tail slack",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, default=DEFAULT_UPSTREAM)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    verify_pins(args.upstream)
    print(json.dumps(build_report(), indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
