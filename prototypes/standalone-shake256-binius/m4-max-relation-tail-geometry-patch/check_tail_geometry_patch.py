#!/usr/bin/env python3
"""Allocation-free certificate for the applied maximum-M4 geometry patch.

The checker never builds a circuit or allocates an encoded oracle.  It pins the
source and compiler rules, checks that the patch is applied, differentially tests
the three scalar-preserving rewrites, and recomputes the conservative hidden
word upper bound from explicit source-operation counts.
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
PATCH = HERE / "hegemon-m4-max-tail-geometry-67e7f6ac.patch"
SECOND_PATCH = (
    HERE.parent
    / "m4-max-relation-merkle-select-patch"
    / "hegemon-m4-max-merkle-select-6a37ca5d.patch"
)
THIRD_PATCH = (
    HERE.parent
    / "m4-max-relation-one-hot-mux-patch"
    / "hegemon-m4-max-one-hot-mux-56301203.patch"
)
FOURTH_PATCH = (
    HERE.parent
    / "m4-max-relation-policy-dedup-patch"
    / "hegemon-m4-max-policy-dedup-5f8f12b4.patch"
)
DEFAULT_UPSTREAM = Path("/private/tmp/binius64-api-3f961630")

BASE_SOURCE_SHA256 = "67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91"
INTERMEDIATE_SOURCE_SHA256 = "6a37ca5d2f2eb826c77c645b9dd7ab1f86ac2522acea86b9099b4ff24956988e"
POST_SECOND_SOURCE_SHA256 = "56301203b5d6d8cd99b1941778fe95887c65cc92957a73ae0413a8565b1f6b9b"
POST_THIRD_SOURCE_SHA256 = "5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976"
APPLIED_SOURCE_SHA256 = "f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b"
PATCH_SHA256 = "bb8f8c6edd6495301981d79b683f7e613d92a34be4948e7a35e9a55c98838e70"
SECOND_PATCH_SHA256 = "4a7289068cb8488d674249501d5b226f2ba4e8f7794014f9af5e65d83cab275c"
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
    "crates/frontend/src/pass/zero_fold.rs":
        "edea72c51412689745bb169c62df3f4eccd5d4b6dc45cf8d5eee797dbef62600",
    "crates/frontend/src/pass/cse.rs":
        "b2923f3afddab5e885487fb4841cc5ebe16ac6ae9306bf4157490de7a81d2e99",
    "crates/frontend/src/pass/fusion/commit_set.rs":
        "9b9838be00105c324b2bb0a9d67172fb58a2e50b6bbe1828479649d7275acbfc",
    "crates/circuits/src/bytes.rs":
        "9530b11dc3b134bf172e5a6ecdfc51e6cc2716e98589c9d78314ad96d9a5c1b7",
    "crates/circuits/src/keccak/permutation.rs":
        "e4d2ca3da3e2bc2dc6971ed9d21ee5e8e058f319fa8479938a062b900cd00c92",
}

PUBLIC_BYTES = 853
STATEMENT_WORDS = math.ceil(PUBLIC_BYTES / 8)
MASK64 = (1 << 64) - 1

DIGEST_OFFSETS = [
    14,
    70,
    126,
    182,
    238,
    294,
    350,
    477,
    533,
    589,
    645,
]
BE_U64_OFFSETS = [406, 414, 422, 430, 438, 447, 456, 469]
BYTE_OFFSETS = [10, 11, 12, 13, 446, 455, 468]
BE_U32_OFFSET = 464


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pins(upstream: Path) -> None:
    assert sha256(SOURCE) == APPLIED_SOURCE_SHA256, "applied maximum M4 source drift"
    if PATCH_SHA256 != "TO_BE_FROZEN":
        assert sha256(PATCH) == PATCH_SHA256, "isolated patch drift"
    assert sha256(SECOND_PATCH) == SECOND_PATCH_SHA256, "second geometry patch drift"
    assert sha256(THIRD_PATCH) == THIRD_PATCH_SHA256, "third geometry patch drift"
    assert sha256(FOURTH_PATCH) == FOURTH_PATCH_SHA256, "fourth geometry patch drift"
    for relative, expected in SEMANTIC_BOUNDARY_PINS.items():
        assert sha256(REPO_ROOT / relative) == expected, f"semantic boundary drift: {relative}"
    for relative, expected in UPSTREAM_PINS.items():
        assert sha256(upstream / relative) == expected, f"upstream drift: {relative}"


def verify_patch_shape() -> None:
    relative_source = SOURCE.relative_to(REPO_ROOT)
    with tempfile.TemporaryDirectory(prefix="hegemon-tail-chain.", dir="/private/tmp") as raw:
        root = Path(raw)
        staged_source = root / relative_source
        staged_source.parent.mkdir(parents=True)
        shutil.copy2(SOURCE, staged_source)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for candidate, expected in (
            (FOURTH_PATCH, POST_THIRD_SOURCE_SHA256),
            (THIRD_PATCH, POST_SECOND_SOURCE_SHA256),
            (SECOND_PATCH, INTERMEDIATE_SOURCE_SHA256),
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
    patch = PATCH.read_text()
    required = [
        "struct BalanceNote",
        "fn public_le_word(",
        "fn assert_public_bytes_const(",
        "let delta: [Wire; DIGEST_WORDS]",
        "constrain_balance(builder, wires, &balance_inputs, &balance_outputs)",
    ]
    for marker in required:
        assert marker in patch, f"missing patch marker: {marker}"
    assert patch.count("diff --git ") == 1
    assert "m4-full-production-prototype/src/lib.rs" in patch.splitlines()[0]
    assert BASE_SOURCE_SHA256 in PATCH.name or "67e7f6ac" in PATCH.name


def words_from_statement(statement: bytes) -> list[int]:
    assert len(statement) == PUBLIC_BYTES
    padded = statement + bytes(STATEMENT_WORDS * 8 - PUBLIC_BYTES)
    return [int.from_bytes(padded[i:i + 8], "little") for i in range(0, len(padded), 8)]


def direct_le_word(words: list[int], byte_offset: int) -> int:
    assert byte_offset + 8 <= PUBLIC_BYTES
    word = byte_offset // 8
    shift = (byte_offset % 8) * 8
    if shift == 0:
        return words[word]
    return ((words[word] >> shift) ^ (words[word + 1] << (64 - shift))) & MASK64


def direct_byte(words: list[int], byte_offset: int) -> int:
    return (words[byte_offset // 8] >> ((byte_offset % 8) * 8)) & 0xFF


def direct_be_u64(words: list[int], byte_offset: int) -> int:
    return int.from_bytes(direct_le_word(words, byte_offset).to_bytes(8, "little"), "big")


def direct_be_u32(words: list[int], byte_offset: int) -> int:
    assert byte_offset % 8 == 0
    swapped = int.from_bytes(words[byte_offset // 8].to_bytes(8, "little"), "big")
    return swapped >> 32


def differential_public_decode() -> int:
    rng = random.Random(0x484547454D4F4E)
    cases = [
        bytes(PUBLIC_BYTES),
        bytes([0xFF]) * PUBLIC_BYTES,
        bytes((index & 0xFF) for index in range(PUBLIC_BYTES)),
    ]
    cases.extend(rng.randbytes(PUBLIC_BYTES) for _ in range(512))
    checks = 0
    for statement in cases:
        words = words_from_statement(statement)
        for offset in DIGEST_OFFSETS:
            old = [
                int.from_bytes(statement[offset + 8 * word:offset + 8 * (word + 1)], "little")
                for word in range(7)
            ]
            new = [direct_le_word(words, offset + 8 * word) for word in range(7)]
            assert new == old
            checks += 7
        for offset in BE_U64_OFFSETS:
            assert direct_be_u64(words, offset) == int.from_bytes(
                statement[offset:offset + 8], "big"
            )
            checks += 1
        for offset in BYTE_OFFSETS:
            assert direct_byte(words, offset) == statement[offset]
            checks += 1
        assert direct_be_u32(words, BE_U32_OFFSET) == int.from_bytes(
            statement[BE_U32_OFFSET:BE_U32_OFFSET + 4], "big"
        )
        checks += 1
    return checks


def constrained_word_slices(byte_offset: int, expected: bytes) -> list[tuple[int, int, int]]:
    slices = []
    consumed = 0
    while consumed < len(expected):
        absolute = byte_offset + consumed
        word = absolute // 8
        within = absolute % 8
        take = min(8 - within, len(expected) - consumed)
        mask = ((1 << (8 * take)) - 1) << (8 * within)
        raw = bytearray(8)
        raw[within:within + take] = expected[consumed:consumed + take]
        slices.append((word, mask, int.from_bytes(raw, "little")))
        consumed += take
    return slices


def accepts_constant_range(statement: bytes, byte_offset: int, expected: bytes) -> bool:
    words = words_from_statement(statement)
    return all((words[word] & mask) == value for word, mask, value in constrained_word_slices(
        byte_offset, expected
    ))


def differential_constant_ranges() -> int:
    rng = random.Random(0x5348414B45323536)
    ranges = [
        (0, rng.randbytes(8)),
        (8, rng.randbytes(2)),
        (701, rng.randbytes(PUBLIC_BYTES - 701)),
    ]
    checks = 0
    for offset, expected in ranges:
        statement = bytearray(rng.randbytes(PUBLIC_BYTES))
        statement[offset:offset + len(expected)] = expected
        assert accepts_constant_range(bytes(statement), offset, expected)
        checks += 1
        covered_bits = 0
        for _, mask, _ in constrained_word_slices(offset, expected):
            covered_bits += mask.bit_count()
        assert covered_bits == len(expected) * 8
        for index in range(len(expected)):
            changed = bytearray(statement)
            changed[offset + index] ^= 1
            assert not accepts_constant_range(bytes(changed), offset, expected)
            checks += 1
    return checks


def differential_merkle_delta() -> int:
    rng = random.Random(0x4D45524B4C45)
    checks = 0
    for _ in range(4096):
        current = rng.getrandbits(64)
        sibling = rng.getrandbits(64)
        for mask in (0, MASK64):
            old_left_delta = mask & (current ^ sibling)
            old_right_delta = mask & (current ^ sibling)
            old = (current ^ old_left_delta, sibling ^ old_right_delta)
            delta = mask & (current ^ sibling)
            new = (current ^ delta, sibling ^ delta)
            assert new == old
            checks += 1
    return checks


def differential_balance_cache() -> int:
    rng = random.Random(0x42414C414E4345)
    checks = 0
    for _ in range(4096):
        value_be = rng.randbytes(8)
        selectors_be = [rng.randbytes(8) for _ in range(4)]
        cached_value = int.from_bytes(value_be, "big")
        cached_selectors = [int.from_bytes(selector, "big") for selector in selectors_be]
        for slot in range(4):
            old_value = int.from_bytes(value_be, "big")
            old_selector = int.from_bytes(selectors_be[slot], "big")
            assert (cached_value, cached_selectors[slot]) == (old_value, old_selector)
            checks += 1
    return checks


def build_report() -> dict[str, object]:
    # Original source mirror, as frozen by max-relation-geometry/static_geometry.py.
    original_attempted_nonkeccak = 16_576
    original_decode_and_transport = 3_074 + 8

    # Seven bytes are still extracted. Eleven 56-byte digests use seven unaligned
    # words at three operations each. Seven unaligned and one aligned BE u64 loads
    # cost 7*(3+11)+11, and the aligned BE u32 costs swap(11)+shift(1).
    optimized_decode = 7 * 2 + 11 * 7 * 3 + (7 * 14 + 11) + 12
    assert optimized_decode == 366
    # Existing trailing-word BAND and seven low-bool BANDs remain; the exact
    # magic/version/activation ranges add three partial-word BANDs.
    optimized_transport = 8 + 3
    assert optimized_transport == 11
    public_decode_cut = original_decode_and_transport - (
        optimized_decode + optimized_transport
    )
    assert public_decode_cut == 2_705

    # One shared delta removes one BXOR and one BAND per seven-word digest at
    # each of 32 levels for two independent input paths.
    merkle_delta_cut = 2 * 32 * 7 * 2
    assert merkle_delta_cut == 896

    # Balance formerly repeated 32 byte swaps. Pinned swap_bytes emits four
    # BANDs, five shifts/rotates, and two XORs: eleven output wires.
    balance_swap_cut = 32 * 11
    assert balance_swap_cut == 352

    attempted_cut = public_decode_cut + merkle_delta_cut + balance_swap_cut
    optimized_attempted_nonkeccak = original_attempted_nonkeccak - attempted_cut
    assert optimized_attempted_nonkeccak == 12_623

    declared_hidden = 114 + 671
    keccak_source_fax = 83 * 24 * 25
    raw_hidden = declared_hidden + keccak_source_fax + optimized_attempted_nonkeccak
    assert raw_hidden == 63_208

    # Direct decoding removes 77 digest-pack and nine numeric-decode leading
    # zero XORs. Three accumulator-byte packs remain. Frame and absorption folds
    # are unchanged.
    guaranteed_folds = 475 + 3 + 1_261
    assert guaranteed_folds == 1_739
    optimized_upper = raw_hidden - guaranteed_folds
    assert optimized_upper == 61_469

    original_upper = 65_336
    net_hidden_cut = original_upper - optimized_upper
    assert net_hidden_cut == 3_867
    active_symbols_upper = math.ceil(optimized_upper / 2)
    tail_symbols = (1 << 15) - active_symbols_upper
    assert (active_symbols_upper, tail_symbols) == (30_735, 2_033)

    return {
        "status": {
            "patch_applied": True,
            "applied_source_sha256": APPLIED_SOURCE_SHA256,
            "second_patch_applied": True,
            "third_patch_applied": True,
            "fourth_patch_applied": True,
            "compiled_exact": False,
            "scalar_equivalence": "finite differential plus algebraic identities",
            "frontier_promotable": False,
        },
        "differential_checks": {
            "public_decode": differential_public_decode(),
            "constant_ranges": differential_constant_ranges(),
            "merkle_delta": differential_merkle_delta(),
            "balance_cache": differential_balance_cache(),
        },
        "source_static_cost": {
            "original_conservative_hidden_words": original_upper,
            "direct_public_decode_net_attempted_cut_before_fold_adjustment": public_decode_cut,
            "merkle_duplicate_delta_cut": merkle_delta_cut,
            "balance_duplicate_swap_cut": balance_swap_cut,
            "removed_guaranteed_zero_folds": 86,
            "net_guaranteed_hidden_word_cut": net_hidden_cut,
            "optimized_conservative_hidden_words": optimized_upper,
            "optimized_active_b128_symbols_upper": active_symbols_upper,
            "optimized_n15_random_tail_symbols_lower": tail_symbols,
        },
        "capacity": {
            "conditional_required_b128_symbols": 1_060,
            "conditional_margin_b128_symbols": tail_symbols - 1_060,
            "full_required_b128_symbols": 1_984,
            "full_margin_b128_symbols": tail_symbols - 1_984,
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
