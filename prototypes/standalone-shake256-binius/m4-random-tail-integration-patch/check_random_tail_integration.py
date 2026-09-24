#!/usr/bin/env python3
"""Dependency-free source gate for the M4 random-tail integration patch.

This checker does not compile or prove.  It ratchets the exact post-stack Binius
source, checks that only whole unused B128 symbols are randomized, verifies that
the shift selector has zero support on that tail, and keeps the missing complete
linear-observation export explicit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


BASE_REVISION = "3f96163049f680b2909f6545690bd929f1b48c44"
COEFFICIENT_PATCH_SHA256 = "684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54"
GROUPED_PATCH_SHA256 = "37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df"
RANDOM_TAIL_PATCH_SHA256 = "0602c48f3cc7545186e625d033c3cefe4563431499977531e365144d12232c18"
DISK_GATE_KIB = 28 * 1024 * 1024
MAXIMUM_SOURCE_SHA256 = {
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs":
        "f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b",
    "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/main.rs":
        "d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c",
}

EXPECTED_SOURCE_SHA256 = {
    "crates/m4-prover/Cargo.toml": "e0e29eb246c9be17cc3d3f6149901f782230d01831e471cfc202fddf5a432aee",
    "crates/m4-prover/src/composite.rs": "1f898dc729de1b52cb4d91bdf14f5998da9b93ca80ba22c0e1651f64f34640c5",
    "crates/m4-prover/src/lib.rs": "12434d8abb12a12e01e502169ec5f4383a2ff1bcb85251b95292a8d7b0045244",
    "crates/prover/src/protocols/shift/segment_words.rs": "626441f3f35a016f7bf49311764bcb951949e4b259f160cd627c048fe8c2abed",
    "crates/prover/src/prove.rs": "6d189d39c4c5a985df7d361c65a80a2ee69ff55324ae697cf54417daf3181a9f",
    "crates/prover/src/protocols/shift/phase_1.rs": "238a8ae6a40e78558fd20c753c4a54521ab3c2757bee715dfe06a74b3061d698",
    "crates/prover/src/protocols/shift/monster.rs": "42a049c8e878f034e192190714f7c0d72b9aa1f728de8ed5ad2eee0bc837b3a5",
    "crates/prover/src/protocols/shift/phase_2.rs": "1dc4f1c3c24b58c49eacc8eb771b8ce391e18518f2b6c48044f91accda806d09",
    "crates/prover/src/ring_switch.rs": "8791a3999df1db67c43fc690bb85192834cda799fedc17e0e1b2e9c813c9119b",
    "crates/verifier/src/protocols/shift/verify.rs": "b494d8f2918957840e54a8dc5acc45ab7feadf22ccc2428d7b1be43855c3a864",
    "crates/core/src/constraint_system/system.rs": "5afc12a694e5049f8b77e6ce2cc91153108886a6ad451fecf63b6299664185c7",
    "crates/m4-verifier/src/composite.rs": "d8bcd73dd7c8f8afa829a2de29d4826f1043afdab6121a217597712585f473c0",
    "crates/m4-verifier/src/commit.rs": "a589e053baedcf3ce6bab4cb00ddf789829e2a29e6f5370971cdab4a156aa477",
    "crates/verifier/src/verify.rs": "0f00c727661b5754b1eecb812a0cbff57d918f84eaa5493330e3a8b328e033d1",
    "crates/iop-prover/src/basefold/compiler.rs": "d8745d8c10ea156c40b76056c37ae02b88891bbc9445644b136ba9d339d80d52",
    "crates/iop-prover/src/basefold/channel.rs": "421763597153dc5a62f376f260576c04069144c6d1c5474377c203acef38205e",
    "crates/iop-prover/src/fri/fold.rs": "e87ba42195e4450d5d7c91626e1f7cfc11272f52722bb71946e6141162f3aa67",
    "crates/iop-prover/src/fri/query.rs": "c5c8f55dd71944943162fd4c4bbbcb9d60e83df9da679ded650cbc131ccd9630",
    "crates/ip-prover/src/channel.rs": "bfd87a15821454ebcce44f10b3da5dc1ef3378750d921adb2146a7eda1b7718e",
    "crates/iop-prover/src/channel/mod.rs": "3d84ed4ea08e41c8f3ce9ba55c09a9c2a7a2d582c49d815c1574e32699fc8c11",
}

EXPECTED_PATCH_FILES = {
    "crates/m4-prover/Cargo.toml",
    "crates/m4-prover/src/composite.rs",
    "crates/m4-prover/src/lib.rs",
    "crates/prover/src/protocols/shift/segment_words.rs",
    "crates/prover/src/prove.rs",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def method_slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def changed_files(patch: str) -> set[str]:
    result = set()
    for line in patch.splitlines():
        if line.startswith("diff --git a/"):
            left = line.split()[2]
            require(left.startswith("a/"), "non-canonical patch path")
            result.add(left[2:])
    return result


def layout_kats() -> None:
    mask64 = (1 << 64) - 1
    for active_words in (2, 3, 5, 9, 14):
        total_symbols = 8
        active = [0x100 + index for index in range(active_words)]
        active_symbols = (active_words + 1) // 2
        draws = [
            ((index + 1) << 96) | ((index + 2) << 32) | index
            for index in range(total_symbols - active_symbols)
        ]

        words = list(active)
        if len(words) % 2:
            words.append(0)
        for value in draws:
            words.extend((value & mask64, value >> 64))

        require(len(words) == 2 * total_symbols, "wrong padded word length")
        require(words[:active_words] == active, "active word prefix changed")
        if active_words % 2:
            require(words[active_words] == 0, "partial active B128 symbol was randomized")

        packed = [words[2 * i] | (words[2 * i + 1] << 64) for i in range(total_symbols)]
        require(packed[active_symbols:] == draws, "tail B128 symbols are not exact RNG draws")

        # The Boolean-hypercube relation sum is independent of every randomized word when the
        # wiring/monster selector is zero outside the declared active prefix.
        selector = [index + 3 for index in range(active_words)] + [0] * (
            len(words) - active_words
        )
        alternate = words[:active_words] + [value ^ 0xDEADBEEF for value in words[active_words:]]
        lhs = sum(value * weight for value, weight in zip(words, selector, strict=True))
        rhs = sum(value * weight for value, weight in zip(alternate, selector, strict=True))
        require(lhs == rhs, "zero-tail selector independence failed")


def audit_tree(tree: Path) -> dict[str, object]:
    tree = tree.resolve()
    require(tree.is_dir(), f"tree is not a directory: {tree}")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tree,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    require(head == BASE_REVISION, f"wrong base revision: {head}")

    for relative, expected in EXPECTED_SOURCE_SHA256.items():
        actual = sha256_file(tree / relative)
        require(actual == expected, f"source hash mismatch: {relative}: {actual}")

    artifact_dir = Path(__file__).resolve().parent
    repo_root = artifact_dir.parents[2]
    coefficient_patch = artifact_dir.parent / "m4-zk-coefficient-mask-patch" / (
        "hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch"
    )
    grouped_patch = artifact_dir.parent / "m4-zk-grouped-relation-patch" / (
        "hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch"
    )
    random_tail_patch = artifact_dir / "hegemon-m4-random-tail-after-zk-stack-3f961630.patch"
    require(sha256_file(coefficient_patch) == COEFFICIENT_PATCH_SHA256, "coefficient patch drift")
    require(sha256_file(grouped_patch) == GROUPED_PATCH_SHA256, "grouped patch drift")
    require(sha256_file(random_tail_patch) == RANDOM_TAIL_PATCH_SHA256, "random-tail patch drift")
    patch_text = random_tail_patch.read_text()
    require(changed_files(patch_text) == EXPECTED_PATCH_FILES, "random-tail patch file scope drift")
    require("/verifier/" not in patch_text and "m4-verifier" not in patch_text, "verifier edited")

    for relative, expected in MAXIMUM_SOURCE_SHA256.items():
        actual = sha256_file(repo_root / relative)
        require(actual == expected, f"maximum relation source drift: {relative}: {actual}")

    prover = (tree / "crates/prover/src/prove.rs").read_text()
    random_method = method_slice(
        prover,
        "\tpub fn prove_with_random_trace_tail",
        "\n\t/// Computes the exact compiled random-tail geometry",
    )
    geometry_method = method_slice(
        prover,
        "\tpub fn random_trace_tail_geometry",
        "\n\t/// Shared prover body.",
    )
    shared_method = method_slice(
        prover,
        "\tfn prove_with_trace_words",
        "\n/// Exact runtime geometry",
    )
    require("mut rng: impl CryptoRng" in random_method, "tail RNG is not cryptographic")
    require("let value = rng.random::<u128>();" in random_method, "tail is not sampled as B128")
    require("for _ in active_symbols..total_symbols" in random_method, "random range drift")
    require("trace_words.push(Word::ZERO);" in random_method, "odd active symbol is not preserved")
    require("pack_witness::<P, _>(alloc, self.log_witness_elems, trace_words)?" in shared_method,
            "commitment does not use shared trace words")
    require("witness.public(),\n\t\t\ttrace_words," in shared_method,
            "shift reduction does not use shared trace words")
    require("witness.non_public(),\n\t\t\tOperatorClaims" not in shared_method,
            "shift reduction still uses zero-padded witness")
    require("witness.non_public().len() != self.constraint_system.n_private" in geometry_method,
            "active-prefix count is not exact")
    require("self.key_collection.hidden.n_words() != self.constraint_system.n_private" in geometry_method,
            "hidden key prefix is not exact")
    require("self.key_collection.log_witness_words() != trace_log_words" in geometry_method,
            "word-domain dimension mismatch is not rejected")
    require("active_symbols >= total_symbols" in geometry_method, "empty tail is not rejected")

    composite = (tree / "crates/m4-prover/src/composite.rs").read_text()
    high_method = method_slice(
        composite,
        "\tpub fn prove_main_with_random_trace_tail",
        "\n\t/// Exports the exact compiled active-prefix",
    )
    preflight = method_slice(
        composite,
        "\tpub fn random_trace_tail_geometry",
        "\n}\n\n#[cfg(test)]",
    )
    require(high_method.index("self.random_trace_tail_geometry(witness)?") <
            high_method.index("create_channel_without_zk_from_transcript"),
            "admission does not precede transcript creation")
    require("RANDOM_TAIL_LOG_TRACE_SYMBOLS: usize = 15" in composite, "n15 tier is not fixed")
    for anchor in (
        "!self.iop_prover.chips.is_empty()",
        "!witness.tables.is_empty()",
        "n_imul_constraints()",
        "specs.len() != 1",
        "spec.log_msg_len != RANDOM_TAIL_LOG_TRACE_SYMBOLS",
        "main.log_witness_elems() != spec.log_msg_len",
        "if spec.is_zk",
    ):
        require(anchor in preflight, f"missing fail-closed admission anchor: {anchor}")

    phase1 = (tree / "crates/prover/src/protocols/shift/phase_1.rs").read_text()
    monster = (tree / "crates/prover/src/protocols/shift/monster.rs").read_text()
    phase2 = (tree / "crates/prover/src/protocols/shift/phase_2.rs").read_text()
    verifier_shift = (tree / "crates/verifier/src/protocols/shift/verify.rs").read_text()
    constraint_system = (tree / "crates/core/src/constraint_system/system.rs").read_text()
    require(".zip(segment.key_ranges.par_iter())" in phase1, "phase-1 tail exclusion drift")
    require("values.resize(capacity, P::default());" in monster, "monster tail is not zero")
    require("P::wide_mul(hidden_i, monster_i)" in phase2, "phase-2 selector product drift")
    require("&hidden_tensor[..cs.n_private]" in verifier_shift, "verifier does not cut active prefix")
    require("the padding is unaddressable" in constraint_system, "padding addressability drift")
    require("term.value_index.index() as usize >= segment_len" in constraint_system,
            "out-of-range value index is not rejected")

    ring_switch = (tree / "crates/prover/src/ring_switch.rs").read_text()
    basefold = (tree / "crates/iop-prover/src/basefold/channel.rs").read_text()
    fri_fold = (tree / "crates/iop-prover/src/fri/fold.rs").read_text()
    ip_channel = (tree / "crates/ip-prover/src/channel.rs").read_text()
    require("channel.send_many(round_coeffs.clone().truncate().coeffs());" in phase2,
            "shift round observations moved")
    require("channel.send_one(witness_eval);" in phase2, "shift evaluation observation moved")
    require("channel.send_many(s_hat_v.as_ref());" in ring_switch, "ring-switch observations moved")
    require("channel.send_many(&alphas);" in basefold, "BaseFold alpha observations moved")
    require("let indices = (0..n_test_queries)" in fri_fold, "adaptive FRI schedule moved")
    require("query_prover.prove_queries(&indices, channel);" in fri_fold, "FRI queries moved")
    require("send_committed_vector(&terminal_commitment, terminate_codeword.to_ref())" in fri_fold,
            "FRI terminal observation moved")
    require("fn send_one(&mut self, elem: F);" in ip_channel, "channel send API drift")
    require("LinearObservation" not in ip_channel, "observation sink now exists; re-audit required")

    layout_kats()
    free_kib = shutil.disk_usage(tree).free // 1024
    return {
        "status": "SOURCE_STATIC_PASS",
        "base_revision": head,
        "prerequisite_patch_sha256": [COEFFICIENT_PATCH_SHA256, GROUPED_PATCH_SHA256],
        "patch_sha256": RANDOM_TAIL_PATCH_SHA256,
        "patch_files": sorted(EXPECTED_PATCH_FILES),
        "source_files_pinned": len(EXPECTED_SOURCE_SHA256),
        "maximum_source_unchanged": True,
        "trace_tier_log_symbols": 15,
        "active_prefix_exported": True,
        "random_tail_geometry_runtime_exact": True,
        "same_trace_buffer_committed_and_shifted": True,
        "selector_tail_zero_source_static": True,
        "verifier_dimensions_unchanged": True,
        "complete_linear_observation_union_exported": False,
        "observation_sink_required": True,
        "adaptive_bcs_zk_proved": False,
        "strict_commitment_digest_bytes_required_downstream": 64,
        "strict_commitment_digest_integrated_here": False,
        "compiled": False,
        "roundtrip": False,
        "complete_zk": False,
        "strict_security": False,
        "proof_bytes": None,
        "frontier_eligible": False,
        "free_disk_kib": free_kib,
        "cargo_admitted": free_kib >= DISK_GATE_KIB,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        print(json.dumps(audit_tree(args.tree), sort_keys=True))
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
