#!/usr/bin/env python3
"""Static, dependency-free audit for the source-only grouped-relation patch.

This checker never compiles or proves.  It verifies the frozen post-stack source,
the transcript-shape invariants that are visible in source, and two small algebra
identities used by the construction.
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
DISK_GATE_KIB = 28 * 1024 * 1024

EXPECTED_SOURCE_SHA256 = {
    "crates/iop-prover/src/basefold/channel.rs": "421763597153dc5a62f376f260576c04069144c6d1c5474377c203acef38205e",
    "crates/iop-prover/src/channel/mod.rs": "3d84ed4ea08e41c8f3ce9ba55c09a9c2a7a2d582c49d815c1574e32699fc8c11",
    "crates/iop-prover/src/channel/naive.rs": "ceb68818b8865b5486d14f3a5d3a4f96a91e9dec522ade48b473ed922341ae7c",
    "crates/iop/src/basefold/channel.rs": "0c453bc7eaf4221d68bbf2dc9cd435d037e685fa8ea4e474473f40fb0c6ff23c",
    "crates/iop/src/channel/mod.rs": "83d4bb193644aa174ca117ef25618e25eb6062e31d6a36ddbff7e44a00a59fe0",
    "crates/iop/src/channel/naive.rs": "af24bcd424fd1b95b9404cd5aeced91204ee0aa21b9409e3c9ea5f013cbd7341",
    "crates/iop/src/channel/oracle_setup.rs": "26a5f18b2cbf7913aa865692a4f3cf3db6d37e626e11157d3f7025181f8c1609",
    "crates/ip-prover/src/sumcheck/grouped.rs": "98cc606cda2cb504ee712eac1c5c9b96fc45f2f06a94b645791604285d249c08",
    "crates/ip-prover/src/sumcheck/mod.rs": "72a1f1ca2575bda7569ef64e8b980a5566edd38653f5d0e9e03178569e27a721",
    "crates/spartan-prover/src/lib.rs": "26a74e1c5efa8c060b1d12aa4541adaca2f9d80ae1d4d9ce2a93ab00d90385f9",
    "crates/spartan-prover/src/wrapper/replay_channel.rs": "1f4f87662d3e2419b863f28c73cc152d034341fee5d8ba373a49768d406ee32b",
    "crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs": "f96c0064eb1a5ebc4161586ef5fa3b81dfb086cf06af177f38c60ee618126c15",
    "crates/spartan-verifier/src/lib.rs": "bf0f323c8ca78ea0e965cc1c46e5a0a0b7e823d5cfde70b7941feb92888fcf7d",
    "crates/spartan-verifier/src/wrapper/builder_channel.rs": "e6ba3619104cd9cc64882dc175fe276d4c55fca2cade903242375b9c4ccf1e39",
    "crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs": "c26df74c909130b908a2602648ffae0a415494d9de8beb5b1756c23cfe705175",
}

PHASE_B_SHA256 = {
    "crates/iop-prover/src/basefold/channel.rs": "5574d4f4077f5ce57900834bbebd861f6e1a5c4f81dc9864d83909a78871b5fe",
    "crates/iop/src/basefold/channel.rs": "8c44d38b32a51db49505d3a3e3973aea9aa327374adf4a750ea617adeefeaab0",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def method_slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def phase_b_slice(source: str) -> bytes:
    begin = source.index("\t// === Phase B:")
    finish = source.index("\nfn batch_relations_per_oracle", begin)
    return source[begin:finish].encode()


def mle_eval(values: list[int], point: list[int], modulus: int) -> int:
    work = [value % modulus for value in values]
    for challenge in point:
        require(len(work) % 2 == 0, "multilinear table length must stay even")
        work = [
            (work[2 * index] * (1 - challenge) + work[2 * index + 1] * challenge)
            % modulus
            for index in range(len(work) // 2)
        ]
    require(len(work) == 1, "evaluation must consume the complete table")
    return work[0]


def algebra_kats() -> None:
    # Use an ordinary prime field only as an independent linear-algebra check.  The Rust patch is
    # field-generic; this is not a security or implementation test.
    modulus = 65_537
    gamma = 31_337
    key = [3, 5, 8, 13]
    private = [21, 34, 55, 89]
    key_mask = [144, 233, 377, 610]
    private_mask = [987, 1_597, 2_584, 4_181]
    t_precommit = [2, 7, 1, 8]
    t_private = [2, 8, 1, 8]

    def inner_product(left: list[int], right: list[int]) -> int:
        return sum(a * b for a, b in zip(left, right, strict=True)) % modulus

    total = (inner_product(key, t_precommit) + inner_product(private, t_private)) % modulus
    sigma = (
        inner_product(key_mask, t_precommit) + inner_product(private_mask, t_private)
    ) % modulus
    masked_key = [
        ((1 - gamma) * value + gamma * mask) % modulus
        for value, mask in zip(key, key_mask, strict=True)
    ]
    masked_private = [
        ((1 - gamma) * value + gamma * mask) % modulus
        for value, mask in zip(private, private_mask, strict=True)
    ]
    masked_total = (
        inner_product(masked_key, t_precommit)
        + inner_product(masked_private, t_private)
    ) % modulus
    expected = ((1 - gamma) * total + gamma * sigma) % modulus
    require(masked_total == expected, "aggregate sigma/shared-gamma identity failed")

    short_table = [11, 17, 23, 29]
    point = [101, 103, 107, 109]
    padded_table = short_table + [0] * 12
    short_eval = mle_eval(short_table, point[:2], modulus)
    padding_factor = ((1 - point[2]) * (1 - point[3])) % modulus
    require(
        mle_eval(padded_table, point, modulus) == short_eval * padding_factor % modulus,
        "per-oracle zero-padding identity failed",
    )


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
    coefficient_patch = artifact_dir.parent / "m4-zk-coefficient-mask-patch" / (
        "hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch"
    )
    grouped_patch = artifact_dir / "hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch"
    require(sha256_file(coefficient_patch) == COEFFICIENT_PATCH_SHA256, "coefficient patch drift")
    require(sha256_file(grouped_patch) == GROUPED_PATCH_SHA256, "grouped patch drift")

    prover = (tree / "crates/spartan-prover/src/lib.rs").read_text()
    verifier = (tree / "crates/spartan-verifier/src/lib.rs").read_text()
    require("precommit_claim" not in prover + verifier, "component precommit claim still exists")
    require(prover.count("channel.prove_grouped_oracle_relation(") == 1, "wrong prover group count")
    require(
        verifier.count("channel.verify_grouped_oracle_relation(") == 1,
        "wrong verifier group count",
    )
    require("let secret_wiring_claim = batched_sum - public_eval;" in prover, "wrong prover total")
    require("let secret_wiring_claim = batched_sum - public_eval;" in verifier, "wrong verifier total")
    require(
        "prove_oracle_relation(\n\t\t\tprecommit_oracle" not in prover,
        "precommit term was decomposed on prover",
    )
    require(
        "verify_oracle_relation(precommit_oracle" not in verifier,
        "precommit term was decomposed on verifier",
    )

    basefold_prover = (tree / "crates/iop-prover/src/basefold/channel.rs").read_text()
    basefold_verifier = (tree / "crates/iop/src/basefold/channel.rs").read_text()
    require(".sum::<F>()" in basefold_prover, "group sigma is not summed")
    require("let gamma = channel.sample();" in basefold_prover, "shared gamma is absent")
    require("let n_zk_relations" in basefold_verifier, "verifier still prices per-oracle sigmas")
    require("max_n - n_i" in basefold_prover, "native-size padding is absent")
    require("let pad_eq = eq_ind_zero(padding_coords);" in basefold_verifier, "padding factor absent")
    require("alphas[oracle_index].replace(alpha).is_none()" in basefold_prover, "alpha uniqueness absent")
    require(
        "a grouped oracle may not also carry ordinary relations" in basefold_prover
        and "a grouped oracle may not also carry ordinary relations" in basefold_verifier,
        "ordinary/grouped overlap is not rejected",
    )

    for relative, expected in PHASE_B_SHA256.items():
        actual = sha256_bytes(phase_b_slice((tree / relative).read_text()))
        require(actual == expected, f"Phase B drift: {relative}: {actual}")

    wrapper_prover = (tree / "crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs").read_text()
    wrapper_verifier = (tree / "crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs").read_text()
    builder = (tree / "crates/spartan-verifier/src/wrapper/builder_channel.rs").read_text()
    replay = (tree / "crates/spartan-prover/src/wrapper/replay_channel.rs").read_text()
    prover_group = method_slice(
        wrapper_prover,
        "\tfn prove_grouped_oracle_relation(",
        "\n\tfn prove_oracle_evaluation_relation(",
    )
    verifier_group = method_slice(
        wrapper_verifier,
        "\tfn verify_grouped_oracle_relation(",
        "\n\tfn verify_oracle_evaluation_relation(",
    )
    builder_group = method_slice(
        builder,
        "\tfn verify_grouped_oracle_relation(",
        "\n\tfn verify_oracle_evaluation_relation(",
    )
    replay_group = method_slice(
        replay,
        "\tfn verify_grouped_oracle_relation(",
        "\n\tfn verify_oracle_evaluation_relation(",
    )
    require(prover_group.count("send_one(claim)") == 1, "prover bridge is not one aggregate")
    require(prover_group.count("interaction.push(claim)") == 1, "aggregate replay event mismatch")
    require("prove_grouped_oracle_relation(terms, claim)" in prover_group, "group not forwarded")
    require(verifier_group.count("recv_one()?") == 1, "verifier bridge is not one aggregate")
    require("verify_grouped_oracle_relation(native_terms, decrypted_value)" in verifier_group, "verifier group not forwarded")
    require(builder_group.count("alloc_inout_elem()") == 1, "builder aggregate allocation mismatch")
    require(replay_group.count("next_inout_elem()") == 1, "replay aggregate allocation mismatch")

    algebra_kats()
    free_kib = shutil.disk_usage(tree).free // 1024
    return {
        "status": "SOURCE_STATIC_PASS",
        "base_revision": head,
        "profile_scope": "field_generic_API_B128_weak_profile_evidence_only",
        "patch_sha256": GROUPED_PATCH_SHA256,
        "source_files_pinned": len(EXPECTED_SOURCE_SHA256),
        "phase_b_unchanged": True,
        "aggregate_bridge_scalars": 1,
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
