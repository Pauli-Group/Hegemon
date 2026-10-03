#!/usr/bin/env python3
"""Fail-closed joint-simulator/rank audit for the coefficient-aware M4 ZK patch.

This program deliberately separates three claims:

* exact linear algebra over the pinned GHASH field;
* source-level protocol-class inventory; and
* unproved computational/statistical simulator obligations.

It never promotes CompleteZK.  A successful process exit means that the audit ran
and its fail-closed rejection was internally consistent, not that the backend is ZK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence


FIELD_BITS = 128
FIELD_ORDER = 1 << FIELD_BITS
FIELD_MASK = FIELD_ORDER - 1
# x^128 + x^7 + x^2 + x + 1, in low-coefficient-first integer form.
GHASH_REDUCTION = 0x87
GHASH_MODULUS = (1 << 128) | GHASH_REDUCTION
PINNED_REVISION = "3f96163049f680b2909f6545690bd929f1b48c44"
PINNED_PATCH_SHA256 = "684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54"
EXPECTED_M4_SOURCE_SHA256 = "67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91"

REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_DIR = Path(__file__).resolve().parent
PATCH_PATH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-zk-coefficient-mask-patch"
    / "hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch"
)
M4_SOURCE_PATH = (
    REPO_ROOT
    / "prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs"
)
DEFAULT_PINNED_CHECKOUT = Path("/private/tmp/hegemon-zk-structural-patch")


PINNED_SOURCE_HASHES = {
    "crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs":
        "3f8a6e676a80a2766716c3f89591f80a218fd4e33d06d26acf81b80fa907ec74",
    "crates/spartan-prover/src/lib.rs":
        "4769dc62a593d1daa0ad3e801e1b3eeb31c560a51fcfcee490a7bb1b17e6084e",
    "crates/iop-prover/src/basefold/channel.rs":
        "16791256670354bf23825e2757a2781034401ee4a661179e74724af44b9a0eda",
    "crates/iop/src/basefold/channel.rs":
        "34e8d86f187f22e9ef2884ccbe3062932ee5b2829d7c6a91bff94c5eb7066db9",
    "crates/ip-prover/src/sumcheck/zk_mlecheck.rs":
        "3f9a53d04ddc0d5c257dddc1456c83251b807c06da30a5c0d2a5a1d537738d93",
    "crates/m4-prover/src/prove.rs":
        "5827181784975cc58e91d56344bd316c106eb75381e624c86c6fba47bfa3a086",
    "crates/m4-verifier/src/verify.rs":
        "3e4bae5dc866394a60d21fa148427766ada37cf24e44b12e622d7b3d15a637b4",
    "crates/spartan-verifier/src/wrapper/builder_channel.rs":
        "ebe1e6e6b741fd2e9c0ea5f83e2428bfd646eadc4a21803e659e1a0fa7141912",
    "crates/spartan-prover/src/wrapper/replay_channel.rs":
        "6c7f4aec2b78c31e9fe2d7817bca843e95d423b71d56832ce8968796e5ba98d0",
}


def gf_add(left: int, right: int) -> int:
    return left ^ right


def gf_mul(left: int, right: int) -> int:
    """Multiply in B128 = GF(2)[X]/(X^128+X^7+X^2+X+1)."""
    left &= FIELD_MASK
    right &= FIELD_MASK
    product = 0
    for _ in range(FIELD_BITS):
        if right & 1:
            product ^= left
        carry = left >> 127
        left = (left << 1) & FIELD_MASK
        if carry:
            left ^= GHASH_REDUCTION
        right >>= 1
    return product


def gf_pow(value: int, exponent: int) -> int:
    result = 1
    base = value & FIELD_MASK
    while exponent:
        if exponent & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exponent >>= 1
    return result


def gf_inv(value: int) -> int:
    if value == 0:
        raise ZeroDivisionError("zero has no inverse in B128")
    return gf_pow(value, FIELD_ORDER - 2)


def gf_div(numerator: int, denominator: int) -> int:
    return gf_mul(numerator, gf_inv(denominator))


def gf_dot(left: Sequence[int], right: Sequence[int]) -> int:
    if len(left) != len(right):
        raise ValueError("dot-product length mismatch")
    result = 0
    for x, y in zip(left, right, strict=True):
        result ^= gf_mul(x, y)
    return result


def gf_sum(values: Iterable[int]) -> int:
    result = 0
    for value in values:
        result ^= value
    return result


def rank(matrix: Sequence[Sequence[int]]) -> int:
    """Exact Gaussian rank over B128."""
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("ragged matrix")
    work = [[value & FIELD_MASK for value in row] for row in matrix]
    pivot_row = 0
    for column in range(width):
        pivot = next((row for row in range(pivot_row, len(work)) if work[row][column]), None)
        if pivot is None:
            continue
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        inverse = gf_inv(work[pivot_row][column])
        work[pivot_row] = [gf_mul(value, inverse) for value in work[pivot_row]]
        for row in range(len(work)):
            if row == pivot_row or work[row][column] == 0:
                continue
            factor = work[row][column]
            work[row] = [
                value ^ gf_mul(factor, pivot_value)
                for value, pivot_value in zip(work[row], work[pivot_row], strict=True)
            ]
        pivot_row += 1
        if pivot_row == len(work):
            break
    return pivot_row


def columns_contained(
    witness_matrix: Sequence[Sequence[int]], mask_matrix: Sequence[Sequence[int]]
) -> tuple[bool, int, int]:
    """Return whether col(W) is contained in col(R), plus the two ranks."""
    if len(witness_matrix) != len(mask_matrix):
        raise ValueError("W and R observation counts differ")
    if not witness_matrix:
        return True, 0, 0
    combined = [
        list(mask_row) + list(witness_row)
        for mask_row, witness_row in zip(mask_matrix, witness_matrix, strict=True)
    ]
    mask_rank = rank(mask_matrix)
    combined_rank = rank(combined)
    return mask_rank == combined_rank, mask_rank, combined_rank


@dataclass
class LinearView:
    witness_names: list[str]
    mask_names: list[str]
    observation_names: list[str] = field(default_factory=list)
    witness_rows: list[list[int]] = field(default_factory=list)
    mask_rows: list[list[int]] = field(default_factory=list)

    def add(
        self,
        name: str,
        witness: dict[str, int] | None = None,
        masks: dict[str, int] | None = None,
    ) -> None:
        witness = witness or {}
        masks = masks or {}
        unknown_witness = set(witness) - set(self.witness_names)
        unknown_masks = set(masks) - set(self.mask_names)
        if unknown_witness or unknown_masks:
            raise ValueError(f"unknown variables: witness={unknown_witness}, masks={unknown_masks}")
        self.observation_names.append(name)
        self.witness_rows.append([witness.get(var, 0) for var in self.witness_names])
        self.mask_rows.append([masks.get(var, 0) for var in self.mask_names])

    def containment(self) -> tuple[bool, int, int]:
        return columns_contained(self.witness_rows, self.mask_rows)


def deterministic_field(label: str) -> int:
    return int.from_bytes(hashlib.shake_256(label.encode("utf-8")).digest(16), "little")


def selected_non_one(label: str) -> int:
    first = deterministic_field(label + ":first")
    second = deterministic_field(label + ":second")
    if first != 1:
        return first
    if second != 1:
        return second
    raise RuntimeError("fixed-shape paired sampler exhausted")


def accepted_coefficient(label: str, coordinates: int = 7) -> tuple[list[int], int]:
    challenges = [selected_non_one(f"{label}:r:{index}") for index in range(coordinates)]
    coefficient = 1
    for challenge in challenges:
        coefficient = gf_mul(coefficient, challenge ^ 1)
    if coefficient == 0:
        raise AssertionError("non-one coordinates must give nonzero c in a field")
    return challenges, coefficient


def transparent_coefficients(label: str, length: int, coefficient: int) -> list[int]:
    if length < 1:
        raise ValueError("transparent length must be positive")
    values = [deterministic_field(f"{label}:a:{index}") for index in range(length - 1)]
    values.append(coefficient ^ gf_sum(values))
    if gf_sum(values) != coefficient:
        raise AssertionError("transparent coefficients do not sum to c")
    return values


def build_joint_view(
    transparent: Sequence[int],
    coefficient: int,
    n_messages: int,
    *,
    include_oracle_masks: bool = True,
    clear_claim_key_rows: Sequence[Sequence[int]] = (),
    claim_blinder_rows: Sequence[Sequence[int]] = (),
) -> LinearView:
    """Build the linearized trace/OTP/clear-claim view.

    `clear_claim_key_rows` has one row per clear functional over
    `[k_trace, k_msg_0, ...]`. `claim_blinder_rows` has the same number of rows
    and one column per fresh, otherwise-unused repair blinder.
    """
    if gf_sum(transparent) != coefficient:
        raise ValueError("trace transparent must sum to coefficient")
    if clear_claim_key_rows and len(clear_claim_key_rows) != len(claim_blinder_rows):
        raise ValueError("claim key/blinder row count mismatch")
    n_keys = 1 + n_messages
    if any(len(row) != n_keys for row in clear_claim_key_rows):
        raise ValueError("clear-claim key width mismatch")
    n_blinders = len(claim_blinder_rows[0]) if claim_blinder_rows else 0
    if any(len(row) != n_blinders for row in claim_blinder_rows):
        raise ValueError("ragged claim blinder matrix")

    witness_names = [f"trace_{i}" for i in range(len(transparent))]
    witness_names += [f"message_{i}" for i in range(n_messages)]
    mask_names = ["k_trace"] + [f"k_message_{i}" for i in range(n_messages)]
    if include_oracle_masks:
        mask_names += [f"omega_trace_{i}" for i in range(len(transparent))]
    mask_names += [f"claim_blinder_{i}" for i in range(n_blinders)]
    view = LinearView(witness_names, mask_names)

    # Idealized joint PCS view: a fresh vector mask accompanies the constant trace shift.
    # This is an algebraic envelope, not a proof that the concrete BaseFold transcript realizes it.
    for index in range(len(transparent)):
        masks = {"k_trace": 1}
        if include_oracle_masks:
            masks[f"omega_trace_{index}"] = 1
        view.add(f"shifted_trace_coordinate_{index}", {f"trace_{index}": 1}, masks)

    view.add(
        "masked_trace_claim_M",
        {f"trace_{i}": value for i, value in enumerate(transparent)},
        {"k_trace": coefficient} if coefficient else {},
    )
    for index in range(n_messages):
        view.add(
            f"otp_ciphertext_{index}",
            {f"message_{index}": 1},
            {f"k_message_{index}": 1},
        )

    for claim_index, (key_row, blinder_row) in enumerate(
        zip(clear_claim_key_rows, claim_blinder_rows, strict=True)
    ):
        masks = {"k_trace": key_row[0]}
        masks.update(
            {
                f"k_message_{index}": key_row[index + 1]
                for index in range(n_messages)
                if key_row[index + 1]
            }
        )
        masks.update(
            {
                f"claim_blinder_{index}": blinder_row[index]
                for index in range(n_blinders)
                if blinder_row[index]
            }
        )
        view.add(f"outer_precommit_clear_claim_{claim_index}", {}, masks)
    return view


def build_key_reuse_view() -> LinearView:
    view = LinearView(["message_0", "message_1"], ["reused_key"])
    view.add("ciphertext_0", {"message_0": 1}, {"reused_key": 1})
    view.add("ciphertext_1", {"message_1": 1}, {"reused_key": 1})
    return view


def build_basefold_scalar_view(
    relation: Sequence[int], evaluation: Sequence[int], gamma: int
) -> LinearView:
    """Linear core of one BaseFold mask-inner-product/evaluation pair.

    The view contains sigma=<omega,T> and alpha=<((1-gamma)x+gamma*omega),D>.
    Concrete sumcheck/FRI reveals less structured data, so this is only a rank diagnostic.
    """
    if len(relation) != len(evaluation):
        raise ValueError("BaseFold vectors have different lengths")
    view = LinearView(
        [f"oracle_{i}" for i in range(len(relation))],
        [f"basefold_mask_{i}" for i in range(len(relation))],
    )
    view.add(
        "basefold_mask_inner_product_sigma",
        {},
        {f"basefold_mask_{i}": value for i, value in enumerate(relation)},
    )
    view.add(
        "basefold_reduced_evaluation_alpha",
        {
            f"oracle_{i}": gf_mul(1 ^ gamma, value)
            for i, value in enumerate(evaluation)
        },
        {
            f"basefold_mask_{i}": gf_mul(gamma, value)
            for i, value in enumerate(evaluation)
        },
    )
    return view


def constructive_joint_mask_check(
    transparent: Sequence[int],
    coefficient: int,
    trace_delta: Sequence[int],
    message_delta: Sequence[int],
    *,
    claim_key_coefficients: Sequence[int] | None = None,
    claim_blinder_coefficient: int | None = None,
) -> bool:
    """Construct masks cancelling an arbitrary witness difference.

    This is the universal proof witness behind the rank check. It works for every
    input when c!=0 and, when a clear claim is present, d!=0.
    """
    if coefficient == 0:
        return False
    if len(transparent) != len(trace_delta):
        raise ValueError("trace delta length mismatch")
    k_trace_delta = gf_div(gf_dot(transparent, trace_delta), coefficient)
    omega_delta = [delta ^ k_trace_delta for delta in trace_delta]
    otp_delta = list(message_delta)

    shifted_ok = all(
        trace_delta[i] ^ k_trace_delta ^ omega_delta[i] == 0
        for i in range(len(trace_delta))
    )
    claim_ok = gf_dot(transparent, trace_delta) ^ gf_mul(coefficient, k_trace_delta) == 0
    otp_ok = all(delta ^ key_delta == 0 for delta, key_delta in zip(message_delta, otp_delta))
    if not (shifted_ok and claim_ok and otp_ok):
        return False

    if claim_key_coefficients is None:
        return True
    key_deltas = [k_trace_delta] + otp_delta
    clear_shift = gf_dot(claim_key_coefficients, key_deltas)
    if claim_blinder_coefficient is None or claim_blinder_coefficient == 0:
        return clear_shift == 0
    h_delta = gf_div(clear_shift, claim_blinder_coefficient)
    return clear_shift ^ gf_mul(claim_blinder_coefficient, h_delta) == 0


INVENTORY = [
    {
        "id": "PUBLIC_CONTEXT",
        "phase": "context",
        "message": "statement and transcript preamble",
        "witness_dependency": "public_only",
        "protection": "none_required",
        "multiplicity": "fixed by 912-byte transport and wrapper context",
    },
    {
        "id": "COMMIT_K",
        "phase": "pre_challenge",
        "message": "Merkle commitment to outer precommit K",
        "witness_dependency": "mask_only_but_later_correlated",
        "protection": "BaseFold is_zk vector mask",
        "multiplicity": "one oracle",
    },
    {
        "id": "COMMIT_SHIFTED_TRACE",
        "phase": "pre_challenge",
        "message": "commitment to pi + k_trace*1",
        "witness_dependency": "direct",
        "protection": "constant shift plus independent BaseFold vector mask",
        "multiplicity": "one and first/only inner oracle",
    },
    {
        "id": "INNER_PRIVATE_FIELD_STREAM",
        "phase": "inner_m4",
        "message": "every send_one/send_many field message E_j=m_j+k_j",
        "witness_dependency": "direct_or_derived",
        "protection": "fresh precommitted OTP per scalar",
        "multiplicity": "symbolic; exact count requires compiled 83-Keccak wrapper",
    },
    {
        "id": "INNER_PUBLIC_CLAIM_STREAM",
        "phase": "inner_m4",
        "message": "send_public_claim values",
        "witness_dependency": "declared_public_by_call_site",
        "protection": "clear; semantic classification must be audited",
        "multiplicity": "symbolic",
    },
    {
        "id": "MASKED_TRACE_CLAIM",
        "phase": "inner_ring_switch",
        "message": "M=s+k_trace*c",
        "witness_dependency": "direct",
        "protection": "rank-one mask with fixed-shape c!=0 sampler",
        "multiplicity": "exactly one",
    },
    {
        "id": "OUTER_PRIVATE_COMMITMENT",
        "phase": "outer_spartan",
        "message": "commitment to replay/private witness",
        "witness_dependency": "direct",
        "protection": "BaseFold is_zk vector mask and Spartan blinding",
        "multiplicity": "one oracle",
    },
    {
        "id": "OUTER_LIBRA_MASK_COMMITMENT",
        "phase": "outer_spartan",
        "message": "commitment to random Libra coefficients",
        "witness_dependency": "mask_only",
        "protection": "BaseFold is_zk vector mask",
        "multiplicity": "one oracle",
    },
    {
        "id": "OUTER_LIBRA_TRANSCRIPT",
        "phase": "outer_spartan",
        "message": "mask_eval, batched round coefficients, mask_eval_out",
        "witness_dependency": "joint witness_and_mask",
        "protection": "Libra masking; theorem and zero-batch-challenge case open",
        "multiplicity": "depends on compiled outer constraint tier",
    },
    {
        "id": "OUTER_ENDPOINT_EVALUATIONS",
        "phase": "outer_spartan",
        "message": "a_eval, b_eval, c_eval",
        "witness_dependency": "direct_linear_evaluations",
        "protection": "claimed Spartan dummy/blinding distribution; simulator open",
        "multiplicity": "three scalars",
    },
    {
        "id": "OUTER_PRECOMMIT_CLEAR_CLAIM",
        "phase": "outer_spartan",
        "message": "precommit_claim=<K,T_K>",
        "witness_dependency": "mask_only_in_isolation_but_correlated_with_OTP_stream",
        "protection": "none in frozen patch",
        "multiplicity": "one direct precommit-oracle functional",
    },
    {
        "id": "BASEFOLD_MASK_INNER_PRODUCTS",
        "phase": "combined_basefold",
        "message": "sigma_i=<omega_i,T_i> for every is_zk oracle",
        "witness_dependency": "mask_only_but_jointly_correlated",
        "protection": "must be handled by joint BaseFold simulator",
        "multiplicity": "one per ZK oracle after relation batching",
    },
    {
        "id": "BASEFOLD_MASKED_SUMCHECK",
        "phase": "combined_basefold",
        "message": "masked sumcheck rounds and alpha_i evaluations",
        "witness_dependency": "joint witness_and_mask",
        "protection": "gamma folding; gamma=0 and dependent-functional cases not gated",
        "multiplicity": "one alpha per committed oracle plus tier-dependent rounds",
    },
    {
        "id": "FRI_FOLD_COMMITMENTS",
        "phase": "combined_fri",
        "message": "fold-round roots and terminal committed vector",
        "witness_dependency": "joint witness_and_mask",
        "protection": "joint PCS/FRI simulator required",
        "multiplicity": "parameter-dependent",
    },
    {
        "id": "MERKLE_QUERY_OPENINGS",
        "phase": "combined_fri",
        "message": "queried leaves, fold cosets, and authentication nodes",
        "witness_dependency": "joint witness_and_mask",
        "protection": "query-conditioned BaseFold/FRI hiding theorem required",
        "multiplicity": "parameter-dependent",
    },
]


RESIDUAL_ASSUMPTIONS = [
    {
        "id": "A_SOURCE_MULTIPLICITY",
        "status": "OPEN",
        "statement": "Compile the 83-Keccak maximum relation and extract exact event multiplicities and one-oracle rank.",
    },
    {
        "id": "A_PUBLIC_CLAIM_CLASSIFICATION",
        "status": "OPEN",
        "statement": "Prove every send_public_claim call is a function only of public input and prior public challenges.",
    },
    {
        "id": "A_BASEFOLD_JOINT_SIMULATOR",
        "status": "OPEN",
        "statement": "Prove a multi-oracle simulator for commitments, sigma_i, gamma folding, sumcheck, alpha_i, FRI, and Merkle queries with correlated K and shifted trace.",
    },
    {
        "id": "A_BASEFOLD_DEGENERACIES",
        "status": "OPEN",
        "statement": "Account for gamma=0 and linearly dependent mask/evaluation functionals or add fixed-shape gates and a composed bound.",
    },
    {
        "id": "A_OUTER_SPARTAN_SIMULATOR",
        "status": "OPEN",
        "statement": "Prove Libra round masking, endpoint-evaluation hiding, dummy-wire blinding, and precommit/private/mask oracle composition.",
    },
    {
        "id": "A_PRECOMMIT_REPAIR_REALIZATION",
        "status": "OPEN",
        "statement": "Implement and prove the grouped precommit+private BaseFold relation, or implement an unused blinder coordinate and prove d nonzero before using the rank-one fallback.",
    },
    {
        "id": "A_ABORT_ROM_QROM",
        "status": "OPEN",
        "statement": "Prove abort-conditioned fixed-shape paired challenge selection in ROM and QROM.",
    },
    {
        "id": "A_NONLINEAR_COMPOSITION",
        "status": "OPEN",
        "statement": "Lift linear mask-span closure to the nonlinear verifier and simulator distribution without selective-failure leakage.",
    },
    {
        "id": "A_E384_STRICT_BACKEND",
        "status": "OPEN",
        "statement": "Realize the mixed B128/E384 IOP and compose strict PQ128 soundness and ZK bounds.",
    },
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_sources(pinned_checkout: Path | None) -> dict:
    checks: list[dict] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    patch_hash = sha256_file(PATCH_PATH)
    record("frozen_patch_sha256", patch_hash == PINNED_PATCH_SHA256, patch_hash)
    m4_hash = sha256_file(M4_SOURCE_PATH)
    record("m4_source_sha256", m4_hash == EXPECTED_M4_SOURCE_SHA256, m4_hash)
    m4_source = M4_SOURCE_PATH.read_text(encoding="utf-8")
    record(
        "m4_fixed_83_keccak",
        "fn fixed_geometry_is_eighty_three_keccak_permutations()" in m4_source
        and "assert_eq!(common + multiplexed_auth, 83);" in m4_source,
        "source-level geometry assertion",
    )
    record(
        "m4_one_main_no_chip",
        "circuit.chips.is_empty()" in m4_source and "build_full_m4" in m4_source,
        "source-level one-main gate",
    )

    checkout_present = pinned_checkout is not None and pinned_checkout.is_dir()
    if checkout_present:
        for relative, expected_hash in PINNED_SOURCE_HASHES.items():
            path = pinned_checkout / relative
            observed = sha256_file(path) if path.is_file() else "missing"
            record(f"pinned_source:{relative}", observed == expected_hash, observed)

        spartan = (pinned_checkout / "crates/spartan-prover/src/lib.rs").read_text(
            encoding="utf-8"
        )
        wrapper = (
            pinned_checkout
            / "crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs"
        ).read_text(encoding="utf-8")
        basefold = (
            pinned_checkout / "crates/iop-prover/src/basefold/channel.rs"
        ).read_text(encoding="utf-8")
        libra = (
            pinned_checkout / "crates/ip-prover/src/sumcheck/zk_mlecheck.rs"
        ).read_text(encoding="utf-8")
        record(
            "one_direct_precommit_clear_functional",
            spartan.count("channel.send_one(precommit_claim);") == 1
            and spartan.count("precommit_oracle.clone()") == 1,
            "one clear claim and one queued precommit relation in IOPProver::prove",
        )
        required_wrapper_patterns = [
            "let encrypted = elem + key;",
            "let masked_claim = claim + state.key * mask_coefficient;",
            "self.next_key_idx,\n\t\t\tself.keys.len()",
            "evaluation masking supports exactly one inner oracle",
            "the evaluation-mask key must be the first precommitted key",
        ]
        record(
            "wrapper_fail_closed_anchors",
            all(pattern in wrapper for pattern in required_wrapper_patterns),
            "fresh OTP, M=s+k*c, complete key consumption, one masked oracle",
        )
        record(
            "basefold_joint_view_anchors",
            all(
                pattern in basefold
                for pattern in [
                    "channel.send_many(&sigmas);",
                    "let gamma = channel.sample();",
                    "channel.send_many(&alphas);",
                    "prove_mlecheck_basefold(",
                ]
            ),
            "sigma, gamma, alpha, and combined FRI are all present",
        )
        record(
            "basefold_phase_a_is_per_oracle_not_grouped",
            "let provers = izip!(relations, &messages, oracle_specs)" in basefold
            and "expects at least one relation per committed oracle" in basefold,
            "a grouped precommit+private relation requires a Phase-A queue/prover refactor",
        )
        record(
            "outer_libra_anchors",
            all(
                pattern in libra
                for pattern in [
                    "channel.send_one(mask_eval);",
                    "channel.send_many(mlecheck::RoundProof::truncate(batched_round_coeffs).coeffs());",
                    "channel.send_one(mask_eval_out);",
                ]
            ),
            "outer mask evaluation and batched round stream",
        )
    else:
        record(
            "pinned_checkout_available",
            False,
            "optional patched checkout absent; patch identity checked but source anchors not re-read",
        )

    return {
        "all_passed": all(item["passed"] for item in checks),
        "pinned_checkout_present": checkout_present,
        "checks": checks,
        "patch_sha256": patch_hash,
        "m4_source_sha256": m4_hash,
    }


def scenario_result(view: LinearView, expected: bool) -> dict:
    contained, mask_rank, combined_rank = view.containment()
    return {
        "contained": contained,
        "expected": expected,
        "expectation_met": contained == expected,
        "observations": len(view.observation_names),
        "witness_columns": len(view.witness_names),
        "mask_columns": len(view.mask_names),
        "mask_rank": mask_rank,
        "combined_rank": combined_rank,
    }


def run_rank_scenarios() -> dict:
    _, coefficient = accepted_coefficient("primary")
    transparent = transparent_coefficients("primary", 6, coefficient)
    key_row = [
        deterministic_field("precommit:key:trace") or 1,
        deterministic_field("precommit:key:message0") or 1,
        deterministic_field("precommit:key:message1") or 1,
        deterministic_field("precommit:key:message2") or 1,
    ]
    repair_coefficient = selected_non_one("precommit:repair:d") ^ 1
    if repair_coefficient == 0:
        raise AssertionError("repair d sampler must yield nonzero coefficient")

    ideal = build_joint_view(transparent, coefficient, 3)
    # Cleaner repair: the total wiring relation is verifier-derived from the already-emitted
    # endpoint evaluations, and no component claim about K crosses the transcript. At the clear
    # linear layer this is exactly the ideal view; the grouped PCS relation remains an open
    # implementation/simulator obligation.
    grouped_relation = build_joint_view(transparent, coefficient, 3)
    current = build_joint_view(
        transparent,
        coefficient,
        3,
        clear_claim_key_rows=[key_row],
        claim_blinder_rows=[[]],
    )
    repaired = build_joint_view(
        transparent,
        coefficient,
        3,
        clear_claim_key_rows=[key_row],
        claim_blinder_rows=[[repair_coefficient]],
    )
    zero_d = build_joint_view(
        transparent,
        coefficient,
        3,
        clear_claim_key_rows=[key_row],
        claim_blinder_rows=[[0]],
    )

    zero_c_transparent = [1, 1, 0, 0]
    zero_c = build_joint_view(zero_c_transparent, 0, 1)
    no_vector_mask = build_joint_view(
        transparent, coefficient, 3, include_oracle_masks=False
    )

    two_claim_rows = [
        [1, 0, 0, 0],
        [0, 1, 0, 0],
    ]
    two_claim_one_blinder = build_joint_view(
        transparent,
        coefficient,
        3,
        clear_claim_key_rows=two_claim_rows,
        claim_blinder_rows=[[1], [1]],
    )
    two_claim_two_blinders = build_joint_view(
        transparent,
        coefficient,
        3,
        clear_claim_key_rows=two_claim_rows,
        claim_blinder_rows=[[1, 0], [0, 1]],
    )

    bf_relation = [1, 0, 1]
    bf_independent_eval = [0, 1, 1]
    bf_dependent_eval = list(bf_relation)
    bf_gamma = deterministic_field("basefold:gamma")
    if bf_gamma in (0, 1):
        bf_gamma = 2

    scenarios = {
        "ideal_c_nonzero_fresh_masks": scenario_result(ideal, True),
        "grouped_precommit_private_total_claim": scenario_result(grouped_relation, True),
        "current_patch_clear_precommit_claim": scenario_result(current, False),
        "rank_one_unused_blinder_d_nonzero": scenario_result(repaired, True),
        "rank_one_unused_blinder_d_zero": scenario_result(zero_d, False),
        "trace_coefficient_c_zero": scenario_result(zero_c, False),
        "missing_basefold_vector_mask": scenario_result(no_vector_mask, False),
        "reused_otp_key": scenario_result(build_key_reuse_view(), False),
        "two_claims_one_blinder": scenario_result(two_claim_one_blinder, False),
        "two_claims_two_blinders": scenario_result(two_claim_two_blinders, True),
        "basefold_generic_independent_functionals": scenario_result(
            build_basefold_scalar_view(bf_relation, bf_independent_eval, bf_gamma), True
        ),
        "basefold_gamma_zero": scenario_result(
            build_basefold_scalar_view(bf_relation, bf_independent_eval, 0), False
        ),
        "basefold_dependent_functionals": scenario_result(
            build_basefold_scalar_view(bf_relation, bf_dependent_eval, bf_gamma), False
        ),
    }

    constructive_trials = 64
    constructive_pass = True
    repaired_constructive_pass = True
    for trial in range(constructive_trials):
        _, trial_c = accepted_coefficient(f"constructive:{trial}")
        trial_a = transparent_coefficients(f"constructive:{trial}", 6, trial_c)
        trace_delta = [deterministic_field(f"delta:t:{trial}:{i}") for i in range(6)]
        message_delta = [deterministic_field(f"delta:m:{trial}:{i}") for i in range(3)]
        constructive_pass &= constructive_joint_mask_check(
            trial_a, trial_c, trace_delta, message_delta
        )
        repaired_constructive_pass &= constructive_joint_mask_check(
            trial_a,
            trial_c,
            trace_delta,
            message_delta,
            claim_key_coefficients=key_row,
            claim_blinder_coefficient=repair_coefficient,
        )

    all_expectations_met = all(item["expectation_met"] for item in scenarios.values())
    return {
        "criterion": "rank(R) == rank([R|W])",
        "field": "GF(2^128)/(x^128+x^7+x^2+x+1)",
        "coefficient_c_hex": f"{coefficient:032x}",
        "repair_coefficient_d_hex": f"{repair_coefficient:032x}",
        "direct_precommit_functional_rank": 1,
        "scenarios": scenarios,
        "constructive_trials": constructive_trials,
        "constructive_c_nonzero_pass": constructive_pass,
        "constructive_repair_pass": repaired_constructive_pass,
        "all_expectations_met": all_expectations_met
        and constructive_pass
        and repaired_constructive_pass,
        "current_patch_clear_rank_closed": scenarios[
            "current_patch_clear_precommit_claim"
        ]["contained"],
        "conditional_rank_one_repair_clear_rank_closed": scenarios[
            "rank_one_unused_blinder_d_nonzero"
        ]["contained"],
        "conditional_grouped_relation_clear_rank_closed": scenarios[
            "grouped_precommit_private_total_claim"
        ]["contained"],
        "grouped_relation_feasibility": {
            "existing_phase_a_can_express_cross_oracle_group": False,
            "reason": (
                "The pinned queue is indexed per oracle, constructs one sumcheck prover per "
                "oracle, and requires a component claim for each. Phase B is multi-oracle but "
                "begins only after those component claims have already been reduced."
            ),
            "required_refactor": [
                "add a queued relation group spanning precommit and private oracle indices",
                "mask the public total with the sum of their independent sigma_i values",
                "run one shared Phase-A sumcheck at the maximum member domain",
                "return one alpha per member oracle for the unchanged combined FRI Phase B",
                "mirror the exact grouped relation in the verifier",
            ],
            "predicted_serialized_delta_bytes": -16,
            "delta_basis": (
                "remove the one clear B128 precommit_claim; retain commitments, sigma_i, "
                "Phase-A round width, per-oracle alphas, and Phase-B FRI topology"
            ),
            "exact_delta_measured": False,
        },
        "repair_comparison": {
            "recommended": "grouped_precommit_private_relation",
            "grouped": (
                "removes the leaking component functional, needs no new blinder or nonzero-d "
                "abort gate, and should save one 16-byte scalar, but requires a cross-oracle "
                "Phase-A relation refactor"
            ),
            "unused_blinder_h": (
                "closes exactly rank one with d!=0 and is a useful control, but retains the "
                "component claim, adds a precommit coordinate/constraint and paired sampler, "
                "and needs one fresh blinder per independent clear-claim rank"
            ),
        },
        "repair_scope": (
            "Only the isolated direct precommit scalar. Outer Libra endpoints, BaseFold sigma/alpha, "
            "FRI, Merkle queries, nonlinear composition, and QROM remain open."
        ),
    }


def validate_certificate(certificate: dict) -> None:
    required_top = {
        "schema_version",
        "subject",
        "source_checks",
        "inventory",
        "rank_audit",
        "residual_assumptions",
        "claims",
        "decision",
    }
    missing = required_top - set(certificate)
    if missing:
        raise ValueError(f"certificate missing fields: {sorted(missing)}")
    if certificate["schema_version"] != 1:
        raise ValueError("unsupported certificate schema")
    if certificate["claims"]["complete_zk"]:
        gates = [
            certificate["source_checks"]["all_passed"],
            certificate["inventory"]["exact_multiplicities_complete"],
            certificate["rank_audit"]["current_patch_clear_rank_closed"],
            all(item["status"] == "DISCHARGED" for item in certificate["residual_assumptions"]),
            certificate["claims"]["compiled_full_m4"],
            certificate["claims"]["joint_simulator_proved"],
            certificate["claims"]["qrom_composed"],
        ]
        if not all(gates):
            raise ValueError("fail-closed gate forbids complete_zk=true")
    if certificate["decision"]["frontier_eligible"] and not certificate["claims"]["complete_zk"]:
        raise ValueError("frontier eligibility requires CompleteZK")
    if not certificate["rank_audit"]["all_expectations_met"]:
        raise ValueError("rank-control expectations did not all hold")


def run_audit(pinned_checkout: Path | None = DEFAULT_PINNED_CHECKOUT) -> dict:
    source_checks = check_sources(pinned_checkout)
    rank_audit = run_rank_scenarios()
    certificate = {
        "schema_version": 1,
        "subject": {
            "name": "Hegemon M4 coefficient-aware joint simulator rank audit",
            "pinned_revision": PINNED_REVISION,
            "patch_sha256": PINNED_PATCH_SHA256,
            "m4_keccak_permutations": 83,
            "m4_relation": "maximum fixed 2-input/2-output one-main source",
        },
        "source_checks": source_checks,
        "inventory": {
            "protocol_class_complete": True,
            "exact_multiplicities_complete": False,
            "items": INVENTORY,
        },
        "rank_audit": rank_audit,
        "residual_assumptions": RESIDUAL_ASSUMPTIONS,
        "claims": {
            "compiled_full_m4": False,
            "joint_simulator_proved": False,
            "basefold_joint_simulator_proved": False,
            "outer_spartan_simulator_proved": False,
            "qrom_composed": False,
            "strict_pq128": False,
            "complete_zk": False,
        },
        "decision": {
            "status": "REJECT_CURRENT_PATCH_REPAIR_CONDITIONAL",
            "frontier_eligible": False,
            "reason_codes": [
                "OUTER_PRECOMMIT_CORRELATION_LEAK",
                "EXACT_MULTIPLICITIES_UNCOMPILED",
                "BASEFOLD_JOINT_SIMULATOR_OPEN",
                "OUTER_SPARTAN_SIMULATOR_OPEN",
                "QROM_COMPOSITION_OPEN",
                "STRICT_E384_BACKEND_OPEN",
            ],
            "conditional_repair": (
                "Preferred: remove the component precommit claim and prove one grouped "
                "precommit+private relation. Control: one fresh unused h closes the one direct "
                "clear functional only if d is forced nonzero; rank-r exposure needs blinder rank r."
            ),
        },
    }
    validate_certificate(certificate)
    return certificate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pinned-checkout",
        type=Path,
        default=DEFAULT_PINNED_CHECKOUT,
        help="patched pinned Binius checkout used for live source-anchor verification",
    )
    parser.add_argument(
        "--no-pinned-checkout",
        action="store_true",
        help="verify only the frozen patch and local M4 source identities",
    )
    parser.add_argument("--compact", action="store_true", help="print compact JSON")
    args = parser.parse_args()
    checkout = None if args.no_pinned_checkout else args.pinned_checkout
    certificate = run_audit(checkout)
    print(json.dumps(certificate, indent=None if args.compact else 2, sort_keys=True))
    print(
        "audit_verdict: complete_zk=false; current_clear_rank=false; "
        "grouped_relation=preferred_conditional_pass; rank_one_repair=conditional_pass"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
