#!/usr/bin/env python3
"""Conservative source-only VOLEitH/QuickSilver byte screen for full M4.

This module is deliberately not a prover and never promotes a frontier point.
It prices two primary-source architectures:

* the generic binary VOLE-in-the-head communication figures from Baum et al.;
* the Keccak checkpoint/cmul construction from PoMFRIT, embedded in a
  FAEST-shaped forest of small VOLEs.

All arithmetic is integer and every returned proof section is byte aligned.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Iterable


HARD_CAP_BYTES = 124_068
FS_XOF_BYTES = 64  # SHAKE256-512
WIRE_HEADER_BYTES = 200


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div expects numerator >= 0 and denominator > 0")
    return (numerator + denominator - 1) // denominator


def bits_to_bytes_exact(bits: int) -> int:
    if bits < 0 or bits % 8:
        raise ValueError(f"section is not byte aligned: {bits} bits")
    return bits // 8


@dataclass(frozen=True)
class M4Relation:
    source_revision: str = "3f96163049f680b2909f6545690bd929f1b48c44"
    keccak_permutations: int = 83
    keccak_rounds: int = 24
    keccak_state_bits: int = 1_600
    chi_word_ands_per_round: int = 25
    word_bits: int = 64
    private_words: int = 671
    public_words: int = 114

    @property
    def private_bits(self) -> int:
        return self.private_words * self.word_bits

    @property
    def public_bits(self) -> int:
        return self.public_words * self.word_bits

    @property
    def word_ands(self) -> int:
        return (
            self.keccak_permutations
            * self.keccak_rounds
            * self.chi_word_ands_per_round
        )

    @property
    def boolean_ands(self) -> int:
        return self.word_ands * self.word_bits


M4 = M4Relation()


@dataclass(frozen=True)
class VoleProfile:
    """Transparent forest parameters used only for a conservative screen.

    ``lambda_bits`` is the MAC/challenge field size. ``small_vole_k`` is the
    number of challenge bits supplied by each small VOLE tree, and ``tau``
    trees jointly cover the challenge. The forest opening reveals at most k
    sibling seeds per tree; unlike FAEST v2's one-tree optimization, this
    bound is simple and does not assume an unimplemented opening compressor.
    """

    name: str
    lambda_bits: int
    tau: int
    small_vole_k: int
    leaf_commitment_blocks: int = 3
    consistency_padding_bits: int = 16
    qrom_reserve_bits: int = 8

    def validate(self) -> None:
        if self.lambda_bits % 8:
            raise ValueError("lambda_bits must be byte aligned")
        if self.tau <= 0 or self.small_vole_k <= 0:
            raise ValueError("tau and small_vole_k must be positive")
        if self.tau * self.small_vole_k < self.lambda_bits:
            raise ValueError("small VOLE challenge space is smaller than lambda")
        if self.consistency_padding_bits % 8:
            raise ValueError("consistency padding must be byte aligned")


# Official FAEST-256s uses lambda=256 and tau=22. It is shown as a category-5
# reference profile, not as a strict 128-bit-QROM proof for the modified M4
# protocol. The strict screen uses 384 challenge bits so that degree and union
# losses do not silently consume the full 128-bit post-quantum target.
FAEST_256S_SHAPE = VoleProfile(
    name="faest-256s-shape",
    lambda_bits=256,
    tau=22,
    small_vole_k=12,
)
STRICT_PQ128_SCREEN = VoleProfile(
    name="strict-pq128-lambda384-forest",
    lambda_bits=384,
    tau=32,
    small_vole_k=12,
)


@dataclass(frozen=True)
class DegreeSplit:
    rounds_per_checkpoint: int
    forward_rounds: int
    inverse_rounds: int
    forward_degree: int
    inverse_degree: int
    max_degree: int


def best_keccak_degree_split(rounds_per_checkpoint: int) -> DegreeSplit:
    """Minimize max(2**forward, 3**inverse) for a Keccak checkpoint.

    Keccak's forward round has algebraic degree 2 and its inverse has degree 3.
    Equating a forward evaluation from the left checkpoint with an inverse
    evaluation from the right checkpoint is the construction used by the
    PoMFRIT SHAKE optimization. In particular, span 6 selects 4+2 and degree
    16, which is a pinned regression test below.
    """

    if not 1 <= rounds_per_checkpoint <= M4.keccak_rounds:
        raise ValueError("rounds_per_checkpoint must be in 1..=24")
    candidates: list[DegreeSplit] = []
    for forward in range(rounds_per_checkpoint + 1):
        inverse = rounds_per_checkpoint - forward
        forward_degree = 2**forward
        inverse_degree = 3**inverse
        candidates.append(
            DegreeSplit(
                rounds_per_checkpoint=rounds_per_checkpoint,
                forward_rounds=forward,
                inverse_rounds=inverse,
                forward_degree=forward_degree,
                inverse_degree=inverse_degree,
                max_degree=max(forward_degree, inverse_degree),
            )
        )
    return min(
        candidates,
        key=lambda item: (
            item.max_degree,
            item.forward_degree + item.inverse_degree,
            item.forward_rounds,
        ),
    )


@dataclass(frozen=True)
class ProofSections:
    header: int
    public_instance: int
    correction_vectors: int
    vole_consistency_response: int
    witness_derandomization: int
    quicksilver_response: int
    bavc_seed_opening: int
    bavc_hidden_leaf_commitments: int
    fs_final_challenge: int
    salt: int
    complete_zk_randomizer: int
    counter: int

    @property
    def total(self) -> int:
        return sum(asdict(self).values())


@dataclass(frozen=True)
class SecurityScreen:
    algebraic_classical_bits: int
    algebraic_qrom_bits: int
    shake_preimage_qrom_bits: int
    shake_collision_qrom_bits: int
    conservative_numeric_bits: int
    numeric_pq128_pass: bool
    exact_qrom_theorem: bool = False
    exact_complete_zk_theorem: bool = False
    exact_relation_refinement: bool = False
    production_parser: bool = False

    @property
    def admitted(self) -> bool:
        return (
            self.numeric_pq128_pass
            and self.exact_qrom_theorem
            and self.exact_complete_zk_theorem
            and self.exact_relation_refinement
            and self.production_parser
        )


@dataclass(frozen=True)
class CheckpointEstimate:
    profile: str
    rounds_per_checkpoint: int
    checkpoint_states: int
    checkpoint_bits: int
    private_input_bits: int
    committed_secret_bits: int
    degree_split: DegreeSplit
    vole_vector_bits: int
    sections: ProofSections
    security: SecurityScreen
    cap_bytes: int
    below_cap: bool
    frontier_admitted: bool
    caveat: str


def security_screen(profile: VoleProfile, degree: int) -> SecurityScreen:
    # The Assert error from the primary construction is (degree + 1)/2^lambda.
    # We additionally reserve fixed headroom for the VOLE consistency and
    # multi-oracle union terms. The square-root conversion is intentionally a
    # conservative QROM screen, not a theorem for this customized transcript.
    degree_loss = math.ceil(math.log2(degree + 1))
    classical = max(0, profile.lambda_bits - degree_loss - profile.qrom_reserve_bits)
    qrom = classical // 2
    shake_preimage = (FS_XOF_BYTES * 8) // 2
    # Generic quantum collision search is O(2^(n/3)).
    shake_collision = (FS_XOF_BYTES * 8) // 3
    numeric = min(qrom, shake_preimage, shake_collision)
    return SecurityScreen(
        algebraic_classical_bits=classical,
        algebraic_qrom_bits=qrom,
        shake_preimage_qrom_bits=shake_preimage,
        shake_collision_qrom_bits=shake_collision,
        conservative_numeric_bits=numeric,
        numeric_pq128_pass=numeric >= 128,
    )


def checkpoint_estimate(
    span: int,
    profile: VoleProfile = STRICT_PQ128_SCREEN,
    relation: M4Relation = M4,
) -> CheckpointEstimate:
    profile.validate()
    degree_split = best_keccak_degree_split(span)
    checkpoint_states = relation.keccak_permutations * ceil_div(
        relation.keccak_rounds, span
    )
    checkpoint_bits = checkpoint_states * relation.keccak_state_bits
    committed_secret_bits = relation.private_bits + checkpoint_bits
    degree = degree_split.max_degree

    # Generalized FAEST/QuickSilver correlation vector: committed witness,
    # (degree - 1) ZK mask field elements, and lambda+B consistency padding.
    # This is committed as witness + degree*lambda + B bits in total.
    vole_vector_bits = (
        committed_secret_bits
        + degree * profile.lambda_bits
        + profile.consistency_padding_bits
    )

    correction_bits = (profile.tau - 1) * vole_vector_bits
    consistency_bits = profile.lambda_bits + profile.consistency_padding_bits
    witness_bits = committed_secret_bits
    # Keep all d coefficients. FAEST reconstructs one from Fiat-Shamir and
    # stores d-1; retaining it is the conservative standalone-envelope choice.
    quicksilver_bits = degree * profile.lambda_bits
    seed_opening_bits = (
        profile.tau
        * profile.small_vole_k
        * profile.lambda_bits
    )
    leaf_commitment_bits = (
        profile.tau
        * profile.leaf_commitment_blocks
        * profile.lambda_bits
    )
    # The two-stage complete-ZK simulator repair in the PoMFRIT appendix adds
    # comrand and rand, totalling 4*lambda bits. We retain it even though a
    # purpose-built standalone proof might prove it unnecessary.
    complete_zk_randomizer_bits = 4 * profile.lambda_bits

    sections = ProofSections(
        header=WIRE_HEADER_BYTES,
        public_instance=bits_to_bytes_exact(relation.public_bits),
        correction_vectors=bits_to_bytes_exact(correction_bits),
        vole_consistency_response=bits_to_bytes_exact(consistency_bits),
        witness_derandomization=bits_to_bytes_exact(witness_bits),
        quicksilver_response=bits_to_bytes_exact(quicksilver_bits),
        bavc_seed_opening=bits_to_bytes_exact(seed_opening_bits),
        bavc_hidden_leaf_commitments=bits_to_bytes_exact(leaf_commitment_bits),
        fs_final_challenge=FS_XOF_BYTES,
        salt=FS_XOF_BYTES,
        complete_zk_randomizer=bits_to_bytes_exact(complete_zk_randomizer_bits),
        counter=4,
    )
    screen = security_screen(profile, degree)
    return CheckpointEstimate(
        profile=profile.name,
        rounds_per_checkpoint=span,
        checkpoint_states=checkpoint_states,
        checkpoint_bits=checkpoint_bits,
        private_input_bits=relation.private_bits,
        committed_secret_bits=committed_secret_bits,
        degree_split=degree_split,
        vole_vector_bits=vole_vector_bits,
        sections=sections,
        security=screen,
        cap_bytes=HARD_CAP_BYTES,
        below_cap=sections.total <= HARD_CAP_BYTES,
        frontier_admitted=False,
        caveat=(
            "source-only upper-bound screen; no exact M4 refinement, complete-ZK "
            "proof, QROM theorem, or production verifier/parser"
        ),
    )


def all_checkpoint_estimates(
    profile: VoleProfile = STRICT_PQ128_SCREEN,
) -> list[CheckpointEstimate]:
    return [checkpoint_estimate(span, profile) for span in range(1, 25)]


def best_checkpoint_estimate(
    profile: VoleProfile = STRICT_PQ128_SCREEN,
) -> CheckpointEstimate:
    return min(all_checkpoint_estimates(profile), key=lambda item: item.sections.total)


def paper_linear_screens(relation: M4Relation = M4) -> dict[str, int | str]:
    """Primary-paper average communication screens at 2^-128 soundness.

    The VOLEitH paper reports 16 bits per Boolean AND for its F2 protocol and
    42 bits per Boolean AND for Limbo at a 2^20-gate circuit. These are not
    exact Hegemon proofs, but they decisively reject the generic-gate route.
    """

    return {
        "boolean_ands": relation.boolean_ands,
        "voleith_16_bits_per_boolean_and_bytes": bits_to_bytes_exact(
            relation.boolean_ands * 16
        ),
        "limbo_42_bits_per_boolean_and_bytes": bits_to_bytes_exact(
            relation.boolean_ands * 42
        ),
        "invalid_16_bits_per_word_and_reward_hack_bytes": bits_to_bytes_exact(
            relation.word_ands * 16
        ),
        "invalid_reason": (
            "a 64-lane bitwise AND is not one multiplication in a field; "
            "the valid binary relation has 64 Boolean multiplications"
        ),
    }


def faest_v2_signature_bytes(
    *,
    lambda_bits: int,
    tau: int,
    witness_bits: int,
    degree: int,
    consistency_padding_bits: int,
    tree_opening_seeds: int,
    leaf_commitment_blocks: int,
) -> int:
    """Exact FAEST-v2 compact formula, generalized only in ``degree``.

    At degree=3 this is the formula in FAEST v2 section 3.1. The regression
    tests instantiate only official degree-3 rows. General degrees are a byte
    screen and are never treated as a standardized parameter set.
    """

    bits = tau * (
        witness_bits + degree * lambda_bits + consistency_padding_bits
    )
    bits += tree_opening_seeds * lambda_bits
    bits += leaf_commitment_blocks * lambda_bits * tau
    bits += lambda_bits  # final Delta challenge
    bits += 128  # iv/salt in FAEST v2
    bits += 32  # grinding counter
    return bits_to_bytes_exact(bits)


def report(profile: VoleProfile) -> dict[str, object]:
    best = best_checkpoint_estimate(profile)
    best_dict = asdict(best)
    best_dict["sections"]["total"] = best.sections.total
    best_dict["over_cap_bytes"] = best.sections.total - HARD_CAP_BYTES
    best_dict["cap_multiple"] = best.sections.total / HARD_CAP_BYTES
    return {
        "status": "SCREEN_ONLY_NOT_FRONTIER",
        "hard_cap_bytes": HARD_CAP_BYTES,
        "relation": {
            **asdict(M4),
            "private_bits": M4.private_bits,
            "public_bits": M4.public_bits,
            "word_ands": M4.word_ands,
            "boolean_ands": M4.boolean_ands,
        },
        "paper_linear_screens": paper_linear_screens(),
        "profile": asdict(profile),
        "private_only_replication_lower_bound_bytes": bits_to_bytes_exact(
            profile.tau * M4.private_bits
        ),
        "best_checkpoint_estimate": best_dict,
        "all_spans": [
            {
                **asdict(item),
                "total_bytes": item.sections.total,
            }
            for item in all_checkpoint_estimates(profile)
        ],
        "admission_gates": {
            "transparent_no_setup_architecture": True,
            "standalone_public_instance_priced": True,
            "shake256_512_priced": True,
            "exact_m4_relation_refinement": False,
            "exact_qrom_theorem_for_custom_transcript": False,
            "exact_complete_zk_theorem_for_custom_transcript": False,
            "production_parser_and_negative_vectors": False,
            "official_lambda384_implementation": False,
            "frontier_admitted": False,
        },
    }


def _profile_from_name(name: str) -> VoleProfile:
    if name == "strict384":
        return STRICT_PQ128_SCREEN
    if name == "faest256":
        return FAEST_256S_SHAPE
    raise ValueError(f"unknown profile {name!r}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("strict384", "faest256"),
        default="strict384",
    )
    parser.add_argument("--compact", action="store_true", help="omit all-span detail")
    args = parser.parse_args(list(argv) if argv is not None else None)
    output = report(_profile_from_name(args.profile))
    if args.compact:
        output.pop("all_spans")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
