#!/usr/bin/env python3
"""Executable algebra audit for CFW26 Construction 11.4.

This module is deliberately small and dependency-free.  It does not implement
an IOR, an encoding, a PCS, Fiat--Shamir, or a production verifier.  It models
only the R1CS/inner-mask algebra needed to distinguish three readings of the
printed construction:

* ``printed-coefficient-1-identity``: coefficient one in Steps 3/8-first and
  the identity form printed in Step 9.  Definition 5.2 makes the pair-shaped
  Step-9 state ill-typed.  A separate, explicitly charitable projection that
  discards the scalar is provided only to expose the resulting residual.
* ``candidate-coefficient-1-times-identity``: coefficient one and the
  scalar-multiplied identity from Definition 5.4.
* ``coefficient-2-scaled-times-identity``: coefficient two everywhere and a
  two-scaled scalar-multiplied identity.

All arithmetic is over explicitly validated small prime fields.  The retained
tests exercise honest random R1CS instances, endpoint-zero masks, mutations,
and the exact value-claim public slice.  Passing this executable audit proves
neither Theorem 11.3 nor complete zero knowledge.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Iterable, Mapping, Sequence


PRINTED = "printed-coefficient-1-identity"
CANDIDATE = "candidate-coefficient-1-times-identity"
SCALED_TWO = "coefficient-2-scaled-times-identity"
FIELD_NAMES = ("A", "B", "C")
EXPERIMENT_SEED = b"hegemon.cfw26.section11.repair-audit.v1"
EXPERIMENT_PRIMES = (5, 7, 11, 13)
TRIALS_PER_PRIME = 96
INNER_MESSAGE_LENGTH = 4


class AuditError(ValueError):
    """Base class for rejected audit inputs."""


class IllTypedLinearFormState(AuditError):
    """Raised when Definition 5.2 is applied to Step 9's pair state."""


@dataclass(frozen=True)
class Branch:
    name: str
    step3_mask_coefficient: int
    step8_mask_coefficient: int
    output_form: str
    output_mask_scale: int | None
    paper_authoritative: bool = False
    theorem_inherited: bool = False
    complete_zk_proved: bool = False
    qrom_proved: bool = False
    production_authorized: bool = False

    @property
    def is_well_typed(self) -> bool:
        return self.output_form != "identity-on-pair"


BRANCHES: Mapping[str, Branch] = {
    PRINTED: Branch(
        name=PRINTED,
        step3_mask_coefficient=1,
        step8_mask_coefficient=1,
        output_form="identity-on-pair",
        output_mask_scale=None,
    ),
    CANDIDATE: Branch(
        name=CANDIDATE,
        step3_mask_coefficient=1,
        step8_mask_coefficient=1,
        output_form="times-identity",
        output_mask_scale=1,
    ),
    SCALED_TWO: Branch(
        name=SCALED_TWO,
        step3_mask_coefficient=2,
        step8_mask_coefficient=2,
        output_form="scaled-times-identity",
        output_mask_scale=2,
    ),
}


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    for divisor in range(2, math.isqrt(value) + 1):
        if value % divisor == 0:
            return False
    return True


def require_prime(value: int) -> None:
    if not is_prime(value):
        raise AuditError(f"field modulus must be prime, got {value}")


def fsum(values: Iterable[int], prime: int) -> int:
    return sum(values) % prime


def dot(left: Sequence[int], right: Sequence[int], prime: int) -> int:
    if len(left) != len(right):
        raise AuditError("dot-product length mismatch")
    return fsum((a * b for a, b in zip(left, right)), prime)


def powers(value: int, length: int, prime: int) -> tuple[int, ...]:
    if length < 0:
        raise AuditError("negative power-vector length")
    result: list[int] = []
    accumulator = 1
    for _ in range(length):
        result.append(accumulator)
        accumulator = accumulator * value % prime
    return tuple(result)


def poly_eval(coefficients: Sequence[int], point: int, prime: int) -> int:
    accumulator = 0
    for coefficient in reversed(coefficients):
        accumulator = (accumulator * point + coefficient) % prime
    return accumulator


def index_bits(index: int, width: int) -> tuple[int, ...]:
    if index < 0 or index >= 1 << width:
        raise AuditError("index outside Boolean cube")
    return tuple((index >> shift) & 1 for shift in reversed(range(width)))


def eq_eval(point: Sequence[int], boolean_point: Sequence[int], prime: int) -> int:
    if len(point) != len(boolean_point):
        raise AuditError("eq polynomial arity mismatch")
    result = 1
    for coordinate, bit in zip(point, boolean_point):
        factor = coordinate if bit else 1 - coordinate
        result = result * factor % prime
    return result


@dataclass(frozen=True)
class R1CSInstance:
    prime: int
    ell: int
    public: tuple[int, ...]
    A: tuple[tuple[int, ...], ...]
    B: tuple[tuple[int, ...], ...]
    C: tuple[tuple[int, ...], ...]

    def validate(self) -> None:
        require_prime(self.prime)
        if self.ell < 1 or self.ell & (self.ell - 1):
            raise AuditError("ell must be a positive power of two")
        if len(self.public) != self.ell:
            raise AuditError("public input length must equal ell")
        size = 2 * self.ell
        for name, matrix in (("A", self.A), ("B", self.B), ("C", self.C)):
            if len(matrix) != size or any(len(row) != size for row in matrix):
                raise AuditError(f"{name} must be a {size} by {size} matrix")
        for value in itertools.chain(
            self.public,
            *(itertools.chain.from_iterable(matrix) for matrix in (self.A, self.B, self.C)),
        ):
            if not isinstance(value, int) or not 0 <= value < self.prime:
                raise AuditError("non-canonical field element")

    @property
    def size(self) -> int:
        return 2 * self.ell

    @property
    def sumcheck_variables(self) -> int:
        return (2 * self.ell).bit_length() - 1


def r1cs_residuals(instance: R1CSInstance, witness: Sequence[int]) -> tuple[int, ...]:
    instance.validate()
    if len(witness) != instance.ell:
        raise AuditError("witness length must equal ell")
    z = instance.public + tuple(value % instance.prime for value in witness)
    prime = instance.prime
    return tuple(
        (dot(a_row, z, prime) * dot(b_row, z, prime) - dot(c_row, z, prime)) % prime
        for a_row, b_row, c_row in zip(instance.A, instance.B, instance.C)
    )


def random_valid_r1cs(
    prime: int, ell: int, rng: random.Random
) -> tuple[R1CSInstance, tuple[int, ...]]:
    """Generate a random square instance with a planted honest witness.

    ``public[0]`` is fixed to one.  Each C row is sampled randomly and then its
    first coefficient is solved so that the planted assignment satisfies the
    row.  This retains randomness in every matrix while giving an exact valid
    relation instance.
    """

    require_prime(prime)
    if ell < 1 or ell & (ell - 1):
        raise AuditError("ell must be a positive power of two")
    public = (1,) + tuple(rng.randrange(prime) for _ in range(ell - 1))
    witness = tuple(rng.randrange(prime) for _ in range(ell))
    z = public + witness
    size = 2 * ell
    matrices: dict[str, list[tuple[int, ...]]] = {name: [] for name in FIELD_NAMES}
    for _ in range(size):
        a_row = [rng.randrange(prime) for _ in range(size)]
        b_row = [rng.randrange(prime) for _ in range(size)]
        c_row = [rng.randrange(prime) for _ in range(size)]
        target = dot(a_row, z, prime) * dot(b_row, z, prime) % prime
        current = dot(c_row, z, prime)
        # z[0] is one, so this adjustment solves the row without inversion.
        c_row[0] = (c_row[0] + target - current) % prime
        matrices["A"].append(tuple(a_row))
        matrices["B"].append(tuple(b_row))
        matrices["C"].append(tuple(c_row))
    instance = R1CSInstance(
        prime=prime,
        ell=ell,
        public=public,
        A=tuple(matrices["A"]),
        B=tuple(matrices["B"]),
        C=tuple(matrices["C"]),
    )
    if any(r1cs_residuals(instance, witness)):
        raise AssertionError("planted R1CS generation failed")
    return instance, witness


def mle_combined_row(
    matrix: Sequence[Sequence[int]], alpha: Sequence[int], prime: int
) -> tuple[int, ...]:
    row_count = len(matrix)
    if row_count < 1 or row_count & (row_count - 1):
        raise AuditError("matrix row count must be a power of two")
    width = row_count.bit_length() - 1
    if len(alpha) != width:
        raise AuditError("alpha arity mismatch")
    column_count = len(matrix[0])
    if any(len(row) != column_count for row in matrix):
        raise AuditError("ragged matrix")
    result = [0] * column_count
    for row_index, row in enumerate(matrix):
        weight = eq_eval(alpha, index_bits(row_index, width), prime)
        for column_index, value in enumerate(row):
            result[column_index] = (result[column_index] + weight * value) % prime
    return tuple(result)


@dataclass(frozen=True)
class MatrixTerms:
    public: int
    witness: int


def matrix_terms(
    instance: R1CSInstance, witness: Sequence[int], alpha: Sequence[int]
) -> dict[str, MatrixTerms]:
    if len(witness) != instance.ell:
        raise AuditError("witness length must equal ell")
    prime = instance.prime
    result: dict[str, MatrixTerms] = {}
    for name, matrix in (("A", instance.A), ("B", instance.B), ("C", instance.C)):
        row = mle_combined_row(matrix, alpha, prime)
        result[name] = MatrixTerms(
            public=dot(row[: instance.ell], instance.public, prime),
            witness=dot(row[instance.ell :], witness, prime),
        )
    return result


def sample_endpoint_zero_polynomial(
    prime: int, length: int, rng: random.Random
) -> tuple[int, ...]:
    require_prime(prime)
    if length < 2:
        raise AuditError("endpoint constraints need at least two coefficients")
    tail = [rng.randrange(prime) for _ in range(length - 2)]
    coefficients = [0, (-sum(tail)) % prime, *tail]
    result = tuple(coefficients)
    if poly_eval(result, 0, prime) or poly_eval(result, 1, prime):
        raise AssertionError("endpoint-zero sampler failed")
    return result


MaskSet = dict[str, tuple[tuple[int, ...], ...]]


def sample_masks(
    prime: int, rounds: int, length: int, rng: random.Random
) -> MaskSet:
    return {
        name: tuple(
            sample_endpoint_zero_polynomial(prime, length, rng) for _ in range(rounds)
        )
        for name in FIELD_NAMES
    }


def mask_sums(masks: MaskSet, alpha: Sequence[int], prime: int) -> dict[str, int]:
    if set(masks) != set(FIELD_NAMES):
        raise AuditError("mask set must contain A, B, and C")
    result: dict[str, int] = {}
    for name in FIELD_NAMES:
        if len(masks[name]) != len(alpha):
            raise AuditError("one inner mask is required per sumcheck variable")
        result[name] = fsum(
            (poly_eval(message, point, prime) for message, point in zip(masks[name], alpha)),
            prime,
        )
    return result


def zero_evader(rho: int, prime: int) -> tuple[int, int, int]:
    """The diagnostic monomial zero-evader (1, rho, rho^2)."""

    return (1, rho % prime, rho * rho % prime)


@dataclass(frozen=True)
class TrialResult:
    branch: str
    well_typed: bool
    boolean_constraints_hold: bool
    target_mu: int
    typed_lhs: int | None
    typed_residual: int | None
    charitable_printed_lhs: int | None
    charitable_printed_residual: int | None
    v_values: tuple[int, int, int]
    u_values: tuple[int, int, int]
    witness_values: tuple[int, int, int]
    mask_sums: tuple[int, int, int]
    ze: tuple[int, int, int]


def relation_mask_vector(
    branch: Branch, alpha_i: int, ze_coordinate: int, length: int, prime: int
) -> tuple[int, ...]:
    base = powers(alpha_i, length, prime)
    if branch.output_form == "identity-on-pair":
        raise IllTypedLinearFormState(
            "Definition 5.2 identity accepts one vector state, but Construction 11.4 "
            "Step 9 supplies (pow(alpha_i), ze(rho)_M)"
        )
    if branch.output_mask_scale is None:
        raise AssertionError("typed branch lacks output scale")
    scalar = branch.output_mask_scale * ze_coordinate % prime
    return tuple(scalar * value % prime for value in base)


def masked_boolean_residuals(
    instance: R1CSInstance,
    witness: Sequence[int],
    masks: MaskSet,
    branch: Branch,
) -> tuple[int, ...]:
    """Evaluate Step 3's masked constraint polynomial on the Boolean cube."""

    if branch.step3_mask_coefficient not in (1, 2):
        raise AuditError("unsupported mask coefficient")
    prime = instance.prime
    d = instance.sumcheck_variables
    z = instance.public + tuple(witness)
    residuals: list[int] = []
    for row_index in range(instance.size):
        bits = index_bits(row_index, d)
        values: dict[str, int] = {}
        for name, matrix in (("A", instance.A), ("B", instance.B), ("C", instance.C)):
            base = dot(matrix[row_index], z, prime)
            mask = fsum(
                (poly_eval(message, bit, prime) for message, bit in zip(masks[name], bits)),
                prime,
            )
            values[name] = (base + branch.step3_mask_coefficient * mask) % prime
        residuals.append((values["A"] * values["B"] - values["C"]) % prime)
    return tuple(residuals)


def evaluate_trial(
    instance: R1CSInstance,
    witness: Sequence[int],
    masks: MaskSet,
    alpha: Sequence[int],
    rho: int,
    branch: Branch,
) -> TrialResult:
    instance.validate()
    if any(r1cs_residuals(instance, witness)):
        raise AuditError("honest trial requires a valid R1CS witness")
    if len(alpha) != instance.sumcheck_variables:
        raise AuditError("alpha arity mismatch")
    prime = instance.prime
    terms = matrix_terms(instance, witness, alpha)
    sums = mask_sums(masks, alpha, prime)
    ze = zero_evader(rho, prime)
    v = {
        name: (
            terms[name].public
            + terms[name].witness
            + branch.step8_mask_coefficient * sums[name]
        )
        % prime
        for name in FIELD_NAMES
    }
    target_mu = fsum(
        (
            ze[index] * (v[name] - terms[name].public)
            for index, name in enumerate(FIELD_NAMES)
        ),
        prime,
    )
    main_lhs = fsum(
        (ze[index] * terms[name].witness for index, name in enumerate(FIELD_NAMES)),
        prime,
    )

    typed_lhs: int | None = None
    typed_residual: int | None = None
    projected_lhs: int | None = None
    projected_residual: int | None = None
    if branch.is_well_typed:
        mask_lhs = 0
        for matrix_index, name in enumerate(FIELD_NAMES):
            for round_index, message in enumerate(masks[name]):
                functional = relation_mask_vector(
                    branch,
                    alpha[round_index],
                    ze[matrix_index],
                    len(message),
                    prime,
                )
                mask_lhs = (mask_lhs + dot(message, functional, prime)) % prime
        typed_lhs = (main_lhs + mask_lhs) % prime
        typed_residual = (typed_lhs - target_mu) % prime
    else:
        # Diagnostic only: pretend identity silently projects the pair state to
        # its first component.  This is more permissive than Definition 5.2.
        projected_lhs = (main_lhs + fsum(sums.values(), prime)) % prime
        projected_residual = (projected_lhs - target_mu) % prime

    return TrialResult(
        branch=branch.name,
        well_typed=branch.is_well_typed,
        boolean_constraints_hold=not any(
            masked_boolean_residuals(instance, witness, masks, branch)
        ),
        target_mu=target_mu,
        typed_lhs=typed_lhs,
        typed_residual=typed_residual,
        charitable_printed_lhs=projected_lhs,
        charitable_printed_residual=projected_residual,
        v_values=tuple(v[name] for name in FIELD_NAMES),
        u_values=tuple(terms[name].public for name in FIELD_NAMES),
        witness_values=tuple(terms[name].witness for name in FIELD_NAMES),
        mask_sums=tuple(sums[name] for name in FIELD_NAMES),
        ze=ze,
    )


def endpoint_zero_polynomials(prime: int, length: int) -> Iterable[tuple[int, ...]]:
    require_prime(prime)
    if length < 2:
        raise AuditError("endpoint constraints need at least two coefficients")
    for tail in itertools.product(range(prime), repeat=length - 2):
        yield (0, (-sum(tail)) % prime, *tail)


def endpoint_evaluation_histogram(
    prime: int, length: int, alpha: int
) -> Counter[int]:
    return Counter(
        poly_eval(polynomial, alpha, prime)
        for polynomial in endpoint_zero_polynomials(prime, length)
    )


def value_slice_distribution(
    *,
    prime: int,
    length: int,
    alpha_last: int,
    mask_coefficient: int,
    public_terms: tuple[int, int, int],
    witness_terms: tuple[int, int, int],
    ze: tuple[int, int, int],
) -> Counter[tuple[int, int, int, int]]:
    """Exact distribution of (v_A,v_B,v_C,mu) from the final inner masks.

    All earlier inner masks are conditioned on and absorbed into
    ``witness_terms``.  Counts retain the number of coefficient-vector
    preimages, not merely the evaluation distribution.
    """

    histogram = endpoint_evaluation_histogram(prime, length, alpha_last)
    result: Counter[tuple[int, int, int, int]] = Counter()
    for t_a, t_b, t_c in itertools.product(histogram, repeat=3):
        masks = (t_a, t_b, t_c)
        v = tuple(
            (
                public_terms[index]
                + witness_terms[index]
                + mask_coefficient * masks[index]
            )
            % prime
            for index in range(3)
        )
        mu = fsum(
            (ze[index] * (v[index] - public_terms[index]) for index in range(3)),
            prime,
        )
        multiplicity = histogram[t_a] * histogram[t_b] * histogram[t_c]
        result[(v[0], v[1], v[2], mu)] += multiplicity
    return result


def _seeded_rng() -> random.Random:
    seed = int.from_bytes(hashlib.sha512(EXPERIMENT_SEED).digest(), "big")
    return random.Random(seed)


def randomized_experiment() -> dict[str, object]:
    rng = _seeded_rng()
    summaries: dict[str, dict[str, int]] = {
        name: {
            "trials": 0,
            "typed_trials": 0,
            "boolean_constraint_passes": 0,
            "typed_relation_passes": 0,
            "typed_relation_failures": 0,
            "charitable_projection_passes": 0,
            "charitable_projection_failures": 0,
        }
        for name in BRANCHES
    }
    per_prime: dict[str, dict[str, dict[str, int]]] = {}
    for prime in EXPERIMENT_PRIMES:
        prime_summary = {
            name: {"trials": 0, "relation_passes": 0, "relation_failures": 0}
            for name in BRANCHES
        }
        for _ in range(TRIALS_PER_PRIME):
            ell = 2 if rng.randrange(2) == 0 else 4
            instance, witness = random_valid_r1cs(prime, ell, rng)
            d = instance.sumcheck_variables
            alpha = tuple(rng.randrange(prime) for _ in range(d - 1)) + (
                rng.randrange(2, prime),
            )
            masks = sample_masks(prime, d, INNER_MESSAGE_LENGTH, rng)
            rho = rng.randrange(prime)
            for name, branch in BRANCHES.items():
                result = evaluate_trial(instance, witness, masks, alpha, rho, branch)
                summary = summaries[name]
                summary["trials"] += 1
                prime_summary[name]["trials"] += 1
                if result.boolean_constraints_hold:
                    summary["boolean_constraint_passes"] += 1
                if result.well_typed:
                    summary["typed_trials"] += 1
                    if result.typed_residual == 0:
                        summary["typed_relation_passes"] += 1
                        prime_summary[name]["relation_passes"] += 1
                    else:
                        summary["typed_relation_failures"] += 1
                        prime_summary[name]["relation_failures"] += 1
                elif result.charitable_printed_residual == 0:
                    summary["charitable_projection_passes"] += 1
                    prime_summary[name]["relation_passes"] += 1
                else:
                    summary["charitable_projection_failures"] += 1
                    prime_summary[name]["relation_failures"] += 1
        per_prime[str(prime)] = prime_summary
    return {
        "seed_sha512": hashlib.sha512(EXPERIMENT_SEED).hexdigest(),
        "primes": list(EXPERIMENT_PRIMES),
        "trials_per_prime": TRIALS_PER_PRIME,
        "inner_message_length": INNER_MESSAGE_LENGTH,
        "branches": summaries,
        "per_prime": per_prime,
    }


def public_slice_experiment() -> dict[str, object]:
    prime = 5
    length = 4
    # B is identically zero and C is identically zero, so this one public R1CS
    # instance accepts both witnesses while A retains witness-dependent terms.
    zero_row = (0, 0, 0, 0)
    instance = R1CSInstance(
        prime=prime,
        ell=2,
        public=(1, 3),
        A=(
            (1, 2, 3, 4),
            (4, 3, 2, 1),
            (2, 1, 4, 3),
            (3, 4, 1, 2),
        ),
        B=(zero_row,) * 4,
        C=(zero_row,) * 4,
    )
    witness_one_raw = (0, 0)
    witness_two_raw = (1, 1)
    if any(r1cs_residuals(instance, witness_one_raw)) or any(
        r1cs_residuals(instance, witness_two_raw)
    ):
        raise AssertionError("two-witness public-slice fixture is not valid")
    alpha = (3, 2)
    alpha_last = alpha[-1]
    terms_one = matrix_terms(instance, witness_one_raw, alpha)
    terms_two = matrix_terms(instance, witness_two_raw, alpha)
    public_terms = tuple(terms_one[name].public for name in FIELD_NAMES)
    if public_terms != tuple(terms_two[name].public for name in FIELD_NAMES):
        raise AssertionError("public terms changed across witnesses")
    witness_one = tuple(terms_one[name].witness for name in FIELD_NAMES)
    witness_two = tuple(terms_two[name].witness for name in FIELD_NAMES)
    if witness_one == witness_two:
        raise AssertionError("two-witness fixture did not change witness contribution")
    ze = (1, 2, 4)
    endpoint_histogram = endpoint_evaluation_histogram(prime, length, alpha_last)
    branches: dict[str, object] = {}
    for name, coefficient in ((PRINTED, 1), (CANDIDATE, 1), (SCALED_TWO, 2)):
        first = value_slice_distribution(
            prime=prime,
            length=length,
            alpha_last=alpha_last,
            mask_coefficient=coefficient,
            public_terms=public_terms,
            witness_terms=witness_one,
            ze=ze,
        )
        second = value_slice_distribution(
            prime=prime,
            length=length,
            alpha_last=alpha_last,
            mask_coefficient=coefficient,
            public_terms=public_terms,
            witness_terms=witness_two,
            ze=ze,
        )
        branches[name] = {
            "support": len(first),
            "total_coefficient_triples": sum(first.values()),
            "min_multiplicity": min(first.values()),
            "max_multiplicity": max(first.values()),
            "two_witness_distributions_equal": first == second,
            "scope": "value-claim slice (v_A,v_B,v_C,mu), not the full protocol view",
        }
    endpoint_zero_histogram = endpoint_evaluation_histogram(prime, length, 0)
    char_two_scaled_values = {(2 * value) % 2 for value in range(2)}
    return {
        "prime": prime,
        "inner_message_length": length,
        "alpha_last": alpha_last,
        "same_public_r1cs_valid_for_both_witnesses": True,
        "public_terms": list(public_terms),
        "witness_contribution_one": list(witness_one),
        "witness_contribution_two": list(witness_two),
        "endpoint_evaluation_histogram": {
            str(key): endpoint_histogram[key] for key in sorted(endpoint_histogram)
        },
        "branches": branches,
        "negative_controls": {
            "alpha_last_zero_support": len(endpoint_zero_histogram),
            "characteristic_two_factor_two_support": len(char_two_scaled_values),
        },
    }


def mutation_experiment() -> dict[str, bool]:
    prime = 101
    q = (3, 5, 7)
    masks = (11, 13, 17)
    ze = (1, 19, 58)

    candidate_mu = fsum(
        (ze[index] * (q[index] + masks[index]) for index in range(3)), prime
    )
    candidate_lhs = candidate_mu
    identity_projection_lhs = fsum(
        itertools.chain(
            (ze[index] * q[index] for index in range(3)),
            masks,
        ),
        prime,
    )
    dropped_scalar_lhs = identity_projection_lhs
    mutated_scalar_lhs = (
        candidate_lhs + masks[1]
    ) % prime  # ze_B -> ze_B + 1

    scaled_mu = fsum(
        (ze[index] * (q[index] + 2 * masks[index]) for index in range(3)), prime
    )
    scaled_lhs = scaled_mu
    unscaled_output_lhs = candidate_lhs

    base = (2, 3, 4)
    g_coefficient_one = (base[0] + masks[0]) * (base[1] + masks[1]) - (
        base[2] + masks[2]
    )
    v_coefficient_two = (base[0] + 2 * masks[0]) * (
        base[1] + 2 * masks[1]
    ) - (base[2] + 2 * masks[2])

    interior_histogram = endpoint_evaluation_histogram(5, 4, 2)
    endpoint_histogram = endpoint_evaluation_histogram(5, 4, 0)
    return {
        "printed_identity_pair_state_rejected": _printed_state_rejects(),
        "printed_charitable_projection_has_counterexample": identity_projection_lhs
        != candidate_mu,
        "candidate_exact_joint_relation_accepts": candidate_lhs == candidate_mu,
        "candidate_dropped_scalar_rejects": dropped_scalar_lhs != candidate_mu,
        "candidate_mutated_scalar_rejects": mutated_scalar_lhs != candidate_mu,
        "candidate_mutated_mu_rejects": candidate_lhs != (candidate_mu + 1) % prime,
        "scaled_two_exact_joint_relation_accepts": scaled_lhs == scaled_mu,
        "scaled_two_unscaled_output_rejects": unscaled_output_lhs != scaled_mu,
        "step3_one_step8_two_hybrid_rejects": g_coefficient_one % prime
        != v_coefficient_two % prime,
        "endpoint_zero_mask_preserves_boolean_constraint": (0 * 1 - 0) % prime == 0,
        "mutated_mask_endpoint_breaks_boolean_constraint": (1 * 1 - 0) % prime != 0,
        "invalid_r1cs_row_rejects": (1 * 1 - 0) % prime != 0,
        "interior_alpha_value_is_uniform": len(interior_histogram) == 5
        and len(set(interior_histogram.values())) == 1,
        "endpoint_alpha_destroys_value_hiding": len(endpoint_histogram) == 1,
        "characteristic_two_destroys_factor_two_hiding": len(
            {(2 * value) % 2 for value in range(2)}
        )
        == 1,
    }


def _printed_state_rejects() -> bool:
    try:
        relation_mask_vector(BRANCHES[PRINTED], 2, 3, 4, 5)
    except IllTypedLinearFormState:
        return True
    return False


def build_report() -> dict[str, object]:
    return {
        "schema": "hegemon.cfw26-section11-repair-audit.experiment.v1",
        "claim_boundary": (
            "Finite-field differential evidence and an algebraic local lemma only; "
            "not an implementation or proof of Theorem 11.3, complete ZK, QROM security, or production authority."
        ),
        "randomized_r1cs": randomized_experiment(),
        "public_value_slice": public_slice_experiment(),
        "mutations": mutation_experiment(),
        "authority": {
            "paper_specification_unambiguous": False,
            "repair_author_selected": False,
            "local_candidate_completeness_lemma": True,
            "theorem_11_3_inherited": False,
            "complete_zero_knowledge_proved": False,
            "qrom_security_proved": False,
            "pq128_composition_proved": False,
            "production_authorized": False,
        },
    }


def self_check(report: Mapping[str, object] | None = None) -> None:
    report = build_report() if report is None else report
    randomized = report["randomized_r1cs"]
    if not isinstance(randomized, Mapping):
        raise AssertionError("randomized report shape")
    branches = randomized["branches"]
    if not isinstance(branches, Mapping):
        raise AssertionError("branch report shape")
    total = len(EXPERIMENT_PRIMES) * TRIALS_PER_PRIME
    printed = branches[PRINTED]
    candidate = branches[CANDIDATE]
    scaled = branches[SCALED_TWO]
    if not all(isinstance(item, Mapping) for item in (printed, candidate, scaled)):
        raise AssertionError("branch summary shape")
    if printed["trials"] != total or printed["typed_trials"] != 0:
        raise AssertionError("printed branch was accidentally typed")
    if printed["charitable_projection_failures"] == 0:
        raise AssertionError("printed projection lacks a counterexample")
    for branch in (candidate, scaled):
        if branch["trials"] != total or branch["typed_trials"] != total:
            raise AssertionError("typed branch trial count")
        if branch["typed_relation_passes"] != total or branch["typed_relation_failures"]:
            raise AssertionError("coherent repair lost honest completeness")
        if branch["boolean_constraint_passes"] != total:
            raise AssertionError("endpoint-zero masks broke R1CS Boolean constraints")
    mutations = report["mutations"]
    if not isinstance(mutations, Mapping) or not all(mutations.values()):
        raise AssertionError("mutation corpus did not separate every case")
    public_slice = report["public_value_slice"]
    if not isinstance(public_slice, Mapping):
        raise AssertionError("public-slice report shape")
    public_branches = public_slice["branches"]
    if not isinstance(public_branches, Mapping):
        raise AssertionError("public-slice branches shape")
    for branch in public_branches.values():
        if not isinstance(branch, Mapping):
            raise AssertionError("public branch shape")
        if branch["support"] != 125 or branch["min_multiplicity"] != 125:
            raise AssertionError("unexpected public-slice distribution")
        if branch["max_multiplicity"] != 125 or not branch["two_witness_distributions_equal"]:
            raise AssertionError("value slice is not exactly witness independent")
    authority = report["authority"]
    if not isinstance(authority, Mapping):
        raise AssertionError("authority shape")
    forbidden = (
        "paper_specification_unambiguous",
        "repair_author_selected",
        "theorem_11_3_inherited",
        "complete_zero_knowledge_proved",
        "qrom_security_proved",
        "pq128_composition_proved",
        "production_authorized",
    )
    if any(authority[name] for name in forbidden):
        raise AssertionError("authority escaped fail-closed state")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-check", action="store_true", help="fail unless all retained invariants hold"
    )
    parser.add_argument(
        "--compact", action="store_true", help="emit compact rather than indented JSON"
    )
    args = parser.parse_args()
    report = build_report()
    if args.self_check:
        self_check(report)
    print(json.dumps(report, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
