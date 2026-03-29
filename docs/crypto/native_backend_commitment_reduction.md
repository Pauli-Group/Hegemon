# Native Backend Commitment Reduction

This note defines the exact commitment-binding problem used by Hegemon's active native backend family and the exact reduction the repository claims for it. It is not a concrete hardness proof. It states the implemented collision game, the intended bounded-kernel Module-SIS target, the reduction from the former to the latter, and the loss terms that enter the current code-derived claim.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v7"`
- `commitment_security_model = "bounded_kernel_module_sis"`
- `commitment_estimator_model = "sis_lattice_euclidean_adps16"`

This note is specific to the exact implemented commitment path in:

- [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs)
- [superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs)
- [superneo-ring/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ring/src/lib.rs)

## Implemented Algebra

The active family works over:

- prime field modulus `q = 18446744069414584321`
- ring degree `n = 8`
- ring `R_q = Z_q[X] / (X^n + 1)`
- commitment row count `k = 74`
- maximum committed message ring elements `M = 513`
- digit width `d = 8`

The active commitment matrix is an element of `R_q^{k x ell}` for `1 <= ell <= M`, derived deterministically from the manifest-owned parameter fingerprint plus row and column indices. The exact deterministic derivation is part of the frozen protocol surface in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md).

For a committed message vector `m ∈ R_q^ell`, the commitment map is:

```text
Com_A(m) = A · m ∈ R_q^k
```

## Exact Message Class

The live commitment path does not commit to arbitrary ring elements. It commits only to message vectors produced by the implemented public-witness reconstruction path:

1. derive the canonical public tx view and serialized STARK public inputs,
2. pack them with `GoldilocksPayPerBitPacker`,
3. expand the packed witness into fixed-width digits,
4. embed those digits coefficientwise into ring elements.

Let `M_live(ell)` denote the set of all valid message vectors of length `ell` that can arise from that exact reconstruction for the active relation and parameter set.

For every `m ∈ M_live(ell)`:

- each coefficient lies in `[0, 2^d - 1] = [0, 255]`,
- so `||m||_∞ <= 255`.

For a collision difference vector `z = m - m'` with `m, m' ∈ M_live(ell)`, the repo uses the exact coefficient bounds:

- `B_inf = 255`
- ambient coefficient dimension `N = M * n = 513 * 8 = 4104`
- `B_2 = ceil(B_inf * sqrt(N)) = ceil(255 * sqrt(4104)) = 16336`

Those are exactly the values exported in `NativeSecurityClaim` as:

- `commitment_problem_dimension = 4104`
- `commitment_problem_coeff_bound = 255`
- `commitment_problem_l2_bound = 16336`

## Collision Game

The active commitment-binding game is:

1. sample the active parameter set and the deterministic matrix `A`,
2. give the adversary the public commitment interface for the live commitment class,
3. the adversary outputs `(m, m')` with:
   - `m, m' ∈ M_live(ell)` for some `1 <= ell <= M`,
   - `m != m'`,
   - `Com_A(m) = Com_A(m')`.

The adversary wins if all three conditions hold.

This is narrower than arbitrary-message commitment binding. The claim is only about the exact bounded live message class the product path reconstructs and verifies.

## Intended Hardness Statement

The intended target problem is the following bounded-kernel Module-SIS instance over the implemented ring:

Given `A ∈ R_q^{k x ell}`, find a nonzero vector `z ∈ R_q^ell` such that:

- `A · z = 0`,
- `||z||_∞ <= B_inf = 255`,
- `||z||_2 <= B_2 = 16336`.

Call this exact problem:

```text
BK-MSIS(q, n, k, ell, B_inf, B_2)
```

with the active concrete bounds above and `ell <= M = 513`.

## Concrete Estimator Instance

The repository now turns that exact bounded-kernel target into one concrete coefficient-space Euclidean SIS estimate.

The active flattening is:

- equation dimension `n_eq = k * n = 74 * 8 = 592`
- witness dimension `m = M * n = 513 * 8 = 4104`
- modulus `q = 18446744069414584321`
- Euclidean bound `B_2 = 16336`

The estimator model implemented in [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) follows the standard Euclidean SIS-lattice line used in the lattice-estimator literature:

1. map the exact ring/module kernel witness into coefficient space,
2. keep the exact Euclidean bound `B_2`,
3. derive the target root-Hermite factor `δ` for the primal lattice attack from `(n_eq, m, q, B_2)`,
4. derive the required BKZ block size `β` from that `δ`,
5. translate `β` into concrete classical, quantum, and paranoid bit estimates with the standard linear cost models.

For the active instance the code computes:

- `commitment_problem_equations = 592`
- `commitment_problem_dimension = 4104`
- `commitment_problem_coeff_bound = 255`
- `commitment_problem_l2_bound = 16336`
- `commitment_estimator_dimension = 4104`
- `commitment_estimator_block_size = 3267`
- `commitment_estimator_classical_bits = 953`
- `commitment_estimator_quantum_bits = 865`
- `commitment_estimator_paranoid_bits = 677`

## Reduction

Let an adversary win the implemented collision game by outputting distinct `m, m' ∈ M_live(ell)` with:

```text
Com_A(m) = Com_A(m').
```

Define:

```text
z = m - m'.
```

Then:

1. `z != 0` because `m != m'`.
2. `A · z = 0` because the commitment map is linear:

   ```text
   A · z = A · (m - m') = A · m - A · m' = 0.
   ```

3. `||z||_∞ <= 255` under the repo's exact bounded live message model.
4. `||z||_2 <= 16336` by the explicit ambient-dimension bound above.

So every successful collision adversary yields a solver for the exact `BK-MSIS` instance defined here.

This is why the repo now treats the commitment claim as:

- an exact reduction from the implemented bounded-message collision game
- to a bounded-kernel Module-SIS style problem
- with no extra reduction slack inside the repository model.

## Loss Terms

The current repo model sets:

- `commitment_reduction_loss_bits = 0`

because the reduction is direct: a valid collision immediately yields a valid bounded-kernel witness for the target problem with no rewinding, guessing, or hybrid loss inside the repository proof sketch.

So the code computes:

```text
commitment_binding_bits
  = commitment_estimator_quantum_bits - commitment_reduction_loss_bits
  = 865 - 0
  = 865
```

The final active floor is then:

```text
transcript_floor_bits = transcript_soundness_bits - composition_loss_bits
                      = 157 - 7
                      = 150

soundness_floor_bits = min(transcript_floor_bits, commitment_binding_bits)
                     = min(150, 865)
                     = 150
```

## What This Note Does Not Establish

This note does **not** establish:

- a completed external cryptanalysis of the active coefficient-space SIS estimate,
- a paper-equivalent Neo/SuperNeo commitment reduction,
- that the active parameter set has already been externally cryptanalyzed,
- or that future tighter analysis will not lower the concrete `128`-bit target.

The current repository meaning is narrower:

- the collision game is now defined exactly for the implemented message class,
- the reduction target is now stated explicitly as a bounded-kernel Module-SIS style problem,
- the code-derived claim now uses an explicit coefficient-space Euclidean SIS estimate for that exact instance instead of the old geometry-only union-bound proxy,
- and the remaining open question is independent review of the exact BK-MSIS-to-SIS concretization and estimator model for this implementation.
