# Native Backend Formal Theorems

This note states the theorem-grade math for Hegemon's active native backend family. It replaces the old ad hoc `floor(challenge_bits * fold_challenge_count / 2)` transcript cap with an exact statement about the implemented five-challenge Fiat-Shamir schedule, proves the exact deterministic-commitment collision reduction the repo claims, proves the coefficient-space flattening step with zero in-repo loss, and records the concrete security arithmetic for the active conservative instance.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`
- `ring_profile = GoldilocksFrog`
- `challenge_bits = 63`
- `fold_challenge_count = 5`
- `matrix_rows = 11`
- `ring_degree = 54`
- `digit_bits = 8`
- `max_commitment_message_ring_elems = 76`
- `max_claimed_receipt_root_leaves = 128`

The exact code surface is the one implemented in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). The exact transcript and artifact bytes are frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md).

## 1. Active Algebra

Let

```text
q = 18446744069414584321
R_q = F_q[X] / (X^54 + X^27 + 1).
```

Because `q ≡ 1 (mod 3)`, Goldilocks contains primitive cube roots of unity. One explicit choice is

```text
ω = 4294967295,
ω^2 = 18446744065119617025,
ω^3 = 1,
ω != 1.
```

So in `F_q[X]`:

```text
X^54 + X^27 + 1 = (X^27 - ω)(X^27 - ω^2).
```

### Lemma 1.1: `X^27 - ω` and `X^27 - ω^2` are irreducible over `F_q`

Let `α` satisfy `α^27 = ω`. Then `α^81 = 1` and `α^27 != 1`, so `α` has multiplicative order `81`. The degree of the minimal polynomial of a primitive `81`st root over `F_q` is `ord_81(q)`. Here

```text
q mod 81 = 4,
ord_81(4) = 27.
```

Therefore every root of `X^27 - ω` has degree `27` over `F_q`. Since the polynomial itself also has degree `27`, it is irreducible. The same argument applies to `X^27 - ω^2`.

### Corollary 1.2: every nonzero polynomial of degree `< 27` is a unit in `R_q`

Let `g(X) ∈ F_q[X]` be nonzero with `deg g < 27`. A nonunit in `R_q` must share a nontrivial common factor with `X^54 + X^27 + 1`, hence with either `X^27 - ω` or `X^27 - ω^2`. By Lemma 1.1 each such factor has degree `27`, which is impossible for `g`. Hence `gcd(g, X^54 + X^27 + 1) = 1`, so the residue class of `g` is invertible in `R_q`.

This is the key algebraic fact for the active fold schedule: every nonzero challenge polynomial of degree at most `4` is automatically a unit in the live quotient.

## 2. Exact Five-Challenge Fold Schedule

For fixed verifier key `vk` and child instances `(left, right)`, the backend forms the fold transcript exactly as in `derive_fold_challenges` in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), then derives five indexed 64-bit XOF words and reduces each word with

```text
reduce_fold_challenge(raw) = (raw mod (2^63 - 1)) + 1.
```

Call the resulting challenge tuple

```text
c = (c_0, c_1, c_2, c_3, c_4) ∈ [1, 2^63 - 1]^5
```

and the associated challenge polynomial

```text
χ_c(X) = c_0 + c_1 X + c_2 X^2 + c_3 X^3 + c_4 X^4 ∈ R_q.
```

Because each `c_i` is strictly positive, `χ_c(X)` is nonzero and has degree at most `4`. Corollary 1.2 therefore implies `χ_c(X) ∈ R_q^×`.

### Theorem 2.1: the active fold verifier is an exact canonicalization check

For fixed `(vk, left, right)`, there is at most one accepted tuple

```text
(proof.challenges, proof.parent_rows, proof.parent_commitment_digest,
 proof.parent_statement_digest, proof.proof_digest, parent).
```

Proof sketch:

1. `verify_fold` recomputes `expected_challenges = derive_fold_challenges(vk, left, right)` and rejects unless `proof.challenges == expected_challenges`.
2. It recomputes `expected_rows = left.rows + χ_c(X) · right.rows` row by row in `R_q` and rejects unless `proof.parent_rows == expected_rows`.
3. It recomputes the folded commitment digest from `expected_rows` and rejects unless both `parent.witness_commitment` and `proof.parent_commitment_digest` match it.
4. It recomputes the folded statement digest from the child statement digests, `c`, and the parent commitment digest, and rejects unless both `parent.statement_digest` and `proof.parent_statement_digest` match it.
5. It recomputes `fold_proof_digest` from the full public transcript and rejects unless `proof.proof_digest` matches.

So acceptance is equivalent to equality with one deterministic recomputation path. There is no hidden-witness extractor and no Neo/SuperNeo CCS soundness claim here. The exact theorem for the active fold layer is canonicality plus the random-oracle challenge law below.

### Theorem 2.2: exact random-oracle bound for the implemented five-challenge rule

Model each indexed BLAKE3 XOF call as an independent uniform `64`-bit word. Since

```text
2^64 = 2(2^63 - 1) + 2,
```

every value in `[1, 2^63 - 1]` has either `2` or `3` preimages under

```text
raw ↦ (raw mod (2^63 - 1)) + 1.
```

Hence, for every fixed transcript,

```text
Pr[c_i = y] <= 3 / 2^64
```

for every `y ∈ [1, 2^63 - 1]`, and the full indexed five-tuple satisfies

```text
Pr[c = t] <= 3^5 / 2^320.
```

Therefore the exact min-entropy of the active challenge tuple is at least

```text
H∞(c) >= 320 - 5 log2(3) = 312.075187...
```

and the exported integer bound is

```text
transcript_soundness_bits = floor(320 - 5 log2(3)) = 312.
```

For the conservative receipt-root fan-in cap `max_claimed_receipt_root_leaves = 128`, the repo applies the explicit union bound

```text
composition_loss_bits = ceil(log2 128) = 7,
transcript_floor_bits = 312 - 7 = 305.
```

This is the mathematically correct replacement for the old blanket `/2` halving rule. It is a theorem-backed bound on the exact indexed challenge-tuple distribution of the implemented schedule, not a claim that the fold layer is a CCS soundness protocol.

## 3. Exact Deterministic-Commitment Reduction

The live product path does not expose a public opening object. It reconstructs the commitment deterministically from the canonical public tx view and serialized STARK public inputs, packs that witness with `GoldilocksPayPerBitPacker`, expands the packed bitstream into `8`-bit digits, and embeds those digits coefficientwise into ring elements before applying the deterministic commitment matrix in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs).

### Lemma 3.1: exact live message length for `TxLeafPublicRelation`

The active `TxLeafPublicRelation` witness schema in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) contains exactly

```text
bits_live = 4935
digits_live = ceil(4935 / 8) = 617
ell_live = ceil(617 / 54) = 12
```

ring elements after the implemented pack-then-digit-expand embedding.

So the exact live deterministic commitment class is a strict sub-class of the manifest-owned conservative cap `M = 76`. The repo keeps `M = 76` in the exported claim because the manifest is allowed to zero-pad messages up to that length, but the current `TxLeafPublicRelation` occupies only `12` ring elements.

### Theorem 3.2: accepted deterministic-commitment collisions reduce directly to BK-MSIS

Fix the live deterministic commitment matrix `A ∈ R_q^{11 x 76}` derived from the active parameter fingerprint. Let `M_live ⊂ R_q^76` be the exact set of zero-padded message vectors produced by the shipped public-witness reconstruction path. Suppose an adversary outputs distinct `m, m' ∈ M_live` with

```text
A m = A m'.
```

Define

```text
z = m - m'.
```

Then:

1. `z != 0` because `m != m'`.
2. `A z = 0` by linearity.
3. Every coefficient of `m` and `m'` lies in `[0, 255]`, so every centered coefficient of `z` lies in `[-255, 255]`.
4. Therefore

   ```text
   ||z||_∞ <= 255.
   ```

5. In the conservative manifest-owned ambient dimension `76 * 54 = 4104`,

   ```text
   ||z||_2 <= ceil(255 * sqrt(4104)) = 16336.
   ```

Thus every accepted collision in the exact live deterministic commitment class yields a valid nonzero witness for the exact bounded-kernel instance

```text
BK-MSIS(q, n = 54, k = 11, ell = 76, B_inf = 255, B_2 = 16336).
```

There is no rewinding, guessing, or hybrid loss in this reduction, so the in-repo reduction loss is exactly

```text
commitment_reduction_loss_bits = 0.
```

### Remark 3.3: exact live subclass versus conservative exported cap

For the shipped `TxLeafPublicRelation`, the exact live ambient coefficient dimension is only

```text
m_live = 12 * 54 = 648,
B_2,live = ceil(255 * sqrt(648)) = 6492.
```

That exact live instance is strictly harder than the conservative exported `76`-element cap. The repo keeps the larger `76`-element instance because that is the manifest-owned compatibility envelope and therefore the safe public claim surface.

## 4. Zero-Loss Flattening To Coefficient-Space SIS

Let

```text
coeff : R_q -> F_q^54
```

be the coefficient map in the basis `(1, X, ..., X^53)`. Because `R_q` is a quotient of degree `54`, `coeff` is an `F_q`-linear isomorphism of vector spaces.

For each `a ∈ R_q`, let `T_a ∈ F_q^{54 x 54}` be the matrix of the `F_q`-linear map `u ↦ a · u` in that coefficient basis. For `A = (a_ij) ∈ R_q^{11 x 76}`, define the block matrix

```text
A_flat = (T_aij) ∈ F_q^{594 x 4104}.
```

### Theorem 4.1: exact equivalence of the ring/module kernel and the flattened kernel

For every `z ∈ R_q^76`,

```text
A z = 0 in R_q^11
iff
A_flat coeff(z) = 0 in F_q^594.
```

This is immediate from the definition of `T_a` and block-matrix multiplication.

### Theorem 4.2: the flattening is zero-loss on the claimed bounded class

Interpret each admissible coefficient in centered form in `[-(q-1)/2, (q-1)/2]`. For the bounded-kernel class above, every centered coefficient already lies in `[-255, 255]`, far below `q/2`. Therefore:

1. the centered lift is unique,
2. the coefficient map is injective on the claimed witness set,
3. the Euclidean norm is preserved exactly:

   ```text
   ||z||_2 = ||coeff(z)||_2.
   ```

So the exported flattened SIS instance is not an approximation to a different normed problem. It is the same bounded witness set written in coefficient coordinates. The in-repo flattening loss is therefore exactly zero.

## 5. Concrete Security Arithmetic

The active exported conservative instance is:

```text
n_eq = 11 * 54 = 594
m = 76 * 54 = 4104
q = 18446744069414584321
B_2 = 16336.
```

The repository's explicit Euclidean SIS line computes:

```text
log2(q) = 63.9999999996641...
log2(B_2) = 13.9957671508778...
log_delta = log2(B_2)^2 / (4 n_eq log2(q))
          = 0.0012881516870700...
d = floor(sqrt(n_eq log2(q) / log_delta)) capped at m
  = 4104
delta = 2^((log2(B_2) - (n_eq / d) log2(q)) / (d - 1))
      = 1.0007998309696493...
```

Using the exact `beta_from_root_hermite_factor` search implemented in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), the first BKZ block size whose reduction-delta beats this target is

```text
β = 3294.
```

The exported cost lines are then

```text
classical_bits = floor(0.2920 * β) = 961
quantum_bits   = floor(0.2650 * β) = 872
paranoid_bits  = floor(0.2075 * β) = 683.
```

So the exact in-repo binding claim for the active conservative instance is

```text
commitment_binding_bits = 872.
```

## 6. Consequence For The Exported Claim

Combining Theorem 2.2 and Theorem 3.2 with the zero-loss flattening of Section 4 gives the active conservative repository floor:

```text
transcript_soundness_bits = 312
composition_loss_bits = 7
transcript_floor_bits = 305
commitment_binding_bits = 872
soundness_floor_bits = min(305, 872) = 305.
```

This note does **not** prove Neo/SuperNeo CCS knowledge soundness. It proves the exact active GoldilocksFrog fold canonicalization law, the exact deterministic-commitment collision reduction the repo claims, the exact coefficient-space flattening, and the concrete arithmetic of the active conservative exported instance.
