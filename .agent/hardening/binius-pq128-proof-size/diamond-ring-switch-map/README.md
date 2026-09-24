# Diamond ZK BaseFold + DP24 ring-switch map

This is a source-only feasibility map for pinned Binius64 revision
`3f96163049f680b2909f6545690bd929f1b48c44`. It does not claim complete zero
knowledge, QROM security, a compiled backend, or a proof-size frontier point.

## Verdict

The closest algebraically real path is

```text
committed coefficients: B128
large opening field:    E256 = GhashSq256b
extension degree:       [E256:B128] = 2
strict repetitions:     two separate E256 protocol instances
```

This path can reuse one immutable packed-polynomial commitment across the two
instances, subject to the multi-opening padding rule below. It cannot reuse the
challenge-dependent sumcheck/FRI transcript without a new parallel-soundness
theorem. The conservative implementation shares only the input commitment and
runs every later message in two lockstep, domain-separated branches.

This is not yet a strict-ZK construction:

1. Diamond's 2025 zero-knowledge theorem covers the *large-field* Binary
   BaseFold IOPCS only. The paper explicitly leaves zero-knowledge
   ring-switching and a zero-knowledge higher-level PIOP to future work.
2. DP24 ring-switching is sound but sends a witness-dependent tensor-algebra
   element in the clear. Its theorem is not a simulator theorem.
3. The papers use a classical IOP/EPROM analysis. They do not provide the
   SHAKE256 QROM composition theorem required by Hegemon's strict lane.
4. Pinned Binius's current ZK channel is a different construction: it
   co-commits an equal-length random mask with the message. It does not add
   Diamond's query-count high-coefficient padding and its Merkle leaves are not
   BCS-salted. Its complete joint simulator is unproved, as recorded by the
   existing `m4-zk-outer-distribution-audit` and
   `m4-zk-joint-simulator-audit` certificates.

Accordingly, this is an implementation route with named theorem gates, not a
security promotion.

## Primary sources

- Benjamin E. Diamond, *Zero-Knowledge Polynomial Commitment in Binary
  Fields*, ePrint 2025/1015: <https://eprint.iacr.org/2025/1015>.
  Construction 4.1 defines the large-field ZK compiler; Theorems 4.2 and 4.3
  give soundness and perfect IOP zero knowledge; Section 4.1 requires the ZK
  BCS transform; Section 5 excludes ring-switching and higher-level PIOPs.
- Benjamin E. Diamond and Jim Posen, *Polylogarithmic Proofs for Multilinears
  over Binary Towers*, ePrint 2024/504:
  <https://eprint.iacr.org/2024/504>. Construction 3.1 and Theorem 3.5 are the
  ring-switch compiler and its soundness theorem; Construction 4.12 is Binary
  BaseFold; Construction 5.1 fuses the two sumchecks; Equation (42) is the
  concrete soundness bound.
- Ben-Sasson, Chiesa, and Spooner, *Interactive Oracle Proofs*, ePrint
  2016/116: <https://eprint.iacr.org/2016/116>. Section 3.2 salts each Merkle
  leaf with a fresh uniform `2*lambda`-bit string and includes that salt in an
  authentication opening.

The locally inspected PDFs have SHA-256 digests:

```text
2025/1015  b6db1430de0cd46cba2719b1d1b23ebdc0f0e14a8e546df767fd011800beaeaf
2024/504  e0c9dd03a2e9b4a9c6b88dd3df077db6400668a6e8234b877d046bc60c9949d9
```

## Why E256 fits and E384 does not

DP24 fixes an extension `L/K` of degree `2^kappa`. Packing consumes exactly
`kappa` Boolean variables: each chunk of `2^kappa` K-coefficients becomes one
L-coefficient. The tensor algebra `L tensor_K L` is represented by exactly
`2^kappa` L-elements.

Pinned `GhashSq256b` is exactly the required degree-two field:

- `crates/field/src/ghash_sq.rs:3-12` defines it as a pair of B128
  coefficients;
- `crates/field/src/ghash_sq.rs:51` constructs a genuine binary field;
- `crates/field/src/ghash_sq.rs:72-78` implements both the degree-two
  B128 extension and its F2 extension;
- `crates/field/src/ghash_sq.rs:93-109` gives canonical 32-byte serialization;
- `crates/field/src/packed_ghash_sq.rs` supplies width-1/2/4 packed arithmetic.

Thus `K=B128`, `L=E256`, and `kappa=1` meet DP24 exactly. Two adjacent B128
Lagrange coefficients pack into one E256 coefficient, so an `N`-variable B128
multilinear becomes an `(N-1)`-variable E256 multilinear without changing the
payload bits.

The cubic `E384/B128` has degree three. There is no integer `kappa` with
`2^kappa=3`, so it cannot consume an integral number of Boolean variables and
Construction 3.1 does not apply. The local type system hard-rejects the same
case: `ExtensionField::DEGREE` is defined as `1 << LOG_DEGREE` in
`crates/field/src/extension.rs:21-27`. Consequently:

- E384 cannot instantiate DP24 ring-switching;
- E384 cannot implement the pinned `ExtensionField<B128>` contract faithfully;
- three B128 coordinates cannot be substituted, because componentwise
  multiplication is a product ring with zero divisors.

A degree-four E512 extension would fit DP24 with `kappa=2`, but pinned Binius
does not contain such a scalar field. Its 512-bit types are packed registers,
not `GF(2^512)`.

## Exact paper interface for B128 -> E256

Let `K=B128`, `L=E256`, `d=[L:K]=2`, and let the original B128 polynomial have
`N` variables. Set `n=N-1`.

The missing generic interface is:

```text
pack_K_to_L:       K^(2^(n+1)) -> L^(2^n)
commit_L:          L^(2^n) -> commitment
ring_switch_send:  packed polynomial, point in L^(n+1) -> A=L tensor_K L
ring_switch_batch: A, fresh L challenge -> one L sumcheck claim
open_L:            commitment, point in L^n, L claim -> BaseFold proof
```

For degree two, `A` serializes as two E256 elements. Generic Construction 3.1
therefore adds exactly

```text
2 E256                 s_hat in A
2*n E256               degree-two sumcheck messages (two coefficients/round)
1 E256                 final packed-polynomial evaluation
```

or `32*(2*n+3)` bytes. DP24 Construction 5.1 fuses the ring-switch sumcheck
with BaseFold's sumcheck; in that fused form the irreducible ring-switch wire
increment is the two-element `s_hat`, or 64 bytes, before any ZK repair.

Pinned source is close but hard-coded to the wrong base pair:

- `crates/math/src/tensor_algebra.rs:29-110` is already generic over a base
  field and extension and can represent `TensorAlgebra<B128,E256>`;
- `crates/prover/src/ring_switch.rs` fixes `B1`, `B128`, a 128-row fold, and
  seven packing variables;
- `crates/verifier/src/ring_switch.rs:48-76` derives packing from the absolute
  degree of the verifier field and constructs `TensorAlgebra<B1,_>`;
- `crates/verifier/src/ring_switch.rs:104-123` likewise evaluates the
  indicator over `B1` rather than an associated base field;
- `crates/verifier/src/config.rs:10-27`, `verifier/src/verify.rs:226-313`, and
  both `prover/src/zk_config.rs` and `verifier/src/zk_config.rs` fix the whole
  production wrapper to B128.

The BaseFold/FRI core itself is field-generic enough for E256:

- both BaseFold compilers require only `F: BinaryField`;
- `GaoMateer` NTTs consume a `BinaryField`, and E256 supplies a trace-one
  element;
- transcript sampling deserializes the requested field type, so an E256
  challenge consumes 32 bytes;
- the Merkle tree hashes fixed-size serialized field elements.

The first code refactor should therefore parameterize the top-level proof
profile and ring switch over `(K,L)`, rather than inventing a new PCS.

## Diamond large-field ZK requirements

For an `n`-variable L-polynomial, inverse-rate log `R`, fold arity `theta`, and
`g` FRI repetitions, Diamond defines

```text
Q = g * 2^theta
```

as the number of initial-oracle point openings. The construction requires:

1. `Q` fresh high coefficients in the committed polynomial;
2. an initial domain of dimension `n+R+1` (one larger than non-ZK BaseFold);
3. a fresh fully random blind polynomial and its commitment;
4. one clear blind evaluation `s_blind`;
5. a fresh combination challenge and a virtual initial oracle;
6. the ordinary interleaved sumcheck/FRI on that virtual oracle;
7. a final degree-one message `(c0,c1)` instead of one constant;
8. the zero-knowledge BCS transform, with a fresh `2*lambda`-bit salt in every
   committed Merkle leaf and the salt revealed with each opened leaf.

At Hegemon's `lambda=128`, each opened leaf salt is exactly 32 bytes. A
SHAKE256-512 root or authentication node is 64 bytes, and an explicit E256
element is 32 bytes.

Pinned `encode_masked` is not this construction. It commits
`message || equal_length_mask` with `log_batch_size=1`; it does not add only
`Q` random high coefficients to the message polynomial. Pinned
`BinaryMerkleTreeScheme::compute_leaf_digest` hashes only the field values, so
there is no BCS salt field in either the commitment or opening grammar. This
alternate co-commitment may be worth proving, but it does not inherit Diamond
Theorem 4.3 or BCS Section 3.2 by inspection.

## Exact wire terms

`wire_terms.py` reproduces the following exact serializer terms.

For a pinned binary Merkle tree with depth `d`, `g` query leaves, digest bytes
`H`, and cap height `c=min(ceil(log2(g)),d)`, the authentication digest bytes
are exactly

```text
MP(d,g,H) = ((d-c)*g + 2^c) * H.
```

This matches `crates/iop/src/merkle_tree/scheme.rs:148-170`. A salted leaf
opening carrying `2^a` field elements costs additionally

```text
g * (2^a * B + S)
```

where `B=32` for E256 and `S=32` at lambda 128. The salt is per leaf, not per
field element.

For a fixed BaseFold schedule with existing opened-tree depths
`d[0],...,d[T-1]`, Diamond's transformation makes each existing tree one level
deeper and adds one blind initial tree of depth `d[0]+1`. Relative to the
unsalted non-ZK opening, and assuming the fold schedule/early-termination point
does not change, its exact additional bytes are

```text
root        H
clear       2*B                         (s_blind and the extra final coefficient)
blind vals  g * 2^theta * B
auth        sum_i (MP(d[i]+1)-MP(d[i])) + MP(d[0]+1)
salts       (T+1) * g * S
```

If the optimizer changes the schedule, use the absolute per-tree formula
instead; do not apply the delta shortcut. Challenges are transcript-derived
and contribute zero proof bytes.

The exact DP24 query count for a target query-phase error `2^-b` is

```text
g = ceil(b / -log2((1 + 2^-R)/2)).
```

At `R=3`, one 264-classical-bit run needs 319 query leaves. Two 132-bit runs
need 160 leaves each, 320 total. This equality in query count does not make
the two-run wire equal: all challenge-dependent roots, folded trees, clear
messages, salts, and authentication structures are duplicated unless a
separate vector-commitment theorem permits co-commitment.

## Sharing one commitment across two E256 repetitions

Sharing only the immutable input commitment is compatible with classical
parallel soundness, provided the implementation and proof enforce all of the
following:

1. The packed polynomial and its commitment are fixed before either branch's
   coins are sampled.
2. At every round, both prover messages are absorbed before the two fresh,
   domain-separated challenges are sampled. This prevents either branch from
   choosing its current polynomial after seeing the other branch's current
   coin.
3. Every challenge-dependent blind polynomial, sumcheck message, fold oracle,
   terminal value, and query set is branch-local.
4. Acceptance is the conjunction of both complete verifier executions. The
   implementation never represents the pair as `E256 x E256` field
   arithmetic; that product has zero divisors.
5. The per-branch soundness statement holds conditionally for every fixed
   auxiliary transcript. Under this condition, the usual tower-property
   argument gives `epsilon^2` for two independent branches.

There is an additional ZK constraint. Diamond pads the committed polynomial
with as many high random coefficients as the number of opened initial points.
A commitment reused by two branches must therefore allocate for the union of
both query sets:

```text
Q_total <= 2 * g * 2^theta.
```

Using only the one-branch `Q` padding lets the second branch expose more
independent initial-codeword functionals than Lemma 4.4 can simulate. If
`Q_total <= 2^n`, the same doubled domain still has enough coefficient slots;
the cost is randomness and prover work rather than another tree-depth bit.
A formal multi-opening version of Lemma 4.4 must handle duplicate and adaptive
query locations.

The original input tree can use one authentication multiproof over the union
of the two independent query sets. This is a serialization optimization, not
a soundness shortcut. Sharing later fold roots is not admitted by the cited
theorems. A root over paired branch values may be plausible as a binding
vector commitment, but it needs a new theorem and ZK simulator and reveals both
branch values at every opened union index.

For a relation polynomial of degree at most `2^120`, one uniform E256 check has
Schwartz-Zippel error at most `2^-136`; two conditionally independent checks
have at most `2^-272` classical error. This calculation covers only that fixed
algebraic event. It does not square omitted ring-switch, sumcheck, FRI,
commitment, Fiat-Shamir, multi-target, ZK, or abort terms, and it is not a QROM
theorem.

## Required theorem and code gates

Implement in this order, retaining an empty strict frontier throughout:

1. **Profile genericity.** Introduce an explicit `(K,L)` proof profile and
   instantiate `(B128,GhashSq256b)`. Do not change the consensus verifier.
2. **Degree-two ring switch.** Generalize prover/verifier ring-switch functions,
   tensor-indicator evaluation, packing, and serialization. Add differential
   tests against a naive B128/E256 Construction 3.1 implementation.
3. **Faithful large-field ZK BaseFold.** Implement query-count high padding,
   a fresh blind polynomial, virtual folding, and salted SHAKE256-512 Merkle
   leaves. Add exact simulator-distribution tests; do not relabel the current
   equal-mask channel.
4. **ZK ring-switch composition.** Prove and implement a simulator for the
   clear `s_hat` tensor-algebra message and the fused sumcheck. A promising
   construction may blind the packed polynomial before ring-switching, but it
   needs a theorem that the blind is a valid packed K-polynomial and that the
   full transcript is simulatable from only the public evaluation.
5. **Two-branch driver.** Share only the input commitment, allocate
   `Q_total`, absorb both messages before each challenge pair, and use explicit
   branch labels in SHAKE256. Add adversarial tests that swap/reuse branch
   messages and challenges.
6. **QROM composition.** Supply a reviewed theorem for salted Merkle hiding,
   Fiat-Shamir, parallel repetition, multi-target hashing, and aborts under
   SHAKE256. Neither cited paper supplies it.
7. **Wire authority.** Populate serializer counters with explicit E256 values,
   64-byte roots/nodes, and 32-byte salts; compare the produced length against
   `wire_terms.py`; exact-consume and mutation-test two independent proofs.

Only after all seven gates may a measured byte count be considered for the
strict frontier.
