# SMZ9 single-proof privacy: constructive route and checked boundary

Status: research argument, not a zero-knowledge theorem or release authorization.
The active target is the unchanged self-contained SMZ9 proof. Nothing here changes
the proof carrier, permits a sidecar authority, or grants concrete SHA-512 security.

## Result obtained

`SmallWoodV8Smz9SingleProofPrivacy.lean` proves an exact simulator-side prerequisite:
the final PIOP input retains all 3,045 field coefficients sampled in the simulator's
last two matrix draws. Their projection is an explicit left inverse, including the
runtime alternating block offsets. The ideal rejection-sampler law supplies their
joint uniform distribution. Consequently the final input has point mass at most
`p^-3045` in this ideal fresh-coin stage, and the checked finite-fiber theorem gives
the conservative bound `2^-512` after any injective encoding. Here
`p = 2^64 - 2^32 + 1`.

This result allows the earlier state to contain the already selected `h_piop`,
its opening points, the Merkle coins, and every earlier field draw. All reconstructed
low coefficients and the digest prefix may depend arbitrarily on the new highs.
It does **not** identify a real conditional quantum state with that classical
fresh-coin experiment. In particular it does not condition on subsequent queries,
rejections, or disclosures involving those coefficients.

The same module also proves the source-shaped LVCS 240/2,560-coordinate
triangular feedback law, including its fixed-head interpolation offset and an
abstract failure branch. It starts from the proved ideal rejection-sampler
output law, with fixed public context and an admissibility-certified selector.
This closes that local algebraic feedback pattern, not refinement of the runtime
selector or its error behavior, and leaves earlier commitment feedback open.

Finally, the module checks a finite obstruction: input entropy and uniformity of
the programmed target, by themselves, do not license target-first reprogramming.
The following constructive route separates those completed steps from the
remaining joint laws.

## Exact runtime chronology and retained words

The honest prover samples its witness interpolation coins, then five pairs of
nonlinear/linear masks, then commits through PCS and DECS. Only afterward does it
derive PIOP challenges, hash the final PIOP input, and choose opening points.
See `circuits/transaction/src/smallwood_engine.rs:5036–5118`.

The typed whole-view simulator instead chooses `final_piop_output` first, derives
the admissible nonce/openings, samples its algebraic views and Merkle material,
and finally samples five nonlinear high rows of length 483 and five linear high
rows of length 126. See `smallwood_engine.rs:7240–7357`. These are distinct
sequential `CryptoRng` draws. Their independence and uniformity belong to the
ideal sampler model or an additional RNG assumption/refinement, not to the
runtime interface marker itself. Even in that ideal model the **complete input**
depends on the output through the earlier opening points and reconstructed
coefficients.

`poly_restore` copies high coefficients directly to the output tail
(`smallwood_engine.rs:16435–16459`). Final PIOP reconstruction uses six nonlinear
evaluations and seven linear evaluations. Its linear correction has degree six,
so it cannot change linear coefficients 7 through 132. The transcript appends all
489 nonlinear coefficients and linear coefficients 1 through 132, after an
eight-word digest prefix (`smallwood_engine.rs:10059–10157`).

For repetition `r < 5`, zero-based final-word positions are:

| Sampled coordinates | Inclusive positions | Count |
|---|---|---:|
| Nonlinear highs | `8 + 621r + 6` through `8 + 621r + 488` | 483 |
| Linear highs | `8 + 621r + 495` through `8 + 621r + 620` | 126 |

The proof of injectivity uses these positions, not equality of cardinalities or
a presumed hiding map. Rust-to-Lean serialization refinement remains separate.

## The exact reprogramming theorem boundary

Grilo–Hövelmanns–Hülsing–Majenz, *Tight adaptive reprogramming in the QROM*,
Theorem 2.1, uses a history-selected classical distribution `p_r` to sample
`(x,x')`, then draws an independent uniform `y` and programs `H(x)=y`. The
distinguisher receives `x,x'` and retains coherent oracle access. Let `qhat_r`
count prior queries and `pmax_r = E[max_x p_{r,X}(x)]`. Its bound is
`Σ_r (sqrt(qhat_r*pmax_r) + qhat_r*pmax_r/2)`.
The fixed-distribution specialization is Proposition 2. This is not a theorem
about an arbitrary supplied conditional-entropy number. Its Fiat–Shamir proof
first reprograms an honest commitment followed by an independent challenge,
then invokes a separate honest-verifier zero-knowledge transcript law.
[Primary source: Figure 2, Theorem 2.1, Proposition 2 and §4.1](https://arxiv.org/html/2010.15103).

In particular, current simulator entropy cannot alone substitute for the theorem's
independent-output sampling order. Consider independent uniform bits `Y,O` and
an arbitrarily long fresh nonce `R`. Set `X=(R,Y)`. The unchanged random oracle's
first response at `X` is `O`; the programmed oracle's response is `Y`. After
receiving `X`, a distinguisher makes one query and compares its response with
the second component. Acceptance probabilities are `1/2` and `1`, despite
arbitrarily high entropy in `X` conditional on the already selected `Y`, and
zero pre-programming queries. The new Lean module derives those probabilities
from explicit finite PMFs; they are not inputs to a security record.

This refutes the proposed **generic inference**, not SMZ9 privacy. A separate
honest-to-simulated joint-law argument could make the target-first implementation
equivalent to a correctly ordered hybrid.

## Constructive honest-to-simulated hybrid, with exact missing claims

The following is a proposed derivation. Each unproved transition is identified;
none is an assumed complete-view bound disguised as an implementation receipt.

### H0 to H1: randomize honest taped-leaf outputs in chronological order

For each honest leaf, hold its salt/index/field payload fixed, sample its fresh
512-bit tape, form the exact domain-separated input, and replace its ordinary
hash result by an independent uniform digest with a coherent programmed overlay.
This is the correct input-before-output order for adaptive reprogramming. The
input has a direct tape projection. Every one of the `2^23` honest leaves must be
covered; the later twenty opened leaves are not the complete commitment history.

Required proof: implement this experiment with the adversary's retained quantum
state and all intervening oracle calls, justify the fresh distribution at each
call, and apply the quantitative theorem. Exact domains and input encoding are
at `smallwood_engine.rs:11687–11723`; actual tape sampling and leaf calls are at
`smallwood_engine.rs:11096–11160`. The real RNG is an additional assumption.

This hybrid makes the leaf digests independent of the field payloads as a
sampling law. It does not erase the witness-dependent inputs from the overlay.
The adversary can still query them coherently; they cannot be dropped by fiat.

### H1 normalization: delay leaf overlays and expose the triangular schedule

An honest proof request is treated as one invocation with no external adversary
call interleaved between its internal steps. Subject to exact domain separation,
leaf-overlay writes can potentially be delayed until the invocation's end:
subsequent internal queries address other domains. This permits independent leaf
digests and the resulting Merkle root to be sampled before the field coins.

Required proof: equality of the two quantum executions, including domain
disjointness, repeated-input behavior, malformed inputs, every internal query,
and the same final coherent overlay. Merely omitting a classical query log is
not that proof. If this scheduling premise is not the intended oracle model,
the interleaved model requires a different argument.

Root independence alone is **insufficient**. The PCS transcript also contains all
five masked DECS polynomials (`smallwood_engine.rs:11160–11195,11505–11529`). For
fixed root-derived gamma and LVCS rows, reparameterize each full DECS mask by
its combined polynomial:

`D_k = gamma_k · LVCS_polynomials + DECS_mask_k`.

This is coefficientwise translation of the fresh degree-387 mask. It can make
the full `D_k` uniform independently of the LVCS rows. The inverse subtracts the
same combination. Required proof: compose this reparameterization with the
delayed leaf overlay, not merely prove uniformity at externally fixed gamma.

### H2: randomize the final PIOP output on the honest side

After the independent root and full DECS polynomials determine `hash_fpp`, the
PIOP combination coefficients are fixed. Reparameterize the nonlinear mask by
the full nonlinear output polynomial, and the sum-zero linear mask by its 132
nonconstant output coefficients. Their explicit affine inverses are the relevant
existing algebraic ingredients. With all earlier query-dependent values fixed,
the 3,105 coefficients provide a fresh final-input distribution; only **then**
sample a uniform final digest and program its domain-separated input.

Required proof: the exact reordering/triangular change of variables makes these
coins fresh at the reprogramming interface, while retaining every dependency in
the delayed leaf table as side information. The previously proved fixed-challenge
algebraic law and the new simulator-side high-tail law do not establish that.
Any adversary/prover oracle queries used to construct the interface must be
charged, not hidden inside a purportedly query-free distribution sampler.

### H3: transform the opened algebraic view without fixing future challenges

The independent final digest determines admissible PIOP opening points.
Witness interpolation and PCS partial-evaluation maps can then be inverted at
those points. The remaining LVCS step is more subtle: the DECS opening indices
depend on the combi-heads and the **first 240 combi-tail output words**, whereas
the remaining **2,560 subset-evaluation words** are produced at those indices.
See `smallwood_engine.rs:11543–11565` for the challenge input.

The appropriate algebraic lemma is triangular, not a fixed-challenge
assertion. For bijections `F_c : Coins ≃ A × B`, if the first coordinate is the
same function `a(r)` for every `c`, then

`r ↦ F_(f(a(r)))(r)`

has inverse `(a,b) ↦ F_(f(a))^-1(a,b)`. Thus the challenge may depend on an
earlier retained output of the same coins. The coordinator's
`SmallWoodV8Smz9TriangularAlgebraicLaw.lean` proves this generic lemma, and the
new single-proof module now instantiates it with the existing exact LVCS map.
It additionally proves:

- The retained first coordinate is exactly the columnwise `C · tails` matrix
  product. The selected-row and complement sums enumerate all 140 rows.
- The second coordinate includes the fixed-head contribution at Lagrange nodes
  `20…387`; its tail contribution uses nodes `0…19`, exactly matching the runtime
  left rotation. The head offset is allowed to depend on the selected targets.
- Any selector from the retained 240 words to admissible targets gives the full
  joint uniform law on the 240 early and 2,560 late words.
- An abstract selector returning `Option` retains both success and `none`, so
  this local law does not silently condition on success. The active Rust DECS
  sampler can exhaust its fifty candidates (constant at `smallwood_engine.rs:125`,
  consumed at `12837`; rejection at `12844–12865`) and returns `Err` before a
  proof exists. Refining that pipeline to the proof-carrying selector and mapping
  its errors to the experiment remain open. The theorem's observation
  `(early, none)` is not a claim that the runtime discloses those early words on
  error. An older Rust comment says forty; the executable constant governs.
- Different committed heads have the same local joint output law when their
  public combination heads and other public selector inputs are matched.

These are checked local algebraic statements. The target-admissibility proofs
remain explicit. More importantly, the honest protocol's earlier PIOP points
and public selector inputs depend on the preexisting commitment. Their joint
freshness must still be supplied by H0–H2, not inferred by fixing those values.
The local theorem therefore does not yet identify the complete honest view with
the witness-free simulator. Generic fixed-challenge bijectivity alone remains
insufficient, as `SmallWoodV8Smz9SequentialAlgebraicLaw.lean` demonstrates.

### H4: remove witness-dependent hidden leaf inputs; then address compact trees

After the algebraic transformation, opened leaf payloads are determined by the
witness-free view. Unopened leaf inputs still contain witness-dependent data.
Their tapes are not disclosed. A hidden-point quantum oracle-change lemma could
remove those overlay entries once the whole public view is fixed, provided the
unopened tapes remain fresh in the actual retained-state experiment. This is
not directly the above adaptive-reprogramming game, which reveals its sampled
position; known targets and unrevealed inputs require their own precise theorem.

An initial witness-free simulator may retain an expensive full tree of random
leaf digests and ordinary internal hashes. It avoids assuming the compact
simulator already has the same law. Replacing unopened subtrees by the executable
compact simulator's programmed random child pairs then needs a separate
hidden-subtree distribution and quantum-programming argument. Root/path replay
success does not discharge it.

These hidden-leaf and compact-subtree transitions are currently unproved. They
must account for collisions/conflicts and the adversary's complete coherent
oracle interface, not only queries performed by the canonical verifier.

## Current acceptance boundary

The new module is a real distribution/projection theorem and a checked
counterexample, not an end-to-end privacy proof. It imports no arbitrary
real/simulated acceptance-probability fields and grants no review or production
constructor. The code's successful final overlay replay, including the empty
`prior_sha512_queries` value at `smallwood_engine.rs:7721`, checks its selected
classical execution only.

To close single-proof privacy, the transitions above must define one coherent
honest/hybrid/simulated experiment and derive its distinguishing bound. Adaptive
multiple-proof composition, runtime refinement, concrete primitive assumptions,
and release authorization remain subsequent independent obligations.

Verification command for the owned module:

```sh
cd formal/crypto
lake env lean HegemonCrypto/SmallWoodV8Smz9SingleProofPrivacy.lean
```

The direct check passed on 2026-09-06 local time using the existing dependency
cache. Axiom audits of the entropy, finite counterexample, exact matrix/interpolation,
triangular-feedback, and abort-preserving sampler theorems reported only
`propext`, `Classical.choice`, and `Quot.sound`. The file contains no `sorry`,
axiom declaration, or `native_decide`. No Rust build, proof generation, shared
library output, or deployment was performed by this privacy lane.
