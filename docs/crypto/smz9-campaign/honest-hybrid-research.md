# Honest-side SMZ9 leaf and DECS-mask hybrid

## Result and boundary

This research closes an exact change-of-variables step **inside an ideal
randomized-leaf experiment**. It does not prove that replacing honest SHA-512
leaf hashes by independent digests is indistinguishable. That initial QROM
transition remains necessary.

The new `SmallWoodV8Smz9HonestHybrid.lean` constructs the chronological experiment
and proves an equal reordered experiment. The earlier state, random leaf
material, complete DECS response, reconstructed original masks, and arbitrary
final observations can all be retained. A projection of that equality derives
the LVCS-tail freshness needed by the local triangular law introduced at commit
`2fdab7e0`; freshness is not assumed by fixing the later PIOP context. The
composition preserves both an earlier-stage abort and a later DECS-sampler abort.

A separate exact theorem permits leaf-only oracle overlays to be delayed across
finite adaptive non-leaf computations, preserving every input/answer and the
final oracle table. A coherent non-leaf query is also modeled explicitly as a
complex-linear, invertible basis permutation preserving squared Hilbert norm.
Its equality under leaf overlays holds only on the non-leaf query subspace.

The source and methods boundaries remain unchanged: one self-contained SMZ9
proof must remain independently verifiable through every lifecycle path. No
wire, runtime, manifest, registry, source capability, or release authority is
changed by these research files.

## The chronological experiment

Let `B` contain the state before new LVCS tails are drawn: the statement, salt,
witness polynomials, PIOP masks, PCS head coins, and the original oracle table.
Its distribution may be arbitrary. It must not contain these newly sampled
tails or DECS masks. This is enforced by the order of the defined experiment.

The randomized-leaf experiment samples:

1. `B` from its supplied earlier-state law.
2. `U`, the 140-by-20 LVCS tail array, from the proved ideal rejection-sampler law.
3. `M`, the five-by-388 DECS coefficient array, from that same ideal sampling model.
4. Independent leaf material `Y`; the concrete ideal leaf law is one uniform
   512-bit digest per each of the `2^23` positions.

The general theorem permits any independent `Y` law, so it includes that full
uniform product without assuming a special root distribution. The root, its
binding hash, and the DECS challenge matrix `Gamma(B,Y)` are computed from `B,Y`.
The leaf-programmed oracle is treated separately below.

Let `A(B)` be the 140-by-368 committed head array. Rotation makes each row's
interpolation values `U[row,0…19]` followed by `A[row,0…367]`. Define the
unmasked DECS coefficient vector `C(B,Y,U)` by precisely the source sequence:
multiply these 388-value rows by `Gamma`, interpolate each combined row at
nodes `0…387`, and take all 388 coefficients. The response is

`D = C(B,Y,U) + M`.

The mathematical formula is coefficientwise Lagrange interpolation, matching
the field computation of `mat_mul` followed by `interpolate_consecutive` at
`smallwood_engine.rs:11169–11184`. The coefficient-vector mask allocation
matches the five `random_poly(387)` calls at `11019–11022`. Actual compiled
Rust-to-Lean refinement and OS randomness are not proved by this formula match.

## The exact coupling

For fixed `B,Y,U`, the map `M ↦ D` is a translation on the entire five-by-388
coefficient space. Its explicit inverse is

`M = D - C(B,Y,U)`.

The theorem `randomized_leaf_honest_joint_reparameterization` derives equality
with the experiment that samples

`B → Y → uniform D → uniform U`,

then reconstructs `M` using that inverse. It uses finite product-draw
commutation and the previously proved ideal rejection-output law. There is no
assumed honest/simulated equality, oracle-distance bound, or uniform-view field.

Crucially, the theorem permits any observation of `(B,Y,U,M,D)`. Thus it retains
the original mask and the final leaf overlay by evaluating those same functions
with the reconstructed mask. This is stronger than comparing the response
alone, but it is **not** independence of the complete retained observation.

The public projection `(B,Y,D, public(B,Y,D), U)` factors with a fresh uniform
`U` at the end. Therefore the root, root binding, DECS gamma, full PCS response,
`hash_fpp`, `h_piop`, and PIOP opening outcomes can be generated before that tail
draw whenever they follow the verified source dependency below. The theorem
derives this statement for a generated context, not an externally fixed one.

The exact source reason is that `pcs_commit_transcript_words` contains only the
root binding followed by the complete five DECS polynomials
(`smallwood_engine.rs:10380–10404`). `piop_run` receives that transcript and
the witness/PIOP polynomials already contained in `B`
(`smallwood_engine.rs:5077–5089,10003–10035`). For this narrow variation of LVCS
tails, preserving `B,Y,D` therefore preserves the full PIOP transcript, its hash,
nonce and opening points. An additional PIOP-mask translation is **not needed
for this tail-only independence result**. It remains relevant to broader
witness/PIOP-mask changes and the final-input reprogramming reduction.

The later DECS opening indices are different: they depend directly on the
retained 240 combination-tail outputs. They are handled by the triangular
theorem, not asserted independent of `U`.

## Composition with the actual local LVCS block

`randomized_leaf_then_lvcs_joint_law` composes the generated-prefix result with
the source-shaped LVCS theorem. A generated stage contains PIOP points, an
admissible fallback used only on discarded branches, and the later optional
DECS selector. The stage may itself be absent after an earlier failure.

For every generated context, the actual `C · U` combination tails and the
selected 128-row interpolation values have the same law as independent uniform
240/2,560-word output blocks, with the same optional selector applied to their
early block. Neither failure level is conditioned away. The head interpolation
offset at nodes `20…387` is included by the imported local theorem.

The stage constructor is still a mathematical interface. It does not prove
the Rust sampler's success/admissibility checks, exact error representation,
matrix-rank checks, or byte-level challenge derivation. Those are explicit
refinement obligations. The point here is the new honest-side source of the
fresh-tail premise, conditional on the randomized-leaf hybrid.

## Delaying leaf-only oracle programming

The actual SMZ9 SHA-512 input is

`LE64(profile length) || profile || LE64(role length) || role ||`
`LE64(word count) || LE64(words) || LE64(counter)`.

The common profile is `hegemon.smallwood.poseidon2-v8.smz9.sha512.profile.v1`,
53 bytes. Key construction copies each component without normalization
(`smallwood_engine.rs:5977–5989`); hashing uses that exact frame
(`4237–4252`). There is **no profile-presence byte** in this oracle input. The
presence marker in `hash_smallwood_sha512_oracle_key_v1` is receipt hashing,
not the actual oracle grammar.

The strict leaf role is `hegemon.smallwood.strict-zk.merkle-leaf.v1`, 42 bytes.
The enumerated subsequent roles have lengths 35, 36, 37, 40, 41 or 44. The new
byte lemma distinguishes them already at byte 61, the first role-length byte,
irrespective of all later payload bytes. It proves input separation, not
collision resistance of the resulting digests. The tags are copied from
`smallwood_engine.rs:124–159`, and SMZ9 preserves them through
`is_sha512_level5` / `transcript_domain` at `537–546,686–694`.

After the leaf batch finishes at `11155–11157`, honest proving makes only
non-leaf calls: internal Merkle hashing, root binding, DECS coefficients, PIOP
input/coefficient/final/opening hashes, and the DECS opening/index domains.
`decs_open` copies already computed evaluations, tapes and authentication paths
at `11229–11250`; it does not rehash leaves. The honest core returns at
`5154–5155`, and its wrapper encodes the proof. Verifier reconstruction does
rehash leaves, so verifier replay is outside this delay interval.

The finite `NonLeafProgram` model supports adaptive queries: each answer selects
the next computation. Induction proves equality of the complete query/answer
list and result with the overlay applied early or late. Both sides retain the
identical final oracle. For a fixed oracle, adding its response into a finite
query register is an explicit permutation; its complex-linear extension is
invertible and norm preserving. Leaf overlays give exactly the same operator
on the non-leaf input subspace.

This delay step requires an atomic honest invocation with no intervening
external leaf queries. It is a semantic reordering, not proof that the current
TLS replay machinery instruments the parallel prover: the overlay is
thread-local at `6045–6047`, while the honest SMZ9 leaf and node batches use
Rayon. A concrete scheduling/refinement proof must account for that. Internal
node inputs also need not be unique; role separation alone says nothing about
their repeated child pairs.

## The oracle correlation that remains

The programmed leaf input contains its actual row evaluations and actual
mask evaluations. Under the reordered experiment these depend on

`U` and `M = D - C(B,Y,U)`.

Thus the final overlay is still correlated with the tails, even though the
projected public prefix is independent of them. The arbitrary-observation
coupling preserves that correlation exactly. It does not remove it.

An external quantum distinguisher can query leaf inputs after receiving the
proof. The coherent non-leaf equality cannot be extended to those queries.
A full privacy proof still needs both the honest-hash to randomized-leaf
QROM transition and a justified treatment of hidden witness-dependent leaf
programs, including the actual retained quantum state. Compact-subtree
simulation, conflicts, complete multi-proof accounting, concrete primitives,
and production authorization remain separate obligations.

## Verification

Use the existing cache without emitting shared build products:

```sh
cd formal/crypto
lake env lean HegemonCrypto/SmallWoodV8Smz9HonestHybrid.lean
```

The complete module, including chronological coupling, generated-prefix/LVCS
composition, literal byte-prefix separation, adaptive trace delay and finite
complex-linear query lemmas, passes the direct Lean check. An axiom audit of
the seven corresponding endpoint theorems reports only `propext`,
`Classical.choice` and `Quot.sound` (the byte-separation and adaptive-trace
endpoints use only `propext`). There are no `sorry`, `admit`, custom axiom or
`native_decide` declarations. No runtime edit, proof generation, Git mutation
or production-state change is part of this work.
