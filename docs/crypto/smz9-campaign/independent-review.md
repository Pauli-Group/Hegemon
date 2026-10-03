# Independent review: HGV8RP03 / SMZ9 extraction and simulator ordering

Date: 2026-09-06 (America/Edmonton). Scope: the frozen HGV8RP03 / SMZ9 profile 6, the current Lean event lemmas and extraction interfaces, the Rust prover/verifier/simulator ordering, the campaign's soundness and privacy arguments, and the new obstruction, published-bound, and triangular-law modules. This was an adversarial source review. It did not edit or execute the new Lean modules. At this review snapshot they are wired into the umbrella import and credited inventory, but the coordinator's full gate is still pending; its eventual outcome belongs in the living ExecPlan. This review grants no production authority.

## Verdict

**No-go for a complete soundness, privacy, PQ128, or production claim.** The reviewed work adds useful ideal-event and obstruction lemmas, but it does not produce either of the two required end-to-end reductions:

1. accepted SMZ9 proof bytes to an extracted HGV8RP03 witness satisfying the exact relation; or
2. the real SMZ9 proof view to the simulator's view in one adaptive SHA-512/QROM experiment.

The most important finding is a scope contradiction in the current degree-enforcement accounting. The original SmallWood DECS binding theorem charges a family of interpolation supports. The current `p^-5` SMZ9 lemma is valid only for a different, stronger-premise event: a fixed, fully materialized committed oracle whose five affine combinations are globally degree-387 codewords. It cannot be substituted for the paper's compiled-proof extraction error without a new theorem. Consequently, the current 288.797-bit interactive and 157.212-bit ideal-CMS figures are conditional arithmetic, not end-to-end security evidence.

The new privacy counterexample is also valid at its stated level: large input entropy conditional on a previously selected program output does not, by itself, justify programming a random oracle to that output. It invalidates an entropy-only reduction route, not SMZ9 privacy itself.

Capability must remain `None`; `production_eligible` and every independent-review/deployment receipt must remain false.

## 1. Published SmallWood degree enforcement versus the current `p^-5` term

The primary-source result is unambiguous. [SmallWood ePrint 2025/1085](https://eprint.iacr.org/2025/1085.pdf), Theorem 1 and its proof on printed pages 7-9, give the uniform-matrix DECS binding term

```text
epsilon_decs = choose(N, d_decs + 2) / |F|^eta + hash-collision term.
```

Equation (14), printed page 25, repeats

```text
epsilon_1 = choose(N, d_decs + 2) / |F|^eta.
```

The paper's proof explains the factor. Its extractor obtains a matrix-dependent set `E_openable`, observes that failure supplies **some** subset `E'` of size `d_decs + 2`, and takes a union bound over all such subsets. This is the accepted-opening/compiled-commitment event, not a single residual fixed before the challenge matrix. `E_openable` is syntactically defined using both the matrix and response, but the paper notes that the resulting leading-coefficient event depends on the committed evaluations and matrix rather than the particular response. The matrix-dependent support, not response adaptivity by itself, is the decisive issue here.

The repository contains two useful fixed-row/full-domain statements, but neither mechanizes the paper's hash-query/`E_openable` extractor:

- `SmallWoodDecsExtraction.lean:459-527` proves a support-union bound with the paper-shaped factor
  `choose(domainSize, degreeBound + 2) * |F|^-repetitions`, but for its own event in which fixed rows have a bad row and every combined word is globally degree bounded.
- `SmallWoodDecsExtraction.lean:529-635` proves the stronger `|F|^-repetitions` bound for that same global event by choosing one bad support from the fixed rows before sampling a fully independent matrix.
- `SmallWoodV8Smz9DecsDegreeEnforcement.lean:5-17,44-85` specializes only that second event to a complete `2^23 x 145` oracle and explicitly excludes the accepted-opening and SHA-512 transfers.

For the frozen values `N = 2^23`, `d_decs = 387`, `eta = 5`, and Goldilocks
`p = 2^64 - 2^32 + 1`:

```text
log2 choose(2^23, 389)       = 6155.756873365286
log2 p^5                     =  319.999999998320
log2 (choose(2^23,389)/p^5) = 5835.756873366965
```

The published upper bound therefore exceeds one by an astronomical margin and supplies no nontrivial probability upper bound at these parameters. This is certificate vacuity, not a demonstrated attack or a claim of zero protocol security, and it does not falsify the fixed-full-oracle lemma. It does falsify crediting that lemma as the paper's `epsilon_1` for accepted compiled proofs. A sharper source-specific extractor could in principle remove or reduce the family charge, but none is present.

This distinction propagates directly into the current ledger. `SmallWoodV8Smz9QromAccounting.lean:180-200` sets `epsilon1Numerator = 1` and `epsilon1Denominator = p^5`; lines 293-330 then derive the 288/157-bit screens from that term. Those screens remain valid calculations for the named ideal full-oracle event, but not for compiled SMZ9 knowledge soundness.

## 2. Twenty openings do not establish a global codeword

A fixed one-cell spike gives a minimal counterexample to the missing bridge. Let one committed row be `w(a)=1` and zero everywhere else. A uniformly sampled 20-subset of the `2^23` evaluation positions misses `a` with probability

```text
(2^23 - 20) / 2^23 = 2097147 / 2097152 ~= 0.9999976158.
```

On that opening set the zero polynomial agrees, but no degree-387 polynomial represents the full word: such a nonzero polynomial would have `2^23 - 1` distinct roots. Thus 20 successful checks cannot be quantifier-swapped into the full-domain agreement required by `SmallWoodV8Smz9OracleExtraction.lean:107-139`. That file itself identifies verifier-acceptance-to-codeword soundness as missing at lines 12-24; `ExtractedProgramSatisfied` remains an assumption at lines 351-378, and the concrete specialization preserves it.

This does not give a counterfeit proof. The PIOP may still detect an invalid relation, and a correct rewinding/proximity argument may recover a valid codeword. It rules out only the shortcut `20 accepted openings => global degree-387 oracle` and raw full-table interpolation under that premise.

The degree-387 root event in `SmallWoodV8Smz9AdmissibleRootProbability.lean:168-248` also fixes a nonzero bounded-degree discrepancy before sampling the 20-subset. If a proof instead selects
`D_S(X) = product_{x in S}(X-x)` after learning `S`, all 20 sampled points are roots with probability one. Any application therefore has to bind the response polynomial before the subset challenge.

## 3. Review of `SmallWoodV8Smz9AccumulatedExtraction.lean`

The new module correctly isolates and now source-shapes the selection problem, but it is an obstruction module, not an extractor:

- Lines 83-124 show that one fixed coordinate residual has exact failure probability `p^-5`.
- Lines 126-154 show that the union of two distinct coordinate events has probability strictly greater than `p^-5`. For independent matrix columns its exact probability is `2*p^-5 - p^-10`, although the module proves only the strict inequality.
- Lines 155-200 prove the safe replacement `|Candidate| * p^-5` for a fixed finite family and an arbitrary matrix-dependent selector.
- Lines 202-239 prove that an indicator word cannot have a degree-387 completion on a 389-point support containing its spike.
- Lines 243-331 connect these ingredients to one fixed 140-row source: data rows 0 and 1 are spikes at domain positions 0 and 1, all other data and implicit mask/response contributions are zero, and a matrix-dependent near-full support omits the surviving nonzero response position. On the two-column union event, the same zero response agrees everywhere on the selected support while one selected data row is not degree 387 on that support. The final theorem packages these claims with the strict probability inequality.

The connected obstruction is faithful to the algebraic core of the paper's `E_openable` issue. With two fixed spike rows, zero masks, and the post-matrix response polynomial `R=0`, the openable positions exclude the spike whose coefficient column is nonzero. The module's selected support is that openable set except in the both-columns-zero branch, where it is a harmless subset. Thus the same fixed source realizes at least two selectable residual fibers; treating the selected support as one prechallenge fiber is invalid.

For that intended source, the natural compiled extraction-failure event is `A0 union A1`, where `Ai` says all five entries of matrix column `i` vanish, and its exact uniform-matrix probability is `2*p^-5 - p^-10`. The fixed-full-domain event in `smz9_noncodeword_degree_enforcement_failure_le` would instead require `A0 intersection A1`, with probability `p^-10`. This both preserves the fixed-oracle theorem and exhibits the quantifier mismatch. The current module proves the strict union inequality and a selected-support witness, not this exact `E_openable` equality.

It still does **not** instantiate the Merkle/hash-query extractor, the actual 20-opening sampler and its miss probability, a complete accepted proof, the PIOP relation, a decoder, or `ExtractedProgramSatisfied`. It is therefore a source-shaped DECS extraction-failure pattern, not a full SMZ9 forgery. The now-present `soundness-argument.md` states that boundary correctly. `SmallWoodV8Smz9PublishedBound.lean` separately proves, by coarse exact integer inequalities, that the published support-union expression is greater than one; it does not turn that upper-bound failure into an attack probability. Both modules are untracked additions but are now umbrella-imported and inventory-listed. Static inspection found no `sorry`, `admit`, or new axiom. The coordinator reports that the published-bound file passed a direct Lean check; the full umbrella gate remained pending at this review freeze, so this review credits no aggregate build result.

The natural all-support family does not repair the parameters: `choose(2^23,389)` has about `2^6155.76` members. To leave even 128 bits from a `p^-5` union bound, a source-derived candidate family would need fewer than roughly `2^192` members before charging any other loss. No such executable family bound is supplied.

The counterexample therefore invalidates a post-matrix selector charged as one fixed fiber. It does not invalidate `smz9_noncodeword_degree_enforcement_failure_le` on its exact fixed-full-oracle event, and it is not an actual proof forgery.

### Stronger source-specific support count in `soundness-argument.md`

The argument's unmechanized strengthening at lines 53-63 is mathematically coherent. Fix two source rows evaluating `X^388` and `X^389`, set the other 138 rows and all masks to zero, and choose the five degree-387 response interpolants after the matrix and support. On a 389-point support `S`, the two degree-388 interpolation residuals have leading direction `(1, sum(S))`. Distinct support sums therefore give distinct five-row affine matrix events. For `L` such sums, their union has exact probability

```text
L * p^-5 - (L - 1) * p^-10,
```

because every pairwise and higher intersection forces both relevant matrix columns to zero.

The [Dias da Silva-Hamidoune restricted-sum theorem](https://londmathsoc.onlinelibrary.wiley.com/doi/abs/10.1112/blms/26.2.140) supplies at least
`389 * (2^23 - 389) + 1 = 3,263,017,192` distinct 389-subset sums, yielding about `2^-288.39644`. The stronger coset-specific count also checks: [Cochrane-Pinner, Theorem 2.1](https://www.math.ksu.edu/~cochrane/research/binsum7.pdf#page=3) bounds the subgroup additive energy by `(16/3) * N^(5/2)` for `N < p^(2/3)`. Cauchy-Schwarz, removal of sums requiring an equal pair or one fixed element, and padding with 193 disjoint opposite pairs (valid because `-H = H`) give
`L >= 541 * 2^23 + 1 = 4,538,236,929`. Its union probability is about `2^-287.92052`, strictly greater than `2^-288`.

This is a useful no-go for assigning the old 288-bit upper screen to that **broad support-selected completion event**. It remains primary-paper mathematics rather than a Lean theorem. It neither gives an efficient support finder nor connects the event to Merkle extraction, the 20 sampled openings, PIOP acceptance, exact proof bytes, or the HGV8RP03 relation. It is therefore not a lower bound on real verifier failure and does not rule out a differently proved PQ128 result.

## 4. Review of the triangular LVCS privacy result

The original layout result remains narrow but source-faithful. The simulator's last retained high-coefficient draws have shape `5 x 483` nonlinear plus `5 x 126` linear, totaling 3,045 Goldilocks words. Rust `poly_restore` retains these high coordinates, and the degree-six linear correction cannot change coefficients seven and above. `SmallWoodV8Smz9SingleProofPrivacy.lean:39-125` exposes an explicit projection/left inverse even when the digest prefix and low coefficients depend arbitrarily on the high coins. Lines 127-161 then give a classical ideal finite-fiber lower bound exceeding 512 bits, conditional on an injective encoder.

That establishes neither actual `getrandom` output nor byte-encoder injectivity, quantum conditional min-entropy, real/simulated view equality, or oracle-programming security. The theorem correctly says so.

The target-first toy at lines 163-211 is a valid counterexample to the missing inference. With `X=(R,Y)`, `R` can have arbitrarily large entropy conditional on the previously uniform target `Y`; nevertheless, after seeing `X`, one query distinguishes an ordinary oracle response from the programmed relation `H(X)=Y` with advantage `1/2`.

This matches the exact hypothesis mismatch with [Grilo-Hovelmanns-Hulsing-Majenz, Figure 2 and Theorem 1](https://www.iacr.org/archive/asiacrypt2021/130900241/130900241.pdf): their reprogramming instruction samples the input and side information from the supplied distribution, then samples the program output independently and uniformly. The SMZ9 simulator instead selects `h_piop`, derives PIOP and DECS challenges from it, constructs the proof and final 3,113-word hash input later, and programs that input to the earlier `h_piop` (`smallwood_engine.rs:7214-7340,7507-7768`). Large fibers of `X` conditional on `Y` do not instantiate the paper's game.

The toy is not itself an oracle/QROM formalization or an SMZ9 distinguisher: it has no query database, no SMZ9 encoding, and no theorem relating `targetFirstInput` to `simulatorFinalInput`. It refutes an entropy-only universal argument, not the possibility that the actual `(X,Y)` joint law has additional hiding or can be coupled to the paper's experiment.

The new result at lines 213-526 is material local progress. It instantiates the generic `triangularChallengeEquiv` from `SmallWoodV8Smz9TriangularAlgebraicLaw.lean` with the exact LVCS tail layout:

- the retained first coordinate is the full `12 x 20 = 240` columnwise `C * tails` product and is definitionally independent of the later DECS targets;
- the second coordinate contains all `20 x 128 = 2,560` complement-row evaluations, with the actual 388-node rotation represented as random tails at nodes 0-19 and committed heads at nodes 20-387;
- the target-dependent committed-head term is retained as an affine offset rather than silently discarded;
- any deterministic selector from those 240 words to admissible targets preserves the complete 2,800-word uniform law; an `Option`-valued selector preserves its abstract success and `none` branches; and
- the law starts from the ideal Goldilocks rejection-sampler output, and it proves local head-offset hiding when the public combination heads and all other selector inputs are already equal.

This closes the **later-target feedback inside the LVCS algebraic block**. It is stronger than fixed-challenge bijectivity and directly answers the same-coins counterexample for this triangular map.

It does not yet instantiate the honest transcript. Rust samples the same 140-by-20 tail matrix before `decs_commit`; the tails affect the complete committed leaf table, Merkle root, the root-derived DECS matrix, five DECS response polynomials, the PCS transcript, the PIOP points, and the public selector inputs before `lvcs_open`. The Lean law instead fixes the points, committed heads, and selector's other public inputs, then supplies a fresh ideal 2,800-word tail law. Conditioning on or retaining that earlier commitment is exactly the missing step. The proposed H0-H2 leaf-output hybrid and DECS-mask translation in `privacy-argument.md` are a plausible route, but remain unproved SHA-512/QROM execution equivalences. There is also no Rust-to-Lean proof that the concrete XOF/coset sampler always returns the `LvcsAdmissibleTargets` subtype.

The campaign argument now records the concrete sampler count correctly: the active constant is 50 at `smallwood_engine.rs:125`, and it is consumed at lines 12837-12847. The Rust comment at lines 12806-12808 still says forty/20 spare; SMZ9 has 30 spare. The generic regression prose at lines 14193-14195 also says 26/25 although that test's `ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1` has 23 openings; its executable calculation correctly uses `OPENING_COUNT - 1` and 50. These comment drifts do not change executable SMZ9 sampling.

Two campaign summaries still need narrower wording. `privacy-argument.md:25-29` calls this the "actual" LVCS law "including ... the sampler's abort branch," and `README.md:71-72` says the later dependency is "discharged." The Lean theorem takes an arbitrary proof-carrying `Option (LvcsAdmissibleTargets points)` selector as an argument; it does not define or refine the runtime `hash_challenge_opening_decs -> xof_decs_opening -> decs_field_evaluation_points` pipeline. Actual exhaustion returns a Rust `Err` before a proof exists, whereas the Lean observation retains `(early, none)`. What is discharged is the source-shaped **local algebraic feedback pattern**, conditional on fixed public context and an admissibility-certified selector; an abstract conservative failure branch is retained.

The privacy author reports a direct check of the frozen module and an axiom audit limited to `propext`, `Classical.choice`, and `Quot.sound`. This review did not rerun that check under its no-build scope; the umbrella/full-formal gate remains the integration authority.

The `p^-3045` point-mass figure in `privacy-argument.md:13-15` is a mathematical corollary of the exact `p^3045` uniform high-coin space and injection. The named checked finite-fiber theorem itself records the deliberately weaker 512-bit conclusion after assuming an injective encoder; the stronger number should not be mistaken for a separately named quantum-entropy theorem.

`privacy-argument.md:43-48` also calls the simulator output and high coefficients "independent draws." The Rust source guarantees distinct sequential `CryptoRng` draws, and explicitly warns at `smallwood_engine.rs:7214-7218` that this interface marker is not a proof of the formal independent-uniform model. Independence is valid in the ideal sampler theorem or under the campaign's RNG assumption/refinement, not as an unconditional runtime fact.

The executable fixture does not close that gap. Its constructor hardcodes `prior_sha512_queries = Vec::new()` after the final program input is known (`smallwood_engine.rs:7719-7735`). The overlay rejects a prior query equal to a program key (`smallwood_engine.rs:6103-6128`), and the explicit conflict test confirms this rejection. That is correct fail-closed behavior, but it is not an adaptive history theorem.

## 5. What the existing event lemmas actually establish

Subject to their explicit hypotheses, the current isolated results are useful:

- `SmallWoodV8Smz9SequentialAlgebraicLaw.lean:48-110` gives the exact fresh 3,105-word uniform law and a prefix-dependent affine joint law when each map/offset depends only on an earlier prefix. Lines 159-192 correctly show collapse when a challenge depends on the same coins.
- `SmallWoodV8Smz9TriangularAlgebraicLaw.lean:24-92` proves that same-coin challenge feedback preserves the joint uniform law when every challenge-indexed equivalence retains the same first coordinate; its history theorem still samples the current coins freshly after the retained history.
- `SmallWoodV8Smz9AdmissibleRootProbability.lean:97-166` gives the corrected degree-552 false-batch root probability on uniformly sampled fully admissible six-tuples.
- The same module at lines 168-248 gives the fixed degree-387 polynomial root event on the exact coset.
- `SmallWoodV8Smz9DecsDegreeEnforcement.lean:44-85` gives `p^-5` for the exact fixed-full-oracle/global-codeword event under a fully independent uniform `5 x 140` matrix.
- `SmallWoodV8Smz9PublishedBound.lean:24-69` proves only that the paper's support-family expression exceeds one at the frozen parameters.
- `SmallWoodV8Smz9SingleProofPrivacy.lean:39-161` gives the simulator-side high-coordinate injection and ideal finite-fiber fact; lines 213-526 prove the exact ideal LVCS feedback/abort law just described.

There is no downstream theorem composing these leaves into accepted-proof extraction or whole-view privacy. The accumulated-extraction, published-bound, triangular-law, and single-proof-privacy modules are now imported at `HegemonCrypto.lean:89,92,102-103`, with named roots in the 114-entry credited inventory. Those are audit/integration edges, not semantic composition. `SmallWoodV8Smz9LogicalOracle.lean:1004-1026` still leaves the exact transition, failure selector, and CMS instability refinements unavailable. `SmallWoodV8Smz9ZeroKnowledge.lean:1983-1991,2038-2065` similarly leaves concrete SHA-512/adaptive and repeated whole-view premises constructor-free and its receipt unavailable.

The review's carrier-cap finding was corrected in `security-contract.md:46-62`: it now distinguishes the 131,072-byte inner parser/envelope ceiling, 125,638-byte maximum-shape routed proof limit, 122,863-byte current projection, 128,297-byte projected complete action, and 131,072-byte outer action cap. A fixed-subject completeness issue remains. The table's Poseidon2 row omits the `x^7` S-box and pinned parameter-set identity, while its relation/profile summary does not explicitly include the source-owned 48-byte HGV8RP03 program digest or zero-grinding fields. Either those bindings belong in the purported complete tuple or the table must be labeled a summary of a separately canonicalized profile. The stale ExecPlan note at lines 1026-1028 likewise still calls the source-specific triangular instantiation "in progress."

## 6. Required repair and acceptance criteria

### Soundness

An acceptable theorem must start from the exact compiled transcript/hash-query experiment and end at the HGV8RP03 relation. It must:

1. extract or binding-fix the complete authenticated oracle before the independent matrix, or derive a source-faithful `E_openable`/support family and charge its actual size;
2. fix every response/discrepancy polynomial before the 20-subset challenge;
3. prove the exact SHA-512 challenge law, including admissibility, aborts, conditioning, and QROM transfer;
4. derive a useful proximity/unique-decoding statement and decode degree-387 rows rather than raw-interpolate an arbitrary full table; and
5. prove that the decoded oracle yields the exact 686-by-64 witness and `ExtractedProgramSatisfied`, hence the executable HGV8RP03 relation.

The first error term must be the paper-shaped support-family term unless a checked new extractor theorem proves a smaller source-specific family or a matrix-independent support. A caller-supplied selector or desired failure probability is not such a theorem.

### Privacy

An acceptable result must define one ordered honest/simulator quantum experiment over actual proof bytes and the shared SHA-512 oracle. It must either:

1. prove that the actual program-input/target joint law is close to a GHHM-compatible law where the output is independently uniform after sampling the input; or
2. invoke and instantiate a different correlated-output reprogramming theorem whose hypotheses control this exact dependence.

It must derive, rather than accept as fields, the full prior-query database, program-point freshness/hit loss, duplicate/collision behavior, lazy hidden-subtree chronology, actual serializer injectivity, runtime randomness pushforward, and two-witness real/simulated view distance. Hardcoding an empty prior history is not an adaptive proof.

### Authority boundary

No reviewed result changes the carrier, capability registry, source-security report, release artifacts, or production authorization. The present work is evidence about failed and still-possible proof routes. It is not evidence that SMZ9 is broken, secure, PQ128, deployable, or independently certified.
