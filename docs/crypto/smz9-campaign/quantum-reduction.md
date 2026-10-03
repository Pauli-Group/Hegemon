# Current SMZ9 quantum-reduction assessment

Date: 2026-09-06. Scope: HGV8RP03 / SMZ9, current four-stage transcript, read-only source and primary-paper review. This document changes no implementation, security receipt, capability, or release authority. No dependency installation, clone, upload, submission, or build was performed for this review.

## Verdict

There is no verified end-to-end quantum privacy or knowledge-soundness reduction to land from the inspected results alone. Two specific routes remain worth pursuing without changing the carrier:

1. **Soundness:** research a stronger concrete degree-enforcement/extraction theorem, then instantiate the existing explicit compressed-oracle implementation with the actual SMZ9 failure event and relate it to the tagged, counter-mode raw oracle. The published SmallWood support-family bound is already vacuous at the current profile, even with a fully independent matrix; this is not just quantum-compiler integration work. The finite compressed-oracle operator arithmetic remains reusable.
2. **Privacy:** a Grilo–Hövelmanns–Hülsing–Majenz (GHHM) adaptive-reprogramming hybrid, with a separately proved honest-to-simulated joint transcript law and a valid lazy hidden-subtree hybrid. The current fixed-fiber entropy facts do not themselves instantiate this theorem.

The generic four-round measure-and-reprogram compiler is a quantitative no-go at a global query budget of `2^64`: its multiplicative loss exceeds `2^515`. None of the existing ledger bit counts is credited here as a proved real-game bound.

## Actual transcript and available semantics

The logical stage ordering in `SmallWoodV8Smz9LogicalOracle.lean:339-365` is:

| Stage | Bound prefix before challenge | Actual challenge |
| --- | --- | --- |
| 1 | Committed `2^23 x 145` oracle, root/salt/public binding | Independent-matrix ideal model: `5 x 140` Goldilocks DECS coefficients |
| 2 | Previous prefix plus the five degree-387 combined-polynomial messages | Five PIOP batching rows |
| 3 | Previous prefix plus nonlinear/linear PIOP polynomial messages | Six admissible PIOP opening points, selected by the canonical bounded nonce procedure |
| 4 | Previous prefix plus the PIOP openings and PCS combination message | Twenty distinct DECS leaf positions |

These are four **logical** challenge stages, not four raw SHA-512 calls. The source uses domain-separated transcript hashes, counter-mode field-XOF calls, bounded field rejection, canonical nonce trials, and subset sampling. The verifier reconstructs earlier messages backwards from the proof before checking the final PIOP digest. See `smallwood_engine.rs:5437-5570`, `11488-11524`, `11878-11934`, and the exact query grammar above. A reduction must preserve the forward prover timing despite that backward verifier reconstruction.

The concrete finite CMS root is `V8Smz9LogicalOracle.exact_smz9_indexed_ideal_logical_qrom_failure_probability_le` at line 786. It uses `DatabaseIndependentContraction`, an explicit complex matrix kernel lifted only over adversary registers (`CmsOracleSimulation.lean:901`), not an arbitrary nonlinear norm-preserving function. The oracle kernel has an explicit `Dec / Phase / Dec` factorization; decompression is a complex-linear isometry (`CmsCompressedOracleUnitary.lean:55`). Thus the more permissive `FiniteQrom.NormPreservingStep` interface should not be used to accuse this particular root of nonlinear quantum dynamics.

For a new whole-view indistinguishability proof, retain physical linear/isometric operations, or CPTP channels with a purification argument. An arbitrary norm-preserving map is insufficient to preserve distances between states. The narrower database-blind interface has additivity and contraction; the concrete headline's stronger matrix-kernel interface is the preferable integration point. A bound on unnormalized branches must not be turned into a conditional-on-success claim by uncharged postselection.

## Exact published privacy tool and missing fit

[GHHM, Theorem 1, Figure 2](https://eprint.iacr.org/2020/1361.pdf) gives

`Delta_AR <= sum_r (sqrt(qhat_r * pmax_r) + (qhat_r * pmax_r)/2)`,

where `pmax_r = E[max_x p_X^(r)(x)]` and `qhat_r` sums the actual oracle-query counts preceding instruction `r` (there is no extra `r-1` instruction term). A classical instruction chooses a sampling distribution; the game freshly samples the input and side information, then an independent uniform output, programs the oracle, and reveals the sampled input/side information. This handles quantum prequeries within that experiment. It is not a theorem for an arbitrary pre-existing point with a supplied quantum conditional-min-entropy number. Theorem 3 supplies a separate multi-HVZK hybrid for its Fiat–Shamir-signature application; it does not declare every programmable transcript zero knowledge.

This distinction matters concretely here:

- `ideal_final_piop_input_has_512_bits_conditional_min_entropy` (`SmallWoodV8Smz9RepeatedAlgebraicZk.lean:528`) counts fibers of an injective affine map with fresh coins **after a fixed prior parameter**. `UniformConditionalMinEntropyAtLeast` at line 434 is a classical finite-fiber predicate, not a cq-state guessing-probability or trace-distance definition.
- Actual PIOP mask coins are sampled before PCS commitment; opening-dependent affine maps are chosen afterwards. The new `SmallWoodV8Smz9SequentialAlgebraicLaw.lean` correctly preserves an earlier prefix through a fresh mask phase, but explicitly does not identify opening-dependent maps with such earlier-prefix choices. Its same-coin counterexample explains why that substitution is invalid.
- The simulator samples `h_piop` first, derives nonce/openings and later messages from it, and only afterwards constructs the raw input programmed to that value (`smallwood_engine.rs:7251-7347`, `7720-7738`). The raw-input/output joint law must be shown reorderable into the paper's experiment, or justified by a separate hybrid. Marginal uniformity of `h_piop` and large fibers of the input do not establish this.

A simple mathematical obstruction to the latter shortcut is `X=(R,Y)`, with fresh 512-bit strings `R,Y`. The input has ample entropy, yet programming `H(X)=Y` is distinguishable from an ordinary random oracle by reading the `Y` part of `X` and querying it. This is not an attack on SMZ9; it shows precisely why its input/target correlation requires proof.

### What the widths do and do not establish

| Source feature | Established finite fact | Missing quantum-game fact |
| --- | --- | --- |
| Full 512-bit digests/raw inputs | Eight raw `u64` digest words are retained; the final PIOP input has 3,113 words, including 3,105 field-view words | Width is not freshness, uniformity, or independence from the prior quantum state |
| Each strict leaf has a 64-byte tape | For fixed other leaf fields, the encoded semantic input is injective in a fresh uniform tape; ideal fiber bound is `2^-512` | The relevant tape remains fresh at the chosen programming step, and the whole hidden-tree simulation is jointly equivalent to the honest one |
| Final PIOP mask fibers | Ideal coin space has cardinality `p^3105`; the fixed-map input is injective, even with the digest prefix fixed | Earlier commitments and subsequently chosen maps can be retained while deriving the required sampling law; raw serialization and target-output correlation also fit |
| Two hidden internal children | The ideal ordered-pair model is injective in two independent 512-bit children | The actual adaptive hidden-subtree hybrid can supply that independence; already generated/disclosed children cannot simply be called fresh again |

The leaf/input fiber facts are in `SmallWoodV8Smz9RepeatedAlgebraicZk.lean:607-749`. They are useful mathematical inputs, not quantum entropy certificates. A tape or salt revealed **after** its programming step is not disqualified merely because it is eventually public; a value already revealed **before** a later step cannot be reused as fresh entropy there. For internal nodes, the raw source encodes the ordered child digests but no level or index, so duplicate keys and collision cases must be handled explicitly.

## Quantitative privacy target, conditional on that fit

Let `Q` count all adversarial queries to the single shared raw oracle over the entire experiment. Let `T` bound all generated or adversary-observed honest proof views, including rejected, orphaned, side-fork, wallet-generated, and repeated views. Let `H(T)` bound all raw oracle queries performed inside the reduction's honest/simulator routines. Set `E = Q + H(T)` as a conservative upper bound for each relevant prior-query count. Derive `H` from the complete raw trace, including counter-mode calls, unsuccessful canonical trials, and queries retrieving programmed outputs; the number of programming points alone is not automatically such a query bound.

Define `b_h(E) = sqrt(E / 2^h) + E / 2^(h+1)`. If the exact lazy hybrid proves fresh 512-bit inputs for each leaf-frontier/final-PIOP point, fresh 1,024-bit inputs for internal-frontier points, and the published sampling/output conditions above, then the current source envelope gives the **conditional** target

`Delta_lazy(Q,T) <= T * (21*b_512(E) + 352*b_1024(E))`.

This uses at most 20 strict-leaf frontier points, at most 372 total frontier points, and one final-PIOP point. It does not assert that all three coordinate maxima occur independently; the expression follows by the joint envelope and the higher cost of leaf points. It is an upper bound for the proposed programming hybrid only, not total privacy loss.

A more conservative eager target, if every tree/final input genuinely satisfies the 512-bit condition, is

`Delta_eager(Q,T) <= 2^24 * T * b_512(E)`.

When `E <= 2^h`, `b_h(E) <= (3/2)*sqrt(E/2^h)`, explaining the shape of existing dyadic screens. That algebra does not supply their theorem hypotheses. Honest/simulator joint-law discrepancy, bounded-sampler failure, repeated-request handling, and primitive-model losses must be added only after independently establishing their event reductions. Do not multiply by `T` twice when a bound already counts all lifetime programming instructions. No epoch, block cap, or restart resets the shared oracle or quantum query budget.

## Soundness compiler: precise no-go and selected alternative

[Don–Fehr–Majenz, Corollary 13](https://eprint.iacr.org/2020/282.pdf) gives, for four appropriately chained uniform-challenge stages,

`p_I >= 24/(2q+5)^8 * p_FS - 24/|C|`,

with the stated additive term aggregated over statements. Rearranging yields

`p_FS <= ((2q+5)^8/24)*p_I + (2q+5)^8/|C|`.

This is a soundness/quantum-knowledge compiler, not a ZK theorem. At `q=2^64`, its multiplier exceeds `2^515`; to reach `2^-128`, even ignoring the additive term, one would need `p_I < 2^-643`. If one additionally counterfactually instantiates its uniform challenge range as exactly 512 bits, its additive term alone exceeds one. The actual multi-output XOF and admissibility selection are not that direct instantiation, so this last calculation is only a diagnostic, not a security claim about the actual protocol.

The better current integration point is the explicit CMS root. Its established **conditional ideal-game** formula is

`Pr[failure] <= (sqrt(6*q^2*mu) + sqrt(beta))^2`,

where `mu` is a proved two-sided `RealInstabilityBound` for the exact property, and `beta` is the actual oracle-to-database claim bridge. See `CmsLifting.lean:35,152`, `CmsClassicalDatabase.lean:588`, and `SmallWoodV8Smz9LogicalOracle.lean:763-823`. The current root's `beta` uses its large indexed logical-product output cardinality. It cannot be credited as the cardinality of one SHA-512 response; the raw-to-logical quantum simulation remains necessary. The [compressed-oracle framework](https://eprint.iacr.org/2020/1305.pdf) supplies machinery, not the SMZ9 instability property automatically.

`mu` must be derived against the actual chronology, including post-challenge extraction and admissible query selection. The soundness workstream found a source-shaped obstruction to feeding a post-challenge chosen interpolation support into the fixed-oracle `p^-5` degree-enforcement lemma: two support-dependent residual directions can already make the union probability `2*p^-5 - p^-10`. This is an event-binding warning, not a full protocol forgery. The probability of observing the needed support and the extraction procedure must be charged together in the CMS experiment. A caller-supplied selector asserting the desired failed-extraction event is not its constructor from actual accepted proof bytes.

### The published SmallWood bound does not close the classical starting point

[SmallWood, Theorem 1 and Equation (14), author full text](https://www.researchgate.net/publication/411178744_SmallWood_Hash-Based_Polynomial_Commitments_and_Zero-Knowledge_Arguments_for_Relatively_Small_Instances) retains the support-family factor even for a fully uniform matrix:

`epsilon_DECS = choose(N,d_DECS+2)*epsilon_D + (Q+1)^2/2^(2*lambda+1)`,

`epsilon_D = max_(v != 0,u) Pr_Gamma[Gamma*v+u=0] = p^-eta`,

`epsilon_1 = choose(N,d_DECS+2)/p^eta`.

Theorem 1's proof unions over supports of size `d_DECS+2`; full matrix independence removes neither that union nor the extractor's support selection. Equation (14) explicitly carries this term into the interactive proof. Theorem 9 gives a classical ROM result with independent `Hash`, `XOF_i`, and `XOF'_i`, not a QROM theorem for the implementation's shared raw oracle. The inspected source is the August 2026 IACR Communications in Cryptology author full text, DOI `10.62056/avzojbhdj`; the [ePrint 2025/1085 record](https://eprint.iacr.org/2025/1085) identifies the paper, but its PDF revision was not byte-compared with this full text.

For the current local profile, `N=2^23`, `d_DECS=387`, `eta=5`, and `p=2^64-2^32+1`. Direct substitution gives the following diagnostic:

`log2(choose(2^23,389)/p^5) ~= 5835.75687337`.

Vacuity does not depend on floating-point accuracy: every factor in the product for `choose(N,389)` exceeds `(N-388)/389 > 2^14`, so `choose(N,389) > 2^5446`, whereas `p^5 < 2^320`. Hence the displayed error bound exceeds `2^5126`, and the resulting probability upper bound is only the trivial `1`. This is a limitation of that published bound at these parameters, not a lower bound on forgery probability or an attack.

Consequently the selected CMS route must first supply substantially stronger, source-matched proximity/extraction mathematics at the near-Singleton regime, or an equally strong event-specific analysis that avoids this exhaustive support union. It cannot simply wrap the paper's `epsilon_1`, drop the binomial coefficient, or equate one fixed residual test with adaptive failed extraction. Only then can an actual two-sided instability proof and raw-oracle refinement deliver a concrete QROM result. This assessment authorizes no profile, carrier, or protocol change.

## Assumptions versus missing research

| Item | Classification / required next result |
| --- | --- |
| SHA-512 treated as a shared quantum random oracle | Explicit cryptographic model/instantiation assumption; digest width or standalone collision estimates cannot prove this identification |
| Secure independent system randomness | Explicit implementation assumption, plus checked transfer of bounded rejection/abort behavior into the defined ideal experiment |
| Current finite field/map/CMS operator arithmetic | Existing mechanized ingredients, subject to the parent's normal axiom and build gates |
| Quantum query model | Use explicit linear/isometric or purified CPTP operations and one global query budget; no uncharged postselection |
| Four-stage raw-to-logical oracle simulation | Missing research/refinement: preserve role tags, counters, request lengths, rejected nonce trials, and coherent access; do not replace a 512-bit raw response with a gigantic uniform product response by fiat |
| Current acceptance to actual extraction failure event / two-sided instability | Missing protocol-specific proof; requires a substantially stronger bound than the published support-family union at the current profile, plus actual byte/verifier binding |
| Privacy whole-view sampling and program target independence | Missing joint-law/hybrid proof, not an extra numerical entropy assumption |
| Lazy hidden-subtree completion and node-input freshness | Missing protocol-specific hybrid with collision/duplicate handling |
| Lifetime `Q,T,H(T)` | Explicit quantified model and verified accounting; canonical accepted actions do not bound all observations |

The next acceptable quantum landing is a concrete game-and-hybrid theorem discharging one of these missing rows, with its exact loss and physically valid semantics. Adding another record whose constructor requires the desired whole-view equality, a `512` entropy field, or the final failure bound would not close it. The existing constructor-free premises correctly keep production authority unavailable.
