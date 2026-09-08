# Complete-security endpoint gaps for the repaired relation under SMZ9/profile 6

Date: 2026-09-07. This dossier records the current fail-closed boundary after
the relation repair. It is not a complete privacy or knowledge-
soundness proof, a retained proof receipt, an independent review, or production
authority.

## Decision

The current tree cannot support any of these claims:

- **P7:** complete adaptive whole-view zero knowledge with loss at most
  `2^-128`;
- **K8:** knowledge soundness for actual accepted proof bytes with loss at most
  `2^-128`; or
- **R0:** universal Rust-source/Lean acceptance and semantic refinement.

This is an inventory of unfinished evidence, not a mathematical impossibility
result. The graph contains deliberately constructor-free premise types; Lean's
proofs that those types are uninhabited follow from how the sentinels were
defined. They block unsupported release claims but do not refute the protocol's
security statements or justify stopping work. Actual endpoint derivations must
replace missing evidence with proved constructions. The governing dependency
graph requires independent P7 and K8 before production credit through R0-R5
([security contract](security-contract.md#dependency-graph)).

## Repaired subject and identity boundary

The source repair has real implementation and specification content:

- out-of-range sponge rate lanes now bind canonical zero/previous-state
  chaining, while explicit in-range private holes remain unbound
  ([source](../../../circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs#L1203-L1262),
  [regressions](../../../circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs#L4329-L4410));
- an enabled stable asset must occur exactly once in `balance_assets`
  ([source](../../../circuits/transaction/src/smallwood_poseidon2_v8_types.rs#L586-L623),
  [regressions](../../../circuits/transaction/src/smallwood_poseidon2_v8_types.rs#L2208-L2263)); and
- the exact semantic compatibility predicate carries the same mint/burn count
  requirement
  ([source](../../../formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean#L316-L352)).

Those changes are implementation/specification evidence. They do not prove a
privacy game, construct an extractor, refine Rust execution to Lean, retain a
new proof, or authorize a capability.

`HGV8RP03` remains the eight-byte program-format magic/lineage marker, and the
separate grammar version remains `3`; neither value is the unique relation
identity
([source](../../../circuits/transaction/src/smallwood_poseidon2_v8_program.rs#L21-L27)).
The repaired 853,429-byte program is disambiguated by its current SHA-512 and
48-byte prefix relation ID
([source](../../../circuits/transaction/src/smallwood_poseidon2_v8_program.rs#L123-L137)).
Its SHA-512 is
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`,
and its native relation ID is the 48-byte prefix
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984`.
The regeneration map expressly permits the magic to remain because the digest
is the per-program discriminator
([source](daybreak-regeneration-map.md#L38-L46),
[source](daybreak-regeneration-map.md#L66-L69)).
This dossier alleges neither an attack nor a hash collision. The new digest/ID
meets the identity-change part of the ExecPlan; old proof bytes remain bound to
their old ID and historical status
([source](../../../.agent/SMZ9_COMPLETE_SECURITY_EXECPLAN.md#L17-L24),
[source](daybreak-regeneration-map.md#L129-L144)).

The security contract has now been explicitly rebound to the repaired SHA-512
and native relation ID while retaining its endpoint topology
([source](security-contract.md#L3-L24),
[source](security-contract.md#L38-L52)). Manifest prose and every future
endpoint theorem or release dossier must likewise reserve `HGV8RP03` for the
format lineage and state the exact digest when it means one program. This is a
documentation/freeze requirement, not evidence of ambiguous bytes.

## Locally established intermediate edges and non-transfer boundaries

| Dependency edge | Current formal or implementation result | Boundary that remains |
| --- | --- | --- |
| Accepted packed domain to a witness-free reference | `canonical_statement_current_privacy_bound` and its two-witness form bound a scalar acceptance difference ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentPublicContext.lean#L411-L468)). | Not a source-equivalent real prover, complete adversary view, cq-state distance, or repeated adaptive hybrid. |
| Generated current game to public reference | The chronological randomized and executed source experiments are bounded ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyComposition.lean#L685-L736)). | The honest-to-randomized transition is an external premise in the next theorem ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyComposition.lean#L738-L768)). |
| Finite retained-update suffix | `compiled_request_suffix_current_adjacency` charges two raw calls per logical read ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentRepeatedPrivacy.lean#L654-L680)). | The module is not a compiler refinement for the complete adaptive Rust prover ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentRepeatedPrivacy.lean#L3-L10)); its honest-leaf loss is only a defined envelope, not an instantiated quantum theorem ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentRepeatedPrivacy.lean#L692-L699)). |
| Exact lazy-program recording | A narrow executable recording receipt is constructed ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9RepeatedAlgebraicZk.lean#L1499-L1541)). | It supplies neither RNG freshness nor adaptive QROM programming; the enclosing premise records are uninhabited ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9RepeatedAlgebraicZk.lean#L1543-L1610)). |
| Coherent vector-source algebra | Full-vector and coherent source commutator bounds are proved ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean#L233-L255), [source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean#L286-L333)), with exact raw/source trace projection ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean#L433-L472), [source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean#L543-L563)). | These lemmas start from a supplied bounded state/database. They do not derive commitment binding, accepted-word proximity, or an extractor from verifier acceptance. |
| Source trace encoding | Bounded forests round-trip through an explicit bit register and the actual source-label range embeds into it ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9SourceExtractionCodec.lean#L373-L440), [source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9SourceExtractionCodec.lean#L503-L524)). | Register size is not a polynomial-time reversible extraction algorithm ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9SourceExtractionCodec.lean#L5-L10)). |
| Arbitrary-source MCA accounting | The exact coefficient/subset-space recovery bound is proved ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9McaRecovery.lean#L682-L733)). | The concrete current-profile `smz9LineBudget` inequality remains outstanding, so its specialization is not a numerical certificate ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9McaRecovery.lean#L740-L755)). |
| Decoded source to packed interpreter | A fully satisfied decoded candidate yields unchanged packed-program acceptance ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentSourceAcceptance.lean#L368-L389)). | No preceding theorem extracts that candidate from an actually accepted proof. The deterministic oracle inverse explicitly leaves acceptance-to-proximity/extraction separate ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9OracleExtraction.lean#L21-L28), [source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9OracleExtraction.lean#L356-L390)). |
| PIOP opening reconstruction | The actual six-opening restore/correction equations are constructed ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9PiopReconstruction.lean#L210-L252)). | A false candidate can also reconstruct at selected points; pre-opening hash chronology and decoded PCS trace binding remain necessary ([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9PiopReconstruction.lean#L192-L204)). |
| Packed witness to typed semantics | The complete `ExactV8RelationSemanticValid` implication now follows from canonical public admission and arbitrary acceptance of the actual repaired packed program. It includes all authorization modes, note/Merkle/nullifier/output links, integer balance and disabled/mint/burn stable transitions ([endpoint](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9ExactSemanticEndpoint.lean), [proof dossier](packed-semantic-endpoint.md)). | Actual Rust public/evaluator/decoder execution, accepted-proof-byte extraction and the reverse valid-typed-witness lowerer-completeness implication remain separate. Full-action semantics additionally require the actual context and inline-ciphertext predicates; the wrapper does not prove their admission. |

## Exact current blockers

### P7: complete adaptive whole-view privacy

The current internal whole-view record is useful audit structure, but its
constructors take public-context and execution-trace data as explicit checked
inputs and disclaim distribution, coupling, QROM, and production claims
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9WholeViewObservation.lean#L14-L27),
[source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9WholeViewObservation.lean#L248-L308),
[source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9WholeViewObservation.lean#L819-L820)).
The older privacy telescope retains one persistent table, but assumes every adjacent
complete-program bound rather than deriving it
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyComposition.lean#L803-L819)).
The new `SmallWoodV8Smz9SourceLifetimePrivacy.lean` endpoint supersedes that
limitation for the modeled actual source lifetime: it derives all three
leaf/final/hidden comparisons, the source-stage execution equalities, a
witness-free public-source simulator and its exact erasure, and the final
two-witness triangle. Under the explicit universal external reprogramming
assumption, `q <= 2^65` and `r <= 2^21` give a source/simulator gap at most
`2^-167` and a two-witness gap below `2^-128`. The full public request/control
flow must agree; its simulator is not defined on a statement alone. See the
[completed ideal source-lifetime endpoint](privacy-endpoint-completion.md#completed-ideal-source-lifetime-endpoint).
This does not provide concrete SHA-512 construction security, actual
Rust/runtime/byte refinement, or an approved deployed resource model.
The concrete premise types for RNG freshness, raw serialization, adaptive final-
PIOP programming, SHA-512 QRO instantiation, all-history leaf freshness,
internal-node entropy, lifetime budgets, and collision applicability are
constructor-free
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9RepeatedAlgebraicZk.lean#L1440-L1451)).
Lean then proves that the final-PIOP, full-history, and lazy-history premise
records are uninhabited
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9RepeatedAlgebraicZk.lean#L1581-L1610)).

At the endpoint, concrete SHA-512 adaptive-QROM and repeated whole-view types
are constructor-free, and
`smz9_adaptive_qrom_whole_view_release_receipt_is_unavailable` proves that the
P7 release receipt has no inhabitant
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9ZeroKnowledge.lean#L1988-L1996),
[source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9ZeroKnowledge.lean#L2032-L2070)).
Therefore no P7 or complete-ZK claim follows.

### K8: accepted-byte knowledge soundness

The current universal weighted MCA inequality is still unproved. The
[finite literature check](mca-universal-literature-boundary.md) substitutes
the actual `N=2^23`, degree 387 and five-coordinate field into the primary
whole-support and capacity results. None of the checked finite certificates
closes the required low-agreement range. This is neither a protocol
counterexample nor an impossibility claim. Even the exact one-point-direction
subclass leaves an unrestricted weighted punctured Reed-Solomon list problem.

The exact ideal logical-QROM theorem still consumes a caller-supplied failure
selector and `RealInstabilityBound`
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9LogicalOracle.lean#L779-L824)).
The exact SMZ9 round-transition refinement, native/extractor failure-selector
refinement, and CMS-instability theorem are constructor-free; Lean proves each
unavailable
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9LogicalOracle.lean#L1004-L1026)).
The SHA-512-to-indexed-product reduction and exact `6/20/140` logical-oracle
instantiation are likewise constructor-free and explicitly unavailable
([source](../../../formal/crypto/HegemonCrypto/SmallWoodHeterogeneousCmsQrom.lean#L1003-L1028)).

The deployed lifetime record consumes those bridges, actual event
identification, concrete Fiat-Shamir/QROM reduction, adaptive whole-view
privacy, a common `(Q,T)` budget, a quantitative bound, and independent review.
Its theorem yields only `conditionalSupply`, and
`deployed_smz9_global_sha512_qrom_lifetime_premises_are_unavailable` proves the
record uninhabited
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean#L1612-L1669)).
The smaller deployed record is also proved uninhabited
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean#L1678-L1699)).
Therefore no K8, no-counterfeit, or PQ128 soundness claim follows.
Even a future K8 would be necessary but insufficient for a consensus
no-counterfeit corollary: full-action, context, ciphertext, state, and lifecycle
binding remain R0-R3 obligations
([source](security-contract.md#L201-L219)).

### R0: universal implementation and semantic refinement

`FullRelationCompilerRefinementReceipt` requires full relation coverage and
semantic equivalence. Checked-in coverage remains only
`sourceExecutableProgramBound`, and Lean proves the full receipt uninhabited
([source](../../../formal/lean/Hegemon/Transaction/Poseidon2V8ConstraintRefinement.lean#L287-L303),
[source](../../../formal/lean/Hegemon/Transaction/Poseidon2V8ConstraintRefinement.lean#L374-L460)).
Consequently `CompiledSmz9RelationBinding` is also proved uninhabited
([source](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9ZeroKnowledge.lean#L1772-L1800)).

The semantic-adequacy receipt names the required arbitrary-input decoder,
canonicality, authorization/cryptographic-link, balance, stable-transition,
and Rust-refinement obligations
([source](../../../formal/lean/Hegemon/Transaction/Poseidon2V8SemanticAdequacy.lean#L56-L116)).
The one-way arbitrary-packed-to-typed relation implication is now proved in
the research tree, including all five fixed semantic conjuncts
([endpoint](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9ExactSemanticEndpoint.lean),
[scope and checking](packed-semantic-endpoint.md)). This is not the reverse
valid-typed-witness lowering theorem or universal Rust execution refinement.
The production-owned full semantic receipt remains unavailable
([source](../../../formal/lean/Hegemon/Transaction/Poseidon2V8SemanticAdequacy.lean#L378-L394)).
Therefore R0 is not a theorem in the current graph, and R1-R5 cannot inherit
authority from source/vector agreement.

## Retained artifacts and authority

The retained-artifact and release state is explicit and fail-closed:

- successor selection is `unselected`, with no identity or evidence bundle
  ([source](../../../config/transaction-proof-successor-selection.json#L1-L7));
- production authorization, source-registry presence, and successor selection
  are false
  ([source](../../../config/smallwood-v8-poseidon2-profile-manifest.json#L2-L7));
- required theorem, refinement, lifecycle, and review receipts remain null
  ([source](../../../config/smallwood-v8-poseidon2-profile-manifest.json#L48-L63));
- the release manifest's fresh retained-proof hash fields remain null; this is
  an unpromoted release record, not an assertion that no fresh proofs exist
  ([source](../../../config/smallwood-v8-poseidon2-profile-manifest.json#L92-L93)); and
- the executable-ZK diagnostic records whole-view refinement false, concrete
  SHA-512 acceptance false, both endpoint receipts absent, and production
  eligibility false
  ([source](../../../docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json#L66-L67),
  [source](../../../docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json#L91-L100)).

Two independently generated repaired-relation proofs are physically retained,
each 122,735 bytes, with cross-verification and an isolated native lifecycle
receipt. They bind the recorded b1e5c143f7abf052 source snapshot. Subsequent
formal/test integration requires another frozen final snapshot and fresh
receipts; it must not silently rebind these old generation inventories
([exact evidence and transport limits](repaired-proof-execution.md)).

Local formal gates, source/vector agreement and simulated proof diagnostics
do not replace those artifacts, independent review, or production authority.

At the 2026-09-08 03:31 UTC audit snapshot, the complete formal-crypto gate
passed 2,945 build jobs and all 745 designated declarations used only
`propext`, `Classical.choice`, and `Quot.sound`. This includes the complete
arbitrary-packed semantic endpoint, full authorization and enabled stable
transition, measured oracle games, literal post-final proof/error bytes,
collision-exact mixed writes, source-tree/path geometry and complete request
query bounds
([umbrella](../../../formal/crypto/HegemonCrypto.lean),
[credited roots](../../../formal/crypto/credited-declarations.txt)). The three
proof-wire vectors were unchanged, and all 48 generated relation modules
(2,266,857 source bytes) matched exactly. Final-write and whole-history
composition modules and the public source-lifetime privacy endpoint are included.
These are local
intermediate checks, not P7, K8, universal Rust execution refinement, retained
proof evidence, independent release review, or production authority.

## Minimum dependency-ordered closure

The minimum partial order is fixed; later evidence cannot bypass an earlier
edge. The privacy steps 2-3 and soundness steps 4-5 are sibling branches and may
proceed in parallel. Both must finish before step 6.

1. **Freeze I0-I5 for the repaired digest.** Reconcile the grammar-marker and
   relation-lineage documentation; bind exact public/proof bytes and every raw
   SHA-512 role/counter to one coherent oracle; define the physical cq
   experiment; and approve one lifetime `(Q,T,V,time,H_sha)` resource model.
2. **Close P0-P4.** Refine the actual Rust prover, public-context serialization,
   RNG/abort behavior, complete honest joint law, and witness-free simulator to
   the same persistent oracle. Instantiate and prove the adaptive single-proof
   programming theorem with exact chronology, dependence, collision, and
   sampler losses.
3. **Close P5-P7.** The modeled repeated-request hybrid, derived adjacent
   bounds and public simulator triangle now pass Lean without oracle reset.
   Connect the actual Rust experiment to that model; compose concrete SHA-512 and all
   refinement losses from the common resource ledger; then construct an
   inhabited P7 receipt proving at most `2^-128`.
4. **Close K0-K4.** Define actual Rust acceptance-and-extraction-failure from
   unchanged proof bytes; prove exact round/challenge chronology and Merkle
   binding/proximity; construct an efficient full committed-oracle extractor;
   prove the concrete universal MCA line budget; and transfer the actual SHA-
   derived PIOP/DECS challenge laws.
5. **Close K5-K8.** Prove the two-sided CMS instability for that event, the
   raw-SHA-512-to-exact-logical-oracle reduction. The one-way packed-witness
   semantic implication is now proved, including authorization, cryptographic
   links and enabled stable transitions; extraction must supply its actual
   admitted domain. Compose all soundness losses and construct an inhabited
   K8 receipt at `2^-128`.
6. **Close R0-R4, then authorize R5 separately.** Prove universal
   Rust/Lean/compiler equivalence on arbitrary bytes, binary/native and full-
   action refinement, and unchanged self-contained proof bytes through wallet,
   RPC, relay, mempool, mining, block, sync, restart, reorg, and fresh-node
   paths. Retain authenticated artifacts and independent review. Only a
   separate explicit release decision may then enable a finite-lifetime
   capability.

Until all six stages complete for the same digest and carrier, the correct
verdict is: **P7 unavailable, K8 unavailable, R0 unavailable; repaired-relation
proofs exist for a preserved historical source snapshot, while final-snapshot
regeneration and actual socket carrier evidence are pending. The active V8
production capability remains `None`, and the repaired relation is unselected
and production-unauthorized**
([source](daybreak-regeneration-map.md#L146-L152)).
