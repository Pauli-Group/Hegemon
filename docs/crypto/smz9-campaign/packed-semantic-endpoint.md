# Complete SMZ9 packed-to-typed semantic implication

Status: the complete fixed relation implication and its full-action wrapper
passed strict direct Lean checking on 2026-09-08 UTC. This closes the
packed-to-typed semantic implication for the repaired generated program. It does
not close universal handwritten Rust execution refinement, accepted-proof-byte
extraction, semantic-to-packed lowerer completeness, or production authorization.

The endpoint does not assume an honestly lowered witness, a private hash result,
typed semantic validity, or a receipt containing the desired conclusion.
Repository integration and the integrated gate are separate from the completed
per-module checks reported here.

## Exact program and premise

The generated `HGV8RP03` relation has 20,605 CSR attempts and 43,904 packed
witness words. The serialized program is 853,429 bytes with SHA-512:

```text
180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84
```

These are the values in
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9RelationProgramComponentsGenerated.lean`.
The source digest identifies this instance; the digest alone is not a proof of
Rust execution correspondence.

The relation endpoint takes exactly one named propositional premise:

```lean
domain : CanonicalPublicPackedDomain statement publicWords packed
```

The definition in `SmallWoodV8Smz9SemanticBinding.lean` expands to:

```lean
encodePublicStatement statement = publicWords ∧
  CanonicalPublicStatement exactV8SemanticPrimitives statement ∧
  hgv8rp03ProgramComponents.AcceptsPacked publicWords packed
```

Its conclusion is:

```lean
ExactV8RelationSemanticValid statement
  (projectTypedWitness statement packed)
```

The statement, public list, and packed list are otherwise universally
quantified. Acceptance is for the actual generated program, not a simplified
surrogate. The projected witness is the existing total source-coordinate
projection. No equality to an honest materializer is required. Raw
`AcceptsPacked` without public admission is deliberately not the domain: the
independent public predicate supplies, among other requirements, inactive public
padding and the repaired exactly-once stable-asset membership rule.

## All five fixed semantic conjuncts

The conclusion uses the existing independent semantic specification in
`formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean`. It is not
a newly weakened endpoint predicate.

| Fixed conjunct | Discharged content |
| --- | --- |
| `CanonicalPublicStatement exactV8SemanticPrimitives statement` | Taken from the explicit public-admission component of the domain. |
| `CanonicalWitnessShape statement witness` | Actual activity flags, active note/key/range/selector constraints, zero inactive openings, shared active spend key, Merkle sibling shape, and stable witness shape. |
| `V8CryptographicLinksValid exactV8SemanticPrimitives statement witness` | Every active input's exact note/Merkle and mode-dependent nullifier links, every active output's exact note commitment, and the full authorization predicate. |
| `V8BalanceValid statement witness` | Existing native-fee and per-asset integer conservation rules, including the compatibility issuance/burn branch. |
| `exactV8StableTransition (derivedRelationContext statement) statement.stablecoin witness.stablecoin` | The complete disabled, mint, and burn cases, including enabled policy, counters, collateral, issuer hashes, and before/after state roots. |

Here `witness` is always `projectTypedWitness statement packed`. Every private
conjunct is derived; none is an extra premise of the final theorem.

The hash chains bind actual accepted rate and capacity coordinates to the exact
Poseidon2 sponge/compression definitions. They include all four note openings,
both 32-level input Merkle paths, both nullifier calls, the transaction PRF,
policy and action-intent sponges, current/next accumulator digests, value-lock
digest, and the stable configuration, issuer, and state-root chains. Finite
source-coordinate certificates are membership proofs in the generated program;
they do not replace the arbitrary-acceptance hypothesis with a finite witness
fixture.

### Authorization and nullifier coverage

| Actual mode | Complete authorization branch | Effective nullifier scalar |
| --- | --- | --- |
| `singleKey` | Zero current/next accumulators and signer tags; every active input key equals PRF limbs 1–4. The transaction spend key follows the first active input, including the second-input-only case. | PRF limb 0 of the active input spend key. |
| `approvalStep` | Both inputs and output slot 0 are active; canonical current/next accumulators and policy signer tags; exact policy root; preserved policy/intent/threshold/signer count; approval count increments once; exactly one newly approved slot and no cleared approval; that slot binds the actual transaction signer's five-word tag; both input keys and the output-slot-0 key bind their required exact digests. | Input zero: current accumulator digest limb 4. Input one: PRF limb 0. |
| `finalThresholdSpend` | Both inputs active; canonical current accumulator and signer tags; zero next accumulator; exact policy root; approval count reaches threshold; intent matches the exact current action; input keys bind the value-lock and current accumulator digests. | Input zero: value-lock digest limb 4. Input one: current accumulator digest limb 4. |

All-mode nullifier composition rewrites the actual source-selected scalar into
`effectiveInputAuthorizationPrf`; it does not treat non-single modes as the
legacy PRF path. Canonical signer constraints include inactive zero tags, active
nonzero tags, distinct active tag first words, and the required accumulator
count/bitmap bounds. The final assembly follows the source-selected mode and
discharges every conjunct of `V8AuthorizationValid`.

## Principal theorem roots

All namespaces in this table have the prefix `HegemonCrypto.SmallWood.`. Files
are under `formal/crypto/HegemonCrypto/`.

| Module | Namespace and theorem |
| --- | --- |
| `SmallWoodV8Smz9InputMerklePublic` | `V8Smz9InputMerklePublic.admitted_packed_project_typed_merkle_roots` |
| `SmallWoodV8Smz9AllModeNullifierEndpoint` | `V8Smz9AllModeNullifierEndpoint.admitted_packed_project_typed_nullifiers` |
| `SmallWoodV8Smz9SemanticEndpointOutputs` | `V8Smz9SemanticEndpointOutputs.admitted_packed_project_typed_output_commitments` |
| `SmallWoodV8Smz9FullAuthorizationEndpoint` | `V8Smz9FullAuthorizationEndpoint.admitted_packed_project_typed_authorization` |
| `SmallWoodV8Smz9StableEnabledEndpoint` | `V8Smz9SemanticStableEnabledEndpoint.admitted_stable_transition` |
| `SmallWoodV8Smz9CryptographicLinksEndpoint` | `V8Smz9ExactSemanticEndpoint.admitted_packed_project_typed_cryptographic_links` |
| `SmallWoodV8Smz9ExactSemanticEndpoint` | `V8Smz9ExactSemanticEndpoint.admitted_packed_project_typed_exact_semantics` |
| `SmallWoodV8Smz9ExactSemanticEndpoint` | `V8Smz9ExactSemanticEndpoint.admitted_packed_project_typed_exact_full_action` |

The full-action theorem has the same `domain` premise plus exactly these two
external-admission predicates:

```lean
ConsensusContextMatches context statement
InlineCiphertextsMatch exactV8SemanticPrimitives statement ciphertexts
```

It concludes `ExactV8FullActionSemanticValid context ciphertexts statement
(projectTypedWitness statement packed)`. Context matching binds the actual
current stable root, parent height, and expected action intent. Ciphertext
matching checks slot presence, exact 2,147-byte active ciphertext length, byte
bounds, and exact ciphertext commitments. This wrapper proves the private
relation conjunct itself; it does not claim that Rust or a caller has established
the two additional premises.

## Dependency closure and checking evidence

A recursive import walk from `ExactSemanticEndpoint` across the four completion
work directories counted **76 new modules**, including the root, with duplicates
removed. The count excludes pre-existing Hegemon and Mathlib infrastructure and
scratch-only audit modules. It is an implementation-unit count, not a count of
independent security properties.

| Completion group | Modules in the final new-module closure |
| --- | ---: |
| Transaction hashes, authorization, Merkle, and final composition | 50 |
| Shared compression and stable hash chains | 7 |
| Stable scalar, policy, typed bridges, and final stable composition | 15 |
| Stable collateral and common predicate | 4 |
| Total | 76 |

The 50-module group includes the separately developed five-module input-Merkle
chain. The 26 remaining modules include shared compression, so they should not
be described as 26 independent stablecoin properties.

Every module used by the final scratch closure was successfully emitted before
its dependent checks. Direct checks used:

```text
-j1 -M3072 -DautoImplicit=false -DwarningAsError=true
```

The complete authorization and cryptographic-links modules passed before the
final relation module. The final relation and full-action roots both passed with
exactly these transitive axiom sets:

```text
[propext, Classical.choice, Quot.sound]
```

No new axiom, `sorry`, or `native_decide` is used to establish these final roots.
Imported specification files may contain unrelated native-decided finite KATs;
the printed transitive dependencies show that those KAT axioms are not used by
these endpoints. Source-membership certificates that use ordinary `decide`
remain kernel-checked.

An independent worker within this execution read the final authorization,
cryptographic-links, relation, and full-action assembly. It found no omitted
fixed conjunct or circular semantic-output premise. This is an internal
execution review, not an external cryptographic review or release approval.
Separate bounded source reviews and their limitations are recorded in
[Rust source-refinement obligations](rust-source-refinement-obligations.md).

## What remains separate

1. **Rust public admission.** Prove actual successful public parsing and
   validation imply exact Lean encoding and `CanonicalPublicStatement`,
   including the source-owned action-intent computation. Public-only admission
   does not require an honest private lowering premise.
2. **Rust packed evaluator and typed decoder.** Prove the real source arithmetic,
   expression interpreter, CSR normalization, 64-lane indexing, and decoder
   branches refine their Lean definitions. A total Lean projection and finite
   layout coverage do not by themselves prove the partial Rust decoder succeeds
   or returns that projection.
3. **Actual proof carrier.** Establish that accepted self-contained SMZ9 proof
   bytes supply the required full-assignment or polynomial evidence and its
   binding to the packed relation. The local `verify_packed_witness` decode,
   typed validation, and relowering checks run in compile/audit/test paths; they
   are not secret-assignment recovery by the candidate proof verifier. This
   theorem starts after packed acceptance and cannot substitute for extraction
   or proof-system soundness.
4. **Lowerer completeness and the full adequacy receipt.** The converse
   `ExactV8RelationSemanticValid ->` successful exact source lowering and packed
   acceptance is not proved here. Nor are all source decoder roundtrips and
   receipt fields automatically inhabited by this one-way implication. The
   repaired stable-asset counterexample regression and passing honest fixtures
   do not establish universal completeness.
5. **End-to-end security and production authority.** This semantic implication
   is not an independently established soundness, QROM, privacy, PQ128, or
   production theorem. Actual consensus/ciphertext admission, unchanged
   self-contained proof transport, and independent security and release gates
   remain necessary.

The result therefore closes the complete fixed **packed-to-typed semantic
implication**, with explicit public admission, while preserving the separate
execution, extraction, completeness, and production boundaries.
