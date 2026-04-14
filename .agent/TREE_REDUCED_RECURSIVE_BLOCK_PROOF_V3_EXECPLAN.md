# Tree-Reduced Recursive Block Proof V3

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the tree-reduced recursive block-proof lane will keep its parallel chunk-and-merge proving model, but it will stop exploding in artifact size. The user-visible outcome is simple: the tree lane should still prove disjoint contiguous segments in parallel and still emit one fixed-width `recursive_block_v3` artifact, but that artifact should be competitively small instead of ballooning to tens of megabytes.

The current experimental tree lane, `recursive_block_v2`, is already constant-size, but its fixed size is wrong for product use: the current derived outer artifact is `26,023,844` bytes, while the shipped serial lane `recursive_block_v1` is `699,404` bytes and the shipped recursive proof field is `698,536` bytes. This plan exists to make the tree design structurally sane, not just bounded.

The key idea is to stop putting full child proof bytes into the parent recursive witness. Instead, `v3` will introduce one compact recursive child object: a fixed-width backend-specific verification object that contains only what a parent merge/carry relation actually needs to verify a child proof. The entire plan stands or falls on that change. If the backend cannot support such an object without carrying the same full proof payload, then tree reduction on this backend is not worth shipping.

## Progress

- [x] (2026-04-14 20:53Z) Audit the current `tree_v2` geometry and confirm the exact blow-up source.
- [x] (2026-04-14 20:53Z) Confirm the current `tree_v2` bounded-domain cap and artifact size: root proof cap `26,023,056`, outer artifact `26,023,844`, with `TREE_RECURSIVE_CHUNK_SIZE_V2 = 4` and `TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 = 1000`.
- [x] (2026-04-14 20:53Z) Draft the `tree_v3` optimization plan centered on a compact recursive child object instead of raw child proof bytes.
- [ ] Prototype the backend compact-child-object surface in `transaction-circuit`.
- [ ] Measure the derived proof-cap geometry for the compact-child-object design and compare it to `v1` and `v2`.
- [ ] Implement a `recursive_block_v3` spike in `circuits/block-recursion` using the compact child object.
- [ ] Redteam malformed child-object decoding, wrong profile/kind wiring, nonzero padding, cross-version misuse, and incorrect boundary joins.
- [ ] Decide whether `v3` is promotable, experimental-only, or a dead end.

## Surprises & Discoveries

- Observation: the current `tree_v2` design is constant-size but compression-bad.
  Evidence: [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs#L1605) derives `level_caps = [51816, 153664, 357360, 764752, 1579536, 3209104, 6468240, 12986512, 26023056]`, and the outer artifact size is `26,023,844`.

- Observation: merge and carry relations re-embed padded child proof bytes directly into the parent witness.
  Evidence: [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs#L248) appends `left_padded` and `right_padded` child proofs to merge witness bytes, and [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs#L301) appends `child_padded` to carry witness bytes.

- Observation: the Smallwood recursive proof-size hint grows with `auxiliary_witness_words().len()`.
  Evidence: [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs#L1553) computes projected proof size from `statement.auxiliary_witness_words().len()`, and [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs#L3005) serializes an `opened_witness` bundle sized by `auxiliary_words_len`.

- Observation: this creates a bad recurrence, not a one-time cap mistake.
  Evidence: the parent merge witness allocates approximately `2 * child_proof_cap + overhead` in [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs#L252), so parent proof size grows with child proof size rather than staying flat by level.

- Observation: a bounded-domain proof cap can make the current tree lane valid, but it cannot make it competitive.
  Evidence: the current `v2` bounded-domain cap now passes `prove_and_verify_recursive_artifact_v2_succeeds`, `recursive_artifact_v2_constant_size_across_tx_counts`, and the explicit `RecursiveBlockV2` consensus/runtime admission tests, but the derived cap is still two orders of magnitude worse than the shipped lane.

## Decision Log

- Decision: do not try to “optimize `v2`” with small local edits.
  Rationale: the blow-up is structural. As long as child proofs are copied into parent auxiliary witness bytes, proof size will remain dominated by recursive witness payload, not by minor serialization overhead.
  Date/Author: 2026-04-14 / Codex

- Decision: model the optimized tree lane as `recursive_block_v3`, not as a silent mutation of `v2`.
  Rationale: the proposed change introduces a different recursive verification object and therefore a different proof language. That must be versioned explicitly.
  Date/Author: 2026-04-14 / Codex

- Decision: the first milestone is a backend spike, not more block-recursion plumbing.
  Rationale: if `transaction-circuit` cannot expose a compact recursive child object, then no amount of work in `circuits/block-recursion` will make the tree lane small.
  Date/Author: 2026-04-14 / Codex

- Decision: define success against two bars, not one.
  Rationale: `v3` must be both correct and worth keeping. The hard correctness bar is fixed-width and fail-closed verification. The utility bar is size competitiveness: if `v3` stays in multi-megabyte territory, it is not a product improvement.
  Date/Author: 2026-04-14 / Codex

- Decision: require one explicit kill condition.
  Rationale: if the backend spike proves that a compact child object cannot avoid carrying effectively the same full proof payload, the plan must stop and document that tree reduction is not viable on the current Smallwood recursive backend.
  Date/Author: 2026-04-14 / Codex

## Outcomes & Retrospective

- Outcome: this document captures the first implementation-grade optimization attempt for the tree lane.
  Gap: no code has been written yet.
  Lesson: the right question is not “can the tree lane be bounded?” It is “can the backend verify children from a compact object instead of full proof bytes?” That is the only redesign that changes the bad recurrence.

## Context and Orientation

The current shipped recursive block artifact is `recursive_block_v1`. It lives in [circuits/block-recursion/src/artifacts.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/artifacts.rs) and fixes the proof field at `698,536` bytes. The current experimental tree lane is `recursive_block_v2` in [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs). It now has a valid bounded-domain constant-size contract, but that contract is huge.

The main backend facts are:

- `transaction-circuit` projects recursive proof size from the statement geometry and the number of auxiliary witness words.
- `tree_v2` merge/carry nodes put padded child proof bytes directly into those auxiliary witness words.
- Therefore `tree_v2` proof size grows with child-proof cap.

Three terms matter here:

`auxiliary witness words` means the extra witness words exposed by a `SmallwoodConstraintAdapter` statement beyond its row-scalar witness. In the current backend, these words are serialized into the recursive proof object.

`compact recursive child object` means a fixed-width backend-specific object that is sufficient for recursive child verification but is smaller than the full serialized child proof. This object does not exist yet. Creating or rejecting it is the first job of this plan.

`product-competitive` means “small enough that replacing the shipped serial lane is plausible.” For this plan, the hard stretch target is “root proof cap no larger than `RECURSIVE_BLOCK_PROOF_BYTES_V1`”. The softer acceptance bar is “root proof cap below `2,000,000` bytes and materially below `v2`.” Anything much larger is experimental only.

The relevant files are:

- [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs): proof-size hint and proof serialization geometry.
- [circuits/transaction/src/smallwood_recursive.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_recursive.rs): recursive proving and verification entry points.
- [circuits/block-recursion/src/tree_v2.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v2.rs): current tree chunk/merge/carry relations and current cap report.
- [circuits/block-recursion/src/artifacts.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/artifacts.rs): shipped `v1` constant-size artifact geometry.
- [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs), [pallets/shielded-pool/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/pallets/shielded-pool/src/lib.rs), and [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs): versioned recursive artifact verification and admission surfaces.

## Plan of Work

The plan has four real stages and one kill gate.

Stage 1 is the backend spike. In [circuits/transaction/src/smallwood_recursive.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_recursive.rs) and [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), define one experimental compact recursive child object:

    pub struct SmallwoodRecursiveChildObjectV3 {
        pub profile_tag: SmallwoodRecursiveProfileTagV1,
        pub relation_kind: SmallwoodRecursiveRelationKindV1,
        pub statement_digest: [u8; 32],
        pub verifier_material: Vec<u8>,
    }

The exact contents of `verifier_material` must come from the recursive verifier’s true needs, not from guesswork. The implementation work in this stage is to identify the minimum backend material required to verify a child proof and encode only that. This stage must also add:

    pub fn derive_recursive_child_object_v3(...) -> Result<SmallwoodRecursiveChildObjectV3, TransactionCircuitError>
    pub fn verify_recursive_statement_from_child_object_v3(...) -> Result<(), TransactionCircuitError>
    pub fn projected_smallwood_recursive_child_object_bytes_v3(...) -> Result<usize, TransactionCircuitError>

If this stage ends up serializing effectively the same full proof payload, stop. Record that the backend cannot support a compact child object and mark the plan dead.

Stage 2 builds a size model around that child object. Add a new experimental module, [circuits/block-recursion/src/tree_v3.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v3.rs), not a mutation of `tree_v2.rs`. The module should keep the same segment statement language as `v2`, but merge/carry witness bytes must now store:

- child profile tag
- child relation kind
- child statement bytes
- fixed-width compact child object bytes

They must not store full padded child proof bytes. The module must expose:

    pub struct TreeProofCapReportV3 { ... }
    pub fn derive_tree_proof_cap_v3() -> Result<TreeProofCapReportV3, BlockRecursionError>
    pub fn recursive_block_artifact_bytes_v3() -> usize

This stage is complete only when the cap report is derived from the compact child object size rather than the full proof size.

Stage 3 is the proving and verification spike. Still in [circuits/block-recursion/src/tree_v3.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v3.rs), implement `ChunkA`, `MergeA`, `MergeB`, `CarryA`, and `CarryB` over the compact child object and prove one real `recursive_block_v3` artifact. Then add verification that reconstructs child relations from the compact child object and the public statement, not from raw child proof bytes. This stage stays experimental only; it must not touch the shipped default lane.

Stage 4 is the comparison gate. Measure `v3` against:

- shipped `v1`
- current bounded `v2`

at `tx_count = 1`, `5`, `32`, `128`, and `1000` if feasible. Record:

- root proof cap
- outer artifact size
- prove time
- verify time
- peak RSS

If `v3` is not materially better than `v2`, reject it. If it is much smaller but still too large to compete with `v1`, keep it experimental only. If it is both correct and competitive, then and only then write the product-lane promotion follow-up.

The kill gate is explicit. Abort the plan if any of the following are true:

- the compact child object cannot be made materially smaller than the full proof,
- recursive verification from the compact child object is not fail-closed,
- the derived `v3` root proof cap remains above `2,000,000` bytes,
- or the implementation requires changing the backend so drastically that it is no longer meaningfully the same recursive proof family.

## Concrete Steps

Run all commands from the repository root, `/Users/pldd/Projects/Reflexivity/Hegemon`.

First, confirm the current comparison point:

    cargo test -p block-recursion v2 -- --ignored --nocapture

Expected result: the `v2` ignored tests pass, including constant-size checks, but the artifact remains about `26 MB`.

Then execute the backend spike:

    cargo test -p transaction-circuit recursive_child_object_v3_ -- --nocapture

Add tests that prove:

- deriving `SmallwoodRecursiveChildObjectV3` from a valid recursive proof succeeds,
- verification from that child object accepts the honest proof,
- tampering any child-object field fails closed,
- cross-profile or cross-relation use fails closed,
- nonzero padding or alternate serializer forms fail closed if fixed-width packing is used.

Then execute the tree-lane spike:

    cargo test -p block-recursion tree_v3_ -- --ignored --nocapture

Add tests that prove:

- `recursive_block_v3` proves and verifies for `tx_count = 1` and `5`,
- serialized width is constant across at least those tx counts,
- `v1`/`v3` and `v2`/`v3` cross-version parsing fail closed,
- malformed child objects, bad join boundaries, wrong child profile tags, and nonzero child padding all fail closed.

Then run the comparison set:

    cargo test -p block-recursion compare_tree_v1_v2_v3_sizes -- --ignored --nocapture

This comparison test must print the measured or derived:

- `v1` root proof cap
- `v2` root proof cap
- `v3` root proof cap
- `v1` artifact size
- `v2` artifact size
- `v3` artifact size

The test may be ignored if it is slow, but it must be executable and must record results in the plan as implementation proceeds.

## Validation and Acceptance

Acceptance is not “the code compiles.” Acceptance means all of the following are true:

- `recursive_block_v3` proves and verifies on real sample blocks.
- `recursive_block_v3` has one exact serialized width across different tx counts in its supported domain.
- the verifier accepts only that width and rejects malformed compact child objects fail-closed.
- `v3` is materially smaller than `v2`.

The stretch acceptance bar is:

- `recursive_block_v3` root proof cap `<= 698,536` bytes, matching the shipped `v1` recursive proof field.

The minimum acceptable experimental bar is:

- `recursive_block_v3` root proof cap `< 2,000,000` bytes,
- and materially below `v2`.

If neither bar is met, the plan is still useful, but the outcome is “reject for product use.”

## Idempotence and Recovery

All work in this plan is additive and should be done behind the experimental `v3` surface. Do not mutate `v1` or the current bounded `v2` lane while proving out the optimization. If the backend spike fails, keep the failure in code only if the tests and plan clearly record that `v3` is rejected. Otherwise, revert the unfinished `v3` spike and preserve only the documentation of the failed approach.

Because the plan is experimental, every stage should be rerunnable without changing shipped defaults. That means:

- no default mode switches,
- no runtime admission changes for `v3` until the comparison gate is passed,
- no silent cap changes to existing `v1` or `v2` constants.

## Artifacts and Notes

The current comparison anchor is:

    recursive_block_v1 proof field: 698,536 bytes
    recursive_block_v2 root proof cap: 26,023,056 bytes
    recursive_block_v2 outer artifact: 26,023,844 bytes

The current bad recurrence in `v2` is:

    merge witness ~= left statement + left padded child proof
                   + right statement + right padded child proof

    carry witness ~= child statement + child padded proof

    projected proof bytes ~= f(auxiliary_witness_words.len())

That is why `v2` grows by level instead of staying flat.

The `v3` spike should aim for this new recurrence instead:

    merge witness ~= left statement + left compact child object
                   + right statement + right compact child object

    carry witness ~= child statement + child compact child object

    projected proof bytes ~= f(constant child object size)

The whole point is to make the parent witness depend on a fixed compact child object, not on the child proof cap.

## Interfaces and Dependencies

At the end of the backend spike, these interfaces must exist:

In [circuits/transaction/src/smallwood_recursive.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_recursive.rs), define:

    pub struct SmallwoodRecursiveChildObjectV3 { ... }
    pub fn derive_recursive_child_object_v3(
        profile: &RecursiveSmallwoodProfileV1,
        descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
        binded_data: &[u8],
        proof_bytes: &[u8],
    ) -> Result<SmallwoodRecursiveChildObjectV3, TransactionCircuitError>

    pub fn verify_recursive_statement_from_child_object_v3(
        profile: &RecursiveSmallwoodProfileV1,
        descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
        binded_data: &[u8],
        child_object: &SmallwoodRecursiveChildObjectV3,
    ) -> Result<(), TransactionCircuitError>

    pub fn projected_smallwood_recursive_child_object_bytes_v3(
        profile: &RecursiveSmallwoodProfileV1,
        descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
    ) -> Result<usize, TransactionCircuitError>

At the end of the block-recursion spike, these interfaces must exist:

In [circuits/block-recursion/src/tree_v3.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tree_v3.rs), define:

    pub struct TreeProofCapReportV3 { ... }
    pub fn derive_tree_proof_cap_v3() -> Result<TreeProofCapReportV3, BlockRecursionError>
    pub fn recursive_block_artifact_bytes_v3() -> usize
    pub fn prove_block_recursive_v3(
        input: &BlockRecursiveProverInputV3,
    ) -> Result<RecursiveBlockArtifactV3, BlockRecursionError>
    pub fn verify_block_recursive_v3(
        artifact: &RecursiveBlockArtifactV3,
        expected_public: &RecursiveBlockPublicV3,
    ) -> Result<RecursiveBlockPublicV3, BlockRecursionError>

Do not export `v3` into consensus/runtime until the comparison gate says it is worth keeping.

Revision note: this file was created on 2026-04-14 because the newly corrected `tree_v2` lane proved that bounded-domain constant size is achievable on the current backend, but only at an unacceptable artifact size. The plan therefore shifts from “make the tree lane sound” to “make the tree lane compact enough to matter.” 
