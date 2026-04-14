# Tree-Reduced Recursive Block Proof

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the recursive block-proof lane will still ship one constant-size `recursive_block` artifact, but proving will no longer be forced through one serial prefix chain over all transactions. Instead, the prover will be able to prove disjoint contiguous segments of the ordered verified-leaf stream in parallel, then merge those segment proofs in a binary tree until one terminal proof remains.

The user-visible win is prover latency and throughput. Large blocks should stop paying an `O(n)` recursive critical path where every step waits for the previous proof. The final shipped artifact must remain fixed-width and consensus-visible semantics must remain unchanged. A successful implementation is observable by proving the same block through both the old serial lane and the new tree-reduced lane, verifying both against the same canonical public tuple, and showing that the new lane reaches the same constant-size product boundary with lower wall-clock latency on multi-core machines.

## Progress

- [x] (2026-04-14 15:50Z) Draft the tree-reduction design against the current shipped prefix-proof lane.
- [x] (2026-04-14 16:12Z) Run hostile review on the draft and fix the first critical/high design issues: explicit artifact versioning, deterministic tree schedule, and composable public boundary fields.
- [x] (2026-04-14 16:26Z) Run a second hostile review and fix the next high issues: explicit recursion-profile schedule and fixed-shape handling for short final chunks.
- [ ] Define the segment public statement, witness model, and exact merge invariants.
- [ ] Prototype a binary merge relation over contiguous intervals without changing the shipped artifact contract.
- [ ] Replace the serial prover loop in `circuits/block-recursion/src/prover.rs` with chunk proving plus merge proving.
- [ ] Add correctness tests proving tree-composed output matches the serial lane on the same ordered verified-leaf stream.
- [ ] Add performance measurements comparing serial prefix proving against tree-reduced proving at multiple transaction counts.
- [ ] Redteam malformed interval composition, duplicate-leaf splicing, gap insertion, reordered children, and forged boundary-state joins.

## Surprises & Discoveries

- Observation: the current shipped recursive statement is a prefix summary, not a segment summary.
  Evidence: [circuits/block-recursion/src/statement.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/statement.rs) defines `RecursivePrefixStatementV1` only in terms of `tx_count`, start/end state digests, cumulative verified-leaf/receipt commitments, and start/end tree commitments. There is no segment start index or explicit mid-state.

- Observation: the current recursive prover is structurally serial.
  Evidence: [circuits/block-recursion/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/prover.rs#L293) iterates over `input.records` in one `for` loop, threads one `current_context`, and makes each recursive step depend on the previous proof context.

- Observation: the theorem note already isolates the exact recursive state needed for compositional reasoning.
  Evidence: [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L214) defines `S_i = (i, lambda_i, tau_i, eta_i, T_i, U_i)`, and [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L405) states that recursive verification is field arithmetic plus Poseidon2 transcript/authentication checks.

- Observation: the current `recursive_block_v1` header cannot safely encode the new relation family.
  Evidence: the theorem note and current verifier only recognize `BaseA`, `StepA`, and `StepB` as terminal recursive relation kinds; see [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L580) and [circuits/block-recursion/src/verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/verifier.rs#L27).

- Observation: the first draft overclaimed “segment commitments” without defining a public composition law.
  Evidence: the live recursive tuple is built from cumulative boundary projections such as `proj_6(lambda_n)`, `proj_6(tau_n)`, `proj_6(eta_n)`, `Sigma_tree(T_0)`, and `Sigma_tree(T_n)`; it does not expose a standalone monoidal summary for arbitrary subranges; see [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L644).

- Observation: the draft left recursion-profile assignment underdefined.
  Evidence: the tree family introduced `Chunk*` and `Merge*` names but did not specify how level parity, orphan carry, and terminal kind interact with the existing alternating recursive profiles. Two honest implementations could otherwise pick different `A/B` schedules.

- Observation: the draft treated the last short chunk as if it would naturally preserve proof shape.
  Evidence: a final chunk with fewer than `K_chunk` leaves changes witness length unless the relation explicitly uses one fixed `K_chunk` witness schema plus inactive-slot constraints. Without that, proof shape and proof width can drift by chunk length.

## Decision Log

- Decision: model the tree-reduced design as a new recursive statement family rather than trying to make the current prefix statement secretly associative.
  Rationale: the current public statement only says “the first `i` leaves are processed.” Tree reduction requires a proof about one contiguous interval `[a,b)`, so the statement must carry interval boundaries and matching boundary states explicitly.
  Date/Author: 2026-04-14 / Codex

- Decision: keep the shipped outer artifact contract constant-size and change only the recursive proving internals.
  Rationale: consensus, node routing, and the runtime already assume one fixed-width recursive block artifact. The performance redesign should preserve that product boundary even if a protocol version bump is required for the new relation family.
  Date/Author: 2026-04-14 / Codex

- Decision: require exact contiguity and exact boundary-state equality at every merge.
  Rationale: order is part of the block semantics. A tree reduction that is only “set-like” or “multiset-like” would be unsound for the statement sponge, verified-leaf sponge, receipt sponge, and append-state transition.
  Date/Author: 2026-04-14 / Codex

- Decision: the tree-reduced shipped artifact must use a new artifact version rather than mutating `recursive_block_v1`.
  Rationale: `v1` hardcodes terminal relation kinds and verifier keys for `BaseA`, `StepA`, and `StepB`. A tree family introduces `Chunk*` and `Merge*` relation ids and likely a different fixed proof cap, so reusing `v1` would silently alias two different proof systems under one header meaning.
  Date/Author: 2026-04-14 / Codex

- Decision: the segment public statement will expose boundary projections and boundary digests, not an underdefined “segment-local commitment” object.
  Rationale: the live recursive semantics are cumulative Poseidon2 states. Those are composable by exact boundary matching, not by a public commutative summary for arbitrary subranges. The plan now defines composition by copying left-start and right-end boundary fields and proving equality at the join.
  Date/Author: 2026-04-14 / Codex

- Decision: the tree schedule must be canonical.
  Rationale: if prover implementations can choose arbitrary chunk partitions or odd-level merge behavior, different provers may emit different recursive proof families for the same block. The plan now fixes chunk sizing, adjacency pairing, and orphan carry behavior.
  Date/Author: 2026-04-14 / Codex

- Decision: use one explicit level-parity schedule for recursive profiles and add unary carry relations for orphan promotion.
  Rationale: a plain “carry unchanged” rule conflicts with alternating recursive profiles. The plan now fixes one canonical profile per level and requires an explicit unary carry proof when an odd orphan must move to the next level.
  Date/Author: 2026-04-14 / Codex

- Decision: every chunk relation uses one fixed `K_chunk` witness schema with canonical zero-padding and inactive-slot constraints.
  Rationale: the final short chunk must not create a second proof shape. A fixed-width chunk witness plus exact active-len checks keeps the tree lane descriptor-stable and artifact-width-stable.
  Date/Author: 2026-04-14 / Codex

## Outcomes & Retrospective

- Outcome: initial design document created.
  Gap: no code has been written yet.
  Lesson: the right redesign target is not “parallelize the current loop.” The current proof object itself must change from prefix proofs to contiguous segment proofs plus merge proofs.

- Outcome: first hostile review completed.
  Gap: implementation work has not started, but the plan no longer relies on unsafe `v1` header reuse or on an underdefined segment-composition story.
  Lesson: if the statement does not expose the right public boundaries, “tree reduction” degrades into hand-waving. The schedule and version surface must be fixed in the design, not deferred to implementation.

- Outcome: second hostile review completed.
  Gap: implementation work still has not started, but the plan now fixes both the recursion-profile schedule and the short-final-chunk shape issue.
  Lesson: tree proving needs a deterministic proof-language schedule, not just a deterministic leaf partition.

## Context and Orientation

The shipped constant-size recursive block proof lives in `circuits/block-recursion`. The main product contract is documented in [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md) and implemented in:

- [circuits/block-recursion/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/prover.rs) for recursive proving,
- [circuits/block-recursion/src/verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/verifier.rs) for recursive verification,
- [circuits/block-recursion/src/relation.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/relation.rs) for the concrete recursive Smallwood relations,
- [circuits/block-recursion/src/statement.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/statement.rs) for the recursive public statement shape,
- [circuits/block-recursion/src/artifacts.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/artifacts.rs) for the fixed-width outer artifact contract,
- [circuits/block-recursion/src/public_replay.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/public_replay.rs) for deterministic public replay from ordered verified leaves plus semantic tuple.

Three terms matter here:

`verified leaf stream` means the ordered list of already externally verified transaction-validity artifacts for one block. This is the `records: Vec<BlockLeafRecordV1>` input that the current recursive prover consumes.

`prefix proof` means a recursive proof whose public statement says “the first `i` verified leaves have been processed and yielded this cumulative state.” That is the current design.

`segment proof` means a recursive proof whose public statement says “the contiguous interval of verified leaves from logical index `a` up to but not including logical index `b` transforms one exact boundary state into another exact boundary state.” This is the design required for tree reduction.

The hard product constraint does not change: one final `recursive_block` artifact must still verify the same public block tuple and must still have fixed serialized width independent of transaction count. The theorem note is explicit that constant size constrains only the shipped artifact, not prover work; see [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L55).

## Why The Current Prefix Design Is Serial

The current recursive state is already well-defined. The theorem note defines

    S_i = (i, lambda_i, tau_i, eta_i, T_i, U_i)

where `i` is the processed-leaf count, `lambda_i` is the verified-leaf sponge state, `tau_i` is the transaction-statement sponge state, `eta_i` is the receipt sponge state, `T_i` is the append-state summary, and `U_i` is the sparse nullifier-set summary; see [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md#L214).

The shipped recursive public statement is the prefix summary `P_i`. In code, [RecursivePrefixStatementV1](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/statement.rs#L6) includes:

- `tx_count`,
- `start_state_digest`,
- `end_state_digest`,
- `verified_leaf_commitment`,
- `tx_statements_commitment`,
- `verified_receipt_commitment`,
- `start_tree_commitment`,
- `end_tree_commitment`.

That structure is enough to say “the first `i` ordered leaves were processed,” but not enough to compose two independently proved subranges without replaying one after the other. The prover therefore threads one recursive proof context in one serial loop in [circuits/block-recursion/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/prover.rs#L293).

Tree reduction is impossible on top of that exact statement because the proof does not expose:

- the interval start index,
- the interval end index,
- an explicit proof that the segment begins at one specific `S_a`,
- an explicit proof that the segment ends at one specific `S_b`,
- enough public structure to join `[a,m)` with `[m,b)` without flattening back into the serial prefix path.

## New Design Overview

The new recursive proving line keeps the same external product boundary but changes the internal recursion family from:

- `BaseA`
- `StepA`
- `StepB`

to a new family that supports contiguous intervals:

- `BaseSegA` or equivalent empty/base interval proof,
- `ChunkA`
- `MergeA`
- `MergeB`
- `CarryA`
- `CarryB`

The exact naming is not important. The exact meaning is.

`Chunk` means “prove one contiguous interval directly from witness records.”

`Merge` means “verify two child interval proofs, prove they are exactly adjacent and state-consistent, and emit one parent interval proof.”

`Carry` means “verify one child interval proof and re-emit the same interval statement under the opposite recursion profile so the next merge level stays homogeneous.”

The final terminal artifact still contains one constant-size recursive proof plus one constant-size public tuple. The difference is how the prover reaches that final proof and, likely, which artifact version carries it. The safe assumption for implementation is:

- `recursive_block_v1` remains the current serial-prefix artifact,
- the tree-reduced line ships as `recursive_block_v2`,
- consensus/node/runtime support both during migration,
- only one is treated as the default shipped path at the end.

## Exact Segment Statement

Define a new public recursive statement `SegmentStatementV1(a,b)` for a contiguous interval `[a,b)` with `0 <= a <= b <= n`.

It must contain enough public information to make composition exact and order-preserving. The minimum public fields are:

1. `start_index = a`
2. `end_index = b`
3. `segment_len = b - a`
4. `start_state_digest = Sigma_state(S_a)`
5. `end_state_digest = Sigma_state(S_b)`
6. `start_leaf_projection = proj_6(lambda_a)`
7. `end_leaf_projection = proj_6(lambda_b)`
8. `start_statement_projection = proj_6(tau_a)`
9. `end_statement_projection = proj_6(tau_b)`
10. `start_receipt_projection = proj_6(eta_a)`
11. `end_receipt_projection = proj_6(eta_b)`
12. `start_tree_commitment = Sigma_tree(T_a)`
13. `end_tree_commitment = Sigma_tree(T_b)`

The important design rule is that these are boundary handles, not a fake standalone “segment commitment” object. They are computed from the exact boundary states `S_a` and `S_b`, and those states are in turn defined by exact replay over the contiguous interval.

The start and end state digests must continue to be constant-size Poseidon2-derived handles over the exact internal state. The current theorem note already defines `Sigma_state(S)` and `Sigma_tree(T)`; reuse that language rather than inventing a second state abstraction.

## Canonical Segment Composition

The boundary fields must stay order-sensitive.

The recursive theorem note already says the construction is bound to the exact ordered verified-leaf stream and exact ordered receipt stream. That must remain true under tree reduction. Therefore:

- the left child must represent `[a,m)`,
- the right child must represent `[m,b)`,
- merge must compose left child then right child, never by sorting, deduplicating, or commutative mixing,
- boundary projections at the join must match exactly,
- the parent boundary fields are copied deterministically from the children:
  - parent start fields come from the left child start,
  - parent end fields come from the right child end.

This means the statement layer must support a deterministic ordered combine operation:

    combine_segment(left[a,m), right[m,b)) = parent[a,b)

where the parent boundary tuple equals the boundary tuple that direct replay over `[a,b)` would produce.

For Poseidon2 sponge states, this is only safe if the merge witness carries the true boundary states and the merge relation checks exact equality at the join point. The public composition helper must only perform:

- adjacency checks,
- copied boundary-field assembly,
- field-equality checks across the public join boundary.

It must not pretend to reconstruct cryptographic state transitions from the public projections alone.

## Boundary State Model

The clean boundary model is:

- every segment proof witnesses the full internal start state `S_a`,
- every segment proof witnesses the full internal end state `S_b`,
- the public statement exposes only constant-size boundary handles derived from those states:
  - `Sigma_state(S_a)` and `Sigma_state(S_b)`,
  - the boundary projections `proj_6(lambda_a)`, `proj_6(lambda_b)`, `proj_6(tau_a)`, `proj_6(tau_b)`, `proj_6(eta_a)`, `proj_6(eta_b)`,
  - `Sigma_tree(T_a)` and `Sigma_tree(T_b)`,
- merge relations witness the full intermediate state `S_m` and prove it matches both children exactly.

This keeps the public statement constant-size while making composition exact.

The merge relation must also witness and join:

- the exact append-state summary `T_m`,
- the exact sparse-set summary `U_m`,
- the exact leaf sponge state `lambda_m`,
- the exact statement sponge state `tau_m`,
- the exact receipt sponge state `eta_m`.

Without that, a malicious prover could splice two valid subproofs that happen to share a short digest but do not share the same true intermediate state.

## Canonical Chunking And Merge Schedule

The scheduler must be deterministic. The same ordered verified-leaf stream must induce the same chunk partition and the same merge tree on every honest prover.

Fix one proving parameter `K_chunk`, a positive power of two measured in leaves. The first implementation should choose one concrete value, for example `8`, and record it in the descriptor/config surface of the tree-reduced relation family.

The canonical chunk partition is:

- walk the ordered verified-leaf stream left to right,
- emit maximal contiguous chunks of length exactly `K_chunk`,
- allow only the final chunk to have length `< K_chunk`.

The canonical merge schedule is:

- at each level, pair adjacent interval proofs left to right,
- if the level has an odd number of interval proofs, promote the final rightmost proof through one unary `Carry` relation into the next level’s profile,
- continue until one root proof remains.

The scheduler is therefore a deterministic left-to-right binary reduction with explicit orphan promotion.

This resolves three otherwise dangerous ambiguities:

- two honest provers cannot choose different chunk boundaries for the same block,
- odd leaf counts do not need a fake empty interval proof,
- the root proof kind is deterministic for every `n`.

Fix level `0` as the chunk level. Chunks are proved under profile `A`. For every later level `h >= 1`:

- if `h` is odd, merge and carry proofs on that level use profile `B`,
- if `h` is even, merge and carry proofs on that level use profile `A`.

Every binary merge on level `h` verifies two child proofs produced on level `h - 1`. Every unary carry on level `h` verifies one child proof produced on level `h - 1` and republishes the same interval statement under level `h`'s profile.

The terminal proof kind is therefore:

- `ChunkA` when the whole block fits in one chunk,
- otherwise `MergeA` or `MergeB` when the last level ends with a binary merge,
- otherwise `CarryA` or `CarryB` when the last surviving node was orphan-promoted at the final level.

That terminal-kind mapping must be encoded in the new artifact-version header and verified exactly.

## Chunk Relation

Define `Chunk_tau_v1(P[a,b))` as the recursion-friendly Smallwood relation that proves a contiguous interval directly from raw witness material.

Its witness contains:

- `S_a`,
- `S_b`,
- the ordered leaves `L_a, ..., L_{b-1}`,
- the exact append witnesses for those leaves,
- the exact nullifier-set update witnesses for those leaves,
- any recursive-proof-local witness needed by the Smallwood backend.

Its checks are:

1. `Sigma_state(S_a)` matches the public start digest.
2. `Sigma_state(S_b)` matches the public end digest.
3. `Sigma_tree(T_a)` matches the public start tree commitment.
4. `Sigma_tree(T_b)` matches the public end tree commitment.
5. the leaf sequence is contiguous and ordered by logical tx index.
6. replay of the one-step transition relation over that interval transforms `S_a` into `S_b`.
7. the derived boundary projections and tree commitments equal the public boundary fields.

The chunk size is a proving parameter, not a consensus parameter. A first implementation should choose one fixed small power of two, for example `8` or `16` leaves, because that gives a stable merge fanout and stable benchmark surface.

Every chunk relation must use one fixed witness schema for exactly `K_chunk` leaves. The statement carries the true `segment_len`; the witness carries `K_chunk` leaf slots; and any slot beyond `segment_len` is canonically zero-padded and constrained inactive. No implementation is allowed to generate a smaller proof shape for the short final chunk.

## Merge Relation

Define `Merge_tau_v1(P[a,b))` as the recursion-friendly Smallwood relation that verifies two child interval proofs:

- left child proves `[a,m)`
- right child proves `[m,b)`

Its witness contains:

- the left child proof,
- the right child proof,
- the full intermediate state `S_m`,
- the left statement `P[a,m)`,
- the right statement `P[m,b)`,
- any recursive-proof-local witness material needed to verify those child proofs.

Its checks are:

1. `left.start_index = a`
2. `left.end_index = m`
3. `right.start_index = m`
4. `right.end_index = b`
5. the left child proof verifies against `P[a,m)`.
6. the right child proof verifies against `P[m,b)`.
7. `Sigma_state(S_m)` equals both `left.end_state_digest` and `right.start_state_digest`.
8. `Sigma_tree(T_m)` equals both `left.end_tree_commitment` and `right.start_tree_commitment`.
9. all public boundary projections match exactly at the join:
   - `left.end_leaf_projection = right.start_leaf_projection`
   - `left.end_statement_projection = right.start_statement_projection`
   - `left.end_receipt_projection = right.start_receipt_projection`
10. all other intermediate cumulative states match exactly in the witnessed join state:
   - `lambda_m`
   - `tau_m`
   - `eta_m`
   - `U_m`
11. the parent public statement `P[a,b)` equals the exact ordered composition of the two child interval statements.

This is the crucial point: merge is not a generic “hash two proofs together” relation. It is a proof that two exact adjacent intervals compose to one larger exact interval.

## Carry Relation

Define `Carry_tau_v1(P[a,b))` as the recursion-friendly Smallwood relation that verifies one child interval proof and republishes the same interval statement under the next level’s profile.

Its witness contains:

- one child proof,
- the same interval statement `P[a,b)`,
- any recursive-proof-local witness material needed to verify the child proof.

Its checks are:

1. the child proof verifies against `P[a,b)` under the previous level’s profile,
2. the emitted parent statement is byte-for-byte the same `P[a,b)`,
3. the new proof is tagged for the next level’s canonical profile.

This relation exists only to make odd-width levels deterministic while preserving one homogeneous proof family per level.

## Final Terminal Proof

The final terminal recursive artifact still proves one statement describing the whole block interval `[0,n)`.

Consensus verification remains conceptually the same:

1. verify ordered `tx_leaf` artifacts externally,
2. reconstruct the canonical semantic tuple and terminal public tuple,
3. reconstruct the terminal interval statement `P[0,n)`,
4. verify one final recursive proof against that terminal statement,
5. reject any non-empty legacy payloads on the recursive lane.

So the shipped object remains one fixed-width proof plus one constant-size public tuple. The tree-reduced proving schedule is internal.

## Why This Preserves Constant Size

The hard invariant in [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md) already says the shipped artifact may have linear prover work while keeping constant serialized size.

Tree reduction does not change that. It changes:

- proof schedule,
- recursion depth,
- parallelism,
- proof relation family,
- likely fixed proof-size constant.

It does not require a linear public transcript or per-transaction payload in the final artifact.

The final proof width will likely increase, because a merge relation verifies two child recursive proofs rather than one previous proof. That is acceptable if:

- the width is still one fixed constant for the artifact version,
- the proof remains below the runtime admission cap for the new recursive-block artifact version,
- the latency reduction on multi-core proving is large enough to justify the larger constant.

## Expected Complexity Shift

The current serial prefix prover has:

- total recursive step count `n`,
- recursive critical path depth `n`,
- no meaningful proof-tree parallelism.

The tree-reduced prover should have:

- chunk proving work roughly proportional to `n`,
- merge proving work roughly proportional to `n`,
- recursive critical path depth roughly `log2(number_of_chunks) + chunk_depth`,
- segment proofs and same-level merge proofs executable in parallel.

This does not make proving sublinear. It makes the dependency graph shallower.

## Required Code Changes

### 1. New statement family

Replace or supplement [circuits/block-recursion/src/statement.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/statement.rs) with a segment-oriented statement module. Do not silently overload `RecursivePrefixStatementV1`; the new statement has different semantics.

Add:

- `RecursiveSegmentStatementV1`
- canonical byte encoding
- canonical digest helpers
- exact ordered segment-composition helpers

### 2. New public replay helpers

Extend [circuits/block-recursion/src/public_replay.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/public_replay.rs) so it can:

- replay one contiguous interval,
- build exact segment boundary tuples for `[a,b)`,
- compose adjacent segments deterministically,
- still build the final public tuple for `[0,n)`.

### 3. New relations

Extend [circuits/block-recursion/src/relation.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/relation.rs) with:

- `ChunkARelationV1`
- `MergeARelationV1`
- `MergeBRelationV1`
- `CarryARelationV1`
- `CarryBRelationV1`

or equivalent names.

Do not try to retrofit tree reduction into the current `Base_A` / `Step_A` / `Step_B` relations by adding conditionals. That would blur proof meaning and make redteam work harder. Keep the serial prefix family available until the tree family is validated against it.

### 4. New prover schedule

Replace the serial loop in [circuits/block-recursion/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/prover.rs#L293) with:

1. build chunk inputs from the ordered verified-leaf stream,
2. prove all chunks in parallel,
3. merge adjacent chunk proofs in parallel level by level,
4. continue until one root proof remains,
5. pad the terminal proof to the fixed artifact width,
6. emit the same outer artifact contract.

The chunk scheduler must preserve exact order. It must never reorder leaves for load balancing.

### 5. Verifier and artifact compatibility

Update [circuits/block-recursion/src/verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/verifier.rs) and [circuits/block-recursion/src/artifacts.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/artifacts.rs) only as needed to:

- add one explicit new artifact version for the tree-reduced line,
- recognize the new relation ids / verification keys / terminal relation kinds,
- preserve one fixed-width artifact per version,
- fail closed on old/new mismatch.

Do not mutate `v1` in place. Even if the final proof-width constant accidentally stayed equal, the relation-family meaning changes, so the tree-reduced line must still use a distinct artifact version.

During migration, add verifier regressions that prove all of the following:

- a valid `recursive_block_v1` artifact still verifies under the legacy serial-prefix path,
- a valid tree-reduced `recursive_block_v2` artifact verifies only under the new path,
- `v1` bytes parsed as `v2` fail closed,
- `v2` bytes parsed as `v1` fail closed,
- terminal relation-kind/header mismatches between version and proof family fail closed.

### 6. Node scheduling

After the relation family exists, update the recursive artifact preparation path in [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs) and [node/src/substrate/prover_coordinator.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/prover_coordinator.rs) so the local worker pool can schedule chunk proving and merge levels explicitly instead of one monolithic recursive build task.

## Milestone 1: Segment Statement Prototype

Introduce `RecursiveSegmentStatementV1` and pure Rust helpers that:

- construct segment statements for `[a,b)`,
- compose adjacent segments,
- reject gaps, overlap, and reorderings.

No recursive proving changes yet. This milestone succeeds when unit tests can build direct segment statements for several partitions of the same ordered leaf stream and show that adjacent composition by copied boundary fields plus join-equality checks yields the same terminal boundary tuple as linear replay over `[0,n)`.

Run from the repo root:

    cargo test -p block-recursion segment_statement_ -- --nocapture

Expected result: direct composition and full replay agree for valid adjacent partitions, and tests reject non-contiguous or reordered partitions.

## Milestone 2: Chunk Relation Prototype

Implement direct chunk relations over small contiguous intervals while keeping the current serial prefix lane intact.

This milestone succeeds when one chunk proof over `k` leaves can be produced and verified, and the verified chunk statement matches pure public replay over the same interval.

Run:

    cargo test -p block-recursion chunk_relation_ -- --nocapture

Expected result: chunk proofs verify for valid intervals and fail for interval-boundary mismatches, leaf reorderings, or tampered boundary states.

## Milestone 3: Merge Relation Prototype

Implement merge relations that verify two child proofs and prove one parent interval statement.

This milestone succeeds when:

- two valid adjacent child proofs merge successfully,
- non-adjacent children fail,
- reordered left/right children fail,
- odd-level orphan promotion through `Carry*` is deterministic and tested,
- tampered intermediate-state joins fail,
- the parent statement equals direct public replay over the full joined interval.

Run:

    cargo test -p block-recursion merge_relation_ -- --nocapture

## Milestone 4: Tree Scheduler

Replace the serial prefix scheduler in the recursive prover with:

- deterministic chunking,
- parallel chunk proving,
- parallel merge levels,
- one final root proof.

Keep the serial scheduler behind a test-only or debug-only comparison path until equivalence is proven.

This milestone succeeds when the same block can be proved both ways and the resulting terminal public tuple matches exactly.

Run:

    cargo test -p block-recursion tree_scheduler_matches_serial_prefix_lane -- --nocapture

Expected result: for the same ordered verified-leaf stream, the old serial lane and the new tree-reduced lane produce artifacts that verify against the same public tuple, while cross-version decoding and cross-version verification fail closed.

## Milestone 5: Performance Validation

Benchmark at several transaction counts, for example `1`, `2`, `4`, `8`, `16`, `32`, under fixed local worker counts.

Capture:

- serial prefix wall-clock time,
- tree-reduced wall-clock time,
- peak RSS,
- final proof size,
- artifact version and proof cap,
- chunk proof count,
- merge proof count,
- critical path estimate.

The tree design should only be kept as the shipped default if it materially improves wall-clock latency on multi-core systems without breaking the constant-size artifact contract or pushing the proof field past the runtime cap.

## Milestone 6: Redteam

Run hostile tests that try to exploit the new composition surface:

- duplicate one leaf into two adjacent segments,
- drop one leaf and keep indices consistent elsewhere,
- swap left and right child proofs,
- splice two children with matching short digests but different true boundary states,
- tamper `start_index` / `end_index`,
- feed a non-canonical chunk size,
- forge an orphan carry with a mismatched child profile,
- mutate inactive padded slots in a short final chunk,
- forge boundary fields while keeping some other public fields self-consistent,
- construct different partitions of the same block and prove they yield the same valid final terminal statement only when they encode the same exact ordered leaf stream.

The tree-reduced design is not acceptable until all critical and high composition bugs are closed.

## Open Technical Questions

1. What is the smallest chunk size that gives a net wall-clock win once merge-proof overhead is included?
2. Is it better to witness full intermediate states `S_m` directly at merge time, or to split the join into multiple smaller consistency claims?
3. What is the new fixed proof cap for the final artifact, and does it still fit comfortably inside runtime admission limits?
4. What exact `K_chunk` gives the best tradeoff on the shipped hardware target?

## Acceptance Criteria

The design is complete only when all of the following are true:

1. The final shipped artifact remains constant-size for all admissible transaction counts.
2. Consensus-visible semantics remain unchanged.
3. Tree proving preserves exact leaf order and exact append-state semantics.
4. The implementation can prove disjoint contiguous chunks in parallel and merge them in parallel by level.
5. The root proof verifies against the same final public tuple as the current serial lane.
6. A hostile review finds no critical or high issues in interval composition or boundary-state joins.
7. Benchmarks show a real multi-core wall-clock win relative to the serial prefix prover.

## Non-Goals

This plan does not try to:

- make transaction proving itself tree-reduced,
- weaken exact ordered semantics into set semantics,
- move tx-artifact validity inside the recursive block proof,
- change the block’s semantic tuple,
- introduce external prover markets or distributed scheduling.

The goal is narrower: keep the same product truth surface, but replace the recursive proving schedule with one that can exploit parallel hardware.
