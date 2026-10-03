# Remove recursive block aggregation from the active chain

This ExecPlan is a living document and must be maintained in accordance with
`.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision
Log`, and `Outcomes & Retrospective` must remain current while the work proceeds.

## Purpose / Big Picture

Hegemon transactions already carry independently verifiable native SmallWood
`tx_leaf` proofs. The active block path nevertheless constructs and transmits an
additional fixed-width `recursive_block_v2` artifact of 523,736 bytes. After this
change, miners put only the ordered shielded transfer actions and their native
SmallWood proofs into new blocks. Every importing node independently verifies
each transaction proof, derives the ordered statement and data-availability
commitments, and applies the resulting state transition. No aggregate proof is
constructed or required for a new block.

Historical recursive blocks remain readable and verifiable. This preserves
testnet history and avoids a reset, but the node no longer accepts new candidate
artifact submissions or selects candidate artifact actions for mining.

## Progress

- [x] (2026-07-28) Located the active 523,736-byte artifact in
  `circuits/block-recursion/src/tree_v2.rs` and traced construction, admission,
  mining, import, wire, and formal-policy dependencies.
- [x] (2026-07-28) Changed consensus policy so independent native transaction proofs are the
  canonical non-empty block path while historical recursive blocks remain valid.
- [x] (2026-07-28) Removed candidate-artifact construction, caching, submission, and mining
  selection from the native node.
- [x] (2026-07-28) Changed native block import to verify an ordered list of independent
  SmallWood transaction proofs when no historical candidate artifact is present.
- [x] (2026-07-28) Removed the untracked block-certificate experiment and its workspace
  dependency.
- [x] (2026-07-28) Updated Lean policy theorems, generated vectors, architecture documentation,
  and implementation-binding metadata.
- [x] (2026-07-28) Ran formatting, focused unit tests, formal checks, core tests, and inspected
  the final dependency and artifact surface.

## Surprises & Discoveries

- Observation: `recursive_block_v2` does not replace transaction proof
  verification. `verify_recursive_block_artifact_against_verified_records`
  first calls `verify_native_tx_leaf_artifact_records`, so the 523,736-byte block
  artifact is additional work and bandwidth.
  Evidence: `consensus/src/proof.rs` verifies every native leaf before decoding
  and verifying the recursive artifact.

- Observation: Native transfer actions already carry the complete native
  `tx_leaf` bytes through `ShieldedTransferInlineArgs` or
  `ShieldedTransferSidecarArgs`.
  Evidence: `node/src/native/block_flow.rs::transfer_proof_from_action`.

## Decision Log

- Decision: New blocks use `ProofVerificationMode::InlineRequired` with no
  `ProvenBatch` and no `block_artifact`.
  Rationale: This existing internal mode accurately represents independent proof
  bytes carried by each transaction action and avoids another wire-version
  variant.
  Date/Author: 2026-07-28 / Codex

- Decision: Preserve historical recursive verification but remove production
  and admission for new candidate artifacts.
  Rationale: Completely deleting the historical verifier would make existing
  testnet blocks unverifiable and force a reset. Keeping a read-only historical
  path has no new-block bandwidth cost.
  Date/Author: 2026-07-28 / Codex

- Decision: The independent path must call the native `TxLeaf` verifier, not the
  generic legacy inline verifier.
  Rationale: The requested chain is specifically an ordered sequence of active
  SmallWood transaction proofs; accepting another backend would weaken the
  cutover.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The active surcharge is removed: new blocks carry ordered transaction actions
and their native SmallWood proofs, with zero aggregate-proof bytes. Candidate
artifact RPC admission, mempool selection, construction, and caching all reject
or are absent. Consensus still verifies historical recursive artifacts, so
existing testnet history remains replayable without a reset.

Focused consensus and native-node tests establish that valid independent proofs
are accepted, invalid proofs are excluded, and historical recursive fixtures
remain accepted. All 81 consensus library tests pass. The formatted production
node builds without a recursive prover API, while the historical decoder and
verifier remain available. The formal policy and preflight gates pass after the
generated review digests were refreshed against the final source.

This is a protocol cutover, not a genesis change. Existing history remains
valid, but miners and validators must activate the new software together because
older nodes expect a recursive candidate artifact on new non-empty blocks.

## Context and Orientation

`protocol/shielded-pool/src/types.rs` defines the historical candidate artifact
wire shape. `node/src/native/node_impl.rs` currently builds a recursive candidate
action before mining. `node/src/native/block_flow.rs` reconstructs consensus
transactions and proof artifacts from block actions and currently requires one
candidate artifact. `consensus/src/proof.rs::ParallelProofVerifier` independently
verifies native transaction proofs but then requires and verifies the additional
recursive artifact. `formal/lean/Hegemon/Consensus/ProofPolicy.lean` models that
policy and emits Rust conformance vectors through
`GenerateProofPolicyVectors.lean`.

The term "independent proof" means that each shielded transaction contains its
own native SmallWood proof and the block has no proof that combines multiple
transactions. The term "historical recursive block" means an already-produced
block containing the old candidate artifact action; new software may verify it
while refusing to produce another.

## Plan of Work

First, change `consensus/src/proof.rs` so a non-empty
`ProofVerificationMode::InlineRequired` block is valid only when transaction
artifacts are present in exact transaction order and no proven batch or block
artifact exists. Verify those artifacts through
`verify_native_tx_leaf_artifact_records`, derive canonical claims and statement
bindings from those verified records, validate anchor history, and apply the
commitment-tree transition. Keep the existing self-contained recursive branch
only for historical blocks.

Second, remove `NativeNode::build_auto_recursive_candidate_action`, its caches,
and its call from work preparation. Reject candidate artifact submissions at the
live RPC boundary and never select such actions from the mempool. Modify
`verify_native_block_artifacts_locked` to use the independent path when no
candidate artifact is present and the historical recursive path when exactly one
old artifact is present.

Third, update the Lean proof-policy model and generated vectors to prove that the
independent path requires exact transaction proof coverage and forbids aggregate
payloads. Update `README.md`, `DESIGN.md`, and `METHODS.md` so none describes
recursive aggregation as the active product path. Remove the untracked
`circuits/block-certificate` experiment and its workspace lockfile entries.

Finally, format and test the modified crates. Confirm from a serialized mined
block fixture that aggregate bytes are zero and from a mutation test that one
invalid SmallWood transaction proof rejects the whole block.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

    cargo fmt --all -- --check
    cargo test -p consensus
    cargo test -p hegemon-node
    bash scripts/check_formal_core.sh
    git diff --check

The focused product test must report a non-empty block with transaction proof
bytes greater than zero, aggregate proof bytes equal to zero, and successful
state-root verification.

## Validation and Acceptance

Acceptance requires all of the following observable behavior:

1. Preparing a mining template with shielded transfers does not append an
   `ACTION_SUBMIT_CANDIDATE_ARTIFACT` action.
2. Importing that template verifies every native `tx_leaf` and succeeds without
   `proven_batch` or `block_artifact`.
3. Mutating any transaction proof causes import to fail with a transaction proof
   verification error.
4. A historical recursive fixture still verifies, preserving existing testnet
   history.
5. No active construction path calls
   `build_recursive_block_v2_artifact_for_native_txs`.
6. The untracked block-certificate experiment is absent from the workspace.

## Idempotence and Recovery

The source edits and tests are repeatable. Historical wire enum values and
decoders are retained, so replaying old blocks remains possible. If a test
exposes an unmodeled dependence on candidate actions, preserve the historical
decoder and route that dependence through the explicit legacy branch rather
than restoring candidate generation.

## Artifacts and Notes

The removed active artifact has a fixed serialized width:

    RECURSIVE_BLOCK_ARTIFACT_BYTES_V2 = 523_736

The independent transaction proof verifier already exists:

    consensus/src/proof.rs::verify_native_tx_leaf_artifact_records

## Interfaces and Dependencies

At completion, `ParallelProofVerifier::verify_block_with_backend` accepts the
active independent path with `ProofVerificationMode::InlineRequired`,
`proven_batch = None`, and `block_artifact = None`. The node no longer requires a
direct `block-recursion` dependency. Consensus retains its historical
`block-recursion` dependency solely to verify old recursive artifacts.

Revision note (2026-07-28): Created after tracing the redundant 523,736-byte
artifact through the active product path and choosing a backward-readable
independent-proof cutover.

Revision note (2026-07-28): Recorded the implemented active-path removal,
historical replay boundary, and validation status.

Revision note (2026-07-28): Closed the plan after the final runtime, historical
compatibility, Lean/preflight, policy, formatting, and diff checks passed.
