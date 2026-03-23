# Migrate Hegemon To A Proof-Backend-Neutral Artifact Boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon already has the right high-level topology for future proof-system upgrades: parent-independent candidate artifacts, a separate parent-bound commitment proof, and an asynchronous proving market. What it does not have is a proof-backend-neutral boundary. Consensus still knows about `TransactionProof`, `InlineTx`, and `MergeRoot` directly. That means any future move to `Neo`, `SuperNeo`, `Arc`, `WARP`, or another receipt/folding/accumulation stack would still force a disruptive rewrite through consensus and import.

After this migration, the user-visible behavior remains the same on day one: the shipping path is still `InlineTx`, blocks still import, wallets still submit normal shielded transactions, and the node still supports the current proving market. The difference is architectural. Consensus verifies a generic proof artifact under a registered verifier profile instead of hard-coding Plonky3 transaction proofs and merge-root recursion shapes. Once this lands, Hegemon can add a new receipt-root or folded-root backend as an additive artifact kind instead of as a consensus rewrite.

## Progress

- [x] (2026-03-21 23:57Z) Audited the current proof-bearing boundaries in `consensus/src/types.rs`, `consensus/src/proof.rs`, `node/src/substrate/service.rs`, `node/src/substrate/artifact_market.rs`, `docs/API_REFERENCE.md`, `DESIGN.md`, and `METHODS.md`.
- [x] (2026-03-21 23:57Z) Wrote the migration map as a concrete ExecPlan keyed to the current `InlineTx` implementation rather than a greenfield design.
- [x] (2026-03-23) Introduced backend-neutral proof vocabulary in consensus and runtime-facing artifact types without changing the shipping `InlineTx` behavior.
- [x] (2026-03-23) Added a verifier registry and adapters so import stops depending directly on `transaction_circuit::TransactionProof`.
- [x] (2026-03-23) Added canonical transaction-validity receipts and statement/verifier profile digests as first-class objects.
- [x] (2026-03-23) Generalized the artifact-market and block payload APIs to carry proof kind and verifier profile alongside legacy proof-mode names.
- [x] (2026-03-23) Added an additive `ReceiptRoot` experimental artifact kind, builder, and verifier path without disturbing the commitment-proof path.
- [x] (2026-03-23) Retired direct consensus ownership of `Option<Vec<TransactionProof>>` in favor of `tx_validity_artifacts` plus `block_artifact`, and exercised the neutral path with focused automated tests.

## Surprises & Discoveries

- Observation: Hegemon is already much closer to the target topology than to the target abstraction.
  Evidence: `consensus/src/types.rs` already defines `CandidateArtifact`, `ArtifactAnnouncement`, `tx_statements_commitment`, and a separate `commitment_proof`, while `node/src/substrate/artifact_market.rs` already hashes and publishes reusable artifacts.

- Observation: the main hard-coded coupling is in import verification, not in the artifact-market or version-schedule layers.
  Evidence: before the migration, `consensus/src/proof.rs` carried raw `TransactionProof` knowledge directly; after the migration, that coupling is isolated behind `InlineTxP3Verifier`, while the block/import boundary uses only `TxValidityArtifact` and `ProofEnvelope`.

- Observation: Hegemon already has the upgrade-policy machinery needed to tolerate verifier-profile evolution.
  Evidence: `consensus/src/version_policy.rs` already carries `VersionSchedule`, `VersionProposal`, and `UpgradeDirective`, and the node/runtime surfaces already expose proof-format and version-commitment concepts.

- Observation: the current `ProvenBatchMode` names encode implementation history instead of the abstraction Hegemon actually needs.
  Evidence: `consensus/src/types.rs` enumerates `InlineTx`, `FlatBatches`, and `MergeRoot`, which are transport/proof-family names rather than generic artifact kinds.

- Observation: the runtime and network boundary could accept the new neutral tuple additively without destabilizing the live block format.
  Evidence: `pallets/shielded-pool::types::CandidateArtifact` and `node::substrate::network_bridge::ArtifactProtocolMessage::Announcement` now carry `proof_kind` and `verifier_profile` while still retaining the legacy `proof_mode` field for compatibility.

- Observation: once the neutral block boundary landed, the last useful compatibility hook was `proof_mode` on runtime/network payloads rather than any consensus-internal raw proof field.
  Evidence: `consensus::types::Block` now carries `tx_validity_artifacts` and `block_artifact`, while runtime/network `CandidateArtifact` still keeps `proof_mode` beside the neutral `(proof_kind, verifier_profile)` tuple.

## Decision Log

- Decision: keep the parent-bound commitment proof architecture intact during this migration.
  Rationale: the commitment proof is already the working block-validity artifact and is orthogonal to proof-backend agility. Replacing it in the same migration would multiply risk for no immediate benefit.
  Date/Author: 2026-03-21 / Codex

- Decision: migrate by additive dual-read / dual-write steps instead of replacing `InlineTx` in one cut.
  Rationale: the shipping path works. The goal is to future-proof consensus and import, not to destabilize the live path.
  Date/Author: 2026-03-21 / Codex

- Decision: the first neutral artifact above `InlineTx` will be a transaction-validity receipt, not a full native CCS transaction proof.
  Rationale: a receipt preserves the current tx STARK and gives the cleanest path to future folded roots. It also generalizes across `Neo`/`SuperNeo`, code-based accumulation, and other future proof families.
  Date/Author: 2026-03-21 / Codex

- Decision: the abstraction must be broader than `Neo`/`SuperNeo`.
  Rationale: the whole point of this migration is to remove consensus dependence on one proof backend. The new boundary must also admit code-accumulation and future transparent/PQ alternatives.
  Date/Author: 2026-03-21 / Codex

- Decision: keep `proof_mode` as a compatibility field in runtime/network payloads while attaching explicit `proof_kind` and `verifier_profile`.
  Rationale: the live payload format and operator tooling still key off `proof_mode`, but new code can already depend on the neutral tuple without waiting for a subtractive cutover.
  Date/Author: 2026-03-23 / Codex

## Outcomes & Retrospective

Stages 1 through 6 are now in-tree. Consensus has backend-neutral proof envelopes and tx-validity receipts, import verification routes through a registry, the tx circuit exports canonical statement/proof/public-input/profile digests, runtime/node artifact payloads carry `(proof_kind, verifier_profile)` beside the legacy `proof_mode`, and the consensus block boundary now uses `tx_validity_artifacts` plus `block_artifact` instead of `transaction_proofs`.

The first non-inline additive artifact kind is also real now: `ReceiptRoot` can be built in the experimental `superneo-*` stack, attached through the same neutral interface, and verified by consensus without further type surgery. The service-level authoring selector now resolves env aliases into `(proof_kind, verifier_profile, legacy_mode)` before choosing a build path, so the migration objective is met: future proof backends can slot in behind the same contract surface without another consensus rewrite.

## Context and Orientation

This section explains the current code structure in plain language.

In Hegemon today, a block carries two proof-bearing surfaces. The first is `tx_validity_artifacts: Option<Vec<TxValidityArtifact>>` in [consensus/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/types.rs). On the live `InlineTx` lane each artifact embeds a canonical tx proof envelope; on future lanes it can carry only a receipt. The second is `block_artifact: Option<ProofEnvelope>` plus the legacy compatibility `proven_batch: Option<ProvenBatch>`, which carry the parent-bound commitment proof and any additive block-level artifact kind such as `MergeRoot` or `ReceiptRoot`.

The commitment proof is the block-level proof over the ordered transaction set, the nullifier list, and the state roots. It is parent-bound, which means it depends on the current chain state and cannot be freely reused across parent changes. That proof already has a good separation of concerns and should stay.

The artifact market is the public mechanism that publishes reusable parent-independent proof objects. In this repository, the important files are [node/src/substrate/artifact_market.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/artifact_market.rs), [node/src/substrate/rpc/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/prover.rs), and the `CandidateArtifact` / `ArtifactAnnouncement` types in [consensus/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/types.rs).

The original hard coupling lived in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs). That surface is now generic at the boundary and proof-family-specific only inside verifier adapters such as `InlineTxP3Verifier`, `MergeRootP3Verifier`, and `ReceiptRootVerifier`.

This ExecPlan uses four terms of art and defines them here:

`Proof artifact` means any object that proves an exact ordered transaction set is valid under some verifier profile. Examples include current inline tx proof lists, a merge-root proof, a future receipt root, or a future accumulation root.

`Verifier profile` means a stable digest that identifies the verification rules for an artifact. In plain terms, it says which proof family and parameter set this artifact expects. It must be explicit so consensus can tell one valid backend from another.

`Transaction-validity receipt` means a small parent-independent object that binds a transaction statement digest to a proof digest, public-input digest, and verifier profile. It is not the block commitment proof. It is the portable bridge between today’s tx STARKs and tomorrow’s folded roots.

`Receipt root` means a parent-independent aggregate artifact over a set of transaction-validity receipts. It is the future insertion point for `Neo`, `SuperNeo`, `Arc`, `WARP`, or another folded/accumulated backend.

## Plan of Work

The migration proceeds in six stages. Each stage is additive and leaves the current `InlineTx` path working.

### Stage 1: Introduce backend-neutral vocabulary without changing behavior

Edit [consensus/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/types.rs) and the mirrored runtime-facing shielded-pool types so the code stops using implementation-history names as the primary abstraction. Keep the current modes alive for compatibility, but add a new neutral layer that future code can target.

Define these types in `consensus/src/types.rs`:

    pub type VerifierProfileDigest = [u8; 48];

    pub enum ProofArtifactKind {
        InlineTxProofSet,
        FlatBatchRoot,
        MergeRoot,
        ReceiptRoot,
        Custom([u8; 16]),
    }

    pub struct ProofEnvelope {
        pub kind: ProofArtifactKind,
        pub verifier_profile: VerifierProfileDigest,
        pub artifact_bytes: Vec<u8>,
    }

    pub struct TxValidityReceipt {
        pub statement_hash: [u8; 48],
        pub proof_digest: [u8; 48],
        pub public_inputs_digest: [u8; 48],
        pub verifier_profile: VerifierProfileDigest,
    }

    pub struct TxValidityArtifact {
        pub receipt: TxValidityReceipt,
        pub proof: Option<ProofEnvelope>,
    }

Do not remove `ProvenBatchMode`, `ProvenBatch`, or `transaction_proofs` in this stage. Instead, make them legacy compatibility carriers and add conversion helpers between the old payloads and the new neutral vocabulary. The key behavioral rule is that the shipping `InlineTx` block body still round-trips exactly as it does today.

At the same time, extend `ArtifactAnnouncement` so it advertises `proof_kind` and `verifier_profile` in addition to the existing `(artifact_hash, tx_statements_commitment, tx_count)` tuple. The current announcement fields stay until the node and runtime readers have been switched.

### Stage 2: Add a verifier registry and stop importing concrete proof backends directly

Edit [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs). Replace direct knowledge of `transaction_circuit::TransactionProof` as the core import abstraction with a registry that maps `(ProofArtifactKind, VerifierProfileDigest)` to a verifier adapter.

Define a new trait in `consensus/src/proof.rs` or a new nearby module such as `consensus/src/verifier_registry.rs`:

    pub trait ArtifactVerifier: Send + Sync {
        fn kind(&self) -> ProofArtifactKind;
        fn verifier_profile(&self) -> VerifierProfileDigest;
        fn verify_tx_artifact(
            &self,
            tx: &crate::types::Transaction,
            artifact: &TxValidityArtifact,
        ) -> Result<TxStatementBinding, ProofError>;
        fn verify_block_artifact(
            &self,
            txs: &[crate::types::Transaction],
            expected_commitment: &[u8; 48],
            envelope: &ProofEnvelope,
        ) -> Result<BlockArtifactVerifyReport, ProofError>;
    }

Also define:

    pub struct BlockArtifactVerifyReport {
        pub tx_count: usize,
        pub verified_statement_commitment: [u8; 48],
        pub verify_ms: u128,
        pub cache_hit: Option<bool>,
        pub cache_build_ms: Option<u128>,
    }

Then implement the first adapter for the current shipping backend:

- `InlineTxP3Verifier` wraps the existing Plonky3 `TransactionProof` verification path and emits `TxStatementBinding`.
- `MergeRootP3Verifier` wraps the current `verify_aggregation_proof_with_metrics` path and maps it into `BlockArtifactVerifyReport`.

The registry must be additive. During the transition, `ParallelProofVerifier` should still accept legacy `transaction_proofs` and `proven_batch` inputs, but internally it should translate them into `TxValidityArtifact` / `ProofEnvelope` and go through the registry. That is the point where consensus stops being proof-family-specific.

### Stage 3: Make transaction-validity receipts first-class and canonical

Add canonical receipt derivation for the current tx proof family in the transaction circuit layer. The likely file is [circuits/transaction/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs), with any digest helpers split into a new small module if necessary.

Define:

    pub fn tx_validity_receipt(
        proof: &TransactionProof,
        verifier_profile: VerifierProfileDigest,
    ) -> Result<TxValidityReceipt, TransactionCircuitError>;

The receipt must digest:

- the canonical transaction statement hash,
- the proof bytes,
- the serialized public inputs,
- the verifier profile.

Do not guess here. The receipt digest rules must be deterministic and versioned. This is the object future receipt-root systems will fold. Once this exists, `statement_bindings_from_transaction_proofs` in `consensus/src/proof.rs` should become a compatibility helper that is implemented by unpacking receipts rather than by embedding more Plonky3-specific logic.

This stage must also add a canonical verifier-profile digest for the current tx proof family. That profile digest should bind the proof family name plus the parameter fingerprint that matters in practice, including at least the tx circuit version, the proof format family, and the FRI parameter profile in use today.

### Stage 4: Generalize block artifacts and artifact-market RPCs

Edit [node/src/substrate/artifact_market.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/artifact_market.rs), [node/src/substrate/rpc/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/prover.rs), and the runtime-facing shielded-pool types. The goal is to stop keying artifact discovery only by proof-mode labels and start keying it by the generic artifact tuple.

The public discovery tuple should become:

`(artifact_hash, tx_statements_commitment, tx_count, proof_kind, verifier_profile)`

The RPC response shape should expose:

    pub struct ArtifactAnnouncementResponse {
        pub artifact_hash: String,
        pub tx_statements_commitment: String,
        pub tx_count: u32,
        pub proof_kind: String,
        pub verifier_profile: String,
        pub claimed_payout_amount: u64,
    }

    pub struct CandidateArtifactResponse {
        pub artifact_hash: String,
        pub tx_statements_commitment: String,
        pub tx_count: u32,
        pub proof_kind: String,
        pub verifier_profile: String,
        pub candidate_txs: Vec<String>,
        pub payload: String,
    }

Keep the current legacy `proof_mode` field during the transition if necessary for client compatibility, but do not let new code depend on it.

At the node selection layer in [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs), replace the environment-driven `PreparedProofMode` enum with a new internal selector that chooses by `ProofArtifactKind` plus a preferred verifier profile. The old env strings can remain as aliases in the first iteration, but they should map through the new neutral selector.

### Stage 5: Add `ReceiptRoot` as the first new neutral artifact kind

This stage is the bridge to future `Neo` / `SuperNeo` and also to code-based accumulation. Do not attempt a native CCS transaction proof here. Keep the transaction STARK and the commitment proof intact. Add only a parent-independent aggregate over `TxValidityReceipt`.

Extend the experimental stack under `circuits/superneo-*` so it can emit a `ProofEnvelope { kind: ReceiptRoot, verifier_profile, artifact_bytes }` plus a receipt manifest that lists or commits to the ordered `TxValidityReceipt` set it covers.

Add a `ReceiptRootVerifier` adapter under the new registry. In the first milestone, it can remain experimental and node-gated, but it must consume the same neutral artifact interface as every other backend.

The import rule becomes:

- verify the commitment proof exactly as today;
- derive the expected `tx_statements_commitment`;
- resolve the artifact verifier by `(kind, verifier_profile)`;
- verify the `ReceiptRoot` artifact against the ordered receipt set;
- skip per-tx inline proof verification only when the artifact verifier says the block artifact is sufficient.

This is the first stage where Hegemon can genuinely host another proof family without further consensus surgery.

### Stage 6: Retire direct consensus ownership of `TransactionProof`

Once `InlineTx` has been routed through receipts and envelopes and once at least one non-inline experimental artifact kind exists, remove the hard dependency on `Option<Vec<TransactionProof>>` from [consensus/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/types.rs).

The final block-level proof-facing shape should look like this:

    pub struct Block<BH> {
        pub header: BH,
        pub transactions: Vec<Transaction>,
        pub coinbase: Option<CoinbaseData>,
        pub tx_validity_artifacts: Option<Vec<TxValidityArtifact>>,
        pub block_artifact: Option<ProofEnvelope>,
        pub tx_statement_bindings: Option<Vec<TxStatementBinding>>,
        pub tx_statements_commitment: Option<[u8; 48]>,
        pub proof_verification_mode: ProofVerificationMode,
    }

The legacy fields can be kept behind compatibility conversion helpers for a short period, but once this stage lands consensus should no longer import `transaction_circuit::TransactionProof` directly.

## Concrete Steps

The implementation should be carried out from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Stage 1 validation commands:

    cargo test -p consensus types
    cargo test -p pallet-shielded-pool
    cargo test -p hegemon-node --features substrate artifact_market

Stage 2 and Stage 3 validation commands:

    cargo test -p consensus proof
    cargo test -p transaction-circuit proof
    cargo test -p hegemon-node --features substrate prover

Stage 4 and Stage 5 validation commands:

    cargo test -p consensus --features experimental-proof-backends
    cargo test -p superneo-hegemon -p superneo-bench
    cargo test -p hegemon-node --features substrate

Expected human-visible checkpoints:

    1. `prover_listArtifactAnnouncements` returns `proof_kind` and `verifier_profile`.
    2. A normal `InlineTx` block still imports with the current payload.
    3. The import logs in `consensus::metrics` show the selected artifact verifier instead of assuming Plonky3 inline verification.
    4. An experimental `ReceiptRoot` artifact can be attached and verified without editing consensus again.

## Validation and Acceptance

The migration is accepted only if all of the following are true.

First, the shipping `InlineTx` path is behaviorally unchanged. A block with inline transaction proofs and the current commitment proof must still import successfully, and the node must still be able to mine and sync under the current default proof mode.

Second, consensus must be able to verify the current backend only through the new neutral registry path. A targeted regression test should fail if import bypasses the registry and calls `verify_transaction_proof_safely` or `verify_aggregation_proof_safely` directly.

Third, the artifact market must advertise proof kind and verifier profile explicitly. A node must be able to reject an artifact whose bytes are valid for one profile but announced under another.

Fourth, there must be at least one additive experimental artifact kind beyond the current inline and merge-root carriers. That artifact does not have to be production-ready, but it must plug into the same envelope and registry system to prove that the new boundary is real.

Fifth, docs must be updated when the migration lands. [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md), [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md), and [docs/API_REFERENCE.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/API_REFERENCE.md) must all describe the new proof-artifact vocabulary, the verifier-profile concept, and the relationship between `InlineTx`, receipts, and future folded roots.

## Idempotence and Recovery

This migration must remain safe to pause and resume after every stage.

Stages 1 through 4 are additive. They can be retried without changing consensus behavior because the shipping `InlineTx` path remains present and the legacy compatibility fields remain available.

Stage 5 is experimental by design. Gate it behind a feature flag or an explicit non-default node/runtime setting so that failed receipt-root experiments do not affect the live path.

Stage 6 is the first subtractive stage. Do not remove `transaction_proofs` from consensus types until the neutral receipt/envelope path has been exercised by both automated tests and a local node import run.

If any stage blocks, stop at the last dual-read / dual-write boundary and keep the legacy compatibility adapters in place. The whole point of the migration is to de-risk future backend changes, so there is no value in forcing a big-bang cut.

## Artifacts and Notes

Current files that define the migration boundary:

    consensus/src/types.rs
    consensus/src/proof.rs
    consensus/src/version_policy.rs
    node/src/substrate/service.rs
    node/src/substrate/artifact_market.rs
    node/src/substrate/rpc/prover.rs
    circuits/transaction/src/proof.rs
    circuits/superneo-*

Current hard-coupling evidence worth preserving while implementing:

    `consensus/src/types.rs` contains `Option<Vec<TransactionProof>>`.
    `consensus/src/proof.rs` calls `verify_transaction_proof_safely` directly.
    `consensus/src/proof.rs` switches on `ProvenBatchMode::{InlineTx,FlatBatches,MergeRoot}`.
    `node/src/substrate/service.rs` chooses proof mode from `HEGEMON_BLOCK_PROOF_MODE`.

The migration should explicitly eliminate those as consensus-defining abstractions while preserving their behavior through adapters.

## Interfaces and Dependencies

At the end of Stage 1, the following interfaces must exist:

    consensus::types::VerifierProfileDigest
    consensus::types::ProofArtifactKind
    consensus::types::ProofEnvelope
    consensus::types::TxValidityReceipt
    consensus::types::TxValidityArtifact

At the end of Stage 2, the following interfaces must exist:

    consensus::proof::ArtifactVerifier
    consensus::proof::BlockArtifactVerifyReport
    consensus::proof::VerifierRegistry

with methods equivalent to:

    pub trait VerifierRegistry: Send + Sync {
        fn get(
            &self,
            kind: &ProofArtifactKind,
            verifier_profile: &VerifierProfileDigest,
        ) -> Option<&dyn ArtifactVerifier>;
    }

At the end of Stage 3, the following interface must exist:

    transaction_circuit::proof::tx_validity_receipt(
        proof: &transaction_circuit::proof::TransactionProof,
        verifier_profile: consensus::types::VerifierProfileDigest,
    ) -> Result<consensus::types::TxValidityReceipt, transaction_circuit::TransactionCircuitError>;

At the end of Stage 4, the node RPC responses must expose `proof_kind` and `verifier_profile`.

At the end of Stage 5, the experimental backend under `circuits/superneo-*` must be able to emit and verify a `ProofEnvelope` with `ProofArtifactKind::ReceiptRoot`.

Revision note: this ExecPlan was created on 2026-03-21 to answer the concrete migration question “how do we get from today’s `InlineTx` implementation to a proof-backend-neutral architecture without a protocol reset?” It deliberately focuses on the migration boundary, not on choosing one winning future backend.
