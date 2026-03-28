# Phase C Deep Recursion Endpoint (0.9.0 Fresh Genesis)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. This document must be maintained in accordance with that file.

## Purpose / Big Picture

Phase C makes aggregation blocks valid without consensus proof-DA dependencies. After this change, validators can import aggregation blocks where shielded sidecar transfers carry `proof.data = []`, as long as `ProofAvailabilityPolicy=SelfContained` and the block carries valid commitment + aggregation proofs bound to canonical transaction statements.

Observable user-visible result: on a fresh `0.9.0` genesis, nodes accept SelfContained aggregation blocks without proof-DA commitment/manifest extrinsics or proof-DA fetch/import paths.

## Progress

- [x] (2026-02-19T00:00Z) Runtime/pallet policy cutover to `ProofAvailabilityPolicy::{InlineRequired, SelfContained}` and removal of proof-DA consensus extrinsics.
- [x] (2026-02-19T00:00Z) Statement-binding migration from `tx_proofs_commitment` to `tx_statements_commitment` in block circuit, consensus verification, and node import/build paths.
- [x] (2026-02-19T00:00Z) Aggregation V3 payload path landed with strict versioned decode + statement commitment binding checks in consensus.
- [x] (2026-02-19T02:35Z) Hardened aggregation V3 verifier to re-derive `tx_statements_commitment` from packed recursion public values (via tx public-input decoding + binding-hash statement hashing) and reject payloads that only carry an unbound commitment field.
- [x] (2026-02-20T00:00Z) Fail-closed mode plumbing landed: importer/builder derive and enforce `ProofVerificationMode::{InlineRequired, SelfContainedAggregation}`; SelfContained blocks now hard-require aggregation proof and disable tx-proof fallback.
- [x] (2026-02-20T00:00Z) Added strict throughput harness guard (`HEGEMON_TP_STRICT_AGGREGATION=1`) that fails runs if accepted blocks report `proven_batch_present=false`.
- [x] (2026-02-20T02:30Z) Phase D authoring cutover landed in node/runtime/consensus: dual proof extrinsics replaced by `submit_proven_batch`, `consensus::types::Block` now carries `proven_batch`, and the block-builder closure no longer performs synchronous proof generation.
- [x] (2026-02-20T03:20Z) Prover coordinator now uses a bounded multi-job worker queue (`workers`, `queue_capacity`, `job_timeout`) with stale-parent result drops and coordinator unit-test coverage.
- [x] (2026-02-20T00:00Z) Recursive witness migration advanced: opened values/permutation opened values moved to witness targets; aggregation prover witness wiring extended and `aggregation_proof_roundtrip` passes.
- [x] (2026-02-20T00:00Z) Added consensus regression tests for fail-closed proof modes (`consensus/tests/self_contained_mode.rs`).
- [x] (2026-02-20T01:00Z) Deep recursion challenger closure landed: vendor recursion challenger now enforces constrained in-circuit absorb/squeeze (Goldilocks Poseidon2 transcript path) and binds sampled challenge public inputs to computed transcript values.
- [x] (2026-02-19T00:00Z) Deterministic, versioned public-value packing marker added to aggregation payload (`public_values_encoding`).
- [x] (2026-02-19T00:00Z) Node tests compile cleanly under removed proof-DA calls (`cargo test -p hegemon-node --no-run`).
- [x] (2026-02-19T00:00Z) Removed now-dead proof-DA helper code paths from `node/src/substrate/service.rs` (fetch/range/payload stubs and obsolete proof-DA blob builders).
- [ ] (2026-02-19T00:00Z) Final devnet throughput/e2e reruns with SelfContained-only lane and refreshed artifact capture.

## Surprises & Discoveries

- Observation: Existing node test helpers still referenced removed runtime calls (`submit_proof_da_commitment`, `submit_proof_da_manifest`) after pallet/runtime cleanup.
  Evidence: `cargo test -p hegemon-node --no-run` failed with missing enum variants until those tests/helpers were removed.

- Observation: Vendor recursion challenger now computes transcript challenges in-circuit and constrains sampled challenge public inputs to those computed values.
  Evidence: `spikes/recursion/vendor/plonky3-recursion/recursion/src/challenger/circuit.rs` now performs constrained absorb/squeeze over a maintained sponge state and connects sampled public inputs to derived challenge targets.

- Observation: Migrating proof/opening targets to witness targets required explicit runner witness wiring in aggregation prover flow.
  Evidence: `circuits/aggregation/src/lib.rs` required extending witness assignment beyond FRI query proofs to commitments/opened values/final poly/PoW witness fields.

- Observation: Aggregation V3 payload previously trusted `tx_statements_commitment` as a field-level claim without recomputing it from proof-constrained public values.
  Evidence: `consensus/src/aggregation.rs` validated the payload commitment bytes against expected commitment but did not derive statement commitment from `packed_public_values` before `verify_batch`.

## Decision Log

- Decision: Phase C endpoint is deep-recursion refactor only; no interim V2 bridge ship.
  Rationale: Bridge modes preserve migration complexity without improving final production guarantees.
  Date/Author: 2026-02-19 / Codex

- Decision: Production `0.9.0` removes `DaRequired` path and treats proof-DA as non-consensus staging only.
  Rationale: Consensus validity in Phase C must be self-contained and independent of proof-DA manifest/fetch pipelines.
  Date/Author: 2026-02-19 / Codex

- Decision: Keep aggregation payload format explicitly versioned (V3) and add a versioned public-value packing discriminator.
  Rationale: Prover/verifier wiring for recursion public values must be deterministic and reject unknown encodings.
  Date/Author: 2026-02-19 / Codex

## Outcomes & Retrospective

Core Phase C architecture is implemented in this branch: runtime/pallet/node/consensus/circuit interfaces align to fail-closed `SelfContained` aggregation semantics with statement-commitment binding. Authoring now uses an asynchronous in-node prover coordinator that prebuilds proven batches keyed by `(parent_hash, tx_statements_commitment, tx_count)` and block assembly attaches only ready payloads.

Remaining gap is fresh-genesis operational proof (throughput/e2e artifacts under strict SelfContained lane).

## Context and Orientation

Relevant modules and their responsibilities:

- `pallets/shielded-pool/src/types.rs`: on-chain policy enum and transfer/proof data model.
- `pallets/shielded-pool/src/lib.rs`: runtime call surface and validity checks.
- `circuits/block/src/p3_commitment_air.rs`, `circuits/block/src/p3_commitment_prover.rs`: block commitment proof semantics (`tx_statements_commitment`).
- `circuits/aggregation/src/lib.rs`: aggregation proof production + payload V3 encoding.
- `consensus/src/aggregation.rs`, `consensus/src/proof.rs`, `consensus/src/error.rs`: V3 decode/verify and block validity enforcement.
- `node/src/substrate/service.rs`: block construction/import wiring and sidecar extraction behavior.
- `spikes/recursion/vendor/plonky3-recursion/recursion/src/challenger/circuit.rs`: in-circuit Fiat-Shamir challenge derivation.
- `spikes/recursion/vendor/plonky3-recursion/recursion/src/types/proof.rs`, `spikes/recursion/vendor/plonky3-recursion/recursion/src/pcs/fri/targets.rs`, `spikes/recursion/vendor/plonky3-recursion/recursion/src/public_inputs.rs`: recursive target allocation and value packing conventions.

Terminology used here:

- “SelfContained”: aggregation validity can be checked from commitment proof + aggregation proof + statement binding, without consensus proof-DA manifest/blob fetch.
- “Statement commitment”: commitment over canonical transaction statement hashes in canonical extrinsic order.
- “Deep recursion refactor”: recursion verifier wiring where Fiat-Shamir challenges are constrained in-circuit and large inner-proof payload components are witness data rather than public-input payload.

## Plan of Work

Keep the codebase on a single production lane for Phase C.

First, keep runtime and import-path semantics strict: SelfContained aggregation accepts proofless sidecar transfers only in aggregation mode and rejects legacy proof-DA calls at runtime.

Second, keep commitment/aggregation binding aligned on statement commitments in both block circuit and consensus checks.

Third, preserve deterministic recursion interfaces by ensuring challenge derivation is constrained in-circuit and witness/public-value packing is versioned.

Finally, prove behavior operationally with fresh-genesis throughput/e2e runs and capture artifacts in this plan and the world-commerce top-level plan.

## Concrete Steps

Run all commands from repository root.

1. Compile critical targets:

    cargo test -p hegemon-node --no-run -q
    cargo test -p consensus --no-run -q
    cargo test -p aggregation-circuit --no-run -q

2. Start a fresh node with mining (fresh DB):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

3. Exercise SelfContained aggregation flow (proofless sidecar + aggregation proof path) with existing throughput/e2e scripts and capture logs.

4. Confirm runtime rejects removed proof-DA calls by attempting to include legacy extrinsics on a test chain and observing block invalidation.

## Validation and Acceptance

Acceptance criteria for this plan:

1. Policy/API surface exposes only `InlineRequired` and `SelfContained` for proof availability.
2. Aggregation blocks import successfully without `transaction_proofs` and without proof-DA commitment/manifest fetch/validation when `SelfContained` is active.
3. Commitment proof and aggregation verification are both bound to canonical statement commitment semantics.
4. Legacy proof-DA runtime calls are invalid in `0.9.0` runtime.
5. Compilation targets above pass; devnet/e2e artifacts show SelfContained lane behavior.

## Idempotence and Recovery

All compile checks are idempotent. Devnet validation should use `--dev --tmp` (or explicit test data directories) so reruns do not require manual state surgery.

For fresh-genesis checks, always clear node and wallet stores before rerunning if chain spec or runtime semantics changed.

## Artifacts and Notes

Current compile evidence:

- `cargo test -p hegemon-node --no-run -q` passes (warnings only).
- `cargo test -p consensus --no-run -q` passes (warnings only).
- `cargo test -p aggregation-circuit --no-run -q` passes (warnings only).

Pending artifact capture:

- SelfContained throughput script logs.
- Two-node sync/e2e logs under Phase C lane.

## Interfaces and Dependencies

Required stable interfaces after this work:

- `pallet_shielded_pool::types::ProofAvailabilityPolicy::{InlineRequired, SelfContained}`.
- Aggregation payload struct with `version == 3` and explicit `public_values_encoding` discriminator.
- `consensus::verify_aggregation_proof(aggregation_proof, tx_count, expected_statement_commitment)` enforcing strict V3 decode/binding.
- Node RPC `da_submitProofs` retained only for proposer staging; not required for consensus import.

Revision note (2026-02-19): Initial Phase C deep-recursion ExecPlan authored to capture the implemented endpoint architecture and the remaining validation steps.
