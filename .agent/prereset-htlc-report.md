# Experimental HTLC host admission workflow

This execution plan and report follows `.agent/PLANS.md`. The isolated SHA proof runner remains a component experiment. This work adds real ML-DSA-65 authorization to the parent host reference relation and a bounded durable local spent-nullifier journal. It enables a runnable claim/refund/reopen demonstration; it does not enable production swaps or prove the full HTLC relation in zero knowledge.

## Progress

- [x] 2026-10-02 14:55 UTC: Read AGENTS, PLANS, DESIGN native cutover/independent proofs and METHODS independent-proof sections; inspect relation and native signature wrappers.
- [x] 2026-10-02 15:03 UTC: Implement fixed-size native key-bound ML-DSA authorization and locked, bounded public journal admission.
- [x] 2026-10-02 15:03 UTC: Add local trusted-oracle demonstration and eleven integration tests (including subprocess helper); add README scope and reproduction commands.
- [x] 2026-10-02 15:07 UTC: Coordinator-authorized release build/tests, scoped Clippy correctness checks, formatting, fresh-key demonstration and public-only reopen passed.
- [x] 2026-10-02 15:07 UTC: Frozen-source honest SHA proof, actual unchecked wrong-witness rejection and public-only fresh-process readback passed; all 135 source inventory members matched. Heavy lane released.
- [x] 2026-10-02 15:10 UTC: Append exact measurements, commands, limits and digests; mark prior final source identity historical. No source changes after validation.

## Context and Orientation

`experimental/htlc-prototype/src/relation.rs` supplies `LockedNote`, `SpendIntent`, `check_spend`, `Authorizer`, `AuthenticatedChain` and the exact branch/intent/parent-bound `authorization_message`. Host note inclusion and height remain an external trusted input. `experimental/htlc-prototype/proof-backend` already depends on `synthetic-crypto`, whose ML-DSA-65 wrapper supplies canonical fixed-size public keys and signatures. No parent, production or crypto source changes are allowed. The backend conservatively hashes its Rust sources into the SHA experiment source identity, so its final source freeze requires a coordinator-run fresh proof validation.

## Plan of Work and Milestones

First add `src/authorization.rs` with fixed-width public-key/signature evidence and a domain-separated key authority digest, verifying the exact relation message with native ML-DSA-65. Then add `src/reference_ledger.rs`, holding an operating-system exclusive file lock for the lifetime of the opened journal. Under that lock, reload and validate a strict fixed-width append-only public record stream, call the relation with the external chain adapter and local spent-set guard, append one public record and fsync before reporting success. Reject busy journals, malformed/truncated records, duplicates and exhausted bounds. Do not repair partial writes, support reorg or store witness secrets. Finally add an example and integration tests covering real claim/refund, authorization mutation, malformed encodings, reopening, replay and process contention.

## Concrete Steps

From `experimental/htlc-prototype/proof-backend`, after the coordinator grants the build lane, run:

    CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-smallwood-target-20261002 CARGO_BUILD_JOBS=1 cargo test --release --offline --locked --test reference_workflow
    CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-smallwood-target-20261002 CARGO_BUILD_JOBS=1 cargo run --release --offline --locked --example reference_workflow -- --demo /private/tmp/FRESH-htlc-host-journal

The demonstration must accept a claim and a mature refund, reject replay and an immature refund, observe a competing process rejected as busy and reopen exactly two public records. Fresh evidence directories must not overwrite retained artifacts.

## Validation and Acceptance

Authorization tests must reject changed intent, context, branch, wrong authority/key and malformed signatures. Journal tests must reject partial-record-truncated/checksum-damaged/duplicate streams, enforce the record cap, and demonstrate competing process admission produces one accepted record at most. Inspect, fsync and reopened public records are local persistence evidence, not consensus authentication or crash/reorg recovery guarantees.

## Idempotence and Recovery

Use a fresh journal for each demonstration. Existing journals are reopened without deleting or rewriting records. A damaged or uncertain append fails closed and requires external operator handling; automatic crash repair is outside scope. No fresh private key, preimage, note opening or SHA assignment may be written or printed.

## Surprises & Discoveries

The installed Rust 1.91.1 supplies native `File::try_lock`, so no new dependency or unsafe locking implementation is required. ML-DSA public-key encoding is fixed-width; wrong key bytes are rejected by the committed authority digest even when structurally decodable. Independent static review identified a missed test trait import and the need to repeat directory fsync on existing files after a potentially failed creation barrier; both were repaired before compilation.

## Decision Log

- Decision: Hold the journal file's OS lock throughout parsing and admission, rejecting lock contention immediately. Rationale: cooperating processes cannot race read/check/append and crashed processes release the lock without deleting a lock file. Date: 2026-10-02.
- Decision: Store fixed-width public validated-spend fields with sequence and chained SHA-256 checksums. Rationale: bound parsing/memory and reject partial-record truncation, mutation, reorder and duplicates without storing secrets. The checksum is corruption detection, not protection from a malicious local journal writer. Date: 2026-10-02.
- Decision: Explicitly exclude whole-record suffix rollback detection, and acknowledge only partial-record truncation detection. Rationale: no external trusted head exists to distinguish a legitimate prior prefix from rollback; trusted-path/cooperating-process scope is essential. Date: 2026-10-02.
- Decision: Journal admission accepts the concrete ML-DSA authorizer rather than any caller-defined Authorizer. Rationale: the standalone host API must not permit a fixture or Boolean adapter to bypass signature verification. Date: 2026-10-02.

## Interfaces and Dependencies

Export `authorization::MlDsaAuthorizer`, `authority`, and `sign_authorization`; export `reference_ledger::ReferenceLedger::open`, `admit`, and `records`. Use existing sha2 and synthetic-crypto dependencies and Rust standard file locks, no dependency additions. The executable lives at `examples/reference_workflow.rs`, preserving the existing default proof runner.

## Outcomes & Retrospective

Delivered `authorization.rs`, `reference_ledger.rs`, `examples/reference_workflow.rs` and `tests/reference_workflow.rs`, with additive exports and preserved README/MEASUREMENTS history. Eleven host integration tests passed in 0.13 seconds and the existing binding test passed in 0.03 seconds. Scoped Clippy correctness checks passed in 21.93 seconds. Fresh-key demo and public-only subprocess inspect/reopen accepted exactly two public records (434-byte journal) while rejecting immature refund, same/opposite-branch replay and competing writers.

The frozen-source SHA closure is `9b095dee66a9cbabf225697d2f8c0d9ff2f589f04a29d671042b2b0afab9e1c7`. Honest proof 311,938 bytes, prove 8.461324875 seconds, verify 0.144039292 seconds; fresh-process verification 0.169752542 seconds. The actual unchecked wrong-witness prover returned a 311,874-byte proof which the real verifier rejected. All statement/binding/byte negatives rejected and all 135 source inventory members matched current bytes. The 164,113-byte production cap is unchanged and exceeded by 147,825 bytes. Peak RSS 1,561,706,496 bytes, 18.28 seconds whole command, zero swaps, under the assigned 16 GiB aggregate limit with two prover threads. Build used two Cargo jobs. The initial sandboxed test timing wrapper returned 1 after successful tests because its read-only timing sysctl was denied; compile RSS was unavailable. Approved diagnostic escalation measured the proof RSS successfully with exit zero. No passed tests were repeated just to recover timing.

Public evidence lives at `/private/tmp/hegemon-htlc-host-evidence-20261002.eNMB6d`: `host.journal`, labeled `host-demo.receipt.json`, labeled `fresh-proof-verification.receipt.json`, and `sha-component/{statement.json,claim.smz1,invalid-witness.smz1,measurement.json,source-closure.sha256}`. Exact commands and digests are in the backend MEASUREMENTS append. No fresh private material was persisted, no retained artifacts removed, no commit/push performed, and no root CI/docs edited by this worker.

The host workflow's authenticated context/inclusion remains external; the SHA proof's context is transcript-bound but unauthenticated. Neither component nor their side-by-side availability establishes a full HTLC proof, production capability or enabled atomic swaps. Directory fsync retry behavior and the whole-record rollback claim boundary were improved by independent source review before the final validation.

Plan created 2026-10-02 for the coordinator's bounded pre-reset delivery; subsequent evidence will update this same report.
