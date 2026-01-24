# World-Commerce Scalability: PQ Privacy Rollup + DA Anchor on Hegemon

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan is the top-level “how we get to world commerce” map. It is intentionally high-level and points at the concrete implementation plans that make it real:

- `.agent/PROOF_AGGREGATION_P3_EXECPLAN.md` (make proofs amortize)
- `.agent/DA_SIDECAR_HOT_AVAILABILITY_EXECPLAN.md` (make data availability real and scalable)
- `.agent/CENSORSHIP_RESISTANCE_FEES_EXECPLAN.md` (make incentives + fees not destroy privacy)
- `.agent/COLD_ARCHIVE_RECOVERY_EXECPLAN.md` (make multi-year recovery possible without making every full node store everything)
- `.agent/CASHVM_BRIDGE_STARK_COVENANT_EXECPLAN.md` (optional: settle/bridge the PQ rollup against a CashVM covenant without CashVM consensus changes)

The work is not “tune some constants.” It is an architecture pivot: the chain becomes a small, verifiable anchor that enforces availability and validity, while high-throughput private commerce happens as batched proofs and batched data.

## Purpose / Big Picture

Make Hegemon capable of “world commerce” private transfers without lowering the post‑quantum security bar (ML‑KEM‑1024 and ≥128‑bit post‑quantum security throughout).

After this work, a developer can run a local devnet and observe all of the following behaviors:

1. Submit a large number of shielded transfers (at least thousands) to a batcher (a “sequencer”: the component that orders transactions into batches).
2. Watch the batcher produce a small number of proofs (ideally 1 per L1 block) and submit only compact commitments on-chain.
3. Watch the node accept the block by (a) verifying the proof(s) and (b) sampling data availability chunks from peers.
4. Prove that ciphertext data needed for wallet recovery is retrievable during the configured “hot retention window” (for example, 7 days) via `da_getChunk` and the wallet RPCs.

## Progress

- [x] (2026-01-21T00:00Z) Draft world-commerce scalability ExecPlan (this file).
- [x] (2026-01-22T18:47Z) Baseline the current system’s throughput bottlenecks with reproducible local measurements (proof sizes, verify times, ciphertext sizes, block size limits).
- [x] (2026-01-22T18:54Z) Execute `.agent/PROOF_AGGREGATION_P3_EXECPLAN.md` through “end-to-end batch proof on devnet” milestone.
- [x] (2026-01-23T00:00Z) Execute `.agent/DA_SIDECAR_HOT_AVAILABILITY_EXECPLAN.md` through “ciphertexts no longer live in block body” milestone.
- [x] (2026-01-23T17:30Z) Proved unsigned DA-sidecar submission end-to-end (`da_submitCiphertexts` + `shielded_transfer_unsigned_sidecar`) and recovered the note via DA-backed wallet sync.
- [x] (2026-01-23T00:00Z) Execute `.agent/CENSORSHIP_RESISTANCE_FEES_EXECPLAN.md` through “forced inclusion lane + private fee policy” milestone.
- [x] (2026-01-23T06:10Z) Execute `.agent/COLD_ARCHIVE_RECOVERY_EXECPLAN.md` through “archive contract + wallet recovery flow works” milestone (wallet fallback + archive provider RPC path implemented; runbook prepared for end-to-end demo).
- [x] (2026-01-23T23:55Z) Run an end-to-end local commerce demo: mine coinbase, sync miner wallet, send a shielded transfer, mine/include it, verify `block_getCommitmentProof` + `da_getChunk`, sync recipient wallet.
- [x] (2026-01-23T20:00Z) Fixed Plonky3 public-input parsing to include ciphertext hashes; `prove_verify_roundtrip_p3` passes in `--features plonky3-e2e`.
- [x] (2026-01-23T20:20Z) Propagated `plonky3-e2e` feature to `transaction-core` so debug e2e tests use production FRI params (log_blowup=4, num_queries=32).
- [x] (2026-01-23T12:00Z) Added a design-philosophy quick reference in this ExecPlan to anchor decisions.
- [x] (2026-01-23T12:30Z) Wired DA policy + hash-only proof binding for sidecar sampling paths; fixed DA ciphertext index reuse on prune; updated runtime API for policy reads.
- [x] (2026-01-23T12:55Z) Unblocked node build (DA encoding SCALE fixes + archive market RPC dependency) and verified `cargo check -p hegemon-node`.
- [x] (2026-01-23T13:05Z) Verified shielded-pool pallet tests pass after policy additions (`cargo test -p pallet-shielded-pool`).
- [x] (2026-01-23T13:15Z) `cargo test -p consensus` completed cleanly (all tests pass; heavy parallel proof test remains ignored).
- [x] (2026-01-23T13:20Z) `cargo test -p state-da` completed cleanly.
- [x] (2026-01-23T13:30Z) Updated `DESIGN.md` and `METHODS.md` to document DA/ciphertext policy toggles.
- [x] (2026-01-23T16:00Z) Drafted `.agent/CASHVM_BRIDGE_STARK_COVENANT_EXECPLAN.md` to answer “CashVM↔Hegemon bridge + covenant rollup” feasibility and link it from this top-level plan.
- [x] (2026-01-24T00:00Z) Benchmarked end-to-end block payload size + proof verification time for sidecar submission + aggregation (2/4/8/16 attempts) using `scripts/throughput_sidecar_aggregation_tmux.sh` and recorded the breakpoint where block resource limits dominate.
- [x] (2026-01-24T00:00Z) Implemented proof sidecar staging (`da_submitProofs`) + wallet integration (`HEGEMON_WALLET_PROOF_SIDECAR=1`) so shielded transfer extrinsics can omit per-tx proof bytes in rollup/aggregation mode.
- [x] (2026-01-24T00:00Z) Added per-block “aggregation mode” marker (`ShieldedPool::enable_aggregation_mode`) so the runtime can skip per-tx proof verification while the node verifies commitment + aggregation proofs during import.
- [x] (2026-01-24T00:00Z) Re-ran end-to-end throughput bench with proof sidecar enabled and recorded 8/16 transfer per block payload sizes + verify times.
- [x] (2026-01-24T00:00Z) Stabilized local verification: cached aggregation verifier artifacts (avoid rebuilding recursion circuit/airs on every block) and capped default rayon threads in `--dev` to reduce macOS “watchdog wedge” risk under memory pressure (override with `HEGEMON_RAYON_THREADS`/`RAYON_NUM_THREADS`).

## Surprises & Discoveries

- Observation: The current transaction proof is already “real” and already targets ≥128-bit soundness, but it is large enough that the chain cannot scale by “just bigger blocks.”
  Evidence: `cargo run -p circuits-bench --release -- --smoke --json --prove` reports `tx_proof_bytes_avg` around 357,130 bytes and `fri_conjectured_soundness_bits` = 128.

- Observation: Proof generation time is orders of magnitude larger than verification time, so batching is mandatory for throughput.
  Evidence: local benchmark reports `prove_ns` = 18,453,849,334 (~18.45s) vs `verify_ns` = 32,573,000 (~32.6ms), with `transactions_per_second` = 0.2125.

- Observation: Even if we magically made proofs free, ciphertext bandwidth dominates at “world commerce” scale because ML‑KEM‑1024 ciphertexts are large and non-negotiable.
  Evidence: `pallets/shielded-pool/src/types.rs` defines `ENCRYPTED_NOTE_SIZE = 579` and `MAX_KEM_CIPHERTEXT_LEN = 1568`. One output note is ~2.1 KiB before other overhead; a typical transfer has two outputs.

- Observation: The current runtime is configured for a 4 MiB block body and 60 second blocks. With today’s proof sizes, that implies well under 1 shielded tx/sec.
  Evidence: `runtime/src/lib.rs` defines `RuntimeBlockLength` as `4 * 1024 * 1024` and `PowTargetBlockTime` as `60_000`.

- Observation: With sidecar ciphertexts enabled, the block body is still dominated by transaction proof bytes; aggregation currently *adds* ~1.0–1.2 MiB more bytes per block and becomes impossible to include once you reach 8 transfers/block under current limits.
  Evidence: at tx_count=4, a block carried `tx_proof_bytes_total=1429209`, `commitment_proof_bytes=228076`, `aggregation_proof_bytes=1112644`, `extrinsics_bytes_total=2773829`, and `verify_ms=3163` in `/tmp/hegemon-throughput-4.log`.
  Evidence: at tx_count=8, a block carried `tx_proof_bytes_total=2857875`, `commitment_proof_bytes=253476`, `extrinsics_bytes_total=3116776`, and attempting to attach `proof_size=1202209` bytes for `submit_aggregation_proof` hit `InvalidTransaction::ExhaustsResources` and was omitted in `/tmp/hegemon-throughput-8b.log`.

- Observation: With today’s on-chain transaction format (tx proofs inside each transfer), the practical upper bound is 8 transfers per block (16 submitted still yields a block with tx_count=8).
  Evidence: `/tmp/hegemon-throughput-16.log` shows `block_payload_size_metrics ... tx_count=8` after submitting 16 sidecar transfers.

- Observation: With proof sidecar enabled (proof bytes omitted from each transfer), block bodies scale with *O(1) proofs per block* (commitment proof + aggregation proof), not O(tx_count) proof bytes.
  Evidence: tx_count=8 block: `extrinsics_bytes_total=1461413`, `commitment_proof_bytes=253476`, `aggregation_proof_bytes=1202537`, `ciphertext_bytes_total=34352` (`block_payload_size_metrics`).
  Evidence: tx_count=16 block: `extrinsics_bytes_total=1584473`, `commitment_proof_bytes=280412`, `aggregation_proof_bytes=1295629`, `ciphertext_bytes_total=68704` (`block_payload_size_metrics`).

- Observation: Aggregation proof verification is currently multi-second even in a release node and scales roughly linearly with tx_count (too slow for short block times).
  Evidence: tx_count=8: `aggregation_verify_ms=5500`, `total_verify_ms=5653`.
  Evidence: tx_count=16: `aggregation_verify_ms=10369`, `total_verify_ms=10659`.

- Observation: Aggregation verification work is currently doing avoidable per-block setup (recursion circuit/air build), which can cause large RAM spikes on laptops; caching reduces overhead but does not yet solve the dominant multi-second `verify_batch` cost.
  Evidence: `consensus/src/aggregation.rs` now caches verifier artifacts keyed by (tx_count, public_inputs_len, proof shape).

- Observation: Transaction STARK proofs are currently failing verification in Plonky3 e2e mode (`OodEvaluationMismatch`), blocking the end-to-end commerce demo and wallet sends.
  Evidence: `cargo test -p transaction-circuit proving_and_verification_succeeds --features plonky3-e2e --release` fails with `STARK verification failed: OodEvaluationMismatch`.
- Observation: The OOD mismatch was caused by the AIR parsing public inputs without the new ciphertext-hash limbs, shifting the merkle-root inputs and failing the merkle-root constraint at row 2175.
  Evidence: debug `prove_verify_roundtrip_p3` panicked at `p3_air.rs:1425` before the fix; the same test now passes in `--features plonky3-e2e`.
- Observation: The `plonky3-e2e` feature was not propagating to `transaction-core`, so debug tests still used fast FRI params (log_blowup=3, num_queries=8).
  Evidence: `prove_verify_roundtrip_p3` printed `log_blowup=3, num_queries=8` before the feature propagation change; after the change it prints `log_blowup=4, num_queries=32`.

## Decision Log

- Decision: Treat “world commerce” as a data-availability + proving-market problem, not as a block-size tuning exercise.
  Rationale: With PQ ciphertext sizes and transparent proofs, the dominant costs are (a) bytes that must be available to wallets and (b) prover throughput. Bigger L1 blocks alone just centralize the network without addressing who stores data, for how long, and who pays.
  Date/Author: 2026-01-21 / Codex

- Decision: Separate “hot availability” from “cold archival.”
  Rationale: Availability-at-acceptance can be enforced by block validity rules (DA sampling, slashing/challenges). Multi-year archival is a different economic product: it should be opt-in, priced by time, and can be served by specialized providers without forcing every consensus node to store petabytes.
  Date/Author: 2026-01-21 / Codex

- Decision: Do not lower security to buy performance; instead, change where work happens.
  Rationale: ML‑KEM‑1024 and ≥128-bit PQ security constraints force larger artifacts. The only viable scaling lever is architectural: batch, aggregate, and separate node roles so that “consensus safety” remains cheap while “throughput work” is paid for and specialized.
  Date/Author: 2026-01-21 / Codex

- Decision: Make the chain a small PQ validity anchor that can be verified by a commodity server, while allowing specialized markets for DA and proving.
  Rationale: If verifying a block requires storing and recomputing everything, validators trend toward a few data centers. If verifying a block requires only (1) checking a small number of proofs and (2) checking a small number of DA samples, the set of verifiers can be wider, and the heavy lifting becomes a paid service.
  Date/Author: 2026-01-21 / Codex
- Decision: Keep ciphertext hashes as public inputs for binding and parsing correctness, without adding in-circuit constraints yet.
  Rationale: The transaction AIR must parse public inputs in the same order as `TransactionPublicInputsP3::to_vec`; binding ciphertext hashes to ciphertext bytes remains an application-level check.
  Date/Author: 2026-01-23 / Codex
- Decision: Treat `plonky3-e2e` as the production-parameter test path by forwarding it into `transaction-core`.
  Rationale: E2E tests must exercise the ≥128-bit soundness configuration to match the security posture we claim.
  Date/Author: 2026-01-23 / Codex

- Decision: Treat per-transaction proof bytes as sidecar-only in aggregation mode (bound by `binding_hash`), and keep only O(1) block proofs on-chain.
  Rationale: Per-tx transparent proof bytes are hundreds of KiB and dominate block propagation. Sidecar staging preserves the PQ security bar while bounding block bodies; future work can either (a) make proofs available via DA sampling or (b) make the aggregation proof truly self-contained (no inner proof bytes required to verify).
  Date/Author: 2026-01-24 / Codex

## Outcomes & Retrospective

Not started. Update this section once the first end-to-end demo is working.

## Context and Orientation

Design principles for decisions in this plan live in `DESIGN.md §0` (canonical pool, PQ-only primitives, transparent proofs, and UX-first privacy).

### Design Philosophy & Principles (Quick Reference)

- One canonical privacy pool: avoid multiple pools or migration cliffs.
- PQ-first, ≥128-bit security everywhere (ML-KEM-1024, ML-DSA, hash-based commitments).
- Transparent proofs only; no trusted setup.
- Chain is the minimal PQ validity/availability anchor; bulk throughput and storage are paid services.
- Availability is enforced at acceptance; archival is explicit, priced, and optional.
- UX and recovery matter: wallet sync must remain viable as the network scales.

Hegemon today is a Substrate-based proof-of-work chain with a shielded pool (Zcash-like “notes” and “nullifiers”) and post-quantum cryptography everywhere:

- “Note encryption” uses ML‑KEM‑1024 (post-quantum KEM) plus an AEAD. Each output note carries an AEAD ciphertext (`ENCRYPTED_NOTE_SIZE`) and a KEM ciphertext (`MAX_KEM_CIPHERTEXT_LEN`), so ciphertext bytes are a real bandwidth cost.
- “Transaction validity” is proven by a transparent STARK proof (Plonky3) verified by the runtime verifier (`pallets/shielded-pool/src/verifier.rs`).
- “Block-level commitments” exist: a commitment proof can bind the set of transaction proof hashes and nullifier uniqueness (see `.agent/archive/scalability_architecture_execplan.md` for the pivot that shipped).
- “Data availability” encoding exists (`state/da/src/lib.rs` and `node/src/substrate/network_bridge.rs`) but today it is tied to block extrinsic bytes; for world commerce it must become a real sidecar (large data outside the block body) with sampling.

Terms used in this plan (define them here so a novice can follow):

- “L1”: the Hegemon base chain. It orders blocks and provides the final “this is accepted” canonical history.
- “Rollup”: a system where many user transactions are processed off-chain, and the chain only receives (a) a commitment to the data and (b) a proof that the processing was valid. The chain verifies the proof; it does not re-execute every user transaction.
- “Sequencer”: the component that receives user transactions and chooses an order for them.
- “Prover”: the component that produces the proof that the batch was valid.
- “Data availability (DA)”: the property that the ciphertext data needed for wallets to learn about incoming notes is retrievable, not just committed to by a hash. We enforce DA by erasure coding + Merkle commitments + random sampling.
- “Hot retention window”: the minimum amount of time ciphertexts must remain retrievable for the chain to be usable for offline receivers. This is enforced by protocol rules and economics.
- “Cold archival”: long-term storage beyond the hot window. This is not free; it is a market.

Baseline numbers (current system, as implemented):

- Transaction proof bytes: ~357 KiB per transfer (from `circuits-bench`).
- Output note ciphertext bytes: ~579 + 1,568 = 2,147 bytes (per output note; two outputs ≈ 4.2 KiB).
- Runtime block body limit: 4 MiB, normal extrinsics share ~75% of that by default (`RuntimeBlockLength` uses a normal ratio).
- Block time: 60 seconds (`PowTargetBlockTime`).

The implied conclusion is mechanical: today’s design cannot reach “mass commerce” as an L1-per-transfer system. Even perfect parallelism and perfect networking cannot fit enough proof bytes into blocks, and even if it did, every node would need to store and serve enormous ciphertext streams forever. So the plan is to batch and to make storage an explicit, priced service.

## Plan of Work

This top-level plan is executed by completing the four concrete ExecPlans listed at the top, in this order:

1. Proof amortization: implement batch/aggregation so L1 verifies O(1) proofs per block, not O(tx_count).
2. DA sidecar: move ciphertext payloads out of the block body, keep only commitments in block headers/extrinsics, and enforce retrievability via sampling.
3. Censorship resistance + fees: prevent “fee markets” from destroying privacy (priority bidding reveals intent) while still paying for DA and proving.
4. Cold archival + recovery: create an explicit, opt-in archival product with clear guarantees and a wallet recovery path.

The key “early win” milestone that proves we are on the right path is:

“A devnet runs where a block can represent thousands of shielded transfers, and a fresh wallet can sync those ciphertexts via DA chunk retrieval without relying on block bodies.”

## Concrete Steps

From the repository root:

1. Set up the repo and build the node:

    make setup
    make node

2. Run the existing proof benchmark to see the baseline:

    cargo run -p circuits-bench --release -- --smoke --json --prove

3. Start a dev node (mining enabled):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

4. Only after the four linked ExecPlans are implemented, run the end-to-end commerce demo described in their acceptance sections.

## Validation and Acceptance

This top-level plan is “done” when all of the following are true on a local devnet:

1. Throughput: a single L1 block can carry validity for ≥1,024 shielded transfers (either directly as one batch proof or as a small number of aggregated proofs).
2. Block verification: a commodity server can verify each block in bounded time (target: < 500 ms for proof verification + DA sampling in native code; state updates should not be O(tx_count) in the verifier).
3. DA retrievability: ciphertext payloads are not carried inside the block body, and `da_getChunk` can retrieve sampled chunks for new blocks.
4. Wallet sync: a fresh wallet can discover and decrypt incoming notes by fetching ciphertexts during the hot retention window.
5. Security: the system keeps ML‑KEM‑1024 note encryption and keeps the STARK soundness target at ≥128-bit.

## Idempotence and Recovery

All steps in this plan must be repeatable on a clean dev chain (`--dev --tmp`). If a milestone requires a chain reset (genesis change), state that explicitly in that plan and provide a safe wipe procedure (delete the dev db, delete wallet db).

## Artifacts and Notes

Record benchmark JSON outputs and the final “commerce demo” log excerpt in the relevant ExecPlan files (not in this top-level plan).

## Interfaces and Dependencies

The concrete ExecPlans will introduce or harden the following interfaces:

- A batch/aggregation proof producer and verifier in Rust (Plonky3-based), integrated into the node’s import pipeline.
- A DA sidecar interface keyed by `DaRoot` with chunk proofs (`state/da` + `node/src/substrate/network_bridge.rs`).
- A wallet-facing RPC that can fetch ciphertext ranges from DA data, not from block bodies.
- A fee model that prices bytes *and* retention time, without relying on public priority bidding.
