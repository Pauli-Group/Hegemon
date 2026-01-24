# Proof Aggregation (Plonky3): Make Block Validity O(1) Proofs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Make Hegemon scalable without trusting provers with user secrets by replacing “verify N transaction proofs” with “verify one small aggregation proof that attests those N proofs were valid.”

This plan is specifically about *non-custodial* scaling: wallets keep generating their own transaction proofs (so they never hand spend secrets to an external prover), and the chain verifies an aggregation proof that compresses many independent transaction proofs.

After this work, a developer can:

1. Generate (or reuse) a set of valid transaction proofs.
2. Generate a single aggregation proof for those proofs.
3. Verify only the aggregation proof during block import and still reject any block containing an invalid transaction proof.

The “it works” proof is:

- `cargo run -p circuits-bench --release -- --smoke --json` reports that aggregated verification requires verifying O(1) proofs per block (not O(tx_count)).
- A dev node mines blocks containing aggregated proof artifacts; block import verifies the aggregation proof and rejects a block where one inner proof is corrupted.

## Progress

- [x] (2026-01-21T00:00Z) Draft proof aggregation ExecPlan (this file).
- [x] (2026-01-21T20:09Z) Ran `cargo test -p plonky3-spike --features plonky3` to confirm the current Plonky3 toolchain builds and executes a basic proof.
- [x] (2026-01-21T20:09Z) Searched the repo and Cargo.lock for recursion/inner-verifier crates and found only legacy recursion error types, no active recursion implementation.
- [x] (2026-01-21T20:10Z) Confirmed current transaction proof sizes and verifier times with `circuits-bench` and recorded the output.
- [x] (2026-01-21T20:18Z) Fetched the Plonky3 recursion repo via a git dependency and ran its recursion Fibonacci test successfully.
- [x] (2026-01-21T20:21Z) Attempted a compatibility build with `p3-*` patched to the recursion repo’s git rev; build failed in `synthetic-crypto` due to dependency/API mismatches (rand_core / ml-dsa / ml-kem), indicating non-trivial integration work.
- [x] (2026-01-21T20:22Z) Prototyping: recursion is feasible upstream (Plonky3-recursion Fibonacci test passes) but not available in the current crates.io dependency set; integrating requires dependency alignment.
- [x] (2026-01-21T20:40Z) Ran the local recursion spike in this repo using Plonky3 git dependencies; Fibonacci recursion test passes once the spike is isolated from the main workspace.
- [x] (2026-01-21T20:47Z) Prototyping: measured toy recursion (Fibonacci verifier-in-circuit) runtime and memory footprint using the local spike.
- [x] (2026-01-21T21:12Z) Aligned workspace Plonky3 dependencies to git rev `7895d23` and updated the poseidon2 constants script dependencies to match.
- [x] (2026-01-21T21:18Z) Updated `synthetic-crypto` to ML-DSA rc.3 / ML-KEM pre.3 / SLH-DSA rc.2 and fixed API changes; `cargo test -p synthetic-crypto` passes.
- [x] (2026-01-22T00:30Z) Prototyping: recursion verification of a real transaction proof succeeds in the local spike after aligning the FRI transcript and conditional PoW challenge handling.
- [x] (2026-01-21T21:40Z) Diagnosed the recursion failure: conflict occurs on `fri_final_poly[0]` (public input index 8883), implying the in-circuit FRI fold chain disagrees with the proof’s final polynomial even though the inner proof verifies.
- [x] (2026-01-22T00:30Z) Implemented a single-proof aggregation circuit for a real transaction proof (verify 1 proof inside an outer proof).
- [x] (2026-01-22T00:30Z) Measured single-proof aggregation (proof sizes, prove/verify times, RSS) via `transaction_aggregate`.
- [x] (2026-01-22T00:46Z) Added a corrupted-proof check for the single-proof aggregation spike (flip a byte, expect recursion circuit rejection).
- [x] (2026-01-22T01:19Z) Scaled aggregation to verify 2/4/8/16 proofs in one outer proof and recorded size + prove/verify times.
- [x] (2026-01-22T01:42Z) Bound recursion proofs to public inputs by including public values in batch-STARK transcripts and verifying with explicit public values.
- [x] (2026-01-22T02:30Z) Integrated aggregation proof verification into consensus block import; nodes verify aggregation proofs with public-value binding and skip per-transaction STARK verification when present, and `submit_aggregation_proof` now carries aggregation bytes on-chain.
- [x] (2026-01-22T06:05Z) Re-ran batch aggregation test with public-value binding after the PoW transcript fix and recorded updated 2/4/8/16 metrics.
- [x] (2026-01-23T23:40Z) Re-ran batch aggregation test after the ciphertext-hash public-input update and recorded refreshed 2/4/8/16 metrics (release build).
- [x] (2026-01-22T04:30Z) Added `circuits/aggregation` crate with `prove_aggregation` library entrypoint and `aggregation-prover` CLI that consumes postcard-encoded `TransactionProof` files.
- [x] (2026-01-22T04:30Z) Wired optional aggregation proof generation into block building behind `HEGEMON_AGGREGATION_PROOFS`, attaching `submit_aggregation_proof` when enabled.
- [x] (2026-01-22T04:30Z) Added an ignored aggregation roundtrip test that verifies aggregation proofs and rejects corrupted inner proofs.
- [x] (2026-01-22T05:20Z) Patched Plonky3 recursion dependencies to a local vendor copy with PoW witness sampling gated on pow bits; aggregation roundtrip test now passes end-to-end.
- [x] (2026-01-22T18:54Z) Security hardening: remove any “optional” gates for consensus‑critical proof verification in production builds.
- [x] (2026-01-22T06:20Z) End-to-end: mined a dev block with an aggregation proof attached (block 6 on dev node).
- [x] (2026-01-22T06:30Z) End-to-end: corrupted aggregation proof causes mined block import rejection.
- [x] (2026-01-24T00:00Z) Benchmarked on-chain aggregation proof inclusion at 2/4/8 transfers per block and fixed a node crash when the aggregation extrinsic exceeds block resources (omit aggregation proof instead of panicking).
- [x] (2026-01-24T00:00Z) Integrated proof sidecar staging so tx proofs can be omitted from each transfer extrinsic while still generating/verifying an aggregation proof per block (benchmarked 8/16 transfers).
- [x] (2026-01-24T00:00Z) Reduced per-block overhead: cached the aggregation verifier circuit/airs/common in `consensus::aggregation::verify_aggregation_proof` and set a dev-mode default rayon thread cap in the node to reduce macOS “watchdog wedge” risk during heavy recursion verification.

## Surprises & Discoveries

- Observation: The current transaction proof is ~357 KiB, which makes “verify every tx proof on L1” a dead end for high throughput even with parallelism.
  Evidence: `cargo run -p circuits-bench --release -- --smoke --json --prove` reports `tx_proof_bytes_avg` around 357,130 bytes.

- Observation: The repo previously attempted recursion with a different STARK backend and explicitly removed it pending a “Plonky3-native recursion design.”
  Evidence: `METHODS.md` notes that recursive epoch proofs were removed and require a Plonky3-native path; `.agent/archive/scalability_architecture_execplan.md` documents the pivot away from recursion.

- Observation: There is no obvious active recursion/inner-verifier crate in the current workspace dependencies.
  Evidence: `rg -n "recurs" Cargo.toml Cargo.lock -S` returns no recursion dependencies; only legacy error types appear under `circuits/block/src/error.rs`.

- Observation: The current proof throughput is ~0.22 tx/s at smoke settings, with ~31.7 ms verification and ~17.8 s proving per transaction.
  Evidence: `cargo run -p circuits-bench --release -- --smoke --json --prove` output includes `transactions_per_second: 0.2202`, `verify_ns: 31701208`, `prove_ns: 17799278334`, `tx_proof_bytes_avg: 357130`.

- Observation: The downloaded Plonky3 crates in the cargo registry do not expose any obvious recursion or “verifier-in-circuit” modules.
  Evidence: `rg -n "recurs|recursion" ~/.cargo/registry/src -g "p3-*" -S` returned no matches.

- Observation: The upstream Plonky3 recursion repo includes a working recursion circuit (Fibonacci test passes) when built against Plonky3 git dependencies.
  Evidence: `cargo test --manifest-path ~/.cargo/git/checkouts/plonky3-recursion-*/**/Cargo.toml --package p3-recursion --test fibonacci` passes.

- Observation: Aligning our workspace to the recursion repo’s Plonky3 git rev causes build failures in `synthetic-crypto` due to rand_core / ml-dsa / ml-kem API mismatches.
  Evidence: Building a temporary crate with `[patch.crates-io]` pointing `p3-*` to `https://github.com/Plonky3/Plonky3` `rev=7895d23` fails with errors like `ml_dsa::SigningKey::decode` missing and `rand_core` trait mismatches in `crypto/src/slh_dsa.rs`.

- Observation: A local recursion spike can run in-repo when isolated from the root workspace, confirming the recursion stack compiles outside the main dependency graph.
  Evidence: `cargo test --manifest-path spikes/recursion/Cargo.toml --test fibonacci -- --nocapture` passes after adding an empty `[workspace]` table to the spike manifest.

- Observation: The toy recursion spike (Fibonacci verifier-in-circuit) peaks around 339 MiB RSS in release mode on macOS.
  Evidence: `/usr/bin/time -l cargo test --manifest-path spikes/recursion/Cargo.toml --test fibonacci --release -- --nocapture` reports `maximum resident set size` of 355,729,408 bytes.

- Observation: The real-transaction recursion mismatch was caused by transcript divergence when FRI PoW bits are zero; the recursion circuit was still sampling/observing PoW data and sampling `zeta_next`, so the transcript no longer matched the non-recursive verifier.
  Evidence: After aligning the transcript order and deriving `zeta_next` from the trace domain (and skipping PoW challenges when bits=0), the `transaction_aggregate` spike produces and verifies an outer proof.

- Observation: Single-proof aggregation now completes with an outer proof size of ~868 KiB, ~45.3 s proving time, ~0.87 s verify time, and ~234 MiB RSS on macOS debug build.
  Evidence: `cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate aggregate_single_transaction_proof -- --ignored --nocapture` prints `outer_aggregate_proof_bytes=867857, outer_prove_ms=45331, outer_verify_ms=869`; `/usr/bin/time -l` reports `maximum resident set size` of 245,678,080 bytes and `125.03 real`.

- Observation: A single-byte corruption in the inner proof causes the recursion circuit to reject the public inputs with a witness conflict.
  Evidence: `corrupted_proof_rejected: WitnessConflict { witness_id: WitnessId(9052), ... }` in `transaction_aggregate`.

- Observation: With public-value binding enabled, aggregated proof size grows from ~0.95 MiB (2 proofs) to ~1.20 MiB (16 proofs); verify time rises from ~0.9 s to ~2.6 s; prove time scales roughly linearly (debug build).
  Evidence: `aggregate_count=2 ... outer_aggregate_proof_bytes=945200, outer_prove_ms=76591, outer_verify_ms=900`; `aggregate_count=4 ... outer_aggregate_proof_bytes=1027153, outer_prove_ms=151774, outer_verify_ms=1173`; `aggregate_count=8 ... outer_aggregate_proof_bytes=1113555, outer_prove_ms=314964, outer_verify_ms=1820`; `aggregate_count=16 ... outer_aggregate_proof_bytes=1202506, outer_prove_ms=778709, outer_verify_ms=2649` in `aggregate_transaction_proof_batch`.

- Observation: Re-running the batch aggregation spike in release mode with the current public-input layout yields much faster proving and verification, while proof sizes remain ~1.0–1.3 MiB.
  Evidence: `aggregate_count=2 ... outer_aggregate_proof_bytes=1028257, outer_prove_ms=7157, outer_verify_ms=56`; `aggregate_count=4 ... outer_aggregate_proof_bytes=1113894, outer_prove_ms=12989, outer_verify_ms=81`; `aggregate_count=8 ... outer_aggregate_proof_bytes=1202976, outer_prove_ms=24844, outer_verify_ms=139`; `aggregate_count=16 ... outer_aggregate_proof_bytes=1295516, outer_prove_ms=71732, outer_verify_ms=372` from `HEGEMON_AGG_COUNTS=2,4,8,16 cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate aggregate_transaction_proof_batch --release -- --ignored --nocapture`.

- Observation: Batch-STARK proofs produced by the circuit prover were not binding public inputs because public values were omitted from the transcript; this must be fixed before aggregation proofs can be tied to specific inner proofs.
  Evidence: Added `PublicAir::trace_to_public_values` and `verify_all_tables_with_public_values` so public inputs are included in the transcript and verification path.

- Observation: The upstream recursion circuit always observes PoW witnesses even when pow bits are zero, which diverges from the non-recursive verifier transcript and breaks aggregation proofs.
  Evidence: Aggregation roundtrip test failed with `WitnessConflict` until switching to a local recursion copy that gates PoW witness sampling on `pow_bits > 0`.

- Observation: Dev node mining with aggregation proofs enabled attaches a ~945 KiB aggregation proof for a single shielded transfer.
  Evidence: `Aggregation proof extrinsic attached block_number=6 proof_size=945469` in `/tmp/hegemon-node-agg-9945.log`.

- Observation: With the current “tx proofs inside each transfer” block format, aggregation proofs quickly become unshippable on-chain: at 8 transfers, attaching the ~1.20 MiB aggregation proof exhausts block resources.
  Evidence: `/tmp/hegemon-throughput-8b.log` shows `tx_count=8`, `tx_proof_bytes_total=2857875`, `commitment_proof_bytes=253476`, and `proof_size=1202209` for `submit_aggregation_proof` failing with `InvalidTransaction::ExhaustsResources`.

- Observation: After moving per-tx proofs off-chain (proof sidecar), the aggregation proof becomes the dominant fixed on-chain cost (~1.20 MiB at 8, ~1.30 MiB at 16), and blocks can include it again under the same runtime limits.
  Evidence: tx_count=8: `aggregation_proof_bytes=1202537`, `extrinsics_bytes_total=1461413`.
  Evidence: tx_count=16: `aggregation_proof_bytes=1295629`, `extrinsics_bytes_total=1584473`.

- Observation: Corrupting the aggregation proof triggers block import rejection during mined block verification.
  Evidence: `Failed to import mined block error=mined block proof verification failed: proof verification failed: aggregation proof verification failed: ...` in `/tmp/hegemon-node-agg-corrupt.log`.

## Decision Log

- Decision: Do not use delegated proving (sending spend witnesses to a prover) as a scalability strategy.
  Rationale: A prover with spend witnesses can steal funds; that is an unacceptable trust model for “world commerce.” We scale by aggregating *proofs*, not by centralizing *witnesses*.
  Date/Author: 2026-01-21 / Codex

- Decision: Treat proof aggregation as a feasibility-gated workstream and start with explicit prototyping milestones.
  Rationale: If the current Plonky3 stack in this repo cannot express recursion at reasonable cost, we must know early and pivot to a different aggregation mechanism (or a different proving stack) rather than building assumptions into the protocol.
  Date/Author: 2026-01-21 / Codex

- Decision: Move `synthetic-crypto` to ML-DSA rc.3, ML-KEM pre.3, and SLH-DSA rc.2 to align with the dependency graph needed for recursion spikes.
  Rationale: The recursion spike pulled newer RustCrypto pre-release APIs; updating the wrapper keeps the workspace and spike aligned without pinning old crates.
  Date/Author: 2026-01-21 / Codex

- Decision: Align the recursive verifier transcript with the non-recursive flow by deriving `zeta_next` from the trace domain and skipping FRI PoW witness/challenge sampling when PoW bits are zero.
  Rationale: Prevent transcript divergence that caused `fri_final_poly[0]` conflicts and ensure recursive verification matches production parameters (PoW disabled).
  Date/Author: 2026-01-22 / Codex

- Decision: Treat public input binding as mandatory for aggregation proofs and require explicit public values during batch-STARK verification.
  Rationale: Without transcript binding to public inputs, an aggregation proof could attest to unrelated proofs. The verifier must supply the public values derived from the inner proofs.
  Date/Author: 2026-01-22 / Codex

- Decision: Encode aggregation proofs as serialized `BatchProof` bytes and verify them by feeding explicit public values into `p3_batch_stark::verify_batch` instead of relying on `BatchStarkProver` internals.
  Rationale: `BatchProof` already supports `serde` serialization, while `BatchStarkProof` metadata is derivable from the recursion circuit; explicit public-value binding avoids needing patched verifier internals.
  Date/Author: 2026-01-22 / Codex

- Decision: Ship a standalone aggregation prover CLI that consumes postcard-encoded `TransactionProof` files.
  Rationale: External prover markets need a clean artifact that takes proof bytes only (no witnesses) and outputs a serialized aggregation proof suitable for `submit_aggregation_proof`.
  Date/Author: 2026-01-22 / Codex

- Decision: Gate local aggregation proof generation behind `HEGEMON_AGGREGATION_PROOFS`.
  Rationale: Aggregation proving is expensive; defaulting it off avoids surprise CPU burn while still allowing explicit opt-in for devnet demos and market-style workflows.
  Date/Author: 2026-01-22 / Codex

- Decision: Patch Plonky3 recursion dependencies to a local vendor copy to align PoW witness handling with the non-recursive FRI transcript.
  Rationale: The upstream recursion transcript observes PoW witnesses even when `pow_bits=0`, which makes aggregated proofs for production parameters unsatisfiable.
  Date/Author: 2026-01-22 / Codex

- Decision: Enforce proof verification in production builds even if `HEGEMON_PARALLEL_PROOF_VERIFICATION` is set to disable.
  Rationale: Consensus-critical verification cannot be optional in production; allow toggling only in non-production builds for local benchmarking.
  Date/Author: 2026-01-22 / Codex

## Outcomes & Retrospective

2026-01-22: Milestone 3 prototyping now produces and verifies an outer proof for a real transaction proof. Measurements recorded for proof size, prove/verify time, RSS, corrupted-proof rejection, batch aggregation scaling to 16 proofs, and public-input binding. Remaining work includes block import integration.

## Context and Orientation

This plan follows the design goals in `DESIGN.md §0`: one canonical privacy pool, PQ-only primitives (ML-KEM-1024 with >=128-bit PQ security), transparent hash-based proofs, and scaling by moving work off L1 without outsourcing spend secrets. Aggregation must therefore operate on transaction proof bytes and public inputs only; it must never require spend witnesses.

Current proof and verification layout:

- Individual transactions are proven with a Plonky3 STARK and verified by `transaction_core::p3_verifier::verify_transaction_proof_bytes_p3`. The runtime verifier wrapper is in `pallets/shielded-pool/src/verifier.rs` (`StarkVerifier`).
- There is a block-level “commitment proof” path (see `.agent/archive/scalability_architecture_execplan.md` and `circuits/block`) that can commit to an ordered list of transaction proof hashes and prove nullifier uniqueness, but it does not eliminate the need to verify transaction proofs for soundness.
- A batch transaction circuit exists (`circuits/batch`) that can prove multiple transactions from the *same prover* in one proof. It helps for wallet self-batching and consolidation, but it does not solve “many users, many independent proofs” without a recursion/aggregation mechanism.

Definitions (avoid jargon):

- “Inner proof”: the existing transaction STARK proof bytes produced by a wallet for one transfer.
- “Outer proof” / “aggregation proof”: a proof whose statement is “these inner proofs are valid for these public inputs.” The outer proof is what the chain verifies.
- “Recursion” in this plan means “proof verification inside a proof”: the outer proof’s constraints include the verification logic of the inner proof system.

The security bar for this plan:

- We keep ML‑KEM‑1024 for note encryption unchanged.
- We keep ≥128-bit post-quantum security targets for hash collision resistance (48-byte digests) and for STARK soundness. If we change FRI parameters, we must re-justify and re-benchmark; we do not lower security.

## Plan of Work

### Milestone 1 (prototyping): Can we do recursion at all?

Goal: determine whether the Plonky3 crates and configurations used in this repo can feasibly express “verify a STARK proof inside another proof.”

Work:

- Inspect the workspace dependencies to find whether any recursion-oriented crates or modules exist. Search for “recursion”, “verifier circuit”, “fri verifier”, and similar in `circuits/` and in Cargo dependencies.
- If there is no recursion support, decide whether to:
  - add a Plonky3 recursion crate (if available as a Rust dependency) while keeping the security model hash-based, or
  - pivot to an alternative aggregation mechanism compatible with the repo’s “hash-only” PQ assumptions.

Acceptance:

- A short note in `Surprises & Discoveries` stating “recursion feasible” or “recursion not currently feasible,” with evidence (buildable code, compile errors, or measured resource requirements).

### Milestone 2 (prototyping): Toy recursion proof that runs end-to-end

Goal: produce a working outer proof that verifies a simple inner proof, using a toy AIR that is already in the repo.

Work:

- Use `circuits/plonky3-spike` as the inner proof system candidate. It already proves and verifies a small Fibonacci AIR.
- Implement an “outer” circuit that takes the serialized Fibonacci proof bytes and public inputs and verifies them inside the circuit.
- Keep the toy security parameters aligned with the production posture: use the same digest size (6 Goldilocks limbs = 48 bytes) and do not reduce the soundness target below 128-bit. It is acceptable to reduce *trace size* to keep the prototype fast, but not to reduce hash output sizes or the claimed security level.

Acceptance:

- A new test (or bench binary) that:
  - generates an inner Fibonacci proof,
  - generates an outer proof attesting that the inner proof is valid,
  - and verifies the outer proof.

### Milestone 3: Verify one real transaction proof inside an outer proof

Goal: upgrade from toy recursion to verifying one real shielded transaction proof.

Work:

- Define an “aggregation public inputs” structure that includes:
  - the transaction public inputs (anchor, nullifiers, commitments, fee, value balance, stablecoin bindings as applicable),
  - and a digest of the inner proof bytes (so the statement binds to a specific proof).
- Implement the inner verifier logic inside the outer circuit using the same Plonky3 verification path as `transaction_core::p3_verifier`.
- Ensure the outer proof binds to the expected AIR hash / circuit ID for the inner transaction proof (no “verify anything” bugs).

Acceptance:

- A reproducible command that:
  - generates a transaction proof with existing tooling,
  - generates an aggregation proof for that transaction proof,
  - verifies the aggregation proof,
  - and fails if a single byte in the inner proof is flipped.

### Milestone 4: Scale to N inner proofs per outer proof

Goal: aggregate multiple independent transaction proofs (start with N=2 and scale upward).

Work:

- Start with a fixed maximum `MAX_AGGREGATED_PROOFS` (for example 16) and padding rules so the outer circuit has a static shape.
- Define an ordering rule and commit to it. For example: “inner proofs are ordered by their transaction hash bytes.” The exact choice matters less than determinism and binding.
- Add benchmarking to measure:
  - outer proof size in bytes as N increases,
  - outer verification time,
  - and prover time/memory.

Acceptance:

- `circuits-bench` gains a new mode (or a separate bench) that prints outer proof size and verification time for N in {1, 2, 4, 8, 16}.

### Milestone 5: Integrate into block import and remove per-tx verification on the hot path

Goal: make block validity depend on the aggregation proof, not on verifying each inner proof during import.

Work:

- Add a way for a block to carry the aggregation proof bytes (as an inherent-style unsigned extrinsic, mirroring `submit_commitment_proof`), and a way to bind it to the block’s transaction list.
- In the node import pipeline (`node/src/substrate/service.rs`), verify the aggregation proof and reject the block if it fails.
- Ensure that any existing runtime proof verification is either:
  - removed (and replaced by deterministic checks that the proof bytes were committed and match the aggregation statement), or
  - made a “structural check” only, so the heavy crypto verification is not done twice.

Acceptance:

- A dev node mines a block with multiple shielded transfers and an aggregation proof.
- Corrupting one inner proof causes the block to be rejected, even if everything else is unchanged.

## Concrete Steps

Run the following from the repository root.

0. If this is a fresh clone, install toolchains first:

    make setup

1. Baseline current proof sizes:

    cargo run -p circuits-bench --release -- --smoke --json --prove

2. Identify recursion code or dependencies:

    rg -n "recurs|verifier circuit|fri verifier|verify inside" circuits -S
    rg -n "recurs" Cargo.toml Cargo.lock -S

3. Run the existing Plonky3 spike test (this confirms the baseline proving stack compiles and runs):

    cargo test -p plonky3-spike --features plonky3

4. Generate and verify an aggregation proof roundtrip (ignored by default because it is slow):

    cargo test -p aggregation-circuit --test aggregation -- --ignored --nocapture

5. Use the standalone aggregation prover to emit proof bytes from postcard-encoded `TransactionProof` files:

    cargo run -p aggregation-circuit --bin aggregation-prover -- --proof /path/to/txproof.pcd --out aggregation-proof.bin

6. After implementing Milestones 2–4, run the new recursion tests/benches and record the output in this plan.

## Validation and Acceptance

Acceptance is defined per-milestone above. The final acceptance for this plan is:

1. A block can carry an aggregation proof that attests validity of N inner transaction proofs.
2. Block import verifies only the aggregation proof (plus any separate block-level commitment proof) and rejects blocks containing any invalid transaction proof.
3. The aggregation proof and its public inputs are domain-separated and bind to the expected inner circuit ID / AIR hash (no cross-circuit confusion).
4. The security targets (ML‑KEM‑1024 note encryption; ≥128-bit PQ hash collision; ≥128-bit STARK soundness) remain unchanged.
5. When `HEGEMON_AGGREGATION_PROOFS=1`, mined blocks include a `submit_aggregation_proof` extrinsic (visible via `author_pendingExtrinsics` or `chain_getBlock`).

## Idempotence and Recovery

Prototyping milestones should be additive. If recursion proves infeasible, do not leave half-integrated consensus code behind. Keep recursion experiments behind a feature flag or in a dedicated crate until the end-to-end path is proven.

If a recursion approach increases proof size or verification time unexpectedly, record the measurements in `Surprises & Discoveries` and decide whether to:

- reduce the number of aggregated proofs per block (and increase block frequency), or
- introduce a multi-level aggregation tree (aggregate 16 at a time, then aggregate those aggregations), or
- change the proof system choice (only if it preserves the hash-based PQ posture).

## Artifacts and Notes

Record here, as indented blocks:

- The JSON bench output for baseline `tx_proof_bytes_avg`.
- The outer proof size and verify time for N in {1, 2, 4, 8, 16}.
- A log excerpt showing a corrupted inner proof causes outer verification failure.

  Plonky3 spike test (baseline proof stack):

    cargo test -p plonky3-spike --features plonky3
    ...
    test tests::fibonacci_prove_verify ... ok

  Baseline proof size/latency output:

    cargo run -p circuits-bench --release -- --smoke --json --prove
    {
      "prove": true,
      "prove_ns": 17799278334,
      "verify_ns": 31701208,
      "commitment_proof_bytes": 228076,
      "tx_proof_bytes_avg": 357130,
      "fri_conjectured_soundness_bits": 128,
      "transactions_per_second": 0.2202218957737747
    }

  Plonky3 recursion repo Fibonacci test (verifier-in-circuit works upstream):

    cargo test --manifest-path ~/.cargo/git/checkouts/plonky3-recursion-*/**/Cargo.toml --package p3-recursion --test fibonacci -- --nocapture
    ...
    test test_fibonacci_verifier ... ok

  Local recursion spike (in-repo):

    cargo test --manifest-path spikes/recursion/Cargo.toml --test fibonacci -- --nocapture
    ...
    test recursion_fibonacci_spike ... ok

  Local recursion spike (release build, memory/time):

    /usr/bin/time -l cargo test --manifest-path spikes/recursion/Cargo.toml --test fibonacci --release -- --nocapture
    ...
    test recursion_fibonacci_spike ... ok
           355729408  maximum resident set size
       17.86 real        46.01 user         3.99 sys

  Transaction aggregation spike (single proof succeeds):

    cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored --nocapture
    ...
    inner_tx_proof_bytes=87018, degree_bits=13, commit_phase_len=13
    fri_params_log_blowup=3, log_final_poly_len=0, log_height_max=3
    recursion_public_inputs_len=8909, air_public_len=60, proof_values_len=8825, challenges_len=24, commitments_len=12, opened_values_len=280, opening_proof_len=8533
    outer_aggregate_proof_bytes=867857, outer_prove_ms=45331, outer_verify_ms=869
    corrupted_proof_rejected: WitnessConflict { witness_id: WitnessId(9052), ... }
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 132.69s

  Transaction aggregation spike (batch scaling):

    HEGEMON_AGG_COUNTS=2,4,8,16 cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate aggregate_transaction_proof_batch -- --ignored --nocapture
    ...
    aggregate_count=2, outer_aggregate_proof_bytes=945209, outer_prove_ms=78731, outer_verify_ms=702
    aggregate_count=4, outer_aggregate_proof_bytes=1028444, outer_prove_ms=153370, outer_verify_ms=759
    aggregate_count=8, outer_aggregate_proof_bytes=1113600, outer_prove_ms=338059, outer_verify_ms=903
    aggregate_count=16, outer_aggregate_proof_bytes=1203159, outer_prove_ms=688541, outer_verify_ms=982

  Transaction aggregation spike (memory/time):

    /usr/bin/time -l cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored --nocapture
    ...
           245678080  maximum resident set size
       125.03 real       122.27 user         1.15 sys

  Compatibility attempt (git Plonky3 rev in our dependency graph) failed:

    cargo build --manifest-path /tmp/recursion_compat/Cargo.toml
    ...
    error[E0599]: no function or associated item named `decode` found for struct `ml_dsa::SigningKey<P>`
    error[E0277]: the trait bound `SlhCompatibleRng: DerefMut` is not satisfied

## Interfaces and Dependencies

At the end of Milestone 5, the repo must have:

- A Rust API for aggregation proving that accepts `TransactionProof` values and returns postcard-encoded `BatchProof` bytes via `aggregation_circuit::prove_aggregation(...)`.
- A standalone `aggregation-prover` CLI that accepts postcard-encoded `TransactionProof` files and emits aggregation proof bytes for `submit_aggregation_proof`.
- A node-level block import hook that locates aggregation proof bytes in the block, verifies them, and rejects invalid blocks.
- A deterministic binding from block transaction ordering to the aggregation statement (so miners cannot “swap proofs”).

Plan update 2026-01-22: added a design-principles paragraph in Context, recorded the new aggregation prover crate/CLI and block-builder integration behind `HEGEMON_AGGREGATION_PROOFS`, and updated steps/interfaces so future decisions stay grounded in the PQ/transparent/anti-witness-sharing philosophy.
