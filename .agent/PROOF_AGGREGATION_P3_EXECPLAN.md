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
- [ ] Prototyping: attempt recursion verification of a real transaction proof in the new spike (currently fails with witness conflict during circuit execution; see Surprises).
- [ ] Implement an aggregation circuit for the *real* transaction proof (verify 1 proof inside an outer proof).
- [ ] Scale aggregation to verify a small batch of proofs (start with 2, then 4, then 8, then 16) and measure.
- [ ] Integrate aggregation into block import so the node verifies the aggregation proof and stops verifying every inner proof on the hot path.
- [ ] Security hardening: remove any “optional” gates for consensus‑critical proof verification in production builds.
- [ ] End-to-end: mine a dev block with an aggregation proof; prove that a corrupted inner proof causes rejection.

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

- Observation: The attempted recursion verifier for a real transaction proof fails at circuit execution with a `WitnessConflict`, so the outer proof cannot be produced yet.
  Evidence: `cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored --nocapture` fails with `WitnessConflict { witness_id: WitnessId(9053), ... }` after printing `inner_tx_proof_bytes=87018`.

Update this section with concrete prototyping results (what worked, what failed, and why) as soon as the first recursion spike is attempted.

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

## Outcomes & Retrospective

Not started. Update after the first working recursion prototype.

## Context and Orientation

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

4. After implementing Milestones 2–4, run the new recursion tests/benches and record the output in this plan.

## Validation and Acceptance

Acceptance is defined per-milestone above. The final acceptance for this plan is:

1. A block can carry an aggregation proof that attests validity of N inner transaction proofs.
2. Block import verifies only the aggregation proof (plus any separate block-level commitment proof) and rejects blocks containing any invalid transaction proof.
3. The aggregation proof and its public inputs are domain-separated and bind to the expected inner circuit ID / AIR hash (no cross-circuit confusion).
4. The security targets (ML‑KEM‑1024 note encryption; ≥128-bit PQ hash collision; ≥128-bit STARK soundness) remain unchanged.

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

  Transaction aggregation spike (failed at circuit execution):

    cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored --nocapture
    ...
    inner_tx_proof_bytes=87018
    thread 'aggregate_single_transaction_proof' panicked at tests/transaction_aggregate.rs:188:31:
    run recursion circuit: WitnessConflict { witness_id: WitnessId(9053), ... }

  Compatibility attempt (git Plonky3 rev in our dependency graph) failed:

    cargo build --manifest-path /tmp/recursion_compat/Cargo.toml
    ...
    error[E0599]: no function or associated item named `decode` found for struct `ml_dsa::SigningKey<P>`
    error[E0277]: the trait bound `SlhCompatibleRng: DerefMut` is not satisfied

## Interfaces and Dependencies

At the end of Milestone 5, the repo must have:

- A Rust API for aggregation proving and verification, with stable entry points (example names):
  - `circuits::aggregate::prove_aggregate(...) -> AggregateProof`
  - `circuits::aggregate::verify_aggregate(...) -> Result<(), VerifyError>`
- A node-level block import hook that locates aggregation proof bytes in the block, verifies them, and rejects invalid blocks.
- A deterministic binding from block transaction ordering to the aggregation statement (so miners cannot “swap proofs”).
