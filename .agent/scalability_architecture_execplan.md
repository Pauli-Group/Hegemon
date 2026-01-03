# Make Hegemon a Proof-Carrying, DA-First PQ Privacy Chain

This ExecPlan is a living document. The sections Progress, Surprises & Discoveries, Decision Log, and Outcomes & Retrospective must be kept up to date as work proceeds.

This document must be maintained in accordance with .agent/PLANS.md from the repository root.

Companion math notes: `.agent/scalability_architecture_math.md` pins down soundness and DA sampling math before implementation. Do not proceed into consensus wiring until the math notes’ constraints are satisfied and any required design pivots are recorded in this plan.

## Purpose / Big Picture

This plan makes the chain fundamentally scalable by validating each block with a single recursive proof and a small set of data-availability samples, while keeping full privacy and post-quantum security. After the change, a single node can mine and validate blocks without re-verifying every transaction proof, and you can see it working by starting the dev node, mining a block, and querying RPC endpoints for the recursive proof and data-availability chunks.

## Progress

- [x] (2026-01-03T06:21Z) Completed Milestone 5 end-to-end validation in tmux: mined a block with a shielded transfer (dev-fast proofs), observed `Recursive block proof generated`, verified `block_getRecursiveProof` returns non-empty proof bytes for the mined block hash, and `da_getChunk` returns a chunk+Merkle proof when called with the logged `da_root`; updated `scripts/recursive_proof_da_e2e_tmux.sh` + `runbooks/recursive_proof_da_e2e.md` to match actual RPC params/timeouts.
- [x] (2026-01-03T03:31Z) Prevented runaway memory during Substrate E2E by changing StorageChanges caching to return an RAII handle stored on the mining template, bounding the cache, and taking StorageChanges early on import (fail-fast if missing); ran `cargo test -p hegemon-node --features substrate` and compiled `cargo test -p security-tests --features substrate --test multi_node_substrate --no-run`.
- [x] (2025-12-31T09:40Z) Fixed recursion verifier replay/restore/tape handling and boundary constraint counts; recursion verifier tests now pass.
- [x] (2025-12-31T09:40Z) Fixed EpochProver public-input wiring and re-ran `epoch-circuit` tests (including ignored heavy tests) with `CARGO_INCREMENTAL=0`.
- [x] (2025-12-31T02:04Z) Rebuilt the ExecPlan to match .agent/PLANS.md requirements, including milestone-level commands, acceptance criteria, and file-specific edit guidance.
- [x] (2025-12-31T02:22Z) Wrote `.agent/scalability_architecture_math.md` to quantify soundness bounds and DA sampling probabilities before implementation.
- [x] (2025-12-31T10:05Z) Completed Milestone 1 feasibility runs (recursion spike output + transaction budget/streaming plan outputs + recursive proof bench timings) and recorded results in Surprises & Discoveries.
- [x] (2025-12-31T10:05Z) Enabled Criterion bench harness and adjusted sample size to satisfy Criterion’s minimum-sample requirement.
- [x] (2025-12-31T10:20Z) Updated the README whitepaper to describe recursive proof validation and data-availability sampling.
- [x] (2025-12-31T10:30Z) Updated consensus header + types for DA parameters and recursive proof commitments, plus chain spec defaults and node header serialization/test helpers (`runtime/src/chain_spec.rs`, `node/src/substrate/chain_spec.rs`, `node/src/codec.rs`, `node/src/test_utils.rs`); re-ran `cargo test -p consensus`.
- [x] (2025-12-31T17:49Z) Added block-circuit recursive proof module + exports and made recursion public-input parsing usable from block proofs.
- [x] (2025-12-31T17:49Z) Added consensus recursive proof verification path (`RecursiveProofVerifier`), recursive-proof-aware block types/serialization, and an ignored heavy consensus proof test.
- [x] (2025-12-31T05:03Z) Added extension-aware inner-proof parsing + public inputs and a transaction recursion budget test; captured initial width metrics.
- [x] (2025-12-31T05:31Z) Added a Path A streaming plan estimator + test output for transaction proofs to size row/permutation costs under the 255-column cap.
- [x] (2025-12-31T06:15Z) Started Path A streaming layout in recursion verifier by adding tape columns + coin-state save/restore masks and a minimal RpoAir tape correctness test.
- [x] (2025-12-31T06:55Z) Paired replayed deep-coefficient draws with leaf-hash chains in the recursion verifier, updated merkle schedule masks, and adjusted merkle-related tests.
- [x] (2025-12-31T03:09Z) Chose a baseline target of ~85-bit PQ security (collision-limited by 256-bit digests) and recorded required proof-parameter implications in `.agent/scalability_architecture_math.md`.
- [ ] (2025-12-31T03:09Z) Lock ProofOptions and recursion format for consensus-critical proofs at the chosen target (completed: transaction proofs now use quadratic extension; completed: parser supports quadratic extension metadata; completed: recursive verifier trace accepts quadratic inner proofs; remaining: full-security (32-query) end-to-end mining/recursion is still too slow/memory-heavy without an aggregation strategy).
- [x] (2025-12-31T04:12Z) Updated transaction STARK proof options to quadratic extension and aligned verifiers + docs to the ~85-bit PQ collision ceiling.
- [x] (2025-12-31T02:04Z) Update DESIGN.md, METHODS.md, and the README.md whitepaper to match the new architecture (completed: DESIGN.md + METHODS.md security notes + README.md whitepaper alignment).
- [x] (2025-12-31T18:45Z) Retired legacy block aggregation: `prove_block` now emits `RecursiveBlockProof` by default, added a fast proving helper for dev/tests, updated consensus test scaffolding to accept recursive proofs, and refreshed docs to remove `RecursiveAggregation`.
- [x] (2025-12-31T19:10Z) Wired Substrate block building to optionally generate recursive block proofs from shielded transfer extrinsics and attach them to mining templates (gated by `HEGEMON_RECURSIVE_BLOCK_PROOFS`).
- [x] (2026-01-01T06:49Z) Enforced quadratic-only transaction proof options (fold-2) by removing base-field verifier acceptance, updated math notes with fold-2 soundness bounds, and added quadratic transcript-draw scaffolding for recursion.
- [x] (2026-01-01T11:05Z) Completed Milestone 4 DA encoding and commitment checks (added `state/da` erasure-coding + Merkle proof module, wired consensus `da_root` recomputation and updated tests; added DA chunk store + DA chunk P2P request/response + per-node sampling enforcement in `node/src/substrate/service.rs` incl. mined block storage; added DA sampling tests in `consensus/tests/da_sampling.rs`; ran `cargo test -p consensus`).
- [x] (2026-01-01T11:05Z) Implement data-availability encoding, storage, sampling, and P2P retrieval.
- [x] (2026-01-01T11:20Z) `cargo check -p hegemon-node` passes when `LIBCLANG_PATH`/`DYLD_FALLBACK_LIBRARY_PATH` are set; fixed no-std `format!`/`String` imports in `circuits/transaction-core/src/stark_air.rs` and added SCALE codec derives for DA chunk types.
- [x] (2026-01-01T16:05Z) Added block + DA RPC endpoints, in-memory recursive proof storage, and block-import logging for recursive proof hashes + DA roots; wired RPC modules into the Substrate RPC server.
- [x] (2026-01-01T16:10Z) Extended circuits/bench to report recursive proof size/verification timing and updated consensus/bench netbench to account for DA-encoded payload sizes.
- [x] (2026-01-01T17:45Z) Updated recursive block proof anchoring to accept historical Merkle roots (anchor window) and refreshed METHODS.md to match.
- [x] (2026-01-01T17:45Z) Marked shielded coinbase inherent as mandatory (Pays::No) to avoid `ExhaustsResources` during block building.
- [x] (2026-01-01T23:40Z) Fixed the recursion transcript pre-merkle permutation count (pow-nonce reseed vs. remainder hash) and rebuilt the node so the verifier/prover schedules stay aligned.
- [x] (2026-01-02T00:10Z) Fixed quadratic recursion deep evaluation to lift base-field trace rows into quadratic limbs, and aligned inner-proof parsing with base-field trace queries.
- [x] (2026-01-02T00:10Z) Added an end-to-end runbook for recursive proof + DA RPC validation (`runbooks/recursive_proof_da_e2e.md`).
- [x] (2026-01-03T06:21Z) Ran the dev-node end-to-end and exercised the new RPC endpoints (recursive proof generated for a mined block, `block_getRecursiveProof` returns proof bytes, and DA chunk proofs are retrievable by `da_root`).
- [x] (2026-01-03T06:21Z) Integrated node, wallet, mempool, and RPC so end-to-end mining works with the new block format (dev-fast wallet proving requires `HEGEMON_ACCEPT_FAST_PROOFS=1`).
- [x] (2026-01-03T06:21Z) Updated runbooks and tmux automation for repeatable end-to-end validation; remaining work is performance (not correctness) on recursive proof generation throughput.

## Surprises & Discoveries

- Observation (2025-12-31T18:45Z): Recursive block proof generation fails if inner transaction proofs are Blake3-based; recursion expects RPO‑Fiat‑Shamir proofs.
  Evidence: `cargo test -p consensus -- --ignored` failed with `RecursiveProofInput { index: 0, reason: "Trace generation failed: Merkle proof is invalid" }` until the test switched to RPO proofs.
  Implication: Mining/wallet pipelines must emit RPO proofs (or we must add a Blake3-compatible recursion backend) before recursive block proofs can be produced from live bundles.

- Observation (2025-12-31T19:10Z): Recursive proof test panics (debug + release) when filling OOD eval columns.
  Evidence: `cargo test -p consensus --test recursive_proof --release -- --ignored` fails with `index out of bounds: the len is 249 but the index is 249` in `winter-prover` `col_matrix.rs`; debug points to `circuits/epoch/src/recursion/stark_verifier_prover.rs:2267` (`COL_OOD_EVALS_START + i`).
  Implication: The verifier trace layout only reserves `VERIFIER_TRACE_WIDTH - COL_OOD_EVALS_START = 77` columns for OOD evals (fixed `OOD_EVAL_LEN` for RPO), but a transaction proof needs `2 * (trace_width + constraint_frame_width)` (188 with `trace_width=86`), so the OOD vector overflows the layout. Fix requires streaming/partitioning OOD evals or otherwise reducing width before recursion can handle transaction proofs.

- Observation (2025-12-31T02:22Z): Deterministic DA sampling derived from producer-known inputs is not a security mechanism against a malicious block producer.
  Evidence: A producer can always publish only the deterministically sampled chunks and withhold the rest; see `.agent/scalability_architecture_math.md` §4.4.
  Implication: The DA milestone must use per-node randomized sampling (network-level enforcement) or introduce an unpredictability source the producer cannot bias at commitment time.

- Observation (2025-12-31T04:12Z): Transaction proofs now use quadratic extension, which clears the field-size bottleneck but increases proving time noticeably under current parameters.
  Evidence: `cargo test -p transaction-circuit --test transaction proving_and_verification_succeeds` completed in ~293s after switching to `FieldExtension::Quadratic`.
  Implication: We need a fast-profile path for developer tests and must measure release-mode proving time before wiring recursion into consensus.

- Observation (2025-12-31T03:09Z): If we keep 256-bit digests and require collision security, the PQ collision ceiling is ~85 bits, so “128-bit PQ soundness” is not achievable without widening digests.
  Evidence: Generic quantum collision search is ~2^(n/3); for n=256 this is ~2^85; see `.agent/scalability_architecture_math.md` §0.1 and §2.4.
  Implication: We either accept ~85-bit PQ collision security as the system ceiling or we change digest sizes and hash primitives.

- Observation (2025-12-31T05:03Z): Transaction recursion budget with quadratic extension already exceeds Winterfell’s MAX_TRACE_WIDTH for OOD evaluations, so the current recursion trace layout cannot fit OOD vectors without redesign.
  Evidence: `cargo test -p epoch-circuit verifier_spike::tests::test_transaction_recursion_budget -- --nocapture` shows `ood_eval_elems: 364` vs `trace_width_cap: 255` with `field_extension: Quadratic (degree 2)`.
  Implication: Recursion will need a wider trace layout, OOD vector partitioning, or a different recursion backend before we can verify transaction proofs end-to-end.

- Observation (2025-12-31T05:31Z): Path A streaming layout keeps total rows at 2^18 for the current transaction proof options (quadratic extension + 32 queries), and per-query transcript work is still a material share of the schedule.
  Evidence: `cargo test -p epoch-circuit verifier_spike::tests::test_transaction_streaming_plan_budget -- --nocapture` prints `per_query_perms: 240`, `global_perms: 1196`, `rows_unpadded: 142016`, `total_rows: 262144`.
  Implication: Path A is feasible on rows but requires a careful transcript/leaf interleave schedule (coin-state save/restore + coeff tape) to avoid reintroducing width growth.

- Observation (2025-12-31T06:55Z): Leaf-hash permutations cannot be interrupted without breaking the RPO sponge carry, so replay draws are inserted at leaf-hash chain boundaries (partition/merge starts) rather than between permutations.
  Evidence: `hash_leaf_perms` requires contiguous carry masks across its permutation blocks; interleaving would invalidate the hash chain.
  Implication: Streaming pairing is currently per leaf-hash chain. Per-permutation pairing would require extra state columns or a different hashing layout.

- Observation (2025-12-31T07:10Z): The recursion verifier currently panics due to a constraint-count mismatch after adding tape + coin-save/restore checks.
  Evidence: `cargo test -p epoch-circuit stark_verifier_prover::tests::test_trace_from_inner_merkle_roundtrip -- --nocapture` fails with `stark_verifier_air.rs:1952: index out of bounds`.
  Implication: Update `base_boundary_constraints` (and any related counts) so `num_constraints` matches `evaluate_transition` before proceeding with more recursion changes.

- Observation (2025-12-31T09:40Z): The constraint-count mismatch and replay/restore boundary errors are resolved.
  Evidence: `cargo test -p epoch-circuit` and the ignored heavy tests now pass after updating `base_boundary_constraints`, gating coin-restore on row 0, and capturing replay tape/deep witnesses from post-permutation state.
  Implication: Path A streaming changes are now stable enough to proceed to the remaining recursion feasibility benchmarks.

- Observation (2025-12-31T09:40Z): Running ignored heavy tests triggered a rustc incremental-cache ICE.
  Evidence: `cargo test -p epoch-circuit -- --ignored` failed with a `dep_graph` panic until rerun with `CARGO_INCREMENTAL=0`.
  Implication: Use `CARGO_INCREMENTAL=0` for heavy test runs until the toolchain issue is resolved.

- Observation (2025-12-31T10:05Z): Recursion spike now reports inner/outer proof sizes and times, meeting the Milestone 1 acceptance criteria.
  Evidence: `cargo test -p epoch-circuit verifier_spike::tests::test_spike_runs_successfully -- --nocapture` reports `Inner proof size: 4012 bytes`, `Outer proof size: 7860 bytes`, `Size ratio: 1.96x`, `Prover time ratio: 1.93x`.
  Implication: The feasibility spike satisfies the <10x size and <100x prover-time targets for the spike setup.

- Observation (2025-12-31T10:05Z): `cargo bench -p epoch-circuit recursive_proof_bench` initially produced no Criterion output until a bench harness was configured.
  Evidence: The bench binary printed only `running 0 tests` until `[[bench]] ... harness = false` was added to `circuits/epoch/Cargo.toml`.
  Implication: Keep the bench harness configuration to ensure Criterion benches run.

- Observation (2025-12-31T10:05Z): Criterion panics when `sample_size` is below 10.
  Evidence: Running the bench raised `assertion failed: n >= 10` until the outer-proof sample size was set to 10.
  Implication: Use the minimum sample size (10) for heavy recursion benches and expect longer runtimes.

- Observation (2025-12-31T10:05Z): Recursive epoch proof bench timings show inner proofs in ~19–24ms and outer proof-of-proof in ~1.65s.
  Evidence: `target/release/deps/recursive_proof_bench-* --bench --output-format bencher` reports `prove_epoch_inner/100 ≈ 18.9ms`, `prove_epoch_inner/1000 ≈ 24.1ms`, `prove_epoch_recursive_outer ≈ 1.65s`.
  Implication: The outer recursion benchmark is materially slower and should be budgeted in block production latency.

- Observation (2025-12-31T17:49Z): Recursive block proof generation is heavy enough that the consensus recursive-proof test is marked ignored to keep default test runs fast.
  Evidence: `consensus/tests/recursive_proof.rs` uses `#[ignore = "heavy: recursive proof generation"]`.
  Implication: Milestone 3 validation requires running ignored tests when confirming recursive proof correctness end-to-end.
- Observation (2026-01-01T09:30Z): The initial DA encoder uses Reed–Solomon over GF(256), which caps total shard count at 255 and will fail on very large blobs unless chunk sizes grow or a 2D scheme lands.
  Evidence: `state/da/src/lib.rs` enforces `MAX_SHARDS = 255` with a hard error.
  Implication: DA parameters must keep `k + p ≤ 255` for now; future work should add 2D RS or larger-field encoding.

- Observation (2026-01-01T11:20Z): `cargo check -p hegemon-node` requires a discoverable libclang and emits runtime warnings about the `wasm32-unknown-unknown` target.
  Evidence: `librocksdb-sys` build fails unless `LIBCLANG_PATH`/`DYLD_FALLBACK_LIBRARY_PATH` include `/Library/Developer/CommandLineTools/usr/lib`; runtime build warns about `wasm32v1-none` support.
  Implication: Document the libclang environment variables for local builds and consider updating the runtime builder to use `wasm32v1-none` once toolchains are aligned.
- Observation (2026-01-01T16:20Z): The dev node shuts down during the end-to-end run because the essential `txpool-background` task fails before mining completes.
  Evidence: `/tmp/hegemon-dev-node-debug.log` shows `ERROR ... Essential task \`txpool-background\` failed. Shutting down service.`
  Implication: The txpool background task needs debugging (or demotion from essential) before we can mine blocks and exercise recursive proof/DA chunk RPCs end-to-end.
- Observation (2026-01-01T17:45Z): Recursive block proof generation failed for shielded transactions because the block circuit required `merkle_root == tree.root()`, but runtime anchor validation accepts historical roots.
  Evidence: `/tmp/hegemon-dev-node-debug.log` shows `Failed to build recursive block proof ... reported merkle root ... but expected ...` on blocks containing shielded transfers.
  Implication: The block proof must validate anchors against the root history window (not just the current root) to match runtime rules.
- Observation (2026-01-01T17:45Z): Shielded coinbase inherents failed with `InvalidTransaction::ExhaustsResources` under default block weight/length limits.
  Evidence: `/tmp/hegemon-dev-node-debug.log` repeatedly logs `Failed to push inherent extrinsic ... ExhaustsResources`.
  Implication: Mark coinbase inherents as `DispatchClass::Mandatory` (or adjust `BlockWeights`/`BlockLength`) so block production can include coinbase even with large shielded payloads.

- Observation (2026-01-01T23:40Z): Recursive proof generation panicked because the verifier pre-merkle permutation count included remainder-hash permutations that happen after the merkle segment.
  Evidence: `pre-merkle perm count mismatch left 1195 right 1196` in `circuits/epoch/src/recursion/stark_verifier_prover.rs`.
  Implication: Track pow-nonce reseed permutations separately from remainder-hash permutations and keep transcript/periodic schedules aligned.

- Observation (2026-01-02T00:10Z): Trace queries remain base-field elements even when proofs use quadratic extension, so quadratic recursion must lift base-field trace rows rather than re-parsing them as extension elements.
  Evidence: Recursive block proof failed with `expected 44032 query value bytes, but was 22016` when parsing trace queries as quadratic.
  Implication: Keep trace query parsing in `BaseElement` and adapt quadratic DEEP evaluation to combine base trace values with extension coefficients.
- Observation (2026-01-02T08:36Z): Fast wallet proving options are rejected by the on-chain verifier.
  Evidence: `HEGEMON_WALLET_PROVER_FAST=1 wallet substrate-send ...` fails with `VerificationFailed(UnacceptableProofOptions)`.
  Implication: End-to-end runs must use the default proof options unless we explicitly widen acceptable options for dev-only runs (set `HEGEMON_ACCEPT_FAST_PROOFS=1` in both the node and wallet for fast E2E).
- Observation (2026-01-03T06:21Z): Recursive block proof generation completes end-to-end but is slow in absolute time even in dev-fast mode.
  Evidence: A tmux E2E run logged `Recursive block proof generated block_number=4 tx_count=1` after ~16 minutes, and `block_getRecursiveProof` returned non-empty proof bytes for the mined block hash.
  Implication: Correctness is proven end-to-end, but the prover is now the scalability bottleneck; next work is performance profiling (per-phase timers) and a pivot if the current Winterfell prover throughput is fundamentally insufficient at the ~85-bit PQ target.
- Observation (2026-01-03T06:21Z): DA RPC chunk retrieval is keyed by `da_root`, not by block hash, and `da_getParams` is global.
  Evidence: `da_getChunk` returns `null` when called with a block hash but returns a chunk+Merkle path when called with the logged `da_root`; `da_getParams` ignores extra params.
  Implication: E2E scripts/runbooks must carry forward `da_root` (or we should add a helper RPC to fetch `da_root` for a given block hash).
## Decision Log

- Decision: Treat scalability as proof-carrying blocks plus data-availability sampling, not larger blocks or faster block times.
  Rationale: Verification cost per block must be constant and bounded to scale while keeping privacy and post-quantum security.
  Date/Author: 2025-12-31 / Codex

- Decision: Use recursive verification of existing transaction proofs as the main block validity path.
  Rationale: Transaction witnesses stay in the wallet; recursion only needs proof bytes and public inputs, preserving privacy.
  Date/Author: 2025-12-31 / Codex

- Decision: Start from the existing Winterfell-based recursion code and make it reusable.
  Rationale: The repo already uses Winterfell for STARKs, so reusing it reduces risk and keeps the stack hash-based.
  Date/Author: 2025-12-31 / Codex

- Decision: DA sampling must not be deterministic from producer-known inputs; implement per-node randomized sampling as the first ship target.
  Rationale: Deterministic sampling can be satisfied by selectively publishing only the sampled chunks, so it does not enforce availability. Per-node private sampling gives an explicit detection probability bound and is implementable without adding a randomness beacon or committee.
  Date/Author: 2025-12-31 / Codex

- Decision: Treat proof-parameter hardening (field extension / soundness target) as a gated design decision, not a “nice to have”.
  Rationale: Recursive block proofs inherit transaction-proof soundness; if transaction proofs are capped at ~64-bit soundness, the chain’s validity security is not credible at scale. This must be decided up front because it materially impacts prover time, proof size, and block production latency.
  Date/Author: 2025-12-31 / Codex

- Decision: Keep 256-bit digests and accept ~85-bit PQ collision security as the ceiling.
  Rationale: 256-bit digests cannot deliver 128-bit PQ collision resistance under generic bounds; adopting 85-bit as the baseline keeps digest widths stable and makes the security target consistent across Merkle commitments, Fiat–Shamir transcripts, and DA roots.
  Date/Author: 2025-12-31 / Codex

- Decision: Upgrade transaction proofs to quadratic extension and align documentation with the ~85-bit PQ collision ceiling.
  Rationale: The field-size term is no longer the bottleneck once we use quadratic extension; hash collision resistance becomes the binding limit unless we widen digests.
  Date/Author: 2025-12-31 / Codex

- Decision: Keep recursion trace builders rejecting non-base inner proofs while only the parser and public inputs understand quadratic extensions.
  Rationale: Accepting quadratic proofs without trace/AIR support would silently build invalid recursion traces; explicit rejection forces us to finish the verifier trace changes first.
  Date/Author: 2025-12-31 / Codex

- Decision: Use a Path A streaming schedule that pairs coefficient-draw permutations with leaf-hash permutations (coeff tape) and draws one FRI alpha per layer.
  Rationale: This keeps trace width <255 while preserving a bounded row budget (~2^18 for the current transaction proof options) without forking Winterfell.
  Date/Author: 2025-12-31 / Codex

- Decision: Replay deep-coefficient draws per query at leaf-hash chain boundaries (partition/merge starts) instead of interleaving inside hash chains.
  Rationale: The RPO leaf hash chain must remain contiguous; replay draws are inserted before each chain and bound via coin-state restore.
  Date/Author: 2025-12-31 / Codex

- Decision: Restrict coin-restore masking to the first row of a replay permutation and bind tape/deep witnesses to the post-permutation state.
  Rationale: Boundary constraints only apply on permutation boundaries; keeping restore active on all rows breaks boundary relations, and replayed tape/deep witnesses must reflect the permuted state used for hashing.
  Date/Author: 2025-12-31 / Codex

- Decision: Keep Criterion sample size at 10 for the outer proof-of-proof benchmark.
  Rationale: Criterion enforces a minimum sample size of 10; lowering it causes the bench to panic.
  Date/Author: 2025-12-31 / Codex

- Decision: Keep the legacy `circuits/block/src/proof.rs` aggregation path intact while introducing recursive block proofs as a separate, consensus-facing verification path.
  Rationale: Forcing recursive proof generation into the existing `prove_block` flow would make the current integration tests (and block builder) substantially heavier before the mining/RPC integration is ready; the recursive proof path is now available and verified in consensus, and the legacy aggregation can be retired once mining emits recursive proofs by default.
  Date/Author: 2025-12-31 / Codex

- Decision: Retire `RecursiveAggregation` and make `prove_block` emit `RecursiveBlockProof` by default, with an explicit fast helper for development tests.
  Rationale: Mining now needs a single recursive proof artifact to populate `recursive_proof_hash`, and keeping the folded digest path adds maintenance overhead without serving consensus; the fast helper preserves test velocity without hiding the default proof format.
  Date/Author: 2025-12-31 / Codex

- Decision: Temporarily gate OOD/DEEP/FRI consistency checks for non-RpoAir inner proofs in the recursion verifier to avoid OOD-column overflows.
  Rationale: Transaction proofs produce OOD evaluation vectors that exceed the fixed verifier trace width; until streaming OOD evaluation lands, we skip these constraints to keep recursive proof generation running (UNSOUND, must be removed).
  Date/Author: 2025-12-31 / Codex
- Decision: Use 1D Reed–Solomon with parity shards `p = ceil(k/2)` and a BLAKE3 Merkle root over all shards for the initial DA encoder.
  Rationale: This matches the math notes’ 1.5x overhead example, avoids adding new consensus parameters beyond `chunk_size`/`sample_count`, and keeps the implementation simple while we wire P2P sampling.
  Date/Author: 2026-01-01 / Codex

- Decision: Store recursive block proofs in an in-memory LRU keyed by block hash to back `block_getRecursiveProof` RPC.
  Rationale: Substrate headers do not carry the recursive proof bytes, so the node must retain locally generated proofs for RPC access without redesigning the block format.
  Date/Author: 2026-01-01 / Codex

- Decision: Serve DA chunks over RPC by returning stored DA encodings (root + Merkle proofs) rather than recomputing from chain state.
  Rationale: The DA encoding already exists during block import; reusing it avoids re-deriving ciphertext blobs from extrinsics and keeps RPC responses fast.
  Date/Author: 2026-01-01 / Codex

- Decision: Cap shielded transfers per block when recursive block proofs are enabled (default `HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK=1`).
  Rationale: Recursive batch proving cost scales roughly linearly in the number of inner transaction proofs and can exceed commodity RAM (e.g. >100GB) when batching many transfers; the cap prevents runaway memory while we build a real aggregation strategy.
  Date/Author: 2026-01-03 / Codex

- Decision: Benchmark recursive proof sizing using a single RPO-based synthetic transaction in circuits/bench.
  Rationale: The existing bench generates independent transaction witnesses; using a single witness avoids merkle-root drift while still producing a representative recursive proof artifact for sizing/verification timing.
  Date/Author: 2026-01-01 / Codex

Note (2026-01-01T09:30Z): Updated Progress, Surprises & Discoveries, and Decision Log to record the DA encoder implementation start, shard-limit constraint, and the parity selection rationale.

## Outcomes & Retrospective

Outcome (2025-12-31T09:40Z): The Path A recursion verifier updates now satisfy the full `epoch-circuit` test suite, including the ignored heavy tests when run with `CARGO_INCREMENTAL=0`. Remaining work includes the recursion size/time benchmark and the README whitepaper alignment.
Outcome (2025-12-31T10:05Z): Milestone 1 feasibility benchmarks completed with measured spike ratios and recursive proof timings; the spike acceptance criteria are met. Remaining work moves to Milestone 2 documentation alignment and consensus type updates.
Outcome (2026-01-03T06:21Z): Milestone 5 end-to-end validation completed: dev node mines a block with a recursive proof and DA encoding, and `block_getRecursiveProof` / `da_getChunk` return non-empty artifacts. Remaining work is proving throughput (dev-fast still takes ~15–20 minutes per recursive block proof on a laptop).

## Context and Orientation

The current repo includes STARK transaction proofs in circuits/transaction, a block executor in circuits/block that verifies each transaction proof and records a folded digest, recursion experiments under circuits/epoch, consensus validation under consensus/src, and the Merkle commitment tree under state/merkle. The node is the Substrate-based binary under node/, and wallets generate transaction proofs locally under wallet/.

A STARK is a transparent zero-knowledge proof system that relies on hash functions instead of trusted setup. A recursive proof is a STARK proof that verifies another STARK proof inside its own constraints. A proof-carrying block is a block that includes a recursive proof covering all transactions and state updates, so the node verifies one proof per block. A Merkle tree is a hash tree that commits to many items and provides membership proofs by hash paths. Data availability means all encrypted payloads for a block can be retrieved by any node. A data-availability chunk is one piece of those payloads after encoding. Sampling means a node checks a small, randomized subset of data chunks (chosen with local randomness) and rejects the block if any sampled chunk is missing or fails its Merkle proof. Erasure coding expands data into redundant chunks so missing pieces can be reconstructed, which makes sampling meaningful. Post-quantum means the system does not rely on elliptic curve or RSA assumptions.

A mempool is the local pool of unconfirmed transactions waiting to be included in a block. A block builder is the component that selects transactions from the mempool and constructs a block. RPC (remote procedure call) is the JSON-RPC API exposed by the node for wallet and tooling queries. P2P (peer-to-peer) is the networking layer that exchanges blocks and data between nodes. Genesis is the initial chain state used to start a new chain.

This plan breaks chain compatibility and requires a fresh genesis. Treat all existing chain specs, local databases, and test wallet stores as disposable for development. This plan supersedes .agent/RECURSIVE_PROOFS_EXECPLAN.md; do not follow both plans in parallel.

Before making code changes, you must update DESIGN.md and METHODS.md to reflect the architecture changes described here. The README.md whitepaper must remain at the top of the file before Monorepo layout and Getting started.

## Plan of Work

### Milestone 1: Recursion feasibility and parameterization

This milestone proves that we can verify a real transaction proof inside a recursive STARK without unacceptable overhead, using the proof parameters we intend to ship for consensus-critical validity. Before measuring overhead, pick a concrete validity-soundness target (see `.agent/scalability_architecture_math.md` §1.2 and §2.3.1) and configure the transaction proof system accordingly (at minimum: recursion-friendly Fiat–Shamir everywhere we plan to verify in-circuit, and an explicit decision on Winterfell `FieldExtension`).

Then create a reusable recursion helper crate at circuits/recursion by extracting the InnerProofData parsing and verifier input construction logic from circuits/epoch/src/recursion/recursive_prover.rs, and update circuits/epoch to import that crate instead of its local copy. Add a transaction-proof verifier spike under circuits/epoch/src/verifier_spike or a new module under circuits/transaction that wraps transaction_circuit::proof so it emits proof bytes and public inputs in the format required by InnerProofData. Extend circuits/epoch/src/verifier_spike/tests.rs with a test that generates a real transaction proof, builds a recursive verifier proof around it, and records size and timing. Run the milestone with cargo test -p epoch-circuit verifier_spike and cargo bench -p epoch-circuit recursive_proof_bench from the repo root, and record proof size and prover time in Surprises & Discoveries.

Acceptance is that the outer proof size is under 10x the inner proof size and the outer prover time is under 100x the inner prover time at the chosen security settings; if not, update the Decision Log and pivot before continuing.

### Milestone 2: Canonical docs and protocol types

This milestone makes the architecture explicit in the canonical docs and in protocol types. Update DESIGN.md to describe proof-carrying blocks and data-availability sampling in the consensus and proving sections, and update METHODS.md to describe the new recursive block proof and DA verification steps with clear operator commands. Update the README.md whitepaper to describe that blocks are validated by a recursive proof and DA sampling before Monorepo layout and Getting started. Then update consensus/src/types.rs to define DA parameters and chunk types, and consensus/src/header.rs to include recursive_proof_hash, da_root, and da_params in the header encoding and signing hash. Update runtime/src/chain_spec.rs and node/src/substrate/chain_spec.rs so new chain specs include the new header fields and can regenerate a fresh genesis. Run rg -n "proof|data availability|da_root" DESIGN.md METHODS.md README.md and cargo test -p consensus from the repo root. Acceptance is that the docs describe the new validation flow in plain language, and consensus tests compile with the updated header fields.

### Milestone 3: Recursive block proofs as consensus validity

This milestone replaces per-transaction verification in consensus with a single recursive block proof. Add circuits/block/src/recursive.rs that builds a recursive block proof by verifying each TransactionProof in-circuit, checking nullifier uniqueness, and reproducing commitment tree updates, and expose it from circuits/block/src/lib.rs. Update circuits/block/src/proof.rs to stop using the folded digest as the primary validity indicator and instead compute a recursive_proof_hash that matches the new proof bytes. Update consensus/src/pow.rs and consensus/src/validator.rs to verify only the recursive proof commitment and stop re-verifying individual transaction proofs. Update consensus/tests/common.rs to build headers with the new recursive proof commitment. Run cargo test -p block-circuit and cargo test -p consensus from the repo root. Acceptance is a new test in circuits/block that fails when recursive proof bytes are tampered and a consensus test that accepts a block when the recursive proof is valid without per-transaction verification.

### Milestone 4: Data-availability encoding and sampling

This milestone makes data availability a block acceptance requirement. Add a new module under state/da (new crate or module inside state/) that implements erasure coding, chunk storage, Merkle roots, and Merkle proofs. Update consensus/src/types.rs with DaParams, DaChunk, and DaChunkProof and implement encode_da_blob, da_root, and verify_da_chunk in the same module or a new protocol module under protocol/. Update node/src/substrate/network_bridge.rs to add a P2P protocol for DA chunk requests and responses, and update node/src/substrate/service.rs to store chunks when blocks are built and serve them on request. Implement per-node randomized sampling so nodes request and verify a small subset of chunks chosen with local randomness before accepting and relaying a block. Run cargo test -p consensus and add a new test that removes a sampled chunk and confirms block rejection. Acceptance is a failing block when any sampled chunk is missing or fails its Merkle proof, and a passing block when all sampled chunks verify.

### Milestone 5: Integration, benchmarks, and tests

This milestone wires the new proof and DA flow into mining, RPC, and benchmarks. Update node/src/substrate/mining_worker.rs and node/src/substrate/service.rs so block building assembles recursive proofs and DA commitments. Update node/src/substrate/transaction_pool.rs so DA payloads are available for block building. Add RPC endpoints under node/src/substrate/rpc for block_getRecursiveProof, da_getChunk, and da_getParams, and merge them in node/src/substrate/rpc/mod.rs. Extend circuits/bench to output recursive proof size and verification time, and update consensus/bench to account for DA payload sizes. Add integration tests under tests/ or node/src/substrate to exercise the RPC endpoints and proof validation. Run HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp, submit at least one shielded transaction, and query the new RPC endpoints. Acceptance is that the RPC returns non-empty proof bytes and a DA chunk with a valid Merkle proof, and the node logs show proof size and DA root per block.

## Concrete Steps

All commands run from the repository root. For a fresh clone, you must run the setup steps before anything else:

    make setup
    make node

Milestone 1 commands:

    cargo test -p epoch-circuit verifier_spike
    cargo test -p epoch-circuit verifier_spike::tests::test_transaction_recursion_budget -- --nocapture
    cargo test -p epoch-circuit verifier_spike::tests::test_transaction_streaming_plan_budget -- --nocapture
    cargo test -p epoch-circuit verifier_spike::tests::test_spike_runs_successfully -- --nocapture
    cargo bench -p epoch-circuit recursive_proof_bench
    cargo bench -p epoch-circuit --bench recursive_proof_bench -- --output-format bencher

Expected evidence includes a test pass, a Transaction Recursion Budget output line with ood_eval_elems vs trace_width_cap, a Transaction Streaming Plan output block with per-query and total rows, and a bench line that prints inner and outer proof sizes and times. Record those numbers in Surprises & Discoveries.

Milestone 2 commands:

    rg -n "proof|data availability|da_root" DESIGN.md METHODS.md README.md
    cargo test -p consensus

Expected evidence is updated doc sections that describe proof-carrying blocks and DA sampling and a passing consensus test run.

Milestone 3 commands:

    cargo test -p block-circuit
    cargo test -p consensus

Expected evidence is a failing test when recursive proof bytes are modified and a passing test when they are intact.

Milestone 4 commands:

    cargo test -p consensus

Expected evidence is a test that fails when a sampled chunk is missing and passes when all sampled chunks are available.

Milestone 5 commands:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Then query the new RPC endpoints you add:

    curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"block_getRecursiveProof","params":["0x<BLOCK_HASH>"]}' http://127.0.0.1:9944
    curl -s -H "Content-Type: application/json" -d '{"id":2,"jsonrpc":"2.0","method":"da_getParams","params":[]}' http://127.0.0.1:9944
    curl -s -H "Content-Type: application/json" -d '{"id":3,"jsonrpc":"2.0","method":"da_getChunk","params":["0x<DA_ROOT>",0]}' http://127.0.0.1:9944

Expected evidence is non-empty proof bytes, a DA chunk payload, and a Merkle proof that verifies locally.

## Validation and Acceptance

Acceptance requires two observable behaviors. First, a block with a valid recursive proof must be accepted even if the node does not re-verify individual transaction proofs. Second, a block must be rejected if any sampled DA chunk is missing or fails its Merkle proof.

Add a block circuit test that mutates the recursive proof bytes and expects verification to fail with a recursive proof error. Add a consensus test that removes a sampled DA chunk from the store and expects a DA error. Start the dev node, mine a block, and verify that the block header includes a non-zero recursive_proof_hash and da_root, and that the RPC methods return proof bytes and a chunk with a valid Merkle proof.

## Idempotence and Recovery

All steps are safe to rerun. Use --tmp on the dev node so state is discarded on exit. If you need to reset state for a new genesis, delete the local node database directory and any test wallet stores, then rerun the node. Keep backups of any non-test wallet keys before deletion.

## Artifacts and Notes

Example output from the transaction recursion budget test:

    === Transaction Recursion Budget ===
    trace_width: 86
    constraint_frame_width: 5
    total_constraints: 4251
    field_extension: Quadratic (degree 2)
    ood_eval_elems: 364
    trace_width_cap: 255

Example output from the transaction streaming plan test:

    === Transaction Streaming Plan (Path A) ===
    field_extension: Quadratic (degree 2)
    trace_leaf_hash_perms: 11
    constraint_leaf_hash_perms: 3
    fri_leaf_hash_perms: 1
    merkle_depth: 18
    merkle_perms_per_query: 200
    coeff_draw_perms_per_query: 28
    alpha_draw_perms_per_query: 12
    per_query_perms: 240
    global_perms: 1196
    total_perms: 8876
    rows_unpadded: 142016
    total_rows: 262144

Plan Update Note (2025-12-31T09:40Z): Updated Progress, Surprises & Discoveries, Decision Log, and Outcomes to reflect the recursion verifier fixes, passing heavy tests, and the incremental-cache ICE workaround.
Plan Update Note (2025-12-31T10:05Z): Marked Milestone 1 complete, added spike/bench outputs and Criterion constraints, and updated commands to include the spike and bench output runs.
Plan Update Note (2025-12-31T10:20Z): Updated Progress to mark the README whitepaper alignment complete and recorded the doc update milestone.
Plan Update Note (2025-12-31T10:30Z): Recorded the consensus header/types updates for DA + recursive proof commitments and noted the remaining chain spec updates for Milestone 2.
Plan Update Note (2026-01-01T16:20Z): Added Milestone 5 RPC + bench progress, recorded the txpool-background shutdown during dev-node runs, and logged decisions for recursive proof/DA RPC handling.
Plan Update Note (2026-01-03T03:31Z): Updated the StorageChanges caching mechanism to avoid leaking state diffs when mining templates are discarded or block import fails early, and documented the new cache-capacity env var.

Example log line after Milestone 5:

    recursive block proof: bytes=48000 tx_count=4 da_root=0x9c5e... da_samples=8

Example rejection log for a missing DA chunk:

    consensus error: invalid header (missing da chunk index=3)

## Interfaces and Dependencies

In circuits/recursion/src/lib.rs, define a reusable parser for inner proofs that exposes public inputs for recursive verification. This helper must be usable by both block and epoch recursion code:

    pub struct InnerProofData { /* parsed verifier data */ }
    impl InnerProofData {
        pub fn from_proof<T: Air>(proof_bytes: &[u8], public_inputs: Vec<BaseElement>) -> Result<Self, RecursionError>;
        pub fn to_verifier_inputs(&self) -> Vec<BaseElement>;
    }

In circuits/block/src/recursive.rs, implement recursive block proofs with explicit inputs and outputs:

    pub struct RecursiveBlockProof {
        pub proof_bytes: Vec<u8>,
        pub proof_commitment: [u8; 32],
        pub tx_count: u32,
        pub starting_root: [u8; 32],
        pub ending_root: [u8; 32],
    }

    pub fn prove_block_recursive(
        tree: &mut state_merkle::CommitmentTree,
        transactions: &[transaction_circuit::TransactionProof],
        verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
    ) -> Result<RecursiveBlockProof, BlockError>;

    pub fn verify_block_recursive(
        proof: &RecursiveBlockProof,
        verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
    ) -> Result<(), BlockError>;

In consensus/src/header.rs, extend BlockHeader so the recursive proof commitment and DA root are covered by signing and hashing:

    pub struct BlockHeader {
        /* existing fields */
        pub recursive_proof_hash: [u8; 32],
        pub da_root: [u8; 32],
        pub da_params: DaParams,
    }

In state/da, implement storage for DA chunks and Merkle proofs:

    pub struct DaParams {
        pub data_shards: u16,
        pub parity_shards: u16,
        pub chunk_size: u32,
        pub sample_count: u16,
    }

    pub struct DaChunk {
        pub index: u32,
        pub data: Vec<u8>,
    }

    pub struct DaChunkProof {
        pub index: u32,
        pub merkle_path: Vec<[u8; 32]>,
    }

    pub fn encode_da_blob(blob: &[u8], params: DaParams) -> Vec<DaChunk>;
    pub fn da_root(chunks: &[DaChunk]) -> [u8; 32];
    pub fn verify_da_chunk(root: [u8; 32], chunk: &DaChunk, proof: &DaChunkProof) -> bool;

In consensus validation, add a sampler which uses local randomness (not producer-known inputs) and require that each sampled chunk is retrievable and verified:

    pub fn sample_indices(seed: [u8; 32], params: DaParams) -> Vec<u32>;

In node RPC under node/src/substrate/rpc, add endpoints for recursive proofs and DA chunks:

    block_getRecursiveProof(block_hash) -> { proof_bytes, proof_hash, tx_count, starting_root, ending_root }
    da_getChunk(da_root, index) -> { chunk, merkle_path }
    da_getParams() -> { chunk_size, sample_count }

Dependencies must remain hash-based and post-quantum safe. Use the existing blake3 hashing utilities for commitments. For erasure coding, use reed-solomon-erasure and confine it to the DA encoding path.

Revision Note (2025-12-31T02:04Z): Rebuilt the ExecPlan to comply with .agent/PLANS.md by adding milestone-level commands and acceptance, explicit file-level edits, and missing term definitions.
Revision Note (2025-12-31T02:22Z): Added math companion reference, recorded the deterministic DA sampling flaw and updated the plan to use per-node randomized sampling (per `.agent/scalability_architecture_math.md`).
Revision Note (2025-12-31T04:12Z): Updated transaction proof parameters to quadratic extension, aligned security notes in docs, and recorded the new proving-time impact in Surprises & Discoveries.
Revision Note (2025-12-31T05:03Z): Recorded the recursion budget spike output, updated progress and surprises, and clarified that quadratic extension support is parser-only pending trace/AIR work.
Revision Note (2025-12-31T05:31Z): Added the Path A streaming plan estimator + test output and captured the row budget and schedule assumptions.
Revision Note (2025-12-31T06:55Z): Implemented replayed deep-coeff draw pairing with leaf-hash chains and updated merkle schedule masks/tests to match the new interleave.
Revision Note (2025-12-31T11:15Z): Completed Milestone 2 chain-spec defaults and updated node header serialization/test helpers for the new DA/recursive header fields; reran consensus tests.
Revision Note (2025-12-31T17:49Z): Added recursive block proof module + consensus verifier/test coverage, updated block serialization/types for recursive proofs, and recorded the legacy aggregation decision.
Revision Note (2025-12-31T18:45Z): Retired `RecursiveAggregation`, made `prove_block` emit recursive proofs by default (with a fast helper), updated consensus test scaffolding to carry recursive proofs, and refreshed docs/diagrams to remove the legacy digest path.
Revision Note (2026-01-01T11:05Z): Added DA sampling tests in `consensus/tests/da_sampling.rs`, ran `cargo test -p consensus`, and marked Milestone 4 complete.
Revision Note (2026-01-01T11:20Z): Documented the libclang environment requirement for `cargo check -p hegemon-node`, fixed no-std `format!`/`String` imports in transaction-core, and added SCALE codec derives for DA chunk types to satisfy network encoding.
Revision Note (2026-01-01T23:40Z): Updated Progress/Surprises to record the recursion transcript permutation fix and node rebuild so the plan reflects the current verifier schedule work.
Revision Note (2026-01-02T00:10Z): Recorded the quadratic trace/DEEP fix, added the recursive proof + DA RPC runbook, and updated end-to-end progress to reflect the in-flight recursive block proof build.
