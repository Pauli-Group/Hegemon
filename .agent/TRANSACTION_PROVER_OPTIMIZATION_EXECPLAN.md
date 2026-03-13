# Transaction Prover Optimization: Thin Inner Proofs Before Backend Migration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan sits under `.agent/WORLD_COMMERCE_SCALABILITY_EXECPLAN.md` and `.agent/PROOF_AGGREGATION_P3_EXECPLAN.md`. Those plans explain why Hegemon needs aggregation, prover markets, and compact block validity. This document is narrower: it optimizes the current Goldilocks/Plonky3 transaction proof so every later aggregation and proving-market step starts from a materially thinner inner proof. The rule for this plan is simple: remove local implementation waste first, then decide whether a backend swap is still worth the complexity.

## Purpose / Big Picture

Make Hegemon’s existing transaction STARK materially smaller and faster without lowering the post-quantum security bar, changing wallet semantics, or changing note/nullifier encodings. After this work, a developer can run the existing transaction and benchmark commands and observe all of the following on the same machine:

1. Release transaction proofs are smaller than the current baseline.
2. Release proving throughput is higher than the current baseline.
3. The current slot-copy batch prover is no longer presented as the world-commerce scaling path, and the benchmark output makes that distinction explicit.
4. The same end-to-end transaction proof roundtrip still passes with production FRI parameters and 48-byte digests.

The success condition is observable, not rhetorical. A novice should be able to check out the repo, run the commands in this plan, and watch the before/after metrics change while the proof system continues to verify the same statements.

## Progress

- [x] (2026-03-13T06:55Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `.agent/WORLD_COMMERCE_SCALABILITY_EXECPLAN.md`, and `.agent/PROOF_AGGREGATION_P3_EXECPLAN.md` to anchor the optimization plan in the current architecture.
- [x] (2026-03-13T06:55Z) Audited the transaction prover, AIR, batch prover, verifier, and benchmark entrypoints in `circuits/transaction-core/src/p3_air.rs`, `circuits/transaction/src/p3_prover.rs`, `circuits/transaction-core/src/p3_verifier.rs`, `circuits/batch/src/p3_prover.rs`, `circuits/aggregation/src/lib.rs`, `circuits/bench/src/main.rs`, and `wallet/src/prover.rs`.
- [x] (2026-03-13T06:55Z) Captured a local release baseline for the current transaction prover and current slot-copy batch prover using `circuits-bench` and `prove_verify_roundtrip_p3`.
- [x] (2026-03-13T06:55Z) Drafted this ExecPlan with milestone sequencing that starts with low-risk structural wins before any backend experiment.
- [x] (2026-03-13T09:35Z) Added benchmark guardrails: `circuits-bench` now reports per-transaction prove/verify costs and the current transaction trace shape, and `scripts/compare-transaction-bench.sh` prints the single-tx vs slot-batch summary in one command.
- [x] (2026-03-13T09:35Z) Prototyped a real preprocessed-schedule transaction prover/verifier path, benchmarked it, and rejected it after it regressed proof size and throughput.
- [x] (2026-03-13T09:35Z) Landed the first production optimization that actually helps: one shared 61-bit scratch region now serves note, fee, value-balance, and issuance range checks on distinct rows, cutting the transaction trace width from `412` to `231`.
- [x] (2026-03-13T09:35Z) Re-ran release validation after the shared-range change: transaction roundtrip passes, `security-tests` `stark_soundness` passes under a libclang-aware environment, and the release smoke benchmark shows lower proof size plus higher tx/s.
- [x] (2026-03-13T09:35Z) Realigned the batch-circuit crate docs so the slot-copy batch path is described as a bounded utility path rather than the public throughput lane.
- [ ] Replace the remaining raw bounded-value design with a full radix-limb version chosen by a small in-repo prototype, then adopt the winning design in the production AIR.
- [ ] Collapse additional columns that are constant across the whole trace and compact the fixed-slot MASP bookkeeping so the AIR stops paying permanent width for values that matter only on a few rows.
- [ ] Run the full validation matrix, capture the post-change metrics, and update `DESIGN.md` and `METHODS.md` if any implementation detail or benchmark claim changes.
- [ ] Optional only after the earlier milestones are green: run a small isolated backend spike for a Circle/M31-style prover on the slimmed transaction shape and record whether a migration is still justified.

## Surprises & Discoveries

- Observation: the current transaction prover still copies fixed schedule columns into the main trace and calls plain `prove(...)`, even though the batch, settlement, and block circuits already use `setup_preprocessed` / `prove_with_preprocessed`.
  Evidence: `circuits/transaction/src/p3_prover.rs` builds the schedule into every row of the main trace and calls `p3_uni_stark::prove`, while `circuits/batch/src/p3_prover.rs` and `circuits/block/src/p3_commitment_prover.rs` use preprocessed setup APIs.

- Observation: the transaction AIR currently spends 244 columns on raw bit-decomposition for bounded values before accounting for any business logic.
  Evidence: `VALUE_RANGE_BITS = 61` in `circuits/transaction-core/src/p3_air.rs`, and four separate scratch regions (`note`, `fee`, `value balance`, `stablecoin issuance`) consume `61 * 4 = 244` columns.

- Observation: the fixed schedule alone contributes 40 columns to the main trace width, and the total trace width is currently 412 columns.
  Evidence: `PREPROCESSED_WIDTH` ends at `PREP_CM_AUTH1_ROW + 1`, which is 40 columns, and `TRACE_WIDTH` includes those schedule columns inside the main trace in `circuits/transaction-core/src/p3_air.rs`.

- Observation: the trace is padded aggressively. The real computation uses 4,576 rows, but the prover rounds up to an 8,192-row minimum trace.
  Evidence: `TOTAL_USED_CYCLES` and `MIN_TRACE_LENGTH` in `circuits/transaction-core/src/p3_air.rs` document the `4576 -> 8192` jump.

- Observation: the current slot-copy batch path is slower per transaction than single-proof proving on the same machine, so it is not a credible throughput story.
  Evidence: `cargo run -p circuits-bench --release -- --smoke --json` reported `tx_proof_bytes_avg = 376753`, total `prove_ns = 9785213292` for 4 single proofs, and `transactions_per_second = 0.407166...`; `cargo run -p circuits-bench --release -- --smoke --json --batch-size 4 --batch-only` reported total `batch_prove_ns = 66461427498` across 16 transactions and `batch_transactions_per_second = 0.240521...`.

- Observation: the current transaction PCS is not paying for hiding randomization, so the performance gap to Stwo-like systems is not explained by “we turned on extra zero-knowledge costs.”
  Evidence: Plonky3’s `TwoAdicFriPcs` sets `const ZK: bool = false` in `fri/src/two_adic_pcs.rs`, and Hegemon’s transaction config uses `TwoAdicFriPcs` in `circuits/transaction-core/src/p3_config.rs`.

- Observation: the current production-parameter roundtrip is stable and gives a clean local sanity check for proof size after every structural change.
  Evidence: `cargo test -p transaction-circuit prove_verify_roundtrip_p3 --release --features plonky3-e2e -- --nocapture` prints `p3 tx proof: bytes=376812, degree_bits=13, log_chunks=3, log_blowup=4, num_queries=32` and passes.

- Observation: moving the transaction schedule into a real preprocessed trace was a net regression on the current Plonky3 transaction proof path.
  Evidence: the preprocessed prototype raised the roundtrip proof size to about `407776` bytes and the release smoke benchmark to `tx_proof_bytes_avg = 407677`, `tx_prove_ns_per_tx = 4234366010`, and `transactions_per_second = 0.235538...`, all worse than baseline.

- Observation: reusing one 61-bit scratch region for fee, value-balance, and issuance checks delivered a real win while preserving the existing proof statement and security target.
  Evidence: after landing the shared-range change, the release smoke benchmark reports `tx_trace_width = 231`, `tx_proof_bytes_avg = 370065`, `tx_prove_ns_per_tx = 1457625750`, and `transactions_per_second = 0.682101...`; the transaction roundtrip prints `p3 tx proof: bytes=370124`; `cargo test -p security-tests --test stark_soundness --release -- --nocapture` still reports `estimated_soundness_bits=128` and passes.

## Decision Log

- Decision: optimize the current Goldilocks/Plonky3 transaction proof before spending engineering time on a backend migration.
  Rationale: the audited code shows large, local, removable inefficiencies: bit-decomposed range checks, copied fixed schedule columns, full-trace constant values, and a misleading batch path. A backend migration without first removing those costs would produce a noisy comparison and would risk porting a bloated AIR to a faster backend.
  Date/Author: 2026-03-13 / Codex

- Decision: keep the security posture fixed during the implementation milestones in this plan.
  Rationale: the point of this plan is to remove waste, not to buy speed by changing security assumptions. The implementation milestones therefore keep 48-byte digests, production FRI defaults (`log_blowup = 4`, `num_queries = 32`), current note/nullifier encodings, and current public-input semantics.
  Date/Author: 2026-03-13 / Codex

- Decision: treat the current slot-copy batch prover as a wallet/convenience path, not as the throughput path for public claims about scaling.
  Rationale: the code in `circuits/batch/src/p3_prover.rs` literally builds single transaction traces and copies them into batch slots. That is acceptable for additive utility and some verification amortization experiments, but it should not be described as the “Stwo competitor” path.
  Date/Author: 2026-03-13 / Codex

- Decision: prototype the bounded-value redesign before freezing the final radix layout.
  Rationale: the design documents want radix embeddings and lookup-style checks, but a naive 16-bit lookup table does not obviously fit inside the current 8,192-row transaction trace. This plan therefore includes a small in-repo prototype step to choose the concrete limb and lookup strategy before the production AIR is rewritten.
  Date/Author: 2026-03-13 / Codex

- Decision: do not include protocol-breaking Merkle redesign, note-format changes, or a mandatory backend swap in the required milestones of this plan.
  Rationale: those are larger, higher-risk changes. The first execution pass should land structural wins that preserve the current protocol surface so the result can be benchmarked and deployed without a fresh proving statement.
  Date/Author: 2026-03-13 / Codex

- Decision: reject the transaction preprocessed-schedule path for the current Plonky3 transaction prover unless a different opening strategy becomes available.
  Rationale: the measured result was unambiguous: narrower main trace, but larger proofs and slower proving because the extra preprocessed commitment/opening overhead outweighed the width reduction on this circuit shape.
  Date/Author: 2026-03-13 / Codex

- Decision: keep the first landed optimization entirely inside the existing proof statement by reusing the same 61-bit scratch region on distinct rows rather than changing note formats, Merkle formats, or FRI settings.
  Rationale: that change removed 183 witness columns without changing the public inputs or the soundness target, and it produced a measurable win immediately.
  Date/Author: 2026-03-13 / Codex

## Outcomes & Retrospective

2026-03-13 partial execution update: one draft milestone failed, and one landed optimization succeeded.

The failed idea was the transaction preprocessed-schedule path. It looked attractive in code review and failed in the benchmark. That is useful progress because it removes one of the most obvious but wrong answers from the search space.

The first landed win was the shared range-scratch change. It cut the transaction trace width from `412` to `231`, reduced release smoke proof size from about `376 KB` to about `370 KB`, and improved release smoke throughput from about `0.41 tx/s` to about `0.68 tx/s` on the same machine while the `stark_soundness` test still reported `128` estimated soundness bits. That is exactly the kind of change this plan is meant to deliver: smaller, faster, same security target.

## Context and Orientation

Hegemon’s current transaction proving path is spread across a small number of files.

`circuits/transaction-core/src/p3_air.rs` defines the actual arithmetic intermediate representation, abbreviated “AIR.” In this repository, AIR means “the row-by-row algebraic rules that the STARK prover and verifier both enforce.” This file defines the trace layout, constants such as `MIN_TRACE_LENGTH`, and the `TransactionAirP3` evaluator.

`circuits/transaction/src/p3_prover.rs` builds the witness trace and runs the Plonky3 prover. It is the place where note data, Merkle paths, nullifiers, ciphertext hashes, range checks, and stablecoin bindings are written into trace columns.

`circuits/transaction-core/src/p3_config.rs` defines the field, hash, and FRI configuration. Today that means Goldilocks as the base field, Poseidon2 as the in-field sponge, 48-byte digests (`6` field elements), and production FRI defaults `log_blowup = 4`, `num_queries = 32`.

`circuits/transaction-core/src/p3_verifier.rs` verifies transaction proofs and infers the FRI profile from proof shape at runtime. This is the verifier-side mirror of the prover configuration.

`circuits/batch/src/p3_prover.rs` implements a different path: a batch circuit that copies multiple single-transaction traces into slots inside a larger trace. In this document, “slot-copy batch prover” refers to that path, not the recursion/aggregation path. This distinction matters because the batch circuit is currently slower per transaction than the single-transaction proof path on the local benchmark.

`circuits/aggregation/src/lib.rs` is the actual recursion lane that the broader scaling plans depend on. That crate proves that many already-generated transaction proofs were valid. This plan improves the cost of those inner proofs so the recursion lane has a better starting point.

`circuits/bench/src/main.rs` is the observable benchmark harness. It already reports proof sizes and total timing, but it does not yet expose enough per-transaction detail to make optimization review easy.

`wallet/src/prover.rs` is the user-facing prover wrapper. It normalizes prover configuration, calls the transaction proof APIs, and is the right place to optionally trigger cache prewarming if later milestones add reusable setup artifacts.

Three terms of art matter here:

“Preprocessed trace” means fixed columns known ahead of time, such as schedule flags and round constants. In Plonky3, these columns can be committed separately and reused instead of being duplicated inside every witness trace. Hegemon already uses this pattern in other circuits.

“Radix limbs” means representing a bounded integer as a small number of larger base-`2^k` chunks instead of 61 separate bits. For example, a 61-bit value can be represented as four 16-bit chunks with a smaller top bound on the last chunk. This plan uses the word “radix” in that concrete sense.

“Throughput lane” means the path we expect operators to use when they care about many transactions, not a convenience path kept around for tests or wallet-side batching. In Hegemon, the intended throughput lane is recursion/aggregation, not the current slot-copy batch circuit.

The original baseline, measured on this machine on 2026-03-13 before any changes in this file were implemented, was:

- Single transaction smoke benchmark: about `376 KB` proofs, about `0.407 tx/s`, and about `2.45 s` of proving time per transaction when derived from the total `prove_ns` across four iterations.
- Batch-only smoke benchmark at `batch_size = 4`: about `0.240 tx/s`, which is worse than the single-transaction path on the same machine.
- Production-parameter transaction roundtrip: `bytes=376812`, `degree_bits=13`, `log_chunks=3`, `log_blowup=4`, `num_queries=32`.

The current post-change state after the first landed optimization is:

- Single transaction smoke benchmark: about `370 KB` proofs, about `0.682 tx/s`, and about `1.46 s` of proving time per transaction.
- Batch-only smoke benchmark at `batch_size = 4`: about `0.337 tx/s`, still worse than the single-transaction path, but materially better than the original batch baseline.
- Production-parameter transaction roundtrip: `bytes=370124`, `degree_bits=13`, `log_chunks=3`, `log_blowup=4`, `num_queries=32`.

This plan keeps the protocol statement fixed. It does not change the `2-in/2-out` join-split shape, the `32`-level Merkle path, the 48-byte encoding, or the current production FRI target. The work is entirely about how efficiently the existing statement is represented and proven.

## Plan of Work

### Milestone 1: Make the baseline impossible to hand-wave away

The first milestone adds enough benchmark visibility that every later optimization can be judged by running one command, not by reading code and guessing. Extend `circuits/bench/src/main.rs` so the emitted `BenchReport` includes per-transaction fields in addition to totals. The required fields are `tx_prove_ns_per_tx`, `tx_verify_ns_per_tx`, `batch_prove_ns_per_tx`, `batch_verify_ns_per_tx`, `tx_trace_rows`, `tx_trace_width`, and `tx_schedule_width`. The values should be derived inside the benchmark harness itself, not left for readers to compute from totals.

Add one small comparison helper under `scripts/` that runs the existing single-proof and batch-only smoke benchmarks and prints the core metrics side by side. Keep it shell-based and idempotent. It should not edit the repository; it should only write benchmark JSON to `/tmp` and print a concise summary. This helper is not the main feature, but it will keep the rest of the plan honest.

At the end of this milestone, a novice should be able to run the benchmark commands in one directory and get a crisp report of “here is what one transaction costs right now” and “here is what the current slot-copy batch path costs right now.”

### Milestone 2: Evaluate preprocessed schedules, but keep them only if the benchmark wins

This milestone was attempted on 2026-03-13 and rejected for the current transaction circuit. The transaction AIR was converted to a real preprocessed schedule, the prover and verifier were wired through `setup_preprocessed`, and the path was benchmarked. The result was worse: proof size and proving throughput both regressed. The current rule is therefore explicit: do not re-land this change unless a different proof-shape strategy is available and the release benchmark shows a real win.

This section remains in the plan because the negative result matters. A future contributor should not repeat the same experiment and then rediscover the same regression.

### Milestone 3: Replace raw bit columns with a radix-limb bounded-value design

The third milestone attacks the largest width offender: the 244 columns currently reserved for raw bounded-value bits. Because the concrete lookup strategy is not trivial under the current `8192`-row trace size, this milestone starts with a local prototype, then lands the chosen production path.

The prototype belongs in a small, isolated module or ignored benchmark under `circuits/transaction-core/` or `circuits/plonky3-spike/`. It must compare at least two concrete bounded-value layouts against the current bit-decomposition baseline: one direct radix-limb design intended for production, and one fallback if the first design would force an unwanted trace-length increase. The prototype’s job is not to prove final performance on all hardware. Its job is to answer the narrow question “which bounded-value layout reduces width without raising the minimum trace length or weakening the bound semantics?”

After the choice is made, implement the production layout in a new helper module `circuits/transaction-core/src/range.rs`. That module must expose deterministic decomposition and recomposition helpers for the chosen limb scheme. The transaction AIR should then replace the `COL_RANGE_*_BITS_START` regions with the chosen limb columns and the minimum accumulator columns needed to enforce correctness. The transaction prover in `circuits/transaction/src/p3_prover.rs` must populate those limbs instead of 61 individual bits.

This milestone is successful when `TRACE_WIDTH` is materially lower than the current baseline, the production roundtrip still passes, and the bounded-value semantics are still proven by unit tests that check decomposition, recomposition, and out-of-range rejection.

### Milestone 4: Stop paying full-trace width for values that matter on a few rows

The fourth milestone removes columns that are currently duplicated across the entire trace even though the AIR only needs them at specific rows or across short row windows. The biggest candidates are the secret-key words, rho words, derived authorization material, duplicated stablecoin payload columns, and some of the slot bookkeeping written into every row by the current trace builder.

In `circuits/transaction/src/p3_prover.rs`, rewrite the trace builder so these values are written only where the AIR actually consumes them. If a value needs to persist across a row interval, add a small carry or running-state gadget rather than storing the same field element in all 8,192 rows. In `circuits/transaction-core/src/p3_air.rs`, update the constraints accordingly.

This milestone also compacts the fixed-slot MASP bookkeeping. The current AIR pays 16 one-hot selector columns for four notes and four slots. Because the statement still has a fixed `2-in/2-out` shape, the required implementation in this milestone is a compact slot-index encoding. Replace the `COL_SEL_*` family with one compact slot-index field per note and derive equality masks inside the AIR instead of storing one-hot selectors for every note/slot pair. A future generalized permutation argument is allowed, but it is not required for this milestone. The requirement is to stop paying 16 dedicated selector columns for a four-slot fixed circuit.

This milestone is complete when the trace width drops again, the MASP balance tests still pass, and the AIR no longer stores long-lived constant data or one-hot selector matrices just to preserve convenience in the witness builder.

### Milestone 5: Tell the truth about the throughput path

The fifth milestone is mostly about behavior and operator-facing clarity. The repository should stop implying that the current slot-copy batch prover is the path to public throughput. In `circuits/batch/src/lib.rs`, `circuits/bench/src/main.rs`, and any nearby docs that describe performance, clarify that the batch circuit is a bounded utility path for wallet-side batching, consolidation, and some verification amortization experiments, while recursion/aggregation remains the throughput lane for public scaling.

Update the benchmark harness so single-proof, slot-copy batch, and aggregation figures can be reported without conflating them. The key behavioral acceptance is that a novice operator reading the benchmark output can tell which path is expected to scale and which path is only a convenience layer. If existing benchmark prose or README claims are no longer defensible after the current measurements, update those documents in the same commit.

If any part of `node/src/substrate/service.rs` or the prover coordinator still treats the slot-copy batch path as the expected scaling story, correct that language and surface. This milestone does not remove the batch circuit. It removes the false impression that the batch circuit is already the answer.

### Milestone 6: Optional backend spike after the inner proof is slimmed

This milestone is optional and must not block the earlier required work. Once the earlier milestones are green, create an isolated spike crate under `spikes/` that ports the slimmed transaction shape, or a faithfully reduced representative fragment of it, to a Circle/M31-style backend. The spike must preserve the same security story in the writeup: if the spike uses a different field, digest, or transcript shape, the benchmark note must say exactly how the comparison is or is not apples-to-apples with Hegemon’s production path.

The only reason to do this spike is to answer a narrower and better question than the one we can answer today: “after removing obvious local waste, how much additional win remains available from a backend migration?” If the answer is “still a lot,” that becomes a separate migration plan. If the answer is “the current backend is now good enough for the next stage,” that should be recorded explicitly.

## Concrete Steps

All commands below are run from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

On a fresh clone, begin with:

    make setup
    make node

On macOS, direct `cargo` commands that touch `librocksdb-sys` may fail with `Library not loaded: @rpath/libclang.dylib`. If that happens, either run through the existing `make` targets or export `LIBCLANG_PATH` and `DYLD_LIBRARY_PATH` using one of the paths described in `AGENTS.md` and the repository setup notes before retrying.

Capture the current baseline before editing anything:

    cargo run -p circuits-bench --release -- --smoke --json > /tmp/hegemon-tx-baseline.json
    cargo run -p circuits-bench --release -- --smoke --json --batch-size 4 --batch-only > /tmp/hegemon-batch4-baseline.json
    cargo test -p transaction-circuit prove_verify_roundtrip_p3 --release --features plonky3-e2e -- --nocapture

The current baseline on this machine produced output shaped like:

    {
      "tx_proof_bytes_avg": 376753,
      "tx_log_blowup_used": 4,
      "fri_num_queries": 32,
      "transactions_per_second": 0.40716613409857155
    }

    {
      "batch_size": 4,
      "batch_prove_ns": 66461427498,
      "batch_transactions_per_second": 0.24052119786911796
    }

    p3 tx proof: bytes=376812, degree_bits=13, log_chunks=3, log_blowup=4, num_queries=32

After Milestone 1 lands, rerun the same benchmark commands and make sure the JSON now exposes the per-transaction and trace-shape fields described in the milestone.

After the currently landed shared-range optimization, the same commands now produce outputs shaped like:

    {
      "tx_proof_bytes_avg": 370065,
      "tx_trace_width": 231,
      "tx_schedule_width": 42,
      "tx_prove_ns_per_tx": 1457625750,
      "transactions_per_second": 0.6821019758097844
    }

    {
      "batch_size": 4,
      "batch_prove_ns_per_tx": 2964712380,
      "batch_transactions_per_second": 0.33694921226690633
    }

    p3 tx proof: bytes=370124, degree_bits=13, log_chunks=3, log_blowup=4, num_queries=32

After any future Milestone 2-style preprocessed-schedule experiment, run:

    cargo test -p transaction-circuit prove_verify_roundtrip_p3 --release --features plonky3-e2e -- --nocapture
    cargo run -p circuits-bench --release -- --smoke --json > /tmp/hegemon-tx-after-preprocessed.json

After Milestones 3 and 4, run:

    cargo test -p transaction-circuit --release --features plonky3-e2e -- --nocapture
    cargo run -p circuits-bench --release -- --smoke --json > /tmp/hegemon-tx-after-range-and-width.json
    cargo run -p circuits-bench --release -- --smoke --json --batch-size 4 --batch-only > /tmp/hegemon-batch4-after-range-and-width.json

After Milestone 5, rerun the benchmark commands and then re-read the updated benchmark text and nearby docs to confirm the throughput lane is described honestly.

If the optional backend spike is attempted, the spike must have one command that both builds and prints a small JSON report. Keep that command inside the spike crate so it remains isolated from the production workspace.

## Validation and Acceptance

The required validation is relative and observable on the same machine. The person executing this plan must keep the baseline JSON files from the first run and compare later runs against them.

Milestones 1 through 5 are accepted only if all of the following are true:

1. The production-parameter roundtrip test still passes:

       cargo test -p transaction-circuit prove_verify_roundtrip_p3 --release --features plonky3-e2e -- --nocapture

2. The single-transaction smoke benchmark still runs and reports the same security posture (`tx_log_blowup_used = 4`, `fri_num_queries = 32`, 48-byte digests), while the post-change `tx_proof_bytes_avg` is lower than the baseline from `/tmp/hegemon-tx-baseline.json`.

3. The post-change per-transaction proving cost from the benchmark harness is lower than the baseline from `/tmp/hegemon-tx-baseline.json`.

4. The benchmark harness reports the current trace shape directly, and the post-change transaction trace width is lower than the current `412`-column baseline.

5. The slot-copy batch path is no longer represented as the public scaling story in the benchmark output or nearby performance text.

6. The repository still passes the targeted security-parameter test when the environment can build it:

       cargo test -p security-tests --test stark_soundness --release -- --nocapture

   If this command fails on macOS because `libclang.dylib` is not visible, fix the environment first and rerun. Do not silently skip the test.

The optional backend spike is accepted only if it prints a benchmark report and a written note records whether the comparison was apples-to-apples with the production security posture.

## Idempotence and Recovery

Every benchmark command in this plan is safe to rerun. The benchmark helper should only write to `/tmp` or another explicit scratch path and should never mutate tracked files.

If a milestone temporarily breaks proof verification, recover by reverting only the in-progress milestone edits and rerunning the production-parameter roundtrip test before attempting the milestone again. Do not continue stacking optimizations on top of a failing proof system.

If direct `cargo` commands on macOS fail because `libclang.dylib` cannot be found, recover by using the `make` targets or by exporting the documented `LIBCLANG_PATH` and `DYLD_LIBRARY_PATH` values, then rerun the same command. Do not workaround this by weakening the test matrix.

The benchmark comparisons must always be made on the same machine and with the same command lines. Cross-machine comparison is not an acceptable substitute because proving time is hardware-sensitive.

## Artifacts and Notes

These excerpts capture the old baseline, the rejected preprocessed experiment, and the current post-change state:

    cargo run -p circuits-bench --release -- --smoke --json
      tx_proof_bytes_avg = 376753
      prove_ns = 9785213292
      verify_ns = 37818459
      transactions_per_second = 0.40716613409857155

    cargo run -p circuits-bench --release -- --smoke --json --batch-size 4 --batch-only
      batch_size = 4
      batch_prove_ns = 66461427498
      batch_verify_ns = 59657291
      batch_transactions_per_second = 0.24052119786911796

    cargo test -p transaction-circuit prove_verify_roundtrip_p3 --release --features plonky3-e2e -- --nocapture
      p3 tx proof: bytes=376812, degree_bits=13, log_chunks=3, log_blowup=4, num_queries=32

    preprocessed-schedule experiment (rejected)
      tx_proof_bytes_avg = 407677
      tx_prove_ns_per_tx = 4234366010
      transactions_per_second = 0.23553845588893577

    current post-change state
      tx_proof_bytes_avg = 370065
      tx_trace_width = 231
      tx_prove_ns_per_tx = 1457625750
      transactions_per_second = 0.6821019758097844

      batch_prove_ns_per_tx = 2964712380
      batch_transactions_per_second = 0.33694921226690633

      p3 tx proof: bytes=370124, degree_bits=13, log_chunks=3, log_blowup=4, num_queries=32

      cargo test -p security-tests --test stark_soundness --release -- --nocapture
        FRI params: log_blowup=4, num_queries=32, estimated_soundness_bits=128
        test result: ok. 4 passed; 0 failed

One command that currently fails without the correct macOS `libclang` environment is:

    cargo test -p security-tests --test stark_soundness --release -- --nocapture
      error: failed to run custom build command for `librocksdb-sys`
      dyld: Library not loaded: @rpath/libclang.dylib

That failure is environmental, not a justification to weaken validation.

## Interfaces and Dependencies

The implementation work in this plan must leave the following concrete interfaces in place.

In `circuits/transaction-core/src/range.rs`, define:

    pub const RANGE_LIMB_BITS: usize;
    pub const RANGE_LIMB_COUNT: usize;
    pub fn decompose_bounded_value(value: u64) -> [u16; RANGE_LIMB_COUNT];
    pub fn recompose_bounded_value(limbs: &[u16; RANGE_LIMB_COUNT]) -> u64;

This module is the single source of truth for the production bounded-value limb layout.

In `circuits/transaction-core/src/p3_air.rs`, `TransactionAirP3` must keep the current shared-range-scratch optimization: one 61-bit scratch region is reused across note, fee, value-balance, and issuance rows instead of allocating separate fee/value-balance/issuance bit regions again.

In `circuits/transaction/src/p3_prover.rs`, define:

    pub fn prewarm_transaction_prover_cache_p3(
        params: TransactionProofParams,
    ) -> Result<(), TransactionCircuitError>;

This function may be a no-op if the cache is already warm, but it must exist so benchmarks, tests, and wallet construction can prewarm the preprocessed prover path explicitly.

In `circuits/transaction-core/src/p3_verifier.rs`, define:

    pub fn prewarm_transaction_verifier_cache_p3(
        fri: InferredFriProfileP3,
    ) -> Result<(), TransactionVerifyErrorP3>;

This gives the verifier side the same explicit warmup surface as the prover side.

In `circuits/bench/src/main.rs`, extend `BenchReport` so it contains:

    tx_prove_ns_per_tx: u128
    tx_verify_ns_per_tx: u128
    batch_prove_ns_per_tx: u128
    batch_verify_ns_per_tx: u128
    tx_trace_rows: usize
    tx_trace_width: usize
    tx_schedule_width: usize

These fields are required because the rest of this plan depends on a single command exposing the exact shape and cost of the current transaction proof.

In `circuits/transaction-core/src/p3_air.rs`, replace the one-hot selector family with compact slot-index fields. The end state must not contain the `COL_SEL_IN0_SLOT0` through `COL_SEL_OUT1_SLOT3` family; it must instead encode slot choice compactly and derive equality masks in the AIR.

Revision note: updated on 2026-03-13 after implementing the first optimization slice. The preprocessed-schedule experiment was measured and rejected, the shared range-scratch optimization was measured and kept, and the benchmark/security sections were updated so the plan reflects the real current state rather than the draft assumptions.
