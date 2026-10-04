# Measure and bound independent RP05 proof verification

This ExecPlan is a living document. Keep Progress, Surprises & Discoveries,
Decision Log, and Outcomes & Retrospective current. The task starts from commit
`ce6d5d75` on branch `codex/rp05-verifier-parallel` in
`/private/tmp/hegemon-verifier-20261002`. The coordinator owns integration and
publication; this worker must not push, update production metadata, or modify
the primary checkout.

## Purpose / Big Picture

Blocks carry independent SMZA transaction proofs. Each proof can be checked
against the same immutable block parent/context before the node processes its
public state transition. This work measures whether a bounded group of worker
threads makes those checks faster, then changes the node only if the measurement
shows a useful gain. Roots, anchors, nullifier uniqueness, note commitments and
durable application remain checked in the original action order. A later proof
failure must not replace an earlier state failure.

## Progress

- [x] Read AGENTS.md, all .agent/PLANS.md, relevant DESIGN/METHODS sections and
  the existing proof/state connector; verify clean isolated baseline.
- [x] Locate the retained primary/independent SMZA artifacts and distinguish
  verifier CPU throughput from validity of a block containing those proofs.
- [x] Add a verifier-only benchmark with matching real proof inputs; initial
  development-verifier measurements are superseded (see below).
- [x] Implement a provisional four-leaf window with ordered state replay and
  a shared fixed worker pool; keep the change only after useful final scaling.
- [x] Close reviewed singleton/direct-call escape from the shared pool and add
  actual queued direct/window/nested-dispatch instrumentation regressions.
- [x] Add an ignored real native two-disjoint-spend acceptance/mining/restart/
  fresh-import regression; fixture generator source supplied by the fixture
  worker, generation and execution still pending.
- [x] Build and measure the normal cached-identity candidate verifier at
  ordinary serial and one/two/four workers; useful component scaling observed.
- [x] Focused retained-profile node suite: 27 passed, one genuine fixture test
  ignored; ordered replay/bounds and actual mixed direct/window/nested cap pass.
- [x] Verify ordered errors, state transitions, bounds and concurrent worker
  limits with regressions and a valid block of independent spends.
- [x] Runtime singleton fix independently source-reviewed; fixture/schema test
  contract independently reviewed, no functional mismatch found.
- [ ] Commit scoped branch and hand off for final integrated review/qualification.

## Surprises & Discoveries

The source SMZA frontend already calls its accepted-proof local audit as part of
verification. That required verifier work stays in the timed path; source-file
inventory, qualification manifest validation and the qualification runner's
additional audit/replay are excluded. The retained primary/independent pair
spends the same fixture notes, so alternating those proofs benchmarks CPU work
but cannot demonstrate an accepted multi-proof block.

The development-artifact verifier re-encodes and hashes the source program on
every invocation; the normal source candidate verifier caches that identity
check. Preliminary development timings therefore do not measure the native
hot path and are superseded. They were per 16-proof round, not per proof: five
rounds (80 checks) took approximately five seconds. Serial median/p95 were
0.983411/1.114166 seconds; one worker 0.964224/1.020247 seconds. Final normal
candidate measurements remain pending.

Review found that batching alone capped pool workers but singleton calls still
ran heavy verification on caller threads. All direct/singleton source calls
now enroll in the same pool. Same-pool recursion invokes the immutable inner
verifier directly to avoid queue-and-wait deadlock. A cfg(test)-only rejecting
sentinel probe exercises those actual paths without accepting synthetic proofs.

## Decision Log

2026-10-02: Add an optional batch method to the
crate-private exact-leaf verifier interface. Its default preserves existing
stateful/scripted verifiers. The production connector can produce indexed
per-leaf Result values concurrently; the state planner must consume them in
canonical order, interleaved with its existing state checks. A shared fixed-size
Rayon pool prevents each concurrent node call from creating another worker
group. Any change to this design requires source inspection and coordinator
agreement before implementation.

2026-10-02 correction: The prototype is written but remains conditional on
normal-source measurements and acceptance tests. Use a process-shared FIFO
pool with at most four workers and four queued leaf jobs per caller window;
do not create per-call pools or queue an entire block. Existing peer/local/
template admission reservations remain outside pool jobs, which acquire no
outer permit or lock. These reservations still bound admitted callers, not
reserved pool threads. FIFO injection and waiting between windows allow other
already queued callers to be considered before later peer windows; no strict
scheduler fairness guarantee is claimed. On one CPU or pool initialization
failure, the legacy sequential-per-caller fallback remains; that fallback is
explicitly not a process-wide four-proof concurrency guarantee.

## Outcomes & Retrospective

Final cached-source component measurements (five 16-proof rounds per fresh
process) show median/p95 seconds: serial 0.847343/0.874542; one worker
0.838332/0.845993; two workers 0.445481/0.455038; four workers
0.244631/0.265782. Peak RSS bytes respectively 14,729,216 / 13,287,424 /
19,922,944 / 37,371,904. Four workers provide a 3.46x component median gain
versus serial on this host. No timed run overlapped a coordinated local
compiler/prover. Raw outputs, exact commands, hashes and scope are retained in
`.agent/RP05_BOUNDED_VERIFIER_MEASUREMENTS.json`.

The source candidate benchmark excludes node contextual decode/copy/FIFO
scheduling and ordered state application, and repeats same-spend proof inputs.
It therefore supports retaining the bounded prototype for final acceptance
tests, not complete block latency, valid multi-proof block or network throughput
claims. Required accepted-proof auditing remains included. Focused node tests
passed 27 with one ignored; genuine duplicate-nullifier/proof-mutation no-write
checks added afterward remain source-only until the next integration slot.
Genuine disjoint proof generation and independent readback passed (102.68s,
peak RSS 2,197,094,400 bytes; readback 0.80s). Final actual native accepted
two-proof block/restart/fresh-import and duplicate-nullifier/proof-mutation
no-write test passed 1/1 in 1.43s. All 31 final state tests passed. Broader V8
suite: 82 passed, two unrelated exceptions, seven ignored; historical obsolete
ciphertext fixture failure handed to coordinator, sandbox process-signal test
passed on approved escalation. Precise commands/exceptions/provenance timing
are retained in `RP05_BOUNDED_VERIFIER_VALIDATION.md`. Final integrated review,
broad node tests and regenerated source qualification belong to coordinator.
No production readiness is credited.

## Context and Orientation

`node/src/native/poseidon2_v8_state.rs::verify_attach` performs proof checks and
ordered state admission before producing an immutable reorganization plan.
`node/src/native/poseidon2_v8_verifier.rs` contextual-decodes exact native leaf
bytes and calls the source-owned proof verifier. Its connector contains only a
checked context and profile selection. `node/src/native/node_impl.rs` has the
RecordingPoseidon2V8Verifier wrapper, which records verified transitions for the
pending-action ordering planner. The worker owns changes to the first two
files and only the recording-wrapper section of node_impl.rs; the coordinator
must reconcile this boundary with the separate sync worker before edits.

The benchmark belongs in
`circuits/transaction/examples/rp05_verifier_bench.rs`; it uses the existing
`rp05-dev-artifacts` feature and reads exact retained `native-leaf.bin` files.
The source-bound retained pair is under
`/private/tmp/rp05-ci-20261001.223oOy/.agent/artifacts/smallwood-poseidon2-v8-smza/rp05-qualification-lanes/overnight-wallet-memory-lint-final/pair`.
Load/decode/fingerprint inputs and build the thread pool before timing. Time
only repeated source-owned verifier calls. Print proof hashes, job count,
workers, per-round wall times and the explicit duplicate-nullifier scope.

## Plan of Work

First create an additive benchmark accepting worker count, jobs per round,
round count and native leaf paths. Compare fresh-process runs at one, two, four
workers on identical inputs, alongside ordinary serial calls. Warm each distinct proof once before
timing. Keep total memory under the coordinator's aggregate 16 GiB budget and
obtain the single compile lane before building.

The provisional optional batch interface and shared pool are implemented;
retain them only after useful measured scaling. Preserve indexed results rather than selecting the
first thread to fail. Keep all block/profile/count/byte/parent/lifetime checks
before launching workers. Continue root/anchor/nullifier/commitment checks and
application in their existing order. Wrappers must explicitly forward profile
and batch behavior; test verifiers retain their original sequential behavior.

Finally add regressions for ordered results, proof-versus-state failure
precedence, empty/singleton fallback and the fixed worker bound. Arrange with
the coordinator for a valid multi-proof block whose spends have disjoint
nullifiers at one parent. The historical same-note pair is useful only for
verifier scaling and rejection cases. Preserve exact carrier bytes through
accepted import and restart, then obtain independent patch review.

## Concrete Steps

Run from `/private/tmp/hegemon-verifier-20261002`. After the coordinator grants
the compile lane, use a compatible existing target rather than creating a
second large target tree:

    cargo build --locked --offline --profile retained-proof -p transaction-circuit --features rp05-dev-artifacts --example rp05_verifier_bench
    TARGET/retained-proof/examples/rp05_verifier_bench serial 16 5 PRIMARY_NATIVE_LEAF INDEPENDENT_NATIVE_LEAF
    TARGET/retained-proof/examples/rp05_verifier_bench 1 16 5 PRIMARY_NATIVE_LEAF INDEPENDENT_NATIVE_LEAF
    TARGET/retained-proof/examples/rp05_verifier_bench 2 16 5 PRIMARY_NATIVE_LEAF INDEPENDENT_NATIVE_LEAF
    TARGET/retained-proof/examples/rp05_verifier_bench 4 16 5 PRIMARY_NATIVE_LEAF INDEPENDENT_NATIVE_LEAF

Record exact commands, source hashes, outputs and host CPU/memory assumptions
under this checkout's `.agent` evidence directory. Exact node test commands
use the existing retained-proof profile/target, sequentially:

    cargo test --locked --offline --profile retained-proof -p hegemon-node --lib bounded_ -- --test-threads=1
    HEGEMON_TEST_DISJOINT_SMZA_DIRECTORY=GENERATED_DIRECTORY cargo test --locked --offline --profile retained-proof -p hegemon-node --features poseidon2-v8-retained-test-support --lib bounded_native_disjoint_smza_block_survives_restart_and_fresh_import -- --ignored --test-threads=1

The coordinator grants each build/prover run separately. The valid block test
checks descriptor hashes, source-bound ActionView gates, canonical action-id
order, actual relay admission/mining, exact persisted carrier bytes and typed
roots/nullifiers after source-reverified restart and fresh import. Its fixture
binding is explicitly test-only; the production gate remains closed.

## Validation and Acceptance

The benchmark must verify every submitted job and use identical job schedules
across worker counts. Runtime implementation is accepted only with useful
measured gain, matching accepted transitions, matching earliest canonical
proof/state errors, unchanged byte/count limits and no state writes by proof
workers. A real valid multi-proof block must be accepted and restore the same
typed roots and nullifiers after restart. Repeating the same retained spend is
explicitly excluded from that acceptance claim. Failed proofs and repeated
nullifiers must leave durable state unchanged.

## Idempotence and Recovery

Read retained artifacts without modifying them. Benchmark runs create no node
or wallet state. Keep runtime edits small and on the isolated branch; failed
experiments may remain unmerged without changing the published baseline.
Preserve unsuccessful measurement/test evidence. No deployment, mainnet
activation, seed changes, commits or pushes occur without coordinator review.

## Artifacts and Notes

Baseline `ce6d5d75`; roughly 80 GiB disk free at initial inspection. Runtime
prototype is source-ready, not accepted or production-authorized. The coordinator owns
the 10 percent usage floor and shared build/prover lane.

The fixture helper builds successfully after fixing two JSON macro repeated
array expressions. The coordinator regranted the lane for generation/final
acceptance; these are complete. No heavy sessions remain. Release the lane
immediately after scoped commit; broad integrated tests run once under the
coordinator. Preserve generation-time pins across later test assertions and
regenerate final integrated qualification rather than relabeling old receipts.

## Interfaces and Dependencies

Use the existing Rayon dependency for a shared FIFO thread pool. The
batch interface returns one Result per exact leaf, in
leaf order, and never creates a durable transition directly. The existing
state planner remains the only route to an accepted canonical plan, and its
same-transaction durable application remains unchanged. Do not change proof
geometry, primitive instantiation, production capability or release manifests.

Revision 2026-10-02: Updated after implementation, review and completed local
measurements/acceptance tests; distinguish superseded development timing and
branch evidence from final integrated qualification, and document shared-pool
reservation/fallback scope.
