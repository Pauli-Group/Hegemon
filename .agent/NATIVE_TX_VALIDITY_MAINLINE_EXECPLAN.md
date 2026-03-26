# Promote NativeTxValidity To Hegemon's Canonical Experimental Proof Target

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon already has a native proof relation, `NativeTxValidityRelation`, plus a proof-ready `TxLeaf -> ReceiptRoot` topology. What is still muddy is product intent. The repository still exposes bridge lanes and synthetic lanes beside the native lane, which makes it too easy for future work to optimize the wrong thing. After this change, a contributor will be able to run the experimental benchmark surface and see one canonical question answered: how does the native tx-validity lane scale versus `InlineTx`? Bridge lanes will remain only as diagnostics and regressions, not as planning targets.

The user-visible effect is disciplined research. Running the benchmark binary or reading the docs should immediately point a contributor at the native path, the native byte costs, the native import bottleneck, and the explicit `InlineTx` fallback rule. This is how the experimental branch stops behaving like a pile of spikes and starts behaving like one coherent migration lane.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, `DESIGN.md`, `METHODS.md`, `consensus/src/proof.rs`, `circuits/superneo-hegemon/src/lib.rs`, and `circuits/superneo-bench/src/main.rs` to anchor this plan in the current branch state.
- [x] (2026-03-26 02:02Z) Confirmed that `NativeTxValidityRelation` exists, the benchmark default already points at `native_tx_leaf_receipt_root`, and the import bottleneck still comes from per-leaf verification in `ReceiptRootVerifier`.
- [x] (2026-03-26 02:02Z) Authored this ExecPlan as a dedicated living document for making the native lane the only decision-grade experimental surface.
- [x] (2026-03-26 02:23Z) Froze the canonical native benchmark vocabulary in `superneo-bench`: `native_tx_leaf_receipt_root` is the only default relation, JSON notes label it as the canonical experimental lane, and every bridge or relation-only lane now requires `--allow-diagnostic-relation`.
- [x] (2026-03-26 02:23Z) Removed bridge lanes from the default benchmark/report surface while keeping them available for explicit regression checks behind the diagnostic opt-in flag.
- [x] (2026-03-26 02:23Z) Added explicit native-lane observability in `node/src/substrate/service.rs`, including stable fallback reasons for unavailable native artifacts, native verifier-profile mismatch, and native artifact validation failure.
- [x] (2026-03-26 02:23Z) Updated `DESIGN.md`, `METHODS.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, and this ExecPlan, then ran `cargo test -p superneo-bench`, `cargo test -p hegemon-node receipt_root -- --nocapture`, and `cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx`.

## Surprises & Discoveries

- Observation: most of the architectural work is already done. The missing piece is not a new proof object but a stricter product boundary around which experimental path matters.
  Evidence: the canonical native relation already exists in [superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L320), the benchmark default already points at the native topology in [superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs#L46), and the docs already describe `native_tx_leaf_receipt_root` as the only planning-grade lane in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L895).

- Observation: the current confusion comes from surfaces, not primitives. The bridge lanes are valuable for comparison but harmful when they stay visible as peers of the native lane.
  Evidence: `RelationChoice` still lists `TxLeafReceiptRoot` and `VerifiedTxReceipt` beside `NativeTxValidity` and `NativeTxLeafReceiptRoot` in [superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs#L34).

- Observation: the node already prefers native leaves and falls back to `InlineTx`; however, that behavior is not yet treated as the single experimental truth across reports and docs.
  Evidence: the current architecture note says the receipt-root lane is native-only and falls back to `InlineTx` when native leaves are unavailable in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L895).

- Observation: soft documentation was not enough to protect the benchmark surface. Contributors still needed a hard opt-in boundary before they would reliably stay on the native lane.
  Evidence: `cargo test -p superneo-bench` now includes a CLI test that rejects `verified_tx_receipt` unless `--allow-diagnostic-relation` is passed, while the default parse path stays on `native_tx_leaf_receipt_root`.

- Observation: caching `InlineTx` fallback outcomes on the `receipt_root` selector would poison native preference for that candidate set.
  Evidence: `node/src/substrate/service.rs` now uses `should_store_prove_ahead_aggregation_outcome(...)` so the prove-ahead cache stores successful native `ReceiptRoot` outcomes but deliberately skips `InlineTx` fallback outcomes for that selector.

## Decision Log

- Decision: keep the bridge lanes in-tree but demote them to explicit diagnostic and regression surfaces.
  Rationale: they still provide valuable comparisons and backward sanity checks, but they should no longer influence planning or default operator behavior.
  Date/Author: 2026-03-26 / Codex

- Decision: treat `NativeTxValidityRelation` plus native `TxLeaf -> ReceiptRoot` as one coherent experimental lane, not as separate unrelated spikes.
  Rationale: the global goal is to replace proof transport with native proof-ready leaves and a folded root. Splitting the relation and topology into separate narratives obscures that.
  Date/Author: 2026-03-26 / Codex

- Decision: preserve `InlineTx` as the shipping fallback and surface fallback reasons prominently.
  Rationale: the experimental lane is not yet production-safe, and contributors need to see exactly why the node chose the shipping path when native artifacts are unavailable or invalid.
  Date/Author: 2026-03-26 / Codex

- Decision: gate bridge and relation-only benchmark lanes behind an explicit CLI flag instead of relying on documentation or help text alone.
  Rationale: the point of this ExecPlan is to stop accidental benchmarking of non-canonical surfaces. A hard CLI gate is cheap and unambiguous.
  Date/Author: 2026-03-26 / Codex

- Decision: cache successful native `ReceiptRoot` outcomes, but never cache `InlineTx` fallback outcomes for that selector.
  Rationale: later attempts must be able to adopt native artifacts as soon as they are available; a transient miss cannot be allowed to pin the candidate set to `InlineTx`.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

This plan is now implemented. The repository did not gain any new proof primitive, but it did gain the missing product boundary: `superneo-bench` defaults to the canonical native lane and forces explicit opt-in for every diagnostic lane; node authoring emits stable native-lane selection and fallback reasons; and the design/method docs now describe `native_tx_leaf_receipt_root` as the only planning-grade experimental surface. The release benchmark still shows the expected native shape after these surface changes: `5481/5564/5606/5627/5637/5642/5645/5646 B/tx` for `k=1/2/4/8/16/32/64/128`, with verification cost remaining the dominant bottleneck on the current experimental import path.

## Context and Orientation

`NativeTxValidityRelation` is the relation in `circuits/superneo-hegemon/src/lib.rs` that consumes a `TransactionWitness` directly and derives the native public statement for the experimental folding backend. A “relation” here means the exact algebraic statement and witness encoding that the backend proves. A “bridge lane” means any path that starts from the existing `TransactionProof` family and wraps or folds it afterward, rather than proving transaction validity natively.

Today, the benchmark CLI in `circuits/superneo-bench/src/main.rs` still exposes several surfaces: `NativeTxValidity`, `NativeTxLeafReceiptRoot`, `TxLeafReceiptRoot`, and `VerifiedTxReceipt`. The difference after this plan is behavioral: `NativeTxLeafReceiptRoot` is the only default, and every other surface now requires `--allow-diagnostic-relation`. The proof-neutral consensus boundary already exists under `consensus/src/proof.rs`, where `TxLeaf` and `ReceiptRoot` are separate artifact kinds routed through a verifier registry. The current native import bottleneck remains linear per leaf because `ReceiptRootVerifier` still resolves and checks every tx artifact before verifying the root.

This plan does not create new cryptography. It standardizes which experimental lane the repository treats as canonical, where fallback is allowed, and how native-vs-bridge results are presented. That is necessary before deeper work on prover optimization or accumulation because otherwise measurements and logs will keep mixing incomparable paths.

## Plan of Work

First, tighten the benchmark surface in `circuits/superneo-bench/src/main.rs`. Keep all relation implementations callable, but change the public contract so the default path, the help text, and any summary output all explicitly label bridge lanes as diagnostic. Introduce a separate flag or naming convention for non-canonical lanes so a novice cannot accidentally benchmark the bridge and think it is the target architecture.

Next, tighten the docs in `METHODS.md`, `DESIGN.md`, and the SuperNeo ExecPlan. Document `NativeTxValidityRelation` as the canonical proving target and `native_tx_leaf_receipt_root` as the canonical topology benchmark. For every remaining mention of `verified_tx_receipt` or `tx_leaf_receipt_root`, explain in one sentence that the lane is retained only for regression or topology comparison and is not planning-grade.

Then, expose fallback semantics explicitly in the node path. In `node/src/substrate/service.rs` and any nearby logging or metrics modules, add structured log lines or counters that say whether authoring selected native `TxLeaf` artifacts or fell back to `InlineTx`, and why. The reasons should at minimum distinguish “native artifacts unavailable,” “native verifier-profile mismatch,” and “native artifact validation failed.” The purpose is not just debugging; it makes native adoption visible to operators and benchmark harnesses.

Finally, make tests and command-line validation reflect the new truth. Add one focused benchmark or smoke test that fails if the default experimental benchmark relation stops being `native_tx_leaf_receipt_root`. Add one node-side test or log assertion that proves the service prefers native artifacts when they exist and falls back only when necessary.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, implement this plan in the following order.

1. Edit `circuits/superneo-bench/src/main.rs` so the default relation, CLI help, and result notes all treat `native_tx_leaf_receipt_root` as canonical and label bridge lanes as diagnostic.

2. Edit `METHODS.md`, `DESIGN.md`, and `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md` so the native relation and topology are described as the only planning-grade experimental lane.

3. Edit `node/src/substrate/service.rs` and any relevant metrics/logging helpers to emit explicit native-lane selection and fallback reasons.

4. Add focused tests:

       cargo test -p superneo-bench
       cargo test -p hegemon-node receipt_root -- --nocapture

5. Re-run the canonical benchmark command:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

The expected human-visible result is that the benchmark output and docs point only at the native lane as decision-grade, while bridge lanes require an explicit opt-in flag and node logs report native-lane fallback reasons with stable labels.

## Validation and Acceptance

Acceptance is behavioral.

Running the benchmark CLI with no relation override must benchmark the native topology and print a note that identifies it as the canonical experimental lane. Reading `METHODS.md` and `DESIGN.md` must make it obvious that bridge lanes are retained only for diagnostics. Running a node in the experimental path and producing or importing a block candidate must produce a log or metric that clearly states whether the node used native `TxLeaf` artifacts or fell back to `InlineTx`.

At the automated level, `cargo test -p superneo-bench` must pass with a test that locks the default benchmark relation, and `cargo test -p hegemon-node receipt_root -- --nocapture` must pass with coverage for native preference and fallback behavior.

## Idempotence and Recovery

This plan is additive and safe. Re-running the benchmark or node tests is harmless. The fallback path remains `InlineTx`, so failure to materialize native artifacts does not break block production on this experimental branch. If a logging or benchmark-surface change goes wrong, revert only the surface-selection edits; do not remove the underlying native artifacts or verifier profiles.

## Artifacts and Notes

The canonical benchmark command after this plan lands is:

    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

The expected output remains JSON, but the `relation` and `note` fields must make it explicit that this is the primary experimental surface. The current release run emits notes such as:

    "note": "canonical experimental lane: native witness -> native tx-leaf -> receipt-root topology; native tx-leaf artifacts=165344B root_artifact=15194B"

Bridge lanes remain available only under explicit relation choices plus `--allow-diagnostic-relation`.

## Interfaces and Dependencies

The following public or user-visible interfaces must exist after implementation.

In `circuits/superneo-bench/src/main.rs`, keep `RelationChoice`, but add a clear canonical-vs-diagnostic distinction in help text and result notes. If a helper is added, prefer a name like:

    fn is_canonical_relation(choice: RelationChoice) -> bool

In `node/src/substrate/service.rs`, add a structured native-lane selection record. If this becomes a type, prefer:

    pub struct NativeArtifactSelectionReport {
        pub used_native_lane: bool,
        pub fallback_reason: Option<String>,
    }

Do not introduce any new proof artifact kinds in this plan. This is a surface and discipline plan, not a cryptography plan.

Revision note: this ExecPlan was created on 2026-03-26 to make `NativeTxValidityRelation` and the native `TxLeaf -> ReceiptRoot` topology the only decision-grade experimental surface on the SuperNeo branch. The repository already contains the relation, topology, and benchmarks; what is missing is a strict product boundary around them.

Revision note (2026-03-26, later): implementation is now complete. `superneo-bench` hard-gates non-canonical lanes behind `--allow-diagnostic-relation`, node authoring emits explicit native-lane selection reports with fallback reasons, successful native receipt-root outcomes are cacheable while `InlineTx` fallbacks are not, and the docs plus focused validation commands were refreshed against the current release benchmark output.
