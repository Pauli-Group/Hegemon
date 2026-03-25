# Stand Up a SuperNeo Experiment Stack

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Hegemon has an isolated experimental stack for SuperNeo-style post-proof folding that can be built and benchmarked without contaminating the shipping `InlineTx` path. A contributor can compile a Hegemon-owned relation into a local customizable constraint-system shape, pack its witness with pay-per-bit rules, run a direct in-repo folding backend, and compare the output against the existing `raw_active` benchmark numbers from `output/prover-recovery/2026-03-14/active-lanes/metrics.tsv`.

The milestone target has also moved. The stack is no longer just crate-boundary scaffolding: it now includes a ring-based Ajtai-style commitment approximation and a verified tx-proof receipt relation that re-checks real `TransactionProof`s before folding. The remaining gap is narrower and explicit: the backend still does not implement Neo/SuperNeo’s exact Module-SIS commitment analysis, decomposition reduction, or sum-check machinery.

The next milestone is architectural rather than cosmetic. The current `ReceiptRoot` path must stop depending on inline tx-proof bytes during import. This milestone therefore introduces a standalone tx-level leaf artifact, `TxLeaf`, and redefines the honest experiment as proof-ready tx leaf artifacts plus a folded root.

## Progress

- [x] (2026-03-20 18:22Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` before changing code.
- [x] (2026-03-20 18:24Z) Created branch `codex/superneo-experiment`.
- [x] (2026-03-20 18:27Z) Scaffolded new workspace crates under `circuits/superneo-*`.
- [x] (2026-03-20 18:58Z) Replaced cargo-new stubs with the Hegemon-owned CCS/core/ring/backend/hegemon/bench stack.
- [x] (2026-03-20 19:04Z) Added targeted tests and ran `cargo test -p superneo-ccs -p superneo-core -p superneo-ring -p superneo-backend-lattice -p superneo-hegemon`.
- [x] (2026-03-20 19:06Z) Ran `cargo run -p superneo-bench -- --relation tx_receipt --k 1,2 --compare-inline-tx` and captured JSON output against the frozen `raw_active` baseline.
- [x] (2026-03-20 19:08Z) Updated `DESIGN.md` and `METHODS.md` to record the experimental stack, its receipt-relation boundary, and the fact that the backend is still a mock.
- [x] (2026-03-21 01:41Z) Closed the first review gaps: parent fold metadata is now verified, security/transcript knobs are hashed into the mock backend, receipt statements bind a trace digest, signed packing fails fast, canonical byte accounting replaced `bincode` sizing, and odd-`k` / negative tests now exist.
- [x] (2026-03-25 04:54Z) Replaced the digest mock with a direct in-repo SuperNeo-style backend: pay-per-bit bit expansion, ring embedding, deterministic Ajtai-style matrix commitments over Goldilocks, and transcript-derived fold challenges.
- [x] (2026-03-25 05:12Z) Added `VerifiedTxProofReceiptRelation`, bound receipt leaves to real `TransactionProof` verification, and changed `ReceiptRoot` artifact construction/import to derive receipts from verified inline tx proofs instead of trusting standalone digest receipts.
- [x] (2026-03-25 05:25Z) Re-ran the experimental crate tests, the consensus `receipt_root_` tests, and the honest `verified_tx_receipt` benchmark after the verified-relation upgrade.
- [x] (2026-03-25 17:38Z) Added a standalone `TxLeaf` experimental tx artifact kind, taught `ReceiptRoot` to consume `TxLeaf` artifacts instead of inline tx proofs, and re-benchmarked that topology separately from the current inline-proof bridge.

## Surprises & Discoveries

- Observation: `cargo new` added most experimental crates to the workspace automatically, but skipped `circuits/superneo-core`, which produced the expected “current package believes it’s in a workspace when it’s not” warning.
  Evidence: `cargo new --lib circuits/superneo-core` emitted the workspace-membership warning during scaffolding.

- Observation: the repo’s current benchmark corpus already contains the exact local `InlineTx` baseline the experiment needs to beat, so the first benchmark binary can compare against a fixed artifact instead of re-running heavy proving work.
  Evidence: `output/prover-recovery/2026-03-14/active-lanes/metrics.tsv` includes `raw_active` rows with `bytes_per_tx`, `total_active_path_prove_ns`, and `total_active_path_verify_ns`.

- Observation: the benchmark harness runs quickly and produces the planned JSON comparison fields, but the resulting numbers are only interface-validation numbers because the backend is a digest mock, not a real folding prover.
  Evidence: `cargo run -p superneo-bench -- --relation tx_receipt --k 1,2 --compare-inline-tx` completed and emitted `bytes_per_tx`, `total_active_path_prove_ns`, `total_active_path_verify_ns`, `packed_witness_bits`, `shape_digest`, and the stored `inline_tx_baseline`.

- Observation: `bincode::serialized_size` was overstating artifact bytes because every fixed-width digest was being counted as a length-prefixed byte blob. The benchmark now uses explicit fixed-width byte accounting for the mock artifacts instead.
  Evidence: the benchmark output dropped from `250/419 B/tx` to `210/355 B/tx` for the `tx_receipt` mock path after switching away from `bincode` sizing.

- Observation: the public `latticefold` / `stark-rings` stack is still hard-blocked on unstable Rust features (`trait_alias`, `inherent_associated_types`) and therefore cannot be adopted directly inside Hegemon’s stable default workspace.
  Evidence: `cargo +1.91.1 check -p latticefold --example e2e` fails in `stark-rings-linalg` with `#![feature] may not be used on the stable release channel`.

- Observation: canonical tx-validity receipts are a good first target for a real folding backend because the verifier can deterministically reconstruct the packed witness from proof-derived receipt digests, which keeps the receipt-root artifact compact even when import still carries inline tx proofs for safety.
  Evidence: after the verified-relation rewrite, `cargo test -p superneo-hegemon` and `cargo test -p consensus receipt_root_ -- --nocapture` both pass while `ReceiptRoot` import re-verifies the ordered `TransactionProof`s instead of accepting receipt-only artifacts.

- Observation: the honest `verified_tx_receipt` benchmark changes the conclusion materially. In `--release`, the current SuperNeo-style receipt-root path is already a byte win against `raw_active`, and on the current local run it also beats the frozen low-`k` active-path timings.
  Evidence: `cargo run --release -p superneo-bench -- --relation verified_tx_receipt --k 1,2 --compare-inline-tx` reports `354390 B/tx`, `15056750 ns` prove, `14502958 ns` verify at `k=1`, and `354612 B/tx`, `26686750 ns` prove, `28173958 ns` verify at `k=2`, versus the stored `raw_active` baselines of `536098/70812417/18299167` and `456262/108371875/29954584`.

- Observation: the current `verified_tx_receipt` benchmark is still a bridge measurement, not the final topology. It starts from already-built `TransactionProof`s and times only the receipt-root stage, so it still assumes inline tx proof carriage outside the folded root.
  Evidence: `circuits/superneo-bench/src/main.rs` builds `proofs` with `sample_transaction_proof(...)` and then times `build_verified_tx_proof_receipt_root_artifact_bytes(&proofs)` directly, while `docs/SCALABILITY_PATH.md` defines the live `InlineTx` path as proof-ready txs plus the parent-bound commitment proof.

- Observation: the new `tx_leaf_receipt_root` benchmark is the first honest measurement of the proof-ready-leaf topology actually implemented on this branch. It measures proof-ready tx leaf artifacts, folded root construction, and receipt-root verification over those artifacts, while tracking edge leaf preparation separately.
  Evidence: `cargo run --release -p superneo-bench -- --relation tx_leaf_receipt_root --k 1,2,4,8 --compare-inline-tx` reports `1827/1910/1952/1973 B/tx`, `831166/1676666/5441584/6035916 ns` active-path prove, `2891708/5438750/16308209/18444125 ns` active-path verify, and `15681791/30136041/150432875/108117208 ns` edge leaf preparation for `k=1,2,4,8`.

## Decision Log

- Decision: the first backend implementation is a deterministic mock backend in `circuits/superneo-backend-lattice`, not a real `latticefold` integration.
  Rationale: the user explicitly asked to build methodically and not blow up laptop memory. The mock backend validates crate boundaries, digest formats, fold orchestration, and benchmark plumbing before introducing heavy external lattice dependencies.
  Date/Author: 2026-03-20 / Codex

- Decision: the first real Hegemon relation is a transaction-proof receipt relation rather than a full transaction AIR port.
  Rationale: the current scaling note says any future compression must be a witness-free post-proof primitive. A post-proof receipt relation respects that boundary and keeps the experiment aligned with the intended direction.
  Date/Author: 2026-03-20 / Codex

- Decision: no shipping crate may depend on any `circuits/superneo-*` crate in milestone one.
  Rationale: `InlineTx` remains the live path. The experiment must be trivially removable if it loses the benchmark.
  Date/Author: 2026-03-20 / Codex

- Decision: implement the next backend milestone directly from the Neo/SuperNeo papers inside Hegemon rather than vendoring `latticefold`.
  Rationale: the user explicitly required an in-repo implementation, and the public latticefold stack currently requires nightly-only compiler features that would destabilize Hegemon’s stable workspace.
  Date/Author: 2026-03-25 / Codex

- Decision: the first direct backend implements the folding geometry and pay-per-bit commitment shape, but not the final Ajtai/module-SIS commitment hardness from Neo/SuperNeo.
  Rationale: this is the largest protocol step that can be landed today in stable Rust without importing an unstable external lattice stack. It converts the experiment from a hash mock into a concrete folding engine while preserving the option to swap in a real lattice commitment later.
  Date/Author: 2026-03-25 / Codex

- Decision: `TxLeaf` is now the canonical experimental tx-artifact kind for the receipt-root lane, and the old `verified_tx_receipt` benchmark is retained only as a bridge/comparison lane.
  Rationale: the topology question is the real research question. The branch now measures and validates the proof-ready tx-leaf path directly, while keeping the bridge path available to compare against the older “inline proofs plus folded root” experiment.
  Date/Author: 2026-03-25 / Codex

## Outcomes & Retrospective

Milestone one is complete and the first review pass is closed. Milestone two is also landed: the repo contains a compilable, benchmarkable experimental stack with a Hegemon-owned relation layer, a Goldilocks packing layer, a direct in-repo folding backend, Hegemon receipt relations, a standalone `TxLeaf` artifact kind, a `ReceiptRoot` verifier that now consumes those tx-leaf artifacts, a JSON benchmark harness that compares both the bridge path and the proof-ready-leaf path against the stored `InlineTx` baseline, and targeted negative tests that lock in the corrected behavior. The remaining gap is still deliberate: this is a concrete SuperNeo-style backend, but it is not yet a production lattice/Ajtai implementation with the paper’s exact security assumptions.

## Context and Orientation

Hegemon’s production proving path lives in the Plonky3-based crates under `circuits/transaction*`, `circuits/batch`, `circuits/block`, and `circuits/aggregation`. The current honest deployment path is documented in `docs/SCALABILITY_PATH.md`: the live low-transaction-throughput winner is `InlineTx`, not recursive hot-path aggregation. Local benchmark data under `output/prover-recovery/2026-03-14/active-lanes/metrics.tsv` records the relevant baseline.

In this ExecPlan, a “CCS” is a customizable constraint system: a sparse algebraic relation more general than R1CS and convenient for folding. A “relation” means the statement and witness encoding that define what is being proved. A “receipt relation” means a relation derived from an already-produced proof artifact rather than the original shielded transaction witness. A “backend” means the engine that commits to witnesses, produces leaf proofs, and folds pairs of proved instances into a parent instance.

The experimental crates introduced here are:

- `circuits/superneo-ccs` for the Hegemon-owned relation and shape types.
- `circuits/superneo-core` for backend traits and artifact wrappers.
- `circuits/superneo-ring` for Goldilocks pay-per-bit witness packing.
- `circuits/superneo-backend-lattice` for the direct in-repo folding backend and the future lattice-hardness adapter boundary.
- `circuits/superneo-hegemon` for Hegemon-specific relations.
- `circuits/superneo-bench` for a JSON benchmark CLI that compares the experiment to the frozen `raw_active` baseline.

## Plan of Work

First, replace the generated crate stubs with concrete public interfaces. In `circuits/superneo-ccs/src/lib.rs`, define relation identifiers, 48-byte statement digests, sparse matrix entries, witness schemas, statement encodings, and digest helpers. Keep every public type Hegemon-owned; do not expose external backend types in signatures.

Next, define the orchestration boundary in `circuits/superneo-core/src/lib.rs`. This file must contain the backend trait, folded-instance wrapper, and leaf/fold artifact types that every backend implementation must satisfy. The trait must be generic over the field type but stable enough that benchmark code can run without knowing anything about a real lattice library.

Then, add Goldilocks witness packing in `circuits/superneo-ring/src/lib.rs`. The packer consumes a `WitnessSchema` and an `Assignment` and emits a packed representation that respects declared bit widths. This is where Hegemon’s future pay-per-bit value proposition lives, so the packer must preserve bounded-width semantics instead of treating every field element as an unstructured 64-bit limb.

After that, implement the direct backend in `circuits/superneo-backend-lattice/src/lib.rs`. The backend should expand packed witnesses to their used bit slices, decompose them into low-bit digits, embed those digits into small ring elements over Goldilocks, commit with a deterministic Ajtai-style public matrix, and fold parent commitments with transcript-derived linear challenges. Verification should recompute the same ring-linear commitments and fold transitions from public data. This gives the experiment a real folding engine without importing a nightly-only external lattice implementation.

With the generic pieces in place, add `ToyBalanceRelation`, `TxProofReceiptRelation`, and then `VerifiedTxProofReceiptRelation` to `circuits/superneo-hegemon/src/lib.rs`. The toy relation proves the plumbing works. The synthetic receipt relation remains useful for narrow crate tests. The verified receipt relation is the real target: it derives a canonical post-proof statement from an actual `TransactionProof`, re-verifies that proof when building the assignment, and then feeds the bounded witness assignment into the packing layer.

Finally, wire everything into `circuits/superneo-bench/src/main.rs`. The benchmark now supports deterministic synthetic leaves, the older `verified_tx_receipt` bridge lane built from real `TransactionProof`s, and the honest `tx_leaf_receipt_root` lane built from proof-ready tx-leaf artifacts. When `--compare-inline-tx` is passed, it also loads the frozen `raw_active` numbers from `output/prover-recovery/2026-03-14/active-lanes/metrics.tsv`.

The current experimental topology is now the proof-ready-leaf lane. `TxLeaf` proof bytes contain the SuperNeo leaf proof plus the smaller transaction public-input object needed to recover a full `TxStatementBinding`, and `ReceiptRoot` verification consumes those tx-leaf artifacts instead of inline tx proofs. This is still an experimental trust boundary, not the final secure system, but it now measures and validates the scaling shape of “proof-ready tx leaves + folded root” directly.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`:

1. Create the experimental branch.

       git switch -c codex/superneo-experiment

2. Replace the generated crate stubs with the actual API layer and direct backend.

       cargo test -p superneo-ccs
       cargo test -p superneo-ring
       cargo test -p superneo-backend-lattice
       cargo test -p superneo-hegemon

3. Run the experimental benchmark against the fixed baseline.

       cargo run --release -p superneo-bench -- --relation tx_leaf_receipt_root --k 1,2,4,8 --compare-inline-tx

Expected output is JSON that includes `relation`, `k`, `bytes_per_tx`, `total_active_path_prove_ns`, `total_active_path_verify_ns`, `packed_witness_bits`, and `shape_digest`. The important current use of the benchmark is honesty: it must measure the verified receipt-root path against the frozen `InlineTx` baseline without pretending the receipt root replaces inline tx proof verification yet.

## Validation and Acceptance

Milestone-one validation is behavioral:

- `cargo test -p superneo-ring` must prove that the packer round-trips a bounded Goldilocks assignment.
- `cargo test -p superneo-backend-lattice` must prove that a leaf proof verifies and that one fold step verifies.
- `cargo test -p superneo-hegemon` must prove that the toy relation, the synthetic receipt relation, and the verified receipt relation all produce assignments that the packer/backend accept.
- `cargo test -p consensus receipt_root_ -- --nocapture` must prove that the experimental `ReceiptRoot` path accepts valid `TxLeaf`-backed blocks and rejects receipt-root artifacts tied to the wrong tx statement set.
- `cargo test -p hegemon-node receipt_root -- --nocapture` must prove that node-side selection and artifact-market glue still work after adding `TxLeaf`.
- `cargo run --release -p superneo-bench -- --relation tx_leaf_receipt_root --k 1,2,4,8 --compare-inline-tx` must complete and print the proof-ready-leaf topology metrics alongside the stored `InlineTx` baseline.

The project should not proceed to a real lattice backend unless this prototype stack remains isolated, easy to understand, and benchmark-ready.

## Idempotence and Recovery

All changes in this milestone are additive. Re-running the targeted tests is safe. The new crates do not modify consensus, runtime, wallet, or node behavior. If the experiment is abandoned, deleting the six `circuits/superneo-*` crates and their workspace entries cleanly removes the entire spike.

## Artifacts and Notes

The important artifact for the current milestone is the proof-ready-leaf benchmark JSON. A representative shape is:

    {
      "relation": "tx_leaf_receipt_root",
      "k": 2,
      "bytes_per_tx": 1910,
      "total_active_path_prove_ns": 1676666,
      "total_active_path_verify_ns": 5438750,
      "packed_witness_bits": 3072,
      "shape_digest": "d957...",
      "note": "proof-ready txs; tx_leaf_artifacts=3026B root_artifact=794B",
      "edge_prepare_ns": 30136041,
      "inline_tx_baseline": {
        "bytes_per_tx": 456262,
        "total_active_path_prove_ns": 108371875,
        "total_active_path_verify_ns": 29954584
      }
    }

Revision note: this file was created on 2026-03-20 to guide the first experimental SuperNeo spike and deliberately started with a mock backend so the crate boundaries could be validated before any heavy lattice integration. It was updated the same day after the stack compiled, the targeted tests passed, the benchmark CLI emitted JSON comparisons, and the design/method documents were amended to capture the experiment boundary. It was updated again on 2026-03-21 after the initial code review so the corrected metadata binding, trace digest binding, fixed-width artifact sizing, and new negative tests were captured in the plan state. It was updated on 2026-03-25 after the mock backend was replaced with a direct in-repo SuperNeo-style folding backend derived from the Neo/SuperNeo papers, and again later that day after the verified tx-proof receipt relation landed and the benchmark switched from synthetic receipt leaves to the honest `verified_tx_receipt` path.

Revision note (2026-03-25, later): the `TxLeaf` milestone is now landed. The honest experimental lane is `tx_leaf_receipt_root`, the receipt-root verifier consumes `TxLeaf` artifacts instead of inline tx proofs, and the benchmark records proof-ready-leaf metrics plus separate edge leaf-preparation time.

## Interfaces and Dependencies

The public interfaces required by milestone one are:

- In `circuits/superneo-ccs/src/lib.rs`, define `RelationId`, `ShapeDigest`, `StatementDigest`, `WitnessField`, `WitnessSchema`, `SparseEntry<F>`, `SparseMatrix<F>`, `CcsShape<F>`, `StatementEncoding<F>`, `Assignment<F>`, and `Relation<F>`.
- In `circuits/superneo-core/src/lib.rs`, define `SecurityParams`, `Backend<F>`, `FoldedInstance<C>`, `LeafArtifact<P>`, and `FoldArtifact<P>`.
- In `circuits/superneo-ring/src/lib.rs`, define `GoldilocksPackingConfig`, `PackedWitness<R>`, `WitnessPacker<F, R>`, and `GoldilocksPayPerBitPacker`.
- In `circuits/superneo-backend-lattice/src/lib.rs`, define `RingProfile`, `LatticeBackendConfig`, `LatticeBackend`, `LatticeCommitment`, `LeafDigestProof`, `FoldDigestProof`, and `BackendShape`.
- In `circuits/superneo-hegemon/src/lib.rs`, define `ToyBalanceRelation`, `ToyBalanceStatement`, `ToyBalanceWitness`, `TxProofReceiptRelation`, `VerifiedTxProofReceiptRelation`, `TxProofReceipt`, `TxProofReceiptWitness`, and the canonical receipt/root helpers that bridge actual `TransactionProof`s into the experimental backend.

The first milestone should depend only on lightweight, already-used crates: `anyhow`, `blake3`, `clap`, `serde`, `serde_json`, `bincode`, `p3-field`, and `p3-goldilocks`. The real lattice implementation should remain a future step once these boundaries prove useful.
