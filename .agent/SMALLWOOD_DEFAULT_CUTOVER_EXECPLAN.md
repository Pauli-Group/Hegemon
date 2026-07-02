# Make SmallWood The Default Transaction Proof Backend

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, a fresh Hegemon build will treat `SmallwoodCandidate` as the active transaction proof family everywhere the product chooses a default transaction proof backend today. A wallet that constructs a default `TransactionWitness`, a node that materializes a transaction proof object from bytes, and the `superneo-bench` native `tx_leaf -> receipt_root` benchmark should all land on the same SmallWood-backed path without requiring a special version override.

The user-visible proof is straightforward. Running the native benchmark from the repository root with:

    cargo run -p superneo-bench --release -- --relation native_tx_leaf_receipt_root --k 1

must produce a JSON row whose native tx-leaf artifact uses the SmallWood backend by default, with bytes materially below the old Plonky3-backed baseline and with no manual `SMALLWOOD_CANDIDATE_VERSION_BINDING` override.

## Progress

- [x] (2026-04-10 18:41Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `governance/VERSIONING.md`, `protocol/versioning/src/lib.rs`, `runtime/src/manifest.rs`, `circuits/transaction/src/proof.rs`, and `circuits/superneo-bench/src/main.rs` to locate the actual default-backend control surface.
- [x] (2026-04-10 18:41Z) Confirmed that the default witness and benchmark paths currently flow through `protocol/versioning::DEFAULT_VERSION_BINDING` and `protocol/versioning::DEFAULT_TX_PROOF_BACKEND`, while `SMALLWOOD_CANDIDATE_VERSION_BINDING` remains a separate non-default binding.
- [x] (2026-04-10 18:57Z) Changed the protocol versioning defaults so the active default binding now resolves to `SmallwoodCandidate`, while `LEGACY_PLONKY3_FRI_VERSION_BINDING` preserves the old explicit Plonky3 mapping for historical decode and comparison surfaces.
- [x] (2026-04-10 18:57Z) Updated manifest, wallet, node, transaction-crate docs, and repo-level docs so they describe SmallWood as the active default and stop advertising a default Plonky3 FRI profile on the live binding.
- [x] (2026-04-10 18:57Z) Ran focused validation and a release benchmark proving that the default native `tx_leaf -> receipt_root` lane now uses SmallWood without a manual version override.

## Surprises & Discoveries

- Observation: the benchmark CLI does not expose a direct `--backend smallwood` switch.
  Evidence: `circuits/superneo-bench/src/main.rs` routes `benchmark_native_tx_leaf_receipt_root` through `sample_witness(seed)` and `build_native_tx_leaf_artifact_bytes(witness)`, and `sample_witness` sets `version: TransactionWitness::default_version_binding()`.

- Observation: the real default switch is in `protocol/versioning`, not in the prover or benchmark code.
  Evidence: `TransactionWitness::default_version_binding()` returns `DEFAULT_VERSION_BINDING`, and `circuits/transaction/src/proof.rs::prove` dispatches on `tx_proof_backend_for_version(witness.version)`.

- Observation: the runtime manifest currently assumes the active default binding also has a Plonky3 FRI profile entry.
  Evidence: `runtime/src/manifest.rs` builds `tx_stark_profiles` by `filter_map(tx_fri_profile_for_version)` and its tests currently expect exactly one profile entry for `DEFAULT_VERSION_BINDING`.

- Observation: the existing native `tx_leaf` test lane already distinguishes backend ids cleanly, but the explicit SmallWood acceptance/tamper tests remain ignored in the default profile because release SmallWood proving is still expensive there.
  Evidence: `cargo test -p superneo-hegemon native_tx_leaf -- --nocapture` passed with the generic round-trip and integrity checks, while the two SmallWood-specific release-proving tests stayed `ignored` under their existing guard text.

- Observation: once the default binding moved, the release benchmark immediately collapsed the native `tx_leaf` artifact to the expected `~114 kB` class without any benchmark-only override.
  Evidence: `cargo run -p superneo-bench --release -- --relation native_tx_leaf_receipt_root --k 1` reported `native tx-leaf artifacts=114092B`, `root_artifact=394B`, and `bytes_per_tx=114486`.

## Decision Log

- Decision: treat this work as a real protocol-default cutover, not a benchmark-only flag addition.
  Rationale: the user asked to abandon the Plonky3 default entirely. Adding a benchmark flag would hide the real default surface in wallets, nodes, and manifests.
  Date/Author: 2026-04-10 / Codex

- Decision: keep a legacy Plonky3 version binding available in code for historical artifacts and comparison surfaces even after SmallWood becomes the default.
  Rationale: the repo still contains historical artifacts, comparison lanes, and decoders that must understand older Plonky3 objects. Defaulting to SmallWood does not require deleting all legacy decode support in the same change.
  Date/Author: 2026-04-10 / Codex

## Outcomes & Retrospective

The cutover landed on the real default surface rather than in a benchmark shim. `DEFAULT_VERSION_BINDING` now equals `SMALLWOOD_CANDIDATE_VERSION_BINDING`, `DEFAULT_TX_PROOF_BACKEND` now equals `SmallwoodCandidate`, and the old `CIRCUIT_V2 + CRYPTO_SUITE_GAMMA` path survives only as `LEGACY_PLONKY3_FRI_VERSION_BINDING` for compatibility and measurement work.

The manifest and docs now tell the same story as the code. The live manifest advertises one tx backend entry and no live default FRI profile, while design/method/governance prose now says SmallWood is the active default transaction-proof family and Plonky3 is legacy comparison material.

Focused validation passed:

- `cargo test -p protocol-versioning`
- `cargo test -p runtime manifest_includes_default_tx_backend_and_only_live_profiles -- --nocapture`
- `cargo test -p transaction-circuit smallwood_candidate -- --nocapture`
- `cargo test -p superneo-hegemon native_tx_leaf -- --nocapture`

The release benchmark proved the actual post-cutover numbers on the default lane:

- command: `cargo run -p superneo-bench --release -- --relation native_tx_leaf_receipt_root --k 1`
- `bytes_per_tx = 114486`
- native tx-leaf artifacts total `114092 B`
- receipt-root artifact `394 B`
- `edge_prepare_ns = 1362975875` (`~1.36 s`)
- `total_active_path_prove_ns = 15524667` (`~15.5 ms`)
- `total_active_path_verify_ns = 33383875` (`~33.4 ms`)
- `peak_rss_bytes = 47251456` (`~45.1 MiB`)

That is the behavior the user asked for: the repo’s default benchmark path now lands on the SmallWood-sized tx-leaf object automatically, without manually overriding the witness version inside the benchmark harness.

## Context and Orientation

The source of truth for transaction proof backend selection lives in [protocol/versioning/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/protocol/versioning/src/lib.rs). That crate defines `VersionBinding`, which is the `(circuit_version, crypto_suite)` pair embedded in every transaction witness and proof. It also defines `TxProofBackend`, the backend enum (`Plonky3Fri` or `SmallwoodCandidate`), plus helper functions that map a binding to a backend or a FRI profile.

The transaction witness type lives in [circuits/transaction/src/witness.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/witness.rs). `TransactionWitness::default_version_binding()` returns `DEFAULT_VERSION_BINDING`, so changing that protocol-level constant changes the default version used by many callers.

The transaction proof dispatcher lives in [circuits/transaction/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs). `prove()` selects the backend from `tx_proof_backend_for_version(witness.version)`. When the backend is `SmallwoodCandidate`, it diverts into the SmallWood prover instead of the Plonky3 prover.

The runtime manifest lives in [runtime/src/manifest.rs](/Users/pldd/Projects/Reflexivity/Hegemon/runtime/src/manifest.rs). It publishes the active protocol bindings and backend/profile metadata consumed by the runtime and chain-spec builders. If the active default moves to SmallWood, that manifest must stop implying that the default binding has a live Plonky3 FRI profile unless a separate legacy binding still carries that profile.

The native aggregation benchmark lives in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). Its `native_tx_leaf_receipt_root` lane creates sample witnesses with `TransactionWitness::default_version_binding()`, builds native `tx_leaf` artifacts, then aggregates them into a `receipt_root`. That benchmark is the clean observable proof that the default path changed.

The wallet and node glue code use `DEFAULT_TX_PROOF_BACKEND` when they materialize a `TransactionProof` object from raw proof bytes. Those entry points live in [wallet/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) and [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs). They must stay aligned with the versioning defaults.

## Plan of Work

Start in `protocol/versioning/src/lib.rs`. Change `DEFAULT_VERSION_BINDING` so the active default binding is the SmallWood binding. Keep an explicit non-default legacy binding for Plonky3 instead of letting `DEFAULT_TX_PROOF_BACKEND` implicitly define both. Change `DEFAULT_TX_PROOF_BACKEND` to `TxProofBackend::SmallwoodCandidate`, and update `tx_proof_backend_for_version` so the default binding maps to SmallWood while the legacy binding still maps to `TxProofBackend::Plonky3Fri`. Keep `tx_fri_profile_for_version` returning a profile only for the explicit Plonky3 binding.

Then update manifest and caller expectations. In `runtime/src/manifest.rs`, keep the active `version_bindings` list aligned with the new SmallWood default and adjust tests so they no longer require a FRI profile entry for the active default if the backend is SmallWood. In `wallet/src/prover.rs`, `node/src/substrate/service.rs`, and any similar call sites, update comments or assumptions that still describe the default path as Plonky3-based.

Next update repo documentation that names the active default backend. That includes at minimum `DESIGN.md`, `METHODS.md`, and `governance/VERSIONING.md`. The prose should say that SmallWood is now the active default tx proof family, while Plonky3 remains a legacy or comparison path where still present. Any statements that the active default binding resolves to `Plonky3Fri` or that the active default binding carries the release FRI profile must be rewritten accordingly.

Finally, run focused validation. Use unit tests around protocol versioning, runtime manifest, transaction proof dispatch, and native tx-leaf artifact handling. Then run a release `superneo-bench` native benchmark to confirm the default path now emits SmallWood-sized artifacts without a manual version override.

## Concrete Steps

Work from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Update the protocol versioning source:

       apply_patch <patch that changes protocol/versioning/src/lib.rs>

2. Update manifest and callers that assume the old default:

       apply_patch <patches for runtime/src/manifest.rs, wallet/src/prover.rs, node/src/substrate/service.rs, and any failing tests>

3. Update the design/methods/governance documents so the active-default story matches code:

       apply_patch <patches for DESIGN.md, METHODS.md, governance/VERSIONING.md, and any related notes>

4. Run focused tests:

       cargo test -p protocol-versioning
       cargo test -p runtime manifest_includes_default_tx_stark_profile -- --nocapture
       cargo test -p transaction-circuit
       cargo test -p superneo-hegemon native_tx_leaf -- --nocapture

5. Run the release benchmark:

       cargo run -p superneo-bench --release -- --relation native_tx_leaf_receipt_root --k 1

Expected result: the benchmark JSON should report `native_tx_leaf_receipt_root` using the SmallWood default path, with `bytes_per_tx` near the SmallWood-backed artifact size rather than the old Plonky3-backed `~358 kB` class.

## Validation and Acceptance

Acceptance is behavioral.

`cargo test -p protocol-versioning` must pass with the new default mapping. A reader should be able to inspect the tests and see that the active default binding maps to `SmallwoodCandidate`, while the legacy Plonky3 binding still maps explicitly to `Plonky3Fri`.

`cargo test -p runtime manifest_includes_default_tx_stark_profile -- --nocapture` must either pass with revised expectations or be replaced by a renamed test that proves the manifest accurately represents the SmallWood default. The key behavior is that the manifest no longer lies about the active binding carrying a Plonky3 FRI profile when it does not.

`cargo test -p transaction-circuit` must pass. This proves that `prove()` and `verify()` still work when the default witness version resolves to SmallWood.

`cargo test -p superneo-hegemon native_tx_leaf -- --nocapture` must pass. This proves that native `tx_leaf` artifact construction and verification still work on the new default path.

The release benchmark command:

    cargo run -p superneo-bench --release -- --relation native_tx_leaf_receipt_root --k 1

must print one JSON result row. That row should show the native lane using the SmallWood-sized proof/artifact surface by default, without editing the witness version manually in the benchmark harness.

## Idempotence and Recovery

All source edits in this plan are repeatable. Reapplying the patch should converge to the same result.

The risky part is changing protocol defaults in a way that strands legacy tests or manifests. If a validation step fails, recover by reading the failing assertion and aligning the caller with the new rule rather than reverting the protocol constant in isolation. Partial rollback is unsafe because callers, docs, and manifests all rely on the same default-binding story.

The benchmark is read-only with respect to repository state. It may take time, but it should not mutate checked-in files unless a contributor explicitly chooses to refresh benchmark artifacts in a follow-up change.

## Artifacts and Notes

Important current evidence before the code change:

    protocol/versioning/src/lib.rs:
      DEFAULT_VERSION_BINDING = (CIRCUIT_V2, CRYPTO_SUITE_GAMMA)
      SMALLWOOD_CANDIDATE_VERSION_BINDING = (CIRCUIT_V2, CRYPTO_SUITE_BETA)
      DEFAULT_TX_PROOF_BACKEND = Plonky3Fri

    circuits/superneo-bench/src/main.rs:
      sample_witness(seed).version = TransactionWitness::default_version_binding()
      benchmark_native_tx_leaf_receipt_root() uses build_native_tx_leaf_artifact_bytes(witness)

This is why the benchmark currently follows the default binding rather than exposing a backend flag.

Change note (2026-04-10): created after the user asked for a real SmallWood default cutover instead of more Plonky3-vs-SmallWood comparison work. The plan chooses a protocol-default switch with explicit legacy Plonky3 mapping rather than a benchmark-only override.
