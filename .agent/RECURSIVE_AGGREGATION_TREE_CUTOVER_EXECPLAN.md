# Recursive Aggregation Tree Cutover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

The current `MergeRoot` path still builds one monolithic recursion proof that verifies every transaction proof directly. That design makes the first strict proofless batch cold-start on one expensive shape, and the coordinator’s published `leaf_batch_prove` / `merge` stage metadata is mostly decorative because only `root_finalize` performs real work. After this cutover, the default fresh-testnet path uses a real fixed-fan-in recursion tree: leaf jobs prove fixed-size batches of transaction proofs, merge jobs prove fixed-size batches of child aggregation proofs, and the root stage only assembles the final `CandidateArtifact` with the root recursive proof plus the commitment proof.

The user-visible result is that additional prover workers can reduce prepared-artifact latency for proofless batches instead of idling behind one root-only proving bottleneck. The observable acceptance target is a strict proofless batch on a fresh testnet that reaches a prepared artifact through leaf and merge stage completions, plus targeted tests that prove consensus accepts V5 recursive payloads and rejects legacy V4 by default.

## Progress

- [x] (2026-03-12 10:11Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `config/testnet-initialization.md`.
- [x] (2026-03-12 10:18Z) Audited the current aggregation, consensus, coordinator, RPC, worker, and service paths in `circuits/aggregation/src/lib.rs`, `consensus/src/aggregation.rs`, `consensus/src/proof.rs`, `node/src/substrate/prover_coordinator.rs`, `node/src/substrate/rpc/prover.rs`, `node/src/bin/prover_worker.rs`, and `node/src/substrate/service.rs`.
- [x] (2026-03-12 10:27Z) Confirmed the key technical feasibility point: the vendored recursion stack already exposes recursive batch-proof verification helpers (`verify_p3_recursion_proof_circuit`, `BatchStarkVerifierInputsBuilder`, `generate_batch_challenges`) that can verify child aggregation proofs inside a merge circuit.
- [x] (2026-03-12 04:08Z) Implemented the first V5 cut in `circuits/aggregation`: new V5 payload schema, fixed-size leaf proving, fixed-size merge-over-leaf proving, shape-based ids, and exact-shape prewarm routing through `circuits/aggregation/src/v5.rs`.
- [x] (2026-03-12 04:08Z) Hard-cut consensus verification to V5 by default in `consensus/src/aggregation.rs`, keeping V4 only behind `HEGEMON_AGG_LEGACY_V4`, and added V5-specific error variants in `consensus/src/error.rs`.
- [x] (2026-03-12 04:08Z) Updated block-import metadata checks in `consensus/src/proof.rs` and artifact assembly metadata in `node/src/substrate/service.rs` so `leaf_count`, `tree_levels`, and `leaf_manifest_commitment` match the new leaf tree instead of the old monolithic stub.
- [x] (2026-03-12 04:08Z) Verified targeted compile/tests for the landed slice: `cargo check -p aggregation-circuit`, `cargo check -p consensus`, `cargo test -p aggregation-circuit --test aggregation aggregation_v5_payload_validation_rejects_invalid_encodings -- --nocapture`, and `cargo test -p consensus verify_aggregation_proof_rejects_legacy_payload_version -- --nocapture`.
- [x] (2026-03-12 04:08Z) Confirmed the node crate still compiles against the V5/proof-metadata changes with the documented macOS `libclang` environment: `LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib cargo check -p hegemon-node`.
- [x] (2026-03-12 04:37Z) Replaced the primary MergeRoot scheduler path in `node/src/substrate/prover_coordinator.rs` with a real leaf/merge DAG backed by `RootFinalizeWorkData`: leaf packages now carry sliced tx proof bytes, local workers execute `prove_leaf_aggregation` / `prove_merge_aggregation`, merge work is published only after all leaves complete, and final `CandidateArtifact` assembly is local to the coordinator.
- [x] (2026-03-12 04:37Z) Extended prover RPC and `node/src/bin/prover_worker.rs` for `leaf_batch_prove` and `merge_node_prove`, and switched `submitStageWorkResult` to raw stage-proof bytes instead of SCALE-encoded `CandidateArtifact` payloads.
- [x] (2026-03-12 04:37Z) Verified node-side compile and one behavioral test after the DAG cut: `cargo test -p hegemon-node prover_rpc_workflow_methods_operate_end_to_end -- --nocapture`.
- [x] (2026-03-12 07:20Z) Ran a remote leaf-parameter sweep on `hegemon-prover` with the ignored `aggregation_v5_leaf_fanin8_cold_warm_profile` benchmark. Measured cold/warm leaf totals were `fan_in=4, queries=4, blowup=2 -> 192015/141124 ms`, `fan_in=4, queries=2, blowup=2 -> 131712/99431 ms`, `fan_in=2, queries=4, blowup=2 -> 96443/71036 ms`, and `fan_in=2, queries=2, blowup=2 -> 66013/50219 ms`.
- [x] (2026-03-12 07:20Z) Reduced those leaf timings to whole-tree implications. Under the current two-level implementation (`max_recursive_txs = leaf_fanin * merge_fanin`), `fan_in=2` needs `merge_fanin=16` just to reach `32` tx and still cannot reach `64` without `merge_fanin=32` or a third level. The best `32/64`-oriented leaf candidate from the sweep is therefore `fan_in=4, queries=2, blowup=2`, which implies a `32 tx, 4-worker` leaf phase of roughly `132s + 99s = 231s` before merge/finalize.
- [x] (2026-03-12 08:12Z) Added merge-stage profiling instrumentation in `circuits/aggregation/src/v5.rs` plus a new ignored benchmark `aggregation_v5_merge_cold_warm_profile` in `circuits/aggregation/tests/aggregation.rs`.
- [x] (2026-03-12 08:27Z) Proved that the current merge implementation is structurally broken on the legacy outer batch-proof backend: the first `leaf_fanin=4`, `merge_fanin=16`, `queries=2`, `blowup=2` merge profile fails with `CircuitBuild(\"... verify_merkle_batch_circuit ... expected: goldilocks digest_elems=6, got: 4\")`.
- [x] (2026-03-12 08:50Z) Prototyped a recursion-compatible outer batch config inside `circuits/aggregation` by switching the aggregation crate’s outer proof path to the transaction-style 6-element Goldilocks Poseidon2 configuration. The aggregation crate compiles and merge profiling now gets past the old digest-arity crash, but the same `leaf_fanin=4`, `merge_fanin=16`, `queries=2`, `blowup=2` run still fails after a `480214 ms` merge cache build with `CircuitRun(\"PublicInputLengthMismatch { expected: 5917, got: 291 }\")`.
- [x] (2026-03-12 15:57Z) Fixed the first merge packing bug in the prototype path: small-case merge profiling (`leaf_fanin=1`, `merge_fanin=2`, `queries=2`, `blowup=2`) now reports `expected_public_len=460` and `packed_public_len=460`, and `v5_merge_set_targets` completes. The remaining blocker has moved to merge witness assignment: the same run now fails with `CircuitRun(\"WitnessConflict { witness_id: WitnessId(507), ... }\")` during `runner.run()`.
- [x] (2026-03-12 16:20Z) Confirmed the merge witness-assignment failure is not a public-input bug anymore. The current prototype resolves merge witness sources through `Unconstrained` op outputs instead of `expr_to_widx`, but the small-case merge still fails at `runner.run()` with `WitnessConflict { witness_id: WitnessId(507), ... }`. That means the lowerer is still collapsing some external merge inputs onto computed witness slots through connect-class sharing; the next fix belongs in the recursion/circuit-lowering layer, not in another ad hoc `v5.rs` flattener.
- [x] (2026-03-12 20:47Z) Replaced the remaining aggregation-local witness ordering logic in both leaf and merge cache builders with canonical recursive private targets resolved through the compiled circuit’s `expr_to_widx` map. `cargo check -p aggregation-circuit` passes with the refactor.
- [x] (2026-03-12 20:47Z) Re-ran the minimal release merge profile (`leaf_fanin=1`, `merge_fanin=2`, `queries=2`, `blowup=2`). The failure moved from an opaque witness conflict to a precise overlap class: for each child, `4748 / 5200` canonical private targets land on witness ids that are simultaneously `WitnessInput` outputs, `Unconstrained` inputs, and later `Add(out)` rows.
- [x] (2026-03-12 21:38Z) Added fast verifier-side consistency tests in the vendored recursion layer. The Goldilocks-12 Poseidon2 hash/compress checks and a direct `RecExtensionValMmcs` verification check pass, while a new ignored reproducer shows the same recursive batch-verifier commitment mismatch on a tiny extension-degree-2 circuit-table proof.
- [x] (2026-03-12 21:38Z) Aligned the recursive merge verifier with the actual batch-proof format by setting child AIR public-value counts to zero in the merge proof path and in consensus cache construction. This shrank the single-child merge verifier public bus from `165` to `21`, but the first recursive batch-verifier commitment check still fails.
- [x] (2026-03-12 22:57Z) Fixed the generic recursive batch-verifier bug in the vendored recursion layer by matching native batch-STARK observation order for flattened batch opened values and by aligning recursive batch verification with the native `trace_domain.next_point(zeta)` / preprocessed-domain rules. The fast Goldilocks D2 recursive batch-verifier repro now passes.
- [x] (2026-03-12 22:57Z) Realigned consensus V5 decoding/verification to the same 6-element Goldilocks outer-proof config the prover now emits. The merge prover’s outer proof bytes now decode correctly in consensus instead of failing immediately as “merge outer proof encoding invalid”.
- [x] (2026-03-12 22:57Z) Verified the end-to-end one-child merge roundtrip under release settings by extending `aggregation_v5_merge_cold_warm_profile` to call `verify_aggregation_proof` on both the cold and warm merge payloads. With `HEGEMON_AGG_LEAF_FANIN=1` and `HEGEMON_AGG_MERGE_FANIN=1`, the full prove+verify path passes.
- [x] (2026-03-12 23:23Z) Verified the original failing two-child merge shape end-to-end under release settings. With `HEGEMON_AGG_LEAF_FANIN=1` and `HEGEMON_AGG_MERGE_FANIN=2`, `aggregation_v5_merge_cold_warm_profile` now generates and verifies both the cold and warm merge payloads through `verify_aggregation_proof`.
- [x] (2026-03-12 23:23Z) Fixed the backend mismatch above aggregation packing by matching native batch-STARK opened-value observation order and native recursive batch-domain handling. The generic Goldilocks D2 repro and the end-to-end `merge(2 leaves)` roundtrip now pass.
- [x] (2026-03-12 23:23Z) Ran broader larger-shape validation in the release merge harness. The two-child cold/warm roundtrip remains green after consensus-side decode fixes, and the same harness now verifies generated merge payloads instead of only proving them.
- [x] (2026-03-13 00:19Z) Identified the node-level `BadProof` cause on the easy local harness: the repository’s `config/dev-chainspec.json` was stale relative to the current node binary. Compared to `./target/release/hegemon-node build-spec --raw --disable-default-bootnode`, it still carried the old runtime WASM and the old proof-availability storage value (`InlineRequired` instead of `SelfContained`).
- [x] (2026-03-13 00:19Z) Refreshed `config/dev-chainspec.json` from the current node binary’s raw build-spec output so the shared local/testnet bootstrap spec now matches the live runtime and default self-contained aggregation policy.
- [x] (2026-03-13 00:19Z) Reproduced the exact proofless sidecar submission manually on a low-difficulty chainspec derived from the refreshed spec. The same `HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1` submission that previously failed as `Pool(InvalidTransaction(InvalidTransaction::BadProof))` is now accepted by the node, and `shielded-pool` trace logs show `verify_binding_hash ... result=true` on the proofless path.
- [x] (2026-03-13 00:49Z) Shifted the default recursion throughput lane to the best measured two-level profile in code and ops: `leaf_fanin=4`, `merge_fanin=8`, tx recursion `queries=2`, tx recursion `log_blowup=2`, and outer aggregation `queries/log_blowup=2/2`.
- [x] (2026-03-13 00:49Z) Fixed the throughput harness so it actually exports aggregation-shape and recursion-profile env vars to the node and wallet, widened the default RPC wait for custom chainspec runs, and stopped defaulting aggregation mode to a single local prover worker.
- [x] (2026-03-13 00:49Z) Re-ran the strict wrapper probe on the refreshed easy chainspec with the tuned defaults. `scripts/throughput_sidecar_aggregation_tmux.sh` now reaches `Send stage complete` and `Strict mode: waiting for local proven batch candidate...` under the new lane instead of failing before proofless submission or running the stale `8 x 8` fallback.
- [ ] (2026-03-13 00:19Z) Finish the strict wrapper run after proofless submission succeeds. Current state: `scripts/throughput_sidecar_aggregation_tmux.sh` with `tx_count=1`, the refreshed easy chainspec, and strict aggregation now gets past funding, sync, and the first proofless sidecar submission, then waits for a local prepared batch instead of failing at pool admission.

## Surprises & Discoveries

- Observation: the repository already has a recursive verifier for `BatchStarkProof` objects, not just transaction proofs.
  Evidence: `spikes/recursion/vendor/plonky3-recursion/recursion/src/verifier/batch_stark.rs` exports `verify_p3_recursion_proof_circuit`, and the recursion tests under `spikes/recursion/vendor/plonky3-recursion/recursion/tests/` use it to build satisfiable recursive batch-verifier circuits.

- Observation: the coordinator already publishes `leaf_batch_prove` work packages, but the heavy work remains root-only.
  Evidence: `node/src/substrate/prover_coordinator.rs` publishes `stage_type = "leaf_batch_prove"` for external work packages, but `WorkerPool::new` only calls the heavy builder when `job.stage_type == "root_finalize"`; all other stage jobs return `WorkerOutcome::StageOnly`.

- Observation: root metadata already has a composable leaf-manifest hook that can bind tree structure separately from the monolithic V4 public-input blob.
  Evidence: `pallets/shielded-pool/src/types.rs` and `consensus/src/types.rs` already define `MergeRootMetadata { tree_arity, tree_levels, leaf_count, leaf_manifest_commitment }`.

- Observation: `config/testnet-initialization.md` is the actual testnet bootstrap runbook referenced indirectly by `config/testnet/README.md` and `runbooks/two_person_testnet.md`, not a top-level `TESTNET_INITIALIZATION.MD`.
  Evidence: both docs link directly to `/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md`, which states the canonical boot-wallet flow, the approved `HEGEMON_SEEDS` rollout rule, and the NTP/chrony requirement.

- Observation: proving and verifying child aggregation proofs in the recursive merge stage does not require the non-serializable `BatchStarkProof` wrapper to be carried in the payload. The serializable inner `BatchProof` plus cached AIR/common data is sufficient.
  Evidence: `circuits/aggregation/src/v5.rs` and `consensus/src/aggregation/v5.rs` now build merge circuits from cached leaf AIRs/common data and decode only `p3_batch_stark::BatchProof` from `outer_proof`.

- Observation: the current V5 cut is bounded to a two-level tree (`leaf` or `merge-over-leaf`) because the merge recursion is wired specifically against leaf children.
  Evidence: `circuits/aggregation/src/v5.rs` and `consensus/src/aggregation/v5.rs` currently reject non-leaf merge children with `"merge stage currently expects leaf children"` / `"merge nodes currently require leaf children"`.

- Observation: `RootFinalizeWorkData` already contains every input needed for the recursive stage DAG except the final root proof bytes, so the node-side cutover did not need a second service-side context builder.
  Evidence: `node/src/substrate/service.rs` already produced `statement_hashes`, `tx_proofs`, `tx_statements_commitment`, DA metadata, tree roots, and nullifier data; the coordinator now slices that into `LeafBatchWorkData` and uses it again for final local artifact assembly.

- Observation: leaf proving is now measurable enough to choose between shapes, and the raw fastest leaf is not automatically the best architecture because the current tree is only two levels.
  Evidence: on `hegemon-prover`, `fan_in=2, queries=2, blowup=2` measured `cold_ms=66013 warm_ms=50219`, but that shape only reaches `32` tx if `merge_fanin=16` and still cannot reach `64` without `merge_fanin=32` or another recursion level. `fan_in=4, queries=2, blowup=2` measured `cold_ms=131712 warm_ms=99431` and remains the best candidate that can plausibly serve both `32` and `64` with a larger merge arity.

- Observation: the legacy outer batch-STARK backend used by the aggregation crate cannot feed the recursive merge verifier on Goldilocks.
  Evidence: the first merge-profile run failed with `CircuitBuild("CircuitBuilder(NonPrimitiveOpArity { op: \"verify_merkle_batch_circuit\", expected: \"goldilocks digest_elems=6\", got: 4 })")`.

- Observation: fixing the outer digest arity alone is not enough; merge proving still mis-packs child outer-proof public inputs.
  Evidence: after switching the aggregation crate prototype to a 6-element outer config, the same merge profile reached `v5_merge_cache_lookup tx_count=16 cache_hit=false cache_build_ms=480204 cache_lookup_ms=480214 total_ms=483926` and then failed with `CircuitRun("PublicInputLengthMismatch { expected: 5917, got: 291 }")`.

- Observation: the child outer-proof public-input packing bug is now resolved on the prototype path, but merge proving still fails because the witness-assignment plan is not yet aligned with the merge circuit’s connected witness layout.
  Evidence: after fixing the packed public-input construction and removing obvious public-input leakage from the witness plan, the small debug case (`leaf_fanin=1`, `merge_fanin=2`) reports `v5_merge_public_input_summary tx_count=2 expected_public_len=460 packed_public_len=460` and `v5_merge_set_targets ... set_witness_ms=1`, then fails with `CircuitRun("WitnessConflict { witness_id: WitnessId(507), ... }")`.

- Observation: resolving merge witness sources through lowered `expr_to_widx` representatives is fundamentally unreliable for this circuit.
  Evidence: even after resolving witness sources through `Unconstrained` op outputs instead of `expr_to_widx`, the same small merge case still fails during `runner.run()` with `WitnessConflict { witness_id: WitnessId(507), ... }`. This shows the remaining conflict comes from lowerer/connect-class witness sharing, not from the aggregation crate’s packed public inputs.

- Observation: the canonical recursive target/value APIs are now wired through aggregation, and they isolate the remaining merge failure to a specific overlap class inside the lowered circuit rather than to aggregation-local flatteners.
  Evidence: after replacing the ad hoc source-order plans with target-based resolution, the minimal release merge profile still fails, but the logs now show `plan_index=0 witness_targets=5200 ... computed_overlap=4748` and the overlap preview points at witness ids that are simultaneously `NonPrimitive(WitnessInput, ...)`, `NonPrimitiveInput(Unconstrained, ...)`, and `Add(out)`.

- Observation: simply skipping the overlap rows is incorrect because those witness ids are consumed before the conflicting `Add(out)` rows execute.
  Evidence: a targeted filter experiment changed the failure from `WitnessConflict` to `NonPrimitiveExecutionFailed { operation_index: NonPrimitiveOpId(1120), op: Unconstrained, message: "WitnessNotSet { witness_id: WitnessId(676) }" }` on the first overlapped merge witness.

- Observation: re-enabling the lowerer’s selective DSU path for connects did not remove the merge overlap class.
  Evidence: with the DSU experiment enabled, the minimal release merge profile still reported `computed_overlap=4748` for each child and failed on the same witness `676`; I reverted that runtime-behavior change after capturing the result.

- Observation: the failure is not leaf-circuit-specific; the recursive batch verifier currently fails on a tiny extension-degree-2 circuit-table proof built directly in the vendored recursion crate.
  Evidence: the new ignored unit repro `pcs::fri::verifier::tests::recursive_batch_verifier_accepts_simple_goldilocks_d2_circuit_table_proof` fails in ~10s with `PrimitiveExecutionFailed { op: "Add { a: WitnessId(298), b: WitnessId(0), out: WitnessId(434496) }", ... }`, which is the same “first commitment digest copy mismatch” shape seen in the merge profile.

- Observation: the Goldilocks-12 Poseidon2 primitives and the recursive extension-MMCS verifier are not the failing layer.
  Evidence: the new unit tests `poseidon2_hash_targets_matches_native_goldilocks12`, `poseidon2_compress_targets_matches_native_goldilocks12`, and `rec_extension_val_mmcs_matches_native_goldilocks12` all pass.

- Observation: the remaining recursive bug was in batch-STARK opened-value observation order, not in the Goldilocks-12 hash primitive.
  Evidence: after changing `BatchProofTargets::flattened_opened_values_targets` to observe trace/preprocessed/permutation openings in native batch order (`local,next` per instance) and aligning the recursive batch verifier with native domain handling, the generic Goldilocks D2 recursive batch-verifier test and the end-to-end `merge(2 leaves)` release profile both pass.

- Observation: the actual generic failure was in the recursive batch-verifier transcript wiring, not in the hash primitive or the MMCS primitive.
  Evidence: the new unit repro `recursive_batch_verifier_accepts_simple_goldilocks_d2_circuit_table_proof` initially failed on the same “first commitment digest copy mismatch” seen in merge. After changing `BatchProofTargets::flattened_opened_values_targets` to observe trace/preprocessed/permutation openings in native batch order (`local,next` per instance) and aligning the recursive verifier with native batch-domain handling, that repro passes.

- Observation: consensus V5 merge verification had a separate decode mismatch after the recursive batch-verifier fix landed.
  Evidence: once `merge(2 leaves)` stopped failing in `runner.run()`, the next failure became `AggregationProofV5Decode("merge outer proof encoding invalid")`. The root cause was that `consensus/src/aggregation/v5.rs` still expected the legacy 4-element / width-8 outer proof type while the prover now serializes the 6-element transaction-style outer proof.

- Observation: the node/throughput harness is no longer blocked by merge proving or by PoW when run against an easy local chainspec; it now fails earlier in kernel-action admission for the first proofless sidecar transfer.
  Evidence: with a locally generated easy chainspec (`initialBits = 0x1e00ffff`) and `HEGEMON_AGG_LEAF_FANIN=4`, `HEGEMON_AGG_MERGE_FANIN=4`, `HEGEMON_TP_TX_COUNT=8`, the tmux harness mined 8 funding blocks in seconds and synced 8 notes, then failed on send `1/8` with `Kernel action submission failed: transaction pool rejected kernel action: Pool(InvalidTransaction(InvalidTransaction::BadProof))`.

- Observation: that local-harness `BadProof` was not a runtime logic bug in the proofless path; it was a stale chainspec artifact.
  Evidence: diffing `config/dev-chainspec.json` against the current `build-spec --raw` output showed exactly two mismatches: the runtime WASM blob and one shielded-pool storage value, which flipped from `0x00` to `0x01`. The changed shielded-pool key corresponds to `ProofAvailabilityPolicyStorage`, and after refreshing the chainspec the same proofless sidecar submission is accepted.

- Observation: the throughput harness had also been silently leaving throughput on the table even after the chainspec fix.
  Evidence: before this pass, `scripts/throughput_sidecar_aggregation_tmux.sh` accepted `HEGEMON_TP_AGG_LEAF_FANIN`-style knobs but did not export the corresponding `HEGEMON_AGG_*` / `HEGEMON_TX_RECURSION_*` variables to the node or wallet. It also defaulted aggregation mode to one local prover worker. After wiring those envs through and moving the default lane to `4 x 8` with `2/2` recursion FRI params, the wrapper reports the tuned config explicitly and still reaches strict prepared-batch waiting.

## Decision Log

- Decision: create a dedicated ExecPlan for this cutover instead of extending the broader permissionless-scaling plan.
  Rationale: this change is a self-contained proving/consensus/coordinator refactor with its own implementation and test matrix, and it needs a restartable document that points a contributor directly at the touched files and validation commands.
  Date/Author: 2026-03-12 / Codex

- Decision: implement merge recursion using the vendored batch-verifier recursion API rather than inventing a bespoke child-proof verifier.
  Rationale: the repo already vendors the exact primitive needed to verify `BatchStarkProof` outputs inside another recursion circuit, which materially reduces risk for the V5 cutover.
  Date/Author: 2026-03-12 / Codex

- Decision: keep `BlockProofMode::MergeRoot` and `MergeRootProofPayload` as the runtime vocabulary while hard-cutting the embedded bytes to V5 recursion.
  Rationale: the on-chain naming is already the accepted fresh-testnet public surface; the required cut is in payload semantics and default verification behavior, not in runtime field names.
  Date/Author: 2026-03-12 / Codex

- Decision: use `config/testnet-initialization.md` as the authoritative bootstrap guide for testnet validation during this work.
  Rationale: it is the actual file shipped in the repo, and it already captures the required boot-wallet, shared-chainspec, `HEGEMON_SEEDS`, and NTP/chrony invariants for fresh-testnet testing.
  Date/Author: 2026-03-12 / Codex

- Decision: ship the first V5 cut as a real two-level tree (`leaf` or `merge-over-leaf`) before generalizing to merge-of-merge recursion.
  Rationale: the immediate throughput acceptance target in the user’s plan is `tx_count=32` and `64`, which fit exactly inside an `8 x 8` leaf/merge tree. General multi-merge recursion requires another layer of node/public-value plumbing in the recursive batch verifier and would have blocked the usable cutover already implemented in circuits/consensus.
  Date/Author: 2026-03-12 / Codex

- Decision: drive the circuit redesign from direct `hegemon-prover` leaf/merge benchmarks before returning to the node-level throughput harness.
  Rationale: the early `32 tx` harness runs only showed that all leaves were inflight and none finished. The direct circuit benchmarks immediately exposed the actual leaf cost structure, the two-level tree-capacity limit, and the merge-stage backend mismatch.
  Date/Author: 2026-03-12 / Codex

- Decision: treat the 6-element outer batch config as a proving-path prototype only until the same config and public-input packing are wired consistently into merge proving and consensus verification.
  Rationale: the prototype removed the old digest-arity crash and proved the merge stage can enter real work, but it also revealed a second blocker (`PublicInputLengthMismatch`) before a merge proof could complete. That makes it evidence for the next design step, not a finished cutover.
  Date/Author: 2026-03-12 / Codex

- Decision: keep the canonical private-target refactor in aggregation, but revert the selective-DSU lowerer experiment after it failed to change the merge overlap class.
  Rationale: resolving through `expr_to_widx` plus overlap diagnostics is aligned with the intended vendor-owned target/value APIs and compiles cleanly. The DSU flip changed runtime behavior but did not remove the `WitnessInput`/`Unconstrained`/`Add(out)` overlap, so it was noise rather than progress and should not stay in-tree.
  Date/Author: 2026-03-12 / Codex

- Decision: keep the new fast recursion-layer consistency tests, but leave the generic Goldilocks D2 recursive batch-verifier repro ignored until the backend mismatch is fixed.
  Rationale: the passing hash/MMCS/challenger tests narrow the live bug to the recursive batch-verifier wiring, and the ignored repro cuts iteration time from minutes to seconds without breaking normal workspace test runs.
  Date/Author: 2026-03-12 / Codex

- Decision: keep the new generic Goldilocks D2 recursive batch-verifier repro as a normal unit test now that it passes.
  Rationale: that test is the shortest high-signal regression guard for the bug that previously blocked `merge(2 leaves)`, and it now completes in seconds rather than minutes.
  Date/Author: 2026-03-12 / Codex

- Decision: move the default two-level recursion lane to `leaf_fanin=4`, `merge_fanin=8`, tx recursion `queries/log_blowup=2/2`, and outer aggregation `queries/log_blowup=2/2`.
  Rationale: the direct `hegemon-prover` leaf sweep showed `fan_in=4`, `queries=2`, `log_blowup=2` is the best current leaf profile that still supports the intended two-level throughput target, while the old `8 x 8` fallback was both slower and, in the harness, often not actually the configured shape.
  Date/Author: 2026-03-13 / Codex

## Outcomes & Retrospective

The circuit and consensus cutover is now partially landed. The repository compiles with a V5 aggregation payload, leaf proofs recurse over fixed-size transaction-proof groups, merge proofs recurse over fixed-size batches of leaf proofs, and consensus rejects V4 by default unless `HEGEMON_AGG_LEGACY_V4=1` is explicitly set. The block-import metadata path also now expects real leaf-tree metadata instead of the old hard-coded `tree_levels=1` / `leaf_count=1` stub.

The node-side DAG now exists in the working tree and compiles: the coordinator publishes leaf and merge stage payloads, the standalone worker accepts those payloads, and local workers execute the same leaf/merge prove helpers before the coordinator assembles the final `CandidateArtifact` itself. The remaining gap is broader validation rather than missing code paths: run the strict integration/throughput harnesses and tighten any behavioral regressions that show up there.

The new experimental result is that the architecture is still blocked at the circuit layer, but the blocker is now concrete. The leaf stage has a credible direction: recursion-specific tx proofs plus `fan_in=4`, `queries=2`, `log_blowup=2` are the best numbers so far that still fit the intended `32/64` target with a larger merge arity. The merge stage, however, is not converged. On the legacy outer backend it fails immediately because the recursive Goldilocks merge verifier expects 6-element digests and the batch prover emits 4. On the prototype 6-element outer backend it burns `~480s` building merge cache/common data and then fails because child outer-proof public values are packed incorrectly. The next successful milestone is therefore not “more workers” or “more scheduler work”; it is a merge proof that completes on `hegemon-prover` for a feasible `32/64`-tx tree shape.

The latest refinement is that merge public-input packing is no longer the first failure. The prototype path now reaches `runner.run()` on a small merge case after public-input length and witness-assignment-plan length both line up. The remaining blocker is a witness conflict inside the merge circuit, which means some merge verifier targets are still being populated with values that do not respect the circuit’s connected witness structure. That is the current place where the recursive architecture remains unrealized.

The newest execution result is more concrete than that earlier summary. Aggregation now resolves leaf and merge witness plans from the recursive layer’s canonical private targets rather than from hand-maintained op-order flatteners, and the crate still compiles. The minimal release merge profile continues to fail, but the failure is now pinned to a specific overlap class: most merge private targets after the commitment prefix map to witness ids that are simultaneously direct proof inputs, inputs to `Unconstrained` hint gadgets, and later `Add(out)` rows in the compiled circuit. A temporary filter that skipped those rows proved they are genuinely required before the hint gadget runs, so the remaining bug is below aggregation packing, in how the recursion/lowering backend treats those proof-fed rows.

The latest narrowing step shows the failure is generic to the recursive batch verifier for Goldilocks extension-degree-2 circuit-table proofs, not to the leaf aggregation circuit itself. A tiny vendored unit repro now fails on the same “first commitment digest copy mismatch” in about ten seconds, while the low-level Goldilocks-12 Poseidon2 and extension-MMCS checks pass. That means the remaining bug sits in the recursive batch-verifier/FRI wiring between those primitives, not in the primitives themselves.

That generic recursive batch-verifier bug is now fixed. The vendored unit repro over a tiny Goldilocks D2 circuit-table proof passes, the merge prover’s single-child release roundtrip now proves and verifies through consensus, and the original `merge(2 leaves)` proving path reaches `v5_merge_runner_run` and `v5_merge_outer_prove` successfully. The remaining work is broader validation and throughput reruns, not the original commitment-root backend mismatch.

The latest result is that the original failing `merge(2 leaves)` shape now completes as a full cold/warm prove-and-verify roundtrip in the existing release profile harness. At this point the recursive aggregation tree works through the merge stage on real batch proofs with consensus verification using the same outer-proof config as the prover.

The broader validation result is now less blocked than it was. The recursive aggregation backend is still working on larger merge shapes inside the release circuit harness, and the node-level proofless submission failure turned out not to be a recursive/proofless logic bug after all. The immediate local blocker was a stale shared chainspec artifact: `config/dev-chainspec.json` still encoded an older runtime and `InlineRequired` proof availability. After refreshing that spec from the current binary, proofless sidecar submissions are accepted again on the easy local chain.

The remaining node-level gap is therefore narrower. The strict tmux throughput wrapper no longer dies at the first proofless sidecar submission; it now reaches the “waiting for local prepared batch” phase on the refreshed easy chainspec. The next debugging/validation target is prepared-batch latency and strict-wrapper completion, not proofless pool admission.

## Context and Orientation

The current producer path spans three crates and one node service layer.

`circuits/aggregation/src/lib.rs` currently produces `AggregationProofV4Payload` and a single `prove_aggregation(...)` routine that verifies all transaction proofs directly inside one recursion circuit. Its cache keys still depend on `tx_count`, and prewarm targets still derive from batch size rather than the exact leaf and merge shapes that a fixed-fan-in tree needs.

`consensus/src/aggregation.rs` currently decodes and verifies only V4 payloads. It derives `tx_statements_commitment` from the packed recursion public values and rebuilds one verifier cache keyed by `(tx_count, pub_inputs_len, log_blowup, shape)`.

`node/src/substrate/prover_coordinator.rs`, `node/src/substrate/rpc/prover.rs`, and `node/src/bin/prover_worker.rs` already expose a stage-work API. Today that API is misleading for the recursive path: external `leaf_batch_prove` packages exist, but they still expect `CandidateArtifact` submissions rather than stage-specific leaf/merge outputs, and the worker binary only knows how to build a full root payload. `node/src/substrate/service.rs` still prepares a `MergeRoot` artifact by calling `build_merge_root_proof_from_materials(...)`, which calls the monolithic `prove_aggregation(...)`.

Terms used in this plan:

- A “leaf aggregation proof” is a recursive proof that verifies up to `HEGEMON_AGG_LEAF_FANIN` transaction STARK proofs. In this branch the default fan-in is `8`, and incomplete leaves are padded deterministically.
- A “merge aggregation proof” is a recursive proof that verifies up to `HEGEMON_AGG_MERGE_FANIN` child aggregation proofs. The child proofs may be leaf proofs or lower-level merge proofs, but every merge shape is keyed by child shape rather than by live candidate size.
- “Root assembly” means building the final `CandidateArtifact` after the final merge proof already exists. It should generate the commitment proof and package the root recursive proof; it should not perform the heavy recursion proving itself.
- The “leaf manifest commitment” is a composable hash over the ordered leaf descriptors for a candidate. It lets consensus and root assembly bind the recursive tree to canonical transaction order without keeping the old monolithic direct-verifier semantics.

## Plan of Work

The implementation proceeds in five technical slices.

First, replace the monolithic V4 payload path in `circuits/aggregation` with a V5 node model. Add `AggregationProofV5Payload` plus explicit `AggregationNodeKind` values for `leaf` and `merge`. Refactor the prover internals so there are two cache-entry builders: one that verifies fixed-fan-in transaction proofs, and one that verifies fixed-fan-in child aggregation proofs using the vendored batch-recursion API. The leaf cache key must be shape-based `(node_kind=leaf, fan_in, inner_tx_shape, pub_inputs_len, log_blowup)` and the merge cache key must be shape-based `(node_kind=merge, fan_in, child_shape_id, child_public_inputs_len)`. Add `prove_leaf_aggregation(...)`, `prove_merge_aggregation(...)`, and exact-shape thread-local prewarm helpers.

Second, hard-cut `consensus/src/aggregation.rs` to V5 by default. Keep V4 decode and verification only behind an explicit environment gate for rollback. The verifier must understand both node kinds so coordinator-side and unit tests can verify leaf, merge, and root payloads. Root verification must derive the canonical statement commitment from the recursively packed public values, reject mismatched `child_count`, `tree_levels`, `shape_id`, or `tx_statements_commitment`, and reject V4 on the fresh chain when the legacy gate is absent.

Third, rework the coordinator into a real proving DAG. Candidate scheduling still begins from the ordered shielded transaction set, but instead of publishing decorative leaves plus one root package, it must materialize leaf packages over contiguous proof slices, wait for leaf completions, publish deterministic merge packages, and only when the final merge result exists perform local root assembly into a prepared `CandidateArtifact`. The state machine must preserve expiry and rate limits while treating stale or rejected packages as ordinary churn instead of fatal worker errors.

Fourth, extend the prover RPC and worker binary for stage-specific payloads. `node/src/substrate/rpc/prover.rs` needs additive payload objects for `leaf_batch_prove` and `merge_node_prove`. The worker binary must dispatch on `stage_type`, prove the requested node, submit a typed stage result, and keep polling when a package is stale or rejected. `root_finalize` should become local-only unless the implementation discovers an unavoidable dependency that still needs it externalized.

Fifth, update docs and scripts. `DESIGN.md` and `METHODS.md` must describe the V5 tree semantics, exact-shape prewarm, and the fact that `FlatBatches` is optional compatibility rather than the main scaling lane. `scripts/throughput_sidecar_aggregation_tmux.sh` must enable blocking prewarm when `HEGEMON_TP_AGG_PREWARM_MAX_TXS > 0` and widen the RPC wait accordingly. Operator-facing notes must continue to repeat the approved `HEGEMON_SEEDS` rule and the NTP/chrony requirement from `config/testnet-initialization.md`.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement and iterate on the aggregation/prover/consensus code:

    cargo test -p aggregation-circuit --tests aggregation -- --nocapture
    cargo test -p consensus aggregation -- --nocapture
    cargo test -p hegemon-node prover_coordinator -- --nocapture
    cargo test -p hegemon-node prover_rpc -- --nocapture

    For direct remote circuit profiling on `hegemon-prover`, use:

    ssh hegemon-prover 'source ~/.cargo/env && cd ~/Hegemon-codex-bench && \
      HEGEMON_AGG_PROFILE=1 \
      HEGEMON_AGG_LEAF_FANIN=4 \
      HEGEMON_AGG_MERGE_FANIN=16 \
      HEGEMON_TX_RECURSION_NUM_QUERIES=2 \
      HEGEMON_TX_RECURSION_LOG_BLOWUP=2 \
      HEGEMON_AGG_OUTER_NUM_QUERIES=2 \
      HEGEMON_AGG_OUTER_LOG_BLOWUP=2 \
      HEGEMON_AGG_PROVER_THREADS=1 \
      HEGEMON_AGG_LEVEL_PARALLELISM=1 \
      HEGEMON_AGG_COMMON_LOOKUP_THREADS=1 \
      cargo test -p aggregation-circuit --test aggregation aggregation_v5_merge_cold_warm_profile \
        --release -- --ignored --nocapture'

2. Validate the worker and stage loop on a local dev chain:

    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

3. Exercise the strict proofless path with the throughput harness using the fresh-testnet bootstrap assumptions from `config/testnet-initialization.md` when moving beyond a local `--dev` node.

4. If the full workspace remains green after targeted fixes, run:

    make check

## Validation and Acceptance

Acceptance for this cutover is behavior, not just compiled code.

`circuits/aggregation` must have tests that round-trip a leaf V5 proof for fan-in `8`, a merge V5 proof for fan-in `8`, a root verification path over a two-level tree, and cache prewarm that produces a cache hit on second use.

`consensus` must verify V5 leaf, merge, and root payloads, reject V4 by default, and reject malformed `child_count`, `tree_levels`, `shape_id`, and `tx_statements_commitment`.

`node` tests must prove that the coordinator creates `ceil(tx_count / leaf_fanin)` leaf packages, turns completed leaves into deterministic merge packages, assembles a final `CandidateArtifact` after the merge root is ready, allows the external worker to consume leaf and merge packages, and keeps the worker loop alive when a package has gone stale.

Integration acceptance is a strict proofless batch that produces a prepared artifact before timeout, plus throughput runs where prepared-bundle latency improves as external worker count increases for `tx_count=32` and `tx_count=64`.

## Idempotence and Recovery

These changes are source-only and safe to rerun. Use `--dev --tmp` or explicit temporary base paths for all local node runs so retries do not require hand-cleaning persistent chain state. If the fresh-testnet validation moves onto a shared chainspec, follow `config/testnet-initialization.md`: do not improvise wallets, use the laptop-created boot-wallet address as the payout address everywhere, keep the same `config/dev-chainspec.json` on every host, keep the exact approved `HEGEMON_SEEDS` list on all miners and provers once the fresh rollout publishes it, and keep NTP/chrony enabled because future-skewed PoW timestamps are rejected.

If rollback is required during implementation, the safe fallback is the explicit V4 legacy gate in consensus rather than silently accepting both formats by default.

## Artifacts and Notes

Important file paths for this cutover:

- `circuits/aggregation/src/lib.rs`
- `circuits/aggregation/tests/aggregation.rs`
- `consensus/src/aggregation.rs`
- `consensus/src/error.rs`
- `consensus/src/proof.rs`
- `node/src/substrate/prover_coordinator.rs`
- `node/src/substrate/rpc/prover.rs`
- `node/src/bin/prover_worker.rs`
- `node/src/substrate/service.rs`
- `scripts/throughput_sidecar_aggregation_tmux.sh`
- `config/testnet-initialization.md`

Evidence snippets and final command output will be appended here as milestones complete.

High-signal evidence from the current experiment loop:

    leaf_cold_warm_profile fan_in=4 cold_ms=131712 warm_ms=99431
    leaf_cold_warm_profile fan_in=2 cold_ms=66013 warm_ms=50219
    cold merge proof: CircuitBuild("CircuitBuilder(NonPrimitiveOpArity { op: \"verify_merkle_batch_circuit\", expected: \"goldilocks digest_elems=6\", got: 4 })")
    v5_merge_cache_lookup tx_count=16 cache_hit=false cache_build_ms=480204 cache_lookup_ms=480214 total_ms=483926
    cold merge proof: CircuitRun("PublicInputLengthMismatch { expected: 5917, got: 291 }")
    v5_merge_public_input_summary tx_count=2 expected_public_len=460 packed_public_len=460
    cold merge proof: CircuitRun("WitnessConflict { witness_id: WitnessId(507), ... }")

## Interfaces and Dependencies

The implementation must leave these interfaces in place:

- In `circuits/aggregation/src/lib.rs`, define:

    pub const AGGREGATION_PROOF_FORMAT_ID_V5: u8 = 5;
    pub enum AggregationNodeKind { Leaf, Merge }
    pub struct AggregationProofV5Payload { ... }
    pub fn prove_leaf_aggregation(...) -> Result<Vec<u8>, AggregationError>;
    pub fn prove_merge_aggregation(...) -> Result<Vec<u8>, AggregationError>;
    pub fn prewarm_leaf_and_merge_caches_from_env() -> Result<(), AggregationError>;

- In `consensus/src/aggregation.rs`, expose V5 verification entry points that accept the same top-level call sites used by `consensus/src/proof.rs`, and keep V4 support off by default behind an explicit environment check.

- In `node/src/substrate/rpc/prover.rs`, extend `WorkPackageResponse` with additive stage payload objects:

    pub leaf_batch_payload: Option<LeafBatchPayloadResponse>
    pub merge_node_payload: Option<MergeNodePayloadResponse>

- In `node/src/substrate/prover_coordinator.rs`, the work DAG must become stage-based and shape-based instead of monolithic root-only scheduling. Stage results must distinguish leaf recursive proofs, merge recursive proofs, and final assembled artifacts.

- In `node/src/bin/prover_worker.rs`, dispatch must handle `leaf_batch_prove` and `merge_node_prove` and keep looping on stale/rejected work instead of exiting.

Plan update note (2026-03-12 10:31Z / Codex): Created this ExecPlan before implementation so the recursive-tree cutover has a self-contained execution record separate from the broader permissionless-scaling plan.
Plan update note (2026-03-12 08:50Z / Codex): Added the `hegemon-prover` experiment results, including the leaf parameter sweep, the legacy merge digest-arity failure, and the prototype 6-element outer-config run that exposed the next blocker in child outer-proof public-input packing.
Plan update note (2026-03-12 20:47Z / Codex): Recorded the canonical private-target refactor in aggregation, the minimal release merge reruns, and the concrete remaining blocker: merge private targets still overlap `WitnessInput`, `Unconstrained`, and later `Add(out)` rows in the lowered recursion backend.
Plan update note (2026-03-12 21:38Z / Codex): Added the fast recursion-layer consistency tests and the ignored generic Goldilocks D2 repro, and recorded that the remaining failure sits above Poseidon2/MMCS primitives but below aggregation packing.
Plan update note (2026-03-12 22:57Z / Codex): Recorded the recursive batch-verifier fix (native batch observation order + native domain handling), the consensus outer-proof config alignment, and the passing one-child release merge roundtrip.
Plan update note (2026-03-12 23:23Z / Codex): Recorded the passing two-child release merge roundtrip with consensus verification, which closes the original `merge(2 leaves)` backend blocker.
Plan update note (2026-03-12 23:23Z / Codex): Recorded the broader validation pass: larger release merge shapes are green, but the local proofless throughput harness now fails earlier on unsigned sidecar admission with `InvalidTransaction::BadProof`.
