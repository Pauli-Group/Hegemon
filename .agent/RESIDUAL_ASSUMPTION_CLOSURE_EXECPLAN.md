# Close Residual Assumptions With Mechanized Refinement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon's formal matrix now reaches 100% by making remaining assumptions explicit. The next standard is to reduce the non-standard assumptions themselves. After this plan is complete, parser, native-node, proof-system, and bridge gaps will be mechanized refinement obligations with Lean theorem surfaces and Rust conformance gates; primitive cryptographic hardness will stay as named assumptions; and DA retention, storage durability, global privacy, release infrastructure, scanner completeness, and performance preservation will be enforced by fail-closed gates and monitoring rather than informal prose.

The visible outcome is that `bash scripts/check_formal_core.sh` fails if any residual is downgraded from one of three permitted categories: mechanized refinement work, named cryptographic assumption, or fail-closed system-model assumption. A developer can inspect `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`, this ExecPlan, `config/formal-security-claims.json`, `config/formal-security-blueprint.json`, and `config/highest-standard-formal-verification-matrix.json` to see the status.

## Progress

- [x] (2026-06-18 18:55Z) Added `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`, a Lean theorem surface that classifies residuals into mechanized parser/native/proof/bridge tracks, named primitive cryptographic assumptions, and fail-closed system-model assumptions.
- [x] (2026-06-18 18:56Z) Imported the new module through `formal/lean/Hegemon.lean` and built `cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon`, which completed 173 jobs successfully.
- [x] (2026-06-18 19:03Z) Registered the new roadmap in `config/formal-security-claims.json` and `config/formal-security-blueprint.json`.
- [x] (2026-06-18 19:05Z) Updated `DESIGN.md`, `METHODS.md`, `formal/lean/README.md`, and `config/highest-standard-formal-verification-matrix.json` so the status is discoverable without reading Lean source.
- [x] (2026-06-18 19:11Z) Ran metadata gates: `jq empty`, `check-claims`, `check-blueprint`, and `git diff --check` all passed.
- [x] (2026-06-18 19:25Z) Ran `bash scripts/check_lean_formal.sh`; it passed with 2413 theorem declarations, 1056 axiom-free theorem declarations, 1357 declarations depending only on waived kernel axioms, and zero temporary axiom theorem leaks.
- [x] (2026-06-18 19:28Z) Committed the roadmap slice as `d04a4b95 Classify residual assumptions for closure`.
- [x] (2026-06-18 19:55Z) Added `Hegemon.Release.SystemModelAssumptionGate`, `config/system-model-assumption-gates.json`, and the formal-core `check-system-model-gates` command so DA/storage/global-privacy/release/scanner/performance residuals are release-blocking fail-closed evidence gates instead of prose.
- [x] (2026-06-18 20:08Z) Validated the system-model gate slice: targeted Lean build passed over 174 jobs; `bash scripts/check_lean_formal.sh` passed with 2417 theorem declarations and zero temporary axiom theorem leaks; `cargo test --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml` passed 121 tests; `check-system-model-gates`, `check-formal-inventory`, `check-claims`, `check-blueprint`, JSON validation, rustfmt check, and `git diff --check` passed.
- [x] (2026-06-18 20:10Z) Committed the system-model gate slice as `990288aa Gate system-model assumptions fail-closed`.
- [x] (2026-06-18 20:08Z) Added a native metadata bincode parser-oracle milestone: production current/legacy `NativeBlockMeta` exact decode is checked against an independent fixint/full-consumption/canonical-reencode oracle over valid, trailing, truncated, noisy, oversized, action-overrun, payload-overrun, and miner-field-overrun byte cases, and `scripts/check_formal_core.sh` now runs that gate.
- [x] (2026-06-18 20:08Z) Validated the native metadata parser-oracle slice: JSON validation, rustfmt check, focused native metadata oracle test, shell syntax, whitespace check, formal inventory, `check-claims`, and `check-blueprint` all passed; blueprint now records 622 falsification cases with the new parser-oracle case.
- [x] (2026-06-18 20:35Z) Added a bridge mint-payload refinement milestone: `BridgeMintPayloadV1` is a versioned fixed-field SCALE payload, `Hegemon.Bridge.MintPayloadAdmission` proves the decoded admission table, Lean generates conformance vectors, formal-core runs the Rust vector gate, and the verified receipt handoff exact-decodes/admission-checks the payload before the still-disabled mint/replay policy.
- [x] (2026-06-18 20:40Z) Validated the bridge mint-payload slice with targeted Lean build, generated-vector JSON validation, Rust vector conformance, malformed-payload/invalid-field regressions, verified-receipt handoff regressions, and rustfmt.
- [x] (2026-06-18 23:31Z) Added a mined-block commit publication refinement milestone: `Hegemon.Native.MinedBlockCommitPublication` now has an executable rejection table and generated vectors that bind the composed production helper order for mined publication: mined-work freshness, block commitment, mined-manifest kind, then atomic manifest shape.
- [x] (2026-06-18 23:33Z) Validated the mined-block commit publication slice with targeted Lean build, generated-vector JSON validation, Rust conformance over `node/src/native/mod.rs` helper calls, and rustfmt.
- [x] (2026-06-18 23:51Z) Ran the full formal-core gate after wiring the generated mined-block commit publication vector test; `bash scripts/check_formal_core.sh` passed through Lean axiom audit, generated Rust conformance vectors, claims, blueprint, system-model gates, native backend vectors, and release-posture checks.
- [x] (2026-06-19 00:54Z) Added a block-action replay publication refinement milestone: `Hegemon.Native.BlockActionReplayPublication` now has an executable rejection table and generated vectors that bind the composed production helper order for decoded action publication: block-action validation, block replay, wire replay projection, validation/wire action-count agreement, wire/replay action-count agreement, validation/wire bridge replay-count agreement, then replay/wire bridge replay-count agreement.
- [x] (2026-06-19 00:54Z) Validated the block-action replay publication slice with targeted Lean build, generated-vector JSON validation, Rust conformance over `node/src/native/mod.rs` helper calls, claim/blueprint/inventory checks, and the full `bash scripts/check_formal_core.sh` wrapper.
- [x] (2026-06-19 01:24Z) Added a pending-action field projection vector milestone: `Hegemon.Native.PendingActionFieldProjectionVectors` now emits sidecar/bridge/candidate/cumulative-index row-order and row-content vectors, and the Rust gate checks production block-action exact decode, sidecar materialization, canonical index rebuild, commitment/nullifier/bridge replay/ciphertext index rows, and ciphertext archive rows against the generated projection.
- [x] (2026-06-19 01:24Z) Validated the pending-action field projection vector slice with targeted Lean build, generated-vector JSON validation, and the focused `lean_generated_pending_action_field_projection_vectors_match_production` Rust gate.
- [x] (2026-06-19 02:35Z) Added an action-request raw JSON projection milestone: `Hegemon.Native.ActionRequestRawJsonProjection` now emits representative `hegemon_submitAction` request byte strings for valid outbound bridge ingress and parser/projection rejects, and the Rust gate drives those bytes through serde_json, strict `SubmitActionRpcRequest` decoding, base64 decoding, and exact route-payload admission.
- [x] (2026-06-19 02:38Z) Validated the raw JSON projection slice with targeted Lean build, generated-vector JSON validation, and the focused `lean_generated_action_request_raw_json_projection_vectors_match_production` Rust gate.
- [x] (2026-06-19 05:21Z) Validated the deployed branch on hegemon-dev at `d81c874b`: remote full `bash scripts/check_formal_core.sh` passed with 121 claims, 2533 named Lean theorem declarations, 111 production-eligible claims, 50 residual risks, 637 falsification cases, 228 implementation bindings, 174 result obligations, 151 theorem-indexed order constraints, and 136 theorem-indexed dominance constraints.
- [x] (2026-06-19 05:27Z) Rebuilt and restarted the hegemon-dev release service from `target/release/hegemon-node`; RPC/P2P listened on 127.0.0.1:9944/0.0.0.0:30333, live mining advanced height 18854 to 18859 over 20 seconds, wallet transaction submission smoke passed, isolated single-node mining reached height 1, isolated two-node restart/sync caught the follower from height 16 to 32 while the miner reached 39, NTP was active, and cleanup left only the systemd release node running.
- [x] (2026-06-19 06:20Z) Added a DA sidecar upload raw JSON projection milestone: `Hegemon.Native.SidecarUploadRawJsonProjection` now emits representative `da_submitCiphertexts`/`da_submitProofs` request byte strings for valid ciphertext upload, malformed JSON, unknown fields, missing/non-array upload fields, too-many arrays, invalid ciphertext/proof bytes, proof metadata failures, and empty proof bytes. Production `NativeNode::submit_ciphertexts` and `NativeNode::submit_proofs` now strict-decode request structs with `serde(deny_unknown_fields)` before admission/staging, and the generated Rust gate drives the Lean bytes through serde_json, strict request decoding, byte parsing, and sidecar admission order.
- [x] (2026-06-19 06:25Z) Validated the DA sidecar raw JSON slice with targeted Lean build, generated-vector JSON validation, the focused `lean_generated_sidecar_upload_raw_json_projection_vectors_match_production` Rust gate, rustfmt check, existing sidecar upload regressions, submit-ciphertexts rejection regressions, submit-proofs rejection regressions, and the full local `bash scripts/check_formal_core.sh` wrapper. Full formal-core reported 121 claims, 2551 named Lean theorem declarations, 111 production-eligible claims, 50 residual risks, 638 falsification cases, 230 implementation bindings, 176 result obligations, 151 theorem-indexed order constraints, 136 theorem-indexed dominance constraints, and 11 native backend vectors.
- [x] (2026-06-19 06:11Z) Deployed `a6de4a24` to hegemon-dev by git bundle without a GitHub push. Remote focused sidecar raw JSON Lean-vector conformance passed, `make node` rebuilt the release binary, systemd restarted successfully, live mining advanced height 18987 to 18991 over 20 seconds, wallet-send passed, malformed `da_submitCiphertexts` and `da_submitProofs` requests rejected with JSON-RPC `-32602` decode errors, final health was syncing=false at height 19001, and NTP was synchronized.
- [x] (2026-06-19 06:45Z) Added a P3 AIR balance final-row implementation-equivalence milestone: `GenerateAirBalanceBoundaryVectors.lean` emits default and stablecoin final-row surfaces plus native-delta, selected-stablecoin-delta, selector-asset, disabled-metadata, nonselected-delta, and boolean-field rejection cases; `lean_generated_air_balance_boundary_vectors_match_production` compares valid cases against real P3 trace/public-input extraction and checks the modeled equations before `p3_air_balance_public_field_mutations_rejected` runs.
- [x] (2026-06-19 06:34Z) Deployed `247638ff` to hegemon-dev by git bundle without a GitHub push. Remote focused AIR balance Lean-vector conformance passed: `lake exe gen_air_balance_boundary_vectors` produced valid JSON and `cargo test -p transaction-circuit lean_generated_air_balance_boundary_vectors_match_production --lib -- --nocapture` passed against the VPS checkout.
- [x] (2026-06-19 06:49Z) Added a raw bridge mint-payload refinement milestone: `Hegemon.Native.BridgeMintPayloadRawAdmission` now lifts decoded mint-payload policy through exact SCALE decode, full byte consumption, and canonical re-encoding of raw `BridgeMintPayloadV1` bytes; `lean_generated_bridge_mint_payload_raw_admission_vectors_match_production` checks valid, malformed, trailing, hash, receipt-message, version, destination, recipient, amount, and asset fixtures against production byte decoding and admission.
- [x] (2026-06-19 06:56Z) Deployed `fdbc885f` to hegemon-dev by git bundle without a GitHub push. Remote focused raw bridge mint-payload Lean-vector conformance passed, RPC health was non-syncing, NTP was synchronized, and `hegemon_miningStatus` reported mining active with one thread and approximately 11 kH/s; no block was found during the final 30-second sample, so the evidence is active-miner status rather than block-production advancement.
- [x] (2026-06-19 08:09Z) Added an active-goal progress measurement gate before unpausing the paused Codex goal. `config/active-goal-progress.json` records the goal thread id, paused status at measurement, fixed theorem-property set, 100.0% weighted completion under the matrix method, and the explicit assumption boundary; `scripts/hegemon_formal_core` now exposes `check-active-goal-progress`, and `scripts/check_formal_core.sh` runs it as a formal-core step.
- [ ] For later milestones, replace each mechanized-track proposition with deeper theorem packages and generated Rust conformance gates.

## Surprises & Discoveries

- Observation: The highest-standard completion certificate already has broad external assumption fields, but it did not classify which residuals are supposed to be closed by further mechanization versus which are legitimate cryptographic or system-model assumptions.
  Evidence: `Hegemon.Release.HighestStandardCompletionCertificate.ExternalSecurityAssumptionBundle` carries parser, proof, storage, DA, native-node, primitive crypto, privacy, bridge, release, and performance fields in one bundle.
- Observation: The hegemon-dev formal-core failure was not a consensus regression; `scripts/test-node.sh` was reusing a stale default `target/debug/hegemon-node` when the binary already existed. Remote tracing also emitted ANSI escapes into the SIGTERM log, making exact grep checks brittle.
  Evidence: remote SIGTERM smoke initially exited 143 before rebuild; after forced default rebuild the node logged `signal="sigterm"` and `operation="shutdown_flush"`, but exact grep failed until the matcher tolerated ANSI formatting.
- Observation: The first DA sidecar raw JSON conformance run found a modeled projection mismatch: when `binding_hash` is absent, production also observes `binding_hash_valid = false` even though the first rejection remains `proofBindingHashMissing`.
  Evidence: `lean_generated_sidecar_upload_raw_json_projection_vectors_match_production` initially failed on `missing-proof-binding-hash-raw-upload-rejected`; the Lean fixture was corrected and the generated gate then passed.

## Decision Log

- Decision: Add a new release-level roadmap module instead of editing the completion certificate directly.
  Rationale: The completion certificate is the 100% closure artifact; changing its shape would ripple through many existing theorem calls. A sibling roadmap theorem keeps the current certificate stable while making the next assurance frontier machine-checkable.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat parser/native/proof/bridge residuals as mechanized refinement tracks, not as acceptable permanent assumptions.
  Rationale: These are implementation-equivalence gaps inside the Hegemon codebase. They should be burned down by Lean specs, generated vectors, and Rust gates.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat primitive cryptography and proof-system hardness as named assumptions until full cryptographic reductions are available.
  Rationale: Proving ML-KEM, ML-DSA, BLAKE-family transcript security, STARK/FRI/PCS soundness, ciphertext indistinguishability, and OS RNG quality inside the repo is a cryptographic research project. The honest highest standard is to name, review, and gate them.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat DA retention, storage/fsync behavior, global privacy, release infrastructure, scanner completeness, and performance preservation as system-model assumptions with fail-closed gates and monitoring.
  Rationale: These depend on operators, networks, disks, cloud hosts, GitHub enforcement, advisory feeds, traffic behavior, and benchmarking. Lean can prove fail-closed policy and checked evidence consumption, not universal environmental honesty.
  Date/Author: 2026-06-18 / Codex

- Decision: Default smoke runs rebuild the repo-local `target/debug/hegemon-node`; explicit `HEGEMON_NODE_BIN` remains an external-binary override.
  Rationale: Branch validation must execute the current checkout by default, while release-binary smoke still needs an explicit opt-in path.
  Date/Author: 2026-06-19 / Codex

## Outcomes & Retrospective

This first slice converts the user-facing classification into a Lean theorem surface and makes the next milestones explicit. It does not yet close the deep parser/native/proof/bridge gaps; it prevents them from being mislabeled as ordinary cryptographic assumptions.

The second slice starts closing the fail-closed system-model bucket by adding a theorem-backed release gate and formal-core checker for DA retention, storage durability, global privacy boundary, release infrastructure, dependency scanner completeness, and performance budget monitoring evidence.

The third slice starts burning down the parser mechanized-refinement bucket at a concrete trust boundary: native metadata exact decode now has an independent arbitrary-byte/mutation oracle gate. This narrows parser drift around current-first/legacy-fallback bincode metadata acceptance while keeping bincode implementation correctness itself outside the claim.

The fourth slice starts burning down the bridge mechanized-refinement bucket at the future mint boundary: a verified receipt can no longer carry arbitrary bytes as the would-be mint instruction. It must exact-decode as `BridgeMintPayloadV1` and pass a theorem/vector-checked decoded admission table before hitting the disabled mint authorization gate. This still does not enable positive bridge minting or prove external receipt soundness.

The hegemon-dev validation slice closed a real deployment-evidence gap: remote formal-core now executes the current checkout, and the deployed release node was rebuilt/restarted and observed mining with wallet submission and restart/sync smokes green. This is validation/harness hardening, not a new cryptographic theorem.

The DA sidecar upload raw JSON slice narrows a native/parser trust boundary: the unsafe DA staging RPCs now reject unknown request/item fields through strict request structs, and formal-core owns representative raw ingress byte strings before any staged rows can be prepared. This is a real production hardening plus conformance gate, while complete serde_json/base64/hex parser correctness, RPC exposure safety, DA availability, and native tx-leaf proof soundness remain explicit assumptions.

The P3 AIR balance final-row slice narrows a proof/AIR implementation-equivalence boundary: Lean now owns representative final-row surfaces and rejection equations, while Rust derives the accepted surfaces from the production P3 trace plus verifier-facing public inputs. This still keeps STARK/FRI/PCS soundness, witness extraction, hash security, and full verifier implementation correctness as named proof-system assumptions.

The active-goal progress measurement slice turns the paused-goal percentage into checked repository state. The percentage is now recomputed from the theorem matrix, and formal-core rejects stale percentages, missing highest-standard property rows, wrong weights, completed rows that still list missing work, completed rows without evidence, or completed rows without explicit external assumptions. This does not create new security proof coverage; it prevents progress accounting from drifting away from the proof matrix before the goal is resumed.

## Context and Orientation

The repository's current formal-verification status is tracked in `config/highest-standard-formal-verification-matrix.json`. The top-level Lean completion certificate lives at `formal/lean/Hegemon/Release/HighestStandardCompletionCertificate.lean`, and the new classification surface lives at `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`.

A mechanized refinement track means a gap should eventually be represented by a Lean executable specification plus production Rust conformance. Parser refinement covers arbitrary raw bytes and canonical decoding. Native-node refinement covers RPC/network ingress through replay, reorg, startup, sync, storage, and accepted publication. Proof/AIR refinement covers deployed proof objects, public statements, witness constraints, and verifier soundness boundaries. Bridge refinement covers PQ-clean receipt verification, decoded receipt grammar, replay-key uniqueness, and authorized mint publication.

A named cryptographic assumption means Hegemon relies on external hardness or soundness claims, such as ML-KEM/ML-DSA security, hash/transcript collision resistance, STARK/FRI/PCS soundness, ciphertext indistinguishability, external review of the native lattice backend, and OS RNG quality.

A fail-closed system-model assumption means Hegemon cannot prove the external world behaves honestly, but it can define evidence and rejection policies. DA availability, storage fsync semantics, global traffic-analysis privacy, release infrastructure enforcement, dependency scanner completeness, and performance budgets belong here.

## Plan of Work

First, keep the classification theorem small and stable. The module `AssumptionClosureRoadmap.lean` defines three records: `MechanizedRefinementTracks`, `NamedPrimitiveCryptoAssumptions`, and `FailClosedSystemModelAssumptions`. The combined `ResidualAssumptionClosureRoadmap` exposes the three classes through named theorems. This is already implemented and builds.

Second, register the roadmap as a formal claim and blueprint node. The claim should cite the four theorem names in `AssumptionClosureRoadmap.lean`, the ExecPlan, the completion certificate, and the matrix. The blueprint node should depend on `formal.highest-standard-completion-certificate` and explain that this node is a classifier and ratchet, not a claim that the deep residuals are already discharged.

Third, update docs. `DESIGN.md` and `METHODS.md` should state that residuals are now split into mechanized tracks, named crypto assumptions, and fail-closed system-model assumptions. `formal/lean/README.md` should point readers to the new module.

Fourth, implement deeper milestones one at a time:

- Parser milestone: for every trust-boundary type still using partial exact-decode evidence, define a bounded Lean byte grammar, generate round-trip/rejection vectors, and add arbitrary-byte oracle corpora. Acceptance is a passing formal-core gate plus a reduced parser residual list in the matrix.
- Native-node milestone: define a raw-ingress-to-publication transition relation covering RPC/network bytes, pending actions, staged sidecars, block imports, reorgs, startup reload, sync, and storage publication. Acceptance is a theorem that accepted publication refines the transition relation plus Rust gates for each ingress family.
- Proof/AIR milestone: split cryptographic STARK/FRI assumptions from concrete AIR-to-Hegemon-statement constraints. Acceptance is a theorem that deployed public inputs, witness rows, balance, authorization, nullifiers, Merkle paths, ciphertext hashes, and stablecoin exceptions imply the transaction relation, with STARK/FRI soundness left as a named assumption.
- Bridge milestone: keep positive inbound minting disabled until a PQ-clean receipt verifier exists. Then bind decoded receipt bytes, verifier output, replay keys, external-chain assumptions, amount/range authorization, and native mint publication into one theorem surface.
- System-model milestone: add fail-closed gates for DA retention evidence, storage durability barriers, privacy telemetry/leakage budgets, branch-protection/export checks, dependency scanner freshness, and performance budgets.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

To build the new Lean module:

    cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon

Expected result:

    Built Hegemon.Release.AssumptionClosureRoadmap
    Built Hegemon
    Build completed successfully

To validate metadata after registering the claim and blueprint node:

    jq empty config/formal-security-claims.json config/formal-security-blueprint.json config/highest-standard-formal-verification-matrix.json
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-claims config/formal-security-claims.json
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-blueprint config/formal-security-blueprint.json --claims config/formal-security-claims.json

To run the full formal gate when a deeper milestone changes Rust or formal-core:

    bash scripts/check_formal_core.sh

## Validation and Acceptance

This first slice is accepted when `lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon`, `bash scripts/check_lean_formal.sh`, JSON validation, claim checking, blueprint checking, and `git diff --check` pass. A later implementation milestone is accepted only when its claim no longer lists the corresponding mechanized track as open or when that track is replaced by a theorem-backed, production-bound claim.

## Idempotence and Recovery

All edits are additive or metadata-only. Re-running the Lean build and metadata gates is safe. If a JSON edit fails validation, revert only the bad JSON hunk or regenerate the exact claim/node patch; do not reset unrelated branch work.

## Artifacts and Notes

The first successful Lean build transcript was:

    cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon
    Built Hegemon.Release.AssumptionClosureRoadmap
    Built Hegemon
    Build completed successfully (173 jobs).

## Interfaces and Dependencies

The first slice defines these theorem names:

    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_mechanized_refinement_tracks
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_named_primitive_crypto_assumptions
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_fail_closed_system_model_assumptions
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_splits_all_open_assumptions

Future claims and blueprint nodes should use these theorem names to keep the residual classification executable and indexed by formal-core.

The fifth slice narrows the deployed proof-artifact parser/refinement bucket at the SmallWood recursive envelope handoff. `Hegemon.Transaction.SmallWoodRecursiveEnvelopeWire` now models representative bincode envelope bytes, trailing/truncated/invalid-enum/truncated-proof-vector rejection, and descriptor equality before recursive proof verification. `gen_smallwood_recursive_envelope_wire_vectors` feeds a production `transaction-circuit` test over `decode_smallwood_recursive_proof_envelope_v1`, canonical reserialization, and descriptor matching. This keeps primitive proof-system soundness and bincode implementation correctness as named assumptions while turning the parser/descriptor handoff into a checked refinement gate.
- 2026-06-18: Added `CandidateArtifactScaleWire` as the next parser-internal refinement slice. The Lean model and generated Rust vectors now bind representative raw `CandidateArtifact` / `SubmitCandidateArtifactArgs` SCALE bytes to production exact decode for recursive-block-v2, receipt-root, custom proof-kind, trailing, truncated, invalid enum, noncanonical compact-prefix, recursive proof overrun, and receipt-count overrun cases. This narrows the candidate-artifact route-payload premise from a pure boolean admission field to a checked raw-byte conformance gate; arbitrary SCALE parser internals remain a separate refinement target.
- 2026-06-18: Added `SyncResponseImport` as the next native-node implementation-equivalence slice. The Lean model and generated Rust vectors now bind inbound sync response import control flow to production helpers: response-count admission before sort/import, deterministic sorted heights, bounded attempted/imported counters, stop-on-first-error behavior, impossible outcome-trace rejection, and continuation requests only for nonempty responses when the peer remains ahead. This narrows the native sync-response refinement gap while keeping peer honesty, network liveness, storage durability, and complete native-node equivalence explicit.
- 2026-06-18: Added `SmallWoodVerifierStatementProjection` as the next proof/AIR implementation-equivalence slice. Lean now models the deployed verifier-call projection from wrapper/public-statement/transcript admission through arithmetization, public values, row/packing/degree metadata, all linear-constraint vectors, auxiliary witness limb count, profile material, transcript bytes, proof-byte presence, and final verifier-result handoff. The generated Rust gate reconstructs the production `PackedStatement` verifier surface for normal and stablecoin inline-Merkle witnesses and checks every modeled drift case. This narrows verifier implementation equivalence while keeping STARK/AIR/PCS soundness, witness extraction, bincode correctness, hash security, and complete native-node refinement explicit.
- 2026-06-18: Added `GenerateMinedBlockCommitPublicationVectors` as a native-node publication refinement slice. The Lean model now exposes a mined-publication rejection table connected to the accepted publication facts, and the Rust gate checks the composed production order over existing helper calls. This narrows mined local-publication helper equivalence while keeping PoW threshold soundness, body/replay parser internals, sled/fsync behavior, and complete native-node refinement explicit.
- 2026-06-19: Added `GenerateBlockActionReplayPublicationVectors` as a native-node decoded-action publication refinement slice. The Lean model now exposes a block-action replay publication rejection table connected to the accepted publication facts, and the Rust gate checks the composed production order over existing validation, replay, and wire-projection helper calls. This narrows decoded-action publication helper equivalence while keeping arbitrary raw parser internals, proof-system soundness, hash/crypto implementation equivalence, sled/fsync behavior, and complete native-node refinement explicit.
- 2026-06-19: Added `GeneratePendingActionFieldProjectionVectors` as a pending-action production row-content refinement slice. The Lean model generates accepted row references for representative sidecar, inbound bridge, outbound bridge, candidate artifact, bridge-first, and two-sidecar cumulative-index action mixes; the Rust gate maps those fixtures to real `PendingAction` values and checks production exact decode, sidecar materialization, canonical index rebuild, commitment/nullifier/bridge replay/ciphertext index rows, and ciphertext archive rows. This narrows the validation/materialization/planning/canonical-row projection residual while keeping arbitrary parser-internal proof and complete native-node equivalence explicit.
- 2026-06-19: Hardened `InboundBridgeReceiptAdmission` as a bridge/native refinement slice. The Lean table now models the native `u32` confirmation-width boundary, proves the maximum representable confirmation count accepts, proves `u32::MAX + 1` rejects with `confirmationsOverflow`, and fixes overflow-before-underconfirmed precedence. Production `evaluate_native_inbound_bridge_receipt_admission` now uses checked arithmetic instead of saturating confirmation counts, with both generated Lean conformance vectors and a focused overflow regression. This closes a concrete bridge fail-open arithmetic gap while keeping external receipt/verifier soundness and positive mint authorization disabled as explicit residuals.
- 2026-06-19: Added `SyncBlockRangePublicationAdmission` as a native-node sync publication refinement slice. The Lean table now models outbound `block_range` publication facts for admitted range, served count, first/last heights, height continuity, previous-parent anchor, parent continuity, canonical-row verification, action-body verification, and rejection precedence. Production `NativeNode::block_range` evaluates the same helper before returning peer-visible rows, and formal-core generates vectors plus a concrete truncated/unanchored/unverified-row regression. This narrows sync response publication equivalence while leaving arbitrary parser internals, peer honesty/liveness, storage durability, and complete native-node refinement explicit.
- 2026-06-19: Added `ActionRequestRawJsonProjection` as a native RPC ingress refinement slice. The Lean model now owns representative raw JSON byte strings for valid outbound bridge submit-action ingress, malformed JSON, unknown fields, non-empty kernel-envelope fields, unsupported routes, non-transfer nullifiers, invalid transfer nullifier hex, invalid base64, and trailing route-payload bytes. The Rust gate reconstructs those exact bytes and runs production serde_json parsing, strict request decoding, base64 public_args decoding, and route-payload exact-decode admission. This narrows the raw JSON/base64 ingress predicate gap while keeping arbitrary parser implementation correctness, semantic payload validity, tx-leaf proof soundness, and complete native-node refinement explicit.
- 2026-06-19: Added `SidecarUploadRawJsonProjection` as a native DA upload ingress refinement slice. The Lean model now owns representative raw JSON byte strings for valid ciphertext upload, malformed upload JSON, unknown request/item fields, missing/non-array upload arrays, too-many ciphertext/proof arrays, invalid ciphertext/proof byte strings, missing/invalid proof metadata, and empty proof bytes. Production `da_submitCiphertexts`/`da_submitProofs` now decode through strict request structs before admission, and the generated Rust gate checks the derived projection facts and first-failure labels against Lean. This narrows the DA sidecar raw-ingress residual while keeping complete serde_json/base64/hex parser correctness, RPC exposure safety, DA availability, and native tx-leaf proof soundness explicit.
- 2026-06-19: Added `GenerateAirBalanceBoundaryVectors` as a proof/AIR implementation-equivalence slice. The generated vector gate now binds the Lean P3 final-row balance equations to production `TransactionProverP3` trace/public-input extraction for normal and stablecoin witnesses, and checks native-delta, selected-stablecoin-delta, selector-asset, disabled-metadata, nonselected-delta, and boolean-field rejection surfaces before the existing verifier mutation test. This narrows AIR-to-production field binding while keeping STARK/FRI/PCS soundness and witness extraction explicit.
