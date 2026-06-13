# Grind Native Implementation Equivalence

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file according to `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon's Lean claims should describe the same objects that the native node actually admits, stores, replays, and publishes. After this work, an operator or auditor can see concrete hardening, not just prose: RPC action requests with extra kernel-envelope data are rejected instead of silently projected away, storage publication waits for durable database acceptance, and the formal-core gate checks generated Lean vectors against the production Rust paths.

## Progress

- [x] (2026-06-12) Audited storage durability and raw-action implementation-equivalence gaps with subagents.
- [x] (2026-06-12) Implemented native storage-durability admission over mined, reorg, repair, noncanonical, pending-action, sidecar, and genesis publication paths.
- [x] (2026-06-12) Added a Lean/Rust/vector gate for native action-request projection so RPC JSON cannot silently carry unproved kernel-envelope fields.
- [x] (2026-06-12) Re-ran the local formal-core gate and native node tests after the action-request projection slice.
- [x] (2026-06-12) Implemented the native atomic-commit manifest admission slice over mined-block, canonical-reorg, canonical-index-repair, and noncanonical block-record commit paths.
- [x] (2026-06-12) Re-ran the local native-node suite and full formal-core gate after the atomic-manifest slice.
- [x] (2026-06-12) Deployed the atomic-manifest/storage/action-projection branch to `hegemon-dev`; smoke tests passed, mining advanced from block 6314 to 6317, and wallet-send transaction validation passed.
- [x] (2026-06-12) Audited the next implementation-equivalence gaps with agents: raw `PendingAction` wire-to-replay projection and native transfer action to tx-leaf artifact binding are the highest-value remaining targets.
- [x] (2026-06-12) Implemented the native action-plan application admission slice so planned starts must line up with the current commitment leaf cursor in release builds before preview, memory application, materialized planning, or canonical-index rebuild.
- [x] (2026-06-12) Re-ran the full local formal-core gate, native node suite, formatting check, diff check, and release build after the action-plan application slice.
- [x] (2026-06-12) Committed and pushed the action-plan application slice, deployed it to `hegemon-dev`, and smoke-tested mining/transactions.
- [x] (2026-06-12) Implemented the first native transfer action-to-tx-leaf artifact binding hardening slice, extending the Lean/Rust gate to input/output active counts, balance-tag projection, receipt statement hash, public-input digest, proof digest/backend-profile agreement, and the existing public-field/payload-hash checks.
- [x] (2026-06-12) Implemented the transaction proof-wrapper / manifest codec exactness slice: Lean admission table, Rust conformance vectors, shared pre-verifier wrapper helper, manifest exact decode, shared statement-hash helper, and hostile nested-wrapper regressions.
- [x] (2026-06-12) Ran targeted proof-wrapper/manifest validation: Lean generator build, vector conformance, transaction proof unit tests, manifest hostile regression, manifest round-trip, shell syntax, package check, and touched-file diff check.
- [x] (2026-06-12) Implemented native action wire-replay projection admission so decoded `PendingAction` ciphertext hash/size rows and inbound replay keys must match materialized planned effects before preview, memory apply, materialized planning, or canonical-index rebuild derives replay rows.
- [x] (2026-06-12) Re-ran targeted Lean/vector/Rust tests, claims validation, blueprint validation, formatting, diff checks, the full native-node library suite, and the full formal-core gate after the tx-leaf binding, wire-replay projection, and proof-wrapper slices.
- [x] (2026-06-12) Implemented the transaction proof-statement binding slice: Lean theorem evidence, Lean-generated binding-message/chunk-preimage vectors, production `StarkVerifier::compute_binding_hash` conformance, and `transaction_statement_hash_from_parts` conformance in both transaction and consensus paths.
- [x] (2026-06-12) Removed a SuperNeo receipt statement-hash drift risk by routing canonical/native receipt construction through the shared statement-hash helper and adding a formal-core regression for the shared helper path.
- [x] (2026-06-12) Re-ran the full formal-core gate after the proof-statement binding slice: 86 theorem-backed claims, 1069 named Lean theorem declarations, 84 production-eligible claims, 86 blueprint nodes, 319 dependency edges, 365 falsification cases, 177 implementation bindings, 132 order constraints / 352 order edges, 147 result obligations, and 121 dominance constraints / 323 dominance edges.

## Surprises & Discoveries

- Observation: The wallet serializes `object_refs`, `authorization_proof`, `authorization_signatures`, and `aux_data` even when they are empty.
  Evidence: `wallet/src/node_rpc.rs` defines `SubmitActionRequest` with those fields and builds requests from `ActionEnvelope`.
- Observation: The native node previously decoded only the native projection fields in `SubmitActionRpcRequest`, so serde ignored any extra JSON fields by default.
  Evidence: `node/src/native/mod.rs` had no `serde(deny_unknown_fields)` on `SubmitActionRpcRequest`.
- Observation: Raw `PendingAction` bytes still need a field-level wire-to-replay projection table.
  Evidence: Agent audit traced `PendingAction` through `NativeBlockMeta.action_bytes`, `decode_block_actions`, `pending_action_hash`, sidecar materialization, replay refinement, and row planning; the current wire-replay projection slice covers decoded ciphertext hash/size rows and inbound replay keys against planned effects, but not the full raw SCALE grammar or every decoded field's downstream use.
- Observation: Native transfer action to tx-leaf artifact binding needed a broader mutation table.
  Evidence: Agent audit found existing coverage for nullifier/commitment/ciphertext/version/fee/payload-hash agreement but missing formal/vector coverage for count agreement, receipt statement hash, public-input digest, proof/backend digest, and balance-tag projection. The current slice adds those gates to `BlockArtifactBindingAdmission` and computes them from decoded native tx-leaf artifacts in `consensus_tx_and_artifact_from_action`.
- Observation: Empty `stark_proof` or absent `stark_public_inputs` cannot be represented as a canonical nested bincode `TransactionProof` wrapper because serde `skip_serializing_if` omits those fields and bincode is not self-describing.
  Evidence: The manifest hostile regression first failed with `failed to decode transaction proof wrapper: io error: failed to fill whole buffer` when the nested proof cleared `stark_proof`. The final slice keeps manifest fail-closed coverage at the codec layer and covers missing proof/public-input presence through direct wrapper-admission unit tests.
- Observation: The proof-binding transcript evidence must model `binding-hash-v3` chunk preimages directly, not a synthetic `tx-statement-v1 || binding_hash` wrapper.
  Evidence: The production verifier computes two BLAKE2 chunks over `StarkVerifier::BINDING_HASH_DOMAIN`, chunk index bytes, and `binding_hash_message(&inputs)`. The final Lean/Rust conformance vectors compare that exact message and both chunk preimages against `compute_binding_hash`.
- Observation: SuperNeo receipt construction had a maintainability drift risk because it carried a local duplicate statement-hash grammar.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` now calls `transaction_statement_hash_from_parts`, and `superneo_receipts_use_shared_statement_hash_helper` checks canonical and native receipt paths against the shared helper.

## Decision Log

- Decision: Treat empty kernel-envelope fields as known compatibility fields but reject them when non-empty.
  Rationale: Rejecting all such field names would break existing wallet JSON, but accepting non-empty values would keep the silent projection hazard.
  Date/Author: 2026-06-12 / Codex.
- Decision: Extend the branch from RPC projection into atomic commit manifests before shipping.
  Rationale: The projection boundary removed silent field dropping, and the next highest-value implementation-equivalence gap was whether storage commit helpers declared the row families they mutate before sled transactions.
  Date/Author: 2026-06-12 / Codex.
- Decision: Add action-plan application admission before the larger raw-action projection table.
  Rationale: The existing action-stream proof emitted planned starts, but production application still relied on debug assertions for leaf-cursor drift. The new slice is narrow, release-relevant, and directly hardens root/index derivation while leaving deeper field-level projection work explicit.
  Date/Author: 2026-06-12 / Codex.
- Decision: Extend the existing block-artifact binding admission table instead of creating a second tx-leaf binding module.
  Rationale: `consensus_tx_and_artifact_from_action` is the native choke point where decoded tx-leaf artifacts become consensus transactions and backend artifacts. Extending the existing helper keeps rejection precedence, generated vectors, and blueprint bindings in one place.
  Date/Author: 2026-06-12 / Codex.
- Decision: Route `tx-proof-manifest` through `transaction_proof_wrapper_public_inputs_p3` and `transaction_statement_hash_from_public_inputs_checked` instead of keeping manifest-local wrapper and statement-hash logic.
  Rationale: The manifest is a trust boundary over nested transaction proof wrappers. It should reject the same malformed wrapper states as transaction verification before backend verification, and it should not carry a second statement-hash grammar that can drift from receipts or tx-leaf binding.
  Date/Author: 2026-06-12 / Codex.
- Decision: Add a decoded row-projection gate before attempting a full raw `PendingAction` SCALE refinement.
  Rationale: The production replay vulnerability surface was whether materialized ciphertext bytes and inbound replay keys could drift from decoded action fields before roots or canonical rows were derived. The new gate hardens that live path while keeping the harder byte-grammar proof explicit.
  Date/Author: 2026-06-12 / Codex.
- Decision: Bind the verifier transcript at the exact `binding-hash-v3` byte-preimage level.
  Rationale: A higher-level statement-hash wrapper would be easier to prove but would not test the production transcript that actually feeds BLAKE2. The conformance gate now compares the message bytes, chunk preimages, and final hash chunks directly.
  Date/Author: 2026-06-12 / Codex.
- Decision: Replace SuperNeo's local statement-hash layout with the shared production helper.
  Rationale: Implementation equivalence is stronger when there is one production grammar. The regression keeps future receipt paths from reintroducing a duplicate statement-hash encoder.
  Date/Author: 2026-06-12 / Codex.

## Outcomes & Retrospective

The action-request projection milestone added a theorem-backed admission table, generated vectors, production helper wiring, and a regression that accepts empty wallet envelope compatibility fields while rejecting unknown or non-empty unimplemented envelope fields before pending-action publication. The atomic-manifest milestone added theorem-backed manifest counts and production gates before noncanonical persistence and mined/reorg/repair sled transactions. The first `hegemon-dev` deployment of those slices passed smoke, mining, and wallet-send validation. The action-plan application milestone adds theorem-backed planned-start length/cursor/overflow admission and release regressions for memory application drift. Local validation passed `bash scripts/check_formal_core.sh`, `cargo test -p hegemon-node --lib --no-default-features`, `cargo fmt --check`, `git diff --check`, and `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release`. Remote validation on `hegemon-dev` passed `bash scripts/check_formal_core.sh`, release rebuild, service restart at `2def4df1`, smoke RPC, mining advancement from block 6597 to 6602, wallet-send compatibility, and NTP synchronization. The tx-leaf binding milestone now covers decoded/action count, digest, backend-profile, and balance-tag projection mismatches before backend artifact construction, with generated Lean vectors and Rust regressions for the newly covered mismatch classes. The proof-wrapper/manifest milestone adds theorem-backed wrapper admission order, manifest exact decode, shared statement-hash derivation, and negative coverage for nested trailing bytes, unsupported backends, missing proof/public-input presence, public-input malformation, balance-slot drift, and verifier rejection. The wire-replay milestone covers decoded action ciphertext row and replay-key projection before roots, memory state, or canonical rows are derived. Earlier local validation for the combined branch passed `cargo test -p hegemon-node --lib --no-default-features` with 250 native-node tests, and `bash scripts/check_formal_core.sh` with 86 claims, 1,049 named Lean theorems, 84 production-eligible claims, 86 blueprint nodes, 359 falsification cases, and all 11 native backend reference vectors. The proof-statement binding/SuperNeo helper slice then passed `bash scripts/check_formal_core.sh` with 86 theorem-backed claims, 1069 named Lean theorem declarations, 84 production-eligible claims, 86 blueprint nodes, 319 dependency edges, 365 falsification cases, all 11 native backend reference vectors, and no unwaived Lean axiom dependencies. The deeper remaining work is now explicit: full raw `PendingAction` SCALE field-level replay equivalence and complete Rust refinement.

## Context and Orientation

The native node lives in `node/src/native/mod.rs`. Users submit protocol actions through the JSON-RPC method `hegemon_submitAction`, which calls `NativeNode::submit_action` and then `NativeNode::validate_and_stage_action`. That path builds a `PendingAction`, stores it in sled, and later mines or replays the SCALE-encoded `PendingAction` bytes inside `NativeBlockMeta.action_bytes`.

The wallet lives in `wallet/src/node_rpc.rs`. It builds a protocol-kernel `ActionEnvelope` but sends a JSON projection to the native node. Some kernel-envelope fields are not implemented in native consensus yet. The projection boundary must therefore reject non-empty unimplemented fields explicitly and must reject unknown JSON fields rather than allowing serde to discard them.

The Lean proof modules live under `formal/lean/Hegemon/Native`. Generated-vector tests in `node/src/native/mod.rs` compare small executable Lean decision tables to Rust helpers. `scripts/check_formal_core.sh` generates all Lean vectors and runs the conformance tests.

## Plan of Work

First, add `ActionRequestProjectionAdmission.lean` and a generator that emits valid, unknown-field, non-empty kernel-field, unsupported-route, nullifier, base64, size, and route-payload decode cases. Import the module from `formal/lean/Hegemon.lean`, add a Lake executable, and wire the vector generation into `scripts/check_formal_core.sh`.

Second, harden `node/src/native/mod.rs` by making `SubmitActionRpcRequest` a strict JSON grammar. Add explicit compatibility fields for empty `object_refs`, `authorization_proof`, `authorization_signatures`, and `aux_data`; add a Rust admission helper that matches the Lean decision table; call it before native action staging; and add generated-vector plus regression tests.

Third, update `config/formal-security-claims.json`, `config/formal-security-blueprint.json`, `DESIGN.md`, `METHODS.md`, `formal/lean/README.md`, and formal-core inventory/docs so the executable claim and its residual limits are visible.

## Concrete Steps

Run all commands from `/private/tmp/hegemon-formal-work` unless stated otherwise.

1. Add the Lean module, generator, imports, inventory, and shell wiring.
2. Patch `node/src/native/mod.rs` for strict request projection and tests.
3. Run:
   `cargo fmt --all`
   `cd formal/lean && lake env lean Hegemon/Native/ActionRequestProjectionAdmission.lean`
   `cd formal/lean && lake exe gen_action_request_projection_admission_vectors > /tmp/hegemon-action-request-projection-vectors.json`
   `HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS=/tmp/hegemon-action-request-projection-vectors.json cargo test -p hegemon-node lean_generated_action_request_projection_admission_vectors_match_production --lib --no-default-features -- --nocapture`
   `cargo test -p hegemon-node --lib --no-default-features`
   `bash scripts/check_formal_core.sh`

## Validation and Acceptance

The new regression must show that a normal wallet-style request with empty kernel-envelope compatibility fields still stages, while requests with unknown fields or non-empty `object_refs`, `authorization_proof`, `authorization_signatures`, or `aux_data` fail before state publication. The generated-vector test must pass for every Lean-emitted case. The full formal-core gate must pass after the ledger and blueprint counts are updated.

## Idempotence and Recovery

The edits are additive and test-driven. If a vector command fails, regenerate the temporary JSON file and rerun only the failing cargo test. If `hegemon-dev` deployment fails, keep the pushed branch intact and inspect the remote service logs before retrying the same checkout/build/restart command.

## Artifacts and Notes

The first two subagent audits found two remaining implementation-equivalence targets after storage durability: native atomic commit manifest equivalence and raw action bytes to replay semantics. This ExecPlan starts with the raw-action projection sub-slice because it removes silent field dropping at a live trust boundary.

## Interfaces and Dependencies

At completion, `node/src/native/mod.rs` must define `decode_submit_action_rpc_request`, `admit_native_action_request_projection`, `evaluate_native_action_request_projection_admission`, and `NativeActionRequestProjectionAdmissionInput`. `formal/lean/Hegemon/Native/ActionRequestProjectionAdmission.lean` must define the corresponding executable decision table and theorem `accepts_iff_action_request_projection_preconditions`.
