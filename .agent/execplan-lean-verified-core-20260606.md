# Lean-Verified Hegemon Core

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`. The active user goal is to build a Lean-verified Hegemon core where every production-critical validity rule is represented by an executable Lean specification, every exported security claim is backed by a named theorem that builds with no `sorry`, `admit`, or undeclared axioms, and release Rust code is forced to conform to that Lean kernel through generated vectors, differential tests, and eventually verified or extracted implementation paths. The final goal also requires validation on `hegemon-dev`.

## Purpose / Big Picture

The repository currently has a claims ledger, a blueprint DAG, reference vectors, and TLA+ model inventory. That is not enough. This plan starts the real machine-checked layer: a pinned Lean 4 project under `formal/lean` with executable protocol specifications and named theorems. The first milestone proves a concrete safety property for inbound bridge replay: after a replay key is accepted and inserted into the consumed set, the same key cannot be accepted again.

After this milestone, a contributor can run `bash scripts/check_lean_formal.sh` from the repository root and observe Lean building the theorem files while the script rejects `sorry`, `admit`, and declared `axiom` text. The existing `bash scripts/check_formal_core.sh` gate will call the Lean gate, so CI/release validation starts depending on a machine-checked proof artifact rather than only JSON metadata.

## Progress

- [x] (2026-06-06T06:43:00Z) Re-read `DESIGN.md`, `METHODS.md`, the current formal-core scripts, and the current branch state.
- [x] (2026-06-06T06:43:00Z) Confirmed local `lean`, `lake`, and `elan` are not installed.
- [x] (2026-06-06T06:58:00Z) Added a pinned Lean project under `formal/lean` with `leanprover/lean4:v4.30.0`.
- [x] (2026-06-06T06:58:00Z) Added an executable bridge replay specification and theorems `Hegemon.Bridge.accept_inserts_key` and `Hegemon.Bridge.accept_prevents_duplicate`.
- [x] (2026-06-06T06:58:00Z) Added `scripts/check_lean_formal.sh`; it builds the explicit `Hegemon` Lean target, directly checks the replay Lean file, and rejects `sorry`, `admit`, and declared axioms.
- [x] (2026-06-06T06:58:00Z) Wired the Lean gate into `scripts/check_formal_core.sh` as a mandatory step 3 of 10.
- [x] (2026-06-06T06:58:00Z) Updated documentation and formal-security metadata so `bridge.inbound-replay-state` points at the named Lean theorem evidence.
- [x] (2026-06-06T06:58:00Z) Installed local `elan`, ran `bash scripts/check_lean_formal.sh`, and ran `bash scripts/check_formal_core.sh`; both passed locally.
- [x] (2026-06-06T07:08:00Z) Validated branch tip `326a1c7d` on `hegemon-dev`; the full 10-step formal-core gate passed after installing elan and downloading the pinned Lean `v4.30.0` toolchain.
- [x] (2026-06-06T18:17:00Z) Extended the Lean bridge kernel with canonical `BridgeMessageV1` byte encoding, two-phase inbound replay staging/import transitions, and theorems `stage_prevents_duplicate_pending`, `import_prevents_reimport`, and `import_prevents_restaging`.
- [x] (2026-06-06T18:17:00Z) Added the Lean executable `gen_bridge_vectors` and a `protocol-kernel` conformance test that checks generated Lean bridge encoding/replay examples against production helpers when `HEGEMON_LEAN_BRIDGE_VECTORS` is set.
- [x] (2026-06-06T18:17:00Z) Moved native bridge duplicate-replay validation to the shared `protocol-kernel::InboundReplayState` helper, so node staging and block-validation paths use the helper checked by Lean-generated vectors.
- [x] (2026-06-06T18:30:00Z) Validated branch tip `972b6933` on `hegemon-dev`: the 11-step formal-core gate passed, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402479` to `402481`, and `scripts/test-node.sh wallet-send` passed.
- [x] (2026-06-06T18:44:00Z) Added shared Lean byte helpers plus a shielded nullifier-state kernel proving zero rejection, duplicate pending rejection, and spent-nullifier rejection.
- [x] (2026-06-06T18:44:00Z) Added `gen_shielded_vectors` and a `protocol-shielded-pool` conformance test that checks generated Lean nullifier stage/import examples against production `NullifierState` when `HEGEMON_LEAN_SHIELDED_VECTORS` is set.
- [x] (2026-06-06T18:44:00Z) Moved native nullifier staging, block validation, state replay/import, and author preview checks to the shared `protocol-shielded-pool::NullifierState` helper.
- [x] (2026-06-06T18:50:00Z) Validated branch tip `0e6e6030` on `hegemon-dev`: the expanded 11-step formal-core gate passed with 10 claims and both generated conformance tests, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402561` to `402564`, and `scripts/test-node.sh wallet-send` passed.
- [x] (2026-06-06T19:24:00Z) Added a Lean consensus fork-choice kernel proving deterministic two-tip ordering by work, height, then hash.
- [x] (2026-06-06T19:24:00Z) Added `gen_consensus_vectors` and a `consensus` conformance test that checks generated Lean fork-choice examples against the production `consensus::fork_choice` helper when `HEGEMON_LEAN_CONSENSUS_VECTORS` is set.
- [x] (2026-06-06T19:24:00Z) Routed `PowConsensus` and native announced-block import through the shared fork-choice helper.
- [x] (2026-06-06T19:24:00Z) Ran `bash scripts/check_lean_formal.sh` and `HEGEMON_LEAN_CONSENSUS_VECTORS=<generated-json> cargo test -p consensus lean_generated_fork_choice_vectors_match_production -- --nocapture`; both passed locally.
- [x] (2026-06-06T19:33:00Z) Ran the full local `bash scripts/check_formal_core.sh`; it passed with the new consensus conformance step, 10 claims, 8 production-eligible claims, and 18 falsification cases.
- [x] (2026-06-06T19:33:00Z) Ran focused production tests: `cargo test -p consensus --test pow_rules --test simulation -- --nocapture` and `cargo test -p hegemon-node bridge_witness_rejects_noncanonical_block_hash --lib --no-default-features -- --nocapture`; both passed.
- [x] (2026-06-06T19:42:00Z) Validated branch tip `aab28185` on `hegemon-dev`: the expanded 11-step formal-core gate passed with consensus fork-choice conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402670` to `402673`, and `scripts/test-node.sh wallet-send` passed.
- [x] (2026-06-06T20:03:00Z) Added a Lean transaction-balance kernel proving valid balances have concrete slots, slot overflow is rejected, native delta equals `fee - value_balance`, and stablecoin/non-native rules are extracted from executable validation.
- [x] (2026-06-06T20:03:00Z) Added `gen_transaction_vectors` and a `transaction-circuit` conformance test that checks generated Lean balance examples against production `TransactionWitness::balance_slots` and `TransactionWitness::validate` when `HEGEMON_LEAN_TRANSACTION_VECTORS` is set.
- [x] (2026-06-06T20:03:00Z) Ran `bash scripts/check_lean_formal.sh` and `HEGEMON_LEAN_TRANSACTION_VECTORS=<generated-json> cargo test -p transaction-circuit lean_generated_balance_vectors_match_production -- --nocapture`; both passed locally.
- [x] (2026-06-06T20:13:00Z) Ran the full local `bash scripts/check_formal_core.sh`; it passed with the new transaction-balance conformance step, 10 claims, 8 production-eligible claims, and 20 falsification cases.
- [x] (2026-06-06T20:13:00Z) Ran `cargo test -p transaction-circuit --test transaction verification_fails_for_bad_balance -- --nocapture`; it passed. The heavier `smallwood_candidate_verification_fails_for_enabled_stablecoin_binding_mutation` run was stopped after several minutes without output and is not counted as evidence for this revision.
- [x] (2026-06-06T20:25:00Z) Validated branch tip `01cbd6f6` on `hegemon-dev`: the expanded 11-step formal-core gate passed with transaction-balance conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402776` to `402777`, and `scripts/test-node.sh wallet-send` passed.
- [x] (2026-06-06T20:30:00Z) Added a Lean supply-accounting kernel proving checked supply-digest increase/decrease, underflow/overflow rejection, no-coinbase native no-op behavior, checked coinbase advance, and native supply overflow rejection.
- [x] (2026-06-06T20:30:00Z) Added `gen_supply_vectors`, consensus conformance for `CoinbaseData::net_native_delta` plus `consensus::reward::update_supply_digest`, and native conformance for no-coinbase/coinbase supply helpers.
- [x] (2026-06-06T20:30:00Z) Removed native `saturating_add` supply-digest advancement from mined-block, announced-block, and replay paths; those paths now reject checked supply overflow.
- [x] (2026-06-06T20:30:00Z) Ran `bash scripts/check_lean_formal.sh`, `HEGEMON_LEAN_SUPPLY_VECTORS=<generated-json> cargo test -p consensus lean_generated_supply_vectors_match_production -- --nocapture`, `HEGEMON_LEAN_SUPPLY_VECTORS=<generated-json> cargo test -p hegemon-node lean_generated_native_supply_vectors_match_production --lib --no-default-features -- --nocapture`, and `cargo test -p hegemon-node native_supply_digest_rejects_overflow --lib --no-default-features -- --nocapture`; all passed locally. Full local formal-core and `hegemon-dev` validation are still pending for this revision.
- [x] (2026-06-06T20:35:00Z) Reran the full local `bash scripts/check_formal_core.sh`; it passed with supply-accounting conformance, 11 claims, 9 production-eligible claims, 11 blueprint nodes, and 23 falsification cases.
- [x] (2026-06-06T20:35:00Z) Ran focused supply regressions after the native checked-ordering fix: `cargo test -p hegemon-node supply --lib --no-default-features -- --nocapture`, `cargo test -p hegemon-node coinbase --lib --no-default-features -- --nocapture`, `cargo test -p consensus supply_digest -- --nocapture`, and `cargo test -p consensus total_minted -- --nocapture`; all passed.
- [x] (2026-06-06T20:40:00Z) Validated branch tip `9df3a4e1` on `hegemon-dev`: the expanded 11-step formal-core gate passed with supply-accounting conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed at height `402926`, mining advanced from height `402928` to `402930`, `scripts/test-node.sh wallet-send` passed, and final service check was active at height `402932`.
- [x] (2026-06-06T20:45:00Z) Added a Lean native action-ordering kernel proving empty/single/equal/ascending/descending and non-transfer-ignored cases for the computed transfer-key subsequence.
- [x] (2026-06-06T20:45:00Z) Added `gen_action_order_vectors` and a native-node conformance test that checks generated Lean action-ordering examples against a Rust fold over the production `transfer_key_extends_canonical_order` helper when `HEGEMON_LEAN_ACTION_ORDER_VECTORS` is set.
- [x] (2026-06-06T20:45:00Z) Routed full native block-action validation through the shared transfer-key order predicate, preserving the existing regression that rejects noncanonical shielded transfer order in `validate_block_actions_locked`.
- [x] (2026-06-06T20:45:00Z) Ran `bash scripts/check_lean_formal.sh`, `HEGEMON_LEAN_ACTION_ORDER_VECTORS=<generated-json> cargo test -p hegemon-node lean_generated_action_order_vectors_match_production --lib --no-default-features -- --nocapture`, and `cargo test -p hegemon-node imported_block_actions_require_canonical_transfer_order --lib --no-default-features -- --nocapture`; all passed locally. Full local formal-core and `hegemon-dev` validation are still pending for this revision.
- [x] (2026-06-06T20:50:00Z) Reran the full local `bash scripts/check_formal_core.sh`; it passed with native action-ordering conformance, 12 claims, 10 production-eligible claims, 12 blueprint nodes, and 26 falsification cases.
- [x] (2026-06-06T20:55:00Z) Fixed the action-ordering conformance test to fold over the production `transfer_key_extends_canonical_order` helper instead of leaving a release-dead helper in `node/src/native/mod.rs`; reran the focused generated-vector test, native order regression, release `hegemon-node` build, and full local formal-core gate successfully.
- [x] (2026-06-06T21:00:00Z) Validated branch tip `778fcfc5` on `hegemon-dev`: the expanded 11-step formal-core gate passed with native action-ordering conformance, `make node` rebuilt the release binary without the earlier `hegemon-node` dead-code warning, `hegemon-node.service` restarted cleanly, smoke RPC checks passed at height `403040`, mining advanced from height `403041` to `403044`, `scripts/test-node.sh wallet-send` passed, and final service check was active at height `403048`.
- [x] (2026-06-06T21:05:00Z) Added a Lean consensus proof-policy kernel proving empty-block proof-payload rejection, non-empty self-contained proof-shape requirements, legacy InlineRequired rejection, recursive commitment-proof-byte rejection, recursive block-artifact requirements, and complete recursive-block acceptance.
- [x] (2026-06-06T21:05:00Z) Added `gen_proof_policy_vectors` and a consensus conformance test that checks generated Lean proof-policy examples against the production `evaluate_block_proof_policy` helper called by `ParallelProofVerifier`.
- [x] (2026-06-06T21:05:00Z) Ran `bash scripts/check_lean_formal.sh`, `HEGEMON_LEAN_PROOF_POLICY_VECTORS=<generated-json> cargo test -p consensus lean_generated_proof_policy_vectors_match_production -- --nocapture`, `cargo test -p consensus --test self_contained_mode -- --nocapture`, `bash scripts/check_formal_core.sh`, and `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release`; all passed locally. The full formal-core gate reported 13 claims, 11 production-eligible claims, 13 blueprint nodes, and 29 falsification cases. Remote `hegemon-dev` validation is still pending for this revision.
- [x] (2026-06-06T21:17:00Z) Validated branch tip `cc446317` on `hegemon-dev`: the expanded formal-core gate passed with consensus proof-policy conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed at height `403167`, mining advanced from height `403168` to `403170`, `scripts/test-node.sh wallet-send` passed, and final service check was active at height `403173`.
- [x] (2026-06-06T21:48:00Z) Added a Lean consensus PoW-admission kernel proving compact-target rejection, strict timestamp admission, hash-threshold rejection, fixed-width Work48 addition, and executable admission accept/reject facts.
- [x] (2026-06-06T21:48:00Z) Added `gen_pow_vectors`, consensus conformance against the production `evaluate_pow_admission` helper used by `PowConsensus`, and light-client conformance against compact-target, hash-threshold, and Work48 cumulative-work helpers.
- [x] (2026-06-06T21:48:00Z) Hardened `PowConsensus` to reject timestamps equal to the parent timestamp and compact targets with exponents over 32, replacing the old private ad hoc admission checks with the shared helper.
- [x] (2026-06-06T21:48:00Z) Ran `bash scripts/check_lean_formal.sh`, focused PoW generated-vector tests, `cargo test -p consensus --test pow_rules --test simulation --test pq_runtime_compat -- --nocapture`, `bash scripts/check_formal_core.sh`, and `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release`; all passed locally. The full formal-core gate reported 14 claims, 12 production-eligible claims, 14 blueprint nodes, and 32 falsification cases.
- [x] (2026-06-06T21:49:00Z) Validated branch tip `ee20c66e` on `hegemon-dev`: the expanded formal-core gate passed with consensus PoW-admission and light-client Work48 conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed at height `403348`, mining advanced from height `403350` to `403353`, `scripts/test-node.sh wallet-send` passed, and final service check was active at height `403359`.
- [x] (2026-06-06T22:09:00Z) Added a Lean transaction Merkle-path kernel proving empty-path behavior, even/odd position-bit orientation, computed-root acceptance, wrong-length rejection, and wrong-root rejection for executable path folding.
- [x] (2026-06-06T22:09:00Z) Added `gen_merkle_vectors`, a `transaction-circuit` conformance test for generated Merkle path examples, and a production `MerklePath::root_with` helper used by `MerklePath::verify` so the vector test and production path share the same fold logic.
- [x] (2026-06-06T22:09:00Z) Ran `bash scripts/check_lean_formal.sh`, `cargo test -p transaction-circuit merkle -- --nocapture`, focused `HEGEMON_LEAN_MERKLE_VECTORS=<generated-json> cargo test -p transaction-circuit lean_generated_merkle_path_vectors_match_production -- --nocapture`, `bash scripts/check_formal_core.sh`, and `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release`; all passed locally. The full formal-core gate reported 15 claims, 13 production-eligible claims, 15 blueprint nodes, and 35 falsification cases.
- [x] (2026-06-06T22:16:00Z) Validated branch tip `3c8b31e7` on `hegemon-dev`: the expanded formal-core gate passed with transaction Merkle-path conformance, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed at height `403507`, mining advanced from height `403508` to `403510`, `scripts/test-node.sh wallet-send` passed, and final service check was active at height `403513`.

## Surprises & Discoveries

- Observation: The current repo has no Lean project and no Lean toolchain files.
  Evidence: `rg --files | rg '(^formal|lean|lake|\\.lean$)'` only found existing formal-core JSON/scripts and no `.lean`, `lakefile.lean`, or `lean-toolchain` files.

- Observation: Lean/Lake/Elan are not installed locally.
  Evidence: `command -v lean`, `command -v lake`, and `command -v elan` returned no paths.

- Observation: Plain `lake build` was too weak as evidence for this initial project.
  Evidence: The first run printed `Build completed successfully (0 jobs)`. Running `lake build Hegemon` compiled `Hegemon.Bridge.Replay` and `Hegemon`, reporting 4 jobs. The script now builds the explicit `Hegemon` target and directly elaborates `Hegemon/Bridge/Replay.lean`.

- Observation: The first actual Lean theorem is now part of the same formal-core gate as the JSON/vector checks.
  Evidence: `bash scripts/check_formal_core.sh` reported `[3/10] Checking Lean formal proof kernel`, `Build completed successfully (4 jobs)`, then `claims = 9`, `production_eligible = 7`, `nodes = 9`, and `production_nodes = 7`.

- Observation: The same Lean theorem gate works on `hegemon-dev` from a fresh Lean toolchain install.
  Evidence: Remote validation at commit `326a1c7d` downloaded Lean `v4.30.0`, built `Hegemon.Bridge.Replay`, built `Hegemon`, and completed the full `bash scripts/check_formal_core.sh` gate.

- Observation: Generated Lean vectors can now be checked against production Rust helpers.
  Evidence: `lake exe gen_bridge_vectors` emits two bridge encoding examples and four replay-state examples; the formal-core gate runs `HEGEMON_LEAN_BRIDGE_VECTORS=<generated-json> cargo test -p protocol-kernel lean_generated_bridge_vectors_match_production -- --nocapture`.

- Observation: `hegemon-dev` can run the new proof/conformance gate and the rebuilt node stays healthy.
  Evidence: Remote `bash scripts/check_formal_core.sh` passed all 11 steps at `972b6933`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed against `http://127.0.0.1:9944`; a 25-second height sample advanced from `402479` to `402481`; `scripts/test-node.sh wallet-send` passed.

- Observation: The second Lean-backed production slice now covers native shielded nullifier state.
  Evidence: Local `bash scripts/check_lean_formal.sh` built `Hegemon.Shielded.Nullifier` and `gen_shielded_vectors`; local `HEGEMON_LEAN_SHIELDED_VECTORS=<generated-json> cargo test -p protocol-shielded-pool lean_generated_nullifier_vectors_match_production -- --nocapture` passed; local `cargo test -p hegemon-node submit_action_stages_and_imports_shielded_transfer --lib --no-default-features -- --nocapture` passed after the native node switched to the shared helper.

- Observation: `hegemon-dev` can run the nullifier proof/conformance gate and the rebuilt node continues mining.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `0e6e6030` reported `claims = 10`, `production_eligible = 8`, `falsification_cases = 16`, and both generated Rust conformance tests passed; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed; a 25-second height sample advanced from `402561` to `402564`; `scripts/test-node.sh wallet-send` passed.

- Observation: The PoW fork-choice claim now has a Lean-backed deterministic ordering slice.
  Evidence: `formal/lean/Hegemon/Consensus/ForkChoice.lean` proves higher work wins, lower work loses, equal-work height tie-breaks, equal-work/height hash tie-breaks, and same-tip non-selection; `consensus/src/fork_choice.rs` checks `gen_consensus_vectors` output against production Rust; `consensus/src/pow.rs` and `node/src/native/mod.rs` call the shared helper.

- Observation: The new consensus theorem scope is deliberately smaller than full finality.
  Evidence: `config/formal-security-claims.json` scopes `formal.pow-fork-choice` to deterministic two-tip ordering and retains `consensus/spec/formal/pow_longest_chain.tla` as bounded aggregate-work/finality model evidence.

- Observation: The expanded formal-core gate still accepts the full claims/blueprint set.
  Evidence: Local `bash scripts/check_formal_core.sh` passed, reported `claims = 10`, `production_eligible = 8`, `falsification_cases = 18`, and ran `lean_generated_fork_choice_vectors_match_production` successfully.

- Observation: `hegemon-dev` can run the fork-choice proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `aab28185` passed all 11 steps, including `lean_generated_fork_choice_vectors_match_production`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `402668`; a 25-second height sample advanced from `402670` to `402673`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `402675`.

- Observation: The transaction-balance claim now has a Lean-backed executable validation slice.
  Evidence: `formal/lean/Hegemon/Transaction/Balance.lean` proves `validBalance_has_slots`, `validBalance_rejects_slot_overflow`, `validBalance_native_delta`, and `validBalance_stablecoin_rules`; `formal/lean/Hegemon/Transaction/GenerateVectors.lean` emits valid and invalid native/non-native/stablecoin/overflow examples; `circuits/transaction/src/witness.rs` checks those vectors against production `TransactionWitness::balance_slots` and `TransactionWitness::validate`.

- Observation: The transaction-balance theorem scope is still narrower than full proof-system soundness.
  Evidence: `config/formal-security-claims.json` scopes `formal.transaction-balance` to executable balance-slot and validation semantics and explicitly excludes note commitments, Merkle membership, nullifier derivation, ciphertext hashing, full AIR/proof-system soundness, and complete Rust refinement.

- Observation: The expanded formal-core gate now checks four Lean-to-Rust conformance surfaces.
  Evidence: Local `bash scripts/check_formal_core.sh` passed, ran bridge replay, shielded nullifier, consensus fork-choice, and transaction-balance generated vector checks, and reported `claims = 10`, `production_eligible = 8`, and `falsification_cases = 20`.

- Observation: `hegemon-dev` can run the transaction-balance proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `01cbd6f6` passed all 11 steps, including `lean_generated_balance_vectors_match_production`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `402775`; a 25-second height sample advanced from `402776` to `402777`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `402777`.

- Observation: The supply-digest claim now has a Lean-backed executable accounting slice and exposed a native overflow hardening fix.
  Evidence: `formal/lean/Hegemon/Consensus/Supply.lean` proves checked increase/decrease and native overflow rejection; `formal/lean/Hegemon/Consensus/GenerateSupplyVectors.lean` emits consensus and native cases; `consensus/src/reward.rs` and `node/src/native/mod.rs` check those vectors; native supply advancement now uses `advance_native_supply_digest` with `checked_add` rather than `saturating_add`.

- Observation: The first supply-accounting generated-vector checks pass locally.
  Evidence: Local `bash scripts/check_lean_formal.sh` passed; local consensus and native `HEGEMON_LEAN_SUPPLY_VECTORS=<generated-json>` tests passed; local `cargo test -p hegemon-node native_supply_digest_rejects_overflow --lib --no-default-features -- --nocapture` passed.

- Observation: The expanded formal-core gate now checks five Lean-to-Rust conformance surfaces.
  Evidence: Local `bash scripts/check_formal_core.sh` passed after adding supply accounting, ran bridge replay, shielded nullifier, consensus fork-choice, consensus/native supply accounting, and transaction-balance generated vector checks, and reported `claims = 11`, `production_eligible = 9`, `nodes = 11`, and `falsification_cases = 23`.

- Observation: `hegemon-dev` can run the supply-accounting proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `9df3a4e1` passed all 11 steps, including `lean_generated_supply_vectors_match_production` and `lean_generated_native_supply_vectors_match_production`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `402926`; a 25-second height sample advanced from `402928` to `402930`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `402932`.

- Observation: The native block action-ordering claim now has a Lean-backed executable predicate over computed transfer keys.
  Evidence: `formal/lean/Hegemon/Native/ActionOrder.lean` proves empty, single, equal-key, ordered-pair, descending-pair, and non-transfer-ignored facts; `formal/lean/Hegemon/Native/GenerateActionOrderVectors.lean` emits eight examples; `node/src/native/mod.rs` checks those vectors by folding over `transfer_key_extends_canonical_order`, the same production helper used inside full block-action validation.

- Observation: The action-ordering theorem scope is intentionally narrower than hash-function equivalence.
  Evidence: `config/formal-security-claims.json` and `config/formal-security-blueprint.json` explicitly exclude BLAKE2 action-order key derivation, full block action payload validation, transaction leaf proof soundness, DA ordering, and complete native-node equivalence from `native.block-action-ordering`.

- Observation: The expanded formal-core gate now checks six Lean-to-Rust conformance surfaces.
  Evidence: Local `bash scripts/check_formal_core.sh` passed after adding native action-ordering, ran bridge replay, shielded nullifier, consensus fork-choice, consensus/native supply accounting, native action-ordering, and transaction-balance generated vector checks, and reported `claims = 12`, `production_eligible = 10`, `nodes = 12`, and `falsification_cases = 26`.

- Observation: The remote release build exposed a dead-code warning before service restart, and the warning was removed before accepting the slice.
  Evidence: `make node` on `hegemon-dev` at `4936dccb` warned that `transfer_keys_are_canonical_order` was unused in release. The conformance test now uses `lean_transfer_keys_are_canonical_order` inside the test module, which folds over the production `transfer_key_extends_canonical_order` helper. Local `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release` completed without that `hegemon-node` warning.

- Observation: `hegemon-dev` can run the native action-ordering proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `778fcfc5` passed all 11 steps, including `lean_generated_action_order_vectors_match_production`, and reported `claims = 12`, `production_eligible = 10`, `nodes = 12`, and `falsification_cases = 26`; remote `make node` completed without the earlier `hegemon-node` warning; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `403040`; a 25-second height sample advanced from `403041` to `403044`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `403048`.

- Observation: The self-contained block proof policy now has a Lean-backed executable admission slice.
  Evidence: `formal/lean/Hegemon/Consensus/ProofPolicy.lean` proves empty-block, non-empty artifact, legacy mode, missing proven-batch, recursive commitment-proof-byte, recursive block-artifact, and complete recursive-block facts; `formal/lean/Hegemon/Consensus/GenerateProofPolicyVectors.lean` emits 15 examples; `consensus/src/proof.rs` checks those vectors against `evaluate_block_proof_policy`, and `ParallelProofVerifier` calls that helper before heavy artifact verification.

- Observation: The expanded formal-core gate now checks seven Lean-to-Rust conformance surfaces.
  Evidence: Local `bash scripts/check_formal_core.sh` passed after adding consensus proof policy, ran bridge replay, shielded nullifier, consensus fork-choice, consensus proof-policy, consensus/native supply accounting, native action-ordering, and transaction-balance generated vector checks, and reported `claims = 13`, `production_eligible = 11`, `nodes = 13`, and `falsification_cases = 29`.

- Observation: `hegemon-dev` can run the consensus proof-policy proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `cc446317` passed with consensus proof-policy conformance and reported `claims = 13`, `production_eligible = 11`, `nodes = 13`, and `falsification_cases = 29`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `403167`; a 25-second height sample advanced from `403168` to `403170`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `403173`.

- Observation: The consensus PoW admission claim now has a Lean-backed executable arithmetic slice.
  Evidence: `formal/lean/Hegemon/Consensus/PowRules.lean` proves compact-target zero-mantissa and exponent-over-32 rejection, strict timestamp parent/median/future-skew rejection, Work48 checked addition, height/pow_bits/insufficient-work rejection, and valid admission acceptance; `formal/lean/Hegemon/Consensus/GeneratePowVectors.lean` emits 11 examples; `consensus/src/pow.rs` checks those vectors against `evaluate_pow_admission`, and `consensus-light-client/src/lib.rs` checks compact-target, hash-threshold, and Work48 cumulative-work helpers against the same vectors.

- Observation: The expanded formal-core gate now checks eight Lean-to-Rust conformance surfaces.
  Evidence: Local `bash scripts/check_formal_core.sh` passed after adding consensus PoW admission, ran bridge replay, shielded nullifier, consensus fork-choice, consensus PoW-admission, consensus proof-policy, consensus/native supply accounting, native action-ordering, and transaction-balance generated vector checks, and reported `claims = 14`, `production_eligible = 12`, `nodes = 14`, and `falsification_cases = 32`.

- Observation: `hegemon-dev` can run the consensus PoW-admission proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `ee20c66e` built 47 Lean jobs, passed bridge replay, shielded nullifier, fork-choice, PoW admission, light-client Work48, proof-policy, supply-accounting, native action-ordering, and transaction-balance conformance, and reported `claims = 14`, `production_eligible = 12`, `nodes = 14`, and `falsification_cases = 32`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `403348`; a 25-second height sample advanced from `403350` to `403353`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `403359`.

- Observation: The transaction Merkle-membership claim now has a Lean-backed executable path-control slice.
  Evidence: `formal/lean/Hegemon/Transaction/MerklePath.lean` proves empty-path behavior, even/odd orientation, computed-root acceptance, wrong-length rejection, and wrong-root rejection. `formal/lean/Hegemon/Transaction/GenerateMerkleVectors.lean` emits seven examples, and the formal-core gate checks them against production `MerklePath::root_with` and `verify_with_depth_and_node`. Local `bash scripts/check_formal_core.sh` passed after adding the claim, reporting `claims = 15`, `production_eligible = 13`, `nodes = 15`, and `falsification_cases = 35`.

- Observation: `hegemon-dev` can run the transaction Merkle-path proof/conformance gate and the rebuilt node remains live.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `3c8b31e7` built 52 Lean jobs, passed bridge replay, shielded nullifier, fork-choice, PoW admission, light-client Work48, proof-policy, supply-accounting, native action-ordering, transaction-balance, and transaction Merkle-path conformance, and reported `claims = 15`, `production_eligible = 13`, `nodes = 15`, and `falsification_cases = 35`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed at height `403507`; a 25-second height sample advanced from `403508` to `403510`; `scripts/test-node.sh wallet-send` passed; final service check was active at height `403513`.

## Decision Log

- Decision: Pin Lean to `leanprover/lean4:v4.30.0`.
  Rationale: Upstream Lean 4 reports `v4.30.0` as the latest release on 2026-05-26. Pinning a specific version avoids the drift of `stable`.
  Date/Author: 2026-06-06 / Codex.

- Decision: Start with bridge replay safety rather than proof-system soundness.
  Rationale: Replay safety is production-critical, finite, and already close to the current bridge claim surface. It can be represented as an executable Lean state transition with a real theorem today. Full SmallWood/PCS soundness is a larger mathematical project and should come after the Lean toolchain and theorem gate are real.
  Date/Author: 2026-06-06 / Codex.

- Decision: Keep cryptographic hashes abstract in the first Lean milestone.
  Rationale: The no-replay theorem depends on equality of replay keys and consumed-set state, not on BLAKE3 cryptographic security. Hash-function implementation equivalence will be a later milestone tied to generated vectors and/or verified code extraction.
  Date/Author: 2026-06-06 / Codex.

- Decision: Add Lean-generated conformance vectors before attempting a larger proof-system theorem.
  Rationale: The active goal requires release Rust to be forced toward the Lean kernel. Generated bridge encoding and replay-state examples are a narrow but concrete differential gate, and they expose production drift faster than another prose claim.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize shielded nullifier state before full MASP balance.
  Rationale: Nullifier uniqueness is the production anti-double-spend invariant and is small enough to prove exactly in Lean today. Full per-asset balance conservation and AIR/proof-system soundness remain larger follow-on kernels.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize deterministic PoW fork-choice ordering before target arithmetic or network finality.
  Rationale: Greatest-work selection is a production-critical consensus rule and the actual implementation already had a small work/height/hash comparator. Proving that ordering and forcing the Rust helper to match is useful now, while full target arithmetic, timestamp behavior, scheduler assumptions, and long-range network finality remain larger kernels.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize `TransactionWitness` balance-slot validation before full AIR/proof-system semantics.
  Rationale: The exported transaction-balance claim was still model-only. The `TransactionWitness::balance_slots` and `validate` methods are a concrete production boundary for native fee accounting, non-native conservation, stablecoin issuance, and slot overflow. Proving and vector-checking that executable kernel makes the claim materially stronger while keeping note commitments, Merkle paths, nullifier derivation, and STARK soundness as explicit follow-on work.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize supply-digest and coinbase accounting before deeper proof-system soundness work.
  Rationale: Supply advancement is a production-critical consensus validity rule and native-node import boundary. The code already had consensus checked arithmetic, but native metadata paths used saturating addition. A Lean executable kernel plus generated vectors makes underflow/overflow/no-coinbase behavior explicit and forces both consensus and native Rust to conform.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize native block transfer ordering over already computed action-order keys before attempting verified BLAKE2 key derivation.
  Rationale: The production validity rule rejects a block when the shielded transfer-key subsequence is not nondecreasing. Proving and conformance-checking that predicate tightens the block import surface immediately, while BLAKE2 implementation equivalence and full action payload validation remain separate proof/refinement work.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize the self-contained proof payload policy before deeper recursive proof-system soundness.
  Rationale: The shipped product path depends on fail-closed proof availability and route-shape checks before any expensive cryptographic verification. Proving and vector-checking that executable admission table makes the consensus path less ambiguous now, while recursive proof soundness, tx leaf proof soundness, DA derivation, and native backend security remain separate larger proof obligations.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize PoW admission arithmetic before deeper bridge/light-client proof composition.
  Rationale: Compact target expansion, timestamp admission, hash-threshold comparison, and fixed-width cumulative-work checks are production-critical header validity rules and are explicitly reused by native import and bridge verification. Proving and vector-checking those arithmetic boundaries removes a stale formal gap before attempting full header serialization, retarget economics, or long-range finality proofs.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize transaction Merkle path control flow before Poseidon2 hash equivalence.
  Rationale: Input membership is a direct anti-counterfeiting rule in the shielded spend statement. The executable path-depth and left/right orientation logic can be proved and forced through Rust conformance now, while Poseidon2 collision resistance and implementation equivalence remain explicit cryptographic assumptions for a later proof/refinement pass.
  Date/Author: 2026-06-06 / Codex.

## Outcomes & Retrospective

This plan is in progress. The expected first outcome is not a complete verified Hegemon, but it must be a real Lean theorem that builds under a pinned toolchain and becomes part of the formal-core gate.

## Context and Orientation

The active branch is `codex/formal-blueprint-dag`. The current formal gate is `scripts/check_formal_core.sh`. It checks JSON claims, a blueprint DAG, bridge reference vectors, native backend vectors, and optional TLA+ model checkers. The current gap is that no claim is backed by a Lean theorem.

The first Lean project will live under `formal/lean`. The project will be deliberately small and dependency-light: no Mathlib dependency for the first theorem, because the theorem only needs Lean's core `List` library and decidable equality. The file `formal/lean/Hegemon/Bridge/Replay.lean` will define a `ReplayKey` as a byte list, a `ReplayState` as a consumed-key list, an executable `accept` transition, and the theorem that accepting a key prevents accepting it again in the resulting state.

The new script `scripts/check_lean_formal.sh` will build the Lean project with `lake build`, then scan Lean sources for forbidden proof placeholders or declared axioms. This scan is not the proof itself; it is a guard that prevents vacuous theorem files from passing.

## Plan of Work

First, create `formal/lean/lean-toolchain`, `formal/lean/lakefile.lean`, and `formal/lean/Hegemon/Bridge/Replay.lean`. The Lean file will define the executable replay-state kernel and prove that once a key has been inserted by `accept`, a second `accept` for the same key returns `none`.

Second, create `scripts/check_lean_formal.sh`. It will add `$HOME/.elan/bin` to PATH when present, require `lake`, run `lake build` in `formal/lean`, and reject forbidden text in `.lean` files: `sorry`, `admit`, and lines beginning with `axiom`.

Third, wire `scripts/check_formal_core.sh` to call `scripts/check_lean_formal.sh` before the JSON/vector checks complete. This makes Lean proof compilation part of the existing release-facing command.

Fourth, update docs and metadata. `DESIGN.md`, `METHODS.md`, `docs/SECURITY_REVIEWS.md`, and `config/formal-security-blueprint.json` should state that the bridge replay claim now has a named Lean theorem. They must not say every production claim is Lean-proved yet.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Install Lean tooling if missing:

    curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y --default-toolchain none
    export PATH="$HOME/.elan/bin:$PATH"

Build the Lean project:

    bash scripts/check_lean_formal.sh

Then run the full formal gate:

    bash scripts/check_formal_core.sh

## Validation and Acceptance

The first milestone is accepted when:

1. `bash scripts/check_lean_formal.sh` exits 0 and runs `lake build`.
2. `bash scripts/check_formal_core.sh` exits 0 and includes a mandatory Lean proof step.
3. `formal/lean/Hegemon/Bridge/Replay.lean` contains a named theorem proving duplicate replay rejection after acceptance.
4. The Lean source contains no `sorry`, `admit`, or declared `axiom`.
5. `hegemon-dev` can fetch the branch tip and run the same formal-core gate.

This does not complete the full active goal. It is the first machine-checked theorem and gate needed to make the goal real.

Observed local output on 2026-06-06:

    [3/10] Checking Lean formal proof kernel
    Build completed successfully (4 jobs).
    [6/10] Checking formal security claims ledger
    {
      "claims": 9,
      "passed": true,
      "production_eligible": 7,
      "residual_risks": 2
    }
    [7/10] Checking formal security blueprint DAG
    {
      "edges": 13,
      "falsification_cases": 13,
      "nodes": 9,
      "passed": true,
      "production_nodes": 7
    }

## Idempotence and Recovery

Installing `elan` with `--default-toolchain none` is safe to repeat. The Lean project pins its toolchain in `formal/lean/lean-toolchain`, so running `lake build` repeatedly should use the same Lean version. If toolchain download fails, rerun the command after network recovery. If `lake build` fails, fix the Lean file and rerun `bash scripts/check_lean_formal.sh`.

## Artifacts and Notes

Expected files:

    formal/lean/lean-toolchain
    formal/lean/lakefile.lean
    formal/lean/Hegemon/Bridge/Replay.lean
    scripts/check_lean_formal.sh
    scripts/check_formal_core.sh

## Interfaces and Dependencies

In `formal/lean/Hegemon/Bridge/Replay.lean`, define:

    abbrev ReplayKey := List UInt8

    structure ReplayState where
      consumed : List ReplayKey

    def ReplayState.accept (state : ReplayState) (key : ReplayKey) : Option ReplayState

    theorem accept_prevents_duplicate :
      ReplayState.accept state key = some next ->
      ReplayState.accept next key = none

Revision note 2026-06-06T06:43:00Z: Created this plan after confirming the repo has no Lean project and the local environment has no Lean tooling installed.

Revision note 2026-06-06T06:58:00Z: Recorded the first pinned Lean project, replay-state theorem, Lean shell gate, formal-core integration, metadata/doc updates, and passing local validation.

Revision note 2026-06-06T07:08:00Z: Recorded successful `hegemon-dev` validation of the pinned Lean theorem gate at commit `326a1c7d`.

Revision note 2026-06-06T18:17:00Z: Added Lean bridge encoding, two-phase replay theorems, generated Lean conformance vectors, a production `InboundReplayState` helper, and a protocol-kernel conformance test wired into the formal-core gate. Remote validation is still pending for this revision.

Revision note 2026-06-06T18:30:00Z: Recorded `hegemon-dev` validation for commit `972b6933`, including formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.

Revision note 2026-06-06T18:44:00Z: Added shared Lean byte helpers, a shielded nullifier-state Lean kernel, generated shielded conformance vectors, a production `NullifierState` helper, and native-node use of that helper. Remote validation is still pending for this revision.

Revision note 2026-06-06T18:50:00Z: Recorded `hegemon-dev` validation for commit `0e6e6030`, including formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.

Revision note 2026-06-06T19:24:00Z: Added Lean fork-choice ordering theorems, generated consensus conformance vectors, a shared production fork-choice helper used by PoW consensus and native import, and local Lean/generated-vector validation. Full local gate and `hegemon-dev` validation are still pending for this revision.

Revision note 2026-06-06T19:33:00Z: Recorded passing full local formal-core validation plus focused consensus/native tests for the fork-choice helper revision. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T19:42:00Z: Recorded `hegemon-dev` validation for commit `aab28185`, including full formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.

Revision note 2026-06-06T20:03:00Z: Added Lean transaction-balance theorems, generated transaction conformance vectors, a production `TransactionWitness` vector test, and local Lean/generated-vector validation. Full local gate and `hegemon-dev` validation are still pending for this revision.

Revision note 2026-06-06T20:13:00Z: Recorded passing full local formal-core validation for the transaction-balance revision plus the focused bad-balance verifier regression. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T20:25:00Z: Recorded `hegemon-dev` validation for commit `01cbd6f6`, including full formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.

Revision note 2026-06-06T20:30:00Z: Added the Lean supply-accounting kernel, generated supply vectors, consensus/native Rust conformance tests, and the native checked supply-digest overflow fix. Full local formal-core and `hegemon-dev` validation are still pending for this revision.

Revision note 2026-06-06T20:35:00Z: Recorded passing full local formal-core validation and focused consensus/native supply regressions for the supply-accounting revision. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T20:40:00Z: Recorded `hegemon-dev` validation for commit `9df3a4e1`, including full formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, wallet submission compatibility, and final active service status.

Revision note 2026-06-06T20:45:00Z: Added the Lean native action-ordering kernel, generated action-ordering vectors, native Rust conformance test, block validation helper routing, metadata/docs updates, and focused local validation. Full local formal-core and `hegemon-dev` validation are still pending for this revision.

Revision note 2026-06-06T20:50:00Z: Recorded passing full local formal-core validation for the native action-ordering revision. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T20:55:00Z: Removed the release-dead native action-ordering conformance helper, corrected the blueprint wording to name the production helper actually used by block import, and reran focused local tests, release build, and full formal-core validation. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T21:00:00Z: Recorded `hegemon-dev` validation for commit `778fcfc5`, including full formal-core, release rebuild without the earlier `hegemon-node` warning, service restart, smoke RPC checks, mining height advance, wallet submission compatibility, and final active service status.

Revision note 2026-06-06T21:05:00Z: Added the Lean consensus proof-policy kernel, generated proof-policy vectors, a production `evaluate_block_proof_policy` helper called by `ParallelProofVerifier`, a consensus conformance test, formal metadata/docs updates, and local validation. Remote `hegemon-dev` validation is still pending.

Revision note 2026-06-06T21:17:00Z: Recorded `hegemon-dev` validation for commit `cc446317`, including full formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, wallet submission compatibility, and final active service status.

Revision note 2026-06-06T21:48:00Z: Added the Lean consensus PoW-admission kernel, generated PoW vectors, consensus/light-client Rust conformance tests, strict consensus timestamp/compact-target hardening, metadata/docs updates, and local validation. Remote `hegemon-dev` validation is still pending.
