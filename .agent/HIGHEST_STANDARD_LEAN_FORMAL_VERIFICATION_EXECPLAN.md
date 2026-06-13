# Highest-Standard Lean Formal Verification for Hegemon

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file according to `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon should become the highest-standard Lean-formally-verified post-quantum privacy chain without turning the node into a slow research prototype. After this work, an operator, auditor, or contributor should be able to inspect a small set of top-level Lean theorems and see that the shipped native node admits only ledger transitions that preserve private-money safety: no unaccounted supply creation, no double spends, no unauthorized spends, correct commitment-tree evolution, per-asset conservation, exact proof-statement binding, fail-closed bridge and DA behavior, and release posture appropriate for a PQC chain. They should also be able to run one release gate, `bash scripts/check_formal_core.sh`, and see those theorem claims checked against production Rust entry points.

The coordinator thread owns this plan, the theorem matrix in `config/highest-standard-formal-verification-matrix.json`, the completion percentage, and integration back into `codex/superneo-formal-verification`. Subagents may audit or implement bounded slices, but this coordinator keeps the theorem targets coherent and prevents branch proliferation.

## Progress

- [x] (2026-06-13 04:14Z) Created the persistent Codex goal for highest-standard Lean formal verification on `codex/superneo-formal-verification`.
- [x] (2026-06-13 04:14Z) Confirmed the branch is clean at `19acdaab5b6bece8e0afcece57d8b4953ccfe36f`.
- [x] (2026-06-13 04:15Z) Started four read-only audit agents covering ledger invariants, proof-system boundaries, privacy/DA/bridge properties, and node/network/release refinement.
- [x] (2026-06-13 04:16Z) Added the first checked-in theorem matrix with weighted completion tracking. Initial highest-standard completion is 44.35%.
- [x] (2026-06-13 04:30Z) Integrated all four agent audit results into the theorem matrix. Current highest-standard completion is 59.46%.
- [x] (2026-06-13 05:06Z) Promoted supply and nullifier replay fragments into `Hegemon.Native.AcceptedChain` theorem targets. Current tracked completion is 60.00%.
- [x] (2026-06-13 05:18Z) Ran `bash scripts/check_formal_core.sh` for the `AcceptedChain` theorem slice; formal-core passed with 86 claims, 1074 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 05:33Z) Strengthened `Hegemon.Native.AcceptedChain` with `accepted_native_replay_chain_nullifiers_unique`, proving the accumulated `chainNullifiers` list is `List.Nodup` for accepted native replay chains. Current tracked completion is 60.14%.
- [x] (2026-06-13 05:45Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 86 claims, 1075 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 05:50Z) Removed the accepted-chain explicit `Nodup` guard by threading `ActionStreamEffect.importedNullifierStateFrom` and proving accepted stream imports preserve accumulated nullifier `List.Nodup`. Current tracked completion is 60.28%.
- [x] (2026-06-13 05:55Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 86 claims, 1076 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 06:08Z) Strengthened `Hegemon.Transaction.Balance` with per-asset no-transmutation theorems for non-stablecoin and stablecoin-enabled valid balances. Current tracked completion is 60.57%.
- [x] (2026-06-13 06:14Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 86 claims, 1081 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 06:51Z) Added theorem lifts for per-asset conservation, accepted proof-artifact balance soundness boundaries, accepted wrapper statement-surface facts, and accepted-chain startup/replay equivalence. Current tracked completion is 61.32%.
- [x] (2026-06-13 06:51Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 86 claims, 1088 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 07:10Z) Added `Hegemon.Privacy.Observer`, an explicit shielded-transaction observer/leakage boundary proving that private witnesses and prover randomness are not projected into the observer view. Current tracked completion is 61.61%.
- [x] (2026-06-13 07:10Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 87 claims, 1093 named Lean theorems, 84 production-eligible claims, 367 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 07:30Z) Added `Hegemon.Transaction.SpendAuthorization`, an explicit active-input authorization relation covering note commitment reconstruction, spend-authority derivation, nullifier derivation, Merkle membership, public slot authorization, and accepted-wrapper lift under `SpendAuthorizationSoundnessAssumption`. Current tracked completion is 62.06%.
- [x] (2026-06-13 07:30Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 88 claims, 1108 named Lean theorems, 84 production-eligible claims, 369 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 07:50Z) Added `Hegemon.Transaction.AcceptedTransactionSoundness`, combining accepted proof-wrapper surface, balance facts, public-input shape validity, per-asset delta consequences, and active-input authorization facts into one accepted-transaction relation under explicit balance and spend soundness assumptions. Current tracked completion is 62.63%.
- [x] (2026-06-13 07:50Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 89 claims, 1116 named Lean theorems, 84 production-eligible claims, 371 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 08:20Z) Added `Hegemon.Transaction.AssetIsolation`, proving accepted-relation authorized asset deltas, zero unselected non-native deltas, and the theorem that any nonzero non-native delta implies the selected stablecoin exception. Current tracked completion is 62.90%.
- [x] (2026-06-13 08:20Z) Strengthened `Hegemon.Privacy.Observer` so observer-visible ciphertext summaries are parsed from public chain wire bytes, with equal public inputs, chain ciphertext bytes, and placement implying equal allowed leakage. Current tracked completion is 63.19%.
- [x] (2026-06-13 08:20Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 90 claims, 1123 named Lean theorems, 84 production-eligible claims, 373 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 09:05Z) Added `Hegemon.Transaction.CanonicalVerifierBoundary`, defining the canonical deployed transaction verifier statement surface and proving that one `DeployedTxVerifierSoundnessAssumption` over that surface implies the accepted-transaction relation, native-delta consequences, and active-input spend facts. Current tracked completion is 63.76%.
- [x] (2026-06-13 09:20Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 91 claims, 1132 named Lean theorems, 84 production-eligible claims, 375 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 09:43Z) Added `Hegemon.Native.CommitmentTreeRefinement`, proving that accepted native action streams determine a canonical planned-start schedule, the corresponding action plan accepts with the same next leaf cursor, and accepted tree transitions expose the applied commitment-tree root. Current tracked completion is 63.94%.
- [x] (2026-06-13 09:43Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1138 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 10:22Z) Strengthened `Hegemon.Wallet.NoteCiphertextWire` and `Hegemon.Privacy.Observer` with accepted-summary suite/KEM format theorems for crypto parser summaries, chain containers, full chain ciphertexts, and observer-visible parsed summaries. Current tracked completion is 64.04%.
- [x] (2026-06-13 10:30Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1143 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 11:02Z) Strengthened the no-theft and canonical verifier boundary with indexed active-input spend facts and nullifier/commitment/ciphertext-vector agreement across public shape, statement preimage, and proof binding message. Current tracked completion is 64.55%.
- [x] (2026-06-13 11:10Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1149 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 11:42Z) Strengthened native replay/startup refinement with a carried ledger replay state for supply, commitment leaf cursor, spent nullifiers, and consumed bridge replay keys. Current tracked completion is 65.13%.
- [x] (2026-06-13 11:56Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1165 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 12:18Z) Strengthened legacy secure-channel and PQ Noise models with stateful protect/open transition theorems for direction-separated key slots and per-direction nonce-counter advancement. Current tracked completion is 65.31%.
- [x] (2026-06-13 12:35Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1179 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 13:12Z) Strengthened `Hegemon.Transaction.CanonicalVerifierBoundary` so the canonical verifier surface binds value-balance sign/magnitude, stablecoin policy/oracle/attestation/issuance payloads, and modeled active spend facts to the exact public-input, statement-hash, and proof-binding anchor/nullifier surface. Current tracked completion is 65.58%.
- [x] (2026-06-13 13:30Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1182 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 13:52Z) Strengthened `Hegemon.Transaction.SpendAuthorization`, `Hegemon.Transaction.AcceptedTransactionSoundness`, and `Hegemon.Transaction.CanonicalVerifierBoundary` with total indexed input-slot facts: every authorized aligned input slot is either inactive with zero public nullifier or active with full note-commitment, spend-authority, nullifier, and Merkle-membership facts bound to the canonical statement and proof-binding nullifier vectors. Current tracked completion is 65.82%.
- [x] (2026-06-13 14:10Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1189 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 14:32Z) Added `Hegemon.Native.BridgeMintSafety`, proving that accepted inbound bridge payloads expose proof-receipt presence, clean state-delta scope, replay-key/message binding, Hegemon destination binding, and payload-hash binding; fresh replay import consumes the key once and rejects immediate reimport; and accepted block/ledger replay couples bridge replay uniqueness with claimed supply. Current tracked completion is 65.99%.
- [x] (2026-06-13 14:45Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1194 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 15:05Z) Strengthened `Hegemon.Privacy.Observer` with a valid observer-chain surface tying parser-derived chain ciphertext summaries to the public active-output count, preserving active-output count under same public inputs and same allowed leakage, and lifting same-public/same-chain-wire valid worlds to equal allowed leakage. Current tracked completion is 66.20%.
- [x] (2026-06-13 15:20Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1200 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 15:40Z) Strengthened `Hegemon.Transaction.PublicInputs`, `Hegemon.Transaction.AcceptedTransactionSoundness`, and `Hegemon.Transaction.CanonicalVerifierBoundary` with indexed output-slot facts: every valid output slot is active with a nonzero public commitment or inactive with zero commitment/ciphertext hash, and the canonical verifier surface binds those fields through statement and proof-binding vectors. Current tracked completion is 66.36%.
- [x] (2026-06-13 16:00Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1210 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 177 implementation bindings.
- [x] (2026-06-13 16:30Z) Added `Hegemon.Native.BlockReplayInputProjection` and centralized native Rust replay-input construction through `native_block_replay_refinement_input_from_state`, proving that production-style projected replay inputs derive parent supply, leaf cursor, spent-nullifier state, and consumed bridge replay state from carried ledger state before reusing the accepted ledger replay startup theorem. Current tracked completion is 66.51%.
- [x] (2026-06-13 16:55Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1218 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 178 implementation bindings.
- [x] (2026-06-13 17:20Z) Deployed commit `915034ff` to `hegemon-dev` by fast-forwarding `/home/ubuntu/hegemon-current-4c4ea6d3`, rebuilding `target/release/hegemon-node` with `make node`, and restarting `hegemon-node.service`. Remote `bash scripts/smoke-test.sh` passed, mining advanced from height 9164 to 9171 over the liveness sample, `bash scripts/test-node.sh wallet-send` passed, and the final snapshot showed service active with zero restarts, height 9210, `is_mining=true`, `threads=1`, `blocks_found=57`, empty pending extrinsics, NTP active/synchronized, `HEGEMON_MINE=1`, `HEGEMON_MINE_THREADS=1`, `HEGEMON_PQ_STRICT_COMPATIBILITY=1`, and isolated-dev `HEGEMON_SEEDS=`.
- [x] (2026-06-13 17:45Z) Strengthened `Hegemon.Native.BridgeMintSafety` with a decoded bridge mint-amount boundary: accepted inbound bridge payloads have zero direct native mint delta under the current state-delta-free production surface; state-delta bridge payloads reject; any future decoded bridge mint amount is authorized only when payload-hash binding and decoded/external amount equality both hold; and formal-core metadata now requires block validation to run bridge payload admission before deriving inbound bridge replay keys. Current tracked completion is 66.68%.
- [x] (2026-06-13 17:55Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1222 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 18:15Z) Strengthened `Hegemon.Native.AcceptedChain` with an accepted ledger/tree replay relation: accepted chain replay now threads a commitment-root cursor through accepted tree transitions while projecting to an accepted ledger replay that preserves supply replay, leaf-cursor replay, canonical commitment plans, nullifier uniqueness, and bridge replay uniqueness. Current tracked completion is 66.80%.
- [x] (2026-06-13 18:30Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1226 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 19:10Z) Strengthened `Hegemon.Transaction.AssetIsolation` with accepted transaction-chain aggregate theorems: aggregate chain asset deltas equal aggregate authorized deltas, and any nonzero non-native aggregate delta requires at least one selected stablecoin exception. Current tracked completion is 66.90%.
- [x] (2026-06-13 19:25Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1231 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 19:50Z) Strengthened `Hegemon.Native.BridgeMintSafety` with accepted inbound bridge amount/replay composition theorems: an accepted inbound payload with an authorized decoded amount and fresh replay import carries payload authorization, payload-hash and amount equality, zero direct native mint delta, one-shot replay import, duplicate replay rejection, ledger replay supply equality, and final replay-key uniqueness. Current tracked completion is 66.98%.
- [x] (2026-06-13 20:05Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 92 claims, 1233 named Lean theorems, 84 production-eligible claims, 377 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 20:35Z) Added `Hegemon.Native.TxLeafCanonicalSurface`, composing accepted native tx-leaf/action binding with the canonical deployed verifier surface and explicit deployed verifier soundness assumption to derive the accepted transaction relation, field-level tx-leaf binding facts, and authorized per-asset delta values. Current tracked completion is 67.19%.
- [x] (2026-06-13 20:50Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 93 claims, 1238 named Lean theorems, 84 production-eligible claims, 379 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 21:05Z) Strengthened `Hegemon.Native.BlockReplayInputProjection` with a direct projected ledger-state executor and proved it extensionally equal to accepted projected replay, then lifted the startup-equivalence theorem through that direct executor. Current tracked completion is 67.41%.
- [x] (2026-06-13 21:20Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 93 claims, 1242 named Lean theorems, 84 production-eligible claims, 379 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 21:35Z) Strengthened `Hegemon.Native.TxLeafCanonicalSurface` with native active-input, total input-slot, and output-slot statement-binding composition theorems: accepted native tx-leaf/action binding plus the canonical deployed verifier surface now carries spend facts and output commitment/ciphertext facts bound to the exact statement/proof-binding vectors under the explicit deployed-verifier soundness assumption. Current tracked completion is 67.71%.
- [x] (2026-06-13 21:50Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 93 claims, 1245 named Lean theorems, 84 production-eligible claims, 379 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 22:05Z) Added `Hegemon.Privacy.NativeObserverSurface`, composing accepted native tx-leaf output-slot binding with the valid observer-chain surface so statement-bound output commitments/ciphertext hashes reach observer ciphertext summary format/count facts and same-chain-wire leakage equality under the explicit deployed-verifier soundness assumption. Current tracked completion is 67.92%.
- [x] (2026-06-13 22:25Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 93 claims, 1248 named Lean theorems, 84 production-eligible claims, 379 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 22:45Z) Added `Hegemon.Transaction.ProofSystemBoundary` and `Hegemon.Native.TxLeafCanonicalSurface.native_tx_leaf_deployed_verifier_boundary_facts`, packaging the explicit deployed-verifier assumption, canonical transcript/precondition bindings, deployed relation facts, accepted transaction relation, exposed spend/balance facts, and native tx-leaf/action equality facts into one future AIR/refinement target. Current tracked completion is 68.18%.
- [x] (2026-06-13 23:05Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 93 claims, 1252 named Lean theorems, 84 production-eligible claims, 379 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 23:35Z) Added `Hegemon.Native.DaSidecarReplayBinding`, composing accepted candidate artifact admission, candidate DA-root binding, proven-batch DA binding, recursive semantic DA-root sourcing, sidecar upload preconditions, action stream acceptance, wire replay projection counts, and projected replay startup equivalence into one DA/sidecar/replay fact package. Current tracked completion is 68.48%.
- [x] (2026-06-13 23:40Z) Ran formal-core metadata checks for the DA/sidecar replay-binding slice; claims passed with 94 claims, 1261 named Lean theorems, 85 production-eligible claims, and blueprint passed with 382 falsification cases and 180 implementation bindings.
- [x] (2026-06-13 23:45Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 94 claims, 1261 named Lean theorems, 85 production-eligible claims, 382 falsification cases, and 180 implementation bindings.
- [x] (2026-06-14 00:20Z) Added `Hegemon.Native.RawIngressSidecarReplayRecoverability`, composing accepted action-request projection, pending-action reload, staged ciphertext/proof reload, sidecar transfer-state materialization, DA/sidecar replay binding, and projected replay startup equivalence into one raw-ingress-to-replay fact package. Current tracked completion is 68.75%.
- [x] (2026-06-14 00:35Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 95 claims, 1269 named Lean theorems, 86 production-eligible claims, 385 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 14:52Z) Strengthened `Hegemon.Native.TxLeafCanonicalSurface` with `native_tx_leaf_canonical_artifact_boundary_facts`, packaging accepted native tx-leaf/action equality admission, canonical deployed-verifier facts, wrapper surface facts, root/fee/balance-slot/stablecoin identity bindings, spend/balance exposure, authorized asset delta, and receipt/public-input/proof/backend/ciphertext-payload binding into one implementation-equivalence theorem. Current tracked completion is 68.98%.
- [x] (2026-06-13 14:58Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 95 claims, 1270 named Lean theorems, 86 production-eligible claims, 385 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 15:10Z) Strengthened `Hegemon.Native.BlockReplayInputProjection` with a raw decoded native replay projection surface: decoded carried supply, leaf cursor, spent-nullifier state, consumed bridge replay state, actions, and block commitment flags now project into the existing projected replay executor, and accepted raw-projected replay inherits supply equality, leaf-cursor equality, canonical commitment-plan preconditions, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. Current tracked completion is 69.26%.
- [x] (2026-06-13 15:17Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 95 claims, 1277 named Lean theorems, 86 production-eligible claims, 385 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 15:45Z) Strengthened `Hegemon.Native.BridgeMintSafety` and `Hegemon.Native.RawIngressSidecarReplayRecoverability` so accepted inbound bridge amount/replay facts and accepted raw-ingress sidecar facts compose with projected and raw-decoded projected replay, exposing replayed supply equality, leaf-cursor equality, carried-state preconditions, canonical commitment-plan preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. Current tracked completion is 69.58%.
- [x] (2026-06-13 16:05Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 95 claims, 1280 named Lean theorems, 86 production-eligible claims, 385 falsification cases, and 180 implementation bindings.
- [x] (2026-06-13 15:48Z) Strengthened `Hegemon.Transaction.CanonicalVerifierBoundary`, `Hegemon.Transaction.ProofSystemBoundary`, `Hegemon.Privacy.Observer`, and `Hegemon.Privacy.NativeObserverSurface` with core statement-binding and active-output observer nonemptiness theorems. Current tracked completion is 69.88%.
- [x] (2026-06-13 15:54Z) Re-ran `bash scripts/check_formal_core.sh`; formal-core passed with 95 claims, 1284 named Lean theorems, 86 production-eligible claims, 385 falsification cases, and 180 implementation bindings.
- [ ] Add or strengthen production bindings for every native import/replay/startup path that can publish accepted state.
- [ ] Repeat `bash scripts/check_formal_core.sh` after each future theorem slice and deploy runtime-affecting validated heads to `hegemon-dev` for mining/transaction smoke.

## Surprises & Discoveries

- Observation: The current formal branch already has a broad formal-core gate, but its coverage is uneven when judged against highest-standard theorem/refinement criteria.
  Evidence: The last passing formal-core run at `19acdaab5b6bece8e0afcece57d8b4953ccfe36f` reported 86 theorem-backed claims and 1069 named Lean theorem declarations, while proof-system soundness and privacy remain mostly assumption-bound rather than fully mechanized.

- Observation: The strongest current areas are nullifier uniqueness, balance/conservation guardrails, statement binding, canonical encoding, replay/admission ordering, PQ channel engineering checks, and release/dependency posture.
  Evidence: Four read-only audit agents independently found no Lean `sorry`/`admit` holes in `formal/lean/Hegemon` and raised those matrix entries where the code has real theorem/vector/refinement evidence.

- Observation: The highest-value claims are still not fully proved: spend authorization, proof-system soundness, privacy/unlinkability/confidentiality, production bridge mint safety, and complete Rust/native-node refinement remain the main blockers.
  Evidence: Agents explicitly reported no end-to-end theorem that accepted spends imply authorized witnesses; no full deployed proof-system soundness theorem; no formal privacy game; and no complete raw-byte-to-state Rust refinement.

- Observation: The generated claim and blueprint metadata still named `codex/formal-equivalence-010`, a deleted historical branch.
  Evidence: `config/formal-security-claims.json` and `config/formal-security-blueprint.json` had `generated_for_branch` set to the old branch until this coordinator update.

- Observation: A local-only action-stream theorem is not enough for chain-wide double-spend safety because two individually accepted blocks can reuse a nullifier unless the modeled chain carries spent state across block boundaries.
  Evidence: The first accepted-chain draft accepted two copies of `validReplay`; the finalized `Hegemon.Native.AcceptedChain.validateNativeReplayChain` now threads `spentNullifiers` and rejects both stale spent-state and cross-block duplicate-nullifier replay.

- Observation: The next proof-system boundary improvement should collapse `BalanceSoundnessAssumption` and `SpendAuthorizationSoundnessAssumption` into one canonical deployed-verifier soundness assumption over the exact statement surface, not into a claim that the deployed proof system is already sound.
  Evidence: The proof-boundary audit identified `AcceptedTransactionSoundness`, `ProofWrapperAdmission`, `PublicInputBinding`, `StatementHash`, and `ProofStatementBinding` as enough to state a sharper `DeployedTxVerifierSoundnessAssumption`; STARK/AIR/SmallWood soundness and witness extraction remain undisguised residuals.

## Decision Log

- Decision: Track completion with a weighted theorem matrix rather than a single informal percent.
  Rationale: Hegemon has many security properties with different importance. No-counterfeiting and proof-system soundness should count more than release-posture policy, while all of them must be visible. The matrix makes progress auditable and prevents overclaiming.
  Date/Author: 2026-06-13 / Codex.

- Decision: Use `codex/superneo-formal-verification` as the only formal verification branch and keep this coordinator thread responsible for integration.
  Rationale: Formal verification work must not sprawl across branches. The branch was straightened so `codex/superneo-formal-verification` carries the verified head, while `codex/superneo-experiment` remains the base line.
  Date/Author: 2026-06-13 / Codex.

- Decision: Define 100% completion as top-level theorem plus production binding, not just Lean helper lemmas or generated vector tests.
  Rationale: The user explicitly rejected claims without proof. A highest-standard property must be stated as a theorem, have explicit assumptions, be checked by CI, and be connected to the shipped code path.
  Date/Author: 2026-06-13 / Codex.

## Outcomes & Retrospective

The immediate outcome is a concrete target and tracking system: 18 critical formal property families, weighted to 100 total points. The initial conservative completion was 44.35%; after four read-only audits, the branch-local tracked completion is 59.46%. This is not a claim of full formal verification. It means the coordinator now has an evidence-weighted baseline for what is already strong and what still blocks the highest standard.

The first theorem slice adds `formal/lean/Hegemon/Native/AcceptedChain.lean`. It proves `accepted_native_replay_chain_no_counterfeiting`, `accepted_native_replay_chain_nullifier_preconditions`, and `accepted_native_replay_chain_nullifiers_unique` over parent-linked native replay chains with carried spent-nullifier state, plus concrete rejection theorems for counterfeit second-block supply, stale spent state, and duplicate cross-block nullifier replay. The follow-up stream slice proves `evaluateActionStreamEffect_preserves_imported_nullifier_nodup` and refactors the accepted-chain relation to thread the same imported nullifier state as `ActionStreamEffect`, so chain uniqueness is derived from stream acceptance rather than an explicit duplicate guard. This raises the tracked baseline to 60.28% while leaving full raw-byte/native-node refinement, storage crash semantics, proof-system soundness, and cryptographic assumptions open.

The next theorem slice strengthens `formal/lean/Hegemon/Transaction/Balance.lean`. It proves that valid non-stablecoin balances have zero delta for every non-native asset, that valid stablecoin balances give the selected stablecoin asset exactly the authorized issuance delta, and that every other non-native asset remains zero. This raises the tracked baseline to 60.57% while leaving proof-system soundness and public-input/proof-artifact lifting open.

The latest theorem slice packages those balance helpers into `validBalance_per_asset_transaction_conservation`, adds `formal/lean/Hegemon/Transaction/AcceptedProofArtifact.lean` to conditionally lift balance facts to accepted proof wrappers under an explicit `BalanceSoundnessAssumption`, exposes accepted proof-wrapper statement-surface facts in `ProofWrapperAdmission`, and packages accepted native replay-chain supply/nullifier facts as `accepted_native_replay_chain_startup_equivalence`. This raises the tracked baseline to 61.32% while still leaving the deployed STARK/AIR soundness theorem, broader accepted-artifact field lift, complete native-node refinement, and privacy/confidentiality games open.

The privacy theorem slice adds `formal/lean/Hegemon/Privacy/Observer.lean`. It defines the public observer view for shielded transactions as public inputs, ciphertext bytes, parsed ciphertext summaries, block height, and action index, and proves that private witnesses and prover randomness do not affect that view. This makes the privacy target more honest by mechanizing the allowed-leakage boundary before any simulator-based ZK or ciphertext-indistinguishability claim. It raises the tracked baseline to 61.61%; proof-system privacy, ML-KEM/AEAD confidentiality, wallet metadata hygiene, timing privacy, network privacy, and complete wallet/native-node refinement remain open.

The spend-authorization theorem slice adds `formal/lean/Hegemon/Transaction/SpendAuthorization.lean`. It defines an explicit active-input authorization relation: the private witness must reconstruct the note commitment, derive the spend-authority public key from the spend secret, derive the public nullifier, and verify Merkle membership under the public root. The accepted-wrapper lift is intentionally conditional on `SpendAuthorizationSoundnessAssumption`, so the branch now has an honest Lean boundary for no-theft reasoning without claiming deployed STARK/AIR or SmallWood soundness. This raises the tracked baseline to 62.06%; discharging or production-binding that soundness assumption remains one of the central blockers.

The accepted-transaction soundness slice adds `formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean`. It packages proof-wrapper admission, accepted statement surface, valid balance facts, public input shape validity, per-asset delta consequences, and active-input authorization facts into a single relation that downstream no-counterfeiting and no-theft theorems can target. The relation is deliberately conditional on `BalanceSoundnessAssumption` and `SpendAuthorizationSoundnessAssumption`; it does not yet prove deployed STARK/AIR soundness, SmallWood soundness, verifier correctness, witness extraction, hash implementation equivalence, proof privacy, note encryption correctness, or complete Rust/native refinement. This raises the tracked baseline to 62.63%, with the next hard gap being to discharge the accepted-transaction soundness assumptions at the deployed verifier boundary.

The asset-isolation and observer chain-wire slice adds `formal/lean/Hegemon/Transaction/AssetIsolation.lean` and strengthens `formal/lean/Hegemon/Privacy/Observer.lean`. `AssetIsolation` proves that the accepted transaction relation authorizes every asset delta: native deltas match modeled native balance, unselected non-native deltas are zero, and any nonzero non-native delta implies the selected stablecoin exception. The observer strengthening proves ciphertext summaries are derived by parsing public chain ciphertext wire bytes and that equal public inputs, equal chain ciphertext bytes, and equal placement imply equal allowed leakage. This raises the tracked baseline to 63.19%. It still does not prove chain-level stablecoin policy/oracle/attestation authorization, bridge mint authorization, deployed verifier soundness, simulator-based ZK, ML-KEM/AEAD confidentiality, ciphertext indistinguishability, wallet metadata privacy, timing privacy, or complete Rust/native-node refinement.

The canonical verifier-boundary slice adds `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`. It defines `CanonicalTxStatementSurface` to bind proof-wrapper admission, public/serialized input binding, transaction statement preimage construction, proof binding-message construction, balance-slot asset agreement, and stablecoin field agreement, then proves that a single `DeployedTxVerifierSoundnessAssumption` over that surface implies the existing accepted-transaction soundness assumptions. This raises the tracked baseline to 63.76% by sharpening proof-system, statement-binding, spend-authorization, and per-asset-conservation accounting. It still does not prove deployed STARK/AIR, SmallWood, witness extraction, verifier implementation correctness, hash collision resistance, bincode/postcard correctness, stablecoin policy validity, bridge mint authorization, or complete Rust/native-node refinement.

The native commitment-tree refinement slice adds `formal/lean/Hegemon/Native/CommitmentTreeRefinement.lean`. It proves that accepted native action-stream replay determines a commitment-start schedule, that the canonical action-plan application accepts that schedule with the same next leaf cursor, and that an accepted consensus tree transition returns the applied commitment-tree root. This raises the tracked baseline to 63.94% by connecting previously separate native action-stream, action-plan, and tree-transition kernels. It remains non-production refinement evidence: Merkle hash security, note commitment correctness, transaction proof soundness, Rust commitment-tree implementation equivalence, reorg/startup replay equivalence, storage durability, and complete native-node refinement remain open.

The wallet/observer ciphertext-format slice strengthens `formal/lean/Hegemon/Wallet/NoteCiphertextWire.lean` and `formal/lean/Hegemon/Privacy/Observer.lean`. It proves generic accepted-summary facts for the modeled parsers: accepted crypto-format summaries have the fixed ML-KEM ciphertext length; accepted chain containers and full chain ciphertexts have the expected chain crypto suite and fixed ML-KEM length; and observer-visible summaries parsed from public chain wire bytes all have that accepted chain format. This raises the tracked baseline to 64.04% by narrowing the public ciphertext format boundary. It does not prove ML-KEM security, AEAD confidentiality, ciphertext indistinguishability, note plaintext-to-commitment binding, wrong-key behavior, simulator-based ZK, wallet metadata privacy, or complete wallet/native equivalence.

The indexed no-theft and canonical verifier-boundary slice strengthens `formal/lean/Hegemon/Transaction/SpendAuthorization.lean`, `formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean`, and `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`. It proves that any indexed active input in aligned public flag/nullifier/witness vectors yields note-commitment reconstruction, spend-authority derivation, nullifier derivation, and Merkle membership facts, then lifts that theorem through the accepted transaction relation and the canonical deployed-verifier boundary. It also strengthens `CanonicalTxStatementSurface` so nullifier, commitment, and ciphertext-hash vectors agree across public shape, statement preimage, and proof binding message. This raises the tracked baseline to 64.55%. It still depends on `DeployedTxVerifierSoundnessAssumption`; deployed STARK/AIR soundness, SmallWood soundness, witness extraction, verifier implementation correctness, hash security, and complete Rust/native refinement remain open.

The native ledger replay-state slice strengthens `formal/lean/Hegemon/Native/ActionStreamEffect.lean` and `formal/lean/Hegemon/Native/AcceptedChain.lean`. It proves that accepted action streams preserve `List.Nodup` for consumed bridge replay keys, then adds a carried `NativeLedgerReplayState` requiring each accepted block to match carried supply, commitment leaf cursor, spent nullifiers, and consumed bridge replay keys before replay. The packaged theorem `accepted_native_ledger_replay_chain_startup_equivalence` proves replayed supply equality, replayed leaf-cursor equality, canonical commitment-start plans, final nullifier uniqueness, and final bridge replay uniqueness, with concrete rejection examples for stale leaf cursors, duplicate bridge replay consumption, and stale bridge replay state. This raises the tracked baseline to 65.13%. It still operates over production-derived replay inputs; raw byte decoding, Merkle hash security, bridge proof/mint authorization, storage durability, and complete native-node equivalence remain open.

The PQ channel-state slice strengthens `formal/lean/Hegemon/Network/SecureChannel.lean` and `formal/lean/Hegemon/Network/PqNoise.lean`. It adds explicit modeled channel states and proves that successful protect/open operations use the role-correct directional key slot, consume the current send or receive nonce, increment only the corresponding counter, leave the opposite counter unchanged, and reject at that direction's counter overflow. This raises the tracked baseline to 65.31% by closing the previous missing full channel-state theorem gap. It still does not prove SHA-256/HKDF/AES-GCM/ML-KEM/ML-DSA security, OS RNG quality, handshake peer-authentication reductions, full active frame-path state refinement, network liveness, or complete native-node equivalence.

The canonical verifier payload-binding slice strengthens `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`. It adds `canonical_statement_surface_value_balance_bound`, `canonical_statement_surface_stablecoin_payload_bound`, and `canonical_surface_authorized_active_input_bound_to_statement`, proving that value-balance sign/magnitude, stablecoin policy/oracle/attestation/issuance payloads, and modeled active spend facts are bound to the exact public-input binding, statement-hash, and proof-binding anchor/nullifier surface. This raises the tracked baseline to 65.58% by narrowing the non-cryptographic statement-surface obligation for proof-system soundness and no-theft. It still depends on `DeployedTxVerifierSoundnessAssumption`; STARK/AIR, SmallWood, FRI, witness extraction, hash security, stablecoin policy validity, bridge mint authorization, and full native-node refinement remain open.

The total input-slot authorization slice strengthens `formal/lean/Hegemon/Transaction/SpendAuthorization.lean`, `formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean`, and `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`. It proves that every authorized aligned input slot is either inactive with zero public nullifier or active with note-commitment reconstruction, spend-authority derivation, nullifier derivation, and Merkle membership; lifts that through the accepted transaction relation and canonical deployed-verifier boundary; and binds the facts to the exact statement and proof-binding nullifier vectors. This raises the tracked baseline to 65.82%. It still depends on proof-system soundness assumptions and does not prove STARK/AIR, SmallWood, FRI, witness extraction, hash security, wallet custody, or complete native-node equivalence.

The bridge mint-safety slice adds `formal/lean/Hegemon/Native/BridgeMintSafety.lean`. It proves that accepted inbound bridge payloads imply proof-receipt presence, clean state-delta scope, replay-key/message binding, Hegemon destination binding, and payload-hash binding; that fresh replay import consumes a key once and immediate reimport rejects; that accepted block replay couples imported bridge replay-key uniqueness with expected and claimed supply; and that accepted ledger replay couples final consumed bridge replay-key uniqueness with replayed supply. This raises the tracked baseline to 65.99%. It still does not prove external-chain receipt soundness, exact decoded mint amount authorization, SCALE decoding correctness, bridge payload-hash cryptographic security, disabled RISC Zero receipt soundness, future PQ bridge receipt soundness, or complete native-node equivalence.

The observer-chain surface slice strengthens `formal/lean/Hegemon/Privacy/Observer.lean`. It defines `validObserverChainSurface`, requiring a valid public-input shape, parser-derived chain ciphertext summaries, and ciphertext-byte count equal to the public active-output count. It proves that valid observer summaries keep the chain suite/KEM shape, valid surfaces have exactly one parsed ciphertext summary per active public output, same public inputs preserve active-output count, same allowed leakage preserves active-output count, and valid same-public/same-chain-wire worlds have equal allowed leakage. This raises the tracked baseline to 66.20%. It still does not prove simulator-based ZK, ML-KEM/AEAD confidentiality, ciphertext indistinguishability, wallet metadata hygiene, timing privacy, network privacy, note plaintext-to-commitment correctness, BLAKE3 ciphertext-hash security, or complete wallet/native-node equivalence.

The output-slot statement-binding slice strengthens `formal/lean/Hegemon/Transaction/PublicInputs.lean`, `formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean`, and `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`. It defines indexed output slots and proves that valid output slots expose active nonzero public commitments or inactive zero commitment/ciphertext-hash pairs; lifts those facts through the accepted transaction relation; and binds the same output flags, commitments, and ciphertext hashes across public shape, statement preimage, and proof binding message in the canonical verifier surface. This raises the tracked baseline to 66.36%. It still does not prove output note plaintext correctness, recipient authorization, ciphertext indistinguishability, BLAKE3/Poseidon2 security or implementation equivalence, deployed AIR/STARK/SmallWood soundness, witness extraction, or complete Rust/native-node refinement.

The native replay-input projection slice adds `formal/lean/Hegemon/Native/BlockReplayInputProjection.lean` and centralizes production Rust construction through `native_block_replay_refinement_input_from_state` in `node/src/native/mod.rs`. The Lean theorem `accepted_projected_native_ledger_replay_chain_startup_equivalence` proves that projected replay inputs derive parent supply, leaf cursor, spent-nullifier state, and consumed bridge replay state from an explicit carried ledger state, that accepted projected chains preserve carried-state preconditions, and that the stronger accepted ledger replay startup theorem still gives replayed supply equality, replayed leaf-cursor equality, canonical commitment plans, final nullifier uniqueness, and final bridge replay-key uniqueness. The Rust helper is now called by mined import, announced import, and canonical replay before the fallible replay-refinement helper. This raises the tracked baseline to 66.51%. It still does not prove raw SCALE decoding, sled transaction implementation correctness, filesystem durability, full raw-action replay equivalence, tx-leaf/recursive proof soundness, PoW threshold validity, or complete native-node equivalence.

The bridge mint amount-boundary slice strengthens `formal/lean/Hegemon/Native/BridgeMintSafety.lean`. It proves that accepted inbound bridge payloads have zero direct native mint delta under the current production surface, because accepted inbound bridge payloads are state-delta-free; it proves state-delta-bearing inbound bridge payloads reject; and it defines a first-class decoded bridge mint-amount authorization surface requiring payload-hash binding plus decoded/external amount equality before any future decoded amount can be treated as authorized. The blueprint now also requires native block validation to run bridge payload admission before deriving inbound bridge replay keys. This raises the tracked baseline to 66.68%. It still does not implement or prove a live PQ-clean bridge mint payload grammar, external-chain proof soundness, SCALE decoder correctness, bridge payload-hash cryptographic security or implementation equivalence, disabled RISC Zero receipt soundness, future PQ bridge receipt soundness, raw-byte import/reorg/startup/sync refinement, or complete native-node equivalence.

The accepted ledger/tree replay slice strengthens `formal/lean/Hegemon/Native/AcceptedChain.lean`. It defines a modeled replay state carrying both the native ledger cursor and an abstract commitment-root cursor, proves that accepted ledger/tree replay projects to an accepted native ledger replay, proves the final commitment root equals replaying the accepted tree-transition chain, and packages those facts with supply replay, leaf-cursor replay, canonical commitment-plan preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. This raises the tracked baseline to 66.80%. It still does not prove Merkle hash security, note commitment correctness, raw action decoding, production tree mutation implementation equivalence, startup/reorg repair equivalence, storage durability, or complete native-node refinement.

The accepted transaction-chain asset-isolation slice strengthens `formal/lean/Hegemon/Transaction/AssetIsolation.lean`. It defines accepted asset transitions over the accepted transaction relation, proves each transition delta equals the authorized delta value, proves aggregate chain deltas equal aggregate authorized deltas, and proves that a nonzero non-native aggregate delta requires at least one selected stablecoin exception. This raises the tracked baseline to 66.90%. It still does not prove deployed proof-system soundness, production stablecoin policy/oracle/attestation admission, bridge mint authorization, raw action decoding, reorg/startup replay binding, or complete native-node refinement.

The bridge authorized-amount/fresh-replay composition slice strengthens `formal/lean/Hegemon/Native/BridgeMintSafety.lean`. It adds `accepted_inbound_payload_authorized_amount_fresh_replay_safe`, proving that accepted inbound bridge payload admission plus decoded amount authorization and fresh replay import jointly expose payload authorization, payload-hash binding, decoded/external amount equality, zero direct native mint delta, replay-key membership, imported count one, preserved replay-key uniqueness, and immediate duplicate rejection. It also adds `accepted_inbound_payload_authorized_amount_ledger_replay_safe`, which packages those bridge facts with accepted ledger replay supply equality and final consumed bridge replay-key uniqueness. This raises the tracked baseline to 66.98%. It still does not prove live bridge mint payload grammar, SCALE decoder correctness, external-chain/PQ receipt soundness, bridge payload-hash cryptographic security, raw-byte native import/reorg/startup/sync refinement, or complete native-node equivalence.

The native tx-leaf canonical-surface composition slice adds `formal/lean/Hegemon/Native/TxLeafCanonicalSurface.lean`. It proves that accepted native tx-leaf/action equality admission exposes field-level binding facts for nullifiers, commitments, ciphertext hashes, active counts, version, fee, stablecoin payload, balance tag, receipt statement hash, public-input digest, proof digest/backend, and ciphertext payload hash. It then composes those facts with the canonical deployed verifier surface and explicit `DeployedTxVerifierSoundnessAssumption` to derive the accepted transaction relation and authorized per-asset delta values. This raises the tracked baseline to 67.19%. It still does not prove deployed AIR/STARK/SmallWood soundness, SCALE decoder correctness, tx-leaf parser completeness, hash security, stablecoin policy admission, bridge mint authorization, recursive proof soundness, or complete native-node refinement.

The projected ledger-state executor slice strengthens `formal/lean/Hegemon/Native/BlockReplayInputProjection.lean`. It adds `projectedLedgerStateAfter`, proves `projectedLedgerStateAfter_eq_validate_projected_replay`, and packages `accepted_projected_ledger_state_after_startup_equivalence` so the direct production-style projected executor inherits accepted replay's supply equality, leaf-cursor equality, canonical commitment-plan preconditions, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. This raises the tracked baseline to 67.41%. It still does not prove raw SCALE decoding, sled transaction correctness, filesystem durability, full raw-action replay equivalence, tx-leaf/recursive proof soundness, PoW threshold validity, or complete native-node equivalence.

The native tx-leaf input/output slot binding slice strengthens `formal/lean/Hegemon/Native/TxLeafCanonicalSurface.lean`. It adds native wrappers around the canonical verifier boundary's active-input, total input-slot, and output-slot statement-binding theorems, proving that accepted native tx-leaf/action binding plus the canonical deployed verifier surface carries active input spend facts, inactive/active input-slot facts, and output commitment/ciphertext facts bound to the exact statement and proof-binding vectors. This raises the tracked baseline to 67.71%. It still does not prove deployed AIR/STARK/SmallWood soundness, witness extraction, raw SCALE decoding, tx-leaf parser completeness, hash security, stablecoin/bridge exception authorization, or complete native-node refinement.

The native observer output-slot surface slice adds `formal/lean/Hegemon/Privacy/NativeObserverSurface.lean`. It proves that valid observer-chain surfaces carry chain-format ciphertext summaries and an active-output count matching the public shape, composes those facts with accepted native tx-leaf output-slot binding, and proves same-chain-wire worlds preserve allowed leakage while retaining the statement/proof-binding output-slot facts. This raises the tracked baseline to 67.92%. It still does not prove simulator zero-knowledge, ML-KEM/AEAD confidentiality, wallet metadata privacy, timing privacy, proof-system privacy, deployed AIR/STARK/SmallWood soundness, ciphertext hash security, or complete native-node refinement.

The proof-system boundary facts slice adds `formal/lean/Hegemon/Transaction/ProofSystemBoundary.lean` and strengthens `formal/lean/Hegemon/Native/TxLeafCanonicalSurface.lean`. It packages the canonical deployed verifier surface, deployed relation facts, accepted transaction relation, wrapper preconditions, public-input binding validity, statement preimage success/length, proof binding-message success, vector binding, value-balance binding, stablecoin payload binding, and exposed spend/balance facts into `CanonicalDeployedVerifierBoundaryFacts`; the native tx-leaf theorem composes that package with accepted tx-leaf/action equality admission. This raises the tracked baseline to 68.18%. It still does not discharge `DeployedTxVerifierSoundnessAssumption`, deployed AIR/STARK/SmallWood soundness, witness extraction, verifier implementation equivalence, hash security, tx-leaf parser completeness, or complete native-node refinement.

The native tx-leaf artifact-boundary packaging slice strengthens `formal/lean/Hegemon/Native/TxLeafCanonicalSurface.lean`. `native_tx_leaf_canonical_artifact_boundary_facts` packages accepted native tx-leaf/action equality admission with the canonical deployed-verifier fact package, wrapper surface facts, root/fee/balance-slot/stablecoin identity bindings, spend/balance exposure, authorized asset delta, and receipt/public-input/proof/backend/ciphertext-payload binding. This raises the tracked baseline to 68.98% without changing runtime behavior. It still depends on `DeployedTxVerifierSoundnessAssumption`; deployed AIR/STARK/SmallWood soundness, witness extraction, verifier implementation equivalence, hash security, tx-leaf parser completeness, stablecoin/bridge authorization, and complete native-node refinement remain open.

The raw decoded native replay projection slice strengthens `formal/lean/Hegemon/Native/BlockReplayInputProjection.lean`. `accepted_raw_projected_ledger_state_after_startup_equivalence` maps decoded native replay fields into the projected replay executor and inherits accepted replay's supply equality, leaf-cursor equality, canonical commitment-plan preconditions, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. Representative raw decoded valid and stale-carried-state examples now pin acceptance and rejection at this layer. This raises the tracked baseline to 69.26% without changing runtime behavior. It still does not prove arbitrary raw SCALE/bincode decoding, hash implementation/security, sled transaction correctness, filesystem durability, tx/recursive proof soundness, or complete native-node equivalence.

The bridge/raw-ingress projected replay composition slice strengthens `formal/lean/Hegemon/Native/BridgeMintSafety.lean` and `formal/lean/Hegemon/Native/RawIngressSidecarReplayRecoverability.lean`. `accepted_inbound_payload_authorized_amount_projected_replay_safe` and `accepted_inbound_payload_authorized_amount_raw_projected_replay_safe` package accepted inbound payload authorization, decoded amount equality, zero direct native mint delta, one-shot replay import, replay duplicate rejection, replayed supply equality, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness over projected and raw-decoded projected replay. `accepted_raw_ingress_raw_projected_replay_binds_sidecar_rows` packages accepted action-request projection, pending/staged sidecar reload, sidecar transfer materialization, DA-root binding facts, raw accepted ledger replay, replayed supply equality, leaf-cursor equality, canonical commitment-plan preconditions, raw carried-state preconditions, and final replay-set uniqueness. This raises the tracked baseline to 69.58% without changing runtime behavior. It still does not prove arbitrary raw SCALE/bincode/JSON parser refinement, external-chain/PQ receipt soundness, bridge payload-hash/DA-root security, sidecar retention/availability, storage durability, proof soundness, or complete native-node equivalence.

The canonical core-binding and observer nonemptiness slice strengthens `formal/lean/Hegemon/Transaction/CanonicalVerifierBoundary.lean`, `formal/lean/Hegemon/Transaction/ProofSystemBoundary.lean`, `formal/lean/Hegemon/Privacy/Observer.lean`, and `formal/lean/Hegemon/Privacy/NativeObserverSurface.lean`. `canonical_statement_surface_core_binding` packages merkle-root/anchor, fee, balance-slot asset/count, value-balance, and stablecoin identity/payload agreement across public inputs, statement hash, and proof binding message; `canonical_boundary_facts_core_statement_binding` carries that package through the deployed-verifier boundary target. `output_slot_active_flag_count_nonzero` and `native_tx_leaf_active_output_slot_forces_nonempty_observer_ciphertexts` prove that active native tx-leaf output slots force nonempty observer ciphertext bytes and parsed summaries through a valid observer-chain surface. This raises the tracked baseline to 69.88% without changing runtime behavior. It still does not discharge deployed verifier/AIR soundness, prove indexed ciphertext-hash-to-wire correspondence, prove simulator zero-knowledge, or prove ML-KEM/AEAD confidentiality.

## Context and Orientation

The canonical branch is `codex/superneo-formal-verification`. The baseline commit is `19acdaab5b6bece8e0afcece57d8b4953ccfe36f`, which hard-disables legacy aggregation V4 and passed the full formal-core gate before branch cleanup. The formal sources live under `formal/lean`. The formal claim ledger is `config/formal-security-claims.json`, and the implementation-binding blueprint is `config/formal-security-blueprint.json`. The new theorem matrix is `config/highest-standard-formal-verification-matrix.json`.

The phrase "highest-standard formal verification" means more than having Lean files. For each critical property, the standard is: define the property as a top-level theorem over Hegemon's abstract ledger or node semantics; prove it in Lean or explicitly parameterize the cryptographic assumption needed; generate conformance evidence where Rust computes executable predicates; bind the shipped Rust entry points to those predicates; put the gates in `scripts/check_formal_core.sh`; and measure or avoid runtime cost when production code changes.

The phrase "little to no performance cost" means theorem work and CI gates should carry the weight wherever possible. Production runtime changes should be cheap admission checks, shared-helper reuse, exact parsers before expensive work, or existing replay planning. Any change that adds hashing, decoding, proof verification, tree replay, or sidecar scans on a hot path must include a benchmark or a clear argument that the computation already existed and was merely moved earlier.

## Plan of Work

First, keep the theorem matrix current. Each property entry has a stable id, a weight, a completion percentage, a theorem target, evidence, missing work, and a performance constraint. Whenever an agent proves a theorem, adds a production binding, or finds a gap, update the relevant entry and recompute `overall_completion_percent` as the weighted average.

Second, collapse helper-level facts into top-level theorems. The first target is `AcceptedNativeChainNoCounterfeiting`, which should combine the existing `Supply.lean` and `SupplyInvariant.lean` facts with native replay/import assumptions. The second target is accepted-chain nullifier uniqueness. These two properties have strong current evidence and high safety value.

Third, strengthen implementation refinement. The Rust paths in `node/src/native/mod.rs`, `consensus/src/pow.rs`, `consensus/src/reward.rs`, and proof-admission modules must call theorem-backed helpers before publishing state, mutating durable canonical indexes, or accepting blocks. The blueprint checker already supports implementation bindings, order constraints, result propagation, and dominance constraints; use those before inventing a new checker.

Fourth, make proof-system and privacy boundaries honest. If a theorem depends on STARK soundness, hash collision resistance, ML-KEM confidentiality, ML-DSA unforgeability, OS RNG quality, or native lattice backend assumptions, encode that dependency in the theorem statement or in a named assumption node. Do not mark those properties complete until the theorem target and assumption boundary are explicit.

Fifth, keep validation operational. Every major slice must pass `bash scripts/check_formal_core.sh`. If production code or deployment-relevant scripts change, update `hegemon-dev`, run mining and transaction smoke, and record the result.

## Concrete Steps

Work from `/private/tmp/hegemon-formal-work` on branch `codex/superneo-formal-verification`.

To inspect the goal and matrix:

    git switch codex/superneo-formal-verification
    python3 -m json.tool config/highest-standard-formal-verification-matrix.json >/tmp/hegemon-formal-matrix.pretty.json
    sed -n '1,120p' .agent/HIGHEST_STANDARD_LEAN_FORMAL_VERIFICATION_EXECPLAN.md

To recompute the overall percent after editing property percentages, use a small JSON-aware script or `jq` if available. The formula is:

    sum(property.weight * property.completion_percent) / sum(property.weight)

The current weights sum to 100, so the numerator divided by 100 is the displayed percent.

To validate formal work:

    bash scripts/check_formal_core.sh

To validate branch hygiene:

    cargo fmt --all --check
    git diff --check
    python3 -m json.tool config/highest-standard-formal-verification-matrix.json >/dev/null
    git status --short --branch

## Validation and Acceptance

The coordinator artifacts are accepted when `config/highest-standard-formal-verification-matrix.json` is valid JSON, this ExecPlan names the active branch and baseline commit, the completion percentage is defined by a reproducible formula, and `git status --short --branch` shows only intended changes before commit.

The overall goal is complete only when the matrix reaches 100% and the final branch passes `bash scripts/check_formal_core.sh`, targeted theorem/refinement tests, release/security gates, and `hegemon-dev` mining plus transaction smoke. A property cannot be set to 100% unless it has a named top-level theorem, explicit assumptions, production binding, and formal-core coverage.

## Idempotence and Recovery

The matrix and ExecPlan are additive documentation/control artifacts. They can be edited repeatedly. If an agent overstates a percentage, lower it and record the reason in the Decision Log. If a branch mistake occurs, recover by fetching `origin/codex/superneo-formal-verification` and resetting a clean worktree only after confirming there are no unrelated local edits to preserve.

## Artifacts and Notes

The branch cleanup before this plan left the remote formal surface as:

    codex/superneo-experiment
    codex/superneo-formal-verification

The verified baseline for this plan is:

    19acdaab5b6bece8e0afcece57d8b4953ccfe36f Hard-disable legacy aggregation V4

The last full formal-core pass at that baseline reported:

    claims=86
    named_lean_theorems=1069
    production_eligible_claims=84
    falsification_cases=365
    implementation_bindings=177

The latest full formal-core pass after the privacy observer slice reported:

    claims=87
    named_lean_theorems=1093
    production_eligible_claims=84
    falsification_cases=367
    implementation_bindings=177

The latest full formal-core pass after the spend-authorization boundary slice reported:

    claims=88
    named_lean_theorems=1108
    production_eligible_claims=84
    falsification_cases=369
    implementation_bindings=177

The latest full formal-core pass after the accepted-transaction soundness boundary slice reported:

    claims=89
    named_lean_theorems=1116
    production_eligible_claims=84
    falsification_cases=371
    implementation_bindings=177

The latest full formal-core pass after the asset-isolation and observer chain-wire slice reported:

    claims=90
    named_lean_theorems=1123
    production_eligible_claims=84
    falsification_cases=373
    implementation_bindings=177

The latest full formal-core pass after the canonical verifier-boundary slice reported:

    claims=91
    named_lean_theorems=1132
    production_eligible_claims=84
    falsification_cases=375
    implementation_bindings=177

The latest full formal-core pass after the native commitment-tree refinement slice reported:

    claims=92
    named_lean_theorems=1138
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the wallet/observer ciphertext-format slice reported:

    claims=92
    named_lean_theorems=1143
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the indexed no-theft/canonical verifier slice reported:

    claims=92
    named_lean_theorems=1149
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the native ledger replay-state slice reported:

    claims=92
    named_lean_theorems=1165
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the PQ channel-state slice reported:

    claims=92
    named_lean_theorems=1179
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the canonical verifier payload-binding slice reported:

    claims=92
    named_lean_theorems=1182
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the total input-slot authorization slice reported:

    claims=92
    named_lean_theorems=1189
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the bridge mint-safety slice reported:

    claims=92
    named_lean_theorems=1194
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the observer-chain surface slice reported:

    claims=92
    named_lean_theorems=1200
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the output-slot statement-binding slice reported:

    claims=92
    named_lean_theorems=1210
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=177

The latest full formal-core pass after the native replay-input projection slice reported:

    claims=92
    named_lean_theorems=1218
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=178

The latest full formal-core pass after the bridge mint amount-boundary slice reported:

    claims=92
    named_lean_theorems=1222
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=180

The latest full formal-core pass after the accepted ledger/tree replay slice reported:

    claims=92
    named_lean_theorems=1226
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=180

The latest full formal-core pass after the accepted transaction-chain asset-isolation slice reported:

    claims=92
    named_lean_theorems=1231
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=180

The latest full formal-core pass after the bridge authorized-amount/fresh-replay composition slice reported:

    claims=92
    named_lean_theorems=1233
    production_eligible_claims=84
    falsification_cases=377
    implementation_bindings=180

The latest full formal-core pass after the native tx-leaf canonical-surface slice reported:

    claims=93
    named_lean_theorems=1238
    production_eligible_claims=84
    falsification_cases=379
    implementation_bindings=180

The latest full formal-core pass after the projected ledger-state executor slice reported:

    claims=93
    named_lean_theorems=1242
    production_eligible_claims=84
    falsification_cases=379
    implementation_bindings=180

The latest full formal-core pass after the native tx-leaf input/output slot binding slice reported:

    claims=93
    named_lean_theorems=1245
    production_eligible_claims=84
    falsification_cases=379
    implementation_bindings=180

The latest full formal-core pass after the proof-system boundary facts slice reported:

    claims=93
    named_lean_theorems=1252
    production_eligible_claims=84
    falsification_cases=379
    implementation_bindings=180

The latest metadata check after the DA/sidecar replay-binding slice reported:

    claims=94
    named_lean_theorems=1261
    production_eligible_claims=85
    falsification_cases=382
    implementation_bindings=180

The latest full formal-core pass after the DA/sidecar replay-binding slice reported:

    claims=94
    named_lean_theorems=1261
    production_eligible_claims=85
    falsification_cases=382
    implementation_bindings=180

The latest metadata target after the raw-ingress sidecar replay-recoverability slice is:

    claims=95
    named_lean_theorems=1269
    production_eligible_claims=86
    falsification_cases=385
    implementation_bindings=180

The latest full formal-core pass after the raw-ingress sidecar replay-recoverability slice reported:

    claims=95
    named_lean_theorems=1269
    production_eligible_claims=86
    falsification_cases=385
    implementation_bindings=180

The latest full formal-core pass after the native tx-leaf canonical artifact-boundary packaging slice reported:

    claims=95
    named_lean_theorems=1270
    production_eligible_claims=86
    falsification_cases=385
    implementation_bindings=180

The latest full formal-core pass after the raw decoded native replay projection slice reported:

    claims=95
    named_lean_theorems=1277
    production_eligible_claims=86
    falsification_cases=385
    implementation_bindings=180

The latest full formal-core pass after the bridge/raw-ingress projected replay composition slice reported:

    claims=95
    named_lean_theorems=1280
    production_eligible_claims=86
    falsification_cases=385
    implementation_bindings=180

## Interfaces and Dependencies

The primary interface for progress tracking is `config/highest-standard-formal-verification-matrix.json`. The primary proof interface is Lean 4 under `formal/lean`. The primary production-binding interface is `config/formal-security-blueprint.json` plus the formal-core checker under `scripts/hegemon_formal_core`. The primary release gate is `scripts/check_formal_core.sh`.

Subagents should report findings in terms of matrix property ids. When a subagent changes code, it must own a disjoint write set and must not delete or rewrite another agent's work. The coordinator integrates, validates, commits, and deploys.

Revision note 2026-06-13 / Codex: Created this plan to turn the user's highest-standard formal verification goal into a branch-local coordinator artifact with explicit theorem targets and percentage tracking.
