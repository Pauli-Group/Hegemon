# Check narrow pre-mainnet candidate obligations

This living ExecPlan follows `.agent/PLANS.md`. The coordinator owns integration, feature qualification and release authority. This worker owns only the new `formal/lean/Hegemon/Release/LaunchCandidate.lean` and this companion file.

## Purpose / Big Picture

The pre-mainnet candidate changes mining allocation, treasury custody, network identity and atomic-swap conditions. These new Lean theorems check specific arithmetic and chronological consequences that the source relations must enforce. They let a reviewer see why rounded allocation conserves the subsidy, why full network bytes cannot alias through field reduction, why initialized distinct approvals require distinct credentials, and why an immature refund cannot pass a small field-difference range check. They do not authorize the candidate or substitute for actual proofs through the node and wallet.

## Progress

- [x] 2026-10-04: Read the existing native independent-proof boundary and inspect the current workers' interfaces.
- [x] 2026-10-04: Create an isolated worktree from `codex/pre-mainnet`; preserve all old RP05 sources and receipts.
- [x] 2026-10-04: Implement the arithmetic, byte encoding, full-owner, approval-history and HTLC obligations in a new standalone Lean module.
- [x] 2026-10-04: Check with the repository's installed Lean 4.32.2 compiler and inspect declared theorem axioms.
- [ ] Coordinator: compare final frozen source constraints and projection vectors with this model, then run changed-candidate proof and lifecycle qualification.

## Surprises & Discoveries

The previous exact-intent projection retained parent height, which changes during sequential approvals. It also retained disabled stablecoin roots, which can change independently of the treasury payment. The RP06 worker now zeros these dynamic context coordinates only in the spending-intent preimage; each actual proof and node import must still authenticate the current context. The source treasury nullifier is retained, while the approval accumulator nullifier stays omitted to avoid a circular commitment to an accumulator that itself contains the intent.

Full network binding fits the existing 104-word intent preimage by occupying eight formerly fixed-zero coordinates. Seven more such coordinates hold the exact source value-note nullifier. The public successor schema is explicitly 128 words, including eight exact little-endian 32-bit network words. The historical RP05 public codec is not reinterpreted.

The new HTLC graph originally reused the first lane index for all 64 copy equations in a batch. The implementation worker corrected this to include the lane index. Its development verifier argument order was also corrected after source inspection. Neither correction is counted here as a proof or end-to-end result.

## Decision Log

Decision: prove narrow mathematical consequences under named relation and initialized-history premises. Rationale: a universal Rust/compiler/operating-system refinement is outside this task, while pretending that successful host checks alone prove relation soundness would be incorrect. Date/author: 2026-10-04 release-sequence worker.

Decision: retain standard Lean kernel proofs without extra axioms, `sorry`, or `native_decide`. Rationale: the arithmetic and finite layouts are small enough for ordinary checked proofs. Date/author: 2026-10-04 release-sequence worker.

Decision: distinguish distinct policy slots from distinct credentials. Rationale: two different indices do not establish two keys when both slots have the same tag. The final threshold theorem explicitly consumes tag distinctness for the approved slots; unused zero-padded slots need not be distinct. Date/author: 2026-10-04 release-sequence worker.

## Context and Orientation

`LaunchCandidate.lean` imports only `Std`; it can be checked directly without rebuilding the existing formal package or producing node binaries. A digest is modeled as seven coordinates, matching the native seven-field-word authorization identity. A chronological approval history is an inductively built history beginning at zero approvals; each step adds one previously absent signer with a concrete credential whose complete tag matches the policy slot. This is stronger than accepting an arbitrary bitmap supplied by a caller. Connecting the real ledger predecessor to that initialized history requires the note-binding, membership and prior-admission premises described below.

## Plan of Work

The implementation is additive. The reward section proves exact conservation, rounding and fee allocation. The network section proves that packing four bounded bytes as a little-endian 32-bit word is injective, extends that result to all eight words, and checks the exact RP06 replacement-slot layout. The owner section proves that splitting a seven-word identity into four authorization words and three extension words loses no coordinate. The approval section proves distinctness and credential origins by induction, then derives the two-credential result under the source's tag-distinctness premise. The HTLC section proves integer maturity and conservation from the actual field-range bounds, and that an accepted branch prevents a subsequent conflicting branch when both use one atomic spent-nullifier state.

## Source enforcement map

The map was reviewed against the workers' source on 2026-10-04. It is a map for final integration review, not a claim that these moving files have a frozen source hash.

| Lean obligation | Concrete source enforcement | Explicit remaining bridge |
|---|---|---|
| `reward_conservation`, `funding_rounding`, `all_fees_go_to_miner`, `checked_reward_fits` | `protocol/shielded-pool/src/poseidon2_v8_coinbase.rs::poseidon2_v8_reward_split`; `node/src/native/block_flow.rs::validate_coinbase_reward_split` and contextual `validate_coinbase_funding_accounting` | All import, restart and reorg paths must use the contextual recipient check; checked Rust arithmetic must match the modeled natural numbers. No claim that a miner must issue a reward when forfeiture is permitted. |
| `network_encoding_injective`, `network_words_are_canonical` | `smallwood_poseidon2_v8_rp06.rs::Rp06PublicStatement::{network_words,to_public_words,try_from_public_words}` and `verify_rp06_candidate`; HTLC `bytes_words`, `HtlcStatement::{binding_bytes,validate_context}` | Native admission must supply the immutable manifest identity and compare the entire 32 bytes, not an attacker-selected identity or old 32-bit profile identifier. No theorem about BLAKE3 collision resistance or JSON manifest parsing. |
| `rp06_projection_has_104_words`, `rp06_network_source_slots_disjoint`, `rp06_all_network_source_words_retained` | RP06 `RP06_INTENT_NETWORK_POSITIONS`, `RP06_INTENT_VALUE_NULLIFIER_POSITIONS`, `rp06_intent_projection_from_public` | Exact generated constraints, transcript and source projection must share these coordinates. The finite layout facts do not establish the complete Rust projection-to-semantic-tuple refinement. |
| `full_seven_owner_roundtrip`, `full_seven_owner_injective` | Native owner is authorization-key words 0–3 plus randomness words 0–2; RP06 `rp06_value_authorization`, `rp06_accumulator_authorization`; HTLC `owner_words` and `bind_locked_note`; funding validator compares all seven | Collision/extraction properties of the owner hash and secret-key encoding remain independent cryptographic premises. A private descriptor is not an authorization witness. |
| `economic_intent_encoding_injective` | RP06 successor intent binds full network, source value-note nullifier, output commitments, ciphertext commitments, fee and remaining immutable operation words | This theorem concerns the semantic preimage, not hash injectivity. Output values/recipients/randomness are bound through note commitments; they are not asserted to be public scalar fields. Actual hash binding and projection correspondence must be qualified. |
| `approval_history_distinct`, `approval_history_origins`, `threshold_two_distinct_credentials` | V8/RP06 `push_auth_constraints`: count-zero inactive predecessor, positive-count active predecessor, one fresh bitmap bit, full seven-word credential equality, active-slot gate and first-limb distinctness; `FinalThresholdSpend` checks threshold and exact intent | Membership, full owner binding, the ledger's previous accepted creation and unspent atomic state must establish a real initialized predecessor history. The source enforces positive ordinary values and zero/native accumulator values; counterfeit accumulator creation must be tested directly. Two distinct secret values do not prove two independent human operators. |
| `refund_range_proves_maturity`, `lock_range_proves_future_timeout` | HTLC `HtlcAdapter::from_statement`: 48-bit timeout, `range(parent-timeout,48)` for refund and `range(timeout-parent-1,48)` for lock; context validation compares authenticated parent | This is a Goldilocks integer-range argument, not a local timer rule. Node application must use the actual accepted parent and recheck on ordered import. |
| `htlc_field_balance_is_integer_balance` | HTLC graph restricts input/output/fee to 56-bit values, requires positive input/output, native asset, and `input=output+fee` | The theorem discharges field-wrap arithmetic. Merkle inclusion, authority, full policy commitment, ciphertext bytes, and the complete SHA-256 claim relation require their own adapter/proof checks. |
| `claim_refund_same_nullifier`, `accepted_claim_blocks_refund`, `accepted_refund_blocks_claim` | HTLC `htlc_nullifier` and source graph use key5, two zeros, position and rho, independently of branch; the opened locked owner binds the shared key; native state consumes nullifiers | Hash binding prevents opening the same policy note under another key. Membership authenticates the position. State must check and consume atomically, including block ordering/reorg. No assumption that separate stale snapshots prevent concurrent spends. |

## Concrete Steps

From the repository's `formal/lean` directory, run:

    lean Hegemon/Release/LaunchCandidate.lean

The command must exit zero. The printed theorem dependencies must contain only standard logical/kernel axioms, currently `propext` and `Quot.sound`, without `sorryAx` or a new declared axiom. The module does not need a network connection, new dependency or heavy build. From the repository root, run `git diff --check` before integrating the two new files.

## Validation and Acceptance

Lean checking establishes the stated mathematical results only. Final integration still needs source-owned malicious-witness tests that bypass wallet/host preflight, complete generated RP06 and HTLC proofs, and independent public-only verification of retained unchanged bytes. Test all treasury signer pairs, duplicate/wrong signer, changed exact source/recipient/fee/ciphertext/network, zero-valued ordinary output, forged accumulator origin, immature refund, invalid secret, same-note opposite-branch replay and changed secret-release mode. Measure actual new proof size, geometry and performance; the historical SHA-only proof and RP05 receipts do not qualify these successors.

The candidate's one-to-five reward arithmetic, full seven-word funding recipient, and complete proof bytes must also survive wallet/RPC, peer relay, mempool, mining, block import, restart, reorg and fresh-node sync. Selection of production authority and the release manifest remain with the coordinator. No activation, replacement receipt or deployment is performed by this module.

## Idempotence and Recovery

The direct Lean command is read-only unless explicit output flags are added. It may be rerun after these new files change. Existing sources, wallet state, node data, artifacts and receipts are untouched. If feature interfaces change, update the source map and affected statements before treating a prior compile as current evidence.

## Artifacts and Notes

The installed compiler is Lean 4.32.2, matching `formal/lean/lean-toolchain`. The initial module compiled in under one second before the small finite-layout checks were added. Final validation is reported by the coordinator from the exact integrated source. No machine-generated receipt is created by this worker.

## Interfaces and Dependencies

All definitions and theorems are under `Hegemon.Release.LaunchCandidate`. No existing package import root or release gate is edited. The parent can import this new module or run the direct command when integrating the formal checks, while separately freezing the concrete candidate's source inventory and evidence.

## Outcomes & Retrospective

The additive module delivers explicit mathematical obligations with narrow source mappings. It does not close the complete changed-candidate security, artifact, lifecycle or release gate. Those remaining obligations are listed above, without demanding an unrelated universal Rust refinement.

Plan revision: created the bounded formal implementation and recorded its exact limits and remaining source/artifact bridges.
