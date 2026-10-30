# Audit: PR 205

**Title:** RP05: public ZK, single-spend history and independent-review resolutions
**URL:** https://github.com/Pauli-Group/Hegemon/pull/205
**State:** open
**Author:** pldallairedemers
**Base:** `main`
**Head:** `codex/smallwood-pq128-experiment` @ `f322352ccdfe6da3310fb43dfc0adcb35660095f`
**Head subject:** `test(node): synchronize pending-action pause release to prevent lost wakeup` (2026-10-02 10:07 -0600)
**Merge base:** `b819911dbf6d045501a3526da1268f1fa83092ea`
**Range:** 91 commits, three-dot diff about 4,953 files, 1,553,621 insertions, 114,823 deletions
**Auditor:** code reading of the branch above against `origin/main`. Lean was not rechecked and the node test suite was not re-run.
**Date:** 2026-10-02

## Verdict

No confirmed consensus double-spend, proof-skip, or authorization bypass on the wired path. Fresh Poseidon2 V8 / SMZA production authority is still absent: `smallwood_poseidon2_production_capability()` returns `None`, and a V8 binding cannot be turned on through a historical replay row. Merging this pull request does not activate RP05 spends.

The live single-spend check for V8 is the seven-limb nullifier set inside `poseidon2_v8_state`, applied only after proof verification and in leaf order. The new canonical-membership store, reorg WAL, and block-store v3 are compiled into the node crate and are not called from block commit or reorg. The legacy 48-byte nullifier tree remains the authority for non-V8 actions.

The highest practical gaps are operational: the mempool does not track V8 nullifiers, so two otherwise valid spends of the same note can both sit pending until block assembly rejects one; the wallet mirror applies decoded V8 statements without locally verifying the STARK; and a large unused membership/WAL layer can be mistaken for the live spend set.

## What this pull request is

The branch carries the SmallWood Poseidon2 V8 / SMZA experiment: circuit and transport code, a native verifier and typed state store, wallet prove/sync paths, a large Lean package, and checked-in qualification artifacts. The pull-request text says the self-contained proof path is unchanged through wallet, relay, mempool, mining, blocks, sync, restart, reorg, and fresh-node verification, and that it does not grant activation, merge, or deployment authority.

That activation claim matches the source registry:

```503:507:protocol/versioning/src/lib.rs
pub const fn smallwood_poseidon2_production_capability(
) -> Option<SmallwoodPoseidon2ProductionCapability> {
    None
}
```

`proof_authority_decision` returns `Denied` for the V8 version binding whenever that capability is absent, including when a historical authorization row is supplied. `fresh_transaction_proof_capabilities()` is therefore empty. `VersionSchedule::allowed_at` intersects any operator schedule with that source list, so a schedule entry cannot invent proof authority.

The tip commit only changes a test helper. `release_pending_action_group_test_hold` now takes the predicate lock before clearing a test hold, so a notify cannot be lost between the predicate check and `wait`. Production commit/rollback code is untouched by that commit.

## Scope

Reviewed closely:

- `protocol/versioning/src/lib.rs` proof-authority decision
- `consensus/src/proof.rs` block-proof policy, especially `InlineRequired`
- `consensus/src/version_policy.rs`
- `node/src/native/admission.rs` transfer and nullifier admission
- `node/src/native/poseidon2_v8_verifier.rs` and `poseidon2_v8_state.rs` ordered verify/apply
- `node/src/native/node_impl.rs` V8 preflight, canonical replay, and the independent-proof preflight header
- `node/src/native/block_flow.rs` supply and replay refinement
- `node/src/native/nullifier_accumulator.rs`, `canonical_membership.rs`, `reorg_wal.rs`, `fork_retention.rs` at the integration boundary
- wallet prove, route selection, tape allocation, and V8 sync
- `experimental/htlc-prototype` isolation from the node binary
- `DESIGN.md` / `METHODS.md` claim text against those gates

Not line-reviewed: about 3,400 Lean modules, `.agent` artifacts and proof binaries, spikes, prototypes, and the bulk of `circuits/transaction/src/smallwood_engine.rs`. Formal endpoints were checked for how the Rust gate treats them, not re-proved.

## Findings

### M1 — V8 mempool admission does not see the nullifiers that block apply uses

**Severity:** medium (availability and miner work; not a committed double-spend)

V8 actions are required to leave the legacy nullifier vector empty:

```1104:1123:node/src/native/admission.rs
    // V8 has a fresh seven-limb state grammar.  Its outer legacy anchor,
    // nullifier, and commitment fields must remain empty; contextual decode,
    // proof verification, and typed state replay are performed by the V8
    // connector at the actual candidate/block height.
    if is_poseidon2_v8_action(action) {
        if action.anchor != [0u8; 48]
            || !action.nullifiers.is_empty()
            || !action.commitments.is_empty()
            || action.candidate_artifact.is_some()
        {
            return Err(anyhow!(
                "Poseidon2 V8 action must not carry legacy 48-byte anchor, nullifier, commitment, or artifact state"
            ));
        }
```

Mempool duplicate detection then walks `action.nullifiers` only (`mempool_transfer_nullifier_admission_state`). An empty list is `Valid`. Each spend can still pass `verify_poseidon2_v8_action_batch_against_parent` against the parent tip, because each proof is checked while the note is unspent. Two such actions can both enter the mempool.

Block apply rejects the second. In `poseidon2_v8_state`, each window is verified, results are consumed in leaf order, and a nullifier already in the attach set or the persisted tree returns `DuplicateNullifier` or `SpentNullifier` before `current_root` advances. A mined block that contains both spends does not commit.

Effect once the capability is turned on: mempool bloat, failed block templates, and wasted proving. The chain tip does not record both spends.

### M2 — Canonical membership, reorg WAL, and block-store v3 are not the live spend set

**Severity:** medium (integration hazard and review hazard)

`node/src/native/mod.rs` declares `canonical_membership`, `reorg_wal`, and `block_store_v3`. `CanonicalMembership` is documented as disk-authoritative exact membership for canonical 48-byte keys. A search of `node_impl.rs` and `storage.rs` shows no calls. Live reorg still edits the legacy nullifier index inside the existing sled transaction (`commit_reorg_suffix_atomically` / full rebuild against `best.nullifier_root`).

`nullifier_accumulator::plan_indexed_append` documents that duplicate membership is the caller's invariant. Current block planning runs the stream effect check before that append. A later caller that persists accumulator rows without the same check can make the accumulator longer than the spent set.

There is also a V2/V3 accumulator split. Production comments say the active raw-48/v2 accumulator has no raw-to-typed adapter at the version boundary. Mixing header roots across those domains would fail admission rather than silently accept a second spend, but only if both sides stay on one encoding.

Do not treat the new membership module as what prevents double-spends today.

### M3 — Wallet V8 mirror updates notes from decoded statements without verifying the proof

**Severity:** medium for a wallet that syncs from an untrusted RPC; not a consensus bug

`wallet/src/poseidon2_v8_sync.rs` decodes inline arguments and updates owned notes, nullifiers, and the stablecoin root. That module does not call the STARK verifier. `wallet/src/async_sync.rs` does require the walked block hash to match the node before apply, so a node that is already enforcing proofs protects an honest sync. A node or proxy that serves a hash-consistent block with an unproven payload can poison the local mirror: phantom balance, or a note the wallet will try to spend and the real network will reject.

The spend path used by `prove_verify_and_submit_poseidon2_v8` still proves and verifies locally before RPC. This finding is the mirror, not that submit path.

### L1 — `InlineRequired` is now an accepting policy

**Severity:** low while the production capability is empty; high impact on the day that capability is filled in

On `main`, `evaluate_block_proof_policy` rejects `ProofVerificationMode::InlineRequired` as `UnsupportedInlineRequired` and otherwise requires a proven batch plus a recursive block artifact.

On this branch, `InlineRequired` is accepted when every transaction has a validity artifact and the block carries neither a proven batch nor a block artifact (`consensus/src/proof.rs` around the policy function). Native independent-proof preflight builds exactly that shape and sets `proof_verification_mode: InlineRequired` (`node_impl.rs` in `verify_independent_smallwood_actions_against_parent`).

The preflight header sets `nullifier_root` to `NATIVE_EMPTY_DIGEST48` and comments that the independent tx-leaf verifier does not consume the block-level nullifier accumulator. That header is a preflight object. Mined-work admission still compares `work.nullifier_root` to the preview root from pending actions. V8 actions leave this preflight and go through `preflight_poseidon2_v8_action_against_parent`, which does run `verify_uncommitted_block`.

This matches the stated RP05 model of per-transaction proofs without a recursive block artifact. It is still a consensus-rule change. Shipping it in the same commit series as an empty capability is safe only for as long as `smallwood_poseidon2_production_capability()` stays `None` and non-V8 fresh proofs stay denied. Filling in the capability without a coordinated height will fork any node still running the `main` policy.

### L2 — V8 wallet notes have no local pending-spend lock

**Severity:** low

`spend_context` selects notes with `spent_by.is_none()`. `prove_verify_and_submit_poseidon2_v8` does not mark them pending before the proof returns. The legacy pool uses `mark_notes_pending`. A second build can select the same notes, produce the same deterministic nullifier, and submit a transaction the network will reject. It does not create two different valid nullifiers for one note.

Selection is also fixed: the first two unspent notes in insertion order. Values are copied per input, so the in-circuit balance still holds. The wallet cannot choose a different pair.

### L3 — Thin RPC submit checks framing, not the proof

**Severity:** low

`submit_poseidon2_production_transaction` in `wallet/src/node_rpc.rs` checks SMZ9 magic, and SMZA magic plus maximum length. It does not run `engine.verify`. Callers other than `prove_verify_and_submit_poseidon2_v8` can push a well-framed invalid proof. The node must reject it. That is a wasted RPC and a footgun, not an acceptance bug, provided node admission stays fail-closed.

### L4 — Legacy wallet prover can be run below the production floor

**Severity:** low, and only on the legacy `StarkProver`

`StarkProver::new` honors `HEGEMON_WALLET_PROVER_FAST` and `LocalProofSelfCheckPolicy::Never`. In a release build it prints a warning and continues. The V8 route does not go through this constructor. A deployment that still builds legacy proofs with those controls will emit proofs below the documented query/blowup floor. The node should reject them if its verifier uses the production profile; the wallet will not stop itself.

### L5 — Reorg WAL has no production flip

**Severity:** low

`reorg_wal.rs` can apply an operation transactionally and test code activates generations directly. There is no production seal/flip wired to commit. Readers cannot observe a partial WAL generation today because the module is unused. The comments require overlay reads to stay authoritative until finalization. That invariant is unenforced in `node_impl` because the module is never called.

### L6 — Debug logging prints nullifiers when asked

**Severity:** low

`wallet/src/store.rs` prints pending nullifiers when `WALLET_DEBUG_PENDING` is set. Default off. Enabling it links shielded spends to a stderr log.

### I1 — HTLC claims match the tree

`experimental/htlc-prototype` is not a workspace member and is not a dependency of `node`. `proof-backend/src/lib.rs` states the crate is never linked to the production node. CI reaches it only through `scripts/check-core.sh` and its own manifest.

Two layers exist and are not composed:

- Host `check_spend` in `experimental/htlc-prototype/src/relation.rs` checks the reference relation, host SHA assignment, refund timeout, and ML-DSA authorization. `reference_ledger.rs` journals that under a local file lock. The journal is not chain state.
- `hashlock_claim.rs` proves `SHA256(secret32) = digest` with opaque public context. `PRODUCTION_RP05_INNER_CAP` is 164,113. Measurements record a 311,682-byte proof with `production_authorized: false` and `full_htlc_relation_proved: false`.

`SMALLWOOD_POSEIDON2_V8_SMZA_MAX_INNER_PROOF_BYTES` stays 164,113. No atomic-swap path is implemented. `METHODS.md` describes this boundary. `DESIGN.md` does not mention HTLC.

### I2 — Parallel proof windows keep state ordered

`POSEIDON2_V8_PROOF_VERIFICATION_WINDOW` is 4. `verify_attach` finishes one window's apply loop before starting the next. The worker pool returns results in leaf-index order. Each leaf still requires `public.before_root == current_root`, a parent-height match, an anchor already in the parent note-root history, and unique nullifiers. Outputs appended in the block are not spendable until a later block. A trailing coinbase commitment is appended only after the proof leaves, so an earlier action in the same block cannot spend the reward.

If the pool fails to build, verification falls back to the serial leaf path. A worker that returns no result or panics becomes `ProofRejected`. Parent and leaf-size checks run before dispatch.

`record_window_verified_transition` runs before the per-leaf state checks. Callers in `node_impl` construct a fresh `RecordingPoseidon2V8Verifier` and read `transitions()` only after `verify_uncommitted_block` or `plan_verified_reorganization` returns success. A failed leaf does not get applied.

### I3 — Tape allocation does not shrink entropy

`sample_fixed_width_tapes_with_source_v1` returns one contiguous tape buffer. Differential tests require the same bytes and the same callback order as the previous partitioned tapes. Note `randomness` still carries a single fresh field word in limb 3 plus address-bound limbs; prover DECS tapes are a separate draw. Those are different objects.

### I4 — Coinbase and bridge mint

V8 coinbase parsing in `admission.rs` requires a nonzero in-range native value, canonical field words, nonzero recipient and authorization keys, an exact ciphertext length, and a commitment that matches the opening hash. `native_block_replay_supply_parts` feeds fee total and the coinbase flag into replay refinement. Inbound bridge mint authorization is rejected with an explicit disabled error until a PQ-clean decoder exists (`admission.rs`).

### I5 — Checked-in databases and proof blobs

The diff adds sled directories and `proof.bin` files under `.agent/artifacts/`, plus a review-package tarball. They are evidence, not runtime state for a fresh node. They do make the review diff enormous and should not be treated as an executable specification.

## Claim check

| Claim in the pull request | Reading of this branch |
| --- | --- |
| No authorization bypass and no activation grant | Holds. Capability constructor is `None`. V8 historical replay is denied. |
| Public ZK and single-spend Lean endpoints | Present as source. Not rechecked in this audit. Rust does not treat those files as admission authority. |
| Ordered state replay despite parallel verify | Holds on `verify_attach`. |
| HTLC proof not admitted, cap unchanged, no atomic swap | Holds. Crate is isolated. Inner cap remains 164,113. |
| Sync prefetch not added to release scheduling | No prefetch symbol in `node/src/native/sync_chunks.rs`. |
| 765 node tests, cross-host lifecycle, CI green | Not re-executed here. The tip test only covers the pause-release lock. |

`DESIGN.md` on this branch says development qualifications do not select production activation authority, and that SMZA tests do not establish complete adaptive ZK, quantum extraction, lifetime security, or release authorization. That is consistent with `smallwood_poseidon2_production_capability`.

## Invariants that held

- Fresh proof authority is one function, currently empty.
- Schedule intersection cannot authorize an unknown binding.
- V8 block apply verifies before it writes, in order, and rejects a `before_root` that is not the running root.
- Same-block spends of a note just created in that block are rejected because the anchor must already be in the parent history.
- Suffix reorg removes nullifier rows only when the stored index matches the planned undo, inside one sled transaction. Full reorg rebuilds the index and checks it against the best nullifier root.
- Restart rebuilds the accumulator from the index and compares it to the stored encoding.
- Fork retention detects cycles and enforces ancestor closure and size caps.
- Wallet production spend re-checks the profile/domain tuple at prove time and verifies before submit.
- Witness bytes are not part of the submission type.
- HTLC code cannot be reached from `hegemon-node`.

## Coverage limit

This is a security reading of the consensus, node, wallet, and experimental boundaries. It is not a line audit of the Lean development, not a reproduction of the cited CI runs, and not a cryptanalysis of Poseidon2, DECS, or the SMZA relation. A passing reading of the Rust gates does not discharge the explicit hypotheses those Lean endpoints still list.

## Before activation

1. Keep `smallwood_poseidon2_production_capability()` as the only switch. Any non-`None` value needs a height, a genesis hash, and a plan for nodes still running the `main` `InlineRequired` rejection.
2. Teach mempool admission the seven-limb nullifiers from the verified public statement, and reject a second pending spend of the same nullifier.
3. Either delete or wire `canonical_membership` / `reorg_wal` / `block_store_v3`. Two spend authorities will drift.
4. Verify proofs inside the wallet mirror, or document that mirror balances are only as honest as the connected node.
5. Mark V8 notes pending across prove and submit.
