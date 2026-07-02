# Implement Private Multisig Wallet Builders

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

This change makes the wallet build real shielded private multisig transactions for the proven SmallWood private authorization relation. After the change, a wallet can create and store local openings for private accumulator/control notes, build approval transactions that consume the current accumulator note plus one signer capability note, and build a final spend transaction that consumes a value note plus a threshold accumulator note. The chain still sees only the existing shielded transaction public shape: nullifiers, commitments, ciphertext hashes, a balance tag, and a proof artifact.

## Progress

- [x] (2026-06-26T04:42:28Z) Read `DESIGN.md`, `METHODS.md`, `README.md`, and the current SmallWood private auth code before editing.
- [x] (2026-06-26T04:42:28Z) Confirmed the branch starts at `27de628a`, which already proves hidden signer membership for `SmallwoodPrivateAuthWitness`.
- [x] (2026-06-26T04:42:28Z) Narrowed the implementation scope to the canonical proven shape: threshold `1` or `2`, exactly two hidden `u64` signer ids, `smallwood_policy_root_bytes(threshold, policy_signers)`, and `SmallwoodPrivateAuthWitness`.
- [x] (2026-06-26T05:58:41Z) Implemented wallet state and API migration from the older arbitrary 48-byte signer commitment scaffold to the proven two-signer descriptor.
- [x] (2026-06-26T05:58:41Z) Added local note-opening storage for accumulator/control notes whose `pk_auth` cannot be recovered from ordinary note ciphertext decryption.
- [x] (2026-06-26T05:58:41Z) Added setup, approval, and final transaction builders that produce `TransactionBundle`s with real SmallWood private auth witnesses.
- [x] (2026-06-26T05:58:41Z) Added focused tests for hidden public shape, approval/final witness binding, local accumulator opening recovery, and fail-closed unsupported scope.
- [x] (2026-06-26T05:58:41Z) Ran focused wallet and transaction-circuit tests successfully before commit.
- [x] (2026-06-26T06:16:11Z) Reworked setup after coordination hard stop so it consumes a spendable native funding note, pays a nonzero fee, and returns change within `MAX_OUTPUTS`.

## Surprises & Discoveries

- Observation: The existing wallet scaffold uses arbitrary 48-byte signer commitments and a Blake2 policy root, but the proven relation at the branch tip uses exactly `[u64; 2]` signer ids and `smallwood_policy_root_bytes`.
  Evidence: `wallet/src/multisig.rs` stores `signer_commitments: Vec<[u8; 48]>`, while `circuits/transaction/src/smallwood_frontend.rs` defines `SmallwoodPrivateAuthWitness { policy_signers: [u64; 2], ... }`.
- Observation: The final spend relation binds the accumulator `intent_digest` to the SmallWood public-statement digest, not to the old wallet host-side intent hash.
  Evidence: `circuits/transaction/src/smallwood_semantics.rs` enforces `mode_final * (auth_intent - auth_statement_digest) == 0`.
- Observation: Ordinary wallet note decryption reconstructs `pk_auth` from the wallet spend key. Accumulator notes deliberately use a different `pk_auth`, so sync needs a stored opening to reconcile the decrypted plaintext with the chain commitment.
  Evidence: `wallet/src/viewing.rs::FullViewingKey::decrypt_note` overwrites recovered `pk_auth` with the wallet spend auth key.
- Observation: The wallet sync path must not trust plausible decrypted plaintext when reconciling local accumulator openings.
  Evidence: The reconciliation tests cover wrong stored `pk_auth`/opening, wrong chain commitment, no normal spend nullifier for reconciled accumulator notes, and unchanged ordinary note nullifier tracking.
- Observation: A no-input, zero-fee setup transaction would be proof-valid but would mint a free commitment unless node fee admission independently rejected it.
  Evidence: Coordination review flagged missing fee-per-weight enforcement on `hegemon_submitAction` staging before commit.

## Decision Log

- Decision: Implement only the two-signer SmallWood policy shape in this worker; reject arbitrary signer counts and thresholds outside `1..=2`.
  Rationale: Coordination explicitly declared the branch-tip SmallWood relation authoritative and asked not to broaden to arbitrary `n`.
  Date/Author: 2026-06-26 / Codex
- Decision: Keep the older opaque approval/final package APIs fail-closed unless they return real transactions; add transaction builders rather than host-verified packages.
  Rationale: The product security boundary is the shielded proof, not a local hash package.
  Date/Author: 2026-06-26 / Codex
- Decision: Store local accumulator/control note openings inside the encrypted wallet and use them during sync only when the decrypted plaintext matches the stored opening and the stored opening commitment matches the chain commitment.
  Rationale: This is the minimal correct path for arbitrary `pk_auth` recovery without pretending the generic note scanner can rediscover hidden auth keys.
  Date/Author: 2026-06-26 / Codex
- Decision: The final builder requires a prepared final plan whose intent digest is computed from the transaction circuit's SmallWood public-statement digest helper.
  Rationale: This prevents host-only intent hashing and binds approvals to the exact final public statement.
  Date/Author: 2026-06-26 / Codex
- Decision: Initial accumulator setup must be a funded shielded spend with a normal native input and nonzero fee.
  Rationale: This closes the free commitment/bloat admission hole while preserving the existing shielded public transaction shape.
  Date/Author: 2026-06-26 / Codex

## Outcomes & Retrospective

Implemented the wallet-side private multisig builder path for the proven two-signer SmallWood scope. The branch now builds funded setup, approval, and final shielded transactions with `SmallwoodPrivateAuthWitness`, stores local accumulator openings privately, reconciles those openings only against exact verified chain commitments, and keeps old opaque host package APIs fail-closed.

## Context and Orientation

The transaction circuit supports at most two inputs and two outputs. In the current SmallWood private auth relation, approval mode authorizes input `0` with the current accumulator auth key and input `1` with the signer wallet spend key. Final mode authorizes input `0` with the normal wallet spend key and input `1` with the threshold accumulator auth key. The wallet must preserve this input ordering.

`wallet/src/multisig.rs` owns multisig account metadata and intent/account helper types. `wallet/src/store.rs` owns encrypted wallet state, tracked notes, and sync reconciliation. `wallet/src/tx_builder.rs` owns construction of `TransactionWitness` values, native tx-leaf artifact bytes, and `TransactionBundle`s. `circuits/transaction/src/smallwood_frontend.rs` owns the authoritative `SmallwoodPrivateAuthWitness`, `SmallwoodAccumulatorAuthOpening`, `SmallwoodPrivateAuthMode`, `smallwood_accumulator_auth_key_bytes`, and `smallwood_policy_root_bytes` helpers.

An accumulator/control note is a zero-value shielded note whose `pk_auth` is the SmallWood accumulator auth key. It is still a normal note commitment and ciphertext on-chain, but generic wallet decryption cannot reconstruct its `pk_auth`; therefore the wallet stores the full note opening locally when it creates the note.

## Plan of Work

First, update `wallet/src/multisig.rs` so account records use the proven hidden policy descriptor: `policy_signers: [u64; 2]`, `threshold: u64`, and `policy_root = transaction_circuit::smallwood_policy_root_bytes(threshold, policy_signers)`. Keep public account projection opaque by exposing only account id, policy commitment, initial accumulator commitment, and hook names.

Second, update `wallet/src/store.rs` to store local accumulator openings and reconcile them during ciphertext sync. The reconciliation accepts only when the stored opening commitment equals the chain commitment and the decrypted plaintext matches the stored opening’s value, asset, recipient, `rho`, and `r`.

Third, factor small helpers in `wallet/src/tx_builder.rs` to build an input witness with a checked Merkle path and to wrap a witness plus optional `SmallwoodPrivateAuthWitness` into a `TransactionBundle`. Then add setup, approval, and final builders. Setup consumes a normal spendable native funding note, pays a nonzero fee, emits the initial zero-value accumulator note, and returns native change only when it fits the two-output limit. Approval consumes current accumulator input `0` and signer capability input `1`, produces next accumulator output `0`, and uses `SmallwoodPrivateAuthMode::ApprovalStep`. Final consumes value input `0` and accumulator input `1`, produces the requested recipient/change outputs, and uses `SmallwoodPrivateAuthMode::FinalThresholdSpend`.

Fourth, expose a transaction-circuit helper if needed to compute the SmallWood final statement digest from a prepared final witness. The helper must compute the same digest the final relation enforces and must not introduce a host-only policy hash.

Finally, update `DESIGN.md` / `wallet/README.md` only where their current text describes the old scaffold shape or where new builder behavior needs to be documented.

## Concrete Steps

Run commands from `/Users/pldd/.codex/worktrees/de59/Hegemon`.

Use:

    cargo test -p wallet multisig
    cargo test -p wallet tx_builder::tests::multisig
    cargo test -p transaction-circuit universal_auth

If a test name differs after implementation, run the nearest focused wallet and transaction-circuit tests that exercise private multisig builders and SmallWood auth.

## Validation and Acceptance

Acceptance requires focused tests showing that an approval transaction proves with `SmallwoodPrivateAuthMode::ApprovalStep`, hides signer ids and policy roots from the public `TransactionBundle`, and rejects unsupported signer/threshold shapes. It also requires a final transaction test where the accumulator `intent_digest` is the exact SmallWood final public-statement digest; changing the final recipient amount, fee, output commitment, or ciphertext hash must make the builder reject or produce a different digest that cannot reuse existing approvals.

The local note-opening storage path is accepted when a test builds an accumulator note with arbitrary `pk_auth`, syncs the matching chain commitment/ciphertext, and records the correct stored opening instead of the normal wallet `pk_auth`.

## Idempotence and Recovery

The code changes are additive and data-versioned. Existing v6 wallet files already migrate to empty multisig accounts. If a v7 wallet contains old multisig records, the new deserializer should fail closed rather than silently reinterpret 48-byte signer commitments as SmallWood signer ids. Tests create temporary wallets and can be rerun without persistent state.

## Artifacts and Notes

Validation passed:

    cargo check -p wallet --lib
    cargo check -p walletd
    cargo test -p wallet multisig -- --nocapture
    cargo test -p wallet reconciliation -- --nocapture
    cargo test -p wallet local_accumulator_opening -- --nocapture
    cargo test -p transaction-circuit universal_auth -- --nocapture
    cargo test -p walletd multisig -- --nocapture

## Interfaces and Dependencies

In `wallet/src/multisig.rs`, expose helpers for deriving the local signer id, creating a two-signer account record, converting stored accumulator openings to `SmallwoodAccumulatorAuthOpening`, and computing duplicate inverses for the second approval.

In `wallet/src/tx_builder.rs`, expose production builders returning `BuiltTransaction` so existing submission code can mark inputs pending and submit through the same node RPC path used by normal shielded transfers.
