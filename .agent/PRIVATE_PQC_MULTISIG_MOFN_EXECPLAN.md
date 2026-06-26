# Complete private PQC m-of-n multisig

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon already has a private shielded accumulator multisig path, but the current branch only proves exactly two hidden signer tags with threshold one or two. The finished feature must let wallet users create a private post-quantum `m-of-n` shielded account without public signer lists, public thresholds, public approval counts, public signatures, MPC transcripts, or reconstructed group secrets. A user should be able to create a hidden policy with up to six signer tags, collect approvals through normal shielded transactions, and spend only after the hidden threshold is met. The chain should continue seeing the ordinary shielded transaction shape.

## Progress

- [x] (2026-06-26) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, and the current private multisig implementation.
- [x] (2026-06-26) Identified the current production limitation: `wallet`, `walletd`, and the SmallWood private-auth witness are fixed to two signer tags and two approved slots.
- [x] (2026-06-26) Replaced the two-slot SmallWood private-auth witness with a fixed-capacity six-slot hidden policy carrying private signer count, threshold, approved slots, and hidden signer tags.
- [x] (2026-06-26) Extended circuit constraints so approval membership, duplicate approval rejection, final threshold comparison, policy-root binding, accumulator-root binding, and intent binding work for hidden `m-of-n`.
- [x] (2026-06-26) Extended wallet and walletd APIs to accept a variable-length private policy, pad it internally, keep public responses policy-shape-free, and exchange private descriptors/openings explicitly off-chain.
- [x] (2026-06-26) Extended Lean/Rust pure accumulator semantics and conformance vectors for policy well-formedness and `m-of-n`; `cargo test -p transaction-circuit private_multisig_accumulator --lib -- --nocapture` passed.
- [x] (2026-06-26) Updated `DESIGN.md`, `METHODS.md`, `wallet/README.md`, and `docs/API_REFERENCE.md`.
- [x] (2026-06-26) Focused checks passed: `cargo fmt --check`, `cargo test -p transaction-circuit universal_auth --lib -- --nocapture`, `cargo test -p transaction-circuit private_multisig_accumulator --lib -- --nocapture`, `cargo test -p wallet --lib multisig -- --nocapture`, and `cargo test -p walletd multisig -- --nocapture`.
- [x] (2026-06-26) Full `bash scripts/check_formal_core.sh` passed, including `private_multisig_accumulator_matches_lean_vectors` and the final `=== Hegemon formal-core gate passed ===` marker.
- [x] (2026-06-26) Fixed a live handoff bug where wallet rescan preserved private local openings but failed to rehydrate accumulator notes whose ciphertexts are not decryptable by the importing signer; regression `local_accumulator_opening_rehydrates_after_rescan_without_decryptable_ciphertext` passed.
- [x] (2026-06-26) Laptop-to-`hegemon-dev` live validation passed on isolated remote node `mslive-1782477119-66287`: Bob funding tx `0x10db41f5cd0a1c51d28eee57e136276c4a355491bba409892bdf104fe8d5bb22`, setup tx `0xe832742697194c3a4846e27c2739fa9f821889876b52247968288012c3e46f26`, Alice approval tx `0xc36925309acfe78aecb7af75624a0d9e849c60c73d5e5dd5628a6b2fb1759933`, Bob approval tx `0xff7a730a7f44be6bfc947c77df2ae626b9e3f85cd8ec469e3f8053515492224e`, final tx `0x6d4311d7126affe860ff5f52b77decb3c5eb0f5c4d0653740ff110c61c1b4fe9`, and Carol recovered the final `1000000` native output at commitment `0x40bcd13e8875d224b703bf88d790e0cfeacbc266a840edf2acac73836760580b40665bc8dfc0ee9660940010de5fd409`.
- [x] (2026-06-26) Reran full `bash scripts/check_formal_core.sh` after the live handoff fix and the sparse-cursor bookkeeping guard; the gate passed with the final `=== Hegemon formal-core gate passed ===` marker.
- [x] (2026-06-26) Commit and push branch `codex/private-predicate-threshold-spend`.

## Surprises & Discoveries

- Observation: The current circuit path binds approvals to circuit-derived signer tags, but the row geometry is specialized to two hidden signer slots.
  Evidence: `SmallwoodPrivateAuthWitness.policy_signer_tags` is `[SmallwoodSignerTag; 2]`, `approved_slots` is `[u64; 2]`, and `walletd` accepts `[SmallwoodSignerTag; 2]`.
- Observation: Separate signer wallets need private off-chain account-descriptor and accumulator-opening exchange to run threshold approvals without revealing policy shape on chain.
  Evidence: The final transaction builders need the account record and current accumulator note opening locally, while public wallet/account responses intentionally hide signer count, threshold, tags, policy root, approval count, and approved slots.
- Observation: The six-slot AIR uses the first signer-tag limb for active-policy distinctness inverses.
  Evidence: Wallet account creation rejects active first-limb collisions and the circuit constrains active pairwise inverse witnesses for that limb; full tag equality is still used for membership.
- Observation: Imported private accumulator openings must survive wallet rescan even when the importing wallet cannot decrypt the accumulator ciphertext.
  Evidence: Live Bob approval initially failed after a sync reset because `reset_sync_state` cleared tracked notes while preserving local openings; `apply_ciphertext_batch` now rehydrates a tracked note from a matching preserved local opening when ciphertext decryption yields `None`.
- Observation: Local-opening rehydration must not require a chain commitment for every undecryptable ciphertext cursor slot.
  Evidence: The full formal-core rerun caught `local_wallet_bookkeeping_does_not_change_public_ciphertext_projection` failing with `ciphertext commitment missing`; the sync path now fails closed only for decrypted notes with missing commitments and only attempts local-opening rehydration when the chain commitment is present. The focused bookkeeping and rehydration tests both pass.

## Decision Log

- Decision: Use a fixed hidden capacity of six signer tags for the production path.
  Rationale: The proof relation stays fixed-size, which preserves the shielded public shape and avoids variable-size on-chain policy data. Six covers the likely product envelope and adds only a small number of private witness rows compared with the current transaction proof size.
  Date/Author: 2026-06-26 / Codex

- Decision: Keep the implementation accumulator-based instead of switching to public simple multisig, threshold signatures, MPC, or reconstructed shared secrets.
  Rationale: The design requirement is private PQC authorization inside Hegemon's shielded pool. Public simple multisig leaks policy shape; threshold signatures and MPC were explicitly rejected; reconstructed shared secrets are unsafe because the reconstructed key can be retained.
  Date/Author: 2026-06-26 / Codex

## Outcomes & Retrospective

The implementation now provides fixed-capacity hidden `m-of-n` private PQC multisig for shielded spends with up to six signer tags. The policy shape, threshold, signer count, approval count, signer tags, policy root, and approved slots remain private witness/local-wallet data; public account responses and on-chain transaction shape stay policy-shape-free. Formal coverage includes Lean hidden-policy accumulator semantics, generated Rust conformance vectors, SmallWood private-auth constraint checks, wallet and walletd private descriptor/opening flows, focused regression tests for imported accumulator openings, and the full formal-core gate.

The remaining product tradeoff is explicit: private account descriptors and accumulator openings are exchanged off-chain between signers, because publishing them would reveal policy data. There is no reconstructed group secret, no public signer list, no public threshold, and no MPC transcript.

## Context and Orientation

The transaction circuit lives under `circuits/transaction`. `circuits/transaction/src/smallwood_frontend.rs` builds the private witness rows and hash preimages used by the active SmallWood transaction proof. `circuits/transaction/src/smallwood_semantics.rs` checks the same row layout as a pure semantic relation. `circuits/transaction/src/private_multisig_accumulator.rs` is a Rust conformance target for the Lean model in `formal/lean/Hegemon/Transaction/PrivateMultisigAccumulator.lean`.

The wallet code lives under `wallet`. `wallet/src/multisig.rs` defines hidden policy records and local accumulator openings. `wallet/src/tx_builder.rs` builds setup, approval, and final spend transactions. `wallet/src/store.rs` persists encrypted wallet state and local accumulator openings. `walletd/src/main.rs` exposes the JSON-RPC methods used by scripts and live validation.

A signer tag is the five-field-element digest derived from a signer spend key by the transaction circuit. The policy root is a private hash over the threshold, signer count, and padded signer tags. The accumulator note is a zero-value shielded note whose hidden spend authorization key commits to the policy root, final-spend intent digest, threshold, signer count, approval count, and approved slot bits.

## Plan of Work

First, introduce a shared fixed capacity constant of six in the transaction circuit and update the SmallWood private-auth witness to carry `signer_count`, six approved slots, and six signer tags. Update policy-root and accumulator-root preimages to include `signer_count`, so an account cannot silently reinterpret the same hidden root as a different `m-of-n` policy. Update the semantic checker to constrain threshold, signer count, approval count, next approval count, active slots, membership flags, and final `count >= threshold` across the six-slot domain.

Second, update wallet state and walletd parameters from fixed arrays of two signer tags to variable-length vectors that are normalized, sorted, deduplicated, and padded internally. Public account responses must remain policy-shape-free. Local accumulator openings must persist the private signer count and six approved slots.

Third, update Lean pure accumulator semantics to model arbitrary finite signer lists and add cases for malformed policy rejection, duplicate signer rejection, wrong policy, wrong intent, forged signer tag, below-threshold final spend, exact-threshold final spend, and final intent mismatch. Regenerate or directly compare vectors through the existing Rust test.

Fourth, update docs and run validation. Focused checks are the transaction-circuit private auth tests, wallet multisig tests, walletd multisig tests, Lean build for the accumulator modules, and `bash scripts/check_formal_core.sh`. Live validation must use laptop walletd against an isolated `hegemon-dev` native node and confirm setup, approval, and final transactions.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

    cargo test -p transaction-circuit universal_auth --lib -- --nocapture
    cargo test -p transaction-circuit private_multisig_accumulator --lib -- --nocapture
    cargo test -p wallet --lib multisig -- --nocapture
    cargo test -p walletd multisig -- --nocapture
    (cd formal/lean && lake build Hegemon.Transaction.PrivateMultisigAccumulator Hegemon.Transaction.GeneratePrivateMultisigAccumulatorVectors)
    bash scripts/check_formal_core.sh

The live validation step should start an isolated native node on `hegemon-dev` using an unused RPC and P2P port, tunnel it to the laptop, drive walletd through setup/approval/final submit, wait for the final transaction to confirm, then kill the isolated node and tunnel.

## Validation and Acceptance

The feature is accepted only when a hidden policy with more than two signers can be created by walletd, approval transactions advance the hidden accumulator one signer at a time, duplicate approval fails, final spend fails before threshold, final spend succeeds at threshold, full formal-core passes, and a live laptop-to-`hegemon-dev` isolated-node transaction flow confirms on chain. The public transaction shape and public account response must not contain signer tags, threshold, signer count, policy root, approval count, or approved slots.

## Idempotence and Recovery

The tests are safe to repeat. The live validation must use an isolated dev node and a temporary wallet path so it does not mutate the shared running node. If live validation fails after starting the isolated node, kill the remote process matching its unique RPC/P2P ports and remove the temporary wallet directory before retrying.

## Artifacts and Notes

Current branch before this plan: `codex/private-predicate-threshold-spend` at `731956d2`.

## Interfaces and Dependencies

At the end of the implementation, `transaction_circuit` should expose a fixed hidden capacity constant and keep `SmallwoodSignerTag = [u64; 5]`. `walletd` should accept `policySignerTags` as a variable-length JSON array with length from one to six and should never include the tags or threshold in public account-list responses. The on-chain transaction fields must remain the existing shielded transaction fields.
