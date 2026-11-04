# Close legacy exports and repair historical security claims

This ExecPlan follows `.agent/PLANS.md` and is a living document. The work is isolated at `/private/tmp/hegemon-v0112-review-fixes`, branch `codex/v0112-review-nonconsensus-fixes`, from current upstream main `74910ff86514c2cbd93d7a7039e6b90b6e4600b6`.

## Purpose / Big Picture

Wallet users must not accidentally export a legacy signer tag containing their personal nullifier key, including tags already stored in private account descriptors. Historical Lean statements must describe collision resistance as a computational assumption or a collision-producing reduction rather than impossible absolute hash injectivity. Security and supply documentation must identify the selected current proof route and distinguish the gross fee-inclusive header counter from actual net issuance. Consensus, relation equations, proof formats, historical replay, keys and wallet storage formats remain unchanged.

## Progress

- [x] (2026-11-04) Verify current main, create an isolated worktree, inspect direct export paths and relevant DESIGN/METHODS sections.
- [x] (2026-11-04) Complete independent boundary investigation and implement export gates with regressions.
- [x] (2026-11-04) Repair historical Lean statements and claim metadata with focused kernel checks.
- [x] (2026-11-04) Update security, wallet and supply documentation, including the remaining historical DESIGN/METHODS and formal README descriptions.
- [x] (2026-11-04) Run wallet and walletd focused checks, inspect the consensus-sensitive diff, obtain one independent bypass/regression review and address the confirmed stale formal README claim.
- [x] (2026-11-04) Finish refreshed source-binding, governance and active-goal consistency checks and record final outcomes.

## Surprises & Discoveries

Current main and the reviewed release have identical Git trees. The reviews overlooked existing seven-word signer hashes and newer conditional conservation reductions. Blocking only `multisig.localSignerTag` would leave `multisig.accountExportPrivate` able to re-export tags stored before this change.

The initial blueprint consistency check rejected stale `target_review.content_blake3` values after source changes. `scripts/hegemon_formal_core/README.md` explicitly states that these digests detect source drift but do not authorize or accept a review. The checker permits only `needs_review` and `blocked` statuses. An internal, dated source-binding maintenance note and digest refresh therefore preserve the independent-review gate rather than granting approval. No status or production authority is promoted.

## Decision Log

The source worktree contains unrelated user changes and is on an older experimental branch, so all implementation is performed on a new branch from current upstream main. No deployment or consensus activation is authorized. Historical data must remain readable and encrypted backups must retain their contents; explicit co-signer export surfaces may fail closed with an explanatory error.

Retain historical injectivity-based declarations for source compatibility, remove their assurance credit everywhere, and reject their reintroduction through the claim checker. Credit the new value/asset-agreement-or-collision reductions without asserting a concrete collision advantage bound. Keep deterministic supply accounting separate from cryptographic conservation. Name actual subsidy issuance precisely because forfeited fees can also reduce note value.

## Outcomes & Retrospective

Implementation and relevant verification are complete. All 26 focused wallet/walletd tests, wallet binaries, changed Lean modules and aggregate, collision-root axiom audits, claim/governance regressions, authorization diagnostics, formal metadata checks, documentation checks and source-isolation checks pass. A read-only candidate review identified the stale formal README wording; it and the corresponding design/method statements have been corrected.

The full blueprint validator passes with 121 nodes, 519 edges, 241 implementation bindings and 677 falsification cases. All 121 external reviews remain pending. Claim IDs, classes, statuses, production eligibility and authority fields remain identical to the base. The historical active-goal ledger remains blocked with 10/20 mechanized tracks closed (50%); validating the ledger does not complete that historical security goal. This patch neither qualifies a new release nor retroactively protects previously disclosed legacy tags.

## Context and Orientation

`wallet/src/store.rs::local_multisig_signer_tag` derives a five-limb tag from the wallet spending key; its first limb is the old nullifier key. `walletd/src/main.rs` exposes this through `multisig.localSignerTag` and also serializes stored tags through private descriptor export. Modern treasury/Common PrivateSpend uses seven-word authorization hashes and separate secret-based nullifiers. `formal/lean/Hegemon/Transaction/SmallWoodProductionConstraintRefinement.lean` and the historical supply composition contain globally quantified hash-injectivity assumptions. Newer RP05 conservation reductions explicitly charge primitive collision events. The current selected release identity is circuit12/PrivateSpend/SMZL, not historical V4 or RP03/SMZ9.

## Plan of Work

Gate legacy wallet-root tag derivation at the shared WalletStore boundary and gate descriptor export containing stored tags at its walletd boundary. Preserve public list/import and encrypted recovery behavior. Add tests at the store and actual request dispatcher, with a stored pre-fix tag and a modern V8 control. Repair or quarantine the historical Lean security claims and expose useful collision-producing conclusions without modifying runtime relations or frozen proof packages. Refresh SECURITY.md, wallet documentation and existing supply documentation with scoped claims and the existing fee-inclusive arithmetic.

## Concrete Steps

From this worktree, inspect `git diff --check` and the final file list. Run focused wallet and walletd library/binary tests with `cargo test --locked --offline --release`, reusing a compatible build cache or an isolated target and limiting jobs to two. Use Lean4.32.2 and existing dependency objects with the changed source build directory first in LEAN_PATH; compile changed modules and audit the updated roots' axioms. Run the relevant claim metadata validation and documentation checks. Do not generate proofs, start nodes or perform a full unrelated workspace build for these API/proof-documentation changes.

## Validation and Acceptance

Legacy signer-tag and stored descriptor export requests must return errors with no result or secret-bearing payload. Malformed/unknown descriptors must not bypass the gate. Modern seven-word signer generation, public legacy account projections, historical import and encrypted restore must retain their existing behavior. The repaired historical reduction must compile and produce an explicit differing-input collision alternative; credited metadata must not present absolute injectivity as computational collision resistance. Only wallet API, proof/claim and documentation files may change. Consensus implementations, runtime proof equations, release capability literals and monetary vectors must have empty diffs.

## Idempotence and Recovery

All tests use disposable stores; no existing wallets or node state are opened. Keep build outputs outside retained artifacts, preserve old artifacts, and do not delete user data. The branch can be reviewed as a diff against its recorded base; reverting these scoped edits restores the base without touching other worktrees.

## Artifacts and Notes

Focused test outcomes and any setup limits are recorded in the final progress and outcome entries. Security validation reports from the preceding review are evidence inputs, not instructions.

Commands run from the isolated worktree, with `CARGO_TARGET_DIR=/private/tmp/hegemon-v0112-review-build` for wallet commands:

    cargo test --locked --offline --release -j 2 -p wallet --lib multisig
    # 19 passed; legacy export denial, V8 signer and encrypted restore controls.
    cargo test --locked --offline --release -j 2 -p walletd --bin walletd walletd_multisig
    # 5 passed; actual dispatcher rejects derived and populated stored exports
    # without a result payload; historical import and public projection work.
    cargo test --locked --offline --release -j 2 -p wallet --lib old_v17_read_only_and_recovery_preserve_keys_accounts_and_source_bytes
    # 1 passed; old read-only/recovered stores retain data and deny export.
    cargo test --locked --offline --release -j 2 -p wallet --lib private_spend_scanner_policy_payloads_roundtrip_without_ordinary_classification
    # 1 passed; Common PrivateSpend scanner control.
    cargo check --locked --offline --release -j 2 -p wallet -p walletd --bins
    # Passed, with warnings.
    cargo fmt --manifest-path scripts/hegemon_formal_core/Cargo.toml -- --check
    # Passed.
    bash scripts/check_formal_crypto.sh --isolation-only
    # Passed: no production authority imports research definitions.
    python3 -m unittest discover -s scripts -p 'test_check_lean_claim_axioms.py'
    # Passed.
    git diff --check
    # Passed.

The forbidden runtime/protocol paths, frozen `formal/rp05` source, monetary vectors, root lockfile, release successor configuration and approved proof profiles have empty diffs. Local links in changed policy/accounting/wallet/formal documentation resolve. No node, proof generation, wallet-state migration, network join, push or deployment was performed.

Additional formal checks use `CARGO_TARGET_DIR=/private/tmp/hegemon-formal-fix-target`:

    cargo test --quiet --offline --manifest-path scripts/hegemon_formal_core/Cargo.toml claims_
    # 13 passed.
    cargo test --quiet --offline --manifest-path scripts/hegemon_formal_core/Cargo.toml governance_
    # 14 passed; receipts record actual final execution events.
    python3 scripts/test_check_smallwood_production_authorization.py
    # Diagnostic passed; unauthorized release and all 26 mutations rejected.
    cargo run --quiet --offline --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-claims config/formal-security-claims.json
    # Passed: 121 claims, 2,743 named Lean roots.
    cargo run --quiet --offline --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-active-goal-progress config/active-goal-progress.json
    # Passed, including the built-in aggregate build and proposition audit.
    cargo run --quiet --offline --release --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-blueprint config/formal-security-blueprint.json --claims config/formal-security-claims.json
    # Passed: 121 nodes; all 121 external reviews remain pending.

Using Lean 4.32.2 from `formal/lean`, with `LEAN_PATH=/private/tmp/hegemon-lean-fix-build`, independently compile `Hegemon/Transaction/SmallWoodProductionConstraintRefinement.lean`, `Hegemon/Consensus/AcceptedSmallWoodBlockComposition.lean` and `Hegemon.lean`. All three exit 0. The exact two-root query through `scripts/lean_axiom_audit.lean` reports `[propext]` for `production_canonical_output_value_and_asset_equal_or_hash_collision` and `[propext, Quot.sound]` for `production_accepted_output_value_and_asset_equal_or_poseidon2_collision`.

The actual progress gate initially began rebuilding an empty cache. It was stopped cleanly (exit 130), its disposable cache was preserved, and a byte-matched baseline cache was copied with APFS cloning into independent temporary storage. All 380 Lean source files were compared: only the two edited modules differed. Lake validated source hashes and rebuilt changed imports before both successful progress-gate runs. No mutable build outputs were symlinked to the baseline.

Persistent verification reports are saved through managed artifact storage under the target-bound `artifacts/review-fix-evidence/` collection. No full live-node lifecycle, full unrelated cryptography rebuild or production authorization was claimed from these scoped checks.

## Interfaces and Dependencies

Preserve the existing method names and result types so legacy clients receive explicit errors rather than silently reinterpreted descriptors. Use established WalletError and WalletdError variants. No new cryptographic dependency or network service is required. Retain the pinned Cargo lock and Lean toolchain.

Revision note: initial plan records the non-consensus implementation boundary and acceptance criteria before source changes.

Revision note (2026-11-04): record completed implementation, focused runtime controls, independent candidate review, the precise archived-theorem and supply wording, and the source-digest freshness distinction before final formal consistency checks.

Revision note (2026-11-04): record final successful blueprint, claim, active-goal and governance validation, cache provenance, preserved pending-review states and remaining production-security boundaries.
