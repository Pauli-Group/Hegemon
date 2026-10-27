# Deliver v0.11.2 wallet status and performance fixes

This living ExecPlan follows `.agent/PLANS.md`. Update Progress, Surprises & Discoveries, Decision Log, and Outcomes & Retrospective as work completes.

## Purpose / Big Picture

A miner checking a new wallet must see immature rewards and when they become usable, rather than an unexplained blank result. Status must report exact HGN amounts, distinguish reserved and conditionally locked funds, and show genuine progress while validating history and synchronizing blocks. Existing encrypted wallets, transaction proofs and the v0.11 chain remain compatible. The endpoint of this work is a pushed, review-ready v0.11.2 pull request and its private treasury-tool companion; merge, tagging, publication and deployment are later actions.

## Progress

- [x] (2026-10-26 Edmonton) Verify existing treasury/mining wallet inventories against canonical reward records; no missing rewards found. Keep operator receipts outside the public change.
- [x] Implement linear historical-root reconstruction, preserving every historical and final-root comparison; three focused regression tests pass.
- [x] Add single-unlock native `status` and numeric progress records; command authority regression passes.
- [x] Add private treasury progress, exact totals and backward-compatible native capability detection; 29 focused tests pass.
- [x] Add read-only native balance snapshot covering reserved, immature and conditional funds; four focused regressions pass.
- [x] Add compatible CLI summaries and explicit empty-state output; five exact formatting regressions pass.
- [x] Apply the explicitly approved exact v0.11.2 source/version binding transition. Current-tree scope25/25, consumer16/16, authenticated598-file source comparison and governance14/14 pass; refresh only actual metadata digests/receipts while preserving review statuses and authority.
- [x] Run focused acceptance and push the wallet changes in public PR #210 (ready for review) and the private companion PR #1. The explicitly approved release-binding update is included in the final follow-up commit.

## Context and Orientation

`wallet/src/poseidon2_v8_sync.rs` stores the authenticated local copy of the chain. Immature rewards already live in a separate bounded queue until their existing 120-block maturity boundary. `wallet/src/store.rs` owns encrypted wallet state and all transaction-input reservations. `wallet/src/bin/private_spend.rs` opens that state, synchronizes it and prints notes and attempts. Reservations mean an unspent input is already held for an existing payment attempt and must not be described as available. HTLC and policy notes have extra spending conditions. Accumulators are bookkeeping, not ordinary available HGN. Asset identifiers label different currencies, so their numeric units cannot be summed as HGN.

The separate private treasury repository wraps a pinned native wallet binary. Its existing binary, network-manifest and source pins remain enforced. Older binaries continue to work with a conservative summary that states unavailable categories as unknown.

## Plan of Work

Extend the wallet mirror with a read-only view of owned pending reward amounts and their existing maturity heights. Expose `WalletStore::private_spend_balance()` through read-only state access, reusing the union of all live input reservations and excluding spent inputs. Use integer atom arithmetic: 100,000,000 atoms equal one HGN. Keep non-native assets grouped by identifier and conditional categories separate.

Append machine-readable `balance` and per-asset rows plus readable HGN output to both `notes` and `status`, retaining the existing raw note-row format. Native `status` opens and synchronizes once. An empty wallet produces an explicit message at the synchronized height; an error never becomes a zero balance. The private wrapper recognizes the new summary while retaining its two-open fallback for older pinned binaries.

Reuse the existing incremental append implementation to derive every historical prefix root once. Compare every stored journal root and the complete final tree/history as before. Do not change encryption parameters, proof verification, wallet serialization, production authority, consensus or network identity. Set the software release target to v0.11.2 while preserving immutable prior release evidence.

## Concrete Steps

From the Hegemon checkout run focused release-profile wallet tests with the existing build cache and two build jobs. Filter for the new balance, historical-prefix and CLI-summary test names, then run the directly affected maturity/reorg tests once. Run formatting and diff checks for changed files. Do not start exhaustive formal compilation, new proof-generation campaigns or unrelated application suites.

From the private treasury checkout run `PYTHONPATH=src python3 -m unittest discover -s tests -v`. Expected behavior includes native one-open status, older two-open fallback, exact integer totals, conservative unknown-category output, terminal-secret isolation and bounded progress streaming. Existing successful tests need not be repeated without a source change or unresolved failure.

Review the exact public and private diffs, commit only the named source, tests and supporting documentation, then push dedicated branches. Create ready-for-review pull requests against the respective default branches. Do not include operator receipts, wallet data, addresses or private repository code in the public repository.

## Validation and Acceptance

An immature-only fixture reports a positive pending balance and the correct future inclusion height. At the 120-block boundary, it moves to ordinary available funds exactly as the existing execution rules allow. Reserved and spent notes are excluded from available funds. Conditional notes and non-native assets are not labeled spendable HGN. Exact atom and HGN formatting remains correct above floating-point precision. Corrupt intermediate historical roots still reject even when the final root is correct. A healthy long scan can stream more than 64 KiB of valid progress without exhausting the diagnostic bound; malformed diagnostics remain bounded and suppressed.

No real wallet passphrase or file is needed for these automated checks. Reuse the completed live balance verification as operational evidence rather than requesting another unlock for unchanged behavior.

## Idempotence and Recovery

All balance views are read-only and no storage version changes. Preserve the existing source worktree and unrelated changes, build cache and operator artifacts. Never delete wallet/node state. Historical release profiles remain immutable. Candidate packaging metadata must not claim accepted platform artifacts before they exist.

## Surprises & Discoveries

The previous empty `notes` output excludes already identified immature rewards. The previous history validation rebuilt an entire commitment prefix for every historical block. The private treasury wrapper opened the wallet three times despite each command already synchronizing it. The release CI also pins exact source postimages; inspect its concrete affected checks instead of inventing another exhaustive qualification campaign.

## Decision Log

Use software version v0.11.2 for this compatible wallet patch; keep network identity v0.11. Keep raw note rows to preserve callers. Use unsigned 128-bit totals and per-asset inventories. Preserve all reservation and maturity enforcement. Reuse unchanged proof evidence and keep exhaustive formal checks nonblocking. Prepare pull requests only; no merge, tag or deploy is part of this request.

## Outcomes & Retrospective

Fourteen focused native tests passed: four balance tests, one maturity/restart/reorg boundary test, five display tests, three historical-prefix tests, and one CLI authority test. Scoped rustfmt and diff checks pass. The private companion has 29 passing tests and is pushed ready for review. The prepared current-successor transition passed 25 scope and 16 consumer controls plus an authenticated 598-file source comparison; verification predicates and production authority remain unchanged. The user explicitly approved the exact seven-file transition (SHA256 `28d08a5202c34ee81185f356d688a8f080e4142742f194a3f6817fde8c878d64`); it is applied and the same controls pass against the actual worktree. Fourteen actual focused governance tests pass on the final inputs. Mechanically stale content digests caused by the method documentation edit are refreshed without changing review statuses, claims or authority. Platform artifacts and exhaustive formal qualification are deferred; no new artifact acceptance is claimed. Existing compatible release build cache is reused with two jobs and approximately 17 GiB free. The wallet implementation is pushed at `f81037dbed2329ec7e7717dd642e21053506fc69` in [PR #210](https://github.com/Pauli-Group/Hegemon/pull/210), open and ready for review. The shared software version is now `0.11.2` and its exact source postimages are bound. Fresh governance receipts identify the actual final-input test execution. Hosted CI remains separate from these focused local checks; no new binary/platform acceptance is claimed. No merge, tag, release or deployment was performed.

## Interfaces and Dependencies

`wallet::store::BalanceAmount` contains `atoms: u128` and `notes: u64`. `PrivateSpendBalance` contains synchronized height, ordinary available/reserved, immature coinbase, HTLC, policy and treasury-value categories, accumulator count, per-asset non-native inventories, next maturity information and watch-only state. The view adds no serialized fields or dependency. The private Python wrapper continues to use only the configured pinned native executable and its private controlling terminal for secrets.
