# Stop the hosted HGN offer step from unlocking the wallet in a loop

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

A person creating a Hegemon (HGN) offer on the hosted testnet page unlocks the wallet in the local companion, waits through a long read, and then sees “The Hegemon balance snapshot is stale.” The only button starts that read over. After this change, a finished read is judged against the node height taken when the read finishes, a later click reads the cached balance instead of unlocking again, and the companion window calls a saved-note recheck a note count rather than a block sync. The person can continue an offer that the wallet can cover without repeating the passphrase and the full note walk.

## Progress

- [x] (2026-11-11 18:45Z) Write this ExecPlan before changing product code.
- [x] (2026-11-11 18:55Z) Stamp the node height after `private-spend status`, reject a negative cache gap, and allow one extra status when the tip is still more than two blocks ahead.
- [x] (2026-11-11 18:55Z) Label `wallet-progress stage=unlock` as saved-note progress in the companion window and on the page.
- [x] (2026-11-11 18:55Z) After the first unlock, refresh with `GET /hegemon/balance`, including one refresh when Continue sees a stale snapshot.
- [x] (2026-11-11 19:05Z) Update DESIGN.md and METHODS.md, rebuild the client manifest, and run the companion and browser tests.

## Surprises & Discoveries

- Observation: the page treats a wallet height ahead of the recorded node height the same as a snapshot older than 60 seconds. Both throw “The Hegemon balance snapshot is stale.”
  Evidence: `assertHegemonGiveSnapshot` in `swap-ui/offer-draft.mjs` rejects `observed_height - synced_height < 0` and `observed_at` more than 60 seconds behind `Date.now()`.

- Observation: `private-spend` prints `wallet-progress stage=unlock current=<note index> target=<note count>` while it rechecks saved notes, before it asks the node for the chain tip. The companion classified every `stage=unlock` line as a block sync.
  Evidence: `wallet/src/poseidon2_v8_sync.rs` reports `commitments.len()` as the target, and `wallet_progress_event` in `scripts/local_swap_companion.py` mapped `stage=unlock|sync|done` to the sync kind.

- Observation: the amount step’s only action was `POST /hegemon/unlock`, which always starts a new status run. `GET /hegemon/balance` already keeps the passphrase in the companion process.
  Evidence: `swap-ui/journey-ui.mjs` called `wallet.unlock()` from the button, and `HostedWalletSession.balance` returns the cache when the tip has not moved.

## Decision Log

- Decision: read the node height after `status` returns, and run `status` at most one more time if that height is still more than two blocks ahead of `synced_height`.
  Rationale: the long note recheck happens before the wallet records its tip. Sampling the height first made a one-block advance look like a stale snapshot. A second status only scans blocks mined during the first, because the wallet file already stores the height. Stopping after that second run avoids a loop when the node keeps moving.
  Date/Author: 2026-11-11

- Decision: do not widen the page’s 60-second window or its two-block rule. A negative gap (`synced_height` ahead of `observed_height`) stays a rejection. The cache predicate becomes `0 <= node height - synced height <= 2` so a wallet ahead of the node is not treated as fresh.
  Rationale: the failure was the height being recorded too early, and the page offering only a full unlock as the repair. The freshness rule itself still matches the funding gate.
  Date/Author: 2026-11-11

- Decision: the first approval still calls `POST /hegemon/unlock`. After a snapshot exists, the button and a stale Continue call `GET /hegemon/balance`. A locked-wallet error from that read falls back to unlock. Continue does not fall back to unlock. There is no timer.
  Rationale: the passphrase should be requested once. Continue must not start an unlock prompt by itself. A shortfall or a watch-only wallet is a real refusal and must not trigger another read.
  Date/Author: 2026-11-11

- Decision: `stage=unlock` progress is `kind: history` and the sentence is “Checking saved notes: N of M.” Block sentences stay on `stage=sync`. No wallet binary change.
  Rationale: the numeric lines are already emitted on the pipe. The terminal-only English lines stay for a person running `private-spend` in a terminal.
  Date/Author: 2026-11-11

## Outcomes & Retrospective

The hosted give-amount step no longer treats a wallet that finished one block ahead of an early height sample as a reason to unlock again. `HostedWalletSession._status_view` runs `status` first, stamps `observed_height` from the node read that follows, and runs `status` once more only when that tip is still more than two blocks ahead. The cache accepts a gap of 0, 1, or 2 blocks and refuses a negative gap. After the first snapshot, the button says “Read balance again” and calls `GET /hegemon/balance`. Continue does the same once when the stored snapshot is stale, and does not fall back to unlock. Note-history progress is “Checking saved notes: N of M.”

`PYTHONPATH=scripts python3 -m unittest scripts.test_local_swap_companion` passed 20 tests. `node --test swap-ui/offer-draft.test.mjs` passed 6 tests. With Node 24 and `CHROMIUM_PATH=/usr/bin/chromium-browser`, `swap-service/hosted-hgn-gate-browser.test.mjs` and `swap-service/journey-browser.test.mjs` both passed, including the stale-snapshot Continue and Read balance again checks. `/usr/bin/chromium` is not installed on this host. The page’s 60-second and two-block rules are unchanged. A live public-testnet wallet was not used.

## Context and Orientation

Hegemon is this repository’s chain. One HGN is 100,000,000 atoms. The hosted page is `swap-ui/hosted.html`, generated from `swap-ui/index.html`. It may call only itself and `http://127.0.0.1:8788`. The companion program `scripts/local_swap_companion.py`, started with `--hosted-wallet-status`, binds that port on this computer. `POST /hegemon/unlock` asks for approval and the wallet passphrase, then runs the `private-spend` program’s `status` command. `GET /hegemon/balance` returns totals if that process still holds the passphrase.

A snapshot is the JSON object with `available_atoms`, `reserved_atoms`, `htlc_atoms`, `immature_atoms`, `synced_height`, `watch_only`, `observed_height`, and `observed_at`. `synced_height` is the wallet’s saved chain height. `observed_height` is the node height the companion records. `observed_at` is Unix milliseconds. The page function `assertHegemonGiveSnapshot` in `swap-ui/offer-draft.mjs` refuses the offer unless that snapshot is under 60 seconds old, the wallet is not more than two blocks behind the recorded node height, the wallet is not ahead of that height, the wallet is not watch-only, and available atoms cover the give amount plus the 1,000-atom public fee.

`private-spend` is a one-shot program. Opening the encrypted wallet rechecks every saved note commitment before scanning new blocks. That recheck prints `wallet-progress stage=unlock`. The chain scan prints `stage=sync`. Testnet blocks are 60 seconds apart (`TARGET_BLOCK_INTERVAL_MS` in `consensus/src/reward.rs`). The companion used to call `read_node()` before `status`, so the recorded height could be older than the height the wallet reached.

The give-amount step is the second step of the offer wizard in `swap-ui/journey-ui.mjs`. The advanced offer form in `swap-ui/app.js` already calls `GET /hegemon/balance` at submit time. This change does not move the passphrase into the browser.

## Plan of Work

In `HostedWalletSession` in `scripts/local_swap_companion.py`, add a helper that runs `status`, then calls `read_node()`, and builds the snapshot with that later height. If the node is still more than two blocks ahead, the helper runs `status` one more time, reads the node again, and returns that snapshot even if the gap remains. `unlock` and the rescan branch of `balance` use the helper. `balance` still reads the node first to decide whether the cache is usable. The cache is usable when the saved height equals the node height, or when the cache is at most 60 seconds old and the node is 0, 1, or 2 blocks ahead. A wallet ahead of the node is not a cache hit. A rescan sets the activity phase to `syncing` and returns it to `idle`.

In `wallet_progress_event`, classify `wallet-progress stage=unlock` as history. Keep `stage=sync` as blocks. While the activity phase is `syncing` and heights are known, the snapshot includes `kind` of `history` or `blocks`. `describe_companion_status` says “Checking saved notes: N of M.” for history and keeps the existing block sentences otherwise. `describeWalletActivity` in `swap-ui/app.js` uses the same split.

In `swap-ui/journey-ui.mjs`, the button says “Unlock Hegemon wallet” until a snapshot exists, then “Read balance again”. The later click calls `balance()`. If that fails because the wallet is locked, it calls `unlock()`. `validateStep` for a hosted HGN give, used by Continue, calls `balance()` once when the stored snapshot fails only with the stale-snapshot message, then tests the new snapshot. Any other error is shown immediately.

Update the hosted HGN funding paragraph in `DESIGN.md` and the wallet-status companion paragraph in `METHODS.md`. Rebuild with `node scripts/build_client_manifest.mjs`.

## Concrete Steps

Work from `/home/william/Hegemon`.

    node --test swap-ui/offer-draft.test.mjs
    PYTHONPATH=scripts python3 -m unittest discover -s scripts -t scripts -p 'test_local_swap_companion.py'
    node scripts/build_client_manifest.mjs
    CHROMIUM_PATH=/usr/bin/chromium node --test swap-service/hosted-hgn-gate-browser.test.mjs swap-service/journey-browser.test.mjs

Expect each command to exit 0. The companion test must show that a node height which changes during `status` is the snapshot’s `observed_height`, that a gap larger than two blocks runs `status` exactly one extra time, and that an unlock progress line is described as saved notes. The browser test must show one `GET /hegemon/balance` and no second `POST /hegemon/unlock` for a stale snapshot on Continue and on Read balance again.

## Validation and Acceptance

On the hosted give-amount step, the first click still waits for approval in the companion. When that read finishes, the page shows available HGN and Continue if the amount plus the 1,000-atom fee is covered, including when one block arrived during the note recheck. The companion window shows “Checking saved notes: N of M.” during the note recheck and “Syncing the wallet: block X of Y.” only during the chain scan. Clicking “Read balance again”, or Continue after the snapshot is older than 60 seconds, calls the cached balance read and does not ask for the passphrase again. A watch-only wallet and a short balance still stop Continue with no extra read.

## Idempotence and Recovery

Re-running the manifest build overwrites only generated client files. Re-running the tests starts disposable processes and does not use an operator wallet. Stopping the companion still wipes the in-memory passphrase. Do not delete a node database or a wallet file.

## Artifacts and Notes

A snapshot that survives the page check has `observed_height` greater than or equal to `synced_height`, and the difference is at most 2. The activity JSON for a note recheck looks like this and contains no note row:

    {"phase":"syncing","current_height":"8724","target_height":"36840","kind":"history"}

The window sentence for that snapshot is “Checking saved notes: 8724 of 36840.”

## Interfaces and Dependencies

In `scripts/local_swap_companion.py`:

    class HostedWalletSession:
        def unlock(self) -> dict
        def balance(self) -> dict

`unlock` and a `balance` rescan stamp `observed_height` from `read_node()` after `status`. `WalletActivity.snapshot()` adds `kind` (`history` or `blocks`) while syncing with known counts.

`describeWalletActivity` in `swap-ui/app.js` and the give-amount button in `swap-ui/journey-ui.mjs` follow the decisions above. `assertHegemonGiveSnapshot` in `swap-ui/offer-draft.mjs` is unchanged.

## Revision note

2026-11-11: Created this plan to record the unlock-loop fix before implementation. The page freshness rule stays. The companion stamps the tip after the wallet read, the amount step refreshes through the cached balance, and note-history progress is no longer labeled as blocks.

2026-11-11: Implementation matches this plan. The companion unit test shows a height that moves during `status` is the stamped height, a negative gap is not a cache hit, and a gap of five blocks runs `status` exactly twice and then stops. The browser test shows one balance read and no second unlock for both Read balance again and Continue.
