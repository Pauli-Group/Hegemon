# Gate hosted HGN offers on a local wallet snapshot

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

A person using the hosted testnet page at `https://hegemon-swap-testnet.willdoyle422.workers.dev` can today publish an offer that gives Hegemon (HGN) without owning any HGN. After this change, that page refuses to continue or create an HGN-give offer unless a companion program on the same computer has unlocked one local wallet and reports enough ordinary available atoms to cover the give amount plus the 1,000-atom public fee. Bitcoin, Ethereum and Cardano offers are unchanged. The check is a snapshot taken in the browser: it does not lock coins, and the hosted offer service never sees the balance. Offering HGN while the local node is still syncing, or while its tip does not match the public explorer, stays closed.

## Progress

- [x] (2026-11-10 02:00Z) Write this ExecPlan before changing product code.
- [x] (2026-11-10 02:40Z) Add `--hosted-wallet-status` with `POST /hegemon/unlock` and `GET /hegemon/balance`, leaving `--hosted-node-status` unchanged.
- [x] (2026-11-10 02:40Z) Add `hegemonGiveCovered` and refuse HGN creation in both the guided wizard and the advanced offer form when the hosted page is in use.
- [x] (2026-11-10 02:40Z) Show available HGN and an Unlock action on the give-amount step, and accept a companion that reports both status and balance.
- [x] (2026-11-10 02:50Z) Extend companion and browser tests, rebuild the client manifest, and update DESIGN.md, METHODS.md, the hosted start instructions and the swap-service README.

## Surprises & Discoveries

- Observation: `scripts/public_hegemon_wallet.py` `balance()` reads the machine line that starts `balance synced_height=` but does not return `immature_atoms`, even though a real `private-spend status` line includes that field.
  Evidence: the parser's required names stop at `htlc_notes` and `watch_only`. The companion snapshot must read `immature_atoms` from that same line and refuse the line if the field is missing, rather than inventing zero.

- Observation: a subprocess companion pointed at a fake low block height cannot receive `matches: true` from `compare_public_tip`, because that function fetches the live explorer.
  Evidence: `scripts/probe_hegemon_testnet.py` `compare_public_tip` calls `public_json` against `https://hegemonprotocol.com`. The wire test therefore starts the real companion process with `read_hosted_node` patched to a ready node, and a fake `private-spend` that prints note rows, so the HTTP body can be shown to omit those rows. A separate in-process session test covers the 60-second and two-block refresh rules without opening a socket.

- Observation: `swap-service/journey-browser.test.mjs` creates an HGN offer with no companion. A hard block makes that test fail unless the test pairs a mocked wallet-status companion and unlocks before Continue.
  Evidence: the test selects `hegemon:hgn`, fills `0.001`, and expects one `POST /offers`. The Ethereum maker later in the same test must stay ungated.

## Decision Log

- Decision: keep `--hosted-node-status` exactly as it is, and add a separate `--hosted-wallet-status` mode.
  Rationale: today's pairing tests and the running status companion must keep working. The new mode is the only one allowed to open a wallet file.
  Date/Author: 2026-11-10

- Decision: one companion process binds one wallet file. Switching between two local wallets means restarting the process with the other `--hegemon-wallet`.
  Rationale: two wallets would need two ports and two pairing codes. That is a different feature.
  Date/Author: 2026-11-10

- Decision: spendable funds are `available_atoms` only. Reserved, HTLC and immature atoms do not count. A watch-only wallet cannot fund an offer. The required total is the give amount plus 1,000 atoms, the public fee in `PublicHegemonProfile`.
  Rationale: those other buckets cannot be spent as an ordinary give. The fee is the amount the public profile actually pays.
  Date/Author: 2026-11-10

- Decision: the gate runs only on the hosted page (`data-hosted-testnet`). The local prototype page does not hard-block HGN offers.
  Rationale: the wallet-status companion accepts only the pinned hosted origin. The local page's origin cannot call it, so a gate there would make local HGN offers impossible.
  Date/Author: 2026-11-10

- Decision: the balance JSON is totals only, plus `observed_height`, `observed_at` (Unix milliseconds as a decimal string) and `watch_only`. Note positions, addresses, the passphrase and the status transcript are not fields.
  Rationale: the plan's totals are what the page needs. `observed_at` lets the page reject a snapshot older than 60 seconds, and `observed_height` lets it reject a wallet more than two blocks behind the node. The companion also refreshes on those same rules before answering.
  Date/Author: 2026-11-10

- Decision: `POST /hegemon/unlock` returns `{unlocked:true, balance:<totals>}` after the terminal approval. `GET /hegemon/balance` returns the totals alone.
  Rationale: the give-amount step can show available HGN immediately. Publish still performs a fresh GET.
  Date/Author: 2026-11-10

- Decision: a locked wallet is HTTP 409 `{"error":"wallet_locked"}`. A node that is syncing, missing the wallet RPC, or failing the public-tip comparison is HTTP 503 `{"error":"hegemon_node_not_ready"}`. Any other wallet failure is HTTP 502 `{"error":"wallet balance unavailable"}` with no wallet text.
  Rationale: the page can name the two states the person can act on. Note rows must never ride along in an error string.
  Date/Author: 2026-11-10

- Decision: the passphrase is kept only as a `bytearray` in the companion process and is zeroed when the process exits or when unlock fails. The browser sends an empty JSON object, never the passphrase.
  Rationale: a later balance refresh must not prompt again, and the hosted origin must not receive the secret.
  Date/Author: 2026-11-10

- Decision: after a successful status read, the companion deletes the scratch log `wallet()` wrote, because that log contains note rows.
  Rationale: the HTTP response is already totals-only. Leaving the log in the scratch directory for the life of the process would keep note positions on disk longer than the request needs.
  Date/Author: 2026-11-10

## Outcomes & Retrospective

The hosted page now refuses an HGN give unless a wallet-status companion on the same computer has unlocked one wallet and reports enough ordinary available atoms for the amount plus the 1,000-atom public fee. Status-only pairing still connects and still cannot read a wallet. The balance response used in the wire test contains totals only; a fake `private-spend` that prints `ordinary position=` does not put that text on the HTTP body. A fresh second GET does not run `private-spend` again. The in-process session test re-runs status after 60 seconds and when the node is more than two blocks ahead. The guided browser test still creates one HGN offer after a mocked unlock, and its Ethereum offer still needs no Hegemon unlock. The new browser test refuses Continue for a status-only companion and for a balance of 1,000 atoms against a 100,000-atom give, refuses the advanced form in that short case, and allows one publish when the snapshot is 5,000,000 atoms.

`swap-service/hosted-node-browser.test.mjs` was not re-run here because a companion was already listening on `127.0.0.1:8788`. That test starts its own status companion on that port. The status-only strings and the 404 for `/hegemon/balance` are covered by the companion unit test and by the new gate browser test's mock.

What remains outside this change: the Worker still does not know a balance, coins are not locked by a listing, and Ethereum, Bitcoin and Cardano gives are not checked. A node that is syncing or whose tip does not match the public explorer keeps HGN offers closed, which is the intended 503.

## Context and Orientation

Hegemon here means the project's own chain. One HGN is 100,000,000 atoms. The public testnet is the v0.11 pre-mainnet network whose genesis and manifest are pinned in `config/testnet/0.11/release.json`. The node speaks JSON-RPC on loopback, normally `http://127.0.0.1:9944`. A wallet is an encrypted file read by the `private-spend` program. That program is a one-shot command, not a long-running service. `status` prints a passphrase prompt, then note rows, then one machine line beginning `balance synced_height=`.

The hosted page is the static site in `swap-ui/hosted.html`, generated from `swap-ui/index.html` by `scripts/build_client_manifest.mjs`. Its content-security policy allows the page to call only itself and `http://127.0.0.1:8788`. The companion in `scripts/local_swap_companion.py` is the program that binds that loopback port. `--hosted-node-status` answers `GET /health` and `GET /hegemon/status` and rejects every wallet flag. The browser pairing code in `swap-ui/app.js` currently requires the capability list to be exactly `['hegemon-public-status']`.

An offer is a listing stored by the Worker or by `swap-service/server.ts`. Creating one does not move coins. The guided wizard is `swap-ui/journey-ui.mjs`. Its last step copies values into the advanced `#offer-form` and submits that form. The amount helpers live in `swap-ui/offer-draft.mjs`. `0.001` HGN is the string `100000`.

`scripts/probe_hegemon_testnet.py` `probe()` reports whether the node is syncing, how many peers it has, and whether `basic_wallet_checks_passed` is true. `compare_public_tip()` compares that node with the public explorer and fails when the heights differ by more than 12 blocks. The companion treats either failure as "not ready".

The approved seed list, for any note that tells an operator how the node itself was started, is `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`. Miners on one network must share those seeds. The host must run NTP or chrony, because a future-skewed block time is rejected and because the public-tip check also rejects a stale or future explorer status.

## Plan of Work

First add `hosted_balance_view`, `read_hosted_node` and `HostedWalletSession` to `scripts/local_swap_companion.py`. `hosted_balance_view` uses `public_hegemon_wallet.balance` and additionally requires `immature_atoms` on that same line. It returns only the totals described in the Decision Log. `read_hosted_node` calls `probe` and `compare_public_tip` and raises `LookupError` with the fixed message `hegemon_node_not_ready` on any failure. `HostedWalletSession.unlock` prints `Type UNLOCK to read the local Hegemon wallet`, reads the passphrase with echo off, runs `private-spend status` through the existing `wallet()` helper, and caches the totals. `balance` returns  the cache when it is younger than 60 seconds and the node tip is at most two blocks ahead of `synced_height`; otherwise it runs `status` again with the cached passphrase and does not prompt.

Then add `--hosted-wallet-status`. It is mutually exclusive with `--hosted-node-status`, `--hegemon-public` and `--enable-hegemon-actions`, accepts only the pinned hosted origin, requires `--hegemon-rpc` on loopback and exactly one mode-0600 `--hegemon-wallet`, and fills genesis and manifest from `config/testnet/0.11/release.json` and `config/testnet/0.11/network-manifest.json`. It requires an interactive terminal. Health capabilities are `hegemon-public-status` and `hegemon-public-balance`. `GET /hegemon/status` stays the same shape as the status-only mode. `GET /hegemon/balance` returns the totals, 409 when locked, or 503 when the node is not ready. `POST /hegemon/unlock` accepts an empty body or `{}`. No other path is served. `--hosted-node-status` still returns 404 for `/hegemon/balance` and 403 for every POST.

In `swap-ui/offer-draft.mjs` add `HEGEMON_PUBLIC_FEE_ATOMS`, `hegemonGiveCovered(amountAtoms, availableAtoms, feeAtoms = 1000n)` and `assertHegemonGiveSnapshot(amountAtoms, snapshot, now)`. The assertion rejects a missing snapshot, a non-integer field, `watch_only !== false`, an `observed_at` older than 60 seconds, an observed height more than two above the synced height, and a shortfall. The shortfall message includes the formatted HGN amount and says the listing was not created and does not lock funds.

In `swap-ui/app.js`, accept a hosted capability list that contains `hegemon-public-status` and only the two known names. Remember whether `hegemon-public-balance` is present. Do not unhide `#hegemon-actions`. When the balance capability is absent, keep the sentence `This is a status check; Hegemon swaps are not ready here yet.` When it is present, say that HGN offers can use the unlocked wallet and that creating a listing does not lock funds. On hosted `#offer-form` submit, if the give asset is Hegemon HGN, GET `/hegemon/balance` and call `assertHegemonGiveSnapshot` before creating an inbox. Map `wallet_locked` and `hegemon_node_not_ready` to short sentences.

In `swap-ui/journey-ui.mjs`, when the hosted give-amount step is HGN, show `#journey-hgn-funds`: the available amount, a Guard Rail (`#ff4e4e`) shortfall, a hint that the listing does not lock funds, and an Unlock button drawn in Ionosphere (`#1be7ff` on `#0e1c36`). Unlock POSTs `/hegemon/unlock` and tells the person to approve it in the companion terminal. Continue stays disabled until `hegemonGiveCovered` succeeds. Publish GETs `/hegemon/balance` again and refuses on failure. The same helper is what the advanced form uses, so the two paths cannot disagree.

Update the start instructions in `swap-ui/index.html` (the hosted copy is generated). Mention both companion commands, the one-wallet limit, the seed list, and NTP. Update the hosted companion sentence in `scripts/build_client_manifest.mjs`. Then run `node scripts/build_client_manifest.mjs`.

## Concrete Steps

Work from the repository root `/home/william/Hegemon`.

Add the companion mode and the page gate as described above. Rebuild the hosted page:

    node scripts/build_client_manifest.mjs

Run the pure and companion tests:

    node --test swap-ui/offer-draft.test.mjs
    PYTHONPATH=scripts python3 -m unittest discover -s scripts -t scripts -p 'test_local_swap_companion.py'

Run the browser checks when Chromium is installed (`CHROMIUM_PATH` may be `/usr/bin/chromium` or `/snap/bin/chromium`):

    CHROMIUM_PATH=/usr/bin/chromium node --test swap-service/hosted-node-browser.test.mjs swap-service/hosted-hgn-gate-browser.test.mjs swap-service/journey-browser.test.mjs

Expect each command to exit 0. The companion test must show that a body containing `position=` never appears on `/hegemon/balance`. The gate browser test must show that a status-only companion still connects, that Continue does not leave the HGN amount step when the balance is below amount plus fee, and that a sufficient mocked balance allows one offer POST. The existing journey test must still create one HGN offer after its mocked unlock, and its Ethereum offer must still be created with no Hegemon unlock.

## Validation and Acceptance

Start a status-only companion exactly as METHODS already describes. The hosted page still connects and still says this is a status check. `GET /hegemon/balance` on that process is HTTP 404.

Start the wallet-status companion in a terminal, with the node already running and NTP enabled:

    umask 077
    mkdir -p "$HOME/.local/share/hegemon-swap"
    python3 scripts/local_swap_companion.py --hosted-wallet-status \
      --hegemon-rpc http://127.0.0.1:9944 \
      --hegemon-wallet /path/to/one.wallet \
      --token-file "$HOME/.local/share/hegemon-swap/companion-token"

Pair it from the hosted page. Choose Hegemon HGN as the asset to give. The amount step shows an Unlock button. After typing `UNLOCK` and the passphrase in that terminal, the page shows available HGN and not a list of notes. Continue stays disabled until the amount plus 1,000 atoms is covered. Creating the offer still does not lock funds: a later spend of those coins is possible, and the Worker has no balance field. If the node is syncing or far from the public tip, the page says HGN offers stay closed and does not publish.

An Ethereum, Bitcoin or Cardano give continues with no unlock.

## Idempotence and Recovery

Re-running the manifest build overwrites only generated files (`swap-ui/hosted.html`, `swap-ui/client-manifest.json`, `swap-ui/index.html` integrity attributes, and `swap-service/cloudflare/client-policy.mjs`). Re-running the tests starts disposable processes and does not use the operator's wallet or the long-running node database. Stopping a wallet-status companion zeroes the in-memory passphrase in its `finally` block. Starting it again prompts again. Do not delete a node database or a wallet file as part of these steps.

## Artifacts and Notes

A successful balance response looks like this and contains no `position=` text:

    {"available_atoms":"5000000","reserved_atoms":"0","htlc_atoms":"0","immature_atoms":"11","synced_height":"8659","watch_only":false,"observed_height":"8659","observed_at":"1700000000000"}

A locked GET is `{"error":"wallet_locked"}` with status 409. A node that is not ready is `{"error":"hegemon_node_not_ready"}` with status 503.

## Interfaces and Dependencies

In `scripts/local_swap_companion.py`:

    def hosted_balance_view(text, observed_height) -> dict
    def read_hosted_node(rpc) -> dict
    class HostedWalletSession:
        def unlock(self) -> dict
        def balance(self) -> dict
        def close(self) -> None

`unlock` raises `ValueError` with `wallet unlock declined locally` or `passphrase required`, and `LookupError` when the node is not ready. `balance` raises `PermissionError` when locked and `LookupError` when the node is not ready.

In `swap-ui/offer-draft.mjs`:

    export const HEGEMON_PUBLIC_FEE_ATOMS = 1000n
    export function hegemonGiveCovered(amountAtoms, availableAtoms, feeAtoms = HEGEMON_PUBLIC_FEE_ATOMS)
    export function assertHegemonGiveSnapshot(amountAtoms, snapshot, now = Date.now())

`hegemonGiveCovered` returns `{covered, requiredAtoms, shortfallAtoms}` using decimal strings. `assertHegemonGiveSnapshot` throws `Error` when the offer must not be created.

`initJourney` in `swap-ui/journey-ui.mjs` takes an optional `hegemonWallet` object with `paired()`, `unlock()` and `balance()`. `swap-ui/app.js` supplies it. The gate is active only when the document element has `data-hosted-testnet`.

The public fee of 1,000 atoms is the value of `PublicHegemonProfile.fee` in `scripts/swap_engine/adapters/hegemon_local.py`. Do not change the Worker offer API.

## Revision note

2026-11-10: Created this plan to record the hosted HGN funding gate before implementation. The status-only companion stays. The new mode returns totals only after a terminal unlock. The page hard-blocks hosted HGN-give offers and leaves every other asset ungated.

2026-11-10: Implementation matches this plan. The 60-second and two-block refresh is covered by `HostedWalletSession` unit tests. The HTTP test uses a fake `private-spend` and proves note rows and the passphrase are absent from the response. `observed_at` was added so the page can reject a snapshot older than 60 seconds.
