---
name: P3 UI wallet integrations
overview: "Plan 3 of 8. Extend the hosted interface beyond Sepolia: claims with encrypted backup, Cardano CIP-30 and Bitcoin PSBT flows, automatic preimage observation, a guided flow, and real wallet qualification."
todos:
  - id: p3-execplan
    content: Write .agent/SWAP_UI_WALLETS_EXECPLAN.md after reading P2 final schema
    status: completed
  - id: p3-choices
    content: Choose and pin Cardano and Bitcoin browser libraries and Cardano script-budget approach
    status: completed
  - id: p3-sepolia-claim
    content: Sepolia claim from encrypted backup with policy checks
    status: completed
  - id: p3-cardano
    content: Cardano CIP-30 fund/claim/refund with body decode and verification before signing
    status: completed
  - id: p3-bitcoin
    content: Bitcoin browser PSBT fund/claim/refund with export/import signing path
    status: completed
  - id: p3-observers
    content: Browser preimage observers with Worker read proxies
    status: completed
  - id: p3-guided
    content: Guided flow view using policy verdict and action journal
    status: completed
  - id: p3-qualify
    content: Real wallet qualification on public testnets
    status: completed
  - id: p3-docs
    content: Update swap-service README, DESIGN.md, METHODS.md
    status: completed
  - id: p3-revise
    content: Revise plans P4..P7 based on what was learned
    status: completed
isProject: false
---

# Plan 3 of 8: Hosted UI wallet integrations

Depends on P1 (policy) and P2 (state schema). Feeds P4 and P5.

## Current state

The hosted page (Cloudflare Worker plus `swap-ui/`) has read-only verifiers for Sepolia, Bitcoin testnet4 and Cardano preview, a pair check, and manual Sepolia deploy/approve/fund/revoke/refund (`swap-ui/sepolia-actions.mjs`). Local-only claim, Bitcoin and Cardano actions go through the loopback companion (`scripts/local_swap_companion.py`) and are not available to the hosted page. Preimage observers exist only in Python (`scripts/public_testnet_observers.py`).

## Scope

1. Sepolia claim from an encrypted backup (extend `swap-ui/ethereum-actions.mjs` claim logic, currently gated to local chain 31337, to Sepolia with the same checks: pinned runtime, hashlock, funded state at confirmed snapshot and head, plus the P1 margin check on the other leg). Keep the warning that the preimage reaches the wallet before approval.
2. Cardano via CIP-30: fund, claim, refund for ADA and native-asset bundles.
   - Needs a transaction builder in the browser (a pinned, vetted library) and script execution budgets. Koios has no evaluation endpoint, so choose between a conservative fixed budget (as the Python path does), an evaluate-capable provider routed through the Worker, or both with a fallback. Decide in step 2.
   - Decode and display the exact transaction body from the wallet-bound bytes and check it against terms before asking for `signTx`; preserve unrelated tokens in change.
3. Bitcoin: browser-built P2WSH funding, claim and refund PSBTs (pinned library). Signing via a PSBT-capable wallet where testnet4 is supported, plus a documented export/import path for local signing (Sparrow/Core) when no extension supports testnet4. Reconstruct and check the script with the existing verifier before each step.
4. Browser preimage observers: port `public_testnet_observers.py` logic to JS (Bitcoin witness, Ethereum claim event/receipt, Cardano redeemer), through the Worker's read proxies, with the same confirmed-depth and unindexed-data handling; save the result into the encrypted backup (`swap-ui/recovery.mjs`, `vault-store.mjs`).
5. Guided flow: a view that walks a user through P2's state sequence with the P1 verdict at each step, using the action journal (`swap-ui/action-journal.mjs`) before every wallet request. Resolve in step 1 whether it uses a JS reducer validated against P2's transition vectors, or a local engine process.
6. Real-wallet qualification: MetaMask (or equivalent) on Sepolia, a CIP-30 wallet on Cardano preview, and a testnet4 PSBT signer. Record wallet versions and results, including lost-response and wrong-network cases.
7. Hegemon stays a clearly labelled "unavailable on public testnet" leg in the UI.

## Steps

1. Read P2's final schema; write `.agent/SWAP_UI_WALLETS_EXECPLAN.md`; consult `BRAND.md` for any new UI.
2. Choose and document the Cardano and Bitcoin builder libraries and the Cardano budget approach; pin versions and record checksums (feeds P5 integrity work).
3. Implement items 1 to 5 in `swap-ui/` with unit tests and Playwright tests against local Anvil and mocked wallet providers (Node 24, Chromium).
4. Add Worker read proxies needed for observers; extend `swap-service/cloudflare/worker.test.mjs`.
5. Run real-wallet qualification on public testnets using disposable funds; log outcomes in `PUBLIC_TESTNET_RESULTS.md` (public IDs only).
6. Update `swap-service/README.md`, `DESIGN.md` and `METHODS.md`.

## Acceptance

- A claim on Sepolia, Cardano preview and Bitcoin testnet4 completed from the hosted page with a real wallet, each with a confirmed transaction ID.
- The observer retrieves a counterparty preimage without manual lookup.
- Wrong-network, declined, lost-response and stale-head cases fail safe in tests.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- The hosted Worker is healthy (HTTP 200, empty offer list) and the served `app.js`, `style.css` and `crypto.mjs` are byte-identical to the repository; no drift to repair before starting.
- The Worker rewrites `/` with `HTMLRewriter` (title, note, hidden local-node sections) and redirects `/index.html` with HTTP 307. Any new Worker read proxy or UI section must keep that rewrite in mind and tests must fetch `/`, not `/index.html`.
- Cloudflare can return HTTP 1010 to non-browser user agents; script-based checks of the hosted site should send a browser-like User-Agent, and Playwright tests are the source of truth.
- Run all JS tests with Node 24 (`~/.local/opt/node-v24.22.2-linux-x64/bin`), and Chromium is `/snap/bin/chromium` (set `CHROMIUM_PATH`).

Revision from P1 (2026-11-05):
- The hosted public pair check already shows a timing verdict. `swap-ui/app.js` loads `/chain-timing.json`, validates it with `validateTiming`, passes per-leg limits (`legRequirements`) into the Sepolia, Bitcoin and Cardano verifiers, calls `checkPublicPair(..., {config, now})`, and renders the result in `#public-pair-timing` with `renderTiming` (pass or fail heading, the gap, claim window and worst-case lock in plain units, each reason, and an assumptions note). Reuse these; do not add a second timing display. The guided flow should call the same `timelock-policy.mjs` and `formatSeconds`.
- Verifier snapshots now carry the head the policy needs: `headTimestamp` (Sepolia, Cardano) and `tip` (Bitcoin). A Hegemon snapshot must provide `height`.
- The browser reducer is pure JS importing `timelock-policy.mjs`; there is no need for a second port. State machine transitions that depend on time must use `legWindow`, so "last safe claim" and "earliest refund" shown to the user come from the same function as the verdict.
- The local regtest and Anvil flow (`#pair-verify`) is not covered by the testnet policy; keep its warning text.
- Static serving: new browser modules and JSON must be added to the allow-list in `swap-service/server.ts` (Cloudflare serves the whole `swap-ui/` directory). A test fails if `swap-ui/chain-timing.json` differs from `config/swap/chain-timing.json`.
- Hosted-claim safety: show "submit claim by" for the leg the user is claiming, computed from `legWindow` and `action_seconds`, and refuse a claim inside the cutoff.

Revision from P2 (2026-11-06):
- The engine exists in Python (`scripts/swap_engine/engine.py`, CLI `scripts/swap_engine_cli.py`). It signs with key files, not browser wallets, so do not port the signing path to the browser. Decision for this plan: port only the pure parts the page needs to *display* and *plan* (`decide` for "what happens next" and `explain`; `planner.plan_with_margin` for suggested expiries). The raw `planTimeouts` returns expiries on the edge of the window tables with zero slack and every simulated pair aborted until `plan_with_margin` (samples threshold times and four corner head advances) was added, so the browser must not offer raw `planTimeouts` expiries. Keep Python as the source of truth: generate JSON transition vectors from `engine.TRANSITIONS` and the decision tests, check the JavaScript against them, and fail the build if they diverge (same pattern as `config/swap/timelock-vectors.json`).
- State schema the UI can read from a store: `record.json` has `version, swap_id, role, state, terms_digest, escrows, txids, submitted, inflight, needs_human, seq, history`; `terms.json` has `version, hashlock, legs.{long,short}.{chain, amount, refundee, claimant, expiry}`. States: initiator `terms_saved, long_fund_submitted, long_funded, short_verified, short_claim_submitted, done, refund_submitted, refunded`; responder `terms_saved, long_verified, short_fund_submitted, short_funded, preimage_known, long_claim_submitted, done, refund_submitted, refunded`; terminal `aborted, failed`; `needs_human` and `inflight` are flags that the UI must surface and must never hide.
- Identity strings in terms are chain-specific and the UI has to produce them exactly: Bitcoin compressed public key (66 hex), Ethereum lowercase `0x` address, Cardano 56-hex payment key hash. An adapter refuses to act when its wallet's identity is not the refundee (own leg) or claimant (counterparty leg) in the terms. The swap id is the first 16 hex characters of sha256 of the canonical terms (sorted keys, no spaces).
- Escrow references exchanged between parties are `{txid}` (Ethereum) and `{txid, vout: 0}` (Bitcoin, Cardano); they are untrusted and verified on chain against the terms before use. A hosted Cardano verifier must treat an empty Koios `tx_info`/`tx_cbor` answer for a confirmed transaction as "pending", not "absent".
- A browser wallet cannot supply the engine's journal guarantees. If P3 lets a user act from the page, the page must write nothing the engine would treat as a signed action; prefer showing the CLI command (`advance`, `receive`, `resolve`) and the engine's `explain` text.

## Last step: revise later plans

Update the master ExecPlan and edit P4..P7:
- P4: whether the UI can finish any Bitcoin case instead of scripts.
- P5: the exact libraries and bundle that need integrity pinning, and the signing hooks available for CIP-30 `signData` and Ethereum signatures.
- P6: UI placeholders needed for a Hegemon leg.
- P7: new test commands, new dependencies and UI doc updates.
