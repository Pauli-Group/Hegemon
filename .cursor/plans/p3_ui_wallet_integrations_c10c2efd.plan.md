---
name: P3 UI wallet integrations
overview: "Plan 3 of 8. Extend the hosted interface beyond Sepolia: claims with encrypted backup, Cardano CIP-30 and Bitcoin PSBT flows, automatic preimage observation, a guided flow, and real wallet qualification."
todos:
  - id: p3-execplan
    content: Write .agent/SWAP_UI_WALLETS_EXECPLAN.md after reading P2 final schema
    status: pending
  - id: p3-choices
    content: Choose and pin Cardano and Bitcoin browser libraries and Cardano script-budget approach
    status: pending
  - id: p3-sepolia-claim
    content: Sepolia claim from encrypted backup with policy checks
    status: pending
  - id: p3-cardano
    content: Cardano CIP-30 fund/claim/refund with body decode and verification before signing
    status: pending
  - id: p3-bitcoin
    content: Bitcoin browser PSBT fund/claim/refund with export/import signing path
    status: pending
  - id: p3-observers
    content: Browser preimage observers with Worker read proxies
    status: pending
  - id: p3-guided
    content: Guided flow view using policy verdict and action journal
    status: pending
  - id: p3-qualify
    content: Real wallet qualification on public testnets
    status: pending
  - id: p3-docs
    content: Update swap-service README, DESIGN.md, METHODS.md
    status: pending
  - id: p3-revise
    content: Revise plans P4..P7 based on what was learned
    status: pending
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

## Last step: revise later plans

Update the master ExecPlan and edit P4..P7:
- P4: whether the UI can finish any Bitcoin case instead of scripts.
- P5: the exact libraries and bundle that need integrity pinning, and the signing hooks available for CIP-30 `signData` and Ethereum signatures.
- P6: UI placeholders needed for a Hegemon leg.
- P7: new test commands, new dependencies and UI doc updates.
