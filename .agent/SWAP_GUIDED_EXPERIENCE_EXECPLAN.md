# Guide people through the testnet swap site

This is a living execution plan and must be maintained in accordance with `.agent/PLANS.md` in this repository.

## Purpose / Big Picture

The hosted testnet site currently presents many wallet, escrow, identity, recovery, and offer controls on one long page. A person must infer both the starting point and the order of actions. The new hosted experience starts by asking whether to create an offer, find an offer, open a shared link, or continue a swap. Offer creation asks about one part of the offer at a time and gives an exact review before publishing. The existing detailed controls remain available through an optional advanced view. The interface must tell the truth: publishing and reserving an offer do not lock funds, completing a swap still involves manual steps, and the hosted page cannot reach a Hegemon node on the user's computer.

## Progress

- [x] (2026-11-09 16:42Z) Inspected the live hosted page, the current branch, its existing guided decision module, and the security and branding guidance. The live page was 9,111 pixels tall at a 1,440-pixel viewport and exposed 15 major headings before an offer was selected.
- [x] (2026-11-09 17:10Z) Implemented guided navigation, exact native-coin conversion, staged creation, shared-link handling, one-time inbox-backup acknowledgement, and separate terms/status screens. Existing transaction and wallet handlers remain in use.
- [x] (2026-11-09 17:22Z) Added focused unit and browser checks and regenerated the client integrity artifacts. `make swap-test` passed with optional external chain tools disabled: 167 UI tests, 19 relay/Worker tests, and the Python fast-tier suites passed; optional chain-tool cases were skipped. The separate browser suite passed all 13 scenarios, including disposable local-chain scenarios, and the final guided-flow scenario passed again after the copy change.
- [x] (2026-11-09 17:22Z) Updated `DESIGN.md` and `METHODS.md` and checked the redesigned interface at desktop and mobile widths. The client-manifest check, whitespace check, and secret scan passed.
- [ ] Commit and push the changes, then update and verify the hosted testnet site.

## Surprises & Discoveries

The current `Guided swap` module is a read-only interpreter of an existing engine status and separately supplied terms for native-asset swaps; it does not model token or NFT legs. It is not an automatic swap coordinator. The new flow must offer it honestly as a way to review an existing native-asset swap, not as a finished automatic swap.

The offer service stores amounts as integer strings in the asset's smallest unit. Native coin values displayed in conventional units must be converted exactly, with integer arithmetic, and the exact stored amount must be shown before submission. ERC-20 and Cardano native-token decimal metadata is not reliably known to this page; such amounts remain explicitly in base units rather than guessing token decimals.

An unchanged baseline checkout also triggered a Node 24 native assertion while the older `swap-service/browser.test.mjs` transitioned to its second scenario. That scenario dynamically imported Node built-in modules inside the test. Moving those imports to the file's existing static imports allowed all three scenarios to complete with the same behavior. An existing guided browser expectation also named Hegemon's public testnet as unavailable even though the current code correctly says a local companion is required; the test now matches the implementation.

## Decision Log

- Decision: Default the hosted page to the step-by-step experience while retaining the existing detailed interface behind an explicit advanced-view control. Keep the local operator interface in its existing mode by default and allow users to opt in to the same guided view there. Rationale: the request concerns the hosted page and existing local tools and integrations must remain accessible. Date/Author: 2026-11-09 / Codex.
- Decision: Use the existing offer creation, reservation, identity, messaging, escrow-verification, and action handlers rather than implementing a second transaction engine. Rationale: this change is about comprehension and must not weaken transaction validation or misrepresent incomplete capabilities. Date/Author: 2026-11-09 / Codex.
- Decision: Keep the entire original offer fragment, including the message key and optional identity code, in the URL fragment when opening a shared link. Validate its origin and format locally and never send the fragment to the server. Rationale: the existing encryption and identity features rely on those values staying in the browser. Date/Author: 2026-11-09 / Codex.
- Decision: Keep an offer refresh from changing the current guided screen unless the person is at the start, public board, link entry, or offer overview. Rationale: a delayed response must not pull someone away from checking an identity or a wallet action. Date/Author: 2026-11-09 / Codex.

## Outcomes & Retrospective

The guided offer and navigation work is implemented and validated. The site still uses the existing manual transaction tools: the native-asset swap review requires existing local engine terms and status, does not support token or NFT swaps, and Hegemon requires a local companion. Publication and hosted verification are the remaining steps.

## Context and Orientation

`swap-ui/index.html` holds the existing forms. `swap-ui/app.js` connects them to wallet and offer handlers. `swap-ui/guided.mjs` and `swap-ui/guided-ui.mjs` interpret an existing swap's terms and status but do not sign or advance it. `swap-service/server.ts` is the local relay; `swap-service/cloudflare/worker.mjs` is the hosted relay. `scripts/build_client_manifest.mjs` derives `swap-ui/hosted.html`, the browser integrity manifest, and the relay's served-file and content-security policy from the source page. The same generator must run after the page or modules change.

The current hosted relay holds offers, reservations, and encrypted messages, not wallets. Hegemon wallet actions require a separately operated local companion. Preserve the current secure submission journals, signed identity handling, and recovery backup disclosures. The original checkout at `/workspace/Hegemon` contains an unrelated `.wrangler` directory; do not alter or commit it. This worktree is `/tmp/hegemon-deploy-cef1bae1`, based on the remote `local-private-spend-htlc` branch.

## Plan of Work

Add a small client-side navigation module and a dedicated offer-draft module under `swap-ui/`. Add a guided shell to `swap-ui/index.html`, style it in `swap-ui/style.css`, and initialize it from `swap-ui/app.js`. Preserve every original form and its identifiers. The guided view should expose one original section only when that action is relevant; advanced mode restores the existing layout. Publish an offer through the existing form and handler only after local validation and an explicit review; do not send anything while moving through the draft. Use the existing form's successful and failed outcomes to present the share link and, if selected, the one-time encrypted inbox backup. Protect against duplicate submissions and preserve the existing warning that the inbox backup does not contain the owner credential or wallet.

Add asset helpers that convert native BTC, ETH, ADA, and HGN decimal quantities exactly to integer base units using `BigInt`, validate their precision and bounds, and show the result. Treat token quantities as explicitly named base units, require exact token identifiers, and handle an ERC-721 quantity as one. Never use floating-point conversion for asset amounts. Validate a pasted shared link as a same-origin URL or fragment and preserve the complete fragment.

When an offer is selected, provide a clear view of the terms and offer controls, then routes to signed identity, encrypted conversation, escrow checks, and the existing swap-status review. Do not suggest that a reservation or a browser form has completed a swap. Preserve the existing Hegemon limitation and allow wallet connections and expert controls without leaving the interface in an inaccessible state.

## Concrete Steps

From the repository root, implement the source changes and add focused `node:test` cases under `swap-ui/` and a Playwright browser scenario under `swap-service/`. Run `node scripts/build_client_manifest.mjs` to update generated files, then `node scripts/build_client_manifest.mjs --check`. Run the relevant `node --test` suites and the browser scenario using Chromium and a disposable local offer database. Run existing browser scenarios that cover offer, identity, guided status, and wallet access where the environment supports them. The multi-hour Hegemon tests are out of scope.

Before publishing, commit only intended source, test, documentation, and generated client files, and push the current branch without force. Deploy the verified Worker and static assets using the already-authorized Wrangler with its cache and build output outside any existing `.wrangler` directory. No D1 schema change is planned. Verify the live site with `NODE_USE_ENV_PROXY=1 node scripts/verify_hosted_client.mjs --base https://hegemon-swap-testnet.willdoyle422.workers.dev` and confirm the entry page starts in guided mode.

## Validation and Acceptance

With a fresh hosted browser, only the start choices should be presented, with a clear testnet notice. Choosing offer creation should show one stage, retain values when navigating back, refuse malformed asset identifiers and amounts, display exact integer units at review, and make no offer request until explicit confirmation. Successful creation should show the private share link and any selected encrypted backup before proceeding. A second browser should be able to open a shared link, see the maker's terms, and reserve using the existing relay without revealing the fragment to the relay. A user must be able to reach the existing identity, messaging, guided-status, wallet, and recovery controls and return to guided mode. Repeat the navigation at a narrow mobile viewport and verify keyboard-accessible controls and legible text.

Unit tests should include fractional native amounts, over-precision, zero, integer bounds, NFT quantity, malformed identifiers, and private-link origin and fragment cases. Browser tests should exercise a real local relay, check that no wallet signing request occurs during drafting, and ensure only one offer is created on submission.

## Idempotence and Recovery

Regenerating the integrity artifacts is deterministic. Offer drafts stay in page memory until publishing; no new server-side draft or wallet is created. The existing action journal and backup records remain in their current browser storage. A failed offer-creation request is shown to the user and must not be retried automatically. A deployment can be rolled back to the previous Worker version because this task makes no database migration. Never expose the private D1 backup, wallet files, or `.wrangler` credentials.

## Artifacts and Notes

The current live URL is `https://hegemon-swap-testnet.willdoyle422.workers.dev/`. Baseline `ae459d8705d464ac1a61c4b3cc0091c1491cfff6` passed the client manifest and fast suite during the preceding deployment.

## Interfaces and Dependencies

Use plain browser JavaScript and the existing Node 24 test runner; do not add a UI framework. Use the installed Chromium and Playwright Core for browser checks. Preserve the HTML `hidden` property on existing sections because wallet and offer handlers own it; guided navigation may hide sections via its own presentation attributes, but must not turn an unavailable capability into an available one.
