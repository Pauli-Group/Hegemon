# Make the hosted swap flow understandable and resumable

This is a living execution plan maintained according to `.agent/PLANS.md`.

## Purpose / Big Picture

A person swapping native BTC, ETH, ADA or HGN on their testnets should see one next action or one explicit waiting state, know which participant is expected to act, and return by refreshing the page. Wallet signatures remain explicit. The user asked to wait until all four chains work in the wizard before publishing. A site that only collects offers or produces command-line instructions is not an automated swap, so the page must say what is actually supported and never interpret an unverified relay assertion as an on-chain confirmation.

## Progress

- [x] (2026-11-11 21:14Z) Inspect the existing offer journey, relay, identity, signed session protocol, chain observers and wallet transaction actions.
- [x] (2026-11-11 21:21Z) Add evidence-based offer and engine-review actor labels, restore offer navigation on reload, and stop guided action prefill on an uncertain local action.
- [x] (2026-11-11 21:29Z) Automatically fill empty wallet addresses, sequence the guided identity signatures, test Cardano–Ethereum signed proposals and add a durable encrypted-packet outbox with lost-response tests.
- [x] (2026-11-11 21:38Z) Add exact Cardano/Ethereum session-asset translation and a purpose-bound, wallet-identity and chain-verification gate, with tests for stale heads, altered terms and premature identity expiry.
- [x] (2026-11-11 21:49Z) Add durable session storage, version-2 backup packet high-water marks, signed-history replay, participant proof preparation and an idempotent participant-publication primitive; test recovery and lost responses in Chromium.
- [x] (2026-11-11 21:57Z) Start matching maker and taker sessions with a pinned offer, durable channel handshake and encrypted session backup; exercise two browser contexts, a lost response and reload.
- [x] Connect the session setup, identity, terms, native-asset funding, on-chain observation and explicit claims to the browser wizard. A two-context browser simulation exercised both claims.
- [x] Exercise simulated ADA–ETH claims in both funding orders, relay-independent refunds on both chains, and encrypted-backup restoration in another browser. The refund tests reload while the relay is unavailable.
- [x] Add Bitcoin testnet term translation, on-chain spend observation, signed-participant planning and the independently verified Bitcoin funding gate. Bitcoin funding, claim, refund and wallet handoff are not yet wired into the wizard.
- [ ] Implement and test guided Bitcoin PSBT signing, recovery, funding, claims and refunds for each supported pairing.
- [ ] Implement and test Hegemon public-pre-mainnet coordination with the local companion, including private note verification, refund handoff, secret release, recovery and explicit local approval.
- [ ] Finish and test the refund and recovery paths, including loss of the relay and uncertain wallet submissions. Add a way to restore an encrypted backup in a fresh browser.
- [ ] Keep unsupported token paths visibly blocked where they are not complete; the user currently needs native BTC, ETH, ADA and HGN only.
- [ ] Connect the signed session protocol to a durable two-browser wizard without weakening its wallet, chain, deadline, secret-backup or uncertain-transaction protections.
- [ ] Exercise both parties through creation, refresh, wallet approval, funding, confirmation, claiming and refunds, including refusal cases.
- [ ] Verify the browser and fast suites, push the branch, back up the remote database, deploy and verify the hosted client.

## Surprises & Discoveries

The offer wizard and the standalone guided swap reviewer are separate. The latter requires pasted engine status and never advances the engine. The authenticated session transport, signed participant statements, signed proposal packets and encrypted session recovery modules exist and have unit tests, but no page imports them. The session protocol test states explicitly that it stops before transactions. `swap-ui/session-outbox.mjs` now persists the exact encrypted frame before sending and serializes its sequence across tabs, but its callers must also persist the channel key and protocol history; it is not yet wired to the page. A guided prefill did not recheck the other leg when the wallet action was later submitted; the warnings now state that limitation and unresolved local action records stop prefill. The older guided engine only accepts version-1 native-asset terms with safe-integer amounts; ordinary ETH amounts and token offers need the newer exact-string terms and verifier support.

## Decision Log

- Decision: Never allow a party's relay message to establish an escrow or a safe deadline without independent chain and timing checks. Rationale: a counterparty or relay can lie and pages can be stale. Date/Author: 2026-11-11 / Codex.
- Decision: Keep explicit wallet approvals and persist action attempts before a wallet is asked; do not repeat an uncertain submission automatically. Rationale: duplicate funding or premature secret disclosure can lose test assets and invalidate a swap. Date/Author: 2026-11-11 / Codex.

## Outcomes & Retrospective

The local wizard connects signed session coordination to ADA/ETH funding, claims, refunds and backup restoration. Browser tests with simulated chains completed claims in both directions and refunds with the relay offline, with separate wallet approval for each transaction. These are not public-testnet tests. Bitcoin planning and verification are partially implemented, while Bitcoin wallet actions and Hegemon sessions remain incomplete. Interrupted-action reconciliation and final validation remain in progress. The user explicitly asked us to wait for all four chains before publishing; no work from this branch has been pushed or deployed.

## Context and Orientation

`swap-ui/journey-ui.mjs` controls navigation and `session-wizard.mjs` presents each session step. `session-store.mjs`, `session-outbox.mjs`, `session-replay.mjs`, `session-recovery.mjs` and `session-action.mjs` provide durable session, message, backup and wallet-attempt records. `session-funding.mjs`, `session-claim.mjs`, `session-refund.mjs` and `session-observation.mjs` coordinate wallet operations and chain evidence; they use pinned contracts, `cardano-wallet.mjs`, `sepolia-actions.mjs` and the chain verifiers. The relay stores opaque session packets. Bitcoin's existing `bitcoin-wallet.mjs` requires a PSBT handoff to an external signer. Hegemon's companion currently has separate hosted read-only and local-only public-action modes; its wallet verifies private HTLC notes and needs local refund handoffs. Hegemon address control cannot currently be proven by its wallet. These constraints must be resolved in the wizard without exposing keys or loosening chain checks. `chain-timing.json` and `timelock-policy.mjs` govern safe windows. The deployment procedure is `.cursor/skills/hegemon-hosted-swap-deploy/SKILL.md`.

## Plan of Work

Build an explicit state projection from saved local evidence, authenticated session packets and fresh chain observations. Present one action or waiting message at a time; refresh restores the current offer and checks relay and chain state without requesting wallet approval. Preserve state and exact outgoing packets before network submission; handle reloads and uncertain outcomes without double spending. Integrate signed participant identities and exact terms, and request a wallet only after explicit user action and revalidation. Preserve refund and encrypted recovery paths. Keep unsupported assets and missing evidence visibly blocked. Use existing pinned contract templates and wallet action functions rather than inventing new contracts.

## Concrete Steps

From the repository root, update browser modules, markup, generated client manifest and focused tests. Run `node scripts/build_client_manifest.mjs`, `node scripts/build_client_manifest.mjs --check`, focused Node and Chromium tests, `make swap-test`, and `make swap-integration`. Push only after tests pass. Back up Cloudflare D1 outside the repository, inspect the existing schema, deploy with the authorized Wrangler and run `node scripts/verify_hosted_client.mjs --base https://hegemon-swap-testnet.willdoyle422.workers.dev`.

## Validation and Acceptance

Two separate browser contexts with mock testnet wallets should create and accept an ETH/ADA offer, independently sign bound participant statements and terms, approve the respective funding and claims, refresh between turns, and display the correct acting party and actual chain confirmations. Wrong network, changed terms, unsafe deadlines, stale or unavailable observations, uncertain wallet submissions, changed participant identities and interrupted communication must block unsafe actions. Recovery after refresh and refund after a deadline must be exercised. Test results do not establish real-funds safety.

## Idempotence and Recovery

A refresh does not sign, send or replace any transaction. Keep exact pending relay packets until acknowledged. Preserve private state and recovery data outside the repository; never overwrite an established offer, terms, participant or escrow reference. The database is backed up before deployment and existing reservations are not deleted.

## Interfaces and Dependencies

Node 24, Chromium and the pinned JavaScript dependencies run browser tests. Ethereum uses an EIP-1193 wallet and Cardano a CIP-30 wallet on their stated test networks. Public chain providers can be unavailable or stale; the UI must say so and never use an absence of evidence as evidence of a confirmed transaction.
