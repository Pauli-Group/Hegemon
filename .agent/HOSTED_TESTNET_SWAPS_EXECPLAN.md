# Build a hosted four-chain testnet swap interface

This living plan follows `.agent/PLANS.md`. It records the work needed for two users to find each other and complete recoverable testnet swaps involving Bitcoin, Ethereum, Cardano and Hegemon. Testnet transactions and a hosted interface must be demonstrated independently; local fixtures alone do not establish public-network behavior. Keep private keys, passphrases, unrevealed secrets and signed private recovery records outside this repository and the relay.

## Progress

- [x] Read the existing public testnet plan, local relay, wallet restrictions and network instructions. The BTC/ETH public swap and multiple Ethereum/Cardano swaps are complete. The remaining Bitcoin cases have been submitted and the session-bound runner is active.
- [x] Confirm the authorized Cloudflare account is reachable with Workers and D1 access; no D1 databases existed at inspection.
- [x] Implement and verify a Cloudflare Workers/D1 offer relay with the existing browser protocol and safe concurrent reservation handling. Published the clearly labeled offer-board prototype at https://hegemon-swap-testnet.willdoyle422.workers.dev; it does not execute swaps.
- [x] Add a read-only hosted Sepolia escrow verifier. A browser using a test provider backed by public RPC checked a funded Sepolia fixture without requesting a transaction; its subsequent refund confirmed.
- [x] Add a read-only hosted Bitcoin testnet4 escrow verifier and check a confirmed, unspent public BTC/ADA escrow.
- [x] Add a read-only hosted Cardano preview escrow verifier and check the confirmed, unspent ADA leg of that public swap.
- [x] Add read-only hosted pair comparison for Ethereum, Bitcoin and Cardano, including exact offer assets and hashlock; validate it with mocked browser snapshots. This does not authorize claims or establish safe deadlines.
- [x] Recheck the confirmed public BTC/ADA escrows against a hosted offer and common hashlock. The actual swap claims remain in progress.
- [ ] Complete public Bitcoin/Cardano, Bitcoin/ERC-20, Bitcoin/Cardano-token and Bitcoin refund cases; record transaction identifiers and recovery outcomes.
- [ ] Determine public Hegemon testnet identity, available remote or checkpoint-backed wallet access and current private-spend support; arrange test HGN and execute Hegemon swaps where possible.
- [ ] Obtain suitable persistent storage and outbound TCP access to the release seed nodes before starting a public Hegemon node. Inspection found 243 MB free on the persistent workspace, no TCP destinations configured, and only memory-backed temporary storage; the current chain size is not known.
- [ ] Add wallet and transaction integrations for public testnets, a guided two-party swap workflow, durable recovery and chain observation; retain explicit limitations until independently tested.
- [ ] Test the hosted interface with two real wallet sessions, claims and refunds; document all remaining limitations.

## Surprises & Discoveries

The public-testnet swap scripts sign locally and journal each uncertain action, but browser transaction actions remain limited to non-forked local networks. The local relay uses Node `node:sqlite` synchronously, which is unavailable as a persistent D1 database in Cloudflare Workers. The Hegemon v0.11.2 guide requires the node's unsafe wallet RPC on loopback for submission; no public remote wallet endpoint is documented. The user prefers not to sync a public full node. Two encrypted test wallets were prepared offline; an existing synced node or suitable service and test HGN remain necessary. Cloudflare returned HTTP 1010 to a Python client, while an actual Chromium browser loaded the deployed page and successfully exchanged encrypted messages. An early live browser run revealed that the message form could be clickable before handshake completion; `swap-ui/app.js` now disables it until the session check completes, and the local and hosted browser runs passed after the change. Public Sepolia RPC sometimes returned a lagging `block not found` or advanced its head during reads; a bounded read-only retry succeeded against the actual funded fixture without weakening the stable-snapshot checks. Blockstream returned HTTP 429 after the Bitcoin test runner's repeated UTxO scans; the runner was revised to reduce requests and retry transient provider failures only after checking all journals for uncertain submissions.

## Decision Log

Keep the existing local relay and isolated-chain guards intact. Add a separate Worker and D1 schema for hosted offer discovery, preserving the API while using single SQL statements for reservation and message authorization so concurrent requests cannot cross reservations. The relay must not hold wallet keys or hashlock secrets. A hosted offer board is only an early milestone, not a working four-chain swap. Use the existing Cloudflare account and a new, project-specific testnet D1 database; do not modify unrelated resources.

## Outcomes & Retrospective

The deployed offer preview is reachable and two independent Chromium contexts created and reserved a private offer, exchanged an encrypted message and closed it. The Worker uses D1 database `bc34dcb0-7983-4413-98c9-a08ba6dce311`. The local API and browser suites reported six passing tests. Work on actual hosted swap execution and Hegemon access remains in progress. Do not imply that the hosted board executes swaps until wallet integration and end-to-end tests pass.

## Context and Orientation

The repository root is `/workspace/Hegemon`. The local browser files are in `swap-ui/`, the local offer server is `swap-service/server.ts`, and public-testnet scripts and their private state are described in `.agent/PUBLIC_TESTNET_SWAP_EXECPLAN.md`. `PUBLIC_TESTNET_RESULTS.md` records current public-chain observations. The Hegemon v0.11.2 guide and frozen network manifest are in `config/testnet/0.11/`. Never change the user's existing `.wrangler/` directory or commit it. Cloudflare Wrangler is available at `/workspace/chain-tools/cloudflare-cli/node_modules/wrangler/bin/wrangler.js`; its authorization was confirmed with `whoami` without reading credentials. Node 24, Python and test-chain tools are available locally.

## Plan of Work

First build a Worker in `swap-service/cloudflare/` which serves the existing public offer API using D1, with a schema that binds messages to the active reservation. Each SQL insertion must atomically recheck the current reservation, identity, expiry and limits; replacing an expired reservation must never expose earlier messages. Same-origin requests, bounded request bodies, no-store responses and modest abuse controls are required. Run automated concurrent reservation, authorization and API compatibility tests against a local D1-compatible SQLite adapter. Run Wrangler's local integration or dry run before creating a distinct test database and deploying an explicitly experimental board. Record database identity and deployment URLs, without including secrets.

In parallel with transaction confirmations, inspect Hegemon's real v0.11.2 code and public-chain connectivity. A full node requires explicit pre-mainnet manifest, genesis, shared seed list and clock synchronization. Do not start a public full node or download chain history merely to probe; use read-only existing services or an authenticated checkpoint if available. Establish a safe wallet and test funding before public Hegemon transactions. Keep Hegemon wallets encrypted and all wallet RPC private.

Next add public-testnet wallet signing and verification for each chain through explicit wallet interfaces, preserving the existing local-only checks. Build a user-visible state machine that saves agreed terms and recovery data before funding, verifies both counterpart escrows and time margins before claims, observes released secrets, handles uncertain submissions without blind retries, and supports refunds after a deadline. The browser must not send private keys or unrevealed secrets to the relay. Treat public provider snapshots and token issuer behavior as explicit trust boundaries. Finally exercise the entire hosted flow with independent funded wallet sessions on actual testnets, including interrupted and refund cases.

## Validation and Acceptance

From the repository root, run `node --test swap-service/server.test.mjs` and the Worker tests added during implementation. Run the existing browser and chain integration checks appropriate to modified interfaces. Compare the hosted relay's responses with the existing API, including concurrent reservation races, changed reservations, unauthenticated requests and restart persistence. Validate network identity and record confirmed transaction IDs and recipient outputs for each swap; a submitted or unconfirmed transaction is not a completed test. A final hosted rehearsal requires two real wallet sessions and separate claim and refund demonstrations. Local tests do not establish public finality or token compatibility.

## Idempotence and Recovery

Cloud resources and test wallets have durable identifiers. Check for an existing project-specific resource before creating one. Back up any existing D1 data before schema changes; use additive migrations. If a transaction is marked inflight, inspect the local journal and relevant chain before any retry. Keep the private test wallet directory until every live escrow has been claimed or refunded. Never log secrets or signed transactions. Temporary local files and isolated fixtures may be removed only when their data is no longer needed for recovery.

## Interfaces and Dependencies

Use the local Node server's `/offers` API as the initial compatibility contract. The relay is an untrusted directory and encrypted-message mailbox, not an on-chain verifier. The browser talks directly to locally controlled wallets and independently selected network providers. D1 is Cloudflare's hosted SQLite service. Worker identity and D1 binding are configured through Wrangler; database migrations must run before deployment. Public network fees, free-tier limits, indexing lag and testnet block times vary.
