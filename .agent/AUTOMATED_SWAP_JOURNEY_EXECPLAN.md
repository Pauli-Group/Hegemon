# Coordinate testnet swaps without requiring a conversation

This is a living execution plan. Maintain it according to `.agent/PLANS.md` in this repository.

## Purpose / Big Picture

A person should be able to make or accept a testnet offer and have the application exchange the details, track both chains, and present the next action without the participants manually messaging each other. Each lock, claim, and refund still needs that person's wallet approval, as requested. The starting page should use a concise visual diagram of the participants' actions and the possible refund, rather than explaining hashlocks or other implementation details. The implementation must not claim a transaction occurred because a relay message says so: it must verify the chain and independently apply the deadline and identity rules before requesting an approval. It must make recovery possible if a browser closes or the relay is unavailable, while stating that the user must return in time to approve claims or refunds.

The scope is the existing testnet preview: Hegemon, Bitcoin, Ethereum, and Cardano, with HGN/BTC and native or token/NFT assets as the user previously requested. The current engine does not yet support every combination; no unsupported case may be silently presented as working. Preserve the user's Hegemon node, existing wallet data and `.wrangler` directories. Do not run multi-hour tests or spend public testnet funds as part of this change.

## Progress

- [x] (2026-11-09 19:00Z) Read the relay, identity, hosted wallet, state-machine and node-companion interfaces. The existing site requires manual coordination and the browser's engine view only reads pasted data. Asked how to sign; the user chose an explicit wallet approval for every transaction.
- [x] (2026-11-09 19:06Z) Replaced the technical explanation with a responsive SVG showing the participants and their actions, a text alternative, and a simple refund branch. Checked desktop and phone layouts, passed the fast suite and guided browser scenario, committed and pushed `0f338ca1`, deployed the diagram, and passed 110 live integrity checks.
- [x] (2026-11-09 20:17Z) Restored the interrupted work and added a separate hosted-to-local node status connection. The companion accepts only the pinned origin and private pairing code, refuses all wallet and transaction operations in this mode, and validates the local node's pre-mainnet identity. Seven focused Python checks and a Chromium test against a synthetic node passed. The status page remains separate from swap execution; deployment verification is still pending.
- [ ] Design and implement authenticated, replay-resistant structured coordination that binds both participants, all terms, and each escrow reference. Completed: additive long-lived relay sessions, owner/taker wallet-bound identity statements, a channel key independent of the share link, encrypted and signed ordered packets, exact asset terms, encrypted recovery backup, and a two-party protocol test with synthetic wallets. Remaining: durable browser journaling, user-facing integration and actual chain actions.
- [ ] Connect the coordinated session to real per-chain observation, deadline policy and wallet approvals, including safe retry, claim and refund behavior. Extend the native-only engine and wallet checks where necessary for Ethereum tokens/NFTs, Cardano native assets, and Hegemon; never enable an unverified chain or asset path.
- [ ] Exercise two parties through real browser UI, isolated chain software or representative chain adapters, including failures and reloads, and document supported and unsupported behavior. Push and deploy tested work; verify the hosted result without creating live offers or transactions.

## Surprises & Discoveries

The browser's `swap-ui/guided.mjs` only interprets pasted native-asset engine terms and status. `swap-ui/swap-flow.mjs` rejects amounts above JavaScript's safe integer range and the current term schema cannot name a token or NFT. The wallet action modules are independent single-leg operations. A correct end-to-end workflow cannot be built by changing labels or inventing status.

The relay's original reservation expires at the earlier of 24 hours or the offer's expiry, and its old chat rejects an expired offer; cleanup removes offer data after seven days. A Bitcoin swap may outlive those windows. `swap_sessions` and `swap_packets` now hold a separate 180-day, participant-authenticated coordination session; creating one closes the listing and snapshots the original offer. The local and Worker relay tests verify it survives expiry and deletion of the listing. The client still must authenticate packet content and persist its own recovery data; this session is not yet connected to the UI.

The hosted page now has a separately enabled, read-only node status connection to the local companion in the development checkout. It requires an exact hosted origin, a private pairing token and possibly browser local-network permission; Hegemon wallet RPC remains loopback-only. This checks the local node identity and its reported status, but cannot observe an escrow or perform a Hegemon swap. Wallet integration still requires a separate security design and explicit transaction approvals.

## Decision Log

- Decision: Require a participant's wallet approval for each transaction. Rationale: the user chose that model; automated coordination does not imply custody of wallet keys or unattended signatures. Date/Author: 2026-11-09 / Codex.
- Decision: Treat the hosted relay as a transport, never as proof of identity, funds, finality or a deadline. Rationale: it can fail, equivocate, replay or substitute data; existing signed identities and independently verified on-chain observations are the trust boundary. Date/Author: 2026-11-09 / Codex.
- Decision: Preserve the original action journals and local Hegemon approval boundaries. Rationale: a lost wallet response is uncertain and must not cause a second transaction to be signed or broadcast automatically. Date/Author: 2026-11-09 / Codex.

## Outcomes & Retrospective

The requested SVG is deployed and passed 110 live integrity checks and desktop/mobile browser checks. The additive durable relay session, wallet-bound participant statements, encrypted signed packet protocol and encrypted recovery envelope are implemented and tested using synthetic wallets. A two-party test exchanges terms and an escrow reference without chat or transactions. The browser does not yet persist session progress or drive real wallet actions; the interface remains a testnet preview, not a completed automated swap service.

## Context and Orientation

The hosted Worker and D1 database are in `swap-service/cloudflare/worker.mjs` and `swap-service/cloudflare/schema.sql`; `swap-service/server.ts` is its local SQLite counterpart. Offers, reservations and encrypted messages are currently bounded in time and do not authorize or store transactions. `swap-ui/app.js` connects these APIs to the forms in `swap-ui/index.html`; `swap-ui/journey-ui.mjs` is the step-by-step navigation, and `swap-ui/style.css` supplies the responsive design. The home diagram is currently a verbose four-step description in `swap-ui/index.html` and CSS rules beginning with `.swap-flow`.

`scripts/swap_engine/engine.py` contains a two-party state machine with chain observations and at-most-one action per advance. `scripts/swap_engine/store.py` persists one party's terms, status and secret with private file permissions and a crash-safe journal. The browser ports the decision and timing functions in `swap-ui/swap-flow.mjs` and `swap-ui/timelock-policy.mjs`; their test vectors prevent differences from the Python rules. `swap-ui/guided.mjs` checks actual public-chain data and decides the next step but currently cannot drive the engine. Public testnet wallet actions are in `swap-ui/sepolia-actions.mjs`, `swap-ui/cardano-wallet.mjs` and `swap-ui/bitcoin-wallet.mjs` with independent verification and action journals. Hegemon private-spend operations run only through the user-operated loopback service `scripts/local_swap_companion.py`. `swap-ui/identity.mjs` and `swap-ui/identity-proofs.mjs` check wallet signatures; Hegemon identities are currently unverified, which must be handled explicitly rather than treated as signed.

A secret is the random value whose hash appears in both contracts. Publishing it before the correct claim can let the other party spend; it must never be placed in a relay message, URL, logs, or unencrypted backup. A transaction is uncertain when a wallet or network response is lost: the application must check chain state or ask for help rather than signing again.

## Plan of Work

First replace the home explanation with a real SVG flow: a maker creates an offer, another person accepts, both approve their own actions, and both receive; a short branch shows that a refund might require waiting. Use a separate responsive rendering for small screens and provide a text alternative for assistive technology. State simply that creating or accepting an offer does not move funds. Do not draw a completed, automatic swap as a currently operational feature while the orchestration is incomplete.

Then establish a persistent, versioned swap session. Define a strict canonical format binding the immutable offer, reservation/session identifier, maker and taker identities, network, asset identifiers and exact base-unit amounts, claim/refund identities, hashlock, expiries, and chain references. Exchange signed or authenticated messages automatically, not in the user chat; verify the other party's authorization and all terms locally. Separate session retention from the offer listing lifetime. Add a D1 migration only if necessary, back up the database before applying it, and update both relay implementations and their tests together. Make replays, conflicting messages, stale sessions, relay equivocation and incomplete recovery fail closed.

Connect the session to an independently persisted client state machine and the existing per-chain checks and wallet-action functions. The owner is the long-leg funder and secret holder; the taker checks the long lock before funding the short leg. Apply the existing conservative timing policy to fresh chain heads before funding and before revealing a secret. Use the public action journal and durable local storage before requesting a signature. Observe or receive transaction references automatically but verify them on the actual chain; never expose a private secret in coordination. A wallet approval starts at most one transaction, and an unknown outcome remains unresolved until checked. The UI should direct a user to approve the next necessary action, explain when waiting or refunds apply, and preserve a recoverable session after reload.

Extend asset representations and verification through every layer instead of simply allowing token names: Ethereum needs native ETH and exact ERC-20/ERC-721/ERC-1155 details, Cardano needs the exact native-asset bundle and required ADA, Bitcoin only BTC and Hegemon only HGN. Exact on-chain integers must not be rounded. Add a private, explicit opt-in to connect a hosted page to a local Hegemon companion only if its exact origin and pairing capability are configured and the companion stays loopback-only. Preserve an honest unsupported state until each path is verified end-to-end.

## Concrete Steps

Work in the existing checkout, currently `/tmp/hegemon-swap-automation`, based on `origin/local-private-spend-htlc`. Before each source change, inspect the affected module and its tests. Run `node scripts/build_client_manifest.mjs` after changing browser files, then `node scripts/build_client_manifest.mjs --check`. Run focused `node --test ...` and `python3 -m unittest ...` suites with Node 24 and the isolated Python dependencies already present. For browser tests, temporarily link `/workspace/swap-ui-test/node_modules` as `swap-service/node_modules`, set `CHROMIUM_PATH=/usr/bin/chromium`, and remove that link afterward. Use disposable SQLite databases and local simulation or isolated chains; never contact the user's node or wallet.

Before deploying, explicitly stage only the intended files, check `git diff --check`, and push to `local-private-spend-htlc` without force. Back up remote D1 outside the repository with the already authorized Wrangler, capture Wrangler logs in mode-0600 files because an export may contain a temporary download URL, inspect the schema, and apply migrations before deploying. Do not change or commit any `.wrangler` directory. Finally run `NODE_USE_ENV_PROXY=1 node scripts/verify_hosted_client.mjs --base https://hegemon-swap-testnet.willdoyle422.workers.dev` and a read-only browser check.

## Validation and Acceptance

A clean browser should show the diagram and let either participant start. In two separate browser profiles, create and accept an offer, automatically exchange authenticated terms without writing a chat message, and see the correct action at each step. Approve each wallet request with disposable keys; neither party's wallet should be asked to sign early or twice. Follow a successful swap and a no-counterparty-funding refund, including a page reload and a relay disconnect. Verify transaction identifiers and balances independently on the isolated chains, and require that mismatched identity, altered terms, wrong network, unsafe deadline, missing chain data, unresolved prior submission, lost keys, and forged secret prevent the next action. Repeat for every claimed-supported chain and asset class. Any unsupported path must stop before funds are locked and say why.

Verify the SVG and its equivalent screen-reader description on desktop and a 390-pixel viewport. `make swap-test` is the fast suite; the multi-hour Hegemon test is out of scope. Any optional chain-tool test skipped must be recorded along with the reason, and simulated results must not be represented as live testnet evidence.

## Idempotence and Recovery

Creating an offer or a swap session and accepting a reservation must be idempotent or reconcile an uncertain response without making a second commitment. Persist the secret and terms before locking anything. Never retry a signing or broadcast on an unknown outcome. Participants must be able to export and restore the full swap recovery record without copying wallet private keys, and the relay must not have the power to discard locally held refund data. A browser that is closed cannot approve a wallet action: the UI must tell users when monitoring or a return is required. Restore or re-run tests only against disposable state.

## Artifacts and Notes

The live testnet URL is `https://hegemon-swap-testnet.willdoyle422.workers.dev/`. The existing branch tip at the start was `4011d58d`. The user's chosen signing model is explicit approval for each lock, claim and refund.

## Interfaces and Dependencies

Use the existing browser Web Crypto, Node 24 test runner, Chromium/Playwright, SQLite and Cloudflare D1. Reuse `swap-ui/identity.mjs`, the existing chain verifiers, `swap-ui/swap-flow.mjs`, `swap-ui/timelock-policy.mjs`, wallet action journals, and the loopback Hegemon companion; do not add a general-purpose backend that holds wallet keys. Keep relay protocol data bounded and versioned, and use authenticated canonical bytes instead of trusting free-form text or a relay-supplied status.

Revision note: initial plan records the chosen signing model and the architectural gaps found during source inspection.

Revision note: recorded the SVG milestone and its deliberately honest preview status before beginning the separate coordination changes.

Revision note: recorded the durable relay transport milestone and its limits; packet authenticity and the actual swap are still unimplemented.

Revision note: added and tested client-side authentication, encryption and recovery primitives, while preserving the explicit gap to real user-facing execution.

## Resume note: wallet approval and workspace interruption

The execution workspace stopped accepting command sessions after the client protocol work was pushed. The previous temporary worktree was lost when the environment restarted; the uncommitted Cardano edits and coordinator draft are not present in Git. The new checkout is `/tmp/hegemon-swap-automation`. The pushed branch through `afedeaad` contains the relay and protocol primitives, but not the draft coordinator or this Cardano fix. The Worker has the diagram update only; migration `0003_swap_sessions.sql` and the coordination primitives have not been deployed.

Before the interruption a local Cardano wallet change passed all 12 focused tests. It rechecked the chain head, the claim cutoff, and the escrow after a wallet signature returned, before asking the wallet to submit. It marked the action uncertain if that final check failed, because the wallet had seen the transaction and secret. It also allowed the coordinator to supply a final two-leg safety check. The exact uncommitted files may not survive the interruption: review, reimplement or recover them and run the tests again. The following records the relevant approach; it is a handoff sketch, not a committed or independently reviewed fix:

    // Add optional verifyBeforeSubmit to cardanoWalletAction's arguments.
    // Run after the wallet witness has been checked and before api.submitTx.
    if (op === 'claim') {
      try {
        const fresh = await read.params();
        if (!Number.isSafeInteger(fresh.slot) || fresh.slot + 5 < nowSlot) {
          throw new WalletError('Cardano chain view went backwards.', 'stale-head');
        }
        if (fresh.slot + params.claimMarginSlots >= expirySlot(t, params.systemStart)) {
          throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
        }
        claimOk();
        await verifyEscrow(terms);
        if (verifyBeforeSubmit !== undefined) {
          if (typeof verifyBeforeSubmit !== 'function') {
            throw new WalletError('The swap safety check is unavailable.', 'swap-check');
          }
          await verifyBeforeSubmit();
        }
        claimOk();
        const latest = await read.params();
        if (!Number.isSafeInteger(latest.slot) || latest.slot + 5 < fresh.slot) {
          throw new WalletError('Cardano chain view went backwards.', 'stale-head');
        }
        if (latest.slot + params.claimMarginSlots >= expirySlot(t, params.systemStart)) {
          throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
        }
      } catch (error) {
        await journal.uncertain(id);
        throw new WalletError(
          (error instanceof Error ? error.message : 'The claim safety check failed.')
            + ' The wallet signed, but this page did not submit; check the action record before retrying.',
          error instanceof WalletError ? error.code : 'swap-check',
        );
      }
    }

Include focused tests for delayed wallet approval crossing the cutoff, a rejected two-leg check, and a chain head reaching the deadline while checking. Each must leave the journal uncertain and never call this page's submit method. Also evaluate the disclosure risk: the wallet sees the secret when it receives the unsigned claim, and the page cannot guarantee when or whether a wallet broadcasts after it receives a transaction. Review equivalent timing behavior for the other chains.

The interrupted coordinator draft was incomplete and must not be treated as production-ready. In particular, strictly validate persisted states, in-flight actions, and outbox entries; bind the actual channel key to the signed channel digest; perform real Hegemon companion checks rather than accepting a Boolean assertion; and preserve single-action/write-ahead semantics across reload and concurrent tabs. Browser persistence, wallet integration, chain adapters, user-facing actions, and end-to-end/refund tests are still required.

Before any deployment, back up D1 outside the repository, inspect its schema, apply `0003_swap_sessions.sql` if absent, and regenerate/check the client integrity artifacts. Do not deploy the new Worker against an unmigrated database. Keep Hegemon wallet RPC on loopback and leave the user's node, wallets, and mining untouched.

Revision note: restored the branch into a separate checkout after the environment interruption and implemented a status-only, explicit hosted-to-loopback connection. The local companion requires the exact hosted origin and pairing token and cannot access a wallet in this mode. This milestone does not implement escrow observation, wallet approvals or automatic swaps; those remain open above.
