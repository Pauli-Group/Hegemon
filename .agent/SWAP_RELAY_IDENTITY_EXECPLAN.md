# Relay identity and client integrity (series plan P5)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agent/PLANS.md` and is part of the series described in `.agent/SWAP_SERIES_EXECPLAN.md` (plan 5 of 8). It builds on P1 (timelock policy), P2 (swap engine), P3 (hosted wallets) and P4 (public Bitcoin cases).

## Purpose / Big Picture

The hosted page is static JavaScript served by a Cloudflare Worker, and the offer relay (the same Worker plus a D1 database) carries two things a swap depends on: the offer owner's public inbox key (used to open an end-to-end encrypted conversation) and the reservation. Neither is authenticated today. A relay operator, or anyone who can change what the Worker serves, can (a) substitute the owner's inbox key and sit in the middle of the conversation, (b) substitute the escrow addresses the two parties agree on, and (c) ship modified page code that does anything it likes with a user's keys. Separately, the owner's inbox private key lives only in one browser's IndexedDB, so losing the browser profile loses the ability to open the conversation.

After this plan: each participant publishes a signed identity statement (a wallet signature over a canonical text naming the offer, the reservation, the inbox key fingerprint, and the claim and refund address for each leg) that the counterparty verifies locally; the pair check refuses to pass unless the escrows' claimant and refund addresses equal the signed identities; the owner's inbox key can be backed up under a passphrase and restored on a fresh browser profile; every file the hosted site serves is listed in a reproducible hash manifest, the page runs under a strict content security policy with subresource integrity, and `scripts/verify_hosted_client.mjs` compares the deployed site to the manifest from a verified checkout. Honest limits are written into the docs: a user's first load of the page is still trusted unless they run it from a checkout they verified, and a relay that invents a whole fake offer under its own identity is only caught if the counterparty confirms the owner's identity code through some channel other than the relay.

Terms. A *relay* is the Worker and D1. A *statement* is the canonical JSON the participant signs. A *proof* is one wallet signature over the statement text. The *identity code* is the first 16 hex characters of the SHA-256 of the canonical statement; two people can read it to each other to confirm they see the same statement. The *inbox fingerprint* is the SHA-256 of the raw 65-byte P-256 public key (`inboxFingerprint` in `swap-ui/public-inbox.mjs`).

## Progress

- [x] (2026-11-06) Survey code, write this plan (p5-execplan).
- [x] (2026-11-06) Identity statement format, per-chain proof verification, negative tests, shared vectors in JavaScript and Python (p5-identity).
- [x] (2026-11-06) Pair check requires escrow claimant and refund addresses to equal the signed identities; identities stored in the engine record (p5-pair).
- [x] (2026-11-06) Encrypted inbox key backup and restore, transactional, fail-closed; restore tested in a fresh browser profile (p5-backup).
- [x] (2026-11-06) Manifest, strict CSP, SRI, hosted verifier, tamper tests, browser enforcement test (p5-integrity).
- [x] (2026-11-06) Additive D1 migration, Worker and local relay changes, tests, `wrangler dev --local` run, deployment dry run, two-session browser test on both relays (p5-worker).
- [x] (2026-11-06) Documentation: swap-service README, DESIGN.md, METHODS.md, this plan (p5-docs).
- [ ] Master plan update and Revision from P5 in P6, P7, P8 (p5-revise).

## Surprises & Discoveries

- `wrangler` was not installed and `npx wrangler@4 --version` hung for minutes on the first fetch; a plain `npm install wrangler@4` into `/tmp` took three minutes. Its install scripts are not run by default under this npm, so `workerd` had no binary until `node node_modules/workerd/install.js` was run by hand. After that `wrangler dev --local` and `wrangler deploy --dry-run` both worked.
- The assets layer's default `html_handling` (`auto-trailing-slash`) would answer a request for `/hosted.html` with a redirect to `/hosted`, so the Worker's own fetch of its page file would not return bytes. `"html_handling": "none"` and `"not_found_handling": "none"` in `wrangler.jsonc` make the Worker the only thing that decides what is served.
- An apostrophe inside a single-quoted message string in `app.js` (“that chain's key”) was a syntax error, and the whole application then failed to start, which every browser test caught at once. Module syntax is now checked in `swap-ui/client-manifest.test.mjs` with `node --check`, because the unit tests never import `app.js`.
- Official BIP-322 vectors and an independent signer (embit) agree with the hand-built sighash used by the browser verifier; the Bitcoin proofs needed no new library beyond the vendored `btc-signer` bundle. Ethereum verification needed keccak-256, which was added to the vendored hash bundle, rebuilt reproducibly.
- The `anvil` binary the older browser tests expect lives at `/workspace/chain-tools/foundry/anvil`, which does not exist here. `swap-service/browser.test.mjs` passes its first test and then its second test crashes the Node process (known, left for P7).
- A route handler still running when Playwright `unroute` was called produced “Route is already handled” noise once under `wrangler dev`; `unrouteAll({behavior:'wait'})` fixed it.

## Decision Log

- Decision: one canonical text, many wallets. The signed text is `hegemon.swap.identity.v1\n` followed by the canonical JSON (sorted keys, no spaces, same rule as the engine's `terms_digest`). Ethereum signs it with `personal_sign` (EIP-191), Cardano with CIP-30 `signData` (CIP-8 COSE_Sign1, payload = the UTF-8 bytes unhashed), Bitcoin with BIP-322 "simple" for P2WPKH or the legacy/BIP-137 compact message signature, whichever the user's wallet can produce. EIP-712 is not used: it needs typed-data support that Cardano and Bitcoin wallets lack, and one text keeps the vectors small. Reason: independent verification in JavaScript and Python with libraries already in the tree.
- Decision: the signer must be one of the statement's own addresses, and every proof must verify. A statement lists the participant's address for each leg; a proof from chain C is accepted only if its signer equals the statement's address on chain C. Addresses on chains with no proof are reported as "asserted", not "proven". This is honest about what a single wallet signature establishes; the UI offers a proof per chain.
- Decision: the engine identity strings (P2) are the statement's address format: Bitcoin compressed public key hex, Ethereum lowercase `0x` address, Cardano 56-hex payment key hash. Hegemon legs carry the literal `pending`; the pair check reports Hegemon identity as unverified and never passes it as verified (P6 and P8 define the real scheme).
- Decision: the owner signs an offer-level statement (reservation is the empty string) because the offer id exists only after the relay creates it and takers need the owner's identity before reserving. The taker signs a session-level statement that binds the reservation id and the taker's ephemeral session key fingerprint. Replaying either on another offer or another reservation fails because those fields are in the signed text.
- Decision: the relay stores the signed blobs (D1 columns `owner_identity` and `reservation_identity`) but is not trusted with them. It validates only structure and size and that the offer and reservation ids inside match the row. Clients verify signatures and bindings themselves. Statements travel in the relay record rather than the encrypted chat so a taker can check the owner before reserving.
- Decision: a relay that fabricates a whole offer under its own identity is only detected by an out-of-band check. The page pins the owner's identity code per offer on first sight (trust on first use), accepts an expected code in the share link (`#<offer>.<message key>.<identity code>`) and shows the code for reading aloud. Anything stronger needs an identity system outside this plan.
- Decision: the inbox key backup is made at creation. A WebCrypto key that is generated non-extractable can never be exported, and a key that can be exported later is equivalent to a readable key for any code that runs in the page. So the owner's inbox key is generated extractable, its PKCS#8 bytes are optionally sealed under a passphrase at that moment, and the copy stored in IndexedDB is re-imported non-extractable. Keys created before this change cannot be backed up; the UI says so and offers a new key. The envelope is the same PBKDF2-SHA256 (600000 iterations) and AES-256-GCM design as `recovery.mjs`, with additional data binding the public key.
- Decision: restore verifies that the backed-up private key really matches the public key in the envelope (an ECDH cross-check with a fresh ephemeral key), refuses to overwrite a different key stored under the same public key, and writes in one IndexedDB transaction like `vault-store.mjs`.
- Decision: serve a pre-rendered hosted page instead of rewriting `index.html` at the edge. The Worker used `HTMLRewriter` to flip the page into hosted mode, which makes the served bytes impossible to reproduce without the Cloudflare runtime. `scripts/build_client_manifest.mjs` now renders `swap-ui/hosted.html` from `index.html` with the same declared edits, checks that every edit matched exactly once, and the Worker serves that file for `/` and `/index.html`. The manifest therefore lists the exact served bytes, and there is no rewrite code left to trust.
- Decision: integrity uses an import map with an `integrity` table (Chromium 127+ and Firefox 138+ enforce it; other browsers ignore it silently, which the docs say) plus `integrity` on the stylesheet. The import map is the only inline script block; the CSP allows it by hash (`script-src 'self' 'sha256-...'`), and `style-src 'self'`. SRI protects against partial or cached tampering; it cannot protect against an attacker who controls the whole origin, which is why the out-of-band verifier exists.
- Decision: the D1 change is additive (two `ALTER TABLE ... ADD COLUMN` statements in `swap-service/cloudflare/migrations/0002_identity.sql`) and is applied before the Worker deploy; `schema.sql` carries the columns for fresh databases. The local relay (`server.ts`) already migrates additively with `PRAGMA table_info` and gets the same columns the same way.

## Outcomes & Retrospective

Everything in the plan's scope is implemented and tested except two things that need an operator: deploying the new Worker and applying the D1 migration to the real database. Acceptance results:

- Substituted inbox key, substituted identity, forged taker statement and replayed statement are detected in the two-session browser test (`swap-service/identity-browser.test.mjs`) against both the local relay and the real Worker in `wrangler dev --local` with local D1; forcing the page's block decision to false makes the test fail.
- The pair check refuses to run without signed identities and throws when an escrow's claimant or refund differs from them (every differing address; `swap-ui/identity-pair.test.mjs`, Python `test_identity.py`).
- The verifier reports a modified module, a modified root, a changed timing file, a missing file, a weakened or removed CSP, a served test file and a served source file, and a page that references something outside the manifest. It passes the real Worker in workerd with 107 checks, and passes the local relay.
- The browser refuses to start the application when `pair-check.mjs`, `identity.mjs`, `vendor/hash.mjs` or `app.js` differs from the manifest by one byte.
- An inbox key restores in a fresh browser profile as a non-extractable key; a corrupted envelope, a wrong passphrase, a swapped public key and a conflicting stored key all fail closed and store nothing.

Honest limits, stated in the docs: first-load trust, trust on first use for the owner's identity unless the code is checked another way, Bitcoin signatures are pasted from a wallet and only P2WPKH keys are accepted, keys created before this change cannot be backed up, import-map integrity is enforced only by newer browsers, the local regtest pair check does not require identities, Hegemon identity is `pending`. What I would do differently: build the manifest check into the first commit of the UI work; every later edit to a served file now needs a rebuild, and forgetting it breaks the page by design.

## Context and Orientation

The page lives in `swap-ui/` (plain ES modules, no bundler; vendored bundles in `swap-ui/vendor/` are built by `swap-service/vendor-src/build.mjs`). Inbox crypto is `swap-ui/public-inbox.mjs` (P-256 ECDH plus HKDF plus AES-GCM; the owner key is in IndexedDB database `hegemon.local.offer-inbox.v1`). `swap-ui/recovery.mjs` and `swap-ui/vault-store.mjs` are the models for the backup envelope and the transactional store. The pair check is `comparePair` in `swap-ui/pair-check.mjs`, called by `checkPublicPair` in `swap-ui/public-pair.mjs` and by the local pair check in `swap-ui/app.js`. Escrow terms name the participants as: Ethereum `claimant` and `refundee` (addresses), Bitcoin `claimant_key` and `refund_key` (compressed public keys), Cardano `claimant` and `refundee` (payment key hashes), Hegemon not yet defined.

The relay: `swap-service/cloudflare/worker.mjs` with `schema.sql` (D1 `hegemon-swap-testnet`), and `swap-service/server.ts` (local SQLite, serves the page with a hand-maintained allow-list and its own CSP). Both implement `/offers`, `/offers/:id/{reserve,messages,close}`. Worker tests use Node 24's in-memory SQLite behind a D1-shaped adapter (`swap-service/cloudflare/worker.test.mjs`). Wrangler is not installed on this machine; the deployment dry run is attempted with a pinned `npx wrangler` and is otherwise documented for the operator.

Roles in an offer. The owner's `give` leg is the leg the owner funds (owner refunds, taker claims); the owner's `receive` leg is funded by the taker (taker refunds, owner claims). The statement for role owner therefore names `give.refund` and `receive.claim`; for role taker, `give.claim` and `receive.refund`.

## Threat model

Assets: the owner's inbox private key, each party's claim and refund addresses, the preimage (never sent to the relay), and the page code that handles keys.

- Relay operator (Worker owner, D1 reader or writer). Can read offers and ciphertext, drop, delay, reorder or replay messages, substitute `ownerPublicKey`, substitute or delete identity blobs, and create fake offers. Defence: identity statements bind the inbox fingerprint, offer id, reservation id and addresses under a wallet signature, so substituting any of them under a known identity is detected; escrow addresses are checked against the signed identities. Not defended: a relay that presents a complete fake offer with its own wallet, unless the counterparty confirms the identity code out of band (pinned code in the link, or read aloud); denial of service; traffic analysis.
- Network attacker (no relay access). TLS is the first defence. The page and the statements add: a man in the middle who can serve a different relay response is in the same position as the relay operator above. Chain data goes through the read proxies and is checked by the page's own verifiers (P3, P4); not changed here.
- Malicious counterparty. Can sign a statement naming addresses it does not control (only harms itself, because escrow terms must equal what it named), replay an old statement of its own (offer id, reservation id and expiry are signed), or claim an address on a chain it never proved ("asserted", shown as such). Cannot reuse the other party's statement on another reservation. Not defended: a counterparty who never funds.
- Compromised CDN or hosting account. Can serve modified JavaScript and a modified manifest. Defence: the hosted verifier run from a separate, verified checkout (compares every served file, the CSP and the timing file to the repository), reproducible hashes, SRI and CSP limiting what a partial compromise can load. Not defended: a first load by a user who runs no verifier, because the attacker controls the code that would do the checking; the docs say so and recommend running the page from a verified checkout (`node swap-service/server.ts`) for real value.

## Plan of Work

1. `swap-ui/identity.mjs`: build, canonicalise, parse and verify statements; `swap-ui/identity-proofs.mjs`: Ethereum, Cardano and Bitcoin proof verification using `vendor/hash.mjs` (add keccak-256) and `vendor/btc-signer.mjs` (secp256k1), `cbor.mjs`. `scripts/swap_engine/identity.py` verifies the same statements in Python (`eth_account`, `embit`, `nacl`, `cbor2`) so the engine record only stores identities the engine itself verified. Vectors in `config/swap/identity-vectors.json` are produced by `scripts/make_identity_vectors.py` with independent signers and checked by both languages.
2. `comparePair(offer, give, receive, timing, identities)`: when `identities` is given, both statements must match the offer id, the roles, the legs' chains, and each escrow's claimant and refund must equal the statement addresses; mismatch throws. The public pair check and the app require identities.
3. `swap-ui/inbox-backup.mjs` plus changes to `public-inbox.mjs`: `createInbox({passphrase})`, `backupInbox`, `restoreInbox`.
4. `scripts/build_client_manifest.mjs` (render `hosted.html`, import map, `client-manifest.json`, generated CSP constants), `scripts/verify_hosted_client.mjs`, Worker and `server.ts` headers.
5. Schema migration, one Worker route, `POST /offers/:id/identity` (owner body `{identity}`; reservation holder body `{identity, reservationId}`), with single-statement guards, presentation fields `ownerIdentity` and `reservationIdentity`, same for `server.ts`.
6. UI section "Identity" in `index.html` and `swap-ui/identity-ui.mjs`; the board shows the counterparty's identity code, proven and asserted chains, and a loud failure if the inbox key or identity does not match.
7. Browser test `swap-service/identity-browser.test.mjs`: two sessions through a relay stub that substitutes the inbox key and, separately, the identity; both substitutions must be detected.
8. Docs and later-plan revisions.

## Concrete Steps

Run from the repository root with Node 24 (`export PATH=$HOME/.local/opt/node-v24.22.2-linux-x64/bin:$PATH`) and Python with `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python`.

    node --test swap-ui/*.test.mjs swap-service/cloudflare/worker.test.mjs
    (cd scripts && python3 -m unittest swap_engine.test_identity)
    node scripts/build_client_manifest.mjs --check
    CHROMIUM_PATH=/snap/bin/chromium node --test swap-service/identity-browser.test.mjs
    node scripts/verify_hosted_client.mjs --base http://127.0.0.1:8787

## Validation and Acceptance

- Substituted inbox key or identity detected in the two-session browser test.
- Pair check fails when an escrow's claimant or refund differs from the signed identity (every differing address).
- Verifier flags any modified served file, an added file, a missing file, a changed header or a changed `chain-timing.json`.
- Inbox key restores on a fresh browser profile and opens the real handshake; wrong passphrase, corrupted envelope and conflicting key all fail closed.
- Negative tests: wrong chain, wrong offer, replay on another reservation, substituted inbox key, expired statement, signer not in the statement, tampered address.

## Idempotence and Recovery

The migration is applied once (`ALTER TABLE ADD COLUMN` fails if repeated; the runbook checks `PRAGMA table_info(offers)` first). Back up D1 before migrating: `wrangler d1 export hegemon-swap-testnet --remote --output backup.sql`. The manifest builder is deterministic and `--check` never writes. If the Worker is deployed before the migration, reservations fail (the reserve statement writes `reservation_identity`) and identity routes fail, so migrate first; the runbook is in `swap-service/README.md`.

## Artifacts and Notes

- `node scripts/build_client_manifest.mjs --check` prints `client manifest and generated files match a fresh build`.
- `node scripts/verify_hosted_client.mjs --base http://127.0.0.1:8799` against `wrangler dev --local` (wrangler 4.158.0, workerd 1.20261104.1, local D1 created from `schema.sql`): `OK: 107 checks, 0 failed (45 files, profile hosted)`. `/hosted.html` and `/client-manifest.json` answer 200; `/server.ts` and `/identity.test.mjs` answer 404.
- Migration path tested on local D1: the previous `schema.sql` (from `git show HEAD:...`) had no `owner_identity`; after `migrations/0002_identity.sql` both new columns were present.
- `wrangler deploy --dry-run --outdir`: bindings `env.DB (hegemon-swap-testnet)` and `env.ASSETS`, no `HTMLRewriter` left in the bundle, Worker bundle about 46 KB. This was a dry run: nothing was deployed and no remote database was touched. The operator deploys with the order in `swap-service/README.md`.
- Test counts at the end: Node `swap-ui/*.test.mjs` plus Worker and relay tests 177 passing; Python `swap_engine` 129 passing (4 skipped); browser tests `identity-browser` (2), sepolia, guided, observer, timing, Cardano wallet, Bitcoin wallet and Sepolia claim all passing. The anvil-based second test in `browser.test.mjs` still fails on this machine (no anvil at `/workspace`).

## Interfaces and Dependencies

- `buildStatement({role, offer, reservation, inbox, legs, nonce, issued, expires})`, `statementText(statement)`, `parseIdentity(blob)`, `verifyIdentity(blob, expected, now)` returning `{statement, code, proven, asserted}` and throwing on any mismatch.
- `comparePair(offer, give, receive, timing, identities)`.
- `createInbox({passphrase})`, `backupInbox(publicKey)`, `restoreInbox(envelope, passphrase)`.
- Python `swap_engine.identity.verify_identity(blob, expected, now)`.
- New vendor export: `keccak_256` in `swap-ui/vendor/hash.mjs`.
