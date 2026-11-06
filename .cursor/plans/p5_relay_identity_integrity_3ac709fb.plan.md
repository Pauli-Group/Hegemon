---
name: P5 Relay identity integrity
overview: Plan 5 of 8. Authenticate counterparties with wallet signatures, back up inbox keys, and make the hosted client code verifiable so a malicious relay cannot silently substitute keys or JavaScript.
todos:
  - id: p5-execplan
    content: Write .agent/SWAP_RELAY_IDENTITY_EXECPLAN.md with threat model
    status: completed
  - id: p5-identity
    content: Signed identity statements with per-chain verifiers and negative tests
    status: completed
  - id: p5-pair
    content: Extend pair check to bind escrow addresses to signed identities
    status: completed
  - id: p5-backup
    content: Encrypted inbox key backup and restore
    status: completed
  - id: p5-integrity
    content: Build manifest, CSP, SRI and verify_hosted_client script
    status: completed
  - id: p5-worker
    content: Additive D1 migration, Worker changes, tests and deploy dry run
    status: completed
  - id: p5-docs
    content: Update README, DESIGN.md, METHODS.md
    status: completed
  - id: p5-revise
    content: Revise plans P6 and P7 based on what was learned
    status: completed
isProject: false
---

# Plan 5 of 8: Relay identity and client integrity

Depends on P2 (record fields) and P3 (libraries, signing hooks). Feeds P7.

## Gaps being closed (from `swap-service/README.md`)

- Participants are not authenticated; the pair check does not establish participant addresses.
- A malicious relay can substitute inbox keys or serve modified JavaScript.
- The owner's non-extractable inbox key is local to one browser and not backed up.
- Hegemon has no identity binding yet.

## Design

1. Wallet-bound identities. Each participant signs an identity statement with a key on a chain they use in the swap: Ethereum `personal_sign`/EIP-712, Cardano CIP-30 `signData` (CIP-8), Bitcoin BIP-322 (or message signing where wallets support it). The statement binds: offer ID, reservation ID, inbox public key fingerprint, the participant's claim and refund addresses per leg, a nonce and an expiry. Counterparty clients verify signatures locally; the relay is not trusted for correctness. The relay may verify too, only for spam control.
2. Pair check extension. `comparePair` additionally requires that each escrow's claimant and refund addresses equal the signed identities, closing the "does not authenticate participant addresses" gap. The P2 record stores the verified identities.
3. Inbox key backup. Export/import the P-256 inbox private key encrypted with a passphrase (PBKDF2/AES-GCM, as in `swap-ui/recovery.mjs`), using the transactional vault in `swap-ui/vault-store.mjs`, with the same fail-closed corruption behaviour.
4. Client integrity. Produce a reproducible build manifest of every served file (SHA-256), served with strict CSP, no inline scripts, and Subresource Integrity for all modules and vendored libraries from P3. Add `scripts/verify_hosted_client.mjs` that fetches the deployed site and compares it to the manifest published in the repo and release notes. State the residual risk honestly: first-load trust remains; offer an option to run the same bundle locally from a verified checkout.
5. Worker changes. Additive D1 migration (back up first; no destructive statements) for signed identity blobs on offers and reservations; atomic single-statement checks preserved; update `swap-service/cloudflare/worker.mjs` and tests.
6. Hegemon: reserve a field and document that identity for the Hegemon leg is pending until a testnet and key scheme are available; do not fake it.

## Steps

1. Read P2/P3 outcomes; write `.agent/SWAP_RELAY_IDENTITY_EXECPLAN.md`; write a short threat model (relay operator, network attacker, malicious counterparty, compromised CDN) in the ExecPlan.
2. Implement the signature statement format, verifiers per chain and negative tests (wrong chain, wrong offer, replay on another reservation, substituted inbox key, expired statement).
3. Extend pair check and the guided flow; browser tests with two sessions and a substituting relay stub that must be detected.
4. Inbox key backup and restore tests including corrupted and conflicting imports.
5. Manifest, CSP, SRI and the verifier script; test that a tampered file is detected.
6. Worker migration, tests on Node 24 with the in-memory SQLite adapter, then `wrangler dev --local`, then the hosted deployment with a dry run first.
7. Update `swap-service/README.md`, `DESIGN.md`, `METHODS.md`; follow `BRAND.md` for UI.

## Acceptance

- A relay that substitutes an inbox key or an identity is detected in a two-session browser test.
- A pair check fails if escrow addresses differ from signed identities.
- The verifier script flags any modified served file.
- Inbox key restores on a fresh browser profile.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- The deployed Worker already sets a CSP (`default-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`), `x-content-type-options: nosniff`, `cache-control: no-store` and `referrer-policy: no-referrer`. Extend these with Subresource Integrity and a manifest rather than starting from none.
- The served root page is the repository `swap-ui/index.html` after the Worker's `HTMLRewriter`, and `/index.html` redirects (HTTP 307). The manifest and `verify_hosted_client` script must hash the rewritten root exactly as served (or have the Worker emit a pre-rewritten static page), and must treat the rewrite code in `swap-service/cloudflare/worker.mjs` as part of the trusted bundle.
- Baseline fact for the verifier's first test: served `app.js`, `style.css` and `crypto.mjs` currently match the repository byte for byte.

Revision from P1 (2026-11-05):
- The timing policy is served by the same operator as the page: `swap-ui/timelock-policy.mjs` and `swap-ui/chain-timing.json` can be substituted exactly like `app.js`. Include both in the verifiable-client manifest P5 designs, and add a check that the served `chain-timing.json` equals the pinned copy.
- Provider-trust incidents to surface: the public Sepolia RPC reported a head block 95 seconds old; the policy only tolerates a head older than 600 seconds plus clock skew (code `clock-drift`) and assumes Bitcoin and Hegemon providers may be two blocks behind. A relay or verifier that sees a head older than those limits should say so rather than guess.
- Identity fields are unchanged by P1, but the record should bind the expiry unit and chain head each side verified against, so a later dispute can recompute the verdict.

Revision from P2 (2026-11-06):
- A relay or offer must carry exactly what the engine needs to start a side: the terms (`version`, `hashlock`, per-leg `chain, amount, refundee, claimant, expiry`) and, later, each side's escrow reference. Identities are chain-specific strings (Bitcoin compressed pubkey hex, Ethereum lowercase address, Cardano 56-hex key hash); the engine refuses to act if its wallet does not match, so bind the offer's signature to these exact strings and to `terms_digest` (sha256 of canonical JSON with sorted keys and no spaces; the swap id is its first 16 hex characters).
- The relay must never carry a preimage. The initiator's preimage stays in the 0600 `secret` file; the responder learns it from the chain. A relay that echoes a preimage is a defect.
- Escrow references are untrusted input to `engine.receive`; the engine records them and then verifies the on-chain escrow against the agreed terms before relying on them. Integrity pinning should make that verification path (adapters and the Cardano and Ethereum verifiers) part of what a user can check, not just the page bundle.
- The planner is part of what protects a user: expiries come from `planner.plan_with_margin`. A relay that lets either party propose arbitrary expiries must have the engine's policy check (`check_ordered`) re-run by both sides before funding; the engine does this and aborts, with nothing funded, on a deterministic policy failure.

Revision from P3 (2026-11-06):
- Files the page now loads that must be covered by the integrity manifest (all under `swap-ui/`): the vendored bundles `vendor/btc-signer.mjs` and `vendor/hash.mjs` (with `vendor/MANIFEST.json` and `vendor/SHA256SUMS` already recording the npm integrity of `@noble/curves` 2.4.0, `@noble/hashes` 2.4.0, `@scure/base` 2.4.0 and `@scure/btc-signer` 2.4.1), the new modules `cbor.mjs`, `cardano-tx.mjs`, `cardano-wallet.mjs`, `cardano-ui.mjs`, `bitcoin-psbt.mjs`, `bitcoin-wallet.mjs`, `bitcoin-ui.mjs`, `observers.mjs`, `observer-ui.mjs`, `swap-flow.mjs`, `guided.mjs`, `guided-ui.mjs`, `timelock-policy.mjs` and `action-journal.mjs`, and the data files `cardano-htlc-script.json`, `ether-escrow-template.json`, `token-escrow-template.json` and `chain-timing.json`. The page is made of ES modules imported at run time, so a `<script integrity>` attribute covers only the first file; use an import map with an `integrity` section (supported by current Chromium) or a single bundle. `swap-service/server.ts` keeps a hand-maintained allow-list that must be extended with every new module, and `swap-ui/chain-timing.json` must equal `config/swap/chain-timing.json`.
- Signing hooks P5 can use: the Cardano wallet interface already exposes `signTx` and `submitTx`; CIP-30 `signData(address, payload)` is not used by P3 and is the right primitive for binding an offer to a Cardano identity (the returned COSE_Sign1 and key can be checked with the vendored `ed25519` and `blake2b`, and `blake2b-224(public key)` is the 56-hex key hash the engine's terms use). Ethereum: P3 uses only `eth_sendTransaction`; `personal_sign` or EIP-712 for identity needs a new verifier (`secp256k1` is exported by `vendor/btc-signer.mjs`; keccak-256, which Ethereum address derivation and message hashing need, is not bundled and would have to be added to `swap-service/vendor-src/entry-hash.mjs`). Bitcoin: the PSBT path has no message signing; bind identity by having the key sign a throwaway PSBT that spends a nonexistent output, or by BIP-322 if a verifier is added.
- Provider-trust incidents seen while building and qualifying P3, which the relay or verifiers should surface to the user: Koios returns `[]` for confirmed transactions while a backend lags; Blockstream and mempool.space briefly reported different blocks at height 158793 during the earlier public Bitcoin cases; publicnode caps `eth_getLogs` at 50000 blocks and its load-balanced backends can briefly report a fresh contract as absent; the Worker's Bitcoin reads reported `unavailable or inconsistent` from a local host until Node's connect timeout was raised. The page currently turns a bytecode read mismatch into one generic message; P5 may want to distinguish "provider disagrees" from "terms differ".
- The Worker's new read routes (`/bitcoin-testnet4/*`, `/sepolia/rpc`, `/sepolia/escrow-events`, `/cardano-preview/*`) are unauthenticated and rate-limited per IP only (180 reads and 40 writes a minute); `POST /bitcoin-testnet4/broadcast` relays any transaction the caller supplies to a public service, so P5's abuse budget and logging should include it.

Revision from P4 (2026-11-06):
- P4 found nothing to resume: all four Bitcoin swaps and the refund had completed on 2026-11-04, and `scripts/verify_public_btc_cases.py` re-verified them from raw bytes. The pattern P5 should copy for relay and verifier trust: read Bitcoin from two providers that each pass the testnet4 genesis check and require agreement on block hash and height (this time they agreed), say plainly when a chain has only one provider (Cardano via Koios only), and treat an empty or partial answer for confirmed data as unavailable, not as absent (Koios returned fewer transactions than asked for on the first attempt; the verifier now asks per transaction and retries). The primary public Sepolia RPC had pruned the receipts of the oldest transactions, so history needs a second source (Blockscout) and the relay should show which source answered.
- Testnet4 block header times are not a reliable clock and a Bitcoin transaction's first-seen time is not kept once it confirms, so the order of a Bitcoin confirmation against another chain's event cannot be recovered afterwards. Offers and observations that the relay stores should carry the observer's wall-clock time and the chain head observed, as the engine journal does.
- Anything that can create an escrow must persist the full terms and hashlock before funding: a P2WSH output can be spent or refunded only with its witness script, and two 20,000-sat qualification escrows are permanently unrecoverable because the browser sessions that knew their hashlocks were discarded. A relay offer record that carries the exact script terms would have prevented that; make that a required field, not an optional one.

## Last step: revise later plans

Update the master ExecPlan and edit P6 and P7:
- P6: the shape of the Hegemon identity field and what the adapter must provide.
- P7: new commands, the manifest/release process and doc updates, and whether the relay change needs its own PR.
