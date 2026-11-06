---
name: P5 Relay identity integrity
overview: Plan 5 of 8. Authenticate counterparties with wallet signatures, back up inbox keys, and make the hosted client code verifiable so a malicious relay cannot silently substitute keys or JavaScript.
todos:
  - id: p5-execplan
    content: Write .agent/SWAP_RELAY_IDENTITY_EXECPLAN.md with threat model
    status: pending
  - id: p5-identity
    content: Signed identity statements with per-chain verifiers and negative tests
    status: pending
  - id: p5-pair
    content: Extend pair check to bind escrow addresses to signed identities
    status: pending
  - id: p5-backup
    content: Encrypted inbox key backup and restore
    status: pending
  - id: p5-integrity
    content: Build manifest, CSP, SRI and verify_hosted_client script
    status: pending
  - id: p5-worker
    content: Additive D1 migration, Worker changes, tests and deploy dry run
    status: pending
  - id: p5-docs
    content: Update README, DESIGN.md, METHODS.md
    status: pending
  - id: p5-revise
    content: Revise plans P6 and P7 based on what was learned
    status: pending
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

## Last step: revise later plans

Update the master ExecPlan and edit P6 and P7:
- P6: the shape of the Hegemon identity field and what the adapter must provide.
- P7: new commands, the manifest/release process and doc updates, and whether the relay change needs its own PR.
