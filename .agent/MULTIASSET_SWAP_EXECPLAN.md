# Build the multi-asset swap prototype

This living plan follows `.agent/PLANS.md`. The objective is a noncustodial local-network prototype with Ethereum ETH, ERC-20, ERC-721 and ERC-1155, Cardano ADA and native assets, Bitcoin BTC and Hegemon HGN. Users create public or private offers and claim or refund their own escrows from desktop or browser. Secrets and signing remain local. The current harness in `scripts/local_multichain_htlc_swap.py` demonstrates HGN/ETH and HGN/ADA only and is not an application.

## Progress

- [x] (2026-11-02) Inspected existing contracts, local harness, wallet architecture and repository instructions.
- [x] (2026-11-02) Implemented ERC-20, ERC-721 and ERC-1155 token escrow and 11 local fixture tests; the existing 9 native ETH tests also pass.
- [x] (2026-11-02) Added receiver interface and reentrant funding tests. All six Ethereum token fixture claim/refund local-chain paths passed. A direct ERC-20/Cardano-native-token swap passed on isolated nodes.
- [x] (2026-11-02) Hegemon/ERC-20 and Hegemon/Cardano-token local happy paths passed; additional local happy paths passed for BTC/ERC-20, BTC/Cardano tokens, ERC-20/Cardano tokens, and same-chain token swaps on Ethereum and Cardano.
- [ ] Cover arbitrary user-selected assets, failure and recovery across every pairing, and connect the real wallet flows.
- [x] (2026-11-02) Added local Cardano fixture minting, HTLC claim and refund for a fungible token and one-of-one token; both passed on fresh isolated nodes.
- [ ] Generalize Cardano token inputs for real user-selected assets and add same-chain and Hegemon-linked end-to-end cases.
- [x] (2026-11-02) Implemented a source-pinned read-only local Ethereum escrow verifier for ETH and standard token kinds; tested on local Anvil and in Chromium.
- [x] (2026-11-02) Added local Bitcoin script/UTxO verification with confirmation checks and Cardano pinned-validator/datum/value snapshot verification; altered and spent outputs were rejected. Cardano confirmation history is not available from the chosen UTxO query.
- [x] (2026-11-02) Added and exercised the Hegemon wallet-side terms checker and read-only companion with terminal approval, including a declined request.
- [x] (2026-11-02) Added a local deadline-only watch with persisted metadata and per-chain genesis binding; it does not monitor spends or act on behalf of users.
- [x] (2026-11-02) Added a browser-local encrypted preimage backup with explicit import/export, passphrase verification, corrupt-storage protection and cross-tab serialization. This is not a complete swap recovery record.
- [x] (2026-11-02) Built and exercised local Anvil deployment primitives for native ETH, ERC-20, ERC-721 and ERC-1155. The companion checks a non-forked local chain anchor; deployment returns an unconfirmed transaction ID. Token contracts need separate approval and funding.
- [x] (2026-11-02) Tested experimental manual Hegemon actions through a locally approved companion, including ordinary transfer, lock, submit, claim and refund on fresh isolated chains.
- [x] (2026-11-02) Implemented separate local token approval and funding actions with pinned runtime and term checks, call simulation, stale-head rejection and distinct transaction confirmations. Exercised all three fixture token kinds and the ERC-20 browser path.
- [x] (2026-11-02) Added a manually approved local Ethereum refund after expiry; fresh ETH and token fixture rehearsals reject early and repeated refunds.
- [x] (2026-11-02) Added local Ethereum claims using an encrypted preimage backup, with an explicit warning before the wallet receives the preimage; the other leg is not automatically verified.
- [x] (2026-11-02) Added optional local Bitcoin Core lock, claim and refund actions, with explicit terminal approval and a synthetic refund signing check before funding; the peerless companion rehearsal passed.
- [x] (2026-11-02) Added optional local Cardano CLI lock, claim and refund actions for exact ADA/native-asset bundles with a locally configured payment key, node-identity checks and terminal approval; companion rehearsals passed.
- [x] (2026-11-02) Added manual local preimage observers for Bitcoin, Ethereum, Cardano and Hegemon with encrypted browser-compatible backups; local chain tests passed.
- [x] (2026-11-02) A BTC/Cardano fixture swap used local companion actions and recovered the Cardano claim preimage from confirmed block data before claiming BTC.
- [x] (2026-11-02) Added a public-term browser action journal before wallet requests, with uncertain outcomes, export/import and fail-closed transactional storage; it does not contain wallet recovery material.
- [x] (2026-11-02) Added a manual two-leg offer comparison against independently queried local escrow snapshots, with explicit limitations on timing, participant identity and Cardano confirmation depth.
- [ ] Implement a complete cross-chain coordinator and end-to-end recovery. These manual actions do not coordinate a swap.
- [ ] Implement a resilient pairwise transaction protocol, wallet signing, actual spend monitoring and full swap recovery.
- [x] (2026-11-02) Added a loopback TypeScript/SQLite prototype relay for public/private offers, exclusive reservations and opaque messages; HTTP/restart test passed.
- [x] (2026-11-02) Added a local browser offer board and AES-GCM encrypted shared-link message prototype; crypto, HTTP and two-session Chromium tests pass.
- [x] (2026-11-02) Added read-only Ethereum EIP-1193 and Cardano CIP-30 connection buttons and exercised them with mocked browser providers.
- [x] (2026-11-02) Added an isolated Electron window for the local offer board; typecheck, build, sandbox policy tests and a virtual-display window test passed.
- [x] (2026-11-02) Enabled encrypted conversation setup for new public offers without a private link, using a per-offer non-extractable inbox key and reservation-bound ephemeral ECDH.
- [ ] Implement authenticated counterparty identities, full wallet transaction interfaces and deployment hardening. The relay can substitute inbox keys or client code, and the inbox private key is not backed up.
- [ ] Exercise local-network end-to-end swaps and document remaining limitations.

## Surprises & Discoveries

Foundry prank affects the next external call, including the SHA-256 precompile; computing the digest before setting the prank fixed the test fixture sender. The current Hegemon tests invoke `private-spend` as an interactive local executable; no app-level swap API is presently exposed. Hegemon proof generation needs substantial memory and time, which must affect timeout margins and interface design.

## Decision Log

Use independent per-offer Ethereum token escrow instances, with exact ERC-20 balance checks, rather than extending the existing native ETH escrow. Keep the existing ETH contract and tests unchanged. Tokens with unexpected transfer quantities must fail. NFT contracts can have arbitrary issuer behavior, so successful interface checks do not guarantee token safety.

## Outcomes & Retrospective

The independent Ethereum token escrow and local Cardano fixture transactions work, and the browser board supports local manual wallet actions and encrypted offer messaging. Full coordinated swaps, authenticated participant identities, complete recovery and production deployment remain unfinished. Local fixture happy paths cover every pair of the four chains and both Ethereum and Cardano same-chain token swaps; public inbox and shared-link messages do not authenticate participants or protect against a malicious server delivering substituted keys or changed client code. No production readiness or deployment is asserted.

## Context and Orientation

`contracts/ethereum/HegemonHTLC.sol` is the existing native ETH escrow. `contracts/cardano/validators/htlc.ak` is the existing Aiken validator. `scripts/htlc_counterpart.py` owns local-chain harness adapters. `hegemon-app` is a React/Electron wallet. The local development tools reside in `/workspace/chain-tools`. All test networks must remain isolated; never start public synchronization.

## Plan of Work

First add a separate Ethereum token escrow for standard fungible and nonfungible interfaces, with a funded state, exact quantities, claimant and refundee, SHA-256 32-byte secret and deadline. Add unit tests covering funding, claim, refund, wrong secrets, unauthorized parties, transfer fees, callbacks and repeated spends. Then adapt the Cardano harness to build UTxOs with explicit policy IDs, asset names and quantities and verify their outputs. Implement the application and service only after the swap state machine verifies real chain state, securely stores recovery data and uses local signing. Build a small TypeScript/SQLite service for untrusted public offers and private coordination without secret custody. Reuse the existing desktop app and provide a browser client with authenticated local companion access for Bitcoin and Hegemon. Complete real multi-chain tests, including offline recovery and service interruption.

## Concrete Steps

From the repo root run `/workspace/chain-tools/foundry/forge test --root contracts/ethereum --use /workspace/chain-tools/solc -vv` and expect all tests to pass. Run the Aiken tests using `/workspace/chain-tools/aiken/aiken-x86_64-unknown-linux-musl/aiken check contracts/cardano`. Run `python3 scripts/check_cardano_token_htlc.py --output /absolute/new/short-path` for actual token claim and refund; its two scenarios must pass with no peers. Run `node --test swap-service/server.test.mjs` for offer persistence and access checks. Run `python3 scripts/check_ethereum_token_htlc.py --output /absolute/new/path` for all three Ethereum token fixture claim and refund paths. Later milestones must add runnable commands and exact acceptance evidence here.

## Validation and Acceptance

Successful completion requires real swaps across all four isolated local chains, token and NFT exact-asset checks, same-chain swaps, user-confirmed signing, restart and refund recovery, private and public offer flows, and no public-chain peers. Unit tests alone do not establish full application completion or token issuer safety.

## Idempotence and Recovery

Use fresh private directories for local chains and wallets and stop owned processes on completion. Never overwrite old receipts. Existing contracts remain present and source-compatible. Keep private keys, secrets and test wallet directories out of version control.

## Artifacts and Notes

The retained prior local test report is `ETHEREUM_CARDANO_HTLC_RESULTS.md`; it does not test token assets or pairwise marketplace behavior.

## Interfaces and Dependencies

The token escrow exposes funding, claim and refund and immutable asset kind, token address, token ID, amount, claimant, refundee, hashlock and expiry. Ethereum uses Solidity 0.8.30 and Foundry; Cardano uses Aiken and Plutus V3. The application service and companion APIs remain to be specified as implementation discovers wallet constraints.

Revision 2026-11-02: recorded local cross-chain and same-chain results, including the failed Cardano time-horizon attempt and the successful larger-epoch retry.

Revision 2026-11-02: added a real-browser private-offer test and clarified that messaging identities, wallet flows and public discovery still need work.

Revision 2026-11-02: added local Ethereum snapshot verification and recorded a browser fixture constructor-encoding mistake caught by that verifier. The remaining networks and end-to-end transaction UI are not implemented.

Revision 2026-11-02: added Bitcoin and Cardano read-only local snapshot verification; Cardano confirmation depth remains an explicit missing capability.

Revision 2026-11-02: added a loopback-only read-only companion for Bitcoin, Cardano and Hegemon. Hegemon access requires a terminal approval and passphrase; its full integrated test is in progress. The companion does not sign or submit swaps.

Revision 2026-11-02: recorded the verified local Hegemon read, separate sandboxed desktop entry point, and limited deadline watch. Swap signing, automatic claim detection and recovery remain unfinished.

Revision 2026-11-02: added encrypted local preimage backup and tested simultaneous tabs and corrupted storage. This is a prerequisite, not an end-to-end claim or complete swap recovery.

Revision 2026-11-02: one cross-tab browser test observed a missing local-storage backup under load. Replaced the shared array with transactional IndexedDB records and added fail-closed migration from the earlier encrypted format; concurrent creation and migration tests are being repeated.

Revision 2026-11-02: strengthened token funding to reject extra sender debits, regenerated the pinned runtime template, and replaced the backup array with transactional IndexedDB. The full fresh Hegemon/token rehearsal against the updated token contract is still running.

Revision 2026-11-02: local deployment primitives passed for all four Ethereum asset kinds in `/workspace/edeploy2/summary.json`, with independently exercised companion anchor and wrong/stale-chain rejection. Added an experimental opt-in Hegemon action interface and terminal approvals. The first Hegemon action rehearsal `/workspace/hact1` failed after a local submission because the companion incorrectly treated the 48-byte action ID as the 32-byte preparation attempt ID; the submission may already have occurred. The parser now preserves both distinct IDs, with regression tests. Fresh chains are being used for subsequent claim and refund runs. Browser testing caught a missing static allowlist entry for the new module; fixed and tests are being repeated. This is still not an atomic swap implementation.

Revision 2026-11-02: separate local ERC-20/721/1155 approval and funding, ERC-1155 operator revocation and rejection cases passed on fresh Anvil (`/workspace/efund4/summary.json`); the Chromium ERC-20 deploy/approve/fund/verify path also passed with a test provider. The first funding test lacked confirmation blocks, and an intermediate revocation check used the wrong fixture getter; both were corrected in subsequent fresh tests. Claim/refund and coordinated multi-chain execution remain unfinished.

Revision 2026-11-02: a companion can optionally unlock a browser-exported encrypted preimage backup for a local Hegemon claim, with the backup file configured on startup and its passphrase entered only at the terminal. Python/JavaScript interoperability and error-handling tests and a fresh Hegemon backup-claim rehearsal (`/workspace/hbackup1/summary.json`) passed. The backup is not a complete recovery record.

Revision 2026-11-02: `/workspace/hact2/summary.json` and `/workspace/hact3/summary.json` passed the local Hegemon/ERC-20 claim and refund paths through terminal-approved companion actions, including canonical submission checks, altered terms and zero peers. Native ETH and three token refund transactions passed on fresh Anvil (`/workspace/erefund1/summary.json`), including early and repeat rejection.

Revision 2026-11-02: manual Ethereum claims passed for ETH and the three token fixture kinds on fresh Anvil (`/workspace/eclaim1/summary.json`), rejecting a wrong preimage before wallet access. Chromium unlocked a generated backup and submitted a real local ETH claim through a test provider; a wrong backup passphrase was rejected. No claim of counterparty-leg verification or full swap execution is made.

Revision 2026-11-02: Bitcoin regtest actions passed local lock, claim and refund through terminal-approved companion processes (`/workspace/bact2/summary.json`), rejecting a wrong refund-branch wallet, early refund, bad bearer token, HTTP secret field, and local denial; peer count stayed zero. A repeat with encrypted wallets and an encrypted-backup claim passed (`/workspace/bact4/summary.json`), including terminal passphrase entry and relocking. Chromium exercised the action form with a mocked companion. Private descriptors must already be imported, and the fixed test fee is not public-network policy.

Revision 2026-11-02: Cardano local CLI actions funded, claimed and refunded a bundle containing a fungible fixture and a one-of-one token on separate peerless nodes (`/workspace/cact1/summary.json`); companion-terminal execution passed after stricter process, configuration and peerless-topology checks (`/workspace/cact3/summary.json`). A subsequent claim and refund rehearsal saved private transaction records before submission, and the claim unlocked an encrypted backup (`/workspace/cact6/summary.json`). The local signing key file is unencrypted, the journal is not complete recovery, and CIP-30 transaction signing remains unfinished.

Revision 2026-11-02: added local claim-preimage observers and encrypted recovery for Bitcoin (`/workspace/bobserve1/summary.json`), Ethereum (`/workspace/eobserve1/summary.json`), Cardano via a local Ogmios stream (`/workspace/owatch3/summary.json`) and Hegemon (`/workspace/hobserve2/summary.json`, a copy of the prior isolated chain). The first Hegemon observer attempt failed because canonical actions were bytearrays, and the corrected parser accepts and tests both byte buffer types. A fresh BTC/Cardano companion rehearsal (`/workspace/bcscomp1/summary.json`) verified both legs, observed a confirmed Cardano claim and used the resulting encrypted backup to claim BTC. This is a scripted manual rehearsal, not a complete pairwise coordinator or finality policy.

Revision 2026-11-02: added a transactional browser journal of validated public action terms before wallet calls. It records returned IDs, retains uncertain outcomes, exports/imports without overwrites and blocks action submission when local journal storage is damaged. Concurrent tabs, interrupted responses and conflicting imports were exercised in Chromium; journal records do not contain keys, preimages or complete swap recovery.

Revision 2026-11-02: new public offers carry an owner P-256 inbox public key. A reserving participant can encrypt a session key to it without a shared link; HKDF and AES-GCM bind the setup to the offer and reservation. A response-loss retry resends the same sealed setup, and the relay atomically rejects messages for a stale reservation. The non-extractable owner key is local to the browser and is not backed up; this channel does not authenticate wallet identities or defend against malicious relay code/key substitution.

Revision 2026-11-02: the conversation UI displays full owner and reservation-key fingerprints for comparison over a separate trusted channel. The owner rejects a changed inbox key against its locally saved offer association; the browser test exercises both matching fingerprints and a substituted key. These checks do not authenticate wallet identities and cannot defend against modified client code served by the relay.

Revision 2026-11-02: rebuilt and typechecked the Electron app, then rechecked its isolated local-board window with dummy node executables and a temporary virtual display. The updated test confirms the current browser modules initialize and the desktop wallet API is unavailable in that window.

Revision 2026-11-02: added a two-leg comparison for local snapshots and an offer-selection race guard. The pair check does not gate claims or establish participant identity, safe deadlines, simultaneous unspent state or finality; Cardano confirmation depth is unknown.
