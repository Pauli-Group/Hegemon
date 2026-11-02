# Build the multi-asset swap prototype

This living plan follows `.agent/PLANS.md`. The objective is a noncustodial local-network prototype with Ethereum ETH, ERC-20, ERC-721 and ERC-1155, Cardano ADA and native assets, Bitcoin BTC and Hegemon HGN. Users create public or private offers and claim or refund their own escrows from desktop or browser. Secrets and signing remain local. The current harness in `scripts/local_multichain_htlc_swap.py` demonstrates HGN/ETH and HGN/ADA only and is not an application.

## Progress

- [x] (2026-11-02) Inspected existing contracts, local harness, wallet architecture and repository instructions.
- [x] (2026-11-02) Implemented ERC-20, ERC-721 and ERC-1155 token escrow and 11 local fixture tests; the existing 9 native ETH tests also pass.
- [ ] Add adversarial callback coverage and real local-chain token swap integration.
- [ ] Implement Cardano native-token transactions and tests.
- [ ] Implement resilient pairwise swap protocol, local companion, wallet integrations and monitoring.
- [ ] Implement noncustodial offer service and desktop/browser interfaces.
- [ ] Exercise local-network end-to-end swaps and document remaining limitations.

## Surprises & Discoveries

Foundry prank affects the next external call, including the SHA-256 precompile; computing the digest before setting the prank fixed the test fixture sender. The current Hegemon tests invoke `private-spend` as an interactive local executable; no app-level swap API is presently exposed. Hegemon proof generation needs substantial memory and time, which must affect timeout margins and interface design.

## Decision Log

Use independent per-offer Ethereum token escrow instances, with exact ERC-20 balance checks, rather than extending the existing native ETH escrow. Keep the existing ETH contract and tests unchanged. Tokens with unexpected transfer quantities must fail. NFT contracts can have arbitrary issuer behavior, so successful interface checks do not guarantee token safety.

## Outcomes & Retrospective

The independent Ethereum token escrow compiles and its 11 unit tests pass. Cardano token handling, the service, UI, wallet integration and full swap protocol remain unfinished. No production readiness or deployment is asserted.

## Context and Orientation

`contracts/ethereum/HegemonHTLC.sol` is the existing native ETH escrow. `contracts/cardano/validators/htlc.ak` is the existing Aiken validator. `scripts/htlc_counterpart.py` owns local-chain harness adapters. `hegemon-app` is a React/Electron wallet. The local development tools reside in `/workspace/chain-tools`. All test networks must remain isolated; never start public synchronization.

## Plan of Work

First add a separate Ethereum token escrow for standard fungible and nonfungible interfaces, with a funded state, exact quantities, claimant and refundee, SHA-256 32-byte secret and deadline. Add unit tests covering funding, claim, refund, wrong secrets, unauthorized parties, transfer fees, callbacks and repeated spends. Then adapt the Cardano harness to build UTxOs with explicit policy IDs, asset names and quantities and verify their outputs. Implement the application and service only after the swap state machine verifies real chain state, securely stores recovery data and uses local signing. Build a small TypeScript/SQLite service for untrusted public offers and private coordination without secret custody. Reuse the existing desktop app and provide a browser client with authenticated local companion access for Bitcoin and Hegemon. Complete real multi-chain tests, including offline recovery and service interruption.

## Concrete Steps

From the repo root run `/workspace/chain-tools/foundry/forge test --root contracts/ethereum --use /workspace/chain-tools/solc -vv` and expect all tests to pass. Run the Aiken tests using `/workspace/chain-tools/aiken/aiken-x86_64-unknown-linux-musl/aiken check contracts/cardano`. Later milestones must add runnable commands and exact acceptance evidence here.

## Validation and Acceptance

Successful completion requires real swaps across all four isolated local chains, token and NFT exact-asset checks, same-chain swaps, user-confirmed signing, restart and refund recovery, private and public offer flows, and no public-chain peers. Unit tests alone do not establish full application completion or token issuer safety.

## Idempotence and Recovery

Use fresh private directories for local chains and wallets and stop owned processes on completion. Never overwrite old receipts. Existing contracts remain present and source-compatible. Keep private keys, secrets and test wallet directories out of version control.

## Artifacts and Notes

The retained prior local test report is `ETHEREUM_CARDANO_HTLC_RESULTS.md`; it does not test token assets or pairwise marketplace behavior.

## Interfaces and Dependencies

The token escrow exposes funding, claim and refund and immutable asset kind, token address, token ID, amount, claimant, refundee, hashlock and expiry. Ethereum uses Solidity 0.8.30 and Foundry; Cardano uses Aiken and Plutus V3. The application service and companion APIs remain to be specified as implementation discovers wallet constraints.
