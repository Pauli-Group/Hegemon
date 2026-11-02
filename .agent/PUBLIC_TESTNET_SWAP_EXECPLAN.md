# Exercise non-Hegemon swaps on public testnets

This living plan follows `.agent/PLANS.md`. The aim is to repeat the Bitcoin, Ethereum, and Cardano HTLC scenarios with actual public-testnet transactions, without syncing full nodes or starting Hegemon. Users should be able to inspect published transaction identifiers and distinguish observed results from uncompleted tests. The existing isolated-node code remains available and its local-only guards remain intact.

## Progress

- [x] (2026-11-02) Inspected the existing isolated rehearsal scripts and repository design. Confirmed Ethereum Sepolia, Cardano preview Koios and Bitcoin testnet4 public endpoints are reachable.
- [x] (2026-11-02) Generated two disposable test participants under `/workspace/public-testnet-swap-20261102`, with private files restricted to the current user. Requested testnet faucet funds for the first participant. These private files must never be committed or used for real funds.
- [x] (2026-11-02) Added read-only public testnet identity and balance probing, and local Bitcoin P2WPKH funding plus HTLC claim/refund construction. Tests validate Bitcoin signatures against a peerless local regtest node and reject wrong secrets, wrong signing keys and early refund.
- [x] (2026-11-02) Added local EIP-1559 Sepolia-ID signing, verified by deploying and claiming ETH, ERC-20, ERC-721 and ERC-1155 fixtures on local Anvil. Added offline Cardano CLI balancing with exact native-asset change, verified by funding, claiming, rejecting an early refund, and refunding an ADA/fungible/NFT HTLC on an isolated local chain.
- [x] (2026-11-02) Added a private, exclusive signed-transaction journal and testnet-specific submission functions. Mock tests exercise network rejection, a lost response without retry and the distinction between submission and confirmation.
- [x] (2026-11-02) Added public UTxO and claim-preimage readers and local-signing drivers for the three test networks. Verified Bitcoin and Cardano UTxO response parsing with real public-chain outputs; the actors are still unfunded and no transaction has been broadcast.
- [ ] Add independently checked remote public-testnet adapters and safe transaction building and submission, without weakening local companion safeguards.
- [ ] Exercise BTC/ETH, BTC/Cardano, ETH/Cardano and both Ethereum and Cardano same-chain paths, including applicable fungible and NFT fixtures, claims, refunds and failure cases, subject to testnet funds, network confirmation times and service availability.
- [ ] Record public transaction identifiers and observations, run regression tests, update architecture documentation and commit the work.

## Surprises & Discoveries

The existing harness assumes its own peerless Bitcoin Core, Anvil and Cardano node and cannot be retargeted by changing an endpoint. Cardano script transactions require remote protocol parameters and an execution budget. Koios exposes preview chain data and transaction submission but no execution-evaluation endpoint was found in its public specification. An offline-built single-script claim succeeded locally when supplied a conservative budget, with correspondingly higher fees; the node still verifies the script. The first attempt reversed cardano-cli's `(steps,memory)` order and the local ledger rejected it as over budget; the corrected transaction was accepted. Public services are trusted sources and may be unavailable or inconsistent. The initial Ethereum wallet output is a two-column address/key record rather than labeled lines; the setup preserved the existing generated key and resumed safely. The first Bitcoin unit run exposed a test cleanup process-group configuration error; setting `start_new_session=True` fixed it and the subsequent actual consensus checks passed. The initial Ethereum test queried a receipt before local mining completed and now waits for the receipt. An initial token-contract deployment exhausted its local test gas limit, and the successful retry used a larger limit.

## Decision Log

Decision: use Bitcoin testnet4, Ethereum Sepolia and Cardano preview. Bitcoin testnet4 has a public faucet and API reachable in this workspace; it replaces the initial signet suggestion before any funding. Date: 2026-11-02.

Decision: use public network access only for these three networks, with no Hegemon node or network access. Preserve the existing local verifier restrictions and add independent tooling. Date: 2026-11-02.

## Outcomes & Retrospective

Work is in progress. Public endpoint reachability and the local Bitcoin, Ethereum and Cardano transaction tests do not establish that a public-testnet swap or any broadcast has succeeded. Testnet transactions are public and no test can establish production safety.

## Context and Orientation

`scripts/check_bitcoin_ethereum_swap.py`, `scripts/check_ethereum_cardano_swap.py`, `scripts/check_samechain_ethereum_swap.py`, and `scripts/check_samechain_cardano_swap.py` are the prior local rehearsals. `contracts/ethereum/TokenHTLC.sol` supports ERC-20, ERC-721 and ERC-1155, `contracts/ethereum/HegemonHTLC.sol` supports native ETH, and `contracts/cardano/validators/htlc.ak` validates Cardano native assets and ADA. `scripts/htlc_counterpart.py` controls local fixtures. Bitcoin testnet4 exposes a public Esplora-compatible API at `https://blockstream.info/testnet4/api`; Ethereum Sepolia exposes JSON-RPC at `https://ethereum-sepolia-rpc.publicnode.com`; Cardano preview exposes Koios at `https://preview.koios.rest/api/v1`. These services can lie and must not receive private keys or unrevealed preimages. The workspace contains Foundry, cardano-cli and Python; Python add-on packages are isolated at `/workspace/chain-tools/public-test-python`. User-generated credentials remain outside the repository in `/workspace/public-testnet-swap-20261102`.

## Plan of Work

First implement testnet identity checks, locally controlled transaction signing, and durable recovery records. Verify network identity before every write and track prepared transactions prior to broadcasting. Obtain faucet funds for each chain. Add deterministic tests for transaction construction and verification before submitting the first public transaction. Then execute individual chain claim and refund cases, followed by pairwise swaps, observing and checking published transactions and shared hashlocks. Do not use short regtest timeouts or promise safety from testnet confirmations; choose generous refund windows and retain keys and records until all funds have been recovered.

## Concrete Steps

From the repository root, run `python3 scripts/public_testnet_probe.py --addresses /workspace/public-testnet-swap-20261102/addresses.json` to check chain identities and balances. Run `PYTHONPATH=scripts:/workspace/chain-tools/public-test-python python3 -m unittest scripts/test_public_testnet_probe.py scripts/test_public_bitcoin_transactions.py scripts/test_public_bitcoin_driver.py scripts/test_public_ethereum_transactions.py scripts/test_public_sepolia_driver.py scripts/test_public_cardano_transactions.py scripts/test_public_swap_journal.py scripts/test_public_testnet_submit.py scripts/test_public_testnet_utxos.py scripts/test_public_testnet_observers.py -v` to exercise the public-testnet primitives and local fixture chains. The public script verifies Bitcoin testnet4 genesis, Sepolia genesis and chain ID, and preview network magic and start time. Test actors' public addresses are in the specified JSON file; the surrounding directory is private. Follow the test scripts and receipts added during implementation. Never put keys in command arguments, source files, public receipts or logs.

## Validation and Acceptance

Passing means independently inspecting confirmed funding and claim or refund transactions on the designated public testnets, with each paired claim using the other chain's observed preimage and with both assets and recipients checked. Record insufficient funds, unavailable services, failures, unconfirmed submissions and pending refunds explicitly; never report an attempted transaction as confirmed. Local unit and regression tests must pass as well.

## Idempotence and Recovery

Prepared or uncertain submissions must not be retried blindly: inspect the transaction identifier, chain and wallet first. Preserve the private output directory and refund data until all funding outputs are claimed or refunded. Public testnet coins are intended only for testing. Do not start a public full node or delete existing wallets and outputs.

## Interfaces and Dependencies

Use local signing with Python `embit` for Bitcoin testnet4, Foundry tooling for Sepolia, and the Cardano signing tools or a maintained Python transaction library for preview. Restrict endpoints and chain identities explicitly. Record only public terms and transaction identifiers in committed receipts. Provider correctness, freshness and finality remain trust assumptions.

Revision 2026-11-02: created the plan after verifying public endpoints and generating disposable keys, before any public transaction or faucet funding.

Revision 2026-11-02: added identity/balance probing and consensus-tested offline Bitcoin transaction builders. Public testnet funding and cross-chain execution are still pending.

Revision 2026-11-02: added Sepolia-ID signing and an offline Cardano transaction builder. Local network tests exposed and fixed receipt timing and the Cardano CLI's execution-budget argument order; no public funding, swap or broadcast is asserted.

Revision 2026-11-02: the offline Cardano path also passed early-refund rejection and mature refund for the token bundle on a fresh isolated chain. Added a private pre-submission journal and testnet network-identity checks, with mocked submission tests. No signed public transaction has been sent.

Revision 2026-11-02: added remote UTxO and confirmed-preimage readers and node-free signing/submission drivers. The Bitcoin and Cardano readers also parsed real public-chain UTxOs, while both actors remained unfunded. The public tests and complete coordination remain unperformed.

Revision 2026-11-02: extended the Sepolia-ID signed local rehearsal to ERC-20, ERC-721 and ERC-1155 claims. Public-network funding and cross-chain execution are still pending.
