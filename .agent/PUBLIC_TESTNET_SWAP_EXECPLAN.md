# Exercise non-Hegemon swaps on public testnets

This living plan follows `.agent/PLANS.md`. The aim is to repeat the Bitcoin, Ethereum, and Cardano HTLC scenarios with actual public-testnet transactions, without syncing full nodes or starting Hegemon. Users should be able to inspect published transaction identifiers and distinguish observed results from uncompleted tests. The existing isolated-node code remains available and its local-only guards remain intact.

## Progress

- [x] (2026-11-02) Inspected the existing isolated rehearsal scripts and repository design. Confirmed Ethereum Sepolia, Cardano preview Koios and Bitcoin testnet4 public endpoints are reachable.
- [x] (2026-11-02) Generated two disposable test participants under `/workspace/public-testnet-swap-20261102`, with private files restricted to the current user. Requested testnet faucet funds for the first participant. These private files must never be committed or used for real funds.
- [x] (2026-11-02) Added read-only public testnet identity and balance probing, and local Bitcoin P2WPKH funding plus HTLC claim/refund construction. Tests validate Bitcoin signatures against a peerless local regtest node and reject wrong secrets, wrong signing keys and early refund.
- [x] (2026-11-02) Added local EIP-1559 Sepolia-ID signing, verified by deploying and claiming ETH, ERC-20, ERC-721 and ERC-1155 fixtures on local Anvil. Added offline Cardano CLI balancing with exact native-asset change, verified by funding, claiming, rejecting an early refund, and refunding an ADA/fungible/NFT HTLC on an isolated local chain.
- [x] (2026-11-02) Added a private, exclusive signed-transaction journal and testnet-specific submission functions. Mock tests exercise network rejection, a lost response without retry and the distinction between submission and confirmation.
- [x] (2026-11-02) Added public UTxO and claim-preimage readers and local-signing drivers for the three test networks. Verified Bitcoin and Cardano UTxO response parsing with real public-chain outputs; the actors are still unfunded and no transaction has been broadcast.
- [x] (2026-11-02) Added a restartable BTC/ETH native-asset scenario. A real two-chain local integration run completed through its public-style drivers; its network and submission functions were redirected to fresh peerless local nodes. A mock loss of response leaves an inflight state and prevents automatic retry.
- [x] (2026-11-02) Added native Cardano fixture minting to offline transaction construction and verified it on the isolated local chain. Added a public-preview script, datum, asset and provider-reported confirmation snapshot verifier with mocked-provider tests.
- [x] (2026-11-02) Funded the disposable participants and completed the native ETH/ADA claim path on Sepolia and Cardano preview. Provider-reported confirmed transaction identifiers and payout evidence are in `PUBLIC_TESTNET_RESULTS.md`.
- [x] (2026-11-02) Completed a Sepolia ERC-20/ERC-721 same-chain swap, verifying fixture payouts; its public transaction identifiers are being added to the results.
- [x] (2026-11-02) Completed a Sepolia ERC-1155/ERC-20 same-chain swap with operator approval revoked, a Cardano preview fungible/NFT same-chain swap, and a native Sepolia refund including an exact early-refund rejection. Public IDs are recorded in `PUBLIC_TESTNET_RESULTS.md`.
- [x] (2026-11-03) Completed a Cardano preview native-ADA refund and public cross-chain ERC-721/NFT and ERC-20/Cardano fungible-token swaps. The Cardano funding/claim and Ethereum claim transaction IDs are recorded in `PUBLIC_TESTNET_RESULTS.md`.
- [x] (2026-11-03) Completed the ERC-1155/Cardano native-token swap and the Sepolia ERC-721 refund; verified recipients and recorded the public transaction identifiers.
- [x] Finish the Cardano preview NFT refund and check Bitcoin testnet4 funding.
- [x] Confirm the BTC/ETH escrow and complete the swap.
- [ ] Complete the resumed Bitcoin/Cardano, Bitcoin/ERC-20, Bitcoin/Cardano token and Bitcoin refund cases.
- [ ] Add independently checked remote public-testnet adapters and safe transaction building and submission, without weakening local companion safeguards.
- [ ] Exercise BTC/ETH, BTC/Cardano, ETH/Cardano and both Ethereum and Cardano same-chain paths, including applicable fungible and NFT fixtures, claims, refunds and failure cases, subject to testnet funds, network confirmation times and service availability.
- [ ] Record public transaction identifiers and observations, run regression tests, update architecture documentation and commit the work.

## Surprises & Discoveries

The existing harness assumes its own peerless Bitcoin Core, Anvil and Cardano node and cannot be retargeted by changing an endpoint. Cardano script transactions require remote protocol parameters and an execution budget. Koios exposes preview chain data and transaction submission but no execution-evaluation endpoint was found in its public specification. An offline-built single-script claim succeeded locally when supplied a conservative budget, with correspondingly higher fees; the node still verifies the script. The first attempt reversed cardano-cli's `(steps,memory)` order and the local ledger rejected it as over budget; the corrected transaction was accepted. Public services are trusted sources and may be unavailable or inconsistent. The initial Ethereum wallet output is a two-column address/key record rather than labeled lines; the setup preserved the existing generated key and resumed safely. The first Bitcoin unit run exposed a test cleanup process-group configuration error; setting `start_new_session=True` fixed it and the subsequent actual consensus checks passed. The initial Ethereum test queried a receipt before local mining completed and now waits for the receipt. An initial token-contract deployment exhausted its local test gas limit, and the successful retry used a larger limit. The first staged BTC/ETH integration run queried an unmined local receipt; after waiting for inclusion, it exposed insufficient claimant gas in a second run. The successful retry funded claimant gas according to the current fee estimate.

## Decision Log

Decision: use Bitcoin testnet4, Ethereum Sepolia and Cardano preview. Bitcoin testnet4 has a public faucet and API reachable in this workspace; it replaces the initial signet suggestion before any funding. Date: 2026-11-02.

Decision: use public network access only for these three networks, with no Hegemon node or network access. Preserve the existing local verifier restrictions and add independent tooling. Date: 2026-11-02.

## Outcomes & Retrospective

Work is in progress. The native Sepolia/preview ETH–ADA swap and the Sepolia ERC-20/ERC-721 same-chain swap completed on public testnets. They do not establish that the remaining combinations, refunds or Bitcoin cases succeeded. Testnet transactions are public and no test can establish production safety.

## Context and Orientation

`scripts/check_bitcoin_ethereum_swap.py`, `scripts/check_ethereum_cardano_swap.py`, `scripts/check_samechain_ethereum_swap.py`, and `scripts/check_samechain_cardano_swap.py` are the prior local rehearsals. `contracts/ethereum/TokenHTLC.sol` supports ERC-20, ERC-721 and ERC-1155, `contracts/ethereum/HegemonHTLC.sol` supports native ETH, and `contracts/cardano/validators/htlc.ak` validates Cardano native assets and ADA. `scripts/htlc_counterpart.py` controls local fixtures. Bitcoin testnet4 exposes a public Esplora-compatible API at `https://blockstream.info/testnet4/api`; Ethereum Sepolia exposes JSON-RPC at `https://ethereum-sepolia-rpc.publicnode.com`; Cardano preview exposes Koios at `https://preview.koios.rest/api/v1`. These services can lie and must not receive private keys or unrevealed preimages. The workspace contains Foundry, cardano-cli and Python; Python add-on packages are isolated at `/workspace/chain-tools/public-test-python`. User-generated credentials remain outside the repository in `/workspace/public-testnet-swap-20261102`.

## Plan of Work

First implement testnet identity checks, locally controlled transaction signing, and durable recovery records. Verify network identity before every write and track prepared transactions prior to broadcasting. Obtain faucet funds for each chain. Add deterministic tests for transaction construction and verification before submitting the first public transaction. Then execute individual chain claim and refund cases, followed by pairwise swaps, observing and checking published transactions and shared hashlocks. Do not use short regtest timeouts or promise safety from testnet confirmations; choose generous refund windows and retain keys and records until all funds have been recovered.

## Concrete Steps

From the repository root, run `python3 scripts/public_testnet_probe.py --addresses /workspace/public-testnet-swap-20261102/addresses.json` to check chain identities and balances. Run `PYTHONPATH=scripts:/workspace/chain-tools/public-test-python python3 -m unittest scripts/test_public_testnet_probe.py scripts/test_public_bitcoin_transactions.py scripts/test_public_bitcoin_driver.py scripts/test_public_ethereum_transactions.py scripts/test_public_sepolia_driver.py scripts/test_public_cardano_transactions.py scripts/test_public_cardano_verify.py scripts/test_public_swap_journal.py scripts/test_public_testnet_submit.py scripts/test_public_testnet_utxos.py scripts/test_public_testnet_observers.py scripts/test_public_btc_eth_rehearsal.py scripts/test_public_btc_eth_integration.py -v` to exercise the public-testnet primitives and local fixture chains. The public script verifies Bitcoin testnet4 genesis, Sepolia genesis and chain ID, and preview network magic and start time. Test actors' public addresses are in the specified JSON file; the surrounding directory is private. After obtaining funds, the native BTC/ETH scenario starts with `PYTHONPATH=scripts:/workspace/chain-tools/public-test-python python3 scripts/public_btc_eth_rehearsal.py init --directory /workspace/public-testnet-swap-20261102`, and successive `advance` operations execute at most one public transaction or wait for confirmations. Its test-only participant mapping is Bitcoin Alice/Ethereum Bob versus Bitcoin Bob/Ethereum Alice. An inflight phase means manual journal and chain inspection is necessary before recovery; no automatic retry is safe. The long Bitcoin refund height and short Ethereum deadline are experimental testnet values, not a real-fund safety policy. Follow the test scripts and receipts added during implementation. Never put keys in command arguments, source files, public receipts or logs.

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

Revision 2026-11-02: implemented a restartable BTC/ETH native scenario with inflight records and full real local-chain integration, added offline Cardano native-asset minting and a provider-backed escrow verifier. BTC/Cardano, ETH/Cardano and same-chain public coordinators and all public transactions remain unfinished.

Revision 2026-11-02: completed a real native ETH/ADA swap across Sepolia and Cardano preview and a real Sepolia ERC-20/ERC-721 swap. The ETH token escrow RPC gas estimate exceeded the original 10-million gas cap on two providers; no signed transaction existed, and after confirming no pending sender nonce the pre-signing state was safely reset and the bounded cap raised to 30 million. The Cardano token/NFT, second Sepolia token swap, ETH refund and cross-chain token scenarios remain in progress. Bitcoin must be checked after those cases as requested.

Revision 2026-11-02: the Cardano fungible/NFT and Sepolia ERC-1155/ERC-20 same-chain claims and the Sepolia native refund completed. The first Cardano same-chain claim paused before signing because the only available fee output also held unrelated tokens; offline construction was tested to preserve those tokens in change, and the resumed public swap completed. Three cross-chain token cases and a separate Cardano refund are underway. A transient provider mismatch on the ERC-20 token deployment check resolved on a later read without resubmitting.

Revision 2026-11-03: the Cardano ADA refund, cross-chain NFT swap and cross-chain ERC-20/Cardano fungible swap completed. The ERC-1155/Cardano cross-chain claim and an ERC-721 refund are in progress; Bitcoin is still deferred until Ethereum and Cardano cases finish.

Revision 2026-11-03: the ERC-1155/Cardano fungible swap and Sepolia ERC-721 refund completed. A transient RPC error interrupted the NFT refund during gas estimation, before signing; the private journal, sender nonce and NFT escrow state established that no refund transaction existed before the pre-signing phase was safely resumed. A Cardano NFT refund remains in progress. Read-only requests now retry bounded transient provider errors; signed submissions still do not retry automatically.

Revision 2026-11-03: the Cardano NFT refund completed. The Bitcoin testnet4 wallet had 3,000 confirmed sats, and the BTC/ETH funding transaction was submitted; the remaining swap is pending. The primary Bitcoin service omitted its six-block estimate, so a tested second-provider fallback verifies the network genesis and retains the most conservative available estimate. Additional testnet4 funds were requested for the other Bitcoin cases.

Revision 2026-11-03: the BTC/ETH Bitcoin lock confirmed, the Sepolia leg was claimed, and the Bitcoin claim was submitted but remains unconfirmed. Another 50,000 sats arrived with one confirmation. A journaled wallet split was prepared and its signed transaction passed local Bitcoin Core mempool acceptance; it awaits the funding's second confirmation before submission. Subsequent scenarios still require independent confirmation and payout checks.

Revision 2026-11-03: added a bounded-action runner for the four prepared Bitcoin cases. It waits for confirmed split outputs, funds at most one new case per pass, serializes the shared Cardano wallets, and stops on uncertain actions. Unit tests exercise scheduling and refusal of inflight states. The runner is session-bound, not a durable service; its existence does not establish that any remaining public swap has completed.

Revision 2026-11-03: the BTC/ETH claim confirmed and paid the intended Bitcoin recipient. The wallet split also confirmed. The previous runner was no longer running, and all four split inputs were verified unspent before restarting it; the BTC/Cardano lock has been submitted. No other Bitcoin cases are reported complete.

Revision 2026-11-03: all four remaining Bitcoin escrow funding transactions were submitted, but remain unconfirmed. The session runner stopped when the Blockstream API returned HTTP 429. Polling now skips repeated wallet UTxO scans once all escrows have been submitted, uses a longer interval, and checks every private journal for an inflight action before retrying transient read failures. The revised runner was restarted and is waiting for the provider; no signed submission is blindly repeated.

Revision 2026-11-03: the primary Bitcoin service continued to return 429. A testnet4-genesis-checked, read-only fallback to mempool.space was added for a restricted set of indexer endpoints, with a five-minute cooldown after a primary transient failure. A live height read succeeded through the secondary service. Broadcast still goes through the existing single-submission journal path, with no fallback or automatic retry of transaction submission. The runner was safely stopped while holding its action lock, then restarted with the changed reader; the four funding transactions were still unconfirmed.
