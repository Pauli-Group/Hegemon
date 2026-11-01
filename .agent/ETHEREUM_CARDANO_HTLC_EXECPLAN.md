# Local Ethereum and Cardano HTLC swaps

This living ExecPlan follows .agent/PLANS.md. Keep Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective current.

## Purpose and context

Extend the current local private-spend Bitcoin test with native ETH and ADA legs. A hash time locked contract (HTLC) pays a designated claimant presenting a 32-byte SHA-256 preimage before its deadline, or pays its designated refund owner after the deadline. Existing scripts/local_private_spend_swap.py supplies the real Hegemon wallet process, peak-memory measurement, local miner and canonical byte checks. Do not edit Hegemon's circuit, wallet or consensus source. Use isolated local chains, never public peers.

## Progress

- [x] Read repository instructions, current harness and design/method documentation; inspected environment.
- [x] Install pinned Foundry 1.8.7, Solidity 0.8.30, Aiken 1.1.24, cardano-node 11.1.3 / CLI 11.2.3.0; checksum installer added.
- [x] Solidity 9 tests and Aiken 10 tests pass; real local Ethereum and Cardano claim/refund smoke tests pass.
- [x] Added both adapters and ran all eight scenarios successfully on fresh local chains.
- [x] Retained public receipts and resource measurements in .agent/ETHEREUM_CARDANO_HTLC_RESULTS.json, reproduction/report in ETHEREUM_CARDANO_HTLC_RESULTS.md, implementation committed as b0cffb76.

## Milestones

First implement a payable Solidity contract under contracts/ethereum and an Aiken validator under contracts/cardano. Aiken compiles Cardano validator source into actual Plutus code. Claim checks the claimant authorization, exact 32-byte preimage, SHA-256 digest and a validity interval wholly before expiry; refund checks refund authorization and expiry. Reject wrong secrets, unauthorized signers, early refunds and repeat or late spends. On Ethereum test actual mined receipts and state/balances in Anvil, a local Ethereum execution node. On Cardano submit actual script transactions to a fresh private Cardano test network if the node tooling is available; emulator or evaluator tests must be explicitly labelled and cannot count as node integration.

Then create scripts/local_multichain_htlc_swap.py using the Hegemon setup and exact exported/canonical action checks of the Bitcoin runner, plus chain-specific adapters. Each scenario starts fresh wallets and databases. Happy swaps reveal a confirmed counterpart secret and spend Hegemon. Missing funding refunds Hegemon. Dual refund confirms refunds on both chains. Late claim confirms a counterpart claim and Hegemon refund, then rejects the spent Hegemon note. Only local deadlines are exercised; public-chain timing margins are not qualified.

## Validation and reproduction

Record pinned tool versions and setup commands in the final report. Build and execute the Solidity and Aiken tests before Hegemon proving. Run `python3 scripts/local_multichain_htlc_swap.py --chain ethereum --output /workspace/new-ethereum-run` and `python3 scripts/local_multichain_htlc_swap.py --chain cardano --output /workspace/new-cardano-run`, using already built Development-capable node and private-spend binaries. Install prerequisites with `python3 -m pip install -r scripts/requirements-htlc-local.txt` and `python3 scripts/setup_multichain_htlc_tools.py`. A fresh Hegemon build uses `RUSTUP_TOOLCHAIN=1.91.1 cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend`. Output paths must be new and private. Capture source and binary hashes, contract code hashes, transaction identifiers, balances, canonical confirmations, negative checks and Hegemon wait4 proof-process resource metrics. Fail visibly on unsupported tooling or failed acceptance. Stop and reap every owned node, including on errors.

## Decision Log

Retain the current branch local-private-spend-htlc so Bitcoin work remains available. Add native ETH and ADA contracts rather than token minting or bridge logic. Preserve all Hegemon proof source bytes and source identity. Use local chain-specific time controls only where supported; state the limits of those controls in results.

## Surprises & Discoveries

The environment has about 3.6 GiB free disk, Docker, Python and Node.js but no Ethereum/Cardano CLI tools initially. Official prebuilt release archives were installed under /workspace/chain-tools. Repository build outputs and Bitcoin data remain available.

## Outcomes & Retrospective

Both counterparty implementations pass their contract tests and actual local transaction smoke checks. All eight full Hegemon paired scenarios passed without interruption: success, missing counterpart funding, dual refund and late claim for each chain. Nineteen contract tests pass. Core Hegemon source remains identical to main. Observed proof processes took 68.763–174.281 seconds with about 1.60–2.00 GiB peak RSS while sharing CPU. All owned runtime nodes stopped. See ETHEREUM_CARDANO_HTLC_RESULTS.md for exact scope and commands.

Cardano CLI reports evaluator rejection as "scripts have execution failures". Duplicate submission may be idempotently acknowledged, so repeat-spend tests construct a new transaction and require the consumed UTxO rejection instead. cardano-testnet create-env supplies keys but address files are produced only by its launcher; the adapter derives addresses directly and starts an owned loopback cardano-node process to ensure cleanup. Anvil has no P2P subsystem and does not implement net_peerCount in this release; isolation checks use the node process's established TCP sockets excluding its loopback RPC port. Cardano checks both empty topology and absence of established TCP connections.

Completion update: validated all eight distinct Hegemon genesis identities, identical proof binaries/source relation, exact negative error paths, current SMZL carriers and stored counterpart confirmations. Recorded the local observer and timing limits to prevent treating functional passes as public-chain or security qualification.
