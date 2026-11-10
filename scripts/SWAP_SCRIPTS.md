# Swap scripts index

What each swap-related script in `scripts/` is for, grouped by role. Start with the swap engine (`swap_engine_cli.py`);
most of the rest are the libraries it wraps, the local fixtures it is tested against, or earlier rehearsals kept as
evidence. Tool locations and versions: `docs/SWAP_TOOLCHAIN.md`. Test tiers: `make swap-test`, `make swap-integration`,
`make swap-hegemon-local`.

Status words: **current** (use it), **library** (imported by the engine or other scripts; not run by hand),
**superseded** (kept as evidence of how an earlier run was staged; new swaps go through the engine),
**tool** (operator utility; never part of CI), **fixture** (local, disposable chains only).

Run Python from the repository root with `PYTHONPATH=scripts` (plus the packages directory from the toolchain doc).

## 1. The swap engine

| Path | Status | Role |
|---|---|---|
| `swap_engine_cli.py` | current | Command line for the two-party engine: plan from the timelock policy, run, resume and inspect a swap. |
| `swap_engine/` (`engine.py`, `store.py`, `planner.py`, `timelock_policy.py`, `identity.py`, `adapter.py`) | current | Durable store, pure transition engine, planner and policy shared with `swap-ui/timelock-policy.mjs` by test vectors. |
| `swap_engine/adapters/{bitcoin,ethereum,cardano}.py` | current | Public-testnet adapters wrapping the drivers below. |
| `swap_engine/adapters/hegemon_local.py`, `hegemon_stub.py`, `swap_engine/hegemon_wallet.py`, `hegemon_fake.py`, `local_hegemon.py` | current | Hegemon adapter: loopback Development profiles (`peers == 0`) and a separate `PublicHegemonProfile` for the v0.11 pre-mainnet (`"profile": "public"`). The recorded-wallet fake is for fast tests; `local_hegemon.py` is the parallel-world runner. |
| `swap_engine/adapters/local_{bitcoin,ethereum,cardano}.py`, `local_world.py`, `sim.py` | fixture | Local-chain adapters, world setup and the simulated chain used for fault-injection tests. |
| `swap_engine/tools.py` | library | Resolve chain tool binaries (`HEGEMON_TOOL_<NAME>`, `HEGEMON_CHAIN_TOOLS`); `python3 -m swap_engine.tools` prints them. |
| `swap_engine/ui_vectors.py`, `make_identity_vectors.py` | tool | Regenerate `config/swap/flow-vectors.json` and `config/swap/identity-vectors.json` that the JavaScript and Python implementations are both tested against. |
| `measure_chain_timing.py` | tool | Measure block-timing windows for `config/swap/chain-timing.json`. |
| `swap-tiers.sh` | current | The three test tiers behind the Makefile targets. |

## 2. Public-testnet drivers and read helpers (libraries)

| Path | Role |
|---|---|
| `public_bitcoin_driver.py`, `public_bitcoin_transactions.py` | Bitcoin testnet4 HTLC funding, claim and refund; the policy floor on refund distance lives here. |
| `public_sepolia_driver.py`, `public_ethereum_transactions.py`, `public_ethereum_verify.py`, `public_ethereum_token_verify.py` | Sepolia signing, journalling and escrow verification against the pinned runtime. |
| `public_cardano_driver.py`, `public_cardano_transactions.py`, `public_cardano_verify.py` | Cardano preview body building, signing and verification. |
| `public_testnet_probe.py`, `public_testnet_submit.py`, `public_testnet_utxos.py`, `public_testnet_observers.py`, `public_swap_journal.py` | Tips and balances, journalled submission, indexers, preimage observation and the private journal that holds signed transactions before broadcast. |
| `public_hegemon_wallet.py`, `public_hegemon_preimage_observer.py`, `probe_hegemon_testnet.py` | Bounded wallet I/O, preimage scan from canonical bytes, and read-only identity checks for a trusted Hegemon pre-mainnet node. The engine's public profile uses the observer and the probe; the older single-run rehearsal still uses the wallet helper. |
| `htlc_counterpart.py`, `ethereum_local_anchor.py` | Loopback Ethereum and Cardano counterparts and the anchor check for local swap tests. |

## 3. Local fixtures and checks (disposable chains only)

| Path | Status | Role |
|---|---|---|
| `local_multichain_htlc_swap.py` | current | Real private-spend HTLC swaps against fresh local Ethereum or Cardano chains, with token and scenario options. Still used by the contract documentation. |
| `local_private_spend_swap.py` | current | Fresh peerless Development chain plus Bitcoin regtest swap scenarios. Also the helper the Hegemon adapter drives. |
| `check_ethereum_token_htlc.py`, `check_cardano_token_htlc.py`, `check_ethereum_cardano_swap.py`, `check_bitcoin_ethereum_swap.py`, `check_bitcoin_cardano_companion_swap.py`, `check_samechain_ethereum_swap.py`, `check_samechain_cardano_swap.py` | fixture | End-to-end token and pair swaps on isolated local chains. |
| `check_bitcoin_local_actions.py`, `check_cardano_local_actions.py`, `check_cardano_preimage_observer.py`, `check_cardano_preview_address.py`, `check_ethereum_deployment.py`, `check_ethereum_escrow_verifier.py` | fixture | Per-chain action, observer and verifier checks. |
| `bitcoin_local_actions.py`, `cardano_local_actions.py`, `hegemon_local_actions.py`, `hegemon_action_runner.py`, `development_wallet_context.py` | fixture | Terminal-approved action builders and runners for peerless local chains. |
| `bitcoin_escrow_verifier.py`, `cardano_escrow_verifier.py`, `verify_ethereum_escrow.mjs`, `export_token_escrow_template.py` | library | Read-only escrow verifiers and the Solidity runtime template exporter (`--check` in the contract docs). |
| `development_atomic_swap_rehearsal.py`, `development_htlc_reorg_rehearsal.py` | fixture | Two-chain rehearsal and reorg recovery on a local Development chain. |
| `check_hegemon_gateway.py`, `check_hegemon_companion_denial.py`, `check_hegemon_preimage_observer.py` | fixture | Interface check for the planned remote Hegemon gateway, wallet-read denial and observer checks. |

## 4. Companions and observers (local, loopback only)

| Path | Role |
|---|---|
| `local_swap_companion.py` | Loopback escrow companion for the hosted page: terminal-approved actions only. `--hegemon-public` is mutually exclusive with `--enable-hegemon-actions` and talks to the v0.11 node; local mode still requires zero peers. `--hosted-node-status` is node status only. `--hosted-wallet-status` is the separate one-wallet totals read used to hard-block an underfunded HGN give; it does not spend. |
| `bitcoin_companion_actions_check.py`, `cardano_companion_actions_check.py`, `hegemon_companion_actions_check.py`, `hegemon_companion_check.py` | Drive the companion through a disposable terminal. |
| `bitcoin_preimage_observer.py`, `cardano_preimage_observer.py`, `hegemon_preimage_observer.py`, `bitcoin_observer_cli_check.py`, `cardano_observer_cli_check.py`, `hegemon_observer_cli_check.py` | Recover a claimed preimage on a local chain, and check each observer CLI. |
| `watch_bitcoin_preimage.py`, `watch_cardano_preimage.py`, `watch_hegemon_preimage.py`, `watch_public_hegemon_preimage.py` | Save an observed preimage as an encrypted backup. |
| `unlock_swap_backup.py` | Unlock the browser's exported preimage backup in a local process. |

## 5. Public-testnet rehearsals (2026 evidence)

These produced the entries in `PUBLIC_TESTNET_RESULTS.md`. Each advance makes at most one public submission and never
retries an uncertain one. They do not check the spacing between the two legs; the engine does, using the policy.

| Path | Status | Note |
|---|---|---|
| `public_btc_eth_rehearsal.py` | superseded | BTC/ETH stage runner. Refund distance raised to 150 blocks to satisfy the driver's policy floor. |
| `public_eth_cardano_rehearsal.py` | superseded | ETH/ADA stage runner. |
| `public_btc_cardano_rehearsal.py` | superseded | BTC/ADA stage runner. Refund distance 150 blocks. |
| `public_samechain_ethereum_rehearsal.py`, `public_samechain_cardano_rehearsal.py` | superseded | Same-chain fixture swaps; the local `check_samechain_*` scripts and the engine cover this. |
| `public_btc_erc20_rehearsal.py`, `public_eth_cardano_token_rehearsal.py` | kept as evidence | Token pair stage runners; refund distance 150 blocks for the Bitcoin leg. |
| `public_bitcoin_refund_rehearsal.py`, `public_cardano_refund_rehearsal.py`, `public_ethereum_refund_rehearsal.py`, `public_cardano_nft_refund.py`, `public_ethereum_nft_refund.py` | kept as evidence | Short refund-path rehearsals. The Bitcoin one passes `rehearsal_short_refund=True` on purpose and is the only caller that may. |
| `public_hegemon_eth_rehearsal.py` | kept as evidence | Single disposable Hegemon/Sepolia swap with Ethereum disclosure first. |
| `verify_public_btc_cases.py`, `public_ethereum_verify.py` | tool | Independent verification of finished cases from public chain data. |

## 6. Wallets, funds and qualification (operator tools; never in CI)

| Path | Role |
|---|---|
| `public_cardano_setup.py`, `public_ethereum_setup.py` | Prepare test actors and mint or deploy disposable fixtures. |
| `public_bitcoin_split.py`, `public_bitcoin_suite.py`, `public_cardano_refuel.py` | Split or refuel test funds; advance prepared Bitcoin cases. |
| `sweep_sepolia_escrows.py` | Refund leftover native Sepolia escrows with a disposable test wallet. |
| `public_sepolia_browser_fixture.py`, `public_sepolia_verifier_fixture.py`, `qualification_signer.py` | Test-only signers and fixtures for hosted-page qualification (`swap-service/qualify/`). Never expose as a service. |
| `submit_ethereum_deployment.mjs` | Local test adapter (loopback only) that the companion uses to submit escrow deployment, funding, claim and refund steps. |

## 7. Build, release and hygiene tools

| Path | Role |
|---|---|
| `setup_multichain_htlc_tools.py` | Install pinned chain tools and build the contracts. |
| `build_client_manifest.mjs` | Rebuild (or `--check`) the integrity manifest, `swap-ui/index.html`, `swap-ui/hosted.html` and the Worker policy. Required after any `swap-ui` edit. |
| `check_swap_secrets.py` | Scan the swap-related files git would commit for private keys, WIF, preimage hex, signed transactions and literal passphrases (`--all` for the whole repository). Part of the fast tier; its allowlist is short and each entry has a reason. |
| `verify_hosted_client.mjs` | Compare a deployed swap page with what this checkout would serve (`--base URL`). |

## 8. Scripts in this directory that are not swap scripts

Release packaging, formal-verification, RP05, SmallWood, native-node and app end-to-end scripts (`check_rp05_*`,
`check_smallwood_*`, `check_v011_*`, `package_v011*_release.py`, `release_*`, `rp05_*`, `smz9_*`, `check-core.sh`,
`dev-setup.sh` and the rest) belong to the protocol and release work and are described in `DESIGN.md`, `METHODS.md`
and `docs/`. `bitcoin_asic_stratum.py` is the Bitcoin80 mining bridge.

## Tests

`test_*.py` files sit beside what they test. The swap series selection is listed in `swap-tiers.sh`
(`SCRIPT_TEST_PATTERNS` plus everything under `swap_engine/`). JavaScript tests are `swap-ui/*.test.mjs` and
`swap-service/**/*.test.mjs`.
