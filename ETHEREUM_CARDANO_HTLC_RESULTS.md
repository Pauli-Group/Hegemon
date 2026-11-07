# Ethereum and Cardano HTLC swap results

Implemented and tested on branch `local-private-spend-htlc`, implementation commit `b0cffb76`. All eight local Hegemon paired scenarios passed, plus nine Solidity tests and ten Aiken tests.

Hegemon's circuit, shared prover, wallet, node, protocol and Cargo source match main at `74910ff86514c2cbd93d7a7039e6b90b6e4600b6`. The node and private-spend binary hashes and relation digest match across all eight cases. No htlc-wip prover changes were carried over.

| Scenario | Ethereum | Cardano |
|---|---|---|
| Successful swap | PASS | PASS |
| Counterpart never funded; HGN refunded | PASS | PASS |
| Both funded legs refunded | PASS | PASS |
| Counterpart claimed; HGN refunded; late HGN claim rejected | PASS | PASS |

## What executed

Ethereum uses `contracts/ethereum/HegemonHTLC.sol` on a fresh Anvil chain with native ETH. Cardano uses the actual Aiken-compiled Plutus V3 validator in `contracts/cardano/validators/htlc.ak` on a fresh private, single-stake-pool cardano-node network with native ADA. These Cardano results include submitted and confirmed ledger transactions, not just unit evaluator runs. Each scenario owns new Hegemon genesis identity, wallets and chain data.

Alice locks HGN for Bob. Bob escrows one ETH or ten ADA for Alice. In the happy case Alice's confirmed claim reveals the 32-byte SHA-256 preimage, and Bob's HGN claim uses the recovered bytes. Hegemon locks 100,000 atoms and uses a separate fee input. Successful exported Hegemon action bytes were matched exactly to canonical block actions and wallet mined state; the resulting note value was checked.

The counterpart checks cover wrong-secret and unauthorized claims, premature refunds and repeated spends. Dual-refund cases verify exact counterpart payouts after expiry and the HGN return. Late HGN claims fail at the wallet after synchronizing the canonical refund, with `unspent private note absent at position`; this is not an adversarial forged-proof test. Solidity tests additionally cover exact expiry boundaries. Aiken tests cover correct preimage with the wrong signer, short secrets, intervals spanning expiry and unbounded intervals. Cardano repeated-spend checks construct another spend of the consumed input; resubmission of identical transaction bytes can be idempotently acknowledged.

Ethereum checks mined receipt status, canonical block hash, additional local blocks and exact payout including sender gas. It extracts the preimage from the confirmed claim event. Cardano observes the expected output UTxOs for two additional blocks, checks escrow input consumption and exact ten-ADA payout, and recovers the preimage from the submitted signed witness bound by the confirmed body's script-data hash. This observer uses the submitted transaction and local ledger state; an independent historical block indexer and reorg recovery remain outside this runner.

Hegemon reported zero peers. Anvil has no P2P chain network; its owned process had no non-RPC established TCP connections. Cardano used empty topology with ledger peer discovery disabled and no established TCP connections. All owned test nodes stopped after the scenarios. Neither public network was synced.

## Resource measurements

Each proof process uses two Rayon workers. Linux wait4 supplies child high-water RSS; elapsed time includes unlock and sync. The Ethereum and Cardano suites shared CPU, so these are observed functional-run measurements, not controlled prover regression benchmarks. Node memory is separate.

| Chain | Proof operation | Observed seconds | Peak RSS range, GiB |
|---|---|---:|---:|
| ethereum | fund-bob | 86.5–156.9 | 1.653–1.726 |
| ethereum | lock | 106.4–141.8 | 1.600–1.904 |
| ethereum | claim | 170.8–170.8 | 1.655–1.655 |
| ethereum | refund | 91.7–144.3 | 1.655–1.717 |
| cardano | fund-bob | 112.7–174.3 | 1.602–1.994 |
| cardano | lock | 114.2–150.9 | 1.602–2.000 |
| cardano | claim | 128.5–128.5 | 1.842–1.842 |
| cardano | refund | 68.8–165.5 | 1.654–1.814 |

## Reproduce and inspect

See `contracts/README.md` for installation, pinned tool versions and commands.

    python3 -m pip install -r scripts/requirements-htlc-local.txt
    python3 scripts/setup_multichain_htlc_tools.py
    TOOLS="${HEGEMON_CHAIN_TOOLS:-$HOME/.local/opt/chain-tools}"
    mkdir -p -m 700 "$HOME/hegemon-runs"
    "$TOOLS/foundry/forge" test --root contracts/ethereum --use "$TOOLS/solc" -vv
    "$TOOLS/aiken/aiken-x86_64-unknown-linux-musl/aiken" check contracts/cardano
    python3 scripts/local_multichain_htlc_swap.py --chain ethereum --output "$HOME/hegemon-runs/new-ethereum-run"
    python3 scripts/local_multichain_htlc_swap.py --chain cardano --output "$HOME/hegemon-runs/new-cardano-run"

Use new output paths. Existing Hegemon binaries must have the Development features described in the README. Raw private output of the recorded runs was in `/workspace/eth-htlc-run1` and `/workspace/ada-htlc-run1` on the original build host and is not part of this repository; those directories contain disposable private keys and passphrases. Public receipts, unit-test results, source/tool hashes and complete proof measurements are retained in `.agent/ETHEREUM_CARDANO_HTLC_RESULTS.json`.

These tests advance shortened local deadlines. They do not establish public-chain timeout margins, confirmation/finality policy, production readiness or an independent security audit. They implement native-asset HTLC swaps and do not mint wrapped assets or operate a bridge.
