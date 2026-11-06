# Two-party swap state machine and chain adapters (series plan P2)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agent/PLANS.md` and is part of the series described in `.agent/SWAP_SERIES_EXECPLAN.md`. It builds on `.agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md` (P1), whose policy module this engine calls.

## Purpose / Big Picture

Until now a public swap was a hand-written script per chain pair (`scripts/public_btc_eth_rehearsal.py`, `public_eth_cardano_rehearsal.py`, `public_btc_cardano_rehearsal.py`, `public_samechain_*`). Each script has its own state file, its own ordering, and its own literal safety margins, and none of them checks both legs, enforces the P1 deadline policy, watches for the revealed secret, and decides between claiming and refunding. After this plan one engine, `scripts/swap_engine/engine.py`, runs either side of a swap between any two chains through one small interface (`ChainAdapter`). A person can run `python3 scripts/swap_engine_cli.py init`, `status`, `advance`, `explain` for their side, and the engine will fund, verify, claim or refund one step at a time, and will refuse to do anything that could lose funds when a read fails or a process dies in the middle of a submission.

Terms used here. An HTLC (hash-time-locked contract) is an escrow that pays a named claimant if they present the preimage (the secret) of a published hash before a deadline, and otherwise lets the funder (the refundee) take the money back after the deadline. A swap has two legs. The long leg is funded first by the initiator, who knows the preimage, and is refundable later. The short leg is funded second by the responder and is refundable earlier. The initiator claims the short leg, which publishes the preimage; the responder reads it and claims the long leg. An adapter is the code that speaks to one chain. An inflight action is a submission whose outcome we do not know yet (for example the process died after signing but before it recorded the transaction id). A journal is the private, append-only directory where drivers store each signed transaction before sending it (`scripts/public_swap_journal.py`).

This is testnet software. It does not make real-funds swaps safe; it makes testnet swaps mechanical and crash-safe, and it states its limits (Outcomes).

## Progress

- [x] (2026-11-05) Surveyed the existing drivers, rehearsals, journal discipline and provider failure modes (Context and Orientation).
- [x] (2026-11-05) Wrote this ExecPlan.
- [x] (2026-11-05) Core: `adapter.py`, `store.py`, `engine.py`, `sim.py` (deterministic simulated chains), `planner.py`.
- [x] (2026-11-05) Tests: `test_store.py` (12), `test_engine.py` (31), `test_planner.py` (4), `test_faults.py` (19) including every ordered pair, crash at every numbered point, 60 sampled double crashes and the refund-path crash sweep.
- [x] (2026-11-06) Adapters: Bitcoin, Ethereum, Cardano over a profile interface, Hegemon stub, `test_adapters.py` (23 tests with in-memory providers).
- [x] (2026-11-06) Local fixtures on real software: Anvil, bitcoind regtest, private Cardano cluster. All eight plannable ordered pairs among Bitcoin, Ethereum and Cardano swap through the engine; three refund scenarios pass (`test_local_chains.py`).
- [x] (2026-11-06) Public acceptance run: Ethereum (Sepolia) long, Cardano (preview) short, through `swap_engine_cli.py` with two stores. Both sides `done` in about seven minutes.
- [x] (2026-11-06) CLI `scripts/swap_engine_cli.py`, `DESIGN.md`, `METHODS.md`.
- [ ] Revise the master plan and P3 to P8 (see the revision notes in each plan file).

## Surprises & Discoveries

- Observation: the existing drivers already journal every signed transaction as `prepared_or_submitted` before broadcast, in a directory the caller chooses. This lets the engine decide an inflight action determinately without changing the drivers: if the per-swap journal directory has no record newer than the engine's known transaction ids, nothing was signed and the inflight marker can be cleared; if there is a record, its transaction id can be read from the chain.
  Evidence: `scripts/public_swap_journal.py` (`prepare`) and `scripts/public_testnet_submit.py` (`submit`).
- Observation: claim semantics differ by chain (see P1): Ethereum and Cardano refuse a claim at or after the deadline, Bitcoin and Hegemon do not. The engine therefore needs its own claim cutoff and cannot lean on the chains to refuse late claims.
- Observation: none of Foundry, Bitcoin Core, cardano-cli, Ogmios were installed on this host. `scripts/setup_multichain_htlc_tools.py` pins Foundry, Aiken, cardano-node and solc by SHA-256 and takes `--tools`; it was run with `--tools ~/.local/opt/chain-tools`. Bitcoin Core 32.1 was downloaded separately and checked against the published SHA256SUMS.
- Observation: the P1 planner returns expiries that sit exactly on a step edge of the measured-window tables, so zero slack remains. A head that advances by one block between planning and the counterparty's first action makes the pair non-compliant, and the first simulated pairs aborted with `insufficient-gap`. `planner.plan_with_margin` samples every moment at which a block-count threshold is crossed plus four corner head advances and moves expiries until the policy holds for a margin of one long-leg confirmation plus a reaction time. A property test with random intermediate block counts validates the corner assumption. P3's browser port must port this planner too.
- Observation: Bitcoin/Bitcoin is unplannable under the real config (`horizon-too-long`, `insufficient-gap`): testnet4's measured spans make two Bitcoin legs exceed the 30-day horizon. It is plannable under the local scaled config, where blocks are regular. This is a property of testnet4 timing, not of the engine.
- Observation: the responder's claim of the long leg needs no cutoff (the preimage is already public), while the initiator's claim of the short leg is gated by the policy. A cutoff on the initiator's claim is an equivalent mutant: the claim-window rule already implies it. Recorded in the mutation check.
- Observation: `public_bitcoin_driver.spend_contract` refuses a claim once `tip >= refund_height` and a refund before it, which is stricter than consensus by one block (BIP65 allows the transaction in the block at `refund_height`). The adapter keeps the stricter rule; the policy's `refundOffsetBlocks` of 1 matches it.
- Observation: the public Ethereum RPC cannot show mempool claims, so the preimage is learned from a mined `Claimed` event. It also load-balances across backends that disagree: a receipt can be null for a mined transaction. The adapter treats "no receipt but `eth_getTransactionByHash` shows a block number" as `ChainUnavailable`, not as absent. Historical escrow checks showed `eth_getLogs` pruning, so the adapter falls back to Blockscout.
- Observation: Koios `tx_info` and `tx_cbor` answer `[]` for confirmed transactions while a backend lags, persistently for some older ones (`tx_cbor` returned nothing for two day-old transactions). The adapter requests candidates in one batch, retries, and raises `ChainUnavailable` rather than skipping a transaction; the spender lookup scans the shared script address's history, so it slows as that address collects other swaps' transactions.
- Observation: the historical Cardano escrows from earlier rehearsals carry a native token (FUNG), so the ADA-only adapter correctly reports them as `problem: escrow differs from the terms in value`. The script address computed from `aiken blueprint convert` matches those on-chain escrows exactly, which validates the validator build.
- Observation: a private Cardano cluster with security parameter 5 and active-slot coefficient 0.5 translates slots only about 30 ahead of the tip; a claim whose validity upper bound is the expiry slot fails to submit with `TimeTranslationPastHorizon`. The adapter caps the upper bound at `tip + profile.validity_slots` (an earlier upper bound is always acceptable to the validator). Preview does not need the cap.
- Observation: a failure after journaling but before broadcast (here a wrong cardano-cli subcommand in the local profile) left the engine `inflight` with "the chain does not show it", exactly as designed; this was the recovery path working, and it also shows why submit-side code must be exercised before a public run.
- Observation: tool locations were hard-coded to `/workspace/...` in `public_cardano_transactions.py` and `public_cardano_verify.py`; both now use `swap_engine.tools` (`HEGEMON_CHAIN_TOOLS`, `HEGEMON_TOOL_<NAME>`, `~/.local/opt/chain-tools`).

## Decision Log

- Decision: the engine never rebroadcasts automatically and never signs while an action is inflight. Rationale: `scripts/public_swap_journal.py` rule; a second signature after a lost response can double-spend funds into a different escrow. A human resolves only the ambiguous case (record exists, transaction not found).
- Decision: three-way inflight recovery driven by the journal: no new journal record means nothing was signed, so the marker clears automatically; a record whose transaction the chain knows is adopted; a record the chain does not know stays inflight until `resolve --adopt` or `resolve --abandon`. Rationale: negative reads are never proof of absence on a lagging public provider.
- Decision: adapters report observations as plain data (`LegObservation`) and the decision function is pure over `(record, observations, config, now)`. Rationale: the whole state machine can be enumerated and tested without a chain, and P3 can port the same function and vectors to the browser.
- Decision: each participant has their own record and store; counterparties exchange only escrow references (`receive`), which are untrusted and verified on chain against the terms before use. Rationale: this matches a real two-party swap; a single-process run just holds two stores.
- Decision: preimage handling. The initiator's preimage lives in a separate 0600 file (`secret`), never in the record, logs, arguments or environment. The responder writes the preimage it learns from chain to `learned-preimage` before changing state. The engine accepts a preimage observed before confirmation because it is checked against the hash and the initiator published it deliberately.
- Decision: the engine applies state-only transitions (for example, submitted to confirmed) in a loop from one observation, then performs at most one write per `advance` call.
- Decision: refunds are due by head, not by wall clock: height chains at `head.height >= expiry + refundOffsetBlocks`; time chains at the chain head's block timestamp `>= expiry`. Rationale: the contract decides, and the head comes from the chain.
- Decision: tool locations (`anvil`, `forge`, `bitcoind`, `cardano-cli`, `aiken`, `ogmios`, solc) come from the environment variable `HEGEMON_CHAIN_TOOLS` (a directory) with per-tool overrides, not `/workspace/...` literals, in all new code.
- Decision: adapters take a profile object (network access, signed send, clock) and keep verification, calldata, scripts and log parsing in shared code. Local-fixture runs therefore exercise the same adapter logic as public runs and differ only in the profile. Rationale: P2 step 5 asked for local-fixture coverage of the real adapters, not of look-alikes.
- Decision: the local chains use real software with a scaled timing config (`local_world.local_timing()`), not a mocked clock, because Cardano's clock cannot be virtual. Nothing in the engine is relaxed for it.
- Decision: the plan's idea of a `sepolia.py` adapter and `test_local_fixtures.py` became `ethereum.py` (serves Sepolia and Anvil) and `test_local_chains.py`.
- Decision: the Hegemon adapter in this plan is a stub that refuses all writes; the real adapter belongs to P6 and P8.

## Outcomes & Retrospective

What exists: one engine runs either side of a swap between Bitcoin, Ethereum and Cardano (Hegemon is a stub) through a nine-method adapter contract, with a durable per-swap store, journal-based crash recovery, a planner that survives head drift, and a CLI. 97 tests run in about 18 seconds without any chain (store, engine, planner, simulated-chain faults and crashes, adapters against in-memory providers, the P1 policy). `HEGEMON_LOCAL_CHAINS=1` runs the real adapters against Anvil, bitcoind regtest and a Cardano cluster: all eight plannable ordered pairs completed with balances checked, and the responder-never-funds, initiator-vanishes (Bitcoin/Ethereum and Cardano/Bitcoin) refund scenarios ended with both sides refunded. One public swap ran for real (Artifacts).

What it does not do. It does not authenticate the counterparty; terms are exchanged out of band. It does not rebroadcast or fee-bump, so a transaction that never confirms leaves the swap waiting until a human acts. It cannot see Ethereum mempool claims. The Cardano spender lookup depends on Koios indexing and slows as the shared script address grows. Bitcoin/Bitcoin is refused by the planner. The local Cardano profile records what it submitted because no transaction index or Ogmios exists on this host. The Hegemon leg is not implemented. The public run covered one pair and the happy path; the public refund paths were exercised only on local chains and simulated chains.

Lessons for the later plans are in the Revision sections at the end of each plan file.

## Context and Orientation

All paths are relative to the repository root. Python 3.10; the Python dependencies (eth-account, eth-abi, embit and others) live at `~/.local/opt/hegemon-swap-python`, so run tests as `cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_<name>`. Node 24 is at `~/.local/opt/node-v24.22.2-linux-x64/bin`.

The package `scripts/swap_engine/` already holds `timelock_policy.py` (P1). Its functions used here: `load_timing()` reads `config/swap/chain-timing.json`; `check_ordered(config, long, short, heads, now)` judges two legs and returns `{ok, reasons, metrics}` with reason codes `bad-input`, `head-stale`, `clock-drift`, `leg-expired`, `claim-window-too-short`, `insufficient-gap`, `horizon-too-long`; `plan_timeouts(config, long_chain, short_chain, heads, now)` picks compliant expiries; `leg_window` and `action_seconds` give the claim cutoff. A leg is `{'chain': name, 'expiry': int}` with chain names `bitcoin`, `hegemon`, `ethereum`, `cardano`; a head is `{'observedAt', 'height'}` for height chains and `{'observedAt', 'timestamp'}` for time chains. Expiry units: Bitcoin refund height and Hegemon timeout in blocks; Ethereum expiry and Cardano expiry in integer seconds (Cardano `expiry_ms // 1000`).

Driver catalogue (what each adapter wraps, surveyed 2026-11-05):

- Journal and submission: `public_swap_journal.prepare(directory, chain, raw)` writes `<chain>-<txid>.signed` and `.json` (state `prepared_or_submitted`) exclusively in a private 0700 directory with fsync; `public_testnet_submit.submit(directory, chain, raw)` verifies the network, journals, then broadcasts, returning `{'chain', 'txid', 'confirmed': False, 'state': 'submitted'}`.
- Bitcoin testnet4: `public_bitcoin_driver.fund(journal, key_file, hashlock, claimant, refund_height, amount)` and `spend_contract(journal, key_file, txid, vout, amount, hashlock, claimant, refund, refund_height, preimage=None)` (claim with preimage, refund without; refund needs locktime). `public_bitcoin_transactions.contract/funding/spend` build scripts. `public_testnet_observers.bitcoin_claim` reads the claim and returns the preimage. Fee provider fallback and HTTP 429 handling are in `public_testnet_probe.request` and `public_bitcoin_driver._fee`.
- Sepolia: `public_sepolia_driver.send(journal, wallet, to, value, data)` (contract creation with `to=None`, `claim(bytes32)`, `refund()` calls), `public_ethereum_verify.verify_native(contract, hashlock, claimant, refundee, expiry, amount, confirmations=2)`, `public_testnet_observers.ethereum_claim`. The default RPC prunes logs older than about 12,000 blocks; Blockscout is the fallback. Lagging reads raise "snapshot or chain changed" or "block not found" and are transient.
- Cardano preview: `public_cardano_transactions.build_balanced(...)` builds a fee-settled raw body with script input, collateral and required signer; fee inputs must be ADA-only because the helper preserves tokens only through the change output; `public_cardano_driver.sign_and_submit(journal, body, signing_key)`; `public_cardano_verify.verify_preview(...)`; `public_testnet_observers.cardano_claim`; `public_testnet_utxos.cardano_utxos`; Koios may return a transaction before its CBOR is indexed (`IndexerDataPending`, transient).
- Rehearsal template: `public_btc_eth_rehearsal.py` and `public_eth_cardano_rehearsal.py` show the flow the engine generalizes: a per-scenario state file, a lock file, a separate secret file, `_begin` setting `<action>_inflight` before every submission, and `advance` refusing to run while inflight.

## Plan of Work

The design is three layers. `adapter.py` defines the `ChainAdapter` contract and the error types. `store.py` is the durable, locked, private per-swap directory. `engine.py` holds the pure decision function `decide(record, observation, config, now)` and the executor `advance(store, adapters, now)`.

The contract. An adapter object belongs to one participant and one chain. It provides `chain` (policy name), `identity()` (the local party's public identity string for this chain), `head()` returning a head dict, `inspect(leg, escrow)` returning a `LegObservation` dict, `fund(leg, journal)`, `claim(leg, escrow, preimage, journal)`, `refund(leg, escrow, journal)` each returning `{'txid': ..., 'escrow': {...}}` where only `fund` returns the escrow reference, and `journal_ids(journal)` listing the transaction ids in the per-swap journal. Errors: `ChainUnavailable` (a read failed; retry later), `ActionRefused` (a write was refused before signing; nothing happened), and any other exception from a write is treated as uncertain and resolved through the journal. A `LegObservation` has `found`, `verified`, `problem`, `confirmations`, `spent` (`None`, `claimed`, `refunded`), `spend_confirmations`, `spend_txid`, and `preimage` (hex or None).

The record. `record.json` in `<root>/<swap_id>/` holds `version`, `swap_id`, `role`, `state`, `terms_digest`, `escrows`, `txids`, `inflight`, `needs_human`, `seq`, `history`. `terms.json` is written once. The legs are `long` and `short`; each leg has `chain`, `amount`, `refundee`, `claimant`, `expiry`. The initiator funds `long` and claims `short`; the responder funds `short` and claims `long`.

States and transitions are enumerated in `engine.TRANSITIONS` and rendered by `swap_engine_cli.py explain`. Initiator: `terms_saved`, `long_fund_submitted`, `long_funded`, `short_verified`, `short_claim_submitted`, `done`, with `refund_submitted` and `refunded` branches. Responder: `terms_saved`, `long_verified`, `short_fund_submitted`, `short_funded`, `preimage_known`, `long_claim_submitted`, `done`, with the same refund branches. `aborted` is terminal and means nothing was funded. `failed` is terminal and means the counterparty beat the policy (for example the long leg was refunded before the responder could claim it) and funds were lost or stuck, with the observation attached.

Safety gates, all enforced by `decide`: before funding, `check_ordered` must be ok on fresh heads (a transient code, `head-stale` or `clock-drift`, waits; a deterministic code aborts only when nothing is funded); before claiming, the leg must still be verified and unspent and the claim cutoff `leg_window(...)['firstRefund'] >= action_seconds(chain)` must hold; the engine never funds twice (a recorded fund transaction id blocks a second fund forever); an unexpected spend sets `needs_human`.

The simulated chain harness (`sim.py`) implements the four claim and refund rule sets with controllable block production, mempool, confirmations, reorgs (dropping a transaction), provider read failure, lagging heads, and lost write responses; it also records every fund, claim and refund so tests can assert conservation of value and absence of double funding. A `CrashHook` counts crash points (before and after each store write, around each adapter write, inside the simulated adapter between journal and broadcast) and raises a `BaseException` subclass at a chosen point so a test can kill a participant at every point and resume.

## Concrete Steps

From the repository root:

    cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest discover -s swap_engine -p 'test_*.py'

The expected output is `OK` with the engine, store, fault-injection and crash tests in addition to the P1 policy tests. For local fixtures:

    export HEGEMON_CHAIN_TOOLS=$HOME/.local/opt/chain-tools
    cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_local_fixtures

The CLI, for a single-process public run with two stores (initiator and responder), is documented by `python3 scripts/swap_engine_cli.py --help` and in `METHODS.md`.

## Validation and Acceptance

Crash-at-every-point tests never lose funds or double-submit: for every crash point in a full simulated swap (both roles, all pairs of chain kinds), resuming ends with both legs claimed or both refunded, no escrow funded twice, total value conserved. All local pair fixtures pass through the engine, or the plan states exactly which could not run and why. One real public-testnet swap completes through the engine with confirmed transaction ids recorded in Artifacts.

## Idempotence and Recovery

`advance` is safe to call repeatedly and after a kill at any point. Stores are private directories, records are replaced atomically, and the lock file serializes processes. `init` fails if the swap id exists. A human can clear an ambiguous inflight action with `resolve --adopt` or `resolve --abandon` after inspecting the chain; both write a history entry.

## Artifacts and Notes

Public acceptance swap (2026-11-06, swap id `75fabdeba3d82e1f`, started 00:45 and finished 00:52 local time), Ethereum Sepolia long leg and Cardano preview short leg, driven by `scripts/swap_engine_cli.py` with separate initiator and responder stores:

    Alice funds the Sepolia escrow   1b5998c2c89252fc0e64beee2c937ce8d7a920f316cb77a671d27b73ae2c8aa0  (block 12074590, contract 0x3aeb87e73b88236425829b1f9ab7b7a9f31af84c, 0.001 ETH)
    Bob funds the Cardano escrow     3554254f12e6aaec3ecff4991db8fdd3428315c730945defa2532fbfc06f307d  (10 ADA)
    Alice claims the Cardano escrow  37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d
    Bob claims the Sepolia escrow    3998d2dad84aca5e06857457608be68790177abab66a539e63a6e41c76ed9c7f  (block 12074618)

Both records ended `done`. Planned expiries came from `plan_with_margin` on live heads: long (Sepolia) about 5,700 seconds ahead, short (Cardano) about 3,660 seconds ahead. A search of both stores, the run log and the wallet configs for the preimage found no copy outside the two 0600 `secret` and `learned-preimage` files. Bob learned the preimage from Alice's confirmed Cardano claim through Koios `tx_cbor`.

Local runs: eight happy-path swaps (Bitcoin/Ethereum, Bitcoin/Cardano, Ethereum/Bitcoin, Ethereum/Ethereum, Ethereum/Cardano, Cardano/Bitcoin, Cardano/Ethereum, Cardano/Cardano) in about 165 seconds including start-up; refund scenarios Ethereum/Cardano (responder never funds), Bitcoin/Ethereum and Cardano/Bitcoin (initiator vanishes; both refund) in about 18 minutes.

Commands: `cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_store swap_engine.test_engine swap_engine.test_planner swap_engine.test_faults swap_engine.test_adapters swap_engine.test_timelock_policy` for the chain-free suite, and the same with `HEGEMON_LOCAL_CHAINS=1 ... swap_engine.test_local_chains` for the real local chains.

## Interfaces and Dependencies

Python modules under `scripts/swap_engine/`: `adapter.py` (contract, `ChainUnavailable`, `ActionRefused`, `JournaledWrites`), `store.py`, `engine.py`, `planner.py`, `sim.py`, `tools.py`, `local_world.py`, and `adapters/` (`ethereum.py`, `bitcoin.py`, `cardano.py`, `hegemon_stub.py`, and the local profiles `local_ethereum.py`, `local_bitcoin.py`, `local_cardano.py`). Tests: `test_store.py`, `test_engine.py`, `test_planner.py`, `test_faults.py`, `test_adapters.py`, `test_local_chains.py` (needs `HEGEMON_LOCAL_CHAINS=1`). CLI `scripts/swap_engine_cli.py`. The adapter contract: `identity()`, `head()`, `inspect(leg, escrow)`, `fund(leg, journal)`, `claim(leg, escrow, preimage, journal)`, `refund(leg, escrow, journal)`, `escrow_ref(leg, txid)`, `journal_ids(journal)`, `transaction_seen(txid)`; hash is sha256 on every chain. Reads `config/swap/chain-timing.json`. Depends on the existing `scripts/public_*` drivers and the Python packages at `~/.local/opt/hegemon-swap-python`.
