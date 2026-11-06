---
name: P2 Swap state machine
overview: Plan 2 of 8. Build one reusable, crash-safe two-party swap engine with chain adapters for Bitcoin, Ethereum, Cardano and a Hegemon stub, replacing the pairwise one-off rehearsal scripts.
todos:
  - id: p2-execplan
    content: Write .agent/SWAP_ENGINE_EXECPLAN.md
    status: completed
  - id: p2-survey
    content: Catalogue driver calls and known failure modes to wrap
    status: completed
  - id: p2-core
    content: Implement adapter interface, durable store and pure transition engine
    status: completed
  - id: p2-faults
    content: Simulated-chain fault-injection and crash-at-every-state tests
    status: completed
  - id: p2-adapters
    content: Wrap Bitcoin, Sepolia, Cardano drivers; add Hegemon stub and fake
    status: completed
  - id: p2-local
    content: Local-fixture swaps for all pairs and same-chain cases through the engine
    status: completed
  - id: p2-public
    content: One real public-testnet swap via the engine
    status: completed
  - id: p2-cli-docs
    content: CLI, DESIGN.md and METHODS.md updates
    status: completed
  - id: p2-revise
    content: Revise plans P3..P7 based on what was learned
    status: completed
isProject: false
---

# Plan 2 of 8: Two-party swap state machine

Depends on P0 and P1 (deadline policy). Feeds P3 (UI), P4 (Bitcoin runs), P6 (Hegemon adapter).

## Problem

Public swaps today are pairwise scripts (`scripts/public_btc_eth_rehearsal.py`, `public_eth_cardano_rehearsal.py`, `public_btc_cardano_rehearsal.py`, `public_samechain_*`, and `public_bitcoin_suite.py`), each with its own state file and ordering. Nothing generically verifies both legs, enforces deadline margins, observes the revealed preimage and drives claim or refund. The plans call this the main gap ("These manual actions do not coordinate a swap").

## Design

New package `scripts/swap_engine/` (kept alongside the existing flat scripts, which stay working).

- `adapter.py`: a `ChainAdapter` interface: `head()`, `verify_escrow(terms)`, `fund(terms)`, `claim(terms, preimage)`, `refund(terms)`, `observe_claim(terms)`, plus `finality(txid)`. Implementations wrap the existing, tested drivers instead of rewriting them: `public_bitcoin_driver.py`, `public_sepolia_driver.py`, `public_cardano_driver.py`, `public_testnet_observers.py`, `public_*_verify.py`.
- `adapters/hegemon_stub.py`: interface-conformant stub plus an in-memory fake used by tests. The real adapter is P6.
- `store.py`: durable per-swap record using the same discipline as `scripts/public_swap_journal.py` (private 0700 directory, exclusive writes, fsync, `prepared_or_submitted` before any broadcast, never retry a broadcast automatically). Holds terms, role, chain identities, hashlock; the preimage is kept separate and never logged.
- `engine.py`: a pure transition function `(record, observations, policy) -> next_action`, and an executor that performs at most one action per `advance` call and then persists. `inflight` always blocks automation until a human or a determinate chain read resolves it.
- Policy checks come from P1 before funding and before claiming.
- Roles: initiator (knows preimage, funds long leg, claims first) and responder.

```mermaid
stateDiagram-v2
    [*] --> TermsSaved
    TermsSaved --> InitiatorFunded: policy ok, fund long leg
    InitiatorFunded --> ResponderVerified: verify long leg and margins
    ResponderVerified --> ResponderFunded: fund short leg
    ResponderFunded --> InitiatorVerified: verify short leg
    InitiatorVerified --> InitiatorClaimed: claim short leg (preimage public)
    InitiatorClaimed --> ResponderObserved: observe preimage
    ResponderObserved --> ResponderClaimed: claim long leg
    ResponderClaimed --> Done
    InitiatorFunded --> Refunding: deadline, no counterparty
    ResponderFunded --> Refunding: deadline, no claim
    Refunding --> Refunded
    TermsSaved --> Aborted
    InitiatorFunded --> Inflight: lost response
    ResponderFunded --> Inflight: lost response
    Inflight --> InitiatorFunded: determinate read resolves
```

## Steps

1. Write `.agent/SWAP_ENGINE_EXECPLAN.md`; consult `DESIGN.md` and `METHODS.md`.
2. Read the existing drivers and rehearsals to catalogue the exact calls each adapter needs and the failure modes already handled (HTTP 429 fallback, Koios unindexed CBOR, Sepolia lagging reads, Cardano fee-input token preservation).
3. Implement the adapter interface, store and engine with a deterministic simulated-chain harness first.
4. Fault-injection tests: lost submission response, provider 429, reorg that drops a funding or claim, process kill and restart at every persisted state (enumerate all transitions), counterparty never funds, counterparty claims at the last allowed moment, preimage observed before confirmation.
5. Wrap the real Bitcoin, Sepolia and Cardano adapters and run local-fixture swaps (Anvil, bitcoind regtest, local Cardano) for every pair and both same-chain cases. Reuse `htlc_counterpart.py` fixtures.
6. Re-express one existing public scenario (BTC/ETH native) as an engine scenario and, once P0/P4 confirm funds, run it for real on testnets as the acceptance run. Keep the old scripts and their tests.
7. Add a CLI `scripts/swap_engine_cli.py` (`init`, `status`, `advance`, `explain`) with no secrets in args or logs.
8. Update `DESIGN.md` and `METHODS.md`.

## Acceptance

- Crash-at-every-state tests never lose funds or double-submit.
- All local pair fixtures pass through the engine.
- One real public-testnet swap completes via the engine with confirmed transaction IDs recorded.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- Add a first step: install or locate Foundry (`anvil`, `forge`), Bitcoin Core 32.x, cardano-cli/cardano-node and Ogmios. None are on this host, so local-fixture swaps (step 5) and the six Python test files that need them cannot run until then. Aiken exists at `~/.aiken/bin/aiken`.
- Adapters and fixtures must read tool locations from configuration or environment variables, not the hard-coded `/workspace/chain-tools/...` and `/workspace/bitcoin-32.1/...` paths now in `scripts/test_public_*.py` and the scripts they import.
- Ethereum adapter needs an explorer fallback (Blockscout `https://eth-sepolia.blockscout.com/api/v2`) for events and receipts older than about 12,000 blocks, because the default public RPC prunes them.
- The public acceptance run (step 6) uses fresh disposable wallets unless P0's private-state decryption succeeds and leftover funds are sufficient. P0 shows no known live escrows, so there is no recovery pressure.
- Second revision from P0 (2026-11-05): the private journals are recovered at `~/.hegemon-private/restore/historical-testnet-journals-20261102` (0700, secrets inside). Use their shapes (86 `prepared_or_submitted` records, `state.json` phases `complete`/`submitted`) as ground truth for the store and fault-injection tests, copying only structure, never secrets. The existing public wallets hold about 0.15 ETH, about 19,977 ADA and 94,748 satoshis, enough for the public acceptance run, so no new faucet funds are needed; the active wallet directory is `~/.local/share/hegemon-testnet-wallets-20261104`.
- Bitcoin claim and refund transactions observed on testnet4 are the reference shapes for the Bitcoin adapter: claim witness is signature, 32-byte preimage, true selector, script; refund witness is signature, empty selector, script, with locktime set.

Revision from P1 (2026-11-05):
- The policy module already exists: `scripts/swap_engine/__init__.py` and `scripts/swap_engine/timelock_policy.py` (tests: `cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_timelock_policy`). Do not recreate the package. The engine's "policy ok" gates call `check_pair` / `check_ordered` before funding and before claiming, `plan_timeouts` to choose the expiries of a new swap, and `leg_requirements` for single-leg verification. Config is `config/swap/chain-timing.json`; read it with `load_timing()`.
- Expiry units the engine must pass: Bitcoin `refund_height`, Hegemon `timeout` (block heights); Ethereum `expiry` and Cardano `expiry_ms // 1000` (integer seconds, Cardano must be a whole number of seconds). Heads: `{observedAt, height}` for height chains and `{observedAt, timestamp}` for time chains, so `ChainAdapter.head()` must return the block height or the latest block timestamp plus the local observation time. Verdict codes the engine must handle: `bad-input`, `head-stale`, `clock-drift`, `leg-expired`, `claim-window-too-short`, `insufficient-gap`, `horizon-too-long`.
- Add a claim cutoff to the engine: refuse a claim when `leg_window(...)['firstRefund'] < action_seconds(chain)` for that leg, because the counterparty could refund first. Bitcoin and Hegemon accept a late claim until a refund lands, so the engine, not the chain, must enforce the cutoff.
- Step 6 (first real public run) should use Ethereum with Cardano, not Bitcoin: the policy plans that pair in about 1.5 to 2 hours. A swap with a Bitcoin testnet4 leg needs a short-leg window of 14.7 hours to 5 days, and a Hegemon leg needs 8 to 35 hours, because those chains' block times vary so widely. Plan the Bitcoin and Hegemon runs for later and budget the waiting.
- The Python rehearsal scripts keep their own literal margins; the engine replaces them rather than editing them. `public_bitcoin_driver.fund` and `public_cardano_verify.verify_preview` now read the policy and the former rejects a refund height under 145 blocks from the tip, so adapters that wrap them inherit the stricter floor.

## Last step: revise later plans

Update the master ExecPlan and edit P3..P7:
- P3: the state schema and transition vectors the browser reducer must match, and a decision on whether the UI embeds a JS port or talks to a local engine process.
- P4: whether Bitcoin cases should be finished with the engine or with `public_bitcoin_suite.py`.
- P5: which identity fields (addresses per leg) the record needs to bind.
- P6: the exact `ChainAdapter` contract and Hegemon-specific inflight needs.
- P7: scripts now superseded and test entry points to add.
