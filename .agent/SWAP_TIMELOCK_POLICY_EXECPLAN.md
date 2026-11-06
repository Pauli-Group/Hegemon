# Cross-chain swap deadline policy (series plan P1)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agent/PLANS.md` and is part of the series described in `.agent/SWAP_SERIES_EXECPLAN.md`.

## Purpose / Big Picture

A swap is safe only if the party who funds second can be sure the party who funds first cannot both claim the second escrow and refund the first one. That depends on how long each chain takes to produce blocks, how many confirmations the verifier waits for, and how fast the counterparty's claim becomes visible. Before this plan the repository had unrelated hard-coded numbers (2 confirmations, 6 Bitcoin blocks, 10 minutes of Cardano margin, 60 seconds on Ethereum, 20 minutes on Sepolia) and no rule that compared the two legs of a swap with each other. After this plan, one tested function says whether a pair of escrows leaves enough time, says why not when it does not, and recommends expiries for a new swap. The browser (`swap-ui/pair-check.mjs`) and Python drivers use the same measured numbers and the same shared test vectors.

This remains a testnet policy. It does not make real-funds swaps safe.

## Progress

- [x] (2026-11-05) Audited every hard-coded timing threshold (table in Context and Orientation).
- [x] (2026-11-05) Measured block timing on Hegemon, Bitcoin testnet4, Cardano preview and Sepolia (script `scripts/measure_chain_timing.py`).
- [x] (2026-11-05) Wrote `swap-ui/timelock-policy.mjs` and the Python mirror `scripts/swap_engine/timelock_policy.py`.
- [x] (2026-11-05) Config `config/swap/chain-timing.json` (Bitcoin and Hegemon tables from `scripts/measure_chain_timing.py --update`), shared vectors `config/swap/timelock-vectors.json` (hand-derived boundary cases), JavaScript tests (11) and Python tests (7): vectors, soundness properties under adversarial gap patterns, plan minimality, mutation tests (every mutation killed).
- [x] (2026-11-05) Wired into `comparePair` (optional `timing` argument), `checkPublicPair`, the Sepolia, Bitcoin and Cardano verifiers (`limits` argument with the old constants kept as floors), `public_bitcoin_driver.fund` and `public_cardano_verify.verify_preview`, the hosted page (`#public-pair-timing`, BRAND.md palette and no new accent), `swap-service/server.ts` allow-list, and a Chromium test (`swap-service/timing-browser.test.mjs`).
- [x] (2026-11-05) Updated `DESIGN.md`, `METHODS.md`, `swap-service/README.md`.
- [x] (2026-11-05) Revised the master plan and plans P2 to P8.

## Surprises & Discoveries

- Observation: the Hegemon chain had a stall of 81,258 seconds (22.6 hours) at height 9,831 within the most recent 3,000 blocks, exactly the testnet stall described earlier. Outside it, the 1-block maximum gap was 913 seconds and the mean 75.7 seconds.
  Evidence: `scripts/measure_chain_timing.py hegemon-pre-mainnet 3000`, measured 2026-11-05.
- Observation: Hegemon can produce 6 blocks in 36 seconds and 12 blocks in 124 seconds. The 14-block minimum lock window the relation enforces (`circuits/transaction/src/private_spend/circuit.rs` line 508) can therefore elapse in about two minutes. It is a replay and anchor guard, not a wall-clock guarantee.
  Evidence: window tables in `config/swap/chain-timing.json`.
- Observation: Bitcoin testnet4 mean block interval over the last 2,000 blocks was about 1,069 seconds (not the ten minutes of mainnet, and not the roughly 520 seconds seen in a smaller earlier sample). Twelve blocks span between 0 and 14,412 seconds. Block heights are a poor unit for deadlines on this network.
  Evidence: same script, `bitcoin-testnet4`.
- Observation: the four contracts do not share claim semantics. Ethereum (`block.timestamp < expiry`) and Cardano (validity range entirely before `expiry`) refuse late claims. Bitcoin's claim branch has no timelock and the Hegemon relation has no upper time bound on a claim, so on those two chains a late claim wins until a refund actually lands. The policy treats the deadline as the end of the safe claim window on every chain.
  Evidence: `contracts/ethereum/TokenHTLC.sol` lines 54, 78, 88; `contracts/cardano/validators/htlc.ak`; script in `swap-ui/bitcoin-testnet-verifier.mjs`; relation lines 508 to 513.
- Observation: a Hegemon refund needs reference height at least the timeout, and a Hegemon reference may lag its inclusion block by up to 12 blocks (DESIGN.md). The earliest inclusion of a refund is therefore block `timeout + 1`. A Bitcoin CLTV refund is first includable at block `locktime + 1` (`nLockTime < block height`). The policy uses refund offset 1 for both.
- Observation: the swap-service suite on Node 24 has failures that predate P1: `browser.test.mjs` aborts with a Node internal assertion after its test passes (identical with P1's changes stashed), and the two desktop tests need a built `hegemon-app/out`.
  Evidence: runs on 2026-11-05; recorded for P7.
- Observation: the public Sepolia RPC reported a head block 95 seconds old, and Cardano preview's 999 recent blocks showed gaps up to 170 seconds (mean 28 seconds). Sepolia's 120 sampled blocks were exactly 12 seconds apart.

## Decision Log

- Decision: derive height-to-time bounds from measured windows, not a distribution. For each window size k (1 to 288 blocks) the config stores the smallest and largest time seen across k consecutive blocks. The slow bound for n blocks is `min over k of ceil(n/k) * max_k` and the fast bound is `max over k of floor(n/k) * min_k`, each scaled by a safety factor (1.25 slow, 0.5 fast). Rationale: no stationarity or independence model is hidden inside a formula, the bounds are provably at least as pessimistic as everything observed, and the tables can be regenerated by one script. Date/Author: 2026-11-05, agent.
- Decision: windows that contain an outage (a single gap over 7,200 seconds) are excluded from the tables and an explicit outage allowance of 7,200 seconds is added to every slow bound. Rationale: otherwise a single historical stall would inflate every number to a day, and the policy would be unusable. The cost is explicit: the policy does not protect a swap against a chain stall longer than the allowance. Hegemon had one such stall (22.6 hours), so a swap with Hegemon on the short leg is exposed to a repeat of it; this must stay in the documentation. Date/Author: 2026-11-05, agent.
- Decision: both legs are judged for both roles (`checkPair` tries each ordering and reports the better one) so the UI does not need to know who is the initiator. Rationale: the verifier only has two escrows and an offer. Date/Author: 2026-11-05, agent.
- Decision: the policy takes integer seconds everywhere. Cardano `expiry_ms` must be a whole number of seconds and is divided by 1,000 by the caller. Rationale: avoids floating point differences between JavaScript and Python. The only floating point left is multiplication of an integer by the factors 0.5, 1.25 and `gapFactor` (1.5), all exactly representable. Date/Author: 2026-11-05, agent.
- Decision: the vectors file uses the same camelCase keys the JavaScript uses, and the Python mirror accepts those keys. Rationale: no translation layer that could diverge. Date/Author: 2026-11-05, agent.
- Decision: keep a byte-identical copy of the config in `swap-ui/chain-timing.json` for the hosted client, with a test that fails if the copies differ. Rationale: the hosted client is a static bundle that cannot read outside `swap-ui/`. Date/Author: 2026-11-05, agent.

## Outcomes & Retrospective

The purpose is met within testnet scope. A pair of escrows is now judged by one rule, in both languages, with numbers from public chains. Measured consequences: Ethereum with Cardano plans in about 1.5 to 2 hours, Hegemon legs need 8 to 35 hours, Bitcoin testnet4 legs 14.7 hours to 5 days, and Bitcoin long with Hegemon short about 20 days. The +144 block Bitcoin margin of earlier rehearsals fails by one block.

What this does not give: protection against a chain stall longer than the two-hour outage allowance (Hegemon had one of 22.6 hours), a claim observer, or real-funds safety. Single-leg floors remain as named constants (`BITCOIN_FLOOR_*`, `CARDANO_FLOOR_*`, `SEPOLIA_FLOOR_*`, `SEPOLIA_ACTION_FLOOR_SECONDS`), and the Python rehearsal scripts keep their literal margins until the P2 engine replaces them. The Cardano Python verifier's test cannot run on this host (Aiken and cardano-cli at `/workspace` paths), so its new defaults were only compile-checked.

Lessons: measure before choosing numbers (the Bitcoin testnet4 mean was twice the figure from a smaller sample); hand-derive boundary vectors so the golden values do not come from the implementation under test; a policy that is honest about block-time variance is inconvenient, and a time-based Bitcoin timelock is worth a design note.

## Context and Orientation

The swap is an HTLC (hash-time-locked contract): an escrow that pays a named recipient if they present the preimage of a hash before a deadline, and otherwise returns to the funder after it. In a two-chain swap one party (the initiator) knows the preimage and funds the long leg first; the other funds the short leg after verifying it, and the initiator claims the short leg, which reveals the preimage on the short chain; the responder reads it and claims the long leg before it can be refunded.

The hard-coded timing literals found by the audit, all to be replaced by this policy:

| Place | Literal |
| --- | --- |
| `swap-ui/cardano-preview-verifier.mjs` lines 28, 35 | 2 confirmations, 600,000 ms margin |
| `swap-ui/bitcoin-testnet-verifier.mjs` lines 30, 33 | 2 confirmations, 6 blocks margin |
| `swap-ui/ethereum-actions.mjs` lines 36, 48, 73, 103 | 60 s margin, 2 confirmations |
| `swap-ui/ethereum-escrow.mjs` lines 49, 81 | 2 confirmations, 60 s margin |
| `swap-ui/sepolia-actions.mjs` line 27 | 1,200 s margin |
| `scripts/public_bitcoin_driver.py` lines 50 to 68 | confirmation and tip margins |
| `scripts/public_*_rehearsal.py` | margins 72, 36, 10,800; expiries +144 blocks, +300 to +21,600 s, slot +300 and +7,200 |
| `scripts/public_cardano_verify.py` line 21 | 60,000 ms remaining |
| `scripts/public_testnet_observers.py`, `hegemon_preimage_observer.py` | 2 confirmations |
| `scripts/local_swap_companion.py`, `private-spend verify-htlc` | min 2 confirmations, min 2 remaining blocks |
| `swap-service/README.md` | documented test thresholds (Sepolia 10 minutes, Bitcoin 6 blocks, Cardano 10 minutes) |

No existing check compared the two legs with each other. `swap-ui/pair-check.mjs` `comparePair` compared assets and hashlocks only.

## Plan of Work

1. `scripts/measure_chain_timing.py` fetches public block timestamps and prints window tables.
2. `config/swap/chain-timing.json` holds the policy numbers, the measured tables (with provenance), the confirmation depths and per-chain inclusion and clock parameters.
3. `swap-ui/timelock-policy.mjs` and `scripts/swap_engine/timelock_policy.py` implement `validateTiming`, bound functions, `checkOrdered`, `checkPair` and `planTimeouts`.
4. `config/swap/timelock-vectors.json` holds the shared cases; both test suites run them. Property tests generate adversarial timing and assert that any accepted pair is safe under a simulation of the worst-case block production, and mutation tests flip each rule in a copy of the policy and assert that a test fails.
5. `comparePair` gains a timing verdict (an extra `timing` field and an error on failure unless explicitly overridden); the hosted verifiers and Python drivers read their margins from the policy; the UI shows the verdict.
6. `DESIGN.md` and `METHODS.md` document the rule, the semantics table and the assumptions.

## Concrete Steps

Run everything from the repository root with Node 24 (`export PATH=$HOME/.local/opt/node-v24.22.2-linux-x64/bin:$PATH`) and `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python`.

    python3 scripts/measure_chain_timing.py hegemon-pre-mainnet 3000
    python3 scripts/measure_chain_timing.py bitcoin-testnet4 2000
    node --test swap-ui/timelock-policy.test.mjs swap-ui/pair-check.test.mjs
    python3 -m unittest scripts.swap_engine.test_timelock_policy

## Validation and Acceptance

Acceptance is that the same vector file passes in both languages, the property tests find no accepted-but-unsafe pair, each mutation is killed, `comparePair` rejects a pair whose gap is too small, and no hard-coded timing literal remains in the verifiers (they import the policy).

## Idempotence and Recovery

The measurement script is read-only. The config is plain data; rerunning the script and regenerating the tables is safe. Nothing here spends funds or touches private journals.

## Artifacts and Notes

See the measured tables in `config/swap/chain-timing.json`.

## Interfaces and Dependencies

In `swap-ui/timelock-policy.mjs`: `validateTiming(config)`, `slowSeconds(chain, n)`, `fastSeconds(chain, n)`, `confirmSeconds(chain, depth)`, `legWindow(config, leg, head, now)`, `checkOrdered(config, {long, short, heads, now})`, `checkPair(config, {a, b, heads, now})`, `planTimeouts(config, {longChain, shortChain, heads, now})`. In `scripts/swap_engine/timelock_policy.py` the snake_case equivalents. A leg is `{chain, expiry}` (block height for Bitcoin and Hegemon, integer seconds for Ethereum and Cardano). A head is `{observedAt, height}` for height chains and `{observedAt, timestamp}` for time chains. A verdict is `{ok, reasons:[{code, message, detail}], metrics, long?}` with codes `bad-input`, `head-stale`, `clock-drift`, `leg-expired`, `claim-window-too-short`, `insufficient-gap`, `horizon-too-long`.
