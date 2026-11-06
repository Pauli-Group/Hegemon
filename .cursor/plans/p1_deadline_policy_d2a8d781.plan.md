---
name: P1 Deadline policy
overview: Plan 1 of 8. Replace the ad hoc timeout thresholds with one tested cross-chain deadline policy shared by the Python engine and the browser UI.
todos:
  - id: p1-audit
    content: Audit and list all hard-coded timing thresholds in verifiers, drivers and docs
    status: completed
  - id: p1-execplan
    content: Write .agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md
    status: completed
  - id: p1-config
    content: Add config/swap/chain-timing.json with sourced per-chain parameters
    status: completed
  - id: p1-impl
    content: Implement JS and Python policy modules with shared vectors
    status: completed
  - id: p1-tests
    content: Unit, property (adversarial timing) and mutation tests
    status: completed
  - id: p1-wire
    content: Wire into pair-check and hosted verifiers; show verdict in UI per BRAND.md
    status: completed
  - id: p1-docs
    content: Update DESIGN.md and METHODS.md
    status: completed
  - id: p1-revise
    content: Revise plans P2..P7 based on what was learned
    status: completed
isProject: false
---

# Plan 1 of 8: Cross-chain deadline policy

Depends on P0 (Node 24 baseline). Consumed by P2 (engine), P3 (UI), P6 (Hegemon timing).

## Problem

Current thresholds are arbitrary test values: 10 minutes remaining, 6 blocks before Bitcoin refund, 2 confirmations, a 20-minute deploy threshold. `swap-ui/deadlines.mjs` only watches a single deadline, and `swap-ui/pair-check.mjs` (`comparePair`) matches assets and hashlocks but explicitly does not check relative timing. The per-chain deadline semantics also differ:

- Bitcoin: `after(HEIGHT)` (CLTV, block height). testnet4 block times are highly variable.
- Ethereum: `block.timestamp >= expiry` (see `swap-ui/ethereum-actions.mjs`, refund check).
- Cardano: validity interval in POSIX ms mapped to slots.
- Hegemon: block height; private-spend minimum lock is 14 blocks (runner uses 16), and a lock/claim proof takes about 62 s (179 s under load) with about 1.7 to 2.0 GB RSS.

## Design

- A single data file `config/swap/chain-timing.json` holds per-chain parameters: expected block interval, pessimistic block interval (for height-to-time conversion), confirmation depth considered safe, worst-case submission-to-inclusion latency, clock/provider skew allowance, and (Hegemon) proof-generation time.
- Two implementations of the same pure functions, `swap-ui/timelock-policy.mjs` and `scripts/swap_engine/timelock_policy.py` (module location finalised in P2), validated against shared test vectors `config/swap/timelock-vectors.json`, so the engine and UI cannot diverge.
- Functions:
  - `planTimeouts(pair, now, heads)`: given an initiator-long leg and responder-short leg, return concrete expiries.
  - `checkMargins(legs, heads)`: verdict plus machine-readable reasons (insufficient gap, too little time left to fund, too little time left to claim).
  - `claimCutoff(leg)` and `fundCutoff(leg)`: last safe moment to act, in native units and wall-clock bounds.
- Core rule: the leg claimed second (the long leg, whose preimage is revealed by the first claim) must outlive the short leg by at least: confirmation time of the short-leg claim on its chain, plus preimage observation latency, plus claim inclusion time on the long chain, plus skew on both chains, plus a safety factor. Convert heights to time using the pessimistic interval on the side where that is conservative.
- The initiator (who knows the preimage) funds the long leg first; the responder verifies before funding the short leg; the initiator must claim the short leg before its cutoff.

## Steps

1. Read `DESIGN.md` and `METHODS.md` swap sections and the existing verifier thresholds in `swap-ui/*-verifier.mjs`, `swap-service/README.md` and the public drivers; list every hard-coded threshold to replace.
2. Write `.agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md` (per `.agent/PLANS.md`).
3. Add `config/swap/chain-timing.json` with sourced numbers (measured testnet block intervals, the Hegemon receipts in `LOCAL_PRIVATE_SPEND_SWAP_RESULTS.md`).
4. Implement the JS and Python policy modules and the shared vectors.
5. Tests: unit vectors per chain pair (BTC/ETH, BTC/ADA, ETH/ADA, same-chain, Hegemon pairs); property tests that simulate adversarial timing (counterparty claims at the last allowed moment, provider lag, skew at bound) and assert the responder can always claim or refund safely whenever the policy accepts; mutation tests that tighten each margin term and confirm a vector fails.
6. Wire into `swap-ui/pair-check.mjs` so `comparePair` returns a timing verdict, update the hosted verifiers to use policy constants instead of literals, and show the verdict in the UI (follow `BRAND.md` for any visual change).
7. Update `DESIGN.md` and `METHODS.md` with the rule and its assumptions; keep the statement that testnet timing is not a real-funds safety guarantee.

## Acceptance

- Same vectors pass in Node 24 and Python.
- Tightening any margin makes a vector fail (mutation check).
- `comparePair` rejects a pair with an insufficient gap in a browser test.
- No remaining unexplained timing literals in the verifiers.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- Existing public cases used very short margins (for example Bitcoin refund locktime 158789 against funding at height 158786). Expect the new policy to reject them; treat them as fixtures, not compliant examples.
- Calibrate Bitcoin testnet4 timing from real data: heights 158680 to 158797 span block times 1793678145 to 1793738646, about 520 seconds per block on average with large variance (several blocks can land in the same minute, e.g. height 158797 held a refund and three claims). Use a pessimistic interval for height-to-time conversion, not 600 seconds.
- Sepolia public RPC prunes history older than about 12,000 blocks, so measured Ethereum intervals and receipts must come from an explorer API (Blockscout) when older than that.
- Node 24 is at `~/.local/opt/node-v24.22.2-linux-x64/bin`; Python deps are at `~/.local/opt/hegemon-swap-python` (use `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python`). Details in `.agent/SWAP_SERIES_EXECPLAN.md`.

## Last step: revise later plans

Update the master ExecPlan and edit P2..P7:
- P2: the exact policy API the engine calls, and the final module path.
- P3: UI messages and verdict shape.
- P4: whether the existing public Bitcoin cases fail the new margin (they used short test deadlines); decide whether to rerun with compliant deadlines.
- P6: the Hegemon timing parameters (proof time, lock window) the adapter must honor.
- P7: documentation items.
