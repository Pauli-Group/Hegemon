---
name: P6 Hegemon offline adapter
overview: "Plan 6 of 8. Make the engine ready for Hegemon without the public testnet: a real local adapter over the private-spend flow tested on isolated chains, a remote-gateway spec, and a measured, separately-branched proving-cost investigation."
todos:
  - id: p6-execplan
    content: Write .agent/SWAP_HEGEMON_ADAPTER_EXECPLAN.md
    status: pending
  - id: p6-adapter
    content: Implement hegemon_local adapter with inflight/timeout/resume handling
    status: pending
  - id: p6-timing
    content: Feed proof time and lock minimum into the P1 policy
    status: pending
  - id: p6-e2e
    content: Local engine swaps for all HGN pairs plus refund, missing-counterparty and late-claim scenarios
    status: pending
  - id: p6-identity
    content: Hegemon identity field, local-only
    status: pending
  - id: p6-gateway
    content: Document scoped remote gateway design and interface check, no deployment
    status: pending
  - id: p6-proving
    content: Proving-cost harness and profile on a separate branch from main
    status: pending
  - id: p6-docs
    content: DESIGN.md and METHODS.md updates
    status: pending
  - id: p6-revise
    content: Revise plan P7 and define the follow-up for when public Hegemon testnet returns
    status: pending
isProject: false
---

# Plan 6 of 8: Hegemon offline adapter and proving cost

Depends on P1, P2 and P5. The Hegemon public testnet is stalled, so everything here runs on isolated local chains.

## Constraints

- On this branch the circuit, wallet, node and protocol source must stay identical to main (see `.agent/LOCAL_PRIVATE_SPEND_SWAP_EXECPLAN.md`); only `wallet/src/bin/private_spend.rs` and `private_spend_build.rs` differ. Proving optimizations therefore go on a separate branch from main, never into this one.
- Measured cost: lock and claim about 62 s and about 1.7 GB RSS, 179 s and 2.0 GB under load. Minimum lock window is 14 blocks (runner uses 16).
- Rely on `DESIGN.md` and `METHODS.md` for private-spend and HTLC rules; consult them before touching anything.

## Part A: real local Hegemon adapter for the engine

1. Write `.agent/SWAP_HEGEMON_ADAPTER_EXECPLAN.md`.
2. Implement `scripts/swap_engine/adapters/hegemon_local.py` wrapping `scripts/hegemon_action_runner.py`, `hegemon_local_actions.py`, `local_private_spend_swap.py` and `watch_hegemon_preimage.py`:
   - `verify_escrow` through the `private-spend` verification command;
   - `fund`/`claim`/`refund` through prepare then submit, with the encrypted refund handoff stored under the engine record directory (0700) and its passphrase never logged;
   - `observe_claim` from canonical action bytes (both bytearray and bytes handled);
   - long-running proofs modelled as an `inflight` state with a hard timeout and a determinate resume check (wallet status), because a lost response may still have submitted.
3. Apply P1 timing parameters: proof time and lock minimum feed the fund and claim cutoffs.
4. Local end-to-end: Hegemon dev chain with Bitcoin regtest, Anvil and local Cardano, running engine swaps HGN/BTC, HGN/ETH, HGN/ERC-20, HGN/ADA, HGN/Cardano-token; plus refund, missing-counterparty and late-claim scenarios mirroring the existing `local_private_spend_swap.py` cases. Fresh output directories only; stop owned processes; zero peers.
5. Identity: attach the Hegemon field reserved in P5, flagged as local-only until a key scheme exists.

## Part B: remote gateway specification (no public deployment)

6. Write a short design in `DESIGN.md` for a scoped, authenticated gateway so users need not run a full node: the minimal methods (chain tip, note sync for a given viewing key, verify escrow, submit prepared action), explicit exclusion of the unsafe wallet RPC, privacy and trust assumptions (the provider learns wallet activity metadata). Add a probe-compatible interface check next to `scripts/probe_hegemon_testnet.py`. Do not implement or expose anything publicly.

## Part C: proving cost investigation (separate branch from main)

7. Create a branch from main. Build a repeatable measurement harness (wall time and peak RSS via `wait4`, as the existing runner does) for lock, claim and refund, and profile where time and memory go in the private-spend proof path (`circuits/transaction/src/smallwood_htlc.rs` and related).
8. Report findings with numbers; implement only low-risk wins that do not change proof statements or the frozen relation; any change to the relation or parameters needs its own ExecPlan and review per the repo's proof-system rules.
9. Record before/after and the effect on P1's Hegemon timing numbers.

## Acceptance

- Engine completes local swaps for every HGN pair and the three failure scenarios, with crash-resume tests for the Hegemon inflight state.
- Gateway design is documented and checked against the repo's wallet RPC restrictions.
- Proving report is on its own branch; this branch's circuit source is still identical to main.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- Local Hegemon end-to-end runs also need Bitcoin Core (`bitcoind` 32.x, expected by `local_private_spend_swap.py` at `/workspace/bitcoin-32.1/bin/bitcoind`), Foundry's `anvil` and cardano tooling, none of which are installed on this host. Step 4 therefore depends on the tool installation added to P2; the Hegemon-only parts (adapter code, fake-chain tests, gateway design, proving harness) can proceed first.
- Proving-cost measurements need a Rust toolchain build of `hegemon-node` and `private-spend` (cargo is present); budget for roughly 2 GB of RAM per proof and several minutes per run.

## Last step: revise later plans

Update the master ExecPlan and edit P7:
- P7: Hegemon adapter docs, the new test targets (which are heavy and must be opt-in), runbook items (`HEGEMON_SEEDS` with the approved seed list, NTP/chrony requirement), and what must be re-planned when the public Hegemon testnet returns (the first follow-up plan after P7).
