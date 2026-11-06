---
name: P4 Bitcoin public cases
overview: Plan 4 of 8. Finish the remaining public Bitcoin testnet4 swap and refund cases and the pending Sepolia fixture refund, using recovered private state and the new engine where possible.
todos:
  - id: p4-status
    content: Determine status of each open case and check against P1 margins
    status: pending
  - id: p4-pending
    content: Confirm pending Bitcoin claim and refund transactions
    status: pending
  - id: p4-btc-ada
    content: Finish BTC/Cardano claim
    status: pending
  - id: p4-btc-tokens
    content: Finish BTC/ERC-20 and BTC/Cardano-token swaps
    status: pending
  - id: p4-sepolia-refund
    content: Refund Sepolia fixture escrow and record it
    status: pending
  - id: p4-verify
    content: Independent verification and PUBLIC_TESTNET_RESULTS.md entries
    status: pending
  - id: p4-sweep
    content: Recover remaining testnet funds and confirm no live escrows
    status: pending
  - id: p4-docs
    content: Regression tests and DESIGN.md/METHODS.md updates
    status: pending
  - id: p4-revise
    content: Revise plans P5..P7 based on what was learned
    status: pending
isProject: false
---

# Plan 4 of 8: Finish the public Bitcoin cases

Gated on P0 (state recovered or fresh wallets decided). Uses P1 policy, and P2 engine or P3 UI where they are ready.

## Open items (from `.agent/PUBLIC_TESTNET_SWAP_EXECPLAN.md` and `PUBLIC_TESTNET_RESULTS.md`)

- BTC/Cardano: both escrows confirmed and unspent (Bitcoin `d15914d8...`, Cardano `fe1d5bd4...`); Cardano claim confirmed, Bitcoin claim submitted, confirmation pending.
- BTC/ERC-20 and BTC/Cardano-token: funding transactions submitted/confirmed, claims not recorded.
- Bitcoin refund: funding `1e8a4ff8...`, refund `0bdc0319...` submitted once to the secondary service, confirmation pending.
- Sepolia browser fixture escrow `0x25b3e3f95ccd58ba022e6c00271f8a1f7cf4737d`: refund after expiry not recorded.
- Already complete and not to be redone: BTC/ETH native.

## Rules for every action

- Never blind-retry a broadcast. Check the journal, txid, UTxO and mempool on two providers before resuming from any `inflight` state.
- Keep private state outside the repo; commit only public IDs and observations.
- Respect provider limits (Blockstream 429): reads fall back to the genesis-checked secondary indexer; broadcasts remain single-submission.

## Steps

1. Re-read the P0 inventory and P1 verdicts for each case. If P1 shows a case used margins below policy, decide per case: finish as-is (testnet fixture) or abandon and refund, and document why.
2. Resolve determinate state for each case via read-only checks; write the findings into `PUBLIC_TESTNET_SWAP_EXECPLAN.md` progress.
3. Complete in deadline order (soonest refund window first): confirm pending Bitcoin claim/refund; finish BTC/Cardano claim; finish BTC/ERC-20 and BTC/Cardano-token claims; refund the Sepolia fixture.
4. Use the P2 engine for any case not already past its point of no return, otherwise the existing `public_bitcoin_suite.py` step runner with its action lock and journal checks. If P3 is ready, finish at least one claim from the hosted UI with a real wallet.
5. For each completed case verify independently: confirmed funding and claim/refund transactions on both chains, preimage matching the shared hashlock, recipient and amount correct. Record IDs in `PUBLIC_TESTNET_RESULTS.md`; an unconfirmed submission is reported as unconfirmed.
6. If the original wallets are unrecoverable: use fresh disposable wallets and faucet funds, rerun the four cases via the engine with policy-compliant deadlines, and record the abandoned escrows as unrecoverable.
7. Recover and consolidate remaining testnet funds; confirm no escrow remains live.
8. Run regression tests; update `DESIGN.md` and `METHODS.md` swap sections.

## Acceptance

- Every public pair from BTC x {ETH, ERC-20, ADA, ADA token} has a completed claim path, and Bitcoin refund is confirmed, each with verified transaction IDs and payout checks.
- Zero escrows remain live or unknown.

## Revisions from earlier plans

Revision from P0 (2026-11-05) changes this plan from "finish the cases" to "verify and record cases that already appear finished". See the Baseline Report in `.agent/SWAP_SERIES_EXECPLAN.md`.
- All four prepared Bitcoin escrow outputs (funding txs `d15914d8...`, `1e8a4ff8...`, `f08a5eda...`, `5d477028...`) are spent at height 158797: the refund `0bdc0319...` has refund-branch shape, and the three other spends (`5888dafe...`, `9808daec...`, `7bbadc74...`) have claim-branch shape. The Cardano BTC/ADA escrow `fe1d5bd4...#0` is spent and the validator address holds no UTxOs. The Sepolia fixture `0x25b3e3f9...` was refunded by `0x94f5bfa9...4a03fdca7` (block 12057283). No escrow known from public data is live, so there is no deadline pressure.
- Revised steps: (1) for each of the three claims, verify the preimage hashes (SHA-256) to the escrow's hashlock and that the paired leg used the same hashlock and paid the intended recipient; (2) identify the BTC/ERC-20 and BTC/Cardano-token paired legs from the private journals (requires the user's decryption of `hidden/hegemon-historical-testnet-journals-20261105.tar.gz.gpg`); if unavailable, record those legs as unverified; (3) record the Sepolia fixture refund and all confirmed IDs in `PUBLIC_TESTNET_RESULTS.md` and mark the matching items done in `.agent/PUBLIC_TESTNET_SWAP_EXECPLAN.md` and `.agent/HOSTED_TESTNET_SWAPS_EXECPLAN.md`; (4) sweep leftover wallet funds (needs the wallets archive); (5) only if a case cannot be verified, rerun it with the P2 engine and policy-compliant deadlines on fresh wallets.
- Use Blockscout for old Sepolia history; the default public RPC prunes it. Use mempool.space or Blockstream for Bitcoin testnet4 reads, with the existing fallback logic.
- The "refund the Sepolia fixture" todo is already done on chain; the remaining work is recording it.

Second revision from P0 (2026-11-05, after decrypting the private journals; supersedes step (2) above):
- No decryption is needed from the user any more. The journals are restored at `~/.hegemon-private/restore/historical-testnet-journals-20261102` (0700; contains preimages and signed transactions, never print or commit). The paired legs are identified in the Baseline Report of `.agent/SWAP_SERIES_EXECPLAN.md`: BTC/ERC-20 uses escrow `0xf2fd8e0441a15ee14aa56114c3d759293de4027f` (lock `a81e42b5...`, claim `04ed607d...`); BTC/Cardano-token uses Cardano lock `b1c66f35...` and claim `5761d261...`; BTC/ADA uses Cardano lock `fe1d5bd4...` and claim `5ef1932a...`.
- Already verified in P0 with public data: all 86 journaled transactions confirmed; every Sepolia escrow `spent() == true`; the Cardano validator address holds no UTxOs; the four Bitcoin claim preimages SHA-256 to their scenario hashlocks.
- Remaining P4 work is therefore: verify each non-Bitcoin paired leg (same hashlock, intended recipient, exact amount, claim order and timing versus the P1 policy), record all IDs and observations in `PUBLIC_TESTNET_RESULTS.md`, tick the stale items in the two older ExecPlans, and run the regression tests. The funds sweep is optional: wallets still hold about 0.15 ETH, about 19,977 ADA and 94,748 satoshis, which should fund P2's acceptance run.
- Do not extract the journals archive over `~/.local/share/hegemon-testnet-wallets-20261104`. The journals README says newer wallet state exists only there.

## Last step: revise later plans

Update the master ExecPlan and edit P5..P7:
- P5: provider-trust incidents seen (429s, lagging reads, unindexed data) that the relay or verifiers should surface.
- P6: any timing observations on Bitcoin that affect Hegemon pairing.
- P7: final public matrix to document and any scripts now obsolete.
