---
name: P4 Bitcoin public cases
overview: Plan 4 of 8. Finish the remaining public Bitcoin testnet4 swap and refund cases and the pending Sepolia fixture refund, using recovered private state and the new engine where possible.
todos:
  - id: p4-status
    content: Determine status of each open case and check against P1 margins
    status: completed
  - id: p4-pending
    content: Confirm pending Bitcoin claim and refund transactions
    status: completed
  - id: p4-btc-ada
    content: Finish BTC/Cardano claim
    status: completed
  - id: p4-btc-tokens
    content: Finish BTC/ERC-20 and BTC/Cardano-token swaps
    status: completed
  - id: p4-sepolia-refund
    content: Refund Sepolia fixture escrow and record it
    status: completed
  - id: p4-verify
    content: Independent verification and PUBLIC_TESTNET_RESULTS.md entries
    status: completed
  - id: p4-sweep
    content: Recover remaining testnet funds and confirm no live escrows
    status: completed
  - id: p4-docs
    content: Regression tests and DESIGN.md/METHODS.md updates
    status: completed
  - id: p4-revise
    content: Revise plans P5..P7 based on what was learned
    status: completed
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

Revision from P1 (2026-11-05):
- The measured policy rejects the +144 block refund margin used by the earlier Bitcoin rehearsals by one block (`policy_limits()` in `scripts/public_bitcoin_driver.py` is now 145 blocks from the tip). Those escrows are already spent, so nothing needs to be redone, but P4's retroactive verdicts should state which historical pairs would have failed the policy and why. Only the Bitcoin refund-case scenario used the short +6 margin; other scenarios used +144 or timestamp margins, so do not describe all earlier cases as very short.
- Any new Bitcoin run must take expiries from `plan_timeouts`, not hand-chosen. Measured testnet4 behavior (2,000 blocks): mean 1,069 s per block, 24-block spans from 2,699 s to 28,824 s, 144-block spans from 46,275 s to 151,329 s. A Bitcoin short leg therefore locks funds for 14.7 hours to 5 days, and a Bitcoin long leg for the same 14.7 hours to 5 days against an Ethereum or Cardano short leg and up to about 20 days against a Hegemon short leg. Decide before spending whether to accept those waits or add a time-based (MTP) Bitcoin timelock variant, which would give the Bitcoin leg a wall-clock deadline like Ethereum and Cardano. That variant changes the script and the verifier, so it needs its own design note and vectors.
- Heights are read through the 2-block provider-lag assumption; keep the existing fallback provider logic, and add the observed head height to every journal record so verdicts can be recomputed later.

Revision from P2 (2026-11-06):
- The engine and `BitcoinAdapter` now cover fund, claim and refund for a Bitcoin swap leg over the same `public_bitcoin_transactions` code as `public_bitcoin_suite.py`. New Bitcoin swap cases should run through `swap_engine_cli.py` with `Testnet4Profile`; keep `public_bitcoin_suite.py` for the cases the engine does not express (splits, refund rehearsals, ERC-20 and token legs). Both use `public_swap_journal`, so journals interoperate.
- Bitcoin/Bitcoin is unplannable under the real config (`horizon-too-long` and `insufficient-gap`); do not schedule a same-chain Bitcoin swap. Bitcoin as the short leg needs a refund height at least about 145 blocks (about two days) out, and as the long leg more; expect waits of days and use `plan_with_margin` expiries, never the +144 block margin.
- The adapter keeps the driver's strict rule: a claim is refused once `tip >= refund_height`, a refund before it. The policy's `refundOffsetBlocks` is 1, so the engine considers a Bitcoin leg refundable one block after the height.
- Wallet constraint found on 2026-11-06: Alice has Bitcoin outputs of 48,000 and 21,499 sats, but Bob's four confirmed outputs are 1,250 sats each, so Bob can fund only an escrow of exactly one output minus the spend fee (the driver needs `amount + fee` to equal the output or leave at least 546 sats of change), about 1,000 sats at the minimum fee. Top up Bob or have Alice fund the Bitcoin leg.
- The Bitcoin adapter sees a claim that sits in the mempool (Esplora `outspend` shows it with zero confirmations) and reads the preimage from its witness, checking sha256 against the hashlock first.

Revision from P3 (2026-11-06):
- The hosted page can now finish Bitcoin testnet4 fund, claim and refund without any script: it builds the PSBT, an external signer signs it, and the page finalizes and broadcasts through `POST /bitcoin-testnet4/broadcast`. On 2026-11-06 the hosted page, driven through the qualification harness, funded, claimed and refunded real testnet4 escrows (transaction ids in `PUBLIC_TESTNET_RESULTS.md`). For P4 this means a Bitcoin case can be run from the UI instead of `public_bitcoin_suite.py`, but the UI path covers only one HTLC per action: it has no fund-split step, no ERC-20/token-leg coordination and no engine journal, so splits and refund rehearsals stay with the scripts and engine-run swaps stay with `BitcoinAdapter`.
- `scripts/qualification_signer.py btc-sign --wallet KEYFILE` is an independent embit PSBT signer (it refuses inputs that do not belong to the key and refuses a key that is not one of the script's two keys); reuse it as the second implementation when verifying P4 transactions.
- The Worker's Bitcoin reads use Blockstream only (no mempool.space fallback), and answered `provider unavailable or inconsistent` repeatedly from this host until Node's connect-attempt timeout was raised (`net.setDefaultAutoSelectFamilyAttemptTimeout(5000)`); expect the same flakiness in P4 runs that go through the Worker and record such incidents rather than retrying silently.
- Block arrival was uneven during qualification: tip 159444 at about 16:20 UTC on 2026-11-06, 159456 at about 17:14, 159457 between 17:22 and 17:32 and 159464 by about 18:08; header timestamps are not a reliable clock on testnet4. A two-confirmation wait took about 12 to 50 minutes and a refund funded at tip+3 (17:15) was broadcast at about 18:00; plan P4 budgets waits as tens of minutes to hours.
- The page refuses a claim whose refund height is less than 145 blocks away (the P1 policy); P4 cases that want a UI claim need a refund height at least that far out, which for a refund exercise means waiting days. Exercise refunds on a second escrow with a near height and a claim on a far one, as the harness does.
- The funding PSBT's inputs must all be the user's `address` coins and every ECDSA signature must be `SIGHASH_ALL`; Bob's four 1,250-sat outputs are still too small to fund an escrow, so Alice funds Bitcoin legs.

## Last step: revise later plans

Update the master ExecPlan and edit P5..P7:
- P5: provider-trust incidents seen (429s, lagging reads, unindexed data) that the relay or verifiers should surface.
- P6: any timing observations on Bitcoin that affect Hegemon pairing.
- P7: final public matrix to document and any scripts now obsolete.
