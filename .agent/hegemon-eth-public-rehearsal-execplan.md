# Run a staged Hegemon–Ethereum public-testnet rehearsal

This living plan follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Alice and Bob are disposable test participants whose wallet files are on the
operator's computer. This plan prepares one native HGN/Sepolia ETH swap using
the existing local pre-mainnet Hegemon relay, without mining or a full Ethereum
node. Alice locks HGN for Bob; Bob locks Sepolia ETH for Alice; Alice claims
the ETH, revealing a preimage; Bob reads that confirmed Ethereum claim and uses
the preimage to claim HGN. A separate, later path must exercise a Hegemon claim
as the first public disclosure. This initial direction does not use the
incomplete public Hegemon preimage observer as a claim gate.

The operator controls each step from the computer containing the wallets and
retains encrypted Hegemon refund material. Every potentially broadcast or
wallet-mutating step is recorded before it starts. An interrupted step is
uncertain and requires local inspection; the runner must never automatically
reprove or resubmit. Both chains and public providers are trusted; confirmation
counts and fixed testnet time margins are not finality or production safety.

## Progress

- [x] (2026-11-04 23:47Z) Confirmed existing Hegemon harnesses require an
  isolated Development node and must remain unchanged.
- [x] (2026-11-04 23:47Z) Chose Ethereum-first disclosure for the initial
  rehearsal; it can use the existing exact-contract Ethereum claim reader.
- [x] (2026-11-05 00:03Z) Implemented the local Hegemon wallet adapter with
  confidential PTY prompts, source identity checks and canonical inclusion.
- [x] (2026-11-05 00:03Z) Implemented and synthetically tested the staged
  Ethereum-first HGN/ETH workflow, including refund material, uncertain-action
  refusal and explicit testnet timing limits. Refund execution is manual.
- [x] (2026-11-05 01:00Z) Corrected the incompatible executable requirement:
  the official v0.11.2 binary lacks the branch's `verify-htlc` command. The
  runner now checks a trusted branch build's capability and pins its digest.
- [ ] Run the funded rehearsal on the operator's computer when available, and
  record only public receipts and measured proof time and peak memory.
- [ ] Implement and independently test the Hegemon-first observer binding and
  additional Bitcoin/Cardano, reverse-direction and refund scenarios.

## Surprises & Discoveries

The previous scripts create and mine their own Development nodes, so changing
their endpoint would cross an intentional network boundary. Hegemon stores the
refund note in an encrypted handoff that must be retained and imported into
Alice's wallet. Bob needs a separate ordinary HGN fee note. The public wallet
prints a 32-byte preparation attempt ID and a distinct 48-byte action ID.
The existing public Hegemon observer does not bind a claim to an exact note and
must not authorize the other leg. Ethereum-first disclosure avoids using it.
The wallet's refund import binds its handoff to the exact canonical lock
statement and note occurrence. Importing it before verifying Bob's view gives
Alice an authenticated recovery record even if Bob's verification fails.
The earlier runner pinned the official release executable while invoking a
verification command added only in this branch. No live rehearsal was started;
the corrected runner requires a branch build and checks it before wallet use.

## Decision Log

- Decision: keep the public driver separate and never start or mine a node.
  Rationale: the operator already has a trusted, synced loopback relay and has
  explicitly chosen not to mine. Date/Author: 2026-11-04 / Codex.
- Decision: persist an inflight phase before each wallet mutation or broadcast;
  require manual recovery from any uncertain phase. Rationale: a timeout may
  happen after a proof or transaction was retained or sent. Date/Author:
  2026-11-04 / Codex.
- Decision: exercise Ethereum disclosure first and verify its exact escrow and
  confirmed claim before claiming HGN. Rationale: this avoids treating the
  incomplete Hegemon observer as proof of a particular note's spend.
  Date/Author: 2026-11-04 / Codex.
- Decision: require an operator-trusted branch-built `private-spend` with
  `verify-htlc`, and pin its digest when the rehearsal starts. Rationale: the
  official v0.11.2 executable cannot perform the necessary verification and a
  locally recorded digest prevents accidental replacement, but proves no build
  provenance. Date/Author: 2026-11-05 / Codex.

## Outcomes & Retrospective

The adapter and Ethereum-first workflow pass offline fixture tests; a real
source-built wallet also completed offline bootstrap and address recovery via
the PTY adapter. No funded public Hegemon swap has yet run, and refund execution
remains manual. Existing public Bitcoin, Ethereum and Cardano results are in
`PUBLIC_TESTNET_RESULTS.md` and do not establish Hegemon behavior.

## Context and Orientation

`scripts/probe_hegemon_testnet.py` pins the release manifest, network, wallet
methods and, optionally, a trusted recent public explorer tip. The branch-built
`private-spend` 0.11.2 wallet syncs against the operator's loopback
node, keeps HGN notes and prepared actions in encrypted wallet files and can
prepare, export, submit, verify or refund an HTLC. Its prompts require a
private terminal; its `status` output includes private note positions and must
stay local. `scripts/public_sepolia_driver.py` signs locally and journals an
Ethereum transaction before one submission. `scripts/public_ethereum_verify.py`
verifies an exact native escrow, while `scripts/public_testnet_observers.py`
extracts a preimage from a specified confirmed Ethereum claim. These scripts
trust their configured data sources and are testnet tools, not light clients.

## Milestones and Plan of Work

First implement and test the Hegemon adapter: accept only a local loopback URL,
require pinned release checks and fresh trusted reference, run the verified
release wallet with a private PTY, parse bounded output without logging secrets,
and determine canonical inclusion using the exact saved action ID and bytes.
Preserve at least two confirmations and detect chain changes. Then implement a
separately journaled state machine for HGN/ETH. Before ETH can be locked, it
must verify the intended Hegemon lock and save/import Alice's encrypted refund
handoff. Before the preimage is revealed on Ethereum, it must recheck both legs
and conservative remaining time margins. The HGN claim must use the observed
Ethereum preimage, not an assumed response. Finally test failure, reorg, stale
node, wrong terms and uncertain-submission behavior with offline fixtures.

## Concrete Steps

From the repository root, run `python3 -m unittest discover -s scripts -p
'test_public_hegemon_wallet.py'` and repeat for
`test_public_hegemon_eth_rehearsal.py`, with dependencies from
`scripts/requirements-htlc-public.txt`. Re-run the existing public Hegemon
probe, observer and public-submission tests. Run `git diff --check`. These
synthetic tests do not submit transactions. The operator procedure is in
`runbooks/hegemon_eth_public_rehearsal.md`.

## Validation and Acceptance

A full synthetic rehearsal must reach both claims only when the exact Hegemon
and Ethereum terms are verified. Wrong networks, a stale or reorganized chain,
wrong note or contract, inadequate balances or deadlines, and interrupted or
uncertain actions must stop without a duplicate submission. Public receipts
must not contain keys, passphrases, or an unrevealed preimage. A successful
live test requires canonical receipts and both expected payouts; fixture tests
alone cannot establish it.

## Idempotence and Recovery

Every action has a durable predecessor phase, so repetition of a pending poll
does not sign or send again. An interrupted proof or submission requires
inspection of the wallet attempt, private journal and chain by the operator;
the program will not guess. Refund handoff and the secret backup remain local.

## Artifacts and Notes

Wallets are disposable public-testnet wallets. The operator must use only one
copy of them at a time and keep private files outside Git. The Hegemon node and
public Ethereum service remain trust assumptions. Record proof time and peak
resident memory when possible; record if a platform cannot measure them.

## Interfaces and Dependencies

Use a trusted branch-built v0.11.2 `private-spend` executable, the frozen manifest and
release identity, and existing Python public-testnet utilities. The new runner
must run on the operator's machine and never request private keys through chat.
The public Hegemon observer remains a separate experimental component.

Revision 2026-11-05: recorded the tested adapter and Ethereum-first driver;
actual public Hegemon validation and automated refunds remain outstanding.

Revision 2026-11-05: replaced the incompatible official executable requirement
with a source-build capability check and per-rehearsal digest pin.
