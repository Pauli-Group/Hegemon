# Hegemon offline adapter, gateway design and proving cost (series plan P6)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agent/PLANS.md` and is part of the series described in `.agent/SWAP_SERIES_EXECPLAN.md` (plan 6 of 8). It builds on P1 (timelock policy), P2 (swap engine), P3 (hosted wallets), P4 (public Bitcoin cases) and P5 (relay identity).

## Purpose / Big Picture

The two-party swap engine (`scripts/swap_engine/`) can run either side of a swap between Bitcoin, Ethereum and Cardano, but its Hegemon adapter is a stub that refuses every write. The Hegemon public testnet is stalled, so nothing here may touch it. This plan makes the engine ready for Hegemon anyway: a real local adapter over the private-spend wallet (`private-spend`, source of truth for the HTLC relation) that is tested end to end on isolated chains; a written design for a scoped remote gateway so users need not run a full node; and a measured, separately branched investigation of the proving cost that dominates every Hegemon leg.

After this plan an engineer can run `python3 -m swap_engine.local_world hegemon ethereum` (and every other Hegemon pairing) and watch two people swap real private-spend HGN for a real asset on another local chain, with the same planner, journal, inflight discipline and policy checks as the public runs, plus refund, missing-counterparty and late-claim runs; read the gateway design in `DESIGN.md`; and read a proving report with numbers on its own branch.

Terms. The *private-spend wallet* is `target/release/private-spend`, a PTY-driven CLI: secrets are typed at a no-echo prompt. An *attempt* is a prepared (proved) action the wallet keeps until it is submitted or cancelled; its 32-byte id is printed as `candidate <64 hex>`. An *action id* is the 48-byte id the node acknowledges on submit (`submitted <96 hex>`). A *locked note* is the HTLC note created by `lock`; it is identified by its commitment-tree *position*, which is the same number in every wallet that holds it. The *claimant* wallet learns of the locked note by syncing (it is encrypted to the claimant); the *refund* wallet holds it only after importing the encrypted *refund handoff* that `lock --refund-handoff` writes. A *profile* is the adapter's description of one network (RPC, wallet runner, clock, journal name).

## Progress

- [x] (2026-11-06) Survey code and write this plan (p6-execplan).
- [x] (2026-11-06) `scripts/swap_engine/adapters/hegemon_local.py` (HegemonAdapter, loopback and attached profiles, local world profile) with journal-before-submit, inflight and resume handling; `hegemon_fake.py`, `hegemon_wallet.py` and `test_hegemon_adapter.py` (p6-adapter).
- [x] (2026-11-06) Local Hegemon timing (`local_world.hegemon_timing`, Erlang windows, post-run span validation), lock floor and `lock-window-short` gate in the shared policy with updated vectors (p6-timing).
- [x] (2026-11-06) Local engine swaps: happy swaps for all six Hegemon pairs (HGN with Ethereum, Bitcoin and Cardano, both orders) pass through the engine in 277 to 651 s; no_counterparty (HGN long), both_refund (ETH long, HGN short) and late_claim (ETH long, HGN short; the late claim is refused by the chain) end with the right states and balances in 2.3 to 2.7 hours each, with fixture-window excursions recorded; HGN against an ERC-20 and a Cardano native token pass only through the older scripted harness (p6-e2e). Results: `.agent/SWAP_HEGEMON_ADAPTER_RESULTS.json`.
- [x] (2026-11-06) Hegemon identity field, local-only (p6-identity).
- [x] (2026-11-06) Remote gateway design in `DESIGN.md` and `scripts/check_hegemon_gateway.py` with tests (p6-gateway).
- [x] (2026-11-06) Proving cost harness, measurements and report on branch `proving-cost-p6` (p6-proving).
- [x] (2026-11-06) `DESIGN.md` and `METHODS.md` (p6-docs).
- [x] (2026-11-06) Revised the master plan and the P7 plan, including the heavy test targets, runbook items and the public-testnet backlog (p6-revise).

## Surprises & Discoveries

- A mined-as-fast-as-possible local chain is unusable. Hegemon retargets every 10 blocks toward 60 s with a 4x clamp, so mining the ~136 blocks needed for reward maturity overshoots the difficulty to about 4.9e8 (one thread about 1.6 MH/s) and the next blocks take minutes. The fix is a one-time template (`build-template`) that mines to maturity and lets the difficulty settle; every world copies it. Block time then really is about 60 s, so a local Hegemon refund takes about two hours and cannot be sped up.
- The planner's default margin ignored the responder's cost of funding a Hegemon short leg (a one minute proof plus two 60 s confirmations). A local Bitcoin-long, Hegemon-short swap reached `insufficient-gap` and the initiator refused to claim. `default_margin` now adds `proveSeconds` plus the short leg's confirmation time when the short chain needs a proof. The fix exposed a second bug: `_bump` guessed 600 s per block when a chain had no measured mean, which advanced a 3 s regtest chain one block per round until the search limit. It now uses the fastest windows.
- The old `late_claim` scenario only worked because of the margin bug: the initiator never claimed, by accident. With the margin fixed the initiator claimed and the swap completed. The scenario now stops the initiator once the responder has submitted the short funding, as `both_refund` does.
- Window validation by every sliding span is stricter than the policy's per-span guarantee. A 1e-3 tail per span over hundreds of overlapping spans makes an excursion likely, and running three long worlds in parallel on a busy host produced long stalls (blocks 500 to 2000 s apart) and, at the start of a run, faster-than-model spans. Results now carry `swap_ok` (the swap's own outcome) beside `ok` (outcome and windows).
- Feature unification and source identity: the wallet refuses a chain whose manifest pins a different relation digest, and the digest hashes the bytes of `circuits/transaction/src/smallwood_engine.rs`. An instrumented prover cannot join an existing chain, and any prover source optimisation is a protocol change.
- Prover cost is structural: 98% of a proof is the DECS commitment over 2^23 leaves (about 11 GB of SHA-512 input). Threads are the only low-risk lever: 65 s at 2 threads, 44 s at 4, 37 s at 8, 119 s at 1; peak memory 1.5 to 1.7 GiB.
- A world's `LocalHegemonProfile.start_mining` after a settle must use a third miner address, or Alice's and Bob's balances move on their own and the before/after balance check is meaningless.

## Decision Log

- Decision: the adapter reuses `scripts/local_private_spend_swap.wallet()` for every wallet call. It already feeds secrets through a no-echo PTY, enforces a 600 second ceiling, records `wait4` peak RSS, and writes a per-call log. Reason: that is the code that produced the recorded local results, and keeping one runner keeps one place for the secret-handling rules.
- Decision: the journal records the *attempt id* (64 hex) as the transaction id, and journals the exported action bytes before submit. The wallet's prepare step proves for minutes and stores the attempt; export writes the exact signed bytes; submit broadcasts them. The engine's inflight marker is therefore set across the whole prove, journal and submit sequence, and the journal file is written after the proof exists and before any broadcast, as `swap_engine.adapter` requires (a pre-proof intent is never journaled, because it cannot be resumed). A crash before the journal write leaves no record, so the engine clears the marker and the wallet's stale attempt is cancelled on the next write; a crash after it leaves a record the engine adopts once the chain shows the action, and the adapter's `transaction_seen` answers from the wallet's attempt status and the canonical block.
- Decision: an escrow reference is `{'txid': <attempt id of the lock>}` and nothing else. The engine records the reference at submit time, before the lock is mined, so it cannot contain the note position. The funder resolves the position from its own attempt (after the refund handoff is imported); the claimant resolves it by trying `verify-htlc` against each unspent HTLC note in its own wallet until one matches every agreed term. Matching all terms is the verification, so an attacker who hands over a wrong reference gains nothing.
- Decision: verification asks `verify-htlc` with floors of 1 confirmation and 1 remaining block, and the engine applies the real policy to the confirmations and head the adapter reports. The CLI refuses a verification when the deadline is within the floor, which would hide an expired escrow, so a verified escrow is cached (per terms digest, in the adapter's private state directory) and a cached escrow whose note has since left the unspent set is reported as spent rather than as missing.
- Decision: spent detection. A claim publishes its preimage in public bytes (`released_preimage` in `scripts/hegemon_preimage_observer.py`); the adapter scans canonical blocks from the lock height for a release matching the hashlock and reports `claimed` with the preimage. A spend with no such release, after the timeout, by our own mined refund attempt is `refunded`. Any other disappearance of a cached note raises `ChainUnavailable` rather than guessing.
- Decision: the local profile only runs against a peerless Development chain it started or that was explicitly pointed at, and verifies `system_health.peers == 0` and the genesis hash before each read, as `hegemon_preimage_observer.py` does. There is no public profile in this plan; P8 adds one with its own guards.
- Decision: identity. `identity()` returns the wallet's shielded address (`private-spend address`, a full `shca1…` string). The signed identity statement for a Hegemon leg stays `pending` (P5) because no key scheme exists; the adapter reports its address so the engine can compare terms, and the local-only status is recorded in the engine record rather than faked as a verified identity.
- Decision: local fixture timing uses Erlang windows with a 1e-3 tail, a 120 s outage allowance and `proveSeconds` 240, thinner than the public entry (1e-6 tail, 7200 s allowance), because the public values would put every local refund most of a day away. Each run validates the blocks it saw against those windows and reports excursions; an excursion makes the run `ok: false` but not `swap_ok: false`.
- Decision: the planner margin for a short leg whose chain needs a proof includes that proof and its confirmation (`planner.default_margin`, mirrored in `swap-ui/swap-flow.mjs`, new `bitcoin/hegemon` flow vector).
- Decision: Hegemon identities are `local:` only, accepted under `allow_local`, never proven; real binding is P8's problem.
- Decision: proving threads are configurable (`SWAP_PROVE_THREADS`, default 2); no prover source was changed.
- Decision: Part C runs on a branch created from `origin/main` in a separate git worktree. Proving changes never enter this branch. The harness is a measurement script; any optimization that changes a proof statement or the frozen relation needs its own ExecPlan and review.

## Outcomes & Retrospective

P6 is complete for the local scope. A real Hegemon adapter drives the private-spend wallet with the engine's journal-before-submit, inflight and resume discipline; it is covered by chain-free tests on a fake wallet and chain (crash at every step, unreadable chain is never "nothing there", wrong escrow reference gains nothing) and by real-software swaps on a private Hegemon chain.

Evidence (`.agent/SWAP_HEGEMON_ADAPTER_RESULTS.json`): happy swaps HGN/ETH 358 s, HGN/BTC 543 s, HGN/ADA 277 s, BTC/HGN 558 s, ETH/HGN 651 s, ADA/HGN 524 s, each in a fresh world, zero peers, no window excursions. HGN/ADA's first run (868 s) saw four six-block spans faster than the model and was repeated. Refund-class scenarios, one world each: no_counterparty with Hegemon as the long leg (8,258 s, initiator refunded, balances unchanged), both_refund with Hegemon as the short leg (8,990 s, both refunded), late_claim with Hegemon as the short leg (9,873 s, responder refunded, the claim attempted after the refund refused, initiator refunded, balances unchanged, `swap_ok` true). All three finished with `ok: false` only because blocks left the modelled windows (18, 92 and 41 excursions, mostly blocks much slower than a 60 s Poisson process, with a few faster spans just after the settled template starts), and the first two ran three worlds in parallel on a busy host. The honest reading: the engine behaved correctly, the fixture's timing model is thinner than the real chain's behaviour under load, and these runs do not demonstrate the timing claim; they demonstrate decisions and outcomes. The local chain averaged about 72 s per block in the last run.

Also delivered: the planner margin fix (the responder's proof and confirmations, and the bump fallback), the local-only identity, `check_hegemon_gateway.py` and the gateway design, `SWAP_PROVE_THREADS`, the opt-in `test_local_hegemon_e2e.py`, DESIGN and METHODS sections, and the proving cost report on branch `proving-cost-p6` (65 s and 1.5 GiB per proof at two threads; threads are the only low-risk lever; any prover source change alters the relation digest).

Fast test status at the end (after the planner change): JavaScript `node --test swap-ui/*.test.mjs` 161 of 161, client manifest fresh, Python `swap_engine` discovery 187 tests OK with 14 skipped (the opt-in heavy tiers), gateway check 8 of 8.

Not done, deliberately: engine token legs (ERC-20, Cardano native token) against Hegemon; a public profile (P8); a gateway deployment; any claim that the timing windows are public-testnet values; a prover optimisation. The older scripted harness ran HGN/ERC-20 and HGN/Cardano-token happy swaps (proofs 63 to 66 s, 1.6 GiB).

Lessons: a chain whose block time is a protocol constant turns every refund test into a multi-hour wall-clock test, so run few long worlds at once and budget the time; derive window checks from the policy's per-span guarantee rather than from all overlapping spans; a fixture bug can hide inside a planner bug (the late-claim scenario passed only because the initiator could not claim).

## Context and Orientation

Constraints from `.agent/LOCAL_PRIVATE_SPEND_SWAP_EXECPLAN.md`: on this branch the circuit, wallet, node and protocol source are identical to `origin/main`; only `wallet/src/bin/private_spend.rs` (the `verify-htlc` command) and `wallet/src/private_spend_build.rs` differ. The local node and wallet need the `development-candidate` feature and `wallet/private-spend-dev-artifacts`, built with `cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend`. Measured proofs: lock and claim about 62 s and 1.7 GB peak RSS on an idle host, 179 s and 2.0 GB under load; the minimum lock window is 14 blocks.

Existing pieces: `scripts/swap_engine/adapter.py` (contract), `adapters/hegemon_stub.py` (placeholder), `adapters/ethereum.py` and `local_ethereum.py` (the profile pattern), `local_world.py` (real local chains and the two-party harness), `scripts/hegemon_action_runner.py` and `hegemon_local_actions.py` (typed, validated action construction for the companion), `scripts/local_private_spend_swap.py` (PTY wallet runner and the node/Bitcoin scenarios), `scripts/hegemon_preimage_observer.py`, `scripts/probe_hegemon_testnet.py`, `config/swap/chain-timing.json` (`chains.hegemon`).

The wallet's relevant commands: `bootstrap-new`, `sync`, `status` (syncs once and prints `ordinary position=N value=V`, `htlc position=N value=V` and one line per attempt `<id> <status> mined=<Option>`), `address`, `ordinary`, `lock` (prints `candidate <id>`; `--release-secret` is required and `--refund-handoff` writes the encrypted handoff), `claim` and `refund` (print `candidate <id>`), `export <attempt> <file>`, `submit <attempt>` (prints `submitted <96 hex>`), `import-refund-handoff <file> --block-height H --refund-index 0`, `cancel <attempt>`, and `verify-htlc --locked N --claim --refund --hashlock --timeout --amount [--min-confirmations --min-remaining-blocks]`.

## Plan of Work

1. `scripts/swap_engine/hegemon_wallet.py`: a small wallet client over `wallet()` with typed parsers (status, attempts, candidate, submitted), a hard timeout and cancellation of an abandoned attempt, and a `FakeHegemonWallet` that simulates a chain of notes, attempts and mining for the unit tests.
2. `scripts/swap_engine/adapters/hegemon_local.py`: `HegemonAdapter(profile, person)` implementing the contract; `LocalHegemonProfile` that starts a fresh peerless Development node with easy proof-of-work, creates alice, bob and treasury wallets, funds fee notes, and advances blocks on a timer.
3. Tests: adapter unit tests on the fake wallet (observation shapes, every refusal, crash at each step of fund/claim/refund with resume, preimage from canonical bytes as `bytes` and `bytearray`, journal discipline, no secret in logs), then engine fault runs with the Hegemon fake.
4. `local_world.py` gains `hegemon` with the scaled timing in `local_timing()`; `test_local_chains.py` gains the Hegemon pairs and failure scenarios, opt-in via `HEGEMON_LOCAL_CHAINS=1`.
5. Identity and gateway design, documentation, the proving branch, then revisions.

## Concrete Steps

From the repository root, with `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python` and the chain tools under `~/.local/opt/chain-tools`:

    cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend
    (cd scripts && python3 -m unittest swap_engine.test_hegemon_adapter swap_engine.test_adapters swap_engine.test_engine)
    (cd scripts && HEGEMON_LOCAL_CHAINS=1 python3 -m unittest swap_engine.test_local_chains)
    (cd scripts && python3 -m swap_engine.local_world hegemon ethereum)

## Validation and Acceptance

- The engine completes local swaps for every Hegemon pair (HGN with BTC, ETH and ADA, in both leg orders where the planner allows) and for refund, missing-counterparty and late-claim scenarios, with crash-resume tests for the Hegemon inflight state.
- The gateway design is in `DESIGN.md`, checked against the repository's wallet RPC restrictions by an interface check that refuses the unsafe methods.
- The proving report is on its own branch; `git diff origin/main -- circuits wallet node protocol consensus crypto` on this branch still shows only the `verify-htlc` change.

## Idempotence and Recovery

Every local run uses a fresh output directory under a private temporary directory and stops the processes it owns. The wallet attempts are idempotent to retry because the adapter cancels an attempt the engine never adopted before it prepares another. A lost response from `submit` is resolved from the wallet's attempt status and the canonical block, never by re-proving.

## Artifacts and Notes

(Filled in as work proceeds.)

## Interfaces and Dependencies

- `HegemonAdapter(profile, person)` conforming to `swap_engine.adapter.ChainAdapter` with `chain = 'hegemon'`.
- A profile provides `wallet(person, args, secrets, label)`, `rpc(method, params)`, `now()`, `journal_chain`, `handoff_dir`, `mine(blocks)` for the local profile, and the node's manifest and genesis.
- `FakeHegemonWallet` in `scripts/swap_engine/hegemon_wallet.py` for tests that need no chain.
