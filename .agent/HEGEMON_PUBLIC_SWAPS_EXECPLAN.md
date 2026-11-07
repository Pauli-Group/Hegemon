# Run public Hegemon HTLC swaps through the engine

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

It is maintained in accordance with `.agent/PLANS.md` and is series plan P8 of `.agent/SWAP_SERIES_EXECPLAN.md`. It builds on the timelock policy (`.agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md`), the two-party engine (`.agent/SWAP_ENGINE_EXECPLAN.md`) and the local Hegemon adapter (`.agent/SWAP_HEGEMON_ADAPTER_EXECPLAN.md`). P7 already closed the cleanup and CI work; this plan is the public-Hegemon follow-up, not a rewrite of P7.

## Purpose / Big Picture

Two people should be able to swap real disposable HGN on the public v0.11 pre-mainnet for disposable ETH on Sepolia, BTC on Bitcoin testnet4 or ADA on Cardano preview, through the same crash-safe engine that already ran a public Sepolia/Cardano swap. Today the Hegemon adapter only talks to a peerless Development chain it started itself. After this plan, a public profile talks to the operator's loopback node on the real pre-mainnet, smoke tests a transfer and a lock/refund, then the engine completes claim-path and refund-path swaps with public identifiers recorded.

A person watching can see: the local node height within two blocks of `https://hegemonprotocol.com/testnet/status.json` and still advancing; `private-spend status` for Alice and Bob against that node; a lock that `verify-htlc` accepts and a refund after expiry; then engine `status` ending `done` or `refunded` with action ids and heights in `PUBLIC_TESTNET_RESULTS.md`. None of that is a real-funds or production claim.

Terms used below. The *pre-mainnet* is the v0.11 public test network selected by `--network pre-mainnet` and the frozen manifest in `config/testnet/0.11/`. A *relay* is a node that follows the chain and does not mine. *Wallet RPC* means `--rpc-methods unsafe` so `private-spend` can call `hegemon_submitAction` and the chain-read methods; it must stay bound to `127.0.0.1`. An *HTLC* is a hash-time-locked note: the claimant spends by revealing a 32-byte preimage of a published SHA-256 hashlock before a height, otherwise the refundee spends after that height. Hegemon notes are private; a counterparty verifies a lock only after importing the encrypted *refund handoff*, and a claim makes the preimage public in canonical action bytes only if the lock used the disclosure flag. `private-spend` is the wallet CLI; secrets are typed at a no-echo prompt, never on the command line.

## Progress

- [x] (2026-11-07 04:50Z) Wrote this ExecPlan; revised `.agent/SWAP_SERIES_EXECPLAN.md` and the P1, P6 and P7 plan files so P8 is the executing public-Hegemon work after P7 closed.
- [x] Diagnosed pid 185459: genesis matches, wallet RPC already on loopback, mining off, NTP yes, tip within 2 of explorer and advancing; left running, no database delete, no restart.
- [x] Built `private-spend` default features, SHA-256 `0a145c9daef68eab7d4b4c540c4dae1ec49f3f469cacd60cc2fbacac05f7ba7d`; wallet delta vs main is `verify-htlc` plus helper.
- [x] Alice ~43 HGN available, Bob 7 HGN plus the smoke ordinary; no treasury or mining.
- [x] Remeasured 3,000 blocks (8274–11273, mean 75.35 s); public proof ~105 s / 1.65 GiB; `proveSeconds` stays 300; copied timing JSON and rebuilt the client manifest.
- [x] `PublicHegemonProfile` beside loopback; local `peers == 0` tests still pass; CLI, companion `--hegemon-public`, public observer wired.
- [x] Smoke ordinary plus two lock/refunds (second disclosed and verified); labelled outside policy.
- [x] Engine swaps: HGN/ETH both directions, HGN/BTC and HGN/ADA all `done` through `planner.plan_with_margin`. HGN/ADA recovered after a SIGTERM during `submit` (`SubmissionUncertain`, journaled action later mined, `advance` adopted it). P1 `claim_gate` refused a late claim; a spent Hegemon `claim` was `ActionRefused`. Engine-policy Hegemon refunds (~21 h) were not waited; public refunds are the smoke locks.
- [x] Guided view labels Hegemon as requiring a local companion; companion public mode exists.
- [x] Public identifiers in `PUBLIC_TESTNET_RESULTS.md`; `python3 scripts/check_swap_secrets.py` reported `no swap-series secrets found`.

## Surprises & Discoveries

- Observation: pid 185459 was already following the public tip with wallet RPC on loopback and mining off, so it was left running. Evidence: `scripts/probe_hegemon_testnet.py --rpc http://127.0.0.1:9944 --check-public-tip` reported `public_testnet_ready: true`.
- Observation: `verify-htlc` requires the lock to have been created with `--release-secret` (`policy.release_secret == 1`). The first smoke lock omitted it and Bob could not verify; the second lock with disclosure verified and later refunded.
- Observation: `private-spend export` uses `create_new(true)`, so a reused export path fails. Smoke resume had to use new `lock2.action` / `refund2.action` names.
- Observation: `scan_public_hegemon_preimage` returns `None` when the lock is unspent. Unpacking that as a pair raised `TypeError` and the engine reported the own leg unreadable. A 0.05 s timeout returned `None` without scanning and the scan cursor then skipped the claim block. Fix: treat `None` as unspent, scan timeout 15 s, do not advance the cursor past unscanned blocks.
- Observation: a public proof is about 105 s and 1.65 GiB, slower than the P6 local 65 s figure, still well under `proveSeconds` 300.
- Observation: wallet `status` on the public chain spends ~45 s unlocking (~24,600 notes scanned twice) before every inspect, so engine cycles are dominated by wallet open time plus Bitcoin confirmations.
- Observation: SIGTERM during `private-spend submit` left the lock attempt `SubmissionUncertain` with a journaled signed action. `transaction_seen` was false until the same attempt was submitted again; it then mined and `advance` adopted it. Date: 2026-11-07, swap `47409b683c7122fb`.

## Decision Log

- Decision: execute P8 after P7 rather than before it. The series revision after P6 put P8 before P7; P7 ran first at the operator's request and left public Hegemon swaps as the follow-up. This file is that follow-up. Date/Author: 2026-11-07 / P8.
- Decision: never delete `~/.hegemon-node-v0.11` or the testnet wallets. If the existing node cannot catch up, start a second relay on a new unused data path and a free P2P port, leaving the old database intact. Date/Author: 2026-11-07 / P8.
- Decision: the public Hegemon profile is a separate class, not a flag that relaxes `LoopbackProfile._guard`. Local mode keeps `system_health.peers == 0` and `--development-local-candidate`. Public mode requires the pinned pre-mainnet genesis and manifest, loopback HTTP RPC, peers at least 1, a tip within 2 blocks of the explorer `status.json` (the probe's `MAX_TIP_GAP` is 12; the plan's acceptance is 2, so the profile is stricter), NTP/chrony already a host requirement, journal-before-submit, and inflight blocking. Date/Author: 2026-11-07 / P8.
- Decision: Hegemon identity stays unauthenticated (`pending` / `local:`). The wallet has no message-signature command. Public runs record identity codes and say the Hegemon side was not proven. Date/Author: 2026-11-07 / P8.
- Decision: smoke locks may use the relation minimum (14 blocks) plus a small margin and are labelled outside the swap policy. Engine swaps use `planner.plan_with_margin` on live heads. Hegemon is preferred as the long leg against a time-based chain because a 22.6 hour stall has already exceeded the policy's two-hour outage allowance. Date/Author: 2026-11-07 / P8.
- Decision: `proveSeconds` stays 300. A public proof on this host was about 105 s and 1.65 GiB; 300 remains several times that. Date/Author: 2026-11-07 / P8.
- Decision: engine-policy Hegemon refunds (~21 hours vs ETH/ADA, days vs Bitcoin) are not waited out in this session. Public Hegemon refunds are the two outside-policy smoke locks. A late claim is refused by `claim_gate` and a second claim of a spent lock is `ActionRefused`. Date/Author: 2026-11-07 / P8.

## Outcomes & Retrospective

Done against the purpose above, with the refund caveat recorded in the Decision Log: public HGN swapped through the engine with ETH (both directions), BTC and ADA; smoke locks refunded on the public chain; late claims refused; a mid-submit crash resumed from the journal; public identifiers only; local `peers == 0` guards unchanged. Hegemon identity stays unauthenticated. Engine-policy refund waits of ~21 hours were not run. The operator's node database and wallets were not deleted; mining stayed off.

What I would do differently: kill the runner earlier in the prove, before `submit`, so the inflight path that clears “nothing was signed” is also exercised on the public node. The kill landed on `SubmissionUncertain`, which is the harder recovery and did work.

## Context and Orientation

The operator's machine already runs `target/release/hegemon-node --network pre-mainnet` (historically pid 185459) with data in `~/.hegemon-node-v0.11`, RPC on `127.0.0.1:9944` and P2P on `0.0.0.0:30333`. The frozen identity is in `config/testnet/0.11/release.json`: network `pre-mainnet`, genesis `0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3`, chain id `0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49`, manifest SHA-256 `386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754`. Approved seeds, which every node and miner on this network must share or they can fork: `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`. PoW timestamps beyond the future-skew bound are rejected, so NTP or chrony must stay enabled. Join and launch details live in `config/testnet/0.11/README.md`; `./start.sh --wallet-rpc` from the repository root is the source-checkout launcher (it sets `--rpc-methods unsafe` on loopback only). The join skill at `.claude/skills/hegemon-testnet-join/SKILL.md` still mentions the 0.10 `--dev` profile; this plan uses the v0.11 `--network pre-mainnet` launcher instead.

Read-only identity checks are `scripts/probe_hegemon_testnet.py` (loopback HTTP only, optional `--check-public-tip` against `https://hegemonprotocol.com/testnet/status.json`). Wallet I/O for the older single-run rehearsal is `scripts/public_hegemon_wallet.py`; it already refuses the official v0.11.2 `private-spend` because that binary lacks `verify-htlc`. Encrypted Alice and Bob wallets are under `~/.local/share/hegemon-testnet-wallets-20261104/testnet-wallets/hegemon-pre-mainnet/` with `.pass` files (mode 0600) and `.lock` files. Do not print passphrases, preimages or handoffs.

The engine lives in `scripts/swap_engine/` with CLI `scripts/swap_engine_cli.py`. `build_adapter('hegemon')` currently constructs `HegemonAdapter(AttachedHegemonProfile(...), 'self')` from a `hegemon` object in `~/.config/hegemon/swap-wallets.json`. `AttachedHegemonProfile` is a `LoopbackProfile`: it prepends `--development-local-candidate` to every wallet command and `_guard` raises if `system_health.peers != 0`. That is correct for P6 fixtures and fatal for a public node. The public profile added here must not go through that class.

`HegemonAdapter` in `scripts/swap_engine/adapters/hegemon_local.py` already journals the proved action before submit, treats a lost response as inflight, resolves a lock by matching every agreed term with `verify-htlc`, and observes a claim preimage from canonical bytes via `scripts/hegemon_preimage_observer.py`. Those behaviours stay. What changes is the profile: public mode uses the production wallet (no `--development-local-candidate`), the pre-mainnet genesis, and the opposite peer check.

The local companion `scripts/local_swap_companion.py` likewise refuses a node with peers and always passes `--development-local-candidate`. Public companion mode is a separate flag, not a relaxation of that path. The hosted page's Content-Security-Policy is `connect-src 'self'`, so the page cannot reach loopback; the Hegemon leg stays labelled as requiring the companion unless a Worker route is added, which this plan does not require.

Timing is already in `config/swap/chain-timing.json` under `chains.hegemon` (3,000 public blocks, mean 75.83 s, one 81,258 s stall, `minLockBlocks` 14, `proveSeconds` 300). P1's tables stay until a fresh measurement from the synced local node and a real proof on this host replace `proveSeconds`. The hosted copy `swap-ui/chain-timing.json` must stay byte-identical; after editing, run `node scripts/build_client_manifest.mjs`.

Disk and memory: a Hegemon proof peaked at about 1.5 to 1.7 GiB on this host in P6; the node itself uses about 1 GiB RSS. Check free space before building. Mining is off unless the user explicitly asks; immature rewards need 120 blocks to mature.

The operator's public node is the one on port 9944. Do not point a Development fixture at it. Do not enable mining from this plan. Do not commit `.pass` files, wallet stores, swap `secret` files or journals.

## Plan of Work

Milestone A, series paper. This file, plus a progress tick on `.agent/SWAP_SERIES_EXECPLAN.md` that P8 is in progress after P7, a short revision on `.cursor/plans/p1_deadline_policy_d2a8d781.plan.md` recording the 3,000-block Hegemon measurement and the stall, a last-step note on `.cursor/plans/p6_hegemon_offline_adapter_e6123051.plan.md` that P8 is executing, and a last-step note on `.cursor/plans/p7_cleanup_docs_ci_daa49917.plan.md` that P8's public profile, timing update and results belong in the Hegemon-adapter and docs PRs of `.agent/SWAP_PR_SPLIT.md`. Do not edit `.cursor/plans/p8_public_hegemon_swaps_bc353df6.plan.md`.

Milestone B, a following node. Record how pid 185459 was started (`ps`, `/proc/PID/cmdline`, environment if readable), its log, `system_health`, `chain_getHeader`, genesis, peers, `timedatectl` or `chronyc tracking`, and disk. Compare height with `status.json`. If it is within two blocks and advancing, keep it and only ensure wallet RPC is on (restart with `./start.sh --wallet-rpc` if RPC methods are safe-only). If it is stuck, stop it cleanly (SIGTERM, wait), keep `~/.hegemon-node-v0.11`, and start:

    export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
    HEGEMON_MINE=0 HEGEMON_MINER_ADDRESS= ./start.sh --wallet-rpc

from the repository root. If restarting the same database still stalls, leave it and start a second relay with `HEGEMON_NODE_PATH` set to a new unused directory and `--port` not 30333 if 30333 is taken; do not delete the old path. Then:

    python3 scripts/probe_hegemon_testnet.py --rpc http://127.0.0.1:9944 --check-public-tip

Acceptance: genesis and chain id match `release.json`, required wallet methods present, local height within 2 of the explorer, and the height advances across several subsequent blocks. If the stall is a node bug, write logs under `.agent/` and use the fresh data path.

Milestone C, wallet binary. Check free disk. From the repository root:

    cargo build --locked --release -p wallet --bin private-spend

Default features, no `private-spend-dev-artifacts`. Record `sha256sum target/release/private-spend`. Diff `wallet/src/bin/private_spend.rs` and `wallet/src/private_spend_build.rs` against `main`; the public spending path must match the qualified release except for `verify-htlc` and its helper. Confirm `target/release/private-spend --help` lists `verify-htlc`.

Milestone D, balances. Confirm no process holds `*.wallet.lock`. Drive `status` for Alice and Bob through the existing PTY helper (`scripts/hegemon_action_runner.py` or `scripts/public_hegemon_wallet.py`), passphrase from the 0600 `.pass` file, never on argv or in logs. Record available, reserved and immature atoms. 1 HGN is 100,000,000 atoms. Choose a few thousand atoms plus fee as the smoke amount. If funds are short, stop and ask the user whether to use the treasury or mine (mining off in this plan unless they say yes; 120 blocks to mature).

Milestone E, timing. Once the node is following:

    python3 scripts/measure_chain_timing.py hegemon-pre-mainnet 500 --update config/swap/chain-timing.json

Prefer more than 500 blocks if the node has them (P1 used 3,000). Time one `lock` proof on this host (the smoke lock) and write its seconds and peak RSS into `proveSeconds` only if the measured proof is not well below 300; 300 stays if it remains conservative. Copy `config/swap/chain-timing.json` to `swap-ui/chain-timing.json` and run `node scripts/build_client_manifest.mjs`. Run `python3 -m unittest swap_engine.test_timelock_policy` from `scripts/` with `PYTHONPATH=scripts`.

Milestone F, public profile. In `scripts/swap_engine/adapters/hegemon_local.py` add `PublicHegemonProfile` next to `LoopbackProfile`, not as a subclass that skips `_guard`. It takes the same config keys as `AttachedHegemonProfile` plus nothing that would point at a Development chain. `pin_genesis` requires the `release.json` genesis. `_guard` requires `system_health.peers >= 1`, genesis unchanged, loopback URL, and a tip gap at most 2 against `probe_hegemon_testnet.compare_public_tip` (treat explorer failure as `ChainUnavailable`, never as "no peers so it must be local"). Wallet argv omits `--development-local-candidate`. Confirmation depth for `observe_release` comes from `legRequirements('hegemon')['confirmations']` in `scripts/swap_engine/timelock_policy.py`, not a hard-coded 1. `scripts/swap_engine_cli.py` `build_adapter('hegemon')` selects `PublicHegemonProfile` when the wallet config has `"profile": "public"` (or `"network": "pre-mainnet"`) and keeps `AttachedHegemonProfile` otherwise, so existing local configs do not silently go public. Add tests in `scripts/swap_engine/test_hegemon_adapter.py` that a public profile refuses zero peers, a non-loopback URL, a wrong genesis, and that a local profile still refuses any peers. Do not change `LocalHegemonProfile`.

For the companion, add `--hegemon-public` that is mutually exclusive with `--enable-hegemon-actions` as it exists today. Public mode checks peers >= 1, pinned genesis, and does not pass `--development-local-candidate`. Local mode is unchanged. `scripts/watch_hegemon_preimage.py` / `scripts/hegemon_preimage_observer.py`: make confirmation depth a parameter defaulting to the policy's Hegemon confirmations; do not lower it.

Milestone G, smoke. Ordinary transfer Alice to Bob of the minimum amount, submit, wait for two confirmations, `status` on both wallets. Then Alice locks that amount for Bob with refund handoff and disclosure, Bob `verify-htlc` with `--min-confirmations` and `--min-remaining-blocks` from `legRequirements`, wait until the timeout height plus confirmations, Alice refunds. Record proof time and RSS. If either smoke fails, stop; do not open a second escrow.

Milestone H, engine swaps. One pair at a time, stores under `~/.hegemon-swaps-alice` and `~/.hegemon-swaps-bob` (already used; do not mix with local fixture stores). Expiries from `python3 scripts/swap_engine_cli.py plan`. Order: Hegemon long / Ethereum short (hours), both directions if balances allow; then Hegemon / Cardano; Bitcoin last (refund height at least 145 blocks). For each pair a happy claim path, and at least one refund path (counterparty never funds). A late claim must be refused by the engine's cutoff even though Hegemon would still accept until a refund lands. Record hashlock and full terms before funding. If a stall hits, wait; do not abandon a live escrow. Pause the plan rather than leave an unrefunded lock.

Milestone I, UI. If the companion public mode from F is enough, point the guided view at it and keep the hosted page's Hegemon label as "local companion required". If that slips, leave the existing "unavailable on public testnet" label and write it as a remaining gap. Any `swap-ui/` edit is followed by `node scripts/build_client_manifest.mjs`.

Milestone J, records. Append to `PUBLIC_TESTNET_RESULTS.md` only public fields: action ids, heights, hashlocks, the other chain's transaction ids. Update `DESIGN.md` (public Hegemon profile next to the local adapter section), `METHODS.md` (how to run, timing, disclosure), `swap-service/README.md` (replace any sentence that says Hegemon public verification is unavailable), and `runbooks/hegemon_eth_public_rehearsal.md` if it still describes the old single-run path as the only path. Run `python3 scripts/check_swap_secrets.py`. Revise P1 numbers if measurement changed them; revise P7's PR split file lists if new files appeared; leave the P8 plan file untouched.

## Concrete Steps

Working directory is the repository root `/home/william/Hegemon` unless a command says otherwise. Python needs `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python`. Node is 24 (`.nvmrc`).

Series paper (this milestone): the files named in Milestone A.

Node:

    timedatectl status
    df -h /
    ps -p 185459 -o pid,lstart,args
    tr '\0' ' ' < /proc/185459/cmdline; echo
    curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}'
    curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":2,"method":"system_health","params":[]}'
    curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":3,"method":"hegemon_nodeConfig","params":[]}'
    curl -s https://hegemonprotocol.com/testnet/status.json
    python3 scripts/probe_hegemon_testnet.py --rpc http://127.0.0.1:9944 --check-public-tip

Expected probe on a healthy node: JSON with matching genesis and `public_testnet_ready` true, or a clear error naming the gap. After a restart, the same probe plus a second health read several minutes later showing a higher height.

Wallet build:

    df -h /
    cargo build --locked --release -p wallet --bin private-spend
    sha256sum target/release/private-spend
    git diff main -- wallet/src/bin/private_spend.rs wallet/src/private_spend_build.rs | head

Expected: the binary exists, help includes `verify-htlc`, the diff is that subcommand and `private_spend_build.rs` support, not a change to the spend circuit.

Tests after the public profile exists, from the repository root:

    python3 -m unittest swap_engine.test_hegemon_adapter swap_engine.test_local_hegemon_timing test_check_hegemon_gateway
    python3 -m unittest swap_engine.test_timelock_policy
    node --test swap-ui/timelock-policy.test.mjs

Expect the new public-profile tests to fail before the class exists and pass after. Local tests that require `peers == 0` must still pass.

## Validation and Acceptance

The plan is done when all of the following are true at once. The local node follows the public tip (gap at most 2) and has survived a restart or was already healthy. `private-spend status` works for Alice and Bob on that chain. At least HGN with ETH and HGN with Bitcoin each complete a claim on both sides, and at least one pair refunds, with public identifiers in `PUBLIC_TESTNET_RESULTS.md`. Every engine run used `plan_with_margin` and the late-claim case was refused. `LoopbackProfile._guard` still raises on any peer. `python3 scripts/check_swap_secrets.py` prints `no swap-series secrets found`. The README whitepaper section is untouched.

## Idempotence and Recovery

Probe, status and plan commands are read-only and can be repeated. `start.sh` does not wipe `HEGEMON_NODE_PATH`. Building `private-spend` overwrites only that binary. Engine `advance` still submits at most once per call and will not retry an inflight action. If a step fails after a lock is funded, the next work is to wait for the refund height and refund, not to start another swap. Swap stores stay under `~/.hegemon-swaps-*` with mode 0700; a crashed run is resumed with `advance`, not re-inited. If the public chain stalls, stop at a state with no live escrow.

## Artifacts and Notes

Public explorer at the time this file was written (to be replaced with a live read in Milestone B): the P8 survey on 2026-11-05 saw `status.json` height 9978, 14 peers, genesis matching `release.json`, software 0.11.2, while the local node sat at 9924 with `isSyncing: true`. That gap is the first thing to re-read; it may have closed.

The older single-run path `scripts/public_hegemon_eth_rehearsal.py` and `runbooks/hegemon_eth_public_rehearsal.md` remain evidence of how a Hegemon/Sepolia rehearsal was staged. New runs go through `scripts/swap_engine_cli.py`.

## Interfaces and Dependencies

`PublicHegemonProfile` in `scripts/swap_engine/adapters/hegemon_local.py` presents the same methods `HegemonAdapter` already calls on `LoopbackProfile`: `now`, `address`, `private_dir`, `handoff_secret`, `rpc`, `pin_genesis`, `height`, `block_hash`, `wallet`, `observe_release`, plus `name = 'hegemon'`, `journal_chain = 'hegemon-pre-mainnet'`, `fee`, `prove_timeout`. `wallet(person, command, secrets=(), label=None, expected=True, timeout=None)` must not add `--development-local-candidate`.

`scripts/swap_engine_cli.py` `build_adapter`:

    if chain == 'hegemon':
        from swap_engine.adapters.hegemon_local import (
            AttachedHegemonProfile, PublicHegemonProfile, HegemonAdapter)
        entry = wallets['hegemon']
        profile = PublicHegemonProfile(entry) if entry.get('profile') == 'public' else AttachedHegemonProfile(entry)
        return HegemonAdapter(profile, 'self')

Wallet config public example (paths only, no secrets in the repository):

    {"hegemon": {"profile": "public", "rpc": "http://127.0.0.1:9944",
      "manifest": "/home/william/Hegemon/config/testnet/0.11/network-manifest.json",
      "wallet": "/absolute/alice.wallet", "wallet_binary": "/home/william/Hegemon/target/release/private-spend",
      "address": "shca1...", "passphrase_file": "/absolute/alice.pass",
      "handoff_passphrase_file": "/absolute/handoff.pass"}}

`compare_public_tip` in `scripts/probe_hegemon_testnet.py` is the explorer comparison. The profile should fail closed when that function raises.

No new Python packages. No Worker deploy. No mining.

## Plan Revisions

Revision 2026-11-07, created: initial self-contained plan from the P8 survey, P6 adapter as it landed, P7 close-out, `config/testnet/0.11/README.md` and the v0.11 launcher. Reason: a novice needs the public identity, the existing pid, the local-versus-public guard split and the engine CLI contract in one file.
