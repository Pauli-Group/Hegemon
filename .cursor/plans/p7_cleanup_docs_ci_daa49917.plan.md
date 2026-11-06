---
name: P7 Cleanup docs CI
overview: "Plan 7 of 8. Make the swap work maintainable and reviewable: one test entry point, CI, an index of scripts, updated design and runbook docs, secret scan, and a split into reviewable PRs."
todos:
  - id: p7-pin
    content: Pin Node 24 and document tool versions
    status: pending
  - id: p7-make
    content: Add make swap-test and swap-integration targets with explicit skips
    status: pending
  - id: p7-ci
    content: CI workflow for the fast tier
    status: pending
  - id: p7-index
    content: Write scripts/SWAP_SCRIPTS.md index and mark superseded scripts
    status: pending
  - id: p7-docs
    content: Update DESIGN.md, METHODS.md, READMEs, CHANGELOG, runbook notes (HEGEMON_SEEDS, NTP)
    status: pending
  - id: p7-secrets
    content: Secret scan and ignore-file hygiene
    status: pending
  - id: p7-prs
    content: Propose and verify reviewable PR split
    status: pending
  - id: p7-close
    content: Final master ExecPlan status and follow-up backlog including resuming Hegemon public swaps
    status: pending
isProject: false
---

# Plan 7 of 8: Cleanup, docs, CI and PR split

Depends on all earlier plans. This plan is the final one in the series, so it also produces the follow-up backlog.

## Scope

1. Toolchain pinning: add `.nvmrc` (24) and `engines` fields to `swap-service/package.json` and the Worker package; document the Python, Foundry, Aiken, cardano-cli and bitcoind versions used (from P0's inventory) in one place.
2. One entry point: a Makefile target `make swap-test` (fast tier: JS suites on Node 24, Python unit tests with the correct `PYTHONPATH`, engine simulated-chain tests, Worker tests) and `make swap-integration` (needs Anvil, bitcoind, cardano-cli, Chromium; skips with an explicit message when tools are missing, never silently passing). Heavy Hegemon runs from P6 are opt-in only.
3. CI: a workflow running the fast tier on Node 24; integration tier documented for manual or self-hosted runs.
4. Script index: `scripts/SWAP_SCRIPTS.md` grouping the 60+ `scripts/public_*`, `check_*`, `local_*` files by role (engine, drivers, observers, local fixtures, one-off rehearsals), marking superseded rehearsals as superseded rather than deleting them.
5. Docs: update `DESIGN.md` and `METHODS.md` for the engine, deadline policy, identity model, gateway design and remaining limits; update `swap-service/README.md` and `contracts/README.md`; add a CHANGELOG entry. Operator runbook notes must include `HEGEMON_SEEDS` set to the currently approved seed list (all miners and nodes share the same seeds to avoid forks) and the NTP/chrony requirement because PoW timestamps beyond the future-skew bound are rejected. Keep the README whitepaper section intact.
6. Hygiene and secrets: scan the branch for keys, preimages, signed transactions and passphrases; confirm `hidden/`, `tools/user-sim/` and private restore directories are ignored or excluded; remove nothing that is evidence.
7. PR split: the branch is about 195 files and 13.5k lines. Use the split-to-prs approach to propose independently reviewable PRs, for example: contracts and local fixtures; public-testnet drivers and results; engine and policy; hosted UI and Worker; Hegemon wallet changes (`private_spend.rs`); docs. Each PR must build and pass its tests alone.
8. Retrospective: write the final outcomes in the master ExecPlan, including honest remaining limitations (no authenticated Hegemon identity, provider trust, testnet-only timing, no production claim).

## Acceptance

- `make swap-test` passes from a clean Node 24 environment; integration tier reports skipped items explicitly.
- CI green on the fast tier.
- Secret scan clean.
- A PR split plan with a verified order of application.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- Make every tool location configurable by environment variable (for example `BITCOIND`, `ANVIL`, `FORGE`, `AIKEN`, `CARDANO_CLI`, `CARDANO_TESTNET`) with a clear skip message when absent, replacing the hard-coded `/workspace/bitcoin-32.1/...` and `/workspace/chain-tools/...` paths in the six failing files: `test_public_bitcoin_transactions.py`, `test_public_btc_eth_integration.py`, `test_public_cardano_transactions.py`, `test_public_cardano_verify.py`, `test_public_ethereum_setup.py`, `test_public_ethereum_transactions.py`, and the scripts they import. Also the `swap-service/README.md` commands that point to `/workspace/chain-tools`.
- Document: Node 24 requirement (`.nvmrc`, `engines`); the `pip install --target` fallback when `python3-venv` is missing; that the default public Sepolia RPC prunes history older than about 12,000 blocks so explorers are needed for old events; and the baseline numbers (JS 23 of 23, Python 25 of 31 files without chain tools).
- Secret and hygiene scan must also cover `~/.hegemon-private` references and ensure `hidden/` stays ignored (it is, via `/hidden` in `.gitignore`).
- Second revision from P0 (2026-11-05): document where private material lives and how it is protected: `hidden/` (gitignored) holds a GPG-encrypted journals archive; decrypted copies belong only under `~/.hegemon-private`; the key passphrase file `~/.config/cursor/gpg/cursor-bob.passphrase` and the private key must be backed up offline, because the user did not remember the passphrase and losing the file makes the archives unrecoverable. The secret scan should also cover `.cursor/plans` (which sits inside the repository tree).
- Results files in the repository lag the chain (Bitcoin claims, refund and the Sepolia fixture refund were finished after the last commit); the docs pass must reconcile `PUBLIC_TESTNET_RESULTS.md` with P4's verified results.

## Last step: close the series

There is no later plan to revise, so instead:
- Update the master ExecPlan with final status for P0..P7.
- Write the follow-up backlog, first item being the plan to resume public Hegemon swaps once the testnet is back (gateway or tunnel access, public-testnet identity, engine run with the real adapter), plus any items deferred from earlier plans.
