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

Revision from P1 (2026-11-05):
- Test entry points to add to the single test command: `node --test swap-ui/*.test.mjs` (33 tests including `timelock-policy.test.mjs`), `cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_timelock_policy`, and the opt-in browser test `swap-service/timing-browser.test.mjs` (needs `npm ci` in `swap-service/` for `playwright-core` and `CHROMIUM_PATH`). `scripts/measure_chain_timing.py` needs the network and stays out of CI.
- Pre-existing failures found while running the swap-service suite on Node 24 (baseline, not caused by P1): `swap-service/browser.test.mjs` passes its test and then aborts with a Node internal assertion; `swap-service/desktop.test.mjs` and `desktop-node-profile.test.mjs` need a built `hegemon-app/out/renderer/index.html`. Fix or mark them opt-in.
- Documentation to index: the cross-chain deadline policy section in `DESIGN.md` and `METHODS.md`, `config/swap/chain-timing.json` (with its `measurement` provenance), `config/swap/timelock-vectors.json`, `.agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md`.
- PR split: P1 is one reviewable PR (policy and config; both implementations and vectors; verifier and `comparePair` wiring; UI panel; docs). The verifiers' old constants remain as named floors (`BITCOIN_FLOOR_*`, `CARDANO_FLOOR_*`, `SEPOLIA_FLOOR_*`, `SEPOLIA_ACTION_FLOOR_SECONDS`).
- Backlog: the Python rehearsal scripts' literal margins (superseded by the engine); a time-based Bitcoin timelock; the `private-spend verify-htlc` defaults; refreshing the measured tables on a schedule.

Revision from P2 (2026-11-06):
- New code: `scripts/swap_engine/` (engine, store, planner, simulated chains, adapters, local profiles, `tools.py`, `local_world.py`), `scripts/swap_engine_cli.py`, `.agent/SWAP_ENGINE_EXECPLAN.md`. `scripts/public_cardano_transactions.py` and `scripts/public_cardano_verify.py` now resolve tools through `swap_engine.tools` instead of `/workspace` literals; the other four failing Python test files and their imports still use fixed paths and are not yet converted.
- Test entry points. Chain-free: from `scripts/`, `PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m unittest swap_engine.test_store swap_engine.test_engine swap_engine.test_planner swap_engine.test_faults swap_engine.test_adapters swap_engine.test_timelock_policy` (97 tests, about 18 seconds, suitable for CI). Real local chains: the same prefix with `HEGEMON_LOCAL_CHAINS=1 ... swap_engine.test_local_chains` (about 25 minutes; needs `~/.local/opt/chain-tools` or `HEGEMON_CHAIN_TOOLS`, with Foundry, aiken, cardano-node and Bitcoin Core). Not CI material without a tool cache.
- The engine supersedes the per-pair rehearsal scripts for new runs (`public_btc_eth_rehearsal.py`, `public_eth_cardano_rehearsal.py`, `public_btc_cardano_rehearsal.py`, `public_samechain_*`). Keep them and their tests; mark them as superseded in their docstrings and in `PUBLIC_TESTNET_RESULTS.md`, and list the engine's public acceptance swap (transaction ids in `.agent/SWAP_ENGINE_EXECPLAN.md`) there.
- Secret scan additions: swap stores (default `~/.hegemon-swaps`, or the per-side stores used in two-party runs) hold the initiator's preimage in `secret` and the responder's in `learned-preimage` (0600); each `journal/` holds signed transactions, including claims that contain the preimage; wallet configs under `~/.config/hegemon/` hold only paths. None of these may enter the repository.
- Untracked build output: the tool setup built `contracts/ethereum/out` and `contracts/cardano` artifacts; confirm `.gitignore` covers them before any commit. The P1 and P2 files under `scripts/swap_engine/`, `config/swap/`, `swap-ui/` are all still uncommitted and need the PR split.
- Docs: `DESIGN.md` and `METHODS.md` have "Two-party swap engine" sections; the METHODS section carries the operator note about `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` and NTP/chrony. Add the CLI to any user-facing index.

Revision from P3 (2026-11-06):
- New test commands. Node 24, repository root: `node --test swap-ui/*.test.mjs swap-service/cloudflare/worker.test.mjs` (133 tests in total, 12 of them the Worker's; the `swap-ui` tests include `vendor.test.mjs`, which checks `swap-ui/vendor/SHA256SUMS`). Playwright with `CHROMIUM_PATH` (`/snap/bin/chromium` here): `swap-service/cardano-wallet-browser.test.mjs`, `bitcoin-wallet-browser.test.mjs`, `observer-browser.test.mjs`, `sepolia-claim-browser.test.mjs`, `guided-browser.test.mjs`, `timing-browser.test.mjs`. Python from `scripts/` with `PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python`: `swap_engine.test_ui_vectors`, `swap_engine.test_bitcoin_browser` (needs `bitcoind` on `PATH`, about 5 s) and `swap_engine.test_cardano_browser` (needs the Cardano tools). `swap-service/qualify/hosted-ui.mjs` is not a test: it spends testnet funds, needs `HEGEMON_QUALIFY=1`, and must stay out of any CI glob (its name is not `*.test.mjs`).
- New dependencies. `swap-service/vendor-src/` needs `npm ci --ignore-scripts` (esbuild 0.25.12, `@scure/btc-signer` 2.4.1, `@noble/*` 2.4.0) only to rebuild `swap-ui/vendor/`; CI should run `node build.mjs --check`. `swap-service` already needs `playwright-core`. The qualification signer needs `embit` and `eth-account` (in `hegemon-swap-python`). Node needs `net.setDefaultAutoSelectFamilyAttemptTimeout(5000)` (or the matching flag) when hosting the Worker locally.
- `swap-service/browser.test.mjs` passes and then aborts with a Node internal assertion at exit on Node 24.22.2 (known since P0, unchanged).
- Documentation touched by P3: `swap-service/README.md` ("Hosted wallet flows, observers and the guided view"), `DESIGN.md` ("Hosted wallet integrations"), `METHODS.md` ("Hosted wallet integrations"), `.agent/SWAP_UI_WALLETS_EXECPLAN.md`, `PUBLIC_TESTNET_RESULTS.md`. `swap-service/cloudflare/worker.mjs` changed and has not been redeployed (Wrangler is not installed here), so the deployed Worker still lacks the new routes until the operator deploys.
- New files for the PR split: `swap-ui/{cbor,cardano-tx,cardano-wallet,cardano-ui,bitcoin-psbt,bitcoin-wallet,bitcoin-ui,observers,observer-ui,swap-flow,guided,guided-ui}.mjs` and their tests, `swap-ui/vendor/`, `swap-service/vendor-src/`, `swap-service/tools/`, `swap-service/qualify/`, the Playwright tests above, `scripts/qualification_signer.py`, `scripts/swap_engine/{ui_vectors,cardano_browser_harness,bitcoin_browser_harness}.py`, `config/swap/flow-vectors.json`, plus edits to `worker.mjs`, `server.ts`, `app.js`, `index.html` and `style.css`.

Revision from P4 (2026-11-06):
- New files: `scripts/verify_public_btc_cases.py` (public re-verification of finished Bitcoin cases and Sepolia fixtures; run with `--journals DIR`, needs the restored private journals and network access), `scripts/test_verify_public_btc_cases.py` (16 offline mutation tests; run from `scripts/` with `PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python`), `scripts/sweep_sepolia_escrows.py`, and a `--sweep-cardano` mode plus hashlock recording in `swap-service/qualify/hosted-ui.mjs`. Keep the verifier and its tests in CI scope; keep the sweep tools and the qualification harness out of CI, since they spend testnet funds.
- The `test_public_*.py` group still has 7 errors on this host that are only hard-coded `/workspace/...` tool paths (`anvil`, `bitcoind`, `cardano-testnet`, `htlc.plutus`); P7 should make those paths configurable. Everything else in that group passes.
- `PUBLIC_TESTNET_RESULTS.md` now holds the final public matrix: BTC with ETH, ERC-20, ADA and an ADA token, the Bitcoin refund, both Sepolia fixtures, the P3 hosted-page flows and the clean-up, with every ID. `.agent/PUBLIC_TESTNET_SWAP_EXECPLAN.md` has its stale Bitcoin and matrix items ticked; its last item (commit the work) remains for P7. `.agent/HOSTED_TESTNET_SWAPS_EXECPLAN.md` already had its Bitcoin items ticked.
- Two 20,000-sat Bitcoin testnet escrows (`05995b8c...`, `cc72202d...`) are permanently unrecoverable and are recorded as abandoned; do not describe the public state as having no unspent escrows. The private journal directory and `~/.hegemon-private/p4-sweep-journal` hold signed transactions and must stay out of the repository; `/tmp/p4.json` is a derived public report and need not be committed.
- Obsolescence candidates: none of the Bitcoin rehearsal scripts is obsolete (`public_bitcoin_suite.py` still covers splits and refund rehearsals); the older results prose that describes the 2026-11-04 Bitcoin cases as trusted provider observations is superseded for those cases by the P4 entry.

## Last step: close the series

There is no later plan to revise, so instead:
- Update the master ExecPlan with final status for P0..P7.
- Write the follow-up backlog, first item being the plan to resume public Hegemon swaps once the testnet is back (gateway or tunnel access, public-testnet identity, engine run with the real adapter), plus any items deferred from earlier plans.
