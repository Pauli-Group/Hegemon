---
name: P0 Baseline and recovery
overview: Plan 0 of 8 in the swap series. Get a trustworthy test baseline (Node 24 and chain tools) and recover/inventory the private public-testnet state before any other work touches it.
todos:
  - id: p0-master
    content: Create .agent/SWAP_SERIES_EXECPLAN.md master plan indexing P0..P7
    status: completed
  - id: p0-node
    content: Install Node 24 user-local and get JS swap suites to 20/20
    status: completed
  - id: p0-tools
    content: Inventory chain tools and run toolless Python unit tests
    status: completed
  - id: p0-decrypt
    content: User decrypts journals/wallets archives into a private 0700 dir outside repo
    status: completed
  - id: p0-inventory
    content: Read-only classification of every public-testnet escrow and journal state
    status: completed
  - id: p0-worker
    content: Verify hosted Worker/D1 health with read-only calls
    status: completed
  - id: p0-report
    content: Write baseline report and P4 go/no-go in the master ExecPlan
    status: completed
  - id: p0-revise
    content: Revise plans P1..P7 based on findings
    status: completed
isProject: false
---

# Plan 0 of 8: Baseline and private-state recovery

Series order: P0 baseline, P1 deadline policy, P2 swap state machine, P3 UI wallet integrations, P4 Bitcoin public cases, P5 relay identity and integrity, P6 Hegemon offline adapter, P7 cleanup/docs/CI. Each plan ends by revising the plans after it.

## Why first

- This machine runs Node 18.19. The swap code needs Node 24 (`node:sqlite`, global `crypto`), so 8 of 20 JS tests fail for environment reasons only.
- The plans store keys, journals and refund data in `/workspace/public-testnet-swap-20261102`, which does not exist here. Pending Bitcoin escrows, the Bitcoin refund and a Sepolia fixture escrow (`0x25b3e3f95ccd58ba022e6c00271f8a1f7cf4737d`) depend on that data.
- Found locally: `/home/william/Hegemon/hidden/hegemon-historical-testnet-journals-20261105.tar.gz.gpg` (gitignored via `/hidden`), encrypted to the local key `Cursor <Bob@williamdoyle.ca>` (F6DB8DA2D5D1A3D3). Related, unread: `~/Downloads/hegemon-testnet-wallets-20261104.tar.gz.gpg` and `~/Downloads/hegemon-swap-cursor-handoff-20261105.asc`.

## Steps

1. Consult `DESIGN.md`, `METHODS.md` and `.agent/PLANS.md`; create `.agent/SWAP_SERIES_EXECPLAN.md` as the master ExecPlan indexing P0..P7 with a progress checklist and a "plan revisions" log.
2. Install Node 24 user-local (no sudo, e.g. a tarball under `~/.local` or nvm). Run `node --test swap-ui/*.test.mjs swap-service/server.test.mjs swap-service/cloudflare/worker.test.mjs`. Expected: all pass. Any remaining failure is a real defect and gets logged.
3. Inventory the toolchain the Python/chain tests need: `forge`/`anvil`, `aiken`, `cardano-cli`, `bitcoind` 32.x, `embit`, `eth_account`, `cbor2`, Chromium/Playwright. Record which are present and which tests are therefore skippable. Run the unit tests that need none of them (`scripts/test_public_*.py` with `PYTHONPATH=scripts`).
4. Decryption is done by the user, not the agent (the passphrase prompt is not available to the agent). Ask the user to run, into a new 0700 directory outside the repo:
   - `install -d -m 700 ~/.hegemon-private/restore`
   - `gpg -d ~/Hegemon/hidden/hegemon-historical-testnet-journals-20261105.tar.gz.gpg | tar -xz -C ~/.hegemon-private/restore`
   - same for the wallets archive if the journals reference wallet files.
   The agent never prints key, preimage or signed-transaction contents.
5. Read-only inventory of the restored tree: list journal states (`prepared_or_submitted`, inflight), per-scenario state files (`btc-eth-state.json` and the Bitcoin suite cases), and which chain/outpoint/contract each escrow uses. Use `public_testnet_utxos.py`, `public_testnet_observers.py` and `public_testnet_probe.py` (read-only, no signing) to classify every escrow as live, claimed, refunded or unknown.
6. Specifically resolve: Bitcoin refund `0bdc031917d9be39cb332ee8ec440e36731353c7dd6ae6f3ecf3a5857d0f2804`, the BTC/Cardano claim, the other Bitcoin cases' funding outputs, and the Sepolia fixture refund. Note refund deadlines so P4 can prioritise anything expiring soon.
7. Verify the hosted Worker at the preview URL still responds and the D1 binding is intact (GET only, no destructive calls). Confirm `.gitignore` covers `hidden/`; leave `tools/user-sim/`, `start.sh` and `scripts/test_premainnet_launcher.py` untouched (unrelated to swaps).
8. Write the baseline report into the master ExecPlan: test results, tool gaps, escrow inventory (public IDs only), and the go/no-go for P4 (state recovered or fresh wallets needed).

## Acceptance

- JS suites 20/20 on Node 24. Python tests that need no chain tools pass.
- Every known escrow has a classified status backed by a public-chain read.
- No secrets in the repo or in terminal output.

## Last step: revise later plans

Update the master ExecPlan and edit P1..P7 for what this plan found:
- P4: restored vs fresh wallets, and any escrows near their refund deadline.
- P2/P6: which chain tools are missing, which decides what the engine can test locally.
- P3/P5: whether the hosted Worker is healthy and any D1 drift.
- P7: the Node 24 requirement and tool list to document.
