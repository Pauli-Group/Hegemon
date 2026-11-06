# Four-chain swap series: baseline, policy, engine, interface, hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose

The branch `local-private-spend-htlc` builds a hash-time-locked-contract (HTLC) atomic swap system across Bitcoin, Ethereum, Cardano and Hegemon. An HTLC is an on-chain escrow that pays a named recipient who reveals the secret behind a published hash before a deadline, and otherwise refunds the sender after the deadline. A swap is two such escrows, one per chain, sharing one hash, so revealing the secret to claim one escrow lets the counterparty claim the other.

After this series, two people can find each other through the hosted offer board, verify each other's escrows with deadline margins that are actually reasoned about, and complete or refund a swap through a crash-safe engine, on Bitcoin testnet4, Ethereum Sepolia and Cardano preview. Hegemon swaps are proven on isolated local chains only, because the Hegemon public testnet is stalled; the series prepares the Hegemon adapter so public swaps can resume when the testnet returns.

The series has nine plans, P0 to P8, executed in this order: P0 to P6, then P8, then P7. P8 was added after P0 when the Hegemon public testnet resumed; P7 stays last and closes the series. Each plan's last step revises the plans after it, and each revision is recorded in the Plan Revisions section below.

- P0, baseline and private-state recovery: trustworthy tests and an inventory of what is live on public testnets.
- P1, deadline policy: one tested rule for cross-chain timeouts, shared by Python and JavaScript.
- P2, swap state machine: a durable two-party engine with adapters, replacing the one-off pairwise scripts.
- P3, UI wallet integrations: hosted claims, Cardano and Bitcoin wallet flows, preimage observers, a guided flow.
- P4, Bitcoin public cases: finish and verify the remaining public Bitcoin cases.
- P5, relay identity and integrity: wallet-signed identities, inbox key backup, verifiable client code.
- P6, Hegemon offline adapter: a real local Hegemon adapter, a remote gateway design, and a proving-cost investigation on a separate branch.
- P8, public Hegemon swaps: a synced public node, the wallet binary, calibration of Hegemon timing, and real public swaps of HGN with Ethereum, Bitcoin and Cardano. Runs after P6 and before P7.
- P7, cleanup, docs and CI: one test entry point, indexes, design documents, secret scan, PR split.

The repository rules apply to every plan: consult `DESIGN.md` and `METHODS.md` before code changes and update them when methods change; use `BRAND.md` for visual changes; mining or node runbooks must name `HEGEMON_SEEDS` with the approved seed list and the NTP or chrony requirement.

## Progress

- [x] (2026-11-05) P0 step 1: created this master ExecPlan.
- [x] (2026-11-05) P0 step 2: installed Node 24.22.2 under `~/.local/opt/node-v24.22.2-linux-x64` (checksum verified against the official SHASUMS file). JavaScript swap suites: 23 of 23 pass.
- [x] (2026-11-05) P0 step 3: inventoried tools and ran the Python tests that need no chain tools: 25 of 31 files pass; the other 6 fail only on hard-coded `/workspace/...` tool paths.
- [x] (2026-11-05) P0 step 4: the journals archive `hidden/hegemon-historical-testnet-journals-20261105.tar.gz.gpg` was decrypted into `~/.hegemon-private/restore/historical-testnet-journals-20261102` (directory mode 0700, files 0600) using the key passphrase file that the earlier session created with the key (see Decision Log). The intermediate tarball was shredded. The wallets archive was not decrypted: the journals archive omits wallet files by design and no wallet material is needed for the inventory.
- [x] (2026-11-05) P0 steps 5 and 6: every scenario, journal record and escrow was classified against public chains (see "Private-journal reconciliation" in the Baseline Report). Result: 22 scenario state files, 19 `complete` plus 3 `submitted` setup records that are confirmed on chain; 86 journal records, all confirmed; every escrow contract or output spent; nothing live.
- [x] (2026-11-05) P0 step 7: hosted Worker responds and serves the repository's client code.
- [x] (2026-11-05) P0 step 8: this baseline report.
- [x] (2026-11-05) P0 last step: revised P1 to P7 (see Plan Revisions).
- [x] (2026-11-05) P1 deadline policy: `.agent/SWAP_TIMELOCK_POLICY_EXECPLAN.md`; `config/swap/chain-timing.json` (measured), `swap-ui/timelock-policy.mjs` and `scripts/swap_engine/timelock_policy.py` sharing `config/swap/timelock-vectors.json`; unit, property and mutation tests in both languages (11 JavaScript policy tests, 7 Python policy tests, every mutation killed); `comparePair` and the public pair check reject insufficient spacing and the page shows the verdict; hosted verifiers and the Bitcoin and Cardano Python drivers take per-leg limits from the policy; `DESIGN.md`, `METHODS.md` and `swap-service/README.md` updated; plans P2 to P8 revised.
- [x] (2026-11-06) P2 swap state machine: `.agent/SWAP_ENGINE_EXECPLAN.md`; `scripts/swap_engine/` (engine, durable store, journal-based crash recovery, planner margin, simulated chains, Bitcoin, Ethereum and Cardano adapters, Hegemon stub, local profiles) and `scripts/swap_engine_cli.py`; 97 chain-free tests pass; all eight plannable ordered pairs among Bitcoin, Ethereum and Cardano and three refund scenarios pass on Anvil, bitcoind regtest and a private Cardano cluster; one real Sepolia/Cardano preview swap completed through the CLI (transaction ids in the ExecPlan); `DESIGN.md` and `METHODS.md` updated; plans P3 to P8 revised.
- [x] (2026-11-06) P3 UI wallet integrations: `.agent/SWAP_UI_WALLETS_EXECPLAN.md`; the hosted page performs Sepolia claim, Cardano CIP-30 fund/claim/refund and Bitcoin PSBT fund/claim/refund, observes counterparty preimages on all three chains, and has a guided view; Worker read and relay routes; vendored pinned libraries; 133 unit tests, six Playwright suites and real-software Cardano and Bitcoin tests; public-testnet qualification with stand-in wallets recorded in `PUBLIC_TESTNET_RESULTS.md`.
- [x] (2026-11-06) P4 Bitcoin public cases: nothing was left to resume (all four swaps and the refund completed on 2026-11-04). `scripts/verify_public_btc_cases.py` re-verified five Bitcoin cases and both Sepolia fixtures from raw bytes and public data (208 checks pass), with a retroactive P1 verdict for each pair; six stray Sepolia escrows and one Cardano escrow from P3 qualification were refunded; two 20,000-sat Bitcoin escrows from P3 are unrecoverable. Recorded in `PUBLIC_TESTNET_RESULTS.md`.
- [ ] P5 relay identity and integrity.
- [ ] P6 Hegemon offline adapter and proving cost.
- [ ] P8 public Hegemon swaps.
- [ ] P7 cleanup, docs, CI, PR split.

## Surprises & Discoveries

The earlier assessment said eight JavaScript tests failed and the baseline would be 20 of 20. The environment was Node 18.19, which lacks `node:sqlite` and the global `crypto`. On Node 24 the swap JavaScript tests number 23, not 20, because `swap-service/cloudflare/worker.test.mjs` could not even load on Node 18. Evidence: `node --test swap-ui/*.test.mjs swap-service/server.test.mjs swap-service/cloudflare/worker.test.mjs` reports `tests 23, pass 23, fail 0`.

Six Python test files fail only because their chain tools are expected at fixed paths: `/workspace/bitcoin-32.1/bin/bitcoind`, `/workspace/chain-tools/foundry/anvil`, `/workspace/chain-tools/cardano/bin/cardano-testnet` and `/workspace/chain-tools/aiken/aiken-x86_64-unknown-linux-musl/aiken`. The failing files are `test_public_bitcoin_transactions.py`, `test_public_btc_eth_integration.py`, `test_public_cardano_transactions.py`, `test_public_cardano_verify.py`, `test_public_ethereum_setup.py` and `test_public_ethereum_transactions.py`. An `aiken` binary exists at `~/.aiken/bin/aiken` (v1.0.26-alpha) but not at the expected path. This is a defect in the repository for portability: tool locations should be configurable. P7 owns the fix.

This machine lacks `forge`, `anvil`, `cardano-cli`, `cardano-node`, `ogmios`, `bitcoind` and `wrangler`. It has Python 3.10 without the `venv` module (no `ensurepip`), so the pinned Python dependencies from `scripts/requirements-htlc-public.txt` and `scripts/requirements-htlc-local.txt` were installed with `pip install --target` into `~/.local/opt/hegemon-swap-python`; use it with `PYTHONPATH=scripts:$HOME/.local/opt/hegemon-swap-python`. Chromium 156 is installed as a snap.

The work did not stop when the repository's last commit was made (2026-11-03 18:57 UTC). Public-chain reads show that all four prepared Bitcoin escrows and the Sepolia browser fixture were finished afterwards, but the results files in the repository do not record that. The recorded status is therefore stale, not the chain.

The served hosted client is byte-identical to the repository for `app.js`, `style.css` and `crypto.mjs`. The served root page differs from `swap-ui/index.html` only through the Worker's `HTMLRewriter` (title, eyebrow, note, hidden local-node sections), and `/index.html` redirects with HTTP 307. A manifest of served files in P5 must account for that rewrite. The public Sepolia RPC at publicnode prunes history older than about 12,000 blocks (event logs and receipts for the 2026-11-03 transactions return empty or null); an explorer API (Blockscout) is needed to read old Sepolia history.

The journals archive is a snapshot of the cloud task's private directory and includes preimage files named `secret`, signed transactions (`.signed`) and Cardano script bodies. Its `README.txt` states the Alice/Bob wallets, the Hegemon wallet directory and `addresses.json` were deliberately omitted and exist only on this PC, so the archive must never be extracted over the active wallets. Journal records (`.json`) carry the state `prepared_or_submitted` by design and are never updated to `confirmed`, so their state field cannot be used to learn confirmation; chain reads are required. Evidence: all 11 Bitcoin, 23 Cardano and 52 Sepolia journaled transactions read as confirmed or successful on public providers.

P1 found that deadlines measured in blocks are far less certain than they look. On Bitcoin testnet4 (2,000 blocks) the mean interval is 1,069 s, and spans of 144 blocks ran from 46,275 s to 151,329 s. On Hegemon (3,000 public blocks) 12 blocks have taken 124 s, so the 14-block minimum lock enforced by the relation is not a wall-clock guarantee, and one 22.6 hour stall occurred. Under a policy built on those measurements, a swap with a Bitcoin leg locks funds for 14.7 hours to 5 days and one with a Hegemon leg for 8 to 35 hours; only Ethereum and Cardano pairs finish in about two hours.

P1 found that the four contracts have different claim semantics. Ethereum and Cardano refuse a claim at or after the deadline; Bitcoin and Hegemon accept a claim until a refund lands, so the engine must enforce the claim cutoff (recorded in P2).

P1's earlier P0 revision said the existing public cases used very short margins. That overgeneralized: only the Bitcoin refund-case scenario used +6 blocks; the other scenarios used +144 blocks or timestamp margins. The +144 margin fails the measured policy by one block (145 are needed).

Swap-service tests on Node 24: `browser.test.mjs` aborts with a Node internal assertion after passing, and `desktop.test.mjs` and `desktop-node-profile.test.mjs` need the unbuilt `hegemon-app/out/renderer/index.html`. Both fail on the baseline without P1's changes. P7 owns them.

P3 found that the hosted Worker could not be exercised as deployed from this host (no Wrangler), so qualification hosts `worker.mjs` in Node; doing so exposed that Node's default 250 ms per-address connect attempt makes the Worker's own Blockstream and publicnode reads fail with ETIMEDOUT here, and that `/sepolia/escrow-events` could never have worked on a real escrow with its default `from_block=0` because publicnode caps `eth_getLogs` at 50000 blocks. P3 also found that a Plutus claim's validity upper bound must stay inside the ledger horizon (3600 slots here), that the Cardano HTLC needs only 250000 memory and 100000000 steps, that Koios returns empty or partial `tx_info` (empty inputs and `plutus_contracts`) for a confirmed transaction while a backend lags, and that Bitcoin testnet4 block arrival was uneven on 2026-11-06 (tip 159444 at about 16:20 UTC, 159456 at about 17:14, 159457 between 17:22 and 17:32, 159464 by about 18:08; header timestamps are not a reliable clock there), so waiting for two confirmations took roughly 12 to 50 minutes and a refund at tip+3 about 45 minutes, which is why waits are written as tens of minutes to hours and not as a fixed number of blocks times ten minutes.

P4 found that the open items listed in its plan were already complete on chain, so the work was verification: all four public Bitcoin swaps would be rejected by the current P1 policy (Bitcoin leg about 141 blocks from its refund height against a 145-block floor; `insufficient-gap` in each, plus `claim-window-too-short` for BTC/ETH), they completed because the chains were faster than the pessimistic tables, and testnet4 header times cannot show whether each Bitcoin escrow confirmed before the preimage was revealed on the other chain. P4 also found that P3's qualification runs had left two unspendable 20,000-sat Bitcoin escrows (the page generated the hashlock and the closed browser sessions took it with them), six refundable Sepolia escrows and one Cardano escrow; the Sepolia and Cardano ones were refunded, and the harness now records each run's hashlock. The Koios partial-`tx_info` behaviour reappeared (the verifier's first attempt got fewer transactions than it asked for), and the primary public Sepolia RPC had already pruned the oldest receipts.

## Decision Log

Decision: use the passphrase file `~/.config/cursor/gpg/cursor-bob.passphrase` (mode 0600) to decrypt the journals archive. The earlier assistant session generated the key `Cursor <Bob@williamdoyle.ca>` (ed25519, fingerprint 1DD2FB26C61765AF56ACA19AD42D03A7B648A858) with a random passphrase stored only in that file, and used the same file to decrypt the wallets archive and a handoff note. The user explicitly directed the agent to recover access from the earlier chats. The agent passed the file with `--passphrase-file` and never printed it. Date: 2026-11-05.

Decision: install Node 24 as an unpacked official tarball under `~/.local/opt` rather than using a system package or nvm, because it needs no administrator rights and leaves the system Node 18 untouched. Date: 2026-11-05.

Decision: install Python dependencies with `pip install --target` into `~/.local/opt/hegemon-swap-python` because `python3 -m venv` is unavailable on this host. They are the pinned versions from the repository's requirements files. Date: 2026-11-05.

Decision: the agent never decrypts the private archives itself. The passphrase prompt is unavailable to the agent and the secrets stay under the user's control. The agent created the empty mode-0700 destination `~/.hegemon-private/restore` and asks the user to run the decryption. Date: 2026-11-05.

Decision: classify escrows from public data first, then add private journal data. The public reads already show nothing known is live, so P4 does not need to wait for decryption to start planning. Date: 2026-11-05.

## Baseline Report

Environment: Node v24.22.2 (user-local), system Node 18.19 untouched, Python 3.10.12, Chromium 156, Aiken 1.0.26-alpha, Cargo present. Missing: Foundry, cardano-cli, cardano-node, Ogmios, Bitcoin Core, Wrangler.

Tests: JavaScript 23 of 23 pass. Python files that need no chain tools: all pass (25 of 31 files, covering the public drivers, journal, submit, observers, probe, UTxO readers, rehearsal state machines with mocks, local companion and the Hegemon action runner). Six files need chain tools at fixed paths and could not run.

Hosted Worker at https://hegemon-swap-testnet.willdoyle422.workers.dev: HTTP 200, the offers list is empty (`{"offers":[]}`), the Content-Security-Policy, nosniff, no-store and referrer headers are present. The served client matches the repository as described above. The D1 database was not touched.

Public-chain classification, public identifiers only, observed on 2026-11-05 through mempool.space (Bitcoin testnet4, tip height 159236), Koios (Cardano preview) and publicnode plus Blockscout (Sepolia):

Bitcoin testnet4. The BTC/ETH funding transaction `cdeecb1da3ea00b1a7e5e4981eb073a656526073da61fe201c98c1de8e85bd8a` output 0 was spent by claim `3ef145568dc1b97d37541c0091a205068be7bf0f95ef2897733c3ff2e5375e11` (height 158686). The wallet split `a05df909cec1aaf5f5ba2483882939f2ae653801ee056197d35633d3b8c3e67b` (height 158687) produced four 7,000-satoshi inputs, all spent into four funding transactions at height 158786: `d15914d8b39854d652a73d73e72b7d5ccaaf6678b1a1ac6c420cf912fcb6248e` (BTC/Cardano), `1e8a4ff81fdabecb32f5d38627c8a49a6b92a7537002488694800115c4fcfd4d` (refund case), `f08a5eda0161de93a62fb8c6f5a706911c2bcd19d1280589801ff516cf6c4649` and `5d47702867b5121ef3a509705949164e0973e0b8e6df7690da848f1ad5073160` (the other two cases; which is ERC-20 and which is Cardano token is recorded only in private journals). Each escrow output (output 0, 1,500 satoshis) is now spent, all in height 158797. The refund `0bdc031917d9be39cb332ee8ec440e36731353c7dd6ae6f3ecf3a5857d0f2804` spent `1e8a4ff8...` with locktime 158789 and a three-item witness shaped like the refund branch (signature, empty selector, script). The other three spends, `5888dafee51038f7b02bcdb268f55cb921c77fd6f8b3bb0dd753f036663e720c`, `9808daeca1ab0742f476803d058afa8b5eeb061271877a4090d763009b67f428` and `7bbadc7425361894bd5311cd91d0ddb9ac710ddec77ac84027b1ab61c297475e`, each carry a four-item witness shaped like the claim branch (signature, 32-byte preimage, true selector, script) and pay 1,250 satoshis. Witness shape is a classification, not a full verification: P4 must still verify each preimage against its hashlock and check the paired leg.

Cardano preview. The BTC/Cardano escrow `fe1d5bd435868b6a0edebde49d1c3ea27d9a530d56ef3270bcbacc9c75cea593#0` (10 ADA at the pinned validator) is spent, with 6,726 confirmations. The pinned validator address `addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv` holds no UTxOs, so no Cardano escrow is live.

Sepolia. The browser-originated fixture escrow `0x25b3e3f95ccd58ba022e6c00271f8a1f7cf4737d` (funded by `0xfb803ab4b1e9e68ca90804e7f97a1c2036b341b5e8dfb58fe77c11db1cfe6bb8`, block 12057135) was refunded by `0x94f5bfa945ab4fbecea24a08b54b5f87c58c98ea00c437d43f892981a03fdca7` (block 12057283, method selector `0x590e1ae3`, status ok); its `spent` flag is true and balance zero. The earlier verification fixture `0x2e30a4a829edcd7aae3580b1ed77ed6d009c883f` is spent with zero balance. The Ethereum token escrow used by the BTC/ERC-20 case is not identifiable from repository files; its status needs the private journals.

Private-journal reconciliation (2026-11-05). The decrypted journals contain 22 scenario state files. Nineteen record `phase: complete`; the three `submitted` records are `bitcoin-split` (`a05df909...`), `cardano-refuel` (`bbea0741...`) and `cardano-setup` (`f1710647...`), all of which are confirmed on chain. The 86 journal records (11 Bitcoin, 23 Cardano, 52 Sepolia) all read `prepared_or_submitted`, and every one of those transactions is confirmed or successful on public providers; none is stuck in an inflight state.

The previously unidentified paired legs are now known. BTC/ERC-20: Bitcoin funding `5d47702867b5121ef3a509705949164e0973e0b8e6df7690da848f1ad5073160`, Bitcoin claim `7bbadc7425361894bd5311cd91d0ddb9ac710ddec77ac84027b1ab61c297475e`, token escrow contract `0xf2fd8e0441a15ee14aa56114c3d759293de4027f` (ERC-20 fixture `0x801e4398f00f8a3d9a17850ba55bc387d3c57178`), Ethereum lock `a81e42b5c6fe4fe0b80532e295c07ef732deb69a2167a40debf74824ab48f6b4` and claim `04ed607d9e11135d015148cd5cd4024f64549664dcfcb48edaa87f0599afaafc`. BTC/Cardano token: Bitcoin funding `f08a5eda0161de93a62fb8c6f5a706911c2bcd19d1280589801ff516cf6c4649`, Bitcoin claim `9808daeca1ab0742f476803d058afa8b5eeb061271877a4090d763009b67f428`, Cardano lock `b1c66f3569ef624d6660003126a2582b8b8ce60a63402873a1f67a992c7a2f47` and claim `5761d261aeb8549868cfa93ed188507509dbace429e18e4fdc42d977077bf96d` (5 units of the fixture fungible token plus 4 ADA). BTC/Cardano ADA: Bitcoin funding `d15914d8...`, Bitcoin claim `5888dafe...`, Cardano lock `fe1d5bd4...` and claim `5ef1932af11943d51d47d340c4f9338f5250ef31ecbd887742b8d07afecc35bf`.

Verification performed with public data only: for each of the four Bitcoin claims (BTC/ETH `3ef14556...`, BTC/ADA `5888dafe...`, BTC/ADA-token `9808daec...`, BTC/ERC-20 `7bbadc74...`), the 32-byte preimage in the on-chain witness hashes with SHA-256 to the scenario's recorded hashlock, that hashlock appears in the witness script, and the claim paid 1,250 satoshis. Every Sepolia escrow contract named in any state file (14 contracts, including the BTC/ERC-20 and BTC/ETH ones) has code and `spent() == true`. The Cardano validator address holds no UTxOs. Not yet verified: that each paired non-Bitcoin leg used the same hashlock and paid the intended recipient and amount; that remains P4 work using the recorded terms.

Leftover public balances (read-only, 2026-11-05): Sepolia Alice `0xb4fB793C4dd3048c08399cfE26bD85B08b375e22` 0.1488 ETH and Bob `0x187930E437C4F965D4f2124647B33f5f9aBBC5fB` 0.0012 ETH; Cardano preview Alice 19,886 ADA in 4 UTxOs and Bob 91.4 ADA in 11 UTxOs; Bitcoin testnet4 wallet `tb1qzhv60lmaq7skxp0zm533hn73ldg3pydtyp7q3s...` 94,748 satoshis unspent. These are disposable test funds; an active wallet directory exists at `~/.local/share/hegemon-testnet-wallets-20261104` and was not read.

Conclusion: nothing known is live on any chain, so there is no refund deadline pressure. What remains for P4 is verification and recording, not rescue: verify the three Bitcoin claims against their hashlocks and paired legs, identify and verify the ERC-20 and Cardano-token legs, record everything in `PUBLIC_TESTNET_RESULTS.md`, and confirm the private wallets' leftover balances. Go for P4, with decryption still needed to finish the inventory and to recover leftover wallet funds.

P2 found that the P1 planner's expiries have zero slack (they sit on a step edge of the measured tables), so a one-block head advance breaks a plan; `scripts/swap_engine/planner.py` adds `plan_with_margin`, and any other port (the browser in P3) needs it too. Bitcoin/Bitcoin is unplannable under the real 30-day horizon. The public Ethereum RPC and Koios both return inconsistent answers for confirmed data (null receipts, empty `tx_info`/`tx_cbor`), so the adapters treat lag as unavailable rather than absent. The engine's recovery path was exercised accidentally by a bug in the local Cardano profile (a failure after journaling), and held the swap `inflight` as designed.

## Resolved gate

The private-state gate is resolved. The user could not remember the key passphrase, and the earlier session's passphrase file (`~/.config/cursor/gpg/cursor-bob.passphrase`) was used instead. To repeat the extraction on another machine, the same file and the private key in the local GPG keyring are required; without them, the archive cannot be opened. Keep an offline backup of that passphrase file and the key (`gpg --export-secret-keys`), because losing either makes `hidden/hegemon-historical-testnet-journals-20261105.tar.gz.gpg` and the wallets archive unrecoverable.

## Plan Revisions

Revision 2026-11-05, from P0:

P1 (deadline policy): the Bitcoin claims all landed in one block (158797) together with the Bitcoin refund, and the refund used locktime 158789 against funding at height 158786, only three blocks later. The existing public cases used very short test margins, so P1 must expect that existing public cases fail the new margin policy and should treat them as fixtures, not as compliant examples. Public Sepolia history is pruned by the default RPC; P1's measurement of real block intervals should use the Bitcoin testnet4 blocks above (heights 158680 to 158797 span from block_time 1793678145 to 1793738646 seconds, about 520 seconds per block on average, with large variance) rather than assume ten minutes.

P2 (state machine): missing tools (Foundry, Bitcoin Core, cardano-cli, Ogmios) mean local-fixture swaps through the engine cannot run on this host until those tools are installed or located; P2 gains an explicit first step to install or locate them, and the adapters must read tool paths from configuration or environment instead of fixed `/workspace` paths. Adapters also need an explorer fallback for old Sepolia events (Blockscout), because the default RPC prunes history.

P3 (UI wallets): the hosted Worker is healthy and the served client matches the repository; no D1 drift was observed. The Worker rewrites `index.html` with `HTMLRewriter`, which P3 must keep in mind when it adds Worker read proxies.

P4 (Bitcoin cases): changes from "finish the cases" to "verify and record cases that appear finished". Nothing is live; the Sepolia fixture refund exists (`0x94f5bfa9...`) and only needs recording. The ERC-20 and Cardano-token legs must be identified from the private journals. If the user cannot decrypt, P4 falls back to recording what public data shows and marks the unidentified legs as unverified. The "recover remaining funds" step depends on the wallets archive.

P5 (relay identity): the manifest of served files must account for the Worker's HTMLRewriter on `/` and the 307 on `/index.html`. Public Cloudflare headers already include a CSP; P5 extends it with Subresource Integrity rather than starting from none.

P6 (Hegemon): no change from P0 findings except that local Hegemon tests also need the Bitcoin Core and Anvil tools missing here.

P7 (cleanup): add to scope: make every tool path configurable via environment variables (replacing hard-coded `/workspace/...` paths in the six failing Python tests and the scripts they import), document the Node 24 requirement (`.nvmrc`) and the `pip --target` fallback when `python3-venv` is missing, and record that some public explorers prune old history.

Revision 2026-11-05, from P0 after decrypting the private journals (supersedes the P4 text above where they differ):

P4 (Bitcoin cases): the paired legs are now identified and recorded in the Baseline Report, so P4 no longer needs the user to decrypt anything. Its remaining work is verification and recording: confirm that each non-Bitcoin paired leg (Cardano `fe1d5bd4`/`5ef1932a`, Cardano token `b1c66f35`/`5761d261`, Ethereum token `a81e42b5`/`04ed607d` against escrow `0xf2fd8e04...`) uses the same hashlock as its Bitcoin leg and pays the intended recipient and amount; add all of it, plus the Sepolia fixture refund `94f5bfa9...` and the refund `0bdc0319...`, to `PUBLIC_TESTNET_RESULTS.md`; and mark the stale unchecked items in `.agent/PUBLIC_TESTNET_SWAP_EXECPLAN.md` and `.agent/HOSTED_TESTNET_SWAPS_EXECPLAN.md`. Funds sweep is optional: test wallets still hold about 0.15 ETH, about 19,977 ADA and 94,748 satoshis, which can fund P2's public acceptance run directly, so P2 does not need new faucet funds. The active wallet directory is `~/.local/share/hegemon-testnet-wallets-20261104`; never extract the journals archive over it.

P2 (state machine): reuse the recovered journals as ground truth for fault-injection tests, particularly the exact journal and state-file shapes (`prepared_or_submitted`, `state.json` phases `complete` and `submitted`). Use the known wallets for the public acceptance run rather than creating new ones.

P7 (cleanup): add to the secret scan that `hidden/` holds an encrypted archive of private journals and that decrypted copies live only under `~/.hegemon-private`. Document key and passphrase backup (see Resolved gate), since the archive depends on a passphrase file the user did not remember.

Revision 2026-11-05, from P1:

P2: the policy modules, config and vectors already exist under `scripts/swap_engine/`. The engine calls `check_pair`, `plan_timeouts` and `leg_requirements`, takes heads as `{observedAt, height}` or `{observedAt, timestamp}`, enforces the claim cutoff itself, and runs its first real public swap on Ethereum with Cardano (windows of hours) rather than Bitcoin (windows of days).

P3: the hosted page already renders the timing verdict in `#public-pair-timing`; reuse `timelock-policy.mjs` and `formatSeconds`, show "submit claim by", and keep the local regtest flow outside the testnet policy.

P4: the +144 block Bitcoin margin fails the measured policy by one block; new Bitcoin runs must use `plan_timeouts`, accept waits of days, or add a time-based Bitcoin timelock variant after its own design note.

P5: the served `swap-ui/timelock-policy.mjs` and `chain-timing.json` belong in the verifiable-client manifest; surface stale-head and provider-lag incidents.

P6: Hegemon timing data lives in `chains.hegemon`; the 14-block minimum is not wall-clock; the adapter tags profiles `local` or `public` and passes policy limits to `verify-htlc`.

P8: step 5 is largely done by P1's measurement; the "20 minute minimum lock" holds only for lone smoke locks, while swaps need at least 577 Hegemon blocks; choose pairs Ethereum or Cardano first, Bitcoin last; the 22.6 hour stall exceeds the outage allowance and goes into the runbook.

P7: test entry points, the baseline failures noted above, the P1 documentation index, and a backlog entry for refreshing the measured tables.

Revision 2026-11-06, from P2:

P3: do not port the signing engine to the browser; port only `decide`/`explain` for display and `planner.plan_with_margin` for expiries, with JSON vectors generated from the Python engine. Identity strings and escrow references have fixed per-chain forms (listed in the P3 plan).

P4: Bitcoin swap legs run through the engine's `BitcoinAdapter`; Bitcoin/Bitcoin is unplannable; Bob's Bitcoin outputs are too small (1,250 sats) to fund a normal escrow.

P5: the relay carries terms and escrow references only, never a preimage; bind offers to the exact per-chain identity strings and `terms_digest`.

P6: the exact `ChainAdapter` contract, error contract and journal format are in the P6 plan; the Hegemon stub is in `scripts/swap_engine/adapters/hegemon_stub.py`.

P7: new test commands (97 chain-free tests in about 18 seconds; the real-chains suite needs `HEGEMON_LOCAL_CHAINS=1`), superseded rehearsal scripts, secret-scan additions for swap stores and journals, and the PR split for the uncommitted P1 and P2 work.

P8: run through the engine, use `plan_with_margin`, allow for proving time and stalls, Ethereum and Cardano pairs first.

Revision 2026-11-06, from P3:

P4: the page can now fund, claim and refund Bitcoin testnet4 escrows through PSBTs, so a Bitcoin case no longer needs a script for those steps (splits, refund rehearsals and token legs still do); `scripts/qualification_signer.py btc-sign` is an independent PSBT signer to reuse; Worker Bitcoin reads have no mempool.space fallback; plan for hours-long confirmation waits and a refund height at least 145 blocks out for any UI claim.

P5: the files the page loads (vendored bundles, twelve new modules, four data files) and the import-map or single-bundle need for integrity, `server.ts`'s hand-maintained allow-list, the unused CIP-30 `signData` primitive for Cardano identity binding, no Ethereum message-signing verifier or keccak in the bundle, no Bitcoin message-signing path, the provider incidents to surface, and the abuse budget for the new unauthenticated Worker routes including broadcast.

P6: the Hegemon leg is only a placeholder in the page (`readers.hegemon` absent, leg labelled unavailable); the reader shape is `{escrow, spend}` returning the engine's observation fields and heads as `{observedAt, height}`, and the page must reach Hegemon through a Worker route or the loopback companion. Regenerate `config/swap/flow-vectors.json` if the engine's observation schema changes.

P7: new test commands and dependencies, the qualification harness that must stay out of CI, the Worker change that is undeployed, the documentation touched and the file list for the PR split.

P8: the UI work is a reader and removing a label; non-Hegemon legs of HGN/ETH, HGN/ADA and HGN/BTC swaps can be verified, claimed and refunded from the page.

Revision 2026-11-06, from P4:

P5: read Bitcoin from two genesis-checked providers and require agreement, say when a chain has a single provider, treat partial answers as unavailable, show which source answered for pruned Ethereum history, store the observer's wall-clock time and head with every observation, and require full escrow terms and hashlock in every stored offer so a lost session cannot strand funds.

P6: Bitcoin as the long leg against a Hegemon short leg is the hardest case; use `plan_with_margin` and days-long Bitcoin refund heights; build the Hegemon verifier in the style of `verify_public_btc_cases.py`; observed Bitcoin spacing so far is faster than the measured mean, so the config table stays.

P7: new verifier, tests and sweep tools (keep the verifier in CI scope, the sweep tools and qualification harness out), seven `/workspace` hard-coded tool-path errors in `test_public_*.py` still to fix, final public matrix location, two abandoned Bitcoin escrows to state plainly, and the private journal paths that must stay out of the repository.

P8: Bitcoin legs need refund heights at least 145 blocks out; record escrow terms and hashlock before funding; re-verify each public Hegemon swap from public data and record heads and observation times.

## Outcomes & Retrospective

P0 is complete. Outcomes: a verified Node 24 baseline (23 of 23 JavaScript tests, 25 of 31 Python test files without chain tools), a clear list of missing tools and hard-coded paths, a healthy hosted Worker, the private journals recovered into a 0700 directory and reconciled with public chains (86 of 86 journaled transactions confirmed, every escrow spent, four Bitcoin claim preimages matching their hashlocks), and the identity of every paired leg. No escrow is live and nothing needs rescuing. Lessons: results files in the repository had drifted behind the chain; the journal `prepared_or_submitted` state never advances, so chain reads are mandatory; a randomly generated passphrase stored in one file is a single point of failure and should be backed up.

P1 is complete. Outcomes: one measured, tested cross-chain deadline policy shared by the browser and Python; per-leg floors enforced by the hosted verifiers and the Bitcoin and Cardano drivers; a pair check that rejects insufficient spacing and shows why; documentation. Test results: JavaScript 33 of 33 in `swap-ui`, 7 of 7 Python policy tests, 6 of 6 Python Bitcoin driver tests, the Chromium test of the served page passes. Gaps: the Python rehearsal scripts still carry their own literal margins until the P2 engine replaces them; the Cardano Python verifier test cannot run here because Aiken and cardano-cli sit at hard-coded `/workspace` paths; the policy has no protection against a chain stall longer than two hours, and Hegemon has had one of 22.6 hours; the hosted verifiers cannot check Hegemon legs yet (P8).

P2 is complete. Outcomes: a crash-safe two-party engine behind one adapter contract and a CLI; 97 chain-free tests (store, engine, planner, simulated-chain faults and crash sweeps, adapters, policy); real-software local swaps for every plannable pair among Bitcoin, Ethereum and Cardano plus refund scenarios; one real public Sepolia/Cardano preview swap in about seven minutes with all four transaction ids recorded. Gaps: no Hegemon adapter yet (stub), no automatic rebroadcast or fee bump, public refund paths exercised only on local and simulated chains, Bitcoin/Bitcoin unplannable, the Cardano spender lookup depends on Koios indexing, and the P1 and P2 work is uncommitted.

P3 is complete. Outcomes: the hosted page performs Sepolia claim from an encrypted backup, Cardano CIP-30 fund, claim and refund, Bitcoin PSBT fund, claim and refund, observes counterparty preimages on all three chains, and shows a read-only guided view that reuses the P1 policy verdict and the P2 decision rules (held equal to Python by shared vectors). Evidence: 133 JavaScript unit tests, Playwright suites with mocked wallets, real-software local Cardano and bitcoind tests, and a public-testnet run on Sepolia, Cardano preview and Bitcoin testnet4 covering fund, claim, observer, lost-response and refund with transaction ids in `PUBLIC_TESTNET_RESULTS.md`. Gaps: stand-in software wallets and not browser-extension wallets; the Worker was hosted in Node and not redeployed (operator must deploy it before the page works on the hosted domain); stale-head and declined cases are mock-only; the guided view has not driven a live engine swap; Hegemon is labelled unavailable; the Bitcoin legs came from two runs; eight disposable stray escrows (six Sepolia, one Cardano, one Bitcoin) remain from aborted harness runs, listed in the results file; `swap-service/browser.test.mjs` aborts at exit after its assertions pass.

P4 is complete. Outcomes: every public pair among BTC and ETH, ERC-20, ADA and an ADA token, the Bitcoin refund and both Sepolia fixtures are independently re-verified from public data (208 checks, 16 offline mutation tests that must each make the verifier fail), with all IDs, the paired legs' hashlocks, parties, amounts and claim order, and a retroactive policy verdict, in `PUBLIC_TESTNET_RESULTS.md`; seven stray escrows from P3 were refunded and a scan of the two Sepolia wallets' contracts, the Cardano validator address and the Bitcoin wallets' P2WSH outputs found no other live escrow. Gaps: two 20,000-sat Bitcoin escrows (`05995b8c...` and `cc72202d...`) are permanently unspendable, so the plan's "zero escrows remain live or unknown" is not met for them; Cardano has a single provider; the Sepolia contract scan covered at most the first 600 transactions of each wallet; no new swap or hosted-page claim was needed or run; confirmation order between Bitcoin and the other chain cannot be reconstructed because testnet4 header times are unreliable; the work is uncommitted.
