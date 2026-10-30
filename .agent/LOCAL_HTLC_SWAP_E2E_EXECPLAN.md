# Local Hegemon and Bitcoin HTLC swap test

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, one command creates a brand-new local Hegemon chain and a brand-new Bitcoin regtest chain, funds both sides by mining, and runs four hash-time-lock swap scenarios. A person can see a successful swap, a Hegemon refund when Bitcoin was never funded, refunds on both chains, and a Hegemon claim that is rejected after the Hegemon refund. Nothing in the run joins a public network or grants production authority.

Run it from the repository root:

    make htlc-swap-e2e

A passing run prints a JSON summary whose top-level `status` is `passed` and whose four scenario entries are `happy`, `no_btc`, `both_refund`, and `late_claim`, each with `"status": "passed"`.

## Progress

- [x] (2026-10-30) Offline `launch_wallet_prepare offline-address` creates a wallet before any node exists and reopens to the same V8 address. Checked with the release example against `/tmp/htlc-addr-spike`.
- [x] Shared helpers live in `scripts/htlc_swap_lib.py`. The older rehearsal imports them, so `scripts/development_htlc_reorg_rehearsal.py` still imports those names from `scripts/development_atomic_swap_rehearsal.py`.
- [x] `scripts/local_htlc_swap_e2e.py` builds or reuses binaries, caches verified Bitcoin Core 31.1, and runs the four scenarios.
- [x] `make htlc-swap-e2e` invokes that script. `python3 scripts/test_local_htlc_swap_e2e.py` passes 9 daemon-free tests.
- [x] (2026-10-30) On this machine (`MemTotal` 32813140 kB), `python3 scripts/test_local_htlc_swap_e2e.py -v` passed 9 tests in 0.002s. The release node was rebuilt at `target/release/hegemon-node` (mtime 2026-10-30 13:05:57 -0400). `strings` on that binary contains `development candidate proof cap`. NTP was synchronized. Bitcoin Core 31.1 was fetched into `~/.cache/hegemon/bitcoin-core-31.1` and its pinned receipt verified.
- [ ] `make htlc-swap-e2e` passes all four scenarios. One `--scenario happy --no-build` run was started after that build. The Hegemon lock proof finished. The Hegemon claim proof was OOM-killed. Stopped. Did not retry, and did not run `no_btc`, `both_refund`, `late_claim`, or `make htlc-swap-e2e`.
- [x] METHODS.md, DESIGN.md, and `runbooks/pre_mainnet_rehearsal.md` name the command and its evidence boundary.

## Surprises & Discoveries

- Observation: `WalletStore::primary_address` is the legacy address. Mining and HTLC offers use `poseidon2_v8_address(0)`. Those two strings differ. The offline command prints both, and the harness mines to the V8 `address` field.
  Evidence: `offline-address` JSON has `same_as_primary`, and the end-to-end test fails if reopening changes `address`.

- Observation: `--print-development-candidate-manifest` prints a private-spend-only manifest. That profile rejects HTLC actions in `require_profile_action`. The harness deletes `private_spend_only` and `private_spend_source` before the node starts, and sets `pow_bits` to `0x207fffff`.
  Evidence: `htlc_capable_manifest` in `scripts/htlc_swap_lib.py`, and the node startup check that RPC `networkManifest` equals that edited file.

- Observation: the printed manifest caps `max_proof_bytes` at the private-spend carrier, 177632. The node then rejects an HTLC proof with "development candidate relation, binding, or proof byte cap rejected". Non-private-spend Development startup in `node/src/native/launch_v8_verifier.rs` allows proofs up to `smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES` (header 417 + ciphertext 2147 + 2 MiB). The harness sets that cap.
  Evidence: the first `happy` receipt under `/tmp/hegemon-htlc-e2e/happy/receipt.json`.

- Observation: retarget happens every 10 blocks and can multiply difficulty by 4 when blocks are fast (`RETARGET_WINDOW` in `consensus/src/reward.rs`). A timeout hundreds of blocks ahead, which the 10-second versus 600-second assumption demands, cannot be mined on this local chain. The harness still uses `timeout_margin_holds`, the same inequality as `HtlcOffer::check_timeout_margin`, with local assumptions of 60s Hegemon blocks, 1s regtest Bitcoin blocks, and 200s of safety. That keeps Hegemon's remaining time strictly longer and the timeout only a few blocks ahead.
  Evidence: `LOCAL_HGN_BLOCK_SECONDS`, `LOCAL_BTC_BLOCK_SECONDS`, and `LOCAL_SAFETY_SECONDS` in `scripts/local_htlc_swap_e2e.py`. The daemon-free test `test_local_regtest_gap_stays_inside_one_retarget_stretch` requires a gap of 4 to 20 blocks.

- Observation: 32 GB was not enough. The happy scenario on this machine got through wallet creation, a fresh Development node, mining to reward maturity, Bitcoin regtest, and the Hegemon lock proof. The kernel then OOM-killed `launch_wallet_prepare` during the Hegemon claim. anon-rss was 27992524 kB (26.7 GiB) and total-vm was 38301712 kB (36.5 GiB). It was a global OOM kill (`CONSTRAINT_NONE`), not a cgroup limit. Do not retry this proof on this machine. The next size that was recommended is a 64 GB Hetzner CCX43, not another 16 GB box.
  Evidence: `journalctl -k` on 2026-10-30 13:44:08–13:44:09 local. `oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=user.slice,mems_allowed=0,global_oom,task=launch_wallet_p,pid=302673,uid=1000`. The kill line is `Out of memory: Killed process 302673 (launch_wallet_p) total-vm:38301712kB, anon-rss:27992524kB, file-rss:0kB, shmem-rss:0kB`. The harness had just printed `happy: proving Hegemon claim`. The receipt at `/tmp/hegemon-htlc-e2e/happy/receipt.json` says exit code -9, elapsed 1113.317 seconds, and the last wallet progress line was `stage=unlock current=7 target=7 notes=0 elapsed_ms=7`.

- Observation: this machine's default `python3` imports `cryptography` 2.3 from the user site because `qrl` 4.0.5 pins that version. cryptography 2.3 has no compressed-point public format, so `rehearsal_bitcoin_key` cannot run under that interpreter. The happy attempt used a separate virtualenv at `/tmp/hegemon-htlc-py` with cryptography 50.0.2. The user-site package was put back to 2.3 afterward.
  Evidence: `python3` reported `/home/william/.local/lib/python3.10/site-packages/cryptography` version 2.3, and `pip` reported `qrl 4.0.5 requires cryptography==2.3`.

## Decision Log

- Decision: Alice holds the secret. She mines and locks Hegemon and claims Bitcoin. Bob funds Bitcoin and claims Hegemon.
  Rationale: the older rehearsal named both of one side "claim", so the same wallet claimed both assets. A swap only works if the secret's owner takes one chain and the counterparty takes the other.
  Date/Author: 2026-10-30 / local HTLC harness

- Decision: add `offline-address` to `wallet/examples/launch_wallet_prepare.rs` instead of bootstrapping with `private-spend`.
  Rationale: `launch_wallet_prepare init` needs a running node, but the manifest needs a funding address first. `private-spend bootstrap-new` uses different passphrase prompts. One wallet binary and one prompt style keep the driver simple. Reopening the same store returns the same V8 address, which is the mining and offer address.
  Date/Author: 2026-10-30 / local HTLC harness

- Decision: do not put this command in CI.
  Rationale: it downloads Bitcoin Core, starts both daemons, and generates several proofs. `scripts/test_local_htlc_swap_e2e.py` is the fast check for roles, the timeout inequality, manifest editing, and refusal of non-loopback RPC or a non-empty directory.
  Date/Author: 2026-10-30 / local HTLC harness

- Decision: allow a Development manifest's `max_proof_bytes` to reach `smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES`, and set the fresh test manifest to that ceiling.
  Rationale: the file loader previously stopped at the private-spend carrier (177632 bytes). The verifier already allows the larger HTLC carrier, and its own startup check uses that ceiling. An HTLC lock was rejected with "development candidate relation, binding, or proof byte cap rejected" under the smaller cap. The loader now uses the same ceiling as startup validation.
  Date/Author: 2026-10-30 / local HTLC harness

- Decision: model local Bitcoin blocks as 1 second inside the timeout inequality.
  Rationale: regtest does not wait ten minutes per block, and this chain cannot mine the height gap that a 600-second Bitcoin assumption creates. The inequality and the "Hegemon refund takes longer" rule stay. The conservative 10-versus-600 cases remain in the daemon-free test because they are what `wallet/src/htlc.rs` checks.
  Date/Author: 2026-10-30 / local HTLC harness

## Outcomes & Retrospective

The harness and the daemon-free tests are in place. The four-scenario run has not passed. On 2026-10-30 the happy scenario was run once on this 32 GB machine (`MemTotal` 32813140 kB) from branch `htlc-wip` at `5e3f80655f6b6f7da326ed87767b5ecd7d52f4bf`. The lock proof completed. The claim proof was OOM-killed at 26.7 GiB anon-rss after 1113.317 seconds. 32 GB was not enough. There is no passing summary JSON. The failed summary printed by the harness was:

    {
      "scenarios": [
        {
          "elapsed_seconds": 1113.317,
          "error": "wallet CLI failed with exit code -9: wallet-progress stage=unlock current=7 target=7 notes=0 elapsed_ms=7",
          "production_authorized": false,
          "scenario": "happy",
          "schema": "hegemon-local-htlc-swap-e2e-v1",
          "status": "failed"
        }
      ],
      "status": "failed"
    }

The same attempt was not repeated. `no_btc`, `both_refund`, `late_claim`, and `make htlc-swap-e2e` were not run. The next machine that was recommended is a 64 GB Hetzner CCX43.

What this must not be read as, even after a pass: production authority, a public network, or proof that a 10-minute Bitcoin assumption can be mined on this retarget schedule. The node is started with `HEGEMON_SEEDS=""`. Shared mining operators still use `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless that list has been rotated, and they keep NTP or chrony enabled because future-skewed proof-of-work timestamps are rejected.

## Context and Orientation

Hegemon is the project in this repository. An HTLC is a hash time-locked payment: one party can take the coins by revealing a secret before a deadline, and the other party can take them back after the deadline. This test runs one HTLC on Hegemon and the matching one on Bitcoin.

The Hegemon leg already exists. `wallet/examples/launch_wallet_prepare.rs` has `htlc` subcommands for the offer, the encrypted agreement, lock, claim, refund, and submit. `wallet/src/htlc.rs` builds the Bitcoin script and implements `HtlcOffer::check_timeout_margin`, which compares remaining time on each chain. It does not compare raw block heights. The node admits those transactions only on a Development manifest that is not private-spend-only, and only when started with `--development-candidate`. Coinbase rewards mature after 120 blocks (`COINBASE_MATURITY` in `protocol/versioning/src/lib.rs`), so the harness mines to height 121 before locking.

The Bitcoin leg already exists as a regtest rehearsal. `scripts/development_atomic_swap_rehearsal.py` drives Bitcoin Core and an already-running Hegemon node. It expects funded wallets and a chosen note. `experimental/htlc-prototype/bitcoin-regtest/fetch_core.sh` downloads Bitcoin Core 31.1, checks the pinned SHA-256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, and requires a valid signature from fingerprint `E777299FC265DD04793070EB944D35F9AC3DB76A`. Regtest is Bitcoin's private test chain. Its coins have no value. The daemon is started with `-regtest -listen=0 -connect=0 -dnsseed=0` and RPC bound to loopback, so it does not sync from the network.

`scripts/development_wallet_context.py` writes the wallet context file from a running Development node. `scripts/check_native_asset_lifecycle.py` showed the shape of a fresh Development node: print a manifest, set an easy proof-of-work target, start with `--dev --network development --development-candidate`, and mine with the RPC.

## Plan of Work

`wallet/examples/launch_wallet_prepare.rs` gains `offline-address`. It creates or opens a store with no RPC and prints the V8 address at the requested index plus the legacy primary address.

`scripts/htlc_swap_lib.py` holds the helpers that used to live only in the rehearsal: Bitcoin RPC, descriptor checksums, the wallet prompt driver, Hegemon RPC, mining-to-height, and the lock/claim/refund submission. The prompt driver also answers `Confirm passphrase:` so a new wallet can be created. `hgn_status` takes an optional swap id and a block limit. New helpers `timeout_margin_holds`, `plan_swap_deadlines`, `party_bitcoin_descriptors`, `htlc_capable_manifest`, `require_loopback_http`, and `require_fresh_directory` are pure enough to test without daemons.

`scripts/development_atomic_swap_rehearsal.py` keeps its command-line behavior and imports those helpers. Names imported by `scripts/development_htlc_reorg_rehearsal.py` stay exported from the rehearsal module.

`scripts/local_htlc_swap_e2e.py` is the new orchestrator. It builds `hegemon-node` with `development-candidate` and `poseidon2-v8-retained-test-support`, and the wallet examples `launch_wallet_prepare` and `htlc_public_fixture`. `--no-build` skips that. Bitcoin Core is taken from `--bitcoin-core-dir` or `~/.cache/hegemon/bitcoin-core-31.1` when `release-verification.json` matches the pin; otherwise `fetch_core.sh` runs into a new directory and is renamed into the cache.

Each scenario gets a new mode-0700 directory. It creates Alice, Bob, and a throwaway treasury wallet offline. The treasury address is only the manifest funding recipient. The node mines to Alice's V8 address and is started with `HEGEMON_SEEDS=""`, `HEGEMON_BOOTSTRAP_AUTHORING=1`, loopback RPC, and loopback peer listen. Context comes from `development_wallet_context.py`. The harness mines to height 121, syncs Alice, and locks one mature note for `note_value - 1` with fee 1, which is the exact input `prepare-lock` requires.

Bitcoin Core regtest starts with no peers. Bob receives 101 blocks so his coins are spendable. Deadlines come from `plan_swap_deadlines` using the local seconds above. Alice's key is the Bitcoin claim key. Bob's key is the Bitcoin refund key. The offer's Hegemon claim address is Bob and its refund address is Alice.

`happy` rejects a wrong Bitcoin secret, a premature Bitcoin refund, a wrong Hegemon secret, and a premature Hegemon refund. Alice then claims Bitcoin. The harness refuses the witness while that block is orphaned, restores it, and only then lets Bob import the secret and claim Hegemon. Bob must own a note of `value - fee`.

`no_btc` never sends Bitcoin to the contract. Alice's early refund is rejected. After the Hegemon timeout her refund confirms.

`both_refund` funds both sides and claims neither. Bob's early Bitcoin refund is rejected, then accepted at the refund height. Alice's Hegemon refund follows her timeout.

`late_claim` lets Alice claim Bitcoin and then refund Hegemon after the timeout, before Bob imports the secret. Bob's later `prepare-claim` must exit non-zero, write no artifact, and add no attempt.

The Makefile target `htlc-swap-e2e` runs all four. On failure the scenario directory is kept. `--keep` keeps successes too. Processes are stopped with SIGTERM and then SIGKILL.

## Concrete Steps

From the repository root `/home/william/projects/Hegemon`:

    python3 scripts/test_local_htlc_swap_e2e.py -v

Expect 9 tests, all ok, and no daemon.

    make htlc-swap-e2e

The first run downloads Bitcoin Core into `~/.cache/hegemon/bitcoin-core-31.1` unless that cache already verifies. Later runs reuse it. Expect a final JSON object with `"status": "passed"` and four scenario objects. Proofs take minutes each. A failed scenario prints `"status": "failed"` and leaves its directory under `/tmp/hegemon-htlc-e2e/<scenario>/`.

Useful flags, if you run the script directly:

    python3 scripts/local_htlc_swap_e2e.py --scenario happy --no-build --keep

`--scenario` accepts `happy`, `no_btc`, `both_refund`, `late_claim`, or `all`.

## Validation and Acceptance

The fast acceptance is `python3 scripts/test_local_htlc_swap_e2e.py -v`: 9 passed. Those tests fail if the timeout inequality, the party descriptors, the manifest edit, or the loopback and empty-directory checks regress.

The behavioral acceptance is `make htlc-swap-e2e`. Success is a JSON summary with `"status": "passed"` and these outcomes in the scenario objects:

- `happy`: Alice owns the Bitcoin output and Bob owns the Hegemon note.
- `no_btc`: Bob never funded Bitcoin, and Alice's Hegemon note returned after the timeout.
- `both_refund`: each party received their own asset back.
- `late_claim`: Bob's claim after Alice's refund was rejected (`"late_claim_rejected": true`).

Every scenario object has `"production_authorized": false` and `"hegemon_seeds": ""`.

## Idempotence and Recovery

The command can be run again. It reuses a verified Core cache and rebuilds binaries unless `--no-build` is set. Each scenario deletes its own directory at the start. A failed run leaves that directory for inspection, including `hegemon-node.log` and `receipt.json`. Delete `/tmp/hegemon-htlc-e2e` to remove leftovers. The Core cache lives in the home directory and is not part of the git tree. No system Bitcoin service is installed. Daemons are killed when a scenario ends, including after an error.

## Artifacts and Notes

Daemon-free result:

    Ran 9 tests in 0.001s
    OK

32 GB happy attempt, 2026-10-30, stopped after one OOM kill. `journalctl -k` records pid 302673 `launch_wallet_p`, anon-rss 27992524 kB, constraint `CONSTRAINT_NONE`. The scenario directory was left at `/tmp/hegemon-htlc-e2e/happy/`. `hegemon-node.log` in that directory is empty; the node was started with `RUST_LOG=warn`. The full four-scenario transcript is still outstanding.

## Interfaces and Dependencies

In `scripts/htlc_swap_lib.py`:

    def timeout_margin_holds(hegemon_height, bitcoin_height, timeout_height, refund_height,
                             hegemon_block_seconds=10, bitcoin_block_seconds=600, safety_seconds=600) -> bool

    def plan_swap_deadlines(hegemon_height, bitcoin_height, lifetime_exclusive=10001, bitcoin_window=8,
                            hegemon_block_seconds=10, bitcoin_block_seconds=600, safety_seconds=600) -> tuple[int, int]

    def party_bitcoin_descriptors(hashlock_hex, alice_pub, alice_wif, bob_pub, bob_wif, refund_height) -> dict

    def htlc_capable_manifest(printed: dict) -> dict

`launch_wallet_prepare offline-address --store PATH` prints JSON with `address`, `primary_address`, `index`, `created`, and `same_as_primary`.

The node binary must be built with features `development-candidate` and `poseidon2-v8-retained-test-support`. The wallet examples need `poseidon2-v8-retained-test-support`, which enables `rpc-client`. Bitcoin Core 31.1 is fetched by `experimental/htlc-prototype/bitcoin-regtest/fetch_core.sh`. Python needs the `cryptography` package for secp256k1 key generation, which the existing rehearsal already requires.

## Revision note

2026-10-30: Initial plan for the fresh-chain harness. The local timeout assumptions were narrowed so the refund height stays mineable under the 10-block retarget.

2026-10-30: Recorded the 32 GB happy-scenario attempt. The lock proof finished and the claim proof was OOM-killed at 26.7 GiB anon-rss. The run was not retried.
