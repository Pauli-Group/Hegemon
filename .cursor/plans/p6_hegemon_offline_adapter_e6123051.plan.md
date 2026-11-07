---
name: P6 Hegemon offline adapter
overview: "Plan 6 of 8. Make the engine ready for Hegemon without the public testnet: a real local adapter over the private-spend flow tested on isolated chains, a remote-gateway spec, and a measured, separately-branched proving-cost investigation."
todos:
  - id: p6-execplan
    content: Write .agent/SWAP_HEGEMON_ADAPTER_EXECPLAN.md
    status: completed
  - id: p6-adapter
    content: Implement hegemon_local adapter with inflight/timeout/resume handling
    status: completed
  - id: p6-timing
    content: Feed proof time and lock minimum into the P1 policy
    status: completed
  - id: p6-e2e
    content: Local engine swaps for all HGN pairs plus refund, missing-counterparty and late-claim scenarios
    status: completed
  - id: p6-identity
    content: Hegemon identity field, local-only
    status: completed
  - id: p6-gateway
    content: Document scoped remote gateway design and interface check, no deployment
    status: completed
  - id: p6-proving
    content: Proving-cost harness and profile on a separate branch from main
    status: completed
  - id: p6-docs
    content: DESIGN.md and METHODS.md updates
    status: completed
  - id: p6-revise
    content: Revise plan P7 and define the follow-up for when public Hegemon testnet returns
    status: completed
isProject: false
---

# Plan 6 of 8: Hegemon offline adapter and proving cost

Depends on P1, P2 and P5. The Hegemon public testnet is stalled, so everything here runs on isolated local chains.

## Constraints

- On this branch the circuit, wallet, node and protocol source must stay identical to main (see `.agent/LOCAL_PRIVATE_SPEND_SWAP_EXECPLAN.md`); only `wallet/src/bin/private_spend.rs` and `private_spend_build.rs` differ. Proving optimizations therefore go on a separate branch from main, never into this one.
- Measured cost: lock and claim about 62 s and about 1.7 GB RSS, 179 s and 2.0 GB under load. Minimum lock window is 14 blocks (runner uses 16).
- Rely on `DESIGN.md` and `METHODS.md` for private-spend and HTLC rules; consult them before touching anything.

## Part A: real local Hegemon adapter for the engine

1. Write `.agent/SWAP_HEGEMON_ADAPTER_EXECPLAN.md`.
2. Implement `scripts/swap_engine/adapters/hegemon_local.py` wrapping `scripts/hegemon_action_runner.py`, `hegemon_local_actions.py`, `local_private_spend_swap.py` and `watch_hegemon_preimage.py`:
   - `verify_escrow` through the `private-spend` verification command;
   - `fund`/`claim`/`refund` through prepare then submit, with the encrypted refund handoff stored under the engine record directory (0700) and its passphrase never logged;
   - `observe_claim` from canonical action bytes (both bytearray and bytes handled);
   - long-running proofs modelled as an `inflight` state with a hard timeout and a determinate resume check (wallet status), because a lost response may still have submitted.
3. Apply P1 timing parameters: proof time and lock minimum feed the fund and claim cutoffs.
4. Local end-to-end: Hegemon dev chain with Bitcoin regtest, Anvil and local Cardano, running engine swaps HGN/BTC, HGN/ETH, HGN/ERC-20, HGN/ADA, HGN/Cardano-token; plus refund, missing-counterparty and late-claim scenarios mirroring the existing `local_private_spend_swap.py` cases. Fresh output directories only; stop owned processes; zero peers.
5. Identity: attach the Hegemon field reserved in P5, flagged as local-only until a key scheme exists.

## Part B: remote gateway specification (no public deployment)

6. Write a short design in `DESIGN.md` for a scoped, authenticated gateway so users need not run a full node: the minimal methods (chain tip, note sync for a given viewing key, verify escrow, submit prepared action), explicit exclusion of the unsafe wallet RPC, privacy and trust assumptions (the provider learns wallet activity metadata). Add a probe-compatible interface check next to `scripts/probe_hegemon_testnet.py`. Do not implement or expose anything publicly.

## Part C: proving cost investigation (separate branch from main)

7. Create a branch from main. Build a repeatable measurement harness (wall time and peak RSS via `wait4`, as the existing runner does) for lock, claim and refund, and profile where time and memory go in the private-spend proof path (`circuits/transaction/src/smallwood_htlc.rs` and related).
8. Report findings with numbers; implement only low-risk wins that do not change proof statements or the frozen relation; any change to the relation or parameters needs its own ExecPlan and review per the repo's proof-system rules.
9. Record before/after and the effect on P1's Hegemon timing numbers.

## Acceptance

- Engine completes local swaps for every HGN pair and the three failure scenarios, with crash-resume tests for the Hegemon inflight state.
- Gateway design is documented and checked against the repo's wallet RPC restrictions.
- Proving report is on its own branch; this branch's circuit source is still identical to main.

## Revisions from earlier plans

Revision from P0 (2026-11-05):
- Local Hegemon end-to-end runs also need Bitcoin Core (`bitcoind` 32.x, expected by `local_private_spend_swap.py` at `/workspace/bitcoin-32.1/bin/bitcoind`), Foundry's `anvil` and cardano tooling, none of which are installed on this host. Step 4 therefore depends on the tool installation added to P2; the Hegemon-only parts (adapter code, fake-chain tests, gateway design, proving harness) can proceed first.
- Proving-cost measurements need a Rust toolchain build of `hegemon-node` and `private-spend` (cargo is present); budget for roughly 2 GB of RAM per proof and several minutes per run.

Revision from P1 (2026-11-05):
- Hegemon timing is now data in `config/swap/chain-timing.json` (`chains.hegemon`): 3,000 public blocks (heights 7065 to 10064), mean 75.8 s outside outages, a 22.6-hour stall at height 9831 (excluded from the tables and covered only by a 7,200 s outage allowance), `minLockBlocks` 14, `proveSeconds` 300 (from the local proof times of 62 to 179 s on a loaded host), confirmations 2, provider lag 2 blocks, refund offset 1. The 14-block minimum lock the relation enforces (`private_spend/circuit.rs` line 508) is not a wall-clock guarantee: 12 blocks have taken 124 s. The policy asks a Hegemon claimant for at least 577 blocks from head to timeout (13,863 s claim window).
- The local adapter should report `head()` as `{observedAt, height}` and tag its profile `local` (manually advanced Development chain, outside the policy) or `public` (policy applies). Local runs keep their shortened deadlines; public runs use `plan_timeouts` / `legRequirements('hegemon')`.
- When the public profile calls `private-spend verify-htlc`, pass `--min-confirmations` and `--min-remaining-blocks` from `legRequirements` instead of the CLI defaults (2 and 2).
- Part C: if proving gets cheaper or slower, update `proveSeconds` in the config (data, not code) and rerun the vectors.

Revision from P2 (2026-11-06):
- The adapter contract this plan must satisfy is `scripts/swap_engine/adapter.py`: `chain = 'hegemon'`; `identity()` (string, the wallet's public identity for the lock); `head()` returning `{'observedAt', 'height'}`; `inspect(leg, escrow)` returning a LegObservation with keys `found, verified, problem, confirmations, spent (None|claimed|refunded), spend_confirmations, spend_txid, preimage (64 hex or None)`; `fund(leg, journal)`, `claim(leg, escrow, preimage, journal)`, `refund(leg, escrow, journal)` each returning `{'txid': ...}`; `escrow_ref(leg, txid)` returning a small dict of strings and ints; `journal_ids(journal)`; `transaction_seen(txid)`. `leg` carries `chain, amount, refundee, claimant, expiry, hashlock` where expiry is the Hegemon timeout in blocks and the hash is sha256 on every chain (confirm the relation's hash).
- Errors: raise `ChainUnavailable` for any failed or lagging read (wallet RPC down, node syncing, snapshot changed); raise `ActionRefused` for a write refused before anything is signed (insufficient balance, bad lock state, expired window); any other exception from a write is treated as uncertain and resolved from the journal, so a write that fails after proving or signing must leave a journal record.
- Journal needs: before broadcasting, write `<chain>-<txid>.signed` and `<chain>-<txid>.json` (`{version: 1, chain, txid, state: 'prepared_or_submitted'}`) into the per-swap journal directory with the same exclusive-create and fsync discipline as `scripts/public_swap_journal.py` (`swap_engine.store._write_new`). Proving takes minutes (`proveSeconds` in `config/swap/chain-timing.json` is 300), so decide what is journaled: the proved and signed transaction, never a pre-proof intent. `swap_engine.adapter.JournaledWrites` already provides `journal_ids` and a helper that maps pre-sign errors to `ActionRefused`.
- Follow the profile pattern: the adapter takes a profile (rpc, signed send, clock) so a local profile (loopback node, dev wallets) and a public profile share verification and parsing code. The engine has been exercised against real Anvil, bitcoind regtest and a Cardano cluster that way; Bitcoin Core, Anvil and cardano-node are now installed under `~/.local/opt/chain-tools`, so local Hegemon tests that need them can run. `swap_engine.adapters.hegemon_stub.HegemonStubAdapter` is the placeholder to replace (reads raise `ChainUnavailable`, writes raise `ActionRefused`); `swap_engine_cli.build_adapter('hegemon')` must construct the real adapter from a `hegemon` entry in the wallet config.
- Inflight discipline matters more here: a lock that takes minutes to prove is the likeliest place for a crash mid-write. The engine writes an inflight marker before the call and never re-signs while it is set; make `journal_ids` reflect proved transactions so a restart can adopt one the chain already shows.

Revision from P3 (2026-11-06):
- The UI has placeholders only for the Hegemon leg: `swap-ui/guided.mjs` reads a leg through `readers.<chain>` and reports a leg with no reader as "not readable", `swap-ui/guided-ui.mjs` labels the Hegemon leg "unavailable on public testnet", `swap-ui/swap-flow.mjs` already validates Hegemon identities and converts a Hegemon leg's height to policy form, and the observer section has no Hegemon option. When the adapter exists, a browser reader needs the shape `{escrow(ref), spend(ref)}` returning the same observation fields the other chains return (`found`, `verified`, `confirmations`, `problem`, `spent`, `spend_confirmations`, `spend_txid`, `preimage`) and heads as `{observedAt, height}`; its network access must go through a Worker route or the loopback companion because the page's Content-Security-Policy allows only its own origin.
- The adapter's `verify` result and the guided view must agree on the fields above, because the guided page reuses the engine's decision rules through `config/swap/flow-vectors.json`; if P6 changes the engine's observation schema, regenerate that file with `scripts/swap_engine/ui_vectors.py` and run `swap_engine.test_ui_vectors`.
- Qualification timing relevant to Hegemon pairing: Ethereum and Cardano legs confirm in about a minute (three confirmations in 40 to 60 seconds on Sepolia, under two minutes on preview), so a Hegemon proving cost of several minutes dominates a pair with either; Bitcoin testnet4 arrivals were irregular and slow at times on 2026-11-06 (see the P4 revision).

Revision from P4 (2026-11-06):
- The old public Bitcoin swaps funded the Bitcoin leg about 141 blocks (138 for BTC/ETH) ahead of its refund height and would all be rejected by the current policy (`insufficient-gap`, plus `claim-window-too-short` for BTC/ETH). Bitcoin as the long leg against a Hegemon short leg is the case the 30-day horizon and the 14.7 hour to 5 day Bitcoin spans make hardest, so P6's adapter and simulations should use `plan_with_margin` expiries and expect Bitcoin refund heights days out, not the +144 shortcut.
- Observed Bitcoin testnet4 spacing so far: 11 blocks (158786 to 158797) took about 6,070 s of header time on 2026-11-04 and 20 blocks (159444 to 159464) took about 108 minutes of wall-clock time on 2026-11-06; both are faster than the measured mean of 1,069 s per block, so the existing table stays the conservative basis and no config change is needed from P4 alone. Header times are not a reliable clock.
- A Hegemon verifier should be built like `scripts/verify_public_btc_cases.py`: take the terms from the swap record, re-derive what the chain must hold (the escrow commitment for the recorded hashlock, parties and expiry), check that the claim's revealed preimage hashes to the hashlock, and report claim order against both deadlines, so a finished Hegemon pair can be re-verified without trusting the scripts that ran it.

Revision from P5 (2026-11-06):
- Hegemon identity field shape today. A signed identity statement already has a slot for each leg, `{chain, address}`. For a Hegemon leg the only accepted address is the literal `pending` (validators: `hegemon:v=>v==='pending'` in `swap-ui/identity.mjs` and the same in `scripts/swap_engine/identity.py`); the page shows a read-only `pending` field (`legSpecs`, `normalizeAddress` in `swap-ui/identity-flow.mjs`), no proof is accepted for it, `verifyIdentity` lists the side under `unverified`, and `comparePair`/`check_terms` return no participants for a Hegemon leg, so no claim or refund address of a Hegemon escrow is compared with anything. This is deliberate and documented as pending, not faked.
- What P6's adapter must provide so P8 can replace it: (1) the Hegemon escrow terms must carry the claim and refund recipient strings the way the companion form does (`claim`, `refund`, shielded addresses) so `check_terms` has something to compare; (2) a decision on what a participant can sign offline to prove control of that recipient (a signature or opening produced by the wallet binary, because the browser has no Hegemon wallet) and on the exact text encoding, so it fits the existing statement text `hegemon.swap.identity.v1` plus canonical JSON; (3) one new `SCHEMES` entry in `swap-ui/identity-proofs.mjs` and its twin in `scripts/swap_engine/identity.py`, an address validator replacing `pending`, `legParticipants` in `swap-ui/pair-check.mjs` returning the Hegemon claimant and refundee, and independently produced vectors added through `scripts/make_identity_vectors.py` into `config/swap/identity-vectors.json` (independent means signed by the wallet binary itself, not by the verifier's own code). The page would take the signature by paste, like the Bitcoin BIP-137 path (`bitcoinProof`), or from the local companion.
- No change to the adapter interface or to the engine record is required: identities are stored under `record['identities']` by `Swap.attach_identities` and the CLI `identities` command, and a Hegemon side is simply listed as unverified until the scheme exists. If the adapter's observation schema changes anyway, regenerate `config/swap/flow-vectors.json` as noted in the P3 revision.
- Any file under `swap-ui/` that P6 adds or edits (for example a Hegemon reader) must be followed by `node scripts/build_client_manifest.mjs`; `node --test swap-ui/client-manifest.test.mjs` fails if the generated manifest, import map or hosted page is stale, and a stale import map makes the browser refuse to start the page.
- The hosted page's content security policy is `connect-src 'self'`, so a Hegemon reader in the hosted page must be a Worker route; only the local profile may talk to the companion at `http://127.0.0.1:8788`.

## Last step: revise later plans

Update the master ExecPlan and edit P7:
- P7: Hegemon adapter docs, the new test targets (which are heavy and must be opt-in), runbook items (`HEGEMON_SEEDS` with the approved seed list, NTP/chrony requirement), and what must be re-planned when the public Hegemon testnet returns (the first follow-up plan after P7).

Revision from P8 (2026-11-07): P7 closed with public Hegemon swaps as the follow-up. P8 is that follow-up and is executing: `.agent/HEGEMON_PUBLIC_SWAPS_EXECPLAN.md`. The local adapter (`LoopbackProfile`, `peers == 0`, `--development-local-candidate`) stays as P6 left it. P8 adds a separate `PublicHegemonProfile` and must not weaken those guards. The public CLI path is `build_adapter('hegemon')` with `"profile": "public"` in the wallet config.
