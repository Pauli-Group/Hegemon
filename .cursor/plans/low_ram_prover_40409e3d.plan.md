---
name: Low RAM prover
overview: Add an opt-in schedule inside the shared Smallwood prover so any proof that uses the bounded commit can run with one less full copy of the row matrix and without Fourier-transforming every polynomial at once. The HTLC swap test is the first caller, not a special case. Node verification stays unchanged.
todos:
  - id: flag
    content: Read HEGEMON_SMALLWOOD_LOW_RAM inside the shared prover, and set it for the wallet process in run_wallet_cli
    status: pending
  - id: schedule
    content: When the flag is set, drop the full rotated-row copy and group the stripe FFTs for every bounded commit
    status: pending
  - id: tests
    content: Assert low-RAM and current schedulers hash the same leaves on the shared engine fixtures
    status: pending
  - id: docs
    content: Document the flag as a prover-wide schedule, including the HTLC rehearsal note in METHODS.md
    status: pending
  - id: rerun
    content: Rerun the HTLC happy scenario as the memory check; stop on another OOM
    status: pending
isProject: false
---

# Low-RAM Smallwood prover

This is a change to the shared prover, not to node consensus code, and not a special case inside the HTLC test.

The process that died at 26.7 GiB was `launch_wallet_prepare`, while it was building a claim proof. `hegemon-node` was a few hundred megabytes. Syncing, mining, and checking a proof do not rebuild those tables. A node that only verifies never enters this schedule. What a 32 GB machine cannot do today is **produce** a bounded-commit proof. That prover lives in [`circuits/transaction/src/smallwood_engine.rs`](circuits/transaction/src/smallwood_engine.rs) and is shared by every SHA-512 disjoint-coset profile that calls `decs_commit_strict_bounded` (HTLC SMZC, and the SMZ9, SMZA, SMZB, private-spend, and asset-spend profiles on that same path).

No file under [`node/src`](node/src) changes. The node binary links this crate, so a rebuilt node contains the new scheduler, but verification is untouched. An old node still accepts a proof from a low-RAM wallet, and a new node still accepts proofs from existing wallets.

The harness already sets `RAYON_NUM_THREADS=1` in [`scripts/htlc_swap_lib.py`](scripts/htlc_swap_lib.py). The claim still died. The resident set was about three retained copies of the same 140-row matrix. Turning more cores off will not fix it.

```mermaid
flowchart LR
  extended[extended_rows]
  rotated[rotated_rows]
  coeffs[interpolated coeffs]
  fft[all polynomial FFTs]
  leaves[Merkle leaves]
  extended --> rotated --> coeffs --> fft --> leaves
```

## Flag

Read `HEGEMON_SMALLWOOD_LOW_RAM` inside the engine, the same way it reads `HEGEMON_SMALLWOOD_TRACE`. Truthy values are `1` and `true`. Default remains today's schedule, so high-RAM provers stay on the current path until an operator asks for the other one.

Any process that proves honors the variable: the wallet example, a future node prove path, or a one-off prover binary. It is not parsed by the HTLC script alone. `run_wallet_cli` sets it so the local swap rehearsal actually uses the schedule. `node_env` keeps stripping unrelated `HEGEMON_*` variables for the isolated test chain; that does not matter for this flag, because the node does not prove the claim.

## Schedule

When the flag is set, every bounded commit uses the low-RAM schedule. There is no HTLC-only branch.

- Do not allocate the full `rotated_rows` matrix. Rotate one extended row into a reused buffer, interpolate it, store the coefficient row, and drop the temporary. `extended_rows` stays, because `LvcsKey` needs it at opening time. Entropy order stays masks first, then leaf tapes in leaf-index order.
- In `strict_coset_leaf_hashes_bounded`, hash the same leaves, but Fourier-transform a small group of polynomials at a time and reuse one scratch buffer. Do not hold a full-domain table for every polynomial at once. Write stripe results straight into the leaf vector. Leaf values, leaf order, and the Merkle root stay the same.
- Leave every `verify_candidate` and every profile's proof encoding untouched.

Each polynomial is still transformed once, so this is about as long as a full-RAM prove of the same statement. The harness is already one-threaded. The saved memory is copies, not skipped work.

## Tests and docs

- Extend the existing bounded-hash comparison in `smallwood_engine.rs` (domain sizes 64, 128, and 512) so the low-RAM scheduler returns the same leaves and the same Merkle root. Those fixtures are engine-level, not HTLC-only.
- Document `HEGEMON_SMALLWOOD_LOW_RAM` in [`METHODS.md`](METHODS.md) as a prover schedule for any bounded commit. In the `make htlc-swap-e2e` paragraph, say the rehearsal turns it on for the wallet. The local node still uses `HEGEMON_SEEDS=""`. Shared miners still use `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` and keep NTP or chrony enabled. The rehearsal remains Development plus regtest evidence and grants no production authority.
- Do not edit [`.cursor/plans/local_hgn_btc_swap_e2e_ef7c0b47.plan.md`](.cursor/plans/local_hgn_btc_swap_e2e_ef7c0b47.plan.md).

## Check on this machine

Rebuild the wallet example and run the happy HTLC scenario with `--no-build`. That is the memory check, because it is the prove that already exhausted 32 GB. If it passes, run the other three scenarios with `--no-build`, then `make htlc-swap-e2e`. If the prover is OOM-killed again, stop. Do not retry. Record RSS from `journalctl -k` in [`.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md`](.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md). On a real pass, record the summary JSON, elapsed time, and this machine's RAM there. Do not commit unless asked.
