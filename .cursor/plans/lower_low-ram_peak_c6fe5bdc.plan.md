---
name: Lower low-RAM peak
overview: In low-RAM mode, keep the HTLC circuit off the heap during the commitment, fold constraints into the existing 5 polynomials instead of storing every constraint polynomial, and print stage sizes before the heavy allocation. Proof bytes stay the same. The goal is a claim that fits this 32 GB machine.
todos:
  - id: stage-sizes
    content: When the low-RAM flag is set, print row count, constraint count, column count, and resident memory before the commitment allocates.
    status: completed
  - id: drop-circuit
    content: Split the HTLC prove so the adapter is dropped for the commitment and rebuilt only for the constraint check.
    status: completed
  - id: fold-constraints
    content: In low-RAM mode, dot the constraints into the 5 gamma combinations at each sample and interpolate those 5, matching the current transcript.
    status: completed
  - id: drop-copies
    content: In low-RAM mode, drop the polynomial clone and the two row matrices before the Fourier work.
    status: completed
  - id: tests-docs
    content: Test the fold against interpolate-then-sum, remove the geometry probe, and update METHODS.md.
    status: completed
  - id: rerun
    content: Rebuild the node and wallet, then run happy --no-build. Stop and record journalctl RSS if the claim is OOM-killed.
    status: in_progress
isProject: false
---

# Fit the HTLC claim on this machine

The leaf-domain buffers are about 2 GiB. The claim was killed at 28.2 GiB because the HTLC circuit stays allocated through the commitment, and [`get_constraint_polynomials`](circuits/transaction/src/smallwood_engine.rs) then stores every constraint polynomial before folding them into 5. Low-RAM mode keeps the current proof bytes. The flag stays default-off.

`relation_digest()` includes the bytes of [`smallwood_engine.rs`](circuits/transaction/src/smallwood_engine.rs). Rebuild `hegemon-node` and the wallet examples after the engine edit. Do not cargo-clean. Do not commit.

## Print sizes first

When `HEGEMON_SMALLWOOD_LOW_RAM` is set, print one line to stderr from [`prove_statement_core`](circuits/transaction/src/smallwood_engine.rs) after `SmallwoodConfig` is built and before `pcs_commit`:

- `row_count`, `constraint_count`, `linear_constraint_count`, `nb_polys`, `nb_lvcs_cols`, `nb_lvcs_rows`
- resident memory from `getrusage` (`ru_maxrss`)

Print the same resident figure again after the commitment returns and after the constraint fold. The happy log then shows which stage owns the memory, including if the kernel kills the process later.

## Drop the circuit during the commitment

[`prove_candidate`](circuits/transaction/src/smallwood_htlc.rs) owns the adapter for the whole `prove_statement_...` call, so a drop inside the engine cannot free it. The commitment itself does not use the adapter. `pcs_commit` takes the config, the witness polynomials, and the masking polynomials.

With the flag set, `prove_candidate` does this:

- `compile` once, which builds the adapter and the packed witness
- copy the owned config, witness polynomials, masking polynomials, salt, and bindings out of a prepare step whose borrow of the adapter ends
- `drop` the adapter
- run `pcs_commit`
- `HtlcAdapter::from_statement` again and `use_smzc` only for `piop_run` and the rest of the proof

The witness is not evaluated a second time. The second `from_statement` rebuilds the same circuit and is the extra time. `prove_development` and the default flag-off path keep today's single call. Remove the temporary `geometry_probe` module at the bottom of [`smallwood_htlc.rs`](circuits/transaction/src/smallwood_htlc.rs).

## Fold into the 5 polynomials

`piop_run` already reduces every constraint polynomial with `gammas[rep]` into one polynomial per repetition, and `rho` is 5. Interpolation is linear, and the degree-factor removal runs after that sum, so the transcript is unchanged if each sample is combined first:

- at sample `s`, compute the constraint row once
- for each of the 5 gamma vectors, add the dot product into `combined[rep][s]`
- drop the constraint row
- interpolate the 5 combined sample vectors
- remove the packing roots and add `mpol_ppoly` exactly as today

Do this only when the flag is set. The default path keeps `get_constraint_polynomials`. Gamma length is `constraint_count` from `derive_gamma_prime`. Witness polynomials stay; the `constraint_count` by sample matrix does not.

Also, on the low-RAM path in [`pcs_commit`](circuits/transaction/src/smallwood_engine.rs), `drop` the polynomial clone and the unstacked rows after `stacked_rows` is filled. Take the stacked rows by value and `drop` them after `extended_rows` is filled, before `decs_commit_strict_bounded`. Randomness order stays: unstack draws, then extended-row masks, then masking polynomials and leaf tapes. `extended_rows` stay in the key. The witness polynomials stay for the PIOP.

## Tests and docs

Add a unit test that a gamma-weighted sum of interpolated samples equals interpolation of the gamma-weighted samples, using degree 2, 139 samples, and more than one constraint. That is the identity the fold uses.

Update the `HEGEMON_SMALLWOOD_LOW_RAM` paragraph in [`METHODS.md`](METHODS.md): the flag also drops the HTLC circuit for the commitment and rebuilds it for the constraint check, and it folds constraint samples into the 5 polynomials instead of retaining one polynomial per constraint. Leaf values, Merkle root, proof encoding, verification, and consensus stay the same.

## Memory check

Rebuild the node with `development-candidate,poseidon2-v8-retained-test-support` and the wallet examples. Run happy with `/tmp/hegemon-htlc-py/bin/python` and `--scenario happy --no-build`. The harness already sets `HEGEMON_SMALLWOOD_LOW_RAM=1`. This is a new schedule, not a retry of the 28.2 GiB kill.

If `launch_wallet_prepare` is OOM-killed, stop. Do not retry. Record `journalctl -k` anon-rss, total-vm, the stage-size line, elapsed seconds, and `MemTotal` in [`.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md`](.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md). If happy passes, run the other three scenarios with `--no-build`, then `make htlc-swap-e2e` with that venv's `python` first on `PATH`, and record the summary JSON. The local node uses `HEGEMON_SEEDS=""`. Shared miners still use `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` and NTP. Development and regtest only.
