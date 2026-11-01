---
name: Quadratic claim SHA
overview: Compile the HTLC claim preimage as local degree-2 SHA-256 gates so the affine-form blow-up never runs, then rebuild the node and wallet and try happy once.
todos:
  - id: quadratic-sha
    content: "Add sha256_quadratic: retained NOT, two-XOR parity, AND-plus-local-quadratic majority, degree 2 when no cubic kinds remain."
    status: completed
  - id: claim-call
    content: Call sha256_quadratic from the HTLC claim only. Leave sha() for asset-spend and recovery.
    status: completed
  - id: relation-digest
    content: Hash sha_lowering.rs, source_cse.rs, affine.rs, and boolean_guards.rs in relation_digest().
    status: completed
  - id: tests-docs
    content: Test truth tables, known SHA-256 digests, degree 2, and a 64-term form cap. Update METHODS.md.
    status: completed
  - id: rerun
    content: Rebuild node and wallet, run happy --no-build once. Stop and record RSS if OOM-killed; otherwise finish the other scenarios.
    status: completed
isProject: false
---

# Local degree-2 SHA for the HTLC claim

The claim dies in [`HtlcAdapter::from_statement`](circuits/transaction/src/smallwood_htlc.rs) while [`sha()`](circuits/transaction/src/smallwood_htlc.rs) turns 55,210 Boolean gates into affine forms. The lock never calls `sha` and finished near 1.7 GiB. The leaf domain stays as it is. This is a new relation: proof bytes change, and the node and wallet must be rebuilt together. Do not cargo-clean. Do not commit.

`sha()` also feeds the asset-spend and recovery circuits. Leave that function in place. Only the HTLC claim switches.

## Quadratic lowering

Add `sha256_quadratic` beside [`sha256_direct`](circuits/transaction/src/smallwood_htlc/sha_lowering.rs). Reuse [`Sha256Hashlock`](circuits/transaction/src/smallwood_htlc/sha256.rs) and the same bit endianness. Every value that a later gate reads is a `Node::Boolean`, which [`source_cse::build`](circuits/transaction/src/smallwood_htlc/source_cse.rs) already keeps as a single-term variable.

- XOR and AND stay the existing degree-2 kinds.
- NOT becomes a retained gate, `z = 1 - a`, instead of a linear expression.
- Parity becomes two XOR gates: `t = a XOR b`, then `z = t XOR c`.
- Majority becomes one AND plus one local degree-2 gate: `t = ab`, then `z = t + c(a + b - 2t)`. That second gate has four inputs, so its batch is five packed rows (output plus `t, a, b, c`). XOR, AND, and NOT keep the current four-row batches.
- The 32-bit digest words stay a linear packing of those retained output bits, then the existing `equal` to the policy hash.

[`from_graph`](circuits/transaction/src/smallwood_htlc/circuit.rs) currently forces degree 3 whenever any direct batch exists. Degree is 3 only when a cubic parity or majority kind is present. A quadratic-only graph reports degree 2. The same rule in `check_source_lowering` must match. [`sha256_direct`](circuits/transaction/src/smallwood_htlc/sha_lowering.rs) still emits cubic kinds, so its tests stay degree 3. The SMZC check in [`ensure_native_htlc_smzc_profile`](circuits/transaction/src/smallwood_engine.rs) keeps requiring degree 2.

In the claim arm, replace `sha(secret_bits)` with `sha256_quadratic(secret_bits)`.

## Relation identity

[`relation_digest()`](circuits/transaction/src/smallwood_htlc.rs) hashes `circuit.rs`, `sha256.rs`, and `smallwood_engine.rs`. It does not hash the modules those files pull in. Add `sha_lowering.rs`, `source_cse.rs`, `affine.rs`, and `boolean_guards.rs` to that hash. Rebuild `hegemon-node` with `development-candidate,poseidon2-v8-retained-test-support` and the wallet examples `launch_wallet_prepare` and `htlc_public_fixture` with `poseidon2-v8-retained-test-support`.

## Tests and docs

- Truth table: the quadratic parity and majority match Boolean parity and majority on every input bit.
- Known SHA-256 vectors: the packed witness from `sha256_quadratic` matches `sha2`, `constraint_degree()` is 2, and the longest affine form has at most 64 terms.
- Existing `sha256_direct` tests still pass.

Update the `HEGEMON_SMALLWOOD_LOW_RAM` paragraph in [`METHODS.md`](METHODS.md): the claim preimage is this local degree-2 lowering; the commitment domain, openings, low-RAM schedule, and verification of a proof produced by that schedule stay as they are. The relation identity now covers the lowering sources.

## Memory check

One happy run, not a retry of the 27.3 GiB kill:

`/tmp/hegemon-htlc-py/bin/python -u scripts/local_htlc_swap_e2e.py --scenario happy --no-build`

The harness already sets `HEGEMON_SMALLWOOD_LOW_RAM=1`. The local node uses `HEGEMON_SEEDS=""`. The `before_commit` line for the claim should show a few thousand to around ten thousand rows and a resident set in the same few-GiB class as the lock.

If `launch_wallet_prepare` is OOM-killed, stop. Do not retry. Record `journalctl -k` anon-rss, total-vm, the stage line, elapsed seconds, and `MemTotal` in [`.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md`](.agent/LOCAL_HTLC_SWAP_E2E_EXECPLAN.md). If happy passes, run `no_btc`, `both_refund`, and `late_claim` with `--no-build`, then `make htlc-swap-e2e` with that venv's `python` first on `PATH`, and record the summary JSON. Shared miners still use `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` and NTP. Development and regtest only.
