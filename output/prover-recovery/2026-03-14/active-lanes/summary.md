# Active-Lane Local Release Comparison

## Verdict

Kill `merge_root` as the low-TPS hot path.

The honest live baseline is `raw_active`, not `raw_shipping`. `raw_shipping` remains useful as the frozen transport fingerprint, but it omits the parent-bound commitment proof entirely. Once `raw_active` was measured directly against `merge_root_active`, merge-root lost at `k=1` and then failed to clear a `65s` wall-clock budget at `k=2`.

## Why `raw_active` Is The Real Baseline

The frozen raw archive under `output/prover-recovery/2026-03-14/raw-baseline/` still matters, and the release fingerprint remains canonical. But that transport lane reports:

- `commitment_prove_ns = 0`
- `commitment_verify_ns = 0`
- `commitment_proof_bytes = 0`

That means it is not the full live path a block would use. `raw_active` is the correct comparator because it measures canonical tx proof bytes plus the same commitment proof stage that `merge_root_active` also pays.

## Measured Results

Direct combined comparison at `k=1` (`benchmark-k1.json`):

- `raw_active`: `536098 B/tx`, `70812417 ns` active-path prove, `18299167 ns` active-path verify
- `merge_root_active`: `536258 B/tx`, `79701375 ns` active-path prove, `25680001 ns` active-path verify

Verdict at `k=1`: `raw_active` already wins on bytes, prove, and verify.

Isolated `raw_active` release runs (`raw-active-k*.json`):

- `k=1`: `536098 B/tx`, `82647708 ns` prove, `18820875 ns` verify
- `k=2`: `456262 B/tx`, `108371875 ns` prove, `29954584 ns` verify
- `k=4`: `411145 B/tx`, `156455625 ns` prove, `54544459 ns` verify
- `k=8`: `385872 B/tx`, `247197333 ns` prove, `102435334 ns` verify

`merge_root_active(k=2)` timed-stall evidence (`merge-root-k2-stall.txt`):

- command budgeted at `65s`
- status: `killed_after_budget`
- no JSON result was produced within budget

## Interpretation

The benchmark question is answered now.

- `merge_root_active` does not beat `raw_active` at `k=1`.
- `merge_root_active` does not even finish at `k=2` inside a `65s` wall-clock budget.
- `raw_active` remains comfortably sub-second on prove and verify at the same `k=2` point.

So merge-root is not the low-TPS hero. If it has any remaining purpose, it is as an experimental compression or archival path after the live raw lane exists, not as the default hot path.

## Next Work

1. Add an explicit raw/inline-tx live block-proof mode in `service.rs`, `prover_coordinator.rs`, and `consensus/src/proof.rs`.
2. Keep merge-root behind an experimental path only until it wins a future benchmark on a metric that matters.
3. Run the local acceptance matrix on the raw-active live lane, not on merge-root.
