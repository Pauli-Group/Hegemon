# Raw Shipping Baseline

This archive freezes the local raw tx-proof shipping baseline before any new proving-primitive work.

## Command

    cargo run --release -p circuits-bench -- --json --iterations 8 --batch-size 0 --lane-batch-sizes 1,2,4,8

## Commit

    17c84c026a19dbff6b836a5d382d3c572c313eb4

## Machine

    Apple M2
    24 GiB RAM
    macOS 26.3.1 (25D2128)

The full machine metadata is in `machine.txt`. The full JSON output is in `benchmark.json`. A flat text extraction of the lane metrics is in `metrics.tsv`.

## Baseline Results

- `k=1`: raw shipping `354244 B/tx`, verify `7.688 ms/tx`
- `k=2`: raw shipping `354240 B/tx`, verify `7.901 ms/tx`
- `k=4`: raw shipping `354238 B/tx`, verify `8.316 ms/tx`
- `k=8`: raw shipping `354237 B/tx`, verify `8.499 ms/tx`

The wrapper lane stayed dead under the same run:

- `k=1`: `tx_proof_manifest` `355287 B/tx`, extra build `8.601 ms/tx`
- `k=2`: `tx_proof_manifest` `355262 B/tx`, extra build `8.163 ms/tx`
- `k=4`: `tx_proof_manifest` `355249 B/tx`, extra build `8.368 ms/tx`
- `k=8`: `tx_proof_manifest` `355243 B/tx`, extra build `8.553 ms/tx`

The legacy witness-batch STARK still compresses bytes, but it remains witness-bound and is not a permissionless public lane.

## Fallback Status

`HEGEMON_BLOCK_PROOF_MODE=flat` is still a dead request path. The node now logs a warning and falls back to `merge_root` instead of silently reviving `tx_proof_manifest`.

The active warning string is:

    HEGEMON_BLOCK_PROOF_MODE=flat is disabled after the tx-proof-manifest benchmark loss; falling back to merge_root

That warning is emitted from both `node/src/substrate/service.rs` and `node/src/substrate/prover_coordinator.rs`.
