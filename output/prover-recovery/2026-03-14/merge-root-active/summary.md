# Merge-Root Active Local Release Check

## Verdict

Stall.

The benchmark is honest again and the first positive release `merge_root_active` run exists at `k=1`, but the next step (`k=2`, warm, release) did not complete in-turn after several minutes of sustained CPU time. That is now the real blocker, not anchor-history mismatch or raw-lane drift.

## Raw Lane Comparability

Reference archive:

- frozen raw baseline command: `cargo run --release -p circuits-bench -- --json --iterations 8 --batch-size 0 --lane-batch-sizes 1,2,4,8`
- frozen proof fingerprint: `tx_proof_bytes_avg ~= 352839`, `tx_trace_rows = 8192`, `fri_log_blowup_config = 4`, `fri_num_queries = 32`
- frozen raw `bytes_per_tx`: `354244 / 354240 / 354238 / 354237` for `k=1/2/4/8`

Current raw-only release check (`raw-compat.json`):

- `tx_proof_bytes_avg = 352790`
- `tx_trace_rows = 8192`
- `fri_log_blowup_config = 4`
- `fri_num_queries = 32`
- raw `bytes_per_tx = 354195 / 354191 / 354189 / 354188` for `k=1/2/4/8`

Assessment:

- The canonical tx proof object is back on the frozen release profile. The earlier `~86.84 kB/tx` result was a dev-build fast-FRI artifact, not a silent serialization or proof-object change.
- The remaining raw-lane byte delta versus the frozen archive is small (`49 / 49 / 49 / 49 B/tx` lower), which is consistent with fixture drift inside the same proof configuration, not a different proof format.

## Merge-Root Active

Positive release run completed for `k=1` (`benchmark.json`):

- warm cache mode: `warm`
- `leaf_prove_ns = 8649541`
- `merge_prove_ns = 0`
- `root_prove_ns = 0`
- `agg_verify_ns = 17000000`
- `commitment_prove_ns = 73457875`
- `commitment_verify_ns = 11057042`
- `root_proof_bytes = 354374`
- `commitment_proof_bytes = 181884`
- `bytes_per_tx = 536258`
- `total_active_path_prove_ns = 82107416`
- `total_active_path_verify_ns = 28301959`
- `agg_cache_hit = false`

Assessment:

- The positive singleton path now proves the real contract: canonical tx proofs with anchor-history-consistent roots can flow through leaf aggregation, aggregation verification, commitment proving, and commitment verification in release mode.
- Singleton merge-root is not compressive on bytes. At `k=1` it is substantially worse than raw shipping because the aggregation object and commitment proof both sit on the wire.

## Fixes That Made This Honest

- `circuits/bench` now generates benchmark tx proofs against a shared benchmark anchor-history tree instead of mixing standalone tx proofs with an empty commitment tree.
- `circuits/bench` now has explicit commitment-contract tests:
  - absent anchor root rejects
  - present anchor root succeeds
- `circuits/block` commitment AIR now parses the full public-input layout correctly, including the two kernel-root commitments. Before that fix, the AIR consumed the wrong offset into the nullifier region, which caused the debug row-0 constraint panic and the release `OodEvaluationMismatch`.
- `circuits/bench --raw-only` now lets the raw-shipping lane be rechecked against the frozen archive without paying merge-root aggregation cost.

## Attempted Next Step

Attempted command:

`cargo run --release -p circuits-bench -- --json --iterations 2 --batch-size 0 --lane-batch-sizes 2 --warm`

Observed result:

- The process remained CPU-active for several minutes and did not yield a JSON result in-turn.
- No archived `k=2` metrics were recorded because the run was not cleanly completed.

## Next Required Work

1. Capture a clean `k=2` warm release result or a timed stall result with explicit wall-clock and stage attribution.
2. If `k=2` does complete, continue to `k=4` and `k=8` in release mode and append those artifacts.
3. Do not run the local acceptance matrix until `k=2` is either measured cleanly or killed with evidence.
