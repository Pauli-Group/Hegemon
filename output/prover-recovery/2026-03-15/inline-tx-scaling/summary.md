# InlineTx Scaling Closeout

Status: `complete`

This archive closes the local InlineTx scaling question on the easy-chain throughput harness. The runs use the live `single` / `InlineTx` path, worker-side tx proving, and the existing parent-bound commitment proof path. Snapshot funding was done once per tx-count and reused per case.

## Cases

- `tx4-pw1`: proof+prepare `6.550 s`, ready->template `373 ms`, first eligible block included `True`, effective_tps `0.237883`
- `tx4-pw2`: proof+prepare `6.076 s`, ready->template `355 ms`, first eligible block included `True`, effective_tps `0.25363`
- `tx8-pw4`: proof+prepare `11.587 s`, ready->template `677 ms`, first eligible block included `True`, effective_tps `0.941398`
- `tx16-pw8`: proof+prepare `21.159 s`, ready->template `1375 ms`, first eligible block included `True`, effective_tps `0.888149`
- `tx32-pw1`: proof+prepare `53.262 s`, ready->template `2774 ms`, first eligible block included `True`, effective_tps `1.895847`
- `tx32-pw16`: proof+prepare `37.752 s`, ready->template `2634 ms`, first eligible block included `True`, effective_tps `4.716286`

## Verdict

- All cases under `proof-ready + prepare < 60 s`: `True`
- All cases included in first eligible mined block: `True`
- `tx32/pw16` vs `tx32/pw1` proof+prepare delta: `15.510 s` saved
- `tx32/pw16` vs `tx32/pw1` total-wall delta on this harness: `24.928 s` saved
- `tx32/pw16` vs `tx32/pw1` effective_tps delta: `2.8204390000000004`

## Artifacts

- `summary.tsv`
- `summary.json`
- `aggregate.json`
- `tx32-comparison.json`
- one subdirectory per case with `benchmark.json`, `send-trace.tsv`, `node.log`, `console.log`, and snapshot logs
