# `tx4/pw1` Repeated Local Result

Status: `advance`

This archive contains 20 repeated local `InlineTx` / raw-active runs from the same funded snapshot source with no snapshot regeneration between runs. Each run copied the same funded snapshot into a fresh temp dir, used the patched release binary, and was reprocessed from the included bundle/block pair rather than the last prepared bundle in the log.

Funded snapshot source:

- `/tmp/hegemon-raw-active-tx4-snapshot-2/base`
- `/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-a`
- `/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-b`
- `/tmp/hegemon-raw-active-tx4-snapshot-2/recipients.json`

## Acceptance Rule Result

The PoW-aware gate passed in all 20 corrected runs:

- `proof-ready + prepare < 60 s`: `20 / 20`
- batch included in the first eligible mined block: `20 / 20`

That means the shielded pipeline is doing its job on `tx4/pw1`. The remaining wall-clock variance is PoW, not proving or miner/template handoff.

## Deterministic Shielded Path

- Proof production: mean `5.926 s`, median `5.885 s`, p90 `6.156 s`
- Prepare/finalize: mean `0.387 s`, median `0.383 s`, p90 `0.430 s`
- Proof + prepare: mean `6.313 s`, median `6.301 s`, p90 `6.576 s`
- `ready -> template active`: mean `369.7 ms`, median `370.5 ms`, p90 `376.0 ms`

## PoW-Driven Variance

- `template active -> first block found`: mean `117.282 s`, median `80.293 s`, p90 `220.037 s`, max `472.945 s`
- `template active -> bundle imported`: mean `117.348 s`, median `80.359 s`, p90 `220.103 s`, max `473.013 s`
- Total wall clock `first tx submitted -> imported`: mean `124.031 s`, median `87.031 s`, p90 `226.547 s`, max `479.475 s`

## Empty-Chain Comparison

The same release miner setup on an empty chain produced this 30-block baseline:

- Mean inter-block time: `134.552 s`
- Median inter-block time: `106.000 s`
- P90 inter-block time: `250.000 s`
- Max inter-block time: `374.000 s`

That empty-chain distribution is the right baseline for interpreting the tx runs. The tx trial `template -> first_found` distribution is the same order of magnitude, so total inclusion latency is dominated by PoW luck on this machine.

## Verdict

The current local evidence supports the PoW-aware acceptance rule:

1. `proof-ready + prepare < 60 s`
2. the batch appears in the next eligible mined block
3. total inclusion latency is treated as a distribution, not a one-shot SLA

On that rule, `tx4/pw1` passes locally. The next honest step is the scaling sweep on the same live lane: `tx4/pw2`, `tx8/pw4`, `tx16/pw8`, `tx32/pw16`.

## Artifacts

- `trials-fixed.json`
- `trials-fixed.tsv`
- `summary-fixed.json`
- `runs/run01` ... `runs/run20`
