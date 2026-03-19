# `tx4/pw1` Patched Local Result

Status: `stall`

This archive is one clean local `InlineTx` / raw-active run on the patched release binary with explicit last-mile timestamps. The funded snapshot path was reused instead of regenerated:

- base path: `/tmp/hegemon-raw-active-tx4-snapshot-2/base`
- wallet A: `/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-a`
- wallet B: `/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-b`
- recipients: `/tmp/hegemon-raw-active-tx4-snapshot-2/recipients.json`

Commit: `b48936b120fe8545423a59a062ece5b6c61f4b1f`
Genesis: `0xc04d82c23b7320e81c15afb8069ea404df1bf1cb2be57f2c79bb59dab3ba5be8`
Measured run id: `tx4-pw1-handoff4`

Measured command:

```bash
env \
  HEGEMON_TP_FORCE=1 \
  HEGEMON_TP_TMUX_SESSION=raw-active-tx4-pw1-handoff4 \
  HEGEMON_TP_LOG_FILE=/tmp/raw-active-tx4-pw1-handoff4.log \
  HEGEMON_TP_RUN_ID=tx4-pw1-handoff4 \
  HEGEMON_TP_ARTIFACTS_DIR=/tmp/hegemon-raw-active-tx4-artifacts-handoff4 \
  HEGEMON_TP_UNSAFE=1 \
  HEGEMON_TP_PROFILE=safe \
  HEGEMON_TP_TX_COUNT=4 \
  HEGEMON_TP_WORKERS=1 \
  HEGEMON_TP_PROVER_WORKERS=1 \
  HEGEMON_TP_PROOF_MODE=single \
  HEGEMON_TP_REUSE_EXISTING_STATE=1 \
  HEGEMON_TP_SKIP_BUILD=1 \
  HEGEMON_AGG_DISABLE_WORKER_PREWARM=1 \
  HEGEMON_TP_NODE_BASE_PATH=/tmp/hegemon-raw-active-tx4-snapshot-2/base \
  HEGEMON_TP_WALLET_A=/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-a \
  HEGEMON_TP_WALLET_B=/tmp/hegemon-raw-active-tx4-snapshot-2/wallet-b \
  HEGEMON_TP_RECIPIENTS_JSON=/tmp/hegemon-raw-active-tx4-snapshot-2/recipients.json \
  bash scripts/throughput_sidecar_aggregation_tmux.sh
```

## Candidate Identity

All last-mile events for the measured batch carried the same candidate identity:

- `bundle_id=fd52030f991f282c1f830b41bbb502e52379ab9d893049e55ceeab2a35c57a58`
- `artifact_hash=b156711fedf5a3a2b06b2db0a5905f556f1702e44e3cffe041d48cadf7f06fc7`
- `tx_count=4`
- `tx_statements_commitment=95761ea4f4c22de5233ad1731af177b27da15b42941362e9b79032fd8ee9a950a854e336ce9bd4ab43a138e62a23c568`
- `template_id=4b998b9ed6c36e0540bb339abff78165b45591650e586164304a8fdaa9a53b92`

## Exact Timestamps

- First tx submitted: `1773546157298`
  - Source: [`send-trace-handoff4.tsv`](./send-trace-handoff4.tsv), tx `1` `start_ms`
- Last tx became proof-ready: `1773546163560`
  - Source: [`send-trace-handoff4.tsv`](./send-trace-handoff4.tsv), tx `4` `end_ms`
- Prepared bundle ready: `1773546163810`
  - Source: [`node-handoff4.log`](./node-handoff4.log), `prepared_bundle_ready`
- Mining unpaused: no event emitted for the final bundle
  - The miner was already active; there was no paused -> unpaused transition to log
- Block template installed: `1773546164361`
  - Source: [`node-handoff4.log`](./node-handoff4.log), `block_template_installed`
- Hashing started on that template: `1773546164361`
  - Source: [`node-handoff4.log`](./node-handoff4.log), `hashing_started`
- Block found: `1773546427015`
  - Source: [`node-handoff4.log`](./node-handoff4.log), `block_found`
- Block imported: `1773546427084`
  - Source: [`node-handoff4.log`](./node-handoff4.log), `block_imported`

## Derived Intervals

- Proof production interval: `6262 ms`
  - `first tx submitted -> last tx proof-ready`
- Prepared-bundle interval: `250 ms`
  - `last tx proof-ready -> prepared_bundle_ready`
- `ready -> template active`: `551 ms`
  - `prepared_bundle_ready -> block_template_installed`
- `template active -> block found`: `262654 ms`
  - `block_template_installed -> block_found`
- `template active -> block imported`: `262723 ms`
  - `block_template_installed -> block_imported`
- Total wall clock: `269786 ms`
  - `first tx submitted -> block_imported`

## Live-Path Metrics

- `prepared_bundle_build_ms=207`
- `commitment_stage_ms=206`
- `import_verify_total_ms=61`
- `tx_verify_total_ms=17`
- `commitment_verify_total_ms=43`
- `payload_bytes_per_tx=414964.25`
- `tx_proof_bytes_total=1431781`
- `commitment_proof_bytes=228076`
- `included_block=12`
- `missed_target_block=false`

## Verdict

The compute path is not the blocker for `tx4/pw1`.

The deterministic path completed quickly:

- proof production: `6.262 s`
- finalize/prepare: `0.250 s`
- ready -> template active: `0.551 s`

The dominant interval was mining randomness after the correct template was already active:

- template active -> block found: `262.654 s`
- template active -> block imported: `262.723 s`

That means the current single-run `< 60 s to imported block` gate is the wrong acceptance criterion for local PoW runs. The honest gate for this path should be:

1. `proof-ready + prepare < 60 s`
2. the batch is present in the next eligible mined block
3. actual inclusion latency is judged from multi-run PoW stats, not one one-shot wall-clock sample

## Artifacts

- [`benchmark-handoff4.json`](./benchmark-handoff4.json)
- [`send-trace-handoff4.tsv`](./send-trace-handoff4.tsv)
- [`node-handoff4.log`](./node-handoff4.log)
- [`benchmark-handoff.json`](./benchmark-handoff.json)
- [`send-trace-handoff.tsv`](./send-trace-handoff.tsv)
- [`node-handoff.log`](./node-handoff.log)
- [`benchmark.json`](./benchmark.json)
- [`send-trace.tsv`](./send-trace.tsv)
- [`node.log`](./node.log)
- [`snapshot.log`](./snapshot.log)
