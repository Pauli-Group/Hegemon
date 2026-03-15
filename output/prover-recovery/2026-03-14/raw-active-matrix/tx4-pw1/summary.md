# `tx4/pw1` Patched Local Result

Status: `stall`

This archive is one clean local `InlineTx` / raw-active run on the patched release binary. No matrix wrapper was used for the measured case. Snapshot bootstrap and experiment execution were split: a funded snapshot was prepared once, then reused for the single `tx4/pw1` run.

Commit: `f88557cfef2c098c14fec5f618bbe949fdd42941`
Genesis: `0xc04d82c23b7320e81c15afb8069ea404df1bf1cb2be57f2c79bb59dab3ba5be8`

Measured command:

```bash
env \
  HEGEMON_TP_FORCE=1 \
  HEGEMON_TP_TMUX_SESSION=raw-active-tx4-pw1 \
  HEGEMON_TP_LOG_FILE=/tmp/raw-active-tx4-pw1.log \
  HEGEMON_TP_RUN_ID=tx4-pw1 \
  HEGEMON_TP_ARTIFACTS_DIR=/tmp/hegemon-raw-active-tx4-artifacts-2 \
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

## Archived timestamps

- First tx submitted: `2026-03-15T02:45:58.356Z`
  - Source: [`send-trace.tsv`](./send-trace.tsv), tx `1` `start_ms`
- Last tx became proof-ready: `2026-03-15T02:46:04.357Z`
  - Source: [`send-trace.tsv`](./send-trace.tsv), tx `4` `end_ms`
- Prepared bundle became available: `2026-03-15T02:46:04Z`
  - Source: [`node.log`](./node.log), `Prepared proven batch candidate ... key_tx_count=4 ... build_ms=206 ... total_job_age_ms=439`
  - Precision note: node logs are second-resolution, so this timestamp is bounded to that second
- Block including the batch was imported: `2026-03-15T02:47:01Z`
  - Source: [`node.log`](./node.log), `Block imported successfully with state changes applied ... block_number=8`

## Derived breakdown

- Proof production interval: `6.001 s`
- Prepared-bundle interval: `< 1 s`
  - The `tx_count=4` finalize job itself reports `build_ms=206` and `total_job_age_ms=439`
  - Because the log timestamp is second-resolution, the exact absolute gap from last proof-ready to prepared-bundle availability is bounded within that second
- Inclusion wait interval: about `57 s`
- Total wall clock: about `62.6 s` to `63.6 s` from first tx submission to imported block
  - Harness `round_total_ms` to payload/verify metrics: `64.697 s`

## Live-path metrics

- `send_total_ms=6085`
- `prepared_bundle_build_ms=206`
- `block_import_verify_ms=61`
- `tx_verify_total_ms=16`
- `commitment_verify_total_ms=43`
- `payload_bytes_per_tx=415023.75`
- `tx_proof_bytes_total=1432019`
- `commitment_proof_bytes=228076`
- `start_block=7`
- `included_block=8`
- `missed_target_block=false`

## Verdict

`tx4/pw1` did not clear the `60 s` gate on the patched binary.

The dominant interval was the inclusion wait after proofs were ready and after the parent-bound bundle was prepared. Proof production was about `6 s` total for four txs. Finalize/commitment work was sub-second. The run then spent roughly `57 s` waiting for the mined inclusion block.

That means the blocker for this archived case is not recursive aggregation, not tx proof generation, and not bundle finalization. It is the post-proof inclusion interval on the local harness path.

## Artifacts

- [`benchmark.json`](./benchmark.json)
- [`send-trace.tsv`](./send-trace.tsv)
- [`node.log`](./node.log)
- [`snapshot.log`](./snapshot.log)
