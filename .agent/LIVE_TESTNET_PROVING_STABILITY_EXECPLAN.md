# Stabilize External Proving On The Live Testnet

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [.agent/PLANS.md](.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon is supposed to be a permissionless PoW chain whose private transaction throughput scales with parallel proving. On the current live testnet, that promise breaks down before the first recursive leaf proof lands: the public authoring node keeps mining empty PoW blocks while the external prover is still working, so the coordinator rotates to a new parent and the proof work becomes stale. After this change, a public authoring node that accepts proof-sidecar traffic can hold local mining long enough for a ready proven batch to appear, then resume mining and include it. A novice operator should be able to deploy `hegemon-ovh` plus `hegemon-prover`, submit a proof-sidecar transfer, and observe that the author pauses mining while the recursive proof is prepared and then mines the proven batch instead of churning forever.

## Progress

- [x] (2026-03-13 20:05Z) Reproduced the live failure mode on the OVH/prover topology and confirmed that `HEGEMON_AGGREGATION_PROOFS=1` plus 1-hour job/TTL budgets are required just to publish live stage work.
- [x] (2026-03-13 20:28Z) Identified the real bottleneck: the coordinator clears stage work on every new parent while the miner keeps producing empty blocks, so long recursive proofs never target a stable parent.
- [x] (2026-03-13 20:46Z) Implemented a local-mining hold path wired from `node/src/substrate/service.rs` through `node/src/substrate/client.rs` into `node/src/substrate/mining_worker.rs`, plus external-worker prewarm/logging in `node/src/bin/prover_worker.rs`.
- [x] (2026-03-13 20:54Z) Built and tested the patched binaries locally with the macOS libclang environment from `Makefile`; targeted `mining_pause` tests passed and `cargo build -p hegemon-node --features substrate --release --bins` succeeded.
- [x] (2026-03-13 20:58Z) Redeployed the patched Linux binaries to `hegemon-ovh`, rebuilt `hegemon-prover-worker` on the prover host, and restarted the public authoring node plus an external worker against the OVH RPC tunnel.
- [x] (2026-03-13 20:46Z) Re-ran a live proof-sidecar transfer (`0xf401c4598c17a250cbf5a819430023a624048002566fcdef880f7adb8106a46b`) and measured the current live bottleneck.
- [x] (2026-03-13 20:58Z) Updated final outcomes in this plan with the current live verification result.

## Surprises & Discoveries

- Observation: the first production blocker was deployment, not proof verification. The OVH environment was missing `HEGEMON_AGGREGATION_PROOFS=1`, so the authoring node logged `Skipping proofless shielded transfer: HEGEMON_AGGREGATION_PROOFS is disabled`.
  Evidence: OVH journal output from March 13, 2026 showed repeated `Skipping proofless shielded transfer` lines until the env file was corrected and the service restarted.

- Observation: external proving was not dead; the worker was consuming heavy CPU on a live `leaf_batch_prove` package for a single transaction.
  Evidence: `ps` on `hegemon-prover` showed the worker at roughly `65` threads and about `49` CPU minutes after only a few wall-clock minutes.

- Observation: the deeper failure is parent churn. The coordinator keys recursive stage work to `(parent_hash, block_number, candidate_txs)` and clears work queues and recursive assemblies on every new best block. Because the public miner kept advancing the chain while the external worker was still proving, the work package disappeared before it could ever be submitted back.
  Evidence: `prover_getStagePlanStatus` kept changing generation/latest package while `prepared_bundles` remained `0`, and previously observed package ids returned `null` from `prover_getWorkStatus` within minutes even though the worker was still burning CPU.

- Observation: the mining-hold fix does stabilize the live parent on OVH. After redeploy, the public authoring node stopped at height `130`, logged `Mining paused while waiting for a ready proven batch`, and held the same `latest_work_package` for more than six minutes instead of continuing to mine empty deferral blocks.
  Evidence: the March 13, 2026 OVH journal shows the pause log line, `chain_getHeader` stayed pinned at block `130`, and `prover_getStagePlanStatus` kept the same package id `c08217478e848e6518f5296dfc915297b18b90b5d67fc021c2fc7f3e35d97ad6`.

- Observation: `hegemon-prover` still has a broken local sync-node supervisor path that repeatedly launches a non-mining node and then dies with `Essential task txpool-background failed`. That local node is not required for the external worker, which can prove directly against the OVH RPC tunnel on `127.0.0.1:19944`, but the current supervisor script is not a clean deployment state.
  Evidence: `/home/localadmin/hegemon-live-run/prover-stack.sh` keeps launching `hegemon-node` plus a worker, and `node.log` on March 13, 2026 shows the node dying immediately after `RPC server started` with `Essential task txpool-background failed`.

## Decision Log

- Decision: fix the current topology by holding local mining while a strict proofless batch is waiting on a ready prepared bundle, instead of attempting a larger refactor to make recursive stage packages survive arbitrary parent churn.
  Rationale: this is the smallest end-to-end change that can make the live external-prover topology usable now. It keeps the current exact-parent proof binding semantics intact and directly addresses the observed failure mode on the only canonical public miner.
  Date/Author: 2026-03-13 / Codex

- Decision: keep exact-parent prepared-bundle matching in block assembly for now.
  Rationale: the repository already documents exact-parent readiness, and changing bundle selection semantics at the same time as the mining hold would enlarge the blast radius. The operational mining hold is enough to make the present single-author topology work.
  Date/Author: 2026-03-13 / Codex

- Decision: prewarm the external prover worker process on startup and emit stage start/finish logs.
  Rationale: the standalone worker previously gave operators almost no signal and paid cold recursive setup on the first live job. Startup prewarm and explicit elapsed-time logging make deployment failures diagnosable and reduce cold-start confusion.
  Date/Author: 2026-03-13 / Codex

## Outcomes & Retrospective

The code-side fix is real and observable on the live public authoring node. OVH now pauses mining when a proofless shielded batch is waiting for a prepared bundle, which prevents the old parent-churn failure mode. The external worker also now prewarms and emits live stage logs, and on the current topology it immediately starts `leaf_batch_prove` for the live work package instead of idling.

However, the scalable path is still not delivering an includable bundle quickly enough. The live test transfer `0xf401c4598c17a250cbf5a819430023a624048002566fcdef880f7adb8106a46b` held the OVH author at block `130` for more than six minutes while a single external worker burned roughly `11-15` CPU cores on `leaf_batch_prove`, yet `prepared_bundles` stayed `0` and the chain never advanced. That means the current live inclusion throughput on this topology is still effectively zero for practical purposes, with a measured lower bound of worse than `1 / 368 s ≈ 0.0027 tx/s` for a single transfer during this run.

The remaining work is no longer “stop invalidating the proof before it can land”; that part now works. The remaining bottleneck is the cost or liveness of the first live recursive leaf proof itself, plus the broken local prover-node supervisor path on `hegemon-prover`. Any future throughput claims must therefore be backed by actual inclusion latency on the live network, not pool admission, stage publication, or proofless-batch pause behavior alone.

## Context and Orientation

The public node logic lives in `node/src/substrate/service.rs`. That file wires the real Substrate client, the transaction pool, the asynchronous `ProverCoordinator`, and the production `MiningWorker`. The coordinator itself lives in `node/src/substrate/prover_coordinator.rs`; it publishes external stage work packages and keeps a map of prepared proof artifacts. The production chain-state bridge is `node/src/substrate/client.rs`; it gives the mining worker callbacks for best block state, pending transactions, block import, and now temporary mining holds. The mining loop itself is in `node/src/substrate/mining_worker.rs`. The external prover process is `node/src/bin/prover_worker.rs`.

In this repository, a “proof-sidecar transfer” means a shielded transfer extrinsic whose transaction proof bytes are omitted from the extrinsic body and expected to be satisfied by a same-block `submit_proven_batch` artifact. A “prepared bundle” means the block-level proof artifact that the authoring node can attach to a block. A “parent hash” is the hash of the block the next candidate block extends. The current recursive coordinator binds work packages to a specific parent hash, so changing the best block can invalidate outstanding work even if the transaction set is unchanged.

The live topology used for this plan is:

- `hegemon-ovh`: the only canonical public authoring/mining node, with RPC bound to localhost and P2P on port `30333`.
- `hegemon-prover`: a private sync node plus an external `hegemon-prover-worker` process, reaching the OVH RPC through an SSH tunnel.
- the laptop: the only wallet with spending authority for the boot wallet and test wallet.

Canonical chainspec metadata for this repository state:

- Chainspec SHA-256: `455f552ec9e73bb07ad95ac8b9bf03c72461acc16ffd9afe738b70c31cce3cc1`
- Genesis hash: `0x15202f417428013d3069f19110043e98c58fc0a943781c5713393b5153413839`
- Approved seed list: `hegemon.pauli.group:30333,158.69.222.121:30333`

## Plan of Work

First, keep the proofless path fail-closed but stop self-sabotaging it. In `node/src/substrate/service.rs`, add a helper that inspects the candidate transactions selected for the next block, detects whether they contain proofless shielded transfers that still lack a matching prepared bundle for the current parent, and returns a human-readable pause reason. Wire that helper into the production chain-state provider in `node/src/substrate/client.rs` by adding a mining-pause callback. Extend the `ChainStateProvider` trait in `node/src/substrate/mining_worker.rs` with a default `mining_pause_reason()` method and make the mining loop clear work and sleep while the callback returns a reason. That preserves the current parent long enough for external recursive work to finish.

Second, improve the standalone prover worker so operators can actually observe it working. In `node/src/bin/prover_worker.rs`, prewarm the aggregation cache on startup unless `HEGEMON_AGG_DISABLE_WORKER_PREWARM=1` is set, and log stage package start, submission, rejection, elapsed time, and output size. This gives immediate evidence that the worker is alive and reduces the first live proof cold start.

Third, update operator-facing documentation so the live topology is deployable without tribal knowledge. `config/testnet-initialization.md`, `runbooks/authoring_pool_upgrade.md`, and `.codex/skills/hegemon-testnet-join/SKILL.md` must all say that public authoring nodes which accept proof-sidecar traffic need `HEGEMON_AGGREGATION_PROOFS=1`, shared approved seeds, healthy NTP/chrony, large recursive timeouts (`HEGEMON_BATCH_JOB_TIMEOUT_MS=3600000` and `HEGEMON_PROVER_WORK_PACKAGE_TTL_MS=3600000` in the current remote setup), and the mining-hold safeguard (`HEGEMON_AGG_HOLD_MINING_WHILE_PROVING=1`, which is now the default behavior when aggregation proofs are enabled). `runbooks/authoring_pool_upgrade.md` must also stop claiming that `hegemon-prover-worker` only handles root-finalize packages; it already handles `leaf_batch_prove` and `merge_node_prove`.

Finally, update `DESIGN.md` and `METHODS.md` so the architecture description matches the new behavior: exact-parent prepared bundles are still required, but public authors using the external-prover topology now hold local mining while a strict proofless batch waits for a ready bundle. That detail matters because it explains how the network can actually realize the scalable proving path without invalidating its own proofs on every empty block.

## Concrete Steps

Work from the repository root:

1. Format the modified Rust files.

       cargo fmt --all

2. Build or test with the macOS libclang environment if working on macOS.

       export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
       export DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib:${DYLD_LIBRARY_PATH}
       cargo test -p hegemon-node --features substrate mining_pause -- --nocapture
       cargo build -p hegemon-node --features substrate --release
       cargo build -p hegemon-node --features substrate --release --bin hegemon-prover-worker

   Expected result: the targeted tests pass, and both `target/release/hegemon-node` and `target/release/hegemon-prover-worker` rebuild successfully.

3. Redeploy the fresh binaries.

       scp target/release/hegemon-node hegemon-ovh:/tmp/hegemon-node
       scp target/release/hegemon-prover-worker hegemon-prover:/tmp/hegemon-prover-worker

   Then on `hegemon-ovh`:

       sudo install -m 0755 /tmp/hegemon-node /usr/local/bin/hegemon-node
       sudo systemctl restart hegemon-node.service
       journalctl -u hegemon-node.service -n 80 --no-pager

   And on `hegemon-prover`:

       install -m 0755 /tmp/hegemon-prover-worker /home/localadmin/Hegemon/target/release/hegemon-prover-worker
       pkill -f hegemon-prover-worker || true
       nohup env HEGEMON_PROVER_RPC_URL=http://127.0.0.1:19944 HEGEMON_PROVER_SOURCE=hegemon-prover-01 RUST_LOG=info /home/localadmin/Hegemon/target/release/hegemon-prover-worker --poll-ms 250 >/home/localadmin/hegemon-live-run/logs/worker.log 2>&1 &

4. Verify the live topology before sending a transaction.

       ssh hegemon-ovh "curl -sS -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system_health\",\"params\":[]}' http://127.0.0.1:9944"
       ssh hegemon-ovh "curl -sS -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prover_getMarketParams\",\"params\":[]}' http://127.0.0.1:9944"
       ssh hegemon-prover "tail -n 80 /home/localadmin/hegemon-live-run/logs/worker.log"

   Expected result: OVH RPC is healthy, `package_ttl_ms` shows `3600000`, and the worker log contains an aggregation-cache prewarm line on startup.

5. Submit a real proof-sidecar transfer and watch the authoring node hold mining until a bundle is ready.

       HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1 ./target/release/wallet substrate-send --store ~/hegemon-boot-wallet --passphrase hegemonboot123 --ws-url ws://127.0.0.1:29944 --recipients /tmp/hegemon-live-recipient.json --fee 0
       ssh hegemon-ovh "journalctl -u hegemon-node.service -f --no-pager"

   Expected result: the OVH log should show a “Mining paused while waiting for a ready proven batch” message instead of continuing to mine empty deferral blocks, followed by a resumed-mining message and inclusion of the proven batch once the worker submits the stage result.

## Validation and Acceptance

The change is accepted only when all of the following are true:

- The targeted local test covering `mining_pause_reason_for_pending_proofless_batch` passes.
- `hegemon-node` and `hegemon-prover-worker` rebuild successfully from this repository state.
- On the live OVH/prover deployment, submitting a proof-sidecar transfer no longer results in endless parent churn with `prepared_bundles=0`.
- The OVH node logs that mining paused while waiting on a ready proven batch, then resumes after the bundle is prepared.
- The test wallet receives the submitted funds on-chain, proving that the scalable proof lane is actually operational rather than merely admitting the transaction to the pool.

Current throughput should be recorded as end-to-end inclusion throughput, not pool admission. For a single transfer on this topology, that means reporting the wall-clock delay from transaction submission to inclusion and converting it to `tx/s` only after the transfer is actually mined.

## Idempotence and Recovery

The local code changes are additive and can be rebuilt repeatedly. `cargo fmt --all` is idempotent. Restarting `hegemon-node.service` and the external worker is safe as long as the approved chainspec and seed list stay unchanged. If a redeploy goes bad, reinstall the previously known-good binaries and restart the same services. If the live transaction test wedges again, use the OVH and prover logs plus `prover_getStagePlanStatus` to determine whether the node failed before publishing stage work, while mining was held, or after the worker submitted a result.

## Artifacts and Notes

Important live evidence already collected during this effort:

    prover_getStagePlanStatus before the fix:
      prepared_bundles = 0
      latest_work_package changed as new empty blocks were mined

    OVH journal before the fix:
      Deferring proofless sidecar transfers until a proven batch is ready (strict mode)
      Aggregation mode enabled (runtime skips per-tx proof verification)
      Deferred proofless sidecar transfers this block ...
      ... followed by more mined empty blocks on new parents

    hegemon-prover worker process before the fix:
      roughly 65 threads
      tens of CPU minutes consumed on one leaf stage
      no chance to land before the author changed parent again

These observations are the reason the mining hold exists.

## Interfaces and Dependencies

At the end of this work, these interfaces must exist:

- In `node/src/substrate/mining_worker.rs`, `crate::substrate::mining_worker::ChainStateProvider` must expose:

      fn mining_pause_reason(&self) -> Option<String>;

  with a default implementation returning `None`.

- In `node/src/substrate/client.rs`, `crate::substrate::client::ProductionChainStateProvider` must expose:

      pub fn set_mining_pause_fn<F>(&self, f: F)
      where
          F: Fn() -> Option<String> + Send + Sync + 'static;

- In `node/src/substrate/service.rs`, authoring must compute a pause reason from current candidate transactions and the `ProverCoordinator` before spawning the production mining worker.

- In `node/src/bin/prover_worker.rs`, startup must prewarm the aggregation cache unless explicitly disabled, and live stage execution must log start/finish/rejection timing.

Revision note (2026-03-13): created this ExecPlan after reproducing the live stale-parent failure on the OVH/prover deployment, and updated it to reflect the implemented mining-hold plus worker-prewarm fix path.

Revision note (2026-03-13, later): V5 singleton leaf proving had regressed by always wrapping a single tx proof in the outer leaf proof. Restored the singleton root fast path and root-only active-child fan-in semantics in `circuits/aggregation/src/v5.rs` and `consensus/src/aggregation/v5.rs`. On the prover host, the old `HEGEMON_AGG_LEAF_FANIN=4, active_children=1` profile dropped from `>6 minutes and still in outer_prove` to `cold_ms=5 warm_ms=4`. Live OVH/prover validation now shows the worker accepting a singleton leaf stage package in `164 ms`, OVH logging `Mining pause cleared`, and OVH building block `175` with the prepared bundle. At that point the proving path is no longer the bottleneck; remaining delay is PoW inclusion latency.
