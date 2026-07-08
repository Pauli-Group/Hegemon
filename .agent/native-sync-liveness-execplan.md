# Make Native Testnet Sync Smooth for Public Joiners

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It follows `.agent/PLANS.md`.

## Purpose / Big Picture

Public Hegemon testnet users should be able to start the shipped 0.10 node, point it at `hegemon.pauli.group:30333`, and sync without long apparent stalls or confusing retry behavior. The current native sync path advances in fixed, single-response chunks and rate-limits repeated requests while a response is still being built or imported. After this change, a fresh local node should catch up from the public seed more smoothly, with fewer rejected retries and measurable sync throughput.

## Progress

- [x] (2026-07-08 01:12Z) Confirmed PR #195 is the active branch and was green before this work.
- [x] (2026-07-08 01:15Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, and the Hegemon testnet join skill before code changes.
- [x] (2026-07-08 01:24Z) Inspected native sync constants and request/response/import flow.
- [x] (2026-07-08 01:36Z) Patched native sync duplicate response/request tracking and genesis-only announce suppression while catching up.
- [x] (2026-07-08 01:39Z) Added focused Rust tests for duplicate native sync response and outbound request admission.
- [x] (2026-07-08 01:44Z) Built the release node after the native sync patch.
- [x] (2026-07-08 01:55Z) Measured fresh local sync from `hegemon.pauli.group:30333` after the native patch; it still stayed at height 0 after 158s.
- [x] (2026-07-08 02:00Z) Measured fresh local sync from `devnet.hegemonprotocol.com:30333`; it still stayed at height 0 after 107s.
- [x] (2026-07-08 02:08Z) Patched the network protocol inbound queue to backpressure instead of dropping sync protocol frames, and demoted per-frame protocol logs to debug.
- [x] (2026-07-08 02:23Z) Patched periodic target catch-up requests to use the async protocol sender instead of lossy `try_send`.
- [x] (2026-07-08 02:42Z) Patched directed protocol sends to wait for peer queue capacity, so sync responses are not dropped behind a full per-peer channel.
- [x] (2026-07-08 03:18Z) Reran focused tests after the network queue patch: `cargo test -p network --lib` and `cargo test -p hegemon-node native_sync --lib --no-default-features`.
- [x] (2026-07-08 03:19Z) Rebuilt the release node with `make node`.
- [x] (2026-07-08 03:22Z) Deployed the patched Linux release binary to `hegemon-ovh` and `hegemon-dev` through a systemd drop-in that can be removed for rollback.
- [x] (2026-07-08 03:34Z) Measured fresh local sync from `hegemon.pauli.group:30333`; height advanced from 0 to 3,712 in 600s instead of remaining stuck at 0.
- [x] (2026-07-08 03:47Z) Patched catch-up load tolerance after the measurement exposed peer timeout/reconnect brittleness: larger command queue, five-minute stale-peer timeout, and 512-block sync response windows bounded by the existing wire-size cap.
- [x] (2026-07-08 03:50Z) Reran focused tests after the catch-up load patch: `cargo test -p network --lib` and `cargo test -p hegemon-node native_sync --lib --no-default-features`.
- [x] (2026-07-08 03:52Z) Rebuilt the local release node with `make node` after the second patch.
- [x] (2026-07-08 04:22Z) Reverted the 512-block response-window experiment after live measurement showed worse pauses; kept the 128-block response cap.
- [x] (2026-07-08 04:45Z) Added and deployed the first tip-extension importer patch, then measured fresh local sync; it avoided reorg rebuilds but still flushed each block individually and reached only height 256 after 300s.
- [x] (2026-07-08 05:08Z) Added the batch tip-extension commit path so a contiguous sync response validates block-by-block but persists the whole chunk in one atomic write.
- [x] (2026-07-08 05:18Z) Reran focused validation after the batch patch: `cargo fmt -p network -p hegemon-node --check`, `cargo test -p hegemon-node sync_response_tip_extension_imports_contiguous_chunk --lib --no-default-features`, `cargo test -p hegemon-node native_sync --lib --no-default-features`, `cargo test -p network --lib`, and `make node`.
- [ ] Deploy the batch tip-extension release binary to `hegemon-ovh` and `hegemon-dev`.
- [ ] Resync a fresh local base path from `hegemon.pauli.group:30333` after the batch patch is live.
- [ ] Compare measured sync progress before and after the full change.
- [ ] Push the PR branch and report validation evidence.

## Surprises & Discoveries

- Observation: The seed currently logs repeated requests for the same 128-block range and then `request_rate_limited`, while the client eventually advances to the next range.
  Evidence: `hegemon-ovh` logs showed peer `0x28c0...e18f` requesting `5377..5504` repeatedly, then later requesting `5505..5632`.
- Observation: The first local patch reduced useless genesis-only announces and ignored above-tip requests, but did not make a fresh node import blocks from either public seed.
  Evidence: After the native patch, a fresh node against `hegemon.pauli.group:30333` stayed at height 0 for 158s while repeatedly requesting `1..128`; a fresh node against `devnet.hegemonprotocol.com:30333` stayed at height 0 for 107s with the same pattern.
- Observation: The seed logs show protocol messages dropped because the handler queue is full or closed.
  Evidence: `hegemon-ovh` repeatedly logged `dropping protocol message because handler queue is full or closed` while peers were requesting sync ranges.
- Observation: After the network receive patch, fresh local nodes still stayed at height 0 from both seeds; local logs showed target requests queued, but remote seed logs did not show those `1..128` requests during the post-patch measurement.
  Evidence: Post-patch OVH run stayed at height 0 for 240s with target 5902; post-patch dev run stayed at height 0 for 120s with target 5907. Local logs queued `from_height=1 to_height=128`; seed grep showed no matching requests in that time window.
- Observation: After the async request patch, the OVH seed received `1..128` and queued a 2.2 MB sync response, but the fresh local node never received that response and stayed at height 0.
  Evidence: OVH logged `received native sync request ... from_height=1 to_height=128` followed by `queued native sync response ... payload_bytes=2221778`; the local node did not log a native sync response.
- Observation: The queued 2.2 MB sync response fits the configured byte budgets.
  Evidence: `MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES` is `wire::MAX_WIRE_FRAME_LEN / 2` (8 MiB), while the peer outbound queue budget is `wire::MAX_WIRE_FRAME_LEN * 16` (256 MiB). The failure is therefore a lossy scheduling/delivery problem, not an intentionally oversized response.
- Observation: Focused tests and the release build pass on the PR branch after the network queue patch.
  Evidence: `cargo test -p network --lib` passed 78 tests, `cargo test -p hegemon-node native_sync --lib --no-default-features` passed 13 tests, and `make node` completed.
- Observation: Deploying the network queue patch to both miners fixed the height-0 stall for a fresh local node.
  Evidence: A temporary local node syncing from `hegemon.pauli.group:30333` reached height 384 at 45s, 1,280 at 120s, 1,792 at 180s, and 3,712 at 600s. The pre-deploy baseline was still height 0 at 180s.
- Observation: A continuation run from the same temporary data directory exposed stale-session brittleness under catch-up load.
  Evidence: The node restarted at height 3,712, connected to the seed, then timed out `158.69.222.121:30333`; late messages from that peer were ignored as an inactive session and the local target stayed empty.
- Observation: The live seed miner remained healthy after the PR binary deploy, while `hegemon-dev` was behind the OVH tip during the measurement window.
  Evidence: `hegemon-ovh` reported height 5,961, target 5,961, `syncing:false`; `hegemon-dev` reported height 5,940, target 5,961, `syncing:true`.
- Observation: The first tip-extension importer removed the reorg rebuild, but still committed and flushed each block one at a time.
  Evidence: A fresh local run against `hegemon.pauli.group:30333` reached height 128 at 60s, remained there at 120s, reached 256 at 180s, and remained at 256 at 300s; logs used `imported native sync response` instead of `by batch reorg`, showing the new path was active but still bounded by per-block persistence.

## Decision Log

- Decision: Keep this as a targeted runtime sync fix on the active PR instead of broad network redesign.
  Rationale: The user needs the public testnet join path to work now. A small change to repeated range handling and request scheduling can be built, tested, and measured quickly without changing chain format or genesis.
  Date/Author: 2026-07-08 / Codex
- Decision: Backpressure registered protocol handlers instead of dropping protocol frames when the channel is temporarily full.
  Rationale: Native sync responses are protocol frames. Dropping them causes fresh nodes to appear connected but stuck at height 0 until another range request succeeds. The existing byte budget remains the memory bound, so awaiting channel capacity improves delivery without making the queue unbounded.
  Date/Author: 2026-07-08 / Codex
- Decision: Use the async protocol sender for periodic target catch-up requests.
  Rationale: `queue_missing_blocks_from_sync_target` was the recurring catch-up path after target discovery. It used `try_send`, so a full protocol queue could mark a range as in flight even when the request never reached the network service. Awaiting the bounded queue makes failures explicit and preserves the in-flight retry invariant.
  Date/Author: 2026-07-08 / Codex
- Decision: Await per-peer queue capacity for targeted registered-protocol messages while leaving broadcast, ping, and address gossip on the existing non-blocking path.
  Rationale: Native sync responses are directed protocol replies. Dropping a multi-megabyte block-range response makes a joining node look connected but frozen. Broadcasts remain best-effort so one slow peer does not stall the network service.
  Date/Author: 2026-07-08 / Codex
- Decision: Increase the P2P command channel to 4,096 entries and stale-peer timeout to five minutes.
  Rationale: Block catch-up moves large protocol responses and import work through the same service. The previous 100-command queue and 90-second timeout could declare a seed stale during live catch-up even though messages were arriving late. The byte budgets still cap memory use.
  Date/Author: 2026-07-08 / Codex
- Decision: Keep native sync response windows at 128 blocks after live-testing a 512-block window.
  Rationale: The 512-block experiment did reduce request count, but live resync stalled for several minutes after each large import chunk. Smaller windows keep import latency and peer responsiveness better under the current verifier/storage path, while the reliable queue and timeout fixes address the original dropped-response failure.
  Date/Author: 2026-07-08 / Codex
- Decision: Add a straight-line tip-extension importer for native sync responses.
  Rationale: The next live run showed responses arriving quickly but canonical progress landing only every few minutes because each response went through full branch reorganization, replay, and index rebuild from genesis. When a response is anchored directly at the current local tip, importing each block through the existing announced-tip extension path preserves validation while avoiding the reorg rebuild path.
  Date/Author: 2026-07-08 / Codex
- Decision: Batch contiguous tip-extension persistence after per-block validation.
  Rationale: The first tip-extension importer proved the reorg rebuild was avoidable, but live measurement showed the remaining cost was one sled transaction and durability flush per block. The batch path keeps announced-block validation, action-root checks, replay refinement, proof/artifact verification, and state-root/nullifier-root checks for every block, then writes the verified contiguous chunk to the canonical indexes in one atomic transaction.
  Date/Author: 2026-07-08 / Codex

## Outcomes & Retrospective

The initial PR binary deployment turned the public-seed join path from stuck to advancing: fresh local sync from `hegemon.pauli.group:30333` progressed from height 0 to 3,712 in 600 seconds. That is a real liveness improvement over the baseline height-0 stall, but not yet acceptable as the final outcome because full catch-up is still slow and restart continuation exposed a stale-peer timeout.

The 512-block response-window experiment was then built, deployed, and measured against the public seed path. It imported the first 512-block chunk but then paused long enough that height remained 512 at 300 seconds and the next 512-block import did not land until roughly 225 seconds later. That result is worse operational behavior than the smaller windows, so the final patch keeps the original 128-block response cap and retains only the reliable P2P delivery, larger command queue, and longer stale-peer timeout fixes.

After deploying that cap correction, another fresh local sync against `hegemon.pauli.group:30333` exposed the next bottleneck: the node reached height 128 at 90 seconds, 256 at 240 seconds, and only 384 at 600 seconds. Logs showed native sync responses arriving repeatedly while imports landed late, which pointed at local import/reorg cost rather than network delivery. The first contiguous-tip fast path avoided reorg rebuilds but still committed each block separately and remained too slow. The current patch batches verified contiguous tip-extension chunks into one atomic commit and must be measured from a fresh base path after deployment.

## Context and Orientation

The native node lives in `node/src/native/mod.rs`. It implements a custom native sync protocol with three relevant message types: `Announce`, `Request`, and `Response`. A joining node hears a peer announce its best block height, requests a missing block range, receives a response containing block metadata rows, imports them, and then asks for more if the peer is still ahead.

The public seed list is `hegemon.pauli.group:30333`. The public testnet profile uses the native 0.10 `--dev` launch path with fresh native genesis. Users normally run a relay/full node, not a miner.

The current bottleneck is not genesis mismatch. It is sync liveness: requests are capped to 128 blocks, only one response per peer is prepared at a time, only one import runs at a time, repeated requests from an impatient or retrying peer count against a rate limit, and the shared protocol multiplexer can drop native sync frames when its handler queue is full.

## Plan of Work

First, change request admission so repeated requests for the same peer and same range while a response is already in flight are treated as idempotent duplicates instead of consuming rate-limit budget. The serving peer should simply keep the existing response worker and avoid logging a warning that looks like a peer failure.

Second, ensure a client that receives a partial response promptly requests the next missing range after import, without being blocked by stale duplicate-request state. Keep ordered import and existing byte caps; do not introduce parallel import in this patch.

Third, make protocol handler delivery reliable under load by awaiting handler capacity after the inbound byte budget has been acquired. This keeps the queue bounded by bytes but prevents sync response loss caused by `try_send` drops. Demote high-frequency protocol frame logs to debug so seed nodes do not spend unnecessary time writing massive info logs.

Fourth, make targeted registered-protocol sends await the per-peer channel. Native sync range responses are directed replies and should not use the lossy gossip path. Keep broadcasts, heartbeats, and address sharing non-blocking.

Fifth, add focused unit tests around same-range duplicate admission, sequential catch-up scheduling, and reliable directed peer delivery. Then build `hegemon-node` and run a fresh local sync against `hegemon.pauli.group:30333` in a temporary base path, measuring height progress over time.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Inspect and patch:

    rg -n "NATIVE_SYNC_REQUEST|begin_sync_response_for_peer|admit_sync_request_from_peer|request_missing_blocks" node/src/native/mod.rs
    cargo test -p hegemon-node native_sync --lib

Build:

    make node

Measure local sync with a temporary base path and non-default ports:

    TMPDIR=$(mktemp -d /tmp/hegemon-sync-liveness.XXXXXX)
    HEGEMON_SEEDS="hegemon.pauli.group:30333" HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
      ./target/release/hegemon-node --dev --base-path "$TMPDIR/node" --port 31333 --rpc-port 19955 --rpc-methods unsafe --name "CodexSyncMeasure"

Poll:

    curl -s -H "content-type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"hegemon_consensusStatus","params":[]}' http://127.0.0.1:19955

## Validation and Acceptance

The focused Rust tests must pass. `make node` must produce `target/release/hegemon-node`. A fresh local node must connect to the public seed, share the same genesis, and advance toward the seed height without repeated same-range rate-limit stalls. Acceptance evidence is a short measurement table with elapsed seconds, local height, target height, and sync rate.

## Idempotence and Recovery

The live sync measurement uses a temporary base path and alternate ports, so it does not touch the user's app node or wallet state. If a measurement process is interrupted, stop the process and remove only the temporary directory printed by `mktemp`.

## Artifacts and Notes

Artifacts will be added after validation.

## Interfaces and Dependencies

The patch changes native sync admission in `node/src/native/mod.rs` and protocol delivery in `network/src/service.rs`. It must not change on-chain block format, genesis, wallet store format, or desktop app defaults. The public testnet seed remains `hegemon.pauli.group:30333`.
