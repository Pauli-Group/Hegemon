# Devnet Hostile Review Runtime Hardening ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

This plan hardens the live `hegemon-node` and wallet surfaces that were exercised during the private `0.10.0` devnet rollout. After this work, nodes on distinct named networks will fail closed before they exchange expensive block or transaction data, DA chunk requests will no longer amplify into unbounded proof generation, transaction gossip will not hold the pending queue lock across async pool submission, wallet nullifier sync will page instead of materializing the whole spent set, and wallet-facing HTTP/RPC defaults will no longer expose an unauthenticated or permissive browser surface by default. The result is observable: two nodes on the same private chainspec still sync, mine, and transfer funds, while incompatible peers and hostile oversized requests get rejected cheaply.

## Progress

- [x] (2026-04-19 08:18Z) Read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` before planning code changes.
- [x] (2026-04-19 08:26Z) Built local and remote `hegemon-node`, `wallet`, and `walletd` binaries and launched an isolated two-node `0.10.0` private devnet between the local machine and `hegemon-dev`.
- [x] (2026-04-19 08:32Z) Proved baseline runtime behavior on the private devnet: both nodes share genesis `0x4d6940676b7929dbbe358c97b8f6f33c1ea951469cde00d36e30e341ee848b94`, the local node mined blocks that `hegemon-dev` imported, and bidirectional shielded transfers succeeded.
- [x] (2026-04-19 08:36Z) Collected hostile review findings from subagents covering wallet/RPC security, consensus/network isolation, and performance/resource exhaustion.
- [x] (2026-04-19 09:05Z) Patched strict chain identity so compatibility checks carry an explicit network identifier, built-in chain aliases no longer collapse onto one id, and unknown/incompatible peers are dropped before transaction admission or full-block verification work.
- [x] (2026-04-19 09:07Z) Bounded DA chunk request amplification and the pending external transaction queue by count and bytes, and removed the queue mutex from the async submission slow path.
- [x] (2026-04-19 09:09Z) Paged wallet nullifier sync and made default node RPC CORS fail closed instead of permissive.
- [x] (2026-04-19 09:12Z) Confirmed the wallet HTTP helper is dead code in this branch; patched its local auth default anyway, but left it unexported because compiling it would require unrelated dependency resurrection.
- [ ] Add focused regressions and rerun the local/remote private devnet validation on rebuilt binaries.
- [ ] Re-run hostile review and close any remaining critical or high findings before final cleanup.

## Surprises & Discoveries

- Observation: the current private devnet does work end to end despite the hostile review findings.
  Evidence: local mining advanced the chain from height `1241` to `1383+`, `hegemon-dev` followed, and confirmed wallet transfers `0x0a979033fec068ec587df17b03a97de04f4a9144cf46caafd901a228f24e1b51` and `0x42265a94f11e3312e007a67d87075c6b8805fdad8f234aa9b6e6016f0cb00ad5` moved funds in opposite directions.

- Observation: transaction-bearing blocks are easy to identify on the private devnet because mined blocks with a shielded transfer currently expose `extrinsic_count = 2` when queried through `chain_getBlock`.
  Evidence: block heights `1367` and `1383` both reported `extrinsic_count: 2` on the local node after the two confirmed transfer tests.

- Observation: incoming wallet transfer history is incomplete even when balances update correctly.
  Evidence: the local wallet balance delta after the first transfer equaled `38 * 499429223 + 1000000`, proving receipt, but `status.get` did not add a `recent` incoming entry. This is not in scope for the current critical/high hardening pass, so it should be tracked separately if it remains after the runtime fixes.

- Observation: `wallet/src/api.rs` is not part of the compiled wallet crate in this branch.
  Evidence: temporarily exporting `pub mod api;` from `wallet/src/lib.rs` failed because the helper depends on crates and types (`axum`, `WalletRpcClient`) that are not wired into the live wallet build graph today.

## Decision Log

- Decision: fix the compatibility boundary first, before wallet pagination or operator-facing defaults.
  Rationale: pre-compatibility block and transaction handling lets incompatible or malicious peers trigger the most expensive work on the node, so it is the highest-risk live path.
  Date/Author: 2026-04-19 / Codex

- Decision: use explicit network identifiers in sync compatibility instead of relying on protocol strings alone.
  Rationale: protocol namespaces are currently hard-coded and shared. Adding a network identifier to the compatibility handshake is the smallest change that closes the chain identity gap without rewriting every PQ protocol registration path in one pass.
  Date/Author: 2026-04-19 / Codex

- Decision: bound pending external transactions by bytes as well as count.
  Rationale: a count-only queue still allows roughly `1000 * 5 MiB` of attacker-controlled payload to pile up in memory before admission checks finish.
  Date/Author: 2026-04-19 / Codex

- Decision: do not resurrect the dead wallet HTTP helper as part of this hardening pass.
  Rationale: the helper is not compiled today, and turning it back on would require unrelated dependency and API plumbing. The live risk is already lower because the helper is not in the build graph, so the hardening pass stays focused on shipped surfaces.
  Date/Author: 2026-04-19 / Codex

## Outcomes & Retrospective

This section will be updated after the hardening patch series and the final devnet rerun complete.

## Context and Orientation

`node/src/substrate/service.rs` owns the main PQ network event loop, the block import loop, and the JSON-RPC server wiring. That file is where incoming peer messages first enter the running node and where permissive default RPC CORS is currently configured.

`node/src/substrate/sync.rs` is the strict compatibility and Bitcoin-style block download state machine. It currently decides compatibility by comparing only genesis hash, sync protocol version, and aggregation proof format. This is where a new explicit network identifier must be carried and enforced.

`node/src/substrate/network_bridge.rs` decodes PQ protocol messages into block announcements, transaction gossip, sync messages, and DA chunk requests. It is the first place where DA chunk requests become per-index proof work.

`node/src/substrate/transaction_pool.rs` is the bridge between network transaction gossip and the Substrate transaction pool. It currently stores pending external transactions in a count-bounded queue, but not a byte-bounded queue, and it holds the queue mutex while awaiting pool submission.

`node/src/substrate/rpc/wallet.rs`, `wallet/src/substrate_rpc.rs`, and `wallet/src/async_sync.rs` together implement wallet archive synchronization. Commitments and ciphertexts already page; nullifiers still materialize the full spent set on both the server and the client.

`wallet/src/api.rs` exposes a small HTTP wallet helper around a loaded store. It currently accepts `auth_token: None`, which means any caller with network access to that HTTP listener can submit transfers from an unlocked wallet.

`node/src/bin/substrate_node.rs` and `node/src/substrate/chain_spec.rs` define how chain specifications are loaded and how named chains identify themselves.

## Plan of Work

Patch `node/src/substrate/sync.rs` and `node/src/substrate/network_bridge.rs` together so sync compatibility probes carry a plain-text network identifier string. The local identifier should come from the loaded chain spec id, with built-in aliases returning distinct ids instead of collapsing `dev`, `local`, and `testnet` onto one literal value. Update the service wiring in `node/src/substrate/service.rs` so transaction gossip from unknown or incompatible peers is dropped before it reaches `TransactionPoolBridge`, and full block announcements from unknown or incompatible peers only update cheap sync metadata instead of entering DA sampling or proof verification.

Patch `node/src/substrate/service.rs` DA chunk handling and `node/src/substrate/network_bridge.rs` message definitions so duplicate chunk indices are deduplicated and the request is truncated to a fixed maximum before any proof generation. Add clear logging when a peer exceeds the cap.

Patch `node/src/substrate/transaction_pool.rs` so `TransactionPoolBridge` tracks pending bytes, rejects or evicts by byte budget, and drains one item at a time without holding the pending mutex across `await`. Add configuration for the byte budget with a conservative default.

Patch `node/src/substrate/rpc/wallet.rs`, `wallet/src/substrate_rpc.rs`, and `wallet/src/async_sync.rs` so nullifiers page using the existing `PaginationParams` shape. The client should loop until `has_more` is false, just like commitments and ciphertexts.

Patch `wallet/src/api.rs` so the wallet HTTP helper refuses to serve mutating endpoints without an auth token by default. The acceptable low-friction fallback is to require either an explicit token argument or loopback-only binding plus a generated warning token printed to stderr. Patch `node/src/substrate/service.rs` RPC CORS defaults so unspecified CORS does not become `CorsLayer::permissive()`.

Add focused regressions close to each patched boundary, rebuild local and remote binaries, rerun the two-node private devnet, and record the result in this ExecPlan.

## Concrete Steps

From the repository root:

    cargo test -p hegemon-node compatibility -- --nocapture
    cargo test -p hegemon-node get_blocks -- --nocapture
    cargo test -p hegemon-node pending -- --nocapture
    cargo test -p hegemon-node da_chunk -- --nocapture
    cargo test -p wallet nullifier -- --nocapture
    cargo test -p wallet api -- --nocapture
    cargo check -p hegemon-node -p wallet -p walletd

After the code changes are compiled locally, sync the working tree snapshot to `hegemon-dev`, rebuild there, and rerun the private devnet flow:

    make node
    cargo build --release -p wallet -p walletd
    rsync -a --delete --exclude .git ./ hegemon-dev:~/Hegemon/
    ssh hegemon-dev 'cd ~/Hegemon && make node && cargo build --release -p wallet -p walletd'

Expected outcomes:

    incompatible peers are marked incompatible before transaction admission or full block verification work begins
    `GetBlocks` with `max_blocks = 0` returns an empty response instead of wrapping the height range
    DA chunk requests larger than the cap log and truncate, rather than generating an unbounded proof vector
    wallet nullifier sync pages through the node response instead of materializing the full set in one RPC call
    wallet HTTP serving without an auth token is rejected or explicitly gated

## Validation and Acceptance

Acceptance is met when all of the following are true:

1. The local and `hegemon-dev` private `0.10.0` nodes still sync on the shared private chainspec and can switch mining roles without forking.
2. A remote-to-local and a local-to-remote shielded transfer both confirm after the hardening patch set, and the recipient balances move by the exact transferred amounts.
3. Focused regressions cover the new network identifier compatibility path, `GetBlocks(max_blocks = 0)`, DA request caps, pending queue byte caps or lock release behavior, nullifier pagination, and wallet API auth defaults.
4. A follow-up hostile review finds no remaining critical or high issues in the touched surfaces.

## Idempotence and Recovery

The code changes in this plan are additive and safe to reapply. The private devnet uses isolated base paths and wallet stores under `tmp/devnet` locally and `~/hegemon-devnet` remotely, so rebuilds and node restarts do not affect `hegemon-ovh`. If a local or remote node gets into a bad state during validation, stop that node, wipe only the isolated devnet base path or wallet copy for the affected environment, restart from the shared private raw chainspec, and leave production hosts untouched.

## Artifacts and Notes

Evidence already collected before patching:

    local genesis hash: 0x4d6940676b7929dbbe358c97b8f6f33c1ea951469cde00d36e30e341ee848b94
    confirmed remote -> local tx: 0x0a979033fec068ec587df17b03a97de04f4a9144cf46caafd901a228f24e1b51
    confirmed local -> remote tx: 0x42265a94f11e3312e007a67d87075c6b8805fdad8f234aa9b6e6016f0cb00ad5
    tx-bearing blocks observed: heights 1367 and 1383 with extrinsic_count = 2

## Interfaces and Dependencies

`node/src/substrate/sync.rs` must continue exposing a `ChainSyncService<Block, Client>` type, but its compatibility request and response handling must additionally compare a local network identifier string.

`node/src/substrate/transaction_pool.rs` must keep `TransactionPoolBridge<P>` as the network-to-pool adapter, but the adapter must track pending byte usage and must not hold the queue mutex while awaiting `pool.submit(...)`.

`node/src/substrate/rpc/wallet.rs` and `wallet/src/substrate_rpc.rs` must end with a paginated nullifier RPC that mirrors the shape already used for commitments and ciphertexts.

`wallet/src/api.rs` must not expose transfer submission over HTTP without an explicit authentication decision.

Revision note (2026-04-19 / Codex): Initial runtime hardening plan created after the two-node private devnet baseline and the first hostile review pass.
