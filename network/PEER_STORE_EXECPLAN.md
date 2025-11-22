# Disk-backed peer store for reconnects

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Persist peers we learn about or connect to so a node can reconnect to familiar addresses after restart. On startup the P2P service should reload saved addresses, drop stale ones, and attempt a bounded number of recent peers before falling back to seeds. The store must serialize updates whenever connections change and keep the address list pruned by TTL so it does not grow unbounded. Unit tests will prove addresses survive restarts and that reconnect attempts honor the configured cap.

## Progress

- [x] (2026-07-16 00:20Z) Read existing P2P service and peer manager to understand connection flows.
- [x] (2026-07-16 01:15Z) Implemented disk-backed peer store with TTL pruning, max entry limits, and reload/persist helpers.
- [x] (2026-07-16 01:35Z) Wired peer store into P2P startup, reconnection planning, and connect/disconnect/address handling.
- [x] (2026-07-16 01:45Z) Added unit tests covering persistence pruning and bounded reconnect ordering.
- [x] (2026-07-16 02:20Z) Run network crate tests after pinning `pallet-timestamp` to the workspace version; all unit and integration cases now pass.

## Surprises & Discoveries

- Pinning `pallet-timestamp` to version `42.0.0` at the workspace level clears the previous resolver error; `cargo test -p network` now completes successfully.
- Rust 2024 treats `gen` as a reserved keyword; the random file name helpers now use `rand::random` to stay edition-safe.

## Decision Log

- Decision: Store persisted peers as socket addresses with timestamps and last-connected ordering in a single bincode file to keep dependencies minimal.
  Rationale: Existing serialization uses bincode and serde; sticking with them matches current patterns and avoids extra formats.
  Date/Author: 2026-07-16 / assistant
- Decision: Add a workspace-level pin for `pallet-timestamp = 42.0.0` to keep the network tests building against the published crates while other pallets evolve.
  Rationale: Avoids resolver drift when workspace members pull newer FRAME versions that are not yet available in the index.
  Date/Author: 2026-07-16 / assistant

## Outcomes & Retrospective

- Test suite (`cargo test -p network`) is green after the workspace `pallet-timestamp` pin and edition-safe random helpers; no peer store wiring regressions surfaced. Continue to watch live node runs for real-world reconnect behavior.

## Context and Orientation

Relevant code lives in `network/src/service.rs` (P2PService lifecycle), `network/src/peer_manager.rs` (connection tracking and address sampling), and `network/src/p2p.rs` (wire protocol). There is no persistent address storage today; seeds are resolved in `P2PService::run` and opportunistic dials use `PeerManager::address_candidates`. New module `network/src/peer_store.rs` will own serialization, pruning, and replay of known peers. Tests for network live in `network/tests/` and inside modules.

## Plan of Work

Add a `PeerStore` struct in a new file under `network/src/peer_store.rs` with methods to load from disk at a configured path, record connected or learned addresses with timestamps, prune entries older than the TTL, and persist to disk whenever the in-memory set changes. Represent entries with the socket address, optional last_connected timestamp for ordering, and last_updated for TTL. Provide methods to fetch recent peers limited to a count for reconnection attempts and to add addresses learned from gossip.

Extend `P2PService` to accept a peer store path/TTL configuration (or default path relative to current directory) and initialize the store in `new` or `run`. When starting, load persisted addresses, prune stale ones, and schedule reconnect attempts to up to five most recent peers before dialing seeds. Hook into connection lifecycle: when a peer connects or disconnects, update the store with the address and timestamp; when new addresses arrive via gossip or coordination, store them as learned addresses. Ensure the store deduplicates against the node’s own advertised addresses.

Add unit tests in the network crate verifying (1) addresses written to the store reload after a restart and survive pruning thresholds, and (2) reconnect sequencing attempts at most five recent peers before seeds. Use temporary directories for store files and synthetic timestamps to simulate staleness. Adjust existing startup logic to respect the bounded reconnect attempts but fall back to seeds when none remain.

## Concrete Steps

1. Create `network/src/peer_store.rs` with `PeerStoreEntry` and `PeerStore` using serde/bincode for persistence. Include methods: `load(path, ttl, max_entries)`, `record_connected(addr)`, `record_learned(addrs)`, `mark_disconnected(addr)`, `recent_peers(limit, exclude)`, and internal `persist` plus TTL pruning invoked on mutations.
2. Update `network/src/lib.rs` to expose the new module if needed and add any configuration structs. Decide on default store path (e.g., `p2p_peers.bin`).
3. Wire `P2PService::new` to accept a peer store (or path) and initialize it. In `run`, load persisted addresses, prune, attempt reconnects to up to five most recent entries before seeds, and update store in command handlers when peers connect/disconnect or addresses arrive.
4. Add unit tests under `network/tests/` or module tests to confirm persistence and bounded reconnect ordering. Use Tokio tests or synchronous where possible; mock connection spawning by observing queued addresses rather than opening sockets.
5. Run `cargo test -p network` to validate changes.

## Validation and Acceptance

After implementation, run `cargo test -p network` from the repository root; expect tests to pass, including new persistence and reconnect ordering coverage. Manual acceptance: start a node twice pointing to the same peer store path; after connecting to peers the first time, the second start should attempt reconnects to up to five stored peers before using seeds.

## Idempotence and Recovery

PeerStore writes replace the on-disk file atomically via writing to a temp file and renaming, so repeated runs keep consistent data. TTL pruning ensures old entries are removed safely. Running the test suite multiple times should not leave residue thanks to temporary directories.

## Artifacts and Notes

None yet.

## Interfaces and Dependencies

- New `network/src/peer_store.rs` defines:
    - `pub struct PeerStore` with fields for path, ttl, max_entries, and in-memory entries.
    - `impl PeerStore` methods:
        - `pub fn load(path: impl AsRef<Path>, ttl: Duration, max_entries: usize) -> Result<Self, NetworkError>`
        - `pub fn record_connected(&mut self, addr: SocketAddr)`
        - `pub fn record_learned(&mut self, addrs: impl IntoIterator<Item = SocketAddr>)`
        - `pub fn record_disconnected(&mut self, addr: SocketAddr)`
        - `pub fn recent_peers(&self, limit: usize, exclude: &HashSet<SocketAddr>) -> Vec<SocketAddr>`
    - Internal persistence uses serde/bincode and prunes entries older than TTL.
- `P2PService` gains a `peer_store: PeerStore` field and uses it when handling connections and gossip.
- `NetworkError` already wraps serialization and IO errors; reuse it for peer store load/save failures.
