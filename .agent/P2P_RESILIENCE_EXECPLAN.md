# Harden native P2P discovery and recovery

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a native Hegemon node will not depend on a single seed for its long-term peer knowledge. Public nodes that connect through a seed can publish a listening-port hint without changing the existing wire format; the receiving node derives the candidate endpoint from the transport-observed IP, shares it with other peers, and retains it for later reconnects. Long-lived nodes periodically refresh addresses from different connected peers, learned dials rotate across candidates, dead connection attempts time out and back off, duplicate opportunistic dials are suppressed, and a disconnect no longer makes a failed peer look newly successful.

The behavior is visible through focused network tests. A three-node test must show that nodes learn a third public endpoint through address exchange, a registration test must show that an unspecified address can only contribute a port while the observed transport supplies the IP, and peer-store tests must show that disconnecting does not advance successful-connect recency. Existing gossip, admission, and native-node tests must continue to pass.

## Progress

- [x] (2026-07-09 18:07Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, and the current `network` and native-node P2P paths.
- [x] (2026-07-09 18:07Z) Created branch `codex/p2p-resilience-hardening` and identified the concrete failure modes.
- [x] (2026-07-09 19:03Z) Implemented rolling-compatible observed endpoint derivation and bounded registration handling.
- [x] (2026-07-09 19:03Z) Implemented periodic rotating discovery, rotating/backed-off learned dialing, connection timeouts, and in-flight dial suppression.
- [x] (2026-07-09 19:03Z) Corrected peer-store disconnect recency and broadened bounded startup reconnect diversity.
- [x] (2026-07-09 19:03Z) Added focused unit and three-node TCP integration regressions.
- [x] (2026-07-09 19:03Z) Updated `DESIGN.md`, `METHODS.md`, the functionality evaluation, and testnet join skills with implemented behavior and the residual NAT boundary.
- [x] (2026-07-09 19:22Z) Ran formatting, the complete network target, clippy, native-node compile/configuration checks, formal-core unit tests, and final diff review.
- [ ] Commit and publish the immutable canary revision, open the pull request, and require all GitHub checks to pass.
- [ ] Deploy the canary to the laptop and `hegemon-dev`; verify chain identity, tip convergence, mining, peer discovery, and reconnect behavior.
- [ ] Deploy the validated revision to `hegemon-ovh`; verify both miners and external peers reconverge without a fork.

## Surprises & Discoveries

- Observation: inbound TCP socket addresses cannot be advertised directly because their ports are normally temporary client ports.
  Evidence: `P2PCommand::NewPeer` receives the accepted socket address, while `RelayRegistration` is the existing message intended to carry reachable endpoints.

- Observation: current nodes already send their bound address in `RelayRegistration` through `NatTraversalConfig::disabled`, but peers discard `0.0.0.0:30333` as non-public.
  Evidence: `NatTraversal::attempt_mapping` returns `internal_addr` when traversal is disabled, and `accept_peer_addresses` rejects unspecified IP addresses.

- Observation: the one-off learned-peer dial path has neither an in-flight set nor a TCP connect timeout, and `max_peers = 0` disables opportunistic dialing even though admission treats zero as unlimited.
  Evidence: `dial_learned_candidates` compares the live count directly with `max_peers`, while `try_add_peer` treats zero as unbounded.

- Observation: `PeerStore::record_disconnected` calls `record_connected`, advancing `last_connected` for a failed session.
  Evidence: `network/src/peer_store.rs` lines 117-120 before this change.

- Observation: limiting each learned dial batch while sampling hash-map order can repeatedly select the same dead prefix and starve later healthy candidates.
  Evidence: before this change `PeerManager::sample_addresses` returned as soon as the limit was reached, with no candidate cursor or failure delay.

- Observation: the full network test target contains strict debug-build PQ handshake wall-clock assertions that are invalid under heavy unrelated host load.
  Evidence: all functional lanes passed, while the two timing assertions failed at a host load average above 48; the branch does not modify PQ handshake code.

## Decision Log

- Decision: keep the existing `CoordinationMessage::RelayRegistration` wire shape and interpret an unspecified address only as a listening-port hint.
  Rationale: appending a new enum variant would disconnect older nodes during a rolling deployment. Combining the peer-supplied port with the transport-observed IP, and requiring explicit self-registration IPs to match that observed IP, prevents third-party IP injection while remaining compatible with honest current senders and old receivers.
  Date/Author: 2026-07-09 / Codex

- Decision: do not treat the raw inbound socket address as a reusable endpoint.
  Rationale: its port is normally ephemeral and advertising it would poison peer stores.
  Date/Author: 2026-07-09 / Codex

- Decision: keep discovery bounded and opportunistic rather than attempting to connect to every learned address.
  Rationale: resilience must not create an unbounded dial or memory amplification path. Address lists, query batches, peer-store capacity, and concurrent one-off dials remain capped; candidate rotation and exponential endpoint backoff prevent dead addresses from monopolizing those bounds.
  Date/Author: 2026-07-09 / Codex

- Decision: leave automatic router port mapping opt-in and document it as a residual reachability boundary.
  Rationale: silently opening a router port changes the user's external attack surface. Public operators can expose the configured P2P port, while outbound-only nodes still gain multi-seed and learned-public-peer redundancy.
  Date/Author: 2026-07-09 / Codex

## Outcomes & Retrospective

The implementation now propagates public self-registrations beyond the seed, refreshes address knowledge across rotating connected peers, rotates learned endpoints, limits one-off connection concurrency, backs failed endpoints off from 30 seconds to 15 minutes, preserves only actual successful-connect recency for persistent startup targets, and clears per-session advertised addresses when a peer is pruned. The existing three-node TCP integration confirms that a node learns another public endpoint through address exchange and that block gossip crosses a non-origin peer.

Validation is green: `cargo test -p network` passed all 107 tests, including 88 unit tests, adversarial transport checks, handshake checks, three-node TCP discovery/gossip, and the PQ timing lane. The two timing assertions initially failed at host load average 48.44, then passed both in isolation and in the complete target after load fell to 4.30, confirming an environmental timing artifact rather than a branch regression. Network clippy passes with warnings denied, formatting passes, `cargo check -p hegemon-node` passes, the approved-seeded-profile and live-mining seed-policy node tests pass, and all 128 `hegemon-formal-core` unit tests pass. Automatic router mapping, DHT discovery, a relay data plane, peer bans, and full NAT hole punching remain explicit residuals.

## Context and Orientation

The `network` crate implements authenticated TCP peer sessions. `network/src/service.rs` owns listener acceptance, persistent seed dials, learned one-off dials, address exchange, heartbeat pruning, and coordination messages. `network/src/peer_manager.rs` owns live peer sessions and bounded in-memory address books. `network/src/peer_store.rs` persists reusable endpoints across restarts. `network/src/p2p.rs` defines the existing wire messages. `node/src/native/service.rs` starts this service for the shipped native node.

A seed is an initially configured public endpoint used to enter the network. It must not remain the only route between nodes after discovery succeeds. A dialable endpoint is a public IP address and nonzero TCP port that another node may attempt to connect to. An inbound connection's observed source IP is trustworthy only as the IP that established that session; its source port is not a listening-port claim. A port hint is the unspecified address `0.0.0.0:PORT` or `[::]:PORT` already emitted by nodes bound to all interfaces. The new code may combine that port with the session's observed source IP, but it must never accept an arbitrary peer-supplied IP through this path.

## Plan of Work

First, add small pure helpers in `network/src/service.rs` for peer capacity, observed endpoint derivation, and registration normalization. Change registration handling so an unspecified address contributes only its port and the connected peer's transport address contributes only its IP; explicit self-registration entries must use that same observed IP. Persist and relay the resulting public endpoints through the existing bounded address path.

Second, add a dedicated discovery tick. It queries a rotating bounded subset of connected peer IDs, then attempts a bounded rotating subset of learned endpoints when capacity remains. Track one-off dial addresses in a set until the attempt completes, place failed endpoints on exponential backoff, add a TCP connect timeout to persistent and one-off connection paths, and preserve the existing exponential reconnect bound for configured persistent targets. Increase the bounded startup reconnect sample so a restart can recover through more than five cached peers.

Third, change `PeerStore::record_disconnected` so it refreshes storage lifetime without overwriting `last_connected`. Add tests that distinguish a successful connection from a later disconnect. Add service tests for endpoint derivation, zero-as-unlimited capacity, rotation, and in-flight suppression, plus an integration test showing that a public listening endpoint learned through a seed is persisted by another node.

Finally, update `DESIGN.md` and `METHODS.md` to describe the compatibility-preserving port-hint rule, periodic address refresh, bounded dial behavior, approved shared seeds, and the residual requirement that an operator expose or map a P2P port to accept inbound sessions. The operator text must retain the approved `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` list and NTP/chrony guidance for miners.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Edit the runtime and tests with `apply_patch`, then run:

    cargo fmt --all --check
    cargo test -p network
    cargo clippy -p network --all-targets -- -D warnings

Run focused native configuration and startup tests selected by name after the network crate is green. If runtime configuration code is touched, run the native node package test target that covers `NativeConfig::from_cli` and `start_native_p2p` without starting a public service.

Inspect the final patch with:

    git diff --check
    git status --short
    git diff --stat

## Validation and Acceptance

Acceptance requires all focused network tests to pass with no ignored new failures. A registration containing `0.0.0.0:30333` from a peer observed at `203.0.113.10:49152` must derive only `203.0.113.10:30333`; a registration cannot cause an unrelated IP to be derived. Non-public derived endpoints must still be rejected by the existing sanitizer.

With `max_peers = 0`, learned-peer dialing must remain enabled because zero means unlimited admission. Multiple address announcements for the same unreachable endpoint must create at most one active one-off dial attempt. Failed endpoints must back off and must not starve later candidates in the bounded dial pool. TCP connect and handshake attempts must terminate within their configured bounds. Periodic discovery must rotate across connected peers instead of querying the same map prefix forever.

After a peer connects and then disconnects, `last_connected` must retain the successful connection time rather than the disconnect time. Startup reconnect selection must remain capped and must prioritize imported peers, then recently successful cached peers, then configured seeds without duplicates.

The final `cargo test -p network`, clippy command, formatting check, and `git diff --check` must pass.

## Idempotence and Recovery

All edits are source-only and can be applied repeatedly through version control. Tests use temporary peer-store paths and abort spawned services at completion. No live testnet state, wallet store, or deployed host is modified by this plan. If a test leaves a temporary peer-store file, the existing random suffix prevents collision and the file may be removed safely.

## Artifacts and Notes

The key pre-change evidence is:

    P2PCommand::NewPeer(... dialable_addr = !inbound)
    PeerStore::record_disconnected(addr) -> record_connected(addr)
    dial_learned_candidates: peer_count >= max_peers rejects max_peers = 0

The final evidence transcript is:

    cargo fmt --all --check
    cargo test -p network
    test result: 107 passed; 0 failed across all network targets
    cargo clippy -p network --all-targets -- -D warnings
    cargo check -p hegemon-node
    cargo test -p hegemon-node approved_seeded_dev_profile_reports_public_testnet_identity --lib
    cargo test -p hegemon-node live_mining_requires_shared_seeds_or_explicit_bootstrap_authoring --lib
    cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml
    test result: 128 passed; 0 failed

## Interfaces and Dependencies

No new crate dependency is required. The implementation will continue using Tokio TCP, timers, and channels; the existing authenticated `CoordinationMessage::RelayRegistration`; `PeerManager`; and `PeerStore`.

`network/src/service.rs` will expose no new public protocol type. It will add private helpers with behavior equivalent to:

    fn observed_registration_addresses(
        transport_addr: SocketAddr,
        advertised: Vec<SocketAddr>,
    ) -> Vec<SocketAddr>;

    fn has_peer_capacity(peer_count: usize, max_peers: usize) -> bool;

The service tracks a bounded set of one-off addresses currently being dialed, bounded retry metadata for learned endpoints, a cursor for rotating learned candidates, and a cursor for rotating address queries. `network/src/peer_manager.rs` provides a stable list of connected peer IDs for query rotation. `network/src/peer_store.rs` preserves its serialized record format.

Revision note (2026-07-09 18:07Z): Initial plan created after inspecting the shipped native P2P path. The design deliberately uses the existing registration message so old and new nodes can coexist during deployment.

Revision note (2026-07-09 19:03Z): Added candidate rotation, exponential learned-endpoint backoff, and observed-IP binding for explicit registrations after final diff review exposed starvation and address-poisoning risks not covered by the initial implementation.

Revision note (2026-07-09 19:22Z): Closed the plan after complete network, clippy, native-node, and formal-core validation passed. Recorded the overloaded-host PQ timing false alarm and clean representative-load rerun.

Revision note (2026-07-09 19:31Z): Added and validated stale advertised-address cleanup when heartbeat pruning removes a peer; the final network count is 107 tests.

Revision note (2026-07-09 19:51Z): Extended the plan for a user-approved rolling deployment. The laptop and `hegemon-dev` are canaries; `hegemon-ovh` remains live until both pass. Roll back on mismatched genesis or tip hash, a closed mining sync gate, persistent zero-peer state, or failed required CI.
