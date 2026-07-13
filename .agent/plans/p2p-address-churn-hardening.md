# Bound learned peer-address churn and report disconnects accurately

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while the work proceeds. This plan follows `.agent/PLANS.md`.

## Purpose / Big Picture

An authenticated peer can currently supply many public ports for one IP address. Hegemon backs off each full `IP:port` separately, so changing the port can keep the node opening outbound sockets even after earlier ports failed. The desktop then labels an ordinary remote socket closure as an unresolved node error. After this change, learned discovery will apply retry and retention controls per IP as well as per endpoint, ordinary disconnects will not present as actionable failures, configured seeds and imported peers will retain their existing behavior, and focused tests plus the repository gates will demonstrate those properties.

## Progress

- [x] (2026-07-12 21:31Z) Reproduced the live symptom and traced the learned-address and log-classification paths.
- [x] (2026-07-12 22:02Z) Added focused regressions for same-IP retention, retry bypass, post-session cooldown, and disconnect classification.
- [x] (2026-07-12 22:06Z) Implemented learned-address admission, endpoint/shared-IP retry state, post-session cooldown, and desktop compatibility classification.
- [x] (2026-07-12 22:14Z) Updated `DESIGN.md`, `METHODS.md`, the libp2p evaluation, and formal review ledgers with the resulting contract.
- [x] (2026-07-12 23:10Z) Passed network, desktop, UI-guard, format, formal-ledger, blueprint, and the complete 14-stage formal-core validation after the final code correction.
- [x] (2026-07-12 23:17Z) Published draft pull request #200 without merging; required CI completion is tracked on the pull request.

## Surprises & Discoveries

- Observation: The live node stayed synchronized with both approved seeds while its 200-line log buffer was saturated by discovery retries.
  Evidence: `system_health` returned `isSyncing=false` and two peers; `hegemon_consensusStatus` returned equal height and sync target while the console showed changing ports on one learned IP.
- Observation: The existing one-in-flight-per-IP rule controls concurrency but not retry rate across ports.
  Evidence: `reserve_dial_candidates` excludes only currently in-flight IPs, while `dial_retry` is keyed by `SocketAddr`.
- Observation: Clearing shared-IP retry state when a one-off task ended would reopen the rotation path after connect-then-close behavior.
  Evidence: `DialFinished` previously treated `PeerRunOutcome::Disconnected` as success even though the route was no longer active; the completion signal now records a fresh cooldown.
- Observation: An inbound session proves only that the remote source can connect to us; it does not prove any advertised listening port on that IP is reachable.
  Evidence: The shared `NewPeer` admission path previously cleared dial retry state for inbound and outbound sessions alike; retry clearing is now outbound-only.
- Observation: Socket sorting during startup would let low attacker-chosen ports displace more recently useful endpoints under the new per-IP cap.
  Evidence: `PeerStore::addresses` now exposes the same success-or-learned recency rank used by store retention, with a socket-address tie break only for equal timestamps.
- Observation: The first PR run stopped at the strict Clippy gate because two explicit returns ended the final coordination match arm.
  Evidence: `rust-lints` reported `clippy::needless_return` at the two `PunchResponse` branches; replacing them with normal arm completion preserved behavior and made `./scripts/check-core.sh lint` pass locally.

## Decision Log

- Decision: Harden only learned one-off discovery; do not alter configured seeds, explicit imported peers, or persistent reconnect loops.
  Rationale: The observed input arrives through authenticated address exchange, while operator endpoints are an intentional compatibility contract.
  Date/Author: 2026-07-12 / Codex
- Decision: Preserve diagnostics for unexpected transport failures but classify ordinary remote-close error kinds as disconnect events below error severity.
  Rationale: A broken pipe already triggers safe peer removal and is not an unresolved node failure.
  Date/Author: 2026-07-12 / Codex
- Decision: Clear stale retry history on accepted connection, then start a fresh endpoint/IP cooldown when an admitted one-off session disconnects.
  Rationale: Reachability should recover an IP from accumulated failure history, but session closure must not permit immediate alternate-port rotation.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The implementation now admits at most four learned endpoints per IP before persistence or propagation, requires both endpoint and shared-IP retry deadlines before a one-off dial, prevents inbound source ports from clearing outbound retry state, and restores cooldown when an admitted one-off session disconnects. Startup retention prefers recently successful or recently learned endpoints instead of attacker-controlled low ports. Configured seeds, imported peers, wire formats, consensus, and storage are unchanged.

Ordinary remote-close errors are warnings in the node, and the desktop also downgrades matching legacy error lines already present in its rolling buffer. Unexpected transport and encryption failures remain errors.

Validation completed locally: `cargo fmt --all -- --check`, `cargo test -p network --lib` (97 passed), desktop typecheck, UI guard, and tests (40 passed), JSON parsing, formal claims (122 claims and 2,605 named Lean theorems), formal blueprint (122 nodes, 524 edges, 649 falsification cases), and a post-correction `scripts/check_formal_core.sh` rerun (all 14 stages). The live node was not restarted or modified.

Residual limitation: shared-IP grouping can delay discovery of another learned port for a legitimate multi-port host behind one IP. That tradeoff is confined to learned one-off discovery; explicit operator endpoints retain their existing independent reconnect behavior. The deterministic regressions close the reproduced rotation path, but no live hostile-peer soak was performed against this candidate branch.

## Context and Orientation

`network/src/service.rs` owns authenticated peer admission, learned-address storage, one-off dial selection, retry state, and the per-peer run loop. A learned address is a public socket endpoint received from another authenticated peer and persisted in `pq-peers.bin`. A configured seed or imported peer is operator supplied and follows a separate persistent connection path. `hegemon-app/electron/nodeManager.ts` retains the most recent 200 node log lines, and `hegemon-app/src/App.tsx` counts every parsed error line for the Console navigation badge.

The attacker-controlled input is an authenticated `Addr` or `RelayRegistration` list containing public endpoints. Each message is capped at 16 entries and rate-limited, but the node can retain up to 1,024 endpoints. Because retry state is keyed by the entire socket address, many ports on one IP can consume repeated dial opportunities. The invariant is that failed learned endpoints from one IP cannot evade bounded retry or occupy an excessive portion of retained learned state merely by changing ports. Legitimate endpoint rotation must still be possible after bounded backoff, and configured seeds/imports must remain endpoint-addressed.

## Plan of Work

Add low-level deterministic helpers in `network/src/service.rs` for per-IP learned-address admission and retry eligibility, then exercise them through the existing service unit-test module. Cap retained learned endpoints per IP, apply a shared IP retry state whenever a one-off endpoint fails, and require both endpoint and IP retry deadlines before reservation. Clear the shared IP retry state after a successful admitted session so a genuinely reachable replacement port restores normal discovery. Keep the existing endpoint backoff for precision and preserve the one-in-flight-per-IP control.

Add a transport-error classifier that recognizes ordinary peer disconnect error kinds such as broken pipe, connection reset, connection aborted, unexpected EOF, and not connected. The peer loop will log those as warnings or informational disconnects and retain error severity for other failures. The existing `PeerDisconnected` command remains responsible for session eviction.

Keep the desktop 200-line buffer, but ensure its red badge reflects genuinely error-level lines after runtime classification. Add or extend parser/UI tests so a warning disconnect does not increment the error count and a true error still does.

Update the peer-discovery prose in `DESIGN.md` and `METHODS.md` to state the per-IP retention and retry contract and the expected-disconnect logging contract.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon-p2p-address-churn` on `codex/p2p-address-churn-hardening`.

Run the focused regression tests while developing:

    cargo test -p network service::tests --lib
    npm --prefix hegemon-app test -- --run

Then run formatting, owning-package tests, and repository gates selected from CI:

    cargo fmt --all -- --check
    cargo test -p network --lib
    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app test -- --run
    bash scripts/check_formal_core.sh

Before publication, inspect `git diff --check`, the final diff, and the branch status. Push the branch, open a draft pull request, and watch all required GitHub checks to successful completion.

## Validation and Acceptance

The regression test must show that many ports on one IP occupy only the allowed retained slots, a failed port blocks immediate selection of another port on that IP, a different IP remains selectable, and a successful connection clears shared IP backoff. Separate tests must show that broken pipe and connection reset are expected disconnects while an unrelated I/O error remains error-level.

Existing tests must continue to prove that multiple explicit endpoints on one host remain valid where the operator path allows them, discovery rotates across distinct IPs, endpoint backoff grows exponentially, duplicate peer sessions are rejected, and disconnect cleanup removes only the active session.

The live node is read-only validation evidence only. This work must not restart it, mutate its base path, clear its peer store, or alter the current testnet.

## Idempotence and Recovery

All tests and format checks are repeatable. Source edits are confined to the isolated worktree. If a test exposes a compatibility conflict, revise only the candidate branch; do not modify the running app, node process, or `/Users/pldd/.hegemon-node-native-010-dev`. The draft pull request must not be merged by Codex.

## Artifacts and Notes

The live triggering error was `failed to send to 42.116.135.181:14428: io error: Broken pipe (os error 32)`. The node then remained synchronized and advanced from height 11,468 to 11,471 with both approved seed peers connected.

## Interfaces and Dependencies

No new dependency is required. The implementation should use `std::net::IpAddr`, `std::io::ErrorKind`, the existing `HashMap` and `HashSet` state, and existing `DialRetryState`. Any new helper must remain private to `network::service` unless tests demonstrate a repository-wide interface is necessary.

Revision note: Initial plan created after reproducing live same-IP port churn and confirming that consensus remained healthy.
