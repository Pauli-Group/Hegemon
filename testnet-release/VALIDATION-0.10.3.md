# v0.10.3 maintenance preparation validation

Prepared on 2026-10-14 UTC in the isolated `codex/testnet-0-10-3-wallet-launcher` branch, starting from published v0.10.2 (`ea3465c4bfb07d00501318772ea88863cb19fb37`). This records the local source/build validation checkpoint before publication. The publication pipeline repair below records subsequent tagged execution; deployment is separate.

## Changes

- Native one-shot wallet RPC defaults, CLI/example defaults, operator runbooks, mirrored join skills and generated desktop profiles use HTTP. Legacy `--ws-url`/`ws_url` names and explicitly selected genuine WebSocket providers remain compatible. HTTP-200 WebSocket rejection includes an actionable hint without transport fallback.
- Desktop renderer and walletd bridge share a two-hour sync-only deadline. Cancellation remains available; expiration invalidates the session immediately and settles even if cleanup hangs. The reset option describes its existing genesis-change semantics.
- Windows uses direct CMD/native execution, with no PowerShell helper or execution-policy override. Reviewed helper hashes are enforced during build, manifest verification, assembly and final ZIP creation. CI requires actual Windows behavior tests and exact HTTP/default/watchdog regressions before publication.
- Node, wallet and walletd package versions are 0.10.3. Genesis, proof formats and difficulty activation at 120,000 remain unchanged. Two native files received only pre-existing rustfmt corrections needed for the formatting gate; no native behavior changed.

## Executed local checks

| Check | Result |
| --- | --- |
| `cargo test --release --locked -p wallet --test node_rpc` | 12 passed, 6 existing integration cases ignored; actual HTTP, WebSocket and rejection fixtures executed |
| `cargo test --release --locked -p wallet --lib node_rpc::tests` | 16 passed, including HTTPS/WSS policy rejection and bounded page admission |
| `cargo test --release --locked -p wallet --bin wallet rpc_argument_tests` | 1 passed; HTTP omission/default and explicit WS compatibility |
| `make setup`, `make node` | Passed; final native package 0.10.3 built with pinned Rust 1.91.1 |
| `cargo build --release --locked -p walletd` | Passed; package 0.10.3 |
| `wallet --version` | `wallet 0.10.3` |
| Four desktop endpoint/connection/watchdog/IPC test files | 59 passed |
| App `npm run typecheck`, `npm run check:ui-guards` | Passed |
| Launcher hash policy | Passed for all three reviewed helpers |
| Launcher policy / artifact boundary / download packaging suites | 27 / 18 / 15 cases passed |
| POSIX launcher fixture suite | 7 passed |
| Windows launcher suite on macOS | 6 portable passed; 20 Windows execution cases skipped |
| Full source-bound release manifest suite | Passed after recording the intended PS1 removal in the Git index |
| CI/release executable policy mutation suite | Passed on authored workflows and negative fixtures |
| `cargo fmt --all -- --check`, shell syntax, `git diff --check` | Passed |

Rust build/test commands used an isolated APFS-cloned build cache, `CARGO_BUILD_JOBS=1` and `CARGO_INCREMENTAL=0`. Desktop dependencies were copied into the isolated worktree after verifying matching lockfiles. The primary dirty checkout was preserved. Independent HTTP/desktop and launcher/source-boundary reviews found no remaining issue; the final CI prevention delta also passes independent review, including eight required-job omission/failure mutations.

## Performance evidence

The exact published v0.10.2 ARM64 node and walletd are profiled against an offline APFS clone of a closed public testnet snapshot with mining/seeds/bootstrap disabled and a disposable wallet. Its scan algorithm is unchanged by these maintenance fixes. See [the performance investigation](../docs/WALLET_SYNC_PERFORMANCE.md) for source costs, measured results and host-specific limits. Fresh HTTP sync passed in 176.339 seconds at height 117,051 for 117,100 commitments/ciphertexts. The 116.436-second no-RPC gap was local commitment-tree reconstruction; upstream service totaled 13.053 seconds. The reopened scan reached the remaining bounded-run deadline during another tree rebuild, so whole-experiment acceptance is false and reopened completion is unverified. Cleanup and retained-source equality passed.

## Remaining publication gates

Actual Windows launcher execution, the complete source/formal/dependency/native-backend/app E2E and all platform artifact gates remain prerequisites for publication. Local portable tests and source reviews do not substitute for those remote gate results. No claim is made that the user's one-hour VPS duration has been reproduced or eliminated. This maintenance fix does not alter scan durability or cryptographic verification to obtain a speed claim.

Local evidence: `/private/tmp/hegemon-wallet-http-sync-investigation`, including independent reviews, desktop receipt, source audit and bounded runtime receipts. These scratch receipts are not shipped in a user ZIP and contain no operator wallet data.

## Authorized cross-thread propagation

The user requested propagation to `Plan the path to mainnet` and `Recursive proofs`. Both received the tested source commit, applicable HTTP/default/watchdog and no-policy-bypass fixes, validation results and measured scan report. Both acknowledged. Mainnet coordinates common source adoption; Recursive proofs records the operating constraints and verifies adoption without concurrent shared-file edits. Integration in those ongoing tasks is separate from this local testnet commit and is not asserted complete by acknowledgement alone.

## Publication pipeline repair

The first tagged pipeline (38499238263, source `99f3e422740c72f48159a5f330a9ec09b50e95df`) stopped at the dependency audit before producing a draft or platform artifacts. Five quinn-proto advisories published on October 12 affected locked version 0.11.16. The maintenance lockfile is updated to upstream patched 0.11.18; no new exception is added. The finalized source bindings and archive are regenerated before replacing the unpublished failed tag and rerunning all release gates. The earlier local-preparation results remain scoped to their recorded source.
