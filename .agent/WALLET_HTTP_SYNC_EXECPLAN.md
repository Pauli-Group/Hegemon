# Make native wallet connections work by default and measure first sync

This living ExecPlan follows `.agent/PLANS.md`. The work is isolated on `codex/testnet-0-10-3-wallet-launcher` based on release v0.10.2 (`ea3465c4bfb07d00501318772ea88863cb19fb37`).

## Purpose / Big Picture

A fresh wallet should use the native node's HTTP interface without an operator discovering that the old WebSocket instructions fail. Runbooks, both installed repository skills, CLI defaults, and generated desktop endpoints must agree. Measure a first wallet scan of the retained public testnet snapshot so the report explains actual work rather than treating an hour-long scan as a connection failure. Preserve wallet secrets, recovery checkpoints, canonical commitment checks, and existing node data.

## Progress

- [x] (2026-10-14 UTC) Verify released HTTP-only node and stale WebSocket defaults; create isolated release-based worktree.
- [x] Delegate exclusive documentation, Rust transport/default, desktop, source performance, and offline profiling scopes.
- [x] (2026-10-14 01:16 UTC) Finish HTTP defaults/instructions and explicit WebSocket regression tests (12 integration and 16 RPC unit cases pass).
- [x] (2026-10-14 01:45 UTC) Complete bounded offline profiling: fresh HTTP scan succeeds in 176.339 seconds; 116.436 seconds is local Poseidon tree reconstruction and upstream RPC totals 13.053 seconds. Reopened scan reaches the remaining time limit during another tree rebuild; retain partial coverage, false whole-run acceptance and clean source/listener checks.
- [x] (2026-10-14 01:31 UTC) Finish desktop timeout review, CLI parser test, version-aligned node/wallet/walletd builds and independent HTTP/launcher/CI review. All 59 focused app tests, type checking, UI guards, full formatting and manifest gates pass. Implementation saved in local commit `7a1429670`.

## Surprises & Discoveries

The native HTTP GET root returns status JSON with HTTP 200. A WebSocket client therefore fails the required HTTP 101 upgrade. `walletd sync.once` preserves the compatibility parameter `ws_url`; a value beginning `http://` already works. The released downloadable README is correct while several repository runbooks and the default `NodeRpcConfig` are stale.

Desktop review also found 90-second renderer and ten-minute bridge limits that interrupt healthy first scans. The shared sync-only deadline is now two hours, with shorter individual node RPC deadlines retained. Cancellation still stops walletd and locks the session.

Source inspection found that every commitment and ciphertext page serializes, encrypts, and fsyncs the entire wallet state, and incoming note checks derive an ML-KEM address key per ciphertext. Runtime samples directly identify local Poseidon commitment-tree reconstruction in the 116-second no-RPC gap; ciphertext samples include persistence and ML-KEM work without exact per-function timing attribution.

## Decision Log

Keep `ws_url` and `--ws-url` as compatible names, but change generated one-shot values to HTTP. Retain explicit WebSocket clients for real subscription providers; never silently downgrade a user-selected transport. Native subscription methods remain unsupported and instructions must state that boundary. No consensus, proof format, payout, seed rotation, release publication, or deployment changes belong to this fix. The user subsequently requested the Windows execution-policy bypass repair for v0.10.3; include that launcher/packaging change and align all three binary package versions.

Use existing attested v0.10.2 binaries for the performance baseline. Run one offline relay over an APFS clone of a closed public-chain snapshot with mining, seeds, and bootstrap disabled. Use a disposable fresh wallet; preserve the original snapshot and all existing wallets. Root coordinates builds and shared files so parallel workers do not race.

## Outcomes & Retrospective

The HTTP/default and direct Windows launcher repairs are implemented. Desktop first-scan deadlines have been corrected and independently reviewed, including cleanup races and never-settling IPC. Local transport, application, source-byte manifest, packaging and gate-policy checks have passed. The final version-aligned builds pass. Fresh-scan profiling is complete after two corrected harness failures; the reopened scan is explicitly partial because the experiment deadline stopped its full-tree reconstruction. Published v0.10.2 remains unchanged; Windows runtime CI and all release gates are prerequisites for publishing v0.10.3.

## Context and Orientation

`node/src/native/service.rs` serves HTTP JSON-RPC at `/`; it has no WebSocket upgrade route. `wallet/src/node_rpc.rs` chooses HTTP or WebSocket from the endpoint scheme. `wallet/src/bin/wallet.rs` supplies CLI defaults, and `walletd/src/main.rs` forwards the `sync.once` endpoint. `wallet/src/async_sync.rs` fetches canonical commitment pages, decrypts note pages, verifies the reconstructed commitment tree, and checks spent notes. `wallet/src/store.rs` owns the encrypted wallet file and its exclusive writer lock. `hegemon-app/electron` adapts one-shot endpoints and manages local node launch; the renderer provides generated connection values. Runbooks and `.codex`/`.claude` skills teach operators how to call these paths.

A commitment is the public hash identifying an encrypted note. The wallet must scan unrelated ciphertexts to find notes it owns and retain all commitments needed for inclusion proofs. A page is a bounded RPC response of up to 256 entries. The Merkle tree hashes all commitments into the root that is compared with the trusted local node; this check remains mandatory.

## Plan of Work

First change only generated one-shot endpoints and stale operator instructions to `http://127.0.0.1:9944/`. Give an actionable HTTP-200 WebSocket rejection hint without transport fallback. Align generated desktop defaults and HTTP local-node detection while preserving saved explicit endpoints. Add real ephemeral HTTP and WebSocket test servers so compatibility is verified through actual requests.

Second audit persistence, cryptographic note scanning, and native archive servicing. Profile the exact released binaries against a disposable APFS clone of the public snapshot. Record per-method request durations, bytes and counts, wallet file growth, process CPU and stack samples, and first versus resumed sync. Treat the user's slow VPS timing as reported evidence; a local Mac measurement cannot prove that host's bottleneck.

Finally run focused transport tests, wallet library/sync tests appropriate to changed code, desktop tests/type checking, shell syntax and diff checks. Record final evidence and unresolved limits. If a clear performance improvement requires a durability or cryptographic design change, record it as follow-up rather than weakening verification or recovery behavior for a speed claim.

## Concrete Steps

All source commands run from `/Users/pldd/.codex/worktrees/wallet-http-sync-fix/Hegemon`. Baseline evidence is written under `/private/tmp/hegemon-wallet-http-sync-investigation/baseline`; source audit uses its separate `source-audit` directory. Use the already compatible downloaded release binaries, with hashes checked against their retained manifest. New source validation uses an isolated cargo target directory and the pinned Rust 1.91.1 toolchain. Check free disk before compilation or clones and retain at least 8 GiB for profiling.

Transport validation: `cargo test --release --locked -p wallet --test node_rpc`; relevant RPC unit tests: `cargo test --release --locked -p wallet --lib node_rpc::tests`; CLI: `cargo test --release --locked -p wallet --bin wallet rpc_argument_tests`. Use `CARGO_TARGET_DIR=/private/tmp/hegemon-wallet-http-sync-investigation/build/target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0`. Setup and the initial native release build passed; the version-aligned node, wallet CLI and walletd builds pass. No further compilation competes with the wallet profile. Desktop: `npm test -- <scoped test paths>` and `npm run typecheck` after acquiring locked dependencies. Formatting uses `cargo fmt --all -- --check` on a clean scoped worktree, and shell runbooks use `bash -n state.sh send.sh`. Exact executed commands and results will be recorded below.

The bounded baseline permits one offline node on loopback RPC 19969/P2P 30359, at most 600 seconds startup and 600 seconds scan, node RSS below 6 GiB, and no automatic retries. It must verify expected genesis and snapshot tip before scanning, then cleanly stop only its own processes and confirm original source metadata and hashes are unchanged.

## Validation and Acceptance

A default `NodeRpcConfig` must connect to a native-compatible HTTP server and complete a real JSON-RPC request. An explicitly chosen WebSocket endpoint must still complete a real WebSocket JSON-RPC request. A native-style HTTP 200 rejection must contain a clear HTTP endpoint hint without fallback. Generated desktop local endpoints must be HTTP and HTTP loopback endpoints must trigger the expected managed-node port/autostart behavior. Instructions must use HTTP for native one-shot calls, retain compatibility keys/flags, and explain that subscription mode needs a genuine WebSocket provider.

The performance report must include measured scan duration and request counts/timing, source evidence for growing wallet rewrites and per-note cryptographic work, and distinguish measurement from an unverified explanation for the user's one-hour VPS report. A scan must finish with canonical height/root agreement and reopen/resume safely before being called successful.

## Idempotence and Recovery

Run tests with disposable temporary stores and unique ports; never use an operator wallet. Do not reset or delete retained snapshots, proofs, or wallet data. Interrupted profiling stops its owned node/wallet processes and leaves receipts for diagnosis. Source changes are reversible on this isolated branch. Prepare the fixes for v0.10.3. No push, publication, or deployment is part of this request.

## Artifacts and Notes

Initial diagnosis: `ws://127.0.0.1:9944` receives HTTP 200 rather than the WebSocket-required 101; `http://127.0.0.1:9944/` successfully scans with the same released binary. Runtime receipts show completed fresh scan, partial reopened coverage and clean source/process/listener preservation. The current user additionally authorized propagation to the Plan the path to mainnet and Recursive proofs threads; both received the tested source commit and precise scope, with mainnet as the single writer for shared files. Both threads acknowledged the handoff. Mainnet assigned adoption review/integration for shared source; Recursive proofs recorded the constraints and avoids duplicate runtime edits. Actual shared-source integration is owned by the mainnet thread and must be distinguished from this verified acknowledgement.

## Interfaces and Dependencies

Keep the existing `NodeRpcConfig.ws_url`/walletd `ws_url` public fields and CLI flags. HTTP uses the existing `jsonrpsee-http-client`; explicit WebSocket uses the existing `jsonrpsee-ws-client`. A test-only `soketto` dependency reuses version 0.8.1 already pinned in the release lock to test real WebSocket handshakes. No production dependency or wire format changes are required.

Revision 2026-10-14: initial plan created after isolating the released source and identifying transport and scan candidates.

Revision 2026-10-14: the user added the Windows execution-policy bypass repair for v0.10.3. Integrate the existing reviewed direct CMD launcher and source-byte allowlist gates from the maintenance repair; remove the retired PowerShell helper from packaging. Root owns package version alignment; the documentation worker owns release packaging and its existing gate wiring. Validate local guard/packaging tests and retain Windows execution as an explicit pending CI requirement.

Revision 2026-10-14 01:18 UTC: HTTP/WS and TLS tests passed after correcting the macOS fixture socket mode. Integrated the reviewed Windows direct launcher, hash allowlist, source/packaging gates and CI omission checks. The retired PS1 deletion is recorded in the isolated Git index; the full actual-worktree manifest suite now passes. Baseline startup is running without concurrent Cargo compilation. Desktop timeout review requires deadline settlement independent of cleanup and immediate token invalidation.

Revision 2026-10-14 01:31 UTC: complete and locally commit the implementation. Close the independently reproduced required-job CI omission gap with eight negative fixtures. Apply only pre-existing rustfmt corrections in two native files; full formatting and source-bound manifests now pass. Profiling attempt 1 supplied an incomplete listen address; attempt 2 reused the recorded height-117050 anchor incorrectly at tip 117051. Both cleanly shut down and preserved original source bytes/metadata. Authorize one final independently audited twelve-minute measurement window with those fixture errors corrected; preserve all failed receipts, retain mining/peer restrictions and do not retry further failures.

Revision 2026-10-14 01:45 UTC: profiling completed with fresh-scan success and incremental deadline. Attribute the measured no-RPC interval to tree hashing; do not present source-estimated write volume or stack-sample presence as measured physical IO or exact phase percentages. Root verifies the 923 fresh requests and CPU/wall measurements, and retains the false whole-run acceptance flag. User explicitly authorized cross-thread propagation; dispatch to both verified titles while preserving consensus versions and proof work.

Revision 2026-10-14: verify acknowledgements from both named threads through bounded thread-status snapshots. Preserve mainnet single-writer ownership and its ongoing proof work; do not claim that acknowledgement alone is completed source integration. Final profiling worker confirms all own processes/listeners/watchers closed and actual encrypted store size 7,026,858 bytes.

## Publication authorization and acceptance

The user explicitly requested publication of v0.10.3. The coordinator will commit the final source and refreshed source-bound review package, push the maintenance branch and v0.10.3 tag, require every release job to pass, verify all downloaded assets against their manifests and reviewed helper bytes, execute a disposable downloaded-binary testnet relay/wallet/restart check, and publish the completed draft as latest. Existing dependency exceptions retain their approved October 24 expiry; no review statuses or proof posture may be promoted. Deployment of the OVH node is outside this publication step.

- [ ] Refresh final source bindings and review archive without changing review status.
- [ ] Run the complete remote release pipeline, including native Windows launcher fixtures.
- [ ] Verify all four platform downloads and actual relay/wallet/restart behavior.
- [ ] Publish v0.10.3 as latest and verify public release metadata.

Publication attempt 1: the dependency gate correctly rejected five new quinn-proto advisories before any draft/assets were produced. Update only quinn-proto 0.11.16 to patched 0.11.18, preserve the five existing approved exceptions, repeat the fresh dependency audit, renew computed source bindings and the archive, and retag the unpublished candidate for a complete new pipeline. Retain the failed run as evidence.
