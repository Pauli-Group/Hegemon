# Hegemon 0.10 Production Readiness Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

The Hegemon desktop app and native 0.10 stack must be able to run as a real user product, not a scripted demo. After this plan is complete, a user can install or run the Electron app, create or open a wallet, connect to the shared dev/testnet through local node RPC only, sync without SSH, mine when configured, receive and send shielded transactions, consolidate notes, execute supported private multisig flows, recover after restarts, and see the same behavior validated by formal-core and monorepo CI gates. The work is not complete until the app, wallet, node, live network path, formal verification evidence, and CI-equivalent commands all pass or a precise release blocker remains documented here.

## Progress

- [x] (2026-07-01 00:36Z) Created the active Codex goal for production-readiness hardening across app, node, wallet, formal verification, and CI.
- [x] (2026-07-01 00:36Z) Refreshed `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, the testnet join skill, CI workflows, the Electron app scripts, and the current native PoW retarget plan.
- [x] (2026-07-01 00:36Z) Captured the current live evidence: small transactions, consolidation, and transaction-tier 1-of-1 multisig completed on `native-devnet-host`, but block production slowed to multi-minute gaps around difficulty `489471780` with observed hash rate near 1 MH/s.
- [x] (2026-07-01 00:36Z) Identified the first release blocker: the PoW liveness acceptance gate is too weak. A chain reaching height 1 or confirming isolated transactions is not sufficient; the gate must prove sustained timing across multiple retarget windows.
- [x] (2026-07-01 00:36Z) Identified the second release blocker: changing mining to 64 reported threads did not materially raise measured hash rate, so mining parallelism needs an implementation fix or a fail-closed operator warning plus regression coverage.
- [x] (2026-07-01 01:20Z) Patched native mining to batch disjoint nonce ranges per worker, count every attempted hash, and remove the per-round idle gap that made configured thread count misleading under high difficulty.
- [x] (2026-07-01 01:20Z) Added focused native regressions for mining hash accounting and slow-window retarget recovery; reran existing prepared-work import, pending revalidation, and fast-window stale-bit rejection tests successfully.
- [x] (2026-07-01 01:02Z) Built the patched Linux release binary on `native-devnet-host`, deployed it to `hegemon-node.service`, set service mining threads to 16, and measured live hash rate around 4.05 MH/s versus about 0.83 MH/s before the patch.
- [x] (2026-07-01 01:09Z) Strengthened `scripts/test-node.sh devnet-liveness` from height>1 to a real block-window gate, added `rpc-liveness` for loopback-only live nodes, and passed the local release two-node liveness gate.
- [x] (2026-07-01 01:18Z) Ran corrected `rpc-liveness` on `native-devnet-host`: start height 193, end height 199, 6 blocks in 395s wall time, chain timestamp average 79.060s, max chain gap 130.655s, 16 threads, hash rate about 4.066 MH/s, pending pool 0.
- [x] (2026-07-01 01:25Z) Updated the Electron node summary and UI to surface mining sync gate, sync target, next difficulty, bootstrap authoring, and pending-pool count; `npm --prefix hegemon-app run typecheck` and `npm --prefix hegemon-app run build` pass.
- [x] (2026-07-01 01:35Z) Ran focused wallet/native/receipt gates: wallet tx-leaf emission passed, native shielded transfer import passed, coinbase shielded mint/supply passed, canonical transfer ordering passed, `superneo-hegemon receipt_root` passed 18/18 with 1 expected ignored slow lane, and `consensus receipt_root` passed 8/8 with expected ignored heavy integrations.
- [x] (2026-07-01 01:40Z) `./scripts/check-core.sh lint` passed. `./scripts/dependency-audit-gate.sh` initially failed on unwaived `RUSTSEC-2026-0190` for `anyhow 1.0.100`; updated `Cargo.lock` to `anyhow 1.0.103`, then dependency audit passed with 8 waived and 0 unwaived findings.
- [x] (2026-07-01 02:20Z) Repaired formal-core drift and passed `bash scripts/check_formal_core.sh` end to end. The run passed checker formatting/tests, Lean proof kernel and axiom audit for 2,598 theorem symbols, generated Rust conformance vectors, dependency audit for formal-core, formal inventory, system-model gates, active-goal progress, claims ledger, blueprint DAG, independent bridge vectors, native backend reference vectors, native backend release posture, and the model-checker non-claim gate.
- [x] (2026-07-01 02:20Z) Formal fixes were: retarget first-boundary Lean/vector semantics now defer until the full retarget window exists; the blueprint miner-identity order edge now points at `verify_pow_header_with_expected_bits`; and stale pending-action reorg bindings now track `revalidate_pending_actions` plus `stage_revalidated_pending_action`.
- [x] (2026-07-01 08:43Z) Added `scripts/live-app-no-ssh-e2e.mjs` and passed the release-binary no-SSH workflow locally. The harness launched a mining seed and an app-style non-mining relay, submitted wallet operations only to the relay loopback RPC, recovered coinbase through the relay, confirmed three small transfers, forced auto-consolidation, and completed private multisig value-lock/setup/approval/final. Final summary: run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-CTSXgL`, duration 203s, final common height 50, seed pending 0, relay pending 0, small txs `0x0aa092328915d6c9236acc48bc000fa0f72169fbd4d0bf8cbb7b776b53901b22`, `0x99b26e54afb78960dbdfb76d8b3f4e8595124c0abb79997ea5855fb78acb1531`, `0x6a4245aba5e0860b8f97716c6c5b49f28be2d4cedf9b0ef0e44a54c2b0f2aa7a`, consolidation tx `0x01113177b0d45b6c5e64b34f5f04f53fbc8693782785fba8b4bd593bb310190f`, multisig final tx `0x78769b65c645a5dc1bcf164a6ce31200a1cf6ff3a5c84589d1d125524ebf2751`.
- [x] Run formal-core and update `DESIGN.md`, `METHODS.md`, runbooks, and any Lean/vector evidence touched by the implementation.
- [x] (2026-07-01 02:45Z) `./scripts/check-core.sh test` passed across crypto, consensus-light-client, consensus, transaction-circuit, block-circuit, disclosure, network, protocol-kernel/shielded-pool, wallet, cashvm-bridge, hegemon-node, and security-pipeline.
- [x] (2026-07-01 03:27Z) Repaired the native artifact fuzz harness so red-team fuzz timeouts run parser/canonicalization coverage instead of proof verification per fuzz input; focused deterministic verifier/tamper tests still cover the heavy proof path.
- [x] (2026-07-01 03:27Z) `bash scripts/run_proving_redteam.sh` passed in full mode. Summary: `output/proving-redteam/20260701T030836Z/summary.txt`; all eight campaigns passed, including parser-malleability, semantic-aliasing, staged-proof-abuse, recursive-block-mismatch, receipt-root-tamper, prover-configuration-downgrade, network-transport-abuse, and review-package-parity. Native backend timing passed with 64 samples per class, Welch t-statistic -0.2957, mean delta 0.152%, median delta 0.283%.
- [x] Run monorepo CI-equivalent commands from `.github/workflows/ci.yml` and record pass/fail evidence here.
- [x] (2026-07-01 03:31Z) `cargo build --release -p hegemon-node -p wallet -p walletd` passed.
- [x] (2026-07-01 03:31Z) `./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd` passed. Source, lockfile, binary symbol, critical module, and approved primitive checks were clean.
- [x] (2026-07-01 05:59Z) Found and fixed a no-SSH transaction propagation blocker: the native P2P sync protocol announced blocks but did not relay pending actions, so packaged-app transfers confirmed only when the laptop node mined them locally. Added bounded `PendingAction` relay, durable peer staging, duplicate suppression, miner-local artifact rejection, stale-candidate eviction, and Lean raw-ingress vector coverage. Focused checks passed: `lean_generated_sync_raw_ingress_vectors_match_production`, `relayed_pending_action*`, and `relayed_transfer_evicts_stale_candidate_artifact_from_mempool`.
- [x] (2026-07-01 07:09Z) Re-ran `./scripts/check-core.sh test` to completion after the pending-action relay fix. The gate passed, including the slow wallet multisig builder/funded setup/rejection tests, wallet CLI/disclosure/vector tests, cashvm-bridge tests, two `hegemon-node` 401-test configurations with the new relayed pending-action regressions, and the `security_pipeline` adversarial integration.
- [x] (2026-07-01 07:20Z) Completed a top-tier app UX pass: removed decorative radial backgrounds, normalized rectangular radii and letter spacing, made disabled primary/secondary controls visually muted, compacted the status bar, added wallet sync-lag visibility, bounded full shielded-address display behind an inspector, stabilized balance/note detail rows, added live send-address length/validity feedback, reset route scroll on navigation, and disabled empty contact submission.
- [x] (2026-07-01 07:20Z) App gates passed after the UX pass: `npm --prefix hegemon-app run typecheck`, `npm --prefix hegemon-app run build`, `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run package`, `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app`, and `git diff --check` for touched app files.
- [x] (2026-07-01 07:20Z) Hardened the macOS app bundle metadata: added app description/author, added an Electron Builder `afterPack` hook, verified `NSAllowsArbitraryLoads=false`, kept local networking enabled, and replaced misleading default camera/microphone/Bluetooth usage strings with explicit non-use text.
- [x] (2026-07-01 07:20Z) Visually inspected the rebuilt packaged Electron app with Computer Use. Overview, Wallet, and Send screens rendered without overlapping text; long wallet path/address surfaces were bounded; route navigation reset to the top; disabled Send/Sync/Add Contact controls were visibly disabled.
- [x] (2026-07-01 07:38Z) Re-ran `bash scripts/check_formal_core.sh` after the pending-action relay, UX, and app package metadata changes. The full gate passed: checker formatting/tests, Lean proof build, axiom audit for 2,602 theorem symbols with 0 temporary and 0 unwaived axiom dependencies, generated Rust conformance vectors, formal-core dependency audit, inventory, system-model gates, active-goal measure, 122-claim ledger, blueprint DAG, bridge vectors, native backend reference vectors, native backend release posture, and model-checker non-claim gate.
- [x] (2026-07-01 08:10Z) Re-ran `bash scripts/run_proving_redteam.sh` after the app package metadata hook. Full mode passed all eight campaigns: parser-malleability, semantic-aliasing, staged-proof-abuse, recursive-block-mismatch, receipt-root-tamper, prover-configuration-downgrade, network-transport-abuse, and review-package-parity. Summary: `output/proving-redteam/20260701T073855Z/summary.txt`. Native backend timing passed with 64 samples per class, Welch t-statistic -0.0506, relative mean delta 0.0714%, relative median delta 0.0655%, threshold 25%.
- [x] (2026-07-01 16:02Z) Retired the broken Codex Security Deep Scan app workflow from this release gate per operator direction and replaced it with direct repo-grounded release audit over the app/node/wallet/release surface. Patched the Electron wallet shell to enable renderer sandboxing, deny navigations/popups/webviews, deny runtime permission prompts, and keep wallet RPC loopback-only; tightened renderer labels so "remote" no longer implies direct public RPC; added an Apple notarization hook plus a fail-closed `npm run dist:prod` credential check. Validation passed: `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run package`, `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app`, `git diff --check`, and the production release env check fails closed without Apple credentials.
- [x] (2026-07-01 08:43Z) Run a live no-SSH app path with release binaries: local app-style relay node, local mining seed, wallet sync, mining, transfers, consolidation, transaction-tier multisig, relay P2P action propagation, and final seed/relay common-height check all passed.
- [x] (2026-07-01 09:10Z) Re-ran `./scripts/check-core.sh test` after the wallet native-nullifier and walletd signer-tag JSON fixes. The gate passed through crypto, consensus-light-client, consensus, transaction-circuit, block/disclosure circuits, network/PQ transport, protocol-kernel/shielded-pool, wallet, cashvm-bridge, two `hegemon-node` 401-test configurations, and the `security_pipeline` adversarial integration.
- [x] (2026-07-01 09:26Z) Re-ran `bash scripts/check_formal_core.sh` after the wallet native-nullifier and walletd signer-tag JSON fixes. The full 14-step gate passed: checker formatting/tests, Lean proof kernel, axiom audit for 2,602 theorem symbols with 0 temporary and 0 unwaived axiom dependencies, generated Rust conformance vectors, formal-core dependency audit with the single allowed `anyhow` advisory warning, inventory, system-model gates, active-goal measure, 122-claim ledger, blueprint DAG with 122 nodes and 524 edges, independent bridge vectors, native backend reference vectors, native backend release posture, and the model-checker non-claim gate.
- [x] (2026-07-01 09:54Z) Re-ran `bash scripts/run_proving_redteam.sh` after the wallet native-nullifier and walletd signer-tag JSON fixes. Full mode passed all eight campaigns: parser-malleability, semantic-aliasing, staged-proof-abuse, recursive-block-mismatch, receipt-root-tamper, prover-configuration-downgrade, network-transport-abuse, and review-package-parity. Summary: `output/proving-redteam/20260701T092636Z/summary.txt`. Native backend timing passed with 64 samples per class, Welch t-statistic `0.2503735954884008`, relative mean delta `0.3846598995296863%`, relative median delta `0.07686249501051754%`, threshold `25%`.
- [x] (2026-07-01 09:58Z) Final cheap hygiene passed after the red-team run and fuzz corpus cleanup: `cargo fmt --all --check`, `npm --prefix hegemon-app run typecheck`, and `git diff --check`.
- [x] (2026-07-01 16:10Z) Superseded the earlier current-tree Codex Security Deep Scan workspace `7ec29cca-0d92-4801-a653-86783256feeb` as a release blocker. The scan never started because the app-side Start action timed out, and the release gate now uses the direct repo-grounded audit recorded below.
- [x] (2026-07-01 13:46Z) Canceled the stale June 27 Codex Security deep scan. The replacement two-round current-tree deep scan found one real release blocker: seed-control drift between `devnet.hegemonprotocol.com:30333` and the approved `hegemon.pauli.group:30333` seed. The blocker was fixed across app defaults, Electron node launch normalization, native shared-mining guidance, shell scripts, runbooks, docs, and the network IPv4-preference fixture. The app keeps the retired devnet hostname/IP only as legacy migration aliases that normalize to the approved seed.
- [x] (2026-07-01 13:46Z) Post-remediation seed sweep passed: outside `target`, app dist, node_modules, and lockfiles, the only `devnet.hegemonprotocol.com:30333` and `51.222.86.107:30333` references are the explicit app legacy alias maps in `hegemon-app/src/App.tsx` and `hegemon-app/electron/nodeManager.ts`; active operator guidance and native/app defaults use `HEGEMON_SEEDS="hegemon.pauli.group:30333"`.
- [x] (2026-07-01 13:46Z) Re-ran app/package gates after seed remediation: `npm --prefix hegemon-app run typecheck`, `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run build`, `npm --prefix hegemon-app run package`, and `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app` passed. Electron Builder still skipped Apple notarization because this environment has no notarization credentials.
- [x] (2026-07-01 13:46Z) Re-ran formal-core after the current production-readiness changes. `bash scripts/check_formal_core.sh` passed with 2,602 Lean theorem symbols, 0 temporary axiom families, 0 unwaived axiom dependencies, 122 claims, 112 production-eligible nodes, native backend vectors 11/11, and native backend posture `candidate_under_review / structural_candidate`.
- [x] (2026-07-01 13:46Z) Re-ran the full proving red-team gate. `bash scripts/run_proving_redteam.sh` passed all eight campaigns: parser-malleability, semantic-aliasing, staged-proof-abuse, recursive-block-mismatch, receipt-root-tamper, prover-configuration-downgrade, network-transport-abuse, and review-package-parity. Summary artifacts: `output/proving-redteam/20260701T121809Z/summary.txt` and `summary.json`. Native backend timing passed with 64 samples per class, Welch t-statistic `0.3798471876015882`, relative mean delta `0.33115515875590655%`, relative median delta `0.008759193920846611%`, threshold `25%`.
- [x] (2026-07-01 13:46Z) Re-ran post-patch monorepo CI-equivalent gates. `./scripts/check-core.sh all` passed; `./scripts/dependency-audit-gate.sh` passed with 8 waived, 0 unwaived, 0 unused waivers; the native shipped-path integration commands from `.github/workflows/ci.yml` passed, including wallet tx-leaf emission, node shielded transfer import, coinbase shielded mint/supply, raw-active bad-proof rejection, receipt-root acceptance/rejection, and canonical transfer ordering. `cargo test -p hegemon-node receipt_root -- --nocapture` remains an empty filter on the current test names, matching the CI command.
- [x] (2026-07-01 13:46Z) Re-ran native backend release gates not covered by the red-team wrapper: `bash scripts/verify_native_receipt_root_scalability.sh` passed for 128 leaves and 1024 blocks, and `./scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz` reported `candidate_under_review / structural_candidate`.
- [x] (2026-07-01 13:46Z) Re-ran release binary audit after the final release build. `./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd` passed: source pattern scan, `Cargo.lock` dependency scan, native binary symbol scan, critical-module verification, and approved primitive checks were clean.
- [x] (2026-07-01 16:02Z) Superseded the fresh post-remediation Codex Security Deep Scan workspace `26ac17f6-50d6-45ba-8891-cb056f9aedf9` as a release blocker. The app-side Start scan workflow timed out twice, Computer Use cannot control the Codex app (`com.openai.codex`) in this environment, and operator direction was to stop using the broken deep-scan path for this release gate.
- [x] (2026-07-01 16:10Z) Prepared the final ship/no-ship report for this turn: source/runtime is a ship candidate on the recorded local gates, while public macOS distribution remains blocked until `npm --prefix hegemon-app run dist:prod` is run with Apple notarization credentials.
- [x] (2026-07-01 16:27Z) Re-ran the release-binary no-SSH app workflow on the current tree after the latest app UI/status and seed-runbook fixes. `HEGEMON_E2E_KEEP=1 node scripts/live-app-no-ssh-e2e.mjs` passed in 354s with run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-jPxyWn`, final common height 46, seed pending 0, relay pending 0, three small transfers, consolidation tx `0x674f6e494be344f8054be917a65d78a194438671dfd20b643e48867782d5899c`, and multisig final tx `0x773734f508fe78dfe6bd73202cf21d484980b463c98b7cc546dba2d44abb2dcf`.
- [x] (2026-07-01 16:27Z) Rechecked the live packaged app managed node after the no-SSH run. The packaged app stayed running on `127.0.0.1:9955`; `hegemon_consensusStatus` reported height 944, peers 1, syncing false, supply digest `471461197512`, and best hash `0x0000000d8e3db91aac10167c7bc5267a0d9928a7f4ad1c77fb578c0a7a2274f9`. Cheap hygiene passed: `npm --prefix hegemon-app run typecheck` and `git diff --check`.
- [x] (2026-07-01 19:12Z) Re-checked the current tree after the peer-topology/app summary patch. `cargo fmt --all --check` and `./scripts/check-core.sh lint` initially failed because `node/src/native/mod.rs` needed rustfmt normalization; `git diff --check` also found trailing whitespace in `formal/lean/Hegemon/Release/CiReleaseGate.lean`. Applied rustfmt and removed the trailing whitespace, then `cargo fmt --all --check`, `./scripts/check-core.sh lint`, and `git diff --check` passed.
- [x] (2026-07-01 19:12Z) Re-ran current app gates after the latest UI/status work: `npm --prefix hegemon-app run typecheck`, `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run build`, `npm --prefix hegemon-app run package`, and `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app` passed. `npm --prefix hegemon-app run dist:prod` failed closed before build because Apple notarization credentials are absent.
- [x] (2026-07-01 19:12Z) Re-ran `./scripts/dependency-audit-gate.sh`; it passed with 8 waived findings, 0 unwaived findings, and 0 unused waivers.
- [x] (2026-07-01 19:12Z) Re-ran `./scripts/check-core.sh test` on the current tree after the peer-topology RPC and formatting changes. The gate passed through crypto, consensus-light-client, consensus, transaction-circuit, block/disclosure circuits, network/PQ transport, protocol-kernel/shielded-pool, wallet, cashvm-bridge, both `hegemon-node` 402-test native configurations, and `security_pipeline`. The `unsafe_peer_topology_rpc_exposes_connected_peer_snapshot` and `peer_snapshot_observer_tracks_connected_peers` regressions were included and passed.
- [x] (2026-07-01 19:12Z) Re-ran the current release binary lane. `./scripts/check-core.sh build` passed, then `./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd` passed with no forbidden classical crypto primitives and all approved PQ/STARK primitives present.
- [x] (2026-07-01 16:37Z) Extended `scripts/live-app-no-ssh-e2e.mjs` to stop the app-style relay node, restart it on the same node base path and ports, require it to rejoin the mining seed at the prior common height, require both pending pools to remain empty, and force-resync both wallets through the restarted relay with no spendable-balance regression.
- [x] (2026-07-01 16:37Z) Re-ran the restart-enhanced no-SSH workflow. `HEGEMON_E2E_KEEP=1 node scripts/live-app-no-ssh-e2e.mjs` passed in 305s with run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-DNM1yA`, final common height 45, seed pending 0, relay pending 0, restart common height 45, restart seed pending 0, restart relay pending 0, restart miner spendable `22459315038`, restart recipient spendable `14999997`, consolidation tx `0x46db5b6f8dfed4d8b6d69406516bc319f90efe1c473d03978849f83eb22027e3`, and multisig final tx `0xdf7ddb8a7bedc80048f853c46af5fd75af1a26d5ab5d9f0bc5fda7777933d9f5`.
- [x] (2026-07-01 16:44Z) Extended `scripts/live-app-no-ssh-e2e.mjs` to prove the disclosure path on the same no-SSH topology: after a confirmed outgoing transfer, the miner wallet must list the outgoing disclosure record, create a disclosure package, verify that package against the relay RPC, and match recipient address, value, asset id, memo, and commitment.
- [x] (2026-07-01 16:44Z) Re-ran the disclosure-enhanced no-SSH workflow. `HEGEMON_E2E_KEEP=1 node scripts/live-app-no-ssh-e2e.mjs` passed in 278s with run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-xkRc8e`, final common height 45, seed pending 0, relay pending 0, restart common height 45, restart pending 0/0, disclosure tx `0x6a8bdb432a39f95b7c5af2d78809337ae4d1674d3ed293ac550b8280f9122a98`, disclosure commitment `0x3f28a9b91c3c85a793e734a90b4cd2347f47459633fe9f2de61f5e2e9fd32424c65594558491e7e3725f66993ac2627b`, consolidation tx `0x493c0969ce6839e089bc51c615b2d5d6c2604f4fcedde2fdb5b94c30b733e243`, and multisig final tx `0x68a97ae02d7855f4edeb514780fac8aa3f9c0a971cbae4c6dc569c21cc8caf22`.
- [x] (2026-07-01 16:53Z) Found and fixed a real app-launch confusion path: Computer Use was opening the macOS dev bundle at `.electron-vite/Hegemon.app`, which launched Electron's `default_app.asar` placeholder when no app entry was provided. `hegemon-app/scripts/dev.mjs` now pins `ELECTRON_ENTRY` and the Electron Vite root/cwd to `hegemon-app`, so `npm --prefix hegemon-app run dev` cannot silently show Electron's default app.
- [x] (2026-07-01 19:30Z) Fixed the packaged-app wallet address copy failure by moving wallet/disclosure copy actions from renderer `navigator.clipboard` to a typed Electron preload/main-process clipboard IPC. Copy-address failures now stay local to the address card instead of turning the wallet/nav health red. Re-ran `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run check:ui-guards`, `npm --prefix hegemon-app run build`, `npm --prefix hegemon-app run package`, `npm --prefix hegemon-app run check:launch-autostart`, and `git diff --check`; the packaged app relaunched on live native-devnet-host at height 1,576, synced, one peer, mining on, loopback RPC, and seed `devnet.hegemonprotocol.com:30333`.
- [x] (2026-07-02) Promoted mining payout visibility into the Wallet UX. The main process now reports the effective managed `HEGEMON_MINER_ADDRESS` in node summary, the Wallet view compares running payout versus wallet receiving address, the Wallet sidebar turns payout mismatch into an explicit warning, and the wallet offers a direct action to save the wallet address as the next mining payout. The UI guard now requires the Mining rewards section and payout-aware nav status.
- [x] (2026-07-01 16:53Z) Updated the first-viewport app status to make live `native-devnet-host` state unambiguous before wallet unlock: the app now labels the default local connection `native-devnet-host P2P 0.10`, shows the active node's chain spec, genesis, approved seed, height, peer count, mining state, and supply from node RPC, and treats the named `~/.hegemon-node-native-devnet-host-010-dev` base path as a managed 0.10 default for seed/port normalization.
- [x] (2026-07-01 16:53Z) Rebuilt and relaunched the packaged app with the app-launch/status fixes. Validation passed: `node --check hegemon-app/scripts/dev.mjs`, `npm --prefix hegemon-app run typecheck`, `git diff --check`, and `npm --prefix hegemon-app run package`. The running packaged app then started its managed node on `127.0.0.1:9955`; direct RPC reported height 965, peers 1, `syncing:false`, genesis `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`, base path `/Users/pldd/.hegemon-node-native-devnet-host-010-dev`, and bootstrap seed `hegemon.pauli.group:30333`.
- [x] (2026-07-01 20:39Z) Re-ran the native-backend-security CI-equivalent lane on the current tree. The package tests passed for `superneo-backend-lattice`, `native-backend-ref`, `superneo-hegemon`, and `superneo-bench`; native backend reference vectors passed 11/11; timing passed with Welch t-statistic `0.23795013119097172` and relative median delta `0.003910010186996191`; receipt-root scalability passed for 128 leaves and 1024 blocks; fuzz campaigns for `native_tx_leaf_artifact` and `receipt_root_artifact` completed; the review package was regenerated/verified; and `check_native_backend_release_posture.sh` reported `candidate_under_review / structural_candidate`.
- [x] (2026-07-01 20:39Z) Removed the last app-launch footgun behind the user's ugly/not-connected report. The generated macOS dev helper is now `.electron-vite/Electron Dev Runner.app`, not `.electron-vite/Hegemon.app`, and `scripts/dev.mjs` deletes the legacy generated `Hegemon.app` so Computer Use/Finder cannot open a branded Electron default placeholder as if it were the product.
- [x] (2026-07-01 20:39Z) Aligned fresh desktop defaults with the validated no-SSH native-devnet-host path: the renderer and Electron node manager now default to loopback RPC port `9955`, the default base path is `~/.hegemon-node-native-devnet-host-010-dev`, and legacy default local profiles on `9944` migrate to the tested `9955` profile when they still point at loopback.
- [x] (2026-07-01 20:39Z) Reworked the first overview viewport so the app opens with a connection verdict instead of a debug dump. Computer Use verified the rebuilt packaged app shows `Connected to native-devnet-host`, `Live P2P connection`, local RPC `ws://127.0.0.1:9955`, approved seed `hegemon.pauli.group:30333`, peer `51.222.86.107:30333`, synced height/target `1,154`, and managed app node status before wallet unlock.
- [x] (2026-07-01 20:39Z) Re-ran current app gates after the default/profile/overview patch: `node --check hegemon-app/scripts/dev.mjs`, `npm --prefix hegemon-app run typecheck`, `npm --prefix hegemon-app run lint`, `npm --prefix hegemon-app run package`, `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app`, `cargo fmt --all --check`, and `git diff --check` passed. `npm --prefix hegemon-app run dist:prod` still fails closed without Apple notarization credentials.
- [x] (2026-07-01 20:39Z) Re-ran the release-binary no-SSH app workflow on the current tree. `HEGEMON_E2E_KEEP=1 ./scripts/check-app-no-ssh-e2e.sh` passed in 315s with run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-Usxivb`, final common height 47, restart common height 48, seed pending 0, relay pending 0, three small transfers, disclosure verification, consolidation tx `0x4f9608cced5f9981685aa375d1fabaa24c3ac9934b0643df50c3575707cf32f2`, and multisig final tx `0x06275ea3ebad380ee936491b5d551b81238eebff4336945e4cd07e5aa657ac49`.
- [x] (2026-07-01 20:39Z) Rechecked the live packaged app after the no-SSH E2E. Direct RPC on `http://127.0.0.1:9955` reported height `1,159`, sync target `1,159`, `syncing:false`, `system_health.isSyncing=false`, one peer, peer list `51.222.86.107:30333`, and best hash `0x00000002f8a09984d1eba336765fa6b2e9373161a9d182e57ab9a2675013349b`.
- [x] (2026-07-01 20:47Z) Fixed the remaining default-launch product gap: the app no longer opens offline and waits for the user to discover `Start node`. On launch, the renderer auto-starts only the default managed native-devnet-host profile when it is a safe loopback profile on port `9955` with the approved seed and default 0.10 base path; relay profiles require no mining intent, and mining profiles require `Auto-start mining` plus a valid miner address. Manual `Stop node` suppresses auto-restart for that session.
- [x] (2026-07-01 20:47Z) Verified zero-click launch against the rebuilt packaged app. After quitting `com.hegemon.desktop`, the managed node stopped. Reopening `hegemon-app/dist/mac-arm64/Hegemon.app` brought RPC `127.0.0.1:9955` up in about 4 seconds without clicking `Start node`; it then caught up to height `1,162` / target `1,162` with `syncing:false`, one peer, mining active, sync gate open, 16 threads, and peer `51.222.86.107:30333`. Computer Use confirmed the first viewport showed `Connected to native-devnet-host` and `Live P2P connection`.
- [x] (2026-07-01 20:47Z) Re-ran app gates after launch auto-start: `npm --prefix hegemon-app run typecheck`, `npm --prefix hegemon-app run package`, `npm --prefix hegemon-app run lint`, `codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app`, and `git diff --check` passed. `npm --prefix hegemon-app run dist:prod` still fails closed without Apple notarization credentials.

## Surprises & Discoveries

- Observation: The transaction/proof path can work while the chain is still not production-ready.
  Evidence: On `native-devnet-host`, three small shielded transfers, consolidation, a 20 HGM transfer, and a 1-of-1 transaction-tier multisig payment all confirmed, yet the same chain later had multi-minute block gaps at difficulty around `489471780`.
- Observation: The slow part of the multisig test was PoW discovery, not proof verification.
  Evidence: Recent node logs showed one-transaction recursive aggregation verification around 9-13 ms, while pending transactions waited minutes for the next block.
- Observation: The existing native PoW retarget ExecPlan accepted height-1 app/seed convergence as final live evidence, which is too weak for production readiness.
  Evidence: The later live chain did converge and confirm transactions, but difficulty ratcheted upward and produced user-visible stalled confirmations.
- Observation: Runtime mining thread count is not currently enough evidence of actual hash-rate scaling.
  Evidence: `hegemon_startMining` accepted `{"threads":64}` and reported 64 threads, but `hegemon_miningStatus.hash_rate` stayed around 1.0-1.1 MH/s, close to the earlier 16-thread value.
- Observation: Unit tests now cover slow retarget recovery, but that is not a substitute for live liveness measurement.
  Evidence: `cargo test -p hegemon-node native_pow_schedule -- --nocapture` passed after adding `native_pow_schedule_recovers_after_slow_window_at_bounded_factor`; the next gate is a release-binary measurement on `native-devnet-host`.
- Observation: The original 180-second live max-gap threshold was too strict for a PoW chain with a 60-second average target.
  Evidence: A 44-block timestamp window from heights 150-193 averaged 58.049s with median 24.203s but had a 306.690s outlier; the liveness script now treats max-gap as a stall threshold while reporting average and max chain gaps explicitly.
- Observation: Formal-core caught stale production-wiring evidence after the mining/app changes.
  Evidence: The first full rerun failed on the PoW retarget vector boundary. After fixing Lean/vector semantics, the next run failed because `native.miner-identity` still expected `verify_pow_header` while production uses the retarget-safe `verify_pow_header_with_expected_bits`. The standalone blueprint rerun then exposed a stale `stage_reorg_pending_action` binding; updating it to the current revalidation helper chain made the blueprint and full formal-core gate pass.
- Observation: Block sync success did not imply transaction relay success.
  Evidence: The packaged app submitted transfer `0xd4a35e4544f11f12497be4ff231f1ef9b5f1a9a8557417243cc43da93c632d43`; it stayed pending across at least one imported peer block and cleared only when the local app-managed miner found block 358. `NativeSyncMessage` had `Announce`, `Request`, and `Response` variants only, with no pending-action relay path.
- Observation: Native wallet consolidation was live-broken even though normal sends worked.
  Evidence: The first no-SSH E2E reached `tx.plan` with three notes and one required consolidation transaction, then walletd waited indefinitely because `NodeRpcClient::is_nullifier_spent` queried `state_getStorage`, while the native node deliberately returns `null` for compatibility storage stubs. Wallet now checks native `hegemon_walletNullifiers` first and falls back to `state_getStorage` only when that method is unavailable.
- Observation: JavaScript could corrupt private multisig signer tags.
  Evidence: `multisig.localSignerTag` returned five `u64` JSON numbers, including values above `2^53`; feeding those through the Node/Electron JSON layer caused `multisig.approvalSubmit` to fail with `local signer is not in hidden multisig policy`. Walletd now serializes signer-tag limbs as fixed-width hex strings and accepts both string limbs and legacy numeric limbs.

## Decision Log

- Decision: Treat block-production liveness as the first release blocker, ahead of further feature polish.
  Rationale: A wallet/app can only feel correct if transactions confirm predictably. If PoW liveness is unstable, every higher-level feature becomes unreliable.
  Date/Author: 2026-07-01 / Codex
- Decision: Do not call app or network readiness from one-off successful transactions.
  Rationale: Isolated confirmations can pass during lucky PoW windows; the release gate must include sustained multi-window timing and restart/resync recovery.
  Date/Author: 2026-07-01 / Codex
- Decision: Preserve unsafe RPC loopback boundaries while testing app behavior.
  Rationale: The desktop app intentionally talks to local RPC. Remote access belongs behind SSH or an equivalent operator tunnel; public unsafe RPC is not a product target.
  Date/Author: 2026-07-01 / Codex
- Decision: Add peer pending-action relay instead of exposing unsafe RPC publicly.
  Rationale: No-SSH app usage still needs app-submitted transactions to reach peer miners. The correct product boundary is local unsafe RPC plus P2P relay of validated self-contained user actions; coinbase and recursive candidate artifacts remain miner-local.
  Date/Author: 2026-07-01 / Codex
- Decision: Use native wallet nullifier pages as the wallet confirmation source on native nodes.
  Rationale: Native nodes are not Substrate storage servers; `state_getStorage` compatibility stubs cannot prove shielded nullifier spends. Consolidation, pending reconciliation, and any wallet path waiting for nullifier confirmation must use the native wallet RPC surface.
  Date/Author: 2026-07-01 / Codex
- Decision: Encode walletd private multisig signer-tag limbs as strings at the JSON boundary.
  Rationale: JavaScript cannot exactly represent arbitrary `u64` limbs. Numeric signer tags silently corrupt hidden policy material before the proof-backed approval step, so the daemon must expose lossless string limbs for GUI clients.
  Date/Author: 2026-07-01 / Codex

## Outcomes & Retrospective

No completion outcome yet. The no-SSH app/wallet/node workflow is green on a release-binary local topology that mirrors the intended product boundary: local unsafe relay RPC plus P2P propagation to a miner, with no SSH and no public unsafe RPC. It now includes same-store relay restart, wallet force-resync, and disclosure list/create/verify coverage after small transfers, consolidation, and transaction-tier multisig. The packaged app auto-starts the default managed `native-devnet-host P2P 0.10` profile on launch, live-connects on the approved seed, catches up to `syncing:false` through its managed local node, and opens with a first-viewport `Connected to native-devnet-host` verdict instead of the dev Electron placeholder, an offline start screen, or raw diagnostics. The app package, formal-core, proving red-team, monorepo CI-equivalent, native-path, dependency-audit, native backend posture, release build, and release binary PQ-audit gates are green after seed-control remediation. The broken Codex Security Deep Scan UI is no longer part of this release gate; it was replaced by the direct manual release audit recorded above. The current source/runtime release surface is a ship candidate; production macOS distribution still requires Apple notarization credentials, and `npm run dist:prod` now fails closed when those credentials are missing.

## Context and Orientation

The Electron desktop app lives under `hegemon-app`. The renderer is `hegemon-app/src/App.tsx`, shared UI/API types are `hegemon-app/src/types.ts`, and Electron main-process code is in `hegemon-app/electron`. `hegemon-app/electron/nodeManager.ts` starts and monitors the bundled `hegemon-node` binary. `hegemon-app/electron/walletdClient.ts` starts `walletd` and sends newline-delimited JSON requests to it. The app must only send wallet RPC to loopback endpoints such as `127.0.0.1`; a remote node must be reached through a local tunnel or by running a local node that syncs over P2P.

The native node is implemented primarily in `node/src/native/mod.rs`. It stores block metadata, serves JSON-RPC, syncs over the Hegemon P2P service, prepares mining work, imports mined blocks, imports announced blocks, stages pending actions, builds automatic coinbase actions, and publishes wallet ciphertext rows. The term `pow_bits` means the compact proof-of-work target encoded in each block. A lower target is harder. The protocol target is a 60-second average block time, with difficulty retargeting every 10 blocks. The consensus constants are in `consensus/src/reward.rs`, and the generic PoW schedule helper is in `consensus/src/pow.rs`.

The wallet library is under `wallet`, and `walletd/src/main.rs` exposes the automation API used by the app and live tests. Supported production-like wallet operations include `sync.once`, `tx.plan`, `tx.send`, `disclosure.*`, and transaction-tier private multisig methods such as `multisig.valueLockSubmit`, `multisig.setupSubmit`, `multisig.approvalSubmit`, and `multisig.finalSubmit`. Older opaque multisig package methods are not the supported product path.

The formal verification release gate is `bash scripts/check_formal_core.sh`. The monorepo CI workflow is `.github/workflows/ci.yml`, with jobs for Rust/Lean lints, dependency audit, formal-core, core tests, native path tests, proving red-team gates, native backend security, and release binary audit. A local release-hardening run must either execute the same commands or document exact environment blockers.

## Plan of Work

First, fix the native liveness blocker. Inspect `mining_loop`, `mine_native_round`, mining task spawning, `hash_rate`, retarget schedule helpers, and live `hegemon_miningStatus` fields. Add regression coverage that proves multiple mining workers search disjoint nonce ranges and that reported hash rate reflects all attempted hashes. Add a sustained retarget simulation that fails if a fast early window can leave a normal single-host devnet at multi-minute block intervals for too long. If the protocol chooses bounded slow recovery rather than immediate retarget easing, make that operator-visible and release-blocking in the liveness gate.

Second, harden the app around truthful node state. In `hegemon-app/electron/nodeManager.ts` and `hegemon-app/src/App.tsx`, ensure the app cannot silently connect to the wrong RPC, cannot imply that public remote unsafe RPC is supported, cannot hide stalled sync or mining, and cannot present a mined transaction as confirmed until the wallet sync observes it. Add typecheck/build coverage and, if practical, browser or Electron-level smoke tests for the main screens.

Third, re-run wallet feature paths after the node fix. Use `walletd` for deterministic automation: sync, small sends, forced consolidation, final transfer after consolidation, disclosure list, and transaction-tier multisig. Confirm the user's wallet receives outputs by disclosure metadata and by independent wallet sync where available.

Fourth, update formal and design material. Any changed consensus, native mining, RPC, or wallet behavior must be reflected in `DESIGN.md`, `METHODS.md`, relevant runbooks, and formal-core evidence. If a behavior is not formally proved, name it as an executable liveness/system gate rather than a theorem.

Fifth, run CI-equivalent validation. The minimum local command set is:

    cargo fmt --all --check
    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run build
    ./scripts/check-core.sh lint
    ./scripts/dependency-audit-gate.sh
    bash scripts/check_formal_core.sh
    ./scripts/check-core.sh test
    cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads -- --nocapture
    cargo test -p hegemon-node submit_action_stages_and_imports_shielded_transfer -- --nocapture
    cargo test -p hegemon-node coinbase_action_mints_shielded_output_and_updates_supply -- --nocapture
    cargo test -p hegemon-node imported_block_actions_require_canonical_transfer_order -- --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    bash scripts/run_proving_redteam.sh
    cargo build --release -p hegemon-node -p wallet -p walletd
    ./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd

The native backend security job is heavier. Run it before final ship/no-ship if local disk and time permit; otherwise record the exact unrun commands as release blockers.

Sixth, run the deep security review requested for this release gate. Scope it to the Hegemon production surfaces that can move funds or mislead operators: `hegemon-app`, `wallet`, `walletd`, `node/src/native`, `network`, `consensus`, release scripts, and operator runbooks. Treat exploitable key handling, incorrect RPC trust boundaries, consensus acceptance bugs, wallet desync/spend bugs, multisig privacy or authorization leaks, and misleading release automation as release blockers until fixed or precisely disproven.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Start with focused native tests while preserving unrelated dirty work:

    cargo test -p hegemon-node native_pow --lib -- --nocapture
    cargo test -p hegemon-node prepared_work_import_survives_action_cache_eviction -- --nocapture
    cargo test -p hegemon-node pending_revalidation -- --nocapture

Then add the missing liveness regressions and run them before changing live `native-devnet-host` again. The test names and exact output must be recorded in this file as they are added.

For app validation, run:

    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run build

For live validation, use the approved seed list:

    HEGEMON_SEEDS="hegemon.pauli.group:30333"

All miners on the same network must share the same seed list. Hosts must keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.

## Validation and Acceptance

Production readiness requires all of the following to be true at the same time:

The app starts cleanly with the bundled binaries, creates or opens a wallet, starts or connects to a local node, syncs to the shared dev/testnet, shows accurate node and wallet height, mines only when the node is caught up, sends transactions, shows pending and confirmed states accurately, and survives app/node restart without losing wallet state.

Block production must be measured over multiple retarget windows. A single block or a single confirmed transaction is not enough. The liveness gate must report actual block timestamps, observed hash rate, configured mining threads, peer count, pending-pool length, difficulty, and next difficulty. It must fail if confirmation latency drifts outside the release target without a documented network/hash-rate explanation.

Wallet acceptance includes small sends, consolidation, disclosure listing, transaction-tier multisig value lock/setup/approval/final, wallet resync, and restart recovery. The final recipient outputs must be observable through disclosure metadata and wallet sync.

Formal acceptance requires `bash scripts/check_formal_core.sh` to pass after all code/doc changes. Any changed formal claim, implementation binding, or residual assumption must be updated with exact evidence rather than prose-only claims.

CI acceptance requires the local CI-equivalent commands to pass. If a CI job cannot be run locally because of platform, disk, or time limits, this plan must list it as an unresolved release blocker rather than silently omitting it.

## Idempotence and Recovery

Do not wipe wallet stores, node base paths, or remote chain state unless the plan explicitly records why a reset is necessary. Prefer new temporary base paths for destructive liveness tests. Preserve unrelated dirty files. If a live transaction is submitted and the script fails before confirmation, check `author_pendingExtrinsics`, wallet pending records, and block height before retrying so duplicate spends are not attempted blindly.

If the remote `native-devnet-host` service is changed, record the service path, binary hash, environment file, base path, and mining status in this plan. Restore any temporary mining-thread changes after measurement unless the new value is an intentional deployment decision.

## Artifacts and Notes

Current live evidence before this plan:

    native-devnet-host height: 143
    pending extrinsics: 0
    mining threads restored to: 16
    observed difficulty: 489471780
    observed hash rate: about 0.95 to 1.1 MH/s
    completed multisig final tx: 0x4996269e2534b3065295f73ee7e37783edf53de8adc64f199a8d790da1ca0758

Current live evidence after the mining-batch patch:

    native-devnet-host service binary sha256: 343a0a7d5003c423f61dc550b96cb61a059436a27fa83f8aa26d3bb198597e0d
    service path: /home/ubuntu/hegemon-current-retarget2-20260630T183408Z/target/release/hegemon-node
    base path: /home/ubuntu/native-devnet/native-1m-threads-20260630T213158Z
    service env: HEGEMON_MINE=1, HEGEMON_MINE_THREADS=16, HEGEMON_BOOTSTRAP_AUTHORING=1, HEGEMON_SEEDS empty for the bootstrap seed
    live rpc-liveness: start 193, end 199, produced 6, elapsed 395s, max wall gap 123s, chain_avg 79.060s, chain_min 11.706s, chain_max 130.655s
    live mining status during pass: 16 threads, hash_rate about 4.066 MH/s, pending extrinsics 0, syncing false

Known current release blockers and retired gates:

    PoW liveness has focused unit retarget regressions, one corrected live rpc-liveness pass, and a current release-binary no-SSH app workflow pass.
    Mining thread scaling is live-measured on native-devnet-host for 16 threads, but broader host/thread-count benchmarking is not yet part of CI.
    App no-SSH full workflow passed on release binaries in the local two-node topology with wallet sync, small transfers, disclosure list/create/verify, consolidation, private multisig final spend, same-store relay restart, and wallet force-resync through the restarted relay. Latest current-tree run: `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-xkRc8e`, duration 278s, common height 45, restart common height 45, seed pending 0, relay pending 0.
    Check-core test, formal-core, app typecheck/build/lint/package, focused relay tests, release build, dependency audit, binary security audit, and proving red-team pass after the latest wallet native-nullifier and walletd signer-tag fixes.
    Retired gate: Codex Security Deep Scan is removed from the release gate for now because the app-side Start-scan workflow repeatedly timed out and operator direction was to stop using it. The replacement direct release audit found and fixed Electron shell lockdown, misleading public-RPC copy, and notarization-process gaps.
    macOS notarization is not complete because Electron Builder has no Apple notarization credentials in this environment; ad-hoc signing verifies locally, and production distribution must use `npm run dist:prod` with Apple credentials so notarization runs instead of being silently skipped.

## Interfaces and Dependencies

In `node/src/native/mod.rs`, the mining loop must keep using disjoint nonce ranges for each worker. The functions and fields to audit are `NativeNode::start_mining`, `mining_loop`, `mine_native_round`, `mining_round`, `mining_hashes`, `NativeNode::hash_rate`, `NativeNode::prepare_work`, `NativeNode::import_mined_block`, and `NativeNode::expected_child_pow_bits`.

In `hegemon-app/electron/nodeManager.ts`, managed node launch must set `HEGEMON_SEEDS` to the approved seed list for shared networks and must not imply public unsafe RPC is acceptable. In `hegemon-app/src/App.tsx`, user-facing status must distinguish local node health, wallet sync height, chain status, peer count, mining state, pending transactions, and confirmed wallet notes.

Revision note, 2026-07-01 / Codex: initial plan created after the user required a production-level goal and after live tests proved that transaction success did not prove sustained block-production readiness.

Revision note, 2026-07-01 / Codex: the pending-action P2P relay fix added a direct sync-loop admission wrapper so the formal blueprint can mechanically verify fail-closed relay staging before P2P rebroadcast. Direct `check-blueprint` now passes with 122 nodes, 236 implementation bindings, 179 result obligations, 154 order constraints, and 139 dominance constraints. Focused runtime regressions passed on the current tree:

    cargo test -p hegemon-node relayed_pending_action --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node relayed_transfer --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node submit_action_stages_and_imports_shielded_transfer --lib --no-default-features -- --nocapture

The full `bash scripts/check_formal_core.sh` gate still must be rerun to completion after this control-flow adjustment.

Revision note, 2026-07-01 / Codex: full `bash scripts/check_formal_core.sh` passed on the current tree after the relay/control-flow adjustment. The pass included Lean proof build, axiom audit, generated Rust conformance vectors, the updated sync raw-ingress pending-action relay vector, formal inventory, system-model gates, claims ledger, blueprint DAG, bridge vectors, native backend reference vectors, and native backend release posture. The wrapper reported 122 blueprint nodes, 236 implementation bindings, 179 result obligations, 154 implementation order constraints, 139 dominance constraints, 646 falsification cases, and 112 production nodes.

Revision note, 2026-07-01 / Codex: the current-tree Codex Security deep scan found one canonical seed-control class after two independent discovery rounds: app/native/script/docs disagreed between `devnet.hegemonprotocol.com:30333` and the approved `hegemon.pauli.group:30333` seed. DNS resolved those hostnames to different addresses, so the split was a concrete release blocker. The remediation standardized app defaults, Electron managed-node normalization, native live-mining guidance/tests, shell scripts, runbooks, and docs on `HEGEMON_SEEDS="hegemon.pauli.group:30333"`; the app keeps the old devnet hostname/IP only as a legacy migration alias. Focused checks passed:

    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run lint
    bash -n scripts/start-mining.sh scripts/generate-testnet-keys.sh start.sh
    cargo test -p hegemon-node live_mining_requires_shared_seeds_or_explicit_bootstrap_authoring -- --nocapture

Revision note, 2026-07-01 / Codex: packaged macOS app launch/autostart now has a repeatable gate at `scripts/check-app-launch-autostart.mjs`, exposed through `npm --prefix hegemon-app run check:launch-autostart`. The gate quits `com.hegemon.desktop`, requires `127.0.0.1:9955` to stop serving first so stale nodes cannot satisfy the test, reopens `hegemon-app/dist/mac-arm64/Hegemon.app`, and fails unless the packaged app starts a loopback-only managed node that uses the approved seed and reaches live native-devnet-host P2P. Current pass evidence:

    npm --prefix hegemon-app run package
    npm --prefix hegemon-app run check:launch-autostart
    version: Hegemon Native Node 0.10.0
    genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
    height/target: 1173/1173
    peers: 1
    syncing: false
    pending extrinsics: 0
    mining: true
    mining threads: 16
    hash rate: 18278.98249640483 H/s
    rpc_external: false
    rpc_methods: unsafe
    rpc_listen_addr: 127.0.0.1:9955
    bootstrap_nodes: hegemon.pauli.group:30333

Revision note, 2026-07-01 / Codex: full current-tree `bash scripts/check_formal_core.sh` completed after the app live/UI work and reached the required final pass line. Current formal-core evidence:

    cargo fmt --all --check
    git diff --check
    bash scripts/check_formal_core.sh

    Lean theorem inventory:
      named Lean theorems: 2604
      claims: 122
      Lean-theorem claims: 122
      production eligible: 112
      residual risks: 50

    Formal-core checker tests: 125 passed
    Lean proof kernel:
      passed: true
      axiom-free theorems: 1148
      axiom-dependent theorems: 1456
      temporary axiom families: 0
      temporary axiom theorems: 0
      budget violations: 0
      unwaived axiom dependencies: 0

    Dependency audit:
      RUSTSEC-2026-0190 / anyhow 1.0.102 recorded as one allowed warning for hegemon-formal-core

    System-model fail-closed gates:
      gates: 6
      evidence paths: 20
      max freshness SLA hours: 168
      passed: true

    Active-goal progress measure:
      completed properties: 18 / 18
      weighted completion percent: 100.0
      goal status when measured: paused

    Blueprint DAG:
      nodes: 122
      production nodes: 112
      implementation bindings: 236
      implementation result obligations: 179
      implementation order constraints: 154
      implementation dominance constraints: 139
      falsification cases: 647
      passed: true

    Bridge vectors: 2 / 2 passed
    Native backend reference vectors: 11 / 11 passed
    Native backend release posture: candidate_under_review / structural_candidate
    Model checker pass: execution not requested; the gate does not claim TLC/Apalache evidence

    Final line:
      === Hegemon formal-core gate passed ===

Follow-up checks after adding the gate passed:

    node --check scripts/check-app-launch-autostart.mjs
    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run lint
    npm --prefix hegemon-app run package
    git diff --check -- scripts/check-app-launch-autostart.mjs hegemon-app/package.json .agent/PROD_READINESS_APP_CI_EXECPLAN.md
    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app

Production distribution remains fail-closed without Apple notarization credentials:

    npm --prefix hegemon-app run dist:prod
    result: rejected before build; missing APPLE_ID/APPLE_APP_SPECIFIC_PASSWORD/APPLE_TEAM_ID or APPLE_API_KEY/APPLE_API_KEY_ID/APPLE_API_ISSUER

Revision note, 2026-07-01 / Codex: wallet UX cleanup removed the debug-console feel from the wallet page. The wallet page now separates the page title from the store-access card, keeps the receiving shielded address in a compact identity row, exposes the full address only inside a bounded details block, truncates commitments/nullifiers/technical note fields with full values in titles, and constrains sync/send diagnostics in scrollable output boxes. Current visual/behavior evidence:

    Computer Use inspected the rebuilt packaged app overview and wallet routes.
    Wallet top viewport renders as Wallet / Shielded Store -> Store access without duplicate Shielded Store headings.
    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run lint
    npm --prefix hegemon-app run package
    npm --prefix hegemon-app run check:launch-autostart
    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app

Current rebuilt-app launch evidence after the wallet UX patch:

    version: Hegemon Native Node 0.10.0
    genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
    height/target: 1177/1177
    peers: 1
    syncing: false
    pending extrinsics: 0
    mining: true
    mining threads: 16
    rpc_external: false
    rpc_methods: unsafe
    rpc_listen_addr: 127.0.0.1:9955
    bootstrap_nodes: hegemon.pauli.group:30333

Revision note, 2026-07-01 / Codex: current-tree no-SSH app workflow gate passed again on release binaries after the Electron UX/autostart work. The gate used `walletd` automation, a native seed miner, a native app relay, local loopback RPC only, and P2P block/action propagation without public unsafe RPC. It covered wallet init/open/sync, relay join/sync, miner-wallet recovery through relay RPC, three small shielded sends, disclosure list/create/verify, recipient note consolidation, private multisig account/value-lock/setup/approval/final submit, recipient sync of the multisig final output, and same-store relay restart recovery.

    bash scripts/check-app-no-ssh-e2e.sh
    result: ok
    durationSeconds: 285
    runDir: /var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-xArRLB
    seedRpcPort: 60227
    relayRpcPort: 60229
    finalCommonHeight: 41
    seedPending: 0
    relayPending: 0
    minerSpendable: 20461598146
    recipientSpendable: 14999997
    restart commonHeight: 41
    restart seedPending: 0
    restart relayPending: 0
    restart minerSpendable: 20461598146
    restart recipientSpendable: 14999997

    smallTxs:
      0x6952928b9a531effb99630cc7b4d7132e3acbc4ebd36a6174349801275d14bef
      0x0abea6763ea7bd263d714dffcf4097cfbec4e4a60dcc9cee5f2e7db0960f2648
      0x580502141542da71fa7ffbe433497ba087d751ff27fdf64b988f384321c40365

    disclosure:
      txHash: 0x6952928b9a531effb99630cc7b4d7132e3acbc4ebd36a6174349801275d14bef
      outputIndex: 0
      commitment: 0x900952b1113190deb77947bad819ba0c2d116755ac96b0d4ffdf0be49624501a898170f269798186575faabdd94b29eb
      value: 10000000
      verified: true

    consolidation:
      txHash: 0x5b4b9183ced79f9f6d5128464d3dc62b78de22fe697ede0cacd444a90f351c76
      target: 20000001

    multisig:
      accountId: 0x8519013aa069d1ddd5e2a73332a58c66308c2b5d1d3586855a3ca3e30017d900
      valueLockTx: 0x88b110e09b68a862b77f79f71d89cb4a7dd97ff8e3b9a1dd45445d627a0536a5
      setupTx: 0x44bc4b4aa55bc75252cecad2476f5e92d60ff63bee26b2f88da7060277d29c95
      approvalTx: 0x2dd3ebc237d62202b9dda4168b4e6eacc1b3f56708e75943cfde887e8505b29c
      finalTx: 0x1f6363624f4fa4c9bc148512d5c98bb41599e274a9d63ae3be7ed3e32da77a68

Revision note, 2026-07-01 / Codex: the packaged app UI was tightened again after live inspection. Positive health/online state now uses Proof Green instead of the cyan action color, the wallet route opens with a live wallet-control strip that shows wallet state, online node state, chain state, loopback RPC posture, balance, wallet sync, sync lag, node height, and peer evidence before setup forms, and wallet diagnostics are collapsed behind a `walletd JSON` details panel. Computer Use inspected the rebuilt packaged overview and wallet routes; the wallet first viewport now shows `Shielded Store`, `Open wallet for native-devnet-host`, node height, one listed peer, loopback RPC, and the store-access workflow without the raw diagnostics block. Final validation bundle checks passed:

    npm --prefix hegemon-app run typecheck
    git diff --check
    npm --prefix hegemon-app run package
    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app
    npm --prefix hegemon-app run check:launch-autostart

Final rebuilt-app launch evidence:

    version: Hegemon Native Node 0.10.0
    genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
    height/target: 1206/1206
    peers: 1
    syncing: false
    pending extrinsics: 0
    mining: true
    mining threads: 16
    hash rate: 76022.82437921922 H/s
    rpc_external: false
    rpc_methods: unsafe
    rpc_listen_addr: 127.0.0.1:9955
    bootstrap_nodes: hegemon.pauli.group:30333

Revision note, 2026-07-01 / Codex: after the user reported the app still looked disconnected and rough, the packaged Electron UI was tightened again and revalidated live. The overview now makes the first-viewport verdict explicit with `native-devnet-host is live`, the approved seed, peer endpoint, local wallet RPC, unsafe/loopback policy, genesis, height, target, peer count, mining state, and hash rate. The wallet overview and wallet route no longer use `N/A` for a locked wallet; locked state is labeled as `Locked` / `Open wallet` while the node remains visibly live. Computer Use inspected the final packaged overview and confirmed the visible window showed live native-devnet-host state, wallet locked state, approved seed `hegemon.pauli.group:30333`, peer `51.222.86.107:30333`, and loopback RPC.

Final final-app validation checks passed:

    npm --prefix hegemon-app run typecheck
    git diff --check
    npm --prefix hegemon-app run package
    npm --prefix hegemon-app run check:launch-autostart

Final final rebuilt-app launch evidence:

    version: Hegemon Native Node 0.10.0
    genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
    height/target: 1251/1251
    peers: 1
    syncing: false
    pending extrinsics: 0
    mining: true
    mining threads: 16
    hash rate: 703132.8624497545 H/s
    rpc_external: false
    rpc_methods: unsafe
    rpc_listen_addr: 127.0.0.1:9955
    bootstrap_nodes: hegemon.pauli.group:30333

Revision note, 2026-07-01 / Codex: CI gate sweep continued on the current tree after the app live-UX work. The following broad gates completed successfully before native-path CI was resumed:

    ./scripts/check-core.sh lint
    result: ok

    ./scripts/dependency-audit-gate.sh
    result: ok
    findings: 8 total, 8 waived, 0 unwaived, 0 unused waivers
    waived advisories:
      RUSTSEC-2025-0141 bincode 1.3.3 until 2026-08-31
      RUSTSEC-2025-0057 fxhash 0.2.1 until 2026-08-31
      RUSTSEC-2024-0384 instant 0.1.13 until 2026-08-31
      RUSTSEC-2024-0436 paste 1.0.15 until 2026-08-31
      RUSTSEC-2026-0012 keccak 0.1.5 until 2026-08-31
      RUSTSEC-2026-0097 rand 0.8.5 until 2026-08-31
      RUSTSEC-2026-0097 rand 0.9.2 until 2026-08-31
      yanked:keccak:0.1.5 keccak 0.1.5 until 2026-08-31

    PROPTEST_CASES=64 ./scripts/check-core.sh test
    result: ok
    notable coverage:
      hegemon-node native library tests: 402 passed
      security_pipeline.rs: 1 passed

Revision note, 2026-07-01 / Codex: CI `native-path-tests` command block was run on the current tree after stopping the packaged app's local miner to free CPU. The command block exited successfully:

    cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads -- --nocapture
      result: ok, 1 passed, 0 failed, finished in 72.17s

    cargo test -p hegemon-node submit_action_stages_and_imports_shielded_transfer -- --nocapture
      result: ok, 1 passed, 0 failed

    cargo test -p hegemon-node coinbase_action_mints_shielded_output_and_updates_supply -- --nocapture
      result: ok, 1 passed, 0 failed

    cargo test -p consensus --test raw_active_mode raw_active_rejects_bad_tx_proof -- --ignored --nocapture
      result: ok, 1 passed, 0 failed, finished in 230.18s

    cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture
      result: ok, 2 passed, 0 failed, finished in 283.01s

    cargo test -p hegemon-node imported_block_actions_require_canonical_transfer_order -- --nocapture
      result: ok, 1 passed, 0 failed

    cargo test -p hegemon-node receipt_root -- --nocapture
      result: ok exit code from the CI command, but the filter matched 0 tests in `hegemon-node` on this tree. Do not treat this command as additional receipt-root behavioral coverage; the actual receipt-root coverage above came from the raw-active consensus target.

Revision note, 2026-07-01 / Codex: current-tree no-SSH app workflow passed again after the final live-connection UI polish. `./scripts/check-app-no-ssh-e2e.sh` completed in 134s with run dir `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-vOC8dE`, final common height 44, restart common height 44, seed pending 0, relay pending 0, miner spendable `21959885815`, recipient spendable `14999997`, and the same-store relay restart preserved both balances and empty pending queues. Covered transactions:

    small transfers:
      0x574cf1e0ae1aa5bf29bc772a7be95c49ab93bfc7c774b36475f732993eaca3e6
      0xe8077df1f680a7405045674fdb35265eb8d9b2f14eb880770da811f66cb0a5b3
      0x6cdcaad7146076fd41625eeed22ab64ecaee1e7a725a94e33956f764dddf8933
    disclosure:
      tx 0x574cf1e0ae1aa5bf29bc772a7be95c49ab93bfc7c774b36475f732993eaca3e6 output 0
      commitment 0x8058a8918ce248fb40125842a84fc5a8f48395846369efd40bd9abee4188892e5b3e5e378fb29b8eed977adfc197c81c
      value 10000000
      verified true
    consolidation:
      0x358a8727654332fcbf4c7adc25e253ca9a4722b9df3b4339b843a641c8dbf091
    transaction-tier private multisig:
      account 0x2e36632097942e152c67acc95b4247ae89872c92bb268ef04f130f8b06cb1d5d
      value-lock 0xc1952a8ede298b5d5348376070941f03434eff5936be74d923e421a5d3912441
      setup 0x3556f4cc35a1375732a600914cface51abb6d9d75300133616fcab73d7c3d456
      approval 0xb1d7b251a05c57ebc15a750d117b70a19bf08d16e0c77971fb5ed756874ed773
      final 0x4c343468f4d2416a34164214a4048f30971e713cf4b80569f2899e681512f81f

Revision note, 2026-07-01 / Codex: CI-mode proving red-team passed on the same current tree. Summary artifacts are in `output/proving-redteam/20260701T224009Z/summary.txt` and `summary.json`; overall `pass`. All eight campaigns passed: parser-malleability, semantic-aliasing, staged-proof-abuse, recursive-block-mismatch, receipt-root-tamper, prover-configuration-downgrade, network-transport-abuse, and review-package-parity.

Revision note, 2026-07-01 / Codex: native-backend-security CI job was re-run end to end on the current tree and passed. Evidence:

    cargo test -p superneo-backend-lattice -p native-backend-ref -p superneo-hegemon -p superneo-bench
      result: ok
      superneo-hegemon: 49 passed, 0 failed, 3 expected slow-profile ignored

    cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
      result: ok, 11 passed, 0 failed

    cargo run -p native-backend-timing --release
      result: ok
      sample_count: 64
      welch_t_statistic: -0.7933032870503071
      relative_mean_delta: 0.006877989081954936
      relative_median_delta: 0.0001949204808879016
      relative_delta_threshold: 0.25

    bash scripts/verify_native_receipt_root_scalability.sh
      result: ok
      leaf_count: 128
      block_count: 1024
      hierarchy_nodes_touched: 7
      epoch_nodes_touched: 10

    cargo +nightly-2026-06-23 fuzz run native_tx_leaf_artifact -- -max_total_time=30
      result: ok, 1717187 runs in 31s

    cargo +nightly-2026-06-23 fuzz run receipt_root_artifact -- -max_total_time=30
      result: ok, 1767549 runs in 31s

    ./scripts/package_native_backend_review.sh
      result: ok
      package sha256: e2edd85b47f8773909234c23f74d549fbb6769e452d7985dc52d59b5c1df9b31

    ./scripts/verify_native_backend_review_package.sh
      result: ok
      packaged vectors: 11 passed, 0 failed
      packaged claim verification: passed

    ./scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz
      result: ok
      posture: candidate_under_review / structural_candidate

Revision note, 2026-07-01 / Codex: release build and binary PQ audit passed after the native-backend-security job regenerated the review package:

    ./scripts/check-core.sh build
      result: ok

    ./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd
      result: ok
      source scan: clean for forbidden ECC/RSA/pairing/trusted-setup patterns
      Cargo.lock scan: no forbidden ECC/RSA/pairing/trusted-setup crates
      release binary symbol scan: no forbidden ECC symbols in hegemon-node, wallet, or walletd
      approved primitives: Blake3, ML-KEM, ML-DSA, SLH-DSA, STARK/FRI, Poseidon

Revision note, 2026-07-01 / Codex: final live packaged-app state after CI CPU throttling was restored. The running packaged app's managed node on `http://127.0.0.1:9955` reports height `1297`, sync target `1297`, `syncing:false`, one peer, best hash `0x00000008340f9b56161f38d3c69dcbec1352cc82a4ce57b1a5b24f4cb0066329`, supply digest `647759713231`, mining sync gate open, `is_mining:true`, `blocks_found:3`, `threads:16`, and hash rate `287135.7698725299 H/s`. Mining was intentionally stopped during heavy CI to avoid starving tests and was restarted with `hegemon_startMining` after the gates passed.

Revision note, 2026-07-01 / Codex: full formal-core was re-run after the regenerated native backend review package and final app live-connection polish. `bash scripts/check_formal_core.sh` passed end to end with the explicit final line `=== Hegemon formal-core gate passed ===`. Notable current-tree evidence: 125 checker tests passed; Lean proof kernel and axiom audit passed with 2,604 named theorem symbols, 1,148 axiom-free theorems, 0 temporary axiom families, 0 temporary axiom theorems, and 0 unwaived axiom dependencies; generated Rust conformance vectors passed; formal inventory passed; system-model fail-closed gates passed for 6 gates and 20 evidence paths; active-goal progress gate passed at 100%; claims ledger passed with 122 claims, 122 Lean-theorem claims, 112 production-eligible claims, and 50 residual risks; blueprint DAG passed with 122 nodes, 524 edges, 647 falsification cases, 236 implementation bindings, 179 implementation result obligations, 154 implementation order constraints, and 139 implementation dominance constraints; independent bridge vectors passed 2/2; native backend reference vectors passed 11/11; native backend release posture remained `candidate_under_review / structural_candidate`. Model-checker execution was not requested, and the gate explicitly did not claim TLC/Apalache evidence.

Revision note, 2026-07-01 / Codex: current packaged app bundle was rebuilt and relaunched after the formal-core run. Validation passed:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run lint
      result: ok

    npm --prefix hegemon-app run package
      result: ok
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app
      result: ok

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1314/1313
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 16
      hash rate: 957853.7083712433 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

Computer Use inspected the relaunched packaged Overview route after autostart. The visible first viewport showed `native-devnet-host is live`, height `1,314`, target `1,313`, one peer `51.222.86.107:30333`, mining `Active`, hash rate `1.53 MH/s`, local RPC `ws://127.0.0.1:9955`, RPC policy `unsafe / loopback`, seed `hegemon.pauli.group:30333`, genesis `0x506fc2cd...a1e6fa59`, and wallet state `Locked` with `Open wallet` guidance instead of `N/A`.

Revision note, 2026-07-02T00:13:15Z / Codex: current-tree dependency, lint, and broad core-test gates passed after the packaged app live-connection rebuild:

    ./scripts/dependency-audit-gate.sh
      result: ok
      findings: 8 total, 8 waived, 0 unwaived, 0 unused waivers
      waived advisories: RUSTSEC-2025-0141 bincode 1.3.3; RUSTSEC-2025-0057 fxhash 0.2.1; RUSTSEC-2024-0384 instant 0.1.13; RUSTSEC-2024-0436 paste 1.0.15; RUSTSEC-2026-0012 keccak 0.1.5; RUSTSEC-2026-0097 rand 0.8.5; RUSTSEC-2026-0097 rand 0.9.2; yanked keccak 0.1.5

    ./scripts/check-core.sh lint
      result: ok
      coverage: cargo fmt, native startup policy, and clippy gates passed

    PROPTEST_CASES=64 ./scripts/check-core.sh test
      result: ok
      coverage: synthetic crypto, consensus-light-client, consensus, transaction-circuit, block-circuit, disclosure-circuit, network, protocol-kernel, protocol-shielded-pool, wallet, cashvm-bridge, hegemon-node with default features, hegemon-node without default features, and security_pipeline
      wallet evidence: 120 unit tests passed; CLI/disclosure/memo/RPC/wire-vector integrations passed; doc tests passed/ignored as expected
      node evidence: 402 native node tests passed, including seed-gated mining, sync admission, RPC resource caps, unsafe RPC policy gates, fork choice, PoW retarget, wallet archive RPCs, and Lean-generated native vectors
      security pipeline: end_to_end_adversarial_flow passed

Live packaged-app mining was stopped only during the heavy local CI run to avoid starving the test host, then restarted on the same managed node with `hegemon_startMining` using 16 threads. Immediate restart evidence: height `1327`, sync target `1327`, `syncing:false`, one peer, `is_mining:true`, mining sync gate open, `threads:16`, `blocks_found:3`, difficulty `487666588`, hash rate `422978.6871938576 H/s`. A delayed follow-up after 35 seconds reported height `1330`, sync target `1330`, `syncing:false`, one peer, best hash `0x000000158c5ac28ac4ed9222297afe2cfa85d00e4ef53e350faada75a13f5c5a`, supply digest `664240877590`, `is_mining:true`, mining sync gate open, `threads:16`, `blocks_found:5`, difficulty `488546665`, and hash rate `588304.399899784 H/s`.

Revision note, 2026-07-02T00:21:54Z / Codex: after visual inspection of the rebuilt packaged Overview window, the app status rail was tightened for production readability. The rail no longer forces network, mining, wallet, seed, and peer context into a cramped single desktop row at normal app widths; it stacks until a true wide viewport is available while keeping the four core metrics in a stable grid. This keeps the live native-devnet-host state legible without hiding the approved seed or wallet control-plane context behind ellipses.

Validation passed after the layout patch:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run package
      result: ok
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app
      result: ok

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1340/1340
      peers: 1
      syncing: false
      pending extrinsics at launch snapshot: 3
      mining: true
      mining threads: 16
      hash rate: 249981.62941035433 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

The three pending actions in the launch snapshot were verified as transient mined work, not a stuck mempool: a follow-up watch started at height `1340` with pending `3`, then the restarted miner advanced to height `1341` with target `1341`, `syncing:false`, one peer, `is_mining:true`, `blocks_found:1`, hash rate about `2.09 MH/s`, and pending `0`. Computer Use inspected the relaunched rebuilt app afterward; the first viewport showed `native-devnet-host is live`, height `1,341`, target `1,341`, one peer, mining `Active`, hash rate `2.12 MH/s`, pending `0`, loopback RPC, the approved seed `hegemon.pauli.group:30333`, and wallet state `Locked`.

Revision note, 2026-07-02T00:28:49Z / Codex: the no-SSH app transaction workflow was re-run after the packaged-app rebuild and status-rail fix. `./scripts/check-app-no-ssh-e2e.sh` passed in 310s with isolated native `--dev` seed and relay nodes, no legacy JSON chain spec, and no `--chain` flag. Run dir: `/var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-RVOVwB`. Final common height `44`, seed pending `0`, relay pending `0`, miner spendable `21959885815`, recipient spendable `14999997`. Relay restart rejoined at common height `44` with seed pending `0`, relay pending `0`, miner spendable `21959885815`, and recipient spendable `14999997`.

    small no-SSH transfers:
      0xc76354892814aaf8aaf1f9523ff21b0db8b9d688ff400b327884003e959e9ea1
      0x5671dbc2b9bfffd1bec2b2a927bd97bb65d9df80fb16a05ba769d6fdb5c10b3a
      0xb4288360933f96afa14d0e8fe4a6f7a09cd8ca29517c2bc5de1b483e14b34d93
    disclosure:
      tx 0xc76354892814aaf8aaf1f9523ff21b0db8b9d688ff400b327884003e959e9ea1 output 0
      commitment 0x81c2e97e8bf0537e6b9766efab65a93705410b0fc8821edffd913b655e40cb4900738fd7fab5e5be43c6df0e8628b08d
      value 10000000
      verified true
    consolidation:
      0xe19c556bddd1732bfb6f0a5c2c234a1b1345758f15986866164fcbfbe82521f6
      target 20000001
    transaction-tier private multisig:
      account 0x7bb11959ef7c8bde9c725eb9936640ebb8576b9db441911d61c980c6d823be1a
      value-lock 0x067e0700a5f28a9660aa39ae7b40a8724379e92389690df897079acee523e11e
      setup 0xc1f535294414c340b64fa771c10aaa8f5770aa536ceafc59efb682d8fc1e6344
      approval 0x48e1a8db9064d850464643ec460af3333c62b814cf3d833c95cc402216178e49
      final 0x662431368e813d1f8b47fb3ffc011e1c03ea735ee15d92130d5985c786802ce8

The live packaged app node remained healthy after the isolated e2e run: `hegemon_consensusStatus` reported height `1350`, sync target `1349`, `syncing:false`, one peer, pending pool `[]`, best hash `0x000000023b5927d449a6ba776f17fa635abe70e6b4c37375ab72f6263dfac0de`, supply digest `674229462050`; `hegemon_miningStatus` reported `is_mining:true`, mining sync gate open, `threads:16`, `blocks_found:4`, difficulty `487512279`, next difficulty `487512279`, and hash rate `2652043.2958400883 H/s`.

Revision note, 2026-07-02T00:31:26Z / Codex: release-binary native devnet liveness was re-run to prove the post-retarget/mining path is not height-jammed. Desktop mining was paused only during this isolated test to avoid CPU starvation, then restarted with 16 threads. Command:

    HEGEMON_NODE_BIN="$PWD/target/release/hegemon-node" HEGEMON_TEST_TIMEOUT_SECS=240 HEGEMON_TEST_LIVENESS_MIN_BLOCKS=12 ./scripts/test-node.sh devnet-liveness
      result: ok
      startup: native follower on RPC 19946/P2P 31334; native miner on RPC 19945/P2P 31333
      initial sync: miner height 2, follower height 16
      liveness window: miner_start 17, miner 29, follower 29, produced 12, elapsed 22s, max_gap 2s
      miner: threads 1, hash_rate 1876474.5384818863 H/s, pending 0

After the isolated liveness gate, the packaged app's managed node was restored to mining and rechecked: height `1352`, sync target `1352`, `syncing:false`, one peer, pending pool `[]`, `is_mining:true`, mining sync gate open, `threads:16`, difficulty `487512279`, next difficulty `487512279`, hash rate `2569179.583136032 H/s`.

Revision note, 2026-07-02T00:34:08Z / Codex: release-binary restart/catch-up and SIGTERM durability gates were re-run. Desktop mining was paused only during the isolated gates, then restored. Evidence:

    HEGEMON_NODE_BIN="$PWD/target/release/hegemon-node" HEGEMON_TEST_TIMEOUT_SECS=240 ./scripts/test-node.sh two-node-restart
      result: ok
      startup: native follower on RPC 19946/P2P 31334; native miner on RPC 19945/P2P 31333
      follower reached height 16 before restart
      restarted follower on RPC 19946/P2P 31334
      restart catch-up: miner height 23, follower height 20

    HEGEMON_NODE_BIN="$PWD/target/release/hegemon-node" HEGEMON_TEST_TIMEOUT_SECS=120 ./scripts/test-node.sh sigterm-shutdown
      result: ok
      startup: native node for SIGTERM shutdown smoke on RPC 19947
      shutdown path flushed through the `shutdown_flush` durability barrier

After both isolated gates, the packaged app's managed node was restored to mining and rechecked: height `1355`, sync target `1355`, `syncing:false`, one peer, pending pool `[]`, best hash `0x000000073a72839cc1dacad0be537c3f906915b613cb310ffe85c0354aa1ce09`, supply digest `676726608165`, `is_mining:true`, mining sync gate open, `threads:16`, difficulty `487512279`, next difficulty `487512279`, and hash rate `2508379.0854610954 H/s`.

Revision note, 2026-07-02T00:46:05Z / Codex: the packaged Electron app was rebuilt and visually re-inspected after the live-connection UX pass. Two release-surface defects were fixed: startup summary races no longer paint a false `target 0` / `Mining gated` state when the local node already has a live peer and nonzero height, and legacy address-book entries marked `0.9.1`, `hegemon-ovh`, or `legacy` are disabled in the send selector until recreated or reverified on Hegemon 0.10. New contacts now carry chain/protocol metadata when added from the live app.

Validation passed after the latest app patch:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run package
      result: ok
      renderer asset: index-P0c0KXNG.js
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app
      result: ok

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1370/1370
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 16
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

Computer Use inspected the freshly relaunched packaged app immediately after autostart. The first Overview paint showed `native-devnet-host is live`, height `1,370`, target `1,370`, one peer `51.222.86.107:30333`, mining `Active`, `Healthy`, local RPC `ws://127.0.0.1:9955`, RPC policy `unsafe / loopback`, approved seed `hegemon.pauli.group:30333`, and wallet state `Locked`. The Send route showed live chain preflight at node height `1,370`, pending pool `0`, disabled send while locked, and both old `0.9.1` contacts disabled in the selector with `(legacy; recreate for 0.10)`. The Wallet route showed node height `1,370`, peer detail, seed, and loopback wallet RPC. The Node route showed mining node config on `9955/30334`, seed `hegemon.pauli.group:30333`, `Syncing: No`, target `1,370`, sync gate `Open`, mining `Active`, hash rate about `3.68 MH/s`, and pending pool `0`.

Revision note, 2026-07-02T01:30:00Z / Codex: after the user reported the packaged app still looked rough and disconnected, the live Overview surface was tightened again and revalidated from the installed Electron bundle. The app now opens with `Live on native-devnet-host`, shorter navigation copy, `Desktop node` branding instead of console copy, a Proof Green live rail/verdict, reduced bordered-box density, tabular sans height telemetry, and a direct statement that the local loopback node is synced through `hegemon.pauli.group:30333` while wallet traffic stays on this laptop. The connection state is still sourced from live node summary/RPC, not static labels.

Validation passed after the final Overview polish:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run check:ui-guards
      result: ok
      coverage: legacy 0.9/0.9.1 contact warning, 0.10 contact allow, startup target-0/mining-gate race suppression, real mining-gate warning, and offline/error state

    bash scripts/check_formal_core.sh
      result: ok
      final line: === Hegemon formal-core gate passed ===
      Lean theorem symbols: 2605
      axiom audit: 0 temporary axiom families, 0 temporary axiom theorems, 0 unwaived axiom dependencies
      claims ledger: 122 claims, 112 production eligible, 50 residual risks
      native backend vectors: 11/11 passed
      native backend posture: candidate_under_review / structural_candidate

    npm --prefix hegemon-app run package
      result: ok
      renderer assets: index-B_u1m0mV.css, index-D6uGjJT-.js
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    codesign --verify --deep --strict hegemon-app/dist/mac-arm64/Hegemon.app
      result: ok

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1404/1404
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 16
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

Computer Use inspected the relaunched packaged Overview route after autostart. The visible first viewport showed `Live on native-devnet-host`, height `1,404`, target `1,404`, one peer `51.222.86.107:30333`, mining `Active`, hash rate `1.55 MH/s`, local RPC `ws://127.0.0.1:9955`, RPC policy `unsafe / loopback`, approved seed `hegemon.pauli.group:30333`, genesis `0x506fc2cd...a1e6fa59`, wallet state `Locked`, and no SSH/public-RPC dependency.

Revision note, 2026-07-02T01:35:31Z / Codex: the app/no-SSH CI workflow was re-run after the final packaged-app Overview polish and UI guard policy wiring. The release policy checker also passed against generated Lean vectors, the PR/main CI workflow, the tag-release workflow, and the branch-protection ruleset:

    tmp=$(mktemp -t hegemon-ci-release-vectors); cd formal/lean && lake exe gen_ci_release_gate_vectors > "$tmp" && cd ../.. && scripts/check_ci_release_gate_policy.py "$tmp" --ci-workflow .github/workflows/ci.yml --release-workflow .github/workflows/release.yml --ruleset-export .github/rulesets/hegemon-release-required-checks.json
      result: ok
      ci release gate vectors: 19 cases passed
      ci workflow release-build gate: passed
      tag release workflow gate: passed
      branch protection ruleset gate: passed

    ./scripts/check-app-no-ssh-e2e.sh
      result: ok
      duration: 245s
      run dir: /var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-vfIgXo
      final common height: 40
      seed pending: 0
      relay pending: 0
      miner spendable: 19962168923
      recipient spendable: 14999997
      restart common height: 40
      restart pending: seed 0, relay 0

    small no-SSH transfers:
      0x09f22459a13b2b3cbce4bb39ed9d02f5e91ce2922550b9dddb13bfa0802b6548
      0x8c4898d0bd096c3abf6f86162349d306cbc1cfb473b2468c5a7096d50165ef80
      0xe38f810c579cb20816c78c3f3c5098def489b99ab04bee561d14e3b4ed916d92
    disclosure:
      tx 0x09f22459a13b2b3cbce4bb39ed9d02f5e91ce2922550b9dddb13bfa0802b6548 output 0
      commitment 0x278b22cbdcd4f1d5f90929a57228c542d3c721cb597ba3921f2cc04dbeaf88f06301787488c2b376979b1d5b935f7522
      value 10000000
      verified true
    consolidation:
      0x574836b689a376649f11ea2f8564afd1daf0985b3f06f9fd1deb828f73739b9e
      target 20000001
    transaction-tier private multisig:
      account 0xcb6d97a3441500817323bf0b5809d1fb0b20021d48e651b92ed1704c470bfee1
      value-lock 0x854bd4dca17f41eec7f6c5e0708137e7acb0426c90f4dfdab9798e22dbdd16d6
      setup 0x77ef3ea4601bc97daeb45acc7c0e2d3c1494bfdcb441df984ebf34acf42fd21c
      approval 0x8c68a7fe92d51a5cdb14076e6827f8c2042524cf635dbd32177275b000d8e7c6
      final 0x0820f209f0d5eb6cc12919f0199c3fd4e065165ac7d36eb689759e6d45feed08

Follow-up cheap gates passed:

    npm --prefix hegemon-app run lint
      result: ok

    ./scripts/dependency-audit-gate.sh
      result: ok
      findings: 8 total, 8 waived, 0 unwaived, 0 unused waivers

    cargo fmt --all --check
      result: ok

    ./scripts/check-core.sh lint
      result: ok
      coverage: native startup policy and clippy/lint gates passed; vendor plonky3 warning output remains non-fatal

The live packaged app node remained healthy after the isolated no-SSH workflow: `hegemon_consensusStatus` on `http://127.0.0.1:9955` reported height `1411`, sync target `1411`, `syncing:false`, one peer, pending pool `[]`, best hash `0x00000005be7d609707230f7e9bcf9de3d96a5ae39314e52c357c17b997ca8358`, and supply digest `704694644653`; `hegemon_miningStatus` reported `is_mining:true`, mining sync gate open, `threads:16`, `blocks_found:6`, difficulty `487114189`, next difficulty `487114189`, and hash rate `3261376.619619167 H/s`.

Production macOS packaging remains fail-closed without Apple credentials, as intended:

    npm --prefix hegemon-app run dist:prod
      result: expected failure before build
      reason: missing Apple notarization credentials
      message: Production macOS releases require Apple notarization credentials. Set APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID, or APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER.

Revision note, 2026-07-02T02:27:50Z / Codex: after the user reported the app still looked ugly and not live-connected, the packaged app was tightened again around the live 0.10 desktop contract. Node advanced local settings now stay collapsed by default, Node internals are behind a details panel, Console key events use width-stable rows, ISO log timestamps are parsed into the time column, duplicated severity/timestamp prefixes are removed from messages, and routine peer-dial retry noise is no longer promoted as key events or errors while the node is healthy. The visible Overview/Node/Wallet/Send/Disclosure/Console routes were inspected through Computer Use from the packaged app bundle after relaunch.

Validation passed after this UI/live-connection pass:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run check:ui-guards
      result: ok

    npm --prefix hegemon-app run lint
      result: ok

    npm --prefix hegemon-app run package
      result: ok
      renderer assets: index-UzByt8rY.css, index-CY9-SMlR.js
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1452/1452
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 4
      hash_rate: 333775.40604802984 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

    git diff --check
      result: ok

2026-07-02T04:07:19Z icon polish revision:
  Replaced the remaining generic empty-state pictograms with a local Hegemon
  line-icon set for terminal logs, transaction activity, contacts, and
  disclosures. The Send activity empty state now uses a clean bidirectional
  transfer mark instead of the old circular clock-like placeholder.

  validation:
    npm --prefix hegemon-app run typecheck
      result: ok
    npm --prefix hegemon-app run check:ui-guards
      result: ok
    npm --prefix hegemon-app run lint
      result: ok
    npm --prefix hegemon-app run build && npm --prefix hegemon-app run package
      result: ok
      packaged app: hegemon-app/dist/mac-arm64/Hegemon.app
      note: local ad-hoc signing succeeded; Apple notarization remains gated by
        release credentials
    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      native-devnet-host: height 1548, target 1548, peers 1, syncing false,
        pending 0, mining true, loopback RPC, seed hegemon.pauli.group:30333
    git diff --check
      result: ok

2026-07-02T04:17:56Z status-rail revision:
  Moved duplicated wallet/node status out of the top status bar and into the
  left navigation rail. Overview carries live/peer context, Node carries synced
  height, Wallet carries lock state plus loopback connection, and Send carries
  transfer readiness. Disclosure and Console stay quiet unless they have records
  or errors.

  validation:
    npm --prefix hegemon-app run lint
      result: ok
    npm --prefix hegemon-app run check:ui-guards
      result: ok
    npm --prefix hegemon-app run build && npm --prefix hegemon-app run package
      result: ok
      packaged app: hegemon-app/dist/mac-arm64/Hegemon.app
      note: local ad-hoc signing succeeded; Apple notarization remains gated by
        release credentials
    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      native-devnet-host: height 1554, target 1554, peers 1, syncing false,
        pending 0, mining true, loopback RPC, seed hegemon.pauli.group:30333
    computer-use packaged visual pass
      result: ok
      observed: top bar no longer renders wallet lock/online duplicates; sidebar
        shows Overview LIVE, Node SYNCED, Wallet LOCKED, Send IDLE

2026-07-02T04:25:22Z top-bar removal and dev seed correction:
  Removed the persistent top bar after moving status into the navigation rail.
  Rotated app-managed 0.10 dev seed defaults and launch validation from the
  ambiguous legacy-looking hegemon.pauli.group hostname to
  devnet.hegemonprotocol.com:30333, while keeping legacy host/IP values as
  migration aliases. Updated operator docs and helper scripts to use the same
  approved 0.10 dev seed.

  live identity evidence:
    system_version: Hegemon Native Node 0.10.0
    chainSpecId: hegemon-native-dev
    chainSpecName: Hegemon Native Dev
    genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
    connected peer: 51.222.86.107:30333

  validation:
    npm --prefix hegemon-app run lint
      result: ok
    npm --prefix hegemon-app run check:ui-guards
      result: ok
    npm --prefix hegemon-app run build && npm --prefix hegemon-app run package
      result: ok
      packaged app: hegemon-app/dist/mac-arm64/Hegemon.app
      note: local ad-hoc signing succeeded; Apple notarization remains gated by
        release credentials
    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      native-devnet-host: height 1560, target 1560, peers 1, syncing false,
        pending 0, mining true, loopback RPC,
        seed devnet.hegemonprotocol.com:30333
    computer-use packaged visual pass
      result: ok
      observed: persistent top bar removed; Overview names Hegemon Native Dev
        instead of foregrounding a seed hostname

2026-07-02T04:38:19Z wallet disclosure-cue and sync-panel revision:
  Added visible plus/minus disclosure cues to expandable panels so clickable
  summaries read as expandable controls. Added a direct Wallet Sync action to
  the wallet KPI tile, using the existing wallet sync/cancel path and enabling
  only when the wallet session is ready.

  validation:
    npm --prefix hegemon-app run lint
      result: ok
    npm --prefix hegemon-app run check:ui-guards
      result: ok
    npm --prefix hegemon-app run build && npm --prefix hegemon-app run package
      result: ok
      packaged app: hegemon-app/dist/mac-arm64/Hegemon.app
      note: local ad-hoc signing succeeded; Apple notarization remains gated by
        release credentials
    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      native-devnet-host: height 1569, target 1569, peers 1, syncing false,
        pending 0, mining true, loopback RPC,
        seed devnet.hegemonprotocol.com:30333
    computer-use packaged visual pass
      result: ok
      observed: Store/session, Connection evidence, and All Notes show
        disclosure cues; Wallet Sync tile exposes a direct Sync action

Revision note, 2026-07-02T03:57:31Z / Codex: the Node, Wallet, and Send tabs were refined around the primary operator flow. Node now opens on the current live node, start/stop action, health, role, height, peers, mining, and storage; profile editing and local node settings are collapsed under `Connection settings`, while internals stay behind `Node internals`. Wallet no longer shows the live-summary hero plus duplicate controls; the store/session block is a disclosure that stays open only while the wallet is locked, and ready-wallet users land on balance, sync, receiving address, notes, and balances. Send now opens with the transfer form and activity side by side; wallet/chain/note context is reduced to a compact strip, and full preflight plus contacts are collapsed below the main workflow.

Current app UX validation:

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run check:ui-guards
      result: ok

    npm --prefix hegemon-app run build
      result: ok
      renderer assets: index-DIge9Zl-.css, index-wKu1-gJs.js

    npm --prefix hegemon-app run package
      result: ok
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1532/1532
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 4
      hash_rate: 671890.9315235136 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

    npm --prefix hegemon-app run lint
      result: ok

    git diff --check
      result: ok

Computer Use inspected the rebuilt packaged app after autostart. Overview remained live and clean. Node showed the current node first with `Healthy`, `Loopback RPC`, height `1,532`, one peer, mining active, and collapsed `Connection settings`. Wallet showed the locked open/create flow first, with funds and diagnostics below. Send showed the transfer form and activity first, with compact wallet/sync/note/pending context and collapsed preflight/contacts.

    live RPC recheck on http://127.0.0.1:9955
      result: ok
      height/target: 1453/1453
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining_sync_gate_open: true
      mining threads: 4
      hash_rate: 2912158.5293705277 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

Revision note, 2026-07-02T03:45:47Z / Codex: the packaged app Overview was tightened again after live inspection. The overview now distinguishes local tip from peer target, treats a locally mining node that is ahead of the last peer target as healthy rather than a target mismatch, collapses RPC/seed/genesis evidence behind a disclosure, and uses a smaller first-viewport command layout. The display-state helper now exposes `heightDelta` and `heightRelation`, and the UI guard covers the local-miner-ahead case.

Current packaged app verification:

    npm --prefix hegemon-app run check:ui-guards
      result: ok

    npm --prefix hegemon-app run typecheck
      result: ok

    npm --prefix hegemon-app run build
      result: ok
      renderer assets: index-DP5X_QDI.css, index-CCF1sUy-.js

    npm --prefix hegemon-app run package
      result: ok
      note: ad-hoc local signing succeeded; Apple notarization was intentionally skipped because production credentials are not present

    npm --prefix hegemon-app run dist:prod
      result: expected failure before build
      reason: missing Apple notarization credentials
      message: Production macOS releases require Apple notarization credentials. Set APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID, or APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER.

    npm --prefix hegemon-app run check:launch-autostart
      result: ok
      version: Hegemon Native Node 0.10.0
      genesis: 0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59
      height/target: 1517/1517
      peers: 1
      syncing: false
      pending extrinsics: 0
      mining: true
      mining threads: 4
      hash_rate: 79530.14241707273 H/s
      rpc_external: false
      rpc_methods: unsafe
      rpc_listen_addr: 127.0.0.1:9955
      bootstrap_nodes: hegemon.pauli.group:30333

Computer Use inspected the relaunched packaged Overview route after the rebuild. The visible first viewport showed `Live on native-devnet-host`, `In sync`, local height `1,517`, peer target `1,517`, `1` peer, mining `Active`, hash rate `257 KH/s`, `Loopback RPC`, and collapsed `Connection evidence` reading `Peer, seed, and genesis verified`.

Current app/no-SSH transaction workflow:

    ./scripts/check-app-no-ssh-e2e.sh
      result: ok
      duration: 184s
      run dir: /var/folders/kk/bqmmc1794slcsjl913bdkqvm0000gn/T/hegemon-no-ssh-e2e-sIwfol
      final common height: 44
      seed pending: 0
      relay pending: 0
      miner spendable: 21959885815
      recipient spendable: 14999997
      restart common height: 44
      restart pending: seed 0, relay 0

    small no-SSH transfers:
      0x0c356ca6f717f71623e2d339f7f1e2838ff934f3c1782171fa49065fa7d32d06
      0x3400a5466e722c1cd1a7d156987b61b9c8a1f2b2d51292c4c8e871bb2b04dba4
      0xa4f3c12581b9f73ab505aebef0a4888b774236731c77f44c9d6e1ef4ee2eb84e
    disclosure:
      tx 0x0c356ca6f717f71623e2d339f7f1e2838ff934f3c1782171fa49065fa7d32d06 output 0
      commitment 0x37a0661c28722c5b1a1f7d4221207e3adea35a7117c54a7eda991a69d88c1fbfe66b0f976a870ead04ab00ad431f3ecc
      value 10000000
      verified true
    consolidation:
      0x081f7737525aecd11e1633393211040227c60d68c1ec7b063899e58213b725f9
      target 20000001
    transaction-tier private multisig:
      account 0xeded5571be07b3eda18a3101d7cfde1a9a7959d0be5a81958c1e027374ea6d9c
      value-lock 0xaa47a915662cf9a256e354997518c105cd9ebd2500055cf3e3afbcb232b4c2dd
      setup 0x56c02b1aa28ddf193f2f0608c6505a91204ca68f27acc6eccb839af57680de8d
      approval 0x0b8adf8c1d18592c1c1d351131c44819e0d551834e9d667249881f0f7b6482f3
      final 0x144804e0d4df8b8aefc04ac41e1aab21710cc45d392200c341617794b5ed4813

Current monorepo release gates:

    cargo fmt --all --check
      result: ok

    ./scripts/dependency-audit-gate.sh
      result: ok
      findings: 8 total, 8 waived, 0 unwaived, 0 unused waivers

    ./scripts/check-core.sh lint
      result: ok

    ./scripts/check-core.sh test
      result: ok
      coverage: synthetic-crypto, consensus-light-client, consensus, transaction-circuit, block/disclosure, network, protocol-kernel, protocol-shielded-pool, wallet, cashvm-bridge, hegemon-node with default and no-default features, and security_pipeline all passed

    ./scripts/check-core.sh build
      result: ok
      coverage: release hegemon-node, wallet, and walletd build passed

    shipped native path focused tests
      result: ok
      covered wallet native tx-leaf emission, node shielded transfer import, coinbase shielded mint/supply, raw-active bad-proof rejection, raw-active receipt-root cases, imported block action ordering, and receipt-root filter command

    bash scripts/check_formal_core.sh
      result: ok
      Lean kernel/build: passed
      axiom audit: 2605 theorems, 0 temporary axiom theorems, 0 budget violations
      system-model gates: 6 gates, 20 evidence paths, passed
      active goal progress gate: 18/18 matrix properties, 100.0 percent, passed
      formal claims ledger: 122 claims, 122 Lean theorem claims, 112 production eligible, passed
      blueprint DAG: 122 nodes, 524 edges, 647 falsification cases, passed
      independent bridge vectors: 2 cases passed
      native backend reference vectors: 11 cases, 11 passed
      native backend release posture: candidate_under_review / structural_candidate
      model checker: not requested; no TLC/Apalache evidence claimed

    ./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node --binary target/release/wallet --binary target/release/walletd
      result: ok
      source scan: clean for forbidden classical primitives
      Cargo.lock scan: clean for forbidden classical crypto dependencies
      binary scan: hegemon-node, wallet, and walletd clean for forbidden ECC symbols
      approved primitives present: Blake3, ML-KEM, ML-DSA, SLH-DSA, STARK/FRI, Poseidon

    native backend release lane
      result: ok
      cargo test -p superneo-backend-lattice -p native-backend-ref -p superneo-hegemon -p superneo-bench: ok
      native-backend-ref verify-vectors testdata/native_backend_vectors: 11 cases, 11 passed
      native-backend-timing: pass true, sample_count 64, relative_mean_delta 0.0036908035100759232, relative_median_delta 0.0029966603647687863
      check_native_backend_release_posture: candidate_under_review / structural_candidate

    git diff --check
      result: ok
