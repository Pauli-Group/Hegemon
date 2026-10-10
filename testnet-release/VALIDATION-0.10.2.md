# v0.10.2 correction preparation validation

Validated on 2026-10-10 UTC, based solely on v0.10.1 commit `89a61f3b341f37dc26d0fc5190ce4571336255e8`. The activation constant is `None`: this is an unpublished preparation, and its binary still validates the historical rule everywhere.

The changed retarget policy has thirteen scoped Lean theorems and twelve activation vectors, alongside thirty-seven preserved legacy vector cases. Rust consensus conformance passed against the generated file. The light-client conformance test also parsed and checked the shared vector file; the light client consumes supplied expected bits and does not independently derive timing history.

The three new consensus regressions pass, including all 145 historical adjustments sampled from OVH. Five new native regressions pass: canonical/work/status/announced import, missing or incorrect tenth ancestor, sync across old and new boundaries, winning-side reorganization, and actual mined import followed by reopening under the same activation policy. The old policy rejects a database containing the simulated corrected boundary. Eight existing native scheduling regressions and the existing retarget-crossing tip-sync regression also pass.

The local `make node` release build passed and RPC reports `Hegemon Native Node 0.10.2`. An isolated two-process liveness run produced fifteen blocks in eight seconds, with miner and follower both at height eighteen and maximum observed gap two seconds. This validates production sealing/transport/sync under the inactive candidate rule; it does not constitute live-network activation evidence.

A disposable relay with mining disabled reached height 768 (832 by the subsequent mining-status poll), with three peers, passed genesis verification, and matched OVH at height 640:

    0x00000002410e79c5058dbee8e67c606d300ebd47e691d62bfdced59406fc382f

That bounded compatibility check demonstrates progress beyond the old 256/512-block stall. It does not claim catch-up to the full live tip. The relay exited cleanly with status zero. Raw logs and report are under `/private/tmp/hegemon-0102-relay-check/`.

The source-bound blueprint and claim checks pass. All 123 independent-review statuses remain pending, unchanged from the maintenance baseline. Only computed binding hashes were refreshed; no review approval was fabricated. Dependency exception bytes and expiry dates are unchanged. Packaging manifest negative checks, eleven download-package tests, seven launcher tests, Bash syntax and scoped diff checks pass. Windows launcher execution and cross-platform artifacts remain final-release gates.

## Reproduce the scoped checks

Use the candidate worktree and an isolated Cargo target directory. The preparation used `CARGO_TARGET_DIR=/private/tmp/hegemon-0102-build`, `CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_DEV_DEBUG=0`, and `CARGO_PROFILE_TEST_DEBUG=0`.

    cargo test -p consensus --locked --lib retarget_activation
    HEGEMON_LEAN_POW_VECTORS=<generated-json> cargo test -p consensus --locked --lib lean_generated_pow_admission_vectors_match_production
    HEGEMON_LEAN_POW_VECTORS=<generated-json> cargo test -p consensus-light-client --locked --lib lean_generated_pow_admission_vectors_match_light_client
    cargo test -p hegemon-node --locked --no-default-features --lib retarget_activation
    cargo test -p hegemon-node --locked --no-default-features --lib pow_schedule
    cargo test -p hegemon-node --locked --no-default-features --lib sync_tip_extension_across_retargets
    make node
    python3 scripts/test_release_artifact_manifest.py
    python3 scripts/test_package_testnet_downloads.py
    python3 scripts/test_testnet_launcher.py
    bash -n testnet-release/testnet-start.sh

Compile `formal/lean/Hegemon/Consensus/PowRules.lean` and run `GeneratePowVectors.lean` using the repository's pinned Lean toolchain. The scoped generator output used here has SHA-256 `a21291e141960f574a8179a2724bcb6ab4e46ebf964cb36edb0a3a4b3f85aea1`.

The locally built inactive native binary SHA-256 is `ec6176789227eff1445f887dad397c817e83acf7a25b5083d153c254892af476`. It is local validation evidence, not a published or manifest-attested cross-platform release artifact.

## Remaining final-release work

Choose and commit a future ten-block activation boundary, refresh the UTC forecast, rebuild the exact final source and binaries, regenerate the source-bound native-backend review archive, and run the full formal-core, dependency audit, native-backend review/posture, app/no-SSH, four-platform binary-manifest/audit and packaging gates. Final source/artifact gates and coordinated publication/deployment are deliberately pending the user's activation decision. Re-run activation lifecycle and conformance on the finalized rule. No live node, website, release, or testnet rule was changed by this preparation.
