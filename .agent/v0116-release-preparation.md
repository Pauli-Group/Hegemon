# Prepare and rehearse v0.11.6 solo payout rotation

Maintain this plan according to .agent/PLANS.md. The earlier solo payout implementation and its development-chain rehearsal are recorded in .agent/solo-payout-key-rotation.md.

## Purpose

Build a v0.11.6 candidate for the existing pre-mainnet network. The release contains opt-in deterministic solo payout rotation and the corrected active and padded note constraints in the V6 diagnostic circuit. Show that an installed v0.11.5 node accepts the rotated rewards and that tools extracted from the candidate archive restore an earlier encrypted wallet, recover the notes and spend them at maturity.

## Progress

- [x] 2026-11-18. Created codex/v0.11.6-payout-rotation from the rotation branch and applied the separate V6 fix.
- [x] 2026-11-18. Ran 19 V6 relation and statement tests successfully on the combined source.
- [x] 2026-11-18. Downloaded the published macOS arm64 v0.11.5 node, checked its SHA-256 against the public asset and confirmed its product version.
- [x] 2026-11-18. Built the four release executables for macOS arm64 from aecbd5e0e6 and verified the candidate archive, its launcher and every archived checksum.
- [x] 2026-11-18. Ran the two-version acceptance and packaged wallet restore-and-spend test successfully. Both versions confirmed the same spending transaction in block 122.
- [ ] 2026-11-18. Build and rehearse the identical candidate source on Linux x86_64, Windows x86_64 and Intel macOS. Record one archive and passing receipt per platform.

## Decisions

- Bump the software label through protocol/versioning/src/lib.rs and the joining metadata. Keep Cargo.lock byte-identical because it participates in the PrivateSpend relation digest.
- Use fresh disposable node and wallet stores, the frozen public pre-mainnet manifest and loopback-only peers. A historical issuer test fixture can pace timestamps at the network's target interval while performing actual proof of work. The two release executables still use their normal chain validation and RPC paths.
- Label the locally built archive as a candidate and bind it to its exact source and binary manifest. Historical v0.11.5 public releases retain their accepted artifacts. Preparation is local.
- Run native qualification from the authorized CI branch. Build all additional binaries from the source revision already used for Apple Silicon. Check out the portable rehearsal separately and record both revisions in the evidence. The qualification workflow has repository read access and uploads its candidate archives and receipts as workflow artifacts.

## Milestones

First, pin the source to both feature commits, inspect the byte-level network and proof inputs, and run the V6 relation and statement tests. The diagnostic tests exercise active and padded notes. Save the normal build manifest with the archives.

Second, create an encrypted full wallet with the candidate tools and back it up before the payout schedule is exported. Independently validate real paid blocks with the public v0.11.5 node. Store the canonical block hashes and commitments for the two rewards. After maturity, restore from the encrypted backup into an unused store. Synchronize with the local verified chain, spend both notes in a single ordinary PrivateSpend and verify acceptance and canonical inclusion.

Run these checks on the three native x86_64 runners with the historical v0.11.5 executable for the same operating system. Use the wallet and proof tool extracted from each archive. Exercise the real Windows console prompts through ConPTY. Keep disposable wallet state and logs in the runner's working area and retain the candidate archive, build manifest and compatibility receipt.

## Concrete steps

From the isolated checkout, run the proof diagnostic and normal artifact build. Package from the same clean Git revision. Use a separate output directory for the archive, its checksums and the test evidence.

    cargo test --release --locked -p transaction-circuit --lib full_shake448
    bash scripts/build_release_artifacts.sh
    python3 -I -B scripts/package_v0116_candidate.py --platform macos-arm64 --manifest target/release/hegemon-release-artifacts.json --output /path/to/candidate-artifacts

The reference executable is the macOS arm64 v0.11.5 published asset named hegemon-node-macos-arm64. Verify SHA-256 d27e6be9eeb057de7f31bb5799d6f4584e80a9ec5ed7a950f283c6e512b40c23 before allowing it to start. Use the separate test output directory to keep the extracted archive and record of tested binaries.

Build the test-only fixture issuer and locate the `hegemon_node` test executable in `target/release/deps` from Cargo's build output. Use an empty output path for the rehearsal. Supply the archive SHA-256 from its sidecar.

    cargo test --release --locked -p hegemon-node --lib --features solo-payout-rehearsal --no-run
    python3 -B scripts/test_v0116_rotation_compatibility.py \
      --package /path/to/candidate-archive.tar.gz --package-sha256 ARCHIVE_SHA256 \
      --previous-node /path/to/v0.11.5/hegemon-node-macos-arm64 \
      --fixture-binary /path/to/hegemon_node-test-binary --out /path/to/new-rehearsal-output

## Validation and acceptance

Compare the packaged manifest and product versions with the build manifest. Confirm that the active PrivateSpend source digest, genesis, network identity and scheduled activation height match the published v0.11.5 settings. The compatibility receipt must name the v0.11.5 binary hash, both accepted reward block hashes and spending transaction inclusion. Count recovered amounts through the packaged wallet, including the inputs it spent and their fee-adjusted change.

## Outcomes

The integrated V6 regression passed all 19 tests. The macOS arm64 candidate archive from aecbd5e0e60208a1502717951b7285b0b25f97e7 has SHA-256 d9aaf8412f395c5de8371904db3e5314ba703561c7345d86fc674c3067ecbec2. Its verifier passed five retained valid proofs and rejected all 30 negative controls. All 41 inputs to the active PrivateSpend source digest matched v0.11.5.

On the first isolated branch, the released v0.11.5 node imported both blocks authored by the packaged v0.11.6 miner and matched the expected recipient and spending authorizations. On a second branch, the same wallet's reward addresses were used at heights 1 and 2 by the historical fixture. Through the published v0.11.5 node, the packaged wallet restored the pre-rotation backup and recovered two mature rewards of 400,000,000 atoms each. It submitted a single ordinary spend and both node versions confirmed the canonical action bytes in block 122, hash 000006adb570a99a2dcdb9dab397634750152b52252cf249a515833469121bbb. The restored wallet then reported the 500,000,000-atom payment and the 299,999,000-atom change after the 1,000-atom fee.

The mixed-version run covers low-height public pre-mainnet rules on isolated loopback nodes. Native executable and package qualification here covers macOS arm64. Other platform binaries and their release qualification remain pending.
