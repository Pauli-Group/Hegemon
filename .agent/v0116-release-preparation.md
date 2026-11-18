# Prepare and rehearse v0.11.6 solo payout rotation

Maintain this plan according to .agent/PLANS.md. The earlier solo payout implementation and its development-chain rehearsal are recorded in .agent/solo-payout-key-rotation.md.

## Purpose

Build a v0.11.6 candidate for the existing pre-mainnet network. The release contains opt-in deterministic solo payout rotation and the corrected active and padded note constraints in the V6 diagnostic circuit. Show that an installed v0.11.5 node accepts the rotated rewards and that tools extracted from the candidate archive restore an earlier encrypted wallet, recover the notes and spend them at maturity.

## Progress

- [x] 2026-11-18. Created codex/v0.11.6-payout-rotation from the rotation branch and applied the separate V6 fix.
- [x] 2026-11-18. Ran 19 V6 relation and statement tests successfully on the combined source.
- [x] 2026-11-18. Downloaded the published macOS arm64 v0.11.5 node, checked its SHA-256 against the public asset and confirmed its product version.
- [ ] Build the release executables with the production feature sets, record their actual artifacts and make an extractable v0.11.6 archive.
- [ ] Run the two-version acceptance and packaged wallet recovery test and record exact artifact hashes and canonical block outcomes.

## Decisions

- Bump the software label through protocol/versioning/src/lib.rs and the joining metadata. Keep Cargo.lock byte-identical because it participates in the PrivateSpend relation digest.
- Use fresh disposable node and wallet stores, the frozen public pre-mainnet manifest and loopback-only peers. A historical issuer test fixture can pace timestamps at the network's target interval while performing actual proof of work. The two release executables still use their normal chain validation and RPC paths.
- Label the locally built archive as a candidate and bind it to its exact source and binary manifest. Historical v0.11.5 public releases retain their accepted artifacts. Preparation is local.

## Milestones

First, pin the source to both feature commits, inspect the byte-level network and proof inputs, and run the V6 relation and statement tests. The diagnostic tests exercise active and padded notes. Save the normal build manifest with the archives.

Second, create an encrypted full wallet with the candidate tools and back it up before the payout schedule is exported. Independently validate real paid blocks with the public v0.11.5 node. Store the canonical block hashes and commitments for the two rewards. After maturity, restore from the encrypted backup into an unused store. Synchronize with the local verified chain, spend both notes in a single ordinary PrivateSpend and verify acceptance and canonical inclusion.

## Concrete steps

From the isolated checkout, run the proof diagnostic and normal artifact build. Package from the same clean Git revision. Use a separate output directory for the archive, its checksums and the test evidence.

    cargo test --release --locked -p transaction-circuit --lib full_shake448
    bash scripts/build_release_artifacts.sh
    python3 -I -B scripts/package_v0116_candidate.py --platform macos-arm64 --manifest target/release/hegemon-release-artifacts.json --output /path/to/candidate-artifacts

The reference executable is the macOS arm64 v0.11.5 published asset named hegemon-node-macos-arm64. Verify SHA-256 d27e6be9eeb057de7f31bb5799d6f4584e80a9ec5ed7a950f283c6e512b40c23 before allowing it to start. Use the separate test output directory to keep the extracted archive and record of tested binaries.

## Validation and acceptance

Compare the packaged manifest and product versions with the build manifest. Confirm that the active PrivateSpend source digest, genesis, network identity and scheduled activation height match the published v0.11.5 settings. The compatibility receipt must name the v0.11.5 binary hash, both accepted reward block hashes and spending transaction inclusion. Count recovered amounts through the packaged wallet, including the inputs it spent and their fee-adjusted change.

## Outcomes

The integrated V6 regression completed with 19 passing tests. Remaining outcomes will be recorded after packaging and the two-version rehearsal.
