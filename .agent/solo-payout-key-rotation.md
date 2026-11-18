# Rotate solo mining payout keys and recover rewards from backup

Maintain this ExecPlan according to .agent/PLANS.md.

## Purpose / Big Picture

A solo miner can pay successive block rewards to independently derived wallet keys. A backup made before mining suffices to find and spend the rewards after restoration. The node holds only payout addresses. Each reward amount and its public opening remain observable on chain.

## Progress

- [x] 2026-11-18 05:46 UTC. Created an isolated branch from release revision 9905f68a. Traced native template construction, reward discovery, private spend input construction and the existing 120-block maturity.
- [x] 2026-11-18 05:57 UTC. Implemented deterministic key derivation, public schedule export and opt-in template selection.
- [x] 2026-11-18 06:07 UTC. Mined two differently addressed rewards, restored an earlier encrypted backup, proved a spend after maturity and confirmed it at height 122.
- [x] 2026-11-18 06:14 UTC. Verified schedule renewal, wallet recovery through the CLI, the active proof source identity and the existing treasury reorganization test.
- [x] 2026-11-18 06:29 UTC. Checked both launcher entry points, built the default node and wallet binaries, and passed the fresh-restore and historical-wallet replay tests. The native lifecycle test confirmed the two-input spend at height 122.

## Surprises & Discoveries

The reward scanner already stores the creation height and full public opening. They let a restored wallet select the correct spending key without adding an on-chain field or saving a secret counter. The existing Development lifecycle fixture can exercise actual proof of work at a low difficulty and the full maturity interval on an isolated chain.

The same mirror can contain private fee-change notes with a different authorization representation. Preserve their original spending mode while selecting the key separately for each reward. A newly recovered wallet clears its stored launch context, so generic synchronization must bind the RPC chain before advancing the mirror through reward heights.

Older generic scans could advance past a reward without recognizing the rotating key. On the released chain, a valid unpinned wallet journal with the original missing stablecoin root now rewinds to genesis once. The wallet persists the verified network identity and replays canonical blocks, retaining the existing wallet and its other records. Both source and package launchers pass an explicit node option for rotation, so an incompatible executable rejects it before mining.

## Decision Log

- 2026-11-18. Derive an independent wallet identity from the existing wallet secret, the chain ID and the reward height. Use address index zero for each derived identity. This makes recovery deterministic across backup, restart and reorganization.
- 2026-11-18. Export a finite range of public payout addresses to the solo mining node. Keep the wallet secret offline, preserve jobs already issued, and stop preparing paid work if the file has no entry for the requested height. An operator can extend the list by replacing the file.

## Outcomes & Retrospective

On an isolated native Development chain, rewards at heights 1 and 2 had different recipients and spending authorities. After recovery from the pre-export backup and removal of the schedule, the wallet had zero available reward notes at tip 119, one at tip 120 and two at tip 121. The node accepted the restored wallet's ordinary proof and mined the spend at height 122. The wallet then marked both inputs spent and recovered both outputs, whose total was the two rewards less the fee.

The default wallet CLI reproduced the same two addresses from a fresh restore and renewed an overlapping range. The wallet regressions cover key vectors, reorganization, schedule ownership and fee change. The native template tests cover height selection, schedule exhaustion, overlapping renewals and the treasury destination. The existing treasury cadence, restart, reorganization and fresh-sync test passed. All 41 inputs to the PrivateSpend relation digest match the v0.11.5 identity. This branch uses local tests and does not publish a release.

An isolated node loaded the released pre-mainnet manifest with mining disabled and zero peers. A freshly restored wallet synchronized twice over its safe loopback RPC. The launchers passed their fixed-address, schedule, relay and integrity checks. One historical package test needs external archived binaries that were unavailable.

## Context and Orientation

The block template is the candidate block a solo miner hashes. Its height already identifies the payout key to both wallet and miner. A reward opening records the amount and public recipient and authorization keys. Ownership requires the matching private spending key. A reward issued in block h can first be spent in block h + 120.

## Plan of Work

In wallet/src/keys.rs and wallet/src/solo_payout.rs derive independent keys and define the versioned schedule. Export it through WalletStore and the wallet CLI. In node/src/native select a scheduled address during candidate construction. In wallet/src/poseidon2_v8_sync.rs and the wallet spend builders resolve the owner using the original height. Use the native Development lifecycle fixture to test restoration, scanning, maturity and confirmed spending.

## Concrete Steps

Run the following from the repository root. The rehearsal feature supplies the Development wallet and prover. Its lifecycle test is ignored during routine test runs because it mines through the full maturity interval.

    cargo build --release --locked -p wallet -p hegemon-node --bin wallet --bin private-spend --bin hegemon-node
    ./target/release/wallet solo-payout-schedule --help
    cargo test --locked --release -p wallet --lib --features private-spend-dev-artifacts -- solo_payout solo_reward imported_recovery_fee_change rpc_wallet_
    python3 -m unittest scripts.test_premainnet_launcher scripts.test_package_v011_release
    cargo test --locked --release -p hegemon-node --lib --features solo-payout-rehearsal native::solo_payout::tests
    RAYON_NUM_THREADS=2 cargo test --locked --release -p hegemon-node --lib --features solo-payout-rehearsal native::treasury_lifecycle_tests::solo_payout_rotation::restored_wallet_spends_mature_solo_rewards -- --exact --ignored --nocapture

## Validation and Acceptance

Back up a fresh wallet before generating addresses. Mine rewards to two different spending authorities. Restore the backup into a fresh store. Confirm that mature notes appear at the correct heights and that a real PrivateSpend consuming both is accepted and included. Confirm that the funding destination and the legacy fixed-miner-address path still work. Inspect the diff against 9905f68a and compare the active proof source digest against its release pin.

## Idempotence and Recovery

The same wallet, chain and height must produce exactly the same address, so regenerating overlapping schedule ranges is safe. Supply a file covering the current height and expected reorg range if the node runs past its schedule. Preserve old encrypted backups, keep the address list private from observers and use disposable wallet stores for the rehearsal.

## Artifacts and Notes

The proof, chain database, test key material and target directory used during verification are local and disposable. Retain the source test and its observed result.

## Interfaces and Dependencies

The existing native node, wallet store, PrivateSpend prover and consensus verifier supply the integration boundary. The solo miner chooses HEGEMON_SOLO_PAYOUT_SCHEDULE instead of HEGEMON_MINER_ADDRESS. The wallet derives each child from its root-derived secret material, the network identity and the block height.

Revision 2026-11-18. Initial plan based on the v0.11.5 implementation.
Revision 2026-11-18. Added the reproducible lifecycle command and its observed chain and wallet outcomes.
