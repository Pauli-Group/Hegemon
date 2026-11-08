# Batch exact treasury rewards every 60 blocks

This living ExecPlan follows `.agent/PLANS.md`. Keep Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective current. The coordinator owns final shared DESIGN.md, METHODS.md, governance and source-pin updates.

## Purpose / Big Picture

The treasury receives one shielded note per 60 accepted active blocks instead of one per block. Miners retain their existing per-height share and every transfer fee. The first active batch starts at activation H and pays at H+59; a fresh genesis policy starts at block 1 and pays at 60. The live existing-chain activation remains unset. The existing two-input PrivateSpend proof and 120-block reward maturity remain unchanged.

## Progress

- [x] (2026-11-08) Read operator instructions, design/method context and treasury acceptance contract in runbooks/mainnet_integration_queue.md.
- [x] (2026-11-08) Freeze scheduled accrual and independent miner forfeiture with coordinator.
- [x] (2026-11-08) Implement pure exact per-height entitlement calculation with boundary, rounding, exhaustion and bounds tests.
- [ ] Integrate construction, independent native validation, actual issuance accounting and RPC logical roles.
- [ ] Exercise native branch/restart/replay and wallet recovery/maturity/spending controls.
- [ ] Run coordinator-approved focused builds/tests and record exact results.

## Surprises & Discoveries

The existing action12 carrier has one required physical primary note and one optional secondary note. Its historical field name `miner_note` does not prevent a treasury-only primary after activation. Node state and wallet recovery already process compact note order independent of recipient role. This preserves exact wire bytes, action authority and the pending reward codec.

## Decision Log

Decision: accrue `block_subsidy(h)/5` for every accepted active block, including blocks whose miner forfeits its own share. Rationale: missing current rewards cannot erase earlier treasury entitlement. Historical omissions below H are never re-accrued. Coordinator approved on 2026-11-08.

Decision: preserve action12 bytes and apply strict contextual role rules only at H. At a positive boundary, a sole primary is treasury and must match exact due amount and manifest recipient/policy; paired notes are miner then treasury. Intermediate/zero boundaries permit only a miner primary. Rationale: no zero dummy, new proof route or state codec is required. Coordinator approved on 2026-11-08.

Decision: derive pending entitlement from immutable policy and accepted branch height, using a checked sum of at most 60 exact per-height shares. Rationale: all accepted active blocks accrue identically, so branch height fully determines pending value; detach/attach and restart cannot retain an orphan payout or lose accrued entitlement.

## Outcomes & Retrospective

Implementation and focused qualification are in progress. No release, production authorization, external CI, push or deployment is authorized by this work.

## Context and Orientation

`consensus/src/reward.rs` defines the unchanged exact emission schedule. `consensus/src/treasury.rs` calculates pending and due treasury entitlement. `node/src/native/block_flow.rs` validates block rewards and tracks the existing gross fee-inclusive issued-note supply digest. `node/src/native/node_impl.rs` constructs local reward actions and validates imports, stored replay and fork changes. `node/src/native/rpc.rs` reports public reward observations. `protocol/shielded-pool/src/poseidon2_v8_coinbase.rs` defines action12 bytes. `wallet/src/poseidon2_v8_sync.rs` discovers publicly opened reward notes by exact recipient and applies unchanged maturity. A physical primary note is the first encoded note, regardless of logical recipient role after activation.

## Plan of Work

Add a pure injectable treasury policy and retain disabled legacy wrappers for existing finite fixtures. Native network validation must select one shared combined-upgrade activation schedule and require exact payout amount, recipient/policy, placement and positive value. Construction must use that policy, including treasury-only payouts when the miner has no address or forfeits. Supply accounting adds actual note values only; pending entitlement is separately reported and never counted as issuance. RPC reports scheduled per-height entitlement, pending value, due value and actual role-specific issuance. Preserve all historical action12 parsing below H and all two-input spend relation files.

## Concrete Steps

Work exclusively in `/private/tmp/hegemon-combined-upgrade-20261108/treasury-source`. Use the coordinator-provided isolated Cargo target and no more than two build jobs. Before compiling, obtain the coordinator's build slot. Run focused consensus treasury tests and node/wallet treasury controls with `cargo test -p consensus treasury` and the exact node/wallet filters recorded below. Format changed Rust files with the repository toolchain's rustfmt. The coordinator integrates shared activation and source pins before final combined qualification.

## Validation and Acceptance

Tests must reject early, missing positive, duplicate, zero, wrong-value and wrong-policy treasury notes. Check H-1/H/H+58/H+59/H+60, fresh 1/59/60/61/120, independently summed halving-crossing amounts, zero subsidy and final residual. Show miner forfeiture never erases treasury entitlement and treasury-only payout never claims miner subsidy or fees. Show actual issued-note supply and pending entitlement remain separate. Reopen and replay branch state across a payout boundary and verify wallet discovery, 120-block maturity, rollback and subsequent existing two-input spending without changing the relation. Final combined ASERT, mining and funded HTLC controls are coordinator-owned acceptance gates.

## Idempotence and Recovery

The implementation is confined to an isolated worktree and performs no network publication or database mutation outside temporary test fixtures. A failed test can be rerun against a fresh temporary fixture. Disabled policy preserves historical behavior. Reconstruct entitlement from the immutable policy and selected branch height rather than transferring mutable accrual between forks.

## Artifacts and Notes

Exact test transcripts and handoff commit will be added after focused validation. The selected live height is unset; tests inject height 120 or fresh-genesis height 1 explicitly.

## Interfaces and Dependencies

`consensus::treasury::TreasuryRewardPolicy::{disabled,at,from_genesis,entitlement}` supplies an immutable policy. `TreasuryEntitlement` exposes exact current accrual, payout and pending-after values. Node activation uses the coordinator-owned `consensus_light_client::pow_rules::native_combined_upgrade_activation_height` seam. No dependency, proof relation, authorization address policy or emission constant changes.

Revision 2026-11-08: initial plan records the coordinator-approved omitted reward semantics and exact-wire approach before native integration.
