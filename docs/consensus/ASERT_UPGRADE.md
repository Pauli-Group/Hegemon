# ASERT upgrade at pre-mainnet H18,660

This branch prepares a height-activated difficulty upgrade for the existing
pre-mainnet. **v0.11.4 activates the combined rules at H18,660.** It does not change genesis, chain ID,
wallets, proof bytes, reward allocation, reward maturity or the 60-second target.
There is no emergency difficulty reset, timestamp-dependent candidate target or
merged mining in this change.

## Consensus rule

`consensus-light-client/src/pow_rules.rs` owns the schedule. Only the pinned
pre-mainnet chain ID `7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49`
receives the live activation at `Some(18_660)`.
Unknown chains retain their historical rule. The optional `asert-rehearsal`
build feature activates at height 20 only for the legacy development chain ID;
its H20 seam applies only to that legacy development chain. The combined
Development rehearsal separately uses H120; ordinary releases use neither feature.

At activation H (at least 2), take reference height and target from block H−1,
and reference timestamp from H−2 on the candidate parent's own branch. Keep this
anchor fixed. For parent P, compute in signed integer milliseconds:

    dt = P.timestamp_ms - anchor_parent.timestamp_ms
    dh = P.height - anchor.height
    exponent = trunc_toward_zero((dt - 60000*(dh+1))*65536 / 3600000)
    shifts = exponent >> 16               # arithmetic signed shift
    fraction = exponent - shifts*65536    # 0 through 65535
    factor = 65536 + ((195766423245049*fraction
                      + 971821376*fraction^2
                      + 5127*fraction^3 + 2^47) >> 48)
    target = floor(anchor.target * factor * 2^(shifts-16))

Clamp the target to `[1, target(0x207fffff)]`, then encode with Bitcoin's positive,
canonical compact format, rounding downward where precision is lost. A fixed
34-byte product retains every intermediate target bit, and bounded shifts cannot
allocate or loop in proportion to the timestamp gap. Parameter arithmetic is
checked; malformed anchors/targets reject. The public helper accepts other
spacing/half-life values for reference comparison, but native consensus uses the
fixed profile constants above.

The first new block already responds to the last old-rule interval. This is
BCH's reference anchor convention; using H−1's timestamp with the `dh+1` formula
would be an off-by-one error. The candidate's timestamp is absent from target
selection. A long gap changes the following target only after a block completes.

The old header rules digest remains the genesis/manifest identifier. The combined
v0.11.4 headers use
`ec304529f49e7ddc777e0ca78b189acec753d4fb18aafe15761e686ea3596b7f`
from H18,660 onward, binding ASERT, version rolling and treasury batching together.
The standalone legacy-development ASERT fixture retains its separate
`992a6a04c320f65fb55dd0576f01d174981e56b959fa50294bad7fffc333c205`
profile. All these profiles use the same Bitcoin80 hash construction.
Changing the global genesis rules alias or the frozen manifest is not an upgrade
mechanism. Both parent and child rules are checked against their exact heights.

## Native integration and scope

Mining templates, ASIC solution submission, announced blocks, sync batches,
replay and startup call the same target arithmetic. Side branches resolve their
own H−1/H−2 pair through parent hashes; sync may use a validated prefix not yet
persisted. A bounded 256-entry process-local cache keys calculated ancestry by
exact parent hash/projection and rereads anchor metadata on hits. It is discarded
on restart and never substitutes for block or transaction-proof validation.
Canonical callers also check the height index against the resolved ancestry.
Cold resolution traverses at most 128 parent links per call. A separate bounded
256-entry continuation cache records exact original and cursor projections;
resumption rereads both. A typed local deferral releases the fair import slot
and queues the same owned announcement behind waiting peers, without cloning
its body or granting it validity. Sync responses retain local-deferral status
and retry without treating the peer as invalid. Cold outbound range service
releases its loader reservation and requeues at the tail while retaining the
exact peer/range owner, so it progresses without waiting for client timeouts. This read budget is a
local scheduling control, not a maximum consensus history or fork depth.

Genesis bytes, network manifest and launch-reference proof rules stay fixed, so
existing private-spend wallet manifest pins remain valid. The V2 explicit
expected-bits header API supports the new rules; its caller remains responsible
for deriving expected bits from authenticated history. The convenience
fixed-difficulty and long-range bridge interfaces cannot derive ASERT history
and explicitly reject it. This change grants no bridge mint authority. V3 is
outside this V2 upgrade.

## Reproduce qualification

From the repository root, use one Cargo build at a time. The reference fixtures
and SHA-256 provenance are in `consensus-light-client/testdata/asert/README.md`.
They retain all 12 BCH files, totaling 14,000 cases. The comparison uses BCH's
reference spacing, half-life and limit; separate Hegemon tests cover its own
limit, millisecond precision and native activation semantics.

    cargo test --locked -p consensus-light-client --release -j 2 --lib
    cargo check --locked -p consensus-light-client --release -j 2 --no-default-features
    cargo test --locked -p hegemon-node --release -j 2 --lib --features asert-rehearsal asert_ -- --nocapture

The native rehearsal uses disposable databases, actual Bitcoin80 seal searches,
mining/import, wrong target/rules rejection, branch-specific anchors, unpersisted
sync, a greater-work reorg, restart and fresh synchronization. A 540-block cold-history
regression checks bounded lookup, changed-cursor rejection and eventual valid
import through repeated local deferrals. It does not launch
or modify shared nodes. Legacy regressions are run separately without the feature.
The standalone Lean model lives in `formal/asert/`, separate from the unchanged
transaction-proof corpus. Its 14 audited roots prove bounded arithmetic and
activation facts; 62 arithmetic and 45 activation cases compare the independent
model with Rust. This is finite conformance, not general Rust refinement or a
proof of mining incentives. Run `bash scripts/check_asert_formal.sh` for the
complete standalone gate. CI runs the ASERT Rust checks within its existing node-default shard and
regenerates the Lean vectors alongside its formal-kernel job.

A release must also pass its full existing qualification gates and a live
multi-node rehearsal before operators receive an activation release.

## Release follow-through

After qualification, select a future height with enough measured lead time for
responsive community operators to upgrade, compile that height into the pinned
chain schedule, and re-run transition tests against the final release. Publish
verified packages/checksums and a mandatory upgrade notice with the exact height,
chain ID and release version. Upgrade seeds, independent nodes, miners' node
software and wallets that bundle node validation before the boundary. Keep
existing databases and wallets. Enable NTP/chrony; timestamp admission is unchanged.

At activation, compare both seeds and an independently syncing node for identical
block hashes and expected targets, inspect explorer production and exercise a
wallet transaction. An old binary is incompatible after activation, so rollback
requires consensus coordination. No live height, announcement, publication or
deployment is performed by this preparation.

The one-hour half-life is a pre-mainnet candidate. Bounded comparisons with
30-minute and three-hour alternatives inform responsiveness and burst tradeoffs;
they are not a proof of optimal miner incentives or sustained mining security.

## Candidate comparison

The [retained deterministic scenarios](asert-scenarios.md) use the actual integer
ASERT implementation with 30-minute, one-hour and three-hour half-lives. After
10x hashpower enters for three hours and leaves, first in-band target recovery
has median 1.62 hours, 2.94 hours and mostly exceeds the six-hour observation
window respectively. Keep one hour as the preparation candidate; these finite,
idealized cases do not establish an optimal half-life. At an identical fixed
parent followed by a 10,000x departure, every half-life retains the same first
block waiting distribution (mean 6.94 days in this model). Later catch-up bursts
hit the experiment's block cap. Neither quick later adjustment nor those
idealized burst counts imply sustained network security or actual throughput.

The [local validation record](asert-validation.json) pins the tested implementation
inputs, commands and retained log hashes. It records focused preparation checks;
it is not a release qualification or production authorization.
