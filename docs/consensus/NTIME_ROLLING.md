# Bounded Bitcoin80 time rolling — v0.11.5

The v0.11.5 pre-mainnet source schedule selects time rolling at **H28,860**.
This is a coordinated consensus upgrade on the existing genesis. Nodes running
v0.11.4 cannot validate the new profile after activation and must upgrade before
that height when the release is approved. The PR prepares source; it does not
authorize publication or deploy nodes.

The planning target is **Friday November 20, 2026, around 09:00 Calgary
(UTC−6)**, following [Alberta’s current time guidance](https://www.alberta.ca/albertas-new-time-system-abt).
Height governs activation. At the November 14 01:07 UTC observation,
the chain was H19,354; 60-second intervals project H28,860 to about 09:31.
A conditional stable-hash ASERT model projects about 08:54. Recent intervals
included a hashpower burst, so neither calculation is a promised activation
time. Recheck the forecast before announcing readiness and retain the agreed
height once operators coordinate around it.

## Consensus construction

`nTime` is the unsigned 32-bit seconds field at bytes 68..72 of the final
80-byte SHA256d mining header. Under earlier rules the full millisecond native
timestamp is also inside the BLAKE3 metadata prehash, hence inside the synthetic
mining coinbase and its Merkle root. A miner changing only nTime cannot construct
the native hash under those rules.

The new profile normalizes **both** a validated mining-version commitment and
the native timestamp to zero **only while computing the mining prehash**.
Canonical persisted metadata retains the actual timestamp, and the final
80-byte header binds the exact submitted seconds through SHA256d. Every other
canonical commitment remains bound. Version commitment validation precedes
normalization. Existing rules and historical block hashes remain unchanged. The new rules
fingerprint is
`d5f91874cea4e4eade6ac7f31b2ada7a2902e71e065d02a476dc6e646da1a38f`.

New-profile native timestamps must be exact whole seconds representable as
u32 nTime. For an admitted block:

    timestamp_ms = submitted_ntime * 1000
    submitted_ntime >= floor(parent_timestamp_ms / 1000) + 1
    timestamp_ms <= admission_now_ms + 90_000

The lower bound is strictly after the immediate parent's timestamp; it is not
the suggested job time and is not Bitcoin's median-time rule. The upper bound
uses the receiving node's current clock, inclusive, at fresh admission.
Stored-history replay validates the selected consensus profile, PoW and parent
ordering without applying today's wall clock. Operators must keep NTP/chrony
enabled. Changing an already solved header's time would change its PoW hash;
the node imports exactly the submitted time or rejects the solution.

The new profile inherits v0.11.4's 24-bit mining-version mask and target codec.
ASERT retains its original H18,660 activation, H18,659 anchor and H18,658 time
origin on each branch. Treasury batches retain their original cadence. Candidate
time does not select its own target. Chain ID, genesis, transaction-proof
formats and source relation, reward amounts and maturity remain unchanged.

## Work RPC and adapter

`hegemon_poolWork` and `hegemon_compactJob` include these fields:

| Field | Meaning |
|---|---|
| `ntime` | Suggested time, eight hexadecimal numeric characters |
| `ntime_rolling` | Whether this job's rules allow time changes |
| `ntime_activation_height` | Source-owned activation height, or null for an unscheduled chain |
| `min_ntime` | Inclusive parent-derived minimum, eight hexadecimal characters |
| `max_ntime` | Inclusive node-clock maximum at this response, eight hexadecimal characters |
| `server_time` | Node clock in seconds at this response, eight hexadecimal characters |
| `max_future_skew_seconds` | 90 |

Before activation the minimum and maximum equal the exact job time. Old RPCs
without range fields are treated as fixed-time jobs. After activation, miners
may submit before or after the suggestion within the actual bounds. A node
may pause issuance when the parent/clock combination has no legal timestamp.

The maximum is a snapshot, not a permanent upper bound frozen when the job was
created. The adapter advances the observed node clock using monotonic elapsed
time and refreshes that observation on polls; it does not trust the adapter
host's wall clock. The node always makes the final clock decision. Same-job
range refreshes do not change coinbase, target or suggested time and never
extend the original 120-second job expiry. A clock rollback may place an
immutable suggested time outside the new range without invalidating every
other possible time on that job.

The adapter hashes the submitted nTime and forwards those exact seconds with
the solution. Duplicate and retry identities include time and effective
version. Prepared block actions remain immutable; normal block admission must
still validate their conditions against the submitted block time.

## Reproducible checks and release boundary

From the repository root run:

    cargo test --locked -p consensus-light-client
    cargo test --locked -p consensus-light-client --features combined-upgrade-rehearsal
    python3 -B scripts/test_bitcoin_asic_stratum.py
    cargo test --locked -p hegemon-node --no-default-features --features development-candidate,combined-upgrade-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts --lib time_rolling
    cargo test --locked -p hegemon-node --no-default-features --features development-candidate,combined-upgrade-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts --lib bitcoin_asic
    cargo test --locked -p hegemon-node --no-default-features --features development-candidate,combined-upgrade-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts --lib timestamp_admission

The isolated `combined-upgrade-rehearsal` feature activates combined rules at
H120 and time rolling at H180 only for its dedicated Development identity.
It does not move the production height. Software tests cover solved backward
and forward times, exact bounds, old-profile behavior, native import, retained
jobs and clock rollback. See the PR preparation record for actual executed
results and remaining release gates. Tests do not establish physical ASIC/MRR
acceptance; that requires a real miner, node acceptance and cross-node import.
