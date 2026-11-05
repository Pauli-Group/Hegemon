# Check Hegemon testnet freshness against a public reference

This living plan follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

The existing read-only Hegemon wallet probe checks the node's identity, RPC
methods, peers and its own sync flag. A stale node can nevertheless report that
it is not syncing. Add an explicit public-reference check so an operator can
compare a local node's height and block hash with the v0.11 pre-mainnet explorer
before using it for public testnet swaps. The explorer is a trusted second
observation, not a light client or independent proof of consensus.

## Progress

- [x] (2026-11-04 17:46Z) Confirmed that a node reported height 8659 and not
  syncing while the public explorer reported height 9471; their block hash at
  height 8659 matched. A restart let the node catch up.
- [x] (2026-11-04 17:49Z) Implemented the opt-in, fixed-HTTPS public-reference check and CLI result.
- [x] (2026-11-04 17:50Z) Tested stale and invalid references, lag, fork hashes, and reorganization
  handling, while preserving offline probe behavior.
- [x] (2026-11-04 17:50Z) Exercised the explorer request with a synthetic local RPC view and documented
  the result and limitations in `DESIGN.md` and `METHODS.md`.
- [x] (2026-11-05 00:57Z) Distinguished syncing from wrong-network failures,
  and rejected old or inconsistent tip and common-block timestamps. Tested
  the stalled-chain case with synthetic fixtures and current explorer data.

## Surprises & Discoveries

The `system_health` sync flag and peer count are node-local observations. In the
reported case both looked healthy even though the public tip was 812 blocks
ahead, so they must not alone establish current public-testnet readiness.
On 2026-11-05 the explorer was refreshing its status while its tip remained at
height 9831 for over an hour. A fresh status update is not a recent block.

## Decision Log

- Decision: Keep the existing offline probe and exit behavior unchanged unless
  the operator explicitly requests the public-reference comparison.
  Rationale: Existing private and restricted environments may not have internet.
  Date/Author: 2026-11-04 / Codex.
- Decision: Compare the block hash at the same height, require bounded height
  difference, and reject stale or wrong-network explorer responses.
  Rationale: Height alone does not establish matching chain history.
  Date/Author: 2026-11-04 / Codex.
- Decision: Use only fixed public explorer URLs, read-only GETs and a loopback
  local RPC. Fail closed if the requested comparison cannot be completed.
  Rationale: The check must not submit transactions or expose wallet secrets.
  Date/Author: 2026-11-04 / Codex.
- Decision: require both the trusted explorer tip and the compared common block
  to have timestamps within 20 minutes, with a bounded future allowance.
  Rationale: a freshly polled but stalled chain is unsuitable for timed swap
  tests. The threshold can reject a slow healthy chain and relies on the local
  clock and reported block timestamps. Date/Author: 2026-11-05 / Codex.

## Outcomes & Retrospective

The optional check is implemented and the probe suite passed 19 tests. Current
public explorer data rejected the reported syncing and hour-old tip, even when
the syncing flag was synthetically cleared. No real Hegemon node was accessed
from this workspace. The operator's node and a funded public-testnet swap still
require separate validation.

## Context and Orientation

`scripts/probe_hegemon_testnet.py` already pins the release manifest, network
identity and private-spend relation. `scripts/test_probe_hegemon_testnet.py`
tests that probe using fake loopback nodes. The public explorer is
`https://hegemonprotocol.com`: `/testnet/status.json` supplies cached node
status, and `/testnet-api/v1/block/<height>?limit=1` supplies a block hash.
Neither service proves that the chain has finality or that the other swap leg
is safe. No wallet keys, preimages or transaction bytes are needed.

## Milestones and Plan of Work

First implement a bounded HTTPS JSON reader and a comparison helper in the
probe. Require the pinned genesis and chain ID, current explorer status, a
small height gap and matching hash at the lower height; recheck the local hash
to detect a reorganization during the comparison. Expose this only through an
explicit CLI flag and distinguish the basic local checks from the reference
result in JSON and exit status.

Then extend the probe's unit tests with fake responses for current matching
chains, stale/wrong-network references, excessive gaps, hash mismatches,
transport failures and local reorganization. Confirm the existing no-network
tests still pass. Exercise the real public explorer only with a synthetic RPC
view so no Hegemon node is started or synced in this workspace.

## Concrete Steps

From the repository root, run `python3 -m unittest discover -s scripts -p
test_probe_hegemon_testnet.py` and expect all probe tests to pass. Run
`git diff --check`. A live explorer format check may call only the two fixed
HTTPS endpoints and must not print or send wallet material.

## Validation and Acceptance

An operator requesting the reference check receives a successful exit only
when the existing node checks pass, the reference is current and on the pinned
network, the height gap is within the configured bound, and both sources agree
on the same-height block hash. Network errors, stale data and chain changes fail
closed. The default offline invocation remains backward compatible.

## Idempotence and Recovery

All requests are read-only and can be repeated. If the explorer is unavailable,
report that the requested comparison could not establish readiness; do not
weaken the check or change the node. No wallet or node data are modified.

## Artifacts and Notes

The live public-explorer format check reported a matching synthetic common
height of 9524 on `pre-mainnet-v0.11`; no actual local node was represented.
The subsequent live format check observed height 9831, reported syncing, and
rejected a block more than 3,900 seconds old. These are trusted explorer data.

## Interfaces and Dependencies

Use Python's standard library. Keep `probe(url, read=...)` compatible. Add a
public-reference comparison callable with injectable reader, fetcher and clock
for deterministic tests; add one explicit probe CLI flag. The HTTPS reader uses
the environment's configured proxy and standard certificate verification.

Revision 2026-11-05: added the block timestamp liveness gate after the public
explorer returned freshly updated status for an hour-old block.
