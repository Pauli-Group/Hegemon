# Expose treasury and reward-account state in the block explorer

This living ExecPlan follows `.agent/PLANS.md` and extends
`.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md`. Keep Progress, Surprises &
Discoveries, Decision Log and Outcomes & Retrospective current. Deployment,
merging and resetting public nodes remain outside this work.

## Purpose / Big Picture


An explorer visitor should see the fixed treasury's available and pending HGN,
public donations and withdrawals, miners' reward accounts and exact release
heights, genesis allocations and the remaining mining budget. Governance views
show the actual current quorum, signer-key hashes, policy generation and any
certified replacement. Every view identifies its network and canonical block.
Reward availability is accounting, not finality: a reorganization can cross an
epoch boundary and change the displayed state and history.

The explorer must consume read-only node APIs, retain integer precision, and
render public text safely. A legacy node or an inactive successor must report
that reward-account data is unavailable; the UI must not replace that condition
with zero balances or a fictional committee. Actual native activation remains
a prerequisite in the parent implementation plan.

## Progress


- [x] (2026-11-05 UTC) Inspect the repository, public RPC dispatch, account
  ledger, canonical storage, branding and existing explorer references.
- [x] (2026-11-05 UTC) Search accessible repositories for the existing explorer;
  its implementation is absent from this checkout. Ask for its repository and
  branch while continuing node and specification work.
- [x] (2026-11-05 UTC) Implement canonical public-state projections and four
  bounded safe read APIs, preserving unavailable states and exact u64 values.
- [x] (2026-11-05 UTC) Test exact integer/root encoding, epoch release, network
  checks, unavailable-state HTTP behavior without writes, genesis/history
  pagination and committed body/context binding. Thirty-three selected tests pass.
- [x] (2026-11-05 ET) Locate the user-supplied `hegemon-website` repository;
  clone its `main` and create new branch `codex/explorer-treasury-rewards`.
- [ ] Integrate that explorer's client, indexer and views, preserving existing
  block and legacy reward views.
- [ ] Qualify the explorer against an activated disposable node, including a
  boundary reorg, restart and fresh synchronization; parent runtime work is open.
- [x] (2026-11-05 UTC) Commit/push backend preparation as a58b2757 and verify
  the remote branch hash and immutable GitHub API-contract readback. No deployment.

## Surprises & Discoveries


The repository contains a static marketing website and an Electron wallet/node
console, but no current block-explorer application or indexer. Historical release
notes describe a separately deployed explorer; they do not identify its source.
GitHub searches of accessible organization repositories found no matching
implementation. Do not build an unrelated replacement or claim the deployed
explorer was updated.

The successor's shared ledger and journal adapters exist, but native runtime
startup explicitly rejects its v2 manifest until block processing is integrated.
An explorer change cannot grant proof authority or skip that guard. Public read
models may be tested with real shared-ledger transitions; such tests do not
constitute running-chain or real-proof qualification.

## Decision Log


Decision: Build read-only, snapshot-bound APIs with monetary atoms, note-root field
words, heights, epochs and claim sequences/generations represented as decimal
strings. Small bounded row/action/scan and signer counts remain JSON integers. Rationale: JavaScript
numbers cannot represent every u64 exactly, and mixing responses from different
forks produces incorrect balances and governance history.
Date/Author: 2026-11-05 UTC, Codex.

Decision: Integrate the existing explorer once its source is supplied. Continue the
independent backend work while that location is pending. Rationale: preserve the
user's existing product and avoid an unsupported parallel indexer.
Date/Author: 2026-11-05 UTC, Codex.

## Outcomes & Retrospective


Backend preparation is implemented and tested: four read APIs and canonical
projections, with an explicit unavailable-state result until the native runtime
installs a verified canonical account ledger. The user paused
explorer UI/indexer work pending Pierre's source location.
No activation, two-node acceptance, deployment or reset is claimed. Backend
commit [a58b2757](https://github.com/Pauli-Group/Hegemon/commit/a58b2757b8ffc592ce72a175bcccf78ae765a741)
is published on codex/protocol-treasury-governance. Remote-head comparison and
GitHub readback confirmed the four API methods and the deferred UI scope.

## Context and Orientation


Work in `/workspace/Hegemon` on `codex/protocol-treasury-governance`. The public
ledger is `protocol/reward-accounts/src/ledger.rs`; its immutable trie clones
cheaply and its genesis descriptor fixes epoch length, initial committee and
allocation-adjusted issuance. `node/src/native/reward_accounts/wire.rs` defines
claim, donation, certified-fork and mandatory reward-record frames. The latter
binds the resulting public-account and shared-note roots to the block's normal
PoW action commitment. `node/src/native/rpc.rs` dispatches JSON-RPC methods;
`node/src/native/util.rs` advertises and classifies them. `NativeState` in
`node/src/native/mod.rs` and its canonical writer lock own current publication.

An atom is 0.00000001 HGN. For epoch length E, earning epoch at h>=1 is
floor((h-1)/E), and its release height is (N+2)*E+1. Genesis is outside reward
epochs and initial allocations are immediately available. The treasury always
uses the fixed protocol identity, independent of the current committee's
ordinary policy-hash account. Signer rotation changes authority/generation,
not the treasury address, balances or claim sequence.

## Plan of Work


First add `node/src/native/reward_accounts/read_model.rs` for deterministic JSON
projections of genesis, supply, account balances, epoch availability and quorum
state. Each response carries chain/genesis, canonical height/hash, account root
and note root as appropriate. Read available balances at the completed snapshot
height and separately expose claimability in the next block; do not release
balances early in the reported current snapshot. Supply shows G, I, P, A, U,
B, remaining mining issuance and the cap, verifying P+A+U=G+I<=MAX_SUPPLY.

Then add `node/src/native/reward_accounts/rpc.rs`, register read-only methods
and advertise them under the normal safe policy. Accept only typed public
addresses checked against the manifest's exact network. Provide status,
single-account lookup, immutable paginated genesis allocations and bounded
canonical activity. Include explicit unavailable-state responses, strict
parameters and pagination limits. Never accept a runtime root setter, caller
ledger snapshot, account mutation or private wallet key through these methods.

Canonical activity includes explicit donations with UTF-8 public memos, claims
with public amount/fee and shielded recipient, certified signer proposals and
implicit reward allocations. A reward record has no memo. Record block hash,
height, action identity/index and earning/release epoch information. Validate
stored action commitments; do not present orphaned rows as canonical. Bound the
number of scanned blocks as well as returned rows. Snapshot-bound cursors must
reject reorgs and malformed offsets, and clients must discard or mark stale
responses on canonical changes. Any persistent explorer index must undo orphan
history before applying replacement blocks.

Once the actual explorer source is available, inspect its own AGENTS.md and
architecture before editing. Add Treasury, Reward Accounts, Genesis/Supply and
Governance routes, account links from blocks and address search. Treasury shows
available/pending totals, release buckets, donation memos and withdrawal history.
An account shows exact balance, next sequence, earning/release buckets and public
activity. Genesis shows initial allocations separately from current balances.
Governance shows N-of-M, ordered signer-key hashes, current generation and pending
certified replacement; never imply arbitrary mutable governance or finality.
Use the existing brand system and responsive accessible controls. Render memos
and addresses as text, preserve full values for copy, and use BigInt for atoms.

Finally extend the parent disposable-chain qualification to the actual explorer:
index a donation and partial claim, observe first-block release after N+2,
rotate signers without moving the pot, reorg across release and claim history,
restart the indexer and synchronize a fresh instance. Compare every displayed
snapshot with canonical RPC and exact supply. Keep inactive/legacy tests separate
from these activation-dependent acceptance cases.

## Concrete Steps


Load `/workspace/toolchains/env.sh` for Rust commands. Run focused node tests
with `cargo test -p hegemon-node --release --no-default-features --lib
reward_accounts_explorer --offline`, plus the native storage and network-profile
regressions after changes. Use scoped rustfmt and `git diff --check`. Record
nonzero test matches. Existing Development-feature tests may need the explicit
features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts.

Record actual explorer setup, build, browser and integration commands after
locating its source; do not invent a successful frontend build. If it is in a
separate repository, create an isolated matching branch and publish scoped
changes there, linking both commits in this plan. Keep main unmodified.

## Validation and Acceptance


For E=1440, h1 and h1440 credits release at h2881, not h2880. A snapshot at h2880
reports the old available amount, pending epoch-zero credits and next-block
claimability; h2881 reports those credits as available. Current-block rewards
remain pending. Release heights are block estimates, with no guaranteed elapsed
time or finality. Test the equivalent boundaries with E=2.

Prove atom-exact G+B=MAX_SUPPLY and P+A+U=G+I for empty, partially funded and fully
allocated genesis. Reject cap overflow, wrong-network addresses, malformed or
extra parameters, negative/fractional pagination and stale snapshot hashes.
Distinguish inactive/legacy data from a valid active zero balance. Verify fork
approval count, stable treasury identity and pending-certificate generation.
Memos containing HTML must render literally; long PQ recipient addresses must
wrap/copy without changing them. Indexers and clients must recover from reorgs,
partial fetches, node disconnection and restart without mixing snapshots.

## Idempotence and Recovery


Read APIs never initialize storage, repair an index or mutate the ledger. Keep
all tests in disposable directories and preserve existing public-chain data.
The explorer must verify chain/genesis before reusing an index. Reorg invalidates
all cursors into orphaned snapshots and removes their displayed activity. Retry
reads against a fresh canonical snapshot rather than retaining a plausible zero
or partially fetched history. No deployment is authorized by this plan.

## Artifacts and Notes


The initial backend API contract and measured test results will be recorded
here as implemented. The missing explorer source location is an explicit input,
not an inferred need for user permission to perform the authorized changes.

## Interfaces and Dependencies


Use existing serde_json, serde, protocol-reward-accounts and canonical native
storage helpers. Add no new consensus or proof dependency for visualization.
The public API methods are hegemon_rewardAccountsStatus, hegemon_rewardAccount,
hegemon_rewardAccountsGenesis and hegemon_rewardAccountsActivity. A canonical
snapshot is the account ledger, its matching canonical block and note root;
these must be read under the existing publication/persistence lock order. No
caller flag can label an unverified ledger as active. The future canonical
account integration must install its verified ledger in the same publication as
the block and notes before these APIs can return active balances.

Revision note (2026-11-05 UTC): add the user's requested explorer scope, public
API work and activation-dependent visual acceptance to the treasury project.

Revision note (2026-11-05 UTC): the user confirmed the explorer source location
is pending Pierre's reply and deferred that UI integration. Finish independent
backend/API work here. No replacement explorer or visual acceptance is claimed.

Implementation evidence (2026-11-05 UTC): native RPC dispatch advertises all four
methods under Safe policy, and a real legacy node returns explicit unavailable
state through both normal dispatch and the production HTTP body handler.
Database-tree snapshots remain equal before/after those requests. Verified
shared-ledger transitions exercise exact supply, N+2 release projections and
real 5-of-7 signer-certificate metadata. Canonical-body fixtures cover bounded
history scans, filtered empty pages, within-block continuation and rejection of
altered body/fee/context data. They are projection fixtures, not mined blocks or
private-proof acceptance. Native publication and explorer/indexer integration
remain prerequisites for active-chain visual acceptance.

Discovery: the first epoch-display test caught the boundary label being computed
from the next block's epoch rather than the displayed epoch; at h4 with E=2,
the next boundary must be h5, not h7. Correct the label while preserving the
unchanged release rule. Also encode note-root field words and large epoch
parameters as strings: they can exceed JavaScript's exact integer range even
though normal block heights and the HGN supply cap are smaller.

Final backend validation (2026-11-05 UTC): 19 reward-account tests (including
eight explorer tests), 13 existing network-profile tests and one existing safe
RPC policy test pass on the final source. The production HTTP body handler
returns unavailable legacy state with the expected JSON-RPC id, and complete
database-tree snapshots remain unchanged. New tests cover exact large note-root
words and epoch lengths, canonical decimal-string height continuations,
within-block pagination and sparse filtered scans. Default-feature-disabled node
cargo check, scoped rustfmt, changed-line whitespace and documentation checks
pass. Existing missing historical overview links are retained; no new missing
relative links were introduced. No real-chain, browser or indexer qualification
is implied by these backend tests.

From /workspace/Hegemon, load source /workspace/toolchains/env.sh, then run:

    cargo test -p hegemon-node --no-default-features --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts --release --lib reward_accounts --offline
    cargo test -p hegemon-node --no-default-features --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts --release --lib network_profile::tests --offline
    cargo test -p hegemon-node --no-default-features --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts --release --lib rpc_policy_gates_unsafe_methods --offline
    cargo check -p hegemon-node --no-default-features --offline

Expect selected pass counts 19, 13 and 1, then a successful check. Logs are
reward-explorer-{native-final-tests,network-final-tests,safe-final-tests,node-check}.log
under /workspace/work/environment-setup. The initial no-Development build also
passed eight selected explorer tests. New documentation is
[docs/PROTOCOL_TREASURY_EXPLORER_API.md](../docs/PROTOCOL_TREASURY_EXPLORER_API.md).

Revision note (2026-11-05 UTC): complete and qualify backend preparation while
honoring the user's pause on the actual explorer UI/indexer. Preserve the v2
runtime startup guard; API reads cannot substitute for source-owned native
account publication, proof qualification or two-node visual acceptance.

Publication record (2026-11-05 UTC): a58b2757b8ffc592ce72a175bcccf78ae765a741
is the tested backend/API commit. GitHub's branch head matched that exact hash;
immutable API-contract readback confirmed all four method names and the paused
UI integration. This follow-up records completed publication only and changes
no runtime source or validation claims.


Revision (2026-11-05 ET): The user supplied
`https://github.com/Pauli-Group/hegemon-website` and required a new branch for
any changes there. Source is now cloned at `/workspace/hegemon-website`, based
on `main` commit `c40a2b5`, with branch `codex/explorer-treasury-rewards`.
This resumes the paused UI/indexer phase; no deployment or native activation
is implied. The website repository will carry its own implementation/check log.
