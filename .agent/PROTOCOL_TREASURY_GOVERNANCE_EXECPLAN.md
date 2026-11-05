# Implement a public treasury pot and fixed-quorum governance

This ExecPlan is a living document maintained under `.agent/PLANS.md`. Keep
Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective
current. The complete proposed protocol is in `docs/PROTOCOL_TREASURY_DESIGN.md`.

## Purpose / Big Picture


Replace the fresh network's wallet-funded treasury with a public balance checked
by every node. Miners implicitly contribute one fifth of each block subsidy,
users can make permissionless transparent donations with optional public memos,
and a fixed quorum of post-quantum signers can authorize payouts into the normal
shielded note pool. Signer replacement needs both a software hard fork and
approval from the current quorum. The feature is intended for a complete chain
reset after qualification, not migration of the current pre-mainnet.

An operator will be able to inspect the treasury without a wallet key, donate,
prepare a payout for offline signatures, combine those signatures and submit it.
A fresh node will derive the same balance, policy and sequence by replaying the
chain. A real two-node lifecycle must demonstrate these behaviors before the
branch is reported as implementing the protocol.

## Progress


- [x] (2026-11-05 UTC) Read AGENTS.md, PLANS.md, relevant DESIGN.md/METHODS.md
  sections and current reward, spend-statement, supply and checkpoint code.
- [x] (2026-11-05 UTC) Fetch main at 74910ff86514c2cbd93d7a7039e6b90b6e4600b6
  and create local/GitHub branch codex/protocol-treasury-governance.
- [x] (2026-11-05 UTC) Write protocol design, accounting invariants and phased
  implementation/validation plan.
- [ ] Commit and publish the design milestone and verify remote file contents.
- [ ] Implement deterministic treasury transitions and real ML-DSA approvals.
- [ ] Implement and qualify donation and payout proof relations/carriers.
- [ ] Integrate state, mandatory rewards, action admission, persistence and replay.
- [ ] Add fork-certificate activation, reset manifests, RPC and CLI lifecycle.
- [ ] Run adversarial/property/real-proof tests and two-node restart/reorg/sync.
- [ ] Publish complete implementation and validation results on the same branch.

## Surprises & Discoveries


The current network funding recipient is enforced by host accounting, and its
allocated reward action creates two notes. Omitting the reward action forfeits
both shares today. A mandatory protocol credit therefore also changes the
optional reward transition rule, which must be intentional and tested.

The v4 spend public statement has 86 words, no donation amount and no public
memo binding. Its circuit equation is private inputs = private outputs + fee.
A host-only debit or classifying a donation as a fee cannot implement a treasury
transfer with sound accounting. Fresh proof source and qualification are needed.

The HTTP proxy is unreachable through ordinary sandbox execution. Fetching
main with the normal escalated execution path succeeded. The branch was created
on GitHub through the GitHub connector. No credentials were printed or replaced.

## Decision Log


Decision: Represent the allocation as compiled integer numerator/denominator
constants 1/5. Rationale: the user explicitly requires hard-fork-only changes;
floating point and configurable manifest fractions would violate this.
Date/Author: 2026-11-05 UTC, user requirement recorded by Codex.

Decision: No notice, caps, expiration or emergency pause. Rationale: explicitly
excluded by the user. Replay prevention and insufficient-balance rejection are
validity requirements, not extra spending restrictions.
Date/Author: 2026-11-05 UTC, user requirement recorded by Codex.

Decision: Retain 120-block maturity for treasury subsidy credits; make donations
usable from the following block and payouts ordinary notes. Rationale: reuse
existing reward eligibility without adding a second coinbase delay to transfers.
The user delegated the maturity implementation choice.
Date/Author: 2026-11-05 UTC, Codex proposal.

Decision: Require a reward transition on every non-genesis block, even with zero
subsidy. Rationale: make treasury funding genuinely implicit in block production
and ensure the exact allocation cannot be omitted. Fees remain miner revenue.
Date/Author: 2026-11-05 UTC, Codex proposal.

Decision: Donations have optional public UTF-8 memos capped at 256 bytes;
subsidy credits have no memo. Rationale: user distinction, bounded decoding and
binding of the exact public bytes to the donation proof.
Date/Author: 2026-11-05 UTC, user scope plus Codex encoding proposal.

Decision: One payout per withdrawal, transparent amount and recipient address,
private note opening, separate signed miner fee and monotonically increasing
sequence. Rationale: a small auditable authorization surface with deterministic
replay protection. Recipient disclosure is explicit and can be revised at design
review; it is not a claim of hidden recipient identity.
Date/Author: 2026-11-05 UTC, Codex proposal.

Decision: Signer replacement preserves N/M, is authorized by current N-of-M,
and takes effect only with a matching compiled successor at a certified height.
Rationale: user requires both hard fork and the withdrawal quorum; a standalone
key-rotation transaction would not satisfy both conditions.
Date/Author: 2026-11-05 UTC, user requirement plus Codex activation proposal.

Decision: N/M and the ordered public keys are genesis parameters. This reset
uses the user-confirmed 5-of-7 policy. Validate 1 <= N <= M <= 16; the maximum
is a resource bound, not a baked-in network quorum. Actual public keys are
launch inputs. Rationale: the user explicitly prefers defining the quorum at
genesis and test secrets must not become real governance credentials.
Date/Author: 2026-11-05 UTC, Codex.

Decision: Start at zero on fresh genesis, with no balance migration, live reset
or deployment in this task. Rationale: user requests a reset after the changes
and a GitHub implementation branch; resetting existing services is a separate
operator action after implementation acceptance.
Date/Author: 2026-11-05 UTC, user scope recorded by Codex.

## Outcomes & Retrospective


The design milestone specifies the proposed state machine, privacy surface,
quorum/fork authority, accounting equations and acceptance evidence. No runtime
code has changed. Proof implementation, node/wallet integration and end-to-end
qualification remain outstanding; this branch must not yet be described as a
working treasury system.

## Context and Orientation


Work in `/workspace/Hegemon`. This Rust workspace has a native proof-of-work
node in `node/`, monetary schedule and validation in `consensus/`, post-quantum
primitives in `crypto/`, wallet builders in `wallet/`, and proof definitions in
`circuits/transaction/`. A note is a commitment to a private value and owner;
a nullifier prevents that note from being spent twice. A proof verifies private
facts without publishing them. A state commitment authenticates resulting chain
state so independent nodes agree on more than an unauthenticated local table.

The current funding path is
`node/src/native/node_impl.rs::build_allocated_reward_action` and
`node/src/native/block_flow.rs::validate_coinbase_funding_accounting`.
`consensus/src/reward.rs` defines subsidy and supply constants. Native supply
replay runs through `advance_native_supply_digest` and
`native_block_replay_supply_parts` in `node/src/native/block_flow.rs`.
`node/src/native/mod.rs::NativeState` holds notes/nullifiers and
`NativeCanonicalStateCheckpointV1` captures canonical replay state. Extend the
actual active block/checkpoint identities; do not silently modify retained
historical wire schemas.

`node/src/native/network_profile.rs` validates manifests and derives network
identity. `protocol/versioning/` owns rule/proof version identities and reward
maturity. `circuits/transaction/src/private_spend/{types,circuit,proof}.rs`
implements current private-spend statements and proofs;
`wallet/src/private_spend_build.rs` assembles them. Reward builders live in
`wallet/src/poseidon2_v8_coinbase.rs` and their circuit in
`circuits/transaction/src/smallwood_poseidon2_v8_coinbase.rs`.
`node/src/native/rpc.rs` exposes node readback. Follow existing wallet CLI
registration and encrypted-store patterns rather than putting keys in RPC.

The proposed state machine is defined in the companion design document. In brief,
release mature subsidy credits at block start; execute actions sequentially with
current mature funds; only credit included donations at block end; then apply
the unique miner reward and enqueue the treasury subsidy for h+120. A withdrawal
debits amount plus fee, creates one equal-value note and increments the exact
sequence. Signer replacement activates at block start before actions and
increments the policy epoch without resetting the withdrawal sequence.

## Plan of Work


### Milestone 1: deterministic state and authority


Create `consensus/src/treasury.rs` and export it from the consensus crate. Define
compiled subsidy constants and checked arithmetic, bounded maturity state,
canonical signer policy, withdrawal payload, quorum certificate, fork
certificate and pure transition functions. Domain-separated message hashing
must use `crypto::hash384::blake2b_384_domain_hash`; signature verification must
use `crypto::ml_dsa` and `crypto::traits` rather than invented signature checks.
State changes are prepared on a candidate and committed only after every check
passes. Numeric action and wire identifiers must be allocated after searching
the complete protocol registry.

Write unit and property tests using genuine ML-DSA signatures: N-1 fails, N
passes, repeats do not count, changed payload or chain/policy fails. Exercise
maturity at h+119/h+120, donation availability, sequence conflicts, insufficient
funds, checked overflows, zero subsidy, rounding and rejected-action atomicity.
This module is a foundation, not an activated treasury. Acceptance is passing
transition tests with the design's P+Q=I invariant across generated histories.

### Milestone 2: donation and payout proofs


Add a successor donation relation extending the public statement with donation
amount and exact memo hash, and enforce inputs = outputs + donation + fee. Keep
native assets and permitted spend modes explicit. Bind fields in the canonical
proof statement and action body, not just unsigned host metadata. Update wallet
builders, range checks, proof/compiler identities, carriers and decoders.

Add a payout relation proving one native note of the authorized public amount
and full recipient policy while hiding its opening. Bind included ciphertext
using the existing encryption semantics, documenting precisely what is and is
not proved about delivery. The node must compare payout public fields to the
quorum payload. This proof may not create spendable value until a matching pot
debit is accepted. Avoid revealing reward-style public openings for withdrawals,
since that could weaken the desired future spend unlinkability.

Generate real proofs and negative fixtures for altered amounts, recipient,
ciphertext, fee, memo and public context. Requalify changed relation/compiler
source and do not reuse v4 measurements as evidence. Acceptance requires genuine
proof verification and rejection of mutated public data, not mock verifiers.

### Milestone 3: block/state/replay integration


Replace the new network's funding-note reward path with a miner note plus a
deterministic pot credit. Require exactly one reward transition per block;
reject legacy funding bundle routes under the new genesis. Extend
`NativeState`, commitments, canonical checkpoints, persisted snapshots, fork
preparation, startup replay, sync and mining template state with the treasury.
Ensure `block_flow.rs` fee projection handles donation/withdrawal fees once and
counts pot transfers as zero new supply. Integrate successor proofs in the same
nullifier/commitment machinery used by normal native actions.

Use one canonical state-transition routine for simulation and import. Publish
treasury snapshots in the same storage transaction as the tip, nullifiers,
commitments and supply. Tests must corrupt persisted pot values, omit or double
credit rewards, duplicate a withdrawal and propose same-block donation spending;
every invalid candidate rejects without partial publication. Acceptance includes
restart and reorganization restoring exact balances, maturity queue and sequence.

### Milestone 4: certified forks, reset identity and tools


Add scheduled signer-replacement certificates for one pending transition, with
current-policy N-of-M approval and exact future height/successor rules binding.
Activation is permitted only by installed matching hard-fork code. At activation
replace keys, increment policy epoch and retain the withdrawal sequence. Test
both sides of the boundary and reorgs removing scheduling or activation.

Replace the reset profile's funding address/fraction fields with initial policy
and compiled treasury-rules identity. Validate N/M, distinct real-format public
keys and absence of known fixture keys in launch profiles. Genesis starts at
zero, includes policy identity, and rejects the old database identity. No live
state deletion is part of code validation.

Expose read-only treasury status/history with canonical height/hash in
`node/src/native/rpc.rs`. Add wallet CLI donation and offline prepare/review/sign/
combine/submit/status workflows for payouts and fork certificates. Real keys
stay in encrypted signer storage. Public memos are escaped plain text. An
ambiguous submission is reconciled against canonical state before retrying;
retrying never creates a second withdrawal intent silently.

Update `README.md`, `DESIGN.md`, `METHODS.md`, versioned network configuration
and reset/operator runbooks to describe actual implemented behavior once it
exists. Preserve historical release evidence. Acceptance is an isolated CLI
demo using disposable keys and real proofs, with status showing the exact same
balance and sequence on two nodes.

### Milestone 5: qualification and branch delivery


Run the focused tests, supply properties, malformed-input cases and real-proof
lifecycle, then full required repository checks appropriate to changed crates.
Start disposable nodes with agreed seeds and synchronized clocks. Mine through
120-block maturity, donate with a public memo, obtain N approvals offline,
withdraw, spend the payout normally, restart, force a local fork/reorg, activate
a certified replacement and synchronize a fresh node. Preserve test commands,
source hashes, proof identities and concise receipts in the plan and tracked
validation document. Distinguish inherited old evidence from new results.

Commit implementation milestones separately and push this branch without merging
main or deploying. Verify the GitHub head matches the tested local commit.
Report real results and remaining failures; a design or transition-only module
is not completion of the requested implementation.

## Concrete Steps


Initial research was performed with `git fetch origin main`, `git rev-parse
origin/main`, source reads and registry searches. The fetched base is
74910ff86514c2cbd93d7a7039e6b90b6e4600b6. Local work is on
`codex/protocol-treasury-governance` and the remote branch exists at that base.

Before runtime code changes, honor first-run instructions in AGENTS.md using
`make setup`, then `make node`. Inspect setup requirements and available
toolchains; record concrete failures rather than pretending a baseline build
passed. Use `work/` for intermediate logs/fixtures, never key material in Git.

After adding the foundation run, from the repository root:

    cargo test -p consensus treasury
    cargo fmt --all -- --check

After proof integration:

    cargo test -p transaction-circuit treasury
    cargo test -p wallet treasury

After node integration:

    cargo test -p hegemon-node --no-default-features treasury
    make node

Add tests with `treasury` in their names so these focused selectors are real.
Inspect test output and fail validation if selectors match zero tests. Extend
this section with the exact real-proof/CLI/two-node commands as those interfaces
are implemented. Broad selectors alone do not establish end-to-end acceptance.

For design-only validation run `git diff --check`, check every referenced source
path/symbol, inspect links and confirm current behavior is clearly distinguished
from proposed behavior. Runtime tests are not necessary for this initial docs
commit and must not be reported as passing.

## Validation and Acceptance


The core conservation equations are P+Q=I, Q=mature+immature and I<=MAX_SUPPLY,
where P is conceptual private-pool value and I is issued subsidy. For each
donation D and fee F, private inputs debit D+F, the pot credits D and miner fees
credit F. For payout A and fee F, pot debit is A+F and pool credits are A and F.
Subsidy S credits the pot floor(S/5) and the miner the remainder. Maturity moves
only treasury partitions. No failed transition changes any component.

Negative acceptance covers wrong network/genesis/rules/policy, duplicate signer,
N-1 approvals, malformed signatures, altered amount/fee/memo/recipient/output,
same sequence twice, old epoch after rotation, stale proof reference,
insufficient mature balance, overflow, old reward route, missing/duplicate reward
transition, counterfeit donation and payout note, and certificate for an
unimplemented successor. Tests must include actual signatures and actual proofs
for the respective cryptographic claims.

End-to-end acceptance is exact canonical agreement after mining, donation,
withdrawal, normal payout spend, restart, reorg, fork activation and fresh sync.
Include clean-build evidence, applicable security/qualification requirements,
and final git/remote hashes. Do not label fixtures as launch credentials.

## Idempotence and Recovery


Keep all work on the dedicated branch. Re-running design checks has no runtime
effect. Run node qualification in fresh disposable directories and stop only
processes owned by the test. Preserve old chain state and wallet backups; never
delete pre-mainnet data to make a test pass. Replay should recreate the same
treasury state. An interrupted database transaction publishes all block state
or none. A fork certificate invalidated by reorg loses its authority with the
orphaned inclusion. Failed or ambiguous broadcasts are reconciled by sequence,
policy and canonical action identity rather than generating duplicate payments.

## Artifacts and Notes


Initial artifacts are this execution plan and `docs/PROTOCOL_TREASURY_DESIGN.md`.
At the design milestone no treasury runtime or proof code has changed, no build
or node lifecycle has been run, and no running chain has been reset. Subsequent
milestones must replace this status with exact observations, not inferred success.

## Interfaces and Dependencies


The foundation should expose `TreasuryState`, `TreasuryPolicy`,
`TreasuryWithdrawal`, `TreasuryForkCertificate`, `TreasuryError`,
`treasury_subsidy(height)`, `verify_withdrawal_authorization`,
`verify_fork_authorization`, and a candidate block transition API. Keep signature
verification separate from pure accounting so tests can exercise each while
production callers must pass the combined authenticated admission result.
Production transition APIs must not accept an arbitrary boolean named verified.

Use existing ML-DSA-65 key parsing and verification, existing 48-byte consensus
domain hashing, existing native note primitives, and the protocol-versioning
registry. Do not add ECC, a second private pool, a generic administrative
execution engine, or a treasury proof bypass. Carriers, state serialization,
genesis schema and RPC formats need explicit versions and bounded decoding.

Revision note (2026-11-05 UTC): created the design-first implementation plan to
capture the user's agreed scope and identify proof/accounting integration work
before runtime edits. The user confirmed 5-of-7 with genesis-configured threshold and keys; the
16-signer maximum bounds decoding and signature-verification work.
