# Implement epoch reward accounts, treasury governance and genesis allocation

This ExecPlan is a living document maintained under `.agent/PLANS.md`. Keep
Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective
current. The companion specification is
[docs/PROTOCOL_TREASURY_DESIGN.md](../docs/PROTOCOL_TREASURY_DESIGN.md).

## Purpose / Big Picture


Replace per-block reward notes with public accounts. Miners and the treasury
accumulate exact block entitlements, which become available after two reward
epoch boundaries. Owners can claim multiple rewards as one shielded note.
Optional genesis distributions fund tests or an explicit launch distribution
without increasing the 21-million-HGN supply cap. Public account ownership is
identified by key/policy hashes; both public and shielded addresses visibly
identify mainnet versus test networks and enforce that distinction in decoding.

An operator will inspect pending/available balances, donate with a public memo,
claim available rewards and obtain offline treasury quorum signatures. A fresh
node will derive the same accounts, supply, epoch releases and policy by replay.
The branch is not a working protocol until the real-proof and two-node lifecycle
passes. The currently authorized revision updates documentation only; runtime
implementation, deployment and reset are subsequent milestones.

## Progress


- [x] (2026-11-05 UTC) Read AGENTS.md/PLANS.md and inspect reward construction,
  supply, private-spend statements, checkpoints and address codecs.
- [x] (2026-11-05 UTC) Create branch codex/protocol-treasury-governance from
  main 74910ff86514c2cbd93d7a7039e6b90b6e4600b6 and publish initial design.
- [x] (2026-11-05 UTC) Confirm genesis-configured 5-of-7, 1,440-block reward
  epochs and genesis allocations deducted from the remaining mining budget.
- [x] (2026-11-05 UTC) Inspect CIP-19/CIP-5 and current Bech32m shca codec;
  specify network-aware account and shielded addresses.
- [x] (2026-11-05 UTC) Revise the design, milestone sequence and overview
  references for epoch accounts, genesis budgets and typed address validation.
- [x] (2026-11-05 UTC) Validate links, terminology, six milestones, source
  paths, whitespace, boundary arithmetic and allocation/supply equations.
- [x] (2026-11-05 UTC) Publish revised documentation in eedd8da6 and verify
  the network-aware address specification through GitHub readback.
- [ ] Implement genesis identities, addresses, allocations and adjusted issuance.
- [ ] Implement account transitions, reward epochs and real ML-DSA authorization.
- [ ] Implement and qualify donation and account-claim proofs/carriers.
- [ ] Integrate rewards, authenticated storage, replay, startup, sync and reorg.
- [ ] Implement certified treasury forks, offline signing, RPC/CLI and dev tools.
- [ ] Run property, adversarial, real-proof and two-node qualification.
- [ ] Publish tested runtime implementation on this branch.

## Surprises & Discoveries


The current allocated reward action creates two notes and can be omitted,
forfeiting subsidy. The successor instead requires one deterministic reward
transition in every non-genesis block, even with zero subsidy. This is a
consensus change, not a wallet-address substitution.

Current v4 private-spend has 86 public words, no donation amount or memo binding,
and balances private inputs against outputs plus fee. Donation and claim proof
changes require fresh relation/compiler identities and real qualification.
The existing long BLOCKS_PER_EPOCH is the 2,100,000-block issuance interval,
not the new 1,440-block reward epoch. Rename conceptually without silently
changing historical schedule bytes or evidence.

`wallet/src/address.rs` uses Bech32m with a single shca prefix, no network
field and a full post-quantum encryption key. That key alone is 1,568 bytes;
shielded addresses cannot satisfy the standard Bech32 90-character limit.
CIP-19 explicitly permits longer encodings and carries a binary network tag;
CIP-5 defines addr versus addr_test. Our successor adopts the network/type
pattern, retains Bech32m and explicitly bounds longer inputs.

An HRP checksum detects accidental changes but cannot authorize a chain or
prevent deliberate re-encoding. Include network class and an independent
genesis-committed discriminator in the payload, and bind operations to chain
and genesis separately. Do not derive the discriminator from a genesis identity
which itself contains encoded addresses.

Earlier sandbox git fetch failed to reach proxy:8080; the standard escalated
execution path succeeded. Preserve configured proxy/credentials and use normal
approval handling for an authorized remote operation rather than bypassing it.

## Decision Log


Decision: Preserve the compiled 1/5 treasury fraction, fee/tip revenue entirely
for miners, genesis-configured 5-of-7 and hard-fork-only treasury replacement
approved by the current quorum. No notice, caps, expiry or pause.
Rationale: explicit user requirements, unchanged by account aggregation.
Date/Author: 2026-11-05 UTC, user requirements recorded by Codex.

Decision: Supersede the initial proposed rolling 120-block maturity and per-block
miner notes with reward accounts and N+2 release. E=1,440 blocks is configured at
genesis, immutable during ordinary operation. Rename signer epoch to policy
generation and the old subsidy interval to issuance era in successor prose.
Rationale: user selected epoch accounting and the concrete epoch length.
Date/Author: 2026-11-05 UTC, user selection recorded by Codex.

Decision: Subsidy, fees and transaction tips earned in N all release at N+2;
tips reward the actual including miner and appear once in total fee accounting.
Genesis allocations are immediately available; private donations become usable
from the following block; claims create ordinary shielded notes with no new
reward delay. Rationale: keep block-derived rewards in one availability system
without imposing another reward delay on transfers of existing eligible value.
Date/Author: 2026-11-05 UTC, agreed plan recorded by Codex.

Decision: Supersede the zero-only genesis and unchanged full mining budget.
Allow optional allocations G and apply the existing exact issuance curve to
B=MAX_SUPPLY-G. Empty distribution is default. Rationale: the user selected a
fixed 21-million cap with proportionally reduced mining issuance, allowing
funded development fixtures and an explicit future production distribution.
Date/Author: 2026-11-05 UTC, user selection recorded by Codex.

Decision: Use single-key/threshold policy-hash accounts, with full keys and
signatures disclosed at claim, and account-scoped sequences. Preserve public
claim amount/recipient disclosure and private note openings. Rationale: compact
post-quantum ownership identifiers and reuse of one claim mechanism for miners,
genesis recipients and quorum-controlled treasury funds.
Date/Author: 2026-11-05 UTC, agreed plan recorded by Codex.

Decision: Add HRPs heg/heg_test for accounts and heg_shield/heg_shield_test for
shielded recipients, with Bech32m checksum, binary kind/class/discriminator and
strict current-network decoding. Historical shca is inspection-only on reset
networks. Rationale: user requests Cardano-like mainnet/testnet safety for both
families; retaining the existing checksum variant keeps Hegemon codec behavior
explicit while introducing fresh network-aware formats. Independent discriminator distinguishes reset testnets.
Date/Author: 2026-11-05 UTC, user revision plus Codex codec design.

Decision: Keep optional vesting, ordinary account transfers/rotation, standalone
named-miner donations, general governance and live reset out of v1. Actual keys,
launch discriminator and production allocation amounts are later launch inputs.
Rationale: those capabilities were discussed but not included in the accepted
documentation plan; they must not become unrequested runtime features.
Date/Author: 2026-11-05 UTC, scope recorded by Codex.

## Outcomes & Retrospective


The initial design is already published. This revision replaces its maturity,
miner-note and zero-genesis assumptions and adds network-aware public/shielded
addresses. No runtime, proof or codec implementation has changed. Subsequent
milestones remain outstanding, and no build, node lifecycle or chain reset is
claimed for a documentation revision. Documentation checks passed: relative links, required headings and six milestones,
source paths, terminology, README structure, release examples, exact supply
budgets and completed-block conservation arithmetic. Runtime tests were not run
for these documentation-only edits. Revision eedd8da6 was pushed successfully;
GitHub readback confirmed the new account/shielded HRPs and binary network
validation specification.

## Context and Orientation


Work in `/workspace/Hegemon` on codex/protocol-treasury-governance. Rust crates
separate node validation (`node/`), issuance/consensus (`consensus/`), crypto
(`crypto/`), wallet (`wallet/`) and proofs (`circuits/transaction/`). A note is a
commitment to private value and ownership. A nullifier prevents double spending.
A proof checks private facts against public bindings. A state commitment lets
other nodes authenticate the complete result, including public account state.

Relevant current entrypoints are
`node/src/native/node_impl.rs::build_allocated_reward_action`,
`node/src/native/block_flow.rs::validate_coinbase_funding_accounting`,
`advance_native_supply_digest` and `native_block_replay_supply_parts`.
`consensus/src/reward.rs` owns the exact subsidy curve and cap;
`protocol/versioning/` owns proof/rules and legacy maturity identities.
`node/src/native/mod.rs::NativeState` and canonical checkpoints need accounts,
epoch state and authenticated availability alongside notes/nullifiers.
`node/src/native/network_profile.rs` validates genesis manifests.

`wallet/src/address.rs::ShieldedAddress` currently has context-free encode/decode
and the shca HRP. Add separate typed account addresses and network-aware codecs;
audit every callsite, including walletd, desktop app, miners and offline tools.
`crypto/src/ml_dsa.rs` and its traits supply ML-DSA-65 signing/verification;
`crypto::hash384` supplies domain-separated 48-byte hashing. Private-spend types,
circuit and proof code are in `circuits/transaction/src/private_spend/`;
wallet builders are in `wallet/src/private_spend_build.rs`.

For E=1,440, height zero is genesis; epoch(h)=floor((h-1)/E) for h>=1 and release
height for rewards earned in N is (N+2)*E+1. Thus blocks 1 and 1,440 both release
at 2,881, before its transactions. Only current/preceding earning epochs remain
pending after releases; use lazy normalized account state or bounded indexes
rather than a full-account sweep on each boundary. Policy generation is a
separate treasury authorization version. Era length L remains 2,100,000 blocks.

Let G be sorted genesis allocation sum and B=MAX_SUPPLY-G. Era budget k is
(B>>k)-(B>>(k+1)), treating shifts >=64 as zero. Block h uses era k=(h-1)/L,
slot j=(h-1)%L and subsidy floor((j+1)*budget/L)-floor(j*budget/L). Use wide
intermediates. Genesis is immediately available; all future rewards sum to B.
Conservation is P+A+U=G+I<=MAX_SUPPLY, with P shielded value, A all available
accounts, U all pending accounts and I cumulative mining issuance.

Address HRPs are heg/heg_test for policy-hash accounts and
heg_shield/heg_shield_test for shielded recipients. Bech32m envelopes include
version, kind, class, independent 32-byte genesis network discriminator and
body. Account body is a 48-byte policy identifier; shielded body retains full
recipient/authorization and encryption material. Bound encoded input at 256 and
4,096 characters respectively and verify exact decoded shape. Emit lowercase;
normalize valid uniform uppercase, reject mixed case. Match HRP, payload and
selected network. Old shca belongs only to explicit historical inspection.

## Plan of Work


### Milestone 1: genesis identities, address codecs and issuance


Add genesis-committed reward_epoch_blocks (reset default 1,440), independent
network class/discriminator, canonical initial treasury policy and optional
sorted allocation rows. Validate positive E, nonzero discriminator, policy
hashes, distinct recipients, positive amounts, checked sum G<=MAX_SUPPLY and
N/M bounds. Treasury allocations must name the active treasury policy. Default
to no allocations and no inferred real launch keys. Bind the adjusted budget
and all new rules into a fresh manifest/network identity.

Add PublicAccountAddress and explicit network-aware address APIs alongside
ShieldedAddress. New envelopes identify version, kind, class and discriminator.
Preserve Bech32m; enforce the documented HRPs, exact typed body, padding and
bounds before wallet construction/signing. Keep raw consensus/genesis account
identifiers distinct from UI encodings. Supply vectors for all four prefixes,
large shielded addresses, bad checksums/variants, wrong network/class/type,
deliberately relabeled HRPs and old shca rejection. Codec changes require all
current operational callsites to receive the selected network explicitly.

Parameterize the exact issuance curve by B=MAX_SUPPLY-G, leaving era length and
atom rounding unchanged. Add a fresh schedule identity. Test empty, partial,
full and rejected excess allocations, tiny residual mining budgets, era edges
and exact eventual issuance. Acceptance is successful focused consensus and
wallet address tests, with no zero-test selectors treated as evidence.

### Milestone 2: account state, epochs and real authorization


Introduce shared public account state with available/pending balances, account
claim sequence and canonical policy descriptor/hash. Single-key and threshold
policies use existing ML-DSA-65, distinct signer-key hashes and the configured
quorum, not boolean verified flags. Implement checked release at N+2 and
candidate transitions that publish only after all checks. Bind claims to chain,
genesis, rules, account, policy generation where applicable, sequence, amount,
fee and output destination. Owner authorization does not register arbitrary
transfers or privileged minting.

Property tests must preserve P+A+U=G+I. Exercise first/last blocks of epochs,
first-block claims, partial claims, insufficient available balance, duplicate
signers, N-1 approvals, wrong key/policy/network, altered payload and replay.
Use actual signatures. Acceptance is a genuine 5-of-7 claim authorization test
plus tests for other valid genesis-selected thresholds and exact release heights.

### Milestone 3: donation and account-claim proofs


Add a fresh donation relation/carrier with public amount and authenticated memo,
separate total fee and the existing chain/reference/nullifier/output bindings.
Enforce private inputs=change+donation+fee. Memos have a 256-byte UTF-8 limit,
empty canonical omission and a domain-separated exact byte/length commitment.
Only donations have public memos; implicit subsidy credits do not.

Add a shared account-claim payout relation proving native HGN note value and
recipient policy while hiding opening/randomness/nullifier. Bind ciphertexts
under the actual implemented encryption guarantees. Compare proof public fields
to the exact approved claim payload, including the network-aware shielded
recipient; a signed arbitrary commitment is not sufficient to prevent inflation.
Debit amount+fee once, create one amount-valued note and credit fee to pending
miner rewards at block end. No extra coinbase delay applies to claimed notes.

Generate genuine proofs and mutated-amount/fee/memo/recipient/output/network
negative fixtures. Allocate new relation/compiler/carrier identities through
the existing registry after checking retained values. Requalify changed source;
do not reuse v4 evidence as qualification. Acceptance requires actual proof
verification, normal spending of a claimed note, and rejection of tampered data.

### Milestone 4: block rewards, storage, replay and reorg


Remove per-block reward-note creation from the successor admission path. At
block start activate any authorized compiled fork and release due epoch buckets;
process actions; at block end credit deferred donations and exactly one mandatory
reward transition. For S subsidy, F total miner fees including tips once and
T=floor(S/5), credit treasury T and miner S-T+F to the earning epoch. Zero-subsidy
blocks still execute this transition. Ordinary donations become available only
in the next block. Current-block fees/rewards cannot fund a claim in that block.

Extend active NativeState, authenticated commitments, checkpoints, atomic sled
publication, supply digest, mining templates, mempool simulation, startup replay,
live import, historical/fork replay and sync through one transition routine.
No account credit or claim is extra issuance. A fee already counted as a tip
must not be credited twice. Reject old reward bundles and old identity databases
under the reset rules; do not mutate historical wire formats in place.

Test missing/double rewards, tampered stored balances, wrong miner destination,
same-block donation/reward claiming, stale proofs and failed block atomicity.
Reorg across earning, release and claim boundaries and compare every state
component after restart. Acceptance is exact independent replay agreement, not
an unauthenticated account table beside an unchanged state root.

### Milestone 5: treasury forks, offline tools and readback


Add one pending signer-replacement certificate approved by current N-of-M,
binding successor policy, unchanged N/M, generation, height and compiled rules.
Schedule before activation, reserve the new policy identifier, reject occupied
ordinary-account targets and unrelated use of the reserved target. Activation
moves the whole treasury account to its new policy with balances/sequence
preserved and generation incremented; old-policy claims reject. Reorg restores
policy, reservation, certificate, balances and sequence together. A signature
cannot install unimplemented rules or substitute for hard-fork software adoption.

Expose canonical height/hash, supply breakdown, reward epoch, account policies,
sequences and available/pending balances with release heights through read-only
RPCs. Add network-aware miner payout configuration, wallet/desktop/walletd
address validation and CLI donation/claim/status operations. Offline prepare,
review, sign, combine and relay workflows support claims and fork certificates.
Review exact network, account, amount, fee, destination and approved bytes;
keys never go into nodes, public manifests or Git. Reconcile uncertain inclusion
before creating new intents.

Provide disposable-network tooling with explicitly funded accounts, short
genesis-configured epochs, unique test discriminators and exported matching
wallet contexts. Launch tooling rejects known fixture policies. Update operator
instructions and current architecture/method/whitepaper references as behavior
is implemented, retaining historical evidence. Full-length address paste/export
must work; test QR capacity rather than promising a small QR for large PQ keys.
Acceptance is the actual offline claim/sign/relay workflow on two local nodes.

### Milestone 6: qualification and branch delivery


Run meaningful focused tests, property histories, malformed-input cases, real
proofs and required checks for affected crates. Start disposable nodes with the
same approved seeds/network and synchronized clocks. Exercise genesis-funded
transactions before any rewards mature, miner rewards/fees/tips across N+2,
public donation memos, partial claims and ordinary private spending. Then restart,
force a disposable reorg across a boundary, activate a quorum-certified signer
change and sync a fresh node. Compare accounts, pending releases, sequences,
policies, note/nullifier roots and exact issued supply at the same canonical hash.

Record source hashes, command outputs, proof identities and failure/retry status.
No mock verifier or transition-only module satisfies acceptance. Preserve actual
new evidence separately from historical 120-block/v4 receipts. Push tested
commits to this branch and verify GitHub head without merging or deploying.

## Concrete Steps


From `/workspace/Hegemon`, inspect branch/status and the complete current design.
The original main base is 74910ff86514c2cbd93d7a7039e6b90b6e4600b6. Keep the
existing branch and its history; do not recreate it or force-push.

For this documentation revision run `git diff --check`, validate relative links,
all required ExecPlan headings, terminology and source references. Check the
release examples mathematically and the subsidy telescoping for G=0, a partial
G and G=MAX_SUPPLY. Inspect that only documentation files changed. Record the
actual result, commit, push and verify the remote head. No runtime build or node
test is necessary or claimed for these prose changes.

Before later runtime code changes, honor AGENTS.md first-run instructions with
`make setup` then `make node`; inspect toolchain/setup failures and record them.
Use `work/` for intermediate logs and disposable noncommitted fixtures. Proposed
focused test selectors, to be backed by actual named tests, are:

    cargo test -p consensus reward_accounts
    cargo test -p wallet address
    cargo test -p transaction-circuit reward_accounts
    cargo test -p wallet reward_accounts
    cargo test -p hegemon-node --no-default-features reward_accounts
    cargo fmt --all -- --check
    make node

Inspect output for nonzero matched tests and actual pass/fail status. Add exact
real-proof and two-node lifecycle commands as those runnable interfaces exist;
do not invent successful commands or receipts in advance.

## Validation and Acceptance


With P shielded value, A available accounts, U pending accounts, G genesis and
I mining issuance, preserve P+A+U=G+I<=MAX_SUPPLY. Subsidy increases U and I by
S. Private fee/tip transfers P to U. Donation D and fee F change P by -(D+F),
A by D and U by F. Claim C and fee F change A by -(C+F), P by C and U by F.
Epoch release moves U to A. These are completed-block equations with fees
credited exactly once. Genesis starts P=0,A=G,U=0,I=0.

Reward tests cover blocks 1/1,440/1,441/2,880/2,881, every first/last epoch
position, same-block rewards remaining unavailable, and reorg undo of release
and claim. Expected reset first availability is 2,881 for both block 1 and
1,440 rewards. No current-successor test may use h+120 as eligibility.

Budget tests cover empty/partial/full/excess allocations, duplicate recipients,
zero/overflow amounts, unchanged empty-allocation curve, era boundaries and
atom-exact eventual B issuance including small budgets. Claims test partial
balances, insufficient availability, concurrent sequences, wrong network/
policy/key/generation, N-1 and duplicate signatures, altered proof data and
ciphertexts, memo mutation/length, same-block donations and failed publication.

Address tests cover single/threshold account round trips and all four HRPs,
wrong-network discriminator/class, HRP/payload relabeling, account/shielded
confusion, checksums, original-Bech32 versus Bech32m rejection, case/padding,
oversized/long valid inputs, binary/hex bypasses and legacy shca restriction.
Exercise node/miner configuration, CLI, desktop/walletd, manifests and offline
signing rather than checking the codec in isolation.

Signer-fork tests cover absent/insufficient/mismatched certificates, unimplemented
successor rules, target collision/reservation, old policy after activation,
sequence preservation and reorg through scheduling/activation. End-to-end
acceptance includes real signatures and proofs, normal spend of a claim,
restart, fresh sync and agreement through boundary reorganizations on two nodes.

## Idempotence and Recovery


Documentation checks do not affect a running network. Use the dedicated branch;
commit and push without force or merge. Runtime tests later use fresh disposable
base paths and stop only their own processes. Preserve old databases and wallet
backups; do not delete pre-mainnet state to satisfy identity checks. Block
publication is all-or-nothing. Reorg must restore accounts, epoch releases,
notes, supply, sequences, policy generation, reservations and certificates.
Broadcast retries reconcile canonical identity and sequence; they do not create
duplicate payments. Legacy address inspection never silently converts networks.

## Artifacts and Notes


The principal artifacts are this ExecPlan and
`docs/PROTOCOL_TREASURY_DESIGN.md`, with proposal references in DESIGN.md,
METHODS.md and the README whitepaper. This revision implements the documentation
plan and Bech32 network-label amendment only. No runtime code, proofs, addresses
in deployed configuration, running services or chain data are modified.

Documentation validation observed:

    git diff --check: passed
    links, required headings, six milestones and source references: passed
    blocks 1 and 1440 release at 2881; 1441 and 2880 at 4321: passed
    delay range within earning epoch: 1441 through 2880 blocks
    G=0, partial G, MAX_SUPPLY-1 and MAX_SUPPLY budget arithmetic: passed
    donation/claim/fee/release conservation examples: passed

These are document and arithmetic checks, not tests of a runtime implementation.

CIP-19 and CIP-5 were inspected for Bech32 user encoding, binary network tags,
mainnet/testnet HRPs and long-address conventions. The complete Hegemon choices
are specified here and in the companion design so an implementer does not need
to infer protocol rules from an external standard. Hegemon retains Bech32m and
its post-quantum primitives rather than adopting Cardano's key types or hashes.

## Interfaces and Dependencies


Add shared types for PublicAccountAddress, AddressNetwork, AccountPolicy,
RewardAccountState, RewardEpoch, GenesisAllocation, AccountClaim and
TreasuryForkCertificate. New consensus entrypoints compute genesis-budget-bound
subsidy, epoch/release heights, prepare/apply candidate account transitions and
verify actual claim/fork authorizations. Public codecs require explicit selected
network context; production transaction paths cannot fall back to historical
context-free decoding. Separate pure accounting tests from authorization tests,
but production admission must require both proofs and verified signatures.

Use existing ML-DSA-65 APIs, 48-byte domain hashing, note/encryption primitives,
Bech32m library and protocol registry. Add bounded versioned formats for genesis,
addresses, actions, statements, storage and RPC. Avoid a second private pool,
ECC, a proof bypass or a general-purpose treasury/admin interpreter.

Revision note (2026-11-05 UTC): superseded rolling 120-block maturity, per-block
miner notes and zero-only genesis with the accepted epoch-account/allocation
plan; added policy-hash ownership and the requested mainnet/testnet Bech32m
address distinction for both public and shielded families. Runtime work remains
future scope; only documentation is implemented in this revision.

Revision note (2026-11-05 UTC): recorded completed documentation validation and
successful publication/readback of eedd8da6. Runtime milestones remain unchecked.
