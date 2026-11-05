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
passes. Runtime implementation is now authorized by the user. Deployment and the live
chain reset remain separate later operator actions.

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
- [x] (2026-11-05 UTC) Install the pinned workspace-local Rust toolchain;
  baseline make node and existing maturity boundary test pass.
- [x] (2026-11-05 UTC) Add shared genesis validation, exact allocation-adjusted
  issuance, policy hashes/quorum verification, and network-aware account codecs.
- [x] (2026-11-05 UTC) Add typed network-aware full-length shielded address codec.
- [ ] Integrate genesis and typed codecs into native manifests and all operational
  callsites (shared library, wallet codec and source-pinned v2 manifest data completed;
  native activation and operational callsites pending).
- [x] (2026-11-05 UTC) Implement candidate account transitions, lazy epoch
  availability, partial claims, deferred donations and real ML-DSA approvals.
- [ ] Integrate account state with real proof verification and node persistence
  (pure accounting fixture tests do not qualify proofs or running-chain behavior).
- [x] (2026-11-05 UTC) Implement explicit donation/claim constraints, a distinct
  SMZT proof identity, bounded carriers and encrypted wallet builders; generate
  and verify real claim/donation proofs with note recovery and 5-of-7 approvals.
- [ ] Qualify those proofs against authenticated running-node references and
  complete the node admission, persistence and lifecycle evidence.
- [x] (2026-11-05 UTC) Add bounded account journals, thin metadata checkpoints,
  authenticated row recovery and forward/reverse replay; protocol tests pass.
- [x] (2026-11-05 UTC) Qualify the native same-tree storage adapter with actual
  shared-note plans: atomic abort, disk restart, epoch-boundary suffix replacement
  and tampered-row recovery rejection (three focused node tests pass).
- [x] (2026-11-05 UTC) Define closed native claim/donation/certificate frames
  and fixed mandatory reward records; seven native storage/framing tests pass.
- [x] (2026-11-05 UTC) Replace moving treasury accounts with a fixed protocol
  identity, preserving balances, epoch buckets and sequence across certified
  signer rotation. Protocol regressions and fresh genuine payout proofs pass.
- [x] (2026-11-05 UTC) Validate v2 reward manifest data/source pins and retain
  an explicit startup rejection until account-aware runtime dispatch exists;
  eleven native account tests and thirteen existing network regressions pass.
- [ ] Wire mandatory reward records, source admission, account journals and
  authenticated storage into actual native startup, sync and reorg paths.
- [x] (2026-11-05 UTC) Build offline reward-account genesis/address CLI and
  verify funded disposable genesis, supply budget, quorum, network rejection
  and exclusive file creation.
- [x] (2026-11-05 UTC) Implement quorum-certified treasury replacement in the
  shared ledger and separately compiled adoption (the later fixed-pot decision
  supersedes successor reservations and account migration).
- [x] (2026-11-05 UTC) Add offline typed-intent review, key generation, signing
  and quorum combination commands with explicit chain/genesis checks.
- [ ] Integrate treasury fork adoption, offline workflow, RPC/claims and
  development tooling with running nodes.
- [x] (2026-11-05 UTC) Implement read-only explorer projections and four safe
  RPCs for status/accounts, genesis and canonical public activity; document the
  [API contract](../docs/PROTOCOL_TREASURY_EXPLORER_API.md). Active data still
  requires the outstanding canonical account integration.
- [ ] Paused by user pending Pierre's source location: existing explorer UI and
  indexer integration, followed by canonical reorg qualification, as specified
  in the [explorer plan](PROTOCOL_TREASURY_EXPLORER_EXECPLAN.md).
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

The existing SMZL private-spend proof frame is exactly 171,281 bytes. Trying
to use it for the new statement correctly failed its fixed-frame check: the
new graph projects to 171,505 bytes. Preserve that rejection. The successor
uses its own SMZT wire, transcript, leaf and sampling domains, 123 relation
inputs plus 24 immutable source/domain binding words, and an exact 171,505-byte
frame. Numeric proof parameters do not supply cryptographic qualification or
production source authority. Source changes require fresh manifests and evidence.

The initial ledger cloned an entire BTreeMap and scanned genesis allocations
and account state for every block. The candidate now shares a compressed
384-bit account trie and immutable genesis, hashes only changed account paths,
and uses checked cached supply totals. Global epoch buckets release before
transactions; individual leaves normalize on access. Startup validation still
reconstructs and audits all totals. Full snapshot encoding is for recovery,
not a scalable per-block persistence strategy: node integration still needs
bounded journal/checkpoint writes in the shared atomic transaction.

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

Superseded proof-magic decision (SMZT correction below): give the successor
relation an SMZR proof identity instead
of widening historical SMZL guards. Claims require empty private inputs and
one positive ordinary output equal to the credited amount; donations prove
inputs = change + explicit donation + fee. Bind the complete operation, public
memo, payout and immutable source identity. The source manifest includes the
actual shared account, policy, governance, genesis, schedule and trie modules.
Rationale: real proof generation exposed incompatible fixed geometry; keeping
identities separate prevents historical proof/profile reinterpretation.
Date/Author: 2026-11-05 UTC, Codex implementation evidence.

Decision: Use SMZT for reward-account proofs and preserve recovery's existing
SMZR envelope unchanged. The old SMZL private-spend relation remains separate.
Rationale: recovery already owns SMZR; distinct exact magics, domains and profile
identities prevent cross-format proof acceptance. Real SMZT proofs are required
for the current source; historical provisional SMZR receipts do not qualify it.
Date/Author: 2026-11-05 UTC, Codex parser and real-proof evidence.

Superseded decision (fixed-pot user revision below): a valid treasury certificate reserves an unused successor policy and
authenticates a future replacement, but cannot activate software rules. At its
height the integrating node must provide a matching compiled fork identity.
Move all balances, epoch buckets and sequence, increment policy generation,
and reject retired treasury identifiers and claims. Preserve N and M exactly.
Rationale: the current quorum must approve replacement without gaining an
ordinary mutable governance/mint authority; the transition remains reversible
when replaying a competing branch.
Date/Author: 2026-11-05 UTC, Codex implementation of the accepted fork policy.

Decision: Keep a fixed treasury protocol identity and rotate only its signer
policy under the certified hard-fork rules. Its identifier hashes a versioned
current-committee authorization reference; its address still enforces the
network. Ordinary miner/genesis accounts remain policy-hash accounts. Do not
move balances, reset sequence, reserve a successor account or retire ordinary
accounts belonging to current or former committees.
Rationale: the user selected the recommended fix after learning that a miner
could pre-fund a future policy address and block the proposed migration. A
fixed pot removes that collision and separates treasury governance from the
committee's ordinary funds. Supply, epochs and signature quorum are unchanged.
Date/Author: 2026-11-05 UTC, explicit user answer recorded by Codex.

Decision: Keep future signer-only schedule rows separate from the immutable
genesis/proof algorithm digest. The compiled parser and all validation logic
remain source-bound; each schedule entry and its current-quorum certificate
bind the exact chain and generation. This hook remains required before runtime
activation. Rationale: hashing future release data into the original genesis
identity would turn a signer replacement into a different chain, invalidating
historical proof support. Exact Development source pins do not establish an
upgrade catalog for arbitrary future algorithm changes.
Date/Author: 2026-11-05 UTC, Codex implementation-plan clarification.

## Outcomes & Retrospective


The initial design is already published. This revision replaces its maturity,
miner-note and zero-genesis assumptions and adds network-aware public/shielded
addresses. The initial documentation revision changed no runtime. Runtime work now adds
the shared protocol-reward-accounts crate and typed wallet address codec.
The shared relation and encrypted wallet/account proof integration now exist,
including genuine claim and donation proofs. Native reward routes, canonical
node publication, real-chain reorg/synchronization, runtime deployment and the
chain reset are not yet implemented or claimed. Documentation checks passed: relative links, required headings and six milestones,
source paths, terminology, README structure, release examples, exact supply
budgets and completed-block conservation arithmetic. Runtime tests were not run
for these documentation-only edits. Revision eedd8da6 was pushed successfully;
GitHub readback confirmed the new account/shielded HRPs and binary network
validation specification.

The fixed-pot revision now preserves one treasury identity while rotating only
its current signer policy/generation. Pre-funding the successor's separate
ordinary account no longer blocks adoption. Fifty selected tests pass: sixteen
protocol tests, four circuit tests, three encrypted-wallet tests, three offline
CLI tests, eleven native storage/framing/profile tests and thirteen existing
network-profile regressions. Circuit and wallet tests each generated actual
claim/donation SMZT proofs. Targeted protocol Clippy, formatting of changed
Rust files, documentation checks and whitespace checks pass. These results do
not qualify account-aware running-node admission, synchronization, RPCs or the
required two-node lifecycle, which remain open milestones.

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

Address HRPs are heg/heg_test for ordinary policy-hash accounts and the fixed
treasury lookup-policy identity, and
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
N/M bounds. Treasury allocations must name the fixed protocol treasury identity. Default
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


The shared foundation is not the native integration. Implement a dedicated
`node/src/native/reward_accounts.rs` source adapter and a fresh manifest schema
in `node/src/native/network_profile.rs`; it must pin the actual reward relation,
genesis account configuration and compiled monetary rules. Do not reinterpret
legacy funded manifests, use an asset registry slot for native money, or borrow
an existing PrivateSpend proof authority for the new relation. A finite,
explicit Development source is the qualification route; production authority
still requires its own existing release/security gates.

Require exactly one public reward record in each successor block. Its committed
bytes identify the including miner and bind height/context, parent and resulting
account roots, resulting shared note root, subsidy and exact miner fee total.
The normal PoW action commitment authenticates that record. Recompute every
field and the account transition during import; it is not a sender-provided
state setter. Genesis authenticates the initial account root. Never make account
acceptance depend on the presence of an optional old coinbase action. Reject all
legacy mint bundles in this fresh profile, including zero-valued variants.

Extend shared-note planning through a distinct account route rather than relaxing
the closed controlled-asset shape: a claim appends only its first, positive
output and consumes no private input nullifiers; a donation consumes its proven
input nullifiers and appends its two change outputs. Both retain ciphertext
bindings and real proof verification. Existing private spends retain their exact
route and credit their fee only once. No claimed note enters the old pending
coinbase vector. The node, not a wallet-provided callback, supplies checked
canonical block hashes and note roots for the permitted reference window.

Persist a bounded journal of changed account leaves and before/after metadata
alongside the shared note/nullifier checkpoint in the same sled transaction.
Use the known touched identifiers (miner, fixed treasury and claim owners)
and the persistent trie to avoid scanning or rewriting the account table.
Maintain one canonical account table plus authenticated metadata; retain undo
and redo rows for the adopted block. A snapshot can be built and fully validated
on startup, but full per-block snapshots are not the storage strategy. A reorg
must restore account leaves, epoch totals, treasury policy/generation, sequence,
notes and nullifiers together before applying the replacement suffix. A failed
transaction publishes neither pool. Compare recovered roots with authenticated
block records, never a second unauthenticated root stored beside the snapshot.

Signer certificates require a matching compiled fork descriptor at scheduling
and activation. Unknown certificates are invalid transactions, not delayed
halt conditions. The node owns that descriptor; neither JSON/RPC configuration
nor a certificate can supply the adopting software's authority. Keep the same
N/M and preserve the complete account balance and sequence on replacement.



Remove per-block reward-note creation from the successor admission path. At
block start activate any authorized compiled fork and release due epoch buckets;
process actions; at block end credit deferred donations and exactly one mandatory
reward transition. For S subsidy, F total miner fees including tips once and
T=floor(S/5), credit treasury T and miner S-T+F to the earning epoch. Zero-subsidy
blocks still execute this transition. Ordinary donations become available only
in the next block. Current-block fees/rewards cannot fund a claim in that block.

Install the verified ledger in NativeState.reward_accounts in the same canonical
publication as the block and notes. Read-only explorer APIs require this state
and matching committed roots; configuration or an RPC cannot create it.

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
binding unchanged N/M, generation, successor authority, height and compiled
rules. Admission and activation both require a matching installed fork identity;
unknown certificates cannot create a future halt. Keep the treasury identifier,
address, balances, epoch buckets and sequence fixed. Activation changes only the
current signer policy, increments generation and consumes the certificate.
Old-generation treasury claims reject. Reorg restores all corresponding state.
Do not reserve, move to or freeze the successor policy's ordinary account: it
may have already received funds or spent with its own sequence. Ordinary public
accounts still use their own single-key/threshold policy hashes and generation
zero; treasury claims resolve the reserved current-committee authorization
reference against actual current state. A certificate cannot install software
rules or act as a general-purpose governance/mint command.

Before enabling native runtime dispatch, install a parser for an initially
empty compiled signer-fork schedule at
`node/src/native/reward_accounts/compiled_forks.json`. Each canonical row binds
network/genesis, current generation, activation height, successor policy and
rules identity. Treat this file as public software-release data, never as an
operator path or mutable RPC configuration. Keep the parser and validation
algorithm in the source commitment, but keep future approved schedule rows out
of the genesis/proof algorithm digest. Updating only a quorum-certified signer
schedule must not change the original genesis identity or strand historical
proofs. The current certificate is still mandatory; compiled data alone cannot
rotate signers. Admission on software without the exact installed row rejects
immediately. Broader rule/proof upgrades require a versioned supported-source
catalog and historical replay tests; do not claim that the present exact-source
Development pins already provide that upgrade mechanism.

The companion [explorer plan](PROTOCOL_TREASURY_EXPLORER_EXECPLAN.md) specifies
read-only API and explorer implementation, including unavailable-state handling,
exact atom formatting, fixed-treasury history and canonical index rollback.
Implement and test those views as part of this milestone.

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

For the historical documentation-only revision, run `git diff --check`, validate relative links,
all required ExecPlan headings, terminology and source references. Check the
release examples mathematically and the subsidy telescoping for G=0, a partial
G and G=MAX_SUPPLY. Inspect that only documentation files changed. Record the
actual result, commit, push and verify the remote head. No runtime build or node
test is necessary or claimed for these prose changes.

The first-run setup milestone already honored AGENTS.md with
`make setup` then `make node`; inspect toolchain/setup failures and record them.
Use `work/` for intermediate logs and disposable noncommitted fixtures. Proposed
focused selectors below are historical suggestions; the current exact reward
commands and measured results follow in Artifacts and Notes:

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
successor rules, fixed treasury identity, pre-funded successor authority, stale treasury generation after activation,
sequence preservation and reorg through scheduling/activation. End-to-end
acceptance includes real signatures and proofs, normal spend of a claim,
restart, fresh sync and agreement through boundary reorganizations on two nodes.

## Idempotence and Recovery


Documentation checks do not affect a running network. Use the dedicated branch;
commit and push without force or merge. Runtime tests later use fresh disposable
base paths and stop only their own processes. Preserve old databases and wallet
backups; do not delete pre-mainnet state to satisfy identity checks. Block
publication is all-or-nothing. Reorg must restore accounts, epoch releases,
notes, supply, sequences, policy generation and certificates.
Broadcast retries reconcile canonical identity and sequence; they do not create
duplicate payments. Legacy address inspection never silently converts networks.

## Artifacts and Notes


The principal artifacts are this ExecPlan and
`docs/PROTOCOL_TREASURY_DESIGN.md`, with proposal references in DESIGN.md,
METHODS.md and the README whitepaper. The original revision implemented only
documentation. Current runtime work adds the shared protocol and typed wallet
codec, without changing deployed configuration, running services or chain data.
The actual initial foundation checks are six protocol foundation tests, three
accounting tests with explicitly marked fixture proof callbacks and one full-size
wallet codec test. Real circuit proofs and node lifecycle acceptance are pending.

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

Revision note (2026-11-05 UTC): runtime implementation authorized. Added shared
protocol crate to avoid node/wallet dependency cycles; moved unchanged native
monetary constants into protocol-versioning and re-exported them from consensus.
Six foundation tests pass, including real 5-of-7 signatures and supply properties;
three ledger accounting tests pass using explicitly named fixture proof callbacks.
The full-size shielded codec test passes. These are foundation checks, not
real-proof, node, or reorg acceptance. Candidate-ledger cloning and full snapshot
validation/root generation must be replaced or bounded before scalable node
integration; they are not evidence of constant per-block work.

Runtime foundation evidence (2026-11-05 UTC): release protocol tests pass (6
foundation/property/signature cases and 3 pure accounting cases); typed wallet
codec test passes; all 9 selected legacy reward tests pass, with optional Lean
vector checks retaining their existing environment-dependent behavior. Targeted
Clippy with --no-deps and warnings denied passes after local fixes; the initial
dependency-inclusive run encountered an existing manual_contains lint in crypto.
The real reward-account CLI successfully generated and inspected disposable
funded genesis and rejected a different network and an existing output file.
Use the installed /workspace/toolchains/env.sh before Cargo commands in this
environment. No node source route, proof qualification or launch is claimed.

Discovery (2026-11-05 UTC): offline wallet integration tests exposed that the
existing treasury-v8 binary unconditionally imports RPC crates but lacked its
required-features declaration. Added required-features=[rpc-client], matching
its actual requirements and the other RPC binaries. The offline reward-account
CLI integration suite then passes (2 tests). Its source is force-added because
the repository's generic bin/ ignore rule otherwise hides new Rust entrypoints.

Proof/governance milestone (2026-11-05 UTC): real circuit claim/donation proofs
and the wallet encrypted claim-then-donate test pass at 171,505 bytes per proof.
The wallet test uses a constructed authenticated-note fixture and the real
proof verifier, not mined nodes; it supplies no two-node lifecycle receipt.
Use these commands from the repository root (source the local environment first):

    cargo test -p protocol-reward-accounts --release --offline
    cargo clippy -p protocol-reward-accounts --all-targets --release --offline --no-deps -- -D warnings
    cargo test -p transaction-circuit --release --lib --features private-spend-dev-artifacts reward_accounts --offline -- --include-ignored --nocapture
    cargo test -p transaction-circuit --release --lib --features private-spend-dev-artifacts native_private_spend_smzd_identity_tests --offline
    cargo test -p wallet --release --no-default-features --lib reward_accounts_actual_claim_then_donate_real_proofs --offline -- --ignored --nocapture
    cargo test -p wallet --release --no-default-features --test reward_account_cli --offline

Offline signing takes a canonical SCALE AccountClaim or TreasuryForkIntent,
a public policy JSON file and a genesis JSON file. Run reward-account
intent-review, intent-sign and intent-combine with --kind claim|treasury-fork,
--intent PATH --policy PATH --genesis PATH --expected-chain-id HEX32
--expected-genesis-hash HEX32. Signing additionally takes --secret-key PATH
--signer-index N --out NEWFILE; combination takes one --approval PATH per
signer and --out NEWFILE. keygen --secret-out NEWFILE emits public policy JSON
on stdout. Keys and intermediate byte buffers are wiped on drop; output files
are created exclusively with Unix mode 0600. Offline review cannot establish
canonical inclusion, available balance or current generation; node admission
must check these against its authenticated state. No RPC submission is implied.

Revision note (2026-11-05 UTC): implement and record the shared proof, encrypted
wallet, persistent account-state, fork-certificate and offline-signing milestone.
Keep native block admission, bounded atomic persistence, operational codecs,
RPC workflows and two-node qualification explicitly outstanding.

Genesis commitment detail (2026-11-05 UTC): hash the actual compiled supply cap,
issuance-era length and treasury numerator/denominator alongside the named rules
and canonical genesis. Changing a monetary constant must change the authenticated
configuration even if a developer forgets to rename the human-readable rules ID.

Documentation validation (2026-11-05 UTC): all new relative links, required
ExecPlan sections, all six milestones and the 1/1,440/2,881 boundary arithmetic
pass. The overview files retain nine pre-existing links to absent historical
.agent artifacts; none were introduced by this change. No missing historical
artifact was fabricated to make the check green. git diff --check passes.

Fork-admission clarification (2026-11-05 UTC): the adopting software must
already contain the exact fork height, successor policy identifier and rules
identity before a certificate can be scheduled. Check that identity again at
activation. Reject unknown certificates immediately; accepting one and then
halting at its requested height would give the quorum a forbidden pause power.
The certificate cannot introduce a new rule or force software adoption.

Parser bound detail (2026-11-05 UTC): SMZR carrier decoding bounds its nested
proof at the exact 171,505-byte frame before allocation, not merely the shared
2 MiB account-proof budget. Its whole carrier is capped at that frame plus
8,192 bytes. Verification requires the exact frame length and magic.

Final source validation for this milestone (2026-11-05 UTC): 14 protocol tests
pass (one persistent-trie case, six foundation/property/signature cases and
seven accounting/governance/replay cases); targeted protocol Clippy with -D
warnings passes. Four successor circuit tests pass including two genuine proofs,
mutation rejection, source binding and disjoint wire framing. Nine legacy/profile
regressions pass (including the two new SMZR codec/domain tests). Three wallet
checks pass including a real encrypted claim-then-donate cycle; three offline
CLI tests and three ML-DSA provider tests pass. A focused wallet recovery check
also passes after wiping both owned output-opening copies on drop. The native
node compiles with its default inactive successor routes. Compiler warnings in
unrelated legacy modules remain; this is not a claim that workspace-wide CI or
two-node qualification has passed. Frozen-source logs are retained under
/workspace/work/environment-setup/reward-frozen-{circuit,wallet,core,clippy}.log;
CLI/provider/node logs use reward-qualified-{cli,keys,node}.log. This evidence
qualifies the shared proof/governance milestone only. No node was deployed or reset.

Publication checkpoint (2026-11-05 UTC): commit
6b179d2a3440c8bde4a448357a450953d1a666dd was pushed to the existing branch;
git ls-remote confirms that exact head and GitHub readback of governance.rs
confirms compiled adoption at scheduling and activation. That committed source
is the reproducible shared proof/governance milestone, not native activation.

Journal integration in progress (2026-11-05 UTC): RewardAccountCheckpoint
excludes immutable genesis allocations and the account table. apply_block_journaled
runs the real normal transition and produces at most 515 changed rows (the
existing 512-proof ceiling plus miner and both treasury identifiers), then
rebuilds only those paths and checks the resulting root. Forward/reverse
replay checks both source metadata and authenticated destination roots. Startup
streams canonical table rows, fully validates supply/epochs/policy and compares
the reconstructed account root with its enclosing canonical record.

node/src/native/reward_accounts.rs implements a distinct reward-accounts/v1/
namespace in the existing shared V8 sled tree. Its metadata binds height, block
hash, account root and note root. Immutable before/after journals, exact row
comparisons and canonical metadata update in the caller's transaction; no
independent canonical commit method exists. The source network still does not
open this adapter: manifest selection, mandatory record validation and the
canonical planners must be wired before activating it. Reward-only storage
tests use the actual shared note-state plan and a verifier that rejects every
private proof. Those tests are storage evidence, not mined-node qualification.
The first test invocation found uncached reqwest 0.12.28 in the existing node
dev-dependency lockfile; rerun with authorized network access fetches locked
packages without changing versions.

Storage milestone validation (2026-11-05 UTC): the protocol suite now passes
15 tests, including bounded journal recovery and full reversal of a partial-claim/
donation history across reward releases. Targeted protocol Clippy with -D warnings
passes. The native node compiles, and all three selected reward_accounts_native
release tests pass using the real shared-note canonical plan and the same sled
transaction as account rows. Forced failure after both writes leaves both tips at
genesis and stores no journal; a successful commit survives closing/reopening the
DB; replacing a suffix across release boundaries and switching back restores exact
roots; tampered rows fail authenticated recovery. These are storage integration
tests, not full-node PoW, source admission, transaction relay or two-node evidence.

Reproduce from the repository root with the installed toolchain:

    cargo test -p protocol-reward-accounts --release --offline
    cargo clippy -p protocol-reward-accounts --all-targets --release --offline --no-deps -- -D warnings
    cargo test -p hegemon-node --no-default-features --release --lib reward_accounts_native --offline

Logs are reward-journal-core-tests.log, reward-journal-clippy.log and
reward-native-store-tests.log under /workspace/work/environment-setup. The first
node test build needed the existing locked dev dependencies fetched online and
one test-only verifier needed its required closed native_leaf_profile method;
the corrected rerun passed. No production verifier or authority was widened.
The shared ledger source changed, so the broad SMZR source commitment changes;
the next real-proof/native qualification must generate fresh source-bound proofs.
The published 6b179d2a proof evidence remains tied to that exact committed source.

Revision note (2026-11-05 UTC): implement and qualify bounded public-account
journals and the native shared-tree atomic storage adapter. Source-profile
selection, mandatory reward records, operational codecs, RPC/CLI integration
and actual native lifecycle qualification remain outstanding.

Proof-namespace correction (2026-11-05 UTC): repository-wide source review
found an existing, unrelated asset-recovery outer envelope named SMZR. Although
its header and inner SMZE frame differ, reusing those four bytes is unnecessary
and makes format separation harder to audit. Supersede the treasury's provisional
SMZR name with unused SMZT throughout its arithmetization, wire, transcript, leaf
and sampling domains. Preserve recovery's existing SMZR unchanged. Earlier
6b179d2a proof logs remain historical evidence for that exact source and are not
SMZT qualification. Regenerate current real proofs and test rejection in both
format decoders before source admission. Numeric parameters and graph geometry
remain unchanged; no production proof authority is added.

SMZT and native wire validation (2026-11-05 UTC): four current circuit tests
pass with fresh genuine SMZT claim/donation proofs and rejection by the recovery
SMZR parser; prefix aliases reject in the opposite direction too. Three current
wallet checks pass, including the real encrypted 5-of-7 claim/donation cycle.
Each proof remains exactly 171,505 bytes. Evidence is in reward-smzt-real-
{circuit,wallet}.log under /workspace/work/environment-setup. Earlier provisional
SMZR evidence is historical only. Recovery's existing SMZR envelope remains
unchanged; no recovery parser or production gate was widened.

node/src/native/reward_accounts/wire.rs reserves shielded-family actions
20 claim, 21 donation, 22 certified fork and 23 final public reward record,
with circuit/profile 15 and domain 11. HGRACC01 account frames cap at 512 KiB
and contain only claims, donations or certificates: the internal PrivateFee
accounting variant is not a network transaction. HGREWD01 reward frames are
exactly 392 bytes including an exact compiled native source commitment. They
bind chain/genesis, height, miner, before/after account roots, resulting shared
note root, subsidy and total miner fees, with no memo or private mint proof.
All fields must match the independently verified account/pool candidate; header
supply must advance by subsidy alone, not fee recycling.

The native wire adapter checks canonical field words, exact ciphertext framing,
SMZT frame size/magic, operation/amount/fee/memo/payout bindings and bounded
approval shape. Decoding remains syntax only. Seven selected native tests pass:
three shared-storage tests plus four framing/binding/adoption-negative tests.
A valid-looking fake donation frame is recognized syntactically but rejected by
a proof verifier that accepts nothing, leaving the parent state unchanged. No
account-to-account grammar exists. Node compilation and whitespace checks pass.
The native registry and manifests still do not select these routes.

Interface decision (2026-11-05 UTC): keep this node wire adapter node-owned.
Wallets submit the already proof/signature-bound public components (canonical
claim/donation intent bytes, policy, approvals and payout carrier) through a
specialized RPC, and the node constructs its own exact frame before normal
admission. This avoids a wallet-to-node Rust dependency or duplicated wire
schemas. A node cannot alter a signed/proven fee, recipient, memo, output or
chain context by reframing those components. The wallet must still pin the
expected network/genesis and compiled proof source and reconcile inclusion.
The RPC and native source selection are not implemented yet.

Revision note (2026-11-05 UTC): correct the provisional proof-magic collision
with asset recovery, requalify the new SMZT proofs, and add tested native wire
and mandatory-record primitives. Actual block orchestration, startup source
selection, operational addresses, RPCs and two-node qualification remain open.

Fixed-pot implementation (2026-11-05 UTC): the shared genesis identity, claim
authorization, rotation and checkpoint codecs now follow the explicit
user decision. The treasury uses a reserved versioned governance-policy hash;
ordinary account claims still require their descriptor hash. Rotation changes
only the current policy and generation, preserving the pot's entire state.
The regression pre-funds the successor's ordinary account, advances both its
sequence and the treasury sequence, performs the fork with claims from both,
and reverses the journal. Sixteen protocol tests and targeted Clippy pass.
Wallet fixtures and offline review now distinguish the stable treasury identity
from its current authority hash. Fresh source-bound circuit and encrypted-wallet
claim/donation proofs pass; both raw proof frames are exactly 171,505 bytes.
The checkpoint schema is now 2 and rules ID names fixed-treasury v2; these are
unreleased reset changes, not an on-disk migration of a running chain.

The new v2 native manifest data validates compiled proof/native pins, the
allocation-adjusted budget, test-network tags and an isolated finite Development
scope. Legacy manifests omit the new field byte-for-byte and retain their old
funding rules. Distribution manifests may be up to 32 MiB with bounded reads;
v1 keeps its 16/64 KiB limits. Runtime source dispatch still explicitly rejects
v2 until the actual account-aware source and block orchestration are installed.
A development-feature node test build exposed existing recovery tests' extra
wallet feature requirements: use --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts
for that harness, rather than widening the default node build.

Fixed-pot qualification (2026-11-05 UTC): after updating the wallet fixtures,
offline review and native syntax, rerun the exact source-bound proofs. Both
wallet and circuit claim/donation proofs are 171,505 bytes and pass. The v2
manifest constructor initially omitted the existing 0x prefix on consensus
hashes; native tests caught the mismatch. It now uses the shared hex32 formatter,
and all eleven native tests pass, including the greater-than-64-KiB bounded
distribution and startup-rejection cases. Thirteen existing network-profile
regressions also pass. The offline test signs a fixed-treasury claim and checks
that its displayed address differs from its committee's ordinary account.

From /workspace/Hegemon, load the installed workspace environment with
`source /workspace/toolchains/env.sh`, then run:

    cargo test -p protocol-reward-accounts --offline
    cargo clippy -p protocol-reward-accounts --all-targets --offline --no-deps -- -D warnings
    cargo test -p transaction-circuit --release --features private-spend-dev-artifacts reward_accounts --offline -- --include-ignored --nocapture
    cargo test -p wallet --release --no-default-features --lib reward_accounts --offline -- --include-ignored --nocapture
    cargo test -p wallet --release --no-default-features --test reward_account_cli --offline
    cargo test -p hegemon-node --no-default-features --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts --release --lib reward_accounts_native --offline
    cargo test -p hegemon-node --no-default-features --features development-candidate,wallet/rpc-client,wallet/private-spend-dev-artifacts --release --lib network_profile::tests --offline

Expect nonzero selected pass counts 16, 4, 3, 3, 11 and 13 respectively; Clippy
exits successfully. The circuit command also reports zero matches in unrelated
integration binaries; the four library tests are the qualifying matches. Use
--lib for a library-only repeat. Local logs are reward-fixed-pot-{regression,
clippy,real-circuit,real-wallet,cli-tests,native-tests,network-regressions}.log
under /workspace/work/environment-setup. No new relative-link failures were
introduced; nine pre-existing overview links to absent historical artifacts
remain unchanged. All required plan sections, six milestones, epoch examples,
supply arithmetic and changed-file formatting/whitespace checks pass.

Revision note (2026-11-05 UTC): implement the user's fixed treasury identity
choice, supersede the earlier destination-reservation design explicitly, update
offline review and qualify the changed proof source. Add tested v2 manifest data
without enabling incomplete runtime dispatch. Keep the compiled signer-schedule
hook and actual node orchestration in the outstanding implementation milestones.

Explorer scope revision (2026-11-05 UTC): the user explicitly requested all
treasury, reward-account, genesis/supply and governance explorer views and their
node APIs. The companion explorer ExecPlan records implementation details and
end-to-end acceptance; this work does not authorize deployment or a chain reset.

Explorer location update (2026-11-05 UTC): the user contacted Pierre for the
existing explorer source and asked to pause that UI work pending his reply.
Continue the node read APIs, tests and integration specification. The backend
contract is docs/PROTOCOL_TREASURY_EXPLORER_API.md; native account publication
remains necessary before active balances can be served. No explorer deployment
or replacement application is included.

Explorer backend qualification (2026-11-05 UTC): four safe read RPCs and canonical
read models are implemented. Nineteen account tests, thirteen network-profile
regressions and one safe-policy test pass, with default node cargo check and
scoped formatting/whitespace checks. The production HTTP path on a real legacy
node returns unavailable data and changes no database rows. Root field words,
heights, epochs, amounts and sequences are encoded without JavaScript integer
rounding. Active account/note publication, actual chain qualification and the
user-deferred existing explorer UI/indexer remain outstanding. The companion
explorer plan contains exact commands and acceptance boundaries.
