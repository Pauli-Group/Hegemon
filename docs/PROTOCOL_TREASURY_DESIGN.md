# Protocol treasury, reward accounts and genesis allocations

Status: implementation in progress; node routes are not activated. This
fresh-genesis successor is developed on `codex/protocol-treasury-governance`,
based on main commit `74910ff86514c2cbd93d7a7039e6b90b6e4600b6`. Follow the
[execution plan](../.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md) for runtime
implementation and qualification. Shared protocol/accounting rules and the typed
wallet address codec are implemented; proof/node integration remains pending.

## Purpose and agreed scope

Every node maintains public reward accounts for miners, the treasury and optional
genesis recipients. Block rewards accumulate in accounts instead of creating
one shielded note per block. Owners claim available balances into the existing
shared shielded note pool. Ordinary private payments stay in that pool; this
proposal adds no general public account-to-account transfer mechanism.

The compiled treasury allocation is the integer fraction 1/5 of each block
subsidy. Changing it requires a hard fork, not a genesis override, environment
variable or administrative transaction. Fees and transaction tips go in full to
the actual including miner. The treasury policy and reward-epoch length are
instead genesis parameters, fixed for a running chain unless changed by an
explicitly specified hard fork.

This reset uses genesis-configured 5-of-7 treasury authority and 1,440-block
reward epochs. Genesis can select valid N-of-M policies with 1 <= N <= M <= 16;
16 is a consensus resource bound. Signer replacement preserves the selected
N/M, requires approval from the current quorum and a matching software hard
fork. No notice period, spending cap, expiry or emergency pause is added.
There is no delegation, DRep system, vesting, generic administrative execution,
continuing mint authority or recovery override for a lost quorum.

The deployment model is a full chain reset, without migrating old balances.
Optional genesis allocations initialize available account balances; an empty
allocation is the default. Preparing and publishing this branch does not reset
running nodes, deploy a network or select real launch keys or sale recipients.

## Current implementation and successor boundary

The branch implements shared account accounting, policy authorization, typed
addresses, fork certificates and offline intent signing. A successor-only SMZT
relation and encrypted wallet builders now pass genuine claim/donation proof
tests. A persistent account trie commits balances and caches supply totals;
recovery checks its root against the enclosing authenticated block commitment.
These components do not activate node routes. Native mandatory rewards, atomic
persistence, operational address migration and two-node lifecycle qualification
remain outstanding in the execution plan.

Current legacy implementation in `wallet/src/address.rs` encodes shielded
addresses with Bech32m and a network-independent `shca` prefix. Its V8 payload
contains full recipient/authorization material and an ML-KEM encryption key,
but no network discriminator. Changing only that prefix would not supply
binary network validation.

Current reward construction in
`node/src/native/node_impl.rs::build_allocated_reward_action` creates miner and
funding notes; `node/src/native/block_flow.rs::validate_coinbase_funding_accounting`
checks the funding recipient against the manifest. Existing reward actions can
be omitted, forfeiting both subsidy shares. Current legacy reward maturity is
120 blocks. The successor replaces both per-block reward notes and this fixed
maturity with mandatory account credits and N+2 reward availability.

`consensus/src/reward.rs` defines the exact 21-million-HGN issuance schedule.
Its existing long subsidy interval is called an issuance era in this design,
not a reward epoch. Genesis allocations require a new budget-bound schedule
identity. Native state, block commitments and replay checkpoints lack these
public accounts and must be extended together.

The current 86-word v4 private-spend statement has no donation amount or public
memo commitment. Its equation is private inputs = private outputs + fee.
Donation and account-claim proofs therefore need fresh identities and actual
qualification. A wallet label, signature or host bookkeeping entry cannot
substitute for a proof of the account/pool value transfer. Historical private
2-of-3 treasury accumulators do not authorize the new public treasury account.

## Epochs and reward availability

A reward epoch groups E accepted blocks, with E committed at genesis. The
selected reset value is E = 1,440. Height zero is genesis and earns no reward.
For h >= 1, reward_epoch(h) = floor((h - 1) / E). Rewards earned in epoch N
become available before processing transactions at height (N + 2) * E + 1,
the first block of epoch N+2. Reject overflow in epoch, height or amount
arithmetic rather than releasing funds early or dropping them.

Epoch zero covers blocks 1 through 1,440. Epoch one covers 1,441 through 2,880.
Epoch two starts at 2,881. Rewards from both block 1 and block 1,440 can first
be claimed in block 2,881. They wait 2,880 and 1,441 blocks respectively. At
the target one-minute block interval this is approximately one to two days;
elapsed time varies. No extra 120-block check survives in the successor rules.
Epoch boundaries are accounting transitions, not finality or checkpoints that
prevent a deeper reorganization.

Use the terms reward epoch, issuance era and policy generation separately.
A policy generation is the version of the treasury signer policy and advances
only when an authorized signer replacement activates. It does not advance with
reward epochs. Issuance eras retain the existing 2,100,000-block length.

Accounts retain an available balance and nonzero pending balances grouped by
earning reward epoch, plus an exact next-claim sequence. After releasing due
balances at an epoch boundary, only the preceding and current earning epochs
remain pending. Use lazy per-account release or equivalent bounded indexing
so a boundary does not require scanning every account in one block. Canonical
state and commitments must have deterministic semantics regardless of that
storage optimization; status readback computes availability at its snapshot.

## Authorization policies and account ownership

An account identifier is a versioned, domain-separated 48-byte hash of a
canonical authorization policy. Support single-key and threshold policies using
ML-DSA-65. Single-key policies commit to the signature-scheme identifier and a
48-byte key hash. Threshold policies commit to N, M and an ordered list of
M distinct key hashes, with 1 <= N <= M <= 16. Use the existing consensus
48-byte domain-hashing framework, with separate key, policy, claim and fork
authorization domains. No elliptic-curve primitive is introduced.

A claim supplies its policy descriptor and the selected full public keys and
signatures. Recompute the descriptor hash and key hashes, check canonical order,
distinct signer indices and at least N valid signatures, and compare them to
the credited account. Public keys need not be disclosed merely to receive a
reward or genesis credit. Actual supplied keys must parse under the declared
scheme. No registration or signer permission is required to credit an account;
an incorrectly constructed identifier can strand funds, so wallet tooling must
verify its generated policy before presenting its address.

The public identifier groups rewards, balances and claims. Key hashing does not
hide that public activity, and signing reveals the relevant public keys. A
policy hash is an authorization identifier, not a shielded encryption address.
Shielded payouts still require the recipient's full encryption information.

The treasury has a reserved ledger role with one active policy identifier.
Only its active policy can claim the treasury balance. The owner of an ordinary
reward/genesis account cannot rotate that account policy through a new recovery
command in v1; it can claim to a new shielded recipient. Treasury replacement
uses only the hard-fork procedure below. No general account transfer or policy
replacement authority is implied.

## Network-aware Bech32 addresses

Use Bech32-family addresses for both account identifiers and shielded recipients.
Follow the network-prefix and binary-tag pattern documented by
[Cardano CIP-19](https://cips.cardano.org/cip/CIP-19) and
[CIP-5](https://cips.cardano.org/cip/CIP-0005), while retaining Hegemon's existing
Bech32m checksum variant. Cardano uses original Bech32; this design is not a
claim of Cardano wire compatibility. The `1` after the human-readable part is
the encoding separator, not part of the configured prefix.

| Address purpose | Mainnet prefix | Non-mainnet prefix |
| --- | --- | --- |
| Public account policy hash | `heg` | `heg_test` |
| Shielded recipient | `heg_shield` | `heg_shield_test` |

Thus user-facing text starts with `heg1...`, `heg_test1...`, `heg_shield1...`
or `heg_shield_test1...`; these are schematic prefixes, not valid test vectors.
Development, testnet and pre-mainnet profiles all use the non-mainnet class.
Do not silently re-encode or relabel an address to match the connected network.

Both address families use a fresh binary envelope containing an address-format
version, explicit account/shielded kind, network class, a 32-byte network
discriminator and the typed body. Account bodies contain the 48-byte policy
identifier. Shielded bodies retain the full supported recipient/authorization
and encryption-key material. Use new version identifiers rather than treating
old payload bytes as this new format.

The network discriminator is an independently selected public value committed
at genesis, distinct from and not derived from the resulting chain ID. This
avoids circularity when genesis contains addresses. Require nonzero values;
use distinct fixed values for documented disposable networks and a freshly
selected value for a new launch. Mainnet/testnet prefixes identify the class;
the payload discriminator distinguishes separate test networks and reset
networks within that class. Genesis commits allocations as sorted raw policy
identifiers and amounts under its own network context, not HRP-dependent text.
Operation proofs and signatures still bind the full chain and genesis identity.

Encoders emit lowercase. Decoders validate checksum variant, version, type,
exact payload shape, canonical padding, network class and discriminator. Accept
uniform-uppercase Bech32 input by normalizing it after validation, but reject
mixed case. Check the HRP against both the encoded type/class and the selected
wallet/node network before building, signing or submitting a transaction. Raw
binary/hex entrypoints perform the same network checks; an HRP is not a security
boundary or a replacement for chain-bound operation authorization.

Expose a typed `PublicAccountAddress` alongside `ShieldedAddress`, plus explicit
network-aware encode/decode APIs. Update CLI, wallet/desktop flows, walletd,
RPC address fields, mining payout configuration, genesis tooling, offline signing
and manifests to use the shared codecs. Account addresses cannot be accepted in
shielded-payment fields or vice versa. Treasury donation is a distinct action,
not an ordinary private payment to its account hash. No production send path
may bypass checks by calling a historical context-free decoder.

Current shielded addresses include a 1,568-byte ML-KEM key and already exceed
standard Bech32's 90-character limit. Like the long-address approach in CIP-19,
allow bounded longer encodings: at most 256 characters for public accounts and
4,096 for shielded addresses, with exact decoded lengths checked separately.
Bound input length before allocation. Test full-length copy/paste and QR/library
integration; QR density may require file/text export rather than promising
one scannable QR for every full address.

Under the reset rules, reject legacy `shca` addresses in operational send,
claim, mining and genesis inputs: they do not assert the selected network.
Retain historical decoding only for explicit archive/recovery inspection.
An explicit local re-export of owned keys into the selected network format is
allowed; silently guessing the network of pasted legacy text is not. This
address change requires regenerated public configuration and updated integrations,
not any change to the underlying user's secret keys.

## Block accounting and processing order

All values are integer HGN atoms, with 100,000,000 atoms per HGN. State contains
account balances, epoch buckets, sequences, the active treasury policy and its
policy generation, and any pending certified signer replacement. Include these
in authenticated state commitments and persist them atomically with the block
tip, note tree, nullifiers and supply.

At block start apply any authorized compiled fork activation, then make all due
epoch balances available. Validate transactions in their encoded order against
the candidate state. Claims may use start-of-block available balances, including
newly released rewards, but cannot use current-block rewards or donations.
Accumulate accepted donations and miner fees separately. At block end credit
donations to available treasury funds and execute exactly one mandatory reward
transition, even when subsidy is zero. It credits account buckets, not notes.

For subsidy S and total included miner fees F, including all transaction tips,
T = floor(S * TREASURY_SUBSIDY_NUMERATOR / TREASURY_SUBSIDY_DENOMINATOR).
Credit T to the treasury's pending epoch balance and S - T + F to the actual
including miner's pending epoch balance. Keep the remainder with the miner.
Use widened checked intermediates. The miner entitlement is the sum of its
actual accepted block rewards, not an equal share computed from block count
when subsidies or fees vary. A miner account can belong to an operator or pool;
it does not attest to one physical device.

A transaction's fee and optional extra tip form its total miner fee once. Do
not count a tip again as a second reward. Fees for donations and account claims
join the same total and follow the same N+2 availability. Public memos belong
to donation actions, not the implicit block subsidy credit. Standalone payments
to named miner accounts are outside v1; inclusion tips reward the actual miner.

## Permissionless donations and shielded claims

A donation spends eligible private HGN with a successor proof establishing
`sum(inputs) = sum(change outputs) + donation + total_miner_fee`. Publish the
positive donation amount, separate total fee and a commitment to the optional
public memo, together with normal input/output/reference bindings. Bind the
exact memo length and bytes to the proof statement. Memos are at most 256 UTF-8
bytes; omitted means empty, with no text normalization during validation.
Check lengths before allocation, render memos as escaped text and count them
in block/mempool limits. Never interpret them as commands.

Donations credit already issued value to the treasury's available balance at
block end and are usable from the following block. They never enter pending
reward buckets. The donor's input openings, address, change and unrelated
balance are not public fields, but amount, memo and timing can identify them
through correlation. Requalify this privacy surface for the new relation.

Any account owner can claim a positive amount A from available funds. The signed
claim includes network/chain/genesis/rules bindings, account identifier, policy
generation where applicable, exact next sequence, A, total fee F, canonical
shielded recipient and output/ciphertext bindings. Require available >= A+F.
Verify ownership and a payout proof, debit A+F, append one shielded note of A,
and advance the sequence once. The including miner earns F as a pending reward.
Partial claims are allowed; failed or replayed claims change nothing. Multiple
claims in a block must use consecutive sequences and remaining available funds.

The payout proof establishes native HGN value A and the intended recipient
policy without revealing the note opening or its later nullifier. It also
binds the ciphertext under the existing encryption semantics. A signature on
an arbitrary commitment is not proof of its hidden value. Qualification must
state the actual delivery/ciphertext guarantee and must not claim stronger
correct-encryption guarantees than the implemented relation provides.

Claim amounts, fees, account identifiers and recipient addresses are public in
v1; note openings and intended later-spend links remain shielded subject to the
new proof's reviewed guarantees. The recipient address must be the shielded
family for the current network, not a public account address. No additional
coinbase maturity applies after claiming; normal note reference rules remain.

Anyone can relay a completed claim without changing its signed fields. There
is no claim expiry or notice period. Concurrent proposals using one sequence
conflict; after one wins, another needs new approval. Reorgs reverse claims,
credits and sequences together and can make an orphaned claim eligible again.

## Genesis allocation and the issuance budget

Genesis specifies an optional sorted distribution of distinct policy identifiers
and positive integer balances. A treasury row must identify the active treasury
policy; other rows initialize ordinary accounts. Reject duplicates, invalid
amounts, overflow and totals above MAX_SUPPLY. Empty is canonical for no
allocation. Balances begin available with sequence zero and no reward-epoch
delay. Defaults allocate nothing to anyone, including the treasury. Development
fixtures explicitly choose disposable funded recipients; launch distribution
and real governance keys remain separate operator inputs.

Let G be the validated allocation sum, MAX_SUPPLY = 21,000,000 HGN and
B = MAX_SUPPLY - G. Mining distributes B using the existing exact curve:
for issuance era k, remaining(k) = B >> k for k < 64, otherwise zero;
era_budget(k) = remaining(k) - remaining(k+1). With era length L = 2,100,000,
for h >= 1, k = floor((h-1)/L), j = (h-1) mod L and
S(h) = floor((j+1)*era_budget(k)/L) - floor(j*era_budget(k)/L).
Use wide intermediates and preserve atom-exact rounding. Sum of future mining
subsidies is B, including very small residual budgets. Genesis earns no subsidy.

Nonzero G lowers the subsidy curve rather than adding to supply or consuming
only the earliest rewards. G=0 recovers the current issuance curve; G=MAX_SUPPLY
leaves zero mining subsidy, but miners can still receive fees and tips.
Genesis allocations have no automatic treasury deduction. A genesis treasury
allocation is an explicit row, not another 20% distribution. There is no later
mint command, vesting schedule or live-balance migration.

## Treasury signer replacement

Genesis commits the initial treasury policy descriptor and signer-key hashes,
with chosen N=5 and M=7 for this reset and policy generation zero. Offline setup
validates the actual public keys before producing that descriptor. Ordinary
accounts and treasury claims use the same claim machinery, but only a certified
hard fork can replace treasury authority.

A replacement preserves N/M and requires N distinct current signers to approve
a domain-separated certificate binding the current chain/genesis, policy hash
and generation, successor descriptor, activation height and compiled successor
rules identity. Include it canonically before a future activation height; allow
one pending replacement. Scheduling rejects an identifier already occupied by
an unrelated account and reserves the successor identifier until activation or
reorg rollback. Reject unrelated reward credits or account creation using that
reserved identifier, so later activity cannot force an activation collision.
Signatures cannot install unimplemented software or execute arbitrary governance
commands. No claim approval is a fork approval.

At activation, installed matching software checks the certificate, atomically
moves the complete treasury state to its new active policy identifier, preserves
available and pending balances and the next sequence, and increments policy
generation. Old-policy claims reject. This reserved-role transition is not a
general account-transfer action. Reject a successor identifier already occupied
by an unrelated ordinary account, so activation cannot merge balances or lose
sequence history. Fork replay restores the whole transition together. Changing
N/M itself requires a separately specified hard fork, not this replacement path.

Compatible software and operator adoption remain necessary. A different network
can deliberately rewrite these requirements; the quorum guarantee describes
validation under the specified rules, not control over all possible forks.

## Conservation, persistence and versioning

Define P as conceptual unspent shielded value, A as all available public-account
balances, U as all pending public-account balances, G as genesis allocation and
I as cumulative mining issuance. With no burn mechanism in this design:
`P + A + U = G + I <= MAX_SUPPLY`. Private note values need not be publicly
summed; accepted proofs establish their contribution to these transitions.

A subsidy increases U by S and I by S. Private fees/tips move value from P to
U. A donation D with fee F decreases P by D+F, increases A by D and U by F.
A claim of C with fee F decreases A by C+F, increases P by C and U by F.
A boundary moves eligible value from U to A. Signer replacement changes no
value. Transfers, claims and maturity are not new issuance in the supply digest.
These equations describe completed blocks, including deferred end-of-block
credits. Genesis initializes P=0, A=G, U=0 and I=0.

Reject negative values, overflow/underflow, invalid proof ranges, duplicate
nullifiers, invalid policies, replay, insufficient available balance and duplicate
or omitted mandatory reward transitions. No accepted action can claim both an
old reward note and its successor account credit. Failed blocks publish no
changes. A zero-subsidy transition still accounts for fees exactly once.

All consensus paths use the same state transition: mining, mempool simulation,
import, startup, historical replay, fork replay and sync. Account state,
sequences, active policy, pending certificate, epoch buckets, supply, notes and
nullifiers are authenticated and atomically persisted with the tip. A reorg
reverses boundary releases and account claims, not just the block credit.
RPC readback uses one snapshot identifying canonical height/hash and reward
epoch. The account collection may grow with new miners; bounded per-block
work, input sizes and indexed account lookup are required.

Allocate fresh manifest, address, action, proof, compiler and checkpoint
identities through the existing registries. The reset manifest commits E,
allocation rows, policy, address network class/discriminator and compiled rules,
including the fixed 1/5 allocation. Reject old manifest/database identities;
do not reinterpret historical roots, notes or proof fixtures. Preserve v4 and
120-block evidence for their historical source identities only.

## Available foundation tooling

The `reward-account` wallet binary implements offline development-genesis,
genesis-check, address-from-policy and address-check commands. These validate
the shared protocol format; the output is not yet an activated native node
manifest. Example commands from the repository root, using a new output path:

    mkdir -p /workspace/work/reward-account-demo
    cargo run -p wallet --release --no-default-features --bin reward-account -- development-genesis --out /workspace/work/reward-account-demo/genesis.json --reward-epoch-blocks 2
    cargo run -p wallet --release --no-default-features --bin reward-account -- genesis-check --genesis /workspace/work/reward-account-demo/genesis.json

Development generation uses clearly labeled known fixture keys, random test
network discrimination, two immediately funded accounts and 5-of-7 treasury
policy. It never overwrites an existing file and must not be used for real
funds. Genesis-check reports the exact allocation/mining budgets and first
release height. Address-check rejects an account or shielded recipient from a
different selected genesis network. Node configuration and claim submission
remain subsequent integration milestones.

## Wallet, operator surface and acceptance

Provide network-aware address generation/inspection, canonical supply readback,
account available/pending balances with release epochs/heights, treasury history,
and sequences/policies from one snapshot. Support private donations, partial
claims, offline prepare/review/sign/combine/submit/status workflows and treasury
fork-certificate signing. Review screens show network, amount, fee, account,
shielded destination and exact approved payload. Keep private keys out of nodes,
pools, public manifests and Git. Reconcile uncertain inclusion before retrying.

Development tooling creates funded disposable genesis accounts, exports matching
network-aware wallet configuration and can use short genesis-configured epochs.
Launch tooling rejects known disposable policies. Preserve existing databases
and backups and use fresh base paths. Shared miners use the approved
`HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`
unless deliberately rotated, agree on network identity/seeds, and enable
NTP/chrony because future-skewed timestamps reject.

Implementation acceptance requires actual ML-DSA signatures and real donation/
claim proofs, epoch boundary/first-block/reorg tests, exact fee/tip/subsidy and
supply properties, empty/partial/full genesis allocation budgets, address
round-trips and cross-network/type rejection, memo mutation, partial claims,
replay and failed-block atomicity. Two nodes and a fresh syncing node must agree
through claims, restart, reorg and certified signer replacement. Full-length
shielded address tooling must be exercised. A demo or foundation-only module is
not completion. Until those milestones pass, the shared accounting and codec implementation
is a foundation for the successor, not an activated or qualified node route.
Foundation unit tests do not imply running-chain acceptance or launch readiness.

Fork-admission clarification (2026-11-05 UTC): the adopting software must
already contain the exact fork height, successor policy identifier and rules
identity before a certificate can be scheduled. Check that identity again at
activation. Reject unknown certificates immediately; accepting one and then
halting at its requested height would give the quorum a forbidden pause power.
The certificate cannot introduce a new rule or force software adoption.
