# Protocol treasury and fixed-quorum governance

Status: design for implementation, not implemented or activated. This document
defines a fresh-genesis successor to the v0.11 wallet-funded treasury. The
implementation branch is `codex/protocol-treasury-governance`, based on `main`
commit `74910ff86514c2cbd93d7a7039e6b90b6e4600b6`. The execution plan is
[`.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md`](../.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md).

## Purpose and agreed scope

The treasury becomes a public HGN balance maintained by every validating node.
It has no wallet address, spending key, or note that represents ownership of the
whole pot. Block production credits a fixed fraction of issuance to the pot;
users can donate from shielded funds. An authorized withdrawal debits the pot
and creates a normal spendable shielded note. Public accounting is intentional.
Private user funds remain in the existing shared note and nullifier system.

The allocation is an integer consensus constant, initially numerator 1 and
denominator 5. Changing it requires a hard fork: new rules implemented in
software adopted by the network. It is not a manifest override, environment
variable, RPC setting, or governance transaction parameter. Transaction fees
continue to go to miners and are not subject to this allocation.

Withdrawal authority is a fixed quorum of designated post-quantum public keys.
The threshold and ordered public keys are genesis parameters, not baked-in
network credentials. This reset selects 5 of 7. The implementation accepts valid
N-of-M genesis policies with 1 <= N <= M <= 16, where 16 is a decoding/resource
bound and changing that bound requires new consensus rules. Deterministic test keys are confined to test fixtures. Real public keys
must be selected before producing a launch genesis; development keys must never
silently become network keys. Changing the signer set requires a hard fork and
authorization by the old set under the same quorum used for withdrawals.

There is no withdrawal notice period, spending limit, authorization expiration,
emergency pause, delegated voting, DRep system, general-purpose administrative
key, or authority to access users' private funds. A quorum can spend all mature
treasury funds. Loss of the quorum can prevent both payouts and authorized signer
rotation; this is a direct consequence of the requested authority rule.

The deployment model is a full chain reset. New genesis initializes a zero
treasury balance, zero withdrawal sequence, and the initial signer policy.
Existing wallet balances and existing treasury funds are not migrated or
automatically credited. Preparing this branch does not reset any running node.

## Current implementation and required changes

`node/src/native/node_impl.rs::build_allocated_reward_action` computes
`block_subsidy(height) / 5` and constructs a miner note and a funding note.
`node/src/native/block_flow.rs::validate_coinbase_funding_accounting` requires
the latter to match the manifest's funding address. The existing reward action
may be absent, in which case both subsidy shares are forfeited. The successor
will require one reward transition per non-genesis block, making the treasury
credit implicit and mandatory. Zero-subsidy blocks still carry this transition
so fee accounting remains explicit. This change must be covered by consensus
tests rather than inherited from old empty-block fixtures.

`consensus/src/reward.rs` defines the issuance schedule, maximum supply and
re-exports the 120-block reward maturity rule. These monetary parameters are
retained. `node/src/native/mod.rs::NativeState`, canonical state checkpoints,
block commitments, storage and replay currently lack a protocol treasury pot.
They must acquire authenticated treasury state together.

`circuits/transaction/src/private_spend/types.rs::PrivateSpendPublic` currently
has no public donation amount or memo binding. Its circuit balances private
inputs against private outputs plus a miner fee. Consequently an ordinary
private-spend proof cannot safely be relabeled a donation. The successor needs
a new proof statement and circuit identity. Donation value must never be
smuggled into the fee field or inferred from wallet bookkeeping.

The legacy private 2-of-3 treasury accumulator is a separate wallet/proof feature.
It does not authorize withdrawals from this public pot. The new mechanism uses
direct ML-DSA-65 signatures through the existing `crypto/src/ml_dsa.rs` APIs;
distinct signer slots sign one canonical authorization message.

## Treasury state and block order

All amounts are integer HGN atoms (`100_000_000` atoms per HGN). No floating
point arithmetic is allowed. State contains a mature balance, a bounded queue of
subsidy credits waiting for maturity, a next-withdrawal sequence number, the
current signer-policy digest and governance epoch, and any scheduled authorized
hard-fork transition. Governance epoch here means a signer-policy generation,
not a reward epoch. Balances use checked arithmetic and cannot exceed the native
maximum supply. Counters reject overflow instead of wrapping.

At the start of inclusion block h, release queued credits whose maturity height
is h into the mature balance. Process actions in their encoded block order,
validating each against the updated state. Withdrawals can use funds already
mature at the block's start, including credits just released at h, but cannot
use donations made within that same block. Accumulate current-block donations
separately, then credit them to the mature balance at block end. Finally apply
the unique reward transition, crediting the treasury subsidy to the immature
queue and appending the miner's reward note. Commit all resulting state together.
No later action can depend on a reward appended at block end.

At height h, with subsidy S and total included miner fees F, compute
T = floor(S * TREASURY_SUBSIDY_NUMERATOR / TREASURY_SUBSIDY_DENOMINATOR)
using a widened intermediate. The miner receives S - T + F, preserving every
atom of rounding remainder. A nonzero T matures at h + 120. Reuse the existing
checked maturity function, with its exact inclusion boundary. Credits can be
stored by release height; the queue has at most 120 entries after a block.
Zero-value credits do not create entries. An unrepresentable maturity height
rejects a block rather than dropping or prematurely releasing the credit.

Donations are transfers of already issued value. They become withdrawable in
the block following their inclusion, without a new 120-block delay. Withdrawn
notes are also transfers of existing value and have no coinbase maturity tag;
their later spending follows ordinary note reference rules. Neither transition
can make immature subsidy spendable sooner.

## Permissionless transparent donations

A donation spends normal shielded inputs using a successor proof. Its public
fields include the native asset identifier, a strictly positive donation amount,
a separate miner fee, the usual chain/reference/nullifier/output/ciphertext
bindings, and a commitment to an optional public memo. The proof establishes
`sum(inputs) = sum(change outputs) + donation + miner_fee`, input authority,
membership, asset equality and all normal spend constraints. Existing input
arity, change outputs and reference-window policy can be reused; inherited
authorization branches must be explicitly checked for compatibility. A memo is
authenticated data, not an executable command or a recipient instruction.

The public memo is at most 256 UTF-8 bytes, with length checked before allocation
and proof work. Empty is the sole canonical representation of an omitted memo.
Do not normalize text during validation. Bind the exact length and bytes through
a domain-separated consensus hash in the public proof statement so a relay
cannot replace the memo on a valid proof. Reject noncanonical encodings,
oversized memos, zero amounts, non-HGN assets, arithmetic overflow, duplicate
nullifiers and trailing data. Memo bytes count toward block and mempool byte
limits. Clients render them as escaped plain text and describe them as permanent
public data.

Anyone with eligible HGN inputs can donate without signer permission or
registration. The donor's address, input openings, change amounts and unrelated
balance are not public fields. Nullifiers, commitments, amount, fee, memo and
inclusion timing are public, so timing and memo correlations remain possible.
The cryptographic privacy claim must be checked for the new statement; it is not
established merely by reusing a proof backend.

Subsidy credits have no memo field and no donor transaction. Their amount is
derived deterministically from block height and the compiled allocation.

## Quorum withdrawals into the shared shielded pool

A withdrawal publishes the amount, miner fee, full recipient address, policy
epoch, sequence number and the agreed output commitment/ciphertext binding.
Recipient-address disclosure is the proposed v1 choice: amount and recipient
are transparent, while the note opening and its eventual spending link remain
shielded. A public address can still identify a recipient if correlated with
external information; this must be explicit in the operator UI. There is no
automatic public disclosure of the recipient's other funds.

Use one output per withdrawal in v1. A new payout proof establishes that this
output is native HGN of the authorized value, controlled by the specified full
V8 recipient policy, and bound to the included ciphertext, without exposing the
note's randomness or later nullifier. The proof uses the project's existing
note and encryption primitives. A simple host-side assertion or a signature on
an arbitrary commitment is insufficient: it would permit crediting a note whose
hidden value exceeds the debit. Whether the backend can prove ciphertext
correctness or uses the existing narrower ciphertext-binding guarantee must be
made explicit during implementation and qualification; do not claim a stronger
delivery guarantee than the relation proves.

The authorization commits to a versioned withdrawal domain, chain identity,
genesis identity, active treasury rules digest, signer-policy digest and epoch,
exact next sequence, amount, fee, canonical recipient and output/ciphertext
bindings. Use canonical length-delimited encoding and the existing 48-byte
domain-separated hash framework. Approvals are ML-DSA-65 signatures on the same
message by at least N distinct members of the configured M. Signer indices are
strictly increasing; reject duplicates, unknown indices, malformed keys or
signatures, and noncanonical extra data. There is no expiry or reference-block
hash in this authority message: it remains eligible while its sequence and
policy remain current. Any proof reference requirements are separately bound
and rechecked without widening signer authority.

Anyone may relay a completed bundle. The relay has no authority to change its
destination, value, fee or output. Successful inclusion checks mature funds
cover amount + fee, verifies proof and signatures, debits that exact sum,
appends one recipient note, credits the fee through normal miner accounting,
and increments the sequence exactly once. Failed actions change nothing.
Concurrent proposals with the same sequence conflict; after one is included,
others must be rebuilt and approved again. A reorganization reverses inclusion,
so an orphaned authorization can become eligible again on the surviving chain.

The fee is public and signed separately from the payout amount. There is no
treasury percentage charged on fees and no fee burn. Both donation and withdrawal
fees must be included exactly once in the block fee total.

## Signer policy and hard-fork authorization

The initial policy fixes genesis-configured N, M, a canonical ordered list of
distinct ML-DSA-65 public keys, and epoch zero in the fresh genesis identity.
This reset uses N=5 and M=7; another fresh genesis may select another valid
threshold without editing source code, within the 16-signer resource bound.
Invalid thresholds,
duplicate keys and malformed keys reject at initialization. N and M remain
unchanged for signer replacements in v1. Changing the threshold or allocation
itself requires a separately specified hard fork, not the signer-replacement
action described here.

A signer replacement has two necessary components: software implementing a
specific successor rules identity at an explicit activation height, and a
certificate approved by N distinct current signers. The certificate commits to
the existing chain/genesis identity, current policy digest and epoch, successor
policy digest with its exact ordered keys and unchanged N/M, activation height,
and successor protocol-rules digest. Withdrawal approvals cannot be reused as
fork approvals because their domains and encoded fields differ.

The certificate is included and authenticated on the canonical chain before
activation. V1 permits one pending replacement at a time. Scheduling must be for
a future block height and cannot introduce arbitrary executable code or new
rules absent from the installed software. A branch implementing the transition
rejects activation without the matching certificate and compiled successor
identity. At the start of the activation block, the policy epoch increments,
the new keys take effect, and old-epoch withdrawal bundles become invalid.
The withdrawal sequence continues without resetting. A reorganization restores
the corresponding scheduled certificate, keys, epoch and sequence together.

This is a restricted governance capability for treasury payouts and certified
signer changes. It is not a general mechanism for changing monetary policy or
issuing arbitrary administrative commands. Nodes still need compatible software
and operators/miners must adopt a hard fork. No rule can stop a different network
from running rewritten software that deliberately discards the certificate
requirement; the guarantee applies to validation under these specified rules.

## Accounting and security invariants

Define Q as mature treasury balance plus all immature treasury credits, and P
as the conceptual total of unspent HGN outside the treasury, including immature
miner rewards. P is an accounting quantity established through proofs; private
note values need not be publicly summed. Let I be cumulative subsidy issued
since zero-supply genesis. With no burns in this design, `P + Q = I` and I never
exceeds MAX_SUPPLY. Treasury movements are transfers and do not count as new
issuance in the existing supply digest.

A block subsidy increases P by S-T and Q by T. An ordinary miner fee transfers
value within P. A donation of D with fee F decreases the donor's pool value by
D+F, returns F to the miner, and increases Q by D: net P change -D and net
Q change +D. A withdrawal of A with fee F decreases Q by A+F, increases P by A
for the recipient and F for the miner, and leaves I unchanged. Releasing an
immature treasury credit changes only the partition within Q.

Every accepted block has exactly one deterministic subsidy transition. No
action can create an additional treasury funding note or claim both the old
wallet allocation and the pot credit. A zero subsidy creates zero new supply.
All amounts and intermediate sums reject overflow/underflow and satisfy proof
range constraints. A pot debit can consume mature funds only. Donation credits
must have matching accepted proof debits; withdrawal outputs must have matching
accepted pot debits. Every fee is removed from one source and credited once.

Every withdrawal consumes precisely the current sequence and sufficient distinct
current-policy signatures. Each policy replacement consumes its current epoch
and a quorum certificate for the exact installed successor. A transaction or
certificate valid on another network, another genesis or another policy cannot
authorize an operation here. These are protocol enforcement claims, independent
of whether the signers' off-chain funding decisions are wise or representative.

Treasury balances, maturity queue, sequence, policy and pending replacement are
included in authenticated state commitments. They are persisted atomically with
notes, nullifiers, supply and the block tip. Mining, mempool simulation, live
import, historical replay, fork replay and startup use the same state transition.
Dropping a candidate or rejecting a block publishes none of its mutations.
Restoring a fork restores every component together. Treasury RPC is generated
from one canonical snapshot and identifies the height and block hash.

## Proof, wire and storage versioning

Add successor treasury action and proof identifiers through the existing
protocol-versioning registry; allocate numeric identifiers only after checking
all active and retained registrations. Donation and payout proofs receive fresh
relation/compiler/source identities and known-answer fixtures. Retain the old
v4 proof statement for its own supported actions, and reject old wallet-funding
reward actions under the new genesis rules. Do not reinterpret historical proof
bytes or present old security/proof measurements as evidence for changed source.

The new network schema commits a treasury rules digest and initial governance
policy instead of a mutable funding address or allocation fraction. The digest
covers the allocation constants, maturity, mandatory reward transition, state
encoding, authorization domains, memo limit, fee treatment and action/proof
identities. Reset manifests, chain identities, genesis data and wallet contexts
must be regenerated together. Old databases fail identity checks; no migration
or automatic deletion is performed. Regenerating network identity must avoid
circularity: initial policy does not contain chain ID, but operation messages do.

Extend native block commitments and canonical checkpoint schemas to authenticate
treasury state. A public balance in a separate unauthenticated database table
would not meet the design. Add decoding limits before accepting keys, approvals,
memos, ciphertexts, queued credits or scheduled certificates. Use the existing
ML-DSA implementation and consensus hash suite; introduce no new cryptographic
primitive or transparent account system for ordinary users.

## Operator and wallet surface

Provide a read-only treasury RPC returning canonical height/hash, mature and
immature balances, pending credit release heights, allocation constants, signer
public keys/quorum, policy epoch, next withdrawal sequence and any pending fork
certificate. Public history exposes subsidy credits, donation amounts/memos and
withdrawal amounts/recipients with canonical transaction/block identifiers.

Provide CLI operations to donate, inspect status, prepare a withdrawal, review
and sign it offline, combine approvals, submit, and reconcile uncertain inclusion.
Provide the same prepare/review/sign/combine flow for a signer-change certificate.
No signer private key goes to a node, mining pool, manifest or repository. A
signer reviews the human-readable chain, amount, fee, recipient and sequence
derived from the exact canonical bytes they approve. Status distinguishes
prepared, insufficient approvals, submitted, canonical, orphaned and superseded.

Test support may generate disposable keys and isolated reset manifests. Launch
tooling rejects those known fixture keys. Reset instructions preserve previous
databases and backups, use new base paths, and require deliberate operator
execution after implementation acceptance. Shared miners use the approved
`HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`
unless deliberately rotated, agree on network identity and seeds, and enable
NTP/chrony because future-skewed PoW timestamps reject.

## Acceptance and delivery

The design milestone is complete when these decisions and the implementation
plan are committed to a GitHub branch based on main. That branch is not described
as a working protocol until all implementation milestones pass.

Implementation acceptance requires real-proof donation and payout tests, genuine
ML-DSA quorum approvals, wrong-chain/policy/message rejection, duplicate-signer
and replay rejection, subsidy/maturity boundaries, atom rounding and zero subsidy,
memo mutation and limits, insufficient mature balance, concurrent withdrawal
ordering, fee conservation, invalid-block atomicity, restart and two-node reorg
agreement, authenticated state tampering rejection, and certified signer
replacement at an actual activation boundary. Supply property tests run over
mixed generated sequences. A fresh-node sync must reproduce the same treasury
state from genesis. A happy-path demo alone is insufficient.

The remaining launch inputs are the seven actual initial public keys. The
implementation should proceed with clearly isolated 5-of-7 fixture policies
while these keys are selected; no live-network launch is implied or required by the
request to prepare the branch.
