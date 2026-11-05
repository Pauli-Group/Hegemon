# Treasury and reward-account explorer API

Status: backend read models and RPC dispatch are implemented on
`codex/protocol-treasury-governance`. Native account-aware publication and the
successor network's activation are still open work in the
[protocol execution plan](../.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md).
The existing explorer's UI and indexer integration are paused pending its source
repository location, at the user's request. The
[explorer execution plan](../.agent/PROTOCOL_TREASURY_EXPLORER_EXECPLAN.md)
records that remaining work. No explorer was deployed or public chain reset.

## Availability and precision

These four JSON-RPC methods are read-only and available under the node's normal
safe RPC policy. They never initialize account storage, change a signer policy,
repair an index or accept a caller-provided ledger/root. Discover them through
`rpc_methods`; older nodes may not support them.

All responses use schema `hegemon.native.reward-accounts.explorer.v1`.
Amounts ending in `_atoms`, compiled subsidy-fraction components, heights,
epoch numbers/lengths, claim sequences, policy generations and note-root field
words are canonical decimal strings. Use integer arithmetic, such as JavaScript
BigInt; one HGN is 100,000,000 atoms. Limits, bounded row counts/offsets, action
indices, scan counts and signer counts are small JSON integers. This preserves
exact large field words and even genesis-configured epoch lengths beyond
JavaScript's safe-integer range. Network/account identifiers and roots use
lowercase hexadecimal; public addresses use the network-aware Bech32m
`heg`/`heg_test` envelope.

A status response from a legacy network contains `configured: false`,
`active: false`, `reason: "network-does-not-use-reward-accounts"` and null
`supply`, `treasury` and `governance`. A configured successor without a published
canonical account ledger instead returns `configured: true`, `active: false`,
`reason: "canonical-reward-state-unavailable"` and immutable `parameters`.
Those are unavailable states, not zero balances. Do not infer activation from
API discovery or genesis configuration alone. The current v2 startup guard
continues to reject incomplete runtime dispatch.

Active balances require the node's canonical ledger and matching block context,
account root and header supply. The node checks the final mandatory reward
record against the ordered action commitment and pins reads using the canonical
persistence lock order. RPC cannot manufacture the ledger needed to pass this
check. The parent runtime must install it with the block and note state.

## Requests and snapshots

Parameters are either `[]` for defaults or one query object inside an array,
`[{...}]`. Extra objects, unknown fields, negative/fractional offsets, malformed
hashes and excessive limits reject. Each method uses only its fields below.
An optional `at` is a 32-byte lowercase canonical hash, optionally prefixed by
`0x`. Status, account and genesis methods accept only the current tip if `at`
is supplied; a changed tip rejects instead of mixing snapshots. Account lookup
is current-state only, not an arbitrary historical balance query.

An active `context` contains `chain_id`, `genesis_hash`, `genesis_config_hash`,
`height`, `block_hash`, `accounts_root` and the seven-word `note_root` array of decimal strings. Pin chain
and genesis before reusing a cache or index. Retry a set of current-state reads
from a fresh status snapshot when `at` becomes stale. The inactive context has
only chain identity, height and block hash; no account root is invented.

## hegemon_rewardAccountsStatus

Call with `[]` or `[{"at":"<current hash>"}]`. An active result contains:

- `parameters`: network class/discriminator, genesis configuration hash, reward
  epoch length, initial treasury authority, fixed treasury address, compiled
  1/5 subsidy fraction, allocation count, total genesis allocation, original
  mining budget, maximum supply and eight atom decimals. Public account transfers
  and epoch finality are explicitly false.
- `epochs`: current reward epoch (null at genesis), next block height and epoch,
  next epoch boundary, epoch-zero release height, and explicit variable-time and
  no-finality indicators. At genesis the next epoch boundary is block one.
- `supply`: `genesis_allocation_atoms`, `mining_issued_atoms`, `shielded_atoms`,
  `available_account_atoms`, `pending_account_atoms`, `total_issued_atoms`,
  `remaining_mining_atoms` and `max_supply_atoms`.
- `treasury`: the account shape described below, including the fixed address.
- `governance`: current `policy_generation`, `authority` and optional
  `pending_replacement`, plus the requirement for a current-quorum certificate
  and matching software hard fork.

The supply projection checks P+A+U=G+I<=MAX_SUPPLY. Remaining mining issuance is
MAX_SUPPLY-(G+I), distinct from the original mining budget MAX_SUPPLY-G. Genesis
allocations are immediately available and receive no automatic treasury cut.

An authority has `policy_hash`, `required`, `members` and ordered
`signer_key_hashes`. A pending replacement has `current_generation`,
`activation_height`, `successor_rules`, `successor_authority`, `approval_count`,
`approving_signer_indices` and `certificate_digest`. It represents the shared
ledger's admitted quorum certificate, not a vote or mutable administrative power.
The successor authority hash is independent of the fixed treasury identity.

## hegemon_rewardAccount

Call with `[{"address":"heg_test1...","at":"<current hash>"}]`; `address`
is required and `at` is optional. Binary/hex aliases and shielded addresses are
not accepted. The address must match the genesis network class and discriminator.
The response contains `context` and `account`.

An account has `address`, raw `account_id`, `is_treasury`, `available_atoms`,
`pending_atoms`, `total_atoms`, `claimable_next_block_atoms`, `next_sequence`,
`policy_generation`, `authorization` and `pending`. Each pending bucket has
`earning_epoch`, `release_epoch`, `release_height` and `amount_atoms`.
`authorization` is the current authority for the treasury and null for an ordinary
account. The ledger stores an ordinary account's policy hash; its disclosed
descriptor can appear in claim activity. Ordinary generation is
zero. A valid active address with no credits returns zero balances; this differs
from a network with no active account ledger.

Available balance describes the completed displayed block. Next-block
claimability separately accounts for release at the next block's start. For
E=1440, an account at h2880 still has epoch-zero rewards pending, but its
`claimable_next_block_atoms` includes them for h2881. At h2881 they are available.
Rewards earned in h2881 remain pending until their own N+2 release. There is no
extra 120-block reward maturity. These heights are availability rules, not finality
or a guaranteed wall-clock deadline; the expected wait is approximately one to
two days at the target minute-per-block interval, with variable elapsed time.

## hegemon_rewardAccountsGenesis

Call with `[{"offset":0,"limit":25,"at":"<current hash>"}]`; all fields are
optional. Limit is 1–100. Offset is a zero-based row offset into the canonical,
sorted immutable genesis distribution and may equal its length for an empty
terminal page. Larger offsets reject.

The result contains schema, `chain_id`, `genesis_hash`, immutable `parameters`,
`rows`, `total_rows` and `next_offset` (null at the end). Each row has `address`,
`initial_amount_atoms` and `is_treasury`. These are original allocations, not
current balances. Genesis data can be read when configured even if canonical
reward-account state is unavailable; it is not evidence of runtime activation.

## hegemon_rewardAccountsActivity

Call with `[{"from_height":"1","action_index":0,"limit":25,"at":"<anchor hash>",
"address":"heg_test1..."}]`. All fields are optional. `from_height` accepts a canonical decimal string or
an unsigned JSON integer; continuations emit its exact decimal string. The default anchor is the
current tip, default starting height is one and default limit is 25. Limit is
1–100. Genesis allocations have their own endpoint. `address` filters by a
validated public account and must be retained when continuing a filtered query.

Results contain schema, chain/genesis identity, `anchor` (height and hash),
`rows`, `scanned_blocks` and `next_cursor`. At most eight canonical blocks are
scanned per request, even when a filter matches no rows. A zero-row page may
therefore have a continuation cursor. The cursor includes `at`, `from_height`,
`action_index` and the account filter. Rows are ordered by ascending block and
action index. A page can stop within a block; the next index points to the first
unread action. Each row has `height`, `block_hash`, `action_index` and the
48-byte canonical `action_id` in addition to its public fields.

Unlike current-balance reads, history can continue against a previously selected
canonical ancestor while new blocks arrive. The node rejects an unknown or
orphaned anchor. A client must discard its accumulated page set when that anchor
is reorganized, and begin again from a fresh canonical anchor. Never append pages
from another chain, anchor or account filter. A persistent index must undo rows
on detached blocks and replay the replacement suffix before publishing a tip.

Kinds and public fields are:

| Kind | Fields |
| --- | --- |
| `block-reward` | `miner_address`, `treasury_address`, subsidy, miner fees, miner credit and treasury credit in atoms; earning/release epochs and release height |
| `treasury-donation` | Treasury `address`, amount, fee, public UTF-8 `memo`, and `first_claim_height` (the following block) |
| `account-claim` / `treasury-withdrawal` | Source `address`, amount, fee, sequence, policy generation, disclosed authorization and network-aware shielded `recipient` |
| `treasury-signer-replacement` | Fixed treasury `address`, current generation, activation height, successor authority/rules, approval count and certificate digest |

A signer-replacement row records certificate admission with a scheduled activation
height; it does not assert that activation has already occurred. Current authority
comes from the status snapshot. The protocol's actual block transition must
activate the matching fork and roll it back on reorg.

Rewards have no memo. The treasury receives floor(subsidy/5); miners receive the
remainder plus fees/tips once. No account-to-account transfer kind exists. The
API checks exact native framing and committed action bodies before projecting
activity; decoding alone never validates a private proof or installs account
state. Ordinary private-spend openings and wallet secrets are not returned.

## Explorer integration and acceptance

Use text rendering for memos, addresses and all node-provided strings. Do not
interpret memo text as HTML. Wrap and copy complete PQ addresses without
rewriting them. Display mainnet/testnet and a pinned chain identity prominently;
HRP alone is not a network check. Use BigInt and fixed eight-decimal formatting
for HGN. Show unavailable, disconnected and stale states explicitly.

Build Treasury, Reward Accounts, Genesis/Supply and Governance views in the
existing explorer once Pierre supplies its repository location. Include public
account links from blocks and search, release buckets and first-claim heights,
partial withdrawals and donation memos, supply conservation, initial allocations
and current quorum/certificates. Preserve existing block and legacy reward views.
The user paused this UI work pending that source; no substitute explorer is
published in this branch.

The backend tests cover exact supply under empty/partial/full genesis,
current-versus-next-block availability, initial allocation pagination, typed
network checks, genuine quorum certificate projection, bounded activity traversal,
mid-block cursors, malformed canonical bodies, strict requests, safe-method
advertisement and real legacy-node dispatch/HTTP handling returning unavailable
data without any database writes. Shared
account transitions and ML-DSA certificates are exercised; tests rejecting all
private proofs cannot qualify claims or running-chain behavior.

Before claiming the explorer fully implemented, complete native activation and
exercise actual explorer requests against two disposable nodes through a real
claim/donation, boundary reorg, signer replacement, restart and fresh sync. Compare
account/note roots, supply and activity at identical canonical hashes. UI rendering
and indexer rollback acceptance remain deferred alongside its source location.
