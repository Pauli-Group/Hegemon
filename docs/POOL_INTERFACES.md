# External mining pool interface

This guide describes the current source interface. Source presence, unit tests,
a disposable lifecycle and an approved public release are separate evidence.
Use the published release/genesis record for an actual join; this guide does
not select a network, approve a treasury address or authorize deployment.

## Separate work, accounting and spending

The pool requests work with `hegemon_poolWork` (`hegemon_compactJob` alias),
submits network-target solutions with `hegemon_submitPoolShare`
(`hegemon_submitCompactSolution` alias), and reads `hegemon_poolStatus`.
The daemon validates network-target solutions through the normal block import
path. It does not keep miners' lower-difficulty share balances: those shares,
worker identities and the payout ledger remain the external pool's job.
The existing `scripts/bitcoin_asic_stratum.py` is a bounded ASIC adapter, not a
pool accounting or custody service.

Keep spending keys and payout construction in a separate wallet process. The
pool work interface cannot unlock a wallet or construct payments. Maintained
`private-spend ordinary` payment amounts and fees are exact integer atoms.
An ordinary transaction has two output slots: normally one payee and change.
Paying several miners therefore requires a queue of individual transactions;
this interface does not promise a many-recipient batch or recursive proof.
Choose payout minimums and cadence with measured fees and throughput.

## Restricted access

Start the node with `--rpc-methods=pool` and a loopback RPC listener. The policy
allows only `rpc_methods`, basic system identity/health, `chain_getBlockHash`,
`chain_getHeader`, `hegemon_nodeConfig`, `hegemon_consensusStatus`, the pool
work/share/status methods and `hegemon_blockReward`. It denies wallet/action
submission, DA writes, mining start/stop, peer topology and witness export.
Both individual and batch requests pass through the same method gate. The
role cannot be combined with `--rpc-external`.

For a remote pool host, use existing authenticated SSH forwarding to the
node's loopback port, or an operator-managed authenticated gateway. The pool
role restricts methods; it does not authenticate callers. On a shared host,
other local users/processes may reach loopback. The adapter rejects a nonempty
legacy `--rpc-token-env` value: putting `auth_token` in JSON parameters is not
node authentication. Do not expose the unrestricted `unsafe` listener to the
Internet. Keep any wallet submission control plane separate from this role.

Before requesting work, compare the approved release/binary, manifest chain
identity, genesis hash (`chain_getBlockHash` at height zero), active rules and
configured full payout address. A matching algorithm name or seed hostname
alone does not establish that the daemon is on the intended chain. Enable
NTP/chrony; the native future-timestamp bound applies to mined work.

## Reward accounting

Call `hegemon_blockReward` with exactly one explicit block hash:

```json
{"jsonrpc":"2.0","id":1,"method":"hegemon_blockReward","params":["0x<64 hexadecimal characters>"]}
```

The `hegemon.block-reward.v1` response identifies the block, chain and observed
canonical tip. It includes `canonical`, `confirmations`, `reward_present`,
scheduled and issued subsidy, fees, separate miner/treasury amounts and public
reward commitments. All `*_atoms` amounts are decimal strings. Parse these as
integers, never binary floating point; preserve that representation through
payout calculation and review. Unknown hashes return `null`. A known block
without a reward has `reward_present=false`; scheduled subsidy is not evidence
of actual issuance.

For V8 notes, `recipient_key_hex`, `authorization_key_hex` and
`authorization_extension_hex` are the on-chain public recipient binding, not
a reconstruction of the full shielded address or its encryption key. Compare
those words and the commitment against the independently configured pool
recipient. A matching amount alone does not prove the block paid the pool.
The legacy response has a separate `recipient_address_hex` shape.

Public V8 reward openings already permit this check without spending keys or
a new ZK receipt. A reward response is an observation, not finality: recheck
canonical membership before crediting or paying, and reverse orphaned credits
in the pool ledger. Do not count acceptance of a submitted block as permanent
canonical settlement.

## Reward maturity and payout policy

Both miner and treasury rewards created at height `h` first become spendable
in a block at `h + 120`. Consensus delays their insertion into the spendable
note tree until the end of `h + 119`, after ordinary outputs; it appends the
miner note before the treasury note. Same-block anchors do not allow spending
them early. Ordinary transaction outputs do not acquire this reward delay.
For example, a reward from block 1 first permits spending in block 121.

The RPC reports `maturity_blocks`, `maturity_height` and
`height_eligible_for_next_block`. Height eligibility does not establish wallet
ownership, unspent status, a valid proof or finality. A reorg can orphan or
remove a released reward and invalidate a pending spend. The pool must choose
its additional confirmation/reserve policy and reconcile that ledger against
the canonical chain. Consensus maturity is not a checkpoint or a guarantee
against a deeper reorg.

The maturity schedule participates in launch-reference rules and the pending
reward state has a separate codec identity. Do not reinterpret an older
immediate-spend database, root or proof fixture under these rules. Use the
approved fresh pre-mainnet identity and fresh state for this rollout; a future
upgrade of an established chain needs an explicit activation/migration rule.

## Expiry, stale work and interrupted submissions

Jobs expire after 120 seconds and carry their exact parent, target, timestamp,
pre-hash and job identity. Refresh expired work and reject parent/template
changes. Node submission accepts only solutions meeting the network target;
a local share below that threshold can still be creditable under the pool's
own share policy. Do not confuse that policy with daemon block acceptance.

An explicit busy error may permit retrying the exact solution while its job
remains valid. A timeout can happen after import succeeded. Reconcile the
candidate's block hash and canonical reward before marking it rejected or
crediting again; never treat an unknown submission status as a fresh payment
or a second earned block. Accepted shares, accepted blocks and paid miners
are distinct journal states.

## Validation and release boundaries

Reuse existing Bitcoin80 node tests, `scripts/test_bitcoin_asic_stratum.py`
and `scripts/test_bitcoin_asic_live.py`; add focused contract checks for the
reward fields, recipient binding, pool method denial, maturity boundary,
restart/reorg and ambiguous submission. Run live checks with a pinned compatible
binary and disposable state. These named tests are a validation method, not a
claim that a particular new artifact has passed them.

For `scripts/release_private_spend_lifecycle.py`, the single-key fixture
exercises four fresh proof cases: ordinary, lock, claim and refund. Its
single-key treasury payout is another ordinary action. The legacy 2-of-3
fixture exercises six cases including approval/final. Report the custody mode
and actual coverage; do not label four fresh cases as six. Reuse unchanged
PR205 evidence only for its matching inherited premises and retain the
current source/parameter/identity delta. Neither local fixture coverage nor a
pool integration run closes G8 without the final authorized release tuple,
artifact/build binding and required release checks.

A private single-key treasury operator tool is a separate deliverable. It can
wrap wallet creation, encrypted backup/restore, review and submission without
putting treasury spending authority in the pool server. AuxPoW merge mining,
new finality/checkpoints, a new ZK reward receipt and many-recipient proofs are
separate protocol features; this interface does not silently activate them.
