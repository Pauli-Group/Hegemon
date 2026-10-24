# Bounded spending policies and explicit secret release

This document describes the new candidate source delta. It does not authorize
production use. The production source registry remains fail-closed. Historical
PR205 and retained G1–G8 evidence apply only to their exact unchanged premises;
they do not qualify this new relation, public statement or carrier.

## Fixed policy language

A note has exactly two positional branch slots, combined with OR. Branch 0 must
be enabled; branch 1 may be disabled with every parameter zero. Each enabled
branch requires all of:

1. One matching spending credential, identified by a seven-word public authority.
2. Reference-parent height greater than or equal to `not_before`.
3. If enabled, knowledge of a 32-byte preimage of the branch's SHA256 hashlock.

The branch can additionally require public release of that preimage.
`release_secret=true` requires `hash_required=true`. This is a bounded
composition of key, absolute-height and hash conditions, not a recursive script
interpreter: no arbitrary nesting, signature threshold, relative delay, height
upper bound or policy-governance revocation is added.

For example, branch 0 may allow key A immediately, while branch 1 allows key B
once the reference parent reaches height T. After T, both branches remain
usable; B's recovery path does not revoke A. A hash condition can require an
additional shared secret, but sharing that secret is not an independent
joint-signer threshold protocol.

A satisfied branch controls an ordinary spend: its controller chooses the
recipient, amount, change and fee under the same transaction/public-statement
binding as ordinary spending. It is not restricted to a destination specified
when the policy note was created. Do not present a branch authority as a
co-signer for a separate owner's payment intent.

## Note identity and custody

The policy owner commits the chain, asset, policy version, both complete branch
descriptors and one independently generated shared nullifier key. The accepted
relation currently restricts the asset to native coin zero; the owner format's
asset field does not activate non-native assets. All branches spend the same
note using the same nullifier at its canonical position, so switching branches
does not create an independent spend or evade replay detection.

The public branch configuration contains no preimage or nullifier key. Its
fields are `enabled`, `authority` (seven canonical field words), `not_before`
(an integer below `2^48`), `hash_required`, `hashlock` (32-byte hexadecimal) and
`release_secret`. There must be exactly two branches. Unknown fields, a
nonzero disabled branch, a zero enabled authority, a hash without its flag, or
release without a hash are rejected. Derive real authorities from the intended
wallets' public authorization identities; do not substitute test constants.

The full private note payload includes the shared nullifier key and must reach
any alternative branch wallet that may spend. A normal encrypted note output
is sent to one full V8 recipient whose authority matches an enabled branch;
it is not automatically encrypted separately to both controllers. Use the
encrypted policy handoff for the other branch and retain it with recovery
material. A copied public JSON descriptor alone cannot restore spendability.

## Wallet workflow

Use the maintained `private-spend` CLI with the exact wallet, manifest, genesis
and RPC context. The following are command shapes, not a production launch
recipe. Candidate use requires a deliberate disposable Development network,
a candidate-capable build and the explicit `--development-local-candidate`
option; source-authorized use remains unavailable until the new tuple is
qualified.

- `policy-lock --inputs POSITION [POSITION] --policy PUBLIC_JSON --recipient ADDRESS --amount ATOMS --fee ATOMS [--policy-handoff NEW_FILE]`
  creates a candidate policy note and optional encrypted handoff. Amounts and
  fees are exact integer atoms. The wallet generates the shared nullifier key;
  it is never supplied in the public JSON.
- Retain the returned candidate ID, then `export ATTEMPT NEW_FILE` or
  `submit ATTEMPT` uses its exact retained action. Synchronize after canonical
  inclusion before deriving the locked note position.
- On another branch wallet,
  `import-policy-handoff FILE --block-height HEIGHT --recipient-index INDEX`
  prompts for the handoff passphrase and verifies the exact canonical lock
  block and that the local credential controls an enabled branch. If export
  was interrupted, `export-policy-handoff ATTEMPT NEW_FILE` retries the retained
  handoff without creating a different note.
- `policy-spend --locked POSITION --fee-input POSITION --branch 0|1 --recipient ADDRESS --amount ATOMS --fee ATOMS`
  requires a separate ordinary fee input and an enabled, mature branch. If a
  hash is required, it prompts without echo for exactly 32 bytes of hexadecimal
  preimage; no command-line preimage argument is accepted. The branch controls
  the payment destinations, including change. Review before exporting or
  submitting the retained action.

Policy preparation rejects a reference parent below `not_before=T`; the first
possible inclusion is T+1 because the condition applies to the parent, not the
spending block. This is an absolute chain height, not a wall-clock time or
confirmation count. Synchronize and prepare against the canonical reference;
a reorg can invalidate that reference and its membership witness. Replay and
unknown submission outcomes use the existing exact-attempt journal.

## Explicit public release and HTLC compatibility

Every new public statement contains `secret_release` and `released_secret`.
Private mode requires flag zero and 32 zero bytes. A selected releasing policy
branch requires flag one and the exact SHA256 preimage. The spender cannot
suppress disclosure while retaining the same committed policy.

Existing HTLC locks remain private by default. Opt in at lock creation with
`lock ... --release-secret`; the new releasing owner domain commits that
choice. Its claim must publish the preimage, while its refund does not. Old
private HTLC owner preimages and their exact `PSN2` payload bytes remain
unchanged. New releasing HTLC and bounded-policy plaintexts use `PSN3` inside
the existing fixed encrypted frame; ordinary `PSN1` is unchanged.

Disclosure begins when a complete releasing action is exported to someone or
broadcast, before confirmation. Rejection, an orphan, cancellation or a reorg
cannot make that secret private again. Never reuse a released secret for an
unrelated lock. Public release is one building block for a cross-chain swap;
it alone does not establish atomicity, finality, timeout safety, monitoring or
correctness of the other chain's hash/time rules.

This change adds no claim upper deadline. The existing HTLC refund becomes
eligible at its timeout reference height; a valid claim is not thereby revoked.
Claim and refund can race after that timeout, and the shared note/nullifier
allows only one canonical spend. Design external protocols and monitoring for
that existing behavior, rather than assuming a new exclusive claim window.

## Identity, size and validation boundary

The relation is `Hegemon.PrivateSpend.BoundedPolicy.CompFF01.v3` and has 86
public field words. The common carrier is `HGPSLC02`, circuit version 12,
with a 568-byte preamble and two 2,608-byte ciphertext slots. Its fixed portion
is 5,784 bytes plus the actual inner proof. The source digest, geometry and
proof artifacts must be regenerated from the final source. Earlier 77-word,
`HGPSLC01` and measured predecessor proof descriptions in DESIGN/METHODS are
historical evidence; do not edit their recorded hashes or relabel those proofs
as current feature validation.

The optimized `private_spend::policy_tests::bounded_policy_actual_proof_overhead`
run on 2026-10-16 generated and verified all five actual candidates below
(`1 passed; 0 failed`). These are measured serialized proofs, not size
projections. The run used two Rayon threads and overlapped another build and
live proving; its timings are observations, not a controlled old/new speed
comparison.

| Candidate | Inner proof bytes | Carrier bytes | Prove (s) | Verify (s) |
| --- | ---: | ---: | ---: | ---: |
| Ordinary | 2,035,605 | 2,041,389 | 110.176 | 2.591 |
| Policy creation | 2,035,605 | 2,041,389 | 95.800 | 1.298 |
| Absolute height | 2,035,605 | 2,041,389 | 124.342 | 1.373 |
| Policy hash with public release | 2,035,605 | 2,041,389 | 104.089 | 1.290 |
| HTLC with public release | 2,035,605 | 2,041,389 | 100.204 | 1.255 |

Each inner proof is 109,480 bytes larger than the retained 1,926,125-byte
predecessor and stays below the unchanged 2,097,152-byte cap. Each carrier is
109,520 bytes larger than the retained 1,931,869-byte carrier (+5.67%). The
current 86-word geometry has 27,820 rows, 724,453 canonical wires, 1,429,570
linear equations and 5,500 nonlinear batches. The measured process peaked at
2,989,375,488 bytes resident and 3,357,723,792 bytes memory footprint; these
process-level peaks cover the complete five-case run, not each case separately.

The retained local measurement log is
`/private/tmp/hegemon-policy-proof-measurements-final-20261016.log` and emits
five `POLICY_MEASUREMENT` rows with relation digest
`f8ba37c7959718f66be6aa881b2296d5592a83e466afd939818ba1a032c5ee542d3ad0bb67d1f902a3ee988395304c35b061623f96f904061034970a2e1e54eb`.
This finite candidate measurement does not authorize a production release.
The disposable two-node Development lifecycle passed all 18 checks with four
fresh wallet-generated proofs: policy lock/spend and releasing HTLC lock/claim.
It verified exact pending relay, canonical inclusion, both wallet readbacks,
payouts, and restart re-verification of every action. The policy rejected an
early reference parent and a disabled branch before proving; its spend prepared
at exact parent 123 was included at height 124. The HTLC claim carried the exact
required public preimage before confirmation. This live run did not exercise
alternative-controller handoff or reorg; focused wallet tests and unchanged
retained evidence keep their separate scopes. Final production qualification
remains open.

Focused validation must check branch authorization, every owner binding,
absolute-height boundaries, hash failures, mandatory release, zero-padding,
branch-independent nullifiers, double-spend rejection, independent-controller
handoff and canonical import, and exact transport/disclosure binding. Run the
new source/compiler/formal delta and actual wallet/node lifecycle as scoped
qualification. Existing component tests, the ignored benchmark's presence or
old G1–G8 receipts do not authorize this successor in production.

Source owners: `circuits/transaction-core/src/bounded_policy.rs`,
`circuits/transaction/src/private_spend/{types,circuit,policy_tests}.rs`,
`crypto/src/private_note_payload.rs`,
`protocol/shielded-pool/src/private_spend_transport.rs`,
`wallet/src/private_spend_build.rs` and `wallet/src/bin/private_spend.rs`.
