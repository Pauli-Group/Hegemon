# Ship the positive native HGN source for V8

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while implementation is
in progress. It follows `.agent/PLANS.md`.

## Purpose / Big Picture

The V8 transaction relation correctly requires zero transparent value balance,
so an empty V8 note tree cannot create positive HGN. After this change, a miner
with a V8/Eta address receives the public subsidy plus fees as one exact V8 note
without generating a transaction proof for every block. Consensus recomputes
the seven-limb note commitment, binds the exact 2,147 ciphertext bytes, appends
the commitment after all proved transaction outputs, and preserves that state
through restart, sync, and reorganization. The route remains unreachable while
the single V8 production capability is absent.

## Progress

- [x] (2026-08-23) Chose a distinct miner-local action rather than relaxing
  `value_balance`, importing a trusted snapshot, or adding a per-block proof.
- [x] (2026-08-23) Added the exact public opening/payload wire and source
  Poseidon2 note/auth-key helpers with deterministic fixture vectors.
- [ ] Add capability-gated node construction, admission, accounting, and V8
  append ordering.
- [ ] Add V8/Eta address and ciphertext construction plus wallet vectors.
- [ ] Run focused tests/checks and record exact bytes and remaining release
  gates.

## Surprises & Discoveries

- The existing legacy coinbase publicly exposes enough material to recompute
  its note commitment. Doing the same for V8 costs no privacy regression and
  avoids a 25-minute proof in every block.
- A nonempty activation root is not a migration. The append frontier, leaf
  records, ownership openings, supply, and release identity would also have to
  be bound. Fresh activation from the canonical empty root is the smaller safe
  path.

## Decision Log

- Decision: reserve shielded action 11 for V8 coinbase; keep action 6 before
  activation and make the two routes mutually exclusive.
  Rationale: issuance is already public and exactly determined by subsidy plus
  fees. A ZK proof adds no monetary guarantee.
- Decision: carry all 18 canonical note-opening words directly.
  Rationale: consensus can recompute the exact HGV8RP03 note hash without a new
  seed KDF or hidden host convention.
- Decision: keep the outer 48-byte commitment vector empty.
  Rationale: seven-limb V8 commitments belong only to typed V8 state and must
  never contaminate the historical commitment tree.

## Context and Orientation

The wire lives in `protocol/shielded-pool/src/poseidon2_v8_coinbase.rs` and the
hash helpers in
`circuits/transaction/src/smallwood_poseidon2_v8_coinbase.rs`. The existing
miner-local builder is `node/src/native/node_impl.rs::build_auto_coinbase_action`.
Admission and accounting are in `node/src/native/admission.rs` and
`node/src/native/block_flow.rs`. Typed V8 append/reorg state is in
`node/src/native/poseidon2_v8_state.rs`. Wallet address/key/note code is in
`wallet/src/address.rs`, `wallet/src/keys.rs`, and `wallet/src/notes.rs`.

## Plan of Work

First freeze the codec and relation-equivalent hash helpers. Then add action 11
as an internal-only route selected only when the source V8 capability is active.
Decode its typed payload, reject noncanonical or nonnative openings, recompute
the commitment, check exact V8/Eta ciphertext metadata and conventional hash,
and reuse the checked subsidy-plus-fee accounting. Extend typed V8 block plans
with at most one trailing coinbase commitment and append it after all verified
transaction output commitments. Finally add V8 address/key/ciphertext helpers
and two deterministic coinbase openings at positions zero and one for the
retained maximum-shape spend fixtures.

## Concrete Steps

Run focused checks rather than a whole-workspace build while concurrent V8 work
is landing:

    cargo test -p protocol-shielded-pool poseidon2_v8_coinbase --locked
    cargo test -p transaction-circuit smallwood_poseidon2_v8_coinbase --locked
    cargo test -p wallet poseidon2_v8 --locked
    cargo test -p hegemon-node poseidon2_v8_coinbase --locked
    cargo check -p hegemon-node --lib --locked

## Validation and Acceptance

Positive acceptance requires two action-11 coinbases at heights one and two to
decrypt for one V8 wallet, append at positions zero and one, and feed the exact
openings/path into a positive-value two-input/two-output SMZ9 proof at height
three. Both proof variants must survive mining, sync, restart, and a sibling
reorganization unchanged. Negative tests cover external submission, missing or
wrong capability, preactivation action 11, postactivation action 6, both routes
in one block, wrong/final ordering, amount/range/field/commitment/ciphertext
mutations, duplicate application, and legacy-state contamination.

## Idempotence and Recovery

All source changes are additive until the release-owned route switch. The
capability remains `None`, so an incomplete build cannot mint. V8 state plans
are read-only until included in the existing atomic sled commit; failed
verification or readback leaves canonical state unchanged.

## Outcomes & Retrospective

In progress.
