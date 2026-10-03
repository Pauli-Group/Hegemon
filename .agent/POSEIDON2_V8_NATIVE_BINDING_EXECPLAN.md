# Bind the compact Poseidon2 proof to a fresh native transport

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while the work proceeds.
It follows `.agent/PLANS.md` and is a narrow transport/state milestone under
`.agent/SMALLWOOD_POSEIDON2_PRODUCTION_EXECPLAN.md`.

## Purpose / Big Picture

Give the compact Poseidon2/SmallWood proof a fresh, collision-free production
identity and one canonical byte path from wallet construction through native
RPC, relay, mempool, mining, block import, restart, sync, reorg, and fresh-node
replay. The proof bytes must remain unchanged. All attacker-controlled declared
lengths must be capped before slicing or allocating. This change must not
reinterpret V4/Gamma, V5/Delta, V6/Epsilon, V7/Zeta, SMZ1, or SMZ2.

The observable result is a V8/Eta family-1/action-10 `HGV8TX02` native leaf
inside a `SWP8LC02` transport. The leaf contains exactly 120 canonical public
statement words, seven relation/balance-binding limbs, one exact 2,147-byte
ciphertext for every active output in slot order, and the exact `SMZ9` proof.
Pure framing is exactly 1,140 bytes and maximum-shape non-proof data is 5,434
bytes. The source geometry projects 122,863 proof bytes, 128,297 SCALE inline
argument bytes, and a 128,522-byte full canonical `PendingAction`. The full
carrier adds exactly 225 bytes and is checked against a separate 131,297-byte
V8 route cap; this is not a retained measurement. The semantic target remains
`hegemon.smallwood.poseidon2-v8.stablecoin-relation.v1`. The sole source-owned
production capability remains absent until the retained proof artifact and
reviewed release evidence are complete.

## Progress

- [x] (2026-08-23 04:25Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`,
  the parent Poseidon2 plan, and active version, action, wallet, RPC, parser,
  admission, manifest, and lifecycle code.
- [x] (2026-08-23 04:25Z) Confirmed V7/Zeta/action 9 is already reserved and
  selected V8/Eta/action 10 with backend 2 and domain set 4. The additive live
  candidate now uses proof profile 6; profile 5 remains historical.
- [x] (2026-08-23 05:45Z) Added the initial collision-free historical candidate
  and cap-before-allocation `HGV8TX01`/`SWP8LC01` codecs; the live additive
  successor is the later `*02`/SMZ9 identity.
- [x] (2026-08-23 05:45Z) Bound wallet request construction and native RPC
  route-specific shape preflight without enabling staging, the manifest, or
  backend dispatch.
- [x] (2026-08-23 05:45Z) Added the exact 129,498-byte historical zero-output
  framing regression, cap, mutation, context, identity-collision, wallet
  byte-preservation, and dormant-route tests; updated `DESIGN.md` and
  `METHODS.md` without freezing it as the accepted-proof maximum.
- [x] (2026-08-23 06:05Z) Finished the focused node route, fixed-gate,
  ten-test state lifecycle, and kernel manifest-negative loop; Rust formatting
  and the scoped whitespace check pass.
- [x] (2026-08-23 07:25Z) Inlined exact active-output ciphertexts, added
  BLAKE2b-384 statement rebinding and per-activity proof caps, and updated the
  wallet/RPC/lifecycle roundtrips without changing ciphertext or proof bytes.
- [x] (2026-08-23 07:35Z) Added the source-digest-pinned native connector that
  reconstructs all 120+7 verifier values, calls the real source-owned verifier,
  and returns roots only after successful SMZ9 verification.
- [x] (2026-08-23 12:40Z) Migrated the live candidate additively to
  `HGV8TX02`/`SWP8LC02`/SMZ9/profile 6 while preserving the `*01`/SMZ8/profile
  5 grammar as mutually rejected historical decode.
- [x] (2026-08-23 13:20Z) Connected contextual proof/state verification to
  RPC/mempool admission, relay group commit, mining selection, normal block
  import, atomic canonical commit, reorg detach/attach, restart, and fresh-node
  replay without projecting seven-limb values into historical 48-byte state.
- [x] (2026-08-23 14:20Z) Restored a temporary one-V8-action mempool/block guard
  after review found legacy semantic-hash ordering, queued-parent races, and DA
  prefix accounting above the already-correct multi-leaf state store. V8 is
  excluded from legacy transfer ordering and legacy DA ciphertext accounting.
- [x] (2026-08-23 16:10Z) Connected the typed pending-chain planner under the
  one-action guard to source-verifier-returned transitions, exact block order,
  seven-limb roots/nullifiers, and full canonical outer-carrier byte caps.
- [x] (2026-08-23 16:10Z) Unified historical DA ownership across mining,
  canonical rebuild, commit, and reorg rows; V8 inline hashes cannot create or
  clear legacy ciphertext-index/archive/staged-sidecar state, while legacy
  transfers and coinbase retain their historical behavior.
- [x] (2026-08-23 16:10Z) Added source-verified common-ancestor detach/attach
  planning for noncanonical fork admission, atomic typed reorg application,
  scratch-from-genesis restart reconciliation, and tip-change eviction of
  existing or orphaned V8 pending actions.
- [x] (2026-08-23 18:10Z) Bound the exact source-present typed V8 plan to an
  application count produced only after the transaction-local sled apply,
  for both mined and active canonical-suffix commits. Missing, extra, or
  multiple applications reject, and a rejected manifest rolls the typed and
  shared rows back together.
- [x] (2026-08-23 18:10Z) Measured the source-encoded canonical carrier:
  128,297 inline bytes plus exactly 225 outer bytes equals 128,522 full
  `PendingAction` bytes. The route cap is 131,297; block-capacity accounting
  uses the full carrier and yields 522 before block overhead.
- [ ] Add queued parent/child proof tokens, planner-ordered multi-action
  template selection, short-lock group composition, state-advance/reorg race
  replanning, and dependent DA-prefix selection before lifting the one-action
  guard.
- [ ] Populate the sole source-owned production capability only after the
  retained maximum-shape proof bytes and reviewed release-manifest hashes are
  real. Until then action 10 remains unauthorized.

## Surprises & Discoveries

- Observation: V7/Zeta/action 9 exists as an inactive prospective identity.
  Consequence: the new identity starts at V8/Eta/action 10 and tests compare it
  directly against the V7 reservation.

- Observation: the generic native RPC public-argument ceiling is roughly two
  MiB, much larger than the new action ceiling.
  Consequence: action 10 uses the source-derived 128,297-byte inline ceiling
  before base64 decode, while every nested proof/leaf parser preserves the
  131,072-byte hard bound and the full canonical outer carrier has the separate
  131,297-byte V8 route cap.

- Observation: a historical self-contained native transaction wrapper adds
  6,080 bytes and belongs to a different relation.
  Consequence: V8 uses a compact new leaf containing its fixed header, 120
  words, seven binding limbs, exact active-output ciphertexts, and exact proof;
  it cannot accept that wrapper.

- Observation: the source relation module now owns the complete HGV8RP02
  executable program, nonzero 48-byte digest, and witness-independent verifier
  factory.
  Consequence: native verification invokes that factory directly; production
  still remains dormant because executable completeness is not retained
  artifact/release authority and the sole capability registry is empty.

- Observation: a proof statement containing ciphertext commitments is not a
  self-contained transaction unless exact ciphertext bytes are also present.
  Consequence: the self-contained HGV8 leaf carries each active slot's 2,147
  bytes inline and rehashes them before proof verification; no staged sidecar
  can satisfy V8.

- Observation: durable V8 stablecoin state must survive canonical reorg and
  startup replay in lockstep with the main chain.
  Consequence: mined extensions and reorgs apply a pre-verified typed plan in
  the same sled transaction as the canonical pointer, while startup re-verifies
  the exact canonical SMZ9 leaves from genesis into scratch state and compares
  every durable typed row.

- Observation: a peer may extend a stored sibling or deeper noncanonical
  branch after the durable V8 tip has advanced elsewhere.
  Consequence: peer admission verifies only the fork-depth detach/attach suffix
  from the durable common ancestor; it never treats the current typed tip as
  the candidate parent and never replays the canonical prefix for each peer
  block.

- Observation: V8 ciphertexts are self-contained leaf bytes, not legacy DA
  sidecars, even when a conventional hash collides with a staged legacy key.
  Consequence: a single explicit ownership predicate gates every historical
  index, archive, staged-removal, count, and rebuild path; V8 has zero such
  effects.

## Decision Log

- Decision: reserve circuit V8, suite Eta=7, family 1/action 10, backend 2,
  profile 6, and domain set 4.
  Reason: a fresh tuple prevents cross-format interpretation.
  Date: 2026-08-23.

- Decision: make `HGV8TX02` the self-contained V8 native leaf: an 88-byte
  header, 120 little-endian canonical Goldilocks words, seven canonical binding
  limbs, exact ciphertext bytes for active outputs in slot order, and the exact
  proof starting with `SMZ9`.
  Reason: the verifier needs a fixed statement and relation binding without a
  6,080-byte historical wrapper, receipt, commitment, cache, or sidecar.
  Date: 2026-08-23.

- Decision: derive ciphertext presence solely from output flags at statement
  words `[2,4)`, recompute conventional BLAKE2b-384 commitments into words
  `[32,44)`, and reduce the routed proof budget by 2,147 bytes per active slot.
  Reason: this makes the action replayable from its own bytes, gives a unique
  parse without per-slot lengths, and preserves the 131,072-byte hard cap.
  Date: 2026-08-23.

- Decision: use a 32-byte `SWP8LC02` header followed by the exact leaf, then a
  canonical four-byte SCALE length at the action boundary.
  Reason: this makes total framing 1,140 bytes and gives every lifecycle layer
  exact cap and length checks without reconstructing the proof.
  Date: 2026-08-23.

- Decision: require a nonzero 48-byte relation digest in construction and
  compare it together with the network during contextual decode, without
  freezing a placeholder constant.
  Reason: the digest must ultimately be owned by the compiled V8 relation
  module. A caller-selected value is syntax, never authorization.
  Date: 2026-08-23.

- Decision: use only
  `smallwood_poseidon2_production_capability() -> Option<Capability>` as
  activation authority and return `None` in this milestone.
  Reason: one object binds activation height, network, relation digest,
  route/profile/domain, and genesis root. A separate boolean or caller-selected
  context could drift from that evidence.
  Date: 2026-08-23.

## Outcomes & Retrospective

The compact transport, wallet/RPC syntax, verifier connector, and typed native
lifecycle are implemented without changing ciphertext or proof bytes. The same
HGV8TX02 leaf is carried through admission, mining, block import, atomic reorg,
restart reconciliation, and fresh-node replay. The production route is
intentionally not live: the sole capability registry remains empty until the
retained proof artifact and reviewed release evidence are pinned. No state
transition can bypass the exact-leaf verifier. Typed lifecycle regressions use
an exact deterministic verifier double, while the real source connector is
covered by fail-closed malformed-proof tests; an end-to-end retained valid
SMZ9 proof lifecycle remains a release-gate requirement, not completed
evidence.

## Context and Orientation

`protocol/versioning/src/lib.rs` owns circuit/suite identities and proof-backend
dispatch. `protocol/shielded-pool/src/family.rs` owns shielded action numbers.
`protocol/shielded-pool/src/poseidon2_production_transport.rs` owns the borrowed
exact codecs. `wallet/src/node_rpc.rs` constructs the JSON-RPC request.
`node/src/native/mod.rs` performs fixed-route checks, encoded-size checks,
base64 decode, and non-authoritative shape preflight.
`node/src/native/admission.rs` is the convergence gate used by RPC, relay,
persisted mempool, mining, block import, restart, sync, and reorg paths.
`node/src/native/poseidon2_v8_state.rs` owns verified seven-limb checkpoints and
requires a `Poseidon2V8ExactLeafVerifier` callback before atomic state changes.
`node/src/native/poseidon2_v8_verifier.rs` implements that capability with the
source-owned transaction verifier. `node/src/native/node_impl.rs` feeds exact
action-10 leaves through that connector in canonical order for mempool batches,
block extensions, reorg replacement suffixes, and startup replay. Production
authority remains absent even though the complete path is present.

## Plan of Work

The transport milestone adds constants without changing defaults or backend
dispatch. Borrowed parsers validate actual outer caps before reading headers,
then validate declared proof, leaf, envelope, and action lengths before slicing
or allocating. Encoders allocate only after the same checks.

Wallet construction builds the exact leaf and wrapper. Native RPC applies the
source-derived route cap before base64 decoding and allocation-free syntax
preflight before contextual decode. If and only if the sole capability exists
and is active at the actual next/block height, the node verifies the exact SMZ9
proof and typed roots before admitting or planning state. The registry remains
empty; no separate boolean or legacy fallback is authoritative.

Retained-proof release testing must replay the real frozen proof through the
already-connected atomic apply, restart, suffix replay, disconnect, reorg, and
fresh-node paths before the capability registry can be populated.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`:

1. Edit only the version/action/transport/native-RPC/wallet/doc surfaces named
   above, using `apply_patch` so unrelated dirty-checkout work is preserved.
2. Format only touched Rust files when unrelated concurrent changes prevent a
   workspace-wide formatting check.
3. Run `cargo test -p protocol-versioning v8_poseidon2 --lib`.
4. Run `cargo test -p protocol-shielded-pool poseidon2_production_transport --lib`.
5. Run the exact wallet, node route, inactive-admission, and kernel-manifest
   tests.
6. Inspect `git diff --check` and the scoped diff before handoff.

## Validation and Acceptance

Acceptance for the dormant seam requires all of the following:

* V8/Eta/action 10, `HGV8TX02`, `SWP8LC02`, and `SMZ9` are distinct from all
  historical and prospective identities; `*01`/SMZ8/profile 5 cannot enter the
  live parser.
* The leaf has exactly 120 canonical words, seven canonical binding limbs, and
  one exact 2,147-byte ciphertext for each active output; a presence/hash
  mismatch, non-Boolean flag, zero/wrong relation digest, wrong network, legacy
  proof magic, or trailing byte rejects before proof verification.
* Proof, leaf, and SCALE inline-argument hard caps are 131,072 bytes. The full
  V8 `PendingAction` route cap is 131,297 bytes because its max-shape outer
  encoding is exactly 225 bytes; every derived inner cap is checked before
  allocation.
* The source geometry projects exactly 122,863 proof bytes, 128,293 envelope
  bytes, 128,297 inline-argument bytes, and 128,522 full `PendingAction` bytes
  at two outputs. It remains a projection until retained artifact replay
  freezes the accepted maximum.
* Wallet/RPC decoding returns borrowed slices of the exact original leaf,
  ciphertext, and proof regions.
* Fixed native admission obtains one complete capability at the actual height,
  validates every binding field, and rejects while it is `None`.
* Exact seven-limb note roots, nullifiers, and commitments never enter legacy
  48-byte fields; any nonempty outer V8 nullifier metadata rejects.
* The temporary one-action guard rejects a second V8 action before authority or
  proof decode. The exact full-carrier byte screen is 522 actions; 523 is only
  a stricter security overcount. Neither is usable throughput until
  planner-ordered multi-action selection, proof-token composition, and
  state-advance/reorg races are wired and tested.
* Default version binding, backend/profile dispatch, kernel manifest, and all
  legacy decoders remain unchanged.

Production acceptance additionally requires retained maximum-shape proof
replay and the independent formal, security, conformance, artifact, and release
evidence that populates the sole source capability.

## Idempotence and Recovery

Tests use in-memory vectors or temporary sled trees. Re-running them is safe. If
a shared dirty file changes concurrently, re-read it and reapply only the narrow
hunk. Do not reset or discard unrelated work.

## Artifacts and Notes

Focused results recorded so far:

    cargo test -p protocol-versioning v8_poseidon2 --lib
    # passed

    cargo test -p protocol-shielded-pool poseidon2_production_transport --lib --locked
    # 9 passed

    cargo test -p wallet poseidon2_v8 --lib --locked -- --nocapture --test-threads=1
    # 8 passed

    cargo test -p wallet poseidon2_v8_request_preserves_exact_native_leaf_and_nested_proof_region --lib
    # 1 passed

    cargo test -p hegemon-node poseidon2_v8_rpc_projection_uses_exact_route_cap_and_canonical_parser --lib
    # 1 passed

    cargo test -p hegemon-node submit_action_rejects_inactive_route_or_excess_nullifiers_before_payload_parsing --lib
    # 1 passed

    cargo test -p hegemon-node poseidon2_v8_state::tests --lib --locked -- --nocapture --test-threads=1
    # 12 passed

    cargo test -p hegemon-node poseidon2_v8_verifier::tests --lib --locked -- --nocapture --test-threads=1
    # 4 passed

    cargo test -p hegemon-node poseidon2_v8_pending::tests --lib --locked -- --nocapture --test-threads=1
    # 8 passed

    cargo test -p hegemon-node poseidon2_v8_ --lib --locked -- --nocapture --test-threads=1
    # 28 passed

    cargo test -p hegemon-node reorg_pending_revalidation_drops_existing_and_orphaned_poseidon2_v8 --lib --locked -- --nocapture --test-threads=1
    # 1 passed

    cargo test -p protocol-kernel poseidon2_v8_transport_identity_has_no_manifest_authority --lib
    # 1 passed

    rustfmt --edition 2021 --check <touched Rust files>
    git diff --check -- <scoped files>
    # passed

The executable relation and exact projector now derive the 122,863-byte proof,
128,297-byte two-output inline-argument, and 128,522-byte full `PendingAction`
projections. These are not retained measurements; release authority still
requires an exact retained proof and readback hashes.

## Interfaces and Dependencies

The stable new interfaces are:

* `protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING`
* `protocol_versioning::smallwood_poseidon2_production_capability()`
* `protocol_shielded_pool::family::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE`
* `protocol_shielded_pool::poseidon2_production_transport::{
  Poseidon2ProductionExpectedContext,
  encode_poseidon2_production_smz9_native_leaf,
  decode_poseidon2_production_smz9_native_leaf_exact,
  encode_poseidon2_production_smz9_envelope,
  decode_poseidon2_production_smz9_envelope_exact,
  encode_poseidon2_production_smz9_inline_args,
  decode_poseidon2_production_smz9_inline_args_exact,
  ensure_poseidon2_production_smz9_stage_bytes
  }`
* `node::native::poseidon2_v8_state::{Poseidon2V8ExactLeafVerifier,
  Poseidon2V8StateStore}` (crate-private production seam)
* `node::native::poseidon2_v8_verifier::Poseidon2V8NativeVerifierConnector`
  (crate-private, source-digest-pinned connector)

`protocol-shielded-pool` gains a no-std `protocol-versioning` dependency so the
codec cannot drift from the version source of truth.
