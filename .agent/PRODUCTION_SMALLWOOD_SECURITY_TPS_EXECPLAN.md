# Make SmallWood V4 production-bound and throughput-competitive

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept current while work proceeds.
Maintain this file in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

Hegemon must accept only transaction proofs covered by its production theorem, must state the
remaining cryptographic assumptions precisely, and must carry the smallest proof that meets the
same post-quantum security target. After this work, a node rejects a theorem-out-of-scope proof
before expensive verification, the Rust and Lean acceptance surfaces agree on V4/Gamma, the
release profile has one canonical parameter record, and release evidence cannot report completion
when a required formal or package gate did not run.

Performance is an acceptance property, not a later cleanup. The current branch records a 118,006
byte wrapped proof, a 2.553 second proof, and a 10.781 millisecond verification as the last measured
V4/Gamma baseline. A replacement profile may be activated only if real canonical proofs are no
larger, verification is no slower, proving does not regress materially, and exact Rust and Lean
arithmetic retains the intended quantum-query work factor. Projected sizes are useful for pruning
candidates but never authorize consensus activation.


## Progress

- [x] (2026-08-17 20:28Z) Revalidated the audit findings against branch
  `codex/smallwood-pq128-experiment` at `038ec2d1275d` and confirmed a clean worktree.
- [x] (2026-08-17 20:28Z) Read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, the prior tight-profile
  plan, and the repository security-finding remediation workflow.
- [x] (2026-08-17 22:10Z) Added native-import regressions and enforced one height-aware policy at
  the shared verifier convergence: active V4/Gamma remains valid; unbounded V2/V3 and recursive
  artifacts reject before proof verification. The same active-binding predicate now covers local,
  relayed, startup, and reorg mempool admission, and template construction quarantines only stale
  inactive rows instead of dropping valid transactions. The cheap policy gate also runs on every
  real import path before nested tx-leaf decoding or preview work.
- [x] (2026-08-17 22:31Z) Closed persistent mempool/template proof poisoning. Local and peer
  transfers now verify before durable publication, semantic-hash single-flight and bounded
  deterministic-failure caching defeat arrival-time replay, verifier work runs outside state
  locks, and one peer/local/template lane is reserved under the global cap. Startup and template
  recovery quarantine only independently invalid rows and retry valid siblings once. External
  candidate and coinbase submissions reject before mempool budgeting.
- [x] (2026-08-17 22:31Z) Made native public-input encodings canonical at the raw boundary:
  negative-zero signed magnitudes reject, decoded Merkle roots must directly equal action anchors,
  and the Lean schema-v2/vector consumer propagates that equality through canonical tx-leaf,
  no-theft, DA, and observer packages. The full Lean library and focused Rust vectors pass.
- [x] (2026-08-17 20:40Z) Reproduced public balance-tag rewrapping, added the failing native-leaf
  regression, and made raw verification reconstruct the tag from the exact SmallWood statement.
  The exploit regression and legitimate round trip pass, with no proof-byte increase.
- [x] (2026-08-17 22:10Z) Rejected raw balance-slot, padding, and stablecoin asset identifiers that
  alias canonical Goldilocks representatives before field reduction. Rewrapped outer-proof
  regressions preserve the inner field statement yet now fail at native import; canonical native
  and stablecoin artifacts remain valid.
- [x] (2026-08-17 21:20Z) Made the V4-to-canonical semantic boundary honest: the theorem now
  preserves one raw witness and invokes `AcceptedTransactionRelation`, but only under the explicit
  `ProductionSmallWoodCanonicalSemanticRefinementAssumption`. The legacy mock-Merkle/`Nat` target
  prevents a genuine fieldwise production proof in this change.
- [x] (2026-08-17 21:20Z) Replaced global Poseidon preimage injectivity with a concrete executable
  six-limb Goldilocks Poseidon2 mirror, cross-language known-answer vectors, a separately named
  constraint-row-to-digest refinement premise, and pair-local no-collision evidence.
- [x] (2026-08-17 21:20Z) Blocked claims that treated caller-supplied verifier/extraction evidence
  as deployed end-to-end QROM authority. The formal-crypto build and 29-declaration axiom audit
  pass, and the indexed authority API has no deployed-end-to-end constructor.
- [ ] Repair the canonical release profile, package archive, active-goal evidence, and stale
  documentation so one `2/23/5` record is emitted and checked everywhere. Completed: canonical
  marker/checker/docs, exact constraint-table and verifier-profile digest ratchets, required
  workflow gates, fail-closed `continue-on-error` policy, and tag-only production-authorization
  lock. Remaining: refresh final governance digests and regenerate the HEAD-bound package after all
  tracked edits are integrated.
- [x] (2026-08-17 20:40Z) Reproduced the active baseline: 118,006 wrapped bytes, 117,986 inner
  bytes, 3.086 seconds proving, 11.581 milliseconds verification, and 124,022 native artifact
  bytes; all eleven native fixtures verify.
- [x] (2026-08-17 21:20Z) Measured six exact proof profiles without modifying active consensus
  constants. The smallest median was 113,490 bytes at `N=2^23,q=19`, but it was roughly nine times
  slower; faster points were larger and one failed even the conditional half-success diagnostic.
- [x] (2026-08-17 21:20Z) Retained `2/23/5`: no candidate was a strict byte/runtime Pareto win at
  unchanged conservative accounting. The active median was 117,878 bytes and about 3.070 seconds
  combined prove/verify. The balance-tag precheck adds no bytes and measured only 0.153% of native
  fixture verification.
- [ ] Bind deterministic adaptive DA to a fresh V2 genesis and PoW metadata. The implementation now
  derives the smallest fitting `1/4/16 KiB` tier, persists the exact root/parameters, exposes bounded
  chunk proofs, and rejects the unavailable sidecar transfer route. Remaining work is the final
  V2 rules-hash preimage/hash ratchet and full replay/restart/adversarial validation.
- [ ] Make maximum-size native blocks propagatable and mining work reusable. Identity-free schema-3
  canonical bodies now use bounded 1 MiB chunk transport, one-body-per-peer/four-body-global
  reassembly, exact owner/range cleanup, absolute and idle deadlines, fair bounded send/import
  queues, worker-thread decode/import, and exact stored-body comparison before known-locator sync
  credit. All twenty-three focused transport tests have passed, including the 64 MiB boundary,
  mutation/cross-mix, withholding/fairness, cache/work counters, bounded 128-block range
  materialization, a global-two pre-materialization loader with full retained-plus-transient byte
  reservation, mining-gate liveness, and exact request-owner cleanup. Peer action ingress first
  reads the fixed 56-byte V3 SCALE route prefix, so truncated/inactive/unknown floods reject before
  length-bearing decode; full preflight then rejects forged ids before proof single-flight or either
  fairness queue. The sole active inline route advances to the bounded proof queue, while no active
  V3 non-proof peer route can reach group commit. Additive fixed-width locator/request/chunk helpers
  already use the central BLAKE2b-384 body transcript, and a marker/tag prefilter pins interim tags
  4..7 plus fresh tags 8..11 before postcard allocation. Scalar sync/range bookkeeping now uses a
  compact tip accessor rather than deep-cloning maximum-size action bodies; its maximum-body
  clone/encode/hash counter regression is implemented and awaits the next integrated compile after
  an unrelated shared persistent-set refactor stabilizes. Remaining transport work is coordinated
  activation of those `BlockId48`/`BodyHash48` types and tags, regenerated vectors/rules ratchet,
  and full integrated gates. Template-cache/DA reuse
  remains tracked by its owning workstream.
- [x] (2026-08-18 05:22Z) Removed `received_ms` from active PendingActionV3 entirely. Exact
  timestamp-bearing V1 (32-byte id) and interim V2 (ActionId48) bytes are identify-and-reject at
  peer, block, and startup decode boundaries; no legacy value is upgraded. Local/block time stays
  out-of-band, and semantic reorg overlap remains defense in depth. Seven focused Rust tests and the
  Lean schema-2 wire-era model pass, including peer rewrite/no-mutation, active field absence,
  local-builder returned-versus-mined id, restart/block rejection, and reorg non-reemission.
- [ ] Remove proof and DA work from native state locks and make peer proof admission fair. Snapshot,
  compute, exact revalidation, and atomic commit are being applied to mined, announced, sync, replay,
  and reorg paths; a bounded per-peer queue/token policy is still required to prevent one sender from
  monopolizing the peer verifier lane with unique invalid proofs.
- [ ] (2026-08-18 01:48Z) Prototype the non-active V3 bare-inline SmallWood route. Completed:
  source-to-wire accounting proves that the 6,080-byte native lattice/receipt wrapper is entirely
  reconstructible except the nine-byte signed value balance and five authoritative raw-seven-lane
  Poseidon values. The additive full-SHA-512/first-48 profile, `SMW3` proof magic, transcript domain,
  exhaustive transaction and block-recursion dispatch, independent digest/XOF KAT, and
  cross-profile/digest/auth-node/noncanonical-tail rejection gates are implemented and targeted
  tests pass. The wire saves exactly `16 * (1 + authentication_nodes)` bytes; raw lanes plus signed
  balance add exactly 49 bytes, so removing the old wrapper saves a fixed net 6,031 bytes.
  Remaining after the source freeze: implement the typed raw56 bare envelope and independent
  reference, width-16 relation with the reviewed matrix orientation, action/capacity integration,
  and the single honest proof regeneration/benchmark after the profile freezes. The active selector
  must not change before external cryptographic review and all acceptance gates pass.
- [x] (2026-08-18 02:24Z) Rejected an unsound deadline activation after the architecture pivot from
  width-16 Poseidon2 to exact RFC 7693 BLAKE2b-384 note/nullifier/Merkle/state hashing. The repo has
  no BLAKE2b compression, Boolean/bit trace, or binary-field SmallWood gadget, so an exact proved
  binding cannot be supplied by substituting host hashes or field reductions. All unfinished
  width-16 edits were removed; transaction-core and transaction-circuit library checks are green.
  The additive `SMW3` SHA-512-first48 proof-commitment work remains non-active and reusable.
- [ ] Regenerate vectors/review artifacts, update architecture and methods documents, and pass the
  focused Rust, Lean, formal-core, formal-crypto, adversarial, package, and release checks.


## Surprises & Discoveries

- Observation: The prior profile plan reports excellent measured improvements, but its production
  conclusion depends on a root-first compiled-protocol reduction that is not composed into the
  supply theorem.
  Evidence: `SmallWoodProductionSupplyChain.lean` accepts `extractionSucceeds` per proof, while
  `SmallWoodCmsQrom.accepts_and_no_valid_witness_probability_le` has no production consumer.

- Observation: Native RPC admission and native block consensus use different version boundaries.
  Evidence: `node/src/native/node_impl.rs::validate_and_stage_action` calls
  `kernel_manifest().binding_allowed`, while `validate_block_actions_locked` and
  `verify_native_block_artifacts_locked` accept no version schedule and raw verification supports
  V2, V3, and V4.

- Observation: The release-profile checker passes a contradictory artifact.
  Evidence: active Rust and Lean constants are `beta=2`, `openings=23`, `eta=5`; the compiled marker
  and checker still require `7/20/33`.

- Observation: The checked-in native-backend package is not reproducible from branch HEAD.
  Evidence: `./scripts/verify_native_backend_review_package.sh` reports the new ExecPlan missing
  from the packaged source file set even before this successor plan is added.

- Observation: A valid SmallWood proof could be wrapped in a new native leaf carrying an arbitrary
  balance tag because the inner 78-field statement omitted that tag and raw verification did not
  reconstruct it.
  Evidence: the new regression rebuilt the outer public proof around a one-byte-mutated tag and the
  pre-fix verifier returned `NativeTxLeafMetadata`; after the fix it rejects with a balance-tag
  mismatch before inner verification.

- Observation: The refreshed proof benchmark is slower than the prior-plan host sample but has the
  same exact byte count.
  Evidence: 118,006 bytes is unchanged; this run measured 3.086 seconds proving and 11.581
  milliseconds verifying versus 2.553 seconds and 10.781 milliseconds in the prior plan. Candidate
  comparison must therefore use same-run medians, not cross-run wall-clock values.

- Observation: The LVCS planner projected Level-5 SHA-512 authentication paths with legacy 32-byte
  digests.
  Evidence: correcting it to 64 bytes increases the active planner report by exactly 14,752 bytes;
  the new regression equates the planner with the SHA-512 projection and checks the width delta.

- Observation: No exact candidate simultaneously reduced proof bytes and end-to-end runtime.
  Evidence: `N=2^23,q=19` measured a 113,490-byte median but a 26.9-second median round trip, while
  the active `N=2^20,q=23` measured 117,878 bytes and 3.070 seconds.

- Observation: The production Poseidon2 construction could be mirrored exactly in Lean without
  claiming collision resistance.
  Evidence: schema-v2 vectors check three 18-word preimages against the executable Lean sponge,
  Rust `note_commitment`, and the production constraint-trace sponge; row-to-digest refinement and
  pair-local no collision remain separate premises.

- Observation: A peer could persist an otherwise valid action after changing its binding to V2 or
  V3, causing every mining template to discard the entire selected set while retaining the poison.
  Evidence: common mempool admission previously omitted the manifest predicate; the new relay,
  startup, reorg, and quarantine regressions prove inactive rows reject or are removed while active
  rows remain mineable.

- Observation: Native tx-leaf conversion reduced serialized asset identifiers before validating
  their canonical integer encodings.
  Evidence: `FIELD_MODULUS + x` and raw `u64::MAX` produce the same inner field statement as their
  canonical asset/padding representatives, but newly rewrapped outer artifacts now reject before
  SmallWood verification.

- Observation: Required workflow checks could be marked `continue-on-error`, and release profile
  attestations accepted all-zero same-length digests.
  Evidence: mutation tests reproduced both fail-open conditions; the workflow policy now rejects
  job- or step-level soft failure and the profile checker pins both active digests.

- Observation: Honest governance cannot make the branch deployable merely by reducing the claim
  surface.
  Evidence: the tag workflow now requires a unique production-eligible claim, every authority
  Boolean true, and at least 128 concrete post-quantum bits. The live claim fails that gate by
  design while fixture and wiring tests pass.

- Observation: Structural mempool validation was insufficient to protect mining throughput.
  Evidence: a peer could persist an active-format but cryptographically invalid tx-leaf; every
  template then reverified it, cleared all selected actions, retained the poison in sled and RAM,
  and repeated the failure after restart. Verify-before-persist plus selective durable quarantine
  closes this remote TPS-to-zero path.

- Observation: The historical `received_ms` field made one action semantic admit multiple raw
  transaction hashes and could also defeat raw-hash reorg overlap.
  Evidence: changing only `received_ms` bypassed a raw-keyed negative/single-flight cache and could
  resurrect an orphaned outbound-bridge payload at a new height/nonce. Active V3 removes the field;
  timestamp-bearing V1/V2 bytes reject before hashing or persistence, local/block time stays
  out-of-band, and semantic reorg overlap remains defense in depth.

- Observation: Proof verification under the node read lock and undifferentiated concurrency caps
  convert a security check into a liveness hazard.
  Evidence: the first recovery pass held `state.read()` across the full verifier, and peer/local
  work could consume every global permit. Final admission snapshots then verifies without the
  lock, revalidates before publication, and reserves one peer, local, and template lane.

- Observation: The action anchor was tied to the decoded statement root only through two equal
  binding hashes.
  Evidence: direct `merkle_root == action.anchor` was absent from the native artifact-binding
  record and Lean model. Schema v2 adds the exact equality before fee admission, removing an
  unnecessary collision-resistance dependency without changing proof bytes.

- Observation: The former fixed 1 KiB DA encoder made valid templates fail far below the action-byte
  cap, while enlarging that constant without a version boundary would reinterpret stored blocks.
  Evidence: a full two-output ML-KEM transfer contributes 4,306 DA bytes, so the old tier fit only
  about 40 transfers. Deterministic `1/4/16 KiB` first-fit tiers raise the DA-only ceiling above the
  520-transfer inline action-byte ceiling, but require a fresh V2 genesis and rules hash.

- Observation: Sidecar-form transfers were not self-contained consensus objects.
  Evidence: sync transported action bytes but not the referenced ciphertext bodies; a fresh peer
  therefore failed with `missing canonical DA ciphertext`. V2 admits inline transfers only until a
  separately bounded and committed sidecar transport exists.

- Observation: The advertised 64 MiB native block limit exceeded the live 16 MiB wire frame and
  8 MiB sync target, so high-throughput blocks could be mined but not announced or synchronized.
  Evidence: canonical inline full-ML-KEM actions are 128,984 bytes each; 520 actions plus the 2,517
  byte coinbase fit the block budget but not one wire frame. V2 transports one canonical block body as bounded 1 MiB chunks
  committed by a chain/rules/schema-qualified locator.

- Observation: Rebuilding every mining template serialized cached proofs and repeated Reed-Solomon
  work often enough to throttle the PoW loop.
  Evidence: the current 520-transfer same-run sample costs 36.41 ms in proof-cache hits plus two
  independent 101.58 ms DA encodes, or about 239.6 ms before remaining preview work. The third
  redundant encode has been removed; a shared stale-while-refresh verified-template cache keeps
  sibling miners hashing, and safe-empty recovery templates never enter that cache.

- Observation: A single global try-acquired peer verifier permit is bounded but not fair.
  Evidence: unique malformed proof encodings evade semantic negative caching and can consume roughly
  64 cold verifications per second, continuously dropping honest relays. Per-peer rate/cooldown and
  a bounded fair queue are required in addition to global concurrency limits.

- Observation: The 6,080-byte `NativeTxLeafArtifact` suffix has no independent validity authority
  on the only active inline route.
  Evidence: parameters, specification, relation, shape, receipt, public inputs, public transaction,
  lattice commitment, and leaf digest are deterministic functions of fixed release constants, the
  canonical action fields, signed value balance, and exact SmallWood bytes. `verify_leaf` hashes the
  reconstructed packed public witness; its receipt-root consumer is inactive. Keeping the current
  20-byte `SmallwoodCandidateProof` wrapper leaves a nine-byte envelope and saves 6,071 bytes.

- Observation: Compact DECS proof size depends on transcript-selected authentication-node sharing,
  so one fixture length is not a capacity bound.
  Evidence: the checked fixture has 350 nodes and saves 5,616 bytes at a 48-byte observed digest;
  a fresh sample had 352 nodes and would save 5,648 bytes; the structural 460-node ceiling saves
  7,376 bytes. Capacity must use the ceiling, while a single non-retried honest KAT records its
  actual node count.


## Decision Log

- Decision: Fix consensus and semantic coverage before changing proof parameters.
  Rationale: Smaller proofs cannot compensate for accepting statements outside the theorem or for
  proving an equation record that does not imply the intended transaction relation.
  Date/Author: 2026-08-17, Codex.

- Decision: Enforce V4/Gamma at every current-height native import path and retain old decoding only
  behind an explicit historical checkpoint or offline replay policy.
  Rationale: Documentation saying historical-only is not a consensus predicate. A height-aware
  fail-closed check is the narrowest boundary that makes production acceptance match Lean.
  Date/Author: 2026-08-17, Codex.

- Decision: Treat SHA-512, Poseidon2, and compiled-machine refinement as explicit assumptions until
  their exact reductions or independently reviewed implementation evidence exists.
  Rationale: Production-grade assurance may state primitive assumptions, but it must not relabel a
  caller-supplied assumption or ideal-oracle theorem as deployed proof.
  Date/Author: 2026-08-17, Codex.

- Decision: Use real proof bytes and wall-clock measurements to choose a profile; use formula-based
  projections only to discard dominated candidates.
  Rationale: Proof encoding, Merkle openings, cache behavior, and verifier parallelism make projected
  size and speed insufficient for consensus activation.
  Date/Author: 2026-08-17, Codex.

- Decision: Do not promise a smaller active proof until a candidate beats the refreshed baseline
  while passing every security gate.
  Rationale: The request forbids trading security for throughput and also forbids a performance
  regression. Retaining the active profile is the correct result when no strict Pareto improvement
  exists.
  Date/Author: 2026-08-17, Codex.

- Decision: Retain the active `2/23/5` profile after exact candidate measurements.
  Rationale: every measured byte reduction multiplied prover time, while the faster smaller-domain
  points were larger or failed the conditional CMS diagnostic. Changing consensus constants would
  violate the no-security/no-performance-regression requirement.
  Date/Author: 2026-08-17, Codex.

- Decision: Fail closed on formal production authority instead of filling missing reductions with
  broad assumptions disguised as theorems.
  Rationale: the current ideal-QROM, compiled-verifier, canonical-semantic, and Poseidon trace
  surfaces are useful conditional evidence but do not compose into deployed end-to-end soundness.
  Date/Author: 2026-08-17, Codex.

- Decision: Authorize active V4/Gamma consensus operation while blocking production release
  authority.
  Rationale: the runtime manifest must accept the active proof tuple and reject historical tuples;
  separately, the tag-release gate must remain closed until the deployed QROM, hash-instantiation,
  compiled-verifier, canonical-semantic, and Poseidon refinement obligations are discharged.
  Date/Author: 2026-08-17, Codex.

- Decision: Pay the proof-verification cost once at admission and reuse the verified-artifact
  cache, rather than persist unverified peer work and make every template absorb the risk.
  Rationale: the 64 MiB mempool byte cap bounds resident SmallWood artifacts below the 4,096-entry
  verification cache, so healthy templates hit cache while invalid artifacts never become durable
  recurring work. Per-class verifier lanes preserve peer, local, and mining liveness.
  Date/Author: 2026-08-17, Codex.

- Decision: Activate adaptive native DA only under a fresh V2 genesis and an exact rules-hash
  preimage, with real DA metadata and root committed into PoW.
  Rationale: deterministic tier selection is consensus-safe only if old blocks cannot be silently
  reinterpreted and light clients can authenticate the encoding they sample.
  Date/Author: 2026-08-17, Codex.

- Decision: Keep V2 transfer ciphertexts inline and make large block bodies chunked rather than
  raising the global wire-frame limit.
  Rationale: inline actions are self-contained for fresh peers, while bounded body chunks preserve
  the 64 MiB block budget without granting an attacker one giant network allocation.
  Date/Author: 2026-08-17, Codex.

- Decision: Remove `PendingAction.received_ms` from active V3 and retain exact timestamp-bearing V1
  and interim V2 grammars only for actionable identify-and-reject errors.
  Rationale: arrival time is neither authorized transaction semantics nor a safe identity input;
  structural field absence removes relay/restart/reorg malleability and eight bytes per active
  action without runtime work, while block-header timestamps use the local clock independently.
  Date/Author: 2026-08-18, Codex.

- Decision: Share a fully verified work template across miners and perform expensive proof/DA work
  outside global state locks, then revalidate the exact tip/action snapshot before atomic commit.
  Rationale: the security checks remain independent, but neither proof verification nor Reed-Solomon
  encoding may serialize unrelated RPC, mempool, sync, or mining progress.
  Date/Author: 2026-08-17, Codex.

- Decision: Prototype V3 as a new full-SHA-512/first-48-observed-commitment arithmetization and
  wire, never as an in-place mutation of the active 64-byte Level-5 profile and never under the
  ambiguous name SHA-512/384.
  Rationale: SHA-512 still computes every raw digest and field-XOF block, while the new domain and
  wire make the 384-bit commitment boundary explicit. The six-word commitment gives a 128-bit
  quantum collision floor, so it needs a separate QROM/binding obligation and external review.
  Cross-profile decoding must fail before proof verification. The active selector remains on the
  existing profile until real proof and throughput gates pass.
  Date/Author: 2026-08-18, Codex.

- Decision: Replace the active native outer artifact with a bare inline envelope containing the
  canonical SmallWood wrapper, five canonical `PoseidonDigest56` values (two nullifiers, two
  commitments, and the anchor), plus `(value_balance_sign, value_balance_magnitude)`.
  Rationale: PendingAction and inline arguments already carry anchor, nullifiers, commitments,
  ciphertexts and their hashes/sizes, fee, balance-slot assets, stablecoin binding, binding hash,
  and version, but the width-16 statement cannot be reconstructed from one-way 48-byte wrappers.
  Reject noncanonical Goldilocks limbs, sign values above one, and negative zero; derive external
  identifiers from raw lanes (never the reverse), reconstruct every digest and fixed identity
  locally, and keep receipt-root and candidate aggregation disabled until they acquire a new schema.
  Date/Author: 2026-08-18, Codex.

- Decision: The width-16 external linear layer is exactly `M4 ⊗ P4` in row-major lane order.
  Apply `P4` inside each contiguous four-lane block first, then gather equal lanes across blocks,
  apply `M4`, and scatter; do not transpose the state, constants, rate, or capacity.
  Rationale: the opposite execution order (contiguous `M4`, then equal-lane `P4`) realizes the
  rejected `P4 ⊗ M4` orientation. A non-symmetric distinguishing KAT and independent formal
  oracle must prove the production order differs before this profile can activate. The central KAT
  fixes input `[0,1,…,15]`, required output
  `[202,209,216,223,262,269,276,283,322,329,336,343,222,229,236,243]`, and rejected opposite-order
  output `[208,223,238,213,236,251,266,241,264,279,294,269,292,307,322,297]`.
  Date/Author: 2026-08-18, Codex.

- Decision: Do not activate either width-16 Poseidon2 or host-only BLAKE2b-384 as the V3 proved
  transaction hash. The new target is exact central-domain RFC 7693 BLAKE2b-384 for note,
  nullifier, Merkle, balance-tag, and state commitments; Poseidon profiles are legacy/research
  reject-only.
  Rationale: `hegemon-hash384` now supplies the typed 48-byte outputs and domains, but SmallWood has
  no BLAKE2b bitwise compression relation. Host recomputation without an exact in-proof Boolean/bit
  trace would sever the note-opening/nullifier/Merkle witness binding. A new arithmetization/backend,
  formal refinement, proof-size ceiling, and prove/verify TPS measurements are activation gates.
  Date/Author: 2026-08-18, Codex.


## Outcomes & Retrospective

Runtime consensus, mempool-poisoning, balance-tag, and pre-reduction asset-alias vulnerabilities are
fixed. The active profile remains the strict measured Pareto choice, and misleading formal
authority is removed. Claim governance now records 100% formal-surface accounting but only 50%
mechanized-assumption closure; tag release is mechanically locked rather than treating that score
as production authority. Final digest refresh, integrated gate execution, and clean-HEAD review
package regeneration remain. The branch is intentionally not production-authorized while the typed
semantic, compiled-verifier, QROM-instantiation/composition, deployed-hash-loss, and Poseidon
row-refinement premises remain open; passing compilation alone is not completion.


## Context and Orientation

SmallWood is Hegemon's hash-based private transaction proof. A version binding is the pair of
circuit and cryptographic-suite identifiers carried by an action. V4/Gamma is the branch's active
pair. `node/src/native/node_impl.rs` handles RPC submission and block import orchestration;
`node/src/native/block_flow.rs` validates block actions and constructs proof artifacts;
`circuits/transaction/src/smallwood_frontend.rs` selects the version-specific relation; and
`circuits/transaction/src/smallwood_engine.rs` owns the active proof parameters and exact error
arithmetic.

The canonical semantic transaction proposition is
`formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean::AcceptedTransactionRelation`.
It includes balance validity, public-input shape, and input authorization. The new production map
in `SmallWoodProductionConstraintRefinement.lean` currently exposes lower-level equation families
but does not derive that canonical proposition.

The isolated `formal/crypto/HegemonCrypto` package contains ideal-oracle and extraction work. Its
production supply theorem currently takes successful extraction as evidence rather than deriving
it from the QROM probability theorem. QROM means the quantum random-oracle model. A production
claim must distinguish the ideal logical oracle, the deployed SHA-512 transcript, the concrete Rust
verifier, and the native consensus importer.

TPS means accepted transactions per second. This plan measures proof creation, proof verification,
native block import, and serialized bytes because each can independently limit TPS. Smaller proof
bytes improve network and storage throughput; verifier and prover timings establish that the byte
reduction did not move the bottleneck into computation.


## Plan of Work

First encode the vulnerable native paths as tests. A block containing a V2 or V3 transaction at an
active V4 height must fail before the raw proof verifier runs. A historical recursive candidate
artifact must fail unless an explicit checkpoint policy authorizes that exact height and binding.
The legitimate V4/Gamma inline block must continue to pass. Put the shared policy check at the
native block-import boundary using `NativeBlockMeta.height`, not only at local RPC submission.

Next make tx-leaf verification bind the balance tag. The full transaction wrapper already
recomputes the tag from balance slots. Reuse that implementation or move it into a shared helper so
raw native import and wrapper verification cannot diverge. Test both a mutated tag and the canonical
tag through the real native artifact boundary.

Then repair the Lean semantic boundary. Prove that the exact V4 row families refine the existing
`SmallWoodSemanticConstraintsSatisfied` proposition and invoke
`accepted_proof_and_semantic_constraints_imply_transaction_relation`. Do not create another renamed
relation that merely repeats the production map. Restate Poseidon binding as equality of concrete
deployed hash outputs followed by an explicit collision-resistance premise.

After the concrete boundaries close, make governance honest and fail closed. The production claim
must remain conditional on primitive hash security and compiled implementation refinement until
those premises are discharged. The release workflow must require formal-crypto isolation, the full
formal-crypto build, the Rust verifier/refinement regression, and reproducible package verification.
The active-goal checker must verify machine-readable gate evidence rather than nonempty command
strings.

Finally refresh performance measurements and explore candidates. Use the existing exact frontier
and ignored release benchmark. Candidate parameters stay local to the benchmark until they produce
a canonical accepted proof and satisfy the same exact Rust/Lean bound. Record serialized component
sizes so future work targets the dominant terms. Activate only a strict Pareto improvement.

The V3 prototype is additive. In `circuits/transaction/src/smallwood_engine.rs`, append a
non-active arithmetization and transcript backend whose field-XOF continues to consume complete
SHA-512 counter blocks, while commitment-producing calls compute full SHA-512 and expose exactly
the first 48 bytes under a new domain and proof magic. In
`circuits/transaction/src/smallwood_frontend.rs`, add exhaustive dispatch and verifier-profile
material without changing `default_smallwood_candidate_arithmetization`. Old and new proof magic
must reject under the other profile. Model the six-word observed commitment separately from the
existing eight-word `ActiveDigest`; do not silently redefine the active formal type.

In `circuits/superneo-hegemon/src/lib.rs`, define a canonical bare-inline envelope consisting of a
one-byte value-balance sign, an eight-byte little-endian magnitude, and the existing canonical
SmallWood candidate wrapper as the remaining bytes. Verification reconstructs flags, root, fee,
balance slots, stablecoin fields, public transaction, receipt, profile, proof/public-input digests,
and balance tag from exact action inputs before verifying the proof. Width-16 actions replace each
of the two nullifier, two commitment, and one anchor 48-byte wrappers with seven raw Goldilocks
lanes, so those five values add 40 bytes; together with signed balance, the exact new public-wire
delta is 49 bytes. External 48-byte identifiers are derived from the raw lanes, never used to
reconstruct them. The verifier does not serialize or verify the retired outer lattice
commitment/leaf. Mirror this reconstruction independently in `tools/native-backend-ref/src/lib.rs`.
Node owners integrate the projector at the PendingAction boundary; this plan does not edit their
shared native regions.


## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Capture the baseline and candidate frontier:

    cargo test -p transaction-circuit \
      compressed_level5_tight_uniform_matrix_frontier_is_materially_smaller \
      --release -- --nocapture

    cargo test -p transaction-circuit \
      compressed_level5_radix2_roundtrip_benchmark \
      --release -- --ignored --nocapture

Exercise the additive V3 profile and bare envelope with disk-bounded development artifacts:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
      cargo test -p transaction-circuit full_sha512_first48_commitment -- --nocapture
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
      cargo test -p superneo-hegemon bare_inline_v3 -- --nocapture
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
      cargo test -p native-backend-ref bare_inline_v3 -- --nocapture

Run focused native security regressions through their owning packages. Exact new test names will be
added here when implemented:

    cargo test -p hegemon-node --lib --no-default-features native_block -- --nocapture
    cargo test -p transaction-circuit --lib balance_tag -- --nocapture

Run formal and conformance gates:

    bash scripts/check_smallwood_production_constraint_table.sh
    bash scripts/check_lean_formal.sh
    bash scripts/check_formal_crypto.sh
    bash scripts/check_formal_crypto.sh --isolation-only
    bash scripts/check_formal_core.sh checker

Run release and adversarial gates:

    python3 -B scripts/test_check_release_crypto_profile.py
    ./scripts/verify_native_backend_review_package.sh
    HEGEMON_REDTEAM_MODE=ci PROPTEST_CASES=64 bash scripts/run_proving_redteam.sh


## Validation and Acceptance

Security acceptance requires the original inactive-version peer-block path and balance-tag mutation
to fail at the patched boundary, while canonical V4/Gamma blocks and tags pass. Lean must derive the
canonical semantic transaction relation. The claims ledger must expose every remaining assumption
and must not credit the ideal-QROM theorem as a deployed SHA-512 theorem.

Performance acceptance requires a refreshed baseline and a real candidate proof. The candidate's
wrapped bytes must be at most the baseline, verification time must be at most the baseline within a
documented noise tolerance, and proving time must not regress materially. Report multiple samples
and use the median. Native block import must also be no slower for the same transaction count.

The V3 prototype additionally requires exact old/new cross-profile rejection, first-48-byte
known-answer tests, no-grinding canonical nonces, producer/verifier/reference agreement, and
mutation rejection for sign, negative zero, raw width-16 lanes, proof bytes, profile, statement
fields, part ordering, and trailing bytes. The deterministic byte formula must report both the
single honest sample and the 460-node structural ceiling. End-to-end action p50, p99, and ceiling
must fit at least 521 transfers per block (target about 536), while median proof creation and
verification are no slower than the existing profile. No retry-to-size or transcript grinding is
permitted.

Release-readiness validation requires every non-authorization command in `Concrete Steps` to pass
from a clean checkout and the native-backend review package to reproduce byte-for-byte. The emitted
crypto-profile JSON must contain one parameter tuple, and SECURITY, DESIGN, METHODS, the Lean
transcript binding, and Rust must agree with it. The live SmallWood production-authorization gate
is expected to fail until all named authority flags are true and the governed claim carries at
least 128 concrete post-quantum security bits; a successful tag release before then is a failure of
this plan, not a passing result.


## Idempotence and Recovery

Tests, formal builds, and profile sweeps are safe to repeat. Generated vectors and the review
package must be regenerated only through their repository scripts, then checked for deterministic
output. Do not delete historical decoders; keep them unreachable from current consensus unless an
explicit checkpoint policy is present. If a candidate proof parameter fails, revert only the
candidate benchmark configuration and retain the production profile.


## Artifacts and Notes

The predecessor `.agent/TIGHT_SMALLWOOD_PQ128_PROFILE_EXECPLAN.md` records the last benchmark and
parameter search. Its measurements remain baseline evidence, but its conclusion that the complete
deployed QROM chain was established was invalidated by the 2026-08-17 source-to-theorem audit.

The most important expected regression transcript is a peer-import test that reaches native block
validation with an otherwise valid historical proof and returns an inactive-binding error before
proof verification. The most important performance transcript reports wrapped proof bytes, proof
time, verification time, and native artifact bytes for both baseline and candidate.


## Interfaces and Dependencies

Use the existing `kernel_manifest().binding_allowed(KernelVersionBinding, height)` policy or factor
its pure predicate into `protocol/versioning` so RPC and block import call the same implementation.
Do not add a second hand-written V4/Gamma comparison.

Use existing transaction-core balance helpers to compute the balance tag. Native tx-leaf import
must not introduce a competing serialization or hash transcript.

No new cryptographic dependency is authorized. Continue using the repository's SHA-512,
Goldilocks, Poseidon2, exact big-integer arithmetic, Serde, and Lean/mathlib facilities.

Revision note: Initial successor plan created on 2026-08-17 after the formal/security diff review
showed that the prior throughput profile was measured but not production-bound end to end.

Revision note: Expanded on 2026-08-18 with the additive V3 bare-inline/full-SHA-512-first48
commitment prototype after exact serializer accounting showed a sound route to recover the strict
width-16 proof growth without reducing query counts or reusing the inactive native lattice wrapper.
