# Ship the compact Poseidon2 SmallWood transaction proof

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while the work proceeds.

This plan follows `.agent/PLANS.md`. It is intentionally narrower than the
conventional-hash and replacement-backend experiments in this checkout. Those
experiments are not part of this cutover.

## Purpose / Big Picture

Hegemon needs one self-contained proof for its complete two-input,
two-output shielded transaction relation. The proof must use the existing
compact SmallWood engine and the existing Poseidon2 relation. The same bytes
must be accepted by the wallet, RPC, relay, mempool, miner, block verifier,
sync, restart, and reorg paths. A fresh node must validate those bytes without
a cache, receipt, sidecar, or trusted preprocessing artifact.

The user-visible success condition is a production-authorized proof whose
source-derived maximum is at most 122,863 proof bytes. Its canonical carriers
must remain at most 128,293 RPC-envelope bytes, 128,297 SCALE inline-argument
bytes, and 128,522 complete `PendingAction` bytes. The parser caps remain
131,068, 131,072, and 131,297 bytes respectively. Neither relation completeness
nor security may be traded for size.

The frozen current candidate keeps the compact SmallWood engine but uses the
686-row, 368-column, degree-eight V8 relation with 120 public field elements,
830 nonlinear identities, 19,899 through 20,473 statement-specialized linear
identities, and at most 21,303 identities in their soundness union. It uses
Goldilocks Poseidon2 with width 16, rate 8, capacity 8, seven-limb digests,
exponent 7, 8 full rounds, and 22 partial rounds. Its SMZ9/profile-6 proof uses
rho=5, six PIOP openings, beta=2, a `2^23` DECS domain, twenty DECS openings,
eta=5, twenty independent 64-byte tapes, a SHA-512 transcript, and no grinding.
The earlier 699-row width-12 relation and its SMZ1 and SMZ8 proof profiles are
historical engineering evidence only; no current plan statement may treat
their rows, tapes, sizes, identities, or security estimates as the active
candidate. A lifecycle audit found that the v4 686-row HGV8RP02 rehearsal
relation forced disabled-stablecoin `parent_height` and roots to zero. HGV8RP03
repairs that relation without changing its geometry: disabled mode binds the
actual parent height and requires both roots to equal the native current root,
while all remaining inactive stablecoin fields stay zero. The native source
capability now carries a distinct seven-limb `note_genesis_root` and requires
the canonical empty depth-32 Poseidon2 root for fresh activation. HGV8RP03 and
native projection also require canonical zero `value_balance`. Fresh proofs
and the positive-value retained lifecycle now pass. The selected native
value source is miner-local V8 coinbase action 11. The historical retained schema spends
two exact action-11 notes at canonical positions zero and one with two
separately randomized maximum-shape HGV8RP03 proofs. Those retained artifacts
predate the current source-security v3 implementation and no longer satisfy
the live-source inventory check; they remain byte-preservation regression
evidence only. The obsolete
three-proof zero-value seed plan is historical only. The retained proofs and
lifecycle are nonauthorizing while the capability is `None`; external security,
review, and hermetic release authority remain required.

## Progress

- [x] (2026-09-04 23:23Z) Final integrated checkpoint passes: the complete
  cryptography build and 87-declaration axiom audit, generator self-tests and
  exact drift checks for all 48 generated modules, CI policy negative tests,
  14 fresh governance tests, and the full 121-node/677-case blueprint validation.
  Mechanically refreshed 26 source digests; verified that every other policy
  and review field is unchanged apart from the executed test receipt. All
  121 independent reviews remain pending. Runtime code, the program binary,
  transaction proof format and 122,863-byte maximum are unchanged. No new
  transaction proof was generated. About 38.3 GiB remains free and no cache
  cleanup was performed without approval.

- [x] (2026-09-04 22:21Z) Resumed and completed the saved governance validation.
  The blueprint check passes 121 nodes and 677 falsification cases with all
  121 nodes still awaiting independent review. The existing progress checker
  passes its historical 10-of-20 assumption accounting. The final blueprint
  receipt now matches the second review-digest refresh. No review decision
  or production authorization changed. The September 3 source checkpoint
  passed 419 transaction tests with 21 explicit benchmarks ignored, the full
  cryptography Lean build, and the axiom audit of 77 credited declarations.
  The complete cached offline preflight passed at 22:37Z, including 246 checker
  tests and the 2,745-theorem Lean audit. Commit `51f90425` preserves this
  checkpoint. The current disk has 39 GiB free and cold builds remain stopped
  below the 40 GiB reserve.
- [x] (2026-09-04 22:37Z) Extended the ideal 12,201-field distribution through
  an explicit bijection into `Smz9HonestAlgebraicCoins`, including nonlinear
  and linear mask interleaving and PCS coordinate transposition. The targeted
  Lean build passed in 8.3 seconds; an independent source review agrees with
  all six Rust allocation families. The joint uniform law follows from the
  checked rejection distribution, not an assumed target distribution. Six
  declarations use only the permitted kernel axioms. Actual Rust execution,
  OS randomness, salt/tapes, and quantum distinguishing bounds remain open.
- [x] (2026-09-04 22:49Z) Proved the complete six-role algebraic output law
  induced by the rejection distribution, its specialization to the existing
  exact maps at fixed admissible challenges, and equality after changing fixed
  secret offsets. The direct Lean check and three axiom audits pass. This is
  joint distribution equality, not six marginal equalities. It neither
  conditions the actual adaptive transcript nor closes its privacy premise.
- [x] (2026-09-04 23:11Z) Proved the original complete structural canonicality
  predicate for the exact generated HGV8RP03 program, without premises.
  All 20,569 CSR attempts in 643 chunks, 8,836 expression nodes, 830 roots,
  and 1,105 descriptors pass. The source generator emits 48 modules with a
  serial import chain; the helper and final composition also pass. Three
  negative examples reject forward references, wrong local indices, and
  wrong family emission. The final theorem uses only permitted kernel axioms.
  Encoded-byte/hash equality, transaction semantics, Rust refinement, and
  cryptographic soundness do not follow from this structural theorem.

- [x] (2026-08-30 20:10Z, historical snapshot) Resumed the production campaign from the frozen
  HGV8RP03/SMZ9 artifacts. Re-read the repository instructions and current
  proof sections of `DESIGN.md`, `METHODS.md`, `README.md`, and this plan;
  reran the retained-artifact checker; confirmed both 122,735-byte and
  122,607-byte proofs then verified against that snapshot; confirmed the successor selection remains
  `unselected`; and measured 92 GiB free on the workspace volume.
- [x] (2026-08-30 20:10Z) Fixed a campaign disk reserve of 40 GiB. Every cold
  build, proof generation, or isolated target directory must check free space
  first and stop before starting when the reserve would be crossed. Temporary
  build directories must be named explicitly and removed only after their
  retained evidence is copied and verified; no broad cleanup or deletion of
  user-owned dirty-tree work is permitted.
- [x] (2026-08-30 20:12Z) Found a live proof-authority contradiction:
  `protocol/versioning` still selects V4/Gamma `SmallwoodCandidate` as the
  default, `protocol/kernel` advertises that binding with a 128-bit claim, and
  native admission allows the legacy inline action, while the security policy
  says fresh blocks authorize no proof profile. Started a dedicated cutover to
  one height-aware source authority; V8 remains disabled.
- [x] (2026-08-30 20:39Z) Added a source-bound exclusive deactivation height
  to the one fresh-proof capability tuple. The central authority, protocol
  manifest, consensus schedule, native admission, and V8 connector now use the
  same half-open activation window. The capability remains absent, and no
  4,096-block lifetime was invented. A future release must bind its exact
  finite window and per-block cap to the composed security budget.
- [x] (2026-08-30 22:20Z) Corrected the lifetime proof-count authority. The
  shared source capability owns the 512-action runtime ceiling and every
  mining, import, replay, reorganization, sync, wallet, and RPC sink derives
  its decision from that source. The 522 maximum-record quotient remains only
  a byte-only throughput diagnostic. The canonical count `M = 2,097,152` is
  arithmetic-only. It cannot supply the security parameter `T`, which must
  cover all observed or generated honest views, including rejected, orphaned,
  offline, side-fork, and repeated views.
- [x] (2026-09-03 15:57Z) Kernel-checked the exact ideal six-opening
  correction-aware sampling theorem in practical time. It proves six distinct
  nonpacking openings, the nonzero degree-six correction, all three PCS root
  families, denominator `(p-64)_6 - 414*p^5`, and abort
  `813^16/p^16`. `lake build
  HegemonCrypto.SmallWoodV8Smz9AdaptiveFiniteAccounting` passed all 2,594 jobs,
  and the focused Rust rejection/accounting vectors pass. This closes the
  previously reported Lean build problem without changing proof bytes.
- [ ] Bind that ideal theorem to the exact Rust/SHA-512 retry execution. The
  current theorem deliberately does not identify SHA-512-derived candidates
  with independent uniform tuples or prove canonical Rust execution
  refinement, and the repository has no generated correction-sampling vector
  artifact. Keep the deployed sampling receipt absent until this bridge is
  explicit; the runtime-randomness refinement work below may discharge the
  deterministic map while retaining entropy and quantum-oracle assumptions.
- [ ] (2026-08-30 22:44Z) Complete repeated-proof algebraic privacy and the
  active final-PIOP programming-input entropy theorem. The result must be
  binary: a proved loss below the 128-bit target under named assumptions, or a
  proved no-go/minimum entropy requirement. No receipt may assume its result.
  The final-PIOP input has a proved 512-bit fresh affine-mask fiber. The
  executable repair now records and exactly replays typed strict-leaf and
  internal-node inputs, consumes a typed `CryptoRng` draw ledger with exact
  rejection and consumption accounting,
  rejects programming conflicts, and proves the active inventory has no
  salt-only point or direct 256-bit route. Its 4,230-byte report is frozen at
  SHA-512 `0efabeb6d53f2557b12f21747fecbcc4694a3ed44a78075804908a6c6b0a028d4b84c7b85a2c33bf62f6248dd0b3ef123953c7f89d31ab386d30b0bfe34a73c8`.
  Algebraic simulator distance is zero under the recorded premises. Remaining
  constructor-free premises are RNG-to-uniform refinement, adaptive hidden
  subtree applicability, concrete SHA-512/global QROM composition, and a
  reviewed upper bound on all observed views `T`.
- [x] (2026-09-03 16:03Z) Factored the production randomness maps into one
  source-injectable Rust implementation and proved their deterministic ideal
  geometry. Production still calls `getrandom::fill`; accepted little-endian
  words are the unique canonical Goldilocks representatives, rejected words
  are never reduced modulo the field, fixed byte strings and DECS tapes are
  copied exactly, and any provider error aborts proof construction. The honest
  SMZ9 inventory is 12,201 accepted field words, one 32-byte salt, and
  8,388,608 64-byte leaf tapes. Six focused Rust tests, the prior engine RNG
  session tests, formatting, the standalone RuntimeRandomness build, and the
  2,634-job `HegemonCrypto` umbrella build pass. Proof bytes are unchanged.
  This establishes the deterministic map, not the external
  source premise: the composed privacy bound must retain an explicit
  quantum-computational distinguishing term for the complete OS/CSPRNG field,
  salt, and tape stream, including concurrent calls.
- [x] (2026-09-03 17:28Z) Proved the ideal probability law for the actual
  Goldilocks rejection map. An iid uniform sequence of raw 64-bit proposals,
  stopped at the first accepted proposal for each output, yields independent
  uniform field elements; the exact 12,201-output SMZ9 specialization is
  kernel checked. This does not identify `getrandom`, a caller-supplied RNG,
  concurrent production calls, or their full salt-and-tape schedule with that
  ideal law. Those runtime steps and a numerical quantum-computational
  advantage bound for the complete runtime coin source remain open.
- [ ] Build the actual joint whole-view refinement rather than composing
  marginal hiding lemmas. Lean now separates a minimal static verifier result
  `(statement bytes, bound-data bytes, proof bytes, verifier result)` from a
  full internal audit record containing the concrete verifier trace,
  programmed inputs and keys, prior queries, ordered oracle trace, replay
  record, histogram, and coin ledger. The constructors still receive those
  values from the caller; no theorem derives them from the Rust prover and
  verifier or places the honest and simulator observations in one probability
  experiment or exposes the interactive oracle queries available to a
  ROM/QROM adversary. The honest tape contains every `2^23` leaf tape while the
  simulator consumes opened tapes plus lazy-program inputs and outputs. The
  next theorem must consume the real typed coins into the actual proof bytes
  and oracle trace and construct one history-dependent joint transport or QROM
  hybrid. Do not award adaptive-zero-knowledge credit to a generic kernel with
  the desired coupling supplied as a premise.
- [x] (2026-09-03 17:28Z) Added typed syntactic audit-record constructors for
  honest and simulated SMZ9 fixtures. They parse the supplied proof bytes,
  authentication paths, and opened tapes and rebuild the checked program
  table, query receipt, histogram, and coin ledger. They do not enforce the
  production matrix dimensions or execute the Rust verifier. The full Rust verifier
  payload, statement and bound data, ordered SHA-512 events, programmed node
  values, and runtime counts are still checked inputs rather than values
  derived from a Rust execution. The audit record also carries its origin and
  mode-specific internals, so it is not itself an adversary-visible view. This
  is necessary plumbing, not a privacy or QROM theorem, and earns no
  production authority.
- [ ] (2026-08-30 22:44Z) Compose the exact PCS, PIOP, DECS, abort, Fiat-Shamir
  QROM, SHA-512, Poseidon2, and lifetime terms from the implemented SMZ9
  parameters. Separate kernel-checked arithmetic, explicit primitive
  assumptions, strongest known attacks, and unavailable external review.
  The report must keep honest-prover field-XOF, nonce, and fixed-DECS exhaustion
  in a completeness ledger rather than silently treating them as invalid-proof
  acceptance. The q=20 `2^142` pass / `2^143` fail result is the frontier of the
  certified conditional upper bound, not a known attack. The strongest
  quantified generic primitive attack currently recorded is the approximately
  `2^149.33` quantum collision work on the seven-limb Poseidon2 digest. A
  4,096-block calculation is a finite screen, not a cryptographic reset. The
  frozen 134,914-byte source report at SHA-512
  `a87a7c6b3ae4f15352c21b51487b82912578aad07dbbc02bf419556462dcb83b1f441132fb2048a928b6ffe173963b905181d80486010748fad7b767419932b8`
  now charges SHA exposure `Q + 2^24*T`, Poseidon2 exposure `Q + 128*T`,
  global-once SHA/product loss, and per-view external terms. Ten Rust accounting
  and mutation tests and an independent formula audit pass. It deliberately
  has no deployed floor while named primitive, logical-oracle, history,
  privacy, and review premises remain absent. The ideal finite-accounting Lean
  build now passes; the exact SMZ9 round-by-round knowledge instance below is
  the first semantic soundness gate.
- [x] (2026-09-03 16:08Z) Completed the strict SMZ9/CMS compatibility audit
  without adding a conditional wrapper or changing the proof wire. The four
  challenge stages and their domains are structurally usable, but the existing
  production theorem is a different protocol, not an SMZ9 instantiation. It
  hard-codes a `2^20` consecutive-subgroup domain, `699 x 64` extracted
  witness, `69 x 749 -> 138 x 375` unstacking, degree 397, five PIOP openings,
  twenty-three DECS openings, depth 20, and ten combination rows. SMZ9 uses the
  `2^23` disjoint coset, `686 x 64`, `70 x 736 -> 140 x 368`, degree 387, six
  PIOP openings, twenty DECS openings, depth 23, and twelve combination rows.
  A 296-line shape-only wrapper was discarded after review because it proved
  no security fact. The only retained correction fixes the old theorem's
  misleading twenty-opening comment to its actual value, twenty-three.
- [ ] Prove the first real SMZ9 round-by-round dependency: an exact analogue of
  `extracted_production_oracles_satisfied_iff_relation` for the HGV8RP03
  `2^23 x 145` oracle and `686 x 64` witness. Then prove the disjoint-coset DECS
  degree bound, affine batching after extraction, the root-event bound over
  `FullAdmissibleOpeningTuple` rather than plain `ValidTuple`, and the exact
  degree-387 twenty-of-`2^23` LVCS bound. Only after those facts exist should
  the prefix syntax be generalized and the Rust byte transition, failure
  selector, and CMS instability be bound. This is proof work on the current
  compact wire; no size expansion is indicated by the audit.
- [x] (2026-09-03 17:28Z) Materialized the exact 852,305-byte HGV8RP03 program
  as typed Lean components and independently bound the Rust source encoder to
  the checked artifact byte for byte. The generator checks the pinned SHA-512,
  parses every section to exhaustion, re-encodes canonically, and rejects hash
  mutation, truncation, trailing data, bad lengths, and bad references. Lean
  proved the exact inventory and fixed identity fields at that checkpoint.
  Every `RelationProgramComponents.Canonical` conjunct was subsequently
  proved on September 4, as recorded above.
- [x] (2026-09-03 17:28Z) Proved the exact `2^23` Goldilocks evaluation coset
  has order `2^23`, is injective, and is disjoint from all 388 interpolation
  coordinates. Added the deterministic `2^23 x 145` oracle-to-`686 x 64`
  candidate inverse and proved it recovers a degree-at-most-387 polynomial
  when full-domain pointwise agreement is supplied. Verifier acceptance still has to imply
  the required codeword proximity and relation satisfaction; the new theorem
  does not assume or claim that step.
- [x] (2026-08-30 22:30Z) Closed the universal HGV8RP03 compiler/verifier
  refinement: every admitted canonical statement must specialize to the exact
  pinned typed linear program and every nonlinear identity must be the exact
  interpreter of that program. Finite fixtures remain regression evidence,
  not the universal claim.
  Source-level program refinement is now complete: the private verifier CSR is
  constructible only from the pinned typed program, and all 830 nonlinear roots
  execute in all 64 packed lanes; the Lean source model proves universal packed
  acceptance. The connection from higher-level transaction semantics to that
  typed program is exact at the source-semantics boundary. Verified Rust
  extraction, an in-Lean RFC 7693 BLAKE2b-384 implementation, and compiled
  machine-code equivalence remain outside this theorem and must not be implied.
- [x] (2026-09-03 17:28Z) Added the exact inverse for the 120-word public
  statement layout. Every canonical typed statement round-trips through the
  decoder, and two canonical statements with identical encoded words are
  equal. This closes public-layout ambiguity only; accepted-program-to-typed-
  transaction semantics remains governed by the separate semantic refinement.
- [x] (2026-08-30 22:35Z) Screened proof-size changes after exposing the
  composed-bound margins. A change is eligible only
  if it preserves HGV8RP03 semantics, complete privacy, at least 128 composed
  quantum bits, canonical self-contained carriers, and the full lifecycle.
  Otherwise retain the current 122,863-byte source ceiling.
  Static result: keeping all other SMZ9 geometry fixed and reducing DECS
  openings from 20 to 19 projects 120,550 bytes, a 2,313-byte reduction, but
  leaves an approximately `2^-142.8` conditional advantage at the fixed
  `2^64` global-query screen before unresolved whole-view and primitive terms.
  That exponent is not an attack-work factor; the exact q=19 work-factor
  boundary has now been independently recomputed: `Q=2^134` remains below
  one-half success and `Q=2^135` does not. This is only a six-bit integer
  margin over the 128-bit target, versus the current q=20 boundary of
  `2^142` pass and `2^143` fail. The old union over the canonical
  `M = 2,097,152` count gives only a 121.7-bit arithmetic diagnostic, but `M`
  is not the observed-view bound `T`. Therefore q=19 cannot be selected unless
  the indexed global-query reduction and a reviewed `T` are actually closed.
  Keeping q=20 and
  changing only to a fresh 56-byte commitment wire is the lower-risk shrink:
  it projects 119,879 bytes while preserving the q=20 interactive work
  boundary. The
  48-byte SHA-512 commitment-node idea is rejected:
  charging all `2*N-1` Merkle programs across that same diagnostic `M` leaves
  only about 113.4 adaptive-programming bits and cannot establish a lifetime
  bound. The first clean word-aligned candidate
  is a fresh 56-byte/448-bit wire. At q=20 it projects 119,879 bytes, saving
  2,984 bytes, and its isolated Merkle-programming screen is about 145.4 bits.
  It remains unselected until that term is added to every other exact loss and
  its parser/transcript refinement is complete. The q20/56 `SMC8` route is an
  inactive candidate measuring 119,767 inner bytes and 125,201 two-output
  action bytes, with 119,879/125,313 source ceilings. It preserves active
  semantics and q20 arithmetic while saving 2,984 source-ceiling bytes, but has
  no retained artifact, transport, manifest, selection, or capability change.
- [x] (2026-08-30 21:10Z) Implemented the q=19, 56-byte/448-bit result as the
  additive inactive `SMC7` proof wire and profile 7. It preserves HGV8RP03 and
  the outer V8 statement exactly, appends fresh transcript and wire identities,
  leaves every historical decoder unchanged, and is exposed only through an
  explicitly named candidate API. The exact source ceiling is 117,702 inner
  bytes, 5,161 below SMZ9. A real `N=2^23` prove, canonical encode/decode,
  verifier reconstruction, replay, mutation rejection, and SMZ9-route rejection
  test passed and measured 117,478 inner bytes. Under the unchanged outer V8
  byte layout that sample corresponds to 122,876 native-leaf bytes, 122,908
  envelope bytes, and 122,912 SCALE action bytes at two active outputs; the
  source-ceiling action is 123,136 bytes. Codec caps, complete-SHA-512/56-byte
  observation, profile separation, and SMZ8/SMZ9 regression tests pass.
  Production capability remains `None`, successor selection remains
  unselected, and no manifest, admission, transport, or retained artifact was
  changed. The complete composed theorem remains the selection gate.
- [x] (2026-08-30 21:40Z) Implemented the lower-risk q=20, 56-byte/448-bit
  sibling as the additive inactive `SMC8` proof wire and profile 8. It keeps
  HGV8RP03, the outer V8 statement, and the complete SMZ9
  rho5/open6/beta2/N=2^23/q20/eta5 sampling tuple unchanged while appending a
  fresh complete-SHA-512 transcript domain, 56-byte observed commitment wire,
  canonical parser cap, compact-authentication encoder, and source-reconstructed
  verifier. The exact source ceiling is 119,879 inner bytes, 2,984 below SMZ9.
  One real `N=2^23` prove/replay/mutation measurement passed in 802.51 seconds
  of test time (805.73 seconds wall) and produced 119,767 canonical inner
  bytes. Under the unchanged V8 carrier formula that sample is 120,871 native
  leaf bytes, 120,903 envelope bytes, and 120,907 SCALE action bytes with zero
  outputs; at two active outputs it is 125,165 / 125,197 / 125,201 bytes. The
  source-ceiling two-output action is 125,313 bytes. Mutation, SMC7, and active
  SMZ9 rejection passed, as did profile-width, codec-cap, compact-path,
  projection, historical codec, transaction-library, block-recursion, and node
  library no-run checks. No proof artifact or hash was retained. Production capability remains
  `None`, successor selection remains unselected, and no admission, manifest,
  transport, or retained-artifact path changed. This is measurement evidence,
  not a security claim; the complete composed theorem remains the selection
  gate.
- [x] (2026-08-30 22:42Z) Added a dedicated release-checker parser for the raw
  executable privacy report. It exact-binds its canonical path, 4,230 bytes,
  full SHA-512, relation/profile identity, zero salt-only points, salt-only-key
  exclusion, direct-route exclusion, and fail-closed production posture. Eight
  field/path/byte/hash mutation controls and the complete Python fixture suite
  pass; the generic evidence schema was not weakened.
- [x] (2026-08-30 22:44Z) Updated the canonical whitepaper, design, methods,
  and machine-readable campaign tracker to the frozen reports and explicit `T`
  claim boundary. Removed the stale 522/523 soundness union and old report sizes
  from current-state claims; dated snapshots retained below are marked
  historical. Production remains false, capability `None`, selection
  `unselected`.
- [x] (2026-08-30) Replaced the source-security report with schema v3. Its lazy
  weighted upper bound derives the joint source constraints `leaf <= 20` and
  `leaf + internal <= 372`, hence charges caps of 21 leaf-plus-final programs
  at 512 bits and 352 internal programs at 1024 bits. This is the
  loss-maximizing envelope corner, not a claim that one compact path attains
  both caps simultaneously. The checker reconstructs the exact upper-bound
  ratio and the strict-128 observed-view maximum
  `18,889,465,930,379,069,227,007`, and rejects the successor. This source
  change deliberately does not repin the historical retained artifacts: their
  old source inventory is obsolete for current-source release evidence, while
  their proof and wire bytes remain unchanged. Production remains false.
- [x] (2026-08-30 23:28Z) Added the fail-closed refresh interfaces without
  changing the fixed pointer, retained proof artifacts, or production
  authority. `construct_smallwood_poseidon2_v8_retained_manifest.py` now
  requires an explicit versioned artifact root and new candidate-manifest
  path, derives the exact schema-v2 29-file inventory, verifies byte and
  SHA-512 identities, executable bits, identical generator binaries, both
  proofs and their common payloads, distinct randomness, chain report, live
  source root, and empty authority, then publishes only after full verification
  with an atomic no-overwrite link. Its `verify` subcommand reuses the frozen
  checker and both retained generators; the fixed checker keeps all old pins.
  The wallet vector generator now requires `--output-root NEW_DIRECTORY`,
  forbids the canonical five-file root and descendants, requires an existing
  real parent, caps every read, stages and rereads the exact five files, and
  atomically publishes without replacement. Fifteen Python constructor tests
  and eight focused wallet Rust tests, including mutation, overwrite, path, and
  simultaneous-publisher controls, pass. Nine node selector tests also prove
  that the lifecycle defaults to the exact fixed pointer and accepts only an
  explicit, canonical, nonsymlinked
  `retained-artifact-manifest.candidate*.json` while capability is `None`.
  Unsupported no-replace platforms fail closed. Capability remains `None`.
- [ ] (2026-08-30 23:28Z) Refresh retained proof evidence only after the
  formal and wallet source inventory freezes. The final checker correctly
  rejected the older artifact pointer because today's source inventory differs
  from its frozen root; the old proof bytes remain regression evidence, not
  current-source release evidence. Check at least 41 GiB free before each
  phase and stop before crossing the 40 GiB reserve. Generate wallet vectors
  only into a new explicit candidate directory. Then perform two isolated
  byte-identical retained builds, two fresh proofs, four cross-verifications,
  exact chain verification, construct and verify a new candidate manifest,
  and run the ignored full lifecycle test through its explicit candidate-only
  selector. Promotion of that candidate to the fixed pointer comes only after
  those checks as a separate review action and must never be implicit.
- [x] (2026-08-22) Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`,
  `.agent/PLANS.md`, the compact-profile ExecPlan, and the active SmallWood
  implementation before editing.
- [x] (2026-08-22) Confirmed that
  `cargo check -p transaction-circuit --lib --locked` succeeds in the dirty
  shared checkout.
- [x] (2026-08-22, superseded) Confirmed that the then-active candidate selected
  the compact SMZ1 arithmetization and the 699-row Poseidon2 relation, and that
  its parameter accounting cleared the configured 260-bit interactive floor.
- [x] (2026-08-22, historical) Confirmed the retained compact proof parses exactly as SMZ1
  and is 119,606 bytes; it is not yet current-source-bound or accompanied by a
  canonical max-shape transaction artifact.
- [x] (2026-08-22) Found that the historical 124,982-byte structural estimate
  omitted SMZ1's 1,472 opened leaf-tape bytes. The corrected conservative
  ceiling is 126,454 bytes, leaving 4,618 bytes below the 128-KiB hard cap.
- [x] (2026-08-22, historical) Ran the focused baseline gates: all six SMZ1 domain/tape
  tests passed, both compact-profile admission tests passed, and the exhaustive
  Rust/Lean generated relation comparison passed every production row in
  156.13 seconds.
- [x] (2026-08-22) Measured the two legal seven-limb Poseidon2 layouts in the
  actual SmallWood geometry. Width 12/rate 5/capacity 7 needs 325 permutations,
  six packed groups, 1,135 rows, and at least 135,270 bytes, so it is
  disqualified. Width 16/rate 8/capacity 8/digest 7 needs 166 permutations,
  three groups, 829 rows, and has an exact 116,910--127,470-byte path-dependent
  range before the stablecoin extension, so it is the selected base.
- [x] (2026-08-22) Recomputed the proof profile after the complete stablecoin
  row audit. The old `N=2^20,q=23` profile no longer clears the interactive
  floor. The selected fresh profile is `N=2^23,q=19`, which at the conservative
  924-row screen has 266.865073 bits in the implemented interactive
  calculator and a 128,378-byte worst-case wrapped-proof projection.
- [x] (2026-08-22) Rejected reuse of the 6,080-byte historical native leaf
  wrapper. V8 carries a compact fixed statement and the one SmallWood proof
  directly; no lattice leaf proof, receipt, cache, sidecar, or historical
  wrapper is part of its validity path.
- [x] (2026-08-22, superseded) Added the then-selected append-only V8 engine identities: arithmetization
  discriminant 16, conventional SHA-512 V8 transcript backend, `SMZ8` inner
  magic, exact `2^23`/19-query profile, nineteen independent 64-byte opened
  leaf tapes, and a 131,072-byte pre-allocation inner parser cap. These are
  historical SMZ8 details, not the SMZ9 tape count or complete-carrier cap. Focused
  profile/domain, codec/mutation/cap, and wrapper/discriminant tests pass; the
  production authority predicate remains false.
- [x] (2026-08-22, historical) Replaced the noncanonical 19-times-depth SMZ8 proof-size screen
  with an exact compact-Merkle split dynamic program. It proves a maximum of
  355 accepted authentication nodes at `N=2^23,q=19`, matches exhaustive
  enumeration of every leaf subset through depth four, and feeds the public
  SMZ8 compiler-geometry projector. The Lean-generated canonical/wrong-magic/
  wrong-count/wrong-depth/trailing-byte SMZ8 vectors all agree with the Rust
  parser. Final relation bytes remain deliberately unpinned until the
  executable adapter reports its completed geometry and auxiliary surface.
- [x] (2026-08-22) Replaced the unbounded SHA-512-to-Goldilocks rejection loop
  with an explicit request/candidate cap and a typed terminal failure latch in
  the prover, verifier, and verifier-trace paths. The exact ideal-uniform abort
  term is executable, and forced all-rejection input returns
  `ConstraintViolation` without unwinding.
- [x] (2026-08-22, historical) Added an executable geometry-generic strict whole-view ROM
  simulator/refinement harness. It emits the exact canonical SMZ1/SMZ8 proof
  grammar without a raw witness, samples every serialized PIOP/PCS/DECS field,
  carries tapes and compact authentication paths, records lazy Merkle and final
  PIOP oracle programming, and replays the concrete verifier trace. Canonical
  wire, witness-free, mutation, alternate-geometry, and zero-length compact
  path regressions pass. This is executable evidence, not a QROM theorem or a
  production authorization.
- [x] (2026-08-22) Bound the exact width-16 Poseidon2 tuple to parameter set
  `hegemon-p2w16-v1-114a4e7eb2684d29`. The derivation checker, eight mutation
  tests, four transaction-core known-answer tests, hardened p3 reference, and
  stock-p3 negative control all pass. The candidate manifest remains
  fail-closed pending independent exact-tuple review and composed proof-system
  evidence.
- [x] (2026-08-22, historical) Closed the SMZ8 parser/wire implementation slice: exact
  profile/domain, canonical codec, pre-allocation cap, exhaustive compact-path
  maximum, and Lean-generated parser vectors pass. The exact accepted maximum
  is 355 authentication nodes, not 437 independent full-path nodes.
- [x] (2026-08-22) Added the exact V8 native transport and durable seven-limb
  stablecoin state lifecycle. Wallet construction and every named transport
  stage exact-decode the same buffer without changing its proof region; typed
  apply, restart, disconnect, atomic reorg, and fresh-node sync tests pass with
  a scripted verifier. These are codec and state-machine component results, not
  a positive live wallet-to-fresh-node SMZ9 lifecycle receipt. Actions 10 and
  11 remain rejected because the source capability registry is empty.
- [x] (2026-08-22) Added the exact 120-word public statement, fixed 721-word
  private witness, all sixteen activity masks, all three authorization modes,
  shared spend-key rule, and exact 2,147-byte inline ciphertext per active
  output. The transport recomputes the conventional BLAKE2b-384 ciphertext
  commitment before proof verification, so the transaction is self-contained
  rather than depending on a sidecar.
- [x] (2026-08-22) Corrected the fresh transaction Merkle schedule to the
  source-owned `poseidon2_width16_compress14` API: one permutation hashes
  `left[0..7] || right[0..7] || domain || suite`. This reduces the live V8
  schedule from 189 to 125 calls, the padded schedule from three groups to two,
  the hash trace from 546 to 364 rows, and the planned full relation from 868
  to 686 rows. At the historical `q=19`, `C=368`, `A=355`, zero-auxiliary SMZ8
  checkpoint, the exact wire formula projected a 114,078-byte raw proof and a
  119,512-byte maximum two-output action.
- [x] (2026-08-23) Compiled the fresh seven-limb 686-row rehearsal relation as a
  dedicated width-16, seven-limb, 120-word `SmallwoodConstraintAdapter`. The
  executable layout is 686 rows with 830 retained nonlinear identities and
  19,898--20,472 statement-specialized linear identities. These counts belong
  to the superseded HGV8RP02 rehearsal relation. Exhaustive tests
  compile and replay all sixteen SingleKey masks, every legal Approval and
  FinalThreshold mask, disabled/mint/burn stablecoin transitions, and reject
  invalid mode shapes plus private/hash/public/inactive mutations.
- [x] (2026-08-23, historical) Bound every executable sparse-row emission to one canonical
  85-family relation program. Every retained shape attempts exactly 20,567
  source emissions; missing, reordered, misclassified, or always-dropped
  families fail closed. The seven-section `HGV8RP01` program is exactly 89,310
  bytes and its SHA-512 digest is
  `5895f13048cc2d44dd599e8ee779b0be2c7996c0a5888d71ac280956e7c8c7bfa78c2ce5e753a18ca88eaca7edbb71d1f7adfce6999a983eeb68e8efe6b8779f`;
  the first 48 bytes are the source-owned V8 relation identity. The descriptor
  parser, known-answer, cursor, and mutation tests pass 4/4, and the executable
  relation suite passes 8/8.
- [x] (2026-08-23) Removed the public Merkle-root words `[47,54)` from the
  action-intent preimage to break the FinalThreshold fixed-point cycle
  `intent -> value-lock key -> note -> root -> intent`. The root remains a
  separate public transcript input and therefore remains proof- and
  consensus-bound. This changes no relation rows, proof fields, or bytes.
- [x] (2026-08-23) Generated, retained, read back, and fresh-process verified
  the first maximum-shape q=19/SMZ8 proof. It is 113,630 proof bytes and
  119,064 complete two-output action bytes. Its proof SHA-512 is
  `b14926ffb401f02b461927bc85a211e54789c90058fb2e49bf6a3db8a02ba7bd4991bf295370d70ec8391663eafba1ef56c3ade6c0391676d3af55e27f85c18a`.
  This artifact is retained as historical parameter evidence, not production
  evidence, because the exact multi-proof composition below disqualified the
  q=19 profile.
- [x] (2026-08-23) Generated two separate maximum-shape q=20/SMZ9 proofs with
  the deterministic `retained-proof` profile, atomically published each
  artifact under artifact-report schema v4, and verified each from a separate
  fresh process using the other clean, byte-identical macOS build. The primary
  proof is 122,351 bytes with
  SHA-512
  `b6d71a9f3b5373ea911b879bbbdd1eaacfcb0358c413290b36398e0a1a716e2fe79b54abf1e663e8ef17f0d46dde1b78862d70757e560df756d5d3d7b48039be`;
  its canonical full `PendingAction` is 128,010 bytes. The independent proof
  is 122,735 bytes with SHA-512
  `bd3fc1c8ae6dc956da061e94bfdd920d9dc474ac1fa64a64f4ed484ab8f8ecd266a6679639d823db47c6702f1f510a7f149bc87e6dda228a326d37c9c5edeb07`;
  its canonical full `PendingAction` is 128,394 bytes. Both pass the exact
  verifier, all relation/carrier/outer-field mutations, canonical transport
  readback, and the six-map honest-proof rank audit. They are retained as
  nonauthorizing rehearsal measurements only: v4 does not bind the complete
  source inventory, their provenance records the dirty-worktree base commit,
  and their exact macOS generator binary cannot equal the Ubuntu release/tag
  verifier. A v5 reseal can retain them as source-bound rehearsal evidence, but
  production requires fresh HGV8RP03 proofs, v5 source inventories, and the
  real lifecycle receipt. Do not add either v4 artifact
  to the production source registry.
- [x] (2026-08-23) Audited the v4 proofs against the real native lifecycle and
  found a relation blocker: disabled-stablecoin canonicalization forces
  `parent_height` and the stablecoin roots to zero. At the time of this audit,
  the native source capability separately lacked the canonical empty depth-32
  Poseidon2 note-tree root, and
  the measured two-input/two-output proofs use a synthetic nonempty anchor.
  Both v4 proofs are therefore height-zero-only rehearsals and cannot become
  final production artifacts through a v5 provenance reseal.
- [x] (2026-08-23) Recomputed the exact source-derived QROM/CMS composition for
  the live R=686/C=368/d=8 relation. q=19/open=5 has a 273-bit interactive
  floor and 141-bit ideal single-proof CMS floor at Q=2^64, but only a 120-bit
  floor after the consensus maximum 561 proofs per block over 4,096 blocks.
  q=20 alone saturates on the five-opening PIOP term and is still only 121
  bits. The smallest conservative repair is six PIOP openings and twenty DECS
  openings: about 288.797 interactive bits, 157.212 ideal CMS bits, and
  136.184 bits after the complete 128,522-byte pending-action size limits each
  block to 522 proofs and that exact 4,096-block interval, before separately
  bounded external terms. The former 523-action calculation is retained only
  as a stricter 136.181-bit overcount.
- [x] (2026-08-23) Derived the exact serializer ceiling for the repaired
  profile: P=696, U=736, LVCS rows=140, columns=368, opened combinations=12,
  and at most 372 compact authentication nodes. The fresh proof projects to
  122,863 bytes and the maximum two-output public-argument action to 128,297
  bytes, leaving 2,775 bytes under the 131,072-byte route cap. Its complete
  canonical `PendingAction` is 128,522 bytes after 225 bytes of outer record
  overhead. The q=19 SMZ8 identity
  will not be reinterpreted: production moves additively to SMZ9/profile 6 and
  preserves SMZ8/profile 5 as an unshipped historical candidate.
- [x] (2026-08-23, historical) Replaced the descriptor-only relation identity
  with the executable `HGV8RP02` grammar. Its nine sections encode all 830
  nonlinear roots through 8,271 typed expression nodes and all 20,567 sparse
  linear attempts through 543 typed public-expression nodes, including exact
  ordered witness indices, coefficient roots, target roots, family/order, and
  normalization policy. Adapter construction evaluates that same sparse-row
  program for the concrete 120-word statement and exact-compares offsets,
  indices, coefficients, targets, family IDs, and the family receipt before
  use. The canonical transcript is 851,812 bytes; its SHA-512 is
  `42ed32d55ca007856445070a90874e5fa653e9e41949443a79ae0e3ff71af06c678c66907ab8ed849ddcc7ddba797cf552515f3002c52fbf3a514af0f13654d6`,
  and its first 48 bytes name the SMZ9/profile-6 relation. This source-pinned
  program metadata does not enter the proof or action bytes; a separately
  retained program artifact and independent hash receipt remain release work.
- [x] (2026-08-23) Repaired disabled stablecoin and balance semantics under
  `HGV8RP03`, semantic relation v2, without changing the 686-by-368 geometry or
  SMZ9/profile-6 wire. Disabled mode binds the actual parent height and requires
  `before_root == after_root == context.current_root`; its remaining economic,
  configuration, counter, authorization, action-intent, and witness fields are
  zero. The relation also enforces zero public `value_balance` sign and
  magnitude. Its canonical program is 852,305 bytes, has 830 nonlinear
  identities, 19,899--20,473 specialized linear identities, a 21,303-identity
  soundness union, 86 families, 20,569 source-emission attempts, and 565 CSR
  expressions. Its SHA-512 is
  `8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3`;
  the first 48 bytes are the relation id. Focused constructor/validator and
  digest KATs pass 1/1 each, and the exhaustive typed/executable suite passes
  9/9 across all sixteen masks, authorization modes, stablecoin modes, and the
  repaired mutation cases. Native projection and release authority remain
  separate fail-closed gates.
- [x] (2026-08-23) Added the historical source-derived HGV8RP02 SMZ9 security
  diagnostic and fail-closed deployed gate. It reconstructs HGV8RP02, exact-compares the
  R686/C368/degree-8 relation and counts 830/20,472/21,302, derives the
  profile-6 proof projection, and evaluates exact rational PCS, IOP,
  Fiat-Shamir, SHA-512, Poseidon2, tape, sampler, whole-view, and history
  terms. Focused tests pass 4/4: exact 288/157/136 floors, equal external
  151-bit terms rejected at 127 composed bits, equal 152-bit terms reaching a
  conditional 128-bit floor, malformed budget rejection, and production
  authority still false. The successor release gate now requires this report
  as a separately hashed evidence file; no such retained passing report or
  receipt is claimed yet. This HGV8RP02 report is historical and cannot supply
  HGV8RP03 counts or identity.
- [x] (2026-08-23, historical; superseded 2026-08-30) Regenerated the then-current
  deterministic source-security diagnostic for HGV8RP03. That checked-in JSON
  was 31,956 bytes and had SHA-512
  `4308fb56c68be761de1f2db8411e26fb5f0addeaa279f52a10e245b5a23b727112fecc9401969305a00c2858ca4c2e8a179a033affaf7b46ea606c0857350fee`,
  binds the current program SHA-512 and relation digest, and uses maximum
  linear/union counts 20,473/21,303. It still reports
  `production_eligible=false`; this is current-source diagnostic evidence, not
  a passing release report.
- [x] (2026-08-23) Reconciled the actual SMZ9 nonce predicate with the security
  report. Rust rejects distinct/outside openings when the degree-six linear
  correction numerator is zero or a PCS-unstack block loses rank, while the
  existing Lean sampling theorem does not model those predicates. The exact
  Goldilocks root inventory adds 68 forbidden values outside the packing
  domain. The report now uses the conservative conditioned denominator
  `(p-64)_6 - 414*p^5`, charges `813^16/p^16` for exhaustion of all
  sixteen nonce trials, and keeps a sampling-refinement
  receipt false. The integer 288/157/136 floors and the 152-bit external-term
  threshold remain unchanged. Exact maximum union counts at 128 bits are
  621,730,874 before external terms, 4,166,198 with four 152-bit terms, and
  2,090,101 with four 151-bit terms; exact theorem equivalence is not claimed.
- [x] (2026-08-23, historical; superseded 2026-08-30) Added the then-current
  isolated Lean correction-aware finite accounting
  module. It proves conditional one-proof floor 157, four-152-term one-proof
  floor 149, exact 2,138,112-proof floor 136, four-152-term history floor 128,
  four-151-term history floor 127, the stricter 2,142,208-proof overcount, all
  three exact maximum counts,
  and rejection at each maximum plus one. The concrete sampler, SHA-512,
  Poseidon2, exact relation/transcript, adaptive whole-view, protocol-lifetime
  budget, and independent-review bridge premises remain constructor-free.
  Focused and full `lake build HegemonCrypto` pass with 2,544 jobs.
- [x] (2026-08-23) Replaced the invalid PCS-unstack rank shortcut. The old
  audit copied an unrelated six-dimensional witness-interpolation rank even
  though an admissible point such as `549755813888` has `r^64 = 1` and makes
  the actual map singular. Rust now constructs the exact forty dense 6-by-6
  blocks from the prover row updates, requires every block to have rank six,
  and records aggregate rank 240. Prover nonce selection and verifier
  canonicalization share the same nonvanishing `r^64 - 1`, `r^35 - 1`, and
  `r^63 - 1` predicate. Lean models the same row-difference formula and proves
  the resulting 240-coordinate additive equivalence under that predicate.
  Focused counterexample, honest-map, report, and Lean checks pass; none of
  this supplies the still-absent adaptive QROM or production receipts.
- [x] (2026-08-23, historical; superseded 2026-08-30) Added the then-current
  fail-closed consensus-visible conditional lifetime
  accounting without changing the proof relation, parameters, or retained
  proof bytes. Native V8 state persists an eight-byte checked count of
  canonical-branch accepted transaction proofs, commits before/after values in
  every block record, compares and writes the counter atomically with the V8
  tip and note state, restores the ancestor value on reorganization, and
  rejects overflow, more than 522 proofs in one accounting step, or a value
  above 621,730,874. Reference vectors pin `522 * 4096 = 2,138,112` and the
  exact conditional ceiling. Restart, sync replay, reorganization, and fresh
  replay must reconstruct the same count and rows. The release checker requires
  a distinct source and executable receipt with these values and with
  `accounting_window_is_cryptographic_reset=false`,
  `counts_all_verifier_invocations=false`, and
  `deployed_security_claimed=false`; its production command inventory remains
  empty. The mechanism therefore does not discharge the missing external
  reductions or global rejected/noncanonical-verification accounting.
- [x] (2026-08-23, historical; superseded 2026-08-30) Retained the then-current
  deterministic source-security diagnostic at
  `docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json`: 31,956
  bytes, SHA-512
  `4308fb56c68be761de1f2db8411e26fb5f0addeaa279f52a10e245b5a23b727112fecc9401969305a00c2858ca4c2e8a179a033affaf7b46ea606c0857350fee`.
  It records no deployed floor, marks only the exact source-internal SMZ9
  transcript refinement present, and keeps every external/adaptive receipt
  absent. The profile manifest
  pins it only as non-authorizing diagnostic evidence, keeps the required
  passing-report receipt null, and the release checker rejects that diagnostic
  digest if used as the passing identity.
- [x] (2026-08-23) Corrected the SMZ9 algebraic hiding inventory and connected
  it to retained-artifact verification. Lean now counts all 2,800 LVCS random
  tail coordinates jointly against 240 random-combination tails plus 2,560
  subset evaluations, rather than counting only the 240 selected tails. The
  accepted-proof Rust audit checks the exact six square coordinate spaces and
  ranks; the artifact report records them, fresh verification recomputes them,
  and the release checker pins `4116/4116/r6`, `240/240/40 blocks/r6/total240`,
  `2445/2445/r6`, `660/660/r6`, `2800/2800/r20+r12`, and
  `1940/1940/r20`. Focused Rust tests, the 2,544-job Lean build, and the
  58-declaration formal-crypto axiom audit pass. This does not inhabit the
  executable Rust-to-Lean honest-map receipt or the adaptive repeated-proof
  SHA-512/QROM whole-view premise.
- [x] (2026-08-23, historical; superseded 2026-08-30) Retained the then-current
  deterministic executable whole-view refinement report at
  `docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json`:
  2,963 bytes, SHA-512
  `df0b7a7e09b46b79bac097c08bcf947fe012a8514d3b6b8c638a0387323919120710f6f834e6b5563ee2f5da533104f985a6059929a716645c0a19051d1e8907`.
  It records exact executable ROM replay and honest-map dimensions without
  claiming the absent adaptive repeated-proof or global SHA-512 QROM receipts.
- [x] (2026-08-23) Put the source-internal accepted-proof refinement on the
  ordinary V8 verifier path. Every success now requires exact canonical SMZ9
  decode/re-encode, zero auxiliary witness material, production-engine
  acceptance of the same HGV8RP03 statement and transcript preamble, and the
  six exact full-rank hiding-map audits. Lean proves the canonical byte-binding
  implication for every byte string. Retained reports bind the receipt to the
  proof length, proof SHA-512, and exact Lean decoder name, and the release
  checker rejects substitutions. Focused refinement tests pass 4/4, security
  tests pass 4/4, the exhaustive relation suite passes 9/9, and the no-proof
  artifact projection reports source inventory SHA-512
  `ad75a8447cf56424492932c7ce80ad006cb6ba7c91d147f1e384f2f2148008aecbfcf32a45ef70de1fb1c70c80c9d30404502db42c790825bd0fa07f70a1c496`.
  The deeper proof that every Rust honest-prover map equals its Lean additive
  equivalence remains absent, as do adaptive QROM, concrete-hash, global
  lifetime, and independent-review receipts; production remains disabled.
- [x] (2026-08-23) Closed the typed V8 atomic-count seam for mined extension
  and active canonical-suffix reorg commits. One transaction-local helper
  applies the optional immutable typed plan, derives actual count zero or one
  only after the raw apply succeeds, and immediately compares it to the source
  count before any shared sled transaction can commit. The dedicated source
  gate pins the Cargo-selected library/operator sources, ordinary module chain,
  exact `NativeNode`/eleven-tree shape, rooted raw apply and evaluator, and the
  direct helper grammar and an ordered macro-free runtime AST digest.
  Formal-core passes 243 tests; focused rollback,
  cardinality, `v8_plan`, and reopen/readback regressions pass.
- [x] (2026-08-23) Hardened lifecycle evidence so artifact parser-stage labels
  and scripted state tests cannot be promoted into production authority. A
  qualifying report must bind the retained primary proof digest at every
  stage, name the production verifier, reject cache/receipt/sidecar validity
  shortcuts, and pin the reviewed release workflow. The source checker reruns
  every source-owned lifecycle command without a shell and exact-compares its
  observed output SHA-512 with both the positive check and stage receipt.
  Removal, stale SMZ8/parser substitution, proof-digest drift, self-asserted
  output hashes, checker-execution removal, and validity-shortcut mutations
  reject. The real command inventory remains empty, so this closes a policy
  bypass without claiming a positive lifecycle run.
- [x] (2026-08-23) Extended executable release-evidence policy beyond lifecycle
  labels. Every local certificate, report, receipt, and release manifest now
  needs a source-owned exact command and canonical parsed receipt binding the
  checkout source inventory, both proof hashes, deployed-security report,
  release workflow, and complete native capability tuple. A separate exact
  capability manifest covers relation/version/network/activation/stablecoin-
  root/note-root identity, and a required receipt covers zero `value_balance`
  enforcement in the relation, wallet projection, and native projection.
  External reviews remain uninhabited without a reviewed signature trust root.
  Both executable command inventories and the source registry remain empty.
- [x] (2026-08-23) Closed the release-evidence substitution and race gaps. The
  checker freezes every source evidence id to one canonical path, requires a
  clean stable Git revision, inventories the default-feature transaction/node/
  wallet Cargo closure plus active excluded path packages and formal roots, and
  recomputes that closure before and after every evidence command. Inactive
  optional standalone SHAKE remains explicitly outside the feature graph while
  the active vendored Reed-Solomon source is included. Linux copies freshly
  built verifier bytes into an anonymous memfd, applies the complete write/grow/
  shrink/seal set, reads back the sealed bytes, and executes only through the
  inherited `/proc/self/fd` descriptor. Non-Linux hosts reject before spawning
  an external verifier and cannot authorize a release. The Linux path rechecks
  seals, bytes, ownership, mode, and descriptor identities after execution.
  An earlier source-owned hermetic-root gate remains empty and rejects before
  `git`, `cargo`, or any evidence command. Its frozen future schema requires a
  root-owned read-only Linux mount containing the checkout, Git metadata,
  dependency cache, release manifest, Python bootstrap/runtime, and every
  exact-hash command under an empty-`PATH` environment. No trusted launcher or
  mount attestation is provisioned yet; fake-PATH `git`/`cargo` fixtures must
  remain unable to execute, and injected runners remain test-only.
  Lifecycle receipts bind exact heights,
  capability roots, relation, proof length, and state transitions. Adaptive and
  global security receipts require future-only positive deployed theorem names
  and full release bindings, while independent review requires exact ML-DSA-87
  key, canonical review, and detached-signature bytes under a source trust root.
  The theorem command inventories, review trust roots, lifecycle commands, and
  production registry all remain empty.
- [x] (2026-08-23) Replaced the temporary one-V8-action staging guard with a
  source-owned 512-action ceiling while preserving the independent exact
  64 MiB aggregate over full canonical `PendingAction` encodings and the
  131,297-byte route cap. The pending planner orders any number of verified
  disabled/no-write actions at one root by canonical action id before the one
  permitted mint or burn edge, and cycle-checks only advancing edges. Block
  verification exact-checks that committed order. Typed state now requires
  every action's note anchor to occur in the immutable canonical parent
  history, rejecting same-block output spending. Focused planner, state,
  mempool, source-count, template-slot, atomic group, and reorg tests pass.
  The production capability remains `None` and no proof was generated.
- [x] (2026-08-30) Executed the positive-value in-process lifecycle: mined two
  exact action-11 V8 coinbase notes at canonical positions zero and one, spent
  them with both independently randomized maximum-shape proofs, and carried
  the applicable proof bytes unchanged through the actual wallet request
  builder, native RPC admission, peer route authority, relayed mempool,
  mining, block persistence, restart, sibling reorganization, re-extension,
  and fresh announced-block import. The feature-gated ignored test passes with
  both retained proofs and exact state readback. It does not open HTTP or peer
  sockets and does not exercise locator/action-body-chunk synchronization;
  those remain external transport gates. Capability remains `None`.
- [x] (2026-08-23) Repaired disabled stablecoin under `HGV8RP03` so it binds
  the actual consensus parent height and passes through the current stablecoin
  root with `before_root == after_root == context.current_root`, while keeping
  the remaining inactive fields zero. The 686-by-368 geometry and every
  carrier projection remain unchanged.
- [x] (2026-08-23) Added the distinct seven-limb note-tree genesis root to the
  native source capability and activation context, independently of the
  120-word proof statement. Fresh activation requires the canonical empty
  depth-32 Poseidon2 root. Production capability remains `None`.
- [x] (2026-08-23) Enforced canonical zero public `value_balance` sign and
  magnitude inside HGV8RP03 and in native V8 projection.
- [x] (2026-08-23) Replaced the two incorrect honest-map rank shortcuts with
  the exact matrices used by the SMZ9 prover and verifier. The PCS audit now
  checks all forty independent six-by-six unstack blocks and rejects the
  concrete singular tuple that the old unrelated matrix accepted. The witness
  audit now checks the actual `poly_restore` interpolation differences rather
  than bare high monomials. Focused Rust regressions pass and the proof wire and
  122,863-byte ceiling are unchanged.
- [x] (2026-08-23) Proved the exact six honest algebraic maps in Lean: witness
  interpolation, PCS unstack, nonlinear PIOP, zero-sum linear PIOP, the joint
  triangular LVCS map, and DECS evaluation/high coefficients. The old empty
  map-receipt types and the theorem declaring the aggregate refinement
  unavailable were replaced by formula-bound receipts and a concrete aggregate
  constructor. Both exact modules build and `check_formal_crypto.sh` audits 64
  declarations successfully. External SHA-512/QROM and independent-review
  premises remain explicit and unavailable.
- [x] (2026-08-23) Froze release-source-inventory v2 over all four shipped root
  packages and both complete formal source trees. Independent Rust and Python
  reconstruction agree byte for byte on 830 files, 22,338,428 bytes, 26 Cargo
  package manifests, and root SHA-512
  `84002dce5de2e03a63ba275d8a7da08ba58804449ad531073b13731aa3ffe25cdedfa116c70ce484b4e062a73b0fb6e6608f53ccf46eb76cb29fe945786b5d8e`.
- [x] (2026-08-23) Built the retained generator twice in isolated target
  directories. The two 2,395,936-byte binaries are byte-identical with
  SHA-512
  `cea3d56a2bc94a778480be697ee29eb9c74a8121e66355f3e08bb624357f7110db1e46110480a9a971f2e2a01dab811af8560ec9e4bf69eeb7d170585279ddec`,
  and both independently reconstruct the frozen v2 source root.
- [x] (2026-08-23) Generated two fresh, independently randomized maximum-shape
  HGV8RP03 SMZ9 proofs from the two clean binaries. The primary proof is
  122,735 bytes with SHA-512
  `e3413d889b23d818ad144b2ca6dcacbeaf1a7269fb7c8dc8f0f4ab2eaf3e9983ff7f82a2978583f201d1d6a0ad0f69960070ad884747e64c8b76a40daa8bc522`
  and a 128,394-byte pending action. The independent proof is 122,607 bytes
  with SHA-512
  `a99deca70a5150f82df021e2275a11ddf97f24daf6ee1fa3791daceac9e3cd39e78f03c521b62dfdd94b3a3a8a7450ee87d7e0eba33287118c9f8799023e69db`
  and a 128,266-byte pending action. Each binary verifies both artifacts; both
  binaries pass the two-proof chain check; proof hashes, salts, and transcript
  roots are distinct; statement, two positive coinbase notes, Merkle paths,
  relation program, and source inventory agree. The manifest-v2 and live
  retained lifecycle gates pass, and capability remains `None`.
- [x] (2026-08-23) Regenerated two independently randomized maximum-shape HGV8RP03 proofs
  and all v5 source-inventory artifacts; reran
  size, mutation, restart, sync, reorg, refinement, release, and real lifecycle
  gates without crossing any carrier cap.
- [x] (2026-08-23) Finished and bound the selected action-11 V8 coinbase source to the complete
  capability, mining-only route, note-root transition, supply, height, network,
  and release identity. RPC, peer relay, and mempool ingress remain fail closed,
  and the route remains dormant while the capability is absent.
- [ ] Close the complete-zero-knowledge and composed post-quantum soundness
  obligations for the exact shipped transcript and wire, without changing the
  relation geometry.
- [x] (2026-08-23) Replaced the single research-only production veto with fail-closed,
  independently tested capability gates whose inputs are retained artifacts.
- [x] (2026-08-23) Bound each canonical envelope in the two-spend positive fixture through every
  production lifecycle path and reject every legacy/candidate action or wire
  identity at the active route.
- [x] (2026-08-23) Generated and retained two current-source-bound proofs under artifact-report
  schema v5: independently randomized maximum-shape two-input/two-output spends
  of the same exact positive action-11 coinbase notes at positions zero and
  one. Bind the complete source inventory, coinbase openings, proof, canonical
  carriers, and native `PendingAction`; verify chain construction, size,
  readback, restart, sync, reorg, and mutation gates.
- [x] (2026-08-23) Ran the internal formal, refinement, retained-artifact,
  lifecycle, source-inventory, and fail-closed release gates; updated the
  canonical design and methods documents; and recorded the retained manifest
  digests. Production authorization correctly rejects because the source
  registry and external authority roots remain empty.
- [x] (2026-08-23) Hardened the schema-v2 retained checker after adversarial
  review. It now exact-compares all 830 source entries twice, binds the live
  generator source and frozen base revision, requires the complete canonical
  two-coinbase-note fixture and provenance transition, and admits exactly the
  intended 29 payload paths, freezes the complete manifest SHA-512, runs both
  pinned binaries against both proofs, and recomputes both chain reports. The
  live check and all twenty-three focused positive and mutation regressions pass,
  including hardlink and inode-alias rejection.
- [ ] Obtain reviewed concrete SHA-512/QROM, exact Poseidon2-tuple, adaptive
  repeated-proof zero-knowledge, and protocol-lifetime composition authority
  in the hermetic Linux release environment; then add the source-registry entry
  and activate the capability in one reviewed consensus release.
- [x] (2026-09-03 15:51Z) Resumed the exact HGV8RP03/SMZ9 production campaign
  from clean commit `d13597da5f60fb9e71f1c496192b406e243a8e08` with 58 GiB free
  and the 40 GiB reserve intact. Freeze the proof wire and 122,863-byte source
  ceiling while four disjoint local obligations run: correction-aware opening
  sampling, runtime-randomness-to-uniform-coins refinement, adaptive whole-view
  quantum zero knowledge, and round-by-round quantum soundness/knowledge. The
  first binary decision is whether the exact four-challenge SMZ9 transcript
  satisfies the tighter SmallWood/CMS quantum Fiat--Shamir hypotheses with at
  least 128 composed bits. Do not spend time on release activation or another
  backend until that theorem either closes or produces a precise no-go.
- [x] (2026-09-03 15:57Z) Re-established the narrow executable baseline from
  the resumed source: transaction library check; security accounting 10/10;
  whole-view ZK refinement 4/4; exhaustive relation and mutation coverage 9/9;
  shielded-pool maximum carrier mutation test 1/1; native exact artifact codec
  test 1/1; and the frozen source-security report exact check all pass.
  The report still says `production_eligible=false`, the capability remains
  absent, and the 122,863-byte source ceiling is unchanged. Disk remained at
  55 GiB free after the builds, above the 40 GiB hard reserve.
- [x] (2026-09-03 16:03Z) Re-audited security-neutral byte headroom before
  changing the wire. The maximum proof is 97,608 bytes of field words, 23,872
  bytes of SHA-512 roots/authentication nodes, 1,280 bytes of opened leaf
  tapes, 32 bytes of salt, 4 bytes each of nonce and magic, and only 63 bytes
  of shape metadata. A new fixed-profile codec could save at most 67
  worst-case bytes (0.055%) without changing cryptographic parameters, but it
  would require a new canonical wire, carriers, manifests, mutations, and
  lifecycle reseal. Proof-specific Merkle deduplication does not reduce the
  worst case. Keep SMZ9 unchanged; the larger 2,313--5,161-byte candidates all
  change a soundness/hash term and remain ineligible until composition closes.
- [x] (2026-09-03 16:34Z) Repaired five latent, independently reproducible
  test contradictions without weakening production code: a compact Merkle
  zero-length path was both accepted and rejected by different tests; frozen
  Level-5 vectors were mislabeled as the current SMZ1 profile in three stale
  assertions; and one HX512 fixture omitted the public bindings required by
  its verifier. All five focused reruns pass. The complete transaction library
  regression then passed 419/419 tests with 21 explicit release/benchmark
  tests ignored. Disk now remains at 53 GiB free, thirteen GiB above reserve.
- [x] (2026-09-03 16:52Z) Revalidated the fail-closed retained-artifact refresh
  seam before freezing any new proof bytes. The wallet's isolated no-overwrite
  publisher passed 8/8 tests, the candidate-manifest constructor passed 15/15,
  and the node's test-only candidate selector passed 9/9. Both the fixed
  retained pointer and the existing candidate correctly reject against the
  changed live source inventory, so neither was silently reused or promoted.
  The cold node build reduced free space to 43 GiB; all heavy work stopped and
  the exact disposable workspace `target/` directory was removed, restoring
  53 GiB free without touching source or retained artifacts. Fresh proof
  generation remains deferred until the active formal source freezes.

## Surprises & Discoveries

- Observation (2026-09-04): at resumption the saved September 3 checkpoint was at commit
  `de5611c2528b8ff44d3068fb9cdefc5b3f044362` with 18 modified and 11 new files.
  Free disk space fell from 53 to 39 GiB while the task was paused. Heavy
  builds stay stopped below the 40 GiB reserve; existing validator binaries
  and source inspection can continue. The second review-digest refresh was
  saved, so only the blueprint governance receipt needed its matching policy
  digest before final validation. That receipt remains an executed test
  record, and every independent review status and production gate is unchanged.

- Observation (2026-09-04): one monolithic HGV8RP03 canonicality check reached
  about 10 GiB RSS after 129 seconds and was stopped without receiving proof
  credit. The generic cursor and three rejection examples pass in 5.67 seconds.
  Subsequent certificates must use bounded serial checks and preserve the
  materialized list-of-chunks representation to avoid a large final reduction.
  This is a Lean checking resource issue, not a transaction proof size change.

- Observation (2026-09-04): after the CSR checks passed, descriptor shard 04
  reached 5.82 GiB RSS while reducing long UTF-8 label round trips and was
  stopped. Rewriting by `String.toList_ofList` preserves the exact predicate
  and made the repaired descriptor builds pass in 2.6–6.5 seconds. The final
  composition passed in 4.8 seconds. CSR modules remain cached; sampled late
  CSR memory was 1.29 GiB. No proof wire or production capability changed.

- Observation: two candidate formal additions were rejected during strict
  review and removed. The proposed whole-view wrapper assumed the desired
  coupling in a premise while leaving its proof-byte and oracle-transport
  parameters unused. The proposed BCS compatibility wrapper only repackaged
  existing counts and mismatches. Neither proved an SMZ9 privacy, knowledge,
  or soundness fact, so both receive zero progress credit.

- Observation: the exact SMZ9 wire is already nearly free of removable
  metadata. Its 122,863-byte maximum consists of 97,608 field-word bytes,
  23,872 SHA-512 root and authentication-node bytes, 1,280 tape bytes, 32 salt
  bytes, 4 nonce bytes, 4 magic bytes, and 63 metadata bytes. A new fixed codec
  can save at most 67 worst-case bytes; every multi-kilobyte reduction changes
  a commitment width or opening count and therefore requires a fresh security
  composition.

- Observation: the compact retained SMZ1 proof is 119,606 bytes, while an
  older retained proof is 371,142 bytes because it carries stale 84-column
  masking/high-coefficient geometry.
  Evidence: exact decode of the two retained artifacts on 2026-08-22.

- Observation: the compact artifact is structurally valid and consumes its
  wire exactly, but its modification time predates current source changes and
  it has no retained statement/action companion or source digest.
  Consequence: it is useful size evidence, not a release artifact.

- Historical observation: during the initial SMZ1 audit,
  `serialized_proof_size_hint_with_profile` modeled the historical SMW2
  opening shape even when asked about SMZ1, so the checked-in
  124,982-byte structural ceiling undercounts SMZ1 by exactly 1,472 bytes.
  Consequence: the conservative corrected historical ceiling was 126,454
  bytes. The active SMZ9 estimator instead projects 122,863 proof bytes and
  charges all twenty tapes.

- Observation: the implemented soundness calculator gives
  262.3777366177 bits for the frozen interactive profile, but production
  authorization also requires the Fiat-Shamir/QROM composition, verifier
  refinement, and exact deployed hash accounting.

- Observation: the current complete-ZK formalization proves the mask/domain
  ingredients and exposes the residual random-oracle simulation loss. It does
  not by itself establish a whole-verifier-view simulator for the deployed
  Rust serialization.

- Observation: the Rust engine now has a whole serialized-view simulator and
  exact replay harness, but its recorded oracle programming has not yet been
  related to an adaptive QROM theorem. Production therefore remains
  fail-closed even though the executable view/refinement slice now exists.

- Observation: the SHA-512 field sampler's finite cap gives, for `n` requested
  words and `C` available candidates, the recorded ideal-uniform abort bound
  `choose(C,C-n+1)*(2^32-1)^(C-n+1)/2^(64*(C-n+1))`. At the maximum admitted
  request the cap supplies 32 extra candidates and the term is below `2^-386`.
  This is an abort term only; it is not a concrete SHA-512/QROM bound.

- Observation: the later correction-factor audit has already been repaired in
  the current engine. Prover nonce selection and verifier canonicalization now
  share `smallwood_piop_opening_points_are_valid`, which rejects the retained
  zero-correction counterexample.

- Historical observation: the stablecoin V3 state transition was not part of
  the 699-row relation. That compact relation proved only the older
  issuance/balance metadata surface and does not bind the before/after state
  root, authenticated state path, issuer authorization, or lifecycle counters.
  Consequence: the 686-row V8 relation added the Poseidon2 stablecoin
  state-transition relation; host prevalidation is not a substitute. The later
  parent-height/genesis-root audit found a separate lifecycle blocker, which
  HGV8RP03 and the native source capability repair without changing the
  686-row geometry.

- Observation: six Goldilocks digest/capacity limbs cannot meet a literal
  `>= 2^128` generic quantum-collision work gate. The exact BHT cardinality is
  `p^2`, where `p = 2^64 - 2^32 + 1`, and is therefore slightly below
  `2^128`. Domain separation and extra rounds cannot change that output-space
  bound. Production needs at least seven capacity limbs and seven digest limbs,
  under a fresh Poseidon2 identity.

- Observation: widening the state is smaller than lowering the rate. A
  width-12/rate-5 construction needs an extra squeeze for every seven-limb
  digest and crosses 128 KiB even with optimal authentication paths. A
  width-16/rate-8 construction keeps the current three packed permutation
  groups and has 3,602 bytes of worst-case proof headroom before the missing
  stablecoin transition.

- Observation: the complete authenticated stablecoin row includes the issuer,
  policy-admin, oracle, attestation, and collateral-custody commitments. The
  mint/burn relation must bind all five as nonzero, pairwise distinct, and
  unchanged. Leaving three of them outside the Poseidon2 leaf would not refine
  the implemented state machine.

- Observation: the smallest profile change that clears the implemented
  interactive floor after the full relation extension is a fresh DECS domain
  and query count. `N=2^21,q=22` leaves only 179 proof bytes at the earlier
  898-row screen and is too fragile. `N=2^23,q=19` provides the strongest and
  smallest tested tuple: at 924 rows its exact worst-case projection is
  128,378 wrapped bytes, leaving 2,694 bytes for the compact V8 statement and
  transport while retaining a 266.865073-bit interactive aggregate.

- Observation: public statement words change the bound SHA-512 transcript but
  do not serialize in the inner proof. Auxiliary witness words do serialize at
  exactly eight bytes each. The final size test must therefore consume the
  compiler-reported auxiliary count instead of copying the earlier 120-word
  public-statement planning budget.

- Historical observation: for the disqualified q=19/SMZ8 profile, nineteen
  independent depth-23 Merkle paths were not a valid
  structural ceiling for an accepted proof. The verifier requires the exact
  compact path lengths for nineteen sorted distinct queries and rejects
  redundant siblings. An exhaustive split dynamic program proves that the
  maximum accepted compact surface is 355 authentication nodes, versus 437
  nodes for nineteen independent full paths. The SMZ8 projector subtracts
  exactly those 82 noncanonical nodes and is exhaustively checked on all leaf
  subsets through depth four. The SMZ9 rehearsal profile instead uses twenty
  openings and at most 372 authentication nodes. HGV8RP02 was its frozen
  686-row rehearsal baseline; HGV8RP03 supersedes that identity without
  changing the recomputed 122,863-byte projection.

- Observation: the initial V8 relation module only rebuilt a host-computed
  material object and therefore could not be verifier authority. That blocker
  is closed: the public-only verifier adapter now reconstructs the executable
  relation from the exact 120 public words and seven binding limbs, and its
  source emissions are checked against the pinned 85-family program before an
  adapter can be returned. Production still requires retained proof, native
  lifecycle, complete-ZK, composed-security, refinement, and release receipts.

- Observation: the first width-16 port inherited a two-permutation
  variable-length sponge for each 14-field transaction Merkle node, even
  though the fresh source API already defines the node as a single fixed-arity
  permutation. The inherited schedule wasted exactly one 64-lane hash group,
  or 182 relation rows. The corrected source-derived geometry projects 11,354
  fewer bytes in the maximum two-output action before proof generation.

- Observation: the initially drafted compact transport omitted the 2,147-byte
  ciphertext carried by each active output. That would not have been a
  self-contained transaction. The fixed transport carries the exact bytes and
  verifies their BLAKE2b-384 commitments before invoking the proof verifier;
  the corrected maximum action projection is 119,512 bytes, not the smaller
  proof-only number.

- Observation: retaining the Merkle root inside the action-intent preimage
  made `FinalThresholdSpend` unconstructible. Its value-lock digest determines
  an input note authorization key, the note determines the Merkle root, and the
  retained root would then determine the intent again. The canonical V8 intent
  projection now zeros `[47,54)` while the proof transcript independently
  binds those public root words.

- Historical observation: the HGV8RP02 executable relation has 830 nonlinear
  identities for every statement. Its sparse linear program specializes to the
  activity and stable selectors and ranges from 19,898 to 20,472 identities
  across every accepted mask/mode/stablecoin fixture; its maximum summed
  identity inventory is 21,302. The eighteen-identity correction comes from nine authorization
  nonzero lanes whose selector and inverse conditions are already enforced by
  nonlinear identities and therefore need no filler linear rows. The engine
  width and security union must use the appropriate count,
  not conflate the maximum linear count with the summed union.

- Observation: the source-derived q=19 security result is adequate per proof
  but not after the release gate's actual multi-proof budget. With Q=2^64 it
  has about 141.903 ideal CMS bits per proof, and union over
  `561 * 4096 = 2,297,856` accepted proofs reduces that to about 120.771 bits.
  Increasing only the DECS opening count cannot fix this because the
  five-opening PIOP consistency term caps the interactive aggregate near
  274.6 bits.

- Observation: six PIOP openings and twenty DECS openings are the smallest
  jointly sufficient tuple under the current model. The extra PIOP row costs
  5,568 opened-witness bytes by itself; total proof growth is 8,785 bytes, not
  the roughly two-kilobyte DECS-only estimate. The exact 128,297-byte action
  still fits the hard cap with 2,775 bytes of margin.

- Observation: the checked-in HGV8RP01 digest binds family names, counts, and
  coordinates, but not every executable nonlinear formula or exact
  statement-specialized CSR identity. It is a useful drift detector, not yet
  a universal compiler-refinement receipt. The production candidate needs a
  fresh exact program identity rather than promoting this descriptor digest.

- Observation: HGV8RP02 closes that exact-program gap without changing proof
  bytes. The nonlinear verifier consumes the shared typed expression program,
  and the linear adapter is rejected unless its complete specialized numeric
  CSR equals the specialization of the pinned typed program. Formula operand,
  root, operator, witness-index, coefficient-root, target-root, selector,
  ordering, normalization, and empty-row mutations are therefore bound or
  fail closed before proof verification.

- Observation: HGV8RP03 supersedes HGV8RP02 as the current source relation.
  Its disabled-mode pass-through and two zero-value-balance equations raise the
  specialized linear inventory to 19,899--20,473 and the summed soundness union
  to 21,303 without changing the 686-row, 368-column proof geometry or the
  122,863-byte projection.

- Observation: native mempool and block validation now enforce a source-owned
  512-V8-action ceiling plus the independent exact 64 MiB full-carrier byte
  budget. The full projected canonical record yields exactly 522 actions from
  the byte screen before block overhead, and the security report retains 523
  as a separately labeled stricter overcount. Both security counts exceed the
  runtime count ceiling, so the recorded union remains conservative.
  The 4,096-block stablecoin epoch is state accounting, not a cryptographic
  reset. The generic
  theorem
  `SmallWoodHeterogeneousCmsQrom.indexed_ideal_logical_qrom_failure_probability_le`
  already charges one common tagged oracle and one global query count without a
  proof-count union. Unbounded history still needs its deployed SMZ9
  instantiation bridging the concrete SHA-512 Fiat-Shamir transcript and exact
  V8 relation under one protocol-lifetime total quantum-query budget, plus
  consensus enforcement of that budget.

- Observation: the new persisted counter is canonical-chain state, not an
  oracle-query meter. It rewinds to the common ancestor during a reorganization
  and does not count rejected proof attempts or proofs verified only on a
  discarded branch. This is the deterministic consensus mechanism requested by
  the conditional finite screen, but a deployed security claim still needs a
  reviewed reduction showing that its counted events cover the union or global
  query budget used by the theorem.

- Observation: the successor authorization checker was designed with a hash
  cycle: its source-owned registry would contain the evidence-bundle digest,
  while the bundle was required to hash the checker containing that registry.
  Positive authorization therefore had no constructible fixed point. Split
  immutable checker logic from the source-owned registry and root both in the
  reviewed release commit without requiring the registry to hash its own
  bundle transitively.

- Observation: the transport artifact's named `lifecycle_stages` are repeated
  exact parsers over one buffer. They prove byte preservation and mutation
  rejection, but they do not execute wallet HTTP RPC, peer relay, mempool,
  mining, block import, restart, sync, reorg, or fresh-node verification. The
  typed lifecycle suite uses `ScriptedVerifier`, so there is still no positive
  retained production-SMZ9 lifecycle receipt while authority is fail closed.

- Observation: exercising the retained v4 proof as a real non-genesis action
  is impossible with the current relation. Disabled-stablecoin canonicalization
  forces `parent_height` and the stablecoin roots to zero. Separately, the
  native source capability does not carry the canonical empty depth-32
  Poseidon2 note-tree root from which fresh activation and replay can establish
  the initial transition, and the retained maximum-shape proofs use a synthetic
  nonempty anchor.
  Consequence: the measured 122,351-byte and 122,735-byte proofs are
  height-zero-only rehearsal artifacts. Artifact-report v5 can repair their
  provenance but cannot repair their semantics; production needs a surgical
  relation change, a fresh identity, new proofs, and a real lifecycle run.

- Observation: the production monetary model requires canonical zero
  `value_balance` because Hegemon has no transparent pool. An empty canonical
  V8 note tree plus that rule has no ordinary-transaction source of positive
  native value.
  Consequence: the earlier zero-value seed/spend plan could validate mechanics
  but not an economically live system. It is superseded by the selected
  proof-bound action-11 V8 coinbase source and two-spend positive fixture.

- Observation: a source allowlist plus a JSON `output_sha512` is still only a
  declaration unless the release checker runs the named command. The checker
  now executes canonical argv directly and compares the bytes it actually
  observed. The current source inventory is empty because no existing test
  traverses the live production lifecycle; this makes the positive schema
  deliberately uninhabited instead of accepting parser-shaped evidence.

## Decision Log

- Decision: use one height-aware, source-owned proof-authority decision for
  protocol manifests, wallet construction, RPC, mempool, mining, block import,
  synchronization, and historical replay. Fresh V4/Gamma must not inherit
  authority from a default constant; V8 remains absent until its complete gate
  passes.
  Reason: the live code advertises and routes V4/Gamma while the security policy
  calls it historical-only. This is a consensus-policy contradiction, not a
  documentation issue.
  Date: 2026-08-30.

- Decision: maintain at least 40 GiB free throughout this campaign and treat
  the existing dirty tree as user-owned evidence. Do not run a cold build or
  proof generation below the reserve, do not use broad destructive cleanup,
  and do not regenerate retained proofs for a merely theoretical size idea.
  Reason: proof and formal builds are large, and reproducibility work is lost
  if disk pressure corrupts or forces ad hoc cleanup of the shared checkout.
  Date: 2026-08-30.

- Decision: optimize size only against the final composed-security and privacy
  inequalities. Prefer removing redundant authenticated bytes or reducing
  duplicated openings; never lower query/opening counts, tape entropy, digest
  width, relation coverage, or verifier binding to win bytes.
  Reason: proof bytes are a throughput cost, but a smaller non-private or
  sub-128-bit artifact is not a Hegemon transaction proof.
  Date: 2026-08-30.

- Decision: treat the exact SMZ9 quantum Fiat--Shamir compatibility theorem as
  the next cutover checkpoint and keep the existing wire unchanged while it is
  evaluated. Generic multi-round bounds that lose a factor quadratic in the
  global query count at every challenge are not acceptable substitutes for the
  tighter round-by-round SmallWood/CMS path.
  Reason: the current conditional arithmetic has useful margin, but the
  published SmallWood argument is classical-ROM and no black-box theorem yet
  binds Hegemon's exact compact transcript, lazy Merkle simulator, and Rust
  proof bytes to the required adaptive QROM games. This checkpoint determines
  whether remaining work is proof-only or a new wire version is necessary.
  Date: 2026-09-03.

- Decision: retain the existing SMZ9 wire and 122,863-byte ceiling while the
  privacy and soundness proofs close. Do not introduce a new codec for the
  67-byte worst-case metadata saving. Keep the q20/56-byte, q19, and combined
  candidates inactive because they change commitment or query security and
  require complete recomposition before they can receive size credit.
  Reason: 121,516 of the 122,863 maximum bytes are field words and SHA-512
  commitment/authentication material. Encoding churn cannot produce a
  meaningful block-capacity gain, while parameter changes can.
  Date: 2026-09-03.

- Decision: retain SmallWood and the compact Poseidon2 transaction relation.
  Reason: it is the only current architecture with a measured proof near
  120 KiB for the full relation. Binary-relation and replacement-backend work
  is out of scope for this production cutover.
  Date: 2026-08-22.

- Decision: disqualify q=19/open=5 for production and append a fresh
  SMZ9/profile-6 identity using q=20/open=6. Preserve every SMZ8/profile-5
  parser and constant as historical, and require exact profile and proof-magic
  mismatch rejection so old bytes can never be reinterpreted.
  Reason: the conservative 4,096-block analysis union is 120 bits for q=19 and
  121 bits for q=20/open=5. q=20/open=6 gives about 136 bits after its
  128,522-byte complete pending-action size reduces the maximum-size byte screen
  to 522 proofs before block overhead, while the public-argument action remains
  below 131,072 bytes. Four equally large external
  per-proof loss terms must each retain at least 152 bits for the conservative
  composed epoch result to remain at least 128 bits.
  Date: 2026-08-23.

- Decision: treat 122,863 proof bytes, 128,293 RPC-envelope bytes, 128,297
  SCALE inline-argument bytes, and 128,522 complete `PendingAction` bytes as
  the source-derived maximum-size release projections. Enforce the distinct
  parser caps of 131,068, 131,072, and 131,297 carrier bytes before allocation.
  The final source-derived structural estimator, rather than the historical
  126,454-byte core estimate, is authoritative for the fresh relation.
  Reason: the historical 124,982-byte estimate omitted 1,472 required SMZ1
  tape bytes. The old corrected 126,454-byte ceiling remains a regression
  baseline for the 699-row core, not a ceiling for the widened complete
  relation. A final artifact or carrier that exceeds its corresponding
  projection or parser cap is a regression, not a production fix.
  Date: 2026-08-22.

- Superseded decision: retain the 699-row core and existing proof engine, and
  permit only the missing stablecoin state-transition rows plus the smallest
  seven-limb Poseidon2 security repair.
  Reason: the audit found two exact blockers which cannot be fixed by a gate
  flip. Both can reuse the algebraic frontend and packed Poseidon trace; a
  binary relation or replacement proof system remains unnecessary. The engine
  was retained, but the completed relation compiled to 686 rows, so 699 is a
  historical baseline and not the active geometry.
  Date: 2026-08-22.

- Decision: allocate a fresh V8/Eta/action-10 outer identity and a fresh inner
  proof identity. Do not reinterpret V4/Gamma, V5/Delta, V6/Epsilon, V7, SMZ1,
  or SMZ2.
  Reason: the relation, stablecoin state machine, hash parameters, and release
  authority change. Historical bytes must retain their historical meaning.
  Date: 2026-08-22.

- Decision: use versioned width-16/rate-8/capacity-8 Poseidon2 with a
  seven-field-element digest as the production hash shape. Treat the current
  686-row relation as the measured rehearsal baseline, repair its lifecycle
  binding under a fresh identity, and require new v5 artifacts plus all
  remaining security, refinement, and lifecycle evidence before activation.
  Reason: it is the only measured legal seven-limb shape below 128 KiB; the
  width-12 alternative is structurally too large.
  Date: 2026-08-22.

- Decision: use `poseidon2_width16_compress14` for every fresh seven-limb
  Merkle node and reserve the variable-length sponge for genuinely
  variable-length preimages.
  Reason: this is the canonical transaction-core API, binds both seven-limb
  children plus domain and suite in one permutation, and eliminates an entire
  packed hash group without weakening or changing the node function.
  Date: 2026-08-22.

- Superseded decision: use the fresh no-grinding SmallWood profile `rho=5`, five PIOP
  openings, `beta=2`, DECS domain `2^23`, 19 DECS openings, and `eta=5`, with
  one independent 64-byte leaf tape per opening and fresh SHA-512 domains.
  Reason: the old 23-query profile fails its interactive floor after relation
  growth. The selected tuple is smaller and stronger than the viable
  `2^22`/20-query alternative, and its distinct wire prevents historical SMZ1
  or SMZ2 bytes from changing meaning. The exact multi-proof composition later
  disqualified this profile; SMZ9/profile 6 uses six PIOP openings, twenty DECS
  openings, and twenty tapes.
  Date: 2026-08-22.

- Superseded decision: encode the fresh inner proof as `SMZ8` and append, rather than
  reuse, both the arithmetization and transcript backend selectors. Bind the
  V8 SHA-512 profile frame to every role request and require exactly nineteen
  paths of depth at most 23 followed by 1,216 tape bytes.
  Reason: exact identity/profile checks prevent any SMZ1 or SMZ2 proof from
  changing meaning, and checking the 131,072-byte borrowed input length before
  matrix or path allocation closes the production parser boundary. SMZ8 is now
  historical and rejected by the active SMZ9/profile-6 route.
  Date: 2026-08-22.

- Decision: retain both artifact-report-v4 proof runs only as nonauthorizing
  rehearsal measurements. Reseal their unchanged proof and carrier bytes under
  artifact-report schema v5, bind each parent v4 report and generator hash plus
  a deterministic complete source inventory, and record the independently
  built verifier's own hash without requiring cross-platform binary equality.
  Reason: v4 fresh verification established the measured 122,351/128,010 and
  122,735/128,394 proof/full-record sizes, but its HEAD-equality and identical
  generator/verifier-binary requirements make release provenance impossible
  across the intended macOS generation and Ubuntu verification boundary. The
  v5 provenance repair confers no authority by itself; security, refinement,
  release, and real lifecycle gates remain required.
  Date: 2026-08-23.

- Decision: do not promote either v4 proof, even after a v5 provenance reseal.
  Repair disabled-mode parent height and stablecoin-root pass-through in the
  relation under the fresh `HGV8RP03` identity, bind the canonical empty
  note-tree genesis root in native capability context, then generate new
  maximum-shape artifacts.
  Reason: provenance cannot turn a height-zero-only proof into a valid
  non-genesis state transition. The current v4 bytes remain useful only as
  measured size and regression evidence.
  Date: 2026-08-23.

- Decision: make canonical zero `value_balance` a double gate in HGV8RP03 and
  native V8 projection, and keep economically live activation fail closed until
  one positive native-value source is consensus-bound.
  Reason: accepting nonzero `value_balance` would manufacture a transparent
  value boundary that Hegemon does not have. Conversely, enforcing zero without
  a coinbase or bound activation state leaves an empty tree economically inert;
  a nonempty activation state must bind the append frontier and note records,
  not only the note root.
  Date: 2026-08-23.

- Decision: do not authorize production from a document checkbox or a single
  Boolean constant.
  Reason: authority must be derived from executable relation, security,
  refinement, lifecycle, artifact, and release-manifest checks that fail
  closed independently.
  Date: 2026-08-22.

- Decision: keep the V8 atomic-manifest claim count-only and keep the positive
  lifecycle receipt uninhabited until a source-authorized retained proof runs
  through the real native workflow.
  Reason: the transaction-local helper can source-bind zero-or-one typed-plan
  application and rollback, but neither its textual gate nor same-buffer stage
  labels prove arbitrary typed-row noninterference or end-to-end execution.
  Typed plan/apply/readback tests remain row authority; capability remains
  `None`, independent of the 512-action throughput ceiling.
  Date: 2026-08-23.

- Decision: make lifecycle evidence executable release authority rather than
  a static report.
  Reason: repeated parser labels and `ScriptedVerifier` state tests do not run
  wallet HTTP RPC, peer relay, mempool, mining, block import, restart, sync,
  reorg, or fresh-node verification. Future source authorization must add exact
  real commands; the checker will run them, bind their actual output hashes,
  and require the retained primary proof digest at every stage. Until those
  commands exist, the inventory remains empty and production remains false.
  Date: 2026-08-23.

- Decision: exclude the seven public Merkle-root words from the V8
  action-intent hash, while retaining them unchanged in the public statement
  and SHA-512 proof transcript.
  Reason: including them creates a cryptographic fixed-point requirement in
  `FinalThresholdSpend`; separate transcript binding gives exact statement and
  consensus binding without that construction cycle.
  Date: 2026-08-23.

- Superseded decision: name the SMZ9/profile-6 V8 relation by the first 48 bytes of
  SHA-512 over one canonical, statement-independent `HGV8RP02` executable
  program rather than a
  digest of Rust source text or a caller-provided relation object.
  Reason: the nine-section typed program commits the exact geometry, public
  map, Poseidon2 parameters, every executable nonlinear formula and root, every
  attempted sparse linear identity and symbolic target, all 125 live hash
  roles, SMZ9/profile-6/HGV8TX02 global bindings, and canonical normalization
  without a self-referential source hash. The verifier evaluates or
  exact-compares the running relation against that program before constructing
  an adapter. Source-file hashes remain release supply-chain evidence rather
  than consensus identity. This identity mechanism remains active, but the
  disabled-parent-height repair advances the concrete program to `HGV8RP03`;
  `HGV8RP02` remains the rehearsal identity.
  Date: 2026-08-23.

## Outcomes & Retrospective

Not complete. The checked checkpoint contains the exact 120-word public
decoder, the generated HGV8RP03 program components, the disjoint evaluation
coset and conditional degree-387 recovery, and the ideal independent law for
12,201 sampled field values. An explicit invertible allocation now transports
that law to all six honest algebraic coin roles. For fixed admissible challenges
and fixed offsets, the joint algebraic output law is also proved independent
of those offsets. Independent source reviews found no errors in either result.
The saved Rust transaction suite passes 419 tests. The complete cryptography
Lean gate passes with 87 audited declarations, including all three new
mathematical results. The integrated build passes 2,738 jobs.
The complete structural canonicality theorem now also passes for the exact
generated program. Its encoded-byte/hash binding and typed transaction
semantic adequacy remain separate obligations.
The connection to actual runtime randomness and to the sequential transcript
remains open. The complete-source quantum distinguishing bound, joint real and
simulated proof and oracle experiment, and exact SMZ9 knowledge theorem remain
open. Current-source retained artifacts and release authority also remain
absent, so the capability stays `None`.

The frozen current HGV8RP03 baseline is the 686-row
SMZ9/profile-6 relation with
twenty tapes and a 122,863-byte proof projection. Its RPC envelope, SCALE inline
arguments, and canonical full `PendingAction` project to 128,293, 128,297, and
128,522 bytes. The two independently randomized HGV8RP03 v5 rehearsals measure
122,735 and 122,607 proof bytes and verify against their frozen 2026-08-23
source inventory. They are not current-source release artifacts: the later
security, randomness, formal, and checker changes deliberately make the live
inventory check reject both the fixed pointer and the existing candidate. The
HGV8RP03 program bytes and proof wire remain frozen, but production still
needs two fresh proofs and a newly constructed current-source v5 candidate
manifest after this formal source checkpoint settles. The atomic mined/reorg typed-plan
count seam is source-bound and covered by formal-core plus
rollback/cardinality/reopen regressions, but capability is `None`, MAX V8
actions is 512, the required cryptographic/refinement/release receipts
remain incomplete, and no retained release-valid proof has executed the full
live wallet-to-fresh-node lifecycle. Record the positive action-11 coinbase and
two-spend receipt here only after every release gate and the actual run have
passed.

## Context and Orientation

The transaction proof implementation lives in
`circuits/transaction/src/smallwood_engine.rs`,
`circuits/transaction/src/smallwood_semantics.rs`,
`circuits/transaction/src/smallwood_frontend.rs`, and
`circuits/transaction/src/proof.rs`. The semantics module constructs the exact
transaction constraint map. The frontend converts it into the engine matrices
and connects public inputs. The engine implements the PIOP, DECS commitment,
transcript, proof wire, and verifier. The proof module selects versioned
production identities and binds the proof to the transaction statement.

The compact core relation covers the fixed-capacity Hegemon transaction surface:
two possible inputs, two possible outputs, all sixteen activity masks,
Merkle membership, note commitments, nullifiers, value conservation, asset and
stablecoin rules, ciphertext and intent binding, and every supported
authorization mode. Inactive slots remain present and are constrained to their
canonical values. The 686-row HGV8RP03 relation includes the stablecoin
before/after state-root transition, preserves the disabled-mode parent height,
passes through the current stablecoin root, and forces canonical zero
`value_balance`. Native capability separately binds the canonical empty
note-tree genesis root. The positive native-value source remains unselected and
fail closed. This fixed capacity is why a single maximum-size artifact can
cover the production size gate.

The native lifecycle crosses `wallet`, `node/src/native`, `consensus`,
`protocol/shielded-pool`, storage, and sync/reorg code. Every boundary must
carry the same canonical proof bytes. Parsing must enforce a cap before
allocation, reject noncanonical encodings and trailing bytes, and bind the
action, network, protocol version, statement, verifier profile, and proof wire
identity.

Formal specifications and generated refinement vectors live under
`formal/crypto`, `formal/lean/Hegemon/Transaction`, and
`formal/lean/Hegemon/Native`. Release authority is checked by scripts under
`scripts/` and by the CI/release workflows. Retained evidence belongs under a
new Poseidon2/SMZ9 production artifact directory; old candidate artifacts must
not be overwritten or silently reclassified.

## Plan of Work

### Milestone 1: freeze and verify the relation and parameters

The exact compiled relation is now HGV8RP03, semantic relation v2. It preserves
686 rows and 368 columns, binds disabled-stablecoin `parent_height`, passes the
stablecoin root through with
`before_root == after_root == context.current_root`, and keeps every other
inactive stablecoin field zero. The native source capability separately binds
the canonical empty depth-32 Poseidon2 note-tree genesis root. HGV8RP03 and
native projection enforce zero `value_balance` sign and magnitude. Finish
binding the final row/column count,
public-input layout, named constraint-family counts, Poseidon2 tuple, constants,
and normalized digest into one versioned profile record. Add executable tests
that regenerate or independently recompute the Poseidon2 round behavior and
compare every production relation row with the formal/reference model. Exercise
all sixteen masks and all authorization modes. A mutation to any public field,
witness field, Poseidon2 parameter, round constant, constraint row, or relation
digest must fail verification or profile admission.

This milestone is complete when the exact full relation has one stable digest,
the Rust verifier and formal/reference evaluator agree on every row, and the
profile gate rejects every alternative tuple or legacy Poseidon relation.

Implement the selected versioned width-16/rate-8/capacity-8, seven-limb
Poseidon2 profile without changing historical width-12 code. Pin the selected
round schedule, constants, provenance, and independent known-answer vectors
under the fresh identity. Retain the width-12/rate-5 measurement as a rejected
size vector.

### Milestone 2: close complete ZK and composed soundness

Use the fresh SMZ9 disjoint-coset, six-opening, twenty-tape profile. Implement a whole-view
simulator/refinement test for the exact serialized proof view, including opened
values, opened witness masks, authentication paths, salt, transcript digest,
and independent leaf tapes. Make the statistical/random-oracle loss explicit
for the supported proof and query budgets. If the existing 256-bit salt does
not leave the required margin, introduce a new production wire identity with a
larger salt only under another fresh identity; do not silently alter the
post-repair relation or opening geometry. The
expected size cost of that repair is tens of bytes, not kilobytes.

Recompute the composed forgery bound from the exact parameters. Include the
PIOP term, DECS/PCS term, Fiat-Shamir/QROM reduction, SHA-512 collision and
preimage terms, Poseidon2 relation assumptions, grinding term (zero here), and
the union over all challenges/openings/proofs admitted by the protocol. Encode
the same equation in Rust and Lean and compare generated vectors. Record the
strongest concrete public attack separately from the proof-derived lower
bound; never substitute one for the other.

This milestone is complete when the active Rust profile and Lean model agree
on every integer/rational input and the final bound, the complete-ZK simulator
is tied to the deployed wire, and mutations of any security parameter make the
production gate fail.

### Milestone 3: make authority executable and fail closed

Replace the current unconditional Poseidon production veto with a structured
production capability record. Each capability is derived from a checked local
artifact or an executable test: exact relation, Poseidon2 parameter assurance,
SMZ9 complete ZK, composed soundness, compiled verifier refinement, canonical
parser, lifecycle identity, maximum-size artifact, and release manifest.
Admission is the conjunction of all capabilities and the exact version/profile
identity. Missing, stale, malformed, or digest-mismatched evidence is false.

Do not let the prover choose the verifier profile. The action/version route
selects the one active profile, and the proof bytes must encode exactly that
identity. Historical proof versions remain independently verifiable only where
consensus history requires them; they are not accepted for new mempool or
mining admission.

### Milestone 4: bind the unchanged proof through the native lifecycle

Use one canonical envelope from wallet construction through RPC, relay,
mempool, mining, block encoding, persistent storage, sync, restart, and reorg.
At each boundary, decode with the same canonical parser and compare the exact
bytes or their consensus-bound digest. Remove any path that reconstructs,
normalizes, substitutes, or validates from a cache/receipt/sidecar. Enforce the
131,072-byte native-leaf and inline bounds, the 131,068-byte envelope bound,
and the 131,297-byte complete `PendingAction` bound before allocation.

Add an end-to-end positive-value lifecycle test. Mine two exact action-11 V8
coinbase notes in consecutive blocks so they occupy canonical positions zero
and one. From the second coinbase parent, submit and mine the primary
maximum-shape spend, reorg to an independently randomized spend of the same
fixture, then extend and reorg back to the stored primary branch. Restart and
fresh sync must confirm byte-for-byte identity and fresh verification of the
original primary proof. Mutate every
envelope/profile/statement/action/network field and representative bytes in
every proof section; each mutation must be rejected at the earliest responsible
boundary.

Do not mark this lifecycle complete from fixture construction or scripted state
tests. Completion requires the actual miner-local action-11 blocks and both
release-valid spends to pass every live path and fresh verification gate.

### Milestone 5: retain the release artifact and cut over

Generate a fresh maximum-shape proof from the final source. Reread and verify it
with the production verifier in a fresh process. Retain the proof, canonical
public inputs, transaction envelope/leaf, profile record, source and relation
digests, exact size report, timing report, mutation report, lifecycle report,
formal/refinement receipts, and release manifest together. The manifest must
name every file and digest and must be verified by the same release script used
in CI.

The release gate must assert:

* the SMZ9 proof is at most 122,863 bytes, the complete inline V8 action is at
  most 128,297 bytes, and the complete canonical `PendingAction` is at most
  128,522 bytes, using a source-derived structural estimate that charges every
  serialized field and all twenty 64-byte leaf tapes;
* the repaired relation has the fresh identity allocated in Milestone 1, its
  final geometry remains within every carrier cap, and it exactly matches its
  fresh profile manifest;
* the active Poseidon2 and SmallWood parameter tuples match exactly;
* the production verifier accepts the retained artifact from a fresh process;
* every required mutation, restart, sync, reorg, formal, refinement, and
  manifest check passed; and
* no candidate/replacement backend is production-authorized.

Only then set the production action/version route active. Update `README.md`,
`DESIGN.md`, `METHODS.md`, security documentation, operator documentation, and
release notes with measured facts and exact claim boundaries.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

First establish focused baselines:

    cargo check -p transaction-circuit --lib --locked
    cargo test -p transaction-circuit --test smallwood_poseidon2_v8_exhaustive --locked
    cargo test -p transaction-circuit smallwood_poseidon2_v8_security::tests --lib --locked
    cargo test -p transaction-circuit smallwood_poseidon2_v8_zk_refinement::tests --lib --locked
    cargo test -p protocol-shielded-pool maximum_shape_codec_is_exact_and_every_frozen_outer_mutation_rejects --lib --locked
    cargo test -p hegemon-node protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly --lib --locked
    git diff --check

Before a retained refresh, exercise the candidate-only publication seams. The
wallet command has no default output and the destination must not exist. The
manifest commands refuse the fixed pointer and any existing output:

    cargo test --locked --offline -p wallet --example generate_poseidon2_v8_retained_vectors
    python3 -I -B scripts/test_construct_smallwood_poseidon2_v8_retained_manifest.py
    cargo test --locked --offline -p hegemon-node retained_smz9_manifest_selector_ --lib
    cargo run --locked --offline -p wallet --example generate_poseidon2_v8_retained_vectors -- --output-root <new-wallet-vector-directory>
    python3 -I -B scripts/construct_smallwood_poseidon2_v8_retained_manifest.py construct --artifact-root <new-versioned-artifact-root> --output .agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-<source-id>.json
    python3 -I -B scripts/construct_smallwood_poseidon2_v8_retained_manifest.py verify --artifact-root <new-versioned-artifact-root> --manifest .agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-<source-id>.json

The versioned artifact root must be the direct child
`.agent/artifacts/smallwood-poseidon2-v8/hgv8rp03-<first-16-hex-of-live-source-root>`.
It must contain exactly the two proof directories, the independently built and
byte-identical generator binaries at the two schema-owned paths, and the exact
chain report before manifest construction. Keep the candidate manifest outside
that root. Constructing or verifying it does not promote the fixed pointer.
The lifecycle defaults to the exact fixed pointer. Before promotion, select a
verified candidate explicitly through the test-only environment variable and
run the full retained lifecycle while capability is still `None`:

    HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_PATH=.agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-<source-id>.json cargo test --locked --offline -p hegemon-node native::poseidon2_v8_verifier::tests::retained_rp03_two_coinbase_chain_survives_rpc_relay_mining_restart_reorg_and_fresh_sync --lib -- --ignored --exact --nocapture

The override is compiled only in tests, rejects the fixed pointer as an
override, and cannot change production capability or production path
resolution. Promote the pointer only as a separate reviewed action after this
candidate lifecycle passes.

After each milestone, rerun the narrow affected crate tests. Before cutover run
the production artifact generator with a new artifact directory, then run the
release-policy, formal-crypto, formal-core, native lifecycle, restart/sync/reorg,
and full locked workspace checks specified by the scripts and CI workflows.
Record every exact command and result in `Progress`.

Do not run proof-size comparisons against Binius, M4, IronSpartan, or any
standalone/replacement backend. They are outside this plan and cannot authorize
the active route.

## Validation and Acceptance

Acceptance is behavioral. A maximum-shape transaction using each supported
authorization mode and representative activity masks must prove and verify.
All sixteen masks must be covered by the exact relation/refinement suite. The
same proof bytes must survive RPC, relay, mempool, mining, block, storage,
restart, sync, and reorg. A fresh node with no cache must accept the valid block.
The suite must reject nonzero `value_balance` in both relation verification and
native projection. The selected action-11 source, its two exact coinbase notes,
initial note root, supply, height, network, and release identity must pass exact
admission and replay with both independently randomized spend proofs.

Negative validation must cover noncanonical lengths, trailing bytes, oversized
declarations, wrong action/network/version/profile, wrong public values,
wrong statement, wrong relation digest, every proof section, every Poseidon2
parameter family, every authorization mode, balance/stablecoin violations,
Merkle/nullifier mutations, and source/manifest staleness.

The production route remains inactive if any command fails or either size cap
is exceeded. Passing unit tests without a fresh retained artifact is not
acceptance. A retained artifact without lifecycle and fresh-process readback is
not acceptance. Formal statements without Rust/refinement vectors are not
acceptance.

## Idempotence and Recovery

All evidence generation must write to a new versioned directory and use atomic
rename only after successful readback. Never overwrite historical artifacts.
If a run fails, retain its log separately or discard only the newly created
temporary directory after checking its exact path. Do not delete shared build
caches or unrelated dirty-worktree changes.

Production authorization is fail closed. At any intermediate commit the active
route must either use the previously authorized profile or remain disabled; it
must never accept a partially migrated profile. Because no prior SmallWood
production profile is currently authorized, all intermediate states remain
disabled until the final manifest passes.

## Artifacts and Interfaces

The final retained directory must contain, at minimum:

    proof.bin
    public-inputs.bin
    transaction-leaf.bin
    profile.json
    relation.json
    size-report.json
    timing-report.json
    mutation-report.json
    lifecycle-report.json
    formal-receipts.json
    release-manifest.json

The lifecycle evidence set contains three such proof bundles: one seed bundle
and two independently randomized maximum-shape spend bundles. The lifecycle
report binds all three proof hashes and the exact seed-to-spend note/root chain.

The production profile API must expose one immutable identity and one
fail-closed admission result. Callers may inspect individual capability results
for diagnostics, but they may not bypass them. The parser API must expose
cap-before-allocation canonical decoding and exact-consumption verification.
The verifier API must take the canonical statement/public values and proof
bytes; it must not accept host-computed private relation outputs or optional
validity hints.

Revision note (2026-08-22): created this surgical Poseidon2/SmallWood cutover
plan after the architecture was narrowed back to the measured compact relation.

Revision note (2026-08-23): the retained successor is additively encoded as
SMZ9/profile 6 with six PIOP openings, twenty DECS openings, and twenty
independent 64-byte tapes; SMZ8/profile 5 remains historical and rejected.
The frozen rehearsal-source projection is 122,863 proof bytes, 128,293 RPC-envelope bytes,
128,297 SCALE inline-argument bytes, and 128,522 full typed PendingAction bytes.
Artifact report v4 uses a read-once no-symlink snapshot, exact carrier-to-
verifier input comparisons, fresh mutation/opening-surface/honest-map checks,
and exact generator provenance. The two v4 reports are nonauthorizing rehearsal
measurements. Artifact report v5 must preserve every proof and carrier byte,
bind its parent v4 report and generator hash, and add a deterministic complete
source inventory while allowing the independently built verifier to record its
own binary hash. The v5 provenance reseal does not satisfy any security,
refinement, release, or lifecycle gate by itself. Retained artifacts must be
built and run with

    cargo build --locked --profile retained-proof -p transaction-circuit --example smallwood_poseidon2_v8_artifact

The named profile inherits release with incremental compilation disabled,
one code-generation unit, no debug information, and debug-information
stripping. Two clean private-target builds must have identical byte strings and
SHA-512 before either expensive retained proof is generated. Production
authorization remains fail closed. The current proofs may be resealed under v5
as provenance-preserving rehearsal evidence, but the height-zero lifecycle
blocker means production requires the repaired relation, a fresh identity, two
new proofs, and the rest of the release evidence, including the real lifecycle
receipt.

Revision note (2026-08-23): clarified that transport `lifecycle_stages` are
same-buffer codec evidence and typed restart/reorg/sync tests are scripted state
evidence, not a positive native lifecycle receipt. Added the count-only atomic
typed-plan closure and its explicit limits; capability remains `None`.

Revision note (2026-08-23): replaced only the temporary one-action V8 staging
limit with a source-owned 512-action ceiling. The independent 64 MiB aggregate
and 131,297-byte record caps remain exact. Neutral disabled/no-write actions at
one root are canonical by action id, at most one mint/burn edge advances each
root, cycles ignore neutral self-loops, and block order is exact-checked.
Every note anchor must come from canonical pre-block history, so same-block
outputs remain unspendable. The unchanged 523-proof security overcount is
strictly above the runtime ceiling. Production authority remains absent.

Revision note (2026-08-23): froze the SMZ9 rehearsal measurements and corrected
all active-size surfaces to 122,863 proof, 128,293 RPC, 128,297 SCALE inline,
and 128,522 complete pending-action bytes with 522 projected-maximum records per
64 MiB screen. The two v4 proofs measure 122,351/128,010 and 122,735/128,394
proof/full-record bytes but are nonauthorizing and height-zero-only because
disabled-stablecoin canonicalization erases `parent_height` and the stablecoin
roots; they also predate the canonical empty depth-32 Poseidon2 note-tree
genesis-root capability binding, and both proofs use a synthetic nonempty anchor.
Artifact schema v5 repairs source provenance only. HGV8RP03 is source-frozen,
while the full proof/native source inventory remains to be sealed after the
action-11 integration; production still needs fresh proofs and a real lifecycle
receipt.

Revision note (2026-08-23): made future lifecycle receipts executable and
retained-proof-bound. The release checker now reruns source-owned exact commands
and compares observed output digests; parser labels, scripted verifiers, stale
proof identities, and validity shortcuts cannot satisfy the gate. No real
command is source-authorized yet, so the registry and production capability
remain empty.

Revision note (2026-08-23): removed static local evidence as a release-authority
shortcut. Canonical source-command receipts now bind checkout sources, both
retained proofs, the deployed-security report, the workflow, and a hash of the
complete native capability tuple. The tuple includes activation height and
separate stablecoin and canonical-empty note genesis roots. Production also
requires an executable zero-`value_balance` projection receipt. No real command
is populated, so this is fail-closed policy rather than a production claim.

Revision note (2026-08-23): recorded the no-transparent-pool consequence.
`HGV8RP03` and native projection must both reject nonzero `value_balance`. The
earlier zero-value seed chain is superseded. Action 11 is the selected
miner-local positive-value source, and the retained schema now spends its exact
notes at positions zero and one with two independently randomized proofs.
Activation remains blocked until that complete lifecycle and every other
release gate pass.

Revision note (2026-08-23, historical; superseded 2026-08-30): hardened release evidence against canonical-path,
dirty-tree, feature-graph, command-time source drift, executable-path TOCTOU,
parser-stage lifecycle, conditional-theorem, string-only history, and unsigned
review substitution. At that snapshot the diagnostic security report remained
explicitly non-authorizing at 31,956 bytes and SHA-512
`4308fb56c68be761de1f2db8411e26fb5f0addeaa279f52a10e245b5a23b727112fecc9401969305a00c2858ca4c2e8a179a033affaf7b46ea606c0857350fee`.
No command, trust root, capability, or profile was authorized by this work.

Revision note (2026-08-23, historical; superseded 2026-08-30): added the
then-current atomic canonical SmallWood V8 proof-lifetime accounting and exact
reference vectors for 522 proofs per block, 4,096 blocks,
2,138,112 proofs per analysis interval, and the conditional 621,730,874-proof
ceiling. Release evidence distinguishes this mechanism from deployed security;
the executable receipt command, capability, registry, review root, and global
QROM theorem remain absent.

Revision note (2026-09-03): recorded the resumed clean-source and disk-reserve
checkpoint and narrowed immediate execution to the four proof obligations that
decide whether HGV8RP03/SMZ9 can reach production without changing proof bytes.
The quantum Fiat--Shamir compatibility theorem is now the explicit first
go/no-go checkpoint; production capability remains absent. Re-established all
narrow Rust relation, privacy, security, carrier, and native-codec baselines,
and closed the practical-time Lean build issue for the ideal correction-aware
six-opening theorem. Its Rust/SHA-512 sampling bridge remains a separate open
obligation rather than being hidden by the successful ideal build.

Revision note (2026-09-04): resumed the saved checkpoint, repaired the final
governance receipt after its dependent review digest changed, and verified
the blueprint and historical progress ledger. Commit `51f90425` preserves
that tested checkpoint. Subsequently proved the exact field allocation,
the joint algebraic law at fixed challenges and offsets, and full structural
canonicality of the materialized HGV8RP03 program. The integrated cryptography
gate passes with 87 audited declarations and 2,738 build jobs. Serial bounded
checks and exact string-roundtrip rewrites resolve the two observed checking
memory spikes. The transaction implementation, program binary, and proof wire
are unchanged. About 38.3 GiB remains free; cold builds and fresh retained
proof generation remain held below the 40 GiB reserve. Complete privacy,
quantum composition, implementation refinement, and release authority remain
open and receive no completion credit from these structural results.
