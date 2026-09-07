# Complete the corrected SMZ9 security argument

This living ExecPlan follows `.agent/PLANS.md` and continues
`.agent/SMZ9_JOINT_ACCEPTANCE_EXECPLAN.md`. A checked intermediate theorem is not
completion of this plan.

## Purpose / Big Picture

The endpoint is a complete security argument for the exact transaction relation
and SMZ9/profile-6 proof selected after the two verified HGV8RP03/typed-semantics
mismatches are repaired. Privacy must use a witness-free
simulator with the adversary's persistent quantum oracle. Knowledge soundness
must construct an efficient extractor from the candidate verifier's accepted
bytes and return a witness satisfying `ExactV8RelationSemanticValid`. The
always-denying outer production gate cannot make either theorem vacuous.

The repair is not a relabeling of HGV8RP03. Constraining out-of-range sponge
padding changes the executable relation bytes and therefore requires a new
relation digest, regenerated source and Lean artifacts, new retained proofs, and
fresh review. Old proof bytes stay nonauthorizing historical evidence. Preserve
the new self-contained bytes through wallet, RPC, relay, mempool, mining,
blocks, sync, restart, reorg and fresh-node verification. Do not change the
wire, profile, primitive, authority, network or dependency merely to make an
intermediate theorem easier. No push, deployment or public submission is part
of this work. The security endpoints and resource accounting remain those in
`docs/crypto/smz9-campaign/security-contract.md`.

## Progress

- [x] (2026-09-07) Rechecked the selected checkout and preserved the three
  unrelated AGENTS/testnet-skill edits. Existing local checkpoints are
  `814b68fb` and `f4abcede`; the latter passed 2,754 jobs and 145 credited roots.
- [x] Derived and independently reviewed an eager witness-free privacy
  construction and an arbitrary-source, sample-weighted recovery reduction.
- [x] (2026-09-07 16:15 UTC) Mechanized the joint 3,105 PIOP / 1,940 DECS
  mask inverse, actual cross-column PCS map, and dependent 7,156-coordinate
  opening transport, including selector failure. Constructed the public eager
  algebraic fields and checked all row/DECS reconstruction round trips.
- [x] Proved the physical complex-linear hidden-program query bound and its
  complete raw-domain indexed 512-bit-tape specialization, with no domain-size
  union factor. Composed the classical context/opened-tape mixture with the
  persistent full-versus-opened oracle transition.
- [x] Proved the arbitrary-source recovery reduction in the exact joint
  coefficient/query product. Specified an interpolation decoder before later
  queries/challenges; the maximum weighted line constant is defined, not assumed.
- [x] Proved packed-program Boolean/radix constraints and seven exact dense
  61-bit value bounds from arbitrary accepted assignments. Corrected the
  reserved asset in the semantic specification and separated frontend public
  admission from raw packed constraints.
- [x] Proved fixed-pre-batching-candidate PIOP soundness for adversarial
  post-batching transcripts and fresh six-point admissible queries, with
  omitted linear constants restored from public targets.
- [x] Proved the exact actual 8,271-node field-expression degree certificate,
  all 830 root degrees at most 552, and successful-source-evaluation
  correspondence, including canonical representatives and equality selection.
- [x] Constructed the actual total typed source projection and proved note
  value, direction/position and one-hot authorization-mode properties from
  arbitrary packed acceptance; the full semantic conjunction remains open.
- [x] Derived the full unchanged canonical-witness predicate and per-asset
  integer balance from the actual accepted packed program. The balance proof
  includes native, ordinary nonnative, mint and burn branches with no-wrap
  bounds; hash/authorization/stable-transition families remain separate.
- [x] Constructed the current unbatched PIOP candidate from arbitrary decoded
  source polynomials and proved full candidate satisfaction implies actual
  unchanged packed-interpreter acceptance, including total Option evaluation
  and the impossible-empty normalized-CSR fallback case.
- [x] (2026-09-07 19:19 UTC) Ran the integrated formal-crypto build and axiom
  audit over 308 designated declarations: 2,797 build jobs passed, every audited
  declaration used only `propext`, `Classical.choice`, and `Quot.sound`, and all
  generated proof-wire files remained byte-identical.
- [x] Proved exact finite capped-sampler tails: DECS abort at most `2^-976`,
  successor maximum-size gamma abort at most `2^-773`, and every permitted retained-row
  gamma abort at most `2^-629`. The `Q^2` result is arithmetic over fixed-vector
  laws, not an adaptive-QROM theorem; a later `(2*Q_raw)^2` use pays its factor
  four explicitly.
- [x] Strictly checked the non-single authorization source prefix and the
  current repeated-request compiler. The former binds Boolean/one-hot bitmap
  transitions and the raw signer tag but not yet the complete canonical
  authorization relation. The latter compiles retained updates and charges two
  raw calls per logical read, but does not yet supply the external adaptive
  reprogramming theorem.
- [x] (2026-09-07 19:35 UTC) Kernel-proved that the old universal
  typed-to-HGV8RP03 completeness claim is false: a typed-valid stable burn whose
  stable asset is omitted from `balanceAssets` is rejected for every packed
  witness by public source root 1042.
- [x] (2026-09-07 20:17 UTC) Daybreak independently constructed a raw HGV8RP03
  counterexample for the final partial output-note sponge block. It preserves
  the decoded typed witness and passes all 20,569 CSR attempts and 53,120
  nonlinear evaluations, while violating canonical chaining at call 75 lane 2.
  The honest materializer rejects it only at `NonCanonicalTypedLowering`.
- [x] Traced the independent profile-6 verifier and confirmed it checks the
  HGV8RP03 CSR/nonlinear relation but never invokes the prover-side canonical
  typed-lowering guard. Production remains fail-closed because the source
  capability is absent.
- [x] Repair the two relation mismatches: bind every out-of-range sponge rate
  lane to canonical no-absorption chaining, and require an enabled stable asset
  exactly once in the typed/public balance list. Explicit in-range private
  sponge holes remain unbound. The focused Rust regressions pass.
- [x] Regenerate the exact source-owned relation program and digest-dependent
  source/Lean, conformance, policy and transport fixtures under the 853,429-byte
  program SHA-512 `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.
  `HGV8RP03` remains only the format-lineage magic; the 48-byte digest prefix is
  the relation discriminator. Never reinterpret old HGV8RP03-format proofs
  under the repaired digest.
- [x] (2026-09-07 21:38 UTC) Integrate the repaired relation, non-single
  authorization, disabled stable transition, bounded enabled-stable arithmetic,
  whole-view observation, coherent extraction, and source-codec endpoints. The
  complete formal-crypto gate passed 2,806 jobs and audited all 376 designated
  declarations under the existing axiom allowlist; three wire vectors and 48
  generated relation modules (2,266,857 source bytes) matched exactly.
- [x] (2026-09-07 21:44 UTC) Run the post-review Rust coverage: the focused
  first-block private-hole and wrong-new-signer-tag regressions each passed,
  the exhaustive relation target passed 10/10, and `cargo fmt --all -- --check`
  passed.
- [x] Record the endpoint decision dossier: P7, K8, and R0 are unavailable in
  the current proof graph, their constructor-free premise records cannot be
  bypassed by local gate results, and production stays fail-closed.
- [x] (2026-09-07 22:50 UTC) Preserve the final formal-core boundary exactly.
  Preflight passed. The vector script passed its repaired-relation/source and
  early consumer checks, then was interrupted at phase 4/14 when it reached a
  native-node SIGTERM smoke step forbidden by this continuation's no-node
  scope (exit 130); no listener or `hegemon-node` process remained, and the
  whole vector script is not recorded as passing. The policy script passed the
  dependency, inventory, system-model, 121-claim, 121-node blueprint and 2/2
  bridge-vector stages, then failed closed at phase 12/14 because the native
  BLAKE2b-384 Boolean transaction relation is unsupported and legacy Poseidon
  review bundles cannot authorize production (exit 1); phases 13/14 were not
  reached. Neither script was bypassed, weakened or rerun past its boundary.
- [ ] Generate and retain fresh primary and independent proofs for the repaired
  digest, then rerun the exact carrier/lifecycle evidence. The old retained
  bundles remain immutable historical evidence; proof generation and node
  execution were not authorized by this continuation.
- [ ] Mechanize the joint PIOP/DECS mask change of variables and compose the
  generated whole view with actual opening maps and abort branches.
- [ ] Prove the physical hidden-program removal inequality, its indexed-tape
  specialization, and its use in the complete persistent-oracle experiment.
- [ ] Prove the general recovery reduction and its required concrete finite
  bound, rather than assume a small candidate family or source cover.
- [ ] Construct packed-program-to-typed-semantics adequacy for arbitrary
  accepted assignments, not only honest lowering fixtures.
- [ ] Construct the actual quantum commitment/extraction and raw-oracle
  transfer, with resource overhead and all losses explicitly derived.
- [ ] Verify and locally land each integrated change without crediting it as
  completion; continue until both endpoint theorems are established or a
  concrete obstruction requires a material user decision.

## Surprises & Discoveries

The old PCS unstack coordinate formula was not the source randomization map:
Rust subtracts a coin polynomial from the next column. The corrected map is
still bijective at distinct nonzero points. The verifier's old stronger
admissibility restrictions are conservative and remain unchanged. Existing
model theorems about the old map must not be credited as source refinement.

The semantic model's reserved asset was incorrectly `p-1`; the source uses
`u64::MAX mod p = 4294967294`. Raw packed acceptance also does not enforce the
entire canonical public-word shape: the frontend performs that admission.
The semantic receipt now uses the actual admitted-public domain instead of
asking for a false raw-acceptance implication. This is not a proof that all
remaining private semantic families follow from acceptance.

Two authorization-specification mismatches were independently source-checked.
The transaction PRF selects the first active input, including the admitted
second-input-only case, rather than always reading input zero. The approval
predicate also omitted the source's binding from the newly approved bitmap
slot to all five words of the transaction signer's policy tag. The source
membership/bitmap constraints enforce that identity at
`smallwood_poseidon2_v8_semantics.rs:800-825`. The semantic model now includes
`ApprovalSignerBound`; it is strengthened to reflect existing execution, not
used to change the accepted protocol. Both corrections require fresh base
formal checks and source-content digests.

The old `ProductionConstraintExpression` and the actual 8,271-node
`FieldExpression` DAG are different interfaces. Generic public PIOP recovery
and eager laws must retain this boundary until the current-program polynomial
and opening adapters are proved; source dimensions alone do not establish it.

The privacy feedback cycle has an explicit inverse. In the independently
randomized-leaf experiment, let D be the full DECS response and T the full
PIOP polynomial message. Given D, derive the PIOP challenge, recover the PIOP
masks from T and the witness polynomials, rebuild the PCS rows, then recover
the DECS masks. This is a joint bijection, so the remaining witness-opening,
PCS and LVCS coins remain fresh. It does not preserve concrete unprogrammed
leaf hashes.

An eager simulator can retain D throughout. After constructing its opened
LVCS values, it computes mask openings as D(J) minus their challenged linear
combination. There is no need to claim independent DECS high coefficients and
mask openings. A full random leaf tree costs the same order of work as the
honest prover and avoids assuming the existing compact simulator has the
right joint law.

Each encoded leaf input identifies its own index. For independent unopened
512-bit tapes, a fixed raw input hits at most one hidden program with probability
at most 2^-512, without a tree-size union factor. The stronger averaged-state
query bound requires discarding the hidden tapes; it is not a bound for an
adversary later given them. Actual aborts, subsequent proof queries and oracle
overwrites must be retained.

The five DECS rows can be viewed as one extension-field word using the same
700 sampled base-field coefficients. Reversing the 140 column combinations
reduces arbitrary-source recovery to a sample-weighted, exact-support line
agreement bound. The desired finite bound at agreement threshold 416 is not
proved. No asymptotic capacity statement supplies its missing constant.

The executable sponge builder conflated an in-range `None` (a deliberately
private absorbed word) with `inputs.get(input_index) = None` beyond the final
input. For an 18-word output note, final call 75 rate lanes 2 through 7 were
therefore unconstrained instead of copied from call 74. A synthetic one-output
assignment changes lane 2, recomputes its hash trace and dependent action intent,
and still satisfies the entire pinned HGV8RP03 CSR/nonlinear program. The
canonical typed-lowering comparison is not part of independent proof
verification, so HGV8RP03 knowledge cannot be promoted to knowledge of the
typed relation.

The opposite-direction mismatch is public and independent of private witness
choices. The typed public predicate allowed an enabled stable asset to be absent
from all four canonical balance slots, while HGV8RP03 root 1042 requires
membership. A concrete asset-1001 burn is fully typed-valid but has root value
1001 for every packed assignment. This is a completeness rejection, not
inflation. Strengthening typed/public admission to the already-enforced packed
membership rule preserves the intended balance semantics.

## Decision Log

Use the complete eager simulator as the first privacy target. Its public proof
format is unchanged; proving the compact simulator's different sampling law is
not necessary to exhibit a witness-free simulator. Retain all correlated oracle
entries until an explicit quantum transition removes them.

After the user instructed the team to complete the work on 2026-09-07, repair
the verified relation/specification mismatches rather than attempt to prove a
false unchanged-refinement statement. The padding repair strengthens the
executable relation and creates a successor identity. The stable-membership
repair strengthens typed/public admission to match the existing packed rule.
Neither repair authorizes production or permits old artifacts to be relabeled.

The coordinator owns this plan, shared imports, inventory, builds and git.
Authors own only the new files assigned below. Initial review checkpoints are
twenty minutes, not automatic stopping conditions. Each lane has at most 40 MiB
of new source and scratch space. Monitor disk to sustain proof production and
keep the computer operational. The coordinator-invented 40 GiB cutoff is
removed following the user's correction; it is not a user constraint or a
stopping condition. Reclaim verified disposable build/scratch data as needed,
preserving sources, retained proofs, node/wallet state and unrelated work.
Reuse cached Lean 4.32.2 and
mathlib, with one direct Lean process per lane and coordinator-only package
builds. No Rust build or retained-proof generation is needed for these changes.

## Outcomes & Retrospective

The prior commits establish local mathematical ingredients, not either
endpoint. This continuation explicitly retains the unfinished complete proof as
the acceptance condition. Record subsequent validation and substantive
obstructions here; never populate a receipt with the desired conclusion.

## Context and Orientation

The active geometry is 686 witness rows, 368 columns, 120 public words,
five DECS rows over 140 committed data rows, degree 387, a 2^23-point Goldilocks
coset and twenty DECS openings. The PIOP has five repetitions and six openings.
The proof maximum remains 122,863 bytes.

`SmallWoodV8Smz9HonestHybrid.lean` establishes the earlier DECS-mask translation.
`SmallWoodV8Smz9HiddenLeafQrom.lean` supplies exact leaf framing and physical
oracle-domain operations. `SmallWoodV8Smz9SingleProofPrivacy.lean` contains the
source-shaped LVCS opening law. `SmallWoodV8Smz9JointQuerySampling.lean` counts
actual independent twenty-subset queries. The packed semantic obligations are
in `formal/lean/Hegemon/Transaction/Poseidon2V8SemanticAdequacy.lean`; that receipt
is currently uninhabited.

## Plan of Work

The privacy author owns new `formal/crypto/HegemonCrypto/SmallWoodV8Smz9EagerPrivacy.lean`
and `docs/crypto/smz9-campaign/eager-privacy-proof.md`. Derive the joint mask
bijection using the actual dimensions and then compose generated view laws.

The physical-oracle author owns new `SmallWoodV8Smz9HiddenPatch.lean` and
`hidden-patch-proof.md` in those respective directories. Define complex-linear
query operations, derive support and distance bounds, and prove their tape
specialization. An arbitrary norm-preserving nonlinear operation is forbidden.

The recovery researcher owns `weighted-mca-research.md` in the dossier and
attacks the concrete sample-weighted coefficient bound. The coordinator owns
`SmallWoodV8Smz9McaRecovery.lean`, defining polynomial agreement and proving the
reverse recovery and finite sampling reductions without a source-cover premise.

The semantic author owns new `SmallWoodV8Smz9SemanticBinding.lean` and
`semantic-adequacy-proof.md`. Trace actual accepted expression/linear constraints
to universal typed properties and construct genuine witnesses to the refinement
obligations. An executable check run only by the honest prover is not verifier
enforcement.

## Concrete Steps

Read the corresponding existing modules before editing. Use `apply_patch` and
distinct temporary output directories. Direct checks from `formal/crypto` use:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/NEW_MODULE.lean

The coordinator integrates frozen, independently reviewed files and runs:

    bash scripts/check_formal_crypto.sh
    python3 -B scripts/smz9_joint_acceptance_probe.py --self-test
    python3 -B scripts/smz9_hidden_leaf_qrom_screen.py --self-test
    git diff --check

Monitor actual resource use while running the gate. Do not turn a discretionary
free-space target into a reason to stop bounded proof checks. Stage only
explicit owned paths after successful current validation.

## Validation and Acceptance

Every new theorem must compile under the existing strict policy, use only the
permitted kernel axioms, and survive independent quantifier/source review.
Wire vectors and the 48 generated program modules must remain unchanged.
Numerical probes test arithmetic and small instances; they cannot certify the
current-field research bound or replace a proof of the defined experiment.

Final acceptance additionally requires generated real/simulated quantum games,
an efficient extractor operating on actual accepted bytes, proved semantic
adequacy, and a composed resource-bound result meeting the security contract.
Explicit primitive and implementation assumptions must not disguise an
unproved protocol lemma. Passing the local gate is necessary, not sufficient.

## Idempotence and Recovery

Keep prior committed sources and retained evidence. Control resource-intensive
operations to avoid exhausting disk while continuing safe proof work. Do not
reset unrelated edits. No authority flag changes as a side effect of testing.

## Artifacts and Notes

Record exact newly checked roots, commands, results and commit identifiers
after each integration. Research derivations remain labeled until their
statements and intended game instantiations are verified.

At 16:15 UTC, strict module checks and coordinator cached builds have passed
for EagerPrivacy, HiddenPatch, SemanticBinding, SemanticDenseRange,
PiopOpeningRecovery, PrivacyGameComposition, McaRecovery, EagerSimulator, and
PiopSoundness. The largest completed central build reported 2,658 jobs; this
is not the complete integrated crypto gate. All endpoint axiom inventories
returned so far contain only `propext`, `Classical.choice`, and `Quot.sound`.
No local commit has yet been made for this continuation.

Additional exclusive lanes now own McaDecoder (coordinator), SemanticDecoder
(semantic author), ProgramPolynomials (semantic constraint author),
CurrentProgramPiop (privacy author), and EagerOracleGame (physical-oracle
author). A separate read-only quantum-extraction bridge review traces the
required source extraction and raw-oracle schedule. The numerical MCA lane
has checked the weighted bound through global quotient dimension four using
finite incidence and a primary-source list-correlated-agreement theorem;
dimensions five and six remain open. That research deduction is not a Lean
certificate and does not establish the general constant.

Historical interruption at approximately 16:18 UTC: the coordinator stopped
new checks at 39.445 GiB free based on an invented 40 GiB threshold. The user
explicitly corrected that error at approximately 16:27 UTC. Work resumed;
only two independently verified unused incremental Cargo caches were removed
(about 560 MiB, reproducible from source). See the disk-maintenance record.
There is no 40 GiB stop condition. Per-process memory limits and small
certificate chunks are used where an actual oversized elaboration is found.

At about 18:11 UTC, the root-owned CurrentSourceAcceptance module passed
strict Lean. Its complete decoded-candidate-to-packed-acceptance theorem does
not take evaluator success or decoded witness validity as an assumption. It
uses the source's unconditional zero-coordinate attempt 19262 to eliminate
the impossible-empty normalized CSR case. The full balance endpoint passed
strict Lean independently; both await current-base cache/axiom integration.

A third independent semantic-target mismatch was verified against actual
hash-schedule lines 965–981, CSR lines 1405–1422, and the single-key public
shape validator: V8AuthorizationValid always selected input zero's key even
when only input one was active. The coordinator corrected the target to the
source's first-active key selection (four zeros if neither is active) and
added three strict-passing regression lemmas. No Rust/wire behavior changed.
Refresh the base caches, affected theorem inventory, semantic-source digest,
blueprint content hashes and relevant gates before the next local commit.

At approximately 16:46 UTC, the complete crypto gate passed: 2,770 jobs,
207 credited declarations under the standard axiom allowlist, unchanged wire
vectors, and all 48 generated HGV8RP03 files (2,263,766 bytes). This includes
the completed EagerOracleGame comparison, CurrentProgramPiop and actual
McaSourceBinding. The base formal Lean stage checked all 2,745 claimed
theorems: 1,198 axiom-free and 1,547 standard-axiom-dependent, no violations.
The corrected public-admission domain and padding constant passed the relevant
generated semantic vectors. The source-content digest was refreshed, not its
authority/status. Fourteen governance tests and the active-goal check passed.

At approximately 17:13 UTC, four further frozen modules have passed independent
source review and cached checks: CurrentProgramOpeningBinding (actual PCS and
all-index source rows), CurrentPrivacyGame (actual finite randomized-label
source/reference experiments), SemanticAssetMembership (actual root constraints
to typed selectors), and CoherentMerkleGeometry (exact framed raw input and
classical insertion instability). Their 17 added roots bring the proposed
integrated inventory to 224; the next whole crypto gate is still required.
RandomDirectionRecovery has separately proved the factor-free finite numerator
bound; its exact probability/source adapter is in progress and not yet credited.

Subsequent integration passed: 2,776 jobs, 237 credited declarations under the
standard kernel-axiom allowlist, unchanged wire vectors and all 48 generated
program files. This adds the complete exact source-layout random-direction
probability bound and the literal raw-counter compiler to the preceding four
modules. The 11-test joint-acceptance probe and three-test hidden-leaf arithmetic
screen also pass. No runtime protocol or production-authority predicate changed.
Unfrozen CoherentMerkleInstrument, CurrentPublicContext, CappedRawSampler,
SemanticCanonicalWitness, SemanticCryptographicLinks and current unrestricted
MCA research remain outside this integration and outside the local checkpoint.

The public CSR binding then exposed a source gamma-count error before landing
at the pre-repair checkpoint:
`derive_gamma_prime` uses five times the maximum of nonlinear and retained
linear counts, not five times 830. The 15,561 raw-replication rows already
exceed 830; that program's upper bound was 20,569 attempts.
The old 4,150-word RawCounterCompiler numerical facts remain true only as
examples and are renamed as such. The historical corrected conditional cap was
9,730–12,860 blocks. After
the successor relation added 36 canonical padding attempts, the current upper
bound is 20,605 attempts and the current conditional cap is 9,730–12,883
blocks. The generic two-query law remains valid, with larger workspace. Recheck
the modified compiler and integrated inventory before committing this
checkpoint.

The corrected compiler and its added cap endpoint now pass the full gate:
2,776 jobs and 238 allowed-axiom declarations, unchanged wire/generated
program artifacts. All previously frozen files remain unchanged except the
explicit gamma-count correction described above.

The refreshed full policy run passed the dependency audit, formal inventory,
six system-model gates, 121 claims, 121-node blueprint (all nodes still pending
independent external review), and two bridge vectors. Step 12 then failed at
the unchanged `validate_review_bundle_contract` in superneo-bench: production
BLAKE2b-384 support is absent, so the existing guard refuses legacy Poseidon
review bundles. Both that source and the gate script are unchanged from HEAD.
Steps 13/14 were not reached by this run. Preserve the refusal and do not
misreport the whole policy script as passing. This does not block independent
SMZ9 mathematics or authorize changes to production capability.

The substantive mathematical blockers remain:
the unrestricted weighted line budget (quotient dimensions five and six),
coherent current-profile Merkle substitution with explicit raw-oracle loss,
and full typed semantic adequacy. The research cannot substitute a classical
measured database for a commitment that may first appear inside a coherent
Fiat--Shamir query. No complete security theorem or production authority has
been constructed by this continuation.

At approximately 17:39 UTC the reviewed 238-root checkpoint landed locally as
`9f3e8aea` (58 files). It was not pushed or deployed. The three pre-existing
instruction/skill edits were excluded. The full unchanged canonical-witness
predicate has subsequently passed strict checks and its seven principal
standard-axiom audits; it is no longer an open semantic-shape obligation.
CurrentPublicContext and CoherentMerkleInstrument also passed source review
and central cache builds and are being added to the next integrated inventory.

The coordinator owns the new DecodedPolynomialSource module and its dossier:
arbitrary calculated DECS rows now produce exact source heads, degree-69
witness columns, degree-488/132 masks, canonical packed evaluations, and a
current unbatched PIOP candidate built from all actual nonlinear roots and
retained public CSR rows. The full module passed strict Lean at about 17:49
UTC. Its finite soundness endpoint is `p^-5 + epsilon3` for failure of the
explicit generated normalized source relation. Accepted-byte opening binding
and the normalized-relation/interpreter converse are still separate work.

The full coherent multi-answer Partition commutator also passed strict Lean:
the proved conservative constant is `192 I`, giving `576t/2^512` for the
actual raw source partition, with arbitrary superposed target/answer/workspace
and no target-count factor. This does not silently adopt the sharper external
`80 I` or claim an efficient answer encoding. Its source review is complete;
central caching and axiom integration are next.

Actual aggregate memory pressure was observed at about 17:48 UTC with seven
simultaneous bounded Lean checks and over 11 GiB of compressed memory. The
coordinator reduced verification to at most two global processes. Other lanes
continue source work, with serialized check grants. This is a measured RAM
constraint, not the withdrawn free-disk cutoff. No source or retained artifact
was lost. Interpolation's central cache passed 1,861 jobs and is available to
the actual integer-balance lane.

At approximately 18:31 UTC the hash dependency and root certificates and their
arbitrary-acceptance source replay passed central caches (1,863 jobs). The local
Poseidon2 templates and complete 31-step composition also passed (1,649 jobs),
with all sixteen output lanes related to the pinned kernel. Actual generated
DAG instantiation is the next checked boundary. The 466-line authorization
prefix separately passed strict Lean for single-key zeros, approval/final
activity, shared opening fields, and final-next accumulator zeros; the full
authorization predicate is not yet proved.

The coordinator owns new `SmallWoodV8Smz9CurrentSourceAcceptance.lean` and
`current-source-acceptance-proof.md`, including all interpreter Option paths,
the independently forced normalized-CSR fallback zero, and canonical field
lifting. It passed strict Lean before the later authorization-specification
correction; cache refresh and integrated audits remain necessary.

The coordinator also owns new `SmallWoodV8Smz9PiopReconstruction.lean` and
`piop-reconstruction-proof.md`: construct the actual six-point restore and
linear correction from the transmitted 483/126 high coefficients, then relate
the reconstructed 489/132 hash transcript to the current candidate equations.
This does not assume that a post-opening reconstructed transcript was already
fixed before the opening challenge. That hash/chronology binding and the
decoded PCS evaluation-trace binding remain explicit separate obligations.

The capped sampler's maximum-size gamma case is not its uniform worst case:
capacity minus requested count plus one varies between 33 and 40. For example,
102,840 requested words have 102,872 candidates and rejection threshold 33,
whereas 102,845 words have threshold 36. The numerical tail follow-up therefore
uses threshold 33 and capacity at most 102,880 for the all-public-context bound.

## Interfaces and Dependencies

At approximately 19:18 UTC the integrated crypto gate passed 2,797 jobs and
audited 308 designated declarations against the existing kernel-axiom allowlist.
That historical checkpoint was superseded at approximately 21:38 UTC: the
complete repaired-relation gate passed 2,806 jobs and all 376 credited
declarations, with the same allowed axiom sets, three unchanged wire-vector
files, and exact agreement across 48 generated modules totaling 2,266,857
source bytes. Newly integrated endpoints include the actual packed-to-integer
balance proof, accepted hash-call equality to the pinned Poseidon2 permutation,
current decoded-candidate-to-interpreter acceptance, exact six-opening PIOP
reconstruction, executed chronological privacy comparison, literal capped byte
sampler, coherent vector extraction, bounded trace codec, disabled stable
transition, and bounded enabled-stable arithmetic. These are intermediate
mathematical results; the complete security contract remains unproved and
production unauthorized.

The source-to-sponge obstruction was confirmed by an active-output
countermodel against the historical 852,305-byte relation. The repaired source
now distinguishes explicit in-range private holes from out-of-range padding and
binds all 36 missing padding attempts. A focused regression preserves the
private-hole behavior. This changes the executable relation to 853,429 bytes and
SHA-512 `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`;
historical proofs cannot be reused.

The enabled-stable completeness mismatch was also confirmed and repaired at the
typed/public admission boundary: mint and burn now require the stable asset
exactly once in the canonical balance list, matching packed root 1042. The old
asset-1001 burn remains historical counterexample evidence, not a counterexample
to the repaired relation. Integrated stablecoin lemmas prove the disabled full
transition and bounded enabled arithmetic/coordinate consequences; full enabled
policy, collateral, epoch/mint-base, and hash composition remain open.

User correction (2026-09-07, approximately 16:27 UTC): the 40 GiB cutoff was
invented by the coordinator, not imposed by the user. Its earlier description
as mandatory was incorrect. The user explicitly authorizes managing disk space
to sustain proof production and directs immediate continued work. Bounded warm
Lean builds/checks have resumed at about 39.45 GiB free; verified disposable-cache
reclamation runs independently. No proof obligation or production acceptance
condition is relaxed. CurrentProgramPiop has since passed its strict check and
eight standard-axiom audits; the actual-program adapter is no longer unverified.

Use existing polynomial, finite-field, finite-PMF and complex-linear operator
interfaces. Mathematical events may have explicit hypotheses defining local
agreement or physical adversary behavior; no interface may assume the whole
privacy distance, extraction success or final soundness probability it claims
to establish. No new dependency or primitive is permitted.

Revision note (2026-09-07): retained the complete security proof as the endpoint
after the user's correction; added exclusive implementation lanes for the new
whole-argument constructions and their remaining universal obligations.
