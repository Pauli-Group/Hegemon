# Qualify the native HTLC q58 mathematics

This ExecPlan is maintained under `.agent/PLANS.md`. It is an additive formal
qualification package, with an initial thirty-minute source and mathematics
budget beginning 2026-10-04 03:08 UTC.


## Purpose / Big Picture

The native hash-and-time-locked note relation has a much larger commitment
polynomial than RP05. A user must be able to distinguish checked new algebra,
arithmetic and byte-framing obligations from an actual accepted-proof security
theorem. The working result is a set of new Lean modules whose precise theorem
statements can be checked without modifying existing RP05 security receipts or
production authority. Hash-and-time-locked means that Claim consumes a private
SHA-256 preimage and Refund requires a public timeout to have elapsed.

The intended complete qualification would prove that accepting an invalid
native HTLC execution is rare and that the complete real proof can be simulated
from its public statement. This bounded milestone does not claim those final
properties until the accepted-wire, oracle and
whole-transcript bridges are proved.


## Progress

- [x] (2026-10-04 03:12Z) Inspect the source profile and existing generic decoder.
- [x] (2026-10-04 03:18Z) Check new exact degree9933/threshold327680 parameters and
  a parameterized response-universal matrix-event proof.
- [x] (2026-10-04 03:20Z) Construct and check the concrete nonzero Hasse table.
- [x] (2026-10-04 03:26Z) Check the sixty-coin commitment mask map in a delegated
  exclusive new file.
- [x] (2026-10-04 03:27Z) Check the conditional accepted-view decoder theorem and
  rational ledger; all seven new Lean files compile.
- [x] (2026-10-04 03:28Z) Check the exact 1987-byte leaf framing and namespace.
- [x] (2026-10-04 03:29Z) Record merged source identity and audit 74 new endpoint
  axioms; only standard propext, Classical.choice and Quot.sound occur.
- [x] (2026-10-04 04:29Z) Construct and compile the complete new response-universal
  line count, including Hasse/support vanishing and degree-9933 Newton.
- [x] (2026-10-04 04:32Z) Audit 91 new global-count theorem dependencies; only
  standard propext, Classical.choice and Quot.sound occur.
- [x] (2026-10-04 05:04Z) Compile `NativeHtlcQualifiedRecovery.lean`: join the
  proved count, exact finite matrix/sample densities, calculated whole-response
  decoder and rational ledger without a supplied `LineCountPremise`.
- [x] (2026-10-04 05:07Z) Compile adaptive selector/dispatch/history read-budget
  composition and audit all eleven new theorem dependencies; only standard
  propext, Classical.choice and Quot.sound occur.
- [x] (2026-10-04 21:11Z) Compile `NativeLaunchLeafNamespace.lean` and audit
  nine theorem dependencies. It recovers the complete RP06/HTLC 1192/576-byte
  preambles, proves statement-prefix injectivity and separates literal family
  frames. It does not establish semantic canonicality or accepted Rust leaves.
- [x] (2026-10-04 21:25Z) Compile `NativeLaunchCommitmentReadback.lean` and audit
  twelve theorem dependencies. It recovers the 64-byte digest, all five canonical
  coefficient rows and the complete statement under each imported branch layout.
  Later components below establish modeled calculated-response correspondence;
  authenticated source correspondence and chronology remain open.
- [x] (2026-10-04 21:53Z) Compile `NativeLaunchCommitmentResponseBinding.lean`
  and audit eight theorems. Literal complete commitment decoding yields the
  calculated restored response without a response-equality premise.
- [x] (2026-10-04 21:57Z) Compile `NativeLaunchFppHistoryBinding.lean` and audit
  nine theorems. Selected finite classical query provenance and relevant
  collision exclusion derive raw FPP equality through the two digest stages.
- [x] (2026-10-04 22:01Z) Compile `NativeLaunchFppResponseHistory.lean` and audit
  five theorems. The new selected-query support theorem derives response equality
  internally from those finite-history conditions and the complete decoder.
  Real-game selector timing, quantum history and source refinement remain open.
- [x] (2026-10-04 22:21Z) Compile `NativeLaunchLeafReadback.lean` and audit
  nine theorems. The complete parser recovers every literal leaf field; equality
  of complete raw frames yields statement, index, committed values, masks, salt
  and tape equality. Merkle authentication and actual source readback remain open.
- [x] (2026-10-04) Compile `NativeLaunchMerklePathBinding.lean` and audit
  nine theorems. Equal literal wrapper digests, recorded prior path inputs and
  finite relevant-collision exclusion derive complete raw leaf/field equality.
- [x] (2026-10-04) Compile `NativeLaunchCompactMerklePath.lean` and audit
  six theorems. Root-only executable reconstruction success produces complete
  ordinary paths, quotient progression and per-opening cursor exhaustion.
  Later components below construct original paths and compose native framing.
  Adversarial source selection and Rust refinement remain open; these
  deterministic results supply no QROM probability claim.
- [x] (2026-10-04) Compile `NativeLaunchOriginalMerkleTree.lean` and audit
  eleven theorems. Adjacent-pair reduction calculates the ordinary index route,
  complete tree root and finite input membership for unrestricted raw leaves.
- [x] (2026-10-04) Compile `NativeLaunchCompactMerkleBinding.lean` and audit
  six theorems. Both paths use index-derived directions; initialized compact
  reconstruction is composed with exact native node and wrapper framing.
- [x] (2026-10-04) Compile `NativeLaunchAuthenticatedReadback.lean` and audit
  four theorems. Wire-derived openings and a selected arbitrary canonical tree
  yield SourceReadback under wrapped-digest equality and finite collision
  exclusion. No desired cell equality or independent alignment is supplied.
  Adversarial original-source selection, actual history and Rust refinement
  remain open; the selected full-tree constructor is a conditional input.
- [x] (2026-10-04) Compile `NativeLaunchRecordedMerkleExtraction.lean` and
  audit ten theorems. Exact native stages extract canonical cells and masks
  pointwise from finite records at an arbitrary wrapped-root digest. Actual
  insertion-induced extraction changes imply a root-target or recorded-child
  hit; the exceptional output set has cardinality at most `1 + 2R`.
- [x] (2026-10-04) Compile `NativeLaunchRecordedOracleGraph.lean` and audit
  nine theorems. Full word-to-byte digest injection, literal constructor
  roundtrips and oracle-graph consistency derive valid-key selection under
  finite collision exclusion. Distribution transport remains open.
- [x] (2026-10-05) Compile `NativeLaunchRecordedPathReadback.lean` and audit
  thirteen theorems. Recorded ordinary paths recover complete leaves without
  a full original tree; compact recovery remains per selected augmentation.
- [x] (2026-10-05) Compile `NativeLaunchRecordedSourceStability.lean` and audit
  nine theorems. A real completed-readback change identifies a fresh insertion
  in an oracle-history prefix and a target or preceding-child hit.
- [x] (2026-10-05) Compile `NativeLaunchRecordedWireReadback.lean` and audit
  three theorems. One constructed graph, salt, statement, context and wrapped
  target derive complete SourceReadback for the whole typed wire.
- [x] (2026-10-05) Compile `NativeLaunchFrozenRecordedSource.lean` and audit
  five theorems. Compact acceptance derives earlier-only whole-wire readback
  or a finite relevant collision or actual completed-readback change.
- [x] (2026-10-05) Compile `NativeLaunchPrefixFppSelector.lean` and audit
  fourteen theorems. Finite ordered selection derives the recorded FPP chain,
  response equality or concrete late-key events, with checked prefix locality.
- [x] (2026-10-05) Compile `NativeLaunchDerivedDecsFailureCover.lean` and
  audit seven theorems. Internally derived source/response binding yields DECS
  support and actual decoder-none covers with five concrete exceptional events.
- [x] (2026-10-05) Compile `NativeLaunchGuardedPointGeometry.lean` and audit
  eight theorems. Source-shaped nonzero-shift and adjacent strict-order guards
  derive global point and typed sampled-point injection without supplied
  injectivity. Native search existence and Rust refinement remain open;
  conditional interpolation disjointness is checked below.
- [x] (2026-10-05) Compile `NativeLaunchGuardedDecsFailureCover.lean` and
  audit five theorems. Internally constructed native points and executable
  guards discharge both DECS injection premises for the same accepted instance.
- [x] (2026-10-05) Compile `NativeLaunchGuardedCosetSelection.lean` and
  audit fourteen theorems. Accepted field-level candidate checks derive full
  interpolation disjointness; a successful bounded selector inherits it.
  Search existence and actual Rust descriptor refinement remain open.
- [x] (2026-10-05) Compile `NativeLaunchFirstQueryFreeze.lean` and audit
  nine theorems. The adaptive Program stops before its first matching answer;
  actual earlier-key agreement preserves its complete stopped result.
- [x] (2026-10-05 02:29Z) Compile `NativeLaunchOnlinePrefixLedger.lean` and
  audit eight theorems. A fixed raw parser captures actual first-prefix entries
  before answering, derives first-stop certificates and preserves full records.
- [x] (2026-10-05 02:35Z) Compile `NativeLaunchRootPrefixSelector.lean` and
  audit fourteen theorems. Literal trigger bytes and earlier recorded pairs
  select typed root context or yield an actual collision/late-wrapper cover.
- [x] (2026-10-05 02:43Z) Compile `NativeLaunchOnlineRootPrefixCover.lean` and
  audit four theorems. Actual ledger membership derives the fixed root snapshot,
  prior-key-only replay and the exact any-counter DECS-matrix prefix internally.
- [x] (2026-10-05 03:07Z) Compile `NativeLaunchOnlineFppPrefixCover.lean`
  and audit six theorems. Nonce-aware successful parsing, pair-only chain
  selection provenance and actual-entry replay/prefix identity are checked.
  Parser roundtrip and accepted-prefix availability remain open; later
  components below check the key/response comparison cover.
- [x] (2026-10-05 03:22Z) Compile `NativeLaunchOnlineFppComparisonCover.lean`
  and audit four theorems. Actual entry membership derives key selection or
  concrete finite collision, late-final or late-FPP events, without supplied
  successful selection, prior membership or coherence.
- [x] (2026-10-05 03:25Z) Compile `NativeLaunchOnlineFppResponseFreeze.lean`
  and audit two theorems. The complete branch-indexed response function is
  frozen from earlier pairs/input; calculated-response comparison and the
  same three actual events are derived internally under explicit
  parse/family/tail/hash premises.
- [ ] Prove actual accepted native execution supplies these parsed prefix
  entries; extract source, construct separate DECS-opening snapshots and refine
  all three stages to Rust. Prove current-family accepted false-relation
  coverage. Generic root freezing and nonce-aware response freezing/comparison
  are checked; full native selection/security is not established.
- [ ] Prove accepted-execution quantum transport for the actual source and
  response view; the line count alone does not establish this bridge.
- [ ] Prove complete initialized adaptive real-versus-public-simulator privacy
  for the new namespace; component bijectivity alone is insufficient.


## Context and Orientation

The implementation is `circuits/transaction/src/smallwood_engine.rs` and the
native HTLC frontend is `circuits/transaction/src/smallwood_htlc.rs` together
with its `circuit.rs` and `sha256.rs` submodules. These are modified by other
workers. This package owns only new `NativeHtlc*` files under
`formal/crypto/HegemonCrypto` and the Std-only leaf file under
`formal/lean/Hegemon/Crypto`. The research package is deliberately not imported
into the production Lean library.

For Claim, the new profile has19731 witness rows, degree2 constraints, six
polynomial openings, five mixing rows,140 stacked data rows,9876 stacked
columns, an8388608-point domain and58 final queries. A commitment polynomial
can have degree9933, so reconstruction needs9934 distinct evaluation points.
The analysis support threshold is327680, with interpolation multiplicity5,
weighted bound1638400,165 powers of the second variable and third-variable
bound10000. Those choices supply1351996034070 unknown coefficients and
1258123427840 homogeneous equations.

A response-universal event quantifies over every bounded response chosen
after the mixing matrix. Its proof must not substitute a fixed-response union
bound. The new line-count target is12548540024940 labels, giving a candidate
matrix loss140 times that count divided by the field size to the fifth power.
Goldilocks has18446744069414584321 elements. The exact same source table and
response selector must be bound to the accepted wire and oracle execution.

The source snapshot for this analysis is coordinator commit
`02753cdd9edfb465e7008999005b92551e2c4ba2`, whose shared engine SHA-256 is
`c59e20da61e63b9f3dd2e41da0921df9ef8abd98bbc22bb5dad0ce54ae127193`.
The HTLC relation identity independently computed by concatenating exactly
`relation_digest()`'s source inputs is
`f894a5b6d368e3fafc1d0fe2c9482e09a0b1e928a74f98b7613c8dbfa01a7456d18014c93dd8d608e0aaa3acef1dc57c049e5d1690095b496535abaa5111f6a0`.
This is a source calculation awaiting agreement with the coordinator's actual
proof receipt, not a newly generated proof or release receipt. The formal
worktree itself intentionally contains no engine edits; merge these additive
files into the stated source snapshot before attributing them to that candidate.


## Milestones

First construct the new parameter arithmetic and finite Hasse matrix. Compile
`NativeHtlcParameters.lean` and `NativeHtlcInterpolation.lean`. Their observable
result is an existence theorem for a nonzero solution of every actual matrix,
not merely a satisfiable inequality.

Second reuse only degree-generic recovery machinery. Compile
`NativeHtlcUniversalMatrix.lean` and `NativeHtlcRecovery.lean`. The result is a
calculated polynomial candidate which equals the full response, or an explicit
exceptional matrix/small-support event. The parser/source binding is a visible
hypothesis. The line-count proposition is named `LineCountPremise`; it is not
an axiom. The subsequent `NativeHtlcGlobalCount.line_count_premise` now
establishes it for every injective Goldilocks evaluation domain.

Third check the changed privacy components. The two width-two commitment
families have six random coefficients per family and five rows, hence60 coins.
The actual exposed correction is minus r to the power delta times a degree-five
random polynomial, with delta59 for nonlinear and delta1 for linear masks.
The leaf serializer uses profile52 bytes, leaf domain47 bytes, three8-byte
lengths, a576-byte public statement,32-byte salt,8-byte index,64-byte tape,
1176-byte payload and8-byte counter: tape starts at739 and total raw size1987.
These are component obligations. A complete adaptive public simulator requires
additional source/coin/oracle scheduling proofs.

Fourth build a new rational ledger. Check the exact local expression
140B/p^5+(327679 falling58)/(8388608 falling58)+1/p^5+
(138 falling6)/((p-64 falling6)-414p^5)+
12(9933 falling58)/(8388608 falling58).
Here falling q means multiplication of q successive decreasing factors.
Only after separate event-density and oracle-transport proofs can the resulting
134-bit fresh-transport arithmetic bound be interpreted as accepted-proof
security.


## Concrete Steps and Validation

Use Lean4.32.2 and the pinned mathlib revision in
`formal/crypto/lake-manifest.json`. Reuse the existing compatible compiled
objects, without writing shared build caches. The scratch output directory is
`/private/tmp/native-htlc-formal-20261004`.

From `formal/crypto`, `lake env printenv LEAN_PATH` gives the required dependency
paths. Prefix that path with the scratch directory and compile each new module
with `lean -o /private/tmp/native-htlc-formal-20261004/HegemonCrypto/NAME.olean
HegemonCrypto/NAME.lean`. Since Lean selects a namespace directory as a whole,
the scratch `HegemonCrypto` directory contains read-only symlinks to existing
generic compiled dependencies and ordinary files for these new objects.
Compile dependencies before their users. The Std-only leaf file needs no
mathlib path.

In a normal configured checkout, from `formal/crypto`, the corresponding
reproduction command is:

    lake build HegemonCrypto.NativeHtlcParameters HegemonCrypto.NativeHtlcInterpolation HegemonCrypto.NativeHtlcUniversalMatrix HegemonCrypto.NativeHtlcRecovery HegemonCrypto.NativeHtlcLedger HegemonCrypto.NativeHtlcPcs

From `formal/lean`, run:

    lean Hegemon/Crypto/NativeHtlcLeaf.lean

Print `#print axioms` for every exported new theorem in a scratch audit module.
Expected primitive dependencies are only standard `propext`,
`Classical.choice` and `Quot.sound`, with none depending on `sorryAx` or a new
custom axiom. Arithmetic is checked by kernel-valid tactics, not presented as
an extraction theorem. Record failures honestly and repair within scope.

No Rust build, node launch, proof generation, deployment, existing receipt
edit, or activation change is part of this worker. The coordinator performs
fresh proof and lifecycle qualification against the final merged source.

The second phase additionally compiles fifteen `NativeHtlcGlobal*.lean`
modules. Their dependency order is Local, Support, Polynomial, Heights,
Independent, Partition, Weights, Newton, Numerator, Nonaffine, Position,
Descent, Branch, Assembly and Count. Prefix each name with
`HegemonCrypto.NativeHtlcGlobal`. The first six original research modules
must already be compiled. These new modules import the checked generic
polynomial machinery from `formal/rp05/generated/Sources`, so append
`formal/rp05/build/lib/lean` to the compiler search path after verifying that
package's source/build state with its documented `rp05_proof_package.py`
workflow. Importing that generic machinery does not invoke an old
degree-405 counting endpoint.

For each new module, the exact compiler form used is:

    LEAN_PATH="$task_lean_path" lean -DwarningAsError=true -o "$task_scratch/HegemonCrypto/NativeHtlcGlobalNAME.olean" HegemonCrypto/NativeHtlcGlobalNAME.lean

Here `task_lean_path` contains the isolated output namespace, the checked RP05
object root and the locked Lake dependency paths, in that order. The isolated
namespace reuses unchanged HegemonCrypto objects through read-only symlinks,
as described above. The new files do not alter the retained RP05 package,
source manifest, build state or old endpoint declarations. Numeric recursion
limits are raised locally where the new exponent19865 needs them; no
unchecked arithmetic tactic or custom axiom is introduced.

The final endpoint is
`NativeHtlcGlobalCount.universal_badLineLabels_327680`. Its only geometric
premise is injectivity of the supplied8388608-point Goldilocks evaluation map.
Its prior five rows and direction are arbitrary. The theorem
`line_count_premise` discharges the previously named recovery premise, and
`matrix_card_bound` joins it to the140-row matrix event without adding a
count premise. `NativeHtlcGlobalAssembly.actual_global_incidence_label_count`
proves the sharper intermediate count1732044224939; the final endpoint
weakens it to12548540024940 for the existing ledger.

The combined audit file is
`/private/tmp/native-htlc-formal-20261004/GlobalAudit.lean`; its successful
log is `global-audit.log` in the same directory. It prints91 actual theorem
dependencies with exactly propext, Classical.choice and Quot.sound, without
errors or sorryAx. `global-source-hashes.json` records the fifteen source
hashes. These are local mathematical validation artifacts, not release
authorization receipts.


## Surprises & Discoveries

The previous degree405/multiplicity5 line-count theorem is not generic in the
degree. Its global incidence and Newton recursion layers contain specialized
constants, so replacing a geometry tuple cannot transfer that theorem.
A new interpolation surplus is necessary but does not by itself prove the
new global count.

The HTLC relation identity includes implementation source, so merging another
profile into the shared engine changes that identity. Proof artifacts must be
regenerated after the coordinator freezes the complete source.

The smallest remaining counting route can avoid the old residual-root
partition. Generalize the current short incidence assembly around arbitrary
degree D and an actual nonzero trivariate source polynomial F. Its generic
Newton adapter needs D+1 at most 2 to the power steps; here steps14 suffices.
The denominator exponent is 2D-1 = 19865. The existing generic full-Hensel
numerator, localized incidence, affine descent and column-count lemmas can then
support a global bound
Z+2YZ+nY+floor(n(2(2D-1)YZ+Y)/(threshold-D)). Its numeric value is
1732044224939, below the explicit conservative budget12548540024940.
The second implementation phase closed the Hasse-table-to-polynomial,
arbitrary-support vanishing, Newton and global-incidence bridges in the new
`NativeHtlcGlobal*.lean` modules. Reused generic machinery is found in
`Mca38LocalizedResponseTracking.lean`,
`Mca38FullNumeratorEndpoint.lean`, `Mca38GlobalIncidenceAssembly.lean` and
`Mca38RbrGlobalMultiplicity.lean` under `formal/rp05/generated/Sources`.

RP06 has 686 witness rows, while its DECS polynomial degree is still405:
the witness/nonlinear/linear degrees69/488/132 have widths1/8/2, yielding736
unstacked columns and368 stacked columns; 368+38-1=405. Its q38 arithmetic
therefore retains the old geometric count, subject to new accepted-source and
namespace binding. Direct exact rational recomputation gives local loss about
2^-265.882957455 and fresh/ordinary scalar losses about2^-131.128069953 and
2^-132.128069953 at T=3*2^64. No numeric query increase follows from the changed
program alone. Its new149-word preamble instead changes leaf raw size to2591
and tape offset to1343, so the old2511 namespace does not apply.

Neither candidate inherits a proof lifetime. A naive union of full
maximum-query per-proof bounds yields strict128 arithmetic ceilings of only
8 fresh/17 ordinary RP06 proofs and77 fresh/155 ordinary HTLC proofs, before
additional losses. Useful larger lifetimes require the actual shared-query,
multi-statement reduction and complete exposure budget. None of these numbers
is a qualified production cap. They also are not an impossibility result: the
existing RP05 history theorem already demonstrates a genuine single-query-budget
approach for its narrower game, as described below.

## Qualified recovery and the remaining global game

`NativeHtlcQualifiedRecovery.accepted_execution_qualified_endpoint` constructs
both a `QualifiedView` and the calculated recovery/event partition. The finite
matrix density is the cardinality of the response-universal exceptional set
divided by the cardinality of all 140-by-5 matrices. The fresh sample density is
the failed-query-set cardinality divided by `choose(8388608,58)` and is bounded
by `falling(327679,58)/falling(8388608,58)`. Its response selector can depend
arbitrarily on the matrix. `matrix_density_uniform_over_prefixes` quantifies
over arbitrary preceding data. No line-count, support-vanishing or factor-count
premise is supplied. The remaining premises are an injective evaluation map,
one complete source/response view fixed before the final query, and the exact
binding of accepted wire continuations and queries to that view. The PIOP,
PCS and physical-oracle transport is still separate; the ledger fields are
rational inequalities, not asserted execution probabilities. Applying the
uniform matrix density to the actual execution also requires the source words
to be fixed before its matrix draw. Fixing the view before the final query
does not alone establish that earlier commitment chronology.

There is an actual shared-query endpoint in
`formal/rp05/generated/Sources/SmzaRp05CurrentHistoryExtractionFailureEndpoint.lean`:
`actual_accepted_history_extraction_failure_mass_below_130_bits`. It sums the
original physical branches' Born weights for any accepted extraction failure
in a history, and charges `queries + readBudget(historyProgram stages)` once.
It neither multiplies a full per-proof bound by the number of transactions nor
accepts a supplied event-inclusion/probability conclusion. However,
`HistoryStage` in `SmzaRp05CurrentHistoryVerifierProgram.lean` fixes each stage's
namespace, statement, pending flag and nonce outside the adaptive proof
producer. The endpoint requires a common namespace and the fixed current RP05
DSL and parsed 120-word statement. It is not a mixed RP06/HTLC theorem and
does not permit adaptive selection of those fixed metadata fields.

`SmallWoodHeterogeneousCmsQrom.indexed_ideal_logical_qrom_failure_probability_le`
is another genuine shared-query theorem: a single run of database-independent
contractions, a final adaptive statement selector, and one total query count.
Its profile is the older five-opening/q23/138-row relation and its oracle is a
stronger product-output logical oracle. It supplies neither the physical
SHA-512 reduction nor the changed candidate parameters. The similarly named
SMZ9 deployed finite-accounting receipt also retains explicit event-reduction
and quantitative premises; its name does not discharge those premises.

The exact missing changed-family statement is a theorem over one normalized,
initially empty physical-oracle game whose answer-adaptive source program
produces a tagged tuple of family, full network/program identity, statement,
parent context, flags/nonce and complete proof field view. A verifier dispatcher
must parse that tuple using the actual frozen SMZB or SMZC source and select the
corresponding formal relation. For every such adversary/program, the sum of the
original branch masses in which any accepted tuple fails that relation must be
bounded by the derived shared-query expression, below the desired release
threshold. The proof must derive event coverage and role densities uniformly
over all reachable metadata and families. Neither a supplied probability bound,
a per-proof union, nor an old common-namespace theorem is that statement.

The shared budget for that theorem must account for the following exposures:

| Exposure | Required accounting |
| --- | --- |
| Adversarial SHA-512 access | One total count of quantum queries, including earlier interactions correlated with the same oracle. |
| Honest proof production and publication | All oracle-dependent generation and exposed prior views must be represented in the game; arbitrary initial workspace does not justify omitting their queries. |
| Source verifier/extractor reads | Worst-case answer-adaptive reads, including failed branches, rejection sampling, raw counters and every family dispatch. |
| Multiple proofs, blocks and epochs | A single declared domain of accounting, with enforced limits and an explicit transition rule; restarting a process does not reset oracle history. |
| Namespace and raw-input grouping | Exact new transcript/leaf serializers and role separation, or an explicit overlap loss, for both families. |
| Other primitives | Explicit security assumptions and losses for the actual Poseidon2, SHA-256, signature and encryption roles; they cannot silently be charged as independent ideal SHA-512 outputs. |

This is distinct from the whole-public-view simulator obligation. A knowledge
failure mass bound alone does not establish zero knowledge.

`NativeLaunchGlobalQueryReadBudget.lean` contributes a structural accounting
step for that future game. `readBudget_bind_le` proves that an answer-adaptive
selector followed by any uniformly bounded continuation uses at most the sum
of their worst-path read budgets. `readBudget_select_dispatch_le` permits the
selector's result to carry arbitrary family and public metadata, and
`readBudget_adaptiveHistory_le` sums the stage budgets of a state-dependent
history. Failed branches are included. These are actual `Program` recursion
theorems, with no fixed proof geometry or predefined metadata list. Their
continuation/stage bounds must still be established for the frozen dispatcher;
the lemmas do not supply event coverage or a quantum failure bound.


## Decision Log

At 2026-10-04 04:11Z the coordinator authorized a further thirty-minute
implementation budget for the actual degree-9933 global counting proof.
This phase owns only new `NativeHtlcGlobal*.lean` modules and this document.
It reconstructs the Hasse, support, factor and incidence chain for the new
parameters. It does not apply the old specialized degree-405 endpoint.

## Minimal changed-candidate evidence contract

The contract was reviewed against coordinator revision
`d5a0b80f9bef292e16ceba214692c44333c30eef`. The following six items are
separate obligations; a receipt naming one does not establish another.

1. Freeze the exact source and capability identity: full chain ID, genesis and
   manifest, relation digest and generated relation program, parser and public
   projection, profile/transcript domains, source inventory, verifier binary,
   activation interval, proof/action byte limits and lifetime limits. RP06 and
   HTLC have separate identities. The shared engine participates in the HTLC
   relation digest, so proof receipts must agree with its final frozen bytes.
2. Establish the intended relation and actual accepted-source bridge. The
   generated CSR and nonlinear constraints must implement their stated
   authorization, conservation, network and SHA-256/time-lock predicates.
   The production parser/verifier must supply exactly the source table,
   response selector, commitment chronology and accepted query used by the
   mathematical endpoint. This is a scoped interface for these exact sources,
   not a universal Rust, compiler or operating-system theorem. Host-bypass
   malicious-witness and parser vectors are finite conformance evidence;
   they do not by themselves prove that interface for all accepted bytes.
3. Complete composed knowledge soundness. The degree-9933 line count,
   calculated decoder and event densities must join actual accepted
   executions through the PIOP/PCS and Fiat-Shamir/QROM transport. RP06 keeps
   degree405 geometry, but still needs its changed program and namespace
   binding. Primitive assumptions stay explicit; construction-specific
   premises cannot be replaced with positive JSON flags.
4. Complete public simulation and lifetime composition. Prove a simulator
   for the entire initialized adaptive public proof view, including opened
   values, response polynomials, leaves, paths, salts/tapes and all oracle
   programming, under the new SMZB/SMZC framing. The sixty-coin bijection and
   1987-byte HTLC leaf are components. Separately derive a shared global-query,
   multi-statement bound covering both proof kinds and every cryptographic
   role/exposure. The existing rational ledger does not supply that theorem,
   and the historical proof-lifetime constant cannot be inherited.
5. Retain at least two independently generated proofs for the frozen identity,
   public-only verification and mutation reports, and the same complete bytes
   through wallet, RPC, relay, mempool, mining, block import, restart, reorg and
   fresh-node validation. Include all changed relation branches and the actual
   size/resource measurements. Lifecycle tests must use authenticated contexts
   and ciphertexts; a standalone proof fixture is not that integration result.
6. Bind the evidence to source-owned executable checks, independent review and
   release authority. The current successor checker pins old RP05 paths and
   formal endpoint names, so these candidates need a profile-specific adapter.
   At the reviewed revision its executable-evidence command inventory, review
   trust roots, hermetic release roots and authorized profile registry are
   empty. The launch capability registry is also empty. The adapter must run
   the exact checks, bind their outputs and review to the same source,
   capability and retained proof digests, and then obtain the separate reviewed
   source authorization. This package neither populates those registries nor
   treats manifests as authority.

At2026-10-04 03:08Z the coordinator authorized new dedicated mathematical files
and an initial thirty-minute budget. Existing RP05 receipts and authority stay
historical. At03:18Z the degree-generic event proof was copied into a new namespace
while the degree-specific global count was exposed as a proposition to prove.
This preserves an honest boundary without importing a degree405 endpoint.
At03:26Z the commitment mask worker completed a generic field bijection and its
actual delta59/delta1 specializations.


## Outcomes & Retrospective

The bounded implementation milestone completed seven Lean files: parameters,
actual interpolation matrix, generic matrix events, calculated decoder,
rational ledger, PCS mask bijection and exact leaf framing. Six research modules
and one Std-only module compile with Lean4.32.2. The audit printed dependencies
for51 crypto and23 leaf endpoints. Their union is exactly the standard Lean
axioms propext, Classical.choice and Quot.sound; no sorry or custom axiom occurs.
The crypto and leaf audit logs are retained in the scratch output directory.

The original interpolation theorem proves a nonzero coefficient table for every
supplied matrix. The new global modules additionally construct the nonzero
trivariate polynomial and prove selected-support vanishing and the new global
line count. The decoder theorem proves recovery of
the entire bounded response from the calculated9934-point interpolant, or the
explicit matrix/small-support event, under a fixed-whole-view binding. It does
not extract that view from a quantum commitment. The exact rational ledger
proves local loss below2^-269 and the proposed fresh transport below2^-134;
the missing accepted-execution and quantum transport premises prevent interpreting it as
unconditional accepted-invalid security.

The PCS theorem proves the actual delta59/delta1 sixty-coin bijection, and the
leaf theorem proves framing, tape injection and a disjoint raw-input partition.
Neither is a complete adaptive simulator. Accepted-wire/QROM
transport, complete initialized public simulation, authorization/conservation
binding for the changed relation, primitive assumptions and production release
authority remain independent obligations. No existing receipt or activation
file was changed.

The later qualified-recovery milestone adds two files and eleven checked
theorems. Both final sources compile with Lean4.32.2 and warnings as errors.
Recovery audits and final source SHA-256 values are retained under
`/private/tmp/native-htlc-qualified-20261004/`; the source-read compile command,
toolchain, source hash and audit are in
`/private/tmp/native-launch-query-20261004/result.json` and `audit.log`.
All theorem dependency audits contain only propext, Classical.choice and
Quot.sound. No new axiom, sorry, native-decide certificate, registry entry,
historical receipt or execution-probability premise was added.

## Mixed-family physical-oracle embedding, 2026-10-04 05:30Z

This bounded phase reviewed coordinator source
`7fae2698ce70a74a40062ed5dd77a865ab47327c`. Its shared engine SHA-256 remains
`c59e20da61e63b9f3dd2e41da0921df9ef8abd98bbc22bb5dad0ce54ae127193`.
The phase owns only new `NativeLaunchAdaptiveHistory*.lean` modules and this
appended report. Its result is an exact input-model and oracle-query coupling,
not a mixed-family accepted-failure theorem.

`NativeLaunchAdaptiveHistoryCodec.lean` defines the actual two family tags and
four challenge roles. It proves roundtrip and injectivity of the literal
source bytes

    LE64(profile.len) || profile || LE64(role.len) || role ||
    LE64(words.len) || LE64(word_0) || ... || LE64(counter).

Its seven domain byte lists were compared directly with the pinned Rust
constants. The profile strings are the 45-byte
`hegemon.smallwood.rp06.smzb.sha512.profile.v1` and the 52-byte
`hegemon.smallwood.native-htlc.smzc.sha512.profile.v1`. Three challenge roles
share their level5 role spelling while the profile frame separates families.
The HTLC final-sample role is the distinct 57-byte
`hegemon.smallwood.native-htlc.smzc.decs-fixed-sampling.v1`; RP06 uses the
44-byte `hegemon.smallwood.level5.decs-fixed-sampling` role. Typed u64 words,
length frames and counters are retained, rather than normalized to an old
profile. These literal definitions match
`concrete_smallwood_sha512_oracle_query_v1` in the engine; the proof does not
claim that arbitrary payload words form an accepted transcript.

`NativeLaunchAdaptiveHistoryOracle.lean` constructs an injective common raw
address map from that codec. All other raw bytes, including nonchallenge roles,
malformed frames and out-of-cap counters, remain live complement inputs. It
proves a complete table factorization, the exact uniform raw law on every
finite query universe, and coherent two-vector-query simulation for arbitrary
superpositions and workspace. There is one physical oracle, including for
superposed family tags. There is no family or transaction multiplier in these
identities. The source replay result preserves the complete ordered read log
and result, including repeats and failed runs. The generic source program's
ex-ante support includes every possible digest reply, so a single universe can
cover all adaptive family/metadata choices of that whole program; it must not
be selected or changed after observing a proof. This does not synthesize the
missing actual native verifier program.

The grouping uses the enforced field-XOF output ceiling `2^24`, giving
`ceil((2^24+32)/8)=2097156` blocks. The smaller observed HTLC Claim maximum
5018970 requested words gives 627376 blocks, but the engine's SMZC profile
guard checks K64/degree2/profile/domain rather than a universal CSR-row cap.
Consequently this phase does not use the retained geometry as an unproved
universal routing bound. The engine's request ceiling is checked before hash
calls; the new finite arithmetic proves that every request below it fits.

| Challenge | Declared candidate request | Blocks per request |
| --- | ---: | ---: |
| DECS matrix, both families | 700 field words | 92 |
| RP06 PIOP matrix, reported maximum | 102940 field words | 12872 |
| HTLC Claim PIOP matrix, retained geometry | 5018970 field words | 627376 |
| PIOP opening, one nonce | 6 field words | 5 |
| RP06 fixed DECS sample | 50 candidates | 11 |
| HTLC fixed DECS sample | 80 candidates | 14 |

Repeated queries are still charged. In particular, finding the first valid
opening nonce, comparing the supplied nonce, then reissuing its XOF can read
one nonce twice: the
bounded search has at most sixteen distinct nonce prefixes but can perform
seventeen requests, hence eighty-five physical block reads rather than eighty.
A finite oracle address universe records distinct keys; it is not the query
budget. The chronology to establish remains root, DECS matrix, FPP, PIOP
matrix, final PIOP, opening challenge, DECS-opening digest, fixed DECS sample.
The verifier can reconstruct/check that chain while issuing its reads in a
different order, so verifier read order alone is not a commitment chronology
proof.

The old shared-query theorem cannot currently be instantiated for these
families. The smallest concrete dependency frontier is:

1. `SmzaRp05LeafNamespace.lean` fixes 1104 preamble bytes and the old v2 leaf
   namespace. `NativeLaunchLeafNamespace.lean` now checks complete RP06/HTLC
   1192/576-byte prefix recovery, statement-prefix injectivity and literal family
   separation. `NativeLaunchLeafReadback.lean` now decodes the complete suffix,
   checks the index range, both count words, every canonical field value and exact
   exhaustion, and recovers all literal fields. Authentication must still be
   connected to the actual salted root wrapper and compact Merkle reconstruction.
   `NativeLaunchMerklePathBinding.lean` now derives complete leaf equality from
   equal wrapped digests, explicit prior input membership, shared ordinary-path
   directions and finite relevant-collision exclusion.
   `NativeLaunchCompactMerklePath.lean` constructs expanded paths from executable
   reconstruction success with separate original-opening cursors.
   `NativeLaunchCompactMerkleBinding.lean` now composes exact native framing and
   the index-derived ordinary routes. `NativeLaunchOriginalMerkleTree.lean`
   calculates the original paths and finite input list for a general full tree.
   `NativeLaunchAuthenticatedReadback.lean` derives SourceReadback for wire-derived
   openings against a selected arbitrary canonical full tree, without supplied
   source-cell equality or independent index/hash alignment. Real adversarial
   tree selection/existence, observed history, complete accepted-failure coverage,
   semantic statement validation, input parsing and Rust refinement remain open.
   These conditional components do not instantiate the historical security type.
2. `SmzaRp05FilteredReadback.lean` fixes old commitment payload lengths,
   including FPP's 2030 coefficients and binding offset 16304. The new
   `NativeLaunchCommitmentReadback.lean` parses the complete 64-byte digest,
   coefficient lists and trailing statements. RP06 keeps 2030 coefficients and
   offset 16304 but has a 1192-byte statement. HTLC Lock/Refund use 10600
   coefficients and offset 84864; Claim uses 49670 and offset 397424, both with
   576-byte statements. Lock/Refund correctly share a parser.
   `NativeLaunchCommitmentResponseBinding.lean` now constructs the five canonical
   rows from modeled restoration and proves that complete decoding gives the
   calculated bounded response. `NativeLaunchFppHistoryBinding.lean` derives raw
   FPP equality through both hash stages under finite recorded-query provenance
   and collision exclusion. `NativeLaunchFppResponseHistory.lean` joins those
   calculations to selected DECS query support, without a supplied response
   equality. These are conditional classical-history components. Graph-generated
   geometry, actual Rust restoration/final-tail correspondence, real-game
   provenance and authenticated commitment chronology remain external obligations.
3. `SmzaRp05RelationModelCore.lean` already permits a variable PIOP width,
   but its statement domain and recovered rows remain the old q38 types. A
   family-indexed replacement needs the actual generated candidate constructors
   and checked relation binding, not a supplied positive correctness flag.
4. `SmzaRp05CurrentTracePrefixes406.lean` fixes the 406-point decoder,
   degree405 responses and q38 query type. HTLC requires its 9934-point decoder,
   degree9933 responses and q58 query type, bound to the complete new source
   view and earlier challenge table.
5. `SmzaRp05Current406EventSpec.lean` embeds those old events and role losses.
   A new family-indexed event must prove instability under the same physical
   oracle and cover every actual accepted failure on the original branches.
   `SmzaRp05CurrentHistoryVerifierProgram.lean` must then replace its fixed
   metadata/current-DSL stage with the actual adaptive tagged dispatcher.

The generic CMS kernel and `SmzaRp05ActualEventRecertification` query-counted
transport can be reused once the new event's instability, initialization and
accepted-failure coverage are constructed. The intended bound uses one total
query count and a uniform bound across selected families. Passing the finite
HTLC matrix density or the new byte coupling as an `EventSpec` premise would
leave precisely those construction obligations unproved; it would not close
the actual shared-Q game. No such premise wrapper or new claimed failure-mass
endpoint was introduced. Public simulation is an additional outstanding
obligation and is not implied by this oracle-input coupling.

Separate `declaredProfileBlocks` and injective `profileCounterRoute` definitions
retain the candidate-specific role sets inside this same oracle: RP06's largest
declared request uses 12872 blocks and HTLC Claim's uses 627376, with the smaller
role sets shown above. Their exact accepted-source geometry conformance remains
to be proved; the route definitions do not assert it. They discard no other
raw queries. The eventual family-dependent event law and global query ledger
must use the proved per-family bounds and actual exposure schedule. Neither
the generic 2097156-block embedding nor this coupling inherits the earlier
131/134-bit arithmetic as a shared-Q security result; that ledger must be
recomputed after the actual event/transport is instantiated.

Both final new files compile with Lean4.32.2 and warnings as errors. The
combined audit prints twenty-nine theorem dependencies and contains only
propext, Classical.choice and Quot.sound. The exact source-domain comparison,
commands, source hashes and combined audit are retained in
`/private/tmp/native-launch-adaptive-history-20261004/`. No engine source,
historical formal endpoint, authorized registry or release receipt changed.


## Complete codec component evidence (2026-10-04 21:25Z)

The leaf component was integrated as `dd5e50cf031567f1d52a3422fa1c5c86c158a281`;
the complete commitment codec was integrated as
`67a5de1165179e841240d722f2b3410d3479284a`. Both retain identical circuits, node
and protocol bytes to frozen `185a132b821ad319a49f4a8746c6110ea7ba0476`, so they
do not change the running development rehearsal or its proof identity. The
leaf compile/audit measured 2.933/2.018 seconds and 2594078720/2553036800 bytes
peak process-tree RSS. The commitment compile/audit measured 3.133/2.028 seconds
and 2683764736/2624372736 bytes. Both used warnings as errors and a serial
120-second/4-GiB lane; theorem dependencies contain only propext, Classical.choice
and Quot.sound. Exact commands, source comparisons and measured receipts remain
in `/private/tmp/native-launch-leaf-namespace-20261004` and
`/private/tmp/native-launch-commitment-readback-20261004`. These are directly checked
components using retained dependency outputs, not a completed aggregate formal CI
or accepted-security endpoint. The commitment injectivity theorem concludes
coefficient-list and statement equality; it does not assert equality of the full
Commitment structure or root functions. All eight production qualification gates
remain open.


## Calculated FPP and finite-history correspondence (2026-10-04 22:01Z)

The three new components are integrated as `ed3417d7e6609a58d785eed45c559465129b0a61`,
`b00b277ec81d2b59d089519b22939284cd0e9797` and
`a5b8fc03ff129fcbc338c0b3eb0af036a9eaa7c8`. Their final Lean SHA-256 values are
`d2745d1a8445ac02a484a2c8e71c00c733223a2bb2b55be2e8745478d12aaa32`,
`e1dfcb3745b7f40c0effe6d533ebde3ad16f7d36981be072823bb19471cd07db` and
`604571fe1fdd9669c5d0a5fcc14c18ff25fecc1a644e2c53618e74c706d205af`.
Circuits, node and protocol source remain byte-identical to frozen `185a132b8`;
no new proof identity, runtime restart or production authority follows.

The decoder constructs canonical field words from every modeled restored
coefficient, recovers all five row boundaries and interprets the complete
bounded polynomials. Its unconditional decoder/constructor theorem preserves
the leading 64-byte `hash_mt` digest and complete statement. The leading digest
is the salted/bound commitment digest, not an unwrapped Merkle root. These
restoration/polynomial definitions are mathematical Lean definitions; a Rust
execution refinement remains required.

The history component models one deterministic oracle on raw bytes with
64-byte outputs. Under selected FPP/final-query membership, the final oracle
response matching the claimed digest, and absence of collisions on history plus
the two verifier inputs, it derives final raw-input equality, embedded FPP
digest equality and then FPP raw-input equality. Collision exclusion is finite;
no globally injective finite-output hash is assumed. Its exceptional cases are
an overlapping event cover, not a probability result. A finite classical input
list is not a quantum compressed-oracle history or chronological evidence.

The join defines the prior response using a separately supplied
`Matrix -> RawInput` selector and complete decoding, with zero on parse failure.
It does not construct that selector from the final wire. This function signature
does not prove independence or selection before a later challenge. The new
selected-query support theorem derives the response equality internally from
the history and decoder calculations; it retains exact source-cell/masking
readback and distinct query-point hypotheses. The query-failure cover concerns
failure of that selected query's support membership. It is not coverage of all
failed decoders or accepted false relations. The supplied leading digest and
final transcript tail still require correspondence to actual Rust calculations.

Strict compile/audit times were 4.244/1.999 seconds for the decoder,
2.005/2.002 seconds for the corrected history component, and 2.902/2.295 seconds
for the join. Their respective peak compile/audit process-tree RSS values were
2660745216/2624356352, 2574319616/2552643584 and 2646523904/2599010304 bytes.
All 22 new theorem dependencies contain only propext, Classical.choice and
Quot.sound. Each invocation was serial, warning-clean, and bounded by 120 seconds,
4 GiB RSS and 10 GiB free disk. Exact commands, cached-source comparisons,
failed-attempt evidence and root integration-review receipts are retained in
`/private/tmp/native-launch-commitment-response-binding-20261004`,
`/private/tmp/native-launch-fpp-history-binding-20261004` and
`/private/tmp/native-launch-fpp-response-history-20261004`. From each component's
recorded worktree, its `run.py` reproduces the compile; setting `MODE=audit`
reproduces the serial audit. No aggregate formal CI or accepted-security endpoint
is claimed. All eight production qualification gates remain open.

Revision note: Record the proved modeled restoration and finite-history links
while retaining real-game provenance, source refinement, quantum transport,
complete public simulation and release authorization as separate obligations.


## Complete strict-leaf readback (2026-10-04 22:21Z)

The component is integrated as `53ee8674a5ea60d475c42bb40d7ca62060449e79`.
Its Lean SHA-256 is
`9c056119c0529eb0c1b4cfc2c47db62b3df13336511c21641fb0b1d7dda493f9`.
The executable parser checks the literal outer profile, leaf role, zero counter
and complete payload size, then reads the entire 1192/576-byte statement,
32-byte salt, eight-byte index below `2^23`, 64-byte tape, count 140 and all
140 canonical committed field values, count five and all five canonical masks.
It requires exact byte exhaustion. Roundtrip and projection theorems recover all
fields; complete raw-frame equality determines the entire statement and every
leaf field. The statement remains arbitrary fixed-width words; this is not
semantic statement acceptance.

The fixed dimensions are supported by the guarded native profiles: packing 64,
six opened evaluations and beta two give `(64 + 6) * 2 = 140` stacked values;
eta five fixes the mask count. Both profiles use `2^23` DECS positions. RP06
requires constraint degree eight and HTLC degree two. Their wire/profile checks
supply the fixed salt and tape widths. The generic leaf helper accepts variable
slices and must not be assigned those stronger native-profile guarantees.
Root review checked the exact leaf order and five cached import source hashes.
A separate bounded Astra review of the same Lean SHA found no actionable logical
or claim-precision gap.

Strict compilation passed in 4.055 seconds at 2789933056 bytes peak process-tree
RSS. The serial nine-theorem audit passed in 2.230 seconds at 2603089920 bytes;
only propext, Classical.choice and Quot.sound occur. One failed compile and its
narrow proof repair are retained. No guard fired. Exact commands, source and
artifact pins, measured receipts and root integration review are in
`/private/tmp/native-launch-leaf-readback-20261004`. The recorded `run.py`
reproduces compilation; `MODE=audit` selects the serial audit. These are direct
component checks using retained dependencies, not aggregate formal CI.

The next authentication construction must preserve actual hash framing. The
RP06/HTLC internal-node input contains only the ordered full child digests;
level and node index are not part of these node hash inputs. The root wrapper
binds salt, full tree-root digest and full statement. Rust root recomputation
returns a root whose wrapped digest enters FPP; it does not directly compare
against an original tree root. Deriving original/reconstructed tree-root equality
therefore needs the FPP history bridge, recorded wrapper-query provenance and
relevant collision exclusion. Compact multiproof reconstruction must then be
refined to an ordinary path before authenticated leaf equality can construct
`SourceReadback`. Original source selection and chronology, actual Rust/field
arithmetic refinement, quantum history accounting and complete public simulation
remain open. Runtime circuits/node/protocol bytes and proof identities are
unchanged. All eight production qualification gates remain OPEN.

Revision note: Close complete literal leaf decoding while keeping authentication,
actual source correspondence and production authority as separate obligations.


## Deterministic Merkle binding and compact extraction (2026-10-04)

The path binder is integrated as `f1a47e2eea71334d49a435777510afb1bba4e633`.
The compact extractor and its comment correction are integrated as
`679bc3ad9` and `040f36c28f2525813f7f794413793fb73e30c914`. Their final Lean
SHA-256 values are `d6098c817014665aa56baa3cf1d032662830d1d70ac6a393bf82d34c858715ed`
and `707f6ecc1dd6e8a997ead6ba55e3c0ca7a707850ffef58a3629aac58b2835a5f`.
Root reviewed every definition/proof, exact engine leaf/root/node inputs,
compact reconstruction and omission schedule. Independent bounded Astra reviews
found no substantive logical or claim gap. One compact comment miscounted data
fields; it was corrected, verified as a comment-only diff and recompiled/audited.

The literal node input is the family profile, 36-byte Merkle-node role,
16 full child words and zero counter. There is no level/index field in this
native branch. The root wrapper uses the 36-byte Merkle-root role, four salt
words, all eight root words and the complete 149/72-word statement, with zero
counter. Codec injectivity preserves both ordered child digests and every
wrapper field.

The binder compares two finite ordinary paths with identical supplied direction
bits and potentially different siblings. Recorded prior leaf, node and wrapper
inputs must belong to the selected history. Rebuilt leaf, node and wrapper
inputs are explicitly added. Collision exclusion applies only to that finite
list. Equal wrapper outputs first give equal raw wrapper fields and tree roots;
path induction gives equal leaf hashes; another finite collision step gives raw
leaf equality, and the complete leaf parser recovers every field. No desired
cell equality, Merkle-binding predicate or global hash injectivity is assumed.
The equal wrapped outputs still need their actual FPP/history correspondence;
these premises establish neither an original committed tree nor chronology.

The compact model uses an error-returning index map and one state/cursor per
original opening. Duplicate current indices must have consistent hashes.
It reuses an opened sibling when present, otherwise reads and advances that
opening's own compact cursor. Ordered parents use successive index parity;
indices divide by two after each level. Final checks require exact cursor
exhaustion, nonempty openings and agreement of every root. An expanded sibling
list instruments the model; it is not automatically erased. Only proof fields
are erased, and their length/fold facts are constructed by initialization and
advancement. No fold test is added to acceptance.

The public extraction theorem starts solely from mapped root success of the
executable reconstruction, which starts from its initializer. It extracts a
complete depth-long ordinary path from each original digest to the returned
root, the exact index quotient and consumption of all compact elements. It
requires no collision or original-tree assumption. Initial shape, sortedness,
range, expected compact lengths, leaf-hash construction and proof parsing are
external to this model. Association-list/map equivalence and Rust-loop refinement
remain unproved. The generic child function is not yet linked to the literal
native hash, and the two resulting paths must still be paired along the actual
index route.

Final binder compile/audit measured 3.291/2.043 seconds and
2675720192/2625421312 bytes peak process-tree RSS. Its nine theorem dependencies
contain only propext, Classical.choice and Quot.sound. Two bounded failed codec
proof attempts are retained. Final corrected compact compile/audit measured
2.003/1.361 seconds and 1512275968/1415135232 bytes; its six theorems use only
propext and Quot.sound. The earlier first-pass compact results are retained under
`pre-comment`. Each invocation used warnings as errors and the serial
120-second/4-GiB/10-GiB disk lane, with no resource guard firing.

Exact commands, measured receipts and root integration reviews are in
`/private/tmp/native-launch-merkle-path-binding-20261004` and
`/private/tmp/native-launch-compact-merkle-path-20261004`. Each recorded `run.py`
reproduces its component compile; `MODE=audit` selects the corresponding audit.
Binder compilation uses the already-integrated `NativeLaunchFppHistoryBinding`
source through its retained compiled object, even though that source is absent
from the older worker checkout. Root pins both integrated source paths and loaded
object paths/hashes. These are direct cached-dependency checks, not clean-checkout
or full aggregate validation.

A calculated original tree can first define data and mask functions from the
same canonical leaf family used to build it. The producer-source specialization
uses retained committed/masking coefficient arrays, exact domain points, tapes,
salt and complete statement, then needs rotation, stacking, evaluation and
serialization correspondence. `SourceReadback` itself permits arbitrary data
functions; polynomial origin cannot be inferred merely from a Merkle root or
honest producer control flow. The acceptance argument must also cover arbitrary
adversarial commitments or derive their required source properties. Existence
and selection of the original tree remain separate obligations. Wrapper-history
linkage and chronology, event coverage, quantum transport,
complete public simulation and release authorization remain open. Runtime and
proof identity are unchanged. All eight production qualification gates remain OPEN.

Revision note: Record deterministic binding and extraction without promoting
conditional finite results to accepted-source or production security.


## Calculated trees, compact binding and source readback (2026-10-04)

The original-tree component is integrated as
`eaf212f702dcae1fbba60d6271bb62584cba6d0b`; compact binding as
`a17caaddf13041d5e8e6d9d582d540f010e658a0`; their source-readback join as
`acdfd5f600273ec265e38521577d291b50e6280b`. Root reviewed all definitions,
proofs, imported source/object pins, failed attempts and guarded receipts.
Independent bounded precision reviews found no substantive logical or claim gap
at the exact final source hashes. The only compact repair split the Boolean
side in two empty-path proofs; the reviewed final hash was independently checked.

The calculated tree accepts an arbitrary raw leaf function. At each level it
hashes adjacent full digests using the literal native node frame. Its paths use
index parity, the corresponding sibling and successive division by two.
Depth/range induction proves the calculated root and leaf/node/wrapper membership
in its finite input list. No separate structural-address adapter is required.
The native depth-23 specialization constructs actual leaf indices, common salt
and full statement, with arbitrary canonical 140-cell and five-mask functions
and tapes. It assumes neither honest polynomial origin nor bounded data degree.
The calculated input list is a mathematical object; membership is not an
observed execution record or a chronological prequery claim.

The compact binder computes both paths' directions from the same Nat index and
proves ordinary fold/query correspondence with exact node framing. Its path is
projected from initialized modeled reconstruction, with failure eliminated by
mapped root success. It retains original-opening cursors and derives raw leaf
and all-field equality using explicit prior provenance, wrapped-digest equality
and finite relevant collision exclusion. Independent direction alignment and an
externally supplied fold certificate are absent.

The readback join defines each opening's index and hash from the wire's position,
canonicalized cell/mask values, salt, tape and complete statement. It calculates
the original tree's ordinary path, fold and input memberships internally.
`authenticated_source_readback` assumes mapped reconstruction success, equality
of outputs on the exact original/rebuilt root wrappers, and finite collision
exclusion for each selected opening. It interprets the derived canonical cell
and mask equalities to construct precisely `SourceReadback`. The theorem takes
a selected `NativeLeaves` value as conditional data; it does not extract that
value from every adversarial real execution or assume an honest producer.
It supplies no response rule, query-point injection or FPP chronology theorem.

| Component | Theorems | Compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Original tree | 11 | 2.788 / 3.086 | 2677817344 / 2627584000 |
| Compact binding | 6 | 2.268 / 2.040 | 2657140736 / 2628517888 |
| Authenticated readback | 4 | 2.041 / 2.036 | 2640003072 / 2627682304 |

Every invocation used the serial 120-second, 4-GiB process-tree RSS and 10-GiB
free-disk limits, with warnings as errors. Every theorem dependency contains
only propext, Classical.choice and Quot.sound. Each component needed one narrow
proof repair; the tree also retained an import-only cache setup failure.
No resource guard fired. Exact commands, runners, logs, source/object pins and
root integration receipts are retained respectively under
`/private/tmp/native-launch-original-merkle-tree-20261004`,
`/private/tmp/native-launch-compact-merkle-binding-20261004` and
`/private/tmp/native-launch-authenticated-readback-20261004`.
Run each directory's `run.py` for its compile and set `MODE=audit` for its
all-theorem audit. These use retained checked dependencies; no clean aggregate
rebuild or CI claim follows. Root verified the actual selected object paths and
hashes, including imports whose source resides in integration rather than the
older worker checkout.

Final source SHA-256 values are, in the same order,
`95aa352310e5ecc080dbcda81ea74fd64f9fc4f953b34628ee89163b5b5d7e58`,
`bdea6dad86194c3f2ebc5dfd8f7dc9f7c403b162dc6d89c40586cb5bc60b3b0a`,
and `bebf2b68aa9c7930868faae454ee3760adc77235493ab37af57521bcb9bdbb0c`.
Root integration receipt SHA-256 values are
`b055851b1d0a2e37bb8dd189c66a8299df714dd0221382f853f5993c72b8774e`,
`c11ab1ea3d17afbde7685e451736f2ce78f6c9fdcafdf72c4c4cf3dd646591e4`,
and `0e4aa150c3c40bcd856de5a07003c30a62ae0895a173908fd23849ca977e2dce`.

At this milestone, the next construction was native extraction from a finite
recorded hash relation, using deterministic defaults on missing branches. The
following section records that instantiation and its separate remaining bridges.
Rehashing those defaults need not reproduce the committed root. The useful
claim is selected-opening readback unless a relevant collision or extraction
change occurred. The generic finite-record kernel in
`SmallWoodV8Smz9CoherentMerkleGeometry.lean` locates insertion-induced changes at
tracked targets or recorded outgoing digests. Its historical `sourceNext`
grammar must not be reused for native RP06/HTLC: new exact root/node/complete-leaf
parsers and index routing need their own instantiation and accepted-opening
proof. Missing wrapper/FPP queries, shared-source stability and selector timing
must be retained as actual exceptional events. A one-fresh-uniform-output
classical count is not a native multi-query or QROM reduction.

Rust parsing/refinement, generated geometry and field arithmetic, complete
adversarial accepted-failure coverage, real chronology/quantum transport, public
simulation, shared-query release accounting and reviewed authority remain open.
Runtime circuits/node/protocol and proof identities remain identical to frozen
`185a132b821ad319a49f4a8746c6110ea7ba0476`. All eight qualification gates remain
OPEN; none of these components changes production authority.

Revision note: Derive conditional native SourceReadback through calculated trees
and actual index routing, and preserve the separate arbitrary-root record
extraction and security obligations.


## Native finite-record extraction and oracle selection (2026-10-04)

The extractor is integrated as `5fff1055a175f42da099004902f1478e0764f6a0`;
the oracle adapter as `95213539675b3b67fe90c8f2a4a78ee9d5546942`.
Their final source SHA-256 values are
`cae9249cc70cab112890a3ef9341f0640853804984d352e5d98fe9d411b0159d`
and `c249e291a52edd2a64fdc273e6586b6bee5f4b223f44d1246bd9b75dcf245079`.
Root read every definition and proof, checked the exact integration bytes,
eight extractor import source/object pins and five adapter pins, and retained
integration receipts. Independent bounded reviews of these exact source hashes
found no substantive logical or claim gap. Runtime circuits/node/protocol
remain byte-identical to frozen `185a132b821ad319a49f4a8746c6110ea7ba0476`.

The extractor reuses only the generic finite-record kernel; it supplies current
native root, binary-node and complete-leaf parsing rather than the historical
`sourceNext` grammar. It fixes the family, typed salt, complete statement and
original index throughout the route. At remaining depth `d+1`, the node selects
bit `(index / 2^d) % 2`. Fuel 25 covers one wrapper, 23 nodes and one terminal
leaf. Arbitrary finite records and an arbitrary target digest are permitted;
there is no complete original tree or polynomial-origin premise. Cyclic or
opaque records do not prevent termination under this explicit fuel.

Readback retains selected raw keys, status and an optional full decoded leaf.
Unavailable cells and masks receive canonical zero defaults. Invalid or
wrong-context candidates are filtered before selection and normally appear as
missing; the generic completion's malformed status is not a diagnosis of every
invalid database record. No result claims that rehashing defaults reproduces
the target. The selected-leaf projection theorem calculates a terminal record
from explicit selection, parsing and context premises; it does not derive those
premises from compact-proof acceptance.

`SourceChanged` is actual completed-readback inequality at some index, including
metadata. A record insertion causing this event must output the fixed wrapped
root target or an existing parsed outgoing child digest. Binary-node child sets
have cardinality at most two even though one index route follows only one child.
This gives at most `1 + 2 * records.card` exceptional outputs without enumerating
all `2^23` positions. The separate uniform theorem counts changes under one fresh
uniform classical output with fixed records, input and target list. It is not
an adaptive multiquery, native distribution-transport or QROM theorem.

The adapter serializes every bit of all eight word-valued digest limbs into the
extractor's 64-byte representation and proves injection. It proves exact
node/root/complete-leaf constructor parsing, including preceding-role rejection.
Its finite graph contains `(key, toOutput(H key))` for the same supplied
deterministic oracle. Membership characterizes those outputs and establishes
functionality. A valid recorded key creates a nonempty candidate set; the
selected record's full output equality and finite relevant-collision exclusion
then force raw-key equality. Desired selection equality is derived rather than
supplied. Global hash injectivity and an honest full source tree are absent.
Injection alone is not a proved bijective distribution transport.

| Component | Theorems | Compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Recorded extraction | 10 | 5.163 / 2.037 | 2841739264 / 2563981312 |
| Oracle graph adapter | 9 | 7.367 / 1.993 | 2654502912 / 2620391424 |

Both components used warnings as errors, serial 120-second limits, 4-GiB
process-tree RSS limits and a 10-GiB free-disk floor. No guard fired in these
passing component runs. All nineteen audited theorem dependencies contain only
propext, Classical.choice and Quot.sound. The extractor needed two narrow
elaboration/proof repairs; the adapter needed one. Failed attempts remain
retained. Exact runners, commands, source/object pins, logs and audits are in
`/private/tmp/native-launch-recorded-merkle-extraction-20261004` and
`/private/tmp/native-launch-recorded-oracle-graph-20261004`. Each directory's
`run.py` reproduces its compile and `MODE=audit` selects its audit. These use
retained dependencies, not a fresh aggregate rebuild or completed CI.
Root integration receipt SHA-256 values are
`8ad932da2461bb3e58256f4b3ae19d86277ce4055add9608e8cf5e675fd83edd`
and `64bbf5ddb46b778cd1c513e6d9d7998d86a0751eace0d5e906f94930a2a1dcdb`.

An initial `NativeLaunchRecordedPathReadback.lean` draft was stopped without
commit or theorem audit. Its exact unverified source SHA-256 is
`26f81d15c052edcbdeaeebf52d203f72a13180045e16bb70f8fbcb9d533ba8d0`,
retained in `/private/tmp/native-launch-recorded-path-readback-20261004`.
Whole-module checks hit 120.225- and 60.166-second wall limits; a true import-only
probe passed in 2.037 seconds. A smaller prefix identified a conditional-hash
mismatch, which was repaired in the draft. The reverse-list tree theorem still
exceeded a 15-second diagnostic check. One earlier prefix log was overwritten;
the report retains its error and measured metadata without claiming the complete
log remains available. These failures are not credited as checked theorems.

The initial path draft's failures above remain historical failed evidence.
The subsequent checked repair and common-wire composition below now derive
readback from initialized compact reconstruction against one shared final graph.
The next deterministic join must compare that graph with a fixed earlier record
and retain actual fresh insertion changes or relevant collisions before
composing the FPP/decoder cover. Actual wrapped-root/FPP linkage, fixed source
selection and timing, chronological record selectors, quantum transport,
complete accepted-failure coverage and public simulation remain separate.
No production authority follows. All eight qualification gates remain OPEN.

Revision note: Record checked arbitrary-root extraction and derived oracle
selection while preserving the unverified compact-path/shared-source frontier.


## Checked recorded paths, source changes and common wire (2026-10-05)

Three new components close modeled path and whole-wire readback while retaining
its execution and probability boundaries. Recorded-source stability is integrated
as `4355417c2e1907294def9546fe18dae650db627a`, recorded paths as
`aa12f5a7cdbbc8fe1fe3586c31ccc0eb233653ea`, and common-wire readback as
`eae1d153818946067a115d58a253dbd2051063b1`. Their source SHA-256 values are
`c925a4956b05238b3e84801cce619b874740d45f65638f8816ad3e4bc5799c9b`,
`ab63c45670439a082f15ec7b51679cbe8bc3491d1329470c14fb2f0758443ca9`, and
`4bd5c27d441377277850d2477be41b667f453a737c672a653090dca638892367`.

The path component derives valid selections from actual leaf/node/wrapper key
membership in an arbitrary finite history and finite relevant-collision
exclusion. Reverse list induction joins the bottom-up ordinary path to the
extractor's top-down quotient bits of the same original index. One symbolic
wrapper step leaves the remaining recursive extraction opaque; the complete
native route uses one wrapper, 23 nodes and one terminal leaf. Initial timeouts
and later concrete rewrite failures were retained. Direct parser-success terms,
explicit membership, a one-step wrapper lemma and context projection
normalization produce the final strict result. No desired readback, independent
direction/hash alignment, full source tree or global hash injection is assumed.
Its compact theorem itself remains per selected augmentation.

The separate common-wire component constructs every leaf from the SAME salt
and full statement and from the actual typed wire's positions, canonical cells,
masks and tapes. It joins every opening's leaf, ordinary node and wrapper keys
in one finite list. Initialized compact success calculates path length/root;
list membership is proved internally. One common graph, context and wrapped
target then yields every decoded leaf and complete SourceReadback against the
canonical recorded data and masks. The source functions are defined at all
positions, including canonical defaults for missing records; out-of-range Nat
columns are zero. No full original tree is selected or supplied.

That list is a union sufficient for membership, not the actual Rust query log.
Rust hashes all selected leaves first, then nodes level-major and original
opening-major, including repeated ancestor queries, before root wrapping.
The common list is built from the final wire and cannot be relabeled as an
earlier prechallenge database. The component establishes no FPP linkage,
unchanged earlier source, independent challenge or probability bound.

The stability component inserts each listed key with the SAME deterministic
oracle output. Its graph equals the graph of the earlier list plus later keys.
An actual completed-readback change produces a concrete prefix/key/suffix
insertion witness and a hit on the fixed target or a parsed child present
immediately before that insertion. For oracle graphs the witness key is absent
from the preceding prefix: reinserting an existing pair cannot change readback.
The broader InsertionHit event can include duplicate or unchanged hits. No-hit
results imply complete readback and all canonical data/mask function equality.
Names earlier/later encode a list split, not a proved game chronology. No
randomness, collision exclusion or desired readback is used in these stability
theorems. They supply no adaptive multiquery or QROM loss.

| Component | Theorems | Compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Recorded-source stability | 9 | 2.250 / 2.019 | 2646327296 / 2626256896 |
| Recorded-path readback | 13 | 2.707 / 1.797 | 2659762176 / 2605219840 |
| Common whole-wire readback | 3 | 2.257 / 2.038 | 2627829760 / 2628206592 |

All 25 exported theorems passed strict warnings-as-errors compilation and
serial all-axiom audits with only propext, Classical.choice and Quot.sound.
Stability and common-wire checks used 120-second limits; the explicitly granted
final path microrepair used 30-second compile/audit limits. Each enforced a
4-GiB process-tree RSS ceiling and 10-GiB free-disk floor. The path's earlier
47.224-second full failure and 2.718-second projection failure remain retained.
The common-wire checks initially exceeded default and one-million-heartbeat
limits; explicit branch/type annotations, equality-instance matching and exact
rewriting preceded the final pass. Temporary diagnostic traces were removed
to satisfy strict warnings. No protection or linter was disabled, and the
individual cause of earlier elaboration behavior was not isolated.

The coordinator read all definitions, proofs, plans and guards and verified
10 stability, 11 path and 13 common-wire source/first-resolved object pins
against the actual compile commands. Independent bounded read-only reviews
of the exact final source hashes found no actionable logical, claim or evidence
gap and independently checked these pins. Checks reuse qualified retained
objects; no fresh aggregate dependency build or aggregate formal CI is claimed.

Evidence directories are
`/private/tmp/native-launch-recorded-source-stability-20261005`,
`/private/tmp/native-launch-recorded-path-readback-r2-20261004`, and
`/private/tmp/native-launch-recorded-wire-readback-20261005`. Each retains
run.py, exact commands, resource results, final source/object pins and all
exported theorem audits. The original path failure directory remains separate.
Integration receipt SHA-256 values are respectively
`87e71249cc8e6181810c9a56525d4c89ec962e5a2abddb471d3f6abc2ea670f8`,
`59d43fac5993df7eaae45dfcf168cfa3e3845a9d171eae307d1afc5b689e0eeb`, and
`6389377af49125356910154ee9de8faeb92cce4f51c613b87903117e45c3f081`.
The common-wire coordinator metadata reader initially used a wrong pin-field
name and produced no receipt; it was corrected, all thirteen pins matched, and
post-integration root verification is explicitly recorded. This was not a Lean
compile failure or a change to the checked source.

The earlier-source transport and finite prefix-derived FPP selector are now
checked in the next section. Their joint DECS support/actual decoder-none
cover is checked in the final section. Actual causal source/response snapshots
remain to be constructed; no component supplies real execution chronology or
a causal response rule across matrices.
DECS opening-position sampling uses the opening transcript hash of h_piop and
combination heads/tails, rather than h_piop directly. The separate DECS mixing
matrix challenge derives from hash_mt. Each source/response snapshot must be
frozen against its relevant first challenge-prefix query at any counter, not
merely the honest counter-zero query. These are separate chronology obligations.
Actual execution chronology, generated geometry/field arithmetic and Rust
refinement, word/byte distribution transport, quantum-history accounting,
complete accepted-failure coverage, public simulation, shared-query release
accounting and reviewed authorization remain open. Runtime circuits/node/
protocol still match frozen185a; proof identities and all eight production
qualification gates remain unchanged and OPEN.

Revision note: Check complete recorded paths, actual fresh insertion witnesses
and one final graph's whole-wire readback, preserving the earlier-source and
real-execution security frontier.


## Earlier-source transport and finite prefix-derived FPP selection

Two bounded deterministic components are integrated as
`fc6ff52026abd03fde88329c578ee036a4d1dbf6` and
`7c184cb95d1e6a9b87706451344671eb14f73d15`.
The exact checked source SHA-256 values are
`953f70f9ba15798adaa2bfd86a107e841790d2b96d3c9c26c4d67aa9ee4e78cf`
and `fff6dfe47f965ba1dbddc1640eafc9db85666c555a332ad1d9d63ffb9f633c06`.
Both use qualified retained dependency objects; no fresh aggregate build or
aggregate formal CI is claimed.

`NativeLaunchFrozenRecordedSource` defines the actual exceptional event as
inequality of completed readback between the earlier graph and its constructed
extension. The event includes raw-key metadata, status, missingness and optional
leaf at any position. Metadata-only changes also qualify, so this event is
broader than field-value change; its absence is a stronger stability condition.
Without that event, the complete earlier data/mask functions equal the final
functions. Combining this transport with compact acceptance and finite collision
exclusion derives earlier-only whole-wire SourceReadback. No desired readback,
full original tree or source-cell equality is supplied. Failure of earlier
readback implies a relevant collision or that actual change event. A change
yields a prefix/key/suffix decomposition with a fresh key absent from the
preceding list prefix and an output hitting the fixed target or a parsed child
of the immediately preceding graph. Context and wrapped target are fixed for
comparison; their actual challenge-time selection remains unproved.

`NativeLaunchPrefixFppSelector` parses complete final frames using the literal
family profile, final role, zero counter and complete consumption. It decodes
unrestricted 64-bit words, preserves the eight-word FPP digest and entire tail,
and checks exact raw re-encoding. Roundtrip requires the explicit physical bound
`8 + tail.length < 2^64`; no canonical field reduction is used. Ordered finite
scans select a matching final record and a matching FPP preimage from the
supplied prefix. Selector inputs contain no wire, point, matrix, rebuilt key
or external prior tail. Success constructs RecordedChain internally. A checked
extensional locality theorem proves that changing oracle values outside the
prefix cannot change selection. This locality is not a chronology certificate.

The response cover uses the actual rebuilt FPP and final keys and returns one
of: calculated-response equality; a relevant finite collision; the rebuilt
final key absent from the prefix while hashing to the fixed claim; or the final
key present while its rebuilt FPP key is absent, with the final parser exposing
that key's digest and tail. It assumes no selected key, successful provenance
or desired response equality. Decoding/selection failure uses a fixed zero
response. The theorem covers one instance, rather than constructing a causal
Matrix-to-prefix/claim response family or assigning either late event a density.

| Component | Theorems | Strict compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Earlier-source transport | 5 | 2.447 / 1.998 | 2661253120 / 2627764224 |
| Prefix-derived FPP selector | 14 | 2.448 / 2.000 | 2663546880 / 2626060288 |

All nineteen exported theorems passed strict warnings-as-errors compilation and
serial all-axiom audits. Only standard propext, Classical.choice and Quot.sound
occur; the generic scan locality theorem uses no axioms. Guards enforced
120-second checks, a 4-GiB process-tree RSS ceiling and 10-GiB free-disk floor.
The earlier-source component retains both failed declaration sources, logs,
commands and results. The selector retains its two initial failed commands,
logs and results, but their exact source snapshots were not saved and are
unavailable. Its successful eleven-theorem source snapshot and 2.891-second
check remain separate from the final fourteen-theorem source/object and checks.
The three locality additions left the checked core unchanged and needed no
repair. No warning or linter was disabled.

The coordinator read complete final sources, plans, guards, commands, metrics
and all axiom output; verified fifteen earlier-source and eleven selector
integrated source/first-resolved object pins; and independently compared the
selector's preserved core with its three locality additions. Independent bounded
read-only reviews of both exact final hashes found no substantive logical,
claim or evidence gap and independently matched those dependency pins.
Retained evidence directories are
`/private/tmp/native-launch-frozen-recorded-source-20261005` and
`/private/tmp/native-launch-prefix-fpp-selector-20261005`. Their root integration
receipt SHA-256 values are
`c1ea87aa3d4cf83265d578530860be563499bb161d88c9b0b551fd197dc194af`
and `e44d1e883fdcf7f1afbf02336f2dfa485e3b17dc45e48eb39e502f5498c58056`.

The final section now checks the composition with DECS query support and the
actual calculated decoder-none cover. It retains both collision sets, actual
source change and both concrete late-preimage events without a positive
provenance flag. Source, context and wrapped target must still be causally
frozen before the first DECS mixing-prefix query at any u64 counter, seeded by
`hash_mt`. FPP response and fixed claimed `h_piop` belong before the first
nonce-aware PIOP-opening prefix, seeded by nonce plus `h_piop`. Separate
DECS-opening transcript provenance belongs before the first DECS-position
sampling prefix, seeded by `decs_trans_hash` of `h_piop` plus combination
heads/tails. These are three distinct unproved real-game obligations; the
final section records the precise source locations and parser scope.

Generated geometry/field arithmetic, actual Rust execution refinement,
word/byte distribution transport, mixed quantum histories and adaptive losses,
complete accepted-failure coverage, public simulation, shared-query accounting
and reviewed release authority remain open. Runtime circuits/node/protocol
match frozen185a, proof identities are unchanged, and all eight production
qualification gates remain OPEN.

Revision note: Derive deterministic earlier-only readback and prefix FPP
provenance while preserving actual timing, security and release boundaries.


## Derived DECS failure cover and guard-derived field geometry

Three bounded deterministic components are integrated as
`6e22eb6c961d695f71517aae4fc20391ecc5d5cb`,
`42c1b34b6de23c2622a6869b7434ba947a27702f` and
`7732d8668d07642864e1b95a2332423e8802d6cc`.
Their exact checked source SHA-256 values are
`e4ad914684d8d92a9901033e05a4ffd48370e0be7ec4c508578493e57beb10e6`,
`84d3a404d305e61c373e13f65f8507ca4e44671b91f4c6b0913256ec5d05b5c8`
and `e0bffee15e6234a06420e655b19b91a3e46d3a17532488b0edc7d61975ea9353`.
The checks use retained dependency objects; no fresh aggregate build or
aggregate formal CI is claimed.

`NativeLaunchDerivedDecsFailureCover` uses the same actual modeled wire,
statement, salt, compact paths, matrix, earlier source history and FPP prefix.
The leading FPP digest is exactly H(rootFrame salt bareRoot statement), also
the earlier-source wrapped target. Its modeled Accepted predicate consists
only of compact root reconstruction, the physical final-frame length bound
and reconstructed FPP digest equality. It is not the complete Rust acceptance
predicate. SourceReadback and calculated-response equality are derived
internally, without desired readback, prior key, RecordedChain or response
equality premises.

Every actual query lies in the same full response support unless one of five
concrete events occurs: a relevant leaf-history collision; an actual completed
source-readback change; a relevant FPP-history collision; the actual rebuilt
final preimage absent from the supplied prefix while hashing to the claim; or
the final preimage present with its actual rebuilt FPP preimage absent and its
parsed digest/tail exposed. The two finite collision sets remain separate.
The failure cover starts from the existing calculated responseDecoder = none,
then derives membership of the actual typed sample in decoderFailureEvent.
Its partition returns those five events, the existing universal bad-matrix
event, or a small full support containing the actual sample. Sample cardinality
is derived from explicit sampled-point injection; full point injection remains
explicit for decoder recovery. The threshold is generic and greater than the
actual branch degree: RP06 degree405/q38, HTLC Lock and Refund degree2119/q58,
and HTLC Claim degree9933/q58. No Claim-specific density is transferred to
another branch.

The response rule fixes oracle, prefix, branch and claim and is constant over
its Matrix argument. It has no wire or point argument, but that type alone
is not temporal causality. A causal Matrix-to-prefix/claim family is not
constructed. Actual source/context/wrapped target selection and response/
opening-transcript provenance must be frozen at three separate first relevant
challenge-prefix queries at any u64 counter, as described above. Response
freezing precedes its own nonce-aware PIOP-opening challenge; the later
DECS-position challenge requires its own transcript provenance.

`NativeLaunchGuardedPointGeometry` uses the exact Goldilocks modulus,
2^23 domain and two-adic root/order certificate shared with the native point
formula. It reuses no historical fixed shift388 or interpolation certificate.
The executable canonical nonzero shift guard derives field nonzeroness, then
the root's exact order derives global point injection for every accepted shift.
Source-shaped candidate/descriptor guards expose the interpolation loop and
bounds, but these theorems use only their nonzero-shift component. They do not
prove interpolation disjointness, the 4096-candidate first-success search or
an executed native descriptor. The executable adjacentIncreasing comparison
models the strict adjacent windows(2) check, then derives chain, pairwise order,
typed wire-position injection and composed sampled-point injection. No desired
injectivity is supplied. The typed Fin domain and branch query count provide
range/count in this model; they do not prove acceptance of raw Rust lengths,
indices or field arithmetic. Its guards are composed into the DECS
failure-cover endpoint in the third component below.

`NativeLaunchGuardedDecsFailureCover` constructs native I shift by overwriting
the generic point field before formulating Accepted, rebuilt FPP keys, responses,
support and actual decoder predicates. All expressions use the same constructed
native point, actual wire, matrix and wrapped target. Shift and actual typed
wire adjacent-index guard booleans derive full and sampled-point injection
internally. No point-equality or injection premise is supplied. The five support/
failure/partition theorems retain all five concrete exceptional events, actual
calculated decoder-none and generic branch degree/query count/valid threshold.
Constructing the field-model point this way does not prove that actual Rust
acceptance refines these guards or that its deterministic search selected the
shift. The source/response causal rules and accepted false-relation implication
remain unproved.

| Component | Theorems | Strict compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Derived DECS failure cover | 7 | 14.951 / 2.002 | 2688843776 / 2629238784 |
| Guard-derived point geometry | 8 | 2.214 / 2.006 | 2621849600 / 2622128128 |
| Guarded DECS composition | 5 | 11.290 / 1.995 | 2667429888 / 2607284224 |

All twenty exported theorems passed strict warnings-as-errors compilation and
serial all-axiom audits, with only propext, Classical.choice and Quot.sound.
The adjacent-chain theorem uses propext only. Guards enforced 120-second checks,
a 4-GiB process-tree RSS ceiling and 10-GiB free-disk floor. Both DECS
components passed on their first attempts without repair. Geometry retains its exact failed source,
command, log and result; its sole source repair corrected Bool conjunction
proof syntax. A separate sandbox process-monitor denial retains the unchanged
repaired source and failure receipt; final compilation/audit used approved
monitoring. No guard, warning or linter was disabled.

The coordinator read all three complete sources, plans, guards, commands,
metrics and all axiom output. It verified all 27 DECS current-source/first-resolved
object pairs and all 91 geometry manifest entries: 89 Hegemon modules including
the component, plus two direct Mathlib imports and 177 source candidates.
All 112 current-source/first-resolved object pairs for the guarded DECS join
were also verified. Independent bounded read-only reviews matched exact final source hashes, pins,
resolution order, metrics and claims, with no substantive logical or evidence
gap. Geometry's plan entry-count wording was corrected before integration.
Source and cached-object hashes are separate provenance; this check does not
prove correspondence by comparing hashes of two different artifact types.

Retained evidence directories are
`/private/tmp/native-launch-derived-decs-failure-cover-20261005`,
`/private/tmp/native-launch-guarded-point-geometry-20261005` and
`/private/tmp/native-launch-guarded-decs-failure-cover-20261005`.
Their root integration receipt SHA-256 values are
`47498fd1768830243c699024b446c50f76dc8a47826ef90d097b34ebdf6e6717`,
`5cdd68562743913e28cf2499aa509c0394f7d1a9008c8c7480b9558e8137a7f8`
and `e33c3f6247c89c0743a758b315289428c0a96a8c33919521d58b2116c36c1c8d`.

The next obligations are actual causal prefix/context construction and
current-family PIOP/relation refinement. An accepted invalid
relation is not proved to imply calculated decoder failure: a decoded
low-degree source can still violate the transaction relation. Supplying that
implication as a transition field would not establish it. The next component
checks conditional field-level candidate disjointness and first-success
selection; search existence and Rust field/byte execution refinement, source
polynomial validity, finite-word/byte distribution transport, mixed quantum
histories and adaptive losses, complete accepted-failure coverage, public
simulation, shared-query accounting and reviewed release authority remain
open. Runtime circuits/node/protocol match frozen185a, proof identities are
unchanged and all eight production qualification gates remain OPEN.

Revision note: Check internally derived DECS support/actual decoder failure
covers, field-model uniqueness and their composition using internally
constructed native points, retaining semantic acceptance, actual native
execution and causal/security boundaries.


## Conditional coset selection and first-query replay

Two bounded components are integrated as
`4bd008c86cdcb84b29b00306156b4ac5ee7d038d` and
`55e36da35e61544378928540af75e0ad3af8829f`.
`NativeLaunchGuardedCosetSelection` source/object SHA-256 values are
`368fef3aa8339c88cc59dda17ab331f9efcbdfb93bdfe2b75b7539e6905af086` and
`f4f1d990deec7e8f391bfdc38553b89c92b845888f1f9c560e463fcc62474174`.
`NativeLaunchFirstQueryFreeze` source/object SHA-256 values are
`0a34a0b428ea61702f7cc93295707ecb94cc67da67dde14a09f1fd880e8b3240` and
`1e38ed7fa3acb0993de3543c0e9e28d93255bcce96bb12db309e3339e1104658`.
Retained dependency objects were used; no fresh aggregate build or aggregate
formal CI is claimed.

The coset component derives complete interpolation disjointness directly from
accepted field-level candidate checks for every `Fin m` coordinate and every
`Fin (2^23)` native point. It handles coordinate zero explicitly using native
point nonzeroness; each other coordinate's loop check contradicts the normalized
point's power being one. It uses the shared exact root-order certificate and
no historical fixed shift388/interpolation certificate or supplied disjointness.

An ordered `List.range 4096` first-success model derives the accepted guard,
failed earlier entries and offset bound from an actual successful result. It
returns `m + offset`; under `0 < m <= 2^23`, checked u64 addition is safe.
Selected-shift disjointness follows internally. There is no proof that this
search succeeds and no executed native descriptor is claimed. The core selector
can return a shift for `m = 0`, while Rust's entry rejects that input; full
zero-count/error control flow and Rust field/byte/descriptor refinement remain
outside this component. Earlier geometry's nonzero-only results are unchanged.

The first-query component uses the existing generic adaptive `Program` datatype
and actual `Program.record` interpreter, without importing old protocol
acceptance as native authority. Its calculated stopped interpreter returns a
completed optional result/log, or the earlier log, first matching raw input and
original continuation. The matching branch does not consult the oracle answer.
Resuming afterward reconstructs the exact full record, including repeated calls
and completed failures. Every recorded earlier key is nonmatching and the
trigger is matching. Agreement only at those actual earlier recorded keys
preserves the entire stopped result under another oracle, including continuation;
no agreement at the trigger or later queries is required.

A fixed snapshot callback inherits replay equality. Target and callback are
fixed theorem parameters and may close over externally future-dependent values;
their signatures do not construct causal selection. An optional classical
existential predicate covers every raw u64 counter for one fixed family, role
and payload. It is not an executable raw parser, a capped-group predicate, or
an online ledger for every newly encountered prefix. Actual native source,
context, FPP response and DECS transcript snapshots remain unconstructed.

| Component | Theorems | Strict compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Guarded coset selection | 14 | 2.453 / 2.003 | 2684076032 / 2624847872 |
| First-query replay | 9 | 2.449 / 2.017 | 2619441152 / 2550546432 |

All 23 exported theorems passed strict warnings-as-errors compilation and
serial all-axiom audits, with only propext, Classical.choice and Quot.sound.
First-query replay and snapshot replay use propext only. Guards enforced one
Lean job, 120-second checks, a 4-GiB process-tree RSS ceiling and a 10-GiB free
disk floor; no resource guard fired. Coset selection needed one narrow repair,
retaining the exact failed source/command/log/result. First-query replay needed
two narrow repairs for reserved identifiers and strict unnecessarySimpa,
retaining each exact failed source/command/log/result. No warning or linter was
disabled and no source strengthening followed final pass/audit.

The coordinator read both complete sources, plans, guards, commands, metrics
and all axiom output. Coset evidence verified 92 total module entries (90
Hegemon including the component and two direct Mathlib imports), 178 source
candidates, actual first-resolved cached objects, toolchain and current Rust
hash. First-query evidence verified all 113 project dependency source/object
pairs, actual first resolutions, exact compile/audit LEAN_PATH and toolchain.
Independent bounded read-only reviews matched both exact final sources,
objects, pins, checks and limits without a substantive gap. The initial root
first-query receipt script used a wrong nested failed-source path, wrote no
receipt, then verified the actual paths without changing sources. Source and
object hashes remain separate provenance, not a correspondence proof.

Retained evidence directories are
`/private/tmp/native-launch-guarded-coset-selection-20261005` and
`/private/tmp/native-launch-first-query-freeze-20261005`.
Root integration receipt SHA-256 values are
`f9d9de66c30370f50b4c89552baebbb57305dc2feec518cb2064cdb319d58519` and
`113128d37595dc093e31946d0dee62623cce38307da6af32613ec136181523cc`.
The second directory retains the source-reading staging report SHA-256
`94ed660f627c4acedbee074b10e00cd25277ab82d52ee72047dbd41abac96262`.

The current Rust engine hash remains
`c59e20da61e63b9f3dd2e41da0921df9ef8abd98bbc22bb5dad0ce54ae127193`.
Its three challenge stages require distinct causal selectors:

1. `derive_decs_challenge` at line 12808 seeds the DECS-coefficient XOF with
   eight words of `hash_mt`. Source, salt, statement/context and wrapped target
   must be derived from an earlier recorded root-wrapper preimage, or covered
   by an actual collision/late-wrapper event, before the first raw query for
   that exact prefix at any u64 counter. Salt and statement are absent from the
   challenge seed. Root wrapping starts at line 12755.
2. `xof_piop_opening_points_for_profile` at line 13636 seeds PIOP opening with
   the u32 nonce represented as a u64 word followed by eight words of `h_piop`
   (lines 13667-13668). FPP response selection belongs before the first raw query
   for this exact nonce-aware prefix at any u64 counter. Existing FPP
   `parseFinal` parses only `piop-transcript`, counter zero, ending at `h_piop`;
   it does not parse `decs-opening`. A later selected accepted nonce still
   needs its own causally recorded prefix entry.
3. `hash_challenge_opening_decs` at line 12462 hashes `h_piop` and each
   combination row's head then tail to produce `decs_trans_hash`.
   `xof_decs_opening_fixed_no_grinding` at line 13846 seeds DECS position sampling
   with only its eight digest words, without a nonce (lines 13886-13889).
   Separate complete `decs-opening` parsing/provenance must be frozen before
   the first raw sampling-prefix query at any u64 counter. RP06 requests 50
   candidate words and HTLC requests 80 in its own sampling namespace.

Capped groups do not shrink the raw physical namespace; complement queries
must still participate in these first-prefix boundaries. At this earlier
milestone the generic stopping core did not construct an online ledger or
derive an accepted proof's source/context from it. The next section constructs
the classical ledger and actual-entry root selector; native accepted-prefix
presence and execution refinement remain unproved. Search existence, actual Rust acceptance and
arithmetic refinement, current-family PIOP/relation semantics, accepted invalid
relation-to-failure coverage, quantum transport/adaptive losses, complete
public simulation, shared-query accounting and reviewed release authority
remain open. Runtime circuits/node/protocol match frozen185a, proof identities
are unchanged and all eight production qualification gates remain OPEN.

Revision note: Check conditional candidate disjointness, successful core
selection and deterministic first-trigger replay; correct the three distinct
source/response/transcript freeze stages without asserting native causal
selection or security closure.


## Online prefix ledger and actual-entry root selection

Three bounded components are integrated as
`6357de3c11e2edbaaacbd438354f8b8422e5c043`,
`21c649f108b2c11fd89294c9e2803981441a2e86` and
`83a4b26789cf58a7176335ae257495babac67a2f`.
`NativeLaunchOnlinePrefixLedger` source/object SHA-256 values are
`7738e0cf4df26e1b6eaa0bf6f86e45799b778f7646d9b1e684e1b38ff50d4cf7` and
`47bc074b1e8168ed775c3c4e8517bbf562ee454db30e6c27d06f4e9688dae88d`.
`NativeLaunchRootPrefixSelector` source/object SHA-256 values are
`838daa53f7d5d75dfe68d5b440cd772ffdc055822b6b152bed70de02312f26ae` and
`8ab4089aea7d6da056ed33494d9494d0044d6c94409403288d728f949b817235`.
`NativeLaunchOnlineRootPrefixCover` source/object SHA-256 values are
`de631ef0693f91ac322311a9ea0dce9b196618c26b37a943b490118782d863b7` and
`5ca185b974783bd98c274c0a3d200e6d9bd67bf19f2f8d1e3a17d2a47d6f3694`.
Retained dependency objects were used; no fresh aggregate build or aggregate
formal CI is claimed.

The online ledger has a fixed `parseSourceFrame` classifier that retains the
complete profile, role and payload bytes and removes only the u64 counter.
It takes no caller classifier, target, capture callback or oracle as a snapshot
selection argument. Before each actual adaptive `Program` read, its run checks
whether that parsed prefix appears in the actual earlier log. A fresh prefix
captures that earlier log, raw triggering input and original continuation
before the answer is read. Every call still appears in the resulting exact
`Program.record`, including repeats, malformed frames, complementary namespace
requests and completed failures. Classification is checked for every native
framed family/role/payload within the framing word-count bound (less than 2^64)
and every u64 counter, including counters outside capped groups. Malformed frames remain logged although they classify to none.

Membership in the actual empty-start run ledger derives the first-stop
certificate and freshness internally. Agreement only on the entry's actual
earlier keys preserves the entire stopped result and continuation under another
oracle; no trigger or future agreement is required. Two actual entries with the
same prefix are proved equal, including their continuation. This is not a
separately exported `List.Nodup` theorem or an explicit theorem that every seen
prefix has an entry. Actual accepted native-prefix presence also remains open.

The root selector takes only the earlier input/answer pairs and the raw trigger.
It parses four salt words, eight bare-root words and all 149 RP06 or 72 HTLC
statement words. Those are unrestricted u64 words, not a proof of statement
semantics. Root-role/counter-zero framing has 161 RP06 or 84 HTLC words. Vector
decoding and final complete re-encoding guards establish literal roundtrip and
exactness. Trigger parsing infers the family, DECS-matrix role and eight-word
seed at any u64 counter from the actual raw frame and also checks re-encoding.
An ordered first-success scan compares each recorded raw digest to `toOutput`
of that seed and parses its key as a typed root context. It does not query the
oracle, inspect a future context, or need a raw-byte-to-word digest inverse.
The word/byte distribution transport remains a separate open obligation.

For a coherent earlier log and a comparator wrapper whose actual oracle hash
equals the trigger seed output, the selector yields that comparator context,
a finite distinct-key raw collision in the earlier keys plus wrapper, or the
actual wrapper's absence from the earlier log with the matching hash equation.
The comparator context is an event/comparison argument, never a selection
input. The generic stopped-root theorem derives log coherence from
`Program.record` internally, while its stopping target remains a parameter.

The join removes that target parameter from its actual-entry API. Its fixed
`rootSnapshot` is literally `selectRoot(before,input)` on the stopped result.
Actual ledger membership derives the stop certificate, snapshot equality,
prior-key-only snapshot replay and root cover. It also derives that the entry
key is exactly the parsed family profile, DECS-matrix role and full eight-word
seed payload with only the counter erased. No supplied desired prefix equality,
context equality, chronology/coherence flag or callback establishes these
results. Successful parsing of the actual trigger and the comparator wrapper's
actual hash-to-seed equation remain explicit premises; they are not a theorem
about whole native Rust acceptance. These are classical generic `Program`
results, with no quantum execution interpretation claimed.

| Component | Theorems | Strict compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Online prefix ledger | 8 | 2.445 / 2.005 | 2604843008 / 2472296448 |
| Root prefix selector | 14 | 2.224 / 2.003 | 2662744064 / 2561835008 |
| Actual-entry root join | 4 | 11.600 / 2.220 | 2682257408 / 2589655040 |

All 26 exported theorems passed strict warnings-as-errors compilation and
serial all-axiom audits using only propext, Classical.choice and Quot.sound.
Checks used one Lean job, a 3500-MiB allocation bound, 120-second wall limit,
4-GiB process-tree RSS ceiling and 10-GiB free-disk floor. No guard fired.
Ledger checking needed one narrow simplification repair; root parsing needed
two narrow elaboration/simplification repairs. Every failed exact source,
command, log and result is retained. The join passed on its first attempt.
No warning/linter was disabled and no source extension followed final checks.

The coordinator read all three complete sources, plans, guards, commands,
metrics and all axiom output. Ledger evidence verified all 114 current project
dependency source/first-resolved object pairs. Root-selector evidence verified
286 modules and 475 current source candidates: 213 project modules and
73 Mathlib modules, with actual first resolutions and cached object hashes.
Join evidence verified all 214 current project dependency source/object pairs,
including both newly integrated direct dependencies. Toolchain and exact
compile/audit LEAN_PATH were verified. Independent bounded read-only reviews
matched exact sources, objects, pins, checks and claim limits without a
substantive gap. Initial root-selector metadata inspection expected a different
collection key, produced no receipt, then verified the actual `imports` list
without source changes. Source and object hashes are separate provenance;
comparing them does not prove cache/source correspondence.

Retained evidence directories are
`/private/tmp/native-launch-online-prefix-ledger-20261005`,
`/private/tmp/native-launch-root-prefix-selector-20261005` and
`/private/tmp/native-launch-online-root-prefix-cover-20261005`.
Root integration receipt SHA-256 values are
`4330e85b35c34e59acdbec059301849d0e348a48149efa61a6a2f528e64bac97`,
`6e5dd1484e8fd68866b30b6a44e2bbd023154de64304e8b4da2bc55dc543b45f`
and `28140290e486b5bc32e24cc55b29a81fdc14f12bf060a25fbcab2c4d8325dee1`.

The first DECS-matrix stage now has a checked generic classical online root
freeze; actual native accepted-prefix presence, source-polynomial extraction
and Rust interpretation remain open. The nonce-aware PIOP chain selector,
whole-response freeze and comparison are checked below. The separate
DECS-opening provenance stage remains to be constructed at its own first
any-counter entry. The DECS failure cover still concerns
actual decoder-none; a decoded low-degree source may violate the transaction
relation, so accepted false-relation coverage is not established. Native search
existence and field/byte/descriptor refinement, mixed quantum histories and
adaptive losses, complete public simulation, shared-query accounting and
reviewed release authority remain open. Runtime circuits/node/protocol match
frozen185a, proof identities are unchanged and all eight production qualification
gates remain OPEN.

Revision note: Record the fixed online classifier and actual-entry root
selection/replay cover, separating checked generic chronology from native
accepted execution, later challenge stages and security/release authority.


## Nonce-aware online PIOP chain provenance

`NativeLaunchOnlineFppPrefixCover` is integrated as
`e0bc3b877107fb39884847612067682ad8388604`.
Its source/object SHA-256 values are
`fe09f64f367d2b13cc4be601e8631ba7944ab32a6f61565a9332115bea07a3f5` and
`55b7073dc89ccde5f542b854b7622f7658818530a0290374a2d4ca90c4a84b6b`.
This checks successful selection provenance and freezing, not the complete
comparison cover suggested by the module filename.

The new trigger parser takes the literal family profile, PIOP-opening role,
nine unrestricted u64 payload words and separate arbitrary u64 raw counter.
The first payload word must fit a u32 nonce; the remaining eight are the full
`h_piop` digest. A final complete raw re-encoding guard proves that every
successfully parsed trigger is exactly its typed frame. No parser roundtrip
or universal parser-success theorem is exported. Raw counters outside capped
sampling groups still belong to the ledger's physical namespace and earlier log.

The fixed selector has only the earlier `Log` input/answer pairs and raw trigger
as arguments. It scans pairs for an exact `piop-transcript` final frame whose
recorded answer matches the trigger digest, then scans the same earlier pairs
for a key whose recorded answer matches that frame's intermediate FPP digest.
It queries no oracle and accepts no wire, matrix, desired context/key or
callback. Comparison uses full raw digest bytes through `toOutput`, without
requiring a raw-digest inverse or a word/byte distribution theorem. Success
derives both recorded pair memberships and the complete final-frame identity.

Actual membership in the online ledger supplies first-stop and earlier-log
coherence internally. Agreement only on actual earlier keys preserves the
stopped result, including its original continuation, and therefore preserves
the fixed chain snapshot. Trigger and future answers need not agree. Given actual successful trigger
parsing and selection, both selected raw hash equations are derived from the
recorded pairs. The exact family/PIOP-opening/nonce-plus-digest prefix is also
derived from actual entry membership, with no supplied desired prefix equality
and no counter-zero restriction. These conditional provenance results do not
assert that selection necessarily succeeds or that its response equals the
later accepted wire's calculated response.

A bounded source inspection pins the current engine hash
`c59e20da61e63b9f3dd2e41da0921df9ef8abd98bbc22bb5dad0ce54ae127193`.
The payload is nonce widened from u32 followed by eight digest words at
lines 13666-13674. The verifier calls canonical opening at lines 5796-5802
before reconstructing PCS/FPP/final hashes at lines 5803-5829. Acceptance thus
does not establish earlier-chain provenance. Honest prover ordering cannot
substitute for adversarial chronology. Canonical nonce search starts at zero
with up to sixteen trials and repeats the winning nonce; failed trials and
rejection counters must remain in actual history. This source inspection is
contextual evidence, not a Rust refinement theorem. The distinct `decs-opening`
hash at lines 12462-12483 concerns `h_piop` plus combination heads/tails, and
cannot serve as this FPP/final provenance.

All six exports passed strict warnings-as-errors compilation on the first
attempt in 2.690 seconds with 2656272384 bytes peak process-tree RSS. Serial
all-six axiom audit passed in 2.019 seconds with 2623045632 bytes peak RSS;
only propext, Classical.choice and Quot.sound occur. Checks used one Lean job,
3500-MiB allocation bound, 120-second wall limit, 4-GiB process-tree RSS ceiling
and 10-GiB free-disk floor. No guard fired, repair was needed or source extension
followed final validation. The coordinator read the complete source, final
plan, guard, commands, metrics and all axiom output, and verified all 215 current
project dependency source/actual first-resolved object pairs, toolchain and
exact compile/audit LEAN_PATH. Independent bounded read-only review matched
the same source/object/pins and precise scope without a substantive gap.
Source/object hashes remain separate provenance, not a correspondence proof;
no fresh aggregate formal build or aggregate CI is claimed.

Retained evidence is under
`/private/tmp/native-launch-online-fpp-prefix-cover-20261005`.
Root integration receipt SHA-256 is
`e4b7b186b0f5d3ccfc0d62aff680fd76565925b56971b4b75015de2427d9f22a`.
The independent review SHA-256 is
`6247bed71fb243d18e7e7f07361c3f99002c00eecb29d85e90cc836203b14a69`.
The source map is retained at
`/private/tmp/native-launch-piop-opening-source-map-20261005/report.md`.

The following two components derive selected-key/calculated-response agreement
or actual finite collisions, actual late final frame or actual late FPP key,
without assuming positive earlier provenance. Conditional chain availability
when both comparator keys occur is derived internally; parser roundtrip and
accepted native-prefix presence remain explicit missing steps. Accepted native-prefix
presence, the third DECS-opening freeze, current-family false-relation coverage,
Rust/field/byte refinement, quantum transport/adaptive losses, complete public
simulation, shared-query accounting and reviewed release authority remain open.
Runtime circuits/node/protocol match frozen185a, proof identities are unchanged
and all eight production qualification gates remain OPEN.

Revision note: Add nonce-aware fixed pair-only selection provenance and actual
entry replay, retaining availability, response comparison and native/security
obligations instead of inferring them from accepted final-digest equality.


## Actual-entry FPP key cover and whole-response freezing

Two further components are integrated as
`1da6dbff1997a3e705c4f2da5597b4b31effa51d` and
`514345a21f251694e727a2a0f88b3f55ebd04162`.
`NativeLaunchOnlineFppComparisonCover` source/object SHA-256 values are
`88ee34cdb39784e27df8af3c07f5f2477863d68fa987d62e91d8062874944e45` and
`5de4d214380415b89b6d0a538f118447612621c52b68614570ebb052cfaf9307`.
`NativeLaunchOnlineFppResponseFreeze` source/object SHA-256 values are
`64120f850129bff17393f0fc55bb8170fb74d4f075367c624fc94f7a38b1e82c` and
`8362e471765a68b97edaca2d6be054d04ccefde8a996f1b3264f6ad722d93d57`.

The key cover removes successful selection as a premise. It starts with actual
ledger membership, successful parsing of the actual nonce-aware trigger, a
physical word-count bound `8 + tail.length < 2^64`, and two actual raw
hash equations for a comparator FPP key and its final frame. Comparator keys,
typed intermediate digest and tail are comparison/event arguments only; none
enters the fixed selector. Membership supplies first-stop and prior-log
coherence internally. If the actual final key is absent, the conclusion retains
that absence and its actual seed hash. If the final key is present but the FPP
key is absent, it retains both membership/absence facts and the actual FPP hash.

When both comparator keys occur, coherence and exact final-frame roundtrip
derive chain availability internally. Either earlier keys plus the two actual
comparator keys contain a distinct-key raw collision, or equal raw outputs
force the selected final key to equal the actual final frame. Complete frame
digest injectivity then identifies the intermediate digest, and the second
finite collision argument identifies the selected FPP key. Success identifies
key, final key and intermediate digest; tail equality is not claimed or needed.
No prior positive key membership, successful selection or coherence certificate
is supplied to the actual-entry theorem. Collision and late-key alternatives
receive no probability bound in this deterministic result.

The response component defines `frozenResponses(before,raw)` as the entire
dependent function across every `Branch`, each with its own bounded five-row
response type. It takes only the earlier recorded pairs and raw trigger.
Selection or decoding failure gives zero at the corresponding branch. Branch
projection, future wire and matrix are later lookup/comparison arguments;
they do not choose the frozen selector or function. Actual ledger membership
and agreement only on actual earlier queried keys preserve the complete
stopped result, and therefore the whole response function, under another
oracle without fixing trigger/future answers.

The response cover applies the key cover to the literal `rebuiltKey` constructed
from the leading digest, full statement, point function, wire and mixing matrix.
Selected key identity internally enables `decode_restored_commitment` and
calculated-response equality. The alternative outcomes are exactly the same
finite raw collision, actual late final frame and actual late FPP key. There
is no supplied response-equality, successful-selection, positive membership
or coherence premise. Actual trigger parsing, trigger-family/branch equality,
the physical tail bound and both actual comparator hash equations remain
explicit. They are not an implementation theorem about native acceptance or
branch canonicality. The whole-function construction prevents an externally
chosen future-dependent branch callback from supplying the response snapshot.

| Component | Theorems | Strict compile / audit seconds | Peak RSS bytes, compile / audit |
| --- | ---: | ---: | ---: |
| Actual-entry FPP key cover | 4 | 2.661 / 2.026 | 2640871424 / 2630909952 |
| Whole-response freeze | 2 | 2.027 / 2.010 | 2637365248 / 2628157440 |

Both components passed strict warnings-as-errors compilation and all-export
axiom audits on their first attempts, with only propext, Classical.choice and
Quot.sound; the finite raw-equality helper uses no axioms. Checks enforced one
Lean job, 3500-MiB allocation bound, 120-second wall limit, 4-GiB process-tree
RSS ceiling and 10-GiB free-disk floor. The response join also finished within
its granted final 90-second validation window. No guard fired, repair occurred
or source extension followed final validation.

The coordinator read complete sources, final plans, guards, commands, metrics
and every axiom result. All 216 current project dependency source/actual
first-resolved object pairs for the key cover and all 217 for the response join
were verified, including the newly integrated direct dependencies, toolchain
and exact compile/audit LEAN_PATH. Independent bounded read-only reviews
matched the same source/object/pins and precise claim limits without a
substantive gap. An initial root metadata reader expected the earlier review's
`material_source_gaps` field; the actual comparison-review schema used
`material_gaps`. No receipt was written before correcting the reader and
verifying the final schema without source changes. Source/object hashes remain
separate provenance, not proof of cache/source correspondence. No fresh
aggregate formal build or aggregate CI is claimed.

Retained evidence directories are
`/private/tmp/native-launch-online-fpp-comparison-cover-20261005` and
`/private/tmp/native-launch-online-fpp-response-freeze-20261005`.
Root integration receipt SHA-256 values are
`7f2b16d600c8b310d071972a89d8a9a2e280ebe0f6ad4e3792783929acd10ef4` and
`b5628b26f6e8458f71653e8ca3ea980b9194964b79dc21836288f8a62d5859b8`.
Together with the nonce-aware selector, this milestone checks twelve exports.

Generic classical online root/context freezing and nonce-aware whole-response
freezing/comparison are now constructed. Successful opening-parser roundtrip,
accepted native-prefix presence, canonical branch/source extraction, the
separate DECS-opening provenance freeze and actual Rust execution refinement
remain open. Calculated response agreement does not imply transaction-relation
validity: a decoded low-degree source may violate the relation. Current-family
accepted false-relation coverage, word/byte distribution transport, mixed
quantum histories and adaptive losses, complete public simulation, shared-query
accounting and reviewed release authority remain open. Runtime circuits/node/
protocol match frozen185a, proof identities are unchanged and all eight
production qualification gates remain OPEN.

Revision note: Derive actual nonce-aware key/response comparison without
positive earlier-provenance or response-equality premises, freezing the entire
branch-indexed function before later comparison while preserving native,
quantum, semantic and release boundaries.


## Constructed native algebra, public codecs and frozen public verification

The following ten additional components have exact source, command, strict
compile, all-export axiom audit, current source/first-resolved import object and
toolchain pins, plus independent bounded source review. Their 86 exports narrow
particular interfaces. They do not close any complete qualification gate.

| Component | Checked exports | Constructed result | Material remaining boundary |
| --- | ---: | --- | --- |
| `NativeLaunchPiopLinearRecompute` | 4 | Seven-node base, normalized six-root correction, six openings and batched target equation from actual inputs | Rust field/branch/array/coefficient/transcript correspondence |
| `NativeLaunchPiopNonlinearRecompute` | 4 | Six-node high-term restoration, batched constraints, masks and cleared-denominator opening equations | Actual native adapter relation and Rust refinement |
| `NativeLaunchOracleOutputEquivalence` | 12 | Bijection between eight unrestricted 64-bit words and 64 bytes; normalized finite event counts are preserved | Adaptive/quantum oracle distributions and shared mixed-history transport |
| `NativeLaunchConstraintAdapterBridge` | 7 | Constructed constant-shifted sparse copy/add/sub/public/product rows have independent arithmetic meanings | Full graph/bit/inverse/range/hash/authorization/application semantics |
| `NativeLaunchPublicProofView` | 13 | Literal SMZB/SMZC complete public byte ordering, eight matrix shapes, 38/58 paths, tapes and nonce | Concrete native Config derivation, full typed wire conversion and public simulation |
| `NativeLaunchSparseCoalescing` | 14 | Explicit duplicate coalescing and zero removal preserve evaluation for every assignment; row semantics and inconsistent empty rows follow | BTreeMap/CSR/field and exact Rust row-omission refinement |
| `NativeLaunchPublicProofParser` | 5 | Constructed canonical raw native prefix/exact parsing, full byte reconstruction, roundtrip and cap/full-consumption checks | All verifier-accepted proof coverage, typed View assembly and Rust allocation order/refinement |
| `NativeLaunchPublicViewCodec` | 7 | Actual Goldilocks byte chunks and all eight typed matrices derive canonicality, exact encoding and prefix roundtrip | Native source/field/configuration refinement |
| `NativeLaunchPublicViewRoundtrip` | 10 | Constructed complete typed View-to-raw ProofWire assembly, derived canonicality and exact encoder equality; exact decoder roundtrip under the explicit total cap | Rust/config/accepted-byte-to-View refinement and public simulation |
| `NativeLaunchSourceConfigBridge` | 10 | Exact audited RP06 and symbolic HTLC dimensions, ShapeGuards, full byte-length formulas and configured roundtrips; RP06 cap derived from aggregate672 bound | Rust Config derivation, public graph row count and compact-path accepted coverage |

The linear constructor includes the seventh zero node and `X^7` high term;
the nonlinear constructor uses six nodes and `X^6`. Neither supplies the
desired reconstruction equation as a premise. Sparse coalescing handles
assignment aliases and initial repeated keys. The parser's canonicality and
size premises are substantive: its soundness theorem derives canonicality
from successful parsing, while its roundtrip only applies to canonical wire
within the explicit branch cap. Its abstract Config does not establish that
Rust selected that Config, and generic authentication parsing occurs before
the native depth refinement, so resource/allocation-order equivalence is not
proved. Whole typed-View assembly now constructs authentication lengths/nodes,
tapes, witness and all eight matrix slots. It derives full payload canonicality
and actual typed/raw encoder equality before applying the capped exact parser;
it does not return a reconstructed typed View or prove every accepted Rust
proof has this typed representation. A whole-public-byte encoder or raw parser
is not a privacy simulator. The Config bridge instantiates RP06 as
`(488,132,140,12,368,736,696)` and HTLC as
`(74,132,140,12,(R+21)/2,R+20,R+10)`. RP06 complete length is
`121105 + 64*authentication_nodes`, deriving164113 bytes from an explicit
aggregate672-node compact bound. HTLC length is
`79957 + 48*R + 40*((R+21)/2) + 64*authentication_nodes`, with separate
`R+10<65536` shape bound and explicit2MiB formula cap. Neither every graph
fitting the wire nor actual Rust/graph-to-Config correspondence is proved.

All final sources passed strict warnings-as-errors compilation and all-export
axiom audits with only `propext`, `Classical.choice` and `Quot.sound`, within
one Lean job, 3500-MiB allocation, 120-second wall, 4-GiB process-tree RSS and
10-GiB disk guards. Failed repair attempts remain retained. The coordinator
read complete final sources, plans, commands, logs and reviews and checked
all actual first-resolved object/current-source pins before integrating exact
source/plan pairs. Separate source and object hashes do not prove cache/source
correspondence. No fresh aggregate formal build or aggregate CI is claimed.
Each source has its maintained `.agent/native-launch-*.md` plan and public
receipts under the corresponding `/private/tmp/native-launch-*-20261005`
directory. The ten-component milestone ends at commit
`e2e3bd89c6aa0d4ef32da9a4aa0a45f283efd12e`.

A separate Linux run used only 20 exact retained public carriers: nine HTLC
carriers across Lock/Claim/Refund and eleven RP06 carriers across ordinary,
approval and final operations. The harness pins the carrier length/SHA-512,
inner-proof SHA-256, relation identity, action and chain context, decodes using
the actual native transport and calls the native verifier without generation
or private inputs. All 20 passed. Six finite wrong-context, relation, proof
mutation, truncation/trailing cases for each of Lock, Claim, Refund and RP06
also rejected, for 24 cases total. These are finite positive/rejection results,
not a universal cryptographic soundness or privacy proof.

The release verifier build passed in 234.906 seconds. The first test stopped
before verification because the harness expected two manifest field aliases
that were absent. Its exact failure receipt/logs are retained. A new manifest
added only `combined_inventory_sha256 = inventory_sha256` and
`source_commit = inventory_source_commit`; every fixture entry, proof byte,
verifier source and executable remained unchanged. The test-only rerun passed
in 19.77 seconds with 234,991,616-byte peak process-tree RSS. Its cgroup
actually enforced 2 CPUs/4 GiB, a 300-second aggregate limit and 10-GiB free
disk floor. All 483 selected public source pins were verified before/after
on Linux and against the integration checkout. The existing rehearsal node
retained PID 708743, zero restarts, original start timestamp and active state.
No deployed CLI, wallet state, proof identity or production profile changed.

| Public verification artifact | SHA-256 |
| --- | --- |
| Frozen native verifier executable | `d6275c958386b4d8bb3a91600b2c4d389b08a611f421b43848b4154d53b84c09` |
| Successful Linux qualification receipt | `2bcdcfa59c8d8d6181767b0e2b6407b3fd8382ee13fdd5b4e9fe2adffb609f56` |
| Successful public test log | `32ec11c4080fc2f5bfe4e3732cfc1f350e000972fe7c411c2b0a824063d36191` |
| Root verification receipt | `40f02e997b390798913edf063a6bc7d08cd1aad5ffb66942b9a6d43b3294cf80` |
| Retained initial failure receipt | `c3d6e307da6d3e2a9f0693eb3d3eaeb60f4ee678a804124c7c54d110c59a41b1` |

The exact harness, manifests and guarded commands are retained under
`/private/tmp/native-launch-gate6-reproduction-20261005/revision-03-root` and
`revision-04-root`; build/failure and successful receipts are under
`/private/tmp/native-launch-gate6-root-verifier-results-20261005/attempt-01`
and `attempt-02`. Distinct hashes alone do not establish independent proof
generation. The public generation and per-stage lifecycle records must still
be joined to exact frozen identities and bytes.

All eight complete gates remain OPEN: transaction relation semantics; actual
accepted Rust-to-model correspondence; composed knowledge soundness; complete
public simulation; shared lifetime query bound; independent frozen generation
and unchanged complete lifecycle; whole-package independent review; and
source-owned release authority. Runtime circuits/node/protocol remain identical
to frozen `185a132b821ad319a49f4a8746c6110ea7ba0476`. No component receipt,
finite test result or completed scoped treasury review grants production
authority.

Revision note: Construct the missing algebra and native public codec interfaces
and add exact frozen public-verifier evidence, retaining the complete semantic,
Rust, simulation, quantum, lifecycle and release obligations.


The user requires step 4 to qualify before step 6. The prematurely overlapping
24-hour Development rehearsal was intentionally stopped after9.19 measured
hours. Its original monitor summary records `operator_stopped_monitor`, all
evidence remains retained, scheduled follow-ups are paused, and all four exact
Development nodes report mining off. Node and wallet state remain available.
This operator stop is not a completed24-hour gate. Step-4 source/proof work
continues independently; no step-6 measurement should restart before step4
qualifies and a start in that order is authorized.


## Fresh wire-codec build and remaining aggregate-build failure

A guarded attempt to rebuild the wider current project dependency graph from
source stopped at `Hegemon.Transaction.SmallWoodProductionConstraintTableGenerated`.
Nineteen preceding modules compiled. The generated table reported kernel
memory exhaustion and compiler join-point failures after94.753 seconds;
the run ended after126.198 seconds without producing that module's object.
Its source and diagnostics remain retained under
`/private/tmp/native-launch-fresh-source-closure-20261005-r2`.
The qualification receipt SHA-256 is
`b55b117055f93d3be22f488b6670454ec7fee9d3f256fa6968e34b86d1c3e757`.
That attempted graph also omitted RP05 source-root discovery, so its142-module
enumeration must not be presented as the complete project graph. There is no
successful aggregate fresh-source build or aggregate CI claim.

The public wire model unnecessarily imported the large response and statement
owners only for three small definitions. `NativeLaunchWireTypes.lean` now holds
the exact four-constructor `Branch`, `queryCount` and `FieldWord` declarations
under their original fully qualified namespaces. The former owners import
this module, and the public view imports it directly. Constructor order,
query counts38/58, Goldilocks modulus, theorem statements and proof bodies are
unchanged. This removes the generated-table dependency from the public wire
build without changing the response-algebra dependency graph.

All ten project modules in the five-root wire closure compiled freshly from
current source into a separate directory containing no cached project objects
or symlinks. The combined45-export axiom audit passed with only `propext`,
`Classical.choice` and `Quot.sound`. That fresh closure plus audit took20.295
seconds and peaked at1,923,203,072 bytes of sampled process-tree RSS. Separate
cached compatibility checks of the changed statement and response owners
passed; they are not fresh-source closure evidence for those owners. All14
successful checks took39.221 seconds of compiler-run time, with the complete
runner elapsed46.981 seconds. One initial compatibility search-path failure
is retained; no Lean source repair was required.

Commands reused cached external library objects. Seven direct external imports
are pinned, and a supplemental source-recursive inventory pins1,776 external
package modules and companion object files. The coordinator verified8,880
external file hashes and the Lean executable hash. That inventory does not
prove full binary-import closure, external source-to-object correspondence or
the complete toolchain installation. Exact evidence is retained under
`/private/tmp/native-launch-wire-types-refactor-20261005`; the independent
patch review is under
`/private/tmp/native-launch-wire-types-refactor-review-20261005`.
Root verification receipt SHA-256 is
`3135dddb650302deae45e2687f355b043d1344a225a33d0747129c846df02541`.

This refactor adds no theorem exports: the prior additional-component total
remains86. It establishes the bounded fresh project wire-build result and
leaves all eight complete qualification gates OPEN. Runtime, proof identities,
production authority and the stopped step-6 rehearsal are unchanged.

Revision note: retain the actual broader source-build failure, remove the
unnecessary wire dependency, and distinguish fresh project objects from
cached external and legacy compatibility inputs.
