# Production PR checklist — September 19

Deliverable: PR #205, not deployment. The PR remains draft until the security
contract and affected release checks are complete. No new host, network,
universal Rust/compiler/OS proof, or proof-size increase is required.

## Completed

- [x] Push the RP04 authorization/nullifier implementation and q38 lifecycle
  integration (`c022de49`) and checked Lean source bundle (`3275af8c`).
- [x] Preserve the independently randomized retained proof pair and lifecycle
  passes. Proofs are 163,409 / 163,281 bytes against the unchanged 164,113 cap.
  Those passes describe their retained source snapshot, not every later edit.
- [x] Repair the rustls advisory; fresh-database audit and the affected
  integration-target compatibility check pass. No new waiver was introduced.
- [x] Check separately named RP04 Lean program/refinement modules and generate
  their Rust conformance vectors, preserving the RP03 historical evidence.
- [x] Check the three repaired native tests, RP04 coinbase KAT and schedule,
  hash-kernel vectors, executable-ROM report, auxiliary geometry projection,
  and recursive-block verified-record mutation tests.
- [x] Prove the remaining response-universal q38 middle-support counting bound,
  including the actual global incidence assembly and concrete extension-field
  specialization. `universal_badLineLabels_65536` passes Lean; its axiom audit
  reports only `propext`, `Classical.choice`, and `Quot.sound`. No counting
  assumption remains in this endpoint. The global bound 1,694,784,843,179
  implies the original 12,310,499,043,179 budget. The 65,536 support threshold
  is analysis-only: q38, degree405, and serialized proof sizes are unchanged.
- [x] Check joint four-role bad-event composition on one initialized oracle
  execution. Concrete role densities and accepted-claim event inclusion remain
  to instantiate; this is not yet the full accepted-transcript soundness theorem.
- [x] Apply the universal count to the actual140-column MCA matrix and the
  final q38 small-support event. Both local density bounds and their combined
  loss below2^-265 pass Lean and the standard-axiom-only audit. This is local
  decoder accounting, not a265-bit whole-system security claim.
- [x] Check canonical RP04 leaf-byte injectivity and recorded Merkle opening
  transport, including salt, index, tape, all145 field words and internal nodes.
  Arbitrary raw transcript framing and accepted arithmetic composition remain.
- [x] Check initialized privacy leaf overlap. The adaptive whole-view privacy
  theorem remains separate from this local estimate.
- [x] Check the initialized CMS state, coordinate isometry, database-size
  invariant, and boundedness of the actual raw query run. The concrete
  full-domain resampling theorem now also passes, as recorded below.
- [x] Check the extracted full-domain per-basis collision estimate in the
  retained local Lean lane and include it in the source bundle. This does not
  close full adaptive privacy.
- [x] Check all six split RP04 degree-data chunks and the complete combined
  degree certificate, preserving every generated expression and bound.
- [x] Check the generic measured-oracle core, including finite public traces
  and initialized execution. The actual whole-view application remains open.
- [x] Derive the five MCA and twelve LVCS scalar checks on the extracted oracle
  from collision-free recorded Merkle payloads. No decoder-success premise
  is introduced.
- [x] Prove that collision-free recorded paths are recovered by the actual
  least-preimage extractor within its explicit recursion budget.
- [x] Check RP04 packed-program canonicality and all coordinate bounds, then
  its public context, decoded source, actual-program connection, scalar-check
  transport, restored-transcript checks and calculated extraction. The latter
  derives failed extraction from the named decoder/algebra events; it does not
  yet discharge their adaptive quantum probabilities or transcript binding.
- [x] Prove that sufficient extraction fuel recovers the same full subtree at
  each wrapper stage, including readback along recorded wrapper prefixes.
- [x] Check exact role-table conditioning, finite averaging and same-execution
  event union, then the exact conditioned run and its ActiveKey-only oracle
  embedding. Fixed-role queries are private contractions, not oracle calls.
  The final role-bound application to accepted events remains separate.
- [x] Check the chronological privacy algebra with the actual q38 coin
  dimensions and its measured execution wrapper. Whole-game composition remains.
- [x] Check chronological algebraic bad-event accounting and recorded PIOP
  reconstruction, including the omitted linear constant and the actual SMZA
  raw-byte framing/database bridge. Complete accepted-execution integration
  still needs the other role/claim bindings.
- [x] Check the complete seven-constructor whole-view oracle execution identity,
  including the initialized family and literal fresh-input swap. Its existing
  GHHM-bound application still takes an external theorem premise: this identity
  does not by itself close the adaptive privacy bound.
- [x] Check exact canonical word readback and the three chronological RP04
  algebraic bad-cell densities. The capped raw-sampler lift remains separate.
- [x] Check exact SMZA PIOP payload parsing and recovery of all3,105 coefficients
  from the actual canonical bytes. No legacy profile is substituted.
- [x] Prove the role-specific quantum bound on the original full-table physical
  execution, allowing advice from the other role tables through exact finite
  conditioning. The ActiveKey-only CMS query count is unchanged. Actual RP04
  accepted-claim inclusion is the remaining application obligation.
- [x] Check exact FPP coefficient readback while preserving the1104 trailing
  context-binding bytes, and DECS evaluation readback with its368-head/38-tail
  wire order and rotation to interpolation order. No coefficients are inferred
  by misinterpreting DECS evaluations.
- [x] Close the initialized full-domain resampling disturbance estimate from
  the actual CMS bounded-support state. The adaptive continuation/hybrid
  probability bound remains a separate endpoint.
- [x] Check the four-role numerical ledger, including the q38 LVCS count,
  capped quantum stage terms and claimed-output bridge under its stated caps.
  The conservative ledger charges the CMS and transported coupling terms
  separately and proves a stage budget below2^-129, leaving explicit
  headroom above2^-129 for the remaining binding/lifetime losses.
  This arithmetic does not itself identify accepted-failure events or close
  binding and lifetime composition.
- [x] Prove RP04 accepted-program balance over natural numbers, using the actual
  note-call positions1/38/75/78, RP04 CSR links and range reconstruction. No
  legacy RP03 acceptance/refinement premise supplies the result. The RP04
  lifetime ledger now also passes: its cap follows outside the identified
  extraction and commitment-binding failures, with zero semantic-ledger loss.
- [x] Prove that one recorded verifier reconstruction binds every recovered
  candidate: its linear target and omitted-constant correction depend only on
  public inputs. Check the chronological trace labels and DECS interpolation.
- [x] Check reconstructed DECS-head binding, exact recorded wrapper/prefix
  readback, and the generic whole-view continuation probability bound.
  Its application to the actual adaptive privacy game remains below.
- [x] Check exact raw-field sampler fibers, raw Merkle-root readback and the
  five MCA/twelve LVCS accepted scalar checks. The deterministic verifier
  readback passes with its stated collision-free-record/database assumptions.
- [x] Reduce the deterministic verifier readback to a single collision-free
  record relation for Merkle openings and both PIOP hash checks. No separate
  database-equality premise remains in this endpoint. Identifying that event
  in the complete quantum verifier execution remains a separate obligation.
- [x] Check phase/decompression isometry and the selected 512-bit raw-record
  collision bound on an initialized quantum CMS execution. Its loss is
  6*T^3/2^512; at T <= 3*2^64 it is 162/2^320, below the retained 2^-129
  headroom. This is not a proof of Poseidon2 commitment-binding hardness.
- [x] Derive the initialized quantum resampling probability bound through an
  arbitrary phase-game continuation from the actual empty-database execution.
  The total-support invariant, normalization and canonical oracle-family
  representation are proved, not supplied as the desired privacy conclusion.
  Full adaptive request-round composition remains a separate obligation.
- [x] Extend that bound to continuations depending on the same revealed tape.
  The diagonal tape/state/program average is checked with the same loss; no
  independence between the continuation and its tape is assumed.
- [x] Replace the RP04 balance-prefix native evaluation with kernel reduction
  and recheck the lifetime ledger against it. The axiom audit finds no axioms
  for the prefix equality and only standard logical axioms for accepted
  balance and the lifetime-cap endpoint.
- [x] Validate the expanded source manifest: 85 checked roots and134 recursive
  custom dependencies (219 files). Source/hash validation is not a fresh build
  of the entire bundle; individual matched PASS receipts are retained.
- [x] Check the formal source hash, both targeted module-parser regressions,
  all 14 governance tests, and the claims/active-progress CLI checks.
  These existing policy checks do not certify the incomplete security proof.
- [x] Pass the full existing blueprint checker with all 121 review statuses
  still pending. Refresh the current diagnostic report pin and preserve the
  historical RP03 report as a byte-pinned test fixture; successor-authorization
  tests pass without adding a registry entry or changing production flags.
- [x] Fix the formal-checker formatting failure and isolate the three PoW-rule
  fixtures from decoder-only transaction authority. All seven `pow_rules` tests
  pass with their original rejection assertions; no production rule is changed.
- [x] Repair the newly observed transaction-core ceiling-division lint and
  Sled reopen contention in the HX512 persistence test. The focused core
  clippy check and exact-value persistence/restart test pass. The test retries
  only transient `WouldBlock`, with a2-second bound; all data assertions remain.
- [x] Refresh the CI-observed governance input hash and rerun all14 focused
  governance tests successfully. The existing claims checker also passes;
  this does not approve the121 pending source reviews or the security contract.
- [x] Refresh the two subsequent CI-stale policy pins and rerun the retained
  governance test binary: all14 tests pass. No compilation or review-status
  change is involved. Two stale Rust fixture expectations are corrected from
  current RP04 data; those changed tests have not been recompiled or rerun.

## Remaining

- [ ] Close accepted-execution readout and four stage-event identifications,
  the algebra-event bound, and transcript/commitment binding. RP04 natural-number
  balance and the lifetime ledger reduction now pass. The universal decoder
  count is checked. The actual
  degree certificate, packed-program canonicality and calculated extraction
  now pass, as do chronological algebra and the recorded PIOP binding adapter.
  Raw sampler event densities and complete accepted-event identification still
  need successful integration. The role-specific conditioned quantum bound
  now passes on the original physical execution. Apply it and the checked
  same-execution union to the actual role events;
  live earlier tables cannot be treated as fixed joint advice.
- [ ] Finish adaptive privacy: compose initialized resampling, chronological
  DECS/PIOP transport and the whole-game interpreter identity. The initialized
  CMS state, per-basis collision estimate and global resampling assembly pass.
  The seven-constructor initialized-purification/average-acceptance identity,
  chronological q38 algebra and measured application wrapper now pass.
  The remaining whole-game probability bound must be derived rather than
  supplied through `ExternalAdaptiveReprogramming`. The generic continuation
  bound, exact phase-isometry and initialized arbitrary-continuation
  specialization now pass. The remaining link identifies that measured
  continuation with the actual complete leaf-request program on the same
  persistent database, followed by adaptive request-round composition.
- [ ] Connect the completed arguments to the repaired relation and activate
  the fresh-proof route. Wallet multisig and release-profile checks currently
  report missing route authority; their tests remain enabled.
- [ ] Finish CI evidence refresh, including the existing source-review
  checker, and verify the final affected source/artifact lifecycle.
  At published head `71f526aa`, CI still reports stale policy pins, transaction
  fixture assertions, broader Clippy failures, a PoW compatibility failure,
  and the app coinbase timeout. These are not represented as passing.
- [ ] Complete the existing release review and mark the PR ready.

Source-only theorem drafts, old snapshot passes, and a passing finite report
are not counted as completed security arguments.
