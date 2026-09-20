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
- [x] Check initialized privacy leaf overlap. Full initialized resampling and
  the adaptive whole-view privacy theorem have not yet passed.
- [x] Check the initialized CMS state, coordinate isometry, database-size
  invariant, and boundedness of the actual raw query run. The concrete
  full-domain resampling theorem remains separate and incomplete.
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
- [x] Validate the expanded source manifest: 54 checked roots and132 recursive
  custom dependencies (186 files). Source/hash validation is not a fresh build
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

## Remaining

- [ ] Close accepted-execution readout and four stage-event identifications,
  the algebra-event bound, transcript/commitment binding, and RP04 semantic
  ledger reduction. The universal decoder count is now checked. The actual
  degree certificate, packed-program canonicality and calculated extraction
  now pass, as do chronological algebra and the recorded PIOP binding adapter.
  Raw sampler event densities and complete accepted-event identification still
  need successful integration. Apply the checked role-specific conditioning,
  active-query embedding and same-execution union to the actual role events;
  live earlier tables cannot be treated as fixed joint advice.
- [ ] Finish adaptive privacy: check initialized resampling, chronological
  DECS/PIOP transport and the whole-game
  interpreter identity. The initialized CMS prefix and extracted per-basis
  collision estimate pass; the global resampling assembly remains under check.
  The seven-constructor initialized-purification/average-acceptance identity
  is written but not checked. The chronological q38 algebra and measured
  application wrapper now pass. The whole-view check has run and exposed finite
  Fourier/measurement proof obligations, which remain under repair.
- [ ] Connect the completed arguments to the repaired relation and activate
  the fresh-proof route. Wallet multisig and release-profile checks currently
  report missing route authority; their tests remain enabled.
- [ ] Finish CI evidence refresh, including the existing source-review
  checker, and verify the final affected source/artifact lifecycle.
- [ ] Complete the existing release review and mark the PR ready.

Source-only theorem drafts, old snapshot passes, and a passing finite report
are not counted as completed security arguments.
