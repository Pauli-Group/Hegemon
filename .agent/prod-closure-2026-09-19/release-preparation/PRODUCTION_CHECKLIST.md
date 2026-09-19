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
- [x] Check canonical RP04 leaf-byte injectivity and recorded Merkle opening
  transport, including salt, index, tape, all145 field words and internal nodes.
  Arbitrary raw transcript framing and accepted arithmetic composition remain.
- [x] Check initialized privacy leaf overlap. Full initialized resampling and
  the adaptive whole-view privacy theorem have not yet passed.
- [x] Validate the expanded source manifest: 35 checked roots and79 recursive
  custom dependencies (114 files). Source/hash validation is not a fresh build
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

## Remaining

- [ ] Close accepted-execution readout and four stage-event identifications,
  the algebra-event bound, transcript/commitment binding, and RP04 semantic
  ledger reduction. The universal decoder count is now checked. The actual
  RP04 degree certificate, chronological algebra, raw sampler event densities,
  and recorded-transcript arithmetic chain still need successful integration.
- [ ] Finish adaptive privacy: check initialized resampling, chronological
  DECS/PIOP transport, measured nonleaf composition, and the whole-game
  interpreter identity. Initialized resampling currently hits the existing
  RAM guard; its source is not counted as a checked proof.
- [ ] Connect the completed arguments to the repaired relation and activate
  the fresh-proof route. Wallet multisig and release-profile checks currently
  report missing route authority; their tests remain enabled.
- [ ] Finish CI evidence refresh, including the existing source-review
  checker, and verify the final affected source/artifact lifecycle.
- [ ] Complete the existing release review and mark the PR ready.

Source-only theorem drafts, old snapshot passes, and a passing finite report
are not counted as completed security arguments.
