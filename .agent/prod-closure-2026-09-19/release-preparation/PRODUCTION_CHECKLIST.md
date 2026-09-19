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
- [x] Reach 49 checked components in the current counting/quantum batch,
  including Hensel root shift, Taylor coefficient height, the full-numerator
  endpoint, actual localized response tracking, Newton truncation, and the
  actual root source with both variable-height bounds and its concrete full numerator.
  Source-manifest validation of the published 53-file bundle also passes.
- [x] Check the formal source hash, both targeted module-parser regressions,
  all 14 governance tests, and the claims/active-progress CLI checks.
  These existing policy checks do not certify the incomplete security proof.

## Remaining

- [ ] Finish kernel validation of the actual global q38 counting theorem and
  concrete extension-field adapter. The source includes the smaller
  1,694,784,843,179 bound and implies the original 12,310,499,043,179 budget;
  neither changes the query count or serialized proof size.
- [ ] Close accepted-execution readout and four stage-event identifications,
  the algebra-event bound, transcript/commitment binding, and RP04 semantic
  ledger reduction. The counted composition source no longer assumes the
  decoder count, but still exposes those specific premises.
- [ ] Finish adaptive privacy: check initialized resampling, chronological
  DECS/PIOP transport, and measured nonleaf composition. The latest split
  leaf-overlap check is below the RSS guard but still fails elaboration
  recursion depth; initialized resampling has not passed.
- [ ] Connect the completed arguments to the repaired relation and activate
  the fresh-proof route. Wallet multisig and release-profile checks currently
  report missing route authority; their tests remain enabled.
- [ ] Finish CI evidence refresh, including the existing source-review
  checker, and verify the final affected source/artifact lifecycle.
- [ ] Complete the existing release review and mark the PR ready.

Source-only theorem drafts, old snapshot passes, and a passing finite report
are not counted as completed security arguments.
