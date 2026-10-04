# Derive non-single-key authorization from HGV8RP03

This living ExecPlan follows `.agent/PLANS.md`. The lane owns only the new `SmallWoodV8Smz9SemanticAuthorizationNonSingle.lean` and this document. The strictly checked 466-line `SmallWoodV8Smz9SemanticAuthorization.lean` prefix is permanently frozen. Shared semantic-specification, import/cache, and integration changes belong to the coordinator.

## Purpose / Big Picture

Derive canonical accumulator and signer-tag shape, threshold/count bounds, approval's monotone one-signer update, and final threshold from arbitrary accepted source witnesses. In particular derive the newly explicit `ApprovalSignerBound` from actual membership/tag roots. Exact Poseidon2 family evaluation remains a separately coordinated dependency; these arithmetic results are not a full `V8AuthorizationValid` receipt.

## Progress

- [x] (2026-09-07 18:40Z) Coordinator authorized a separate module and a source-only first checkpoint within 30 minutes and 30 MiB.
- [x] Independently mapped 44 gated Boolean roots, five one-hot families, weighted count fields, current/next bitmap sums, increment/delta roots, and role-nonzero CSR templates.
- [x] (2026-09-07 18:59Z) First source-only checkpoint written and frozen: 771 lines / 46,036 bytes. It includes the 44 gated Boolean words, five natural one-hot sums with explicit no-wrap bounds, six natural bitmap deltas, exact one-change/no-clearing consequences, 30 member/tag limb links, raw `ApprovalSignerBound`, two bitmap/count source sums, and projected approval-count increment.
- [x] (2026-09-07 19:30Z) Strict Lean passed for the Boolean/count/transition module, and ten principal axiom audits returned only `propext`, `Classical.choice`, and `Quot.sound`.
- [x] (2026-09-07 19:32Z) Final clean-source strict rerun exited zero with no output after removing audit commands. Global slot one was explicitly released; source and dossier are frozen.
- [ ] Derive canonical nonzero/distinct signer tags and accumulator shape.
- [ ] Integrate the exact source hash-family equalities to discharge the full target.

## Surprises & Discoveries

The existing target was strengthened centrally after two independently confirmed gaps: transaction-PRF key selection for a second-input-only transaction, and binding the changed approval slot to the selected signer's five-word tag. Runtime/wire behavior did not change. The latter target clause was absent even though the actual source enforces it through one-hot membership bits, bitmap deltas, and five limb equalities per slot.

## Decision Log

Keep the checked structural prefix frozen and derive the non-single continuation in a new module. Source premises are actual packed acceptance and admitted public data; no honest-lowering, canonical-accumulator, or authorization-success assumption may be introduced. Decision: 2026-09-07.

## Outcomes & Retrospective

The arithmetic/transition module has passed strict Lean and ten principal axiom audits. No complete non-single or full authorization theorem is claimed. The original source-only checkpoint has been superseded by the checked 828-line module; coordinator-owned cache and integration work remain separate.

The checked structural endpoints are `accepted_approval_bitmap_transition`, `accepted_approval_count_increment`, and `accepted_approval_raw_signer_bound`. The latter intentionally binds the changed slot to actual raw rows 105–109; it does not identify those words with an independently evaluated transaction PRF. That separate source-frame/evaluation obligation remains explicit. All 44 Boolean and 30 signer expression templates/root memberships are now certified by ordinary kernel-checked decisions, beyond the earlier host-language inspection.

The remaining non-single families are threshold/signer weighted-selector interpretation and ordering, current/next canonical accumulator construction, role-based nonzero policy/intent/tag words, inactive-tag zeros, pairwise active-tag distinctness, final threshold and intent linkage, and exact primitive hash-family composition.

## Context and Orientation

The exact source has 247 replicated raw rows. Authorization rows 92–246 contain mode selectors, current/next openings, count selectors, tags, membership selectors, and pairwise inverses. Source nonlinear node 1234 is approval plus final mode; node 217 is approval. Current and next source openings are reconstructed from exact CSR families 29 and 31 by the frozen prefix.

## Plan of Work

First derive enabled gate values and all 44 Boolean words from exact executable records. Then derive one-hot selector sums and bounded natural weighted counts, using canonical field representatives only after no-wrap bounds. Bind current/next source bitmaps and membership deltas over natural numbers; prove exactly one changed slot and no clearing using their exact six-word lengths. Derive membership tag equality and integrate it with the shared source PRF linkage. Finally derive nonzero role words, inactive-tag zeroing, pairwise distinction, threshold ordering, and canonical accumulators.

## Concrete Steps

The coordinator controls all global Lean slots. Until an explicit grant, use source-only review and edits in the two owned files. Intended strict command from `formal/crypto`:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticAuthorizationNonSingle.lean

No shared-cache output, Rust build, runtime mutation, or git operation is authorized by this lane.

The first check at the unchanged 3072 MiB cap reached the memory limit while reducing the combined 44-entry Boolean certificate. The proof was split into seven bounded Boolean families, five one-hot cases, and six signer-slot families. Subsequent diagnostics were local syntax, renamed list lemmas, and simplifier normalization; these were fixed without changing any source or target predicate. The successful strict run included ten temporary `#print axioms` commands, which were removed afterward without changing any theorem declaration or proof.

The final source is 828 lines / 48,903 bytes, SHA-256 `6decba2d8075c38f2808dd5f8d0a6a4588a0e603b4353ec2a83999ce376ee626`. The clean-source strict rerun after removing the audit commands exited zero with no output at 19:32Z. No `-o` or shared-cache write was used. The earlier 40 GiB pause was explicitly corrected by the coordinator as stale, user-removed guidance; no disk blocker is asserted by this lane.

## Validation and Acceptance

No `sorry`, `admit`, `native_decide`, new axiom, semantic-success receipt, weakened target, or assumed canonical accumulator. Check full source expression records and roots. Source field addition must be lifted to exact natural addition using explicit small bounds before applying bitmap/cardinality lemmas. Equal list lengths must be proved because `List.zip` truncates. Audit principal theorem axioms once strict checking passes.

All ten audited endpoints use only `propext`, `Classical.choice`, and `Quot.sound`:

- `accepted_threshold_flags_sum_one` (line 363)
- `accepted_signer_flags_sum_one` (line 370)
- `accepted_count_flags_sum_one` (line 377)
- `accepted_next_count_flags_sum_one` (line 384)
- `accepted_approval_raw_bitmap_step` (line 416)
- `accepted_approval_bitmap_transition` (line 540)
- `accepted_approval_raw_signer_bound` (line 666)
- `accepted_current_raw_count` (line 784)
- `accepted_next_raw_count` (line 791)
- `accepted_approval_count_increment` (line 816)

The one-hot theorems concern indicator-word sums, not an assumed interpretation of threshold/signer weighted selectors. The bitmap-count theorems independently establish the scalar approval counts as exact natural sums. The cryptographic meaning of raw legacy words, canonical nonzero accumulator/tag shape, and final-spend threshold remain outside these proved endpoints.

## Idempotence and Recovery

Preserve the checked prefix, all other source modules, existing artifacts, and coordinator cache files. An incomplete family remains explicitly open rather than being hidden under a generalized interface.

## Interfaces and Dependencies

The input boundary remains `CanonicalPublicPackedDomain` and `hgv8rp03ProgramComponents.AcceptsPacked`. The output uses the actual `projectAuthorization` and independent `V8AuthorizationValid` components. Shared source Poseidon2-to-kernel and exact family-frame theorems will supply primitive equalities, not authorization success assumptions.
