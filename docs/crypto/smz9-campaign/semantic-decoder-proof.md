# Bind the packed source projection to typed witness shape

This living ExecPlan follows `.agent/PLANS.md`. The earlier interpreter and dense-range files are frozen for coordinator integration. This lane owns only this document and `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticDecoder.lean`.

## Purpose / Big Picture

Construct the typed witness from the same packed coordinates consumed by the actual Rust decoder, then prove accepted-source shape properties without assuming successful decoding or a canonical typed witness. Preserve the existing `CanonicalWitnessShape` definition; a proved subset must remain labeled as a subset rather than replacing that target.

## Progress

- [x] (2026-09-07 15:55Z) Read the full canonical witness predicate, typed structures, actual Rust decoder, typed parser, and the 721-word source descriptors.
- [x] (2026-09-07 16:00Z) Constructed the total typed source projection matching note, input, output, authorization, and stable source ordering.
- [x] (2026-09-07 16:11Z) Proved fixed sizes, canonical field projections, all four note value bounds, all input direction/position bounds, shared spend-key equality, and actual authorization-mode one-hotness.
- [x] (2026-09-07 16:06Z) Checked all eight exact note value/asset bridge attempts against the full executable CSR records; derived natural source equality for arbitrary accepted packed assignments.
- [x] (2026-09-07 16:04Z) Independent read-only source review found no coordinate, order, or branch-gating divergence in the total projection on the canonical accepted branch.
- [x] (2026-09-07 16:14Z) Final strict Lean source check and seven principal axiom audits passed. Each audited theorem depends only on `propext`, `Classical.choice`, and `Quot.sound`.
- [ ] Full inactive zeroing, nonpadding/selector membership, and active-key nonzero remain the next canonical-witness subfamilies, not premises of the completed theorems.

## Surprises & Discoveries

`CanonicalWitnessShape` contains input/output note shape, inactive zeroing, nonzero and shared spend keys, bounded Merkle positions, canonical siblings, selectors, and 94 canonical stable words. Detailed authorization validity belongs to the separate `V8AuthorizationValid` predicate; it must not be silently folded into or omitted from a complete semantic claim.

The Rust source projection unconditionally decodes note words even for inactive slots. Consequently this module must not manufacture zero notes based only on activity. Actual inactive equations must establish zeroing. The Rust implementation also rejects invalid direction bits and non-one-hot authorization modes; the total source projection below is not permission to skip those checks.

## Decision Log

Use a total typed source projection, explicitly distinct from the Rust validator. Malformed assignments still have a projection; accepted-program theorems must establish each useful fact about it. This avoids a circular decoder-success premise. Decision: 2026-09-07.

## Outcomes & Retrospective

The total typed witness now has concrete, universally proved source-derived properties. All results quantify over arbitrary accepted packed assignments; none assumes honest lowering, typed parser success, or a canonical typed witness. The full `CanonicalWitnessShape` theorem is not yet established, and no complete decoder or semantic adequacy theorem is asserted merely from the existence of the projection.

Completed facts are: two input and two output objects with exact indexed access; every projected note limb, spend-key limb, sibling limb, and stable word is canonical; note keys/rho/randomness and spend keys have length four; each input has 32 seven-word siblings; stable words have length 94; both active inputs project the same spend key; every accepted direction is Boolean and every projected position is below `2^32`; every projected note value is below `2^61`; and the three raw authorization flags form exactly one of `(1,0,0)`, `(0,1,0)`, or `(0,0,1)`. The selected authorization enum follows that accepted triple.

These are actual conjuncts or necessary decoder conditions, not a replacement weakened definition of `CanonicalWitnessShape`. The target definition was left unchanged.

## Context and Orientation

`circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs:3782` constructs 721 typed words from the 43,904-word packed assignment, then invokes the typed parser and semantic surface validator. Sponge block zero reads the initial state directly; later blocks subtract the preceding final state. Note source order is value, asset, recipient, rho, randomness, authorization, whereas typed note order moves authorization before rho and randomness. Input positions pack 32 Boolean direction rows; sibling selection uses those same directions. The decoder derives first-match balance selectors from the public asset list and decodes three raw mode rows as one-hot authorization.

The formal descriptor map in `Poseidon2V8DecoderRefinement.lean` covers 721 source entries but its finite coverage theorems do not prove arbitrary decoder success. The checked `SemanticBinding` and `SemanticDenseRange` modules now provide actual accepted private Boolean/radix-4/zero equations and seven ordinary-integer 61-bit source bounds. Reuse those results, not honest-lowering validation.

## Plan of Work

The completed route constructs each typed component by the exact source formulas, proves generic canonicality for packed reads and sponge subtraction, and proves exact fixed lengths for keys, note fields, sibling arrays, and stable words. Eight exact CSR records bind four note value words and four asset words to raw coordinates. The prior seven-value dense theorem then gives all four decoded note-value bounds. Existing Boolean row theorems feed a proved binary positional-sum induction. For authorization, exact nodes 216/217/218 and 1241/1242/1243 connect the three canonical raw flags to the actual sum-minus-one root; finite case analysis over their already proved Boolean values excludes the five invalid triples.

Next canonical-witness work is genuinely separate. Inactive notes must be zeroed by the 72 activity-gated sponge-word attempts at 15866..15901 and 18386..18421; the projection deliberately does not manufacture inactive zero notes. Inactive input positions and siblings require their own gated direction/raw/inline-right equations. Active note assets require the four zero-product membership roots and first-match selector proof, including explicit exclusion of the canonical padding sentinel. The active spend key still needs nonzero extraction from the selected-key difference/inverse root and its CSR bindings. Only after these are proved can the existing full canonical-witness predicate be assembled.

## Concrete Steps

From `formal/crypto`, use the cached toolchain:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticDecoder.lean

Use one Lean process, no shared cache writes, no Rust builds or installations, and less than 35 MiB new source/scratch. Stop new generation below 40 GiB free disk. The coordinator refreshed `SemanticDenseRange.olean` before this lane imports it.

## Validation and Acceptance

The source must compile without `sorry`, `admit`, new axioms, or `native_decide`. Principal theorems must derive properties from raw packed acceptance or the legitimate canonical-public domain, never assume the desired typed shape or decoder success. Source indices must be checked against the pinned executable graph and sparse attempts. Kernel validity does not discharge actual Rust execution refinement or cryptographic links.

Final validation completed on 2026-09-07 at approximately 16:14Z: the strict source command above passed with warnings as errors and automatic implicit variables disabled. A second read-only stdin check appended `#print axioms` for `accepted_note_source_bridge`, `accepted_input_output_note_value_bounds`, `accepted_project_position_bound`, `accepted_authorization_one_hot`, `accepted_project_authorization_mode`, `project_stable_words_shape`, and `project_note_field_shape`; all seven reported only `propext`, `Classical.choice`, and `Quot.sound`. The new source has no `sorry`, `admit`, `native_decide`, or axiom declarations. It contains 436 lines and 25,063 bytes; the two owned source/document files total less than 36 KiB. No shared cache was built and no Rust build, installation, retained artifact mutation, or Git mutation was performed by this lane.

Immediately after those completed checks, the coordinator reported free disk below the hard 40 GiB reserve (41,361,916 KiB, approximately 39.445 GiB). No Lean process remained active in this lane. Further checks/builds were stopped; only this bounded document update and handoff followed. Preserve all data and restore the reserve before new build/check allocation.

## Idempotence and Recovery

Only the two new files are changed. Preserve all coordinator and other-agent ownership. Repeated strict source checks are read-only; no retained proof, public word list, or packed witness is rewritten.

## Artifacts and Notes

Exact source audits identified note value/asset bridge attempts 15806/15807, 15836/15837, 18326/18327, and 18356/18357. Each has coefficient-one hash-initial source, coefficient-minus-one raw source (root 158), and target zero. Asset membership roots are 916, 992, 1004, and 1023. Authorization mode roots 1236/1238/1240 enforce Boolean rows 92/93/94, and root 1243 enforces their sum equals one.

The eight bridge records are kernel-checked in full, including global index, family, local index, emission kind, terms, and target. The first input uses hash-initial value/asset addresses 18113/18177 and raw 0/64; the second uses 18149/18213 and 2176/2240; the outputs use 29769/29833 against 4352/4416 and 29772/29836 against 5120/5184. Field equality becomes natural equality using canonical representatives, so range transfer is not a modular-wraparound argument.

Independent source review confirms note order conversion, the global call-0 spend key, current accumulator call 98, approval-only next accumulator call 101, policy tag rows `196 + 5*slot + limb`, and all `55+4+28+7` stable source words. Three totalization boundaries remain explicit: position sums correspond to Rust bitwise OR only after Boolean directions; invalid authorization triples project to a fallback whereas Rust rejects them (the accepted one-hot theorem now excludes those); and default reads intentionally totalize indices that Rust length/canonicality checks reject. A verified Rust execution-refinement theorem is still separate from this source review.

## Interfaces and Dependencies

Reuse the fixed semantic structures and source coordinate formulas. `projectTypedWitness` is a total source projection, not a replacement semantic target or Rust acceptance predicate. Keep complete hash links, per-asset integer conservation, detailed authorization, stablecoin arithmetic, and actual execution refinement as separately identified obligations.

Revision note (2026-09-07): Created the typed source projection lane after reading the full semantic target and actual decoder; completed source-bound structural/range/mode families, strict checks, and seven axiom audits; froze verified results when the coordinator reported the disk reserve breach. Complete canonical witness shape and execution refinement remain open.
