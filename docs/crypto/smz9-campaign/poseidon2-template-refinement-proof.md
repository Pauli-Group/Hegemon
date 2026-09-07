# Prove the Poseidon2 arithmetic templates


This ExecPlan follows `.agent/PLANS.md` and remains a living record of the bounded implementation.

## Purpose / Big Picture


Connect the arithmetic wires replayed from the HGV8RP03 expression program to the pinned width-16 Poseidon2 permutation. A wire is an intermediate field value; a template is the fixed sequence of additions and multiplications producing those values. The observable result is a Lean theorem deriving the kernel output from those individual equations, without assuming that the final hash trace already matches the kernel. This is deterministic arithmetic refinement, not a hash-security or proof-soundness assertion.

## Progress


- [x] (2026-09-07 17:42Z) Read the pinned kernel and obtain the source-owned 72-addition and seventh-power maps.
- [x] (2026-09-07 17:51Z) Define the generic external, seventh-power and internal templates, kernel bridges, and the full round schedule.
- [x] (2026-09-07 18:14Z) Obtain a conclusive strict pass for the local arithmetic and both round-to-kernel interfaces.
- [x] (2026-09-07 18:15Z) Split and freeze the local interfaces for the actual-source replay owner under coordinator authorization.
- [x] (2026-09-07 18:26Z) Complete and strictly check the separate full-schedule composition module; clean check exits zero with no output.

## Surprises & Discoveries


The existing trace-to-permutation theorem assumes the desired trace equality. It cannot discharge the missing template refinement. The source external layer has 28 chunk additions followed by four 11-addition column circuits. Its output offsets are `[9,8,10,6]`, not consecutive wires. The second hash group reverses some constant-addition operands because it reuses constants; commutative field arithmetic must accommodate that.

The first complete strict check hit the explicit 3 GiB Lean memory cap when checking sixteen duplicated internal-sum proofs. The correction proves the sum once and handles the lane lookup symbolically. The earlier external-layer and seventh-power slice elaborated; its only reported issue was an unreachable cleanup tactic, which was removed. One check was cleanly interrupted on the coordinator's aggregate-memory instruction; subsequent checks use the coordinator's allocated single slot.

Plain-pipe diagnostics were buffered. Running the strict check through a terminal and isolating the local block gave a conclusive exit zero in approximately 2.5 seconds, with 153 milliseconds of kernel checking in the profile. The checked local block includes both external and internal round refinement. Full-schedule composition is checked separately with `Elab.async false`, which makes deferred checking easier to locate and does not weaken the proof.

The final composition bottleneck was automatic reduction of the internal-round fold. Explicitly rewriting `List.foldl_cons`, naming intermediate field/natural states, and then applying the induction hypothesis avoids expanding the permutation during equality checking. The final composition module passes with a finite 10,000-heartbeat cap. A generic list-induction lemma reconstructs a list from its indexed entries before specializing to sixteen lanes.

## Decision Log


Decision: place only generic arithmetic refinement in `formal/crypto/HegemonCrypto/SmallWoodV8Smz9Poseidon2TemplateRefinement.lean`; keep actual expression-index certification and source replay in the separately owned semantic-link module. This avoids circular dependencies and makes the assumptions visible. Date: 2026-09-07.

Decision: compare field values with casts of the natural-number kernel outputs. Goldilocks field equality is the semantic notion used by the existing expression interpreter bridge. Canonical natural representatives can subsequently be recovered by uniqueness. Date: 2026-09-07.

Decision: share the internal-sum proof rather than duplicating it for every lane. This preserves the exact claim while keeping kernel checking within the memory cap. Date: 2026-09-07.

Decision: the coordinator authorized one additional file, `formal/crypto/HegemonCrypto/SmallWoodV8Smz9Poseidon2LocalTemplateRefinement.lean`, to freeze the strictly checked local interfaces while composition is corrected independently. Both modules use the same namespace; definitions are moved, not duplicated. Date: 2026-09-07 18:15Z.

Decision: retain explicit one-round unfolding in the induction proof and named intermediate states in the final composition. This controls elaboration without adding assumptions or changing any mathematical statement. Date: 2026-09-07 18:26Z.

## Outcomes & Retrospective


Both modules now have conclusive strict passes: 24 local arithmetic/round theorems and eight composition/list theorems. The final theorem `permutationField_refines_kernel` derives equality of all sixteen output lanes through the pinned initial linear layer and 4/22/4 round schedule. A separate source-aware reviewer checked the 72-addition offsets, seventh-power chain, internal diagonal schedule and premise boundaries without finding a mismatch; the coordinator reviewed and cached the local module. The source replay owner can now instantiate the local gate equations and consume the composed kernel equality. That actual-DAG instantiation remains a separate theorem, as do cryptographic security and production authorization. No runtime, carrier, protocol, configuration or dependency change occurred.

## Context and Orientation


`formal/lean/Hegemon/Transaction/Poseidon2Width16Kernel.lean` defines modular natural-number addition and multiplication, the external `M4 ⊗ P4` layer, the internal diagonal layer, the seventh-power substitution and the complete round schedule. `formal/crypto/HegemonCrypto/Goldilocks.lean` supplies the corresponding residue field. `formal/crypto/HegemonCrypto/SmallWoodV8Smz9ProgramPolynomials.lean` interprets source expression nodes in that field. The new module proves arithmetic identities from the exact local wire equations and exposes them for the source replay owner.

## Plan of Work


First define the four-lane chunk and column operations in the field and prove that the 72 local additions compute those operations. Then establish the modular-kernel cast bridge and seventh-power multiplication chain. Compose these results into round-level interfaces, adding the internal diagonal layer if the source map arrives within the bounded pass. Keep unfinished boundaries explicit rather than introducing a premise equal to the desired result.

## Concrete Steps


Work from the repository root. Edit only this document and the two named Lean modules using `apply_patch`. Ask the coordinator to run the warm strict checks from `formal/crypto`, caching the local module before checking its importer:

    lake env lean -j1 -M 3072 -DwarningAsError=true HegemonCrypto/SmallWoodV8Smz9Poseidon2LocalTemplateRefinement.lean

    lake env lean -j1 -M 3072 -DwarningAsError=true HegemonCrypto/SmallWoodV8Smz9Poseidon2TemplateRefinement.lean

Use the existing dependency cache. Do not build missing dependencies, update Lake, or alter import aggregators. The coordinator owns build scheduling and the memory guard.

## Validation and Acceptance


Acceptance requires strict Lean elaboration with no errors, warnings, admissions or new axioms. Review theorem statements to ensure their premises are individual addition/multiplication equations, not the final kernel equality. Check all four column output positions and arbitrary input field values. Record any unproved actual-source or round-composition link explicitly.

The final clean composition check on 2026-09-07 exits zero with no output. The local module also passed the coordinator's cache build in 2.0 seconds. A source scan finds no `sorry`, `admit`, `axiom`, `native_decide`, or trailing whitespace in either file. The coordinator performs the final imported-axiom audit while caching the composition module; absence of an explicit `axiom` declaration alone is not that audit.

## Idempotence and Recovery


The change is additive and does not modify runtime files or retained proof artifacts. A failed strict check can be repaired within the same two owned files. Do not delete or reset unrelated work. No node launch or substantial build is required.

## Artifacts and Notes


Actual external template bases are group zero `[2036,2252,2468,2684,2900,4364,4580,4796,5012]` and group one `[5100,5300,5500,5700,5900,7310,7510,7710,7910]`. For lane `j`, the output is `base + 28 + 11*(j%4) + [9,8,10,6][j/4]`. These coordinates are inputs to the separately checked actual-source certificate, not assumptions hidden inside the generic arithmetic theorem.

## Interfaces and Dependencies


Use namespace `HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement`. The generic external theorem accepts an input field-valued function and a 72-wire field-valued function satisfying explicit local equations. The kernel bridge accepts an arbitrary list of natural-number representatives. The source owner can instantiate those functions with its replayed DAG values. Imports must be existing cached modules only.

Revision 2026-09-07: created the scoped plan before implementation, recording the source map and the distinction between deterministic arithmetic and cryptographic security.

Revision 2026-09-07 17:51Z: added the internal and full-schedule interfaces and recorded the capped-check correction and independent statement review.

Revision 2026-09-07 18:15Z: recorded the conclusive local strict pass and coordinator-authorized split, preserving the still-unverified full-schedule boundary.

Revision 2026-09-07 18:26Z: closed the full-schedule proof and recorded the clean strict-check result, finite heartbeat cap, and remaining actual-source/cryptographic boundaries.
