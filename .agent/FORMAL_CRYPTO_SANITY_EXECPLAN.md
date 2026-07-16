# Establish a Non-Vacuous Lean Cryptography Boundary

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds. Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon currently has an extensive dependency-free Lean model that binds production SmallWood constraint tables, transaction semantics, proof bytes, and accepted-chain composition to Rust conformance tests. It deliberately leaves primitive proof-system knowledge soundness as an assumption. This change adds an isolated research package that states the missing cryptographic claim with an explicit adaptive standard-QROM game interface, defines the underlying customizable constraint system (CCS) relation in a conventional mathematical form, and proves that its declarative and executable relation checks agree.

After this work, a reviewer can run one command and observe four facts: the research package builds under pinned dependencies; the CCS relation has a proved executable checker; a non-vacuous knowledge-soundness target is bound to the exact SmallWood production relation but not falsely marked proved; and no runtime crate or production proof registry depends on the research package. This is a sanity check and architectural foundation, not a claim that the deployed SmallWood PIOP, LVCS/DECS polynomial commitment scheme, Fiat-Shamir transform, or extractor is now formally proved.

## Progress

- [x] (2026-07-16T04:13:35Z) Audited the current branch, Hegemon Lean package, SmallWood production refinement, and active runtime boundary.
- [x] (2026-07-16T04:13:35Z) Inspected ArkLib and VCVio release interfaces as candidate theory inputs.
- [x] (2026-07-16T04:43:27Z) Implemented the isolated `formal/crypto` Lake package.
- [x] (2026-07-16T04:43:27Z) Defined canonical CCS syntax, declarative satisfaction, executable satisfaction, and proved their equivalence without local axioms or placeholders.
- [x] (2026-07-16T04:43:27Z) Bound the SmallWood knowledge-soundness target to Hegemon's exact production constraint relation.
- [x] (2026-07-16T04:43:27Z) Added a fail-closed research/release posture declaration proving that an unproved target cannot authorize a production security claim.
- [x] (2026-07-16T04:43:27Z) Added a deterministic gate covering local placeholders, transitive theorem axioms, dependency pins, package isolation, and focused adversarial relation cases.
- [x] (2026-07-16T04:43:27Z) Added dedicated formal-crypto architecture and package documentation with the exact assurance boundary and promotion obligations; common production evidence documents remain unchanged to avoid unrelated review-digest churn.
- [x] (2026-07-16T06:00:50Z) Ran the initial focused package gate, existing Lean validation, complete formal-core gate, workflow syntax checks, and an adversarial diff review locally.
- [x] (2026-07-16T09:00:00Z) Removed ArkLib from the build after CI showed that its classical straight-line definition forced an unrelated one-hour dependency build and still did not state the required QROM theorem.
- [x] (2026-07-16T09:00:00Z) Replaced the imported baseline with a local relation-bound standard-QROM target carrying `q_H`, `q_P`, the exact extraction-failure event, and an exact rational loss.
- [x] (2026-07-16T16:00:00Z) Re-ran the reduced package gate in 13.18 seconds with all thirteen credited declarations, adversarial examples, dependency checks, and runtime-isolation checks passing.
- [ ] Finish the path-scoped GitHub check green within its 30-minute budget.

## Surprises & Discoveries

- Observation: `formal/lean/lake-manifest.json` has an empty package list, so the current Hegemon model intentionally uses only Lean core and remains cheap to build.
  Evidence: the manifest contains `"packages": []`.

- Observation: ArkLib tag `v4.30.0` matches Hegemon's Lean toolchain and supplies classical probabilistic knowledge-soundness definitions, but some unrelated and supporting declarations in the tagged tree still use `sorry`.
  Evidence: ArkLib commit `e6d77b18ca1334a91faf4d1ccf9f96d854d58ba4` uses `leanprover/lean4:v4.30.0`; source inspection found unfinished declarations in `ArkLib/OracleReduction/Execution.lean`, `ArkLib/OracleReduction/Security/RoundByRound.lean`, and other modules.

- Observation: the current `SmallWoodKnowledgeSoundnessReduction` is an explicit assumption decomposition rather than a probabilistic extraction proof.
  Evidence: `KnowledgeSoundnessReduction.airRowsToWitness` is supplied as a field, and production evidence supplies `noNamedSoundnessFailure`; neither definition quantifies over adversarial provers or bounds a bad-event probability.

- Observation: a cold ArkLib/Mathlib dependency tree is operationally large even when Hegemon imports only the basic security definition, and GitHub did not finish it within 60 minutes.
  Evidence: the resolved `formal/crypto/.lake` tree occupied 8.2 GiB locally; CI was still at build item 2,641 when its one-hour timeout cancelled the job.

- Observation: kernel-checking the adversarial examples was necessary for a strict axiom allowlist.
  Evidence: `native_decide` initially introduced one generated axiom per example; replacing it with `decide` reduced every credited declaration to `propext`, `Classical.choice`, and `Quot.sound` only.

- Observation: the first gate draft left its root import file outside the lexical trust-bypass scan and did not independently pin the credited declaration inventory.
  Evidence: adversarial review showed `HegemonCrypto.lean` was outside the initial `find` root and the list file could be shortened consistently with the audit output. The final gate scans every local Lean source, fixes the exact six-file and ten-theorem source inventory, and compares the thirteen credited declarations to an in-script fixed list.

- Observation: FRI is not part of the active SmallWood transaction-proof backend.
  Evidence: the executable path in `circuits/transaction/src/smallwood_engine.rs` uses the SmallWood PIOP and LVCS/DECS hash-based PCS, and neither that path nor its active proof-options or no-grinding model contains a FRI layer. The architecture therefore names the actual SmallWood components and does not inherit terminology from other proof paths in the repository.

- Observation: ArkLib's imported target is straight-line, single-execution knowledge soundness and is not itself the final deployed Fiat-Shamir claim.
  Evidence: `Verifier.knowledgeSoundness` consumes one verifier execution and a straight-line extractor. The final Hegemon theorem must separately model adaptive multi-theorem non-interactive proofs in the classical ROM and QROM before refining canonical bytes and Rust acceptance. Simulation extractability is a distinct stronger game required only by a consuming proof that exposes simulated proofs.

- Observation: changing common production evidence documents for this isolated research proposal causes unrelated release-review digest churn.
  Evidence: a temporary `DESIGN.md`/`METHODS.md` edit changed review digests for many unrelated blueprint nodes. Those edits and the temporary digest update were removed; the dedicated architecture document now owns the research design, and the unchanged production blueprint passes directly.

## Decision Log

- Decision: Keep `formal/crypto` as a separate Lake package that depends on `formal/lean`, never the reverse.
  Rationale: this makes the research relation able to reuse the exact production model while making it structurally impossible for an unfinished research theorem to enter the shipped runtime or lightweight proof gate through an import.
  Date/Author: 2026-07-16 / Codex.

- Decision: Do not make ArkLib a build dependency of the sanity package; state the exact Hegemon target locally and treat published libraries and papers as theory inputs until a concrete reduction is mechanized.
  Rationale: ArkLib's imported definition was classical, straight-line, and weaker than Hegemon's required adaptive QROM target. Building its broad dependency tree consumed an hour without adding a QROM theorem or production assurance.
  Date/Author: 2026-07-16 / Codex.

- Decision: Do not add a theorem asserting SmallWood knowledge soundness in this sanity-check change.
  Rationale: the prover, verifier rounds, extractor, PCS binding reduction, Fiat-Shamir security proof, and concrete error composition do not yet exist in Lean. A theorem at this stage would necessarily assume the missing result or prove a weaker statement.
  Date/Author: 2026-07-16 / Codex.

- Decision: Use semantic module names and parameter records rather than numbered module revisions.
  Rationale: incompatible research states are represented by immutable dependency commits and explicit parameter values, avoiding version-suffix proliferation and ambiguous authority.
  Date/Author: 2026-07-16 / Codex.

- Decision: Split continuous enforcement into an always-on lightweight isolation workflow and a path-scoped full research build with a 30-minute hard timeout.
  Rationale: reverse-dependency drift is production-critical and cheap to check on every PR; the path-scoped target should build only Hegemon's local formal dependencies and must fail rather than consume an unbounded runner.
  Date/Author: 2026-07-16 / Codex.

## Outcomes & Retrospective

The isolated package is adversarially gated. `HegemonCrypto.CCS.System.satisfiesB_iff` proves generic declarative/executable CCS equivalence; five kernel-checked examples reject coefficient, omitted-factor, duplicated-factor, and witness mutations; `HegemonCrypto.SmallWood.relationB_iff` binds the executable relation to the exact production predicate; and `HegemonCrypto.SmallWood.KnowledgeSoundnessTarget` states, but does not prove, the adaptive standard-QROM bad-event bound. The package's thirteen credited declarations are audited against the kernel axiom allowlist.

The architecture review also records the exact next theorem ladder: production-to-CCS equivalence, interactive completeness and extraction, adaptive multi-theorem classical-ROM knowledge soundness, separate adaptive QROM knowledge soundness, canonical byte decoding, exact Rust refinement, and one final production bad-event bound. Simulation extractability remains a separate conditional property. The local target prevents a weaker imported classical baseline from being mistaken for the deployed non-interactive theorem.

Final local validation after removing ArkLib passed:

- `bash scripts/check_formal_crypto.sh`: passed in 13.18 seconds with thirteen exact declaration audits, fixed source inventory, local-only dependency checks, standard-QROM target checks, and open production posture.
- `bash scripts/check_lean_formal.sh`: 2,684 claimed theorems, zero temporary axioms, zero unwaived dependencies, and zero budget violations.
- `bash scripts/check_formal_core.sh`: all fourteen stages, 123 blueprint nodes, 11/11 native backend vectors, independent bridge vectors, and candidate-under-review native backend posture.
- `git diff --check`, JSON parsing, Bash syntax, and Ruby YAML parsing: passed.
- Adversarial diff review: no reportable runtime or cryptographic-authority finding after fixing the two checker inventory bypasses described above.

The obsolete local ArkLib build tree is untracked and independently removable. The result is not cryptographic closure: exact production-to-CCS refinement, concrete protocol completeness, extraction, commitment and PCS reductions, Fiat-Shamir ROM and QROM proofs, primitive security, concrete parameter composition, canonical serialization, Rust refinement, executable side-channel/randomness hardening, and independent cryptographic review are still open by construction.

## Context and Orientation

`formal/lean` is Hegemon's existing Lean package. `Hegemon.Transaction.SmallWoodProductionConstraintRefinement` defines the exact generated production constraint map over canonical Goldilocks field representatives stored as natural numbers. `Hegemon.Transaction.SmallWoodKnowledgeSoundnessReduction` decomposes the currently assumed proof-system boundary into named failure predicates. `scripts/check_lean_formal.sh` and `scripts/check_formal_core.sh` build that package and bind many executable specifications to production Rust tests.

A customizable constraint system, abbreviated CCS, consists of matrices, coefficients, and multisets of matrix indices. A vector satisfies the system when, at every row, the weighted sum of products of selected matrix-vector evaluations is zero. A proof of knowledge must do more than establish verifier acceptance: it must provide an extractor and bound the probability that a malicious prover causes acceptance while extraction fails to produce a satisfying witness.

The new `formal/crypto` package is research-only. Its only direct dependency is the existing Hegemon production model in `formal/lean`; it does not import an external proof library. It is not linked into a Rust crate, consensus verifier registry, node binary, or release proof policy.

## Plan of Work

Create `formal/crypto/lean-toolchain`, `formal/crypto/lakefile.toml`, and `formal/crypto/HegemonCrypto.lean`. Use only the local `../lean` package for exact Hegemon definitions.

In `formal/crypto/HegemonCrypto/CCS.lean`, define CCS over a field with finite row, variable, matrix, and term index types. Preserve repeated factors with `Multiset`. Define a proposition-valued row equation and a boolean checker under decidable equality. Prove row-level and system-level equivalence and include small positive and adversarial examples covering a changed coefficient, omitted factor, duplicated factor, and malformed witness assignment.

In `formal/crypto/HegemonCrypto/SmallWoodRelation.lean`, define the input relation by directly reusing `ExactProductionConstraintMapEvaluates`, rather than translating the production map into a lossy new representation. Add an explicit future refinement interface for a proved conversion from the production sparse expression program to canonical CCS. The interface must not be inhabited or treated as evidence in this change.

In `formal/crypto/HegemonCrypto/KnowledgeSoundnessTarget.lean`, define the standard-QROM model choice, `q_H` and `q_P` budget, accepted-without-extracted-relation-witness event, abstract event-probability interface, and exact rational loss. The target must require all of them without asserting that a deployed verifier satisfies it. Define a release posture whose only current state is research-open and prove that this posture cannot authorize a claim that the target is closed.

Add `scripts/check_formal_crypto.sh`. It must require the exact local direct dependency set, verify immutable transitive dependency pins, reject placeholders and declared axioms in `formal/crypto`, build the package, run focused examples, collect axioms for every credited local theorem, reject `sorryAx`, and verify by dependency-graph inspection that no Cargo manifest or existing `formal/lean` Lake file refers to `formal/crypto` or an external research library. Run it in a dedicated path-scoped CI job with a 30-minute timeout; deleting or skipping the gate must fail that job.

Update `DESIGN.md`, `METHODS.md`, and `formal/lean/README.md` to distinguish three layers: production semantic refinement, the named proof-system assumption boundary, and the isolated probabilistic research target. Do not change runtime routing, proof bytes, consensus formats, genesis, storage, or networking.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    bash scripts/check_formal_crypto.sh

The command must end with a single success line and report the explicit standard-QROM target, the local declaration count audited, and the open research posture. It must fail if a local theorem contains `sorry`, if a credited theorem depends on `sorryAx`, if dependency revisions drift, or if runtime code starts depending on the research package.

Then run:

    bash scripts/check_lean_formal.sh
    bash scripts/check_formal_core.sh
    git diff --check

The existing gates must remain green. No node restart or network migration is required because this work changes no executable runtime path.

## Validation and Acceptance

Acceptance requires all of the following observable behavior. The CCS positive example evaluates to true. Mutating a coefficient, omitting a factor, duplicating a factor, or changing the witness causes the corresponding negative checker result. Lean proves the checker equivalent to the proposition-valued relation for every finite CCS instance. The SmallWood target requires the standard QROM, explicit adaptive query budgets, exact extraction-failure event, and exact production relation. No theorem claims that target is satisfied. Axiom collection reports no `sorryAx` for local credited declarations. A repository dependency scan proves no shipped Rust package or existing Hegemon Lean package imports `formal/crypto` or an external research library. Existing formal-core remains green, and the complete GitHub check finishes within 30 minutes.

## Idempotence and Recovery

Lake dependency downloads and builds are repeatable. The new package has its own `.lake` directory and can be removed with `rm -rf formal/crypto/.lake` without touching runtime artifacts or `formal/lean/.lake`. The validation script must use temporary files with cleanup traps. If disk availability falls below 8 GiB, stop before building dependencies and remove only `formal/crypto/.lake`; do not clean unrelated user worktrees.

## Artifacts and Notes

Primary research sources and candidate libraries are recorded in `docs/FORMAL_CRYPTO_ARCHITECTURE.md`; none is a direct build dependency or receives theorem credit in this sanity package.

## Interfaces and Dependencies

`HegemonCrypto.CCS.System` must expose dimensions, matrices, coefficients, and factor multisets. `HegemonCrypto.CCS.Satisfies` must be the declarative relation. `HegemonCrypto.CCS.satisfiesB` must be executable. `HegemonCrypto.CCS.satisfiesB_iff` must establish their equivalence.

`HegemonCrypto.SmallWood.Relation` must be a `Set` of production statement and witness pairs backed directly by `ExactProductionConstraintMapEvaluates`.

`HegemonCrypto.SmallWood.KnowledgeSoundnessTarget` must require `OracleModel.standardQrom`, `QueryBudget.quantumHashQueries`, `QueryBudget.priorProofInteractions`, `ExtractionFailure`, and a nonnegative exact-rational `ConcreteLoss`. The file may define the target; it must not provide an inhabitant or theorem asserting the target for the deployed verifier.

Plan revision note: created 2026-07-16 to separate canonical cryptographic research definitions from Hegemon's existing deterministic production-refinement package and prevent assumption-shaped proofs from receiving security credit. Revised 2026-07-16 after CI proved the ArkLib baseline both too weak for the QROM target and too broad for the 30-minute build budget.
