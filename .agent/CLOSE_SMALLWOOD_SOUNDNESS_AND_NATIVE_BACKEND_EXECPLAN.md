# Close SmallWood Soundness and the Native Backend Gap

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds.

This plan follows `.agent/PLANS.md`. It is deliberately strict about the word "close": a theorem that merely accepts the desired soundness conclusion as an argument does not close a gap, generated examples do not prove a universal claim, and repository-authored prose does not constitute independent cryptanalysis.

## Purpose / Big Picture

At the plan baseline, Hegemon's deployed transaction verifier reached its exact transaction-constraint theorems through one monolithic premise named `DeployedSmallWoodProofSystemSoundnessAssumption`. The native lattice folding backend was separately held at `candidate_under_review`: its verifier checked deterministic fold consistency, but did not prove that folded objects satisfy a CCS relation or that a witness exists. This change narrows or eliminates those two deployed gaps without changing the active transaction or recursive-block wire formats and without introducing Plonky3 or another dead backend into an executable path.

After this work, a reviewer must be able to distinguish three things mechanically:

1. what the production SmallWood verifier actually checks;
2. which mathematical soundness reductions turn those checks into exact-row satisfiability and which primitive assumptions remain; and
3. whether the native backend is production-eligible or provably unreachable from production.

If the native backend cannot gain an actual relation proof and the required independent acceptance evidence in this effort, the closure action is removal from release/executable eligibility, not promotion based on structural fold checks.

## Progress

- [x] (2026-07-15) Created branch `codex/close-proof-soundness-native-backend` from clean `main` at `86a6469f466763cb0df055284bb4abadf51b99da`.
- [x] (2026-07-15) Confirmed 101 GiB free and no pre-existing working-tree changes.
- [x] (2026-07-15) Located the deployed SmallWood soundness boundary in `SmallWoodProductionConstraintRefinement.lean` and the final accepted-block use in `AcceptedSmallWoodBlockComposition.lean`.
- [x] (2026-07-15) Confirmed the native `verify_fold` recomputes transcript challenges, rows, commitments, statement digests, and proof digests but does not verify CCS satisfiability or witness knowledge.
- [x] (2026-07-15) Confirmed the active native quotient is `X^54 + X^27 + 1`, not an irreducible degree-54 field polynomial; its two degree-27 factors explain why a nonzero fold polynomial of degree below five can still be a unit.
- [x] (2026-07-15) Replaced the four floating-point release decisions with exact integer inequalities and bound their active dimensions to Lean-generated facts (`rho = 3`, 1,537 PCS polynomials, 134 by 781 LVCS matrix).
- [x] (2026-07-15) Proved in Lean that the active no-grinding dimensions and all four exact error-term inequalities clear the 128-bit floor, then checked the generated facts against production Rust.
- [x] (2026-07-15) Traced native transaction-leaf admission end to end: the envelope is already part of active artifact compatibility, but acceptance replays the embedded SmallWood proof; native folding is used only by the policy-rejected ReceiptRoot lane.
- [x] (2026-07-15) Froze the exact SmallWood reduction statement against the active Rust profile and corrected the stale `rho = 2` parameter discussion.
- [x] (2026-07-15) Decomposed verifier acceptance into statement/hash, transcript, PCS-opening, AIR-row, extraction, and implementation-refinement stages; the exact-row conclusion now follows from that staged evidence or exposes a named failure.
- [x] (2026-07-15) Proved that native transaction-leaf acceptance is non-authoritative: it requires successful embedded SmallWood verification, and deterministic envelope checks cannot substitute for that proof.
- [x] (2026-07-15) Removed ReceiptRoot/native-fold verification from production registration while retaining fail-closed policy, decoding, and direct research tests needed for compatibility.
- [x] (2026-07-15) Removed native relation/knowledge-soundness and independent-review claims from deployed/release eligibility; unresolved fold/ring work remains explicitly non-production research.
- [x] (2026-07-15) Updated `DESIGN.md`, `METHODS.md`, formal claims, the verification matrix, and release gates to match only the proved result.
- [x] (2026-07-15) Ran the focused and aggregate Lean/Rust gates, exact GitHub core/native-path commands, release build and binary audit, and an isolated current-branch two-node runtime workflow through mining, transfer, private multisig, restart, and clean shutdown.
- [ ] Commit, push, open a ready pull request, and wait for all required GitHub checks to finish green.

## Surprises & Discoveries

- Observation: the active Rust SmallWood profile uses `rho = 3`, while `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md` contains a stale worked section using `rho = 2` and `n_pcs = 1535`.
  Evidence: `smallwood_engine.rs` and the release-profile gate require `rho = 3`; the document's worked mapping says `rho = 2`.

- Observation: `NativeBackendAlgebra.lean` currently turns low-degree nonzero challenge polynomials into units only under the blanket proposition `ActiveLowDegreeUnitAssumption`.
  Evidence: theorem `active_challenge_polynomial_is_unit_under_low_degree_unit_assumption` accepts that proposition directly.

- Observation: the native backend's fold verifier is an integrity/recomputation check, not a proof-of-knowledge verifier.
  Evidence: `verify_fold` has no CCS relation, witness, opening proof, or satisfiability predicate; the repository's `KNOWN_GAPS.md` says the same.

- Observation: the active quotient `X^54 + X^27 + 1` is cyclotomic `Phi_81`, which factors over Goldilocks into two degree-27 irreducibles because the order of the field size modulo 81 is 27. The quotient ring is therefore not a field, but every nonzero polynomial of degree below 27 is coprime to both factors and is a unit in the product ring.
  Evidence: active `GoldilocksFrog` multiplication implements the degree-54 quotient; the existing reduction note identifies the two degree-27 factors.

- Observation: removing the native crate or transaction-leaf envelope outright would break decoding/verification compatibility for active wallet and testnet artifacts.
  Evidence: wallet submissions call `build_native_tx_leaf_artifact_bytes_with_auth`, and node/consensus admission calls `verify_native_tx_leaf_artifact_bytes` before checking the reconstructed transaction statement.

- Observation: the transaction-leaf envelope does not replace SmallWood proof verification. Its verifier decodes the embedded proof, runs the SmallWood verifier, reconstructs the canonical receipt, and only then checks the deterministic native commitment.
  Evidence: `verify_native_tx_leaf_artifact_bytes` rejects before commitment acceptance when embedded SmallWood verification or receipt reconstruction fails.

- Observation: the only consensus mode that invokes native folding as a proof path is `ReceiptRoot`, and production proof policy rejects that mode before registry dispatch.
  Evidence: `ProofPolicy.receipt_root_is_retired` and recursive-block policy tests reject ReceiptRoot payloads.

## Decision Log

- Decision: preserve the active transaction and recursive-block runtime/wire formats.
  Rationale: this is assurance work; changing consensus artifacts would create migration risk unrelated to the requested closure.
  Date/Author: 2026-07-15 / Codex

- Decision: do not add Plonky3, historical proof engines, or new version-suffixed schemas.
  Rationale: none is needed for the two proof obligations, and dead/versioned surfaces would increase audit scope without strengthening the result.
  Date/Author: 2026-07-15 / Codex

- Decision: primitive random-oracle, collision-resistance, and computational-hardness statements may remain named assumptions only when a checked reduction connects them to the deployed verifier; the broad proposition "accepted proof implies witness" may not remain the sole bridge.
  Rationale: Lean cannot prove a computational hardness assumption from first principles, but it can and should prove that the implementation's claimed consequence follows from narrowly stated assumptions.
  Date/Author: 2026-07-15 / Codex

- Decision: native production acceptance requires both an actual relation/knowledge argument and independent acceptance evidence. Internal deterministic-fold proofs alone can close implementation-equivalence tracks but cannot promote the backend.
  Rationale: structural consistency is not proof of satisfiability, and a project cannot independently review itself.
  Date/Author: 2026-07-15 / Codex

- Decision: if the native relation/acceptance requirements cannot be met, close the deployed gap by making the candidate unreachable from release and executable policy rather than preserving an ambiguous future-production switch.
  Rationale: fail-closed removal is a valid deployed-system closure; relabeling an incomplete backend is not.
  Date/Author: 2026-07-15 / Codex

- Decision: preserve native transaction-leaf envelope decoding as a compatibility and integrity layer, but prove and enforce that it has no independent authorization authority.
  Rationale: active artifacts already use the envelope, while their semantic validity is supplied by the embedded SmallWood proof. Removing the envelope would create an unnecessary consensus migration; treating it as a proof system would overclaim its security.
  Date/Author: 2026-07-15 / Codex

- Decision: remove ReceiptRoot verifier registration from the production registry instead of attempting to complete a CCS proof of knowledge in this change.
  Rationale: ReceiptRoot is already rejected by consensus policy, no independent acceptance artifact exists, and structural folding does not establish witness knowledge. Removing dispatch makes the existing policy boundary defense in depth without changing accepted artifacts.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

The SmallWood theorem boundary is no longer one conclusion-shaped implication from verifier acceptance to an exact witness. `KnowledgeSoundnessReduction` exposes five protocol stages, and the production refinement adds an explicit implementation-mismatch branch. The accepted-proof theorem now returns either an extracted witness satisfying the exact generated map or one of six named failure classes. The accepted-transaction and accepted-block no-counterfeit theorems consume structured evidence excluding those failures. Exact Lean and `BigUint` calculations independently check the active `rho = 3`, 1,537-polynomial, 134-by-781 LVCS profile and the sum of all four single-query error terms at the 128-bit work-factor floor; the general theorem accounts for random-oracle query budget rather than claiming a query-independent `2^-128` bound.

The native lattice candidate was not promoted or relabeled as sound. Production transaction-leaf acceptance still decodes the existing envelope for wire compatibility, but now has a checked authority boundary proving that uncached verification and cache reuse inherit successful embedded SmallWood verification. Deterministic commitment and native-leaf checks cannot substitute for that proof. ReceiptRoot/native-fold dispatch was removed from the production verifier registry while the policy rejection and test-only research adapter remain. No accepted runtime or consensus wire format changed.

Local validation completed on the working tree:

- `bash scripts/check_formal_core.sh`: all 14 stages passed; Lean built 2,684 theorem identities, the axiom audit reported zero violations, and all generated Rust conformance vectors passed.
- `./scripts/check-core.sh lint`, `PROPTEST_CASES=64 ./scripts/check-core.sh test`, the eight exact `native-path-tests` commands, and `./scripts/dependency-audit-gate.sh`: passed.
- `HEGEMON_REDTEAM_MODE=ci PROPTEST_CASES=64 bash scripts/run_proving_redteam.sh`: every parser, semantic, SmallWood, recursive-block, receipt-root, network, and review-package test passed; the final package-generation command correctly stopped because the source tree was not yet committed. The same command must be rerun on the clean commit.
- `./scripts/check-core.sh build` and the release PQ binary audit: passed; the shipped dependency and executable graphs contain no Plonky3.
- `./scripts/check-app-no-ssh-e2e.sh`: passed with two branch-built nodes synchronized through height 39, three ordinary sends, consolidation, private multisig setup/approval/finalization, persisted balances after relay restart, and clean process shutdown.
- Disk remained bounded: 90 GiB free with a 10 GiB rebuildable `target/` tree after all local builds.

Residual boundaries remain explicit. The staged theorem is a reduction, not a proof of random-oracle, hash-collision, PCS-binding, AIR polynomial, or extractor hardness assumptions from first principles; its paper model is classical-ROM rather than a QROM proof. Complete arbitrary Rust/compiler/native-node refinement also remains outside the theorem. The native lattice backend still lacks a CCS proof of knowledge, collision reduction, and independent cryptanalytic acceptance, so it remains research-only and has no production authorization or aggregation dispatch.

## Context and Orientation

The active deployed proof selector is `SmallwoodCandidate`; accepted recursive blocks use `recursive_block_v2`. At the plan baseline, `formal/lean/Hegemon/Transaction/SmallWoodProductionConstraintRefinement.lean` defined `DeployedSmallWoodProofSystemSoundnessAssumption` as a direct implication from verifier acceptance to existence of witness values satisfying the exact generated production map, and `formal/lean/Hegemon/Consensus/AcceptedSmallWoodBlockComposition.lean` consumed that implication for every accepted proof in the block. The implementation now replaces that premise with staged reduction evidence and explicit named failure classes.

`formal/lean/Hegemon/Transaction/SmallWoodVerifierSoundnessEnvelope.lean` already names several residual components, but most are bare `Prop` fields. The relevant Rust verifier is in `circuits/transaction/src/smallwood_engine.rs`; its trace structures expose transcript, PCS opening, row, and commitment data that can support production conformance.

The native research backend lives in `circuits/superneo-backend-lattice`. `fold_pair` constructs deterministic folded rows and digests; `verify_fold` recomputes them. `formal/lean/Hegemon/Native/NativeBackendAlgebra.lean` currently proves challenge-range arithmetic, conservative norm bounds, canonical coefficients, and equality uniqueness. Release posture is governed by `scripts/check_native_backend_release_posture.sh` and the review package under `audits/native-backend-128b`.

The formal completion ledger is `config/highest-standard-formal-verification-matrix.json`, and theorem identity enforcement is in `scripts/hegemon_formal_core/src/lib.rs`.

## Plan of Work

### Milestone 1: Freeze the real SmallWood claim

Record the active parameters directly from production, obtain the SmallWood protocol's primary-source soundness statement, and map every mathematical symbol to the exact Rust operation. Correct stale documentation. Add a fail-closed machine check that the profile used by the proof and verifier equals the profile used by the soundness calculation.

Acceptance requires exact active constants, no floating-point comparison at the release boundary, and a checked mapping for every error term. A prose parameter table is insufficient.

### Milestone 2: Derive exact-row extraction from narrow assumptions

Introduce an executable Lean model for the deployed verifier's acceptance decomposition. Its inputs must be concrete proof/statement/trace data, not pre-asserted booleans named after desired conclusions. Prove that acceptance plus narrowly stated PCS binding, Fiat-Shamir/random-oracle, hash binding, AIR algebraic soundness, and extraction reductions yields witness rows satisfying the generated exact map. Bind representative and adversarial traces to the production Rust verifier, and enforce source/theorem identities in formal-core.

The broad `DeployedSmallWoodProofSystemSoundnessAssumption` may remain as a compatibility alias only if it is *derived* by theorem from the narrower reduction certificate. The final block theorem must consume the derived result, not ask callers for both the old broad implication and the new components.

### Milestone 3: Prove native transaction leaves are non-authoritative

Model the ordered native transaction-leaf admission stages and prove that acceptance implies successful embedded SmallWood verification. Bind the model to production decision vectors, including malformed envelopes, invalid embedded proofs, mismatched receipts, and commitment substitutions. The deterministic lattice commitment may remain as artifact integrity metadata, but no theorem or claim may treat it as proof of relation satisfiability or witness knowledge.

### Milestone 4: Resolve native production eligibility

Remove ReceiptRoot verifier dispatch from the production registry and prove the active SmallWood/recursive-block policy cannot select native folding. Retain transaction-leaf envelope verification only for active artifact compatibility and only after embedded SmallWood verification. Reclassify unresolved quotient-unit, collision-reduction, and CCS-knowledge work as non-production research rather than open deployed-verification claims.

### Milestone 5: Claims, documentation, validation, and publication

Update `DESIGN.md`, `METHODS.md`, the theorem matrix, claims, and release evidence to the exact achieved result. Run all focused and full gates, then a local node smoke test using the current branch. Check disk space before and after large builds. Commit coherent milestones, push once the branch is locally green, open a non-draft PR, and wait for every required GitHub check to finish.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Focused Lean builds should use:

    cd formal/lean
    lake build Hegemon.Transaction.SmallWoodVerifierSoundnessEnvelope Hegemon.Native.NativeBackendAlgebra

Focused Rust checks should use exact test filters for `transaction-circuit` and `superneo-backend-lattice`; avoid broad duplicate builds until the focused surfaces pass.

The full local gates are:

    bash scripts/check_lean_formal.sh
    bash scripts/check_formal_core.sh
    bash scripts/check_native_backend_release_posture.sh
    git diff --check

The runtime smoke must build and execute the current checkout, not a stale binary. It must verify active proof policy, genesis, mining/import, and clean shutdown without selecting the native research backend.

## Validation and Acceptance

The work is accepted only if:

- final accepted SmallWood block soundness is derived from a production-bound reduction with primitive assumptions named at their real cryptographic boundary;
- exact soundness arithmetic is machine checked and uses the active `rho = 3` profile;
- no theorem accepts exact witness satisfiability as an unexamined premise while being counted as closure;
- native transaction-leaf acceptance is proved to require embedded SmallWood verification and cannot derive authority from deterministic envelope checks;
- native folding release eligibility is impossible by checked policy and absent production dispatch;
- active runtime and consensus wire formats are unchanged;
- Plonky3 is absent from the shipped dependency/executable path;
- all local and required GitHub checks are green.

## Idempotence and Recovery

Generated vectors must be deterministic. Re-running generators and package checks must leave the tree unchanged. Do not reset or clean unrelated user work. If disk usage grows materially, remove only rebuildable `target` outputs after recording which validation has completed.

## Artifacts and Notes

Record exact paper theorem/section references, active parameter values, generated-vector hashes, release-package hashes, test transcripts, and runtime smoke evidence here as they become available.

## Interfaces and Dependencies

Prefer new theorem records that carry concrete protocol data and implications over collections of unrelated `Prop` flags. Any remaining cryptographic assumptions must be named by primitive or reduction boundary. The final SmallWood theorem should expose the same no-counterfeit conclusion currently consumed by consensus, so runtime code does not change.

The native release policy interface must remain fail closed. No internal command may manufacture the external acceptance artifact it verifies.
