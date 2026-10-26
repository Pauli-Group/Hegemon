# Prove candidate-loop coset disjointness

This scratch ExecPlan follows .agent/PLANS.md; no repository writes are authorized.

## Purpose / Big Picture

An accepted executable field-level candidate check should imply that every interpolation coordinate is unequal to every native coset point. A bounded first-success selector should inherit this guarantee if it succeeds; no existence assertion or exhaustive search is intended.

## Progress

- [x] Read current guards and Rust candidate/descriptor/search source.
- [x] Draft generic field proof and optional first-success model.
- [x] Complete bounded strict compile and all-export axiom audit; retain provenance.
- [x] Release heavy lane immediately after final audit; no further strengthening.

## Context and Orientation

Integration is /Users/pldd/.codex/worktrees/premainnet-integration/Hegemon at c9f2d109de63e1e027d21cf299aa3f473188f44a. Relevant source is circuits/transaction/src/smallwood_engine.rs around 17039-17194. The cached NativeLaunchGuardedPointGeometry defines candidateGuard for a canonical nonzero shift and all coordinates below m; zero is explicitly skipped. Native points are shift times a power of the exact root of order 2^23. Disjoint means these field elements cannot be equal. Current source/object correspondence remains separate from cached-object pins.

## Plan of Work and Milestone

Create NativeLaunchGuardedCosetSelection.lean in this directory. First extract each finite loop check, prove native points nonzero, and prove normalized native points have power 2^23 equal to one. Split coordinate zero explicitly; otherwise the loop check contradicts that power. Then model offset range 0..4095 with List.find?, return m+offset, prove membership, acceptance, failed prefix, safe u64 addition under 0<m<=2^23, and compose returned-shift disjointness.

## Concrete Steps and Validation

Run python3 /private/tmp/native-launch-guarded-coset-selection-20261005/run.py, then MODE=audit python3 /private/tmp/native-launch-guarded-coset-selection-20261005/run.py. Both must exit0 with warningAsError=true, no sorryAx or custom axiom. Runner uses j1/M3500, 120s wall, 4GiB total process RSS, 10GiB disk floor. ps requires approved monitoring access. Do not compile the old root source with unlimited heartbeat options. Audit every exported theorem and release heavy lane immediately.

## Idempotence and Recovery

Only scratch files are written. Preserve each failed exact source, command, result and log before up to three narrow repairs. Stop after final strict+audit pass; no strengthening.

## Surprises & Discoveries

One repair was needed: explicitly rewrite field multiplication order, specify the List.find? predicate, and use if_pos directly for checked addition. The initial failed source, command, log and result are retained in attempt-01.

## Decision Log

Use symbolic finite proofs, cached exact root power theorem, and executable first-success search without enumeration. Distinguish the Nat field model from Rust u64 arithmetic and error returns; safe addition is proved only under valid descriptor geometry.

## Outcomes & Retrospective

All 14 theorem exports passed strict compile (2.453s, peak total RSS 2,684,076,032 bytes, free disk 27,007,754,240 bytes) and axiom audit (2.003s, peak total RSS 2,624,847,872 bytes, free disk 27,007,782,912 bytes). Only propext/Classical.choice/Quot.sound; checked_add_safe uses propext/Quot.sound. The candidate loop implies disjointness for every Fin m coordinate and every Fin (2^23) point; zero is explicit. The first-success selector inherits disjointness and yields a rejected-prefix certificate, offset bounds and safe checked addition under valid geometry. No search-existence proof or executed candidate is claimed. selectedShift models the core first-success loop; the Rust entry zero-count/error behavior is not fully modeled. Rust field/byte/descriptor refinement, causal chronology, QROM, false-relation exclusion and all eight production gates remain open.

## Artifacts and Dependencies

Source, run.py, Audit.lean, exact compile/audit commands and outputs, failed attempts and pins.json are retained here. Depend on the checked NativeLaunchGuardedPointGeometry and exact cached root constants, never old shift388 interpolation facts.

Final provenance: source SHA256 368fef3aa8339c88cc59dda17ab331f9efcbdfb93bdfe2b75b7539e6905af086; object SHA256 f4f1d990deec7e8f391bfdc38553b89c92b845888f1f9c560e463fcc62474174. pins.json contains 92 modules with independently pinned source candidates and actual first-resolved cached objects, plus current Rust source. All object resolutions succeeded. Final plan update records the one repair and completed validation; the compiled source was not strengthened afterward.
