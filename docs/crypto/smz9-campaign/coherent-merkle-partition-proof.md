# Bound the full coherent extraction commutator

This is a bounded living ExecPlan under `.agent/PLANS.md`. It owns only
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentMerklePartition.lean`
and this note; the previously frozen Instrument is not edited in this lane.

## Purpose / Big Picture

Upgrade the concrete binary-reflection estimate to an actual multi-answer
partition-controlled XOR extraction operation. The proof must not multiply
the loss by the number of possible extraction traces or assume the desired
full commutator inequality as a caller-provided field.

## Progress

- [x] (2026-09-07 17:29 UTC) Correct a proposed proof route: `E Q E^-1 - Q`
  does not have zero diagonal answer-register blocks. The earlier binary
  theorem is unaffected. The coordinator was notified about the unproved
  proposal in the frozen note.
- [x] (2026-09-07 17:41 UTC) Prove finite label-sign averaging, Jensen's inequality,
  exact dephasing and the dimension-free `192 I` full permutation estimate.
- [x] (2026-09-07 17:44 UTC) Prove the concrete CMS kernel symmetry under
  equal-label answer translation and remove cutoffs on strict reachable support.
- [x] (2026-09-07 17:48 UTC) Extend to arbitrary superposed targets through exact
  orthogonal slices; instantiate source counting and a faithful full-source codec.
- [x] (2026-09-07 17:49 UTC) Final clean-source strict Lean check exits zero with
  no output. Code frozen. Coordinator will perform the shared-cache/dependency
  audit; no further local Lean process is running.
- [ ] Coordinator dependency audit and shared-cache verification.

## Context and Orientation

The frozen Instrument constructs the faithful complete extraction unitary,
literal byte/bit conversion, a complete Walsh phase system, and a proved
binary-reflection bound `48 I`. Geometry proves `I <= 3t/2^512` from the
source parser and finite raw database. A commutator is the difference between
applying extraction then querying and querying then extracting.

## Plan of Work and Milestones

First average independent plus/minus signs attached to extraction labels.
The average conjugated query retains exactly the matrix entries whose source
and target have equal extraction labels. The remaining matrix has squared
operator norm at most the binary commutator bound by finite Cauchy--Schwarz.
Second prove that the controlled-XOR extraction commutes with the retained
equal-label matrix, directly from the query's workspace-preservation property.
The triangle inequality then gives the conservative full bound `192 I`.
This constant is not represented as the sharper external-paper `80 I`.
Finally instantiate the counting bound and remove the cutoff projections on
explicit strict reachable support. These milestones now pass the strict local
check. `full_answer_actual_query_bound` concerns the concrete CMS query and the
complete answer-register translation, not a Boolean reflection.

`targetBasisEquiv` factors the target register from the remaining CMS basis.
`target_slice_query` proves that the actual kernel preserves these orthogonal
blocks, and `target_slice_extraction` identifies the source extraction action
on each block. Summing the homogeneous bounds gives
`coherent_source_extraction_commutator_bound` without multiplying by the number
of targets or by the number of possible extraction labels.

The principal endpoint is `coherent_faithful_source_commutator_bound`. It takes
an injective encoding of the finite `SourceLabelRange` into the answer group,
and its actual unitary computes that encoding of `sourceRangeValue` into the
answer register. Thus no caller-selected Boolean predicate, extracted object,
full commutator bound, or success probability replaces the source output.
The encoding premise describes only a faithful representation; the earlier
one-hot construction supplies one, with no efficiency claim.

For every finite raw-input universe embedded injectively into literal source
bytes, every target-control value selects at most `t` framed-graph targets.
On states supported on databases of size at most `b < t`, the complete theorem
proves, with arbitrary target/answer/workspace entanglement:

    || E_source O_raw psi - O_raw E_source psi ||^2
      <= (576 t / 2^512) ||psi||^2.

Here `O_raw` is `queryState digestPhaseSystem t`, with the exact 512-bit XOR
output register and complete Walsh phases. The bound is homogeneous; no
normalization premise is hidden. Both temporary database-size projections
are proved to disappear on the stated strict support.

## Surprises & Discoveries

Signs must be attached to extraction labels, not used with an unjustified
zero-diagonal answer-register premise. If two databases have different labels,
`E Q E^-1` can have zero answer-diagonal entry while the original `Q` has a
nonzero entry, so their difference can have a nonzero diagonal entry.

The vector-oracle counter type remains generic. The previously used 523-block
source cap is incorrect for the actual current gamma program, whose replicated
base rows require far more words. Uniformity of one selected 512-bit block,
not the cardinality of the entire vector response, controls the extraction
instability. No current-source vector cap is asserted here.

## Decision Log

Prefer a fully proved conservative dimension-free constant over an unproved
sharper one. The `192 I` route uses the already checked `48 I` binary theorem
and two explicit matrix identities; the classical source instability is not
replaced by an operator-norm assumption.

The published generalized bound is `80 I` in Theorem 5.4 of
[Chiesa, Di, Hu and Zheng](https://eprint.iacr.org/2025/2166.pdf).
This module does not assume that theorem or claim its sharper constant.
It instead proves `192 I`, giving the conservative source numerator `576t`.
The scalar loss is therefore 2.4 times the paper-level `240t` substitution,
before any experiment-specific `t+1` budget convention or game composition.

## Concrete Steps and Validation

From `formal/crypto`, use the warm environment:

    lake env lean -DwarningAsError=true -o /tmp/SmallWoodV8Smz9CoherentMerklePartition.olean HegemonCrypto/SmallWoodV8Smz9CoherentMerklePartition.lean

Require exit zero, no disabled linters, no admitted proof or additional axiom,
and a dependency audit of the final source endpoint. The root coordinator
owns the shared import cache. Scratch artifacts stay below 40 MiB; no oracle
table is evaluated or materialized.

The final local command completed with exit zero and no output at 17:49 UTC.
The coordinator requested that the code remain frozen and will run the audit
after review. The code contains no admitted proof, added axiom, unsafe or
native-evaluation proof shortcut, or disabled linter. The independent sign
worker compiled the sign orthogonality and equal-label averaging identities
in an isolated scratch file; the integrated module passed its own strict check.

## Idempotence and Recovery

Only additive source and a temporary object are produced. No nodes, Rust
builds, retained artifacts, public submissions, proof bytes or release settings
are changed. A failed warm check is repaired locally before promotion.

## Interfaces and Dependencies

The module uses the actual `CmsCompressedOracle.queryState` kernel and frozen
Instrument's `extractionLinearEquiv`, and proves structural kernel equalities
on concrete basis coordinates. Abstract intermediate lemmas accept the already
established binary coarsening estimate; the final source theorem discharges it
using Geometry and the CMS proof. `source_value_instability` derives each
Boolean coarsening's two-sided bound from the changed-output counting theorem,
and `source_one_hot_stable` verifies the existing faithful source encoding's
required deterministic dependence on the complete trace.

The generic CMS theorem permits any finite output group and phase system, so
it can later serve a vector oracle with an arbitrary finite counter type.
The concrete source endpoint proved here is still the raw 512-bit oracle,
not the compiled large-vector oracle. The latter needs its own database/parser
projection and selected-block counting adapter. This proof neither charges one
database record per block nor substitutes the whole vector's cardinality for
the selected raw digest's `2^512` denominator.

## Outcomes & Retrospective

The full multi-answer and coherently target-controlled source bound passes
the strict local check. Its faithful codec is a mathematical finite encoding;
an efficient source trace codec and reversible implementation remain separate.
Accepted-opening binding, the large vector-oracle source adapter, protocol
round chronology, decoder extraction, final game composition and production
release authority are not supplied by this matrix theorem.

Revision note: 2026-09-07 17:32 UTC, initial plan replaces the disproved
answer-diagonal shortcut with label dephasing and a conservative constant.

Revision note: 2026-09-07 17:49 UTC, full source/target-controlled endpoint passes;
code frozen for coordinator audit under the global memory scheduling limit.
