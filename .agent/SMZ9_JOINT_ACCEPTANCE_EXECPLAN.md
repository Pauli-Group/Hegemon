# Prove the joint SMZ9 acceptance and extraction bounds

This is a living ExecPlan under `.agent/PLANS.md`, continuing
`.agent/SMALLWOOD_POSEIDON2_PRODUCTION_EXECPLAN.md` from commit `2fdab7e0`.

## Purpose / Big Picture

The user authorized immediate work on the actual probability that accepted
SMZ9 proof bytes fail to yield a valid HGV8RP03 witness. A malformed committed
table alone is not that event. This milestone must produce checkable mathematical
progress on the actual sampling experiment and test the proposed extraction
claims adversarially. It must not promote the current compact profile using the
already-refuted fixed-residual shortcut.

The unchanged target is the 686-row, 368-column HGV8RP03 relation with its
120 public words, SMZ9 profile 6, five DECS matrix rows, 140 data rows and five
mask rows, degree 387, the `2^23`-point Goldilocks coset, and twenty openings.
The source maximum remains 122,863 proof bytes. Production capability remains
absent. No wire, parameter, dependency, deployment or publication change is
authorized by this research milestone.

## Progress

- [x] (2026-09-07) Rechecked the selected checkout at `2fdab7e0`, preserved the
  three unrelated AGENTS/testnet-skill edits, and confirmed approximately
  40.16 GiB free against the hard 40 GiB reserve.
- [x] Assigned disjoint author lanes for the sampled-acceptance theorem,
  large-agreement extraction research, and the honest-side privacy hybrid.
- [x] Prove sampled acceptance for the fixed two-monomial source with arbitrary
  challenge-dependent responses fixed before fresh uniform opening queries.
- [x] Exhaust small-field agreement events and residual-rank predictions,
  including independent brute-force checks of the optimized probe.
- [x] Derive or falsify a useful large-agreement extraction statement; record
  its exact remaining hypotheses and current-parameter quantitative loss.
- [x] Close a constructive honest-side transcript coupling step without
  assuming the desired full-view equality or quantum security bound.
- [x] Independently review surviving claims, run strict cached Lean and axiom/
  vector gates under a disk guard, and commit only verified scoped artifacts.
- [x] Landed that checkpoint as local commit `814b68fb`; all unrelated edits
  remained outside the commit.
- [x] Prove concrete Vandermonde/quotient bindings and the general adaptive
  high-rank count on the actual SMZ9 coset.
- [x] Prove fixed-candidate and fixed-family queried-mismatch bounds `p^-5`
  and `L*p^-5`, including arbitrary matrix-dependent responses.
- [x] Prove deterministic polynomial-patch response coverage, and generic
  exact twenty-subset sampling for arbitrary prefix-dependent agreement.
- [x] Construct the first honest-leaf ideal-QROM reduction against an explicit
  published theorem; verify tape-input mass and two-query oracle-domain
  decomposition, with all newly required query costs.
- [x] Finish and gate the composed specified finite-list recovery probability,
  integrate the follow-on source review and exact arithmetic, then land locally.

## Surprises & Discoveries

For the fixed data rows `X^388` and `X^389`, zero masks and other rows, the
probability that some matrix-selected bad completion exists is not the same
as the probability that its fixed response passes twenty fresh queries. Unless
both selected matrix columns vanish in all five rows, at least one response
discrepancy is a nonzero polynomial of degree at most 389. Thus its agreement
set has at most 389 points, giving sampled acceptance at most
`p^-10 + (1-p^-10)*(389)_20/(2^23)_20`. The complete finite experiment is now
proved in Lean, including the exact exceptional-matrix count and arbitrary
matrix-dependent response functions. It is not a general security bound.

The new high-rank argument counts full-rank supports inside the same agreement
set and weights that incidence count by its own twenty-subset probability.
It does not multiply independent-looking marginal bounds. With agreement split
416 and rank cutoff 20, the two covered branches sum to approximately
`2^-286.642743`; ranks 1 through 19 at larger agreement are omitted, not bounded.
Generic independent-support, affine-row and first-moment identities are proved
in Lean. Their full Vandermonde/quotient-dimension/SMZ9 game instantiation is not.

Follow-on correction: `SmallWoodV8Smz9RankIncidenceBinding.lean` now supplies
the concrete Vandermonde/quotient bridge and matrix-dependent high-rank integer
count. Its exact twenty-opening weighting and the omitted low-rank structures
remain separate; the unweighted current-coset tail is no longer only paper math.

Low local rank does not imply low global rank: a zero core with 140 distinct
exceptional basis-vector positions has global quotient rank 140 but a large
rank-one agreement set when one matrix column vanishes. Conversely, the small
global-dimension decoder's rank exception is not a matching failure attack.
Robust recovery must charge sampled disagreements with the recovered tuple.

The honest-order hybrid admits an exact change of variables from independent
LVCS tails and DECS masks to independent tails and the full DECS response.
This derives fresh tails after the generated public prefix inside the ideal
randomized-leaf experiment, retains original-mask/final-overlay correlation,
and composes the local LVCS law with both abort levels. Literal frame bytes
separate leaf and later non-leaf inputs; the delayed-overlay theorem is limited
to non-leaf queries and an atomic honest invocation. The initial and final
hidden-leaf QROM transitions remain open.

The initial transition now has a reviewed, explicit ideal-QROM reduction to
GHHM21 adaptive reprogramming. It samples the fresh tape/input before the new
digest, then reads that digest through the selected oracle; all `T*2^23` such
reads are charged and the programmed table persists. The final hidden-leaf
removal remains open. The published distance theorem is external, while the
input mass, physical query maps, independent-domain factorization and exact
two-query coherent simulation are newly checked Lean results.

A fixed query subset permits choosing one mismatching source/candidate position
before counting matrices. This tightens the fixed-list loss from `20L*p^-5`
to `L*p^-5`. A source covered by L fixed polynomial patches except at h points
has response coverage above `387L+h` agreement, giving a concrete recovery case
even at global source quotient rank 140. This does not construct a small cover
for arbitrary malicious sources. Conversely, twenty accepted openings alone
always admit an interpolated data/mask lift and therefore are an inadequate
knowledge-extraction endpoint.

## Decision Log

The coordinator owns this plan, shared imports, the declaration inventory,
builds and commits. The three author lanes own only their named new files.
They may use cached direct Lean checks with temporary outputs, but not shared
package builds. Initial checkpoints are twenty minutes with 20-30 MiB of new
disk per lane. The final gate is coordinator-only and stops above the hard
reserve rather than deleting unrelated files or retained evidence.

The central event is accepted proof plus failure of a specified efficient
extractor, not merely absence of a globally degree-bounded source table.
Near-codeword corruption can be compatible with robust recovery. The response
must be fixed before the opening sample; no conditional sampling claim is
inferred from Fiat-Shamir source order. Quantum oracle and extraction costs
remain separate until their actual joint experiment is constructed.

## Outcomes & Retrospective

The three new Lean modules pass direct strict checks and independent source
review. The integrated coordinator gate passes 2,748 jobs and all 129 scoped
roots against the existing kernel axiom allowlist. All three wire vectors and
48 generated-program modules are unchanged. The disk guard's minimum sampled
availability was 40.133030 GiB. The earlier gate passed 2,745 jobs and 114 roots;
that historical result was not substituted for the current gate.
Full privacy, accepted-proof extraction and quantum composition remain open.

The follow-on probe has eleven passing tests, including literal two-patch
coverage and fixed-candidate sampled mismatch. The new hidden-leaf arithmetic
script has three passing tests and exact integer boundary/successor checks for
all four query-budget cases. None of these arithmetic screens is a production
history authorization or a whole-security bound. The second integrated gate
passes 2,754 jobs and 145 scoped roots with unchanged wire vectors and all 48
generated-program modules. Minimum sampled free disk was 40.176918 GiB. The
first attempt found one omitted explicit type binder under `autoImplicit=false`;
the signature was corrected and the complete gate rerun successfully, without
changing a mathematical statement or the checking policy.

The completed `SmallWoodV8Smz9PiecewiseRecovery.lean` theorem bounds the actual
joint accepted-pair fraction for the specified first-projecting-candidate scan
by `choose(h+L*d,20)/choose(N,20) + L/p^5`. Independent review confirmed the
event inclusion, exact product-coordinate swap and additive union without an
event-independence assumption. It is not a probability conditioned on acceptance
or a transaction-witness theorem. The finite scan is mathematical, not a Rust
extractor implementation; arbitrary-source cover construction remains open.

The exhaustive probe passes eight tests. Its three default experiments enumerate
99,771 matrices and check 229 fixed-support affine-rank counts and 20 high-rank
strata. Independent literal response enumeration agreed on 733 tiny cases.
The current-profile screen uses exact rational expressions and verifies the
integer floor of every displayed partial-bound exponent; logarithmic decimals
are diagnostics. For the F17 example, support-existence probability is
`4609/83521`, while optimal sampled acceptance is `583/584647`.

## Context and Orientation

`formal/crypto/HegemonCrypto/SmallWoodV8Smz9AccumulatedExtraction.lean` contains
the fixed-source counterexample and valid pre-fixed-family bound.
`SmallWoodV8Smz9AdmissibleRootProbability.lean` counts exact twenty-subset root
events. `SmallWoodV8Smz9SingleProofPrivacy.lean` contains the source-shaped local
LVCS feedback law. The reports in `docs/crypto/smz9-campaign/` distinguish those
checked facts from missing whole-game results.

An agreement set is the set of domain positions where all five transmitted
degree-387 response polynomials match the challenged committed values. A
residual is the difference between a word and its interpolation through a fixed
degree-plus-one anchor set. Residual rank counts independent linear constraints
on a challenge row. For a fixed support, consistent rank-r affine constraints
have probability `p^-r` per independent matrix row. Selection over supports
still needs its own accounting; that fiber count alone is not the answer.

## Plan of Work

First, the sampled-acceptance author writes only
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SampledAcceptance.lean`. Its response
is an arbitrary function of the matrix, with explicit degree bounds. It counts
the two-zero-column exception and averages the conditional twenty-subset bound.

The coordinator writes `scripts/smz9_joint_acceptance_probe.py`, a small-field
exhaustive diagnostic with a built-in unit-test mode. It enumerates all matrix
challenges and optimizes adversarial responses before the sampled queries.
Support interpolation compresses this enumeration, and independent literal
response enumeration checks that optimization on tiny cases. Report both the
existence event and sampled acceptance, with exact rational values. No diagnostic
number is a current-Goldilocks theorem or extractor guarantee.

The extraction researcher writes only
`docs/crypto/smz9-campaign/joint-extraction-research.md`, investigating whether
large agreement yields a bounded simultaneous polynomial candidate family.
The privacy researcher writes only `honest-hybrid-research.md` in that folder
and, if constructive, `SmallWoodV8Smz9HonestHybrid.lean`. That law must derive
the needed coin/transcript coupling in a defined ideal randomized-leaf
experiment, not assume fresh coins after observing their commitment.

## Concrete Steps

From the repository root, run:

    python3 -B scripts/smz9_joint_acceptance_probe.py --self-test
    python3 -B scripts/smz9_joint_acceptance_probe.py
    HEGEMON_FORMAL_CRYPTO_MIN_FREE_GIB=40 bash scripts/check_formal_crypto.sh
    git diff --check

The final command must additionally be wrapped by the coordinator's free-disk
monitor because the existing script's built-in reserve check is cold-build-only.
Use the already pinned Lean 4.32.2 and mathlib cache. No installation, Rust
build, node launch or retained-proof generation is required.

## Validation and Acceptance

The probe must reject malformed domains/parameters, agree with direct response
enumeration on tiny cases, reproduce exact fixed-support rank probabilities,
and demonstrate why unweighted support existence and sampled acceptance differ.
The theorem must compile with the package's warnings-as-errors policy, preserve
matrix-dependent response choices, and use only the existing kernel axiom
allowlist. A separate reviewer checks quantifier order and source scope.
Only after the complete gate passes may the new declarations receive audit
credit. Neither this milestone nor a passing gate grants a security receipt.

## Idempotence and Recovery

The probe writes JSON to standard output and creates no cache with `-B`.
Temporary Lean outputs use distinct paths. Stop a guarded check if free disk
approaches 40 GiB, preserving completed source and all prior artifacts.
Stage explicit task-owned files only. Never reset the user's dirty files.

## Artifacts and Notes

Prior local commits: `de2f827d` and `2fdab7e0`. Current dispatch creates no
new app tasks, worktrees, external submissions or production authority.

## Interfaces and Dependencies

Use Python's standard library only for the probe. Use existing finite-field,
polynomial, subset-counting and ideal probability definitions for Lean.
Do not add a library or a record whose fields assume the desired final bound.

Revision note (2026-09-07): started the user-authorized joint-event milestone
to replace the wrong global-noncodeword event with sampled acceptance and
constructive recovery, while continuing the honest-order privacy argument.

Revision note (2026-09-07 05:10Z): integrated and verified the three scoped
modules, reviewed research arguments and exhaustive diagnostic. Continued
independent bounded work on the concrete rank-map binding, robust sampled
candidate mismatch, piecewise polynomial coverage and the hidden-leaf QROM
transition. Those follow-on obligations receive no credit from this gate.
