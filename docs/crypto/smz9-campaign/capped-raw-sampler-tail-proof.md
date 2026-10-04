# Bound the literal capped sampler's abort tail


This ExecPlan follows `.agent/PLANS.md`. Exclusive writes are the new module
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CappedRawSamplerTail.lean` and this
file. The existing capped sampler remains frozen.

## Purpose / Big Picture


Replace an exact but unevaluated finite abort count with a proved numerical
upper bound. The calculation must start from the same finite byte-vector
experiment that produces successful field outputs and the explicit abort
outcome. It must neither assume a binomial distribution nor enumerate the
astronomically large sample space.

## Progress


- [x] (2026-09-07 18:21Z) Selected finite rejected-coordinate subsets as a cover of the actual abort fiber.
- [x] (2026-09-07 18:29Z) Wrote the cylinder count, union bound and exact arithmetic certificates.
- [x] (2026-09-07 18:32Z) Corrected the pre-successor uniform gamma bound to cover every permitted row count using threshold 33, not its then-current maximum-size threshold 36.
- [x] (2026-09-07 18:53Z) First strict check identified local elaboration errors and hit its 3 GiB ceiling; no numerical theorem was credited.
- [x] (2026-09-07 18:58Z) Corrected the reported dependent-type, predicate and scalar-cast issues source-only.
- [x] (2026-09-07 19:19Z) Full source passed the strict single-worker 3 GiB check after bounded scratch localization.
- [x] (2026-09-07 19:20Z) Audited twelve principal declarations: only `propext`, `Classical.choice` and `Quot.sound`; froze the checked module.
- [x] (2026-09-07 20:56Z) Updated successor capacities and independently recomputed the maximum-specific and uniform integer floors source-only.
- [x] (2026-09-07 20:58Z) First successor check stopped on the stale pre-successor sampler interface; no theorem failure was credited.
- [x] (2026-09-07 20:59Z) After the coordinator-authorized sampler-interface refresh, the successor tail passed its one strict rerun.
- [ ] Re-run the principal declaration audit for the successor delta if the coordinator requires updated axiom evidence.

## Context and Orientation


`SmallWoodV8Smz9CappedRawSampler` proves that aborting raw vectors contain at
least `C-n+1` rejected words, where `C` is the number of u64 candidates and
`n` is the requested output count. A rejected word has one of `2^32-1`
values among all `2^64` u64 values. Its abort probability is the cardinality
of that actual vector set divided by `(2^64)^C`.

A cylinder fixes a set of coordinate positions that must reject while all
other positions remain unrestricted. Every vector with at least `k`
rejections belongs to at least one cylinder indexed by a `k`-element set.
There are `choose(C,k)` such sets. Adding their cardinalities is a valid
upper bound even when the cylinders overlap.

The exact DECS parameters are `C=736`, `n=700`, `k=37`. The largest
source-gamma request justified by the 20,605-row upper bound has `C=103064`,
`n=103025`, `k=40`, but this is not the smallest rejection threshold: a nearby
request can have threshold 33. The uniform source-gamma theorem therefore
uses `C<=103064` and `k>=33`, covering every retained row count at most
20,605. The older 4150-word gamma example is not substituted for that family.

## Plan of Work


First prove the cardinality of a selected cylinder using an equivalence
with a coordinate-wise function type. Next cover the real rejection fiber
with the finite family of cylinders and apply cardinality subadditivity.
Finally cancel the unrestricted-coordinate factor from the exact uniform
law and evaluate only 33, 37 or 40 descending factorial factors.

The checked generic bound is

    Pr[at least k rejected words] <= choose(C,k)*(2^32-1)^k/(2^64)^k.

The successor target specializations are `2^-976` for DECS and `2^-773`
for the maximum-size gamma request alone. Its corresponding `Q^2` allowance
for `Q<=2^128` is `2^-516`. The uniform all-row gamma bound remains `2^-629`;
the DECS plus uniform gamma sum, multiplied by `Q^2` for `Q<=2^128`, remains
at most `2^-372`. These are finite-experiment arithmetic
theorems, not an adaptive quantum freshness guarantee. If a later reduction
uses `(2*Q_raw)^2`, its factor four must be retained explicitly; this arithmetic
then gives `2^-370` for `Q_raw<=2^128`, not `2^-372`.

## Concrete Steps


The coordinator first refreshes the frozen dependency cache. Wait for its
explicit slot grant before starting one compiler. From `formal/crypto`:

    lake env lean -M3072 -j1 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CappedRawSamplerTail.lean

A pass has no errors or warnings and exit code zero; `--profile` optionally
prints timing data. The full module passed this command with `--profile`
at 19:19Z, with 1.44 seconds of import time. A sequential scratch source
check appended twelve `#print axioms` commands and passed at 19:20Z.
Every audited theorem used only `propext`, `Classical.choice` and `Quot.sound`.
The successor source passed the same strict command at 20:59Z after its edited
sampler dependency interface was refreshed in the coordinator-granted slot.
Release the slot immediately after the principal audit.
Do not run concurrent retries or write shared cache files. The coordinator
owns shared integration imports, cache refresh and any central integration audit.

## Validation and Acceptance


The actual finite fiber must feed the numerical theorem. A generic
cardinality formula disconnected from the literal parser is insufficient.
The exact DECS and uniform all-row gamma parser probabilities must be bounded by
the stated inverse powers of two using kernel-checked integer arithmetic,
without `native_decide`, admitted axioms or a normal approximation.

The whole-query-squared theorem is arithmetic accounting for fixed-vector
abort laws. It does not prove adaptive QROM freshness, state restoration,
Rust execution refinement or production authority.

## Surprises & Discoveries


Directly evaluating Pascal's recursion at capacity 103,064 would be a poor
proof computation. Rewrite the binomial coefficient using a descending
factorial divided by `k!`; only `k` factors are then evaluated.

Concrete binomial expressions can expand during elaboration even before the
explicit arithmetic tactic. Keep the numerator and `Nat.choose` locally
irreducible, prove the descending-factorial rewrite with symbolic parameters,
then instantiate the short expression and use kernel `decide`. The finite
exponent-evaluation threshold is 4096, while the compiler memory ceiling
remains 3 GiB. Final inverse-power arithmetic is transferred from finite
extended reals to real numbers before `norm_num`.

Maximum request size is not the worst rejection threshold. The source cap
is `(n+39)/8` blocks for a positive request, so `8*cap-n+1` ranges from
33 through 40. For example, `n=103000` has `C=103032` and threshold 33.
The all-row proof uses actual event inclusion at threshold 33 before
monotonicity in the candidate capacity; it does not assume the row residue.

## Decision Log


Use a finite union bound over rejected-coordinate subsets, because it
connects directly to the existing abort fiber and works without an assumed
binomial law. Keep successful sampler proofs unchanged. Perform arithmetic
only after cancelling the unrestricted-coordinate factor, so no expression
with millions of sample-space bits needs evaluation.

## Outcomes & Retrospective


The pre-successor 370-line module passed strict verification and the
twelve-declaration principal axiom audit. It bounded the literal parser's
actual finite abort fiber by a union of rejected-coordinate cylinders and
derived DECS `2^-976`, then-current maximum-size gamma `2^-690`, all-row gamma
`2^-629`, and the uniform query-squared allowance `2^-372` for `Q<=2^128`.
The successor source now strengthens the maximum-specific floor to `2^-773`
and its query-squared allowance to `2^-516`, while preserving the all-row
`2^-629`/`2^-372` bounds. This delta passed its coordinated strict check.

This does not discharge adaptive fresh-oracle sampling, repeated quantum
request composition, Rust byte-execution refinement, cryptographic soundness,
or production authorization. The existing capped-sampler source stayed frozen;
no shared import or cache was written. Source, document and the bounded
localization/audit scratch together remained below 0.4 MiB.

## Idempotence and Recovery


Both owned files are additive. Repeating the read-only strict command is
safe after a new slot grant. No retained proof, runtime, wallet, node state,
shared import or cache is modified by this lane. Total source and scratch
must stay below 30 MiB.

## Interfaces and Dependencies


The new module imports the frozen capped-sampler module and mathlib finite
set and binomial-coefficient facts. `rejection_tail_fiber_card_union_bound`
proves the finite cover count. `literal_byte_parser_abort_choose_union_bound`
transfers it to the exact parser law. Integer certificates feed the final
DECS, maximum-size gamma, uniform all-row gamma and query-squared allowance theorems.

## Artifacts and Notes


Independent integer arithmetic predicts floor security bits 976 for DECS,
773 for successor maximum-size gamma and 629 for the uniform all-row gamma
bound. The Lean certificate source states those inequalities and passed the
successor strict check.

Revision 2026-09-07 18:29Z: wrote the finite covering argument, explicit
source parameters and planned exact numerical acceptance before checking.

Revision 2026-09-07 18:32Z: separated maximum-size gamma from the uniform
all-row bound, proving threshold range 33 through 40 before numerical use.

Revision 2026-09-07 18:58Z: recorded the first strict failure and replaced
ambiguous dependent-Pi inference and mixed natural/extended-real cancellation
with explicit constructions before the next bounded correction check.

Revision 2026-09-07 19:20Z: completed bounded strict verification and the
principal axiom audit after preventing concrete Pascal expansion, evaluating
only short descending-factorial certificates, and explicitly transferring
finite extended-real numerical arithmetic. All four numerical endpoint
theorems are checked, with the fixed-vector/QROM boundary retained.

Revision 2026-09-07 20:56Z: updated the successor relation to 20,605 attempts,
103,025 requested words, 12,883 digest calls, 103,064 candidates and maximum
threshold 40. Recomputed the maximum-specific floor as `2^-773` and its
query-squared allowance as `2^-516`; the uniform `k=33` floors remain
`2^-629` and `2^-372`. No Lean compiler was started before a slot grant.

Revision 2026-09-07 20:59Z: the first tail check exposed a stale dependency
interface and stopped. After the explicitly authorized sampler `.olean` refresh,
the single tail rerun passed with no output under the 3 GiB, one-worker limit.
