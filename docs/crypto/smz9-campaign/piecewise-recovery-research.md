# SMZ9 piecewise polynomial recovery: constructive cases and limits

Date: 2026-09-07. Status: bounded recovery research with checked companion theorems, not an end-to-end proof or a runtime change. The earlier [joint-extraction dossier](joint-extraction-research.md) remains a separate frozen artifact. This document supplies additional algebraic recovery cases; it does not assume that arbitrary malicious source words have the required structure. The research author performed no builds, downloads to disk, dependency changes, Git operations, or runtime edits; the coordinator's later formal integration is recorded below.

## Result

A small **polynomial patch cover** can supply actual response-to-candidate coverage even when the source's global residual rank is much larger than five. With two patches covering the domain, every response with at least 775 agreeing positions must be the projection of a listed polynomial tuple. Combining this coverage with the separately proved fixed-list sampled-inconsistency argument gives a conditional classical DECS term

`choose(774,20)/choose(N,20) + 2/p^5`,

approximately `2^-268.433334` for the current parameters. There are explicit sources of global residual rank 140 satisfying this two-patch condition. This is a constructive positive case, not a theorem that all arbitrary sources admit such a cover.

Two additional diagnostics prevent false closure:

- Twenty accepted DECS openings always admit a degree-bounded polynomial lift, because twenty is less than 388. Such a lift alone is not knowledge extraction.
- The `p^-1` singularity rate of a five-by-five matrix is not an inherent large-agreement failure rate. A current-parameter monomial source has that singularity rate but only a `p^-25` large-agreement exception.

## Fixed experiment and notation

Use `F=Goldilocks`, `p=2^64-2^32+1`, `N=2^23`, and the fixed distinct evaluation domain `D`. Set `d=387`, `k=d+1=388`, and `t=20`. Fix all 140 data words `W` and five mask words `M` before sampling a uniform matrix `A in F^(5 x 140)`. After seeing `A`, choose arbitrary degree-at-most-`d` response polynomials `R`. Define

`G = {x in D : A W(x)+M(x)=R(x)}`.

Only then sample an independent uniform `t`-element subset `J` of `D`. The ideal DECS equations accept when `J subset G`. The source-owned profile is in [the accounting definitions](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean#L27-L137) and [runtime profile](../../../circuits/transaction/src/smallwood_engine.rs#L240-L252). As before, this finite experiment does not itself instantiate the raw QROM, authenticated-source extraction, or the later PIOP.

## Twenty-opening polynomial lifting is an inadequate endpoint

Suppose only that the DECS equations accept at the twenty distinct points `J`. Interpolate each data row on `J` to a polynomial `Q_data,j` of degree at most 19. Define

`Q_mask = R - A Q_data`.

Every mask polynomial has degree at most 387. On `J`, the accepted equations imply `Q_mask=M`, while the data interpolants match `W`. Moreover,

`A Q_data+Q_mask=R`

holds identically as a polynomial equation. This works for every matrix `A`, including singular matrices, and for every accepted set of DECS values. It does not need the committed source to be close to any codeword.

Consequently, an interface asking only for degree-bounded polynomials matching the twenty revealed rows and the response is automatically satisfiable. A sound extractor must additionally connect its tuple to a source-fixed candidate or sufficient committed information, and prove the actual PCS/PIOP and HGV8RP03 semantic obligations. Treating these freshly fitted polynomials as the committed witness would skip the binding theorem.

## Matrix singularity can greatly overstate large-agreement failure

Take the first five data words to be

`x^388, x^389, x^390, x^391, x^392`,

and all remaining data and mask words to be zero. Their global quotient dimension modulo degree-at-most-387 polynomials is exactly five: a nontrivial combination cannot agree with a lower-degree polynomial on all `N>392` distinct points.

Let `E` be the first five columns of `A`. This uniform five-by-five matrix is singular with probability

`1-product_{i=0}^4(1-p^(i-5))`,

whose leading term is `p^-1`. Nevertheless, if any adaptive response `R` agrees at 393 or more points, then each polynomial

`sum_{j=0}^4 E_ij*x^(388+j) - R_i(x)`

has degree at most 392 and at least 393 roots. Every polynomial is therefore zero, forcing `E=0` and `R=0`. Conversely, `E=0,R=0` gives agreement everywhere. Thus the exact probability that some response has agreement at least 393 is `p^-25`, approximately `2^-1600`, not `p^-1`.

For every nonzero `E`, all responses have agreement at most 392, so the joint twenty-opening contribution is bounded by

`choose(392,20)/choose(N,20) + p^-25`,

with the first term approximately `2^-288.416928`. This is a source-specific DECS statement. It neither establishes security of arbitrary sources nor constructs an accepted full proof. Its purpose is to show that a coarse rank-deficiency event cannot be called an unavoidable attack or extraction-failure probability.

## What ordinary common-tuple list recovery really provides

For a fixed full source, consider all common 145-polynomial tuples of degree at most `d` agreeing with it on at least `a` positions. Different tuples can have agreement-support intersection at most `d`: at least one coordinate polynomial differs, and that difference has at most `d` roots.

If there are `L` tuples, choose exactly `a` positions from each support. Counting the multiplicities of these selected supports and applying Cauchy-Schwarz gives

`L^2*a^2/N <= L*a + L*(L-1)*d`.

Therefore, when `a^2>N*d`,

`L <= N*(a-d)/(a^2-N*d)`.

This is a common-tuple list bound, not a product of 145 independent scalar list bounds. The list can be sought constructively by encoding each source value in `F^145` as one element of an auxiliary extension field `F_(p^145)`. Under a fixed `F`-basis, extension-field degree-at-most-`d` polynomials correspond exactly to tuples of 145 base-field polynomials. The evaluation points remain the same elements of the base field. [Guruswami–Sudan, Theorem 7, author full text](https://people.csail.mit.edu/madhu/papers/1998/gs.pdf) gives polynomial reconstruction for agreement greater than `sqrt(d*N)`, using polynomial root finding over the rational-function field. This yields an algorithmic route to the common list; no implementation or practical runtime claim is made here.

The auxiliary extension is an extractor's representation choice, **not** a larger verifier challenge field. All matrix probabilities still use the original `p`.

For the current profile, the smallest integer agreement above that threshold is 56,978. The displayed list bound is then less than 4,691,463. However, relegating all supports of at most 56,977 points to the twenty-opening error gives approximately `2^-144.042938`, far weaker than the near-Singleton screen. At agreement 416, the list-bound denominator is negative; this argument provides no bound there.

Even beyond Johnson, constructing this list does not prove that every projected response is the projection of one listed tuple. That is the separate correlated-agreement/coverage obligation. The next lemma proves coverage under a concrete additional condition.

## Polynomial patch-cover lemma

Fix, before `A`, a finite list of `L` common polynomial tuples

`Q_i=(Q_i,data,Q_i,mask)`, each of degree at most `d`.

Let `C_i` be the positions where the entire fixed source tuple `(W,M)` equals `Q_i`. Suppose their union leaves at most `h` positions uncovered. The patches may overlap. This condition is checked directly against the fixed full source; it is not a probability or a claimed simulator equality.

Define the polynomial projection

`R_i(A)=A Q_i,data+Q_i,mask`.

**Claim.** Every response satisfying `|G|>L*d+h` equals `R_i(A)` as a polynomial vector for at least one listed tuple.

**Proof.** Suppose `R` differs from every `R_i(A)`. For each `i`, at least one coordinate of `R-R_i(A)` is a nonzero degree-at-most-`d` polynomial. At every position of `G intersect C_i`, that difference vanishes. Hence `|G intersect C_i|<=d`. The union of the patches contains all but at most `h` points, so

`|G| <= h + sum_i |G intersect C_i| <= h+L*d`,

a contradiction. This proof allows an arbitrary post-matrix response and arbitrary global span of the source.

For a disjoint assignment of covered positions to patches, the same proof sharpens the cutoff to `h+sum_i min(d,patchSize_i)`. The simpler `L*d+h` expression suffices for the cases below.

### Constructive selection and sampled inconsistency

Given the list, `A`, and `R`, compute each polynomial `R_i(A)` and select the first equal one. On the large-agreement branch the coverage lemma guarantees that this succeeds.

For each fixed candidate `Q_i`, let `B_i` be its fixed set of mismatching source positions. First fix the entire sampled subset `J`, which is independent of `A`. If `J` meets `B_i`, choose one canonical point `x_i(J)` in that intersection using only `J`, the fixed source, and `Q_i`--not the matrix or response. Acceptance together with `R=R_i(A)` forces the five affine matrix equations at this one point. Their probability is `p^-5` when its data residual is nonzero, and zero when only its mask residual is nonzero. Complete response equality and the other sampled equations only shrink the event.

Averaging over `J` therefore bounds the mismatch event for this candidate by

`p^-5 * Pr_J[J intersects B_i] <= p^-5`.

There is no factor of twenty: one matrix-independent mismatch witness per fixed subset suffices. The response may remain an arbitrary function of `A`; no conditioning on response equality is used to assert a uniform matrix law. Union over the fixed candidate list gives the sharper bound

`Pr[large agreement, DECS acceptance, selected candidate disagrees at a sampled point]`

`<= p^-5 * sum_i Pr_J[J intersects B_i] <= L/p^5`.

For the uniform distinct twenty-subset, the individual hit probability is exactly `1-choose(N-|B_i|,20)/choose(N,20)`. Keeping these hit probabilities can further tighten the bound for candidates with small mismatch sets.

Separately, the small-agreement branch contributes at most

`choose(L*d+h,20)/choose(N,20)`

when `L*d+h<=N`, with the usual zero value below twenty. Combining the branches gives the conditional classical term

`epsilon_patch <= choose(L*d+h,20)/choose(N,20) + L/p^5`.

The selected candidate is permitted to depend on `A,R`; the **list and cover are not**. No independence between response selection and matrix consistency is assumed. No uniqueness of the projected candidate is required for this sampled-inconsistency bound.

## A two-patch source with global quotient rank 140

Split the actual evaluation domain into two sets of size `N/2`, denoted `S` and its complement. Fix masks to zero and set, for `j=0,...,139`,

`W_j(x)=x^j` on `S`, and `W_j(x)=0` outside `S`.

The two polynomial tuples

`Q_0=(0^140,0^5)`,

`Q_1=((1,x,...,x^139),0^5)`

cover every source position. Yet the 140 data classes are linearly independent modulo degree-at-most-387 polynomials. Indeed, if a linear combination of the `W_j` equals such a polynomial `P` globally, then `P` has `N/2>387` roots outside `S` and must be zero. The corresponding degree-at-most-139 combination then vanishes at all `N/2>139` points of `S`, forcing all coefficients to be zero.

This source has global residual rank 140, well outside the injective-global-dimension case, but the patch-cover decoder applies with `L=2,h=0`. Its response threshold is `2*387+1=775`.

The two source-fixed candidates can also be recovered without knowing the partition in advance: perform common-tuple list recovery at agreement `N/2`, then verify the resulting patch cover. At this threshold, the list bound is

`2*(N-2*d)/(N-4*d) = 2.000184570... < 3`,

so there are at most two candidates. In this example both displayed tuples have exactly half-domain agreement, so both are returned by a complete decoder. This is an extension-field common-tuple invocation, not independent decoding of each source row.

The example supplies a genuine high-global-rank recovery case. Its candidate tuples need not satisfy any given transaction's public statement or PIOP constraints; no witness-validity or full-proof acceptance claim is made.

## Exact arithmetic screens and their boundary

For `L=2,h=0`, the two terms are approximately

`choose(774,20)/choose(N,20) = 2^-268.433334289`,

`2/p^5 = 2^-318.999999998`.

Their sum has essentially 268.433334 bits. As an **isolated arithmetic diagnostic only**, multiplying this sum by `12*(2^64)^2` leaves approximately 136.848372 bits. This does not establish that this classical probability is the actual CMS instability parameter, nor does it include other PIOP, oracle, lifetime, or implementation losses.

An exact integer screen of

`12*2^256*(choose(b,20)*p^5 + 2*choose(N,20)) < choose(N,20)*p^5`

passes at `b=1048` and fails at `b=1049`. Thus the same isolated screen accommodates a verified two-patch cover with at most `h=274` uncovered positions (`b=774+h`). Three full-size patches already give `b=1161` and fail this screen before other terms. These comparisons are properties of the displayed conditional formula, not security certificates for arbitrary source words.

## What is still missing for actual accepted-proof recovery

The patch condition has not been proved for every malicious committed source. Neither small residual rank on an adaptively selected agreement support nor a large global rank supplies that condition. The arbitrary-source branch with local ranks 1 through 19 remains open after the existing high-rank split.

For a source satisfying the condition, this work constructs a common polynomial candidate and controls disagreement at the sampled DECS positions. The later proof still has to bind the candidate to PCS reconstruction, the actual PIOP messages and challenges, the packed program, and finally HGV8RP03 witness semantics. Candidate availability or a polynomial lift is not itself evidence of a valid witness. Obtaining the required full committed source from a quantum Merkle/oracle experiment is also a separate extraction and query-accounting obligation.

The useful next result is therefore either a uniform source-to-small-patch-cover theorem with a controlled exception, or a different robust decoder for the uncovered low-rank structures. The two-patch example shows that global dimension alone is too coarse; it does not make the remaining structures disappear.

## Checked companion and reproducibility

`SmallWoodV8Smz9PiecewiseCoverage.lean` proves the deterministic actual-coset
patch-cover lemma. `SmallWoodV8Smz9RobustQueryMismatch.lean` proves `L/p^5` in
the fixed-source/fixed-list matrix/subset experiment. The generic exact sampling
and accepted-pair swap live in `SmallWoodV8Smz9JointQuerySampling.lean`.
`SmallWoodV8Smz9PiecewiseRecovery.lean` specifies the first-projecting-candidate
scan and proves its joint acceptance-and-recovery-failure probability bound by
composing those results. It is not failure conditioned on acceptance, a Rust
extractor, or a witness-validity theorem. The cover remains a substantive premise.

The full coordinator gate passes 2,754 jobs and 145 allowed-axiom roots, with
unchanged wire/program artifacts. Independent mathematical review approves the
completed composition. Run `python3 -B scripts/smz9_joint_acceptance_probe.py --self-test`
for eleven checks, and `--patch-cover-screen` for the exact conditional arithmetic,
including the 1,048/1,049 boundary comparison.
