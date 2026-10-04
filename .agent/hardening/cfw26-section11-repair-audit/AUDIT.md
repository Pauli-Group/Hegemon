# CFW26 Construction 11.4 repair audit

Status: the printed construction is internally inconsistent and cannot inherit
Theorem 11.3 as a production authority. A coefficient-one plus
`times(identity)` restatement has a short, independently provable typing and
honest-completeness lemma. A consistently coefficient-two restatement has the
same local property in odd characteristic. Neither restatement is selected by
the authors here, and neither has a complete RBR/HVZK/QROM proof in this
artifact.

This audit is intentionally isolated. It does not implement a code, IOR, PCS,
Fiat--Shamir transform, Hegemon relation, or verifier. The executable model is
dependency-free finite-field evidence for the disputed algebra only.

## Primary-source identity and anchors

The source is Chiesa, Fenzi, and Weng, *Zero-Knowledge IOPPs for Constrained
Interleaved Codes*, IACR ePrint 2026/391. The examined 82-page local PDF has
972,446 bytes and SHA-512:

```text
be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd
```

`SOURCE_ANCHORS.json` pins retained page renders and the following exact
locations:

- Definition 5.2, printed page 35: `identity` consumes one matrix state `V`
  and returns `V`.
- Definition 5.4, printed page 35: `times(sl)` consumes `(state, scalar)` and
  returns the scalar times `sl(state)`.
- Definition 11.1, printed page 66: the constrained-code output relation sums
  the main-code inner product and one inner product for each inner-mask oracle.
- Theorem 11.3, printed pages 66--67: the inner forms are declared to be
  `identity`; the theorem states the RBR and HVZK claims and their premises.
- Construction 11.4 Step 1, printed page 68: every inner-mask polynomial is
  conditioned to evaluate to zero at both 0 and 1.
- Construction 11.4 Step 3, printed page 68: each masked matrix contraction has
  one copy of its inner-mask sum.
- Construction 11.4 Step 8, printed page 69: the defining equation for `v_M`
  again has one mask sum, but its immediately following claimed decomposition
  has two.
- Construction 11.4 Step 9, printed page 69: the inner form is `identity`, its
  state is the pair `(pow(alpha_i), ze(rho)_M)`, and the target is the
  `ze`-weighted sum of `v_M-u_M`.
- Theorem 11.3's HVZK proof sketch, printed pages 70--71: the value claim uses
  coefficient two and invertibility of two to make each `v_M` uniform.
- Lemma 6.4, printed pages 38--39: odd characteristic is also used in an
  earlier outer sumcheck rank argument. Consequently, the theorem's
  `char(F) != 2` premise does not itself identify the intended Section 11
  coefficient.

No author correction is inferred from this local snapshot. This artifact is
not an erratum search and does not elevate either repair to author intent.

## Exact conflict

Write `d = log(ell)+1`. For `M` in `{A,B,C}`, at the verifier's point `alpha`
define

```text
u_M = public-input contribution,
q_M = witness contribution,
S_M = sum_i inner_mask_(M,i)(alpha_i),
z_M = ze(rho)_M.
```

Step 3 and Step 8's first equation give

```text
v_M = u_M + q_M + S_M.                         (1)
```

Step 8's second equation and the page-71 value claim instead give

```text
v_M = u_M + q_M + 2 S_M.                       (2)
```

Equations (1) and (2) cannot both hold for arbitrary masks in an odd field.
The verifier's Step-9 target is

```text
mu = sum_M z_M (v_M - u_M).                    (3)
```

The state `(pow(alpha_i), z_M)` is not an input of Definition 5.2's identity
form. It is exactly the input shape of Definition 5.4's scalar-multiplied
form. Thus the literal text is ill-typed before one asks whether its equality
holds.

If one charitably discards the scalar and applies identity to only
`pow(alpha_i)`, the relation's left side under Equation (1) is

```text
sum_M z_M q_M + sum_M S_M,
```

whereas Equation (3) is

```text
sum_M z_M q_M + sum_M z_M S_M.
```

The residual is `sum_M (1-z_M) S_M`, which is not identically zero. In the
retained seeded campaign, this charitable projection failed 289 of 384 honest
trials. Its 95 accidental equalities are field cancellations, not
completeness.

## Three separated branches

| Branch | Step 3 / Step 8 coefficient | Inner form and state | Typed | Local honest relation |
|---|---:|---|---:|---:|
| printed coefficient-1 / identity | 1 | `identity(pow(alpha_i),z_M)` | no | no |
| candidate coefficient-1 plus `times(identity)` | 1 | `times(identity)(pow(alpha_i),z_M)` | yes | yes |
| coefficient-2 / scaled | 2 | `2 times(identity)(pow(alpha_i),z_M)` | yes | yes in the tested odd fields |

The third line is a family of edits, not a one-token change: Step 3, Step 8's
defining line, and Step 9's mask functional must all carry coefficient two.
Changing only the page-69 decomposition reproduces a final-check mismatch.

## Independently stated local lemma

**Lemma (candidate coefficient-one typing and honest completeness).** Let `F`
be a field; let the R1CS witness satisfy every row; let each inner mask
`s_(M,i)` satisfy `s_(M,i)(0)=s_(M,i)(1)=0`; define Step 3 and `v_M` with one
copy of each mask; and replace every Step-9 inner form with
`times(identity)` at state `(pow(alpha_i),z_M)`. Then:

1. the output relation is well-typed;
2. the masked constraint polynomial vanishes on the Boolean cube; and
3. the honest output witness satisfies the joint constrained-code equality.

**Proof.** Definition 5.4 maps the pair state to
`z_M pow(alpha_i)`. Its inner product with the coefficient vector of
`s_(M,i)` is `z_M s_(M,i)(alpha_i)`. Therefore the output relation's left side
is

```text
sum_M z_M q_M + sum_M sum_i z_M s_(M,i)(alpha_i)
= sum_M z_M (q_M + S_M)
= sum_M z_M (v_M-u_M)
= mu.
```

At a Boolean row `a`, every `s_(M,i)(a_i)` is zero by the endpoint
conditions. Step 3 therefore reduces to the original R1CS row residual, which
is zero. This proves the three local statements. The executable model checks
the same identity over 384 random valid R1CS instances and exhaustively over
the scalar variables in `F_5`.

The coefficient-two/scaled branch has the same proof with every `S_M`
replaced by `2 S_M` and Step 9 returning `2 z_M pow(alpha_i)`.

This lemma closes the local type/completeness defect for a new, explicitly
restated construction. It does **not** make the printed construction
unambiguous and does **not** permit Theorem 11.3 to be cited unchanged.

## Value-claim public slice

The page-71 hiding step also has a coefficient-one analogue. Let `K` be the
vector space of coefficient vectors for polynomials of degree below
`ell_in_zk` that vanish at 0 and 1. When `ell_in_zk >= 4` and
`alpha` is neither endpoint, evaluation `K -> F` is surjective: the polynomial
`c X(X-1)` lies in `K`, and its evaluation is
`c alpha(alpha-1)`, a bijective function of `c`. A uniform mask therefore has
a uniform evaluation.

It follows that, after conditioning on all other inner masks, both

```text
const_M + 1 * s_(M,d)(alpha_d)
```

and, in odd characteristic,

```text
const_M + 2 * s_(M,d)(alpha_d)
```

are uniform over `F`. Independence of the A/B/C masks gives a uniform triple
`(v_A,v_B,v_C)`. Since `mu` is then a public affine function of that triple,
the slice `(v_A,v_B,v_C,mu)` is witness-independent.

The exact retained enumeration uses `F_5`, message length 4, and
`alpha_d=2`. Each individual evaluation has histogram
`{0:5,1:5,2:5,3:5,4:5}`. For each coherent nonzero coefficient, the public
slice has 125 support points, each with multiplicity 125 among 15,625 mask
coefficient triples, and the distributions for two different witnesses are
identical. The retained fixture uses one public R1CS instance that accepts both
witnesses and gives them distinct witness-contribution triples. The literal
branch has the same *value-slice* distribution because
its Step-8 defining coefficient is one; that does not repair its ill-typed
output relation.

Negative controls behave as required:

- `alpha_d=0` collapses the evaluation support to one;
- coefficient two in characteristic two collapses its scaled value support to
  one.

This is not a full-view simulator. It excludes the outer sumcheck transcript,
all encoded-oracle answers, adaptive query semantics, and every hybrid error.
It therefore establishes no complete-ZK claim.

## Retained differential evidence

`cfw26_section11_repair_audit.py` uses only the Python standard library. Its
seed is SHA-512 pinned and its random campaign covers `F_5`, `F_7`, `F_11`,
and `F_13`, 96 trials per field, with `ell` in `{2,4}`. Every trial constructs
fresh random A/B rows and solves one random C coefficient per row for an exact
planted witness. It then checks all Boolean masked constraints and the joint
output relation.

Results:

- candidate coefficient-one plus `times(identity)`: 384/384 Boolean checks
  and 384/384 typed joint relations pass;
- coefficient-two/scaled: 384/384 Boolean checks and 384/384 typed joint
  relations pass;
- printed identity: 0/384 typed trials; its non-authoritative projection fails
  289/384.

The mutation corpus separates 15 cases, including the pair-state type error,
discarded or changed `ze` scalar, changed `mu`, coefficient-two without output
scaling, the Step3-one/Step8-two hybrid, nonzero mask endpoints, an invalid
R1CS row, an endpoint `alpha`, and characteristic two.

Run the retained checks without writing bytecode:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s .agent/hardening/cfw26-section11-repair-audit -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  .agent/hardening/cfw26-section11-repair-audit/check_audit.py
```

## Theorem-premise decision

`THEOREM_PREMISE_LEDGER.json` separates the local lemma from every theorem
premise. In particular, this artifact does not implement or prove:

- the main, inner, or outer zero-knowledge encodings;
- the outer-mask affine-image argument;
- adaptive oracle simulators and their hybrid bound;
- the zero-evader error;
- the relaxed-relation RBR knowledge extractor or error vector;
- the full HVZK view;
- Fiat--Shamir or QROM security;
- composed PQ128 security; or
- Hegemon compiler/verifier refinement and production binding.

Verdict: an independently stated lemma can close the coefficient-one
candidate's local typing, honest-completeness, and value-slice gap. It cannot
close or inherit Theorem 11.3. A complete independent restatement and proof of
the entire reduction would still be required. Accordingly all theorem
inheritance, complete-ZK, QROM, PQ128, and production flags remain false.
