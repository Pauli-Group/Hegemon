# Parametric repair proof for CFW26 Construction 11.4

Verdict: Hegemon can state a coherent independent construction with a public
nonzero mask coefficient `c`, and can select `c=1`. The repaired construction
has a direct perfect-completeness proof and a whole-view HVZK proof for the
paper's *formal nonadaptive* class `D<=t`, conditional on the stated
zero-knowledge encodings. It does not inherit Theorem 11.3. The printed
construction has three independent type/completeness defects, its first RBR
error coordinate is false under the stated premises, and Definition 3.16 does
not justify the proof sketch's claimed adaptive answering. Full RBR, adaptive
complete ZK, Fiat--Shamir/QROM, PQ128 composition, and production authority
remain false.

This artifact is a theorem-delta audit, not an implementation of the IOR or a
production proof system.

## Sources and dependency closure

`SOURCE_DEPENDENCY_MAP.json` records every source dependency read for this
proof attempt. The two pinned primary snapshots are:

- CFW26, *Zero-Knowledge IOPPs for Constrained Interleaved Codes*, ePrint
  2026/391, 82 pages, SHA-512
  `be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd`.
- ACFY25, *WHIR: Reed--Solomon Proximity Testing with Super-Fast
  Verification*, 83 pages, SHA-512
  `0b5fceaa077ee4ff3dc3cbe1ef9d68ec67761a2778c4c7a6caf7bde8dd5b1c3eef42c9c9373303bba997726e836620b508fd470b926475c86c6736fa272d58d9`.

The retained page renders cover CFW26 Claims 3.1/Lemma 3.2; Definitions
3.3--3.16, 4.1--4.7, 5.1--5.8; Construction 6.3 and Lemmas 6.4--6.5;
Definitions 11.1--11.2, Theorem 11.3, Construction 11.4, and its proof sketch;
plus ACFY25 Appendix A's source GR1CS construction and full RBR proof. The
source Section 11 RBR argument is explicitly only a proof sketch and delegates
the unmasked analysis to ACFY25 and the masking analysis to Section 6.

## Notation

Let

```text
d      = log2(ell)+1,
L_in   = inner-mask coefficient-vector length,
L_out  = outer-mask coefficient-vector length,
c      in F*, a public nonzero coefficient,
z_M    = ze(rho)_M for M in {A,B,C}.
```

For a matrix `M`, verifier point `alpha in F^d`, public input `v`, and witness
`w`, define

```text
u_M(alpha) = sum_b Mhat(alpha,(b,0)) vhat(b),
q_M(alpha) = sum_b Mhat(alpha,(b,1)) what(b),
S_M(alpha) = sum_i s_(M,i)(alpha_i).
```

For a coefficient vector `s`, let

```text
pow(x) = (1,x,x^2,...,x^(L-1)),  so <s,pow(x)> = s(x).
```

## The three additional literal defects

The earlier coefficient audit found the Step-3/Step-8 conflict and the
ill-typed pair passed to `identity`. Reading the full target relation exposes
two more exact typing/completeness issues.

### Endpoint state is evaluation at a coefficient, not at one

Construction 11.4 Step 1 samples each inner mask as a *coefficient vector*
conditioned on `s(0)=s(1)=0`, then prints

```text
st1 = (1,0,...,0),
st2 = (0,1,0,...,0),
sl_in_circle = (identity,identity)^T,
target = (0,0)^T.
```

The second row therefore computes the coefficient of `X`, not `s(1)`. Over
any field, `s(X)=X^2-X` satisfies both sampled endpoint conditions, while the
printed second row returns `-1`. Thus even a coefficient-repaired honest
prover generally fails Definition 11.1's output relation.

The exact repair is

```text
st1 = pow(0) = (1,0,...,0),
st2 = pow(1) = (1,1,...,1).
```

The executable counterexample is retained in
`endpoint_state_counterexample()`.

### Main identity is a dimension-changing footnoted abuse

Theorem 11.3 prints `sl_M=identity` and Step 9 prints `st_M=M`, yet the main
message has length `ell` while `M` is a `2ell` by `2ell` matrix description.
The footnote says to compute an MLE, but Definition 5.2's identity does not do
that and `alpha` is missing from the printed state.

The exact repair names a row-MLE succinct form:

```text
row_M(M,alpha)[b] = Mhat(alpha,(b,1))  for b in {0,1}^{log ell},
state_M = (M,alpha).
```

This is a vector of the required witness-message length. The public half is
computed separately as `u_M`.

### Inner joint form needs scalar multiplication

Definition 5.2's identity accepts one vector state. Step 9 passes the pair
`(pow(alpha_i),z_M)`, which has Definition 5.4's `times(identity)` shape. The
parametric repair uses that form and includes `c` in its scalar:

```text
sl_in_(M,i) = times(identity),
state_in_(M,i) = (pow(alpha_i), c z_M).
```

For Hegemon's `c=1`, this is exactly
`times(identity)(pow(alpha_i),z_M)`.

## Entire repaired construction C11.4(c)

This section is a self-contained restatement, rather than a reference to the
ambiguous printed forms.

The source relation contains `((F,n0,ell,A,B,C,v),w)` where `F` is finite,
`A,B,C` are `(ell+n0)` by `(ell+n0)` matrices, `v in F^n0`, `w in F^ell`,
and, for `z=(v,w)`, every row `a` satisfies

```text
(A z)[a] (B z)[a] = (C z)[a].
```

Assume `ell=n0`, `ell` is a power of two, and set `d=log2(ell)+1`, so each
matrix is `2ell` by `2ell`. Let `c in F*` be part of the public relation
version. The three encodings have maps

```text
Enc_C    : F^ell   x F^r     -> Sigma^m,
Enc_Cin  : F^L_in  x F^r_in  -> Sigma_in^m_in,
Enc_Cout : F^L_out x F^r_out -> Sigma_out^m_out.
```

There are `3d` inner-mask messages and `d` outer-mask messages. Define one
typed row-MLE succinct form

```text
sl_row(M,alpha)[b] = Mhat(alpha,(b,1)),
```

whose state is `(M,alpha)` and whose output is a row in `F^ell`. The main form
is `sl[ze,(sl_row,sl_row,sl_row)]`. Every inner joint form is
`times(identity)` in `F^L_in`. Every inner endpoint form is the identity on a
`2` by `L_in` state, and every outer evaluation form is the identity on a
one-row `L_out` state.

For completeness, the repaired target relation's explicit instance is

```text
x = ((mu,st,(st_in_(M,i))_(M,i)),
     ((mu_endpoint_(M,i),st_endpoint_(M,i))_(M,i)),
     ((mu_out_j,st_out_j)_j)),
```

its implicit instance is

```text
y = (f_bar,(s_bar_(M,i))_(M,i),(t_bar_j)_j),
```

and its witness is

```text
(f,r,(s_(M,i),r_(M,i))_(M,i),(t_j,r_j)_j).
```

Membership means exactly: `f_bar=Enc_C(f,r)`; every inner and outer oracle is
the corresponding encoding; every inner endpoint form applied to its message
equals its two-component endpoint target; every outer evaluation form applied
to its message equals its scalar target; and

```text
<f,sl_main(st)> + sum_(M,i) <s_(M,i),sl_in_(M,i)(st_in_(M,i))> = mu.
```

The ten protocol steps below construct this target instance and witness.
Assume `L_in>=4` and `L_out>=2 L_in` when invoking the conditional HVZK claim.

1. **Inner masks.** For every `M in {A,B,C}` and `i in [d]`, sample uniformly
   `s_(M,i) in F^{<L_in}[X]` subject to
   `s_(M,i)(0)=s_(M,i)(1)=0`; sample encoding randomness and send its
   `Enc_Cin` oracle. Set its endpoint target to `(0,0)` and its endpoint state
   to `(pow(0),pow(1))^T` under `(identity,identity)^T`.

2. **Witness encoding.** Regard the witness as the coefficient/evaluation
   vector of its multilinear extension, sample encoding randomness, and send
   `Enc_C(w,r)`.

3. **Parametric masked constraint.** Define the input/witness multilinear
   extension `zhat` exactly as in Step 3, and define

   ```text
   g_c(X) = (Acontraction(X)+c sum_i s_(A,i)(X_i))
            (Bcontraction(X)+c sum_i s_(B,i)(X_i))
            -(Ccontraction(X)+c sum_i s_(C,i)(X_i)).
   ```

4. **Outer masks and initial target.** Independently sample `d` uniform
   polynomials `t_i in F^{<L_out}[X]`, encode each under `Cout`, and send

   ```text
   mu_tilde = sum_{a in {0,1}^d} sum_i t_i(a_i).
   ```

5. **Initial verifier randomness.** Sample `epsilon in F` and `r in F^d`.

6. **Masked sumcheck.** Run the printed `d`-round sumcheck on

   ```text
   sum_a [epsilon g_c(a) eq(r,a) + sum_i t_i(a_i)] = mu_tilde.
   ```

   The round-`j` polynomial is the sum over the remaining Boolean suffix of
   that same integrand after fixing the prior coordinates to `alpha`. Sample
   `alpha_j in F` after each message, except sample
   `alpha_d in F\{0,1}`.

7. **Outer evaluations.** Send `m_j=t_j(alpha_j)`. The output succinct state
   is `pow(alpha_j)`, form `identity`, target `m_j`.

8. **Final sumcheck values.** Send, for each `M`,

   ```text
   v_M = u_M(alpha)+q_M(alpha)+c S_M(alpha).
   ```

   Check

   ```text
   epsilon (v_A v_B-v_C) eq(r,alpha)+sum_j m_j = h_d(alpha_d).
   ```

   Compute the public values `u_M(alpha)`.

9. **Joint challenge and typed forms.** Sample `rho`, set
   `z=ze(rho)`, define each main row form `row_M(M,alpha)`, and set

   ```text
   sl_main = sl[ze,(row_A,row_B,row_C)],
   state_main = ((A,alpha),(B,alpha),(C,alpha),rho),
   sl_in_(M,i) = times(identity),
   state_in_(M,i) = (pow(alpha_i),c z_M),
   mu = sum_M z_M(v_M-u_M).
   ```

10. **Output.** Output Definition 11.1's explicit instance with these typed
    states/targets, its implicit oracle tuple (main, `3d` inner, `d` outer),
    and the corresponding messages/randomness as witness.

This construction adds no prover message relative to the intended source
construction: `alpha` was already verifier randomness and `c` is a versioned
public constant. It does change the mathematical relation. Exact wire
serialization is outside this audit, so an implementation needs a new
domain/version identity and must separately prove its byte-level binding.

## Complete factor-c occurrence audit

| Site | Source | C11.4(c) | Why |
|---|---|---|---|
| Step 3 A mask sum | `1` | `c` | defines masked factor |
| Step 3 B mask sum | `1` | `c` | defines masked factor |
| Step 3 C mask sum | `1` | `c` | defines masked factor |
| Step 6 partial `g` | inherits `1` | inherits `c` | same polynomial at every round |
| Step 8 defining `v_M` | `1` | `c` | must equal factor evaluated at `alpha` |
| Step 8 second equality | `2` | `c` | must be an actual decomposition |
| Step 9 inner functional | ill-typed identity | `c z_M pow(alpha_i)` | joint equality |
| Page-71 value claim | `2` | `c` | uniform iff `c!=0` |
| RBR partial-state equations | unstated | same `c` | degree unchanged |
| final zero-evader discrepancy | unstated | includes `c S_M` | detects a nonzero 3-vector |

No other factor two in the source proof is replaced. In particular, the
`2^(d-j)` multiplicities in the *outer-mask* affine map come from summing over
Boolean suffixes. They are unrelated to `c` and remain the reason the source
assumes odd characteristic.

The complete structural-two audit is:

| Occurrence | Replace by `c`? | Reason |
|---|---:|---|
| `char(F)!=2` in Theorem 11.3/Lemma 6.4 | no | the outer-map powers of two still need inverses even for `c=1` |
| `L_out>=2 L_in` | no | this is the quadratic masked-factor degree bound |
| `2^(d-j)` in the Lemma-6.4 affine map | no | it counts Boolean suffix assignments |
| last challenge in `F\{0,1}` and denominator `|F|-2` | no | two endpoint roots are excluded |
| `2ell` matrix geometry and `d=log2(ell)+1` | no | this is public/witness concatenation geometry |
| individual degree `<2` and Boolean domain `{0,1}` | no | this defines multilinear interpolation |
| two inner endpoint rows | no | both endpoint constraints are required |
| ACFY25 `n=2k` and the quadratic predicate | no | these are source RBR geometry/degree terms |

Thus replacing the mask coefficient preserves the published *value* argument
for every `c!=0`, but it does not allow Hegemon to drop odd characteristic or
alter any of these structural occurrences. `factor_occurrence_ledger()`
retains the same classification in machine-readable output.

## Perfect completeness of C11.4(c)

This step is closed for every `c` (nonzero is needed later for privacy).

At each Boolean row `a`, all inner masks vanish because every coordinate is 0
or 1. Hence `g_c(a)` is exactly the original R1CS residual and is zero for an
honest witness. The Step-4 definition of `mu_tilde` therefore makes the Step-6
initial sumcheck claim exact. Standard sumcheck telescoping gives every round
check and its terminal evaluation. The Step-8 `v_M` are exactly the three
factors used to compute `g_c(alpha)`, so the final sumcheck check holds.

The repaired endpoint states compute the sampled endpoint evaluations and
therefore yield `(0,0)`. Each outer state computes `t_j(alpha_j)=m_j`.
Finally,

```text
<w,sl_main> + sum_(M,i) <s_(M,i),c z_M pow(alpha_i)>
= sum_M z_M q_M + sum_M c z_M S_M
= sum_M z_M(v_M-u_M)
= mu.
```

All Definition 11.1 equalities hold, including code encodings by construction.

The literal printed construction does not receive this proof: `X^2-X`
already falsifies its endpoint output claim, its main identity is not the
row-MLE map, its inner pair state is ill-typed, and its two Step-8 equations
disagree.

## Degree closure

For one sumcheck variable, a masked matrix factor has degree at most
`L_in-1`. The A/B product has degree at most `2L_in-2`; multiplication by the
equality polynomial adds one. Thus each round message has degree at most
`2L_in-1` and fits in `F^{<L_out}[X]` when `L_out>=2L_in`. Multiplication by a
nonzero constant `c` changes no degree.

This per-round degree fact is separate from the initial RBR challenge. The
multilinear extension of the Boolean residual table is a polynomial in `d`
variables of total degree up to `d`, regardless of `L_out`.

## Whole-view HVZK for the formal nonadaptive class

This step is closed conditionally for exactly the theorem's formal class
`D<=t` in Definition 4.7, assuming all three encoding simulators from
Definition 3.16 and the paper's odd-characteristic/length premises. It is not
an adaptive-query theorem.

### Value lemma for arbitrary nonzero c

Let `K` be the vector space of degree-below-`L_in` polynomials vanishing at 0
and 1. For `alpha_d` outside `{0,1}`, the evaluation map `K -> F` is
surjective: `a X(X-1)` is in `K`, and its value
`a alpha_d(alpha_d-1)` ranges bijectively over `F`. A uniform inner mask has a
uniform evaluation. Multiplication by `c` preserves uniformity exactly when
`c!=0`. Conditioning on every other inner mask gives

```text
v_M = constant_M + c s_(M,d)(alpha_d),
```

so each `v_M` is uniform; independence of the three final masks makes the
triple uniform and witness-independent. The executable audit enumerates every
`c` in `F_5`, `F_7`, and `F_11`; every nonzero coefficient gives full uniform
support and `c=0` collapses it.

### Outer transcript lemma

Fix verifier randomness, inner randomness, and therefore `(v_A,v_B,v_C)`.
The `d L_out` outer coefficients map affinely to

```text
(mu_tilde, h_1,...,h_d, m_1,...,m_d).
```

The ambient dimension is `1+d L_out+d`. The `d` sumcheck equations plus the
terminal equation are `d+1` independent affine constraints, so their solution
space `T(v)` has dimension `d L_out`.

The linear part of the honest map is injective in odd characteristic. If its
output difference is zero, the nonconstant coefficients of `h_j` equal
`2^(d-j)` times the nonconstant coefficients of `t_j`; hence every `t_j` is a
constant. The revealed value `m_j=t_j(alpha_j)=0` then makes every constant
zero. Domain and target dimensions agree, so the map is a bijection onto
`T(v)`. Uniform masks therefore produce the uniform distribution on `T(v)`.

`c` is absent from this linear map; it only changes the fixed affine inner
term. The executable rank audit checks image-equals-kernel in 36 odd-field
geometries. Characteristic-two controls lose rank, as predicted.

### Correct formal simulator and encoding hybrids

The simulator samples `(epsilon,r,alpha,rho)`, samples the `v` triple uniformly,
samples uniformly from `T(v)` by finite-field Gaussian elimination, and
computes the complete explicit output instance. Because Definition 4.7 makes
`D<=t` nonadaptive, write `D=(D0,D1)`: run `D0` on that explicit instance to
obtain all query sets before seeing any oracle answer. Call the corresponding
Definition-3.16 simulator on each fixed set, then run `D1` on those answers.

The value and outer-transcript lemmas give an exact match for the non-oracle
transcript. Conditioned on the transcript, messages, and fixed query sets,
replace each encoded oracle answer by its simulator one at a time. Each change
costs at most `zeta`. There are

```text
3d inner + d outer + 1 main = 4d+1 = 4 log2(ell)+5
```

oracles. The whole extended view in Definition 4.1 is therefore within
`(4 log2(ell)+5) zeta`, exactly for `D<=t`.

### Why the word “adaptive” remains open

The Section 11 proof sketch says to answer `D`'s “(adaptive) oracle queries”,
but Definition 4.7 explicitly restricts `D<=t` to nonadaptive query sets, and
Definition 3.16 supplies a simulator for a fixed set rather than an online,
consistent simulator.

This is not a cosmetic proof omission. The executable pointer encoding over
`F_11` is injective and has a single message-independent fixed-set simulator
with distance at most `2/11` for every message and every fixed set of at most
two queries. The executable check enumerates the full quantifier. An adaptive
distinguisher queries a pointer and then its indicated cell and recovers the
message perfectly; the views for two messages have statistical distance 1.
Thus the cited premise does not imply adaptive-query ZK. A stronger
online/straight-line encoding premise and a new hybrid proof are required.

## RBR theorem delta

The coefficient substitution itself is harmless to the local RBR steps:

- it changes no polynomial degree;
- each univariate sumcheck discrepancy still has degree below `L_out`;
- the final discrepancy is a vector
  `D_M=(v_M-u_M)-(q_M+c S_M)`, and Definition 3.3 bounds
  `Pr[sum_M ze(rho)_M D_M=0]` by `epsilon_zero` whenever that vector is
  nonzero; and
- list-size union factors are unchanged.

However, the printed first error coordinate is not valid under the theorem's
stated premises.

### Exact initial-coordinate counterexample

Choose `F_101`, `L_in=4`, `L_out=8`, and `d=10` (`ell=512`). These satisfy
`L_in>=4` and `L_out>=2L_in`. Use zero masks and a sparse invalid R1CS whose
residual is one only on the all-one Boolean row: take the planted assignment's
first coordinate to be one, set `A z=B z=1` on every row, and set `C z=1`
except `C z=0` on that row. The multilinear extension of the residual table is

```text
P(r)=product_(i=1)^d r_i.
```

With a matching zero outer target, the initial consistency equation is
`epsilon P(r)=0`. Its exact acceptance probability is

```text
1-(100/101)^11
= 1156683466653165551101 / 11156683466653165551101
≈ 0.1036762825.
```

Commit to the zero witness, use zero inner and outer masks, and set the outer
target to zero. Whenever `epsilon P(r)=0`, run the honest sumcheck for that
actual polynomial and reveal `v_M=u_M`. Every endpoint, outer-evaluation,
terminal-sumcheck, and repaired joint-target equation then holds, so the
downstream target relation has a witness although the source R1CS has none.
This is a complete accepting reduction path, not only a failed proof
technique.

With singleton decoding lists, the printed first coordinate is

```text
(L_out+1)/|F| = 9/101 ≈ 0.0891089109,
```

which is smaller than the actual probability. The safe direct
Schwartz--Zippel numerator is `d+1`, giving `11/101≈0.1089108911` here.

The numerical coordinate can be repaired by either:

1. replacing `L_out+1` with `d+1`; or
2. adding the missing premise `L_out>=d`, after which the printed value is a
   valid loose upper bound.

ACFY25 Appendix A's unmasked RBR proof explicitly retains dimension in its
initial polynomial-identity error; it does not justify replacing dimension by
an unrelated mask-message length. Either numerical repair remains only a
necessary delta: it does not supply the missing Section-11 knowledge-state and
extractor proof.

### What remains open for RBR

The per-round `L_out/|F|` and last-round `L_out/(|F|-2)` local polynomial
bounds, and the final `epsilon_zero` step, are source-compatible after the
typed `c` repair. Nevertheless, Section 11 does not state its knowledge-state
function or extractor; it only cites ACFY25 and Section 6 by analogy. This
artifact does not fill every list-candidate transition, relaxed-distance
witness map, and erasure-correction runtime argument. Coupled with the false
printed first coordinate, the exact RBR theorem remains open. A corrected
error vector plus a complete independently checked state/extractor proof is
required.

The printed vector has `d+3` coordinates: one initial coordinate, `d`
sumcheck-coordinate entries, one separately printed last-domain entry, and
one zero-evader entry. For `ell=2^25`, `d=26`, that is 29 coordinates; the
encoding-HVZK union has 105 oracle terms.

## Closure ledger

| Obligation | Result |
|---|---|
| Full repaired construction stated | closed for C11.4(c) |
| All factor-two/c occurrences tracked | closed |
| Typed main row-MLE form | closed in restatement; printed literal false |
| Endpoint output relation | closed with `pow(1)`; printed literal false |
| Perfect completeness | closed for repaired construction |
| Value distribution for `c!=0` | closed |
| Outer affine transcript distribution | closed in odd characteristic |
| Fixed-set encoding hybrids | closed conditionally on Definition 3.16 |
| Whole HVZK for formal `D<=t` | closed conditionally, nonadaptive only |
| Adaptive-query HVZK | false under current premise; explicit separation |
| Initial printed RBR error | false; explicit counterexample |
| Full corrected RBR state/extractor | open |
| Theorem 11.3 inheritance | false |
| Complete zero knowledge for Hegemon | false |
| Fiat--Shamir/QROM/PQ128 | absent |
| Production authority | false |

Hegemon's `c=1` choice is algebraically the simplest coherent member of the
family, but it is an independent new specification. It must receive a new
relation/domain/version identity and a complete RBR, adaptive/required-view
ZK, QROM, compiler-refinement, and production proof before admission.
