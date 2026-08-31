# SmallWood HX512 direct trace/copy screen

This ExecPlan follows `.agent/PLANS.md`. It owns only this directory, runs no
Cargo build, changes no SmallWood/V5 source or transport, and grants no
production authority.

## Purpose

Screen whether the generic SmallWood LPPC/DECS row-polynomial machinery can
remain compact for the prospective HX512B01 relation if the flat Boolean
occurrence adapter is replaced by a radix trace with scalar copy constraints.
Derive schedule, row, nonlinear, scalar-linear, degree, serializer, matrix,
privacy-width, and isolated DECS geometry exactly where possible. Keep missing
topology, full-relation, proof, complete-ZK, QROM, and refinement evidence
explicitly false or `null`.

## Progress

- [x] Inspect the active engine, semantics, frontend, Boolean BLAKE gadget,
  HX512 suite, and retained comparison artifacts.
- [x] Pin 90 physical calls and 213 RFC 7693 BLAKE2b-512 compressions.
- [x] Verify the fused G schedule: 192 ternary plus 192 binary additions and
  384 rotated XORs per compression.
- [x] Exhaustively verify radix-4 addition, XOR, rotate-63 interpolation, and
  Goldilocks nonresidue 7 arithmetic.
- [x] Preserve the dependency boundary between the two feedforward XOR stages.
- [x] Account for all three RFC control XORs per compression: fold 205 fixed
  positions and allocate 16 selector-bound words for eight private-mode
  authorization positions.
- [x] Conservatively bind the mode-gated authorization state2/state3 digest
  with one 1,024-cell nonlinear selector batch, one 1,024-cell
  broadcast/alias batch, and 1,024 scalar broadcast-copy checks.
- [x] Exhaust every integer packing `K=1..32767`; the `2K` subset matrix width
  proves the current-u16 upper bound.
- [x] Price every current serializer component and matrix dimension.
- [x] Record the K1024/K1029 byte tie and deterministic K1024 tie-break.
- [x] Record fixed-zero padding and distinguish auth nodes `H=460` from
  `cfg.constraint_count`, which remains `null` for the full relation.
- [x] Record the dense-topology indexer as an unimplemented executable gate.
- [x] Add BCS Lemma 7.5 SHA-512 no-go and lambda-768/1024 wire sensitivities,
  separately accounting for SmallWood Theorem 10's `2lambda` salt/`h` widths.
- [x] Add isolated DECS epsilon4 geometry and prevent serializer-only profile
  selection.
- [x] Freeze source pins and canonical JSON after the final local correction.
- [x] Run the canonical checker and nine dependency-free tests, including 31
  fail-closed mutations.

## Exact conditional projection

At radix 4 and K1024, 32 digits represent a word. The fixed core allocates:

```text
2*ceil(81,792*32/1024)     addition sum/carry rows
+ ceil(81,792/1024)        final-carry rows
+ 2*ceil(61,344*32/1024)  even-XOR result/rotation rows
+ 3*ceil(20,448*32/1024)  odd-XOR/shift/recomposition rows
+ 2*ceil(1,704*32/1024)   two dependent feedforward stages
+ ceil(16*32/1024)        selector-bound initial control words
+ ceil(1,024/1024)         mode-gated state2/state3 selector batch
+ ceil(1,024/1024)         mode-gated digest broadcast/alias batch
= 11,054 rows.
```

The 97,704 source bits occupy 48 radix-4 rows, and the 3,408 materialized
message words occupy 107 rows, giving conditional direct-base `R=11,209`.
There are 8,496 nonlinear core output polynomials, 5,316,480 addition/copy
linear checks, 512 control-selection checks, 1,024 authorization-digest
broadcast/copy checks, and 2,176 fixed-zero core padding checks. The
control/link-inclusive core linear total is 5,318,016; with core padding it is
5,320,192, and including 812 source/message padding checks the known direct
minimum is 5,321,004. Full non-hash rows and both exact full `cfg` counts
remain `null`.

The selected matrix geometry is:

```text
witness degree       1,028
mpol degree/width    5,144 / 6
ppol highs           5 x 5,140
mlin degree/width    2,051 / 2
plin highs           5 x 2,046
opened polynomials   11,219
unstacked columns    11,249
LVCS                 2,058 x 5,625
rcombi               10 x 23
subset               23 x 2,048
partial              5 x 30
masking              23 x 5
high coefficients    5 x 5,625
opened row scalars   5 x 11,219
DECS polynomial      5,648 <= 2^20
```

All serialized matrix dimensions fit `u16`. The current encoder's exact
conditional inner expression is

```text
P(K,R,H,A) = 6722 + 648K + 64H + 40R
             + 40*ceil((R+40)/2) + 8A.

P(1024,11209,460,0) = 1,373,074 bytes.
```

The component sum is
`104 + 205604 + 81844 + 1844 + 376836 + 1204 + 29465 + 1472 + 924 + 225004 + 448773`.
This excludes a wrapper, all unknown non-hash rows/auxiliary words, and any
fresh wide-hash wire changes.

## Corrections retained

The first phase-local radix-4 projection chose K992, R11573, and 1,374,178
bytes. Dense same-role packing reduced the expression, but an initial K1024
draft incorrectly pooled two dependent feedforward stages, understating the
base by one row. A second draft omitted private authorization control
selection. The next 11,207-row/1,372,954-byte draft added the 512-digit control
row but omitted the mode-gated state2/state3 digest linkage. The retained
projection also adds a 1,024-cell nonlinear selector row and a 1,024-cell
broadcast/alias row with 1,024 copy checks. These failures demonstrate why the
projection cannot become executable evidence without a complete indexer.

The all-integer search finds the same 1,373,074-byte expression at K1024 and
K1029. K1024 allocates fewer cells, has less padding, and preserves 32 whole
radix-4 words per row, so it is the canonical byte co-minimum. K1029 has fewer
row polynomials and is not dominated on every metric. The other byte minima
are k1/K1558=1,688,546, k4/K463=1,541,786, and
k8/K93=4,101,986; degree 30/510 disqualifies k4/k8 locally.

## Open topology and security gates

The generic linear table addresses arbitrary flattened cells, but nonlinear
identities combine fixed row-polynomial evaluations at one packing coordinate.
A qualifying adapter must implement a public, secret-independent topological
map keyed by `(role, call, compression, round, half-round, G-index, word,
digit)`, align every nonlinear operand/result tuple, bind all fixed and
selected RFC controls, detect aliases/cycles/double-use/omissions, and constrain
every pad to zero. Until then, 11,209 is a conditional serializer projection,
not an executable row count.

For complete ZK, the ordinary radix-2 domain remains forbidden because it
opens interpolation point 64. A final geometry needs a proven-disjoint coset,
independent tapes for every committed leaf, exact index/domain/length binding,
and a whole-view simulator covering every transcript/opening/retry correlation.

BCS Lemma 7.5 contributes `p(x)*2^(-lambda/4+2)`. SHA-512 reaches only
`2^-126` even at `p=1`; actual `p` for this custom transform is `null`, and
64-byte tapes do not satisfy the BCS `2lambda` salt width. Conditional
lambda-768/1024 privacy-Merkle projections are 1,390,738/1,406,930 bytes. If a
fresh grammar also serializes exactly one SmallWood-Theorem-10-width
`2lambda` salt and one `h`, the sensitivities are 1,391,026/1,407,346 bytes.
The complete theorem-faithful wire remains `null`.

The selected 5,625-column DECS geometry has an isolated classical epsilon4 of
about 173.409 bits at 23 openings, versus about 262.378 bits at historical
375 columns. This is not composed security. A final optimizer must jointly
select K, openings, N, eta, rho, digest/tape lambda, exact full R, and every
QROM/grinding/union/refinement term.

## Claim boundary

This package is a source-static arithmetic and serializer screen. It does not
implement the dense topology, change a parser/profile/wire, build a proof,
measure proof bytes or runtime, establish complete ZK or composed PQ/QROM
security, refine a verifier/consensus path, or authorize production.
