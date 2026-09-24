# SmallWood HX512 direct-trace screen

This package is a dependency-free, fail-closed architecture screen. It does
not implement or authorize a proof backend.

The smallest serializer projection in the exhaustive `k in {1,2,4,8}` and
integer-`K` search is radix 4 at `K=1024` or `K=1029`. `K=1024` is the
canonical member of the byte tie because it preserves whole-word alignment
and uses fewer allocated cells. Its dependency-safe conditional geometry is:

```text
core rows                         11,054
source rows                           48
materialized-message rows            107
direct-base R                     11,209
core nonlinear output polynomials  8,496
arithmetic/copy linear checks   5,316,480
control-selection linear checks       512
auth digest broadcast/copy checks    1,024
fixed-zero core padding checks       2,176
maximum degree                           6
```

The schedule fuses each BLAKE G's two `a=a+b+x/y` operations into ternary
radix-4 additions and keeps its two `c=c+d` operations binary: 384 addition
relations per compression instead of 576 binary additions. The two dependent
feedforward XOR stages retain separate padding. Of the 213 RFC control
positions, 205 are profile-fixed; the eight authorization positions need 16
selector-bound precomputed initial-control words. Blanket constant folding is
not sound. A separate conservative authorization linkage materializes one
1,024-cell nonlinear selector batch and one 1,024-cell broadcast/alias batch
to bind the selected mode's state2/state3 digest into the common topology;
the latter contributes 1,024 scalar copy checks. These are two rows and one
additional nonlinear output polynomial at `K=1024`.

Every selected proof matrix fits the current `u16 x u16` payload grammar. For
the current strict shape (`rho=5`, five openings, `beta=2`, 23 depth-20 DECS
paths, `eta=5`, `N=2^20`, 64-byte digests/tapes, no auxiliary words), the exact
conditional inner-payload expression is

```text
P(K,R,H,A) = 6722 + 648K + 64H + 40R
             + 40*ceil((R+40)/2) + 8A

P(1024,11209,460,0) = 1,373,074 bytes.
```

This is serializer-shape arithmetic, not proof bytes. The local
arithmetization enum has no `K=1024` profile, the strict V6 path is `K=64`, and
no parser/wire identity/refinement accepts this candidate. More importantly,
the dense row count remains conditional until an executable,
secret-independent topological indexer proves every nonlinear operand/result
alignment, alias, cycle, omission, and padding-zero property. Full non-hash
rows and exact `cfg.constraint_count` remain `null`.

The conditional 1.37 MB expression is below the retained Ligero paper lanes
(8,652,192 and 16,437,920 bytes), while Aurora proof bytes remain `null`. The
corrected 29,509,887-scalar HX512 occurrence projection is not directly
ratio-comparable: it is a projected full relation, whereas this screen counts
packed direct-base rows and still omits non-hash adapter rows.

Complete ZK also fails closed. SHA-512 cannot satisfy the direct BCS Lemma 7.5
strict `>128` requirement even at the impossible best case `p(x)=1`: its term
is `2^-126`. The actual custom transform's `p(x)` is `null`, and current
64-byte tapes are not the theorem's `2lambda` leaf salts at `lambda=512`.
Conditional fresh-width sensitivities are:

| lambda | BCS node | BCS tape | privacy-Merkle-only bytes | plus one SmallWood Thm. 10 `2lambda` salt and one `h` |
|---:|---:|---:|---:|---:|
| 768 | 96 B | 192 B | 1,390,738 | 1,391,026 |
| 1024 | 128 B | 256 B | 1,406,930 | 1,407,346 |

The final theorem-faithful wire remains `null`: BCS uses `lambda`-bit oracle
outputs and `2lambda`-bit leaf salts, while SmallWood Theorem 10 separately
samples the proof salt and Fiat-Shamir `h_i` values at `2lambda` bits. No
refinement connects the custom engine to either theorem.

`K=1024` is not a final security profile. Its isolated classical DECS
`epsilon4` geometry is about 173.409 bits at 23 openings, down from about 262.4
bits for the historical 375-column geometry, before QROM and union losses.
The final optimizer must jointly search `K`, openings, `N`, `eta`, `rho`,
digest/tape widths, exact full `R`, and every composed security term.

Run the retained checks without Cargo or third-party dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/smallwood-hx512-trace-screen/trace_screen.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/smallwood-hx512-trace-screen/check_trace_screen.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/smallwood-hx512-trace-screen -p 'test_*.py' -v
```

All proof, complete-ZK, composed PQ/QROM, refinement, consensus, and production
authority fields remain false or `null`.
