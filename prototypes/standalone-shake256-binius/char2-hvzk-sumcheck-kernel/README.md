# Characteristic-two HVZK sumcheck kernel

This directory audits one narrow algebraic transform for the strict mixed-field
backend.  It proves a local hiding fact; it does **not** build a zero-knowledge
proof system.

## Exact quadratic construction

Let `g_i(X)` be the honest degree-at-most-two round polynomial and let the
incoming hidden offset be `Delta_{i-1}`, with `Delta_0 = 0`.  Before the
verifier chooses the current challenge, sample independent uniform
`a_i,b_i` from the **entire challenge field** and send

```text
Z(X)       = X(X+1) = X^2 + X
q_i(X)     = g_i(X) + Delta_{i-1} X + a_i + b_i Z(X)
Delta_i    = Delta_{i-1} r_i + a_i + b_i Z(r_i).
```

Because the field has characteristic two,

```text
q_i(0) + q_i(1)
  = g_i(0) + g_i(1) + Delta_{i-1},
q_i(r_i) = g_i(r_i) + Delta_i.
```

Thus the ordinary sumcheck consistency chain is preserved.  More importantly,
the kernel of `L(p)=p(0)+p(1)` on quadratic polynomials is exactly

```text
ker L = { a + b Z(X) : a,b in E }.
```

For fixed `g_i` and `Delta_{i-1}`, `(a_i,b_i) -> q_i` is a bijection onto the
affine fiber with the required endpoint sum.  The visible round polynomial is
therefore uniform on that fiber and independent of the witness.  A simulator
can sample that fiber directly, obtain `r_i`, and continue from `q_i(r_i)`.
The checker exhaustively confirms the resulting two-round transcript identity
over GF(4).

For individual degree `d`, the corresponding kernel basis is

```text
1, Z(X), X Z(X), ..., X^(d-2) Z(X),
```

so `d` independent field masks are required.  The quadratic M4 composition is
the `d=2` case above. A degree-one padding round must instead use only
`q_i(X)=g_i(X)+Delta_{i-1}X+a_i`; adding `b_i Z(X)` would illegally raise its
degree. The executable audit covers both cases.

## What this does not prove

The local transform is unsound if `Delta_n` is merely an unbound hidden
existential.  A cheating prover can choose arbitrary consistent `q_i` for a
false public sum and then set `Delta_n = q_n(r_n) + f(r)`; the executable
negative control does exactly that.

A real protocol must bind the mask source before the challenges.  Two valid
architectural shapes remain possible:

1. sample `R` uniformly from the complete degree-bounded, zero-Boolean-sum
   kernel; commit to `H=F+R` before the first challenge; bind `H=F+R` and the
   degree to that same committed oracle; and terminate the complete round chain
   in one PCS opening of that same `H` at the final challenge point; or
2. jointly commit to every independent round-mask coefficient before the
   Fiat--Shamir challenges and prove, inside a binding outer relation, the
   exact witness-derived `g_i`, challenge derivation, `q_i`, delta recurrence,
   and terminal equation against the committed witness.

The terminal delta, the separate values `F(r)` and `R(r)`, and all mask
coefficients must remain hidden. Only the combined terminal value
`H(r)=q_n(r_n)` may be opened. For a constant-translation witness pair with the
same public sum, revealing `Delta_n` gives total variation one. This is a
worst-case counterexample, not a claim that every distinct witness pair has
distance one. A SHAKE/Merkle commitment also needs a joint simulator for the
commitments, openings, and outer proof, selective-abort conditioning, and a
QROM proof; its digest alone does not turn this local algebra into complete ZK.

The masks must be independent and uniform in E384.  Omitting `a_i` exposes the
constant coefficient.  Reusing either mask correlates rounds.  Restricting the
masks to embedded B128 confines the transcript to a proper B128-affine
subspace of E384; an allowed translation outside that subspace has disjoint
support and total variation one.

The E384 randomized tests exercise multiplication and the masking recurrence.
They rely on the separate irreducibility certificate in `../strict-mixed-field`
for the fact that `Y^3+Y+1` defines a field; this audit does not reprove that
certificate.

## Canonical local wire cost

For `q(X)=c0+c1 X+c2 X^2`, consistency gives
`c2 = current_claim + c1`. Mirroring the pinned sumcheck `RoundProof`, the
canonical round payload sends only `(c0,c1)` and reconstructs the omitted
highest coefficient `c2`. At 48 bytes per E384 element this is exactly

```text
visible_sumcheck_bytes = 96 * rounds.
```

At a 15-round committed tier this local payload is 1,440 bytes. Sending all
three dense coefficients would be 2,160 bytes, so canonical consistency
reconstruction removes exactly 720 bytes. These figures are for one quadratic
sumcheck instance, not the complete M4 transcript.

The two fresh masks consume 96 bytes of private E384 randomness per round but
add zero direct round-message bytes.  A qualifying encoding sends **zero**
explicit terminal-delta bytes; sending it would add 48 bytes and destroy the
proved hiding property.  If all masks were transmitted raw as three B128
coefficient lanes, their material would cost `96 * rounds` bytes, but raw
transmission is forbidden because it reveals them.

The commitment and opening cost needed to bind these hidden masks is
deliberately recorded as unknown.  Consequently `96 * rounds` is the exact
local visible payload, not a complete-proof estimate and not a proof-size
frontier point.

For mixed-degree protocols, each degree-one round sends one E384 coefficient
and uses one E384 mask, while each quadratic round sends two coefficients and
uses two masks:

```text
visible_sumcheck_bytes = 48 * linear_rounds + 96 * quadratic_rounds.
private_mask_material  = 48 * linear_rounds + 96 * quadratic_rounds.
```

Run the audit without creating bytecode:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/char2-hvzk-sumcheck-kernel/char2_hvzk_sumcheck_audit.py
```

Success prints `LOCAL_KERNEL_PASS` while retaining all production capability
flags as false.
