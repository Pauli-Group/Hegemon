# Audit the characteristic-two HVZK sumcheck kernel

This is an isolated, dependency-free algebra audit.  It does not modify the
production relation, the pinned Binius checkout, the sealed ledger, or the
accepted frontier.

## Purpose

For a quadratic sumcheck round over a characteristic-two field, parameterize
the complete kernel of

```text
L(g) = g(0) + g(1)
```

with a constant and `Z(X) = X(X+1)`.  Check the proposed recurrence

```text
q_i(X) = g_i(X) + Delta_{i-1} X + a_i + b_i Z(X)
Delta_i = Delta_{i-1} r_i + a_i + b_i Z(r_i)
```

using independent full-extension masks `a_i,b_i`.  Establish only the local
perfect-hiding statement that is actually justified, and produce negative
controls for every tempting overclaim.

## Acceptance

- Exhaustively enumerate the quadratic affine fibers and a two-round GF(4)
  transcript.
- Show identical visible distributions for two witnesses with the same public
  sum, and total variation one for a constant-translation witness pair when the
  terminal delta is revealed.
- Show total variation one for `b_i Z(X)` without the constant mask, for masks
  restricted to a proper subfield, and for reused round masks.
- Demonstrate an accepting false-sum transcript when the terminal delta is an
  unbound existential value.
- Differentially check the recurrence over the pinned B128 field and the true
  `E384 = B128[Y]/(Y^3+Y+1)` extension using deterministic SHAKE-generated
  cases.
- Emit exact local wire counters and leave the binding/hiding PCS cost unknown.
- Keep `complete_zk`, `sound_binding`, `strict_pq128`, and `frontier_eligible`
  false.

## Resource controls

Run only the dependency-free Python checker with bytecode generation disabled.
Do not invoke Cargo, build a prover, allocate an oracle, or write a target
directory while free disk is below the repository's 28-GiB admission floor.
