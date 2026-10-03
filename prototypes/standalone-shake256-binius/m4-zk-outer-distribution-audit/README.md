# Outer IronSpartan ZK distribution audit

This directory is a dependency-free, source-bound audit of the outer IronSpartan hiding mechanisms after the separate grouped precommit/private relation repair. It is not a prover, a complete simulator, a strict-security result, or a proof-size frontier point.

## Exact endpoint result

The prover sends `A(r), B(r), C(r)` in the clear. The two private dummy multiplication rows contribute

```text
X = u*a1 + v*a2
Y = u*b1 + v*b2
Z = u*a1*b1 + v*a2*b2,
```

where `u` and `v` are the equality-indicator weights of the two appended rows. For field order `Q`:

- If `u`, `v`, and `u+v` are nonzero, a pure nonzero `C` translation has exact statistical distance `1/Q`; a translation with nonzero `A` or `B` component has `(Q-1)/Q^2`.
- In characteristic two, `u=v!=0` gives the smaller distances `1/Q^2` and `2(Q-1)/Q^3`.
- If exactly one of `u,v` is zero, the distribution is supported on a multiplication graph and a pure `C` translation has distance `1`.
- If both are zero, every nonzero translation has distance `1`.

Let the padded outer constraint tier have `n` variables, and let the two consecutive dummy row indices have Hamming distance `d`. For uniform `r`,

```text
G = Pr[u != 0 and v != 0]
  = (1 - 1/Q)^(n-d) (1 - 2/Q)^d.
```

In characteristic two, the equal-nonzero event is

```text
E = ((Q-1)^(n-d) / Q^n)
    * (((Q-2)^d + (Q-2)(-1)^d) / (Q-1)).
```

Because `r` is exposed, the exact joint distance for a fixed pure-`C` witness translation is

```text
(1-G) + (G-E)/Q + E/Q^2.
```

The two rows are appended at indices `M,M+1`, so `d = HammingWeight(M xor (M+1)) = 1 + trailing_ones(M)`. The maximum outer tier was not compiled in this source/math-only task, so `M,n,d` remain symbolic rather than fabricated.

At `Q=2^128`, the endpoint loss alone is approximately `(n+d+1)2^-128`. B128 therefore supplies only a single-event 128-bit scale, not a strict composed 128-bit statistical bound.

### Strict mixed-field blocker

The formulas above are exact for the pinned same-field backend, where dummy values, row weights, and endpoints all lie in B128. They do **not** carry over to the desired B128-symbol/E384-challenge seam.

With two B128-valued dummy rows and weights `u,v in E384`, the dummy contribution to `A(r)` is

```text
u*a1 + v*a2 in Span_B128{u,v}.
```

E384 has B128-dimension three, while this support has dimension at most two. Any possible witness endpoint translation outside that span moves the marginal to a disjoint coset, giving exact statistical distance `1`; hence the joint endpoint is also perfectly distinguishable. The executable model checks the degree-three vector-space analogue directly.

At least three B128-linearly independent dummy weights are necessary to cover the linear `A/B` endpoints. That is not a sufficiency result: the correlated `C=sum_i u_i*a_i*b_i` distribution still needs a new proof. Alternatively, E384-valued dummy triples would widen the committed representation and must be priced and bound by the mixed-field PCS.

## Libra result

For `g_i(X)=g_i0+g_i1 X+g_i2 X^2`, the exposed mask-linear rows are

```text
mask_eval     = sum_i(g_i0 + z_i*g_i1 + z_i*g_i2)
round i       = beta*g_i1, beta*g_i2
mask_eval_out = sum_i(g_i0 + r_i*g_i1 + r_i^2*g_i2).
```

When `beta != 0`, their exact rank is `2n+1` among `2n+2` rows. The single dependency is exactly the verifier's valid-transcript consistency relation, so the local linear mask spans valid transcript translations. When `beta=0`, every main round coefficient is unmasked and the mask rank is at most two. This costs another `1/Q` bad event. No `z_i` or `r_i` value causes a rank failure because the construction never divides by them.

This is a fixed-challenge linear result, not an adaptive Fiat-Shamir or QROM simulator.

## BaseFold and raw-opening result

The pinned compiler uses

```text
pi' = (1-gamma)pi + gamma*omega
s'  = (1-gamma)s  + gamma*sigma.
```

`gamma=0` removes privacy with probability `1/Q`. `gamma=1` removes the committed witness from the checked opening with probability `1/Q`, a soundness rather than privacy event. The source rejects neither value.

These BaseFold equations are also same-field equations in the pinned implementation. Applying an E384 `gamma` to B128 `pi,omega` produces E384 folded values unless the missing coefficient-lane/vector PCS interface proves how B128 commitments remain binding without widening.

The verifier configuration sets `n_dummy_wires = n_test_queries`. That is a necessary dimension count, not a rank proof. The FRI prover directly opens every original committed codeword at the sampled indices and sends the terminal codeword in full. A sufficient result still needs, for every admitted query transcript, a full-row-rank certificate from the dummy coordinates to all distinct raw message-codeword openings and terminal linear views, followed by a joint `sigma/alpha/FRI/Merkle` simulator. The source contains no such check or theorem.

Therefore the current `n_dummy_constraints=2`, `n_dummy_wires=q_queries` configuration is not certified as complete statistical ZK. The exact local endpoint and Libra calculations are compatible with statistical hiding after charging bad events, but B128 loses strict 128-bit security under their union. A strict route needs the real E384 field plus full ROM/QROM composition; three independent B128 coordinates do not count.

## Frozen source anchors

- `crates/spartan-prover/src/lib.rs:452-478,521-537` — sampled endpoint and clear `A/B/C`; random dummy triples.
- `crates/spartan-verifier/src/lib.rs:249-260` — `n_dummy_wires=n_test_queries`, `n_dummy_constraints=2`.
- `crates/spartan-verifier/src/constraint_system.rs:39-95` — dummy rows appended before power-of-two padding.
- `crates/ip-prover/src/sumcheck/zk_mlecheck.rs:163-183,232-239,281-305,361-407` and `crates/ip/src/mlecheck.rs:114-144` — Libra mask and verifier transcript.
- `crates/iop-prover/src/basefold/channel.rs:248-334` — `sigma`, `gamma`, masked message/claim, and `alpha`.
- `crates/iop-prover/src/fri/query.rs:68-80,116-123,215-241` and `crates/iop-prover/src/fri/fold.rs:352-377` — raw query openings and full terminal codeword.

The executable checks these anchor snippets against pinned revision `3f96163049f680b2909f6545690bd929f1b48c44`.

## Run

From the repository root:

```sh
python3 -m unittest discover \
  -s prototypes/standalone-shake256-binius/m4-zk-outer-distribution-audit \
  -p 'test_*.py'

python3 prototypes/standalone-shake256-binius/m4-zk-outer-distribution-audit/outer_spartan_distribution_audit.py \
  --check-certificate
```

Success must still print `complete_zk=false` and `strict_pq128=false`.
