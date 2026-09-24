# HX512 composed-PQ128 ledger

This directory contains a source-pinned, exact-rational security ledger for
the inactive HX512/SmallWood candidate.  It is not a security certificate and
cannot authorize production.

The four interactive errors are computed as

```text
epsilon1 = |F|^-eta
epsilon2 = |F|^-rho
wit_degree = K + s - 1
mpol_degree = 6*wit_degree - K
D = mpol_degree + K
epsilon3 = falling(D, s) / falling(|F|-K, s)
epsilon4 = falling(n_lvcs_cols+q-1, q) / falling(N, q)
```

and the exact CMS envelope is

```text
12*Q^2*(epsilon1+epsilon2+epsilon3+epsilon4)
  + 48*Q^3/2^512
  + 2*K^2/2^512.
```

`Q=2^64` is global across the exact proof epoch; it is not multiplied by the
number of proofs.  Per-proof classical-ZK, sampler, RNG, and lifecycle losses
are unioned by the consensus proof cap.  GHCM leaf/chain losses put the same
cap directly into `R`.  BLAKE2b's 95 domain-separated semantic call slots are
likewise accounted under one global oracle query budget, so 95 is a physical
inventory/cap input rather than a second collision multiplier.

The retained input deliberately leaves final adapter/engine/transcript
geometry, hashes, theorem losses, RNG/refinement evidence, and consensus caps
null.  Consequently the retained report has no selected profile and every
authority flag is false.

For the PIOP opening term alone, exact `12*Q^2*epsilon3` has 125, 176, and 228
whole security bits at s5, s6, and s7.  The fixed `rho=eta=5` epsilon1 and
epsilon2 terms dominate the aggregate s7 screen at 187 whole bits.  The s7
epsilon3 number is therefore not advertised as the aggregate composed bound.

Run:

```sh
python3 .agent/hardening/hx512-composed-pq128/ledger.py \
  --input .agent/hardening/hx512-composed-pq128/ledger_input.json \
  --output .agent/hardening/hx512-composed-pq128/ledger_report.json \
  --repo-root .
python3 -m unittest discover \
  -s .agent/hardening/hx512-composed-pq128 -p 'test_*.py'
```

Use `--check` to require byte-identical canonical report regeneration.
