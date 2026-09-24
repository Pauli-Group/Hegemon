# Retain an exact fail-closed HX512 composed-PQ128 ledger

This ExecPlan is a living record for the bounded HX512 security-accounting
artifact.  It changes no production code.  The deliverable is a Python
standard-library checker, canonical input/report JSON, adversarial tests, and
an explicit claim boundary.

## Progress

- [x] Read the existing SmallWood interactive/CMS accounting, the q48/s6
  correction, the GHCM dyadic checkpoint, and the frozen HX512 grammar/stable
  codec pins.
- [x] Fix the arithmetic contract: Goldilocks, `K=1024`, `rho=eta=5`,
  `beta=2`, `N=2^20`, `q=48`, and candidates `s in {6,7}`.
- [x] Implement strict canonical JSON parsing, exact `Fraction` arithmetic,
  source pinning, scope-aware unions, and fail-closed selection.
- [x] Add adversarial tests for every nullable gate, equality at `2^-128`,
  cap/enforcement mutations, s5 regression, s6/s7 ordering, GHCM history, and
  global-query non-double-counting.
- [x] Generate and read back the retained canonical report.  Thirteen tests
  pass; the retained input selects no profile and every authority remains
  false.

## Decisions

- `Q=2^64` is a single global tagged-product-oracle budget over the modeled
  proof epoch.  It is not reset per proof.  CMS and generic hash screens are
  therefore charged once at `Q`, while per-proof losses are unioned by the
  exact proof-epoch cap and GHCM uses that cap inside its reprogram-event
  count.  The report includes a counterfactual per-proof CMS union but never
  selects it.
- The frozen 95-call semantic registry is one shared domain-separated
  BLAKE2b-512 oracle family.  The physical call count constrains the global
  query budget; it is not also a factor multiplying the global collision or
  preimage screens.
- The 11,892-row topology observation is only a hash-topology lower-bound
  sensitivity.  Non-hash adapter rows are not frozen, so final relation row
  count, LVCS columns, interpolation length, physical transcript calls, and
  proof bytes remain parameterized and null in the retained input.
- A caller-supplied theorem Boolean or zero loss cannot grant production
  authority.  Even a fully populated arithmetic screen leaves
  `composed_pq128=false` and `production_authorized=false`; a future release
  gate must independently authenticate theorem evidence and implementation
  refinement.
- The exact epsilon3-only CMS screens are 125, 176, and 228 whole security
  bits for s5, s6, and s7 respectively.  At fixed `rho=eta=5`, the aggregate
  s7 optimistic screen is instead dominated by epsilon1/epsilon2 and floors
  at 187 bits.  The ledger preserves both facts explicitly rather than
  presenting the epsilon3 improvement as aggregate security.

## Acceptance

The checker must reject noncanonical/duplicate-key JSON, wrong fixed
parameters, stale required pins, nonzero grinding or retries, cap claims that
are not consensus enforced, and every missing quantitative or refinement
premise.  It must reproduce the exact s5 rejection and compare s6/s7 with
integer rational arithmetic.  Equality to `2^-128` is failure.  A conditional
smallest-s selection is permitted only for one explicitly modeled and
consensus-enforced proof-epoch cap.
