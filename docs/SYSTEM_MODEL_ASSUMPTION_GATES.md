# System-Model Assumption Gates

This document records the release-blocking evidence expected for assumptions
that cannot be discharged by Lean alone because they depend on operators,
networks, storage devices, external infrastructure, advisory feeds, or
deployment traffic.

The machine-readable source of record is
`config/system-model-assumption-gates.json`. The formal-core command
`check-system-model-gates` rejects a release if any required category is
missing, not marked fail-closed, not release-blocking, stale beyond the
declared freshness SLA, or lacking checked-in evidence paths.

Required categories:

- `da-retention`: data-availability sidecar retention and hot/cold
  availability evidence.
- `storage-durability`: critical native storage mutation durability-barrier
  evidence.
- `global-privacy-boundary`: public metadata, batch timing, topology, and
  miner-order leakage boundary evidence.
- `release-infrastructure`: CI release workflow and branch-protection/ruleset
  evidence.
- `dependency-scanner-completeness`: cargo-audit, waiver, forbidden primitive,
  and binary scanner freshness evidence.
- `performance-budget`: evidence that formal gates and runtime hardening remain
  inside the accepted performance budget.

These gates do not prove the external world behaves honestly. They make the
system model explicit and fail closed when required operational evidence is not
present.
