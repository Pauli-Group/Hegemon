# Frozen full-Pay1x2 measurements

`full-pay1x2-rate-sweep-2026-08-19.json` is the real inverse-rate sweep for the
complete V2 cryptographic core with the final 478-byte network-bound HGS2
statement in the public transcript. `rate3-harness-2026-08-19.json` is the
repository harness result for the selected rate, including process-tree peak
RSS, block capacity, byte caps, and the explicit unsupported-security override.
The rate-three row and harness were regenerated under the corrected prospective
HGS2 `2/5/4/1/1` route and full `HGSP`/action/network composition.
`composed-verifier-v5-delta-2026-08-19.json` freezes the source hashes, route,
fresh-forgery negative controls, and pre-proof rejection inventory.
`core-baseline-pre-adapter-2026-08-19.json` preserves the earlier 232-byte-core
measurement so the adapter overhead remains auditable.

These are host measurements, not analytical estimates. Timing and RSS vary by
host; canonical transcript sizes are deterministic for the fixed backend
revision, circuit, rate, and deterministic-test seed.
