# Proving Attack Matrix

This matrix records the exploit families the repository actively exercises against the shipped proving path. For `0.10.0`, the default block-proof lane is `tx_leaf -> recursive_block`, with `receipt_root` retained as an explicit alternate lane that still needs hostile coverage. The point of this file is operational: every row maps an attack family to the current mechanical guardrails and the command that proves those guardrails still hold.

## Shipped path

- Default tx-proof artifact: canonical native `tx_leaf`
- Default block-proof artifact: canonical native `recursive_block`
- Alternate block-proof lane: explicit native `receipt_root`
- Staged sidecar material: proposer-local only, never network truth

## Matrix

| Campaign | Exploit family | Primary target | Mechanical guardrails today | Proof command |
| --- | --- | --- | --- | --- |
| `parser-malleability` | Non-canonical or malformed native artifact bytes that decode differently across paths | `tx_leaf` decode and self-verification | Canonical decode, exact size cap, self-verification against the public tx view, and binding-hash recomputation before staging or import | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `semantic-aliasing` | Two byte-different artifacts that try to claim the same semantic statement set | binding hashes, duplicate proof identities, conflicting shielded transfers | binding-hash derivation from canonical public inputs, duplicate-binding rejection, and tx-level conflict filtering before authoring | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `staged-proof-abuse` | DA/staging memory pressure, restart confusion, or conflicting restaged bytes | pending ciphertext/proof stores and proposer-local staging | count caps, byte-budget caps, conflicting-byte rejection, and fail-closed restart behavior | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `recursive-block-mismatch` | Block artifact with mismatched tx count, statement commitment, or verifier profile | shipped `recursive_block` verifier path | verifier-profile pinning, tx-count equality, statement-commitment equality, and public replay over already-verified tx-leaf records | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `receipt-root-tamper` | Alternate-lane artifact that replays the wrong receipts or wrong statement set | explicit `receipt_root` lane | native receipt replay and exact receipt/statement matching before acceptance | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `prover-configuration-downgrade` | Wallet prover silently slipping below the production floor | local prover configuration and post-prove checks | production floor clamp unless `HEGEMON_WALLET_PROVER_FAST=1` is set explicitly, plus local self-check defaulting to `Always` | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |
| `review-package-parity` | Review package diverges from the code and vectors the verifier actually ships | native backend review package, vectors, and parity scripts | packaged review artifact, vector verification, and review-package verification script | `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` |

## What this matrix does not claim

- It does not claim the native backend has completed external cryptanalysis.
- It does not claim the timing harness proves constant time.
- It does not claim one CI pass exhausts parser or cryptanalytic search space.

Those remaining research and review questions are tracked in [native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md).

## Modes

The red-team runner supports two operating modes:

- `HEGEMON_REDTEAM_MODE=ci`: PR-friendly hostile regression coverage and review-package parity.
- `HEGEMON_REDTEAM_MODE=full`: everything in `ci`, plus heavier fuzz and adversarial suites that are still practical for local release hardening.

The repository treats `ci` as the merge-blocking minimum and `full` as the release-candidate hardening pass.
