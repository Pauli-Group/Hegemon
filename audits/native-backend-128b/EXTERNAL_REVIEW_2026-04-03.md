# Native Backend Full-Gate External Review

Reviewer: Codex external review pass

Date: 2026-04-03

Repository fingerprint: `6a9b335dc1d4070f2fb507ad607bcac1678cef96`

Reviewed package hash: `a7e884631cd77552ab4f960e5ec0b6d0ae4ddacc39fec2d0a441a3b45abb4f22`

## Summary

- Shipping recommendation: acceptable only as `candidate_under_review`
- Claim verdict: `claim unsupported`
- Review-package exactness verdict: `implementation inconsistent`
- Verifier-path verdict: `implementation consistent`

The sampled implementation path is materially stronger than the weakest language in the docs: the native tx-leaf verifier replays STARK verification, re-derives the canonical receipt, reconstructs the deterministic commitment, and receipt-root verification replays every fold step. I did not find an accepting-path bug in the sampled verifier surface.

The external `128`-bit story is still not defensible as a settled claim. The repo openly relies on heuristic or unproven steps for transcript soundness and for the concrete coefficient-space security floor, and the review package that is supposed to freeze the exact claim surface still contains stale numbers, stale schedule labels, and deployment-state contradictions.

## Findings

### 1. High: the external `128`-bit claim is unsupported by the repo's own stated assumptions

- `docs/crypto/native_backend_security_analysis.md:33` defines `transcript_soundness_bits = floor(challenge_bits * fold_challenge_count / 2) = 157`.
- `docs/crypto/native_backend_security_analysis.md:35` says the `/2` divisor is a blanket conservative cap and is "not derived from a specific theorem for this construction."
- `docs/crypto/native_backend_commitment_reduction.md:3` says the reduction note is "not a concrete hardness proof."
- `docs/crypto/native_backend_commitment_reduction.md:31` says external reviewers still need to verify that the `GoldilocksFrog` quotient does not admit an easier attack than the flattened SIS estimate.
- `docs/crypto/native_backend_security_analysis.md:126` says the active ring hardness question is still open and external review is still expected.

Impact:

- The repo can defend "candidate under review with mechanical overclaim rejection."
- The repo cannot defend "externally supported 128-bit security floor" today.

Verdict:

- `claim unsupported`

### 2. High: the exact-spec and review-package surface is internally inconsistent

The package repeatedly describes itself as the exact frozen review surface, but several documents disagree with the code or with each other:

- `docs/crypto/native_backend_security_analysis.md:38` still carries a stale `513 * 8 * 9` line next to the active `76 * 54 * 9` line.
- `docs/crypto/native_backend_security_analysis.md:66` says the flattened instance uses `n_eq = 592`, while the code computes `11 * 54 = 594` in [circuits/superneo-backend-lattice/src/lib.rs:309](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L309) and the code test locks that current floor in [circuits/superneo-backend-lattice/src/lib.rs:3016](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L3016).
- `docs/crypto/native_backend_security_analysis.md:72` still says the structural statistic is `commitment_random_matrix_bits = 360`, while the code test locks the active value at `486` in [circuits/superneo-backend-lattice/src/lib.rs:3016](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L3016).
- `docs/crypto/native_backend_commitment_reduction.md:100` and `docs/crypto/native_backend_commitment_reduction.md:101` contain both `ell <= M = 513` and `ell <= M = 76`.
- `docs/crypto/native_backend_attack_worksheet.md:61` still names `fs.quint_goldilocks_negacyclic_fold_challenges` and `docs/crypto/native_backend_attack_worksheet.md:67` still says "invalid negacyclic mix rows," but the active spec moved to profile mix in `R_q = Z_q[X] / (X^54 + X^27 + 1)` in `docs/crypto/native_backend_spec.md`.
- `DESIGN.md:222` still refers to the active `v7` spec even though the active manifest and spec docs are `v8`.
- `README.md:71` says the current deployment path starts from live `InlineTx`, while node authoring/import logic forces canonical native `receipt_root` on the product path by default in [node/src/substrate/prover_coordinator.rs:1174](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/prover_coordinator.rs#L1174) and [node/src/substrate/service.rs:2604](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs#L2604).
- `audits/native-backend-128b/CLAIMS.md` lists the active structural statistic as `486` but later says the reported structural term remains `360`.

Impact:

- The repo's "exact claim surface" is not exact today.
- That weakens the value of the review package as an external-audit artifact even where the implementation is correct.

Verdict:

- `implementation inconsistent`

### 3. Medium: the cryptographic reduction is exact only inside a narrower repo-owned model than the headline wording suggests

The code and docs are explicit that the live claim is not Neo/SuperNeo-equivalent and that folding alone does not establish CCS knowledge soundness:

- `docs/crypto/native_backend_security_analysis.md:123` says the folding layer alone does not provide knowledge soundness over the CCS relation.
- `audits/native-backend-128b/KNOWN_GAPS.md:1` says the backend does not implement `Π_CCS`, `Π_RLC`, or `Π_DEC`.
- The live soundness argument depends on tx-leaf construction and import re-verifying the embedded STARK proof and then reconstructing the deterministic commitment from public witness data, as implemented in [circuits/superneo-hegemon/src/lib.rs:2535](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2535) and [circuits/superneo-hegemon/src/lib.rs:2792](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2792).

Impact:

- The reduction note is useful and materially better than the old geometry-only story.
- It still does not justify describing this backend as a settled proof-system security result.

Verdict:

- `claim partially supported but overstated`

## Implementation Review

Sampled verifier-path conclusions:

- Tx-leaf verification rejects mismatched `params_fingerprint` and `spec_digest` and rebuilds the canonical receipt in [circuits/superneo-hegemon/src/lib.rs:2547](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2547) and [circuits/superneo-hegemon/src/lib.rs:2595](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2595).
- Tx-leaf verification replays STARK verification in [circuits/superneo-hegemon/src/lib.rs:2605](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2605).
- Tx-leaf verification reconstructs the public witness, repacks it, recomputes the deterministic commitment, and checks the embedded leaf proof in [circuits/superneo-hegemon/src/lib.rs:2610](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2610).
- Receipt-root verification replays each child tx-leaf, recomputes every fold step, and rejects unused fold steps in [circuits/superneo-hegemon/src/lib.rs:2847](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2847) through [circuits/superneo-hegemon/src/lib.rs:2945](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L2945).
- Fold verification recomputes challenge vectors, parent rows, parent commitment digest, parent statement digest, and proof digest in [circuits/superneo-backend-lattice/src/lib.rs:1476](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L1476).
- Both tx-leaf and receipt-root decoders reject trailing bytes in [circuits/superneo-hegemon/src/lib.rs:3681](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L3681) and [circuits/superneo-hegemon/src/lib.rs:4035](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L4035).

I did not find a concrete accepting-path defect in the sampled implementation surface.

Verdict:

- `implementation consistent`

## Reproduced Evidence

Executed checks:

- `cargo test -p superneo-backend-lattice --lib -- --nocapture`
  Result: 19 tests passed.
- `cargo test -p superneo-backend-lattice structural_128b_security_claim_matches_current_floor -- --nocapture`
  Result: passed.
- `cargo test -p superneo-backend-lattice validate_rejects_security_target_above_soundness_floor -- --nocapture`
  Result: passed.
- `cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors`
  Result: 11/11 bundled review vectors passed under the independent verifier.
- `cargo test -p superneo-hegemon native_tx_leaf_rejects_spec_digest_mismatch -- --nocapture`
  Result: passed in 38.79s.
- `cargo test -p superneo-hegemon native_tx_leaf_rejects_tampered_stark_proof -- --nocapture`
  Result: passed in 41.12s.
- `cargo test -p superneo-hegemon native_tx_leaf_rejects_mixed_parameter_set -- --nocapture`
  Result: passed in 41.01s.
- `cargo test -p superneo-hegemon native_receipt_root_rejects_spec_digest_mismatch -- --nocapture`
  Result: passed in 59.18s.
- `cargo test -p superneo-hegemon native_receipt_root_rejects_tampered_fold_rows -- --nocapture`
  Result: passed in 173.82s.

Evidence limitation:

- I did not find an existing production-path CLI that replays `testdata/native_backend_vectors/bundle.json` directly through the production verifier. The exact bundle was replayed through the independent reference verifier, and the production path was sampled through the repo's targeted tamper tests for the same failure classes.

## Final Recommendation

This scheme is acceptable only as `candidate_under_review`.

It is not acceptable today as an externally supported `128`-bit lattice-folding claim. The implementation surface I sampled is consistent and reasonably hardened against obvious tampering, but the concrete security floor still rests on repo-owned heuristic steps and the exact-spec review package still contains enough drift that it cannot yet serve as a clean external-audit anchor.
