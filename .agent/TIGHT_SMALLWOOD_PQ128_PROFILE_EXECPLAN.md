# Restore a Throughput-Competitive 128-Bit PQ SmallWood Profile

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept current while the work proceeds.
This plan follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon must retain both private-transaction throughput and a defensible 128-bit
post-quantum soundness target. The previous V4 SmallWood profile produced an approximately
185 kB proof because the production arithmetic charged a scalar-power support-union penalty
to a full independent uniform DECS challenge matrix. In the uniform-matrix protocol the
extractor fixes the bad support before sampling that matrix, so the relevant failure event is
one codimension-`eta` affine fiber with probability `|F|^-eta`; there is no union over every
possible support. This work mechanizes that distinction, retains the generic finite-QROM
quadratic query loss, searches the exact production relation, benchmarks real proofs, and
activates only the measured winner.

The user-visible result is a smaller native transaction object whose parser, verifier,
extractor, and consensus version remain fail-closed. The result is demonstrated by an exact
release benchmark and by formal and Rust tests that recompute the same security inequality.

## Progress

- [x] (2026-07-31) Confirmed that the proof itself regressed from the historical
  87.5--93.3 kB range to approximately 184.9 kB; native framing accounts for only 6,144 B.
- [x] (2026-07-31) Isolated the incorrect support-union term while retaining the generic
  `6 * q^2 * instability` QROM lifting loss.
- [x] (2026-07-31) Mechanized the uniform-matrix affine-fiber extraction bound and kept the
  scalar-power union bound for historical scalar-power profiles.
- [x] (2026-07-31) Swept the admissible V4 relation profiles and selected the practical
  `N = 2^20`, `beta = 2`, `eta = 5`, `q = 23` point.
- [x] (2026-07-31) Generated and benchmarked a canonical 118,006 B wrapped proof in 2.553 s;
  verification took 10.781 ms and the exact interactive floor was 262.377737 bits.
- [x] (2026-07-31) Regenerated the native backend fixture; its complete transaction-leaf
  artifact is 124,022 B, down from 191,019 B.
- [x] (2026-07-31) Rebuilt both Lean libraries and passed Rust, formal, adversarial,
  compatibility, release-profile, and security-blueprint gates.
- [x] (2026-07-31) Updated `DESIGN.md`, `METHODS.md`, the SmallWood soundness report, generated
  vectors, and reviewed-content digests with exact final evidence.
- [x] (2026-07-31) Removed Cargo, Lean, formal-core, and retired RISC Zero build products,
  leaving 16 GiB free before the final commit.

## Surprises & Discoveries

- Observation: The 191,019 B native artifact is not mainly packaging overhead.
  Evidence: the measured wrapped proof is 184,875 B and native context adds 6,144 B.

- Observation: Most growth is caused by proof parameters rather than the V4 relation.
  Evidence: V4 reduced LPPC rows from 1,531 to 699, but changing `rho` from 3 to 5,
  PIOP openings from 3 to 5, `beta` from 2 to 7, the DECS domain from `2^15` to
  `2^20`, `eta` from 3 to 33, and digests from 32 to 64 bytes increased proof bytes.

- Observation: The dominant overcount was inside the interactive DECS error, not the generic
  QROM lifting theorem.
  Evidence: the old arithmetic multiplied the uniform-matrix failure probability by
  `binomial(N, d + 2)`, while the round-by-round extractor selects a single bad support before
  the independent challenge matrix is sampled.

- Observation: The size-only minimum in the bounded sweep used `N = 2^23`, but saved only
  about five percent while multiplying the evaluation domain and prover work by eight.
  Evidence: its projected proof was about 118,910 B versus the selected point's deterministic
  124,982 B ceiling, before transcript-dependent compact encoding.

- Observation: The selected proof remains larger than the historical 87.5--93.3 kB samples.
  Evidence: SHA-512 digests, the larger V4 relation, five repetitions, and the current
  commitment/opening surfaces are retained to preserve the PQ target and production relation.

## Decision Log

- Decision: Preserve and use the generic finite-QROM theorem, including its quadratic query
  loss, but correct the interactive uniform-matrix error supplied to it.
  Rationale: Removing the QROM loss would weaken the advertised PQ claim. Removing a
  scalar-power union bound from a protocol that samples a full independent matrix fixes a
  modeling error without changing the adversary model.
  Date/Author: 2026-07-31, Codex.

- Decision: Keep the scalar-power support-union arithmetic for historical scalar-power
  challenge profiles.
  Rationale: The correction is challenge-family-specific and must not reinterpret historical
  proofs under a theorem that does not apply to them.
  Date/Author: 2026-07-31, Codex.

- Decision: Keep the SHA-512 production transcript during the initial search.
  Rationale: This isolates proof-parameter inflation from hash-output security and avoids
  silently reintroducing the 256-bit-output quantum-collision bottleneck.
  Date/Author: 2026-07-31, Codex.

- Decision: Do not activate a projected winner.
  Rationale: Consensus changes require actual proof generation, canonical round-trip
  verification, and measured bytes and timings.
  Date/Author: 2026-07-31, Codex.

- Decision: Select the `N = 2^20` practical Pareto point instead of the `N = 2^23` size-only
  projection.
  Rationale: Eight times the domain work is not justified by an approximately five-percent
  projected byte reduction. The selected point proves in 2.553 s on the measured host.
  Date/Author: 2026-07-31, Codex.

- Decision: Tighten V4/Gamma in place on this unmerged branch.
  Rationale: `main` still uses V3, so no deployed V4 proof is reinterpreted and an additional
  V5 wire version would add dead version creep.
  Date/Author: 2026-07-31, Codex.

## Outcomes & Retrospective

The active wrapped proof fell from 184,875 B to 118,006 B, a 36.2 percent reduction. Proving
fell from 15.286 s to 2.553 s and verification from 31.602 ms to 10.781 ms on the same release
benchmark path. The complete generated native transaction-leaf artifact is 124,022 B, down
from 191,019 B. The selected profile's exact interactive floor is 262.377737 bits before the
pinned generic QROM lifting theorem is applied.

Both Lean libraries, the transaction-circuit release suite, formal-core checker, formal-crypto
gate, release profile checks, native vectors, protocol compatibility tests, the adversarial
proving campaign, and the 122-node security blueprint pass. This establishes consistency and
the stated reduction relative to the pinned SHA-512, Poseidon2, and QRO assumptions. It does
not substitute for independent cryptanalysis or external review of those assumptions.

## Context and Orientation

`circuits/transaction/src/smallwood_engine.rs` owns the SmallWood transcript, PCS/PIOP/DECS
implementation, exact soundness arithmetic, proof encoding, and active profile constants.
`circuits/transaction/src/smallwood_frontend.rs` builds the exact V4 Hegemon transaction
relation and contains release profile sweeps and round-trip benchmarks.

`formal/lean/Hegemon/Transaction/SmallWoodNoGrindingSoundness.lean` contains exact integer
versions of the four interactive SmallWood errors. `formal/crypto/HegemonCrypto` contains the
interactive extractor, parser/verifier refinement, production acceptance closure, and both
generic and SmallWood-specific random-oracle developments.

The four interactive errors are named `epsilon1` through `epsilon4`. A query bound `Q` is the
number of random-oracle calls available to an adversary. A 128-bit quantum-query work factor
means that the formal upper bound does not permit constant forgery probability with fewer than
`2^128` oracle calls. This is distinct from merely requiring each interactive error to be
smaller than `2^-128`.

The active production transcript uses SHA-512 with canonical rejection sampling and
first-valid nonce enforcement. Historical V2 and V3 proof versions remain verification-only.

## Plan of Work

First, separate the scalar-power and independent-uniform-matrix challenge families in both
Rust and Lean. Prove the exact affine-fiber cardinality and probability for one fixed nonzero
residual, then connect the extractor's pre-challenge bad support to that event. Preserve the
support-union numerator only for scalar-power challenges.

Second, use exact integer numerator/denominator arithmetic for all four interactive errors and
feed their aggregate to the existing generic finite-QROM theorem. Floating-point logarithms
are diagnostics only.

Third, sweep admissible `rho`, PIOP opening count, `beta`, radix-2 DECS domain size, DECS
opening count, and `eta`. Rank qualifying candidates on both proof bytes and prover work, then
generate real V4 proofs for practical finalists. Select a Pareto point rather than a
size-at-any-cost point.

Fourth, activate the measured winner in the not-yet-merged V4/Gamma profile, align every Lean
geometry and query-accounting constant, regenerate native vectors, and keep V2/V3 historical
decoding unchanged.

Finally, update design and methods documentation and run the formal, Rust, adversarial,
compatibility, release-profile, native-vector, and security-blueprint checks.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Build and audit both formal libraries:

    lake build Hegemon
    lake build HegemonCrypto
    bash scripts/check_lean_formal.sh
    bash scripts/check_formal_crypto.sh

Run the deterministic uniform-matrix frontier and exact release benchmark:

    cargo test -p transaction-circuit \
      compressed_level5_tight_uniform_matrix_frontier_is_materially_smaller \
      --release -- --nocapture

    cargo test -p transaction-circuit \
      compressed_level5_radix2_roundtrip_benchmark \
      --release -- --ignored --nocapture

Run final formal and release checks:

    cargo test -p transaction-circuit --release --quiet
    cargo test -p protocol-versioning --release --quiet
    python3 -B scripts/test_check_release_crypto_profile.py
    bash scripts/check_formal_core.sh checker
    HEGEMON_REDTEAM_MODE=ci PROPTEST_CASES=64 bash scripts/run_proving_redteam.sh

Regenerate and verify the native vectors and reviewed security graph:

    cargo run --quiet -p native-backend-ref -- generate-vectors \
      testdata/native_backend_vectors
    cargo run --quiet -p native-backend-ref -- verify-vectors \
      testdata/native_backend_vectors
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
      check-blueprint config/formal-security-blueprint.json \
      --claims config/formal-security-claims.json

## Validation and Acceptance

The change is accepted only when:

1. Lean proves the exact uniform-matrix affine-fiber inequality used by Rust.
2. Rust and Lean agree byte-for-byte on profile constants and exact bound components.
3. A release-mode prover emits a canonical proof that the production verifier accepts.
4. The selected proof is on the measured size/prover-work Pareto frontier and materially
   smaller than the old profile.
5. The native transaction artifact is materially smaller than 191,019 B.
6. Historical V2 and V3 proofs retain their version-specific verification behavior.
7. Formal, Rust, adversarial, compatibility, and security gates pass.

If no candidate approaches the historical sub-100 kB range, the outcome must identify the
irreducible byte terms and must not label the profile a throughput success.

## Idempotence and Recovery

Profile searches and benchmarks are read-only except for explicitly generated JSON evidence.
Generated artifacts must be deterministic or carry a clear randomized-measurement label.
Consensus activation occurs only after a candidate passes generation and verification. If a
candidate fails, leave the existing V4 profile unchanged and record the rejection.

## Artifacts and Notes

The historical exact size report in
`docs/crypto/tx_proof_smallwood_current_size_report.json` records an 87,310 B proof sample.
The regenerated report in
`docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json` records approximately
118 kB inside the SmallWood proof. The old 184.9 kB benchmark remains documented as the
regression comparison anchor.

The primary paper is Thibauld Feneuil and Matthieu Rivain, “SmallWood: Hash-Based Polynomial
Commitments and Zero-Knowledge Arguments for Relatively Small Instances,” IACR ePrint
2025/1085. The active theorem interface is pinned in the formal-crypto package; its generic
QROM lifting loss remains part of the production claim.

## Interfaces and Dependencies

The Rust side exposes an exact report containing the profile, all four rational interactive
errors, their aggregate, the QROM-lifted target, and whether the target work factor is met.

The Lean side must define the same expression over `Rat` or `Nat` numerator/denominator pairs
and prove the active profile's target theorem without floating-point arithmetic.

No new cryptographic dependency is permitted. Existing `num-bigint`, SHA-512, Goldilocks,
Serde, and Lean/mathlib facilities are sufficient.

Revision note: Initial plan created on 2026-07-31 and corrected after proving that the
regression came from applying a scalar-power support union inside the uniform-matrix
interactive error, not from the generic QROM lifting theorem itself.
