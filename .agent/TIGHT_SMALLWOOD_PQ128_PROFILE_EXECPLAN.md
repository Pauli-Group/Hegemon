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

- [x] (2026-08-30) Split the HGV8RP03 transaction semantic target from the executable relation
  model, added universal Lean acceptance and rejection theorems factored through five named
  refinement obligations, and added a Rust typed-lowering receipt replayed by all existing
  2-input/2-output mask, authorization-mode, and stablecoin fixtures.  The cross-language receipt
  deliberately records exact primitive interpretation refinement, universal accepted-witness
  soundness, and production authority as false: arbitrary packed-witness decoding, the five
  per-family proofs, and source refinement for the fixed primitive symbols are still absent.
- [x] (2026-08-23) Rebuilt the exact HGV8RP03/SMZ9 witness-free whole-view simulator from
  source, replayed its canonical verifier trace and both programmed-oracle seams, audited the
  six concrete affine hiding-map ranks, and retained a deterministic 2,892-byte diagnostic
  report.  Both adaptive-QROM and protocol-lifetime receipts remain structurally absent.
- [x] (2026-08-23) Replaced the source security report's arbitrary unbounded-history prose
  value with the exact evidence identity
  `hegemon.formal.smallwood-smz9.global-sha512-qrom-lifetime.v1`, added conditional and
  constructor-free Lean boundaries, and kept production authorization false.
- [x] (2026-08-23) Evaluated a finite profile-retirement alternative without changing proof
  bytes.  The exact conditional cap is already computed, but no consensus cap was added:
  all four external whole-view losses are still unbounded.  If each is later proved at most
  `2^-152`, the exact 128-bit cap is 4,166,198 accepted proofs; at `2^-151` it is 2,090,101.
- [x] (2026-08-22) Re-audited the live branch after later proof-backend work and found a
  concrete reporting regression: Lean and the deployed-profile checker still use the proved
  fixed committed-support term `1 / |F|^eta`, while the Rust engine had reintroduced the
  scalar-power support union for the active uniform challenge matrix.
- [x] (2026-08-22) Reconciled the Rust calculation, status checker, tests, and security documentation so the
  actual-parameter theorem, production status, and known attacks are three separate records.
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

- Observation: program/interpreter equivalence is not transaction semantic adequacy.  The Rust
  validator and honest assignment builder show that accepted typed witnesses lower to accepted
  HGV8RP03 assignments, but an arbitrary 43,904-word accepted assignment does not yet come with a
  checked decoder or proofs of public structure, witness shape, cryptographic links, per-asset
  balance, and stablecoin transition. Lean now exposes those five obligations separately, fixes
  rather than caller-selects the primitive symbols, and separately records that those symbols are
  not yet refined to the exact Poseidon2, stablecoin, and BLAKE2b source functions.

- Observation: A finite profile lifetime can replace an unbounded-history theorem only after
  the missing external reductions have numeric losses and consensus stores and reorgs one
  monotonically bounded accepted-proof count.  The present 4,096-block stablecoin epoch is not
  a cryptographic reset and the source capability/state contains no such lifetime counter.
  Evidence: the source report leaves all four external whole-view loss terms absent; its exact
  arithmetic yields caps of 4,166,198 and 2,090,101 only under hypothetical equal 152-bit and
  151-bit bounds respectively.

- Observation: the live repository contained two different answers for the same active
  parameter tuple.
  Evidence: `SmallWoodDecsExtraction.lean` fixes a bad support from committed rows before the
  uniform matrix and proves the `|F|^-eta` term, while
  `report_smallwood_no_grinding_soundness_from_cfg` and its focused Rust test charged
  `binomial(N, d + 2) / |F|^eta` to that same uniform-matrix profile. The latter formula is
  retained only for historical scalar-power challenges.

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

- Decision: Do not add a profile-retirement counter yet.
  Rationale: A counter would honestly solve only global history composition.  With adaptive
  Merkle programming, final-PIOP programming, concrete SHA-512 QROM instantiation, and the
  residual whole-view term still unbounded, no defensible maximum proof count exists to encode.
  Date/Author: 2026-08-23, Codex.

- Decision: Treat the executable SMZ9 simulator/rank report as necessary local refinement
  evidence, not as complete zero knowledge or a QROM receipt.
  Rationale: It proves canonical witness-free construction and replay for one source-rebuilt
  profile, while the adaptive quantum-oracle hybrid and global deployed composition remain
  separate cryptographic reductions.
  Date/Author: 2026-08-23, Codex.

- Decision: keep three independent status fields: the mathematical bound for the exact
  parameters, the production integration status, and the strongest documented attack.
  Rationale: a missing implementation/refinement proof does not erase the parameter theorem,
  and a theorem is not an attack measurement. Conflating those facts produced the misleading
  report that triggered this repair.
  Date/Author: 2026-08-22, Codex.

- Decision: apply the fixed-support theorem only to the full independent uniform DECS matrix;
  retain the support union for every scalar-power profile.
  Rationale: the prover commits all rows into the Merkle root before deriving the uniform
  coefficients from that root. This is the ordering assumed by the theorem and is not true of
  the historical scalar-power argument.
  Date/Author: 2026-08-22, Codex.

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

The 2026-07-31 benchmark reduced the then-current wrapped proof from 184,875 B to 118,006 B,
with a complete native transaction-leaf artifact of 124,022 B. Those are retained benchmark
measurements, not current production authorization.

The 2026-08-22 reconciliation now computes the uniform committed-matrix DECS term proved by
the extractor while preserving the larger support union for the historical scalar-power
model. The retained actual parameters give a conditional 262.3777366-bit interactive bound.
The production result is recorded separately as unavailable and disabled because the exact
conventional-hash relation, complete zero knowledge, concrete hash reductions, and compiled
verifier refinement are incomplete. Known attacks are also separate: no end-to-end SmallWood
transaction forgery is recorded; SMW2 has a reproduced witness-privacy failure, and the
retained Poseidon2 digest has a generic quantum collision limit near `2^128` queries.

Focused validation passed for the Rust uniform and scalar challenge calculations, the compact
profile's independent production gate, the deployed-profile status checker, and the Lean
`SmallWoodDecsExtraction` target. Broader historical suite claims remain historical until the
entire current worktree is rerun.

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
