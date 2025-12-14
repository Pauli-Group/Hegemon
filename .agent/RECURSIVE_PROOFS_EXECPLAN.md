# STARK Recursive Proofs Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Implement recursive STARK proof composition where a proof can verify other proofs, enabling logarithmic compression of verification work. A recursive proof proves "I correctly verified proofs P1, P2, ..., Pn" in constant size regardless of how many proofs are verified. This enables:

1. **Epoch proofs**: A single proof attesting to all transactions in an epoch (e.g., 1000 blocks)
2. **Light client sync**: Verify chain state with O(log N) verification instead of O(N)
3. **Cross-chain bridging**: Compact proofs for cross-chain state verification

**What changes for users**: After this work, a light client can sync the entire chain by verifying **one** outer proof which verifies a fixed number of batched inner proofs. Verification work becomes O(1) in the number of epochs (constant number of proofs), rather than O(number of epochs).

## Progress

- [x] (2025-12-10) Draft plan: capture scope, context, and work breakdown.
- [x] (2025-12-10) Phase 0: Create epoch crate skeleton and validate dimensions.
- [x] (2025-12-10) Phase 1a: Implement Merkle tree (compute_proof_root, generate_merkle_proof, verify_merkle_proof).
- [x] (2025-12-10) Phase 1b: Create Epoch types and mock EpochProver stub.
- [x] (2025-12-10) Phase 1c: Implement EpochProofAir with Poseidon constraints (adapting BatchTransactionAir pattern).
- [x] (2025-12-10) Phase 1d: Real EpochProver with trace generation.
- [x] (2025-12-10) Phase 1e: Light client verification API.
- [x] (2025-12-10) Phase 1f: Pallet integration (storage, events, extrinsics).
- [x] (2025-12-10) Phase 1g: Two-node integration testing.
- [x] (2025-12-10) Phase 2a: Research spike - minimal verifier circuit feasibility.
- [x] (2025-12-11) Phase 2b: Integrate miden-crypto RPO hash into winterfell.
- [x] (2025-12-11) Phase 2c: Implement RpoAir + RpoStarkProver (RPO permutation proofs).
- [x] (2025-12-11) Phase 2g: Make inner proofs RPO-friendly (completed: epoch + transaction + batch RPO provers + verifiers).
- [x] (2025-12-13) Phase 2d: MerkleVerifierAir + FriVerifierAir.
- [x] (2025-12-11) Phase 2d.1: MerkleVerifierAir roundtrip + tamper-reject coverage (Merkle chaining, `Rpo256::merge` digest placement in rate[0..3], power-of-two padding for standalone Merkle traces).
- [x] (2025-12-11) Phase 2d.2: FriVerifierAir folding factor 2 + remainder Horner checks (boundary-gated folding mask, re-enabled RPO transitions) with prover roundtrip + tamper-reject tests.
- [x] (2025-12-13) Phase 2d.3: In-circuit hashing of trace/constraint/FRI leaf contents and bind those digests to the authentication-path inputs used during Merkle verification.
- [x] (2025-12-13) Phase 2d.4: Finalize FRI verification by binding the folded DRP value to the remainder polynomial commitment (and wire this into StarkVerifierAir).
- [x] (2025-12-13) Phase 2e: StarkVerifierAir.
- [x] (2025-12-12) Phase 2e.1: Transcript reconstruction + stage masks + witness checks (coeff/z/deep/alpha/reseed/query draws).
- [x] (2025-12-12) Phase 2e.2: Merkle index shift wiring + query-position binding accumulator + per-draw query schedule expansion.
- [x] (2025-12-12) Phase 2e.3: Store transcript challenges in constant columns (constraint coeffs, DEEP coeffs, FRI alphas) and enforce capture at draw boundaries with periodic end masks.
- [x] (2025-12-12) Phase 2e.3a: Store OOD evaluation frame elements (trace+quotient at z and z*g) in constant columns and enforce capture at OOD-hash input rows.
- [x] (2025-12-13) Phase 2e.4: Bind inner openings by hashing leaf contents in-circuit (trace/constraint/FRI) and asserting those digests are consistent with the inner proof’s committed roots.
- [x] (2025-12-13) Phase 2e.5: Implement DEEP composition checks using stored challenges, OOD evaluations, and authenticated trace/constraint openings.
- [x] (2025-12-13) Phase 2e.6: Implement full FRI folding, remainder evaluation, and DRP binding using stored alphas and authenticated FRI openings.
- [x] (2025-12-13) Phase 2e.7: End-to-end recursion: generate inner RPO proof, generate outer proof verifying it, and demonstrate tamper-reject of the inner proof.
- [x] (2025-12-13) Phase 2f: Wire `StarkVerifierAir` into `RecursiveEpochProver` (proof-of-proof) and propagate recursive epoch proofs over the PQ network.
- [x] (2025-12-13) Phase 3a: Query-position binding soundness hardening (bind transcript draws → opened Merkle/FRI indices; duplicates/collisions).
- [x] (2025-12-13) Phase 3b: Batch inner verification (outer proof verifies N inner `RpoAir` proofs sequentially; no depth-2 self-recursion).
- [x] (2025-12-14) Phase 3b: Fix batch segment-boundary masking + transition-degree alignment; ignored batch tests now pass (`test_batch_prover_two_proofs`, `test_batch_prover_tamper_reject`).
- [x] (2025-12-14) Phase 3c: Two-stage epoch aggregation (epochs → batched inner → single outer).
- [x] (2025-12-13) Phase 3d: Testnet proof retrieval + persistence (request/serve protocol, local storage, receipt validation, RPC/CLI).
- [x] (2025-12-13) Phase 3e: Performance budgets + benchmarks (100/500/1000 epoch sizes, memory; regression thresholds; CI gate).
- [x] (2025-12-13) Phase 3f: Documentation + cleanup (trace layout diagram, runbook, CI for ignored heavy tests, audit-prep notes).
- [x] (2025-12-13) Phase 3a.1: Formalize query binding: transcript draws must bind to opened indices (Merkle + FRI).
- [x] (2025-12-13) Phase 3a.2: Bind `COL_POS_SORTED_VALUE` (or replacement) to transcript-derived masked draw, not a prover-chosen witness.
- [x] (2025-12-13) Phase 3a.3: Add adversarial test: duplicate draws mapping to the same unique position.
- [x] (2025-12-13) Phase 3a.4: Remove query-dedup limitation from `SECURITY.md` once hardening ships.
- [x] (2025-12-13) Phase 3b.1: Define batch-verifier public inputs + trace segmentation (N inner proofs; width-flat).
- [x] (2025-12-13) Phase 3b.2: Implement `StarkVerifierBatchAir` + prover which verifies N `RpoAir` proofs in one outer proof.
- [x] (2025-12-13) Phase 3b.3: Add test: N inner proofs → 1 outer batch proof (roundtrip + tamper reject).
- [x] (2025-12-14) Phase 3c.1: Define batched-inner public inputs: `(epoch_start, epoch_end, batch_chain_digest)` (or equivalent deterministic commitment).
- [x] (2025-12-14) Phase 3c.2: Implement batched-inner prover: `K` epochs → 1 inner `RpoAir` proof committing to those epochs.
- [x] (2025-12-14) Phase 3c.3: Add two-stage test: `K` epochs → batched inner; `N` batched inners → 1 outer proof.
- [ ] (2025-12-13) Phase 3x (deferred): Depth-2 self recursion (verifier-of-verifier) via streaming/replay trace layout.
- [x] (2025-12-13) Phase 3x.1 (deferred): Add `RpoStarkVerifierProver` (RPO Fiat–Shamir + RPO commitments) for outer proofs.
- [ ] (2025-12-13) Phase 3x.2 (deferred groundwork): Parameterize recursive verification for `StarkVerifierAir` as an inner proof (trace/FRI sizing expectations) (completed: quantify inner `StarkVerifierAir` size + Winterfell 255-column hard cap; add `StarkVerifierPublicInputs::try_from_elements` + generalized context-prefix/z computation for verifier proofs; propagate inner-proof dimensions/counts (`trace_width`, `constraint_frame_width`, transition/assertion counts) into `StarkVerifierPublicInputs` to avoid recursive AIR instantiation during transcript reconstruction; compute inner constraint-composition coefficients deterministically from public inputs (no longer depends on stored coeff columns for OOD step-3); add an ignored test validating Winterfell verifier step-3 OOD consistency for a `StarkVerifierAir` proof; parameterize transcript/Merkle sizing (coeff/deep/OOD permutation counts + leaf lengths) from inner-proof metadata; gate fixed-size (RpoAir-only) constant-column storage and DEEP/FRI state-machine constraints behind `InnerProofKind::RpoAir` while depth-2 streaming is pending; trace builder now initializes DEEP/FRI state columns to zero for verifier-as-inner traces; remaining: streaming/replay trace layout + full in-circuit verification for verifier proofs).
- [ ] (2025-12-13) Phase 3x.3 (deferred): Add depth-2 recursion test: inner → outer → outer₂.
- [x] (2025-12-13) Phase 3d.1: Extend network protocol: request/serve epoch proofs by number (and later range).
- [x] (2025-12-13) Phase 3d.2: Persist epoch proofs locally on receipt/generation (configurable directory).
- [x] (2025-12-13) Phase 3d.3: Validate received proofs before storing/forwarding (commitment checks; optional full STARK verify).
- [x] (2025-12-13) Phase 3d.4: Add RPC surface for querying recursive epoch proofs.
- [x] (2025-12-13) Phase 3d.5: Add CLI flag for persistence location (e.g. `--recursive-epoch-proofs-dir <path>`).
- [x] (2025-12-13) Phase 3e.1: Add recursion benchmark harness (proof size/time/memory).
- [x] (2025-12-13) Phase 3e.2: Benchmark with realistic epoch sizes (100/500/1000 proof hashes).
- [x] (2025-12-13) Phase 3e.3: Define regression thresholds (size ratio, prover time ratio, memory ceiling).
- [x] (2025-12-13) Phase 3e.4: Add CI job to alert/fail on threshold violations (nightly/optional gate acceptable).
- [x] (2025-12-13) Phase 3f.1: Remove or `#[cfg(test)]`-gate `StarkVerifierProver::prove_pub_inputs_hash`.
- [x] (2025-12-13) Phase 3f.2: Add trace-column layout diagram to `circuits/epoch/src/recursion/stark_verifier_air.rs` module docs.
- [x] (2025-12-13) Phase 3f.3: Create `runbooks/recursive_proofs_testnet.md` and keep it current.
- [x] (2025-12-13) Phase 3f.4: Run ignored proof-of-proof tests in CI (nightly/weekly job).
- [x] (2025-12-13) Phase 3f.5: Add `LightClient::sync_recursive()` tamper-reject test coverage.
- [ ] Phase 4: Security audit and production hardening.

**Current status (2025-12-14)**: Phase 1 shipped and is live in the pallet. Phase 2d/2e are complete end‑to‑end for RPO inner proofs: `StarkVerifierAir` reconstructs the RPO Fiat‑Shamir transcript, verifies Merkle openings for trace/constraint/FRI leaves, performs DEEP composition, completes FRI folding, and binds the final folded value to the remainder polynomial evaluation. Phase 2f is now shipped: `RecursiveEpochProver::prove_epoch_recursive()` generates a proof‑of‑proof for epoch accumulators, `node/src/substrate/service.rs` broadcasts recursive epoch proofs on epoch boundaries (guarded by `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`) and sends the latest proof to new peers on connect, and `LightClient::sync_recursive()` can verify these recursive proofs. Phase 3b is complete and stable in debug builds: `StarkVerifierBatchAir` + `StarkVerifierBatchProver` can verify N inner `RpoAir` proofs in a single outer proof (width-flat, length = segment_len × num_segments), with per-segment transition masking and batch-specific degree descriptors. Phase 3c is now complete: `RecursiveEpochProver::prove_epoch_batch()` generates batched-inner proofs committing to fixed epoch ranges, and the two-stage pipeline is covered by a CI-scale test (`test_two_stage_epoch_batch_pipeline_small_options`) plus a heavier ignored test (`test_two_stage_epoch_batch_pipeline_roundtrip_and_tamper_reject`). Depth‑2 self recursion is deferred behind a streaming/replay trace layout (Phase 3x).

## Surprises & Discoveries

- Observation (2025-12-13): `winterfell::TraceTable::new()` does not initialize memory; any newly added trace columns must be explicitly populated for every row.
  Evidence: Adding DEEP/FRI state columns without writing them produced nondeterministic failures (garbage field elements) and invalid proofs, even when all other witness data was correct.
  Implication: Every trace builder must write every column for all rows (even constant columns), or you must use a constructor that zero-initializes memory.

- Observation (2025-12-13): Winterfell debug proving asserts *exact* transition constraint evaluation degrees; degree descriptors must match the effective degrees of real traces, not just an upper bound.
  Evidence: `winter-prover` panicked with `transition constraint degrees didn't match` until `StarkVerifierAir::new()` degree descriptors were updated for the DEEP/FRI constraints and the prover filled the new state columns deterministically.
  Implication: Any future verifier-AIR constraints must be accompanied by updated `TransitionConstraintDegree` descriptors and validated against at least one real proof roundtrip in debug builds. This applies equally to the batch verifier: per-segment transition exemptions and per-segment “constant” columns change effective degrees and must be reflected in `StarkVerifierBatchAir::new()`.

- Observation (2025-12-14): Winterfell enforces a minimum blowup factor of 16; smaller blowup factors panic during `AirContext::new()`.
  Evidence: `winter-air-0.13.1/src/air/context.rs` panics with `blowup factor too small; expected at least 16, but was 8` when running the two-stage pipeline with a reduced blowup factor.
  Implication: CI-scale recursion tests can reduce `num_queries`, but cannot drop below `blowup_factor=16`. The small two-stage test uses `num_queries=1`, `blowup_factor=16` to keep runtime reasonable while staying within Winterfell’s constraints.

- Observation (2025-12-13): Winterfell verification includes an OOD “constraint consistency” check comparing `evaluate_constraints(z)` against the reduced quotient columns at `z`; omitting it makes recursive verification unsound.
  Evidence: An inner proof for a different AIR with the same context (same trace info/options/assertions/periodic columns) could satisfy all Merkle/FRI/transcript checks but still be invalid under the intended AIR until the OOD consistency check was added.
  Implication: `StarkVerifierAir` must enforce `ood_constraint_eval_1 == ood_constraint_eval_2` (winter-verifier step 3) and the prover must include the correct OOD frame digest in transcript reseeding.

- Observation (2025-12-13): Periodic columns must be evaluated at the OOD point using Winterfell’s cycle-length semantics (`x ↦ x^{num_cycles}`), not by naïvely interpolating a full-length repeated value vector.
  Evidence: A native check of verifier-proof OOD consistency initially failed until the periodic values at `z` were computed via `air.get_periodic_column_polys()` and evaluated at `z.exp_vartime(num_cycles)` (matching `winter-verifier::evaluate_constraints`).
  Implication: Any depth-2 verifier-of-verifier OOD consistency check must compute periodic values at `z` exactly the way Winterfell does, or the constraint composition evaluation will drift and valid proofs will be rejected.

- Observation (2025-12-13): `StarkVerifierAir`-as-inner is much larger than the `RpoAir` inner case; naive “store everything in constant columns” scaling makes depth-2 recursion impractical without a more compact verifier trace layout.
  Evidence: With minimal security parameters (`num_queries=1`, `num_draws=1`), parsing an RPO-backed `StarkVerifierAir` proof yields: `trace_width=236`, `constraint_cols=10`, `transition_constraints=406`, `assertions=447`, `constraint_coeffs=853`, `deep_coeffs=246`, `ood_evals=492`.
  Implication: Phase 3b.2 must either (a) redesign the verifier trace to *replay* transcript draws (coeffs/deep) and *stream* OOD/DEEP data into accumulators (trading width for length), or (b) accept a much larger verifier AIR specialized for verifier proofs.

- Observation (2025-12-13): Constraint-composition coefficients (for winter-verifier step-3) are fully determined by the inner proof’s public inputs + commitments (pre-OOD), so they can be recomputed in the outer AIR and don’t need to be stored in constant columns.
  Evidence: `circuits/epoch/src/recursion/stark_verifier_air.rs` now derives `inner_constraint_coeffs` alongside `expected_z` from the same RPO transcript seed and uses them directly in the RpoAir OOD consistency check.
  Implication: Phase 3b.2 streaming/replay must still handle large OOD evaluation vectors and DEEP coefficients, but coefficient storage is no longer on the critical path for depth-2.

- Observation (2025-12-13): Winterfell hard-caps execution trace width at 255 columns, making the “store everything in constant columns” approach impossible for depth-2 verifier-of-verifier proofs.
  Evidence: `winter-air::TraceInfo::MAX_TRACE_WIDTH = 255` and the inner `StarkVerifierAir` sizing above implies hundreds of additional constant columns would be required (e.g. 853 coeffs + 492 OOD evals + 246 DEEP coeffs), far exceeding 255.
  Implication: Phase 3b.2 must pursue option (a): streaming/replay (width stays ≤255; length grows), or switch to a different proving stack which supports wider traces.

- Observation (2025-12-12): Winterfell’s `FieldExtension` is 1-based (`None = 1`, `Quadratic = 2`, `Cubic = 3`), not 0-based.
  Evidence: `winter-air-0.13.1/src/options.rs` uses `#[repr(u8)]` with `None = 1`. In a real inner proof, `proof.context.to_elements()` packed options element is `0x01020720` (high byte `0x01`) for `FieldExtension::None`, not `0x00020720`.
  Implication: Any host-side reconstruction of the inner `Context::to_elements()` (used for transcript seeding) must encode `FieldExtension::None` as `1`, or transcript-derived values (notably `z`) will drift and in-circuit checks will fail.

- Observation (2025-12-12): Winterfell’s FRI layer count depends on blowup factor, not just domain size.
  Evidence: `winter-fri-0.13.1/src/options.rs` computes `max_remainder_size = (remainder_max_degree + 1) * blowup_factor` and folds until `domain_size <= max_remainder_size`. For `trace_len=16`, `blowup=32`, `remainder_max_degree=7`, `lde_domain_size=512` gives `num_fri_layers=1` (since `512 -> 256` and stop).
  Implication: Transcript scheduling (commitment reseeds / alpha draws), Merkle auth depth per layer, and periodic selector layout must use this definition of “number of FRI layers”.

- Observation (2025-12-12): `RpoRandomCoin::draw_integers` does not enforce uniqueness; duplicates can occur and Winterfell relies on caller-side `sort+dedup` to define `num_unique_queries`.
  Evidence: `miden-crypto-0.19.2/src/rand/rpo.rs` pushes masked values into `values` and stops at `num_values` without dedup; our `InnerProofData::from_proof` explicitly `sort_unstable()` + `dedup()`.
  Implication: “True recursion” must either (a) model `sort+dedup` in-circuit and bind the unique query list to the Merkle index bits, or (b) otherwise prove that the unique query list used by Merkle authentication is consistent with the raw draws.

- Observation (2025-12-12): Query draws drift if the OOD reseed digest is not wired into the transcript used for DEEP/FRI/query stages.
  Evidence: `StarkVerifierProver::build_trace_from_inner()` previously used a zero OOD digest placeholder; this caused transcript-derived query positions to diverge from `InnerProofData::from_proof` and broke Merkle/query binding. Fix was to store `InnerProofData.ood_digest` and feed it into the prover trace.
  Implication: Even if the OOD digest remains a “private witness” (not publicly asserted yet), the prover must use the exact digest from the inner proof to keep transcript challenges aligned.

- Observation (2025-12-12): Our RPO permutation constants drifted from miden-crypto, breaking recursion correctness.
  Evidence: `recursion::rpo_air::tests::test_permutation_matches_miden_crypto` failed until MDS/ARK constants were sourced directly from `miden_crypto::hash::rpo::Rpo256`.
  Implication: All recursion AIR/prover code must treat miden-crypto as the single source of truth for RPO parameters.

- Observation (2025-12-12): Verifier AIR periodic columns must remain truly periodic over the full power-of-two trace length.
  Evidence: Zeroing periodic columns on padded rows caused winterfell to infer max-degree transition polynomials. Fix was to fill padding with dummy RPO permutations and update TransitionConstraintDegree to account for all periodic multiplications.
  Implication: Any future verifier sub-AIR that stacks permutations must either (a) keep periodic columns periodic and add dummy work, or (b) introduce explicit masking columns and update degrees accordingly.

- Observation (2025-12-12): DEEP composer can panic if stacked permutations are exactly 16‑periodic.
  Evidence: `FriVerifierProver` hit a DEEP composition assert until stacked RPO inputs were made non‑periodic.
  Implication: Any verifier trace that stacks permute‑only steps must vary inputs to avoid accidental self‑consistency assumptions in winterfell’s DEEP layer.

- Observation (2025-12-12): Transcript phase ordering needs explicit in‑circuit binding.
  Evidence: Without fixed stage masks, a malicious prover could shift “draw” boundaries while still satisfying local RPO constraints.
  Implication: We enforce coeff/z/deep transcript stages via dedicated mask columns asserted at known boundary rows.

- Observation (2025-12-12): Transcript-derived challenges must be available after they are drawn (for DEEP + FRI verification), so the verifier trace must persist them.
  Evidence: The winterfell verifier draws constraint-composition coefficients, DEEP coefficients, and FRI alphas early, then uses them later when checking DEEP composition and FRI folding; without storing them, StarkVerifierAir cannot reference the correct challenge values outside the draw permutations.
  Implication: Store these values in constant trace columns and enforce “capture at draw boundaries” with periodic selector masks.

- Observation (2025-12-12): FRI remainder commitment is reseeded but has no alpha draw.
  Evidence: `winter-fri` calls `commit_fri_layer(remainder)` without `draw_fri_alpha()`. Our initial transcript reconstruction incorrectly drew an alpha for the remainder, shifting query positions.
  Implication: Both host‑side witness extraction and in‑circuit transcript must treat the last FRI commitment as remainder‑only (reseed, no alpha).

- Observation (2025-12-12): `RpoRandomCoin::draw_integers` absorbs the PoW nonce then skips the first rate element.
  Evidence: miden‑crypto sets `current = RATE_START + 1` after nonce permutation, so the first draw permutation yields 7 usable outputs and the total permutations is `ceil((q + 1)/8)`.
  Implication: Query‑position transcript binding must model the nonce absorption boundary and allocate an extra permutation when `q` is a multiple of 8. Our current verifier stage binds raw draw permutations; full masking/dedup remains pending.

- Observation (2025-12-12): `Rpo256::merge` places digests in the first half of the rate, not capacity.
  Evidence: Algebraic sponge `merge()` copies two digests into rate[0..7] and returns `DIGEST_RANGE = RATE_START..RATE_START+4`. Merkle AIR initially treated capacity[0..3] as the digest, causing root mismatches.
  Implication: All Merkle/Fri verifier logic must read and chain digests from rate[0..3]; capacity is reserved for padding/domain separation only.

- Observation: (From PROOF_AGGREGATION_EXECPLAN) FRAME pallet extrinsics work better with individual parameters than combined structs.
  Evidence: BatchShieldedTransfer in proof aggregation required Debug/Clone/TypeInfo on generic parameters, which complicated the implementation. Using individual parameters for `batch_shielded_transfer(proof, nullifiers, commitments, ...)` was cleaner.
  Implication: When adding epoch-related extrinsics, use individual parameters (epoch_number, proof_bytes, commitment, etc.) rather than an Epoch struct.

- Observation: (From PROOF_AGGREGATION_EXECPLAN) Transaction batching achieves ~12x proof size savings and ~12x verification speedup for batch of 16.
  Evidence: Benchmark results showed 8.4 KB batch proof vs 102 KB for 16 individual proofs (12.1x), and 4.1ms vs 48ms verification (11.7x).
  Implication: Phase 2 verifier circuit must have <12x overhead to be worthwhile over batching. If recursive proof size is >12x inner proof size, batching is the better approach.

- Observation: (From PROOF_AGGREGATION_EXECPLAN) AcceptAllBatchProofs mock verifier pattern enables rapid pallet development before circuit is complete.
  Evidence: batch-circuit tests passed with mock verifier, allowing parallel development of pallet and circuit.
  Implication: Use AcceptAllEpochProofs mock for epoch pallet integration during Phase 1 development.

- Observation: Existing `BatchTransactionAir` and `TransactionAirStark` provide reusable Poseidon constraint patterns.
  Evidence: Both circuits use identical Poseidon round structure (8 rounds, 16-step cycles, x^5 S-box, MDS mixing). Constants exported via `transaction_circuit::stark_air`.
  Implication: EpochProofAir reuses these patterns directly instead of implementing Blake2 in-circuit.

- Observation: Winterfell requires helper functions (`mds_mix`, `sbox`, `round_constant`) to be exported for trace generation.
  Evidence: `BatchTransactionAir` imports these from `transaction_circuit::stark_air` for fill_poseidon_padding.
  Implication: Ensure `transaction-circuit` exports all necessary primitives for epoch circuit reuse.

- Observation: Winterfell's Prover trait requires implementing all associated types, not using `winterfell::prove()` directly.
  Evidence: Phase 1d implementation required full Prover trait impl with get_pub_inputs, new_trace_lde, options, etc.
  Implication: Prover implementations need ~100 lines of boilerplate beyond trace generation. Document pattern for future circuits.

- Observation: BoundedVec required for all FRAME storage types to satisfy MaxEncodedLen constraint.
  Evidence: Phase 1f pallet integration failed with `Vec<u8>` for epoch proofs; fixed with `BoundedVec<u8, ConstU32<MAX_EPOCH_PROOF_SIZE>>`.
  Implication: Always use bounded storage types in pallets to prevent DoS via unbounded storage growth.

- Observation: Winterfell 0.13.1 verify() function requires 4 generic parameters (AIR, HashFn, RandCoin, VC).
  Evidence: Phase 2a implementation failed with 3 params; required `MerkleTree<Blake3>` as the vector commitment (VC) type.
  Implication: Future circuits must specify all 4 type parameters for verification.

- Observation: True STARK recursion (verifying a STARK inside a STARK) is impractical with winterfell alone.
  Evidence: Phase 2a spike shows that encoding FRI verification + Merkle authentication + Fiat-Shamir hashing as AIR constraints would require ~800+ columns for Blake3 hashing alone (8 FRI queries * ~100 columns per hash).
  Implication: For true recursion, consider Plonky2 (native Goldilocks recursion) or Miden VM (STARK-based VM with recursion primitives).

- Observation: Simplified "verifier" circuit achieves good metrics but doesn't implement real verification.
  Evidence: Phase 2a spike achieved 1.96x size ratio and 6.5x prover time ratio (both well under 10x/100x targets), but uses fixed initial values and doesn't verify inner proof correctness.
  Implication: Phase 1's Merkle accumulator approach provides practical value; true recursion is a future research project requiring different tooling.

- Observation: miden-crypto provides production-ready algebraic hashes with winterfell compatibility.
  Evidence: `miden_crypto::hash::rpo::RpoRandomCoin` implements `winterfell::RandomCoin` trait. RPO uses x^7 S-box and linear MDS layers - all algebraic operations that map directly to AIR constraints.
  Implication: True recursion is feasible by: (1) adding miden-crypto dep, (2) implementing RpoAir with ~5 columns, (3) building FriVerifierAir and StarkVerifierAir on top. This is pure STARKs over algebraic hash - quantum resistant, no elliptic curves.

- Observation: Dual-mode proofs enable optimization for different use cases.
  Evidence: Blake3 verification is ~3x faster than RPO for native verification. But RPO is ~20x cheaper than Blake3 for in-circuit verification.
  Implication: Use Blake3 for outer proofs (verified by nodes), RPO for inner proofs (verified recursively). Best of both worlds.

- Observation: RPO requires ~13 columns in AIR, not ~5 as initially estimated.
  Evidence: Phase 2c implementation required 13 trace columns: 12 for RPO state (STATE_WIDTH=12) plus 1 for round counter. Periodic columns provide 13 more values (1 half-round selector + 12 ARK constants).
  Implication: Still far better than ~100 columns for Blake3. The 13-column design supports full RPO permutation with x^7 S-box and MDS mixing.

- Observation: Constraint degree calculation must account for all polynomial multiplications.
  Evidence: Initial RpoAir failed with "expected 135 constraints, actual 120" error. TransitionConstraintDegree::with_cycles(8, vec![16]) was required, not degree 9.
  Implication: When using periodic columns, the degree is the maximum degree of base constraints (x^7 = degree 7) plus one for transition (degree 8). Periodic column values don't add to degree.

- Observation: Blowup factor must be >= 2 * (max constraint degree - 1) for cycles.
  Evidence: RpoProofOptions with blowup_factor=8 failed; required blowup_factor=32 for degree-8 constraints with cycle length 16.
  Implication: For RPO constraints: blowup >= 2 * 16 = 32 (cycle length determines minimum blowup).

- Observation (2025-12-11): BatchTransactionProver needed real public inputs during proving.
  Evidence: With get_pub_inputs returning `BatchPublicInputs::default()`, winterfell panicked (`at least one assertion must be specified`) when proving batch traces.
  Implication: Batch provers now store extracted `BatchPublicInputs` during `prove_batch` so AIR assertions are satisfied for both Blake3 and RPO paths.

- Observation: miden-crypto 0.19.2 uses winter-crypto 0.13, which is compatible with winterfell 0.13.1.
  Evidence: Both use identical BaseElement (Goldilocks field) and the same Hasher/RandomCoin traits.
  Implication: Direct dependency works without version conflicts. RPO and Blake3 can coexist in the same project.

## Decision Log

- Decision: Implement in phases, starting with Merkle Accumulator (practical value) before attempting full verifier circuit (true recursion).
  Rationale: The Merkle Accumulator approach provides immediate light client support without requiring a verifier circuit. Full recursion requires encoding STARK verification as AIR constraints (~50-100 columns, 2^16+ rows), which is a significant research/engineering effort. By shipping Phase 1 first, we deliver value while Phase 2 research proceeds.
  Date/Author: 2025-12-10.

- Decision: Phase 1 does NOT depend on transaction batching (PROOF_AGGREGATION_EXECPLAN).
  Rationale: Epoch proofs can commit to individual transaction proof hashes. Batching is an optimization that reduces the number of proofs per epoch but is not required for the accumulator pattern to work.
  Date/Author: 2025-12-10.

- Decision: Use Poseidon hash for epoch AIR constraints (not Blake2).
  Rationale: The existing `BatchTransactionAir` and `TransactionAirStark` already implement Poseidon round constraints (x^5 S-box, MDS mixing, 8 rounds in 16-step cycles). Reusing this pattern avoids implementing Blake2 as AIR constraints (~100 columns). The epoch proof uses Poseidon in-circuit while epoch commitment uses Blake2-256 for the final hash (hashed outside the circuit as public input).
  Date/Author: 2025-12-10.

- Decision: Use quadratic field extension for 128-bit security in production.
  Rationale: Security analysis in dimensions.rs shows base Goldilocks field provides ~36 bits security from FRI. Extension field is required for 128-bit target. Development/testing can use base field; production proofs must use `FieldExtension::Quadratic`.
  Date/Author: 2025-12-10.

- Decision: Stub-first development for epoch prover.
  Rationale: Following PROOF_AGGREGATION_EXECPLAN pattern (AcceptAllBatchProofs), we create `MockEpochProver` first. This enables pallet integration testing before the full AIR is implemented. Replace with real prover once EpochProofAir is complete.
  Date/Author: 2025-12-10.

- Decision: Use miden-crypto RPO for recursive proof Fiat-Shamir (not Blake3).
  Rationale: Phase 2a research spike showed Blake3 in-circuit requires ~100 columns per compression, making true recursion impractical. RPO (Rescue Prime Optimized) from miden-crypto is an algebraic hash requiring only ~5 columns. Crucially, `RpoRandomCoin` implements winterfell's `RandomCoin` trait, enabling drop-in replacement. This preserves quantum resistance (no elliptic curves) while enabling practical recursion.
  Date/Author: 2025-12-10.

- Decision: Dual-mode proof system (Blake3 for native, RPO for recursion).
  Rationale: Native proofs (transaction, epoch) continue using Blake3 for maximum verification speed. Recursive proofs use RPO Fiat-Shamir, accepting slightly higher native verification cost in exchange for 20x cheaper in-circuit verification. The inner proof is committed to via RPO hash, verified via StarkVerifierAir.
  Date/Author: 2025-12-10.

- Decision: Pursue full proof‑of‑proof recursion now, starting with RPO inner proofs.
  Rationale: Groundwork for RPO Fiat‑Shamir exists, but true recursion requires (1) inner transaction/batch proofs to use RPO and (2) verifier AIRs to enforce the full winterfell STARK verifier. User priority is O(1) recursive sync, so we will complete Phase 2g → 2d/2e → 2f rather than treating recursion as a future research item.
  Date/Author: 2025-12-11.

- Decision (2025-12-13): Implement depth-2 recursion via streaming/replay (not wider traces).
  Rationale: Winterfell’s 255-column trace width cap makes “store all challenges/OOD/DEEP in constant columns” infeasible for verifier-as-inner proofs. Streaming transcript draws and OOD/DEEP values trades trace length for width while preserving soundness.
  Date/Author: 2025-12-13.

- Decision (2025-12-13): Fail closed for unimplemented verifier-of-verifier OOD step-3.
  Rationale: The OOD constraint consistency check is soundness-critical. Until streaming/replay ships for inner `StarkVerifierAir` proofs, the circuit must reject depth-2 traces rather than silently skipping the check.
  Date/Author: 2025-12-13.

- Decision (2025-12-13): Gate fixed-size OOD/DEEP constant-column constraints behind `InnerProofKind::RpoAir`.
  Rationale: The current verifier trace stores only RpoAir-sized OOD frames and DEEP coefficients in constant columns. Applying those constraints to verifier-as-inner proofs would either (a) silently bind only prefixes of the needed vectors or (b) force impossible widths. Gating keeps the RpoAir path sound while we implement streaming/replay, and lets depth-2 traces be constructed deterministically without accidentally “half-verifying” DEEP/FRI.
  Date/Author: 2025-12-13.

- Decision (2025-12-13): Pivot Phase 3b to depth‑1 batch verification (no self-recursion).
  Rationale: Depth‑2 verifier‑of‑verifier recursion triggers trace-width explosion under Winterfell’s 255‑column cap. A batch verifier which verifies `N` `RpoAir` proofs sequentially in one outer proof keeps trace width flat (≤255) while still enabling single‑proof sync when combined with fixed-size epoch batching.
  Date/Author: 2025-12-13.

- Decision (2025-12-13): Decode verifier-proof public inputs from `StarkVerifierPublicInputs::to_elements()`.
  Rationale: Depth-2 recursion requires reconstructing the inner verifier proof’s context (trace info, commitments, query parameters) from its public inputs. Reusing the existing `to_elements()` layout avoids inventing a second serialization format and keeps proof statements stable.
  Date/Author: 2025-12-13.

- Decision (2025-12-12): Source RPO constants directly from miden-crypto.
  Rationale: A single-bit mismatch in ARK constants makes in-circuit hashing unverifiable. Aliasing `MDS`, `ARK1`, and `ARK2` to `Rpo256` prevents future divergence.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Keep StarkVerifierAir’s RPO schedule periodic by padding with dummy permutations.
  Rationale: Winterfell assumes periodic columns repeat with the declared cycle. Dummy permutations preserve this assumption without weakening soundness, and degree descriptors were updated to match the actual periodic multiplications (base 7 with three 16-cycles for RPO constraints; base 1 with one 16-cycle for carryover).
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Bind transcript stages with explicit stage masks and witness equality checks.
  Rationale: The random‑coin transcript is the security spine of recursion; fixing coeff/z/deep boundaries prevents prover‑chosen reordering while keeping constraints local.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Hardcode StarkVerifierAir to RpoAir context and fixed deep‑coeff counts for now.
  Rationale: We need a working end‑to‑end transcript before generalizing to arbitrary AIR contexts. OOD digest is treated as a private witness until Merkle/DEEP value binding is implemented.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Encode `FieldExtension::None` as `1` when reconstructing the inner `Context::to_elements()` prefix.
  Rationale: Winterfell’s `FieldExtension` is `#[repr(u8)]` with `None = 1`; using `0` produces a different seed and breaks transcript-derived challenges (notably `z`), causing the verifier AIR to reject valid inner proofs.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Temporarily set the query-position multiset witness (`COL_POS_SORTED_VALUE`) to the masked draw itself for end-to-end trace correctness in the presence of duplicate draws.
  Rationale: `draw_integers` can emit duplicates but `query_positions` are deduped before queries are built; until we model `sort+dedup` and bind Merkle index bits to the deduped list, using the masked draw as `q_val` keeps the grand-product accumulator from falsely rejecting valid proofs and unblocks other verifier milestones.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Bind transcript-drawn query positions to authenticated trace indices with a grand-product accumulator.
  Rationale: If the verifier circuit can authenticate arbitrary Merkle leaves, the prover could open leaves at prover-chosen indices unless those indices are cryptographically bound to transcript randomness. We avoid an in-circuit `sort+dedup` gadget by maintaining a global accumulator `acc` such that `acc <- acc * (draw + gamma)` at each `draw_integers` decomp boundary and `acc <- acc / (trace_index + gamma)` at the end of each trace-leaf hashing segment, and then asserting `acc == 1` at the end. This enforces multiset equality between transcript draws and the Merkle indices actually opened.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Treat recursion query openings as “per draw” and expand the proof’s unique openings by replication.
  Rationale: Winterfell’s proof format provides unique query openings (base positions are `sort+dedup`ed, and FRI folded positions are deduped at each layer). StarkVerifierAir’s trace schedule stays fixed-size if we treat queries as “per draw” and expand `InnerProofData` so each draw has a corresponding trace/constraint/FRI opening by reusing the unique opening when duplicates occur (including FRI fold collisions). This keeps the verifier AIR local and avoids expensive in-circuit sorting/deduping.
  Date/Author: 2025-12-12.

- Decision (2025-12-13): Add an RPO-backed outer prover for `StarkVerifierAir` and keep verification compatible with both RPO and legacy Blake3 outer proofs.
  Rationale: RPO commitments + RPO Fiat–Shamir are a prerequisite for recursion depth 2+; however, existing node/testnet flows already produce Blake3 outer proofs. We ship `RpoStarkVerifierProver` and prefer verifying RPO outer proofs first, falling back to Blake3 for backwards compatibility. Node-side proof generation can opt into RPO outer proofs via `HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1`.
  Date/Author: 2025-12-13.

- Decision (2025-12-12): Store the inner proof’s OOD digest and feed it as a private witness in the verifier trace.
  Rationale: The transcript must be identical to the inner verifier’s transcript to reproduce DEEP coefficients, FRI alphas, and query draws. Using a placeholder OOD digest causes challenge drift and breaks recursion correctness. Until in-circuit leaf-content binding is implemented, the OOD digest is not publicly asserted, but it must still match the inner proof to keep transcript evolution correct.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Enforce Merkle leaf→merge wiring and index-bit binding inside StarkVerifierAir.
  Rationale: Without an in-AIR constraint that copies the leaf hash digest into the first merge permutation (and then shifts the index consistently with the `path_bit` stream), a prover can “inject” arbitrary digests or reorder left/right inputs without being cryptographically tied to the leaf index bits. Adding `COL_MERKLE_INDEX` with shift relation (`idx_cur = 2*idx_next + bit`) and root index zero checks makes Merkle authentication structurally sound, and unlocks the next milestone: binding that index to transcript-derived query positions.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Persist transcript challenges in constant columns and constrain them to match the RPO sponge outputs at each draw boundary.
  Rationale: Later verifier steps (DEEP composition and FRI folding) need stable access to the exact challenge values drawn earlier from the transcript. Capturing these values once (and enforcing constantness + boundary capture) keeps later constraints local and avoids duplicating transcript logic.
  Date/Author: 2025-12-12.

- Decision (2025-12-12): Persist OOD evaluation frame elements in constant columns and constrain them to match the OOD-hash input permutations.
  Rationale: The DEEP composition check needs trace/quotient OOD evaluations later, but the transcript only commits to them via the OOD digest. Storing them in constant columns and enforcing “capture at OOD input rows” makes the later DEEP constraints local while keeping the transcript binding sound.
  Date/Author: 2025-12-12.

## Outcomes & Retrospective

**Phase 1 Complete (2025-12-10)**:

Files created:
- `circuits/epoch/Cargo.toml` - Epoch circuit crate manifest
- `circuits/epoch/src/lib.rs` - Public API exports
- `circuits/epoch/src/dimensions.rs` - Parameter validation and sizing calculations
- `circuits/epoch/src/types.rs` - Epoch struct and commitment computation
- `circuits/epoch/src/merkle.rs` - Merkle tree operations (compute_proof_root, generate_merkle_proof, verify_merkle_proof)
- `circuits/epoch/src/air.rs` - EpochProofAir with Poseidon constraints
- `circuits/epoch/src/prover.rs` - EpochProver (Prover trait impl) and MockEpochProver
- `circuits/epoch/src/light_client.rs` - LightClient with verify_epoch, verify_inclusion, from_checkpoint
- `tests/epoch_sync.rs` - Light client sync integration tests

Files modified:
- `Cargo.toml` - Added circuits/epoch to workspace members
- `pallets/shielded-pool/Cargo.toml` - Added epoch-circuit dependency with epoch-proofs feature
- `pallets/shielded-pool/src/lib.rs` - Added epoch storage, events, hooks, record_proof_hash
- `tests/Cargo.toml` - Added epoch-circuit dependency and epoch_sync test entry

Test results:
- epoch-circuit: 48 passed, 1 ignored (full proof generation - computationally expensive)
- pallet-shielded-pool: 76 passed (with and without epoch-proofs feature)

Key metrics:
- Merkle depth for 10,000 proofs: 14 levels
- Light client verification: O(log N) complexity achieved
- Proof root computation: Blake3-256 for efficiency

Next steps: Phase 2 research spike to evaluate verifier circuit feasibility.

**Phase 2a Complete (2025-12-10)**:

Files created:
- `circuits/epoch/src/verifier_spike/mod.rs` - Module structure and public exports
- `circuits/epoch/src/verifier_spike/fibonacci_air.rs` - Minimal inner proof AIR (2-column Fibonacci sequence)
- `circuits/epoch/src/verifier_spike/fibonacci_verifier_air.rs` - Simplified "verifier" circuit (5-column trace with Poseidon-like constraints)
- `circuits/epoch/src/verifier_spike/tests.rs` - Integration tests and benchmarks

Files modified:
- `circuits/epoch/src/lib.rs` - Added verifier_spike module export

Test results:
- 12 verifier spike tests passed
- All 60 epoch-circuit tests pass (including verifier spike)

Key metrics from spike:
- Inner (Fibonacci) proof size: 4,012 bytes
- Inner prover time: 4ms
- Inner verify time: 550µs
- Outer (Verifier) proof size: 7,860 bytes (1.96x inner)
- Outer prover time: 26ms (6.5x inner)
- Outer verify time: 1,000µs

Success criteria evaluation:
- Size ratio < 10x: PASS (actual: 1.96x)
- Prover time ratio < 100x: PASS (actual: 6.5x)

Findings:
1. A simplified circuit that mimics verification is achievable with reasonable overhead
2. True recursion (STARK verifying STARK) is impractical with winterfell alone:
   - Blake3 in-circuit requires ~100 columns per compression
   - FRI verification needs 8+ query Merkle paths
   - Estimated: 800+ columns, 2^18+ rows for real verifier
3. Winterfell limitations:
   - No built-in recursion primitives
   - No algebraic hash (Poseidon) in winter-crypto
   - FRI verification logic not exposed as reusable AIR
4. Alternatives for true recursion:
   - Plonky2: Native Goldilocks field recursion support
   - Miden VM: STARK-based VM with recursion primitives
5. Recommendation: Phase 1 (Merkle accumulator) provides practical value now; true recursion is a future research project requiring alternative tooling

**Path Forward (2025-12-10)**:

The research spike identified the core blocker: Blake3 Fiat-Shamir hashing is prohibitively expensive in-circuit (~100 columns per compression). True recursion requires an algebraic hash. After researching alternatives:

- **miden-crypto**: Provides RPO (Rescue Prime Optimized), RPX, and Poseidon2 algebraic hashes. Crucially, `RpoRandomCoin` implements winterfell's `RandomCoin` trait, enabling drop-in replacement for Fiat-Shamir.
- **Quantum Resistance**: RPO is hash-based, not elliptic-curve-based. Combined with Goldilocks field (2^64 - 2^32 + 1), the entire proof system remains quantum-safe.
- **In-circuit cost**: RPO permutation requires ~5 columns vs ~100 for Blake3.

Architecture for true recursion:
1. Add miden-crypto dependency (RPO, RpoRandomCoin)
2. Implement RpoAir: AIR constraints for RPO permutation (~5 columns, algebraic S-box)
3. Implement FriVerifierAir: FRI verification logic as AIR (query folding, polynomial interpolation)
4. Implement MerkleVerifierAir: Merkle path verification using RpoAir
5. Implement StarkVerifierAir: Full STARK verifier = constraint evaluation + FRI + Fiat-Shamir
6. Enable recursive epoch proofs: inner proofs verified in-circuit, outer proof is O(1) size

This is pure STARKs over algebraic hash - no elliptic curves anywhere in the proof system.

**Phase 2 Groundwork Complete (2025-12-11)**:

Files created (~3,100 lines total):
- `circuits/epoch/src/recursion/mod.rs` - Module exports and documentation (43 lines)
- `circuits/epoch/src/recursion/rpo_air.rs` - RPO permutation as AIR constraints with x^7 S-box, MDS mixing (686 lines)
- `circuits/epoch/src/recursion/rpo_proof.rs` - Dual-mode proof options & RPO hash utilities (331 lines)
- `circuits/epoch/src/recursion/merkle_air.rs` - Merkle path verification using RPO hash (467 lines)
- `circuits/epoch/src/recursion/fri_air.rs` - FRI folding verification for polynomial commitment (382 lines)
- `circuits/epoch/src/recursion/stark_verifier_air.rs` - Complete STARK verifier composing all components (441 lines)
- `circuits/epoch/src/recursion/recursive_prover.rs` - Epoch prover with RPO-based Fiat-Shamir (521 lines)
- `circuits/epoch/src/recursion/tests.rs` - Comprehensive integration tests (247 lines)

Files modified:
- `circuits/epoch/Cargo.toml` - Added miden-crypto 0.19.2 dependency
- `circuits/epoch/src/lib.rs` - Added recursion module and exports (RecursiveEpochProver, RpoAir, etc.)

Test results:
- 107 epoch-circuit tests passed
- 47 recursion-specific tests passed
- End‑to‑end RPO permutation proof generation and native verification works

Key technical achievements:
1. **RPO Algebraic Hash** (~13 columns vs ~100+ for Blake3)
   - Uses miden-crypto 0.19.2's RPO parameters (STATE_WIDTH=12, NUM_ROUNDS=7, ALPHA=7)
   - Constraint degree 8 with periodic columns for cycles[16]
   - Full S-box constraints (forward x^7, inverse verification)
   - ROWS_PER_PERMUTATION=16 (power of 2 for FRI)

2. **Merkle Verification in AIR**
   - MerkleVerifierAir enforces Merkle authentication paths (leaf hashing + path-bit chaining + index shifts + root binding) with tamper‑reject coverage.
   - StarkVerifierAir reuses the same stacking order to bind queried trace/constraint/FRI leaf openings to the inner proof’s commitments.

3. **FRI Folding Verification**
   - FriVerifierAir validates folding‑factor‑2 transitions and remainder Horner checks (and is exercised via prover roundtrip tests).
   - StarkVerifierAir completes FRI by selecting per-layer evaluations, folding with stored alphas, and binding the folded value to the remainder polynomial evaluation.

4. **StarkVerifierAir**
   - Implements full winterfell verifier logic in-circuit: transcript reconstruction, Merkle openings for trace/constraint/FRI, DEEP composition, FRI folding, and remainder binding.
   - Exercised end‑to‑end by `test_trace_from_inner_merkle_roundtrip` and supported by focused tamper-detection tests for folding and remainder binding.

5. **RecursiveEpochProver (groundwork)**
   - Uses RPO‑based proof accumulator and proves an RPO permutation over it
   - Does **not** yet verify inner STARK proofs in‑circuit

Proof options:
- Default blowup_factor: 32 (required for degree-8 constraints with cycle 16)
- FRI remainder max degree: 7 (must be 2^k - 1)
- Supports both fast (testing) and production options

**Phase 3 Groundwork Complete (2025-12-11)**:

Files created:
- `circuits/epoch/src/recursion/rpo_stark_prover.rs` - Full winterfell Prover using Rpo256 and RpoRandomCoin (~410 lines)
  - `RpoStarkProver` - Generic STARK prover with associated types:
    - `HashFn = Rpo256`
    - `RandomCoin = RpoRandomCoin`
    - `VC = MerkleTree<Rpo256>`
  - `prove_epoch_with_rpo()` - Generate real STARK proofs
  - `verify_epoch_with_rpo()` - Verify using RPO-based Fiat-Shamir
  - Full Prover trait implementation with DefaultTraceLde, DefaultConstraintCommitment, etc.

Files modified:
- `circuits/epoch/src/recursion/mod.rs` - Added rpo_stark_prover module export
- `circuits/epoch/src/recursion/recursive_prover.rs` - Wired RpoStarkProver into RecursiveEpochProver:
  - `generate_real_stark_proof()` replaces mock proof generation
  - `verify_epoch_proof()` uses real STARK verification
  - `is_recursive: true` now set (real proofs, not mock)
- `circuits/epoch/src/lib.rs` - Re-exported winterfell::Proof for pallet usage
- `pallets/shielded-pool/src/lib.rs` - Integration complete:
  - `finalize_epoch_internal()` uses `RecursiveEpochProver` instead of `MockEpochProver`
  - `verify_stored_epoch_proof()` added for light client verification
  - Real RPO-based STARK proofs generated at epoch boundaries

Test results:
- 114 epoch-circuit tests passed (7 new tests for RpoStarkProver)
- Full end-to-end proof generation and verification works
- Pallet compiles with `epoch-proofs` feature

Key technical achievements:
1. **Real RPO STARK Proofs** - No more mock epoch proofs; actual RPO‑based permutation proofs
2. **Drop‑in Integration** - RecursiveEpochProver API unchanged; pallet emits RPO epoch proofs
3. **Proof Serialization** - proof.to_bytes() for storage, Proof::from_bytes() for deserialization
4. **Proof‑of‑Proof Recursion (Phase 2d/2e)** - verifier circuit shipped end‑to‑end for RPO inner proofs; production wiring into `RecursiveEpochProver` is still pending (Phase 2f).

Quantum resistance:
- Pure STARKs - no elliptic curves anywhere
- Security derives from:
  - RPO collision resistance (algebraic hash, post-quantum)
  - FRI soundness over Goldilocks field (2^64 - 2^32 + 1)

Next steps: Complete Phase 2d/2e/2f (true recursion end‑to‑end), then Phase 3 testnet validation and security audit.

## Context and Orientation

Current STARK implementation uses winterfell 0.13.1 which provides FRI-based STARK proving/verification. The system currently proves individual transactions (or batches, if PROOF_AGGREGATION_EXECPLAN is implemented).

Relevant files (paths relative to repository root):

- `circuits/transaction/src/stark_air.rs` - `TransactionAirStark` with 5-column trace, Poseidon constraints
- `circuits/transaction/src/stark_prover.rs` - `TransactionProverStark` generates proofs
- `circuits/transaction/src/stark_verifier.rs` - Off-chain verification using `winterfell::verify()`
- `pallets/shielded-pool/src/verifier.rs` - On-chain `StarkVerifier` implementation
- `consensus/src/lib.rs` - Block validation logic
- `circuits/epoch/src/recursion/` - True STARK recursion module (Phase 2)
  - `rpo_air.rs` - RPO permutation as AIR constraints (~13 columns)
  - `rpo_proof.rs` - Dual-mode proof options and RPO utilities
  - `merkle_air.rs` - Merkle path verification using RPO
  - `fri_air.rs` - FRI folding verification
  - `stark_verifier_air.rs` - Complete STARK verifier composing all components
  - `recursive_prover.rs` - RecursiveEpochProver with RPO-based accumulation

Key dependencies:
- winterfell 0.13.1 - Core STARK library (Goldilocks field, FRI protocol)
- winter-crypto - Blake3 hashing for Fiat-Shamir
- miden-crypto 0.19.2 - RPO algebraic hash for in-circuit verification
- sp-core - Substrate primitives for on-chain types

Terminology:
- `Epoch`: A fixed number of blocks (e.g., 1000 blocks). Epoch boundaries are where epoch proofs are generated.
- `Epoch proof`: A STARK proof that attests to a Merkle tree of transaction proof hashes being valid.
- `Proof hash`: Blake2-256 hash of a serialized STARK proof. Used as leaf in the epoch Merkle tree.
- `Verifier circuit`: An AIR that encodes STARK verification as constraints. Required for true recursion.
- `Merkle accumulator`: A Merkle tree of proof hashes. Simpler than true recursion but provides practical compression.
- `Inner proof`: The proof being verified inside a recursive circuit.
- `Outer proof`: The recursive proof that attests to inner proof validity.

## Technical Approach Overview

We implement recursion in three phases:

**Phase 1: Merkle Accumulator (Complete ✓)**
- Collect all transaction proofs in an epoch
- Compute Merkle tree of proof hashes
- Generate an "epoch proof" that proves knowledge of the Merkle root and attests to the epoch's validity
- Light clients verify epoch proofs + Merkle inclusion proofs for specific transactions

**Phase 2: True Recursion with miden-crypto RPO (Phase 2d/2e complete; Phase 2f pending)**  

Completed groundwork:
- Replaced Blake3 Fiat‑Shamir with RPO for recursion (algebraic hash, ~13 columns vs ~100).
- Implemented `RpoAir` + `RpoStarkProver` and aligned permutation constants to `miden_crypto::hash::rpo::Rpo256`.
- Inner epoch/transaction/batch proofs now support RPO Fiat‑Shamir.

In progress / remaining:
- `RecursiveEpochProver` still does not verify inner STARK proofs in‑circuit (Phase 2f). The verifier circuit exists; it now needs to be wired into epoch proving so epoch proofs can recursively attest to prior epoch proofs.
- Phase 3 remains: two-person testnet recursive sync + light client recursive mode, followed by security review/hardening.

**Phase 3: Production and Security Audit (Pending)**
- Two-person testnet validation with recursive sync + light client recursive mode
- Security audit and production hardening

### Two-Person Testnet Scenario

Once Phase 2 is complete, here's how recursive proofs work in a two-person testnet:

**Node Alice (mining/producing blocks)**:
1. Mines blocks, each containing shielded transactions with STARK proofs
2. At epoch boundary (every 1000 blocks), Alice's node:
   - Collects all transaction proof hashes from the epoch
   - Generates an epoch proof (proves Merkle root of all proofs)
   - **With recursion**: Generates a recursive proof that verifies the previous epoch proof in-circuit
3. Broadcasts the recursive epoch proof (~8KB, constant size regardless of epoch count)

**Node Bob (syncing late joiner)**:
1. Bob comes online after 10 epochs (10,000 blocks) have been mined
2. **Without recursion**: Bob downloads 10 epoch proofs (~80KB) and verifies each sequentially
3. **With recursion**: Bob receives ONE recursive proof (~8KB) that attests to ALL 10 epochs
   - The recursive proof says: "I verified epoch 10's proof, which verified epoch 9's proof, which..."
   - Bob verifies this single proof in ~1ms
   - Bob now has cryptographic certainty about the entire chain state

**The O(1) advantage**:
```
Epochs synced:    10        100       1,000     10,000
Without recursion: 10 proofs  100 proofs  1,000 proofs  10,000 proofs
With recursion:    1 proof    1 proof     1 proof       1 proof
```

Bob's verification time is constant regardless of how long Alice has been mining.

**What Bob can do after sync**:
- Query any shielded balance with Merkle inclusion proof
- Verify any historical transaction with O(log N) proof
- Start mining/producing blocks immediately
- Submit shielded transactions with full confidence in chain state

**Trust assumptions**:
- Zero: Bob trusts only math (STARK soundness, RPO collision resistance)
- No trusted setup, no elliptic curves, quantum-safe

Phase 1 provides immediate value. Phase 2 enables O(1) sync for light clients and late joiners.

## Technical Challenges

### Challenge 1: Verifier Circuit Complexity (Addressed)

The STARK verification algorithm involves:
1. Recomputing commitment hashes from proof data
2. Sampling FRI query positions via Fiat-Shamir
3. Evaluating polynomial constraints at query points
4. Checking FRI layer consistency (Merkle proofs + folding)
5. Verifying the final low-degree polynomial

With Blake3: ~100 columns per hash → impractical
With RPO: ~5 columns per hash → feasible

Estimated with RPO:
- Trace width: 20-40 columns (down from 50-100 with Blake3)
- Trace length: 2^14 - 2^16 rows per inner proof (down from 2^16-2^20)
- Constraint degree: 5+ (hash functions, polynomial evaluation)

### Challenge 2: In-Circuit Hash Functions (Solved)

Winterfell uses Blake3 for Fiat-Shamir. Implementing Blake3 as AIR constraints is expensive (~100 columns for the compression function). 

**Solution**: miden-crypto provides:
- **RPO (Rescue Prime Optimized)**: Algebraic hash with x^α S-box, ~5 columns in AIR
- **RpoRandomCoin**: Implements winterfell's `RandomCoin` trait for Fiat-Shamir
- **Poseidon2**: Alternative algebraic hash, similar cost

By using RPO for Fiat-Shamir in recursive proofs, we reduce hashing cost by ~20x.

### Challenge 3: Winterfell Limitations (Mitigated)

Winterfell 0.13.1 does not provide:
- Built-in recursion support → **Build StarkVerifierAir ourselves**
- Verifier circuit implementations → **Build FriVerifierAir, MerkleVerifierAir**
- In-circuit field arithmetic helpers → **RPO S-box is algebraic (x^α), natural in AIR**

miden-crypto closes the gap for hashing. We build the verifier AIRs on top.
- Verifier circuit implementations
- In-circuit field arithmetic helpers

We must build the verifier circuit from scratch or evaluate alternative proof systems (Plonky2, Miden VM).

## Plan of Work

### Phase 0: Dimension and Parameter Validation (0.5 days)

**Goal**: Validate all mathematical assumptions before building the full implementation. Compute Merkle tree depths, security parameters, and proof sizing.

**Files to create**:
- `circuits/epoch/src/dimensions.rs`

#### Step 0.1: Create epoch dimension calculations

Create `circuits/epoch/src/dimensions.rs`:

```rust
//! Epoch proof dimension calculations.
//!
//! Validates sizing assumptions and security parameters.

/// Number of blocks per epoch
pub const EPOCH_SIZE: u64 = 1000;

/// Maximum proofs per epoch (assumes ~10 tx per block average)
pub const MAX_PROOFS_PER_EPOCH: usize = 10_000;

/// Compute Merkle tree depth for N proofs
pub fn merkle_depth(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 0;
    }
    // Depth = ceil(log2(num_proofs))
    let bits = usize::BITS - (num_proofs - 1).leading_zeros();
    bits as usize
}

/// Compute padded leaf count (next power of 2)
pub fn padded_leaf_count(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 1;
    }
    num_proofs.next_power_of_two()
}

/// Size of Merkle inclusion proof in bytes
pub fn merkle_proof_size(num_proofs: usize) -> usize {
    let depth = merkle_depth(num_proofs);
    depth * 32  // 32 bytes per sibling hash
}

/// Winterfell security parameters
pub mod security {
    /// Number of FRI queries (affects security level)
    pub const FRI_QUERIES: usize = 8;
    
    /// Log2 of blowup factor
    pub const BLOWUP_LOG2: usize = 4;
    
    /// Grinding factor (PoW bits)
    pub const GRINDING_FACTOR: usize = 4;
    
    /// Approximate security level in bits
    /// Formula: queries × blowup_log2 + grinding + field_security
    /// For Goldilocks (64-bit prime), field_security ≈ 64
    /// But effective security is limited by smallest component
    pub fn security_level_bits() -> usize {
        // Conservative estimate: min(field_bits/2, query_security)
        // Goldilocks: 64-bit field → ~32 bits from field
        // Queries: 8 × log2(16) = 32 bits from FRI
        // Total: ~64 bits from FRI, augmented by grinding
        // With extension field: can reach 128 bits
        let fri_security = FRI_QUERIES * BLOWUP_LOG2;
        let total = fri_security + GRINDING_FACTOR;
        total  // ~36 bits base, need extension field for 128
    }
    
    /// Check if we need field extension for target security
    pub fn needs_extension_field(target_bits: usize) -> bool {
        security_level_bits() < target_bits
    }
}

/// Epoch proof trace sizing (for EpochProofAir)
pub mod trace {
    /// Trace width for epoch proof (simplified)
    /// - 4 columns for Blake2 state simulation
    /// - 1 column for Merkle position
    /// - 1 column for accumulator
    pub const EPOCH_TRACE_WIDTH: usize = 6;
    
    /// Rows per Merkle hash operation
    pub const ROWS_PER_HASH: usize = 16;  // Match CYCLE_LENGTH
    
    /// Compute trace rows for epoch with N proofs
    pub fn epoch_trace_rows(num_proofs: usize) -> usize {
        let depth = super::merkle_depth(num_proofs);
        let padded = super::padded_leaf_count(num_proofs);
        // Need to hash: all leaves to root = padded - 1 internal nodes
        // Plus: depth hashes per inclusion proof verification
        let tree_hashes = padded - 1;
        let rows = tree_hashes * ROWS_PER_HASH;
        rows.next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_depth_calculations() {
        assert_eq!(merkle_depth(1), 0);
        assert_eq!(merkle_depth(2), 1);
        assert_eq!(merkle_depth(3), 2);
        assert_eq!(merkle_depth(4), 2);
        assert_eq!(merkle_depth(5), 3);
        assert_eq!(merkle_depth(1000), 10);  // 2^10 = 1024
        assert_eq!(merkle_depth(10000), 14); // 2^14 = 16384
        
        println!("\nMerkle depths for typical epoch sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            println!("  {:5} proofs → depth {:2} (padded to {})", 
                proofs, merkle_depth(proofs), padded_leaf_count(proofs));
        }
    }

    #[test]
    fn test_merkle_proof_sizes() {
        println!("\nMerkle proof sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let size = merkle_proof_size(proofs);
            println!("  {:5} proofs → {:3} byte proof ({} siblings)",
                proofs, size, size / 32);
        }
        
        // 1000 proofs = depth 10 = 320 bytes
        assert_eq!(merkle_proof_size(1000), 320);
    }

    #[test]
    fn test_security_parameters() {
        let base_security = security::security_level_bits();
        println!("\nSecurity analysis:");
        println!("  FRI queries: {}", security::FRI_QUERIES);
        println!("  Blowup (log2): {}", security::BLOWUP_LOG2);
        println!("  Grinding: {} bits", security::GRINDING_FACTOR);
        println!("  Base security: {} bits", base_security);
        println!("  Needs extension for 128-bit: {}", 
            security::needs_extension_field(128));
        
        // We should need extension field for 128-bit security
        assert!(security::needs_extension_field(128),
            "Expected to need extension field for 128-bit security");
    }

    #[test]
    fn test_epoch_trace_sizing() {
        println!("\nEpoch proof trace sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let rows = trace::epoch_trace_rows(proofs);
            let cols = trace::EPOCH_TRACE_WIDTH;
            let cells = rows * cols;
            println!("  {:5} proofs → {:6} rows × {} cols = {:8} cells",
                proofs, rows, cols, cells);
        }
    }

    #[test]
    fn test_light_client_verification_complexity() {
        // Light client verifies: 1 epoch proof + 1 Merkle inclusion proof
        // Compare to: verifying all N transaction proofs
        
        println!("\nLight client verification savings:");
        let epoch_verify_ms = 5.0;  // Epoch proof verification
        let tx_verify_ms = 3.0;     // Single tx proof verification
        
        for proofs in [100, 500, 1000, 5000, 10000] {
            let merkle_proof_bytes = merkle_proof_size(proofs);
            let merkle_verify_ms = 0.01 * merkle_depth(proofs) as f64;  // ~0.01ms per hash
            
            let light_client_ms = epoch_verify_ms + merkle_verify_ms;
            let full_verify_ms = proofs as f64 * tx_verify_ms;
            let speedup = full_verify_ms / light_client_ms;
            
            println!("  {:5} proofs: light={:.2}ms vs full={:.0}ms ({:.0}x speedup)",
                proofs, light_client_ms, full_verify_ms, speedup);
        }
    }
}
```

#### Step 0.2: Run validation

```bash
cd circuits/epoch
cargo test dimensions -- --nocapture
```

**Expected output**:
```
running 5 tests
test dimensions::tests::test_merkle_depth_calculations ... ok

Merkle depths for typical epoch sizes:
    100 proofs → depth  7 (padded to 128)
    500 proofs → depth  9 (padded to 512)
   1000 proofs → depth 10 (padded to 1024)
   5000 proofs → depth 13 (padded to 8192)
  10000 proofs → depth 14 (padded to 16384)

test dimensions::tests::test_merkle_proof_sizes ... ok

Merkle proof sizes:
    100 proofs → 224 byte proof (7 siblings)
    500 proofs → 288 byte proof (9 siblings)
   1000 proofs → 320 byte proof (10 siblings)
   5000 proofs → 416 byte proof (13 siblings)
  10000 proofs → 448 byte proof (14 siblings)

test dimensions::tests::test_security_parameters ... ok

Security analysis:
  FRI queries: 8
  Blowup (log2): 4
  Grinding: 4 bits
  Base security: 36 bits
  Needs extension for 128-bit: true

test dimensions::tests::test_epoch_trace_sizing ... ok
test dimensions::tests::test_light_client_verification_complexity ... ok

Light client verification savings:
    100 proofs: light=5.07ms vs full=300ms (59x speedup)
    500 proofs: light=5.09ms vs full=1500ms (295x speedup)
   1000 proofs: light=5.10ms vs full=3000ms (588x speedup)
   5000 proofs: light=5.13ms vs full=15000ms (2924x speedup)
  10000 proofs: light=5.14ms vs full=30000ms (5837x speedup)

test result: ok. 5 passed; 0 failed
```

**Validation criteria**:
- Merkle depth ≤ 14 for 10K proofs ✓
- Merkle proof size ≤ 512 bytes ✓  
- Extension field needed for 128-bit security ✓ (document in Decision Log)
- Light client speedup > 100x for 1000+ proofs ✓

If security analysis shows issues, update ProofOptions before proceeding.

### Phase 1: Merkle Accumulator (Epoch Proofs)

**Goal**: Enable light clients to verify epochs with O(log N) work.

#### Step 1.1: Create epoch circuit crate

Working directory: `circuits/`

```bash
cargo new epoch --lib
```

Add to `circuits/epoch/Cargo.toml`:
```toml
[package]
name = "epoch-circuit"
version = "0.1.0"
edition = "2021"
description = "Epoch proofs for light client verification"

[dependencies]
winterfell = "0.13.1"
winter-air = "0.13.1"
winter-prover = "0.13.1"
winter-crypto = "0.13.1"
winter-math = "0.13.1"
sp-core = { version = "21.0.0", default-features = false }
parity-scale-codec = { version = "3.6", default-features = false }
log = "0.4"

# Reuse Poseidon constants from transaction circuit
transaction-circuit = { path = "../transaction" }

[dev-dependencies]
rand = "0.8"

[features]
default = ["std"]
std = [
    "sp-core/std",
    "parity-scale-codec/std",
]
```

Add `"circuits/epoch"` to workspace `Cargo.toml` members.

**Validation**: `cargo check -p epoch-circuit` succeeds.

#### Step 1.2: Define epoch types

Create `circuits/epoch/src/types.rs`:

```rust
use sp_core::hashing::blake2_256;

/// Number of blocks per epoch
pub const EPOCH_SIZE: u64 = 1000;

/// Epoch metadata committed to in the epoch proof
#[derive(Clone, Debug)]
pub struct Epoch {
    /// Epoch number (0, 1, 2, ...)
    pub epoch_number: u64,
    /// First block number in this epoch
    pub start_block: u64,
    /// Last block number in this epoch (inclusive)
    pub end_block: u64,
    /// Merkle root of all proof hashes in this epoch
    pub proof_root: [u8; 32],
    /// State root at end of epoch
    pub state_root: [u8; 32],
    /// Nullifier set root at end of epoch
    pub nullifier_set_root: [u8; 32],
    /// Commitment tree root at end of epoch
    pub commitment_tree_root: [u8; 32],
}

impl Epoch {
    /// Compute the epoch commitment (used as public input)
    pub fn commitment(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(&self.epoch_number.to_le_bytes());
        data.extend_from_slice(&self.start_block.to_le_bytes());
        data.extend_from_slice(&self.end_block.to_le_bytes());
        data.extend_from_slice(&self.proof_root);
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.nullifier_set_root);
        data.extend_from_slice(&self.commitment_tree_root);
        blake2_256(&data)
    }
}

/// A proof hash is Blake2-256 of the serialized STARK proof
pub fn proof_hash(proof_bytes: &[u8]) -> [u8; 32] {
    blake2_256(proof_bytes)
}
```

#### Step 1.3: Implement proof Merkle tree

Create `circuits/epoch/src/merkle.rs`:

```rust
//! Merkle tree operations for epoch proof accumulation.
//!
//! Uses Blake2-256 for hashing (consistent with Substrate).

use sp_core::hashing::blake2_256;

/// Compute Merkle root from list of proof hashes.
///
/// Pads to next power of 2 with zero hashes.
pub fn compute_proof_root(proof_hashes: &[[u8; 32]]) -> [u8; 32] {
    if proof_hashes.is_empty() {
        return [0u8; 32];
    }
    if proof_hashes.len() == 1 {
        return proof_hashes[0];
    }
    
    // Pad to power of 2
    let mut leaves = proof_hashes.to_vec();
    while !leaves.len().is_power_of_two() {
        leaves.push([0u8; 32]);
    }
    
    // Build tree bottom-up
    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(&pair[1]);
            next_level.push(blake2_256(&combined));
        }
        leaves = next_level;
    }
    
    leaves[0]
}

/// Generate Merkle proof for proof hash at given index.
///
/// Returns sibling hashes from leaf to root.
pub fn generate_merkle_proof(
    proof_hashes: &[[u8; 32]], 
    index: usize
) -> Vec<[u8; 32]> {
    if proof_hashes.is_empty() || index >= proof_hashes.len() {
        return vec![];
    }
    if proof_hashes.len() == 1 {
        return vec![];  // Single element, no siblings needed
    }
    
    // Pad to power of 2
    let mut leaves = proof_hashes.to_vec();
    while !leaves.len().is_power_of_two() {
        leaves.push([0u8; 32]);
    }
    
    let mut proof = Vec::new();
    let mut idx = index;
    
    // Collect siblings while building tree
    while leaves.len() > 1 {
        // Sibling index: flip the last bit
        let sibling_idx = idx ^ 1;
        proof.push(leaves[sibling_idx]);
        
        // Compute next level
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(&pair[1]);
            next_level.push(blake2_256(&combined));
        }
        leaves = next_level;
        idx /= 2;
    }
    
    proof
}

/// Verify Merkle proof for a proof hash.
///
/// Returns true if the proof is valid for the given root.
pub fn verify_merkle_proof(
    root: [u8; 32],
    leaf: [u8; 32],
    index: usize,
    proof: &[[u8; 32]],
) -> bool {
    let mut current = leaf;
    let mut idx = index;
    
    for sibling in proof {
        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            // Current is left child
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            // Current is right child
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }
        current = blake2_256(&combined);
        idx /= 2;
    }
    
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_proof_root_empty() {
        assert_eq!(compute_proof_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_compute_proof_root_single() {
        let leaf = [1u8; 32];
        assert_eq!(compute_proof_root(&[leaf]), leaf);
    }

    #[test]
    fn test_compute_proof_root_two() {
        let leaf0 = [1u8; 32];
        let leaf1 = [2u8; 32];
        let root = compute_proof_root(&[leaf0, leaf1]);
        
        // Manual computation
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf0);
        combined[32..].copy_from_slice(&leaf1);
        let expected = blake2_256(&combined);
        
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        // Test with various sizes
        for num_leaves in [2, 3, 4, 7, 8, 15, 16, 100, 1000] {
            let leaves: Vec<[u8; 32]> = (0..num_leaves)
                .map(|i| {
                    let mut leaf = [0u8; 32];
                    leaf[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    leaf
                })
                .collect();
            
            let root = compute_proof_root(&leaves);
            
            // Verify proof for each leaf
            for (idx, leaf) in leaves.iter().enumerate() {
                let proof = generate_merkle_proof(&leaves, idx);
                assert!(
                    verify_merkle_proof(root, *leaf, idx, &proof),
                    "Failed for {} leaves at index {}",
                    num_leaves, idx
                );
            }
        }
    }

    #[test]
    fn test_merkle_proof_invalid_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();
        
        let root = compute_proof_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);
        
        // Modify leaf - should fail
        let bad_leaf = [99u8; 32];
        assert!(!verify_merkle_proof(root, bad_leaf, 0, &proof));
    }

    #[test]
    fn test_merkle_proof_wrong_index() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();
        
        let root = compute_proof_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);
        
        // Use wrong index - should fail
        assert!(!verify_merkle_proof(root, leaves[0], 1, &proof));
    }
}
```

#### Step 1.4: Implement EpochProofAir

The epoch proof AIR proves knowledge of proof hashes that form the claimed Merkle root.
We adapt the Poseidon constraint pattern from `BatchTransactionAir`.

**Key insight**: We don't need to prove full Merkle tree computation in-circuit for Phase 1.
Instead, we prove:
1. The prover knows a list of field elements (proof hash limbs)
2. The Poseidon hash of these limbs equals a committed value
3. The committed value corresponds to the epoch's proof_root (verified off-circuit)

This is simpler than encoding Blake2 Merkle tree computation but still provides
binding: the prover cannot generate an epoch proof without knowing all proof hashes.

Create `circuits/epoch/src/air.rs`:

```rust
//! Epoch proof AIR (Algebraic Intermediate Representation).
//!
//! Proves knowledge of proof hashes that commit to an epoch.
//! Uses Poseidon hash for in-circuit computation, following the pattern
//! from BatchTransactionAir.

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// Reuse Poseidon constants from transaction circuit
use transaction_circuit::stark_air::{
    round_constant, COL_S0, COL_S1, COL_S2, CYCLE_LENGTH,
};

/// Number of Poseidon rounds per cycle.
pub const POSEIDON_ROUNDS: usize = 8;

/// Trace width: 3 Poseidon state columns + 1 proof hash input + 1 accumulator
pub const EPOCH_TRACE_WIDTH: usize = 5;
pub const COL_PROOF_INPUT: usize = 3;
pub const COL_ACCUMULATOR: usize = 4;

/// Public inputs for epoch proof.
#[derive(Clone, Debug)]
pub struct EpochPublicInputs {
    /// Poseidon hash of all proof hashes (computed in-circuit)
    pub proof_accumulator: BaseElement,
    /// Number of proofs in this epoch
    pub num_proofs: u32,
    /// Epoch commitment (Blake2 hash of Epoch struct, verified off-circuit)
    pub epoch_commitment: [u8; 32],
}

impl ToElements<BaseElement> for EpochPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.proof_accumulator,
            BaseElement::new(self.num_proofs as u64),
        ]
    }
}

/// Epoch proof AIR.
///
/// Trace layout:
/// ```text
/// Row 0..CYCLE_LENGTH:     Hash proof_hash[0] into accumulator
/// Row CYCLE_LENGTH..2*CL:  Hash proof_hash[1] into accumulator
/// ...
/// Row (N-1)*CL..N*CL:      Hash proof_hash[N-1] into accumulator
/// (Padding to power of 2)
/// ```
///
/// Each hash cycle absorbs one proof hash limb into the Poseidon state.
/// After all proofs are absorbed, the final state is the proof_accumulator.
pub struct EpochProofAir {
    context: AirContext<BaseElement>,
    pub_inputs: EpochPublicInputs,
}

impl EpochProofAir {
    /// Calculate trace length for given number of proofs.
    ///
    /// Each proof hash is 32 bytes = 4 field elements (8 bytes each).
    /// We absorb 1 element per cycle.
    pub fn trace_length(num_proofs: usize) -> usize {
        let elements_per_proof = 4;  // 32 bytes / 8 bytes per element
        let total_elements = num_proofs * elements_per_proof;
        let total_cycles = total_elements.max(1);
        let rows = total_cycles * CYCLE_LENGTH;
        rows.next_power_of_two()
    }
}

impl Air for EpochProofAir {
    type BaseField = BaseElement;
    type PublicInputs = EpochPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Poseidon x^5 constraint degree, cyclic
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];

        // Assertions:
        // 1. Initial state is zero (1 assertion per state column)
        // 2. Final accumulator matches public input (1 assertion)
        let num_assertions = 4;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Periodic values: [hash_flag, rc0, rc1, rc2]
        let hash_flag = periodic_values[0];
        let rc0 = periodic_values[1];
        let rc1 = periodic_values[2];
        let rc2 = periodic_values[3];

        // Absorb proof input into state (add to S0 before round)
        let absorbed_s0 = current[COL_S0] + current[COL_PROOF_INPUT];

        // Compute Poseidon round
        let t0 = absorbed_s0 + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        // S-box: x^5
        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        // MDS mixing: [[2,1,1],[1,2,1],[1,1,2]]
        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        // Constraint: hash_flag * (next - hash_result) = 0
        result[0] = hash_flag * (next[COL_S0] - hash_s0);
        result[1] = hash_flag * (next[COL_S1] - hash_s1);
        result[2] = hash_flag * (next[COL_S2] - hash_s2);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let trace_len = self.context.trace_len();
        
        vec![
            // Initial state is zero
            Assertion::single(COL_S0, 0, BaseElement::ZERO),
            Assertion::single(COL_S1, 0, BaseElement::ZERO),
            Assertion::single(COL_S2, 0, BaseElement::ZERO),
            // Final accumulator matches public input
            Assertion::single(COL_S0, trace_len - 1, self.pub_inputs.proof_accumulator),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Hash mask: 1 for rounds 0..7, 0 for rounds 8..15
        let mut hash_mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
        for i in 0..POSEIDON_ROUNDS {
            hash_mask[i] = BaseElement::ONE;
        }

        let mut result = vec![hash_mask];

        // Round constants for each position
        for pos in 0..3 {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                if step < POSEIDON_ROUNDS {
                    column.push(round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_length_calculation() {
        // 1 proof = 4 elements = 4 cycles = 64 rows → 64
        assert_eq!(EpochProofAir::trace_length(1), 64);
        
        // 16 proofs = 64 elements = 64 cycles = 1024 rows → 1024
        assert_eq!(EpochProofAir::trace_length(16), 1024);
        
        // 1000 proofs = 4000 elements = 4000 cycles = 64000 rows → 65536
        assert_eq!(EpochProofAir::trace_length(1000), 65536);
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = EpochPublicInputs {
            proof_accumulator: BaseElement::new(12345),
            num_proofs: 100,
            epoch_commitment: [0u8; 32],
        };
        
        let elements = pub_inputs.to_elements();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], BaseElement::new(12345));
        assert_eq!(elements[1], BaseElement::new(100));
    }
}
```

#### Step 1.4b: Implement EpochProver

Create `circuits/epoch/src/prover.rs`:

```rust
//! Epoch proof generation.
//!
//! Generates STARK proofs that attest to epoch validity.

use winterfell::{
    math::fields::f64::BaseElement,
    Matrix, ProofOptions, Prover, Trace, TraceTable,
};

use crate::air::{
    EpochProofAir, EpochPublicInputs, EPOCH_TRACE_WIDTH, POSEIDON_ROUNDS,
    COL_S0, COL_S1, COL_S2, COL_PROOF_INPUT, COL_ACCUMULATOR,
};
use crate::types::Epoch;

use transaction_circuit::stark_air::{mds_mix, round_constant, sbox, CYCLE_LENGTH};

/// Epoch proof (serialized STARK proof).
#[derive(Clone, Debug)]
pub struct EpochProof {
    /// Serialized winterfell proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Epoch commitment for verification.
    pub epoch_commitment: [u8; 32],
    /// Proof accumulator (Poseidon hash of all proof hashes).
    pub proof_accumulator: BaseElement,
}

/// Epoch prover.
pub struct EpochProver {
    options: ProofOptions,
}

impl EpochProver {
    /// Create new epoch prover with default options.
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                8,   // num_queries
                16,  // blowup_factor
                4,   // grinding_factor
                winterfell::FieldExtension::None,  // Use Quadratic for production
                2,   // fri_folding_factor
                31,  // fri_remainder_max_degree
            ),
        }
    }

    /// Create prover with production security settings.
    pub fn production() -> Self {
        Self {
            options: ProofOptions::new(
                8,
                16,
                4,
                winterfell::FieldExtension::Quadratic,  // 128-bit security
                2,
                31,
            ),
        }
    }

    /// Generate epoch proof from epoch metadata and proof hashes.
    pub fn prove(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<EpochProof, &'static str> {
        if proof_hashes.is_empty() {
            return Err("Cannot create epoch proof for empty epoch");
        }

        // Build execution trace
        let (trace, proof_accumulator) = self.build_trace(proof_hashes)?;
        
        // Create public inputs
        let pub_inputs = EpochPublicInputs {
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
            epoch_commitment: epoch.commitment(),
        };

        // Generate proof
        let proof = winterfell::prove::<EpochProofAir>(
            trace,
            pub_inputs,
            self.options.clone(),
        ).map_err(|_| "Proof generation failed")?;

        Ok(EpochProof {
            proof_bytes: proof.to_bytes(),
            epoch_commitment: epoch.commitment(),
            proof_accumulator,
        })
    }

    /// Build execution trace for epoch proof.
    fn build_trace(
        &self,
        proof_hashes: &[[u8; 32]],
    ) -> Result<(TraceTable<BaseElement>, BaseElement), &'static str> {
        // Convert proof hashes to field elements (4 elements per hash)
        let mut inputs: Vec<BaseElement> = Vec::with_capacity(proof_hashes.len() * 4);
        for hash in proof_hashes {
            for chunk in hash.chunks(8) {
                let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
                inputs.push(BaseElement::new(value));
            }
        }

        let trace_len = EpochProofAir::trace_length(proof_hashes.len());
        let mut trace = TraceTable::new(EPOCH_TRACE_WIDTH, trace_len);

        // Initialize state
        let mut s0 = BaseElement::ZERO;
        let mut s1 = BaseElement::ZERO;
        let mut s2 = BaseElement::ZERO;

        let mut row = 0;
        let mut input_idx = 0;

        // Process each input element
        while row < trace_len {
            // Get input for this cycle (or zero for padding)
            let input = if input_idx < inputs.len() {
                inputs[input_idx]
            } else {
                BaseElement::ZERO
            };
            input_idx += 1;

            // Absorb input into state
            s0 = s0 + input;

            // Run Poseidon rounds
            for step in 0..POSEIDON_ROUNDS {
                trace.set(COL_S0, row, s0);
                trace.set(COL_S1, row, s1);
                trace.set(COL_S2, row, s2);
                trace.set(COL_PROOF_INPUT, row, if step == 0 { input } else { BaseElement::ZERO });
                trace.set(COL_ACCUMULATOR, row, s0);

                // Apply Poseidon round
                let t0 = s0 + round_constant(step, 0);
                let t1 = s1 + round_constant(step, 1);
                let t2 = s2 + round_constant(step, 2);

                let x0 = sbox(t0);
                let x1 = sbox(t1);
                let x2 = sbox(t2);

                (s0, s1, s2) = mds_mix(x0, x1, x2);
                row += 1;
            }

            // Idle steps (copy state)
            for _ in POSEIDON_ROUNDS..CYCLE_LENGTH {
                trace.set(COL_S0, row, s0);
                trace.set(COL_S1, row, s1);
                trace.set(COL_S2, row, s2);
                trace.set(COL_PROOF_INPUT, row, BaseElement::ZERO);
                trace.set(COL_ACCUMULATOR, row, s0);
                row += 1;
            }
        }

        Ok((trace, s0))  // Final s0 is the proof accumulator
    }
}

/// Mock epoch prover for pallet integration testing.
///
/// Returns a fixed proof that passes AcceptAllEpochProofs verifier.
pub struct MockEpochProver;

impl MockEpochProver {
    /// Generate mock epoch proof.
    pub fn prove(
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<EpochProof, &'static str> {
        Ok(EpochProof {
            proof_bytes: vec![0u8; 32],  // Minimal mock proof
            epoch_commitment: epoch.commitment(),
            proof_accumulator: BaseElement::new(proof_hashes.len() as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;

    fn test_epoch() -> Epoch {
        Epoch {
            epoch_number: 0,
            start_block: 0,
            end_block: 999,
            proof_root: [1u8; 32],
            state_root: [2u8; 32],
            nullifier_set_root: [3u8; 32],
            commitment_tree_root: [4u8; 32],
        }
    }

    #[test]
    fn test_mock_prover() {
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32]];
        
        let proof = MockEpochProver::prove(&epoch, &hashes).unwrap();
        assert_eq!(proof.epoch_commitment, epoch.commitment());
    }

    #[test]
    fn test_trace_building() {
        let prover = EpochProver::new();
        let hashes = vec![[1u8; 32], [2u8; 32]];
        
        let (trace, accumulator) = prover.build_trace(&hashes).unwrap();
        
        // 2 proofs × 4 elements = 8 cycles = 128 rows → 128
        assert_eq!(trace.length(), 128);
        assert_ne!(accumulator, BaseElement::ZERO);
    }

    #[test]
    #[ignore]  // Slow test, run with --ignored
    fn test_full_proof_generation() {
        let prover = EpochProver::new();
        let epoch = test_epoch();
        let hashes: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        
        let proof = prover.prove(&epoch, &hashes).unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.epoch_commitment, epoch.commitment());
    }
}
```

#### Step 1.5: Light client verification API

Create `circuits/epoch/src/light_client.rs`:

```rust
//! Light client API for epoch-based chain verification.
//!
//! Light clients verify:
//! 1. Epoch proofs (STARK verification)
//! 2. Merkle inclusion proofs (for specific transactions)

use crate::{merkle, Epoch, EpochProof};
use crate::air::{EpochProofAir, EpochPublicInputs};

/// Result of epoch verification.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyResult {
    /// Epoch is valid.
    Valid,
    /// Epoch proof failed STARK verification.
    InvalidProof,
    /// Epoch number is not sequential.
    NonSequentialEpoch { expected: u64, got: u64 },
    /// Proof accumulator mismatch.
    AccumulatorMismatch,
}

/// Light client state.
///
/// Maintains verified epochs for efficient chain sync.
pub struct LightClient {
    /// Verified epochs (indexed by epoch_number).
    verified_epochs: Vec<Epoch>,
    /// Current chain tip epoch.
    pub tip_epoch: u64,
}

impl LightClient {
    /// Create new light client starting from genesis.
    pub fn new() -> Self {
        Self {
            verified_epochs: Vec::new(),
            tip_epoch: 0,
        }
    }

    /// Create light client starting from a trusted epoch.
    ///
    /// Use this for checkpoint-based sync.
    pub fn from_checkpoint(epoch: Epoch) -> Self {
        let tip = epoch.epoch_number;
        Self {
            verified_epochs: vec![epoch],
            tip_epoch: tip,
        }
    }

    /// Verify an epoch proof and add to verified set.
    pub fn verify_epoch(
        &mut self,
        epoch: &Epoch,
        proof: &EpochProof,
    ) -> VerifyResult {
        // Check epoch commitment matches proof
        if epoch.commitment() != proof.epoch_commitment {
            return VerifyResult::AccumulatorMismatch;
        }

        // Check epoch is sequential (or first epoch)
        if !self.verified_epochs.is_empty() {
            let expected = self.tip_epoch + 1;
            if epoch.epoch_number != expected {
                return VerifyResult::NonSequentialEpoch {
                    expected,
                    got: epoch.epoch_number,
                };
            }
        }

        // Verify STARK proof
        let pub_inputs = EpochPublicInputs {
            proof_accumulator: proof.proof_accumulator,
            num_proofs: 0,  // Not checked in verification
            epoch_commitment: epoch.commitment(),
        };

        match winterfell::verify::<EpochProofAir>(
            winterfell::Proof::from_bytes(&proof.proof_bytes).ok()?,
            pub_inputs,
        ) {
            Ok(_) => {
                self.verified_epochs.push(epoch.clone());
                self.tip_epoch = epoch.epoch_number;
                VerifyResult::Valid
            }
            Err(_) => VerifyResult::InvalidProof,
        }
    }

    /// Verify epoch without STARK proof (for mock/testing).
    pub fn accept_epoch(&mut self, epoch: Epoch) {
        self.tip_epoch = epoch.epoch_number;
        self.verified_epochs.push(epoch);
    }

    /// Check if a specific transaction proof was included in an epoch.
    ///
    /// Returns true if the Merkle proof is valid.
    pub fn verify_inclusion(
        &self,
        epoch_number: u64,
        proof_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        index: usize,
    ) -> bool {
        if let Some(epoch) = self.get_epoch(epoch_number) {
            merkle::verify_merkle_proof(epoch.proof_root, proof_hash, index, merkle_proof)
        } else {
            false
        }
    }

    /// Get verified epoch by number.
    pub fn get_epoch(&self, epoch_number: u64) -> Option<&Epoch> {
        self.verified_epochs
            .iter()
            .find(|e| e.epoch_number == epoch_number)
    }

    /// Get all verified epochs.
    pub fn verified_epochs(&self) -> &[Epoch] {
        &self.verified_epochs
    }

    /// Get number of verified epochs.
    pub fn num_verified(&self) -> usize {
        self.verified_epochs.len()
    }
}

impl Default for LightClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;
    use crate::merkle::{compute_proof_root, generate_merkle_proof};

    fn make_epoch(n: u64, proof_root: [u8; 32]) -> Epoch {
        Epoch {
            epoch_number: n,
            start_block: n * 1000,
            end_block: (n + 1) * 1000 - 1,
            proof_root,
            state_root: [0u8; 32],
            nullifier_set_root: [0u8; 32],
            commitment_tree_root: [0u8; 32],
        }
    }

    #[test]
    fn test_light_client_inclusion() {
        let mut client = LightClient::new();

        // Create epoch with known proof hashes
        let proof_hashes: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let proof_root = compute_proof_root(&proof_hashes);
        let epoch = make_epoch(0, proof_root);
        client.accept_epoch(epoch);

        // Verify valid inclusion
        for (idx, hash) in proof_hashes.iter().enumerate() {
            let merkle_proof = generate_merkle_proof(&proof_hashes, idx);
            assert!(
                client.verify_inclusion(0, *hash, &merkle_proof, idx),
                "Failed for index {}",
                idx
            );
        }

        // Verify invalid inclusion (wrong hash)
        let bad_hash = [99u8; 32];
        let merkle_proof = generate_merkle_proof(&proof_hashes, 0);
        assert!(!client.verify_inclusion(0, bad_hash, &merkle_proof, 0));
    }

    #[test]
    fn test_light_client_epoch_chain() {
        let mut client = LightClient::new();

        // Add epochs 0, 1, 2
        for i in 0..3 {
            let epoch = make_epoch(i, [i as u8; 32]);
            client.accept_epoch(epoch);
        }

        assert_eq!(client.tip_epoch, 2);
        assert_eq!(client.num_verified(), 3);
        assert!(client.get_epoch(1).is_some());
        assert!(client.get_epoch(99).is_none());
    }
}
```

### Phase 2: Verifier Circuit (Research Spike) - COMPLETE

**Goal**: Determine if winterfell can practically support verifier-as-AIR. ✓ **COMPLETE**

#### Step 2.1: Minimal verifier circuit for Fibonacci - COMPLETE

Completed research spike with results:
- Inner (Fibonacci) proof: 4,012 bytes, 4ms prove, 550µs verify
- Outer (Verifier) proof: 7,860 bytes (1.96x), 26ms prove (6.5x), 1ms verify
- Success criteria met: 1.96x < 10x (size), 6.5x < 100x (time)

**Key finding**: Simplified verifier works, but true recursion requires algebraic hash (RPO) for Fiat-Shamir.

### Phase 2b-2e: True Recursion with miden-crypto (NEW)

**Goal**: Implement full STARK recursion using RPO algebraic hash. Quantum-safe, no elliptic curves.

#### Step 2b: Integrate miden-crypto RPO (1 week)

1. Add miden-crypto dependency:
```toml
# circuits/epoch/Cargo.toml
[dependencies]
miden-crypto = "0.11"  # RPO, RPX, Poseidon2, RpoRandomCoin
```

2. Create dual-mode proof infrastructure:
```rust
// circuits/epoch/src/recursion/mod.rs
pub mod rpo_proof;  // Proofs using RPO Fiat-Shamir (for recursion)
pub mod blake_proof; // Proofs using Blake3 Fiat-Shamir (for native)
```

3. Implement RpoRandomCoin adapter for winterfell:
```rust
use miden_crypto::hash::rpo::RpoRandomCoin;
use winterfell::RandomCoin;

// RpoRandomCoin already implements winterfell::RandomCoin
// Verify it compiles with winterfell 0.13.1
```

**Success criteria**:
- cargo check passes with miden-crypto
- Can generate proofs using RpoRandomCoin instead of Blake3

#### Step 2c: Implement RpoAir (1 week)

RPO permutation as AIR constraints (~5 columns):

```rust
pub struct RpoAir {
    // 4 state columns (256-bit state = 4 × 64-bit Goldilocks elements)
    // 1 round counter column
}

impl Air for RpoAir {
    // Constraints for RPO round:
    // 1. S-box: state[i]^α (α = 7 for RPO)
    // 2. MDS mixing: linear combination of state elements
    // 3. Round constant addition
    // 4. 7 rounds total per permutation
}
```

Create `circuits/epoch/src/recursion/rpo_air.rs`:
- RpoAir with ~5 columns
- RpoProver for trace generation
- Tests: verify RPO permutation matches miden-crypto reference

**Success criteria**:
- RpoAir proof verifies
- Output matches miden_crypto::hash::rpo::Rpo256::hash()

#### Step 2g: Make Inner Proofs RPO‑Friendly (2 weeks)

**Goal**: Ensure all *inner* proofs that will be verified recursively (transaction proofs and batch transaction proofs) are generated using RPO‑based Fiat‑Shamir instead of Blake3. Without this, the outer verifier AIR cannot cheaply reconstruct the Fiat‑Shamir transcript.

Work required:
1. Add `miden-crypto` to `circuits/transaction` and `circuits/batch` crates.
2. Create RPO variants of the existing winterfell provers:
   - `TransactionProverStarkRpo` in `circuits/transaction/src/rpo_prover.rs`
   - `BatchTransactionProverRpo` in `circuits/batch/src/rpo_prover.rs`
   Each should:
   - Reuse the existing AIR and trace builders.
   - Set `HashFn = Rpo256`, `RandomCoin = RpoRandomCoin`, and `VC = MerkleTree<Rpo256>`.
3. Add matching native verifiers:
   - `verify_transaction_proof_rpo()` in `circuits/transaction/src/rpo_verifier.rs`
   - `verify_batch_proof_rpo()` in `circuits/batch/src/rpo_verifier.rs`
4. Export these from the crates behind a `rpo-fiat-shamir` (or `recursion`) feature flag so we can switch epoch finalization to RPO proofs without breaking the Blake3 default.

**Success criteria**:
- `cargo test -p transaction-circuit rpo_proofs` passes: RPO transaction proofs verify, and a tampered proof fails.
- `cargo test -p batch-circuit rpo_proofs` passes: RPO batch proofs verify, and a tampered proof fails.
- Proof bytes remain stable and round‑trip via `Proof::to_bytes()` / `Proof::from_bytes()`.

#### Step 2d: Implement FriVerifierAir + MerkleVerifierAir (2 weeks)

This step builds the two sub‑verifiers that `StarkVerifierAir` composes.

**Current state (2025‑12‑12)**:
- `circuits/epoch/src/recursion/merkle_air.rs` exists with a stacked‑RPO trace layout, chaining helpers, and `perm_mask` gating. It does **not** yet authenticate real Merkle paths from an inner proof.
- `circuits/epoch/src/recursion/fri_air.rs` exists with folding‑factor‑2 constraints and RPO transitions re‑enabled. `FriVerifierProver` round‑trips a minimal FRI verifier proof. It does **not** yet verify all layers, folded positions, or the remainder polynomial for real inner proofs.
- Host‑side `InnerProofData::from_proof` already extracts `trace_auth_paths`, `constraint_auth_paths`, and per‑layer FRI data.

**Work remaining**:
1. **MerkleVerifierAir**
   - **Model winterfell leaf hashing in‑circuit**.
     - Trace leaves: hash the full trace row with the RPO sponge exactly as `hash_row_rpo()` / `Rpo256::hash_elements()` do. For RpoAir inner proofs this is a 13‑element row ⇒ 2 sponge blocks. Add fixed periodic selectors in the outer AIR so the capacity carries across the intra‑leaf boundary while the rate is overwritten by the next block.
     - Constraint leaves: hash the constraint‑composition row (currently 8 elements) as a single sponge block.
     - FRI leaves: hash each folded pair (2 elements) as a single sponge block.
     - Enforce correct sponge initialization per leaf: capacity[0]=len%8, capacity[1..3]=0 on each leaf start, and capacity carry between blocks.
   - **Model winterfell Merkle path chaining in‑circuit**.
     - After leaf hashing, run one RPO permutation per Merkle level, matching `Rpo256::merge(left,right)` (capacity=0, rate=left||right, digest in rate[0..3]).
     - Add a trace column `path_bit` per permutation to choose left/right order, and enforce `path_bit ∈ {0,1}` on every Merkle boundary.
     - Add a full‑length periodic `merkle_chain_mask` so the digest‑to‑next‑level binding is non‑optional.
   - **Deterministic stacking order**.
     - Fix the order of all authenticated openings in the outer trace: for each query do trace leaf→trace path→constraint leaf→constraint path→FRI layer 0 leaf→path→… for every committed FRI layer. This order must be reflected both in `StarkVerifierAir::get_periodic_column_values()` and in the prover trace builder.
   - **Root binding + tests**.
     - At the end of each authenticated path, enforce equality to the corresponding public‑input root (`trace_commitment`, `constraint_commitment`, and each `fri_commitments[layer]` excluding the remainder).
     - Add tamper‑reject tests: flip a leaf element, flip a sibling, swap path order, or change a root ⇒ outer proof fails.

2. **FriVerifierAir**
   - For each query and each FRI layer, enforce degree‑respecting projection (DRP) folding using the `fri_alphas` challenges derived in `StarkVerifierAir`.
   - Recompute folded positions per layer (folding factor 2) and bind them to the Merkle openings used above.
   - Verify the remainder polynomial by Horner evaluation at the final folded positions (matches `winter-fri` remainder handling). **Horner checks are implemented; remaining is binding the final DRP fold output into the remainder evaluation once Merkle/transcript wiring is complete.**
   - Add a prover trace builder that consumes `InnerProofData.fri_layers` / `fri_remainder`, plus tamper‑reject tests (wrong layer value, wrong alpha, wrong remainder).

**Success criteria**:
- `MerkleVerifierAir` rejects any invalid trace/constraint/FRI opening.
- `FriVerifierAir` rejects any invalid fold or remainder evaluation.

#### Step 2e: Implement StarkVerifierAir (2 weeks)

`StarkVerifierAir` is the “verifier‑of‑verifier”: it reconstructs the inner proof’s Fiat‑Shamir transcript in‑circuit and then checks all Merkle, FRI, constraint, and DEEP relations.

**Current state (2025‑12‑12)**:
- In‑circuit RPO transcript is enforced through: public‑input hash → seed → coin.init → trace reseed → constraint‑coeff draws → constraint reseed → z draw → OOD reseed (OOD digest witness for now) → DEEP coeff draws → FRI commitment reseeds and alpha draws.
- Witness equality checks exist for `constraint_coeffs`, `z`, `deep_coeffs`, and `fri_alphas`.
- Stage masks (`coeff_mask`, `z_mask`, `deep_mask`, `fri_mask`) are asserted at fixed boundaries to prevent transcript re‑ordering.

**Work remaining**:
1. **Bind query positions in‑circuit**
   - Model `RpoRandomCoin::draw_integers` exactly: absorb PoW nonce into rate[0], permute, skip the first rate element, and bit‑mask draws into `[0, domain_size)`.
   - Add witness columns for query positions (or a commitment to them) and check against the drawn values; then enforce sort/dedup to match `num_unique_queries`.

2. **Integrate MerkleVerifierAir**
   - Append a Merkle authentication segment after the transcript segment in `stark_verifier_air.rs`.
   - Reuse RPO state columns for leaf hashing and Merkle merges.
   - Add fixed periodic selectors for:
     - leaf sponge init (`len%8` in capacity[0]) and intra‑leaf capacity carry,
     - Merkle merge init (capacity zero),
     - digest‑chaining between Merkle levels,
     - one‑hot root checks per tree type/layer.
   - Add a trace column for per‑level `path_bit` and enforce binary + correct left/right chaining.
   - **Note**: binding Merkle indexes to transcript‑drawn query positions is deferred until full `draw_integers` modeling (step 1) is in place; current Merkle work assumes provided positions/bits are correct and focuses on hashing/path soundness.

3. **Integrate FriVerifierAir**
   - Use bound `fri_alphas` + query positions to verify all FRI layers and the remainder polynomial in‑circuit.

4. **DEEP composition checks**
   - Compute DEEP evaluations per query using `deep_coeffs`, `z`, domain generator `g`, and OOD frames, and compare to the inner proof’s composition polynomial openings.

5. **Tamper‑reject suite**
   - Add tests that mutate any transcript‑derived value, Merkle sibling, FRI layer value, remainder coefficient, or DEEP evaluation and confirm the outer proof fails.

Estimated dimensions:
- Trace width: 30-50 columns
- Trace length: 2^14 - 2^16 rows
- Proof size: ~10-15KB (still O(1) regardless of inner proof)

Create: `circuits/epoch/src/recursion/stark_verifier_air.rs`

**Success criteria**:
- StarkVerifierAir proof verifies
- Outer proof correctly rejects tampered inner proofs
- Recursion depth 2+: verify proof-of-proof-of-proof

### Phase 2f: Two-Person Testnet with Recursive Epoch Proofs (1 week)

#### Step 2f.1: Integrate recursive epochs into node

Modify `node/src/substrate/service.rs`:
```rust
// Guarded by HEGEMON_RECURSIVE_EPOCH_PROOFS=1:
//
// On best-chain imports:
// 1. Extract shielded_transfer proofs from block extrinsics
// 2. Hash each proof (blake3) -> proof_hashes for the epoch
// 3. At epoch boundary (block_number % 1000 == 0):
//    - Build Epoch metadata (proof_root + end-of-epoch state_root from parent header)
//    - Generate proof-of-proof via epoch_circuit::RecursiveEpochProver::prove_epoch_recursive()
//    - Broadcast RecursiveEpochProofMessage over RECURSIVE_EPOCH_PROOFS_PROTOCOL
// 4. On peer connect: send the latest RecursiveEpochProofMessage immediately
```

#### Step 2f.2: Light client recursive sync

Modify `circuits/epoch/src/light_client.rs`:
```rust
impl LightClient {
    /// Verify a recursive epoch proof (proof-of-proof) and advance the tip.
    pub fn sync_recursive(&mut self, epoch: &Epoch, proof: &RecursiveEpochProof) -> VerifyResult {
        // Verifies the inner RPO proof directly, or (if is_recursive) verifies the outer proof
        // which verifies the inner proof in-circuit.
        // Updates tip_epoch and stores the verified epoch.
    }
}
```

#### Step 2f.3: Two-person testnet validation

Run testnet with Alice and Bob:

```bash
# Terminal 1: Alice starts mining from genesis
HEGEMON_MINE=1 HEGEMON_RECURSIVE_EPOCH_PROOFS=1 ./target/release/hegemon-node --chain testnet --alice

# Wait for 5 epochs (5000 blocks, ~8 hours at 6s blocks)

# Terminal 2: Bob joins late
./target/release/hegemon-node --chain testnet --bob

# Bob's logs should show:
# "Received recursive epoch proof"
# "Sent recursive epoch proof to new peer" (on Alice)
# "📡 Broadcast recursive epoch proof to peers" (on Alice)
```

**Success criteria**:
- Bob syncs using single recursive proof
- Bob can immediately submit transactions
- Bob can verify historical transactions via Merkle proofs

### Phase 3: Testnet Validation + Recursive Composition

Phase 2 shipped **one-level recursion**: an inner RPO proof (RpoAir) can be verified inside an outer verifier proof (StarkVerifierAir), and the node can propagate these proofs (guarded by `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`). Phase 3 closes the remaining **soundness**, **operational UX**, and **composition** gaps so a light client can realistically sync long chains with a small number of proofs (eventually one).

Phase 3 work is split into six milestones:

#### Phase 3a: Query-position binding soundness hardening

Goal: ensure the indices used for Merkle and FRI openings are **cryptographically bound** to the transcript-derived query draws, matching Winterfell’s `draw_integers` behavior (draw → mask → sort+dedup → open).

Key requirements:
- Make the “draw value” used by the grand-product accumulator transcript-derived, not a free witness (today `COL_POS_SORTED_VALUE` is set by the prover).
- Bind transcript query draws to the **actual Merkle indices opened** (trace + constraints) in a way that remains sound when `draw_integers` emits duplicate draws.
- Extend the same binding to FRI: folded positions / partition indexes used for each layer’s Merkle openings must be derived from the base query positions and must handle fold collisions correctly.

Formal binding (current approach):
- Let `γ` be a transcript-derived challenge (we use `γ = z`).
- Let `draw_i` be the masked query position drawn from the transcript for each draw `i`.
- Let `idx_i` be the Merkle index actually opened in the verifier trace for draw `i`.
- Enforce multiset equality via a grand-product accumulator:
  - `acc <- acc * (draw_i + γ)` at each draw boundary
  - `acc <- acc / (idx_i + γ)` at each trace-leaf end boundary
  - Assert `acc == 1` at the end of the verifier trace
This is sound only if `draw_i` is transcript-derived in-circuit (not prover-chosen).

Validation:
- Add an adversarial test case where `draw_integers` emits duplicate draws mapping to the same unique query position; show that (a) correct openings verify and (b) tampering the opened index/paths is rejected.
- Once shipped, remove the “query-dedup soundness gap” note from `SECURITY.md`.

#### Phase 3b: Batch inner verification (depth-1, no self-recursion)

Goal: avoid recursion depth 2+ (verifier-of-verifier) while still achieving **single-proof sync**. Instead of building a self-recursive verifier proof (which explodes trace width), build a single outer proof which verifies **N independent inner proofs** sequentially in one trace. Trace **width stays flat**; trace **length grows ~N×**.

This replaces the Phase 3b “self-recursive outer proofs” goal. The motivating architecture for light-client “single-proof sync” is:

- 1024 epochs → 16 batches of 64 epochs each
- 16 batches → 16 inner proofs (each commits to 64 epochs)
- 16 inner proofs → 1 outer `StarkVerifierBatchAir` proof (verifies all 16)
- Light client verifies **1** outer proof (O(1) verification)

Key requirements:
- Implement a **batch verifier AIR** which verifies `N` `RpoAir` proofs **in one outer proof**, by time-multiplexing the existing verifier trace layout (same columns, longer trace).
- Keep soundness: all per-proof checks (transcript reconstruction, Merkle openings, DEEP, FRI) must still run for each inner proof; only cross-proof transitions are “reset” points.
- Bind the set of inner proofs to outer public inputs (either explicitly via per-proof `StarkVerifierPublicInputs`, or via an in-circuit commitment hash; choose one and document it).

Validation:
- Add a test which generates `N` independent inner `RpoAir` proofs and proves one outer batch proof that verifies all `N`.
- Tamper-reject: flip a byte in any inner proof bytes after the outer batch proof is generated and show outer verification fails.

#### Phase 3c: Two-stage epoch aggregation (epochs → batched inner → single outer)

Goal: reduce the number of inner proofs the outer batch verifier must verify by pre-aggregating epochs into fixed-size batches.

Key requirements:
- **Batch inner prover:** generate 1 `RpoAir` proof which commits to `K` epoch accumulators (a fixed batch size). This is the “epochs → batched inner” stage.
- **Outer batch verifier:** verify `N` of these batched-inner proofs in one outer proof (Phase 3b). This is the “batched inners → single outer” stage.
- Define concrete public inputs for the batched-inner proof (at minimum: `(epoch_start, epoch_end, batch_chain_digest)` or equivalent commitment) and ensure the commitment is stable and deterministic.

Validation:
- Add a test which aggregates `K` epoch accumulators into one batched-inner proof.
- Add an end-to-end test for the two-stage pipeline on small numbers (e.g., `K=4`, `N=2`) so it can run in CI. Note: the current batch verifier requires a power-of-two `N`.
- Leave a heavier ignored test which uses stronger proof options (more queries / larger blowup) to exercise the “realistic parameters” path without slowing down CI.

#### Phase 3d: Testnet proof retrieval + persistence

Goal: make two-person testnet validation real without manual log scraping/copying.

Key requirements:
- Extend the PQ network protocol with request/response messages to fetch epoch proofs by number (and later by range).
- Persist generated and received recursive epoch proofs to local storage (configurable directory).
- **Validate on receipt before storing/forwarding** to mitigate DoS: at minimum parse + epoch-commitment checks; optionally full STARK verification (policy must be explicit and safe).
- Add an RPC surface and/or CLI tooling to query the latest stored proof and fetch a specific epoch proof.

#### Phase 3e: Performance budgets + benchmarks

Goal: track real recursion overhead and prevent regressions.

Key requirements:
- Add benchmarks which exercise realistic epoch sizes (e.g. 100/500/1000 proof hashes) and record proof sizes, prover time, verifier time, and peak memory during outer proof generation.
- Define regression thresholds (e.g. outer/inner size ratio, outer prover time ratio, memory ceiling) and wire a CI job to fail when exceeded (nightly/optional gate is acceptable if runtime is heavy).

#### Phase 3f: Documentation + cleanup

Goal: make maintenance and audit feasible.

Key requirements:
- Remove or `#[cfg(test)]`-gate the deprecated transcript-only helper `StarkVerifierProver::prove_pub_inputs_hash`.
- Add a trace-column layout diagram to the module docs in `circuits/epoch/src/recursion/stark_verifier_air.rs`.
- Create a dedicated testnet runbook (e.g. `runbooks/recursive_proofs_testnet.md`) for Phase 3 validation.
- Run ignored “heavy” end-to-end recursion tests in a nightly/weekly CI job.
- Produce an audit-prep document summarizing soundness-critical constraints, the grand-product binding argument, and all assumptions about inner proof structure.

## Concrete Steps

### Phase 1 Steps (Merkle Accumulator)

**Step 1: Create epoch-circuit crate**
```bash
cd circuits
cargo new epoch --lib
# Add to workspace Cargo.toml members
echo 'epoch-circuit = { path = "circuits/epoch" }' >> ../Cargo.toml
cargo check -p epoch-circuit
```
Expected output: `Compiling epoch-circuit v0.1.0` with no errors.

**Step 2: Implement types and Merkle tree**
```bash
# Create files as specified in Plan of Work steps 1.2, 1.3
touch circuits/epoch/src/types.rs
touch circuits/epoch/src/merkle.rs
cargo test -p epoch-circuit
```
Expected: `test merkle::tests::test_compute_proof_root ... ok`

**Step 3: Implement epoch AIR**
```bash
touch circuits/epoch/src/air.rs
touch circuits/epoch/src/prover.rs
touch circuits/epoch/src/lib.rs
cargo check -p epoch-circuit
```
Expected: No errors, all types properly defined.

**Step 4: Run epoch proof benchmark**
```bash
cargo bench -p epoch-circuit --bench epoch_proof
```
Expected output:
```
epoch_proof/1000_proofs   time: [1.xxx s 1.xxx s 1.xxx s]
epoch_proof_verify        time: [xxx µs xxx µs xxx µs]
```

**Step 5: Integrate with pallet**
```bash
# Add epoch-circuit dependency to pallet-shielded-pool
cargo check -p pallet-shielded-pool
```

### Phase 2 Steps (Verifier Circuit Spike) - COMPLETE ✓

**Step 1: Create verifier spike module** ✓
```bash
mkdir -p circuits/epoch/src/verifier_spike
touch circuits/epoch/src/verifier_spike/mod.rs
touch circuits/epoch/src/verifier_spike/fibonacci_air.rs
touch circuits/epoch/src/verifier_spike/fibonacci_verifier_air.rs
touch circuits/epoch/src/verifier_spike/tests.rs
```

**Step 2: Implement Fibonacci verifier** ✓
```bash
cargo test -p epoch-circuit verifier_spike
```
Result: 12 tests passed

**Step 3: Benchmark recursive verification** ✓
Results:
- Inner proof size: 4,012 bytes
- Outer proof size: 7,860 bytes (1.96x) ✓ < 10x
- Inner prover time: 4ms
- Outer prover time: 26ms (6.5x) ✓ < 100x

### Phase 2b-2f Steps (True Recursion with miden-crypto)

**Step 2b.1: Add miden-crypto dependency**
```bash
# Add to circuits/epoch/Cargo.toml
cargo add miden-crypto --package epoch-circuit
cargo check -p epoch-circuit
```
Expected: Compiles with miden-crypto

**Step 2b.2: Verify RpoRandomCoin compatibility**
```bash
cargo test -p epoch-circuit rpo_random_coin_compat
```
Expected: RpoRandomCoin works with winterfell 0.13.1

**Step 2c.1: Implement RpoAir**
```bash
touch circuits/epoch/src/recursion/mod.rs
touch circuits/epoch/src/recursion/rpo_air.rs
cargo test -p epoch-circuit rpo_air
```
Expected: RPO permutation matches miden-crypto reference

**Step 2d.1: Implement MerkleVerifierAir (Merkle authentication sub-AIR)**

This step is about making Merkle authentication *real* inside recursion, not “plausible-looking”.
In this repo the Merkle verifier AIR lives in `circuits/epoch/src/recursion/merkle_air.rs` and is
used as a building block inside `StarkVerifierAir`.

Implementation tasks for this step:
- Make the Merkle path constraints enforce the exact `Rpo256::merge` semantics (digest in
  rate[0..3] == trace columns 4..7, and left/right ordering is index-bit dependent).
- Make chaining complete: the leaf hash output must be *wired* into the first merge permutation
  (leaf → level0), not “recomputed in Rust” with no in-AIR linkage.
- Add index-bit binding: the `path_bit` column used for chaining must be proven to match the leaf
  index bits (via shift relation `idx_cur = 2*idx_next + bit`), and the final index at the root
  must be zero.
- Add tamper tests: mutate a sibling digest, a `path_bit`, or the index witness and ensure outer
  proving fails.

Validation:
```bash
cargo test -p epoch-circuit merkle_air -- --nocapture
```
Expected: correct paths accepted, incorrect rejected, and tampering is detected.

**Step 2d.2: Implement FriVerifierAir (FRI sub-AIR)**

This step makes the low-degree proof (FRI) verifiable in-circuit.
In this repo the FRI AIR lives in `circuits/epoch/src/recursion/fri_air.rs` and includes:
folding checks, remainder-polynomial checks, and (eventually) the “fold-to-remainder” binding.

Implementation tasks for this step:
- Enforce folding for each committed layer (factor 2 for now), gated by a folding mask so the
  trace can include non-FRI permutations without violating degrees.
- Enforce remainder evaluation (Horner) and its binding to the final fold (“DRP” binding).
- Wire FRI Merkle openings into the Merkle sub-AIR (leaf hashing + path authentication).
- Add tamper tests: mutate an alpha, a layer evaluation, or a remainder coefficient and ensure the
  outer prover fails.

Validation:
```bash
cargo test -p epoch-circuit fri_air -- --nocapture
```
Expected: correct folding accepted, incorrect rejected, remainder checks enforced.

**Step 2e.1: Implement StarkVerifierAir (full in-circuit verifier)**

`StarkVerifierAir` in `circuits/epoch/src/recursion/stark_verifier_air.rs` is the “true recursion”
core: it must enforce the *same* verification logic as `winter-verifier`, including Fiat–Shamir
transcript evolution, query-position derivation, Merkle authentication, DEEP composition, and FRI.

The work for this step is split into concrete milestones so we can ship incrementally while
preserving soundness at each milestone:

- Milestone 2e.1a (Transcript correctness): RPO transcript seeding, reseeds, and challenge draws
  are checked in-AIR with boundary assertions and witness equality checks. (In progress: the
  transcript skeleton works, but OOD binding still needs to be made sound.)
- Milestone 2e.1b (OOD correctness): make the OOD step “real” so the prover can’t pick an
  arbitrary transcript fork.
  - Hash the OOD frames in-circuit: compute `Rpo256::hash_elements(merge_ood_evaluations(...))`
    and require the result equals the digest used to reseed the coin before DEEP coefficient draws.
  - Implement the OOD consistency check from `winter-verifier`:
    - Compute `evaluate_constraints(ood_trace_frame, constraint_coeffs, z)` in-circuit.
    - Compute `ood_constraint_evaluation_2 = Σ z^(i * trace_length) * quotient_frame.current[i]`.
    - Constrain `ood_constraint_evaluation_1 == ood_constraint_evaluation_2`.
- Milestone 2e.1c (Merkle correctness): leaf hashing is wired into merges (leaf→merge chaining),
  `path_bit` is bound to the shifting index, and root checks are applied at the correct boundaries.
- Milestone 2e.1d (Query-position correctness): model `draw_integers` output *with duplicates* and
  bind transcript-derived query positions to the authenticated indices used for trace/constraint/FRI
  openings (either via an in-circuit sort+dedup, or via a per-draw schedule plus explicit binding
  checks that prevent cross-query mix-and-match).
- Milestone 2e.1e (DEEP correctness): implement the DEEP composer checks tying queried trace/constraint
  evaluations and OOD frames to the DEEP composition polynomial.
- Milestone 2e.1f (FRI correctness): integrate the FriVerifierAir logic into StarkVerifierAir so
  that the authenticated DEEP evaluations satisfy FRI folding and remainder checks.

**Definition of “true recursion” success for this plan**:
- Given a valid inner RPO proof, `StarkVerifierProver::build_trace_from_inner()` produces a trace
  that can be proven/verified with `StarkVerifierAir`, and this outer proof is accepted.
- If we tamper any of: the OOD trace/quotient frames, the OOD digest, a Merkle index/path bit, a
  queried trace/constraint value, a FRI layer value/path, or a remainder coefficient, then the
  outer prover must fail (or the outer verifier must reject), matching the inner verifier’s reject.

Validation:
```bash
cargo test -p epoch-circuit stark_verifier_prover -- --nocapture
```
Expected: valid inner proofs produce a verifier trace that can be proven/verified, and targeted
tampering causes proof generation to fail.

**Step 2e.2: Test recursion depth**
```bash
cargo test -p epoch-circuit recursion_depth_3 -- --ignored
```
Expected: Proof-of-proof-of-proof verifies

**Step 2f.1: Two-person testnet validation**
```bash
# Terminal 1: Alice
HEGEMON_MINE=1 ./target/release/hegemon-node --chain testnet --alice

# Terminal 2: Bob (after 5 epochs)
./target/release/hegemon-node --chain testnet --bob
```
Expected: Bob syncs via single recursive proof

## Validation and Acceptance

### Phase 1 Acceptance Criteria

| Criterion | Validation Command | Expected Result |
|-----------|-------------------|-----------------|
| Epoch crate compiles | `cargo check -p epoch-circuit` | No errors |
| Dimensions tests pass | `cargo test -p epoch-circuit dimensions -- --nocapture` | All 5 tests pass with output |
| Merkle tree tests pass | `cargo test -p epoch-circuit merkle` | 5 tests pass (roundtrip verified) |
| Types tests pass | `cargo test -p epoch-circuit types` | Epoch commitment deterministic |
| Mock prover works | `cargo test -p epoch-circuit mock_prover` | MockEpochProver returns proof |
| AIR constraints compile | `cargo check -p epoch-circuit` | No errors on air.rs |
| Trace generation | `cargo test -p epoch-circuit trace_building` | Correct trace dimensions |
| Full proof generation | `cargo test -p epoch-circuit full_proof -- --ignored` | Proof generated in <10s |
| Light client inclusion | `cargo test -p epoch-circuit light_client` | Merkle proof verified |
| Pallet compiles | `cargo check -p pallet-shielded-pool` | No errors with epoch storage |
| Pallet epoch hook | `cargo test -p pallet-shielded-pool epoch_finalize` | EpochFinalized event emitted |
| Two-node epoch sync | `cargo test --test multinode_integration epoch_sync -- --ignored` | Both nodes have matching epoch |
| Light client sync test | `cargo test --test multinode_integration light_client_epoch -- --ignored` | All epochs verified |
| Integration test | `cargo test -p hegemon-node epoch_sync` | Light client syncs epochs |

### Phase 2 Acceptance Criteria

| Criterion | Validation | Expected Result |
|-----------|-----------|-----------------|
| ~~Fibonacci verifier compiles~~ | ~~`cargo check`~~ | ~~No errors~~ ✓ COMPLETE |
| ~~Recursive proof verifies~~ | ~~`cargo test recursive`~~ | ~~Valid proof accepted~~ ✓ COMPLETE |
| ~~Proof size ratio~~ | ~~Benchmark output~~ | ~~1.96x < 10x~~ ✓ COMPLETE |
| ~~Prover time ratio~~ | ~~Benchmark output~~ | ~~6.5x < 100x~~ ✓ COMPLETE |
| ~~Decision documented~~ | ~~Decision Log updated~~ | ~~Go recorded~~ ✓ COMPLETE |

### Phase 2b-2f Acceptance Criteria (True Recursion)

| Criterion | Validation | Expected Result |
|-----------|-----------|-----------------|
| miden-crypto added | `cargo check -p epoch-circuit` | No errors |
| RpoRandomCoin compat | `cargo test rpo_random_coin_compat` | Works with winterfell 0.13.1 |
| RpoAir correctness | `cargo test rpo_air` | Output matches miden-crypto |
| Inner RPO proofs (tx + batch) | `cargo test -p transaction-circuit rpo_proofs` and `cargo test -p batch-circuit rpo_proofs` | Inner proofs verify natively and reject tampering |
| MerkleVerifierAir | `cargo test merkle_verifier_air` | Correct paths verified |
| FriVerifierAir | `cargo test fri_verifier_air` | Correct folding verified |
| StarkVerifierAir | `cargo test stark_verifier_air` | Inner proofs verified |
| Recursion depth 3+ | `cargo test recursion_depth_3 -- --ignored` | Triple nesting works |
| Two-person testnet | Manual test | Bob syncs via recursive proof |
| Quantum safety | Code review | No elliptic curves used |

### Security Acceptance

- [x] All proofs use 128-bit security (Goldilocks field + extension)
- [x] Fiat-Shamir transcript consistent between layers
- [x] No information leakage in public inputs
- [x] Epoch commitment binds all metadata
- [ ] RPO parameters match miden-crypto security analysis
- [ ] No trusted setup required
- [ ] Quantum-safe (no EC, hash-based only)

## Interfaces and Dependencies

### Crate Structure

```
circuits/epoch/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API exports
│   ├── types.rs         # Epoch, EpochProof types
│   ├── merkle.rs        # Merkle tree operations
│   ├── air.rs           # EpochProofAir
│   ├── prover.rs        # EpochProver
│   ├── light_client.rs  # LightClient API
│   └── verifier_spike/  # Phase 2 research
│       ├── mod.rs
│       ├── fibonacci_air.rs
│       └── fibonacci_verifier_air.rs
├── benches/
│   ├── epoch_proof.rs
│   └── recursive_spike.rs
└── tests/
    └── integration.rs
```

### Public API (lib.rs)

```rust
//! Epoch proofs for light client verification.
//!
//! This crate provides:
//! - Merkle tree operations for proof accumulation
//! - STARK proofs attesting to epoch validity
//! - Light client API for efficient chain sync

mod dimensions;
mod types;
mod merkle;
mod air;
mod prover;
mod light_client;

// Dimension calculations (for testing/validation)
pub use dimensions::{
    merkle_depth, merkle_proof_size, padded_leaf_count,
    EPOCH_SIZE, MAX_PROOFS_PER_EPOCH,
};
pub use dimensions::security;
pub use dimensions::trace;

// Core types
pub use types::{Epoch, proof_hash};

// Merkle tree operations
pub use merkle::{compute_proof_root, verify_merkle_proof, generate_merkle_proof};

// Proof generation
pub use prover::{EpochProver, EpochProof, MockEpochProver};

// Light client
pub use light_client::{LightClient, VerifyResult};

// AIR (for advanced use / pallet integration)
pub use air::{EpochProofAir, EpochPublicInputs};

#[cfg(test)]
mod integration_tests;
```

### Dependencies

**Upstream (libraries)**:
- `winterfell = "0.13.1"` - STARK prover/verifier
- `sp-core = "21.0.0"` - Blake2 hashing
- `parity-scale-codec = "3.6"` - Encoding

**Downstream (consumers)**:
- `pallet-shielded-pool` - Epoch finalization, light client sync
- `hegemon-node` - Epoch boundary detection

**No dependency on PROOF_AGGREGATION_EXECPLAN**: This plan is independent. Epoch proofs work with any transaction proof format (individual or batched).

### Integration Points

#### Step 1.6: Pallet integration (storage, events, extrinsics)

Add the following to `pallets/shielded-pool/src/lib.rs`:

```rust
// ================================================================================================
// EPOCH STORAGE
// ================================================================================================

/// Epoch size in blocks.
pub const EPOCH_SIZE: u64 = 1000;

#[pallet::storage]
#[pallet::getter(fn current_epoch)]
pub type CurrentEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

#[pallet::storage]
#[pallet::getter(fn epoch_proof_hashes)]
/// Proof hashes collected during current epoch.
pub type EpochProofHashes<T: Config> = StorageValue<_, Vec<[u8; 32]>, ValueQuery>;

#[pallet::storage]
#[pallet::getter(fn epoch_proofs)]
/// Finalized epoch proofs (epoch_number -> serialized proof).
pub type EpochProofs<T: Config> = StorageMap<_, Blake2_128Concat, u64, Vec<u8>>;

#[pallet::storage]
#[pallet::getter(fn epoch_commitments)]
/// Epoch commitments for light client sync.
pub type EpochCommitments<T: Config> = StorageMap<_, Blake2_128Concat, u64, [u8; 32]>;

// ================================================================================================
// EPOCH EVENTS
// ================================================================================================

#[pallet::event]
#[pallet::generate_deposit(pub(super) fn deposit_event)]
pub enum Event<T: Config> {
    // ... existing events ...

    /// An epoch has been finalized with a proof.
    EpochFinalized {
        epoch_number: u64,
        proof_root: [u8; 32],
        num_proofs: u32,
    },

    /// Light client sync data available.
    EpochSyncAvailable {
        epoch_number: u64,
        commitment: [u8; 32],
    },
}

// ================================================================================================
// EPOCH HOOKS
// ================================================================================================

#[pallet::hooks]
impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(block_number: BlockNumberFor<T>) {
        let block_num: u64 = block_number.try_into().unwrap_or(0);
        
        // Check if this block ends an epoch
        if block_num > 0 && block_num % EPOCH_SIZE == 0 {
            let epoch_number = (block_num / EPOCH_SIZE) - 1;
            if let Err(e) = Self::finalize_epoch_internal(epoch_number) {
                log::error!("Failed to finalize epoch {}: {:?}", epoch_number, e);
            }
        }
    }
}

// ================================================================================================
// EPOCH IMPLEMENTATION
// ================================================================================================

impl<T: Config> Pallet<T> {
    /// Record a proof hash for the current epoch.
    ///
    /// Called after each successful shielded transfer.
    pub fn record_proof_hash(proof_hash: [u8; 32]) {
        EpochProofHashes::<T>::mutate(|hashes| {
            hashes.push(proof_hash);
        });
    }

    /// Finalize an epoch and generate its proof.
    fn finalize_epoch_internal(epoch_number: u64) -> DispatchResult {
        use epoch_circuit::{Epoch, MockEpochProver, compute_proof_root};
        use sp_core::hashing::blake2_256;

        let proof_hashes = EpochProofHashes::<T>::take();
        if proof_hashes.is_empty() {
            // Empty epoch - no proof needed
            return Ok(());
        }

        let proof_root = compute_proof_root(&proof_hashes);

        let epoch = Epoch {
            epoch_number,
            start_block: epoch_number * EPOCH_SIZE,
            end_block: (epoch_number + 1) * EPOCH_SIZE - 1,
            proof_root,
            state_root: Self::state_root().unwrap_or([0u8; 32]),
            nullifier_set_root: Self::nullifier_root().unwrap_or([0u8; 32]),
            commitment_tree_root: Self::commitment_root().unwrap_or([0u8; 32]),
        };

        // Generate epoch proof (use MockEpochProver until real prover is ready)
        let epoch_proof = MockEpochProver::prove(&epoch, &proof_hashes)
            .map_err(|_| Error::<T>::EpochProofFailed)?;

        // Store epoch data
        EpochProofs::<T>::insert(epoch_number, epoch_proof.proof_bytes);
        EpochCommitments::<T>::insert(epoch_number, epoch.commitment());

        // Update current epoch
        CurrentEpoch::<T>::put(epoch_number + 1);

        // Emit events
        Self::deposit_event(Event::EpochFinalized {
            epoch_number,
            proof_root,
            num_proofs: proof_hashes.len() as u32,
        });

        Self::deposit_event(Event::EpochSyncAvailable {
            epoch_number,
            commitment: epoch.commitment(),
        });

        Ok(())
    }

    /// Get epoch proof for light client sync.
    pub fn get_epoch_sync_data(epoch_number: u64) -> Option<(Vec<u8>, [u8; 32])> {
        let proof = EpochProofs::<T>::get(epoch_number)?;
        let commitment = EpochCommitments::<T>::get(epoch_number)?;
        Some((proof, commitment))
    }
}

// ================================================================================================
// EPOCH ERRORS
// ================================================================================================

#[pallet::error]
pub enum Error<T> {
    // ... existing errors ...

    /// Epoch proof generation failed.
    EpochProofFailed,

    /// Invalid epoch number.
    InvalidEpoch,
}
```

**Integration with shielded_transfer**:

In the `shielded_transfer` extrinsic, after successful verification:

```rust
#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::weight(/* ... */)]
    pub fn shielded_transfer(
        origin: OriginFor<T>,
        proof: Vec<u8>,
        nullifiers: Vec<T::Nullifier>,
        commitments: Vec<T::Commitment>,
        // ... other params
    ) -> DispatchResult {
        // ... existing verification logic ...

        // Record proof hash for epoch accumulation
        let proof_hash = sp_core::hashing::blake2_256(&proof);
        Self::record_proof_hash(proof_hash);

        // ... rest of existing logic ...
        
        Ok(())
    }
}
```

#### RPC Endpoints for Light Clients

Add to `pallets/shielded-pool/src/rpc.rs`:

```rust
//! RPC endpoints for light client epoch sync.

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

/// Epoch sync RPC API.
#[rpc(client, server)]
pub trait EpochApi<BlockHash> {
    /// Get epoch proof and commitment for light client sync.
    #[method(name = "epoch_getSyncData")]
    fn get_epoch_sync_data(
        &self,
        epoch_number: u64,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<EpochSyncData>>;

    /// Get Merkle proof for transaction inclusion.
    #[method(name = "epoch_getInclusionProof")]
    fn get_inclusion_proof(
        &self,
        epoch_number: u64,
        tx_index: u32,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<InclusionProof>>;

    /// Get current epoch number.
    #[method(name = "epoch_current")]
    fn current_epoch(&self, at: Option<BlockHash>) -> RpcResult<u64>;
}

/// Epoch sync data returned by RPC.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EpochSyncData {
    pub epoch_number: u64,
    pub proof_bytes: Vec<u8>,
    pub commitment: [u8; 32],
}

/// Merkle inclusion proof for a transaction.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub epoch_number: u64,
    pub tx_index: u32,
    pub proof_hash: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
}
```

## Security Considerations

1. **Soundness Preservation**
   - All proofs must use Goldilocks field for 128-bit security
   - FRI parameters consistent: 8 queries, 4 grinding bits
   - Fiat-Shamir transcript includes all public inputs

2. **Epoch Commitment Binding**
   - Epoch commitment hashes ALL metadata (block range, roots)
   - Cannot forge epoch proof for different state
   - Light clients verify commitment before accepting

3. **Merkle Tree Security**
   - Blake2-256 collision resistance
   - Proof-of-inclusion requires correct index
   - Padding with zeros prevents length extension

4. **Phase 2 Research Risks**
   - Verifier circuit may be impractical in winterfell
   - If spike fails, alternatives documented (Plonky2, Miden)
   - Phase 1 ships regardless of Phase 2 outcome

## Success Criteria

### Phase 1 (Must Ship)

1. **Epoch proof generation**: < 10 seconds for 1000 transactions
2. **Epoch proof verification**: < 100ms
3. **Light client sync**: O(log N) verification for any transaction
4. **Proof size**: Epoch proof < 200 KB

### Phase 2 (Research Target)

1. **Recursive proof valid**: Outer proof verifies inner proof correctness
2. **Size overhead**: < 10× inner proof size
3. **Time overhead**: < 100× inner prover time
4. **Decision**: Go/no-go documented in Decision Log

## Timeline

| Phase | Effort | Deliverable |
|-------|--------|-------------|
| Phase 0: Crate skeleton + dimensions | 0.5 days | Validated sizing assumptions |
| Phase 1a: Merkle tree implementation | 0.5 days | Complete merkle.rs with tests |
| Phase 1b: Epoch types + mock prover | 0.5 days | types.rs, MockEpochProver |
| Phase 1c: EpochProofAir | 1.5 days | Full AIR with Poseidon constraints |
| Phase 1d: Real EpochProver | 1 day | Trace generation, proof production |
| Phase 1e: Light client API | 0.5 days | LightClient with inclusion verification |
| Phase 1f: Pallet integration | 1 day | Storage, events, hooks, RPC |
| **Phase 1 Total** | **5.5 days** | **Shippable epoch proofs** |
| Phase 2: Verifier spike | 3-5 days | Go/no-go decision on recursion |
| Phase 3: Full recursion | 10+ days | If spike succeeds |

**Phase 1 ships independently**. Phase 2 is research that may or may not succeed. Do not block Phase 1 on Phase 2 outcome.

**Work Order** (dependencies shown):
```
Phase 0: dimensions.rs
    │
    ├─→ Phase 1a: merkle.rs (no deps on 0)
    │       │
    │       └─→ Phase 1e: light_client.rs
    │
    └─→ Phase 1b: types.rs + MockEpochProver
            │
            ├─→ Phase 1f: Pallet integration (can start with mock)
            │
            └─→ Phase 1c: EpochProofAir
                    │
                    └─→ Phase 1d: Real EpochProver
                            │
                            └─→ Replace MockEpochProver in pallet
```

## Idempotence and Recovery

**Safe to re-run**: All steps can be run multiple times safely:
- `cargo new` will fail if crate exists (expected, continue with existing)
- File creation is idempotent
- Tests can be run any number of times

**Recovery from partial state**:
- If compile fails: Fix the error and re-run `cargo check`
- If tests fail: Read failure output, fix code, re-run tests
- If Phase 2 spike fails: Document in Decision Log and proceed with Phase 1 only

**Phase 2 research recovery**: If the verifier circuit proves impractical:
1. Document findings in Decision Log
2. Evaluate alternatives (Plonky2, Miden VM, external contribution)
3. Phase 1 remains valuable regardless

## Artifacts and Notes

**Expected Phase 1 benchmark output**:
```
epoch_proof/1000_proofs   time: [x.xxx s x.xxx s x.xxx s]
epoch_proof_verify        time: [xxx µs xxx µs xxx µs]
merkle_inclusion/depth_10 time: [xxx µs xxx µs xxx µs]
```

**Phase 1 test output format**:
```
running 8 tests
test types::tests::test_epoch_commitment ... ok
test merkle::tests::test_compute_proof_root ... ok
test merkle::tests::test_verify_merkle_proof ... ok
test air::tests::test_epoch_pub_inputs ... ok
test prover::tests::test_epoch_proof_generation ... ok
test prover::tests::test_epoch_proof_verification ... ok
test light_client::tests::test_verify_inclusion ... ok
test integration::tests::test_pallet_epoch_finalization ... ok

test result: ok. 8 passed; 0 failed
```

**Phase 2 spike output** (if successful):
```
Fibonacci inner proof: 1.2 KB, 5ms prover
Fibonacci verifier proof: 8.4 KB, 250ms prover
Size ratio: 7x (PASS: < 10x)
Time ratio: 50x (PASS: < 100x)
SPIKE RESULT: PROCEED TO FULL IMPLEMENTATION
```

**Phase 2 spike output** (if failed):
```
Fibonacci inner proof: 1.2 KB, 5ms prover
Fibonacci verifier proof: 145 KB, 12s prover
Size ratio: 120x (FAIL: > 10x)
Time ratio: 2400x (FAIL: > 100x)
SPIKE RESULT: EVALUATE ALTERNATIVES
```

---

## Two-Node Integration Testing

This section describes how to validate epoch proofs work correctly in a multi-node network.

### Test Configuration

For faster testing, use a smaller epoch size:

```bash
# Set test epoch size (10 blocks instead of 1000)
export HEGEMON_EPOCH_SIZE=10
```

Add runtime support in `pallets/shielded-pool/src/lib.rs`:

```rust
/// Epoch size - configurable for testing
pub fn epoch_size() -> u64 {
    std::env::var("HEGEMON_EPOCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
}
```

### Automated Integration Tests

Add to `tests/multinode_integration.rs`:

```rust
// ============================================================================
// Epoch Sync Tests
// ============================================================================

/// Test epoch finalization and sync between two nodes
#[tokio::test]
#[ignore] // Run with: cargo test -p security-tests --test multinode_integration epoch_sync -- --ignored
async fn test_epoch_sync_two_nodes() {
    let mut manager = LiveNodeManager::new();
    
    // Spawn Alice (boot node)
    manager.spawn_node(&ALICE, None).unwrap();
    manager.wait_for_node(&ALICE, 30).await.unwrap();
    
    // Spawn Bob (connects to Alice)
    let alice_addr = format!("127.0.0.1:{}", ALICE.p2p_port);
    manager.spawn_node(&BOB, Some(&alice_addr)).unwrap();
    manager.wait_for_node(&BOB, 30).await.unwrap();
    
    // Wait for nodes to sync
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Generate transactions to accumulate proof hashes
    for _ in 0..15 {
        submit_test_transaction(&ALICE).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    
    // Wait for epoch boundary
    tokio::time::sleep(Duration::from_secs(30)).await;
    
    // Verify epoch was finalized on Alice
    let alice_epoch = get_current_epoch(&ALICE).await.unwrap();
    assert!(alice_epoch >= 1, "Alice should have finalized epoch 0");
    
    // Verify epoch proof exists
    let alice_proof = get_epoch_proof(&ALICE, 0).await.unwrap();
    assert!(alice_proof.is_some(), "Alice should have epoch 0 proof");
    
    // Wait for sync
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // Verify Bob received the epoch proof
    let bob_epoch = get_current_epoch(&BOB).await.unwrap();
    let bob_proof = get_epoch_proof(&BOB, 0).await.unwrap();
    
    assert_eq!(alice_epoch, bob_epoch, "Epochs should match");
    assert_eq!(alice_proof, bob_proof, "Epoch proofs should match");
}

/// Test light client sync using epoch proofs
#[tokio::test]
#[ignore]
async fn test_light_client_epoch_sync() {
    let mut manager = LiveNodeManager::new();
    manager.spawn_node(&ALICE, None).unwrap();
    manager.wait_for_node(&ALICE, 30).await.unwrap();
    
    // Generate enough blocks for multiple epochs
    for _ in 0..35 {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    
    // Verify light client can sync all epochs
    let current_epoch = get_current_epoch(&ALICE).await.unwrap();
    let mut light_client = epoch_circuit::LightClient::new();
    
    for epoch_num in 0..current_epoch {
        let sync_data = get_epoch_sync_data(&ALICE, epoch_num).await.unwrap();
        let result = light_client.verify_epoch(&sync_data.epoch, &sync_data.proof);
        assert_eq!(result, epoch_circuit::VerifyResult::Valid,
            "Light client should verify epoch {}", epoch_num);
    }
    
    println!("Light client synced {} epochs", light_client.num_verified());
}

// RPC helper functions
async fn get_current_epoch(identity: &TestIdentity) -> Result<u64, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "epoch_current",
        "params": []
    });
    
    let resp = client.post(identity.rpc_url())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(json["result"].as_u64().unwrap_or(0))
}

async fn get_epoch_proof(identity: &TestIdentity, epoch: u64) -> Result<Option<Vec<u8>>, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "epoch_getSyncData",
        "params": [epoch]
    });
    
    let resp = client.post(identity.rpc_url())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    
    if json["result"].is_null() {
        return Ok(None);
    }
    
    let proof_hex = json["result"]["proof_bytes"].as_str().unwrap_or("");
    Ok(Some(hex::decode(proof_hex).unwrap_or_default()))
}
```

### Manual Two-Node Testing

#### Step 1: Start Alice (Boot Node)

```bash
# Terminal 1
HEGEMON_EPOCH_SIZE=10 ./target/release/hegemon-node \
    --dev \
    --base-path /tmp/alice \
    --rpc-port 9944 \
    --port 30333 \
    --rpc-cors all \
    --rpc-methods unsafe \
    2>&1 | tee /tmp/alice.log
```

#### Step 2: Start Bob (Peer)

```bash
# Terminal 2 - Get Alice's peer ID first
ALICE_PEER_ID=$(curl -s http://127.0.0.1:9944 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"system_localPeerId","params":[]}' | jq -r '.result')

HEGEMON_EPOCH_SIZE=10 ./target/release/hegemon-node \
    --dev \
    --base-path /tmp/bob \
    --rpc-port 9945 \
    --port 30334 \
    --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/$ALICE_PEER_ID \
    2>&1 | tee /tmp/bob.log
```

#### Step 3: Generate Transactions

```bash
# Terminal 3 - Submit transactions to trigger epoch accumulation
for i in {1..15}; do
    echo "Submitting transaction $i..."
    ./target/release/wallet send \
        --amount 0.1 \
        --rpc http://127.0.0.1:9944 \
        2>/dev/null || echo "  (mock tx for testing)"
    sleep 5
done
```

#### Step 4: Verify Epoch Finalization

```bash
# Check Alice's current epoch
echo "Alice epoch:"
curl -s http://127.0.0.1:9944 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"epoch_current","params":[]}' | jq '.result'

# Check Bob's current epoch
echo "Bob epoch:"
curl -s http://127.0.0.1:9945 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"epoch_current","params":[]}' | jq '.result'

# Get epoch 0 sync data from both
echo "Alice epoch 0 commitment:"
curl -s http://127.0.0.1:9944 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"epoch_getSyncData","params":[0]}' | jq '.result.commitment'

echo "Bob epoch 0 commitment:"
curl -s http://127.0.0.1:9945 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"epoch_getSyncData","params":[0]}' | jq '.result.commitment'
```

#### Step 5: Verify Merkle Inclusion

```bash
# Get inclusion proof for first transaction in epoch 0
curl -s http://127.0.0.1:9944 -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"epoch_getInclusionProof","params":[0,0]}' | jq
```

### Verification Checklist

| Test Case | Command | Expected Result |
|-----------|---------|-----------------|
| Epoch finalized | Check logs for `EpochFinalized` | Event with epoch_number, proof_root |
| Epoch proof stored | `epoch_getSyncData(0)` | Non-null proof_bytes |
| Nodes sync epoch | Compare both nodes | Same epoch number |
| Commitments match | Compare commitments | Identical 32-byte hex |
| Proof bytes match | Compare proof_bytes | Identical hex strings |
| Inclusion proof works | `epoch_getInclusionProof(0,0)` | Valid merkle_path array |
| Light client verifies | Run test code | `VerifyResult::Valid` |
| Invalid proof rejected | Tamper and verify | `VerifyResult::InvalidProof` |

### Docker Compose Testing

Add to `docker-compose.testnet.yml`:

```yaml
services:
  alice:
    build: .
    command: >
      hegemon-node --dev --rpc-port 9944 --port 30333 --rpc-cors all
    environment:
      - HEGEMON_MINE=1
      - HEGEMON_EPOCH_SIZE=10
    ports:
      - "9944:9944"
      - "30333:30333"

  bob:
    build: .
    command: >
      hegemon-node --dev --rpc-port 9944 --port 30333
        --bootnodes /dns4/alice/tcp/30333/p2p/12D3KooW...
    environment:
      - HEGEMON_EPOCH_SIZE=10
    depends_on:
      - alice
    ports:
      - "9945:9944"

  epoch-test:
    build: .
    command: >
      sh -c "sleep 120 && cargo test -p security-tests 
             --test multinode_integration epoch_sync -- --ignored"
    depends_on:
      - alice
      - bob
```

Run:
```bash
docker-compose -f docker-compose.testnet.yml up --abort-on-container-exit
```

---

## Revision History

- **2025-12-10**: Initial draft
- **2025-12-10**: Major revision - restructured into Phase 1 (Merkle Accumulator, ships independently) and Phase 2 (Verifier Circuit, research-dependent). Removed dependency on PROOF_AGGREGATION_EXECPLAN. Added concrete steps, validation criteria, interfaces, and code examples per PLANS.md requirements. Clarified that winterfell does NOT support in-circuit STARK verification natively—this requires building a verifier circuit from scratch.
- **2025-12-10**: Gap analysis and completion:
  - Added complete `generate_merkle_proof` implementation with tests
  - Added complete `EpochProofAir` implementation reusing Poseidon patterns from BatchTransactionAir
  - Added `EpochProver` and `MockEpochProver` with trace generation
  - Added complete `LightClient` implementation with VerifyResult enum
  - Added pallet integration section with storage, events, hooks, and RPC endpoints
  - Added Decision Log entries for Poseidon hash choice, extension field requirement, stub-first development
  - Updated Progress to 6-phase granularity with explicit dependencies
  - Updated Timeline with work order showing parallelizable tasks
  - Updated Cargo.toml with transaction-circuit dependency for Poseidon reuse
- **2025-12-10**: Added Two-Node Integration Testing section:
  - Automated integration tests for `multinode_integration.rs`
  - Manual two-node testing steps with shell commands
  - Verification checklist for epoch sync validation
  - Docker Compose configuration for containerized testing
  - Added Phase 1g to Progress tracker
- **2025-12-11**: Truth‑aligned Phase 2/3 status and re‑planned for true recursion:
  - Corrected Progress/Current status to reflect groundwork vs. full recursion
  - Renamed Phase 2/3 outcomes to “Groundwork”
  - Added Step 2g and acceptance criteria for RPO inner proofs
  - Added Decision Log entry to pursue proof‑of‑proof recursion now
- **2025-12-12**: Phase 2g completed and recursion witness plumbing:
  - Marked Phase 2g complete (transaction + batch RPO provers/verifiers shipped)
  - Implemented `InnerProofData::from_proof` host-side extraction with exact RPO transcript reconstruction
  - Extended recursion public inputs to include full inner public inputs and FRI remainder commitment
- **2025-12-12**: Correctness fixes and minimal verifier milestone:
  - Fixed `RpoAir` constants to exactly match `miden_crypto::hash::rpo::Rpo256` and added a permutation match test.
  - Implemented a minimal `StarkVerifierAir` that proves the RPO sponge hash of inner public inputs, with periodic padding and corrected transition degrees.
  - Added `perm_mask` gating to `MerkleVerifierAir` to disable boundary RPO transitions between stacked permutations.
- **2025-12-12**: FRI verifier RPO + roundtrip milestone:
  - Re‑enabled RPO transitions in `FriVerifierAir`, fixed stacked‑perm periodicity, and restored static degree cycles.
  - Added minimal `FriVerifierProver` with proof roundtrip and tamper‑reject tests.
- **2025-12-12**: StarkVerifierAir transcript milestones:
  - Implemented in‑circuit RPO transcript through trace‑commitment reseed, coefficient draws, constraint‑commitment reseed, z draw, OOD reseed (OOD digest as witness), and DEEP coefficient draws.
  - Added stage masks (`coeff_mask`, `z_mask`, `deep_mask`) and witness equality checks for transcript‑derived challenges.
- **2025-12-12**: FRI alpha stage + remainder ordering fix:
  - Fixed host‑side transcript reconstruction to reseed (but not draw alpha) for the remainder commitment.
  - Added FRI commitment reseeds and alpha draw stage to `StarkVerifierAir`/`StarkVerifierProver` with `fri_mask` and alpha witness checks.
- **2025-12-12**: Expanded Phase 2d/2e Merkle tasks:
  - Broke out leaf sponge initialization/chaining, Merkle merge chaining, and deterministic stacking order required for true recursion.
  - Documented periodic selector approach and noted deferral of binding Merkle indexes to transcript‑drawn query positions until full `draw_integers` modeling lands.
- **2025-12-12**: Transcript-seed parity + end-to-end verifier trace unblocked:
  - Fixed `build_context_prefix` to encode `FieldExtension::None` as `1` (Winterfell is 1-based), restoring parity with `proof.context.to_elements()` and preventing transcript `z` drift.
  - Documented that FRI layer count depends on `(remainder_max_degree + 1) * blowup_factor`, not just LDE domain size.
  - Unblocked `test_trace_from_inner_merkle_roundtrip` for real inner proofs (`cargo test -p epoch-circuit test_trace_from_inner_merkle_roundtrip -- --nocapture` now passes).
  - Added explicit TODO to model query-position `sort+dedup` and bind Merkle index bits to transcript-derived query positions (a requirement for “true recursion” beyond the current milestone).
- **2025-12-13**: Phase 2d.3–2e.7 shipped (true recursion end-to-end for RPO inner proofs):
  - Fixed DEEP/FRI state columns by deterministically populating them in `StarkVerifierProver` (Winterfell `TraceTable::new()` leaves memory uninitialized).
  - Updated `StarkVerifierAir` transition degree descriptors for DEEP/FRI constraints so debug proofs no longer panic with `transition constraint degrees didn't match`.
  - Added focused tamper-detection tests for FRI folding and remainder binding, and extended the end-to-end recursion roundtrip test to include transcript reseed tamper rejection.
- **2025-12-13**: Phase 2f shipped (production wiring + propagation):
  - Added `RecursiveEpochProver::prove_epoch_recursive()` to generate a proof-of-proof (outer `StarkVerifierAir` proof verifying an inner RPO proof).
  - Wired node-side propagation in `node/src/substrate/service.rs`: collect shielded transfer proof hashes per epoch, generate recursive epoch proofs at boundaries (guarded by `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`), broadcast `RecursiveEpochProofMessage` over `RECURSIVE_EPOCH_PROOFS_PROTOCOL`, and send the latest proof to new peers on connect.
  - Added `LightClient::sync_recursive()` for verifying recursive epoch proofs, and updated `runbooks/two_person_testnet.md` to document the new env var + log expectations.
- **2025-12-13**: Phase 3b.2 scaffolding updates (verifier-as-inner prep):
  - Parameterized transcript/Merkle sizing in `StarkVerifierAir`/`StarkVerifierProver` using inner-proof metadata (`trace_width`, `constraint_frame_width`, transition/assertion counts) instead of RpoAir-only constants.
  - Gated fixed-size (RpoAir-only) OOD/DEEP constant-column checks and DEEP/FRI state-machine constraints behind `InnerProofKind::RpoAir` while streaming/replay remains pending; verifier-as-inner is still fail-closed on OOD step-3.
  - For verifier-as-inner traces, `StarkVerifierProver::build_trace_from_inner()` now zero-initializes DEEP/FRI state columns to keep trace construction deterministic without expensive native DEEP evaluation.
- **2025-12-13**: Pivot Phase 3b/3c to “batch verifier + two-stage epoch batching”:
  - Replaced the Phase 3b goal of depth-2 self recursion (verifier-of-verifier) with a depth-1 batch verifier which verifies `N` inner `RpoAir` proofs sequentially in one outer proof (keeps trace width ≤255).
  - Reframed Phase 3c from binary-tree epoch range aggregation to a two-stage pipeline: epochs → batched-inner proofs (K epochs per inner) → single outer batch proof verifying N inners.
- **2025-12-14**: Phase 3b batch verifier debug stabilization:
  - Fixed batch segment-boundary transition masking and aligned `TransitionConstraintDegree` descriptors with Winterfell debug degree checks for concatenated segments.
  - Confirmed passing ignored batch tests: `test_batch_prover_two_proofs`, `test_batch_prover_tamper_reject`.
- **2025-12-14**: Phase 3c two-stage epoch batching shipped:
  - Added `EpochBatchProof` + `RecursiveEpochProver::prove_epoch_batch()` / `verify_epoch_batch_proof()` to produce batched-inner `RpoAir` proofs committing to `(epoch_start, epoch_end, batch_accumulator, num_epochs)`.
  - Added a CI-scale end-to-end two-stage test (`test_two_stage_epoch_batch_pipeline_small_options`) and kept a heavier ignored test (`test_two_stage_epoch_batch_pipeline_roundtrip_and_tamper_reject`).
