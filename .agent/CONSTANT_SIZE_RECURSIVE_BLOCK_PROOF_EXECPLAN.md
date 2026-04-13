# Ship A Constant-Size Recursive Block Proof

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, a non-empty shielded block will be able to carry one constant-size recursive block-proof artifact instead of the current linear `receipt_root` lane plus linear commitment-proof public inputs. A user or operator will know the feature is real when two shielded blocks with different transaction counts both import successfully with one recursive block artifact of the same serialized length, while consensus still checks the exact same semantic block tuple it checks today: `tx_statements_commitment`, starting and ending shielded roots, starting and ending kernel roots, `nullifier_root`, `da_root`, and `tx_count`. The recursive proof-visible tuple is allowed one additional constant-size verified-leaf commitment, one additional constant-size verified-receipt commitment, and two constant-size append-state digests so the proof binds the exact ordered verified-leaf stream, the exact ordered verified receipt stream, and the exact frontier/history state rather than only the start/end roots.

The crucial correction in this revision is that the first milestone is backend work, not block-proof plumbing. The checked-in SuperNeo backend does not currently provide hidden-witness recursion. It provides verified-leaf aggregation. Any plan that starts with `BlockStepV1` / accumulator / final-artifact implementation before fixing that is lying about the critical path.

## Progress

- [x] (2026-04-12 21:42Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `docs/SCALABILITY_PATH.md`, `docs/crypto/native_backend_verified_aggregation.md`, `circuits/aggregation/src/v5.rs`, `circuits/block/src/p3_commitment_air.rs`, `circuits/block/src/p3_commitment_prover.rs`, and `consensus/src/commitment_tree.rs` to locate the current proof-size leaks and the live block-truth surface.
- [x] (2026-04-12 21:42Z) Confirmed the three hard current proof-size leaks: `AggregationProofV5Payload` serializes `packed_public_values` and `representative_child_proof`; `CommitmentBlockPublicInputsP3` serializes linear nullifier vectors; and `tx_statements_commitment` is a sequential Poseidon sponge, so any honest merge construction must carry constant-size boundary state rather than pretending the leaf hash itself is associative.
- [x] (2026-04-12 21:56Z) Wrote the first blackboard-level recursive construction in `docs/crypto/constant_recursive_block_proof.md` and rendered a visual summary in `docs/assets/constant-recursive-block-proof-blackboards.svg`.
- [x] (2026-04-12 22:10Z) Corrected the construction to include the missing `leaf_count` state variable and moved the note from an architecture sketch to a theorem-style state machine.
- [x] (2026-04-12 22:49Z) Resolved the two previously-open design questions against the actual code: preserve the current semantic block tuple exactly, and keep BLAKE3 out of recursive arithmetic by using Poseidon2 for internal recursive state binding and sparse-set updates while leaving `nullifier_root` / `da_root` recomputation outside the proof.
- [x] (2026-04-12 22:49Z) Stated the real blocker explicitly: the checked-in SuperNeo backend is verified-leaf aggregation, not a witness-sound recursive backend, so backend work is milestone one.
- [x] (2026-04-12 23:34Z) Fixed the root-only soundness hole in the theorem note by introducing the recursive proof-visible tuple `Y_rec(B) = (Y_sem(B), Sigma_tree(T_0), Sigma_tree(T_n))`, so consensus can bind the exact append-state frontier/history with only `96` extra bytes.
- [x] (2026-04-12 23:34Z) Fixed the backend construction note to use Poseidon2 field statement commitments and recursive Fiat-Shamir internally instead of the current BLAKE3 `statement_digest` surface.
- [x] (2026-04-12 23:34Z) Made the missing backend claim stricter: the current backend is not only non-recursive, it also pushes relation satisfaction into surrounding Rust witness-reconstruction logic instead of proving it in a witness-sound verifier.
- [x] (2026-04-12 23:58Z) Fixed the product boundary in the theorem note: the recursive block proof replaces only the current linear `receipt_root` block artifact and explicitly consumes the ordered verified tx-leaf stream already produced by the external tx-artifact verifier.
- [x] (2026-04-12 23:58Z) Added the constant-size verified-receipt commitment `C_receipt(B)` and threaded its Poseidon2 sponge state through the recursive state machine, raising the recursive proof-visible tuple from `436` to `484` bytes while preserving the exact live semantic tuple.
- [x] (2026-04-12 23:59Z) Fixed the exact verified-leaf binding hole by adding `C_leaf(B)`, threading `lambda_i` through the recursive state machine, updating the recursive proof-visible tuple to carry both `C_leaf(B)` and `C_receipt(B)`, and raising that tuple to `532` bytes.
- [x] (2026-04-12 23:59Z) Replaced the fake relaxed-`C_e` accumulator sketch with a backend note that at least named the missing recursive object instead of hiding it.
- [x] (2026-04-13 05:12Z) Rebuilt Section 4.2 around a real parent-satisfiability invariant instead of the fake affine-system fold.
- [x] (2026-04-13 06:03Z) Replaced the custom CCS-to-ME sketch with the actual hard-step cryptography: exact `CCCS_step(Q_i)` claims, running `LCCCS_step(Q_pref[i])` accumulators, `Pi_CCS` linearization, `Pi_RLC` folding, and `Pi_DEC` normalization on the running lattice instance-witness pair.
- [x] (2026-04-13 05:12Z) Replaced the dead root-accumulator / checked-fold story with a unary accumulation transcript `T_acc[0,n]` ending in a terminal low-norm accumulator `A_n` plus one constant-size decider proof `pi_dec[0,n]`.
- [x] (2026-04-13 05:26Z) Synced the blackboard and ExecPlan to the corrected `CCCS_step -> Reduce_step_to_me -> Fold_me -> Normalize_me -> pi_dec` construction so the companion artifacts stop contradicting the theorem note.
- [x] (2026-04-13 06:44Z) Removed the remaining seal-layer fixed point from the theorem note: the shipped block artifact is now `(Header_dec_step(v*, Q_pref[n]), A_n, pi_dec[0,n])` plus `Y_rec(B)`, and the outer verifier reconstructs `Q_pref[n]` from deterministic public replay instead of relying on a second wrapper proof.
- [x] (2026-04-13 07:11Z) Fixed the remaining structural gaps in the theorem note: `A_0` is now a canonical same-family `LCCCS_step(Q_pref[0])` initializer rather than a different base relation, `Header_dec_step` now binds the decider profile plus canonical init-accumulator digest, and public replay computes `U_n` via `SparseSetRoot(Set(N_pub(B)))` after an explicit duplicate check.
- [x] (2026-04-13 07:32Z) Tightened the recursive carrier specification so the step relation now explicitly enforces `segment_len = 1`, the hard step binds full `LCCCS_step` source instances through `DigestLCCCS_step(...)` and a field-native `DigestProofCCS_step(...)`, and the bootstrap object `A_0` is written as the explicit neutral running instance instead of an opaque backend constant blob.
- [x] (2026-04-13 07:49Z) Closed the remaining typed-instance/spec ambiguities: `LCCCS_step(Q_pref)` is now defined as a real relation whose statement slot must equal `mu_step(Q_pref)`, prefix composition is an explicit `ComposeCheck(...)` predicate carried inside `Pi_RLC`, and the recursive Fiat-Shamir layer now uses one canonical little-endian byte-to-field encoding for all absorbed byte objects.
- [x] (2026-04-13 08:05Z) Corrected the cryptographic core again: the running `RLCCCS` carrier now explicitly includes `x = public_inputs(Q_pref)` and uses `z = (w, u, x)` in the evaluation equations, the base accumulator `A_0` now derives its `v_j` values from that exact carrier instead of zeroing them out, and the recursive Fiat-Shamir encoding now uses injective 32-bit chunk packing rather than invalid 64-bit Goldilocks limb casting.
- [x] (2026-04-13 03:18Z) Closed the remaining carrier/transcript mismatches against HyperNova itself: exact `CCCS_step(Q_i)` now carries `x_i = public_inputs(Q_i)` with the same common carrier layout `z = (w, scalar, x)` used by `RLCCCS_step`, the note now names `RLCCCS_step(...)` as the actual carrier relation instead of treating `LCCCS_step(Q_pref)` as a tagged tuple, `Fold_me` now takes the target prefix summary `Q_pref[i]` explicitly, and theorem assumptions now bind the full canonical encoding layer (`enc_vk`, `enc_security_tuple`, `enc_commit_digest`, `enc_proof_ccs`) used by recursive Fiat-Shamir.
- [x] (2026-04-13 03:18Z) Tightened the reduction transcript itself: `Pi_CCS` now takes the exact committed step claim `u_i = CCCS_step(Q_i)` explicitly rather than relying on implicit witness reconstruction, and the private unary accumulation transcript `T_acc[0,n]` now carries `u_i` in each round alongside `Q_i`, `B_i`, `H_i`, and `A_i`.
- [x] (2026-04-13 03:18Z) Made the randomized lattice commitment story explicit instead of cheating by omission: exact and running committed claims now carry opening randomness, the canonical initializer fixes `rho_0^acc = 0^{opening_randomness_bits}` so `A_0` stays deterministic, and the private accumulation transcript now includes the exact and running opening randomness needed for the committed relations it claims to close.
- [x] (2026-04-13 03:18Z) Closed the remaining backend-interface gaps in the design note: `Pi_CCS` now explicitly consumes the exact commitment opening and is verified under the recomputed transcript `chi_i = chi_step(Q_i, C_i)`, `Pi_RLC` and `Pi_DEC` now explicitly thread the private witness/opening pairs they consume and produce, and `InitAccumulator_step` now states the actual left-identity law needed for the first fold rather than only claiming that `A_0` is a valid empty-prefix carrier.
- [x] (2026-04-13 03:18Z) Closed the last lattice-line completeness gap in the design note by defining the temporary post-fold message class `M_hi(v*)` explicitly, stating that `Pi_RLC` outputs a running witness/opening pair in that class, and stating that `Pi_DEC` is the exact reduction back from `M_hi(v*)` into the bounded live class `M_low(v*)`.
- [ ] Implement a witness-sound recursive SuperNeo backend that can prove fixed-shape CCS relations without exposing `expected_packed` to the verifier, can linearize exact `CCCS_step(Q_i)` claims, can fold one running `LCCCS_step(Q_pref[i - 1])` instance with one new temporary linearized step instance via `Pi_RLC`, can normalize the running high-norm lattice instance back into the bounded message class via `Pi_DEC`, and can close the hidden unary accumulation transcript with a constant-size decider.
- [ ] Implement `BlockStepV1`, the hidden accumulator/decider path, and the terminal accumulator-plus-decider artifact on top of that strengthened backend while preserving the exact current semantic tuple and adding only the constant-size verified-leaf commitment, verified-receipt commitment, and two append-state digests required for soundness.
- [ ] Replace the current linear block commitment/nullifier public-input surface with the recursive `(Header_dec_step, A_n, pi_dec, Y_rec)` path and add proof-length equality tests across different block sizes.

## Surprises & Discoveries

- Observation: the current SuperNeo backend is not a generic hidden-witness proof system.
  Evidence: [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs) defines `verify_leaf(..., expected_packed, proof)` and `fold_pair` / `verify_fold` only over deterministic `FoldedInstance` digests; [docs/crypto/native_backend_verified_aggregation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_verified_aggregation.md) documents the shipped object as verified-leaf aggregation rather than CCS knowledge soundness.

- Observation: the recursive note’s earlier `D_tree` / `D_state` BLAKE3 story was wrong for a SuperNeo construction.
  Evidence: the recursive arithmetic has no BLAKE3 gadget or arithmetization path in the repo, while [circuits/transaction-core/src/hashing_pq.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/hashing_pq.rs) already provides the field-native Poseidon2 hashing surface needed for internal state binding.

- Observation: the recursive path cannot quietly redefine the public block tuple.
  Evidence: [circuits/block/src/p3_commitment_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block/src/p3_commitment_air.rs) and [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs) already bind `tx_statements_commitment`, the start and end shielded roots, the start and end kernel roots, `nullifier_root`, `da_root`, and `tx_count` into the live verification flow.

- Observation: the current public `nullifier_root` semantic is BLAKE3 over the sorted unique non-zero nullifier list, not a sparse-tree root.
  Evidence: [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L1768) and [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs#L4111) both recompute it that way.

- Observation: preserving only start/end roots is too weak for recursive block soundness.
  Evidence: append correctness depends on the exact frontier plus leaf count, and anchor admissibility depends on the bounded accepted-root history in [consensus/src/commitment_tree.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/commitment_tree.rs#L72).

- Observation: the current `StatementEncoding` byte digest is unsuitable as the recursive verifier transcript handle.
  Evidence: [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs#L54) carries `statement_digest`, but [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md#L118) explicitly requires an in-field hash for recursive verifier transcripts.

- Observation: the recursive block proof must bind the ordered verified receipt stream, not only the ordered statement-hash list.
  Evidence: the live product path verifies tx artifacts first and then verifies the block artifact against that exact ordered receipt stream in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L1537); dropping that binding would silently weaken the current truth surface.

- Observation: binding only the ordered verified receipt stream is still too weak; the recursive witness must also bind the exact ordered verified-leaf payload `(R_i, V_i, Xi_i)`.
  Evidence: the live `TxLeafPublicRelation` verifier in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L1904) checks receipt-to-tx/stark consistency before block verification begins, so a recursive block proof that only commits to `R_i` would underbind the product's actual tx-artifact truth surface.

## Decision Log

- Decision: preserve the current semantic block tuple exactly on the recursive path, but allow one extra constant-size verified-leaf commitment, one extra constant-size verified-receipt commitment, and two extra constant-size append-state digests in the recursive proof-visible tuple.
  Rationale: changing `da_root`, kernel-root, nullifier-root, or state-root semantics would turn a proof-format migration into a broader consensus redesign, but roots alone do not bind the exact frontier/history state needed for anchor-membership soundness and statement hashes/receipts alone do not bind the exact ordered verified-leaf payload the current product already checks.
  Date/Author: 2026-04-12 / Codex

- Decision: use Poseidon2 for internal recursive state commitments and the internal sparse nullifier set, while keeping BLAKE3 only for current public semantics and SuperNeo statement digests outside arithmetic.
  Rationale: that is the only honest hash boundary supported by the checked-in code today.
  Date/Author: 2026-04-12 / Codex

- Decision: the strengthened recursive backend must introduce field-native statement commitments and recursive Fiat-Shamir, not reuse the current byte-oriented `statement_digest` / BLAKE3 transcript surface.
  Rationale: a recursive verifier over Goldilocks cannot honestly depend on BLAKE3 digest recomputation without a BLAKE3 arithmetization, and the repo explicitly calls for in-field recursive transcripts.
  Date/Author: 2026-04-12 / Codex

- Decision: treat the current checked-in SuperNeo backend as insufficient and make backend work the first implementation milestone.
  Rationale: a plan that starts with `BlockSegmentV1` before replacing `verify_leaf(..., expected_packed, ...)` with a witness-sound recursive proof system is reward hacking.
  Date/Author: 2026-04-12 / Codex

- Decision: use one fixed one-transaction step relation plus a hidden SuperNeo accumulator/decider, not a self-referential segment-proof tree.
  Rationale: the sequential sponges `tau` and `eta` are carried inside constant-size hidden boundary state, so arbitrary block length can come from private accumulation over fixed-width summaries instead of embedding child proofs into the same CCS relation. That removes the proof-size fixed point and avoids any fake `N_max` cap.
  Date/Author: 2026-04-12 / Codex

## Outcomes & Retrospective

The design is now materially more honest than the earlier sketch. The note no longer hides behind a fake public tuple, no longer pretends BLAKE3 is available inside recursion, no longer leaves the append-state frontier/history underbound, no longer drops either the verified-leaf binding or the verified-receipt binding that the live product already enforces, and no longer implies the current SuperNeo backend is "basically enough." The latest correction also removes the mathematically false affine-system fold law and replaces it with the actual paper object: `CCCS_step -> LCCCS_step -> Pi_RLC -> Pi_DEC` on the active lattice commitment module. The remaining gap is still large: no backend code has been written, and the current repo still ships only the native `tx_leaf -> receipt_root` verified-leaf aggregation lane.

## Context and Orientation

The current shipped product path for non-empty shielded blocks is documented in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md) and [docs/crypto/native_backend_verified_aggregation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_verified_aggregation.md). A `tx_leaf` artifact proves one native transaction validity receipt, and a `receipt_root` artifact replays tx-leaf verification and deterministic fold recomputation over those verified leaves. That object is not a constant-size recursive block proof.

The current block commitment proof in [circuits/block/src/p3_commitment_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block/src/p3_commitment_air.rs) has a constant-size fixed header plus linear nullifier and sorted-nullifier vectors in its public inputs. Consensus verifies those public values in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs), recomputing `tx_statements_commitment`, state roots, kernel roots, `nullifier_root`, and `da_root` from the block body and parent state.

The current SuperNeo backend in [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs) and [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) is not yet a witness-sound recursive backend. It requires `expected_packed` at verification time, only folds deterministic digests, and relies on surrounding Rust replay logic to enforce relation satisfaction. That is why the first milestone must modify the backend rather than block-proof plumbing.

The design target lives in [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md). That note defines the invariant, the exact semantic tuple `Y_sem(B)`, the recursive proof-visible tuple `Y_rec(B)`, the external verified-leaf stream boundary, the constant-size verified-leaf commitment `C_leaf(B)`, the constant-size receipt commitment `C_receipt(B)`, the Poseidon2-only internal recursive state digests, the internal sparse nullifier set, the missing SuperNeo hidden-witness backend, the fixed `BlockStepRelation_v*`, and the corrected recursive backend stack:

- exact committed CCS step claims `CCCS_step(Q_i)`;
- running linearized committed CCS accumulators `LCCCS_step(Q_pref[i])`;
- a `Pi_CCS` linearization step `Reduce_step_to_me`;
- a `Pi_RLC` fold `Fold_me` from one running `LCCCS` instance and one new temporary linearized step instance to the next running instance;
- a `Pi_DEC` normalization step `Normalize_me` on the running lattice instance-witness pair;
- a constant-size decider over the hidden unary accumulation transcript `T_acc[0,n]`.

## Plan of Work

Start in the SuperNeo backend, not in consensus.

First, extend `circuits/superneo-core/src/lib.rs` with a witness-sound recursive proof interface. The final backend API must allow a verifier to check a fixed-shape CCS relation from public statement data plus proof bytes, without receiving `expected_packed`. It must introduce field-native statement commitments and a field-native Fiat-Shamir transcript, not reuse the current byte-oriented `statement_digest` path. It must also provide:

- an exact committed CCS step-claim object;
- a `CCCS` proof API for one exact hidden-witness step claim;
- a running `LCCCS` accumulator carrier;
- a `Pi_CCS` linearization API;
- a `Pi_RLC` fold API from one running `LCCCS` instance and one new temporary linearized step instance to the next running instance;
- a `Pi_DEC` normalization proof API that restores the fixed low-norm running message class without changing semantics;
- a final decider proof over the hidden unary accumulation transcript.

This may require a new backend trait or parallel backend family rather than mutating the existing verified-leaf API in place.

Second, implement the strengthened backend in `circuits/superneo-backend-lattice/src/lib.rs` or a sibling backend crate. The key behavior to demonstrate is not performance; it is witness-soundness plus recursive composability for one fixed-shape relation. Concretely, this milestone must add the missing SuperNeo layers the current backend does not have:

- one exact hidden-witness `CCCS_step(Q)` proof for a fixed relation;
- one running `LCCCS_step(Q_pref[i])` accumulator over the active pay-per-bit Ajtai commitment module;
- one sound `Pi_CCS` linearization from an exact step claim to a temporary linearized step instance;
- one sound `Pi_RLC` fold from the previous running `LCCCS` instance and the new temporary linearized step instance to the next running high-norm instance;
- one `Pi_DEC` normalization proof that brings the running high-norm instance back into the bounded message class expected by the next accumulator state;
- one final constant-size decider over the hidden unary accumulation transcript `T_acc[0,n]`.

A toy relation that proves a hidden witness satisfies a simple arithmetic identity is acceptable as the first proof-of-concept, but the verifier must not receive the witness itself.

Third, build the block-recursion crate. Create `circuits/block-recursion/src/lib.rs` with the state types from the design note: the raw recursive state, the Poseidon2 internal state digests, the verified-leaf sponge, the receipt sponge, the internal sparse nullifier set, the fixed one-transaction `BlockStepRelation_v*`, the hidden prefix accumulator `A_i`, and the terminal accumulator-plus-decider artifact. The step relation must consume one externally verified tx-leaf record, absorb the exact canonical leaf payload into `lambda`, absorb the canonical receipt into `eta`, absorb the canonical statement hash into `tau`, update the append-only tree state, update the internal nullifier set, and enforce `i_out = i_in + 1`. The final artifact must ship the exact current semantic tuple plus the constant-size verified-leaf commitment `C_leaf(B)`, the constant-size receipt commitment `C_receipt(B)`, and the two constant-size append-state digests `Sigma_tree(T_0)` and `Sigma_tree(T_n)` required to bind the exact live truth surface, together with the terminal accumulator `A_n` and the decider proof `pi_dec[0,n]` that closes the full unary accumulation transcript `T_acc[0,n]`.

Fourth, integrate a new recursive block-proof kind into consensus and authoring. `consensus/src/types.rs`, `consensus/src/proof.rs`, `node/src/substrate/service.rs`, and any runtime manifest or RPC surfaces must accept a new constant-size recursive proof kind alongside the current `receipt_root` lane. On that new path, consensus must reconstruct `Q_pref[n]` from deterministic public replay, rebuild `U_n` with `SparseSetRoot(Set(N_pub(B)))` after an explicit duplicate check, verify `(Header_dec_step, A_n, pi_dec[0,n])` directly against the decider profile bound in `Header_dec_step`, and then perform the same deterministic public recomputations it performs today for statement commitment, state roots, kernel roots, `nullifier_root`, and `da_root`.

Fifth, add acceptance tests. One test must prove the exact hard invariant by generating recursive block proofs for at least two different transaction counts and asserting equality of serialized proof length. Another must tamper with one coordinate of the recursive proof-visible tuple and require verification failure. Another must ensure no serialized recursive block artifact contains legacy linear payload fields.

## Concrete Steps

Work from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Keep the design artifacts current:

       edit docs/crypto/constant_recursive_block_proof.md
       edit docs/assets/constant-recursive-block-proof-blackboards.svg
       edit .agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md

2. Extend the backend interface:

       edit circuits/superneo-core/src/lib.rs
       edit circuits/superneo-backend-lattice/src/lib.rs

   Expected result: a new witness-sound recursive proof API exists beside or above the current verified-leaf API.

3. Prove the backend change on a toy relation before touching block logic:

       cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture

   Expected result: one test shows verification succeeds on the correct witness and fails when the witness changes, without passing the witness itself to the verifier.

4. Create the block recursion crate and wire the state machine:

       cargo new circuits/block-recursion --lib
       edit circuits/block-recursion/Cargo.toml
       edit circuits/block-recursion/src/lib.rs

5. Integrate the recursive proof kind into consensus and node authoring:

       edit consensus/src/types.rs
       edit consensus/src/proof.rs
       edit node/src/substrate/service.rs

6. Run focused validation:

       cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture
       cargo test -p block-recursion -- --nocapture
       cargo test -p consensus recursive_block -- --nocapture
       cargo test -p hegemon-node recursive_block -- --nocapture

7. Run the proof-size invariant test:

       cargo test -p block-recursion proof_bytes_constant_across_tx_counts -- --nocapture

   Expected result: the printed serialized proof length is identical across the tested transaction counts, and the serialized artifact does not contain any legacy linear payload surface.

## Validation and Acceptance

Acceptance is binary.

The feature succeeds only if all of the following are true:

1. Two recursive block proofs for different transaction counts have identical serialized length.
2. The recursive path preserves the exact current semantic tuple and adds only one constant-size verified-leaf commitment, one constant-size verified-receipt commitment, and the two constant-size append-state digests needed to bind the exact live truth surface.
3. The recursive artifact contains no per-transaction proof bytes, per-transaction public inputs, representative child proofs, nullifier vectors, sorted-nullifier vectors, or `receipt_root` record lists.
4. The recursive core uses field-native Poseidon2 internal state binding, field-native recursive Fiat-Shamir, and an internal Poseidon sparse nullifier set; it does not depend on an unimplemented in-circuit BLAKE3 gadget.
5. Consensus recomputes the ordered verified-leaf commitment, the ordered receipt commitment, `tx_statements_commitment`, the exact append-state transition, the shielded state roots, kernel roots, `nullifier_root`, and `da_root` and rejects any mismatch on the recursive path.
6. The backend used by the recursive path is witness-sound, does not require the verifier to receive `expected_packed`, and does not push relation satisfiability back out into surrounding Rust replay logic.

At minimum, run:

    cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture
    cargo test -p block-recursion
    cargo test -p consensus recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block -- --nocapture

and one explicit equality-of-proof-length test:

    cargo test -p block-recursion proof_bytes_constant_across_tx_counts -- --nocapture

## Idempotence and Recovery

All design-document edits in this plan are additive and safe to repeat. Backend experimentation must land behind a new recursive proof API or feature gate so the current native `receipt_root` product path remains intact until the recursive path is real. If the backend milestone fails, stop there, record the blocker in this plan, and leave the recursive proof kind disabled. Do not rename the fallback as "shipped."

## Artifacts and Notes

The three repo facts that force this plan order are:

    circuits/superneo-core/src/lib.rs:
      verify_leaf(..., expected_packed, proof)
      fold_pair / verify_fold over FoldedInstance digests

    circuits/block/src/p3_commitment_air.rs:
      CommitmentBlockPublicInputsP3 serializes nullifiers: Vec<[Felt; 6]>
      CommitmentBlockPublicInputsP3 serializes sorted_nullifiers: Vec<[Felt; 6]>

    consensus/src/proof.rs:
      recomputes tx_statements_commitment, roots, kernel roots, nullifier_root, da_root

and the design consequence is:

    current SuperNeo is verified-leaf aggregation, not recursive hidden-witness proof
    current root-only block tuple would underbind frontier/history state
    current block commitment proof is not constant-size
    a real recursive block proof needs backend work first, must preserve the live semantic tuple, and must use a fixed step relation plus hidden accumulator/decider rather than self-referential segment proofs

## Interfaces and Dependencies

At the end of the first backend milestone, the repository must contain a new recursive proof interface in `circuits/superneo-core/src/lib.rs` with stable names and behavior equivalent to:

    pub trait RecursiveBackend<F> {
        type ProverKey;
        type VerifierKey;
        type Proof;
        type StatementCommitment;

        fn prove_relation(
            &self,
            pk: &Self::ProverKey,
            relation_id: &RelationId,
            statement: &RecursiveStatementEncoding<F>,
            witness: &[F],
        ) -> anyhow::Result<Self::Proof>;

        fn verify_relation(
            &self,
            vk: &Self::VerifierKey,
            relation_id: &RelationId,
            statement: &RecursiveStatementEncoding<F>,
            proof: &Self::Proof,
        ) -> anyhow::Result<()>;
    }

    pub struct RecursiveStatementEncoding<F> {
        pub public_inputs: Vec<F>,
        pub statement_commitment: [F; 6],
        pub external_statement_digest: Option<[u8; 48]>,
    }

At the end of the first block-recursion milestone, the repository must contain `circuits/block-recursion/src/lib.rs` with stable names and behavior equivalent to:

    pub struct BlockRecursiveStateV1 { ... }
    pub struct BlockStepPublicV1 { ... }
    pub struct BlockAccumulatorArtifactV1 { ... }
    pub fn prove_block_step_v1(...) -> Result<Vec<u8>, BlockRecursionError>
    pub fn prove_block_recursive_v1(...) -> Result<BlockAccumulatorArtifactV1, BlockRecursionError>
    pub fn verify_block_recursive_v1(...) -> Result<BlockStepPublicV1, BlockRecursionError>

The final recursive path must also add one new proof artifact kind in consensus/runtime plumbing and one equality-of-length invariant test.

Revision note (2026-04-13): rewritten again after hostile review to remove both the false affine-system fold law and the later seal-layer fixed point. The plan now preserves the current semantic tuple exactly while adding one constant-size verified-leaf commitment, one constant-size verified-receipt commitment, and two constant-size append-state digests to the recursive proof-visible tuple, uses Poseidon2 for internal recursion and recursive Fiat-Shamir, explicitly keeps tx-artifact verification outside the recursive block proof, replaces the dead custom accumulator sketch with the actual paper line `CCCS_step -> LCCCS_step -> Pi_CCS -> Pi_RLC -> Pi_DEC`, makes `A_0` a canonical same-family initializer, binds the decider profile in the shipped artifact header, reconstructs `U_n` publicly via `SparseSetRoot` after a duplicate check, and ships the terminal accumulator-plus-decider artifact directly instead of assuming a second wrapper proof.
