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
- [x] (2026-04-13 03:18Z) Added the final anti-cheat wire guardrails: `Header_dec_step` now binds the canonical accumulator/decider serializer digests plus exact terminal width constants, `VerifyBlockRecursive` now requires exact-consumption decoding with no trailing bytes, and the falsification criteria now treat variable-length terminal encodings or hidden sidecars as direct failures of the invariant.
- [x] (2026-04-13 04:00Z) Reworked the ExecPlan into an implementation blueprint by naming concrete crate boundaries, exact recursive backend trait surfaces, exact artifact/header structs, canonical serializer ownership, file-by-file edit targets, and milestone test names.
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

- Decision: implement recursion as a parallel trait family beside `Backend<F>` instead of mutating the shipped verified-leaf API in place.
  Rationale: the current product still depends on `prove_leaf` / `verify_leaf` and `fold_pair` / `verify_fold`; recursive objects have different statements, proofs, witnesses, openings, and verifier obligations, so a sibling interface avoids corrupting the current lane before the new lane is real.
  Date/Author: 2026-04-13 / Codex

- Decision: split the new `circuits/block-recursion` crate into explicit modules for state, statements, artifacts, public replay, relation wiring, prover, verifier, and tests.
  Rationale: the constant-size guarantee depends on typed relations, canonical serializers, and deterministic replay staying visibly separate. A monolithic file would make it too easy to hide a linear payload in “helper” code.
  Date/Author: 2026-04-13 / Codex

## Outcomes & Retrospective

The design is now materially more honest than the earlier sketch. The note no longer hides behind a fake public tuple, no longer pretends BLAKE3 is available inside recursion, no longer leaves the append-state frontier/history underbound, no longer drops either the verified-leaf binding or the verified-receipt binding that the live product already enforces, and no longer implies the current SuperNeo backend is "basically enough." The latest correction also removes the mathematically false affine-system fold law and replaces it with the actual paper object: `CCCS_step -> LCCCS_step -> Pi_CCS -> Pi_RLC -> Pi_DEC` on the active lattice commitment module. The remaining gap is implementation, not theorem prose. This revision closes the handoff gap by naming the exact crate boundaries, public Rust surfaces, serializer ownership, and milestone tests required to make the backend real.

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

Start in the SuperNeo backend, not in consensus. The first deliverable is not a block proof. It is a toy recursive backend that proves one hidden-witness fixed-shape relation without `expected_packed`. Until that exists, every later milestone is dead code.

Milestone 1 is the recursive interface layer in `circuits/superneo-core/src/lib.rs`. Add a parallel trait family rather than changing `Backend<F>`. The new family must name the exact committed claim, temporary linearized claim, running accumulator, high-norm temporary accumulator, normalization proof, and terminal decider proof as first-class typed objects. This crate owns only the generic recursive carriers, digests, and decider-profile serialization. It must not define the concrete block-level wire artifact; that belongs exclusively to `circuits/block-recursion/src/artifacts.rs`.

Milestone 2 is the lattice backend implementation in `circuits/superneo-backend-lattice/src/lib.rs`. Reuse `NativeBackendParams`, `BackendKey`, the live ring profile, the live opening-randomness rules, and the existing commitment-opening machinery. Do not invent a second commitment scheme. The work here is to lift those primitives into recursive proof objects: exact step proof, CCS linearization proof, typed fold proof, normalization proof, and terminal decider. The first real proof target is a toy relation where the verifier sees only public statement data and proof bytes. Once that toy path exists, the same API is promoted to the real `BlockStepRelation_v*`.

Milestone 3 is the canonical verified-leaf boundary in `circuits/superneo-hegemon/src/lib.rs`. Expose stable helpers that return the fixed recursive payload for one verified tx leaf, the canonical receipt limb encoding, the canonical tx-leaf witness payload, and the verifier-profile / statement-hash bindings already enforced by the live validator. This milestone prevents the future block-recursion crate from re-encoding tx-leaf data in a subtly different way.

Milestone 4 is the new `circuits/block-recursion` crate plus a workspace entry in the root [Cargo.toml](/Users/pldd/Projects/Reflexivity/Hegemon/Cargo.toml). Implement it as modules, not one giant file. `state.rs` owns the raw recursive state and Poseidon2 commitments. `statement.rs` owns `Q_i`, `Q_pref[i]`, `public_inputs`, and `ComposeCheck`. `artifacts.rs` is the sole owner of the wire contract: `HeaderDecStepV1`, `RecursiveBlockArtifactV1`, `BlockAccumulationTranscriptV1`, the canonical `ser_header_dec_step_v1`, `ser_recursive_block_artifact_v1`, `ser_block_accumulation_transcript_v1` functions, and the matching exact-consumption parsers. `public_replay.rs` owns deterministic replay from verified leaf records to `C_leaf`, `C_receipt`, `C_stmt`, `Sigma_tree(T_0)`, `Sigma_tree(T_n)`, `U_n`, `Y_sem`, and `Y_rec`. `relation.rs` owns the compiled `BlockStepRelation_v*` and assignment builder. `prover.rs` owns the recursion loop `CCCS_step -> Pi_CCS -> Pi_RLC -> Pi_DEC -> pi_dec`. `verifier.rs` owns `VerifyBlockRecursive`. No other crate is allowed to define an alternate on-wire recursive block artifact or alternate private transcript serializer for this path.

Milestone 5 is consensus and node integration. Add one explicit new proof kind in `consensus/src/types.rs` rather than hiding the recursive path under `Custom([u8; 16])`. Register a recursive block verifier in `consensus/src/proof.rs` through the existing `ArtifactVerifier` registry so the old `ReceiptRoot` lane stays intact. Then wire authoring and service code in `node/src/substrate/service.rs` and the existing prover RPC surface so the recursive artifact can be produced only behind an explicit feature gate or runtime switch.

Milestone 6 is hard acceptance. The implementation is not done when it compiles. It is done when proof bytes are identical across at least two block sizes, tampering any coordinate of `Y_rec(B)` or the decider header fails verification, the artifact parser rejects trailing bytes and alternate-width encodings, and a dev node imports a block carrying the recursive proof kind without changing the live semantic tuple.

## Concrete Steps

Work from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Keep the design artifacts current:

       edit docs/crypto/constant_recursive_block_proof.md
       edit docs/assets/constant-recursive-block-proof-blackboards.svg
       edit .agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md

2. Add the recursive backend types in `circuits/superneo-core/src/lib.rs`:

       edit circuits/superneo-core/src/lib.rs

   Add these stable public objects before any backend implementation:

       pub struct RecursiveStatementEncoding<F> { ... }
       pub struct CccsClaim<C, F> { ... }
       pub struct LcccsInstance<C, F> { ... }
       pub struct RecursiveDeciderProfile { ... }
       pub struct CanonicalDeciderTranscript { ... }

       pub trait RecursiveBackend<F> {
           type ProverKey;
           type VerifierKey;
           type PackedWitness;
           type Commitment;
           type CommitmentOpening;
           type CccsProof;
           type LinearizationProof;
           type FoldProof;
           type NormalizationProof;
           type DeciderProof;

           fn setup_recursive(
               &self,
               security: &SecurityParams,
               shape: &CcsShape<F>,
           ) -> Result<(Self::ProverKey, Self::VerifierKey)>;

           fn prove_cccs(
               &self,
               pk: &Self::ProverKey,
               relation_id: &RelationId,
               statement: &RecursiveStatementEncoding<F>,
               packed: &Self::PackedWitness,
               opening: &Self::CommitmentOpening,
           ) -> Result<(CccsClaim<Self::Commitment, F>, Self::CccsProof)>;

           fn verify_cccs(
               &self,
               vk: &Self::VerifierKey,
               claim: &CccsClaim<Self::Commitment, F>,
               proof: &Self::CccsProof,
           ) -> Result<()>;

           fn reduce_cccs(
               &self,
               pk: &Self::ProverKey,
               claim: &CccsClaim<Self::Commitment, F>,
               packed: &Self::PackedWitness,
               opening: &Self::CommitmentOpening,
           ) -> Result<(LcccsInstance<Self::Commitment, F>, Self::LinearizationProof)>;

           fn verify_linearized(
               &self,
               vk: &Self::VerifierKey,
               claim: &CccsClaim<Self::Commitment, F>,
               linearized: &LcccsInstance<Self::Commitment, F>,
               proof: &Self::LinearizationProof,
           ) -> Result<()>;

           fn fold_lcccs(
               &self,
               pk: &Self::ProverKey,
               previous_prefix: &RecursiveStatementEncoding<F>,
               left: &LcccsInstance<Self::Commitment, F>,
               step_statement: &RecursiveStatementEncoding<F>,
               right: &LcccsInstance<Self::Commitment, F>,
               linearization_proof: &Self::LinearizationProof,
               target_prefix: &RecursiveStatementEncoding<F>,
               left_packed: &Self::PackedWitness,
               left_opening: &Self::CommitmentOpening,
               right_packed: &Self::PackedWitness,
               right_opening: &Self::CommitmentOpening,
           ) -> Result<(
               LcccsInstance<Self::Commitment, F>,
               Self::PackedWitness,
               Self::CommitmentOpening,
               Self::FoldProof,
           )>;

           // `fold_lcccs` must derive the fold challenge from the exact tuple
           // `(previous_prefix, step_statement, target_prefix, DigestLCCCS_step(left),
           //   DigestLCCCS_step(right), DigestProofCCS_step(linearization_proof))`
           // and must reject unless `ComposeCheck(previous_prefix, step_statement, target_prefix) = 1`.

           fn verify_fold_lcccs(
               &self,
               vk: &Self::VerifierKey,
               previous_prefix: &RecursiveStatementEncoding<F>,
               left: &LcccsInstance<Self::Commitment, F>,
               step_statement: &RecursiveStatementEncoding<F>,
               right: &LcccsInstance<Self::Commitment, F>,
               linearization_proof: &Self::LinearizationProof,
               parent: &LcccsInstance<Self::Commitment, F>,
               target_prefix: &RecursiveStatementEncoding<F>,
               proof: &Self::FoldProof,
           ) -> Result<()>;

           fn normalize_lcccs(
               &self,
               pk: &Self::ProverKey,
               statement: &RecursiveStatementEncoding<F>,
               high_norm: &LcccsInstance<Self::Commitment, F>,
               high_norm_packed: &Self::PackedWitness,
               high_norm_opening: &Self::CommitmentOpening,
           ) -> Result<(
               LcccsInstance<Self::Commitment, F>,
               Self::PackedWitness,
               Self::CommitmentOpening,
               Self::NormalizationProof,
           )>;

           fn verify_normalized(
               &self,
               vk: &Self::VerifierKey,
               statement: &RecursiveStatementEncoding<F>,
               high_norm: &LcccsInstance<Self::Commitment, F>,
               normalized: &LcccsInstance<Self::Commitment, F>,
               proof: &Self::NormalizationProof,
           ) -> Result<()>;

           fn prove_decider(
               &self,
               pk: &Self::ProverKey,
               decider_profile: &RecursiveDeciderProfile,
               statement: &RecursiveStatementEncoding<F>,
               terminal: &LcccsInstance<Self::Commitment, F>,
               transcript: &CanonicalDeciderTranscript,
           ) -> Result<Self::DeciderProof>;

           fn verify_decider(
               &self,
               vk: &Self::VerifierKey,
               decider_profile: &RecursiveDeciderProfile,
               statement: &RecursiveStatementEncoding<F>,
               terminal: &LcccsInstance<Self::Commitment, F>,
               proof: &Self::DeciderProof,
           ) -> Result<()>;
       }

       pub fn serialize_lcccs_instance<C, F>(...) -> Result<Vec<u8>>;
       pub fn deserialize_lcccs_instance<C, F>(...) -> Result<LcccsInstance<C, F>>;
       pub fn serialize_decider_profile(...) -> Result<Vec<u8>>;
       pub fn deserialize_decider_profile(...) -> Result<RecursiveDeciderProfile>;

   Expected result: the repo has a recursive proof API whose verifier never receives `expected_packed`.

3. Implement the toy recursive backend in `circuits/superneo-backend-lattice/src/lib.rs`:

       edit circuits/superneo-backend-lattice/src/lib.rs
       edit circuits/superneo-backend-lattice/Cargo.toml

       cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture
       cargo test -p superneo-backend-lattice recursive_toy_relation_rejects_wrong_witness -- --nocapture
       cargo test -p superneo-backend-lattice recursive_decider_rejects_tampered_profile -- --nocapture

   Expected result: one test verifies a hidden witness successfully, one rejects the wrong witness, and one rejects a decider/profile mismatch.

4. Expose canonical verified-leaf payload helpers:

       edit circuits/superneo-hegemon/src/lib.rs

   Add stable helpers with fixed-width outputs:

       pub struct RecursiveLeafPayloadV1 { ... }
       pub fn recursive_leaf_payload_v1(...) -> Result<RecursiveLeafPayloadV1>;
       pub fn recursive_leaf_payload_limbs_v1(...) -> Result<Vec<Goldilocks>>;
       pub fn recursive_receipt_limbs_v1(...) -> [Goldilocks; 24];
       pub fn recursive_statement_hash_v1(...) -> [u8; 48];

5. Create the block recursion crate and wire the state machine:

       edit Cargo.toml
       cargo new circuits/block-recursion --lib
       edit circuits/block-recursion/Cargo.toml
       edit circuits/block-recursion/src/lib.rs
       add circuits/block-recursion/src/state.rs
       add circuits/block-recursion/src/statement.rs
       add circuits/block-recursion/src/artifacts.rs
       add circuits/block-recursion/src/public_replay.rs
       add circuits/block-recursion/src/relation.rs
       add circuits/block-recursion/src/prover.rs
       add circuits/block-recursion/src/verifier.rs
       add circuits/block-recursion/src/tests.rs

   If `circuits/block-recursion` already exists, do not run `cargo new` again; keep the existing crate and edit the files in place. `lib.rs` should only re-export the stable public API. The public surface should include:

       pub struct BlockStepStatementV1 { ... }
       pub struct BlockPrefixStatementV1 { ... }
       pub struct RecursiveBlockPublicV1 { ... }
       pub struct HeaderDecStepV1 { ... }
       pub struct RecursiveBlockArtifactV1 { ... }
       pub struct BlockAccumulationTranscriptV1 { ... }
       pub enum BlockRecursionError { ... }
       pub fn prove_block_recursive_v1(...) -> Result<RecursiveBlockArtifactV1, BlockRecursionError>;
       pub fn verify_block_recursive_v1(...) -> Result<RecursiveBlockPublicV1, BlockRecursionError>;
       pub fn serialize_recursive_block_artifact_v1(...) -> Result<Vec<u8>, BlockRecursionError>;
       pub fn deserialize_recursive_block_artifact_v1(bytes: &[u8]) -> Result<RecursiveBlockArtifactV1, BlockRecursionError>;
       pub fn serialize_block_accumulation_transcript_v1(...) -> Result<CanonicalDeciderTranscript, BlockRecursionError>;
       pub fn public_replay_v1(...) -> Result<RecursiveBlockPublicV1, BlockRecursionError>;

   `artifacts.rs` is the canonical owner of the on-wire recursive block artifact and the private accumulation transcript. `circuits/superneo-core` may serialize generic `LcccsInstance` carriers and decider-profile objects, but it must not define a second wire artifact schema for the block path.

6. Integrate the recursive proof kind into consensus and node authoring:

       edit consensus/src/types.rs
       edit consensus/src/proof.rs
       edit node/src/substrate/service.rs
       edit node/src/substrate/rpc/prover.rs

   Add one explicit kind:

       ProofArtifactKind::RecursiveBlockV1

   Add a dedicated verifier-profile helper and one new `ArtifactVerifier` implementation that calls `block_recursion::verify_block_recursive_v1`.

7. Run focused validation:

       cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture
       cargo test -p superneo-backend-lattice recursive_toy_relation_rejects_wrong_witness -- --nocapture
       cargo test -p superneo-backend-lattice recursive_decider_rejects_tampered_profile -- --nocapture
       cargo test -p block-recursion public_replay_matches_consensus_tuple -- --nocapture
       cargo test -p block-recursion recursive_artifact_rejects_trailing_bytes -- --nocapture
       cargo test -p block-recursion recursive_artifact_rejects_legacy_linear_payload -- --nocapture
       cargo test -p block-recursion recursive_artifact_rejects_width_mismatch -- --nocapture
       cargo test -p block-recursion recursive_artifact_rejects_alternate_serializer_under_same_profile -- --nocapture
       cargo test -p consensus recursive_block -- --nocapture
       cargo test -p hegemon-node recursive_block -- --nocapture

8. Run the proof-size invariant test:

       cargo test -p block-recursion proof_bytes_constant_across_tx_counts -- --nocapture

   Expected result: the printed serialized proof length is identical across the tested transaction counts, the parser rejects trailing bytes, and the serialized artifact contains no legacy linear payload surface.

9. Run one end-to-end node smoke once the proof kind is wired:

       make setup
       make node
       HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

   Expected result: a dev block with the recursive proof kind imports and consensus logs no mismatch on `tx_statements_commitment`, state roots, kernel roots, `nullifier_root`, or `da_root`.

## Validation and Acceptance

Acceptance is binary.

The feature succeeds only if all of the following are true:

1. Two recursive block proofs for different transaction counts have identical serialized length.
2. `deserialize_recursive_block_artifact_v1` requires exact-consumption decoding and rejects trailing bytes, alternate serializers, and width mismatches under one fixed header/profile.
3. The recursive path preserves the exact current semantic tuple and adds only one constant-size verified-leaf commitment, one constant-size verified-receipt commitment, and the two constant-size append-state digests needed to bind the exact live truth surface.
4. The recursive artifact contains no per-transaction proof bytes, per-transaction public inputs, representative child proofs, nullifier vectors, sorted-nullifier vectors, or `receipt_root` record lists.
5. The recursive core uses field-native Poseidon2 internal state binding, field-native recursive Fiat-Shamir, and an internal Poseidon sparse nullifier set; it does not depend on an unimplemented in-circuit BLAKE3 gadget.
6. Consensus recomputes the ordered verified-leaf commitment, the ordered receipt commitment, `tx_statements_commitment`, the exact append-state transition, the shielded state roots, kernel roots, `nullifier_root`, and `da_root` and rejects any mismatch on the recursive path.
7. The backend used by the recursive path is witness-sound, does not require the verifier to receive `expected_packed`, and does not push relation satisfiability back out into surrounding Rust replay logic.
8. One dev-node smoke run imports a recursive block artifact successfully without making the recursive path the default product lane.

At minimum, run:

    cargo test -p superneo-backend-lattice recursive_toy_relation -- --nocapture
    cargo test -p superneo-backend-lattice recursive_toy_relation_rejects_wrong_witness -- --nocapture
    cargo test -p superneo-backend-lattice recursive_decider_rejects_tampered_profile -- --nocapture
    cargo test -p block-recursion public_replay_matches_consensus_tuple -- --nocapture
    cargo test -p block-recursion recursive_artifact_rejects_trailing_bytes -- --nocapture
    cargo test -p block-recursion recursive_artifact_rejects_legacy_linear_payload -- --nocapture
    cargo test -p block-recursion recursive_artifact_rejects_width_mismatch -- --nocapture
    cargo test -p block-recursion recursive_artifact_rejects_alternate_serializer_under_same_profile -- --nocapture
    cargo test -p consensus recursive_block -- --nocapture
    cargo test -p hegemon-node recursive_block -- --nocapture

and one explicit equality-of-proof-length test:

    cargo test -p block-recursion proof_bytes_constant_across_tx_counts -- --nocapture

## Idempotence and Recovery

All design-document edits in this plan are additive and safe to repeat. Backend experimentation must land behind a new recursive proof API or feature gate so the current native `receipt_root` product path remains intact until the recursive path is real. Add `ProofArtifactKind::RecursiveBlockV1`, but do not make it the default kind until the dev-node smoke and constant-byte tests pass. If `circuits/block-recursion` already exists, skip `cargo new` and continue with the file edits. If the backend milestone fails, stop there, record the blocker in this plan, and leave the recursive proof kind disabled. Do not rename the fallback as "shipped." If the new crate is added to the workspace before it compiles, keep its public API behind `#[cfg(feature = "recursive-block-v1")]` or an equivalent cargo feature so the workspace can still be built incrementally.

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

    pub struct RecursiveStatementEncoding<F> {
        pub public_inputs: Vec<F>,
        pub statement_commitment: [F; 6],
        pub external_statement_digest: Option<[u8; 48]>,
    }

    pub struct CccsClaim<C, F> {
        pub relation_id: RelationId,
        pub shape_digest: ShapeDigest,
        pub statement: RecursiveStatementEncoding<F>,
        pub witness_commitment: C,
    }

    pub struct LcccsInstance<C, F> {
        pub relation_id: RelationId,
        pub shape_digest: ShapeDigest,
        pub statement: RecursiveStatementEncoding<F>,
        pub witness_commitment: C,
        pub relaxation_scalar: F,
        pub challenge_point: Vec<F>,
        pub evaluations: Vec<F>,
    }

    pub struct RecursiveDeciderProfile {
        pub decider_id: [u8; 32],
        pub decider_vk_digest: [u8; 32],
        pub decider_transcript_digest: [u8; 32],
        pub init_acc_digest: [u8; 32],
        pub acc_encoding_digest: [u8; 32],
        pub dec_encoding_digest: [u8; 32],
        pub acc_bytes: u32,
        pub dec_bytes: u32,
        pub artifact_bytes: u32,
    }

    pub struct CanonicalDeciderTranscript {
        pub transcript_digest: [u8; 48],
        pub transcript_bytes: Vec<u8>,
    }

    pub trait RecursiveBackend<F> {
        type ProverKey;
        type VerifierKey;
        type PackedWitness;
        type Commitment: Clone;
        type CommitmentOpening: Clone;
        type CccsProof: Clone;
        type LinearizationProof: Clone;
        type FoldProof: Clone;
        type NormalizationProof: Clone;
        type DeciderProof: Clone;

        fn setup_recursive(
            &self,
            security: &SecurityParams,
            shape: &CcsShape<F>,
        ) -> Result<(Self::ProverKey, Self::VerifierKey)>;

        fn prove_cccs(
            &self,
            pk: &Self::ProverKey,
            relation_id: &RelationId,
            statement: &RecursiveStatementEncoding<F>,
            packed: &Self::PackedWitness,
            opening: &Self::CommitmentOpening,
        ) -> Result<(CccsClaim<Self::Commitment, F>, Self::CccsProof)>;

        fn verify_cccs(
            &self,
            vk: &Self::VerifierKey,
            claim: &CccsClaim<Self::Commitment, F>,
            proof: &Self::CccsProof,
        ) -> Result<()>;

        fn reduce_cccs(
            &self,
            pk: &Self::ProverKey,
            claim: &CccsClaim<Self::Commitment, F>,
            packed: &Self::PackedWitness,
            opening: &Self::CommitmentOpening,
        ) -> Result<(LcccsInstance<Self::Commitment, F>, Self::LinearizationProof)>;

        fn verify_linearized(
            &self,
            vk: &Self::VerifierKey,
            claim: &CccsClaim<Self::Commitment, F>,
            linearized: &LcccsInstance<Self::Commitment, F>,
            proof: &Self::LinearizationProof,
        ) -> Result<()>;

        fn fold_lcccs(
            &self,
            pk: &Self::ProverKey,
            previous_prefix: &RecursiveStatementEncoding<F>,
            left: &LcccsInstance<Self::Commitment, F>,
            step_statement: &RecursiveStatementEncoding<F>,
            right: &LcccsInstance<Self::Commitment, F>,
            linearization_proof: &Self::LinearizationProof,
            target_prefix: &RecursiveStatementEncoding<F>,
            left_packed: &Self::PackedWitness,
            left_opening: &Self::CommitmentOpening,
            right_packed: &Self::PackedWitness,
            right_opening: &Self::CommitmentOpening,
        ) -> Result<(
            LcccsInstance<Self::Commitment, F>,
            Self::PackedWitness,
            Self::CommitmentOpening,
            Self::FoldProof,
        )>;

        fn verify_fold_lcccs(
            &self,
            vk: &Self::VerifierKey,
            previous_prefix: &RecursiveStatementEncoding<F>,
            left: &LcccsInstance<Self::Commitment, F>,
            step_statement: &RecursiveStatementEncoding<F>,
            right: &LcccsInstance<Self::Commitment, F>,
            linearization_proof: &Self::LinearizationProof,
            parent: &LcccsInstance<Self::Commitment, F>,
            target_prefix: &RecursiveStatementEncoding<F>,
            proof: &Self::FoldProof,
        ) -> Result<()>;

        fn normalize_lcccs(
            &self,
            pk: &Self::ProverKey,
            statement: &RecursiveStatementEncoding<F>,
            high_norm: &LcccsInstance<Self::Commitment, F>,
            high_norm_packed: &Self::PackedWitness,
            high_norm_opening: &Self::CommitmentOpening,
        ) -> Result<(
            LcccsInstance<Self::Commitment, F>,
            Self::PackedWitness,
            Self::CommitmentOpening,
            Self::NormalizationProof,
        )>;

        fn verify_normalized(
            &self,
            vk: &Self::VerifierKey,
            statement: &RecursiveStatementEncoding<F>,
            high_norm: &LcccsInstance<Self::Commitment, F>,
            normalized: &LcccsInstance<Self::Commitment, F>,
            proof: &Self::NormalizationProof,
        ) -> Result<()>;

        fn prove_decider(
            &self,
            pk: &Self::ProverKey,
            decider_profile: &RecursiveDeciderProfile,
            statement: &RecursiveStatementEncoding<F>,
            terminal: &LcccsInstance<Self::Commitment, F>,
            transcript: &CanonicalDeciderTranscript,
        ) -> Result<Self::DeciderProof>;

        fn verify_decider(
            &self,
            vk: &Self::VerifierKey,
            decider_profile: &RecursiveDeciderProfile,
            statement: &RecursiveStatementEncoding<F>,
            terminal: &LcccsInstance<Self::Commitment, F>,
            proof: &Self::DeciderProof,
        ) -> Result<()>;
    }

    pub fn serialize_lcccs_instance<C, F>(...) -> Result<Vec<u8>>;
    pub fn deserialize_lcccs_instance<C, F>(...) -> Result<LcccsInstance<C, F>>;
    pub fn serialize_decider_profile(...) -> Result<Vec<u8>>;
    pub fn deserialize_decider_profile(...) -> Result<RecursiveDeciderProfile>;

At the end of the second backend milestone, `circuits/superneo-backend-lattice/src/lib.rs` must contain:

    pub struct RecursiveLatticeProofBundle { ... }
    pub struct RecursiveLatticeDeciderProof { ... }
    pub fn recursive_backend_v2(params: NativeBackendParams) -> LatticeRecursiveBackend;

and unit tests with stable names:

    recursive_toy_relation
    recursive_toy_relation_rejects_wrong_witness
    recursive_decider_rejects_tampered_profile

At the end of the block-recursion milestone, the repository must contain `circuits/block-recursion/src/lib.rs` and sibling modules with stable names and behavior equivalent to:

    pub struct BlockStepStatementV1 { ... }
    pub struct BlockPrefixStatementV1 { ... }
    pub struct RecursiveBlockPublicV1 { ... }
    pub struct HeaderDecStepV1 { ... }
    pub struct RecursiveBlockArtifactV1 { ... }
    pub struct BlockAccumulationTranscriptV1 { ... }
    pub fn prove_block_recursive_v1(...) -> Result<RecursiveBlockArtifactV1, BlockRecursionError>;
    pub fn verify_block_recursive_v1(...) -> Result<RecursiveBlockPublicV1, BlockRecursionError>;
    pub fn serialize_recursive_block_artifact_v1(...) -> Result<Vec<u8>, BlockRecursionError>;
    pub fn deserialize_recursive_block_artifact_v1(bytes: &[u8]) -> Result<RecursiveBlockArtifactV1, BlockRecursionError>;
    pub fn serialize_block_accumulation_transcript_v1(...) -> Result<CanonicalDeciderTranscript, BlockRecursionError>;
    pub fn public_replay_v1(...) -> Result<RecursiveBlockPublicV1, BlockRecursionError>;

The final recursive path must also add:

    ProofArtifactKind::RecursiveBlockV1

in `consensus/src/types.rs`, one `ArtifactVerifier` implementation in `consensus/src/proof.rs`, one authoring path in `node/src/substrate/service.rs`, and the test names:

    public_replay_matches_consensus_tuple
    proof_bytes_constant_across_tx_counts
    recursive_artifact_rejects_trailing_bytes
    recursive_artifact_rejects_legacy_linear_payload
    recursive_artifact_rejects_width_mismatch
    recursive_artifact_rejects_alternate_serializer_under_same_profile

Revision note (2026-04-13): rewritten again to turn the theorem note into an implementation blueprint. This revision keeps the same invariant and recursive construction, but it now names the exact crate boundaries, exact Rust trait family, exact artifact shells, exact serializer ownership, exact consensus proof kind, and the minimum milestone tests required before implementation can claim the feature is real.
