# Ship A Constant-Size Recursive Smallwood Block Proof

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, a non-empty shielded block will carry one constant-size recursive block proof whose byte length does not depend on transaction count. A node operator will be able to import two non-empty shielded blocks with different numbers of transactions and observe that the shipped block-proof artifact has the same serialized length in both cases, while consensus still checks the exact same semantic block tuple it checks today: `tx_count`, `tx_statements_commitment`, the start and end shielded roots, the start and end kernel roots, `nullifier_root`, and `da_root`. The recursive proof-visible tuple is allowed only four extra 48-byte coordinates: `C_leaf`, `C_receipt`, `Sigma_tree(T_0)`, and `Sigma_tree(T_n)`.

The important correction in this plan is that the recursive object is no longer an assumed `CCCS/LCCCS/decider` backend. The implementation target is a direct Smallwood proof-carrying recursion line over two alternating recursion profiles, exactly as derived in [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md).

## Progress

- [x] (2026-04-13 19:05Z) Re-read `DESIGN.md`, `METHODS.md`, `docs/crypto/constant_recursive_block_proof.md`, `circuits/transaction/src/smallwood_engine.rs`, `circuits/transaction/src/smallwood_semantics.rs`, `circuits/superneo-hegemon/src/lib.rs`, and `consensus/src/proof.rs` to pin the current truth surface and the actual proving substrate already in tree.
- [x] (2026-04-13 19:11Z) Replaced the theorem note’s fake accumulator/decider construction with a direct Smallwood-native recursive derivation: one base proof `pi_0^A`, one exact one-step relation, two alternating recursive verifier profiles `A/B`, and one terminal recursive proof `pi_n^{tau(n),k_term(n)}`.
- [x] (2026-04-13 19:18Z) Rewrote this ExecPlan so it matches the new direct Smallwood derivation instead of the dead `CCCS/LCCCS/pi_dec` architecture.
- [ ] Implement the recursion-friendly Smallwood proof profiles `SmallwoodRecA_v1(v*)` and `SmallwoodRecB_v1(v*)` with Poseidon2 transcript/authentication and one fixed serializer `ser_sw_rec`.
- [ ] Implement the recursive block relations `Base_A_v*`, `Step_A_v*`, and `Step_B_v*`, plus the canonical recursive serializers `ser_artifact_rec = ser_header_rec_step(Header_rec_step(v*, tau(n), k_term(n), P_n)) || ser_sw_rec(pi_n^{tau(n),k_term(n)})` and `ser_pi_block = ser_artifact_rec || ser_y_rec`.
- [ ] Replace the current fake recursive plumbing with the real recursive artifact path in `circuits/block-recursion`, `consensus`, `node`, and `pallets/shielded-pool`.
- [ ] Validate constant-size behavior by importing non-empty shielded blocks of at least two different transaction counts and proving that `|ser_pi_block(B)|` is identical while the current semantic tuple remains unchanged.

## Surprises & Discoveries

- Observation: the only real non-Plonky3 proof substrate already checked in is the Smallwood tx-proof engine in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs).
  Evidence: the previously-added `superneo-backend-lattice` “recursive” lane still verifies by rebuilding commitments from explicit openings, while `smallwood_engine.rs` already contains the fixed-shape PIOP/PCS proof flow that can be made recursion-friendly by changing the transcript and authentication surface rather than inventing a second proof system.

- Observation: the old `block-recursion` and `superneo-backend-lattice` recursive scaffolding was designed around an accumulator/decider object that the theorem note no longer uses.
  Evidence: the current derivation ends with `Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})` and explicitly says “there is no accumulator object `A_n` and no separate decider proof `pi_dec[0,n]`.” Any implementation plan that still tells the engineer to build `A_n` and `pi_dec` is now wrong by construction.

- Observation: the recursive block proof does not replace per-transaction proof verification.
  Evidence: the theorem note’s verifier boundary still starts from the already externally verified tx-leaf stream `L(B)`. The recursive block proof replaces the current block-level `commitment proof + receipt_root` object, not the tx-artifact verifier.

- Observation: self-reference is avoided by alternating two recursion profiles, not by a hidden fixed-point theorem.
  Evidence: the new derivation uses `SmallwoodRecA_v1(v*)` to verify `B` and `SmallwoodRecB_v1(v*)` to verify `A`, with one shared fixed serializer length `L_rec(v*)`.

## Decision Log

- Decision: replace the old `CCCS/LCCCS/A_n/pi_dec` implementation target with direct Smallwood proof-carrying recursion.
  Rationale: the previous target was not actually derived in the note and encouraged fake backend code. The new theorem note derives a concrete object the repo can implement directly: a base Smallwood proof plus alternating recursive step proofs.
  Date/Author: 2026-04-13 / Codex

- Decision: keep the tx-artifact verifier outside the recursive block proof and bind its exact ordered output with `C_leaf` and `C_receipt`.
  Rationale: that preserves the current product boundary and avoids pretending the recursive block proof replaces the transaction prover.
  Date/Author: 2026-04-13 / Codex

- Decision: use Poseidon2 for recursive transcript/authentication and keep BLAKE3 only for existing external semantics.
  Rationale: the repo has no in-circuit BLAKE3 path for this recursion. The direct Smallwood recursive verifier must stay inside field arithmetic.
  Date/Author: 2026-04-13 / Codex

- Decision: the canonical shipped on-chain proof object is `Pi_block(B) = (Artifact_rec(B), Y_rec(B))`, with inner recursive artifact `Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})`.
  Rationale: the theorem note fixes the outer wire object as `ser_pi_block = ser_artifact_rec || ser_y_rec`. Treating only the inner recursive artifact as the shipped object would weaken the implementation handoff and re-open outer wire-contract drift.
  Date/Author: 2026-04-13 / Codex

- Decision: treat the previously-added fake recursive backend and its digest-attestation verifier as migration debt, not as a foundation to extend.
  Rationale: continuing to build on the fake layer invites more reward hacking. The correct path is to replace it with the directly-derived recursive Smallwood object.
  Date/Author: 2026-04-13 / Codex

## Outcomes & Retrospective

The repo now has a theorem note that names a real implementation target instead of an assumed backend family. The next risk is no longer “what is the intended recursive object?” It is straightforward engineering risk: replace the fake recursive scaffolding with the direct Smallwood recursion the note now specifies. The old plan was encouraging work on the wrong object. This revision fixes that, but no cryptographic code has been landed yet under this new plan.

## Context and Orientation

The current tx proof line lives in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs). That file contains the Smallwood prover and verifier used for `SmallwoodCandidate` transaction proofs. It is a fixed-shape row-polynomial proof system with a PIOP layer (polynomial interactive oracle proof) and a PCS layer (polynomial commitment scheme). Today it uses BLAKE3-derived transcript material and byte-oriented DECS authentication.

The current verified tx-leaf boundary lives in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). That crate already defines the canonical receipt encoding, the canonical tx public-view encoding, and the `TxLeafPublicRelation` seam that binds the receipt to the tx/stark public inputs. The recursive block proof must consume exactly that ordered verified stream, not a new private encoding.

The current recursive-proof-visible block semantics live in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs) and [docs/crypto/constant_recursive_block_proof.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/constant_recursive_block_proof.md). The semantic tuple `Y_sem(B)` stays unchanged. The recursive tuple `Y_rec(B)` adds only `C_leaf`, `C_receipt`, `Sigma_tree(T_0)`, and `Sigma_tree(T_n)`. The recursive verifier still recomputes `nullifier_root` and `da_root` outside the proof.

The existing `circuits/block-recursion` and `circuits/superneo-backend-lattice` code contains dead-end recursive scaffolding from the previous design. Treat that code as migration material to refactor or delete. Do not extend it as if the theorem still ends in an accumulator and a decider. The new theorem note ends in one terminal recursive Smallwood proof and one canonical recursive header.

In this plan, “recursive profile” means a recursion-friendly Smallwood proving profile with one fixed proof schema and one fixed serializer. “Alternating profiles” means profile `A` verifies profile `B` inside recursion and profile `B` verifies profile `A`. “Base relation” means the statement for the empty-prefix proof `pi_0^A`. “Step relation” means the statement for one exact verified-leaf transition plus one verification of the previous recursive proof.

## Plan of Work

Milestone 1 replaces the fake backend abstraction with real recursive Smallwood profiles. Work in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), and add helper modules alongside it if the file becomes too large. The goal is to introduce two concrete recursion profiles, `SmallwoodRecA_v1(v*)` and `SmallwoodRecB_v1(v*)`, that keep the current fixed-shape PIOP/PCS proof skeleton but swap the transcript and authentication layers to Poseidon2 and commit to one exact serializer `ser_sw_rec`. This milestone is done when the repo can prove and verify a toy recursive Smallwood statement under profile `A` and a second toy recursive statement under profile `B`, with the proof byte length fixed and identical for both profiles.

Milestone 2 implements the recursive verifier gadget as real relation code. Work in [circuits/block-recursion/src/relation.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/relation.rs) and split it if needed into `base_relation.rs`, `step_relation.rs`, and `recursive_verifier.rs`. The base relation `Base_A_v*` must accept exactly the canonical base state `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`. The step relations `Step_A_v*` and `Step_B_v*` must verify the previous recursive proof under the opposite profile, then prove one exact `BlockStepRelation_v*` update from `S_{i-1}` to `S_i` over the verified leaf `L_i`. This milestone is done when a local test can construct `pi_0^A`, then one step proof, then a second alternating step proof, and verify each of them through the same exact parser and verifier path that the final block artifact will use.

Milestone 2A is the lowering sub-plan for that verifier gadget. This is the part that turns the recursive verifier from host Rust into executable Smallwood relation code. Work in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), [circuits/transaction/src/smallwood_recursive.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_recursive.rs), [circuits/block-recursion/src/relation.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/relation.rs), and [circuits/block-recursion/src/tests.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/tests.rs).

Milestone 2A.1 freezes the verifier trace. Add one exact parsed-proof / verifier-trace representation for recursive Smallwood proofs, covering: descriptor fields, canonical proof fields, transcript input words, transcript output words, challenge values, opening points, opened witness rows, PCS intermediate values, DECS intermediate values, Merkle/auth path nodes, and the final accept bit. The trace builder must be generated by the existing host verifier and must use one deterministic field order under `Cfg_rec(v*)`.

Milestone 2A.2 fixes the previous-proof witness layout. Define one exact row/column packing for previous recursive proof data consumed by `Step_A` and `Step_B`. That layout must cover: descriptor rows, proof-envelope rows, transcript rows, PCS rows, DECS rows, Merkle/auth rows, and the block-step transition rows. The same layout must work for `BaseA`, `StepA`, and `StepB`; no special wrapper path is allowed.

Milestone 2A.3 lowers descriptor/profile/shape first. Replace hosted recursive checks in `relation.rs` with direct constraints for profile tag, relation kind, relation id, shape digest, verifier-key digest, canonical proof byte length, canonical envelope byte length, and descriptor-to-binding consistency. At the end of this stage, no hosted helper may decide descriptor or envelope validity for `Step_A` or `Step_B`.

Milestone 2A.4 lowers the recursive transcript. Materialize transcript state as witness rows and constrain Poseidon2 absorbs/squeezes, binding bytes, challenge derivation, and transcript digest equality directly in `compute_constraints_u64(...)`. At the end of this stage, no hosted helper may derive recursive transcript challenges for `Step_A` or `Step_B`.

Milestone 2A.5 lowers PCS. Materialize the exact PCS verifier intermediates used by recursive Smallwood verification and constrain opened evaluation points, row-scalar consistency, reconstructed PCS transcript terms, and polynomial-evaluation equalities directly in the step relations. At the end of this stage, no hosted helper may decide PCS validity for `Step_A` or `Step_B`.

Milestone 2A.6 lowers DECS and Merkle authentication. Materialize DECS openings, masking-eval data, authentication paths, Merkle parents, and final roots as witness rows, then constrain each parent recomputation and final equality directly. At the end of this stage, no hosted helper may decide DECS or Merkle validity for `Step_A` or `Step_B`.

Milestone 2A.7 removes the last hosted verifier shortcut. Delete any `verify_recursive_statement_*`, `verify_recursive_proof_*`, or equivalent hosted recursive-verification call from inside `Step_A` or `Step_B`. After this step, the only remaining host-side recursive verification should live in tests that compare the arithmetized verifier against the existing host verifier.

Milestone 2A.8 proves equivalence and redteams it. Add tests that build `pi_0^A`, then `Step_B`, then `Step_A`; generate the verifier trace from the host verifier; feed that trace as witness data; and show that the step relations accept exactly what the host verifier accepts. Then add tamper tests for descriptor, proof length, binding bytes, transcript challenge, PCS values, DECS values, auth path nodes, and Merkle roots. Every tamper must fail before Milestone 2 is considered complete.

Milestone 2A is complete only when `relation.rs` contains no hosted recursive-proof verification shortcut and every previous-proof validity check is represented as witness rows plus low-degree constraints.

Milestone 3 fixes the wire contract. Work in [circuits/block-recursion/src/artifacts.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/artifacts.rs), [circuits/block-recursion/src/statement.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/statement.rs), and [circuits/block-recursion/src/verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/verifier.rs). Remove the old `HeaderDecStepV1`, `BlockAccumulationTranscriptV1`, and any serializer or parser that still assumes `A_n` or `pi_dec`. Replace them with the theorem note’s `Header_rec_step(v*, tau, k, P)` and `Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})`. The canonical parser must exact-consume bytes under `ser_artifact_rec = ser_header_rec_step(Header_rec_step(v*, tau(n), k_term(n), P_n)) || ser_sw_rec(pi_n^{tau(n),k_term(n)})` and `ser_pi_block = ser_artifact_rec || ser_y_rec`, enforce one header width `L_hdr_rec(v*)`, one proof width `L_rec(v*)`, one public tuple width `532`, and reject trailing bytes or alternate widths under one profile. This milestone is done when the artifact parser rejects the old accumulator/decider layout and accepts only the new `ser_pi_block`.

Milestone 4 wires the recursive block prover and verifier to the real public replay boundary. Work in [circuits/block-recursion/src/public_replay.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/public_replay.rs), [circuits/block-recursion/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/prover.rs), and [circuits/block-recursion/src/verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block-recursion/src/verifier.rs). The prover must build `pi_0^{A,BaseA}`, iterate through the ordered verified-leaf stream, alternate profiles `A/B`, and emit the terminal proof `pi_n^{tau(n),k_term(n)}` plus `Header_rec_step(v*, tau(n), k_term(n), P_n)`. The verifier must exact-parse `Pi_block` under `ser_pi_block`, replay `C_leaf`, `C_receipt`, `C_stmt`, `T_0`, `T_n`, `U_n`, and `Y_sem`, reconstruct `P_n`, check the header fields, and run `VerifySw_{tau(n),k_term(n)}(R_{tau(n),k_term(n)}, P_n, pi_n)`. This milestone is done when a block-recursion unit test proves and verifies blocks of at least two transaction counts and both proofs serialize to the same number of bytes.

Milestone 5 removes the fake recursive product path and replaces it with the real one. Work in [consensus/src/types.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/types.rs), [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs), [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs), [node/src/substrate/prover_coordinator.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/prover_coordinator.rs), and [pallets/shielded-pool/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/pallets/shielded-pool/src/lib.rs). Remove any code path that treats a digest-attestation object as a recursive proof. Import and author only the full recursive wire object `Pi_block(B) = (Artifact_rec(B), Y_rec(B))` on the recursive lane, exact-parsed under `ser_pi_block`. This milestone is done when consensus rejects the old fake recursive artifact and accepts only the new direct Smallwood recursive block proof under the canonical outer serializer.

Milestone 6 validates the actual product behavior. Run a dev node, author shielded blocks with at least two different non-empty transaction counts, and prove that the full shipped recursive block-proof bytes are constant-size while the semantic tuple remains unchanged. This milestone is done only when the end-to-end node path imports those blocks successfully and the logs or tests show equal serialized `ser_pi_block(B)` lengths.

Every milestone in this plan is gated by an explicit hostile-review loop. After the code for a milestone lands, stop feature work on later milestones and review the current implementation from scratch as if it were adversarial code. Fix every Critical or High finding immediately, then rerun the hostile review from scratch. Do not advance to the next milestone until there are no remaining Critical or High findings against the current milestone. Then fix any remaining Medium findings that affect soundness, completeness, typing, transcript binding, serializer exactness, wire format, verifier semantics, or constant-size enforcement. “Milestone complete” means code landed, tests passing, hostile review rerun, and no material findings left at that milestone boundary.

## Concrete Steps

Work from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Keep the theorem note, blackboard, and plan synchronized before code changes. Edit:

       docs/crypto/constant_recursive_block_proof.md
       docs/assets/constant-recursive-block-proof-blackboards.svg
       .agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md

   The note, the blackboard, and this plan must all describe the same object: `Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})`.

2. Replace the fake recursive profile story in the proving layer. In `circuits/transaction/src/smallwood_engine.rs`, define:

       pub struct RecursiveSmallwoodProfileV1 { ... }
       pub enum RecursiveSmallwoodProfileTagV1 { A, B }
       pub enum RecursiveRelationKindV1 { BaseA, StepA, StepB }
       pub struct RecursiveVerifierDescriptorV1 {
           profile_tag: RecursiveSmallwoodProfileTagV1,
           relation_kind: RecursiveRelationKindV1,
           relation_id: Digest32,
           shape_digest: Digest32,
           vk_digest: Digest32,
       }
       pub struct RecursiveSmallwoodProofV1 { ... }

       pub fn recursive_descriptor_v1(
           profile: &RecursiveSmallwoodProfileV1,
           relation_kind: RecursiveRelationKindV1,
       ) -> RecursiveVerifierDescriptorV1;

       pub fn prove_recursive_statement_v1(
           profile: &RecursiveSmallwoodProfileV1,
           descriptor: &RecursiveVerifierDescriptorV1,
           statement: &(dyn SmallwoodConstraintAdapter + Sync),
           witness_values: &[u64],
           binded_data: &[u8],
       ) -> Result<Vec<u8>, TransactionCircuitError>;

       pub fn verify_recursive_statement_v1(
           profile: &RecursiveSmallwoodProfileV1,
           descriptor: &RecursiveVerifierDescriptorV1,
           statement: &(dyn SmallwoodConstraintAdapter + Sync),
           binded_data: &[u8],
           proof_bytes: &[u8],
       ) -> Result<(), TransactionCircuitError>;

   These functions must use one canonical serializer `ser_sw_rec`, Poseidon2 recursive transcript/authentication, and exact-consumption parsing. They must not expose witness openings to the verifier. `RecursiveVerifierDescriptorV1` is the source of truth for `(profile_tag, relation_kind, relation_id, shape_digest, vk_digest)` and must be the exact keyed object hashed by the recursive transcript and copied into `HeaderRecStepV1`; no call site may infer those values ad hoc. `prove_recursive_statement_v1` and `verify_recursive_statement_v1` must reject if the supplied profile, descriptor, and statement adapter disagree on profile tag, relation kind, relation id, shape digest, verifier-key digest, or common recursive config. `BaseA`, `StepA`, and `StepB` must all inhabit one common recursive config `Cfg_rec(v*)`, meaning the exact size-driving tuple that the recursive `validate_proof_shape(...)` analogue checks: row count, packing factor, constraint degree, linear-constraint count, witness size, constraint count, number of polys, degree/width/delta vectors, LVCS dimensions, and the exact opened-combination / opening-point schedule. That is what forces `pi_0^{A,BaseA}` to have the same byte width as later `A`-profile step proofs.

3. Expose the two alternating recursion profiles. In the same crate, add:

       pub fn recursive_profile_a_v1(...) -> RecursiveSmallwoodProfileV1;
       pub fn recursive_profile_b_v1(...) -> RecursiveSmallwoodProfileV1;

   The profiles may differ in domain separators, verifier-key constants, and which opposite profile they verify, but they must share the same fixed proof byte length `L_rec(v*)` because all admissible recursive relations compile to the same `Cfg_rec(v*)`. The profile constructors must also expose the exact common recursive config and the exact fixed opening schedule embedded in it so prover, verifier, and serializer width are all forced by one object.

4. Replace the stale artifact types in `circuits/block-recursion/src/artifacts.rs`. Remove or migrate:

       HeaderDecStepV1
       RecursiveBlockArtifactV1
       BlockAccumulationTranscriptV1

   and define:

       pub struct HeaderRecStepV1 { ... }
       pub struct RecursiveBlockArtifactRecV1 { ... }

       pub fn serialize_header_rec_step_v1(...) -> Result<Vec<u8>, BlockRecursionError>;
       pub fn deserialize_header_rec_step_v1(...) -> Result<HeaderRecStepV1, BlockRecursionError>;
       pub fn serialize_recursive_block_artifact_rec_v1(...) -> Result<Vec<u8>, BlockRecursionError>;
       pub fn deserialize_recursive_block_artifact_rec_v1(...) -> Result<RecursiveBlockArtifactRecV1, BlockRecursionError>;

   `HeaderRecStepV1` must bind exactly:

       artifact_version_rec
       tx_line_digest_v*
       rec_profile_tag_tau
       terminal_relation_kind_k
       relation_id_base_A
       relation_id_step_A
       relation_id_step_B
       shape_digest_rec
       vk_digest_base_A
       vk_digest_step_A
       vk_digest_step_B
       proof_encoding_digest_rec
       proof_bytes_rec
       statement_digest_rec(P_n)

   The canonical header serializer must also be defined here and match the theorem note exactly:

       ser_header_rec_step =
           u32_le(artifact_version_rec) ||
           pack32(tx_line_digest_v*) ||
           u32_le(tag_profile_tau) ||
           u32_le(tag_kind_k) ||
           pack32(relation_id_base_A) ||
           pack32(relation_id_step_A) ||
           pack32(relation_id_step_B) ||
           pack32(shape_digest_rec) ||
           pack32(vk_digest_base_A) ||
           pack32(vk_digest_step_A) ||
           pack32(vk_digest_step_B) ||
           pack32(proof_encoding_digest_rec) ||
           u32_le(proof_bytes_rec) ||
           pack32(statement_digest_rec(P_n))

   with fixed width `L_hdr_rec(v*) = 336` bytes.

   The canonical outer serializers must also be defined here and match the theorem note exactly:

       ser_y_sem =
           u32_le(n) ||
           ser_F6(C_stmt) ||
           ser_C48(root_prev) ||
           ser_C48(root_new) ||
           ser_C48(kernel_prev) ||
           ser_C48(kernel_new) ||
           ser_C48(nullifier_root) ||
           ser_C48(da_root)

       ser_y_rec =
           ser_y_sem ||
           ser_F6(C_leaf) ||
           ser_F6(C_receipt) ||
           ser_F6(Sigma_tree(T_0)) ||
           ser_F6(Sigma_tree(T_n))

       ser_artifact_rec =
           ser_header_rec_step(Header_rec_step(v*, tau(n), k_term(n), P_n)) ||
           ser_sw_rec(pi_n^{tau(n),k_term(n)})

       ser_pi_block =
           ser_artifact_rec ||
           ser_y_rec

   with fixed public tuple width `|ser_y_rec| = 532` bytes.

5. Implement the recursive statements in `circuits/block-recursion/src/statement.rs`. Define:

       pub struct RecursivePrefixStatementV1 { ... }   // P_i
       pub struct RecursiveStepStatementV1 { ... }     // Q_i

       pub fn prefix_statement_v1(...) -> RecursivePrefixStatementV1;
       pub fn step_statement_v1(...) -> RecursiveStepStatementV1;
       pub fn statement_digest_rec_v1(...) -> Digest32;
       pub fn statement_digest_step_v1(...) -> Digest32;

   These must match the theorem note exactly. `P_i` is the public recursive prefix summary. `Q_i` is the one-step statement.

6. Implement the base and step relations in `circuits/block-recursion/src/relation.rs`. Define three concrete adapters:

       pub struct BaseARelationV1 { ... }
       pub struct StepARelationV1 { ... }
       pub struct StepBRelationV1 { ... }

   Each must implement `SmallwoodConstraintAdapter`. `BaseARelationV1` must occupy the same common recursive config `Cfg_rec(v*)` as `StepARelationV1`, with unused step-only witness slots constrained to canonical zero encodings. `StepA/BRelationV1` must verify the previous recursive proof under the opposite profile and explicit `RecursiveVerifierDescriptorV1`, then enforce the exact one-step state transition on `L_i`.

   Milestone 2 implementation order is mandatory:

       6a. Add a verifier-trace builder in transaction-circuit that records every recursive verifier intermediate under one fixed trace schema.
       6b. Define the previous-proof witness-row layout for `Step_A` / `Step_B` in block-recursion and document the row allocation next to the code.
       6c. Replace hosted descriptor/profile/shape checks with direct constraints.
       6d. Replace hosted recursive transcript checks with direct constraints.
       6e. Replace hosted PCS checks with direct constraints.
       6f. Replace hosted DECS/Merkle checks with direct constraints.
       6g. Remove the final hosted recursive verifier helper call from the step relations.
       6h. Redteam the resulting chain with positive and tamper tests before touching artifacts or product wiring.

7. Rewrite `circuits/block-recursion/src/prover.rs` around the direct recursive chain. Define:

       pub fn prove_block_recursive_v1(...) -> Result<RecursiveBlockArtifactRecV1, BlockRecursionError>;

   The implementation must:

       compute T_0 from parent state
       build pi_0^{A,BaseA} for P_0 using descriptor (profile=A, relation_kind=BaseA)
       iterate verified leaves in order
       alternate A/B profiles
       emit terminal pi_n^{tau(n),k_term(n)} using the explicit keyed descriptor `(profile_tag, relation_kind, relation_id, shape_digest, vk_digest)`
       build HeaderRecStepV1 from `(tau(n), k_term(n), P_n)`

8. Rewrite `circuits/block-recursion/src/verifier.rs` around the direct recursive verifier boundary. Define:

       pub fn verify_block_recursive_v1(...) -> Result<(), BlockRecursionError>;

   The verifier must:

       exact-parse the new artifact under `ser_pi_block`
       replay C_leaf, C_receipt, C_stmt, T_0, T_n, U_n
       rebuild P_n
       verify header fields
       derive the canonical keyed descriptor for `(tau(n), k_term(n))`
       call verify_recursive_statement_v1(profile_tau, descriptor_tau, relation_for_tau, binded_data_for_P_n, pi_n)

9. Remove or quarantine the fake recursive backend. In:

       circuits/superneo-core/src/lib.rs
       circuits/superneo-backend-lattice/src/lib.rs

   either delete the dead recursive trait/object path or mark it internal and unused by the block-recursion crate. The final recursive block product must not depend on the fake accumulator/decider API.

10. Wire the real artifact through the product path. In:

       consensus/src/types.rs
       consensus/src/proof.rs
       node/src/substrate/service.rs
       node/src/substrate/prover_coordinator.rs
       pallets/shielded-pool/src/types.rs
       pallets/shielded-pool/src/lib.rs

   ensure the recursive lane carries only the new `Artifact_rec` layout, not the old fake recursive payload.

## Validation and Acceptance

### Hostile Review and Redteam Loop

The implementation workflow includes a mandatory adversarial loop, not just positive-path testing.

For each milestone, perform this exact sequence:

1. Implement the milestone in code.
2. Run the milestone’s direct tests and checks.
3. Do a hostile review from scratch against the code as it exists now, not against memory of prior fixes.
4. Fix every Critical and High finding immediately.
5. Rerun the hostile review from scratch.
6. Repeat until the hostile review returns no Critical or High findings.
7. Then fix every remaining Medium finding that affects soundness, completeness, typing, transcript binding, serializer exactness, wire format, verifier semantics, or constant-size enforcement.
8. Redteam the milestone with concrete tamper cases before advancing.

The hostile review must actively look for:

- forged prior-proof acceptance
- hosted verifier shortcuts surviving inside recursive relations
- witness-carrying or digest-attestation substitutes for real recursive verification
- alternate serializers or alternate widths accepted under one profile
- trailing-byte acceptance
- profile / relation-kind / descriptor mismatch acceptance
- transcript challenge drift between host verifier and recursive relation
- PCS / DECS / Merkle checks that are only partially constrained
- any path where proof size can vary with transaction count

The redteam tests must be milestone-specific:

- Milestone 1: wrong descriptor digest, wrong profile tag, wrong relation kind, wrong proof width, tampered recursive proof bytes.
- Milestone 2 / 2A: tampered verifier trace rows, transcript challenges, PCS values, DECS values, Merkle/auth nodes, prior-proof bytes, and prior-proof descriptor fields.
- Milestone 3: malformed `Header_rec_step`, malformed `Y_rec(B)`, trailing bytes, alternate-width headers, alternate-width proofs, alternate-width outer objects, and any serializer mismatch under the same profile.
- Milestone 4: forged terminal recursive proof, wrong `P_n`, wrong `tau(n)`, wrong `k_term(n)`, mismatched `C_leaf`, `C_receipt`, `Sigma_tree(T_0)`, or `Sigma_tree(T_n)`.
- Milestone 5: forged consensus payloads, recursive lane accepting the old fake artifact, or product wiring that still routes through the lattice placeholder.
- Milestone 6: end-to-end import of non-empty blocks with different transaction counts, equal `|ser_pi_block(B)|`, and rejection of tampered shipped artifacts.

If a hostile review or redteam pass forces a protocol correction, update the theorem note, the blackboard, and this plan before continuing. Do not let code and spec drift at any point in the loop.

Run the following from `/Users/pldd/Projects/Reflexivity/Hegemon` as work progresses:

    cargo test -p transaction --lib smallwood -- --nocapture
    cargo test -p block-recursion --lib -- --nocapture
    cargo test -p consensus --lib -- --nocapture
    cargo test -p pallet-shielded-pool --lib -- --nocapture
    cargo check -p hegemon-node --lib

The implementation is not accepted until all of the following are true:

1. A unit test proves and verifies `pi_0^A`.
2. A unit test proves and verifies at least one `Step_B` proof over a real verified leaf.
3. A unit test proves and verifies at least one `Step_A` proof that verifies a prior `Step_B` proof.
4. Two block-recursion tests with different non-zero transaction counts produce the same serialized recursive proof byte length.
5. Tampering any byte of `Header_rec_step`, `Y_rec(B)`, or `pi_n` causes verification failure.
6. The parser rejects trailing bytes and alternate-width encodings.
7. A dev-node smoke test imports at least two non-empty shielded blocks on the recursive lane with the same proof byte length.

Use this dev-node smoke once the consensus and node wiring lands:

    make setup
    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Then submit shielded transactions through the existing wallet/client flow until you mine at least two non-empty shielded blocks of different transaction counts. Capture the recursive artifact byte lengths and confirm they match exactly.

## Idempotence and Recovery

These edits are additive until Milestone 5. It is safe to rerun the unit tests and parsers repeatedly. When replacing the fake recursive artifact path, keep the old `ReceiptRoot` lane intact until the new recursive lane proves blocks end to end. If a refactor breaks the recursive lane midway, revert only the half-finished recursive product wiring and keep the theorem note plus unit tests. Do not leave consensus defaulting to an unverified fake recursive artifact at any stopping point.

## Artifacts and Notes

Successful work under this plan should produce concise evidence like:

    cargo test -p block-recursion recursive_base_and_step_chain_roundtrip -- --nocapture
    test recursive_base_and_step_chain_roundtrip ... ok

    cargo test -p block-recursion recursive_proof_length_constant_across_block_sizes -- --nocapture
    block_size=1 proof_bytes=NNNN
    block_size=4 proof_bytes=NNNN
    test recursive_proof_length_constant_across_block_sizes ... ok

    cargo test -p consensus recursive_block_import_preserves_semantic_tuple -- --nocapture
    test recursive_block_import_preserves_semantic_tuple ... ok

Keep the strongest evidence snippets in commit messages or follow-up notes, but do not let them replace the required tests.

## Interfaces and Dependencies

The implementation must continue to use the existing `SmallwoodConstraintAdapter` interface in [circuits/transaction/src/smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs). Do not introduce Plonky3 or a second proof system. The recursive prover/verifier must be built by extending the Smallwood engine itself.

The canonical recursive artifact owner is `circuits/block-recursion/src/artifacts.rs`. No second recursive artifact schema may exist elsewhere in the repo. The canonical verified-leaf boundary remains `circuits/superneo-hegemon/src/lib.rs`. The consensus verification boundary remains `consensus/src/proof.rs`.

The final stable public items that must exist are:

    transaction::smallwood_engine::RecursiveSmallwoodProfileV1
    transaction::smallwood_engine::RecursiveSmallwoodProfileTagV1
    transaction::smallwood_engine::RecursiveRelationKindV1
    transaction::smallwood_engine::RecursiveVerifierDescriptorV1
    transaction::smallwood_engine::recursive_descriptor_v1
    transaction::smallwood_engine::prove_recursive_statement_v1
    transaction::smallwood_engine::verify_recursive_statement_v1
    block_recursion::artifacts::HeaderRecStepV1
    block_recursion::artifacts::RecursiveBlockArtifactRecV1
    block_recursion::prover::prove_block_recursive_v1
    block_recursion::verifier::verify_block_recursive_v1

The final shipped artifact must be:

    Pi_block(B) = (Artifact_rec(B), Y_rec(B))
    Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})

Any implementation that instead ships `A_n`, `pi_dec`, a witness-carrying fold object, a proof-system cap, or a linear sidecar fails this plan.

Change note: this ExecPlan was rewritten on 2026-04-13 because the theorem note no longer derives a `CCCS/LCCCS/decider` backend. The correct implementation target is now direct Smallwood proof-carrying recursion with one terminal recursive proof, so the old plan’s milestones would have sent the engineer to build the wrong object.
