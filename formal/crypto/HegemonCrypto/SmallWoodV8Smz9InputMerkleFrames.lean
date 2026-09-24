import HegemonCrypto.SmallWoodV8Smz9InputMerkleEquations
import HegemonCrypto.SmallWoodV8Smz9PositionBits

namespace HegemonCrypto.SmallWood.V8Smz9InputMerkleFrames

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex inputMerkleCall inputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9InputMerkleSources
open HegemonCrypto.SmallWood.V8Smz9InputMerkleEquations
open HegemonCrypto.SmallWood.V8Smz9PositionBits

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def initialHalf (packed : List Nat) (step half : Nat) : Digest :=
  (List.range 7).map fun limb =>
    packedWord packed (hashInitialIndex (merkleCall step) (7 * half + limb))

theorem initial_half_getD (packed : List Nat) (step half : Nat)
    {limb : Nat} (bound : limb < 7) :
    (initialHalf packed step half).getD limb 0 =
      packedWord packed (hashInitialIndex (merkleCall step) (7 * half + limb)) := by
  simp [initialHalf, List.getD_eq_getElem?_getD, bound]

theorem accepted_compress_initial_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step : Nat} (stepBound : step < 64) :
    packedInitialState packed (merkleCall step) =
      compressFrame poseidon2V8MerkleDomain (initialHalf packed step 0) (initialHalf packed step 1) := by
  apply List.map_congr_left
  intro lane member
  have bound := List.mem_range.mp member
  by_cases left : lane < 7
  · change _ = (if lane < 7 then _ else _)
    rw [if_pos left, initial_half_getD packed step 0 left]
    simp only [Nat.mul_zero, Nat.zero_add]
  · by_cases right : lane < 14
    · change _ = (if lane < 7 then _ else if lane < 14 then _ else _)
      rw [if_neg left, if_pos right,
        initial_half_getD packed step 1 (show lane - 7 < 7 from by omega)]
      have index : 7 * 1 + (lane - 7) = lane := by omega
      rw [index]
    · change _ = (if lane < 7 then _ else if lane < 14 then _ else _)
      rw [if_neg left, if_neg right]
      exact accepted_initial_capacity accepted stepBound bound (by omega)

theorem accepted_previous_digest_is_selected_half {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step : Nat} (stepBound : step < 64) :
    callDigest packed (previousCall step) =
      initialHalf packed step (if directionWord packed (step / 32) (step % 32) = 0 then 0 else 1) := by
  apply List.ext_getElem
  · simp [callDigest, packedFinalState, digestWords, initialHalf]
  · intro limb leftBound rightBound
    have bound : limb < 7 := by simpa [initialHalf] using rightBound
    simp only [callDigest, packedFinalState, List.getElem_take,
      initialHalf, List.getElem_map, List.getElem_range]
    have current := accepted_current_source accepted stepBound bound
    have selected := accepted_selected_current accepted stepBound bound
    by_cases direction : directionWord packed (step / 32) (step % 32) = 0
    · rw [if_pos direction] at selected ⊢
      have initial := accepted_initial_source accepted stepBound (lane := limb) (by omega)
      rw [if_pos bound, Nat.mod_eq_of_lt bound] at initial
      simpa only [Nat.mul_zero, Nat.zero_add] using
        current.symm.trans (selected.trans initial.symm)
    · rw [if_neg direction] at selected ⊢
      have initial := accepted_initial_source accepted stepBound (lane := 7 + limb) (by omega)
      have large : ¬7 + limb < 7 := by omega
      have remainder : (7 + limb) % 7 = limb := by omega
      rw [if_neg large, remainder] at initial
      exact current.symm.trans (selected.trans initial.symm)

def siblingDigest (packed : List Nat) (input level : Nat) : Digest :=
  initialHalf packed (input * 32 + level)
    (if directionWord packed input level = 0 then 1 else 0)

theorem flat_step_parts {input level : Nat} (levelBound : level < 32) :
    (input * 32 + level) / 32 = input ∧ (input * 32 + level) % 32 = level := by omega

theorem accepted_merkle_step {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input level : Nat} (inputBound : input < 2) (levelBound : level < 32) :
    callDigest packed (inputMerkleCall input level) =
      if directionWord packed input level = 0 then
        poseidon2V8Compress14 poseidon2V8MerkleDomain
          (callDigest packed (previousCall (input * 32 + level)))
          (siblingDigest packed input level)
      else poseidon2V8Compress14 poseidon2V8MerkleDomain
        (siblingDigest packed input level)
        (callDigest packed (previousCall (input * 32 + level))) := by
  have stepBound : input * 32 + level < 64 := by omega
  have parts := flat_step_parts levelBound (input := input)
  have call : merkleCall (input * 32 + level) = inputMerkleCall input level := by
    simp only [merkleCall, parts.1, parts.2]
  have callBound : merkleCall (input * 32 + level) < 128 := by
    rw [call]
    unfold inputMerkleCall
    split_ifs <;> omega
  have hash := accepted_compress_digest accepted callBound poseidon2V8MerkleDomain
    (initialHalf packed (input * 32 + level) 0) (initialHalf packed (input * 32 + level) 1)
    (accepted_compress_initial_frame accepted stepBound)
  have selected := accepted_previous_digest_is_selected_half accepted stepBound
  rw [parts.1, parts.2] at selected
  rw [← call, hash, selected]
  unfold siblingDigest
  split_ifs <;> rfl

theorem project_input_sibling (statement : V8PublicStatement) (packed : List Nat)
    (input : Nat) {level : Nat} (levelBound : level < 32) :
    (projectInput statement packed input).siblings.getD level [] =
      siblingDigest packed input level := by
  have parts := flat_step_parts levelBound (input := input)
  simp only [projectInput, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range, levelBound, Option.map_some, Option.getD_some]
  unfold siblingDigest initialHalf merkleCall
  rw [parts.1, parts.2]
  split_ifs <;> rfl

def boundaryCall (input count : Nat) : Nat :=
  if count = 0 then inputNoteCall input + 2 else inputMerkleCall input (count - 1)

theorem previous_flat_call {input level : Nat} (levelBound : level < 32) :
    previousCall (input * 32 + level) = boundaryCall input level := by
  have parts := flat_step_parts levelBound (input := input)
  simp only [previousCall, merkleCall, boundaryCall, parts.1, parts.2]
  by_cases zero : level = 0
  · simp only [zero, if_true]
  · simp only [zero, if_false]
    unfold inputMerkleCall
    split_ifs <;> omega

/-- All prefixes of either accepted 32-level input path, with directions
decoded from the actual accepted Boolean rows. -/
theorem accepted_merkle_fold_prefix {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) {input count : Nat}
    (inputBound : input < 2) (countBound : count ≤ 32) :
    (List.range count).foldl (fun current level =>
      if (projectPosition packed input / 2 ^ level) % 2 = 0 then
        poseidon2V8Compress14 poseidon2V8MerkleDomain current
          ((projectInput statement packed input).siblings.getD level [])
      else poseidon2V8Compress14 poseidon2V8MerkleDomain
        ((projectInput statement packed input).siblings.getD level []) current)
      (callDigest packed (inputNoteCall input + 2)) =
        callDigest packed (boundaryCall input count) := by
  induction count with
  | zero => simp [boundaryCall]
  | succ count ih =>
      have lower : count < 32 := by omega
      rw [List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [ih (by omega), accepted_project_position_bit accepted inputBound lower,
        project_input_sibling statement packed input lower]
      have step := accepted_merkle_step accepted inputBound lower
      rw [previous_flat_call lower] at step
      have successor : boundaryCall input (count + 1) = inputMerkleCall input count := by
        simp [boundaryCall]
      rw [successor]
      exact step.symm

/-- The source path and the existing typed Merkle primitive agree for either
arbitrary accepted packed input, before applying the active public-root gate. -/
theorem accepted_merkle_root_eq_final_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    exactV8MerkleRoot (exactV8NoteCommitment (projectInput statement packed input.val).note)
      (projectInput statement packed input.val).position
      (projectInput statement packed input.val).siblings =
        callDigest packed (inputMerkleCall input.val 31) := by
  have note : noteBridgeCall input.val = inputNoteCall input.val := by
    fin_cases input <;> rfl
  have noteDigest := accepted_note_digest_eq_exact_commitment accepted
    (⟨input.val, by have := input.isLt; omega⟩ : Fin 4)
  rw [note] at noteDigest
  change exactV8MerkleRoot (exactV8NoteCommitment (projectNote packed (inputNoteCall input.val)))
    (projectPosition packed input.val) (projectInput statement packed input.val).siblings = _
  rw [← noteDigest]
  exact accepted_merkle_fold_prefix accepted statement input.isLt (count := 32) (by decide)


end HegemonCrypto.SmallWood.V8Smz9InputMerkleFrames
