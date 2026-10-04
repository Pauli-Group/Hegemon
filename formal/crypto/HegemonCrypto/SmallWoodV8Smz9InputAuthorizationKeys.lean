import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex rawIndex inputNoteCall outputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def noteAuthRow (note : Nat) : Nat := [97, 101, 76, 88].getD note 0
def noteAuthLocal (limb : Nat) : Nat := if limb < 2 then 10 + limb else 18 + limb

def noteAuthAttempt (note limb : Nat) : CsrExecutableAttempt :=
  let call := noteBridgeCall note + (14 + limb) / 8
  let lane := (14 + limb) % 8
  let localIndex := noteAuthLocal limb
  attempt (noteBridgeAttemptIndex note + localIndex) (if note < 2 then 12 else 21)
    (36 * (note % 2) + localIndex) 0
    [(hashInitialIndex call lane, 1), (hashFinalIndex (call - 1) lane, 158),
      (rawIndex (noteAuthRow note + limb), 158)] 0

def noteAuthFilter (entry : CsrExecutableAttempt) : Bool :=
  (entry.family == 12 || entry.family == 21) &&
    [10, 11, 20, 21].contains (entry.localIndex % 36)

def noteAuthAttempts : List CsrExecutableAttempt :=
  (List.range 4).flatMap (fun note => (List.range 4).map (noteAuthAttempt note))

theorem exact_note_auth_filter :
    noteFrameChunks.flatten.filter noteAuthFilter = noteAuthAttempts := by decide

theorem exact_note_auth_attempt (note : Fin 4) (limb : Fin 4) :
    noteAuthAttempt note.val limb.val ∈ exactCsrAttempts := by
  have filtered : noteAuthAttempt note.val limb.val ∈ noteFrameChunks.flatten.filter noteAuthFilter := by
    rw [exact_note_auth_filter]
    exact List.mem_flatMap.mpr ⟨note.val, List.mem_range.mpr note.isLt,
      List.mem_map.mpr ⟨limb.val, List.mem_range.mpr limb.isLt, rfl⟩⟩
  obtain ⟨chunk, chunkMember, entryMember⟩ := List.mem_flatten.mp (List.mem_filter.mp filtered).1
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, note_frame_chunk_mem_exact chunkMember, entryMember⟩

/-- Each decoded note authorization word is fixed by its actual source CSR
equation, including words14/15 in block1 and words16/17 in block2. -/
theorem accepted_note_authorization_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (note : Fin 4) (limb : Fin 4) :
    spongeSourceWord packed (noteBridgeCall note.val) (14 + limb.val) =
      packedWord packed (rawIndex (noteAuthRow note.val + limb.val)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_note_auth_attempt note limb))
  simp only [noteAuthAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, zero, one, negative, one_mul, neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  have block : (14 + limb.val) / 8 ≠ 0 := by have := limb.isLt; omega
  simp only [spongeSourceWord, if_neg block]
  rw [field_sub_cast _ _ (by
    have canonical := packed_word_canonical accepted.2.1
      (hashFinalIndex (noteBridgeCall note.val + (14 + limb.val) / 8 - 1) ((14 + limb.val) % 8))
    change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at canonical
    omega)]
  simp only [packedWord]
  linear_combination equation

theorem accepted_note_authorization_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (note : Fin 4) :
    (projectNote packed (noteBridgeCall note.val)).authorizationKey =
      (List.range 4).map (fun limb => packedWord packed (rawIndex (noteAuthRow note.val + limb))) := by
  simp only [projectNote]
  apply List.map_congr_left
  intro limb member
  exact accepted_note_authorization_source_word accepted note ⟨limb, List.mem_range.mp member⟩

theorem accepted_input_authorization_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    (projectInput statement packed input.val).note.authorizationKey =
      (List.range 4).map (fun limb => packedWord packed (rawIndex (97 + 4 * input.val + limb))) := by
  have note : (input.val : Nat) < 4 := by have := input.isLt; omega
  have source := accepted_note_authorization_source accepted ⟨input.val, note⟩
  have call : noteBridgeCall input.val = inputNoteCall input.val := by fin_cases input <;> rfl
  have row : noteAuthRow input.val = 97 + 4 * input.val := by fin_cases input <;> rfl
  rw [call, row] at source
  exact source

theorem accepted_output_authorization_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (output : Fin 2) :
    (projectOutput statement packed output.val).note.authorizationKey =
      (List.range 4).map (fun limb => packedWord packed (rawIndex (76 + 12 * output.val + limb))) := by
  let note : Fin 4 := ⟨2 + output.val, by have := output.isLt; omega⟩
  have source := accepted_note_authorization_source accepted note
  have call : noteBridgeCall note.val = outputNoteCall output.val := by fin_cases output <;> rfl
  have row : noteAuthRow note.val = 76 + 12 * output.val := by fin_cases output <;> rfl
  rw [call, row] at source
  exact source

theorem accepted_typed_input_authorization_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    ((projectTypedWitness statement packed).inputs.getD input.val default).note.authorizationKey =
      (List.range 4).map (fun limb => packedWord packed (rawIndex (97 + 4 * input.val + limb))) := by
  rw [project_typed_input_at statement packed default input.isLt]
  exact accepted_input_authorization_source accepted statement input

theorem accepted_typed_output_authorization_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (output : Fin 2) :
    ((projectTypedWitness statement packed).outputs.getD output.val default).note.authorizationKey =
      (List.range 4).map (fun limb => packedWord packed (rawIndex (76 + 12 * output.val + limb))) := by
  rw [project_typed_output_at statement packed default output.isLt]
  exact accepted_output_authorization_source accepted statement output


end HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
