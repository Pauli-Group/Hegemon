import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import HegemonCrypto.SmallWoodV8Smz9NoteOutputPublic

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointOutputs

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (outputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (encoded_output_flag)
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9NoteOutputPublic

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000

/-- Arbitrary packed acceptance binds each active output's actual projected
note opening to its seven exact public commitment words. -/
theorem accepted_active_output_exact_commitment {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (output : Fin 2) (active : publicWords.getD (2 + output.val) 0 = 1) :
    exactV8NoteCommitment (projectNote packed (outputNoteCall output.val)) =
      (List.range 7).map (fun limb => publicWords.getD (18 + 7 * output.val + limb) 0) := by
  let note : Fin 4 := ⟨2 + output.val, by have := output.isLt; omega⟩
  have call : noteBridgeCall note.val = outputNoteCall output.val := by
    fin_cases output <;> rfl
  have digest := accepted_note_digest_eq_exact_commitment accepted note
  rw [call] at digest
  rw [← digest]
  apply List.ext_getElem
  · simp [packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa using rightBound
    simp only [packedFinalState, List.getElem_take, List.getElem_map, List.getElem_range]
    exact accepted_active_output_commitment_word accepted output ⟨limb, limbBound⟩ active

/-- The complete output-commitment conjunct of V8CryptographicLinksValid,
derived from public admission and arbitrary accepted packed source words. -/
theorem admitted_packed_project_typed_output_commitments {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    ∀ slot, slot < outputCount → flagAt statement.outputFlags slot = 1 →
      exactV8SemanticPrimitives.noteCommitment
          ((projectTypedWitness statement packed).outputs.getD slot default).note =
        digestAt statement.commitments slot := by
  intro slot slotBound active
  have bound : slot < 2 := slotBound
  have rawActive : publicWords.getD (2 + slot) 0 = 1 := by
    rw [← domain.1, encoded_output_flag statement domain.2.1 bound]
    exact active
  rw [project_typed_output_at statement packed default bound]
  change exactV8NoteCommitment (projectNote packed (outputNoteCall slot)) = _
  exact (accepted_active_output_exact_commitment domain.2.2 ⟨slot, bound⟩ rawActive).trans
    (admitted_public_commitment_digest domain ⟨slot, bound⟩)


end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointOutputs
