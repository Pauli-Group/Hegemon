import SmzaRp05AcceptedModeExhaustiveness
import SmzaRp05AcceptedNullifierMuxJoin
import SmzaRp05NullifierMuxCertificate

/-! Acceptance-level mapping of the five packed nullifier-key words in all
three checked selector modes. This is a word-selection result only; it makes
no collision-resistance or digest-security claim. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedAllModeNullifierKeys

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05AcceptedModeExhaustiveness
open HegemonCrypto.SmallWood.SmzaRp05AcceptedNullifierMuxJoin
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (canonical_nat_cast_injective)

set_option autoImplicit false
set_option maxRecDepth 1000000

def acceptedPolicyKey (packed : List Nat) : Fin 5 → Nat :=
  fun limb => packed.getD (policyNullifierKeyRow * packingFactor + limb.val) 0

private theorem packed_lane_row_getD (packed : List Nat) (lane row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed lane).getD row 0 =
      packed.getD (row * packingFactor + lane) 0 := by
  have shape : (packedWitnessLaneRows packed lane).length = relationRowCount := by
    simp [packedWitnessLaneRows]
  rw [List.getD_eq_getElem _ _ (by omega)]
  simp only [packedWitnessLaneRows, List.getElem_map, List.getElem_range]

private theorem row_word_nat_eq
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (limb : Fin 5) (row otherRow : Nat)
    (rowBound : row < relationRowCount)
    (otherBound : otherRow < relationRowCount)
    (equal : ((packedWitnessLaneRows packed limb.val).getD row 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD otherRow 0 : Goldilocks)) :
    packed.getD (row * packingFactor + limb.val) 0 =
      packed.getD (otherRow * packingFactor + limb.val) 0 := by
  rw [packed_lane_row_getD packed limb.val row rowBound,
    packed_lane_row_getD packed limb.val otherRow otherBound] at equal
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (row * packingFactor + limb.val))
    (packed_word_canonical accepted.2.1 (otherRow * packingFactor + limb.val)) equal

private theorem nullifier_preimage_first_five_word
    (packed : List Nat) (input : Fin 2) (limb : Fin 5) :
    (nullifierPreimage packed input).getD limb.val 0 =
      packed.getD (inputNullifierKeyRow input * packingFactor + limb.val) 0 := by
  unfold nullifierPreimage
  fin_cases limb <;> simp [packingFactor]

/-- In every accepted selector mode, the actual first five Nat words of the
twelve-word preimage equal that mode's selected packed key. Approval uses
policy for input 0 and global for input 1; Final uses policy for both. -/
theorem accepted_all_mode_nullifier_preimage_key_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (certificate : CurrentNullifierMuxCertificate program)
    (input : Fin 2) (limb : Fin 5) :
    (nullifierPreimage packed input).getD limb.val 0 =
      if ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 1 then
        if input.val = 0 then acceptedPolicyKey packed limb else acceptedGlobalKey packed limb
      else if ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 1 then
        acceptedPolicyKey packed limb
      else acceptedGlobalKey packed limb := by
  have modes := accepted_mode_selectors_exhaustive accepted ⟨limb.val, by omega⟩
  rcases modes.2 with singleCase | approvalCase | finalCase
  · rcases singleCase with ⟨singleSelected, approvalUnselected, finalUnselected⟩
    have global := accepted_single_nullifier_preimage_key_word accepted certificate input limb
      singleSelected approvalUnselected finalUnselected
    rw [approvalUnselected, finalUnselected]
    norm_num
    exact global
  · rcases approvalCase with ⟨singleUnselected, approvalSelected, finalUnselected⟩
    have fieldEq := accepted_approval_nullifier_key_word certificate accepted input limb
      approvalSelected singleUnselected finalUnselected
    have rowBound : inputNullifierKeyRow input < relationRowCount := by
      fin_cases input <;> decide
    have targetRowBound :
        (if input.val = 0 then policyNullifierKeyRow else globalNullifierKeyRow) <
          relationRowCount := by
      fin_cases input <;> decide
    have natEq := row_word_nat_eq accepted limb (inputNullifierKeyRow input)
      (if input.val = 0 then policyNullifierKeyRow else globalNullifierKeyRow)
      rowBound targetRowBound fieldEq
    rw [approvalSelected]
    simp only [if_true]
    rw [nullifier_preimage_first_five_word]
    fin_cases input <;>
      simpa [acceptedPolicyKey, acceptedGlobalKey, policyNullifierKeyRow,
        globalNullifierKeyRow, packingFactor] using natEq
  · rcases finalCase with ⟨singleUnselected, approvalUnselected, finalSelected⟩
    have fieldEq := accepted_final_nullifier_key_word certificate accepted input limb
      finalSelected singleUnselected approvalUnselected
    have rowBound : inputNullifierKeyRow input < relationRowCount := by
      fin_cases input <;> decide
    have targetRowBound : policyNullifierKeyRow < relationRowCount := by decide
    have natEq := row_word_nat_eq accepted limb (inputNullifierKeyRow input)
      policyNullifierKeyRow rowBound targetRowBound fieldEq
    rw [nullifier_preimage_first_five_word]
    rw [approvalUnselected, finalSelected]
    norm_num
    simpa [acceptedPolicyKey, packingFactor] using natEq

end HegemonCrypto.SmallWood.SmzaRp05AcceptedAllModeNullifierKeys
