import SmzaRp05AuthorizationClosureIdentity
import SmzaRp05CurrentNullifierCertificates

/-! Same historical note and position across transactions: either the source
nullifier is identical, or the accepted owners give a canonical collision
between exact padded authorization messages with different selected keys. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureCrossTransaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05CurrentNullifierCertificates
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
open scoped Classical

private theorem binding_right_canonical {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (which : Fin 2) :
    (bindingRight packed which).length = 7 ∧
      ∀ word ∈ bindingRight packed which,
        word < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  have wordBound := fun n => packed_word_canonical accepted.2.1 n
  fin_cases which <;>
    simp [bindingRight, packedFinalState, packedWord, List.range_succ] <;>
    exact ⟨wordBound _, wordBound _, wordBound _, wordBound _, wordBound _,
      wordBound _, wordBound _⟩

theorem accepted_message_canonical {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (input : Fin 2) :
    (selectedMessage packed input).Canonical := by
  unfold selectedMessage
  split
  · exact ⟨fun limb => packed_word_canonical accepted.2.1 _, trivial⟩
  · exact ⟨fun limb => packed_word_canonical accepted.2.1 _,
      binding_right_canonical accepted _⟩

/-- This is the precise induced primitive event, retaining canonical
five-word keys, two zero pads, the seven-word right argument and live
domain/suite framing. It is not arbitrary-width permutation collision. -/
def FramedAuthorizationCollision
    (left right : FramedAuthorizationInput) : Prop :=
  left.Canonical ∧ right.Canonical ∧ left.key ≠ right.key ∧
    ∀ limb : Fin 7, left.digest.getD limb.val 0 = right.digest.getD limb.val 0

theorem framed_collision_inputs_distinct
    {left right : FramedAuthorizationInput}
    (collision : FramedAuthorizationCollision left right) : left ≠ right := by
  intro equal
  exact collision.2.2.1 (congrArg FramedAuthorizationInput.key equal)

/-- Equality of actual selected keys, position and rho identifies all twelve
source words. No collision assumption is used in this deterministic branch. -/
private theorem equal_key_position_rho_preimage
    (leftPacked rightPacked : List Nat) (leftInput rightInput : Fin 2)
    (sameKey : ∀ limb : Fin 5,
      (nullifierPreimage leftPacked leftInput).getD limb.val 0 =
        (nullifierPreimage rightPacked rightInput).getD limb.val 0)
    (samePosition : projectPosition leftPacked leftInput.val =
      projectPosition rightPacked rightInput.val)
    (sameRho : ∀ limb : Fin 4,
      spongeSourceWord leftPacked (inputNoteFirstCall leftInput) (6 + limb.val) =
        spongeSourceWord rightPacked (inputNoteFirstCall rightInput) (6 + limb.val)) :
    nullifierPreimage leftPacked leftInput = nullifierPreimage rightPacked rightInput := by
  have keys : ∀ limb : Fin 5,
      leftPacked.getD (inputNullifierKeyRow leftInput * 64 + limb.val) 0 =
        rightPacked.getD (inputNullifierKeyRow rightInput * 64 + limb.val) 0 := by
    intro limb
    have equal := sameKey limb
    fin_cases limb <;> simpa [nullifierPreimage] using equal
  have keyMap :
      (List.range 5).map (fun limb =>
        leftPacked.getD (inputNullifierKeyRow leftInput * 64 + limb) 0) =
      (List.range 5).map (fun limb =>
        rightPacked.getD (inputNullifierKeyRow rightInput * 64 + limb) 0) := by
    apply List.map_congr_left
    intro limb member
    exact keys ⟨limb, List.mem_range.mp member⟩
  have rhoMap :
      (List.range 4).map (fun limb =>
        spongeSourceWord leftPacked (inputNoteFirstCall leftInput) (6 + limb)) =
      (List.range 4).map (fun limb =>
        spongeSourceWord rightPacked (inputNoteFirstCall rightInput) (6 + limb)) := by
    apply List.map_congr_left
    intro limb member
    exact sameRho ⟨limb, List.mem_range.mp member⟩
  unfold nullifierPreimage
  rw [keyMap, rhoMap, samePosition]

theorem accepted_same_note_position_preimage_or_authorization_collision
    {leftPublic leftPacked rightPublic rightPacked : List Nat}
    (leftAccepted : program.AcceptsPacked leftPublic leftPacked)
    (rightAccepted : program.AcceptsPacked rightPublic rightPacked)
    (leftInput rightInput : Fin 2)
    (leftActive : leftPublic.getD leftInput.val 0 = 1)
    (rightActive : rightPublic.getD rightInput.val 0 = 1)
    (sameOwner : ∀ limb : Fin 7,
      leftPacked.getD ((95 + leftInput.val) * 64 + limb.val) 0 =
        rightPacked.getD ((95 + rightInput.val) * 64 + limb.val) 0)
    (samePosition : projectPosition leftPacked leftInput.val =
      projectPosition rightPacked rightInput.val)
    (sameRho : ∀ limb : Fin 4,
      spongeSourceWord leftPacked (inputNoteFirstCall leftInput) (6 + limb.val) =
        spongeSourceWord rightPacked (inputNoteFirstCall rightInput) (6 + limb.val)) :
    nullifierPreimage leftPacked leftInput = nullifierPreimage rightPacked rightInput ∨
      FramedAuthorizationCollision (selectedMessage leftPacked leftInput)
        (selectedMessage rightPacked rightInput) := by
  by_cases sameKey : (selectedMessage leftPacked leftInput).key =
      (selectedMessage rightPacked rightInput).key
  · left
    apply equal_key_position_rho_preimage leftPacked rightPacked leftInput rightInput
      _ samePosition sameRho
    intro limb
    rw [accepted_message_key_word leftAccepted, accepted_message_key_word rightAccepted,
      sameKey]
  · right
    refine ⟨accepted_message_canonical leftAccepted leftInput,
      accepted_message_canonical rightAccepted rightInput, sameKey, ?_⟩
    intro limb
    exact (accepted_owner_message_digest leftAccepted leftInput leftActive limb).symm.trans
      ((sameOwner limb).trans
        (accepted_owner_message_digest rightAccepted rightInput rightActive limb))

theorem accepted_same_note_position_public_nullifier_or_authorization_collision
    {leftPublic leftPacked rightPublic rightPacked : List Nat}
    (leftAccepted : program.AcceptsPacked leftPublic leftPacked)
    (rightAccepted : program.AcceptsPacked rightPublic rightPacked)
    (leftInput rightInput : Fin 2)
    (leftActive : leftPublic.getD leftInput.val 0 = 1)
    (rightActive : rightPublic.getD rightInput.val 0 = 1)
    (sameOwner : ∀ limb : Fin 7,
      leftPacked.getD ((95 + leftInput.val) * 64 + limb.val) 0 =
        rightPacked.getD ((95 + rightInput.val) * 64 + limb.val) 0)
    (samePosition : projectPosition leftPacked leftInput.val =
      projectPosition rightPacked rightInput.val)
    (sameRho : ∀ limb : Fin 4,
      spongeSourceWord leftPacked (inputNoteFirstCall leftInput) (6 + limb.val) =
        spongeSourceWord rightPacked (inputNoteFirstCall rightInput) (6 + limb.val)) :
    (∀ limb : Fin 7,
      leftPublic.getD (4 + leftInput.val * 7 + limb.val) 0 =
        rightPublic.getD (4 + rightInput.val * 7 + limb.val) 0) ∨
      FramedAuthorizationCollision (selectedMessage leftPacked leftInput)
        (selectedMessage rightPacked rightInput) := by
  rcases accepted_same_note_position_preimage_or_authorization_collision
      leftAccepted rightAccepted leftInput rightInput leftActive rightActive
      sameOwner samePosition sameRho with equal | collision
  · left
    intro limb
    rw [accepted_current_active_public_nullifier leftAccepted leftInput leftActive,
      accepted_current_active_public_nullifier rightAccepted rightInput rightActive, equal]
  · exact Or.inr collision

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureCrossTransaction
