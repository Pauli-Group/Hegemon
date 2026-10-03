import SmzaRp05AuthorizationClosureTags

/-! Accepted Approval chooses a fresh signer slot whose complete policy tag
is the source-live SingleKey digest. The selected slot is derived from the
actual Boolean/one-hot roots rather than supplied to the endpoint. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTagsExistence

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTags
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option autoImplicit false

theorem local_approval_has_selected_slot {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1) :
    ∃ slot : Fin 6, (rows.getD (membershipRow slot) 0 : Goldilocks) = 1 := by
  classical
  by_contra noSlot
  have notSelected : ∀ slot : Fin 6,
      (rows.getD (membershipRow slot) 0 : Goldilocks) ≠ 1 := by
    simpa only [not_exists] using noSlot
  have zero (slot : Fin 6) :
      (rows.getD (membershipRow slot) 0 : Goldilocks) = 0 := by
    have boolean := semantic (.membershipBoolean slot)
    simp only [localCheckTerm, SourceTerm.eval, approvalSelected, one_mul] at boolean
    rcases mul_eq_zero.mp boolean with hzero | hone
    · exact hzero
    · exact (notSelected slot (sub_eq_zero.mp hone)).elim
  have oneHot := semantic .membershipOneHot
  change (rows.getD approvalRow 0 : Goldilocks) *
    ((rows.getD (membershipRow 5) 0 : Goldilocks) +
      ((rows.getD (membershipRow 4) 0 : Goldilocks) +
        ((rows.getD (membershipRow 3) 0 : Goldilocks) +
          ((rows.getD (membershipRow 2) 0 : Goldilocks) +
            ((rows.getD (membershipRow 0) 0 : Goldilocks) +
              (rows.getD (membershipRow 1) 0 : Goldilocks))))) - 1) = 0 at oneHot
  rw [approvalSelected, zero 5, zero 4, zero 3, zero 2, zero 0, zero 1] at oneHot
  norm_num at oneHot

theorem local_selected_slot_fresh {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (slot : Fin 6)
    (selected : (rows.getD (membershipRow slot) 0 : Goldilocks) = 1) :
    (rows.getD (approvedRow slot) 0 : Goldilocks) = 0 := by
  have fresh := semantic (.membershipFresh slot)
  simpa only [localCheckTerm, SourceTerm.eval, approvalSelected, selected,
    one_mul, mul_one] using fresh

private theorem lane_zero_row (packed : List Nat) (row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed 0).getD row 0 =
      packed.getD (row * 64) 0 := by
  simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound,
    packingFactor]

/-- The accepted equations themselves provide a fresh selected slot with
all seven policy words bound to the semantic digest of the accepted key. -/
theorem accepted_approval_has_fresh_semantic_signer
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (approvalSelected : packed.getD (93 * 64) 0 = 1) :
    ∃ slot : Fin 6,
      packed.getD ((206 + slot.val) * 64) 0 = 1 ∧
      packed.getD ((139 + slot.val) * 64) 0 = 0 ∧
      ∀ limb : Fin 7,
        packed.getD ((164 + 7 * slot.val + limb.val) * 64) 0 =
          (LiveAuthorizationInput.digest
            (.singleKey (acceptedGlobalKey packed))).getD limb.val 0 := by
  have semantic := packed_program_implies_local_semantics
    HegemonCrypto.SmallWood.SmzaRp05LocalCertificate.certificate accepted 0
  have approval : ((packedWitnessLaneRows packed 0).getD approvalRow 0 : Goldilocks) = 1 := by
    rw [lane_zero_row packed approvalRow (by decide)]
    simpa [approvalRow] using congrArg (fun n : Nat => (n : Goldilocks)) approvalSelected
  obtain ⟨slot, selected⟩ := local_approval_has_selected_slot semantic approval
  have fresh := local_selected_slot_fresh semantic approval slot selected
  change ((packedWitnessLaneRows packed 0).getD (membershipRow slot) 0 : Goldilocks) = 1
    at selected
  change ((packedWitnessLaneRows packed 0).getD (approvedRow slot) 0 : Goldilocks) = 0
    at fresh
  rw [lane_zero_row packed (membershipRow slot) (by
    have bound := slot.isLt
    simp [membershipRow, relationRowCount]
    omega)] at selected
  rw [lane_zero_row packed (approvedRow slot) (by
    have bound := slot.isLt
    simp [approvedRow, relationRowCount]
    omega)] at fresh
  have selectedNat : packed.getD ((206 + slot.val) * 64) 0 = 1 :=
    canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 ((206 + slot.val) * 64))
      (by decide) selected
  have freshNat : packed.getD ((139 + slot.val) * 64) 0 = 0 :=
    canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 ((139 + slot.val) * 64))
      (by decide) fresh
  exact ⟨slot, selectedNat, freshNat,
    accepted_selected_policy_tag_eq_semantic_single_key_digest
      accepted approvalSelected slot selectedNat⟩

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTagsExistence
