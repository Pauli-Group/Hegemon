import SmzaRp05LocalCertificate

/-! Selector exhaustiveness for each accepted RP05 packed witness lane.
    This proves only the three mode selectors are Boolean and one-hot. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedModeExhaustiveness

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05LocalCertificate
open HegemonCrypto.SmallWood.SmzaRp05Components

set_option autoImplicit false

private theorem three_one_hot_cases (s a f : Goldilocks)
    (sBool : s = 0 ∨ s = 1) (aBool : a = 0 ∨ a = 1)
    (fBool : f = 0 ∨ f = 1) (total : s + (a + f) = 1) :
    (s = 1 ∧ a = 0 ∧ f = 0) ∨
      (s = 0 ∧ a = 1 ∧ f = 0) ∨
      (s = 0 ∧ a = 0 ∧ f = 1) := by
  rcases sBool with hs | hs <;> rcases aBool with ha | ha <;>
    rcases fBool with hf | hf <;> simp_all;
      exact (show (2 : Goldilocks) ≠ 0 by decide) total

theorem accepted_mode_selectors_exhaustive
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (lane : Fin 64) :
    let rows := packedWitnessLaneRows packed lane.val
    (((rows.getD singleRow 0 : Goldilocks) = 0 ∨
        (rows.getD singleRow 0 : Goldilocks) = 1) ∧
      ((rows.getD approvalRow 0 : Goldilocks) = 0 ∨
        (rows.getD approvalRow 0 : Goldilocks) = 1) ∧
      ((rows.getD finalRow 0 : Goldilocks) = 0 ∨
        (rows.getD finalRow 0 : Goldilocks) = 1)) ∧
    ((rows.getD singleRow 0 : Goldilocks) = 1 ∧
        (rows.getD approvalRow 0 : Goldilocks) = 0 ∧
        (rows.getD finalRow 0 : Goldilocks) = 0 ∨
      (rows.getD singleRow 0 : Goldilocks) = 0 ∧
        (rows.getD approvalRow 0 : Goldilocks) = 1 ∧
        (rows.getD finalRow 0 : Goldilocks) = 0 ∨
      (rows.getD singleRow 0 : Goldilocks) = 0 ∧
        (rows.getD approvalRow 0 : Goldilocks) = 0 ∧
        (rows.getD finalRow 0 : Goldilocks) = 1) := by
  dsimp
  let semantic := packed_program_implies_local_semantics certificate accepted lane
  have sBool : ((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) = 0 ∨
      ((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) = 1 := by
    have h := semantic (.modeBoolean ⟨0, by decide⟩)
    change ((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) *
      (((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) - 1) = 0 at h
    rcases mul_eq_zero.mp h with hz | hone
    · exact Or.inl hz
    · exact Or.inr (sub_eq_zero.mp hone)
  have aBool : ((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) = 0 ∨
      ((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) = 1 := by
    have h := semantic (.modeBoolean ⟨1, by decide⟩)
    change ((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) *
      (((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) - 1) = 0 at h
    rcases mul_eq_zero.mp h with hz | hone
    · exact Or.inl hz
    · exact Or.inr (sub_eq_zero.mp hone)
  have fBool : ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) = 0 ∨
      ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) = 1 := by
    have h := semantic (.modeBoolean ⟨2, by decide⟩)
    change ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) *
      (((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) - 1) = 0 at h
    rcases mul_eq_zero.mp h with hz | hone
    · exact Or.inl hz
    · exact Or.inr (sub_eq_zero.mp hone)
  have total : ((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) +
      (((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks)) = 1 := by
    have h := semantic .modeOneHot
    change ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) +
      (((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks)) - 1 = 0 at h
    linear_combination h
  exact ⟨⟨sBool, aBool, fBool⟩, three_one_hot_cases _ _ _ sBool aBool fBool total⟩

end HegemonCrypto.SmallWood.SmzaRp05AcceptedModeExhaustiveness
