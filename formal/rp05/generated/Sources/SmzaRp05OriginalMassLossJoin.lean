import SmzaRp05CurrentAuthorizationCertificate

/-! Add extraction and primitive losses on one original outcome measure.
No normalization, independence, or conditioning on acceptance is required.
This arithmetic helper does not construct the original execution or derive
the two extraction bounds; the concrete joint consumer must do that. -/
namespace HegemonCrypto.SmallWood.SmzaRp05OriginalMassLossJoin

open SmzaRp05CurrentAuthorizationCertificate (outcomeEventMass)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

theorem outcome_mass_union_le_add
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (left right : Outcome → Prop) :
    outcomeEventMass mass (fun outcome => left outcome ∨ right outcome) ≤
      outcomeEventMass mass left + outcomeEventMass mass right := by
  classical
  unfold outcomeEventMass
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro outcome _
  by_cases leftOccurs : left outcome <;>
    by_cases rightOccurs : right outcome <;>
    simp [leftOccurs, rightOccurs, nonnegative outcome]

/-- The two extraction losses and the primitive failure use the same original
finite weights. In particular, failed or rejected outcomes need not be removed
from the outcome space and the weights need not sum to one. -/
theorem three_original_mass_losses_below_129
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (firstFailure secondFailure primitiveFailure : Outcome → Prop)
    (epsilon : ℝ)
    (firstBound : outcomeEventMass mass firstFailure <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ))
    (secondBound : outcomeEventMass mass secondFailure <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ))
    (primitiveBound : outcomeEventMass mass primitiveFailure ≤ epsilon) :
    outcomeEventMass mass (fun outcome =>
      firstFailure outcome ∨ secondFailure outcome ∨ primitiveFailure outcome) <
        ((1 / (2 : Rat) ^ 129 : Rat) : ℝ) + epsilon := by
  have inner := outcome_mass_union_le_add mass nonnegative
    secondFailure primitiveFailure
  have outer := outcome_mass_union_le_add mass nonnegative firstFailure
    (fun outcome => secondFailure outcome ∨ primitiveFailure outcome)
  have arithmetic :
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) +
          ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) =
        ((1 / (2 : Rat) ^ 129 : Rat) : ℝ) := by norm_num
  linarith

end
end HegemonCrypto.SmallWood.SmzaRp05OriginalMassLossJoin
