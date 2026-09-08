import HegemonCrypto.SmallWoodV8Smz9SourceRoleCsrFieldTerms

namespace HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrSymbolic

open HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

/-- Symbolic interpretation of all actual extra terms for roles 21..29.
No constructor or witness occurs in this layer. -/
def parentRoleExtraContribution (pub rowField : Nat → F) (offset limb : Nat) : F :=
  if offset = 0 then
    if limb < 4 then
      -(pub 0 * liveAnyInput pub) * rowField (41520 + limb) +
      -(pub 1 * (1 - pub 0) * liveAnyInput pub) * rowField (41524 + limb)
    else 0
  else if offset = 1 then
    -rowField ((138 + limb) * 64) +
      (if limb = 0 then rowField 5952 + rowField 6016 else 0)
  else if offset = 2 then
    -rowField ((145 + limb) * 64) +
      (if limb = 0 then rowField 5952 + rowField 6016 else 0)
  else
    -(if limb < 5 then rowField ((196 + 5 * (offset - 3) + limb) * 64) else 0) +
      (if limb = 0 then
        ((List.range (6 - (offset - 3))).map fun index =>
          rowField ((176 + (offset - 3) + index) * 64)).sum
       else 0)

def parentRoleTargetContribution (pub : Nat → F) (offset limb : Nat) : F :=
  if offset = 0 then (if limb = 0 then 1 - liveAnyInput pub else 0)
  else if limb = 0 then 1 else 0

/-- Finite case splitting is confined to an abstract row function, not a candidate. -/
theorem parent_role_extra_sum_shape (pub rowField : Nat → F)
    (offset : Fin 9) (limb : Nat) :
    fieldTermSum pub rowField (liveRoleExtraTerms (21 + offset.val) limb) =
      parentRoleExtraContribution pub rowField offset.val limb := by
  fin_cases offset <;>
    by_cases zero : limb = 0 <;>
    by_cases low4 : limb < 4 <;>
    by_cases low5 : limb < 5
  all_goals simp [fieldTermSum, liveRoleExtraTerms, parentRoleExtraContribution,
    zero, low4, low5, List.map_map, Function.comp_def]

theorem parent_role_target_shape (pub : Nat → F) (offset : Fin 9) (limb : Nat) :
    actualCsrCoefficients pub (liveRoleTarget (21 + offset.val) limb) =
      parentRoleTargetContribution pub offset.val limb := by
  fin_cases offset <;> by_cases zero : limb = 0 <;>
    simp [liveRoleTarget, parentRoleTargetContribution, zero]

theorem parent_role_field_kernel_shape (pub rowField : Nat → F)
    (offset : Fin 9) (limb : Nat) :
    roleCsrFieldKernel pub rowField (21 + offset.val) limb =
      rowField (41536 + (21 + offset.val) + 64 * limb) +
      parentRoleExtraContribution pub rowField offset.val limb -
      parentRoleTargetContribution pub offset.val limb := by
  rw [roleCsrFieldKernel, parent_role_extra_sum_shape, parent_role_target_shape]


end
end HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrSymbolic
