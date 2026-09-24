import HegemonCrypto.SmallWoodV8Smz9SourceRoleCsrFieldTerms

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrSymbolic

open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

def fieldUnit (limb : Nat) : F := if limb = 0 then 1 else 0

/-- The exact stable-role extra terms after evaluating their actual DAG coefficients. -/
def stableExtraContribution (pub rowField : Nat → F) (role limb : Nat) : F :=
  if role < 5 then
    -liveEnabled pub * rowField (41408 + roleCommitmentStart role + limb)
  else if role < 15 then
    -liveEnabled pub * rowField (41408 + roleCommitmentStart (rolePair role).1 + limb) +
      liveEnabled pub * rowField (41408 + roleCommitmentStart (rolePair role).2 + limb)
  else if role = 15 then -liveMint pub * rowField (41491 + limb)
  else if role = 16 then 0
  else if role = 17 ∨ role = 18 then
    (if limb = 0 then -liveMint pub else 0) * rowField (41425 + (role - 17))
  else if role = 19 then
    (if limb = 0 then -liveEnabled pub else 0) * rowField 41408
  else 0

def stableTargetValue (pub : Nat → F) (role limb : Nat) : F :=
  if role < 15 then (1 - liveEnabled pub) * fieldUnit limb
  else if role = 15 then (1 - liveMint pub) * fieldUnit limb
  else if role = 16 then (1 - liveEnabled pub + pub 86 * liveEnabled pub) * fieldUnit limb
  else if role = 17 ∨ role = 18 then (1 - liveMint pub) * fieldUnit limb
  else if role = 19 then (1 - liveEnabled pub) * fieldUnit limb
  else liveEnabled pub * pub (87 + limb) + (1 - liveEnabled pub) * fieldUnit limb

theorem stable_extra_terms_symbolic (pub rowField : Nat → F)
    (role : Fin 21) (limb : Nat) :
    fieldTermSum pub rowField (liveRoleExtraTerms role.val limb) =
      stableExtraContribution pub rowField role.val limb := by
  fin_cases role <;> by_cases zero : limb = 0 <;>
    simp [liveRoleExtraTerms,stableExtraContribution,fieldTermSum,zero]

theorem stable_target_symbolic (pub : Nat → F) (role : Fin 21) (limb : Fin 7) :
    actualCsrCoefficients pub (liveRoleTarget role.val limb.val) =
      stableTargetValue pub role.val limb.val := by
  fin_cases role <;> fin_cases limb <;>
    simp [liveRoleTarget,stableTargetValue,fieldUnit] <;> ring

theorem stable_role_field_kernel_symbolic (pub rowField : Nat → F)
    (role : Fin 21) (limb : Fin 7) :
    roleCsrFieldKernel pub rowField role.val limb.val =
      rowField (41536 + role.val + 64 * limb.val) +
        stableExtraContribution pub rowField role.val limb.val -
        stableTargetValue pub role.val limb.val := by
  rw [roleCsrFieldKernel,stable_extra_terms_symbolic,stable_target_symbolic]


end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrSymbolic
