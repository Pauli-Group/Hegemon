import Q38Rp05ChronologicalAlgebra
import Q38Rp05WholePrivacy
import HegemonCrypto.SmallWoodV8Smz9CurrentProgramOpeningBinding
import HegemonCrypto.SmallWoodV8Smz9SingleProofPrivacy

/-!
# RP05 public-head finite-index bridge

This module isolates only the Fin 6 / Fin piopOpeningCount cast and the
definitional PCS-base identification used after the source-mask equality has
already been established.  It does not assert that the RP05 DSL's masks have
that source interpretation.
-/

namespace HegemonCrypto.SmallWood.Q38Rp05PublicHeadIndexBridge

open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge

noncomputable section
set_option autoImplicit false

def rp05PiopPoints (points : Fin 6 → Goldilocks) :
    Fin piopOpeningCount → Goldilocks :=
  fun opening => points (Fin.cast (by rfl : piopOpeningCount = 6) opening)

theorem rp05_piop_points_cast_eq (points : Fin 6 → Goldilocks) :
    rp05PiopPoints points = (fun opening : Fin piopOpeningCount => points opening) := by
  funext opening
  apply congrArg points
  apply Fin.ext
  rfl

theorem rp05_piop_points_eq_fin6 (points : Fin 6 → Goldilocks) :
    rp05PiopPoints points = points := by
  have hCount : piopOpeningCount = 6 := by rfl
  cases hCount
  funext opening
  apply congrArg points
  apply Fin.ext
  rfl

theorem rp05_public_combination_heads_fin6_cast
    (points : Fin 6 → Goldilocks) (heads : LvcsCommittedHeads Goldilocks) :
    lvcsPublicCombinationHeads (rp05PiopPoints points) heads =
    lvcsPublicCombinationHeads (fun opening : Fin piopOpeningCount => points opening)
        heads := by
  rw [rp05_piop_points_cast_eq]

theorem rp05_pcs_base_is_physical_partial_base
    (points : Fin 6 → Goldilocks) (masks : Q) :
    pcsBase points masks 0 = physicalPartialBase points masks := by
  rfl

end
end HegemonCrypto.SmallWood.Q38Rp05PublicHeadIndexBridge
