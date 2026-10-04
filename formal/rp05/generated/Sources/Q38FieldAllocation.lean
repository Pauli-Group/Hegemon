import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy

namespace HegemonCrypto.SmallWood.V8Smz9Q38FieldAllocation
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9EagerPrivacy
noncomputable section
set_option autoImplicit false
set_option Elab.async false

/-- Fresh q38 types: these do not reuse q20 tails or DECS coefficient spaces. -/
abbrev Tails (F : Type*) := Fin 140 → Fin 38 → F
abbrev Decs (F : Type*) := Fin 5 → Fin 406 → F
abbrev Remaining (F : Type*) :=
  WitnessInterpolationCoins F × (SourcePcsCoins F × Tails F)
abbrev Joint (F : Type*) := PiopCoefficients F × Decs F
abbrev Roles (F : Type*) := WitnessInterpolationCoins F ×
  (PiopCoefficients F × (SourcePcsCoins F × (Tails F × Decs F)))

def roleAllocation (F : Type*) : (Fin 14811 → F) ≃ Roles F :=
  (splitEquiv 4116 10695 F).trans
    (Equiv.prodCongr (matrixEquiv 686 6 F)
      ((splitEquiv 3105 7590 F).trans
        (Equiv.prodCongr ((alternatingMasksEquiv F).trans (sourceMaskCoefficientEquiv F))
          ((splitEquiv 240 7350 F).trans
            (Equiv.prodCongr (sourcePcsAllocationEquiv F)
              ((splitEquiv 5320 2030 F).trans
                (Equiv.prodCongr (matrixEquiv 140 38 F) (matrixEquiv 5 406 F))))))))

def roleOrder (F : Type*) : Roles F ≃ (Remaining F × Joint F) where
  toFun groups :=
    ((groups.1, groups.2.2.1, groups.2.2.2.1), (groups.2.1, groups.2.2.2.2))
  invFun coins :=
    (coins.1.1, coins.2.1, coins.1.2.1, coins.1.2.2, coins.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

def allocation : RuntimeFieldCoins 14811 ≃ (Remaining Goldilocks × Joint Goldilocks) :=
  (Equiv.piCongrRight fun _ : Fin 14811 => idealFieldCoinEquivGoldilocks).trans
    ((roleAllocation Goldilocks).trans (roleOrder Goldilocks))

theorem q38_ideal_allocation_uniform :
    pmfMap (iidUniformRejectionSamplerOutputPMF 14811) allocation =
      uniformFintypePMF (Remaining Goldilocks × Joint Goldilocks) := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv allocation

/-- The rank boundary adapts to 38 low evaluation coordinates plus 368
retained high coefficients. This equivalence is only coefficient allocation;
the q38 interpolation and full P7 oracle-game transport remain separate. -/
def decsSplit (F : Type*) :
    (Fin 5 → ((Fin 38 → F) × (Fin 368 → F))) ≃ Decs F :=
  Equiv.piCongrRight fun _ : Fin 5 => (splitEquiv 38 368 F).symm

end
end HegemonCrypto.SmallWood.V8Smz9Q38FieldAllocation
