import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout

/-!
# Joint SMZ9 algebraic output law at fixed challenges

The input distribution below is the proved ideal rejection-sampler law. It is allocated to the
existing six honest field-coin roles, then passed through the existing six exact algebraic maps
with fixed secret offsets. The complete joint output distribution is uniform, and hence equal
for every pair of fixed secret offsets. This proves equality of the full algebraic vector, not
only equality of its separate marginal distributions.

The challenge points and their admissibility proofs are explicit fixed parameters. This file
does not condition an actual transcript on its sampled challenges, and does not claim such
conditioning preserves uniform coins. Integrating this calculation into the real sequential
protocol still requires its challenge/coin dependencies and transcript interaction to be proved.
The result contains no salt or leaf tapes, no OS-source or Rust-execution refinement, no oracle
programming claim, and no quantum or production authority.
-/

namespace HegemonCrypto.SmallWood.V8Smz9JointAlgebraicLaw

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout

/-- The complete six-role algebraic output, in the same role order as the honest coins. -/
abbrev JointAlgebraicView (F : Type*) :=
  WitnessOpeningView F ×
    PcsPartialEvaluationView F ×
    NonlinearPiopView F ×
    LinearPiopView F ×
    LvcsJointTailView F ×
    DecsEvaluationHighView F

/-- Affine output map with its explicit inverse: subtract the offset, then invert the map. -/
def affineOutputEquiv
    {Coins View : Type*} [AddCommGroup Coins] [AddCommGroup View]
    (map : Coins ≃+ View) (secret : View) : Coins ≃ View where
  toFun := transformedAffineView map secret
  invFun output := map.symm (output - secret)
  left_inv coins := by
    change map.symm (secret + map coins - secret) = coins
    have cancel : secret + map coins - secret = map coins := by abel
    rw [cancel]
    exact map.symm_apply_apply coins
  right_inv output := by
    change secret + map (map.symm (output - secret)) = output
    rw [map.apply_symm_apply]
    abel

/-- Product of all six affine maps; no coordinate or correlation is omitted. -/
def jointAffineOutputEquiv
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F) (secret : JointAlgebraicView F) :
    Smz9HonestAlgebraicCoins F ≃ JointAlgebraicView F :=
  Equiv.prodCongr
    (affineOutputEquiv maps.witnessInterpolationTransform secret.1)
    (Equiv.prodCongr
      (affineOutputEquiv maps.pcsUnstackTransform secret.2.1)
      (Equiv.prodCongr
        (affineOutputEquiv maps.nonlinearPiopTransform secret.2.2.1)
        (Equiv.prodCongr
          (affineOutputEquiv maps.linearPiopTransform secret.2.2.2.1)
          (Equiv.prodCongr
            (affineOutputEquiv maps.lvcsJointTailTransform secret.2.2.2.2.1)
            (affineOutputEquiv maps.decsEvaluationHighTransform secret.2.2.2.2.2)))))

/-- The joint equivalence applies exactly the existing source-formula affine maps. -/
theorem joint_output_has_all_six_coordinates
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F) (secret : JointAlgebraicView F)
    (coins : Smz9HonestAlgebraicCoins F) :
    jointAffineOutputEquiv maps secret coins =
      (transformedAffineView maps.witnessInterpolationTransform secret.1 coins.1,
        transformedAffineView maps.pcsUnstackTransform secret.2.1 coins.2.1,
        transformedAffineView maps.nonlinearPiopTransform secret.2.2.1 coins.2.2.1,
        transformedAffineView maps.linearPiopTransform secret.2.2.2.1 coins.2.2.2.1,
        transformedAffineView maps.lvcsJointTailTransform secret.2.2.2.2.1 coins.2.2.2.2.1,
        transformedAffineView maps.decsEvaluationHighTransform secret.2.2.2.2.2
          coins.2.2.2.2.2) := rfl

noncomputable local instance : Fintype Goldilocks :=
  Fintype.ofEquiv IdealFieldCoin idealFieldCoinEquivGoldilocks

/-- Use the exact input enumeration already used by the field-layout law. -/
noncomputable local instance : Fintype (Smz9HonestAlgebraicCoins Goldilocks) :=
  Fintype.ofEquiv (RuntimeFieldCoins honestAlgebraicFieldCoinCount) runtimeFieldLayoutEquiv

/--
For fixed maps and offsets, the rejection-generated complete algebraic output equals a uniformly
sampled output vector. The result supplies the equality; no output-law equality is a premise.
-/
theorem joint_algebraic_output_law
    (maps : Smz9AlgebraicHidingMaps Goldilocks) (secret : JointAlgebraicView Goldilocks) :
    pmfMap (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)
        ((jointAffineOutputEquiv maps secret) ∘ runtimeFieldLayoutEquiv) =
      uniformFintypePMF (JointAlgebraicView Goldilocks) := by
  rw [← pmfMap_comp, exact_smz9_honest_algebraic_coin_law]
  exact uniform_pmf_map_equiv (jointAffineOutputEquiv maps secret)

/-- Instantiate the joint law with the six existing exact maps at fixed admissible challenges. -/
theorem exact_fixed_challenge_joint_algebraic_law
    (piopPoints : Fin piopOpeningCount → Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible piopPoints)
    (pcsAdmissible : Smz9PcsUnstackAdmissible piopPoints)
    (linearAdmissible : Smz9LinearPiopAdmissible piopPoints)
    (decsPoints : Fin decsOpeningCount → Goldilocks)
    (lvcsAdmissible : Smz9LvcsTailAdmissible piopPoints decsPoints)
    (secret : JointAlgebraicView Goldilocks) :
    let maps := (smz9HonestAlgebraicMapRefinementOfExactMaps
      piopPoints witnessAdmissible pcsAdmissible linearAdmissible decsPoints lvcsAdmissible).maps
    pmfMap (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)
        ((jointAffineOutputEquiv maps secret) ∘ runtimeFieldLayoutEquiv) =
      uniformFintypePMF (JointAlgebraicView Goldilocks) := by
  exact joint_algebraic_output_law _ secret

/--
Witness-dependent fixed offsets do not change the complete algebraic law at the same fixed
admissible challenge points. This corollary does not quantify over an actual transcript sampler.
-/
theorem fixed_challenge_secret_independence
    (piopPoints : Fin piopOpeningCount → Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible piopPoints)
    (pcsAdmissible : Smz9PcsUnstackAdmissible piopPoints)
    (linearAdmissible : Smz9LinearPiopAdmissible piopPoints)
    (decsPoints : Fin decsOpeningCount → Goldilocks)
    (lvcsAdmissible : Smz9LvcsTailAdmissible piopPoints decsPoints)
    (leftSecret rightSecret : JointAlgebraicView Goldilocks) :
    let maps := (smz9HonestAlgebraicMapRefinementOfExactMaps
      piopPoints witnessAdmissible pcsAdmissible linearAdmissible decsPoints lvcsAdmissible).maps
    pmfMap (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)
        ((jointAffineOutputEquiv maps leftSecret) ∘ runtimeFieldLayoutEquiv) =
      pmfMap (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)
        ((jointAffineOutputEquiv maps rightSecret) ∘ runtimeFieldLayoutEquiv) := by
  exact (joint_algebraic_output_law _ leftSecret).trans
    (joint_algebraic_output_law _ rightSecret).symm

end HegemonCrypto.SmallWood.V8Smz9JointAlgebraicLaw
