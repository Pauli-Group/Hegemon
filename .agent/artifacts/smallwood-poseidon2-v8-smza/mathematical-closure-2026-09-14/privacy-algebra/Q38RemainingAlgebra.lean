import Q38JointSimulatorR2
import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy

namespace HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9JointAlgebraicLaw V8Smz9SingleProofPrivacy
open V8Smz9EagerPrivacy V8SmzaMathPrivacy
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

/-- Unchanged6-point witness/PCS coins, followed by actual38-tail coins. -/
abbrev RemainingCoins (F : Type*) :=
  WitnessInterpolationCoins F × (SourcePcsCoins F × Tails F)
abbrev RemainingView (F : Type*) :=
  WitnessOpeningView F × (SourcePcsView F × (Earlier F × Later F))

/-- The inverse recovers witness coins, then actual triangular PCS coins,
    then38-tail coins. All challenge selection depends on earlier PUBLIC
    outputs; no desired distribution equality is a parameter. -/
def remainingEquiv {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Targets points) :
    RemainingCoins F ≃ RemainingView F :=
  let witnessEquiv := sourceWitnessOpeningEquiv values points witnessAdmissible
  (Equiv.prodCongr witnessEquiv (Equiv.refl _)).trans
    (Equiv.prodCongrRight fun witnessView =>
      let witnessCoins := witnessEquiv.symm witnessView
      let pcsEquiv := sourceAffinePcsEquiv points witnessAdmissible.openingPointsInjective
        pointsNonzero (pcsBase witnessCoins)
      (Equiv.prodCongr pcsEquiv (Equiv.refl _)).trans
        (Equiv.prodCongrRight fun pcsView =>
          V8SmzaMathPrivacy.exactLvcsChallengeFeedbackEquiv points
            (heads witnessCoins (pcsEquiv.symm pcsView)) (choose witnessView pcsView)))

def chronologicalView {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Targets points)
    (coins : RemainingCoins F) : RemainingView F :=
  let witnessView := sourceWitnessOpenings values points coins.1
  let pcsView := sourcePcsFullView points (pcsBase coins.1) coins.2.1
  let early := earlier points coins.2.2
  (witnessView, pcsView, early,
    fullSubset (heads coins.1 coins.2.1) coins.2.2 (choose witnessView pcsView early).val)

theorem remaining_equiv_is_chronological {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Targets points)
    (coins : RemainingCoins F) :
    remainingEquiv values points witnessAdmissible pointsNonzero pcsBase heads choose coins =
      chronologicalView values points pcsBase heads choose coins := by
  rcases coins with ⟨witnessCoins, pcsCoins, tailCoins⟩
  simp only [remainingEquiv, Equiv.trans_apply, Equiv.prodCongr_apply,
    Prod.map_apply, Equiv.refl_apply, Equiv.prodCongrRight_apply, Equiv.symm_apply_apply]
  simp only [V8SmzaMathPrivacy.exact_lvcs_feedback_matches_chronological_output,
    source_witness_opening_equiv_matches_polynomials, source_affine_pcs_equiv_apply,
    chronologicalView]

/-- Joint4116 witness openings +240 actual PCS words +5320 LVCS words. -/
theorem remaining_chronological_joint_uniform {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Targets points) :
    pmfMap (uniformFintypePMF (RemainingCoins F))
      (chronologicalView values points pcsBase heads choose) =
      uniformFintypePMF (RemainingView F) := by
  have law := uniform_pmf_map_equiv
    (remainingEquiv values points witnessAdmissible pointsNonzero pcsBase heads choose)
  have same : (remainingEquiv values points witnessAdmissible pointsNonzero pcsBase heads choose :
      RemainingCoins F → RemainingView F) = chronologicalView values points pcsBase heads choose := by
    funext coins
    exact remaining_equiv_is_chronological values points witnessAdmissible pointsNonzero
      pcsBase heads choose coins
  rw [same] at law
  exact law

abbrev PartialView (F : Type*) :=
  WitnessOpeningView F × (SourcePcsView F × (Earlier F × Option (Later F)))

def partialChronologicalView {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Option (Targets points))
    (coins : RemainingCoins F) : PartialView F :=
  let witnessView := sourceWitnessOpenings values points coins.1
  let pcsView := sourcePcsFullView points (pcsBase coins.1) coins.2.1
  (witnessView, pcsView, V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput points
    (heads coins.1 coins.2.1) (choose witnessView pcsView) coins.2.2)

def abortProjection {F : Type*} [Field F] {points : Fin 6 → F}
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Option (Targets points))
    (view : RemainingView F) : PartialView F :=
  (view.1, view.2.1, view.2.2.1, (choose view.1 view.2.1 view.2.2.1).map fun _ => view.2.2.2)

/-- Includes a failed final selector, with all earlier outputs retained. -/
theorem remaining_partial_joint_law {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → Heads F)
    (fallback : Targets points)
    (choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Option (Targets points)) :
    pmfMap (uniformFintypePMF (RemainingCoins F))
      (partialChronologicalView values points pcsBase heads choose) =
      pmfMap (uniformFintypePMF (RemainingView F)) (abortProjection choose) := by
  let totalChoose := fun witnessView pcsView early => (choose witnessView pcsView early).getD fallback
  have uniform := remaining_chronological_joint_uniform values points witnessAdmissible
    pointsNonzero pcsBase heads totalChoose
  have pushed := congrArg (fun law => pmfMap law (abortProjection choose)) uniform
  rw [pmfMap_comp] at pushed
  have same : abortProjection choose ∘ chronologicalView values points pcsBase heads totalChoose =
      partialChronologicalView values points pcsBase heads choose := by
    funext coins
    cases selected : choose (sourceWitnessOpenings values points coins.1)
        (sourcePcsFullView points (pcsBase coins.1) coins.2.1) (earlier points coins.2.2) with
    | none =>
      simp [abortProjection, chronologicalView, partialChronologicalView,
        V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput, selected]
    | some targets =>
      simp [abortProjection, chronologicalView, partialChronologicalView,
        V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput, totalChoose, selected]
  rw [same] at pushed
  exact pushed

end
end HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
