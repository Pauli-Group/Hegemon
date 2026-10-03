import Q38RemainingAlgebra
import Q38MaskFeedback

namespace HegemonCrypto.SmallWood.V8SmzaCompleteAlgebra
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9JointAlgebraicLaw V8Smz9SingleProofPrivacy V8Smz9EagerPrivacy
open V8SmzaMathPrivacy V8SmzaRemainingAlgebra V8SmzaMaskFeedback
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

structure OpeningPlan (F : Type*) [Field F] where
  points : Fin 6 → F
  admissible : Smz9WitnessInterpolationAdmissible points
  nonzero : ∀ i, points i ≠ 0
  fallback : Targets points
  choose : WitnessOpeningView F → SourcePcsView F → Earlier F → Option (Targets points)

/-- Dependency order of the actual algebraic protocol. PIOP's unmasked
    polynomial can depend on witness interpolation coins and D, but not PCS
    coins or LVCS tapes. Q then fixes committed heads and PCS base columns.
    Plans depend only on the public D/PIOP output. These are typed functional
    dependencies, not assumptions of distribution equality. -/
structure Model (F : Type*) [Field F] where
  values : WitnessPackingValues F
  gamma : Gamma F
  piopUnmasked : WitnessInterpolationCoins F → Decs F → PiopCoefficients F
  heads : WitnessInterpolationCoins F → SourcePcsCoins F → PiopCoefficients F → Heads F
  pcsBase : WitnessInterpolationCoins F → PiopCoefficients F → Decs F → SourcePcsView F
  plan : MaskOutputs F → Option (OpeningPlan F)

abbrev PublicView (F : Type*) := MaskOutputs F × Option (PartialView F)

def sourceOpening {F : Type*} [Field F] (model : Model F)
    (output : MaskOutputs F) (coins : RemainingCoins F) (q : PiopCoefficients F) :
    Option (PartialView F) :=
  (model.plan output).map fun plan =>
    partialChronologicalView model.values plan.points
      (fun witness => model.pcsBase witness q output.1)
      (fun witness pcs => model.heads witness pcs q) plan.choose coins

def recoveredQ {F : Type*} [Field F] (model : Model F)
    (output : MaskOutputs F) (witness : WitnessInterpolationCoins F) : PiopCoefficients F :=
  output.2 - model.piopUnmasked witness output.1

def afterPublicOpening {F : Type*} [Field F] (model : Model F)
    (output : MaskOutputs F) (coins : RemainingCoins F) : Option (PartialView F) :=
  (model.plan output).map fun plan =>
    partialChronologicalView model.values plan.points
      (fun witness => model.pcsBase witness (recoveredQ model output witness) output.1)
      (fun witness pcs => model.heads witness pcs (recoveredQ model output witness))
      plan.choose coins

theorem recovered_opening_is_source {F : Type*} [Field F] (model : Model F)
    (output : MaskOutputs F) (coins : RemainingCoins F) :
    sourceOpening model output coins (recoveredQ model output coins.1) =
      afterPublicOpening model output coins := rfl

def source {F : Type*} [Field F] [Fintype F] (model : Model F) : PMF (PublicView F) :=
  (uniformFintypePMF (RemainingCoins F)).bind fun coins =>
    (uniformFintypePMF (MaskCoins F)).bind fun masks =>
      let output := forward model.gamma (model.heads coins.1 coins.2.1) coins.2.2
        (model.piopUnmasked coins.1) masks
      PMF.pure (output, sourceOpening model output coins masks.1)

/-- Only the public plan is an input. No private values, masks, quotient
    offsets, heads or witness search occurs in this simulator. -/
def simulate {F : Type*} [Field F] [Fintype F]
    (plan : MaskOutputs F → Option (OpeningPlan F)) : PMF (PublicView F) :=
  (uniformFintypePMF (MaskOutputs F)).bind fun output =>
    pmfMap (uniformFintypePMF (RemainingView F)) fun view =>
      (output, (plan output).map fun p => abortProjection p.choose view)

theorem source_masks_first_transport {F : Type*} [Field F] [Fintype F] (model : Model F) :
    source model = (uniformFintypePMF (MaskOutputs F)).bind fun output =>
      pmfMap (uniformFintypePMF (RemainingCoins F)) fun coins =>
        (output, afterPublicOpening model output coins) := by
  unfold source
  have transported :
      ((uniformFintypePMF (RemainingCoins F)).bind fun coins =>
        (uniformFintypePMF (MaskCoins F)).bind fun masks =>
          let output := forward model.gamma (model.heads coins.1 coins.2.1) coins.2.2
            (model.piopUnmasked coins.1) masks
          PMF.pure (output, sourceOpening model output coins masks.1)) =
      ((uniformFintypePMF (RemainingCoins F)).bind fun coins =>
        (uniformFintypePMF (MaskOutputs F)).bind fun output =>
          PMF.pure (output, afterPublicOpening model output coins)) := by
    apply congrArg (PMF.bind (uniformFintypePMF (RemainingCoins F)))
    funext coins
    have step := q38_mask_transport_retains_coins model.gamma
      (model.heads coins.1 coins.2.1) coins.2.2 (model.piopUnmasked coins.1)
      (fun masks output => PMF.pure (output, sourceOpening model output coins masks.1))
    have opening : ∀ output, sourceOpening model output coins
        (output.2 - model.piopUnmasked coins.1 output.1) = afterPublicOpening model output coins :=
      fun output => recovered_opening_is_source model output coins
    simpa only [inverse, opening] using step
  rw [transported, PMF.bind_comm]
  rfl

theorem q38_complete_joint_algebraic_simulator {F : Type*} [Field F] [Fintype F]
    (model : Model F) : source model = simulate model.plan := by
  rw [source_masks_first_transport]
  unfold simulate
  apply congrArg (PMF.bind (uniformFintypePMF (MaskOutputs F)))
  funext output
  cases selected : model.plan output with
  | none =>
    simp [afterPublicOpening, selected, pmfMap, Function.comp_def]
  | some plan =>
    have law := remaining_partial_joint_law model.values plan.points plan.admissible plan.nonzero
      (fun witness => model.pcsBase witness (recoveredQ model output witness) output.1)
      (fun witness pcs => model.heads witness pcs (recoveredQ model output witness))
      plan.fallback plan.choose
    have pushed := congrArg (fun p => pmfMap p (fun view => (output, some view))) law
    simp only [pmfMap_comp] at pushed
    simpa only [afterPublicOpening, selected, Option.map_some, Function.comp_def] using pushed

/-- Joint public D, PIOP transcript, witness openings, PCS openings, LVCS
    openings and both public sampler-abort levels survive every continuation. -/
theorem q38_complete_joint_continuation {F Output : Type*} [Field F] [Fintype F]
    (model : Model F) (next : PublicView F → PMF Output) :
    (source model).bind next = (simulate model.plan).bind next := by
  rw [q38_complete_joint_algebraic_simulator]

end
end HegemonCrypto.SmallWood.V8SmzaCompleteAlgebra
