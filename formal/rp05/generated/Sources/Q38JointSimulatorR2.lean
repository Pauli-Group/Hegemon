import Q38TailRankR2
import HegemonCrypto.SmallWoodV8Smz9HonestHybrid
namespace HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9TriangularAlgebraicLaw V8Smz9JointAlgebraicLaw
open Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev Heads (F : Type*) := Fin 140 → Fin 368 → F
abbrev Earlier (F : Type*) := Fin 12 → Fin 38 → F
abbrev Later (F : Type*) := Fin 38 → Fin 128 → F
abbrev Decs (F : Type*) := Fin 5 → Fin 406 → F
abbrev Gamma (F : Type*) := Fin 5 → Fin 140 → F

def earlier {F : Type*} [Field F] (points : Fin 6 → F) (tails : Tails F) :
    Earlier F := fun combination tail =>
  selectedTailMap points tails combination tail + subsetContribution points tails combination tail

def headContribution {F : Type*} [Field F] (heads : Heads F)
    (targets : Fin 38 → F) : Later F := fun opening subset =>
  ∑ column : Fin 368, heads (smz9LvcsSubsetRow subset) column *
    (Lagrange.basis (Finset.univ : Finset (Fin 406)) (fun node => (node.val : F))
      (Fin.natAdd 38 column)).eval (targets opening)

def fullSubset {F : Type*} [Field F] (heads : Heads F) (tails : Tails F)
    (targets : Fin 38 → F) : Later F :=
  headContribution heads targets + (jointTailMap (fun _ : Fin 6 => (0:F)) targets tails).2

abbrev Targets {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :=
  { targets : Fin q38Openings → F // TailAdmissible points targets }

/-- Actual exact tail map plus the actual committed-head interpolation offset. -/
def exactLvcsFullViewEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (targets : Targets points) :
    Tails F ≃ (Earlier F × Later F) :=
  affineOutputEquiv (jointTailAddEquiv points targets.val targets.property)
    (0, headContribution heads targets.val)

theorem exact_lvcs_full_view_retains_earlier_tails
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (targets : Targets points) (tails : Tails F) :
    (exactLvcsFullViewEquiv points heads targets tails).1 = earlier points tails := by
  change (0 : Earlier F) +
    (jointTailAddEquiv points targets.val targets.property tails).1 = _
  rw [zero_add, joint_tail_add_equiv_apply]
  rfl

theorem exact_lvcs_full_view_later_coordinate
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (targets : Targets points) (tails : Tails F) :
    (exactLvcsFullViewEquiv points heads targets tails).2 =
      fullSubset heads tails targets.val := by
  change headContribution heads targets.val +
    (jointTailAddEquiv points targets.val targets.property tails).2 = _
  rw [joint_tail_add_equiv_apply]
  rfl

/-- The challenge is genuinely computed from these same coins' earlier 456 output words. -/
def exactLvcsChallengeFeedbackEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (chooseTargets : Earlier F → Targets points) :
    Tails F ≃ (Earlier F × Later F) :=
  triangularChallengeEquiv (exactLvcsFullViewEquiv points heads)
    (earlier points) (exact_lvcs_full_view_retains_earlier_tails points heads)
      chooseTargets

theorem exact_lvcs_feedback_matches_chronological_output
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (chooseTargets : Earlier F → Targets points)
    (tails : Tails F) :
    exactLvcsChallengeFeedbackEquiv points heads chooseTargets tails =
      (earlier points tails,
        fullSubset heads tails
          (chooseTargets (earlier points tails)).val) := by
  change exactLvcsFullViewEquiv points heads
    (chooseTargets (earlier points tails)) tails = _
  apply Prod.ext
  · exact exact_lvcs_full_view_retains_earlier_tails points heads _ tails
  · exact exact_lvcs_full_view_later_coordinate points heads _ tails

/-- All 5,320 output words remain jointly uniform with this later-challenge feedback. -/
theorem exact_lvcs_feedback_joint_uniform_law
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (chooseTargets : Earlier F → Targets points) :
    pmfMap (uniformFintypePMF (Tails F))
      (fun tails =>
        (earlier points tails,
          fullSubset heads tails
            (chooseTargets (earlier points tails)).val)) =
      uniformFintypePMF (Earlier F × Later F) := by
  have sameFunction :
      (fun tails =>
        (earlier points tails,
          fullSubset heads tails
            (chooseTargets (earlier points tails)).val)) =
        exactLvcsChallengeFeedbackEquiv points heads chooseTargets := by
    funext tails
    exact (exact_lvcs_feedback_matches_chronological_output points heads chooseTargets tails).symm
  rw [sameFunction]
  exact uniform_pmf_map_equiv (exactLvcsChallengeFeedbackEquiv points heads chooseTargets)

theorem exact_lvcs_feedback_word_counts :
    lvcsOpenedCombinationCount * q38Openings = 456 ∧
      q38Openings * lvcsSubsetRowCount = 4864 ∧
      lvcsRowCount * q38Openings = 5320 := by decide

/-- The fixed DECS sampler can exhaust its candidate pool. Preserve that branch explicitly. -/
def exactLvcsPartialFeedbackOutput {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (chooseTargets : Earlier F → Option (Targets points))
    (tails : Tails F) : Earlier F × Option (Later F) :=
  let early := earlier points tails
  (early, (chooseTargets early).map fun targets =>
    fullSubset heads tails targets.val)

/--
The law includes failure, rather than asserting that conditioning on success is free. The
fallback is only used to construct a bijection on the discarded failure branch; it is never
exposed by either output. The selector may implement any deterministic hash/sampler at fixed
earlier public inputs, provided its successful targets satisfy the stated admissibility.
-/
theorem exact_lvcs_partial_feedback_joint_law
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : Heads F)
    (fallback : Targets points)
    (chooseTargets : Earlier F → Option (Targets points)) :
    pmfMap (uniformFintypePMF (Tails F))
        (exactLvcsPartialFeedbackOutput points heads chooseTargets) =
      pmfMap (uniformFintypePMF (Earlier F × Later F))
        (fun view => (view.1, (chooseTargets view.1).map fun _ => view.2)) := by
  let totalChoose : Earlier F → Targets points :=
    fun early => (chooseTargets early).getD fallback
  let observe : Earlier F × Later F →
      Earlier F × Option (Later F) :=
    fun view => (view.1, (chooseTargets view.1).map fun _ => view.2)
  have uniform := exact_lvcs_feedback_joint_uniform_law points heads totalChoose
  have pushed := congrArg (fun law => pmfMap law observe) uniform
  rw [pmfMap_comp] at pushed
  have sameFunction :
      observe ∘ (fun tails =>
        (earlier points tails,
          fullSubset heads tails
            (totalChoose (earlier points tails)).val)) =
        exactLvcsPartialFeedbackOutput points heads chooseTargets := by
    funext tails
    cases selected : chooseTargets (earlier points tails) with
    | none => simp [observe, exactLvcsPartialFeedbackOutput, selected]
    | some targets =>
      simp [observe, exactLvcsPartialFeedbackOutput,
        totalChoose, selected]
  rw [sameFunction] at pushed
  exact pushed



def unmasked {F : Type*} [Field F] (gamma : Gamma F)
    (heads : Heads F) (tails : Tails F) : Decs F :=
  fun combination coefficient =>
    (Lagrange.interpolate (Finset.univ : Finset (Fin 406))
      (fun node => (node.val : F))
      (fun node => ∑ row : Fin 140, gamma combination row *
        Fin.append (tails row) (heads row) node)).coeff coefficient.val

def response {F : Type*} [Field F] (gamma : Gamma F)
    (heads : Heads F) (tails : Tails F) (mask : Decs F) : Decs F :=
  unmasked gamma heads tails + mask

def responseEquiv {F : Type*} [Field F] (gamma : Gamma F)
    (heads : Heads F) (tails : Tails F) : Decs F ≃ Decs F :=
  affineOutputEquiv (AddEquiv.refl _) (unmasked gamma heads tails)

structure PublicStage where
  points : Fin 6 → Goldilocks
  fallback : Targets points
  choose : Earlier Goldilocks → Option (Targets points)

def realStage (heads : Heads Goldilocks) (stage : Option PublicStage)
    (tails : Tails Goldilocks) :
    Option (Earlier Goldilocks × Option (Later Goldilocks)) :=
  stage.map fun s => exactLvcsPartialFeedbackOutput s.points heads s.choose tails

def simulatedStage (stage : Option PublicStage) (view : TailView Goldilocks) :
    Option (Earlier Goldilocks × Option (Later Goldilocks)) :=
  stage.map fun s => (view.1, (s.choose view.1).map fun _ => view.2)

theorem stage_joint_abort_law (heads : Heads Goldilocks) (stage : Option PublicStage) :
    pmfMap (uniformFintypePMF (Tails Goldilocks)) (realStage heads stage) =
      pmfMap (uniformFintypePMF (TailView Goldilocks)) (simulatedStage stage) := by
  cases stage with
  | none => simp [realStage, simulatedStage, pmfMap, Function.comp_def]
  | some s =>
    have law := exact_lvcs_partial_feedback_joint_law s.points heads s.fallback s.choose
    have mapped := congrArg (fun p => pmfMap p some) law
    simp only [pmfMap_comp] at mapped
    exact mapped

/-- Public state (including auxiliary quantum state if desired) is sampled once.
This model is the randomized-leaf algebraic hybrid, NOT the original oracle game. -/
def realJoint {Base Leaves : Type*} (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → Heads Goldilocks) (gamma : Base → Leaves → Gamma Goldilocks)
    (stage : Base → Leaves → Decs Goldilocks → Option PublicStage) :=
  baseLaw.bind fun base =>
    (uniformFintypePMF (Tails Goldilocks)).bind fun tails =>
      (uniformFintypePMF (Decs Goldilocks)).bind fun mask =>
        leafLaw.bind fun leaves => PMF.pure
          (base, leaves, response (gamma base leaves) (heads base) tails mask,
            realStage (heads base)
              (stage base leaves (response (gamma base leaves) (heads base) tails mask)) tails)

/-- Direct public-only simulator: no heads, witness, witness search, or
asserted distribution equality is an input. Both modeled abort levels remain. -/
def simulateJoint {Base Leaves : Type*} (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (stage : Base → Leaves → Decs Goldilocks → Option PublicStage) :=
  baseLaw.bind fun base => leafLaw.bind fun leaves =>
    (uniformFintypePMF (Decs Goldilocks)).bind fun reply =>
      pmfMap (uniformFintypePMF (TailView Goldilocks))
        (fun view => (base, leaves, reply, simulatedStage (stage base leaves reply) view))

theorem q38_joint_simulator {Base Leaves : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → Heads Goldilocks) (gamma : Base → Leaves → Gamma Goldilocks)
    (stage : Base → Leaves → Decs Goldilocks → Option PublicStage) :
    realJoint baseLaw leafLaw heads gamma stage = simulateJoint baseLaw leafLaw stage := by
  unfold realJoint simulateJoint
  apply congrArg (PMF.bind baseLaw)
  funext base
  simp_rw [PMF.bind_comm (uniformFintypePMF (Decs Goldilocks)) leafLaw]
  rw [PMF.bind_comm (uniformFintypePMF (Tails Goldilocks)) leafLaw]
  apply congrArg (PMF.bind leafLaw)
  funext leaves
  have transport :
      ((uniformFintypePMF (Tails Goldilocks)).bind fun tails =>
        (uniformFintypePMF (Decs Goldilocks)).bind fun mask => PMF.pure
          (base, leaves, response (gamma base leaves) (heads base) tails mask,
            realStage (heads base)
              (stage base leaves (response (gamma base leaves) (heads base) tails mask)) tails)) =
      (uniformFintypePMF (Tails Goldilocks)).bind (fun tails =>
        (uniformFintypePMF (Decs Goldilocks)).bind fun reply => PMF.pure
          (base, leaves, reply, realStage (heads base) (stage base leaves reply) tails)) := by
    apply congrArg (PMF.bind (uniformFintypePMF (Tails Goldilocks)))
    funext tails
    exact V8Smz9HonestHybrid.uniform_translation_preserves_arbitrary_observation
      (responseEquiv (gamma base leaves) (heads base) tails)
      (fun _ reply => PMF.pure
        (base, leaves, reply, realStage (heads base) (stage base leaves reply) tails))
  rw [transport, PMF.bind_comm]
  apply congrArg (PMF.bind (uniformFintypePMF (Decs Goldilocks)))
  funext reply
  have law := congrArg
    (fun p => pmfMap p (fun result => (base, leaves, reply, result)))
    (stage_joint_abort_law (heads base) (stage base leaves reply))
  simp only [pmfMap_comp] at law
  exact law

/-- An arbitrary joint-view-dependent continuation can abort or retain all
prior correlations. Equality was derived before applying this continuation. -/
theorem q38_joint_continuation {Base Leaves Output : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → Heads Goldilocks) (gamma : Base → Leaves → Gamma Goldilocks)
    (stage : Base → Leaves → Decs Goldilocks → Option PublicStage)
    (next : (Base × Leaves × Decs Goldilocks ×
      Option (Earlier Goldilocks × Option (Later Goldilocks))) → PMF Output) :
    (realJoint baseLaw leafLaw heads gamma stage).bind next =
      (simulateJoint baseLaw leafLaw stage).bind next := by
  rw [q38_joint_simulator]

/-- The complete visible round record, including modeled failure. -/
abbrev RoundView (Base Leaves : Type*) := Base × Leaves × Decs Goldilocks ×
  Option (Earlier Goldilocks × Option (Later Goldilocks))

def roundAborted {Base Leaves : Type*} (view : RoundView Base Leaves) : Bool :=
  match view.2.2.2 with
  | none => true
  | some (_, none) => true
  | some (_, some _) => false

/-- Public adaptive schedule. Neither witnesses nor private committed heads
    are stored here; all dependence is on the complete visible history. -/
structure PublicSchedule (Base Leaves : Type*) where
  bases : List (RoundView Base Leaves) → PMF Base
  leaves : List (RoundView Base Leaves) → PMF Leaves
  stages : List (RoundView Base Leaves) → Base → Leaves → Decs Goldilocks →
    Option PublicStage

def runReal {Base Leaves : Type*} (schedule : PublicSchedule Base Leaves)
    (heads : List (RoundView Base Leaves) → Base → Heads Goldilocks)
    (gamma : List (RoundView Base Leaves) → Base → Leaves → Gamma Goldilocks) :
    Nat → List (RoundView Base Leaves) → PMF (List (RoundView Base Leaves))
  | 0, history => PMF.pure history
  | rounds + 1, history =>
    (realJoint (schedule.bases history) (schedule.leaves history)
      (heads history) (gamma history) (schedule.stages history)).bind fun view =>
        if roundAborted view then PMF.pure (history ++ [view])
        else runReal schedule heads gamma rounds (history ++ [view])

def runSimulator {Base Leaves : Type*} (schedule : PublicSchedule Base Leaves) :
    Nat → List (RoundView Base Leaves) → PMF (List (RoundView Base Leaves))
  | 0, history => PMF.pure history
  | rounds + 1, history =>
    (simulateJoint (schedule.bases history) (schedule.leaves history)
      (schedule.stages history)).bind fun view =>
        if roundAborted view then PMF.pure (history ++ [view])
        else runSimulator schedule rounds (history ++ [view])

/-- Whole adaptive history equality within the specified randomized-leaf
    algebraic model, including the first abort and its full prefix. There is
    no success conditioning or hypothesis that the histories are close. -/
theorem q38_adaptive_joint_history {Base Leaves : Type*}
    (schedule : PublicSchedule Base Leaves)
    (heads : List (RoundView Base Leaves) → Base → Heads Goldilocks)
    (gamma : List (RoundView Base Leaves) → Base → Leaves → Gamma Goldilocks)
    (rounds : Nat) (history : List (RoundView Base Leaves)) :
    runReal schedule heads gamma rounds history =
      runSimulator schedule rounds history := by
  induction rounds generalizing history with
  | zero => rfl
  | succ rounds ih =>
    simp only [runReal, runSimulator, q38_joint_simulator]
    apply congrArg (PMF.bind _)
    funext view
    split
    · rfl
    · exact ih (history ++ [view])

end
end HegemonCrypto.SmallWood.V8SmzaMathPrivacy
