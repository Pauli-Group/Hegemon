import SmzaRp04RawMcaSampling
import SmzaJointRoleOracleExecution
import SmzaRp04PrefixLabelReadback

/-! All actual raw-output densities for the four RP04 challenge roles.

This discharges the per-label density interface of the single initialized
oracle theorem. Labels may be absent when their prerequisite parse/recovery
has failed. No density is conditioned on successful parsing. The two final
DECS-query losses are combined on the same output, without independence.

Constructing these labels from the recorded extraction prefix and identifying
the actual accepted-failure event remain separate deterministic obligations.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells

open HegemonCrypto.CmsClassicalDatabase
open SmzaChallengeStageTargets SmzaRp04RoleBadCells
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling SmzaRp04McaRoleCells
open SmzaRp04PublicContext SmzaRp04ChronologicalAlgebra
open SmzaRp04ActualProgram
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open SmzaRp04CalculatedExtraction
open V8Smz9CoherentVectorMerkle V8Smz9RawCounterCompiler
open V8Smz9RuntimeFieldLayout V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
attribute [local irreducible] batchingWidth recoveredCandidate

structure Routes (Counter : Type*) (publicWords : List Nat) extends
    RawRoutes Counter publicWords where
  decsMatrix : Fin (digestCallCap (140 * 5)) ↪ Counter

def optionalEvent {Label Output : Type*}
    (event : Label → Output → Prop) (label : Option Label) (output : Output) : Prop :=
  ∃ present, label = some present ∧ event present output

theorem optional_event_probability_le {Label Output : Type*}
    [Fintype Output] (event : Label → Output → Prop)
    (loss : Rat) (nonnegative : 0 ≤ loss)
    (bound : ∀ label, outputEventProbability (event label) ≤ loss)
    (label : Option Label) :
    outputEventProbability (optionalEvent event label) ≤ loss := by
  cases label with
  | none => simpa [optionalEvent, outputEventProbability] using nonnegative
  | some label =>
      have sameEvent : optionalEvent event (some label) = event label := by
        funext output
        apply propext
        simp [optionalEvent]
      rw [sameEvent]
      exact bound label

theorem output_event_union_le {Output : Type*} [Fintype Output]
    (left right : Output → Prop) :
    outputEventProbability (fun output => left output ∨ right output) ≤
      outputEventProbability left + outputEventProbability right := by
  classical
  let a := Finset.univ.filter left
  let b := Finset.univ.filter right
  have union : (Finset.univ.filter fun output => left output ∨ right output) =
      a ∪ b := by
    ext output
    simp only [a, b, Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union]
  have cardBound :
      (Finset.univ.filter fun output => left output ∨ right output).card ≤
        a.card + b.card := by
    rw [union]
    exact Finset.card_union_le a b
  unfold outputEventProbability
  rw [← add_div]
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  norm_cast
  convert cardBound using 1
  · congr 1
    ext output
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]

theorem complete_role_loss_nonnegative (role : Role) : 0 ≤ completeRoleLoss role := by
  cases role <;>
    dsimp only [completeRoleLoss, roleLoss, matrixLoss, smallSupportLoss,
      q38LvcsLoss, q38SingleRootLoss, epsilon3] <;> positivity

def decsMatrixBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (oracle : CommittedOracle)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, actualDecsMatrixOutput routes.decsMatrix vector = some output ∧
    matrixBad oracle output

def piopMatrixBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (label : PiopMatrixPrefixKey publicWords)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, actualPiopMatrixOutput routes.piopMatrix vector = some output ∧
    piopMatrixPrefixBad label output

def piopOpeningBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (label : PiopOpeningLabel publicWords)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, actualPiopOpeningOutput routes.piopOpening vector = some output ∧
    piopOpeningCellBad label output

def supportBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (label : SmallSupportLabel)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, actualDecsSampleOutput routes.decsSample vector = some output ∧
    smallSupportBad label output

def lvcsBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (label : DecsSamplePrefixKey)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, actualDecsSampleOutput routes.decsSample vector = some output ∧
    decsSamplePrefixBad label output

def completeRawBad {Counter : Type*} {publicWords : List Nat}
    (routes : Routes Counter publicWords) (role : Role)
    (label : PrefixLabels publicWords) (vector : VectorOutput Counter) : Prop :=
  match role with
  | .decsMatrix => optionalEvent (decsMatrixBad routes) label.decsMatrix vector
  | .piopMatrix => optionalEvent (piopMatrixBad routes) label.piopMatrix vector
  | .piopOpening => optionalEvent (piopOpeningBad routes) label.piopOpening vector
  | .decsSample => optionalEvent (supportBad routes) label.smallSupport vector ∨
      optionalEvent (lvcsBad routes) label.lvcs vector

/-- The actual capped raw samplers discharge every classical density needed
by the checked one-execution quantum theorem. No stage-security conclusion,
uniform-readout hypothesis, or universal-count hypothesis is supplied. -/
theorem complete_raw_role_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {publicWords : List Nat} (routes : Routes Counter publicWords)
    (role : Role) (label : PrefixLabels publicWords) :
    outputEventProbability (completeRawBad routes role label) ≤
      completeRoleLoss role := by
  cases role with
  | decsMatrix =>
      exact optional_event_probability_le (decsMatrixBad routes) matrixLoss
        (complete_role_loss_nonnegative .decsMatrix)
        (actual_matrix_bad_and_success_le routes.decsMatrix) label.decsMatrix
  | piopMatrix =>
      exact optional_event_probability_le (piopMatrixBad routes) (roleLoss .piopMatrix)
        (complete_role_loss_nonnegative .piopMatrix)
        (actual_piop_matrix_prefix_bad_and_success_le routes.piopMatrix) label.piopMatrix
  | piopOpening =>
      exact optional_event_probability_le (piopOpeningBad routes) (roleLoss .piopOpening)
        (complete_role_loss_nonnegative .piopOpening)
        (actual_piop_opening_bad_and_success_le routes.piopOpening) label.piopOpening
  | decsSample =>
      have smallNonnegative : 0 ≤ smallSupportLoss := by unfold smallSupportLoss; positivity
      have lvcsNonnegative : 0 ≤ roleLoss .decsSample := by
        change 0 ≤ 12 * ((Nat.choose 405 38 : Rat) /
          Nat.choose (Fintype.card SmzaQ38McaSourceBinding.Position) 38)
        exact mul_nonneg (by norm_num)
          (div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _))
      have supportBound := optional_event_probability_le (supportBad routes)
        smallSupportLoss smallNonnegative
        (actual_small_support_bad_and_success_le routes.decsSample) label.smallSupport
      have lvcsBound := optional_event_probability_le (lvcsBad routes)
        (roleLoss .decsSample) lvcsNonnegative
        (actual_decs_sample_prefix_bad_and_success_le routes.decsSample) label.lvcs
      exact (output_event_union_le _ _).trans (add_le_add supportBound lvcsBound)

end
end HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells
