import HegemonCrypto.SmallWoodV8Smz9CurrentProgramOpeningBinding

/-! # Current-program indexed eager oracle game

The context below uses the fixed current program, preserves failed index
sampling, and carries independently sampled leaf tapes. The completed source
table is constructed at every leaf index from the physical rows and recovered
masks. Its equality on opened indices is proved, not supplied as a premise.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame

open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9EagerPrivacy V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator
open V8Smz9CurrentProgramPiop V8Smz9CurrentProgramOpeningBinding
open V8Smz9EagerOracleGame V8Smz9PrivacyGameComposition
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open Polynomial
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxRecDepth 5000
set_option maxHeartbeats 500000
set_option backward.isDefEq.respectTransparency false

def currentIndexedContext (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourceRemainingView Goldilocks) : EagerContext points :=
  (choose view.1 view.2.1 view.2.2.1).map fun targets =>
    (targets, currentEagerAlgebraicFields parameters points selected gamma response transcript
      (indexedPoints targets.val) view)

def currentSampledContext (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourcePartialRemainingView Goldilocks) : EagerContext points :=
  view.2.2.2.bind fun subset =>
    currentIndexedContext parameters points selected gamma response transcript choose
      (view.1, view.2.1, view.2.2.1, subset)

theorem current_indexed_context_preserves_abort
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourceRemainingView Goldilocks) :
    currentSampledContext parameters points selected gamma response transcript choose
        (sourceRemainingAbortProjection (valueChooser choose) view) =
      currentIndexedContext parameters points selected gamma response transcript choose view := by
  cases chosen : choose view.1 view.2.1 view.2.2.1 <;>
    simp [currentSampledContext, sourceRemainingAbortProjection, valueChooser, currentIndexedContext, chosen]

def currentSourceContext (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks) :
    EagerContext points :=
  currentSampledContext parameters points selected gamma response transcript choose
    (sourceRemainingPartialChronologicalView values points
      (currentPcsBaseForTranscript parameters values points transcript)
      (currentCommittedHeadsForTranscript parameters values transcript) (valueChooser choose) coins)

/-- Actual current-program context transport retains arbitrary subsequent
observations of the complete fresh tape table, including previous oracle state. -/
theorem current_indexed_context_fresh_tape_law {Result : Type*}
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (observe : EagerContext points → TapeTable → PMF Result) :
    ((uniformFintypePMF (SourceRemainingCoins Goldilocks)).bind fun coins =>
      (uniformFintypePMF TapeTable).bind fun tapes =>
        observe (currentSourceContext parameters points selected gamma response transcript choose values coins)
          tapes) =
    ((uniformFintypePMF (SourceRemainingView Goldilocks)).bind fun view =>
      (uniformFintypePMF TapeTable).bind fun tapes =>
        observe (currentIndexedContext parameters points selected gamma response transcript choose view) tapes) := by
  have transported := source_partial_context_fresh_tape_transport
    (Index := LeafIndex) (Tape := LeafTape) values points admissible pointsNonzero
    (currentPcsBaseForTranscript parameters values points transcript)
    (currentCommittedHeadsForTranscript parameters values transcript) fallback
    (valueChooser choose) (currentSampledContext parameters points selected gamma response transcript choose) observe
  simpa only [currentSourceContext, current_indexed_context_preserves_abort] using transported

/-- The reference can depend on the public context and revealed tapes. The
hidden tape law is derived from the product experiment, even on sampler abort. -/
theorem current_indexed_context_conditional_hidden_tape_law {Reference Result : Type*}
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points)
    (reference : (context : EagerContext points) →
      OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) → Reference)
    (observe : (context : EagerContext points) →
      OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) →
      HiddenTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) → Reference → PMF Result) :
    ((uniformFintypePMF (SourceRemainingCoins Goldilocks)).bind fun coins =>
      (uniformFintypePMF TapeTable).bind fun tapes =>
        let context := currentSourceContext parameters points selected gamma response transcript choose values coins
        let split := splitTapes (openedOrEmpty (contextSelection context)) tapes
        observe context split.1 split.2 (reference context split.1)) =
    ((uniformFintypePMF (SourceRemainingView Goldilocks)).bind fun view =>
      let context := currentIndexedContext parameters points selected gamma response transcript choose view
      (uniformFintypePMF (OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)))).bind
        fun visible =>
      (uniformFintypePMF (HiddenTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)))).bind
        fun hidden => observe context visible hidden (reference context visible)) := by
  have transported := source_partial_context_conditional_tape_law
    (Index := LeafIndex) (Tape := LeafTape) values points admissible pointsNonzero
    (currentPcsBaseForTranscript parameters values points transcript)
    (currentCommittedHeadsForTranscript parameters values transcript) fallback
    (valueChooser choose) (currentSampledContext parameters points selected gamma response transcript choose)
    contextSelection reference observe
  refine transported.trans ?_
  apply congrArg (PMF.bind (uniformFintypePMF (SourceRemainingView Goldilocks)))
  funext view
  rw [current_indexed_context_preserves_abort]

/-- Genuine source rows and mask polynomials at every one of the 2^23 indices.
There is no arbitrary completion of the unopened suffixes. -/
def fullPhysicalSuffix (heads : LvcsCommittedHeads Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks) (decsMask : DecsFullCoefficients Goldilocks) :
    LeafIndex → LeafSuffix := fun index =>
  canonicalLeafSuffix
    (fun row => consecutiveInterpolation (lvcsRotatedRow heads tails row)
      (V8Smz9DisjointCoset.evaluationPoint index))
    (fun polynomial => (coefficientPolynomial (decsMask polynomial)).eval
      (V8Smz9DisjointCoset.evaluationPoint index))

theorem full_physical_suffix_at_opening
    (heads : LvcsCommittedHeads Goldilocks) (tails : LvcsRandomTailCoins Goldilocks)
    (decsMask : DecsFullCoefficients Goldilocks) (indices : Fin 20 → LeafIndex) (opening : Fin 20) :
    fullPhysicalSuffix heads tails decsMask (indices opening) =
      canonicalLeafSuffix (fullRowEvaluations heads tails (indexedPoints indices) opening)
        (fun polynomial => (coefficientPolynomial (decsMask polynomial)).eval
          (indexedPoints indices opening)) := rfl

def currentSourceSuffix (parameters : CurrentPublicParameters)
    (values : WitnessPackingValues Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (coins : SourceRemainingCoins Goldilocks) : LeafIndex → LeafSuffix :=
  let witness := sourceWitnessPolynomials values coins.1
  let masks := currentRecoveredMasksAtCoins parameters values transcript coins.1
  let heads := physicalHeads witness masks coins.2.1
  fullPhysicalSuffix heads coins.2.2 (response - exactDecsUnmaskedCoefficients gamma heads coins.2.2)

def sourceChosenIndices (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (choose : IndexChooser points) (coins : SourceRemainingCoins Goldilocks) :
    Option (IndexedTargets points) :=
  choose (sourceWitnessOpenings values points coins.1)
    (sourcePcsFullView points (currentPcsBaseForTranscript parameters values points transcript coins.1) coins.2.1)
    (lvcsEarlierOutput points coins.2.2)

theorem current_source_context_is_physical
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks) :
    currentSourceContext parameters points selected gamma response transcript choose values coins =
      (sourceChosenIndices parameters points values transcript choose coins).map fun targets =>
        (targets, currentEagerAlgebraicFields parameters points selected gamma response transcript
          (indexedPoints targets.val)
          (physicalView points (sourceWitnessPolynomials values coins.1)
            (currentRecoveredMasksAtCoins parameters values transcript coins.1) coins.2.1 coins.2.2
            (indexedPoints targets.val))) := by
  cases chosen : sourceChosenIndices parameters points values transcript choose coins with
  | none =>
      have chosenRaw := chosen
      unfold sourceChosenIndices at chosenRaw
      simp only [currentSourceContext, currentSampledContext, currentIndexedContext,
        sourceRemainingPartialChronologicalView, exactLvcsPartialFeedbackOutput,
        valueChooser, chosenRaw, Option.map_none, Option.bind_none]
  | some targets =>
      have chosenRaw := chosen
      unfold sourceChosenIndices at chosenRaw
      simp only [currentSourceContext, currentSampledContext, currentIndexedContext,
        sourceRemainingPartialChronologicalView, exactLvcsPartialFeedbackOutput,
        valueChooser, chosenRaw, Option.map_some, Option.bind_some]
      rfl

theorem current_source_suffix_matches_public_opened_suffix
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (values : WitnessPackingValues Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (choose : IndexChooser points) (coins : SourceRemainingCoins Goldilocks)
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows values lane))
    (validLinearValues : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * values row lane) =
          parameters.linearTargets polynomial) :
    ∀ index ∈ openedOrEmpty (contextSelection
      (currentSourceContext parameters points selected gamma response transcript choose values coins)),
      currentSourceSuffix parameters values gamma response transcript coins index =
        publicSuffix points selected
          (currentSourceContext parameters points selected gamma response transcript choose values coins) index := by
  intro index member
  rw [current_source_context_is_physical] at member ⊢
  cases chosen : sourceChosenIndices parameters points values transcript choose coins with
  | none => simp [chosen, contextSelection, openedOrEmpty] at member
  | some targets =>
      simp only [chosen, Option.map_some] at member ⊢
      change index ∈ Finset.univ.image targets.val at member
      obtain ⟨opening, _, rfl⟩ := Finset.mem_image.mp member
      simp only [publicSuffix, opening_slot_at _ targets.property.1]
      let witness := sourceWitnessPolynomials values coins.1
      let masks := currentRecoveredMasksAtCoins parameters values transcript coins.1
      let heads := physicalHeads witness masks coins.2.1
      let decsMask := response - exactDecsUnmaskedCoefficients gamma heads coins.2.2
      have suffix := accepted_source_witness_opened_suffix_is_reconstructed parameters points admissible
        selected packingCardNonzero nodesInjective values coins.1 masks coins.2.1 coins.2.2 gamma decsMask
        (indexedPoints targets.val) accepted validLinearValues opening
      dsimp only at suffix
      have fields := inverse_current_physical_fields_keep_original_responses parameters points selected witness
        transcript coins.2.1 coins.2.2 gamma response (indexedPoints targets.val)
      change currentPhysicalFields parameters points selected witness masks coins.2.1 coins.2.2 gamma
        decsMask (indexedPoints targets.val) = _ at fields
      change canonicalLeafSuffix
        (rowsFromFields points selected (indexedPoints targets.val)
          (currentPhysicalFields parameters points selected witness masks coins.2.1 coins.2.2 gamma
            decsMask (indexedPoints targets.val)) opening)
        ((currentPhysicalFields parameters points selected witness masks coins.2.1 coins.2.2 gamma
            decsMask (indexedPoints targets.val)).decsMaskEvaluations opening) = _ at suffix
      rw [fields] at suffix
      change fullPhysicalSuffix heads coins.2.2 decsMask (targets.val opening) = _
      rw [full_physical_suffix_at_opening]
      exact suffix.symm

/-- The explicit bijection used for averaging, with fallback only on the
discarded late coordinate. The visible context still retains sampler failure. -/
def currentCoordinateEquiv (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (fallback : LvcsAdmissibleTargets points) (choose : IndexChooser points) :
    SourceRemainingCoins Goldilocks ≃ SourceRemainingView Goldilocks :=
  sourceRemainingViewEquiv values points admissible pointsNonzero
    (currentPcsBaseForTranscript parameters values points transcript)
    (currentCommittedHeadsForTranscript parameters values transcript)
    (fun witness columns early => ((valueChooser choose) witness columns early).getD fallback)

theorem current_source_context_eq_public_context_at_inverse_coordinates
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (coins : SourceRemainingCoins Goldilocks) :
    currentSourceContext parameters points selected gamma response transcript choose values coins =
      currentIndexedContext parameters points selected gamma response transcript choose
        (currentCoordinateEquiv parameters points values transcript admissible pointsNonzero fallback choose coins) := by
  rw [current_source_context_is_physical]
  unfold currentCoordinateEquiv
  rw [source_remaining_equiv_matches_chronological_view]
  cases chosen : sourceChosenIndices parameters points values transcript choose coins with
  | none =>
      have chosenRaw := chosen
      unfold sourceChosenIndices at chosenRaw
      simp only [currentIndexedContext, sourceRemainingChronologicalView, chosenRaw, Option.map_none]
  | some targets =>
      have chosenRaw := chosen
      unfold sourceChosenIndices at chosenRaw
      simp only [currentIndexedContext, sourceRemainingChronologicalView, valueChooser, chosenRaw,
        Option.map_some, Option.getD_some]
      rfl

def uniformAverage {A : Type*} [Fintype A] [Nonempty A] (value : A → ℝ) : ℝ :=
  ∑ point, (uniformFintypePMF A point).toReal * value point

theorem uniform_average_equiv {A B : Type*} [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (equivalence : A ≃ B) (value : B → ℝ) :
    uniformAverage (fun point => value (equivalence point)) = uniformAverage value := by
  unfold uniformAverage
  simp only [uniformFintypePMF_apply]
  rw [← Finset.mul_sum, ← Finset.mul_sum, Fintype.card_congr equivalence,
    equivalence.sum_comp value]

theorem uniform_average_difference_le {A : Type*} [Fintype A] [Nonempty A]
    (left right : A → ℝ) (loss : ℝ)
    (bound : ∀ point, |left point - right point| ≤ loss) :
    |uniformAverage left - uniformAverage right| ≤ loss :=
  pmf_mixture_difference_le (uniformFintypePMF A) left right loss bound

theorem current_hidden_patch_loss_closed_form (queries : ℕ) :
    hiddenPatchLoss queries = 4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
  have power : (2 ^ 512 : ℝ) = (2 ^ 256 : ℝ) ^ 2 := by
    rw [← pow_mul]
  have denominatorNonzero : (2 ^ 256 : ℝ) ≠ 0 := by positivity
  unfold hiddenPatchLoss
  rw [power]
  have square : 4 * (queries : ℝ) ^ 2 * ((2 ^ 256 : ℝ) ^ 2)⁻¹ =
      (2 * (queries : ℝ) / (2 ^ 256 : ℝ)) ^ 2 := by
    field_simp
    ring
  rw [square, Real.sqrt_sq_eq_abs, abs_of_nonneg (by positivity)]
  ring

theorem current_source_public_observation_average
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (observe : EagerContext points → ℝ) :
    uniformAverage (fun coins : SourceRemainingCoins Goldilocks =>
      observe (currentSourceContext parameters points selected gamma response transcript choose values coins)) =
    uniformAverage (fun view : SourceRemainingView Goldilocks =>
      observe (currentIndexedContext parameters points selected gamma response transcript choose view)) := by
  simp_rw [current_source_context_eq_public_context_at_inverse_coordinates parameters points values admissible
    pointsNonzero selected gamma response transcript fallback choose]
  exact uniform_average_equiv
    (currentCoordinateEquiv parameters points values transcript admissible pointsNonzero fallback choose)
    (fun view => observe (currentIndexedContext parameters points selected gamma response transcript choose view))

section PhysicalGame

variable {Other Output Workspace : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Output] [DecidableEq Output] [AddGroup Output]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Complete source-table versus the actual current-program public reference.
The sole source validity premises are interpreter acceptance and the public
linear weighted-value relation. No suffix or game equality is assumed. -/
theorem current_source_table_to_public_reference_bound
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (values : WitnessPackingValues Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (choose : IndexChooser points) (coins : SourceRemainingCoins Goldilocks)
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows values lane))
    (validLinearValues : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * values row lane) =
          parameters.linearTargets polynomial)
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection
      (currentSourceContext parameters points selected gamma response transcript choose values coins)))) :
    let context := currentSourceContext parameters points selected gamma response transcript choose values coins
    |fullProgrammedAcceptance (openedOrEmpty (contextSelection context)) visible
        (completedAtomicReference points selected salt labels context continuation
          (currentSourceSuffix parameters values gamma response transcript coins)) -
      referenceAcceptance (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
        (publicAtomicReference points selected salt labels context continuation))| ≤
      hiddenPatchLoss continuation.queries :=
  completed_table_to_public_reference_bound points selected salt labels _ continuation
    (currentSourceSuffix parameters values gamma response transcript coins)
    (current_source_suffix_matches_public_opened_suffix parameters points admissible selected
      packingCardNonzero nodesInjective values gamma response transcript choose coins accepted validLinearValues)
    visible

/-- The continuation is generated from public context and revealed tapes only.
Its old oracle, quantum state and query steps cannot inspect the fresh hidden
tape argument, which is bound later inside the physical acceptance functions. -/
abbrev CurrentContinuationFactory (points : Fin 6 → Goldilocks) :=
  (context : EagerContext points) →
    OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) →
      PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace)

def publicContextAcceptance (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points)
    (context : EagerContext points) : ℝ :=
  uniformAverage fun visiblePadding : TapeTable =>
    let opened := openedOrEmpty (contextSelection context)
    let visible := (splitTapes opened visiblePadding).1
    referenceAcceptance (keepOpenedPrograms opened visible
      (publicAtomicReference points selected salt labels context (continuation context visible)))

def sourceContextAcceptance (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points) : ℝ :=
  let context := currentSourceContext parameters points selected gamma response transcript choose values coins
  uniformAverage fun visiblePadding : TapeTable =>
    let opened := openedOrEmpty (contextSelection context)
    let visible := (splitTapes opened visiblePadding).1
    fullProgrammedAcceptance opened visible
      (completedAtomicReference points selected salt labels context (continuation context visible)
        (currentSourceSuffix parameters values gamma response transcript coins))

def currentFullSourceAcceptance (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points) : ℝ :=
  uniformAverage fun coins : SourceRemainingCoins Goldilocks =>
    sourceContextAcceptance parameters points selected gamma response transcript choose values coins
      salt labels continuation

/-- Witness-free reference: no witness values or inverse source masks occur in
the definition. Every index-selection failure is retained in the context. -/
def currentPublicReferenceAcceptance (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points) : ℝ :=
  uniformAverage fun view : SourceRemainingView Goldilocks =>
    publicContextAcceptance points selected salt labels continuation
      (currentIndexedContext parameters points selected gamma response transcript choose view)

/-- Actual finite experiments, not fields holding desired probabilities. First
compare each genuine source table against its public reference; only then move
the public-only reference through the exact source-coordinate bijection. -/
theorem current_averaged_source_to_witness_free_reference_bound
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (values : WitnessPackingValues Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (fallback : LvcsAdmissibleTargets points) (choose : IndexChooser points)
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows values lane))
    (validLinearValues : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * values row lane) =
          parameters.linearTargets polynomial)
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points)
    (queryBound : ℕ) (queriesBounded : ∀ context visible,
      (continuation context visible).queries ≤ queryBound) :
    |currentFullSourceAcceptance parameters points selected gamma response transcript choose values salt labels continuation -
      currentPublicReferenceAcceptance parameters points selected gamma response transcript choose salt labels continuation| ≤
      hiddenPatchLoss queryBound := by
  have publicTransport := current_source_public_observation_average parameters points values admissible
    pointsNonzero selected gamma response transcript fallback choose
    (publicContextAcceptance points selected salt labels continuation)
  unfold currentFullSourceAcceptance currentPublicReferenceAcceptance
  rw [← publicTransport]
  apply uniform_average_difference_le
  intro coins
  unfold sourceContextAcceptance publicContextAcceptance
  apply uniform_average_difference_le
  intro visiblePadding
  exact (current_source_table_to_public_reference_bound parameters points admissible selected packingCardNonzero
    nodesInjective values gamma response transcript choose coins accepted validLinearValues salt labels
    (continuation _ _) _).trans (hidden_patch_loss_mono (queriesBounded _ _))

/-- Two valid witnesses share the very same explicit public reference. This is
the randomized-label algebraic/hidden-table phase, not the preceding honest
hash-to-randomized-label QROM transition or a production privacy certificate. -/
theorem current_two_witness_source_game_bound
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (leftValues rightValues : WitnessPackingValues Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (fallback : LvcsAdmissibleTargets points) (choose : IndexChooser points)
    (leftAccepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows leftValues lane))
    (rightAccepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows rightValues lane))
    (leftLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * leftValues row lane) = parameters.linearTargets polynomial)
    (rightLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * rightValues row lane) = parameters.linearTargets polynomial)
    (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points)
    (queryBound : ℕ) (queriesBounded : ∀ context visible,
      (continuation context visible).queries ≤ queryBound) :
    |currentFullSourceAcceptance parameters points selected gamma response transcript choose leftValues salt labels continuation -
      currentFullSourceAcceptance parameters points selected gamma response transcript choose rightValues salt labels continuation| ≤
      2 * hiddenPatchLoss queryBound := by
  have leftBound := current_averaged_source_to_witness_free_reference_bound parameters points admissible
    pointsNonzero selected packingCardNonzero nodesInjective leftValues gamma response transcript fallback choose
    leftAccepted leftLinear salt labels continuation queryBound queriesBounded
  have rightBound := current_averaged_source_to_witness_free_reference_bound parameters points admissible
    pointsNonzero selected packingCardNonzero nodesInjective rightValues gamma response transcript fallback choose
    rightAccepted rightLinear salt labels continuation queryBound queriesBounded
  have triangle := abs_sub_le
    (currentFullSourceAcceptance parameters points selected gamma response transcript choose leftValues salt labels continuation)
    (currentPublicReferenceAcceptance parameters points selected gamma response transcript choose salt labels continuation)
    (currentFullSourceAcceptance parameters points selected gamma response transcript choose rightValues salt labels continuation)
  rw [abs_sub_comm
    (currentPublicReferenceAcceptance parameters points selected gamma response transcript choose salt labels continuation)]
    at triangle
  linarith

end PhysicalGame

end
end HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
