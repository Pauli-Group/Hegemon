import HegemonCrypto.SmallWoodV8Smz9MeasuredTablePublic

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredCurrentPrivacy

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9CurrentPublicContext
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9EagerPrivacy V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator
open V8Smz9CurrentProgramPiop V8Smz9CurrentProgramOpeningBinding
open V8Smz9EagerOracleGame V8Smz9PrivacyGameComposition
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames V8Smz9MeasuredTablePublic
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Other Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

/-- The complete future measured program and prior oracle may depend on the
public context and already opened tapes, never the fresh hidden tape table. -/
abbrev CurrentMeasuredFactory (points : Fin 6 → Goldilocks) :=
  (context : EagerContext points) →
    OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) →
      MeasuredContinuation (Other := Other) (Work := Work)

theorem measured_current_source_table_to_public_reference_bound
    (randomized : Bool) (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
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
        parameters.linearWeights polynomial row lane * values row lane) = parameters.linearTargets polynomial)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection
      (currentSourceContext parameters points selected gamma response transcript choose values coins)))) :
    let context := currentSourceContext parameters points selected gamma response transcript choose values coins
    |measuredFullTableAcceptance randomized (openedOrEmpty (contextSelection context)) visible
        salt labels continuation (currentSourceSuffix parameters values gamma response transcript coins) -
      measuredPublicTableAcceptance randomized points selected salt labels context continuation visible| ≤
      hiddenPatchLoss (queryCount continuation.program) :=
  measured_completed_table_to_public_reference_bound randomized points selected salt labels _ continuation
    (currentSourceSuffix parameters values gamma response transcript coins)
    (current_source_suffix_matches_public_opened_suffix parameters points admissible selected
      packingCardNonzero nodesInjective values gamma response transcript choose coins accepted validLinearValues) visible

def measuredPublicContextAcceptance (randomized : Bool) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points)
    (context : EagerContext points) : ℝ :=
  uniformAverage fun visiblePadding : TapeTable =>
    let opened := openedOrEmpty (contextSelection context)
    let visible := (splitTapes opened visiblePadding).1
    measuredPublicTableAcceptance randomized points selected salt labels context
      (continuation context visible) visible

def measuredSourceContextAcceptance (randomized : Bool)
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points) : ℝ :=
  let context := currentSourceContext parameters points selected gamma response transcript choose values coins
  uniformAverage fun visiblePadding : TapeTable =>
    let opened := openedOrEmpty (contextSelection context)
    let visible := (splitTapes opened visiblePadding).1
    measuredFullTableAcceptance randomized opened visible salt labels (continuation context visible)
      (currentSourceSuffix parameters values gamma response transcript coins)

def measuredCurrentFullSourceAcceptance (randomized : Bool)
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points) : ℝ :=
  uniformAverage fun coins : SourceRemainingCoins Goldilocks =>
    measuredSourceContextAcceptance randomized parameters points selected gamma response transcript choose values coins
      salt labels continuation

/-- Explicit witness-free reference: only public inverse coordinates and the
public-context/opened-tape continuation factory occur in the definition. -/
def measuredCurrentPublicReferenceAcceptance (randomized : Bool)
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points) : ℝ :=
  uniformAverage fun view : SourceRemainingView Goldilocks =>
    measuredPublicContextAcceptance randomized points selected salt labels continuation
      (currentIndexedContext parameters points selected gamma response transcript choose view)

/-- First remove the hidden source programs on each actual public fiber,
then transport only the public reference through the checked coordinate law. -/
theorem measured_current_averaged_source_to_witness_free_reference_bound
    (randomized : Bool) (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
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
        parameters.linearWeights polynomial row lane * values row lane) = parameters.linearTargets polynomial)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points)
    (queryBound : Nat) (queriesBounded : ∀ context visible,
      queryCount (continuation context visible).program ≤ queryBound) :
    |measuredCurrentFullSourceAcceptance randomized parameters points selected gamma response transcript choose
        values salt labels continuation -
      measuredCurrentPublicReferenceAcceptance randomized parameters points selected gamma response transcript choose
        salt labels continuation| ≤ hiddenPatchLoss queryBound := by
  have publicTransport := current_source_public_observation_average parameters points values admissible
    pointsNonzero selected gamma response transcript fallback choose
    (measuredPublicContextAcceptance randomized points selected salt labels continuation)
  unfold measuredCurrentFullSourceAcceptance measuredCurrentPublicReferenceAcceptance
  rw [← publicTransport]
  apply uniform_average_difference_le
  intro coins
  unfold measuredSourceContextAcceptance measuredPublicContextAcceptance
  apply uniform_average_difference_le
  intro visiblePadding
  exact (measured_current_source_table_to_public_reference_bound randomized parameters points admissible selected
    packingCardNonzero nodesInjective values gamma response transcript choose coins accepted validLinearValues
    salt labels (continuation _ _) _).trans (hidden_patch_loss_mono (queriesBounded _ _))

/-- Actual admitted packed acceptance supplies both source algebraic premises;
the reference remains explicitly free of packed witness values. -/
theorem measured_canonical_statement_current_privacy_bound
    (randomized : Bool) (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := Other) (Work := Work) points)
    (queryBound : Nat) (queriesBounded : ∀ context visible,
      queryCount (continuation context visible).program ≤ queryBound) :
    |measuredCurrentFullSourceAcceptance randomized (statementParameters statement batching) points selected
        gamma response transcript choose (packingValues witness) salt labels continuation -
      measuredCurrentPublicReferenceAcceptance randomized (statementParameters statement batching) points selected
        gamma response transcript choose salt labels continuation| ≤ hiddenPatchLoss queryBound := by
  obtain ⟨_, nonlinear, linear⟩ :=
    canonical_statement_supplies_current_game_algebra statement publicValues witness domain batching
  exact measured_current_averaged_source_to_witness_free_reference_bound randomized
    (statementParameters statement batching) points admissible pointsNonzero selected packingCardNonzero
    nodesInjective (packingValues witness) gamma response transcript fallback choose nonlinear linear
    salt labels continuation queryBound queriesBounded


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredCurrentPrivacy
