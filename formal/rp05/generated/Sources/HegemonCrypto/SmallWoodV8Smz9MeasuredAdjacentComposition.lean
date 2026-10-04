import HegemonCrypto.SmallWoodV8Smz9MeasuredCurrentPrivacy
import HegemonCrypto.SmallWoodV8Smz9AdjacentComposition

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredAdjacentComposition

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9RuntimeRandomness V8Smz9JointAlgebraicLaw V8Smz9HonestHybrid
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9AdjacentComposition V8Smz9MeasuredTablePublic V8Smz9MeasuredCurrentPrivacy
open V8Smz9MeasuredSourceHiddenPatch
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

section ContinuedAbort

variable {Other Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

def measuredContinuedAbortSource (randomized : Bool)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (payload : LeafIndex → LeafSuffix) : ℝ :=
  uniformAverage fun tapes : LeafIndex → LeafTape =>
    V8Smz9HonestWholeViewGames.run randomized continuation.program
      (fullSourceOverlay continuation.oldLeaf continuation.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt) payload tapes) continuation.initial

def measuredContinuedAbortPublic (randomized : Bool)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work)) : ℝ :=
  V8Smz9HonestWholeViewGames.run randomized continuation.program
    (Sum.elim continuation.oldLeaf continuation.other) continuation.initial

/-- A nonce-exhausted request keeps every current leaf program until the
complete measured future has executed; no scalar failure substitutes for it. -/
theorem measured_continued_abort_source_to_public (randomized : Bool)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (payload : LeafIndex → LeafSuffix) :
    |measuredContinuedAbortSource randomized continuation salt labels payload -
      measuredContinuedAbortPublic randomized continuation| ≤ hiddenPatchLoss (queryCount continuation.program) := by
  rw [current_hidden_patch_loss_closed_form]
  exact full_source_overlay_measured_distance_le randomized continuation.program
    continuation.oldLeaf continuation.other labels Finset.univ (fun _ => canonicalLeafHeader salt) payload
    continuation.initial continuation.normalized

end ContinuedAbort

variable {Work : Type} [Fintype Work]

abbrev MeasuredSuccessfulContinuation (bound : Nat) := (opening : ComputedOpening) →
  PiopCoefficients Goldilocks → CurrentMeasuredFactory (Other := OtherRawInput bound) (Work := Work) opening.points

/-- Actual nonce/index interpreters select the same source branches as the
checked adjacent component. Only the future interpreter is extended to all
complete measured Programs, with persistent future fresh updates. -/
def measuredActualPostFinalSource (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : MeasuredContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : MeasuredSuccessfulContinuation (Work := Work) bound) : ℝ :=
  let parameters := statementParameters statement batching
  match sourceComputedOpening bound (by omega) digest pending oracle with
  | none => uniformAverage fun base : SourceRemainingCoins Goldilocks =>
      measuredContinuedAbortSource randomized aborted salt labels
        (currentSourceSuffix parameters values gamma response transcript base)
  | some opening => measuredCurrentFullSourceAcceptance randomized parameters opening.points
      (computed_opening_selected_rank opening) gamma response transcript
      (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      values salt labels (succeeded opening transcript)

/-- This reference has no witness values. Actual nonce/index failure cases
and complete post-failure measured continuation are retained. -/
def measuredActualPostFinalPublic (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : MeasuredContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : MeasuredSuccessfulContinuation (Work := Work) bound) : ℝ :=
  let parameters := statementParameters statement batching
  match sourceComputedOpening bound (by omega) digest pending oracle with
  | none => measuredContinuedAbortPublic randomized aborted
  | some opening => measuredCurrentPublicReferenceAcceptance randomized parameters opening.points
      (computed_opening_selected_rank opening) gamma response transcript
      (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      salt labels (succeeded opening transcript)

/-- The selected opening's geometry and index schedule are reused from their
actual interpreted source certificates, not supplied as final premises. -/
theorem measured_actual_post_final_source_to_public_bound
    (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : MeasuredContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : MeasuredSuccessfulContinuation (Work := Work) bound)
    (queryBound : Nat) (abortBounded : queryCount aborted.program ≤ queryBound)
    (successBounded : ∀ opening context visible,
      queryCount (succeeded opening transcript context visible).program ≤ queryBound) :
    |measuredActualPostFinalSource randomized bound largeEnough statement batching gamma response transcript
        (packingValues witness) salt labels digest pending oracle aborted succeeded -
      measuredActualPostFinalPublic randomized bound largeEnough statement batching gamma response transcript
        salt labels digest pending oracle aborted succeeded| ≤ hiddenPatchLoss queryBound := by
  cases chosen : sourceComputedOpening bound (by omega) digest pending oracle with
  | none =>
      simp only [measuredActualPostFinalSource, measuredActualPostFinalPublic, chosen]
      rw [← uniform_average_const (A := SourceRemainingCoins Goldilocks)
        (measuredContinuedAbortPublic randomized aborted)]
      apply uniform_average_difference_le
      intro base
      exact (measured_continued_abort_source_to_public randomized aborted salt labels _).trans
        (hidden_patch_loss_mono abortBounded)
  | some opening =>
      simp only [measuredActualPostFinalSource, measuredActualPostFinalPublic, chosen]
      exact measured_canonical_statement_current_privacy_bound randomized statement publicValues witness domain
        batching opening.points (computed_opening_interpolation_admissible opening)
        (computed_opening_points_nonzero opening) (computed_opening_selected_rank opening)
        (by decide) actual_interpolation_nodes_distinct gamma response transcript (computedOpeningFallback opening)
        (computedIndexChooser bound largeEnough (statementParameters statement batching) opening transcript digest oracle)
        salt labels (succeeded opening transcript) queryBound (successBounded opening)

theorem measured_actual_post_final_transcript_mixture_bound
    (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : PiopCoefficients Goldilocks → MeasuredContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : MeasuredSuccessfulContinuation (Work := Work) bound)
    (queryBound : Nat) (abortBounded : ∀ transcript, queryCount (aborted transcript).program ≤ queryBound)
    (successBounded : ∀ opening transcript context visible,
      queryCount (succeeded opening transcript context visible).program ≤ queryBound) :
    |uniformAverage (fun transcript =>
        measuredActualPostFinalSource randomized bound largeEnough statement batching gamma response transcript
          (packingValues witness) salt labels digest pending oracle (aborted transcript) succeeded) -
      uniformAverage (fun transcript =>
        measuredActualPostFinalPublic randomized bound largeEnough statement batching gamma response transcript
          salt labels digest pending oracle (aborted transcript) succeeded)| ≤ hiddenPatchLoss queryBound := by
  apply uniform_average_difference_le
  intro transcript
  exact measured_actual_post_final_source_to_public_bound randomized bound largeEnough statement publicValues
    witness domain batching gamma response transcript salt labels digest pending oracle (aborted transcript)
    succeeded queryBound (abortBounded transcript) (fun opening => successBounded opening transcript)


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredAdjacentComposition
