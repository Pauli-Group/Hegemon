import HegemonCrypto.SmallWoodV8Smz9SourceIndexSampler

/-! Actual nonce and index execution followed by source-to-public comparison.
The nonce failure branch runs the complete future physical circuit with every
current leaf still programmed. It is not replaced by a scalar failure event.
The successful branch uses the actual source index sampler and derives its
rank/interpolation requirements from the returned source opening words.

This module is an adjacent-game component, not a claim that the complete Rust
request has yet been compiled into the honest reprogramming experiment. -/

namespace HegemonCrypto.SmallWood.V8Smz9AdjacentComposition

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9RuntimeRandomness V8Smz9JointAlgebraicLaw V8Smz9HonestHybrid
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution
open V8Smz9WholeViewObservation
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

structure ComputedOpening where
  nonce : Fin 16
  words : List FieldWord
  valid : words.length = 6 ∧ SourceOpeningAdmissible (sourcePointVector words)
  pendingFailure : Bool

/-- The branch and its certificate are obtained by actually interpreting the
source nonce schedule. No admissibility certificate is an input. -/
def sourceComputedOpening (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister) : Option ComputedOpening :=
  let result := NonleafProgram.interpret oracle (sourceChooseOpening bound largeEnough digest pending)
  match selected : result.selected with
  | none => none
  | some pair => some ⟨pair.1, pair.2,
      source_selected_opening_is_valid bound largeEnough digest pending oracle pair.1 pair.2 selected,
      result.pendingFailure⟩

def ComputedOpening.points (opening : ComputedOpening) : Fin 6 → Goldilocks :=
  sourcePointVector opening.words

theorem computed_opening_points_distinct (opening : ComputedOpening) :
    Function.Injective opening.points := opening.valid.2.1

theorem computed_opening_points_nonzero (opening : ComputedOpening) :
    ∀ index, opening.points index ≠ 0 := opening.valid.2.2.1

theorem actual_packing_nodes_distinct :
    Function.Injective (smz9PackingPoint (F := Goldilocks)) := by
  intro left right same
  have equal := actual_interpolation_nodes_distinct
    (a₁ := ⟨left.val, left.isLt.trans_le (by decide)⟩)
    (a₂ := ⟨right.val, right.isLt.trans_le (by decide)⟩) same
  exact Fin.ext (congrArg (fun index : Fin 388 => index.val) equal)

theorem computed_opening_interpolation_admissible (opening : ComputedOpening) :
    Smz9WitnessInterpolationAdmissible opening.points :=
  ⟨actual_packing_nodes_distinct, computed_opening_points_distinct opening,
    opening.valid.2.2.2.1⟩

def computedOpeningFallback (opening : ComputedOpening) : LvcsAdmissibleTargets opening.points :=
  let indices : Fin 20 → LeafIndex := fun index => ⟨index.val, index.isLt.trans_le (by decide)⟩
  ⟨indexedPoints indices, actual_indexed_targets_admissible opening.points
    (computed_opening_points_distinct opening) indices
    (by intro left right same; exact Fin.ext (congrArg (fun index : LeafIndex => index.val) same))⟩

theorem computed_opening_selected_rank (opening : ComputedOpening) :
    Function.Injective (smz9LvcsSelectedBlockMap opening.points) :=
  actual_selected_block_injective (computed_opening_points_distinct opening)

section PhysicalContinuation

variable {Other Work : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Work] [DecidableEq Work]

/-- An aborted request exposes no current tape. The old table and the complete
future circuit are fixed before those hidden tapes are sampled. This circuit
may itself be the retained-update two-query compiler. -/
structure AbortContinuation where
  oldLeaf : LeafInput → DigestRegister
  other : Other → DigestRegister
  initial : V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other)
    (Output := DigestRegister) (Workspace := Work)
  normalized : ‖initial‖ = 1
  steps : ℕ → V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other)
    (Output := DigestRegister) (Workspace := Work) ≃ₗᵢ[ℂ]
      V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other) (Output := DigestRegister) (Workspace := Work)
  queries : ℕ
  post : V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other)
    (Output := DigestRegister) (Workspace := Work) ≃ₗᵢ[ℂ]
      V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other) (Output := DigestRegister) (Workspace := Work)
  event : Finset (V8Smz9HiddenLeafQrom.QueryBasis (LeafInput ⊕ Other) DigestRegister Work)

def continuedAbortSource (continuation : AbortContinuation (Other := Other) (Work := Work))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (payload : LeafIndex → LeafSuffix) : ℝ :=
  (∑ tapes : LeafIndex → LeafTape, born continuation.event
    (continuation.post (V8Smz9HiddenPatch.run
      (fullSourceOverlay continuation.oldLeaf continuation.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt) payload tapes)
      continuation.steps continuation.initial continuation.queries))) /
    (Fintype.card (LeafIndex → LeafTape) : ℝ)

def continuedAbortPublic (continuation : AbortContinuation (Other := Other) (Work := Work)) : ℝ :=
  (∑ _tapes : LeafIndex → LeafTape, born continuation.event
    (continuation.post (V8Smz9HiddenPatch.run
      (Sum.elim continuation.oldLeaf continuation.other)
      continuation.steps continuation.initial continuation.queries))) /
    (Fintype.card (LeafIndex → LeafTape) : ℝ)

theorem continued_abort_source_to_public (continuation : AbortContinuation (Other := Other) (Work := Work))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (payload : LeafIndex → LeafSuffix) :
    |continuedAbortSource continuation salt labels payload - continuedAbortPublic continuation| ≤
      hiddenPatchLoss continuation.queries :=
  full_source_overlay_cq_born_distance_le continuation.oldLeaf continuation.other labels Finset.univ
    (fun _ => canonicalLeafHeader salt) payload continuation.steps continuation.initial
    continuation.normalized continuation.queries (fun _ => continuation.post) (fun _ => continuation.event)

end PhysicalContinuation

variable {Work : Type*} [Fintype Work] [DecidableEq Work]

abbrev SuccessfulContinuation (bound : Nat) := (opening : ComputedOpening) →
  PiopCoefficients Goldilocks → CurrentContinuationFactory
    (Other := OtherRawInput bound) (Output := DigestRegister) (Workspace := Work) opening.points

def computedIndexChooser (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) : IndexChooser opening.points :=
  sourceCurrentIndexChooser bound largeEnough parameters opening.points
    (computed_opening_points_distinct opening) transcript digest oracle

/-- Source side after the leaf/final adjacent games. Both the point branch
and the later index branch are computed by their actual source read schedules.
On nonce exhaustion, the complete current physical suffix remains programmed. -/
def actualPostFinalSource (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : AbortContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : SuccessfulContinuation (Work := Work) bound) : ℝ :=
  let parameters := statementParameters statement batching
  match sourceComputedOpening bound (by omega) digest pending oracle with
  | none => uniformAverage fun base : SourceRemainingCoins Goldilocks =>
      continuedAbortSource aborted salt labels
        (currentSourceSuffix parameters values gamma response transcript base)
  | some opening => currentFullSourceAcceptance parameters opening.points
      (computed_opening_selected_rank opening) gamma response transcript
      (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      values salt labels (succeeded opening transcript)

/-- The reference has no witness input. It retains the same actually computed
nonce/index branches and the same complete continuation after a public abort. -/
def actualPostFinalPublic (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : AbortContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : SuccessfulContinuation (Work := Work) bound) : ℝ :=
  let parameters := statementParameters statement batching
  match sourceComputedOpening bound (by omega) digest pending oracle with
  | none => continuedAbortPublic aborted
  | some opening => currentPublicReferenceAcceptance parameters opening.points
      (computed_opening_selected_rank opening) gamma response transcript
      (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      salt labels (succeeded opening transcript)

/-- This derives an actual computed post-final adjacent comparison, including
continued failures. The only privacy premise is the previously proved generic
physical hidden-patch theorem, not a requested SMZ9 endpoint distance. -/
theorem actual_post_final_source_to_public_bound (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : AbortContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : SuccessfulContinuation (Work := Work) bound)
    (queryBound : ℕ) (abortBounded : aborted.queries ≤ queryBound)
    (successBounded : ∀ opening context visible, (succeeded opening transcript context visible).queries ≤ queryBound) :
    |actualPostFinalSource bound largeEnough statement batching gamma response transcript (packingValues witness)
        salt labels digest pending oracle aborted succeeded -
      actualPostFinalPublic bound largeEnough statement batching gamma response transcript
        salt labels digest pending oracle aborted succeeded| ≤ hiddenPatchLoss queryBound := by
  cases chosen : sourceComputedOpening bound (by omega) digest pending oracle with
  | none =>
      simp only [actualPostFinalSource, actualPostFinalPublic, chosen]
      rw [← uniform_average_const (A := SourceRemainingCoins Goldilocks) (continuedAbortPublic aborted)]
      apply uniform_average_difference_le
      intro base
      exact (continued_abort_source_to_public aborted salt labels _).trans (hidden_patch_loss_mono abortBounded)
  | some opening =>
      simp only [actualPostFinalSource, actualPostFinalPublic, chosen]
      exact canonical_statement_current_privacy_bound statement publicValues witness domain batching opening.points
        (computed_opening_interpolation_admissible opening) (computed_opening_points_nonzero opening)
        (computed_opening_selected_rank opening) (by decide) actual_interpolation_nodes_distinct
        gamma response transcript (computedOpeningFallback opening)
        (computedIndexChooser bound largeEnough (statementParameters statement batching) opening transcript digest oracle)
        salt labels (succeeded opening transcript) queryBound (successBounded opening)

/-- Averaging fresh full transcript coefficients preserves the same bound.
The nonce branch is computed from the independent digest before this average;
the exact reordering from the randomized final game is proved in the opening
schedule module. The entire future circuit may still depend on the transcript. -/
theorem actual_post_final_transcript_mixture_bound (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister)
    (aborted : PiopCoefficients Goldilocks → AbortContinuation (Other := OtherRawInput bound) (Work := Work))
    (succeeded : SuccessfulContinuation (Work := Work) bound)
    (queryBound : ℕ) (abortBounded : ∀ transcript, (aborted transcript).queries ≤ queryBound)
    (successBounded : ∀ opening transcript context visible,
      (succeeded opening transcript context visible).queries ≤ queryBound) :
    |uniformAverage (fun transcript =>
        actualPostFinalSource bound largeEnough statement batching gamma response transcript (packingValues witness)
          salt labels digest pending oracle (aborted transcript) succeeded) -
      uniformAverage (fun transcript =>
        actualPostFinalPublic bound largeEnough statement batching gamma response transcript
          salt labels digest pending oracle (aborted transcript) succeeded)| ≤ hiddenPatchLoss queryBound := by
  apply uniform_average_difference_le
  intro transcript
  exact actual_post_final_source_to_public_bound bound largeEnough statement publicValues witness domain
    batching gamma response transcript salt labels digest pending oracle (aborted transcript) succeeded queryBound
    (abortBounded transcript) (fun opening => successBounded opening transcript)

end
end HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
