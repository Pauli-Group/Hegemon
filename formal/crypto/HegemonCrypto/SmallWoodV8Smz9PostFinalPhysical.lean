import HegemonCrypto.SmallWoodV8Smz9PostFinalProgram

/-! Tape-disintegration and the byte-valued measured source endpoint. -/
namespace HegemonCrypto.SmallWood.V8Smz9PostFinalPhysical

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9CurrentPublicContext
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9PostFinalSerializer V8Smz9PostFinalProgram V8Smz9MeasuredSameOracleAdjacent
open V8Smz9MeasuredTablePublic V8Smz9MeasuredCurrentPrivacy V8Smz9MeasuredAdjacentComposition
open V8Smz9HonestLeafBatch
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

theorem uniform_average_tape_disintegration (opened : Finset LeafIndex)
    (observe : OpenedTapes (Tape := LeafTape) opened → HiddenTapes (Tape := LeafTape) opened → ℝ) :
    uniformAverage (fun tapes : TapeTable =>
      observe (splitTapes opened tapes).1 (splitTapes opened tapes).2) =
    uniformAverage (fun visible : OpenedTapes (Tape := LeafTape) opened =>
      uniformAverage (observe visible)) := by
  rw [uniform_average_equiv (splitTapes opened) (fun pair => observe pair.1 pair.2)]
  exact uniform_average_product observe

theorem uniform_average_tape_padding (opened : Finset LeafIndex)
    (observe : OpenedTapes (Tape := LeafTape) opened → HiddenTapes (Tape := LeafTape) opened → ℝ) :
    uniformAverage (fun tapes : TapeTable =>
      observe (splitTapes opened tapes).1 (splitTapes opened tapes).2) =
    uniformAverage (fun visiblePadding : TapeTable => uniformAverage (fun hiddenPadding : TapeTable =>
      observe (splitTapes opened visiblePadding).1 (splitTapes opened hiddenPadding).2)) := by
  rw [uniform_average_tape_disintegration]
  symm
  rw [uniform_average_tape_disintegration opened (fun visible _hidden =>
    uniformAverage (fun hiddenPadding : TapeTable => observe visible (splitTapes opened hiddenPadding).2))]
  simp_rw [uniform_average_const]
  apply congrArg uniformAverage
  funext visible
  rw [uniform_average_tape_disintegration opened (fun _visible hidden => observe visible hidden)]
  exact uniform_average_const _

variable {Work : Type} [Fintype Work]

abbrev ByteFuture (bound : Nat) := Except String (List CanonicalBytes.Byte) →
  Program (LeafInput ⊕ OtherRawInput bound) Work

def byteAbortFuture (bound : Nat) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) : MeasuredFuture (Work := Work) bound :=
  ⟨next (.error "smallwood opening nonce trial limit exhausted"), state, normalized⟩

def byteSuccessFuture (bound : Nat) (largeEnough : 37434 ≤ bound)
    (salt : SaltBytes) (digest : DigestRegister) (tree : List (List DigestRegister))
    (oracle : OtherRawInput bound → DigestRegister) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) : SuccessfulFuture (Work := Work) bound :=
  fun opening _transcript context visible =>
    ⟨next (sourceContextBytes bound largeEnough salt opening digest tree oracle context visible), state, normalized⟩

def physicalPostFinalAcceptance (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister) (tree : List (List DigestRegister))
    (oracle : FullOracle bound) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) : ℝ :=
  uniformAverage fun coins : SourceRemainingCoins Goldilocks =>
    uniformAverage fun tapes : TapeTable =>
      run randomized (sourcePostFinalProgram bound largeEnough parameters gamma response transcript digest pending
        values coins salt tree tapes next)
        (fullSourceOverlay (fun input => oracle (Sum.inl input)) (fun input => oracle (Sum.inr input))
          labels Finset.univ (fun _ => canonicalLeafHeader salt)
          (currentSourceSuffix parameters values gamma response transcript coins) tapes) state

attribute [local irreducible] V8Smz9HonestWholeViewGames.run sourcePostFinalProgram sourceContextBytes sourceComputedOpening
  sourcePublicPostFinalBytes currentSourceContext currentSourceSuffix

theorem measured_source_context_is_single_tape_average (randomized : Bool) (bound : Nat)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser opening.points)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : CurrentMeasuredFactory (Other := OtherRawInput bound) (Work := Work) opening.points) :
    measuredSourceContextAcceptance randomized parameters opening.points (computed_opening_selected_rank opening)
      gamma response transcript choose values coins salt labels continuation =
    let context := currentSourceContext parameters opening.points (computed_opening_selected_rank opening)
      gamma response transcript choose values coins
    uniformAverage fun tapes : TapeTable =>
      let future := continuation context (splitTapes (openedOrEmpty (contextSelection context)) tapes).1
      run randomized future.program
        (fullSourceOverlay future.oldLeaf future.other labels Finset.univ
          (fun _ => canonicalLeafHeader salt)
          (currentSourceSuffix parameters values gamma response transcript coins) tapes) future.initial := by
  let context := currentSourceContext parameters opening.points (computed_opening_selected_rank opening)
    gamma response transcript choose values coins
  let opened := openedOrEmpty (contextSelection context)
  let observe (visible : OpenedTapes (Tape := LeafTape) opened) (hidden : HiddenTapes (Tape := LeafTape) opened) :=
    let future := continuation context visible
    run randomized future.program
      (fullSourceOverlay future.oldLeaf future.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt)
        (currentSourceSuffix parameters values gamma response transcript coins)
        (mergeTapes opened visible hidden)) future.initial
  have padding := uniform_average_tape_padding opened observe
  change uniformAverage (fun visiblePadding : TapeTable => uniformAverage (fun hiddenPadding : TapeTable =>
    observe (splitTapes opened visiblePadding).1 (splitTapes opened hiddenPadding).2)) =
    uniformAverage (fun tapes =>
    let future := continuation context (splitTapes opened tapes).1
    run randomized future.program
      (fullSourceOverlay future.oldLeaf future.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt)
        (currentSourceSuffix parameters values gamma response transcript coins) tapes) future.initial)
  rw [← padding]
  apply congrArg uniformAverage
  funext tapes
  dsimp only [observe, mergeTapes]
  rw [(splitTapes opened).symm_apply_apply]

/-- The literal charged program and the measured-source endpoint are the
same experiment after disintegrating one fresh full tape table. Both retain
the complete actual leaf overlay through every byte/error continuation. -/
theorem physical_post_final_is_same_oracle_source (randomized : Bool)
    (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister) (tree : List (List DigestRegister))
    (oracle : FullOracle bound) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) :
    physicalPostFinalAcceptance randomized bound largeEnough (statementParameters statement batching)
      gamma response transcript digest pending values salt labels tree oracle next state =
    sameOraclePostFinalSource randomized bound largeEnough statement batching gamma response transcript
      values salt labels digest pending oracle (byteAbortFuture bound next state normalized)
      (byteSuccessFuture bound largeEnough salt digest tree (fun input => oracle (Sum.inr input))
        next state normalized) := by
  unfold physicalPostFinalAcceptance
  simp_rw [source_post_final_leaf_overlay_remains]
  unfold sameOraclePostFinalSource measuredActualPostFinalSource
  cases chosen : sourceComputedOpening bound (by omega) digest pending (fun input => oracle (Sum.inr input)) with
  | none =>
      simp only [sourcePublicPostFinalBytes, chosen, measuredContinuedAbortSource,
        byteAbortFuture, withPersistentOracle]
  | some opening =>
      simp only [sourcePublicPostFinalBytes, chosen, measuredCurrentFullSourceAcceptance]
      apply congrArg uniformAverage
      funext coins
      rw [measured_source_context_is_single_tape_average]
      rfl

/-- Explicit byte/error reference. Its inputs contain no private witness or
private source coins. Only the already-public transcript/commitment data,
the common oracle, and the caller's complete byte continuation occur. -/
def bytePostFinalReference (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (tree : List (List DigestRegister))
    (oracle : FullOracle bound) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) : ℝ :=
  sameOraclePostFinalPublic randomized bound largeEnough statement batching gamma response transcript
    salt labels digest pending oracle (byteAbortFuture bound next state normalized)
    (byteSuccessFuture bound largeEnough salt digest tree (fun input => oracle (Sum.inr input))
      next state normalized)

/-- The actual source opening/index/serialization program is now the left
experiment. The bound is derived from packed acceptance and the checked
measured hidden-patch theorem; no endpoint equality or distance is assumed. -/
theorem actual_byte_program_to_public_reference_bound (randomized : Bool)
    (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : V8Smz9SemanticBinding.CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (tree : List (List DigestRegister))
    (oracle : FullOracle bound) (next : ByteFuture (Work := Work) bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1)
    (queryBound : Nat) (bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound) :
    |physicalPostFinalAcceptance randomized bound largeEnough (statementParameters statement batching)
        gamma response transcript digest pending (packingValues witness) salt labels tree oracle next state -
      bytePostFinalReference randomized bound largeEnough statement batching gamma response transcript
        digest pending salt labels tree oracle next state normalized| ≤ hiddenPatchLoss queryBound := by
  rw [physical_post_final_is_same_oracle_source randomized bound largeEnough statement batching gamma response
    transcript digest pending (packingValues witness) salt labels tree oracle next state normalized]
  exact same_oracle_post_final_source_to_public_bound randomized bound largeEnough statement publicValues witness
    domain batching gamma response transcript salt labels digest pending oracle
    (byteAbortFuture bound next state normalized)
    (byteSuccessFuture bound largeEnough salt digest tree (fun input => oracle (Sum.inr input)) next state normalized)
    queryBound (bounded _) (fun _opening _context _visible => bounded _)

end
end HegemonCrypto.SmallWood.V8Smz9PostFinalPhysical
