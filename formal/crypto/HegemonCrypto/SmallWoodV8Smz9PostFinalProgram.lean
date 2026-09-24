import HegemonCrypto.SmallWoodV8Smz9PostFinalSerializer
import HegemonCrypto.SmallWoodV8Smz9MeasuredSameOracleAdjacent

/-! Literal post-final reads followed by the actual SMZ9 byte observation.
The code supplied to the honest game is defined before its oracle is chosen.
Opening certification is computed from returned words; its extra guard is
proved unreachable for the actual repeated-XOF schedule. -/

namespace HegemonCrypto.SmallWood.V8Smz9PostFinalProgram

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9PostFinalSerializer V8Smz9MeasuredSameOracleAdjacent
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

attribute [local irreducible] sourceChooseOpening sourceChooseOpeningLoop sourceOpeningXof sourceOpeningValid

def certifyOpening (result : OpeningResult) : Option ComputedOpening :=
  match result.selected with
  | none => none
  | some pair => if valid : sourceOpeningValid pair.2 = true then
      some ⟨pair.1, pair.2, (source_opening_valid_characterization pair.2).mp valid,
        result.pendingFailure⟩
    else none

theorem certify_actual_opening (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister) :
    certifyOpening (NonleafProgram.interpret oracle
      (sourceChooseOpening bound largeEnough digest pending)) =
      sourceComputedOpening bound largeEnough digest pending oracle := by
  unfold sourceComputedOpening
  dsimp only
  split
  · rename_i selected
    simp only [certifyOpening, selected]
  · rename_i pair selected
    have valid := (source_opening_valid_characterization pair.2).mpr
      (source_selected_opening_is_valid bound largeEnough digest pending oracle pair.1 pair.2 selected)
    simp only [certifyOpening, selected, dif_pos valid]

theorem source_decs_targets_ignore_pending (bound : Nat) (largeEnough : 37434 ≤ bound)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Fin 12 → Fin 20 → Goldilocks) (left right : Bool)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourceDecsSelection bound largeEnough points distinct digest heads tails left)).targets =
    (NonleafProgram.interpret oracle
      (sourceDecsSelection bound largeEnough points distinct digest heads tails right)).targets := by
  simp only [sourceDecsSelection, NonleafProgram.interpret, NonleafProgram.interpret_bind]

def sourcePhysicalIndexProgram (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks) :
    NonleafProgram (OtherRawInput bound) (DecsSelectionResult opening.points) :=
  sourceCurrentDecsSelection bound largeEnough parameters opening.points
    (computed_opening_points_distinct opening) transcript digest
    (sourceWitnessOpenings values opening.points coins.1)
    (sourcePcsFullView opening.points
      (currentPcsBaseForTranscript parameters values opening.points transcript coins.1) coins.2.1)
    (lvcsEarlierOutput opening.points coins.2.2) opening.pendingFailure

def sourcePhysicalFields (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (targets : IndexedTargets opening.points) : EagerAlgebraicFields Goldilocks :=
  currentEagerAlgebraicFields parameters opening.points (computed_opening_selected_rank opening)
    gamma response transcript (indexedPoints targets.val)
    (physicalView opening.points (sourceWitnessPolynomials values coins.1)
      (currentRecoveredMasksAtCoins parameters values transcript coins.1) coins.2.1 coins.2.2
      (indexedPoints targets.val))

def sourcePhysicalContext (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (result : DecsSelectionResult opening.points) : EagerContext opening.points :=
  result.targets.map fun targets =>
    (targets, sourcePhysicalFields parameters opening gamma response transcript values coins targets)

theorem source_physical_context_is_current (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (oracle : OtherRawInput bound → DigestRegister) :
    sourcePhysicalContext parameters opening gamma response transcript values coins
      (NonleafProgram.interpret oracle
        (sourcePhysicalIndexProgram bound largeEnough parameters opening transcript digest values coins)) =
    currentSourceContext parameters opening.points (computed_opening_selected_rank opening)
      gamma response transcript (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      values coins := by
  rw [current_source_context_is_physical]
  unfold sourcePhysicalContext sourcePhysicalFields sourceChosenIndices
    computedIndexChooser sourceCurrentIndexChooser sourcePhysicalIndexProgram sourceCurrentDecsSelection
  rw [source_decs_targets_ignore_pending (left := opening.pendingFailure) (right := false)]

theorem source_physical_fields_reproduce_index_program (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (targets : IndexedTargets opening.points) :
    sourceFieldsDecsSelection bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (sourcePhysicalFields parameters opening gamma response transcript values coins targets)
      opening.pendingFailure =
    sourcePhysicalIndexProgram bound largeEnough parameters opening transcript digest values coins := by
  unfold sourcePhysicalFields
  rw [current_fields_reproduce_source_decs_selection]
  rfl

def finishBytes (pending : Bool) (bytes : List CanonicalBytes.Byte) : Except String (List CanonicalBytes.Byte) :=
  match sourceScopeFinish pending bytes with
  | .error message => .error message
  | .ok encoded => if encoded.length ≤ 131072 then .ok encoded
      else .error "smallwood SMZ8/SMZ9 inner proof exceeds the 131072-byte cap"

def sourceSelectedBytes (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (result : DecsSelectionResult opening.points) : Except String (List CanonicalBytes.Byte) :=
  match result.targets with
  | none => .error "fixed DECS sampler exhausted its candidate pool"
  | some targets => finishBytes result.pendingFailure
      (sourceProofBytes salt opening.nonce digest tree targets.val
        (sourcePhysicalFields parameters opening gamma response transcript values coins targets)
        (fun index => tapes (targets.val index)))

def sourceSelectedBytesProgram (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable) :
    NonleafProgram (OtherRawInput bound) (Except String (List CanonicalBytes.Byte)) :=
  NonleafProgram.bind
    (sourcePhysicalIndexProgram bound largeEnough parameters opening transcript digest values coins)
    (fun result => .done (sourceSelectedBytes parameters opening gamma response transcript digest
      values coins salt tree tapes result))

def sourcePostFinalBytesProgram (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable) :
    NonleafProgram (OtherRawInput bound) (Except String (List CanonicalBytes.Byte)) :=
  NonleafProgram.bind (sourceChooseOpening bound (by omega) digest pending) fun result =>
    match certifyOpening result with
    | none => .done (.error "smallwood opening nonce trial limit exhausted")
    | some opening => sourceSelectedBytesProgram bound largeEnough parameters opening gamma response
        transcript digest values coins salt tree tapes

attribute [local irreducible] sourcePhysicalIndexProgram sourcePhysicalFields sourceProofBytes
  currentSourceContext

theorem source_selected_program_returns_public_bytes (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (opening : ComputedOpening)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle (sourceSelectedBytesProgram bound largeEnough parameters opening
      gamma response transcript digest values coins salt tree tapes) =
    let context := currentSourceContext parameters opening.points (computed_opening_selected_rank opening)
      gamma response transcript (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
      values coins
    sourceContextBytes bound largeEnough salt opening digest tree oracle context
      ((splitTapes (openedOrEmpty (contextSelection context))) tapes).1 := by
  dsimp only
  rw [← source_physical_context_is_current]
  simp only [sourceSelectedBytesProgram, NonleafProgram.interpret_bind, NonleafProgram.interpret]
  generalize resultEq : NonleafProgram.interpret oracle
      (sourcePhysicalIndexProgram bound largeEnough parameters opening transcript digest values coins) = result
  obtain ⟨challenge, sampled, targets, pending⟩ := result
  cases targets with
  | none => rfl
  | some targets =>
      simp only [sourcePhysicalContext, Option.map_some, sourceSelectedBytes, sourceContextBytes,
        source_physical_fields_reproduce_index_program, resultEq, finishBytes]
      rfl

def sourcePublicPostFinalBytes (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister) : Except String (List CanonicalBytes.Byte) :=
  match sourceComputedOpening bound (by omega) digest pending oracle with
  | none => .error "smallwood opening nonce trial limit exhausted"
  | some opening =>
      let context := currentSourceContext parameters opening.points (computed_opening_selected_rank opening)
        gamma response transcript (computedIndexChooser bound largeEnough parameters opening transcript digest oracle)
        values coins
      sourceContextBytes bound largeEnough salt opening digest tree oracle context
        ((splitTapes (openedOrEmpty (contextSelection context))) tapes).1

/-- This is an execution theorem for the pre-oracle source program, not a
free oracle-dependent continuation supplied to the reprogramming premise. -/
theorem source_post_final_program_returns_public_bytes (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle (sourcePostFinalBytesProgram bound largeEnough parameters
      gamma response transcript digest pending values coins salt tree tapes) =
    sourcePublicPostFinalBytes bound largeEnough parameters gamma response transcript digest pending
      values coins salt tree tapes oracle := by
  simp only [sourcePostFinalBytesProgram, NonleafProgram.interpret_bind, certify_actual_opening]
  unfold sourcePublicPostFinalBytes
  cases sourceComputedOpening bound (by omega) digest pending oracle with
  | none => rfl
  | some opening =>
      exact source_selected_program_returns_public_bytes bound largeEnough parameters opening
        gamma response transcript digest values coins salt tree tapes oracle

variable {Work : Type} [Fintype Work]

def sourcePostFinalProgram (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (next : Except String (List CanonicalBytes.Byte) → Program (LeafInput ⊕ OtherRawInput bound) Work) :
    Program (LeafInput ⊕ OtherRawInput bound) Work :=
  NonleafProgram.compile (sourcePostFinalBytesProgram bound largeEnough parameters gamma response transcript
    digest pending values coins salt tree tapes) next

theorem source_post_final_program_executes_actual_bytes (randomized : Bool)
    (bound : Nat) (largeEnough : 37434 ≤ bound) (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (next : Except String (List CanonicalBytes.Byte) → Program (LeafInput ⊕ OtherRawInput bound) Work)
    (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    run randomized (sourcePostFinalProgram bound largeEnough parameters gamma response transcript digest pending
      values coins salt tree tapes next) oracle state =
    run randomized (next (sourcePublicPostFinalBytes bound largeEnough parameters gamma response transcript
      digest pending values coins salt tree tapes (fun input => oracle (Sum.inr input)))) oracle state := by
  rw [sourcePostFinalProgram, NonleafProgram.compiled_execution,
    source_post_final_program_returns_public_bytes]

theorem source_post_final_leaf_overlay_remains (randomized : Bool)
    (bound : Nat) (largeEnough : 37434 ≤ bound) (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (pending : Bool)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (next : Except String (List CanonicalBytes.Byte) → Program (LeafInput ⊕ OtherRawInput bound) Work)
    (oldLeaf : LeafInput → DigestRegister) (other : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister) (payloads : LeafIndex → LeafSuffix)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    let actualOracle := fullSourceOverlay oldLeaf other labels Finset.univ
      (fun _ => canonicalLeafHeader salt) payloads tapes
    run randomized (sourcePostFinalProgram bound largeEnough parameters gamma response transcript digest pending
      values coins salt tree tapes next) actualOracle state =
    run randomized (next (sourcePublicPostFinalBytes bound largeEnough parameters gamma response transcript
      digest pending values coins salt tree tapes other)) actualOracle state := by
  dsimp only
  rw [source_post_final_program_executes_actual_bytes]
  rfl

end
end HegemonCrypto.SmallWood.V8Smz9PostFinalProgram
