import Q38Rp05NonleafComposition
import Q38Rp05CurrentP10

/-! The entire current request's nonleaf computation, recorded once before
serialization. The source coins and labels are fixed arguments; leaf tapes
are absent from the prefix. Nonce and index aborts remain actual outcomes.
Source only: no Lean compilation has been run for this module. -/
namespace HegemonCrypto.SmallWood.Q38Rp05RecordedRequest

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentP10
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05NonleafComposition
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

attribute [local irreducible]
  HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.selectedBytes

structure RequestRecord (dsl : RelationDsl) (statement : Statement) where
  parameters : Parameters dsl statement
  gamma : Gamma Goldilocks
  reply : D
  coefficients : Q
  digest : DigestRegister
  tree : List (List DigestRegister)
  postFinal : CurrentRecordedPostFinal

def recordedPostFinal
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (computed : PrefinalResult × D) (coefficients : Q)
    (digest : DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound) (RequestRecord dsl statement) :=
  let parameters := decodedParameters dsl statement computed.1.piopGamma
  let gamma := decodedQ38DecsGamma computed.1.decsGamma
  let pending := sourcePendingFailure
    (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma
  NonleafProgram.bind (rp05ChooseOpening bound (by omega) digest pending)
    fun nonce =>
      match certifyOpening nonce with
      | none => .done ⟨parameters, gamma, computed.2, coefficients, digest,
          computed.1.tree, .nonceAbort⟩
      | some opening =>
          NonleafProgram.bind
            (currentSelectIndices bound largeEnough opening.points
              (computed_opening_points_distinct opening) digest
              (combinationHeads dsl statement parameters opening.points
                coefficients (sourceWitnessOpenings values opening.points base.1)
                (sourcePcsFullView opening.points
                  (pcsBase opening.points masks.1 computed.2) base.2.1))
              (earlier opening.points base.2.2) opening.pendingFailure)
          fun selected => .done ⟨parameters, gamma, computed.2, coefficients,
              digest, computed.1.tree, .opened opening selected⟩

private theorem interpret_read_atomic
    {Other Result : Type} (oracle : Other → DigestRegister)
    (input : Other) (rest : DigestRegister → NonleafProgram Other Result) :
    NonleafProgram.interpret oracle (.read input rest) =
      NonleafProgram.interpret oracle (rest (oracle input)) := by
  rfl

private theorem interpret_recordedPostFinal
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (computed : PrefinalResult × D) (coefficients : Q)
    (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (recordedPostFinal largeEnough dsl statement values base masks computed
        coefficients digest) =
      let parameters := decodedParameters dsl statement computed.1.piopGamma
      let gamma := decodedQ38DecsGamma computed.1.decsGamma
      let pending := sourcePendingFailure
        (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma
      match certifyOpening (NonleafProgram.interpret oracle
          (rp05ChooseOpening bound (by omega) digest pending)) with
      | none => ⟨parameters, gamma, computed.2, coefficients, digest,
          computed.1.tree, .nonceAbort⟩
      | some opening =>
          let selected := NonleafProgram.interpret oracle
            (currentSelectIndices bound largeEnough opening.points
              (computed_opening_points_distinct opening) digest
              (combinationHeads dsl statement parameters opening.points
                coefficients (sourceWitnessOpenings values opening.points base.1)
                (sourcePcsFullView opening.points
                  (pcsBase opening.points masks.1 computed.2) base.2.1))
              (earlier opening.points base.2.2) opening.pendingFailure)
          ⟨parameters, gamma, computed.2, coefficients, digest,
            computed.1.tree, .opened opening selected⟩ := by
  unfold recordedPostFinal
  dsimp only
  rw [NonleafProgram.interpret_bind]
  cases opened : certifyOpening (NonleafProgram.interpret oracle
      (rp05ChooseOpening bound (by omega) digest
        (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma)
          computed.1.piopGamma))) with
  | none => rfl
  | some opening =>
      rw [NonleafProgram.interpret_bind]
      rfl

private def currentRequestPostFinalOutput
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (base : RemainingCoins Goldilocks)
    (masks : Q × D) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (computed : PrefinalResult × D) (coefficients : Q)
    (digest : DigestRegister) : Except String (List Byte) :=
  let parameters := decodedParameters dsl statement computed.1.piopGamma
  let gamma := decodedQ38DecsGamma computed.1.decsGamma
  let pending := sourcePendingFailure
    (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma
  NonleafProgram.interpret oracle
    (currentHonestPostFinalProgram bound largeEnough dsl statement parameters
      values base masks.1 gamma computed.2 coefficients digest pending salt
      computed.1.tree tapes)

def recordedPrefix
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound) (RequestRecord dsl statement) :=
  NonleafProgram.bind
    (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
      base masks widthBound) fun computed =>
    let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
      values base masks computed.1.piopGamma
    .read (currentFinalKey bound (by omega) computed.1.hashFpp coefficients)
      fun digest =>
      recordedPostFinal largeEnough dsl statement values base masks computed
        coefficients digest

private theorem recorded_prefix_interpreted
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (computed : PrefinalResult × D)
    (hComputed : NonleafProgram.interpret oracle
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = computed) :
    NonleafProgram.interpret oracle
      (recordedPrefix largeEnough dsl statement values salt widthBound
        base masks labels) =
      let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
        values base masks computed.1.piopGamma
      let digest := oracle (currentFinalKey bound (by omega)
        computed.1.hashFpp coefficients)
      NonleafProgram.interpret oracle
        (recordedPostFinal largeEnough dsl statement values base masks
          computed coefficients digest) := by
  simp only [recordedPrefix, NonleafProgram.interpret_bind]
  rw [hComputed]
  rw [interpret_read_atomic]

def recordBytes
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (salt : SaltBytes)
    (tapes : TapeTable) (record : RequestRecord dsl statement) :
    Except String (List Byte) :=
  match record.postFinal with
  | .nonceAbort => .error "smallwood opening nonce trial limit exhausted"
  | .opened opening selected =>
    selectedBytes dsl statement record.parameters opening record.gamma
      record.reply record.coefficients record.digest salt record.tree tapes
      (selectedPhysicalView values base q record.reply selected) selected

private theorem current_request_result_eq_postfinal_output
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oracle : Rp05FullRawInput bound → DigestRegister)
    (computed : PrefinalResult × D)
    (hComputed : NonleafProgram.interpret
      (fun input => oracle (Sum.inr input))
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = computed)
    (coefficients : Q)
    (hCoefficients : Q38Rp05RequestCompiler.transcript dsl statement
      values base masks computed.1.piopGamma = coefficients)
    (digest : DigestRegister)
    (hDigest : oracle (Sum.inr
      (currentFinalKey bound (by omega) computed.1.hashFpp coefficients)) =
      digest) :
    currentRequestResult largeEnough dsl statement values salt widthBound
      base masks tapes labels oracle =
    currentRequestPostFinalOutput largeEnough dsl statement values salt base
      masks tapes (fun input => oracle (Sum.inr input)) computed coefficients
      digest := by
  dsimp only [currentRequestResult, currentTwoReadResult,
    currentRequestPostFinalOutput]
  rw [hComputed, hCoefficients, hDigest]

private theorem current_selected_physical_view_eq_recorded
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    {points : Fin 6 → Goldilocks} (job : SelectionResult points) :
    currentSelectedPhysicalView values base q reply job =
      selectedPhysicalView values base q reply job := by
  cases job.targets <;> rfl

private theorem current_postfinal_recorded_bytes
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (base : RemainingCoins Goldilocks)
    (masks : Q × D) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (computed : PrefinalResult × D) (coefficients : Q)
    (digest : DigestRegister) :
    currentRequestPostFinalOutput largeEnough dsl statement values salt base
      masks tapes oracle computed coefficients digest =
    recordBytes dsl statement values base masks.1 salt tapes
      (NonleafProgram.interpret oracle
        (recordedPostFinal largeEnough dsl statement values base masks
          computed coefficients digest)) := by
  unfold currentRequestPostFinalOutput
  rw [current_post_final_executes, interpret_recordedPostFinal]
  cases opened : certifyOpening (NonleafProgram.interpret oracle
      (rp05ChooseOpening bound (by omega) digest
        (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma)
          computed.1.piopGamma))) with
  | none => simp only [opened, recordBytes]
  | some opening =>
      simp only [opened, recordBytes]
      rw [current_selected_physical_view_eq_recorded]

attribute [local irreducible]
  recordedPrefix recordedPostFinal recordBytes currentRequestPostFinalOutput
  HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest.currentRequestResult
  HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal.rp05CurrentPrefinal

/-- This is a compiler identity for the literal current request, not an
assumed match to an unrelated selector. Its one record supplies every byte
and the exact nonce/index exhaustion result. -/
theorem current_request_result_eq_recorded
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oracle : Rp05FullRawInput bound → DigestRegister) :
    currentRequestResult largeEnough dsl statement values salt widthBound
        base masks tapes labels oracle =
      recordBytes dsl statement values base masks.1 salt tapes
        (NonleafProgram.interpret (fun input => oracle (Sum.inr input))
          (recordedPrefix largeEnough dsl statement values salt widthBound
            base masks labels)) := by
  let other := fun input => oracle (Sum.inr input)
  let computed := NonleafProgram.interpret other
    (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
      base masks widthBound)
  let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
    values base masks computed.1.piopGamma
  let digest := other (currentFinalKey bound (by omega)
    computed.1.hashFpp coefficients)
  have hComputed : NonleafProgram.interpret other
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = computed := rfl
  have hCoefficients : Q38Rp05RequestCompiler.transcript dsl statement
      values base masks computed.1.piopGamma = coefficients := rfl
  have hDigest : other (currentFinalKey bound (by omega)
      computed.1.hashFpp coefficients) = digest := rfl
  have hCurrent :
      currentRequestResult largeEnough dsl statement values salt widthBound
          base masks tapes labels oracle =
        currentRequestPostFinalOutput largeEnough dsl statement values salt
          base masks tapes other computed coefficients digest := by
    exact current_request_result_eq_postfinal_output (bound := bound)
      largeEnough dsl statement values salt widthBound base masks tapes labels
      oracle computed hComputed coefficients hCoefficients digest hDigest
  have hPrefix := recorded_prefix_interpreted largeEnough dsl statement
    values salt widthBound base masks labels other computed hComputed
  have hPost := current_postfinal_recorded_bytes largeEnough dsl statement
    values salt base masks tapes other computed coefficients digest
  exact hCurrent.trans (hPost.trans
    (congrArg (recordBytes dsl statement values base masks.1 salt tapes)
      hPrefix.symm))

def recordUnopened {dsl : RelationDsl} {statement : Statement}
    (record : RequestRecord dsl statement) : Finset LeafIndex :=
  match record.postFinal with
  | .nonceAbort => Finset.univ
  | .opened _ selected => rp05AbortAwareUnopened selected

def recordAnchor {dsl : RelationDsl} {statement : Statement}
    (record : RequestRecord dsl statement) : Unopened (recordUnopened record) := by
  cases h : record.postFinal with
  | nonceAbort => exact ⟨0, by simp [recordUnopened, h]⟩
  | opened opening selected =>
    cases chosen : selected.targets with
    | none => exact ⟨0, by simp [recordUnopened, h, rp05AbortAwareUnopened, chosen]⟩
    | some targets =>
      simpa [recordUnopened, h, rp05AbortAwareUnopened, chosen] using
        q38Anchor targets.val targets.property.1

theorem record_bytes_ignore_unopened
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (salt : SaltBytes)
    (tapes : TapeTable) (record : RequestRecord dsl statement) :
    recordBytes dsl statement values base q salt tapes record =
      recordBytes dsl statement values base q salt
        (visiblePadding (recordUnopened record)
          ((tapeSplit (recordUnopened record) tapes).1)) record := by
  cases record with
  | mk parameters gamma reply coefficients digest tree postFinal =>
    cases postFinal with
    | nonceAbort => simp only [recordBytes]
    | opened opening selected =>
      simp only [recordBytes, recordUnopened]
      change selectedBytes dsl statement parameters opening gamma reply
          coefficients digest salt tree tapes
          (selectedPhysicalView values base q reply selected) selected =
        selectedBytes dsl statement parameters opening gamma reply coefficients
          digest salt tree
          (visiblePadding (rp05AbortAwareUnopened selected)
            ((tapeSplit (rp05AbortAwareUnopened selected) tapes).1))
          (selectedPhysicalView values base q reply selected) selected
      exact selected_bytes_ignore_unopened_tapes dsl statement parameters
        opening values base q gamma reply coefficients digest salt tree selected tapes

def recordContinuation
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (salt : SaltBytes)
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (record : RequestRecord dsl statement)
    (visible : Opened (recordUnopened record) → LeafTape) :
    Program (Rp05FullRawInput bound) Work :=
  next (recordBytes dsl statement values base q salt
    (visiblePadding (recordUnopened record) visible) record)

/-- P8/P9 now instantiated with the ENTIRE corrected request compiler,
including DECS, response-indexed PIOP, final digest, nonce, index and bytes.
There is no separate branch-game comparison premise. The sole loss is
downstream erasure; every current-prefix read is on the nonleaf carrier. -/
theorem current_recorded_complete_opening_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (queries : Nat) (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work)) :
    let selector := recordedPrefix largeEnough dsl statement values salt
      widthBound base masks labels
    let continuation := recordContinuation dsl statement values base masks.1 salt next
    let data := q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2
    |fullGame randomized (asSelection selector) recordUnopened continuation
        old other labels statement salt data state -
      publicGame randomized (asSelection selector) recordUnopened continuation
        old other labels statement salt data state| ≤
      (4 * (queries : ℝ) / (2 : ℝ)^256) * ‖state‖^2 := by
  exact current_nonleaf_retained_opening_bound_mass randomized
    (recordedPrefix largeEnough dsl statement values salt widthBound base masks labels)
    recordUnopened recordAnchor
    (recordContinuation dsl statement values base masks.1 salt next)
    old other labels statement salt
    (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
    queries (fun _ _ => bounded _) state

/-- Explicit whole-request probability, using the bytes/error produced by
the current compiler and the same old-oracle-indexed state. The Boolean
chooses the full leaf overlay or precisely the recorded retained set. -/
def recordedRequestProbability
    {bound : Nat} {Work : Type} [Fintype Work]
    (retainOnly : Bool) (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work)) : ℝ :=
  let recorded := NonleafProgram.interpret other
    (recordedPrefix largeEnough dsl statement values salt widthBound base masks labels)
  let programmed := if retainOnly then (recordUnopened recorded)ᶜ else Finset.univ
  uniformAverage fun tapes : TapeTable =>
    run randomized
      (next (currentRequestResult largeEnough dsl statement values salt
        widthBound base masks tapes labels (Sum.elim old other)))
      (overlay old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
        programmed tapes) state

/-- Both sides now name the literal complete request result rather than an
unidentified branch kernel. The same recorded selector determines bytes and
the retained keys; every current-prefix phase is present, including aborts. -/
theorem current_complete_recorded_probability_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (queries : Nat) (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work)) :
    |recordedRequestProbability false randomized largeEnough dsl statement values
        salt widthBound base masks labels next old other state -
      recordedRequestProbability true randomized largeEnough dsl statement values
        salt widthBound base masks labels next old other state| ≤
      (4 * (queries : ℝ) / (2 : ℝ)^256) * ‖state‖^2 := by
  let selector := recordedPrefix largeEnough dsl statement values salt
    widthBound base masks labels
  let continuation := recordContinuation dsl statement values base masks.1 salt next
  let data := q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2
  have fullIdentity :
      fullGame randomized (asSelection selector) recordUnopened continuation
        old other labels statement salt data state =
      recordedRequestProbability false randomized largeEnough dsl statement values
        salt widthBound base masks labels next old other state := by
    unfold fullGame recordedRequestProbability
    apply congrArg uniformAverage
    funext tapes
    rw [show realOracle old other labels statement salt data tapes =
      overlay old other labels statement salt data Finset.univ tapes from rfl]
    rw [current_nonleaf_feedback_exact]
    rw [current_request_result_eq_recorded]
    rw [record_bytes_ignore_unopened]
    rfl
  have retainedIdentity :
      publicGame randomized (asSelection selector) recordUnopened continuation
        old other labels statement salt data state =
      recordedRequestProbability true randomized largeEnough dsl statement values
        salt widthBound base masks labels next old other state := by
    unfold publicGame recordedRequestProbability
    apply congrArg uniformAverage
    funext tapes
    rw [execute_as_selection]
    rw [current_request_result_eq_recorded]
    rw [record_bytes_ignore_unopened]
    rfl
  rw [← fullIdentity, ← retainedIdentity]
  exact current_recorded_complete_opening_bound_mass randomized largeEnough dsl
    statement values salt widthBound base masks labels next queries bounded
    old other state

end
end HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
