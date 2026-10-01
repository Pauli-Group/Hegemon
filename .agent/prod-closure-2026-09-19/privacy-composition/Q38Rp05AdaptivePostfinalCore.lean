import Q38Rp05RetainedKernelJoin
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting
import SmzaRp05CurrentCoset406

/-! Concrete current-profile public request and adaptive schedule.
The existing correction-log compiler implements fixed published-label writes;
it does not resample a label or replay the transcript selector. Source only.
The remaining endpoint is identified in SCHEDULER_HANDOFF.md. -/
namespace HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentP10
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.Q38Rp05DependentP10
open HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

variable {bound : Nat} {Work : Type} [Fintype Work]
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05FullRawInput bound
abbrev Bytes := Except String (List Byte)

def uniformSource (A : Type) [Fintype A] [Nonempty A] : RandomSource :=
  ⟨A, inferInstance, inferInstance⟩

def mixedNonleaf {Result : Type} :
    NonleafProgram (Rp05OtherRawInput bound) Result →
    (Result → MixedProgram OracleInput Work) → MixedProgram OracleInput Work
  | .done result, next => next result
  | .read input rest, next => .honestRead (.inr input)
      (fun answer => mixedNonleaf (rest answer) next)

theorem mixed_nonleaf_executes {Result : Type} (mode : Bool)
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → MixedProgram OracleInput Work)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (mixedNonleaf program next) oracle state =
      V8Smz9MixedMaskCompiler.run mode
        (next (NonleafProgram.interpret (fun key => oracle (.inr key)) program))
        oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

/-- Ordered writes, including collisions, are the same literal batch update.
Answers are already sampled/published and are never replaced by fresh coins. -/
def writeBatch : (count : Nat) → (Fin count → OracleInput) →
    (Fin count → DigestRegister) → MixedProgram OracleInput Work → MixedProgram OracleInput Work
  | 0, _, _, next => next
  | count + 1, keys, answers, next =>
      .write (keys 0) (answers 0)
        (writeBatch count (fun i => keys i.succ) (fun i => answers i.succ) next)

theorem write_batch_executes (mode : Bool) (count : Nat)
    (keys : Fin count → OracleInput) (answers : Fin count → DigestRegister)
    (next : MixedProgram OracleInput Work) (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (writeBatch count keys answers next) oracle state =
      V8Smz9MixedMaskCompiler.run mode next
        (updateRp05Batch count keys answers oracle) state := by
  induction count generalizing oracle with
  | zero => rfl
  | succ count ih => exact ih _ _ _

def publicOpenedWrites
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks) (result : SelectionResult opening.points)
    (next : MixedProgram OracleInput Work) : MixedProgram OracleInput Work :=
  match result.targets, view.2.2.2 with
  | some _, some later =>
    let selected := selectedIndices result
    let heads := combinationHeads dsl statement parameters opening.points
      transcript view.1 view.2.1
    let targets := fun i =>
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint (selected i)
    let data := q38SelectedPublicData selected
      (q38PublicSuffix opening.points (computed_opening_selected_rank opening)
        gamma reply heads view.2.2.1 targets later)
    writeBatch 38
      (fun i => .inl (rp05SourceLeafInput statement salt
        (data (selected i)) (selected i) (tapes (selected i))))
      (fun i => labels (selected i)) next
  | _, _ => next

theorem public_opened_writes_executes
    (mode : Bool) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks) (result : SelectionResult opening.points)
    (next : MixedProgram OracleInput Work) (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode
      (publicOpenedWrites dsl statement parameters opening gamma reply transcript
        salt tapes labels view result next) oracle state =
      V8Smz9MixedMaskCompiler.run mode next
        (currentPublicOpenedOracleFromResult bound dsl statement parameters opening
          gamma reply transcript salt tapes labels view result oracle) state := by
  cases h : result.targets <;> cases v : view.2.2.2 <;>
    simp only [publicOpenedWrites, currentPublicOpenedOracleFromResult, h, v]
  exact write_batch_executes _ _ _ _ _ _ _

/-- The literal post-final phase, parameterized by the already computed record.
Keeping the record abstract avoids evaluating the concrete Merkle interpreter
while checking a theorem about its continuation. -/
def publicPostfinal
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (tapes : TapeTable)
    (stage : DynamicStage dsl statement) (reply : D) (transcript : Q)
    (next : Bytes → MixedProgram OracleInput Work) : MixedProgram OracleInput Work :=
  .honestRead (.inr (currentFinalKey bound (by omega) stage.hashFpp transcript))
    fun digest =>
  mixedNonleaf (rp05ChooseOpening bound (by omega) digest stage.pending) fun trial =>
  match certifyOpening trial with
  | none => next (.error "smallwood opening nonce trial limit exhausted")
  | some opening =>
    .random (uniformSource (RemainingView Goldilocks)) fun fullView =>
    mixedNonleaf (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement stage.parameters opening.points transcript
        fullView.1 fullView.2.1) fullView.2.2.1 opening.pendingFailure) fun selected =>
    let view : PartialView Goldilocks :=
      (fullView.1, fullView.2.1, fullView.2.2.1,
        selected.targets.map fun _ => fullView.2.2.2)
    publicOpenedWrites dsl statement stage.parameters opening stage.gamma reply transcript
      salt tapes labels view selected
      (next (selectedBytes dsl statement stage.parameters opening stage.gamma reply transcript
        digest salt stage.tree tapes view selected))

attribute [local irreducible] certifyOpening rp05ChooseOpening NonleafProgram.interpret

theorem public_postfinal_executes
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (tapes : TapeTable)
    (stage : DynamicStage dsl statement) (reply : D) (transcript : Q)
    (abortPoints : Fin 6 → Goldilocks)
    (next : Bytes → MixedProgram OracleInput Work)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (publicPostfinal largeEnough dsl statement salt labels tapes stage reply transcript next)
      oracle state =
    uniformAverage (fun fullView : RemainingView Goldilocks =>
      dynamicKernel largeEnough dsl statement salt tapes stage
        (fun key => oracle (Sum.inr key)) reply transcript
        (abortProjection (dynamicChoose largeEnough dsl statement abortPoints stage
          (fun key => oracle (Sum.inr key)) transcript) fullView)
        (dynamicContinuationObservation dsl statement salt tapes labels oracle state
          (fun bytes => V8Smz9MixedMaskCompiler.compile (next bytes) []))) := by
  let other := fun key => oracle (Sum.inr key)
  let digest := other (currentFinalKey bound (by omega) stage.hashFpp transcript)
  -- Expose both consumers of the same opening before splitting it. In
  -- particular, the partial-view selector has a dependent Targets motive;
  -- case splitting must substitute its discriminator as well as the kernel's.
  simp only [publicPostfinal, V8Smz9MixedMaskCompiler.run, mixed_nonleaf_executes,
    dynamicKernel, dynamicOpening, dynamicDigest, dynamicChoose, dynamicChooseCore,
    abortProjection]
  cases opened : certifyOpening (NonleafProgram.interpret other
      (rp05ChooseOpening bound (by omega) digest stage.pending)) with
  | none =>
    simp only [dynamicContinuationObservation, currentPublicOpenedOracleFromRecorded,
      V8Smz9MixedMaskCompiler.compile_executes,
      V8Smz9MixedMaskCompiler.effective_empty, uniform_average_const]
  | some opening =>
    simp only [V8Smz9MixedMaskCompiler.run, mixed_nonleaf_executes]
    apply congrArg uniformAverage
    funext fullView
    rw [public_opened_writes_executes]
    simp only [currentChooseTargets,
      dynamicContinuationObservation, currentPublicOpenedOracleFromRecorded,
      V8Smz9MixedMaskCompiler.compile_executes,
      V8Smz9MixedMaskCompiler.effective_empty]
    cases (NonleafProgram.interpret (fun key => oracle (Sum.inr key))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening)
        (oracle (Sum.inr (currentFinalKey bound (by omega) stage.hashFpp transcript)))
        (combinationHeads dsl statement stage.parameters opening.points transcript
          fullView.1 fullView.2.1) fullView.2.2.1 opening.pendingFailure)).targets <;> rfl

end
end HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
