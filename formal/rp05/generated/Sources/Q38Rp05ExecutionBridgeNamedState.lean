import Q38Rp05ExecutionBridgeFourier
import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames

namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

section IndexedRawEnvironment

variable {Input Work Index : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Index] [DecidableEq Index]

/-- A named complete oracle branch with the whole saved-label table retained
as an orthogonal environment register. -/
def vectorLabeledOracleState (oracle : Input → DigestRegister)
    (labels : Index → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    ResponseCmsState Input ((Index → DigestRegister) × Work) :=
  fun basis =>
    if basis.database = totalDatabase oracle ∧ basis.workspace.1 = labels then
      state (basis.input, basis.phase, basis.workspace.2)
    else 0

/-- Classical coordinate action of one indexed raw oracle/label swap. -/
def swapOracleLabels (key : Input) (index : Index)
    (pair : (Input → DigestRegister) × (Index → DigestRegister)) :
    (Input → DigestRegister) × (Index → DigestRegister) :=
  (Function.update pair.1 key (pair.2 index),
    Function.update pair.2 index (pair.1 key))

omit [Fintype Work] [DecidableEq Work] in
/-- The concrete indexed raw swap is exactly the classical complete-oracle /
saved-label transposition on every named state. -/
theorem indexed_raw_swap_vector_labeled_state
    (key : Input) (index : Index)
    (oracle : Input → DigestRegister) (labels : Index → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    indexedRawSwap key index (vectorLabeledOracleState oracle labels state) =
      vectorLabeledOracleState
        (Function.update oracle key (labels index))
        (Function.update labels index (oracle key)) state := by
  funext basis
  cases value : basis.database key with
  | none =>
      have oldImpossible : basis.database ≠ totalDatabase oracle := by
        intro equal
        have atKey := congrFun equal key
        simp [totalDatabase, value] at atKey
      have newImpossible : basis.database ≠
          totalDatabase (Function.update oracle key (labels index)) := by
        intro equal
        have atKey := congrFun equal key
        simp [totalDatabase, value] at atKey
      simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap,
        swapBasis, vectorLabeledOracleState, value, oldImpossible,
        newImpossible]
  | some answer =>
      unfold indexedRawSwap transportWorkspace
      simp only [labelSplit, rawSwap, swapBasis, value,
        vectorLabeledOracleState]
      congr 1
      apply propext
      constructor
      · rintro ⟨databaseEq, labelEq⟩
        constructor
        · funext input
          by_cases same : input = key
          · subst input
            have atAnswer := congrFun labelEq index
            have answerEq : answer = labels index := by
              simpa [labelSplit, Equiv.funSplitAt, Equiv.piSplitAt] using atAnswer
            calc
              basis.database key = some answer := value
              _ = some (labels index) := congrArg some answerEq
              _ = totalDatabase (Function.update oracle key (labels index)) key := by
                simp [totalDatabase]
          · have atInput := congrFun databaseEq input
            simpa [setDatabaseCoordinate, totalDatabase, value,
              Function.update_of_ne same, same] using atInput
        · funext site
          by_cases same : site = index
          · subst site
            have atKey := congrFun databaseEq key
            simpa [setDatabaseCoordinate, totalDatabase, value] using atKey
          · have atSite := congrFun labelEq site
            simpa [Function.update_of_ne same, same, labelSplit, value] using atSite
      · rintro ⟨databaseEq, labelEq⟩
        constructor
        · funext input
          by_cases same : input = key
          · subst input
            have atKey := congrFun labelEq index
            simpa [setDatabaseCoordinate, totalDatabase, value] using atKey
          · have atInput := congrFun databaseEq input
            simpa [setDatabaseCoordinate, totalDatabase, value,
              Function.update_of_ne same, same] using atInput
        · funext site
          by_cases same : site = index
          · subst site
            have atKey := congrFun databaseEq key
            simpa [setDatabaseCoordinate, totalDatabase, value] using atKey
          · have atSite := congrFun labelEq site
            simpa [Function.update_of_ne same, same, labelSplit, value] using atSite

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
