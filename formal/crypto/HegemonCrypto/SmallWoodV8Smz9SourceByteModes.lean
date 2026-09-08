import HegemonCrypto.SmallWoodV8Smz9SourceByteProgram

/-! Changing the frozen future bit is justified by the complete retained
future's actual execution equality, not by dropping selected events. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceByteProgram

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9PostFinalProgram V8Smz9PostFinalPhysical V8Smz9BytePrefix
open V8Smz9MeasuredSameOracleAdjacent V8Smz9EagerOracleGame
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work]

attribute [local irreducible] V8Smz9HonestWholeViewGames.run uniformAverage

theorem raw_source_byte_continuation_modes_congr (leftMode rightMode : Bool)
    (bound queryBound : Nat) (job : BytePivotJob (Work := Work) bound queryBound)
    (next : ByteFuture (Work := Work) bound) (bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound)
    (remaining : ∀ bytes oracle state,
      V8Smz9HonestWholeViewGames.run leftMode (job.next bytes) oracle state =
        V8Smz9HonestWholeViewGames.run rightMode (next bytes) oracle state)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    rawByteSourceKernel leftMode bound queryBound job oracle state =
      rawByteSourceKernel rightMode bound queryBound
        (replaceByteNext bound queryBound job next bounded) oracle state := by
  unfold rawByteSourceKernel physicalPostFinalAcceptance replaceByteNext
  simp_rw [source_post_final_program_executes_actual_bytes]
  apply congrArg uniformAverage
  funext coins
  apply congrArg uniformAverage
  funext tapes
  exact remaining _ _ state

theorem source_byte_continuation_modes_congr (outerLeft outerRight leftMode rightMode : Bool)
    (bound queryBound : Nat) (job : BytePivotJob (Work := Work) bound queryBound)
    (next : ByteFuture (Work := Work) bound) (bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound)
    (remaining : ∀ bytes oracle state,
      V8Smz9HonestWholeViewGames.run leftMode (job.next bytes) oracle state =
        V8Smz9HonestWholeViewGames.run rightMode (next bytes) oracle state)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run outerLeft (sourceByteProgram leftMode bound queryBound job) oracle state =
      V8Smz9MixedMaskCompiler.run outerRight
        (sourceByteProgram rightMode bound queryBound (replaceByteNext bound queryBound job next bounded))
        oracle state := by
  rw [source_byte_program_executes_raw_kernel, source_byte_program_executes_raw_kernel]
  exact raw_source_byte_continuation_modes_congr leftMode rightMode bound queryBound job next bounded
    remaining oracle state


end
end HegemonCrypto.SmallWood.V8Smz9SourceByteProgram
