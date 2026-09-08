import HegemonCrypto.SmallWoodV8Smz9PublicByteProgram
import HegemonCrypto.SmallWoodV8Smz9MixedLiteralWrites
import HegemonCrypto.SmallWoodV8Smz9PostFinalQueryBudget
import HegemonCrypto.SmallWoodV8Smz9MixedAdapterAccounting

/-! Both sides of the byte pivot are operational pre-oracle programs.
The source uses the checked literal all-leaf replay, not an injected table;
the reference uses its actual opened-only replay. One initial correction log
and the entire measured prior history are included in each compiled game. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceByteProgram

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9CurrentPublicContext V8Smz9HonestHybrid V8Smz9ZeroKnowledge
open V8Smz9PrivacyGameComposition V8Smz9PostFinalQueryBudget
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9DynamicPhysicalTransport V8Smz9PostFinalProgram V8Smz9PostFinalPhysical
open V8Smz9BytePrefix V8Smz9MeasuredPrefix V8Smz9PublicByteProgram V8Smz9MeasuredSameOracleAdjacent
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical BigOperators

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work]

def byteRecoveredMasks (bound queryBound : Nat) (job : BytePivotJob (Work := Work) bound queryBound)
    (coins : SourceRemainingCoins Goldilocks) : JointMaskCoins Goldilocks :=
  jointMaskInverse job.gamma (currentJointHeads (packingValues job.witness) coins) coins.2.2
    (currentJointUnmasked job.statement (fun _ => job.batching) (packingValues job.witness) coins)
    (job.response, job.transcript)

def sourceByteProgram (futureMode : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) : MixedProgram (FullRawInput bound) Work :=
  .random (finiteCoins (SourceRemainingCoins Goldilocks)) fun coins =>
    .random (finiteCoins TapeTable) fun tapes =>
      V8Smz9MixedMaskCompiler.actualLeafWrites (packingValues job.witness) coins
        (byteRecoveredMasks bound queryBound job coins) job.salt tapes job.labels
        (V8Smz9MixedMaskCompiler.fixedProgram futureMode
          (sourcePostFinalProgram bound job.largeEnough (statementParameters job.statement job.batching)
            job.gamma job.response job.transcript job.digest job.pending (packingValues job.witness)
            coins job.salt job.tree tapes job.next))

attribute [local irreducible] V8Smz9HonestWholeViewGames.run V8Smz9MixedMaskCompiler.run
  V8Smz9MixedMaskCompiler.actualLeafWrites sourcePostFinalProgram actualLeafOverlay uniformAverage

theorem recovered_byte_overlay_is_source (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) (coins : SourceRemainingCoins Goldilocks)
    (tapes : TapeTable) (oracle : FullOracle bound) :
    actualLeafOverlay oracle (packingValues job.witness) coins (byteRecoveredMasks bound queryBound job coins)
      job.salt tapes job.labels =
    fullSourceOverlay (fun input => oracle (Sum.inl input)) (fun input => oracle (Sum.inr input))
      job.labels Finset.univ (fun _ => canonicalLeafHeader job.salt)
      (currentSourceSuffix (statementParameters job.statement job.batching) (packingValues job.witness)
        job.gamma job.response job.transcript coins) tapes := by
  have suffix := current_joint_inverse_recovers_source_suffix job.statement (fun _ => job.batching)
    (packingValues job.witness) coins job.gamma (job.response, job.transcript)
  unfold actualLeafOverlay byteRecoveredMasks
  rw [suffix]

theorem source_byte_program_executes_raw_kernel (outerMode futureMode : Bool)
    (bound queryBound : Nat) (job : BytePivotJob (Work := Work) bound queryBound)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run outerMode (sourceByteProgram futureMode bound queryBound job) oracle state =
      rawByteSourceKernel futureMode bound queryBound job oracle state := by
  unfold sourceByteProgram rawByteSourceKernel physicalPostFinalAcceptance
  simp only [V8Smz9MixedMaskCompiler.run]
  apply congrArg uniformAverage
  funext coins
  apply congrArg uniformAverage
  funext tapes
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_execution,
    V8Smz9MixedMaskCompiler.fixed_program_execution, recovered_byte_overlay_is_source]

/-- The concrete source and public byte compilers are inserted into the
same actual prior program before the initial uniform oracle draw. The local
subnormalized bound is proved from the source byte theorem, not supplied. -/
theorem operational_history_byte_pivot_bound (historyMode futureMode : Bool) (bound queryBound : Nat)
    (history : Prefix (FullRawInput bound) Work (BytePivotJob (Work := Work) bound queryBound))
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |V8Smz9HonestWholeViewGames.acceptance historyMode
        (V8Smz9MixedMaskCompiler.compile
          (compilePrefix history (sourceByteProgram futureMode bound queryBound)) []) initial -
      V8Smz9HonestWholeViewGames.acceptance historyMode
        (V8Smz9MixedMaskCompiler.compile
          (compilePrefix history (fun job => publicByteProgram futureMode bound job.toPublicBytePivot)) []) initial| ≤
      hiddenPatchLoss queryBound := by
  rw [compiled_prefix_acceptance, compiled_prefix_acceptance]
  apply actual_history_prefix_pivot_bound historyMode history _ _ (hiddenPatchLoss queryBound)
  · rw [current_hidden_patch_loss_closed_form]
    positivity
  · intro job oracle state
    rw [source_byte_program_executes_raw_kernel, public_byte_program_executes_raw_kernel]
    exact actual_byte_pivot_subnormalized_bound futureMode bound queryBound job oracle state
  · exact normalized

theorem source_byte_program_query_bound (futureMode : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) :
    V8Smz9MixedMaskCompiler.queryCount (sourceByteProgram futureMode bound queryBound job) ≤
      8388705 + queryBound := by
  apply Finset.sup_le
  intro coins _
  apply Finset.sup_le
  intro tapes _
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_query_count,
    V8Smz9MixedMaskCompiler.fixed_program_query_count]
  have counted := source_post_final_query_bound bound job.largeEnough
    (statementParameters job.statement job.batching) job.gamma job.response job.transcript job.digest
    (packingValues job.witness) coins job.salt job.tree tapes job.pending job.next queryBound job.bounded
  omega

def replaceByteNext (bound queryBound : Nat) (job : BytePivotJob (Work := Work) bound queryBound)
    (next : ByteFuture (Work := Work) bound) (bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound) :
    BytePivotJob (Work := Work) bound queryBound :=
  { job with next := next, bounded := bounded }

/-- Replacing the complete future under the source call preserves a
subnormalized continuation bound. All current source work is classical and
atomic, so its private sampling and persistent writes retain the same input
Born weight on every branch. -/
theorem raw_source_byte_continuation_bound (futureMode : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound)
    (next : ByteFuture (Work := Work) bound) (bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound)
    (loss : ℝ)
    (remaining : ∀ bytes oracle state,
      |V8Smz9HonestWholeViewGames.run futureMode (job.next bytes) oracle state -
        V8Smz9HonestWholeViewGames.run futureMode (next bytes) oracle state| ≤ loss * ‖state‖ ^ 2)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    |rawByteSourceKernel futureMode bound queryBound job oracle state -
      rawByteSourceKernel futureMode bound queryBound (replaceByteNext bound queryBound job next bounded)
        oracle state| ≤ loss * ‖state‖ ^ 2 := by
  unfold rawByteSourceKernel physicalPostFinalAcceptance replaceByteNext
  simp_rw [source_post_final_program_executes_actual_bytes]
  apply uniform_average_difference_le
  intro coins
  apply uniform_average_difference_le
  intro tapes
  exact remaining _ _ state

end
end HegemonCrypto.SmallWood.V8Smz9SourceByteProgram
