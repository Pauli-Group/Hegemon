import HegemonCrypto.SmallWoodV8Smz9TypedScheduleValidity
import Mathlib.Tactic.FinCases
import Mathlib.Data.Fintype.Fin

namespace HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
set_option Elab.async false
set_option maxHeartbeats 1200000
set_option maxRecDepth 10000

def expectedRoles : List Role :=
  [.transactionPrf] ++
  (List.range 3).map (Role.inputNote 0) ++ (List.range 32).map (Role.inputMerkle 0) ++ [.inputNullifier 0] ++
  (List.range 3).map (Role.inputNote 1) ++ (List.range 32).map (Role.inputMerkle 1) ++ [.inputNullifier 1] ++
  (List.range 3).map (Role.outputNote 0) ++ (List.range 3).map (Role.outputNote 1) ++
  (List.range 15).map Role.actionIntent ++ (List.range 4).map Role.policy ++
  (List.range 3).map Role.currentAccumulator ++ (List.range 3).map Role.nextAccumulator ++
  (List.range 2).map Role.valueLock ++ (List.range 4).map Role.stableConfigChunk ++
  (List.range 3).map Role.stableConfigNode ++ [.stableLeaf false, .stableLeaf true] ++
  (List.range 4).flatMap (fun level => [.stablePath false level, .stablePath true level]) ++
  [.issuerCommitment, .issuerAuthorization]

theorem expected_roles_count : expectedRoles.length = 125 := by decide

/-- Every source role, in exact order; this includes inactive slots without
replacing their calls by padding or skipping their computation. -/
theorem all_125_roles_exact (statement : V8PublicStatement) (witness : V8Witness)
    (earlier : Nat → State) (call : Fin 125) :
    (sourceCallPlan statement witness call.val earlier).role = expectedRoles.getD call.val .padding := by
  fin_cases call <;> rfl


/-- Changing unavailable future calls cannot change any live source call plan. -/
theorem source_plan_only_reads_prior (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (earlier other : Nat → State)
    (agree : ∀ i, i < call.val → earlier i = other i) :
    sourceCallPlan statement witness call.val earlier = sourceCallPlan statement witness call.val other := by
  fin_cases call <;>
    simp [sourceCallPlan, sourceInputPlan, finalDigest, agree]

theorem scheduled_plan_uses_actual_prior_finals (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) :
    sourceCallPlan statement witness call.val (builtFinals statement witness call.val) =
      sourceCallPlan statement witness call.val (scheduledFinal statement witness) := by
  apply source_plan_only_reads_prior
  intro i hi
  exact built_finals_readback statement witness call.val i hi

/-- This includes the separate sponge predecessor lookup performed by
`preparePlan`, not only dependencies already embedded in the call plan. -/
theorem prepared_frame_only_reads_prior (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (earlier other : Nat → State)
    (agree : ∀ i, i < call.val → earlier i = other i) :
    preparePlan earlier (sourceCallPlan statement witness call.val earlier) =
      preparePlan other (sourceCallPlan statement witness call.val other) := by
  fin_cases call <;>
    simp [sourceCallPlan, sourceInputPlan, finalDigest, preparePlan, previousSponge, agree]

theorem scheduled_initial_uses_actual_prior_finals (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) :
    scheduledInitial statement witness call.val =
      preparePlan (scheduledFinal statement witness)
        (sourceCallPlan statement witness call.val (scheduledFinal statement witness)) := by
  apply prepared_frame_only_reads_prior
  intro i hi
  exact built_finals_readback statement witness call.val i hi

/-- Typed validity alone yields every literal source-prepared frame using its
actual prior permutation results; no raw-frame or evaluator-success premise. -/
theorem typed_valid_initial_is_actual_source_frame (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) :
    stateWords (typedLiveInitialStates statement witness call) =
      rawPreparedPlan (scheduledFinal statement witness)
        (sourceCallPlan statement witness call.val (scheduledFinal statement witness)) := by
  change stateWords (scheduledInitial statement witness call.val) = _
  rw [scheduled_initial_uses_actual_prior_finals statement witness call]
  exact prepare_plan_does_not_alter_canonical_frame _ _
    (source_call_plan_raw_canonical statement witness
      (typed_valid_supplies_compression_sources statement witness valid) _ call.val call.isLt)

end HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

