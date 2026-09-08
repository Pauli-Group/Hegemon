import HegemonCrypto.SmallWoodV8Smz9SourceHiddenCore
import HegemonCrypto.SmallWoodV8Smz9FinalLifetimeBounds
import HegemonCrypto.SmallWoodV8Smz9FinalByteJob
import HegemonCrypto.SmallWoodV8Smz9SourceByteModes

namespace HegemonCrypto.SmallWood.V8Smz9SourceHiddenEmbedding

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9HonestHybrid
open V8Smz9DynamicRequest V8Smz9DynamicTransport V8Smz9PostFinalProgram V8Smz9PostFinalPhysical
open V8Smz9MixedFinalOperational V8Smz9FinalLifetime V8Smz9BytePrefix
open V8Smz9SourceByteProgram V8Smz9RuntimeDistribution
open V8Smz9MeasuredSameOracleAdjacent
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical BigOperators

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

theorem final_byte_stage_job_is_factory (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (queries : Nat)
    (left : ByteResult → MixedProgram (FullRawInput bound) Work)
    (leftBound : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (left bytes) ≤ queries)
    (right : ByteResult → V8Smz9HiddenLifetime.BoundedMixed bound Work queries) :
    replaceByteNext bound queries
      (finalByteJob largeEnough request labels stage response transcript digest queries left leftBound)
      (V8Smz9HiddenLifetime.futureGames right) (V8Smz9HiddenLifetime.future_games_query_bound right) =
    (finalByteStage largeEnough request labels stage response transcript digest).toJob right := rfl

theorem after_final_continues_hidden_bytes (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) {queries requests : Nat}
    (left : ByteResult → MixedProgram (FullRawInput bound) Work)
    (leftBound : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (left bytes) ≤ queries)
    (right : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run true (left bytes) oracle state =
        V8Smz9HiddenLifetime.runLifetime false (right bytes) oracle state)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (afterFinal (requestContext largeEnough request) labels stage response transcript digest left) oracle state =
      V8Smz9HiddenLifetime.runLifetime false
        (.byteCall (finalByteStage largeEnough request labels stage response transcript digest) right) oracle state := by
  rw [after_final_is_source_byte_job true largeEnough request labels stage response transcript digest queries left leftBound]
  let rightPrograms := fun bytes => V8Smz9HiddenLifetime.compileWorld false (right bytes)
  have transported := source_byte_continuation_modes_congr true false true false bound queries
    (finalByteJob largeEnough request labels stage response transcript digest queries left leftBound)
    (V8Smz9HiddenLifetime.futureGames rightPrograms)
    (V8Smz9HiddenLifetime.future_games_query_bound rightPrograms)
    (by
      intro bytes current branch
      change V8Smz9HonestWholeViewGames.run true (V8Smz9MixedMaskCompiler.compile (left bytes) []) current branch = _
      rw [V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty,
        V8Smz9HiddenLifetime.future_games_execution]
      exact remaining bytes current branch) oracle state
  rw [final_byte_stage_job_is_factory] at transported
  rw [V8Smz9HiddenLifetime.source_call_execution]
  exact transported.trans (source_byte_program_executes_raw_kernel false false bound queries _ oracle state)

theorem randomized_final_request_is_hidden_request (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound) {queries requests : Nat}
    (left : ByteResult → MixedProgram (FullRawInput bound) Work)
    (leftBound : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (left bytes) ≤ queries)
    (right : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run true (left bytes) oracle state =
        V8Smz9HiddenLifetime.runLifetime false (right bytes) oracle state)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true (operationalRequest (requestContext largeEnough request) left) oracle state =
      V8Smz9HiddenLifetime.runLifetime false (hiddenRequest largeEnough request right) oracle state := by
  rw [operational_request_executes_prefix, hidden_request_executes_retained_prefix]
  apply congrArg uniformAverage
  funext labels
  apply congrArg uniformAverage
  funext response
  rw [selected_final_randomized_execution]
  apply congrArg uniformAverage
  funext transcript
  apply congrArg uniformAverage
  funext digest
  exact after_final_continues_hidden_bytes largeEnough request labels _ response transcript digest
    left leftBound right remaining _ state

attribute [local irreducible] compileHidden V8Smz9FinalLifetime.compileFinal
  V8Smz9HiddenLifetime.compileWorld operationalRequest hiddenRequest

/-- Actual whole-lifetime identification. The induction hypothesis is used
on every current effective oracle and every unnormalized branch state. -/
theorem randomized_final_lifetime_is_source_hidden_lifetime (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : V8Smz9SourceLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true (compileFinal largeEnough lifetime) oracle state =
      V8Smz9HiddenLifetime.runLifetime false (compileHidden largeEnough lifetime) oracle state := by
  induction lifetime generalizing oracle state with
  | finish event =>
      simp only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run]
  | gate operation next ih =>
      simpa only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run] using ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run] using ih oracle (query oracle state)
  | honestRead input next ih =>
      simpa only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run] using ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run]
      apply Finset.sum_congr rfl
      intro result _
      simpa only [compileFinal, V8Smz9HiddenLifetime.runLifetime] using
        ih result oracle (operation.branch result state)
  | random source next ih =>
      simp only [compileFinal, compileFinalWith, compileHidden, V8Smz9HiddenLifetime.runLifetime,
        V8Smz9HiddenLifetime.compileWorld, V8Smz9MixedMaskCompiler.run]
      apply congrArg uniformAverage
      funext coins
      simpa only [compileFinal, V8Smz9HiddenLifetime.runLifetime] using ih coins oracle state
  | sourceRequest request next ih =>
      rw [compiled_final_source_request, compileHidden]
      apply randomized_final_request_is_hidden_request largeEnough request
        (fun bytes => compileFinal largeEnough (next bytes))
        (fun bytes => compiled_final_query_bound largeEnough (next bytes))
        (fun bytes => compileHidden largeEnough (next bytes))
      exact ih

theorem final_randomized_acceptance_is_hidden_source (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : V8Smz9SourceLifetime.Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    finalLifetimeAcceptance true largeEnough lifetime initial =
      V8Smz9HiddenLifetime.lifetimeAcceptance false (compileHidden largeEnough lifetime) initial := by
  unfold finalLifetimeAcceptance V8Smz9HiddenLifetime.lifetimeAcceptance V8Smz9MixedMaskCompiler.acceptance
  exact congrArg uniformAverage (funext fun oracle =>
    randomized_final_lifetime_is_source_hidden_lifetime largeEnough lifetime oracle initial)

/-- The repeated hidden replacement is now attached to the concrete full
source lifetime, not an independently supplied post-final stage schedule. -/
theorem actual_final_to_public_lifetime_hidden_bound (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : V8Smz9SourceLifetime.Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |finalLifetimeAcceptance true largeEnough lifetime initial -
      V8Smz9HiddenLifetime.lifetimeAcceptance true (compileHidden largeEnough lifetime) initial| ≤
      (requests : ℝ) * V8Smz9PrivacyGameComposition.hiddenPatchLoss queries := by
  rw [final_randomized_acceptance_is_hidden_source]
  exact V8Smz9HiddenLifetime.hidden_lifetime_acceptance_bound _ initial normalized


end
end HegemonCrypto.SmallWood.V8Smz9SourceHiddenEmbedding
