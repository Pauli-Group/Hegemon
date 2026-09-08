import HegemonCrypto.SmallWoodV8Smz9FinalContinuation
import HegemonCrypto.SmallWoodV8Smz9FinalSourceExecution

/-! The second reprogramming stage over the actual adaptive source-request
AST. Each request is the checked operational final program, and the same
recursive continuation receives its actual byte/error result and persistent
table. Only the full-T final events are selected in this stage. -/

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames (GameState Program)
open V8Smz9HonestFinalGame V8Smz9MixedFinalOperational V8Smz9SourceLifetime
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical BigOperators ENNReal

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- A symbolic constructor for a source-request node. The exported compiler
below instantiates it with the actual checked operational source program. -/
abbrev MixedRequestCompiler (bound : Nat) (Work : Type) [Fintype Work] :=
  SourceRequestData bound → (V8Smz9SourceLifetime.ByteResult → MixedProgram (FullRawInput bound) Work) →
    MixedProgram (FullRawInput bound) Work

def actualFinalRequestCompiler (largeEnough : 37434 ≤ bound) : MixedRequestCompiler bound Work :=
  fun request next => operationalRequest (requestContext largeEnough request) next

/-- Native prior/future operations and every request branch are retained.
The symbolic step prevents reduction of the concrete eight-million-leaf
program while checking structural induction over the lifetime. -/
def compileFinalWith (step : MixedRequestCompiler bound Work) :
    {queries requests : Nat} → Lifetime bound Work queries requests → MixedProgram (FullRawInput bound) Work
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (compileFinalWith step next)
  | _, _, .quantumQuery next => .quantumQuery (compileFinalWith step next)
  | _, _, .honestRead input next => .honestRead input (fun answer => compileFinalWith step (next answer))
  | _, _, .instrument operation next => .instrument operation (fun outcome => compileFinalWith step (next outcome))
  | _, _, .random source next => .random source (fun coins => compileFinalWith step (next coins))
  | _, _, .sourceRequest request next => step request (fun bytes => compileFinalWith step (next bytes))

def compileFinal (largeEnough : 37434 ≤ bound) {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) : MixedProgram (FullRawInput bound) Work :=
  compileFinalWith (actualFinalRequestCompiler largeEnough) lifetime

theorem compiled_final_source_request (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (request : SourceRequestData bound)
    (next : V8Smz9SourceLifetime.ByteResult → Lifetime bound Work queries requests) :
    compileFinal largeEnough (.sourceRequest request next) =
      operationalRequest (requestContext largeEnough request) (fun bytes => compileFinal largeEnough (next bytes)) := rfl

attribute [local irreducible] V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run
  operationalRequest V8Smz9PostFinalQueryBudget.sourceCompleteByteRequest

/-- The symbolic induction is immediately specialized below to the actual
source operations. Its local relation is proved, not exposed as a premise of
the actual lifetime endpoint. -/
theorem compiled_with_source_refinement
    (leftStep : MixedRequestCompiler bound Work) (rightStep : V8Smz9SourceLifetime.RequestCompiler bound Work)
    (stepsRelated : ∀ request left right,
      (∀ bytes oracle state, V8Smz9MixedMaskCompiler.run false (left bytes) oracle state =
        V8Smz9HonestWholeViewGames.run true (right bytes) oracle state) →
      ∀ oracle state, V8Smz9MixedMaskCompiler.run false (leftStep request left) oracle state =
        V8Smz9HonestWholeViewGames.run true (rightStep request right) oracle state)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false (compileFinalWith leftStep lifetime) oracle state =
      V8Smz9HonestWholeViewGames.run true (compileWith rightStep lifetime) oracle state := by
  induction lifetime generalizing oracle state with
  | finish event =>
      simp only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run]
  | gate operation next ih =>
      simpa only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run] using
        ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run] using
        ih oracle (V8Smz9HiddenPatch.query oracle state)
  | honestRead input next ih =>
      simpa only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run] using
        ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run]
      exact Finset.sum_congr rfl fun outcome _ => ih outcome oracle (operation.branch outcome state)
  | random source next ih =>
      simp only [compileFinalWith, compileWith, V8Smz9MixedMaskCompiler.run, V8Smz9HonestWholeViewGames.run]
      apply congrArg uniformAverage
      funext coins
      exact ih coins oracle state
  | sourceRequest request next ih => exact stepsRelated request _ _ ih oracle state

theorem actual_final_request_refines_source (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound)
    (left : V8Smz9SourceLifetime.ByteResult → MixedProgram (FullRawInput bound) Work)
    (right : V8Smz9SourceLifetime.ByteResult → Program (FullRawInput bound) Work)
    (remaining : ∀ bytes oracle state, V8Smz9MixedMaskCompiler.run false (left bytes) oracle state =
      V8Smz9HonestWholeViewGames.run true (right bytes) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false (actualFinalRequestCompiler largeEnough request left) oracle state =
      V8Smz9HonestWholeViewGames.run true (actualRequestCompiler largeEnough request right) oracle state := by
  unfold actualFinalRequestCompiler
  calc
    _ = V8Smz9MixedMaskCompiler.run false
        (operationalRequest (requestContext largeEnough request)
          (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (right bytes))) oracle state := by
      apply operational_request_continuation_congr
      intro bytes current currentState
      rw [V8Smz9MixedMaskCompiler.fixed_program_execution]
      exact remaining bytes current currentState
    _ = _ := by
      rw [operational_request_false_is_complete_source]
      exact (actual_request_execution_explicit largeEnough request right true oracle state).symm

/-- Whole-lifetime source transport with no endpoint-equality premise.
Every recursive continuation receives the exact retained logical table and
subnormalized branch state left by the current source request. -/
theorem compiled_final_false_is_randomized_source (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false (compileFinal largeEnough lifetime) oracle state =
      V8Smz9HonestWholeViewGames.run true (compileSource largeEnough lifetime) oracle state :=
  compiled_with_source_refinement (actualFinalRequestCompiler largeEnough) (actualRequestCompiler largeEnough)
    (actual_final_request_refines_source largeEnough) lifetime oracle state

theorem compiled_final_with_input_mass (step : MixedRequestCompiler bound Work) (cap : ℝ≥0∞)
    (bounded : ∀ request next, (∀ bytes, V8Smz9MixedMaskCompiler.InputMassAtMost cap (next bytes)) →
      V8Smz9MixedMaskCompiler.InputMassAtMost cap (step request next))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.InputMassAtMost cap (compileFinalWith step lifetime) := by
  induction lifetime with
  | finish event => trivial
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact ih
  | instrument operation next ih => exact ih
  | random source next ih => exact ih
  | sourceRequest request next ih => exact bounded request _ ih

theorem compiled_final_input_mass (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹
      (compileFinal largeEnough lifetime) :=
  compiled_final_with_input_mass (actualFinalRequestCompiler largeEnough) _
    (fun request next remaining => operational_request_mass (requestContext largeEnough request) next remaining) lifetime

theorem compiled_final_with_programming_bound (step : MixedRequestCompiler bound Work)
    (bounded : ∀ request next programs, (∀ bytes, V8Smz9MixedMaskCompiler.programmingCount (next bytes) ≤ programs) →
      V8Smz9MixedMaskCompiler.programmingCount (step request next) ≤ programs + 1)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.programmingCount (compileFinalWith step lifetime) ≤ requests := by
  induction lifetime with
  | finish event => exact Nat.zero_le _
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact Finset.sup_le fun answer _ => ih answer
  | instrument operation next ih => exact Finset.sup_le fun outcome _ => ih outcome
  | random source next ih => exact Finset.sup_le fun coins _ => ih coins
  | sourceRequest request next ih => exact bounded request _ _ ih

theorem compiled_final_programming_bound (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.programmingCount (compileFinal largeEnough lifetime) ≤ requests :=
  compiled_final_with_programming_bound (actualFinalRequestCompiler largeEnough)
    (fun request next programs remaining =>
      operational_request_program_bound (requestContext largeEnough request) next programs remaining) lifetime

/-- One uniformly sampled initial oracle and one fixed initial quantum state;
the whole recursive mixed program is compiled with one initial empty log. -/
def finalLifetimeAcceptance (randomized : Bool) (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  V8Smz9MixedMaskCompiler.acceptance randomized (compileFinal largeEnough lifetime) initial

theorem false_final_lifetime_is_actual_randomized_source (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    finalLifetimeAcceptance false largeEnough lifetime initial =
      sourceLifetimeAcceptance true largeEnough lifetime initial := by
  unfold finalLifetimeAcceptance sourceLifetimeAcceptance
    V8Smz9MixedMaskCompiler.acceptance V8Smz9HonestWholeViewGames.acceptance
  apply congrArg uniformAverage
  funext oracle
  exact compiled_final_false_is_randomized_source largeEnough lifetime oracle initial

theorem final_lifetime_is_single_physical_compilation (randomized : Bool) (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.acceptance randomized
      (V8Smz9MixedMaskCompiler.compile (compileFinal largeEnough lifetime) []) initial =
      finalLifetimeAcceptance randomized largeEnough lifetime initial :=
  V8Smz9MixedMaskCompiler.compiled_acceptance_eq randomized _ initial

theorem final_lifetime_acceptance_is_probability (randomized : Bool) (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    0 ≤ finalLifetimeAcceptance randomized largeEnough lifetime initial ∧
      finalLifetimeAcceptance randomized largeEnough lifetime initial ≤ 1 := by
  have probability := V8Smz9HonestWholeViewGames.game_acceptance_is_probability randomized
    (V8Smz9MixedMaskCompiler.compile (compileFinal largeEnough lifetime) []) initial normalized
  simpa only [final_lifetime_is_single_physical_compilation] using probability


end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
