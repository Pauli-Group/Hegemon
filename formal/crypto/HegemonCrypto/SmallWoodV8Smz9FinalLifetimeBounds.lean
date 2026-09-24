import HegemonCrypto.SmallWoodV8Smz9FinalLifetime
import HegemonCrypto.SmallWoodV8Smz9MixedFinalAccounting

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9HonestFinalGame V8Smz9MixedFinalOperational V8Smz9SourceLifetime
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

attribute [local irreducible] operationalRequest

/-- The lifetime index charges every current fixed leaf write, all actual
source pre/post-final reads including failure branches, and all native future
queries. It is derived from the concrete per-request source count. -/
theorem compiled_final_with_query_bound (step : MixedRequestCompiler bound Work)
    (bounded : ∀ request next queries, (∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries) →
      V8Smz9MixedMaskCompiler.queryCount (step request next) ≤ 16790291 + queries)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.queryCount (compileFinalWith step lifetime) ≤ queries := by
  induction lifetime with
  | finish event => exact Nat.zero_le _
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact Nat.add_le_add_right ih 1
  | honestRead input next ih => exact Nat.add_le_add_right (Finset.sup_le fun answer _ => ih answer) 1
  | instrument operation next ih => exact Finset.sup_le fun outcome _ => ih outcome
  | random source next ih => exact Finset.sup_le fun coins _ => ih coins
  | sourceRequest request next ih =>
      exact bounded request _ _ ih

theorem compiled_final_query_bound (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.queryCount (compileFinal largeEnough lifetime) ≤ queries :=
  compiled_final_with_query_bound (actualFinalRequestCompiler largeEnough)
    (fun request next queries remaining =>
      operational_request_query_bound (requestContext largeEnough request) next queries remaining) lifetime

/-- Whole-history final-hash reprogramming with derived source budgets and
full p^-3105 mass. The only analytic premise is the existing universal
external theorem applied to one physical compilation of the whole lifetime. -/
theorem whole_final_lifetime_reprogramming_bound (largeEnough : 37434 ≤ bound)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |finalLifetimeAcceptance true largeEnough lifetime initial -
      finalLifetimeAcceptance false largeEnough lifetime initial| ≤
      (requests : ℝ) * (Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2) := by
  apply V8Smz9MixedMaskCompiler.mixed_adaptive_reprogramming_bound ghhm _ initial queries requests _
    normalized (compiled_final_query_bound largeEnough lifetime)
    (compiled_final_programming_bound largeEnough lifetime) (by positivity)
  simpa only [ENNReal.ofReal_inv_of_pos (by norm_num [goldilocksModulus] :
      (0 : ℝ) < (goldilocksModulus : ℝ) ^ 3105),
    ENNReal.ofReal_pow (Nat.cast_nonneg goldilocksModulus), ENNReal.ofReal_natCast] using
      compiled_final_input_mass largeEnough lifetime

/-- The final-hash bound starts at the actual randomized-leaf source
lifetime, not at a separately stipulated intermediate endpoint. -/
theorem actual_source_lifetime_to_final_randomized_bound (largeEnough : 37434 ≤ bound)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |finalLifetimeAcceptance true largeEnough lifetime initial -
      sourceLifetimeAcceptance true largeEnough lifetime initial| ≤
      (requests : ℝ) * (Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2) := by
  rw [← false_final_lifetime_is_actual_randomized_source]
  exact whole_final_lifetime_reprogramming_bound largeEnough ghhm lifetime initial normalized


end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
