import HegemonCrypto.SmallWoodV8Smz9SourcePublicSimulator
import HegemonCrypto.SmallWoodV8Smz9SourceHiddenEmbedding
import HegemonCrypto.SmallWoodV8Smz9LifetimePrivacyBudget

/-! Complete three-stage ideal-QROM privacy composition for the actual
source lifetime. The simulator input is the public source AST. All endpoint
equalities and resource charges are derived. The external universal adaptive
reprogramming theorem remains an explicit assumption; concrete Rust/RNG/hash
refinement and a deployed resource policy are separate obligations. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceLifetimePrivacy

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames V8Smz9SourceLifetime
open V8Smz9HonestFinalGame
open V8Smz9FinalLifetime V8Smz9SourceHiddenEmbedding
open V8Smz9SourcePublicErasure V8Smz9SourcePublicSimulator
open V8Smz9LifetimePrivacyBudget
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- The actual honest source, with all failed requests and retained oracle
updates, is compared to a directly compiled witness-free public simulator. -/
theorem actual_source_to_public_simulator_bound (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance false largeEnough lifetime initial -
      simulatorAcceptance largeEnough (eraseSource lifetime) initial| ≤ privacyLoss queries requests := by
  have leaves : |sourceLifetimeAcceptance false largeEnough lifetime initial -
      sourceLifetimeAcceptance true largeEnough lifetime initial| ≤ leafLoss queries requests := by
    rw [abs_sub_comm]
    exact whole_source_lifetime_leaf_reprogramming_bound largeEnough ghhm lifetime initial normalized
  have final : |sourceLifetimeAcceptance true largeEnough lifetime initial -
      finalLifetimeAcceptance true largeEnough lifetime initial| ≤ finalLoss queries requests := by
    rw [abs_sub_comm]
    exact actual_source_lifetime_to_final_randomized_bound largeEnough ghhm lifetime initial normalized
  have hidden : |finalLifetimeAcceptance true largeEnough lifetime initial -
      simulatorAcceptance largeEnough (eraseSource lifetime) initial| ≤ hiddenLoss queries requests := by
    rw [source_simulator_is_public_world]
    exact actual_final_to_public_lifetime_hidden_bound largeEnough lifetime initial normalized
  calc
    _ ≤ |sourceLifetimeAcceptance false largeEnough lifetime initial -
          sourceLifetimeAcceptance true largeEnough lifetime initial| +
        |sourceLifetimeAcceptance true largeEnough lifetime initial -
          finalLifetimeAcceptance true largeEnough lifetime initial| +
        |finalLifetimeAcceptance true largeEnough lifetime initial -
          simulatorAcceptance largeEnough (eraseSource lifetime) initial| := by
      have first := abs_sub_le (sourceLifetimeAcceptance false largeEnough lifetime initial)
        (sourceLifetimeAcceptance true largeEnough lifetime initial)
        (simulatorAcceptance largeEnough (eraseSource lifetime) initial)
      have second := abs_sub_le (sourceLifetimeAcceptance true largeEnough lifetime initial)
        (finalLifetimeAcceptance true largeEnough lifetime initial)
        (simulatorAcceptance largeEnough (eraseSource lifetime) initial)
      linarith
    _ ≤ leafLoss queries requests + finalLoss queries requests + hiddenLoss queries requests :=
      add_le_add (add_le_add leaves final) hidden
    _ = _ := rfl

theorem publicly_equivalent_source_simulators_equal (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} {left right : Lifetime bound Work queries requests}
    (related : PubliclyEquivalent left right)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    simulatorAcceptance largeEnough (eraseSource left) initial =
      simulatorAcceptance largeEnough (eraseSource right) initial := by
  rw [public_erasure_eq_of_publicly_equivalent related]

/-- The two admitted witness policies may differ at every request, but their
entire public request/control-flow erasure and common initial state agree. -/
theorem actual_two_witness_lifetime_bound (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} {left right : Lifetime bound Work queries requests}
    (related : PubliclyEquivalent left right)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance false largeEnough left initial -
      sourceLifetimeAcceptance false largeEnough right initial| ≤ 2 * privacyLoss queries requests := by
  have leftBound := actual_source_to_public_simulator_bound largeEnough ghhm left initial normalized
  have rightBound := actual_source_to_public_simulator_bound largeEnough ghhm right initial normalized
  have same := publicly_equivalent_source_simulators_equal largeEnough related initial
  rw [← same] at rightBound
  have triangle := abs_sub_le (sourceLifetimeAcceptance false largeEnough left initial)
    (simulatorAcceptance largeEnough (eraseSource left) initial)
    (sourceLifetimeAcceptance false largeEnough right initial)
  rw [abs_sub_comm (simulatorAcceptance largeEnough (eraseSource left) initial)] at triangle
  linarith

theorem source_simulator_bound_at_analysis_resources (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (queryBound : queries ≤ 2 ^ 65) (requestBound : requests ≤ 2 ^ 21)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance false largeEnough lifetime initial -
      simulatorAcceptance largeEnough (eraseSource lifetime) initial| ≤ (2 ^ 167 : ℝ)⁻¹ :=
  (actual_source_to_public_simulator_bound largeEnough ghhm lifetime initial normalized).trans
    (privacy_loss_at_analysis_resources queries requests queryBound requestBound)

theorem two_witness_source_bound_below_target (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} {left right : Lifetime bound Work queries requests}
    (related : PubliclyEquivalent left right)
    (queryBound : queries ≤ 2 ^ 65) (requestBound : requests ≤ 2 ^ 21)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance false largeEnough left initial -
      sourceLifetimeAcceptance false largeEnough right initial| < (2 ^ 128 : ℝ)⁻¹ :=
  (actual_two_witness_lifetime_bound largeEnough ghhm related initial normalized).trans_lt
    (two_witness_privacy_loss_below_target queries requests queryBound requestBound)

end
end HegemonCrypto.SmallWood.V8Smz9SourceLifetimePrivacy
