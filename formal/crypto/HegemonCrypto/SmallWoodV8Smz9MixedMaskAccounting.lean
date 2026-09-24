import HegemonCrypto.SmallWoodV8Smz9MixedMaskSemantics

namespace HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState)
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

private theorem value_le_univ_sup {A : Type} [Fintype A] (value : A → Nat) (point : A) :
    value point ≤ Finset.univ.sup value := Finset.le_sup (Finset.mem_univ point)

/-- A worst-case raw-query budget. Every fixed write costs one raw read of the
baseline, and every selected fresh instruction includes its ordinary retrieval.
No read is made free on an override hit, an abort branch, or a selected outcome. -/
def queryCount : MixedProgram Input Work → Nat
  | .finish _ => 0
  | .gate _ next => queryCount next
  | .quantumQuery next => queryCount next + 1
  | .honestRead _ next => (Finset.univ.sup fun answer => queryCount (next answer)) + 1
  | .instrument _ next => Finset.univ.sup fun outcome => queryCount (next outcome)
  | .random _ next => Finset.univ.sup fun coins => queryCount (next coins)
  | .freshInput _ next =>
      (Finset.univ.sup fun coins => Finset.univ.sup fun answer => queryCount (next coins answer)) + 1
  | .write _ _ next => queryCount next + 1

/-- Only the external, selected fresh-input events count as reprogrammings in
the theorem application. Fixed writes have already been charged as raw reads. -/
def programmingCount : MixedProgram Input Work → Nat
  | .finish _ => 0
  | .gate _ next => programmingCount next
  | .quantumQuery next => programmingCount next
  | .honestRead _ next => Finset.univ.sup fun answer => programmingCount (next answer)
  | .instrument _ next => Finset.univ.sup fun outcome => programmingCount (next outcome)
  | .random _ next => Finset.univ.sup fun coins => programmingCount (next coins)
  | .freshInput _ next =>
      (Finset.univ.sup fun coins => Finset.univ.sup fun answer => programmingCount (next coins answer)) + 1
  | .write _ _ next => programmingCount next

def InputMassAtMost (cap : ℝ≥0∞) : MixedProgram Input Work → Prop
  | .finish _ => True
  | .gate _ next => InputMassAtMost cap next
  | .quantumQuery next => InputMassAtMost cap next
  | .honestRead _ next => ∀ answer, InputMassAtMost cap (next answer)
  | .instrument _ next => ∀ outcome, InputMassAtMost cap (next outcome)
  | .random _ next => ∀ coins, InputMassAtMost cap (next coins)
  | .freshInput sampler next =>
      (∀ input, pmfMap (uniformFintypePMF sampler.Coins) sampler.input input ≤ cap) ∧
      ∀ coins answer, InputMassAtMost cap (next coins answer)
  | .write _ _ next => InputMassAtMost cap next

theorem compiled_query_count_le (program : MixedProgram Input Work) (log : CorrectionLog Input) :
    V8Smz9HonestWholeViewGames.queryCount (compile program log) ≤ queryCount program := by
  induction program generalizing log with
  | finish event => exact Nat.le_refl 0
  | gate operation next ih => exact ih log
  | quantumQuery next ih => exact Nat.add_le_add_right (ih log) 1
  | honestRead input next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.queryCount, queryCount]
      apply Nat.add_le_add_right
      apply Finset.sup_le
      intro answer _
      exact (ih (answer + correction log input) log).trans
        (value_le_univ_sup (fun output => queryCount (next output)) (answer + correction log input))
  | instrument operation next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.queryCount, queryCount]
      apply Finset.sup_le
      intro outcome _
      exact (ih outcome log).trans
        (Finset.le_sup (f := fun branch => queryCount (next branch)) (Finset.mem_univ outcome))
  | random source next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.queryCount, queryCount]
      apply Finset.sup_le
      intro coins _
      exact (ih coins log).trans
        (Finset.le_sup (f := fun coin => queryCount (next coin)) (Finset.mem_univ coins))
  | freshInput sampler next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.queryCount, queryCount]
      apply Nat.add_le_add_right
      apply Finset.sup_le
      intro coins _
      apply Finset.sup_le
      intro answer _
      exact (ih coins (answer + correction log (sampler.input coins)) log).trans
        ((Finset.le_sup (f := fun output => queryCount (next coins output))
          (Finset.mem_univ (answer + correction log (sampler.input coins)))).trans
          (Finset.le_sup (f := fun coin => Finset.univ.sup fun output => queryCount (next coin output))
            (Finset.mem_univ coins)))
  | write input answer next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.queryCount, queryCount]
      apply Nat.add_le_add_right
      apply Finset.sup_le
      intro rawAnswer _
      exact ih ((input, answer - rawAnswer) :: log)

theorem compiled_programming_count_le (program : MixedProgram Input Work) (log : CorrectionLog Input) :
    V8Smz9HonestWholeViewGames.programmingCount (compile program log) ≤ programmingCount program := by
  induction program generalizing log with
  | finish event => exact Nat.le_refl 0
  | gate operation next ih => exact ih log
  | quantumQuery next ih => exact ih log
  | honestRead input next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.programmingCount, programmingCount]
      apply Finset.sup_le
      intro answer _
      exact (ih (answer + correction log input) log).trans
        (value_le_univ_sup (fun output => programmingCount (next output)) (answer + correction log input))
  | instrument operation next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.programmingCount, programmingCount]
      apply Finset.sup_le
      intro outcome _
      exact (ih outcome log).trans
        (Finset.le_sup (f := fun branch => programmingCount (next branch)) (Finset.mem_univ outcome))
  | random source next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.programmingCount, programmingCount]
      apply Finset.sup_le
      intro coins _
      exact (ih coins log).trans
        (Finset.le_sup (f := fun coin => programmingCount (next coin)) (Finset.mem_univ coins))
  | freshInput sampler next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.programmingCount, programmingCount]
      apply Nat.add_le_add_right
      apply Finset.sup_le
      intro coins _
      apply Finset.sup_le
      intro answer _
      exact (ih coins (answer + correction log (sampler.input coins)) log).trans
        ((Finset.le_sup (f := fun output => programmingCount (next coins output))
            (Finset.mem_univ (answer + correction log (sampler.input coins)))).trans
          (Finset.le_sup (f := fun coin => Finset.univ.sup fun output => programmingCount (next coin output))
            (Finset.mem_univ coins)))
  | write input answer next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.programmingCount, programmingCount]
      apply Finset.sup_le
      intro rawAnswer _
      exact ih ((input, answer - rawAnswer) :: log)

theorem compiled_input_mass (cap : ℝ≥0∞) (program : MixedProgram Input Work)
    (log : CorrectionLog Input) (bounded : InputMassAtMost cap program) :
    V8Smz9HonestWholeViewGames.InputMassAtMost cap (compile program log) := by
  induction program generalizing log with
  | finish event => trivial
  | gate operation next ih => exact ih log bounded
  | quantumQuery next ih => exact ih log bounded
  | honestRead input next ih =>
      intro rawAnswer
      exact ih (rawAnswer + correction log input) log (bounded _)
  | instrument operation next ih =>
      intro outcome
      exact ih outcome log (bounded outcome)
  | random source next ih =>
      intro coins
      exact ih coins log (bounded coins)
  | freshInput sampler next ih =>
      refine ⟨bounded.1, ?_⟩
      intro coins rawAnswer
      exact ih coins (rawAnswer + correction log (sampler.input coins)) log (bounded.2 _ _)
  | write input answer next ih =>
      intro rawAnswer
      exact ih ((input, answer - rawAnswer) :: log) bounded

/-- The existing physical external theorem is applied to the actual compiled
program. This adapter assumes no new mixed-game distance statement. -/
theorem mixed_adaptive_reprogramming_bound
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming (Input := Input) (Work := Work))
    (program : MixedProgram Input Work) (initial : GameState (Input := Input) (Work := Work))
    (queries programs : Nat) (cap : ℝ)
    (normalized : ‖initial‖ = 1) (queriesBounded : queryCount program ≤ queries)
    (programsBounded : programmingCount program ≤ programs) (nonnegative : 0 ≤ cap)
    (massBounded : InputMassAtMost (ENNReal.ofReal cap) program) :
    |acceptance true program initial - acceptance false program initial| ≤
      (programs : ℝ) * (Real.sqrt ((queries : ℝ) * cap) + (queries : ℝ) * cap / 2) := by
  have bound := ghhm (compile program []) initial queries programs cap normalized
    ((compiled_query_count_le program []).trans queriesBounded)
    ((compiled_programming_count_le program []).trans programsBounded)
    nonnegative (compiled_input_mass _ program [] massBounded)
  simpa only [compiled_acceptance_eq] using bound


end
end HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler
