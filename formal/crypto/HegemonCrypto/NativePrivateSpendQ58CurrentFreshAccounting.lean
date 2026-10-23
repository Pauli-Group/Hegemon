import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting

/-! A single syntax bound for a persistent mixed program. The total quantum
oracle-query complexity Q is the security parameter; it is not an installed
runtime limiter. Every fresh programming instruction is already charged in Q.
This theorem does not claim witness-independent public simulation. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshAccounting

open V8Smz9HiddenLeafQrom V8Smz9RuntimeDistribution
open V8Smz9MixedMaskCompiler
open V8Smz9HonestWholeViewGames (GameState)
open scoped Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

omit [DecidableEq Input] in
/-- The inclusive budget counts raw reads on fixed writes and fresh events,
including on error and instrument branches. No current per-request coefficient
such as 9806 is needed for this fresh-input comparison. -/
theorem programming_count_le_query_count (program : MixedProgram Input Work) :
    programmingCount program ≤ queryCount program := by
  induction program with
  | finish event => exact Nat.le_refl 0
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih.trans (Nat.le_add_right _ _)
  | honestRead input next ih =>
      simp only [programmingCount, queryCount]
      apply le_trans _ (Nat.le_add_right _ _)
      apply Finset.sup_le
      intro answer _
      exact (ih answer).trans (Finset.le_sup
        (f := fun output => queryCount (next output)) (Finset.mem_univ answer))
  | instrument operation next ih =>
      simp only [programmingCount, queryCount]
      apply Finset.sup_le
      intro outcome _
      exact (ih outcome).trans (Finset.le_sup
        (f := fun branch => queryCount (next branch)) (Finset.mem_univ outcome))
  | random source next ih =>
      simp only [programmingCount, queryCount]
      apply Finset.sup_le
      intro coins _
      exact (ih coins).trans (Finset.le_sup
        (f := fun coin => queryCount (next coin)) (Finset.mem_univ coins))
  | freshInput sampler next ih =>
      simp only [programmingCount, queryCount]
      apply Nat.add_le_add_right
      apply Finset.sup_le
      intro coins _
      apply Finset.sup_le
      intro answer _
      exact (ih coins answer).trans
        ((Finset.le_sup (f := fun output => queryCount (next coins output))
          (Finset.mem_univ answer)).trans
          (Finset.le_sup
            (f := fun coin => Finset.univ.sup fun output => queryCount (next coin output))
            (Finset.mem_univ coins)))
  | write input answer next ih => exact ih.trans (Nat.le_add_right _ _)

def freshLifetimeLoss (queries : Nat) : ℝ :=
  (queries : ℝ) * (Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
    (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2)

/-- One comparison for the complete persistent program, rather than a new
oracle or a fresh adversary state per request. The only distance premise is the
existing external adaptive reprogramming theorem. The structural InputMass
certificate must come from the program's actual fresh samplers. -/
theorem persistent_mixed_fresh_bound
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := Input) (Work := Work))
    (program : MixedProgram Input Work)
    (initial : GameState (Input := Input) (Work := Work)) (queries : Nat)
    (normalized : ‖initial‖ = 1) (queryBound : queryCount program ≤ queries)
    (massBound : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ program) :
    |acceptance true program initial - acceptance false program initial| ≤
      freshLifetimeLoss queries := by
  apply mixed_adaptive_reprogramming_bound ghhm program initial queries queries
    ((2 ^ 512 : ℝ)⁻¹) normalized queryBound
    ((programming_count_le_query_count program).trans queryBound) (by positivity)
  simpa only [ENNReal.ofReal_inv_of_pos (by positivity : (0 : ℝ) < 2 ^ 512),
    ENNReal.ofReal_pow (by norm_num : (0 : ℝ) ≤ 2), ENNReal.ofReal_ofNat] using massBound

/-- Compilation is pointwise exact in the original table and state. Fixed
writes do not receive free correlated advice; correction records start empty. -/
theorem persistent_compile_exact (randomized : Bool)
    (program : MixedProgram Input Work) (oracle : Input → DigestRegister)
    (initial : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized (compile program []) oracle initial =
      run randomized program oracle initial := by
  rw [compile_executes, effective_empty]

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshAccounting
